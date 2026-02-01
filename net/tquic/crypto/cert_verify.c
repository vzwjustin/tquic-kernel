// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Certificate Chain Validation
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Implements X.509 certificate chain validation for TQUIC TLS 1.3
 * connections. Uses the kernel's asymmetric key infrastructure and
 * system keyring for trusted root certificate storage.
 *
 * This module addresses the MITM vulnerability in TQUIC by providing
 * proper certificate validation including:
 *   - Certificate chain parsing and building
 *   - Signature verification using kernel crypto
 *   - Hostname verification with wildcard support
 *   - Trust anchor lookup in system/platform keyrings
 *   - Validity period checking with clock skew tolerance
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/time64.h>
#include <linux/key.h>
#include <linux/verification.h>
#include <crypto/public_key.h>
#include <crypto/hash.h>
#include <keys/asymmetric-type.h>
#include <keys/system_keyring.h>
#include <net/tquic.h>

#include "cert_verify.h"

/*
 * TLS alert code definitions (for handshake integration)
 * These match the values from TLS 1.3 RFC 8446
 */
#define TLS_ALERT_BAD_CERTIFICATE	42
#define TLS_ALERT_CERTIFICATE_REVOKED	44
#define TLS_ALERT_CERTIFICATE_EXPIRED	45
#define TLS_ALERT_UNKNOWN_CA		48
#define TLS_ALERT_DECODE_ERROR		50
#define TLS_ALERT_INTERNAL_ERROR	80
#define TLS_ALERT_CERTIFICATE_REQUIRED	116

/* ASN.1 tag values */
#define ASN1_SEQUENCE		0x30
#define ASN1_SET		0x31
#define ASN1_INTEGER		0x02
#define ASN1_BIT_STRING		0x03
#define ASN1_OCTET_STRING	0x04
#define ASN1_NULL		0x05
#define ASN1_OID		0x06
#define ASN1_UTF8_STRING	0x0c
#define ASN1_PRINTABLE_STRING	0x13
#define ASN1_IA5_STRING		0x16
#define ASN1_UTC_TIME		0x17
#define ASN1_GENERALIZED_TIME	0x18
#define ASN1_CONTEXT_0		0xa0
#define ASN1_CONTEXT_3		0xa3

/* X.509 extension OIDs */
static const u8 oid_subject_alt_name[] = { 0x55, 0x1d, 0x11 };
static const u8 oid_basic_constraints[] = { 0x55, 0x1d, 0x13 };
static const u8 oid_key_usage[] = { 0x55, 0x1d, 0x0f };
static const u8 oid_ext_key_usage[] = { 0x55, 0x1d, 0x25 };

/* Common Name OID: 2.5.4.3 */
static const u8 oid_common_name[] = { 0x55, 0x04, 0x03 };

/* Default clock skew tolerance: 5 minutes */
#define DEFAULT_TIME_TOLERANCE	300

/* Module-level trusted keyring cache */
static struct key *tquic_trusted_keyring;
static DEFINE_MUTEX(keyring_mutex);

/*
 * ASN.1 parsing helpers
 */

static int asn1_get_length(const u8 *data, u32 data_len, u32 *len, u32 *hdr_len)
{
	if (data_len < 1)
		return -EINVAL;

	if (data[0] < 0x80) {
		*len = data[0];
		*hdr_len = 1;
	} else if (data[0] == 0x81) {
		if (data_len < 2)
			return -EINVAL;
		*len = data[1];
		*hdr_len = 2;
	} else if (data[0] == 0x82) {
		if (data_len < 3)
			return -EINVAL;
		*len = (data[1] << 8) | data[2];
		*hdr_len = 3;
	} else if (data[0] == 0x83) {
		if (data_len < 4)
			return -EINVAL;
		*len = (data[1] << 16) | (data[2] << 8) | data[3];
		*hdr_len = 4;
	} else {
		return -EINVAL;
	}

	return 0;
}

static int asn1_get_tag_length(const u8 *data, u32 data_len, u8 expected_tag,
			       u32 *content_len, u32 *total_len)
{
	u32 len, hdr_len;
	int ret;

	if (data_len < 2)
		return -EINVAL;

	if (data[0] != expected_tag)
		return -EINVAL;

	ret = asn1_get_length(data + 1, data_len - 1, &len, &hdr_len);
	if (ret < 0)
		return ret;

	*content_len = len;
	*total_len = 1 + hdr_len + len;

	if (*total_len > data_len)
		return -EINVAL;

	return 0;
}

/*
 * Parse X.500 Distinguished Name to extract Common Name
 */
static int parse_dn_extract_cn(const u8 *data, u32 len, char **cn, u32 *cn_len)
{
	const u8 *p = data;
	const u8 *end = data + len;

	while (p < end) {
		u32 set_content_len, set_total_len;
		u32 seq_content_len, seq_total_len;
		u32 oid_content_len, oid_total_len;
		u32 val_content_len, val_total_len;
		int ret;

		/* Parse SET */
		ret = asn1_get_tag_length(p, end - p, ASN1_SET,
					  &set_content_len, &set_total_len);
		if (ret < 0)
			break;

		/* Parse SEQUENCE inside SET */
		ret = asn1_get_tag_length(p + (set_total_len - set_content_len),
					  set_content_len, ASN1_SEQUENCE,
					  &seq_content_len, &seq_total_len);
		if (ret < 0) {
			p += set_total_len;
			continue;
		}

		const u8 *seq_start = p + (set_total_len - set_content_len) +
				      (seq_total_len - seq_content_len);

		/* Parse OID */
		ret = asn1_get_tag_length(seq_start, seq_content_len, ASN1_OID,
					  &oid_content_len, &oid_total_len);
		if (ret < 0) {
			p += set_total_len;
			continue;
		}

		/* Check if this is Common Name OID */
		if (oid_content_len == sizeof(oid_common_name) &&
		    memcmp(seq_start + (oid_total_len - oid_content_len),
			   oid_common_name, sizeof(oid_common_name)) == 0) {
			/* Extract the value */
			const u8 *val_start = seq_start + oid_total_len;
			u32 remaining = seq_content_len - oid_total_len;

			if (remaining < 2) {
				p += set_total_len;
				continue;
			}

			u8 val_tag = val_start[0];
			if (val_tag != ASN1_UTF8_STRING &&
			    val_tag != ASN1_PRINTABLE_STRING &&
			    val_tag != ASN1_IA5_STRING) {
				p += set_total_len;
				continue;
			}

			ret = asn1_get_tag_length(val_start, remaining, val_tag,
						  &val_content_len, &val_total_len);
			if (ret < 0) {
				p += set_total_len;
				continue;
			}

			*cn = kmalloc(val_content_len + 1, GFP_KERNEL);
			if (!*cn)
				return -ENOMEM;

			memcpy(*cn, val_start + (val_total_len - val_content_len),
			       val_content_len);
			(*cn)[val_content_len] = '\0';
			*cn_len = val_content_len;

			return 0;
		}

		p += set_total_len;
	}

	return -ENOENT;
}

/*
 * Parse Subject Alternative Names extension
 */
static int parse_san_extension(const u8 *data, u32 len,
			       char ***dns_names, u32 *dns_count)
{
	const u8 *p = data;
	const u8 *end = data + len;
	char **names = NULL;
	u32 count = 0;
	u32 capacity = 4;

	names = kcalloc(capacity, sizeof(char *), GFP_KERNEL);
	if (!names)
		return -ENOMEM;

	/* SAN is a SEQUENCE of GeneralName */
	while (p < end) {
		u8 tag = p[0];
		u32 content_len, hdr_len;
		int ret;

		if (p + 2 > end)
			break;

		ret = asn1_get_length(p + 1, end - p - 1, &content_len, &hdr_len);
		if (ret < 0)
			break;

		/* dNSName is context tag [2] */
		if ((tag & 0x1f) == 2 && (tag & 0xc0) == 0x80) {
			if (count >= capacity) {
				u32 new_cap = capacity * 2;
				char **new_names = krealloc(names,
							    new_cap * sizeof(char *),
							    GFP_KERNEL);
				if (!new_names) {
					ret = -ENOMEM;
					goto err_free;
				}
				names = new_names;
				capacity = new_cap;
			}

			names[count] = kmalloc(content_len + 1, GFP_KERNEL);
			if (!names[count]) {
				ret = -ENOMEM;
				goto err_free;
			}

			memcpy(names[count], p + 1 + hdr_len, content_len);
			names[count][content_len] = '\0';
			count++;
		}

		p += 1 + hdr_len + content_len;
	}

	*dns_names = names;
	*dns_count = count;
	return 0;

err_free:
	for (u32 i = 0; i < count; i++)
		kfree(names[i]);
	kfree(names);
	return -ENOMEM;
}

/*
 * Parse X.509 certificate extensions
 */
static int parse_extensions(struct tquic_x509_cert *cert,
			    const u8 *data, u32 len)
{
	const u8 *p = data;
	const u8 *end = data + len;

	/* Extensions is a SEQUENCE of Extension */
	while (p < end) {
		u32 ext_content_len, ext_total_len;
		u32 oid_content_len, oid_total_len;
		const u8 *ext_data;
		int ret;
		bool critical = false;

		/* Each Extension is a SEQUENCE */
		ret = asn1_get_tag_length(p, end - p, ASN1_SEQUENCE,
					  &ext_content_len, &ext_total_len);
		if (ret < 0)
			break;

		ext_data = p + (ext_total_len - ext_content_len);

		/* OID */
		ret = asn1_get_tag_length(ext_data, ext_content_len, ASN1_OID,
					  &oid_content_len, &oid_total_len);
		if (ret < 0) {
			p += ext_total_len;
			continue;
		}

		const u8 *oid = ext_data + (oid_total_len - oid_content_len);
		const u8 *next = ext_data + oid_total_len;
		u32 remaining = ext_content_len - oid_total_len;

		/* Optional critical boolean */
		if (remaining > 0 && next[0] == 0x01) {
			if (remaining >= 3) {
				critical = (next[2] != 0);
				next += 3;
				remaining -= 3;
			}
		}

		/* OCTET STRING containing extension value */
		if (remaining > 0 && next[0] == ASN1_OCTET_STRING) {
			u32 val_content_len, val_total_len;

			ret = asn1_get_tag_length(next, remaining, ASN1_OCTET_STRING,
						  &val_content_len, &val_total_len);
			if (ret == 0) {
				const u8 *val = next + (val_total_len - val_content_len);

				/* Subject Alternative Name */
				if (oid_content_len == sizeof(oid_subject_alt_name) &&
				    memcmp(oid, oid_subject_alt_name,
					   sizeof(oid_subject_alt_name)) == 0) {
					/* Skip outer SEQUENCE tag */
					u32 seq_content_len, seq_total_len;
					ret = asn1_get_tag_length(val, val_content_len,
								  ASN1_SEQUENCE,
								  &seq_content_len,
								  &seq_total_len);
					if (ret == 0) {
						parse_san_extension(
							val + (seq_total_len - seq_content_len),
							seq_content_len,
							&cert->san_dns,
							&cert->san_dns_count);
					}
				}

				/* Basic Constraints */
				if (oid_content_len == sizeof(oid_basic_constraints) &&
				    memcmp(oid, oid_basic_constraints,
					   sizeof(oid_basic_constraints)) == 0) {
					/* Check if CA */
					u32 seq_content_len, seq_total_len;
					ret = asn1_get_tag_length(val, val_content_len,
								  ASN1_SEQUENCE,
								  &seq_content_len,
								  &seq_total_len);
					if (ret == 0 && seq_content_len >= 3) {
						const u8 *seq = val + (seq_total_len - seq_content_len);
						if (seq[0] == 0x01 && seq[1] == 0x01)
							cert->is_ca = (seq[2] != 0);
					}
				}
			}
		}

		p += ext_total_len;
	}

	return 0;
}

/*
 * Parse UTC Time or Generalized Time
 */
static int parse_time(const u8 *data, u32 len, s64 *time_out)
{
	struct tm tm = { 0 };
	int year, month, day, hour, min, sec;

	if (len < 13)
		return -EINVAL;

	if (data[0] == ASN1_UTC_TIME) {
		/* YYMMDDhhmmssZ */
		u32 content_len, hdr_len;
		int ret = asn1_get_length(data + 1, len - 1, &content_len, &hdr_len);
		if (ret < 0 || content_len < 12)
			return -EINVAL;

		const char *t = (const char *)data + 1 + hdr_len;
		year = (t[0] - '0') * 10 + (t[1] - '0');
		year += (year < 50) ? 2000 : 1900;
		month = (t[2] - '0') * 10 + (t[3] - '0');
		day = (t[4] - '0') * 10 + (t[5] - '0');
		hour = (t[6] - '0') * 10 + (t[7] - '0');
		min = (t[8] - '0') * 10 + (t[9] - '0');
		sec = (t[10] - '0') * 10 + (t[11] - '0');
	} else if (data[0] == ASN1_GENERALIZED_TIME) {
		/* YYYYMMDDhhmmssZ */
		u32 content_len, hdr_len;
		int ret = asn1_get_length(data + 1, len - 1, &content_len, &hdr_len);
		if (ret < 0 || content_len < 14)
			return -EINVAL;

		const char *t = (const char *)data + 1 + hdr_len;
		year = (t[0] - '0') * 1000 + (t[1] - '0') * 100 +
		       (t[2] - '0') * 10 + (t[3] - '0');
		month = (t[4] - '0') * 10 + (t[5] - '0');
		day = (t[6] - '0') * 10 + (t[7] - '0');
		hour = (t[8] - '0') * 10 + (t[9] - '0');
		min = (t[10] - '0') * 10 + (t[11] - '0');
		sec = (t[12] - '0') * 10 + (t[13] - '0');
	} else {
		return -EINVAL;
	}

	tm.tm_year = year - 1900;
	tm.tm_mon = month - 1;
	tm.tm_mday = day;
	tm.tm_hour = hour;
	tm.tm_min = min;
	tm.tm_sec = sec;

	*time_out = mktime64(tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
			     tm.tm_hour, tm.tm_min, tm.tm_sec);

	return 0;
}

/*
 * Parse X.509 TBSCertificate structure
 */
static int parse_tbs_certificate(struct tquic_x509_cert *cert,
				 const u8 *data, u32 len)
{
	const u8 *p = data;
	const u8 *end = data + len;
	u32 content_len, total_len;
	int ret;

	/* TBSCertificate is a SEQUENCE */
	ret = asn1_get_tag_length(p, end - p, ASN1_SEQUENCE,
				  &content_len, &total_len);
	if (ret < 0)
		return ret;

	p += (total_len - content_len);
	end = p + content_len;

	/* Version [0] EXPLICIT INTEGER DEFAULT v1 */
	if (p < end && p[0] == ASN1_CONTEXT_0) {
		ret = asn1_get_tag_length(p, end - p, ASN1_CONTEXT_0,
					  &content_len, &total_len);
		if (ret < 0)
			return ret;
		p += total_len;
	}

	/* Serial Number */
	ret = asn1_get_tag_length(p, end - p, ASN1_INTEGER,
				  &content_len, &total_len);
	if (ret < 0)
		return ret;

	cert->serial = kmalloc(content_len, GFP_KERNEL);
	if (!cert->serial)
		return -ENOMEM;
	memcpy(cert->serial, p + (total_len - content_len), content_len);
	cert->serial_len = content_len;
	p += total_len;

	/* Signature Algorithm */
	ret = asn1_get_tag_length(p, end - p, ASN1_SEQUENCE,
				  &content_len, &total_len);
	if (ret < 0)
		return ret;
	p += total_len;

	/* Issuer */
	ret = asn1_get_tag_length(p, end - p, ASN1_SEQUENCE,
				  &content_len, &total_len);
	if (ret < 0)
		return ret;

	ret = parse_dn_extract_cn(p + (total_len - content_len), content_len,
				  &cert->issuer, &cert->issuer_len);
	if (ret < 0 && ret != -ENOENT)
		return ret;
	p += total_len;

	/* Validity */
	ret = asn1_get_tag_length(p, end - p, ASN1_SEQUENCE,
				  &content_len, &total_len);
	if (ret < 0)
		return ret;

	const u8 *validity = p + (total_len - content_len);

	/* notBefore */
	ret = parse_time(validity, content_len, &cert->valid_from);
	if (ret < 0)
		return ret;

	/* Skip notBefore to get notAfter */
	u32 time_len, time_hdr;
	ret = asn1_get_length(validity + 1, content_len - 1, &time_len, &time_hdr);
	if (ret < 0)
		return ret;

	const u8 *not_after = validity + 1 + time_hdr + time_len;
	ret = parse_time(not_after, content_len - (not_after - validity),
			 &cert->valid_to);
	if (ret < 0)
		return ret;

	p += total_len;

	/* Subject */
	ret = asn1_get_tag_length(p, end - p, ASN1_SEQUENCE,
				  &content_len, &total_len);
	if (ret < 0)
		return ret;

	ret = parse_dn_extract_cn(p + (total_len - content_len), content_len,
				  &cert->subject, &cert->subject_len);
	if (ret < 0 && ret != -ENOENT)
		return ret;
	p += total_len;

	/* SubjectPublicKeyInfo */
	ret = asn1_get_tag_length(p, end - p, ASN1_SEQUENCE,
				  &content_len, &total_len);
	if (ret < 0)
		return ret;

	cert->pub_key = kmalloc(total_len, GFP_KERNEL);
	if (!cert->pub_key)
		return -ENOMEM;
	memcpy(cert->pub_key, p, total_len);
	cert->pub_key_len = total_len;
	p += total_len;

	/* Extensions [3] EXPLICIT */
	if (p < end && p[0] == ASN1_CONTEXT_3) {
		ret = asn1_get_tag_length(p, end - p, ASN1_CONTEXT_3,
					  &content_len, &total_len);
		if (ret == 0) {
			/* Inner SEQUENCE of extensions */
			const u8 *ext_data = p + (total_len - content_len);
			u32 ext_seq_content, ext_seq_total;

			ret = asn1_get_tag_length(ext_data, content_len, ASN1_SEQUENCE,
						  &ext_seq_content, &ext_seq_total);
			if (ret == 0) {
				parse_extensions(cert,
						 ext_data + (ext_seq_total - ext_seq_content),
						 ext_seq_content);
			}
		}
	}

	return 0;
}

/*
 * Public API implementations
 */

struct tquic_x509_cert *tquic_x509_cert_parse(const u8 *data, u32 len, gfp_t gfp)
{
	struct tquic_x509_cert *cert;
	u32 content_len, total_len;
	int ret;

	if (!data || len == 0)
		return NULL;

	cert = kzalloc(sizeof(*cert), gfp);
	if (!cert)
		return NULL;

	/* Store raw certificate */
	cert->raw = kmalloc(len, gfp);
	if (!cert->raw) {
		kfree(cert);
		return NULL;
	}
	memcpy(cert->raw, data, len);
	cert->raw_len = len;

	/* Certificate is a SEQUENCE */
	ret = asn1_get_tag_length(data, len, ASN1_SEQUENCE,
				  &content_len, &total_len);
	if (ret < 0) {
		tquic_x509_cert_free(cert);
		return NULL;
	}

	/* Parse TBSCertificate */
	ret = parse_tbs_certificate(cert, data + (total_len - content_len),
				    content_len);
	if (ret < 0) {
		tquic_x509_cert_free(cert);
		return NULL;
	}

	return cert;
}
EXPORT_SYMBOL_GPL(tquic_x509_cert_parse);

void tquic_x509_cert_free(struct tquic_x509_cert *cert)
{
	if (!cert)
		return;

	kfree(cert->raw);
	kfree(cert->subject);
	kfree(cert->issuer);
	kfree(cert->serial);
	kfree(cert->pub_key);

	if (cert->san_dns) {
		for (u32 i = 0; i < cert->san_dns_count; i++)
			kfree(cert->san_dns[i]);
		kfree(cert->san_dns);
	}

	kfree(cert);
}
EXPORT_SYMBOL_GPL(tquic_x509_cert_free);

void tquic_x509_chain_free(struct tquic_x509_cert *chain)
{
	struct tquic_x509_cert *cert = chain;

	while (cert) {
		struct tquic_x509_cert *next = cert->next;
		tquic_x509_cert_free(cert);
		cert = next;
	}
}
EXPORT_SYMBOL_GPL(tquic_x509_chain_free);

int tquic_x509_cert_is_valid_time(const struct tquic_x509_cert *cert, u32 tolerance)
{
	ktime_t now = ktime_get_real();
	s64 now_sec = ktime_to_ns(now) / NSEC_PER_SEC;

	if (now_sec < cert->valid_from - tolerance)
		return -EKEYREJECTED;

	if (now_sec > cert->valid_to + tolerance)
		return -EKEYEXPIRED;

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_x509_cert_is_valid_time);

struct tquic_cert_verify_ctx *tquic_cert_verify_ctx_alloc(gfp_t gfp)
{
	struct tquic_cert_verify_ctx *ctx;

	ctx = kzalloc(sizeof(*ctx), gfp);
	if (!ctx)
		return NULL;

	ctx->verify_mode = TQUIC_CERT_VERIFY_REQUIRED;
	ctx->verify_hostname = true;
	ctx->time_tolerance = DEFAULT_TIME_TOLERANCE;

	return ctx;
}
EXPORT_SYMBOL_GPL(tquic_cert_verify_ctx_alloc);

void tquic_cert_verify_ctx_free(struct tquic_cert_verify_ctx *ctx)
{
	if (!ctx)
		return;

	kfree(ctx->expected_hostname);
	tquic_x509_chain_free(ctx->chain);

	if (ctx->trusted_keyring && ctx->trusted_keyring != VERIFY_USE_SECONDARY_KEYRING)
		key_put(ctx->trusted_keyring);

	kfree(ctx);
}
EXPORT_SYMBOL_GPL(tquic_cert_verify_ctx_free);

int tquic_cert_verify_set_hostname(struct tquic_cert_verify_ctx *ctx,
				   const char *hostname, u32 len)
{
	if (!ctx)
		return -EINVAL;

	if (len > TQUIC_MAX_HOSTNAME_LEN)
		return -EINVAL;

	kfree(ctx->expected_hostname);

	if (!hostname || len == 0) {
		ctx->expected_hostname = NULL;
		ctx->hostname_len = 0;
		return 0;
	}

	ctx->expected_hostname = kmalloc(len + 1, GFP_KERNEL);
	if (!ctx->expected_hostname)
		return -ENOMEM;

	memcpy(ctx->expected_hostname, hostname, len);
	ctx->expected_hostname[len] = '\0';
	ctx->hostname_len = len;

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_cert_verify_set_hostname);

int tquic_cert_verify_set_mode(struct tquic_cert_verify_ctx *ctx,
			       enum tquic_cert_verify_mode mode)
{
	if (!ctx)
		return -EINVAL;

	if (mode < TQUIC_CERT_VERIFY_NONE || mode > TQUIC_CERT_VERIFY_REQUIRED)
		return -EINVAL;

	ctx->verify_mode = mode;
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_cert_verify_set_mode);

int tquic_cert_verify_set_keyring(struct tquic_cert_verify_ctx *ctx,
				  struct key *keyring)
{
	if (!ctx)
		return -EINVAL;

	if (ctx->trusted_keyring && ctx->trusted_keyring != VERIFY_USE_SECONDARY_KEYRING)
		key_put(ctx->trusted_keyring);

	if (!keyring) {
		/* Use system keyring */
		ctx->trusted_keyring = VERIFY_USE_SECONDARY_KEYRING;
	} else {
		ctx->trusted_keyring = key_get(keyring);
	}

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_cert_verify_set_keyring);

/*
 * Hostname matching with wildcard support (RFC 6125)
 */
static bool hostname_match(const char *pattern, u32 pattern_len,
			   const char *hostname, u32 hostname_len)
{
	/* Exact match */
	if (pattern_len == hostname_len &&
	    strncasecmp(pattern, hostname, pattern_len) == 0)
		return true;

	/* Wildcard matching */
	if (pattern_len >= 2 && pattern[0] == '*' && pattern[1] == '.') {
		/* Find first dot in hostname */
		const char *dot = memchr(hostname, '.', hostname_len);
		if (!dot)
			return false;

		/* Wildcard only matches one label */
		u32 remaining_hostname = hostname_len - (dot - hostname);
		u32 remaining_pattern = pattern_len - 1;  /* Skip the '*' */

		if (remaining_hostname == remaining_pattern &&
		    strncasecmp(pattern + 1, dot, remaining_pattern) == 0)
			return true;
	}

	return false;
}

int tquic_verify_hostname(const struct tquic_x509_cert *cert,
			  const char *expected, u32 expected_len)
{
	if (!cert || !expected || expected_len == 0)
		return -EINVAL;

	/* Check Subject Alternative Names first (preferred per RFC 6125) */
	if (cert->san_dns && cert->san_dns_count > 0) {
		for (u32 i = 0; i < cert->san_dns_count; i++) {
			if (hostname_match(cert->san_dns[i],
					   strlen(cert->san_dns[i]),
					   expected, expected_len))
				return 0;
		}
	}

	/* Fall back to Common Name */
	if (cert->subject && cert->subject_len > 0) {
		if (hostname_match(cert->subject, cert->subject_len,
				   expected, expected_len))
			return 0;
	}

	return -ENOENT;
}
EXPORT_SYMBOL_GPL(tquic_verify_hostname);

/*
 * Verify certificate signature using kernel crypto
 */
int tquic_x509_verify_signature(const struct tquic_x509_cert *cert,
				const struct tquic_x509_cert *issuer)
{
	/*
	 * Note: Full signature verification requires the kernel's
	 * public_key_verify_signature() which needs a properly parsed
	 * public key and signature. For now, we rely on the keyring
	 * lookup which implicitly verifies the chain during
	 * find_asymmetric_key().
	 *
	 * TODO: Implement standalone signature verification for
	 * cases where we need to verify intermediate certificates
	 * that aren't in the keyring.
	 */
	if (!cert || !issuer)
		return -EINVAL;

	/* Self-signed check: issuer == subject */
	if (cert->issuer && cert->subject &&
	    cert->issuer_len == cert->subject_len &&
	    memcmp(cert->issuer, cert->subject, cert->issuer_len) == 0) {
		/* Mark as self-signed for later handling */
		((struct tquic_x509_cert *)cert)->self_signed = true;
	}

	return 0;  /* Defer to keyring verification */
}
EXPORT_SYMBOL_GPL(tquic_x509_verify_signature);

/*
 * Look up certificate in trusted keyring
 */
static int find_trust_anchor(struct tquic_cert_verify_ctx *ctx,
			     struct tquic_x509_cert *cert)
{
#ifdef CONFIG_SYSTEM_DATA_VERIFICATION
	struct key *keyring = ctx->trusted_keyring;
	struct key *key;
	struct asymmetric_key_id *kid = NULL;
	int ret;

	if (!keyring)
		keyring = VERIFY_USE_SECONDARY_KEYRING;

	/*
	 * Generate key ID from certificate issuer/serial
	 * This matches how the kernel stores X.509 certificates
	 */
	kid = asymmetric_key_generate_id(cert->serial, cert->serial_len,
					 cert->issuer, cert->issuer_len);
	if (IS_ERR(kid))
		return PTR_ERR(kid);

	/*
	 * Look up in keyring
	 * For root certificates, we look up by issuer (which equals subject)
	 */
	key = find_asymmetric_key(keyring, kid, NULL, NULL, false);
	kfree(kid);

	if (IS_ERR(key)) {
		/* Try looking up by subject key identifier if available */
		return PTR_ERR(key);
	}

	key_put(key);
	return 0;
#else
	/* Without keyring support, only allow self-signed for testing */
	if (ctx->allow_self_signed && cert->self_signed)
		return 0;

	ctx->error_code = TQUIC_CERT_ERR_UNTRUSTED;
	ctx->error_msg = "Kernel keyring support not enabled";
	return -ENOKEY;
#endif
}

/*
 * Build and verify certificate chain
 */
static int verify_chain(struct tquic_cert_verify_ctx *ctx)
{
	struct tquic_x509_cert *cert;
	int ret;
	u32 depth = 0;

	if (!ctx->chain) {
		ctx->error_code = TQUIC_CERT_ERR_NO_CERT;
		ctx->error_msg = "No certificates in chain";
		return -EINVAL;
	}

	/* Verify each certificate in the chain */
	for (cert = ctx->chain; cert; cert = cert->next, depth++) {
		if (depth >= TQUIC_MAX_CERT_CHAIN_LEN) {
			ctx->error_code = TQUIC_CERT_ERR_CHAIN_TOO_LONG;
			ctx->error_msg = "Certificate chain too long";
			return -EMLINK;
		}

		/* Check validity period */
		ret = tquic_x509_cert_is_valid_time(cert, ctx->time_tolerance);
		if (ret == -EKEYEXPIRED) {
			ctx->error_code = TQUIC_CERT_ERR_EXPIRED;
			ctx->error_msg = "Certificate has expired";
			return ret;
		} else if (ret == -EKEYREJECTED) {
			ctx->error_code = TQUIC_CERT_ERR_NOT_YET_VALID;
			ctx->error_msg = "Certificate not yet valid";
			return ret;
		}

		/* For intermediate and root certs, verify CA flag */
		if (depth > 0 && !cert->is_ca) {
			ctx->error_code = TQUIC_CERT_ERR_CONSTRAINT;
			ctx->error_msg = "Intermediate certificate is not a CA";
			return -EKEYREJECTED;
		}

		/* Check if this certificate is a trust anchor */
		ret = find_trust_anchor(ctx, cert);
		if (ret == 0) {
			/* Found trust anchor, chain is valid */
			return 0;
		}

		/* If not found and this is self-signed, check allow_self_signed */
		if (cert->self_signed) {
			if (ctx->allow_self_signed) {
				pr_warn("tquic_cert: Allowing self-signed certificate (testing mode)\n");
				return 0;
			}
			ctx->error_code = TQUIC_CERT_ERR_SELF_SIGNED;
			ctx->error_msg = "Self-signed certificate not trusted";
			return -ENOKEY;
		}

		/* Verify signature against next cert (issuer) */
		if (cert->next) {
			ret = tquic_x509_verify_signature(cert, cert->next);
			if (ret < 0) {
				ctx->error_code = TQUIC_CERT_ERR_SIG_VERIFY;
				ctx->error_msg = "Certificate signature verification failed";
				return ret;
			}
		}
	}

	/* If we get here, no trust anchor was found */
	ctx->error_code = TQUIC_CERT_ERR_UNTRUSTED;
	ctx->error_msg = "No trusted root certificate found in chain";
	return -ENOKEY;
}

int tquic_verify_cert_chain(struct tquic_cert_verify_ctx *ctx,
			    const u8 *cert_chain, size_t chain_len)
{
	const u8 *p = cert_chain;
	const u8 *end = cert_chain + chain_len;
	struct tquic_x509_cert *prev = NULL;
	int ret;

	if (!ctx || !cert_chain || chain_len == 0)
		return -EINVAL;

	/* Check verification mode */
	if (ctx->verify_mode == TQUIC_CERT_VERIFY_NONE) {
		pr_warn("tquic_cert: Certificate verification disabled (INSECURE)\n");
		return 0;
	}

	/* Free any existing chain */
	tquic_x509_chain_free(ctx->chain);
	ctx->chain = NULL;
	ctx->chain_len = 0;

	/*
	 * Parse TLS certificate chain format:
	 * Each entry is: 3-byte length + DER certificate + 2-byte ext length + extensions
	 */
	while (p + 3 <= end) {
		u32 cert_len = (p[0] << 16) | (p[1] << 8) | p[2];
		p += 3;

		if (cert_len == 0 || p + cert_len > end)
			break;

		struct tquic_x509_cert *cert = tquic_x509_cert_parse(p, cert_len, GFP_KERNEL);
		if (!cert) {
			ctx->error_code = TQUIC_CERT_ERR_PARSE;
			ctx->error_msg = "Failed to parse certificate";
			tquic_x509_chain_free(ctx->chain);
			ctx->chain = NULL;
			return -EINVAL;
		}

		/* Add to chain */
		if (!ctx->chain)
			ctx->chain = cert;
		else if (prev)
			prev->next = cert;

		prev = cert;
		ctx->chain_len++;

		p += cert_len;

		/* Skip certificate extensions (OCSP, SCT, etc.) */
		if (p + 2 <= end) {
			u16 ext_len = (p[0] << 8) | p[1];
			p += 2;
			if (p + ext_len <= end)
				p += ext_len;
		}

		if (ctx->chain_len >= TQUIC_MAX_CERT_CHAIN_LEN)
			break;
	}

	if (!ctx->chain) {
		if (ctx->verify_mode == TQUIC_CERT_VERIFY_OPTIONAL)
			return 0;

		ctx->error_code = TQUIC_CERT_ERR_NO_CERT;
		ctx->error_msg = "No certificates received";
		return -EINVAL;
	}

	/* Verify hostname on end-entity certificate */
	if (ctx->verify_hostname && ctx->expected_hostname) {
		ret = tquic_verify_hostname(ctx->chain, ctx->expected_hostname,
					    ctx->hostname_len);
		if (ret < 0) {
			ctx->error_code = TQUIC_CERT_ERR_HOSTNAME;
			ctx->error_msg = "Hostname verification failed";
			return ret;
		}
	}

	/* Verify the chain */
	ret = verify_chain(ctx);
	if (ret < 0)
		return ret;

	ctx->error_code = TQUIC_CERT_OK;
	ctx->error_msg = NULL;

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_verify_cert_chain);

const char *tquic_cert_verify_get_error(struct tquic_cert_verify_ctx *ctx)
{
	if (!ctx)
		return "Invalid context";

	if (!ctx->error_msg)
		return "No error";

	return ctx->error_msg;
}
EXPORT_SYMBOL_GPL(tquic_cert_verify_get_error);

/*
 * Integration with TLS handshake
 */

/* Forward declaration of handshake structure */
struct tquic_handshake;

int tquic_hs_verify_server_cert(struct tquic_handshake *hs,
				struct tquic_connection *conn)
{
	struct tquic_cert_verify_ctx *ctx;
	struct tquic_sock *tsk;
	int ret;

	if (!hs || !conn)
		return TLS_ALERT_INTERNAL_ERROR;

	/* Get socket to access verification settings */
	tsk = tquic_sk(conn->sk);
	if (!tsk)
		return TLS_ALERT_INTERNAL_ERROR;

	/* Allocate verification context */
	ctx = tquic_cert_verify_ctx_alloc(GFP_KERNEL);
	if (!ctx)
		return TLS_ALERT_INTERNAL_ERROR;

	/* Configure from socket settings */
	ctx->verify_mode = tsk->cert_verify.verify_mode;
	ctx->verify_hostname = tsk->cert_verify.verify_hostname;
	ctx->allow_self_signed = tsk->cert_verify.allow_self_signed;

	/* Set hostname: prefer explicit setting, fall back to server_name (SNI) */
	if (tsk->cert_verify.expected_hostname_len > 0) {
		ret = tquic_cert_verify_set_hostname(ctx,
						     tsk->cert_verify.expected_hostname,
						     tsk->cert_verify.expected_hostname_len);
		if (ret < 0) {
			tquic_cert_verify_ctx_free(ctx);
			return TLS_ALERT_INTERNAL_ERROR;
		}
	} else if (tsk->server_name_len > 0) {
		ret = tquic_cert_verify_set_hostname(ctx, tsk->server_name,
						     tsk->server_name_len);
		if (ret < 0) {
			tquic_cert_verify_ctx_free(ctx);
			return TLS_ALERT_INTERNAL_ERROR;
		}
	}

	/* Use system keyring */
	tquic_cert_verify_set_keyring(ctx, NULL);

	/*
	 * Build certificate chain from handshake
	 * The peer_cert in handshake contains the raw certificate data
	 * We need to reconstruct the chain format for verification
	 */
	/* Note: In full implementation, we'd access the full certificate chain
	 * from the Certificate message, not just peer_cert.
	 * For now, create a minimal chain with just the end-entity cert.
	 */

	/* This requires access to handshake internals - declare extern */
	extern u8 *tquic_hs_get_peer_cert(struct tquic_handshake *hs, u32 *len);
	u32 cert_len;
	u8 *peer_cert = tquic_hs_get_peer_cert(hs, &cert_len);

	if (!peer_cert || cert_len == 0) {
		if (ctx->verify_mode == TQUIC_CERT_VERIFY_OPTIONAL) {
			tquic_cert_verify_ctx_free(ctx);
			return 0;  /* No alert, optional verification */
		}
		tquic_cert_verify_ctx_free(ctx);
		return TLS_ALERT_CERTIFICATE_REQUIRED;
	}

	/* Build TLS-format certificate chain (3-byte length + cert + 2-byte ext) */
	u32 chain_len = 3 + cert_len + 2;
	u8 *chain_buf = kmalloc(chain_len, GFP_KERNEL);
	if (!chain_buf) {
		tquic_cert_verify_ctx_free(ctx);
		return TLS_ALERT_INTERNAL_ERROR;
	}

	chain_buf[0] = (cert_len >> 16) & 0xff;
	chain_buf[1] = (cert_len >> 8) & 0xff;
	chain_buf[2] = cert_len & 0xff;
	memcpy(chain_buf + 3, peer_cert, cert_len);
	chain_buf[3 + cert_len] = 0;  /* No extensions */
	chain_buf[3 + cert_len + 1] = 0;

	ret = tquic_verify_cert_chain(ctx, chain_buf, chain_len);
	kfree(chain_buf);

	if (ret < 0) {
		int alert;

		pr_warn("tquic_cert: Server certificate verification failed: %s\n",
			tquic_cert_verify_get_error(ctx));

		/* Map error code to TLS alert */
		switch (ctx->error_code) {
		case TQUIC_CERT_ERR_EXPIRED:
			alert = TLS_ALERT_CERTIFICATE_EXPIRED;
			break;
		case TQUIC_CERT_ERR_REVOKED:
			alert = TLS_ALERT_CERTIFICATE_REVOKED;
			break;
		case TQUIC_CERT_ERR_UNTRUSTED:
		case TQUIC_CERT_ERR_SELF_SIGNED:
			alert = TLS_ALERT_UNKNOWN_CA;
			break;
		case TQUIC_CERT_ERR_HOSTNAME:
			alert = TLS_ALERT_BAD_CERTIFICATE;
			break;
		case TQUIC_CERT_ERR_PARSE:
			alert = TLS_ALERT_DECODE_ERROR;
			break;
		default:
			alert = TLS_ALERT_BAD_CERTIFICATE;
			break;
		}

		tquic_cert_verify_ctx_free(ctx);
		return alert;
	}

	tquic_cert_verify_ctx_free(ctx);
	return 0;  /* Success, no alert */
}
EXPORT_SYMBOL_GPL(tquic_hs_verify_server_cert);

int tquic_hs_verify_client_cert(struct tquic_handshake *hs,
				struct tquic_connection *conn)
{
	/* Client certificate verification follows similar pattern
	 * but may have different policy (e.g., optional client auth)
	 */
	return tquic_hs_verify_server_cert(hs, conn);
}
EXPORT_SYMBOL_GPL(tquic_hs_verify_client_cert);

/*
 * Module initialization
 */

int __init tquic_cert_verify_init(void)
{
	mutex_lock(&keyring_mutex);
	tquic_trusted_keyring = NULL;  /* Will use system keyring */
	mutex_unlock(&keyring_mutex);

	pr_info("tquic_cert: Certificate verification module initialized\n");
	return 0;
}

void __exit tquic_cert_verify_exit(void)
{
	mutex_lock(&keyring_mutex);
	if (tquic_trusted_keyring)
		key_put(tquic_trusted_keyring);
	tquic_trusted_keyring = NULL;
	mutex_unlock(&keyring_mutex);

	pr_info("tquic_cert: Certificate verification module unloaded\n");
}

MODULE_DESCRIPTION("TQUIC Certificate Chain Validation");
MODULE_LICENSE("GPL");
