// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Certificate Chain Validation
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Implements X.509 certificate chain validation for TQUIC TLS 1.3
 * connections. Uses the kernel's asymmetric key infrastructure and
 * system keyring for trusted root certificate storage.
 *
 * This module provides proper certificate validation including:
 *   - Certificate chain parsing and building
 *   - Signature verification using kernel crypto API
 *   - Hostname verification with wildcard support (RFC 6125)
 *   - Trust anchor lookup in system/platform keyrings
 *   - Validity period checking with clock skew tolerance
 *   - Key usage and path length constraint validation
 *   - Certificate revocation checking (OCSP stapling support)
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/capability.h>
#include <linux/overflow.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/time64.h>
#include <linux/key.h>
#include <linux/verification.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uaccess.h>
#include <crypto/public_key.h>
#include <crypto/hash.h>
#include <crypto/utils.h>
#include <crypto/sig.h>
#include <keys/asymmetric-type.h>
#include <keys/system_keyring.h>
#include <net/tquic.h>

#include "cert_verify.h"
#include "../tquic_compat.h"
#include "../tquic_debug.h"

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
static const u8 oid_authority_key_id[] = { 0x55, 0x1d, 0x23 };
static const u8 oid_subject_key_id[] = { 0x55, 0x1d, 0x0e };
static const u8 __maybe_unused oid_crl_distribution_points[] = { 0x55, 0x1d, 0x1f };
static const u8 __maybe_unused oid_authority_info_access[] = { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01 };
/* Name Constraints OID: 2.5.29.30 */
static const u8 oid_name_constraints[] = { 0x55, 0x1d, 0x1e };

/* Common Name OID: 2.5.4.3 */
static const u8 oid_common_name[] = { 0x55, 0x04, 0x03 };

/* Signature algorithm OIDs */
static const u8 oid_sha256_rsa[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b };
static const u8 oid_sha384_rsa[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c };
static const u8 oid_sha512_rsa[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d };
static const u8 oid_sha256_ecdsa[] = { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02 };
static const u8 oid_sha384_ecdsa[] = { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03 };
static const u8 oid_sha512_ecdsa[] = { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04 };
static const u8 oid_rsa_pss[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a };
static const u8 oid_ed25519[] = { 0x2b, 0x65, 0x70 };

/* Public key algorithm OIDs */
static const u8 oid_rsa_encryption[] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
static const u8 oid_ec_public_key[] = { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01 };

/* EC curve OIDs */
static const u8 oid_secp256r1[] = { 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };
static const u8 oid_secp384r1[] = { 0x2b, 0x81, 0x04, 0x00, 0x22 };
static const u8 oid_secp521r1[] = { 0x2b, 0x81, 0x04, 0x00, 0x23 };

/* Extended key usage OIDs */
static const u8 oid_server_auth[] = { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01 };
static const u8 oid_client_auth[] = { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x02 };

/* OCSP responder OID */
static const u8 __maybe_unused oid_ocsp[] = { 0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01 };

/* Default clock skew tolerance: 5 minutes */
#define DEFAULT_TIME_TOLERANCE	300

/* Default minimum key sizes */
#define DEFAULT_MIN_RSA_BITS	2048
#define DEFAULT_MIN_EC_BITS	256

/* Sysctl tunables */
static int tquic_cert_verify_mode = TQUIC_CERT_VERIFY_REQUIRED;
static int tquic_cert_verify_hostname_enabled = 1;
static int tquic_cert_revocation_mode = TQUIC_REVOKE_SOFT_FAIL;
static int tquic_cert_time_tolerance = DEFAULT_TIME_TOLERANCE;
static int tquic_cert_min_rsa_bits = DEFAULT_MIN_RSA_BITS;
static int tquic_cert_min_ec_bits = DEFAULT_MIN_EC_BITS;

/* Module-level trusted keyring */
static struct key *tquic_trusted_keyring;
static DEFINE_MUTEX(keyring_mutex);

/* Procfs directory */
static struct proc_dir_entry *tquic_cert_proc_dir;

/*
 * ASN.1 parsing helpers
 */

static int asn1_get_length(const u8 *data, u32 data_len, u32 *len, u32 *hdr_len)
{
	tquic_dbg("asn1_get_length: data_len=%u\n", data_len);

	if (data_len < 1)
		return -EINVAL;

	if (data[0] < 0x80) {
		*len = data[0];
		*hdr_len = 1;
	} else if (data[0] == 0x80) {
		/* Indefinite length encoding not supported in DER */
		return -EINVAL;
	} else if (data[0] == 0x81) {
		if (data_len < 2)
			return -EINVAL;
		*len = data[1];
		/* DER: long form must not be used for lengths < 128 */
		if (*len < 0x80)
			return -EINVAL;
		*hdr_len = 2;
	} else if (data[0] == 0x82) {
		if (data_len < 3)
			return -EINVAL;
		*len = (data[1] << 8) | data[2];
		/* DER: must use minimal length encoding */
		if (*len < 0x100)
			return -EINVAL;
		*hdr_len = 3;
	} else if (data[0] == 0x83) {
		if (data_len < 4)
			return -EINVAL;
		*len = (data[1] << 16) | (data[2] << 8) | data[3];
		/* DER: must use minimal length encoding */
		if (*len < 0x10000)
			return -EINVAL;
		*hdr_len = 4;
	} else {
		/* Reject 4+ byte length encodings (> 16MB not expected) */
		return -EINVAL;
	}

	/* Sanity check: content length must not exceed remaining data */
	if (*len > data_len - *hdr_len)
		return -EINVAL;

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

	/* Check for overflow in total_len computation */
	if (check_add_overflow(1u + hdr_len, len, total_len))
		return -EOVERFLOW;

	if (*total_len > data_len)
		return -EINVAL;

	return 0;
}

/*
 * Identify signature algorithm from OID
 */
/* Hash algorithm OIDs for RSA-PSS parameter parsing (RFC 4055) */
static const u8 oid_sha256_hash[] = {
	0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01
};
static const u8 oid_sha384_hash[] = {
	0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02
};
static const u8 oid_sha512_hash[] = {
	0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03
};

/*
 * CF-150: parse RSA-PSS hash from AlgorithmIdentifier
 *
 * RSA-PSS parameters (RFC 4055 Section 3.1):
 *   RSASSA-PSS-params ::= SEQUENCE {
 *     hashAlgorithm      [0] HashAlgorithm DEFAULT sha1,
 *     maskGenAlgorithm   [1] MaskGenAlgorithm DEFAULT mgf1SHA1,
 *     saltLength         [2] INTEGER DEFAULT 20,
 *     trailerField       [3] TrailerField DEFAULT trailerFieldBC
 *   }
 *
 * Returns the hash algo from the [0] tagged hashAlgorithm field,
 * or TQUIC_HASH_SHA256 if parameters are absent (RFC 4055 default
 * is SHA-1 but TLS 1.3 only uses SHA-256/384/512 with RSA-PSS).
 */
static enum tquic_hash_algo parse_rsa_pss_hash(const u8 *params,
					       u32 params_len)
{
	const u8 *p, *seq_end;
	u32 content_len, total_len, oid_content_len, oid_total_len;
	int ret;

	if (!params || params_len == 0)
		return TQUIC_HASH_SHA256;

	/* Parameters should be a SEQUENCE */
	ret = asn1_get_tag_length(params, params_len, ASN1_SEQUENCE,
				  &content_len, &total_len);
	if (ret < 0)
		return TQUIC_HASH_SHA256;

	p = params + (total_len - content_len);
	seq_end = p + content_len;

	/* Look for [0] EXPLICIT hashAlgorithm */
	if (p >= seq_end || p[0] != 0xA0)
		return TQUIC_HASH_SHA256;

	ret = asn1_get_length(p + 1, seq_end - p - 1,
			      &content_len, &total_len);
	if (ret < 0)
		return TQUIC_HASH_SHA256;

	p += 1 + total_len;
	/* p now points at hashAlgorithm AlgorithmIdentifier content */
	/* Rewind to content start */
	p -= content_len;

	/* Inner AlgorithmIdentifier SEQUENCE */
	ret = asn1_get_tag_length(p, content_len, ASN1_SEQUENCE,
				  &content_len, &total_len);
	if (ret < 0)
		return TQUIC_HASH_SHA256;

	p += total_len - content_len;

	/* Extract the hash OID */
	ret = asn1_get_tag_length(p, content_len, ASN1_OID,
				  &oid_content_len, &oid_total_len);
	if (ret < 0)
		return TQUIC_HASH_SHA256;

	p += oid_total_len - oid_content_len;

	if (oid_content_len == sizeof(oid_sha256_hash) &&
	    memcmp(p, oid_sha256_hash, oid_content_len) == 0)
		return TQUIC_HASH_SHA256;
	if (oid_content_len == sizeof(oid_sha384_hash) &&
	    memcmp(p, oid_sha384_hash, oid_content_len) == 0)
		return TQUIC_HASH_SHA384;
	if (oid_content_len == sizeof(oid_sha512_hash) &&
	    memcmp(p, oid_sha512_hash, oid_content_len) == 0)
		return TQUIC_HASH_SHA512;

	/* Unrecognized hash OID -- default to SHA-256 */
	return TQUIC_HASH_SHA256;
}

static void identify_sig_algo(const u8 *oid, u32 oid_len,
			      const u8 *params, u32 params_len,
			      enum tquic_hash_algo *hash_algo,
			      enum tquic_pubkey_algo *pubkey_algo)
{
	*hash_algo = TQUIC_HASH_UNKNOWN;
	*pubkey_algo = TQUIC_PUBKEY_ALGO_UNKNOWN;

	if (oid_len == sizeof(oid_sha256_rsa) &&
	    memcmp(oid, oid_sha256_rsa, oid_len) == 0) {
		*hash_algo = TQUIC_HASH_SHA256;
		*pubkey_algo = TQUIC_PUBKEY_ALGO_RSA;
	} else if (oid_len == sizeof(oid_sha384_rsa) &&
		   memcmp(oid, oid_sha384_rsa, oid_len) == 0) {
		*hash_algo = TQUIC_HASH_SHA384;
		*pubkey_algo = TQUIC_PUBKEY_ALGO_RSA;
	} else if (oid_len == sizeof(oid_sha512_rsa) &&
		   memcmp(oid, oid_sha512_rsa, oid_len) == 0) {
		*hash_algo = TQUIC_HASH_SHA512;
		*pubkey_algo = TQUIC_PUBKEY_ALGO_RSA;
	} else if (oid_len == sizeof(oid_sha256_ecdsa) &&
		   memcmp(oid, oid_sha256_ecdsa, oid_len) == 0) {
		*hash_algo = TQUIC_HASH_SHA256;
		*pubkey_algo = TQUIC_PUBKEY_ALGO_ECDSA_P256;
	} else if (oid_len == sizeof(oid_sha384_ecdsa) &&
		   memcmp(oid, oid_sha384_ecdsa, oid_len) == 0) {
		*hash_algo = TQUIC_HASH_SHA384;
		*pubkey_algo = TQUIC_PUBKEY_ALGO_ECDSA_P384;
	} else if (oid_len == sizeof(oid_sha512_ecdsa) &&
		   memcmp(oid, oid_sha512_ecdsa, oid_len) == 0) {
		*hash_algo = TQUIC_HASH_SHA512;
		*pubkey_algo = TQUIC_PUBKEY_ALGO_ECDSA_P521;
	} else if (oid_len == sizeof(oid_rsa_pss) &&
		   memcmp(oid, oid_rsa_pss, oid_len) == 0) {
		/* CF-150: parse RSA-PSS hash from AlgorithmIdentifier */
		*hash_algo = parse_rsa_pss_hash(params, params_len);
		*pubkey_algo = TQUIC_PUBKEY_ALGO_RSA;
	} else if (oid_len == sizeof(oid_ed25519) &&
		   memcmp(oid, oid_ed25519, oid_len) == 0) {
		*hash_algo = TQUIC_HASH_UNKNOWN;  /* Ed25519 uses internal hash */
		*pubkey_algo = TQUIC_PUBKEY_ALGO_ED25519;
	}
}

/*
 * Identify public key algorithm from OID
 */
static void identify_pubkey_algo(const u8 *oid, u32 oid_len,
				 const u8 *params, u32 params_len,
				 enum tquic_pubkey_algo *pubkey_algo,
				 u32 *key_bits)
{
	*pubkey_algo = TQUIC_PUBKEY_ALGO_UNKNOWN;
	*key_bits = 0;

	if (oid_len == sizeof(oid_rsa_encryption) &&
	    memcmp(oid, oid_rsa_encryption, oid_len) == 0) {
		*pubkey_algo = TQUIC_PUBKEY_ALGO_RSA;
		/* Key bits extracted from key data later */
	} else if (oid_len == sizeof(oid_ec_public_key) &&
		   memcmp(oid, oid_ec_public_key, oid_len) == 0) {
		/* Identify curve from parameters */
		if (params && params_len >= sizeof(oid_secp256r1)) {
			if (params_len == sizeof(oid_secp256r1) &&
			    memcmp(params, oid_secp256r1, params_len) == 0) {
				*pubkey_algo = TQUIC_PUBKEY_ALGO_ECDSA_P256;
				*key_bits = 256;
			} else if (params_len == sizeof(oid_secp384r1) &&
				   memcmp(params, oid_secp384r1, params_len) == 0) {
				*pubkey_algo = TQUIC_PUBKEY_ALGO_ECDSA_P384;
				*key_bits = 384;
			} else if (params_len == sizeof(oid_secp521r1) &&
				   memcmp(params, oid_secp521r1, params_len) == 0) {
				*pubkey_algo = TQUIC_PUBKEY_ALGO_ECDSA_P521;
				*key_bits = 521;
			}
		}
	} else if (oid_len == sizeof(oid_ed25519) &&
		   memcmp(oid, oid_ed25519, oid_len) == 0) {
		*pubkey_algo = TQUIC_PUBKEY_ALGO_ED25519;
		*key_bits = 256;
	}
}

/*
 * Get hash algorithm name for kernel crypto API
 */
static const char *get_hash_algo_name(enum tquic_hash_algo algo)
{
	switch (algo) {
	case TQUIC_HASH_SHA256:
		return "sha256";
	case TQUIC_HASH_SHA384:
		return "sha384";
	case TQUIC_HASH_SHA512:
		return "sha512";
	default:
		return NULL;
	}
}

/*
 * Get hash digest size
 */
static u32 get_hash_digest_size(enum tquic_hash_algo algo)
{
	tquic_dbg("get_hash_digest_size: algo=%d\n", algo);

	switch (algo) {
	case TQUIC_HASH_SHA256:
		return 32;
	case TQUIC_HASH_SHA384:
		return 48;
	case TQUIC_HASH_SHA512:
		return 64;
	default:
		return 0;
	}
}

/*
 * Parse X.500 Distinguished Name to extract Common Name
 */
static int parse_dn_extract_cn(const u8 *data, u32 len, char **cn, u32 *cn_len)
{
	const u8 *p = data;
	const u8 *end = data + len;

	tquic_dbg("parse_dn_extract_cn: dn_len=%u\n", len);

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
			       char ***dns_names, u32 *dns_count,
			       u8 ***ip_addrs, u32 **ip_lens, u32 *ip_count)
{
	const u8 *p = data;
	const u8 *end = data + len;
	char **names = NULL;
	u8 **ips = NULL;
	u32 *ip_lengths = NULL;
	u32 name_count = 0;
	u32 addr_count = 0;
	size_t name_capacity = 4;
	size_t ip_capacity = 4;

	names = kcalloc(name_capacity, sizeof(char *), GFP_KERNEL);
	if (!names)
		return -ENOMEM;

	ips = kcalloc(ip_capacity, sizeof(u8 *), GFP_KERNEL);
	if (!ips) {
		kfree_sensitive(names);
		return -ENOMEM;
	}

	ip_lengths = kcalloc(ip_capacity, sizeof(u32), GFP_KERNEL);
	if (!ip_lengths) {
		kfree_sensitive(names);
		kfree_sensitive(ips);
		return -ENOMEM;
	}

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
			if (name_count >= name_capacity) {
				size_t new_cap = name_capacity * 2;
				char **new_names;

				/*
				 * CF-560: Tighten SAN name capacity limit.
				 * 256 DNS names is generous for any real cert.
				 */
				if (name_capacity >= 256)
					goto err_free;
				new_names = krealloc_array(names, new_cap,
							   sizeof(char *),
							   GFP_KERNEL);
				if (!new_names)
					goto err_free;
				names = new_names;
				name_capacity = new_cap;
			}

			/*
			 * CF-413: Reject SAN DNS names containing embedded
			 * NUL bytes to prevent truncation attacks where
			 * "evil.com\0.good.com" matches "evil.com".
			 */
			if (memchr(p + 1 + hdr_len, 0, content_len)) {
				p += 1 + hdr_len + content_len;
				continue;
			}

			names[name_count] = kmalloc(content_len + 1, GFP_KERNEL);
			if (!names[name_count])
				goto err_free;

			memcpy(names[name_count], p + 1 + hdr_len, content_len);
			names[name_count][content_len] = '\0';
			name_count++;
		}
		/* iPAddress is context tag [7] */
		else if ((tag & 0x1f) == 7 && (tag & 0xc0) == 0x80) {
			if (content_len == 4 || content_len == 16) {
				if (addr_count >= ip_capacity) {
					size_t new_cap = ip_capacity * 2;
					u8 **new_ips;
					u32 *new_lens;

					if (ip_capacity >= 256)
						goto err_free;
					new_ips = krealloc_array(ips, new_cap,
								 sizeof(u8 *),
								 GFP_KERNEL);
					if (!new_ips)
						goto err_free;
					ips = new_ips;
					new_lens = krealloc_array(ip_lengths,
								  new_cap,
								  sizeof(u32),
								  GFP_KERNEL);
					if (!new_lens)
						goto err_free;
					ip_lengths = new_lens;
					ip_capacity = new_cap;
				}

				ips[addr_count] = kmalloc(content_len, GFP_KERNEL);
				if (!ips[addr_count])
					goto err_free;

				memcpy(ips[addr_count], p + 1 + hdr_len, content_len);
				ip_lengths[addr_count] = content_len;
				addr_count++;
			}
		}

		p += 1 + hdr_len + content_len;
	}

	*dns_names = names;
	*dns_count = name_count;
	*ip_addrs = ips;
	*ip_lens = ip_lengths;
	*ip_count = addr_count;
	return 0;

err_free:
	{
		u32 j;

		for (j = 0; j < name_count; j++)
			kfree_sensitive(names[j]);
		kfree_sensitive(names);
		for (j = 0; j < addr_count; j++)
			kfree_sensitive(ips[j]);
	}
	kfree_sensitive(ips);
	kfree_sensitive(ip_lengths);
	return -ENOMEM;
}

/*
 * Parse key usage extension
 */
static int parse_key_usage(const u8 *data, u32 len, u16 *key_usage)
{
	u32 content_len, total_len;
	int ret;

	tquic_dbg("parse_key_usage: data_len=%u\n", len);

	ret = asn1_get_tag_length(data, len, ASN1_BIT_STRING,
				  &content_len, &total_len);
	if (ret < 0)
		return ret;

	const u8 *bits = data + (total_len - content_len);
	if (content_len < 2)
		return -EINVAL;

	u8 unused_bits = bits[0];
	if (unused_bits > 7)
		return -EINVAL;

	*key_usage = 0;
	if (content_len >= 2)
		*key_usage = bits[1];
	if (content_len >= 3)
		*key_usage |= (bits[2] << 8);

	return 0;
}

/*
 * Parse extended key usage extension
 */
static int parse_ext_key_usage(const u8 *data, u32 len, u32 *ext_key_usage)
{
	const u8 *p = data;
	const u8 *end = data + len;
	u32 content_len, total_len;
	int ret;

	tquic_dbg("parse_ext_key_usage: data_len=%u\n", len);

	/* SEQUENCE of OIDs */
	ret = asn1_get_tag_length(p, end - p, ASN1_SEQUENCE,
				  &content_len, &total_len);
	if (ret < 0)
		return ret;

	p += (total_len - content_len);
	end = p + content_len;

	*ext_key_usage = 0;

	while (p < end) {
		u32 oid_content_len, oid_total_len;

		ret = asn1_get_tag_length(p, end - p, ASN1_OID,
					  &oid_content_len, &oid_total_len);
		if (ret < 0)
			break;

		const u8 *oid = p + (oid_total_len - oid_content_len);

		if (oid_content_len == sizeof(oid_server_auth) &&
		    memcmp(oid, oid_server_auth, oid_content_len) == 0)
			*ext_key_usage |= TQUIC_EKU_SERVER_AUTH;

		if (oid_content_len == sizeof(oid_client_auth) &&
		    memcmp(oid, oid_client_auth, oid_content_len) == 0)
			*ext_key_usage |= TQUIC_EKU_CLIENT_AUTH;

		p += oid_total_len;
	}

	return 0;
}

/*
 * Parse basic constraints extension
 */
static int parse_basic_constraints(const u8 *data, u32 len,
				   bool *is_ca, int *path_len)
{
	const u8 *p = data;
	const u8 *end = data + len;
	u32 content_len, total_len;
	int ret;

	*is_ca = false;
	*path_len = -1;

	/* SEQUENCE */
	ret = asn1_get_tag_length(p, end - p, ASN1_SEQUENCE,
				  &content_len, &total_len);
	if (ret < 0)
		return ret;

	p += (total_len - content_len);
	end = p + content_len;

	/* Optional CA BOOLEAN */
	if (p < end && p[0] == 0x01) {  /* BOOLEAN */
		/*
		 * CF-555: Parse the BOOLEAN properly instead of
		 * hardcoding length=3.  DER BOOLEAN is always
		 * 01 01 xx but validate the length byte.
		 */
		if (p + 2 <= end && p[1] == 0x01 && p + 3 <= end) {
			*is_ca = (p[2] != 0);
			p += 3;
		} else if (p + 2 <= end) {
			/* Non-standard BOOLEAN length - skip it */
			u32 blen = p[1];

			if (p + 2 + blen <= end)
				p += 2 + blen;
		}
	}

	/* Optional pathLenConstraint INTEGER */
	if (p < end && p[0] == ASN1_INTEGER) {
		u32 int_content_len, int_total_len;

		ret = asn1_get_tag_length(p, end - p, ASN1_INTEGER,
					  &int_content_len, &int_total_len);
		if (ret == 0 && int_content_len == 1) {
			*path_len = p[int_total_len - 1];
		}
	}

	return 0;
}

/*
 * Parse a GeneralSubtrees sequence into name_constraint array entries.
 * Each GeneralSubtree is SEQUENCE { GeneralName, minimum, maximum }.
 * We only extract dNSName [2] and rfc822Name [1] types.
 */
static int parse_general_subtrees(const u8 *data, u32 len,
				  struct tquic_name_constraint *out,
				  u32 max_entries, u32 *nr_entries,
				  bool *has_unsupported)
{
	const u8 *p = data;
	const u8 *end = data + len;
	u32 count = 0;

	while (p < end && count < max_entries) {
		u32 subtree_content, subtree_total;
		u32 name_content, name_hdr;
		u8 tag;
		int ret;

		/* Each GeneralSubtree is a SEQUENCE */
		ret = asn1_get_tag_length(p, end - p, ASN1_SEQUENCE,
					  &subtree_content, &subtree_total);
		if (ret < 0)
			break;

		const u8 *st = p + (subtree_total - subtree_content);
		u32 st_len = subtree_content;

		if (st_len < 2) {
			p += subtree_total;
			continue;
		}

		/* First element is GeneralName (context-tagged) */
		tag = st[0];

		ret = asn1_get_length(st + 1, st_len - 1,
				      &name_content, &name_hdr);
		if (ret < 0) {
			p += subtree_total;
			continue;
		}

		/*
		 * dNSName [2] IMPLICIT IA5String
		 * rfc822Name [1] IMPLICIT IA5String
		 */
		if ((tag & 0xc0) == 0x80) {
			u8 name_type = tag & 0x1f;

			if (name_type == TQUIC_NC_TYPE_DNS ||
			    name_type == TQUIC_NC_TYPE_EMAIL) {
				const u8 *name_data = st + 1 + name_hdr;
				char *name;

				if (name_content > 255) {
					p += subtree_total;
					continue;
				}

				name = kmalloc(name_content + 1, GFP_KERNEL);
				if (!name)
					return -ENOMEM;

				memcpy(name, name_data, name_content);
				name[name_content] = '\0';

				out[count].type = name_type;
				out[count].name = name;
				out[count].name_len = name_content;
				count++;
			} else {
				/*
				 * Unsupported GeneralName type (e.g.
				 * directoryName, iPAddress, uniformResourceIdentifier).
				 */
				*has_unsupported = true;
			}
		} else {
			*has_unsupported = true;
		}

		p += subtree_total;
	}

	*nr_entries = count;
	return 0;
}

/*
 * Parse nameConstraints extension value (RFC 5280 Section 4.2.1.10)
 *
 * NameConstraints ::= SEQUENCE {
 *   permittedSubtrees  [0] GeneralSubtrees OPTIONAL,
 *   excludedSubtrees   [1] GeneralSubtrees OPTIONAL
 * }
 */
static int parse_name_constraints(const u8 *data, u32 len,
				  bool critical,
				  struct tquic_name_constraints **out)
{
	struct tquic_name_constraints *nc;
	const u8 *p;
	const u8 *end;
	u32 seq_content, seq_total;
	int ret;

	ret = asn1_get_tag_length(data, len, ASN1_SEQUENCE,
				  &seq_content, &seq_total);
	if (ret < 0)
		return ret;

	nc = kzalloc(sizeof(*nc), GFP_KERNEL);
	if (!nc)
		return -ENOMEM;

	nc->critical = critical;

	p = data + (seq_total - seq_content);
	end = p + seq_content;

	while (p < end) {
		u8 tag = p[0];
		u32 content_len, hdr_len;

		if (p + 2 > end)
			break;

		ret = asn1_get_length(p + 1, end - p - 1,
				      &content_len, &hdr_len);
		if (ret < 0)
			break;

		/* permittedSubtrees [0] IMPLICIT GeneralSubtrees */
		if (tag == 0xa0) {
			ret = parse_general_subtrees(
				p + 1 + hdr_len, content_len,
				nc->permitted,
				TQUIC_MAX_NAME_CONSTRAINTS,
				&nc->nr_permitted,
				&nc->has_unsupported_type);
			if (ret < 0)
				goto err_free;
		}
		/* excludedSubtrees [1] IMPLICIT GeneralSubtrees */
		else if (tag == 0xa1) {
			ret = parse_general_subtrees(
				p + 1 + hdr_len, content_len,
				nc->excluded,
				TQUIC_MAX_NAME_CONSTRAINTS,
				&nc->nr_excluded,
				&nc->has_unsupported_type);
			if (ret < 0)
				goto err_free;
		}

		p += 1 + hdr_len + content_len;
	}

	*out = nc;
	return 0;

err_free:
	{
		u32 i;

		for (i = 0; i < nc->nr_permitted; i++)
			kfree_sensitive(nc->permitted[i].name);
		for (i = 0; i < nc->nr_excluded; i++)
			kfree_sensitive(nc->excluded[i].name);
	}
	kfree_sensitive(nc);
	return ret;
}

/*
 * Free a name_constraints structure
 */
static void free_name_constraints(struct tquic_name_constraints *nc)
{
	u32 i;

	if (!nc)
		return;

	tquic_dbg("free_name_constraints: permitted=%u excluded=%u\n",
		  nc->nr_permitted, nc->nr_excluded);

	for (i = 0; i < nc->nr_permitted; i++)
		kfree_sensitive(nc->permitted[i].name);
	for (i = 0; i < nc->nr_excluded; i++)
		kfree_sensitive(nc->excluded[i].name);
	kfree_sensitive(nc);
}

/*
 * Check whether @name is within the subtree defined by @constraint.
 *
 * For DNS names (RFC 5280 Section 4.2.1.10):
 *   - An empty constraint matches everything.
 *   - A constraint starting with "." matches any name that ends with
 *     that suffix (e.g. ".example.com" matches "foo.example.com").
 *   - Otherwise, the name must exactly equal the constraint or end
 *     with "." + constraint.
 *
 * For email/rfc822Name:
 *   - If constraint contains "@", full address match.
 *   - If constraint starts with ".", domain suffix match on the
 *     domain part of the address.
 *   - Otherwise the domain part must exactly match.
 */
static bool name_in_subtree(const char *name, u32 name_len,
			    const struct tquic_name_constraint *constraint)
{
	const char *cname = constraint->name;
	u32 clen = constraint->name_len;

	if (clen == 0)
		return true;

	if (constraint->type == TQUIC_NC_TYPE_DNS) {
		/* Leading dot: suffix match */
		if (cname[0] == '.') {
			if (name_len > clen &&
			    strncasecmp(name + name_len - clen,
					cname, clen) == 0)
				return true;
			/* Also match if name equals constraint without dot */
			if (name_len == clen - 1 &&
			    strncasecmp(name, cname + 1, clen - 1) == 0)
				return true;
			return false;
		}
		/* Exact or parent-domain match */
		if (name_len == clen &&
		    strncasecmp(name, cname, clen) == 0)
			return true;
		if (name_len > clen + 1 &&
		    name[name_len - clen - 1] == '.' &&
		    strncasecmp(name + name_len - clen, cname, clen) == 0)
			return true;
		return false;
	}

	if (constraint->type == TQUIC_NC_TYPE_EMAIL) {
		const char *at;

		/* Constraint with "@": full address match */
		if (memchr(cname, '@', clen)) {
			return name_len == clen &&
			       strncasecmp(name, cname, clen) == 0;
		}

		/* Find "@" in the name to isolate domain */
		at = memchr(name, '@', name_len);
		if (!at)
			return false;

		{
			u32 domain_off = (u32)(at - name) + 1;
			const char *domain = name + domain_off;
			u32 domain_len = name_len - domain_off;

			if (cname[0] == '.') {
				/* Domain suffix match */
				if (domain_len > clen &&
				    strncasecmp(domain + domain_len - clen,
						cname, clen) == 0)
					return true;
				if (domain_len == clen - 1 &&
				    strncasecmp(domain,
						cname + 1, clen - 1) == 0)
					return true;
				return false;
			}
			/* Exact domain match */
			return domain_len == clen &&
			       strncasecmp(domain, cname, clen) == 0;
		}
	}

	return false;
}

/*
 * Check a single name against name constraints.
 * Returns 0 if the name passes, -EKEYREJECTED if it violates constraints.
 */
static int check_name_against_constraints(
	const char *name, u32 name_len, u8 name_type,
	const struct tquic_name_constraints *nc)
{
	u32 i;
	bool found_type_in_permitted = false;

	/* Check excluded subtrees first -- any match is a rejection */
	for (i = 0; i < nc->nr_excluded; i++) {
		if (nc->excluded[i].type != name_type)
			continue;
		if (name_in_subtree(name, name_len, &nc->excluded[i])) {
			pr_debug("tquic_cert: name '%.*s' in excluded subtree '%s'\n",
				 name_len, name, nc->excluded[i].name);
			return -EKEYREJECTED;
		}
	}

	/*
	 * Check permitted subtrees.  Per RFC 5280 Section 4.2.1.10:
	 * if permittedSubtrees contains entries for this name type,
	 * the name MUST fall within at least one of them.
	 */
	for (i = 0; i < nc->nr_permitted; i++) {
		if (nc->permitted[i].type != name_type)
			continue;
		found_type_in_permitted = true;
		if (name_in_subtree(name, name_len, &nc->permitted[i]))
			return 0;
	}

	if (found_type_in_permitted) {
		pr_debug("tquic_cert: name '%.*s' not in any permitted subtree\n",
			 name_len, name);
		return -EKEYREJECTED;
	}

	/* No permitted entries for this type -- name is unconstrained */
	return 0;
}

/*
 * Validate a subject certificate against a CA's name constraints.
 * Checks the subject's CN (as a DNS name) and all SAN entries.
 *
 * Returns 0 on success, -EKEYREJECTED on constraint violation.
 */
static int check_name_constraints(const struct tquic_x509_cert *subject,
				  const struct tquic_name_constraints *nc)
{
	int ret;
	u32 i;

	if (!nc)
		return 0;

	/*
	 * If the extension is critical and contains a constraint type
	 * we cannot process, we must reject (RFC 5280 Section 4.2).
	 */
	if (nc->critical && nc->has_unsupported_type) {
		pr_debug("tquic_cert: critical nameConstraints has unsupported type\n");
		return -EKEYREJECTED;
	}

	/* Check SAN DNS names */
	for (i = 0; i < subject->san_dns_count; i++) {
		ret = check_name_against_constraints(
			subject->san_dns[i],
			strlen(subject->san_dns[i]),
			TQUIC_NC_TYPE_DNS, nc);
		if (ret < 0)
			return ret;
	}

	/*
	 * If no SAN DNS names, fall back to checking CN as a DNS name.
	 * Per RFC 6125 the CN should only be checked when no SAN is
	 * present, and the same applies to name constraints per
	 * RFC 5280 Section 4.2.1.10 guidance.
	 */
	if (subject->san_dns_count == 0 && subject->subject &&
	    subject->subject_len > 0) {
		ret = check_name_against_constraints(
			subject->subject, subject->subject_len,
			TQUIC_NC_TYPE_DNS, nc);
		if (ret < 0)
			return ret;
	}

	return 0;
}

/*
 * Parse X.509 certificate extensions
 */
static int parse_extensions(struct tquic_x509_cert *cert,
			    const u8 *data, u32 len)
{
	const u8 *p = data;
	const u8 *end = data + len;

	cert->path_len_constraint = -1;

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
						/*
						 * CF-360: Check and propagate
						 * errors from SAN parsing.
						 */
						ret = parse_san_extension(
							val + (seq_total_len - seq_content_len),
							seq_content_len,
							&cert->san_dns,
							&cert->san_dns_count,
							&cert->san_ip,
							&cert->san_ip_len,
							&cert->san_ip_count);
						if (ret < 0)
							return ret;
					}
				}

				/* Basic Constraints */
				if (oid_content_len == sizeof(oid_basic_constraints) &&
				    memcmp(oid, oid_basic_constraints,
					   sizeof(oid_basic_constraints)) == 0) {
					parse_basic_constraints(val, val_content_len,
								&cert->is_ca,
								&cert->path_len_constraint);
				}

				/* Key Usage */
				if (oid_content_len == sizeof(oid_key_usage) &&
				    memcmp(oid, oid_key_usage,
					   sizeof(oid_key_usage)) == 0) {
					parse_key_usage(val, val_content_len,
							&cert->key_usage);
				}

				/* Extended Key Usage */
				if (oid_content_len == sizeof(oid_ext_key_usage) &&
				    memcmp(oid, oid_ext_key_usage,
					   sizeof(oid_ext_key_usage)) == 0) {
					parse_ext_key_usage(val, val_content_len,
							    &cert->ext_key_usage);
				}

				/* Subject Key Identifier */
				if (oid_content_len == sizeof(oid_subject_key_id) &&
				    memcmp(oid, oid_subject_key_id,
					   sizeof(oid_subject_key_id)) == 0) {
					/* OCTET STRING containing key id */
					u32 skid_content, skid_total;
					ret = asn1_get_tag_length(val, val_content_len,
								  ASN1_OCTET_STRING,
								  &skid_content,
								  &skid_total);
					if (ret == 0) {
						cert->skid = kmalloc(skid_content, GFP_KERNEL);
						if (cert->skid) {
							memcpy(cert->skid,
							       val + (skid_total - skid_content),
							       skid_content);
							cert->skid_len = skid_content;
						}
					}
				}

				/* Name Constraints */
				if (oid_content_len == sizeof(oid_name_constraints) &&
				    memcmp(oid, oid_name_constraints,
					   sizeof(oid_name_constraints)) == 0) {
					parse_name_constraints(
						val, val_content_len,
						critical,
						&cert->name_constraints);
				}

				/* Authority Key Identifier */
				if (oid_content_len == sizeof(oid_authority_key_id) &&
				    memcmp(oid, oid_authority_key_id,
					   sizeof(oid_authority_key_id)) == 0) {
					/* SEQUENCE containing key id */
					u32 seq_content, seq_total;
					ret = asn1_get_tag_length(val, val_content_len,
								  ASN1_SEQUENCE,
								  &seq_content,
								  &seq_total);
					if (ret == 0 && seq_content > 0) {
						const u8 *seq_data = val + (seq_total - seq_content);
						/* keyIdentifier [0] */
						if (seq_data[0] == 0x80) {
							u32 kid_len, kid_hdr;
							ret = asn1_get_length(seq_data + 1,
									      seq_content - 1,
									      &kid_len, &kid_hdr);
							if (ret == 0) {
								cert->akid = kmalloc(kid_len, GFP_KERNEL);
								if (cert->akid) {
									memcpy(cert->akid,
									       seq_data + 1 + kid_hdr,
									       kid_len);
									cert->akid_len = kid_len;
								}
							}
						}
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
/*
 * Parse a two-digit decimal field, validating that both characters are
 * ASCII digits and that the resulting value is within [min_val, max_val].
 * Returns 0 on success, -EINVAL on bad characters or out-of-range value.
 */
static int parse_2digit(const char *s, int min_val, int max_val, int *out)
{
	tquic_dbg("parse_2digit: min=%d max=%d\n", min_val, max_val);

	if (s[0] < '0' || s[0] > '9' || s[1] < '0' || s[1] > '9')
		return -EINVAL;
	*out = (s[0] - '0') * 10 + (s[1] - '0');
	if (*out < min_val || *out > max_val)
		return -EINVAL;
	return 0;
}

static int parse_time(const u8 *data, u32 len, s64 *time_out)
{
	int year, month, day, hour, min, sec;
	int yy;

	tquic_dbg("parse_time: tag=0x%02x len=%u\n", data[0], len);

	if (len < 13)
		return -EINVAL;

	if (data[0] == ASN1_UTC_TIME) {
		/* YYMMDDhhmmssZ */
		u32 content_len, hdr_len;
		const char *t;
		int ret = asn1_get_length(data + 1, len - 1,
					  &content_len, &hdr_len);
		if (ret < 0 || content_len < 12)
			return -EINVAL;

		t = (const char *)data + 1 + hdr_len;

		ret = parse_2digit(t, 0, 99, &yy);
		if (ret < 0)
			return ret;
		year = yy + ((yy < 50) ? 2000 : 1900);

		ret = parse_2digit(t + 2, 1, 12, &month);
		if (ret < 0)
			return ret;
		ret = parse_2digit(t + 4, 1, 31, &day);
		if (ret < 0)
			return ret;
		ret = parse_2digit(t + 6, 0, 23, &hour);
		if (ret < 0)
			return ret;
		ret = parse_2digit(t + 8, 0, 59, &min);
		if (ret < 0)
			return ret;
		ret = parse_2digit(t + 10, 0, 59, &sec);
		if (ret < 0)
			return ret;
	} else if (data[0] == ASN1_GENERALIZED_TIME) {
		/* YYYYMMDDhhmmssZ */
		u32 content_len, hdr_len;
		const char *t;
		int yy_hi, yy_lo;
		int ret = asn1_get_length(data + 1, len - 1,
					  &content_len, &hdr_len);
		if (ret < 0 || content_len < 14)
			return -EINVAL;

		t = (const char *)data + 1 + hdr_len;

		/* Year: 4 digits parsed as two 2-digit pairs */
		ret = parse_2digit(t, 0, 99, &yy_hi);
		if (ret < 0)
			return ret;
		ret = parse_2digit(t + 2, 0, 99, &yy_lo);
		if (ret < 0)
			return ret;
		year = yy_hi * 100 + yy_lo;

		ret = parse_2digit(t + 4, 1, 12, &month);
		if (ret < 0)
			return ret;
		ret = parse_2digit(t + 6, 1, 31, &day);
		if (ret < 0)
			return ret;
		ret = parse_2digit(t + 8, 0, 23, &hour);
		if (ret < 0)
			return ret;
		ret = parse_2digit(t + 10, 0, 59, &min);
		if (ret < 0)
			return ret;
		ret = parse_2digit(t + 12, 0, 59, &sec);
		if (ret < 0)
			return ret;
	} else {
		return -EINVAL;
	}

	/* Validate year range to prevent mktime64 issues */
	if (year < 1970 || year > 9999)
		return -EINVAL;

	*time_out = mktime64(year, month, day, hour, min, sec);

	return 0;
}

/*
 * Parse signature algorithm and extract signature value
 */
static int parse_signature(struct tquic_x509_cert *cert,
			   const u8 *data, u32 len)
{
	const u8 *p = data;
	u32 content_len, total_len;
	int ret;

	/* Algorithm SEQUENCE */
	ret = asn1_get_tag_length(p, len, ASN1_SEQUENCE,
				  &content_len, &total_len);
	if (ret < 0)
		return ret;

	const u8 *algo_seq = p + (total_len - content_len);

	/* OID */
	u32 oid_content_len, oid_total_len;
	ret = asn1_get_tag_length(algo_seq, content_len, ASN1_OID,
				  &oid_content_len, &oid_total_len);
	if (ret < 0)
		return ret;

	cert->signature.algo = algo_seq + (oid_total_len - oid_content_len);
	cert->signature.algo_len = oid_content_len;

	/* Parameters follow the OID within the AlgorithmIdentifier SEQUENCE */
	{
		const u8 *sig_params = algo_seq + oid_total_len;
		u32 sig_params_len = 0;

		if (oid_total_len < content_len)
			sig_params_len = content_len - oid_total_len;

		identify_sig_algo(cert->signature.algo,
				  cert->signature.algo_len,
				  sig_params, sig_params_len,
				  &cert->signature.hash_algo,
				  &cert->signature.pubkey_algo);
	}

	p += total_len;

	/* Signature BIT STRING */
	ret = asn1_get_tag_length(p, len - total_len, ASN1_BIT_STRING,
				  &content_len, &total_len);
	if (ret < 0)
		return ret;

	const u8 *sig_data = p + (total_len - content_len);
	if (content_len < 2)
		return -EINVAL;

	/* First byte is unused bits count */
	u8 unused_bits = sig_data[0];
	if (unused_bits > 7)
		return -EINVAL;

	cert->signature.sig_len = content_len - 1;
	cert->signature.signature = kmalloc(cert->signature.sig_len, GFP_KERNEL);
	if (!cert->signature.signature)
		return -ENOMEM;

	memcpy(cert->signature.signature, sig_data + 1, cert->signature.sig_len);

	return 0;
}

/*
 * Parse SubjectPublicKeyInfo
 */
static int parse_public_key_info(struct tquic_x509_cert *cert,
				 const u8 *data, u32 len)
{
	const u8 *p = data;
	u32 content_len, total_len;
	u32 algo_content_len, algo_total_len;
	int ret;

	/* Outer SPKI SEQUENCE */
	ret = asn1_get_tag_length(p, len, ASN1_SEQUENCE,
				  &content_len, &total_len);
	if (ret < 0)
		return ret;

	const u8 *spki_content = p + (total_len - content_len);
	u32 spki_remaining = content_len;

	/* AlgorithmIdentifier SEQUENCE (inside SPKI) */
	ret = asn1_get_tag_length(spki_content, spki_remaining,
				  ASN1_SEQUENCE,
				  &algo_content_len, &algo_total_len);
	if (ret < 0)
		return ret;

	const u8 *algo_seq = spki_content +
			     (algo_total_len - algo_content_len);

	/* OID (inside AlgorithmIdentifier) */
	u32 oid_content_len, oid_total_len;
	ret = asn1_get_tag_length(algo_seq, algo_content_len, ASN1_OID,
				  &oid_content_len, &oid_total_len);
	if (ret < 0)
		return ret;

	cert->pubkey.algo = algo_seq + (oid_total_len - oid_content_len);
	cert->pubkey.algo_len = oid_content_len;

	/* Parameters (for EC, this is the curve OID) */
	const u8 *params = NULL;
	u32 params_len = 0;
	const u8 *after_oid = algo_seq + oid_total_len;
	u32 remaining = algo_content_len - oid_total_len;

	if (remaining > 0 && after_oid[0] == ASN1_OID) {
		u32 param_content, param_total;
		ret = asn1_get_tag_length(after_oid, remaining, ASN1_OID,
					  &param_content, &param_total);
		if (ret == 0) {
			params = after_oid + (param_total - param_content);
			params_len = param_content;
		}
	}

	identify_pubkey_algo(cert->pubkey.algo, cert->pubkey.algo_len,
			     params, params_len,
			     &cert->pubkey.pubkey_algo,
			     &cert->pubkey.key_bits);

	/* Public key BIT STRING (after AlgorithmIdentifier in SPKI) */
	const u8 *bitstr_start = spki_content + algo_total_len;
	u32 bitstr_avail = spki_remaining - algo_total_len;

	ret = asn1_get_tag_length(bitstr_start, bitstr_avail,
				  ASN1_BIT_STRING,
				  &content_len, &total_len);
	if (ret < 0)
		return ret;

	/* Update p to point to BIT STRING for RSA key size extraction */
	p = bitstr_start;

	/*
	 * Store the raw public key from the BIT STRING content.
	 * The BIT STRING has a leading "unused bits" byte (usually 0x00)
	 * followed by the actual key data:
	 *   - RSA: DER-encoded RSAPublicKey SEQUENCE
	 *   - EC: uncompressed point (0x04 || x || y)
	 *
	 * The kernel's crypto_akcipher_set_pub_key("rsa") expects just
	 * the RSAPublicKey DER, not the full SPKI.
	 */
	{
		const u8 *key_bits = p + (total_len - content_len);

		if (content_len < 2) {
			/* BIT STRING too short */
			return -EINVAL;
		}

		/* Skip unused bits byte */
		cert->pubkey.key_len = content_len - 1;
		cert->pubkey.key_data = kmalloc(cert->pubkey.key_len,
						GFP_KERNEL);
		if (!cert->pubkey.key_data)
			return -ENOMEM;

		memcpy(cert->pubkey.key_data, key_bits + 1,
		       cert->pubkey.key_len);
	}

	/* For RSA, extract key size from modulus */
	if (cert->pubkey.pubkey_algo == TQUIC_PUBKEY_ALGO_RSA) {
		const u8 *rsa_key = cert->pubkey.key_data;
		u32 rsa_remaining = cert->pubkey.key_len;

		u32 rsa_seq_content, rsa_seq_total;
		ret = asn1_get_tag_length(rsa_key, rsa_remaining,
					  ASN1_SEQUENCE,
					  &rsa_seq_content,
					  &rsa_seq_total);
		if (ret == 0) {
			/* First INTEGER is modulus */
			const u8 *modulus_start = rsa_key +
				(rsa_seq_total - rsa_seq_content);
			u32 mod_content, mod_total;
			ret = asn1_get_tag_length(modulus_start,
						  rsa_seq_content,
						  ASN1_INTEGER,
						  &mod_content,
						  &mod_total);
			if (ret == 0) {
				/* Skip leading zero if present */
				const u8 *mod = modulus_start +
					(mod_total - mod_content);
				if (mod_content > 0 && mod[0] == 0)
					mod_content--;
				cert->pubkey.key_bits = mod_content * 8;
			}
		}
	}

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
	if (ret < 0) {
		pr_debug("tquic_tbs: step1 TBS SEQUENCE failed ret=%d p[0]=%02x len=%u\n",
			ret, p[0], (u32)(end - p));
		return ret;
	}

	/* Store TBS for signature verification */
	cert->tbs = p;
	cert->tbs_len = total_len;

	p += (total_len - content_len);
	end = p + content_len;

	/* Version [0] EXPLICIT INTEGER DEFAULT v1 */
	if (p < end && p[0] == ASN1_CONTEXT_0) {
		ret = asn1_get_tag_length(p, end - p, ASN1_CONTEXT_0,
					  &content_len, &total_len);
		if (ret < 0) {
			pr_debug("tquic_tbs: step2 Version failed ret=%d\n", ret);
			return ret;
		}
		p += total_len;
	}

	/* Serial Number */
	ret = asn1_get_tag_length(p, end - p, ASN1_INTEGER,
				  &content_len, &total_len);
	if (ret < 0) {
		pr_debug("tquic_tbs: step3 Serial failed ret=%d p[0]=%02x\n",
			ret, p[0]);
		return ret;
	}

	cert->serial = kmalloc(content_len, GFP_KERNEL);
	if (!cert->serial)
		return -ENOMEM;
	memcpy(cert->serial, p + (total_len - content_len), content_len);
	cert->serial_len = content_len;
	p += total_len;

	/* Signature Algorithm */
	ret = asn1_get_tag_length(p, end - p, ASN1_SEQUENCE,
				  &content_len, &total_len);
	if (ret < 0) {
		pr_debug("tquic_tbs: step4 SigAlg failed ret=%d p[0]=%02x\n",
			ret, p[0]);
		return ret;
	}
	p += total_len;

	/* Issuer */
	ret = asn1_get_tag_length(p, end - p, ASN1_SEQUENCE,
				  &content_len, &total_len);
	if (ret < 0) {
		pr_debug("tquic_tbs: step5 Issuer failed ret=%d p[0]=%02x\n",
			ret, p[0]);
		return ret;
	}

	/* Store raw issuer DN */
	cert->issuer_raw = kmalloc(total_len, GFP_KERNEL);
	if (cert->issuer_raw) {
		memcpy(cert->issuer_raw, p, total_len);
		cert->issuer_raw_len = total_len;
	}

	ret = parse_dn_extract_cn(p + (total_len - content_len), content_len,
				  &cert->issuer, &cert->issuer_len);
	if (ret < 0 && ret != -ENOENT)
		return ret;
	p += total_len;

	/* Validity */
	ret = asn1_get_tag_length(p, end - p, ASN1_SEQUENCE,
				  &content_len, &total_len);
	if (ret < 0) {
		pr_debug("tquic_tbs: step6 Validity failed ret=%d p[0]=%02x\n",
			ret, p[0]);
		return ret;
	}

	const u8 *validity = p + (total_len - content_len);

	/* notBefore */
	ret = parse_time(validity, content_len, &cert->valid_from);
	if (ret < 0) {
		pr_debug("tquic_tbs: step6b notBefore failed ret=%d\n", ret);
		return ret;
	}

	/* Skip notBefore to get notAfter */
	u32 time_len, time_hdr;
	ret = asn1_get_length(validity + 1, content_len - 1, &time_len, &time_hdr);
	if (ret < 0)
		return ret;

	const u8 *not_after = validity + 1 + time_hdr + time_len;
	ret = parse_time(not_after, content_len - (not_after - validity),
			 &cert->valid_to);
	if (ret < 0) {
		pr_debug("tquic_tbs: step7 notAfter failed ret=%d\n", ret);
		return ret;
	}

	p += total_len;

	/* Subject */
	ret = asn1_get_tag_length(p, end - p, ASN1_SEQUENCE,
				  &content_len, &total_len);
	if (ret < 0) {
		pr_debug("tquic_tbs: step8 Subject failed ret=%d p[0]=%02x\n",
			ret, p[0]);
		return ret;
	}

	/* Store raw subject DN */
	cert->subject_raw = kmalloc(total_len, GFP_KERNEL);
	if (cert->subject_raw) {
		memcpy(cert->subject_raw, p, total_len);
		cert->subject_raw_len = total_len;
	}

	ret = parse_dn_extract_cn(p + (total_len - content_len), content_len,
				  &cert->subject, &cert->subject_len);
	if (ret < 0 && ret != -ENOENT)
		return ret;
	p += total_len;

	/* SubjectPublicKeyInfo */
	ret = asn1_get_tag_length(p, end - p, ASN1_SEQUENCE,
				  &content_len, &total_len);
	if (ret < 0) {
		pr_debug("tquic_tbs: step9 SPKI failed ret=%d p[0]=%02x\n",
			ret, p[0]);
		return ret;
	}

	ret = parse_public_key_info(cert, p, total_len);
	if (ret < 0) {
		pr_debug("tquic_tbs: step10 parse_pub_key failed ret=%d\n", ret);
		return ret;
	}

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
	const u8 *p;
	int ret;

	if (!data || len == 0)
		return NULL;

	cert = kzalloc(sizeof(*cert), gfp);
	if (!cert)
		return NULL;

	cert->path_len_constraint = -1;

	/* Store raw certificate */
	cert->raw = kmalloc(len, gfp);
	if (!cert->raw) {
		kfree_sensitive(cert);
		return NULL;
	}
	memcpy(cert->raw, data, len);
	cert->raw_len = len;

	/* Certificate is a SEQUENCE */
	ret = asn1_get_tag_length(data, len, ASN1_SEQUENCE,
				  &content_len, &total_len);
	if (ret < 0) {
		pr_debug("tquic_x509: SEQUENCE tag failed: ret=%d len=%u data[0..3]=%02x%02x%02x%02x\n",
			ret, len,
			len > 0 ? data[0] : 0, len > 1 ? data[1] : 0,
			len > 2 ? data[2] : 0, len > 3 ? data[3] : 0);
		tquic_x509_cert_free(cert);
		return NULL;
	}

	pr_debug("tquic_x509: SEQUENCE ok content_len=%u total_len=%u\n",
		content_len, total_len);

	p = data + (total_len - content_len);

	/* Parse TBSCertificate */
	ret = parse_tbs_certificate(cert, p, content_len);
	if (ret < 0) {
		pr_debug("tquic_x509: parse_tbs failed: ret=%d\n", ret);
		tquic_x509_cert_free(cert);
		return NULL;
	}

	/* Parse signature */
	const u8 *after_tbs = cert->tbs + cert->tbs_len;

	/* Validate tbs pointer is within parsed data bounds */
	if (after_tbs < cert->tbs || after_tbs > p + content_len) {
		pr_debug("tquic_x509: tbs bounds check failed\n");
		tquic_x509_cert_free(cert);
		return NULL;
	}

	u32 remaining = content_len - (after_tbs - p);

	ret = parse_signature(cert, after_tbs, remaining);
	if (ret < 0) {
		pr_debug("tquic_x509: parse_signature failed: ret=%d\n", ret);
		tquic_x509_cert_free(cert);
		return NULL;
	}

	/* Check if self-signed */
	if (cert->issuer_raw && cert->subject_raw &&
	    cert->issuer_raw_len == cert->subject_raw_len &&
	    !crypto_memneq(cert->issuer_raw, cert->subject_raw, cert->issuer_raw_len)) {
		cert->self_signed = true;
	}

	return cert;
}
EXPORT_SYMBOL_GPL(tquic_x509_cert_parse);

void tquic_x509_cert_free(struct tquic_x509_cert *cert)
{
	u32 i;

	if (!cert)
		return;

	tquic_dbg("tquic_x509_cert_free: subject=%s is_ca=%d\n",
		  cert->subject ? cert->subject : "(null)", cert->is_ca);

	kfree_sensitive(cert->raw);
	kfree_sensitive(cert->subject);
	kfree_sensitive(cert->issuer);
	kfree_sensitive(cert->subject_raw);
	kfree_sensitive(cert->issuer_raw);
	kfree_sensitive(cert->serial);
	kfree_sensitive(cert->pubkey.key_data);
	kfree_sensitive(cert->signature.signature);
	kfree_sensitive(cert->akid);
	kfree_sensitive(cert->skid);
	kfree_sensitive(cert->ocsp_url);
	free_name_constraints(cert->name_constraints);

	if (cert->san_dns) {
		for (i = 0; i < cert->san_dns_count; i++)
			kfree_sensitive(cert->san_dns[i]);
		kfree_sensitive(cert->san_dns);
	}

	if (cert->san_ip) {
		for (i = 0; i < cert->san_ip_count; i++)
			kfree_sensitive(cert->san_ip[i]);
		kfree_sensitive(cert->san_ip);
		kfree_sensitive(cert->san_ip_len);
	}

	if (cert->crl_dp) {
		for (i = 0; i < cert->crl_dp_count; i++)
			kfree_sensitive(cert->crl_dp[i]);
		kfree_sensitive(cert->crl_dp);
	}

	kfree_sensitive(cert);
}
EXPORT_SYMBOL_GPL(tquic_x509_cert_free);

void tquic_x509_chain_free(struct tquic_x509_cert *chain)
{
	struct tquic_x509_cert *cert = chain;

	tquic_dbg("tquic_x509_chain_free: chain=%p\n", chain);

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

	tquic_dbg("tquic_x509_cert_is_valid_time: valid_from=%lld valid_to=%lld tolerance=%u\n",
		  cert->valid_from, cert->valid_to, tolerance);

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

	ctx->verify_mode = tquic_cert_verify_mode;
	ctx->verify_hostname = tquic_cert_verify_hostname_enabled;
	ctx->check_revocation = tquic_cert_revocation_mode;
	ctx->time_tolerance = tquic_cert_time_tolerance;
	ctx->min_key_bits_rsa = tquic_cert_min_rsa_bits;
	ctx->min_key_bits_ec = tquic_cert_min_ec_bits;

	return ctx;
}
EXPORT_SYMBOL_GPL(tquic_cert_verify_ctx_alloc);

void tquic_cert_verify_ctx_free(struct tquic_cert_verify_ctx *ctx)
{
	if (!ctx)
		return;

	tquic_dbg("tquic_cert_verify_ctx_free: verify_mode=%d\n",
		  ctx->verify_mode);

	kfree_sensitive(ctx->expected_hostname);
	kfree_sensitive(ctx->ocsp_stapling);
	tquic_x509_chain_free(ctx->chain);

	if (ctx->trusted_keyring && ctx->trusted_keyring != VERIFY_USE_SECONDARY_KEYRING)
		key_put(ctx->trusted_keyring);

	kfree_sensitive(ctx);
}
EXPORT_SYMBOL_GPL(tquic_cert_verify_ctx_free);

int tquic_cert_verify_set_hostname(struct tquic_cert_verify_ctx *ctx,
				   const char *hostname, u32 len)
{
	if (!ctx)
		return -EINVAL;

	if (len > TQUIC_MAX_HOSTNAME_LEN)
		return -EINVAL;

	kfree_sensitive(ctx->expected_hostname);

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

		/* Wildcard only matches one label (RFC 6125 Section 6.4.3) */
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
	u32 i;

	if (!cert || !expected || expected_len == 0)
		return -EINVAL;

	/* Check Subject Alternative Names first (preferred per RFC 6125) */
	if (cert->san_dns && cert->san_dns_count > 0) {
		for (i = 0; i < cert->san_dns_count; i++) {
			if (hostname_match(cert->san_dns[i],
					   strlen(cert->san_dns[i]),
					   expected, expected_len))
				return 0;
		}
	}

	/* Fall back to Common Name (deprecated but still common) */
	if (cert->subject && cert->subject_len > 0) {
		if (hostname_match(cert->subject, cert->subject_len,
				   expected, expected_len))
			return 0;
	}

	return -ENOENT;
}
EXPORT_SYMBOL_GPL(tquic_verify_hostname);

/*
 * Compute hash of TBSCertificate for signature verification
 */
static int compute_tbs_hash(const struct tquic_x509_cert *cert,
			    enum tquic_hash_algo hash_algo,
			    u8 *digest, u32 *digest_len)
{
	struct crypto_shash *tfm;
	SHASH_DESC_ON_STACK(desc, tfm);
	const char *algo_name;
	int ret;

	algo_name = get_hash_algo_name(hash_algo);
	if (!algo_name)
		return -EINVAL;

	tfm = crypto_alloc_shash(algo_name, 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	desc->tfm = tfm;

	ret = crypto_shash_init(desc);
	if (ret)
		goto out;

	ret = crypto_shash_update(desc, cert->tbs, cert->tbs_len);
	if (ret)
		goto out;

	ret = crypto_shash_final(desc, digest);
	if (ret)
		goto out;

	*digest_len = crypto_shash_digestsize(tfm);

out:
	crypto_free_shash(tfm);
	return ret;
}

/*
 * Verify certificate signature using kernel crypto API
 *
 * This is the core signature verification function. It performs standalone cryptographic
 * signature verification for intermediate certificates not in the keyring.
 *
 * Uses the newer crypto_sig API (kernel 6.x+) which provides a simpler synchronous
 * interface for signature verification.
 */
int tquic_x509_verify_signature(const struct tquic_x509_cert *cert,
				const struct tquic_x509_cert *issuer)
{
	struct crypto_sig *tfm = NULL;
	u8 digest[64];
	u32 digest_len = 0;
	int ret;
	const char *alg_name;

	if (!cert || !issuer)
		return -EINVAL;

	/* Self-signed check: issuer == subject.
	 * Use crypto_memneq for constant-time comparison to avoid
	 * leaking certificate structure via timing side-channels.
	 */
	if (cert->issuer_raw && cert->subject_raw &&
	    cert->issuer_raw_len == cert->subject_raw_len &&
	    !crypto_memneq(cert->issuer_raw, cert->subject_raw,
			   cert->issuer_raw_len)) {
		((struct tquic_x509_cert *)cert)->self_signed = true;
	}

	/* Verify issuer's subject matches cert's issuer */
	if (cert->issuer_raw && issuer->subject_raw) {
		if (cert->issuer_raw_len != issuer->subject_raw_len ||
		    crypto_memneq(cert->issuer_raw, issuer->subject_raw,
				  cert->issuer_raw_len)) {
			pr_debug("tquic_cert: Issuer DN mismatch\n");
			return -EKEYREJECTED;
		}
	}

	/* Compute hash of TBSCertificate */
	ret = compute_tbs_hash(cert, cert->signature.hash_algo,
			       digest, &digest_len);
	if (ret < 0) {
		pr_debug("tquic_cert: Failed to compute TBS hash: %d\n", ret);
		return ret;
	}

	/* Select algorithm name based on signature algorithm type */
	switch (cert->signature.pubkey_algo) {
	case TQUIC_PUBKEY_ALGO_RSA:
		/*
		 * Construct RSA algorithm name dynamically from the
		 * certificate's hash algorithm.
		 */
		switch (cert->signature.hash_algo) {
		case TQUIC_HASH_SHA256:
			alg_name = "pkcs1pad(rsa,sha256)";
			break;
		case TQUIC_HASH_SHA384:
			alg_name = "pkcs1pad(rsa,sha384)";
			break;
		case TQUIC_HASH_SHA512:
			alg_name = "pkcs1pad(rsa,sha512)";
			break;
		default:
			pr_debug("tquic_cert: unsupported RSA hash algo %d\n",
				 cert->signature.hash_algo);
			return -EOPNOTSUPP;
		}
		break;
	case TQUIC_PUBKEY_ALGO_ECDSA_P256:
	case TQUIC_PUBKEY_ALGO_ECDSA_P384:
	case TQUIC_PUBKEY_ALGO_ECDSA_P521:
		alg_name = "ecdsa";
		break;
	case TQUIC_PUBKEY_ALGO_ED25519:
		alg_name = "ed25519";
		break;
	default:
		pr_debug("tquic_cert: Unsupported signature algorithm\n");
		return -EINVAL;
	}

	/* Allocate signature verification tfm */
	tfm = crypto_alloc_sig(alg_name, 0, 0);
	if (IS_ERR(tfm)) {
		ret = PTR_ERR(tfm);
		pr_debug("tquic_cert: Failed to allocate sig tfm for %s: %d\n",
			 alg_name, ret);
		if (cert->signature.pubkey_algo == TQUIC_PUBKEY_ALGO_ED25519) {
			pr_debug("tquic_cert: Ed25519 not available in kernel, "
				"certificate signature cannot be verified\n");
			return -EOPNOTSUPP;
		}
		return ret;
	}

	/* Set public key from issuer certificate */
	ret = crypto_sig_set_pubkey(tfm, issuer->pubkey.key_data,
				    issuer->pubkey.key_len);
	if (ret) {
		pr_debug("tquic_cert: Failed to set public key: %d\n", ret);
		goto out_free_tfm;
	}

	/* Verify signature: pass signature and digest to verify */
	ret = crypto_sig_verify(tfm,
				cert->signature.signature, cert->signature.sig_len,
				digest, digest_len);
	if (ret) {
		pr_debug("tquic_cert: Signature verification failed: %d\n", ret);
		ret = -EKEYREJECTED;
	}

out_free_tfm:
	crypto_free_sig(tfm);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_x509_verify_signature);

/*
 * Check certificate key usage for TLS
 */
int tquic_x509_check_key_usage(const struct tquic_x509_cert *cert,
			       int depth, bool is_server)
{
	if (!cert)
		return -EINVAL;

	/* End-entity certificate (depth 0) */
	if (depth == 0) {
		/* Must have digitalSignature for TLS */
		if (cert->key_usage != 0 &&
		    !(cert->key_usage & TQUIC_KU_DIGITAL_SIGNATURE)) {
			pr_debug("tquic_cert: End-entity missing digitalSignature\n");
			return -EKEYREJECTED;
		}

		/* Check extended key usage if present */
		if (cert->ext_key_usage != 0) {
			if (is_server && !(cert->ext_key_usage & TQUIC_EKU_SERVER_AUTH)) {
				pr_debug("tquic_cert: Server cert missing serverAuth EKU\n");
				return -EKEYREJECTED;
			}
			if (!is_server && !(cert->ext_key_usage & TQUIC_EKU_CLIENT_AUTH)) {
				pr_debug("tquic_cert: Client cert missing clientAuth EKU\n");
				return -EKEYREJECTED;
			}
		}
	} else {
		/* CA certificate */
		if (!cert->is_ca) {
			pr_debug("tquic_cert: Intermediate cert is not a CA\n");
			return -EKEYREJECTED;
		}

		/* CA must have keyCertSign */
		if (cert->key_usage != 0 &&
		    !(cert->key_usage & TQUIC_KU_KEY_CERT_SIGN)) {
			pr_debug("tquic_cert: CA missing keyCertSign\n");
			return -EKEYREJECTED;
		}
	}

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_x509_check_key_usage);

/*
 * Check minimum key size
 */
static int check_key_size(const struct tquic_cert_verify_ctx *ctx,
			  const struct tquic_x509_cert *cert)
{
	switch (cert->pubkey.pubkey_algo) {
	case TQUIC_PUBKEY_ALGO_RSA:
		if (cert->pubkey.key_bits < ctx->min_key_bits_rsa) {
			pr_debug("tquic_cert: RSA key too small: %u < %u\n",
				 cert->pubkey.key_bits, ctx->min_key_bits_rsa);
			return -EKEYREJECTED;
		}
		break;
	case TQUIC_PUBKEY_ALGO_ECDSA_P256:
	case TQUIC_PUBKEY_ALGO_ECDSA_P384:
	case TQUIC_PUBKEY_ALGO_ECDSA_P521:
		if (cert->pubkey.key_bits < ctx->min_key_bits_ec) {
			pr_debug("tquic_cert: EC key too small: %u < %u\n",
				 cert->pubkey.key_bits, ctx->min_key_bits_ec);
			return -EKEYREJECTED;
		}
		break;
	default:
		break;
	}

	return 0;
}

/*
 * Certificate revocation checking
 *
 * In kernel space, full CRL/OCSP checking is limited because:
 * 1. We cannot make HTTP requests from kernel context
 * 2. CRL/OCSP responders require network access
 *
 * We support:
 * - OCSP stapling (data provided in TLS handshake)
 * - Basic CRL checking if CRL is pre-loaded
 */

/*
 * Parse a stapled OCSP response to extract the certificate status.
 *
 * Navigates the ASN.1 structure per RFC 6960 to extract:
 *   - The OCSPResponseStatus (must be 0 = successful)
 *   - The CertStatus from the first SingleResponse
 *
 * Returns:
 *   0            certificate status is "good"
 *   -EKEYREVOKED certificate is revoked
 *   -ENODATA     status cannot be determined (parse error, unknown, or
 *                non-successful response status)
 */
static int parse_ocsp_cert_status(const u8 *data, u32 len)
{
	const u8 *p = data;
	u32 remaining = len;
	u32 content_len, total_len, hdr_len;
	u32 skip;
	int ret;

	tquic_dbg("parse_ocsp_cert_status: data_len=%u\n", len);

	/* Outer SEQUENCE (OCSPResponse) */
	ret = asn1_get_tag_length(p, remaining, ASN1_SEQUENCE,
				  &content_len, &total_len);
	if (ret < 0)
		return -ENODATA;
	p += total_len - content_len;
	remaining = content_len;

	/* ENUMERATED responseStatus (tag 0x0A) */
	if (remaining < 3 || p[0] != 0x0A)
		return -ENODATA;
	ret = asn1_get_length(p + 1, remaining - 1, &content_len, &hdr_len);
	if (ret < 0 || content_len != 1)
		return -ENODATA;

	/* responseStatus must be 0 (successful) */
	if (p[1 + hdr_len] != 0)
		return -ENODATA;

	skip = 1 + hdr_len + content_len;
	p += skip;
	remaining -= skip;

	/* [0] EXPLICIT responseBytes */
	if (remaining < 2 || p[0] != 0xA0)
		return -ENODATA;
	ret = asn1_get_length(p + 1, remaining - 1, &content_len, &hdr_len);
	if (ret < 0)
		return -ENODATA;
	p += 1 + hdr_len;
	remaining = content_len;

	/* SEQUENCE (ResponseBytes) */
	ret = asn1_get_tag_length(p, remaining, ASN1_SEQUENCE,
				  &content_len, &total_len);
	if (ret < 0)
		return -ENODATA;
	p += total_len - content_len;
	remaining = content_len;

	/* OID responseType -- skip */
	ret = asn1_get_tag_length(p, remaining, ASN1_OID,
				  &content_len, &total_len);
	if (ret < 0)
		return -ENODATA;
	p += total_len;
	remaining -= total_len;

	/* OCTET STRING (contains DER-encoded BasicOCSPResponse) */
	ret = asn1_get_tag_length(p, remaining, ASN1_OCTET_STRING,
				  &content_len, &total_len);
	if (ret < 0)
		return -ENODATA;
	p += total_len - content_len;
	remaining = content_len;

	/* SEQUENCE (BasicOCSPResponse) */
	ret = asn1_get_tag_length(p, remaining, ASN1_SEQUENCE,
				  &content_len, &total_len);
	if (ret < 0)
		return -ENODATA;
	p += total_len - content_len;
	remaining = content_len;

	/* SEQUENCE (tbsResponseData) */
	ret = asn1_get_tag_length(p, remaining, ASN1_SEQUENCE,
				  &content_len, &total_len);
	if (ret < 0)
		return -ENODATA;
	p += total_len - content_len;
	remaining = content_len;

	/* Optional [0] EXPLICIT version -- skip if present */
	if (remaining > 0 && p[0] == 0xA0) {
		ret = asn1_get_length(p + 1, remaining - 1,
				      &content_len, &hdr_len);
		if (ret < 0)
			return -ENODATA;
		skip = 1 + hdr_len + content_len;
		if (skip > remaining)
			return -ENODATA;
		p += skip;
		remaining -= skip;
	}

	/* ResponderID -- CHOICE: [1] byName or [2] byKey -- skip */
	if (remaining < 2)
		return -ENODATA;
	if (p[0] != 0xA1 && p[0] != 0xA2)
		return -ENODATA;
	ret = asn1_get_length(p + 1, remaining - 1,
			      &content_len, &hdr_len);
	if (ret < 0)
		return -ENODATA;
	skip = 1 + hdr_len + content_len;
	if (skip > remaining)
		return -ENODATA;
	p += skip;
	remaining -= skip;

	/* GeneralizedTime (producedAt) -- skip */
	if (remaining < 2 || p[0] != ASN1_GENERALIZED_TIME)
		return -ENODATA;
	ret = asn1_get_length(p + 1, remaining - 1,
			      &content_len, &hdr_len);
	if (ret < 0)
		return -ENODATA;
	skip = 1 + hdr_len + content_len;
	if (skip > remaining)
		return -ENODATA;
	p += skip;
	remaining -= skip;

	/* SEQUENCE OF SingleResponse (responses) */
	ret = asn1_get_tag_length(p, remaining, ASN1_SEQUENCE,
				  &content_len, &total_len);
	if (ret < 0)
		return -ENODATA;
	p += total_len - content_len;
	remaining = content_len;

	/* First SingleResponse SEQUENCE */
	ret = asn1_get_tag_length(p, remaining, ASN1_SEQUENCE,
				  &content_len, &total_len);
	if (ret < 0)
		return -ENODATA;
	p += total_len - content_len;
	remaining = content_len;

	/* CertID SEQUENCE -- skip */
	ret = asn1_get_tag_length(p, remaining, ASN1_SEQUENCE,
				  &content_len, &total_len);
	if (ret < 0)
		return -ENODATA;
	if (total_len > remaining)
		return -ENODATA;
	p += total_len;
	remaining -= total_len;

	/* CertStatus -- the context-specific tag reveals the status */
	if (remaining < 1)
		return -ENODATA;

	if (p[0] == 0x80) {
		/* good [0] IMPLICIT NULL */
		return 0;
	} else if (p[0] == 0xA1) {
		/* revoked [1] IMPLICIT RevokedInfo */
		return -EKEYREVOKED;
	}

	/* unknown [2] or unrecognized -- cannot determine status */
	return -ENODATA;
}

int tquic_check_revocation(struct tquic_cert_verify_ctx *ctx,
			   const struct tquic_x509_cert *cert)
{
	if (!ctx || !cert)
		return -EINVAL;

	if (ctx->check_revocation == TQUIC_REVOKE_NONE)
		return 0;

	/* Check OCSP stapling data if provided */
	if (ctx->ocsp_stapling && ctx->ocsp_stapling_len > 0) {
		int status;

		/*
		 * CF-007: verify OCSP response signature
		 *
		 * OCSP response validation (RFC 6960):
		 * Parse the response to extract the certificate status.
		 *
		 * Signature verification status:
		 *   - The OCSP BasicResponse signature over tbsResponseData
		 *     is NOT verified because the OCSP responder certificate
		 *     may not be available in kernel context.
		 *   - The responder cert chain to a trusted root is NOT
		 *     verified for the same reason.
		 *
		 * Because the signature is not verified, an on-path attacker
		 * can forge OCSP responses.  In hard-fail mode we therefore
		 * reject the connection (fail closed) rather than trusting
		 * an unverified "good" status.  In soft-fail mode the
		 * parsed status is accepted with a warning.
		 */
		if (ctx->ocsp_stapling_len < 10 ||
		    ctx->ocsp_stapling[0] != 0x30) {
			pr_debug("tquic_cert: OCSP stapling data malformed "
				"(len=%u, tag=0x%02x)\n",
				ctx->ocsp_stapling_len,
				ctx->ocsp_stapling[0]);
			if (ctx->check_revocation == TQUIC_REVOKE_HARD_FAIL)
				return -EKEYREVOKED;
			/* Soft-fail: treat as if no OCSP data */
			goto no_ocsp;
		}

		status = parse_ocsp_cert_status(ctx->ocsp_stapling,
						ctx->ocsp_stapling_len);
		if (status == 0) {
			/*
			 * CF-007: OCSP signature is NOT verified.
			 * Since a network attacker could forge a "good"
			 * status, we must not trust the response in any
			 * mode.  Hard-fail rejects outright; soft-fail
			 * falls through to the no-OCSP path which will
			 * allow the connection with a warning.
			 */
			pr_debug("tquic_cert: OCSP status good (%u bytes)"
				" -- signature NOT verified\n",
				ctx->ocsp_stapling_len);
			if (ctx->check_revocation == TQUIC_REVOKE_HARD_FAIL)
				return -EKEYREVOKED;
			goto no_ocsp;
		}

		if (status == -EKEYREVOKED) {
			pr_debug("tquic_cert: OCSP response indicates "
				"certificate is revoked\n");
			return -EKEYREVOKED;
		}

		/*
		 * Could not determine revocation status from the OCSP
		 * response (parse error, non-successful response, or
		 * unknown cert status).
		 */
		pr_debug("tquic_cert: OCSP response present but certificate "
			"status could not be determined\n");
		if (ctx->check_revocation == TQUIC_REVOKE_HARD_FAIL)
			return -EKEYREVOKED;
	}

no_ocsp:
	/*
	 * Without usable OCSP stapling, we cannot perform online revocation
	 * checking from kernel context.  Hard-fail mode MUST reject.
	 */
	if (ctx->check_revocation == TQUIC_REVOKE_HARD_FAIL) {
		pr_debug("tquic_cert: Revocation check required but no "
			"usable OCSP stapling available -- rejecting\n");
		return -EKEYREVOKED;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_check_revocation);

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

	if (!keyring)
		keyring = VERIFY_USE_SECONDARY_KEYRING;

	/*
	 * Generate key ID from certificate issuer/serial
	 * This matches how the kernel stores X.509 certificates
	 */
	if (!cert->serial || !cert->issuer_raw)
		return -EINVAL;

	kid = asymmetric_key_generate_id(cert->serial, cert->serial_len,
					 cert->issuer_raw, cert->issuer_raw_len);
	if (IS_ERR(kid))
		return PTR_ERR(kid);

	/*
	 * Look up in keyring
	 * For root certificates, we look up by issuer (which equals subject)
	 */
	key = find_asymmetric_key(keyring, kid, NULL, NULL, false);
	kfree_sensitive(kid);

	if (IS_ERR(key)) {
		/* Try custom TQUIC keyring */
		mutex_lock(&keyring_mutex);
		if (tquic_trusted_keyring) {
			kid = asymmetric_key_generate_id(cert->serial, cert->serial_len,
							 cert->issuer_raw, cert->issuer_raw_len);
			if (!IS_ERR(kid)) {
				key = find_asymmetric_key(tquic_trusted_keyring,
							  kid, NULL, NULL, false);
				kfree_sensitive(kid);
			}
		}
		mutex_unlock(&keyring_mutex);

		if (IS_ERR(key))
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
static int verify_chain(struct tquic_cert_verify_ctx *ctx, bool is_server)
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
		ctx->error_depth = depth;

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

		/* Check key size */
		ret = check_key_size(ctx, cert);
		if (ret < 0) {
			ctx->error_code = TQUIC_CERT_ERR_WEAK_KEY;
			ctx->error_msg = "Certificate key too weak";
			return ret;
		}

		/* Check key usage */
		ret = tquic_x509_check_key_usage(cert, depth, is_server);
		if (ret < 0) {
			ctx->error_code = TQUIC_CERT_ERR_KEY_USAGE;
			ctx->error_msg = "Invalid key usage for certificate";
			return ret;
		}

		/* For intermediate and root certs, verify CA flag and path length */
		if (depth > 0) {
			if (!cert->is_ca) {
				ctx->error_code = TQUIC_CERT_ERR_CONSTRAINT;
				ctx->error_msg = "Intermediate certificate is not a CA";
				return -EKEYREJECTED;
			}

			/* Check path length constraint */
			if (cert->path_len_constraint >= 0 &&
			    (int)(depth - 1) > cert->path_len_constraint) {
				ctx->error_code = TQUIC_CERT_ERR_PATH_LEN;
				ctx->error_msg = "Path length constraint violated";
				return -EKEYREJECTED;
			}

			/*
			 * Name constraints (RFC 5280 Section 4.2.1.10):
			 * If this CA has nameConstraints, verify all
			 * subordinate certificates in the chain comply.
			 * Walk from the leaf (ctx->chain) up to but not
			 * including the current CA certificate.
			 */
			if (cert->name_constraints) {
				struct tquic_x509_cert *sub;

				for (sub = ctx->chain; sub && sub != cert;
				     sub = sub->next) {
					ret = check_name_constraints(
						sub,
						cert->name_constraints);
					if (ret < 0) {
						ctx->error_code =
							TQUIC_CERT_ERR_NAME_CONSTRAINTS;
						ctx->error_msg =
							"Name constraints violated";
						return -EKEYREJECTED;
					}
				}
			}
		}

		/* Check revocation status */
		ret = tquic_check_revocation(ctx, cert);
		if (ret < 0) {
			ctx->error_code = TQUIC_CERT_ERR_REVOKED;
			ctx->error_msg = "Certificate has been revoked";
			return ret;
		}

		/*
		 * Verify issuer-subject linkage and signature BEFORE
		 * checking trust anchors.  This ensures the chain is
		 * properly linked and prevents accepting a certificate
		 * that matches a trust anchor but was not actually
		 * issued by it (CF-361).
		 */
		if (cert->next) {
			/* Verify issuer-subject DN linkage */
			if (cert->issuer_raw && cert->next->subject_raw) {
				if (cert->issuer_raw_len !=
				    cert->next->subject_raw_len ||
				    crypto_memneq(cert->issuer_raw,
						  cert->next->subject_raw,
						  cert->issuer_raw_len)) {
					ctx->error_code = TQUIC_CERT_ERR_SIG_VERIFY;
					ctx->error_msg = "Issuer-subject linkage mismatch in chain";
					return -EKEYREJECTED;
				}
			}

			ret = tquic_x509_verify_signature(cert, cert->next);
			if (ret < 0) {
				ctx->error_code = TQUIC_CERT_ERR_SIG_VERIFY;
				ctx->error_msg = "Certificate signature verification failed";
				return ret;
			}
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
				pr_debug("tquic_cert: Allowing self-signed certificate (testing mode)\n");
				return 0;
			}
			ctx->error_code = TQUIC_CERT_ERR_SELF_SIGNED;
			ctx->error_msg = "Self-signed certificate not trusted";
			return -ENOKEY;
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
		pr_debug("tquic_cert: Certificate verification disabled (INSECURE)\n");
		return 0;
	}

	/* Free any existing chain */
	tquic_x509_chain_free(ctx->chain);
	ctx->chain = NULL;
	ctx->chain_len = 0;
	ctx->error_depth = 0;

	/*
	 * Parse TLS certificate chain format:
	 * Each entry is: 3-byte length + DER certificate + 2-byte ext length + extensions
	 */
	while (p + 3 <= end) {
		u32 cert_len = (p[0] << 16) | (p[1] << 8) | p[2];
		p += 3;

		if (cert_len == 0 || p + cert_len > end)
			break;

		/* Early chain length check to avoid parsing excess certs */
		if (ctx->chain_len >= TQUIC_MAX_CERT_CHAIN_LEN) {
			ctx->error_code = TQUIC_CERT_ERR_CHAIN_TOO_LONG;
			ctx->error_msg = "Certificate chain too long";
			tquic_x509_chain_free(ctx->chain);
			ctx->chain = NULL;
			return -EMLINK;
		}

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

		/* Process certificate extensions (OCSP stapling, SCT, etc.) */
		if (p + 2 <= end) {
			u16 ext_len = (p[0] << 8) | p[1];
			p += 2;

			if (ext_len > 0 && p + ext_len <= end) {
				/* First cert extensions may contain OCSP stapling */
				if (ctx->chain_len == 1 && !ctx->ocsp_stapling) {
					/* Look for OCSP response in extensions */
					/* Format: extension type (2 bytes) + length (2 bytes) + data */
					const u8 *ext_p = p;
					const u8 *ext_end = p + ext_len;

					while (ext_p + 4 <= ext_end) {
						u16 ext_type = (ext_p[0] << 8) | ext_p[1];
						u16 ext_data_len = (ext_p[2] << 8) | ext_p[3];
						ext_p += 4;

						/* OCSP status_request extension */
						if (ext_type == 5 && ext_data_len > 0 &&
						    ext_p + ext_data_len <= ext_end) {
							ctx->ocsp_stapling = kmalloc(ext_data_len,
										     GFP_KERNEL);
							if (ctx->ocsp_stapling) {
								memcpy(ctx->ocsp_stapling,
								       ext_p, ext_data_len);
								ctx->ocsp_stapling_len = ext_data_len;
							}
						}
						ext_p += ext_data_len;
					}
				}
				p += ext_len;
			}
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

	/* CF-003: use ctx->is_server to select correct EKU check */
	ret = verify_chain(ctx, ctx->is_server);
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
	ctx->is_server = true;  /* Verifying a server certificate */

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

	/* Get peer certificate chain from handshake */
	extern u8 *tquic_hs_get_peer_cert_chain(struct tquic_handshake *hs, u32 *len);
	u32 chain_len;
	u8 *peer_chain = tquic_hs_get_peer_cert_chain(hs, &chain_len);

	if (!peer_chain || chain_len == 0) {
		if (ctx->verify_mode == TQUIC_CERT_VERIFY_OPTIONAL) {
			tquic_cert_verify_ctx_free(ctx);
			return 0;  /* No alert, optional verification */
		}
		tquic_cert_verify_ctx_free(ctx);
		return TLS_ALERT_CERTIFICATE_REQUIRED;
	}

	/* Verify the certificate chain */
	ret = tquic_verify_cert_chain(ctx, peer_chain, chain_len);

	if (ret < 0) {
		int alert;

		pr_debug("tquic_cert: Server certificate verification failed: %s (depth %u)\n",
			tquic_cert_verify_get_error(ctx), ctx->error_depth);

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
		case TQUIC_CERT_ERR_KEY_USAGE:
		case TQUIC_CERT_ERR_CONSTRAINT:
		case TQUIC_CERT_ERR_NAME_CONSTRAINTS:
		case TQUIC_CERT_ERR_WEAK_KEY:
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

	pr_debug("tquic_cert: Server certificate verification succeeded\n");
	tquic_cert_verify_ctx_free(ctx);
	return 0;  /* Success, no alert */
}
EXPORT_SYMBOL_GPL(tquic_hs_verify_server_cert);

int tquic_hs_verify_client_cert(struct tquic_handshake *hs,
				struct tquic_connection *conn)
{
	struct tquic_cert_verify_ctx *ctx;
	struct tquic_sock *tsk;
	int ret;

	if (!hs || !conn)
		return TLS_ALERT_INTERNAL_ERROR;

	tsk = tquic_sk(conn->sk);
	if (!tsk)
		return TLS_ALERT_INTERNAL_ERROR;

	ctx = tquic_cert_verify_ctx_alloc(GFP_KERNEL);
	if (!ctx)
		return TLS_ALERT_INTERNAL_ERROR;

	/*
	 * Client certificate verification differs from server cert:
	 *  - No hostname verification (client certs don't carry server names)
	 *  - Verify mode comes from the server's client-auth configuration
	 *  - Self-signed policy is server-determined
	 */
	ctx->verify_mode = tsk->cert_verify.verify_mode;
	ctx->verify_hostname = false;  /* Never verify hostname for client certs */
	ctx->allow_self_signed = tsk->cert_verify.allow_self_signed;
	/* CF-003: use client EKU for client certificate verification */
	ctx->is_server = false;

	tquic_cert_verify_set_keyring(ctx, NULL);

	/* Get peer (client) certificate chain from handshake */
	{
		extern u8 *tquic_hs_get_peer_cert_chain(struct tquic_handshake *hs,
							u32 *len);
		u32 chain_len;
		u8 *peer_chain = tquic_hs_get_peer_cert_chain(hs, &chain_len);

		if (!peer_chain || chain_len == 0) {
			if (ctx->verify_mode == TQUIC_CERT_VERIFY_OPTIONAL) {
				tquic_cert_verify_ctx_free(ctx);
				return 0;
			}
			tquic_cert_verify_ctx_free(ctx);
			return TLS_ALERT_CERTIFICATE_REQUIRED;
		}

		ret = tquic_verify_cert_chain(ctx, peer_chain, chain_len);
	}

	if (ret < 0) {
		int alert;

		pr_debug("tquic_cert: Client certificate verification failed: %s (depth %u)\n",
			tquic_cert_verify_get_error(ctx), ctx->error_depth);

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
		case TQUIC_CERT_ERR_KEY_USAGE:
		case TQUIC_CERT_ERR_CONSTRAINT:
		case TQUIC_CERT_ERR_NAME_CONSTRAINTS:
		case TQUIC_CERT_ERR_WEAK_KEY:
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

	pr_debug("tquic_cert: Client certificate verification succeeded\n");
	tquic_cert_verify_ctx_free(ctx);
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_hs_verify_client_cert);

/*
 * Trusted CA management
 */

int tquic_add_trusted_ca(const u8 *cert_data, u32 cert_len,
			 const char *description)
{
#ifdef CONFIG_SYSTEM_DATA_VERIFICATION
	struct key *keyring;
	key_ref_t key_ref;
	int ret;

	if (!cert_data || cert_len == 0 || !description)
		return -EINVAL;

	mutex_lock(&keyring_mutex);

	/* Create keyring if it doesn't exist */
	if (!tquic_trusted_keyring) {
		keyring = keyring_alloc(".tquic_trusted",
					GLOBAL_ROOT_UID, GLOBAL_ROOT_GID,
					current_cred(),
					KEY_POS_ALL | KEY_USR_VIEW | KEY_USR_READ |
					KEY_USR_SEARCH,
					KEY_ALLOC_NOT_IN_QUOTA,
					NULL, NULL);
		if (IS_ERR(keyring)) {
			mutex_unlock(&keyring_mutex);
			return PTR_ERR(keyring);
		}
		tquic_trusted_keyring = keyring;
	}

	/* Add certificate to keyring */
	key_ref = key_create_or_update(make_key_ref(tquic_trusted_keyring, true),
				       "asymmetric", description,
				       cert_data, cert_len,
				       KEY_POS_ALL | KEY_USR_VIEW | KEY_USR_READ,
				       KEY_ALLOC_NOT_IN_QUOTA);
	if (IS_ERR(key_ref)) {
		ret = PTR_ERR(key_ref);
		mutex_unlock(&keyring_mutex);
		return ret;
	}

	key_ref_put(key_ref);
	mutex_unlock(&keyring_mutex);

	pr_info("tquic_cert: Added trusted CA: %s\n", description);
	return 0;
#else
	return -EAGAIN;
#endif
}
EXPORT_SYMBOL_GPL(tquic_add_trusted_ca);

int tquic_remove_trusted_ca(const char *description)
{
#ifdef CONFIG_SYSTEM_DATA_VERIFICATION
	key_ref_t key_ref;
	struct key *key;

	if (!description)
		return -EINVAL;

	mutex_lock(&keyring_mutex);

	if (!tquic_trusted_keyring) {
		mutex_unlock(&keyring_mutex);
		return -ENOENT;
	}

	key_ref = keyring_search(make_key_ref(tquic_trusted_keyring, true),
				 &key_type_asymmetric, description, true);
	if (IS_ERR(key_ref)) {
		mutex_unlock(&keyring_mutex);
		return PTR_ERR(key_ref);
	}

	key = key_ref_to_ptr(key_ref);
	key_unlink(tquic_trusted_keyring, key);
	key_ref_put(key_ref);

	mutex_unlock(&keyring_mutex);

	pr_info("tquic_cert: Removed trusted CA: %s\n", description);
	return 0;
#else
	return -EAGAIN;
#endif
}
EXPORT_SYMBOL_GPL(tquic_remove_trusted_ca);

int tquic_clear_trusted_cas(void)
{
#ifdef CONFIG_SYSTEM_DATA_VERIFICATION
	int count = 0;

	mutex_lock(&keyring_mutex);

	if (tquic_trusted_keyring) {
		key_put(tquic_trusted_keyring);
		tquic_trusted_keyring = NULL;
		count = 1;  /* Simplified - actual count would need iteration */
	}

	mutex_unlock(&keyring_mutex);

	pr_info("tquic_cert: Cleared all custom trusted CAs\n");
	return count;
#else
	return 0;
#endif
}
EXPORT_SYMBOL_GPL(tquic_clear_trusted_cas);

/*
 * Sysctl accessor functions
 */


/*
 * Procfs interface for trusted CA management
 */

static int tquic_proc_trusted_cas_show(struct seq_file *m, void *v)
{
	tquic_dbg("tquic_proc_trusted_cas_show: reading procfs\n");

#ifdef CONFIG_SYSTEM_DATA_VERIFICATION
	mutex_lock(&keyring_mutex);

	if (tquic_trusted_keyring) {
		seq_printf(m, "TQUIC Trusted CA Keyring: %s\n",
			   tquic_trusted_keyring->description);
		/* Listing individual keys would require more complex iteration */
	} else {
		seq_puts(m, "No custom trusted CAs configured.\n");
		seq_puts(m, "Using system keyring for trust anchors.\n");
	}

	mutex_unlock(&keyring_mutex);
#else
	seq_puts(m, "Kernel keyring support not enabled.\n");
#endif
	return 0;
}

static int tquic_proc_trusted_cas_open(struct inode *inode, struct file *file)
{
	return single_open(file, tquic_proc_trusted_cas_show, NULL);
}

static ssize_t tquic_proc_trusted_cas_write(struct file *file,
					    const char __user *buffer,
					    size_t count, loff_t *ppos)
{
	char *kbuf;
	int ret;

	/* Require CAP_NET_ADMIN to modify trusted CAs */
	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	if (count > TQUIC_MAX_CERT_SIZE || count == 0)
		return -EINVAL;

	kbuf = kmalloc(size_add(count, 1), GFP_KERNEL);
	if (!kbuf)
		return -ENOMEM;

	if (copy_from_user(kbuf, buffer, count)) {
		kfree_sensitive(kbuf);
		return -EFAULT;
	}
	kbuf[count] = '\0';

	/* Check for command prefix */
	if (strncmp(kbuf, "clear", 5) == 0) {
		tquic_clear_trusted_cas();
		ret = count;
	} else if (strncmp(kbuf, "remove:", 7) == 0) {
		ret = tquic_remove_trusted_ca(kbuf + 7);
		if (ret == 0)
			ret = count;
	} else {
		/* Assume it's a DER certificate with description */
		/* Format: "description:base64data" or raw DER */
		ret = -EINVAL;  /* Would need base64 decoding */
	}

	kfree_sensitive(kbuf);
	return ret;
}

static const struct proc_ops tquic_proc_trusted_cas_ops = {
	.proc_open	= tquic_proc_trusted_cas_open,
	.proc_read	= seq_read,
	.proc_write	= tquic_proc_trusted_cas_write,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

static int tquic_proc_verify_config_show(struct seq_file *m, void *v)
{
	static const char *mode_names[] = { "none", "optional", "required" };
	static const char *revoke_names[] = { "none", "soft_fail", "hard_fail" };

	tquic_dbg("tquic_proc_verify_config_show: mode=%d hostname_check=%d\n",
		  tquic_cert_verify_mode, tquic_cert_verify_hostname_enabled);

	seq_printf(m, "verify_mode: %s\n",
		   mode_names[tquic_cert_verify_mode]);
	seq_printf(m, "verify_hostname: %s\n",
		   tquic_cert_verify_hostname_enabled ? "yes" : "no");
	seq_printf(m, "revocation_mode: %s\n",
		   revoke_names[tquic_cert_revocation_mode]);
	seq_printf(m, "time_tolerance: %d seconds\n",
		   tquic_cert_time_tolerance);
	seq_printf(m, "min_rsa_bits: %d\n", tquic_cert_min_rsa_bits);
	seq_printf(m, "min_ec_bits: %d\n", tquic_cert_min_ec_bits);

	return 0;
}

static int tquic_proc_verify_config_open(struct inode *inode, struct file *file)
{
	return single_open(file, tquic_proc_verify_config_show, NULL);
}

static const struct proc_ops tquic_proc_verify_config_ops = {
	.proc_open	= tquic_proc_verify_config_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

/*
 * Module initialization
 */

int __init tquic_cert_verify_init(void)
{
	mutex_lock(&keyring_mutex);
	tquic_trusted_keyring = NULL;  /* Will use system keyring by default */
	mutex_unlock(&keyring_mutex);

	/* Create procfs entries */
	tquic_cert_proc_dir = proc_mkdir("tquic_cert", init_net.proc_net);
	if (tquic_cert_proc_dir) {
		proc_create("trusted_cas", 0600, tquic_cert_proc_dir,
			    &tquic_proc_trusted_cas_ops);
		proc_create("config", 0444, tquic_cert_proc_dir,
			    &tquic_proc_verify_config_ops);
	}

	pr_info("tquic_cert: Certificate verification module initialized\n");
	pr_info("tquic_cert: Default mode: required, hostname verification: enabled\n");
	return 0;
}

void tquic_cert_verify_exit(void)
{
	/* Remove procfs entries */
	if (tquic_cert_proc_dir) {
		remove_proc_entry("trusted_cas", tquic_cert_proc_dir);
		remove_proc_entry("config", tquic_cert_proc_dir);
		remove_proc_entry("tquic_cert", init_net.proc_net);
	}

	mutex_lock(&keyring_mutex);
	if (tquic_trusted_keyring)
		key_put(tquic_trusted_keyring);
	tquic_trusted_keyring = NULL;
	mutex_unlock(&keyring_mutex);

	pr_info("tquic_cert: Certificate verification module unloaded\n");
}

MODULE_DESCRIPTION("TQUIC Certificate Chain Validation");
MODULE_LICENSE("GPL");
