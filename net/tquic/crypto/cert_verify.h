/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: Certificate Chain Validation
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Provides X.509 certificate chain validation for TQUIC TLS 1.3
 * connections using the kernel's keyring infrastructure.
 */

#ifndef _TQUIC_CERT_VERIFY_H
#define _TQUIC_CERT_VERIFY_H

#include <linux/types.h>
#include <linux/key.h>

/* Forward declarations */
struct tquic_handshake;
struct tquic_connection;

/* Certificate verification modes */
enum tquic_cert_verify_mode {
	TQUIC_CERT_VERIFY_NONE     = 0,  /* No verification (insecure) */
	TQUIC_CERT_VERIFY_OPTIONAL = 1,  /* Verify if cert present, but allow missing */
	TQUIC_CERT_VERIFY_REQUIRED = 2,  /* Full verification required (default) */
};

/* Maximum hostname length for SNI matching */
#define TQUIC_MAX_HOSTNAME_LEN	255

/* Maximum certificate chain length */
#define TQUIC_MAX_CERT_CHAIN_LEN	16

/* Maximum single certificate size */
#define TQUIC_MAX_CERT_SIZE		16384

/**
 * struct tquic_x509_cert - Parsed X.509 certificate
 * @raw: Raw DER-encoded certificate data
 * @raw_len: Length of raw data
 * @subject: Subject DN (Common Name extracted)
 * @subject_len: Length of subject
 * @issuer: Issuer DN
 * @issuer_len: Length of issuer
 * @serial: Serial number
 * @serial_len: Length of serial number
 * @valid_from: Not before timestamp (seconds since epoch)
 * @valid_to: Not after timestamp (seconds since epoch)
 * @is_ca: True if certificate is a CA
 * @san_dns: Subject Alternative Names (DNS)
 * @san_dns_count: Number of DNS SANs
 * @pub_key: Public key data
 * @pub_key_len: Length of public key
 * @sig_algo: Signature algorithm OID
 * @self_signed: True if self-signed
 * @next: Next certificate in chain (issuer direction)
 */
struct tquic_x509_cert {
	u8 *raw;
	u32 raw_len;
	char *subject;
	u32 subject_len;
	char *issuer;
	u32 issuer_len;
	u8 *serial;
	u32 serial_len;
	s64 valid_from;
	s64 valid_to;
	bool is_ca;
	char **san_dns;
	u32 san_dns_count;
	u8 *pub_key;
	u32 pub_key_len;
	u16 sig_algo;
	bool self_signed;
	struct tquic_x509_cert *next;
};

/**
 * struct tquic_cert_verify_ctx - Certificate verification context
 * @trusted_keyring: Reference to kernel keyring with trusted root CAs
 * @expected_hostname: Expected server hostname for SNI matching
 * @hostname_len: Length of expected_hostname
 * @verify_mode: Verification mode (none/optional/required)
 * @verify_hostname: Whether to perform hostname verification
 * @allow_self_signed: Allow self-signed certificates (testing only)
 * @check_revocation: Check certificate revocation status
 * @time_tolerance: Allowed clock skew in seconds
 * @chain: Parsed certificate chain
 * @chain_len: Number of certificates in chain
 * @error_code: Last error code
 * @error_msg: Human-readable error message
 */
struct tquic_cert_verify_ctx {
	struct key *trusted_keyring;
	char *expected_hostname;
	u32 hostname_len;
	enum tquic_cert_verify_mode verify_mode;
	bool verify_hostname;
	bool allow_self_signed;
	bool check_revocation;
	u32 time_tolerance;
	struct tquic_x509_cert *chain;
	u32 chain_len;
	int error_code;
	const char *error_msg;
};

/**
 * struct tquic_cert_chain_entry - Entry in certificate chain from TLS
 * @cert_data: Raw DER certificate data
 * @cert_len: Length of certificate data
 * @extensions: Certificate extensions (OCSP, SCT)
 * @ext_len: Length of extensions
 */
struct tquic_cert_chain_entry {
	const u8 *cert_data;
	u32 cert_len;
	const u8 *extensions;
	u32 ext_len;
};

/* Certificate verification result codes */
#define TQUIC_CERT_OK			0
#define TQUIC_CERT_ERR_PARSE		-1
#define TQUIC_CERT_ERR_EXPIRED		-2
#define TQUIC_CERT_ERR_NOT_YET_VALID	-3
#define TQUIC_CERT_ERR_REVOKED		-4
#define TQUIC_CERT_ERR_UNTRUSTED	-5
#define TQUIC_CERT_ERR_HOSTNAME		-6
#define TQUIC_CERT_ERR_SELF_SIGNED	-7
#define TQUIC_CERT_ERR_CHAIN_TOO_LONG	-8
#define TQUIC_CERT_ERR_SIG_VERIFY	-9
#define TQUIC_CERT_ERR_NO_CERT		-10
#define TQUIC_CERT_ERR_INTERNAL		-11
#define TQUIC_CERT_ERR_WEAK_KEY		-12
#define TQUIC_CERT_ERR_CONSTRAINT	-13

/*
 * Core API
 */

/**
 * tquic_cert_verify_ctx_alloc - Allocate certificate verification context
 * @gfp: GFP flags for allocation
 *
 * Returns: Allocated context or NULL on failure
 */
struct tquic_cert_verify_ctx *tquic_cert_verify_ctx_alloc(gfp_t gfp);

/**
 * tquic_cert_verify_ctx_free - Free certificate verification context
 * @ctx: Context to free
 */
void tquic_cert_verify_ctx_free(struct tquic_cert_verify_ctx *ctx);

/**
 * tquic_cert_verify_set_hostname - Set expected hostname for verification
 * @ctx: Verification context
 * @hostname: Expected hostname (will be copied)
 * @len: Length of hostname
 *
 * Returns: 0 on success, -errno on failure
 */
int tquic_cert_verify_set_hostname(struct tquic_cert_verify_ctx *ctx,
				   const char *hostname, u32 len);

/**
 * tquic_cert_verify_set_mode - Set verification mode
 * @ctx: Verification context
 * @mode: Verification mode
 *
 * Returns: 0 on success, -EINVAL if mode is invalid
 */
int tquic_cert_verify_set_mode(struct tquic_cert_verify_ctx *ctx,
			       enum tquic_cert_verify_mode mode);

/**
 * tquic_cert_verify_set_keyring - Set trusted keyring for verification
 * @ctx: Verification context
 * @keyring: Keyring containing trusted root certificates
 *           NULL to use system keyring
 *
 * Returns: 0 on success, -errno on failure
 */
int tquic_cert_verify_set_keyring(struct tquic_cert_verify_ctx *ctx,
				  struct key *keyring);

/**
 * tquic_verify_cert_chain - Verify certificate chain
 * @ctx: Verification context
 * @cert_chain: Raw DER-encoded certificate chain from TLS
 * @chain_len: Length of certificate chain data
 *
 * Parses and validates the certificate chain received during TLS handshake.
 * Performs:
 *   - Certificate parsing
 *   - Chain building (end-entity -> intermediate -> root)
 *   - Signature verification at each level
 *   - Validity period checking
 *   - Root trust anchor lookup in keyring
 *   - Hostname verification (if enabled)
 *
 * Returns: 0 on success, negative error code on failure
 *          Error details available via ctx->error_code and ctx->error_msg
 */
int tquic_verify_cert_chain(struct tquic_cert_verify_ctx *ctx,
			    const u8 *cert_chain, size_t chain_len);

/**
 * tquic_verify_hostname - Verify hostname matches certificate
 * @cert: End-entity certificate
 * @expected: Expected hostname
 * @expected_len: Length of expected hostname
 *
 * Checks the certificate's Subject CN and Subject Alternative Names
 * against the expected hostname. Supports wildcard matching per RFC 6125.
 *
 * Returns: 0 if hostname matches, -ENOENT if no match found
 */
int tquic_verify_hostname(const struct tquic_x509_cert *cert,
			  const char *expected, u32 expected_len);

/**
 * tquic_cert_verify_get_error - Get human-readable error message
 * @ctx: Verification context
 *
 * Returns: Error message string (do not free)
 */
const char *tquic_cert_verify_get_error(struct tquic_cert_verify_ctx *ctx);

/*
 * Integration with handshake
 */

/**
 * tquic_hs_verify_server_cert - Verify server certificate during handshake
 * @hs: Handshake context
 * @conn: TQUIC connection
 *
 * Called after receiving Certificate message from server.
 * Uses the socket's certificate verification settings.
 *
 * Returns: 0 on success, TLS alert code on failure
 */
int tquic_hs_verify_server_cert(struct tquic_handshake *hs,
				struct tquic_connection *conn);

/**
 * tquic_hs_verify_client_cert - Verify client certificate during handshake
 * @hs: Handshake context
 * @conn: TQUIC connection
 *
 * Called after receiving Certificate message from client (mutual auth).
 * Uses the socket's client certificate verification settings.
 *
 * Returns: 0 on success, TLS alert code on failure
 */
int tquic_hs_verify_client_cert(struct tquic_handshake *hs,
				struct tquic_connection *conn);

/*
 * X.509 Certificate parsing helpers
 */

/**
 * tquic_x509_cert_parse - Parse a single X.509 certificate
 * @data: DER-encoded certificate data
 * @len: Length of data
 * @gfp: GFP flags for allocation
 *
 * Returns: Parsed certificate structure or NULL on failure
 */
struct tquic_x509_cert *tquic_x509_cert_parse(const u8 *data, u32 len,
					      gfp_t gfp);

/**
 * tquic_x509_cert_free - Free parsed certificate
 * @cert: Certificate to free
 */
void tquic_x509_cert_free(struct tquic_x509_cert *cert);

/**
 * tquic_x509_chain_free - Free entire certificate chain
 * @chain: First certificate in chain
 */
void tquic_x509_chain_free(struct tquic_x509_cert *chain);

/**
 * tquic_x509_cert_is_valid_time - Check certificate validity period
 * @cert: Certificate to check
 * @tolerance: Allowed clock skew in seconds
 *
 * Returns: 0 if valid, -EKEYEXPIRED if expired, -EKEYREJECTED if not yet valid
 */
int tquic_x509_cert_is_valid_time(const struct tquic_x509_cert *cert,
				  u32 tolerance);

/**
 * tquic_x509_verify_signature - Verify certificate signature
 * @cert: Certificate to verify
 * @issuer: Issuer certificate (or self for root)
 *
 * Returns: 0 on success, -EKEYREJECTED on signature mismatch
 */
int tquic_x509_verify_signature(const struct tquic_x509_cert *cert,
				const struct tquic_x509_cert *issuer);

/*
 * Module initialization
 */
int __init tquic_cert_verify_init(void);
void __exit tquic_cert_verify_exit(void);

#endif /* _TQUIC_CERT_VERIFY_H */
