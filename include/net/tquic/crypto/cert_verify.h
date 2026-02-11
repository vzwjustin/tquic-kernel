/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: Certificate Chain Validation
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
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

/* Maximum number of name constraint subtrees per certificate */
#define TQUIC_MAX_NAME_CONSTRAINTS	32

/* GeneralName types used in name constraints (RFC 5280 Section 4.2.1.10) */
#define TQUIC_NC_TYPE_DNS	2	/* dNSName [2] */
#define TQUIC_NC_TYPE_EMAIL	1	/* rfc822Name [1] */

/**
 * struct tquic_name_constraint - A single name constraint subtree entry
 * @type: GeneralName type (TQUIC_NC_TYPE_DNS, TQUIC_NC_TYPE_EMAIL)
 * @name: The name/domain string (null-terminated, heap-allocated)
 * @name_len: Length of name string (excluding null terminator)
 */
struct tquic_name_constraint {
	u8 type;
	char *name;
	u32 name_len;
};

/**
 * struct tquic_name_constraints - Parsed nameConstraints extension
 * @permitted: Array of permitted subtree entries
 * @nr_permitted: Number of permitted subtree entries
 * @excluded: Array of excluded subtree entries
 * @nr_excluded: Number of excluded subtree entries
 * @critical: Whether the extension was marked critical
 * @has_unsupported_type: A constraint type we cannot process was present
 */
struct tquic_name_constraints {
	struct tquic_name_constraint permitted[TQUIC_MAX_NAME_CONSTRAINTS];
	u32 nr_permitted;
	struct tquic_name_constraint excluded[TQUIC_MAX_NAME_CONSTRAINTS];
	u32 nr_excluded;
	bool critical;
	bool has_unsupported_type;
};

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

/* Maximum CRL/OCSP response size */
#define TQUIC_MAX_CRL_SIZE		(1024 * 1024)	/* 1MB */
#define TQUIC_MAX_OCSP_RESP_SIZE	(64 * 1024)	/* 64KB */

/* Signature algorithm identifiers (TLS 1.3 / RFC 8446) */
#define TLS_SIG_RSA_PKCS1_SHA256	0x0401
#define TLS_SIG_RSA_PKCS1_SHA384	0x0501
#define TLS_SIG_RSA_PKCS1_SHA512	0x0601
#define TLS_SIG_ECDSA_SECP256R1_SHA256	0x0403
#define TLS_SIG_ECDSA_SECP384R1_SHA384	0x0503
#define TLS_SIG_ECDSA_SECP521R1_SHA512	0x0603
#define TLS_SIG_RSA_PSS_RSAE_SHA256	0x0804
#define TLS_SIG_RSA_PSS_RSAE_SHA384	0x0805
#define TLS_SIG_RSA_PSS_RSAE_SHA512	0x0806
#define TLS_SIG_ED25519			0x0807
#define TLS_SIG_ED448			0x0808

/* Public key algorithm types */
enum tquic_pubkey_algo {
	TQUIC_PUBKEY_ALGO_RSA = 0,
	TQUIC_PUBKEY_ALGO_ECDSA_P256,
	TQUIC_PUBKEY_ALGO_ECDSA_P384,
	TQUIC_PUBKEY_ALGO_ECDSA_P521,
	TQUIC_PUBKEY_ALGO_ED25519,
	TQUIC_PUBKEY_ALGO_ED448,
	TQUIC_PUBKEY_ALGO_UNKNOWN,
};

/* Hash algorithm types */
enum tquic_hash_algo {
	TQUIC_HASH_SHA256 = 0,
	TQUIC_HASH_SHA384,
	TQUIC_HASH_SHA512,
	TQUIC_HASH_UNKNOWN,
};

/**
 * struct tquic_x509_signature - Parsed certificate signature
 * @algo: Signature algorithm OID
 * @sig_algo_id: TLS signature algorithm identifier
 * @signature: Signature bytes
 * @sig_len: Length of signature
 * @hash_algo: Hash algorithm used
 * @pubkey_algo: Public key algorithm used
 */
struct tquic_x509_signature {
	const u8 *algo;
	u32 algo_len;
	u16 sig_algo_id;
	u8 *signature;
	u32 sig_len;
	enum tquic_hash_algo hash_algo;
	enum tquic_pubkey_algo pubkey_algo;
};

/**
 * struct tquic_x509_pubkey - Parsed public key
 * @algo: Algorithm OID
 * @algo_len: Length of algorithm OID
 * @key_data: Raw public key data (DER)
 * @key_len: Length of key data
 * @pubkey_algo: Public key algorithm type
 * @key_bits: Key size in bits
 */
struct tquic_x509_pubkey {
	const u8 *algo;
	u32 algo_len;
	u8 *key_data;
	u32 key_len;
	enum tquic_pubkey_algo pubkey_algo;
	u32 key_bits;
};

/**
 * struct tquic_x509_cert - Parsed X.509 certificate
 * @raw: Raw DER-encoded certificate data
 * @raw_len: Length of raw data
 * @tbs: TBSCertificate data (for signature verification)
 * @tbs_len: Length of TBSCertificate
 * @subject: Subject DN (Common Name extracted)
 * @subject_len: Length of subject
 * @issuer: Issuer DN
 * @issuer_len: Length of issuer
 * @issuer_raw: Raw issuer DN for matching
 * @issuer_raw_len: Length of raw issuer DN
 * @subject_raw: Raw subject DN for matching
 * @subject_raw_len: Length of raw subject DN
 * @serial: Serial number
 * @serial_len: Length of serial number
 * @valid_from: Not before timestamp (seconds since epoch)
 * @valid_to: Not after timestamp (seconds since epoch)
 * @is_ca: True if certificate is a CA
 * @path_len_constraint: Path length constraint (-1 if none)
 * @key_usage: Key usage bits
 * @ext_key_usage: Extended key usage flags
 * @san_dns: Subject Alternative Names (DNS)
 * @san_dns_count: Number of DNS SANs
 * @san_ip: Subject Alternative Names (IP addresses)
 * @san_ip_count: Number of IP SANs
 * @pubkey: Parsed public key
 * @signature: Parsed signature
 * @sig_algo: Signature algorithm OID
 * @self_signed: True if self-signed
 * @akid: Authority Key Identifier
 * @akid_len: Length of AKID
 * @skid: Subject Key Identifier
 * @skid_len: Length of SKID
 * @crl_dp: CRL Distribution Point URLs
 * @crl_dp_count: Number of CRL DPs
 * @ocsp_url: OCSP responder URL
 * @ocsp_url_len: Length of OCSP URL
 * @next: Next certificate in chain (issuer direction)
 */
struct tquic_x509_cert {
	u8 *raw;
	u32 raw_len;
	const u8 *tbs;
	u32 tbs_len;
	char *subject;
	u32 subject_len;
	char *issuer;
	u32 issuer_len;
	u8 *issuer_raw;
	u32 issuer_raw_len;
	u8 *subject_raw;
	u32 subject_raw_len;
	u8 *serial;
	u32 serial_len;
	s64 valid_from;
	s64 valid_to;
	bool is_ca;
	int path_len_constraint;
	u16 key_usage;
	u32 ext_key_usage;
	char **san_dns;
	u32 san_dns_count;
	u8 **san_ip;
	u32 *san_ip_len;
	u32 san_ip_count;
	struct tquic_x509_pubkey pubkey;
	struct tquic_x509_signature signature;
	u16 sig_algo;
	bool self_signed;
	u8 *akid;
	u32 akid_len;
	u8 *skid;
	u32 skid_len;
	char **crl_dp;
	u32 crl_dp_count;
	char *ocsp_url;
	u32 ocsp_url_len;
	struct tquic_name_constraints *name_constraints;
	struct tquic_x509_cert *next;
};

/* Key usage bits (RFC 5280) */
#define TQUIC_KU_DIGITAL_SIGNATURE	0x0080
#define TQUIC_KU_NON_REPUDIATION	0x0040
#define TQUIC_KU_KEY_ENCIPHERMENT	0x0020
#define TQUIC_KU_DATA_ENCIPHERMENT	0x0010
#define TQUIC_KU_KEY_AGREEMENT		0x0008
#define TQUIC_KU_KEY_CERT_SIGN		0x0004
#define TQUIC_KU_CRL_SIGN		0x0002
#define TQUIC_KU_ENCIPHER_ONLY		0x0001
#define TQUIC_KU_DECIPHER_ONLY		0x8000

/* Extended key usage flags */
#define TQUIC_EKU_SERVER_AUTH		0x0001
#define TQUIC_EKU_CLIENT_AUTH		0x0002
#define TQUIC_EKU_CODE_SIGNING		0x0004
#define TQUIC_EKU_EMAIL_PROTECTION	0x0008
#define TQUIC_EKU_TIME_STAMPING		0x0010
#define TQUIC_EKU_OCSP_SIGNING		0x0020

/* Revocation check modes */
enum tquic_revocation_mode {
	TQUIC_REVOKE_NONE = 0,		/* No revocation checking */
	TQUIC_REVOKE_SOFT_FAIL = 1,	/* Check but ignore failures */
	TQUIC_REVOKE_HARD_FAIL = 2,	/* Check and fail if cannot verify */
};

/**
 * struct tquic_cert_verify_ctx - Certificate verification context
 * @trusted_keyring: Reference to kernel keyring with trusted root CAs
 * @expected_hostname: Expected server hostname for SNI matching
 * @hostname_len: Length of expected_hostname
 * @verify_mode: Verification mode (none/optional/required)
 * @verify_hostname: Whether to perform hostname verification
 * @allow_self_signed: Allow self-signed certificates (testing only)
 * @check_revocation: Revocation check mode
 * @time_tolerance: Allowed clock skew in seconds
 * @min_key_bits_rsa: Minimum RSA key size (default 2048)
 * @min_key_bits_ec: Minimum EC key size (default 256)
 * @chain: Parsed certificate chain
 * @chain_len: Number of certificates in chain
 * @error_code: Last error code
 * @error_msg: Human-readable error message
 * @error_depth: Chain depth where error occurred
 * @ocsp_stapling: OCSP stapling data from TLS
 * @ocsp_stapling_len: Length of OCSP stapling data
 */
struct tquic_cert_verify_ctx {
	struct key *trusted_keyring;
	char *expected_hostname;
	u32 hostname_len;
	enum tquic_cert_verify_mode verify_mode;
	bool verify_hostname;
	bool allow_self_signed;
	enum tquic_revocation_mode check_revocation;
	u32 time_tolerance;
	u32 min_key_bits_rsa;
	u32 min_key_bits_ec;
	struct tquic_x509_cert *chain;
	u32 chain_len;
	int error_code;
	const char *error_msg;
	u32 error_depth;
	u8 *ocsp_stapling;
	u32 ocsp_stapling_len;
	/* CF-003: use client EKU for client certificate verification */
	bool is_server;
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
#define TQUIC_CERT_ERR_KEY_USAGE	-14
#define TQUIC_CERT_ERR_ISSUER_MISMATCH	-15
#define TQUIC_CERT_ERR_PATH_LEN		-16
#define TQUIC_CERT_ERR_REVOCATION_CHECK	-17
#define TQUIC_CERT_ERR_NAME_CONSTRAINTS	-18

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
 *   - Key usage validation
 *   - Path length constraint checking
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
 * Performs actual cryptographic signature verification using
 * the kernel's public_key_verify_signature() API.
 *
 * Returns: 0 on success, -EKEYREJECTED on signature mismatch
 */
int tquic_x509_verify_signature(const struct tquic_x509_cert *cert,
				const struct tquic_x509_cert *issuer);

/**
 * tquic_x509_check_key_usage - Verify certificate key usage
 * @cert: Certificate to check
 * @depth: Chain depth (0 = end-entity)
 * @is_server: True if verifying server certificate
 *
 * Returns: 0 if key usage is appropriate, -EKEYREJECTED otherwise
 */
int tquic_x509_check_key_usage(const struct tquic_x509_cert *cert,
			       int depth, bool is_server);

/*
 * Revocation checking
 */

/**
 * tquic_check_revocation - Check certificate revocation status
 * @ctx: Verification context
 * @cert: Certificate to check
 *
 * Checks OCSP stapling first (if provided), then falls back to CRL.
 *
 * Returns: 0 if not revoked, -EKEYREVOKED if revoked, other errors on failure
 */
int tquic_check_revocation(struct tquic_cert_verify_ctx *ctx,
			   const struct tquic_x509_cert *cert);

/*
 * Trusted CA management via procfs
 */

/**
 * tquic_add_trusted_ca - Add a trusted CA certificate
 * @cert_data: DER-encoded certificate data
 * @cert_len: Length of certificate data
 * @description: Human-readable description
 *
 * Adds a CA certificate to the TQUIC trusted keyring.
 *
 * Returns: 0 on success, -errno on failure
 */
int tquic_add_trusted_ca(const u8 *cert_data, u32 cert_len,
			 const char *description);

/**
 * tquic_remove_trusted_ca - Remove a trusted CA certificate
 * @description: Description of certificate to remove
 *
 * Returns: 0 on success, -ENOENT if not found
 */
int tquic_remove_trusted_ca(const char *description);

/**
 * tquic_clear_trusted_cas - Remove all custom trusted CAs
 *
 * Returns: Number of certificates removed
 */
int tquic_clear_trusted_cas(void);

/*
 * Sysctl accessors
 */
int tquic_sysctl_get_cert_verify_mode(void);
bool tquic_sysctl_get_cert_verify_hostname(void);
int tquic_sysctl_get_cert_revocation_mode(void);
u32 tquic_sysctl_get_cert_time_tolerance(void);

/*
 * Module initialization
 */
int __init tquic_cert_verify_init(void);
void __exit tquic_cert_verify_exit(void);

#endif /* _TQUIC_CERT_VERIFY_H */
