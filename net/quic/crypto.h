/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * QUIC Cryptographic Operations Header
 *
 * Declarations for QUIC packet protection as specified in RFC 9001.
 *
 * Copyright (c) 2024 Linux QUIC Implementation Authors
 */

#ifndef _NET_QUIC_CRYPTO_H
#define _NET_QUIC_CRYPTO_H

#include <linux/types.h>
#include <linux/socket.h>
#include <crypto/hash.h>

/*
 * TLS 1.3 Cipher Suite Identifiers
 */
#define QUIC_CIPHER_AES_128_GCM_SHA256		0x1301
#define QUIC_CIPHER_AES_256_GCM_SHA384		0x1302
#define QUIC_CIPHER_CHACHA20_POLY1305_SHA256	0x1303

/*
 * QUIC Version Constants
 */
#define QUIC_VERSION_1		0x00000001
#define QUIC_VERSION_2		0x6b3343cf

/*
 * Cryptographic Size Constants
 */
#define QUIC_MAX_CID_LEN	20
#define QUIC_TAG_SIZE		16
#define QUIC_IV_SIZE		12
#define QUIC_SAMPLE_SIZE	16
#define QUIC_HP_MASK_SIZE	5

/*
 * Maximum key sizes
 */
#define QUIC_MAX_KEY_SIZE	32
#define QUIC_MAX_IV_SIZE	12
#define QUIC_MAX_HASH_SIZE	48

/* Opaque crypto context */
struct quic_crypto_ctx;

/*
 * Crypto context management
 */

/**
 * quic_crypto_ctx_alloc - Allocate a QUIC crypto context
 * @cipher_suite: TLS cipher suite identifier (e.g., QUIC_CIPHER_AES_128_GCM_SHA256)
 * @gfp: Memory allocation flags
 *
 * Allocates and initializes a new QUIC crypto context for the specified
 * cipher suite. The context includes AEAD, header protection, and HMAC
 * cipher handles.
 *
 * Return: Pointer to allocated context on success, ERR_PTR on failure
 */
struct quic_crypto_ctx *quic_crypto_ctx_alloc(u16 cipher_suite, gfp_t gfp);

/**
 * quic_crypto_ctx_free - Free a QUIC crypto context
 * @ctx: Context to free (may be NULL)
 *
 * Releases all resources associated with the crypto context, including
 * zeroizing sensitive key material.
 */
void quic_crypto_ctx_free(struct quic_crypto_ctx *ctx);

/**
 * quic_crypto_ctx_get - Get a reference to a crypto context
 * @ctx: Context to reference
 *
 * Return: The context pointer
 */
struct quic_crypto_ctx *quic_crypto_ctx_get(struct quic_crypto_ctx *ctx);

/**
 * quic_crypto_ctx_put - Release a reference to a crypto context
 * @ctx: Context to release
 */
void quic_crypto_ctx_put(struct quic_crypto_ctx *ctx);

/*
 * Key Derivation Functions (RFC 9001)
 */

/**
 * quic_hkdf_extract - HKDF-Extract operation
 * @hmac: HMAC transform handle
 * @salt: Salt value
 * @salt_len: Length of salt
 * @ikm: Input keying material
 * @ikm_len: Length of IKM
 * @prk: Output pseudorandom key
 * @prk_len: Length of PRK buffer
 *
 * Performs HKDF-Extract as defined in RFC 5869.
 *
 * Return: 0 on success, negative error code on failure
 */
int quic_hkdf_extract(struct crypto_shash *hmac,
		      const u8 *salt, size_t salt_len,
		      const u8 *ikm, size_t ikm_len,
		      u8 *prk, size_t prk_len);

/**
 * quic_hkdf_expand_label - HKDF-Expand-Label operation
 * @hmac: HMAC transform handle
 * @secret: Input secret
 * @secret_len: Length of secret
 * @label: Label string (without "tls13 " prefix)
 * @context: Context data (may be NULL)
 * @context_len: Length of context
 * @out: Output buffer
 * @out_len: Desired output length
 *
 * Performs HKDF-Expand-Label as defined in RFC 8446 Section 7.1.
 *
 * Return: 0 on success, negative error code on failure
 */
int quic_hkdf_expand_label(struct crypto_shash *hmac,
			   const u8 *secret, size_t secret_len,
			   const char *label,
			   const u8 *context, size_t context_len,
			   u8 *out, size_t out_len);

/**
 * quic_derive_initial_secrets - Derive initial packet protection keys
 * @ctx: Crypto context
 * @dcid: Destination Connection ID
 * @dcid_len: Length of DCID
 * @is_server: True if deriving server keys, false for client keys
 * @version: QUIC version number
 *
 * Derives the initial secrets from the destination connection ID as
 * specified in RFC 9001 Section 5.2. Uses version-specific salt.
 *
 * Return: 0 on success, negative error code on failure
 */
int quic_derive_initial_secrets(struct quic_crypto_ctx *ctx,
				const u8 *dcid, size_t dcid_len,
				bool is_server, u32 version);

/**
 * quic_derive_handshake_secrets - Derive handshake packet protection keys
 * @ctx: Crypto context
 * @secret: Handshake traffic secret from TLS
 * @secret_len: Length of secret
 *
 * Derives handshake traffic keys from the TLS handshake secret.
 *
 * Return: 0 on success, negative error code on failure
 */
int quic_derive_handshake_secrets(struct quic_crypto_ctx *ctx,
				  const u8 *secret, size_t secret_len);

/**
 * quic_derive_application_secrets - Derive 1-RTT packet protection keys
 * @ctx: Crypto context
 * @secret: Application traffic secret from TLS
 * @secret_len: Length of secret
 *
 * Derives 1-RTT (application) traffic keys from the TLS traffic secret.
 * Resets the key phase to 0.
 *
 * Return: 0 on success, negative error code on failure
 */
int quic_derive_application_secrets(struct quic_crypto_ctx *ctx,
				    const u8 *secret, size_t secret_len);

/*
 * Header Protection (RFC 9001 Section 5.4)
 */

/**
 * quic_hp_mask - Generate header protection mask
 * @ctx: Crypto context
 * @sample: 16-byte sample from encrypted packet
 * @mask: Output 5-byte mask
 *
 * Generates the header protection mask using AES-ECB encryption
 * of the sample.
 *
 * Return: 0 on success, negative error code on failure
 */
int quic_hp_mask(struct quic_crypto_ctx *ctx,
		 const u8 *sample, u8 *mask);

/**
 * quic_protect_header - Apply header protection
 * @ctx: Crypto context
 * @packet: Packet buffer (modified in place)
 * @packet_len: Length of packet
 * @pn_offset: Offset of packet number field
 * @pn_len: Length of packet number field (1-4 bytes)
 *
 * Applies header protection to the first byte and packet number field
 * of a QUIC packet.
 *
 * Return: 0 on success, negative error code on failure
 */
int quic_protect_header(struct quic_crypto_ctx *ctx,
			u8 *packet, size_t packet_len,
			size_t pn_offset, size_t pn_len);

/**
 * quic_unprotect_header - Remove header protection
 * @ctx: Crypto context
 * @packet: Packet buffer (modified in place)
 * @packet_len: Length of packet
 * @pn_offset: Offset of packet number field
 * @pn_len: Output - detected packet number length
 *
 * Removes header protection from the first byte and packet number
 * field of a QUIC packet.
 *
 * Return: 0 on success, negative error code on failure
 */
int quic_unprotect_header(struct quic_crypto_ctx *ctx,
			  u8 *packet, size_t packet_len,
			  size_t pn_offset, size_t *pn_len);

/*
 * Packet Protection (AEAD - RFC 9001 Section 5.3)
 */

/**
 * quic_encrypt_packet - Encrypt QUIC packet payload
 * @ctx: Crypto context
 * @packet_number: Full packet number for nonce construction
 * @aad: Additional authenticated data (QUIC header)
 * @aad_len: Length of AAD
 * @plaintext: Plaintext payload
 * @plaintext_len: Length of plaintext
 * @ciphertext: Output buffer for AAD + ciphertext + tag
 * @ciphertext_len: In: buffer size, Out: actual output length
 *
 * Encrypts the packet payload using AEAD. The AAD is the QUIC header
 * up to and including the packet number.
 *
 * Return: 0 on success, negative error code on failure
 */
int quic_encrypt_packet(struct quic_crypto_ctx *ctx,
			u64 packet_number,
			const u8 *aad, size_t aad_len,
			const u8 *plaintext, size_t plaintext_len,
			u8 *ciphertext, size_t *ciphertext_len);

/**
 * quic_decrypt_packet - Decrypt QUIC packet payload
 * @ctx: Crypto context
 * @packet_number: Full packet number for nonce construction
 * @aad: Additional authenticated data (QUIC header)
 * @aad_len: Length of AAD
 * @ciphertext: Ciphertext + authentication tag
 * @ciphertext_len: Length of ciphertext + tag
 * @plaintext: Output buffer for decrypted payload
 * @plaintext_len: In: buffer size, Out: actual plaintext length
 *
 * Decrypts and authenticates the packet payload.
 *
 * Return: 0 on success, -EBADMSG on authentication failure,
 *         other negative error code on failure
 */
int quic_decrypt_packet(struct quic_crypto_ctx *ctx,
			u64 packet_number,
			const u8 *aad, size_t aad_len,
			const u8 *ciphertext, size_t ciphertext_len,
			u8 *plaintext, size_t *plaintext_len);

/*
 * Key Update (RFC 9001 Section 6)
 */

/**
 * quic_key_update - Perform key update
 * @ctx: Crypto context
 *
 * Derives new traffic keys from the current secret and toggles
 * the key phase bit.
 *
 * Return: 0 on success, negative error code on failure
 */
int quic_key_update(struct quic_crypto_ctx *ctx);

/**
 * quic_get_key_phase - Get current key phase
 * @ctx: Crypto context
 *
 * Return: Current key phase bit (0 or 1)
 */
u8 quic_get_key_phase(const struct quic_crypto_ctx *ctx);

/*
 * Retry Token Handling (RFC 9001 Section 5.8)
 */

/**
 * quic_generate_retry_token - Generate a retry token
 * @odcid: Original Destination Connection ID
 * @odcid_len: Length of ODCID
 * @client_addr: Client socket address
 * @token: Output buffer for token
 * @token_len: In: buffer size, Out: actual token length
 * @server_key: Server-specific encryption key
 * @key_len: Length of server key
 *
 * Generates an encrypted retry token containing the original DCID,
 * client IP address, and timestamp.
 *
 * Return: 0 on success, negative error code on failure
 */
int quic_generate_retry_token(const u8 *odcid, size_t odcid_len,
			      const struct sockaddr *client_addr,
			      u8 *token, size_t *token_len,
			      const u8 *server_key, size_t key_len);

/**
 * quic_validate_retry_token - Validate a retry token
 * @token: Token to validate
 * @token_len: Length of token
 * @client_addr: Client socket address (for IP validation)
 * @odcid: Output buffer for Original DCID
 * @odcid_len: In: buffer size, Out: actual ODCID length
 * @server_key: Server-specific decryption key
 * @key_len: Length of server key
 * @max_age_seconds: Maximum token age in seconds
 *
 * Decrypts and validates a retry token, checking the client IP
 * and timestamp.
 *
 * Return: 0 on success, -ETIMEDOUT if expired, -EACCES if IP mismatch,
 *         -EBADMSG if decryption fails, other negative on error
 */
int quic_validate_retry_token(const u8 *token, size_t token_len,
			      const struct sockaddr *client_addr,
			      u8 *odcid, size_t *odcid_len,
			      const u8 *server_key, size_t key_len,
			      u32 max_age_seconds);

/**
 * quic_compute_retry_tag - Compute retry packet integrity tag
 * @version: QUIC version
 * @odcid: Original Destination Connection ID
 * @odcid_len: Length of ODCID
 * @retry_packet: Retry packet (without tag)
 * @retry_packet_len: Length of retry packet
 * @tag: Output 16-byte integrity tag
 *
 * Computes the retry integrity tag as specified in RFC 9001 Section 5.8.
 *
 * Return: 0 on success, negative error code on failure
 */
int quic_compute_retry_tag(u32 version,
			   const u8 *odcid, size_t odcid_len,
			   const u8 *retry_packet, size_t retry_packet_len,
			   u8 *tag);

/**
 * quic_verify_retry_tag - Verify retry packet integrity tag
 * @version: QUIC version
 * @odcid: Original Destination Connection ID
 * @odcid_len: Length of ODCID
 * @retry_packet: Retry packet (without tag)
 * @retry_packet_len: Length of retry packet
 * @tag: Expected 16-byte integrity tag
 *
 * Verifies the retry integrity tag.
 *
 * Return: 0 if valid, -EBADMSG if invalid, other negative on error
 */
int quic_verify_retry_tag(u32 version,
			  const u8 *odcid, size_t odcid_len,
			  const u8 *retry_packet, size_t retry_packet_len,
			  const u8 *tag);

/*
 * TLS 1.3 Extension Types (RFC 8446, RFC 7301, RFC 6066)
 */
#define TLS_EXT_SERVER_NAME		0	/* RFC 6066 - SNI */
#define TLS_EXT_ALPN			16	/* RFC 7301 - Application-Layer Protocol Negotiation */
#define TLS_EXT_SUPPORTED_VERSIONS	43	/* RFC 8446 - Supported Versions */
#define TLS_EXT_KEY_SHARE		51	/* RFC 8446 - Key Share */
#define TLS_EXT_QUIC_TRANSPORT_PARAMS	0x39	/* RFC 9001 - QUIC Transport Parameters */

/*
 * TLS Extension Building
 */

/**
 * quic_tls_build_sni_extension - Build SNI extension for ClientHello
 * @hostname: Server hostname (null-terminated)
 * @buf: Output buffer
 * @buf_len: Buffer size
 *
 * Builds the server_name extension (RFC 6066) for TLS ClientHello.
 *
 * Return: Number of bytes written on success, negative error code on failure
 */
int quic_tls_build_sni_extension(const char *hostname, u8 *buf, size_t buf_len);

/**
 * quic_tls_build_alpn_extension - Build ALPN extension
 * @alpn_list: ALPN protocol list (length-prefixed format per RFC 7301)
 * @alpn_len: Length of ALPN list
 * @buf: Output buffer
 * @buf_len: Buffer size
 *
 * Builds the application_layer_protocol_negotiation extension (RFC 7301).
 * Input format: each protocol is prefixed by its length byte.
 * Example: "\x02h3\x08http/1.1" for ["h3", "http/1.1"]
 *
 * Return: Number of bytes written on success, negative error code on failure
 */
int quic_tls_build_alpn_extension(const u8 *alpn_list, size_t alpn_len,
				  u8 *buf, size_t buf_len);

/**
 * quic_tls_parse_sni_extension - Parse SNI extension from ClientHello
 * @data: Extension data (after type and length)
 * @data_len: Length of extension data
 * @hostname: Output buffer for hostname
 * @hostname_len: In: buffer size, Out: actual hostname length
 *
 * Parses the server_name extension from a ClientHello.
 *
 * Return: 0 on success, -EINVAL on parse error, -ENOSPC if buffer too small
 */
int quic_tls_parse_sni_extension(const u8 *data, size_t data_len,
				 char *hostname, size_t *hostname_len);

/**
 * quic_tls_parse_alpn_extension - Parse ALPN extension
 * @data: Extension data (after type and length)
 * @data_len: Length of extension data
 * @alpn_list: Output buffer for ALPN list
 * @alpn_len: In: buffer size, Out: actual list length
 *
 * Parses the ALPN extension. Output format is the same as input to
 * quic_tls_build_alpn_extension (length-prefixed protocol list).
 *
 * Return: 0 on success, -EINVAL on parse error, -ENOSPC if buffer too small
 */
int quic_tls_parse_alpn_extension(const u8 *data, size_t data_len,
				  u8 *alpn_list, size_t *alpn_len);

/**
 * quic_tls_select_alpn - Server ALPN selection
 * @client_alpn: Client's ALPN list (length-prefixed format)
 * @client_alpn_len: Length of client list
 * @server_alpn: Server's supported ALPN list (length-prefixed format)
 * @server_alpn_len: Length of server list
 * @selected: Output buffer for selected protocol
 * @selected_len: In: buffer size, Out: selected protocol length
 *
 * Selects the first protocol from client's list that server supports.
 * Per RFC 7301, server preference should be used when both lists have
 * common protocols.
 *
 * Return: 0 on success (protocol selected),
 *         -ENOENT if no common protocol,
 *         negative error code on failure
 */
int quic_tls_select_alpn(const u8 *client_alpn, size_t client_alpn_len,
			 const u8 *server_alpn, size_t server_alpn_len,
			 u8 *selected, size_t *selected_len);

/**
 * quic_tls_validate_alpn - Validate server's ALPN selection
 * @offered_alpn: Client's offered ALPN list (length-prefixed format)
 * @offered_len: Length of offered list
 * @selected: Server's selected protocol (length-prefixed, single entry)
 * @selected_len: Length of selected protocol
 *
 * Verifies that server's selected ALPN was in client's offered list.
 * Per RFC 7301 Section 3.2, server MUST NOT select a protocol not offered.
 *
 * Return: 0 if valid, -EPROTO if not in offered list
 */
int quic_tls_validate_alpn(const u8 *offered_alpn, size_t offered_len,
			   const u8 *selected, size_t selected_len);

/*
 * Utility Functions
 */

/**
 * quic_crypto_get_params - Get cipher suite parameters
 * @ctx: Crypto context
 * @key_len: Output key length (may be NULL)
 * @iv_len: Output IV length (may be NULL)
 * @tag_len: Output authentication tag length (may be NULL)
 *
 * Return: 0 on success, negative error code on failure
 */
int quic_crypto_get_params(const struct quic_crypto_ctx *ctx,
			   u8 *key_len, u8 *iv_len, u8 *tag_len);

/**
 * quic_crypto_set_keys - Directly set traffic keys
 * @ctx: Crypto context
 * @key: Packet protection key
 * @iv: Initialization vector
 * @hp_key: Header protection key
 *
 * Sets keys directly without derivation. Useful for testing or
 * external key management.
 *
 * Return: 0 on success, negative error code on failure
 */
int quic_crypto_set_keys(struct quic_crypto_ctx *ctx,
			 const u8 *key, const u8 *iv, const u8 *hp_key);

/**
 * quic_crypto_get_keys - Export current traffic keys
 * @ctx: Crypto context
 * @key: Output key buffer (may be NULL)
 * @iv: Output IV buffer (may be NULL)
 * @hp_key: Output HP key buffer (may be NULL)
 *
 * Return: 0 on success, negative error code on failure
 */
int quic_crypto_get_keys(const struct quic_crypto_ctx *ctx,
			 u8 *key, u8 *iv, u8 *hp_key);

/**
 * quic_crypto_is_cipher_supported - Check if cipher suite is supported
 * @cipher_suite: TLS cipher suite identifier
 *
 * Return: true if supported, false otherwise
 */
bool quic_crypto_is_cipher_supported(u16 cipher_suite);

/**
 * quic_crypto_get_supported_ciphers - Get list of supported cipher suites
 * @ciphers: Output array for cipher suite IDs
 * @count: In: array size, Out: number of cipher suites
 *
 * Return: 0 on success, -ENOSPC if array too small
 */
int quic_crypto_get_supported_ciphers(u16 *ciphers, size_t *count);

#endif /* _NET_QUIC_CRYPTO_H */
