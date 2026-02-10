/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * TQUIC Cryptographic Operations Header
 *
 * Declarations for QUIC packet protection as specified in RFC 9001.
 *
 * Copyright (c) 2024-2026 Linux TQUIC Implementation Authors
 */

#ifndef _NET_TQUIC_QUIC_CRYPTO_H
#define _NET_TQUIC_QUIC_CRYPTO_H

#include <linux/types.h>
#include <linux/socket.h>
#include <crypto/hash.h>
#include <net/tquic.h>

/*
 * TLS 1.3 Cipher Suite Identifiers
 */
#define TQUIC_CIPHER_AES_128_GCM_SHA256		0x1301
#define TQUIC_CIPHER_AES_256_GCM_SHA384		0x1302
#define TQUIC_CIPHER_CHACHA20_POLY1305_SHA256	0x1303

/* Legacy aliases */
#define QUIC_CIPHER_AES_128_GCM_SHA256		TQUIC_CIPHER_AES_128_GCM_SHA256
#define QUIC_CIPHER_AES_256_GCM_SHA384		TQUIC_CIPHER_AES_256_GCM_SHA384
#define QUIC_CIPHER_CHACHA20_POLY1305_SHA256	TQUIC_CIPHER_CHACHA20_POLY1305_SHA256

/*
 * Cryptographic Size Constants
 */
#define TQUIC_TAG_SIZE		16
#define TQUIC_IV_SIZE		12
#define TQUIC_SAMPLE_SIZE	16
#define TQUIC_HP_MASK_SIZE	5

/* Legacy aliases */
#define QUIC_TAG_SIZE		TQUIC_TAG_SIZE
#define QUIC_IV_SIZE		TQUIC_IV_SIZE
#define QUIC_SAMPLE_SIZE	TQUIC_SAMPLE_SIZE
#define QUIC_HP_MASK_SIZE	TQUIC_HP_MASK_SIZE

/*
 * Maximum key sizes
 */
#define TQUIC_MAX_KEY_SIZE	32
#define TQUIC_MAX_IV_SIZE	12
#define TQUIC_MAX_HASH_SIZE	48

/* Legacy aliases */
#define QUIC_MAX_KEY_SIZE	TQUIC_MAX_KEY_SIZE
#define QUIC_MAX_IV_SIZE	TQUIC_MAX_IV_SIZE
#define QUIC_MAX_HASH_SIZE	TQUIC_MAX_HASH_SIZE

/*
 * Crypto context management
 */

/**
 * tquic_crypto_init - Initialize a TQUIC crypto context
 * @ctx: Context to initialize
 * @cipher_type: TLS cipher suite identifier (e.g., TQUIC_CIPHER_AES_128_GCM_SHA256)
 *
 * Initializes a TQUIC crypto context for the specified cipher suite.
 * The context includes AEAD, header protection, and HMAC cipher handles.
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_crypto_init(struct tquic_crypto_ctx *ctx, u16 cipher_type);

/**
 * tquic_crypto_destroy - Free resources in a TQUIC crypto context
 * @ctx: Context to destroy
 *
 * Releases all resources associated with the crypto context, including
 * zeroizing sensitive key material. The context structure itself is
 * not freed (it's typically embedded in the connection structure).
 */
void tquic_crypto_destroy(void *crypto);

/* Legacy aliases */
#define quic_crypto_init	tquic_crypto_init
#define quic_crypto_destroy	tquic_crypto_destroy

/*
 * Key Derivation Functions (RFC 9001)
 *
 * Note: HKDF functions are internal to crypto.c and not exposed in the API.
 * Use the higher-level quic_crypto_derive_*_secrets() functions instead.
 */

/**
 * tquic_crypto_derive_initial_secrets - Derive initial packet protection keys
 * @conn: TQUIC connection
 * @cid: Destination Connection ID
 *
 * Derives the initial secrets from the destination connection ID as
 * specified in RFC 9001 Section 5.2. Uses version-specific salt and
 * initializes the Initial encryption level crypto context.
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_crypto_derive_initial_secrets(struct tquic_connection *conn,
					struct tquic_cid *cid);

/**
 * tquic_crypto_derive_secrets - Derive traffic secrets and keys
 * @ctx: Crypto context
 * @secret: Traffic secret from TLS
 * @secret_len: Length of secret
 *
 * Derives traffic keys (key, IV, HP key) from the given secret using
 * HKDF-Expand-Label. Used for handshake and application data protection.
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_crypto_derive_secrets(struct tquic_crypto_ctx *ctx,
				const u8 *secret, u32 secret_len);

/* Legacy aliases */
#define quic_crypto_derive_initial_secrets	tquic_crypto_derive_initial_secrets
#define quic_crypto_derive_secrets		tquic_crypto_derive_secrets

/*
 * Header Protection (RFC 9001 Section 5.4)
 */

/**
 * tquic_crypto_hp_mask - Generate header protection mask
 * @ctx: Crypto context
 * @sample: 16-byte sample from encrypted packet
 * @mask: Output 5-byte mask
 *
 * Generates the header protection mask using AES-ECB encryption
 * of the sample.
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_crypto_hp_mask(struct tquic_crypto_ctx *ctx, const u8 *sample,
			 u8 *mask);

/**
 * tquic_crypto_protect_header - Apply header protection
 * @ctx: Crypto context
 * @skb: Socket buffer containing packet (modified in place)
 * @pn_offset: Offset of packet number field
 * @pn_len: Length of packet number field (1-4 bytes)
 *
 * Applies header protection to the first byte and packet number field
 * of a QUIC packet.
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_crypto_protect_header(struct tquic_crypto_ctx *ctx, struct sk_buff *skb,
				u8 pn_offset, u8 pn_len);

/**
 * tquic_crypto_unprotect_header - Remove header protection
 * @ctx: Crypto context
 * @skb: Socket buffer containing packet (modified in place)
 * @pn_offset: Output - offset of packet number field
 * @pn_len: Output - detected packet number length
 *
 * Removes header protection from the first byte and packet number
 * field of a QUIC packet.
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_crypto_unprotect_header(struct tquic_crypto_ctx *ctx, struct sk_buff *skb,
				  u8 *pn_offset, u8 *pn_len);

/* Legacy aliases */
#define quic_crypto_hp_mask		tquic_crypto_hp_mask
#define quic_crypto_protect_header	tquic_crypto_protect_header
#define quic_crypto_unprotect_header	tquic_crypto_unprotect_header

/*
 * Packet Protection (AEAD - RFC 9001 Section 5.3)
 */

/**
 * tquic_crypto_encrypt - Encrypt TQUIC packet payload
 * @ctx: Crypto context
 * @skb: Socket buffer containing packet
 * @pn: Packet number for nonce construction
 *
 * Encrypts the packet payload using AEAD. The header portion (up to
 * header_len as stored in TQUIC_SKB_CB) is used as AAD, and the
 * payload is encrypted in-place. Adds authentication tag to end.
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_crypto_encrypt(struct tquic_crypto_ctx *ctx, struct sk_buff *skb,
			 u64 pn);

/**
 * tquic_crypto_decrypt - Decrypt TQUIC packet payload
 * @ctx: Crypto context
 * @skb: Socket buffer containing packet
 * @pn: Packet number for nonce construction
 *
 * Decrypts and authenticates the packet payload. The header portion
 * is used as AAD. Decryption is done in-place and the authentication
 * tag is removed on success.
 *
 * Return: 0 on success, -EBADMSG on authentication failure,
 *         other negative error code on failure
 */
int tquic_crypto_decrypt(struct tquic_crypto_ctx *ctx, struct sk_buff *skb,
			 u64 pn);

/* Legacy aliases */
#define quic_crypto_encrypt	tquic_crypto_encrypt
#define quic_crypto_decrypt	tquic_crypto_decrypt

/*
 * Key Update (RFC 9001 Section 6)
 */

/**
 * tquic_crypto_update_keys - Perform key update (deprecated, use initiate instead)
 * @conn: TQUIC connection
 *
 * Derives new traffic keys from the current secret and toggles
 * the key phase bit. This is an internal function; prefer using
 * tquic_crypto_initiate_key_update() for initiating updates.
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_crypto_update_keys(struct tquic_connection *conn);

/**
 * tquic_crypto_initiate_key_update - Initiate a key update
 * @conn: TQUIC connection
 *
 * Initiates a key update on the connection. Updates TX keys, toggles
 * the key phase bit, and marks the update as pending until acknowledged
 * by the peer per RFC 9001 Section 6.2.
 *
 * Return: 0 on success, -EAGAIN if update already pending, negative error otherwise
 */
int tquic_crypto_initiate_key_update(struct tquic_connection *conn);

/**
 * tquic_crypto_on_key_phase_change - Handle key phase change in received packet
 * @conn: TQUIC connection
 * @rx_key_phase: Key phase bit from received packet
 *
 * Handles receipt of a packet with a different key phase, either confirming
 * a locally-initiated update or responding to a peer-initiated update.
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_crypto_on_key_phase_change(struct tquic_connection *conn, u8 rx_key_phase);

/**
 * tquic_crypto_decrypt_with_phase - Decrypt considering key phase
 * @ctx: Crypto context
 * @skb: Socket buffer containing packet
 * @pn: Packet number
 * @key_phase: Key phase bit from packet header
 *
 * Attempts decryption with current or previous keys based on key phase.
 * Returns -EKEYREJECTED if a key update is needed.
 *
 * Return: 0 on success, -EKEYREJECTED if key update needed, negative error otherwise
 */
int tquic_crypto_decrypt_with_phase(struct tquic_crypto_ctx *ctx,
				    struct sk_buff *skb, u64 pn, u8 key_phase);

/**
 * tquic_crypto_discard_old_keys - Discard previous generation keys
 * @conn: TQUIC connection
 *
 * Called by timer to discard old keys after a key update.
 */
void tquic_crypto_discard_old_keys(struct tquic_connection *conn);

/**
 * tquic_crypto_get_key_phase - Get current TX key phase
 * @ctx: Crypto context
 *
 * Return: Current key phase bit (0 or 1)
 */
u8 tquic_crypto_get_key_phase(struct tquic_crypto_ctx *ctx);

/* Legacy aliases */
#define quic_crypto_update_keys		tquic_crypto_update_keys
#define quic_crypto_initiate_key_update	tquic_crypto_initiate_key_update
#define quic_crypto_on_key_phase_change	tquic_crypto_on_key_phase_change
#define quic_crypto_decrypt_with_phase	tquic_crypto_decrypt_with_phase
#define quic_crypto_discard_old_keys	tquic_crypto_discard_old_keys
#define quic_crypto_get_key_phase	tquic_crypto_get_key_phase

/*
 * Retry Token Handling (RFC 9001 Section 5.8)
 *
 * Retry packets are optional in QUIC and used for address validation.
 * See tquic_retry.c for the Retry packet implementation. The crypto
 * operations here focus on standard handshake and application data
 * encryption which is complete and functional.
 */

/*
 * TLS 1.3 Extension Types (RFC 8446, RFC 7301, RFC 6066)
 */
#define TQUIC_TLS_EXT_SERVER_NAME		0	/* RFC 6066 - SNI */
#define TQUIC_TLS_EXT_ALPN			16	/* RFC 7301 - ALPN */
#define TQUIC_TLS_EXT_SUPPORTED_VERSIONS	43	/* RFC 8446 */
#define TQUIC_TLS_EXT_KEY_SHARE			51	/* RFC 8446 */
#define TQUIC_TLS_EXT_QUIC_TRANSPORT_PARAMS	0x39	/* RFC 9001 */

/* Legacy aliases */
#define TLS_EXT_SERVER_NAME		TQUIC_TLS_EXT_SERVER_NAME
#define TLS_EXT_ALPN			TQUIC_TLS_EXT_ALPN
#define TLS_EXT_SUPPORTED_VERSIONS	TQUIC_TLS_EXT_SUPPORTED_VERSIONS
#define TLS_EXT_KEY_SHARE		TQUIC_TLS_EXT_KEY_SHARE
#define TLS_EXT_QUIC_TRANSPORT_PARAMS	TQUIC_TLS_EXT_QUIC_TRANSPORT_PARAMS

/*
 * TLS Extension Building
 */

/**
 * tquic_tls_build_sni_extension - Build SNI extension for ClientHello
 * @hostname: Server hostname (null-terminated)
 * @buf: Output buffer
 * @buf_len: Buffer size
 *
 * Builds the server_name extension (RFC 6066) for TLS ClientHello.
 *
 * Return: Number of bytes written on success, negative error code on failure
 */
int tquic_tls_build_sni_extension(const char *hostname, u8 *buf, size_t buf_len);

/**
 * tquic_tls_build_alpn_extension - Build ALPN extension
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
int tquic_tls_build_alpn_extension(const u8 *alpn_list, size_t alpn_len,
				   u8 *buf, size_t buf_len);

/**
 * tquic_tls_parse_sni_extension - Parse SNI extension from ClientHello
 * @data: Extension data (after type and length)
 * @data_len: Length of extension data
 * @hostname: Output buffer for hostname
 * @hostname_len: In: buffer size, Out: actual hostname length
 *
 * Parses the server_name extension from a ClientHello.
 *
 * Return: 0 on success, -EINVAL on parse error, -ENOSPC if buffer too small
 */
int tquic_tls_parse_sni_extension(const u8 *data, size_t data_len,
				  char *hostname, size_t *hostname_len);

/**
 * tquic_tls_parse_alpn_extension - Parse ALPN extension
 * @data: Extension data (after type and length)
 * @data_len: Length of extension data
 * @alpn_list: Output buffer for ALPN list
 * @alpn_len: In: buffer size, Out: actual list length
 *
 * Parses the ALPN extension. Output format is the same as input to
 * tquic_tls_build_alpn_extension (length-prefixed protocol list).
 *
 * Return: 0 on success, -EINVAL on parse error, -ENOSPC if buffer too small
 */
int tquic_tls_parse_alpn_extension(const u8 *data, size_t data_len,
				   u8 *alpn_list, size_t *alpn_len);

/**
 * tquic_tls_select_alpn - Server ALPN selection
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
int tquic_tls_select_alpn(const u8 *client_alpn, size_t client_alpn_len,
			  const u8 *server_alpn, size_t server_alpn_len,
			  u8 *selected, size_t *selected_len);

/**
 * tquic_tls_validate_alpn - Validate server's ALPN selection
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
int tquic_tls_validate_alpn(const u8 *offered_alpn, size_t offered_len,
			    const u8 *selected, size_t selected_len);

/* Legacy aliases for TLS functions */
#define quic_tls_build_sni_extension	tquic_tls_build_sni_extension
#define quic_tls_build_alpn_extension	tquic_tls_build_alpn_extension
#define quic_tls_parse_sni_extension	tquic_tls_parse_sni_extension
#define quic_tls_parse_alpn_extension	tquic_tls_parse_alpn_extension
#define quic_tls_select_alpn		tquic_tls_select_alpn
#define quic_tls_validate_alpn		tquic_tls_validate_alpn

/*
 * Crypto Context Access
 *
 * The crypto context structure exposes key lengths, cipher type, and
 * cipher suite information directly via its fields. For internal TQUIC
 * module use, access the tquic_crypto_ctx fields directly rather than
 * through accessor functions. This provides efficient access without
 * function call overhead for hot paths.
 */

#endif /* _NET_TQUIC_QUIC_CRYPTO_H */
