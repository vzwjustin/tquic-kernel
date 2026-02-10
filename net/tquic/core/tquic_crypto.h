/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * TQUIC Cryptographic Operations Header
 *
 * Declarations for TQUIC packet protection as specified in RFC 9001.
 *
 * Copyright (c) 2024 Linux QUIC Implementation Authors
 * Copyright (c) 2026 Linux Foundation
 */

#ifndef _NET_TQUIC_CRYPTO_H
#define _NET_TQUIC_CRYPTO_H

#include <linux/types.h>
#include <linux/socket.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/ktime.h>
#include <crypto/hash.h>
#include <crypto/aead.h>
#include <crypto/skcipher.h>

/*
 * TLS 1.3 Cipher Suite Identifiers
 */
#define TQUIC_CIPHER_AES_128_GCM_SHA256		0x1301
#define TQUIC_CIPHER_AES_256_GCM_SHA384		0x1302
#define TQUIC_CIPHER_CHACHA20_POLY1305_SHA256	0x1303

/*
 * Cryptographic Size Constants
 */
#define TQUIC_TAG_SIZE		16
#define TQUIC_IV_SIZE		12
#define TQUIC_SAMPLE_SIZE	16
#define TQUIC_HP_MASK_SIZE	5

/*
 * Maximum key sizes
 */
#define TQUIC_MAX_KEY_SIZE	32
#define TQUIC_MAX_IV_SIZE	12
#define TQUIC_MAX_HASH_SIZE	48

/*
 * Encryption levels (may be defined in include/net/tquic.h)
 */
#ifndef TQUIC_CRYPTO_INITIAL
#define TQUIC_CRYPTO_INITIAL		0
#define TQUIC_CRYPTO_HANDSHAKE		1
#define TQUIC_CRYPTO_APPLICATION	2
#define TQUIC_CRYPTO_EARLY_DATA		3
#define TQUIC_CRYPTO_MAX		4
#endif

/*
 * TQUIC error codes
 */
#define TQUIC_ERROR_CRYPTO_BASE		0x100

/*
 * TLS state machine states
 */
enum tquic_tls_state {
	TQUIC_TLS_STATE_INITIAL = 0,	/* Initial secrets only, no TLS msgs */
	TQUIC_TLS_STATE_START,		/* Ready to begin handshake */
	TQUIC_TLS_STATE_WAIT_SH,	/* Client: waiting for ServerHello */
	TQUIC_TLS_STATE_WAIT_EE,	/* Client: waiting for EncryptedExtensions */
	TQUIC_TLS_STATE_WAIT_CERT_CR,	/* Client: waiting for Cert or CertReq */
	TQUIC_TLS_STATE_WAIT_CERT,	/* Client: waiting for Certificate */
	TQUIC_TLS_STATE_WAIT_CV,	/* Client: waiting for CertificateVerify */
	TQUIC_TLS_STATE_WAIT_FINISHED,	/* Waiting for peer Finished */
	TQUIC_TLS_STATE_CONNECTED,	/* 1-RTT established */
	TQUIC_TLS_STATE_ERROR,		/* TLS alert received */
};

/*
 * TLS handshake context for state machine validation
 */
struct tquic_tls_ctx {
	enum tquic_tls_state	state;
	u8			is_server:1;
	u8			cert_request_sent:1;
	u8			using_psk:1;
	u8			early_data_accepted:1;
	u8			handshake_complete:1;
	u8			alert_received:1;
	u8			alert_sent:1;
	u8			alert_code;
	u64			crypto_offset[TQUIC_CRYPTO_MAX];
};

/* TQUIC crypto secret */
struct tquic_crypto_secret {
	u8	secret[64];
	u8	key[32];
	u8	iv[12];
	u8	hp_key[32];
	u32	secret_len;
	u32	key_len;
	u32	iv_len;
	u32	hp_key_len;
};

/* TQUIC crypto context */
struct tquic_crypto_ctx {
	struct crypto_aead	*tx_aead;
	struct crypto_aead	*rx_aead;
	struct crypto_sync_skcipher	*tx_hp;
	struct crypto_sync_skcipher	*rx_hp;
	struct crypto_shash	*hash;
	struct tquic_crypto_secret tx;
	struct tquic_crypto_secret rx;
	u16			cipher_type;
	u8			local_cid_len;	/* CF-378: local CID length for short header parsing */
	u8			key_phase:1;
	u8			keys_available:1;

	/*
	 * Key Update Support (RFC 9001 Section 6)
	 */
	struct crypto_aead	*rx_aead_prev;
	struct tquic_crypto_secret rx_prev;
	u8			rx_prev_valid:1;
	u8			rx_key_phase:1;
	u8			key_update_pending:1;
	u64			key_update_pn;
	ktime_t			last_key_update;
};

/* TQUIC packet control block for skb->cb */
struct tquic_skb_cb {
	u64	pn;
	u32	header_len;
	u8	pn_len;
	u8	key_phase;
	u8	dcid_len;
	u8	scid_len;
	u8	packet_type;
	u8	crypto_level;
};

#define TQUIC_SKB_CB(skb) ((struct tquic_skb_cb *)((skb)->cb))

/* Forward declarations */
struct tquic_connection;
struct tquic_cid;

/*
 * Crypto wrapper structure
 *
 * This structure wraps the TLS state machine context and crypto contexts
 * for all encryption levels. It is stored in tquic_connection->crypto_state
 * as an opaque pointer.
 */
struct tquic_crypto_wrapper {
	struct tquic_tls_ctx tls;
	struct tquic_crypto_ctx crypto[TQUIC_CRYPTO_MAX];
};

/**
 * tquic_crypto_wrapper_alloc - Allocate crypto wrapper for connection
 * @gfp: GFP flags for allocation
 *
 * Allocates and initializes a crypto wrapper structure.
 * The caller must store the returned pointer in conn->crypto_state.
 *
 * Return: Pointer to wrapper on success, NULL on failure
 */
static inline struct tquic_crypto_wrapper *tquic_crypto_wrapper_alloc(gfp_t gfp)
{
	return kzalloc(sizeof(struct tquic_crypto_wrapper), gfp);
}

/**
 * tquic_crypto_wrapper_free - Free crypto wrapper
 * @wrapper: Wrapper to free
 *
 * Frees the crypto wrapper and all associated resources.
 */
static inline void tquic_crypto_wrapper_free(struct tquic_crypto_wrapper *wrapper)
{
	if (!wrapper)
		return;

	/* Zeroize key material before freeing to prevent lingering secrets */
	memzero_explicit(wrapper, sizeof(*wrapper));
	kfree(wrapper);
}

/*
 * Crypto context management
 */

/**
 * tquic_crypto_ctx_init - Initialize a TQUIC crypto context
 * @ctx: Context to initialize
 * @cipher_type: TLS cipher suite identifier (e.g., TQUIC_CIPHER_AES_128_GCM_SHA256)
 *
 * Initializes a TQUIC crypto context for the specified cipher suite.
 * The context includes AEAD, header protection, and HMAC cipher handles.
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_crypto_ctx_init(struct tquic_crypto_ctx *ctx, u16 cipher_type);

/**
 * tquic_crypto_ctx_destroy - Free resources in a TQUIC crypto context
 * @ctx: Context to destroy
 *
 * Releases all resources associated with the crypto context, including
 * zeroizing sensitive key material. The context structure itself is
 * not freed (it's typically embedded in the connection structure).
 */
void tquic_crypto_ctx_destroy(struct tquic_crypto_ctx *ctx);

/*
 * Key Derivation Functions (RFC 9001)
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
					const struct tquic_cid *cid);

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
 * of a TQUIC packet.
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
 * field of a TQUIC packet.
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_crypto_unprotect_header(struct tquic_crypto_ctx *ctx, struct sk_buff *skb,
				 u8 *pn_offset, u8 *pn_len);

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

/*
 * Key Update (RFC 9001 Section 6)
 */

/**
 * tquic_crypto_update_keys - Perform key update
 * @conn: TQUIC connection
 *
 * Derives new traffic keys from the current secret and toggles
 * the key phase bit.
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_crypto_update_keys(struct tquic_connection *conn);

/*
 * TLS 1.3 Extension Types (RFC 8446, RFC 7301, RFC 6066)
 */
#define TLS_EXT_SERVER_NAME		0	/* RFC 6066 - SNI */
#define TLS_EXT_ALPN			16	/* RFC 7301 - Application-Layer Protocol Negotiation */
#define TLS_EXT_SUPPORTED_VERSIONS	43	/* RFC 8446 - Supported Versions */
#define TLS_EXT_KEY_SHARE		51	/* RFC 8446 - Key Share */
#define TLS_EXT_TQUIC_TRANSPORT_PARAMS	0x39	/* RFC 9001 - QUIC Transport Parameters */

/*
 * TLS State Machine Functions
 */

/**
 * tquic_tls_init - Initialize TLS state machine for connection
 * @conn: TQUIC connection
 * @is_server: True if server, false if client
 */
void tquic_tls_init(struct tquic_connection *conn, bool is_server);

/**
 * tquic_tls_start_handshake - Begin TLS handshake
 * @conn: TQUIC connection
 */
void tquic_tls_start_handshake(struct tquic_connection *conn);

/**
 * tquic_tls_process_handshake_message - Validate and process TLS message
 * @conn: TQUIC connection
 * @data: TLS handshake message data
 * @len: Length of message data
 * @level: TQUIC encryption level
 *
 * Returns 0 on success, negative error code on protocol violation.
 */
int tquic_tls_process_handshake_message(struct tquic_connection *conn,
				       const u8 *data, u32 len, u8 level);

/**
 * tquic_tls_is_handshake_complete - Check if handshake is complete
 * @conn: TQUIC connection
 */
bool tquic_tls_is_handshake_complete(struct tquic_connection *conn);

/**
 * tquic_tls_get_state - Get current TLS state
 * @conn: TQUIC connection
 */
int tquic_tls_get_state(struct tquic_connection *conn);

/**
 * tquic_tls_set_psk_mode - Enable PSK-only mode
 * @conn: TQUIC connection
 * @using_psk: True if using PSK without certificates
 */
void tquic_tls_set_psk_mode(struct tquic_connection *conn, bool using_psk);

/**
 * tquic_tls_process_alert - Process a TLS alert
 * @conn: TQUIC connection
 * @alert_level: Alert level (1=warning, 2=fatal)
 * @alert_desc: Alert description code
 *
 * Returns the corresponding TQUIC transport error code.
 */
u64 tquic_tls_process_alert(struct tquic_connection *conn,
			   u8 alert_level, u8 alert_desc);

/**
 * tquic_tls_in_error_state - Check if TLS is in error state
 * @conn: TQUIC connection
 */
bool tquic_tls_in_error_state(struct tquic_connection *conn);

/**
 * tquic_tls_get_alert_code - Get the alert code if in error state
 * @conn: TQUIC connection
 */
u8 tquic_tls_get_alert_code(struct tquic_connection *conn);

/*
 * TLS Extension Building and Parsing
 */

/**
 * tquic_tls_build_sni_extension - Build SNI extension for ClientHello
 * @hostname: Server hostname (null-terminated)
 * @buf: Output buffer
 * @buf_len: Buffer size
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
 * Return: 0 on success, -ENOENT if no common protocol, negative error on failure
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
 * Return: 0 if valid, -EPROTO if not in offered list
 */
int tquic_tls_validate_alpn(const u8 *offered_alpn, size_t offered_len,
			   const u8 *selected, size_t selected_len);

#endif /* _NET_TQUIC_CRYPTO_H */
