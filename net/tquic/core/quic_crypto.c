// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * TQUIC - True QUIC with WAN Bonding
 *
 * Cryptographic operations for TLS 1.3 integration
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 */

#include <linux/slab.h>
#include <crypto/aead.h>
#include <crypto/hash.h>
#include <crypto/skcipher.h>
#include <crypto/gcm.h>
#include <net/tquic.h>
#include "tquic_crypto.h"

/* TQUIC v1 initial salt (RFC 9001 Section 5.2) */
static const u8 tquic_v1_initial_salt[20] = {
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
	0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
	0xcc, 0xbb, 0x7f, 0x0a
};

/* TQUIC v2 initial salt (RFC 9369) */
static const u8 tquic_v2_initial_salt[20] = {
	0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb,
	0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
	0xf9, 0xbd, 0x2e, 0xd9
};

/*
 * TLS 1.3 Handshake Message Types (RFC 8446 Section 4)
 * Used for TLS state machine validation per RFC 9001.
 */
#define TLS_HS_CLIENT_HELLO		1
#define TLS_HS_SERVER_HELLO		2
#define TLS_HS_NEW_SESSION_TICKET	4
#define TLS_HS_END_OF_EARLY_DATA	5
#define TLS_HS_ENCRYPTED_EXTENSIONS	8
#define TLS_HS_CERTIFICATE		11
#define TLS_HS_CERTIFICATE_REQUEST	13
#define TLS_HS_CERTIFICATE_VERIFY	15
#define TLS_HS_FINISHED			20
#define TLS_HS_KEY_UPDATE		24
#define TLS_HS_MESSAGE_HASH		254

/*
 * TLS 1.3 Alert Types (RFC 8446 Section 6.2)
 */
#define TLS_ALERT_CLOSE_NOTIFY			0
#define TLS_ALERT_UNEXPECTED_MESSAGE		10
#define TLS_ALERT_BAD_RECORD_MAC		20
#define TLS_ALERT_RECORD_OVERFLOW		22
#define TLS_ALERT_HANDSHAKE_FAILURE		40
#define TLS_ALERT_BAD_CERTIFICATE		42
#define TLS_ALERT_UNSUPPORTED_CERTIFICATE	43
#define TLS_ALERT_CERTIFICATE_REVOKED		44
#define TLS_ALERT_CERTIFICATE_EXPIRED		45
#define TLS_ALERT_CERTIFICATE_UNKNOWN		46
#define TLS_ALERT_ILLEGAL_PARAMETER		47
#define TLS_ALERT_UNKNOWN_CA			48
#define TLS_ALERT_ACCESS_DENIED			49
#define TLS_ALERT_DECODE_ERROR			50
#define TLS_ALERT_DECRYPT_ERROR			51
#define TLS_ALERT_PROTOCOL_VERSION		70
#define TLS_ALERT_INSUFFICIENT_SECURITY		71
#define TLS_ALERT_INTERNAL_ERROR		80
#define TLS_ALERT_INAPPROPRIATE_FALLBACK	86
#define TLS_ALERT_USER_CANCELED			90
#define TLS_ALERT_MISSING_EXTENSION		109
#define TLS_ALERT_UNSUPPORTED_EXTENSION		110
#define TLS_ALERT_UNRECOGNIZED_NAME		112
#define TLS_ALERT_BAD_CERTIFICATE_STATUS	113
#define TLS_ALERT_UNKNOWN_PSK_IDENTITY		115
#define TLS_ALERT_CERTIFICATE_REQUIRED		116
#define TLS_ALERT_NO_APPLICATION_PROTOCOL	120

/*
 * TQUIC-TLS State Machine (RFC 9001 Section 4)
 *
 * Client states:
 *   START -> [send ClientHello] -> WAIT_SH
 *   WAIT_SH -> [recv ServerHello] -> WAIT_EE
 *   WAIT_EE -> [recv EncryptedExtensions] -> WAIT_CERT_CR
 *   WAIT_CERT_CR -> [recv CertificateRequest] -> WAIT_CERT
 *              or -> [recv Certificate] -> WAIT_CV
 *   WAIT_CERT -> [recv Certificate] -> WAIT_CV
 *   WAIT_CV -> [recv CertificateVerify] -> WAIT_FINISHED
 *   WAIT_FINISHED -> [recv Finished, send Finished] -> CONNECTED
 *
 * Server states:
 *   START -> [recv ClientHello] -> RECVD_CH
 *   RECVD_CH -> [send ServerHello, EncryptedExtensions, ...] -> WAIT_FINISHED
 *   WAIT_FINISHED -> [recv Finished] -> CONNECTED
 *
 * For PSK-only (0-RTT):
 *   WAIT_EE -> [recv EncryptedExtensions] -> WAIT_FINISHED (no cert)
 */
/* TLS state names for debugging */
static const char * const tquic_tls_state_names[] = {
	[TQUIC_TLS_STATE_INITIAL]	= "INITIAL",
	[TQUIC_TLS_STATE_START]		= "START",
	[TQUIC_TLS_STATE_WAIT_SH]	= "WAIT_SH",
	[TQUIC_TLS_STATE_WAIT_EE]	= "WAIT_EE",
	[TQUIC_TLS_STATE_WAIT_CERT_CR]	= "WAIT_CERT_CR",
	[TQUIC_TLS_STATE_WAIT_CERT]	= "WAIT_CERT",
	[TQUIC_TLS_STATE_WAIT_CV]	= "WAIT_CV",
	[TQUIC_TLS_STATE_WAIT_FINISHED]	= "WAIT_FINISHED",
	[TQUIC_TLS_STATE_CONNECTED]	= "CONNECTED",
	[TQUIC_TLS_STATE_ERROR]		= "ERROR",
};

/*
 * tquic_crypto_wrapper_get - Get crypto wrapper for connection
 * @conn: TQUIC connection
 *
 * Returns the crypto wrapper containing TLS and crypto contexts.
 * The wrapper is stored in conn->crypto_state.
 */
static struct tquic_crypto_wrapper *tquic_crypto_wrapper_get(struct tquic_connection *conn)
{
	return (struct tquic_crypto_wrapper *)conn->crypto_state;
}

/*
 * tquic_hp_encrypt_block - Single-block ECB encryption for header protection
 * @tfm: Sync skcipher transform
 * @dst: Output buffer (at least 16 bytes)
 * @src: Input buffer (16 bytes)
 *
 * Performs a single AES-ECB block encryption for QUIC header protection.
 * Returns 0 on success, negative error code on failure.
 */
static int tquic_hp_encrypt_block(struct crypto_sync_skcipher *tfm,
				  u8 *dst, const u8 *src)
{
	SYNC_SKCIPHER_REQUEST_ON_STACK(req, tfm);
	struct scatterlist sg_src, sg_dst;
	u8 src_buf[16], dst_buf[16];
	int err;

	memcpy(src_buf, src, 16);
	sg_init_one(&sg_src, src_buf, 16);
	sg_init_one(&sg_dst, dst_buf, 16);

	skcipher_request_set_sync_tfm(req, tfm);
	skcipher_request_set_crypt(req, &sg_src, &sg_dst, 16, NULL);

	err = crypto_skcipher_encrypt(req);
	if (!err)
		memcpy(dst, dst_buf, 16);

	skcipher_request_zero(req);
	return err;
}

/*
 * tquic_tls_ctx_get - Get TLS context for connection
 * @conn: TQUIC connection
 *
 * Returns the TLS context for state machine validation.
 * TLS context is stored in the crypto wrapper.
 */
static struct tquic_tls_ctx *tquic_tls_ctx_get(struct tquic_connection *conn)
{
	struct tquic_crypto_wrapper *wrapper = tquic_crypto_wrapper_get(conn);
	if (!wrapper)
		return NULL;
	return &wrapper->tls;
}

/*
 * tquic_tls_state_name - Get human-readable state name
 * @state: TLS state value
 *
 * Returns string name for the TLS state, useful for debugging.
 */
static inline const char *tquic_tls_state_name(enum tquic_tls_state state)
{
	if (state < ARRAY_SIZE(tquic_tls_state_names))
		return tquic_tls_state_names[state];
	return "UNKNOWN";
}

/*
 * tquic_tls_validate_level - Validate encryption level for message type
 * @msg_type: TLS handshake message type
 * @level: TQUIC encryption level
 *
 * Validates that the TLS message is sent at the correct TQUIC encryption
 * level per RFC 9001 Section 4.1.
 *
 * Returns 0 if valid, -EPROTO otherwise.
 */
static int tquic_tls_validate_level(u8 msg_type, u8 level)
{
	/*
	 * RFC 9001 Section 4.1.4:
	 * - ClientHello, ServerHello: Initial level
	 * - EncryptedExtensions through Finished: Handshake level
	 * - NewSessionTicket: Application (1-RTT) level
	 * - EndOfEarlyData: Handshake level (client only)
	 */
	switch (msg_type) {
	case TLS_HS_CLIENT_HELLO:
	case TLS_HS_SERVER_HELLO:
		if (level != TQUIC_CRYPTO_INITIAL)
			return -EPROTO;
		break;

	case TLS_HS_ENCRYPTED_EXTENSIONS:
	case TLS_HS_CERTIFICATE_REQUEST:
	case TLS_HS_CERTIFICATE:
	case TLS_HS_CERTIFICATE_VERIFY:
	case TLS_HS_FINISHED:
	case TLS_HS_END_OF_EARLY_DATA:
		if (level != TQUIC_CRYPTO_HANDSHAKE)
			return -EPROTO;
		break;

	case TLS_HS_NEW_SESSION_TICKET:
		if (level != TQUIC_CRYPTO_APPLICATION)
			return -EPROTO;
		break;

	default:
		/* Unknown message types are rejected */
		return -EPROTO;
	}

	return 0;
}

/*
 * tquic_tls_validate_transition - Validate TLS state machine transition
 * @ctx: TLS context
 * @msg_type: TLS handshake message type received
 * @level: TQUIC encryption level
 *
 * Validates that the received TLS handshake message is allowed in the
 * current state per RFC 9001 Section 4. Invalid transitions indicate
 * either a protocol violation or an attack attempt.
 *
 * Returns 0 if transition is valid, negative error code otherwise.
 */
static int tquic_tls_validate_transition(struct tquic_tls_ctx *ctx,
					u8 msg_type, u8 level)
{
	enum tquic_tls_state old_state = ctx->state;
	enum tquic_tls_state new_state = TQUIC_TLS_STATE_ERROR;
	int err = 0;

	/*
	 * RFC 9001 Section 4.1.3: Once 1-RTT keys are available,
	 * endpoints MUST NOT send or accept handshake messages
	 * (except NewSessionTicket which uses 1-RTT).
	 */
	if (ctx->state == TQUIC_TLS_STATE_CONNECTED) {
		if (msg_type == TLS_HS_NEW_SESSION_TICKET) {
			/* NewSessionTicket is allowed after handshake */
			if (level != TQUIC_CRYPTO_APPLICATION) {
				pr_warn("TQUIC-TLS: NewSessionTicket at wrong level %u\n",
					level);
				return -EPROTO;
			}
			return 0;
		}
		pr_warn("TQUIC-TLS: handshake message %u after 1-RTT established\n",
			msg_type);
		return -EPROTO;
	}

	/* Error state is terminal */
	if (ctx->state == TQUIC_TLS_STATE_ERROR) {
		pr_debug("TQUIC-TLS: in error state, rejecting message %u\n",
			 msg_type);
		return -EPROTO;
	}

	/*
	 * Validate message type against current state.
	 * State transitions depend on whether we're client or server.
	 */
	if (ctx->is_server) {
		/* Server-side state machine */
		switch (ctx->state) {
		case TQUIC_TLS_STATE_INITIAL:
		case TQUIC_TLS_STATE_START:
			/* Server expects ClientHello at Initial level */
			if (msg_type == TLS_HS_CLIENT_HELLO) {
				if (level != TQUIC_CRYPTO_INITIAL) {
					pr_warn("TQUIC-TLS: ClientHello at wrong level %u\n",
						level);
					err = -EPROTO;
					break;
				}
				new_state = TQUIC_TLS_STATE_WAIT_FINISHED;
			} else {
				pr_warn("TQUIC-TLS: server expected ClientHello, got %u\n",
					msg_type);
				err = -EPROTO;
			}
			break;

		case TQUIC_TLS_STATE_WAIT_FINISHED:
			/* Server expects Finished at Handshake level */
			if (msg_type == TLS_HS_FINISHED) {
				if (level != TQUIC_CRYPTO_HANDSHAKE) {
					pr_warn("TQUIC-TLS: Finished at wrong level %u\n",
						level);
					err = -EPROTO;
					break;
				}
				new_state = TQUIC_TLS_STATE_CONNECTED;
				ctx->handshake_complete = 1;
			} else if (msg_type == TLS_HS_CERTIFICATE) {
				/* Client certificate if requested */
				if (level != TQUIC_CRYPTO_HANDSHAKE) {
					err = -EPROTO;
					break;
				}
				new_state = TQUIC_TLS_STATE_WAIT_CV;
			} else if (msg_type == TLS_HS_END_OF_EARLY_DATA) {
				/* End of 0-RTT data */
				if (level != TQUIC_CRYPTO_HANDSHAKE) {
					err = -EPROTO;
					break;
				}
				/* Stay in WAIT_FINISHED */
				return 0;
			} else {
				pr_warn("TQUIC-TLS: server expected Finished, got %u\n",
					msg_type);
				err = -EPROTO;
			}
			break;

		case TQUIC_TLS_STATE_WAIT_CV:
			/* Server expects CertificateVerify after client cert */
			if (msg_type == TLS_HS_CERTIFICATE_VERIFY) {
				if (level != TQUIC_CRYPTO_HANDSHAKE) {
					err = -EPROTO;
					break;
				}
				new_state = TQUIC_TLS_STATE_WAIT_FINISHED;
			} else {
				pr_warn("TQUIC-TLS: expected CertificateVerify, got %u\n",
					msg_type);
				err = -EPROTO;
			}
			break;

		default:
			pr_warn("TQUIC-TLS: server in unexpected state %u\n",
				ctx->state);
			err = -EPROTO;
			break;
		}
	} else {
		/* Client-side state machine */
		switch (ctx->state) {
		case TQUIC_TLS_STATE_INITIAL:
		case TQUIC_TLS_STATE_START:
			/* Client shouldn't receive messages in START state */
			pr_warn("TQUIC-TLS: client received message %u in START\n",
				msg_type);
			err = -EPROTO;
			break;

		case TQUIC_TLS_STATE_WAIT_SH:
			/* Client expects ServerHello at Initial level */
			if (msg_type == TLS_HS_SERVER_HELLO) {
				if (level != TQUIC_CRYPTO_INITIAL) {
					pr_warn("TQUIC-TLS: ServerHello at wrong level %u\n",
						level);
					err = -EPROTO;
					break;
				}
				new_state = TQUIC_TLS_STATE_WAIT_EE;
			} else {
				pr_warn("TQUIC-TLS: expected ServerHello, got %u\n",
					msg_type);
				err = -EPROTO;
			}
			break;

		case TQUIC_TLS_STATE_WAIT_EE:
			/* Client expects EncryptedExtensions at Handshake level */
			if (msg_type == TLS_HS_ENCRYPTED_EXTENSIONS) {
				if (level != TQUIC_CRYPTO_HANDSHAKE) {
					pr_warn("TQUIC-TLS: EE at wrong level %u\n",
						level);
					err = -EPROTO;
					break;
				}
				/* Next state depends on PSK mode */
				if (ctx->using_psk)
					new_state = TQUIC_TLS_STATE_WAIT_FINISHED;
				else
					new_state = TQUIC_TLS_STATE_WAIT_CERT_CR;
			} else {
				pr_warn("TQUIC-TLS: expected EncryptedExtensions, got %u\n",
					msg_type);
				err = -EPROTO;
			}
			break;

		case TQUIC_TLS_STATE_WAIT_CERT_CR:
			/* Client expects Certificate or CertificateRequest */
			if (msg_type == TLS_HS_CERTIFICATE_REQUEST) {
				if (level != TQUIC_CRYPTO_HANDSHAKE) {
					err = -EPROTO;
					break;
				}
				ctx->cert_request_sent = 1;
				new_state = TQUIC_TLS_STATE_WAIT_CERT;
			} else if (msg_type == TLS_HS_CERTIFICATE) {
				if (level != TQUIC_CRYPTO_HANDSHAKE) {
					err = -EPROTO;
					break;
				}
				new_state = TQUIC_TLS_STATE_WAIT_CV;
			} else {
				pr_warn("TQUIC-TLS: expected Cert or CertReq, got %u\n",
					msg_type);
				err = -EPROTO;
			}
			break;

		case TQUIC_TLS_STATE_WAIT_CERT:
			/* Client expects Certificate after CertificateRequest */
			if (msg_type == TLS_HS_CERTIFICATE) {
				if (level != TQUIC_CRYPTO_HANDSHAKE) {
					err = -EPROTO;
					break;
				}
				new_state = TQUIC_TLS_STATE_WAIT_CV;
			} else {
				pr_warn("TQUIC-TLS: expected Certificate, got %u\n",
					msg_type);
				err = -EPROTO;
			}
			break;

		case TQUIC_TLS_STATE_WAIT_CV:
			/* Client expects CertificateVerify */
			if (msg_type == TLS_HS_CERTIFICATE_VERIFY) {
				if (level != TQUIC_CRYPTO_HANDSHAKE) {
					err = -EPROTO;
					break;
				}
				new_state = TQUIC_TLS_STATE_WAIT_FINISHED;
			} else {
				pr_warn("TQUIC-TLS: expected CertificateVerify, got %u\n",
					msg_type);
				err = -EPROTO;
			}
			break;

		case TQUIC_TLS_STATE_WAIT_FINISHED:
			/* Client expects Finished */
			if (msg_type == TLS_HS_FINISHED) {
				if (level != TQUIC_CRYPTO_HANDSHAKE) {
					pr_warn("TQUIC-TLS: Finished at wrong level %u\n",
						level);
					err = -EPROTO;
					break;
				}
				new_state = TQUIC_TLS_STATE_CONNECTED;
				ctx->handshake_complete = 1;
			} else {
				pr_warn("TQUIC-TLS: expected Finished, got %u\n",
					msg_type);
				err = -EPROTO;
			}
			break;

		default:
			pr_warn("TQUIC-TLS: client in unexpected state %u\n",
				ctx->state);
			err = -EPROTO;
			break;
		}
	}

	if (err) {
		ctx->state = TQUIC_TLS_STATE_ERROR;
		return err;
	}

	/* Log state transition for debugging */
	if (new_state != ctx->state) {
		pr_debug("TQUIC-TLS: state %s -> %s (msg=%u, level=%u)\n",
			 tquic_tls_state_name(old_state),
			 tquic_tls_state_name(new_state),
			 msg_type, level);
		ctx->state = new_state;
	}

	return 0;
}

/*
 * tquic_tls_handle_alert - Handle TLS alert message
 * @ctx: TLS context
 * @alert_level: Alert level (1=warning, 2=fatal)
 * @alert_desc: Alert description code
 *
 * Processes TLS alert messages per RFC 8446 Section 6.
 * All alerts in TQUIC-TLS are treated as connection errors per RFC 9001.
 *
 * Returns corresponding TQUIC error code.
 */
static u64 tquic_tls_handle_alert(struct tquic_tls_ctx *ctx,
				 u8 alert_level, u8 alert_desc)
{
	ctx->alert_received = 1;
	ctx->alert_code = alert_desc;
	ctx->state = TQUIC_TLS_STATE_ERROR;

	pr_warn("TQUIC-TLS: received alert level=%u desc=%u\n",
		alert_level, alert_desc);

	/*
	 * Map TLS alerts to TQUIC crypto errors.
	 * Per RFC 9001 Section 4.8: TQUIC_ERROR_CRYPTO_BASE (0x100) + alert
	 */
	return TQUIC_ERROR_CRYPTO_BASE + alert_desc;
}

/*
 * tquic_tls_init - Initialize TLS state machine for connection
 * @conn: TQUIC connection
 * @is_server: True if server, false if client
 *
 * Initializes the TLS state machine for a new connection.
 */
void tquic_tls_init(struct tquic_connection *conn, bool is_server)
{
	struct tquic_tls_ctx *ctx = tquic_tls_ctx_get(conn);

	if (!ctx)
		return;

	memset(ctx, 0, sizeof(*ctx));
	ctx->state = TQUIC_TLS_STATE_INITIAL;
	ctx->is_server = is_server ? 1 : 0;
}
EXPORT_SYMBOL_GPL(tquic_tls_init);

/*
 * tquic_tls_start_handshake - Begin TLS handshake
 * @conn: TQUIC connection
 *
 * Transitions from INITIAL to START state, preparing for handshake.
 * For clients, also transitions to WAIT_SH after sending ClientHello.
 */
void tquic_tls_start_handshake(struct tquic_connection *conn)
{
	struct tquic_tls_ctx *ctx = tquic_tls_ctx_get(conn);

	if (!ctx)
		return;

	if (ctx->state != TQUIC_TLS_STATE_INITIAL) {
		pr_warn("TQUIC-TLS: start_handshake called in state %s\n",
			tquic_tls_state_name(ctx->state));
		return;
	}

	ctx->state = TQUIC_TLS_STATE_START;

	/* Client transitions to WAIT_SH after sending ClientHello */
	if (!ctx->is_server) {
		pr_debug("TQUIC-TLS: client starting handshake, waiting for ServerHello\n");
		ctx->state = TQUIC_TLS_STATE_WAIT_SH;
	} else {
		pr_debug("TQUIC-TLS: server starting handshake, waiting for ClientHello\n");
	}
}
EXPORT_SYMBOL_GPL(tquic_tls_start_handshake);

/*
 * tquic_tls_process_handshake_message - Validate and process TLS message
 * @conn: TQUIC connection
 * @data: TLS handshake message data
 * @len: Length of message data
 * @level: TQUIC encryption level
 *
 * Validates the TLS handshake message against the state machine and
 * updates state accordingly. This is the main entry point for TLS
 * message validation per RFC 9001.
 *
 * Returns 0 on success, negative error code on protocol violation.
 */
int tquic_tls_process_handshake_message(struct tquic_connection *conn,
				       const u8 *data, u32 len, u8 level)
{
	struct tquic_tls_ctx *ctx = tquic_tls_ctx_get(conn);
	u8 msg_type;
	u32 msg_len;
	int err;

	if (!ctx)
		return -EINVAL;

	if (len < 4) {
		pr_warn("TQUIC-TLS: message too short (%u bytes)\n", len);
		return -EINVAL;
	}

	/* TLS handshake message format:
	 * msg_type (1 byte) + length (3 bytes) + data
	 */
	msg_type = data[0];
	msg_len = ((u32)data[1] << 16) | ((u32)data[2] << 8) | data[3];

	if (msg_len > len - 4) {
		pr_warn("TQUIC-TLS: message length %u exceeds data %u\n",
			msg_len, len - 4);
		return -EINVAL;
	}

	/* First validate the encryption level for this message type */
	err = tquic_tls_validate_level(msg_type, level);
	if (err) {
		pr_warn("TQUIC-TLS: message type %u at wrong level %u\n",
			msg_type, level);
		ctx->state = TQUIC_TLS_STATE_ERROR;
		return err;
	}

	/* Validate state machine transition */
	err = tquic_tls_validate_transition(ctx, msg_type, level);
	if (err) {
		/* State machine already set to ERROR */
		return err;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_tls_process_handshake_message);

/*
 * tquic_tls_is_handshake_complete - Check if handshake is complete
 * @conn: TQUIC connection
 *
 * Returns true if TLS handshake has completed successfully.
 */
bool tquic_tls_is_handshake_complete(struct tquic_connection *conn)
{
	struct tquic_tls_ctx *ctx = tquic_tls_ctx_get(conn);

	if (!ctx)
		return false;

	return ctx->handshake_complete;
}
EXPORT_SYMBOL_GPL(tquic_tls_is_handshake_complete);

/*
 * tquic_tls_get_state - Get current TLS state
 * @conn: TQUIC connection
 *
 * Returns current TLS handshake state as integer.
 */
int tquic_tls_get_state(struct tquic_connection *conn)
{
	struct tquic_tls_ctx *ctx = tquic_tls_ctx_get(conn);

	if (!ctx)
		return -EINVAL;

	return ctx->state;
}
EXPORT_SYMBOL_GPL(tquic_tls_get_state);

/*
 * tquic_tls_set_psk_mode - Enable PSK-only mode
 * @conn: TQUIC connection
 * @using_psk: True if using PSK without certificates
 *
 * Sets PSK mode which affects state machine (skips cert states).
 */
void tquic_tls_set_psk_mode(struct tquic_connection *conn, bool using_psk)
{
	struct tquic_tls_ctx *ctx = tquic_tls_ctx_get(conn);

	if (!ctx)
		return;

	ctx->using_psk = using_psk ? 1 : 0;
}
EXPORT_SYMBOL_GPL(tquic_tls_set_psk_mode);

/*
 * tquic_tls_process_alert - Process a TLS alert
 * @conn: TQUIC connection
 * @alert_level: Alert level (1=warning, 2=fatal)
 * @alert_desc: Alert description code
 *
 * Handles incoming TLS alerts per RFC 9001 Section 4.8.
 * Returns the corresponding TQUIC transport error code.
 */
u64 tquic_tls_process_alert(struct tquic_connection *conn,
			   u8 alert_level, u8 alert_desc)
{
	struct tquic_tls_ctx *ctx = tquic_tls_ctx_get(conn);

	if (!ctx)
		return TQUIC_ERROR_CRYPTO_BASE + TLS_ALERT_INTERNAL_ERROR;

	return tquic_tls_handle_alert(ctx, alert_level, alert_desc);
}
EXPORT_SYMBOL_GPL(tquic_tls_process_alert);

/*
 * tquic_tls_in_error_state - Check if TLS is in error state
 * @conn: TQUIC connection
 *
 * Returns true if TLS state machine is in error state.
 */
bool tquic_tls_in_error_state(struct tquic_connection *conn)
{
	struct tquic_tls_ctx *ctx = tquic_tls_ctx_get(conn);

	if (!ctx)
		return true;

	return ctx->state == TQUIC_TLS_STATE_ERROR;
}
EXPORT_SYMBOL_GPL(tquic_tls_in_error_state);

/*
 * tquic_tls_get_alert_code - Get the alert code if in error state
 * @conn: TQUIC connection
 *
 * Returns the TLS alert code that caused the error, or 0 if no alert.
 */
u8 tquic_tls_get_alert_code(struct tquic_connection *conn)
{
	struct tquic_tls_ctx *ctx = tquic_tls_ctx_get(conn);

	if (!ctx)
		return TLS_ALERT_INTERNAL_ERROR;

	return ctx->alert_code;
}
EXPORT_SYMBOL_GPL(tquic_tls_get_alert_code);

/* HKDF labels for TQUIC */
static const char tquic_client_in_label[] = "client in";
static const char tquic_server_in_label[] = "server in";
static const char tquic_key_label[] = "quic key";
static const char tquic_iv_label[] = "quic iv";
static const char tquic_hp_label[] = "quic hp";
static const char tquic_ku_label[] = "quic ku";

struct hkdf_ctx {
	struct crypto_shash *hash;
	u32 hash_len;
};

static int hkdf_extract(struct hkdf_ctx *ctx, const u8 *salt, size_t salt_len,
			const u8 *ikm, size_t ikm_len, u8 *prk)
{
	SHASH_DESC_ON_STACK(desc, ctx->hash);
	int err;

	err = crypto_shash_setkey(ctx->hash, salt, salt_len);
	if (err)
		return err;

	desc->tfm = ctx->hash;
	return crypto_shash_digest(desc, ikm, ikm_len, prk);
}

int tquic_hkdf_expand_label(struct hkdf_ctx *ctx, const u8 *prk,
			   const char *label, size_t label_len,
			   const u8 *context, size_t context_len,
			   u8 *out, size_t out_len)
{
	SHASH_DESC_ON_STACK(desc, ctx->hash);
	u8 info[256];
	u8 t[64];
	size_t info_len;
	size_t done = 0;
	u8 iter = 1;
	int err;

	/*
	 * Bounds check: label and context must fit within the info buffer.
	 * info layout: 2 (length) + 1 (label_len byte) + 6 ("tls13 ") +
	 *              label_len + 1 (context_len byte) + context_len
	 * Must not exceed sizeof(info) = 256.
	 * Also enforce TLS 1.3 limits: label < 246 (255 - 6 - "tls13 "),
	 * context <= 255.
	 */
	if (label_len > 245 || context_len > 255) {
		err = -EINVAL;
		goto out_zeroize;
	}

	if (10 + label_len + context_len > sizeof(info)) {
		err = -EOVERFLOW;
		goto out_zeroize;
	}

	/* Build HKDF-Expand-Label info
	 * struct {
	 *   uint16 length = Length;
	 *   opaque label<7..255> = "tls13 " + Label;
	 *   opaque context<0..255> = Context;
	 * } HkdfLabel;
	 */
	info[0] = (out_len >> 8) & 0xff;
	info[1] = out_len & 0xff;
	info[2] = 6 + label_len;  /* "tls13 " + label */
	memcpy(&info[3], "tls13 ", 6);
	memcpy(&info[9], label, label_len);
	info[9 + label_len] = context_len;
	if (context_len > 0)
		memcpy(&info[10 + label_len], context, context_len);
	info_len = 10 + label_len + context_len;

	err = crypto_shash_setkey(ctx->hash, prk, ctx->hash_len);
	if (err)
		return err;

	desc->tfm = ctx->hash;

	/* T(0) = empty string */
	memset(t, 0, sizeof(t));

	while (done < out_len) {
		u8 input[256 + 64 + 1];
		size_t input_len = 0;
		size_t copy_len;

		if (iter > 1) {
			memcpy(input, t, ctx->hash_len);
			input_len = ctx->hash_len;
		}

		memcpy(input + input_len, info, info_len);
		input_len += info_len;
		input[input_len++] = iter;

		err = crypto_shash_digest(desc, input, input_len, t);
		if (err)
			goto out_zeroize;

		copy_len = min(out_len - done, (size_t)ctx->hash_len);
		memcpy(out + done, t, copy_len);
		done += copy_len;
		iter++;
	}

	err = 0;

out_zeroize:
	memzero_explicit(t, sizeof(t));
	return err;
}

int tquic_crypto_ctx_init(struct tquic_crypto_ctx *ctx, u16 cipher_type)
{
	const char *aead_name;
	const char *cipher_name;
	const char *hash_name;
	int key_len;

	switch (cipher_type) {
	case TQUIC_CIPHER_AES_128_GCM_SHA256:
		aead_name = "gcm(aes)";
		cipher_name = "ecb(aes)";
		hash_name = "hmac(sha256)";
		key_len = 16;
		break;
	case TQUIC_CIPHER_AES_256_GCM_SHA384:
		aead_name = "gcm(aes)";
		cipher_name = "ecb(aes)";
		hash_name = "hmac(sha384)";
		key_len = 32;
		break;
	case TQUIC_CIPHER_CHACHA20_POLY1305_SHA256:
		aead_name = "rfc7539(chacha20,poly1305)";
		cipher_name = "chacha20";
		hash_name = "hmac(sha256)";
		key_len = 32;
		break;
	default:
		return -EINVAL;
	}

	ctx->cipher_type = cipher_type;

	/* Allocate TX AEAD */
	ctx->tx_aead = crypto_alloc_aead(aead_name, 0, 0);
	if (IS_ERR(ctx->tx_aead)) {
		int err = PTR_ERR(ctx->tx_aead);
		ctx->tx_aead = NULL;
		return err;
	}

	/* Allocate RX AEAD */
	ctx->rx_aead = crypto_alloc_aead(aead_name, 0, 0);
	if (IS_ERR(ctx->rx_aead)) {
		int err = PTR_ERR(ctx->rx_aead);
		crypto_free_aead(ctx->tx_aead);
		ctx->tx_aead = NULL;
		ctx->rx_aead = NULL;
		return err;
	}

	/* Allocate TX header protection cipher */
	ctx->tx_hp = crypto_alloc_sync_skcipher(cipher_name, 0, 0);
	if (IS_ERR(ctx->tx_hp)) {
		int err = PTR_ERR(ctx->tx_hp);
		crypto_free_aead(ctx->rx_aead);
		crypto_free_aead(ctx->tx_aead);
		ctx->tx_aead = NULL;
		ctx->rx_aead = NULL;
		ctx->tx_hp = NULL;
		return err;
	}

	/* Allocate RX header protection cipher */
	ctx->rx_hp = crypto_alloc_sync_skcipher(cipher_name, 0, 0);
	if (IS_ERR(ctx->rx_hp)) {
		int err = PTR_ERR(ctx->rx_hp);
		crypto_free_sync_skcipher(ctx->tx_hp);
		crypto_free_aead(ctx->rx_aead);
		crypto_free_aead(ctx->tx_aead);
		ctx->tx_aead = NULL;
		ctx->rx_aead = NULL;
		ctx->tx_hp = NULL;
		ctx->rx_hp = NULL;
		return err;
	}

	/* Allocate hash for key derivation */
	ctx->hash = crypto_alloc_shash(hash_name, 0, 0);
	if (IS_ERR(ctx->hash)) {
		int err = PTR_ERR(ctx->hash);
		crypto_free_sync_skcipher(ctx->rx_hp);
		crypto_free_sync_skcipher(ctx->tx_hp);
		crypto_free_aead(ctx->rx_aead);
		crypto_free_aead(ctx->tx_aead);
		ctx->tx_aead = NULL;
		ctx->rx_aead = NULL;
		ctx->tx_hp = NULL;
		ctx->rx_hp = NULL;
		ctx->hash = NULL;
		return err;
	}

	ctx->tx.key_len = key_len;
	ctx->rx.key_len = key_len;
	ctx->tx.iv_len = 12;
	ctx->rx.iv_len = 12;
	ctx->tx.hp_key_len = key_len;
	ctx->rx.hp_key_len = key_len;

	return 0;
}

void tquic_crypto_ctx_destroy(struct tquic_crypto_ctx *ctx)
{
	if (ctx->hash)
		crypto_free_shash(ctx->hash);
	if (ctx->rx_hp)
		crypto_free_sync_skcipher(ctx->rx_hp);
	if (ctx->tx_hp)
		crypto_free_sync_skcipher(ctx->tx_hp);
	if (ctx->rx_aead)
		crypto_free_aead(ctx->rx_aead);
	if (ctx->tx_aead)
		crypto_free_aead(ctx->tx_aead);

	/* Use memzero_explicit to prevent compiler from optimizing away
	 * the clearing of key material (secrets, keys, IVs).
	 */
	memzero_explicit(ctx, sizeof(*ctx));
}

void tquic_crypto_destroy(void *crypto)
{
	if (!crypto)
		return;

	tquic_crypto_ctx_destroy((struct tquic_crypto_ctx *)crypto);
}
EXPORT_SYMBOL_GPL(tquic_crypto_destroy);

int tquic_crypto_derive_init_secrets(struct tquic_connection *conn,
				     struct tquic_cid *cid)
{
	struct tquic_crypto_wrapper *wrapper = tquic_crypto_wrapper_get(conn);
	struct tquic_crypto_ctx *ctx;

	if (!wrapper)
		return -EINVAL;

	ctx = &wrapper->crypto[TQUIC_CRYPTO_INITIAL];
	struct hkdf_ctx hkdf;
	const u8 *salt;
	u8 initial_secret[32];
	u8 client_secret[32];
	u8 server_secret[32];
	int err;

	/* Initialize with AES-128-GCM-SHA256 for initial packets */
	err = tquic_crypto_ctx_init(ctx, TQUIC_CIPHER_AES_128_GCM_SHA256);
	if (err)
		return err;

	/* CF-378: Store local CID length for short header parsing */
	ctx->local_cid_len = cid ? cid->len : 0;

	hkdf.hash = ctx->hash;
	hkdf.hash_len = 32;  /* SHA-256 */

	/* Select salt based on version */
	if (conn->version == TQUIC_VERSION_2)
		salt = tquic_v2_initial_salt;
	else
		salt = tquic_v1_initial_salt;

	/* Extract initial secret */
	err = hkdf_extract(&hkdf, salt, 20, cid->id, cid->len, initial_secret);
	if (err)
		goto out;

	/* Derive client and server secrets */
	err = tquic_hkdf_expand_label(&hkdf, initial_secret, tquic_client_in_label,
				strlen(tquic_client_in_label), NULL, 0,
				client_secret, 32);
	if (err)
		goto out;

	err = tquic_hkdf_expand_label(&hkdf, initial_secret, tquic_server_in_label,
				strlen(tquic_server_in_label), NULL, 0,
				server_secret, 32);
	if (err)
		goto out;

	/* Derive keys and IVs */
	if (conn->role == TQUIC_ROLE_SERVER) {
		/* Server: RX uses client secret, TX uses server secret */
		err = tquic_crypto_derive_secrets(ctx, client_secret, 32);
		if (err)
			goto out;
		memcpy(ctx->rx.secret, client_secret, 32);
		memcpy(ctx->tx.secret, server_secret, 32);
	} else {
		/* Client: TX uses client secret, RX uses server secret */
		err = tquic_crypto_derive_secrets(ctx, client_secret, 32);
		if (err)
			goto out;
		memcpy(ctx->tx.secret, client_secret, 32);
		memcpy(ctx->rx.secret, server_secret, 32);
	}

	/* Derive TX keys */
	err = tquic_hkdf_expand_label(&hkdf, ctx->tx.secret, tquic_key_label,
				strlen(tquic_key_label), NULL, 0,
				ctx->tx.key, ctx->tx.key_len);
	if (err)
		goto out;

	err = tquic_hkdf_expand_label(&hkdf, ctx->tx.secret, tquic_iv_label,
				strlen(tquic_iv_label), NULL, 0,
				ctx->tx.iv, ctx->tx.iv_len);
	if (err)
		goto out;

	err = tquic_hkdf_expand_label(&hkdf, ctx->tx.secret, tquic_hp_label,
				strlen(tquic_hp_label), NULL, 0,
				ctx->tx.hp_key, ctx->tx.hp_key_len);
	if (err)
		goto out;

	/* Derive RX keys */
	err = tquic_hkdf_expand_label(&hkdf, ctx->rx.secret, tquic_key_label,
				strlen(tquic_key_label), NULL, 0,
				ctx->rx.key, ctx->rx.key_len);
	if (err)
		goto out;

	err = tquic_hkdf_expand_label(&hkdf, ctx->rx.secret, tquic_iv_label,
				strlen(tquic_iv_label), NULL, 0,
				ctx->rx.iv, ctx->rx.iv_len);
	if (err)
		goto out;

	err = tquic_hkdf_expand_label(&hkdf, ctx->rx.secret, tquic_hp_label,
				strlen(tquic_hp_label), NULL, 0,
				ctx->rx.hp_key, ctx->rx.hp_key_len);
	if (err)
		goto out;

	/* Set keys on crypto transforms */
	err = crypto_aead_setkey(ctx->tx_aead, ctx->tx.key, ctx->tx.key_len);
	if (err)
		goto out;

	err = crypto_aead_setkey(ctx->rx_aead, ctx->rx.key, ctx->rx.key_len);
	if (err)
		goto out;

	err = crypto_sync_skcipher_setkey(ctx->tx_hp, ctx->tx.hp_key, ctx->tx.hp_key_len);
	if (err)
		goto out;

	err = crypto_sync_skcipher_setkey(ctx->rx_hp, ctx->rx.hp_key, ctx->rx.hp_key_len);
	if (err)
		goto out;

	err = crypto_aead_setauthsize(ctx->tx_aead, 16);
	if (err)
		goto out;

	err = crypto_aead_setauthsize(ctx->rx_aead, 16);
	if (err)
		goto out;

	ctx->keys_available = 1;
	ctx->tx.secret_len = 32;
	ctx->rx.secret_len = 32;

out:
	memzero_explicit(initial_secret, sizeof(initial_secret));
	memzero_explicit(client_secret, sizeof(client_secret));
	memzero_explicit(server_secret, sizeof(server_secret));
	return err;
}

int tquic_crypto_derive_secrets(struct tquic_crypto_ctx *ctx,
			       const u8 *secret, u32 secret_len)
{
	struct hkdf_ctx hkdf;
	int err;

	if (!ctx->hash)
		return -EINVAL;

	hkdf.hash = ctx->hash;
	hkdf.hash_len = secret_len;

	/* Derive key */
	err = tquic_hkdf_expand_label(&hkdf, secret, tquic_key_label,
				strlen(tquic_key_label), NULL, 0,
				ctx->tx.key, ctx->tx.key_len);
	if (err)
		return err;

	/* Derive IV */
	err = tquic_hkdf_expand_label(&hkdf, secret, tquic_iv_label,
				strlen(tquic_iv_label), NULL, 0,
				ctx->tx.iv, ctx->tx.iv_len);
	if (err)
		return err;

	/* Derive HP key */
	err = tquic_hkdf_expand_label(&hkdf, secret, tquic_hp_label,
				strlen(tquic_hp_label), NULL, 0,
				ctx->tx.hp_key, ctx->tx.hp_key_len);
	if (err)
		return err;

	return 0;
}

int tquic_crypto_derive_initial_secrets(struct tquic_connection *conn,
					const struct tquic_cid *cid)
{
	return tquic_crypto_derive_init_secrets(conn, (struct tquic_cid *)cid);
}
EXPORT_SYMBOL_GPL(tquic_crypto_derive_initial_secrets);

static void tquic_crypto_compute_nonce(const u8 *iv, u64 pn, u8 *nonce)
{
	int i;

	memcpy(nonce, iv, 12);

	/* XOR packet number into last 8 bytes of IV */
	for (i = 0; i < 8; i++)
		nonce[11 - i] ^= (pn >> (i * 8)) & 0xff;
}

int tquic_crypto_encrypt(struct tquic_crypto_ctx *ctx, struct sk_buff *skb,
			u64 pn)
{
	struct aead_request *req;
	struct scatterlist sg[2];
	u8 nonce[12];
	u8 *payload;
	u32 payload_len;
	u32 header_len;
	int err;

	if (!ctx->tx_aead || !ctx->keys_available)
		return -EINVAL;

	header_len = TQUIC_SKB_CB(skb)->header_len;
	payload = skb->data + header_len;
	payload_len = skb->len - header_len;

	tquic_crypto_compute_nonce(ctx->tx.iv, pn, nonce);

	req = aead_request_alloc(ctx->tx_aead, GFP_ATOMIC);
	if (!req)
		return -ENOMEM;

	/* Expand skb for authentication tag */
	if (skb_tailroom(skb) < 16) {
		err = pskb_expand_head(skb, 0, 16 - skb_tailroom(skb), GFP_ATOMIC);
		if (err) {
			aead_request_free(req);
			return err;
		}
	}

	sg_init_table(sg, 2);
	sg_set_buf(&sg[0], skb->data, header_len);  /* AAD */
	sg_set_buf(&sg[1], payload, payload_len + 16);  /* Payload + tag space */

	aead_request_set_crypt(req, &sg[1], &sg[1], payload_len, nonce);
	aead_request_set_ad(req, header_len);

	err = crypto_aead_encrypt(req);

	aead_request_free(req);

	if (!err)
		skb_put(skb, 16);  /* Add auth tag to length */

	return err;
}

int tquic_crypto_decrypt(struct tquic_crypto_ctx *ctx, struct sk_buff *skb,
			u64 pn)
{
	struct aead_request *req;
	struct scatterlist sg[2];
	u8 nonce[12];
	u8 *payload;
	u32 payload_len;
	u32 header_len;
	int err;

	if (!ctx->rx_aead || !ctx->keys_available)
		return -EINVAL;

	header_len = TQUIC_SKB_CB(skb)->header_len;
	payload = skb->data + header_len;
	payload_len = skb->len - header_len;

	if (payload_len < 16)
		return -EINVAL;  /* Too short for auth tag */

	tquic_crypto_compute_nonce(ctx->rx.iv, pn, nonce);

	req = aead_request_alloc(ctx->rx_aead, GFP_ATOMIC);
	if (!req)
		return -ENOMEM;

	sg_init_table(sg, 2);
	sg_set_buf(&sg[0], skb->data, header_len);  /* AAD */
	sg_set_buf(&sg[1], payload, payload_len);  /* Payload + tag */

	aead_request_set_crypt(req, &sg[1], &sg[1], payload_len, nonce);
	aead_request_set_ad(req, header_len);

	err = crypto_aead_decrypt(req);

	aead_request_free(req);

	if (!err)
		skb_trim(skb, skb->len - 16);  /* Remove auth tag from length */

	return err;
}

int tquic_crypto_hp_mask(struct tquic_crypto_ctx *ctx, const u8 *sample,
			u8 *mask)
{
	int err;

	if (!ctx->rx_hp)
		return -EINVAL;

	/* For AES, we encrypt a block of zeros with the sample as part of the input */
	if (ctx->cipher_type == TQUIC_CIPHER_AES_128_GCM_SHA256 ||
	    ctx->cipher_type == TQUIC_CIPHER_AES_256_GCM_SHA384) {
		err = tquic_hp_encrypt_block(ctx->rx_hp, mask, sample);
	} else {
		/* ChaCha20: counter=sample[0..3], nonce=sample[4..15] */
		/* Encrypt zeros to get mask - simplified */
		memset(mask, 0, 5);
		err = tquic_hp_encrypt_block(ctx->rx_hp, mask, sample);
	}

	return err;
}

/* Minimum interval between key updates (1 second) */
#define TQUIC_KEY_UPDATE_MIN_INTERVAL_NS	(1000000000ULL)

int tquic_crypto_update_keys(struct tquic_connection *conn)
{
	struct tquic_crypto_wrapper *wrapper = tquic_crypto_wrapper_get(conn);
	struct tquic_crypto_ctx *ctx;
	ktime_t now;

	if (!wrapper)
		return -EINVAL;

	ctx = &wrapper->crypto[TQUIC_CRYPTO_APPLICATION];
	struct hkdf_ctx hkdf;
	u8 new_secret[64];
	int err;

	if (!ctx->hash || !ctx->keys_available)
		return -EINVAL;

	/* Rate limit key updates to prevent abuse (min 1 second interval) */
	now = ktime_get();
	if (ctx->last_key_update &&
	    ktime_to_ns(ktime_sub(now, ctx->last_key_update)) <
	    TQUIC_KEY_UPDATE_MIN_INTERVAL_NS) {
		pr_warn("TQUIC: key update rate limited (too frequent)\n");
		return -EAGAIN;
	}

	hkdf.hash = ctx->hash;
	hkdf.hash_len = ctx->tx.secret_len;

	/* Derive new secret from current secret */
	err = tquic_hkdf_expand_label(&hkdf, ctx->tx.secret, tquic_ku_label,
				strlen(tquic_ku_label), NULL, 0,
				new_secret, ctx->tx.secret_len);
	if (err)
		return err;

	/* Derive new keys from new secret */
	memcpy(ctx->tx.secret, new_secret, ctx->tx.secret_len);

	err = tquic_hkdf_expand_label(&hkdf, ctx->tx.secret, tquic_key_label,
				strlen(tquic_key_label), NULL, 0,
				ctx->tx.key, ctx->tx.key_len);
	if (err)
		goto out;

	err = tquic_hkdf_expand_label(&hkdf, ctx->tx.secret, tquic_iv_label,
				strlen(tquic_iv_label), NULL, 0,
				ctx->tx.iv, ctx->tx.iv_len);
	if (err)
		goto out;

	/* Update AEAD key */
	err = crypto_aead_setkey(ctx->tx_aead, ctx->tx.key, ctx->tx.key_len);
	if (err)
		goto out;

	/* Toggle key phase */
	ctx->key_phase = !ctx->key_phase;

	/* Record time of successful key update for rate limiting */
	ctx->last_key_update = now;

out:
	memzero_explicit(new_secret, sizeof(new_secret));
	return err;
}

/* Helper to apply header protection */
int tquic_crypto_protect_header(struct tquic_crypto_ctx *ctx, struct sk_buff *skb,
			       u8 pn_offset, u8 pn_len)
{
	u8 mask[16];
	u8 *sample;
	u8 *header;
	int i;
	int err;

	if (skb->len < pn_offset + 4 + 16)
		return -EINVAL;

	/* Sample starts 4 bytes after packet number */
	sample = skb->data + pn_offset + 4;

	/* Generate mask using TX HP key */
	if (ctx->cipher_type == TQUIC_CIPHER_AES_128_GCM_SHA256 ||
	    ctx->cipher_type == TQUIC_CIPHER_AES_256_GCM_SHA384) {
		err = tquic_hp_encrypt_block(ctx->tx_hp, mask, sample);
	} else {
		memset(mask, 0, 16);
		err = tquic_hp_encrypt_block(ctx->tx_hp, mask, sample);
	}

	if (err)
		return err;

	header = skb->data;

	/* Apply mask to first byte */
	if (header[0] & 0x80) {
		/* Long header */
		header[0] ^= mask[0] & 0x0f;
	} else {
		/* Short header */
		header[0] ^= mask[0] & 0x1f;
	}

	/* Apply mask to packet number */
	for (i = 0; i < pn_len; i++)
		skb->data[pn_offset + i] ^= mask[1 + i];

	return 0;
}

/* Helper to remove header protection */
int tquic_crypto_unprotect_header(struct tquic_crypto_ctx *ctx, struct sk_buff *skb,
				 u8 *pn_offset, u8 *pn_len)
{
	u8 mask[16];
	u8 *sample;
	u8 *header;
	int sample_offset;
	int i;
	int err;

	header = skb->data;

	/* Determine packet number offset based on header type */
	if (header[0] & 0x80) {
		/* Long header - need to parse DCID/SCID lengths */
		u8 dcid_len = header[5];
		u8 scid_len;

		if (skb->len < 7 + dcid_len)
			return -EINVAL;

		scid_len = header[6 + dcid_len];

		if (skb->len < 7 + dcid_len + 1 + scid_len + 4 + 16)
			return -EINVAL;

		*pn_offset = 7 + dcid_len + 1 + scid_len;

		/* For Initial packets, also need to skip token length and token */
		/* Simplified: assume handshake packet without token */
	} else {
		/*
		 * CF-378: Use the known local CID length instead of
		 * hardcoding 8 bytes.  The receiver always knows the
		 * length of its own CIDs.
		 */
		u8 local_cid_len = ctx->local_cid_len;

		*pn_offset = 1 + local_cid_len;
	}

	sample_offset = *pn_offset + 4;
	if (skb->len < sample_offset + 16)
		return -EINVAL;

	sample = skb->data + sample_offset;

	/* Generate mask using RX HP key */
	if (ctx->cipher_type == TQUIC_CIPHER_AES_128_GCM_SHA256 ||
	    ctx->cipher_type == TQUIC_CIPHER_AES_256_GCM_SHA384) {
		err = tquic_hp_encrypt_block(ctx->rx_hp, mask, sample);
	} else {
		memset(mask, 0, 16);
		err = tquic_hp_encrypt_block(ctx->rx_hp, mask, sample);
	}

	if (err)
		return err;

	/* Remove mask from first byte */
	if (header[0] & 0x80) {
		header[0] ^= mask[0] & 0x0f;
		*pn_len = (header[0] & 0x03) + 1;
	} else {
		header[0] ^= mask[0] & 0x1f;
		*pn_len = (header[0] & 0x03) + 1;
	}

	/* Remove mask from packet number */
	for (i = 0; i < *pn_len; i++)
		skb->data[*pn_offset + i] ^= mask[1 + i];

	return 0;
}

/*
 * TLS Extension Building and Parsing (RFC 6066, RFC 7301)
 */

/**
 * tquic_tls_build_sni_extension - Build SNI extension for ClientHello
 * @hostname: Server hostname (null-terminated)
 * @buf: Output buffer
 * @buf_len: Buffer size
 *
 * Builds the server_name extension (RFC 6066 Section 3) for TLS ClientHello.
 * Format:
 *   Extension Type (2 bytes): 0x0000 (server_name)
 *   Extension Length (2 bytes)
 *   Server Name List Length (2 bytes)
 *   Server Name Type (1 byte): 0x00 (host_name)
 *   Host Name Length (2 bytes)
 *   Host Name (variable)
 *
 * Return: Number of bytes written on success, negative error code on failure
 */
int tquic_tls_build_sni_extension(const char *hostname, u8 *buf, size_t buf_len)
{
	size_t hostname_len;
	size_t ext_data_len;
	size_t total_len;
	u8 *p = buf;

	if (!hostname || !buf)
		return -EINVAL;

	hostname_len = strlen(hostname);
	if (hostname_len == 0 || hostname_len > 255)
		return -EINVAL;

	/* Calculate lengths */
	/* Extension data: name_list_len(2) + name_type(1) + name_len(2) + name */
	ext_data_len = 2 + 1 + 2 + hostname_len;
	/* Total: ext_type(2) + ext_len(2) + ext_data */
	total_len = 4 + ext_data_len;

	if (buf_len < total_len)
		return -ENOSPC;

	/* Extension Type: server_name (0x0000) */
	*p++ = 0x00;
	*p++ = 0x00;

	/* Extension Length */
	*p++ = (ext_data_len >> 8) & 0xff;
	*p++ = ext_data_len & 0xff;

	/* Server Name List Length */
	*p++ = ((1 + 2 + hostname_len) >> 8) & 0xff;
	*p++ = (1 + 2 + hostname_len) & 0xff;

	/* Server Name Type: host_name (0x00) */
	*p++ = 0x00;

	/* Host Name Length */
	*p++ = (hostname_len >> 8) & 0xff;
	*p++ = hostname_len & 0xff;

	/* Host Name */
	memcpy(p, hostname, hostname_len);

	return total_len;
}
EXPORT_SYMBOL_GPL(tquic_tls_build_sni_extension);

/**
 * tquic_tls_build_alpn_extension - Build ALPN extension
 * @alpn_list: ALPN protocol list (length-prefixed format per RFC 7301)
 * @alpn_len: Length of ALPN list
 * @buf: Output buffer
 * @buf_len: Buffer size
 *
 * Builds the application_layer_protocol_negotiation extension (RFC 7301).
 * Format:
 *   Extension Type (2 bytes): 0x0010 (application_layer_protocol_negotiation)
 *   Extension Length (2 bytes)
 *   Protocol Name List Length (2 bytes)
 *   Protocol Name List (variable): sequence of length-prefixed strings
 *
 * Return: Number of bytes written on success, negative error code on failure
 */
int tquic_tls_build_alpn_extension(const u8 *alpn_list, size_t alpn_len,
				  u8 *buf, size_t buf_len)
{
	size_t ext_data_len;
	size_t total_len;
	u8 *p = buf;

	if (!alpn_list || alpn_len == 0 || !buf)
		return -EINVAL;

	/* Extension data: proto_list_len(2) + proto_list */
	ext_data_len = 2 + alpn_len;
	/* Total: ext_type(2) + ext_len(2) + ext_data */
	total_len = 4 + ext_data_len;

	if (buf_len < total_len)
		return -ENOSPC;

	/* Extension Type: application_layer_protocol_negotiation (0x0010) */
	*p++ = 0x00;
	*p++ = 0x10;

	/* Extension Length */
	*p++ = (ext_data_len >> 8) & 0xff;
	*p++ = ext_data_len & 0xff;

	/* Protocol Name List Length */
	*p++ = (alpn_len >> 8) & 0xff;
	*p++ = alpn_len & 0xff;

	/* Protocol Name List (already in length-prefixed format) */
	memcpy(p, alpn_list, alpn_len);

	return total_len;
}
EXPORT_SYMBOL_GPL(tquic_tls_build_alpn_extension);

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
				 char *hostname, size_t *hostname_len)
{
	size_t name_list_len;
	size_t name_len;
	u8 name_type;
	size_t offset = 0;

	if (!data || !hostname || !hostname_len || data_len < 5)
		return -EINVAL;

	/* Server Name List Length - validate bounds before 16-bit read */
	if (offset + 2 > data_len)
		return -EINVAL;
	name_list_len = (data[offset] << 8) | data[offset + 1];
	offset += 2;

	if (offset + name_list_len > data_len)
		return -EINVAL;

	/* Parse first (and typically only) server name entry */
	if (offset + 3 > data_len)
		return -EINVAL;

	name_type = data[offset++];
	if (name_type != 0x00) {
		/* Only host_name type is supported */
		return -EINVAL;
	}

	/* Name Length - validate bounds before 16-bit read */
	if (offset + 2 > data_len)
		return -EINVAL;
	name_len = (data[offset] << 8) | data[offset + 1];
	offset += 2;

	if (offset + name_len > data_len)
		return -EINVAL;

	if (name_len > *hostname_len)
		return -ENOSPC;

	memcpy(hostname, data + offset, name_len);
	*hostname_len = name_len;

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_tls_parse_sni_extension);

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
				  u8 *alpn_list, size_t *alpn_len)
{
	size_t list_len;

	if (!data || !alpn_list || !alpn_len || data_len < 2)
		return -EINVAL;

	/* Protocol Name List Length */
	list_len = (data[0] << 8) | data[1];

	if (2 + list_len > data_len)
		return -EINVAL;

	if (list_len > *alpn_len)
		return -ENOSPC;

	memcpy(alpn_list, data + 2, list_len);
	*alpn_len = list_len;

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_tls_parse_alpn_extension);

/**
 * tquic_tls_select_alpn - Server ALPN selection
 * @client_alpn: Client's ALPN list (length-prefixed format)
 * @client_alpn_len: Length of client list
 * @server_alpn: Server's supported ALPN list (length-prefixed format)
 * @server_alpn_len: Length of server list
 * @selected: Output buffer for selected protocol
 * @selected_len: In: buffer size, Out: selected protocol length
 *
 * Selects the first protocol from server's list that client supports.
 * Per RFC 7301, server preference should be used.
 *
 * Return: 0 on success (protocol selected),
 *         -ENOENT if no common protocol,
 *         negative error code on failure
 */
int tquic_tls_select_alpn(const u8 *client_alpn, size_t client_alpn_len,
			 const u8 *server_alpn, size_t server_alpn_len,
			 u8 *selected, size_t *selected_len)
{
	size_t s_offset, c_offset;
	u8 s_proto_len, c_proto_len;

	if (!client_alpn || !server_alpn || !selected || !selected_len)
		return -EINVAL;

	/* Iterate server protocols (server preference) */
	for (s_offset = 0; s_offset < server_alpn_len; ) {
		s_proto_len = server_alpn[s_offset];
		if (s_offset + 1 + s_proto_len > server_alpn_len)
			return -EINVAL;

		/* Check if this server protocol is in client's list */
		for (c_offset = 0; c_offset < client_alpn_len; ) {
			c_proto_len = client_alpn[c_offset];
			if (c_offset + 1 + c_proto_len > client_alpn_len)
				return -EINVAL;

			/* Compare protocols */
			if (s_proto_len == c_proto_len &&
			    memcmp(server_alpn + s_offset + 1,
				   client_alpn + c_offset + 1,
				   s_proto_len) == 0) {
				/* Found match - return in length-prefixed format */
				if (1 + s_proto_len > *selected_len)
					return -ENOSPC;

				selected[0] = s_proto_len;
				memcpy(selected + 1,
				       server_alpn + s_offset + 1,
				       s_proto_len);
				*selected_len = 1 + s_proto_len;
				return 0;
			}

			c_offset += 1 + c_proto_len;
		}

		s_offset += 1 + s_proto_len;
	}

	/* No common protocol found */
	return -ENOENT;
}
EXPORT_SYMBOL_GPL(tquic_tls_select_alpn);

/**
 * tquic_tls_validate_alpn - Validate server's ALPN selection
 * @offered_alpn: Client's offered ALPN list (length-prefixed format)
 * @offered_len: Length of offered list
 * @selected: Server's selected protocol (length-prefixed, single entry)
 * @selected_len: Length of selected protocol (including length byte)
 *
 * Verifies that server's selected ALPN was in client's offered list.
 *
 * Return: 0 if valid, -EPROTO if not in offered list
 */
int tquic_tls_validate_alpn(const u8 *offered_alpn, size_t offered_len,
			   const u8 *selected, size_t selected_len)
{
	size_t offset;
	u8 sel_proto_len, proto_len;

	if (!offered_alpn || !selected || selected_len < 2)
		return -EINVAL;

	/* Get selected protocol length */
	sel_proto_len = selected[0];
	if (1 + sel_proto_len != selected_len)
		return -EINVAL;

	/* Search for selected protocol in offered list */
	for (offset = 0; offset < offered_len; ) {
		proto_len = offered_alpn[offset];
		if (offset + 1 + proto_len > offered_len)
			return -EINVAL;

		if (proto_len == sel_proto_len &&
		    memcmp(offered_alpn + offset + 1,
			   selected + 1,
			   proto_len) == 0) {
			return 0;  /* Found - valid selection */
		}

		offset += 1 + proto_len;
	}

	/* Server selected a protocol not offered by client */
	pr_warn("TQUIC-TLS: server selected ALPN not in client's list\n");
	return -EPROTO;
}
EXPORT_SYMBOL_GPL(tquic_tls_validate_alpn);
