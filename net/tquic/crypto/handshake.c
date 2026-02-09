// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: TLS 1.3 Handshake for QUIC
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Implements the full TLS 1.3 handshake protocol for QUIC connections,
 * including key schedule, transport parameters, ALPN, and PSK support.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/string.h>
#include <crypto/aead.h>
#include <crypto/hash.h>
#include <crypto/skcipher.h>
#include <crypto/ecdh.h>
#include <crypto/curve25519.h>
#include <crypto/akcipher.h>
#include <crypto/sig.h>
#include <crypto/utils.h>
#include <net/tquic.h>
#include <net/tquic/handshake.h>
#include "cert_verify.h"

/* TLS 1.3 Version */
#define TLS_VERSION_13			0x0304
#define TLS_LEGACY_VERSION		0x0303

/* TLS 1.3 Handshake Message Types */
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

/* TLS 1.3 Extension Types */
#define TLS_EXT_SERVER_NAME		0
#define TLS_EXT_MAX_FRAGMENT_LENGTH	1
#define TLS_EXT_STATUS_REQUEST		5
#define TLS_EXT_SUPPORTED_GROUPS	10
#define TLS_EXT_EC_POINT_FORMATS	11
#define TLS_EXT_SIGNATURE_ALGORITHMS	13
#define TLS_EXT_ALPN			16
#define TLS_EXT_SCT			18
#define TLS_EXT_PADDING			21
#define TLS_EXT_ENCRYPT_THEN_MAC	22
#define TLS_EXT_EXTENDED_MASTER_SECRET	23
#define TLS_EXT_SESSION_TICKET		35
#define TLS_EXT_PRE_SHARED_KEY		41
#define TLS_EXT_EARLY_DATA		42
#define TLS_EXT_SUPPORTED_VERSIONS	43
#define TLS_EXT_COOKIE			44
#define TLS_EXT_PSK_KEY_EXCHANGE_MODES	45
#define TLS_EXT_CERTIFICATE_AUTHORITIES	47
#define TLS_EXT_OID_FILTERS		48
#define TLS_EXT_POST_HANDSHAKE_AUTH	49
#define TLS_EXT_SIGNATURE_ALGORITHMS_CERT 50
#define TLS_EXT_KEY_SHARE		51
#define TLS_EXT_QUIC_TRANSPORT_PARAMS	0x39

/* TLS 1.3 Cipher Suites (common ones defined in <net/tquic/handshake.h>) */
#define TLS_AES_128_CCM_SHA256		0x1304
#define TLS_AES_128_CCM_8_SHA256	0x1305

/* Signature Algorithms */
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

/* Named Groups */
#define TLS_GROUP_SECP256R1		23
#define TLS_GROUP_SECP384R1		24
#define TLS_GROUP_SECP521R1		25
#define TLS_GROUP_X25519		29
#define TLS_GROUP_X448			30

/* PSK Key Exchange Modes */
#define TLS_PSK_KE			0
#define TLS_PSK_DHE_KE			1

/* Key sizes and limits (common ones defined in <net/tquic/handshake.h>) */
#define TLS_CERT_MAX_LEN		16384

/* QUIC Transport Parameters */
#define QUIC_TP_ORIGINAL_DCID			0x00
#define QUIC_TP_MAX_IDLE_TIMEOUT		0x01
#define QUIC_TP_STATELESS_RESET_TOKEN		0x02
#define QUIC_TP_MAX_UDP_PAYLOAD_SIZE		0x03
#define QUIC_TP_INITIAL_MAX_DATA		0x04
#define QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL  0x05
#define QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE 0x06
#define QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI	0x07
#define QUIC_TP_INITIAL_MAX_STREAMS_BIDI	0x08
#define QUIC_TP_INITIAL_MAX_STREAMS_UNI		0x09
#define QUIC_TP_ACK_DELAY_EXPONENT		0x0a
#define QUIC_TP_MAX_ACK_DELAY			0x0b
#define QUIC_TP_DISABLE_ACTIVE_MIGRATION	0x0c
#define QUIC_TP_PREFERRED_ADDRESS		0x0d
#define QUIC_TP_ACTIVE_CONN_ID_LIMIT		0x0e
#define QUIC_TP_INITIAL_SCID			0x0f
#define QUIC_TP_RETRY_SCID			0x10
#define QUIC_TP_MAX_DATAGRAM_FRAME_SIZE		0x20
#define QUIC_TP_GREASE_QUIC_BIT			0x2ab2

/* Alert descriptions */
enum tls_alert {
	TLS_ALERT_CLOSE_NOTIFY = 0,
	TLS_ALERT_UNEXPECTED_MESSAGE = 10,
	TLS_ALERT_BAD_RECORD_MAC = 20,
	TLS_ALERT_RECORD_OVERFLOW = 22,
	TLS_ALERT_HANDSHAKE_FAILURE = 40,
	TLS_ALERT_BAD_CERTIFICATE = 42,
	TLS_ALERT_UNSUPPORTED_CERTIFICATE = 43,
	TLS_ALERT_CERTIFICATE_REVOKED = 44,
	TLS_ALERT_CERTIFICATE_EXPIRED = 45,
	TLS_ALERT_CERTIFICATE_UNKNOWN = 46,
	TLS_ALERT_ILLEGAL_PARAMETER = 47,
	TLS_ALERT_UNKNOWN_CA = 48,
	TLS_ALERT_ACCESS_DENIED = 49,
	TLS_ALERT_DECODE_ERROR = 50,
	TLS_ALERT_DECRYPT_ERROR = 51,
	TLS_ALERT_PROTOCOL_VERSION = 70,
	TLS_ALERT_INSUFFICIENT_SECURITY = 71,
	TLS_ALERT_INTERNAL_ERROR = 80,
	TLS_ALERT_INAPPROPRIATE_FALLBACK = 86,
	TLS_ALERT_USER_CANCELED = 90,
	TLS_ALERT_MISSING_EXTENSION = 109,
	TLS_ALERT_UNSUPPORTED_EXTENSION = 110,
	TLS_ALERT_UNRECOGNIZED_NAME = 112,
	TLS_ALERT_BAD_CERTIFICATE_STATUS_RESPONSE = 113,
	TLS_ALERT_UNKNOWN_PSK_IDENTITY = 115,
	TLS_ALERT_CERTIFICATE_REQUIRED = 116,
	TLS_ALERT_NO_APPLICATION_PROTOCOL = 120,
};

/* PSK identity for session resumption */
struct tquic_psk_identity {
	u8 *identity;
	u32 identity_len;
	u32 obfuscated_ticket_age;
	u8 binder[TLS_FINISHED_MAX_LEN];
	u32 binder_len;
};

/* Key share entry */
struct tquic_key_share {
	u16 group;
	u8 *public_key;
	u32 public_key_len;
	u8 *private_key;
	u32 private_key_len;
};

/* TLS 1.3 Handshake context */
struct tquic_handshake {
	/* State machine */
	enum tquic_hs_state state;
	bool is_server;
	bool using_psk;
	bool early_data_offered;
	bool early_data_accepted;
	bool client_auth_requested;

	/* Cipher suite */
	u16 cipher_suite;
	u32 hash_len;

	/* Random values */
	u8 client_random[TLS_RANDOM_LEN];
	u8 server_random[TLS_RANDOM_LEN];

	/* Legacy session ID */
	u8 session_id[TLS_SESSION_ID_MAX_LEN];
	u8 session_id_len;

	/* Key exchange */
	struct tquic_key_share key_share;
	u8 shared_secret[64];
	u32 shared_secret_len;

	/* Transcript hash */
	struct crypto_shash *hash_tfm;
	u8 *transcript;
	u32 transcript_len;
	u32 transcript_alloc;

	/* Key schedule secrets */
	u8 early_secret[TLS_SECRET_MAX_LEN];
	u8 handshake_secret[TLS_SECRET_MAX_LEN];
	u8 master_secret[TLS_SECRET_MAX_LEN];
	u8 client_handshake_secret[TLS_SECRET_MAX_LEN];
	u8 server_handshake_secret[TLS_SECRET_MAX_LEN];
	u8 client_app_secret[TLS_SECRET_MAX_LEN];
	u8 server_app_secret[TLS_SECRET_MAX_LEN];
	u8 exporter_secret[TLS_SECRET_MAX_LEN];
	u8 resumption_secret[TLS_SECRET_MAX_LEN];

	/* Finished keys */
	u8 client_finished_key[TLS_SECRET_MAX_LEN];
	u8 server_finished_key[TLS_SECRET_MAX_LEN];

	/* ALPN */
	char *alpn_selected;
	u32 alpn_len;
	char **alpn_list;
	u32 alpn_count;

	/* SNI */
	char *sni;
	u32 sni_len;

	/* Transport parameters */
	struct tquic_hs_transport_params local_params;
	struct tquic_hs_transport_params peer_params;
	bool params_received;

	/* PSK/Resumption */
	struct tquic_psk_identity *psk_identities;
	u32 psk_count;
	u32 psk_selected;
	struct tquic_session_ticket *session_ticket;

	/* Certificates */
	u8 *peer_cert;
	u32 peer_cert_len;
	u8 *local_cert;
	u32 local_cert_len;
	u8 *local_key;
	u32 local_key_len;

	/* Alert */
	enum tls_alert alert;
	bool alert_sent;

	/* Crypto transforms */
	struct crypto_aead *aead;
	struct crypto_shash *hmac;
};

/* Forward declarations */
static int tquic_hs_derive_secret(struct tquic_handshake *hs,
				  const u8 *secret, const char *label,
				  const u8 *context, u32 context_len,
				  u8 *out, u32 out_len);
static int tquic_hs_hkdf_expand_label(struct tquic_handshake *hs,
				      const u8 *secret, u32 secret_len,
				      const char *label,
				      const u8 *context, u32 context_len,
				      u8 *out, u32 out_len);
static int tquic_hs_update_transcript(struct tquic_handshake *hs,
				      const u8 *data, u32 len);
static int tquic_hs_transcript_hash(struct tquic_handshake *hs,
				    u8 *out, u32 *out_len);

/*
 * Variable-length integer encoding (QUIC style)
 */
static int hs_varint_encode(u64 val, u8 *buf, u32 *len)
{
	if (val < 0x40) {
		buf[0] = val;
		*len = 1;
	} else if (val < 0x4000) {
		buf[0] = 0x40 | (val >> 8);
		buf[1] = val & 0xff;
		*len = 2;
	} else if (val < 0x40000000) {
		buf[0] = 0x80 | (val >> 24);
		buf[1] = (val >> 16) & 0xff;
		buf[2] = (val >> 8) & 0xff;
		buf[3] = val & 0xff;
		*len = 4;
	} else {
		buf[0] = 0xc0 | (val >> 56);
		buf[1] = (val >> 48) & 0xff;
		buf[2] = (val >> 40) & 0xff;
		buf[3] = (val >> 32) & 0xff;
		buf[4] = (val >> 24) & 0xff;
		buf[5] = (val >> 16) & 0xff;
		buf[6] = (val >> 8) & 0xff;
		buf[7] = val & 0xff;
		*len = 8;
	}
	return 0;
}

static int hs_varint_decode(const u8 *buf, u32 buf_len, u64 *val, u32 *len)
{
	u8 prefix;

	if (buf_len < 1)
		return -EINVAL;

	prefix = buf[0] >> 6;

	switch (prefix) {
	case 0:
		*val = buf[0];
		*len = 1;
		break;
	case 1:
		if (buf_len < 2)
			return -EINVAL;
		*val = ((buf[0] & 0x3f) << 8) | buf[1];
		*len = 2;
		break;
	case 2:
		if (buf_len < 4)
			return -EINVAL;
		*val = ((buf[0] & 0x3f) << 24) |
		       (buf[1] << 16) |
		       (buf[2] << 8) |
		       buf[3];
		*len = 4;
		break;
	case 3:
		if (buf_len < 8)
			return -EINVAL;
		*val = ((u64)(buf[0] & 0x3f) << 56) |
		       ((u64)buf[1] << 48) |
		       ((u64)buf[2] << 40) |
		       ((u64)buf[3] << 32) |
		       ((u64)buf[4] << 24) |
		       ((u64)buf[5] << 16) |
		       ((u64)buf[6] << 8) |
		       (u64)buf[7];
		*len = 8;
		break;
	}

	return 0;
}

/*
 * QUIC Transport Parameters encoding
 */
static int tquic_encode_transport_params(struct tquic_hs_transport_params *params,
					 u8 *buf, u32 buf_len, u32 *out_len,
					 bool is_server)
{
	u8 *p = buf;
	u8 *end = buf + buf_len;
	u8 varint[8];
	u32 vlen;

/* Macro to check buffer space before writing a varint */
#define TP_CHECK_SPACE(needed) do {		\
	if (p + (needed) > end)			\
		return -ENOSPC;			\
} while (0)

/* Macro to encode a varint with bounds check */
#define TP_ENCODE_VARINT(val) do {		\
	hs_varint_encode((val), varint, &vlen);	\
	TP_CHECK_SPACE(vlen);			\
	memcpy(p, varint, vlen);		\
	p += vlen;				\
} while (0)

/* Macro to copy data with bounds check */
#define TP_COPY(src, len) do {			\
	TP_CHECK_SPACE(len);			\
	memcpy(p, (src), (len));		\
	p += (len);				\
} while (0)

/* Macro to write a single byte with bounds check */
#define TP_WRITE_BYTE(b) do {			\
	TP_CHECK_SPACE(1);			\
	*p++ = (b);				\
} while (0)

	/* max_idle_timeout */
	if (params->max_idle_timeout > 0) {
		TP_ENCODE_VARINT(QUIC_TP_MAX_IDLE_TIMEOUT);
		TP_ENCODE_VARINT(8);
		TP_ENCODE_VARINT(params->max_idle_timeout);
	}

	/* max_udp_payload_size */
	if (params->max_udp_payload_size > 0) {
		TP_ENCODE_VARINT(QUIC_TP_MAX_UDP_PAYLOAD_SIZE);
		TP_ENCODE_VARINT(8);
		TP_ENCODE_VARINT(params->max_udp_payload_size);
	}

	/* initial_max_data */
	TP_ENCODE_VARINT(QUIC_TP_INITIAL_MAX_DATA);
	TP_ENCODE_VARINT(8);
	TP_ENCODE_VARINT(params->initial_max_data);

	/* initial_max_stream_data_bidi_local */
	TP_ENCODE_VARINT(QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL);
	TP_ENCODE_VARINT(8);
	TP_ENCODE_VARINT(params->initial_max_stream_data_bidi_local);

	/* initial_max_stream_data_bidi_remote */
	TP_ENCODE_VARINT(QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE);
	TP_ENCODE_VARINT(8);
	TP_ENCODE_VARINT(params->initial_max_stream_data_bidi_remote);

	/* initial_max_stream_data_uni */
	TP_ENCODE_VARINT(QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI);
	TP_ENCODE_VARINT(8);
	TP_ENCODE_VARINT(params->initial_max_stream_data_uni);

	/* initial_max_streams_bidi */
	TP_ENCODE_VARINT(QUIC_TP_INITIAL_MAX_STREAMS_BIDI);
	TP_ENCODE_VARINT(8);
	TP_ENCODE_VARINT(params->initial_max_streams_bidi);

	/* initial_max_streams_uni */
	TP_ENCODE_VARINT(QUIC_TP_INITIAL_MAX_STREAMS_UNI);
	TP_ENCODE_VARINT(8);
	TP_ENCODE_VARINT(params->initial_max_streams_uni);

	/* ack_delay_exponent */
	if (params->ack_delay_exponent != 3) {
		TP_ENCODE_VARINT(QUIC_TP_ACK_DELAY_EXPONENT);
		TP_ENCODE_VARINT(1);
		TP_WRITE_BYTE(params->ack_delay_exponent);
	}

	/* max_ack_delay */
	if (params->max_ack_delay != 25) {
		TP_ENCODE_VARINT(QUIC_TP_MAX_ACK_DELAY);
		TP_ENCODE_VARINT(8);
		TP_ENCODE_VARINT(params->max_ack_delay);
	}

	/* disable_active_migration */
	if (params->disable_active_migration) {
		TP_ENCODE_VARINT(QUIC_TP_DISABLE_ACTIVE_MIGRATION);
		TP_ENCODE_VARINT(0);
	}

	/* active_connection_id_limit */
	TP_ENCODE_VARINT(QUIC_TP_ACTIVE_CONN_ID_LIMIT);
	TP_ENCODE_VARINT(8);
	TP_ENCODE_VARINT(params->active_conn_id_limit);

	/* initial_source_connection_id */
	if (params->initial_scid_len > 0) {
		TP_ENCODE_VARINT(QUIC_TP_INITIAL_SCID);
		TP_ENCODE_VARINT(params->initial_scid_len);
		TP_COPY(params->initial_scid, params->initial_scid_len);
	}

	/* Server-only parameters */
	if (is_server) {
		/* original_destination_connection_id */
		if (params->original_dcid_len > 0) {
			TP_ENCODE_VARINT(QUIC_TP_ORIGINAL_DCID);
			TP_ENCODE_VARINT(params->original_dcid_len);
			TP_COPY(params->original_dcid, params->original_dcid_len);
		}

		/* stateless_reset_token */
		if (params->has_stateless_reset_token) {
			TP_ENCODE_VARINT(QUIC_TP_STATELESS_RESET_TOKEN);
			TP_ENCODE_VARINT(16);
			TP_COPY(params->stateless_reset_token, 16);
		}

		/* retry_source_connection_id */
		if (params->has_retry_scid) {
			TP_ENCODE_VARINT(QUIC_TP_RETRY_SCID);
			TP_ENCODE_VARINT(params->retry_scid_len);
			TP_COPY(params->retry_scid, params->retry_scid_len);
		}
	}

	/* max_datagram_frame_size (for DATAGRAM extension) */
	if (params->max_datagram_frame_size > 0) {
		TP_ENCODE_VARINT(QUIC_TP_MAX_DATAGRAM_FRAME_SIZE);
		TP_ENCODE_VARINT(8);
		TP_ENCODE_VARINT(params->max_datagram_frame_size);
	}

	/* grease_quic_bit (RFC 9287) - zero-length parameter */
	if (params->grease_quic_bit) {
		TP_ENCODE_VARINT(QUIC_TP_GREASE_QUIC_BIT);
		TP_ENCODE_VARINT(0);  /* Zero-length value */
	}

#undef TP_CHECK_SPACE
#undef TP_ENCODE_VARINT
#undef TP_COPY
#undef TP_WRITE_BYTE

	*out_len = p - buf;
	return 0;
}

/*
 * QUIC Transport Parameters decoding
 */
static int tquic_decode_transport_params(const u8 *buf, u32 buf_len,
					 struct tquic_hs_transport_params *params,
					 bool is_server)
{
	const u8 *p = buf;
	const u8 *end = buf + buf_len;
	u64 param_id, param_len, val;
	u32 vlen;
	int ret;

	memset(params, 0, sizeof(*params));

	/* Set defaults */
	params->max_udp_payload_size = 65527;
	params->ack_delay_exponent = 3;
	params->max_ack_delay = 25;
	params->active_conn_id_limit = 2;

	while (p < end) {
		ret = hs_varint_decode(p, end - p, &param_id, &vlen);
		if (ret < 0)
			return ret;
		p += vlen;

		ret = hs_varint_decode(p, end - p, &param_len, &vlen);
		if (ret < 0)
			return ret;
		p += vlen;

		if (p + param_len > end)
			return -EINVAL;

		switch (param_id) {
		case QUIC_TP_ORIGINAL_DCID:
			if (param_len > TQUIC_MAX_CID_LEN)
				return -EINVAL;
			memcpy(params->original_dcid, p, param_len);
			params->original_dcid_len = param_len;
			break;

		case QUIC_TP_MAX_IDLE_TIMEOUT:
			ret = hs_varint_decode(p, param_len, &val, &vlen);
			if (ret < 0)
				return ret;
			params->max_idle_timeout = val;
			break;

		case QUIC_TP_STATELESS_RESET_TOKEN:
			if (param_len != 16)
				return -EINVAL;
			memcpy(params->stateless_reset_token, p, 16);
			params->has_stateless_reset_token = true;
			break;

		case QUIC_TP_MAX_UDP_PAYLOAD_SIZE:
			ret = hs_varint_decode(p, param_len, &val, &vlen);
			if (ret < 0)
				return ret;
			if (val < 1200)
				return -EINVAL;
			params->max_udp_payload_size = val;
			break;

		case QUIC_TP_INITIAL_MAX_DATA:
			ret = hs_varint_decode(p, param_len, &val, &vlen);
			if (ret < 0)
				return ret;
			params->initial_max_data = val;
			break;

		case QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL:
			ret = hs_varint_decode(p, param_len, &val, &vlen);
			if (ret < 0)
				return ret;
			params->initial_max_stream_data_bidi_local = val;
			break;

		case QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE:
			ret = hs_varint_decode(p, param_len, &val, &vlen);
			if (ret < 0)
				return ret;
			params->initial_max_stream_data_bidi_remote = val;
			break;

		case QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI:
			ret = hs_varint_decode(p, param_len, &val, &vlen);
			if (ret < 0)
				return ret;
			params->initial_max_stream_data_uni = val;
			break;

		case QUIC_TP_INITIAL_MAX_STREAMS_BIDI:
			ret = hs_varint_decode(p, param_len, &val, &vlen);
			if (ret < 0)
				return ret;
			params->initial_max_streams_bidi = val;
			break;

		case QUIC_TP_INITIAL_MAX_STREAMS_UNI:
			ret = hs_varint_decode(p, param_len, &val, &vlen);
			if (ret < 0)
				return ret;
			params->initial_max_streams_uni = val;
			break;

		case QUIC_TP_ACK_DELAY_EXPONENT:
			if (param_len < 1)
				return -EINVAL;
			if (p[0] > 20)
				return -EINVAL;
			params->ack_delay_exponent = p[0];
			break;

		case QUIC_TP_MAX_ACK_DELAY:
			ret = hs_varint_decode(p, param_len, &val, &vlen);
			if (ret < 0)
				return ret;
			if (val >= 16384)
				return -EINVAL;
			params->max_ack_delay = val;
			break;

		case QUIC_TP_DISABLE_ACTIVE_MIGRATION:
			params->disable_active_migration = true;
			break;

		case QUIC_TP_ACTIVE_CONN_ID_LIMIT:
			ret = hs_varint_decode(p, param_len, &val, &vlen);
			if (ret < 0)
				return ret;
			if (val < 2)
				return -EINVAL;
			params->active_conn_id_limit = val;
			break;

		case QUIC_TP_INITIAL_SCID:
			if (param_len > TQUIC_MAX_CID_LEN)
				return -EINVAL;
			memcpy(params->initial_scid, p, param_len);
			params->initial_scid_len = param_len;
			break;

		case QUIC_TP_RETRY_SCID:
			if (param_len > TQUIC_MAX_CID_LEN)
				return -EINVAL;
			memcpy(params->retry_scid, p, param_len);
			params->retry_scid_len = param_len;
			params->has_retry_scid = true;
			break;

		case QUIC_TP_MAX_DATAGRAM_FRAME_SIZE:
			ret = hs_varint_decode(p, param_len, &val, &vlen);
			if (ret < 0)
				return ret;
			params->max_datagram_frame_size = val;
			break;

		case QUIC_TP_GREASE_QUIC_BIT:
			params->grease_quic_bit = true;
			break;

		default:
			/* Unknown parameters are ignored (for extensibility) */
			break;
		}

		p += param_len;
	}

	return 0;
}

/*
 * HKDF-Extract
 */
static int tquic_hkdf_extract(struct crypto_shash *hmac,
			      const u8 *salt, u32 salt_len,
			      const u8 *ikm, u32 ikm_len,
			      u8 *prk, u32 prk_len)
{
	SHASH_DESC_ON_STACK(desc, hmac);
	int ret;

	desc->tfm = hmac;

	ret = crypto_shash_setkey(hmac, salt, salt_len);
	if (ret)
		return ret;

	ret = crypto_shash_init(desc);
	if (ret)
		return ret;

	ret = crypto_shash_update(desc, ikm, ikm_len);
	if (ret)
		return ret;

	return crypto_shash_final(desc, prk);
}

/*
 * HKDF-Expand-Label for TLS 1.3
 */
static int tquic_hs_hkdf_expand_label(struct tquic_handshake *hs,
				      const u8 *secret, u32 secret_len,
				      const char *label,
				      const u8 *context, u32 context_len,
				      u8 *out, u32 out_len)
{
	u8 hkdf_label[512];
	u8 *p = hkdf_label;
	u32 label_len = strlen(label);
	u32 total_label_len = 6 + label_len;  /* "tls13 " + label */
	SHASH_DESC_ON_STACK(desc, hs->hmac);
	u8 t[64];
	int ret;
	u32 i, n, hash_len;

	hash_len = crypto_shash_digestsize(hs->hmac);

	/* HkdfLabel structure */
	*p++ = (out_len >> 8) & 0xff;
	*p++ = out_len & 0xff;
	*p++ = total_label_len;
	memcpy(p, "tls13 ", 6);
	p += 6;
	memcpy(p, label, label_len);
	p += label_len;
	*p++ = context_len;
	if (context_len > 0) {
		memcpy(p, context, context_len);
		p += context_len;
	}

	desc->tfm = hs->hmac;

	/* HKDF-Expand */
	n = (out_len + hash_len - 1) / hash_len;

	for (i = 0; i < n; i++) {
		u8 counter = i + 1; /* RFC 5869: counter is 1-based */

		ret = crypto_shash_setkey(hs->hmac, secret, secret_len);
		if (ret)
			goto out_zeroize;

		ret = crypto_shash_init(desc);
		if (ret)
			goto out_zeroize;

		if (i > 0) {
			ret = crypto_shash_update(desc, t, hash_len);
			if (ret)
				goto out_zeroize;
		}

		ret = crypto_shash_update(desc, hkdf_label, p - hkdf_label);
		if (ret)
			goto out_zeroize;

		ret = crypto_shash_update(desc, &counter, 1);
		if (ret)
			goto out_zeroize;

		ret = crypto_shash_final(desc, t);
		if (ret)
			goto out_zeroize;

		memcpy(out + i * hash_len, t,
		       min_t(u32, hash_len, out_len - i * hash_len));
	}

	ret = 0;

out_zeroize:
	memzero_explicit(t, sizeof(t));
	return ret;
}

/*
 * Derive-Secret for TLS 1.3 key schedule
 */
static int tquic_hs_derive_secret(struct tquic_handshake *hs,
				  const u8 *secret, const char *label,
				  const u8 *context, u32 context_len,
				  u8 *out, u32 out_len)
{
	return tquic_hs_hkdf_expand_label(hs, secret, hs->hash_len,
					  label, context, context_len,
					  out, out_len);
}

/*
 * Update transcript hash
 */
/* Maximum transcript size: 256 KB should be more than enough for any
 * TLS 1.3 handshake (typical is a few KB). This prevents unbounded
 * memory growth from malicious or malformed handshake data.
 */
#define TQUIC_MAX_TRANSCRIPT_SIZE	(256 * 1024)

static int tquic_hs_update_transcript(struct tquic_handshake *hs,
				      const u8 *data, u32 len)
{
	u32 new_len;
	u8 *new_buf;

	new_len = hs->transcript_len + len;

	/* Check for overflow and enforce maximum transcript size */
	if (new_len < hs->transcript_len || new_len > TQUIC_MAX_TRANSCRIPT_SIZE) {
		pr_warn("tquic_hs: transcript size overflow (%u + %u)\n",
			hs->transcript_len, len);
		return -EOVERFLOW;
	}

	if (new_len > hs->transcript_alloc) {
		u32 new_alloc = max(new_len * 2, 4096U);

		new_buf = krealloc(hs->transcript, new_alloc, GFP_KERNEL);
		if (!new_buf)
			return -ENOMEM;

		hs->transcript = new_buf;
		hs->transcript_alloc = new_alloc;
	}

	memcpy(hs->transcript + hs->transcript_len, data, len);
	hs->transcript_len = new_len;

	return 0;
}

/*
 * Compute transcript hash
 */
static int tquic_hs_transcript_hash(struct tquic_handshake *hs,
				    u8 *out, u32 *out_len)
{
	SHASH_DESC_ON_STACK(desc, hs->hash_tfm);
	int ret;

	desc->tfm = hs->hash_tfm;

	ret = crypto_shash_init(desc);
	if (ret)
		return ret;

	ret = crypto_shash_update(desc, hs->transcript, hs->transcript_len);
	if (ret)
		return ret;

	ret = crypto_shash_final(desc, out);
	if (ret)
		return ret;

	*out_len = crypto_shash_digestsize(hs->hash_tfm);
	return 0;
}

/*
 * TLS 1.3 Key Schedule - derive early secrets for 0-RTT
 */
static int __maybe_unused tquic_hs_derive_early_secrets(struct tquic_handshake *hs,
							const u8 *psk, u32 psk_len)
{
	u8 zero_salt[TLS_SECRET_MAX_LEN] = {0};
	u8 transcript_hash[TLS_SECRET_MAX_LEN];
	u32 hash_len;
	int ret;

	hash_len = hs->hash_len;

	/* Early Secret = HKDF-Extract(0, PSK) */
	ret = tquic_hkdf_extract(hs->hmac, zero_salt, hash_len,
				 psk, psk_len, hs->early_secret, hash_len);
	if (ret)
		return ret;

	/* Get transcript hash up to ClientHello */
	ret = tquic_hs_transcript_hash(hs, transcript_hash, &hash_len);
	if (ret)
		return ret;

	/* Derive binder key if using PSK */
	if (psk && psk_len > 0) {
		u8 binder_key[TLS_SECRET_MAX_LEN];

		/* ext binder or res binder depending on external PSK or resumption */
		ret = tquic_hs_derive_secret(hs, hs->early_secret,
					     "ext binder", NULL, 0,
					     binder_key, hash_len);
		memzero_explicit(binder_key, sizeof(binder_key));
		if (ret)
			return ret;
	}

	return 0;
}

/*
 * TLS 1.3 Key Schedule - derive handshake secrets
 */
static int tquic_hs_derive_handshake_secrets(struct tquic_handshake *hs)
{
	u8 derived[TLS_SECRET_MAX_LEN];
	u8 transcript_hash[TLS_SECRET_MAX_LEN];
	u32 hash_len;
	int ret;

	hash_len = hs->hash_len;

	/* Compute empty hash */
	ret = tquic_hs_derive_secret(hs, hs->early_secret, "derived",
				     NULL, 0, derived, hash_len);
	if (ret)
		return ret;

	/* Handshake Secret = HKDF-Extract(derived, shared_secret) */
	ret = tquic_hkdf_extract(hs->hmac, derived, hash_len,
				 hs->shared_secret, hs->shared_secret_len,
				 hs->handshake_secret, hash_len);
	if (ret)
		return ret;

	/* Get transcript hash */
	ret = tquic_hs_transcript_hash(hs, transcript_hash, &hash_len);
	if (ret)
		return ret;

	/* client_handshake_traffic_secret */
	ret = tquic_hs_derive_secret(hs, hs->handshake_secret,
				     "c hs traffic", transcript_hash, hash_len,
				     hs->client_handshake_secret, hash_len);
	if (ret)
		return ret;

	/* server_handshake_traffic_secret */
	ret = tquic_hs_derive_secret(hs, hs->handshake_secret,
				     "s hs traffic", transcript_hash, hash_len,
				     hs->server_handshake_secret, hash_len);
	if (ret)
		return ret;

	/* Derive finished keys */
	ret = tquic_hs_hkdf_expand_label(hs, hs->client_handshake_secret, hash_len,
					 "finished", NULL, 0,
					 hs->client_finished_key, hash_len);
	if (ret)
		return ret;

	ret = tquic_hs_hkdf_expand_label(hs, hs->server_handshake_secret, hash_len,
					 "finished", NULL, 0,
					 hs->server_finished_key, hash_len);
	if (ret)
		return ret;

	return 0;
}

/*
 * TLS 1.3 Key Schedule - derive application secrets
 */
static int tquic_hs_derive_app_secrets(struct tquic_handshake *hs)
{
	u8 derived[TLS_SECRET_MAX_LEN];
	u8 transcript_hash[TLS_SECRET_MAX_LEN];
	u8 zero_ikm[TLS_SECRET_MAX_LEN] = {0};
	u32 hash_len;
	int ret;

	hash_len = hs->hash_len;

	/* Derive from handshake secret */
	ret = tquic_hs_derive_secret(hs, hs->handshake_secret, "derived",
				     NULL, 0, derived, hash_len);
	if (ret)
		return ret;

	/* Master Secret = HKDF-Extract(derived, 0) */
	ret = tquic_hkdf_extract(hs->hmac, derived, hash_len,
				 zero_ikm, hash_len,
				 hs->master_secret, hash_len);
	if (ret)
		return ret;

	/* Get transcript hash */
	ret = tquic_hs_transcript_hash(hs, transcript_hash, &hash_len);
	if (ret)
		return ret;

	/* client_application_traffic_secret_0 */
	ret = tquic_hs_derive_secret(hs, hs->master_secret,
				     "c ap traffic", transcript_hash, hash_len,
				     hs->client_app_secret, hash_len);
	if (ret)
		return ret;

	/* server_application_traffic_secret_0 */
	ret = tquic_hs_derive_secret(hs, hs->master_secret,
				     "s ap traffic", transcript_hash, hash_len,
				     hs->server_app_secret, hash_len);
	if (ret)
		return ret;

	/* exporter_master_secret */
	ret = tquic_hs_derive_secret(hs, hs->master_secret,
				     "exp master", transcript_hash, hash_len,
				     hs->exporter_secret, hash_len);
	if (ret)
		return ret;

	return 0;
}

/*
 * Derive resumption master secret (after receiving client Finished)
 */
static int tquic_hs_derive_resumption_secret(struct tquic_handshake *hs)
{
	u8 transcript_hash[TLS_SECRET_MAX_LEN];
	u32 hash_len;
	int ret;

	hash_len = hs->hash_len;

	/* Get transcript hash after client Finished */
	ret = tquic_hs_transcript_hash(hs, transcript_hash, &hash_len);
	if (ret)
		return ret;

	/* resumption_master_secret */
	ret = tquic_hs_derive_secret(hs, hs->master_secret,
				     "res master", transcript_hash, hash_len,
				     hs->resumption_secret, hash_len);
	if (ret)
		return ret;

	return 0;
}

/*
 * Build extensions for ClientHello
 */
static int tquic_hs_build_ch_extensions(struct tquic_handshake *hs,
					u8 *buf, u32 buf_len, u32 *out_len)
{
	u8 *p = buf;
	u8 *ext_len_ptr;
	u8 transport_params[1024];
	u32 tp_len;
	int ret;

	ext_len_ptr = p;
	p += 2;  /* Extension length placeholder */

	/* Supported Versions extension */
	*p++ = (TLS_EXT_SUPPORTED_VERSIONS >> 8) & 0xff;
	*p++ = TLS_EXT_SUPPORTED_VERSIONS & 0xff;
	*p++ = 0;
	*p++ = 3;  /* Extension data length */
	*p++ = 2;  /* Supported versions list length */
	*p++ = (TLS_VERSION_13 >> 8) & 0xff;
	*p++ = TLS_VERSION_13 & 0xff;

	/* Supported Groups extension */
	*p++ = (TLS_EXT_SUPPORTED_GROUPS >> 8) & 0xff;
	*p++ = TLS_EXT_SUPPORTED_GROUPS & 0xff;
	*p++ = 0;
	*p++ = 4;  /* Extension data length */
	*p++ = 0;
	*p++ = 2;  /* Groups list length */
	*p++ = (TLS_GROUP_X25519 >> 8) & 0xff;
	*p++ = TLS_GROUP_X25519 & 0xff;

	/* Signature Algorithms extension */
	*p++ = (TLS_EXT_SIGNATURE_ALGORITHMS >> 8) & 0xff;
	*p++ = TLS_EXT_SIGNATURE_ALGORITHMS & 0xff;
	*p++ = 0;
	*p++ = 8;  /* Extension data length */
	*p++ = 0;
	*p++ = 6;  /* Algorithms list length */
	*p++ = (TLS_SIG_ECDSA_SECP256R1_SHA256 >> 8) & 0xff;
	*p++ = TLS_SIG_ECDSA_SECP256R1_SHA256 & 0xff;
	*p++ = (TLS_SIG_RSA_PSS_RSAE_SHA256 >> 8) & 0xff;
	*p++ = TLS_SIG_RSA_PSS_RSAE_SHA256 & 0xff;
	*p++ = (TLS_SIG_RSA_PKCS1_SHA256 >> 8) & 0xff;
	*p++ = TLS_SIG_RSA_PKCS1_SHA256 & 0xff;

	/* Key Share extension */
	*p++ = (TLS_EXT_KEY_SHARE >> 8) & 0xff;
	*p++ = TLS_EXT_KEY_SHARE & 0xff;
	*p++ = 0;
	*p++ = 36;  /* Extension data length for X25519 */
	*p++ = 0;
	*p++ = 34;  /* Key shares list length */
	*p++ = (TLS_GROUP_X25519 >> 8) & 0xff;
	*p++ = TLS_GROUP_X25519 & 0xff;
	*p++ = 0;
	*p++ = 32;  /* Key exchange length */
	memcpy(p, hs->key_share.public_key, 32);
	p += 32;

	/* PSK Key Exchange Modes extension */
	*p++ = (TLS_EXT_PSK_KEY_EXCHANGE_MODES >> 8) & 0xff;
	*p++ = TLS_EXT_PSK_KEY_EXCHANGE_MODES & 0xff;
	*p++ = 0;
	*p++ = 2;  /* Extension data length */
	*p++ = 1;  /* Modes list length */
	*p++ = TLS_PSK_DHE_KE;  /* PSK with (EC)DHE key establishment */

	/* ALPN extension */
	if (hs->alpn_count > 0) {
		u32 alpn_total_len = 0;
		u32 i;

		for (i = 0; i < hs->alpn_count; i++)
			alpn_total_len += 1 + strlen(hs->alpn_list[i]);

		*p++ = (TLS_EXT_ALPN >> 8) & 0xff;
		*p++ = TLS_EXT_ALPN & 0xff;
		*p++ = ((alpn_total_len + 2) >> 8) & 0xff;
		*p++ = (alpn_total_len + 2) & 0xff;
		*p++ = (alpn_total_len >> 8) & 0xff;
		*p++ = alpn_total_len & 0xff;

		for (i = 0; i < hs->alpn_count; i++) {
			u32 len = strlen(hs->alpn_list[i]);
			*p++ = len;
			memcpy(p, hs->alpn_list[i], len);
			p += len;
		}
	}

	/* SNI extension */
	if (hs->sni && hs->sni_len > 0) {
		*p++ = (TLS_EXT_SERVER_NAME >> 8) & 0xff;
		*p++ = TLS_EXT_SERVER_NAME & 0xff;
		*p++ = ((hs->sni_len + 5) >> 8) & 0xff;
		*p++ = (hs->sni_len + 5) & 0xff;
		*p++ = ((hs->sni_len + 3) >> 8) & 0xff;
		*p++ = (hs->sni_len + 3) & 0xff;
		*p++ = 0;  /* Host name type */
		*p++ = (hs->sni_len >> 8) & 0xff;
		*p++ = hs->sni_len & 0xff;
		memcpy(p, hs->sni, hs->sni_len);
		p += hs->sni_len;
	}

	/* QUIC Transport Parameters extension */
	ret = tquic_encode_transport_params(&hs->local_params,
					    transport_params,
					    sizeof(transport_params),
					    &tp_len, false);
	if (ret < 0)
		return ret;

	*p++ = (TLS_EXT_QUIC_TRANSPORT_PARAMS >> 8) & 0xff;
	*p++ = TLS_EXT_QUIC_TRANSPORT_PARAMS & 0xff;
	*p++ = (tp_len >> 8) & 0xff;
	*p++ = tp_len & 0xff;
	memcpy(p, transport_params, tp_len);
	p += tp_len;

	/* Early Data indication (if we have PSK) */
	if (hs->session_ticket && hs->early_data_offered) {
		*p++ = (TLS_EXT_EARLY_DATA >> 8) & 0xff;
		*p++ = TLS_EXT_EARLY_DATA & 0xff;
		*p++ = 0;
		*p++ = 0;  /* Empty extension */
	}

	/* PSK extension (must be last) */
	if (hs->psk_count > 0) {
		u32 identities_len = 0;
		u32 binders_len = 0;
		u32 i;

		for (i = 0; i < hs->psk_count; i++) {
			identities_len += 2 + hs->psk_identities[i].identity_len + 4;
			binders_len += 1 + hs->hash_len;
		}

		*p++ = (TLS_EXT_PRE_SHARED_KEY >> 8) & 0xff;
		*p++ = TLS_EXT_PRE_SHARED_KEY & 0xff;
		*p++ = ((identities_len + binders_len + 4) >> 8) & 0xff;
		*p++ = (identities_len + binders_len + 4) & 0xff;

		/* Identities */
		*p++ = (identities_len >> 8) & 0xff;
		*p++ = identities_len & 0xff;

		for (i = 0; i < hs->psk_count; i++) {
			struct tquic_psk_identity *psk = &hs->psk_identities[i];
			*p++ = (psk->identity_len >> 8) & 0xff;
			*p++ = psk->identity_len & 0xff;
			memcpy(p, psk->identity, psk->identity_len);
			p += psk->identity_len;
			*p++ = (psk->obfuscated_ticket_age >> 24) & 0xff;
			*p++ = (psk->obfuscated_ticket_age >> 16) & 0xff;
			*p++ = (psk->obfuscated_ticket_age >> 8) & 0xff;
			*p++ = psk->obfuscated_ticket_age & 0xff;
		}

		/* Binders */
		*p++ = (binders_len >> 8) & 0xff;
		*p++ = binders_len & 0xff;

		for (i = 0; i < hs->psk_count; i++) {
			*p++ = hs->hash_len;
			memcpy(p, hs->psk_identities[i].binder, hs->hash_len);
			p += hs->hash_len;
		}
	}

	/* Fill in extension length */
	ext_len_ptr[0] = ((p - ext_len_ptr - 2) >> 8) & 0xff;
	ext_len_ptr[1] = (p - ext_len_ptr - 2) & 0xff;

	*out_len = p - buf;
	return 0;
}

/*
 * Generate ClientHello message
 */
int tquic_hs_generate_client_hello(struct tquic_handshake *hs,
				   u8 *buf, u32 buf_len, u32 *out_len)
{
	u8 *p = buf;
	u8 *msg_len_ptr;
	u8 *extensions;
	u32 ext_len;
	int ret;

	/* Allocate extensions buffer dynamically to reduce stack usage */
	extensions = kzalloc(2048, GFP_KERNEL);
	if (!extensions)
		return -ENOMEM;

	/* Generate random */
	get_random_bytes(hs->client_random, TLS_RANDOM_LEN);

	/* Generate X25519 key pair */
	hs->key_share.group = TLS_GROUP_X25519;
	hs->key_share.public_key = kzalloc(32, GFP_KERNEL);
	hs->key_share.private_key = kzalloc(32, GFP_KERNEL);
	if (!hs->key_share.public_key || !hs->key_share.private_key) {
		kfree(extensions);
		return -ENOMEM;
	}

	get_random_bytes(hs->key_share.private_key, 32);
	hs->key_share.private_key_len = 32;
	hs->key_share.public_key_len = 32;

	/* Clamp private key for X25519 */
	hs->key_share.private_key[0] &= 248;
	hs->key_share.private_key[31] &= 127;
	hs->key_share.private_key[31] |= 64;

	/*
	 * Compute public key from private key using X25519 base point.
	 * Uses the kernel's curve25519 implementation.
	 */
	if (!curve25519_generate_public(hs->key_share.public_key,
					hs->key_share.private_key)) {
		pr_warn("tquic_hs: X25519 public key generation failed\n");
		kfree(extensions);
		return -EINVAL;
	}

	/* Build extensions */
	ret = tquic_hs_build_ch_extensions(hs, extensions, 2048, &ext_len);
	if (ret < 0) {
		kfree(extensions);
		return ret;
	}

	/* Handshake header */
	*p++ = TLS_HS_CLIENT_HELLO;
	msg_len_ptr = p;
	p += 3;  /* Message length placeholder */

	/* Legacy version */
	*p++ = (TLS_LEGACY_VERSION >> 8) & 0xff;
	*p++ = TLS_LEGACY_VERSION & 0xff;

	/* Random */
	memcpy(p, hs->client_random, TLS_RANDOM_LEN);
	p += TLS_RANDOM_LEN;

	/* Legacy session ID */
	if (hs->session_id_len == 0) {
		get_random_bytes(hs->session_id, 32);
		hs->session_id_len = 32;
	}
	*p++ = hs->session_id_len;
	memcpy(p, hs->session_id, hs->session_id_len);
	p += hs->session_id_len;

	/* Cipher suites */
	*p++ = 0;
	*p++ = 6;  /* 3 cipher suites * 2 bytes */
	*p++ = (TLS_AES_128_GCM_SHA256 >> 8) & 0xff;
	*p++ = TLS_AES_128_GCM_SHA256 & 0xff;
	*p++ = (TLS_AES_256_GCM_SHA384 >> 8) & 0xff;
	*p++ = TLS_AES_256_GCM_SHA384 & 0xff;
	*p++ = (TLS_CHACHA20_POLY1305_SHA256 >> 8) & 0xff;
	*p++ = TLS_CHACHA20_POLY1305_SHA256 & 0xff;

	/* Legacy compression methods */
	*p++ = 1;  /* Length */
	*p++ = 0;  /* null compression */

	/* Extensions */
	memcpy(p, extensions, ext_len);
	p += ext_len;

	/* Free extensions buffer - no longer needed after memcpy */
	kfree(extensions);

	/* Fill in message length */
	msg_len_ptr[0] = ((p - msg_len_ptr - 3) >> 16) & 0xff;
	msg_len_ptr[1] = ((p - msg_len_ptr - 3) >> 8) & 0xff;
	msg_len_ptr[2] = (p - msg_len_ptr - 3) & 0xff;

	*out_len = p - buf;

	/* Update transcript */
	ret = tquic_hs_update_transcript(hs, buf, *out_len);
	if (ret < 0)
		return ret;

	hs->state = TQUIC_HS_WAIT_SH;

	pr_debug("tquic_hs: generated ClientHello (%u bytes)\n", *out_len);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_hs_generate_client_hello);

/*
 * Process ServerHello message
 */
int tquic_hs_process_server_hello(struct tquic_handshake *hs,
				  const u8 *data, u32 len)
{
	const u8 *p = data;
	const u8 *end = data + len;
	u8 msg_type;
	u32 msg_len;
	u16 version;
	u16 cipher_suite;
	u8 session_id_len;
	u8 compression;
	u16 ext_len;
	bool found_supported_versions = false;
	bool found_key_share = false;
	int ret;

	if (hs->state != TQUIC_HS_WAIT_SH)
		return -EINVAL;

	/* Parse handshake header */
	if (len < 4)
		return -EINVAL;

	msg_type = *p++;
	if (msg_type != TLS_HS_SERVER_HELLO)
		return -EINVAL;

	msg_len = (p[0] << 16) | (p[1] << 8) | p[2];
	p += 3;

	if (p + msg_len > end)
		return -EINVAL;

	/* Legacy version */
	version = (p[0] << 8) | p[1];
	p += 2;

	/* Server random */
	if (p + TLS_RANDOM_LEN > end)
		return -EINVAL;
	memcpy(hs->server_random, p, TLS_RANDOM_LEN);
	p += TLS_RANDOM_LEN;

	/* Check for HelloRetryRequest magic */
	/* SHA-256 hash of "HelloRetryRequest" */
	static const u8 hrr_random[32] = {
		0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11,
		0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
		0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e,
		0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c
	};

	if (memcmp(hs->server_random, hrr_random, 32) == 0) {
		/* HelloRetryRequest - need to restart with new parameters */
		pr_debug("tquic_hs: received HelloRetryRequest\n");
		return -EAGAIN;  /* Signal need for retry */
	}

	/* Session ID */
	session_id_len = *p++;
	if (session_id_len > TLS_SESSION_ID_MAX_LEN)
		return -EINVAL;
	if (p + session_id_len > end)
		return -EINVAL;
	/* Verify session ID echoed back */
	if (session_id_len != hs->session_id_len ||
	    memcmp(p, hs->session_id, session_id_len) != 0) {
		pr_warn("tquic_hs: session ID mismatch\n");
		return -EINVAL;
	}
	p += session_id_len;

	/* Cipher suite */
	cipher_suite = (p[0] << 8) | p[1];
	p += 2;

	/* Validate cipher suite */
	if (cipher_suite != TLS_AES_128_GCM_SHA256 &&
	    cipher_suite != TLS_AES_256_GCM_SHA384 &&
	    cipher_suite != TLS_CHACHA20_POLY1305_SHA256) {
		pr_warn("tquic_hs: unsupported cipher suite 0x%04x\n", cipher_suite);
		return -EINVAL;
	}
	hs->cipher_suite = cipher_suite;

	/* Set hash length based on cipher suite */
	if (cipher_suite == TLS_AES_256_GCM_SHA384)
		hs->hash_len = 48;
	else
		hs->hash_len = 32;

	/* Compression (must be null) */
	compression = *p++;
	if (compression != 0) {
		pr_warn("tquic_hs: non-null compression\n");
		return -EINVAL;
	}

	/* Extensions */
	if (p + 2 > end)
		return -EINVAL;
	ext_len = (p[0] << 8) | p[1];
	p += 2;

	if (p + ext_len > end)
		return -EINVAL;

	/* Parse extensions */
	while (p < data + 4 + msg_len) {
		u16 ext_type;
		u16 ext_data_len;

		if (p + 4 > end)
			break;

		ext_type = (p[0] << 8) | p[1];
		ext_data_len = (p[2] << 8) | p[3];
		p += 4;

		if (p + ext_data_len > end)
			return -EINVAL;

		switch (ext_type) {
		case TLS_EXT_SUPPORTED_VERSIONS:
			if (ext_data_len < 2)
				return -EINVAL;
			version = (p[0] << 8) | p[1];
			if (version != TLS_VERSION_13) {
				pr_warn("tquic_hs: unsupported version 0x%04x\n", version);
				return -EINVAL;
			}
			found_supported_versions = true;
			break;

		case TLS_EXT_KEY_SHARE:
			if (ext_data_len < 4)
				return -EINVAL;
			{
				u16 group = (p[0] << 8) | p[1];
				u16 key_len = (p[2] << 8) | p[3];

				if (group != hs->key_share.group) {
					pr_warn("tquic_hs: key share group mismatch\n");
					return -EINVAL;
				}

				if (ext_data_len < 4 + key_len)
					return -EINVAL;

				/*
				 * Store peer's public key and compute shared secret
				 * using X25519 (Curve25519) key exchange.
				 */
				if (key_len != CURVE25519_KEY_SIZE) {
					pr_warn("tquic_hs: invalid X25519 key length\n");
					return -EINVAL;
				}

				/* Compute shared secret: ECDH(our_private, peer_public) */
				if (!curve25519(hs->shared_secret,
					       hs->key_share.private_key,
					       p + 4)) {
					pr_warn("tquic_hs: X25519 key exchange failed\n");
					return -EINVAL;
				}
				hs->shared_secret_len = CURVE25519_KEY_SIZE;
			}
			found_key_share = true;
			break;

		case TLS_EXT_PRE_SHARED_KEY:
			if (ext_data_len < 2)
				return -EINVAL;
			hs->psk_selected = (p[0] << 8) | p[1];
			hs->using_psk = true;
			break;
		}

		p += ext_data_len;
	}

	if (!found_supported_versions) {
		pr_warn("tquic_hs: missing supported_versions extension\n");
		return -EINVAL;
	}

	if (!found_key_share && !hs->using_psk) {
		pr_warn("tquic_hs: missing key_share extension\n");
		return -EINVAL;
	}

	/* Update transcript */
	ret = tquic_hs_update_transcript(hs, data, len);
	if (ret < 0)
		return ret;

	/* Derive handshake secrets */
	ret = tquic_hs_derive_handshake_secrets(hs);
	if (ret < 0)
		return ret;

	hs->state = TQUIC_HS_WAIT_EE;

	pr_debug("tquic_hs: processed ServerHello, cipher=0x%04x\n", cipher_suite);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_hs_process_server_hello);

/*
 * Process EncryptedExtensions message
 */
int tquic_hs_process_encrypted_extensions(struct tquic_handshake *hs,
					  const u8 *data, u32 len)
{
	const u8 *p = data;
	const u8 *end = data + len;
	u8 msg_type;
	u32 msg_len;
	u16 ext_len;
	int ret;

	if (hs->state != TQUIC_HS_WAIT_EE)
		return -EINVAL;

	/* Parse handshake header */
	if (len < 4)
		return -EINVAL;

	msg_type = *p++;
	if (msg_type != TLS_HS_ENCRYPTED_EXTENSIONS)
		return -EINVAL;

	msg_len = (p[0] << 16) | (p[1] << 8) | p[2];
	p += 3;

	if (p + msg_len > end)
		return -EINVAL;

	/* Extensions length */
	if (p + 2 > end)
		return -EINVAL;
	ext_len = (p[0] << 8) | p[1];
	p += 2;

	if (p + ext_len > end)
		return -EINVAL;

	/* Parse extensions */
	while (p < data + 4 + msg_len) {
		u16 ext_type;
		u16 ext_data_len;

		if (p + 4 > end)
			break;

		ext_type = (p[0] << 8) | p[1];
		ext_data_len = (p[2] << 8) | p[3];
		p += 4;

		if (p + ext_data_len > end)
			return -EINVAL;

		switch (ext_type) {
		case TLS_EXT_ALPN:
			/* ALPN negotiation result */
			if (ext_data_len >= 3) {
				u16 list_len = (p[0] << 8) | p[1];
				u8 proto_len = p[2];

				if (list_len >= proto_len + 1 && proto_len > 0) {
					kfree(hs->alpn_selected);
					hs->alpn_selected = kmalloc(proto_len + 1, GFP_KERNEL);
					if (hs->alpn_selected) {
						memcpy(hs->alpn_selected, p + 3, proto_len);
						hs->alpn_selected[proto_len] = '\0';
						hs->alpn_len = proto_len;
					}
				}
			}
			break;

		case TLS_EXT_EARLY_DATA:
			hs->early_data_accepted = true;
			break;

		case TLS_EXT_QUIC_TRANSPORT_PARAMS:
			ret = tquic_decode_transport_params(p, ext_data_len,
							    &hs->peer_params, true);
			if (ret < 0) {
				pr_warn("tquic_hs: failed to decode transport params\n");
				return ret;
			}
			hs->params_received = true;
			break;
		}

		p += ext_data_len;
	}

	/* Update transcript */
	ret = tquic_hs_update_transcript(hs, data, len);
	if (ret < 0)
		return ret;

	/* Next state depends on whether PSK was used */
	if (hs->using_psk)
		hs->state = TQUIC_HS_WAIT_FINISHED;
	else
		hs->state = TQUIC_HS_WAIT_CERT_CR;

	pr_debug("tquic_hs: processed EncryptedExtensions\n");

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_hs_process_encrypted_extensions);

/*
 * Process Certificate message
 */
int tquic_hs_process_certificate(struct tquic_handshake *hs,
				 const u8 *data, u32 len)
{
	const u8 *p = data;
	const u8 *end = data + len;
	u8 msg_type;
	u32 msg_len;
	u8 cert_req_ctx_len;
	u32 certs_len;
	int ret;

	if (hs->state != TQUIC_HS_WAIT_CERT_CR && hs->state != TQUIC_HS_WAIT_CERT)
		return -EINVAL;

	/* Parse handshake header */
	if (len < 4)
		return -EINVAL;

	msg_type = *p++;
	if (msg_type != TLS_HS_CERTIFICATE)
		return -EINVAL;

	msg_len = (p[0] << 16) | (p[1] << 8) | p[2];
	p += 3;

	if (p + msg_len > end)
		return -EINVAL;

	/* Certificate request context (empty for server cert) */
	cert_req_ctx_len = *p++;
	if (cert_req_ctx_len > 0)
		p += cert_req_ctx_len;

	/* Certificate list length */
	if (p + 3 > end)
		return -EINVAL;
	certs_len = (p[0] << 16) | (p[1] << 8) | p[2];
	p += 3;

	if (p + certs_len > end)
		return -EINVAL;

	/* Parse certificate entries */
	while (p < data + 4 + msg_len && certs_len > 0) {
		u32 cert_len;
		u16 ext_len;

		if (p + 3 > end)
			break;

		cert_len = (p[0] << 16) | (p[1] << 8) | p[2];
		p += 3;
		certs_len -= 3;

		if (p + cert_len > end || cert_len > certs_len)
			return -EINVAL;

		/* Store first certificate (end-entity) */
		if (!hs->peer_cert && cert_len > 0) {
			hs->peer_cert = kmalloc(cert_len, GFP_KERNEL);
			if (!hs->peer_cert)
				return -ENOMEM;
			memcpy(hs->peer_cert, p, cert_len);
			hs->peer_cert_len = cert_len;
		}

		p += cert_len;
		certs_len -= cert_len;

		/* Certificate extensions */
		if (p + 2 > end)
			break;
		ext_len = (p[0] << 8) | p[1];
		p += 2;
		certs_len -= 2;

		if (ext_len > certs_len)
			return -EINVAL;

		p += ext_len;
		certs_len -= ext_len;
	}

	/* Update transcript */
	ret = tquic_hs_update_transcript(hs, data, len);
	if (ret < 0)
		return ret;

	hs->state = TQUIC_HS_WAIT_CV;

	pr_debug("tquic_hs: processed Certificate (%u bytes)\n", hs->peer_cert_len);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_hs_process_certificate);

/*
 * MGF1 - Mask Generation Function (RFC 8017 Appendix B.2.1)
 * Used for RSASSA-PSS signature verification.
 *
 * @hash_alg: Hash algorithm name (e.g., "sha256")
 * @seed: Seed value
 * @seed_len: Length of seed
 * @mask: Output buffer for generated mask
 * @mask_len: Desired length of mask
 *
 * Returns 0 on success, negative error code on failure.
 */
static int tquic_mgf1(const char *hash_alg, const u8 *seed, u32 seed_len,
		      u8 *mask, u32 mask_len)
{
	struct crypto_shash *hash_tfm;
	u32 hash_len;
	u32 counter = 0;
	u8 counter_be[4];
	u8 hash_out[64];  /* Max hash size (SHA-512) */
	u32 offset = 0;
	int err;

	hash_tfm = crypto_alloc_shash(hash_alg, 0, 0);
	if (IS_ERR(hash_tfm))
		return PTR_ERR(hash_tfm);

	hash_len = crypto_shash_digestsize(hash_tfm);

	while (offset < mask_len) {
		SHASH_DESC_ON_STACK(desc, hash_tfm);
		u32 copy_len;

		desc->tfm = hash_tfm;

		/* Counter in big-endian */
		counter_be[0] = (counter >> 24) & 0xff;
		counter_be[1] = (counter >> 16) & 0xff;
		counter_be[2] = (counter >> 8) & 0xff;
		counter_be[3] = counter & 0xff;

		/* Hash(seed || counter) per RFC 8017 B.2.1 */
		err = crypto_shash_init(desc);
		if (err)
			goto out;
		err = crypto_shash_update(desc, seed, seed_len);
		if (err)
			goto out;
		err = crypto_shash_update(desc, counter_be, 4);
		if (err)
			goto out;
		err = crypto_shash_final(desc, hash_out);
		shash_desc_zero(desc);
		if (err)
			goto out;

		/* Copy to mask buffer */
		copy_len = min(hash_len, mask_len - offset);
		memcpy(mask + offset, hash_out, copy_len);
		offset += copy_len;
		counter++;
	}
	err = 0;

out:
	crypto_free_shash(hash_tfm);
	return err;
}

/*
 * EMSA-PSS-VERIFY - PSS padding verification (RFC 8017 Section 9.1.2)
 * Used for RSASSA-PSS signature verification in TLS 1.3.
 *
 * @hash_alg: Hash algorithm name
 * @hash_len: Hash output length in bytes
 * @msg_hash: Hash of the message to verify
 * @em: Encoded message (output of RSA public key operation)
 * @em_len: Length of encoded message (key size in bytes)
 *
 * TLS 1.3 uses salt length equal to hash length.
 *
 * Returns 0 on success, -EKEYREJECTED if verification fails.
 */
static int tquic_emsa_pss_verify(const char *hash_alg, u32 hash_len,
				 const u8 *msg_hash, const u8 *em, u32 em_len)
{
	u8 *db_mask = NULL;
	u8 *db = NULL;
	u8 *m_prime = NULL;
	u8 h_prime[64];  /* Max hash size */
	struct crypto_shash *hash_tfm = NULL;
	u32 salt_len = hash_len;  /* TLS 1.3: sLen = hLen */
	u32 db_len;
	u32 ps_len;
	u32 i;
	int err = -EKEYREJECTED;

	/* Step 3: emLen must be at least hLen + sLen + 2 */
	if (em_len < hash_len + salt_len + 2) {
		pr_debug("tquic_pss: EM too short\n");
		return -EKEYREJECTED;
	}

	/* Step 4: Check rightmost byte is 0xbc */
	if (em[em_len - 1] != 0xbc) {
		pr_debug("tquic_pss: Invalid trailer byte 0x%02x (expected 0xbc)\n",
			 em[em_len - 1]);
		return -EKEYREJECTED;
	}

	db_len = em_len - hash_len - 1;

	/* Allocate working buffers */
	db_mask = kmalloc(db_len, GFP_KERNEL);
	db = kmalloc(db_len, GFP_KERNEL);
	m_prime = kmalloc(8 + hash_len + salt_len, GFP_KERNEL);
	if (!db_mask || !db || !m_prime) {
		err = -ENOMEM;
		goto out;
	}

	/* Step 5-6: maskedDB is leftmost (emLen - hLen - 1) bytes */
	/* Step 7: H is the next hLen bytes */
	/* maskedDB = em[0..db_len-1], H = em[db_len..db_len+hash_len-1] */

	/* Step 8: Generate dbMask = MGF1(H, emLen - hLen - 1) */
	err = tquic_mgf1(hash_alg, em + db_len, hash_len, db_mask, db_len);
	if (err) {
		pr_debug("tquic_pss: MGF1 failed: %d\n", err);
		goto out;
	}

	/* Step 9: DB = maskedDB XOR dbMask */
	for (i = 0; i < db_len; i++)
		db[i] = em[i] ^ db_mask[i];

	/* Step 10: Check leftmost 8*emLen - emBits bits are zero.
	 * For RSA keys, emBits = 8*emLen - 1, so we check the top bit.
	 * This MUST be a check, not a modification - reject invalid signatures.
	 */
	if (db[0] & 0x80) {
		pr_debug("tquic_pss: Invalid DB leading bit (must be 0)\n");
		err = -EKEYREJECTED;
		goto out;
	}

	/* Step 11: Check DB = PS || 0x01 || salt
	 * PS is (emLen - hLen - sLen - 2) zero bytes
	 */
	ps_len = db_len - salt_len - 1;
	for (i = 0; i < ps_len; i++) {
		if (db[i] != 0x00) {
			pr_debug("tquic_pss: Non-zero padding at position %u\n", i);
			err = -EKEYREJECTED;
			goto out;
		}
	}

	if (db[ps_len] != 0x01) {
		pr_debug("tquic_pss: Missing 0x01 separator at position %u\n", ps_len);
		err = -EKEYREJECTED;
		goto out;
	}

	/* Step 12: Salt is the rightmost sLen bytes of DB */
	/* salt = db[db_len - salt_len .. db_len - 1] */

	/* Step 13: M' = (0x)00 00 00 00 00 00 00 00 || mHash || salt */
	memset(m_prime, 0, 8);
	memcpy(m_prime + 8, msg_hash, hash_len);
	memcpy(m_prime + 8 + hash_len, db + db_len - salt_len, salt_len);

	/* Step 14: H' = Hash(M') */
	hash_tfm = crypto_alloc_shash(hash_alg, 0, 0);
	if (IS_ERR(hash_tfm)) {
		err = PTR_ERR(hash_tfm);
		hash_tfm = NULL;
		goto out;
	}

	{
		SHASH_DESC_ON_STACK(desc, hash_tfm);
		desc->tfm = hash_tfm;
		err = crypto_shash_digest(desc, m_prime, 8 + hash_len + salt_len,
					  h_prime);
		shash_desc_zero(desc);
	}

	if (err) {
		pr_debug("tquic_pss: Failed to compute H'\n");
		goto out;
	}

	/* Step 15: Compare H and H' */
	if (crypto_memneq(em + db_len, h_prime, hash_len)) {
		pr_debug("tquic_pss: H != H' - signature verification failed\n");
		err = -EKEYREJECTED;
		goto out;
	}

	pr_debug("tquic_pss: EMSA-PSS verification succeeded\n");
	err = 0;

out:
	if (hash_tfm)
		crypto_free_shash(hash_tfm);
	kfree(m_prime);
	kfree(db);
	kfree(db_mask);
	return err;
}

/*
 * Verify RSA-PSS signature (RSASSA-PSS per RFC 8017 Section 8.1.2)
 *
 * @pubkey_data: DER-encoded public key
 * @pubkey_len: Length of public key
 * @hash_alg: Hash algorithm name
 * @hash_len: Hash output length
 * @msg_hash: Hash of message being verified
 * @signature: Signature to verify
 * @sig_len: Length of signature
 *
 * Returns 0 on success, negative error on failure.
 */
static int tquic_verify_rsa_pss(const u8 *pubkey_data, u32 pubkey_len,
				const char *hash_alg, u32 hash_len,
				const u8 *msg_hash,
				const u8 *signature, u32 sig_len)
{
	struct crypto_akcipher *tfm = NULL;
	struct akcipher_request *req = NULL;
	struct scatterlist sg_in, sg_out;
	u8 *em = NULL;  /* Encoded message */
	u32 key_size;
	int err;
	DECLARE_CRYPTO_WAIT(wait);

	/* Allocate raw RSA cipher */
	tfm = crypto_alloc_akcipher("rsa", 0, 0);
	if (IS_ERR(tfm)) {
		err = PTR_ERR(tfm);
		pr_warn("tquic_pss: Failed to allocate RSA: %d\n", err);
		return err;
	}

	/* Set public key */
	err = crypto_akcipher_set_pub_key(tfm, pubkey_data, pubkey_len);
	if (err) {
		pr_warn("tquic_pss: Failed to set public key: %d\n", err);
		goto out_free_tfm;
	}

	/* Get key size */
	key_size = crypto_akcipher_maxsize(tfm);
	if (key_size == 0 || sig_len != key_size) {
		pr_warn("tquic_pss: Signature length %u != key size %u\n",
			sig_len, key_size);
		err = -EINVAL;
		goto out_free_tfm;
	}

	/* Allocate buffer for encoded message */
	em = kmalloc(key_size, GFP_KERNEL);
	if (!em) {
		err = -ENOMEM;
		goto out_free_tfm;
	}

	/* Allocate request */
	req = akcipher_request_alloc(tfm, GFP_KERNEL);
	if (!req) {
		err = -ENOMEM;
		goto out_free_em;
	}

	/* Set up scatter-gather for RSA public key operation (encrypt = verify) */
	sg_init_one(&sg_in, signature, sig_len);
	sg_init_one(&sg_out, em, key_size);

	akcipher_request_set_crypt(req, &sg_in, &sg_out, sig_len, key_size);
	akcipher_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				      crypto_req_done, &wait);

	/* Perform RSA public key operation: em = signature^e mod n */
	err = crypto_wait_req(crypto_akcipher_encrypt(req), &wait);
	if (err) {
		pr_warn("tquic_pss: RSA operation failed: %d\n", err);
		goto out_free_req;
	}

	/* Verify PSS padding */
	err = tquic_emsa_pss_verify(hash_alg, hash_len, msg_hash, em, key_size);

out_free_req:
	akcipher_request_free(req);
out_free_em:
	kfree(em);
out_free_tfm:
	crypto_free_akcipher(tfm);
	return err;
}

/*
 * Process CertificateVerify message
 */
int tquic_hs_process_certificate_verify(struct tquic_handshake *hs,
					const u8 *data, u32 len)
{
	const u8 *p = data;
	const u8 *end = data + len;
	u8 msg_type;
	u32 msg_len;
	u16 sig_alg;
	u16 sig_len;
	int ret;

	if (hs->state != TQUIC_HS_WAIT_CV)
		return -EINVAL;

	/* Parse handshake header */
	if (len < 4)
		return -EINVAL;

	msg_type = *p++;
	if (msg_type != TLS_HS_CERTIFICATE_VERIFY)
		return -EINVAL;

	msg_len = (p[0] << 16) | (p[1] << 8) | p[2];
	p += 3;

	if (p + msg_len > end)
		return -EINVAL;

	/* Signature algorithm */
	if (p + 2 > end)
		return -EINVAL;
	sig_alg = (p[0] << 8) | p[1];
	p += 2;

	/* Signature length */
	if (p + 2 > end)
		return -EINVAL;
	sig_len = (p[0] << 8) | p[1];
	p += 2;

	if (p + sig_len > end)
		return -EINVAL;

	/*
	 * Verify signature against transcript hash and certificate public key.
	 * The signature is over:
	 * - 64 spaces (0x20)
	 * - "TLS 1.3, server CertificateVerify" (or client variant)
	 * - 0x00
	 * - Transcript-Hash(CH..Certificate)
	 */
	{
		u8 content[200];
		u8 *cp = content;
		u8 transcript_hash[64];
		u8 content_hash[64];
		int hash_len;
		u32 content_len;
		u32 content_hash_len;
		struct tquic_x509_cert *cert = NULL;
		struct crypto_sig *sig_tfm = NULL;
		struct crypto_shash *hash_tfm = NULL;
		const char *hash_alg;
		const char *sig_alg_name;
		int err;

		/* Verify we have a peer certificate */
		if (!hs->peer_cert || hs->peer_cert_len == 0) {
			pr_warn("tquic_hs: CertificateVerify without peer certificate\n");
			return -EINVAL;
		}

		/* Build content to verify */
		memset(cp, 0x20, 64);  /* 64 spaces */
		cp += 64;
		memcpy(cp, "TLS 1.3, server CertificateVerify", 33);
		cp += 33;
		*cp++ = 0x00;

		/* Get transcript hash */
		{
			u32 hash_len_out;
			int ret = tquic_hs_transcript_hash(hs, transcript_hash,
							   &hash_len_out);
			if (ret < 0) {
				pr_warn("tquic_hs: Failed to get transcript hash\n");
				return -EINVAL;
			}
			hash_len = hash_len_out;
		}
		memcpy(cp, transcript_hash, hash_len);
		cp += hash_len;
		content_len = cp - content;

		/* Parse peer certificate to extract public key */
		cert = tquic_x509_cert_parse(hs->peer_cert, hs->peer_cert_len,
					     GFP_KERNEL);
		if (!cert) {
			pr_warn("tquic_hs: Failed to parse peer certificate\n");
			return -EINVAL;
		}

		/*
		 * Verify signature using kernel crypto API.
		 * Support RSA-PSS (0x0804, 0x0805, 0x0806) and
		 * ECDSA (0x0403, 0x0503, 0x0603) algorithms.
		 *
		 * RSA-PSS uses proper RSASSA-PSS per RFC 8017 Section 8.1.2.
		 * ECDSA uses kernel's native ECDSA verification.
		 */
		switch (sig_alg) {
		case 0x0804:  /* rsa_pss_rsae_sha256 */
			hash_alg = "sha256";
			content_hash_len = 32;
			sig_alg_name = NULL;  /* Use RSA-PSS path */
			break;
		case 0x0805:  /* rsa_pss_rsae_sha384 */
			hash_alg = "sha384";
			content_hash_len = 48;
			sig_alg_name = NULL;  /* Use RSA-PSS path */
			break;
		case 0x0806:  /* rsa_pss_rsae_sha512 */
			hash_alg = "sha512";
			content_hash_len = 64;
			sig_alg_name = NULL;  /* Use RSA-PSS path */
			break;
		case 0x0403:  /* ecdsa_secp256r1_sha256 */
			hash_alg = "sha256";
			sig_alg_name = "ecdsa-nist-p256";
			content_hash_len = 32;
			break;
		case 0x0503:  /* ecdsa_secp384r1_sha384 */
			hash_alg = "sha384";
			sig_alg_name = "ecdsa-nist-p384";
			content_hash_len = 48;
			break;
		case 0x0603:  /* ecdsa_secp521r1_sha512 */
			hash_alg = "sha512";
			sig_alg_name = "ecdsa-nist-p521";
			content_hash_len = 64;
			break;
		default:
			pr_warn("tquic_hs: unsupported signature algorithm 0x%04x\n",
				sig_alg);
			tquic_x509_cert_free(cert);
			return -EINVAL;
		}

		/* Hash the content */
		hash_tfm = crypto_alloc_shash(hash_alg, 0, 0);
		if (IS_ERR(hash_tfm)) {
			err = PTR_ERR(hash_tfm);
			pr_warn("tquic_hs: Failed to allocate hash %s: %d\n",
				hash_alg, err);
			tquic_x509_cert_free(cert);
			return err;
		}

		{
			SHASH_DESC_ON_STACK(desc, hash_tfm);
			desc->tfm = hash_tfm;

			err = crypto_shash_digest(desc, content, content_len,
						  content_hash);
			shash_desc_zero(desc);
		}
		crypto_free_shash(hash_tfm);

		if (err) {
			pr_warn("tquic_hs: Failed to hash content: %d\n", err);
			tquic_x509_cert_free(cert);
			return err;
		}

		/*
		 * Verify signature based on algorithm type.
		 * RSA-PSS requires special handling with EMSA-PSS verification.
		 * ECDSA uses the kernel's native signature verification via
		 * the crypto_sig API (kernel 6.x+).
		 */
		if (sig_alg_name == NULL) {
			/* RSA-PSS verification (RFC 8017 Section 8.1.2) */
			err = tquic_verify_rsa_pss(cert->pubkey.key_data,
						   cert->pubkey.key_len,
						   hash_alg, content_hash_len,
						   content_hash,
						   p, sig_len);
			if (err) {
				pr_warn("tquic_hs: RSA-PSS signature verification FAILED: %d\n",
					err);
				tquic_x509_cert_free(cert);
				return err;
			}
			pr_debug("tquic_hs: RSA-PSS CertificateVerify verified successfully\n");
		} else {
			/* ECDSA verification using crypto_sig API */
			sig_tfm = crypto_alloc_sig(sig_alg_name, 0, 0);
			if (IS_ERR(sig_tfm)) {
				err = PTR_ERR(sig_tfm);
				pr_warn("tquic_hs: Failed to allocate sig %s: %d\n",
					sig_alg_name, err);
				tquic_x509_cert_free(cert);
				return err;
			}

			/* Set public key from peer certificate */
			err = crypto_sig_set_pubkey(sig_tfm, cert->pubkey.key_data,
						    cert->pubkey.key_len);
			if (err) {
				pr_warn("tquic_hs: Failed to set public key: %d\n", err);
				crypto_free_sig(sig_tfm);
				tquic_x509_cert_free(cert);
				return err;
			}

			/* Perform ECDSA signature verification (synchronous) */
			err = crypto_sig_verify(sig_tfm, p, sig_len,
						content_hash, content_hash_len);
			crypto_free_sig(sig_tfm);
			if (err) {
				pr_warn("tquic_hs: ECDSA signature verification FAILED: %d\n",
					err);
				tquic_x509_cert_free(cert);
				return err;
			}

			pr_debug("tquic_hs: ECDSA CertificateVerify verified successfully\n");
		}

		tquic_x509_cert_free(cert);
	}

	pr_debug("tquic_hs: CertificateVerify sig_alg=0x%04x, sig_len=%u\n",
		 sig_alg, sig_len);

	/* Update transcript */
	ret = tquic_hs_update_transcript(hs, data, len);
	if (ret < 0)
		return ret;

	hs->state = TQUIC_HS_WAIT_FINISHED;

	pr_debug("tquic_hs: processed CertificateVerify\n");

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_hs_process_certificate_verify);

/*
 * Process Finished message
 */
int tquic_hs_process_finished(struct tquic_handshake *hs,
			      const u8 *data, u32 len)
{
	const u8 *p = data;
	const u8 *end = data + len;
	u8 msg_type;
	u32 msg_len;
	u8 transcript_hash[TLS_SECRET_MAX_LEN];
	u8 verify_data[TLS_SECRET_MAX_LEN];
	u32 hash_len;
	SHASH_DESC_ON_STACK(desc, hs->hmac);
	int ret;

	if (hs->state != TQUIC_HS_WAIT_FINISHED)
		return -EINVAL;

	/* Parse handshake header */
	if (len < 4)
		return -EINVAL;

	msg_type = *p++;
	if (msg_type != TLS_HS_FINISHED)
		return -EINVAL;

	msg_len = (p[0] << 16) | (p[1] << 8) | p[2];
	p += 3;

	if (p + msg_len > end)
		return -EINVAL;

	if (msg_len != hs->hash_len)
		return -EINVAL;

	/* Compute expected verify_data */
	ret = tquic_hs_transcript_hash(hs, transcript_hash, &hash_len);
	if (ret < 0)
		return ret;

	/* verify_data = HMAC(finished_key, transcript_hash) */
	desc->tfm = hs->hmac;

	ret = crypto_shash_setkey(hs->hmac, hs->server_finished_key, hs->hash_len);
	if (ret)
		return ret;

	ret = crypto_shash_init(desc);
	if (ret)
		return ret;

	ret = crypto_shash_update(desc, transcript_hash, hash_len);
	if (ret)
		return ret;

	ret = crypto_shash_final(desc, verify_data);
	if (ret)
		return ret;

	/* Verify */
	if (crypto_memneq(p, verify_data, hs->hash_len)) {
		pr_warn("tquic_hs: Finished verification failed\n");
		hs->alert = TLS_ALERT_DECRYPT_ERROR;
		return -EINVAL;
	}

	/* Update transcript (before deriving app secrets) */
	ret = tquic_hs_update_transcript(hs, data, len);
	if (ret < 0)
		return ret;

	/* Derive application secrets */
	ret = tquic_hs_derive_app_secrets(hs);
	if (ret < 0)
		return ret;

	if (!hs->is_server) {
		/* Client needs to send its own Finished */
		hs->state = TQUIC_HS_COMPLETE;
	}

	pr_debug("tquic_hs: processed server Finished\n");

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_hs_process_finished);

/*
 * Generate Finished message
 */
int tquic_hs_generate_finished(struct tquic_handshake *hs,
			       u8 *buf, u32 buf_len, u32 *out_len)
{
	u8 *p = buf;
	u8 transcript_hash[TLS_SECRET_MAX_LEN];
	u8 verify_data[TLS_SECRET_MAX_LEN];
	u32 hash_len;
	SHASH_DESC_ON_STACK(desc, hs->hmac);
	const u8 *finished_key;
	int ret;

	if (buf_len < 4 + hs->hash_len)
		return -EINVAL;

	/* Compute transcript hash */
	ret = tquic_hs_transcript_hash(hs, transcript_hash, &hash_len);
	if (ret < 0)
		return ret;

	/* Select appropriate finished key */
	finished_key = hs->is_server ? hs->server_finished_key : hs->client_finished_key;

	/* Compute verify_data */
	desc->tfm = hs->hmac;

	ret = crypto_shash_setkey(hs->hmac, finished_key, hs->hash_len);
	if (ret)
		return ret;

	ret = crypto_shash_init(desc);
	if (ret)
		return ret;

	ret = crypto_shash_update(desc, transcript_hash, hash_len);
	if (ret)
		return ret;

	ret = crypto_shash_final(desc, verify_data);
	if (ret)
		return ret;

	/* Build Finished message */
	*p++ = TLS_HS_FINISHED;
	*p++ = 0;
	*p++ = (hs->hash_len >> 8) & 0xff;
	*p++ = hs->hash_len & 0xff;
	memcpy(p, verify_data, hs->hash_len);
	p += hs->hash_len;

	*out_len = p - buf;

	/* Update transcript */
	ret = tquic_hs_update_transcript(hs, buf, *out_len);
	if (ret < 0)
		return ret;

	/* After client sends Finished, derive resumption secret */
	if (!hs->is_server) {
		ret = tquic_hs_derive_resumption_secret(hs);
		if (ret < 0)
			return ret;

		hs->state = TQUIC_HS_COMPLETE;
	}

	pr_debug("tquic_hs: generated Finished (%u bytes)\n", *out_len);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_hs_generate_finished);

/*
 * Process NewSessionTicket message (for session resumption)
 */
int tquic_hs_process_new_session_ticket(struct tquic_handshake *hs,
					const u8 *data, u32 len)
{
	const u8 *p = data;
	const u8 *end = data + len;
	u8 msg_type;
	u32 msg_len;
	u32 lifetime;
	u32 age_add;
	u8 nonce_len;
	u16 ticket_len;
	u16 ext_len;
	u8 psk[TLS_SECRET_MAX_LEN];
	int ret;

	/* Parse handshake header */
	if (len < 4)
		return -EINVAL;

	msg_type = *p++;
	if (msg_type != TLS_HS_NEW_SESSION_TICKET)
		return -EINVAL;

	msg_len = (p[0] << 16) | (p[1] << 8) | p[2];
	p += 3;

	if (p + msg_len > end)
		return -EINVAL;

	/* Ticket lifetime */
	if (p + 4 > end)
		return -EINVAL;
	lifetime = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
	p += 4;

	/* Ticket age add */
	if (p + 4 > end)
		return -EINVAL;
	age_add = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
	p += 4;

	/* Ticket nonce */
	nonce_len = *p++;
	if (p + nonce_len > end)
		return -EINVAL;

	/* Allocate session ticket structure */
	if (!hs->session_ticket) {
		hs->session_ticket = kzalloc(sizeof(*hs->session_ticket), GFP_KERNEL);
		if (!hs->session_ticket)
			return -ENOMEM;
	}

	hs->session_ticket->lifetime = lifetime;
	hs->session_ticket->age_add = age_add;
	hs->session_ticket->nonce_len = nonce_len;
	memcpy(hs->session_ticket->nonce, p, nonce_len);
	p += nonce_len;

	/* Ticket */
	if (p + 2 > end)
		return -EINVAL;
	ticket_len = (p[0] << 8) | p[1];
	p += 2;

	if (p + ticket_len > end)
		return -EINVAL;

	kfree(hs->session_ticket->ticket);
	hs->session_ticket->ticket = kmalloc(ticket_len, GFP_KERNEL);
	if (!hs->session_ticket->ticket)
		return -ENOMEM;

	memcpy(hs->session_ticket->ticket, p, ticket_len);
	hs->session_ticket->ticket_len = ticket_len;
	p += ticket_len;

	/* Extensions */
	if (p + 2 > end)
		return -EINVAL;
	ext_len = (p[0] << 8) | p[1];
	p += 2;

	/* Parse extensions (early_data max size, etc.) */
	/* Skip for now */

	/* Derive PSK from resumption secret */
	/* PSK = HKDF-Expand-Label(resumption_secret, "resumption", nonce, hash_len) */
	ret = tquic_hs_hkdf_expand_label(hs, hs->resumption_secret, hs->hash_len,
					 "resumption",
					 hs->session_ticket->nonce,
					 hs->session_ticket->nonce_len,
					 psk, hs->hash_len);
	if (ret < 0)
		return ret;

	memcpy(hs->session_ticket->resumption_secret, psk, hs->hash_len);
	hs->session_ticket->resumption_secret_len = hs->hash_len;
	hs->session_ticket->cipher_suite = hs->cipher_suite;
	hs->session_ticket->creation_time = ktime_get_real_seconds();

	/* Copy transport parameters for 0-RTT */
	memcpy(&hs->session_ticket->params, &hs->peer_params,
	       sizeof(hs->session_ticket->params));

	pr_debug("tquic_hs: received session ticket (lifetime=%u)\n", lifetime);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_hs_process_new_session_ticket);

/*
 * Set up PSK for session resumption
 */
int tquic_hs_setup_psk(struct tquic_handshake *hs,
		       struct tquic_session_ticket *ticket)
{
	struct tquic_psk_identity *psk;
	u64 now;
	u32 age;
	u32 obfuscated_age;

	if (!ticket || !ticket->ticket)
		return -EINVAL;

	/* Check ticket expiration */
	now = ktime_get_real_seconds();
	if (now > ticket->creation_time + ticket->lifetime)
		return -ETIMEDOUT;

	/* Allocate PSK identity */
	hs->psk_identities = kzalloc(sizeof(*hs->psk_identities), GFP_KERNEL);
	if (!hs->psk_identities)
		return -ENOMEM;

	psk = &hs->psk_identities[0];

	psk->identity = kmalloc(ticket->ticket_len, GFP_KERNEL);
	if (!psk->identity) {
		kfree(hs->psk_identities);
		hs->psk_identities = NULL;
		return -ENOMEM;
	}

	memcpy(psk->identity, ticket->ticket, ticket->ticket_len);
	psk->identity_len = ticket->ticket_len;

	/* Compute obfuscated ticket age */
	age = (now - ticket->creation_time) * 1000;  /* Convert to ms */
	obfuscated_age = age + ticket->age_add;
	psk->obfuscated_ticket_age = obfuscated_age;

	hs->psk_count = 1;
	hs->cipher_suite = ticket->cipher_suite;

	if (ticket->cipher_suite == TLS_AES_256_GCM_SHA384)
		hs->hash_len = 48;
	else
		hs->hash_len = 32;

	/* Store session ticket for early data */
	hs->session_ticket = ticket;

	pr_debug("tquic_hs: set up PSK for resumption\n");

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_hs_setup_psk);

/*
 * Compute PSK binder
 */
int tquic_hs_compute_binder(struct tquic_handshake *hs,
			    const u8 *partial_ch, u32 partial_ch_len,
			    u8 *binder, u32 *binder_len)
{
	u8 binder_key[TLS_SECRET_MAX_LEN];
	u8 finished_key[TLS_SECRET_MAX_LEN];
	u8 transcript_hash[TLS_SECRET_MAX_LEN];
	SHASH_DESC_ON_STACK(desc, hs->hash_tfm);
	SHASH_DESC_ON_STACK(hmac_desc, hs->hmac);
	u32 hash_len;
	int ret;

	hash_len = hs->hash_len;

	/* Derive binder key from early secret */
	ret = tquic_hs_derive_secret(hs, hs->early_secret,
				     "res binder", NULL, 0,
				     binder_key, hash_len);
	if (ret < 0)
		goto out_zeroize;

	/* Compute transcript hash of partial ClientHello (without binders) */
	desc->tfm = hs->hash_tfm;

	ret = crypto_shash_init(desc);
	if (ret)
		goto out_zeroize;

	ret = crypto_shash_update(desc, partial_ch, partial_ch_len);
	if (ret)
		goto out_zeroize;

	ret = crypto_shash_final(desc, transcript_hash);
	if (ret)
		goto out_zeroize;

	/* Compute finished key */
	ret = tquic_hs_hkdf_expand_label(hs, binder_key, hash_len,
					 "finished", NULL, 0,
					 finished_key, hash_len);
	if (ret < 0)
		goto out_zeroize;

	/* Compute binder = HMAC(finished_key, transcript_hash) */
	hmac_desc->tfm = hs->hmac;

	ret = crypto_shash_setkey(hs->hmac, finished_key, hash_len);
	if (ret)
		goto out_zeroize;

	ret = crypto_shash_init(hmac_desc);
	if (ret)
		goto out_zeroize;

	ret = crypto_shash_update(hmac_desc, transcript_hash, hash_len);
	if (ret)
		goto out_zeroize;

	ret = crypto_shash_final(hmac_desc, binder);
	if (ret)
		goto out_zeroize;

	*binder_len = hash_len;
	ret = 0;

out_zeroize:
	memzero_explicit(binder_key, sizeof(binder_key));
	memzero_explicit(finished_key, sizeof(finished_key));
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_hs_compute_binder);

/*
 * Get QUIC keys from handshake secrets
 */
int tquic_hs_get_quic_keys(struct tquic_handshake *hs,
			   int level,
			   u8 *client_key, u32 *client_key_len,
			   u8 *client_iv, u32 *client_iv_len,
			   u8 *client_hp, u32 *client_hp_len,
			   u8 *server_key, u32 *server_key_len,
			   u8 *server_iv, u32 *server_iv_len,
			   u8 *server_hp, u32 *server_hp_len)
{
	const u8 *client_secret;
	const u8 *server_secret;
	u32 key_len, iv_len;
	int ret;

	/* Determine key/IV lengths based on cipher suite */
	switch (hs->cipher_suite) {
	case TLS_AES_128_GCM_SHA256:
	case TLS_AES_128_CCM_SHA256:
		key_len = 16;
		iv_len = 12;
		break;
	case TLS_AES_256_GCM_SHA384:
		key_len = 32;
		iv_len = 12;
		break;
	case TLS_CHACHA20_POLY1305_SHA256:
		key_len = 32;
		iv_len = 12;
		break;
	default:
		return -EINVAL;
	}

	/* Select secrets based on encryption level */
	switch (level) {
	case 1:  /* Handshake */
		client_secret = hs->client_handshake_secret;
		server_secret = hs->server_handshake_secret;
		break;
	case 2:  /* Application */
		client_secret = hs->client_app_secret;
		server_secret = hs->server_app_secret;
		break;
	default:
		return -EINVAL;
	}

	/* Derive client keys */
	ret = tquic_hs_hkdf_expand_label(hs, client_secret, hs->hash_len,
					 "quic key", NULL, 0,
					 client_key, key_len);
	if (ret < 0)
		return ret;
	*client_key_len = key_len;

	ret = tquic_hs_hkdf_expand_label(hs, client_secret, hs->hash_len,
					 "quic iv", NULL, 0,
					 client_iv, iv_len);
	if (ret < 0)
		return ret;
	*client_iv_len = iv_len;

	ret = tquic_hs_hkdf_expand_label(hs, client_secret, hs->hash_len,
					 "quic hp", NULL, 0,
					 client_hp, key_len);
	if (ret < 0)
		return ret;
	*client_hp_len = key_len;

	/* Derive server keys */
	ret = tquic_hs_hkdf_expand_label(hs, server_secret, hs->hash_len,
					 "quic key", NULL, 0,
					 server_key, key_len);
	if (ret < 0)
		return ret;
	*server_key_len = key_len;

	ret = tquic_hs_hkdf_expand_label(hs, server_secret, hs->hash_len,
					 "quic iv", NULL, 0,
					 server_iv, iv_len);
	if (ret < 0)
		return ret;
	*server_iv_len = iv_len;

	ret = tquic_hs_hkdf_expand_label(hs, server_secret, hs->hash_len,
					 "quic hp", NULL, 0,
					 server_hp, key_len);
	if (ret < 0)
		return ret;
	*server_hp_len = key_len;

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_hs_get_quic_keys);

/*
 * Initialize handshake context
 */
struct tquic_handshake *tquic_hs_init(bool is_server)
{
	struct tquic_handshake *hs;
	const char *hash_alg;
	const char *hmac_alg;

	hs = kzalloc(sizeof(*hs), GFP_KERNEL);
	if (!hs)
		return NULL;

	hs->is_server = is_server;
	hs->state = TQUIC_HS_START;
	hs->cipher_suite = TLS_AES_128_GCM_SHA256;
	hs->hash_len = 32;

	/* Set default transport parameters */
	hs->local_params.max_idle_timeout = 30000;
	hs->local_params.max_udp_payload_size = 65527;
	hs->local_params.initial_max_data = 1 << 20;
	hs->local_params.initial_max_stream_data_bidi_local = 1 << 18;
	hs->local_params.initial_max_stream_data_bidi_remote = 1 << 18;
	hs->local_params.initial_max_stream_data_uni = 1 << 18;
	hs->local_params.initial_max_streams_bidi = 128;
	hs->local_params.initial_max_streams_uni = 128;
	hs->local_params.ack_delay_exponent = 3;
	hs->local_params.max_ack_delay = 25;
	hs->local_params.active_conn_id_limit = 8;

	/* Allocate transcript buffer */
	hs->transcript_alloc = 4096;
	hs->transcript = kmalloc(hs->transcript_alloc, GFP_KERNEL);
	if (!hs->transcript)
		goto err_free;

	/* Allocate crypto transforms */
	hash_alg = "sha256";
	hmac_alg = "hmac(sha256)";

	hs->hash_tfm = crypto_alloc_shash(hash_alg, 0, 0);
	if (IS_ERR(hs->hash_tfm)) {
		pr_err("tquic_hs: failed to allocate hash\n");
		goto err_transcript;
	}

	hs->hmac = crypto_alloc_shash(hmac_alg, 0, 0);
	if (IS_ERR(hs->hmac)) {
		pr_err("tquic_hs: failed to allocate HMAC\n");
		goto err_hash;
	}

	pr_debug("tquic_hs: initialized handshake context (server=%d)\n", is_server);

	return hs;

err_hash:
	crypto_free_shash(hs->hash_tfm);
err_transcript:
	kfree(hs->transcript);
err_free:
	kfree(hs);
	return NULL;
}
EXPORT_SYMBOL_GPL(tquic_hs_init);

/*
 * Set ALPN protocols
 */
int tquic_hs_set_alpn(struct tquic_handshake *hs,
		      const char **protos, u32 count)
{
	u32 i;

	if (hs->alpn_list) {
		for (i = 0; i < hs->alpn_count; i++)
			kfree(hs->alpn_list[i]);
		kfree(hs->alpn_list);
	}

	hs->alpn_list = kcalloc(count, sizeof(char *), GFP_KERNEL);
	if (!hs->alpn_list)
		return -ENOMEM;

	for (i = 0; i < count; i++) {
		hs->alpn_list[i] = kstrdup(protos[i], GFP_KERNEL);
		if (!hs->alpn_list[i]) {
			while (i > 0)
				kfree(hs->alpn_list[--i]);
			kfree(hs->alpn_list);
			hs->alpn_list = NULL;
			return -ENOMEM;
		}
	}

	hs->alpn_count = count;
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_hs_set_alpn);

/*
 * Set SNI hostname
 */
int tquic_hs_set_sni(struct tquic_handshake *hs, const char *hostname)
{
	kfree(hs->sni);

	if (!hostname) {
		hs->sni = NULL;
		hs->sni_len = 0;
		return 0;
	}

	hs->sni_len = strlen(hostname);
	if (hs->sni_len > TLS_MAX_SNI_LEN)
		return -EINVAL;

	hs->sni = kstrdup(hostname, GFP_KERNEL);
	if (!hs->sni)
		return -ENOMEM;

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_hs_set_sni);

/*
 * Set local transport parameters
 */
int tquic_hs_set_transport_params(struct tquic_handshake *hs,
				  struct tquic_hs_transport_params *params)
{
	memcpy(&hs->local_params, params, sizeof(*params));
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_hs_set_transport_params);

/*
 * Get peer transport parameters
 */
int tquic_hs_get_transport_params(struct tquic_handshake *hs,
				  struct tquic_hs_transport_params *params)
{
	if (!hs->params_received)
		return -EAGAIN;

	memcpy(params, &hs->peer_params, sizeof(*params));
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_hs_get_transport_params);

/*
 * Check if handshake is complete
 */
bool tquic_hs_is_complete(struct tquic_handshake *hs)
{
	return hs && hs->state == TQUIC_HS_COMPLETE;
}
EXPORT_SYMBOL_GPL(tquic_hs_is_complete);

/*
 * Get selected ALPN protocol
 */
const char *tquic_hs_get_alpn(struct tquic_handshake *hs)
{
	return hs ? hs->alpn_selected : NULL;
}
EXPORT_SYMBOL_GPL(tquic_hs_get_alpn);

/*
 * Check if early data was accepted
 */
bool tquic_hs_early_data_accepted(struct tquic_handshake *hs)
{
	return hs && hs->early_data_accepted;
}
EXPORT_SYMBOL_GPL(tquic_hs_early_data_accepted);

/*
 * Get current handshake state
 */
enum tquic_hs_state tquic_hs_get_state(struct tquic_handshake *hs)
{
	return hs ? hs->state : TQUIC_HS_ERROR;
}
EXPORT_SYMBOL_GPL(tquic_hs_get_state);

/*
 * Get negotiated cipher suite
 */
u16 tquic_hs_get_cipher_suite(struct tquic_handshake *hs)
{
	return hs ? hs->cipher_suite : 0;
}
EXPORT_SYMBOL_GPL(tquic_hs_get_cipher_suite);

/*
 * Get handshake-level traffic secrets
 *
 * Returns the client_handshake_secret and server_handshake_secret derived
 * after ServerHello is processed. These are used to derive handshake-level
 * packet protection keys for CRYPTO frame exchange.
 */
int tquic_hs_get_handshake_secrets(struct tquic_handshake *hs,
				   u8 *client_secret, u32 *client_len,
				   u8 *server_secret, u32 *server_len)
{
	if (!hs || !client_secret || !client_len ||
	    !server_secret || !server_len)
		return -EINVAL;

	/* Handshake secrets available after ServerHello processing */
	if (hs->state < TQUIC_HS_WAIT_EE && hs->state != TQUIC_HS_COMPLETE)
		return -EAGAIN;

	memcpy(client_secret, hs->client_handshake_secret, hs->hash_len);
	*client_len = hs->hash_len;
	memcpy(server_secret, hs->server_handshake_secret, hs->hash_len);
	*server_len = hs->hash_len;

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_hs_get_handshake_secrets);

/*
 * Get application-level traffic secrets
 *
 * Returns the client_app_secret and server_app_secret derived after the
 * handshake completes. These are used for 1-RTT packet protection.
 */
int tquic_hs_get_app_secrets(struct tquic_handshake *hs,
			     u8 *client_secret, u32 *client_len,
			     u8 *server_secret, u32 *server_len)
{
	if (!hs || !client_secret || !client_len ||
	    !server_secret || !server_len)
		return -EINVAL;

	/* App secrets only available after handshake completion */
	if (hs->state != TQUIC_HS_COMPLETE)
		return -EAGAIN;

	memcpy(client_secret, hs->client_app_secret, hs->hash_len);
	*client_len = hs->hash_len;
	memcpy(server_secret, hs->server_app_secret, hs->hash_len);
	*server_len = hs->hash_len;

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_hs_get_app_secrets);

/*
 * Process a TLS record from a CRYPTO frame
 *
 * Routes the incoming TLS handshake message to the appropriate processing
 * function based on the current state machine state. Generates response
 * messages (if any) into out_buf.
 *
 * @hs: Handshake context
 * @data: TLS record data (handshake message type + length + payload)
 * @len: Length of input data
 * @out_buf: Buffer for response messages (ClientHello, Finished, etc.)
 * @out_buf_len: Size of output buffer
 * @out_len: Number of bytes written to out_buf
 *
 * Returns: 0 on success, negative errno on error
 */
int tquic_hs_process_record(struct tquic_handshake *hs,
			    const u8 *data, u32 len,
			    u8 *out_buf, u32 out_buf_len, u32 *out_len)
{
	u8 msg_type;
	u32 msg_len;
	const u8 *msg_data;
	int ret;

	if (!hs || !data || len < 4)
		return -EINVAL;

	*out_len = 0;

	/*
	 * Parse TLS handshake message header:
	 *   msg_type (1 byte) + length (3 bytes) + body
	 */
	msg_type = data[0];
	msg_len = ((u32)data[1] << 16) | ((u32)data[2] << 8) | data[3];

	if (4 + msg_len > len)
		return -EINVAL;

	msg_data = data + 4;

	switch (msg_type) {
	case TLS_HS_SERVER_HELLO:
		if (hs->state != TQUIC_HS_WAIT_SH)
			return -EPROTO;
		ret = tquic_hs_process_server_hello(hs, data, 4 + msg_len);
		break;

	case TLS_HS_ENCRYPTED_EXTENSIONS:
		if (hs->state != TQUIC_HS_WAIT_EE)
			return -EPROTO;
		ret = tquic_hs_process_encrypted_extensions(hs, data,
							    4 + msg_len);
		break;

	case TLS_HS_CERTIFICATE_REQUEST:
		if (hs->state != TQUIC_HS_WAIT_CERT_CR)
			return -EPROTO;
		/*
		 * Certificate request - note it and advance state.
		 * We don't support client certificates yet, so we'll
		 * send an empty Certificate message later.
		 */
		hs->client_auth_requested = true;
		hs->state = TQUIC_HS_WAIT_CERT;
		ret = 0;
		break;

	case TLS_HS_CERTIFICATE:
		if (hs->state != TQUIC_HS_WAIT_CERT &&
		    hs->state != TQUIC_HS_WAIT_CERT_CR)
			return -EPROTO;
		ret = tquic_hs_process_certificate(hs, data, 4 + msg_len);
		break;

	case TLS_HS_CERTIFICATE_VERIFY:
		if (hs->state != TQUIC_HS_WAIT_CV)
			return -EPROTO;
		ret = tquic_hs_process_certificate_verify(hs, data,
							  4 + msg_len);
		break;

	case TLS_HS_FINISHED:
		if (hs->state != TQUIC_HS_WAIT_FINISHED)
			return -EPROTO;
		ret = tquic_hs_process_finished(hs, data, 4 + msg_len);
		if (ret < 0)
			break;

		/*
		 * After processing server Finished, generate client Finished.
		 * This is the last client handshake message.
		 */
		ret = tquic_hs_generate_finished(hs, out_buf, out_buf_len,
						 out_len);
		break;

	case TLS_HS_NEW_SESSION_TICKET:
		ret = tquic_hs_process_new_session_ticket(hs, data,
							  4 + msg_len);
		break;

	default:
		pr_debug("tquic_hs: unexpected message type %u in state %d\n",
			 msg_type, hs->state);
		ret = -EPROTO;
		break;
	}

	return ret;
}
EXPORT_SYMBOL_GPL(tquic_hs_process_record);

/*
 * Cleanup handshake context
 */
void tquic_hs_cleanup(struct tquic_handshake *hs)
{
	u32 i;

	if (!hs)
		return;

	/* Free key share */
	kfree(hs->key_share.public_key);
	kfree(hs->key_share.private_key);

	/* Free transcript */
	kfree(hs->transcript);

	/* Free ALPN */
	if (hs->alpn_list) {
		for (i = 0; i < hs->alpn_count; i++)
			kfree(hs->alpn_list[i]);
		kfree(hs->alpn_list);
	}
	kfree(hs->alpn_selected);

	/* Free SNI */
	kfree(hs->sni);

	/* Free PSK identities */
	if (hs->psk_identities) {
		for (i = 0; i < hs->psk_count; i++)
			kfree(hs->psk_identities[i].identity);
		kfree(hs->psk_identities);
	}

	/* Free session ticket */
	if (hs->session_ticket) {
		kfree(hs->session_ticket->ticket);
		kfree(hs->session_ticket);
	}

	/* Free certificates */
	kfree(hs->peer_cert);
	kfree(hs->local_cert);
	kfree(hs->local_key);

	/* Free crypto transforms */
	if (hs->hash_tfm && !IS_ERR(hs->hash_tfm))
		crypto_free_shash(hs->hash_tfm);

	if (hs->hmac && !IS_ERR(hs->hmac))
		crypto_free_shash(hs->hmac);

	if (hs->aead && !IS_ERR(hs->aead))
		crypto_free_aead(hs->aead);

	/* Clear sensitive data */
	memzero_explicit(hs->early_secret, sizeof(hs->early_secret));
	memzero_explicit(hs->handshake_secret, sizeof(hs->handshake_secret));
	memzero_explicit(hs->master_secret, sizeof(hs->master_secret));
	memzero_explicit(hs->client_handshake_secret, sizeof(hs->client_handshake_secret));
	memzero_explicit(hs->server_handshake_secret, sizeof(hs->server_handshake_secret));
	memzero_explicit(hs->client_app_secret, sizeof(hs->client_app_secret));
	memzero_explicit(hs->server_app_secret, sizeof(hs->server_app_secret));
	memzero_explicit(hs->client_finished_key, sizeof(hs->client_finished_key));
	memzero_explicit(hs->server_finished_key, sizeof(hs->server_finished_key));
	memzero_explicit(hs->shared_secret, sizeof(hs->shared_secret));

	kfree(hs);
}
EXPORT_SYMBOL_GPL(tquic_hs_cleanup);

/*
 * Get peer certificate data (for certificate verification)
 */
u8 *tquic_hs_get_peer_cert(struct tquic_handshake *hs, u32 *len)
{
	if (!hs) {
		*len = 0;
		return NULL;
	}

	*len = hs->peer_cert_len;
	return hs->peer_cert;
}
EXPORT_SYMBOL_GPL(tquic_hs_get_peer_cert);

/*
 * Get peer certificate chain (full chain from Certificate message)
 * Returns pointer to stored chain data and sets len to total chain length
 */
u8 *tquic_hs_get_peer_cert_chain(struct tquic_handshake *hs, u32 *len)
{
	/* For now, return just the end-entity certificate
	 * Full chain support would require storing all certs from Certificate msg
	 */
	return tquic_hs_get_peer_cert(hs, len);
}
EXPORT_SYMBOL_GPL(tquic_hs_get_peer_cert_chain);

/*
 * Get expected hostname (SNI) for certificate verification
 */
const char *tquic_hs_get_sni(struct tquic_handshake *hs, u32 *len)
{
	if (!hs || !hs->sni) {
		*len = 0;
		return NULL;
	}

	*len = hs->sni_len;
	return hs->sni;
}
EXPORT_SYMBOL_GPL(tquic_hs_get_sni);

/*
 * Check if handshake is using PSK (skip certificate verification)
 */
bool tquic_hs_is_psk_mode(struct tquic_handshake *hs)
{
	return hs ? hs->using_psk : false;
}
EXPORT_SYMBOL_GPL(tquic_hs_is_psk_mode);

MODULE_DESCRIPTION("TQUIC TLS 1.3 Handshake for QUIC");
MODULE_LICENSE("GPL");
