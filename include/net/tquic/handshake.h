/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: TLS 1.3 Handshake for QUIC - Header
 *
 * Copyright (c) 2026 Linux Foundation
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 */

#ifndef _NET_TQUIC_HANDSHAKE_H
#define _NET_TQUIC_HANDSHAKE_H

#include <linux/types.h>
#include <crypto/hash.h>
#include <crypto/aead.h>

/* TLS 1.3 Constants */
#define TLS_SECRET_MAX_LEN		48
#define TLS_KEY_MAX_LEN			32
#define TLS_IV_MAX_LEN			12
#define TLS_FINISHED_MAX_LEN		48
#define TLS_RANDOM_LEN			32
#define TLS_SESSION_ID_MAX_LEN		32
#define TLS_MAX_ALPN_LEN		255
#define TLS_MAX_SNI_LEN			255

/* Cipher suites */
#define TLS_AES_128_GCM_SHA256		0x1301
#define TLS_AES_256_GCM_SHA384		0x1302
#define TLS_CHACHA20_POLY1305_SHA256	0x1303

/* Handshake state machine */
enum tquic_hs_state {
	TQUIC_HS_START = 0,
	TQUIC_HS_WAIT_SH,
	TQUIC_HS_WAIT_EE,
	TQUIC_HS_WAIT_CERT_CR,
	TQUIC_HS_WAIT_CERT,
	TQUIC_HS_WAIT_CV,
	TQUIC_HS_WAIT_FINISHED,
	TQUIC_HS_WAIT_EOED,
	TQUIC_HS_WAIT_CERT_REQ,
	TQUIC_HS_COMPLETE,
	TQUIC_HS_ERROR,
};

/* QUIC transport parameters */
struct tquic_hs_transport_params {
	u64 original_dcid_len;
	u8 original_dcid[20];
	u64 max_idle_timeout;
	u8 stateless_reset_token[16];
	bool has_stateless_reset_token;
	u64 max_udp_payload_size;
	u64 initial_max_data;
	u64 initial_max_stream_data_bidi_local;
	u64 initial_max_stream_data_bidi_remote;
	u64 initial_max_stream_data_uni;
	u64 initial_max_streams_bidi;
	u64 initial_max_streams_uni;
	u64 ack_delay_exponent;
	u64 max_ack_delay;
	bool disable_active_migration;
	u64 active_conn_id_limit;
	u64 initial_scid_len;
	u8 initial_scid[20];
	u64 retry_scid_len;
	u8 retry_scid[20];
	bool has_retry_scid;
	u64 max_datagram_frame_size;
	bool grease_quic_bit;
};

/* Session ticket for resumption */
struct tquic_session_ticket {
	u32 lifetime;
	u32 age_add;
	u8 nonce[255];
	u8 nonce_len;
	u8 *ticket;
	u32 ticket_len;
	u8 resumption_secret[TLS_SECRET_MAX_LEN];
	u32 resumption_secret_len;
	u16 cipher_suite;
	u64 creation_time;
	u32 max_early_data;		/* Max 0-RTT data (early_data ext) */
	struct tquic_hs_transport_params params;
};

/* Opaque handshake context */
struct tquic_handshake;

/* Core handshake functions */
struct tquic_handshake *tquic_hs_init(bool is_server);
void tquic_hs_cleanup(struct tquic_handshake *hs);

/* Client handshake */
int tquic_hs_generate_client_hello(struct tquic_handshake *hs,
				   u8 *buf, u32 buf_len, u32 *out_len);
int tquic_hs_process_server_hello(struct tquic_handshake *hs,
				  const u8 *data, u32 len);
int tquic_hs_process_encrypted_extensions(struct tquic_handshake *hs,
					  const u8 *data, u32 len);
int tquic_hs_process_certificate(struct tquic_handshake *hs,
				 const u8 *data, u32 len);
int tquic_hs_process_certificate_verify(struct tquic_handshake *hs,
					const u8 *data, u32 len);
int tquic_hs_process_finished(struct tquic_handshake *hs,
			      const u8 *data, u32 len);
int tquic_hs_generate_finished(struct tquic_handshake *hs,
			       u8 *buf, u32 buf_len, u32 *out_len);

/* Session resumption */
int tquic_hs_process_new_session_ticket(struct tquic_handshake *hs,
					const u8 *data, u32 len);
int tquic_hs_setup_psk(struct tquic_handshake *hs,
		       struct tquic_session_ticket *ticket);
int tquic_hs_compute_binder(struct tquic_handshake *hs,
			    const u8 *partial_ch, u32 partial_ch_len,
			    u8 *binder, u32 *binder_len);

/* Key derivation for QUIC */
int tquic_hs_get_quic_keys(struct tquic_handshake *hs,
			   int level,
			   u8 *client_key, u32 *client_key_len,
			   u8 *client_iv, u32 *client_iv_len,
			   u8 *client_hp, u32 *client_hp_len,
			   u8 *server_key, u32 *server_key_len,
			   u8 *server_iv, u32 *server_iv_len,
			   u8 *server_hp, u32 *server_hp_len);

/* Configuration */
int tquic_hs_set_alpn(struct tquic_handshake *hs,
		      const char **protos, u32 count);
int tquic_hs_set_sni(struct tquic_handshake *hs, const char *hostname);
int tquic_hs_set_transport_params(struct tquic_handshake *hs,
				  struct tquic_hs_transport_params *params);
int tquic_hs_get_transport_params(struct tquic_handshake *hs,
				  struct tquic_hs_transport_params *params);

/* Status queries */
bool tquic_hs_is_complete(struct tquic_handshake *hs);
const char *tquic_hs_get_alpn(struct tquic_handshake *hs);
bool tquic_hs_early_data_accepted(struct tquic_handshake *hs);
enum tquic_hs_state tquic_hs_get_state(struct tquic_handshake *hs);

/* Secret accessors for QUIC key installation */
u16 tquic_hs_get_cipher_suite(struct tquic_handshake *hs);
int tquic_hs_get_handshake_secrets(struct tquic_handshake *hs,
				   u8 *client_secret, u32 *client_len,
				   u8 *server_secret, u32 *server_len);
int tquic_hs_get_app_secrets(struct tquic_handshake *hs,
			     u8 *client_secret, u32 *client_len,
			     u8 *server_secret, u32 *server_len);

/* TLS record processing for inline handshake */
int tquic_hs_process_record(struct tquic_handshake *hs,
			    const u8 *data, u32 len,
			    u8 *out_buf, u32 out_buf_len, u32 *out_len);

#endif /* _NET_TQUIC_HANDSHAKE_H */
