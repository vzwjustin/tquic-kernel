/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: WAN Bonding over QUIC - Frame Definitions
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * This header provides QUIC frame parsing, construction, and utility
 * functions according to RFC 9000.
 */

#ifndef _NET_TQUIC_FRAME_H
#define _NET_TQUIC_FRAME_H

#include <linux/types.h>

/*
 * QUIC Frame Type Values (RFC 9000, Section 12.4)
 */
#define TQUIC_FRAME_PADDING		0x00
#define TQUIC_FRAME_PING		0x01
#define TQUIC_FRAME_ACK			0x02
#define TQUIC_FRAME_ACK_ECN		0x03
#define TQUIC_FRAME_RESET_STREAM	0x04
#define TQUIC_FRAME_STOP_SENDING	0x05
#define TQUIC_FRAME_CRYPTO		0x06
#define TQUIC_FRAME_NEW_TOKEN		0x07
#define TQUIC_FRAME_STREAM_BASE		0x08
#define TQUIC_FRAME_STREAM_MAX		0x0f
#define TQUIC_FRAME_MAX_DATA		0x10
#define TQUIC_FRAME_MAX_STREAM_DATA	0x11
#define TQUIC_FRAME_MAX_STREAMS_BIDI	0x12
#define TQUIC_FRAME_MAX_STREAMS_UNI	0x13
#define TQUIC_FRAME_DATA_BLOCKED	0x14
#define TQUIC_FRAME_STREAM_DATA_BLOCKED	0x15
#define TQUIC_FRAME_STREAMS_BLOCKED_BIDI	0x16
#define TQUIC_FRAME_STREAMS_BLOCKED_UNI		0x17
#define TQUIC_FRAME_NEW_CONNECTION_ID		0x18
#define TQUIC_FRAME_RETIRE_CONNECTION_ID	0x19
#define TQUIC_FRAME_PATH_CHALLENGE	0x1a
#define TQUIC_FRAME_PATH_RESPONSE	0x1b
#define TQUIC_FRAME_CONNECTION_CLOSE	0x1c
#define TQUIC_FRAME_CONNECTION_CLOSE_APP	0x1d
#define TQUIC_FRAME_HANDSHAKE_DONE	0x1e

/* DATAGRAM frame types (RFC 9221) */
#define TQUIC_FRAME_DATAGRAM		0x30  /* No length field */
#define TQUIC_FRAME_DATAGRAM_LEN	0x31  /* With length field */

/* STREAM frame flags */
#define TQUIC_STREAM_FLAG_FIN		0x01
#define TQUIC_STREAM_FLAG_LEN		0x02
#define TQUIC_STREAM_FLAG_OFF		0x04

/* Maximum values */
#define TQUIC_MAX_VARINT		((1ULL << 62) - 1)
#define TQUIC_MAX_ACK_RANGES		256
#define TQUIC_MAX_FRAME_SIZE		(16 * 1024)
#define TQUIC_MAX_REASON_LEN		256
#define TQUIC_MAX_TOKEN_LEN		(8 * 1024)
#define TQUIC_STATELESS_RESET_TOKEN_LEN	16

/*
 * ACK Range structure
 */
struct tquic_ack_range {
	u64 gap;
	u64 ack_range_len;
};

/*
 * Parsed frame structures
 */
struct tquic_frame_padding {
	size_t length;
};

struct tquic_frame_ack {
	u64 largest_ack;
	u64 ack_delay;
	u64 ack_range_count;
	u64 first_ack_range;
	struct tquic_ack_range *ranges;
	bool has_ecn;
	u64 ect0_count;
	u64 ect1_count;
	u64 ecn_ce_count;
};

struct tquic_frame_reset_stream {
	u64 stream_id;
	u64 app_error_code;
	u64 final_size;
};

struct tquic_frame_stop_sending {
	u64 stream_id;
	u64 app_error_code;
};

struct tquic_frame_crypto {
	u64 offset;
	u64 length;
	const u8 *data;
};

struct tquic_frame_new_token {
	u64 token_len;
	const u8 *token;
};

struct tquic_frame_stream {
	u64 stream_id;
	u64 offset;
	u64 length;
	const u8 *data;
	bool fin;
	bool has_offset;
	bool has_length;
};

struct tquic_frame_max_data {
	u64 max_data;
};

struct tquic_frame_max_stream_data {
	u64 stream_id;
	u64 max_stream_data;
};

struct tquic_frame_max_streams {
	u64 max_streams;
	bool bidi;
};

struct tquic_frame_data_blocked {
	u64 max_data;
};

struct tquic_frame_stream_data_blocked {
	u64 stream_id;
	u64 max_stream_data;
};

struct tquic_frame_streams_blocked {
	u64 max_streams;
	bool bidi;
};

struct tquic_frame_new_connection_id {
	u64 seq_num;
	u64 retire_prior_to;
	u8 cid_len;
	u8 cid[20];  /* TQUIC_MAX_CID_LEN */
	u8 stateless_reset_token[TQUIC_STATELESS_RESET_TOKEN_LEN];
};

struct tquic_frame_retire_connection_id {
	u64 seq_num;
};

struct tquic_frame_path_challenge {
	u8 data[8];
};

struct tquic_frame_path_response {
	u8 data[8];
};

struct tquic_frame_connection_close {
	u64 error_code;
	u64 frame_type;
	u64 reason_len;
	const u8 *reason;
	bool app_close;
};

/*
 * DATAGRAM frame (RFC 9221)
 */
struct tquic_frame_datagram {
	u64 length;
	const u8 *data;
	bool has_length;  /* true if type 0x31 (explicit length) */
};

/*
 * Generic frame union
 */
struct tquic_frame {
	u8 type;
	union {
		struct tquic_frame_padding padding;
		struct tquic_frame_ack ack;
		struct tquic_frame_reset_stream reset_stream;
		struct tquic_frame_stop_sending stop_sending;
		struct tquic_frame_crypto crypto;
		struct tquic_frame_new_token new_token;
		struct tquic_frame_stream stream;
		struct tquic_frame_max_data max_data;
		struct tquic_frame_max_stream_data max_stream_data;
		struct tquic_frame_max_streams max_streams;
		struct tquic_frame_data_blocked data_blocked;
		struct tquic_frame_stream_data_blocked stream_data_blocked;
		struct tquic_frame_streams_blocked streams_blocked;
		struct tquic_frame_new_connection_id new_cid;
		struct tquic_frame_retire_connection_id retire_cid;
		struct tquic_frame_path_challenge path_challenge;
		struct tquic_frame_path_response path_response;
		struct tquic_frame_connection_close conn_close;
		struct tquic_frame_datagram datagram;
	};
};

/*
 * Variable-Length Integer API
 *
 * These functions are defined in core/varint.c and handle offset-based
 * reading and writing of QUIC variable-length integers.
 */
int tquic_varint_read(const u8 *buf, size_t buf_len, size_t *offset, u64 *value);
int tquic_varint_write(u8 *buf, size_t buf_len, size_t *offset, u64 value);
int tquic_varint_encode(u64 value, u8 *buf, size_t len);
int tquic_varint_decode(const u8 *buf, size_t len, u64 *value);
int tquic_varint_len(u64 value);

/*
 * Frame Parsing
 */
int tquic_parse_frame(const u8 *buf, size_t buf_len, struct tquic_frame *frame,
		      struct tquic_ack_range *ranges_buf, size_t max_ranges);

/*
 * Frame Size Calculation
 */
size_t tquic_padding_frame_size(size_t length);
size_t tquic_ping_frame_size(void);
size_t tquic_ack_frame_size(u64 largest_ack, u64 ack_delay, u64 first_ack_range,
			    const struct tquic_ack_range *ranges, u64 range_count,
			    bool has_ecn, u64 ect0, u64 ect1, u64 ecn_ce);
size_t tquic_reset_stream_frame_size(u64 stream_id, u64 error_code, u64 final_size);
size_t tquic_stop_sending_frame_size(u64 stream_id, u64 error_code);
size_t tquic_crypto_frame_size(u64 offset, u64 length);
size_t tquic_new_token_frame_size(u64 token_len);
size_t tquic_stream_frame_size(u64 stream_id, u64 offset, u64 length,
			       bool has_offset, bool has_length);
size_t tquic_max_data_frame_size(u64 max_data);
size_t tquic_max_stream_data_frame_size(u64 stream_id, u64 max_stream_data);
size_t tquic_max_streams_frame_size(u64 max_streams);
size_t tquic_data_blocked_frame_size(u64 max_data);
size_t tquic_stream_data_blocked_frame_size(u64 stream_id, u64 max_stream_data);
size_t tquic_streams_blocked_frame_size(u64 max_streams);
size_t tquic_new_connection_id_frame_size(u64 seq_num, u64 retire_prior_to,
					  u8 cid_len);
size_t tquic_retire_connection_id_frame_size(u64 seq_num);
size_t tquic_path_challenge_frame_size(void);
size_t tquic_path_response_frame_size(void);
size_t tquic_connection_close_frame_size(u64 error_code, u64 frame_type,
					 u64 reason_len, bool app_close);
size_t tquic_handshake_done_frame_size(void);
size_t tquic_datagram_frame_size(u64 data_len, bool with_length);

/*
 * Frame Construction
 */
int tquic_write_padding_frame(u8 *buf, size_t buf_len, size_t length);
int tquic_write_ping_frame(u8 *buf, size_t buf_len);
int tquic_write_ack_frame(u8 *buf, size_t buf_len, u64 largest_ack,
			  u64 ack_delay, u64 first_ack_range,
			  const struct tquic_ack_range *ranges, u64 range_count,
			  bool has_ecn, u64 ect0, u64 ect1, u64 ecn_ce);
int tquic_write_reset_stream_frame(u8 *buf, size_t buf_len, u64 stream_id,
				   u64 error_code, u64 final_size);
int tquic_write_stop_sending_frame(u8 *buf, size_t buf_len, u64 stream_id,
				   u64 error_code);
int tquic_write_crypto_frame(u8 *buf, size_t buf_len, u64 offset,
			     const u8 *data, u64 data_len);
int tquic_write_new_token_frame(u8 *buf, size_t buf_len,
				const u8 *token, u64 token_len);
int tquic_write_stream_frame(u8 *buf, size_t buf_len, u64 stream_id,
			     u64 offset, const u8 *data, u64 data_len,
			     bool has_offset, bool has_length, bool fin);
int tquic_write_max_data_frame(u8 *buf, size_t buf_len, u64 max_data);
int tquic_write_max_stream_data_frame(u8 *buf, size_t buf_len, u64 stream_id,
				      u64 max_stream_data);
int tquic_write_max_streams_frame(u8 *buf, size_t buf_len, u64 max_streams,
				  bool bidi);
int tquic_write_data_blocked_frame(u8 *buf, size_t buf_len, u64 max_data);
int tquic_write_stream_data_blocked_frame(u8 *buf, size_t buf_len,
					  u64 stream_id, u64 max_stream_data);
int tquic_write_streams_blocked_frame(u8 *buf, size_t buf_len, u64 max_streams,
				      bool bidi);
int tquic_write_new_connection_id_frame(u8 *buf, size_t buf_len, u64 seq_num,
					u64 retire_prior_to, const u8 *cid,
					u8 cid_len, const u8 *stateless_reset_token);
int tquic_write_retire_connection_id_frame(u8 *buf, size_t buf_len, u64 seq_num);
int tquic_write_path_challenge_frame(u8 *buf, size_t buf_len, const u8 *data);
int tquic_write_path_response_frame(u8 *buf, size_t buf_len, const u8 *data);
int tquic_write_connection_close_frame(u8 *buf, size_t buf_len, u64 error_code,
				       u64 frame_type, const u8 *reason,
				       u64 reason_len, bool app_close);
int tquic_write_handshake_done_frame(u8 *buf, size_t buf_len);
int tquic_write_datagram_frame(u8 *buf, size_t buf_len, const u8 *data,
			       u64 data_len, bool with_length);

/*
 * Frame Parsing (DATAGRAM specific)
 */
int tquic_parse_datagram_frame(const u8 *buf, size_t buf_len,
			       struct tquic_frame *frame);

/*
 * Utility Functions
 */
const char *tquic_frame_type_name(u8 type);
bool tquic_frame_is_ack_eliciting(u8 type);
bool tquic_frame_is_probing(u8 type);
bool tquic_frame_allowed_in_pn_space(u8 type, int pn_space);
size_t tquic_varint_encode_len(u64 val);

/**
 * tquic_is_stream_frame - Check if frame type is a STREAM frame
 * @type: Frame type byte
 *
 * Returns true if the frame type is in the STREAM range (0x08-0x0f).
 */
static inline bool tquic_is_stream_frame(u8 type)
{
	return type >= TQUIC_FRAME_STREAM_BASE && type <= TQUIC_FRAME_STREAM_MAX;
}

/**
 * tquic_stream_frame_has_fin - Check if STREAM frame has FIN flag
 * @type: Frame type byte
 *
 * Returns true if the FIN bit is set.
 */
static inline bool tquic_stream_frame_has_fin(u8 type)
{
	return type & TQUIC_STREAM_FLAG_FIN;
}

/**
 * tquic_stream_frame_has_length - Check if STREAM frame has length field
 * @type: Frame type byte
 *
 * Returns true if the LEN bit is set.
 */
static inline bool tquic_stream_frame_has_length(u8 type)
{
	return type & TQUIC_STREAM_FLAG_LEN;
}

/**
 * tquic_stream_frame_has_offset - Check if STREAM frame has offset field
 * @type: Frame type byte
 *
 * Returns true if the OFF bit is set.
 */
static inline bool tquic_stream_frame_has_offset(u8 type)
{
	return type & TQUIC_STREAM_FLAG_OFF;
}

/**
 * tquic_is_datagram_frame - Check if frame type is a DATAGRAM frame
 * @type: Frame type byte
 *
 * Returns true if the frame type is DATAGRAM (0x30 or 0x31).
 */
static inline bool tquic_is_datagram_frame(u8 type)
{
	return (type & 0xfe) == TQUIC_FRAME_DATAGRAM;
}

/**
 * tquic_datagram_frame_has_length - Check if DATAGRAM frame has length field
 * @type: Frame type byte
 *
 * Returns true if the length field is present (type 0x31).
 */
static inline bool tquic_datagram_frame_has_length(u8 type)
{
	return type & 0x01;
}

#endif /* _NET_TQUIC_FRAME_H */
