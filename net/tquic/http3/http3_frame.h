/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC HTTP/3 Frame Layer - Internal Header
 *
 * Copyright (c) 2026 Linux Foundation
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Internal definitions for HTTP/3 frame parsing and construction
 * per RFC 9114. This header is for use within the http3/ directory.
 */

#ifndef _TQUIC_HTTP3_FRAME_H
#define _TQUIC_HTTP3_FRAME_H

#include <linux/types.h>
#include <linux/errno.h>
#include <net/tquic_http3.h>

/*
 * Maximum frame header size: type (8 bytes) + length (8 bytes)
 * Using worst-case varint encoding for both fields.
 */
#define H3_MAX_FRAME_HEADER_SIZE	16

/*
 * Maximum payload size for safety. Very large payloads may indicate
 * a malformed frame or attack. 1MB is generous for HTTP/3 frames.
 */
#define H3_MAX_FRAME_PAYLOAD_SIZE	(1 * 1024 * 1024)

/*
 * Frame parsing result codes
 */
#define H3_PARSE_OK		0
#define H3_PARSE_NEED_MORE	(-EAGAIN)
#define H3_PARSE_INVALID	(-EINVAL)
#define H3_PARSE_ERROR		(-H3_FRAME_ERROR)

/**
 * struct h3_frame_parser - Frame parsing context
 * @buf: Current buffer position
 * @len: Remaining buffer length
 * @consumed: Bytes consumed so far
 *
 * Helper structure for tracking parse progress.
 */
struct h3_frame_parser {
	const u8 *buf;
	size_t len;
	size_t consumed;
};

/**
 * struct h3_frame_writer - Frame writing context
 * @buf: Current buffer position
 * @len: Remaining buffer space
 * @written: Bytes written so far
 *
 * Helper structure for tracking write progress.
 */
struct h3_frame_writer {
	u8 *buf;
	size_t len;
	size_t written;
};

/*
 * Internal varint helpers using QUIC varint encoding.
 * HTTP/3 uses the same varint format as QUIC.
 */

/**
 * h3_varint_size - Get encoded size of varint
 * @value: Value to encode
 *
 * Returns: 1, 2, 4, or 8 bytes; 0 if value is too large.
 */
static inline int h3_varint_size(u64 value)
{
	if (value <= 63)
		return 1;
	if (value <= 16383)
		return 2;
	if (value <= 1073741823)
		return 4;
	if (value <= 4611686018427387903ULL)
		return 8;
	return 0;
}

/**
 * h3_varint_decode_len - Get length from first byte
 * @byte: First byte of encoded varint
 *
 * Returns: Number of bytes in the encoded varint.
 */
static inline int h3_varint_decode_len(u8 byte)
{
	return 1 << ((byte >> 6) & 0x3);
}

/* Varint encode/decode functions */
int h3_varint_encode(u64 value, u8 *buf, size_t len);
int h3_varint_decode(const u8 *buf, size_t len, u64 *value);

/* Parser initialization and helpers */
static inline void h3_parser_init(struct h3_frame_parser *p,
				  const u8 *buf, size_t len)
{
	p->buf = buf;
	p->len = len;
	p->consumed = 0;
}

static inline bool h3_parser_remaining(struct h3_frame_parser *p, size_t bytes)
{
	return p->len >= bytes;
}

static inline void h3_parser_advance(struct h3_frame_parser *p, size_t bytes)
{
	/*
	 * Defense-in-depth: prevent size_t underflow on p->len.
	 * Callers should validate bounds via h3_parser_remaining() or
	 * h3_varint_decode() before calling, but clamp here to avoid
	 * silent buffer over-reads if a caller is ever buggy.
	 */
	if (unlikely(bytes > p->len)) {
		WARN_ON_ONCE(1);
		bytes = p->len;
	}
	p->buf += bytes;
	p->len -= bytes;
	p->consumed += bytes;
}

/* Writer initialization and helpers */
static inline void h3_writer_init(struct h3_frame_writer *w,
				  u8 *buf, size_t len)
{
	w->buf = buf;
	w->len = len;
	w->written = 0;
}

static inline bool h3_writer_remaining(struct h3_frame_writer *w, size_t bytes)
{
	return w->len >= bytes;
}

static inline void h3_writer_advance(struct h3_frame_writer *w, size_t bytes)
{
	w->buf += bytes;
	w->len -= bytes;
	w->written += bytes;
}

/*
 * Internal frame parsing functions
 */
int h3_parse_frame_header(struct h3_frame_parser *p, u64 *type, u64 *length);
int h3_parse_data_frame(struct h3_frame_parser *p, u64 frame_len,
			struct tquic_h3_frame_data *frame);
int h3_parse_headers_frame(struct h3_frame_parser *p, u64 frame_len,
			   struct tquic_h3_frame_headers *frame);
int h3_parse_cancel_push_frame(struct h3_frame_parser *p, u64 frame_len,
			       struct tquic_h3_frame_cancel_push *frame);
int h3_parse_settings_frame(struct h3_frame_parser *p, u64 frame_len,
			    struct tquic_h3_frame_settings *frame,
			    struct tquic_h3_frame_settings_entry *entries_buf,
			    u32 max_entries);
int h3_parse_push_promise_frame(struct h3_frame_parser *p, u64 frame_len,
				struct tquic_h3_frame_push_promise *frame);
int h3_parse_goaway_frame(struct h3_frame_parser *p, u64 frame_len,
			  struct tquic_h3_frame_goaway *frame);
int h3_parse_max_push_id_frame(struct h3_frame_parser *p, u64 frame_len,
			       struct tquic_h3_frame_max_push_id *frame);

/*
 * Internal frame writing functions
 */
int h3_write_frame_header(struct h3_frame_writer *w, u64 type, u64 length);
int h3_write_data_payload(struct h3_frame_writer *w,
			  const struct tquic_h3_frame_data *frame);
int h3_write_headers_payload(struct h3_frame_writer *w,
			     const struct tquic_h3_frame_headers *frame);
int h3_write_cancel_push_payload(struct h3_frame_writer *w,
				 const struct tquic_h3_frame_cancel_push *frame);
int h3_write_settings_payload(struct h3_frame_writer *w,
			      const struct tquic_h3_settings *settings);
int h3_write_push_promise_payload(struct h3_frame_writer *w,
				  const struct tquic_h3_frame_push_promise *frame);
int h3_write_goaway_payload(struct h3_frame_writer *w,
			    const struct tquic_h3_frame_goaway *frame);
int h3_write_max_push_id_payload(struct h3_frame_writer *w,
				 const struct tquic_h3_frame_max_push_id *frame);

/*
 * Settings encoding helpers
 */
size_t h3_settings_encoded_size(const struct tquic_h3_settings *settings);
int h3_encode_settings(const struct tquic_h3_settings *settings,
		       u8 *buf, size_t len);
int h3_decode_settings(const u8 *buf, size_t len,
		       struct tquic_h3_settings *settings);

/*
 * Frame validation
 */
bool h3_frame_valid_on_control_stream(u64 type);
bool h3_frame_valid_on_request_stream(u64 type);
bool h3_frame_valid_on_push_stream(u64 type);

#endif /* _TQUIC_HTTP3_FRAME_H */
