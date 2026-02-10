// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC HTTP/3 Frame Layer
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Implementation of HTTP/3 frame parsing and construction per RFC 9114.
 *
 * HTTP/3 frames use the format:
 *   Frame Type (varint) || Frame Length (varint) || Frame Payload
 *
 * This file provides:
 *   - Frame type definitions and validation
 *   - Frame parsing from wire format
 *   - Frame construction to wire format
 *   - Size calculation utilities
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/unaligned.h>
#include <net/tquic_http3.h>

#include "http3_frame.h"
#include "http3_priority.h"

/*
 * =============================================================================
 * Variable-Length Integer Encoding/Decoding
 * =============================================================================
 *
 * HTTP/3 uses the same varint encoding as QUIC (RFC 9000 Section 16).
 */

/**
 * h3_varint_encode - Encode value as QUIC/HTTP3 varint
 * @value: Value to encode
 * @buf: Output buffer
 * @len: Buffer length
 *
 * Returns: Bytes written on success, negative error on failure.
 */
int h3_varint_encode(u64 value, u8 *buf, size_t len)
{
	int size;

	if (!buf)
		return -EINVAL;

	size = h3_varint_size(value);
	if (size == 0)
		return -EOVERFLOW;

	if (len < size)
		return -ENOSPC;

	switch (size) {
	case 1:
		buf[0] = (u8)value;
		break;
	case 2:
		put_unaligned_be16((u16)value | 0x4000, buf);
		break;
	case 4:
		put_unaligned_be32((u32)value | 0x80000000, buf);
		break;
	case 8:
		put_unaligned_be64(value | 0xc000000000000000ULL, buf);
		break;
	default:
		return -EINVAL;
	}

	return size;
}

/**
 * h3_varint_decode - Decode QUIC/HTTP3 varint
 * @buf: Input buffer
 * @len: Buffer length
 * @value: Output value
 *
 * Returns: Bytes consumed on success, negative error on failure.
 */
int h3_varint_decode(const u8 *buf, size_t len, u64 *value)
{
	int size;
	u64 result;

	if (!buf || !value || len == 0)
		return -EINVAL;

	size = h3_varint_decode_len(buf[0]);
	if (len < size)
		return -EAGAIN;

	switch (size) {
	case 1:
		result = buf[0] & 0x3f;
		break;
	case 2:
		result = get_unaligned_be16(buf) & 0x3fff;
		break;
	case 4:
		result = get_unaligned_be32(buf) & 0x3fffffff;
		break;
	case 8:
		result = get_unaligned_be64(buf) & 0x3fffffffffffffffULL;
		break;
	default:
		return -EINVAL;
	}

	*value = result;
	return size;
}

/*
 * =============================================================================
 * Frame Header Parsing
 * =============================================================================
 */

/**
 * h3_parse_frame_header - Parse frame type and length
 * @p: Parser context
 * @type: Output frame type
 * @length: Output payload length
 *
 * Parses the frame header (type and length fields) from the buffer.
 *
 * Returns: 0 on success, negative error on failure.
 */
int h3_parse_frame_header(struct h3_frame_parser *p, u64 *type, u64 *length)
{
	int ret;
	u64 frame_type, frame_len;

	/* Parse frame type (varint) */
	ret = h3_varint_decode(p->buf, p->len, &frame_type);
	if (ret < 0)
		return ret;
	h3_parser_advance(p, ret);

	/* Parse frame length (varint) */
	ret = h3_varint_decode(p->buf, p->len, &frame_len);
	if (ret < 0)
		return ret;
	h3_parser_advance(p, ret);

	/* Sanity check on payload length */
	if (frame_len > H3_MAX_FRAME_PAYLOAD_SIZE)
		return -H3_FRAME_ERROR;

	*type = frame_type;
	*length = frame_len;
	return 0;
}

/*
 * =============================================================================
 * Individual Frame Type Parsing
 * =============================================================================
 */

/**
 * h3_parse_data_frame - Parse DATA frame payload
 * @p: Parser context
 * @frame_len: Frame payload length
 * @frame: Output frame structure
 *
 * DATA frame payload is raw data bytes.
 */
int h3_parse_data_frame(struct h3_frame_parser *p, u64 frame_len,
			struct tquic_h3_frame_data *frame)
{
	if (!h3_parser_remaining(p, frame_len))
		return -EAGAIN;

	frame->data = p->buf;
	frame->len = frame_len;

	h3_parser_advance(p, frame_len);
	return 0;
}

/**
 * h3_parse_headers_frame - Parse HEADERS frame payload
 * @p: Parser context
 * @frame_len: Frame payload length
 * @frame: Output frame structure
 *
 * HEADERS frame payload is QPACK-encoded header block.
 */
int h3_parse_headers_frame(struct h3_frame_parser *p, u64 frame_len,
			   struct tquic_h3_frame_headers *frame)
{
	if (!h3_parser_remaining(p, frame_len))
		return -EAGAIN;

	frame->data = p->buf;
	frame->len = frame_len;

	h3_parser_advance(p, frame_len);
	return 0;
}

/**
 * h3_parse_cancel_push_frame - Parse CANCEL_PUSH frame payload
 * @p: Parser context
 * @frame_len: Frame payload length
 * @frame: Output frame structure
 *
 * CANCEL_PUSH payload is a single varint (push ID).
 */
int h3_parse_cancel_push_frame(struct h3_frame_parser *p, u64 frame_len,
			       struct tquic_h3_frame_cancel_push *frame)
{
	const u8 *start = p->buf;
	int ret;

	ret = h3_varint_decode(p->buf, p->len, &frame->push_id);
	if (ret < 0)
		return ret;
	h3_parser_advance(p, ret);

	/* Verify we consumed exactly frame_len bytes */
	if ((size_t)(p->buf - start) != frame_len)
		return -H3_FRAME_ERROR;

	return 0;
}

/**
 * h3_parse_settings_frame - Parse SETTINGS frame payload
 * @p: Parser context
 * @frame_len: Frame payload length
 * @frame: Output frame structure
 * @entries_buf: Buffer for settings entries
 * @max_entries: Maximum entries to parse
 *
 * SETTINGS payload is a sequence of (identifier, value) varint pairs.
 */
int h3_parse_settings_frame(struct h3_frame_parser *p, u64 frame_len,
			    struct tquic_h3_frame_settings *frame,
			    struct tquic_h3_frame_settings_entry *entries_buf,
			    u32 max_entries)
{
	const u8 *end;
	u32 count = 0;
	int ret;

	/* Validate frame_len fits in size_t before pointer arithmetic */
	if (frame_len > (u64)SIZE_MAX)
		return -EINVAL;

	if (!h3_parser_remaining(p, frame_len))
		return -EAGAIN;

	end = p->buf + (size_t)frame_len;

	frame->entries = entries_buf;
	frame->count = 0;

	while (p->buf < end) {
		u64 id, value;

		/* Parse setting identifier */
		ret = h3_varint_decode(p->buf, end - p->buf, &id);
		if (ret < 0)
			return ret;
		h3_parser_advance(p, ret);

		/* Parse setting value */
		ret = h3_varint_decode(p->buf, end - p->buf, &value);
		if (ret < 0)
			return ret;
		h3_parser_advance(p, ret);

		/* Skip GREASE identifiers per RFC 9114 Section 7.2.4.1 */
		if (tquic_h3_is_grease_id(id))
			continue;

		/*
		 * CF-333: Don't write past entries_buf boundary,
		 * but keep parsing to validate the rest of the frame.
		 */
		if (count < max_entries && entries_buf) {
			entries_buf[count].id = id;
			entries_buf[count].value = value;
		}
		count++;
	}

	/* Check for leftover data (malformed) */
	if (p->buf != end)
		return -H3_FRAME_ERROR;

	frame->count = count;
	return 0;
}

/**
 * h3_parse_push_promise_frame - Parse PUSH_PROMISE frame payload
 * @p: Parser context
 * @frame_len: Frame payload length
 * @frame: Output frame structure
 *
 * PUSH_PROMISE payload is push ID (varint) followed by QPACK headers.
 */
int h3_parse_push_promise_frame(struct h3_frame_parser *p, u64 frame_len,
				struct tquic_h3_frame_push_promise *frame)
{
	const u8 *start = p->buf;
	size_t push_id_len;
	int ret;

	if (!h3_parser_remaining(p, frame_len))
		return -EAGAIN;

	/* Parse push ID */
	ret = h3_varint_decode(p->buf, p->len, &frame->push_id);
	if (ret < 0)
		return ret;
	push_id_len = ret;
	h3_parser_advance(p, ret);

	/* Rest is encoded headers */
	if (frame_len < push_id_len)
		return -H3_FRAME_ERROR;

	frame->data = p->buf;
	frame->len = frame_len - push_id_len;

	h3_parser_advance(p, frame->len);

	/* Verify we consumed exactly frame_len bytes */
	if ((size_t)(p->buf - start) != frame_len)
		return -H3_FRAME_ERROR;

	return 0;
}

/**
 * h3_parse_goaway_frame - Parse GOAWAY frame payload
 * @p: Parser context
 * @frame_len: Frame payload length
 * @frame: Output frame structure
 *
 * GOAWAY payload is a single varint (stream or push ID).
 */
int h3_parse_goaway_frame(struct h3_frame_parser *p, u64 frame_len,
			  struct tquic_h3_frame_goaway *frame)
{
	const u8 *start = p->buf;
	int ret;

	ret = h3_varint_decode(p->buf, p->len, &frame->id);
	if (ret < 0)
		return ret;
	h3_parser_advance(p, ret);

	/* Verify we consumed exactly frame_len bytes */
	if ((size_t)(p->buf - start) != frame_len)
		return -H3_FRAME_ERROR;

	return 0;
}

/**
 * h3_parse_max_push_id_frame - Parse MAX_PUSH_ID frame payload
 * @p: Parser context
 * @frame_len: Frame payload length
 * @frame: Output frame structure
 *
 * MAX_PUSH_ID payload is a single varint (maximum push ID).
 */
int h3_parse_max_push_id_frame(struct h3_frame_parser *p, u64 frame_len,
			       struct tquic_h3_frame_max_push_id *frame)
{
	const u8 *start = p->buf;
	int ret;

	ret = h3_varint_decode(p->buf, p->len, &frame->push_id);
	if (ret < 0)
		return ret;
	h3_parser_advance(p, ret);

	/* Verify we consumed exactly frame_len bytes */
	if ((size_t)(p->buf - start) != frame_len)
		return -H3_FRAME_ERROR;

	return 0;
}

/*
 * =============================================================================
 * Public Frame Parsing API
 * =============================================================================
 */

/**
 * tquic_h3_parse_frame - Parse HTTP/3 frame from buffer
 * @buf: Input buffer
 * @len: Buffer length
 * @frame: Output frame structure
 * @entries_buf: Buffer for settings entries (if parsing SETTINGS)
 * @max_entries: Maximum entries in buffer
 *
 * Returns: Number of bytes consumed on success, negative error on failure.
 */
int tquic_h3_parse_frame(const u8 *buf, size_t len,
			 struct tquic_h3_frame *frame,
			 struct tquic_h3_frame_settings_entry *entries_buf,
			 u32 max_entries)
{
	struct h3_frame_parser parser;
	u64 type, payload_len;
	int ret;

	if (!buf || !frame)
		return -EINVAL;

	h3_parser_init(&parser, buf, len);

	/* Parse frame header */
	ret = h3_parse_frame_header(&parser, &type, &payload_len);
	if (ret < 0)
		return ret;

	frame->type = type;

	/* Check if we have the complete payload */
	if (!h3_parser_remaining(&parser, payload_len))
		return -EAGAIN;

	/* Parse frame-type-specific payload */
	switch (type) {
	case H3_FRAME_DATA:
		ret = h3_parse_data_frame(&parser, payload_len, &frame->data);
		break;

	case H3_FRAME_HEADERS:
		ret = h3_parse_headers_frame(&parser, payload_len,
					     &frame->headers);
		break;

	case H3_FRAME_CANCEL_PUSH:
		ret = h3_parse_cancel_push_frame(&parser, payload_len,
						 &frame->cancel_push);
		break;

	case H3_FRAME_SETTINGS:
		ret = h3_parse_settings_frame(&parser, payload_len,
					      &frame->settings,
					      entries_buf, max_entries);
		break;

	case H3_FRAME_PUSH_PROMISE:
		ret = h3_parse_push_promise_frame(&parser, payload_len,
						  &frame->push_promise);
		break;

	case H3_FRAME_GOAWAY:
		ret = h3_parse_goaway_frame(&parser, payload_len,
					    &frame->goaway);
		break;

	case H3_FRAME_MAX_PUSH_ID:
		ret = h3_parse_max_push_id_frame(&parser, payload_len,
						 &frame->max_push_id);
		break;

	default:
		/* Unknown frame type - skip it per RFC 9114 Section 7.2.8 */
		if (tquic_h3_is_grease_id(type)) {
			h3_parser_advance(&parser, payload_len);
			ret = 0;
		} else {
			/* Skip unknown frame types for forward compatibility */
			h3_parser_advance(&parser, payload_len);
			ret = 0;
		}
		break;
	}

	if (ret < 0)
		return ret;

	frame->raw_len = parser.consumed;
	return parser.consumed;
}
EXPORT_SYMBOL_GPL(tquic_h3_parse_frame);

/*
 * =============================================================================
 * Frame Header Writing
 * =============================================================================
 */

/**
 * h3_write_frame_header - Write frame type and length
 * @w: Writer context
 * @type: Frame type
 * @length: Payload length
 *
 * Returns: 0 on success, negative error on failure.
 */
int h3_write_frame_header(struct h3_frame_writer *w, u64 type, u64 length)
{
	int ret;

	/* Write frame type */
	ret = h3_varint_encode(type, w->buf, w->len);
	if (ret < 0)
		return ret;
	h3_writer_advance(w, ret);

	/* Write frame length */
	ret = h3_varint_encode(length, w->buf, w->len);
	if (ret < 0)
		return ret;
	h3_writer_advance(w, ret);

	return 0;
}

/*
 * =============================================================================
 * Individual Frame Type Writing
 * =============================================================================
 */

/**
 * tquic_h3_write_data_frame - Write DATA frame
 * @buf: Output buffer
 * @len: Buffer length
 * @data: Payload data
 * @data_len: Payload length
 *
 * Returns: Bytes written on success, negative error on failure.
 */
int tquic_h3_write_data_frame(u8 *buf, size_t len,
			      const u8 *data, u64 data_len)
{
	struct h3_frame_writer writer;
	int ret;

	if (!buf || (!data && data_len > 0))
		return -EINVAL;

	h3_writer_init(&writer, buf, len);

	/* Write header */
	ret = h3_write_frame_header(&writer, H3_FRAME_DATA, data_len);
	if (ret < 0)
		return ret;

	/* Write payload */
	if (!h3_writer_remaining(&writer, data_len))
		return -ENOSPC;

	if (data_len > 0) {
		memcpy(writer.buf, data, data_len);
		h3_writer_advance(&writer, data_len);
	}

	return writer.written;
}
EXPORT_SYMBOL_GPL(tquic_h3_write_data_frame);

/**
 * tquic_h3_write_headers_frame - Write HEADERS frame
 * @buf: Output buffer
 * @len: Buffer length
 * @data: QPACK-encoded headers
 * @data_len: Headers length
 *
 * Returns: Bytes written on success, negative error on failure.
 */
int tquic_h3_write_headers_frame(u8 *buf, size_t len,
				 const u8 *data, u64 data_len)
{
	struct h3_frame_writer writer;
	int ret;

	if (!buf || (!data && data_len > 0))
		return -EINVAL;

	h3_writer_init(&writer, buf, len);

	/* Write header */
	ret = h3_write_frame_header(&writer, H3_FRAME_HEADERS, data_len);
	if (ret < 0)
		return ret;

	/* Write payload */
	if (!h3_writer_remaining(&writer, data_len))
		return -ENOSPC;

	if (data_len > 0) {
		memcpy(writer.buf, data, data_len);
		h3_writer_advance(&writer, data_len);
	}

	return writer.written;
}
EXPORT_SYMBOL_GPL(tquic_h3_write_headers_frame);

/**
 * tquic_h3_write_cancel_push_frame - Write CANCEL_PUSH frame
 * @buf: Output buffer
 * @len: Buffer length
 * @push_id: Push ID to cancel
 *
 * Returns: Bytes written on success, negative error on failure.
 */
int tquic_h3_write_cancel_push_frame(u8 *buf, size_t len, u64 push_id)
{
	struct h3_frame_writer writer;
	int payload_len;
	int ret;

	if (!buf)
		return -EINVAL;

	payload_len = h3_varint_size(push_id);
	if (payload_len == 0)
		return -EOVERFLOW;

	h3_writer_init(&writer, buf, len);

	/* Write header */
	ret = h3_write_frame_header(&writer, H3_FRAME_CANCEL_PUSH, payload_len);
	if (ret < 0)
		return ret;

	/* Write payload (push ID) */
	ret = h3_varint_encode(push_id, writer.buf, writer.len);
	if (ret < 0)
		return ret;
	h3_writer_advance(&writer, ret);

	return writer.written;
}
EXPORT_SYMBOL_GPL(tquic_h3_write_cancel_push_frame);

/**
 * h3_settings_encoded_size - Calculate encoded settings size
 * @settings: Settings to encode
 *
 * Returns: Size in bytes needed for encoding.
 */
size_t h3_settings_encoded_size(const struct tquic_h3_settings *settings)
{
	size_t size = 0;

	/* QPACK_MAX_TABLE_CAPACITY */
	if (settings->qpack_max_table_capacity != 0) {
		size += h3_varint_size(H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY);
		size += h3_varint_size(settings->qpack_max_table_capacity);
	}

	/* MAX_FIELD_SECTION_SIZE */
	if (settings->max_field_section_size != H3_DEFAULT_MAX_FIELD_SECTION_SIZE) {
		size += h3_varint_size(H3_SETTINGS_MAX_FIELD_SECTION_SIZE);
		size += h3_varint_size(settings->max_field_section_size);
	}

	/* QPACK_BLOCKED_STREAMS */
	if (settings->qpack_blocked_streams != 0) {
		size += h3_varint_size(H3_SETTINGS_QPACK_BLOCKED_STREAMS);
		size += h3_varint_size(settings->qpack_blocked_streams);
	}

	return size;
}

/**
 * tquic_h3_write_settings_frame - Write SETTINGS frame
 * @buf: Output buffer
 * @len: Buffer length
 * @settings: Settings to encode
 *
 * Returns: Bytes written on success, negative error on failure.
 */
int tquic_h3_write_settings_frame(u8 *buf, size_t len,
				  const struct tquic_h3_settings *settings)
{
	struct h3_frame_writer writer;
	size_t payload_len;
	int ret;

	if (!buf || !settings)
		return -EINVAL;

	payload_len = h3_settings_encoded_size(settings);

	h3_writer_init(&writer, buf, len);

	/* Write header */
	ret = h3_write_frame_header(&writer, H3_FRAME_SETTINGS, payload_len);
	if (ret < 0)
		return ret;

	/* Write settings entries */
	if (settings->qpack_max_table_capacity != 0) {
		ret = h3_varint_encode(H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY,
				       writer.buf, writer.len);
		if (ret < 0)
			return ret;
		h3_writer_advance(&writer, ret);

		ret = h3_varint_encode(settings->qpack_max_table_capacity,
				       writer.buf, writer.len);
		if (ret < 0)
			return ret;
		h3_writer_advance(&writer, ret);
	}

	if (settings->max_field_section_size != H3_DEFAULT_MAX_FIELD_SECTION_SIZE) {
		ret = h3_varint_encode(H3_SETTINGS_MAX_FIELD_SECTION_SIZE,
				       writer.buf, writer.len);
		if (ret < 0)
			return ret;
		h3_writer_advance(&writer, ret);

		ret = h3_varint_encode(settings->max_field_section_size,
				       writer.buf, writer.len);
		if (ret < 0)
			return ret;
		h3_writer_advance(&writer, ret);
	}

	if (settings->qpack_blocked_streams != 0) {
		ret = h3_varint_encode(H3_SETTINGS_QPACK_BLOCKED_STREAMS,
				       writer.buf, writer.len);
		if (ret < 0)
			return ret;
		h3_writer_advance(&writer, ret);

		ret = h3_varint_encode(settings->qpack_blocked_streams,
				       writer.buf, writer.len);
		if (ret < 0)
			return ret;
		h3_writer_advance(&writer, ret);
	}

	return writer.written;
}
EXPORT_SYMBOL_GPL(tquic_h3_write_settings_frame);

/**
 * tquic_h3_write_push_promise_frame - Write PUSH_PROMISE frame
 * @buf: Output buffer
 * @len: Buffer length
 * @push_id: Push ID
 * @headers: QPACK-encoded headers
 * @headers_len: Headers length
 *
 * Returns: Bytes written on success, negative error on failure.
 */
int tquic_h3_write_push_promise_frame(u8 *buf, size_t len,
				      u64 push_id,
				      const u8 *headers, u64 headers_len)
{
	struct h3_frame_writer writer;
	int push_id_size;
	int ret;

	if (!buf || (!headers && headers_len > 0))
		return -EINVAL;

	push_id_size = h3_varint_size(push_id);
	if (push_id_size == 0)
		return -EOVERFLOW;

	h3_writer_init(&writer, buf, len);

	/* Write header */
	ret = h3_write_frame_header(&writer, H3_FRAME_PUSH_PROMISE,
				    push_id_size + headers_len);
	if (ret < 0)
		return ret;

	/* Write push ID */
	ret = h3_varint_encode(push_id, writer.buf, writer.len);
	if (ret < 0)
		return ret;
	h3_writer_advance(&writer, ret);

	/* Write encoded headers */
	if (!h3_writer_remaining(&writer, headers_len))
		return -ENOSPC;

	if (headers_len > 0) {
		memcpy(writer.buf, headers, headers_len);
		h3_writer_advance(&writer, headers_len);
	}

	return writer.written;
}
EXPORT_SYMBOL_GPL(tquic_h3_write_push_promise_frame);

/**
 * tquic_h3_write_goaway_frame - Write GOAWAY frame
 * @buf: Output buffer
 * @len: Buffer length
 * @id: Stream or push ID
 *
 * Returns: Bytes written on success, negative error on failure.
 */
int tquic_h3_write_goaway_frame(u8 *buf, size_t len, u64 id)
{
	struct h3_frame_writer writer;
	int payload_len;
	int ret;

	if (!buf)
		return -EINVAL;

	payload_len = h3_varint_size(id);
	if (payload_len == 0)
		return -EOVERFLOW;

	h3_writer_init(&writer, buf, len);

	/* Write header */
	ret = h3_write_frame_header(&writer, H3_FRAME_GOAWAY, payload_len);
	if (ret < 0)
		return ret;

	/* Write ID */
	ret = h3_varint_encode(id, writer.buf, writer.len);
	if (ret < 0)
		return ret;
	h3_writer_advance(&writer, ret);

	return writer.written;
}
EXPORT_SYMBOL_GPL(tquic_h3_write_goaway_frame);

/**
 * tquic_h3_write_max_push_id_frame - Write MAX_PUSH_ID frame
 * @buf: Output buffer
 * @len: Buffer length
 * @push_id: Maximum push ID
 *
 * Returns: Bytes written on success, negative error on failure.
 */
int tquic_h3_write_max_push_id_frame(u8 *buf, size_t len, u64 push_id)
{
	struct h3_frame_writer writer;
	int payload_len;
	int ret;

	if (!buf)
		return -EINVAL;

	payload_len = h3_varint_size(push_id);
	if (payload_len == 0)
		return -EOVERFLOW;

	h3_writer_init(&writer, buf, len);

	/* Write header */
	ret = h3_write_frame_header(&writer, H3_FRAME_MAX_PUSH_ID, payload_len);
	if (ret < 0)
		return ret;

	/* Write push ID */
	ret = h3_varint_encode(push_id, writer.buf, writer.len);
	if (ret < 0)
		return ret;
	h3_writer_advance(&writer, ret);

	return writer.written;
}
EXPORT_SYMBOL_GPL(tquic_h3_write_max_push_id_frame);

/*
 * =============================================================================
 * Frame Size Calculation
 * =============================================================================
 */

/**
 * tquic_h3_data_frame_size - Calculate DATA frame wire size
 * @data_len: Payload length
 */
size_t tquic_h3_data_frame_size(u64 data_len)
{
	return h3_varint_size(H3_FRAME_DATA) +
	       h3_varint_size(data_len) +
	       data_len;
}
EXPORT_SYMBOL_GPL(tquic_h3_data_frame_size);

/**
 * tquic_h3_headers_frame_size - Calculate HEADERS frame wire size
 * @headers_len: Encoded headers length
 */
size_t tquic_h3_headers_frame_size(u64 headers_len)
{
	return h3_varint_size(H3_FRAME_HEADERS) +
	       h3_varint_size(headers_len) +
	       headers_len;
}
EXPORT_SYMBOL_GPL(tquic_h3_headers_frame_size);

/**
 * tquic_h3_cancel_push_frame_size - Calculate CANCEL_PUSH frame wire size
 * @push_id: Push ID
 */
size_t tquic_h3_cancel_push_frame_size(u64 push_id)
{
	int payload_len = h3_varint_size(push_id);

	return h3_varint_size(H3_FRAME_CANCEL_PUSH) +
	       h3_varint_size(payload_len) +
	       payload_len;
}
EXPORT_SYMBOL_GPL(tquic_h3_cancel_push_frame_size);

/**
 * tquic_h3_settings_frame_size - Calculate SETTINGS frame wire size
 * @settings: Settings structure
 */
size_t tquic_h3_settings_frame_size(const struct tquic_h3_settings *settings)
{
	size_t payload_len;

	if (!settings)
		return 0;

	payload_len = h3_settings_encoded_size(settings);

	return h3_varint_size(H3_FRAME_SETTINGS) +
	       h3_varint_size(payload_len) +
	       payload_len;
}
EXPORT_SYMBOL_GPL(tquic_h3_settings_frame_size);

/**
 * tquic_h3_push_promise_frame_size - Calculate PUSH_PROMISE frame wire size
 * @push_id: Push ID
 * @headers_len: Encoded headers length
 */
size_t tquic_h3_push_promise_frame_size(u64 push_id, u64 headers_len)
{
	int push_id_size = h3_varint_size(push_id);

	return h3_varint_size(H3_FRAME_PUSH_PROMISE) +
	       h3_varint_size(push_id_size + headers_len) +
	       push_id_size +
	       headers_len;
}
EXPORT_SYMBOL_GPL(tquic_h3_push_promise_frame_size);

/**
 * tquic_h3_goaway_frame_size - Calculate GOAWAY frame wire size
 * @id: Stream or push ID
 */
size_t tquic_h3_goaway_frame_size(u64 id)
{
	int payload_len = h3_varint_size(id);

	return h3_varint_size(H3_FRAME_GOAWAY) +
	       h3_varint_size(payload_len) +
	       payload_len;
}
EXPORT_SYMBOL_GPL(tquic_h3_goaway_frame_size);

/**
 * tquic_h3_max_push_id_frame_size - Calculate MAX_PUSH_ID frame wire size
 * @push_id: Maximum push ID
 */
size_t tquic_h3_max_push_id_frame_size(u64 push_id)
{
	int payload_len = h3_varint_size(push_id);

	return h3_varint_size(H3_FRAME_MAX_PUSH_ID) +
	       h3_varint_size(payload_len) +
	       payload_len;
}
EXPORT_SYMBOL_GPL(tquic_h3_max_push_id_frame_size);

/**
 * tquic_h3_frame_size - Calculate wire size of generic frame
 * @frame: Frame structure
 */
size_t tquic_h3_frame_size(const struct tquic_h3_frame *frame)
{
	if (!frame)
		return 0;

	switch (frame->type) {
	case H3_FRAME_DATA:
		return tquic_h3_data_frame_size(frame->data.len);

	case H3_FRAME_HEADERS:
		return tquic_h3_headers_frame_size(frame->headers.len);

	case H3_FRAME_CANCEL_PUSH:
		return tquic_h3_cancel_push_frame_size(frame->cancel_push.push_id);

	case H3_FRAME_SETTINGS:
		/* Cannot compute without full settings data */
		return 0;

	case H3_FRAME_PUSH_PROMISE:
		return tquic_h3_push_promise_frame_size(frame->push_promise.push_id,
							frame->push_promise.len);

	case H3_FRAME_GOAWAY:
		return tquic_h3_goaway_frame_size(frame->goaway.id);

	case H3_FRAME_MAX_PUSH_ID:
		return tquic_h3_max_push_id_frame_size(frame->max_push_id.push_id);

	default:
		return 0;
	}
}
EXPORT_SYMBOL_GPL(tquic_h3_frame_size);

/*
 * =============================================================================
 * Utility Functions
 * =============================================================================
 */

/**
 * tquic_h3_frame_type_name - Get human-readable frame type name
 * @type: Frame type value
 */
const char *tquic_h3_frame_type_name(u64 type)
{
	switch (type) {
	case H3_FRAME_DATA:
		return "DATA";
	case H3_FRAME_HEADERS:
		return "HEADERS";
	case H3_FRAME_CANCEL_PUSH:
		return "CANCEL_PUSH";
	case H3_FRAME_SETTINGS:
		return "SETTINGS";
	case H3_FRAME_PUSH_PROMISE:
		return "PUSH_PROMISE";
	case H3_FRAME_GOAWAY:
		return "GOAWAY";
	case H3_FRAME_MAX_PUSH_ID:
		return "MAX_PUSH_ID";
	case TQUIC_H3_FRAME_PRIORITY_UPDATE:
		return "PRIORITY_UPDATE";
	default:
		if (tquic_h3_is_grease_id(type))
			return "GREASE";
		return "UNKNOWN";
	}
}
EXPORT_SYMBOL_GPL(tquic_h3_frame_type_name);

/**
 * tquic_h3_error_name - Get human-readable error name
 * @error: Error code value
 */
const char *tquic_h3_error_name(u64 error)
{
	switch (error) {
	case H3_NO_ERROR:
		return "H3_NO_ERROR";
	case H3_GENERAL_PROTOCOL_ERROR:
		return "H3_GENERAL_PROTOCOL_ERROR";
	case H3_INTERNAL_ERROR:
		return "H3_INTERNAL_ERROR";
	case H3_STREAM_CREATION_ERROR:
		return "H3_STREAM_CREATION_ERROR";
	case H3_CLOSED_CRITICAL_STREAM:
		return "H3_CLOSED_CRITICAL_STREAM";
	case H3_FRAME_UNEXPECTED:
		return "H3_FRAME_UNEXPECTED";
	case H3_FRAME_ERROR:
		return "H3_FRAME_ERROR";
	case H3_EXCESSIVE_LOAD:
		return "H3_EXCESSIVE_LOAD";
	case H3_ID_ERROR:
		return "H3_ID_ERROR";
	case H3_SETTINGS_ERROR:
		return "H3_SETTINGS_ERROR";
	case H3_MISSING_SETTINGS:
		return "H3_MISSING_SETTINGS";
	case H3_REQUEST_REJECTED:
		return "H3_REQUEST_REJECTED";
	case H3_REQUEST_CANCELLED:
		return "H3_REQUEST_CANCELLED";
	case H3_REQUEST_INCOMPLETE:
		return "H3_REQUEST_INCOMPLETE";
	case H3_MESSAGE_ERROR:
		return "H3_MESSAGE_ERROR";
	case H3_CONNECT_ERROR:
		return "H3_CONNECT_ERROR";
	case H3_VERSION_FALLBACK:
		return "H3_VERSION_FALLBACK";
	default:
		return "UNKNOWN";
	}
}
EXPORT_SYMBOL_GPL(tquic_h3_error_name);

/*
 * =============================================================================
 * Frame Validation
 * =============================================================================
 */

/**
 * h3_frame_valid_on_control_stream - Check if frame type valid on control stream
 * @type: Frame type
 *
 * Returns true if the frame type may appear on the control stream.
 */
bool h3_frame_valid_on_control_stream(u64 type)
{
	switch (type) {
	case H3_FRAME_CANCEL_PUSH:
	case H3_FRAME_SETTINGS:
	case H3_FRAME_GOAWAY:
	case H3_FRAME_MAX_PUSH_ID:
	case TQUIC_H3_FRAME_PRIORITY_UPDATE:	/* RFC 9218 */
		return true;
	default:
		/* GREASE frames allowed anywhere */
		return tquic_h3_is_grease_id(type);
	}
}

/**
 * h3_frame_valid_on_request_stream - Check if frame type valid on request stream
 * @type: Frame type
 *
 * Returns true if the frame type may appear on a request stream.
 */
bool h3_frame_valid_on_request_stream(u64 type)
{
	switch (type) {
	case H3_FRAME_DATA:
	case H3_FRAME_HEADERS:
	case H3_FRAME_PUSH_PROMISE:  /* Server only */
		return true;
	default:
		/* GREASE frames allowed anywhere */
		return tquic_h3_is_grease_id(type);
	}
}

/**
 * h3_frame_valid_on_push_stream - Check if frame type valid on push stream
 * @type: Frame type
 *
 * Returns true if the frame type may appear on a push stream.
 */
bool h3_frame_valid_on_push_stream(u64 type)
{
	switch (type) {
	case H3_FRAME_DATA:
	case H3_FRAME_HEADERS:
		return true;
	default:
		/* GREASE frames allowed anywhere */
		return tquic_h3_is_grease_id(type);
	}
}

MODULE_DESCRIPTION("TQUIC HTTP/3 Frame Layer");
MODULE_LICENSE("GPL");
