// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: WAN Bonding over QUIC - Frame Parsing and Construction
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * This file implements QUIC frame parsing, construction, and size calculation
 * according to RFC 9000. All frame types are supported including:
 * - PADDING, PING
 * - ACK (with ECN counts)
 * - RESET_STREAM, STOP_SENDING
 * - CRYPTO, NEW_TOKEN
 * - STREAM (with offset/length/fin handling)
 * - MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS
 * - DATA_BLOCKED, STREAM_DATA_BLOCKED, STREAMS_BLOCKED
 * - NEW_CONNECTION_ID, RETIRE_CONNECTION_ID
 * - PATH_CHALLENGE, PATH_RESPONSE
 * - CONNECTION_CLOSE
 * - HANDSHAKE_DONE
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/bug.h>
#include <linux/limits.h>
#include <linux/overflow.h>
#include <net/tquic.h>
#include <net/tquic_frame.h>
#include "../tquic_debug.h"

/*
 * SECURITY FIX: Defense against size_t underflow in frame parsing.
 *
 * When parsing untrusted network input, we must guard against arithmetic
 * underflow on size_t variables. A malformed frame could cause 'remaining'
 * to wrap around to a huge value, leading to buffer over-reads or worse.
 *
 * This macro validates that we have sufficient bytes BEFORE any subtraction,
 * providing defense-in-depth even when called functions also validate bounds.
 */

/**
 * FRAME_ADVANCE_SAFE - Safely advance parser position with underflow protection
 * @p: Pointer to current position (updated on success)
 * @remaining: Bytes remaining in buffer (updated on success)
 * @n: Number of bytes to advance
 *
 * Returns 0 on success, -EPROTO if advancing would underflow.
 * This provides defense-in-depth against malformed input that could
 * cause size_t underflow and subsequent buffer over-reads.
 */
#define FRAME_ADVANCE_SAFE(p, remaining, n) ({			\
	int __ret = 0;						\
	size_t __n = (n);					\
	if (unlikely(__n > (remaining))) {			\
		__ret = -EPROTO;				\
	} else {						\
		(p) += __n;					\
		(remaining) -= __n;				\
	}							\
	__ret;							\
})

/**
 * frame_check_remaining - Validate sufficient bytes remain before operation
 * @remaining: Current remaining byte count
 * @needed: Number of bytes needed
 *
 * Returns true if sufficient bytes available, false otherwise.
 * Use this for explicit bounds checks before any buffer access.
 */
static inline bool frame_check_remaining(size_t remaining, size_t needed)
{
	return remaining >= needed;
}

/* =========================================================================
 * QUIC Variable-Length Integer Encoding (RFC 9000, Section 16)
 *
 * QUIC varints use the two most significant bits to encode the length:
 * - 00: 1 byte  (6-bit value,  max 63)
 * - 01: 2 bytes (14-bit value, max 16383)
 * - 10: 4 bytes (30-bit value, max 1073741823)
 * - 11: 8 bytes (62-bit value, max 4611686018427387903)
 * ========================================================================= */

/**
 * frame_varint_len - Get the encoded length of a varint value (local helper)
 * @val: Value to encode
 *
 * Returns the number of bytes needed to encode the value, or 0 if
 * the value is too large.
 */
static inline size_t frame_varint_len(u64 val)
{
	if (val <= 63)
		return 1;
	if (val <= 16383)
		return 2;
	if (val <= 1073741823)
		return 4;
	if (val <= TQUIC_MAX_VARINT)
		return 8;
	return 0;  /* Value too large */
}

/**
 * frame_varint_decode_len - Get length from first byte of encoded varint
 * @first_byte: First byte of the encoded varint
 *
 * Returns the total number of bytes in the encoded varint.
 */
static inline size_t frame_varint_decode_len(u8 first_byte)
{
	return 1 << (first_byte >> 6);
}

/**
 * frame_varint_decode - Decode a QUIC variable-length integer (local helper)
 * @buf: Buffer containing the encoded varint
 * @buf_len: Length of the buffer
 * @val: Output parameter for decoded value
 * @consumed: Output parameter for bytes consumed
 *
 * Returns 0 on success, negative error code on failure.
 */
static int frame_varint_decode(const u8 *buf, size_t buf_len,
			       u64 *val, size_t *consumed)
{
	size_t len;
	u64 v;

	if (buf_len < 1)
		return -EINVAL;

	len = frame_varint_decode_len(buf[0]);
	if (buf_len < len)
		return -EINVAL;

	switch (len) {
	case 1:
		v = buf[0] & 0x3f;
		break;
	case 2:
		v = ((u64)(buf[0] & 0x3f) << 8) | buf[1];
		break;
	case 4:
		v = ((u64)(buf[0] & 0x3f) << 24) |
		    ((u64)buf[1] << 16) |
		    ((u64)buf[2] << 8) |
		    buf[3];
		break;
	case 8:
		v = ((u64)(buf[0] & 0x3f) << 56) |
		    ((u64)buf[1] << 48) |
		    ((u64)buf[2] << 40) |
		    ((u64)buf[3] << 32) |
		    ((u64)buf[4] << 24) |
		    ((u64)buf[5] << 16) |
		    ((u64)buf[6] << 8) |
		    buf[7];
		break;
	default:
		return -EINVAL;
	}

	*val = v;
	if (consumed)
		*consumed = len;
	return 0;
}

/**
 * frame_varint_encode - Encode a QUIC variable-length integer (local helper)
 * @val: Value to encode
 * @buf: Buffer to write encoded value
 * @buf_len: Length of the buffer
 *
 * Returns number of bytes written on success, negative error code on failure.
 */
static int frame_varint_encode(u64 val, u8 *buf, size_t buf_len)
{
	size_t len = frame_varint_len(val);

	if (len == 0)
		return -EOVERFLOW;
	if (buf_len < len)
		return -ENOSPC;

	switch (len) {
	case 1:
		buf[0] = (u8)val;
		break;
	case 2:
		buf[0] = 0x40 | (u8)(val >> 8);
		buf[1] = (u8)val;
		break;
	case 4:
		buf[0] = 0x80 | (u8)(val >> 24);
		buf[1] = (u8)(val >> 16);
		buf[2] = (u8)(val >> 8);
		buf[3] = (u8)val;
		break;
	case 8:
		buf[0] = 0xc0 | (u8)(val >> 56);
		buf[1] = (u8)(val >> 48);
		buf[2] = (u8)(val >> 40);
		buf[3] = (u8)(val >> 32);
		buf[4] = (u8)(val >> 24);
		buf[5] = (u8)(val >> 16);
		buf[6] = (u8)(val >> 8);
		buf[7] = (u8)val;
		break;
	}

	return (int)len;
}

/* =========================================================================
 * Frame Parsing Functions
 * ========================================================================= */

/**
 * tquic_parse_padding_frame - Parse PADDING frame
 * @buf: Buffer containing the frame
 * @buf_len: Length of the buffer
 * @frame: Output frame structure
 *
 * SECURITY: Counts consecutive PADDING (0x00) bytes with explicit bounds check.
 * The loop is bounded by buf_len preventing any buffer over-read.
 * Returns bytes consumed on success, negative error code on failure.
 */
static int tquic_parse_padding_frame(const u8 *buf, size_t buf_len,
				     struct tquic_frame *frame)
{
	size_t count = 0;

	/*
	 * SECURITY: Loop is bounded by buf_len; count can never exceed buf_len.
	 * Each iteration checks count < buf_len before accessing buf[count].
	 */
	while (count < buf_len && buf[count] == TQUIC_FRAME_PADDING)
		count++;

	frame->type = TQUIC_FRAME_PADDING;
	frame->padding.length = count;
	return (int)count;
}

/**
 * tquic_parse_ping_frame - Parse PING frame
 * @buf: Buffer containing the frame (starting at frame type)
 * @buf_len: Length of the buffer
 * @frame: Output frame structure
 *
 * SECURITY: Fixed-size frame (type byte only) with explicit bounds check.
 * PING frames have no payload, just the type byte.
 * Returns bytes consumed on success, negative error code on failure.
 */
static int tquic_parse_ping_frame(const u8 *buf, size_t buf_len,
				  struct tquic_frame *frame)
{
	if (!frame_check_remaining(buf_len, 1))
		return -EINVAL;

	frame->type = TQUIC_FRAME_PING;
	return 1;
}

/**
 * tquic_parse_ack_frame - Parse ACK frame (with or without ECN)
 * @buf: Buffer containing the frame
 * @buf_len: Length of the buffer
 * @frame: Output frame structure
 * @has_ecn: Whether this is an ACK_ECN frame
 * @ranges_buf: Buffer to store ACK ranges (caller-provided)
 * @max_ranges: Maximum number of ranges the buffer can hold
 *
 * SECURITY: This function handles untrusted network input. All arithmetic
 * on size_t variables uses explicit bounds checking to prevent underflow
 * that could lead to buffer over-reads or remote code execution.
 *
 * Returns bytes consumed on success, negative error code on failure.
 * Returns -EINVAL for invalid input, -EPROTO for malformed frames,
 * -EOVERFLOW if range count exceeds maximum.
 */
static int tquic_parse_ack_frame(const u8 *buf, size_t buf_len,
				 struct tquic_frame *frame, bool has_ecn,
				 struct tquic_ack_range *ranges_buf,
				 size_t max_ranges)
{
	const u8 *p = buf;
	size_t remaining = buf_len;
	size_t consumed = 0;  /* Initialize to prevent use of garbage on error paths */
	u64 i;
	int ret;

	/*
	 * SECURITY: Validate minimum frame size upfront.
	 * ACK frame requires at least: type(1) + largest_ack(1) + delay(1) +
	 * range_count(1) + first_range(1) = 5 bytes minimum.
	 */
	if (!frame_check_remaining(remaining, 1))
		return -EINVAL;

	if (!ranges_buf && max_ranges > 0)
		return -EINVAL;

	/* Skip frame type - already validated above */
	ret = FRAME_ADVANCE_SAFE(p, remaining, 1);
	if (ret < 0)
		return ret;

	frame->type = has_ecn ? TQUIC_FRAME_ACK_ECN : TQUIC_FRAME_ACK;
	frame->ack.has_ecn = has_ecn;
	frame->ack.ranges = ranges_buf;

	/*
	 * SECURITY: Each varint decode is followed by explicit bounds check
	 * before advancing. Even though frame_varint_decode() checks bounds
	 * internally, we verify at caller site for defense-in-depth.
	 */

	/* Largest Acknowledged */
	ret = frame_varint_decode(p, remaining, &frame->ack.largest_ack, &consumed);
	if (ret < 0)
		return ret;
	ret = FRAME_ADVANCE_SAFE(p, remaining, consumed);
	if (ret < 0)
		return ret;

	/* ACK Delay */
	ret = frame_varint_decode(p, remaining, &frame->ack.ack_delay, &consumed);
	if (ret < 0)
		return ret;
	ret = FRAME_ADVANCE_SAFE(p, remaining, consumed);
	if (ret < 0)
		return ret;

	/* ACK Range Count */
	ret = frame_varint_decode(p, remaining, &frame->ack.ack_range_count, &consumed);
	if (ret < 0)
		return ret;
	ret = FRAME_ADVANCE_SAFE(p, remaining, consumed);
	if (ret < 0)
		return ret;

	/*
	 * SECURITY: Validate range count against caller's buffer size.
	 * A malicious peer could send huge range count to exhaust resources
	 * or overflow array bounds.
	 */
	if (frame->ack.ack_range_count > (u64)max_ranges)
		return -EOVERFLOW;

	/* First ACK Range */
	ret = frame_varint_decode(p, remaining, &frame->ack.first_ack_range, &consumed);
	if (ret < 0)
		return ret;
	ret = FRAME_ADVANCE_SAFE(p, remaining, consumed);
	if (ret < 0)
		return ret;

	/*
	 * CF-207: Validate first_ack_range <= largest_ack per RFC 9000
	 * Section 19.3.1: "The smallest value is determined by subtracting
	 * the First ACK Range value from the Largest Acknowledged."
	 * If first_ack_range > largest_ack, the subtraction would underflow.
	 */
	if (frame->ack.first_ack_range > frame->ack.largest_ack)
		return -EINVAL;

	/*
	 * Additional ACK Ranges - each contains Gap + ACK Range Length.
	 * SECURITY: Loop bound is validated above against max_ranges.
	 */
	for (i = 0; i < frame->ack.ack_range_count; i++) {
		/* Gap */
		ret = frame_varint_decode(p, remaining, &ranges_buf[i].gap, &consumed);
		if (ret < 0)
			return ret;
		ret = FRAME_ADVANCE_SAFE(p, remaining, consumed);
		if (ret < 0)
			return ret;

		/* ACK Range Length */
		ret = frame_varint_decode(p, remaining, &ranges_buf[i].ack_range_len, &consumed);
		if (ret < 0)
			return ret;
		ret = FRAME_ADVANCE_SAFE(p, remaining, consumed);
		if (ret < 0)
			return ret;
	}

	/* ECN Counts (if present in ACK_ECN frame type 0x03) */
	if (has_ecn) {
		/* ECT(0) Count */
		ret = frame_varint_decode(p, remaining, &frame->ack.ect0_count, &consumed);
		if (ret < 0)
			return ret;
		ret = FRAME_ADVANCE_SAFE(p, remaining, consumed);
		if (ret < 0)
			return ret;

		/* ECT(1) Count */
		ret = frame_varint_decode(p, remaining, &frame->ack.ect1_count, &consumed);
		if (ret < 0)
			return ret;
		ret = FRAME_ADVANCE_SAFE(p, remaining, consumed);
		if (ret < 0)
			return ret;

		/* ECN-CE Count */
		ret = frame_varint_decode(p, remaining, &frame->ack.ecn_ce_count, &consumed);
		if (ret < 0)
			return ret;
		ret = FRAME_ADVANCE_SAFE(p, remaining, consumed);
		if (ret < 0)
			return ret;
	}

	/*
	 * SECURITY: Final calculation is safe because we only reach here
	 * after all FRAME_ADVANCE_SAFE calls succeeded, guaranteeing
	 * remaining <= buf_len.
	 */
	return (int)(buf_len - remaining);
}

/**
 * tquic_parse_reset_stream_frame - Parse RESET_STREAM frame
 * @buf: Buffer containing the frame
 * @buf_len: Length of the buffer
 * @frame: Output frame structure
 *
 * SECURITY: Uses bounds-checked arithmetic to prevent size_t underflow.
 * Returns bytes consumed on success, negative error code on failure.
 */
static int tquic_parse_reset_stream_frame(const u8 *buf, size_t buf_len,
					  struct tquic_frame *frame)
{
	const u8 *p = buf;
	size_t remaining = buf_len;
	size_t consumed = 0;
	int ret;

	if (!frame_check_remaining(remaining, 1))
		return -EINVAL;

	/* Skip frame type */
	ret = FRAME_ADVANCE_SAFE(p, remaining, 1);
	if (ret < 0)
		return ret;

	frame->type = TQUIC_FRAME_RESET_STREAM;

	/* Stream ID */
	ret = frame_varint_decode(p, remaining, &frame->reset_stream.stream_id, &consumed);
	if (ret < 0)
		return ret;
	ret = FRAME_ADVANCE_SAFE(p, remaining, consumed);
	if (ret < 0)
		return ret;

	/* Application Protocol Error Code */
	ret = frame_varint_decode(p, remaining, &frame->reset_stream.app_error_code, &consumed);
	if (ret < 0)
		return ret;
	ret = FRAME_ADVANCE_SAFE(p, remaining, consumed);
	if (ret < 0)
		return ret;

	/* Final Size */
	ret = frame_varint_decode(p, remaining, &frame->reset_stream.final_size, &consumed);
	if (ret < 0)
		return ret;
	ret = FRAME_ADVANCE_SAFE(p, remaining, consumed);
	if (ret < 0)
		return ret;

	return (int)(buf_len - remaining);
}

/**
 * tquic_parse_stop_sending_frame - Parse STOP_SENDING frame
 * @buf: Buffer containing the frame
 * @buf_len: Length of the buffer
 * @frame: Output frame structure
 *
 * SECURITY: Uses bounds-checked arithmetic to prevent size_t underflow.
 * Returns bytes consumed on success, negative error code on failure.
 */
static int tquic_parse_stop_sending_frame(const u8 *buf, size_t buf_len,
					  struct tquic_frame *frame)
{
	const u8 *p = buf;
	size_t remaining = buf_len;
	size_t consumed = 0;
	int ret;

	if (!frame_check_remaining(remaining, 1))
		return -EINVAL;

	/* Skip frame type */
	ret = FRAME_ADVANCE_SAFE(p, remaining, 1);
	if (ret < 0)
		return ret;

	frame->type = TQUIC_FRAME_STOP_SENDING;

	/* Stream ID */
	ret = frame_varint_decode(p, remaining, &frame->stop_sending.stream_id, &consumed);
	if (ret < 0)
		return ret;
	ret = FRAME_ADVANCE_SAFE(p, remaining, consumed);
	if (ret < 0)
		return ret;

	/* Application Protocol Error Code */
	ret = frame_varint_decode(p, remaining, &frame->stop_sending.app_error_code, &consumed);
	if (ret < 0)
		return ret;
	ret = FRAME_ADVANCE_SAFE(p, remaining, consumed);
	if (ret < 0)
		return ret;

	return (int)(buf_len - remaining);
}

/**
 * tquic_parse_crypto_frame - Parse CRYPTO frame
 * @buf: Buffer containing the frame
 * @buf_len: Length of the buffer
 * @frame: Output frame structure
 *
 * SECURITY: Uses bounds-checked arithmetic to prevent size_t underflow.
 * The crypto.length field is validated against both SIZE_MAX and remaining
 * buffer before advancing to prevent integer overflow attacks.
 *
 * Note: frame->crypto.data points into the original buffer.
 * Returns bytes consumed on success, negative error code on failure.
 */
static int tquic_parse_crypto_frame(const u8 *buf, size_t buf_len,
				    struct tquic_frame *frame)
{
	const u8 *p = buf;
	size_t remaining = buf_len;
	size_t consumed = 0;
	int ret;

	if (!frame_check_remaining(remaining, 1))
		return -EINVAL;

	/* Skip frame type */
	ret = FRAME_ADVANCE_SAFE(p, remaining, 1);
	if (ret < 0)
		return ret;

	frame->type = TQUIC_FRAME_CRYPTO;

	/* Offset */
	ret = frame_varint_decode(p, remaining, &frame->crypto.offset, &consumed);
	if (ret < 0)
		return ret;
	ret = FRAME_ADVANCE_SAFE(p, remaining, consumed);
	if (ret < 0)
		return ret;

	/* Length */
	ret = frame_varint_decode(p, remaining, &frame->crypto.length, &consumed);
	if (ret < 0)
		return ret;
	ret = FRAME_ADVANCE_SAFE(p, remaining, consumed);
	if (ret < 0)
		return ret;

	/*
	 * SECURITY: Validate crypto data length before advancing.
	 * A malicious frame could specify a huge length to cause underflow
	 * or buffer over-read. Check against SIZE_MAX prevents u64->size_t
	 * truncation issues on 32-bit systems.
	 */
	if (frame->crypto.length > SIZE_MAX)
		return -EPROTO;
	if (!frame_check_remaining(remaining, (size_t)frame->crypto.length))
		return -EPROTO;

	frame->crypto.data = p;
	ret = FRAME_ADVANCE_SAFE(p, remaining, (size_t)frame->crypto.length);
	if (ret < 0)
		return ret;

	return (int)(buf_len - remaining);
}

/**
 * tquic_parse_new_token_frame - Parse NEW_TOKEN frame
 * @buf: Buffer containing the frame
 * @buf_len: Length of the buffer
 * @frame: Output frame structure
 *
 * SECURITY: Uses bounds-checked arithmetic to prevent size_t underflow.
 * Token length is validated against maximum and buffer bounds.
 *
 * Note: frame->new_token.token points into the original buffer.
 * Returns bytes consumed on success, negative error code on failure.
 */
static int tquic_parse_new_token_frame(const u8 *buf, size_t buf_len,
				       struct tquic_frame *frame)
{
	const u8 *p = buf;
	size_t remaining = buf_len;
	size_t consumed = 0;
	int ret;

	if (!frame_check_remaining(remaining, 1))
		return -EINVAL;

	/* Skip frame type */
	ret = FRAME_ADVANCE_SAFE(p, remaining, 1);
	if (ret < 0)
		return ret;

	frame->type = TQUIC_FRAME_NEW_TOKEN;

	/* Token Length */
	ret = frame_varint_decode(p, remaining, &frame->new_token.token_len, &consumed);
	if (ret < 0)
		return ret;
	ret = FRAME_ADVANCE_SAFE(p, remaining, consumed);
	if (ret < 0)
		return ret;

	/*
	 * SECURITY: Validate token length before buffer access.
	 * - Empty tokens are invalid per RFC 9000
	 * - Check against TQUIC_MAX_TOKEN_LEN for resource limits
	 * - Check against SIZE_MAX for 32-bit system safety
	 * - Check against remaining for buffer bounds
	 */
	if (frame->new_token.token_len == 0)
		return -EPROTO;
	if (frame->new_token.token_len > TQUIC_MAX_TOKEN_LEN)
		return -EPROTO;
	if (frame->new_token.token_len > SIZE_MAX)
		return -EPROTO;
	if (!frame_check_remaining(remaining, (size_t)frame->new_token.token_len))
		return -EPROTO;

	frame->new_token.token = p;
	ret = FRAME_ADVANCE_SAFE(p, remaining, (size_t)frame->new_token.token_len);
	if (ret < 0)
		return ret;

	return (int)(buf_len - remaining);
}

/**
 * tquic_parse_stream_frame - Parse STREAM frame
 * @buf: Buffer containing the frame
 * @buf_len: Length of the buffer
 * @frame: Output frame structure
 *
 * STREAM frames (0x08-0x0f) have the following bit flags in the type:
 * - Bit 0 (0x01): FIN - indicates final offset
 * - Bit 1 (0x02): LEN - length field present
 * - Bit 2 (0x04): OFF - offset field present
 *
 * SECURITY: Uses bounds-checked arithmetic to prevent size_t underflow.
 * The stream data length is carefully validated before buffer access.
 *
 * Note: frame->stream.data points into the original buffer.
 * Returns bytes consumed on success, negative error code on failure.
 */
static int tquic_parse_stream_frame(const u8 *buf, size_t buf_len,
				    struct tquic_frame *frame)
{
	const u8 *p = buf;
	size_t remaining = buf_len;
	size_t consumed = 0;
	u8 flags;
	int ret;

	if (!frame_check_remaining(remaining, 1))
		return -EINVAL;

	flags = buf[0] & 0x07;
	frame->type = buf[0];
	frame->stream.fin = !!(flags & TQUIC_STREAM_FLAG_FIN);
	frame->stream.has_length = !!(flags & TQUIC_STREAM_FLAG_LEN);
	frame->stream.has_offset = !!(flags & TQUIC_STREAM_FLAG_OFF);

	/* Skip frame type */
	ret = FRAME_ADVANCE_SAFE(p, remaining, 1);
	if (ret < 0)
		return ret;

	/* Stream ID */
	ret = frame_varint_decode(p, remaining, &frame->stream.stream_id, &consumed);
	if (ret < 0)
		return ret;
	ret = FRAME_ADVANCE_SAFE(p, remaining, consumed);
	if (ret < 0)
		return ret;

	/* Offset (if present) */
	if (frame->stream.has_offset) {
		ret = frame_varint_decode(p, remaining, &frame->stream.offset, &consumed);
		if (ret < 0)
			return ret;
		ret = FRAME_ADVANCE_SAFE(p, remaining, consumed);
		if (ret < 0)
			return ret;
	} else {
		frame->stream.offset = 0;
	}

	/* Length (if present, otherwise data extends to end of packet) */
	if (frame->stream.has_length) {
		ret = frame_varint_decode(p, remaining, &frame->stream.length, &consumed);
		if (ret < 0)
			return ret;
		ret = FRAME_ADVANCE_SAFE(p, remaining, consumed);
		if (ret < 0)
			return ret;

		/*
		 * SECURITY: Validate stream data length before buffer access.
		 * Check against SIZE_MAX for 32-bit safety, then against remaining.
		 */
		if (frame->stream.length > SIZE_MAX)
			return -EPROTO;
		if (!frame_check_remaining(remaining, (size_t)frame->stream.length))
			return -EPROTO;

		frame->stream.data = p;
		ret = FRAME_ADVANCE_SAFE(p, remaining, (size_t)frame->stream.length);
		if (ret < 0)
			return ret;
	} else {
		/* Data extends to end of packet - remaining is already bounded */
		frame->stream.length = remaining;
		frame->stream.data = p;
		remaining = 0;
	}

	return (int)(buf_len - remaining);
}

/**
 * tquic_parse_max_data_frame - Parse MAX_DATA frame
 * @buf: Buffer containing the frame
 * @buf_len: Length of the buffer
 * @frame: Output frame structure
 *
 * SECURITY: Uses bounds-checked arithmetic to prevent size_t underflow.
 * Returns bytes consumed on success, negative error code on failure.
 */
static int tquic_parse_max_data_frame(const u8 *buf, size_t buf_len,
				      struct tquic_frame *frame)
{
	const u8 *p = buf;
	size_t remaining = buf_len;
	size_t consumed = 0;
	int ret;

	if (!frame_check_remaining(remaining, 1))
		return -EINVAL;

	/* Skip frame type */
	ret = FRAME_ADVANCE_SAFE(p, remaining, 1);
	if (ret < 0)
		return ret;

	frame->type = TQUIC_FRAME_MAX_DATA;

	/* Maximum Data */
	ret = frame_varint_decode(p, remaining, &frame->max_data.max_data, &consumed);
	if (ret < 0)
		return ret;
	ret = FRAME_ADVANCE_SAFE(p, remaining, consumed);
	if (ret < 0)
		return ret;

	return (int)(buf_len - remaining);
}

/**
 * tquic_parse_max_stream_data_frame - Parse MAX_STREAM_DATA frame
 * @buf: Buffer containing the frame
 * @buf_len: Length of the buffer
 * @frame: Output frame structure
 *
 * SECURITY: Uses bounds-checked arithmetic to prevent size_t underflow.
 * Returns bytes consumed on success, negative error code on failure.
 */
static int tquic_parse_max_stream_data_frame(const u8 *buf, size_t buf_len,
					     struct tquic_frame *frame)
{
	const u8 *p = buf;
	size_t remaining = buf_len;
	size_t consumed = 0;
	int ret;

	if (!frame_check_remaining(remaining, 1))
		return -EINVAL;

	/* Skip frame type */
	ret = FRAME_ADVANCE_SAFE(p, remaining, 1);
	if (ret < 0)
		return ret;

	frame->type = TQUIC_FRAME_MAX_STREAM_DATA;

	/* Stream ID */
	ret = frame_varint_decode(p, remaining, &frame->max_stream_data.stream_id, &consumed);
	if (ret < 0)
		return ret;
	ret = FRAME_ADVANCE_SAFE(p, remaining, consumed);
	if (ret < 0)
		return ret;

	/* Maximum Stream Data */
	ret = frame_varint_decode(p, remaining, &frame->max_stream_data.max_stream_data, &consumed);
	if (ret < 0)
		return ret;
	ret = FRAME_ADVANCE_SAFE(p, remaining, consumed);
	if (ret < 0)
		return ret;

	return (int)(buf_len - remaining);
}

/**
 * tquic_parse_max_streams_frame - Parse MAX_STREAMS frame
 * @buf: Buffer containing the frame
 * @buf_len: Length of the buffer
 * @frame: Output frame structure
 * @bidi: true for bidirectional (0x12), false for unidirectional (0x13)
 *
 * SECURITY: Uses bounds-checked arithmetic to prevent size_t underflow.
 * Returns bytes consumed on success, negative error code on failure.
 */
static int tquic_parse_max_streams_frame(const u8 *buf, size_t buf_len,
					 struct tquic_frame *frame, bool bidi)
{
	const u8 *p = buf;
	size_t remaining = buf_len;
	size_t consumed = 0;
	int ret;

	if (!frame_check_remaining(remaining, 1))
		return -EINVAL;

	/* Skip frame type */
	ret = FRAME_ADVANCE_SAFE(p, remaining, 1);
	if (ret < 0)
		return ret;

	frame->type = bidi ? TQUIC_FRAME_MAX_STREAMS_BIDI : TQUIC_FRAME_MAX_STREAMS_UNI;
	frame->max_streams.bidi = bidi;

	/* Maximum Streams */
	ret = frame_varint_decode(p, remaining, &frame->max_streams.max_streams, &consumed);
	if (ret < 0)
		return ret;
	ret = FRAME_ADVANCE_SAFE(p, remaining, consumed);
	if (ret < 0)
		return ret;

	/* SECURITY: Validate max streams per RFC 9000 (cannot exceed 2^60) */
	if (frame->max_streams.max_streams > (1ULL << 60))
		return -EPROTO;

	return (int)(buf_len - remaining);
}

/**
 * tquic_parse_data_blocked_frame - Parse DATA_BLOCKED frame
 * @buf: Buffer containing the frame
 * @buf_len: Length of the buffer
 * @frame: Output frame structure
 *
 * SECURITY: Uses bounds-checked arithmetic to prevent size_t underflow.
 * Returns bytes consumed on success, negative error code on failure.
 */
static int tquic_parse_data_blocked_frame(const u8 *buf, size_t buf_len,
					  struct tquic_frame *frame)
{
	const u8 *p = buf;
	size_t remaining = buf_len;
	size_t consumed = 0;
	int ret;

	if (!frame_check_remaining(remaining, 1))
		return -EINVAL;

	/* Skip frame type */
	ret = FRAME_ADVANCE_SAFE(p, remaining, 1);
	if (ret < 0)
		return ret;

	frame->type = TQUIC_FRAME_DATA_BLOCKED;

	/* Maximum Data (the limit at which blocking occurred) */
	ret = frame_varint_decode(p, remaining, &frame->data_blocked.max_data, &consumed);
	if (ret < 0)
		return ret;
	ret = FRAME_ADVANCE_SAFE(p, remaining, consumed);
	if (ret < 0)
		return ret;

	return (int)(buf_len - remaining);
}

/**
 * tquic_parse_stream_data_blocked_frame - Parse STREAM_DATA_BLOCKED frame
 * @buf: Buffer containing the frame
 * @buf_len: Length of the buffer
 * @frame: Output frame structure
 *
 * SECURITY: Uses bounds-checked arithmetic to prevent size_t underflow.
 * Returns bytes consumed on success, negative error code on failure.
 */
static int tquic_parse_stream_data_blocked_frame(const u8 *buf, size_t buf_len,
						 struct tquic_frame *frame)
{
	const u8 *p = buf;
	size_t remaining = buf_len;
	size_t consumed = 0;
	int ret;

	if (!frame_check_remaining(remaining, 1))
		return -EINVAL;

	/* Skip frame type */
	ret = FRAME_ADVANCE_SAFE(p, remaining, 1);
	if (ret < 0)
		return ret;

	frame->type = TQUIC_FRAME_STREAM_DATA_BLOCKED;

	/* Stream ID */
	ret = frame_varint_decode(p, remaining, &frame->stream_data_blocked.stream_id, &consumed);
	if (ret < 0)
		return ret;
	ret = FRAME_ADVANCE_SAFE(p, remaining, consumed);
	if (ret < 0)
		return ret;

	/* Maximum Stream Data (the limit at which blocking occurred) */
	ret = frame_varint_decode(p, remaining, &frame->stream_data_blocked.max_stream_data, &consumed);
	if (ret < 0)
		return ret;
	ret = FRAME_ADVANCE_SAFE(p, remaining, consumed);
	if (ret < 0)
		return ret;

	return (int)(buf_len - remaining);
}

/**
 * tquic_parse_streams_blocked_frame - Parse STREAMS_BLOCKED frame
 * @buf: Buffer containing the frame
 * @buf_len: Length of the buffer
 * @frame: Output frame structure
 * @bidi: true for bidirectional (0x16), false for unidirectional (0x17)
 *
 * SECURITY: Uses bounds-checked arithmetic to prevent size_t underflow.
 * Returns bytes consumed on success, negative error code on failure.
 */
static int tquic_parse_streams_blocked_frame(const u8 *buf, size_t buf_len,
					     struct tquic_frame *frame, bool bidi)
{
	const u8 *p = buf;
	size_t remaining = buf_len;
	size_t consumed = 0;
	int ret;

	if (!frame_check_remaining(remaining, 1))
		return -EINVAL;

	/* Skip frame type */
	ret = FRAME_ADVANCE_SAFE(p, remaining, 1);
	if (ret < 0)
		return ret;

	frame->type = bidi ? TQUIC_FRAME_STREAMS_BLOCKED_BIDI :
			     TQUIC_FRAME_STREAMS_BLOCKED_UNI;
	frame->streams_blocked.bidi = bidi;

	/* Maximum Streams (the limit at which blocking occurred) */
	ret = frame_varint_decode(p, remaining, &frame->streams_blocked.max_streams, &consumed);
	if (ret < 0)
		return ret;
	ret = FRAME_ADVANCE_SAFE(p, remaining, consumed);
	if (ret < 0)
		return ret;

	/* SECURITY: Validate max streams per RFC 9000 (cannot exceed 2^60) */
	if (frame->streams_blocked.max_streams > (1ULL << 60))
		return -EPROTO;

	return (int)(buf_len - remaining);
}

/**
 * tquic_parse_new_connection_id_frame - Parse NEW_CONNECTION_ID frame
 * @buf: Buffer containing the frame
 * @buf_len: Length of the buffer
 * @frame: Output frame structure
 *
 * SECURITY: Uses bounds-checked arithmetic to prevent size_t underflow.
 * Connection ID length is validated against protocol limits before use.
 * Returns bytes consumed on success, negative error code on failure.
 */
static int tquic_parse_new_connection_id_frame(const u8 *buf, size_t buf_len,
					       struct tquic_frame *frame)
{
	const u8 *p = buf;
	size_t remaining = buf_len;
	size_t consumed = 0;
	int ret;

	if (!frame_check_remaining(remaining, 1))
		return -EINVAL;

	/* Skip frame type */
	ret = FRAME_ADVANCE_SAFE(p, remaining, 1);
	if (ret < 0)
		return ret;

	frame->type = TQUIC_FRAME_NEW_CONNECTION_ID;

	/* Sequence Number */
	ret = frame_varint_decode(p, remaining, &frame->new_cid.seq_num, &consumed);
	if (ret < 0)
		return ret;
	ret = FRAME_ADVANCE_SAFE(p, remaining, consumed);
	if (ret < 0)
		return ret;

	/* Retire Prior To */
	ret = frame_varint_decode(p, remaining, &frame->new_cid.retire_prior_to, &consumed);
	if (ret < 0)
		return ret;
	ret = FRAME_ADVANCE_SAFE(p, remaining, consumed);
	if (ret < 0)
		return ret;

	/* SECURITY: Retire Prior To must not be greater than Sequence Number */
	if (frame->new_cid.retire_prior_to > frame->new_cid.seq_num)
		return -EPROTO;

	/* Connection ID Length (1 byte, not varint) */
	if (!frame_check_remaining(remaining, 1))
		return -EPROTO;
	frame->new_cid.cid_len = *p;
	ret = FRAME_ADVANCE_SAFE(p, remaining, 1);
	if (ret < 0)
		return ret;

	/*
	 * SECURITY: Validate CID length before buffer access.
	 * RFC 9000 requires 1-20 bytes for NEW_CONNECTION_ID.
	 */
	if (frame->new_cid.cid_len < 1 || frame->new_cid.cid_len > TQUIC_MAX_CID_LEN)
		return -EPROTO;

	/* Connection ID - validate remaining buffer first */
	if (!frame_check_remaining(remaining, frame->new_cid.cid_len))
		return -EPROTO;
	memcpy(frame->new_cid.cid, p, frame->new_cid.cid_len);
	ret = FRAME_ADVANCE_SAFE(p, remaining, frame->new_cid.cid_len);
	if (ret < 0)
		return ret;

	/* Stateless Reset Token (16 bytes) */
	if (!frame_check_remaining(remaining, TQUIC_STATELESS_RESET_TOKEN_LEN))
		return -EPROTO;
	memcpy(frame->new_cid.stateless_reset_token, p, TQUIC_STATELESS_RESET_TOKEN_LEN);
	ret = FRAME_ADVANCE_SAFE(p, remaining, TQUIC_STATELESS_RESET_TOKEN_LEN);
	if (ret < 0)
		return ret;

	return (int)(buf_len - remaining);
}

/**
 * tquic_parse_retire_connection_id_frame - Parse RETIRE_CONNECTION_ID frame
 * @buf: Buffer containing the frame
 * @buf_len: Length of the buffer
 * @frame: Output frame structure
 *
 * SECURITY: Uses bounds-checked arithmetic to prevent size_t underflow.
 * Returns bytes consumed on success, negative error code on failure.
 */
static int tquic_parse_retire_connection_id_frame(const u8 *buf, size_t buf_len,
						  struct tquic_frame *frame)
{
	const u8 *p = buf;
	size_t remaining = buf_len;
	size_t consumed = 0;
	int ret;

	if (!frame_check_remaining(remaining, 1))
		return -EINVAL;

	/* Skip frame type */
	ret = FRAME_ADVANCE_SAFE(p, remaining, 1);
	if (ret < 0)
		return ret;

	frame->type = TQUIC_FRAME_RETIRE_CONNECTION_ID;

	/* Sequence Number */
	ret = frame_varint_decode(p, remaining, &frame->retire_cid.seq_num, &consumed);
	if (ret < 0)
		return ret;
	ret = FRAME_ADVANCE_SAFE(p, remaining, consumed);
	if (ret < 0)
		return ret;

	return (int)(buf_len - remaining);
}

/**
 * tquic_parse_path_challenge_frame - Parse PATH_CHALLENGE frame
 * @buf: Buffer containing the frame
 * @buf_len: Length of the buffer
 * @frame: Output frame structure
 *
 * SECURITY: Fixed-size frame with explicit bounds check.
 * Returns bytes consumed on success, negative error code on failure.
 */
static int tquic_parse_path_challenge_frame(const u8 *buf, size_t buf_len,
					    struct tquic_frame *frame)
{
	/* SECURITY: PATH_CHALLENGE is fixed 9 bytes: type(1) + data(8) */
	if (!frame_check_remaining(buf_len, 9))
		return -EINVAL;

	frame->type = TQUIC_FRAME_PATH_CHALLENGE;
	memcpy(frame->path_challenge.data, buf + 1, 8);

	return 9;
}

/**
 * tquic_parse_path_response_frame - Parse PATH_RESPONSE frame
 * @buf: Buffer containing the frame
 * @buf_len: Length of the buffer
 * @frame: Output frame structure
 *
 * SECURITY: Fixed-size frame with explicit bounds check.
 * Returns bytes consumed on success, negative error code on failure.
 */
static int tquic_parse_path_response_frame(const u8 *buf, size_t buf_len,
					   struct tquic_frame *frame)
{
	/* SECURITY: PATH_RESPONSE is fixed 9 bytes: type(1) + data(8) */
	if (!frame_check_remaining(buf_len, 9))
		return -EINVAL;

	frame->type = TQUIC_FRAME_PATH_RESPONSE;
	memcpy(frame->path_response.data, buf + 1, 8);

	return 9;
}

/**
 * tquic_parse_connection_close_frame - Parse CONNECTION_CLOSE frame
 * @buf: Buffer containing the frame
 * @buf_len: Length of the buffer
 * @frame: Output frame structure
 * @app_close: true for application close (0x1d), false for transport (0x1c)
 *
 * SECURITY: Uses bounds-checked arithmetic to prevent size_t underflow.
 * Reason phrase length is validated against buffer bounds.
 *
 * Note: frame->conn_close.reason points into the original buffer.
 * Returns bytes consumed on success, negative error code on failure.
 */
static int tquic_parse_connection_close_frame(const u8 *buf, size_t buf_len,
					      struct tquic_frame *frame,
					      bool app_close)
{
	const u8 *p = buf;
	size_t remaining = buf_len;
	size_t consumed = 0;
	int ret;

	if (!frame_check_remaining(remaining, 1))
		return -EINVAL;

	/* Skip frame type */
	ret = FRAME_ADVANCE_SAFE(p, remaining, 1);
	if (ret < 0)
		return ret;

	frame->type = app_close ? TQUIC_FRAME_CONNECTION_CLOSE_APP :
				  TQUIC_FRAME_CONNECTION_CLOSE;
	frame->conn_close.app_close = app_close;

	/* Error Code */
	ret = frame_varint_decode(p, remaining, &frame->conn_close.error_code, &consumed);
	if (ret < 0)
		return ret;
	ret = FRAME_ADVANCE_SAFE(p, remaining, consumed);
	if (ret < 0)
		return ret;

	/* Frame Type (only for transport close, not app close) */
	if (!app_close) {
		ret = frame_varint_decode(p, remaining, &frame->conn_close.frame_type, &consumed);
		if (ret < 0)
			return ret;
		ret = FRAME_ADVANCE_SAFE(p, remaining, consumed);
		if (ret < 0)
			return ret;
	} else {
		frame->conn_close.frame_type = 0;
	}

	/* Reason Phrase Length */
	ret = frame_varint_decode(p, remaining, &frame->conn_close.reason_len, &consumed);
	if (ret < 0)
		return ret;
	ret = FRAME_ADVANCE_SAFE(p, remaining, consumed);
	if (ret < 0)
		return ret;

	/*
	 * SECURITY: Validate reason phrase length before buffer access.
	 * Check against SIZE_MAX for 32-bit safety, then against remaining.
	 */
	if (frame->conn_close.reason_len > SIZE_MAX)
		return -EPROTO;
	if (!frame_check_remaining(remaining, (size_t)frame->conn_close.reason_len))
		return -EPROTO;

	if (frame->conn_close.reason_len > 0)
		frame->conn_close.reason = p;
	else
		frame->conn_close.reason = NULL;

	ret = FRAME_ADVANCE_SAFE(p, remaining, (size_t)frame->conn_close.reason_len);
	if (ret < 0)
		return ret;

	return (int)(buf_len - remaining);
}

/**
 * tquic_parse_handshake_done_frame - Parse HANDSHAKE_DONE frame
 * @buf: Buffer containing the frame
 * @buf_len: Length of the buffer
 * @frame: Output frame structure
 *
 * SECURITY: Fixed-size frame (type byte only) with explicit bounds check.
 * HANDSHAKE_DONE has no payload, just the type byte.
 * Returns bytes consumed on success, negative error code on failure.
 */
static int tquic_parse_handshake_done_frame(const u8 *buf, size_t buf_len,
					    struct tquic_frame *frame)
{
	if (!frame_check_remaining(buf_len, 1))
		return -EINVAL;

	frame->type = TQUIC_FRAME_HANDSHAKE_DONE;
	return 1;
}

/**
 * tquic_parse_datagram_frame - Parse DATAGRAM frame (RFC 9221)
 * @buf: Buffer containing the frame
 * @buf_len: Length of the buffer
 * @frame: Output frame structure
 *
 * DATAGRAM frames (0x30-0x31) carry unreliable application data:
 * - Type 0x30: No length field, data extends to end of packet
 * - Type 0x31: Has length field specifying data size
 *
 * SECURITY: Uses bounds-checked arithmetic to prevent size_t underflow.
 * Datagram length is validated against buffer bounds before access.
 *
 * Note: frame->datagram.data points into the original buffer.
 * Returns bytes consumed on success, negative error code on failure.
 */
int tquic_parse_datagram_frame(const u8 *buf, size_t buf_len,
			       struct tquic_frame *frame)
{
	const u8 *p = buf;
	size_t remaining = buf_len;
	size_t consumed = 0;
	u8 frame_type;
	int ret;

	if (!frame_check_remaining(remaining, 1))
		return -EINVAL;

	frame_type = buf[0];
	frame->type = frame_type;
	frame->datagram.has_length = (frame_type & 0x01) != 0;

	/* Skip frame type */
	ret = FRAME_ADVANCE_SAFE(p, remaining, 1);
	if (ret < 0)
		return ret;

	if (frame->datagram.has_length) {
		/* Type 0x31: Length field present */
		ret = frame_varint_decode(p, remaining, &frame->datagram.length, &consumed);
		if (ret < 0)
			return ret;
		ret = FRAME_ADVANCE_SAFE(p, remaining, consumed);
		if (ret < 0)
			return ret;

		/*
		 * SECURITY: Validate datagram length before buffer access.
		 * Check against SIZE_MAX for 32-bit safety, then against remaining.
		 */
		if (frame->datagram.length > SIZE_MAX)
			return -EPROTO;
		if (!frame_check_remaining(remaining, (size_t)frame->datagram.length))
			return -EPROTO;

		frame->datagram.data = p;
		ret = FRAME_ADVANCE_SAFE(p, remaining, (size_t)frame->datagram.length);
		if (ret < 0)
			return ret;
	} else {
		/* Type 0x30: Data extends to end of packet - remaining is bounded */
		frame->datagram.length = remaining;
		frame->datagram.data = p;
		remaining = 0;
	}

	return (int)(buf_len - remaining);
}
EXPORT_SYMBOL_GPL(tquic_parse_datagram_frame);

/**
 * tquic_parse_frame - Parse a single QUIC frame from a buffer
 * @buf: Buffer containing the frame
 * @buf_len: Length of the buffer
 * @frame: Output frame structure
 * @ranges_buf: Buffer for ACK ranges (can be NULL if ACK not expected)
 * @max_ranges: Maximum number of ACK ranges
 *
 * SECURITY: This is the main entry point for parsing untrusted network data.
 * All frame-specific parsers use bounds-checked arithmetic (FRAME_ADVANCE_SAFE)
 * to prevent size_t underflow vulnerabilities that could lead to buffer
 * over-reads or remote code execution.
 *
 * Error codes:
 *   -EINVAL: Invalid parameters (NULL pointers, zero length)
 *   -EPROTO: Malformed frame (bounds violation, invalid length fields)
 *   -EOVERFLOW: Resource limits exceeded (e.g., too many ACK ranges)
 *   -EPROTONOSUPPORT: Unknown frame type
 *
 * Returns bytes consumed on success, negative error code on failure.
 */
int tquic_parse_frame(const u8 *buf, size_t buf_len, struct tquic_frame *frame,
		      struct tquic_ack_range *ranges_buf, size_t max_ranges)
{
	u8 type;

	/* SECURITY: Validate inputs before accessing buffer */
	if (!buf || !frame || !frame_check_remaining(buf_len, 1))
		return -EINVAL;

	type = buf[0];
	tquic_dbg("tquic_parse_frame: type=0x%02x buf_len=%zu\n",
		  type, buf_len);

	/* Handle STREAM frames (0x08-0x0f) */
	if (type >= TQUIC_FRAME_STREAM_BASE && type <= TQUIC_FRAME_STREAM_MAX)
		return tquic_parse_stream_frame(buf, buf_len, frame);

	switch (type) {
	case TQUIC_FRAME_PADDING:
		return tquic_parse_padding_frame(buf, buf_len, frame);

	case TQUIC_FRAME_PING:
		return tquic_parse_ping_frame(buf, buf_len, frame);

	case TQUIC_FRAME_ACK:
		return tquic_parse_ack_frame(buf, buf_len, frame, false,
					     ranges_buf, max_ranges);

	case TQUIC_FRAME_ACK_ECN:
		return tquic_parse_ack_frame(buf, buf_len, frame, true,
					     ranges_buf, max_ranges);

	case TQUIC_FRAME_RESET_STREAM:
		return tquic_parse_reset_stream_frame(buf, buf_len, frame);

	case TQUIC_FRAME_STOP_SENDING:
		return tquic_parse_stop_sending_frame(buf, buf_len, frame);

	case TQUIC_FRAME_CRYPTO:
		return tquic_parse_crypto_frame(buf, buf_len, frame);

	case TQUIC_FRAME_NEW_TOKEN:
		return tquic_parse_new_token_frame(buf, buf_len, frame);

	case TQUIC_FRAME_MAX_DATA:
		return tquic_parse_max_data_frame(buf, buf_len, frame);

	case TQUIC_FRAME_MAX_STREAM_DATA:
		return tquic_parse_max_stream_data_frame(buf, buf_len, frame);

	case TQUIC_FRAME_MAX_STREAMS_BIDI:
		return tquic_parse_max_streams_frame(buf, buf_len, frame, true);

	case TQUIC_FRAME_MAX_STREAMS_UNI:
		return tquic_parse_max_streams_frame(buf, buf_len, frame, false);

	case TQUIC_FRAME_DATA_BLOCKED:
		return tquic_parse_data_blocked_frame(buf, buf_len, frame);

	case TQUIC_FRAME_STREAM_DATA_BLOCKED:
		return tquic_parse_stream_data_blocked_frame(buf, buf_len, frame);

	case TQUIC_FRAME_STREAMS_BLOCKED_BIDI:
		return tquic_parse_streams_blocked_frame(buf, buf_len, frame, true);

	case TQUIC_FRAME_STREAMS_BLOCKED_UNI:
		return tquic_parse_streams_blocked_frame(buf, buf_len, frame, false);

	case TQUIC_FRAME_NEW_CONNECTION_ID:
		return tquic_parse_new_connection_id_frame(buf, buf_len, frame);

	case TQUIC_FRAME_RETIRE_CONNECTION_ID:
		return tquic_parse_retire_connection_id_frame(buf, buf_len, frame);

	case TQUIC_FRAME_PATH_CHALLENGE:
		return tquic_parse_path_challenge_frame(buf, buf_len, frame);

	case TQUIC_FRAME_PATH_RESPONSE:
		return tquic_parse_path_response_frame(buf, buf_len, frame);

	case TQUIC_FRAME_CONNECTION_CLOSE:
		return tquic_parse_connection_close_frame(buf, buf_len, frame, false);

	case TQUIC_FRAME_CONNECTION_CLOSE_APP:
		return tquic_parse_connection_close_frame(buf, buf_len, frame, true);

	case TQUIC_FRAME_HANDSHAKE_DONE:
		return tquic_parse_handshake_done_frame(buf, buf_len, frame);

	case TQUIC_FRAME_DATAGRAM:
	case TQUIC_FRAME_DATAGRAM_LEN:
		return tquic_parse_datagram_frame(buf, buf_len, frame);

	default:
		/* Unknown frame type */
		return -EPROTONOSUPPORT;
	}
}
EXPORT_SYMBOL_GPL(tquic_parse_frame);

/* =========================================================================
 * Frame Size Calculation Functions
 * ========================================================================= */

/**
 * tquic_padding_frame_size - Calculate size needed for PADDING frame
 * @length: Number of padding bytes
 *
 * Returns the size in bytes.
 */
size_t tquic_padding_frame_size(size_t length)
{
	return length;  /* Each padding byte is a 0x00 */
}
EXPORT_SYMBOL_GPL(tquic_padding_frame_size);

/**
 * tquic_ping_frame_size - Calculate size needed for PING frame
 *
 * Returns the size in bytes (always 1).
 */
size_t tquic_ping_frame_size(void)
{
	return 1;
}
EXPORT_SYMBOL_GPL(tquic_ping_frame_size);

/**
 * tquic_ack_frame_size - Calculate size needed for ACK frame
 * @largest_ack: Largest acknowledged packet number
 * @ack_delay: ACK delay value
 * @first_ack_range: First ACK range
 * @ranges: Array of additional ACK ranges
 * @range_count: Number of additional ranges
 * @has_ecn: Whether ECN counts are included
 * @ect0: ECT(0) count (if has_ecn)
 * @ect1: ECT(1) count (if has_ecn)
 * @ecn_ce: ECN-CE count (if has_ecn)
 *
 * Returns the size in bytes, or 0 on error.
 */
size_t tquic_ack_frame_size(u64 largest_ack, u64 ack_delay, u64 first_ack_range,
			    const struct tquic_ack_range *ranges, u64 range_count,
			    bool has_ecn, u64 ect0, u64 ect1, u64 ecn_ce)
{
	size_t size = 1;  /* Frame type */
	u64 i;

	size += frame_varint_len(largest_ack);
	size += frame_varint_len(ack_delay);
	size += frame_varint_len(range_count);
	size += frame_varint_len(first_ack_range);

	for (i = 0; i < range_count; i++) {
		size += frame_varint_len(ranges[i].gap);
		size += frame_varint_len(ranges[i].ack_range_len);
	}

	if (has_ecn) {
		size += frame_varint_len(ect0);
		size += frame_varint_len(ect1);
		size += frame_varint_len(ecn_ce);
	}

	return size;
}
EXPORT_SYMBOL_GPL(tquic_ack_frame_size);

/**
 * tquic_reset_stream_frame_size - Calculate size for RESET_STREAM frame
 * @stream_id: Stream identifier
 * @error_code: Application error code
 * @final_size: Final size of the stream
 *
 * Returns the size in bytes.
 */
size_t tquic_reset_stream_frame_size(u64 stream_id, u64 error_code, u64 final_size)
{
	return 1 + frame_varint_len(stream_id) +
	       frame_varint_len(error_code) +
	       frame_varint_len(final_size);
}
EXPORT_SYMBOL_GPL(tquic_reset_stream_frame_size);

/**
 * tquic_stop_sending_frame_size - Calculate size for STOP_SENDING frame
 * @stream_id: Stream identifier
 * @error_code: Application error code
 *
 * Returns the size in bytes.
 */
size_t tquic_stop_sending_frame_size(u64 stream_id, u64 error_code)
{
	return 1 + frame_varint_len(stream_id) + frame_varint_len(error_code);
}
EXPORT_SYMBOL_GPL(tquic_stop_sending_frame_size);

/**
 * tquic_crypto_frame_size - Calculate size for CRYPTO frame
 * @offset: Offset in the crypto stream
 * @length: Length of crypto data
 *
 * Returns the size in bytes (not including the actual crypto data).
 */
size_t tquic_crypto_frame_size(u64 offset, u64 length)
{
	return 1 + frame_varint_len(offset) + frame_varint_len(length) + length;
}
EXPORT_SYMBOL_GPL(tquic_crypto_frame_size);

/**
 * tquic_new_token_frame_size - Calculate size for NEW_TOKEN frame
 * @token_len: Length of the token
 *
 * Returns the size in bytes.
 */
size_t tquic_new_token_frame_size(u64 token_len)
{
	return 1 + frame_varint_len(token_len) + token_len;
}
EXPORT_SYMBOL_GPL(tquic_new_token_frame_size);

/**
 * tquic_stream_frame_size - Calculate size for STREAM frame
 * @stream_id: Stream identifier
 * @offset: Offset (0 if not included)
 * @length: Data length
 * @has_offset: Whether to include offset field
 * @has_length: Whether to include length field
 *
 * Returns the size in bytes (including data).
 */
size_t tquic_stream_frame_size(u64 stream_id, u64 offset, u64 length,
			       bool has_offset, bool has_length)
{
	size_t size = 1;  /* Frame type */

	size += frame_varint_len(stream_id);

	if (has_offset)
		size += frame_varint_len(offset);

	if (has_length)
		size += frame_varint_len(length);

	size += length;  /* Stream data */

	return size;
}
EXPORT_SYMBOL_GPL(tquic_stream_frame_size);

/**
 * tquic_max_data_frame_size - Calculate size for MAX_DATA frame
 * @max_data: Maximum data value
 *
 * Returns the size in bytes.
 */
size_t tquic_max_data_frame_size(u64 max_data)
{
	return 1 + frame_varint_len(max_data);
}
EXPORT_SYMBOL_GPL(tquic_max_data_frame_size);

/**
 * tquic_max_stream_data_frame_size - Calculate size for MAX_STREAM_DATA frame
 * @stream_id: Stream identifier
 * @max_stream_data: Maximum stream data value
 *
 * Returns the size in bytes.
 */
size_t tquic_max_stream_data_frame_size(u64 stream_id, u64 max_stream_data)
{
	return 1 + frame_varint_len(stream_id) + frame_varint_len(max_stream_data);
}
EXPORT_SYMBOL_GPL(tquic_max_stream_data_frame_size);

/**
 * tquic_max_streams_frame_size - Calculate size for MAX_STREAMS frame
 * @max_streams: Maximum streams value
 *
 * Returns the size in bytes.
 */
size_t tquic_max_streams_frame_size(u64 max_streams)
{
	return 1 + frame_varint_len(max_streams);
}
EXPORT_SYMBOL_GPL(tquic_max_streams_frame_size);

/**
 * tquic_data_blocked_frame_size - Calculate size for DATA_BLOCKED frame
 * @max_data: Maximum data limit at which blocking occurred
 *
 * Returns the size in bytes.
 */
size_t tquic_data_blocked_frame_size(u64 max_data)
{
	return 1 + frame_varint_len(max_data);
}
EXPORT_SYMBOL_GPL(tquic_data_blocked_frame_size);

/**
 * tquic_stream_data_blocked_frame_size - Calculate size for STREAM_DATA_BLOCKED
 * @stream_id: Stream identifier
 * @max_stream_data: Maximum stream data at which blocking occurred
 *
 * Returns the size in bytes.
 */
size_t tquic_stream_data_blocked_frame_size(u64 stream_id, u64 max_stream_data)
{
	return 1 + frame_varint_len(stream_id) + frame_varint_len(max_stream_data);
}
EXPORT_SYMBOL_GPL(tquic_stream_data_blocked_frame_size);

/**
 * tquic_streams_blocked_frame_size - Calculate size for STREAMS_BLOCKED
 * @max_streams: Maximum streams at which blocking occurred
 *
 * Returns the size in bytes.
 */
size_t tquic_streams_blocked_frame_size(u64 max_streams)
{
	return 1 + frame_varint_len(max_streams);
}
EXPORT_SYMBOL_GPL(tquic_streams_blocked_frame_size);

/**
 * tquic_new_connection_id_frame_size - Calculate size for NEW_CONNECTION_ID
 * @seq_num: Sequence number
 * @retire_prior_to: Retire prior to value
 * @cid_len: Connection ID length
 *
 * Returns the size in bytes.
 */
size_t tquic_new_connection_id_frame_size(u64 seq_num, u64 retire_prior_to,
					  u8 cid_len)
{
	return 1 + frame_varint_len(seq_num) + frame_varint_len(retire_prior_to) +
	       1 + cid_len + TQUIC_STATELESS_RESET_TOKEN_LEN;
}
EXPORT_SYMBOL_GPL(tquic_new_connection_id_frame_size);

/**
 * tquic_retire_connection_id_frame_size - Calculate size for RETIRE_CONNECTION_ID
 * @seq_num: Sequence number to retire
 *
 * Returns the size in bytes.
 */
size_t tquic_retire_connection_id_frame_size(u64 seq_num)
{
	return 1 + frame_varint_len(seq_num);
}
EXPORT_SYMBOL_GPL(tquic_retire_connection_id_frame_size);

/**
 * tquic_path_challenge_frame_size - Calculate size for PATH_CHALLENGE
 *
 * Returns the size in bytes (always 9).
 */
size_t tquic_path_challenge_frame_size(void)
{
	return 9;  /* 1 byte type + 8 bytes data */
}
EXPORT_SYMBOL_GPL(tquic_path_challenge_frame_size);

/**
 * tquic_path_response_frame_size - Calculate size for PATH_RESPONSE
 *
 * Returns the size in bytes (always 9).
 */
size_t tquic_path_response_frame_size(void)
{
	return 9;  /* 1 byte type + 8 bytes data */
}
EXPORT_SYMBOL_GPL(tquic_path_response_frame_size);

/**
 * tquic_connection_close_frame_size - Calculate size for CONNECTION_CLOSE
 * @error_code: Error code
 * @frame_type: Frame type that triggered close (for transport close only)
 * @reason_len: Length of reason phrase
 * @app_close: true for application close
 *
 * Returns the size in bytes.
 */
size_t tquic_connection_close_frame_size(u64 error_code, u64 frame_type,
					 u64 reason_len, bool app_close)
{
	size_t size = 1;  /* Frame type */

	size += frame_varint_len(error_code);

	if (!app_close)
		size += frame_varint_len(frame_type);

	size += frame_varint_len(reason_len);
	size += reason_len;

	return size;
}
EXPORT_SYMBOL_GPL(tquic_connection_close_frame_size);

/**
 * tquic_handshake_done_frame_size - Calculate size for HANDSHAKE_DONE
 *
 * Returns the size in bytes (always 1).
 */
size_t tquic_handshake_done_frame_size(void)
{
	return 1;
}
EXPORT_SYMBOL_GPL(tquic_handshake_done_frame_size);

/**
 * tquic_datagram_frame_size - Calculate size for DATAGRAM frame (RFC 9221)
 * @data_len: Length of datagram payload
 * @with_length: true if length field should be included (type 0x31)
 *
 * Returns the size in bytes (including data).
 */
size_t tquic_datagram_frame_size(u64 data_len, bool with_length)
{
	size_t size = 1;  /* Frame type */

	if (with_length)
		size += frame_varint_len(data_len);

	size += data_len;

	return size;
}
EXPORT_SYMBOL_GPL(tquic_datagram_frame_size);

/* =========================================================================
 * Frame Construction Functions
 * ========================================================================= */

/**
 * tquic_write_padding_frame - Write PADDING frame(s)
 * @buf: Output buffer
 * @buf_len: Length of buffer
 * @length: Number of padding bytes to write
 *
 * Returns bytes written on success, negative error code on failure.
 */
int tquic_write_padding_frame(u8 *buf, size_t buf_len, size_t length)
{
	if (buf_len < length)
		return -ENOSPC;

	memset(buf, TQUIC_FRAME_PADDING, length);
	return (int)length;
}
EXPORT_SYMBOL_GPL(tquic_write_padding_frame);

/**
 * tquic_write_ping_frame - Write PING frame
 * @buf: Output buffer
 * @buf_len: Length of buffer
 *
 * Returns bytes written on success, negative error code on failure.
 */
int tquic_write_ping_frame(u8 *buf, size_t buf_len)
{
	if (buf_len < 1)
		return -ENOSPC;

	buf[0] = TQUIC_FRAME_PING;
	return 1;
}
EXPORT_SYMBOL_GPL(tquic_write_ping_frame);

/**
 * tquic_write_ack_frame - Write ACK frame
 * @buf: Output buffer
 * @buf_len: Length of buffer
 * @largest_ack: Largest acknowledged packet number
 * @ack_delay: ACK delay value
 * @first_ack_range: First ACK range
 * @ranges: Array of additional ACK ranges
 * @range_count: Number of additional ranges
 * @has_ecn: Whether to include ECN counts
 * @ect0: ECT(0) count
 * @ect1: ECT(1) count
 * @ecn_ce: ECN-CE count
 *
 * Returns bytes written on success, negative error code on failure.
 */
int tquic_write_ack_frame(u8 *buf, size_t buf_len, u64 largest_ack,
			  u64 ack_delay, u64 first_ack_range,
			  const struct tquic_ack_range *ranges, u64 range_count,
			  bool has_ecn, u64 ect0, u64 ect1, u64 ecn_ce)
{
	u8 *p = buf;
	size_t remaining = buf_len;
	u64 i;
	int ret;

	/* Frame type */
	if (remaining < 1)
		return -ENOSPC;
	*p++ = has_ecn ? TQUIC_FRAME_ACK_ECN : TQUIC_FRAME_ACK;
	remaining--;

	/* Largest Acknowledged */
	ret = frame_varint_encode(largest_ack, p, remaining);
	if (ret < 0)
		return ret;
	p += ret;
	remaining -= ret;

	/* ACK Delay */
	ret = frame_varint_encode(ack_delay, p, remaining);
	if (ret < 0)
		return ret;
	p += ret;
	remaining -= ret;

	/* ACK Range Count */
	ret = frame_varint_encode(range_count, p, remaining);
	if (ret < 0)
		return ret;
	p += ret;
	remaining -= ret;

	/* First ACK Range */
	ret = frame_varint_encode(first_ack_range, p, remaining);
	if (ret < 0)
		return ret;
	p += ret;
	remaining -= ret;

	/* Additional ACK Ranges */
	for (i = 0; i < range_count; i++) {
		ret = frame_varint_encode(ranges[i].gap, p, remaining);
		if (ret < 0)
			return ret;
		p += ret;
		remaining -= ret;

		ret = frame_varint_encode(ranges[i].ack_range_len, p, remaining);
		if (ret < 0)
			return ret;
		p += ret;
		remaining -= ret;
	}

	/* ECN Counts (if present) */
	if (has_ecn) {
		ret = frame_varint_encode(ect0, p, remaining);
		if (ret < 0)
			return ret;
		p += ret;
		remaining -= ret;

		ret = frame_varint_encode(ect1, p, remaining);
		if (ret < 0)
			return ret;
		p += ret;
		remaining -= ret;

		ret = frame_varint_encode(ecn_ce, p, remaining);
		if (ret < 0)
			return ret;
		p += ret;
		remaining -= ret;
	}

	return (int)(buf_len - remaining);
}
EXPORT_SYMBOL_GPL(tquic_write_ack_frame);

/**
 * tquic_write_reset_stream_frame - Write RESET_STREAM frame
 * @buf: Output buffer
 * @buf_len: Length of buffer
 * @stream_id: Stream identifier
 * @error_code: Application error code
 * @final_size: Final size of the stream
 *
 * Returns bytes written on success, negative error code on failure.
 */
int tquic_write_reset_stream_frame(u8 *buf, size_t buf_len, u64 stream_id,
				   u64 error_code, u64 final_size)
{
	u8 *p = buf;
	size_t remaining = buf_len;
	int ret;

	if (remaining < 1)
		return -ENOSPC;
	*p++ = TQUIC_FRAME_RESET_STREAM;
	remaining--;

	ret = frame_varint_encode(stream_id, p, remaining);
	if (ret < 0)
		return ret;
	p += ret;
	remaining -= ret;

	ret = frame_varint_encode(error_code, p, remaining);
	if (ret < 0)
		return ret;
	p += ret;
	remaining -= ret;

	ret = frame_varint_encode(final_size, p, remaining);
	if (ret < 0)
		return ret;
	p += ret;
	remaining -= ret;

	return (int)(buf_len - remaining);
}
EXPORT_SYMBOL_GPL(tquic_write_reset_stream_frame);

/**
 * tquic_write_stop_sending_frame - Write STOP_SENDING frame
 * @buf: Output buffer
 * @buf_len: Length of buffer
 * @stream_id: Stream identifier
 * @error_code: Application error code
 *
 * Returns bytes written on success, negative error code on failure.
 */
int tquic_write_stop_sending_frame(u8 *buf, size_t buf_len, u64 stream_id,
				   u64 error_code)
{
	u8 *p = buf;
	size_t remaining = buf_len;
	int ret;

	if (remaining < 1)
		return -ENOSPC;
	*p++ = TQUIC_FRAME_STOP_SENDING;
	remaining--;

	ret = frame_varint_encode(stream_id, p, remaining);
	if (ret < 0)
		return ret;
	p += ret;
	remaining -= ret;

	ret = frame_varint_encode(error_code, p, remaining);
	if (ret < 0)
		return ret;
	p += ret;
	remaining -= ret;

	return (int)(buf_len - remaining);
}
EXPORT_SYMBOL_GPL(tquic_write_stop_sending_frame);

/**
 * tquic_write_crypto_frame - Write CRYPTO frame
 * @buf: Output buffer
 * @buf_len: Length of buffer
 * @offset: Offset in the crypto stream
 * @data: Crypto data to write
 * @data_len: Length of crypto data
 *
 * Returns bytes written on success, negative error code on failure.
 */
int tquic_write_crypto_frame(u8 *buf, size_t buf_len, u64 offset,
			     const u8 *data, u64 data_len)
{
	u8 *p = buf;
	size_t remaining = buf_len;
	int ret;

	tquic_dbg("tquic_write_crypto_frame: offset=%llu len=%llu\n",
		  offset, data_len);
	if (remaining < 1)
		return -ENOSPC;
	*p++ = TQUIC_FRAME_CRYPTO;
	remaining--;

	ret = frame_varint_encode(offset, p, remaining);
	if (ret < 0)
		return ret;
	p += ret;
	remaining -= ret;

	ret = frame_varint_encode(data_len, p, remaining);
	if (ret < 0)
		return ret;
	p += ret;
	remaining -= ret;

	/* Validate data_len doesn't exceed size_t and remaining buffer */
	if (data_len > SIZE_MAX || remaining < data_len)
		return -ENOSPC;
	memcpy(p, data, data_len);
	p += data_len;
	remaining -= data_len;

	return (int)(buf_len - remaining);
}
EXPORT_SYMBOL_GPL(tquic_write_crypto_frame);

/**
 * tquic_write_new_token_frame - Write NEW_TOKEN frame
 * @buf: Output buffer
 * @buf_len: Length of buffer
 * @token: Token data
 * @token_len: Length of token
 *
 * Returns bytes written on success, negative error code on failure.
 */
int tquic_write_new_token_frame(u8 *buf, size_t buf_len,
				const u8 *token, u64 token_len)
{
	u8 *p = buf;
	size_t remaining = buf_len;
	int ret;

	if (token_len == 0)
		return -EINVAL;

	if (remaining < 1)
		return -ENOSPC;
	*p++ = TQUIC_FRAME_NEW_TOKEN;
	remaining--;

	ret = frame_varint_encode(token_len, p, remaining);
	if (ret < 0)
		return ret;
	p += ret;
	remaining -= ret;

	/* Validate token_len doesn't exceed size_t and remaining buffer */
	if (token_len > SIZE_MAX || remaining < token_len)
		return -ENOSPC;
	memcpy(p, token, token_len);
	p += token_len;
	remaining -= token_len;

	return (int)(buf_len - remaining);
}
EXPORT_SYMBOL_GPL(tquic_write_new_token_frame);

/**
 * tquic_write_stream_frame - Write STREAM frame
 * @buf: Output buffer
 * @buf_len: Length of buffer
 * @stream_id: Stream identifier
 * @offset: Offset (ignored if has_offset is false)
 * @data: Stream data
 * @data_len: Length of data
 * @has_offset: Include offset field
 * @has_length: Include length field
 * @fin: Set FIN flag
 *
 * Returns bytes written on success, negative error code on failure.
 */
int tquic_write_stream_frame(u8 *buf, size_t buf_len, u64 stream_id,
			     u64 offset, const u8 *data, u64 data_len,
			     bool has_offset, bool has_length, bool fin)
{
	u8 *p = buf;
	tquic_dbg("tquic_write_stream_frame: stream=%llu offset=%llu len=%llu fin=%d\n",
		  stream_id, offset, data_len, fin);
	size_t remaining = buf_len;
	u8 type;
	int ret;

	/* Build frame type byte */
	type = TQUIC_FRAME_STREAM_BASE;
	if (fin)
		type |= TQUIC_STREAM_FLAG_FIN;
	if (has_length)
		type |= TQUIC_STREAM_FLAG_LEN;
	if (has_offset)
		type |= TQUIC_STREAM_FLAG_OFF;

	if (remaining < 1)
		return -ENOSPC;
	*p++ = type;
	remaining--;

	/* Stream ID */
	ret = frame_varint_encode(stream_id, p, remaining);
	if (ret < 0)
		return ret;
	p += ret;
	remaining -= ret;

	/* Offset (if present) */
	if (has_offset) {
		ret = frame_varint_encode(offset, p, remaining);
		if (ret < 0)
			return ret;
		p += ret;
		remaining -= ret;
	}

	/* Length (if present) */
	if (has_length) {
		ret = frame_varint_encode(data_len, p, remaining);
		if (ret < 0)
			return ret;
		p += ret;
		remaining -= ret;
	}

	/* Stream data - validate data_len doesn't exceed size_t and remaining buffer */
	if (data_len > SIZE_MAX || remaining < data_len)
		return -ENOSPC;
	if (data_len > 0)
		memcpy(p, data, data_len);
	p += data_len;
	remaining -= data_len;

	return (int)(buf_len - remaining);
}
EXPORT_SYMBOL_GPL(tquic_write_stream_frame);

/**
 * tquic_write_max_data_frame - Write MAX_DATA frame
 * @buf: Output buffer
 * @buf_len: Length of buffer
 * @max_data: Maximum data value
 *
 * Returns bytes written on success, negative error code on failure.
 */
int tquic_write_max_data_frame(u8 *buf, size_t buf_len, u64 max_data)
{
	u8 *p = buf;
	size_t remaining = buf_len;
	int ret;

	if (remaining < 1)
		return -ENOSPC;
	*p++ = TQUIC_FRAME_MAX_DATA;
	remaining--;

	ret = frame_varint_encode(max_data, p, remaining);
	if (ret < 0)
		return ret;
	p += ret;
	remaining -= ret;

	return (int)(buf_len - remaining);
}
EXPORT_SYMBOL_GPL(tquic_write_max_data_frame);

/**
 * tquic_write_max_stream_data_frame - Write MAX_STREAM_DATA frame
 * @buf: Output buffer
 * @buf_len: Length of buffer
 * @stream_id: Stream identifier
 * @max_stream_data: Maximum stream data value
 *
 * Returns bytes written on success, negative error code on failure.
 */
int tquic_write_max_stream_data_frame(u8 *buf, size_t buf_len, u64 stream_id,
				      u64 max_stream_data)
{
	u8 *p = buf;
	size_t remaining = buf_len;
	int ret;

	if (remaining < 1)
		return -ENOSPC;
	*p++ = TQUIC_FRAME_MAX_STREAM_DATA;
	remaining--;

	ret = frame_varint_encode(stream_id, p, remaining);
	if (ret < 0)
		return ret;
	p += ret;
	remaining -= ret;

	ret = frame_varint_encode(max_stream_data, p, remaining);
	if (ret < 0)
		return ret;
	p += ret;
	remaining -= ret;

	return (int)(buf_len - remaining);
}
EXPORT_SYMBOL_GPL(tquic_write_max_stream_data_frame);

/**
 * tquic_write_max_streams_frame - Write MAX_STREAMS frame
 * @buf: Output buffer
 * @buf_len: Length of buffer
 * @max_streams: Maximum streams value
 * @bidi: true for bidirectional, false for unidirectional
 *
 * Returns bytes written on success, negative error code on failure.
 */
int tquic_write_max_streams_frame(u8 *buf, size_t buf_len, u64 max_streams,
				  bool bidi)
{
	u8 *p = buf;
	size_t remaining = buf_len;
	int ret;

	/* Validate max_streams doesn't exceed 2^60 */
	if (max_streams > (1ULL << 60))
		return -EINVAL;

	if (remaining < 1)
		return -ENOSPC;
	*p++ = bidi ? TQUIC_FRAME_MAX_STREAMS_BIDI : TQUIC_FRAME_MAX_STREAMS_UNI;
	remaining--;

	ret = frame_varint_encode(max_streams, p, remaining);
	if (ret < 0)
		return ret;
	p += ret;
	remaining -= ret;

	return (int)(buf_len - remaining);
}
EXPORT_SYMBOL_GPL(tquic_write_max_streams_frame);

/**
 * tquic_write_data_blocked_frame - Write DATA_BLOCKED frame
 * @buf: Output buffer
 * @buf_len: Length of buffer
 * @max_data: Maximum data limit at which blocking occurred
 *
 * Returns bytes written on success, negative error code on failure.
 */
int tquic_write_data_blocked_frame(u8 *buf, size_t buf_len, u64 max_data)
{
	u8 *p = buf;
	size_t remaining = buf_len;
	int ret;

	if (remaining < 1)
		return -ENOSPC;
	*p++ = TQUIC_FRAME_DATA_BLOCKED;
	remaining--;

	ret = frame_varint_encode(max_data, p, remaining);
	if (ret < 0)
		return ret;
	p += ret;
	remaining -= ret;

	return (int)(buf_len - remaining);
}
EXPORT_SYMBOL_GPL(tquic_write_data_blocked_frame);

/**
 * tquic_write_stream_data_blocked_frame - Write STREAM_DATA_BLOCKED frame
 * @buf: Output buffer
 * @buf_len: Length of buffer
 * @stream_id: Stream identifier
 * @max_stream_data: Limit at which blocking occurred
 *
 * Returns bytes written on success, negative error code on failure.
 */
int tquic_write_stream_data_blocked_frame(u8 *buf, size_t buf_len,
					  u64 stream_id, u64 max_stream_data)
{
	u8 *p = buf;
	size_t remaining = buf_len;
	int ret;

	if (remaining < 1)
		return -ENOSPC;
	*p++ = TQUIC_FRAME_STREAM_DATA_BLOCKED;
	remaining--;

	ret = frame_varint_encode(stream_id, p, remaining);
	if (ret < 0)
		return ret;
	p += ret;
	remaining -= ret;

	ret = frame_varint_encode(max_stream_data, p, remaining);
	if (ret < 0)
		return ret;
	p += ret;
	remaining -= ret;

	return (int)(buf_len - remaining);
}
EXPORT_SYMBOL_GPL(tquic_write_stream_data_blocked_frame);

/**
 * tquic_write_streams_blocked_frame - Write STREAMS_BLOCKED frame
 * @buf: Output buffer
 * @buf_len: Length of buffer
 * @max_streams: Limit at which blocking occurred
 * @bidi: true for bidirectional, false for unidirectional
 *
 * Returns bytes written on success, negative error code on failure.
 */
int tquic_write_streams_blocked_frame(u8 *buf, size_t buf_len, u64 max_streams,
				      bool bidi)
{
	u8 *p = buf;
	size_t remaining = buf_len;
	int ret;

	/* Validate max_streams doesn't exceed 2^60 */
	if (max_streams > (1ULL << 60))
		return -EINVAL;

	if (remaining < 1)
		return -ENOSPC;
	*p++ = bidi ? TQUIC_FRAME_STREAMS_BLOCKED_BIDI :
		      TQUIC_FRAME_STREAMS_BLOCKED_UNI;
	remaining--;

	ret = frame_varint_encode(max_streams, p, remaining);
	if (ret < 0)
		return ret;
	p += ret;
	remaining -= ret;

	return (int)(buf_len - remaining);
}
EXPORT_SYMBOL_GPL(tquic_write_streams_blocked_frame);

/**
 * tquic_write_new_connection_id_frame - Write NEW_CONNECTION_ID frame
 * @buf: Output buffer
 * @buf_len: Length of buffer
 * @seq_num: Sequence number
 * @retire_prior_to: Retire prior to value
 * @cid: Connection ID
 * @cid_len: Connection ID length (1-20)
 * @stateless_reset_token: Stateless reset token (16 bytes)
 *
 * Returns bytes written on success, negative error code on failure.
 */
int tquic_write_new_connection_id_frame(u8 *buf, size_t buf_len, u64 seq_num,
					u64 retire_prior_to, const u8 *cid,
					u8 cid_len, const u8 *stateless_reset_token)
{
	u8 *p = buf;
	size_t remaining = buf_len;
	int ret;

	/* Validate CID length */
	if (cid_len < 1 || cid_len > TQUIC_MAX_CID_LEN)
		return -EINVAL;

	/* Validate retire_prior_to <= seq_num */
	if (retire_prior_to > seq_num)
		return -EINVAL;

	if (remaining < 1)
		return -ENOSPC;
	*p++ = TQUIC_FRAME_NEW_CONNECTION_ID;
	remaining--;

	ret = frame_varint_encode(seq_num, p, remaining);
	if (ret < 0)
		return ret;
	p += ret;
	remaining -= ret;

	ret = frame_varint_encode(retire_prior_to, p, remaining);
	if (ret < 0)
		return ret;
	p += ret;
	remaining -= ret;

	/* CID length (1 byte, not varint) */
	if (remaining < 1)
		return -ENOSPC;
	*p++ = cid_len;
	remaining--;

	/* Connection ID */
	if (remaining < cid_len)
		return -ENOSPC;
	memcpy(p, cid, cid_len);
	p += cid_len;
	remaining -= cid_len;

	/* Stateless Reset Token */
	if (remaining < TQUIC_STATELESS_RESET_TOKEN_LEN)
		return -ENOSPC;
	memcpy(p, stateless_reset_token, TQUIC_STATELESS_RESET_TOKEN_LEN);
	p += TQUIC_STATELESS_RESET_TOKEN_LEN;
	remaining -= TQUIC_STATELESS_RESET_TOKEN_LEN;

	return (int)(buf_len - remaining);
}
EXPORT_SYMBOL_GPL(tquic_write_new_connection_id_frame);

/**
 * tquic_write_retire_connection_id_frame - Write RETIRE_CONNECTION_ID frame
 * @buf: Output buffer
 * @buf_len: Length of buffer
 * @seq_num: Sequence number to retire
 *
 * Returns bytes written on success, negative error code on failure.
 */
int tquic_write_retire_connection_id_frame(u8 *buf, size_t buf_len, u64 seq_num)
{
	u8 *p = buf;
	size_t remaining = buf_len;
	int ret;

	if (remaining < 1)
		return -ENOSPC;
	*p++ = TQUIC_FRAME_RETIRE_CONNECTION_ID;
	remaining--;

	ret = frame_varint_encode(seq_num, p, remaining);
	if (ret < 0)
		return ret;
	p += ret;
	remaining -= ret;

	return (int)(buf_len - remaining);
}
EXPORT_SYMBOL_GPL(tquic_write_retire_connection_id_frame);

/**
 * tquic_write_path_challenge_frame - Write PATH_CHALLENGE frame
 * @buf: Output buffer
 * @buf_len: Length of buffer
 * @data: 8 bytes of challenge data
 *
 * Returns bytes written on success, negative error code on failure.
 */
int tquic_write_path_challenge_frame(u8 *buf, size_t buf_len, const u8 *data)
{
	if (buf_len < 9)
		return -ENOSPC;

	buf[0] = TQUIC_FRAME_PATH_CHALLENGE;
	memcpy(buf + 1, data, 8);

	return 9;
}
EXPORT_SYMBOL_GPL(tquic_write_path_challenge_frame);

/**
 * tquic_write_path_response_frame - Write PATH_RESPONSE frame
 * @buf: Output buffer
 * @buf_len: Length of buffer
 * @data: 8 bytes of response data (must match challenge)
 *
 * Returns bytes written on success, negative error code on failure.
 */
int tquic_write_path_response_frame(u8 *buf, size_t buf_len, const u8 *data)
{
	if (buf_len < 9)
		return -ENOSPC;

	buf[0] = TQUIC_FRAME_PATH_RESPONSE;
	memcpy(buf + 1, data, 8);

	return 9;
}
EXPORT_SYMBOL_GPL(tquic_write_path_response_frame);

/**
 * tquic_write_connection_close_frame - Write CONNECTION_CLOSE frame
 * @buf: Output buffer
 * @buf_len: Length of buffer
 * @error_code: Error code
 * @frame_type: Frame type that triggered close (ignored if app_close)
 * @reason: Reason phrase (can be NULL)
 * @reason_len: Length of reason phrase
 * @app_close: true for application close (0x1d), false for transport (0x1c)
 *
 * Returns bytes written on success, negative error code on failure.
 */
int tquic_write_connection_close_frame(u8 *buf, size_t buf_len, u64 error_code,
				       u64 frame_type, const u8 *reason,
				       u64 reason_len, bool app_close)
{
	u8 *p = buf;
	size_t remaining = buf_len;
	int ret;

	tquic_dbg("tquic_write_connection_close_frame: error=%llu app=%d\n",
		  error_code, app_close);
	if (remaining < 1)
		return -ENOSPC;
	*p++ = app_close ? TQUIC_FRAME_CONNECTION_CLOSE_APP :
			   TQUIC_FRAME_CONNECTION_CLOSE;
	remaining--;

	ret = frame_varint_encode(error_code, p, remaining);
	if (ret < 0)
		return ret;
	p += ret;
	remaining -= ret;

	/* Frame type (only for transport close) */
	if (!app_close) {
		ret = frame_varint_encode(frame_type, p, remaining);
		if (ret < 0)
			return ret;
		p += ret;
		remaining -= ret;
	}

	ret = frame_varint_encode(reason_len, p, remaining);
	if (ret < 0)
		return ret;
	p += ret;
	remaining -= ret;

	if (reason_len > 0) {
		/* Validate reason_len doesn't exceed size_t and remaining buffer */
		if (reason_len > SIZE_MAX || remaining < reason_len)
			return -ENOSPC;
		memcpy(p, reason, reason_len);
		p += reason_len;
		remaining -= reason_len;
	}

	return (int)(buf_len - remaining);
}
EXPORT_SYMBOL_GPL(tquic_write_connection_close_frame);

/**
 * tquic_write_handshake_done_frame - Write HANDSHAKE_DONE frame
 * @buf: Output buffer
 * @buf_len: Length of buffer
 *
 * Returns bytes written on success, negative error code on failure.
 */
int tquic_write_handshake_done_frame(u8 *buf, size_t buf_len)
{
	if (buf_len < 1)
		return -ENOSPC;

	buf[0] = TQUIC_FRAME_HANDSHAKE_DONE;
	return 1;
}
EXPORT_SYMBOL_GPL(tquic_write_handshake_done_frame);

/**
 * tquic_write_datagram_frame - Write DATAGRAM frame (RFC 9221)
 * @buf: Output buffer
 * @buf_len: Length of buffer
 * @data: Datagram payload
 * @data_len: Length of payload
 * @with_length: true to include length field (type 0x31), false for 0x30
 *
 * DATAGRAM frames carry unreliable, unordered application data.
 * Type 0x30 has no length field (data extends to end of packet).
 * Type 0x31 includes an explicit length field.
 *
 * Returns bytes written on success, negative error code on failure.
 */
int tquic_write_datagram_frame(u8 *buf, size_t buf_len, const u8 *data,
			       u64 data_len, bool with_length)
{
	u8 *p = buf;
	size_t remaining = buf_len;
	int ret;

	if (remaining < 1)
		return -ENOSPC;

	/* Frame type: 0x30 without length, 0x31 with length */
	*p++ = with_length ? TQUIC_FRAME_DATAGRAM_LEN : TQUIC_FRAME_DATAGRAM;
	remaining--;

	if (with_length) {
		ret = frame_varint_encode(data_len, p, remaining);
		if (ret < 0)
			return ret;
		p += ret;
		remaining -= ret;
	}

	/* Validate data_len doesn't exceed SIZE_MAX and remaining buffer */
	if (data_len > SIZE_MAX || remaining < data_len)
		return -ENOSPC;

	if (data_len > 0)
		memcpy(p, data, data_len);
	p += data_len;
	remaining -= data_len;

	return (int)(buf_len - remaining);
}
EXPORT_SYMBOL_GPL(tquic_write_datagram_frame);

/* =========================================================================
 * Utility Functions
 * ========================================================================= */

/**
 * tquic_frame_type_name - Get human-readable name for frame type
 * @type: Frame type byte
 *
 * Returns string name for the frame type.
 */
const char *tquic_frame_type_name(u8 type)
{
	/* Handle STREAM frames (0x08-0x0f) */
	if (type >= TQUIC_FRAME_STREAM_BASE && type <= TQUIC_FRAME_STREAM_MAX)
		return "STREAM";

	switch (type) {
	case TQUIC_FRAME_PADDING:
		return "PADDING";
	case TQUIC_FRAME_PING:
		return "PING";
	case TQUIC_FRAME_ACK:
		return "ACK";
	case TQUIC_FRAME_ACK_ECN:
		return "ACK_ECN";
	case TQUIC_FRAME_RESET_STREAM:
		return "RESET_STREAM";
	case TQUIC_FRAME_STOP_SENDING:
		return "STOP_SENDING";
	case TQUIC_FRAME_CRYPTO:
		return "CRYPTO";
	case TQUIC_FRAME_NEW_TOKEN:
		return "NEW_TOKEN";
	case TQUIC_FRAME_MAX_DATA:
		return "MAX_DATA";
	case TQUIC_FRAME_MAX_STREAM_DATA:
		return "MAX_STREAM_DATA";
	case TQUIC_FRAME_MAX_STREAMS_BIDI:
		return "MAX_STREAMS_BIDI";
	case TQUIC_FRAME_MAX_STREAMS_UNI:
		return "MAX_STREAMS_UNI";
	case TQUIC_FRAME_DATA_BLOCKED:
		return "DATA_BLOCKED";
	case TQUIC_FRAME_STREAM_DATA_BLOCKED:
		return "STREAM_DATA_BLOCKED";
	case TQUIC_FRAME_STREAMS_BLOCKED_BIDI:
		return "STREAMS_BLOCKED_BIDI";
	case TQUIC_FRAME_STREAMS_BLOCKED_UNI:
		return "STREAMS_BLOCKED_UNI";
	case TQUIC_FRAME_NEW_CONNECTION_ID:
		return "NEW_CONNECTION_ID";
	case TQUIC_FRAME_RETIRE_CONNECTION_ID:
		return "RETIRE_CONNECTION_ID";
	case TQUIC_FRAME_PATH_CHALLENGE:
		return "PATH_CHALLENGE";
	case TQUIC_FRAME_PATH_RESPONSE:
		return "PATH_RESPONSE";
	case TQUIC_FRAME_CONNECTION_CLOSE:
		return "CONNECTION_CLOSE";
	case TQUIC_FRAME_CONNECTION_CLOSE_APP:
		return "CONNECTION_CLOSE_APP";
	case TQUIC_FRAME_HANDSHAKE_DONE:
		return "HANDSHAKE_DONE";
	case TQUIC_FRAME_DATAGRAM:
	case TQUIC_FRAME_DATAGRAM_LEN:
		return "DATAGRAM";
	default:
		return "UNKNOWN";
	}
}
EXPORT_SYMBOL_GPL(tquic_frame_type_name);

/**
 * tquic_frame_is_ack_eliciting - Check if frame type elicits ACK
 * @type: Frame type byte
 *
 * Returns true if the frame type requires acknowledgment.
 * PADDING, ACK, and CONNECTION_CLOSE frames do not elicit ACKs.
 */
bool tquic_frame_is_ack_eliciting(u8 type)
{
	switch (type) {
	case TQUIC_FRAME_PADDING:
	case TQUIC_FRAME_ACK:
	case TQUIC_FRAME_ACK_ECN:
	case TQUIC_FRAME_CONNECTION_CLOSE:
	case TQUIC_FRAME_CONNECTION_CLOSE_APP:
		return false;
	default:
		return true;
	}
}
EXPORT_SYMBOL_GPL(tquic_frame_is_ack_eliciting);

/**
 * tquic_frame_is_probing - Check if frame is a probing frame
 * @type: Frame type byte
 *
 * Returns true if this is a probing frame (PATH_CHALLENGE, PATH_RESPONSE,
 * NEW_CONNECTION_ID, PADDING).
 */
bool tquic_frame_is_probing(u8 type)
{
	switch (type) {
	case TQUIC_FRAME_PADDING:
	case TQUIC_FRAME_PATH_CHALLENGE:
	case TQUIC_FRAME_PATH_RESPONSE:
	case TQUIC_FRAME_NEW_CONNECTION_ID:
		return true;
	default:
		return false;
	}
}
EXPORT_SYMBOL_GPL(tquic_frame_is_probing);

/**
 * tquic_frame_allowed_in_pn_space - Check if frame allowed in packet number space
 * @type: Frame type byte
 * @pn_space: Packet number space (0=Initial, 1=Handshake, 2=Application)
 *
 * Returns true if the frame type is allowed in the given packet number space.
 */
bool tquic_frame_allowed_in_pn_space(u8 type, int pn_space)
{
	/* Handle STREAM frames */
	if (type >= TQUIC_FRAME_STREAM_BASE && type <= TQUIC_FRAME_STREAM_MAX) {
		/* STREAM only allowed in Application (1-RTT) */
		return pn_space == TQUIC_PN_SPACE_APPLICATION;
	}

	switch (type) {
	/* Allowed in all packet number spaces */
	case TQUIC_FRAME_PADDING:
	case TQUIC_FRAME_PING:
	case TQUIC_FRAME_CRYPTO:
	case TQUIC_FRAME_CONNECTION_CLOSE:
		return true;

	/* Only allowed in Initial and Handshake */
	case TQUIC_FRAME_ACK:
	case TQUIC_FRAME_ACK_ECN:
		return true;  /* ACK allowed in all spaces */

	/* Only allowed in Application (1-RTT) */
	case TQUIC_FRAME_RESET_STREAM:
	case TQUIC_FRAME_STOP_SENDING:
	case TQUIC_FRAME_NEW_TOKEN:
	case TQUIC_FRAME_MAX_DATA:
	case TQUIC_FRAME_MAX_STREAM_DATA:
	case TQUIC_FRAME_MAX_STREAMS_BIDI:
	case TQUIC_FRAME_MAX_STREAMS_UNI:
	case TQUIC_FRAME_DATA_BLOCKED:
	case TQUIC_FRAME_STREAM_DATA_BLOCKED:
	case TQUIC_FRAME_STREAMS_BLOCKED_BIDI:
	case TQUIC_FRAME_STREAMS_BLOCKED_UNI:
	case TQUIC_FRAME_NEW_CONNECTION_ID:
	case TQUIC_FRAME_RETIRE_CONNECTION_ID:
	case TQUIC_FRAME_PATH_CHALLENGE:
	case TQUIC_FRAME_PATH_RESPONSE:
	case TQUIC_FRAME_CONNECTION_CLOSE_APP:
	case TQUIC_FRAME_HANDSHAKE_DONE:
	case TQUIC_FRAME_DATAGRAM:
	case TQUIC_FRAME_DATAGRAM_LEN:
		return pn_space == TQUIC_PN_SPACE_APPLICATION;

	default:
		return false;
	}
}
EXPORT_SYMBOL_GPL(tquic_frame_allowed_in_pn_space);

/* =========================================================================
 * Variable-Length Integer API (exported for other modules)
 * ========================================================================= */

/**
 * tquic_varint_encode_len - Get encoded length for a value
 * @val: Value to encode
 *
 * Returns the number of bytes needed, or 0 if value is too large.
 */
size_t tquic_varint_encode_len(u64 val)
{
	return frame_varint_len(val);
}
EXPORT_SYMBOL_GPL(tquic_varint_encode_len);

MODULE_DESCRIPTION("TQUIC Frame Parsing and Construction");
MODULE_LICENSE("GPL");
