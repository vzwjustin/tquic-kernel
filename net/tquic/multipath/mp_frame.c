// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: QUIC Multipath Frame Parsing and Generation
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Implementation of frame parsing and generation for QUIC Multipath
 * Extension (RFC 9369). This module handles:
 *   - PATH_ABANDON frame parsing and generation
 *   - MP_NEW_CONNECTION_ID frame parsing and generation
 *   - MP_RETIRE_CONNECTION_ID frame parsing and generation
 *   - MP_ACK frame parsing and generation
 *   - PATH_STATUS frame parsing and generation
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <net/tquic.h>

#include "mp_frame.h"
#include "../core/varint.h"
#include "../tquic_debug.h"

/*
 * =============================================================================
 * Variable-length Integer Helpers
 * =============================================================================
 */

/**
 * mp_varint_size - Calculate encoded size of a varint
 * @val: Value to encode
 *
 * Returns number of bytes needed.
 */
static inline size_t mp_varint_size(u64 val)
{
	if (val <= 63)
		return 1;
	if (val <= 16383)
		return 2;
	if (val <= 1073741823)
		return 4;
	return 8;
}

/**
 * mp_varint_decode - Decode a varint from buffer
 * @buf: Input buffer
 * @len: Buffer length
 * @val: Output value
 * @consumed: Output bytes consumed
 *
 * Returns 0 on success, negative error on failure.
 */
static int mp_varint_decode(const u8 *buf, size_t len, u64 *val, size_t *consumed)
{
	size_t varint_len;
	u64 v;

	if (!buf || !val || len < 1)
		return -EINVAL;

	/* Determine length from prefix bits */
	varint_len = 1 << ((buf[0] & 0xc0) >> 6);

	if (len < varint_len)
		return -ENODATA;

	switch (varint_len) {
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
		*consumed = varint_len;

	return 0;
}

/**
 * mp_varint_encode - Encode a varint to buffer
 * @val: Value to encode
 * @buf: Output buffer
 * @len: Buffer length
 *
 * Returns bytes written on success, negative error on failure.
 */
static int mp_varint_encode(u64 val, u8 *buf, size_t len)
{
	size_t needed = mp_varint_size(val);

	if (len < needed)
		return -ENOSPC;

	switch (needed) {
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

	return (int)needed;
}

/*
 * =============================================================================
 * PATH_ABANDON Frame (RFC 9369 Section 5.3)
 * =============================================================================
 */

/**
 * tquic_mp_parse_path_abandon - Parse PATH_ABANDON frame
 * @buf: Input buffer (starting at frame type)
 * @len: Buffer length
 * @frame: Output parsed frame
 *
 * PATH_ABANDON Frame {
 *   Type (i) = 0x17,
 *   Path Identifier (i),
 *   Error Code (i),
 *   Reason Phrase Length (i),
 *   Reason Phrase (..),
 * }
 *
 * Returns number of bytes consumed or negative error.
 */
int tquic_mp_parse_path_abandon(const u8 *buf, size_t len,
				struct tquic_mp_path_abandon *frame)
{
	size_t offset = 0;
	size_t consumed;
	int ret;

	if (!buf || !frame || len < 1)
		return -EINVAL;

	memset(frame, 0, sizeof(*frame));

	/* Skip frame type - caller should verify it's 0x17 */
	ret = mp_varint_decode(buf, len, &frame->path_id, &consumed);
	if (ret < 0)
		return ret;

	/* Frame type is varint, skip it */
	offset = consumed;

	/* Path Identifier */
	ret = mp_varint_decode(buf + offset, len - offset,
			       &frame->path_id, &consumed);
	if (ret < 0)
		return ret;
	offset += consumed;

	/* Error Code */
	ret = mp_varint_decode(buf + offset, len - offset,
			       &frame->error_code, &consumed);
	if (ret < 0)
		return ret;
	offset += consumed;

	/* Reason Phrase Length */
	ret = mp_varint_decode(buf + offset, len - offset,
			       &frame->reason_len, &consumed);
	if (ret < 0)
		return ret;
	offset += consumed;

	/* Validate reason length */
	if (frame->reason_len > TQUIC_MP_MAX_REASON_LEN)
		return -EINVAL;

	if (len - offset < frame->reason_len)
		return -ENODATA;

	/* Reason Phrase */
	if (frame->reason_len > 0) {
		memcpy(frame->reason, buf + offset, frame->reason_len);
		offset += frame->reason_len;
	}

	return (int)offset;
}
EXPORT_SYMBOL_GPL(tquic_mp_parse_path_abandon);

/**
 * tquic_mp_write_path_abandon - Write PATH_ABANDON frame
 * @frame: Frame to write
 * @buf: Output buffer
 * @len: Buffer length
 *
 * Returns number of bytes written or negative error.
 */
int tquic_mp_write_path_abandon(const struct tquic_mp_path_abandon *frame,
				u8 *buf, size_t len)
{
	size_t offset = 0;
	int ret;

	if (!frame || !buf)
		return -EINVAL;

	/* Frame Type (0x17) */
	ret = mp_varint_encode(TQUIC_MP_FRAME_PATH_ABANDON, buf + offset,
			       len - offset);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Path Identifier */
	ret = mp_varint_encode(frame->path_id, buf + offset, len - offset);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Error Code */
	ret = mp_varint_encode(frame->error_code, buf + offset, len - offset);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Reason Phrase Length */
	ret = mp_varint_encode(frame->reason_len, buf + offset, len - offset);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Reason Phrase */
	if (frame->reason_len > 0) {
		if (len - offset < frame->reason_len)
			return -ENOSPC;
		memcpy(buf + offset, frame->reason, frame->reason_len);
		offset += frame->reason_len;
	}

	return (int)offset;
}
EXPORT_SYMBOL_GPL(tquic_mp_write_path_abandon);

/**
 * tquic_mp_path_abandon_size - Calculate encoded size of PATH_ABANDON
 * @frame: Frame to measure
 *
 * Returns encoded size in bytes.
 */
size_t tquic_mp_path_abandon_size(const struct tquic_mp_path_abandon *frame)
{
	size_t size = 0;

	if (!frame)
		return 0;

	size += mp_varint_size(TQUIC_MP_FRAME_PATH_ABANDON);
	size += mp_varint_size(frame->path_id);
	size += mp_varint_size(frame->error_code);
	size += mp_varint_size(frame->reason_len);
	size += frame->reason_len;

	return size;
}
EXPORT_SYMBOL_GPL(tquic_mp_path_abandon_size);

/*
 * =============================================================================
 * MP_NEW_CONNECTION_ID Frame (RFC 9369 Section 5.1)
 * =============================================================================
 */

/**
 * tquic_mp_parse_new_connection_id - Parse MP_NEW_CONNECTION_ID frame
 * @buf: Input buffer
 * @len: Buffer length
 * @frame: Output parsed frame
 *
 * MP_NEW_CONNECTION_ID Frame {
 *   Type (i) = 0x40,
 *   Path Identifier (i),
 *   Sequence Number (i),
 *   Retire Prior To (i),
 *   Length (8),
 *   Connection ID (8..160),
 *   Stateless Reset Token (128),
 * }
 *
 * Returns number of bytes consumed or negative error.
 */
int tquic_mp_parse_new_connection_id(const u8 *buf, size_t len,
				     struct tquic_mp_new_connection_id *frame)
{
	size_t offset = 0;
	size_t consumed;
	u64 frame_type;
	int ret;

	if (!buf || !frame || len < 1)
		return -EINVAL;

	memset(frame, 0, sizeof(*frame));

	/* Frame Type */
	ret = mp_varint_decode(buf, len, &frame_type, &consumed);
	if (ret < 0)
		return ret;
	if (frame_type != TQUIC_MP_FRAME_MP_NEW_CONNECTION_ID)
		return -EINVAL;
	offset = consumed;

	/* Path Identifier */
	ret = mp_varint_decode(buf + offset, len - offset,
			       &frame->path_id, &consumed);
	if (ret < 0)
		return ret;
	offset += consumed;

	/* Sequence Number */
	ret = mp_varint_decode(buf + offset, len - offset,
			       &frame->seq_num, &consumed);
	if (ret < 0)
		return ret;
	offset += consumed;

	/* Retire Prior To */
	ret = mp_varint_decode(buf + offset, len - offset,
			       &frame->retire_prior_to, &consumed);
	if (ret < 0)
		return ret;
	offset += consumed;

	/* Validate retire_prior_to <= seq_num */
	if (frame->retire_prior_to > frame->seq_num)
		return -EINVAL;

	/* Connection ID Length (1 byte) */
	if (len - offset < 1)
		return -ENODATA;
	frame->cid_len = buf[offset];
	offset++;

	/* Validate CID length */
	if (frame->cid_len > TQUIC_MAX_CID_LEN)
		return -EINVAL;

	/* Connection ID */
	if (len - offset < frame->cid_len)
		return -ENODATA;
	memcpy(frame->cid, buf + offset, frame->cid_len);
	offset += frame->cid_len;

	/* Stateless Reset Token (16 bytes) */
	if (len - offset < TQUIC_MP_RESET_TOKEN_LEN)
		return -ENODATA;
	memcpy(frame->stateless_reset_token, buf + offset,
	       TQUIC_MP_RESET_TOKEN_LEN);
	offset += TQUIC_MP_RESET_TOKEN_LEN;

	return (int)offset;
}
EXPORT_SYMBOL_GPL(tquic_mp_parse_new_connection_id);

/**
 * tquic_mp_write_new_connection_id - Write MP_NEW_CONNECTION_ID frame
 * @frame: Frame to write
 * @buf: Output buffer
 * @len: Buffer length
 *
 * Returns number of bytes written or negative error.
 */
int tquic_mp_write_new_connection_id(const struct tquic_mp_new_connection_id *frame,
				     u8 *buf, size_t len)
{
	size_t offset = 0;
	int ret;

	if (!frame || !buf)
		return -EINVAL;

	if (frame->cid_len > TQUIC_MAX_CID_LEN)
		return -EINVAL;

	/* Frame Type (0x40) */
	ret = mp_varint_encode(TQUIC_MP_FRAME_MP_NEW_CONNECTION_ID,
			       buf + offset, len - offset);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Path Identifier */
	ret = mp_varint_encode(frame->path_id, buf + offset, len - offset);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Sequence Number */
	ret = mp_varint_encode(frame->seq_num, buf + offset, len - offset);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Retire Prior To */
	ret = mp_varint_encode(frame->retire_prior_to, buf + offset,
			       len - offset);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Connection ID Length (1 byte) */
	if (len - offset < 1 + frame->cid_len + TQUIC_MP_RESET_TOKEN_LEN)
		return -ENOSPC;
	buf[offset] = frame->cid_len;
	offset++;

	/* Connection ID */
	memcpy(buf + offset, frame->cid, frame->cid_len);
	offset += frame->cid_len;

	/* Stateless Reset Token */
	memcpy(buf + offset, frame->stateless_reset_token,
	       TQUIC_MP_RESET_TOKEN_LEN);
	offset += TQUIC_MP_RESET_TOKEN_LEN;

	return (int)offset;
}
EXPORT_SYMBOL_GPL(tquic_mp_write_new_connection_id);

/**
 * tquic_mp_new_connection_id_size - Calculate encoded size
 * @frame: Frame to measure
 *
 * Returns encoded size in bytes.
 */
size_t tquic_mp_new_connection_id_size(const struct tquic_mp_new_connection_id *frame)
{
	size_t size = 0;

	if (!frame)
		return 0;

	size += mp_varint_size(TQUIC_MP_FRAME_MP_NEW_CONNECTION_ID);
	size += mp_varint_size(frame->path_id);
	size += mp_varint_size(frame->seq_num);
	size += mp_varint_size(frame->retire_prior_to);
	size += 1;  /* CID length */
	size += frame->cid_len;
	size += TQUIC_MP_RESET_TOKEN_LEN;

	return size;
}
EXPORT_SYMBOL_GPL(tquic_mp_new_connection_id_size);

/*
 * =============================================================================
 * MP_RETIRE_CONNECTION_ID Frame (RFC 9369 Section 5.2)
 * =============================================================================
 */

/**
 * tquic_mp_parse_retire_connection_id - Parse MP_RETIRE_CONNECTION_ID frame
 * @buf: Input buffer
 * @len: Buffer length
 * @frame: Output parsed frame
 *
 * MP_RETIRE_CONNECTION_ID Frame {
 *   Type (i) = 0x41,
 *   Path Identifier (i),
 *   Sequence Number (i),
 * }
 *
 * Returns number of bytes consumed or negative error.
 */
int tquic_mp_parse_retire_connection_id(const u8 *buf, size_t len,
					struct tquic_mp_retire_connection_id *frame)
{
	size_t offset = 0;
	size_t consumed;
	u64 frame_type;
	int ret;

	if (!buf || !frame || len < 1)
		return -EINVAL;

	memset(frame, 0, sizeof(*frame));

	/* Frame Type */
	ret = mp_varint_decode(buf, len, &frame_type, &consumed);
	if (ret < 0)
		return ret;
	if (frame_type != TQUIC_MP_FRAME_MP_RETIRE_CONNECTION_ID)
		return -EINVAL;
	offset = consumed;

	/* Path Identifier */
	ret = mp_varint_decode(buf + offset, len - offset,
			       &frame->path_id, &consumed);
	if (ret < 0)
		return ret;
	offset += consumed;

	/* Sequence Number */
	ret = mp_varint_decode(buf + offset, len - offset,
			       &frame->seq_num, &consumed);
	if (ret < 0)
		return ret;
	offset += consumed;

	return (int)offset;
}
EXPORT_SYMBOL_GPL(tquic_mp_parse_retire_connection_id);

/**
 * tquic_mp_write_retire_connection_id - Write MP_RETIRE_CONNECTION_ID frame
 * @frame: Frame to write
 * @buf: Output buffer
 * @len: Buffer length
 *
 * Returns number of bytes written or negative error.
 */
int tquic_mp_write_retire_connection_id(const struct tquic_mp_retire_connection_id *frame,
					u8 *buf, size_t len)
{
	size_t offset = 0;
	int ret;

	if (!frame || !buf)
		return -EINVAL;

	/* Frame Type (0x41) */
	ret = mp_varint_encode(TQUIC_MP_FRAME_MP_RETIRE_CONNECTION_ID,
			       buf + offset, len - offset);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Path Identifier */
	ret = mp_varint_encode(frame->path_id, buf + offset, len - offset);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Sequence Number */
	ret = mp_varint_encode(frame->seq_num, buf + offset, len - offset);
	if (ret < 0)
		return ret;
	offset += ret;

	return (int)offset;
}
EXPORT_SYMBOL_GPL(tquic_mp_write_retire_connection_id);

/**
 * tquic_mp_retire_connection_id_size - Calculate encoded size
 * @frame: Frame to measure
 *
 * Returns encoded size in bytes.
 */
size_t tquic_mp_retire_connection_id_size(const struct tquic_mp_retire_connection_id *frame)
{
	size_t size = 0;

	if (!frame)
		return 0;

	size += mp_varint_size(TQUIC_MP_FRAME_MP_RETIRE_CONNECTION_ID);
	size += mp_varint_size(frame->path_id);
	size += mp_varint_size(frame->seq_num);

	return size;
}
EXPORT_SYMBOL_GPL(tquic_mp_retire_connection_id_size);

/*
 * =============================================================================
 * MP_ACK Frame (RFC 9369 Section 5.4)
 * =============================================================================
 */

/**
 * tquic_mp_parse_ack - Parse MP_ACK frame
 * @buf: Input buffer
 * @len: Buffer length
 * @frame: Output parsed frame
 * @ack_delay_exponent: ACK delay exponent for conversion
 *
 * MP_ACK Frame {
 *   Type (i) = 0x42..0x43,
 *   Path Identifier (i),
 *   Largest Acknowledged (i),
 *   ACK Delay (i),
 *   ACK Range Count (i),
 *   First ACK Range (i),
 *   ACK Range (..) ...,
 *   [ECN Counts (..)],
 * }
 *
 * Returns number of bytes consumed or negative error.
 */
int tquic_mp_parse_ack(const u8 *buf, size_t len,
		       struct tquic_mp_ack *frame, u8 ack_delay_exponent)
{
	size_t offset = 0;
	size_t consumed;
	u64 frame_type;
	u64 i;
	u64 ack_delay_raw;
	int ret;

	if (!buf || !frame || len < 1)
		return -EINVAL;

	memset(frame, 0, sizeof(*frame));

	/* Frame Type */
	ret = mp_varint_decode(buf, len, &frame_type, &consumed);
	if (ret < 0)
		return ret;

	if (frame_type == TQUIC_MP_FRAME_MP_ACK_ECN)
		frame->has_ecn = true;
	else if (frame_type == TQUIC_MP_FRAME_MP_ACK)
		frame->has_ecn = false;
	else
		return -EINVAL;

	offset = consumed;

	/* Path Identifier */
	ret = mp_varint_decode(buf + offset, len - offset,
			       &frame->path_id, &consumed);
	if (ret < 0)
		return ret;
	offset += consumed;

	/* Largest Acknowledged */
	ret = mp_varint_decode(buf + offset, len - offset,
			       &frame->largest_ack, &consumed);
	if (ret < 0)
		return ret;
	offset += consumed;

	/* ACK Delay (convert from encoded value to microseconds) */
	ret = mp_varint_decode(buf + offset, len - offset,
			       &ack_delay_raw, &consumed);
	if (ret < 0)
		return ret;
	/* RFC 9000 Section 18.2: ack_delay_exponent values above 20 are invalid */
	if (ack_delay_exponent > 20)
		return -EPROTO;
	frame->ack_delay = min_t(u64, ack_delay_raw << ack_delay_exponent,
				 16000000ULL); /* cap at 16s */
	offset += consumed;

	/* ACK Range Count */
	ret = mp_varint_decode(buf + offset, len - offset,
			       &frame->ack_range_count, &consumed);
	if (ret < 0)
		return ret;
	offset += consumed;

	if (frame->ack_range_count > TQUIC_MP_MAX_ACK_RANGES)
		return -EINVAL;

	/* First ACK Range */
	ret = mp_varint_decode(buf + offset, len - offset,
			       &frame->first_ack_range, &consumed);
	if (ret < 0)
		return ret;
	offset += consumed;

	/* Validate first range doesn't exceed largest ack */
	if (frame->first_ack_range > frame->largest_ack)
		return -EINVAL;

	/* Additional ACK Ranges */
	for (i = 0; i < frame->ack_range_count; i++) {
		/* Gap */
		ret = mp_varint_decode(buf + offset, len - offset,
				       &frame->ranges[i].gap, &consumed);
		if (ret < 0)
			return ret;
		offset += consumed;

		/* ACK Range Length */
		ret = mp_varint_decode(buf + offset, len - offset,
				       &frame->ranges[i].ack_range_len, &consumed);
		if (ret < 0)
			return ret;
		offset += consumed;
	}

	/* ECN Counts (if present) */
	if (frame->has_ecn) {
		ret = mp_varint_decode(buf + offset, len - offset,
				       &frame->ect0_count, &consumed);
		if (ret < 0)
			return ret;
		offset += consumed;

		ret = mp_varint_decode(buf + offset, len - offset,
				       &frame->ect1_count, &consumed);
		if (ret < 0)
			return ret;
		offset += consumed;

		ret = mp_varint_decode(buf + offset, len - offset,
				       &frame->ecn_ce_count, &consumed);
		if (ret < 0)
			return ret;
		offset += consumed;
	}

	return (int)offset;
}
EXPORT_SYMBOL_GPL(tquic_mp_parse_ack);

/**
 * tquic_mp_write_ack - Write MP_ACK frame
 * @frame: Frame to write
 * @buf: Output buffer
 * @len: Buffer length
 * @ack_delay_exponent: ACK delay exponent for encoding
 *
 * Returns number of bytes written or negative error.
 */
int tquic_mp_write_ack(const struct tquic_mp_ack *frame,
		       u8 *buf, size_t len, u8 ack_delay_exponent)
{
	size_t offset = 0;
	u64 frame_type;
	u64 ack_delay_encoded;
	u64 i;
	int ret;

	if (!frame || !buf)
		return -EINVAL;

	/* Frame Type */
	frame_type = frame->has_ecn ? TQUIC_MP_FRAME_MP_ACK_ECN :
				      TQUIC_MP_FRAME_MP_ACK;
	ret = mp_varint_encode(frame_type, buf + offset, len - offset);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Path Identifier */
	ret = mp_varint_encode(frame->path_id, buf + offset, len - offset);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Largest Acknowledged */
	ret = mp_varint_encode(frame->largest_ack, buf + offset, len - offset);
	if (ret < 0)
		return ret;
	offset += ret;

	/* ACK Delay (encode from microseconds) */
	ack_delay_encoded = frame->ack_delay >> ack_delay_exponent;
	ret = mp_varint_encode(ack_delay_encoded, buf + offset, len - offset);
	if (ret < 0)
		return ret;
	offset += ret;

	/* ACK Range Count */
	ret = mp_varint_encode(frame->ack_range_count, buf + offset,
			       len - offset);
	if (ret < 0)
		return ret;
	offset += ret;

	/* First ACK Range */
	ret = mp_varint_encode(frame->first_ack_range, buf + offset,
			       len - offset);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Additional ACK Ranges */
	for (i = 0; i < frame->ack_range_count; i++) {
		/* Gap */
		ret = mp_varint_encode(frame->ranges[i].gap, buf + offset,
				       len - offset);
		if (ret < 0)
			return ret;
		offset += ret;

		/* ACK Range Length */
		ret = mp_varint_encode(frame->ranges[i].ack_range_len,
				       buf + offset, len - offset);
		if (ret < 0)
			return ret;
		offset += ret;
	}

	/* ECN Counts (if present) */
	if (frame->has_ecn) {
		ret = mp_varint_encode(frame->ect0_count, buf + offset,
				       len - offset);
		if (ret < 0)
			return ret;
		offset += ret;

		ret = mp_varint_encode(frame->ect1_count, buf + offset,
				       len - offset);
		if (ret < 0)
			return ret;
		offset += ret;

		ret = mp_varint_encode(frame->ecn_ce_count, buf + offset,
				       len - offset);
		if (ret < 0)
			return ret;
		offset += ret;
	}

	return (int)offset;
}
EXPORT_SYMBOL_GPL(tquic_mp_write_ack);

/**
 * tquic_mp_ack_size - Calculate encoded size of MP_ACK
 * @frame: Frame to measure
 *
 * Returns encoded size in bytes.
 */
size_t tquic_mp_ack_size(const struct tquic_mp_ack *frame)
{
	size_t size = 0;
	u64 frame_type;
	u64 i;

	if (!frame)
		return 0;

	frame_type = frame->has_ecn ? TQUIC_MP_FRAME_MP_ACK_ECN :
				      TQUIC_MP_FRAME_MP_ACK;
	size += mp_varint_size(frame_type);
	size += mp_varint_size(frame->path_id);
	size += mp_varint_size(frame->largest_ack);
	size += mp_varint_size(frame->ack_delay);
	size += mp_varint_size(frame->ack_range_count);
	size += mp_varint_size(frame->first_ack_range);

	for (i = 0; i < frame->ack_range_count; i++) {
		size += mp_varint_size(frame->ranges[i].gap);
		size += mp_varint_size(frame->ranges[i].ack_range_len);
	}

	if (frame->has_ecn) {
		size += mp_varint_size(frame->ect0_count);
		size += mp_varint_size(frame->ect1_count);
		size += mp_varint_size(frame->ecn_ce_count);
	}

	return size;
}
EXPORT_SYMBOL_GPL(tquic_mp_ack_size);

/*
 * =============================================================================
 * PATH_STATUS Frame (RFC 9369 Section 5.6)
 * =============================================================================
 */

/**
 * tquic_mp_parse_path_status - Parse PATH_STATUS frame
 * @buf: Input buffer
 * @len: Buffer length
 * @frame: Output parsed frame
 *
 * PATH_STATUS Frame {
 *   Type (i) = 0x44,
 *   Path Identifier (i),
 *   Path Status Sequence Number (i),
 *   Path Status (i),
 *   Priority (i),
 * }
 *
 * Returns number of bytes consumed or negative error.
 */
int tquic_mp_parse_path_status(const u8 *buf, size_t len,
			       struct tquic_mp_path_status *frame)
{
	size_t offset = 0;
	size_t consumed;
	u64 frame_type;
	int ret;

	if (!buf || !frame || len < 1)
		return -EINVAL;

	memset(frame, 0, sizeof(*frame));

	/* Frame Type */
	ret = mp_varint_decode(buf, len, &frame_type, &consumed);
	if (ret < 0)
		return ret;
	if (frame_type != TQUIC_MP_FRAME_PATH_STATUS)
		return -EINVAL;
	offset = consumed;

	/* Path Identifier */
	ret = mp_varint_decode(buf + offset, len - offset,
			       &frame->path_id, &consumed);
	if (ret < 0)
		return ret;
	offset += consumed;

	/* Path Status Sequence Number */
	ret = mp_varint_decode(buf + offset, len - offset,
			       &frame->seq_num, &consumed);
	if (ret < 0)
		return ret;
	offset += consumed;

	/* Path Status */
	ret = mp_varint_decode(buf + offset, len - offset,
			       &frame->status, &consumed);
	if (ret < 0)
		return ret;
	offset += consumed;

	/* Priority */
	ret = mp_varint_decode(buf + offset, len - offset,
			       &frame->priority, &consumed);
	if (ret < 0)
		return ret;
	offset += consumed;

	return (int)offset;
}
EXPORT_SYMBOL_GPL(tquic_mp_parse_path_status);

/**
 * tquic_mp_write_path_status - Write PATH_STATUS frame
 * @frame: Frame to write
 * @buf: Output buffer
 * @len: Buffer length
 *
 * Returns number of bytes written or negative error.
 */
int tquic_mp_write_path_status(const struct tquic_mp_path_status *frame,
			       u8 *buf, size_t len)
{
	size_t offset = 0;
	int ret;

	if (!frame || !buf)
		return -EINVAL;

	/* Frame Type (0x44) */
	ret = mp_varint_encode(TQUIC_MP_FRAME_PATH_STATUS, buf + offset,
			       len - offset);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Path Identifier */
	ret = mp_varint_encode(frame->path_id, buf + offset, len - offset);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Path Status Sequence Number */
	ret = mp_varint_encode(frame->seq_num, buf + offset, len - offset);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Path Status */
	ret = mp_varint_encode(frame->status, buf + offset, len - offset);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Priority */
	ret = mp_varint_encode(frame->priority, buf + offset, len - offset);
	if (ret < 0)
		return ret;
	offset += ret;

	return (int)offset;
}
EXPORT_SYMBOL_GPL(tquic_mp_write_path_status);

/**
 * tquic_mp_path_status_size - Calculate encoded size of PATH_STATUS
 * @frame: Frame to measure
 *
 * Returns encoded size in bytes.
 */
size_t tquic_mp_path_status_size(const struct tquic_mp_path_status *frame)
{
	size_t size = 0;

	if (!frame)
		return 0;

	size += mp_varint_size(TQUIC_MP_FRAME_PATH_STATUS);
	size += mp_varint_size(frame->path_id);
	size += mp_varint_size(frame->seq_num);
	size += mp_varint_size(frame->status);
	size += mp_varint_size(frame->priority);

	return size;
}
EXPORT_SYMBOL_GPL(tquic_mp_path_status_size);

/*
 * =============================================================================
 * Module Initialization
 * =============================================================================
 */

/**
 * tquic_mp_frame_init - Initialize multipath frame module
 */
int __init tquic_mp_frame_init(void)
{
	pr_info("tquic: Multipath frame support initialized (RFC 9369)\n");
	return 0;
}

/**
 * tquic_mp_frame_exit - Cleanup multipath frame module
 */
void __exit tquic_mp_frame_exit(void)
{
	pr_info("tquic: Multipath frame support cleaned up\n");
}

#ifndef TQUIC_OUT_OF_TREE
MODULE_DESCRIPTION("TQUIC Multipath Frame Support (RFC 9369)");
MODULE_LICENSE("GPL");
#endif
