// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC Variable-Length Integer Encoding
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Implementation of QUIC variable-length integer encoding and decoding
 * as specified in RFC 9000 Section 16.
 *
 * The encoding uses the 2 most significant bits of the first byte to
 * indicate the total length:
 *   00 = 1 byte:  6-bit value  (0 to 63)
 *   01 = 2 bytes: 14-bit value (0 to 16383)
 *   10 = 4 bytes: 30-bit value (0 to 1073741823)
 *   11 = 8 bytes: 62-bit value (0 to 4611686018427387903)
 *
 * All multi-byte values are stored in network byte order (big-endian).
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/unaligned.h>

#include "varint.h"

/**
 * tquic_varint_encode - Encode an integer to QUIC variable-length format
 * @value: The value to encode
 * @buf: Output buffer (must be at least 8 bytes)
 *
 * Encodes the value into the buffer using the minimum number of bytes.
 * Values are encoded in network byte order with length prefix in MSBs.
 *
 * Returns the number of bytes written, or negative error on failure.
 */
int tquic_varint_encode(u64 value, u8 *buf, size_t len)
{
	int needed;

	if (!buf)
		return -EINVAL;

	/* Calculate required length */
	needed = tquic_varint_size(value);
	if (needed <= 0 || (size_t)needed > len)
		return -ENOBUFS;

	if (value <= TQUIC_VARINT_1BYTE_MAX) {
		/* 1 byte: prefix 00, 6-bit value */
		buf[0] = (u8)value;
		return TQUIC_VARINT_SIZE_1BYTE;
	}

	if (value <= TQUIC_VARINT_2BYTE_MAX) {
		/* 2 bytes: prefix 01, 14-bit value in network byte order */
		put_unaligned_be16((u16)value | (TQUIC_VARINT_2BYTE_PREFIX << 8),
				   buf);
		return TQUIC_VARINT_SIZE_2BYTE;
	}

	if (value <= TQUIC_VARINT_4BYTE_MAX) {
		/* 4 bytes: prefix 10, 30-bit value in network byte order */
		put_unaligned_be32((u32)value | (TQUIC_VARINT_4BYTE_PREFIX << 24),
				   buf);
		return TQUIC_VARINT_SIZE_4BYTE;
	}

	if (value <= TQUIC_VARINT_8BYTE_MAX) {
		/* 8 bytes: prefix 11, 62-bit value in network byte order */
		put_unaligned_be64(value | ((u64)TQUIC_VARINT_8BYTE_PREFIX << 56),
				   buf);
		return TQUIC_VARINT_SIZE_8BYTE;
	}

	/* Value exceeds maximum encodable value */
	return -EOVERFLOW;
}
EXPORT_SYMBOL_GPL(tquic_varint_encode);

/**
 * tquic_varint_len - Calculate the encoded size for a value
 * @value: The value to be encoded
 *
 * Returns the number of bytes needed to encode the value, or 0 if the
 * value exceeds the maximum encodable value. This is an exported wrapper
 * around the inline tquic_varint_size().
 */
int tquic_varint_len(u64 value)
{
	return tquic_varint_size(value);
}
EXPORT_SYMBOL_GPL(tquic_varint_len);

/**
 * tquic_varint_decode - Decode a QUIC variable-length integer
 * @buf: Input buffer containing encoded varint
 * @len: Length of available data in buffer
 * @value: Output parameter for decoded value
 *
 * Decodes a varint from the buffer. The length prefix in the first byte
 * determines how many bytes are consumed.
 *
 * Returns the number of bytes consumed on success, or negative error.
 */
int tquic_varint_decode(const u8 *buf, size_t len, u64 *value)
{
	int varint_len;
	u64 result;

	if (!buf || !value || len == 0)
		return -EINVAL;

	/* Determine the encoded length from the first byte's prefix bits */
	varint_len = tquic_varint_decode_len(buf[0]);

	/* Check if we have enough data */
	if (len < varint_len)
		return -ENODATA;

	switch (varint_len) {
	case TQUIC_VARINT_SIZE_1BYTE:
		/* 1 byte: mask off prefix bits (which are 00) */
		result = buf[0] & TQUIC_VARINT_VALUE_MASK;
		break;

	case TQUIC_VARINT_SIZE_2BYTE:
		/* 2 bytes: read big-endian, mask off prefix */
		result = get_unaligned_be16(buf) & 0x3fff;
		break;

	case TQUIC_VARINT_SIZE_4BYTE:
		/* 4 bytes: read big-endian, mask off prefix */
		result = get_unaligned_be32(buf) & 0x3fffffff;
		break;

	case TQUIC_VARINT_SIZE_8BYTE:
		/* 8 bytes: read big-endian, mask off prefix */
		result = get_unaligned_be64(buf) & 0x3fffffffffffffffULL;
		break;

	default:
		/* Should never happen given tquic_varint_decode_len() */
		return -EINVAL;
	}

	*value = result;
	return varint_len;
}
EXPORT_SYMBOL_GPL(tquic_varint_decode);

/**
 * tquic_varint_read - Read a varint from buffer with bounds checking
 * @buf: Input buffer
 * @buf_len: Total buffer length
 * @offset: Current offset in buffer (updated on success)
 * @value: Output parameter for decoded value
 *
 * This is a convenience wrapper around tquic_varint_decode() that handles
 * offset management and bounds checking for sequential reads.
 *
 * Returns 0 on success, or negative error.
 */
int tquic_varint_read(const u8 *buf, size_t buf_len, size_t *offset, u64 *value)
{
	int ret;
	size_t remaining;

	if (!buf || !offset || !value)
		return -EINVAL;

	if (*offset >= buf_len)
		return -EINVAL;

	remaining = buf_len - *offset;

	ret = tquic_varint_decode(buf + *offset, remaining, value);
	if (ret < 0)
		return ret;

	*offset += ret;
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_varint_read);

/**
 * tquic_varint_write - Write a varint to buffer with bounds checking
 * @buf: Output buffer
 * @buf_len: Total buffer length
 * @offset: Current offset in buffer (updated on success)
 * @value: Value to encode
 *
 * This is a convenience wrapper around tquic_varint_encode() that handles
 * offset management and bounds checking for sequential writes.
 *
 * Returns 0 on success, or negative error.
 */
int tquic_varint_write(u8 *buf, size_t buf_len, size_t *offset, u64 value)
{
	int encoded_size;
	size_t remaining;

	if (!buf || !offset)
		return -EINVAL;

	if (*offset >= buf_len)
		return -EINVAL;

	/* Calculate the size needed for this value */
	encoded_size = tquic_varint_size(value);
	if (encoded_size == 0)
		return -EINVAL; /* Value too large */

	remaining = buf_len - *offset;

	/* Check if we have enough space */
	if (remaining < encoded_size)
		return -ENOSPC;

	/* Encode the value */
	if (tquic_varint_encode(value, buf + *offset, remaining) != encoded_size)
		return -EINVAL;

	*offset += encoded_size;
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_varint_write);

/**
 * tquic_varint_encode_force - Encode with specific length
 * @value: The value to encode
 * @buf: Output buffer
 * @length: Required encoding length (1, 2, 4, or 8)
 *
 * Encodes the value using exactly the specified number of bytes.
 * The value must fit within the specified length's maximum.
 *
 * Returns 0 on success, or negative error.
 */
int tquic_varint_encode_force(u64 value, u8 *buf, int length)
{
	if (!buf)
		return -EINVAL;

	switch (length) {
	case TQUIC_VARINT_SIZE_1BYTE:
		if (value > TQUIC_VARINT_1BYTE_MAX)
			return -EINVAL;
		buf[0] = (u8)value;
		break;

	case TQUIC_VARINT_SIZE_2BYTE:
		if (value > TQUIC_VARINT_2BYTE_MAX)
			return -EINVAL;
		put_unaligned_be16((u16)value | (TQUIC_VARINT_2BYTE_PREFIX << 8),
				   buf);
		break;

	case TQUIC_VARINT_SIZE_4BYTE:
		if (value > TQUIC_VARINT_4BYTE_MAX)
			return -EINVAL;
		put_unaligned_be32((u32)value | (TQUIC_VARINT_4BYTE_PREFIX << 24),
				   buf);
		break;

	case TQUIC_VARINT_SIZE_8BYTE:
		if (value > TQUIC_VARINT_8BYTE_MAX)
			return -EINVAL;
		put_unaligned_be64(value | ((u64)TQUIC_VARINT_8BYTE_PREFIX << 56),
				   buf);
		break;

	default:
		return -EINVAL;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_varint_encode_force);

MODULE_DESCRIPTION("TQUIC Variable-Length Integer Encoding");
MODULE_LICENSE("GPL");
