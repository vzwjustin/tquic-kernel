/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC Variable-Length Integer Encoding
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * This header provides QUIC variable-length integer encoding and decoding
 * utilities as specified in RFC 9000 Section 16.
 *
 * QUIC varints use the 2 most significant bits (MSB) to indicate length:
 *   00 = 1 byte  (6-bit value,  0 to 63)
 *   01 = 2 bytes (14-bit value, 0 to 16383)
 *   10 = 4 bytes (30-bit value, 0 to 1073741823)
 *   11 = 8 bytes (62-bit value, 0 to 4611686018427387903)
 */

#ifndef _TQUIC_VARINT_H
#define _TQUIC_VARINT_H

#include <linux/types.h>
#include <linux/errno.h>
#include <asm/byteorder.h>

/* Varint length prefix bits (2 MSB of first byte) */
#define TQUIC_VARINT_1BYTE_PREFIX	0x00
#define TQUIC_VARINT_2BYTE_PREFIX	0x40
#define TQUIC_VARINT_4BYTE_PREFIX	0x80
#define TQUIC_VARINT_8BYTE_PREFIX	0xc0

/* Mask for extracting the length prefix */
#define TQUIC_VARINT_PREFIX_MASK	0xc0

/* Mask for extracting value from first byte */
#define TQUIC_VARINT_VALUE_MASK		0x3f

/* Maximum values for each encoding length */
#define TQUIC_VARINT_1BYTE_MAX		63ULL
#define TQUIC_VARINT_2BYTE_MAX		16383ULL
#define TQUIC_VARINT_4BYTE_MAX		1073741823ULL
#define TQUIC_VARINT_8BYTE_MAX		4611686018427387903ULL

/* Maximum encodable value */
#define TQUIC_VARINT_MAX		TQUIC_VARINT_8BYTE_MAX

/* Varint encoding sizes */
#define TQUIC_VARINT_SIZE_1BYTE		1
#define TQUIC_VARINT_SIZE_2BYTE		2
#define TQUIC_VARINT_SIZE_4BYTE		4
#define TQUIC_VARINT_SIZE_8BYTE		8

/**
 * tquic_varint_size - Calculate the encoded size for a value
 * @value: The value to be encoded
 *
 * Returns the number of bytes needed to encode the value, or 0 if the
 * value exceeds the maximum encodable value.
 */
static inline int tquic_varint_size(u64 value)
{
	if (value <= TQUIC_VARINT_1BYTE_MAX)
		return TQUIC_VARINT_SIZE_1BYTE;
	if (value <= TQUIC_VARINT_2BYTE_MAX)
		return TQUIC_VARINT_SIZE_2BYTE;
	if (value <= TQUIC_VARINT_4BYTE_MAX)
		return TQUIC_VARINT_SIZE_4BYTE;
	if (value <= TQUIC_VARINT_8BYTE_MAX)
		return TQUIC_VARINT_SIZE_8BYTE;

	return 0; /* Value too large */
}

/**
 * tquic_varint_decode_len - Get decoded length from first byte
 * @first_byte: The first byte of an encoded varint
 *
 * Returns the total length of the encoded varint based on the prefix bits.
 */
static inline int tquic_varint_decode_len(u8 first_byte)
{
	return 1 << ((first_byte & TQUIC_VARINT_PREFIX_MASK) >> 6);
}

/**
 * tquic_varint_encode - Encode an integer to QUIC variable-length format
 * @value: The value to encode
 * @buf: Output buffer (must be at least 8 bytes)
 *
 * Encodes the value into the buffer using the minimum number of bytes.
 * Returns the number of bytes written, or 0 if the value is too large.
 */
int tquic_varint_encode(u64 value, u8 *buf, size_t len);

/**
 * tquic_varint_decode - Decode a QUIC variable-length integer
 * @buf: Input buffer containing encoded varint
 * @len: Length of available data in buffer
 * @value: Output parameter for decoded value
 *
 * Decodes a varint from the buffer into value. The buffer must contain
 * at least as many bytes as indicated by the length prefix in the first byte.
 *
 * Returns the number of bytes consumed on success, or negative error:
 *   -EINVAL: Buffer too short or NULL parameters
 *   -ENODATA: Need more data (buffer shorter than encoded length)
 */
int tquic_varint_decode(const u8 *buf, size_t len, u64 *value);

/**
 * tquic_varint_read - Read a varint from buffer with bounds checking
 * @buf: Input buffer
 * @buf_len: Total buffer length
 * @offset: Current offset in buffer (updated on success)
 * @value: Output parameter for decoded value
 *
 * Reads a varint starting at the given offset, performing bounds checking.
 * On success, the offset is updated to point past the decoded varint.
 *
 * Returns 0 on success, or negative error:
 *   -EINVAL: NULL parameters or offset >= buf_len
 *   -ENODATA: Need more data to complete decode
 */
int tquic_varint_read(const u8 *buf, size_t buf_len, size_t *offset, u64 *value);

/**
 * tquic_varint_write - Write a varint to buffer with bounds checking
 * @buf: Output buffer
 * @buf_len: Total buffer length
 * @offset: Current offset in buffer (updated on success)
 * @value: Value to encode
 *
 * Writes an encoded varint starting at the given offset, performing bounds
 * checking. On success, the offset is updated to point past the written data.
 *
 * Returns 0 on success, or negative error:
 *   -EINVAL: NULL parameters, value too large, or offset >= buf_len
 *   -ENOSPC: Not enough space in buffer
 */
int tquic_varint_write(u8 *buf, size_t buf_len, size_t *offset, u64 value);

/**
 * tquic_varint_encode_force - Encode with specific length (for wire format)
 * @value: The value to encode
 * @buf: Output buffer
 * @length: Required encoding length (1, 2, 4, or 8)
 *
 * Encodes the value using exactly the specified number of bytes.
 * This is useful when a specific wire format length is required.
 *
 * Returns 0 on success, or negative error:
 *   -EINVAL: Invalid length or value doesn't fit in specified length
 */
int tquic_varint_encode_force(u64 value, u8 *buf, int length);

#endif /* _TQUIC_VARINT_H */
