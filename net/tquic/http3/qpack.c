// SPDX-License-Identifier: GPL-2.0-only
/*
 * QPACK Header Compression for HTTP/3 - RFC 9204
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * This file provides:
 * - Main QPACK context management
 * - Integer encoding/decoding (HPACK format)
 * - String encoding/decoding with optional Huffman
 * - Huffman coding implementation (RFC 7541 Appendix B)
 * - Header list management
 * - Sysctl integration
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/sysctl.h>
#include <linux/init.h>
#include <net/tquic.h>

#include "qpack.h"
#include "../tquic_sysctl.h"

/*
 * =============================================================================
 * Sysctl Configuration (via main tquic_sysctl.c)
 * =============================================================================
 */

/**
 * qpack_sysctl_max_table_capacity - Get configured max table capacity
 *
 * Returns: Maximum QPACK dynamic table capacity from sysctl
 */
u64 qpack_sysctl_max_table_capacity(void)
{
	return tquic_sysctl_get_qpack_max_table_capacity();
}
EXPORT_SYMBOL_GPL(qpack_sysctl_max_table_capacity);

/*
 * =============================================================================
 * Huffman Coding - RFC 7541 Appendix B
 * =============================================================================
 *
 * The Huffman code table is copied from HPACK (RFC 7541) and is used
 * unchanged by QPACK. Each symbol (0-255 and EOS) has a variable-length
 * code and bit length.
 */

/* Huffman encoding table: [symbol] = { code, bit_length } */
static const struct {
	u32 code;
	u8 bits;
} huffman_encode_table[257] = {
	/* 0x00 */ { 0x1ff8, 13 },
	/* 0x01 */ { 0x7fffd8, 23 },
	/* 0x02 */ { 0xfffffe2, 28 },
	/* 0x03 */ { 0xfffffe3, 28 },
	/* 0x04 */ { 0xfffffe4, 28 },
	/* 0x05 */ { 0xfffffe5, 28 },
	/* 0x06 */ { 0xfffffe6, 28 },
	/* 0x07 */ { 0xfffffe7, 28 },
	/* 0x08 */ { 0xfffffe8, 28 },
	/* 0x09 */ { 0xffffea, 24 },
	/* 0x0a */ { 0x3ffffffc, 30 },
	/* 0x0b */ { 0xfffffe9, 28 },
	/* 0x0c */ { 0xfffffea, 28 },
	/* 0x0d */ { 0x3ffffffd, 30 },
	/* 0x0e */ { 0xfffffeb, 28 },
	/* 0x0f */ { 0xfffffec, 28 },
	/* 0x10 */ { 0xfffffed, 28 },
	/* 0x11 */ { 0xfffffee, 28 },
	/* 0x12 */ { 0xfffffef, 28 },
	/* 0x13 */ { 0xffffff0, 28 },
	/* 0x14 */ { 0xffffff1, 28 },
	/* 0x15 */ { 0xffffff2, 28 },
	/* 0x16 */ { 0x3ffffffe, 30 },
	/* 0x17 */ { 0xffffff3, 28 },
	/* 0x18 */ { 0xffffff4, 28 },
	/* 0x19 */ { 0xffffff5, 28 },
	/* 0x1a */ { 0xffffff6, 28 },
	/* 0x1b */ { 0xffffff7, 28 },
	/* 0x1c */ { 0xffffff8, 28 },
	/* 0x1d */ { 0xffffff9, 28 },
	/* 0x1e */ { 0xffffffa, 28 },
	/* 0x1f */ { 0xffffffb, 28 },
	/* ' '  */ { 0x14, 6 },
	/* '!'  */ { 0x3f8, 10 },
	/* '"'  */ { 0x3f9, 10 },
	/* '#'  */ { 0xffa, 12 },
	/* '$'  */ { 0x1ff9, 13 },
	/* '%'  */ { 0x15, 6 },
	/* '&'  */ { 0xf8, 8 },
	/* '\'' */ { 0x7fa, 11 },
	/* '('  */ { 0x3fa, 10 },
	/* ')'  */ { 0x3fb, 10 },
	/* '*'  */ { 0xf9, 8 },
	/* '+'  */ { 0x7fb, 11 },
	/* ','  */ { 0xfa, 8 },
	/* '-'  */ { 0x16, 6 },
	/* '.'  */ { 0x17, 6 },
	/* '/'  */ { 0x18, 6 },
	/* '0'  */ { 0x0, 5 },
	/* '1'  */ { 0x1, 5 },
	/* '2'  */ { 0x2, 5 },
	/* '3'  */ { 0x19, 6 },
	/* '4'  */ { 0x1a, 6 },
	/* '5'  */ { 0x1b, 6 },
	/* '6'  */ { 0x1c, 6 },
	/* '7'  */ { 0x1d, 6 },
	/* '8'  */ { 0x1e, 6 },
	/* '9'  */ { 0x1f, 6 },
	/* ':'  */ { 0x5c, 7 },
	/* ';'  */ { 0xfb, 8 },
	/* '<'  */ { 0x7ffc, 15 },
	/* '='  */ { 0x20, 6 },
	/* '>'  */ { 0xffb, 12 },
	/* '?'  */ { 0x3fc, 10 },
	/* '@'  */ { 0x1ffa, 13 },
	/* 'A'  */ { 0x21, 6 },
	/* 'B'  */ { 0x5d, 7 },
	/* 'C'  */ { 0x5e, 7 },
	/* 'D'  */ { 0x5f, 7 },
	/* 'E'  */ { 0x60, 7 },
	/* 'F'  */ { 0x61, 7 },
	/* 'G'  */ { 0x62, 7 },
	/* 'H'  */ { 0x63, 7 },
	/* 'I'  */ { 0x64, 7 },
	/* 'J'  */ { 0x65, 7 },
	/* 'K'  */ { 0x66, 7 },
	/* 'L'  */ { 0x67, 7 },
	/* 'M'  */ { 0x68, 7 },
	/* 'N'  */ { 0x69, 7 },
	/* 'O'  */ { 0x6a, 7 },
	/* 'P'  */ { 0x6b, 7 },
	/* 'Q'  */ { 0x6c, 7 },
	/* 'R'  */ { 0x6d, 7 },
	/* 'S'  */ { 0x6e, 7 },
	/* 'T'  */ { 0x6f, 7 },
	/* 'U'  */ { 0x70, 7 },
	/* 'V'  */ { 0x71, 7 },
	/* 'W'  */ { 0x72, 7 },
	/* 'X'  */ { 0xfc, 8 },
	/* 'Y'  */ { 0x73, 7 },
	/* 'Z'  */ { 0xfd, 8 },
	/* '['  */ { 0x1ffb, 13 },
	/* '\\' */ { 0x7fff0, 19 },
	/* ']'  */ { 0x1ffc, 13 },
	/* '^'  */ { 0x3ffc, 14 },
	/* '_'  */ { 0x22, 6 },
	/* '`'  */ { 0x7ffd, 15 },
	/* 'a'  */ { 0x3, 5 },
	/* 'b'  */ { 0x23, 6 },
	/* 'c'  */ { 0x4, 5 },
	/* 'd'  */ { 0x24, 6 },
	/* 'e'  */ { 0x5, 5 },
	/* 'f'  */ { 0x25, 6 },
	/* 'g'  */ { 0x26, 6 },
	/* 'h'  */ { 0x27, 6 },
	/* 'i'  */ { 0x6, 5 },
	/* 'j'  */ { 0x74, 7 },
	/* 'k'  */ { 0x75, 7 },
	/* 'l'  */ { 0x28, 6 },
	/* 'm'  */ { 0x29, 6 },
	/* 'n'  */ { 0x2a, 6 },
	/* 'o'  */ { 0x7, 5 },
	/* 'p'  */ { 0x2b, 6 },
	/* 'q'  */ { 0x76, 7 },
	/* 'r'  */ { 0x2c, 6 },
	/* 's'  */ { 0x8, 5 },
	/* 't'  */ { 0x9, 5 },
	/* 'u'  */ { 0x2d, 6 },
	/* 'v'  */ { 0x77, 7 },
	/* 'w'  */ { 0x78, 7 },
	/* 'x'  */ { 0x79, 7 },
	/* 'y'  */ { 0x7a, 7 },
	/* 'z'  */ { 0x7b, 7 },
	/* '{'  */ { 0x7ffe, 15 },
	/* '|'  */ { 0x7fc, 11 },
	/* '}'  */ { 0x3ffd, 14 },
	/* '~'  */ { 0x1ffd, 13 },
	/* 0x7f */ { 0xffffffc, 28 },
	/* 0x80 */ { 0xfffe6, 20 },
	/* 0x81 */ { 0x3fffd2, 22 },
	/* 0x82 */ { 0xfffe7, 20 },
	/* 0x83 */ { 0xfffe8, 20 },
	/* 0x84 */ { 0x3fffd3, 22 },
	/* 0x85 */ { 0x3fffd4, 22 },
	/* 0x86 */ { 0x3fffd5, 22 },
	/* 0x87 */ { 0x7fffd9, 23 },
	/* 0x88 */ { 0x3fffd6, 22 },
	/* 0x89 */ { 0x7fffda, 23 },
	/* 0x8a */ { 0x7fffdb, 23 },
	/* 0x8b */ { 0x7fffdc, 23 },
	/* 0x8c */ { 0x7fffdd, 23 },
	/* 0x8d */ { 0x7fffde, 23 },
	/* 0x8e */ { 0xffffeb, 24 },
	/* 0x8f */ { 0x7fffdf, 23 },
	/* 0x90 */ { 0xffffec, 24 },
	/* 0x91 */ { 0xffffed, 24 },
	/* 0x92 */ { 0x3fffd7, 22 },
	/* 0x93 */ { 0x7fffe0, 23 },
	/* 0x94 */ { 0xffffee, 24 },
	/* 0x95 */ { 0x7fffe1, 23 },
	/* 0x96 */ { 0x7fffe2, 23 },
	/* 0x97 */ { 0x7fffe3, 23 },
	/* 0x98 */ { 0x7fffe4, 23 },
	/* 0x99 */ { 0x1fffdc, 21 },
	/* 0x9a */ { 0x3fffd8, 22 },
	/* 0x9b */ { 0x7fffe5, 23 },
	/* 0x9c */ { 0x3fffd9, 22 },
	/* 0x9d */ { 0x7fffe6, 23 },
	/* 0x9e */ { 0x7fffe7, 23 },
	/* 0x9f */ { 0xffffef, 24 },
	/* 0xa0 */ { 0x3fffda, 22 },
	/* 0xa1 */ { 0x1fffdd, 21 },
	/* 0xa2 */ { 0xfffe9, 20 },
	/* 0xa3 */ { 0x3fffdb, 22 },
	/* 0xa4 */ { 0x3fffdc, 22 },
	/* 0xa5 */ { 0x7fffe8, 23 },
	/* 0xa6 */ { 0x7fffe9, 23 },
	/* 0xa7 */ { 0x1fffde, 21 },
	/* 0xa8 */ { 0x7fffea, 23 },
	/* 0xa9 */ { 0x3fffdd, 22 },
	/* 0xaa */ { 0x3fffde, 22 },
	/* 0xab */ { 0xfffff0, 24 },
	/* 0xac */ { 0x1fffdf, 21 },
	/* 0xad */ { 0x3fffdf, 22 },
	/* 0xae */ { 0x7fffeb, 23 },
	/* 0xaf */ { 0x7fffec, 23 },
	/* 0xb0 */ { 0x1fffe0, 21 },
	/* 0xb1 */ { 0x1fffe1, 21 },
	/* 0xb2 */ { 0x3fffe0, 22 },
	/* 0xb3 */ { 0x1fffe2, 21 },
	/* 0xb4 */ { 0x7fffed, 23 },
	/* 0xb5 */ { 0x3fffe1, 22 },
	/* 0xb6 */ { 0x7fffee, 23 },
	/* 0xb7 */ { 0x7fffef, 23 },
	/* 0xb8 */ { 0xfffea, 20 },
	/* 0xb9 */ { 0x3fffe2, 22 },
	/* 0xba */ { 0x3fffe3, 22 },
	/* 0xbb */ { 0x3fffe4, 22 },
	/* 0xbc */ { 0x7ffff0, 23 },
	/* 0xbd */ { 0x3fffe5, 22 },
	/* 0xbe */ { 0x3fffe6, 22 },
	/* 0xbf */ { 0x7ffff1, 23 },
	/* 0xc0 */ { 0x3ffffe0, 26 },
	/* 0xc1 */ { 0x3ffffe1, 26 },
	/* 0xc2 */ { 0xfffeb, 20 },
	/* 0xc3 */ { 0x7fff1, 19 },
	/* 0xc4 */ { 0x3fffe7, 22 },
	/* 0xc5 */ { 0x7ffff2, 23 },
	/* 0xc6 */ { 0x3fffe8, 22 },
	/* 0xc7 */ { 0x1ffffec, 25 },
	/* 0xc8 */ { 0x3ffffe2, 26 },
	/* 0xc9 */ { 0x3ffffe3, 26 },
	/* 0xca */ { 0x3ffffe4, 26 },
	/* 0xcb */ { 0x7ffffde, 27 },
	/* 0xcc */ { 0x7ffffdf, 27 },
	/* 0xcd */ { 0x3ffffe5, 26 },
	/* 0xce */ { 0xfffff1, 24 },
	/* 0xcf */ { 0x1ffffed, 25 },
	/* 0xd0 */ { 0x7fff2, 19 },
	/* 0xd1 */ { 0x1fffe3, 21 },
	/* 0xd2 */ { 0x3ffffe6, 26 },
	/* 0xd3 */ { 0x7ffffe0, 27 },
	/* 0xd4 */ { 0x7ffffe1, 27 },
	/* 0xd5 */ { 0x3ffffe7, 26 },
	/* 0xd6 */ { 0x7ffffe2, 27 },
	/* 0xd7 */ { 0xfffff2, 24 },
	/* 0xd8 */ { 0x1fffe4, 21 },
	/* 0xd9 */ { 0x1fffe5, 21 },
	/* 0xda */ { 0x3ffffe8, 26 },
	/* 0xdb */ { 0x3ffffe9, 26 },
	/* 0xdc */ { 0xffffffd, 28 },
	/* 0xdd */ { 0x7ffffe3, 27 },
	/* 0xde */ { 0x7ffffe4, 27 },
	/* 0xdf */ { 0x7ffffe5, 27 },
	/* 0xe0 */ { 0xfffec, 20 },
	/* 0xe1 */ { 0xfffff3, 24 },
	/* 0xe2 */ { 0xfffed, 20 },
	/* 0xe3 */ { 0x1fffe6, 21 },
	/* 0xe4 */ { 0x3fffe9, 22 },
	/* 0xe5 */ { 0x1fffe7, 21 },
	/* 0xe6 */ { 0x1fffe8, 21 },
	/* 0xe7 */ { 0x7ffff3, 23 },
	/* 0xe8 */ { 0x3fffea, 22 },
	/* 0xe9 */ { 0x3fffeb, 22 },
	/* 0xea */ { 0x1ffffee, 25 },
	/* 0xeb */ { 0x1ffffef, 25 },
	/* 0xec */ { 0xfffff4, 24 },
	/* 0xed */ { 0xfffff5, 24 },
	/* 0xee */ { 0x3ffffea, 26 },
	/* 0xef */ { 0x7ffff4, 23 },
	/* 0xf0 */ { 0x3ffffeb, 26 },
	/* 0xf1 */ { 0x7ffffe6, 27 },
	/* 0xf2 */ { 0x3ffffec, 26 },
	/* 0xf3 */ { 0x3ffffed, 26 },
	/* 0xf4 */ { 0x7ffffe7, 27 },
	/* 0xf5 */ { 0x7ffffe8, 27 },
	/* 0xf6 */ { 0x7ffffe9, 27 },
	/* 0xf7 */ { 0x7ffffea, 27 },
	/* 0xf8 */ { 0x7ffffeb, 27 },
	/* 0xf9 */ { 0xffffffe, 28 },
	/* 0xfa */ { 0x7ffffec, 27 },
	/* 0xfb */ { 0x7ffffed, 27 },
	/* 0xfc */ { 0x7ffffee, 27 },
	/* 0xfd */ { 0x7ffffef, 27 },
	/* 0xfe */ { 0x7fffff0, 27 },
	/* 0xff */ { 0x3ffffee, 26 },
	/* EOS  */ { 0x3fffffff, 30 },
};

/*
 * Huffman decode table - state machine for decoding
 * This is a simplified decoder that processes 4 bits at a time.
 */

/* State machine entry: { next_state, symbol, flags } */
/* flags: 0x80 = complete symbol, 0x40 = accepted (may emit), 0x00 = incomplete */

/*
 * For simplicity, we use a byte-at-a-time decoder with lookup.
 * A production implementation would use a more efficient state machine.
 */

/**
 * qpack_huffman_encode - Encode data using Huffman coding
 * @src: Source data
 * @src_len: Source length
 * @dst: Destination buffer
 * @dst_len: Destination buffer size
 * @encoded_len: Output - encoded length
 *
 * Returns: 0 on success, negative error code on failure
 */
int qpack_huffman_encode(const u8 *src, size_t src_len,
			 u8 *dst, size_t dst_len, size_t *encoded_len)
{
	size_t dst_offset = 0;
	u32 bit_buffer = 0;
	u8 bit_count = 0;
	size_t i;

	if (!src || !dst || !encoded_len)
		return -EINVAL;

	for (i = 0; i < src_len; i++) {
		u8 sym = src[i];
		u32 code = huffman_encode_table[sym].code;
		u8 bits = huffman_encode_table[sym].bits;

		/* Add code to bit buffer */
		bit_buffer = (bit_buffer << bits) | code;
		bit_count += bits;

		/* Write complete bytes */
		while (bit_count >= 8) {
			if (dst_offset >= dst_len)
				return -ENOSPC;
			dst[dst_offset++] = (bit_buffer >> (bit_count - 8)) & 0xFF;
			bit_count -= 8;
		}
	}

	/* Pad with EOS prefix if needed */
	if (bit_count > 0) {
		if (dst_offset >= dst_len)
			return -ENOSPC;
		/* Pad remaining bits with 1s (EOS prefix) */
		dst[dst_offset++] = (bit_buffer << (8 - bit_count)) | (0xFF >> bit_count);
	}

	*encoded_len = dst_offset;
	return 0;
}
EXPORT_SYMBOL_GPL(qpack_huffman_encode);

/**
 * qpack_huffman_decode - Decode Huffman-encoded data
 * @src: Huffman-encoded source
 * @src_len: Source length
 * @dst: Destination buffer
 * @dst_len: Destination buffer size
 * @decoded_len: Output - decoded length
 *
 * Returns: 0 on success, negative error code on failure
 *
 * This is a simple bit-by-bit decoder. Production implementations
 * would use a state machine with multi-bit processing.
 */
int qpack_huffman_decode(const u8 *src, size_t src_len,
			 u8 *dst, size_t dst_len, size_t *decoded_len)
{
	size_t dst_offset = 0;
	u32 bit_buffer = 0;
	u8 bit_count = 0;
	size_t src_offset = 0;
	int sym;
	/*
	 * Bound total iterations to prevent O(n*256) algorithmic
	 * complexity attacks.  Huffman coding expands by at most 7:5
	 * for HPACK/QPACK, so src_len * 2 is a generous bound.
	 */
	size_t max_output = min(dst_len, src_len * 2 + 1);

	if (!src || !dst || !decoded_len)
		return -EINVAL;

	while ((src_offset < src_len || bit_count > 0) &&
	       dst_offset < max_output) {
		/* Refill bit buffer */
		while (bit_count < 24 && src_offset < src_len) {
			bit_buffer = (bit_buffer << 8) | src[src_offset++];
			bit_count += 8;
		}

		if (bit_count == 0)
			break;

		/* Try to match a symbol - check from longest to shortest */
		sym = -1;
		for (int s = 0; s < 256; s++) {
			u8 bits = huffman_encode_table[s].bits;
			if (bits <= bit_count) {
				u32 mask = (1 << bits) - 1;
				u32 code = (bit_buffer >> (bit_count - bits)) & mask;
				if (code == huffman_encode_table[s].code) {
					/* Found match - prefer longer codes */
					if (sym < 0 || huffman_encode_table[s].bits >
						       huffman_encode_table[sym].bits) {
						sym = s;
					}
				}
			}
		}

		if (sym >= 0) {
			if (dst_offset >= dst_len)
				return -ENOSPC;
			dst[dst_offset++] = sym;
			bit_count -= huffman_encode_table[sym].bits;
		} else {
			/* Check for EOS padding */
			if (bit_count < 8) {
				u32 mask = (1 << bit_count) - 1;
				if ((bit_buffer & mask) == mask) {
					/* Valid EOS padding */
					break;
				}
			}
			return -EINVAL; /* Invalid encoding */
		}
	}

	*decoded_len = dst_offset;
	return 0;
}
EXPORT_SYMBOL_GPL(qpack_huffman_decode);

/**
 * qpack_huffman_encoded_len - Calculate Huffman-encoded length
 * @src: Source data
 * @src_len: Source length
 *
 * Returns: Encoded length in bytes
 */
size_t qpack_huffman_encoded_len(const u8 *src, size_t src_len)
{
	size_t total_bits = 0;
	size_t i;

	if (!src)
		return 0;

	for (i = 0; i < src_len; i++)
		total_bits += huffman_encode_table[src[i]].bits;

	/* Round up to bytes */
	return (total_bits + 7) / 8;
}
EXPORT_SYMBOL_GPL(qpack_huffman_encoded_len);

/*
 * =============================================================================
 * Integer Encoding/Decoding (HPACK format)
 * =============================================================================
 */

/**
 * qpack_encode_integer - Encode integer with prefix
 * @value: Value to encode
 * @prefix_bits: Number of bits available in first byte (1-8)
 * @prefix_value: Prefix bits to OR into first byte
 * @buf: Output buffer
 * @buf_len: Buffer size
 * @encoded_len: Output - encoded length
 *
 * Returns: 0 on success, negative error code on failure
 */
int qpack_encode_integer(u64 value, u8 prefix_bits, u8 prefix_value,
			 u8 *buf, size_t buf_len, size_t *encoded_len)
{
	u8 max_prefix;
	size_t offset = 0;

	if (!buf || !encoded_len || prefix_bits == 0 || prefix_bits > 8)
		return -EINVAL;

	if (buf_len == 0)
		return -ENOSPC;

	max_prefix = (1 << prefix_bits) - 1;

	if (value < max_prefix) {
		/* Value fits in prefix */
		buf[0] = prefix_value | (u8)value;
		*encoded_len = 1;
		return 0;
	}

	/* Value doesn't fit - use continuation bytes */
	buf[offset++] = prefix_value | max_prefix;
	value -= max_prefix;

	while (value >= 128) {
		if (offset >= buf_len)
			return -ENOSPC;
		buf[offset++] = (u8)(value & 0x7F) | 0x80;
		value >>= 7;
	}

	if (offset >= buf_len)
		return -ENOSPC;
	buf[offset++] = (u8)value;

	*encoded_len = offset;
	return 0;
}
EXPORT_SYMBOL_GPL(qpack_encode_integer);

/**
 * qpack_decode_integer - Decode integer with prefix
 * @buf: Input buffer
 * @buf_len: Buffer size
 * @prefix_bits: Number of bits in first byte (1-8)
 * @value: Output - decoded value
 * @consumed: Output - bytes consumed
 *
 * Returns: 0 on success, negative error code on failure
 */
int qpack_decode_integer(const u8 *buf, size_t buf_len, u8 prefix_bits,
			 u64 *value, size_t *consumed)
{
	u8 max_prefix;
	size_t offset = 0;
	u64 result;
	u8 shift;

	if (!buf || !value || !consumed || prefix_bits == 0 || prefix_bits > 8)
		return -EINVAL;

	if (buf_len == 0)
		return -ENODATA;

	max_prefix = (1 << prefix_bits) - 1;
	result = buf[offset++] & max_prefix;

	if (result < max_prefix) {
		/* Value fits in prefix */
		*value = result;
		*consumed = 1;
		return 0;
	}

	/* Decode continuation bytes */
	shift = 0;
	do {
		if (offset >= buf_len)
			return -ENODATA;

		/* Overflow check - must be before shift to prevent UB */
		if (shift > 62)
			return -EOVERFLOW;

		result += (u64)(buf[offset] & 0x7F) << shift;
		shift += 7;

	} while (buf[offset++] & 0x80);

	*value = result;
	*consumed = offset;
	return 0;
}
EXPORT_SYMBOL_GPL(qpack_decode_integer);

/*
 * =============================================================================
 * String Encoding/Decoding
 * =============================================================================
 */

/**
 * qpack_encode_string - Encode string with optional Huffman
 * @str: String to encode
 * @str_len: String length
 * @huffman: Use Huffman coding
 * @buf: Output buffer
 * @buf_len: Buffer size
 * @encoded_len: Output - encoded length
 *
 * Returns: 0 on success, negative error code on failure
 */
int qpack_encode_string(const char *str, u16 str_len, bool huffman,
			u8 *buf, size_t buf_len, size_t *encoded_len)
{
	size_t len_encoded;
	size_t data_len;
	int ret;

	if (!buf || !encoded_len)
		return -EINVAL;

	if (huffman) {
		/* Calculate Huffman-encoded length */
		data_len = qpack_huffman_encoded_len((const u8 *)str, str_len);

		/* Encode length with H=1 prefix */
		ret = qpack_encode_integer(data_len, 7, 0x80, buf, buf_len, &len_encoded);
		if (ret)
			return ret;

		/* Encode data */
		if (len_encoded + data_len > buf_len)
			return -ENOSPC;

		ret = qpack_huffman_encode((const u8 *)str, str_len,
					   buf + len_encoded, buf_len - len_encoded,
					   &data_len);
		if (ret)
			return ret;

		*encoded_len = len_encoded + data_len;
	} else {
		/* Encode length with H=0 prefix */
		ret = qpack_encode_integer(str_len, 7, 0x00, buf, buf_len, &len_encoded);
		if (ret)
			return ret;

		/* Copy data */
		if (len_encoded + str_len > buf_len)
			return -ENOSPC;

		if (str_len > 0)
			memcpy(buf + len_encoded, str, str_len);

		*encoded_len = len_encoded + str_len;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(qpack_encode_string);

/**
 * qpack_decode_string - Decode string
 * @buf: Input buffer
 * @buf_len: Buffer size
 * @str: Output string buffer
 * @str_max_len: Maximum string length
 * @str_len: Output - actual string length
 * @consumed: Output - bytes consumed
 *
 * Returns: 0 on success, negative error code on failure
 */
int qpack_decode_string(const u8 *buf, size_t buf_len,
			char *str, size_t str_max_len,
			size_t *str_len, size_t *consumed)
{
	bool huffman;
	u64 len;
	size_t len_consumed;
	int ret;

	if (!buf || !str || !str_len || !consumed)
		return -EINVAL;

	if (buf_len == 0)
		return -ENODATA;

	/* Check Huffman flag */
	huffman = !!(buf[0] & 0x80);

	/* Decode length */
	ret = qpack_decode_integer(buf, buf_len, 7, &len, &len_consumed);
	if (ret)
		return ret;

	if (len_consumed + len > buf_len)
		return -ENODATA;

	if (huffman) {
		/* Decode Huffman data */
		ret = qpack_huffman_decode(buf + len_consumed, len,
					   (u8 *)str, str_max_len, str_len);
		if (ret)
			return ret;
	} else {
		/* Copy literal data */
		if (len > str_max_len)
			return -ENOSPC;
		memcpy(str, buf + len_consumed, len);
		*str_len = len;
	}

	*consumed = len_consumed + len;
	return 0;
}
EXPORT_SYMBOL_GPL(qpack_decode_string);

/*
 * =============================================================================
 * Header List Management
 * =============================================================================
 */

/**
 * qpack_header_list_init - Initialize header list
 * @list: List to initialize
 */
void qpack_header_list_init(struct qpack_header_list *list)
{
	if (!list)
		return;

	INIT_LIST_HEAD(&list->headers);
	list->count = 0;
	list->total_size = 0;
}
EXPORT_SYMBOL_GPL(qpack_header_list_init);

/**
 * qpack_header_list_add - Add header to list
 * @list: Header list
 * @name: Header name
 * @name_len: Name length
 * @value: Header value
 * @value_len: Value length
 * @never_index: Never index flag
 *
 * Returns: 0 on success, negative error code on failure
 */
/*
 * Safety limits for header lists to prevent memory exhaustion.
 * An attacker could send header blocks with thousands of headers,
 * each triggering kernel memory allocations.
 */
#define QPACK_MAX_HEADER_COUNT	256
#define QPACK_MAX_HEADER_LIST_SIZE	(64 * 1024)	/* 64 KB */

int qpack_header_list_add(struct qpack_header_list *list,
			  const char *name, u16 name_len,
			  const char *value, u16 value_len,
			  bool never_index)
{
	struct qpack_header_field *hdr;
	u64 entry_size;

	if (!list || !name)
		return -EINVAL;

	/*
	 * Enforce header count and total size limits to prevent
	 * memory exhaustion from malicious header blocks.
	 */
	if (list->count >= QPACK_MAX_HEADER_COUNT)
		return -E2BIG;

	entry_size = (u64)name_len + value_len + 32;
	if (list->total_size + entry_size > QPACK_MAX_HEADER_LIST_SIZE)
		return -E2BIG;

	hdr = kzalloc(sizeof(*hdr), GFP_KERNEL);
	if (!hdr)
		return -ENOMEM;

	hdr->name = kmalloc(name_len + 1, GFP_KERNEL);
	if (!hdr->name) {
		kfree(hdr);
		return -ENOMEM;
	}
	memcpy(hdr->name, name, name_len);
	hdr->name[name_len] = '\0';
	hdr->name_len = name_len;

	hdr->value = kmalloc(value_len + 1, GFP_KERNEL);
	if (!hdr->value) {
		kfree(hdr->name);
		kfree(hdr);
		return -ENOMEM;
	}
	if (value_len > 0)
		memcpy(hdr->value, value, value_len);
	hdr->value[value_len] = '\0';
	hdr->value_len = value_len;

	hdr->never_index = never_index;
	INIT_LIST_HEAD(&hdr->list);

	list_add_tail(&hdr->list, &list->headers);
	list->count++;
	list->total_size += name_len + value_len + 32;

	return 0;
}
EXPORT_SYMBOL_GPL(qpack_header_list_add);

/**
 * qpack_header_list_destroy - Free all headers in list
 * @list: Header list
 */
void qpack_header_list_destroy(struct qpack_header_list *list)
{
	struct qpack_header_field *hdr, *tmp;

	if (!list)
		return;

	list_for_each_entry_safe(hdr, tmp, &list->headers, list) {
		list_del_init(&hdr->list);
		kfree(hdr->name);
		kfree(hdr->value);
		kfree(hdr);
	}

	list->count = 0;
	list->total_size = 0;
}
EXPORT_SYMBOL_GPL(qpack_header_list_destroy);

/**
 * qpack_header_list_find - Find header by name
 * @list: Header list
 * @name: Header name to find
 * @name_len: Name length
 *
 * Returns: First matching header or NULL
 */
struct qpack_header_field *qpack_header_list_find(struct qpack_header_list *list,
						  const char *name, u16 name_len)
{
	struct qpack_header_field *hdr;

	if (!list || !name)
		return NULL;

	list_for_each_entry(hdr, &list->headers, list) {
		if (hdr->name_len == name_len &&
		    memcmp(hdr->name, name, name_len) == 0)
			return hdr;
	}

	return NULL;
}
EXPORT_SYMBOL_GPL(qpack_header_list_find);

/*
 * =============================================================================
 * Main QPACK Context API
 * =============================================================================
 */

/**
 * qpack_context_create - Create QPACK context for connection
 * @conn: Parent connection
 * @max_table_capacity: Maximum dynamic table capacity
 * @max_blocked_streams: Maximum blocked streams
 *
 * Returns: QPACK context or NULL on failure
 */
struct qpack_context *qpack_context_create(struct tquic_connection *conn,
					   u64 max_table_capacity,
					   u32 max_blocked_streams)
{
	struct qpack_context *ctx;
	int ret;

	if (!conn)
		return NULL;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return NULL;

	ctx->conn = conn;

	ret = qpack_encoder_init(&ctx->encoder, conn, max_table_capacity,
				 max_blocked_streams);
	if (ret) {
		kfree(ctx);
		return NULL;
	}

	ret = qpack_decoder_init(&ctx->decoder, conn, max_table_capacity,
				 max_blocked_streams);
	if (ret) {
		qpack_encoder_destroy(&ctx->encoder);
		kfree(ctx);
		return NULL;
	}

	return ctx;
}
EXPORT_SYMBOL_GPL(qpack_context_create);

/**
 * qpack_context_destroy - Destroy QPACK context
 * @ctx: Context to destroy
 */
void qpack_context_destroy(struct qpack_context *ctx)
{
	if (!ctx)
		return;

	qpack_encoder_destroy(&ctx->encoder);
	qpack_decoder_destroy(&ctx->decoder);
	kfree(ctx);
}
EXPORT_SYMBOL_GPL(qpack_context_destroy);

/**
 * qpack_context_set_streams - Set encoder/decoder streams
 * @ctx: QPACK context
 * @encoder_stream: Unidirectional encoder stream
 * @decoder_stream: Unidirectional decoder stream
 *
 * Returns: 0 on success, negative error code on failure
 */
int qpack_context_set_streams(struct qpack_context *ctx,
			      struct tquic_stream *encoder_stream,
			      struct tquic_stream *decoder_stream)
{
	if (!ctx)
		return -EINVAL;

	qpack_encoder_set_stream(&ctx->encoder, encoder_stream);
	qpack_decoder_set_stream(&ctx->decoder, decoder_stream);

	return 0;
}
EXPORT_SYMBOL_GPL(qpack_context_set_streams);

/**
 * qpack_process_encoder_stream - Process incoming encoder stream data
 * @ctx: QPACK context
 * @data: Incoming data
 * @len: Data length
 *
 * Returns: 0 on success, negative error code on failure
 */
int qpack_process_encoder_stream(struct qpack_context *ctx,
				 const u8 *data, size_t len)
{
	if (!ctx)
		return -EINVAL;

	return qpack_decoder_process_encoder_stream(&ctx->decoder, data, len);
}
EXPORT_SYMBOL_GPL(qpack_process_encoder_stream);

/**
 * qpack_process_decoder_stream - Process incoming decoder stream data
 * @ctx: QPACK context
 * @data: Incoming data
 * @len: Data length
 *
 * Returns: 0 on success, negative error code on failure
 */
int qpack_process_decoder_stream(struct qpack_context *ctx,
				 const u8 *data, size_t len)
{
	if (!ctx)
		return -EINVAL;

	return qpack_encoder_process_decoder_stream(&ctx->encoder, data, len);
}
EXPORT_SYMBOL_GPL(qpack_process_decoder_stream);

/*
 * =============================================================================
 * Module Init/Exit
 * =============================================================================
 */

/**
 * qpack_init - Initialize QPACK subsystem
 *
 * Returns: 0 on success, negative error code on failure
 *
 * Note: QPACK sysctl is registered via tquic_sysctl.c as
 * net.tquic.qpack_max_table_capacity
 */
int __init qpack_init(void)
{
	pr_info("qpack: QPACK header compression initialized (RFC 9204)\n");
	return 0;
}

/**
 * qpack_exit - Cleanup QPACK subsystem
 */
void __exit qpack_exit(void)
{
	pr_info("qpack: QPACK header compression unloaded\n");
}

MODULE_DESCRIPTION("QPACK Header Compression for HTTP/3 (RFC 9204)");
MODULE_AUTHOR("Linux Foundation");
MODULE_LICENSE("GPL");
