// SPDX-License-Identifier: GPL-2.0
/*
 * KUnit tests for TQUIC variable-length integer encoding/decoding
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * QUIC uses a variable-length integer encoding (RFC 9000 Section 16):
 * - 1 byte:  0xxxxxxx (0-63)
 * - 2 bytes: 01xxxxxx xxxxxxxx (0-16383)
 * - 4 bytes: 10xxxxxx xxxxxxxx xxxxxxxx xxxxxxxx (0-1073741823)
 * - 8 bytes: 11xxxxxx ... (0-4611686018427387903)
 */

#include <kunit/test.h>
#include <linux/kernel.h>
#include <linux/types.h>

/* Varint encoding prefix masks */
#define TQUIC_VARINT_1BYTE_PREFIX	0x00
#define TQUIC_VARINT_2BYTE_PREFIX	0x40
#define TQUIC_VARINT_4BYTE_PREFIX	0x80
#define TQUIC_VARINT_8BYTE_PREFIX	0xc0
#define TQUIC_VARINT_PREFIX_MASK	0xc0

/* Maximum values for each encoding length */
#define TQUIC_VARINT_1BYTE_MAX		63ULL
#define TQUIC_VARINT_2BYTE_MAX		16383ULL
#define TQUIC_VARINT_4BYTE_MAX		1073741823ULL
#define TQUIC_VARINT_8BYTE_MAX		4611686018427387903ULL

/**
 * tquic_varint_decode - Decode a QUIC variable-length integer
 * @data: Pointer to encoded data
 * @len: Available data length
 * @value: Output value
 *
 * Returns: Number of bytes consumed, or negative error
 */
static int tquic_varint_decode(const u8 *data, size_t len, u64 *value)
{
	u8 prefix;
	int bytes_needed;

	if (len < 1)
		return -EINVAL;

	prefix = data[0] & TQUIC_VARINT_PREFIX_MASK;

	switch (prefix) {
	case TQUIC_VARINT_1BYTE_PREFIX:
		bytes_needed = 1;
		break;
	case TQUIC_VARINT_2BYTE_PREFIX:
		bytes_needed = 2;
		break;
	case TQUIC_VARINT_4BYTE_PREFIX:
		bytes_needed = 4;
		break;
	case TQUIC_VARINT_8BYTE_PREFIX:
		bytes_needed = 8;
		break;
	default:
		return -EINVAL;
	}

	if (len < bytes_needed)
		return -EINVAL;

	switch (bytes_needed) {
	case 1:
		*value = data[0] & 0x3f;
		break;
	case 2:
		*value = ((u64)(data[0] & 0x3f) << 8) | data[1];
		break;
	case 4:
		*value = ((u64)(data[0] & 0x3f) << 24) |
			 ((u64)data[1] << 16) |
			 ((u64)data[2] << 8) |
			 data[3];
		break;
	case 8:
		*value = ((u64)(data[0] & 0x3f) << 56) |
			 ((u64)data[1] << 48) |
			 ((u64)data[2] << 40) |
			 ((u64)data[3] << 32) |
			 ((u64)data[4] << 24) |
			 ((u64)data[5] << 16) |
			 ((u64)data[6] << 8) |
			 data[7];
		break;
	}

	return bytes_needed;
}

/**
 * tquic_varint_encode - Encode a value as QUIC variable-length integer
 * @value: Value to encode
 * @data: Output buffer
 * @len: Buffer length
 *
 * Returns: Number of bytes written, or negative error
 */
static int tquic_varint_encode(u64 value, u8 *data, size_t len)
{
	if (value <= TQUIC_VARINT_1BYTE_MAX) {
		if (len < 1)
			return -EINVAL;
		data[0] = (u8)value;
		return 1;
	} else if (value <= TQUIC_VARINT_2BYTE_MAX) {
		if (len < 2)
			return -EINVAL;
		data[0] = TQUIC_VARINT_2BYTE_PREFIX | (u8)(value >> 8);
		data[1] = (u8)value;
		return 2;
	} else if (value <= TQUIC_VARINT_4BYTE_MAX) {
		if (len < 4)
			return -EINVAL;
		data[0] = TQUIC_VARINT_4BYTE_PREFIX | (u8)(value >> 24);
		data[1] = (u8)(value >> 16);
		data[2] = (u8)(value >> 8);
		data[3] = (u8)value;
		return 4;
	} else if (value <= TQUIC_VARINT_8BYTE_MAX) {
		if (len < 8)
			return -EINVAL;
		data[0] = TQUIC_VARINT_8BYTE_PREFIX | (u8)(value >> 56);
		data[1] = (u8)(value >> 48);
		data[2] = (u8)(value >> 40);
		data[3] = (u8)(value >> 32);
		data[4] = (u8)(value >> 24);
		data[5] = (u8)(value >> 16);
		data[6] = (u8)(value >> 8);
		data[7] = (u8)value;
		return 8;
	}

	return -EOVERFLOW;
}

/**
 * tquic_varint_len - Get required encoding length for a value
 * @value: Value to check
 *
 * Returns: Required bytes (1, 2, 4, or 8), or 0 if too large
 */
static int tquic_varint_len(u64 value)
{
	if (value <= TQUIC_VARINT_1BYTE_MAX)
		return 1;
	if (value <= TQUIC_VARINT_2BYTE_MAX)
		return 2;
	if (value <= TQUIC_VARINT_4BYTE_MAX)
		return 4;
	if (value <= TQUIC_VARINT_8BYTE_MAX)
		return 8;
	return 0;
}

/* Test: Decode 1-byte varints */
static void tquic_varint_test_decode_1byte(struct kunit *test)
{
	u64 value;
	int ret;

	/* Minimum value: 0 */
	u8 data_zero[] = {0x00};
	ret = tquic_varint_decode(data_zero, sizeof(data_zero), &value);
	KUNIT_EXPECT_EQ(test, ret, 1);
	KUNIT_EXPECT_EQ(test, value, 0ULL);

	/* Maximum 1-byte value: 63 */
	u8 data_max[] = {0x3f};
	ret = tquic_varint_decode(data_max, sizeof(data_max), &value);
	KUNIT_EXPECT_EQ(test, ret, 1);
	KUNIT_EXPECT_EQ(test, value, 63ULL);

	/* Mid value: 37 */
	u8 data_mid[] = {0x25};
	ret = tquic_varint_decode(data_mid, sizeof(data_mid), &value);
	KUNIT_EXPECT_EQ(test, ret, 1);
	KUNIT_EXPECT_EQ(test, value, 37ULL);
}

/* Test: Decode 2-byte varints */
static void tquic_varint_test_decode_2byte(struct kunit *test)
{
	u64 value;
	int ret;

	/* Minimum 2-byte encoding: 64 */
	u8 data_min[] = {0x40, 0x40};
	ret = tquic_varint_decode(data_min, sizeof(data_min), &value);
	KUNIT_EXPECT_EQ(test, ret, 2);
	KUNIT_EXPECT_EQ(test, value, 64ULL);

	/* Maximum 2-byte value: 16383 */
	u8 data_max[] = {0x7f, 0xff};
	ret = tquic_varint_decode(data_max, sizeof(data_max), &value);
	KUNIT_EXPECT_EQ(test, ret, 2);
	KUNIT_EXPECT_EQ(test, value, 16383ULL);

	/* Example from RFC: 494 = 0x40 0x01 0xee -> but wait, 494 needs check */
	u8 data_494[] = {0x41, 0xee};
	ret = tquic_varint_decode(data_494, sizeof(data_494), &value);
	KUNIT_EXPECT_EQ(test, ret, 2);
	KUNIT_EXPECT_EQ(test, value, 494ULL);
}

/* Test: Decode 4-byte varints */
static void tquic_varint_test_decode_4byte(struct kunit *test)
{
	u64 value;
	int ret;

	/* Minimum 4-byte encoding: 16384 */
	u8 data_min[] = {0x80, 0x00, 0x40, 0x00};
	ret = tquic_varint_decode(data_min, sizeof(data_min), &value);
	KUNIT_EXPECT_EQ(test, ret, 4);
	KUNIT_EXPECT_EQ(test, value, 16384ULL);

	/* Maximum 4-byte value: 1073741823 */
	u8 data_max[] = {0xbf, 0xff, 0xff, 0xff};
	ret = tquic_varint_decode(data_max, sizeof(data_max), &value);
	KUNIT_EXPECT_EQ(test, ret, 4);
	KUNIT_EXPECT_EQ(test, value, 1073741823ULL);

	/* Example: 15293 */
	u8 data_15293[] = {0x80, 0x00, 0x3b, 0xbd};
	ret = tquic_varint_decode(data_15293, sizeof(data_15293), &value);
	KUNIT_EXPECT_EQ(test, ret, 4);
	KUNIT_EXPECT_EQ(test, value, 15293ULL);
}

/* Test: Decode 8-byte varints */
static void tquic_varint_test_decode_8byte(struct kunit *test)
{
	u64 value;
	int ret;

	/* Minimum 8-byte encoding: 1073741824 */
	u8 data_min[] = {0xc0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00};
	ret = tquic_varint_decode(data_min, sizeof(data_min), &value);
	KUNIT_EXPECT_EQ(test, ret, 8);
	KUNIT_EXPECT_EQ(test, value, 1073741824ULL);

	/* Maximum 8-byte value */
	u8 data_max[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	ret = tquic_varint_decode(data_max, sizeof(data_max), &value);
	KUNIT_EXPECT_EQ(test, ret, 8);
	KUNIT_EXPECT_EQ(test, value, TQUIC_VARINT_8BYTE_MAX);

	/* Example: 151288809941952652 from RFC */
	u8 data_example[] = {0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c};
	ret = tquic_varint_decode(data_example, sizeof(data_example), &value);
	KUNIT_EXPECT_EQ(test, ret, 8);
	KUNIT_EXPECT_EQ(test, value, 151288809941952652ULL);
}

/* Test: Encode 1-byte varints */
static void tquic_varint_test_encode_1byte(struct kunit *test)
{
	u8 buf[8];
	int ret;

	/* Zero */
	ret = tquic_varint_encode(0, buf, sizeof(buf));
	KUNIT_EXPECT_EQ(test, ret, 1);
	KUNIT_EXPECT_EQ(test, buf[0], 0x00);

	/* Maximum 1-byte */
	ret = tquic_varint_encode(63, buf, sizeof(buf));
	KUNIT_EXPECT_EQ(test, ret, 1);
	KUNIT_EXPECT_EQ(test, buf[0], 0x3f);

	/* Mid value */
	ret = tquic_varint_encode(37, buf, sizeof(buf));
	KUNIT_EXPECT_EQ(test, ret, 1);
	KUNIT_EXPECT_EQ(test, buf[0], 0x25);
}

/* Test: Encode 2-byte varints */
static void tquic_varint_test_encode_2byte(struct kunit *test)
{
	u8 buf[8];
	int ret;

	/* Minimum 2-byte */
	ret = tquic_varint_encode(64, buf, sizeof(buf));
	KUNIT_EXPECT_EQ(test, ret, 2);
	KUNIT_EXPECT_EQ(test, buf[0], 0x40);
	KUNIT_EXPECT_EQ(test, buf[1], 0x40);

	/* Maximum 2-byte */
	ret = tquic_varint_encode(16383, buf, sizeof(buf));
	KUNIT_EXPECT_EQ(test, ret, 2);
	KUNIT_EXPECT_EQ(test, buf[0], 0x7f);
	KUNIT_EXPECT_EQ(test, buf[1], 0xff);

	/* 494 */
	ret = tquic_varint_encode(494, buf, sizeof(buf));
	KUNIT_EXPECT_EQ(test, ret, 2);
	KUNIT_EXPECT_EQ(test, buf[0], 0x41);
	KUNIT_EXPECT_EQ(test, buf[1], 0xee);
}

/* Test: Encode 4-byte varints */
static void tquic_varint_test_encode_4byte(struct kunit *test)
{
	u8 buf[8];
	int ret;

	/* Minimum 4-byte */
	ret = tquic_varint_encode(16384, buf, sizeof(buf));
	KUNIT_EXPECT_EQ(test, ret, 4);
	KUNIT_EXPECT_EQ(test, buf[0], 0x80);
	KUNIT_EXPECT_EQ(test, buf[1], 0x00);
	KUNIT_EXPECT_EQ(test, buf[2], 0x40);
	KUNIT_EXPECT_EQ(test, buf[3], 0x00);

	/* Maximum 4-byte */
	ret = tquic_varint_encode(1073741823, buf, sizeof(buf));
	KUNIT_EXPECT_EQ(test, ret, 4);
	KUNIT_EXPECT_EQ(test, buf[0], 0xbf);
	KUNIT_EXPECT_EQ(test, buf[1], 0xff);
	KUNIT_EXPECT_EQ(test, buf[2], 0xff);
	KUNIT_EXPECT_EQ(test, buf[3], 0xff);
}

/* Test: Encode 8-byte varints */
static void tquic_varint_test_encode_8byte(struct kunit *test)
{
	u8 buf[8];
	int ret;

	/* Minimum 8-byte */
	ret = tquic_varint_encode(1073741824, buf, sizeof(buf));
	KUNIT_EXPECT_EQ(test, ret, 8);
	KUNIT_EXPECT_EQ(test, buf[0], 0xc0);

	/* Maximum 8-byte */
	ret = tquic_varint_encode(TQUIC_VARINT_8BYTE_MAX, buf, sizeof(buf));
	KUNIT_EXPECT_EQ(test, ret, 8);
	KUNIT_EXPECT_EQ(test, buf[0], 0xff);
	KUNIT_EXPECT_EQ(test, buf[7], 0xff);
}

/* Test: Varint length calculation */
static void tquic_varint_test_length(struct kunit *test)
{
	/* 1-byte range */
	KUNIT_EXPECT_EQ(test, tquic_varint_len(0), 1);
	KUNIT_EXPECT_EQ(test, tquic_varint_len(63), 1);

	/* 2-byte range */
	KUNIT_EXPECT_EQ(test, tquic_varint_len(64), 2);
	KUNIT_EXPECT_EQ(test, tquic_varint_len(16383), 2);

	/* 4-byte range */
	KUNIT_EXPECT_EQ(test, tquic_varint_len(16384), 4);
	KUNIT_EXPECT_EQ(test, tquic_varint_len(1073741823), 4);

	/* 8-byte range */
	KUNIT_EXPECT_EQ(test, tquic_varint_len(1073741824), 8);
	KUNIT_EXPECT_EQ(test, tquic_varint_len(TQUIC_VARINT_8BYTE_MAX), 8);

	/* Too large (should return 0) */
	KUNIT_EXPECT_EQ(test, tquic_varint_len(TQUIC_VARINT_8BYTE_MAX + 1), 0);
}

/* Test: Encode-decode roundtrip */
static void tquic_varint_test_roundtrip(struct kunit *test)
{
	u8 buf[8];
	u64 values[] = {0, 1, 63, 64, 100, 16383, 16384, 100000,
			1073741823, 1073741824, TQUIC_VARINT_8BYTE_MAX};
	int i, enc_len, dec_len;
	u64 decoded;

	for (i = 0; i < ARRAY_SIZE(values); i++) {
		enc_len = tquic_varint_encode(values[i], buf, sizeof(buf));
		KUNIT_EXPECT_GT(test, enc_len, 0);

		dec_len = tquic_varint_decode(buf, sizeof(buf), &decoded);
		KUNIT_EXPECT_EQ(test, enc_len, dec_len);
		KUNIT_EXPECT_EQ(test, values[i], decoded);
	}
}

/* Test: Insufficient buffer for decode */
static void tquic_varint_test_decode_insufficient(struct kunit *test)
{
	u64 value;
	int ret;

	/* 2-byte varint with only 1 byte available */
	u8 data_2byte[] = {0x40};
	ret = tquic_varint_decode(data_2byte, 1, &value);
	KUNIT_EXPECT_LT(test, ret, 0);

	/* 4-byte varint with only 2 bytes available */
	u8 data_4byte[] = {0x80, 0x00};
	ret = tquic_varint_decode(data_4byte, 2, &value);
	KUNIT_EXPECT_LT(test, ret, 0);

	/* 8-byte varint with only 4 bytes available */
	u8 data_8byte[] = {0xc0, 0x00, 0x00, 0x00};
	ret = tquic_varint_decode(data_8byte, 4, &value);
	KUNIT_EXPECT_LT(test, ret, 0);

	/* Empty buffer */
	ret = tquic_varint_decode(data_2byte, 0, &value);
	KUNIT_EXPECT_LT(test, ret, 0);
}

/* Test: Insufficient buffer for encode */
static void tquic_varint_test_encode_insufficient(struct kunit *test)
{
	u8 buf[8];
	int ret;

	/* 2-byte value with 1-byte buffer */
	ret = tquic_varint_encode(64, buf, 1);
	KUNIT_EXPECT_LT(test, ret, 0);

	/* 4-byte value with 2-byte buffer */
	ret = tquic_varint_encode(16384, buf, 2);
	KUNIT_EXPECT_LT(test, ret, 0);

	/* 8-byte value with 4-byte buffer */
	ret = tquic_varint_encode(1073741824, buf, 4);
	KUNIT_EXPECT_LT(test, ret, 0);
}

/* Test: Encode overflow (value too large) */
static void tquic_varint_test_encode_overflow(struct kunit *test)
{
	u8 buf[8];
	int ret;

	/* Value larger than maximum */
	ret = tquic_varint_encode(TQUIC_VARINT_8BYTE_MAX + 1, buf, sizeof(buf));
	KUNIT_EXPECT_LT(test, ret, 0);

	/* Maximum valid u64 */
	ret = tquic_varint_encode(ULLONG_MAX, buf, sizeof(buf));
	KUNIT_EXPECT_LT(test, ret, 0);
}

/* Test: RFC 9000 examples (Section 16) */
static void tquic_varint_test_rfc_examples(struct kunit *test)
{
	u64 value;
	int ret;

	/* Example: 0 -> 0x00 */
	u8 ex1[] = {0x00};
	ret = tquic_varint_decode(ex1, sizeof(ex1), &value);
	KUNIT_EXPECT_EQ(test, ret, 1);
	KUNIT_EXPECT_EQ(test, value, 0ULL);

	/* Example: 37 -> 0x25 */
	u8 ex2[] = {0x25};
	ret = tquic_varint_decode(ex2, sizeof(ex2), &value);
	KUNIT_EXPECT_EQ(test, ret, 1);
	KUNIT_EXPECT_EQ(test, value, 37ULL);

	/* Example: 15293 -> 0x7bbd */
	u8 ex3[] = {0x7b, 0xbd};
	ret = tquic_varint_decode(ex3, sizeof(ex3), &value);
	KUNIT_EXPECT_EQ(test, ret, 2);
	KUNIT_EXPECT_EQ(test, value, 15293ULL);

	/* Example: 494878333 -> 0x9d7f3e7d */
	u8 ex4[] = {0x9d, 0x7f, 0x3e, 0x7d};
	ret = tquic_varint_decode(ex4, sizeof(ex4), &value);
	KUNIT_EXPECT_EQ(test, ret, 4);
	KUNIT_EXPECT_EQ(test, value, 494878333ULL);

	/* Example: 151288809941952652 -> 0xc2197c5eff14e88c */
	u8 ex5[] = {0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c};
	ret = tquic_varint_decode(ex5, sizeof(ex5), &value);
	KUNIT_EXPECT_EQ(test, ret, 8);
	KUNIT_EXPECT_EQ(test, value, 151288809941952652ULL);
}

/* Test: Prefix detection */
static void tquic_varint_test_prefix_detection(struct kunit *test)
{
	/* 1-byte: prefix 00xxxxxx */
	KUNIT_EXPECT_EQ(test, 0x00 & TQUIC_VARINT_PREFIX_MASK, TQUIC_VARINT_1BYTE_PREFIX);
	KUNIT_EXPECT_EQ(test, 0x3f & TQUIC_VARINT_PREFIX_MASK, TQUIC_VARINT_1BYTE_PREFIX);

	/* 2-byte: prefix 01xxxxxx */
	KUNIT_EXPECT_EQ(test, 0x40 & TQUIC_VARINT_PREFIX_MASK, TQUIC_VARINT_2BYTE_PREFIX);
	KUNIT_EXPECT_EQ(test, 0x7f & TQUIC_VARINT_PREFIX_MASK, TQUIC_VARINT_2BYTE_PREFIX);

	/* 4-byte: prefix 10xxxxxx */
	KUNIT_EXPECT_EQ(test, 0x80 & TQUIC_VARINT_PREFIX_MASK, TQUIC_VARINT_4BYTE_PREFIX);
	KUNIT_EXPECT_EQ(test, 0xbf & TQUIC_VARINT_PREFIX_MASK, TQUIC_VARINT_4BYTE_PREFIX);

	/* 8-byte: prefix 11xxxxxx */
	KUNIT_EXPECT_EQ(test, 0xc0 & TQUIC_VARINT_PREFIX_MASK, TQUIC_VARINT_8BYTE_PREFIX);
	KUNIT_EXPECT_EQ(test, 0xff & TQUIC_VARINT_PREFIX_MASK, TQUIC_VARINT_8BYTE_PREFIX);
}

/* Test: Boundary values */
static void tquic_varint_test_boundaries(struct kunit *test)
{
	u8 buf[8];
	int len;

	/* Test boundary between 1 and 2 byte encoding */
	len = tquic_varint_encode(63, buf, sizeof(buf));
	KUNIT_EXPECT_EQ(test, len, 1);
	len = tquic_varint_encode(64, buf, sizeof(buf));
	KUNIT_EXPECT_EQ(test, len, 2);

	/* Test boundary between 2 and 4 byte encoding */
	len = tquic_varint_encode(16383, buf, sizeof(buf));
	KUNIT_EXPECT_EQ(test, len, 2);
	len = tquic_varint_encode(16384, buf, sizeof(buf));
	KUNIT_EXPECT_EQ(test, len, 4);

	/* Test boundary between 4 and 8 byte encoding */
	len = tquic_varint_encode(1073741823, buf, sizeof(buf));
	KUNIT_EXPECT_EQ(test, len, 4);
	len = tquic_varint_encode(1073741824, buf, sizeof(buf));
	KUNIT_EXPECT_EQ(test, len, 8);
}

/* Test: Sequential varints in buffer */
static void tquic_varint_test_sequential(struct kunit *test)
{
	/* Buffer with multiple varints: 1, 494, 16384 */
	u8 data[] = {
		0x01,			/* 1 (1 byte) */
		0x41, 0xee,		/* 494 (2 bytes) */
		0x80, 0x00, 0x40, 0x00,	/* 16384 (4 bytes) */
	};
	u64 value;
	int offset = 0;
	int ret;

	/* Decode first varint */
	ret = tquic_varint_decode(data + offset, sizeof(data) - offset, &value);
	KUNIT_EXPECT_EQ(test, ret, 1);
	KUNIT_EXPECT_EQ(test, value, 1ULL);
	offset += ret;

	/* Decode second varint */
	ret = tquic_varint_decode(data + offset, sizeof(data) - offset, &value);
	KUNIT_EXPECT_EQ(test, ret, 2);
	KUNIT_EXPECT_EQ(test, value, 494ULL);
	offset += ret;

	/* Decode third varint */
	ret = tquic_varint_decode(data + offset, sizeof(data) - offset, &value);
	KUNIT_EXPECT_EQ(test, ret, 4);
	KUNIT_EXPECT_EQ(test, value, 16384ULL);
}

static struct kunit_case tquic_varint_test_cases[] = {
	KUNIT_CASE(tquic_varint_test_decode_1byte),
	KUNIT_CASE(tquic_varint_test_decode_2byte),
	KUNIT_CASE(tquic_varint_test_decode_4byte),
	KUNIT_CASE(tquic_varint_test_decode_8byte),
	KUNIT_CASE(tquic_varint_test_encode_1byte),
	KUNIT_CASE(tquic_varint_test_encode_2byte),
	KUNIT_CASE(tquic_varint_test_encode_4byte),
	KUNIT_CASE(tquic_varint_test_encode_8byte),
	KUNIT_CASE(tquic_varint_test_length),
	KUNIT_CASE(tquic_varint_test_roundtrip),
	KUNIT_CASE(tquic_varint_test_decode_insufficient),
	KUNIT_CASE(tquic_varint_test_encode_insufficient),
	KUNIT_CASE(tquic_varint_test_encode_overflow),
	KUNIT_CASE(tquic_varint_test_rfc_examples),
	KUNIT_CASE(tquic_varint_test_prefix_detection),
	KUNIT_CASE(tquic_varint_test_boundaries),
	KUNIT_CASE(tquic_varint_test_sequential),
	{}
};

static struct kunit_suite tquic_varint_test_suite = {
	.name = "tquic-varint",
	.test_cases = tquic_varint_test_cases,
};

kunit_test_suite(tquic_varint_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for TQUIC variable-length integer encoding");
