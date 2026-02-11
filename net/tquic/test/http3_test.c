// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC HTTP/3 Unit Tests
 *
 * Copyright (c) 2026 Linux Foundation
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Comprehensive KUnit test suite for HTTP/3 (RFC 9114), QPACK (RFC 9204),
 * and Extensible Priorities (RFC 9218).
 *
 * Test Categories:
 * - HTTP/3 Frame Layer (varint, frame parsing/writing)
 * - HTTP/3 Settings (encoding, decoding, validation)
 * - QPACK (Huffman coding, integer encoding, string encoding, headers)
 * - HTTP/3 Priority (RFC 9218 extensible priorities)
 * - GREASE handling
 */

#include <kunit/test.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <net/tquic_http3.h>

#include "../http3/http3_frame.h"
#include "../http3/qpack.h"

/*
 * =============================================================================
 * HTTP/3 Varint Encoding/Decoding Tests
 * =============================================================================
 */

static void test_h3_varint_size(struct kunit *test)
{
	/* 1-byte values: 0-63 */
	KUNIT_EXPECT_EQ(test, 1, h3_varint_size(0));
	KUNIT_EXPECT_EQ(test, 1, h3_varint_size(63));

	/* 2-byte values: 64-16383 */
	KUNIT_EXPECT_EQ(test, 2, h3_varint_size(64));
	KUNIT_EXPECT_EQ(test, 2, h3_varint_size(16383));

	/* 4-byte values: 16384-1073741823 */
	KUNIT_EXPECT_EQ(test, 4, h3_varint_size(16384));
	KUNIT_EXPECT_EQ(test, 4, h3_varint_size(1073741823));

	/* 8-byte values: 1073741824-4611686018427387903 */
	KUNIT_EXPECT_EQ(test, 8, h3_varint_size(1073741824ULL));
	KUNIT_EXPECT_EQ(test, 8, h3_varint_size(4611686018427387903ULL));
}

static void test_h3_varint_encode_decode_1byte(struct kunit *test)
{
	u8 buf[8];
	u64 value;
	int ret;

	/* Encode value 0 */
	ret = h3_varint_encode(0, buf, sizeof(buf));
	KUNIT_EXPECT_EQ(test, 1, ret);
	KUNIT_EXPECT_EQ(test, 0x00, buf[0]);

	ret = h3_varint_decode(buf, sizeof(buf), &value);
	KUNIT_EXPECT_EQ(test, 1, ret);
	KUNIT_EXPECT_EQ(test, 0ULL, value);

	/* Encode value 63 (max 1-byte) */
	ret = h3_varint_encode(63, buf, sizeof(buf));
	KUNIT_EXPECT_EQ(test, 1, ret);
	KUNIT_EXPECT_EQ(test, 0x3f, buf[0]);

	ret = h3_varint_decode(buf, sizeof(buf), &value);
	KUNIT_EXPECT_EQ(test, 1, ret);
	KUNIT_EXPECT_EQ(test, 63ULL, value);
}

static void test_h3_varint_encode_decode_2byte(struct kunit *test)
{
	u8 buf[8];
	u64 value;
	int ret;

	/* Encode value 64 (min 2-byte) */
	ret = h3_varint_encode(64, buf, sizeof(buf));
	KUNIT_EXPECT_EQ(test, 2, ret);

	ret = h3_varint_decode(buf, sizeof(buf), &value);
	KUNIT_EXPECT_EQ(test, 2, ret);
	KUNIT_EXPECT_EQ(test, 64ULL, value);

	/* Encode value 16383 (max 2-byte) */
	ret = h3_varint_encode(16383, buf, sizeof(buf));
	KUNIT_EXPECT_EQ(test, 2, ret);

	ret = h3_varint_decode(buf, sizeof(buf), &value);
	KUNIT_EXPECT_EQ(test, 2, ret);
	KUNIT_EXPECT_EQ(test, 16383ULL, value);
}

static void test_h3_varint_encode_decode_4byte(struct kunit *test)
{
	u8 buf[8];
	u64 value;
	int ret;

	/* Encode value 16384 (min 4-byte) */
	ret = h3_varint_encode(16384, buf, sizeof(buf));
	KUNIT_EXPECT_EQ(test, 4, ret);

	ret = h3_varint_decode(buf, sizeof(buf), &value);
	KUNIT_EXPECT_EQ(test, 4, ret);
	KUNIT_EXPECT_EQ(test, 16384ULL, value);

	/* Encode value 1073741823 (max 4-byte) */
	ret = h3_varint_encode(1073741823, buf, sizeof(buf));
	KUNIT_EXPECT_EQ(test, 4, ret);

	ret = h3_varint_decode(buf, sizeof(buf), &value);
	KUNIT_EXPECT_EQ(test, 4, ret);
	KUNIT_EXPECT_EQ(test, 1073741823ULL, value);
}

static void test_h3_varint_encode_decode_8byte(struct kunit *test)
{
	u8 buf[8];
	u64 value;
	int ret;

	/* Encode value 1073741824 (min 8-byte) */
	ret = h3_varint_encode(1073741824ULL, buf, sizeof(buf));
	KUNIT_EXPECT_EQ(test, 8, ret);

	ret = h3_varint_decode(buf, sizeof(buf), &value);
	KUNIT_EXPECT_EQ(test, 8, ret);
	KUNIT_EXPECT_EQ(test, 1073741824ULL, value);

	/* Encode max valid varint value */
	ret = h3_varint_encode(4611686018427387903ULL, buf, sizeof(buf));
	KUNIT_EXPECT_EQ(test, 8, ret);

	ret = h3_varint_decode(buf, sizeof(buf), &value);
	KUNIT_EXPECT_EQ(test, 8, ret);
	KUNIT_EXPECT_EQ(test, 4611686018427387903ULL, value);
}

static void test_h3_varint_buffer_too_small(struct kunit *test)
{
	u8 buf[1];
	int ret;

	/* Try to encode 2-byte value into 1-byte buffer */
	ret = h3_varint_encode(64, buf, sizeof(buf));
	KUNIT_EXPECT_EQ(test, -ENOSPC, ret);
}

static void test_h3_varint_decode_len(struct kunit *test)
{
	/* First two bits determine length */
	KUNIT_EXPECT_EQ(test, 1, h3_varint_decode_len(0x00)); /* 00xxxxxx */
	KUNIT_EXPECT_EQ(test, 1, h3_varint_decode_len(0x3f)); /* 00xxxxxx */
	KUNIT_EXPECT_EQ(test, 2, h3_varint_decode_len(0x40)); /* 01xxxxxx */
	KUNIT_EXPECT_EQ(test, 2, h3_varint_decode_len(0x7f)); /* 01xxxxxx */
	KUNIT_EXPECT_EQ(test, 4, h3_varint_decode_len(0x80)); /* 10xxxxxx */
	KUNIT_EXPECT_EQ(test, 4, h3_varint_decode_len(0xbf)); /* 10xxxxxx */
	KUNIT_EXPECT_EQ(test, 8, h3_varint_decode_len(0xc0)); /* 11xxxxxx */
	KUNIT_EXPECT_EQ(test, 8, h3_varint_decode_len(0xff)); /* 11xxxxxx */
}

/*
 * =============================================================================
 * HTTP/3 DATA Frame Tests
 * =============================================================================
 */

static void test_h3_data_frame_write(struct kunit *test)
{
	u8 buf[128];
	const u8 payload[] = "Hello, HTTP/3!";
	int ret;

	ret = tquic_h3_write_data_frame(buf, sizeof(buf),
					payload, sizeof(payload) - 1);
	KUNIT_ASSERT_GT(test, ret, 0);

	/* Verify frame type */
	KUNIT_EXPECT_EQ(test, H3_FRAME_DATA, buf[0]);
}

static void test_h3_data_frame_parse(struct kunit *test)
{
	u8 buf[128];
	const u8 payload[] = "Test data";
	struct tquic_h3_frame frame;
	int written, parsed;

	/* Write frame */
	written = tquic_h3_write_data_frame(buf, sizeof(buf),
					    payload, sizeof(payload) - 1);
	KUNIT_ASSERT_GT(test, written, 0);

	/* Parse frame */
	parsed = tquic_h3_parse_frame(buf, written, &frame, NULL, 0);
	KUNIT_ASSERT_EQ(test, written, parsed);
	KUNIT_EXPECT_EQ(test, H3_FRAME_DATA, (u64)frame.type);
	KUNIT_EXPECT_EQ(test, sizeof(payload) - 1, (size_t)frame.data.len);
	KUNIT_EXPECT_EQ(test, 0, memcmp(frame.data.data, payload,
					sizeof(payload) - 1));
}

static void test_h3_data_frame_size(struct kunit *test)
{
	size_t size;

	/* Empty payload */
	size = tquic_h3_data_frame_size(0);
	KUNIT_EXPECT_EQ(test, 2UL, size);  /* type(1) + len(1) */

	/* Small payload */
	size = tquic_h3_data_frame_size(10);
	KUNIT_EXPECT_EQ(test, 12UL, size);  /* type(1) + len(1) + data(10) */

	/* Large payload (2-byte length) */
	size = tquic_h3_data_frame_size(1000);
	KUNIT_EXPECT_EQ(test, 1003UL, size);  /* type(1) + len(2) + data(1000) */
}

/*
 * =============================================================================
 * HTTP/3 HEADERS Frame Tests
 * =============================================================================
 */

static void test_h3_headers_frame_write(struct kunit *test)
{
	u8 buf[128];
	const u8 qpack_data[] = { 0x00, 0x00, 0x51, 0x01 };  /* Mock QPACK */
	int ret;

	ret = tquic_h3_write_headers_frame(buf, sizeof(buf),
					   qpack_data, sizeof(qpack_data));
	KUNIT_ASSERT_GT(test, ret, 0);

	/* Verify frame type */
	KUNIT_EXPECT_EQ(test, H3_FRAME_HEADERS, buf[0]);
}

static void test_h3_headers_frame_parse(struct kunit *test)
{
	u8 buf[128];
	const u8 qpack_data[] = { 0x00, 0x00, 0x51, 0x01 };
	struct tquic_h3_frame frame;
	int written, parsed;

	/* Write frame */
	written = tquic_h3_write_headers_frame(buf, sizeof(buf),
					       qpack_data, sizeof(qpack_data));
	KUNIT_ASSERT_GT(test, written, 0);

	/* Parse frame */
	parsed = tquic_h3_parse_frame(buf, written, &frame, NULL, 0);
	KUNIT_ASSERT_EQ(test, written, parsed);
	KUNIT_EXPECT_EQ(test, H3_FRAME_HEADERS, (u64)frame.type);
	KUNIT_EXPECT_EQ(test, sizeof(qpack_data), (size_t)frame.headers.len);
}

/*
 * =============================================================================
 * HTTP/3 SETTINGS Frame Tests
 * =============================================================================
 */

static void test_h3_settings_frame_write(struct kunit *test)
{
	u8 buf[128];
	struct tquic_h3_settings settings;
	int ret;

	tquic_h3_settings_init(&settings);
	settings.qpack_max_table_capacity = 4096;
	settings.qpack_blocked_streams = 100;

	ret = tquic_h3_write_settings_frame(buf, sizeof(buf), &settings);
	KUNIT_ASSERT_GT(test, ret, 0);

	/* Verify frame type */
	KUNIT_EXPECT_EQ(test, H3_FRAME_SETTINGS, buf[0]);
}

static void test_h3_settings_frame_parse(struct kunit *test)
{
	u8 buf[128];
	struct tquic_h3_settings settings;
	struct tquic_h3_frame frame;
	struct tquic_h3_frame_settings_entry entries[16];
	int written, parsed;

	/* Set up settings */
	tquic_h3_settings_init(&settings);
	settings.qpack_max_table_capacity = 4096;

	/* Write frame */
	written = tquic_h3_write_settings_frame(buf, sizeof(buf), &settings);
	KUNIT_ASSERT_GT(test, written, 0);

	/* Parse frame */
	parsed = tquic_h3_parse_frame(buf, written, &frame, entries, 16);
	KUNIT_ASSERT_EQ(test, written, parsed);
	KUNIT_EXPECT_EQ(test, H3_FRAME_SETTINGS, (u64)frame.type);
}

static void test_h3_settings_init_defaults(struct kunit *test)
{
	struct tquic_h3_settings settings;

	tquic_h3_settings_init(&settings);

	KUNIT_EXPECT_EQ(test, H3_DEFAULT_QPACK_MAX_TABLE_CAPACITY,
			(u64)settings.qpack_max_table_capacity);
	KUNIT_EXPECT_EQ(test, H3_DEFAULT_MAX_FIELD_SECTION_SIZE,
			(u64)settings.max_field_section_size);
	KUNIT_EXPECT_EQ(test, H3_DEFAULT_QPACK_BLOCKED_STREAMS,
			(u64)settings.qpack_blocked_streams);
	KUNIT_EXPECT_TRUE(test, settings.enable_priority);
}

static void test_h3_settings_encode_decode(struct kunit *test)
{
	u8 buf[128];
	struct tquic_h3_settings original, decoded;
	int encoded_len;

	/* Set up settings */
	tquic_h3_settings_init(&original);
	original.qpack_max_table_capacity = 8192;
	original.max_field_section_size = 32768;
	original.qpack_blocked_streams = 200;

	/* Encode */
	encoded_len = h3_encode_settings(&original, buf, sizeof(buf));
	KUNIT_ASSERT_GT(test, encoded_len, 0);

	/* Decode */
	KUNIT_ASSERT_EQ(test, 0, h3_decode_settings(buf, encoded_len, &decoded));

	/* Verify */
	KUNIT_EXPECT_EQ(test, original.qpack_max_table_capacity,
			decoded.qpack_max_table_capacity);
	KUNIT_EXPECT_EQ(test, original.max_field_section_size,
			decoded.max_field_section_size);
	KUNIT_EXPECT_EQ(test, original.qpack_blocked_streams,
			decoded.qpack_blocked_streams);
}

/*
 * =============================================================================
 * HTTP/3 GOAWAY Frame Tests
 * =============================================================================
 */

static void test_h3_goaway_frame_write(struct kunit *test)
{
	u8 buf[32];
	int ret;

	ret = tquic_h3_write_goaway_frame(buf, sizeof(buf), 12);
	KUNIT_ASSERT_GT(test, ret, 0);

	/* Verify frame type */
	KUNIT_EXPECT_EQ(test, H3_FRAME_GOAWAY, buf[0]);
}

static void test_h3_goaway_frame_parse(struct kunit *test)
{
	u8 buf[32];
	struct tquic_h3_frame frame;
	int written, parsed;

	/* Write frame */
	written = tquic_h3_write_goaway_frame(buf, sizeof(buf), 100);
	KUNIT_ASSERT_GT(test, written, 0);

	/* Parse frame */
	parsed = tquic_h3_parse_frame(buf, written, &frame, NULL, 0);
	KUNIT_ASSERT_EQ(test, written, parsed);
	KUNIT_EXPECT_EQ(test, H3_FRAME_GOAWAY, (u64)frame.type);
	KUNIT_EXPECT_EQ(test, 100ULL, frame.goaway.id);
}

static void test_h3_goaway_frame_large_id(struct kunit *test)
{
	u8 buf[32];
	struct tquic_h3_frame frame;
	u64 large_id = 0x3FFFFFFFFFFFFFFFULL;  /* Max varint */
	int written, parsed;

	/* Write frame with large ID */
	written = tquic_h3_write_goaway_frame(buf, sizeof(buf), large_id);
	KUNIT_ASSERT_GT(test, written, 0);

	/* Parse frame */
	parsed = tquic_h3_parse_frame(buf, written, &frame, NULL, 0);
	KUNIT_ASSERT_EQ(test, written, parsed);
	KUNIT_EXPECT_EQ(test, large_id, frame.goaway.id);
}

/*
 * =============================================================================
 * HTTP/3 MAX_PUSH_ID Frame Tests
 * =============================================================================
 */

static void test_h3_max_push_id_frame_write(struct kunit *test)
{
	u8 buf[32];
	int ret;

	ret = tquic_h3_write_max_push_id_frame(buf, sizeof(buf), 5);
	KUNIT_ASSERT_GT(test, ret, 0);

	/* Verify frame type */
	KUNIT_EXPECT_EQ(test, H3_FRAME_MAX_PUSH_ID, buf[0]);
}

static void test_h3_max_push_id_frame_parse(struct kunit *test)
{
	u8 buf[32];
	struct tquic_h3_frame frame;
	int written, parsed;

	/* Write frame */
	written = tquic_h3_write_max_push_id_frame(buf, sizeof(buf), 42);
	KUNIT_ASSERT_GT(test, written, 0);

	/* Parse frame */
	parsed = tquic_h3_parse_frame(buf, written, &frame, NULL, 0);
	KUNIT_ASSERT_EQ(test, written, parsed);
	KUNIT_EXPECT_EQ(test, H3_FRAME_MAX_PUSH_ID, (u64)frame.type);
	KUNIT_EXPECT_EQ(test, 42ULL, frame.max_push_id.push_id);
}

/*
 * =============================================================================
 * HTTP/3 CANCEL_PUSH Frame Tests
 * =============================================================================
 */

static void test_h3_cancel_push_frame_write(struct kunit *test)
{
	u8 buf[32];
	int ret;

	ret = tquic_h3_write_cancel_push_frame(buf, sizeof(buf), 7);
	KUNIT_ASSERT_GT(test, ret, 0);

	/* Verify frame type */
	KUNIT_EXPECT_EQ(test, H3_FRAME_CANCEL_PUSH, buf[0]);
}

static void test_h3_cancel_push_frame_parse(struct kunit *test)
{
	u8 buf[32];
	struct tquic_h3_frame frame;
	int written, parsed;

	/* Write frame */
	written = tquic_h3_write_cancel_push_frame(buf, sizeof(buf), 99);
	KUNIT_ASSERT_GT(test, written, 0);

	/* Parse frame */
	parsed = tquic_h3_parse_frame(buf, written, &frame, NULL, 0);
	KUNIT_ASSERT_EQ(test, written, parsed);
	KUNIT_EXPECT_EQ(test, H3_FRAME_CANCEL_PUSH, (u64)frame.type);
	KUNIT_EXPECT_EQ(test, 99ULL, frame.cancel_push.push_id);
}

/*
 * =============================================================================
 * HTTP/3 PUSH_PROMISE Frame Tests
 * =============================================================================
 */

static void test_h3_push_promise_frame_write(struct kunit *test)
{
	u8 buf[128];
	const u8 headers[] = { 0x00, 0x00, 0x51, 0x01 };
	int ret;

	ret = tquic_h3_write_push_promise_frame(buf, sizeof(buf), 3,
						headers, sizeof(headers));
	KUNIT_ASSERT_GT(test, ret, 0);

	/* Verify frame type */
	KUNIT_EXPECT_EQ(test, H3_FRAME_PUSH_PROMISE, buf[0]);
}

static void test_h3_push_promise_frame_parse(struct kunit *test)
{
	u8 buf[128];
	const u8 headers[] = { 0x00, 0x00, 0x51, 0x01 };
	struct tquic_h3_frame frame;
	int written, parsed;

	/* Write frame */
	written = tquic_h3_write_push_promise_frame(buf, sizeof(buf), 5,
						    headers, sizeof(headers));
	KUNIT_ASSERT_GT(test, written, 0);

	/* Parse frame */
	parsed = tquic_h3_parse_frame(buf, written, &frame, NULL, 0);
	KUNIT_ASSERT_EQ(test, written, parsed);
	KUNIT_EXPECT_EQ(test, H3_FRAME_PUSH_PROMISE, (u64)frame.type);
	KUNIT_EXPECT_EQ(test, 5ULL, frame.push_promise.push_id);
	KUNIT_EXPECT_EQ(test, sizeof(headers), (size_t)frame.push_promise.len);
}

/*
 * =============================================================================
 * HTTP/3 Frame Validation Tests
 * =============================================================================
 */

static void test_h3_frame_valid_on_control_stream(struct kunit *test)
{
	/* Valid on control stream */
	KUNIT_EXPECT_TRUE(test, h3_frame_valid_on_control_stream(H3_FRAME_SETTINGS));
	KUNIT_EXPECT_TRUE(test, h3_frame_valid_on_control_stream(H3_FRAME_GOAWAY));
	KUNIT_EXPECT_TRUE(test, h3_frame_valid_on_control_stream(H3_FRAME_MAX_PUSH_ID));
	KUNIT_EXPECT_TRUE(test, h3_frame_valid_on_control_stream(H3_FRAME_CANCEL_PUSH));
	KUNIT_EXPECT_TRUE(test, h3_frame_valid_on_control_stream(TQUIC_H3_FRAME_PRIORITY_UPDATE));

	/* Invalid on control stream */
	KUNIT_EXPECT_FALSE(test, h3_frame_valid_on_control_stream(H3_FRAME_DATA));
	KUNIT_EXPECT_FALSE(test, h3_frame_valid_on_control_stream(H3_FRAME_HEADERS));
}

static void test_h3_frame_valid_on_request_stream(struct kunit *test)
{
	/* Valid on request stream */
	KUNIT_EXPECT_TRUE(test, h3_frame_valid_on_request_stream(H3_FRAME_DATA));
	KUNIT_EXPECT_TRUE(test, h3_frame_valid_on_request_stream(H3_FRAME_HEADERS));
	KUNIT_EXPECT_TRUE(test, h3_frame_valid_on_request_stream(H3_FRAME_PUSH_PROMISE));

	/* Invalid on request stream */
	KUNIT_EXPECT_FALSE(test, h3_frame_valid_on_request_stream(H3_FRAME_SETTINGS));
	KUNIT_EXPECT_FALSE(test, h3_frame_valid_on_request_stream(H3_FRAME_GOAWAY));
	KUNIT_EXPECT_FALSE(test, h3_frame_valid_on_request_stream(H3_FRAME_MAX_PUSH_ID));
}

static void test_h3_frame_valid_on_push_stream(struct kunit *test)
{
	/* Valid on push stream */
	KUNIT_EXPECT_TRUE(test, h3_frame_valid_on_push_stream(H3_FRAME_DATA));
	KUNIT_EXPECT_TRUE(test, h3_frame_valid_on_push_stream(H3_FRAME_HEADERS));

	/* Invalid on push stream */
	KUNIT_EXPECT_FALSE(test, h3_frame_valid_on_push_stream(H3_FRAME_SETTINGS));
	KUNIT_EXPECT_FALSE(test, h3_frame_valid_on_push_stream(H3_FRAME_PUSH_PROMISE));
}

/*
 * =============================================================================
 * HTTP/3 Frame Name/Error Utility Tests
 * =============================================================================
 */

static void test_h3_frame_type_name(struct kunit *test)
{
	KUNIT_EXPECT_STREQ(test, "DATA", tquic_h3_frame_type_name(H3_FRAME_DATA));
	KUNIT_EXPECT_STREQ(test, "HEADERS", tquic_h3_frame_type_name(H3_FRAME_HEADERS));
	KUNIT_EXPECT_STREQ(test, "SETTINGS", tquic_h3_frame_type_name(H3_FRAME_SETTINGS));
	KUNIT_EXPECT_STREQ(test, "GOAWAY", tquic_h3_frame_type_name(H3_FRAME_GOAWAY));
	KUNIT_EXPECT_STREQ(test, "MAX_PUSH_ID", tquic_h3_frame_type_name(H3_FRAME_MAX_PUSH_ID));
	KUNIT_EXPECT_STREQ(test, "CANCEL_PUSH", tquic_h3_frame_type_name(H3_FRAME_CANCEL_PUSH));
	KUNIT_EXPECT_STREQ(test, "PUSH_PROMISE", tquic_h3_frame_type_name(H3_FRAME_PUSH_PROMISE));
	KUNIT_EXPECT_STREQ(test, "PRIORITY_UPDATE",
			   tquic_h3_frame_type_name(TQUIC_H3_FRAME_PRIORITY_UPDATE));
}

static void test_h3_error_name(struct kunit *test)
{
	KUNIT_EXPECT_STREQ(test, "H3_NO_ERROR", tquic_h3_error_name(H3_NO_ERROR));
	KUNIT_EXPECT_STREQ(test, "H3_FRAME_ERROR", tquic_h3_error_name(H3_FRAME_ERROR));
	KUNIT_EXPECT_STREQ(test, "H3_SETTINGS_ERROR", tquic_h3_error_name(H3_SETTINGS_ERROR));
	KUNIT_EXPECT_STREQ(test, "H3_REQUEST_CANCELLED",
			   tquic_h3_error_name(H3_REQUEST_CANCELLED));
}

/*
 * =============================================================================
 * HTTP/3 GREASE Tests
 * =============================================================================
 */

static void test_h3_grease_identifier(struct kunit *test)
{
	/* GREASE values follow pattern: 0x1f * N + 0x21 */
	KUNIT_EXPECT_TRUE(test, tquic_h3_is_grease_id(0x21));       /* 0x1f * 0 + 0x21 */
	KUNIT_EXPECT_TRUE(test, tquic_h3_is_grease_id(0x40));       /* 0x1f * 1 + 0x21 */
	KUNIT_EXPECT_TRUE(test, tquic_h3_is_grease_id(0x5f));       /* 0x1f * 2 + 0x21 */
	KUNIT_EXPECT_TRUE(test, tquic_h3_is_grease_id(0x7e));       /* 0x1f * 3 + 0x21 */

	/* Non-GREASE values */
	KUNIT_EXPECT_FALSE(test, tquic_h3_is_grease_id(H3_FRAME_DATA));
	KUNIT_EXPECT_FALSE(test, tquic_h3_is_grease_id(H3_FRAME_HEADERS));
	KUNIT_EXPECT_FALSE(test, tquic_h3_is_grease_id(H3_FRAME_SETTINGS));
	KUNIT_EXPECT_FALSE(test, tquic_h3_is_grease_id(0x22));
	KUNIT_EXPECT_FALSE(test, tquic_h3_is_grease_id(0x30));
}

/*
 * =============================================================================
 * QPACK Integer Encoding/Decoding Tests
 * =============================================================================
 */

static void test_qpack_encode_decode_integer_prefix5(struct kunit *test)
{
	u8 buf[16];
	u64 value;
	size_t encoded_len, consumed;
	int ret;

	/* Value fits in 5-bit prefix (0-30) */
	ret = qpack_encode_integer(10, 5, 0x00, buf, sizeof(buf), &encoded_len);
	KUNIT_ASSERT_EQ(test, 0, ret);
	KUNIT_EXPECT_EQ(test, 1UL, encoded_len);
	KUNIT_EXPECT_EQ(test, 0x0a, buf[0]);

	ret = qpack_decode_integer(buf, encoded_len, 5, &value, &consumed);
	KUNIT_ASSERT_EQ(test, 0, ret);
	KUNIT_EXPECT_EQ(test, 10ULL, value);
	KUNIT_EXPECT_EQ(test, 1UL, consumed);

	/* Value exceeds 5-bit prefix (>30) */
	ret = qpack_encode_integer(100, 5, 0x00, buf, sizeof(buf), &encoded_len);
	KUNIT_ASSERT_EQ(test, 0, ret);
	KUNIT_EXPECT_GT(test, encoded_len, 1UL);

	ret = qpack_decode_integer(buf, encoded_len, 5, &value, &consumed);
	KUNIT_ASSERT_EQ(test, 0, ret);
	KUNIT_EXPECT_EQ(test, 100ULL, value);
}

static void test_qpack_encode_decode_integer_prefix7(struct kunit *test)
{
	u8 buf[16];
	u64 value;
	size_t encoded_len, consumed;
	int ret;

	/* Value fits in 7-bit prefix (0-126) */
	ret = qpack_encode_integer(50, 7, 0x00, buf, sizeof(buf), &encoded_len);
	KUNIT_ASSERT_EQ(test, 0, ret);
	KUNIT_EXPECT_EQ(test, 1UL, encoded_len);

	ret = qpack_decode_integer(buf, encoded_len, 7, &value, &consumed);
	KUNIT_ASSERT_EQ(test, 0, ret);
	KUNIT_EXPECT_EQ(test, 50ULL, value);

	/* Large value needing continuation */
	ret = qpack_encode_integer(1000, 7, 0x80, buf, sizeof(buf), &encoded_len);
	KUNIT_ASSERT_EQ(test, 0, ret);
	KUNIT_EXPECT_GT(test, encoded_len, 1UL);
	KUNIT_EXPECT_EQ(test, 0xff, buf[0]);  /* Prefix bits + max prefix value */

	ret = qpack_decode_integer(buf, encoded_len, 7, &value, &consumed);
	KUNIT_ASSERT_EQ(test, 0, ret);
	KUNIT_EXPECT_EQ(test, 1000ULL, value);
}

static void test_qpack_encode_integer_with_prefix(struct kunit *test)
{
	u8 buf[16];
	size_t encoded_len;
	int ret;

	/* Encode with prefix bits */
	ret = qpack_encode_integer(5, 4, 0xf0, buf, sizeof(buf), &encoded_len);
	KUNIT_ASSERT_EQ(test, 0, ret);
	KUNIT_EXPECT_EQ(test, 1UL, encoded_len);
	KUNIT_EXPECT_EQ(test, 0xf5, buf[0]);  /* prefix 0xf0 | value 0x05 */
}

/*
 * =============================================================================
 * QPACK String Encoding/Decoding Tests
 * =============================================================================
 */

static void test_qpack_encode_decode_string_literal(struct kunit *test)
{
	u8 buf[128];
	char decoded[128];
	const char *str = "content-type";
	size_t encoded_len, str_len, consumed;
	int ret;

	/* Encode without Huffman */
	ret = qpack_encode_string(str, strlen(str), false,
				  buf, sizeof(buf), &encoded_len);
	KUNIT_ASSERT_EQ(test, 0, ret);
	KUNIT_EXPECT_EQ(test, 0x00, buf[0] & 0x80);  /* H=0 */

	/* Decode */
	ret = qpack_decode_string(buf, encoded_len, decoded, sizeof(decoded),
				  &str_len, &consumed);
	KUNIT_ASSERT_EQ(test, 0, ret);
	KUNIT_EXPECT_EQ(test, strlen(str), str_len);
	KUNIT_EXPECT_EQ(test, 0, memcmp(decoded, str, str_len));
}

static void test_qpack_encode_decode_string_huffman(struct kunit *test)
{
	u8 buf[128];
	char decoded[128];
	const char *str = "hello";
	size_t encoded_len, str_len, consumed;
	int ret;

	/* Encode with Huffman */
	ret = qpack_encode_string(str, strlen(str), true,
				  buf, sizeof(buf), &encoded_len);
	KUNIT_ASSERT_EQ(test, 0, ret);
	KUNIT_EXPECT_EQ(test, 0x80, buf[0] & 0x80);  /* H=1 */

	/* Decode */
	ret = qpack_decode_string(buf, encoded_len, decoded, sizeof(decoded),
				  &str_len, &consumed);
	KUNIT_ASSERT_EQ(test, 0, ret);
	KUNIT_EXPECT_EQ(test, strlen(str), str_len);
	KUNIT_EXPECT_EQ(test, 0, memcmp(decoded, str, str_len));
}

static void test_qpack_encode_string_empty(struct kunit *test)
{
	u8 buf[128];
	size_t encoded_len;
	int ret;

	/* Encode empty string */
	ret = qpack_encode_string("", 0, false, buf, sizeof(buf), &encoded_len);
	KUNIT_ASSERT_EQ(test, 0, ret);
	KUNIT_EXPECT_EQ(test, 1UL, encoded_len);
	KUNIT_EXPECT_EQ(test, 0x00, buf[0]);
}

/*
 * =============================================================================
 * QPACK Huffman Encoding/Decoding Tests
 * =============================================================================
 */

static void test_qpack_huffman_encode_simple(struct kunit *test)
{
	u8 src[] = "www";
	u8 dst[32];
	size_t encoded_len;
	int ret;

	ret = qpack_huffman_encode(src, sizeof(src) - 1, dst, sizeof(dst),
				   &encoded_len);
	KUNIT_ASSERT_EQ(test, 0, ret);
	KUNIT_EXPECT_LT(test, encoded_len, sizeof(src) - 1);  /* Compressed */
}

static void test_qpack_huffman_decode_simple(struct kunit *test)
{
	const u8 src[] = "example";
	u8 encoded[32];
	u8 decoded[32];
	size_t encoded_len, decoded_len;
	int ret;

	/* Encode */
	ret = qpack_huffman_encode(src, sizeof(src) - 1, encoded, sizeof(encoded),
				   &encoded_len);
	KUNIT_ASSERT_EQ(test, 0, ret);

	/* Decode */
	ret = qpack_huffman_decode(encoded, encoded_len, decoded, sizeof(decoded),
				   &decoded_len);
	KUNIT_ASSERT_EQ(test, 0, ret);
	KUNIT_EXPECT_EQ(test, sizeof(src) - 1, decoded_len);
	KUNIT_EXPECT_EQ(test, 0, memcmp(decoded, src, decoded_len));
}

static void test_qpack_huffman_encoded_len(struct kunit *test)
{
	const u8 str1[] = "www";
	const u8 str2[] = "aaaaa";  /* All same character */
	size_t len1, len2;

	len1 = qpack_huffman_encoded_len(str1, sizeof(str1) - 1);
	len2 = qpack_huffman_encoded_len(str2, sizeof(str2) - 1);

	KUNIT_EXPECT_GT(test, len1, 0UL);
	KUNIT_EXPECT_GT(test, len2, 0UL);
}

/*
 * =============================================================================
 * QPACK Header List Tests
 * =============================================================================
 */

static void test_qpack_header_list_init(struct kunit *test)
{
	struct qpack_header_list list;

	qpack_header_list_init(&list);

	KUNIT_EXPECT_EQ(test, 0, (int)list.count);
	KUNIT_EXPECT_EQ(test, 0ULL, list.total_size);
	KUNIT_EXPECT_TRUE(test, list_empty(&list.headers));
}

static void test_qpack_header_list_add(struct kunit *test)
{
	struct qpack_header_list list;
	int ret;

	qpack_header_list_init(&list);

	ret = qpack_header_list_add(&list, "content-type", 12, "text/plain", 10, false);
	KUNIT_ASSERT_EQ(test, 0, ret);
	KUNIT_EXPECT_EQ(test, 1, (int)list.count);

	ret = qpack_header_list_add(&list, "content-length", 14, "100", 3, false);
	KUNIT_ASSERT_EQ(test, 0, ret);
	KUNIT_EXPECT_EQ(test, 2, (int)list.count);

	qpack_header_list_destroy(&list);
	KUNIT_EXPECT_EQ(test, 0, (int)list.count);
}

static void test_qpack_header_list_find(struct kunit *test)
{
	struct qpack_header_list list;
	struct qpack_header_field *found;

	qpack_header_list_init(&list);
	qpack_header_list_add(&list, "content-type", 12, "text/html", 9, false);
	qpack_header_list_add(&list, "x-custom", 8, "value", 5, false);

	/* Find existing header */
	found = qpack_header_list_find(&list, "content-type", 12);
	KUNIT_ASSERT_NOT_NULL(test, found);
	KUNIT_EXPECT_EQ(test, 9, (int)found->value_len);
	KUNIT_EXPECT_EQ(test, 0, memcmp(found->value, "text/html", 9));

	/* Find non-existing header */
	found = qpack_header_list_find(&list, "x-missing", 9);
	KUNIT_EXPECT_NULL(test, found);

	qpack_header_list_destroy(&list);
}

static void test_qpack_header_list_never_index(struct kunit *test)
{
	struct qpack_header_list list;
	struct qpack_header_field *hdr;

	qpack_header_list_init(&list);

	/* Add sensitive header with never_index=true */
	qpack_header_list_add(&list, "authorization", 13, "Bearer secret", 13, true);

	hdr = qpack_header_list_find(&list, "authorization", 13);
	KUNIT_ASSERT_NOT_NULL(test, hdr);
	KUNIT_EXPECT_TRUE(test, hdr->never_index);

	qpack_header_list_destroy(&list);
}

/*
 * =============================================================================
 * HTTP/3 Priority Tests (RFC 9218)
 * =============================================================================
 */

static void test_h3_priority_init(struct kunit *test)
{
	struct tquic_h3_priority pri;

	tquic_h3_priority_init(&pri);

	KUNIT_EXPECT_EQ(test, TQUIC_H3_PRIORITY_URGENCY_DEFAULT, (int)pri.urgency);
	KUNIT_EXPECT_FALSE(test, pri.incremental);
}

static void test_h3_priority_parse_header(struct kunit *test)
{
	struct tquic_h3_priority pri;
	int ret;

	/* Parse "u=2, i" */
	ret = tquic_h3_parse_priority_header("u=2, i", 6, &pri);
	KUNIT_ASSERT_EQ(test, 0, ret);
	KUNIT_EXPECT_EQ(test, 2, (int)pri.urgency);
	KUNIT_EXPECT_TRUE(test, pri.incremental);

	/* Parse "u=5" */
	ret = tquic_h3_parse_priority_header("u=5", 3, &pri);
	KUNIT_ASSERT_EQ(test, 0, ret);
	KUNIT_EXPECT_EQ(test, 5, (int)pri.urgency);
	KUNIT_EXPECT_FALSE(test, pri.incremental);

	/* Parse "i" (incremental only, default urgency) */
	ret = tquic_h3_parse_priority_header("i", 1, &pri);
	KUNIT_ASSERT_EQ(test, 0, ret);
	KUNIT_EXPECT_EQ(test, TQUIC_H3_PRIORITY_URGENCY_DEFAULT, (int)pri.urgency);
	KUNIT_EXPECT_TRUE(test, pri.incremental);
}

static void test_h3_priority_format_header(struct kunit *test)
{
	struct tquic_h3_priority pri;
	char buf[64];
	int ret;

	/* Format with urgency and incremental */
	pri.urgency = 2;
	pri.incremental = true;
	ret = tquic_h3_format_priority_header(&pri, buf, sizeof(buf));
	KUNIT_ASSERT_GT(test, ret, 0);
	/* Should contain "u=2" and "i" */
	KUNIT_EXPECT_NOT_NULL(test, strstr(buf, "u=2"));
	KUNIT_EXPECT_NOT_NULL(test, strstr(buf, "i"));

	/* Format with just urgency */
	pri.urgency = 5;
	pri.incremental = false;
	ret = tquic_h3_format_priority_header(&pri, buf, sizeof(buf));
	KUNIT_ASSERT_GT(test, ret, 0);
	KUNIT_EXPECT_NOT_NULL(test, strstr(buf, "u=5"));
}

static void test_h3_priority_urgency_bounds(struct kunit *test)
{
	struct tquic_h3_priority pri;
	int ret;

	/* Urgency 0 (highest) */
	ret = tquic_h3_parse_priority_header("u=0", 3, &pri);
	KUNIT_ASSERT_EQ(test, 0, ret);
	KUNIT_EXPECT_EQ(test, 0, (int)pri.urgency);

	/* Urgency 7 (lowest) */
	ret = tquic_h3_parse_priority_header("u=7", 3, &pri);
	KUNIT_ASSERT_EQ(test, 0, ret);
	KUNIT_EXPECT_EQ(test, 7, (int)pri.urgency);
}

/*
 * =============================================================================
 * Test Module Definition
 * =============================================================================
 */

static struct kunit_case http3_varint_test_cases[] = {
	KUNIT_CASE(test_h3_varint_size),
	KUNIT_CASE(test_h3_varint_encode_decode_1byte),
	KUNIT_CASE(test_h3_varint_encode_decode_2byte),
	KUNIT_CASE(test_h3_varint_encode_decode_4byte),
	KUNIT_CASE(test_h3_varint_encode_decode_8byte),
	KUNIT_CASE(test_h3_varint_buffer_too_small),
	KUNIT_CASE(test_h3_varint_decode_len),
	{}
};

static struct kunit_case http3_data_frame_test_cases[] = {
	KUNIT_CASE(test_h3_data_frame_write),
	KUNIT_CASE(test_h3_data_frame_parse),
	KUNIT_CASE(test_h3_data_frame_size),
	{}
};

static struct kunit_case http3_headers_frame_test_cases[] = {
	KUNIT_CASE(test_h3_headers_frame_write),
	KUNIT_CASE(test_h3_headers_frame_parse),
	{}
};

static struct kunit_case http3_settings_test_cases[] = {
	KUNIT_CASE(test_h3_settings_frame_write),
	KUNIT_CASE(test_h3_settings_frame_parse),
	KUNIT_CASE(test_h3_settings_init_defaults),
	KUNIT_CASE(test_h3_settings_encode_decode),
	{}
};

static struct kunit_case http3_goaway_frame_test_cases[] = {
	KUNIT_CASE(test_h3_goaway_frame_write),
	KUNIT_CASE(test_h3_goaway_frame_parse),
	KUNIT_CASE(test_h3_goaway_frame_large_id),
	{}
};

static struct kunit_case http3_push_frame_test_cases[] = {
	KUNIT_CASE(test_h3_max_push_id_frame_write),
	KUNIT_CASE(test_h3_max_push_id_frame_parse),
	KUNIT_CASE(test_h3_cancel_push_frame_write),
	KUNIT_CASE(test_h3_cancel_push_frame_parse),
	KUNIT_CASE(test_h3_push_promise_frame_write),
	KUNIT_CASE(test_h3_push_promise_frame_parse),
	{}
};

static struct kunit_case http3_validation_test_cases[] = {
	KUNIT_CASE(test_h3_frame_valid_on_control_stream),
	KUNIT_CASE(test_h3_frame_valid_on_request_stream),
	KUNIT_CASE(test_h3_frame_valid_on_push_stream),
	KUNIT_CASE(test_h3_frame_type_name),
	KUNIT_CASE(test_h3_error_name),
	KUNIT_CASE(test_h3_grease_identifier),
	{}
};

static struct kunit_case qpack_integer_test_cases[] = {
	KUNIT_CASE(test_qpack_encode_decode_integer_prefix5),
	KUNIT_CASE(test_qpack_encode_decode_integer_prefix7),
	KUNIT_CASE(test_qpack_encode_integer_with_prefix),
	{}
};

static struct kunit_case qpack_string_test_cases[] = {
	KUNIT_CASE(test_qpack_encode_decode_string_literal),
	KUNIT_CASE(test_qpack_encode_decode_string_huffman),
	KUNIT_CASE(test_qpack_encode_string_empty),
	{}
};

static struct kunit_case qpack_huffman_test_cases[] = {
	KUNIT_CASE(test_qpack_huffman_encode_simple),
	KUNIT_CASE(test_qpack_huffman_decode_simple),
	KUNIT_CASE(test_qpack_huffman_encoded_len),
	{}
};

static struct kunit_case qpack_header_list_test_cases[] = {
	KUNIT_CASE(test_qpack_header_list_init),
	KUNIT_CASE(test_qpack_header_list_add),
	KUNIT_CASE(test_qpack_header_list_find),
	KUNIT_CASE(test_qpack_header_list_never_index),
	{}
};

static struct kunit_case http3_priority_test_cases[] = {
	KUNIT_CASE(test_h3_priority_init),
	KUNIT_CASE(test_h3_priority_parse_header),
	KUNIT_CASE(test_h3_priority_format_header),
	KUNIT_CASE(test_h3_priority_urgency_bounds),
	{}
};

static struct kunit_suite http3_varint_test_suite = {
	.name = "http3_varint",
	.test_cases = http3_varint_test_cases,
};

static struct kunit_suite http3_data_frame_test_suite = {
	.name = "http3_data_frame",
	.test_cases = http3_data_frame_test_cases,
};

static struct kunit_suite http3_headers_frame_test_suite = {
	.name = "http3_headers_frame",
	.test_cases = http3_headers_frame_test_cases,
};

static struct kunit_suite http3_settings_test_suite = {
	.name = "http3_settings",
	.test_cases = http3_settings_test_cases,
};

static struct kunit_suite http3_goaway_frame_test_suite = {
	.name = "http3_goaway_frame",
	.test_cases = http3_goaway_frame_test_cases,
};

static struct kunit_suite http3_push_frame_test_suite = {
	.name = "http3_push_frame",
	.test_cases = http3_push_frame_test_cases,
};

static struct kunit_suite http3_validation_test_suite = {
	.name = "http3_validation",
	.test_cases = http3_validation_test_cases,
};

static struct kunit_suite qpack_integer_test_suite = {
	.name = "qpack_integer",
	.test_cases = qpack_integer_test_cases,
};

static struct kunit_suite qpack_string_test_suite = {
	.name = "qpack_string",
	.test_cases = qpack_string_test_cases,
};

static struct kunit_suite qpack_huffman_test_suite = {
	.name = "qpack_huffman",
	.test_cases = qpack_huffman_test_cases,
};

static struct kunit_suite qpack_header_list_test_suite = {
	.name = "qpack_header_list",
	.test_cases = qpack_header_list_test_cases,
};

static struct kunit_suite http3_priority_test_suite = {
	.name = "http3_priority",
	.test_cases = http3_priority_test_cases,
};

kunit_test_suites(
	&http3_varint_test_suite,
	&http3_data_frame_test_suite,
	&http3_headers_frame_test_suite,
	&http3_settings_test_suite,
	&http3_goaway_frame_test_suite,
	&http3_push_frame_test_suite,
	&http3_validation_test_suite,
	&qpack_integer_test_suite,
	&qpack_string_test_suite,
	&qpack_huffman_test_suite,
	&qpack_header_list_test_suite,
	&http3_priority_test_suite
);

MODULE_DESCRIPTION("TQUIC HTTP/3 Unit Tests");
MODULE_AUTHOR("Linux Foundation");
MODULE_LICENSE("GPL");
