// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Reliable Stream Reset - KUnit Tests
 *
 * Copyright (c) 2026 Linux Foundation
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Tests for RESET_STREAM_AT frame encoding/decoding and handling
 * as defined in draft-ietf-quic-reliable-stream-reset-07.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <net/tquic.h>

#include "../core/reliable_reset.h"
#include "../core/transport_params.h"

/*
 * =============================================================================
 * Frame Encoding/Decoding Tests
 * =============================================================================
 */

/*
 * Test: Calculate size of RESET_STREAM_AT frame
 */
static void test_reset_stream_at_size(struct kunit *test)
{
	struct tquic_reset_stream_at frame;
	size_t size;

	/* Small values - all 1-byte varints */
	frame.stream_id = 4;
	frame.error_code = 1;
	frame.final_size = 100;
	frame.reliable_size = 50;

	size = tquic_reset_stream_at_size(&frame);
	/* 1 (type) + 1 (stream_id) + 1 (error) + 1 (final) + 1 (reliable) = 5 */
	KUNIT_EXPECT_EQ(test, size, (size_t)5);

	/* Larger values requiring multi-byte varints */
	frame.stream_id = 0x4000;  /* 2-byte varint */
	frame.error_code = 0x100;  /* 2-byte varint */
	frame.final_size = 0x40000000;  /* 4-byte varint */
	frame.reliable_size = 0x3FFFFFFF;  /* 4-byte varint */

	size = tquic_reset_stream_at_size(&frame);
	/* 1 (type) + 2 + 2 + 4 + 4 = 13 */
	KUNIT_EXPECT_EQ(test, size, (size_t)13);
}

/*
 * Test: Encode RESET_STREAM_AT frame with small values
 */
static void test_encode_reset_stream_at_small(struct kunit *test)
{
	struct tquic_reset_stream_at frame;
	u8 buf[64];
	ssize_t len;

	frame.stream_id = 4;
	frame.error_code = 0x42;
	frame.final_size = 1000;
	frame.reliable_size = 500;

	len = tquic_encode_reset_stream_at(&frame, buf, sizeof(buf));
	KUNIT_ASSERT_GT(test, len, (ssize_t)0);

	/* Verify frame type */
	KUNIT_EXPECT_EQ(test, buf[0], (u8)TQUIC_FRAME_RESET_STREAM_AT);
}

/*
 * Test: Encode RESET_STREAM_AT frame with large values
 */
static void test_encode_reset_stream_at_large(struct kunit *test)
{
	struct tquic_reset_stream_at frame;
	u8 buf[64];
	ssize_t len;

	frame.stream_id = 0x123456789ULL;  /* 8-byte varint */
	frame.error_code = 0xDEADBEEF;
	frame.final_size = 0x100000000ULL;  /* 8-byte varint */
	frame.reliable_size = 0x80000000ULL;  /* 8-byte varint */

	len = tquic_encode_reset_stream_at(&frame, buf, sizeof(buf));
	KUNIT_ASSERT_GT(test, len, (ssize_t)0);

	/* Verify frame type */
	KUNIT_EXPECT_EQ(test, buf[0], (u8)TQUIC_FRAME_RESET_STREAM_AT);
}

/*
 * Test: Encode fails when reliable_size > final_size
 */
static void test_encode_reset_stream_at_invalid(struct kunit *test)
{
	struct tquic_reset_stream_at frame;
	u8 buf[64];
	ssize_t len;

	frame.stream_id = 4;
	frame.error_code = 1;
	frame.final_size = 100;
	frame.reliable_size = 200;  /* Invalid: > final_size */

	len = tquic_encode_reset_stream_at(&frame, buf, sizeof(buf));
	KUNIT_EXPECT_LT(test, len, (ssize_t)0);
}

/*
 * Test: Encode fails when buffer too small
 */
static void test_encode_reset_stream_at_buffer_too_small(struct kunit *test)
{
	struct tquic_reset_stream_at frame;
	u8 buf[3];  /* Too small */
	ssize_t len;

	frame.stream_id = 4;
	frame.error_code = 1;
	frame.final_size = 100;
	frame.reliable_size = 50;

	len = tquic_encode_reset_stream_at(&frame, buf, sizeof(buf));
	KUNIT_EXPECT_EQ(test, len, (ssize_t)-ENOSPC);
}

/*
 * Test: Decode RESET_STREAM_AT frame
 */
static void test_decode_reset_stream_at(struct kunit *test)
{
	struct tquic_reset_stream_at original, decoded;
	u8 buf[64];
	ssize_t encoded_len, decoded_len;

	/* Encode a frame */
	original.stream_id = 16;
	original.error_code = 0x100;
	original.final_size = 5000;
	original.reliable_size = 2500;

	encoded_len = tquic_encode_reset_stream_at(&original, buf, sizeof(buf));
	KUNIT_ASSERT_GT(test, encoded_len, (ssize_t)0);

	/* Decode (skip the type byte) */
	decoded_len = tquic_decode_reset_stream_at(buf + 1, encoded_len - 1,
						   &decoded);
	KUNIT_ASSERT_GT(test, decoded_len, (ssize_t)0);

	/* Verify decoded values match */
	KUNIT_EXPECT_EQ(test, decoded.stream_id, original.stream_id);
	KUNIT_EXPECT_EQ(test, decoded.error_code, original.error_code);
	KUNIT_EXPECT_EQ(test, decoded.final_size, original.final_size);
	KUNIT_EXPECT_EQ(test, decoded.reliable_size, original.reliable_size);
}

/*
 * Test: Decode fails when reliable_size > final_size
 */
static void test_decode_reset_stream_at_invalid_sizes(struct kunit *test)
{
	/*
	 * Manually craft a buffer with invalid reliable_size > final_size.
	 * This tests the protocol validation in the decoder.
	 *
	 * Frame format (after type byte):
	 *   Stream ID: 0x04 (1 byte)
	 *   Error Code: 0x01 (1 byte)
	 *   Final Size: 0x32 = 50 (1 byte)
	 *   Reliable Size: 0x64 = 100 (1 byte) - INVALID: > final_size
	 */
	u8 buf[] = { 0x04, 0x01, 0x32, 0x64 };
	struct tquic_reset_stream_at decoded;
	ssize_t len;

	len = tquic_decode_reset_stream_at(buf, sizeof(buf), &decoded);
	KUNIT_EXPECT_EQ(test, len, (ssize_t)-EPROTO);
}

/*
 * Test: Decode fails with truncated input
 */
static void test_decode_reset_stream_at_truncated(struct kunit *test)
{
	/* Only 2 bytes - not enough for complete frame */
	u8 buf[] = { 0x04, 0x01 };
	struct tquic_reset_stream_at decoded;
	ssize_t len;

	len = tquic_decode_reset_stream_at(buf, sizeof(buf), &decoded);
	KUNIT_EXPECT_LT(test, len, (ssize_t)0);
}

/*
 * Test: Encode and decode round-trip with various values
 */
static void test_encode_decode_roundtrip(struct kunit *test)
{
	struct tquic_reset_stream_at original, decoded;
	u8 buf[64];
	ssize_t encoded_len, decoded_len;

	/* Test case 1: Zero values */
	original.stream_id = 0;
	original.error_code = 0;
	original.final_size = 0;
	original.reliable_size = 0;

	encoded_len = tquic_encode_reset_stream_at(&original, buf, sizeof(buf));
	KUNIT_ASSERT_GT(test, encoded_len, (ssize_t)0);

	decoded_len = tquic_decode_reset_stream_at(buf + 1, encoded_len - 1,
						   &decoded);
	KUNIT_ASSERT_GT(test, decoded_len, (ssize_t)0);
	KUNIT_EXPECT_EQ(test, decoded.stream_id, original.stream_id);
	KUNIT_EXPECT_EQ(test, decoded.final_size, original.final_size);
	KUNIT_EXPECT_EQ(test, decoded.reliable_size, original.reliable_size);

	/* Test case 2: reliable_size == final_size (entire stream reliable) */
	original.stream_id = 8;
	original.error_code = 0xFF;
	original.final_size = 10000;
	original.reliable_size = 10000;

	encoded_len = tquic_encode_reset_stream_at(&original, buf, sizeof(buf));
	KUNIT_ASSERT_GT(test, encoded_len, (ssize_t)0);

	decoded_len = tquic_decode_reset_stream_at(buf + 1, encoded_len - 1,
						   &decoded);
	KUNIT_ASSERT_GT(test, decoded_len, (ssize_t)0);
	KUNIT_EXPECT_EQ(test, decoded.reliable_size, original.reliable_size);

	/* Test case 3: Large stream ID (server-initiated bidi) */
	original.stream_id = 0xFFFFFFFFFFFFFFF;  /* Very large ID */
	original.error_code = 0xABCDEF;
	original.final_size = 0x3FFFFFFFFFFFF;
	original.reliable_size = 0x1FFFFFFFFFFFF;

	encoded_len = tquic_encode_reset_stream_at(&original, buf, sizeof(buf));
	KUNIT_ASSERT_GT(test, encoded_len, (ssize_t)0);

	decoded_len = tquic_decode_reset_stream_at(buf + 1, encoded_len - 1,
						   &decoded);
	KUNIT_ASSERT_GT(test, decoded_len, (ssize_t)0);
	KUNIT_EXPECT_EQ(test, decoded.stream_id, original.stream_id);
}

/*
 * =============================================================================
 * Transport Parameter Tests
 * =============================================================================
 */

/*
 * Test: Transport parameter encoding/decoding
 */
static void test_tp_reliable_stream_reset_encode_decode(struct kunit *test)
{
	struct tquic_transport_params original, decoded;
	u8 *buf;
	ssize_t encoded_len;
	int ret;

	buf = kunit_kzalloc(test, 512, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buf);

	tquic_tp_init(&original);
	original.initial_scid.len = 8;
	original.initial_scid_present = true;

	/* Enable reliable stream reset */
	original.reliable_stream_reset = true;

	/* Encode */
	encoded_len = tquic_tp_encode(&original, false, buf, 512);
	KUNIT_ASSERT_GT(test, encoded_len, (ssize_t)0);

	/* Decode */
	ret = tquic_tp_decode(buf, encoded_len, false, &decoded);
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Verify */
	KUNIT_EXPECT_TRUE(test, decoded.reliable_stream_reset);
}

/*
 * Test: Transport parameter disabled by default
 */
static void test_tp_reliable_stream_reset_default_disabled(struct kunit *test)
{
	struct tquic_transport_params params;

	tquic_tp_init(&params);
	KUNIT_EXPECT_FALSE(test, params.reliable_stream_reset);
}

/*
 * Test: Negotiation - both peers support
 */
static void test_tp_negotiate_reliable_reset_both_support(struct kunit *test)
{
	struct tquic_transport_params local, remote;
	struct tquic_negotiated_params result;
	int ret;

	tquic_tp_init(&local);
	tquic_tp_init(&remote);

	local.reliable_stream_reset = true;
	remote.reliable_stream_reset = true;

	ret = tquic_tp_negotiate(&local, &remote, &result);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_TRUE(test, result.reliable_reset_enabled);
}

/*
 * Test: Negotiation - only local supports
 */
static void test_tp_negotiate_reliable_reset_local_only(struct kunit *test)
{
	struct tquic_transport_params local, remote;
	struct tquic_negotiated_params result;
	int ret;

	tquic_tp_init(&local);
	tquic_tp_init(&remote);

	local.reliable_stream_reset = true;
	remote.reliable_stream_reset = false;

	ret = tquic_tp_negotiate(&local, &remote, &result);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_FALSE(test, result.reliable_reset_enabled);
}

/*
 * Test: Negotiation - only remote supports
 */
static void test_tp_negotiate_reliable_reset_remote_only(struct kunit *test)
{
	struct tquic_transport_params local, remote;
	struct tquic_negotiated_params result;
	int ret;

	tquic_tp_init(&local);
	tquic_tp_init(&remote);

	local.reliable_stream_reset = false;
	remote.reliable_stream_reset = true;

	ret = tquic_tp_negotiate(&local, &remote, &result);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_FALSE(test, result.reliable_reset_enabled);
}

/*
 * Test: Negotiation - neither supports
 */
static void test_tp_negotiate_reliable_reset_neither(struct kunit *test)
{
	struct tquic_transport_params local, remote;
	struct tquic_negotiated_params result;
	int ret;

	tquic_tp_init(&local);
	tquic_tp_init(&remote);

	local.reliable_stream_reset = false;
	remote.reliable_stream_reset = false;

	ret = tquic_tp_negotiate(&local, &remote, &result);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_FALSE(test, result.reliable_reset_enabled);
}

/*
 * Test: Set reliable reset support helper
 */
static void test_set_reliable_reset_support(struct kunit *test)
{
	struct tquic_transport_params params;

	tquic_tp_init(&params);
	KUNIT_EXPECT_FALSE(test, params.reliable_stream_reset);

	tquic_set_reliable_reset_support(&params, true);
	KUNIT_EXPECT_TRUE(test, params.reliable_stream_reset);

	tquic_set_reliable_reset_support(&params, false);
	KUNIT_EXPECT_FALSE(test, params.reliable_stream_reset);
}

/*
 * =============================================================================
 * Frame Type Constant Tests
 * =============================================================================
 */

/*
 * Test: Frame type constant value
 */
static void test_frame_type_constant(struct kunit *test)
{
	/* Verify RESET_STREAM_AT frame type is 0x24 per draft */
	KUNIT_EXPECT_EQ(test, TQUIC_FRAME_RESET_STREAM_AT, 0x24);
}

/*
 * Test: Transport parameter constant value
 */
static void test_transport_param_constant(struct kunit *test)
{
	/* Verify reliable_stream_reset TP ID is 0x17cd per draft */
	KUNIT_EXPECT_EQ(test, TQUIC_TP_RELIABLE_STREAM_RESET, 0x17cd);
}

/*
 * =============================================================================
 * Edge Case Tests
 * =============================================================================
 */

/*
 * Test: reliable_size exactly equals final_size
 */
static void test_reliable_size_equals_final_size(struct kunit *test)
{
	struct tquic_reset_stream_at frame;
	u8 buf[64];
	ssize_t len;

	frame.stream_id = 4;
	frame.error_code = 1;
	frame.final_size = 1000;
	frame.reliable_size = 1000;  /* Equal to final_size - valid */

	len = tquic_encode_reset_stream_at(&frame, buf, sizeof(buf));
	KUNIT_ASSERT_GT(test, len, (ssize_t)0);
}

/*
 * Test: reliable_size is zero
 */
static void test_reliable_size_zero(struct kunit *test)
{
	struct tquic_reset_stream_at frame;
	u8 buf[64];
	ssize_t len;

	frame.stream_id = 4;
	frame.error_code = 1;
	frame.final_size = 1000;
	frame.reliable_size = 0;  /* Zero reliable - immediate reset */

	len = tquic_encode_reset_stream_at(&frame, buf, sizeof(buf));
	KUNIT_ASSERT_GT(test, len, (ssize_t)0);
}

/*
 * Test: Maximum varint values
 */
static void test_max_varint_values(struct kunit *test)
{
	struct tquic_reset_stream_at frame, decoded;
	u8 buf[64];
	ssize_t encoded_len, decoded_len;

	/* Maximum 62-bit varint value */
	u64 max_varint = 0x3FFFFFFFFFFFFFFFULL;

	frame.stream_id = max_varint;
	frame.error_code = max_varint;
	frame.final_size = max_varint;
	frame.reliable_size = max_varint;

	encoded_len = tquic_encode_reset_stream_at(&frame, buf, sizeof(buf));
	KUNIT_ASSERT_GT(test, encoded_len, (ssize_t)0);

	decoded_len = tquic_decode_reset_stream_at(buf + 1, encoded_len - 1,
						   &decoded);
	KUNIT_ASSERT_GT(test, decoded_len, (ssize_t)0);

	KUNIT_EXPECT_EQ(test, decoded.stream_id, max_varint);
	KUNIT_EXPECT_EQ(test, decoded.error_code, max_varint);
	KUNIT_EXPECT_EQ(test, decoded.final_size, max_varint);
	KUNIT_EXPECT_EQ(test, decoded.reliable_size, max_varint);
}

/*
 * =============================================================================
 * Test Suite Registration
 * =============================================================================
 */

static struct kunit_case reliable_reset_test_cases[] = {
	/* Encoding/Decoding tests */
	KUNIT_CASE(test_reset_stream_at_size),
	KUNIT_CASE(test_encode_reset_stream_at_small),
	KUNIT_CASE(test_encode_reset_stream_at_large),
	KUNIT_CASE(test_encode_reset_stream_at_invalid),
	KUNIT_CASE(test_encode_reset_stream_at_buffer_too_small),
	KUNIT_CASE(test_decode_reset_stream_at),
	KUNIT_CASE(test_decode_reset_stream_at_invalid_sizes),
	KUNIT_CASE(test_decode_reset_stream_at_truncated),
	KUNIT_CASE(test_encode_decode_roundtrip),

	/* Transport parameter tests */
	KUNIT_CASE(test_tp_reliable_stream_reset_encode_decode),
	KUNIT_CASE(test_tp_reliable_stream_reset_default_disabled),
	KUNIT_CASE(test_tp_negotiate_reliable_reset_both_support),
	KUNIT_CASE(test_tp_negotiate_reliable_reset_local_only),
	KUNIT_CASE(test_tp_negotiate_reliable_reset_remote_only),
	KUNIT_CASE(test_tp_negotiate_reliable_reset_neither),
	KUNIT_CASE(test_set_reliable_reset_support),

	/* Constant value tests */
	KUNIT_CASE(test_frame_type_constant),
	KUNIT_CASE(test_transport_param_constant),

	/* Edge case tests */
	KUNIT_CASE(test_reliable_size_equals_final_size),
	KUNIT_CASE(test_reliable_size_zero),
	KUNIT_CASE(test_max_varint_values),
	{}
};

static struct kunit_suite reliable_reset_test_suite = {
	.name = "tquic-reliable-reset",
	.test_cases = reliable_reset_test_cases,
};

kunit_test_suites(&reliable_reset_test_suite);

MODULE_AUTHOR("Linux Foundation");
MODULE_DESCRIPTION("TQUIC Reliable Stream Reset KUnit Tests");
MODULE_LICENSE("GPL");
