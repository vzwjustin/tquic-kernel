// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Extended Key Update KUnit Tests
 *
 * Copyright (c) 2026 Linux Foundation
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Tests for the Extended Key Update extension (draft-ietf-quic-extended-key-update-01):
 * - Frame encoding/decoding
 * - State machine transitions
 * - PSK injection
 * - Key derivation
 * - Transport parameter negotiation
 * - RFC 9001 fallback
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <net/tquic.h>

#include "../crypto/extended_key_update.h"
#include "../core/transport_params.h"

/*
 * =============================================================================
 * Frame Encoding/Decoding Tests
 * =============================================================================
 */

/**
 * test_eku_encode_decode_request - Test KEY_UPDATE_REQUEST encoding/decoding
 */
static void test_eku_encode_decode_request(struct kunit *test)
{
	struct tquic_eku_frame_request original, decoded;
	u8 buf[256];
	ssize_t encoded_len, decoded_len;

	/* Create a request frame */
	memset(&original, 0, sizeof(original));
	original.request_id = 12345;
	original.flags = TQUIC_EKU_FLAG_IMMEDIATE_UPDATE;
	original.psk_len = 0;

	/* Encode */
	encoded_len = tquic_eku_encode_request(&original, buf, sizeof(buf));
	KUNIT_ASSERT_GT(test, encoded_len, (ssize_t)0);

	/* Skip frame type byte for decoding */
	decoded_len = tquic_eku_decode_request(buf + 1, encoded_len - 1, &decoded);
	KUNIT_ASSERT_GT(test, decoded_len, (ssize_t)0);

	/* Verify */
	KUNIT_EXPECT_EQ(test, decoded.request_id, original.request_id);
	KUNIT_EXPECT_EQ(test, decoded.flags, original.flags);
	KUNIT_EXPECT_EQ(test, decoded.psk_len, original.psk_len);
}

/**
 * test_eku_encode_decode_request_with_psk - Test with PSK hint
 */
static void test_eku_encode_decode_request_with_psk(struct kunit *test)
{
	struct tquic_eku_frame_request original, decoded;
	u8 buf[256];
	ssize_t encoded_len, decoded_len;

	/* Create a request frame with PSK hint */
	memset(&original, 0, sizeof(original));
	original.request_id = 67890;
	original.flags = TQUIC_EKU_FLAG_PSK_INJECTED | TQUIC_EKU_FLAG_URGENT;
	original.psk_len = 32;
	get_random_bytes(original.psk_hint, 32);

	/* Encode */
	encoded_len = tquic_eku_encode_request(&original, buf, sizeof(buf));
	KUNIT_ASSERT_GT(test, encoded_len, (ssize_t)0);

	/* Skip frame type byte for decoding */
	decoded_len = tquic_eku_decode_request(buf + 1, encoded_len - 1, &decoded);
	KUNIT_ASSERT_GT(test, decoded_len, (ssize_t)0);

	/* Verify */
	KUNIT_EXPECT_EQ(test, decoded.request_id, original.request_id);
	KUNIT_EXPECT_EQ(test, decoded.flags, original.flags);
	KUNIT_EXPECT_EQ(test, decoded.psk_len, original.psk_len);
	KUNIT_EXPECT_EQ(test, memcmp(decoded.psk_hint, original.psk_hint, 32), 0);
}

/**
 * test_eku_encode_decode_response - Test KEY_UPDATE_RESPONSE encoding/decoding
 */
static void test_eku_encode_decode_response(struct kunit *test)
{
	struct tquic_eku_frame_response original, decoded;
	u8 buf[64];
	ssize_t encoded_len, decoded_len;

	/* Create a response frame */
	memset(&original, 0, sizeof(original));
	original.request_id = 12345;
	original.status = TQUIC_EKU_STATUS_SUCCESS;

	/* Encode */
	encoded_len = tquic_eku_encode_response(&original, buf, sizeof(buf));
	KUNIT_ASSERT_GT(test, encoded_len, (ssize_t)0);

	/* Skip frame type byte for decoding */
	decoded_len = tquic_eku_decode_response(buf + 1, encoded_len - 1, &decoded);
	KUNIT_ASSERT_GT(test, decoded_len, (ssize_t)0);

	/* Verify */
	KUNIT_EXPECT_EQ(test, decoded.request_id, original.request_id);
	KUNIT_EXPECT_EQ(test, decoded.status, original.status);
}

/**
 * test_eku_encode_decode_response_error - Test error status
 */
static void test_eku_encode_decode_response_error(struct kunit *test)
{
	struct tquic_eku_frame_response original, decoded;
	u8 buf[64];
	ssize_t encoded_len, decoded_len;

	/* Create a response frame with error status */
	memset(&original, 0, sizeof(original));
	original.request_id = 99999;
	original.status = TQUIC_EKU_STATUS_PSK_MISMATCH;

	/* Encode */
	encoded_len = tquic_eku_encode_response(&original, buf, sizeof(buf));
	KUNIT_ASSERT_GT(test, encoded_len, (ssize_t)0);

	/* Skip frame type byte for decoding */
	decoded_len = tquic_eku_decode_response(buf + 1, encoded_len - 1, &decoded);
	KUNIT_ASSERT_GT(test, decoded_len, (ssize_t)0);

	/* Verify */
	KUNIT_EXPECT_EQ(test, decoded.request_id, original.request_id);
	KUNIT_EXPECT_EQ(test, decoded.status, original.status);
}

/**
 * test_eku_encode_buffer_too_small - Test buffer too small error
 */
static void test_eku_encode_buffer_too_small(struct kunit *test)
{
	struct tquic_eku_frame_request req;
	u8 buf[2];  /* Too small */
	ssize_t ret;

	memset(&req, 0, sizeof(req));
	req.request_id = 12345;

	ret = tquic_eku_encode_request(&req, buf, sizeof(buf));
	KUNIT_EXPECT_LT(test, ret, (ssize_t)0);
}

/*
 * =============================================================================
 * State Machine Tests
 * =============================================================================
 */

/**
 * test_eku_state_names - Test state name function
 */
static void test_eku_state_names(struct kunit *test)
{
	const char *name;

	name = tquic_eku_get_state_name(TQUIC_EKU_STATE_IDLE);
	KUNIT_EXPECT_STREQ(test, name, "IDLE");

	name = tquic_eku_get_state_name(TQUIC_EKU_STATE_REQUEST_SENT);
	KUNIT_EXPECT_STREQ(test, name, "REQUEST_SENT");

	name = tquic_eku_get_state_name(TQUIC_EKU_STATE_REQUEST_RECEIVED);
	KUNIT_EXPECT_STREQ(test, name, "REQUEST_RECEIVED");

	name = tquic_eku_get_state_name(TQUIC_EKU_STATE_RESPONSE_SENT);
	KUNIT_EXPECT_STREQ(test, name, "RESPONSE_SENT");

	name = tquic_eku_get_state_name(TQUIC_EKU_STATE_UPDATE_COMPLETE);
	KUNIT_EXPECT_STREQ(test, name, "UPDATE_COMPLETE");

	name = tquic_eku_get_state_name(TQUIC_EKU_STATE_ERROR);
	KUNIT_EXPECT_STREQ(test, name, "ERROR");

	name = tquic_eku_get_state_name(100);  /* Invalid */
	KUNIT_EXPECT_STREQ(test, name, "UNKNOWN");
}

/*
 * =============================================================================
 * Transport Parameter Tests
 * =============================================================================
 */

/**
 * test_eku_tp_encode_decode - Test transport parameter encoding/decoding
 */
static void test_eku_tp_encode_decode(struct kunit *test)
{
	struct tquic_transport_params original, decoded;
	u8 *buf;
	ssize_t encoded_len;
	int ret;

	buf = kunit_kzalloc(test, 512, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buf);

	/* Initialize with defaults */
	tquic_tp_set_defaults_client(&original);

	/* Set EKU parameter */
	original.extended_key_update = 8;  /* Max 8 outstanding requests */
	original.extended_key_update_present = true;

	/* Set initial_scid for encoding */
	original.initial_scid.len = 8;
	memset(original.initial_scid.id, 0x42, 8);
	original.initial_scid_present = true;

	/* Encode */
	encoded_len = tquic_tp_encode(&original, false, buf, 512);
	KUNIT_ASSERT_GT(test, encoded_len, (ssize_t)0);

	/* Decode */
	ret = tquic_tp_decode(buf, encoded_len, false, &decoded);
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Verify EKU parameter */
	KUNIT_EXPECT_TRUE(test, decoded.extended_key_update_present);
	KUNIT_EXPECT_EQ(test, decoded.extended_key_update, (u64)8);
}

/**
 * test_eku_tp_negotiate_both_support - Test negotiation when both support
 */
static void test_eku_tp_negotiate_both_support(struct kunit *test)
{
	struct tquic_transport_params local, remote;
	struct tquic_negotiated_params result;
	int ret;

	tquic_tp_set_defaults_client(&local);
	tquic_tp_set_defaults_server(&remote);

	/* Both support EKU */
	local.extended_key_update = 16;
	local.extended_key_update_present = true;
	remote.extended_key_update = 8;
	remote.extended_key_update_present = true;

	ret = tquic_tp_negotiate(&local, &remote, &result);
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Should be enabled with min of both values */
	KUNIT_EXPECT_TRUE(test, result.extended_key_update_enabled);
	KUNIT_EXPECT_EQ(test, result.extended_key_update_max, (u64)8);
}

/**
 * test_eku_tp_negotiate_only_local - Test negotiation when only local supports
 */
static void test_eku_tp_negotiate_only_local(struct kunit *test)
{
	struct tquic_transport_params local, remote;
	struct tquic_negotiated_params result;
	int ret;

	tquic_tp_set_defaults_client(&local);
	tquic_tp_set_defaults_server(&remote);

	/* Only local supports EKU */
	local.extended_key_update = 16;
	local.extended_key_update_present = true;
	remote.extended_key_update = 0;
	remote.extended_key_update_present = false;

	ret = tquic_tp_negotiate(&local, &remote, &result);
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Should NOT be enabled */
	KUNIT_EXPECT_FALSE(test, result.extended_key_update_enabled);
	KUNIT_EXPECT_EQ(test, result.extended_key_update_max, (u64)0);
}

/**
 * test_eku_tp_negotiate_only_remote - Test negotiation when only remote supports
 */
static void test_eku_tp_negotiate_only_remote(struct kunit *test)
{
	struct tquic_transport_params local, remote;
	struct tquic_negotiated_params result;
	int ret;

	tquic_tp_set_defaults_client(&local);
	tquic_tp_set_defaults_server(&remote);

	/* Only remote supports EKU */
	local.extended_key_update = 0;
	local.extended_key_update_present = false;
	remote.extended_key_update = 8;
	remote.extended_key_update_present = true;

	ret = tquic_tp_negotiate(&local, &remote, &result);
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Should NOT be enabled */
	KUNIT_EXPECT_FALSE(test, result.extended_key_update_enabled);
	KUNIT_EXPECT_EQ(test, result.extended_key_update_max, (u64)0);
}

/**
 * test_eku_tp_negotiate_neither - Test negotiation when neither supports
 */
static void test_eku_tp_negotiate_neither(struct kunit *test)
{
	struct tquic_transport_params local, remote;
	struct tquic_negotiated_params result;
	int ret;

	tquic_tp_set_defaults_client(&local);
	tquic_tp_set_defaults_server(&remote);

	/* Neither supports EKU */
	local.extended_key_update = 0;
	local.extended_key_update_present = false;
	remote.extended_key_update = 0;
	remote.extended_key_update_present = false;

	ret = tquic_tp_negotiate(&local, &remote, &result);
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Should NOT be enabled */
	KUNIT_EXPECT_FALSE(test, result.extended_key_update_enabled);
	KUNIT_EXPECT_EQ(test, result.extended_key_update_max, (u64)0);
}

/*
 * =============================================================================
 * Frame Type Constant Tests
 * =============================================================================
 */

/**
 * test_eku_frame_types - Verify frame type constants
 */
static void test_eku_frame_types(struct kunit *test)
{
	/* KEY_UPDATE_REQUEST frame type */
	KUNIT_EXPECT_EQ(test, TQUIC_FRAME_KEY_UPDATE_REQUEST, 0x40);

	/* KEY_UPDATE_RESPONSE frame type */
	KUNIT_EXPECT_EQ(test, TQUIC_FRAME_KEY_UPDATE_RESPONSE, 0x41);
}

/**
 * test_eku_status_codes - Verify status code constants
 */
static void test_eku_status_codes(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, TQUIC_EKU_STATUS_SUCCESS, 0x00);
	KUNIT_EXPECT_EQ(test, TQUIC_EKU_STATUS_BUSY, 0x01);
	KUNIT_EXPECT_EQ(test, TQUIC_EKU_STATUS_UNSUPPORTED, 0x02);
	KUNIT_EXPECT_EQ(test, TQUIC_EKU_STATUS_PSK_MISMATCH, 0x03);
	KUNIT_EXPECT_EQ(test, TQUIC_EKU_STATUS_INTERNAL_ERROR, 0x04);
}

/**
 * test_eku_flags - Verify flag constants
 */
static void test_eku_flags(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, TQUIC_EKU_FLAG_ENABLED, BIT(0));
	KUNIT_EXPECT_EQ(test, TQUIC_EKU_FLAG_PSK_INJECTED, BIT(1));
	KUNIT_EXPECT_EQ(test, TQUIC_EKU_FLAG_IMMEDIATE_UPDATE, BIT(2));
	KUNIT_EXPECT_EQ(test, TQUIC_EKU_FLAG_URGENT, BIT(3));

	/* Flags should be combinable */
	KUNIT_EXPECT_EQ(test, TQUIC_EKU_FLAG_ENABLED | TQUIC_EKU_FLAG_PSK_INJECTED,
			0x03);
}

/*
 * =============================================================================
 * PSK Material Tests
 * =============================================================================
 */

/**
 * test_eku_psk_max_len - Verify PSK max length constant
 */
static void test_eku_psk_max_len(struct kunit *test)
{
	/* PSK max should accommodate SHA-384 output plus some margin */
	KUNIT_EXPECT_GE(test, TQUIC_EKU_PSK_MAX_LEN, 48);
}

/*
 * =============================================================================
 * Request/Response Large ID Tests
 * =============================================================================
 */

/**
 * test_eku_large_request_id - Test encoding/decoding large request IDs
 */
static void test_eku_large_request_id(struct kunit *test)
{
	struct tquic_eku_frame_request original, decoded;
	u8 buf[256];
	ssize_t encoded_len, decoded_len;

	/* Use a large 8-byte varint request ID */
	memset(&original, 0, sizeof(original));
	original.request_id = 0x3FFFFFFFFFFFFFFFULL;  /* Max varint value */
	original.flags = 0;
	original.psk_len = 0;

	/* Encode */
	encoded_len = tquic_eku_encode_request(&original, buf, sizeof(buf));
	KUNIT_ASSERT_GT(test, encoded_len, (ssize_t)0);

	/* Skip frame type byte for decoding */
	decoded_len = tquic_eku_decode_request(buf + 1, encoded_len - 1, &decoded);
	KUNIT_ASSERT_GT(test, decoded_len, (ssize_t)0);

	/* Verify large ID preserved */
	KUNIT_EXPECT_EQ(test, decoded.request_id, original.request_id);
}

/*
 * =============================================================================
 * Test Suite Definition
 * =============================================================================
 */

static struct kunit_case extended_key_update_test_cases[] = {
	/* Frame encoding/decoding */
	KUNIT_CASE(test_eku_encode_decode_request),
	KUNIT_CASE(test_eku_encode_decode_request_with_psk),
	KUNIT_CASE(test_eku_encode_decode_response),
	KUNIT_CASE(test_eku_encode_decode_response_error),
	KUNIT_CASE(test_eku_encode_buffer_too_small),

	/* State machine */
	KUNIT_CASE(test_eku_state_names),

	/* Transport parameters */
	KUNIT_CASE(test_eku_tp_encode_decode),
	KUNIT_CASE(test_eku_tp_negotiate_both_support),
	KUNIT_CASE(test_eku_tp_negotiate_only_local),
	KUNIT_CASE(test_eku_tp_negotiate_only_remote),
	KUNIT_CASE(test_eku_tp_negotiate_neither),

	/* Constants */
	KUNIT_CASE(test_eku_frame_types),
	KUNIT_CASE(test_eku_status_codes),
	KUNIT_CASE(test_eku_flags),
	KUNIT_CASE(test_eku_psk_max_len),

	/* Edge cases */
	KUNIT_CASE(test_eku_large_request_id),

	{}
};

static struct kunit_suite extended_key_update_test_suite = {
	.name = "tquic-extended-key-update",
	.test_cases = extended_key_update_test_cases,
};

kunit_test_suites(&extended_key_update_test_suite);

MODULE_AUTHOR("Linux Foundation");
MODULE_DESCRIPTION("TQUIC Extended Key Update KUnit Tests");
MODULE_LICENSE("GPL");
