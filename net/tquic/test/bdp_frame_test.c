// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: BDP Frame Extension KUnit Tests
 *
 * Copyright (c) 2026 Linux Foundation
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * KUnit tests for the BDP Frame extension (draft-kuhn-quic-bdpframe-extension-05)
 * including encoding/decoding, HMAC authentication, validation, and Careful Resume.
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <crypto/hash.h>
#include <net/tquic.h>

#include "../cong/bdp_frame.h"
#include "../core/transport_params.h"

/*
 * Helper: Create a mock connection for testing
 */
static struct tquic_connection *create_test_connection(struct kunit *test)
{
	struct tquic_connection *conn;

	conn = kunit_kzalloc(test, sizeof(*conn), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, conn);

	conn->state = TQUIC_CONN_CONNECTED;
	conn->role = TQUIC_ROLE_SERVER;
	conn->version = TQUIC_VERSION_1;
	spin_lock_init(&conn->lock);
	refcount_set(&conn->refcnt, 1);
	INIT_LIST_HEAD(&conn->paths);

	return conn;
}

/*
 * Helper: Create a mock path for testing
 */
static struct tquic_path *create_test_path(struct kunit *test,
					   struct tquic_connection *conn)
{
	struct tquic_path *path;

	path = kunit_kzalloc(test, sizeof(*path), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, path);

	path->conn = conn;
	path->path_id = 0;
	path->state = TQUIC_PATH_ACTIVE;
	path->stats.rtt_smoothed = 50000;  /* 50ms */
	path->stats.cwnd = 100 * 1200;     /* 100 packets */
	INIT_LIST_HEAD(&path->list);

	list_add(&path->list, &conn->paths);
	conn->active_path = path;
	conn->num_paths = 1;

	return path;
}

/*
 * Test: BDP state initialization and release
 */
static void test_bdp_init_release(struct kunit *test)
{
	struct tquic_connection *conn;
	int ret;

	conn = create_test_connection(test);

	/* Initialize BDP state */
	ret = tquic_bdp_init(conn);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_NOT_NULL(test, conn->bdp_state);

	/* Verify initial state */
	KUNIT_EXPECT_FALSE(test, tquic_bdp_is_enabled(conn));

	/* Release */
	tquic_bdp_release(conn);
	KUNIT_EXPECT_NULL(test, conn->bdp_state);

	/* Double release should be safe */
	tquic_bdp_release(conn);
}

/*
 * Test: Set HMAC key
 */
static void test_bdp_set_hmac_key(struct kunit *test)
{
	struct tquic_connection *conn;
	u8 key[32];
	int ret;

	conn = create_test_connection(test);
	ret = tquic_bdp_init(conn);
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Generate random key */
	get_random_bytes(key, sizeof(key));

	/* Set key */
	ret = tquic_bdp_set_hmac_key(conn, key, sizeof(key));
	KUNIT_EXPECT_EQ(test, ret, 0);

	/* Partial key should work */
	ret = tquic_bdp_set_hmac_key(conn, key, 16);
	KUNIT_EXPECT_EQ(test, ret, 0);

	/* NULL key should fail */
	ret = tquic_bdp_set_hmac_key(conn, NULL, 32);
	KUNIT_EXPECT_NE(test, ret, 0);

	tquic_bdp_release(conn);
}

/*
 * Test: BDP frame encoding
 */
static void test_bdp_encode_frame(struct kunit *test)
{
	struct tquic_bdp_frame frame;
	u8 *buf;
	ssize_t len;

	buf = kunit_kzalloc(test, 256, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buf);

	/* Initialize frame */
	memset(&frame, 0, sizeof(frame));
	frame.bdp = 1000000;           /* 1MB */
	frame.saved_cwnd = 500000;     /* 500KB */
	frame.saved_rtt = 50000;       /* 50ms */
	frame.lifetime = 3600;         /* 1 hour */
	get_random_bytes(frame.endpoint_token, TQUIC_BDP_TOKEN_LEN);
	get_random_bytes(frame.hmac, TQUIC_BDP_HMAC_LEN);

	/* Encode */
	len = tquic_encode_bdp_frame(&frame, buf, 256);
	KUNIT_EXPECT_GT(test, len, (ssize_t)0);

	/* Minimum size: type(1) + varints(4*1 min) + token(16) + hmac(16) = 37 */
	KUNIT_EXPECT_GE(test, len, (ssize_t)37);

	/* Buffer too small should fail */
	len = tquic_encode_bdp_frame(&frame, buf, 10);
	KUNIT_EXPECT_LT(test, len, (ssize_t)0);

	/* NULL frame should fail */
	len = tquic_encode_bdp_frame(NULL, buf, 256);
	KUNIT_EXPECT_LT(test, len, (ssize_t)0);
}

/*
 * Test: BDP frame decoding
 */
static void test_bdp_decode_frame(struct kunit *test)
{
	struct tquic_bdp_frame original, decoded;
	u8 *buf;
	ssize_t encoded_len, decoded_len;

	buf = kunit_kzalloc(test, 256, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buf);

	/* Initialize frame */
	memset(&original, 0, sizeof(original));
	original.bdp = 2000000;
	original.saved_cwnd = 1000000;
	original.saved_rtt = 100000;
	original.lifetime = 7200;
	get_random_bytes(original.endpoint_token, TQUIC_BDP_TOKEN_LEN);
	get_random_bytes(original.hmac, TQUIC_BDP_HMAC_LEN);

	/* Encode */
	encoded_len = tquic_encode_bdp_frame(&original, buf, 256);
	KUNIT_ASSERT_GT(test, encoded_len, (ssize_t)0);

	/* Decode */
	memset(&decoded, 0, sizeof(decoded));
	decoded_len = tquic_decode_bdp_frame(buf, encoded_len, &decoded);
	KUNIT_ASSERT_EQ(test, decoded_len, encoded_len);

	/* Verify fields match */
	KUNIT_EXPECT_EQ(test, decoded.bdp, original.bdp);
	KUNIT_EXPECT_EQ(test, decoded.saved_cwnd, original.saved_cwnd);
	KUNIT_EXPECT_EQ(test, decoded.saved_rtt, original.saved_rtt);
	KUNIT_EXPECT_EQ(test, decoded.lifetime, original.lifetime);
	KUNIT_EXPECT_EQ(test, memcmp(decoded.endpoint_token, original.endpoint_token,
				     TQUIC_BDP_TOKEN_LEN), 0);
	KUNIT_EXPECT_EQ(test, memcmp(decoded.hmac, original.hmac,
				     TQUIC_BDP_HMAC_LEN), 0);
}

/*
 * Test: BDP frame roundtrip encode/decode
 */
static void test_bdp_roundtrip(struct kunit *test)
{
	struct tquic_bdp_frame frames[] = {
		{ .bdp = TQUIC_BDP_MIN_BDP, .saved_cwnd = TQUIC_BDP_MIN_CWND,
		  .saved_rtt = TQUIC_BDP_MIN_RTT_US, .lifetime = 60 },
		{ .bdp = 10000000, .saved_cwnd = 5000000,
		  .saved_rtt = 200000, .lifetime = 3600 },
		{ .bdp = TQUIC_BDP_MAX_BDP / 2, .saved_cwnd = TQUIC_BDP_MAX_CWND / 2,
		  .saved_rtt = 1000000, .lifetime = 86400 },
	};
	u8 *buf;
	ssize_t len;
	int i;

	buf = kunit_kzalloc(test, 256, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buf);

	for (i = 0; i < ARRAY_SIZE(frames); i++) {
		struct tquic_bdp_frame decoded;

		get_random_bytes(frames[i].endpoint_token, TQUIC_BDP_TOKEN_LEN);
		get_random_bytes(frames[i].hmac, TQUIC_BDP_HMAC_LEN);

		len = tquic_encode_bdp_frame(&frames[i], buf, 256);
		KUNIT_ASSERT_GT(test, len, (ssize_t)0);

		memset(&decoded, 0, sizeof(decoded));
		len = tquic_decode_bdp_frame(buf, 256, &decoded);
		KUNIT_ASSERT_GT(test, len, (ssize_t)0);

		KUNIT_EXPECT_EQ_MSG(test, decoded.bdp, frames[i].bdp,
				    "BDP mismatch at index %d", i);
		KUNIT_EXPECT_EQ_MSG(test, decoded.saved_cwnd, frames[i].saved_cwnd,
				    "cwnd mismatch at index %d", i);
		KUNIT_EXPECT_EQ_MSG(test, decoded.saved_rtt, frames[i].saved_rtt,
				    "RTT mismatch at index %d", i);
	}
}

/*
 * Test: HMAC computation and verification
 */
static void test_bdp_hmac(struct kunit *test)
{
	struct tquic_connection *conn;
	struct tquic_bdp_frame frame;
	u8 key[32];
	u8 original_hmac[TQUIC_BDP_HMAC_LEN];
	int ret;

	conn = create_test_connection(test);
	ret = tquic_bdp_init(conn);
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Set HMAC key */
	get_random_bytes(key, sizeof(key));
	ret = tquic_bdp_set_hmac_key(conn, key, sizeof(key));
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Initialize frame */
	memset(&frame, 0, sizeof(frame));
	frame.bdp = 5000000;
	frame.saved_cwnd = 2000000;
	frame.saved_rtt = 75000;
	frame.lifetime = 3600;
	get_random_bytes(frame.endpoint_token, TQUIC_BDP_TOKEN_LEN);

	/* Compute HMAC */
	ret = tquic_bdp_compute_hmac(conn, &frame);
	KUNIT_EXPECT_EQ(test, ret, 0);

	/* Save HMAC for later comparison */
	memcpy(original_hmac, frame.hmac, TQUIC_BDP_HMAC_LEN);

	/* Verify HMAC */
	ret = tquic_bdp_verify_hmac(conn, &frame);
	KUNIT_EXPECT_EQ(test, ret, 0);

	/* Modify frame - HMAC should fail */
	frame.bdp = 6000000;
	ret = tquic_bdp_verify_hmac(conn, &frame);
	KUNIT_EXPECT_NE(test, ret, 0);

	/* Restore original BDP but corrupt HMAC */
	frame.bdp = 5000000;
	frame.hmac[0] ^= 0xff;
	ret = tquic_bdp_verify_hmac(conn, &frame);
	KUNIT_EXPECT_NE(test, ret, 0);

	tquic_bdp_release(conn);
}

/*
 * Test: BDP frame validation - valid frame
 */
static void test_bdp_validate_valid(struct kunit *test)
{
	struct tquic_connection *conn;
	struct tquic_bdp_frame frame;
	u8 key[32];
	int ret;

	conn = create_test_connection(test);
	ret = tquic_bdp_init(conn);
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Set HMAC key */
	get_random_bytes(key, sizeof(key));
	ret = tquic_bdp_set_hmac_key(conn, key, sizeof(key));
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Generate endpoint token */
	memset(&frame, 0, sizeof(frame));
	frame.bdp = 1000000;
	frame.saved_cwnd = 500000;
	frame.saved_rtt = 50000;
	frame.lifetime = 3600;
	ret = tquic_bdp_generate_endpoint_token(conn, frame.endpoint_token);
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Compute HMAC */
	ret = tquic_bdp_compute_hmac(conn, &frame);
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Validate */
	ret = tquic_validate_bdp_frame(conn, &frame);
	KUNIT_EXPECT_EQ(test, ret, 0);

	tquic_bdp_release(conn);
}

/*
 * Test: BDP frame validation - invalid ranges
 */
static void test_bdp_validate_ranges(struct kunit *test)
{
	struct tquic_connection *conn;
	struct tquic_bdp_frame frame;
	u8 key[32];
	int ret;

	conn = create_test_connection(test);
	ret = tquic_bdp_init(conn);
	KUNIT_ASSERT_EQ(test, ret, 0);

	get_random_bytes(key, sizeof(key));
	ret = tquic_bdp_set_hmac_key(conn, key, sizeof(key));
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* BDP too small */
	memset(&frame, 0, sizeof(frame));
	frame.bdp = TQUIC_BDP_MIN_BDP - 1;
	frame.saved_cwnd = 500000;
	frame.saved_rtt = 50000;
	frame.lifetime = 3600;
	ret = tquic_validate_bdp_frame(conn, &frame);
	KUNIT_EXPECT_NE(test, ret, 0);

	/* BDP too large */
	frame.bdp = TQUIC_BDP_MAX_BDP + 1;
	ret = tquic_validate_bdp_frame(conn, &frame);
	KUNIT_EXPECT_NE(test, ret, 0);

	/* CWND too small */
	frame.bdp = 1000000;
	frame.saved_cwnd = TQUIC_BDP_MIN_CWND - 1;
	ret = tquic_validate_bdp_frame(conn, &frame);
	KUNIT_EXPECT_NE(test, ret, 0);

	/* RTT too small */
	frame.saved_cwnd = 500000;
	frame.saved_rtt = TQUIC_BDP_MIN_RTT_US - 1;
	ret = tquic_validate_bdp_frame(conn, &frame);
	KUNIT_EXPECT_NE(test, ret, 0);

	/* Lifetime too long */
	frame.saved_rtt = 50000;
	frame.lifetime = TQUIC_BDP_MAX_LIFETIME_SEC + 1;
	ret = tquic_validate_bdp_frame(conn, &frame);
	KUNIT_EXPECT_NE(test, ret, 0);

	tquic_bdp_release(conn);
}

/*
 * Test: Careful Resume initialization
 */
static void test_careful_resume_init(struct kunit *test)
{
	struct tquic_connection *conn;
	struct tquic_path *path;
	struct tquic_bdp_frame frame;
	int ret;

	conn = create_test_connection(test);
	path = create_test_path(test, conn);

	/* Initialize frame */
	memset(&frame, 0, sizeof(frame));
	frame.bdp = 1000000;
	frame.saved_cwnd = 500000;
	frame.saved_rtt = 50000;
	frame.lifetime = 3600;

	/* Initialize Careful Resume */
	ret = tquic_careful_resume_init(path, &frame);
	KUNIT_EXPECT_EQ(test, ret, 0);

	/* Path cwnd should be set to conservative initial value */
	KUNIT_EXPECT_LT(test, path->stats.cwnd, frame.saved_cwnd);
	KUNIT_EXPECT_GE(test, path->stats.cwnd, (u32)TQUIC_BDP_MIN_CWND);
}

/*
 * Test: Careful Resume validation - path unchanged
 */
static void test_careful_resume_validate_unchanged(struct kunit *test)
{
	struct tquic_connection *conn;
	struct tquic_path *path;
	struct tquic_bdp_frame frame;
	bool valid;
	int ret;

	conn = create_test_connection(test);
	path = create_test_path(test, conn);

	memset(&frame, 0, sizeof(frame));
	frame.bdp = 1000000;
	frame.saved_cwnd = 500000;
	frame.saved_rtt = 50000;  /* 50ms */
	frame.lifetime = 3600;

	ret = tquic_careful_resume_init(path, &frame);
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Validate with similar RTT - should pass */
	valid = tquic_careful_resume_validate(path, 55000);  /* 55ms */
	KUNIT_EXPECT_TRUE(test, valid);

	/* Validate with slightly higher RTT - should still pass */
	valid = tquic_careful_resume_validate(path, 75000);  /* 75ms */
	KUNIT_EXPECT_TRUE(test, valid);
}

/*
 * Test: Careful Resume validation - path changed significantly
 */
static void test_careful_resume_validate_changed(struct kunit *test)
{
	struct tquic_connection *conn;
	struct tquic_path *path;
	struct tquic_bdp_frame frame;
	bool valid;
	int ret;

	conn = create_test_connection(test);
	path = create_test_path(test, conn);

	memset(&frame, 0, sizeof(frame));
	frame.bdp = 1000000;
	frame.saved_cwnd = 500000;
	frame.saved_rtt = 50000;  /* 50ms */
	frame.lifetime = 3600;

	ret = tquic_careful_resume_init(path, &frame);
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Validate with much higher RTT - should fail */
	valid = tquic_careful_resume_validate(path, 150000);  /* 150ms = 3x */
	KUNIT_EXPECT_FALSE(test, valid);
}

/*
 * Test: Careful Resume safe retreat
 */
static void test_careful_resume_safe_retreat(struct kunit *test)
{
	struct tquic_connection *conn;
	struct tquic_path *path;
	struct tquic_bdp_frame frame;
	int ret;

	conn = create_test_connection(test);
	ret = tquic_bdp_init(conn);
	KUNIT_ASSERT_EQ(test, ret, 0);

	path = create_test_path(test, conn);

	memset(&frame, 0, sizeof(frame));
	frame.bdp = 1000000;
	frame.saved_cwnd = 500000;
	frame.saved_rtt = 50000;
	frame.lifetime = 3600;

	ret = tquic_careful_resume_init(path, &frame);
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Trigger safe retreat */
	tquic_careful_resume_safe_retreat(path);

	/* Cwnd should be reset to minimum */
	KUNIT_EXPECT_EQ(test, path->stats.cwnd, (u32)TQUIC_BDP_MIN_CWND);

	tquic_bdp_release(conn);
}

/*
 * Test: Transport parameter encoding/decoding for enable_bdp_frame
 */
static void test_bdp_transport_param(struct kunit *test)
{
	struct tquic_transport_params original, decoded;
	u8 *buf;
	ssize_t len;
	int ret;

	buf = kunit_kzalloc(test, 512, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buf);

	/* Set up parameters with BDP frame enabled */
	tquic_tp_set_defaults_client(&original);
	original.initial_scid_present = true;
	original.initial_scid.len = 8;
	original.enable_bdp_frame = true;

	/* Encode */
	len = tquic_tp_encode(&original, false, buf, 512);
	KUNIT_ASSERT_GT(test, len, (ssize_t)0);

	/* Decode */
	ret = tquic_tp_decode(buf, len, false, &decoded);
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Verify BDP frame parameter */
	KUNIT_EXPECT_TRUE(test, decoded.enable_bdp_frame);
}

/*
 * Test: Transport parameter negotiation for BDP frame
 */
static void test_bdp_negotiation(struct kunit *test)
{
	struct tquic_transport_params local, remote;
	struct tquic_negotiated_params result;
	int ret;

	tquic_tp_set_defaults_client(&local);
	tquic_tp_set_defaults_server(&remote);

	/* Both support BDP frame */
	local.enable_bdp_frame = true;
	remote.enable_bdp_frame = true;

	ret = tquic_tp_negotiate(&local, &remote, &result);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_TRUE(test, result.bdp_frame_enabled);

	/* Only local supports */
	local.enable_bdp_frame = true;
	remote.enable_bdp_frame = false;

	ret = tquic_tp_negotiate(&local, &remote, &result);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_FALSE(test, result.bdp_frame_enabled);

	/* Only remote supports */
	local.enable_bdp_frame = false;
	remote.enable_bdp_frame = true;

	ret = tquic_tp_negotiate(&local, &remote, &result);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_FALSE(test, result.bdp_frame_enabled);

	/* Neither supports */
	local.enable_bdp_frame = false;
	remote.enable_bdp_frame = false;

	ret = tquic_tp_negotiate(&local, &remote, &result);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_FALSE(test, result.bdp_frame_enabled);
}

/*
 * Test: Store and restore BDP frame for reconnection
 */
static void test_bdp_store_restore(struct kunit *test)
{
	struct tquic_connection *conn;
	struct tquic_bdp_frame original, restored;
	int ret;

	conn = create_test_connection(test);
	ret = tquic_bdp_init(conn);
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Initialize frame */
	memset(&original, 0, sizeof(original));
	original.bdp = 1000000;
	original.saved_cwnd = 500000;
	original.saved_rtt = 50000;
	original.lifetime = 3600;
	get_random_bytes(original.endpoint_token, TQUIC_BDP_TOKEN_LEN);
	get_random_bytes(original.hmac, TQUIC_BDP_HMAC_LEN);

	/* Store */
	ret = tquic_bdp_store_for_reconnect(conn, &original);
	KUNIT_EXPECT_EQ(test, ret, 0);

	/* Restore */
	memset(&restored, 0, sizeof(restored));
	ret = tquic_bdp_restore_for_reconnect(conn, &restored);
	KUNIT_EXPECT_EQ(test, ret, 0);

	/* Verify match */
	KUNIT_EXPECT_EQ(test, restored.bdp, original.bdp);
	KUNIT_EXPECT_EQ(test, restored.saved_cwnd, original.saved_cwnd);
	KUNIT_EXPECT_EQ(test, restored.saved_rtt, original.saved_rtt);
	KUNIT_EXPECT_EQ(test, restored.lifetime, original.lifetime);

	tquic_bdp_release(conn);

	/* Restore after release should fail */
	ret = tquic_bdp_init(conn);
	KUNIT_ASSERT_EQ(test, ret, 0);
	ret = tquic_bdp_restore_for_reconnect(conn, &restored);
	KUNIT_EXPECT_NE(test, ret, 0);

	tquic_bdp_release(conn);
}

/*
 * Test: BDP frame generation from CC state
 */
static void test_bdp_generate(struct kunit *test)
{
	struct tquic_connection *conn;
	struct tquic_path *path;
	struct tquic_bdp_frame frame;
	struct tquic_bdp_state *bdp;
	u8 key[32];
	int ret;

	conn = create_test_connection(test);
	ret = tquic_bdp_init(conn);
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Enable BDP frame */
	bdp = conn->bdp_state;
	bdp->enabled = true;

	/* Set HMAC key */
	get_random_bytes(key, sizeof(key));
	ret = tquic_bdp_set_hmac_key(conn, key, sizeof(key));
	KUNIT_ASSERT_EQ(test, ret, 0);

	path = create_test_path(test, conn);
	path->stats.rtt_smoothed = 75000;  /* 75ms */
	path->stats.cwnd = 200 * 1200;     /* 200 packets */

	/* Generate frame */
	ret = tquic_generate_bdp_frame(conn, path, &frame);
	KUNIT_EXPECT_EQ(test, ret, 0);

	/* Verify generated values */
	KUNIT_EXPECT_EQ(test, frame.saved_cwnd, (u64)(200 * 1200));
	KUNIT_EXPECT_EQ(test, frame.saved_rtt, (u64)75000);
	KUNIT_EXPECT_EQ(test, frame.lifetime, (u64)TQUIC_BDP_DEFAULT_LIFETIME_SEC);

	tquic_bdp_release(conn);
}

static struct kunit_case bdp_frame_test_cases[] = {
	KUNIT_CASE(test_bdp_init_release),
	KUNIT_CASE(test_bdp_set_hmac_key),
	KUNIT_CASE(test_bdp_encode_frame),
	KUNIT_CASE(test_bdp_decode_frame),
	KUNIT_CASE(test_bdp_roundtrip),
	KUNIT_CASE(test_bdp_hmac),
	KUNIT_CASE(test_bdp_validate_valid),
	KUNIT_CASE(test_bdp_validate_ranges),
	KUNIT_CASE(test_careful_resume_init),
	KUNIT_CASE(test_careful_resume_validate_unchanged),
	KUNIT_CASE(test_careful_resume_validate_changed),
	KUNIT_CASE(test_careful_resume_safe_retreat),
	KUNIT_CASE(test_bdp_transport_param),
	KUNIT_CASE(test_bdp_negotiation),
	KUNIT_CASE(test_bdp_store_restore),
	KUNIT_CASE(test_bdp_generate),
	{}
};

static struct kunit_suite bdp_frame_test_suite = {
	.name = "tquic-bdp-frame",
	.test_cases = bdp_frame_test_cases,
};

kunit_test_suites(&bdp_frame_test_suite);

MODULE_AUTHOR("Linux Foundation");
MODULE_DESCRIPTION("TQUIC BDP Frame Extension KUnit Tests");
MODULE_LICENSE("GPL");
