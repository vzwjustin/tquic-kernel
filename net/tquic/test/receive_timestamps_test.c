// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Receive Timestamps Extension KUnit Tests
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Tests for the QUIC Receive Timestamps extension implementation
 * (draft-smith-quic-receive-ts-03).
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/ktime.h>
#include <net/tquic.h>

#include "../core/receive_timestamps.h"
#include "../core/transport_params.h"

/*
 * =============================================================================
 * Initialization Tests
 * =============================================================================
 */

/*
 * Test: Initialize receive timestamps state
 */
static void test_receive_ts_init(struct kunit *test)
{
	struct tquic_receive_ts_state *state;
	int ret;

	state = kunit_kzalloc(test, sizeof(*state), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, state);

	ret = tquic_receive_ts_init(state);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_NOT_NULL(test, state->ring_buffer);
	KUNIT_EXPECT_FALSE(test, state->params.enabled);
	KUNIT_EXPECT_EQ(test, state->params.max_receive_timestamps_per_ack,
			(u64)TQUIC_DEFAULT_MAX_RECEIVE_TIMESTAMPS);
	KUNIT_EXPECT_EQ(test, state->params.receive_timestamps_exponent,
			(u8)TQUIC_DEFAULT_RECEIVE_TS_EXPONENT);
	KUNIT_EXPECT_FALSE(test, state->timestamp_basis_set);
	KUNIT_EXPECT_EQ(test, state->ring_head, (u32)0);
	KUNIT_EXPECT_EQ(test, state->ring_count, (u32)0);

	tquic_receive_ts_destroy(state);
}

/*
 * Test: Destroy receive timestamps state
 */
static void test_receive_ts_destroy(struct kunit *test)
{
	struct tquic_receive_ts_state *state;
	int ret;

	state = kunit_kzalloc(test, sizeof(*state), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, state);

	ret = tquic_receive_ts_init(state);
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Should not crash */
	tquic_receive_ts_destroy(state);

	/* Ring buffer should be NULL after destroy */
	KUNIT_EXPECT_NULL(test, state->ring_buffer);
}

/*
 * Test: Reset receive timestamps state
 */
static void test_receive_ts_reset(struct kunit *test)
{
	struct tquic_receive_ts_state *state;
	int ret;
	ktime_t now = ktime_get();

	state = kunit_kzalloc(test, sizeof(*state), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, state);

	ret = tquic_receive_ts_init(state);
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Record some timestamps */
	tquic_receive_ts_record(state, 1, now);
	tquic_receive_ts_record(state, 2, now);
	tquic_receive_ts_record(state, 3, now);

	KUNIT_EXPECT_TRUE(test, state->timestamp_basis_set);
	KUNIT_EXPECT_GT(test, state->ring_count, (u32)0);

	/* Reset and verify state is cleared */
	tquic_receive_ts_reset(state);

	KUNIT_EXPECT_FALSE(test, state->timestamp_basis_set);
	KUNIT_EXPECT_EQ(test, state->ring_count, (u32)0);
	KUNIT_EXPECT_EQ(test, state->ring_head, (u32)0);

	tquic_receive_ts_destroy(state);
}

/*
 * =============================================================================
 * Parameter Negotiation Tests
 * =============================================================================
 */

/*
 * Test: Set local parameters
 */
static void test_receive_ts_set_local_params(struct kunit *test)
{
	struct tquic_receive_ts_state *state;
	int ret;

	state = kunit_kzalloc(test, sizeof(*state), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, state);

	ret = tquic_receive_ts_init(state);
	KUNIT_ASSERT_EQ(test, ret, 0);

	tquic_receive_ts_set_local_params(state, 100, 2);

	KUNIT_EXPECT_EQ(test, state->params.max_receive_timestamps_per_ack, (u64)100);
	KUNIT_EXPECT_EQ(test, state->params.receive_timestamps_exponent, (u8)2);

	tquic_receive_ts_destroy(state);
}

/*
 * Test: Set peer parameters
 */
static void test_receive_ts_set_peer_params(struct kunit *test)
{
	struct tquic_receive_ts_state *state;
	int ret;

	state = kunit_kzalloc(test, sizeof(*state), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, state);

	ret = tquic_receive_ts_init(state);
	KUNIT_ASSERT_EQ(test, ret, 0);

	tquic_receive_ts_set_peer_params(state, 50, 3);

	/* Peer params affect what we send */
	KUNIT_EXPECT_EQ(test, state->max_timestamps, (u32)50);
	KUNIT_EXPECT_EQ(test, state->exponent, (u8)3);

	tquic_receive_ts_destroy(state);
}

/*
 * Test: Parameter clamping to maximum values
 */
static void test_receive_ts_param_clamping(struct kunit *test)
{
	struct tquic_receive_ts_state *state;
	int ret;

	state = kunit_kzalloc(test, sizeof(*state), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, state);

	ret = tquic_receive_ts_init(state);
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Values exceeding maximum should be clamped */
	tquic_receive_ts_set_local_params(state, TQUIC_MAX_RECEIVE_TIMESTAMPS + 100, 30);

	KUNIT_EXPECT_EQ(test, state->params.max_receive_timestamps_per_ack,
			(u64)TQUIC_MAX_RECEIVE_TIMESTAMPS);
	KUNIT_EXPECT_EQ(test, state->params.receive_timestamps_exponent,
			(u8)TQUIC_MAX_RECEIVE_TS_EXPONENT);

	tquic_receive_ts_destroy(state);
}

/*
 * Test: Negotiation enabled when both peers support
 */
static void test_receive_ts_negotiate_enabled(struct kunit *test)
{
	struct tquic_receive_ts_state *state;
	bool enabled;
	int ret;

	state = kunit_kzalloc(test, sizeof(*state), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, state);

	ret = tquic_receive_ts_init(state);
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Both sides advertise support */
	tquic_receive_ts_set_local_params(state, 100, 0);
	tquic_receive_ts_set_peer_params(state, 50, 2);

	enabled = tquic_receive_ts_negotiate(state);

	KUNIT_EXPECT_TRUE(test, enabled);
	KUNIT_EXPECT_TRUE(test, tquic_receive_ts_is_enabled(state));

	tquic_receive_ts_destroy(state);
}

/*
 * Test: Negotiation disabled when one peer doesn't support
 */
static void test_receive_ts_negotiate_disabled(struct kunit *test)
{
	struct tquic_receive_ts_state *state;
	bool enabled;
	int ret;

	state = kunit_kzalloc(test, sizeof(*state), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, state);

	ret = tquic_receive_ts_init(state);
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Local supports but peer doesn't (zero max_timestamps) */
	tquic_receive_ts_set_local_params(state, 100, 0);
	tquic_receive_ts_set_peer_params(state, 0, 0);

	enabled = tquic_receive_ts_negotiate(state);

	KUNIT_EXPECT_FALSE(test, enabled);
	KUNIT_EXPECT_FALSE(test, tquic_receive_ts_is_enabled(state));

	tquic_receive_ts_destroy(state);
}

/*
 * =============================================================================
 * Timestamp Recording Tests
 * =============================================================================
 */

/*
 * Test: Record packet timestamp
 */
static void test_receive_ts_record(struct kunit *test)
{
	struct tquic_receive_ts_state *state;
	ktime_t now;
	int ret;

	state = kunit_kzalloc(test, sizeof(*state), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, state);

	ret = tquic_receive_ts_init(state);
	KUNIT_ASSERT_EQ(test, ret, 0);

	now = ktime_get();

	ret = tquic_receive_ts_record(state, 42, now);
	KUNIT_EXPECT_EQ(test, ret, 0);

	/* First record should set basis */
	KUNIT_EXPECT_TRUE(test, state->timestamp_basis_set);
	KUNIT_EXPECT_EQ(test, state->timestamp_basis_pn, (u64)42);
	KUNIT_EXPECT_EQ(test, state->ring_count, (u32)1);

	tquic_receive_ts_destroy(state);
}

/*
 * Test: Lookup recorded timestamp
 */
static void test_receive_ts_lookup(struct kunit *test)
{
	struct tquic_receive_ts_state *state;
	ktime_t now;
	u64 recv_time_us;
	int ret;

	state = kunit_kzalloc(test, sizeof(*state), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, state);

	ret = tquic_receive_ts_init(state);
	KUNIT_ASSERT_EQ(test, ret, 0);

	now = ktime_get();

	/* Record multiple packets */
	tquic_receive_ts_record(state, 1, now);
	tquic_receive_ts_record(state, 2, ktime_add_us(now, 1000));
	tquic_receive_ts_record(state, 3, ktime_add_us(now, 2000));

	/* Lookup should succeed for recorded packets */
	ret = tquic_receive_ts_lookup(state, 2, &recv_time_us);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_GE(test, recv_time_us, (u64)900);  /* ~1000us delta */
	KUNIT_EXPECT_LE(test, recv_time_us, (u64)1100);

	/* Lookup should fail for non-existent packet */
	ret = tquic_receive_ts_lookup(state, 99, &recv_time_us);
	KUNIT_EXPECT_NE(test, ret, 0);

	tquic_receive_ts_destroy(state);
}

/*
 * Test: Ring buffer wrapping
 */
static void test_receive_ts_ring_wrap(struct kunit *test)
{
	struct tquic_receive_ts_state *state;
	ktime_t now;
	u64 recv_time_us;
	u64 pn;
	int ret;

	state = kunit_kzalloc(test, sizeof(*state), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, state);

	ret = tquic_receive_ts_init(state);
	KUNIT_ASSERT_EQ(test, ret, 0);

	now = ktime_get();

	/* Fill the ring buffer completely and overflow */
	for (pn = 0; pn < TQUIC_RECEIVE_TS_RINGBUF_SIZE + 10; pn++) {
		ret = tquic_receive_ts_record(state, pn, ktime_add_us(now, pn * 100));
		KUNIT_ASSERT_EQ(test, ret, 0);
	}

	/* Ring count should be capped at buffer size */
	KUNIT_EXPECT_EQ(test, state->ring_count, (u32)TQUIC_RECEIVE_TS_RINGBUF_SIZE);

	/* Recent packets should be findable */
	ret = tquic_receive_ts_lookup(state,
				      TQUIC_RECEIVE_TS_RINGBUF_SIZE + 5,
				      &recv_time_us);
	KUNIT_EXPECT_EQ(test, ret, 0);

	/* Old packets should have been overwritten */
	ret = tquic_receive_ts_lookup(state, 0, &recv_time_us);
	KUNIT_EXPECT_NE(test, ret, 0);

	tquic_receive_ts_destroy(state);
}

/*
 * =============================================================================
 * Timestamp Basis Tests
 * =============================================================================
 */

/*
 * Test: Set and get timestamp basis
 */
static void test_receive_ts_basis(struct kunit *test)
{
	struct tquic_receive_ts_state *state;
	ktime_t basis_time, retrieved_time;
	u64 basis_pn, retrieved_pn;
	bool has_basis;
	int ret;

	state = kunit_kzalloc(test, sizeof(*state), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, state);

	ret = tquic_receive_ts_init(state);
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Initially no basis */
	has_basis = tquic_receive_ts_get_basis(state, &retrieved_time, &retrieved_pn);
	KUNIT_EXPECT_FALSE(test, has_basis);

	/* Set basis manually */
	basis_time = ktime_get();
	basis_pn = 100;
	tquic_receive_ts_set_basis(state, basis_time, basis_pn);

	/* Retrieve and verify */
	has_basis = tquic_receive_ts_get_basis(state, &retrieved_time, &retrieved_pn);
	KUNIT_EXPECT_TRUE(test, has_basis);
	KUNIT_EXPECT_EQ(test, retrieved_pn, basis_pn);

	tquic_receive_ts_destroy(state);
}

/*
 * Test: Automatic basis set on first record
 */
static void test_receive_ts_auto_basis(struct kunit *test)
{
	struct tquic_receive_ts_state *state;
	ktime_t now, retrieved_time;
	u64 retrieved_pn;
	bool has_basis;
	int ret;

	state = kunit_kzalloc(test, sizeof(*state), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, state);

	ret = tquic_receive_ts_init(state);
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* No basis initially */
	has_basis = tquic_receive_ts_get_basis(state, NULL, NULL);
	KUNIT_EXPECT_FALSE(test, has_basis);

	/* Record first packet - should set basis */
	now = ktime_get();
	tquic_receive_ts_record(state, 42, now);

	has_basis = tquic_receive_ts_get_basis(state, &retrieved_time, &retrieved_pn);
	KUNIT_EXPECT_TRUE(test, has_basis);
	KUNIT_EXPECT_EQ(test, retrieved_pn, (u64)42);

	tquic_receive_ts_destroy(state);
}

/*
 * =============================================================================
 * Statistics Tests
 * =============================================================================
 */

/*
 * Test: Get statistics
 */
static void test_receive_ts_statistics(struct kunit *test)
{
	struct tquic_receive_ts_state *state;
	u64 ts_sent, ts_recv;
	u32 ring_util;
	ktime_t now;
	int ret;
	int i;

	state = kunit_kzalloc(test, sizeof(*state), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, state);

	ret = tquic_receive_ts_init(state);
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Initially all stats should be zero */
	tquic_receive_ts_get_stats(state, &ts_sent, &ts_recv, &ring_util);
	KUNIT_EXPECT_EQ(test, ts_sent, (u64)0);
	KUNIT_EXPECT_EQ(test, ts_recv, (u64)0);
	KUNIT_EXPECT_EQ(test, ring_util, (u32)0);

	/* Add some timestamps */
	now = ktime_get();
	for (i = 0; i < 100; i++)
		tquic_receive_ts_record(state, i, ktime_add_us(now, i * 100));

	/* Check ring utilization */
	tquic_receive_ts_get_stats(state, &ts_sent, &ts_recv, &ring_util);
	KUNIT_EXPECT_GT(test, ring_util, (u32)0);
	KUNIT_EXPECT_LE(test, ring_util, (u32)100);

	tquic_receive_ts_destroy(state);
}

/*
 * =============================================================================
 * Transport Parameter Integration Tests
 * =============================================================================
 */

/*
 * Test: Transport parameter encoding with receive timestamps
 */
static void test_tp_receive_timestamps_encode(struct kunit *test)
{
	struct tquic_transport_params params;
	u8 *buf;
	ssize_t encoded_len;

	buf = kunit_kzalloc(test, 1024, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buf);

	tquic_tp_set_defaults_client(&params);

	/* Verify defaults include receive timestamps */
	KUNIT_EXPECT_TRUE(test, params.max_receive_timestamps_per_ack_present);
	KUNIT_EXPECT_TRUE(test, params.receive_timestamps_exponent_present);
	KUNIT_EXPECT_GT(test, params.max_receive_timestamps_per_ack, (u64)0);

	/* Encode should succeed */
	encoded_len = tquic_tp_encode(&params, false, buf, 1024);
	KUNIT_EXPECT_GT(test, encoded_len, (ssize_t)0);
}

/*
 * Test: Transport parameter decoding with receive timestamps
 */
static void test_tp_receive_timestamps_decode(struct kunit *test)
{
	struct tquic_transport_params original, decoded;
	u8 *buf;
	ssize_t encoded_len;
	int ret;

	buf = kunit_kzalloc(test, 1024, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buf);

	tquic_tp_set_defaults_client(&original);
	original.initial_scid_present = true;
	original.initial_scid.len = 8;
	memset(original.initial_scid.id, 0x42, 8);

	/* Encode */
	encoded_len = tquic_tp_encode(&original, false, buf, 1024);
	KUNIT_ASSERT_GT(test, encoded_len, (ssize_t)0);

	/* Decode */
	ret = tquic_tp_decode(buf, encoded_len, false, &decoded);
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Verify receive timestamps parameters */
	KUNIT_EXPECT_TRUE(test, decoded.max_receive_timestamps_per_ack_present);
	KUNIT_EXPECT_TRUE(test, decoded.receive_timestamps_exponent_present);
	KUNIT_EXPECT_EQ(test, decoded.max_receive_timestamps_per_ack,
			original.max_receive_timestamps_per_ack);
	KUNIT_EXPECT_EQ(test, decoded.receive_timestamps_exponent,
			original.receive_timestamps_exponent);
}

/*
 * Test: Transport parameter negotiation for receive timestamps
 */
static void test_tp_receive_timestamps_negotiate(struct kunit *test)
{
	struct tquic_transport_params local, remote;
	struct tquic_negotiated_params result;
	int ret;

	tquic_tp_set_defaults_client(&local);
	tquic_tp_set_defaults_server(&remote);

	/* Both support receive timestamps with different values */
	local.max_receive_timestamps_per_ack = 100;
	local.max_receive_timestamps_per_ack_present = true;
	local.receive_timestamps_exponent = 0;
	local.receive_timestamps_exponent_present = true;

	remote.max_receive_timestamps_per_ack = 50;
	remote.max_receive_timestamps_per_ack_present = true;
	remote.receive_timestamps_exponent = 2;
	remote.receive_timestamps_exponent_present = true;

	ret = tquic_tp_negotiate(&local, &remote, &result);
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Should be enabled */
	KUNIT_EXPECT_TRUE(test, result.receive_timestamps_enabled);

	/* Max timestamps should be minimum of both */
	KUNIT_EXPECT_EQ(test, result.max_receive_timestamps, (u64)50);

	/* Exponent should be maximum of both (coarser precision) */
	KUNIT_EXPECT_EQ(test, result.receive_timestamps_exponent, (u8)2);
}

/*
 * Test: Receive timestamps disabled when one peer doesn't support
 */
static void test_tp_receive_timestamps_not_negotiated(struct kunit *test)
{
	struct tquic_transport_params local, remote;
	struct tquic_negotiated_params result;
	int ret;

	tquic_tp_set_defaults_client(&local);
	tquic_tp_init(&remote);  /* Use init which doesn't set receive ts params */

	/* Local supports but remote doesn't advertise */
	local.max_receive_timestamps_per_ack = 100;
	local.max_receive_timestamps_per_ack_present = true;
	local.receive_timestamps_exponent = 0;
	local.receive_timestamps_exponent_present = true;

	/* Remote didn't advertise receive timestamps */
	remote.max_receive_timestamps_per_ack_present = false;

	ret = tquic_tp_negotiate(&local, &remote, &result);
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Should not be enabled */
	KUNIT_EXPECT_FALSE(test, result.receive_timestamps_enabled);
	KUNIT_EXPECT_EQ(test, result.max_receive_timestamps, (u64)0);
}

/*
 * =============================================================================
 * Decode Tests
 * =============================================================================
 */

/*
 * Test: Decode timestamps from encoded data
 */
static void test_receive_ts_decode(struct kunit *test)
{
	struct tquic_receive_ts_state *state;
	struct tquic_ack_timestamps timestamps;
	u8 buf[64];
	size_t offset = 0;
	ssize_t decoded_len;
	int ret;

	state = kunit_kzalloc(test, sizeof(*state), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, state);

	ret = tquic_receive_ts_init(state);
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Enable timestamps */
	tquic_receive_ts_set_local_params(state, 100, 0);
	tquic_receive_ts_set_peer_params(state, 100, 0);
	tquic_receive_ts_negotiate(state);

	/*
	 * Manually encode a simple timestamp structure:
	 * - Largest acked timestamp delta: 1000 (varint)
	 * - Timestamp range count: 1 (varint)
	 * - Delta count: 2 (varint)
	 * - Deltas: 100, 200 (varints)
	 */
	buf[offset++] = 0x43;  /* 2-byte varint: 1000 = 0x3e8 -> 0x43 0xe8 */
	buf[offset++] = 0xe8;
	buf[offset++] = 0x01;  /* Range count: 1 */
	buf[offset++] = 0x02;  /* Delta count: 2 */
	buf[offset++] = 0x40;  /* Delta 1: 100 = 0x64 -> 0x40 0x64 */
	buf[offset++] = 0x64;
	buf[offset++] = 0x40;  /* Delta 2: 200 = 0xc8 -> 0x40 0xc8 */
	buf[offset++] = 0xc8;

	decoded_len = tquic_receive_ts_decode(state, buf, offset, &timestamps);
	KUNIT_ASSERT_GT(test, decoded_len, (ssize_t)0);

	KUNIT_EXPECT_EQ(test, timestamps.largest_acked_timestamp, (u64)1000);
	KUNIT_EXPECT_EQ(test, timestamps.timestamp_range_count, (u32)1);

	tquic_receive_ts_free_decoded(&timestamps);
	tquic_receive_ts_destroy(state);
}

/*
 * Test: Free decoded timestamps
 */
static void test_receive_ts_free_decoded(struct kunit *test)
{
	struct tquic_ack_timestamps timestamps;

	memset(&timestamps, 0, sizeof(timestamps));

	/* Should not crash on empty structure */
	tquic_receive_ts_free_decoded(&timestamps);

	/* Should not crash on NULL */
	tquic_receive_ts_free_decoded(NULL);
}

static struct kunit_case receive_timestamps_test_cases[] = {
	/* Initialization tests */
	KUNIT_CASE(test_receive_ts_init),
	KUNIT_CASE(test_receive_ts_destroy),
	KUNIT_CASE(test_receive_ts_reset),

	/* Parameter negotiation tests */
	KUNIT_CASE(test_receive_ts_set_local_params),
	KUNIT_CASE(test_receive_ts_set_peer_params),
	KUNIT_CASE(test_receive_ts_param_clamping),
	KUNIT_CASE(test_receive_ts_negotiate_enabled),
	KUNIT_CASE(test_receive_ts_negotiate_disabled),

	/* Timestamp recording tests */
	KUNIT_CASE(test_receive_ts_record),
	KUNIT_CASE(test_receive_ts_lookup),
	KUNIT_CASE(test_receive_ts_ring_wrap),

	/* Timestamp basis tests */
	KUNIT_CASE(test_receive_ts_basis),
	KUNIT_CASE(test_receive_ts_auto_basis),

	/* Statistics tests */
	KUNIT_CASE(test_receive_ts_statistics),

	/* Transport parameter tests */
	KUNIT_CASE(test_tp_receive_timestamps_encode),
	KUNIT_CASE(test_tp_receive_timestamps_decode),
	KUNIT_CASE(test_tp_receive_timestamps_negotiate),
	KUNIT_CASE(test_tp_receive_timestamps_not_negotiated),

	/* Decode tests */
	KUNIT_CASE(test_receive_ts_decode),
	KUNIT_CASE(test_receive_ts_free_decoded),

	{}
};

static struct kunit_suite receive_timestamps_test_suite = {
	.name = "tquic-receive-timestamps",
	.test_cases = receive_timestamps_test_cases,
};

kunit_test_suites(&receive_timestamps_test_suite);

MODULE_AUTHOR("Linux Foundation");
MODULE_DESCRIPTION("TQUIC Receive Timestamps Extension KUnit Tests");
MODULE_LICENSE("GPL");
