// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: One-Way Delay Measurement Extension KUnit Tests
 *
 * Copyright (c) 2026 Linux Foundation
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Comprehensive tests for One-Way Delay measurement extension (draft-huitema-quic-1wd):
 *   - Transport parameter encoding/decoding
 *   - ACK_1WD frame parsing and generation
 *   - One-way delay calculation
 *   - Clock skew estimation
 *   - OWD state management
 *   - Asymmetric path detection
 *
 * Test Structure:
 *   Section 1: Transport Parameter Tests
 *   Section 2: ACK_1WD Frame Tests
 *   Section 3: OWD Calculation Tests
 *   Section 4: Clock Skew Estimation Tests
 *   Section 5: State Management Tests
 *   Section 6: Asymmetric Path Detection Tests
 */

#include <kunit/test.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/ktime.h>

/*
 * =============================================================================
 * Test Constants (mirror production values)
 * =============================================================================
 */

/* Frame types (draft-huitema-quic-1wd) */
#define TEST_FRAME_ACK_1WD		0x1a02ULL
#define TEST_FRAME_ACK_1WD_ECN		0x1a03ULL

/* Transport parameter ID */
#define TEST_TP_ENABLE_ONE_WAY_DELAY	0xff02de1aULL

/* Default values */
#define TEST_OWD_DEFAULT_RESOLUTION_US	1000	/* 1ms */
#define TEST_OWD_MIN_RESOLUTION_US	1
#define TEST_OWD_MAX_RESOLUTION_US	1000000

/* OWD state flags */
#define TEST_OWD_FLAG_ENABLED		BIT(0)
#define TEST_OWD_FLAG_SKEW_VALID	BIT(2)
#define TEST_OWD_FLAG_FORWARD_VALID	BIT(3)
#define TEST_OWD_FLAG_REVERSE_VALID	BIT(4)
#define TEST_OWD_FLAG_ASYMMETRIC	BIT(5)

/* Minimum samples for valid estimates */
#define TEST_OWD_MIN_SAMPLES		4

/*
 * =============================================================================
 * Test Data Structures
 * =============================================================================
 */

/**
 * struct test_owd_sample - OWD measurement sample for testing
 */
struct test_owd_sample {
	s64 forward_delay_us;
	s64 reverse_delay_us;
	u64 rtt_us;
	bool valid;
};

/**
 * struct test_owd_state - Simplified OWD state for testing
 */
struct test_owd_state {
	u32 flags;
	u64 local_resolution_us;
	u64 peer_resolution_us;
	u64 effective_resolution_us;
	s64 forward_delay_us;
	s64 reverse_delay_us;
	s64 min_forward_us;
	s64 min_reverse_us;
	s64 clock_skew_us;
	u64 sample_count;
	ktime_t reference_time;
};

/**
 * struct test_ack_1wd_frame - Parsed ACK_1WD frame for testing
 */
struct test_ack_1wd_frame {
	u64 largest_acked;
	u64 ack_delay;
	u64 first_range;
	u32 range_count;
	bool has_ecn;
	u64 ect0;
	u64 ect1;
	u64 ce;
	u64 receive_timestamp;
};

/*
 * =============================================================================
 * Variable-Length Integer Encoding/Decoding Helpers
 * =============================================================================
 */

static size_t test_varint_size(u64 value)
{
	if (value <= 63)
		return 1;
	if (value <= 16383)
		return 2;
	if (value <= 1073741823ULL)
		return 4;
	return 8;
}

static int test_varint_encode(u8 *buf, size_t buf_len, u64 value)
{
	size_t len = test_varint_size(value);

	if (buf_len < len)
		return -ENOBUFS;

	if (len == 1) {
		buf[0] = (u8)value;
	} else if (len == 2) {
		buf[0] = (u8)(0x40 | (value >> 8));
		buf[1] = (u8)(value & 0xff);
	} else if (len == 4) {
		buf[0] = (u8)(0x80 | (value >> 24));
		buf[1] = (u8)((value >> 16) & 0xff);
		buf[2] = (u8)((value >> 8) & 0xff);
		buf[3] = (u8)(value & 0xff);
	} else {
		buf[0] = (u8)(0xc0 | (value >> 56));
		buf[1] = (u8)((value >> 48) & 0xff);
		buf[2] = (u8)((value >> 40) & 0xff);
		buf[3] = (u8)((value >> 32) & 0xff);
		buf[4] = (u8)((value >> 24) & 0xff);
		buf[5] = (u8)((value >> 16) & 0xff);
		buf[6] = (u8)((value >> 8) & 0xff);
		buf[7] = (u8)(value & 0xff);
	}

	return len;
}

static int test_varint_decode(const u8 *buf, size_t buf_len, u64 *value)
{
	size_t len;
	u8 prefix;

	if (buf_len < 1)
		return -EINVAL;

	prefix = buf[0] >> 6;
	len = 1 << prefix;

	if (buf_len < len)
		return -EINVAL;

	switch (len) {
	case 1:
		*value = buf[0] & 0x3f;
		break;
	case 2:
		*value = ((u64)(buf[0] & 0x3f) << 8) | buf[1];
		break;
	case 4:
		*value = ((u64)(buf[0] & 0x3f) << 24) |
			 ((u64)buf[1] << 16) |
			 ((u64)buf[2] << 8) |
			 buf[3];
		break;
	case 8:
		*value = ((u64)(buf[0] & 0x3f) << 56) |
			 ((u64)buf[1] << 48) |
			 ((u64)buf[2] << 40) |
			 ((u64)buf[3] << 32) |
			 ((u64)buf[4] << 24) |
			 ((u64)buf[5] << 16) |
			 ((u64)buf[6] << 8) |
			 buf[7];
		break;
	}

	return len;
}

/*
 * =============================================================================
 * OWD State Management Helpers
 * =============================================================================
 */

static void test_owd_state_init(struct test_owd_state *state, u64 resolution_us)
{
	memset(state, 0, sizeof(*state));
	state->local_resolution_us = resolution_us;
	state->effective_resolution_us = resolution_us;
	state->min_forward_us = S64_MAX;
	state->min_reverse_us = S64_MAX;
	state->reference_time = ktime_get();
}

static int test_owd_enable(struct test_owd_state *state, u64 peer_resolution_us)
{
	if (peer_resolution_us < TEST_OWD_MIN_RESOLUTION_US ||
	    peer_resolution_us > TEST_OWD_MAX_RESOLUTION_US)
		return -ERANGE;

	state->peer_resolution_us = peer_resolution_us;
	state->effective_resolution_us = max(state->local_resolution_us,
					     peer_resolution_us);
	state->flags |= TEST_OWD_FLAG_ENABLED;
	return 0;
}

static bool test_owd_is_enabled(const struct test_owd_state *state)
{
	return state && (state->flags & TEST_OWD_FLAG_ENABLED);
}

static u64 test_owd_ktime_to_timestamp(const struct test_owd_state *state,
				       ktime_t time)
{
	s64 delta_us;

	if (!state || state->effective_resolution_us == 0)
		return 0;

	delta_us = ktime_us_delta(time, state->reference_time);
	if (delta_us < 0)
		delta_us = 0;

	return (u64)delta_us / state->effective_resolution_us;
}

static s64 test_owd_timestamp_to_us(const struct test_owd_state *state,
				    u64 timestamp)
{
	if (!state || state->effective_resolution_us == 0)
		return 0;

	return (s64)timestamp * state->effective_resolution_us;
}

static void test_owd_update_sample(struct test_owd_state *state,
				   const struct test_owd_sample *sample)
{
	if (!sample->valid)
		return;

	/* Update minimum values */
	if (sample->forward_delay_us < state->min_forward_us)
		state->min_forward_us = sample->forward_delay_us;
	if (sample->reverse_delay_us < state->min_reverse_us)
		state->min_reverse_us = sample->reverse_delay_us;

	/* First sample initializes estimates */
	if (state->sample_count == 0) {
		state->forward_delay_us = sample->forward_delay_us;
		state->reverse_delay_us = sample->reverse_delay_us;
	} else {
		/* EWMA update with alpha = 1/8 */
		state->forward_delay_us +=
			(sample->forward_delay_us - state->forward_delay_us) >> 3;
		state->reverse_delay_us +=
			(sample->reverse_delay_us - state->reverse_delay_us) >> 3;
	}

	state->sample_count++;

	/* Mark as valid after enough samples */
	if (state->sample_count >= TEST_OWD_MIN_SAMPLES) {
		state->flags |= TEST_OWD_FLAG_FORWARD_VALID |
				TEST_OWD_FLAG_REVERSE_VALID;

		/* Check for asymmetry (>20% difference) */
		s64 diff = state->forward_delay_us - state->reverse_delay_us;
		if (diff < 0)
			diff = -diff;

		if (diff * 5 > (state->forward_delay_us + state->reverse_delay_us))
			state->flags |= TEST_OWD_FLAG_ASYMMETRIC;
		else
			state->flags &= ~TEST_OWD_FLAG_ASYMMETRIC;
	}
}

static u32 test_owd_get_asymmetry_ratio(const struct test_owd_state *state)
{
	if (!(state->flags & TEST_OWD_FLAG_FORWARD_VALID))
		return 1000;

	if (state->reverse_delay_us == 0)
		return 2000;

	return (u32)((state->forward_delay_us * 1000) / state->reverse_delay_us);
}

/*
 * =============================================================================
 * ACK_1WD Frame Encoding/Decoding
 * =============================================================================
 */

static int test_ack_1wd_frame_encode(u8 *buf, size_t buf_len,
				     const struct test_ack_1wd_frame *frame,
				     const struct test_owd_state *state,
				     ktime_t recv_time)
{
	size_t offset = 0;
	int ret;
	u64 frame_type;
	u64 timestamp;

	/* Frame type */
	frame_type = frame->has_ecn ? TEST_FRAME_ACK_1WD_ECN : TEST_FRAME_ACK_1WD;
	ret = test_varint_encode(buf + offset, buf_len - offset, frame_type);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Largest Acknowledged */
	ret = test_varint_encode(buf + offset, buf_len - offset,
				 frame->largest_acked);
	if (ret < 0)
		return ret;
	offset += ret;

	/* ACK Delay */
	ret = test_varint_encode(buf + offset, buf_len - offset,
				 frame->ack_delay);
	if (ret < 0)
		return ret;
	offset += ret;

	/* ACK Range Count */
	ret = test_varint_encode(buf + offset, buf_len - offset,
				 frame->range_count);
	if (ret < 0)
		return ret;
	offset += ret;

	/* First ACK Range */
	ret = test_varint_encode(buf + offset, buf_len - offset,
				 frame->first_range);
	if (ret < 0)
		return ret;
	offset += ret;

	/* ECN Counts (if present) */
	if (frame->has_ecn) {
		ret = test_varint_encode(buf + offset, buf_len - offset,
					 frame->ect0);
		if (ret < 0)
			return ret;
		offset += ret;

		ret = test_varint_encode(buf + offset, buf_len - offset,
					 frame->ect1);
		if (ret < 0)
			return ret;
		offset += ret;

		ret = test_varint_encode(buf + offset, buf_len - offset,
					 frame->ce);
		if (ret < 0)
			return ret;
		offset += ret;
	}

	/* Receive Timestamp */
	timestamp = test_owd_ktime_to_timestamp(state, recv_time);
	ret = test_varint_encode(buf + offset, buf_len - offset, timestamp);
	if (ret < 0)
		return ret;
	offset += ret;

	return offset;
}

static int test_ack_1wd_frame_decode(const u8 *buf, size_t buf_len,
				     struct test_ack_1wd_frame *frame)
{
	size_t offset = 0;
	u64 frame_type;
	int ret;

	memset(frame, 0, sizeof(*frame));

	/* Frame type */
	ret = test_varint_decode(buf + offset, buf_len - offset, &frame_type);
	if (ret < 0)
		return ret;
	offset += ret;

	if (frame_type == TEST_FRAME_ACK_1WD_ECN)
		frame->has_ecn = true;
	else if (frame_type != TEST_FRAME_ACK_1WD)
		return -EINVAL;

	/* Largest Acknowledged */
	ret = test_varint_decode(buf + offset, buf_len - offset,
				 &frame->largest_acked);
	if (ret < 0)
		return ret;
	offset += ret;

	/* ACK Delay */
	ret = test_varint_decode(buf + offset, buf_len - offset,
				 &frame->ack_delay);
	if (ret < 0)
		return ret;
	offset += ret;

	/* ACK Range Count */
	u64 range_count;
	ret = test_varint_decode(buf + offset, buf_len - offset, &range_count);
	if (ret < 0)
		return ret;
	offset += ret;
	frame->range_count = (u32)range_count;

	/* First ACK Range */
	ret = test_varint_decode(buf + offset, buf_len - offset,
				 &frame->first_range);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Skip additional ACK ranges */
	/* (simplified - just skip range_count * 2 varints) */

	/* ECN Counts (if present) */
	if (frame->has_ecn) {
		ret = test_varint_decode(buf + offset, buf_len - offset,
					 &frame->ect0);
		if (ret < 0)
			return ret;
		offset += ret;

		ret = test_varint_decode(buf + offset, buf_len - offset,
					 &frame->ect1);
		if (ret < 0)
			return ret;
		offset += ret;

		ret = test_varint_decode(buf + offset, buf_len - offset,
					 &frame->ce);
		if (ret < 0)
			return ret;
		offset += ret;
	}

	/* Receive Timestamp */
	ret = test_varint_decode(buf + offset, buf_len - offset,
				 &frame->receive_timestamp);
	if (ret < 0)
		return ret;
	offset += ret;

	return offset;
}

/*
 * =============================================================================
 * OWD Calculation Helpers
 * =============================================================================
 */

static int test_owd_calculate(const struct test_owd_state *state,
			      s64 send_time_us, u64 remote_recv_ts,
			      s64 ack_recv_time_us,
			      struct test_owd_sample *sample)
{
	s64 recv_time_us;
	s64 skew_us = 0;
	s64 forward, reverse;
	u64 rtt_us;

	memset(sample, 0, sizeof(*sample));

	/* Convert remote timestamp to microseconds */
	recv_time_us = test_owd_timestamp_to_us(state, remote_recv_ts);

	/* Calculate RTT for reference */
	rtt_us = ack_recv_time_us - send_time_us;
	if (rtt_us <= 0)
		return -EINVAL;

	sample->rtt_us = rtt_us;

	/* Get clock skew if available */
	if (state->flags & TEST_OWD_FLAG_SKEW_VALID)
		skew_us = state->clock_skew_us;

	/* Calculate forward delay (sender -> receiver) */
	forward = (recv_time_us - skew_us) - send_time_us;

	/* Calculate reverse delay (receiver -> sender) */
	reverse = ack_recv_time_us - (recv_time_us - skew_us);

	/* Sanity checks */
	if (forward < 0) {
		forward = rtt_us / 2;
		reverse = rtt_us - forward;
	} else if (reverse < 0) {
		reverse = rtt_us / 2;
		forward = rtt_us - reverse;
	}

	if (forward > (s64)rtt_us)
		forward = rtt_us;
	if (reverse > (s64)rtt_us)
		reverse = rtt_us;

	sample->forward_delay_us = forward;
	sample->reverse_delay_us = reverse;
	sample->valid = true;

	return 0;
}

/*
 * =============================================================================
 * SECTION 1: Transport Parameter Tests
 * =============================================================================
 */

/* Test: Encode/decode enable_one_way_delay transport parameter */
static void test_tp_owd_encode_decode(struct kunit *test)
{
	u8 buf[32];
	u64 resolution = 1000;  /* 1ms */
	u64 output;
	int offset = 0;
	int ret;

	/* ARRANGE/ACT: Encode parameter ID */
	ret = test_varint_encode(buf + offset, sizeof(buf) - offset,
				 TEST_TP_ENABLE_ONE_WAY_DELAY);
	KUNIT_EXPECT_GT(test, ret, 0);
	offset += ret;

	/* Encode value length */
	size_t value_len = test_varint_size(resolution);
	ret = test_varint_encode(buf + offset, sizeof(buf) - offset, value_len);
	KUNIT_EXPECT_GT(test, ret, 0);
	offset += ret;

	/* Encode value */
	ret = test_varint_encode(buf + offset, sizeof(buf) - offset, resolution);
	KUNIT_EXPECT_GT(test, ret, 0);
	offset += ret;

	/* ASSERT: Verify encoding */
	KUNIT_EXPECT_GT(test, offset, 0);

	/* ACT: Decode and verify */
	size_t decode_offset = 0;
	u64 param_id;
	ret = test_varint_decode(buf + decode_offset, offset, &param_id);
	KUNIT_EXPECT_GT(test, ret, 0);
	decode_offset += ret;
	KUNIT_EXPECT_EQ(test, param_id, TEST_TP_ENABLE_ONE_WAY_DELAY);

	ret = test_varint_decode(buf + decode_offset, offset - decode_offset,
				 &value_len);
	KUNIT_EXPECT_GT(test, ret, 0);
	decode_offset += ret;

	ret = test_varint_decode(buf + decode_offset, offset - decode_offset,
				 &output);
	KUNIT_EXPECT_GT(test, ret, 0);
	KUNIT_EXPECT_EQ(test, output, resolution);
}

/* Test: Default resolution value */
static void test_tp_owd_default_resolution(struct kunit *test)
{
	/* ARRANGE/ACT/ASSERT: Verify default is 1ms */
	KUNIT_EXPECT_EQ(test, (u64)TEST_OWD_DEFAULT_RESOLUTION_US, 1000ULL);
}

/* Test: Minimum resolution value */
static void test_tp_owd_min_resolution(struct kunit *test)
{
	struct test_owd_state state;

	/* ARRANGE */
	test_owd_state_init(&state, TEST_OWD_MIN_RESOLUTION_US);

	/* ACT */
	int ret = test_owd_enable(&state, TEST_OWD_MIN_RESOLUTION_US);

	/* ASSERT: Minimum resolution accepted */
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, state.effective_resolution_us, 1ULL);
}

/* Test: Maximum resolution value */
static void test_tp_owd_max_resolution(struct kunit *test)
{
	struct test_owd_state state;

	/* ARRANGE */
	test_owd_state_init(&state, TEST_OWD_MAX_RESOLUTION_US);

	/* ACT */
	int ret = test_owd_enable(&state, TEST_OWD_MAX_RESOLUTION_US);

	/* ASSERT: Maximum resolution accepted */
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, state.effective_resolution_us, 1000000ULL);
}

/* Test: Invalid resolution rejected */
static void test_tp_owd_invalid_resolution(struct kunit *test)
{
	struct test_owd_state state;

	/* ARRANGE */
	test_owd_state_init(&state, TEST_OWD_DEFAULT_RESOLUTION_US);

	/* ACT/ASSERT: Zero resolution rejected */
	int ret = test_owd_enable(&state, 0);
	KUNIT_EXPECT_LT(test, ret, 0);

	/* ACT/ASSERT: Overflow resolution rejected */
	ret = test_owd_enable(&state, TEST_OWD_MAX_RESOLUTION_US + 1);
	KUNIT_EXPECT_LT(test, ret, 0);
}

/*
 * =============================================================================
 * SECTION 2: ACK_1WD Frame Tests
 * =============================================================================
 */

/* Test: Encode and decode ACK_1WD frame */
static void test_ack_1wd_frame_roundtrip(struct kunit *test)
{
	u8 buf[128];
	struct test_owd_state state;
	struct test_ack_1wd_frame input = {
		.largest_acked = 100,
		.ack_delay = 5000,  /* 5ms in encoded units */
		.first_range = 10,
		.range_count = 0,
		.has_ecn = false,
	};
	struct test_ack_1wd_frame output;
	ktime_t recv_time;
	int ret;

	/* ARRANGE */
	test_owd_state_init(&state, TEST_OWD_DEFAULT_RESOLUTION_US);
	test_owd_enable(&state, TEST_OWD_DEFAULT_RESOLUTION_US);
	recv_time = ktime_add_us(state.reference_time, 50000);  /* 50ms offset */

	/* ACT: Encode */
	ret = test_ack_1wd_frame_encode(buf, sizeof(buf), &input, &state,
					recv_time);
	KUNIT_EXPECT_GT(test, ret, 0);

	/* ACT: Decode */
	int decode_ret = test_ack_1wd_frame_decode(buf, ret, &output);
	KUNIT_EXPECT_GT(test, decode_ret, 0);

	/* ASSERT: Values match */
	KUNIT_EXPECT_EQ(test, output.largest_acked, input.largest_acked);
	KUNIT_EXPECT_EQ(test, output.ack_delay, input.ack_delay);
	KUNIT_EXPECT_EQ(test, output.first_range, input.first_range);
	KUNIT_EXPECT_FALSE(test, output.has_ecn);

	/* Verify timestamp */
	u64 expected_ts = 50000 / TEST_OWD_DEFAULT_RESOLUTION_US;  /* 50 */
	KUNIT_EXPECT_EQ(test, output.receive_timestamp, expected_ts);
}

/* Test: ACK_1WD_ECN frame with ECN counts */
static void test_ack_1wd_ecn_frame(struct kunit *test)
{
	u8 buf[128];
	struct test_owd_state state;
	struct test_ack_1wd_frame input = {
		.largest_acked = 200,
		.ack_delay = 3000,
		.first_range = 5,
		.range_count = 0,
		.has_ecn = true,
		.ect0 = 150,
		.ect1 = 10,
		.ce = 2,
	};
	struct test_ack_1wd_frame output;
	ktime_t recv_time;
	int ret;

	/* ARRANGE */
	test_owd_state_init(&state, TEST_OWD_DEFAULT_RESOLUTION_US);
	test_owd_enable(&state, TEST_OWD_DEFAULT_RESOLUTION_US);
	recv_time = ktime_add_us(state.reference_time, 25000);

	/* ACT */
	ret = test_ack_1wd_frame_encode(buf, sizeof(buf), &input, &state,
					recv_time);
	KUNIT_EXPECT_GT(test, ret, 0);

	ret = test_ack_1wd_frame_decode(buf, ret, &output);
	KUNIT_EXPECT_GT(test, ret, 0);

	/* ASSERT: ECN counts preserved */
	KUNIT_EXPECT_TRUE(test, output.has_ecn);
	KUNIT_EXPECT_EQ(test, output.ect0, 150ULL);
	KUNIT_EXPECT_EQ(test, output.ect1, 10ULL);
	KUNIT_EXPECT_EQ(test, output.ce, 2ULL);
}

/* Test: Frame type validation */
static void test_ack_1wd_frame_type(struct kunit *test)
{
	u8 buf[8];
	struct test_ack_1wd_frame frame;
	int ret;

	/* ARRANGE: Create buffer with wrong frame type */
	ret = test_varint_encode(buf, sizeof(buf), 0x02);  /* Regular ACK */
	KUNIT_EXPECT_GT(test, ret, 0);

	/* ACT/ASSERT: Decoding should fail */
	ret = test_ack_1wd_frame_decode(buf, ret, &frame);
	KUNIT_EXPECT_LT(test, ret, 0);
}

/*
 * =============================================================================
 * SECTION 3: OWD Calculation Tests
 * =============================================================================
 */

/* Test: Calculate symmetric OWD (RTT/2 each direction) */
static void test_owd_calculate_symmetric(struct kunit *test)
{
	struct test_owd_state state;
	struct test_owd_sample sample;
	s64 send_time_us = 0;
	s64 ack_recv_time_us = 100000;  /* 100ms RTT */
	u64 remote_recv_ts;
	int ret;

	/* ARRANGE: Set up state with reference time at 0 */
	test_owd_state_init(&state, TEST_OWD_DEFAULT_RESOLUTION_US);
	test_owd_enable(&state, TEST_OWD_DEFAULT_RESOLUTION_US);
	state.clock_skew_us = 0;
	state.flags |= TEST_OWD_FLAG_SKEW_VALID;

	/* Remote received at 50ms (symmetric path) */
	remote_recv_ts = 50000 / state.effective_resolution_us;  /* 50 */

	/* ACT */
	ret = test_owd_calculate(&state, send_time_us, remote_recv_ts,
				 ack_recv_time_us, &sample);

	/* ASSERT */
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_TRUE(test, sample.valid);
	KUNIT_EXPECT_EQ(test, sample.rtt_us, 100000ULL);

	/* With symmetric path and no skew, forward ~= reverse ~= RTT/2 */
	KUNIT_EXPECT_EQ(test, sample.forward_delay_us, 50000LL);
	KUNIT_EXPECT_EQ(test, sample.reverse_delay_us, 50000LL);
}

/* Test: Calculate asymmetric OWD */
static void test_owd_calculate_asymmetric(struct kunit *test)
{
	struct test_owd_state state;
	struct test_owd_sample sample;
	s64 send_time_us = 0;
	s64 ack_recv_time_us = 100000;  /* 100ms RTT */
	u64 remote_recv_ts;
	int ret;

	/* ARRANGE */
	test_owd_state_init(&state, TEST_OWD_DEFAULT_RESOLUTION_US);
	test_owd_enable(&state, TEST_OWD_DEFAULT_RESOLUTION_US);
	state.clock_skew_us = 0;
	state.flags |= TEST_OWD_FLAG_SKEW_VALID;

	/* Remote received at 30ms (asymmetric - fast forward, slow reverse) */
	remote_recv_ts = 30000 / state.effective_resolution_us;  /* 30 */

	/* ACT */
	ret = test_owd_calculate(&state, send_time_us, remote_recv_ts,
				 ack_recv_time_us, &sample);

	/* ASSERT */
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_TRUE(test, sample.valid);

	/* Forward = 30ms, Reverse = 70ms */
	KUNIT_EXPECT_EQ(test, sample.forward_delay_us, 30000LL);
	KUNIT_EXPECT_EQ(test, sample.reverse_delay_us, 70000LL);
}

/* Test: Invalid timing rejected */
static void test_owd_calculate_invalid_timing(struct kunit *test)
{
	struct test_owd_state state;
	struct test_owd_sample sample;
	int ret;

	/* ARRANGE */
	test_owd_state_init(&state, TEST_OWD_DEFAULT_RESOLUTION_US);
	test_owd_enable(&state, TEST_OWD_DEFAULT_RESOLUTION_US);

	/* ACT/ASSERT: ACK received before send - invalid */
	ret = test_owd_calculate(&state, 100000, 50, 50000, &sample);
	KUNIT_EXPECT_LT(test, ret, 0);
}

/*
 * =============================================================================
 * SECTION 4: Clock Skew Tests
 * =============================================================================
 */

/* Test: Clock skew compensation */
static void test_owd_clock_skew_compensation(struct kunit *test)
{
	struct test_owd_state state;
	struct test_owd_sample sample;
	s64 send_time_us = 0;
	s64 ack_recv_time_us = 100000;
	u64 remote_recv_ts;
	int ret;

	/* ARRANGE: Remote clock is 10ms ahead */
	test_owd_state_init(&state, TEST_OWD_DEFAULT_RESOLUTION_US);
	test_owd_enable(&state, TEST_OWD_DEFAULT_RESOLUTION_US);
	state.clock_skew_us = 10000;  /* Remote is 10ms ahead */
	state.flags |= TEST_OWD_FLAG_SKEW_VALID;

	/*
	 * Remote timestamp shows 60ms (which includes 10ms skew).
	 * Real receive time was 50ms, but remote clock reads 60ms.
	 */
	remote_recv_ts = 60000 / state.effective_resolution_us;  /* 60 */

	/* ACT */
	ret = test_owd_calculate(&state, send_time_us, remote_recv_ts,
				 ack_recv_time_us, &sample);

	/* ASSERT: Skew should be compensated */
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_TRUE(test, sample.valid);

	/* After skew compensation: forward = 60-10 = 50ms */
	KUNIT_EXPECT_EQ(test, sample.forward_delay_us, 50000LL);
	KUNIT_EXPECT_EQ(test, sample.reverse_delay_us, 50000LL);
}

/*
 * =============================================================================
 * SECTION 5: State Management Tests
 * =============================================================================
 */

/* Test: Initial state is disabled */
static void test_owd_state_initial(struct kunit *test)
{
	struct test_owd_state state;

	/* ARRANGE/ACT */
	test_owd_state_init(&state, TEST_OWD_DEFAULT_RESOLUTION_US);

	/* ASSERT */
	KUNIT_EXPECT_FALSE(test, test_owd_is_enabled(&state));
	KUNIT_EXPECT_EQ(test, state.sample_count, 0ULL);
	KUNIT_EXPECT_EQ(test, state.forward_delay_us, 0LL);
	KUNIT_EXPECT_EQ(test, state.reverse_delay_us, 0LL);
}

/* Test: Enable sets proper state */
static void test_owd_state_enable(struct kunit *test)
{
	struct test_owd_state state;

	/* ARRANGE */
	test_owd_state_init(&state, 500);  /* 500us local resolution */

	/* ACT */
	int ret = test_owd_enable(&state, 1000);  /* 1000us peer resolution */

	/* ASSERT */
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_TRUE(test, test_owd_is_enabled(&state));
	/* Should use coarser (larger) resolution */
	KUNIT_EXPECT_EQ(test, state.effective_resolution_us, 1000ULL);
}

/* Test: Sample updates state */
static void test_owd_state_sample_update(struct kunit *test)
{
	struct test_owd_state state;
	struct test_owd_sample sample = {
		.forward_delay_us = 30000,
		.reverse_delay_us = 70000,
		.rtt_us = 100000,
		.valid = true,
	};

	/* ARRANGE */
	test_owd_state_init(&state, TEST_OWD_DEFAULT_RESOLUTION_US);
	test_owd_enable(&state, TEST_OWD_DEFAULT_RESOLUTION_US);

	/* ACT */
	test_owd_update_sample(&state, &sample);

	/* ASSERT: First sample initializes estimates */
	KUNIT_EXPECT_EQ(test, state.sample_count, 1ULL);
	KUNIT_EXPECT_EQ(test, state.forward_delay_us, 30000LL);
	KUNIT_EXPECT_EQ(test, state.reverse_delay_us, 70000LL);
	KUNIT_EXPECT_EQ(test, state.min_forward_us, 30000LL);
	KUNIT_EXPECT_EQ(test, state.min_reverse_us, 70000LL);
}

/* Test: Valid estimates after minimum samples */
static void test_owd_state_valid_estimates(struct kunit *test)
{
	struct test_owd_state state;
	struct test_owd_sample sample = {
		.forward_delay_us = 40000,
		.reverse_delay_us = 60000,
		.rtt_us = 100000,
		.valid = true,
	};
	int i;

	/* ARRANGE */
	test_owd_state_init(&state, TEST_OWD_DEFAULT_RESOLUTION_US);
	test_owd_enable(&state, TEST_OWD_DEFAULT_RESOLUTION_US);

	/* ACT: Add minimum number of samples */
	for (i = 0; i < TEST_OWD_MIN_SAMPLES; i++)
		test_owd_update_sample(&state, &sample);

	/* ASSERT: Estimates now valid */
	KUNIT_EXPECT_TRUE(test, state.flags & TEST_OWD_FLAG_FORWARD_VALID);
	KUNIT_EXPECT_TRUE(test, state.flags & TEST_OWD_FLAG_REVERSE_VALID);
}

/*
 * =============================================================================
 * SECTION 6: Asymmetric Path Detection Tests
 * =============================================================================
 */

/* Test: Symmetric path detection */
static void test_owd_symmetric_path(struct kunit *test)
{
	struct test_owd_state state;
	struct test_owd_sample sample = {
		.forward_delay_us = 50000,
		.reverse_delay_us = 50000,
		.rtt_us = 100000,
		.valid = true,
	};
	int i;

	/* ARRANGE */
	test_owd_state_init(&state, TEST_OWD_DEFAULT_RESOLUTION_US);
	test_owd_enable(&state, TEST_OWD_DEFAULT_RESOLUTION_US);

	/* ACT */
	for (i = 0; i < TEST_OWD_MIN_SAMPLES; i++)
		test_owd_update_sample(&state, &sample);

	/* ASSERT: Not asymmetric */
	KUNIT_EXPECT_FALSE(test, state.flags & TEST_OWD_FLAG_ASYMMETRIC);
	KUNIT_EXPECT_EQ(test, test_owd_get_asymmetry_ratio(&state), 1000U);
}

/* Test: Asymmetric path detection - forward heavy */
static void test_owd_asymmetric_forward_heavy(struct kunit *test)
{
	struct test_owd_state state;
	struct test_owd_sample sample = {
		.forward_delay_us = 70000,  /* 70ms */
		.reverse_delay_us = 30000,  /* 30ms */
		.rtt_us = 100000,
		.valid = true,
	};
	int i;

	/* ARRANGE */
	test_owd_state_init(&state, TEST_OWD_DEFAULT_RESOLUTION_US);
	test_owd_enable(&state, TEST_OWD_DEFAULT_RESOLUTION_US);

	/* ACT */
	for (i = 0; i < TEST_OWD_MIN_SAMPLES; i++)
		test_owd_update_sample(&state, &sample);

	/* ASSERT: Detected as asymmetric */
	KUNIT_EXPECT_TRUE(test, state.flags & TEST_OWD_FLAG_ASYMMETRIC);

	/* Ratio = 70000/30000 * 1000 = 2333 */
	u32 ratio = test_owd_get_asymmetry_ratio(&state);
	KUNIT_EXPECT_GT(test, ratio, 2000U);
}

/* Test: Asymmetric path detection - reverse heavy */
static void test_owd_asymmetric_reverse_heavy(struct kunit *test)
{
	struct test_owd_state state;
	struct test_owd_sample sample = {
		.forward_delay_us = 20000,  /* 20ms */
		.reverse_delay_us = 80000,  /* 80ms */
		.rtt_us = 100000,
		.valid = true,
	};
	int i;

	/* ARRANGE */
	test_owd_state_init(&state, TEST_OWD_DEFAULT_RESOLUTION_US);
	test_owd_enable(&state, TEST_OWD_DEFAULT_RESOLUTION_US);

	/* ACT */
	for (i = 0; i < TEST_OWD_MIN_SAMPLES; i++)
		test_owd_update_sample(&state, &sample);

	/* ASSERT: Detected as asymmetric */
	KUNIT_EXPECT_TRUE(test, state.flags & TEST_OWD_FLAG_ASYMMETRIC);

	/* Ratio = 20000/80000 * 1000 = 250 */
	u32 ratio = test_owd_get_asymmetry_ratio(&state);
	KUNIT_EXPECT_LT(test, ratio, 500U);
}

/* Test: EWMA smoothing */
static void test_owd_ewma_smoothing(struct kunit *test)
{
	struct test_owd_state state;
	struct test_owd_sample sample1 = {
		.forward_delay_us = 40000,
		.reverse_delay_us = 60000,
		.rtt_us = 100000,
		.valid = true,
	};
	struct test_owd_sample sample2 = {
		.forward_delay_us = 80000,
		.reverse_delay_us = 20000,
		.rtt_us = 100000,
		.valid = true,
	};

	/* ARRANGE */
	test_owd_state_init(&state, TEST_OWD_DEFAULT_RESOLUTION_US);
	test_owd_enable(&state, TEST_OWD_DEFAULT_RESOLUTION_US);

	/* ACT: First sample */
	test_owd_update_sample(&state, &sample1);
	s64 forward_after_first = state.forward_delay_us;

	/* ACT: Second sample */
	test_owd_update_sample(&state, &sample2);

	/* ASSERT: EWMA applied (alpha = 1/8) */
	/* New = Old + (Sample - Old) / 8 */
	/* Expected forward: 40000 + (80000 - 40000) / 8 = 40000 + 5000 = 45000 */
	KUNIT_EXPECT_EQ(test, forward_after_first, 40000LL);
	KUNIT_EXPECT_EQ(test, state.forward_delay_us, 45000LL);

	/* Expected reverse: 60000 + (20000 - 60000) / 8 = 60000 - 5000 = 55000 */
	KUNIT_EXPECT_EQ(test, state.reverse_delay_us, 55000LL);
}

/* Test: Minimum values tracking */
static void test_owd_min_values(struct kunit *test)
{
	struct test_owd_state state;
	struct test_owd_sample samples[] = {
		{ .forward_delay_us = 50000, .reverse_delay_us = 50000, .valid = true },
		{ .forward_delay_us = 30000, .reverse_delay_us = 70000, .valid = true },
		{ .forward_delay_us = 40000, .reverse_delay_us = 60000, .valid = true },
		{ .forward_delay_us = 35000, .reverse_delay_us = 45000, .valid = true },
	};
	int i;

	/* ARRANGE */
	test_owd_state_init(&state, TEST_OWD_DEFAULT_RESOLUTION_US);
	test_owd_enable(&state, TEST_OWD_DEFAULT_RESOLUTION_US);

	/* ACT */
	for (i = 0; i < 4; i++)
		test_owd_update_sample(&state, &samples[i]);

	/* ASSERT: Minimum values tracked */
	KUNIT_EXPECT_EQ(test, state.min_forward_us, 30000LL);
	KUNIT_EXPECT_EQ(test, state.min_reverse_us, 45000LL);
}

/*
 * =============================================================================
 * Test Suite Definition
 * =============================================================================
 */

static struct kunit_case tquic_owd_test_cases[] = {
	/* Transport Parameter Tests */
	KUNIT_CASE(test_tp_owd_encode_decode),
	KUNIT_CASE(test_tp_owd_default_resolution),
	KUNIT_CASE(test_tp_owd_min_resolution),
	KUNIT_CASE(test_tp_owd_max_resolution),
	KUNIT_CASE(test_tp_owd_invalid_resolution),

	/* ACK_1WD Frame Tests */
	KUNIT_CASE(test_ack_1wd_frame_roundtrip),
	KUNIT_CASE(test_ack_1wd_ecn_frame),
	KUNIT_CASE(test_ack_1wd_frame_type),

	/* OWD Calculation Tests */
	KUNIT_CASE(test_owd_calculate_symmetric),
	KUNIT_CASE(test_owd_calculate_asymmetric),
	KUNIT_CASE(test_owd_calculate_invalid_timing),

	/* Clock Skew Tests */
	KUNIT_CASE(test_owd_clock_skew_compensation),

	/* State Management Tests */
	KUNIT_CASE(test_owd_state_initial),
	KUNIT_CASE(test_owd_state_enable),
	KUNIT_CASE(test_owd_state_sample_update),
	KUNIT_CASE(test_owd_state_valid_estimates),

	/* Asymmetric Path Detection Tests */
	KUNIT_CASE(test_owd_symmetric_path),
	KUNIT_CASE(test_owd_asymmetric_forward_heavy),
	KUNIT_CASE(test_owd_asymmetric_reverse_heavy),
	KUNIT_CASE(test_owd_ewma_smoothing),
	KUNIT_CASE(test_owd_min_values),
	{}
};

static struct kunit_suite tquic_owd_test_suite = {
	.name = "tquic-one-way-delay",
	.test_cases = tquic_owd_test_cases,
};

kunit_test_suite(tquic_owd_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for TQUIC One-Way Delay Measurement Extension");
MODULE_AUTHOR("Linux Foundation");
