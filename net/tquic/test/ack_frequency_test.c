// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: ACK Frequency Extension KUnit Tests
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Comprehensive tests for ACK frequency extension (draft-ietf-quic-ack-frequency):
 *   - Transport parameter encoding/decoding
 *   - ACK_FREQUENCY frame parsing and generation
 *   - IMMEDIATE_ACK frame parsing
 *   - Negotiation state machine transitions
 *   - Dynamic adjustment triggers
 *
 * Test Structure:
 *   Section 1: Transport Parameter Tests
 *   Section 2: ACK_FREQUENCY Frame Tests
 *   Section 3: IMMEDIATE_ACK Frame Tests
 *   Section 4: State Machine Transition Tests
 *   Section 5: Dynamic Adjustment Tests
 */

#include <kunit/test.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/jiffies.h>

/*
 * =============================================================================
 * Test Constants (mirror production values)
 * =============================================================================
 */

#define TQUIC_FRAME_ACK_FREQUENCY	0xafULL
#define TQUIC_FRAME_IMMEDIATE_ACK	0x1fULL
#define TQUIC_TP_MIN_ACK_DELAY		0xff04de1aULL

#define TQUIC_ACK_FREQ_DEFAULT_THRESHOLD	2
#define TQUIC_ACK_FREQ_DEFAULT_MAX_DELAY_US	25000
#define TQUIC_ACK_FREQ_DEFAULT_REORDER_THRESHOLD 1

#define TQUIC_MIN_ACK_DELAY_MIN_US	1
#define TQUIC_MIN_ACK_DELAY_MAX_US	16383000
#define TQUIC_ACK_FREQ_MAX_THRESHOLD	255
#define TQUIC_ACK_FREQ_MAX_REORDER	255

/*
 * =============================================================================
 * Test Data Structures
 * =============================================================================
 */

/**
 * enum test_ack_freq_nego_state - Mirror production state enum
 */
enum test_ack_freq_nego_state {
	TEST_ACK_FREQ_STATE_DISABLED = 0,
	TEST_ACK_FREQ_STATE_PENDING,
	TEST_ACK_FREQ_STATE_NEGOTIATED,
	TEST_ACK_FREQ_STATE_ACTIVE,
	TEST_ACK_FREQ_STATE_ERROR,
};

/**
 * enum test_ack_freq_adjustment_reason - Mirror production adjustment reasons
 */
enum test_ack_freq_adjustment_reason {
	TEST_ACK_FREQ_REASON_NONE = 0,
	TEST_ACK_FREQ_REASON_CONGESTION,
	TEST_ACK_FREQ_REASON_HIGH_RTT,
	TEST_ACK_FREQ_REASON_LOW_RTT,
	TEST_ACK_FREQ_REASON_REORDERING,
	TEST_ACK_FREQ_REASON_APPLICATION,
	TEST_ACK_FREQ_REASON_BANDWIDTH,
	TEST_ACK_FREQ_REASON_ECN,
};

/**
 * struct test_ack_frequency_frame - Mirror production frame structure
 */
struct test_ack_frequency_frame {
	u64 sequence_number;
	u64 ack_eliciting_threshold;
	u64 request_max_ack_delay;
	u64 reorder_threshold;
};

/**
 * struct test_ack_frequency_state - Simplified state for testing
 */
struct test_ack_frequency_state {
	enum test_ack_freq_nego_state nego_state;
	bool enabled;
	u64 min_ack_delay_us;
	u64 peer_min_ack_delay_us;
	u64 last_sent_seq;
	u64 last_recv_seq;
	u64 current_threshold;
	u64 current_max_delay_us;
	u64 current_reorder_threshold;
	bool immediate_ack_pending;
	bool ack_frequency_pending;
	u64 packets_since_ack;
	enum test_ack_freq_adjustment_reason last_adjustment_reason;
	bool in_congestion;
	u64 frames_sent;
	u64 frames_received;
};

/*
 * =============================================================================
 * Variable-Length Integer Encoding/Decoding Helpers
 * =============================================================================
 */

/**
 * test_varint_size - Get number of bytes needed for varint
 * @value: Value to encode
 *
 * Returns: 1, 2, 4, or 8 bytes
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

/**
 * test_varint_encode - Encode variable-length integer
 * @buf: Output buffer
 * @buf_len: Buffer length
 * @value: Value to encode
 *
 * Returns: Bytes written, or negative error
 */
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

/**
 * test_varint_decode - Decode variable-length integer
 * @buf: Input buffer
 * @buf_len: Buffer length
 * @value: Output value
 *
 * Returns: Bytes consumed, or negative error
 */
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
 * ACK Frequency Frame Encoding/Decoding
 * =============================================================================
 */

/**
 * test_ack_freq_frame_encode - Encode ACK_FREQUENCY frame
 * @buf: Output buffer
 * @buf_len: Buffer length
 * @frame: Frame to encode
 *
 * Returns: Bytes written, or negative error
 */
static int test_ack_freq_frame_encode(u8 *buf, size_t buf_len,
				      const struct test_ack_frequency_frame *frame)
{
	size_t offset = 0;
	int ret;

	/* Frame type */
	ret = test_varint_encode(buf + offset, buf_len - offset,
				 TQUIC_FRAME_ACK_FREQUENCY);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Sequence number */
	ret = test_varint_encode(buf + offset, buf_len - offset,
				 frame->sequence_number);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Ack-eliciting threshold */
	ret = test_varint_encode(buf + offset, buf_len - offset,
				 frame->ack_eliciting_threshold);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Request max ACK delay */
	ret = test_varint_encode(buf + offset, buf_len - offset,
				 frame->request_max_ack_delay);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Reorder threshold */
	ret = test_varint_encode(buf + offset, buf_len - offset,
				 frame->reorder_threshold);
	if (ret < 0)
		return ret;
	offset += ret;

	return offset;
}

/**
 * test_ack_freq_frame_decode - Decode ACK_FREQUENCY frame
 * @buf: Input buffer (starting at frame type)
 * @buf_len: Buffer length
 * @frame: Output frame
 *
 * Returns: Bytes consumed, or negative error
 */
static int test_ack_freq_frame_decode(const u8 *buf, size_t buf_len,
				      struct test_ack_frequency_frame *frame)
{
	size_t offset = 0;
	u64 frame_type;
	int ret;

	/* Frame type */
	ret = test_varint_decode(buf + offset, buf_len - offset, &frame_type);
	if (ret < 0)
		return ret;
	if (frame_type != TQUIC_FRAME_ACK_FREQUENCY)
		return -EINVAL;
	offset += ret;

	/* Sequence number */
	ret = test_varint_decode(buf + offset, buf_len - offset,
				 &frame->sequence_number);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Ack-eliciting threshold */
	ret = test_varint_decode(buf + offset, buf_len - offset,
				 &frame->ack_eliciting_threshold);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Request max ACK delay */
	ret = test_varint_decode(buf + offset, buf_len - offset,
				 &frame->request_max_ack_delay);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Reorder threshold */
	ret = test_varint_decode(buf + offset, buf_len - offset,
				 &frame->reorder_threshold);
	if (ret < 0)
		return ret;
	offset += ret;

	return offset;
}

/**
 * test_immediate_ack_encode - Encode IMMEDIATE_ACK frame
 * @buf: Output buffer
 * @buf_len: Buffer length
 *
 * Returns: Bytes written, or negative error
 */
static int test_immediate_ack_encode(u8 *buf, size_t buf_len)
{
	return test_varint_encode(buf, buf_len, TQUIC_FRAME_IMMEDIATE_ACK);
}

/**
 * test_immediate_ack_decode - Decode IMMEDIATE_ACK frame
 * @buf: Input buffer
 * @buf_len: Buffer length
 *
 * Returns: Bytes consumed, or negative error
 */
static int test_immediate_ack_decode(const u8 *buf, size_t buf_len)
{
	u64 frame_type;
	int ret;

	ret = test_varint_decode(buf, buf_len, &frame_type);
	if (ret < 0)
		return ret;
	if (frame_type != TQUIC_FRAME_IMMEDIATE_ACK)
		return -EINVAL;
	return ret;
}

/*
 * =============================================================================
 * State Management Helpers
 * =============================================================================
 */

/**
 * test_ack_freq_state_init - Initialize test ACK frequency state
 * @state: State to initialize
 */
static void test_ack_freq_state_init(struct test_ack_frequency_state *state)
{
	memset(state, 0, sizeof(*state));
	state->nego_state = TEST_ACK_FREQ_STATE_DISABLED;
	state->min_ack_delay_us = 1000;  /* 1ms default */
	state->current_threshold = TQUIC_ACK_FREQ_DEFAULT_THRESHOLD;
	state->current_max_delay_us = TQUIC_ACK_FREQ_DEFAULT_MAX_DELAY_US;
	state->current_reorder_threshold = TQUIC_ACK_FREQ_DEFAULT_REORDER_THRESHOLD;
}

/**
 * test_ack_freq_enable - Enable ACK frequency extension
 * @state: State to enable
 * @peer_min_ack_delay: Peer's min_ack_delay
 */
static void test_ack_freq_enable(struct test_ack_frequency_state *state,
				 u64 peer_min_ack_delay)
{
	state->peer_min_ack_delay_us = peer_min_ack_delay;
	state->enabled = true;
	state->nego_state = TEST_ACK_FREQ_STATE_NEGOTIATED;
}

/**
 * test_ack_freq_handle_frame - Handle received ACK_FREQUENCY frame
 * @state: ACK frequency state
 * @frame: Received frame
 *
 * Returns: 0 on success, -EINVAL if old sequence number
 */
static int test_ack_freq_handle_frame(struct test_ack_frequency_state *state,
				      const struct test_ack_frequency_frame *frame)
{
	/* Only process if sequence number is larger than last received */
	if (state->last_recv_seq > 0 &&
	    frame->sequence_number <= state->last_recv_seq)
		return -EINVAL;

	/* Validate threshold */
	if (frame->ack_eliciting_threshold > TQUIC_ACK_FREQ_MAX_THRESHOLD)
		return -EINVAL;

	/* Validate max delay (cannot be less than peer's min_ack_delay) */
	if (frame->request_max_ack_delay < state->min_ack_delay_us)
		return -EINVAL;

	/* Update state */
	state->last_recv_seq = frame->sequence_number;
	state->current_threshold = frame->ack_eliciting_threshold;
	state->current_max_delay_us = frame->request_max_ack_delay;
	state->current_reorder_threshold = frame->reorder_threshold;
	state->frames_received++;

	if (state->nego_state == TEST_ACK_FREQ_STATE_NEGOTIATED)
		state->nego_state = TEST_ACK_FREQ_STATE_ACTIVE;

	return 0;
}

/**
 * test_ack_freq_handle_immediate_ack - Handle IMMEDIATE_ACK frame
 * @state: ACK frequency state
 */
static void test_ack_freq_handle_immediate_ack(
	struct test_ack_frequency_state *state)
{
	state->immediate_ack_pending = true;
}

/**
 * test_ack_freq_should_ack - Determine if ACK should be sent
 * @state: ACK frequency state
 * @pn: Packet number received
 *
 * Returns: true if ACK should be sent
 */
static bool test_ack_freq_should_ack(struct test_ack_frequency_state *state,
				     u64 pn)
{
	/* Always ACK if immediate ACK pending */
	if (state->immediate_ack_pending) {
		state->immediate_ack_pending = false;
		state->packets_since_ack = 0;
		return true;
	}

	/* Increment packet counter */
	state->packets_since_ack++;

	/* ACK if threshold reached */
	if (state->packets_since_ack >= state->current_threshold) {
		state->packets_since_ack = 0;
		return true;
	}

	return false;
}

/**
 * test_ack_freq_on_congestion - Handle congestion event
 * @state: ACK frequency state
 * @in_congestion: Whether entering congestion
 */
static void test_ack_freq_on_congestion(struct test_ack_frequency_state *state,
					bool in_congestion)
{
	if (in_congestion && !state->in_congestion) {
		/* Reduce threshold to get more ACKs during congestion */
		state->current_threshold = 1;
		state->last_adjustment_reason = TEST_ACK_FREQ_REASON_CONGESTION;
	}
	state->in_congestion = in_congestion;
}

/*
 * =============================================================================
 * Transport Parameter Encoding/Decoding
 * =============================================================================
 */

/**
 * test_min_ack_delay_tp_encode - Encode min_ack_delay transport parameter
 * @min_ack_delay_us: Value in microseconds
 * @buf: Output buffer
 * @buf_len: Buffer length
 *
 * Returns: Bytes written, or negative error
 */
static int test_min_ack_delay_tp_encode(u64 min_ack_delay_us,
					u8 *buf, size_t buf_len)
{
	size_t offset = 0;
	int ret;

	/* Parameter ID */
	ret = test_varint_encode(buf + offset, buf_len - offset,
				 TQUIC_TP_MIN_ACK_DELAY);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Parameter value length */
	size_t value_len = test_varint_size(min_ack_delay_us);
	ret = test_varint_encode(buf + offset, buf_len - offset, value_len);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Parameter value */
	ret = test_varint_encode(buf + offset, buf_len - offset, min_ack_delay_us);
	if (ret < 0)
		return ret;
	offset += ret;

	return offset;
}

/**
 * test_min_ack_delay_tp_decode - Decode min_ack_delay transport parameter
 * @buf: Input buffer
 * @buf_len: Buffer length
 * @min_ack_delay_us: Output value
 *
 * Returns: Bytes consumed, or negative error
 */
static int test_min_ack_delay_tp_decode(const u8 *buf, size_t buf_len,
					u64 *min_ack_delay_us)
{
	size_t offset = 0;
	u64 param_id, value_len;
	int ret;

	/* Parameter ID */
	ret = test_varint_decode(buf + offset, buf_len - offset, &param_id);
	if (ret < 0)
		return ret;
	if (param_id != TQUIC_TP_MIN_ACK_DELAY)
		return -EINVAL;
	offset += ret;

	/* Parameter value length */
	ret = test_varint_decode(buf + offset, buf_len - offset, &value_len);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Parameter value */
	ret = test_varint_decode(buf + offset, buf_len - offset, min_ack_delay_us);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Validate */
	if (*min_ack_delay_us < TQUIC_MIN_ACK_DELAY_MIN_US ||
	    *min_ack_delay_us > TQUIC_MIN_ACK_DELAY_MAX_US)
		return -ERANGE;

	return offset;
}

/*
 * =============================================================================
 * SECTION 1: Transport Parameter Tests
 * =============================================================================
 */

/* Test: Encode/decode min_ack_delay transport parameter */
static void test_tp_min_ack_delay_encode_decode(struct kunit *test)
{
	u8 buf[32];
	u64 input_delay = 1000;  /* 1ms */
	u64 output_delay;
	int encode_ret, decode_ret;

	/* ARRANGE/ACT: Encode */
	encode_ret = test_min_ack_delay_tp_encode(input_delay, buf, sizeof(buf));

	/* ASSERT: Encoding succeeds */
	KUNIT_EXPECT_GT(test, encode_ret, 0);

	/* ACT: Decode */
	decode_ret = test_min_ack_delay_tp_decode(buf, encode_ret, &output_delay);

	/* ASSERT: Decoding succeeds and value matches */
	KUNIT_EXPECT_GT(test, decode_ret, 0);
	KUNIT_EXPECT_EQ(test, output_delay, input_delay);
}

/* Test: min_ack_delay at minimum value */
static void test_tp_min_ack_delay_minimum(struct kunit *test)
{
	u8 buf[32];
	u64 output_delay;
	int ret;

	/* ARRANGE/ACT: Encode minimum value */
	ret = test_min_ack_delay_tp_encode(TQUIC_MIN_ACK_DELAY_MIN_US,
					   buf, sizeof(buf));
	KUNIT_EXPECT_GT(test, ret, 0);

	ret = test_min_ack_delay_tp_decode(buf, sizeof(buf), &output_delay);
	KUNIT_EXPECT_GT(test, ret, 0);
	KUNIT_EXPECT_EQ(test, output_delay, (u64)TQUIC_MIN_ACK_DELAY_MIN_US);
}

/* Test: min_ack_delay at maximum value */
static void test_tp_min_ack_delay_maximum(struct kunit *test)
{
	u8 buf[32];
	u64 output_delay;
	int ret;

	/* ARRANGE/ACT: Encode maximum value */
	ret = test_min_ack_delay_tp_encode(TQUIC_MIN_ACK_DELAY_MAX_US,
					   buf, sizeof(buf));
	KUNIT_EXPECT_GT(test, ret, 0);

	ret = test_min_ack_delay_tp_decode(buf, sizeof(buf), &output_delay);
	KUNIT_EXPECT_GT(test, ret, 0);
	KUNIT_EXPECT_EQ(test, output_delay, (u64)TQUIC_MIN_ACK_DELAY_MAX_US);
}

/* Test: min_ack_delay with typical value (25ms) */
static void test_tp_min_ack_delay_typical(struct kunit *test)
{
	u8 buf[32];
	u64 typical_delay = 25000;  /* 25ms in microseconds */
	u64 output_delay;
	int ret;

	/* ARRANGE/ACT */
	ret = test_min_ack_delay_tp_encode(typical_delay, buf, sizeof(buf));
	KUNIT_EXPECT_GT(test, ret, 0);

	ret = test_min_ack_delay_tp_decode(buf, sizeof(buf), &output_delay);
	KUNIT_EXPECT_GT(test, ret, 0);
	KUNIT_EXPECT_EQ(test, output_delay, typical_delay);
}

/* Test: Encoding with insufficient buffer */
static void test_tp_encode_buffer_too_small(struct kunit *test)
{
	u8 buf[2];  /* Too small */
	int ret;

	/* ARRANGE/ACT/ASSERT: Should fail with small buffer */
	ret = test_min_ack_delay_tp_encode(1000, buf, sizeof(buf));
	KUNIT_EXPECT_LT(test, ret, 0);
}

/*
 * =============================================================================
 * SECTION 2: ACK_FREQUENCY Frame Tests
 * =============================================================================
 */

/* Test: Encode and decode ACK_FREQUENCY frame with typical values */
static void test_ack_freq_frame_roundtrip(struct kunit *test)
{
	u8 buf[64];
	struct test_ack_frequency_frame input = {
		.sequence_number = 1,
		.ack_eliciting_threshold = 2,
		.request_max_ack_delay = 25000,
		.reorder_threshold = 1,
	};
	struct test_ack_frequency_frame output;
	int encode_ret, decode_ret;

	/* ARRANGE/ACT: Encode */
	encode_ret = test_ack_freq_frame_encode(buf, sizeof(buf), &input);
	KUNIT_EXPECT_GT(test, encode_ret, 0);

	/* ACT: Decode */
	decode_ret = test_ack_freq_frame_decode(buf, encode_ret, &output);

	/* ASSERT: Roundtrip successful */
	KUNIT_EXPECT_EQ(test, decode_ret, encode_ret);
	KUNIT_EXPECT_EQ(test, output.sequence_number, input.sequence_number);
	KUNIT_EXPECT_EQ(test, output.ack_eliciting_threshold,
			input.ack_eliciting_threshold);
	KUNIT_EXPECT_EQ(test, output.request_max_ack_delay,
			input.request_max_ack_delay);
	KUNIT_EXPECT_EQ(test, output.reorder_threshold, input.reorder_threshold);
}

/* Test: ACK_FREQUENCY with large sequence number */
static void test_ack_freq_frame_large_seq(struct kunit *test)
{
	u8 buf[64];
	struct test_ack_frequency_frame input = {
		.sequence_number = 1000000,
		.ack_eliciting_threshold = 10,
		.request_max_ack_delay = 100000,
		.reorder_threshold = 5,
	};
	struct test_ack_frequency_frame output;
	int ret;

	/* ARRANGE/ACT */
	ret = test_ack_freq_frame_encode(buf, sizeof(buf), &input);
	KUNIT_EXPECT_GT(test, ret, 0);

	ret = test_ack_freq_frame_decode(buf, sizeof(buf), &output);
	KUNIT_EXPECT_GT(test, ret, 0);

	/* ASSERT */
	KUNIT_EXPECT_EQ(test, output.sequence_number, input.sequence_number);
}

/* Test: ACK_FREQUENCY with zero reorder threshold (ignore order) */
static void test_ack_freq_frame_ignore_order(struct kunit *test)
{
	u8 buf[64];
	struct test_ack_frequency_frame input = {
		.sequence_number = 1,
		.ack_eliciting_threshold = 4,
		.request_max_ack_delay = 50000,
		.reorder_threshold = 0,  /* Ignore reordering */
	};
	struct test_ack_frequency_frame output;
	int ret;

	/* ARRANGE/ACT */
	ret = test_ack_freq_frame_encode(buf, sizeof(buf), &input);
	KUNIT_EXPECT_GT(test, ret, 0);

	ret = test_ack_freq_frame_decode(buf, sizeof(buf), &output);
	KUNIT_EXPECT_GT(test, ret, 0);

	/* ASSERT: Zero reorder threshold preserved */
	KUNIT_EXPECT_EQ(test, output.reorder_threshold, 0ULL);
}

/* Test: ACK_FREQUENCY decode with truncated buffer */
static void test_ack_freq_frame_truncated(struct kunit *test)
{
	u8 buf[64];
	struct test_ack_frequency_frame frame = {
		.sequence_number = 1,
		.ack_eliciting_threshold = 2,
		.request_max_ack_delay = 25000,
		.reorder_threshold = 1,
	};
	struct test_ack_frequency_frame output;
	int ret;

	/* ARRANGE: Encode valid frame */
	ret = test_ack_freq_frame_encode(buf, sizeof(buf), &frame);
	KUNIT_EXPECT_GT(test, ret, 0);

	/* ACT/ASSERT: Decode with truncated buffer should fail */
	ret = test_ack_freq_frame_decode(buf, ret / 2, &output);
	KUNIT_EXPECT_LT(test, ret, 0);
}

/* Test: ACK_FREQUENCY with invalid frame type */
static void test_ack_freq_frame_wrong_type(struct kunit *test)
{
	u8 buf[4] = {0x00, 0x01, 0x02, 0x03};  /* Not ACK_FREQUENCY type */
	struct test_ack_frequency_frame output;
	int ret;

	/* ACT/ASSERT: Should fail with wrong frame type */
	ret = test_ack_freq_frame_decode(buf, sizeof(buf), &output);
	KUNIT_EXPECT_LT(test, ret, 0);
}

/*
 * =============================================================================
 * SECTION 3: IMMEDIATE_ACK Frame Tests
 * =============================================================================
 */

/* Test: Encode and decode IMMEDIATE_ACK frame */
static void test_immediate_ack_roundtrip(struct kunit *test)
{
	u8 buf[4];
	int encode_ret, decode_ret;

	/* ARRANGE/ACT: Encode */
	encode_ret = test_immediate_ack_encode(buf, sizeof(buf));
	KUNIT_EXPECT_GT(test, encode_ret, 0);

	/* ACT: Decode */
	decode_ret = test_immediate_ack_decode(buf, encode_ret);

	/* ASSERT */
	KUNIT_EXPECT_EQ(test, decode_ret, encode_ret);
}

/* Test: IMMEDIATE_ACK decode with empty buffer */
static void test_immediate_ack_empty_buffer(struct kunit *test)
{
	u8 buf[0];
	int ret;

	/* ACT/ASSERT: Should fail with empty buffer */
	ret = test_immediate_ack_decode(buf, 0);
	KUNIT_EXPECT_LT(test, ret, 0);
}

/* Test: IMMEDIATE_ACK decode with wrong frame type */
static void test_immediate_ack_wrong_type(struct kunit *test)
{
	u8 buf[1] = {0xaf};  /* ACK_FREQUENCY type, not IMMEDIATE_ACK */
	int ret;

	/* ACT/ASSERT: Should fail with wrong type */
	ret = test_immediate_ack_decode(buf, sizeof(buf));
	KUNIT_EXPECT_LT(test, ret, 0);
}

/*
 * =============================================================================
 * SECTION 4: State Machine Transition Tests
 * =============================================================================
 */

/* Test: Initial state is DISABLED */
static void test_state_initial_disabled(struct kunit *test)
{
	struct test_ack_frequency_state state;

	/* ARRANGE/ACT */
	test_ack_freq_state_init(&state);

	/* ASSERT */
	KUNIT_EXPECT_EQ(test, state.nego_state, TEST_ACK_FREQ_STATE_DISABLED);
	KUNIT_EXPECT_FALSE(test, state.enabled);
}

/* Test: Enable transitions to NEGOTIATED */
static void test_state_enable_negotiated(struct kunit *test)
{
	struct test_ack_frequency_state state;

	/* ARRANGE */
	test_ack_freq_state_init(&state);

	/* ACT */
	test_ack_freq_enable(&state, 1000);

	/* ASSERT */
	KUNIT_EXPECT_EQ(test, state.nego_state, TEST_ACK_FREQ_STATE_NEGOTIATED);
	KUNIT_EXPECT_TRUE(test, state.enabled);
	KUNIT_EXPECT_EQ(test, state.peer_min_ack_delay_us, 1000ULL);
}

/* Test: First ACK_FREQUENCY frame transitions to ACTIVE */
static void test_state_active_on_frame(struct kunit *test)
{
	struct test_ack_frequency_state state;
	struct test_ack_frequency_frame frame = {
		.sequence_number = 1,
		.ack_eliciting_threshold = 2,
		.request_max_ack_delay = 25000,
		.reorder_threshold = 1,
	};
	int ret;

	/* ARRANGE */
	test_ack_freq_state_init(&state);
	test_ack_freq_enable(&state, 1000);

	/* ACT */
	ret = test_ack_freq_handle_frame(&state, &frame);

	/* ASSERT */
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, state.nego_state, TEST_ACK_FREQ_STATE_ACTIVE);
	KUNIT_EXPECT_EQ(test, state.frames_received, 1ULL);
}

/* Test: Reject old sequence number */
static void test_state_reject_old_seq(struct kunit *test)
{
	struct test_ack_frequency_state state;
	struct test_ack_frequency_frame frame1 = {
		.sequence_number = 5,
		.ack_eliciting_threshold = 2,
		.request_max_ack_delay = 25000,
		.reorder_threshold = 1,
	};
	struct test_ack_frequency_frame frame2 = {
		.sequence_number = 3,  /* Old sequence number */
		.ack_eliciting_threshold = 4,
		.request_max_ack_delay = 50000,
		.reorder_threshold = 2,
	};
	int ret;

	/* ARRANGE */
	test_ack_freq_state_init(&state);
	test_ack_freq_enable(&state, 1000);
	test_ack_freq_handle_frame(&state, &frame1);

	/* ACT */
	ret = test_ack_freq_handle_frame(&state, &frame2);

	/* ASSERT: Old sequence number rejected */
	KUNIT_EXPECT_LT(test, ret, 0);
	KUNIT_EXPECT_EQ(test, state.current_threshold, 2ULL);  /* Unchanged */
	KUNIT_EXPECT_EQ(test, state.frames_received, 1ULL);  /* Only first counted */
}

/* Test: Accept newer sequence number */
static void test_state_accept_new_seq(struct kunit *test)
{
	struct test_ack_frequency_state state;
	struct test_ack_frequency_frame frame1 = {
		.sequence_number = 1,
		.ack_eliciting_threshold = 2,
		.request_max_ack_delay = 25000,
		.reorder_threshold = 1,
	};
	struct test_ack_frequency_frame frame2 = {
		.sequence_number = 2,
		.ack_eliciting_threshold = 4,
		.request_max_ack_delay = 50000,
		.reorder_threshold = 2,
	};
	int ret;

	/* ARRANGE */
	test_ack_freq_state_init(&state);
	test_ack_freq_enable(&state, 1000);
	test_ack_freq_handle_frame(&state, &frame1);

	/* ACT */
	ret = test_ack_freq_handle_frame(&state, &frame2);

	/* ASSERT: New sequence number accepted */
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, state.current_threshold, 4ULL);
	KUNIT_EXPECT_EQ(test, state.current_max_delay_us, 50000ULL);
	KUNIT_EXPECT_EQ(test, state.frames_received, 2ULL);
}

/* Test: Reject threshold above maximum */
static void test_state_reject_excessive_threshold(struct kunit *test)
{
	struct test_ack_frequency_state state;
	struct test_ack_frequency_frame frame = {
		.sequence_number = 1,
		.ack_eliciting_threshold = TQUIC_ACK_FREQ_MAX_THRESHOLD + 1,
		.request_max_ack_delay = 25000,
		.reorder_threshold = 1,
	};
	int ret;

	/* ARRANGE */
	test_ack_freq_state_init(&state);
	test_ack_freq_enable(&state, 1000);

	/* ACT */
	ret = test_ack_freq_handle_frame(&state, &frame);

	/* ASSERT: Invalid threshold rejected */
	KUNIT_EXPECT_LT(test, ret, 0);
}

/* Test: Reject max_delay below min_ack_delay */
static void test_state_reject_low_max_delay(struct kunit *test)
{
	struct test_ack_frequency_state state;
	struct test_ack_frequency_frame frame = {
		.sequence_number = 1,
		.ack_eliciting_threshold = 2,
		.request_max_ack_delay = 500,  /* Below min_ack_delay */
		.reorder_threshold = 1,
	};
	int ret;

	/* ARRANGE */
	test_ack_freq_state_init(&state);
	state.min_ack_delay_us = 1000;  /* Our min_ack_delay */
	test_ack_freq_enable(&state, 1000);

	/* ACT */
	ret = test_ack_freq_handle_frame(&state, &frame);

	/* ASSERT: Invalid max_delay rejected */
	KUNIT_EXPECT_LT(test, ret, 0);
}

/*
 * =============================================================================
 * SECTION 5: Dynamic Adjustment Tests
 * =============================================================================
 */

/* Test: Should ACK when threshold reached */
static void test_should_ack_threshold_reached(struct kunit *test)
{
	struct test_ack_frequency_state state;
	int i;
	bool should_ack;

	/* ARRANGE */
	test_ack_freq_state_init(&state);
	state.current_threshold = 5;

	/* ACT/ASSERT: First 4 packets should not trigger ACK */
	for (i = 1; i <= 4; i++) {
		should_ack = test_ack_freq_should_ack(&state, i);
		KUNIT_EXPECT_FALSE(test, should_ack);
	}

	/* ACT/ASSERT: 5th packet should trigger ACK */
	should_ack = test_ack_freq_should_ack(&state, 5);
	KUNIT_EXPECT_TRUE(test, should_ack);
	KUNIT_EXPECT_EQ(test, state.packets_since_ack, 0ULL);  /* Reset */
}

/* Test: IMMEDIATE_ACK forces ACK */
static void test_immediate_ack_forces_ack(struct kunit *test)
{
	struct test_ack_frequency_state state;
	bool should_ack;

	/* ARRANGE */
	test_ack_freq_state_init(&state);
	state.current_threshold = 10;  /* High threshold */

	/* ACT: Set immediate ACK pending */
	test_ack_freq_handle_immediate_ack(&state);
	KUNIT_EXPECT_TRUE(test, state.immediate_ack_pending);

	/* ACT/ASSERT: Next packet should trigger immediate ACK */
	should_ack = test_ack_freq_should_ack(&state, 1);
	KUNIT_EXPECT_TRUE(test, should_ack);
	KUNIT_EXPECT_FALSE(test, state.immediate_ack_pending);  /* Cleared */
}

/* Test: Congestion event reduces threshold */
static void test_congestion_reduces_threshold(struct kunit *test)
{
	struct test_ack_frequency_state state;

	/* ARRANGE */
	test_ack_freq_state_init(&state);
	state.current_threshold = 10;

	/* ACT: Enter congestion */
	test_ack_freq_on_congestion(&state, true);

	/* ASSERT: Threshold reduced to 1 for more ACKs */
	KUNIT_EXPECT_EQ(test, state.current_threshold, 1ULL);
	KUNIT_EXPECT_TRUE(test, state.in_congestion);
	KUNIT_EXPECT_EQ(test, state.last_adjustment_reason,
			TEST_ACK_FREQ_REASON_CONGESTION);
}

/* Test: Default values after initialization */
static void test_default_values(struct kunit *test)
{
	struct test_ack_frequency_state state;

	/* ARRANGE/ACT */
	test_ack_freq_state_init(&state);

	/* ASSERT: Check all default values */
	KUNIT_EXPECT_EQ(test, state.current_threshold,
			(u64)TQUIC_ACK_FREQ_DEFAULT_THRESHOLD);
	KUNIT_EXPECT_EQ(test, state.current_max_delay_us,
			(u64)TQUIC_ACK_FREQ_DEFAULT_MAX_DELAY_US);
	KUNIT_EXPECT_EQ(test, state.current_reorder_threshold,
			(u64)TQUIC_ACK_FREQ_DEFAULT_REORDER_THRESHOLD);
	KUNIT_EXPECT_EQ(test, state.packets_since_ack, 0ULL);
	KUNIT_EXPECT_FALSE(test, state.immediate_ack_pending);
	KUNIT_EXPECT_FALSE(test, state.in_congestion);
}

/* Test: Packet counter resets after ACK */
static void test_packet_counter_reset(struct kunit *test)
{
	struct test_ack_frequency_state state;
	int i;

	/* ARRANGE */
	test_ack_freq_state_init(&state);
	state.current_threshold = 3;

	/* ACT: Receive 3 packets, trigger ACK */
	for (i = 1; i <= 3; i++) {
		test_ack_freq_should_ack(&state, i);
	}

	/* ASSERT: Counter reset */
	KUNIT_EXPECT_EQ(test, state.packets_since_ack, 0ULL);

	/* ACT: Next packet increments counter again */
	test_ack_freq_should_ack(&state, 4);
	KUNIT_EXPECT_EQ(test, state.packets_since_ack, 1ULL);
}

/* Test: Frame statistics tracking */
static void test_frame_statistics(struct kunit *test)
{
	struct test_ack_frequency_state state;
	struct test_ack_frequency_frame frame1 = {
		.sequence_number = 1,
		.ack_eliciting_threshold = 2,
		.request_max_ack_delay = 25000,
		.reorder_threshold = 1,
	};
	struct test_ack_frequency_frame frame2 = {
		.sequence_number = 2,
		.ack_eliciting_threshold = 3,
		.request_max_ack_delay = 30000,
		.reorder_threshold = 1,
	};

	/* ARRANGE */
	test_ack_freq_state_init(&state);
	test_ack_freq_enable(&state, 1000);

	/* ACT */
	test_ack_freq_handle_frame(&state, &frame1);
	test_ack_freq_handle_frame(&state, &frame2);

	/* ASSERT */
	KUNIT_EXPECT_EQ(test, state.frames_received, 2ULL);
	KUNIT_EXPECT_EQ(test, state.last_recv_seq, 2ULL);
}

/*
 * =============================================================================
 * Test Suite Definition
 * =============================================================================
 */

static struct kunit_case tquic_ack_frequency_test_cases[] = {
	/* Transport Parameter Tests */
	KUNIT_CASE(test_tp_min_ack_delay_encode_decode),
	KUNIT_CASE(test_tp_min_ack_delay_minimum),
	KUNIT_CASE(test_tp_min_ack_delay_maximum),
	KUNIT_CASE(test_tp_min_ack_delay_typical),
	KUNIT_CASE(test_tp_encode_buffer_too_small),

	/* ACK_FREQUENCY Frame Tests */
	KUNIT_CASE(test_ack_freq_frame_roundtrip),
	KUNIT_CASE(test_ack_freq_frame_large_seq),
	KUNIT_CASE(test_ack_freq_frame_ignore_order),
	KUNIT_CASE(test_ack_freq_frame_truncated),
	KUNIT_CASE(test_ack_freq_frame_wrong_type),

	/* IMMEDIATE_ACK Frame Tests */
	KUNIT_CASE(test_immediate_ack_roundtrip),
	KUNIT_CASE(test_immediate_ack_empty_buffer),
	KUNIT_CASE(test_immediate_ack_wrong_type),

	/* State Machine Tests */
	KUNIT_CASE(test_state_initial_disabled),
	KUNIT_CASE(test_state_enable_negotiated),
	KUNIT_CASE(test_state_active_on_frame),
	KUNIT_CASE(test_state_reject_old_seq),
	KUNIT_CASE(test_state_accept_new_seq),
	KUNIT_CASE(test_state_reject_excessive_threshold),
	KUNIT_CASE(test_state_reject_low_max_delay),

	/* Dynamic Adjustment Tests */
	KUNIT_CASE(test_should_ack_threshold_reached),
	KUNIT_CASE(test_immediate_ack_forces_ack),
	KUNIT_CASE(test_congestion_reduces_threshold),
	KUNIT_CASE(test_default_values),
	KUNIT_CASE(test_packet_counter_reset),
	KUNIT_CASE(test_frame_statistics),
	{}
};

static struct kunit_suite tquic_ack_frequency_test_suite = {
	.name = "tquic-ack-frequency",
	.test_cases = tquic_ack_frequency_test_cases,
};

kunit_test_suite(tquic_ack_frequency_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for TQUIC ACK Frequency Extension");
MODULE_AUTHOR("Linux Foundation");
