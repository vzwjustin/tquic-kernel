// SPDX-License-Identifier: GPL-2.0-only
/*
 * KUnit tests for TQUIC flow control
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * QUIC uses credit-based flow control at both connection and stream levels.
 * Tests cover MAX_DATA, MAX_STREAM_DATA, and blocked states.
 */

#include <kunit/test.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <net/tquic.h>

/* Flow control test context */
struct flow_control_test_ctx {
	u64 max_data;		/* Connection-level max data */
	u64 data_sent;		/* Data already sent */
	u64 data_received;	/* Data already received */
	u64 max_stream_data;	/* Stream-level max data */
	u64 stream_offset;	/* Current stream offset */
	bool blocked;		/* Whether flow is blocked */
};

/**
 * fc_can_send - Check if flow control allows sending
 * @ctx: Flow control context
 * @bytes: Number of bytes to send
 *
 * Returns true if allowed, false if blocked
 */
static bool fc_can_send(struct flow_control_test_ctx *ctx, u64 bytes)
{
	return (ctx->data_sent + bytes) <= ctx->max_data;
}

/**
 * fc_send - Consume flow control credit
 * @ctx: Flow control context
 * @bytes: Number of bytes to send
 *
 * Returns 0 on success, -ENOSPC if blocked
 */
static int fc_send(struct flow_control_test_ctx *ctx, u64 bytes)
{
	if (!fc_can_send(ctx, bytes)) {
		ctx->blocked = true;
		return -ENOSPC;
	}

	ctx->data_sent += bytes;
	return 0;
}

/**
 * fc_update_max_data - Process MAX_DATA frame
 * @ctx: Flow control context
 * @new_max: New maximum data value
 *
 * Returns: true if limit increased, false otherwise
 */
static bool fc_update_max_data(struct flow_control_test_ctx *ctx, u64 new_max)
{
	if (new_max > ctx->max_data) {
		ctx->max_data = new_max;
		ctx->blocked = false;
		return true;
	}
	return false;
}

/**
 * fc_available - Get available flow control credit
 * @ctx: Flow control context
 *
 * Returns: Number of bytes that can be sent
 */
static u64 fc_available(struct flow_control_test_ctx *ctx)
{
	if (ctx->data_sent >= ctx->max_data)
		return 0;
	return ctx->max_data - ctx->data_sent;
}

/**
 * stream_fc_can_send - Check stream-level flow control
 * @ctx: Flow control context
 * @offset: Target stream offset
 * @bytes: Data length
 *
 * Returns true if allowed
 */
static bool stream_fc_can_send(struct flow_control_test_ctx *ctx,
			       u64 offset, u64 bytes)
{
	return (offset + bytes) <= ctx->max_stream_data;
}

/* Test: Initial flow control state */
static void tquic_fc_test_initial_state(struct kunit *test)
{
	struct flow_control_test_ctx ctx = {
		.max_data = tquic_get_validated_max_data(),
		.data_sent = 0,
		.data_received = 0,
		.blocked = false,
	};

	KUNIT_EXPECT_EQ(test, ctx.max_data, (u64)tquic_get_validated_max_data());
	KUNIT_EXPECT_EQ(test, ctx.data_sent, 0ULL);
	KUNIT_EXPECT_FALSE(test, ctx.blocked);
	KUNIT_EXPECT_EQ(test, fc_available(&ctx), (u64)tquic_get_validated_max_data());
}

/* Test: Basic flow control send */
static void tquic_fc_test_basic_send(struct kunit *test)
{
	struct flow_control_test_ctx ctx = {
		.max_data = 1000,
		.data_sent = 0,
		.blocked = false,
	};
	int ret;

	/* Should be able to send 500 bytes */
	KUNIT_EXPECT_TRUE(test, fc_can_send(&ctx, 500));

	ret = fc_send(&ctx, 500);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, ctx.data_sent, 500ULL);
	KUNIT_EXPECT_EQ(test, fc_available(&ctx), 500ULL);
	KUNIT_EXPECT_FALSE(test, ctx.blocked);
}

/* Test: Flow control blocking */
static void tquic_fc_test_blocking(struct kunit *test)
{
	struct flow_control_test_ctx ctx = {
		.max_data = 1000,
		.data_sent = 0,
		.blocked = false,
	};
	int ret;

	/* Send up to the limit */
	ret = fc_send(&ctx, 1000);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, ctx.data_sent, 1000ULL);
	KUNIT_EXPECT_EQ(test, fc_available(&ctx), 0ULL);

	/* Try to send more - should be blocked */
	KUNIT_EXPECT_FALSE(test, fc_can_send(&ctx, 1));

	ret = fc_send(&ctx, 1);
	KUNIT_EXPECT_EQ(test, ret, -ENOSPC);
	KUNIT_EXPECT_TRUE(test, ctx.blocked);
	KUNIT_EXPECT_EQ(test, ctx.data_sent, 1000ULL);  /* Unchanged */
}

/* Test: MAX_DATA update unblocks flow */
static void tquic_fc_test_max_data_update(struct kunit *test)
{
	struct flow_control_test_ctx ctx = {
		.max_data = 1000,
		.data_sent = 1000,
		.blocked = true,
	};
	bool updated;
	int ret;

	/* Receive MAX_DATA with higher limit */
	updated = fc_update_max_data(&ctx, 2000);
	KUNIT_EXPECT_TRUE(test, updated);
	KUNIT_EXPECT_EQ(test, ctx.max_data, 2000ULL);
	KUNIT_EXPECT_FALSE(test, ctx.blocked);
	KUNIT_EXPECT_EQ(test, fc_available(&ctx), 1000ULL);

	/* Should be able to send again */
	ret = fc_send(&ctx, 500);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

/* Test: MAX_DATA update with same or lower value */
static void tquic_fc_test_max_data_no_decrease(struct kunit *test)
{
	struct flow_control_test_ctx ctx = {
		.max_data = 2000,
		.data_sent = 1000,
		.blocked = false,
	};
	bool updated;

	/* MAX_DATA with same value should not update */
	updated = fc_update_max_data(&ctx, 2000);
	KUNIT_EXPECT_FALSE(test, updated);
	KUNIT_EXPECT_EQ(test, ctx.max_data, 2000ULL);

	/* MAX_DATA with lower value should not update */
	updated = fc_update_max_data(&ctx, 1500);
	KUNIT_EXPECT_FALSE(test, updated);
	KUNIT_EXPECT_EQ(test, ctx.max_data, 2000ULL);
}

/* Test: Stream-level flow control */
static void tquic_fc_test_stream_level(struct kunit *test)
{
	struct flow_control_test_ctx ctx = {
		.max_stream_data = tquic_get_validated_max_stream_data(),
		.stream_offset = 0,
	};

	/* Can send within limit */
	KUNIT_EXPECT_TRUE(test, stream_fc_can_send(&ctx, 0, 1000));
	KUNIT_EXPECT_TRUE(test, stream_fc_can_send(&ctx, 0, tquic_get_validated_max_stream_data()));

	/* Cannot exceed limit */
	KUNIT_EXPECT_FALSE(test, stream_fc_can_send(&ctx, 0,
						    tquic_get_validated_max_stream_data() + 1));

	/* Offset + length must not exceed */
	KUNIT_EXPECT_TRUE(test, stream_fc_can_send(&ctx, 1000, 100));
	ctx.max_stream_data = 1000;
	KUNIT_EXPECT_FALSE(test, stream_fc_can_send(&ctx, 500, 600));  /* 1100 > 1000 */
}

/* Test: Connection and stream flow control interaction */
static void tquic_fc_test_dual_level(struct kunit *test)
{
	struct flow_control_test_ctx ctx = {
		.max_data = 10000,		/* Connection limit */
		.max_stream_data = 5000,	/* Stream limit */
		.data_sent = 0,
		.stream_offset = 0,
	};

	/* Both limits should be checked */

	/* Within both limits */
	KUNIT_EXPECT_TRUE(test, fc_can_send(&ctx, 1000));
	KUNIT_EXPECT_TRUE(test, stream_fc_can_send(&ctx, 0, 1000));

	/* Exceeds stream limit but not connection */
	KUNIT_EXPECT_TRUE(test, fc_can_send(&ctx, 6000));
	KUNIT_EXPECT_FALSE(test, stream_fc_can_send(&ctx, 0, 6000));

	/* After sending on stream, check remaining */
	ctx.stream_offset = 4000;
	KUNIT_EXPECT_TRUE(test, stream_fc_can_send(&ctx, 4000, 1000));  /* 5000 total */
	KUNIT_EXPECT_FALSE(test, stream_fc_can_send(&ctx, 4000, 1001)); /* 5001 > 5000 */
}

/* Test: Flow control with multiple sends */
static void tquic_fc_test_multiple_sends(struct kunit *test)
{
	struct flow_control_test_ctx ctx = {
		.max_data = 10000,
		.data_sent = 0,
		.blocked = false,
	};
	int i, ret;

	/* Send 100 times, 100 bytes each */
	for (i = 0; i < 100; i++) {
		ret = fc_send(&ctx, 100);
		KUNIT_EXPECT_EQ(test, ret, 0);
	}

	KUNIT_EXPECT_EQ(test, ctx.data_sent, 10000ULL);
	KUNIT_EXPECT_EQ(test, fc_available(&ctx), 0ULL);

	/* Next send should fail */
	ret = fc_send(&ctx, 1);
	KUNIT_EXPECT_EQ(test, ret, -ENOSPC);
	KUNIT_EXPECT_TRUE(test, ctx.blocked);
}

/* Test: Flow control credit calculation */
static void tquic_fc_test_credit_calculation(struct kunit *test)
{
	struct flow_control_test_ctx ctx = {
		.max_data = 100000,
		.data_sent = 0,
	};

	/* Initial credit equals max_data */
	KUNIT_EXPECT_EQ(test, fc_available(&ctx), 100000ULL);

	/* After sending, credit decreases */
	fc_send(&ctx, 30000);
	KUNIT_EXPECT_EQ(test, fc_available(&ctx), 70000ULL);

	/* After more sending */
	fc_send(&ctx, 50000);
	KUNIT_EXPECT_EQ(test, fc_available(&ctx), 20000ULL);

	/* After reaching limit */
	fc_send(&ctx, 20000);
	KUNIT_EXPECT_EQ(test, fc_available(&ctx), 0ULL);
}

/* Test: DATA_BLOCKED condition detection */
static void tquic_fc_test_data_blocked(struct kunit *test)
{
	struct flow_control_test_ctx ctx = {
		.max_data = 5000,
		.data_sent = 5000,
		.blocked = false,
	};

	/* Should detect blocked state */
	KUNIT_EXPECT_FALSE(test, fc_can_send(&ctx, 1));
	KUNIT_EXPECT_EQ(test, fc_available(&ctx), 0ULL);

	/* Attempt to send should set blocked flag */
	fc_send(&ctx, 100);
	KUNIT_EXPECT_TRUE(test, ctx.blocked);
}

/* Test: Large flow control values */
static void tquic_fc_test_large_values(struct kunit *test)
{
	struct flow_control_test_ctx ctx = {
		.max_data = (1ULL << 62),  /* Very large value */
		.data_sent = 0,
		.blocked = false,
	};

	/* Should handle large values */
	KUNIT_EXPECT_TRUE(test, fc_can_send(&ctx, (1ULL << 40)));
	KUNIT_EXPECT_EQ(test, fc_available(&ctx), ctx.max_data);

	/* Send a large amount */
	fc_send(&ctx, (1ULL << 40));
	KUNIT_EXPECT_EQ(test, ctx.data_sent, (1ULL << 40));
}

/* Test: Flow control with zero limit (should block immediately) */
static void tquic_fc_test_zero_limit(struct kunit *test)
{
	struct flow_control_test_ctx ctx = {
		.max_data = 0,
		.data_sent = 0,
		.blocked = false,
	};

	/* Cannot send anything with zero limit */
	KUNIT_EXPECT_FALSE(test, fc_can_send(&ctx, 1));
	KUNIT_EXPECT_EQ(test, fc_available(&ctx), 0ULL);

	/* Sending should fail */
	int ret = fc_send(&ctx, 1);
	KUNIT_EXPECT_EQ(test, ret, -ENOSPC);
	KUNIT_EXPECT_TRUE(test, ctx.blocked);
}

/* Test: MAX_STREAM_DATA update */
static void tquic_fc_test_max_stream_data_update(struct kunit *test)
{
	struct flow_control_test_ctx ctx = {
		.max_stream_data = 1000,
		.stream_offset = 900,
	};

	/* Near limit */
	KUNIT_EXPECT_TRUE(test, stream_fc_can_send(&ctx, 900, 100));
	KUNIT_EXPECT_FALSE(test, stream_fc_can_send(&ctx, 900, 200));

	/* Update stream limit */
	ctx.max_stream_data = 2000;

	/* Now can send more */
	KUNIT_EXPECT_TRUE(test, stream_fc_can_send(&ctx, 900, 200));
	KUNIT_EXPECT_TRUE(test, stream_fc_can_send(&ctx, 900, 1100));
	KUNIT_EXPECT_FALSE(test, stream_fc_can_send(&ctx, 900, 1101));
}

/* Test: Auto-tuning simulation (increasing limits) */
static void tquic_fc_test_auto_tuning(struct kunit *test)
{
	struct flow_control_test_ctx ctx = {
		.max_data = 65536,  /* Initial 64KB */
		.data_sent = 0,
		.blocked = false,
	};
	int rounds = 0;

	/* Simulate auto-tuning: double limit when 50% consumed */
	while (ctx.max_data < (1 << 20)) {  /* Stop at 1MB */
		/* Send half the limit */
		fc_send(&ctx, ctx.max_data / 2);

		/* Simulate receiving MAX_DATA with doubled limit */
		fc_update_max_data(&ctx, ctx.max_data * 2);
		rounds++;
	}

	/* Should have doubled several times */
	KUNIT_EXPECT_GT(test, rounds, 0);
	KUNIT_EXPECT_GE(test, ctx.max_data, (u64)(1 << 20));
}

/* Test: Connection flow control limits */
static void tquic_fc_test_connection_limits(struct kunit *test)
{
	/* Verify default constants */
	KUNIT_EXPECT_EQ(test, tquic_get_validated_max_data(), (u64)(1 << 20));
	KUNIT_EXPECT_EQ(test, tquic_get_validated_max_stream_data(), (u64)(1 << 18));

	/* Stream default should be less than connection default */
	KUNIT_EXPECT_LT(test, (u64)tquic_get_validated_max_stream_data(),
			(u64)tquic_get_validated_max_data());
}

/* Test: Bidirectional stream flow control */
static void tquic_fc_test_bidi_stream(struct kunit *test)
{
	/*
	 * Bidirectional streams have separate flow control for each direction.
	 * Each direction has its own MAX_STREAM_DATA limit.
	 */
	struct flow_control_test_ctx send_ctx = {
		.max_stream_data = 10000,
		.stream_offset = 0,
	};
	struct flow_control_test_ctx recv_ctx = {
		.max_stream_data = 8000,
		.stream_offset = 0,
	};

	/* Send direction */
	KUNIT_EXPECT_TRUE(test, stream_fc_can_send(&send_ctx, 0, 10000));
	KUNIT_EXPECT_FALSE(test, stream_fc_can_send(&send_ctx, 0, 10001));

	/* Receive direction (independent) */
	KUNIT_EXPECT_TRUE(test, stream_fc_can_send(&recv_ctx, 0, 8000));
	KUNIT_EXPECT_FALSE(test, stream_fc_can_send(&recv_ctx, 0, 8001));

	/* Directions are independent */
	send_ctx.stream_offset = 5000;
	KUNIT_EXPECT_TRUE(test, stream_fc_can_send(&send_ctx, 5000, 5000));
	KUNIT_EXPECT_TRUE(test, stream_fc_can_send(&recv_ctx, 0, 8000));
}

/* Test: MAX_STREAMS limits */
static void tquic_fc_test_max_streams(struct kunit *test)
{
	u64 max_streams_bidi = TQUIC_MAX_STREAM_COUNT_BIDI;
	u64 max_streams_uni = TQUIC_MAX_STREAM_COUNT_UNI;

	/* Both should be large values */
	KUNIT_EXPECT_GT(test, max_streams_bidi, 0ULL);
	KUNIT_EXPECT_GT(test, max_streams_uni, 0ULL);

	/* These are default stream limits */
	KUNIT_EXPECT_GE(test, max_streams_bidi, 1ULL);
	KUNIT_EXPECT_GE(test, max_streams_uni, 1ULL);
	/* Stream IDs use varint encoding, so max is 2^62-1 */
	KUNIT_EXPECT_LE(test, max_streams_bidi, (1ULL << 62));
	KUNIT_EXPECT_LE(test, max_streams_uni, (1ULL << 62));
}

/* Test: Partial send when near limit */
static void tquic_fc_test_partial_send(struct kunit *test)
{
	struct flow_control_test_ctx ctx = {
		.max_data = 1000,
		.data_sent = 900,
		.blocked = false,
	};
	u64 available;

	available = fc_available(&ctx);
	KUNIT_EXPECT_EQ(test, available, 100ULL);

	/* Can send up to available amount */
	KUNIT_EXPECT_TRUE(test, fc_can_send(&ctx, 100));
	KUNIT_EXPECT_FALSE(test, fc_can_send(&ctx, 101));

	/* Send exactly available amount */
	fc_send(&ctx, 100);
	KUNIT_EXPECT_EQ(test, fc_available(&ctx), 0ULL);
}

static struct kunit_case tquic_fc_test_cases[] = {
	KUNIT_CASE(tquic_fc_test_initial_state),
	KUNIT_CASE(tquic_fc_test_basic_send),
	KUNIT_CASE(tquic_fc_test_blocking),
	KUNIT_CASE(tquic_fc_test_max_data_update),
	KUNIT_CASE(tquic_fc_test_max_data_no_decrease),
	KUNIT_CASE(tquic_fc_test_stream_level),
	KUNIT_CASE(tquic_fc_test_dual_level),
	KUNIT_CASE(tquic_fc_test_multiple_sends),
	KUNIT_CASE(tquic_fc_test_credit_calculation),
	KUNIT_CASE(tquic_fc_test_data_blocked),
	KUNIT_CASE(tquic_fc_test_large_values),
	KUNIT_CASE(tquic_fc_test_zero_limit),
	KUNIT_CASE(tquic_fc_test_max_stream_data_update),
	KUNIT_CASE(tquic_fc_test_auto_tuning),
	KUNIT_CASE(tquic_fc_test_connection_limits),
	KUNIT_CASE(tquic_fc_test_bidi_stream),
	KUNIT_CASE(tquic_fc_test_max_streams),
	KUNIT_CASE(tquic_fc_test_partial_send),
	{}
};

static struct kunit_suite tquic_fc_test_suite = {
	.name = "tquic-flow-control",
	.test_cases = tquic_fc_test_cases,
};

kunit_test_suite(tquic_fc_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for TQUIC flow control");
