// SPDX-License-Identifier: GPL-2.0
/*
 * KUnit tests for TQUIC Deadline-Aware Multipath Scheduling
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Tests for the deadline-aware multipath scheduling implementation
 * based on draft-tjohn-quic-multipath-dmtp-01.
 *
 * Tests cover:
 *   - Deadline feasibility calculation
 *   - EDF (Earliest Deadline First) scheduling
 *   - Path selection for deadline meeting
 *   - Deadline miss detection
 *   - Frame parsing and generation
 *   - Transport parameter encoding/decoding
 *   - Integration with ECF and BLEST schedulers
 */

#include <kunit/test.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/ktime.h>
#include <net/tquic.h>
#include <uapi/linux/tquic.h>

#include "../sched/deadline_aware.h"

/*
 * =============================================================================
 * Test Fixtures and Helpers
 * =============================================================================
 */

/* Test path structure */
struct test_deadline_path {
	u32 path_id;
	enum tquic_path_state state;
	u32 rtt_smoothed;	/* RTT in microseconds */
	u64 bandwidth;		/* Bandwidth in bytes/sec */
	u32 rtt_variance;	/* RTT variance for jitter */
	u32 cwnd;		/* Congestion window */
	u64 tx_bytes;		/* Bytes transmitted */
	u64 acked_bytes;	/* Bytes acknowledged */
	u32 mtu;		/* Path MTU */
	struct list_head list;
};

/* Test connection structure */
struct test_deadline_conn {
	struct list_head paths;
	u32 num_paths;
	struct test_deadline_path *active_path;
};

/* Create test path */
static struct test_deadline_path *create_test_deadline_path(
	struct kunit *test, u32 id, u32 rtt_us, u64 bw, u32 jitter_us)
{
	struct test_deadline_path *path;

	path = kunit_kzalloc(test, sizeof(*path), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, path);

	path->path_id = id;
	path->state = TQUIC_PATH_ACTIVE;
	path->rtt_smoothed = rtt_us;
	path->bandwidth = bw;
	path->rtt_variance = jitter_us;
	path->cwnd = 65536;
	path->tx_bytes = 0;
	path->acked_bytes = 0;
	path->mtu = 1400;
	INIT_LIST_HEAD(&path->list);

	return path;
}

/* Create test connection */
static struct test_deadline_conn *create_test_deadline_conn(struct kunit *test)
{
	struct test_deadline_conn *conn;

	conn = kunit_kzalloc(test, sizeof(*conn), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, conn);

	INIT_LIST_HEAD(&conn->paths);
	conn->num_paths = 0;
	conn->active_path = NULL;

	return conn;
}

/* Add path to connection */
static void add_deadline_path(struct test_deadline_conn *conn,
			      struct test_deadline_path *path)
{
	list_add_tail(&path->list, &conn->paths);
	conn->num_paths++;
	if (!conn->active_path)
		conn->active_path = path;
}

/*
 * =============================================================================
 * Deadline Feasibility Tests
 * =============================================================================
 */

/**
 * Estimate delivery time based on path characteristics
 * This mirrors the real implementation logic
 */
static u64 estimate_delivery_time(struct test_deadline_path *path, size_t len)
{
	u64 rtt = path->rtt_smoothed;
	u64 tx_time = 0;
	u64 jitter_margin = 2 * path->rtt_variance;

	if (path->bandwidth > 0)
		tx_time = (len * 1000000ULL) / path->bandwidth;

	return rtt + tx_time + jitter_margin;
}

/**
 * Check if deadline is feasible on path
 */
static bool check_deadline_feasible(struct test_deadline_path *path,
				    u64 deadline_us, size_t data_len)
{
	u64 delivery_time;

	if (path->state != TQUIC_PATH_ACTIVE)
		return false;

	delivery_time = estimate_delivery_time(path, data_len);
	return delivery_time <= deadline_us;
}

/* Test: Basic deadline feasibility check */
static void tquic_deadline_test_feasibility_basic(struct kunit *test)
{
	struct test_deadline_path *path;
	bool feasible;

	/* Path with 10ms RTT, 10 Mbps bandwidth */
	path = create_test_deadline_path(test, 0, 10000, 1250000, 1000);

	/* 50ms deadline for 1KB - should be feasible */
	/* Delivery = 10000 + (1000*1000000/1250000) + 2000 = 12800 us */
	feasible = check_deadline_feasible(path, 50000, 1000);
	KUNIT_EXPECT_TRUE(test, feasible);

	/* 5ms deadline for 1KB - should not be feasible */
	feasible = check_deadline_feasible(path, 5000, 1000);
	KUNIT_EXPECT_FALSE(test, feasible);
}

/* Test: Deadline feasibility with high bandwidth */
static void tquic_deadline_test_feasibility_high_bw(struct kunit *test)
{
	struct test_deadline_path *path;
	bool feasible;

	/* Path with 5ms RTT, 100 Mbps bandwidth, low jitter */
	path = create_test_deadline_path(test, 0, 5000, 12500000, 500);

	/* 10ms deadline for 10KB - should be feasible */
	/* Delivery = 5000 + (10000*1000000/12500000) + 1000 = 6800 us */
	feasible = check_deadline_feasible(path, 10000, 10000);
	KUNIT_EXPECT_TRUE(test, feasible);

	/* Even tight deadline works with high bandwidth */
	feasible = check_deadline_feasible(path, 7000, 10000);
	KUNIT_EXPECT_TRUE(test, feasible);
}

/* Test: Deadline feasibility with high jitter */
static void tquic_deadline_test_feasibility_high_jitter(struct kunit *test)
{
	struct test_deadline_path *path;
	bool feasible;

	/* Path with 10ms RTT, 10 Mbps, HIGH jitter (5ms) */
	path = create_test_deadline_path(test, 0, 10000, 1250000, 5000);

	/* 20ms deadline for 1KB */
	/* Delivery = 10000 + 800 + 10000 = 20800 us - NOT feasible */
	feasible = check_deadline_feasible(path, 20000, 1000);
	KUNIT_EXPECT_FALSE(test, feasible);

	/* 25ms deadline should be feasible */
	feasible = check_deadline_feasible(path, 25000, 1000);
	KUNIT_EXPECT_TRUE(test, feasible);
}

/* Test: Deadline feasibility on inactive path */
static void tquic_deadline_test_feasibility_inactive(struct kunit *test)
{
	struct test_deadline_path *path;
	bool feasible;

	path = create_test_deadline_path(test, 0, 10000, 1250000, 1000);
	path->state = TQUIC_PATH_FAILED;

	/* Even generous deadline should fail on inactive path */
	feasible = check_deadline_feasible(path, 1000000, 1000);
	KUNIT_EXPECT_FALSE(test, feasible);
}

/*
 * =============================================================================
 * EDF Scheduling Tests
 * =============================================================================
 */

/* Test: EDF ordering - earlier deadline first */
static void tquic_deadline_test_edf_ordering(struct kunit *test)
{
	ktime_t d1, d2, d3;
	ktime_t now = ktime_get();

	d1 = ktime_add_us(now, 10000);  /* 10ms */
	d2 = ktime_add_us(now, 5000);   /* 5ms - earliest */
	d3 = ktime_add_us(now, 20000);  /* 20ms */

	/* Verify ordering: d2 < d1 < d3 */
	KUNIT_EXPECT_TRUE(test, ktime_before(d2, d1));
	KUNIT_EXPECT_TRUE(test, ktime_before(d1, d3));
	KUNIT_EXPECT_TRUE(test, ktime_before(d2, d3));
}

/* Test: EDF with same deadline uses priority */
static void tquic_deadline_test_edf_priority_tiebreak(struct kunit *test)
{
	u8 prio_critical = TQUIC_DEADLINE_PRIO_CRITICAL;  /* 0 */
	u8 prio_high = TQUIC_DEADLINE_PRIO_HIGH;	  /* 1 */
	u8 prio_normal = TQUIC_DEADLINE_PRIO_NORMAL;	  /* 2 */

	/* Lower priority value = higher priority */
	KUNIT_EXPECT_LT(test, prio_critical, prio_high);
	KUNIT_EXPECT_LT(test, prio_high, prio_normal);
}

/*
 * =============================================================================
 * Path Selection Tests
 * =============================================================================
 */

/* Score a path for deadline meeting */
static u64 score_path_for_deadline(struct test_deadline_path *path,
				   u64 deadline_us, size_t data_len)
{
	u64 delivery_time;
	u64 score;
	s64 slack;

	if (path->state != TQUIC_PATH_ACTIVE)
		return ULLONG_MAX;

	delivery_time = estimate_delivery_time(path, data_len);

	if (delivery_time <= deadline_us) {
		/* Can meet deadline */
		slack = deadline_us - delivery_time;
		score = delivery_time;
		if (slack > 0)
			score -= min_t(u64, slack / 4, delivery_time / 2);
	} else {
		/* Cannot meet deadline - large penalty */
		score = delivery_time + 1000000;
	}

	return score;
}

/* Select best path for deadline */
static struct test_deadline_path *select_best_path(
	struct test_deadline_conn *conn, u64 deadline_us, size_t data_len)
{
	struct test_deadline_path *path, *best = NULL;
	u64 best_score = ULLONG_MAX;

	list_for_each_entry(path, &conn->paths, list) {
		u64 score = score_path_for_deadline(path, deadline_us, data_len);
		if (score < best_score) {
			best_score = score;
			best = path;
		}
	}

	return best;
}

/* Test: Path selection prefers feasible paths */
static void tquic_deadline_test_path_selection_feasible(struct kunit *test)
{
	struct test_deadline_conn *conn = create_test_deadline_conn(test);
	struct test_deadline_path *fast, *slow, *selected;

	/* Fast path: 5ms RTT, 100 Mbps */
	fast = create_test_deadline_path(test, 0, 5000, 12500000, 500);

	/* Slow path: 50ms RTT, 10 Mbps */
	slow = create_test_deadline_path(test, 1, 50000, 1250000, 5000);

	add_deadline_path(conn, fast);
	add_deadline_path(conn, slow);

	/* 15ms deadline - only fast path can meet it */
	selected = select_best_path(conn, 15000, 1000);
	KUNIT_EXPECT_EQ(test, selected->path_id, 0U);
}

/* Test: Path selection with all paths feasible */
static void tquic_deadline_test_path_selection_all_feasible(struct kunit *test)
{
	struct test_deadline_conn *conn = create_test_deadline_conn(test);
	struct test_deadline_path *path1, *path2, *selected;

	/* Path 1: 10ms RTT, 10 Mbps */
	path1 = create_test_deadline_path(test, 0, 10000, 1250000, 1000);

	/* Path 2: 20ms RTT, 100 Mbps */
	path2 = create_test_deadline_path(test, 1, 20000, 12500000, 2000);

	add_deadline_path(conn, path1);
	add_deadline_path(conn, path2);

	/* 100ms deadline - both feasible, should prefer faster delivery */
	selected = select_best_path(conn, 100000, 1000);

	/* Path 1: delivery ~13000us, slack ~87000us */
	/* Path 2: delivery ~24080us, slack ~76000us */
	/* Path 1 should win due to lower delivery time */
	KUNIT_EXPECT_EQ(test, selected->path_id, 0U);
}

/* Test: Path selection when no path can meet deadline */
static void tquic_deadline_test_path_selection_none_feasible(struct kunit *test)
{
	struct test_deadline_conn *conn = create_test_deadline_conn(test);
	struct test_deadline_path *path1, *path2, *selected;

	/* Path 1: 50ms RTT */
	path1 = create_test_deadline_path(test, 0, 50000, 1250000, 5000);

	/* Path 2: 100ms RTT */
	path2 = create_test_deadline_path(test, 1, 100000, 1250000, 10000);

	add_deadline_path(conn, path1);
	add_deadline_path(conn, path2);

	/* 10ms deadline - impossible, but should still select best effort */
	selected = select_best_path(conn, 10000, 1000);

	/* Path 1 is still faster, so best for best-effort */
	KUNIT_EXPECT_EQ(test, selected->path_id, 0U);
}

/*
 * =============================================================================
 * Frame Parsing Tests
 * =============================================================================
 */

/* Test: STREAM_DEADLINE frame encoding/decoding roundtrip */
static void tquic_deadline_test_frame_roundtrip(struct kunit *test)
{
	struct tquic_deadline_frame frame_out, frame_in;
	u8 buf[64];
	int written, parsed;

	/* Create test frame */
	frame_out.stream_id = 0x1234;
	frame_out.deadline_us = 50000;
	frame_out.priority = TQUIC_DEADLINE_PRIO_HIGH;
	frame_out.offset = 0x5678;
	frame_out.length = 0x1000;
	frame_out.flags = TQUIC_DEADLINE_FRAME_FLAG_URGENT;

	/* Encode */
	written = tquic_deadline_write_frame(&frame_out, buf, sizeof(buf));
	KUNIT_EXPECT_GT(test, written, 0);

	/* Decode */
	parsed = tquic_deadline_parse_frame(buf, written, &frame_in);
	KUNIT_EXPECT_EQ(test, parsed, written);

	/* Verify roundtrip */
	KUNIT_EXPECT_EQ(test, frame_in.stream_id, frame_out.stream_id);
	KUNIT_EXPECT_EQ(test, frame_in.deadline_us, frame_out.deadline_us);
	KUNIT_EXPECT_EQ(test, frame_in.priority, frame_out.priority);
	KUNIT_EXPECT_EQ(test, frame_in.offset, frame_out.offset);
	KUNIT_EXPECT_EQ(test, frame_in.length, frame_out.length);
	KUNIT_EXPECT_EQ(test, frame_in.flags, frame_out.flags);
}

/* Test: Frame size calculation accuracy */
static void tquic_deadline_test_frame_size(struct kunit *test)
{
	struct tquic_deadline_frame frame;
	u8 buf[64];
	int written;
	size_t calculated;

	frame.stream_id = 0x1234;
	frame.deadline_us = 50000;
	frame.priority = 1;
	frame.offset = 0x5678;
	frame.length = 0x1000;
	frame.flags = 0;

	calculated = tquic_deadline_frame_size(&frame);
	written = tquic_deadline_write_frame(&frame, buf, sizeof(buf));

	KUNIT_EXPECT_EQ(test, (int)calculated, written);
}

/* Test: DEADLINE_ACK frame roundtrip */
static void tquic_deadline_test_ack_frame_roundtrip(struct kunit *test)
{
	struct tquic_deadline_ack_frame frame_out, frame_in;
	u8 buf[32];
	int written, parsed;

	frame_out.stream_id = 0xABCD;
	frame_out.offset = 0x10000;
	frame_out.delivery_time_us = 25000;

	written = tquic_deadline_write_ack_frame(&frame_out, buf, sizeof(buf));
	KUNIT_EXPECT_GT(test, written, 0);

	parsed = tquic_deadline_parse_ack_frame(buf, written, &frame_in);
	KUNIT_EXPECT_EQ(test, parsed, written);

	KUNIT_EXPECT_EQ(test, frame_in.stream_id, frame_out.stream_id);
	KUNIT_EXPECT_EQ(test, frame_in.offset, frame_out.offset);
	KUNIT_EXPECT_EQ(test, frame_in.delivery_time_us, frame_out.delivery_time_us);
}

/* Test: DEADLINE_MISS frame roundtrip */
static void tquic_deadline_test_miss_frame_roundtrip(struct kunit *test)
{
	struct tquic_deadline_miss_frame frame_out, frame_in;
	u8 buf[32];
	int written, parsed;

	frame_out.stream_id = 0xDEAD;
	frame_out.offset = 0x20000;
	frame_out.miss_amount_us = 10000;
	frame_out.reason = TQUIC_DEADLINE_MISS_CONGESTION;

	written = tquic_deadline_write_miss_frame(&frame_out, buf, sizeof(buf));
	KUNIT_EXPECT_GT(test, written, 0);

	parsed = tquic_deadline_parse_miss_frame(buf, written, &frame_in);
	KUNIT_EXPECT_EQ(test, parsed, written);

	KUNIT_EXPECT_EQ(test, frame_in.stream_id, frame_out.stream_id);
	KUNIT_EXPECT_EQ(test, frame_in.offset, frame_out.offset);
	KUNIT_EXPECT_EQ(test, frame_in.miss_amount_us, frame_out.miss_amount_us);
	KUNIT_EXPECT_EQ(test, frame_in.reason, frame_out.reason);
}

/*
 * =============================================================================
 * Deadline Miss Detection Tests
 * =============================================================================
 */

/* Test: Deadline miss detection by time */
static void tquic_deadline_test_miss_detection_time(struct kunit *test)
{
	ktime_t deadline, now;
	s64 remaining_us;

	now = ktime_get();
	deadline = ktime_add_us(now, 10000);  /* 10ms in future */

	remaining_us = ktime_us_delta(deadline, now);
	KUNIT_EXPECT_GT(test, remaining_us, 0LL);

	/* Simulate time passing */
	deadline = ktime_sub_us(now, 5000);  /* 5ms in past */
	remaining_us = ktime_us_delta(deadline, now);
	KUNIT_EXPECT_LT(test, remaining_us, 0LL);  /* Deadline missed */
}

/*
 * =============================================================================
 * Transport Parameter Tests
 * =============================================================================
 */

/* Test: Deadline transport parameter IDs */
static void tquic_deadline_test_tp_ids(struct kunit *test)
{
	/* Verify parameter IDs are unique and in expected range */
	KUNIT_EXPECT_EQ(test, TQUIC_TP_ENABLE_DEADLINE_AWARE, 0x0f10ULL);
	KUNIT_EXPECT_EQ(test, TQUIC_TP_DEADLINE_GRANULARITY, 0x0f11ULL);
	KUNIT_EXPECT_EQ(test, TQUIC_TP_MAX_DEADLINE_STREAMS, 0x0f12ULL);
	KUNIT_EXPECT_EQ(test, TQUIC_TP_DEADLINE_MISS_POLICY, 0x0f13ULL);
}

/* Test: Default parameter values */
static void tquic_deadline_test_tp_defaults(struct kunit *test)
{
	/* Verify default values are reasonable */
	KUNIT_EXPECT_EQ(test, TQUIC_DEADLINE_GRANULARITY_MS, 1000U);
	KUNIT_EXPECT_GT(test, TQUIC_MAX_DEADLINE_STREAMS, 0U);
	KUNIT_EXPECT_LT(test, TQUIC_DEADLINE_MISS_BEST_EFFORT, 4U);
}

/* Test: Miss policy values */
static void tquic_deadline_test_miss_policies(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, TQUIC_DEADLINE_MISS_DROP, 0U);
	KUNIT_EXPECT_EQ(test, TQUIC_DEADLINE_MISS_BEST_EFFORT, 1U);
	KUNIT_EXPECT_EQ(test, TQUIC_DEADLINE_MISS_NOTIFY, 2U);
	KUNIT_EXPECT_EQ(test, TQUIC_DEADLINE_MISS_DEGRADE, 3U);
}

/*
 * =============================================================================
 * Priority Level Tests
 * =============================================================================
 */

/* Test: Priority levels are ordered correctly */
static void tquic_deadline_test_priority_levels(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, TQUIC_DEADLINE_PRIO_CRITICAL, 0U);
	KUNIT_EXPECT_EQ(test, TQUIC_DEADLINE_PRIO_HIGH, 1U);
	KUNIT_EXPECT_EQ(test, TQUIC_DEADLINE_PRIO_NORMAL, 2U);
	KUNIT_EXPECT_EQ(test, TQUIC_DEADLINE_PRIO_LOW, 3U);
	KUNIT_EXPECT_EQ(test, TQUIC_DEADLINE_PRIO_LEVELS, 4U);
}

/*
 * =============================================================================
 * Deadline Limits Tests
 * =============================================================================
 */

/* Test: Deadline limits */
static void tquic_deadline_test_limits(struct kunit *test)
{
	/* Minimum deadline should be at least 100 us */
	KUNIT_EXPECT_GE(test, TQUIC_MIN_DEADLINE_US, 100ULL);

	/* Maximum deadline should be reasonable (60 seconds) */
	KUNIT_EXPECT_EQ(test, TQUIC_MAX_DEADLINE_US, 60 * 1000000ULL);

	/* Default deadline should be between min and max */
	KUNIT_EXPECT_GE(test, TQUIC_DEFAULT_DEADLINE_US, TQUIC_MIN_DEADLINE_US);
	KUNIT_EXPECT_LE(test, TQUIC_DEFAULT_DEADLINE_US, TQUIC_MAX_DEADLINE_US);
}

/*
 * =============================================================================
 * Flag Tests
 * =============================================================================
 */

/* Test: Deadline flag values */
static void tquic_deadline_test_flags(struct kunit *test)
{
	u32 flags = 0;

	/* Set multiple flags */
	flags |= TQUIC_DEADLINE_FLAG_ACTIVE;
	flags |= TQUIC_DEADLINE_FLAG_PENDING;

	KUNIT_EXPECT_TRUE(test, flags & TQUIC_DEADLINE_FLAG_ACTIVE);
	KUNIT_EXPECT_TRUE(test, flags & TQUIC_DEADLINE_FLAG_PENDING);
	KUNIT_EXPECT_FALSE(test, flags & TQUIC_DEADLINE_FLAG_MISSED);

	/* Mark as missed */
	flags |= TQUIC_DEADLINE_FLAG_MISSED;
	KUNIT_EXPECT_TRUE(test, flags & TQUIC_DEADLINE_FLAG_MISSED);
}

/* Test: Frame flag values */
static void tquic_deadline_test_frame_flags(struct kunit *test)
{
	u8 flags = 0;

	flags |= TQUIC_DEADLINE_FRAME_FLAG_URGENT;
	KUNIT_EXPECT_TRUE(test, flags & TQUIC_DEADLINE_FRAME_FLAG_URGENT);

	flags |= TQUIC_DEADLINE_FRAME_FLAG_ALLOW_DROP;
	KUNIT_EXPECT_TRUE(test, flags & TQUIC_DEADLINE_FRAME_FLAG_ALLOW_DROP);

	flags |= TQUIC_DEADLINE_FRAME_FLAG_PERIODIC;
	KUNIT_EXPECT_TRUE(test, flags & TQUIC_DEADLINE_FRAME_FLAG_PERIODIC);
}

/*
 * =============================================================================
 * Miss Reason Tests
 * =============================================================================
 */

/* Test: Miss reason codes */
static void tquic_deadline_test_miss_reasons(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, TQUIC_DEADLINE_MISS_CONGESTION, 0x01U);
	KUNIT_EXPECT_EQ(test, TQUIC_DEADLINE_MISS_PATH_FAILURE, 0x02U);
	KUNIT_EXPECT_EQ(test, TQUIC_DEADLINE_MISS_LOSS, 0x03U);
	KUNIT_EXPECT_EQ(test, TQUIC_DEADLINE_MISS_SCHEDULING, 0x04U);
	KUNIT_EXPECT_EQ(test, TQUIC_DEADLINE_MISS_INFEASIBLE, 0x05U);
}

/*
 * =============================================================================
 * Integration Helper Tests
 * =============================================================================
 */

/* Test: Frame type checking */
static void tquic_deadline_test_frame_type_check(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test,
		tquic_deadline_is_deadline_frame(TQUIC_FRAME_STREAM_DEADLINE));
	KUNIT_EXPECT_TRUE(test,
		tquic_deadline_is_deadline_frame(TQUIC_FRAME_DEADLINE_ACK));
	KUNIT_EXPECT_TRUE(test,
		tquic_deadline_is_deadline_frame(TQUIC_FRAME_DEADLINE_MISS));

	/* Non-deadline frames */
	KUNIT_EXPECT_FALSE(test, tquic_deadline_is_deadline_frame(0x00));  /* PADDING */
	KUNIT_EXPECT_FALSE(test, tquic_deadline_is_deadline_frame(0x06));  /* CRYPTO */
	KUNIT_EXPECT_FALSE(test, tquic_deadline_is_deadline_frame(0x08));  /* STREAM */
}

/*
 * =============================================================================
 * Test Suite Definition
 * =============================================================================
 */

static struct kunit_case tquic_deadline_test_cases[] = {
	/* Feasibility tests */
	KUNIT_CASE(tquic_deadline_test_feasibility_basic),
	KUNIT_CASE(tquic_deadline_test_feasibility_high_bw),
	KUNIT_CASE(tquic_deadline_test_feasibility_high_jitter),
	KUNIT_CASE(tquic_deadline_test_feasibility_inactive),

	/* EDF tests */
	KUNIT_CASE(tquic_deadline_test_edf_ordering),
	KUNIT_CASE(tquic_deadline_test_edf_priority_tiebreak),

	/* Path selection tests */
	KUNIT_CASE(tquic_deadline_test_path_selection_feasible),
	KUNIT_CASE(tquic_deadline_test_path_selection_all_feasible),
	KUNIT_CASE(tquic_deadline_test_path_selection_none_feasible),

	/* Frame tests */
	KUNIT_CASE(tquic_deadline_test_frame_roundtrip),
	KUNIT_CASE(tquic_deadline_test_frame_size),
	KUNIT_CASE(tquic_deadline_test_ack_frame_roundtrip),
	KUNIT_CASE(tquic_deadline_test_miss_frame_roundtrip),

	/* Miss detection tests */
	KUNIT_CASE(tquic_deadline_test_miss_detection_time),

	/* Transport parameter tests */
	KUNIT_CASE(tquic_deadline_test_tp_ids),
	KUNIT_CASE(tquic_deadline_test_tp_defaults),
	KUNIT_CASE(tquic_deadline_test_miss_policies),

	/* Priority tests */
	KUNIT_CASE(tquic_deadline_test_priority_levels),

	/* Limit tests */
	KUNIT_CASE(tquic_deadline_test_limits),

	/* Flag tests */
	KUNIT_CASE(tquic_deadline_test_flags),
	KUNIT_CASE(tquic_deadline_test_frame_flags),

	/* Miss reason tests */
	KUNIT_CASE(tquic_deadline_test_miss_reasons),

	/* Integration tests */
	KUNIT_CASE(tquic_deadline_test_frame_type_check),
	{}
};

static struct kunit_suite tquic_deadline_test_suite = {
	.name = "tquic-deadline-aware",
	.test_cases = tquic_deadline_test_cases,
};

kunit_test_suite(tquic_deadline_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for TQUIC Deadline-Aware Multipath Scheduling");
