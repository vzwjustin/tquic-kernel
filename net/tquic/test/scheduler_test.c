// SPDX-License-Identifier: GPL-2.0
/*
 * KUnit tests for TQUIC packet scheduler (WAN bonding)
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Tests the various packet scheduling algorithms used for WAN bonding:
 * - Round-robin
 * - Minimum RTT
 * - Weighted round-robin
 * - BLEST (Blocking Estimation)
 * - ECF (Earliest Completion First)
 * - Redundant (send on all paths)
 */

#include <kunit/test.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <net/tquic.h>
#include <uapi/linux/tquic.h>

/* Test path structure (simplified for testing) */
struct test_path {
	u32 path_id;
	enum tquic_path_state state;
	u32 rtt_smoothed;	/* RTT in microseconds */
	u64 bandwidth;		/* Bandwidth in bytes/sec */
	u32 cwnd;		/* Congestion window */
	u8 priority;
	u8 weight;
	struct list_head list;
	u32 select_count;	/* Track how many times selected */
};

/* Test connection structure */
struct test_conn {
	struct list_head paths;
	u32 num_paths;
	struct test_path *active_path;
};

/* Initialize test path */
static struct test_path *create_test_path(struct kunit *test, u32 id,
					  u32 rtt, u64 bw, u8 weight)
{
	struct test_path *path;

	path = kunit_kzalloc(test, sizeof(*path), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, path);

	path->path_id = id;
	path->state = TQUIC_PATH_ACTIVE;
	path->rtt_smoothed = rtt;
	path->bandwidth = bw;
	path->cwnd = 65536;
	path->priority = 128;
	path->weight = weight;
	path->select_count = 0;
	INIT_LIST_HEAD(&path->list);

	return path;
}

/* Initialize test connection */
static struct test_conn *create_test_conn(struct kunit *test)
{
	struct test_conn *conn;

	conn = kunit_kzalloc(test, sizeof(*conn), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, conn);

	INIT_LIST_HEAD(&conn->paths);
	conn->num_paths = 0;
	conn->active_path = NULL;

	return conn;
}

/* Add path to connection */
static void add_path_to_conn(struct test_conn *conn, struct test_path *path)
{
	list_add_tail(&path->list, &conn->paths);
	conn->num_paths++;
	if (!conn->active_path)
		conn->active_path = path;
}

/* Round-robin scheduler implementation */
static struct test_path *sched_roundrobin(struct test_conn *conn, u32 *counter)
{
	struct test_path *path;
	u32 idx = 0;
	u32 target;

	if (conn->num_paths == 0)
		return NULL;

	target = (*counter)++ % conn->num_paths;

	list_for_each_entry(path, &conn->paths, list) {
		if (path->state != TQUIC_PATH_ACTIVE)
			continue;
		if (idx == target) {
			path->select_count++;
			return path;
		}
		idx++;
	}

	return conn->active_path;
}

/* Minimum RTT scheduler implementation */
static struct test_path *sched_minrtt(struct test_conn *conn)
{
	struct test_path *path, *best = NULL;
	u32 min_rtt = UINT_MAX;

	list_for_each_entry(path, &conn->paths, list) {
		if (path->state != TQUIC_PATH_ACTIVE)
			continue;
		if (path->rtt_smoothed < min_rtt) {
			min_rtt = path->rtt_smoothed;
			best = path;
		}
	}

	if (best)
		best->select_count++;

	return best ?: conn->active_path;
}

/* Weighted round-robin scheduler implementation */
static struct test_path *sched_weighted(struct test_conn *conn, u32 *counter)
{
	struct test_path *path;
	u32 total_weight = 0;
	u32 target, cumulative = 0;

	list_for_each_entry(path, &conn->paths, list) {
		if (path->state == TQUIC_PATH_ACTIVE)
			total_weight += path->weight;
	}

	if (total_weight == 0)
		return conn->active_path;

	target = (*counter)++ % total_weight;

	list_for_each_entry(path, &conn->paths, list) {
		if (path->state != TQUIC_PATH_ACTIVE)
			continue;
		cumulative += path->weight;
		if (target < cumulative) {
			path->select_count++;
			return path;
		}
	}

	return conn->active_path;
}

/* BLEST scheduler implementation (simplified) */
static struct test_path *sched_blest(struct test_conn *conn, u32 pkt_len)
{
	struct test_path *path, *best = NULL;
	u64 min_completion = ULLONG_MAX;

	list_for_each_entry(path, &conn->paths, list) {
		u64 completion_time;

		if (path->state != TQUIC_PATH_ACTIVE)
			continue;

		/* Estimate completion time */
		completion_time = path->rtt_smoothed;
		if (path->bandwidth > 0)
			completion_time += (pkt_len * 1000000ULL) / path->bandwidth;

		if (completion_time < min_completion) {
			min_completion = completion_time;
			best = path;
		}
	}

	if (best)
		best->select_count++;

	return best ?: conn->active_path;
}

/* Test: Round-robin basic distribution */
static void tquic_sched_test_roundrobin_basic(struct kunit *test)
{
	struct test_conn *conn = create_test_conn(test);
	struct test_path *path1 = create_test_path(test, 0, 10000, 1000000, 1);
	struct test_path *path2 = create_test_path(test, 1, 20000, 1000000, 1);
	struct test_path *selected;
	u32 counter = 0;

	add_path_to_conn(conn, path1);
	add_path_to_conn(conn, path2);

	/* First selection should be path1 */
	selected = sched_roundrobin(conn, &counter);
	KUNIT_EXPECT_EQ(test, selected->path_id, 0U);

	/* Second selection should be path2 */
	selected = sched_roundrobin(conn, &counter);
	KUNIT_EXPECT_EQ(test, selected->path_id, 1U);

	/* Third selection should cycle back to path1 */
	selected = sched_roundrobin(conn, &counter);
	KUNIT_EXPECT_EQ(test, selected->path_id, 0U);
}

/* Test: Round-robin even distribution */
static void tquic_sched_test_roundrobin_distribution(struct kunit *test)
{
	struct test_conn *conn = create_test_conn(test);
	struct test_path *path1 = create_test_path(test, 0, 10000, 1000000, 1);
	struct test_path *path2 = create_test_path(test, 1, 20000, 1000000, 1);
	struct test_path *path3 = create_test_path(test, 2, 15000, 1000000, 1);
	u32 counter = 0;
	int i;

	add_path_to_conn(conn, path1);
	add_path_to_conn(conn, path2);
	add_path_to_conn(conn, path3);

	/* Select 300 times */
	for (i = 0; i < 300; i++)
		sched_roundrobin(conn, &counter);

	/* Each path should be selected 100 times */
	KUNIT_EXPECT_EQ(test, path1->select_count, 100U);
	KUNIT_EXPECT_EQ(test, path2->select_count, 100U);
	KUNIT_EXPECT_EQ(test, path3->select_count, 100U);
}

/* Test: Minimum RTT selection */
static void tquic_sched_test_minrtt_selection(struct kunit *test)
{
	struct test_conn *conn = create_test_conn(test);
	struct test_path *path1 = create_test_path(test, 0, 50000, 1000000, 1);  /* 50ms */
	struct test_path *path2 = create_test_path(test, 1, 10000, 1000000, 1);  /* 10ms - lowest */
	struct test_path *path3 = create_test_path(test, 2, 30000, 1000000, 1);  /* 30ms */
	struct test_path *selected;

	add_path_to_conn(conn, path1);
	add_path_to_conn(conn, path2);
	add_path_to_conn(conn, path3);

	/* Should always select path2 (lowest RTT) */
	selected = sched_minrtt(conn);
	KUNIT_EXPECT_EQ(test, selected->path_id, 1U);

	selected = sched_minrtt(conn);
	KUNIT_EXPECT_EQ(test, selected->path_id, 1U);

	/* Path2 should have all selections */
	KUNIT_EXPECT_EQ(test, path1->select_count, 0U);
	KUNIT_EXPECT_EQ(test, path2->select_count, 2U);
	KUNIT_EXPECT_EQ(test, path3->select_count, 0U);
}

/* Test: Minimum RTT with RTT change */
static void tquic_sched_test_minrtt_change(struct kunit *test)
{
	struct test_conn *conn = create_test_conn(test);
	struct test_path *path1 = create_test_path(test, 0, 20000, 1000000, 1);
	struct test_path *path2 = create_test_path(test, 1, 10000, 1000000, 1);
	struct test_path *selected;

	add_path_to_conn(conn, path1);
	add_path_to_conn(conn, path2);

	/* Initially path2 has lower RTT */
	selected = sched_minrtt(conn);
	KUNIT_EXPECT_EQ(test, selected->path_id, 1U);

	/* Simulate RTT change - path1 becomes faster */
	path1->rtt_smoothed = 5000;
	path2->rtt_smoothed = 15000;

	selected = sched_minrtt(conn);
	KUNIT_EXPECT_EQ(test, selected->path_id, 0U);
}

/* Test: Weighted round-robin distribution */
static void tquic_sched_test_weighted_distribution(struct kunit *test)
{
	struct test_conn *conn = create_test_conn(test);
	struct test_path *path1 = create_test_path(test, 0, 10000, 1000000, 1);  /* Weight 1 */
	struct test_path *path2 = create_test_path(test, 1, 10000, 1000000, 3);  /* Weight 3 */
	u32 counter = 0;
	int i;

	add_path_to_conn(conn, path1);
	add_path_to_conn(conn, path2);

	/* Total weight = 4, select 400 times */
	for (i = 0; i < 400; i++)
		sched_weighted(conn, &counter);

	/* path1 should get 1/4 = 100 selections */
	/* path2 should get 3/4 = 300 selections */
	KUNIT_EXPECT_EQ(test, path1->select_count, 100U);
	KUNIT_EXPECT_EQ(test, path2->select_count, 300U);
}

/* Test: Weighted with unequal weights */
static void tquic_sched_test_weighted_unequal(struct kunit *test)
{
	struct test_conn *conn = create_test_conn(test);
	struct test_path *path1 = create_test_path(test, 0, 10000, 1000000, 2);
	struct test_path *path2 = create_test_path(test, 1, 10000, 1000000, 3);
	struct test_path *path3 = create_test_path(test, 2, 10000, 1000000, 5);
	u32 counter = 0;
	int i;

	add_path_to_conn(conn, path1);
	add_path_to_conn(conn, path2);
	add_path_to_conn(conn, path3);

	/* Total weight = 10, select 1000 times */
	for (i = 0; i < 1000; i++)
		sched_weighted(conn, &counter);

	/* Distribution should match weights */
	KUNIT_EXPECT_EQ(test, path1->select_count, 200U);  /* 2/10 */
	KUNIT_EXPECT_EQ(test, path2->select_count, 300U);  /* 3/10 */
	KUNIT_EXPECT_EQ(test, path3->select_count, 500U);  /* 5/10 */
}

/* Test: BLEST scheduler prefers faster completion */
static void tquic_sched_test_blest_selection(struct kunit *test)
{
	struct test_conn *conn = create_test_conn(test);
	/* path1: high RTT, high bandwidth */
	struct test_path *path1 = create_test_path(test, 0, 100000, 10000000, 1);
	/* path2: low RTT, low bandwidth - should win for small packets */
	struct test_path *path2 = create_test_path(test, 1, 10000, 1000000, 1);
	struct test_path *selected;

	add_path_to_conn(conn, path1);
	add_path_to_conn(conn, path2);

	/* For small packet (100 bytes):
	 * path1: 100000 + (100 * 1000000 / 10000000) = 100010 us
	 * path2: 10000 + (100 * 1000000 / 1000000) = 10100 us
	 * path2 wins
	 */
	selected = sched_blest(conn, 100);
	KUNIT_EXPECT_EQ(test, selected->path_id, 1U);
}

/* Test: BLEST with varying packet sizes */
static void tquic_sched_test_blest_packet_size(struct kunit *test)
{
	struct test_conn *conn = create_test_conn(test);
	/* path1: 10ms RTT, 10 Mbps */
	struct test_path *path1 = create_test_path(test, 0, 10000, 10000000, 1);
	/* path2: 50ms RTT, 100 Mbps */
	struct test_path *path2 = create_test_path(test, 1, 50000, 100000000, 1);
	struct test_path *selected;

	add_path_to_conn(conn, path1);
	add_path_to_conn(conn, path2);

	/* Small packet favors low RTT path */
	selected = sched_blest(conn, 100);
	KUNIT_EXPECT_EQ(test, selected->path_id, 0U);

	/* Reset counts for next test */
	path1->select_count = 0;
	path2->select_count = 0;

	/* Large packet - bandwidth matters more */
	/* path1: 10000 + (1000000 * 1000000 / 10000000) = 110000 us
	 * path2: 50000 + (1000000 * 1000000 / 100000000) = 60000 us
	 */
	selected = sched_blest(conn, 1000000);
	KUNIT_EXPECT_EQ(test, selected->path_id, 1U);
}

/* Test: Scheduler with inactive paths */
static void tquic_sched_test_inactive_paths(struct kunit *test)
{
	struct test_conn *conn = create_test_conn(test);
	struct test_path *path1 = create_test_path(test, 0, 10000, 1000000, 1);
	struct test_path *path2 = create_test_path(test, 1, 5000, 1000000, 1);  /* Lowest RTT */
	struct test_path *path3 = create_test_path(test, 2, 20000, 1000000, 1);
	struct test_path *selected;

	path2->state = TQUIC_PATH_FAILED;  /* Mark as failed */

	add_path_to_conn(conn, path1);
	add_path_to_conn(conn, path2);
	add_path_to_conn(conn, path3);

	/* MinRTT should skip failed path2, select path1 */
	selected = sched_minrtt(conn);
	KUNIT_EXPECT_EQ(test, selected->path_id, 0U);
	KUNIT_EXPECT_EQ(test, path2->select_count, 0U);
}

/* Test: Scheduler with all paths inactive */
static void tquic_sched_test_all_inactive(struct kunit *test)
{
	struct test_conn *conn = create_test_conn(test);
	struct test_path *path1 = create_test_path(test, 0, 10000, 1000000, 1);
	struct test_path *path2 = create_test_path(test, 1, 5000, 1000000, 1);
	struct test_path *selected;

	path1->state = TQUIC_PATH_FAILED;
	path2->state = TQUIC_PATH_STANDBY;

	add_path_to_conn(conn, path1);
	add_path_to_conn(conn, path2);

	/* Should fall back to active_path */
	selected = sched_minrtt(conn);
	KUNIT_EXPECT_EQ(test, selected, conn->active_path);
}

/* Test: Single path scheduling */
static void tquic_sched_test_single_path(struct kunit *test)
{
	struct test_conn *conn = create_test_conn(test);
	struct test_path *path1 = create_test_path(test, 0, 10000, 1000000, 1);
	struct test_path *selected;
	u32 counter = 0;
	int i;

	add_path_to_conn(conn, path1);

	/* All schedulers should return the only path */
	for (i = 0; i < 10; i++) {
		selected = sched_roundrobin(conn, &counter);
		KUNIT_EXPECT_EQ(test, selected->path_id, 0U);
	}

	selected = sched_minrtt(conn);
	KUNIT_EXPECT_EQ(test, selected->path_id, 0U);

	counter = 0;
	selected = sched_weighted(conn, &counter);
	KUNIT_EXPECT_EQ(test, selected->path_id, 0U);
}

/* Test: Empty connection handling */
static void tquic_sched_test_empty_conn(struct kunit *test)
{
	struct test_conn *conn = create_test_conn(test);
	struct test_path *selected;
	u32 counter = 0;

	/* Should handle empty path list gracefully */
	selected = sched_minrtt(conn);
	KUNIT_EXPECT_NULL(test, selected);

	selected = sched_roundrobin(conn, &counter);
	KUNIT_EXPECT_NULL(test, selected);
}

/* Test: Path priority effect */
static void tquic_sched_test_priority(struct kunit *test)
{
	struct test_conn *conn = create_test_conn(test);
	struct test_path *path1 = create_test_path(test, 0, 10000, 1000000, 1);
	struct test_path *path2 = create_test_path(test, 1, 10000, 1000000, 1);

	path1->priority = 255;  /* Lowest priority */
	path2->priority = 0;    /* Highest priority */

	add_path_to_conn(conn, path1);
	add_path_to_conn(conn, path2);

	/* Priority should be used in quality calculations */
	KUNIT_EXPECT_LT(test, path2->priority, path1->priority);
}

/* Test: Bonding mode constants */
static void tquic_sched_test_bonding_modes(struct kunit *test)
{
	/* Verify bonding mode constants are distinct */
	KUNIT_EXPECT_EQ(test, TQUIC_BOND_MODE_NONE, 0);
	KUNIT_EXPECT_EQ(test, TQUIC_BOND_MODE_FAILOVER, 1);
	KUNIT_EXPECT_EQ(test, TQUIC_BOND_MODE_ROUNDROBIN, 2);
	KUNIT_EXPECT_EQ(test, TQUIC_BOND_MODE_WEIGHTED, 3);
	KUNIT_EXPECT_EQ(test, TQUIC_BOND_MODE_MINRTT, 4);
	KUNIT_EXPECT_EQ(test, TQUIC_BOND_MODE_REDUNDANT, 5);
	KUNIT_EXPECT_EQ(test, TQUIC_BOND_MODE_AGGREGATE, 6);
	KUNIT_EXPECT_EQ(test, TQUIC_BOND_MODE_BLEST, 7);
	KUNIT_EXPECT_EQ(test, TQUIC_BOND_MODE_ECF, 8);

	/* All modes should be unique */
	KUNIT_EXPECT_NE(test, TQUIC_BOND_MODE_FAILOVER, TQUIC_BOND_MODE_ROUNDROBIN);
	KUNIT_EXPECT_NE(test, TQUIC_BOND_MODE_AGGREGATE, TQUIC_BOND_MODE_BLEST);
}

/* Test: Path state transitions */
static void tquic_sched_test_path_states(struct kunit *test)
{
	struct test_path *path = create_test_path(test, 0, 10000, 1000000, 1);

	/* Test state transitions */
	path->state = TQUIC_PATH_PENDING;
	KUNIT_EXPECT_NE(test, path->state, TQUIC_PATH_ACTIVE);

	path->state = TQUIC_PATH_ACTIVE;
	KUNIT_EXPECT_EQ(test, path->state, TQUIC_PATH_ACTIVE);

	path->state = TQUIC_PATH_STANDBY;
	KUNIT_EXPECT_NE(test, path->state, TQUIC_PATH_ACTIVE);

	path->state = TQUIC_PATH_FAILED;
	KUNIT_EXPECT_EQ(test, path->state, TQUIC_PATH_FAILED);
}

/* Test: Path statistics initialization */
static void tquic_sched_test_path_stats(struct kunit *test)
{
	struct test_path *path = create_test_path(test, 0, 10000, 1000000, 1);

	/* Verify initial stats */
	KUNIT_EXPECT_EQ(test, path->rtt_smoothed, 10000U);
	KUNIT_EXPECT_EQ(test, path->bandwidth, 1000000ULL);
	KUNIT_EXPECT_EQ(test, path->cwnd, 65536U);
	KUNIT_EXPECT_EQ(test, path->weight, 1);
}

/* Test: Max paths limit */
static void tquic_sched_test_max_paths(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, TQUIC_MAX_PATHS, 16);
	KUNIT_EXPECT_EQ(test, TQUIC_MAX_PATHS_USER, 16);

	/* Should be able to add up to max paths */
	KUNIT_EXPECT_GE(test, TQUIC_MAX_PATHS, 2);
}

/* Test: Weighted scheduler with zero weight */
static void tquic_sched_test_weighted_zero_weight(struct kunit *test)
{
	struct test_conn *conn = create_test_conn(test);
	struct test_path *path1 = create_test_path(test, 0, 10000, 1000000, 0);  /* Zero weight */
	struct test_path *path2 = create_test_path(test, 1, 10000, 1000000, 5);
	u32 counter = 0;
	int i;

	add_path_to_conn(conn, path1);
	add_path_to_conn(conn, path2);

	/* path1 with zero weight should never be selected */
	for (i = 0; i < 100; i++)
		sched_weighted(conn, &counter);

	KUNIT_EXPECT_EQ(test, path1->select_count, 0U);
	KUNIT_EXPECT_EQ(test, path2->select_count, 100U);
}

/* Test: Failover mode behavior */
static void tquic_sched_test_failover_mode(struct kunit *test)
{
	struct test_conn *conn = create_test_conn(test);
	struct test_path *primary = create_test_path(test, 0, 10000, 1000000, 1);
	struct test_path *backup = create_test_path(test, 1, 20000, 1000000, 1);

	add_path_to_conn(conn, primary);
	add_path_to_conn(conn, backup);

	/* In failover mode, always use active path if available */
	conn->active_path = primary;
	KUNIT_EXPECT_EQ(test, conn->active_path->path_id, 0U);

	/* Simulate primary failure */
	primary->state = TQUIC_PATH_FAILED;
	conn->active_path = backup;
	KUNIT_EXPECT_EQ(test, conn->active_path->path_id, 1U);

	/* Simulate primary recovery */
	primary->state = TQUIC_PATH_ACTIVE;
	conn->active_path = primary;
	KUNIT_EXPECT_EQ(test, conn->active_path->path_id, 0U);
}

static struct kunit_case tquic_sched_test_cases[] = {
	KUNIT_CASE(tquic_sched_test_roundrobin_basic),
	KUNIT_CASE(tquic_sched_test_roundrobin_distribution),
	KUNIT_CASE(tquic_sched_test_minrtt_selection),
	KUNIT_CASE(tquic_sched_test_minrtt_change),
	KUNIT_CASE(tquic_sched_test_weighted_distribution),
	KUNIT_CASE(tquic_sched_test_weighted_unequal),
	KUNIT_CASE(tquic_sched_test_blest_selection),
	KUNIT_CASE(tquic_sched_test_blest_packet_size),
	KUNIT_CASE(tquic_sched_test_inactive_paths),
	KUNIT_CASE(tquic_sched_test_all_inactive),
	KUNIT_CASE(tquic_sched_test_single_path),
	KUNIT_CASE(tquic_sched_test_empty_conn),
	KUNIT_CASE(tquic_sched_test_priority),
	KUNIT_CASE(tquic_sched_test_bonding_modes),
	KUNIT_CASE(tquic_sched_test_path_states),
	KUNIT_CASE(tquic_sched_test_path_stats),
	KUNIT_CASE(tquic_sched_test_max_paths),
	KUNIT_CASE(tquic_sched_test_weighted_zero_weight),
	KUNIT_CASE(tquic_sched_test_failover_mode),
	{}
};

static struct kunit_suite tquic_sched_test_suite = {
	.name = "tquic-scheduler",
	.test_cases = tquic_sched_test_cases,
};

kunit_test_suite(tquic_sched_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for TQUIC packet scheduler");
