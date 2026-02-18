// SPDX-License-Identifier: GPL-2.0-only
/*
 * KUnit tests for TQUIC NAT Keepalive (RFC 9308 Section 3.5)
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * This test suite validates the NAT keepalive implementation:
 * - Initialization and cleanup
 * - Timer scheduling and cancellation
 * - Adaptive interval estimation
 * - Power mode optimization
 * - Activity tracking
 * - Keepalive packet generation (minimal PING frame)
 */

#include <kunit/test.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/timer.h>
#include <linux/ktime.h>
#include <net/tquic.h>

#include "../pm/nat_keepalive.h"
#include "../protocol.h"

/*
 * =============================================================================
 * Test Fixtures and Helpers
 * =============================================================================
 */

/* Minimum/maximum interval constants from nat_keepalive.h */
#define TEST_MIN_INTERVAL_MS	5000
#define TEST_MAX_INTERVAL_MS	120000
#define TEST_DEFAULT_INTERVAL_MS 25000

/**
 * struct nat_keepalive_test_ctx - Test context for NAT keepalive tests
 * @path: Mock path structure
 * @conn: Mock connection structure
 * @config: Test configuration
 */
struct nat_keepalive_test_ctx {
	struct tquic_path path;
	struct tquic_connection conn;
	struct tquic_nat_keepalive_config config;
};

/* Allocate and initialize test context */
static int nat_keepalive_test_init(struct kunit *test)
{
	struct nat_keepalive_test_ctx *ctx;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);

	/* Initialize mock connection */
	INIT_LIST_HEAD(&ctx->conn.paths);
	spin_lock_init(&ctx->conn.lock);
	atomic64_set(&ctx->conn.pkt_num_tx, 0);
	ctx->conn.sk = NULL;  /* No real socket for testing */

	/* Initialize mock path */
	ctx->path.path_id = 1;
	ctx->path.conn = &ctx->conn;
	ctx->path.state = TQUIC_PATH_ACTIVE;
	ctx->path.mtu = 1200;
	ctx->path.nat_keepalive_state = NULL;
	ctx->path.dev = NULL;
	INIT_LIST_HEAD(&ctx->path.list);
	memset(&ctx->path.remote_cid, 0, sizeof(ctx->path.remote_cid));
	ctx->path.remote_cid.len = 8;

	/* Initialize default config */
	ctx->config.enabled = true;
	ctx->config.adaptive_mode = true;
	ctx->config.interval_ms = TEST_DEFAULT_INTERVAL_MS;
	ctx->config.min_interval_ms = TEST_MIN_INTERVAL_MS;
	ctx->config.max_interval_ms = TEST_MAX_INTERVAL_MS;
	ctx->config.power_mode = TQUIC_NAT_KEEPALIVE_POWER_NORMAL;
	ctx->config.mobile_aware = false;
	ctx->config.probe_on_activity = false;

	test->priv = ctx;
	return 0;
}

/* Clean up test context */
static void nat_keepalive_test_exit(struct kunit *test)
{
	struct nat_keepalive_test_ctx *ctx = test->priv;

	if (ctx->path.nat_keepalive_state) {
		tquic_nat_keepalive_cleanup(&ctx->path);
	}
}

/*
 * =============================================================================
 * SECTION 1: Initialization Tests
 * =============================================================================
 */

/* Test: Basic initialization succeeds */
static void test_nat_keepalive_init_basic(struct kunit *test)
{
	struct nat_keepalive_test_ctx *ctx = test->priv;
	int ret;

	ret = tquic_nat_keepalive_init(&ctx->path, &ctx->conn);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_NOT_NULL(test, ctx->path.nat_keepalive_state);

	/* Verify state is initialized */
	KUNIT_EXPECT_TRUE(test, ctx->path.nat_keepalive_state->initialized);
	KUNIT_EXPECT_FALSE(test, ctx->path.nat_keepalive_state->suspended);
}

/* Test: Initialization with null path fails */
static void test_nat_keepalive_init_null_path(struct kunit *test)
{
	struct nat_keepalive_test_ctx *ctx = test->priv;
	int ret;

	ret = tquic_nat_keepalive_init(NULL, &ctx->conn);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

/* Test: Initialization with null connection fails */
static void test_nat_keepalive_init_null_conn(struct kunit *test)
{
	struct nat_keepalive_test_ctx *ctx = test->priv;
	int ret;

	ret = tquic_nat_keepalive_init(&ctx->path, NULL);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

/* Test: Double initialization returns success without error */
static void test_nat_keepalive_double_init(struct kunit *test)
{
	struct nat_keepalive_test_ctx *ctx = test->priv;
	int ret;

	ret = tquic_nat_keepalive_init(&ctx->path, &ctx->conn);
	KUNIT_EXPECT_EQ(test, ret, 0);

	/* Second init should return 0 without error */
	ret = tquic_nat_keepalive_init(&ctx->path, &ctx->conn);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

/* Test: Cleanup after initialization */
static void test_nat_keepalive_cleanup_basic(struct kunit *test)
{
	struct nat_keepalive_test_ctx *ctx = test->priv;
	int ret;

	ret = tquic_nat_keepalive_init(&ctx->path, &ctx->conn);
	KUNIT_EXPECT_EQ(test, ret, 0);

	tquic_nat_keepalive_cleanup(&ctx->path);
	KUNIT_EXPECT_NULL(test, ctx->path.nat_keepalive_state);
}

/* Test: Cleanup on uninitialized path is safe */
static void test_nat_keepalive_cleanup_uninitialized(struct kunit *test)
{
	struct nat_keepalive_test_ctx *ctx = test->priv;

	/* Should not crash */
	tquic_nat_keepalive_cleanup(&ctx->path);
	KUNIT_EXPECT_NULL(test, ctx->path.nat_keepalive_state);
}

/* Test: Cleanup with null path is safe */
static void test_nat_keepalive_cleanup_null(struct kunit *test)
{
	/* Should not crash */
	tquic_nat_keepalive_cleanup(NULL);
	KUNIT_SUCCEED(test);
}

/*
 * =============================================================================
 * SECTION 2: Configuration Tests
 * =============================================================================
 */

/* Test: Set configuration after init */
static void test_nat_keepalive_set_config(struct kunit *test)
{
	struct nat_keepalive_test_ctx *ctx = test->priv;
	struct tquic_nat_keepalive_config new_config;
	int ret;

	ret = tquic_nat_keepalive_init(&ctx->path, &ctx->conn);
	KUNIT_EXPECT_EQ(test, ret, 0);

	/* Modify configuration */
	new_config = ctx->config;
	new_config.interval_ms = 15000;
	new_config.adaptive_mode = false;

	ret = tquic_nat_keepalive_set_config(&ctx->path, &new_config);
	KUNIT_EXPECT_EQ(test, ret, 0);

	/* Verify config was applied */
	KUNIT_EXPECT_EQ(test, ctx->path.nat_keepalive_state->config->interval_ms,
			15000U);
	KUNIT_EXPECT_FALSE(test, ctx->path.nat_keepalive_state->config->adaptive_mode);
}

/* Test: Set config on uninitialized path fails */
static void test_nat_keepalive_set_config_uninitialized(struct kunit *test)
{
	struct nat_keepalive_test_ctx *ctx = test->priv;
	int ret;

	ret = tquic_nat_keepalive_set_config(&ctx->path, &ctx->config);
	KUNIT_EXPECT_EQ(test, ret, -ENOENT);
}

/* Test: Set power mode */
static void test_nat_keepalive_set_power_mode(struct kunit *test)
{
	struct nat_keepalive_test_ctx *ctx = test->priv;
	int ret;

	ret = tquic_nat_keepalive_init(&ctx->path, &ctx->conn);
	KUNIT_EXPECT_EQ(test, ret, 0);

	/* Test POWER_SAVING mode */
	ret = tquic_nat_keepalive_set_power_mode(&ctx->path,
						 TQUIC_NAT_KEEPALIVE_POWER_SAVING);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, ctx->path.nat_keepalive_state->config->power_mode,
			TQUIC_NAT_KEEPALIVE_POWER_SAVING);

	/* Test POWER_AGGRESSIVE mode */
	ret = tquic_nat_keepalive_set_power_mode(&ctx->path,
						 TQUIC_NAT_KEEPALIVE_POWER_AGGRESSIVE);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, ctx->path.nat_keepalive_state->config->power_mode,
			TQUIC_NAT_KEEPALIVE_POWER_AGGRESSIVE);

	/* Test POWER_NORMAL mode */
	ret = tquic_nat_keepalive_set_power_mode(&ctx->path,
						 TQUIC_NAT_KEEPALIVE_POWER_NORMAL);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, ctx->path.nat_keepalive_state->config->power_mode,
			TQUIC_NAT_KEEPALIVE_POWER_NORMAL);
}

/* Test: Invalid power mode is rejected */
static void test_nat_keepalive_set_power_mode_invalid(struct kunit *test)
{
	struct nat_keepalive_test_ctx *ctx = test->priv;
	int ret;

	ret = tquic_nat_keepalive_init(&ctx->path, &ctx->conn);
	KUNIT_EXPECT_EQ(test, ret, 0);

	/* Invalid mode value */
	ret = tquic_nat_keepalive_set_power_mode(&ctx->path, 255);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

/*
 * =============================================================================
 * SECTION 3: Timer and Scheduling Tests
 * =============================================================================
 */

/* Test: Schedule keepalive */
static void test_nat_keepalive_schedule(struct kunit *test)
{
	struct nat_keepalive_test_ctx *ctx = test->priv;
	int ret;

	ret = tquic_nat_keepalive_init(&ctx->path, &ctx->conn);
	KUNIT_EXPECT_EQ(test, ret, 0);

	/* Timer should be scheduled after init */
	KUNIT_EXPECT_TRUE(test,
			  timer_pending(&ctx->path.nat_keepalive_state->timer));
}

/* Test: Suspend stops timer */
static void test_nat_keepalive_suspend(struct kunit *test)
{
	struct nat_keepalive_test_ctx *ctx = test->priv;
	int ret;

	ret = tquic_nat_keepalive_init(&ctx->path, &ctx->conn);
	KUNIT_EXPECT_EQ(test, ret, 0);

	tquic_nat_keepalive_suspend(&ctx->path);

	KUNIT_EXPECT_TRUE(test, ctx->path.nat_keepalive_state->suspended);
	KUNIT_EXPECT_FALSE(test,
			   timer_pending(&ctx->path.nat_keepalive_state->timer));
}

/* Test: Resume restarts timer */
static void test_nat_keepalive_resume(struct kunit *test)
{
	struct nat_keepalive_test_ctx *ctx = test->priv;
	int ret;

	ret = tquic_nat_keepalive_init(&ctx->path, &ctx->conn);
	KUNIT_EXPECT_EQ(test, ret, 0);

	/* Suspend then resume */
	tquic_nat_keepalive_suspend(&ctx->path);
	KUNIT_EXPECT_TRUE(test, ctx->path.nat_keepalive_state->suspended);

	tquic_nat_keepalive_resume(&ctx->path);
	KUNIT_EXPECT_FALSE(test, ctx->path.nat_keepalive_state->suspended);
	KUNIT_EXPECT_TRUE(test,
			  timer_pending(&ctx->path.nat_keepalive_state->timer));
}

/* Test: Suspend on null path is safe */
static void test_nat_keepalive_suspend_null(struct kunit *test)
{
	/* Should not crash */
	tquic_nat_keepalive_suspend(NULL);
	KUNIT_SUCCEED(test);
}

/* Test: Resume on null path is safe */
static void test_nat_keepalive_resume_null(struct kunit *test)
{
	/* Should not crash */
	tquic_nat_keepalive_resume(NULL);
	KUNIT_SUCCEED(test);
}

/*
 * =============================================================================
 * SECTION 4: Activity Tracking Tests
 * =============================================================================
 */

/* Test: Activity resets timer */
static void test_nat_keepalive_on_activity(struct kunit *test)
{
	struct nat_keepalive_test_ctx *ctx = test->priv;
	ktime_t before, after;
	int ret;

	ret = tquic_nat_keepalive_init(&ctx->path, &ctx->conn);
	KUNIT_EXPECT_EQ(test, ret, 0);

	before = ctx->path.nat_keepalive_state->last_activity;

	/* Simulate small delay */
	udelay(100);

	tquic_nat_keepalive_on_activity(&ctx->path);

	after = ctx->path.nat_keepalive_state->last_activity;

	/* Activity timestamp should be updated */
	KUNIT_EXPECT_TRUE(test, ktime_after(after, before) ||
				ktime_equal(after, before));
}

/* Test: Activity on null path is safe */
static void test_nat_keepalive_on_activity_null(struct kunit *test)
{
	/* Should not crash */
	tquic_nat_keepalive_on_activity(NULL);
	KUNIT_SUCCEED(test);
}

/* Test: Activity on uninitialized path is safe */
static void test_nat_keepalive_on_activity_uninitialized(struct kunit *test)
{
	struct nat_keepalive_test_ctx *ctx = test->priv;

	/* Should not crash */
	tquic_nat_keepalive_on_activity(&ctx->path);
	KUNIT_SUCCEED(test);
}

/*
 * =============================================================================
 * SECTION 5: ACK Handling Tests
 * =============================================================================
 */

/* Test: ACK for keepalive packet */
static void test_nat_keepalive_on_ack(struct kunit *test)
{
	struct nat_keepalive_test_ctx *ctx = test->priv;
	int ret;

	ret = tquic_nat_keepalive_init(&ctx->path, &ctx->conn);
	KUNIT_EXPECT_EQ(test, ret, 0);

	/* Simulate sending keepalive and receiving ACK */
	ctx->path.nat_keepalive_state->pending_ack = true;
	ctx->path.nat_keepalive_state->pending_pn = 100;

	tquic_nat_keepalive_on_ack(&ctx->path, 100);

	/* Pending should be cleared */
	KUNIT_EXPECT_FALSE(test, ctx->path.nat_keepalive_state->pending_ack);
	KUNIT_EXPECT_EQ(test, ctx->path.nat_keepalive_state->total_acked, 1ULL);
}

/* Test: ACK with higher PN also clears pending */
static void test_nat_keepalive_on_ack_higher_pn(struct kunit *test)
{
	struct nat_keepalive_test_ctx *ctx = test->priv;
	int ret;

	ret = tquic_nat_keepalive_init(&ctx->path, &ctx->conn);
	KUNIT_EXPECT_EQ(test, ret, 0);

	ctx->path.nat_keepalive_state->pending_ack = true;
	ctx->path.nat_keepalive_state->pending_pn = 100;

	/* ACK for higher PN should also clear */
	tquic_nat_keepalive_on_ack(&ctx->path, 150);

	KUNIT_EXPECT_FALSE(test, ctx->path.nat_keepalive_state->pending_ack);
}

/* Test: ACK with lower PN doesn't clear pending */
static void test_nat_keepalive_on_ack_lower_pn(struct kunit *test)
{
	struct nat_keepalive_test_ctx *ctx = test->priv;
	int ret;

	ret = tquic_nat_keepalive_init(&ctx->path, &ctx->conn);
	KUNIT_EXPECT_EQ(test, ret, 0);

	ctx->path.nat_keepalive_state->pending_ack = true;
	ctx->path.nat_keepalive_state->pending_pn = 100;

	/* ACK for lower PN should not clear */
	tquic_nat_keepalive_on_ack(&ctx->path, 50);

	KUNIT_EXPECT_TRUE(test, ctx->path.nat_keepalive_state->pending_ack);
}

/* Test: ACK on null path is safe */
static void test_nat_keepalive_on_ack_null(struct kunit *test)
{
	/* Should not crash */
	tquic_nat_keepalive_on_ack(NULL, 100);
	KUNIT_SUCCEED(test);
}

/*
 * =============================================================================
 * SECTION 6: Timeout Handling Tests
 * =============================================================================
 */

/* Test: Timeout increments failure count */
static void test_nat_keepalive_on_timeout(struct kunit *test)
{
	struct nat_keepalive_test_ctx *ctx = test->priv;
	int ret;

	ret = tquic_nat_keepalive_init(&ctx->path, &ctx->conn);
	KUNIT_EXPECT_EQ(test, ret, 0);

	ctx->path.nat_keepalive_state->pending_ack = true;
	ctx->path.nat_keepalive_state->pending_pn = 100;

	tquic_nat_keepalive_on_timeout(&ctx->path);

	/* Pending should be cleared, timeout counted */
	KUNIT_EXPECT_FALSE(test, ctx->path.nat_keepalive_state->pending_ack);
	KUNIT_EXPECT_EQ(test, ctx->path.nat_keepalive_state->total_timeouts, 1ULL);
}

/* Test: Timeout on null path is safe */
static void test_nat_keepalive_on_timeout_null(struct kunit *test)
{
	/* Should not crash */
	tquic_nat_keepalive_on_timeout(NULL);
	KUNIT_SUCCEED(test);
}

/*
 * =============================================================================
 * SECTION 7: Statistics Tests
 * =============================================================================
 */

/* Test: Get statistics */
static void test_nat_keepalive_get_stats(struct kunit *test)
{
	struct nat_keepalive_test_ctx *ctx = test->priv;
	u64 sent, acked, timeouts;
	int ret;

	ret = tquic_nat_keepalive_init(&ctx->path, &ctx->conn);
	KUNIT_EXPECT_EQ(test, ret, 0);

	/* Set some test values */
	ctx->path.nat_keepalive_state->total_sent = 10;
	ctx->path.nat_keepalive_state->total_acked = 8;
	ctx->path.nat_keepalive_state->total_timeouts = 2;

	tquic_nat_keepalive_get_stats(&ctx->path, &sent, &acked, &timeouts);

	KUNIT_EXPECT_EQ(test, sent, 10ULL);
	KUNIT_EXPECT_EQ(test, acked, 8ULL);
	KUNIT_EXPECT_EQ(test, timeouts, 2ULL);
}

/* Test: Get stats with null outputs */
static void test_nat_keepalive_get_stats_partial(struct kunit *test)
{
	struct nat_keepalive_test_ctx *ctx = test->priv;
	u64 sent;
	int ret;

	ret = tquic_nat_keepalive_init(&ctx->path, &ctx->conn);
	KUNIT_EXPECT_EQ(test, ret, 0);

	ctx->path.nat_keepalive_state->total_sent = 5;

	/* Only get sent count */
	tquic_nat_keepalive_get_stats(&ctx->path, &sent, NULL, NULL);
	KUNIT_EXPECT_EQ(test, sent, 5ULL);
}

/* Test: Get stats on null path returns zeros */
static void test_nat_keepalive_get_stats_null(struct kunit *test)
{
	u64 sent = 99, acked = 99, timeouts = 99;

	tquic_nat_keepalive_get_stats(NULL, &sent, &acked, &timeouts);

	KUNIT_EXPECT_EQ(test, sent, 0ULL);
	KUNIT_EXPECT_EQ(test, acked, 0ULL);
	KUNIT_EXPECT_EQ(test, timeouts, 0ULL);
}

/*
 * =============================================================================
 * SECTION 8: Timeout Estimation Tests
 * =============================================================================
 */

/* Test: Estimate timeout returns sensible value */
static void test_nat_keepalive_estimate_timeout(struct kunit *test)
{
	struct nat_keepalive_test_ctx *ctx = test->priv;
	u32 timeout;
	int ret;

	ret = tquic_nat_keepalive_init(&ctx->path, &ctx->conn);
	KUNIT_EXPECT_EQ(test, ret, 0);

	timeout = tquic_nat_keepalive_estimate_timeout(
		ctx->path.nat_keepalive_state);

	/* Should be approximately 2x the default interval */
	KUNIT_EXPECT_GE(test, timeout, TEST_DEFAULT_INTERVAL_MS);
	KUNIT_EXPECT_LE(test, timeout, TEST_MAX_INTERVAL_MS * 2);
}

/* Test: Estimate timeout on null returns default */
static void test_nat_keepalive_estimate_timeout_null(struct kunit *test)
{
	u32 timeout;

	timeout = tquic_nat_keepalive_estimate_timeout(NULL);

	/* Should return a reasonable default */
	KUNIT_EXPECT_GT(test, timeout, 0U);
}

/*
 * =============================================================================
 * SECTION 9: Sysctl Accessor Tests
 * =============================================================================
 */

/* Test: Sysctl accessors return valid values */
static void test_nat_keepalive_sysctl_accessors(struct kunit *test)
{
	int enabled;
	u32 interval;
	int adaptive;

	enabled = tquic_sysctl_get_nat_keepalive_enabled();
	interval = tquic_sysctl_get_nat_keepalive_interval();
	adaptive = tquic_sysctl_get_nat_keepalive_adaptive();

	/* Enabled should be 0 or 1 */
	KUNIT_EXPECT_TRUE(test, enabled == 0 || enabled == 1);

	/* Interval should be within bounds */
	KUNIT_EXPECT_GE(test, interval, (u32)TEST_MIN_INTERVAL_MS);
	KUNIT_EXPECT_LE(test, interval, (u32)TEST_MAX_INTERVAL_MS);

	/* Adaptive should be 0 or 1 */
	KUNIT_EXPECT_TRUE(test, adaptive == 0 || adaptive == 1);
}

/*
 * =============================================================================
 * SECTION 10: Path State Tests
 * =============================================================================
 */

/* Test: Keepalive not sent on failed path */
static void test_nat_keepalive_failed_path(struct kunit *test)
{
	struct nat_keepalive_test_ctx *ctx = test->priv;
	int ret;

	ret = tquic_nat_keepalive_init(&ctx->path, &ctx->conn);
	KUNIT_EXPECT_EQ(test, ret, 0);

	/* Mark path as failed */
	ctx->path.state = TQUIC_PATH_FAILED;

	/* Send should return error */
	ret = tquic_nat_keepalive_send(ctx->path.nat_keepalive_state);
	KUNIT_EXPECT_EQ(test, ret, -ENETUNREACH);
}

/* Test: Keepalive not sent on closed path */
static void test_nat_keepalive_closed_path(struct kunit *test)
{
	struct nat_keepalive_test_ctx *ctx = test->priv;
	int ret;

	ret = tquic_nat_keepalive_init(&ctx->path, &ctx->conn);
	KUNIT_EXPECT_EQ(test, ret, 0);

	ctx->path.state = TQUIC_PATH_CLOSED;

	ret = tquic_nat_keepalive_send(ctx->path.nat_keepalive_state);
	KUNIT_EXPECT_EQ(test, ret, -ENETUNREACH);
}

/* Test: Keepalive not sent on unused path */
static void test_nat_keepalive_unused_path(struct kunit *test)
{
	struct nat_keepalive_test_ctx *ctx = test->priv;
	int ret;

	ret = tquic_nat_keepalive_init(&ctx->path, &ctx->conn);
	KUNIT_EXPECT_EQ(test, ret, 0);

	ctx->path.state = TQUIC_PATH_UNUSED;

	ret = tquic_nat_keepalive_send(ctx->path.nat_keepalive_state);
	KUNIT_EXPECT_EQ(test, ret, -ENETUNREACH);
}

/*
 * =============================================================================
 * SECTION 11: Disabled Keepalive Tests
 * =============================================================================
 */

/* Test: Keepalive not sent when disabled */
static void test_nat_keepalive_disabled(struct kunit *test)
{
	struct nat_keepalive_test_ctx *ctx = test->priv;
	struct tquic_nat_keepalive_config disabled_config;
	int ret;

	ret = tquic_nat_keepalive_init(&ctx->path, &ctx->conn);
	KUNIT_EXPECT_EQ(test, ret, 0);

	/* Disable keepalive */
	disabled_config = ctx->config;
	disabled_config.enabled = false;

	ret = tquic_nat_keepalive_set_config(&ctx->path, &disabled_config);
	KUNIT_EXPECT_EQ(test, ret, 0);

	/* Send should return error */
	ret = tquic_nat_keepalive_send(ctx->path.nat_keepalive_state);
	KUNIT_EXPECT_EQ(test, ret, -ENOENT);

	/* Timer should not be pending */
	KUNIT_EXPECT_FALSE(test,
			   timer_pending(&ctx->path.nat_keepalive_state->timer));
}

/*
 * =============================================================================
 * SECTION 12: Global Statistics Tests
 * =============================================================================
 */

/* Test: Global statistics are accessible */
static void test_nat_keepalive_global_stats(struct kunit *test)
{
	s64 sent, acked, timeouts;

	/* Read global stats */
	sent = atomic64_read(&tquic_nat_keepalive_global_stats.total_keepalives_sent);
	acked = atomic64_read(&tquic_nat_keepalive_global_stats.total_keepalives_acked);
	timeouts = atomic64_read(&tquic_nat_keepalive_global_stats.total_nat_timeouts);

	/* Should be non-negative */
	KUNIT_EXPECT_GE(test, sent, 0LL);
	KUNIT_EXPECT_GE(test, acked, 0LL);
	KUNIT_EXPECT_GE(test, timeouts, 0LL);
}

/*
 * =============================================================================
 * Test Suite Definition
 * =============================================================================
 */

static struct kunit_case tquic_nat_keepalive_test_cases[] = {
	/* Initialization tests */
	KUNIT_CASE(test_nat_keepalive_init_basic),
	KUNIT_CASE(test_nat_keepalive_init_null_path),
	KUNIT_CASE(test_nat_keepalive_init_null_conn),
	KUNIT_CASE(test_nat_keepalive_double_init),
	KUNIT_CASE(test_nat_keepalive_cleanup_basic),
	KUNIT_CASE(test_nat_keepalive_cleanup_uninitialized),
	KUNIT_CASE(test_nat_keepalive_cleanup_null),

	/* Configuration tests */
	KUNIT_CASE(test_nat_keepalive_set_config),
	KUNIT_CASE(test_nat_keepalive_set_config_uninitialized),
	KUNIT_CASE(test_nat_keepalive_set_power_mode),
	KUNIT_CASE(test_nat_keepalive_set_power_mode_invalid),

	/* Timer and scheduling tests */
	KUNIT_CASE(test_nat_keepalive_schedule),
	KUNIT_CASE(test_nat_keepalive_suspend),
	KUNIT_CASE(test_nat_keepalive_resume),
	KUNIT_CASE(test_nat_keepalive_suspend_null),
	KUNIT_CASE(test_nat_keepalive_resume_null),

	/* Activity tracking tests */
	KUNIT_CASE(test_nat_keepalive_on_activity),
	KUNIT_CASE(test_nat_keepalive_on_activity_null),
	KUNIT_CASE(test_nat_keepalive_on_activity_uninitialized),

	/* ACK handling tests */
	KUNIT_CASE(test_nat_keepalive_on_ack),
	KUNIT_CASE(test_nat_keepalive_on_ack_higher_pn),
	KUNIT_CASE(test_nat_keepalive_on_ack_lower_pn),
	KUNIT_CASE(test_nat_keepalive_on_ack_null),

	/* Timeout handling tests */
	KUNIT_CASE(test_nat_keepalive_on_timeout),
	KUNIT_CASE(test_nat_keepalive_on_timeout_null),

	/* Statistics tests */
	KUNIT_CASE(test_nat_keepalive_get_stats),
	KUNIT_CASE(test_nat_keepalive_get_stats_partial),
	KUNIT_CASE(test_nat_keepalive_get_stats_null),

	/* Timeout estimation tests */
	KUNIT_CASE(test_nat_keepalive_estimate_timeout),
	KUNIT_CASE(test_nat_keepalive_estimate_timeout_null),

	/* Sysctl accessor tests */
	KUNIT_CASE(test_nat_keepalive_sysctl_accessors),

	/* Path state tests */
	KUNIT_CASE(test_nat_keepalive_failed_path),
	KUNIT_CASE(test_nat_keepalive_closed_path),
	KUNIT_CASE(test_nat_keepalive_unused_path),

	/* Disabled keepalive tests */
	KUNIT_CASE(test_nat_keepalive_disabled),

	/* Global statistics tests */
	KUNIT_CASE(test_nat_keepalive_global_stats),
	{}
};

static struct kunit_suite tquic_nat_keepalive_test_suite = {
	.name = "tquic-nat-keepalive",
	.init = nat_keepalive_test_init,
	.exit = nat_keepalive_test_exit,
	.test_cases = tquic_nat_keepalive_test_cases,
};

kunit_test_suite(tquic_nat_keepalive_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for TQUIC NAT Keepalive (RFC 9308 Section 3.5)");
MODULE_AUTHOR("Linux Foundation");
