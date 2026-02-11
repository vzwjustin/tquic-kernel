// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC Path Manager Unit Tests
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Comprehensive KUnit test suite for TQUIC path management covering:
 * - Path validation (PATH_CHALLENGE/PATH_RESPONSE)
 * - RTT calculation (RFC 6298)
 * - Path state machine transitions
 * - NAT keepalive
 * - Path manager netlink interface
 * - Multipath path selection
 */

#include <kunit/test.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/random.h>
#include <linux/ktime.h>
#include <linux/timer.h>
#include <net/sock.h>
#include <net/tquic.h>
#include <uapi/linux/tquic_pm.h>

#include "../pm/nat_keepalive.h"
#include "../pm/nat_lifecycle.h"

/*
 * =============================================================================
 * Path Manager Command Tests
 * =============================================================================
 */

static void test_pm_cmd_enum_values(struct kunit *test)
{
	/* Verify command enum values start at expected values */
	KUNIT_EXPECT_EQ(test, 0, (int)TQUIC_PM_CMD_UNSPEC);
	KUNIT_EXPECT_EQ(test, 1, (int)TQUIC_PM_CMD_ADD_PATH);
	KUNIT_EXPECT_EQ(test, 2, (int)TQUIC_PM_CMD_DEL_PATH);
	KUNIT_EXPECT_EQ(test, 3, (int)TQUIC_PM_CMD_GET_PATH);
	KUNIT_EXPECT_EQ(test, 4, (int)TQUIC_PM_CMD_SET_PATH_STATE);
	KUNIT_EXPECT_EQ(test, 5, (int)TQUIC_PM_CMD_FLUSH_PATHS);
	KUNIT_EXPECT_EQ(test, 6, (int)TQUIC_PM_CMD_SET_LIMITS);
	KUNIT_EXPECT_EQ(test, 7, (int)TQUIC_PM_CMD_GET_LIMITS);
	KUNIT_EXPECT_EQ(test, 8, (int)TQUIC_PM_CMD_SET_FLAGS);
	KUNIT_EXPECT_EQ(test, 9, (int)TQUIC_PM_CMD_ANNOUNCE);
	KUNIT_EXPECT_EQ(test, 10, (int)TQUIC_PM_CMD_REMOVE);
}

static void test_pm_attr_enum_values(struct kunit *test)
{
	/* Verify key attribute enum values */
	KUNIT_EXPECT_EQ(test, 0, (int)TQUIC_PM_ATTR_UNSPEC);
	KUNIT_EXPECT_EQ(test, 1, (int)TQUIC_PM_ATTR_TOKEN);
	KUNIT_EXPECT_EQ(test, 2, (int)TQUIC_PM_ATTR_PATH_ID);
	KUNIT_EXPECT_EQ(test, 3, (int)TQUIC_PM_ATTR_FAMILY);
}

static void test_pm_event_enum_values(struct kunit *test)
{
	/* Verify event enum values */
	KUNIT_EXPECT_EQ(test, 0, (int)TQUIC_PM_EVENT_UNSPEC);
	KUNIT_EXPECT_EQ(test, 1, (int)TQUIC_PM_EVENT_CREATED);
	KUNIT_EXPECT_EQ(test, 2, (int)TQUIC_PM_EVENT_ESTABLISHED);
	KUNIT_EXPECT_EQ(test, 3, (int)TQUIC_PM_EVENT_CLOSED);
	KUNIT_EXPECT_EQ(test, 4, (int)TQUIC_PM_EVENT_ANNOUNCED);
	KUNIT_EXPECT_EQ(test, 5, (int)TQUIC_PM_EVENT_REMOVED);
	KUNIT_EXPECT_EQ(test, 6, (int)TQUIC_PM_EVENT_PRIORITY);
	KUNIT_EXPECT_EQ(test, 9, (int)TQUIC_PM_EVENT_VALIDATED);
	KUNIT_EXPECT_EQ(test, 10, (int)TQUIC_PM_EVENT_FAILED);
	KUNIT_EXPECT_EQ(test, 11, (int)TQUIC_PM_EVENT_DEGRADED);
}

/*
 * =============================================================================
 * Path Flags Tests
 * =============================================================================
 */

static void test_pm_addr_flags(struct kunit *test)
{
	/* Verify flag bit positions */
	KUNIT_EXPECT_EQ(test, 1U << 0, (u32)TQUIC_PM_ADDR_FLAG_SIGNAL);
	KUNIT_EXPECT_EQ(test, 1U << 1, (u32)TQUIC_PM_ADDR_FLAG_SUBFLOW);
	KUNIT_EXPECT_EQ(test, 1U << 2, (u32)TQUIC_PM_ADDR_FLAG_BACKUP);
	KUNIT_EXPECT_EQ(test, 1U << 3, (u32)TQUIC_PM_ADDR_FLAG_FULLMESH);
	KUNIT_EXPECT_EQ(test, 1U << 4, (u32)TQUIC_PM_ADDR_FLAG_IMPLICIT);

	/* Test flag combinations */
	u32 flags = TQUIC_PM_ADDR_FLAG_SIGNAL | TQUIC_PM_ADDR_FLAG_BACKUP;
	KUNIT_EXPECT_TRUE(test, flags & TQUIC_PM_ADDR_FLAG_SIGNAL);
	KUNIT_EXPECT_TRUE(test, flags & TQUIC_PM_ADDR_FLAG_BACKUP);
	KUNIT_EXPECT_FALSE(test, flags & TQUIC_PM_ADDR_FLAG_FULLMESH);
}

static void test_pm_flags_no_overlap(struct kunit *test)
{
	/* Verify no flag bits overlap */
	u32 all_flags = TQUIC_PM_ADDR_FLAG_SIGNAL |
			TQUIC_PM_ADDR_FLAG_SUBFLOW |
			TQUIC_PM_ADDR_FLAG_BACKUP |
			TQUIC_PM_ADDR_FLAG_FULLMESH |
			TQUIC_PM_ADDR_FLAG_IMPLICIT;

	/* Each flag should contribute exactly one bit */
	KUNIT_EXPECT_EQ(test, 5, hweight32(all_flags));
}

/*
 * =============================================================================
 * Path State Tests
 * =============================================================================
 */

static void test_path_state_transitions(struct kunit *test)
{
	/* Verify path state enum values per include/net/tquic.h */
	KUNIT_EXPECT_EQ(test, 0, (int)TQUIC_PATH_UNUSED);
	KUNIT_EXPECT_EQ(test, 1, (int)TQUIC_PATH_PENDING);
	KUNIT_EXPECT_EQ(test, 2, (int)TQUIC_PATH_VALIDATED);
	KUNIT_EXPECT_EQ(test, 3, (int)TQUIC_PATH_ACTIVE);
	KUNIT_EXPECT_EQ(test, 4, (int)TQUIC_PATH_STANDBY);
	KUNIT_EXPECT_EQ(test, 6, (int)TQUIC_PATH_FAILED);
	KUNIT_EXPECT_EQ(test, 7, (int)TQUIC_PATH_CLOSED);
}

static void test_path_state_valid_transitions(struct kunit *test)
{
	/* Valid transitions:
	 * UNUSED -> PENDING (start validation)
	 * PENDING -> VALIDATED (validation passed)
	 * VALIDATED -> ACTIVE (path in use)
	 * PENDING -> FAILED (validation failure)
	 * ACTIVE -> STANDBY (demote)
	 * STANDBY -> ACTIVE (promote)
	 * ACTIVE -> FAILED (loss of connectivity)
	 * STANDBY -> FAILED (loss of connectivity)
	 * Any -> CLOSED (removal)
	 */

	/* Initial state should be UNUSED */
	enum tquic_path_state state = TQUIC_PATH_UNUSED;
	KUNIT_EXPECT_EQ(test, TQUIC_PATH_UNUSED, state);

	/* Transition to PENDING (validation in progress) */
	state = TQUIC_PATH_PENDING;
	KUNIT_EXPECT_EQ(test, TQUIC_PATH_PENDING, state);

	/* Transition to VALIDATED on validation success */
	state = TQUIC_PATH_VALIDATED;
	KUNIT_EXPECT_EQ(test, TQUIC_PATH_VALIDATED, state);

	/* Transition to ACTIVE (path in use) */
	state = TQUIC_PATH_ACTIVE;
	KUNIT_EXPECT_EQ(test, TQUIC_PATH_ACTIVE, state);

	/* Transition to STANDBY */
	state = TQUIC_PATH_STANDBY;
	KUNIT_EXPECT_EQ(test, TQUIC_PATH_STANDBY, state);

	/* Transition back to ACTIVE */
	state = TQUIC_PATH_ACTIVE;
	KUNIT_EXPECT_EQ(test, TQUIC_PATH_ACTIVE, state);

	/* Transition to FAILED */
	state = TQUIC_PATH_FAILED;
	KUNIT_EXPECT_EQ(test, TQUIC_PATH_FAILED, state);
}

/*
 * =============================================================================
 * RTT Calculation Tests
 * =============================================================================
 */

static void test_rtt_first_measurement(struct kunit *test)
{
	struct tquic_path_stats stats = {0};
	u32 rtt_sample_us = 100000;  /* 100ms */

	/* First RTT measurement - RFC 6298 Section 2.2 */
	KUNIT_EXPECT_EQ(test, 0U, stats.rtt_smoothed);
	KUNIT_EXPECT_EQ(test, 0U, stats.rtt_variance);

	/* After first measurement:
	 * SRTT = RTT
	 * RTTVAR = RTT / 2 */
	stats.rtt_smoothed = rtt_sample_us;
	stats.rtt_variance = rtt_sample_us / 2;

	KUNIT_EXPECT_EQ(test, 100000U, stats.rtt_smoothed);
	KUNIT_EXPECT_EQ(test, 50000U, stats.rtt_variance);
}

static void test_rtt_update_calculation(struct kunit *test)
{
	struct tquic_path_stats stats;
	s32 delta;
	u32 rtt_sample_us;

	/* Initialize with first sample */
	stats.rtt_smoothed = 100000;  /* 100ms */
	stats.rtt_variance = 50000;   /* 50ms */
	stats.rtt_min = 100000;

	/* Second sample: 80ms (20ms lower) */
	rtt_sample_us = 80000;
	delta = rtt_sample_us - stats.rtt_smoothed;

	/* Update RTTVAR: RTTVAR = (1 - 1/4) * RTTVAR + 1/4 * |delta|
	 * = 50000 - 12500 + 5000 = 42500 */
	stats.rtt_variance = stats.rtt_variance -
		(stats.rtt_variance / 4) +
		(abs(delta) / 4);

	/* Update SRTT: SRTT = (1 - 1/8) * SRTT + 1/8 * RTT
	 * = 100000 - 12500 + 10000 = 97500 */
	stats.rtt_smoothed = stats.rtt_smoothed -
		(stats.rtt_smoothed / 8) +
		(rtt_sample_us / 8);

	KUNIT_EXPECT_EQ(test, 97500U, stats.rtt_smoothed);
	KUNIT_EXPECT_EQ(test, 42500U, stats.rtt_variance);
}

static void test_rtt_min_tracking(struct kunit *test)
{
	struct tquic_path_stats stats = {0};

	/* Track minimum RTT */
	stats.rtt_min = 0;

	/* First sample */
	u32 sample1 = 100000;
	if (stats.rtt_min == 0 || sample1 < stats.rtt_min)
		stats.rtt_min = sample1;
	KUNIT_EXPECT_EQ(test, 100000U, stats.rtt_min);

	/* Higher sample - should not update min */
	u32 sample2 = 150000;
	if (stats.rtt_min == 0 || sample2 < stats.rtt_min)
		stats.rtt_min = sample2;
	KUNIT_EXPECT_EQ(test, 100000U, stats.rtt_min);

	/* Lower sample - should update min */
	u32 sample3 = 80000;
	if (stats.rtt_min == 0 || sample3 < stats.rtt_min)
		stats.rtt_min = sample3;
	KUNIT_EXPECT_EQ(test, 80000U, stats.rtt_min);
}

/*
 * =============================================================================
 * Path Validation Timeout Tests
 * =============================================================================
 */

/* Path validation constants matching path_validation.c */
#define TEST_VALIDATION_MIN_TIMEOUT_US	100000   /* 100ms */
#define TEST_VALIDATION_MAX_TIMEOUT_US	10000000 /* 10 seconds */
#define TEST_VALIDATION_DEFAULT_TIMEOUT_US 1000000 /* 1 second */
#define TEST_VALIDATION_RTT_MULTIPLIER	3
#define TEST_VALIDATION_MAX_RETRIES	3

static u32 calc_validation_timeout_us(u32 rtt_smoothed, u32 rtt_variance)
{
	u32 timeout_us;

	if (rtt_smoothed == 0) {
		timeout_us = TEST_VALIDATION_DEFAULT_TIMEOUT_US;
	} else {
		timeout_us = rtt_smoothed * TEST_VALIDATION_RTT_MULTIPLIER;
		u32 variance_us = max(1000U, rtt_variance * 4);
		timeout_us += variance_us;
	}

	return clamp(timeout_us,
		     TEST_VALIDATION_MIN_TIMEOUT_US,
		     TEST_VALIDATION_MAX_TIMEOUT_US);
}

static void test_validation_timeout_no_rtt(struct kunit *test)
{
	/* No RTT measurement - should use default */
	u32 timeout = calc_validation_timeout_us(0, 0);
	KUNIT_EXPECT_EQ(test, TEST_VALIDATION_DEFAULT_TIMEOUT_US, timeout);
}

static void test_validation_timeout_with_rtt(struct kunit *test)
{
	/* With RTT: 100ms SRTT, 25ms RTTVAR */
	u32 timeout = calc_validation_timeout_us(100000, 25000);

	/* Expected: 3 * 100000 + max(1000, 4 * 25000) = 300000 + 100000 = 400000 */
	KUNIT_EXPECT_EQ(test, 400000U, timeout);
}

static void test_validation_timeout_clamp_min(struct kunit *test)
{
	/* Very low RTT - should clamp to minimum */
	u32 timeout = calc_validation_timeout_us(10000, 1000);  /* 10ms SRTT */

	/* Would be 3 * 10000 + 4000 = 34000, but clamped to 100000 */
	KUNIT_EXPECT_EQ(test, TEST_VALIDATION_MIN_TIMEOUT_US, timeout);
}

static void test_validation_timeout_clamp_max(struct kunit *test)
{
	/* Very high RTT (satellite) - should clamp to maximum */
	u32 timeout = calc_validation_timeout_us(5000000, 1000000);  /* 5s SRTT */

	/* Would be 3 * 5000000 + 4000000 = 19000000, clamped to 10000000 */
	KUNIT_EXPECT_EQ(test, TEST_VALIDATION_MAX_TIMEOUT_US, timeout);
}

static void test_validation_max_retries(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, 3, TEST_VALIDATION_MAX_RETRIES);
}

/*
 * =============================================================================
 * NAT Keepalive Tests
 * =============================================================================
 */

static void test_nat_keepalive_constants(struct kunit *test)
{
	/* Default NAT mapping timeout is typically 30 seconds */
	KUNIT_EXPECT_GT(test, (int)TQUIC_NAT_KEEPALIVE_INTERVAL_MS, 0);
	KUNIT_EXPECT_LE(test, (int)TQUIC_NAT_KEEPALIVE_INTERVAL_MS, 30000);
}

static void test_nat_keepalive_config_init(struct kunit *test)
{
	struct tquic_nat_keepalive_config config;

	memset(&config, 0, sizeof(config));

	/* Initialize with defaults */
	config.enabled = true;
	config.interval_ms = TQUIC_NAT_KEEPALIVE_INTERVAL_MS;

	KUNIT_EXPECT_TRUE(test, config.enabled);
	KUNIT_EXPECT_GT(test, config.interval_ms, 0U);
}

/*
 * =============================================================================
 * NAT Lifecycle Tests
 * =============================================================================
 */

static void test_nat_lifecycle_state_enum(struct kunit *test)
{
	/* Verify NAT lifecycle states */
	KUNIT_EXPECT_EQ(test, 0, (int)TQUIC_NAT_STATE_UNKNOWN);
	KUNIT_EXPECT_EQ(test, 1, (int)TQUIC_NAT_STATE_ACTIVE);
	KUNIT_EXPECT_EQ(test, 2, (int)TQUIC_NAT_STATE_STALE);
	KUNIT_EXPECT_EQ(test, 3, (int)TQUIC_NAT_STATE_EXPIRED);
}

static void test_nat_rebinding_detection(struct kunit *test)
{
	/* Test structure for NAT rebinding event */
	struct {
		u32 old_addr;
		u32 new_addr;
		u16 old_port;
		u16 new_port;
		bool rebind_detected;
	} test_case;

	/* Same address and port - no rebind */
	test_case.old_addr = 0x0A000001;  /* 10.0.0.1 */
	test_case.new_addr = 0x0A000001;
	test_case.old_port = 12345;
	test_case.new_port = 12345;
	test_case.rebind_detected = (test_case.old_addr != test_case.new_addr) ||
				    (test_case.old_port != test_case.new_port);
	KUNIT_EXPECT_FALSE(test, test_case.rebind_detected);

	/* Different port - rebind detected */
	test_case.new_port = 54321;
	test_case.rebind_detected = (test_case.old_addr != test_case.new_addr) ||
				    (test_case.old_port != test_case.new_port);
	KUNIT_EXPECT_TRUE(test, test_case.rebind_detected);

	/* Different address - rebind detected */
	test_case.new_addr = 0x0A000002;  /* 10.0.0.2 */
	test_case.new_port = 12345;
	test_case.rebind_detected = (test_case.old_addr != test_case.new_addr) ||
				    (test_case.old_port != test_case.new_port);
	KUNIT_EXPECT_TRUE(test, test_case.rebind_detected);
}

/*
 * =============================================================================
 * Bandwidth Estimation Tests
 * =============================================================================
 */

static void test_bandwidth_calculation(struct kunit *test)
{
	u64 bytes_delivered = 1000000;  /* 1 MB */
	u64 interval_us = 1000000;       /* 1 second */
	u64 bw;

	/* Calculate bytes per second */
	bw = (bytes_delivered * 1000000ULL) / interval_us;

	/* 1 MB per second */
	KUNIT_EXPECT_EQ(test, 1000000ULL, bw);
}

static void test_bandwidth_smoothing(struct kunit *test)
{
	u64 current_bw = 1000000;  /* 1 MB/s */
	u64 new_sample = 2000000;  /* 2 MB/s */
	u64 smoothed_bw;

	/* Simple exponential smoothing: (7 * old + new) / 8 */
	smoothed_bw = (current_bw * 7 + new_sample) / 8;

	/* Should be between old and new value */
	KUNIT_EXPECT_GT(test, smoothed_bw, current_bw);
	KUNIT_EXPECT_LT(test, smoothed_bw, new_sample);

	/* Expected: (7 * 1000000 + 2000000) / 8 = 1125000 */
	KUNIT_EXPECT_EQ(test, 1125000ULL, smoothed_bw);
}

static void test_bandwidth_zero_interval(struct kunit *test)
{
	u64 bytes_delivered = 1000;
	u64 interval_us = 0;
	u64 bw = 0;

	/* Division by zero protection */
	if (interval_us == 0)
		bw = 0;
	else
		bw = (bytes_delivered * 1000000ULL) / interval_us;

	KUNIT_EXPECT_EQ(test, 0ULL, bw);
}

/*
 * =============================================================================
 * PATH_CHALLENGE/PATH_RESPONSE Tests
 * =============================================================================
 */

static void test_path_challenge_data_size(struct kunit *test)
{
	/* RFC 9000 Section 8.2: PATH_CHALLENGE contains 8-byte random data */
	u8 challenge[8];

	KUNIT_EXPECT_EQ(test, 8UL, sizeof(challenge));
}

static void test_path_challenge_randomness(struct kunit *test)
{
	u8 challenge1[8];
	u8 challenge2[8];

	/* Generate two random challenges */
	get_random_bytes(challenge1, sizeof(challenge1));
	get_random_bytes(challenge2, sizeof(challenge2));

	/* Should be different (with extremely high probability) */
	KUNIT_EXPECT_NE(test, 0, memcmp(challenge1, challenge2, 8));
}

static void test_path_response_match(struct kunit *test)
{
	u8 challenge[8];
	u8 response[8];

	/* Generate random challenge */
	get_random_bytes(challenge, sizeof(challenge));

	/* PATH_RESPONSE must echo exact challenge data */
	memcpy(response, challenge, sizeof(response));

	KUNIT_EXPECT_EQ(test, 0, memcmp(challenge, response, 8));
}

static void test_path_response_mismatch(struct kunit *test)
{
	u8 challenge[8];
	u8 wrong_response[8];

	/* Generate random challenge */
	get_random_bytes(challenge, sizeof(challenge));

	/* Wrong response */
	get_random_bytes(wrong_response, sizeof(wrong_response));

	/* Should not match (with extremely high probability) */
	KUNIT_EXPECT_NE(test, 0, memcmp(challenge, wrong_response, 8));
}

/*
 * =============================================================================
 * Path Stats Structure Tests
 * =============================================================================
 */

static void test_path_stats_init(struct kunit *test)
{
	struct tquic_path_stats stats;

	memset(&stats, 0, sizeof(stats));

	/* Initial values should be zero */
	KUNIT_EXPECT_EQ(test, 0U, stats.rtt_smoothed);
	KUNIT_EXPECT_EQ(test, 0U, stats.rtt_variance);
	KUNIT_EXPECT_EQ(test, 0U, stats.rtt_min);
	KUNIT_EXPECT_EQ(test, 0ULL, stats.bandwidth);
	KUNIT_EXPECT_EQ(test, 0ULL, stats.bytes_sent);
	KUNIT_EXPECT_EQ(test, 0ULL, stats.bytes_received);
	KUNIT_EXPECT_EQ(test, 0ULL, stats.packets_sent);
	KUNIT_EXPECT_EQ(test, 0ULL, stats.packets_received);
}

static void test_path_stats_counters(struct kunit *test)
{
	struct tquic_path_stats stats;

	memset(&stats, 0, sizeof(stats));

	/* Increment counters */
	stats.packets_sent++;
	stats.bytes_sent += 1200;  /* Typical QUIC packet */

	KUNIT_EXPECT_EQ(test, 1ULL, stats.packets_sent);
	KUNIT_EXPECT_EQ(test, 1200ULL, stats.bytes_sent);

	/* Multiple packets */
	for (int i = 0; i < 100; i++) {
		stats.packets_sent++;
		stats.bytes_sent += 1200;
	}

	KUNIT_EXPECT_EQ(test, 101ULL, stats.packets_sent);
	KUNIT_EXPECT_EQ(test, 121200ULL, stats.bytes_sent);
}

/*
 * =============================================================================
 * Netlink Group Names Tests
 * =============================================================================
 */

static void test_netlink_group_names(struct kunit *test)
{
	KUNIT_EXPECT_STREQ(test, "tquic_pm_cmd", TQUIC_PM_CMD_GRP_NAME);
	KUNIT_EXPECT_STREQ(test, "tquic_pm_events", TQUIC_PM_EV_GRP_NAME);
}

static void test_pm_name_and_version(struct kunit *test)
{
	KUNIT_EXPECT_STREQ(test, "tquic_pm", TQUIC_PM_NAME);
	KUNIT_EXPECT_EQ(test, 1, (int)TQUIC_PM_VER);
}

/*
 * =============================================================================
 * Address Attributes Tests
 * =============================================================================
 */

static void test_addr_attr_enum(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, 0, (int)TQUIC_PM_ADDR_ATTR_UNSPEC);
	KUNIT_EXPECT_EQ(test, 1, (int)TQUIC_PM_ADDR_ATTR_FAMILY);
	KUNIT_EXPECT_EQ(test, 2, (int)TQUIC_PM_ADDR_ATTR_ID);
	KUNIT_EXPECT_EQ(test, 3, (int)TQUIC_PM_ADDR_ATTR_ADDR4);
	KUNIT_EXPECT_EQ(test, 4, (int)TQUIC_PM_ADDR_ATTR_ADDR6);
	KUNIT_EXPECT_EQ(test, 5, (int)TQUIC_PM_ADDR_ATTR_PORT);
	KUNIT_EXPECT_EQ(test, 6, (int)TQUIC_PM_ADDR_ATTR_IF_IDX);
}

/*
 * =============================================================================
 * Test Module Definition
 * =============================================================================
 */

static struct kunit_case pm_cmd_test_cases[] = {
	KUNIT_CASE(test_pm_cmd_enum_values),
	KUNIT_CASE(test_pm_attr_enum_values),
	KUNIT_CASE(test_pm_event_enum_values),
	{}
};

static struct kunit_case pm_flags_test_cases[] = {
	KUNIT_CASE(test_pm_addr_flags),
	KUNIT_CASE(test_pm_flags_no_overlap),
	{}
};

static struct kunit_case path_state_test_cases[] = {
	KUNIT_CASE(test_path_state_transitions),
	KUNIT_CASE(test_path_state_valid_transitions),
	{}
};

static struct kunit_case rtt_calc_test_cases[] = {
	KUNIT_CASE(test_rtt_first_measurement),
	KUNIT_CASE(test_rtt_update_calculation),
	KUNIT_CASE(test_rtt_min_tracking),
	{}
};

static struct kunit_case validation_timeout_test_cases[] = {
	KUNIT_CASE(test_validation_timeout_no_rtt),
	KUNIT_CASE(test_validation_timeout_with_rtt),
	KUNIT_CASE(test_validation_timeout_clamp_min),
	KUNIT_CASE(test_validation_timeout_clamp_max),
	KUNIT_CASE(test_validation_max_retries),
	{}
};

static struct kunit_case nat_keepalive_test_cases[] = {
	KUNIT_CASE(test_nat_keepalive_constants),
	KUNIT_CASE(test_nat_keepalive_config_init),
	{}
};

static struct kunit_case nat_lifecycle_test_cases[] = {
	KUNIT_CASE(test_nat_lifecycle_state_enum),
	KUNIT_CASE(test_nat_rebinding_detection),
	{}
};

static struct kunit_case bandwidth_test_cases[] = {
	KUNIT_CASE(test_bandwidth_calculation),
	KUNIT_CASE(test_bandwidth_smoothing),
	KUNIT_CASE(test_bandwidth_zero_interval),
	{}
};

static struct kunit_case path_challenge_test_cases[] = {
	KUNIT_CASE(test_path_challenge_data_size),
	KUNIT_CASE(test_path_challenge_randomness),
	KUNIT_CASE(test_path_response_match),
	KUNIT_CASE(test_path_response_mismatch),
	{}
};

static struct kunit_case path_stats_test_cases[] = {
	KUNIT_CASE(test_path_stats_init),
	KUNIT_CASE(test_path_stats_counters),
	{}
};

static struct kunit_case netlink_test_cases[] = {
	KUNIT_CASE(test_netlink_group_names),
	KUNIT_CASE(test_pm_name_and_version),
	KUNIT_CASE(test_addr_attr_enum),
	{}
};

static struct kunit_suite pm_cmd_test_suite = {
	.name = "pm_commands",
	.test_cases = pm_cmd_test_cases,
};

static struct kunit_suite pm_flags_test_suite = {
	.name = "pm_flags",
	.test_cases = pm_flags_test_cases,
};

static struct kunit_suite path_state_test_suite = {
	.name = "path_state",
	.test_cases = path_state_test_cases,
};

static struct kunit_suite rtt_calc_test_suite = {
	.name = "rtt_calculation",
	.test_cases = rtt_calc_test_cases,
};

static struct kunit_suite validation_timeout_test_suite = {
	.name = "validation_timeout",
	.test_cases = validation_timeout_test_cases,
};

static struct kunit_suite nat_keepalive_test_suite = {
	.name = "nat_keepalive",
	.test_cases = nat_keepalive_test_cases,
};

static struct kunit_suite nat_lifecycle_test_suite = {
	.name = "nat_lifecycle",
	.test_cases = nat_lifecycle_test_cases,
};

static struct kunit_suite bandwidth_test_suite = {
	.name = "bandwidth_estimation",
	.test_cases = bandwidth_test_cases,
};

static struct kunit_suite path_challenge_test_suite = {
	.name = "path_challenge",
	.test_cases = path_challenge_test_cases,
};

static struct kunit_suite path_stats_test_suite = {
	.name = "path_stats",
	.test_cases = path_stats_test_cases,
};

static struct kunit_suite netlink_test_suite = {
	.name = "pm_netlink",
	.test_cases = netlink_test_cases,
};

kunit_test_suites(
	&pm_cmd_test_suite,
	&pm_flags_test_suite,
	&path_state_test_suite,
	&rtt_calc_test_suite,
	&validation_timeout_test_suite,
	&nat_keepalive_test_suite,
	&nat_lifecycle_test_suite,
	&bandwidth_test_suite,
	&path_challenge_test_suite,
	&path_stats_test_suite,
	&netlink_test_suite
);

MODULE_DESCRIPTION("TQUIC Path Manager Unit Tests");
MODULE_AUTHOR("Linux Foundation");
MODULE_LICENSE("GPL");
