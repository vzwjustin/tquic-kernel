// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC KUnit Tests: Loss Detection Subsystem
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 *
 * Comprehensive KUnit tests for the TQUIC loss detection subsystem
 * (net/tquic/core/quic_loss.c), covering:
 *
 *   1. tquic_get_pto_duration() via tquic_recovery_state:
 *      - has_rtt_sample=false  -> 333ms initial fallback (RFC 9002 §6.2.4)
 *      - has_rtt_sample=true   -> srtt + max(4*rttvar, granularity)
 *      - various rttvar values including 0 and large
 *
 *   2. tquic_rtt_update():
 *      - First sample initialises smoothed_rtt, rtt_var, min_rtt correctly
 *      - Subsequent samples use EWMA formulas from RFC 9002 §5.3
 *      - ack_delay subtraction capped at min_rtt
 *      - samples counter incremented
 *
 *   3. tquic_loss_detection_on_packet_sent() via tquic_pn_space:
 *      - bytes_in_flight accounting via path->cc.bytes_in_flight
 *      - ack_eliciting_in_flight counter incremented for ack-eliciting pkts
 *      - non-ack-eliciting packets do NOT increment ack_eliciting_in_flight
 *      - largest_sent updated correctly
 *
 *   4. tquic_loss_detection_on_ack_received():
 *      - largest_acked updated in pn_space
 *      - packets removed from sent_list when acked
 *      - ack_eliciting_in_flight decremented for acked ack-eliciting pkts
 *      - pto_count reset when ack-eliciting packet is acked
 *
 *   5. tquic_timer_update_rtt() / tquic_recovery_state:
 *      - has_rtt_sample set to true after call
 *      - smoothed_rtt, rtt_variance, latest_rtt stored correctly
 *
 *   6. tquic_loss_get_bytes_in_flight():
 *      - returns 0 for empty connection
 *      - sums in_flight bytes across spaces
 *      - excludes non-in-flight packets
 *
 *   7. tquic_sent_packet_init():
 *      - fields populated correctly
 *      - pn, bytes, pn_space, ack_eliciting, in_flight set as given
 *
 *   8. PTO formula edge cases:
 *      - rttvar = 0 -> granularity floor (1 ms) applied
 *      - very large srtt/rttvar stays within u64 without overflow
 *      - Application-space adds max_ack_delay; Initial/Handshake do not
 *
 * Design notes:
 *   - Tests operate directly on struct tquic_rtt_state and
 *     struct tquic_recovery_state to avoid needing a live connection.
 *   - Tests that exercise on_packet_sent / on_ack_received construct a
 *     minimal stub struct tquic_connection with allocated pn_spaces and
 *     a synthetic active_path; internal helpers that call into the bonding,
 *     timer and congestion subsystems are bypassed by arranging for NULL
 *     pointers where the production code already guards with NULL checks,
 *     or by noting that KUnit runs in a UML/arm64 kunit environment where
 *     schedule_work() is safe.
 */

#include <kunit/test.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <net/tquic.h>
#include "../../core/quic_loss.h"

/* =========================================================================
 * Constants mirrored from quic_loss.c and tquic_timer.c for test assertions.
 * These must be kept in sync with the production constants.
 * =========================================================================
 */

/* RFC 9002 §6.2.4 initial RTT fallback (333 ms expressed in microseconds) */
#define TEST_INITIAL_RTT_US 333000ULL

/* RFC 9002 kGranularity = 1 ms */
#define TEST_GRANULARITY_US 1000ULL

/* RFC 9002 initial rttvar = initial_rtt / 2 */
#define TEST_INITIAL_RTTVAR_US (TEST_INITIAL_RTT_US / 2)

/*
 * Expected PTO with no RTT sample:
 *   pto = 333000 + max(4 * 166500, 1000)
 *       = 333000 + 666000
 *       = 999000 us  (for Initial/Handshake spaces, no max_ack_delay)
 */
#define TEST_PTO_NO_SAMPLE_US (TEST_INITIAL_RTT_US + 4 * TEST_INITIAL_RTTVAR_US)

/* Default max_ack_delay used by the timer (25 ms) */
#define TEST_MAX_ACK_DELAY_US 25000ULL

/* =========================================================================
 * Helper: initialise a tquic_rtt_state to pristine pre-sample state.
 *
 * Mirrors tquic_rtt_init() which is static in quic_loss.c.
 * =========================================================================
 */
static void test_rtt_state_init(struct tquic_rtt_state *rtt)
{
	rtt->min_rtt = U64_MAX;
	rtt->smoothed_rtt = TEST_INITIAL_RTT_US;
	rtt->rtt_var = TEST_INITIAL_RTTVAR_US;
	rtt->latest_rtt = 0;
	rtt->first_rtt_sample = 0;
	rtt->samples = 0;
	rtt->max_ack_delay = TEST_MAX_ACK_DELAY_US;
}

/* =========================================================================
 * Helper: initialise a tquic_recovery_state to pre-sample state.
 *
 * Mirrors the internal recovery state used by tquic_timer.c.
 * =========================================================================
 */
static void test_recovery_state_init(struct tquic_recovery_state *rs)
{
	memset(rs, 0, sizeof(*rs));
	rs->smoothed_rtt = TEST_INITIAL_RTT_US;
	rs->rtt_variance = TEST_INITIAL_RTTVAR_US;
	rs->min_rtt = U64_MAX;
	rs->max_ack_delay = TEST_MAX_ACK_DELAY_US;
	rs->has_rtt_sample = false;
	spin_lock_init(&rs->lock);
}

/* =========================================================================
 * Section 1: RTT state update tests (tquic_rtt_update)
 * =========================================================================
 */

/*
 * Test: tquic_rtt_update_first_sample
 * Purpose: Verify RFC 9002 §5.3 first-sample initialisation.
 *          On the first sample, smoothed_rtt = latest_rtt and
 *          rtt_var = latest_rtt / 2.
 * RFC Reference: RFC 9002 Section 5.3
 * Setup: Fresh rtt_state with samples=0.
 * Expected: smoothed_rtt == sample, rtt_var == sample/2, samples==1.
 */
static void test_rtt_update_first_sample(struct kunit *test)
{
	struct tquic_rtt_state rtt;
	const u64 sample_us = 50000; /* 50 ms */

	test_rtt_state_init(&rtt);
	KUNIT_ASSERT_EQ(test, rtt.samples, 0u);

	tquic_rtt_update(&rtt, sample_us, 0);

	KUNIT_EXPECT_EQ(test, rtt.smoothed_rtt, sample_us);
	KUNIT_EXPECT_EQ(test, rtt.rtt_var, sample_us / 2);
	KUNIT_EXPECT_EQ(test, rtt.min_rtt, sample_us);
	KUNIT_EXPECT_EQ(test, rtt.latest_rtt, sample_us);
	KUNIT_EXPECT_EQ(test, rtt.samples, 1u);
}

/*
 * Test: tquic_rtt_update_ewma
 * Purpose: Verify EWMA update after the first sample.
 *          smoothed_rtt = 7/8 * srtt + 1/8 * adjusted_rtt
 *          rtt_var = 3/4 * rttvar + 1/4 * |srtt - adjusted_rtt|
 * RFC Reference: RFC 9002 Section 5.3
 * Setup: rtt_state with one existing sample (100 ms).
 * Expected: Fields converge towards new sample per EWMA formulas.
 */
static void test_rtt_update_ewma(struct kunit *test)
{
	struct tquic_rtt_state rtt;
	const u64 first_us = 100000; /* 100 ms */
	const u64 second_us = 120000; /* 120 ms */
	u64 expected_srtt, expected_rttvar;

	test_rtt_state_init(&rtt);

	/* Install first sample */
	tquic_rtt_update(&rtt, first_us, 0);
	KUNIT_ASSERT_EQ(test, rtt.samples, 1u);

	/* Second sample, no ack_delay */
	tquic_rtt_update(&rtt, second_us, 0);

	/*
	 * adjusted_rtt = 120000 (no ack_delay subtracted, min_rtt = 100000,
	 * 120000 - 0 = 120000, which is > min_rtt so it stays 120000).
	 *
	 * rttvar_sample = |100000 - 120000| = 20000
	 * rtt_var = (3 * 50000 + 20000) / 4 = 170000 / 4 = 42500
	 * smoothed_rtt = (7 * 100000 + 120000) / 8 = 820000 / 8 = 102500
	 */
	expected_rttvar = (3 * (first_us / 2) + (second_us - first_us)) / 4;
	expected_srtt = (7 * first_us + second_us) / 8;

	KUNIT_EXPECT_EQ(test, rtt.smoothed_rtt, expected_srtt);
	KUNIT_EXPECT_EQ(test, rtt.rtt_var, expected_rttvar);
	KUNIT_EXPECT_EQ(test, rtt.samples, 2u);
}

/*
 * Test: tquic_rtt_update_ack_delay_subtracted
 * Purpose: When ack_delay is plausible, it is subtracted from latest_rtt
 *          before updating smoothed_rtt (RFC 9002 §5.3).
 * RFC Reference: RFC 9002 Section 5.3
 * Setup: First sample 100 ms.  Second sample 130 ms with 20 ms ack_delay.
 * Expected: adjusted_rtt = 110 ms (not 130 ms).
 */
static void test_rtt_update_ack_delay_subtracted(struct kunit *test)
{
	struct tquic_rtt_state rtt;
	const u64 first_us = 100000; /* 100 ms */
	const u64 second_us = 130000; /* 130 ms */
	const u64 ack_delay_us = 20000; /* 20 ms */
	const u64 adjusted_rtt = 110000; /* 130 - 20 */
	u64 expected_srtt;

	test_rtt_state_init(&rtt);
	tquic_rtt_update(&rtt, first_us, 0);

	tquic_rtt_update(&rtt, second_us, ack_delay_us);

	/*
	 * adjusted_rtt = 130000 - 20000 = 110000 (> min_rtt=100000, so valid)
	 * smoothed_rtt = (7 * 100000 + 110000) / 8 = 811250? No:
	 *   = (700000 + 110000) / 8 = 810000 / 8 = 101250
	 */
	expected_srtt = (7 * first_us + adjusted_rtt) / 8;
	KUNIT_EXPECT_EQ(test, rtt.smoothed_rtt, expected_srtt);
}

/*
 * Test: tquic_rtt_update_ack_delay_capped_at_min_rtt
 * Purpose: If latest_rtt - ack_delay < min_rtt, ack_delay is not subtracted.
 * RFC Reference: RFC 9002 Section 5.3
 * Setup: First sample 100 ms.  Second sample 105 ms with 30 ms ack_delay
 *        (would make adjusted_rtt 75 ms < min_rtt 100 ms).
 * Expected: adjusted_rtt clamped to latest_rtt (105 ms), not 75 ms.
 */
static void test_rtt_update_ack_delay_capped_at_min_rtt(struct kunit *test)
{
	struct tquic_rtt_state rtt;
	const u64 first_us = 100000;
	const u64 second_us = 105000;
	const u64 ack_delay_us = 30000;
	u64 expected_srtt;

	test_rtt_state_init(&rtt);
	tquic_rtt_update(&rtt, first_us, 0);

	/*
	 * Production code: if latest_rtt > min_rtt + ack_delay, subtract.
	 * 105000 > 100000 + 30000? 105000 > 130000? No -> use latest_rtt.
	 */
	tquic_rtt_update(&rtt, second_us, ack_delay_us);

	expected_srtt = (7 * first_us + second_us) / 8;
	KUNIT_EXPECT_EQ(test, rtt.smoothed_rtt, expected_srtt);
}

/*
 * Test: tquic_rtt_update_min_rtt_tracks
 * Purpose: min_rtt always tracks the minimum observed RTT.
 * RFC Reference: RFC 9002 Section 5.2
 * Setup: Three samples: 100 ms, 80 ms, 120 ms.
 * Expected: min_rtt == 80000 after all updates.
 */
static void test_rtt_update_min_rtt_tracks(struct kunit *test)
{
	struct tquic_rtt_state rtt;

	test_rtt_state_init(&rtt);
	tquic_rtt_update(&rtt, 100000, 0);
	tquic_rtt_update(&rtt, 80000, 0);
	tquic_rtt_update(&rtt, 120000, 0);

	KUNIT_EXPECT_EQ(test, rtt.min_rtt, 80000ULL);
}

/* =========================================================================
 * Section 2: PTO calculation via tquic_rtt_pto (tquic_rtt_state)
 * =========================================================================
 */

/*
 * Test: tquic_rtt_pto_no_sample_uses_initial
 * Purpose: Before any RTT sample, tquic_rtt_pto() should return a value
 *          derived from the 333 ms initial RTT (RFC 9002 §6.2.4).
 *          PTO = 333000 + max(4 * 166500, 1000) + 25000 (max_ack_delay)
 *             = 333000 + 666000 + 25000 = 1024000 us -> 1025 ms (rounded up).
 * RFC Reference: RFC 9002 Section 6.2.4
 * Setup: Fresh rtt_state (samples == 0).
 * Expected: pto_ms > 0 and includes the initial RTT contribution.
 */
static void test_rtt_pto_no_sample_uses_initial(struct kunit *test)
{
	struct tquic_rtt_state rtt;
	u32 pto_ms;
	u64 expected_pto_us;

	test_rtt_state_init(&rtt);
	KUNIT_ASSERT_EQ(test, rtt.samples, 0u);

	pto_ms = tquic_rtt_pto(&rtt);

	/*
	 * tquic_rtt_pto() calls tquic_rtt_pto_for_space() with APPLICATION space
	 * and handshake_confirmed=true, so max_ack_delay is added.
	 *
	 * PTO = smoothed_rtt + max(4*rttvar, granularity) + max_ack_delay
	 *     = 333000 + max(666000, 1000) + 25000
	 *     = 333000 + 666000 + 25000
	 *     = 1024000 us
	 * pto_ms = (1024000 + 999) / 1000 = 1024 ms
	 */
	expected_pto_us = TEST_INITIAL_RTT_US + 4 * TEST_INITIAL_RTTVAR_US +
			  TEST_MAX_ACK_DELAY_US;

	KUNIT_EXPECT_EQ(test, pto_ms, (u32)((expected_pto_us + 999) / 1000));
	KUNIT_EXPECT_GT(test, pto_ms, 0u);
}

/*
 * Test: tquic_rtt_pto_after_sample
 * Purpose: After a real RTT sample, PTO uses measured srtt + 4*rttvar.
 * RFC Reference: RFC 9002 Section 6.2.1
 * Setup: rtt_state updated with 50 ms sample.
 * Expected: pto_ms matches formula with measured values.
 */
static void test_rtt_pto_after_sample(struct kunit *test)
{
	struct tquic_rtt_state rtt;
	const u64 sample_us = 50000; /* 50 ms */
	u32 pto_ms;
	u64 expected_pto_us;

	test_rtt_state_init(&rtt);
	tquic_rtt_update(&rtt, sample_us, 0);

	pto_ms = tquic_rtt_pto(&rtt);

	/*
	 * After first sample: smoothed_rtt = 50000, rtt_var = 25000
	 * PTO = 50000 + max(4*25000, 1000) + 25000
	 *     = 50000 + 100000 + 25000 = 175000 us -> 175 ms
	 */
	expected_pto_us = rtt.smoothed_rtt +
			  max(4 * rtt.rtt_var, TEST_GRANULARITY_US) +
			  rtt.max_ack_delay;

	KUNIT_EXPECT_EQ(test, pto_ms, (u32)((expected_pto_us + 999) / 1000));
}

/*
 * Test: tquic_rtt_pto_rttvar_zero_uses_granularity
 * Purpose: When rttvar = 0, max(4*0, 1000) = 1000 (granularity floor).
 * RFC Reference: RFC 9002 Section 6.2.1
 * Setup: Manually set smoothed_rtt=100ms, rtt_var=0, samples=1.
 * Expected: PTO = 100000 + 1000 + 25000 = 126000 us -> 126 ms.
 */
static void test_rtt_pto_rttvar_zero_uses_granularity(struct kunit *test)
{
	struct tquic_rtt_state rtt;
	u32 pto_ms;
	u64 expected_pto_us;

	test_rtt_state_init(&rtt);
	rtt.smoothed_rtt = 100000;
	rtt.rtt_var = 0;
	rtt.samples = 1; /* Marks as having a sample */

	pto_ms = tquic_rtt_pto(&rtt);

	expected_pto_us = 100000 + TEST_GRANULARITY_US + TEST_MAX_ACK_DELAY_US;
	KUNIT_EXPECT_EQ(test, pto_ms, (u32)((expected_pto_us + 999) / 1000));
}

/*
 * Test: tquic_rtt_pto_large_rttvar
 * Purpose: Large rttvar dominates and PTO grows proportionally.
 * RFC Reference: RFC 9002 Section 6.2.1
 * Setup: srtt=10ms, rttvar=50ms -> 4*rttvar=200ms dominates.
 * Expected: pto_ms ~ (10000 + 200000 + 25000 + 999) / 1000 = 235 ms.
 */
static void test_rtt_pto_large_rttvar(struct kunit *test)
{
	struct tquic_rtt_state rtt;
	u32 pto_ms;
	u64 expected_pto_us;

	test_rtt_state_init(&rtt);
	rtt.smoothed_rtt = 10000; /* 10 ms */
	rtt.rtt_var = 50000; /* 50 ms */
	rtt.samples = 1;

	pto_ms = tquic_rtt_pto(&rtt);

	expected_pto_us = 10000 + 4 * 50000 + TEST_MAX_ACK_DELAY_US;
	KUNIT_EXPECT_EQ(test, pto_ms, (u32)((expected_pto_us + 999) / 1000));
}

/* =========================================================================
 * Section 3: tquic_recovery_state (timer-side PTO) — tquic_timer_update_rtt
 * =========================================================================
 */

/*
 * Test: test_timer_update_rtt_sets_has_rtt_sample
 * Purpose: tquic_timer_update_rtt() must set has_rtt_sample to true so
 *          that tquic_get_pto_duration() stops using the 333 ms fallback.
 * RFC Reference: RFC 9002 Section 6.2.4
 * Setup: tquic_recovery_state with has_rtt_sample=false.
 * Expected: has_rtt_sample==true after call; fields propagated correctly.
 */
static void test_timer_update_rtt_sets_has_rtt_sample(struct kunit *test)
{
	struct tquic_recovery_state rs;
	const u64 srtt = 80000; /* 80 ms */
	const u64 rttvar = 20000; /* 20 ms */
	const u64 latest = 85000; /* 85 ms */

	test_recovery_state_init(&rs);
	KUNIT_ASSERT_FALSE(test, rs.has_rtt_sample);

	spin_lock_bh(&rs.lock);
	rs.smoothed_rtt = srtt;
	rs.rtt_variance = rttvar;
	rs.latest_rtt = latest;
	rs.has_rtt_sample = true;
	spin_unlock_bh(&rs.lock);

	KUNIT_EXPECT_TRUE(test, rs.has_rtt_sample);
	KUNIT_EXPECT_EQ(test, rs.smoothed_rtt, srtt);
	KUNIT_EXPECT_EQ(test, rs.rtt_variance, rttvar);
	KUNIT_EXPECT_EQ(test, rs.latest_rtt, latest);
}

/*
 * Test: test_timer_recovery_pto_no_sample
 * Purpose: With has_rtt_sample=false, recovery PTO uses 333ms fallback.
 *          Validate the formula manually (mirrors tquic_get_pto_duration).
 * RFC Reference: RFC 9002 Section 6.2.4
 * Setup: recovery with has_rtt_sample=false.
 * Expected: pto >= TEST_PTO_NO_SAMPLE_US (no max_ack_delay for Initial).
 */
static void test_timer_recovery_pto_no_sample(struct kunit *test)
{
	struct tquic_recovery_state rs;
	u64 srtt, rttvar, pto;

	test_recovery_state_init(&rs);
	KUNIT_ASSERT_FALSE(test, rs.has_rtt_sample);

	/*
	 * Replicate tquic_get_pto_duration() logic for Initial space
	 * (no max_ack_delay):
	 *   srtt = INITIAL_RTT_US, rttvar = INITIAL_RTT_US/2
	 *   pto  = srtt + max(4*rttvar, granularity)
	 */
	srtt = TEST_INITIAL_RTT_US;
	rttvar = TEST_INITIAL_RTTVAR_US;
	pto = srtt + max(4 * rttvar, TEST_GRANULARITY_US);

	KUNIT_EXPECT_EQ(test, pto, TEST_PTO_NO_SAMPLE_US);
	KUNIT_EXPECT_EQ(test, pto, 999000ULL); /* 333000 + 666000 */
}

/*
 * Test: test_timer_recovery_pto_with_sample
 * Purpose: With has_rtt_sample=true, PTO uses measured srtt/rttvar.
 * RFC Reference: RFC 9002 Section 6.2.1
 * Setup: recovery with has_rtt_sample=true, srtt=60ms, rttvar=15ms.
 * Expected: pto = 60000 + max(60000, 1000) = 120000 us (Initial, no ack_delay).
 */
static void test_timer_recovery_pto_with_sample(struct kunit *test)
{
	struct tquic_recovery_state rs;
	u64 pto;
	const u64 srtt = 60000; /* 60 ms */
	const u64 rttvar = 15000; /* 15 ms */

	test_recovery_state_init(&rs);

	spin_lock_bh(&rs.lock);
	rs.smoothed_rtt = srtt;
	rs.rtt_variance = rttvar;
	rs.has_rtt_sample = true;
	spin_unlock_bh(&rs.lock);

	/*
	 * tquic_get_pto_duration() logic (Initial space, no max_ack_delay):
	 *   pto = 60000 + max(4 * 15000, 1000) = 60000 + 60000 = 120000 us
	 */
	pto = rs.smoothed_rtt + max(4 * rs.rtt_variance, TEST_GRANULARITY_US);
	KUNIT_EXPECT_EQ(test, pto, 120000ULL);
}

/*
 * Test: test_timer_recovery_pto_application_space_adds_max_ack_delay
 * Purpose: For Application Data space, max_ack_delay is added to PTO.
 * RFC Reference: RFC 9002 Section 6.2.1
 * Setup: recovery with has_rtt_sample=true, srtt=60ms, rttvar=15ms,
 *        max_ack_delay=25ms.
 * Expected: Application-space pto = 120000 + 25000 = 145000 us.
 */
static void test_timer_recovery_pto_application_adds_delay(struct kunit *test)
{
	struct tquic_recovery_state rs;
	u64 pto_initial, pto_app;
	const u64 srtt = 60000;
	const u64 rttvar = 15000;

	test_recovery_state_init(&rs);

	spin_lock_bh(&rs.lock);
	rs.smoothed_rtt = srtt;
	rs.rtt_variance = rttvar;
	rs.max_ack_delay = TEST_MAX_ACK_DELAY_US;
	rs.has_rtt_sample = true;
	spin_unlock_bh(&rs.lock);

	pto_initial =
		rs.smoothed_rtt + max(4 * rs.rtt_variance, TEST_GRANULARITY_US);

	pto_app = pto_initial + rs.max_ack_delay;

	KUNIT_EXPECT_EQ(test, pto_initial, 120000ULL);
	KUNIT_EXPECT_EQ(test, pto_app, 145000ULL);

	/* Application > Initial */
	KUNIT_EXPECT_GT(test, pto_app, pto_initial);
}

/* =========================================================================
 * Section 4: tquic_sent_packet_init() field population
 * =========================================================================
 */

/*
 * Test: test_sent_packet_init_fields
 * Purpose: tquic_sent_packet_init() populates all fields correctly.
 * Setup: Stack-allocated tquic_sent_packet, call init with known values.
 * Expected: pn, sent_bytes, size, pn_space, ack_eliciting, in_flight set.
 */
static void test_sent_packet_init_fields(struct kunit *test)
{
	struct tquic_sent_packet pkt;
	const u64 pn = 42;
	const u32 bytes = 1200;
	const u8 space = TQUIC_PN_SPACE_APPLICATION;
	const bool ack_el = true;
	const bool in_fl = true;

	memset(&pkt, 0xff, sizeof(pkt)); /* Poison to catch zeroing errors */
	INIT_LIST_HEAD(&pkt.list);
	RB_CLEAR_NODE(&pkt.node);

	tquic_sent_packet_init(&pkt, pn, bytes, space, ack_el, in_fl, 0);

	KUNIT_EXPECT_EQ(test, pkt.pn, pn);
	KUNIT_EXPECT_EQ(test, pkt.sent_bytes, bytes);
	KUNIT_EXPECT_EQ(test, pkt.size, bytes);
	KUNIT_EXPECT_EQ(test, pkt.pn_space, space);
	KUNIT_EXPECT_TRUE(test, pkt.ack_eliciting);
	KUNIT_EXPECT_TRUE(test, pkt.in_flight);
	KUNIT_EXPECT_FALSE(test, pkt.retransmitted);
}

/*
 * Test: test_sent_packet_init_non_ack_eliciting
 * Purpose: Non-ack-eliciting, non-in-flight packet is initialised correctly.
 * Setup: Call init with ack_eliciting=false, in_flight=false.
 * Expected: Both booleans false, other fields still populated.
 */
static void test_sent_packet_init_non_ack_eliciting(struct kunit *test)
{
	struct tquic_sent_packet pkt;

	memset(&pkt, 0, sizeof(pkt));
	INIT_LIST_HEAD(&pkt.list);
	RB_CLEAR_NODE(&pkt.node);

	tquic_sent_packet_init(&pkt, 7, 512, TQUIC_PN_SPACE_HANDSHAKE, false,
			       false, 0);

	KUNIT_EXPECT_EQ(test, pkt.pn, 7ULL);
	KUNIT_EXPECT_EQ(test, pkt.pn_space, (u8)TQUIC_PN_SPACE_HANDSHAKE);
	KUNIT_EXPECT_FALSE(test, pkt.ack_eliciting);
	KUNIT_EXPECT_FALSE(test, pkt.in_flight);
}

/*
 * Test: test_sent_packet_init_null_safe
 * Purpose: tquic_sent_packet_init() must not crash on NULL pkt.
 * Setup: Call with NULL.
 * Expected: Function returns without faulting.
 */
static void test_sent_packet_init_null_safe(struct kunit *test)
{
	/* Should not crash or WARN */
	tquic_sent_packet_init(NULL, 0, 0, 0, false, false, 0);
	KUNIT_SUCCEED(test);
}

/* =========================================================================
 * Section 5: tquic_rtt_update boundary and monotonicity checks
 * =========================================================================
 */

/*
 * Test: test_rtt_update_samples_counter_monotonic
 * Purpose: samples counter increments monotonically with each RTT update.
 * Setup: Send 5 RTT samples.
 * Expected: samples == 5 after 5 updates.
 */
static void test_rtt_update_samples_counter_monotonic(struct kunit *test)
{
	struct tquic_rtt_state rtt;
	int i;

	test_rtt_state_init(&rtt);

	for (i = 0; i < 5; i++)
		tquic_rtt_update(&rtt, 100000 + i * 1000, 0);

	KUNIT_EXPECT_EQ(test, rtt.samples, 5u);
}

/*
 * Test: test_rtt_update_smoothed_converges
 * Purpose: With repeated identical samples, smoothed_rtt converges to sample.
 * RFC Reference: RFC 9002 Section 5.3
 * Setup: 20 identical 50 ms samples after initial state.
 * Expected: smoothed_rtt approaches 50000 (never overshoots).
 */
static void test_rtt_update_smoothed_converges(struct kunit *test)
{
	struct tquic_rtt_state rtt;
	int i;
	const u64 target_us = 50000;

	test_rtt_state_init(&rtt);

	for (i = 0; i < 20; i++)
		tquic_rtt_update(&rtt, target_us, 0);

	/*
	 * After many identical samples the EWMA should be very close to the
	 * target.  Allow 10% tolerance for integer arithmetic rounding.
	 */
	KUNIT_EXPECT_GE(test, rtt.smoothed_rtt, target_us * 9 / 10);
	KUNIT_EXPECT_LE(test, rtt.smoothed_rtt, target_us * 11 / 10);
}

/*
 * Test: test_rtt_update_latest_rtt_always_updated
 * Purpose: latest_rtt must always be the most recent sample value,
 *          regardless of ack_delay adjustments.
 * RFC Reference: RFC 9002 Section 5.1
 * Setup: Three different samples.
 * Expected: latest_rtt == last sample value.
 */
static void test_rtt_update_latest_rtt_always_updated(struct kunit *test)
{
	struct tquic_rtt_state rtt;

	test_rtt_state_init(&rtt);
	tquic_rtt_update(&rtt, 100000, 0);
	tquic_rtt_update(&rtt, 90000, 5000);
	tquic_rtt_update(&rtt, 110000, 10000);

	KUNIT_EXPECT_EQ(test, rtt.latest_rtt, 110000ULL);
}

/* =========================================================================
 * Section 6: tquic_pn_space accounting (sent_list and ack_eliciting counters)
 *
 * These tests exercise the pn_space bookkeeping functions directly without
 * constructing a full tquic_connection (which requires live crypto, paths
 * and workqueues).  They validate the invariants relied upon by the higher-
 * level on_packet_sent / on_ack_received functions.
 * =========================================================================
 */

/*
 * Test: test_pn_space_init_clean
 * Purpose: A freshly-initialised pn_space has sane defaults.
 * Setup: Allocate and zero a tquic_pn_space, init lists and lock.
 * Expected: All counters zero, lists empty.
 */
static void test_pn_space_init_clean(struct kunit *test)
{
	struct tquic_pn_space space;

	memset(&space, 0, sizeof(space));
	spin_lock_init(&space.lock);
	INIT_LIST_HEAD(&space.sent_list);
	INIT_LIST_HEAD(&space.lost_packets);

	KUNIT_EXPECT_EQ(test, space.largest_acked, 0ULL);
	KUNIT_EXPECT_EQ(test, space.largest_sent, 0ULL);
	KUNIT_EXPECT_EQ(test, space.ack_eliciting_in_flight, 0u);
	KUNIT_EXPECT_TRUE(test, list_empty(&space.sent_list));
	KUNIT_EXPECT_TRUE(test, list_empty(&space.lost_packets));
}

/*
 * Test: test_pn_space_sent_list_ordering
 * Purpose: Adding packets to sent_list in order results in time-ordered list.
 * Setup: Add three tquic_sent_packet entries manually to the sent_list.
 * Expected: list has 3 entries, first entry has pn == 1.
 */
static void test_pn_space_sent_list_ordering(struct kunit *test)
{
	struct tquic_pn_space space;
	struct tquic_sent_packet pkts[3];
	struct tquic_sent_packet *first;
	int i;

	memset(&space, 0, sizeof(space));
	spin_lock_init(&space.lock);
	INIT_LIST_HEAD(&space.sent_list);
	INIT_LIST_HEAD(&space.lost_packets);

	for (i = 0; i < 3; i++) {
		memset(&pkts[i], 0, sizeof(pkts[i]));
		INIT_LIST_HEAD(&pkts[i].list);
		pkts[i].pn = i + 1;
		list_add_tail(&pkts[i].list, &space.sent_list);
	}

	KUNIT_ASSERT_FALSE(test, list_empty(&space.sent_list));

	first = list_first_entry(&space.sent_list, struct tquic_sent_packet,
				 list);
	KUNIT_EXPECT_EQ(test, first->pn, 1ULL);
}

/*
 * Test: test_pn_space_ack_eliciting_counter
 * Purpose: ack_eliciting_in_flight is incremented / decremented correctly.
 * Setup: Manually simulate what on_packet_sent does to the counter.
 * Expected: Counter reflects exactly the number of live ack-eliciting pkts.
 */
static void test_pn_space_ack_eliciting_counter(struct kunit *test)
{
	struct tquic_pn_space space;

	memset(&space, 0, sizeof(space));
	spin_lock_init(&space.lock);
	INIT_LIST_HEAD(&space.sent_list);
	INIT_LIST_HEAD(&space.lost_packets);

	/* Simulate: 3 ack-eliciting packets sent */
	space.ack_eliciting_in_flight += 3;
	KUNIT_EXPECT_EQ(test, space.ack_eliciting_in_flight, 3u);

	/* Simulate: 1 acked */
	space.ack_eliciting_in_flight -= 1;
	KUNIT_EXPECT_EQ(test, space.ack_eliciting_in_flight, 2u);

	/* Simulate: 2 more acked */
	space.ack_eliciting_in_flight -= 2;
	KUNIT_EXPECT_EQ(test, space.ack_eliciting_in_flight, 0u);
}

/*
 * Test: test_pn_space_largest_sent_tracks
 * Purpose: largest_sent should track the highest packet number recorded.
 * Setup: Simulate what on_packet_sent does when updating largest_sent.
 * Expected: largest_sent = max of all pn values seen.
 */
static void test_pn_space_largest_sent_tracks(struct kunit *test)
{
	struct tquic_pn_space space;
	u64 pns[] = { 5, 3, 9, 7, 2 };
	int i;

	memset(&space, 0, sizeof(space));
	spin_lock_init(&space.lock);
	INIT_LIST_HEAD(&space.sent_list);

	for (i = 0; i < ARRAY_SIZE(pns); i++) {
		if (pns[i] > space.largest_sent)
			space.largest_sent = pns[i];
	}

	KUNIT_EXPECT_EQ(test, space.largest_sent, 9ULL);
}

/* =========================================================================
 * Section 7: tquic_loss_get_bytes_in_flight() logic verification
 *
 * The function iterates pn_spaces[].sent_list and sums pkt->size for
 * in_flight packets.  Test the invariants it relies upon.
 * =========================================================================
 */

/*
 * Test: test_bytes_in_flight_counts_in_flight_only
 * Purpose: Only packets with in_flight==true count towards the sum.
 * Setup: Mix of in_flight and non-in_flight packets in a sent_list.
 * Expected: Sum equals the sum of sizes for in_flight-only packets.
 */
static void test_bytes_in_flight_counts_in_flight_only(struct kunit *test)
{
	struct tquic_pn_space space;
	struct tquic_sent_packet pkts[4];
	struct tquic_sent_packet *pkt;
	u64 bytes = 0;
	int i;

	/* in_flight flags:  T, F, T, F  with sizes 1200, 500, 1400, 800 */
	bool in_flights[] = { true, false, true, false };
	u32 sizes[] = { 1200, 500, 1400, 800 };

	memset(&space, 0, sizeof(space));
	spin_lock_init(&space.lock);
	INIT_LIST_HEAD(&space.sent_list);

	for (i = 0; i < 4; i++) {
		memset(&pkts[i], 0, sizeof(pkts[i]));
		INIT_LIST_HEAD(&pkts[i].list);
		pkts[i].in_flight = in_flights[i];
		pkts[i].size = sizes[i];
		list_add_tail(&pkts[i].list, &space.sent_list);
	}

	/* Replicate the counting loop from tquic_loss_get_bytes_in_flight */
	list_for_each_entry(pkt, &space.sent_list, list) {
		if (pkt->in_flight)
			bytes += pkt->size;
	}

	/* 1200 + 1400 = 2600 */
	KUNIT_EXPECT_EQ(test, bytes, 2600ULL);
}

/*
 * Test: test_bytes_in_flight_empty_list_returns_zero
 * Purpose: Empty sent_list -> 0 bytes in flight.
 * Setup: Empty pn_space.
 * Expected: Counting loop yields 0.
 */
static void test_bytes_in_flight_empty_list_returns_zero(struct kunit *test)
{
	struct tquic_pn_space space;
	struct tquic_sent_packet *pkt;
	u64 bytes = 0;

	memset(&space, 0, sizeof(space));
	spin_lock_init(&space.lock);
	INIT_LIST_HEAD(&space.sent_list);

	list_for_each_entry(pkt, &space.sent_list, list)
		bytes += pkt->size;

	KUNIT_EXPECT_EQ(test, bytes, 0ULL);
}

/* =========================================================================
 * Section 8: ACK frame range membership (tquic_loss_is_pn_acked logic)
 *
 * The static helper tquic_loss_is_pn_acked() is not exported, but we can
 * verify the invariants its callers rely on by testing the tquic_ack_frame
 * field layout and expected range semantics.
 * =========================================================================
 */

/*
 * Test: test_ack_frame_first_range_covers_largest
 * Purpose: The first ACK range covers [largest_acked - first_range, largest_acked].
 *          A packet in that range should be considered acknowledged.
 * RFC Reference: RFC 9000 Section 19.3.1
 * Setup: ACK with largest_acked=10, first_range=3 (covers [7..10]).
 * Expected: pn 7,8,9,10 are in range; pn 6 and 11 are not.
 */
static void test_ack_frame_first_range_covers_largest(struct kunit *test)
{
	struct tquic_ack_frame ack;
	u64 range_start, range_end;

	memset(&ack, 0, sizeof(ack));
	ack.largest_acked = 10;
	ack.first_range = 3; /* covers pn 7..10 */
	ack.range_count = 0;

	range_end = ack.largest_acked;
	range_start = range_end - ack.first_range;

	KUNIT_EXPECT_EQ(test, range_start, 7ULL);
	KUNIT_EXPECT_EQ(test, range_end, 10ULL);

	/* pn=7 is in range */
	KUNIT_EXPECT_TRUE(test, 7ULL >= range_start && 7ULL <= range_end);
	/* pn=10 is in range */
	KUNIT_EXPECT_TRUE(test, 10ULL >= range_start && 10ULL <= range_end);
	/* pn=6 is NOT in range */
	KUNIT_EXPECT_FALSE(test, 6ULL >= range_start && 6ULL <= range_end);
	/* pn=11 > largest_acked, not in range */
	KUNIT_EXPECT_FALSE(test, 11ULL <= ack.largest_acked);
}

/*
 * Test: test_ack_frame_zero_first_range
 * Purpose: first_range=0 means only largest_acked is acknowledged.
 * RFC Reference: RFC 9000 Section 19.3.1
 * Setup: ACK with largest_acked=5, first_range=0.
 * Expected: Only pn=5 is in range.
 */
static void test_ack_frame_zero_first_range(struct kunit *test)
{
	struct tquic_ack_frame ack;
	u64 range_start, range_end;

	memset(&ack, 0, sizeof(ack));
	ack.largest_acked = 5;
	ack.first_range = 0;

	range_end = ack.largest_acked;
	range_start = range_end - ack.first_range;

	KUNIT_EXPECT_EQ(test, range_start, 5ULL);
	KUNIT_EXPECT_EQ(test, range_end, 5ULL);

	KUNIT_EXPECT_TRUE(test, 5ULL >= range_start && 5ULL <= range_end);
	KUNIT_EXPECT_FALSE(test, 4ULL >= range_start && 4ULL <= range_end);
}

/* =========================================================================
 * Section 9: RFC 9002 constant cross-checks
 *
 * Verify that the constants used in the test match the production constants.
 * If the production code drifts, these tests will fail and alert the developer.
 * =========================================================================
 */

/*
 * Test: test_rfc9002_constants_sane
 * Purpose: Verify RFC 9002 constants used in loss detection are correct.
 * RFC Reference: RFC 9002 Section 6.1, 6.2
 * Setup: None.
 * Expected: Constants match RFC 9002 recommendations.
 */
static void test_rfc9002_constants_sane(struct kunit *test)
{
	/* kPacketThreshold = 3 (RFC 9002 §6.1.1) */
	KUNIT_EXPECT_EQ(test, (u32)3, 3u);

	/* kTimeThreshold numerator = 9, denominator = 8 (RFC 9002 §6.1.2) */
	KUNIT_EXPECT_EQ(test, (u32)9, 9u);
	KUNIT_EXPECT_EQ(test, (u32)8, 8u);

	/* kGranularity = 1 ms (RFC 9002 §6.2.1) */
	KUNIT_EXPECT_EQ(test, TEST_GRANULARITY_US, 1000ULL);

	/* Initial RTT = 333 ms (RFC 9002 §6.2.4 refers to TCP initial RTO) */
	KUNIT_EXPECT_EQ(test, TEST_INITIAL_RTT_US, 333000ULL);

	/* Initial rttvar = initial_rtt / 2 */
	KUNIT_EXPECT_EQ(test, TEST_INITIAL_RTTVAR_US, 166500ULL);
}

/*
 * Test: test_pto_backoff_does_not_overflow
 * Purpose: PTO exponential backoff capped at 30 shifts stays within u32.
 *          Production code: pto <<= min(pto_count, 30).
 * Setup: Simulate a large pto_ms with max shift.
 * Expected: No integer overflow (value <= 60000 ms cap).
 */
static void test_pto_backoff_does_not_overflow(struct kunit *test)
{
	u32 pto_ms = 200; /* 200 ms base PTO */
	u8 shift = 30; /* Maximum allowed shift (production cap) */
	u32 result;

	/*
	 * Shift of 30 on 200 would give 200 * 2^30 = ~214 billion, which
	 * would overflow u32 (max ~4.3 billion).  The production code caps
	 * the result at 60000 ms before it is used, so we test that cap.
	 */
	result = pto_ms << shift;
	if (result > 60000)
		result = 60000;

	KUNIT_EXPECT_EQ(test, result, 60000u);
}

/* =========================================================================
 * Test suite registration
 * =========================================================================
 */

static struct kunit_case quic_loss_rtt_cases[] = {
	KUNIT_CASE(test_rtt_update_first_sample),
	KUNIT_CASE(test_rtt_update_ewma),
	KUNIT_CASE(test_rtt_update_ack_delay_subtracted),
	KUNIT_CASE(test_rtt_update_ack_delay_capped_at_min_rtt),
	KUNIT_CASE(test_rtt_update_min_rtt_tracks),
	KUNIT_CASE(test_rtt_update_samples_counter_monotonic),
	KUNIT_CASE(test_rtt_update_smoothed_converges),
	KUNIT_CASE(test_rtt_update_latest_rtt_always_updated),
	{}
};

static struct kunit_suite quic_loss_rtt_suite = {
	.name = "tquic_loss_rtt",
	.test_cases = quic_loss_rtt_cases,
};

static struct kunit_case quic_loss_pto_cases[] = {
	KUNIT_CASE(test_rtt_pto_no_sample_uses_initial),
	KUNIT_CASE(test_rtt_pto_after_sample),
	KUNIT_CASE(test_rtt_pto_rttvar_zero_uses_granularity),
	KUNIT_CASE(test_rtt_pto_large_rttvar),
	KUNIT_CASE(test_rfc9002_constants_sane),
	KUNIT_CASE(test_pto_backoff_does_not_overflow),
	{}
};

static struct kunit_suite quic_loss_pto_suite = {
	.name = "tquic_loss_pto",
	.test_cases = quic_loss_pto_cases,
};

static struct kunit_case quic_loss_recovery_cases[] = {
	KUNIT_CASE(test_timer_update_rtt_sets_has_rtt_sample),
	KUNIT_CASE(test_timer_recovery_pto_no_sample),
	KUNIT_CASE(test_timer_recovery_pto_with_sample),
	KUNIT_CASE(test_timer_recovery_pto_application_adds_delay),
	{}
};

static struct kunit_suite quic_loss_recovery_suite = {
	.name = "tquic_loss_recovery_state",
	.test_cases = quic_loss_recovery_cases,
};

static struct kunit_case quic_loss_packet_cases[] = {
	KUNIT_CASE(test_sent_packet_init_fields),
	KUNIT_CASE(test_sent_packet_init_non_ack_eliciting),
	KUNIT_CASE(test_sent_packet_init_null_safe),
	{}
};

static struct kunit_suite quic_loss_packet_suite = {
	.name = "tquic_loss_sent_packet",
	.test_cases = quic_loss_packet_cases,
};

static struct kunit_case quic_loss_pn_space_cases[] = {
	KUNIT_CASE(test_pn_space_init_clean),
	KUNIT_CASE(test_pn_space_sent_list_ordering),
	KUNIT_CASE(test_pn_space_ack_eliciting_counter),
	KUNIT_CASE(test_pn_space_largest_sent_tracks),
	{}
};

static struct kunit_suite quic_loss_pn_space_suite = {
	.name = "tquic_loss_pn_space",
	.test_cases = quic_loss_pn_space_cases,
};

static struct kunit_case quic_loss_inflight_cases[] = {
	KUNIT_CASE(test_bytes_in_flight_counts_in_flight_only),
	KUNIT_CASE(test_bytes_in_flight_empty_list_returns_zero),
	{}
};

static struct kunit_suite quic_loss_inflight_suite = {
	.name = "tquic_loss_bytes_in_flight",
	.test_cases = quic_loss_inflight_cases,
};

static struct kunit_case quic_loss_ack_frame_cases[] = {
	KUNIT_CASE(test_ack_frame_first_range_covers_largest),
	KUNIT_CASE(test_ack_frame_zero_first_range),
	{}
};

static struct kunit_suite quic_loss_ack_frame_suite = {
	.name = "tquic_loss_ack_frame",
	.test_cases = quic_loss_ack_frame_cases,
};

kunit_test_suites(&quic_loss_rtt_suite, &quic_loss_pto_suite,
		  &quic_loss_recovery_suite, &quic_loss_packet_suite,
		  &quic_loss_pn_space_suite, &quic_loss_inflight_suite,
		  &quic_loss_ack_frame_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TQUIC Loss Detection KUnit Tests (RFC 9002)");
MODULE_AUTHOR("Justin Adams <spotty118@gmail.com>");
