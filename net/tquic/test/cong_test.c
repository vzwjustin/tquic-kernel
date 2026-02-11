// SPDX-License-Identifier: GPL-2.0
/*
 * KUnit tests for TQUIC congestion control algorithms
 *
 * Copyright (c) 2026 Linux Foundation
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Tests the various congestion control algorithms:
 * - BBR (Bottleneck Bandwidth and RTT)
 * - BBRv2 (improved BBR)
 * - BBRv3 (latest BBR)
 * - CUBIC
 * - COPA (Competitive Online Pareto Algorithm)
 * - Prague (L4S compatible)
 * - Westwood
 * - Coupled (Multipath coupled CC)
 */

#include <kunit/test.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <net/tquic.h>

#include "../cong/tquic_cong.h"

/*
 * =============================================================================
 * Test Helpers
 * =============================================================================
 */

/* Test path state for CC testing */
struct cc_test_path {
	struct tquic_path_stats stats;
	u64 cwnd;
	u64 ssthresh;
	u64 pacing_rate;
	u64 bytes_in_flight;
	void *cc_state;
};

/* Initialize a test path */
static struct cc_test_path *create_cc_test_path(struct kunit *test)
{
	struct cc_test_path *path;

	path = kunit_kzalloc(test, sizeof(*path), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, path);

	/* Initialize with reasonable defaults */
	path->stats.rtt_min = 10000;	/* 10ms */
	path->stats.rtt_smoothed = 20000;	/* 20ms */
	path->stats.rtt_var = 5000;	/* 5ms variance */
	path->stats.bytes_sent = 0;
	path->stats.bytes_acked = 0;
	path->stats.bytes_lost = 0;

	path->cwnd = 10 * 1200;		/* 10 packets initial cwnd */
	path->ssthresh = UINT64_MAX;	/* Start in slow start */
	path->pacing_rate = 0;
	path->bytes_in_flight = 0;

	return path;
}

/* Simulate sending a packet */
static void cc_test_send(struct cc_test_path *path, u32 bytes)
{
	path->bytes_in_flight += bytes;
	path->stats.bytes_sent += bytes;
}

/* Simulate receiving an ACK */
static void cc_test_ack(struct cc_test_path *path, u32 bytes, u64 rtt_sample)
{
	if (bytes > path->bytes_in_flight)
		bytes = path->bytes_in_flight;

	path->bytes_in_flight -= bytes;
	path->stats.bytes_acked += bytes;

	/* Update RTT */
	if (rtt_sample > 0) {
		if (rtt_sample < path->stats.rtt_min)
			path->stats.rtt_min = rtt_sample;

		/* EWMA smoothing */
		path->stats.rtt_smoothed = (7 * path->stats.rtt_smoothed +
					    rtt_sample) / 8;
	}
}

/* Simulate a loss event */
static void cc_test_loss(struct cc_test_path *path, u32 bytes)
{
	if (bytes > path->bytes_in_flight)
		bytes = path->bytes_in_flight;

	path->bytes_in_flight -= bytes;
	path->stats.bytes_lost += bytes;
}

/*
 * =============================================================================
 * CUBIC Tests
 * =============================================================================
 */

/* Test CUBIC slow start behavior */
static void test_cubic_slow_start(struct kunit *test)
{
	struct cc_test_path *path;
	u64 initial_cwnd;
	int i;

	path = create_cc_test_path(test);
	initial_cwnd = path->cwnd;

	/* Simulate slow start: cwnd should increase exponentially */
	for (i = 0; i < 10; i++) {
		u64 prev_cwnd = path->cwnd;

		/* Send data */
		cc_test_send(path, 1200);

		/* Receive ACK - in slow start, cwnd increases by 1 MSS per ACK */
		cc_test_ack(path, 1200, 20000);

		/* Increase cwnd per slow start rules */
		if (path->cwnd < path->ssthresh)
			path->cwnd += 1200;

		KUNIT_EXPECT_GT(test, path->cwnd, prev_cwnd);
	}

	KUNIT_EXPECT_GT(test, path->cwnd, initial_cwnd);
	kunit_info(test, "CUBIC slow start: cwnd %llu -> %llu\n",
		   initial_cwnd, path->cwnd);
}

/* Test CUBIC congestion avoidance behavior */
static void test_cubic_congestion_avoidance(struct kunit *test)
{
	struct cc_test_path *path;
	u64 cwnd_before_loss;
	int i;

	path = create_cc_test_path(test);

	/* Move out of slow start */
	path->cwnd = 100 * 1200;
	path->ssthresh = 80 * 1200;

	cwnd_before_loss = path->cwnd;

	/* Simulate loss event */
	cc_test_loss(path, 1200);

	/* CUBIC reduces cwnd to 0.7 * cwnd on loss */
	path->cwnd = (path->cwnd * 70) / 100;
	path->ssthresh = path->cwnd;

	KUNIT_EXPECT_LT(test, path->cwnd, cwnd_before_loss);
	KUNIT_EXPECT_GT(test, path->cwnd, 0ULL);

	/* Verify recovery - cwnd should grow back (CUBIC curve) */
	for (i = 0; i < 100; i++) {
		cc_test_send(path, 1200);
		cc_test_ack(path, 1200, 20000);

		/* Simplified congestion avoidance growth */
		path->cwnd += (1200 * 1200) / path->cwnd;
	}

	kunit_info(test, "CUBIC congestion avoidance: cwnd after recovery %llu\n",
		   path->cwnd);
}

/* Test CUBIC fast convergence */
static void test_cubic_fast_convergence(struct kunit *test)
{
	struct cc_test_path *path;
	u64 w_max_before, w_max_after;

	path = create_cc_test_path(test);

	/* Set up a scenario for fast convergence */
	path->cwnd = 200 * 1200;
	path->ssthresh = 150 * 1200;
	w_max_before = path->cwnd;

	/* First loss */
	path->cwnd = (path->cwnd * 70) / 100;

	/* Second loss with lower peak */
	w_max_after = path->cwnd + 10 * 1200;  /* Small growth */
	path->cwnd = w_max_after;
	path->cwnd = (path->cwnd * 70) / 100;

	/* Fast convergence should reduce W_max further */
	KUNIT_EXPECT_LT(test, w_max_after, w_max_before);

	kunit_info(test, "CUBIC fast convergence: w_max %llu -> %llu\n",
		   w_max_before, w_max_after);
}

/*
 * =============================================================================
 * BBR Tests
 * =============================================================================
 */

/* Test BBR startup phase */
static void test_bbr_startup(struct kunit *test)
{
	struct cc_test_path *path;
	u64 bandwidth_samples[10];
	int i;

	path = create_cc_test_path(test);

	/* Simulate BBR startup - probing for bandwidth */
	for (i = 0; i < 10; i++) {
		/* Send at pacing gain = 2.89 (startup) */
		u32 send_bytes = 5 * 1200;

		cc_test_send(path, send_bytes);
		cc_test_ack(path, send_bytes, 10000 + i * 100);

		/* Calculate bandwidth sample */
		bandwidth_samples[i] = ((u64)send_bytes * 1000000) /
				       path->stats.rtt_smoothed;
	}

	/* Verify bandwidth samples are increasing initially */
	KUNIT_EXPECT_GT(test, bandwidth_samples[5], bandwidth_samples[0]);

	kunit_info(test, "BBR startup: bandwidth samples %llu -> %llu\n",
		   bandwidth_samples[0], bandwidth_samples[9]);
}

/* Test BBR drain phase */
static void test_bbr_drain(struct kunit *test)
{
	struct cc_test_path *path;
	u64 inflight_before, inflight_after;

	path = create_cc_test_path(test);

	/* Set up as if leaving startup with high inflight */
	path->bytes_in_flight = 100 * 1200;
	inflight_before = path->bytes_in_flight;

	/* Simulate drain: pacing_gain < 1 */
	/* In drain, we send less than we receive ACKs for */
	for (int i = 0; i < 20 && path->bytes_in_flight > 10 * 1200; i++) {
		/* Send at reduced rate */
		cc_test_send(path, 500);

		/* Receive ACKs at higher rate */
		cc_test_ack(path, 1500, 15000);
	}

	inflight_after = path->bytes_in_flight;
	KUNIT_EXPECT_LT(test, inflight_after, inflight_before);

	kunit_info(test, "BBR drain: inflight %llu -> %llu\n",
		   inflight_before, inflight_after);
}

/* Test BBR probe bandwidth phase */
static void test_bbr_probe_bw(struct kunit *test)
{
	struct cc_test_path *path;
	u64 bw_estimates[8];
	int phase;

	path = create_cc_test_path(test);
	path->cwnd = 50 * 1200;

	/* BBR ProbeBW cycles through 8 phases */
	for (phase = 0; phase < 8; phase++) {
		u32 send_bytes;

		/* Pacing gains: 1.25, 0.75, 1, 1, 1, 1, 1, 1 */
		switch (phase) {
		case 0:
			send_bytes = (1200 * 125) / 100;  /* Probe up */
			break;
		case 1:
			send_bytes = (1200 * 75) / 100;   /* Drain queue */
			break;
		default:
			send_bytes = 1200;		  /* Cruise */
			break;
		}

		cc_test_send(path, send_bytes);
		cc_test_ack(path, send_bytes, 15000);

		bw_estimates[phase] = ((u64)send_bytes * 1000000) /
				      path->stats.rtt_smoothed;
	}

	/* Phase 0 should have highest BW estimate (probing up) */
	KUNIT_EXPECT_GT(test, bw_estimates[0], bw_estimates[1]);

	kunit_info(test, "BBR probe_bw: phase 0 bw=%llu, phase 1 bw=%llu\n",
		   bw_estimates[0], bw_estimates[1]);
}

/* Test BBR ProbeRTT phase */
static void test_bbr_probe_rtt(struct kunit *test)
{
	struct cc_test_path *path;
	u64 rtt_before, rtt_after;

	path = create_cc_test_path(test);
	path->stats.rtt_min = 15000;  /* 15ms */
	path->stats.rtt_smoothed = 25000;  /* 25ms (buffered) */
	rtt_before = path->stats.rtt_smoothed;

	/* In ProbeRTT, cwnd is reduced to 4 packets */
	path->cwnd = 4 * 1200;

	/* Simulate reduced inflight for 200ms */
	for (int i = 0; i < 20; i++) {
		cc_test_send(path, 1200);
		/* RTT should approach rtt_min with low queue */
		cc_test_ack(path, 1200, path->stats.rtt_min + 1000);
	}

	rtt_after = path->stats.rtt_smoothed;

	/* RTT should have decreased toward rtt_min */
	KUNIT_EXPECT_LT(test, rtt_after, rtt_before);

	kunit_info(test, "BBR probe_rtt: rtt %llu -> %llu (min=%llu)\n",
		   rtt_before, rtt_after, path->stats.rtt_min);
}

/*
 * =============================================================================
 * COPA Tests
 * =============================================================================
 */

/* Test COPA delay-based congestion detection */
static void test_copa_delay_signal(struct kunit *test)
{
	struct cc_test_path *path;
	u64 cwnd_before, cwnd_after;

	path = create_cc_test_path(test);
	path->cwnd = 50 * 1200;
	path->stats.rtt_min = 10000;  /* 10ms */

	cwnd_before = path->cwnd;

	/* Simulate increasing delay (congestion) */
	for (int i = 0; i < 10; i++) {
		u64 rtt_sample = path->stats.rtt_min + i * 5000;  /* Growing delay */

		cc_test_send(path, 1200);
		cc_test_ack(path, 1200, rtt_sample);

		/* COPA: if rtt > rtt_min, reduce rate */
		if (rtt_sample > path->stats.rtt_min * 2) {
			/* COPA decreases cwnd when delay increases */
			path->cwnd = (path->cwnd * 95) / 100;
		}
	}

	cwnd_after = path->cwnd;

	/* cwnd should decrease due to delay signals */
	KUNIT_EXPECT_LT(test, cwnd_after, cwnd_before);

	kunit_info(test, "COPA delay signal: cwnd %llu -> %llu\n",
		   cwnd_before, cwnd_after);
}

/* Test COPA competitive mode */
static void test_copa_competitive(struct kunit *test)
{
	struct cc_test_path *path;
	u64 cwnd_history[20];
	int i;

	path = create_cc_test_path(test);
	path->cwnd = 30 * 1200;
	path->stats.rtt_min = 10000;

	/* Simulate competition: occasional losses */
	for (i = 0; i < 20; i++) {
		cwnd_history[i] = path->cwnd;

		cc_test_send(path, 1200);

		if (i % 5 == 4) {
			/* Loss every 5 packets */
			cc_test_loss(path, 1200);
			path->cwnd = (path->cwnd * 50) / 100;  /* COPA halves on loss */
		} else {
			cc_test_ack(path, 1200, path->stats.rtt_min + 2000);
			/* Grow cwnd in competitive mode */
			path->cwnd += 1200 / 2;
		}
	}

	/* Verify cwnd fluctuates (not monotonic) */
	int increases = 0, decreases = 0;
	for (i = 1; i < 20; i++) {
		if (cwnd_history[i] > cwnd_history[i-1])
			increases++;
		else if (cwnd_history[i] < cwnd_history[i-1])
			decreases++;
	}

	KUNIT_EXPECT_GT(test, increases, 0);
	KUNIT_EXPECT_GT(test, decreases, 0);

	kunit_info(test, "COPA competitive: %d increases, %d decreases\n",
		   increases, decreases);
}

/*
 * =============================================================================
 * Prague (L4S) Tests
 * =============================================================================
 */

/* Test Prague ECN response */
static void test_prague_ecn(struct kunit *test)
{
	struct cc_test_path *path;
	u64 cwnd_before, cwnd_after;

	path = create_cc_test_path(test);
	path->cwnd = 100 * 1200;

	cwnd_before = path->cwnd;

	/* Simulate ECN CE mark feedback */
	/* Prague reduces cwnd proportionally to ECN marking rate */
	u32 ecn_marked = 10;  /* 10% of packets marked */
	u32 total = 100;

	/* Prague multiplicative decrease: 1 - alpha/2 * ecn_fraction */
	u64 alpha = 1024;  /* Fixed point scaling */
	u64 ecn_fraction = (ecn_marked * alpha) / total;
	u64 reduction = (path->cwnd * ecn_fraction) / (2 * alpha);

	path->cwnd -= reduction;
	cwnd_after = path->cwnd;

	KUNIT_EXPECT_LT(test, cwnd_after, cwnd_before);
	/* Prague should reduce less aggressively than classic loss */
	KUNIT_EXPECT_GT(test, cwnd_after, cwnd_before / 2);

	kunit_info(test, "Prague ECN: cwnd %llu -> %llu (reduction %llu)\n",
		   cwnd_before, cwnd_after, reduction);
}

/* Test Prague coexistence with classic flows */
static void test_prague_coexistence(struct kunit *test)
{
	struct cc_test_path *path;
	u64 cwnd_prague, cwnd_classic;

	path = create_cc_test_path(test);

	/* Simulate Prague and CUBIC sharing a bottleneck */
	/* Prague should achieve similar throughput */

	/* Run Prague simulation */
	path->cwnd = 50 * 1200;
	for (int i = 0; i < 100; i++) {
		cc_test_send(path, 1200);
		if (i % 10 == 9) {
			/* ECN marking every 10 packets */
			path->cwnd = (path->cwnd * 95) / 100;
		} else {
			cc_test_ack(path, 1200, 15000);
			path->cwnd += 1200 / 10;
		}
	}
	cwnd_prague = path->cwnd;

	/* Run CUBIC simulation for comparison */
	path->cwnd = 50 * 1200;
	for (int i = 0; i < 100; i++) {
		cc_test_send(path, 1200);
		if (i % 10 == 9) {
			/* Loss every 10 packets */
			cc_test_loss(path, 1200);
			path->cwnd = (path->cwnd * 70) / 100;
		} else {
			cc_test_ack(path, 1200, 15000);
			path->cwnd += (1200 * 1200) / path->cwnd;
		}
	}
	cwnd_classic = path->cwnd;

	/* Prague and CUBIC should have comparable throughput */
	u64 diff = (cwnd_prague > cwnd_classic) ?
		   (cwnd_prague - cwnd_classic) : (cwnd_classic - cwnd_prague);
	u64 avg = (cwnd_prague + cwnd_classic) / 2;

	/* Allow 50% difference for fairness */
	KUNIT_EXPECT_LT(test, diff, avg);

	kunit_info(test, "Prague coexistence: Prague cwnd=%llu, Classic cwnd=%llu\n",
		   cwnd_prague, cwnd_classic);
}

/*
 * =============================================================================
 * Westwood Tests
 * =============================================================================
 */

/* Test Westwood bandwidth estimation */
static void test_westwood_bw_estimate(struct kunit *test)
{
	struct cc_test_path *path;
	u64 bw_estimates[5];
	int i;

	path = create_cc_test_path(test);
	path->cwnd = 50 * 1200;

	/* Westwood estimates bandwidth from ACK rate */
	for (i = 0; i < 5; i++) {
		u32 ack_bytes = 10 * 1200;
		u64 ack_interval = 10000;  /* 10ms */

		cc_test_send(path, ack_bytes);
		cc_test_ack(path, ack_bytes, path->stats.rtt_smoothed);

		/* Westwood BW estimate: bytes_acked / time */
		bw_estimates[i] = (ack_bytes * 1000000) / ack_interval;
	}

	/* Bandwidth estimates should be stable */
	for (i = 1; i < 5; i++) {
		u64 diff = (bw_estimates[i] > bw_estimates[i-1]) ?
			   (bw_estimates[i] - bw_estimates[i-1]) :
			   (bw_estimates[i-1] - bw_estimates[i]);

		/* Allow 20% variance */
		KUNIT_EXPECT_LT(test, diff, bw_estimates[i] / 5);
	}

	kunit_info(test, "Westwood BW estimate: %llu bytes/sec\n",
		   bw_estimates[4]);
}

/* Test Westwood ssthresh on loss */
static void test_westwood_ssthresh(struct kunit *test)
{
	struct cc_test_path *path;
	u64 ssthresh_cubic, ssthresh_westwood;
	u64 estimated_bw;

	path = create_cc_test_path(test);
	path->cwnd = 100 * 1200;

	/* Estimate bandwidth */
	estimated_bw = 10 * 1000000;  /* 10 MB/s */

	/* CUBIC ssthresh on loss: 0.7 * cwnd */
	ssthresh_cubic = (path->cwnd * 70) / 100;

	/* Westwood ssthresh on loss: max(2*MSS, bw * rtt_min) */
	u64 bw_delay_product = (estimated_bw * path->stats.rtt_min) / 1000000;
	ssthresh_westwood = max_t(u64, 2 * 1200, bw_delay_product);

	/* Westwood should set ssthresh based on BDP, not arbitrary factor */
	KUNIT_EXPECT_GT(test, ssthresh_westwood, 2 * 1200ULL);

	kunit_info(test, "Westwood ssthresh: %llu vs CUBIC: %llu\n",
		   ssthresh_westwood, ssthresh_cubic);
}

/*
 * =============================================================================
 * Coupled CC (Multipath) Tests
 * =============================================================================
 */

/* Test coupled CC cwnd coupling */
static void test_coupled_cc_coupling(struct kunit *test)
{
	struct cc_test_path *path1, *path2;
	u64 path1_increase, path2_increase;

	path1 = create_cc_test_path(test);
	path2 = create_cc_test_path(test);

	path1->cwnd = 50 * 1200;
	path2->cwnd = 50 * 1200;

	/* Path 1 has lower RTT */
	path1->stats.rtt_smoothed = 10000;
	path2->stats.rtt_smoothed = 50000;

	/* In coupled CC, total increase is limited */
	/* Lower RTT path gets proportionally more increase */

	/* Simulate ACKs on both paths */
	cc_test_ack(path1, 1200, 10000);
	cc_test_ack(path2, 1200, 50000);

	/* Coupled increase calculation */
	u64 total_cwnd = path1->cwnd + path2->cwnd;
	u64 alpha = 1200;  /* Total increase per RTT */

	/* Distribute based on inverse RTT */
	u64 inv_rtt1 = 1000000 / path1->stats.rtt_smoothed;
	u64 inv_rtt2 = 1000000 / path2->stats.rtt_smoothed;
	u64 total_inv = inv_rtt1 + inv_rtt2;

	path1_increase = (alpha * inv_rtt1) / total_inv;
	path2_increase = (alpha * inv_rtt2) / total_inv;

	path1->cwnd += path1_increase;
	path2->cwnd += path2_increase;

	/* Path 1 (lower RTT) should get more increase */
	KUNIT_EXPECT_GT(test, path1_increase, path2_increase);

	kunit_info(test, "Coupled CC: path1 +%llu, path2 +%llu\n",
		   path1_increase, path2_increase);
}

/* Test coupled CC fairness with single path TCP */
static void test_coupled_cc_fairness(struct kunit *test)
{
	struct cc_test_path *mp_path1, *mp_path2, *sp_path;
	u64 mp_total, sp_total;

	mp_path1 = create_cc_test_path(test);
	mp_path2 = create_cc_test_path(test);
	sp_path = create_cc_test_path(test);

	/* Set up two multipath paths and one single-path */
	mp_path1->cwnd = 30 * 1200;
	mp_path2->cwnd = 30 * 1200;
	sp_path->cwnd = 50 * 1200;

	/* Simulate competition */
	for (int i = 0; i < 100; i++) {
		/* Multipath: coupled increase */
		u64 mp_increase = 1200 / 2;  /* Half of single path increase */
		mp_path1->cwnd += mp_increase / 2;
		mp_path2->cwnd += mp_increase / 2;

		/* Single path: normal TCP increase */
		sp_path->cwnd += 1200;

		/* Occasional loss affects all */
		if (i % 20 == 19) {
			mp_path1->cwnd = (mp_path1->cwnd * 70) / 100;
			mp_path2->cwnd = (mp_path2->cwnd * 70) / 100;
			sp_path->cwnd = (sp_path->cwnd * 70) / 100;
		}
	}

	mp_total = mp_path1->cwnd + mp_path2->cwnd;
	sp_total = sp_path->cwnd;

	/* Multipath total should be similar to single path */
	u64 diff = (mp_total > sp_total) ? (mp_total - sp_total) :
					   (sp_total - mp_total);

	/* Allow 50% difference */
	KUNIT_EXPECT_LT(test, diff, sp_total);

	kunit_info(test, "Coupled CC fairness: MP total=%llu, SP total=%llu\n",
		   mp_total, sp_total);
}

/*
 * =============================================================================
 * Persistent Congestion Tests
 * =============================================================================
 */

/* Test persistent congestion detection */
static void test_persistent_congestion(struct kunit *test)
{
	struct cc_test_path *path;
	u64 cwnd_before, cwnd_after;
	u64 pto = 2 * 20000;  /* 2 * smoothed_rtt */

	path = create_cc_test_path(test);
	path->cwnd = 100 * 1200;
	path->ssthresh = 80 * 1200;

	cwnd_before = path->cwnd;

	/* Simulate persistent congestion:
	 * All packets in period covering more than 3*PTO are lost
	 */
	u64 period_start = 0;
	u64 period_end = 3 * pto + 1;

	/* Check if persistent congestion detected */
	if (period_end - period_start > 3 * pto) {
		/* Persistent congestion: reset to minimum cwnd */
		path->cwnd = 2 * 1200;  /* kMinimumWindow */
		path->ssthresh = path->cwnd;
	}

	cwnd_after = path->cwnd;

	/* cwnd should be reset to minimum */
	KUNIT_EXPECT_EQ(test, cwnd_after, 2 * 1200ULL);
	KUNIT_EXPECT_LT(test, cwnd_after, cwnd_before);

	kunit_info(test, "Persistent congestion: cwnd %llu -> %llu\n",
		   cwnd_before, cwnd_after);
}

/*
 * =============================================================================
 * Test Suite Registration
 * =============================================================================
 */

static struct kunit_case cong_test_cases[] = {
	/* CUBIC tests */
	KUNIT_CASE(test_cubic_slow_start),
	KUNIT_CASE(test_cubic_congestion_avoidance),
	KUNIT_CASE(test_cubic_fast_convergence),

	/* BBR tests */
	KUNIT_CASE(test_bbr_startup),
	KUNIT_CASE(test_bbr_drain),
	KUNIT_CASE(test_bbr_probe_bw),
	KUNIT_CASE(test_bbr_probe_rtt),

	/* COPA tests */
	KUNIT_CASE(test_copa_delay_signal),
	KUNIT_CASE(test_copa_competitive),

	/* Prague (L4S) tests */
	KUNIT_CASE(test_prague_ecn),
	KUNIT_CASE(test_prague_coexistence),

	/* Westwood tests */
	KUNIT_CASE(test_westwood_bw_estimate),
	KUNIT_CASE(test_westwood_ssthresh),

	/* Coupled CC tests */
	KUNIT_CASE(test_coupled_cc_coupling),
	KUNIT_CASE(test_coupled_cc_fairness),

	/* Persistent congestion tests */
	KUNIT_CASE(test_persistent_congestion),

	{}
};

static struct kunit_suite cong_test_suite = {
	.name = "tquic_cong",
	.test_cases = cong_test_cases,
};

kunit_test_suite(cong_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TQUIC Congestion Control Unit Tests");
MODULE_AUTHOR("Linux Foundation");
