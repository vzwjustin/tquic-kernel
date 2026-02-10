// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Westwood+ Congestion Control
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * TCP Westwood+ adapted for TQUIC multipath WAN bonding.
 *
 * Westwood+ is a sender-side modification of TCP that performs
 * bandwidth estimation based on ACK rate. It's particularly suited
 * for wireless and lossy links where packet loss doesn't always
 * indicate congestion.
 *
 * Key features:
 * - Bandwidth estimation from ACK arrival rate
 * - Bandwidth-aware recovery after loss
 * - AIMD with smarter ssthresh selection
 * - Low-pass filter for bandwidth estimation
 *
 * Reference:
 *   Mascolo, S., Casetti, C., Gerla, M., Sanadidi, M., & Wang, R.
 *   "TCP Westwood: End-to-End Congestion Control for Wired/Wireless Networks"
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/math64.h>
#include <net/tquic.h>
#include "../tquic_debug.h"
#include "persistent_cong.h"

/* Westwood+ parameters */
#define WESTWOOD_INIT_CWND	(10 * 1200)	/* 10 packets */
#define WESTWOOD_MIN_CWND	(2 * 1200)	/* 2 packets */
#define WESTWOOD_MSS		1200		/* Maximum segment size */

/* Bandwidth filter parameters */
#define WESTWOOD_FILTER_LEN	8	/* Low-pass filter length */
#define WESTWOOD_DECAY_FACTOR	7	/* Filter decay: 7/8 */

/* Time constants (microseconds) */
#define WESTWOOD_RTT_MIN_DEFAULT	(50 * USEC_PER_MSEC)	/* 50ms */
#define WESTWOOD_BW_SAMPLE_INTERVAL	(50 * USEC_PER_MSEC)	/* 50ms */

/* ECN beta factor for Westwood (same as loss, use BDP-based recovery) */
#define WESTWOOD_ECN_BETA	800	/* 0.8 scaled by 1000 */
#define WESTWOOD_ECN_SCALE	1000

/* Per-path Westwood+ state */
struct tquic_westwood {
	/* Core state */
	u64 cwnd;		/* Current congestion window */
	u64 ssthresh;		/* Slow start threshold */
	bool in_slow_start;	/* In slow start phase */

	/* Bandwidth estimation */
	u64 bw_est;		/* Current bandwidth estimate (bytes/sec) */
	u64 bw_sample;		/* Current bandwidth sample */
	u64 bw_filter[WESTWOOD_FILTER_LEN];	/* Low-pass filter samples */
	u32 bw_filter_idx;	/* Current filter index */
	u32 bw_sample_count;	/* Number of samples */

	/* ACK tracking for bandwidth estimation */
	u64 bytes_acked;	/* Bytes acked in current interval */
	ktime_t last_ack_time;	/* Time of last ACK */
	ktime_t bw_sample_start;	/* Start of current sample interval */

	/* RTT tracking */
	u32 rtt_min_us;		/* Minimum RTT (microseconds) */
	u32 rtt_current_us;	/* Current RTT */

	/* Cumulative ACK tracking */
	u64 cumulative_ack;	/* Cumulative acknowledged bytes */
	ktime_t first_ack_time;	/* Time of first ACK in sample */

	/* Recovery state */
	bool in_recovery;	/* Currently in loss recovery */
	u64 recovery_start;	/* Cumulative ACK at recovery start */

	/* Statistics */
	u64 total_bytes_acked;
	u64 loss_events;

	/* ECN state per RFC 9002 Section 7 */
	ktime_t last_ecn_time;	/* Time of last ECN response */
	bool ecn_in_round;	/* ECN CE received in current round */
	u64 ecn_events;		/* Total ECN CE events */
};

/*
 * Low-pass filter for bandwidth estimation
 * Uses exponentially weighted moving average
 */
static u64 westwood_filter_bw(struct tquic_westwood *ww, u64 bw_sample)
{
	u64 filtered;

	if (ww->bw_sample_count == 0) {
		/* First sample */
		ww->bw_est = bw_sample;
		ww->bw_sample_count = 1;
		return bw_sample;
	}

	/* Add to circular buffer */
	ww->bw_filter[ww->bw_filter_idx] = bw_sample;
	ww->bw_filter_idx = (ww->bw_filter_idx + 1) % WESTWOOD_FILTER_LEN;
	if (ww->bw_sample_count < WESTWOOD_FILTER_LEN)
		ww->bw_sample_count++;

	/*
	 * Apply EWMA filter:
	 * bw_est = (DECAY_FACTOR * bw_est + (8 - DECAY_FACTOR) * sample) / 8
	 */
	filtered = (WESTWOOD_DECAY_FACTOR * ww->bw_est +
		    (8 - WESTWOOD_DECAY_FACTOR) * bw_sample) / 8;

	ww->bw_est = filtered;

	return filtered;
}

/*
 * Calculate bandwidth sample from ACK rate
 * Uses eligible rate estimation (cumulative ACKs over time)
 */
static void westwood_update_bw(struct tquic_westwood *ww, u64 bytes_acked,
			       ktime_t now)
{
	s64 delta_us;
	u64 bw_sample;

	if (ww->bw_sample_start == 0) {
		/* First ACK - initialize */
		ww->bw_sample_start = now;
		ww->bytes_acked = bytes_acked;
		ww->first_ack_time = now;
		return;
	}

	ww->bytes_acked += bytes_acked;
	delta_us = ktime_us_delta(now, ww->bw_sample_start);

	/* Need sufficient time to get meaningful sample */
	if (delta_us < WESTWOOD_BW_SAMPLE_INTERVAL)
		return;

	/* Calculate bandwidth sample: bytes/sec */
	if (delta_us > 0) {
		bw_sample = ww->bytes_acked * USEC_PER_SEC;
		bw_sample = div64_u64(bw_sample, delta_us);

		/* Filter the sample */
		westwood_filter_bw(ww, bw_sample);
	}

	/* Reset for next sample interval */
	ww->bw_sample_start = now;
	ww->bytes_acked = 0;
}

/*
 * Calculate bandwidth-delay product (BDP)
 */
static u64 westwood_bdp(struct tquic_westwood *ww)
{
	u64 bdp;

	if (ww->bw_est == 0 || ww->rtt_min_us == 0)
		return ww->cwnd;

	/* BDP = bandwidth * RTT_min */
	bdp = ww->bw_est * ww->rtt_min_us / USEC_PER_SEC;

	return max(bdp, (u64)WESTWOOD_MIN_CWND);
}

/*
 * Initialize Westwood+ state for a path
 */
static void *tquic_westwood_init(struct tquic_path *path)
{
	struct tquic_westwood *ww;

	ww = kzalloc(sizeof(*ww), GFP_KERNEL);
	if (!ww)
		return NULL;

	ww->cwnd = WESTWOOD_INIT_CWND;
	ww->ssthresh = ULLONG_MAX;
	ww->in_slow_start = true;
	ww->rtt_min_us = WESTWOOD_RTT_MIN_DEFAULT;
	ww->bw_sample_start = ns_to_ktime(0);

	tquic_dbg("westwood: initialized for path %u\n", path->path_id);

	return ww;
}

static void tquic_westwood_release(void *state)
{
	kfree(state);
}

/*
 * Called when a packet is sent
 */
static void tquic_westwood_on_sent(void *state, u64 bytes, ktime_t sent_time)
{
	/* Could track in-flight data for more accurate estimation */
}

/*
 * Called when ACK is received - main Westwood+ logic
 */
static void tquic_westwood_on_ack(void *state, u64 bytes_acked, u64 rtt_us)
{
	struct tquic_westwood *ww = state;
	ktime_t now;

	if (!ww)
		return;

	now = ktime_get();

	/*
	 * Reset ECN round flag if an RTT has elapsed since the last
	 * ECN response, per RFC 9002 Section 7.1 (once-per-RTT limit).
	 */
	if (ww->ecn_in_round && ww->rtt_current_us > 0) {
		s64 elapsed = ktime_us_delta(now, ww->last_ecn_time);

		if (elapsed >= (s64)ww->rtt_current_us)
			ww->ecn_in_round = false;
	}

	ww->total_bytes_acked += bytes_acked;
	ww->cumulative_ack += bytes_acked;

	/* Update RTT tracking */
	if (rtt_us > 0) {
		ww->rtt_current_us = rtt_us;
		if (rtt_us < ww->rtt_min_us || ww->rtt_min_us == 0)
			ww->rtt_min_us = rtt_us;
	}

	/* Update bandwidth estimation */
	westwood_update_bw(ww, bytes_acked, now);

	/* Check if we've exited recovery */
	if (ww->in_recovery && ww->cumulative_ack > ww->recovery_start) {
		ww->in_recovery = false;
		tquic_dbg("westwood: exited recovery, cwnd=%llu bw_est=%llu\n",
			  ww->cwnd, ww->bw_est);
	}

	/* Don't grow cwnd during recovery */
	if (ww->in_recovery)
		return;

	ww->last_ack_time = now;

	/* Slow start phase */
	if (ww->in_slow_start) {
		/* Exponential increase */
		ww->cwnd += bytes_acked;

		if (ww->cwnd >= ww->ssthresh) {
			ww->in_slow_start = false;
			tquic_dbg("westwood: exiting slow start, cwnd=%llu\n",
				  ww->cwnd);
		}
		return;
	}

	/* Congestion avoidance - AIMD increase */
	/* Increase: cwnd += MSS * bytes_acked / cwnd (approximately 1 MSS per RTT) */
	ww->cwnd += (WESTWOOD_MSS * bytes_acked) / ww->cwnd;
}

/*
 * Called on packet loss - Westwood+ recovery
 * Uses bandwidth estimate to set ssthresh instead of cwnd/2
 */
static void tquic_westwood_on_loss(void *state, u64 bytes_lost)
{
	struct tquic_westwood *ww = state;
	u64 bdp;

	if (!ww)
		return;

	ww->loss_events++;

	/* Already in recovery - don't reduce again */
	if (ww->in_recovery)
		return;

	/*
	 * Westwood+ key insight: Use BDP estimate for recovery
	 * instead of the traditional cwnd/2
	 */
	bdp = westwood_bdp(ww);

	/*
	 * Set ssthresh to estimated BDP
	 * This is the key difference from standard AIMD
	 */
	ww->ssthresh = max(bdp, (u64)WESTWOOD_MIN_CWND);

	/*
	 * Set cwnd to ssthresh (not cwnd/2)
	 * This allows faster recovery on lossy links
	 */
	ww->cwnd = ww->ssthresh;

	/* Enter recovery mode */
	ww->in_recovery = true;
	ww->recovery_start = ww->cumulative_ack + ww->cwnd;
	ww->in_slow_start = false;

	tquic_warn("westwood: loss, cwnd=%llu ssthresh=%llu bw_est=%llu bdp=%llu\n",
		   ww->cwnd, ww->ssthresh, ww->bw_est, bdp);
}

/*
 * Called on RTT update
 */
static void tquic_westwood_on_rtt(void *state, u64 rtt_us)
{
	struct tquic_westwood *ww = state;

	if (!ww || rtt_us == 0)
		return;

	ww->rtt_current_us = rtt_us;

	/* Update minimum RTT */
	if (rtt_us < ww->rtt_min_us || ww->rtt_min_us == 0)
		ww->rtt_min_us = rtt_us;
}

/*
 * Called on ECN Congestion Experienced (CE) marks
 *
 * Westwood+ key insight: Use bandwidth estimate for recovery
 * rather than traditional multiplicative decrease. This works
 * well for ECN too, as ECN indicates congestion without loss.
 *
 * Per RFC 9002 Section 7:
 * - Treat ECN-CE as congestion signal similar to loss
 * - Use BDP-based recovery (Westwood's core feature)
 * - Don't reduce more than once per RTT
 *
 * Westwood+ ECN response uses the same bandwidth-based approach
 * as loss recovery, setting ssthresh to estimated BDP.
 */
static void tquic_westwood_on_ecn(void *state, u64 ecn_ce_count)
{
	struct tquic_westwood *ww = state;
	ktime_t now;
	s64 time_since_last;
	u64 bdp;

	if (!ww || ecn_ce_count == 0)
		return;

	now = ktime_get();
	ww->ecn_events++;

	/*
	 * Per RFC 9002: Don't respond more than once per RTT.
	 */
	if (ww->ecn_in_round) {
		tquic_dbg("westwood: ECN CE ignored (already responded this round)\n");
		return;
	}

	/* Time-based rate limiting using min_rtt */
	if (ww->rtt_min_us > 0) {
		time_since_last = ktime_us_delta(now, ww->last_ecn_time);
		if (time_since_last < ww->rtt_min_us) {
			tquic_dbg("westwood: ECN CE ignored (within RTT window)\n");
			return;
		}
	}

	/* Don't reduce if already in recovery */
	if (ww->in_recovery) {
		tquic_dbg("westwood: ECN CE ignored (in recovery)\n");
		return;
	}

	/*
	 * Westwood+ ECN Recovery:
	 *
	 * Use the same bandwidth-based approach as loss recovery.
	 * This is Westwood's key advantage - it uses the estimated
	 * BDP to set ssthresh rather than cwnd/2.
	 *
	 * For ECN, we can be slightly less aggressive since packets
	 * weren't actually lost. Use 80% of estimated BDP.
	 */
	bdp = westwood_bdp(ww);

	/*
	 * Set ssthresh to estimated BDP * beta_ecn
	 * Slightly less aggressive than loss (which uses raw BDP)
	 */
	ww->ssthresh = max(bdp * WESTWOOD_ECN_BETA / WESTWOOD_ECN_SCALE,
			   (u64)WESTWOOD_MIN_CWND);

	/*
	 * Set cwnd to ssthresh.
	 * Westwood allows faster recovery than traditional cwnd/2.
	 */
	ww->cwnd = ww->ssthresh;

	/* Enter recovery mode */
	ww->in_recovery = true;
	ww->recovery_start = ww->cumulative_ack + ww->cwnd;
	ww->in_slow_start = false;

	/* Mark that we responded to ECN in this round */
	ww->ecn_in_round = true;
	ww->last_ecn_time = now;

	tquic_dbg("westwood: ECN CE response, ce_count=%llu cwnd=%llu ssthresh=%llu bw_est=%llu bdp=%llu\n",
		  ecn_ce_count, ww->cwnd, ww->ssthresh, ww->bw_est, bdp);
}

static u64 tquic_westwood_get_cwnd(void *state)
{
	struct tquic_westwood *ww = state;
	return ww ? ww->cwnd : WESTWOOD_INIT_CWND;
}

static u64 tquic_westwood_get_pacing_rate(void *state)
{
	struct tquic_westwood *ww = state;

	if (!ww || ww->rtt_min_us == 0)
		return 0;

	/*
	 * Pacing rate based on cwnd / RTT
	 * Could also use bw_est directly
	 *
	 * Cap cwnd before multiplication to prevent u64 overflow.
	 */
	return div64_u64(min_t(u64, ww->cwnd, U64_MAX / USEC_PER_SEC) *
			 USEC_PER_SEC, ww->rtt_min_us);
}

static bool tquic_westwood_can_send(void *state, u64 bytes)
{
	struct tquic_westwood *ww = state;

	if (!ww)
		return true;

	/* Standard cwnd-based sending allowed */
	return true;
}

/*
 * Called on persistent congestion (RFC 9002 Section 7.6)
 *
 * For Westwood+, persistent congestion indicates our bandwidth
 * estimation was severely wrong. We reset:
 * 1. cwnd to minimum
 * 2. Bandwidth estimation filter (start fresh)
 * 3. Recovery state
 */
static void tquic_westwood_on_persistent_cong(void *state,
					      struct tquic_persistent_cong_info *info)
{
	struct tquic_westwood *ww = state;

	if (!ww || !info)
		return;

	tquic_warn("westwood: persistent congestion, cwnd %llu -> %llu\n",
		   ww->cwnd, info->min_cwnd);

	/* Reset cwnd to minimum per RFC 9002 */
	ww->cwnd = info->min_cwnd;
	ww->ssthresh = info->min_cwnd;

	/* Exit slow start */
	ww->in_slow_start = false;

	/* Clear recovery state */
	ww->in_recovery = false;

	/* Reset bandwidth estimation - our estimates were clearly wrong */
	ww->bw_est = 0;
	ww->bw_sample_count = 0;
	ww->bw_filter_idx = 0;
	memset(ww->bw_filter, 0, sizeof(ww->bw_filter));

	/* Reset sample interval tracking */
	ww->bytes_acked = 0;
	ww->bw_sample_start = ns_to_ktime(0);

	/* Reset ECN state */
	ww->ecn_in_round = false;
}

static struct tquic_cong_ops __maybe_unused tquic_westwood_ops = {
	.name = "westwood",
	.owner = THIS_MODULE,
	.init = tquic_westwood_init,
	.release = tquic_westwood_release,
	.on_packet_sent = tquic_westwood_on_sent,
	.on_ack = tquic_westwood_on_ack,
	.on_loss = tquic_westwood_on_loss,
	.on_rtt_update = tquic_westwood_on_rtt,
	.on_ecn = tquic_westwood_on_ecn,  /* ECN CE handler per RFC 9002 */
	.on_persistent_congestion = tquic_westwood_on_persistent_cong,
	.get_cwnd = tquic_westwood_get_cwnd,
	.get_pacing_rate = tquic_westwood_get_pacing_rate,
	.can_send = tquic_westwood_can_send,
};

#ifndef TQUIC_OUT_OF_TREE
static int __init tquic_westwood_module_init(void)
{
	tquic_info("cc: westwood algorithm registered\n");
	return tquic_register_cong(&tquic_westwood_ops);
}

static void __exit tquic_westwood_module_exit(void)
{
	tquic_unregister_cong(&tquic_westwood_ops);
}

module_init(tquic_westwood_module_init);
module_exit(tquic_westwood_module_exit);
#endif /* !TQUIC_OUT_OF_TREE */

MODULE_DESCRIPTION("TQUIC Westwood+ Congestion Control");
MODULE_AUTHOR("Linux Foundation");
MODULE_LICENSE("GPL");
MODULE_ALIAS("tquic-cong-westwood");
