// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: BBR Congestion Control
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * BBR (Bottleneck Bandwidth and RTT) congestion control for TQUIC.
 * Adapted for multipath WAN bonding scenarios.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <net/tquic.h>
#include "../tquic_debug.h"
#include "persistent_cong.h"

/* BBR parameters */
#define BBR_SCALE		8
#define BBR_UNIT		(1 << BBR_SCALE)

/* Pacing gain during STARTUP */
#define BBR_HIGH_GAIN		((2885 * BBR_UNIT) / 1000)  /* 2/ln(2) */
/* Pacing gain during DRAIN */
#define BBR_DRAIN_GAIN		((1000 * BBR_UNIT) / 2885)
/* Pacing gain during PROBE_BW */
#define BBR_PACING_GAIN		BBR_UNIT
/* cwnd gain */
#define BBR_CWND_GAIN		(2 * BBR_UNIT)

/* Probe RTT duration */
#define BBR_PROBE_RTT_MS	200

/* Min cwnd in packets */
#define BBR_MIN_CWND_PKTS	4

/* Initial RTT fallback for cycle duration (333ms, matching QUIC default) */
#define TQUIC_INITIAL_RTT_MS	333

/* BBR state machine */
enum bbr_mode {
	BBR_STARTUP,	/* Ramp up to fill pipe */
	BBR_DRAIN,	/* Drain excess queue */
	BBR_PROBE_BW,	/* Discover bandwidth */
	BBR_PROBE_RTT,	/* Probe min RTT */
};

/* ECN parameters for BBR */
#define BBR_ECN_INFLIGHT_REDUCTION	((BBR_UNIT * 3) / 4)  /* 0.75 */
#define BBR_ECN_PACING_REDUCTION	((BBR_UNIT * 9) / 10) /* 0.9 */

/* Per-path BBR state */
struct tquic_bbr {
	/* Core BBR state */
	enum bbr_mode mode;
	u64 bw;			/* Max bandwidth (bytes/us) */
	u32 min_rtt_us;		/* Min RTT in microseconds */
	u32 rtt_cnt;		/* Rounds since RTT measurement */

	/* Pacing state */
	u64 pacing_rate;	/* Current pacing rate */
	u32 pacing_gain;	/* Pacing gain (scaled) */
	u32 cwnd_gain;		/* cwnd gain (scaled) */

	/* cwnd */
	u64 cwnd;		/* Congestion window */
	u64 prior_cwnd;		/* cwnd before PROBE_RTT */

	/* Bandwidth filter */
	struct {
		u64 bw[10];	/* Bandwidth samples */
		u32 head;	/* Ring buffer head */
		u32 count;	/* Sample count */
	} bw_filter;

	/* RTT filter */
	u32 min_rtt_stamp;	/* Timestamp of min RTT */

	/* Round counting and delivery rate */
	u64 delivered;		/* Total delivered bytes */
	u64 round_start;	/* delivered at round start */
	bool round_started;
	u64 prior_delivered;	/* delivered at start of interval */
	ktime_t prior_delivered_time; /* timestamp at start of interval */

	/* Cycle state for PROBE_BW */
	u32 cycle_idx;		/* Cycle index */
	u32 cycle_stamp;	/* Cycle start time */

	/* PROBE_RTT state */
	bool probe_rtt_done;
	u32 probe_rtt_stamp;

	/* ECN state per RFC 9002 Section 7 */
	u64 inflight_hi;	/* High water mark for inflight */
	u64 inflight_lo;	/* Low water mark for inflight */
	ktime_t last_ecn_time;	/* Time of last ECN response */
	bool ecn_in_round;	/* ECN CE received in current round */
	bool ecn_eligible;	/* Path is ECN-capable */
	u64 ecn_ce_total;	/* Total CE marks received */
};

/* Pacing gain cycle for PROBE_BW */
static const u32 bbr_pacing_cycle[] = {
	BBR_UNIT * 5 / 4,	/* 1.25 - probe for more bandwidth */
	BBR_UNIT * 3 / 4,	/* 0.75 - drain excess */
	BBR_UNIT,
	BBR_UNIT,
	BBR_UNIT,
	BBR_UNIT,
	BBR_UNIT,
	BBR_UNIT,
};
#define BBR_CYCLE_LEN	ARRAY_SIZE(bbr_pacing_cycle)

/*
 * Update bandwidth filter with new sample
 */
static void bbr_update_bw(struct tquic_bbr *bbr, u64 bw_sample)
{
	struct tquic_bbr *f = bbr;
	u64 max_bw = 0;
	int i;

	tquic_dbg("bbr: update_bw sample=%llu prev_max=%llu\n",
		  bw_sample, bbr->bw);

	/* Add to ring buffer */
	f->bw_filter.bw[f->bw_filter.head] = bw_sample;
	f->bw_filter.head = (f->bw_filter.head + 1) % 10;
	if (f->bw_filter.count < 10)
		f->bw_filter.count++;

	/* Find max */
	for (i = 0; i < f->bw_filter.count; i++) {
		if (f->bw_filter.bw[i] > max_bw)
			max_bw = f->bw_filter.bw[i];
	}

	bbr->bw = max_bw;
}

/*
 * Calculate pacing rate
 */
static void bbr_set_pacing_rate(struct tquic_bbr *bbr)
{
	u64 rate;

	tquic_dbg("bbr: set_pacing_rate bw=%llu gain=%u\n",
		  bbr->bw, bbr->pacing_gain);

	rate = bbr->bw * bbr->pacing_gain / BBR_UNIT;

	/* Ensure minimum rate */
	if (rate < 1200)
		rate = 1200;

	bbr->pacing_rate = rate;
}

/*
 * Calculate cwnd
 */
static void bbr_set_cwnd(struct tquic_bbr *bbr)
{
	u64 target_cwnd;

	tquic_dbg("bbr: set_cwnd bw=%llu min_rtt=%u gain=%u\n",
		  bbr->bw, bbr->min_rtt_us, bbr->cwnd_gain);

	if (bbr->bw == 0 || bbr->min_rtt_us == 0) {
		bbr->cwnd = 10 * 1200;  /* Initial cwnd */
		return;
	}

	/* BDP */
	target_cwnd = bbr->bw * bbr->min_rtt_us / 1000000;

	/* Apply gain */
	target_cwnd = target_cwnd * bbr->cwnd_gain / BBR_UNIT;

	/* Ensure minimum */
	target_cwnd = max(target_cwnd, (u64)(BBR_MIN_CWND_PKTS * 1200));

	bbr->cwnd = target_cwnd;
}

/*
 * Check if we should enter PROBE_RTT
 */
static void bbr_check_probe_rtt(struct tquic_bbr *bbr, u32 now_ms)
{
	tquic_dbg("bbr: check_probe_rtt mode=%d min_rtt_stamp=%u now=%u\n",
		  bbr->mode, bbr->min_rtt_stamp, now_ms);

	if (bbr->mode == BBR_PROBE_RTT)
		return;

	/* Enter PROBE_RTT if min_rtt is stale */
	if (now_ms - bbr->min_rtt_stamp > 10000) {  /* 10 seconds */
		bbr->prior_cwnd = bbr->cwnd;
		bbr->mode = BBR_PROBE_RTT;
		bbr->probe_rtt_done = false;
		bbr->probe_rtt_stamp = now_ms;
		bbr->pacing_gain = BBR_UNIT;
	}
}

/*
 * Handle PROBE_RTT state
 */
static void bbr_handle_probe_rtt(struct tquic_bbr *bbr, u32 now_ms)
{
	tquic_dbg("bbr: handle_probe_rtt done=%d stamp=%u now=%u\n",
		  bbr->probe_rtt_done, bbr->probe_rtt_stamp, now_ms);

	/* Reduce cwnd to min */
	bbr->cwnd = BBR_MIN_CWND_PKTS * 1200;

	if (!bbr->probe_rtt_done) {
		if (now_ms - bbr->probe_rtt_stamp >= BBR_PROBE_RTT_MS) {
			bbr->probe_rtt_done = true;
			bbr->min_rtt_stamp = now_ms;
		}
	} else {
		/* Exit PROBE_RTT */
		bbr->cwnd = bbr->prior_cwnd;
		bbr->mode = BBR_PROBE_BW;
		bbr->cycle_idx = 0;
		bbr->pacing_gain = bbr_pacing_cycle[0];
	}
}

/*
 * Initialize BBR state
 */
static void *tquic_bbr_init(struct tquic_path *path)
{
	struct tquic_bbr *bbr;

	bbr = kzalloc(sizeof(*bbr), GFP_KERNEL);
	if (!bbr)
		return NULL;

	bbr->mode = BBR_STARTUP;
	bbr->pacing_gain = BBR_HIGH_GAIN;
	bbr->cwnd_gain = BBR_CWND_GAIN;
	bbr->cwnd = 10 * 1200;
	bbr->min_rtt_us = UINT_MAX;
	bbr->prior_delivered_time = ktime_get();

	tquic_dbg("bbr: initialized for path %u\n", path->path_id);

	return bbr;
}

static void tquic_bbr_release(void *state)
{
	kfree(state);
}

static void tquic_bbr_on_sent(void *state, u64 bytes, ktime_t sent_time)
{
	/* Track sent data for delivery rate */
}

/*
 * Process ACK - main BBR logic
 */
static void tquic_bbr_on_ack(void *state, u64 bytes_acked, u64 rtt_us)
{
	struct tquic_bbr *bbr = state;
	u32 now_ms = jiffies_to_msecs(jiffies);
	u64 bw_sample;

	if (!bbr)
		return;

	tquic_dbg("bbr: on_ack bytes=%llu rtt=%llu mode=%d cwnd=%llu bw=%llu\n",
		  bytes_acked, rtt_us, bbr->mode, bbr->cwnd, bbr->bw);

	/*
	 * Reset ECN round flag if an RTT has elapsed since the last
	 * ECN response, per RFC 9002 Section 7.1 (once-per-RTT limit).
	 */
	if (bbr->ecn_in_round && bbr->min_rtt_us > 0 &&
	    bbr->min_rtt_us != UINT_MAX) {
		s64 elapsed = ktime_us_delta(ktime_get(), bbr->last_ecn_time);

		if (elapsed >= (s64)bbr->min_rtt_us)
			bbr->ecn_in_round = false;
	}

	/* Update min RTT */
	if (rtt_us < bbr->min_rtt_us || bbr->min_rtt_us == UINT_MAX) {
		bbr->min_rtt_us = rtt_us;
		bbr->min_rtt_stamp = now_ms;
	}

	/* Update round counting */
	bbr->delivered += bytes_acked;

	/*
	 * Compute delivery rate as bytes_delivered / delivery_interval.
	 * This is the correct BBR bandwidth estimation per the BBR paper,
	 * not bytes_acked/rtt which overestimates BW on coalesced ACKs.
	 */
	{
		ktime_t now = ktime_get();
		s64 interval_us = ktime_us_delta(now,
						 bbr->prior_delivered_time);
		u64 delivered_delta = bbr->delivered - bbr->prior_delivered;

		if (interval_us > 0 && delivered_delta > 0) {
			bw_sample = delivered_delta * USEC_PER_SEC /
				    (u64)interval_us;
			bbr_update_bw(bbr, bw_sample);
		}

		/* Update delivery tracking for next interval */
		bbr->prior_delivered = bbr->delivered;
		bbr->prior_delivered_time = now;
	}

	/* State machine */
	switch (bbr->mode) {
	case BBR_STARTUP:
		/* Check if bandwidth growth has slowed */
		if (bbr->bw_filter.count >= 3) {
			u64 thresh = bbr->bw * 5 / 4;
			if (bw_sample < thresh) {
				/* Bandwidth not growing, exit startup */
				bbr->mode = BBR_DRAIN;
				bbr->pacing_gain = BBR_DRAIN_GAIN;
			}
		}
		break;

	case BBR_DRAIN:
		/*
		 * Drain excess queue built up during STARTUP.
		 * Stay in DRAIN until estimated inflight <= BDP.
		 * BBR_DRAIN_GAIN < 1.0, so pacing rate < BtlBw,
		 * which will gradually reduce the queue.
		 */
		bbr->pacing_gain = BBR_DRAIN_GAIN;
		if (bbr->bw > 0 && bbr->min_rtt_us != UINT_MAX) {
			u64 bdp = bbr->bw * bbr->min_rtt_us / 1000000;

			/*
			 * Transition to PROBE_BW once inflight has
			 * drained to the estimated BDP. Use cwnd as
			 * a proxy for inflight.
			 */
			if (bbr->cwnd <= bdp) {
				bbr->mode = BBR_PROBE_BW;
				bbr->cycle_idx = 0;
				bbr->cycle_stamp = now_ms;
				bbr->pacing_gain = bbr_pacing_cycle[0];
			}
		}
		break;

	case BBR_PROBE_BW:
		/* Cycle through pacing gains */
		if (bbr->min_rtt_us == UINT_MAX) {
			/* No RTT sample yet; use initial RTT as cycle duration */
			if (now_ms - bbr->cycle_stamp >=
			    TQUIC_INITIAL_RTT_MS) {
				bbr->cycle_idx = (bbr->cycle_idx + 1) %
						 BBR_CYCLE_LEN;
				bbr->pacing_gain =
					bbr_pacing_cycle[bbr->cycle_idx];
				bbr->cycle_stamp = now_ms;
			}
		} else if (now_ms - bbr->cycle_stamp >= bbr->min_rtt_us / 1000) {
			bbr->cycle_idx = (bbr->cycle_idx + 1) % BBR_CYCLE_LEN;
			bbr->pacing_gain = bbr_pacing_cycle[bbr->cycle_idx];
			bbr->cycle_stamp = now_ms;
		}
		bbr_check_probe_rtt(bbr, now_ms);
		break;

	case BBR_PROBE_RTT:
		bbr_handle_probe_rtt(bbr, now_ms);
		break;
	}

	/* Update pacing rate and cwnd */
	bbr_set_pacing_rate(bbr);
	if (bbr->mode != BBR_PROBE_RTT)
		bbr_set_cwnd(bbr);
}

static void tquic_bbr_on_loss(void *state, u64 bytes_lost)
{
	/*
	 * BBR v1 doesn't traditionally reduce cwnd on loss.
	 * However, persistent loss can indicate that inflight_hi
	 * is too high. BBR v2 addresses this more explicitly.
	 *
	 * For BBR v1 compatibility, we track but don't aggressively respond.
	 */
}

/*
 * Called on ECN Congestion Experienced (CE) marks
 *
 * BBR treats ECN as a signal to reduce inflight_hi (the ceiling
 * on bytes in flight). Unlike loss-based algorithms, BBR doesn't
 * directly reduce cwnd but instead constrains the amount of data
 * it keeps in flight.
 *
 * Per RFC 9002 Section 7 and BBR draft:
 * - ECN-CE indicates the queue is building at a bottleneck
 * - BBR should reduce its inflight target
 * - May enter PROBE_RTT sooner or reduce pacing rate
 */
static void tquic_bbr_on_ecn(void *state, u64 ecn_ce_count)
{
	struct tquic_bbr *bbr = state;
	ktime_t now;
	s64 time_since_last;
	u64 bdp;

	if (!bbr || ecn_ce_count == 0)
		return;

	now = ktime_get();

	/*
	 * Per RFC 9002: Don't respond more than once per RTT.
	 * Use time-based rate limiting.
	 */
	if (bbr->ecn_in_round) {
		tquic_dbg("bbr: ECN CE ignored (already responded this round)\n");
		return;
	}

	/* Time-based rate limiting using min_rtt */
	if (bbr->min_rtt_us > 0 && bbr->min_rtt_us != UINT_MAX) {
		time_since_last = ktime_us_delta(now, bbr->last_ecn_time);
		if (time_since_last < bbr->min_rtt_us) {
			tquic_dbg("bbr: ECN CE ignored (within RTT window)\n");
			return;
		}
	}

	bbr->ecn_ce_total += ecn_ce_count;
	bbr->ecn_eligible = true;

	/*
	 * BBR ECN Response Strategy:
	 *
	 * 1. Reduce inflight_hi - this caps the amount of data BBR
	 *    will keep in flight, reducing queue occupancy.
	 *
	 * 2. Temporarily reduce pacing gain - this slows down the
	 *    sending rate to drain the queue.
	 *
	 * 3. Consider entering PROBE_RTT sooner if ECN is persistent.
	 */

	/* Calculate current BDP as baseline */
	if (bbr->bw > 0 && bbr->min_rtt_us > 0 && bbr->min_rtt_us != UINT_MAX) {
		bdp = bbr->bw * bbr->min_rtt_us / 1000000;
	} else {
		bdp = bbr->cwnd;
	}

	/*
	 * Set inflight_hi to limit queue buildup.
	 * Use 75% of current cwnd as the new ceiling, but not less than BDP.
	 */
	if (bbr->inflight_hi == 0)
		bbr->inflight_hi = bbr->cwnd;

	bbr->inflight_hi = max(
		bbr->inflight_hi * BBR_ECN_INFLIGHT_REDUCTION / BBR_UNIT,
		bdp);

	/*
	 * Reduce cwnd to inflight_hi if it's higher.
	 * This is a soft constraint - BBR will probe back up.
	 */
	if (bbr->cwnd > bbr->inflight_hi)
		bbr->cwnd = bbr->inflight_hi;

	/*
	 * Temporarily reduce pacing gain in PROBE_BW mode.
	 * This helps drain the queue faster.
	 */
	if (bbr->mode == BBR_PROBE_BW) {
		/* Move to a draining cycle phase */
		bbr->pacing_gain = bbr_pacing_cycle[1];  /* 0.75 drain gain */
		bbr->cycle_stamp = jiffies_to_msecs(jiffies);
	}

	/*
	 * If we're seeing persistent ECN-CE, consider entering PROBE_RTT
	 * to completely drain the queue and measure true min_rtt.
	 */
	if (bbr->ecn_ce_total > 10 && bbr->mode != BBR_PROBE_RTT) {
		u32 now_ms = jiffies_to_msecs(jiffies);

		/* Enter PROBE_RTT if min_rtt is getting stale anyway */
		if (now_ms - bbr->min_rtt_stamp > 5000) {  /* 5 seconds */
			bbr->prior_cwnd = bbr->cwnd;
			bbr->mode = BBR_PROBE_RTT;
			bbr->probe_rtt_done = false;
			bbr->probe_rtt_stamp = now_ms;
			bbr->pacing_gain = BBR_UNIT;
		}
	}

	/* Mark that we responded to ECN in this round */
	bbr->ecn_in_round = true;
	bbr->last_ecn_time = now;

	/* Update pacing rate after changes */
	bbr_set_pacing_rate(bbr);

	tquic_dbg("bbr: ECN CE response, ce_count=%llu total=%llu cwnd=%llu inflight_hi=%llu\n",
		  ecn_ce_count, bbr->ecn_ce_total, bbr->cwnd, bbr->inflight_hi);
}

static void tquic_bbr_on_rtt(void *state, u64 rtt_us)
{
	struct tquic_bbr *bbr = state;

	if (!bbr)
		return;

	tquic_dbg("bbr: on_rtt rtt_us=%llu min_rtt=%u\n",
		  rtt_us, bbr->min_rtt_us);

	/* Update min RTT */
	if (rtt_us < bbr->min_rtt_us) {
		bbr->min_rtt_us = rtt_us;
		bbr->min_rtt_stamp = jiffies_to_msecs(jiffies);
	}
}

static u64 tquic_bbr_get_cwnd(void *state)
{
	struct tquic_bbr *bbr = state;
	return bbr ? bbr->cwnd : 10 * 1200;
}

static u64 tquic_bbr_get_pacing_rate(void *state)
{
	struct tquic_bbr *bbr = state;
	return bbr ? bbr->pacing_rate : 0;
}

static bool tquic_bbr_can_send(void *state, u64 bytes)
{
	return true;  /* BBR uses pacing, not cwnd limiting */
}

/*
 * Called on persistent congestion (RFC 9002 Section 7.6)
 *
 * For BBR, persistent congestion requires:
 * 1. Reset cwnd to minimum
 * 2. Reset inflight limits
 * 3. Re-enter STARTUP to rediscover bandwidth
 *
 * BBR is model-based, so persistent congestion means our model
 * is severely wrong. We need to start fresh.
 */
static void tquic_bbr_on_persistent_cong(void *state,
					 struct tquic_persistent_cong_info *info)
{
	struct tquic_bbr *bbr = state;

	if (!bbr || !info)
		return;

	tquic_warn("bbr: persistent congestion, cwnd %llu -> %llu\n",
		   bbr->cwnd, info->min_cwnd);

	/* Reset cwnd to minimum per RFC 9002 */
	bbr->cwnd = info->min_cwnd;
	bbr->prior_cwnd = info->min_cwnd;

	/* Reset inflight limits */
	bbr->inflight_hi = 0;
	bbr->inflight_lo = 0;

	/*
	 * Re-enter STARTUP mode to rediscover bandwidth.
	 * Persistent congestion means our bandwidth estimate was wrong.
	 */
	bbr->mode = BBR_STARTUP;
	bbr->pacing_gain = BBR_HIGH_GAIN;
	bbr->cwnd_gain = BBR_CWND_GAIN;

	/* Reset bandwidth filter - our estimates were clearly wrong */
	memset(&bbr->bw_filter, 0, sizeof(bbr->bw_filter));
	bbr->bw = 0;

	/* Keep min_rtt estimate but mark it as potentially stale */
	bbr->rtt_cnt = 0;

	/* Update pacing rate based on new state */
	bbr_set_pacing_rate(bbr);

	/* Reset ECN state */
	bbr->ecn_in_round = false;
	bbr->ecn_ce_total = 0;
}

static struct tquic_cong_ops __maybe_unused tquic_bbr_ops = {
	.name = "bbr",
	.owner = THIS_MODULE,
	.init = tquic_bbr_init,
	.release = tquic_bbr_release,
	.on_packet_sent = tquic_bbr_on_sent,
	.on_ack = tquic_bbr_on_ack,
	.on_loss = tquic_bbr_on_loss,
	.on_rtt_update = tquic_bbr_on_rtt,
	.on_ecn = tquic_bbr_on_ecn,  /* ECN CE handler per RFC 9002 */
	.on_persistent_congestion = tquic_bbr_on_persistent_cong,
	.get_cwnd = tquic_bbr_get_cwnd,
	.get_pacing_rate = tquic_bbr_get_pacing_rate,
	.can_send = tquic_bbr_can_send,
};

#ifndef TQUIC_OUT_OF_TREE
static int __init tquic_bbr_module_init(void)
{
	return tquic_register_cong(&tquic_bbr_ops);
}

static void __exit tquic_bbr_module_exit(void)
{
	tquic_unregister_cong(&tquic_bbr_ops);
}

module_init(tquic_bbr_module_init);
module_exit(tquic_bbr_module_exit);
#endif /* !TQUIC_OUT_OF_TREE */

MODULE_DESCRIPTION("TQUIC BBR Congestion Control");
MODULE_LICENSE("GPL");
MODULE_ALIAS("tquic-cong-bbr");
