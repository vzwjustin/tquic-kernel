// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: BBRv2 Congestion Control
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * BBRv2 implementation for QUIC. BBR (Bottleneck Bandwidth and RTT)
 * uses bandwidth and RTT estimates to control sending rate, aiming
 * to maximize throughput while minimizing queuing delay.
 *
 * BBRv2 improvements:
 * - Explicit loss handling via inflight_lo/inflight_hi bounds
 * - ECN support for L4S and classic ECN networks
 * - Better fairness through conservative startup and probing
 * - Reduced buffer bloat via target queue of ~2 BDP
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/random.h>

#include "bbrv2.h"
#include "../tquic_debug.h"

/* Default MTU for calculations */
#define BBR_DEFAULT_MSS		1200

/* Pacing gain cycle for ProbeBW (8 phases) */
static const u32 bbr_pacing_gain_cycle[] = {
	BBR_UNIT * 5 / 4,	/* 1.25x probe up */
	BBR_UNIT * 3 / 4,	/* 0.75x probe down */
	BBR_UNIT,		/* 1.00x cruise */
	BBR_UNIT,
	BBR_UNIT,
	BBR_UNIT,
	BBR_UNIT,
	BBR_UNIT,
};

/* Default parameters */
static u32 bbr_probe_rtt_interval_ms = 10000;	/* 10 seconds */
static u32 bbr_ecn_factor = BBR2_ECN_THRESH;
static u32 bbr_loss_thresh = BBR2_LOSS_THRESH;
static u32 bbr_beta = BBR2_BETA;
static u32 bbr_headroom = BBR2_HEADROOM;

module_param(bbr_probe_rtt_interval_ms, uint, 0644);
MODULE_PARM_DESC(bbr_probe_rtt_interval_ms, "ProbeRTT interval (default: 10000ms)");

/**
 * bbr_minmax_reset - Reset windowed filter
 * @filter: Filter to reset
 * @window_len: Window length
 */
static void bbr_minmax_reset(struct bbr_minmax *filter, u64 window_len)
{
	memset(filter->samples, 0, sizeof(filter->samples));
	filter->window_len = window_len;
}

/**
 * bbr_minmax_running_max - Update windowed max filter
 * @filter: Filter to update
 * @now: Current timestamp
 * @value: New sample value
 *
 * Return: Current maximum value
 */
static u64 bbr_minmax_running_max(struct bbr_minmax *filter, u64 now, u64 value)
{
	struct bbr_minmax_sample *s = filter->samples;
	u64 dt = now - s[0].time;

	/* New maximum or window expired */
	if (value >= s[0].value || dt > filter->window_len) {
		s[0].time = now;
		s[0].value = value;
		s[1] = s[0];
		s[2] = s[0];
		return value;
	}

	/* Second subwindow */
	if (value >= s[1].value) {
		s[1].time = now;
		s[1].value = value;
		s[2] = s[1];
	} else if (value >= s[2].value) {
		s[2].time = now;
		s[2].value = value;
	}

	/* Check for subwindow expiration */
	dt = now - s[1].time;
	if (dt > filter->window_len / 4) {
		s[0] = s[1];
		s[1] = s[2];
		s[2].time = now;
		s[2].value = value;
	}

	return s[0].value;
}

/**
 * bbr_minmax_running_min - Update windowed min filter
 * @filter: Filter to update
 * @now: Current timestamp
 * @value: New sample value
 *
 * Return: Current minimum value
 */
static u64 bbr_minmax_running_min(struct bbr_minmax *filter, u64 now, u64 value)
{
	struct bbr_minmax_sample *s = filter->samples;
	u64 dt = now - s[0].time;

	/* New minimum or window expired */
	if (value <= s[0].value || dt > filter->window_len) {
		s[0].time = now;
		s[0].value = value;
		s[1] = s[0];
		s[2] = s[0];
		return value;
	}

	/* Update subwindows */
	if (value <= s[1].value) {
		s[1].time = now;
		s[1].value = value;
		s[2] = s[1];
	} else if (value <= s[2].value) {
		s[2].time = now;
		s[2].value = value;
	}

	dt = now - s[1].time;
	if (dt > filter->window_len / 4) {
		s[0] = s[1];
		s[1] = s[2];
		s[2].time = now;
		s[2].value = value;
	}

	return s[0].value;
}

/**
 * bbr_get_mss - Get MSS from path or use default
 * @bbr: BBRv2 state
 *
 * Return: Maximum segment size
 */
static u32 bbr_get_mss(struct bbrv2 *bbr)
{
	if (bbr->path && bbr->path->mtu > 0)
		return bbr->path->mtu;
	return BBR_DEFAULT_MSS;
}

/**
 * bbr_bdp - Calculate bandwidth-delay product
 * @bbr: BBRv2 state
 *
 * Return: BDP in bytes
 */
static u64 bbr_bdp(struct bbrv2 *bbr)
{
	/* BDP = bw * min_rtt */
	return (bbr->bw * bbr->min_rtt_us) / USEC_PER_SEC;
}

/**
 * bbr_inflight - Calculate target inflight
 * @bbr: BBRv2 state
 * @gain: Cwnd gain to apply
 *
 * Return: Target inflight bytes
 */
static u32 bbr_inflight(struct bbrv2 *bbr, u32 gain)
{
	u64 inflight;
	u32 mss = bbr_get_mss(bbr);

	inflight = bbr_bdp(bbr);
	inflight = (inflight * gain) >> BBR_SCALE;

	return max((u32)inflight, (u32)(BBR_MIN_CWND * mss));
}

/**
 * bbr_update_round - Check if a new round has started
 * @bbr: BBRv2 state
 * @delivered: Bytes delivered so far
 */
static void bbr_update_round(struct bbrv2 *bbr, u64 delivered)
{
	if (delivered >= bbr->next_round_delivered) {
		bbr->round_start = true;
		bbr->round_count++;
		bbr->next_round_delivered = delivered;
		bbr->ecn_in_round = 0;
		bbr->loss_in_round = 0;
	} else {
		bbr->round_start = false;
	}
}

/**
 * bbr_check_full_bw_reached - Check if startup has filled the pipe
 * @bbr: BBRv2 state
 *
 * Detects when bandwidth growth has plateaued, indicating full pipe.
 */
static void bbr_check_full_bw_reached(struct bbrv2 *bbr)
{
	u64 bw_thresh;

	if (bbr->full_bw_reached || !bbr->round_start)
		return;

	/* Check if bandwidth increased by at least 25% */
	bw_thresh = (bbr->full_bw * 5) / 4;

	if (bbr->bw >= bw_thresh) {
		bbr->full_bw = bbr->bw;
		bbr->full_bw_count = 0;
		return;
	}

	/* No significant increase for 3 rounds = full */
	if (++bbr->full_bw_count >= 3) {
		bbr->full_bw_reached = true;
	}
}

/**
 * bbr_set_cwnd - Set the congestion window
 * @bbr: BBRv2 state
 */
static void bbr_set_cwnd(struct bbrv2 *bbr)
{
	u32 target;
	u32 mss = bbr_get_mss(bbr);

	target = bbr_inflight(bbr, bbr->cwnd_gain);

	/* BBRv2: Bound cwnd by inflight_lo and inflight_hi */
	if (bbr->inflight_lo != UINT_MAX)
		target = min(target, bbr->inflight_lo);
	if (bbr->inflight_hi != 0)
		target = min(target, bbr->inflight_hi);

	/* During recovery, don't increase cwnd */
	if (bbr->in_loss_recovery)
		target = min(target, bbr->prior_cwnd);

	/* Ensure minimum cwnd */
	bbr->cwnd = max(target, BBR_MIN_CWND * mss);
}

/**
 * bbr_enter_startup - Enter Startup mode
 * @bbr: BBRv2 state
 */
static void bbr_enter_startup(struct bbrv2 *bbr)
{
	enum bbr_mode old_mode = bbr->mode;

	bbr->mode = BBR_STARTUP;
	bbr->pacing_gain = BBR_HIGH_GAIN;
	bbr->cwnd_gain = BBR_HIGH_GAIN;
	tquic_dbg("bbrv2: state %u -> STARTUP\n", old_mode);
}

/**
 * bbr_enter_drain - Enter Drain mode
 * @bbr: BBRv2 state
 */
static void bbr_enter_drain(struct bbrv2 *bbr)
{
	bbr->mode = BBR_DRAIN;
	bbr->pacing_gain = BBR_DRAIN_GAIN;
	bbr->cwnd_gain = BBR_HIGH_GAIN;
	tquic_dbg("bbrv2: state -> DRAIN, cwnd=%u\n", bbr->cwnd);
}

/**
 * bbr_enter_probe_bw - Enter ProbeBW mode
 * @bbr: BBRv2 state
 */
static void bbr_enter_probe_bw(struct bbrv2 *bbr)
{
	bbr->mode = BBR_PROBE_BW;
	bbr->probe_bw_phase = BBR2_PROBE_BW_CRUISE;
	bbr->pacing_gain = BBR_UNIT;
	bbr->cwnd_gain = BBR_CWND_GAIN;

	/* Random start position in cycle for fairness */
	bbr->cycle_idx = get_random_u32() % BBR_GAIN_CYCLE_LEN;
	bbr->cycle_start = ktime_get_ns();
	tquic_dbg("bbrv2: state -> PROBE_BW, bw=%llu cwnd=%u\n",
		  bbr->bw, bbr->cwnd);
}

/**
 * bbr_enter_probe_rtt - Enter ProbeRTT mode
 * @bbr: BBRv2 state
 */
static void bbr_enter_probe_rtt(struct bbrv2 *bbr)
{
	bbr->mode = BBR_PROBE_RTT;
	bbr->pacing_gain = BBR_UNIT;
	bbr->cwnd_gain = BBR_UNIT;
	bbr->probe_rtt_start = ktime_get_ns();
	tquic_dbg("bbrv2: state -> PROBE_RTT, min_rtt=%u\n",
		  (u32)bbr->min_rtt_us);
}

/**
 * bbr_update_model - Update BBR model from ack
 * @bbr: BBRv2 state
 * @acked: Bytes acked
 * @rtt_us: RTT sample
 */
static void bbr_update_model(struct bbrv2 *bbr, u64 acked, u64 rtt_us)
{
	u64 now = ktime_get_ns();
	u64 bw_sample;

	/* Update round */
	bbr->bytes_delivered += acked;
	bbr_update_round(bbr, bbr->bytes_delivered);

	/* Update bandwidth estimate */
	if (rtt_us > 0 && acked > 0) {
		bw_sample = (acked * USEC_PER_SEC) / rtt_us;
		bbr->bw = bbr_minmax_running_max(&bbr->bw_filter, now, bw_sample);
	}

	/* Update RTT estimate */
	if (rtt_us > 0) {
		bbr->rtt_us = rtt_us;
		bbr->min_rtt_us = bbr_minmax_running_min(&bbr->rtt_filter, now, rtt_us);
	}
}

/**
 * bbr_update_gains_cycle - Update pacing gains in ProbeBW
 * @bbr: BBRv2 state
 */
static void bbr_update_gains_cycle(struct bbrv2 *bbr)
{
	u64 now = ktime_get_ns();
	u64 cycle_elapsed;

	if (bbr->mode != BBR_PROBE_BW)
		return;

	cycle_elapsed = now - bbr->cycle_start;

	/* Advance cycle every RTT */
	if (cycle_elapsed >= bbr->min_rtt_us * 1000) {
		bbr->cycle_idx = (bbr->cycle_idx + 1) % BBR_GAIN_CYCLE_LEN;
		bbr->cycle_start = now;
	}

	bbr->pacing_gain = bbr_pacing_gain_cycle[bbr->cycle_idx];
}

/**
 * bbr_check_probe_rtt - Check if ProbeRTT is needed
 * @bbr: BBRv2 state
 */
static void bbr_check_probe_rtt(struct bbrv2 *bbr)
{
	u64 now = ktime_get_ns();

	/* Periodically probe RTT to maintain accurate min_rtt */
	if (bbr->mode != BBR_PROBE_RTT &&
	    (now - bbr->probe_rtt_done) > bbr_probe_rtt_interval_ms * NSEC_PER_MSEC) {
		bbr_enter_probe_rtt(bbr);
	}
}

/**
 * bbrv2_init - Initialize BBRv2 state
 * @path: Path to initialize CC for
 *
 * Return: Pointer to allocated bbrv2 state, or NULL on failure
 */
static void *bbrv2_init(struct tquic_path *path)
{
	struct bbrv2 *bbr;
	u32 initial_cwnd;

	bbr = kzalloc(sizeof(*bbr), GFP_KERNEL);
	if (!bbr)
		return NULL;

	bbr->path = path;

	/* Initialize filters with 10 RTT window (assume 100ms initially) */
	bbr_minmax_reset(&bbr->bw_filter, NSEC_PER_SEC);
	bbr_minmax_reset(&bbr->rtt_filter, 10ULL * NSEC_PER_SEC);

	/* Get initial cwnd from path stats or use default */
	initial_cwnd = 10 * bbr_get_mss(bbr);

	bbr->bw = 0;
	bbr->rtt_us = 0;
	bbr->min_rtt_us = UINT_MAX;
	bbr->cwnd = initial_cwnd;
	bbr->inflight_lo = UINT_MAX;
	bbr->inflight_hi = 0;
	bbr->prior_cwnd = 0;
	bbr->round_count = 0;
	bbr->next_round_delivered = 0;
	bbr->bytes_delivered = 0;
	bbr->full_bw = 0;
	bbr->full_bw_count = 0;
	bbr->full_bw_reached = false;
	bbr->in_loss_recovery = false;
	bbr->ecn_eligible = true;
	bbr->ecn_in_round = 0;
	bbr->loss_in_round = 0;
	bbr->probe_rtt_done = ktime_get_ns();

	/* Set parameters */
	bbr->params.probe_rtt_interval_ms = bbr_probe_rtt_interval_ms;
	bbr->params.ecn_factor = bbr_ecn_factor;
	bbr->params.loss_thresh = bbr_loss_thresh;
	bbr->params.beta = bbr_beta;
	bbr->params.headroom = bbr_headroom;

	/* Start in Startup mode */
	bbr_enter_startup(bbr);

	return bbr;
}

/**
 * bbrv2_release - Release BBRv2 state
 * @cong_data: BBRv2 state to release
 */
static void bbrv2_release(void *cong_data)
{
	kfree(cong_data);
}

/**
 * bbrv2_get_cwnd - Get congestion window
 * @cong_data: BBRv2 state
 *
 * Return: Cwnd in bytes
 */
static u64 bbrv2_get_cwnd(void *cong_data)
{
	struct bbrv2 *bbr = cong_data;

	if (!bbr)
		return 10 * BBR_DEFAULT_MSS;

	return bbr->cwnd;
}

/**
 * bbrv2_get_pacing_rate - Get pacing rate
 * @cong_data: BBRv2 state
 *
 * Return: Pacing rate in bytes/sec
 */
static u64 bbrv2_get_pacing_rate(void *cong_data)
{
	struct bbrv2 *bbr = cong_data;
	u64 rate;

	if (!bbr || bbr->bw == 0)
		return 0;

	rate = (bbr->bw * bbr->pacing_gain) >> BBR_SCALE;

	/* Apply headroom for BBRv2 */
	rate = (rate * (BBR_UNIT - bbr_headroom)) >> BBR_SCALE;

	return rate;
}

/**
 * bbrv2_on_ack - Process acknowledgment
 * @cong_data: BBRv2 state
 * @bytes_acked: Bytes acknowledged
 * @rtt_us: RTT sample
 */
static void bbrv2_on_ack(void *cong_data, u64 bytes_acked, u64 rtt_us)
{
	struct bbrv2 *bbr = cong_data;
	u32 mss;

	if (!bbr)
		return;

	mss = bbr_get_mss(bbr);

	/* Update model */
	bbr_update_model(bbr, bytes_acked, rtt_us);

	/* Mode-specific processing */
	switch (bbr->mode) {
	case BBR_STARTUP:
		bbr_check_full_bw_reached(bbr);
		if (bbr->full_bw_reached)
			bbr_enter_drain(bbr);
		break;

	case BBR_DRAIN:
		/* Exit Drain when inflight drops to BDP */
		/* Estimate inflight from cwnd (simplified) */
		if (bbr->cwnd <= bbr_bdp(bbr))
			bbr_enter_probe_bw(bbr);
		break;

	case BBR_PROBE_BW:
		bbr_update_gains_cycle(bbr);
		break;

	case BBR_PROBE_RTT:
		/* Exit ProbeRTT after duration */
		if (ktime_get_ns() - bbr->probe_rtt_start >=
		    BBR_PROBE_RTT_DURATION_MS * NSEC_PER_MSEC) {
			bbr->probe_rtt_done = ktime_get_ns();
			if (bbr->full_bw_reached)
				bbr_enter_probe_bw(bbr);
			else
				bbr_enter_startup(bbr);
		}
		break;
	}

	/* Check for ProbeRTT */
	bbr_check_probe_rtt(bbr);

	/* Update cwnd during ProbeRTT */
	if (bbr->mode == BBR_PROBE_RTT) {
		bbr->cwnd = BBR_PROBE_RTT_CWND * mss;
	} else {
		bbr_set_cwnd(bbr);
	}
}

/**
 * bbrv2_on_loss - Process loss event
 * @cong_data: BBRv2 state
 * @bytes_lost: Bytes lost
 */
static void bbrv2_on_loss(void *cong_data, u64 bytes_lost)
{
	struct bbrv2 *bbr = cong_data;
	u32 mss;

	if (!bbr)
		return;

	mss = bbr_get_mss(bbr);
	bbr->loss_in_round += bytes_lost / mss;

	if (bbr->in_loss_recovery)
		return;

	bbr->in_loss_recovery = true;
	bbr->prior_cwnd = bbr->cwnd;

	/* BBRv2: Set inflight_lo based on loss */
	bbr->inflight_lo = (bbr->cwnd * bbr->params.beta) >> BBR_SCALE;
	bbr->inflight_lo = max(bbr->inflight_lo, BBR_MIN_CWND * mss);

	/* Reduce cwnd */
	bbr->cwnd = bbr->inflight_lo;
	tquic_warn("bbrv2: loss recovery, cwnd %u -> %u\n",
		   bbr->prior_cwnd, bbr->cwnd);

	/* Exit Startup if we see loss */
	if (bbr->mode == BBR_STARTUP) {
		bbr->full_bw_reached = true;
		bbr_enter_drain(bbr);
	}
}

/**
 * bbrv2_on_ecn - Process ECN feedback
 * @cong_data: BBRv2 state
 * @ecn_ce_count: CE marked packets
 */
static void bbrv2_on_ecn(void *cong_data, u64 ecn_ce_count)
{
	struct bbrv2 *bbr = cong_data;
	u32 mss;

	if (!bbr || !bbr->ecn_eligible || ecn_ce_count == 0)
		return;

	mss = bbr_get_mss(bbr);
	bbr->ecn_in_round += ecn_ce_count;

	/* If ECN exceeds threshold, reduce inflight bounds */
	if (bbr->ecn_in_round > bbr->params.ecn_factor) {
		bbr->inflight_hi = max((bbr->inflight_hi * bbr->params.beta) >> BBR_SCALE,
				       (u32)(BBR_MIN_CWND * mss));
		bbr_set_cwnd(bbr);
	}
}

/**
 * bbrv2_on_persistent_congestion - Handle persistent congestion
 * @cong_data: BBRv2 state
 * @info: Persistent congestion info
 */
static void bbrv2_on_persistent_congestion(void *cong_data,
					   struct tquic_persistent_cong_info *info)
{
	struct bbrv2 *bbr = cong_data;
	u32 mss, old_cwnd;

	if (!bbr)
		return;

	mss = bbr_get_mss(bbr);
	old_cwnd = bbr->cwnd;

	/* Reset to minimum cwnd per RFC 9002 Section 7.6 */
	bbr->cwnd = 2 * mss;
	tquic_warn("bbrv2: persistent congestion, cwnd %u -> %u\n",
		   old_cwnd, bbr->cwnd);
	bbr->inflight_lo = bbr->cwnd;
	bbr->inflight_hi = 0;
	bbr->in_loss_recovery = false;

	/* Reset to startup */
	bbr->full_bw_reached = false;
	bbr->full_bw = 0;
	bbr->full_bw_count = 0;
	bbr_enter_startup(bbr);
}

/**
 * bbrv2_can_send - Check if we can send more data
 * @cong_data: BBRv2 state
 * @bytes: Bytes to send
 *
 * Return: true if can send
 */
static bool bbrv2_can_send(void *cong_data, u64 bytes)
{
	struct bbrv2 *bbr = cong_data;

	if (!bbr)
		return true;

	/* Simplified: assume we can send if cwnd allows */
	return bytes <= bbr->cwnd;
}

struct tquic_cong_ops bbrv2_cong_ops = {
	.name = "bbrv2",
	.owner = THIS_MODULE,
	.init = bbrv2_init,
	.release = bbrv2_release,
	.on_ack = bbrv2_on_ack,
	.on_loss = bbrv2_on_loss,
	.on_ecn = bbrv2_on_ecn,
	.on_persistent_congestion = bbrv2_on_persistent_congestion,
	.get_cwnd = bbrv2_get_cwnd,
	.get_pacing_rate = bbrv2_get_pacing_rate,
	.can_send = bbrv2_can_send,
};

int __init tquic_bbrv2_init(void)
{
	tquic_info("cc: bbrv2 algorithm registered\n");
	return tquic_register_cong(&bbrv2_cong_ops);
}

void __exit tquic_bbrv2_exit(void)
{
	tquic_unregister_cong(&bbrv2_cong_ops);
}

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TQUIC BBRv2 Congestion Control");
MODULE_AUTHOR("Linux Foundation");
