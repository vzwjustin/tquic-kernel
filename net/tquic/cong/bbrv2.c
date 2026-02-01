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
	struct minmax_sample *s = filter->samples;
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
	struct minmax_sample *s = filter->samples;
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

	inflight = bbr_bdp(bbr);
	inflight = (inflight * gain) >> BBR_SCALE;

	return max((u32)inflight, (u32)(BBR_MIN_CWND * bbr->base.max_datagram_size));
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
 * bbr_set_pacing_rate - Set the pacing rate
 * @bbr: BBRv2 state
 */
static void bbr_set_pacing_rate(struct bbrv2 *bbr)
{
	u64 rate;

	rate = (bbr->bw * bbr->pacing_gain) >> BBR_SCALE;

	/* Apply headroom for BBRv2 */
	rate = (rate * (BBR_UNIT - bbr_headroom)) >> BBR_SCALE;

	bbr->base.pacing_rate = rate;
}

/**
 * bbr_set_cwnd - Set the congestion window
 * @bbr: BBRv2 state
 */
static void bbr_set_cwnd(struct bbrv2 *bbr)
{
	u32 target;
	u32 mss = bbr->base.max_datagram_size;

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
	bbr->mode = BBR_STARTUP;
	bbr->pacing_gain = BBR_HIGH_GAIN;
	bbr->cwnd_gain = BBR_HIGH_GAIN;
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
}

/**
 * bbr_update_model - Update BBR model from ack
 * @bbr: BBRv2 state
 * @acked: Bytes acked
 * @rtt_us: RTT sample
 * @delivered: Total delivered bytes
 */
static void bbr_update_model(struct bbrv2 *bbr, u64 acked, u64 rtt_us, u64 delivered)
{
	u64 now = ktime_get_ns();
	u64 bw_sample;

	/* Update round */
	bbr_update_round(bbr, delivered);

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
 * @cong: Base congestion control structure
 *
 * Return: 0 on success
 */
static int bbrv2_init(struct tquic_cong *cong)
{
	struct bbrv2 *bbr = container_of(cong, struct bbrv2, base);

	/* Initialize filters with 10 RTT window (assume 100ms initially) */
	bbr_minmax_reset(&bbr->bw_filter, NSEC_PER_SEC);
	bbr_minmax_reset(&bbr->rtt_filter, 10 * NSEC_PER_SEC);

	bbr->bw = 0;
	bbr->rtt_us = 0;
	bbr->min_rtt_us = UINT_MAX;
	bbr->cwnd = cong->initial_window;
	bbr->inflight_lo = UINT_MAX;
	bbr->inflight_hi = 0;
	bbr->prior_cwnd = 0;
	bbr->round_count = 0;
	bbr->next_round_delivered = 0;
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

	return 0;
}

/**
 * bbrv2_release - Release BBRv2 state
 * @cong: Base congestion control structure
 */
static void bbrv2_release(struct tquic_cong *cong)
{
	/* No dynamic allocations */
}

/**
 * bbrv2_get_cwnd - Get congestion window
 * @cong: Base congestion control structure
 *
 * Return: Cwnd in bytes
 */
static u32 bbrv2_get_cwnd(struct tquic_cong *cong)
{
	struct bbrv2 *bbr = container_of(cong, struct bbrv2, base);

	return bbr->cwnd;
}

/**
 * bbrv2_on_ack - Process acknowledgment
 * @cong: Base congestion control structure
 * @acked: Bytes acknowledged
 * @rtt_us: RTT sample
 */
static void bbrv2_on_ack(struct tquic_cong *cong, u64 acked, u64 rtt_us)
{
	struct bbrv2 *bbr = container_of(cong, struct bbrv2, base);
	u32 mss = bbr->base.max_datagram_size;

	/* Update model */
	bbr_update_model(bbr, acked, rtt_us, cong->bytes_delivered);

	/* Mode-specific processing */
	switch (bbr->mode) {
	case BBR_STARTUP:
		bbr_check_full_bw_reached(bbr);
		if (bbr->full_bw_reached)
			bbr_enter_drain(bbr);
		break;

	case BBR_DRAIN:
		/* Exit Drain when inflight drops to BDP */
		if (cong->bytes_in_flight <= bbr_bdp(bbr))
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

	bbr_set_pacing_rate(bbr);
}

/**
 * bbrv2_on_ecn - Process ECN feedback
 * @cong: Base congestion control structure
 * @ce_count: CE marked packets
 * @acked_bytes: Bytes acknowledged
 */
static void bbrv2_on_ecn(struct tquic_cong *cong, u64 ce_count, u64 acked_bytes)
{
	struct bbrv2 *bbr = container_of(cong, struct bbrv2, base);
	u32 ecn_fraction;

	if (!bbr->ecn_eligible || ce_count == 0)
		return;

	bbr->ecn_in_round += ce_count;

	/* Calculate ECN fraction */
	if (acked_bytes > 0) {
		ecn_fraction = (ce_count * bbr->base.max_datagram_size * BBR_UNIT) /
			       acked_bytes;

		/* If ECN fraction exceeds threshold, reduce inflight bounds */
		if (ecn_fraction > bbr->params.ecn_factor) {
			bbr->inflight_hi = max((bbr->inflight_hi * bbr->params.beta) >> BBR_SCALE,
					       (u32)(BBR_MIN_CWND * bbr->base.max_datagram_size));
			bbr_set_cwnd(bbr);
		}
	}
}

/**
 * bbrv2_on_loss - Process loss event
 * @cong: Base congestion control structure
 * @lost_bytes: Bytes lost
 */
static void bbrv2_on_loss(struct tquic_cong *cong, u64 lost_bytes)
{
	struct bbrv2 *bbr = container_of(cong, struct bbrv2, base);
	u32 mss = bbr->base.max_datagram_size;

	bbr->loss_in_round += lost_bytes / mss;

	if (bbr->in_loss_recovery)
		return;

	bbr->in_loss_recovery = true;
	bbr->prior_cwnd = bbr->cwnd;

	/* BBRv2: Set inflight_lo based on loss */
	bbr->inflight_lo = (bbr->cwnd * bbr->params.beta) >> BBR_SCALE;
	bbr->inflight_lo = max(bbr->inflight_lo, BBR_MIN_CWND * mss);

	/* Reduce cwnd */
	bbr->cwnd = bbr->inflight_lo;

	/* Exit Startup if we see loss */
	if (bbr->mode == BBR_STARTUP) {
		bbr->full_bw_reached = true;
		bbr_enter_drain(bbr);
	}
}

/**
 * bbrv2_on_recovery_exit - Exit loss recovery
 * @cong: Base congestion control structure
 */
static void bbrv2_on_recovery_exit(struct tquic_cong *cong)
{
	struct bbrv2 *bbr = container_of(cong, struct bbrv2, base);

	bbr->in_loss_recovery = false;

	/* Restore cwnd but respect inflight bounds */
	bbr_set_cwnd(bbr);
}

/**
 * bbrv2_in_slow_start - Check if in slow start
 * @cong: Base congestion control structure
 *
 * Return: true if in Startup mode
 */
static bool bbrv2_in_slow_start(struct tquic_cong *cong)
{
	struct bbrv2 *bbr = container_of(cong, struct bbrv2, base);

	return bbr->mode == BBR_STARTUP;
}

/**
 * bbrv2_in_recovery - Check if in recovery
 * @cong: Base congestion control structure
 *
 * Return: true if in loss recovery
 */
static bool bbrv2_in_recovery(struct tquic_cong *cong)
{
	struct bbrv2 *bbr = container_of(cong, struct bbrv2, base);

	return bbr->in_loss_recovery;
}

const struct tquic_cong_ops bbrv2_cong_ops = {
	.name = "bbrv2",
	.init = bbrv2_init,
	.release = bbrv2_release,
	.get_cwnd = bbrv2_get_cwnd,
	.on_ack = bbrv2_on_ack,
	.on_ecn = bbrv2_on_ecn,
	.on_loss = bbrv2_on_loss,
	.on_recovery_exit = bbrv2_on_recovery_exit,
	.in_slow_start = bbrv2_in_slow_start,
	.in_recovery = bbrv2_in_recovery,
};
EXPORT_SYMBOL_GPL(bbrv2_cong_ops);

int __init tquic_bbrv2_init(void)
{
	pr_info("tquic: BBRv2 congestion control initialized\n");
	return tquic_cong_register(&bbrv2_cong_ops);
}

void __exit tquic_bbrv2_exit(void)
{
	tquic_cong_unregister(&bbrv2_cong_ops);
}

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TQUIC BBRv2 Congestion Control");
MODULE_AUTHOR("Linux Foundation");
