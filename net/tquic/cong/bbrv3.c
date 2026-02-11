// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC BBRv3 Congestion Control
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * BBRv3 implementation for QUIC. This is the latest iteration of BBR
 * with improved ECN handling, better fairness, and enhanced stability.
 *
 * Key improvements over BBRv2:
 * - More responsive to ECN signals (L4S compatible)
 * - Improved Startup exit for better competing flow fairness
 * - Refined bandwidth probing with variable duration
 * - Better handling of aggregation and ACK delays
 * - Enhanced RTT probing with less queue drain
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/random.h>

#include "bbrv3.h"
#include "../protocol.h"
#include "../tquic_debug.h"

/* Default MTU for calculations */
#define BBR3_DEFAULT_MSS	1200

/* Module parameters */
static u32 bbr3_probe_rtt_interval_sec = BBR3_PROBE_RTT_INTERVAL_SEC;
static u32 bbr3_loss_thresh = BBR3_LOSS_THRESH_PERCENT;
static u32 bbr3_ecn_thresh = BBR3_ECN_THRESH_PERCENT;
static u32 bbr3_beta = BBR3_BETA;
static u32 bbr3_headroom = BBR3_HEADROOM;
static bool bbr3_ecn_aware = true;

module_param(bbr3_probe_rtt_interval_sec, uint, 0644);
MODULE_PARM_DESC(bbr3_probe_rtt_interval_sec, "ProbeRTT interval (seconds)");

module_param(bbr3_ecn_aware, bool, 0644);
MODULE_PARM_DESC(bbr3_ecn_aware, "Enable ECN awareness for L4S");

/*
 * =============================================================================
 * Windowed Filter Operations
 * =============================================================================
 */

static void bbrv3_minmax_reset(struct bbrv3_minmax *f, u64 window_len)
{
	memset(f->samples, 0, sizeof(f->samples));
	f->window_len = window_len;
}

static u64 bbrv3_minmax_running_max(struct bbrv3_minmax *f, u64 now, u64 value)
{
	struct bbrv3_minmax_sample *s = f->samples;
	u64 dt = now - s[0].time;

	if (value >= s[0].value || dt > f->window_len) {
		s[0].time = now;
		s[0].value = value;
		s[1] = s[0];
		s[2] = s[0];
		return value;
	}

	if (value >= s[1].value) {
		s[1].time = now;
		s[1].value = value;
		s[2] = s[1];
	} else if (value >= s[2].value) {
		s[2].time = now;
		s[2].value = value;
	}

	dt = now - s[1].time;
	if (dt > f->window_len / 4) {
		s[0] = s[1];
		s[1] = s[2];
		s[2].time = now;
		s[2].value = value;
	}

	return s[0].value;
}

static u64 bbrv3_minmax_running_min(struct bbrv3_minmax *f, u64 now, u64 value)
{
	struct bbrv3_minmax_sample *s = f->samples;
	u64 dt = now - s[0].time;

	if (value <= s[0].value || dt > f->window_len) {
		s[0].time = now;
		s[0].value = value;
		s[1] = s[0];
		s[2] = s[0];
		return value;
	}

	if (value <= s[1].value) {
		s[1].time = now;
		s[1].value = value;
		s[2] = s[1];
	} else if (value <= s[2].value) {
		s[2].time = now;
		s[2].value = value;
	}

	dt = now - s[1].time;
	if (dt > f->window_len / 4) {
		s[0] = s[1];
		s[1] = s[2];
		s[2].time = now;
		s[2].value = value;
	}

	return s[0].value;
}

/*
 * =============================================================================
 * Helper Functions
 * =============================================================================
 */

static u32 bbrv3_get_mss(struct bbrv3 *bbr)
{
	if (bbr->path && bbr->path->mtu > 0)
		return bbr->path->mtu;
	return BBR3_DEFAULT_MSS;
}

static u64 bbrv3_bdp(struct bbrv3 *bbr)
{
	if (bbr->bw == 0 || bbr->min_rtt_us == 0)
		return BBR3_MIN_CWND * bbrv3_get_mss(bbr);
	return (bbr->bw * bbr->min_rtt_us) / USEC_PER_SEC;
}

static u64 bbrv3_inflight(struct bbrv3 *bbr, u32 gain)
{
	u64 inflight = bbrv3_bdp(bbr);
	u32 mss = bbrv3_get_mss(bbr);

	inflight = (inflight * gain) >> BBR3_SCALE;

	/* Add extra acked estimate if enabled */
	if (bbr->params.use_extra_acked) {
		u64 extra = max(bbr->extra_acked[0], bbr->extra_acked[1]);
		inflight += extra * mss;
	}

	return max_t(u64, inflight, BBR3_MIN_CWND * mss);
}

static u64 bbrv3_pacing_rate(struct bbrv3 *bbr)
{
	u64 rate;

	if (bbr->bw == 0)
		return 0;

	rate = bbr->bw;

	/* Apply pacing gain */
	rate = (rate * bbr->pacing_gain) >> BBR3_SCALE;

	/* Apply headroom */
	rate = (rate * (BBR3_UNIT - bbr->params.headroom)) >> BBR3_SCALE;

	return rate;
}

/*
 * =============================================================================
 * Round Trip Tracking
 * =============================================================================
 */

static void bbrv3_update_round(struct bbrv3 *bbr, u64 delivered)
{
	if (delivered >= bbr->next_round_delivered) {
		bbr->round_start = true;
		bbr->round_count++;
		bbr->next_round_delivered = bbr->bytes_delivered;
		bbr->round_start_delivered = delivered;

		/* Reset per-round counters */
		bbr->loss_in_round = 0;
		bbr->ecn_in_round = 0;
	} else {
		bbr->round_start = false;
	}
}

/*
 * =============================================================================
 * Bandwidth Estimation
 * =============================================================================
 */

static void bbrv3_update_bw(struct bbrv3 *bbr, u64 acked, u64 rtt_us)
{
	u64 now = ktime_get_ns();
	u64 bw_sample;
	u64 interval_ns, delivered_delta, interval_us;

	if (acked == 0)
		return;

	/*
	 * Compute delivery rate as bytes_delivered / delivery_interval.
	 * Note: bytes_delivered is already updated by the caller.
	 * This replaces the incorrect bytes_acked/rtt calculation which
	 * overestimates BW when ACKs are coalesced.
	 */
	interval_ns = now - bbr->prior_delivered_time_ns;
	delivered_delta = bbr->bytes_delivered - bbr->prior_delivered;

	if (interval_ns > 0 && delivered_delta > 0) {
		interval_us = interval_ns / 1000;
		if (interval_us > 0) {
			bw_sample = delivered_delta * USEC_PER_SEC /
				    interval_us;

			/* Update max bandwidth filter */
			bbr->bw = bbrv3_minmax_running_max(&bbr->bw_filter,
							   now, bw_sample);

			/* Track max observed */
			if (bw_sample > bbr->max_bw)
				bbr->max_bw = bw_sample;
		}
	}

	bbr->prior_delivered = bbr->bytes_delivered;
	bbr->prior_delivered_time_ns = now;
}

static void bbrv3_update_rtt(struct bbrv3 *bbr, u64 rtt_us)
{
	u64 now = ktime_get_ns();

	if (rtt_us == 0)
		return;

	bbr->rtt_us = rtt_us;
	bbr->min_rtt_us = bbrv3_minmax_running_min(&bbr->rtt_filter, now, rtt_us);
	bbr->min_rtt_stamp = ktime_get();
}

/*
 * =============================================================================
 * Startup Phase
 * =============================================================================
 */

static void bbrv3_enter_startup(struct bbrv3 *bbr)
{
	bbr->mode = BBR3_STARTUP;
	bbr->pacing_gain = BBR3_STARTUP_PACING_GAIN;
	bbr->cwnd_gain = BBR3_STARTUP_CWND_GAIN;
	tquic_dbg("bbrv3: state -> STARTUP\n");
}

static void bbrv3_check_startup_done(struct bbrv3 *bbr)
{
	u64 bw_thresh;

	if (bbr->full_bw_reached || !bbr->round_start)
		return;

	/* BBRv3: Check for 25% bandwidth growth */
	bw_thresh = (bbr->full_bw * 125) / 100;

	if (bbr->bw >= bw_thresh) {
		bbr->full_bw = bbr->bw;
		bbr->full_bw_count = 0;
		return;
	}

	/* Three rounds without growth = full pipe */
	if (++bbr->full_bw_count >= 3) {
		bbr->full_bw_reached = true;
		bbr->full_bw_now = true;
	}
}

static void bbrv3_check_startup_high_loss(struct bbrv3 *bbr)
{
	u64 loss_percent;

	if (!bbr->round_start || bbr->bytes_delivered == 0)
		return;

	/* Check for excessive loss in Startup */
	loss_percent = (bbr->loss_in_round * 100) /
		       max_t(u64, 1, bbr->round_start_delivered);

	if (loss_percent > bbr->params.loss_thresh_percent) {
		bbr->full_bw_reached = true;
		bbr->full_bw_now = true;
	}
}

/*
 * =============================================================================
 * Drain Phase
 * =============================================================================
 */

static void bbrv3_enter_drain(struct bbrv3 *bbr)
{
	bbr->mode = BBR3_DRAIN;
	bbr->pacing_gain = BBR3_DRAIN_PACING_GAIN;
	bbr->cwnd_gain = BBR3_STARTUP_CWND_GAIN;
	tquic_dbg("bbrv3: state -> DRAIN, cwnd=%llu\n", bbr->cwnd);
}

static void bbrv3_check_drain_done(struct bbrv3 *bbr)
{
	/* Exit drain when inflight drops to BDP */
	if (bbr->cwnd <= bbrv3_bdp(bbr))
		return;

	/* Would check actual inflight here in real implementation */
}

/*
 * =============================================================================
 * ProbeBW Phase
 * =============================================================================
 */

static void bbrv3_enter_probe_bw(struct bbrv3 *bbr)
{
	bbr->mode = BBR3_PROBE_BW;
	bbr->probe_bw_phase = BBR3_BW_PROBE_CRUISE;
	bbr->pacing_gain = BBR3_UNIT;
	bbr->cwnd_gain = BBR3_PROBE_BW_CWND_GAIN;
	bbr->cycle_start = ktime_get();
	bbr->cycle_count = 0;

	/* Random offset into cycle for fairness */
	bbr->probe_up_rounds = get_random_u32() % 4;
	tquic_dbg("bbrv3: state -> PROBE_BW, bw=%llu cwnd=%llu\n",
		  bbr->bw, bbr->cwnd);
}

static void bbrv3_advance_probe_bw_cycle(struct bbrv3 *bbr)
{
	u64 now_ns = ktime_get_ns();
	u64 cycle_ns = bbr->min_rtt_us * 1000;  /* One RTT per phase minimum */

	if (now_ns - ktime_to_ns(bbr->cycle_start) < cycle_ns)
		return;

	switch (bbr->probe_bw_phase) {
	case BBR3_BW_PROBE_CRUISE:
		if (bbr->cycle_count >= bbr->probe_up_rounds) {
			/* Time to probe up */
			bbr->probe_bw_phase = BBR3_BW_PROBE_REFILL;
			bbr->pacing_gain = BBR3_PROBE_BW_REFILL_GAIN;
			bbr->cycle_count = 0;
		} else {
			bbr->cycle_count++;
		}
		break;

	case BBR3_BW_PROBE_REFILL:
		bbr->probe_bw_phase = BBR3_BW_PROBE_UP;
		bbr->pacing_gain = BBR3_PROBE_BW_PACING_UP;
		bbr->probe_up_acked = false;
		bbr->bw_probe_samples = 0;
		break;

	case BBR3_BW_PROBE_UP:
		/* BBRv3: Extended probing duration */
		if (bbr->probe_up_acked && bbr->bw_probe_samples >= 2) {
			bbr->probe_bw_phase = BBR3_BW_PROBE_DOWN;
			bbr->pacing_gain = BBR3_PROBE_BW_PACING_DOWN;
		}
		break;

	case BBR3_BW_PROBE_DOWN:
		bbr->probe_bw_phase = BBR3_BW_PROBE_CRUISE;
		bbr->pacing_gain = BBR3_PROBE_BW_CRUISE_GAIN;
		bbr->probe_up_rounds = 1 + (get_random_u32() % 4);  /* 1-4 rounds */
		bbr->cycle_count = 0;
		break;
	}

	bbr->cycle_start = ktime_get();
}

/*
 * =============================================================================
 * ProbeRTT Phase
 * =============================================================================
 */

static void bbrv3_enter_probe_rtt(struct bbrv3 *bbr)
{
	bbr->mode = BBR3_PROBE_RTT;
	bbr->pacing_gain = BBR3_UNIT;
	bbr->cwnd_gain = BBR3_UNIT;
	bbr->probe_rtt_start = ktime_get();
	bbr->probe_rtt_round_done = false;
	tquic_dbg("bbrv3: state -> PROBE_RTT, min_rtt=%u\n",
		  (u32)bbr->min_rtt_us);
}

static void bbrv3_check_probe_rtt(struct bbrv3 *bbr)
{
	ktime_t now = ktime_get();

	if (bbr->mode == BBR3_PROBE_RTT) {
		/* Check if ProbeRTT duration complete */
		if (ktime_ms_delta(now, bbr->probe_rtt_start) >=
		    BBR3_PROBE_RTT_DURATION_MS) {
			bbr->probe_rtt_done_time = now;

			if (bbr->full_bw_reached)
				bbrv3_enter_probe_bw(bbr);
			else
				bbrv3_enter_startup(bbr);
		}
		return;
	}

	/* Check if time for ProbeRTT */
	if (ktime_to_ms(now) - ktime_to_ms(bbr->probe_rtt_done_time) >
	    bbr->params.probe_rtt_interval_sec * MSEC_PER_SEC) {
		bbrv3_enter_probe_rtt(bbr);
	}
}

/*
 * =============================================================================
 * ECN Handling (L4S Support)
 * =============================================================================
 */

static void bbrv3_handle_ecn(struct bbrv3 *bbr, u64 ce_count)
{
	u64 ce_ratio;
	u32 mss = bbrv3_get_mss(bbr);

	if (!bbr->params.ecn_aware || ce_count == 0)
		return;

	bbr->ecn_in_round += ce_count;

	/* Calculate ECN marking ratio -- guard against overflow and div-by-zero */
	if (bbr->ecn_ect_count > 0) {
		u64 total = bbr->ecn_ect_count + ce_count;

		if (unlikely(total < bbr->ecn_ect_count))
			total = U64_MAX; /* overflow */
		ce_ratio = div64_u64(ce_count * 100, total);
	} else {
		ce_ratio = 100;
	}

	/* BBRv3: More responsive ECN with DCTCP-style alpha update */
	if (ce_ratio > 0) {
		/* EWMA update of alpha */
		u64 new_alpha = (ce_count << BBR3_SCALE) /
				max_t(u64, 1, bbr->ecn_ect_count + ce_count);
		bbr->ecn_alpha = (bbr->ecn_alpha + new_alpha) / 2;
	}

	/* Reduce cwnd based on ECN if above threshold */
	if (ce_ratio >= bbr->params.ecn_thresh_percent) {
		u64 reduction = (bbr->cwnd * bbr->ecn_alpha) >> BBR3_SCALE;
		bbr->cwnd = max_t(u64, bbr->cwnd - reduction,
				  BBR3_MIN_CWND * mss);
		bbr->inflight_hi = bbr->cwnd;
	}
}

/*
 * =============================================================================
 * Loss Handling
 * =============================================================================
 */

static void bbrv3_handle_loss(struct bbrv3 *bbr, u64 bytes_lost)
{
	u32 mss = bbrv3_get_mss(bbr);

	if (bytes_lost == 0)
		return;

	bbr->loss_in_round += bytes_lost / mss;
	bbr->bytes_lost += bytes_lost;

	if (bbr->in_loss_recovery)
		return;

	bbr->in_loss_recovery = true;
	bbr->prior_cwnd = bbr->cwnd;
	tquic_warn("bbrv3: loss event, cwnd=%llu bytes_lost=%llu\n",
		   bbr->cwnd, bytes_lost);

	/* BBRv3: Apply beta multiplier on loss */
	bbr->inflight_lo = (bbr->cwnd * bbr->params.beta) >> BBR3_SCALE;
	bbr->inflight_lo = max_t(u32, bbr->inflight_lo, BBR3_MIN_CWND * mss);

	/* Update cwnd */
	bbr->cwnd = bbr->inflight_lo;

	/* Update bandwidth lower bound */
	bbr->bw_lo = (bbr->bw * bbr->params.beta) >> BBR3_SCALE;

	/* Exit Startup on loss if not already done */
	if (bbr->mode == BBR3_STARTUP && !bbr->full_bw_reached) {
		bbr->full_bw_reached = true;
		bbrv3_enter_drain(bbr);
	}
}

/*
 * =============================================================================
 * Cwnd Computation
 * =============================================================================
 */

static void bbrv3_set_cwnd(struct bbrv3 *bbr)
{
	u64 target;
	u32 mss = bbrv3_get_mss(bbr);

	/* Compute target based on BDP and gain */
	target = bbrv3_inflight(bbr, bbr->cwnd_gain);

	/* Apply bounds from loss/ECN response */
	if (bbr->inflight_lo != UINT_MAX)
		target = min_t(u64, target, bbr->inflight_lo);
	if (bbr->inflight_hi != 0)
		target = min_t(u64, target, bbr->inflight_hi);

	/* ProbeRTT: use minimum cwnd */
	if (bbr->mode == BBR3_PROBE_RTT)
		target = BBR3_PROBE_RTT_CWND * mss;

	/* Don't increase during loss recovery */
	if (bbr->in_loss_recovery)
		target = min_t(u64, target, bbr->prior_cwnd);

	/* Ensure minimum cwnd */
	bbr->cwnd = max_t(u64, target, BBR3_MIN_CWND * mss);
}

/*
 * =============================================================================
 * Congestion Control Operations
 * =============================================================================
 */

static void *bbrv3_init(struct tquic_path *path)
{
	struct bbrv3 *bbr;
	u32 mss;

	bbr = kzalloc(sizeof(*bbr), GFP_KERNEL);
	if (!bbr)
		return NULL;

	bbr->path = path;
	mss = bbrv3_get_mss(bbr);

	/* Initialize filters */
	bbrv3_minmax_reset(&bbr->bw_filter, 2 * NSEC_PER_SEC);
	bbrv3_minmax_reset(&bbr->rtt_filter, 10ULL * NSEC_PER_SEC);

	/* Initialize state */
	bbr->bw = 0;
	bbr->max_bw = 0;
	bbr->bw_lo = UINT_MAX;
	bbr->bw_hi = 0;
	bbr->min_rtt_us = UINT_MAX;
	bbr->rtt_us = 0;
	bbr->cwnd = 10 * mss;  /* Initial window */
	bbr->inflight_lo = UINT_MAX;
	bbr->inflight_hi = 0;
	bbr->round_count = 0;
	bbr->full_bw = 0;
	bbr->full_bw_count = 0;
	bbr->full_bw_reached = false;
	bbr->in_loss_recovery = false;
	bbr->loss_round_delivered = 0;
	bbr->ecn_alpha = BBR3_ECN_ALPHA_INIT;
	bbr->ecn_eligible = true;
	bbr->probe_rtt_done_time = ktime_get();

	/* Set tunable parameters */
	bbr->params.probe_rtt_interval_sec = bbr3_probe_rtt_interval_sec;
	bbr->params.loss_thresh_percent = bbr3_loss_thresh;
	bbr->params.ecn_thresh_percent = bbr3_ecn_thresh;
	bbr->params.ecn_alpha_gain = BBR3_UNIT / 16;
	bbr->params.beta = bbr3_beta;
	bbr->params.headroom = bbr3_headroom;
	bbr->params.ecn_aware = bbr3_ecn_aware;
	bbr->params.use_extra_acked = true;

	/* Start in Startup mode */
	bbrv3_enter_startup(bbr);

	return bbr;
}

static void bbrv3_release(void *cong_data)
{
	kfree(cong_data);
}

static u64 bbrv3_get_cwnd(void *cong_data)
{
	struct bbrv3 *bbr = cong_data;

	if (!bbr)
		return 10 * BBR3_DEFAULT_MSS;

	return bbr->cwnd;
}

static u64 bbrv3_get_pacing_rate(void *cong_data)
{
	struct bbrv3 *bbr = cong_data;

	if (!bbr)
		return 0;

	return bbrv3_pacing_rate(bbr);
}

static void bbrv3_on_ack(void *cong_data, u64 bytes_acked, u64 rtt_us)
{
	struct bbrv3 *bbr = cong_data;

	if (!bbr)
		return;

	/* Update delivery tracking */
	bbr->bytes_delivered += bytes_acked;
	bbrv3_update_round(bbr, bbr->bytes_delivered);

	/* Update estimates */
	bbrv3_update_bw(bbr, bytes_acked, rtt_us);
	bbrv3_update_rtt(bbr, rtt_us);

	/* Exit loss recovery if acked past recovery point */
	if (bbr->in_loss_recovery &&
	    bbr->bytes_delivered >= bbr->loss_round_delivered) {
		bbr->in_loss_recovery = false;
	}

	/* Mode-specific processing */
	switch (bbr->mode) {
	case BBR3_STARTUP:
		bbrv3_check_startup_done(bbr);
		bbrv3_check_startup_high_loss(bbr);
		if (bbr->full_bw_reached)
			bbrv3_enter_drain(bbr);
		break;

	case BBR3_DRAIN:
		bbrv3_check_drain_done(bbr);
		/* Check bytes-in-flight, not cwnd, per BBRv3 spec */
		if (bbr->path && bbr->path->cc.bytes_in_flight <= bbrv3_bdp(bbr))
			bbrv3_enter_probe_bw(bbr);
		break;

	case BBR3_PROBE_BW:
		bbrv3_advance_probe_bw_cycle(bbr);
		if (bbr->probe_bw_phase == BBR3_BW_PROBE_UP)
			bbr->probe_up_acked = true;
		break;

	case BBR3_PROBE_RTT:
		/* Handled in check_probe_rtt */
		break;
	}

	/* Check for ProbeRTT */
	bbrv3_check_probe_rtt(bbr);

	/* Update cwnd */
	bbrv3_set_cwnd(bbr);
}

static void bbrv3_on_loss(void *cong_data, u64 bytes_lost)
{
	struct bbrv3 *bbr = cong_data;

	if (!bbr)
		return;

	bbrv3_handle_loss(bbr, bytes_lost);
}

static void bbrv3_on_ecn(void *cong_data, u64 ecn_ce_count)
{
	struct bbrv3 *bbr = cong_data;

	if (!bbr)
		return;

	bbrv3_handle_ecn(bbr, ecn_ce_count);
}

static void bbrv3_on_persistent_congestion(void *cong_data,
					   struct tquic_persistent_cong_info *info)
{
	struct bbrv3 *bbr = cong_data;
	u32 mss;

	if (!bbr)
		return;

	mss = bbrv3_get_mss(bbr);

	/* Reset to minimum state per RFC 9002 */
	bbr->cwnd = 2 * mss;
	bbr->inflight_lo = bbr->cwnd;
	bbr->inflight_hi = 0;
	bbr->bw_lo = 0;
	bbr->bw_hi = 0;
	bbr->in_loss_recovery = false;

	/* Restart from Startup */
	bbr->full_bw_reached = false;
	bbr->full_bw = 0;
	bbr->full_bw_count = 0;
	bbrv3_enter_startup(bbr);

	tquic_warn("bbrv3: persistent congestion, reset to startup, cwnd=%llu\n",
		   bbr->cwnd);
}

static bool bbrv3_can_send(void *cong_data, u64 bytes)
{
	struct bbrv3 *bbr = cong_data;
	u64 inflight;

	if (!bbr)
		return true;

	/* Check bytes-in-flight + new packet against cwnd */
	inflight = bbr->path ? bbr->path->cc.bytes_in_flight : 0;
	return (inflight + bytes) <= bbr->cwnd;
}

struct tquic_cong_ops bbrv3_cong_ops = {
	.name = "bbrv3",
	.owner = THIS_MODULE,
	.init = bbrv3_init,
	.release = bbrv3_release,
	.on_ack = bbrv3_on_ack,
	.on_loss = bbrv3_on_loss,
	.on_ecn = bbrv3_on_ecn,
	.on_persistent_congestion = bbrv3_on_persistent_congestion,
	.get_cwnd = bbrv3_get_cwnd,
	.get_pacing_rate = bbrv3_get_pacing_rate,
	.can_send = bbrv3_can_send,
};

int __init tquic_bbrv3_init(void)
{
	tquic_info("cc: bbrv3 algorithm registered\n");
	return tquic_register_cong(&bbrv3_cong_ops);
}

void __exit tquic_bbrv3_exit(void)
{
	tquic_unregister_cong(&bbrv3_cong_ops);
}

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TQUIC BBRv3 Congestion Control");
MODULE_AUTHOR("Linux Foundation");
