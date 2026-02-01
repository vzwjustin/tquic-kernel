/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: BBRv2 Congestion Control
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Implementation of BBRv2 (Bottleneck Bandwidth and Round-trip propagation time)
 * congestion control algorithm version 2 for QUIC.
 *
 * BBRv2 improvements over BBRv1:
 * - Better coexistence with loss-based congestion control
 * - ECN support for low-latency networks
 * - Improved fairness and reduced queuing delay
 * - Explicit loss tolerance via inflight_lo/inflight_hi
 */

#ifndef _TQUIC_BBRV2_H
#define _TQUIC_BBRV2_H

#include <linux/types.h>
#include <linux/ktime.h>
#include "../cong.h"

/* BBRv2 constants */
#define BBR_SCALE		8	/* Bandwidth scaling shift */
#define BBR_UNIT		(1 << BBR_SCALE)
#define BBR_MIN_CWND		4	/* Minimum cwnd in packets */
#define BBR_GAIN_CYCLE_LEN	8	/* Pacing gain cycle length */
#define BBR_HIGH_GAIN		((BBR_UNIT * 2885) / 1000)	/* 2.885x */
#define BBR_DRAIN_GAIN		((BBR_UNIT * 1000) / 2885)	/* 1/2.885 */
#define BBR_CWND_GAIN		((BBR_UNIT * 2))		/* 2x */
#define BBR_PROBE_RTT_CWND	4	/* Cwnd during ProbeRTT */
#define BBR_PROBE_RTT_DURATION_MS 200	/* ProbeRTT duration */

/* BBRv2-specific constants */
#define BBR2_LOSS_THRESH	2	/* Loss threshold (2%) */
#define BBR2_HEADROOM		((BBR_UNIT * 15) / 100)	/* 15% headroom */
#define BBR2_PROBE_BW_ROUNDS	8	/* Rounds per ProbeUP/DOWN cycle */
#define BBR2_ECN_THRESH		((BBR_UNIT * 50) / 100)	/* 50% ECN -> reduce */
#define BBR2_BETA		((BBR_UNIT * 70) / 100)	/* 0.7 beta for loss */
#define BBR2_INFLIGHT_LO_FACTOR ((BBR_UNIT * 100) / 100)
#define BBR2_INFLIGHT_HI_FACTOR ((BBR_UNIT * 115) / 100) /* 1.15x headroom */

/**
 * enum bbr_mode - BBRv2 operating mode
 * @BBR_STARTUP: Exponential search for bandwidth
 * @BBR_DRAIN: Drain excess queue from Startup
 * @BBR_PROBE_BW: Steady-state probing for bandwidth changes
 * @BBR_PROBE_RTT: Periodic RTT probing by draining queue
 */
enum bbr_mode {
	BBR_STARTUP,
	BBR_DRAIN,
	BBR_PROBE_BW,
	BBR_PROBE_RTT,
};

/**
 * enum bbr2_probe_bw_phase - BBRv2 ProbeBW sub-states
 * @BBR2_PROBE_BW_DOWN: Probing for lower bandwidth
 * @BBR2_PROBE_BW_CRUISE: Steady state, no probing
 * @BBR2_PROBE_BW_REFILL: Refilling pipe after ProbeDown
 * @BBR2_PROBE_BW_UP: Probing for higher bandwidth
 */
enum bbr2_probe_bw_phase {
	BBR2_PROBE_BW_DOWN,
	BBR2_PROBE_BW_CRUISE,
	BBR2_PROBE_BW_REFILL,
	BBR2_PROBE_BW_UP,
};

/**
 * struct bbr_params - BBRv2 tunable parameters
 * @probe_rtt_interval_ms: How often to probe RTT
 * @ecn_factor: ECN response aggressiveness
 * @loss_thresh: Loss threshold for reduction (percentage)
 * @beta: Multiplicative decrease factor
 * @headroom: Extra bandwidth headroom
 */
struct bbr_params {
	u32 probe_rtt_interval_ms;
	u32 ecn_factor;
	u32 loss_thresh;
	u32 beta;
	u32 headroom;
};

/**
 * struct minmax_sample - Sample for windowed min/max tracking
 * @time: Timestamp of sample
 * @value: Sample value
 */
struct minmax_sample {
	u64 time;
	u64 value;
};

/**
 * struct bbr_minmax - Windowed min/max filter
 * @samples: Ring buffer of samples
 * @window_len: Window length in time units
 */
struct bbr_minmax {
	struct minmax_sample samples[3];
	u64 window_len;
};

/**
 * struct bbrv2 - BBRv2 congestion control state
 * @base: Base congestion control structure
 * @mode: Current BBR mode
 * @probe_bw_phase: Current ProbeBW sub-state
 * @bw_filter: Windowed max bandwidth filter
 * @rtt_filter: Windowed min RTT filter
 * @bw: Current bandwidth estimate (bytes per second)
 * @rtt_us: Current RTT estimate (microseconds)
 * @min_rtt_us: Minimum observed RTT
 * @cwnd: Current congestion window
 * @cwnd_gain: Current cwnd multiplier
 * @pacing_gain: Current pacing rate multiplier
 * @inflight_lo: Lower bound on inflight (from loss signals)
 * @inflight_hi: Upper bound on inflight (target)
 * @prior_cwnd: Cwnd before reduction
 * @round_count: Number of round trips
 * @next_round_delivered: Delivered bytes to start next round
 * @cycle_idx: Current position in pacing gain cycle
 * @cycle_start: Start time of current cycle
 * @probe_rtt_start: Start time of ProbeRTT
 * @probe_rtt_done: ProbeRTT completion timestamp
 * @round_start: Is this the start of a round?
 * @idle_restart: Restarting from idle?
 * @full_bw: Bandwidth at full pipe detection
 * @full_bw_count: Rounds without bandwidth increase
 * @full_bw_reached: Has startup reached full bandwidth?
 * @in_loss_recovery: Currently in loss recovery
 * @ecn_eligible: Connection supports ECN
 * @ecn_in_round: ECN marks seen in current round
 * @loss_in_round: Losses in current round
 * @params: Tunable parameters
 */
struct bbrv2 {
	struct tquic_cong base;
	enum bbr_mode mode;
	enum bbr2_probe_bw_phase probe_bw_phase;
	struct bbr_minmax bw_filter;
	struct bbr_minmax rtt_filter;
	u64 bw;
	u32 rtt_us;
	u32 min_rtt_us;
	u32 cwnd;
	u32 cwnd_gain;
	u32 pacing_gain;
	u32 inflight_lo;
	u32 inflight_hi;
	u32 prior_cwnd;
	u64 round_count;
	u64 next_round_delivered;
	u32 cycle_idx;
	u64 cycle_start;
	u64 probe_rtt_start;
	u64 probe_rtt_done;
	bool round_start;
	bool idle_restart;
	u64 full_bw;
	u32 full_bw_count;
	bool full_bw_reached;
	bool in_loss_recovery;
	bool ecn_eligible;
	u32 ecn_in_round;
	u32 loss_in_round;
	struct bbr_params params;
};

/* BBRv2 congestion control operations */
extern const struct tquic_cong_ops bbrv2_cong_ops;

/* Module init/exit */
int __init tquic_bbrv2_init(void);
void __exit tquic_bbrv2_exit(void);

#endif /* _TQUIC_BBRV2_H */
