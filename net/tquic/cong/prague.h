/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: Prague Congestion Control
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Implementation of Prague congestion control for L4S networks.
 * Prague is designed to coexist with classic ECN traffic while
 * achieving low latency in L4S (DUALPI2/FQ-CoDel-L4S) networks.
 *
 * Reference: draft-ietf-ccwg-rfc9002bis (QUIC Loss Detection)
 *            TCP Prague (draft-briscoe-iccrg-prague-congestion-control)
 */

#ifndef _TQUIC_PRAGUE_H
#define _TQUIC_PRAGUE_H

#include <linux/types.h>
#include "../cong.h"

/* Prague constants */
#define PRAGUE_ALPHA_SHIFT		10	/* Alpha scaling (1024) */
#define PRAGUE_ALPHA_MAX		(1 << PRAGUE_ALPHA_SHIFT)
#define PRAGUE_G_SHIFT			4	/* EWMA gain 1/16 */
#define PRAGUE_MIN_CWND			2	/* Minimum cwnd in packets */
#define PRAGUE_BETA_SCALE		512	/* Beta scaling for 0.7 = 358 */
#define PRAGUE_BETA_ECN			358	/* 0.7 * 512 */
#define PRAGUE_BETA_LOSS		409	/* 0.8 * 512 */
#define PRAGUE_RTT_VIRT_SHIFT		3	/* Virtual RTT multiplier */

/* Prague RTT independence */
#define PRAGUE_RTT_SCALING_MIN_US	1000	/* 1ms min RTT for scaling */
#define PRAGUE_RTT_TARGET_US		25000	/* 25ms target RTT */

/**
 * enum prague_state - Prague CC state
 * @PRAGUE_OPEN: Normal operation, cwnd increasing
 * @PRAGUE_RECOVERY: In loss recovery
 * @PRAGUE_ECN_REDUCED: Recently reduced due to ECN
 */
enum prague_state {
	PRAGUE_OPEN = 0,
	PRAGUE_RECOVERY,
	PRAGUE_ECN_REDUCED,
};

/**
 * struct prague_params - Prague tunable parameters
 * @ecn_alpha_init: Initial alpha value
 * @rtt_target_us: Target RTT in microseconds
 * @rtt_scaling: Enable RTT-independence scaling
 * @classic_ecn_fallback: Fall back to classic ECN response if needed
 */
struct prague_params {
	u32 ecn_alpha_init;
	u32 rtt_target_us;
	bool rtt_scaling;
	bool classic_ecn_fallback;
};

/**
 * struct prague - Prague congestion control state
 * @base: Base congestion control structure
 * @state: Current Prague state
 * @alpha: EWMA of ECN marking fraction (scaled << ALPHA_SHIFT)
 * @cwnd: Congestion window in bytes
 * @ssthresh: Slow start threshold
 * @bytes_acked: Bytes acknowledged in current RTT
 * @ecn_bytes: Bytes with CE marks in current RTT
 * @loss_cwnd: Cwnd at which loss occurred
 * @prior_cwnd: Cwnd before reduction
 * @rtt_min_us: Minimum observed RTT
 * @rtt_us: Smoothed RTT
 * @rtt_cnt: RTT sample count
 * @in_slow_start: In slow start phase
 * @ce_state: Accumulated CE state for proportional response
 * @acked_bytes_ecn: Bytes acked with ECN feedback
 * @params: Tunable parameters
 */
struct prague {
	struct tquic_cong base;
	enum prague_state state;
	u32 alpha;
	u32 cwnd;
	u32 ssthresh;
	u64 bytes_acked;
	u64 ecn_bytes;
	u32 loss_cwnd;
	u32 prior_cwnd;
	u32 rtt_min_us;
	u32 rtt_us;
	u32 rtt_cnt;
	bool in_slow_start;
	u32 ce_state;
	u64 acked_bytes_ecn;
	struct prague_params params;
};

/* Prague congestion control operations */
extern const struct tquic_cong_ops prague_cong_ops;

/* Module init/exit */
int __init tquic_prague_init(void);
void __exit tquic_prague_exit(void);

#endif /* _TQUIC_PRAGUE_H */
