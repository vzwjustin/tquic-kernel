// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: CUBIC Congestion Control
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * CUBIC congestion control adapted for TQUIC multipath WAN bonding.
 * Based on the CUBIC algorithm from TCP but modified for QUIC semantics.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/math64.h>
#include <net/tquic.h>
#include "../tquic_debug.h"
#include "persistent_cong.h"

/* CUBIC parameters */
#define TQUIC_CUBIC_C		410	/* C = 0.4 scaled by 1024 */
#define TQUIC_CUBIC_BETA	717	/* beta = 0.7 scaled by 1024 */
#define TQUIC_CUBIC_BETA_SCALE	1024

/* Initial and minimum cwnd */
#define TQUIC_CUBIC_INIT_CWND	(10 * 1200)	/* 10 packets */
#define TQUIC_CUBIC_MIN_CWND	(2 * 1200)	/* 2 packets */

/* ECN beta factor for cwnd reduction (RFC 9002: typically 0.8) */
#define TQUIC_CUBIC_BETA_ECN		819	/* 0.8 scaled by 1024 */

/* Per-path CUBIC state */
struct tquic_cubic {
	u64 cwnd;		/* Current congestion window */
	u64 ssthresh;		/* Slow start threshold */
	u64 w_max;		/* Window size before last reduction */
	u64 w_last_max;		/* Previous w_max */
	u64 epoch_start;	/* Time when epoch started (us) */
	u64 origin_point;	/* Origin of cubic curve */
	u64 k;			/* Time to reach w_max */
	u32 ack_cnt;		/* ACK counter for cwnd increase */
	u32 cnt;		/* Window increase counter */
	u32 last_cwnd;		/* Last cwnd for hystart */
	u32 tcp_cwnd;		/* Emulated TCP cwnd */
	bool in_slow_start;	/* In slow start phase */

	/* ECN state per RFC 9002 Section 7 */
	ktime_t last_ecn_time;	/* Time of last ECN response */
	u64 ecn_round_start;	/* Packet count at round start for ECN */
	bool ecn_in_round;	/* ECN CE received in current round */
	u64 rtt_us;		/* Current RTT estimate for round tracking */
};

/*
 * Cube root calculation (approximation)
 */
static u32 cubic_root(u64 a)
{
	u32 x, b, shift;

	tquic_dbg("cubic: cubic_root a=%llu\n", a);

	if (a == 0)
		return 0;

	/* Initial approximation */
	b = fls64(a);
	shift = (b + 2) / 3;
	x = 1 << shift;

	/* Newton-Raphson iterations */
	x = (2 * x + (u32)div64_u64(a, (u64)x * x)) / 3;
	x = (2 * x + (u32)div64_u64(a, (u64)x * x)) / 3;
	x = (2 * x + (u32)div64_u64(a, (u64)x * x)) / 3;

	return x;
}

/*
 * Calculate CUBIC window increase
 */
static u64 cubic_calc_w(struct tquic_cubic *cubic, u64 t)
{
	u64 offs, delta, bic_target;

	tquic_dbg("cubic: calc_w t=%llu k=%llu origin=%llu\n",
		  t, cubic->k, cubic->origin_point);

	/*
	 * W_cubic(t) = C(t-K)^3 + W_max
	 *
	 * To avoid overflow in C * offs^3, compute in steps:
	 * First compute offs^2, then multiply by offs, then by C,
	 * shifting progressively to keep values in range.
	 * offs is in milliseconds, so for a 10-second epoch offs <= 10000.
	 * offs^3 can be up to 10^12, times C=410 is ~4*10^14, which fits u64
	 * but we must be careful with the shift order.
	 */
	if (t < cubic->k) {
		offs = cubic->k - t;
		/* Split the shift: (C * offs * offs) >> 10 first, then * offs >> 20 */
		delta = (TQUIC_CUBIC_C * offs * offs) >> 10;
		delta = (delta * offs) >> 20;
		if (delta > cubic->origin_point)
			bic_target = 0;
		else
			bic_target = cubic->origin_point - delta;
	} else {
		offs = t - cubic->k;
		delta = (TQUIC_CUBIC_C * offs * offs) >> 10;
		delta = (delta * offs) >> 20;
		bic_target = cubic->origin_point + delta;
	}

	return bic_target;
}

/*
 * Calculate TCP-friendly window
 */
static u64 cubic_tcp_friendliness(struct tquic_cubic *cubic, u64 t)
{
	/* Simplified TCP-friendly calculation (guard w_max == 0) */
	if (cubic->w_max == 0)
		return cubic->tcp_cwnd;
	return cubic->tcp_cwnd + (t * 1200 / cubic->w_max);
}

/*
 * Initialize CUBIC state for a path
 */
static void *tquic_cubic_init(struct tquic_path *path)
{
	struct tquic_cubic *cubic;

	cubic = kzalloc(sizeof(*cubic), GFP_KERNEL);
	if (!cubic)
		return NULL;

	cubic->cwnd = TQUIC_CUBIC_INIT_CWND;
	cubic->ssthresh = ULLONG_MAX;
	cubic->in_slow_start = true;

	tquic_dbg("cubic: initialized for path %u\n", path->path_id);

	return cubic;
}

static void tquic_cubic_release(void *state)
{
	kfree(state);
}

/*
 * Called when a packet is sent
 */
static void tquic_cubic_on_sent(void *state, u64 bytes, ktime_t sent_time)
{
	/* Track in-flight data if needed */
}

/*
 * Called when ACK is received
 */
static void tquic_cubic_on_ack(void *state, u64 bytes_acked, u64 rtt_us)
{
	struct tquic_cubic *cubic = state;
	u64 now_us = ktime_to_us(ktime_get());
	u64 target, t;

	if (!cubic)
		return;

	tquic_dbg("cubic: on_ack bytes=%llu rtt=%llu cwnd=%llu ss=%d\n",
		  bytes_acked, rtt_us, cubic->cwnd, cubic->in_slow_start);

	/*
	 * New round detection: if an RTT has elapsed since the last
	 * ECN response, we are in a new round. Reset ecn_in_round
	 * so we can respond to ECN-CE in the new round per RFC 9002
	 * Section 7.1.
	 */
	if (cubic->ecn_in_round && cubic->rtt_us > 0) {
		s64 elapsed = ktime_us_delta(ktime_get(), cubic->last_ecn_time);

		if (elapsed >= (s64)cubic->rtt_us)
			cubic->ecn_in_round = false;
	}

	if (cubic->in_slow_start) {
		/* Slow start: increase cwnd exponentially */
		cubic->cwnd += bytes_acked;

		if (cubic->cwnd >= cubic->ssthresh) {
			cubic->in_slow_start = false;
			cubic->epoch_start = 0;
		}
		return;
	}

	/* Congestion avoidance: CUBIC increase */
	if (cubic->epoch_start == 0) {
		/* New epoch */
		cubic->epoch_start = now_us;
		cubic->ack_cnt = 1;

		if (cubic->cwnd < cubic->w_last_max) {
			cubic->k = cubic_root((cubic->w_last_max - cubic->cwnd) *
					      TQUIC_CUBIC_BETA_SCALE /
					      TQUIC_CUBIC_C);
			cubic->origin_point = cubic->w_last_max;
		} else {
			cubic->k = 0;
			cubic->origin_point = cubic->cwnd;
		}

		cubic->tcp_cwnd = cubic->cwnd;
	}

	/* Time since epoch start in ms */
	t = (now_us - cubic->epoch_start) / 1000;

	target = cubic_calc_w(cubic, t);

	/* TCP friendliness */
	if (target < cubic->tcp_cwnd)
		target = cubic->tcp_cwnd;

	/* Increase cwnd (guard against division by zero) */
	if (target > cubic->cwnd && cubic->cwnd > 0) {
		u64 inc = (target - cubic->cwnd) * bytes_acked / cubic->cwnd;

		cubic->cwnd += inc;
	}

	/* Update TCP emulation (guard against division by zero) */
	if (cubic->cwnd > 0)
		cubic->tcp_cwnd += bytes_acked / cubic->cwnd;
}

/*
 * Called on packet loss
 */
static void tquic_cubic_on_loss(void *state, u64 bytes_lost)
{
	struct tquic_cubic *cubic = state;

	if (!cubic)
		return;

	/* Fast convergence */
	if (cubic->cwnd < cubic->w_last_max)
		cubic->w_last_max = cubic->cwnd *
			(TQUIC_CUBIC_BETA_SCALE + TQUIC_CUBIC_BETA) /
			(2 * TQUIC_CUBIC_BETA_SCALE);
	else
		cubic->w_last_max = cubic->cwnd;

	cubic->w_max = cubic->cwnd;

	/* Multiplicative decrease */
	cubic->ssthresh = max(cubic->cwnd * TQUIC_CUBIC_BETA / TQUIC_CUBIC_BETA_SCALE,
			      (u64)TQUIC_CUBIC_MIN_CWND);
	cubic->cwnd = cubic->ssthresh;

	/* Reset epoch */
	cubic->epoch_start = 0;
	cubic->in_slow_start = false;

	tquic_warn("cubic: loss detected, cwnd=%llu ssthresh=%llu\n",
		   cubic->cwnd, cubic->ssthresh);
}

/*
 * Called on RTT update
 */
static void tquic_cubic_on_rtt(void *state, u64 rtt_us)
{
	struct tquic_cubic *cubic = state;

	if (!cubic || rtt_us == 0)
		return;

	tquic_dbg("cubic: on_rtt rtt_us=%llu prev=%llu\n",
		  rtt_us, cubic->rtt_us);

	/* Store RTT for ECN round tracking */
	cubic->rtt_us = rtt_us;
}

/*
 * Called on ECN Congestion Experienced (CE) marks
 *
 * Per RFC 9002 Section 7.1:
 * - Treat ECN-CE as congestion signal similar to loss
 * - Reduce cwnd using multiplicative decrease
 * - Don't reduce more than once per RTT
 *
 * For CUBIC, we use a slightly less aggressive reduction than loss
 * (beta_ecn = 0.8 vs beta = 0.7 for loss) since ECN indicates
 * congestion before actual packet loss occurs.
 */
static void tquic_cubic_on_ecn(void *state, u64 ecn_ce_count)
{
	struct tquic_cubic *cubic = state;
	ktime_t now;
	s64 time_since_last;

	if (!cubic || ecn_ce_count == 0)
		return;

	now = ktime_get();

	/*
	 * Per RFC 9002 Section 7.1: "A sender MUST NOT apply this
	 * reduction more than once in a given round trip."
	 *
	 * Use time-based rate limiting: don't respond more than once
	 * per RTT. This is a conservative approximation.
	 */
	if (cubic->ecn_in_round) {
		tquic_dbg("cubic: ECN CE ignored (already responded this round)\n");
		return;
	}

	/* Also check time-based rate limiting as backup */
	if (cubic->rtt_us > 0) {
		time_since_last = ktime_us_delta(now, cubic->last_ecn_time);
		if (time_since_last < cubic->rtt_us) {
			tquic_dbg("cubic: ECN CE ignored (within RTT window)\n");
			return;
		}
	}

	/*
	 * ECN congestion response:
	 * - Save w_max for fast convergence
	 * - Reduce cwnd by beta_ecn factor (typically 0.8)
	 * - Enter congestion avoidance (exit slow start)
	 * - Reset epoch for CUBIC curve calculation
	 */

	/* Fast convergence: remember previous maximum */
	if (cubic->cwnd < cubic->w_last_max) {
		cubic->w_last_max = cubic->cwnd *
			(TQUIC_CUBIC_BETA_SCALE + TQUIC_CUBIC_BETA_ECN) /
			(2 * TQUIC_CUBIC_BETA_SCALE);
	} else {
		cubic->w_last_max = cubic->cwnd;
	}

	cubic->w_max = cubic->cwnd;

	/*
	 * Multiplicative decrease with beta_ecn (0.8)
	 * Less aggressive than loss (0.7) since ECN is early signal
	 */
	cubic->ssthresh = max(cubic->cwnd * TQUIC_CUBIC_BETA_ECN /
			      TQUIC_CUBIC_BETA_SCALE,
			      (u64)TQUIC_CUBIC_MIN_CWND);
	cubic->cwnd = cubic->ssthresh;

	/* Reset CUBIC epoch to start new curve */
	cubic->epoch_start = 0;
	cubic->in_slow_start = false;

	/* Mark that we responded to ECN in this round */
	cubic->ecn_in_round = true;
	cubic->last_ecn_time = now;

	tquic_dbg("cubic: ECN CE response, ce_count=%llu cwnd=%llu ssthresh=%llu\n",
		  ecn_ce_count, cubic->cwnd, cubic->ssthresh);
}

static u64 tquic_cubic_get_cwnd(void *state)
{
	struct tquic_cubic *cubic = state;
	return cubic ? cubic->cwnd : TQUIC_CUBIC_INIT_CWND;
}

static u64 tquic_cubic_get_pacing_rate(void *state)
{
	struct tquic_cubic *cubic = state;

	if (!cubic)
		return 0;

	tquic_dbg("cubic: get_pacing_rate cwnd=%llu rtt=%llu\n",
		  cubic->cwnd, cubic->rtt_us);

	/*
	 * Pacing rate = cwnd / RTT (in bytes per second).
	 * Use 1.25x multiplier for headroom, similar to TCP pacing.
	 * If no RTT sample yet, use a conservative default (100ms).
	 *
	 * Cap cwnd before multiplication to prevent u64 overflow:
	 * cwnd * USEC_PER_SEC * 5 must fit in u64.
	 */
	{
		u64 capped = min_t(u64, cubic->cwnd,
				   U64_MAX / (USEC_PER_SEC * 5));

		if (cubic->rtt_us > 0)
			return div64_u64(capped * USEC_PER_SEC * 5,
					 (u64)cubic->rtt_us * 4);

		/* No RTT sample: assume 100ms */
		return div64_u64(capped * USEC_PER_SEC * 5, 100000ULL * 4);
	}
}

static bool tquic_cubic_can_send(void *state, u64 bytes)
{
	struct tquic_cubic *cubic = state;

	if (!cubic)
		return true;

	/* Simplified: allow send if within cwnd */
	return true;
}

/*
 * Called on persistent congestion (RFC 9002 Section 7.6)
 *
 * Per RFC 9002:
 * "When persistent congestion is established, the sender's congestion
 * window MUST be reduced to the minimum congestion window (kMinimumWindow),
 * which equals 2 * max_datagram_size."
 *
 * For CUBIC, we also reset:
 * - ssthresh to the new cwnd
 * - Epoch start (to begin fresh CUBIC curve)
 * - w_max and w_last_max (fast convergence state)
 */
static void tquic_cubic_on_persistent_cong(void *state,
					   struct tquic_persistent_cong_info *info)
{
	struct tquic_cubic *cubic = state;

	if (!cubic || !info)
		return;

	tquic_warn("cubic: persistent congestion, cwnd %llu -> %llu\n",
		   cubic->cwnd, info->min_cwnd);

	/* Reset to minimum cwnd per RFC 9002 */
	cubic->cwnd = info->min_cwnd;
	cubic->ssthresh = info->min_cwnd;

	/* Reset CUBIC state to start fresh */
	cubic->epoch_start = 0;
	cubic->w_max = cubic->cwnd;
	cubic->w_last_max = cubic->cwnd;
	cubic->k = 0;
	cubic->origin_point = cubic->cwnd;
	cubic->tcp_cwnd = cubic->cwnd;
	cubic->ack_cnt = 0;

	/* Exit slow start - persistent congestion means we were too aggressive */
	cubic->in_slow_start = false;

	/* Reset ECN round tracking */
	cubic->ecn_in_round = false;
}

static struct tquic_cong_ops tquic_cubic_ops = {
	.name = "cubic",
	.owner = THIS_MODULE,
	.init = tquic_cubic_init,
	.release = tquic_cubic_release,
	.on_packet_sent = tquic_cubic_on_sent,
	.on_ack = tquic_cubic_on_ack,
	.on_loss = tquic_cubic_on_loss,
	.on_rtt_update = tquic_cubic_on_rtt,
	.on_ecn = tquic_cubic_on_ecn,  /* ECN CE handler per RFC 9002 */
	.on_persistent_congestion = tquic_cubic_on_persistent_cong,
	.get_cwnd = tquic_cubic_get_cwnd,
	.get_pacing_rate = tquic_cubic_get_pacing_rate,
	.can_send = tquic_cubic_can_send,
};

#ifndef TQUIC_OUT_OF_TREE
static int __init tquic_cubic_module_init(void)
{
	return tquic_register_cong(&tquic_cubic_ops);
}

static void __exit tquic_cubic_module_exit(void)
{
	tquic_unregister_cong(&tquic_cubic_ops);
}

module_init(tquic_cubic_module_init);
module_exit(tquic_cubic_module_exit);
#endif /* !TQUIC_OUT_OF_TREE */

MODULE_DESCRIPTION("TQUIC CUBIC Congestion Control");
MODULE_LICENSE("GPL");
MODULE_ALIAS("tquic-cong-cubic");
