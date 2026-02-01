// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * QUIC Congestion Control
 *
 * Implementation of congestion control algorithms for QUIC
 * Based on RFC 9002 - QUIC Loss Detection and Congestion Control
 *
 * Implements:
 *   - Reno (NewReno) congestion control
 *   - CUBIC congestion control
 *   - BBR (Bottleneck Bandwidth and RTT) congestion control
 *   - BBRv2 congestion control
 *
 * Copyright (c) 2024 Linux QUIC Authors
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/math64.h>
#include <linux/random.h>
#include <linux/minmax.h>
#include <net/quic.h>

/* RFC 9002 constants */
#define QUIC_INITIAL_CWND_PACKETS	10
#define QUIC_INITIAL_CWND_MIN		(2 * QUIC_MAX_PACKET_SIZE)
#define QUIC_MIN_CWND			(2 * QUIC_MAX_PACKET_SIZE)
#define QUIC_LOSS_REDUCTION_FACTOR	2	/* Reno: cwnd / 2 */

/* Default initial RTT (333ms per RFC 9002) */
#define QUIC_INITIAL_RTT_MS		333
#define QUIC_INITIAL_RTT_US		(QUIC_INITIAL_RTT_MS * 1000)

/* Pacing constants */
#define QUIC_PACING_MULTIPLIER_NUM	5
#define QUIC_PACING_MULTIPLIER_DEN	4	/* 1.25x pacing */

/* CUBIC constants */
#define CUBIC_BETA_SCALE		1024
#define CUBIC_BETA			717	/* 0.7 * 1024 */
#define CUBIC_C_SCALE			10	/* C = 0.4, scaled by 10 */
#define CUBIC_C				4	/* C * CUBIC_C_SCALE */

/* BBR constants */
#define BBR_SCALE			8
#define BBR_UNIT			(1 << BBR_SCALE)
#define BBR_HIGH_GAIN			((BBR_UNIT * 2885) / 1000 + 1)	/* 2/ln(2) */
#define BBR_DRAIN_GAIN			((BBR_UNIT * 1000) / 2885)
#define BBR_CWND_GAIN			(BBR_UNIT * 2)
#define BBR_PROBE_RTT_CWND		(4 * QUIC_MAX_PACKET_SIZE)
#define BBR_MIN_RTT_WIN_SEC		10
#define BBR_PROBE_RTT_DURATION_MS	200
#define BBR_CYCLE_LEN			8
#define BBR_FULL_BW_THRESH		((BBR_UNIT * 5) / 4)	/* 1.25x */
#define BBR_FULL_BW_CNT			3

/* BBR modes */
#define BBR_MODE_STARTUP		0
#define BBR_MODE_DRAIN			1
#define BBR_MODE_PROBE_BW		2
#define BBR_MODE_PROBE_RTT		3

/* BBRv2 additional constants */
#define BBR2_LOSS_THRESH		((BBR_UNIT * 2) / 100)	/* 2% loss threshold */
#define BBR2_INFLIGHT_LO_SCALE		((BBR_UNIT * 9) / 10)	/* 0.9x */
#define BBR2_HEADROOM			((BBR_UNIT * 15) / 100)	/* 15% headroom */
#define BBR2_PROBE_RTT_CWND_GAIN	((BBR_UNIT * 1) / 2)	/* 0.5x */
#define BBR2_STARTUP_CWND_GAIN		(BBR_UNIT * 2)
#define BBR2_STARTUP_PACING_GAIN	((BBR_UNIT * 277) / 100)	/* 2.77x */

/* BBR pacing gain cycle for PROBE_BW mode */
static const int bbr_pacing_gain[] = {
	(BBR_UNIT * 5) / 4,	/* probe for more bandwidth */
	(BBR_UNIT * 3) / 4,	/* drain queue */
	BBR_UNIT, BBR_UNIT, BBR_UNIT,	/* cruise at estimated bw */
	BBR_UNIT, BBR_UNIT, BBR_UNIT
};

/*
 * Compute cubic root using Newton-Raphson iteration
 * This is used for CUBIC's time-based window growth
 */
static u32 cubic_root(u64 a)
{
	u32 x, b, shift;
	static const u8 v[] = {
		0,   54,   54,   54,  118,  118,  118,  118,
		123,  129,  134,  138,  143,  147,  151,  156,
		157,  161,  164,  168,  170,  173,  176,  179,
		181,  185,  187,  190,  192,  194,  197,  199,
		200,  202,  204,  206,  209,  211,  213,  215,
		217,  219,  221,  222,  224,  225,  227,  229,
		231,  232,  234,  236,  237,  239,  240,  242,
		244,  245,  246,  248,  250,  251,  252,  254,
	};

	if (a == 0)
		return 0;

	b = fls64(a);
	if (b < 7)
		return ((u32)v[(u32)a] + 35) >> 6;

	b = ((b * 84) >> 8) - 1;
	shift = (a >> (b * 3));

	if (shift >= 64)
		shift = 63;

	x = ((u32)(((u32)v[shift] + 10) << b)) >> 6;

	/* Newton-Raphson iteration */
	x = (2 * x + (u32)div64_u64(a, (u64)x * (u64)(x - 1)));
	x = ((x * 341) >> 10);

	return x;
}

/*
 * Initialize congestion control state
 * Called when a new connection or path is created
 */
void quic_cc_init(struct quic_cc_state *cc, enum quic_cc_algo algo)
{
	memset(cc, 0, sizeof(*cc));

	cc->algo = algo;

	/* RFC 9002: Initial window is min(10 * max_datagram_size, max(14720, 2 * max_datagram_size)) */
	cc->cwnd = min_t(u64, QUIC_INITIAL_CWND_PACKETS * QUIC_MAX_PACKET_SIZE,
			 max_t(u64, 14720, QUIC_INITIAL_CWND_MIN));
	cc->congestion_window = cc->cwnd;
	cc->ssthresh = U64_MAX;		/* No initial slow start threshold */
	cc->bytes_in_flight = 0;
	cc->in_slow_start = 1;
	cc->in_recovery = 0;
	cc->app_limited = 0;
	cc->pto_count = 0;
	cc->loss_burst_count = 0;
	cc->last_sent_time = 0;
	cc->congestion_recovery_start = 0;

	/* Algorithm-specific initialization */
	switch (algo) {
	case QUIC_CC_RENO:
		/* Reno uses default values */
		break;

	case QUIC_CC_CUBIC:
		cc->cubic_k = 0;
		cc->cubic_origin_point = 0;
		cc->cubic_epoch_start = 0;
		break;

	case QUIC_CC_BBR:
	case QUIC_CC_BBR2:
		cc->bbr_mode = BBR_MODE_STARTUP;
		cc->bbr_bw = 0;
		cc->bbr_min_rtt = U64_MAX;
		cc->bbr_cycle_index = 0;
		/* Initial pacing rate based on initial cwnd and RTT */
		cc->pacing_rate = div64_u64(cc->cwnd * USEC_PER_SEC,
					    QUIC_INITIAL_RTT_US);
		break;
	}

	/* Default pacing rate for non-BBR algorithms */
	if (algo != QUIC_CC_BBR && algo != QUIC_CC_BBR2) {
		cc->pacing_rate = div64_u64(cc->cwnd * USEC_PER_SEC,
					    QUIC_INITIAL_RTT_US);
	}
}
EXPORT_SYMBOL_GPL(quic_cc_init);

/*
 * Handle packet sent event
 * Updates bytes in flight tracking
 */
void quic_cc_on_packet_sent(struct quic_cc_state *cc, u32 bytes)
{
	cc->bytes_in_flight += bytes;
	cc->last_sent_time = ktime_get_ns();

	/* Track if we're application limited */
	if (cc->bytes_in_flight < cc->cwnd)
		cc->app_limited = 1;
	else
		cc->app_limited = 0;
}
EXPORT_SYMBOL_GPL(quic_cc_on_packet_sent);

/*
 * Reno congestion avoidance: additive increase
 * Increases cwnd by 1 MSS per RTT during congestion avoidance
 */
static void reno_on_ack(struct quic_cc_state *cc, u64 acked_bytes,
			struct quic_rtt *rtt)
{
	if (cc->in_slow_start) {
		/* Slow start: exponential growth */
		cc->cwnd += acked_bytes;
		if (cc->cwnd >= cc->ssthresh) {
			cc->in_slow_start = 0;
			cc->cwnd = cc->ssthresh;
		}
	} else {
		/* Congestion avoidance: linear growth */
		/* Increase by (acked_bytes * MSS) / cwnd per ACK */
		cc->cwnd += div64_u64((u64)acked_bytes * QUIC_MAX_PACKET_SIZE,
				      cc->cwnd);
	}

	cc->congestion_window = cc->cwnd;
}

/*
 * CUBIC congestion control on ACK
 * Implements the CUBIC window growth function
 */
static void cubic_on_ack(struct quic_cc_state *cc, u64 acked_bytes,
			 struct quic_rtt *rtt)
{
	u64 target_cwnd;
	u64 tcp_cwnd;
	u64 t;		/* Time since epoch start in seconds (scaled) */
	u64 offs;
	u64 delta;
	ktime_t now = ktime_get();

	if (cc->in_slow_start) {
		/* Slow start: exponential growth */
		cc->cwnd += acked_bytes;
		if (cc->cwnd >= cc->ssthresh) {
			cc->in_slow_start = 0;
			cc->cwnd = cc->ssthresh;
			cc->cubic_epoch_start = now;
			cc->cubic_origin_point = cc->cwnd;
		}
		cc->congestion_window = cc->cwnd;
		return;
	}

	/* Initialize epoch on first congestion avoidance ACK */
	if (cc->cubic_epoch_start == 0) {
		cc->cubic_epoch_start = now;
		if (cc->cwnd < cc->cubic_origin_point) {
			/*
			 * Compute K = cubic_root((origin - cwnd) / C)
			 * K is the time to reach origin_point
			 */
			u64 diff = cc->cubic_origin_point - cc->cwnd;
			/* Scale by 10 for fixed point, convert bytes to packets */
			diff = div64_u64(diff * CUBIC_C_SCALE,
					 (u64)QUIC_MAX_PACKET_SIZE * CUBIC_C);
			cc->cubic_k = cubic_root(diff);
		} else {
			cc->cubic_k = 0;
			cc->cubic_origin_point = cc->cwnd;
		}
	}

	/* Calculate time since epoch start in 1/1024 seconds */
	t = ktime_ms_delta(now, cc->cubic_epoch_start);
	t = (t << 10) / 1000;  /* Convert to 1/1024 seconds */

	/* CUBIC function: W(t) = C * (t - K)^3 + origin_point */
	if (t < cc->cubic_k)
		offs = cc->cubic_k - t;
	else
		offs = t - cc->cubic_k;

	/* Calculate delta = C * offs^3 (in packets, then convert to bytes) */
	delta = offs * offs * offs;
	delta = div64_u64(delta * CUBIC_C * QUIC_MAX_PACKET_SIZE,
			  (u64)CUBIC_C_SCALE << 30);

	if (t < cc->cubic_k)
		target_cwnd = cc->cubic_origin_point - delta;
	else
		target_cwnd = cc->cubic_origin_point + delta;

	/* TCP-friendly region: ensure we're at least as fast as Reno */
	/* TCP cwnd grows by ~1.5 MSS per RTT */
	if (rtt->smoothed_rtt > 0) {
		u64 rtt_ms = rtt->smoothed_rtt / 1000;
		u64 elapsed_ms = ktime_ms_delta(now, cc->cubic_epoch_start);
		u64 rtt_count = rtt_ms > 0 ? div64_u64(elapsed_ms, rtt_ms) : 1;

		tcp_cwnd = cc->cubic_origin_point +
			   rtt_count * QUIC_MAX_PACKET_SIZE *
			   (CUBIC_BETA_SCALE + CUBIC_BETA) /
			   (CUBIC_BETA_SCALE * 2);

		target_cwnd = max(target_cwnd, tcp_cwnd);
	}

	/* Don't grow faster than 1 MSS per ACK */
	if (target_cwnd > cc->cwnd + acked_bytes)
		target_cwnd = cc->cwnd + acked_bytes;

	cc->cwnd = max(target_cwnd, (u64)QUIC_MIN_CWND);
	cc->congestion_window = cc->cwnd;
}

/*
 * Update BBR bandwidth estimate
 * Maintains a windowed maximum of delivery rate samples
 */
static void bbr_update_bw(struct quic_cc_state *cc, u64 acked_bytes,
			  struct quic_rtt *rtt)
{
	u64 bw;

	if (!rtt->has_sample || rtt->latest_rtt == 0)
		return;

	/* Calculate bandwidth: bytes / time */
	bw = div64_u64(acked_bytes * USEC_PER_SEC, rtt->latest_rtt);

	/* Update max bandwidth (simplified windowed max) */
	if (bw > cc->bbr_bw || cc->app_limited == 0)
		cc->bbr_bw = bw;
}

/*
 * Update BBR minimum RTT
 * Maintains the minimum RTT over a 10-second window
 */
static void bbr_update_min_rtt(struct quic_cc_state *cc, struct quic_rtt *rtt)
{
	if (!rtt->has_sample)
		return;

	if (rtt->latest_rtt < cc->bbr_min_rtt || cc->bbr_min_rtt == U64_MAX)
		cc->bbr_min_rtt = rtt->latest_rtt;
}

/*
 * BBR state machine transition
 */
static void bbr_check_state_transition(struct quic_cc_state *cc,
				       struct quic_rtt *rtt)
{
	static u32 full_bw_count;
	static u64 full_bw;

	switch (cc->bbr_mode) {
	case BBR_MODE_STARTUP:
		/* Check if we've filled the pipe */
		if (cc->bbr_bw > 0) {
			if (cc->bbr_bw >= (full_bw * BBR_FULL_BW_THRESH) >> BBR_SCALE) {
				full_bw = cc->bbr_bw;
				full_bw_count = 0;
			} else {
				full_bw_count++;
				if (full_bw_count >= BBR_FULL_BW_CNT) {
					cc->bbr_mode = BBR_MODE_DRAIN;
					full_bw_count = 0;
				}
			}
		}
		break;

	case BBR_MODE_DRAIN:
		/* Exit drain when inflight <= BDP */
		if (cc->bbr_bw > 0 && cc->bbr_min_rtt < U64_MAX) {
			u64 bdp = div64_u64(cc->bbr_bw * cc->bbr_min_rtt,
					    USEC_PER_SEC);
			if (cc->bytes_in_flight <= bdp)
				cc->bbr_mode = BBR_MODE_PROBE_BW;
		}
		break;

	case BBR_MODE_PROBE_BW:
		/* Cycle through pacing gains */
		cc->bbr_cycle_index = (cc->bbr_cycle_index + 1) % BBR_CYCLE_LEN;
		break;

	case BBR_MODE_PROBE_RTT:
		/* Return to previous mode after probing */
		cc->bbr_mode = BBR_MODE_PROBE_BW;
		break;
	}
}

/*
 * BBR congestion control on ACK
 */
static void bbr_on_ack(struct quic_cc_state *cc, u64 acked_bytes,
		       struct quic_rtt *rtt)
{
	u64 bdp;
	u64 cwnd_gain;
	u64 pacing_gain;

	/* Update bandwidth and RTT estimates */
	bbr_update_bw(cc, acked_bytes, rtt);
	bbr_update_min_rtt(cc, rtt);

	/* Check for state transitions */
	bbr_check_state_transition(cc, rtt);

	/* Calculate BDP (bandwidth-delay product) */
	if (cc->bbr_bw == 0 || cc->bbr_min_rtt == U64_MAX) {
		/* No valid estimates yet, use default */
		cc->congestion_window = cc->cwnd;
		return;
	}

	bdp = div64_u64(cc->bbr_bw * cc->bbr_min_rtt, USEC_PER_SEC);

	/* Apply gains based on mode */
	switch (cc->bbr_mode) {
	case BBR_MODE_STARTUP:
		cwnd_gain = BBR_HIGH_GAIN;
		pacing_gain = BBR_HIGH_GAIN;
		cc->in_slow_start = 1;
		break;

	case BBR_MODE_DRAIN:
		cwnd_gain = BBR_HIGH_GAIN;	/* Maintain high cwnd */
		pacing_gain = BBR_DRAIN_GAIN;	/* But slow pacing */
		cc->in_slow_start = 0;
		break;

	case BBR_MODE_PROBE_BW:
		cwnd_gain = BBR_CWND_GAIN;
		pacing_gain = bbr_pacing_gain[cc->bbr_cycle_index];
		cc->in_slow_start = 0;
		break;

	case BBR_MODE_PROBE_RTT:
		cwnd_gain = BBR_UNIT;
		pacing_gain = BBR_UNIT;
		cc->in_slow_start = 0;
		break;

	default:
		cwnd_gain = BBR_UNIT;
		pacing_gain = BBR_UNIT;
		break;
	}

	/* Calculate cwnd and pacing rate */
	cc->cwnd = (bdp * cwnd_gain) >> BBR_SCALE;
	cc->cwnd = max(cc->cwnd, (u64)QUIC_MIN_CWND);

	if (cc->bbr_mode == BBR_MODE_PROBE_RTT)
		cc->cwnd = min(cc->cwnd, (u64)BBR_PROBE_RTT_CWND);

	cc->congestion_window = cc->cwnd;

	/* Update pacing rate */
	cc->pacing_rate = (cc->bbr_bw * pacing_gain) >> BBR_SCALE;
}

/*
 * BBRv2 congestion control on ACK
 * Adds loss-based cwnd reduction compared to BBR
 */
static void bbr2_on_ack(struct quic_cc_state *cc, u64 acked_bytes,
			struct quic_rtt *rtt)
{
	u64 bdp;
	u64 cwnd_gain;
	u64 pacing_gain;
	u64 inflight_lo;

	/* Update bandwidth and RTT estimates */
	bbr_update_bw(cc, acked_bytes, rtt);
	bbr_update_min_rtt(cc, rtt);

	/* Check for state transitions */
	bbr_check_state_transition(cc, rtt);

	/* Calculate BDP */
	if (cc->bbr_bw == 0 || cc->bbr_min_rtt == U64_MAX) {
		cc->congestion_window = cc->cwnd;
		return;
	}

	bdp = div64_u64(cc->bbr_bw * cc->bbr_min_rtt, USEC_PER_SEC);

	/* BBRv2-specific: Calculate inflight_lo with headroom */
	inflight_lo = (bdp * (BBR_UNIT - BBR2_HEADROOM)) >> BBR_SCALE;

	/* Apply gains based on mode */
	switch (cc->bbr_mode) {
	case BBR_MODE_STARTUP:
		cwnd_gain = BBR2_STARTUP_CWND_GAIN;
		pacing_gain = BBR2_STARTUP_PACING_GAIN;
		cc->in_slow_start = 1;
		break;

	case BBR_MODE_DRAIN:
		cwnd_gain = BBR_HIGH_GAIN;
		pacing_gain = BBR_DRAIN_GAIN;
		cc->in_slow_start = 0;
		break;

	case BBR_MODE_PROBE_BW:
		cwnd_gain = BBR_CWND_GAIN;
		pacing_gain = bbr_pacing_gain[cc->bbr_cycle_index];
		cc->in_slow_start = 0;
		break;

	case BBR_MODE_PROBE_RTT:
		cwnd_gain = BBR2_PROBE_RTT_CWND_GAIN;
		pacing_gain = BBR_UNIT;
		cc->in_slow_start = 0;
		break;

	default:
		cwnd_gain = BBR_UNIT;
		pacing_gain = BBR_UNIT;
		break;
	}

	/* Calculate cwnd with BBRv2 constraints */
	cc->cwnd = (bdp * cwnd_gain) >> BBR_SCALE;

	/* BBRv2: Apply inflight_lo constraint if in recovery */
	if (cc->in_recovery && cc->cwnd > inflight_lo)
		cc->cwnd = inflight_lo;

	cc->cwnd = max(cc->cwnd, (u64)QUIC_MIN_CWND);

	if (cc->bbr_mode == BBR_MODE_PROBE_RTT) {
		u64 probe_cwnd = (bdp * BBR2_PROBE_RTT_CWND_GAIN) >> BBR_SCALE;
		cc->cwnd = max(probe_cwnd, (u64)QUIC_MIN_CWND);
	}

	cc->congestion_window = cc->cwnd;

	/* Update pacing rate */
	cc->pacing_rate = (cc->bbr_bw * pacing_gain) >> BBR_SCALE;
}

/*
 * Handle acknowledgment of data
 * This is the main entry point for congestion control when packets are ACKed
 */
void quic_cc_on_ack(struct quic_cc_state *cc, u64 acked_bytes,
		    struct quic_rtt *rtt)
{
	/* Exit recovery if we've acknowledged all data from recovery start */
	if (cc->in_recovery && cc->bytes_in_flight == 0)
		cc->in_recovery = 0;

	/* Update bytes in flight */
	if (acked_bytes <= cc->bytes_in_flight)
		cc->bytes_in_flight -= acked_bytes;
	else
		cc->bytes_in_flight = 0;

	/* Algorithm-specific handling */
	switch (cc->algo) {
	case QUIC_CC_RENO:
		reno_on_ack(cc, acked_bytes, rtt);
		break;

	case QUIC_CC_CUBIC:
		cubic_on_ack(cc, acked_bytes, rtt);
		break;

	case QUIC_CC_BBR:
		bbr_on_ack(cc, acked_bytes, rtt);
		break;

	case QUIC_CC_BBR2:
		bbr2_on_ack(cc, acked_bytes, rtt);
		break;
	}

	/* Update pacing rate for Reno and CUBIC */
	if (cc->algo == QUIC_CC_RENO || cc->algo == QUIC_CC_CUBIC) {
		if (rtt->smoothed_rtt > 0) {
			cc->pacing_rate = div64_u64(cc->cwnd * USEC_PER_SEC *
						    QUIC_PACING_MULTIPLIER_NUM,
						    rtt->smoothed_rtt *
						    QUIC_PACING_MULTIPLIER_DEN);
		}
	}
}
EXPORT_SYMBOL_GPL(quic_cc_on_ack);

/*
 * Handle packet loss
 * RFC 9002: On loss, reduce congestion window
 */
void quic_cc_on_loss(struct quic_cc_state *cc, u64 lost_bytes)
{
	ktime_t now = ktime_get();

	cc->loss_burst_count++;

	/* Don't reduce cwnd if already in recovery */
	if (cc->in_recovery)
		return;

	/* Enter recovery */
	cc->in_recovery = 1;
	cc->congestion_recovery_start = now;

	switch (cc->algo) {
	case QUIC_CC_RENO:
		/* RFC 9002: cwnd = cwnd / 2 */
		cc->ssthresh = max(cc->cwnd / QUIC_LOSS_REDUCTION_FACTOR,
				   (u64)QUIC_MIN_CWND);
		cc->cwnd = cc->ssthresh;
		cc->in_slow_start = 0;
		break;

	case QUIC_CC_CUBIC:
		/* CUBIC uses beta = 0.7 */
		cc->ssthresh = (cc->cwnd * CUBIC_BETA) / CUBIC_BETA_SCALE;
		cc->ssthresh = max(cc->ssthresh, (u64)QUIC_MIN_CWND);
		cc->cwnd = cc->ssthresh;
		cc->in_slow_start = 0;
		/* Reset CUBIC state */
		cc->cubic_origin_point = cc->ssthresh;
		cc->cubic_epoch_start = 0;
		cc->cubic_k = 0;
		break;

	case QUIC_CC_BBR:
		/* BBR doesn't reduce cwnd on loss during normal operation */
		/* Only track the loss for bandwidth estimation */
		break;

	case QUIC_CC_BBR2:
		/* BBRv2 responds to loss more aggressively */
		if (cc->bbr_mode != BBR_MODE_PROBE_RTT) {
			u64 bdp = 0;
			if (cc->bbr_bw > 0 && cc->bbr_min_rtt < U64_MAX)
				bdp = div64_u64(cc->bbr_bw * cc->bbr_min_rtt,
						USEC_PER_SEC);
			/* Reduce cwnd to inflight_lo */
			cc->cwnd = (bdp * BBR2_INFLIGHT_LO_SCALE) >> BBR_SCALE;
			cc->cwnd = max(cc->cwnd, (u64)QUIC_MIN_CWND);
		}
		break;
	}

	cc->congestion_window = cc->cwnd;

	/* Update pacing rate */
	if (cc->algo == QUIC_CC_RENO || cc->algo == QUIC_CC_CUBIC) {
		cc->pacing_rate = div64_u64(cc->cwnd * USEC_PER_SEC *
					    QUIC_PACING_MULTIPLIER_NUM,
					    QUIC_INITIAL_RTT_US *
					    QUIC_PACING_MULTIPLIER_DEN);
	}
}
EXPORT_SYMBOL_GPL(quic_cc_on_loss);

/*
 * Handle congestion event (ECN CE marking)
 * Similar to loss handling per RFC 9002
 */
void quic_cc_on_congestion_event(struct quic_cc_state *cc)
{
	ktime_t now = ktime_get();

	/* Don't respond if already in recovery */
	if (cc->in_recovery)
		return;

	/* Enter recovery */
	cc->in_recovery = 1;
	cc->congestion_recovery_start = now;

	switch (cc->algo) {
	case QUIC_CC_RENO:
		cc->ssthresh = max(cc->cwnd / QUIC_LOSS_REDUCTION_FACTOR,
				   (u64)QUIC_MIN_CWND);
		cc->cwnd = cc->ssthresh;
		cc->in_slow_start = 0;
		break;

	case QUIC_CC_CUBIC:
		cc->ssthresh = (cc->cwnd * CUBIC_BETA) / CUBIC_BETA_SCALE;
		cc->ssthresh = max(cc->ssthresh, (u64)QUIC_MIN_CWND);
		cc->cwnd = cc->ssthresh;
		cc->in_slow_start = 0;
		cc->cubic_origin_point = cc->ssthresh;
		cc->cubic_epoch_start = 0;
		cc->cubic_k = 0;
		break;

	case QUIC_CC_BBR:
		/* BBR treats ECN similarly to loss for the drain mechanism */
		if (cc->bbr_mode == BBR_MODE_STARTUP)
			cc->bbr_mode = BBR_MODE_DRAIN;
		break;

	case QUIC_CC_BBR2:
		/* BBRv2 uses ECN to reduce inflight */
		if (cc->bbr_bw > 0 && cc->bbr_min_rtt < U64_MAX) {
			u64 bdp = div64_u64(cc->bbr_bw * cc->bbr_min_rtt,
					    USEC_PER_SEC);
			cc->cwnd = (bdp * BBR2_INFLIGHT_LO_SCALE) >> BBR_SCALE;
			cc->cwnd = max(cc->cwnd, (u64)QUIC_MIN_CWND);
		}
		if (cc->bbr_mode == BBR_MODE_STARTUP)
			cc->bbr_mode = BBR_MODE_DRAIN;
		break;
	}

	cc->congestion_window = cc->cwnd;
}
EXPORT_SYMBOL_GPL(quic_cc_on_congestion_event);

/*
 * Calculate pacing delay for sending the next packet
 * Returns delay in nanoseconds
 */
u64 quic_cc_pacing_delay(struct quic_cc_state *cc, u32 bytes)
{
	u64 delay_ns;

	if (cc->pacing_rate == 0)
		return 0;

	/* delay = bytes / pacing_rate (pacing_rate is in bytes/sec) */
	delay_ns = div64_u64((u64)bytes * NSEC_PER_SEC, cc->pacing_rate);

	/* During slow start, pace more aggressively */
	if (cc->in_slow_start && (cc->algo == QUIC_CC_RENO ||
				  cc->algo == QUIC_CC_CUBIC)) {
		delay_ns = delay_ns / 2;
	}

	return delay_ns;
}
EXPORT_SYMBOL_GPL(quic_cc_pacing_delay);

/*
 * Check if congestion control allows sending
 * Returns true if the given number of bytes can be sent
 */
bool quic_cc_can_send(struct quic_cc_state *cc, u32 bytes)
{
	/* Always allow at least one packet (for probes, PTO, etc.) */
	if (bytes <= QUIC_MAX_PACKET_SIZE && cc->bytes_in_flight == 0)
		return true;

	/* Check against congestion window */
	if (cc->bytes_in_flight + bytes <= cc->cwnd)
		return true;

	/* BBR modes may have different rules */
	if (cc->algo == QUIC_CC_BBR || cc->algo == QUIC_CC_BBR2) {
		/* In PROBE_BW with high gain, allow slight overshoot */
		if (cc->bbr_mode == BBR_MODE_PROBE_BW &&
		    cc->bbr_cycle_index == 0) {
			u64 overshoot = cc->cwnd / 4;
			if (cc->bytes_in_flight + bytes <= cc->cwnd + overshoot)
				return true;
		}
	}

	return false;
}
EXPORT_SYMBOL_GPL(quic_cc_can_send);

/*
 * Reset congestion state after persistent congestion
 * Per RFC 9002 Section 7.6.2
 */
void quic_cc_on_persistent_congestion(struct quic_cc_state *cc)
{
	/* Reset to minimum window */
	cc->cwnd = QUIC_MIN_CWND;
	cc->congestion_window = cc->cwnd;
	cc->ssthresh = cc->cwnd;
	cc->in_slow_start = 1;
	cc->in_recovery = 0;
	cc->bytes_in_flight = 0;

	/* Reset algorithm-specific state */
	switch (cc->algo) {
	case QUIC_CC_CUBIC:
		cc->cubic_epoch_start = 0;
		cc->cubic_origin_point = 0;
		cc->cubic_k = 0;
		break;

	case QUIC_CC_BBR:
	case QUIC_CC_BBR2:
		cc->bbr_mode = BBR_MODE_STARTUP;
		cc->bbr_cycle_index = 0;
		/* Keep bandwidth and RTT estimates */
		break;

	default:
		break;
	}

	/* Reset pacing to initial rate */
	cc->pacing_rate = div64_u64(cc->cwnd * USEC_PER_SEC,
				    QUIC_INITIAL_RTT_US);
}
EXPORT_SYMBOL_GPL(quic_cc_on_persistent_congestion);

/*
 * Handle PTO (probe timeout) expiration
 * Per RFC 9002 Section 6.2
 */
void quic_cc_on_pto(struct quic_cc_state *cc)
{
	cc->pto_count++;

	/*
	 * BBR and BBRv2 don't modify cwnd on PTO
	 * Reno and CUBIC also don't modify cwnd on PTO per RFC 9002
	 * The probe packets are sent even if it exceeds cwnd
	 */
}
EXPORT_SYMBOL_GPL(quic_cc_on_pto);

/*
 * Get current congestion control statistics
 */
void quic_cc_get_info(struct quic_cc_state *cc, struct quic_stats *stats)
{
	stats->cwnd = cc->cwnd;
	stats->bytes_in_flight = cc->bytes_in_flight;

	/* Determine congestion state */
	if (cc->in_slow_start)
		stats->congestion_state = 0;	/* Slow start */
	else if (cc->in_recovery)
		stats->congestion_state = 2;	/* Recovery */
	else
		stats->congestion_state = 1;	/* Congestion avoidance */
}
EXPORT_SYMBOL_GPL(quic_cc_get_info);

/*
 * Set application limited state
 * Called when application isn't providing data fast enough
 */
void quic_cc_set_app_limited(struct quic_cc_state *cc, bool limited)
{
	cc->app_limited = limited ? 1 : 0;
}
EXPORT_SYMBOL_GPL(quic_cc_set_app_limited);

/*
 * Check if connection is in slow start
 */
bool quic_cc_in_slow_start(struct quic_cc_state *cc)
{
	return cc->in_slow_start;
}
EXPORT_SYMBOL_GPL(quic_cc_in_slow_start);

/*
 * Check if connection is in recovery
 */
bool quic_cc_in_recovery(struct quic_cc_state *cc)
{
	return cc->in_recovery;
}
EXPORT_SYMBOL_GPL(quic_cc_in_recovery);

/*
 * Exit recovery state manually (e.g., after undo)
 */
void quic_cc_exit_recovery(struct quic_cc_state *cc)
{
	if (!cc->in_recovery)
		return;

	cc->in_recovery = 0;

	/* For CUBIC, reset epoch to allow proper growth */
	if (cc->algo == QUIC_CC_CUBIC) {
		cc->cubic_epoch_start = 0;
	}
}
EXPORT_SYMBOL_GPL(quic_cc_exit_recovery);

/*
 * Get the current congestion window in bytes
 */
u64 quic_cc_get_cwnd(struct quic_cc_state *cc)
{
	return cc->cwnd;
}
EXPORT_SYMBOL_GPL(quic_cc_get_cwnd);

/*
 * Get the current pacing rate in bytes per second
 */
u64 quic_cc_get_pacing_rate(struct quic_cc_state *cc)
{
	return cc->pacing_rate;
}
EXPORT_SYMBOL_GPL(quic_cc_get_pacing_rate);

/*
 * Get the slow start threshold
 */
u64 quic_cc_get_ssthresh(struct quic_cc_state *cc)
{
	return cc->ssthresh;
}
EXPORT_SYMBOL_GPL(quic_cc_get_ssthresh);

/*
 * Get the current bytes in flight
 */
u64 quic_cc_get_bytes_in_flight(struct quic_cc_state *cc)
{
	return cc->bytes_in_flight;
}
EXPORT_SYMBOL_GPL(quic_cc_get_bytes_in_flight);

/*
 * Manually set the congestion window (for testing or special cases)
 */
void quic_cc_set_cwnd(struct quic_cc_state *cc, u64 cwnd)
{
	cc->cwnd = max(cwnd, (u64)QUIC_MIN_CWND);
	cc->congestion_window = cc->cwnd;
}
EXPORT_SYMBOL_GPL(quic_cc_set_cwnd);

/*
 * Change the congestion control algorithm
 */
void quic_cc_set_algo(struct quic_cc_state *cc, enum quic_cc_algo algo)
{
	u64 saved_cwnd = cc->cwnd;
	u64 saved_ssthresh = cc->ssthresh;
	u64 saved_bytes_in_flight = cc->bytes_in_flight;

	/* Re-initialize with new algorithm */
	quic_cc_init(cc, algo);

	/* Restore window state */
	cc->cwnd = saved_cwnd;
	cc->ssthresh = saved_ssthresh;
	cc->bytes_in_flight = saved_bytes_in_flight;
	cc->congestion_window = cc->cwnd;
}
EXPORT_SYMBOL_GPL(quic_cc_set_algo);

/*
 * Debug function to get algorithm name
 */
const char *quic_cc_algo_name(enum quic_cc_algo algo)
{
	switch (algo) {
	case QUIC_CC_RENO:
		return "reno";
	case QUIC_CC_CUBIC:
		return "cubic";
	case QUIC_CC_BBR:
		return "bbr";
	case QUIC_CC_BBR2:
		return "bbr2";
	default:
		return "unknown";
	}
}
EXPORT_SYMBOL_GPL(quic_cc_algo_name);

MODULE_AUTHOR("Linux QUIC Authors");
MODULE_DESCRIPTION("QUIC Congestion Control Implementation");
MODULE_LICENSE("GPL");
