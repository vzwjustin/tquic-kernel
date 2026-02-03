// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * TQUIC Congestion Control
 *
 * Implementation of congestion control algorithms for TQUIC
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
#include <net/tquic.h>

/*
 * Maximum packet size constant
 * Per RFC 9000, the minimum Initial packet size is 1200 bytes.
 * We use 1500 for Ethernet MTU compatibility.
 */
#define TQUIC_MAX_PACKET_SIZE		1500

/*
 * TQUIC congestion control algorithms
 */
enum tquic_cc_algo {
	TQUIC_CC_RENO	= 0,
	TQUIC_CC_CUBIC	= 1,
	TQUIC_CC_BBR	= 2,
	TQUIC_CC_BBR2	= 3,
};

/*
 * TQUIC RTT measurement structure
 */
struct tquic_rtt {
	u32		latest_rtt;
	u32		min_rtt;
	u32		smoothed_rtt;
	u32		rttvar;
	ktime_t		first_rtt_sample;
	u8		has_sample:1;
};

/*
 * TQUIC congestion control state
 */
struct tquic_cc_state {
	u64		cwnd;
	u64		ssthresh;
	u64		bytes_in_flight;
	u64		congestion_window;
	u64		pacing_rate;
	u64		last_sent_time;
	ktime_t		congestion_recovery_start;
	u32		pto_count;
	u32		loss_burst_count;
	u8		in_slow_start:1;
	u8		in_recovery:1;
	u8		app_limited:1;
	enum tquic_cc_algo algo;
	/*
	 * PRR (Proportional Rate Reduction) state per RFC 6937
	 * Smoothly reduces cwnd during loss recovery instead of halving
	 * immediately. Tracks bytes delivered and sent during recovery
	 * to proportionally allow new transmissions.
	 */
	u64		prr_delivered;		/* Bytes delivered since loss */
	u64		prr_out;		/* Bytes sent since loss */
	u64		recov_start_pipe;	/* Bytes in flight at recovery start */
	/* BBR specific */
	u64		bbr_bw;
	u64		bbr_min_rtt;
	u64		bbr_full_bw;		/* Full bandwidth estimate for startup exit */
	u32		bbr_cycle_index;
	u32		bbr_full_bw_count;	/* Count of rounds without BW increase */
	u8		bbr_mode;
	/* CUBIC specific */
	u64		cubic_k;
	u64		cubic_origin_point;
	ktime_t		cubic_epoch_start;
};

/*
 * TQUIC statistics for congestion control
 */
struct tquic_stats {
	u64		cwnd;
	u64		bytes_in_flight;
	u8		congestion_state;
};

/* RFC 9002 constants */
#define TQUIC_INITIAL_CWND_PACKETS	10
#define TQUIC_INITIAL_CWND_MIN		(2 * TQUIC_MAX_PACKET_SIZE)
#define TQUIC_MIN_CWND			(2 * TQUIC_MAX_PACKET_SIZE)
#define TQUIC_LOSS_REDUCTION_FACTOR	2	/* Reno: cwnd / 2 */

/*
 * PRR (Proportional Rate Reduction) per RFC 6937
 * Smoothly reduces cwnd during loss recovery instead of halving immediately
 */
#define PRR_SSTHRESH_REDUCTION		2	/* ssthresh = cwnd/2 for PRR */

/* Default initial RTT (333ms per RFC 9002) */
#define TQUIC_INITIAL_RTT_MS		333
#define TQUIC_INITIAL_RTT_US		(TQUIC_INITIAL_RTT_MS * 1000)

/* Pacing constants */
#define TQUIC_PACING_MULTIPLIER_NUM	5
#define TQUIC_PACING_MULTIPLIER_DEN	4	/* 1.25x pacing */

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
#define BBR_PROBE_RTT_CWND		(4 * TQUIC_MAX_PACKET_SIZE)
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
void tquic_cc_init(struct tquic_cc_state *cc, enum tquic_cc_algo algo)
{
	memset(cc, 0, sizeof(*cc));

	cc->algo = algo;

	/* RFC 9002: Initial window is min(10 * max_datagram_size, max(14720, 2 * max_datagram_size)) */
	cc->cwnd = min_t(u64, TQUIC_INITIAL_CWND_PACKETS * TQUIC_MAX_PACKET_SIZE,
			 max_t(u64, 14720, TQUIC_INITIAL_CWND_MIN));
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

	/* PRR state initialization */
	cc->prr_delivered = 0;
	cc->prr_out = 0;
	cc->recov_start_pipe = 0;

	/* Algorithm-specific initialization */
	switch (algo) {
	case TQUIC_CC_RENO:
		/* Reno uses default values */
		break;

	case TQUIC_CC_CUBIC:
		cc->cubic_k = 0;
		cc->cubic_origin_point = 0;
		cc->cubic_epoch_start = 0;
		break;

	case TQUIC_CC_BBR:
	case TQUIC_CC_BBR2:
		cc->bbr_mode = BBR_MODE_STARTUP;
		cc->bbr_bw = 0;
		cc->bbr_min_rtt = U64_MAX;
		cc->bbr_cycle_index = 0;
		cc->bbr_full_bw = 0;
		cc->bbr_full_bw_count = 0;
		/* Initial pacing rate based on initial cwnd and RTT */
		cc->pacing_rate = div64_u64(cc->cwnd * USEC_PER_SEC,
					    TQUIC_INITIAL_RTT_US);
		break;
	}

	/* Default pacing rate for non-BBR algorithms */
	if (algo != TQUIC_CC_BBR && algo != TQUIC_CC_BBR2) {
		cc->pacing_rate = div64_u64(cc->cwnd * USEC_PER_SEC,
					    TQUIC_INITIAL_RTT_US);
	}
}
EXPORT_SYMBOL_GPL(tquic_cc_init);

/*
 * Handle packet sent event
 * Updates bytes in flight tracking
 */
void tquic_cc_on_packet_sent(struct tquic_cc_state *cc, u32 bytes)
{
	cc->bytes_in_flight += bytes;
	cc->last_sent_time = ktime_get_ns();

	/* PRR: Track bytes sent during recovery */
	if (cc->in_recovery)
		cc->prr_out += bytes;

	/* Track if we're application limited */
	if (cc->bytes_in_flight < cc->cwnd)
		cc->app_limited = 1;
	else
		cc->app_limited = 0;
}
EXPORT_SYMBOL_GPL(tquic_cc_on_packet_sent);

/*
 * Reno congestion avoidance: additive increase
 * Increases cwnd by 1 MSS per RTT during congestion avoidance
 */
static void reno_on_ack(struct tquic_cc_state *cc, u64 acked_bytes,
			struct tquic_rtt *rtt)
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
		cc->cwnd += div64_u64((u64)acked_bytes * TQUIC_MAX_PACKET_SIZE,
				      cc->cwnd);
	}

	cc->congestion_window = cc->cwnd;
}

/*
 * CUBIC congestion control on ACK
 * Implements the CUBIC window growth function
 */
static void cubic_on_ack(struct tquic_cc_state *cc, u64 acked_bytes,
			 struct tquic_rtt *rtt)
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
					 (u64)TQUIC_MAX_PACKET_SIZE * CUBIC_C);
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
	delta = div64_u64(delta * CUBIC_C * TQUIC_MAX_PACKET_SIZE,
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
			   rtt_count * TQUIC_MAX_PACKET_SIZE *
			   (CUBIC_BETA_SCALE + CUBIC_BETA) /
			   (CUBIC_BETA_SCALE * 2);

		target_cwnd = max(target_cwnd, tcp_cwnd);
	}

	/* Don't grow faster than 1 MSS per ACK */
	if (target_cwnd > cc->cwnd + acked_bytes)
		target_cwnd = cc->cwnd + acked_bytes;

	cc->cwnd = max(target_cwnd, (u64)TQUIC_MIN_CWND);
	cc->congestion_window = cc->cwnd;
}

/*
 * Update BBR bandwidth estimate
 * Maintains a windowed maximum of delivery rate samples
 */
static void bbr_update_bw(struct tquic_cc_state *cc, u64 acked_bytes,
			  struct tquic_rtt *rtt)
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
static void bbr_update_min_rtt(struct tquic_cc_state *cc, struct tquic_rtt *rtt)
{
	if (!rtt->has_sample)
		return;

	if (rtt->latest_rtt < cc->bbr_min_rtt || cc->bbr_min_rtt == U64_MAX)
		cc->bbr_min_rtt = rtt->latest_rtt;
}

/*
 * BBR state machine transition
 *
 * Note: full_bw and full_bw_count are stored per-connection in cc->bbr_full_bw
 * and cc->bbr_full_bw_count to avoid data races between concurrent connections.
 */
static void bbr_check_state_transition(struct tquic_cc_state *cc,
				       struct tquic_rtt *rtt)
{
	switch (cc->bbr_mode) {
	case BBR_MODE_STARTUP:
		/* Check if we've filled the pipe */
		if (cc->bbr_bw > 0) {
			u64 thresh = (cc->bbr_full_bw * BBR_FULL_BW_THRESH) >> BBR_SCALE;
			if (cc->bbr_bw >= thresh) {
				cc->bbr_full_bw = cc->bbr_bw;
				cc->bbr_full_bw_count = 0;
			} else {
				cc->bbr_full_bw_count++;
				if (cc->bbr_full_bw_count >= BBR_FULL_BW_CNT) {
					cc->bbr_mode = BBR_MODE_DRAIN;
					cc->bbr_full_bw_count = 0;
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
static void bbr_on_ack(struct tquic_cc_state *cc, u64 acked_bytes,
		       struct tquic_rtt *rtt)
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
	cc->cwnd = max(cc->cwnd, (u64)TQUIC_MIN_CWND);

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
static void bbr2_on_ack(struct tquic_cc_state *cc, u64 acked_bytes,
			struct tquic_rtt *rtt)
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

	cc->cwnd = max(cc->cwnd, (u64)TQUIC_MIN_CWND);

	if (cc->bbr_mode == BBR_MODE_PROBE_RTT) {
		u64 probe_cwnd = (bdp * BBR2_PROBE_RTT_CWND_GAIN) >> BBR_SCALE;
		cc->cwnd = max(probe_cwnd, (u64)TQUIC_MIN_CWND);
	}

	cc->congestion_window = cc->cwnd;

	/* Update pacing rate */
	cc->pacing_rate = (cc->bbr_bw * pacing_gain) >> BBR_SCALE;
}

/*
 * Handle acknowledgment of data
 * This is the main entry point for congestion control when packets are ACKed
 */
void tquic_cc_on_ack(struct tquic_cc_state *cc, u64 acked_bytes,
		    struct tquic_rtt *rtt)
{
	/*
	 * PRR: Track bytes delivered during recovery (RFC 6937)
	 * Must be done before updating bytes_in_flight
	 */
	if (cc->in_recovery)
		cc->prr_delivered += acked_bytes;

	/* Exit recovery if we've acknowledged all data from recovery start */
	if (cc->in_recovery && cc->bytes_in_flight == 0) {
		cc->in_recovery = 0;
		/* Reset PRR state on recovery exit */
		cc->prr_delivered = 0;
		cc->prr_out = 0;
		cc->recov_start_pipe = 0;
	}

	/* Update bytes in flight */
	if (acked_bytes <= cc->bytes_in_flight)
		cc->bytes_in_flight -= acked_bytes;
	else
		cc->bytes_in_flight = 0;

	/* Algorithm-specific handling */
	switch (cc->algo) {
	case TQUIC_CC_RENO:
		reno_on_ack(cc, acked_bytes, rtt);
		break;

	case TQUIC_CC_CUBIC:
		cubic_on_ack(cc, acked_bytes, rtt);
		break;

	case TQUIC_CC_BBR:
		bbr_on_ack(cc, acked_bytes, rtt);
		break;

	case TQUIC_CC_BBR2:
		bbr2_on_ack(cc, acked_bytes, rtt);
		break;
	}

	/* Update pacing rate for Reno and CUBIC */
	if (cc->algo == TQUIC_CC_RENO || cc->algo == TQUIC_CC_CUBIC) {
		if (rtt->smoothed_rtt > 0) {
			cc->pacing_rate = div64_u64(cc->cwnd * USEC_PER_SEC *
						    TQUIC_PACING_MULTIPLIER_NUM,
						    rtt->smoothed_rtt *
						    TQUIC_PACING_MULTIPLIER_DEN);
		}
	}
}
EXPORT_SYMBOL_GPL(tquic_cc_on_ack);

/*
 * Handle packet loss
 * RFC 9002: On loss, reduce congestion window
 * RFC 6937: Use PRR for smooth cwnd reduction during recovery
 */
void tquic_cc_on_loss(struct tquic_cc_state *cc, u64 lost_bytes)
{
	ktime_t now = ktime_get();

	cc->loss_burst_count++;

	/* Don't reduce cwnd if already in recovery */
	if (cc->in_recovery)
		return;

	/* Enter recovery */
	cc->in_recovery = 1;
	cc->congestion_recovery_start = now;

	/*
	 * PRR initialization (RFC 6937)
	 * Record pipe (bytes in flight) at start of recovery
	 * Reset PRR counters for new recovery episode
	 */
	cc->recov_start_pipe = cc->bytes_in_flight;
	cc->prr_delivered = 0;
	cc->prr_out = 0;

	switch (cc->algo) {
	case TQUIC_CC_RENO:
		/*
		 * RFC 9002: ssthresh = cwnd / 2
		 * With PRR, we don't immediately set cwnd = ssthresh.
		 * Instead, cwnd remains high and PRR limits sending.
		 */
		cc->ssthresh = max(cc->cwnd / TQUIC_LOSS_REDUCTION_FACTOR,
				   (u64)TQUIC_MIN_CWND);
		/* PRR: Keep cwnd high during recovery, limit by PRR calc */
		cc->in_slow_start = 0;
		break;

	case TQUIC_CC_CUBIC:
		/* CUBIC uses beta = 0.7 for ssthresh */
		cc->ssthresh = (cc->cwnd * CUBIC_BETA) / CUBIC_BETA_SCALE;
		cc->ssthresh = max(cc->ssthresh, (u64)TQUIC_MIN_CWND);
		/* PRR: Keep cwnd, limit sending by PRR calculation */
		cc->in_slow_start = 0;
		/* Reset CUBIC state for when recovery ends */
		cc->cubic_origin_point = cc->ssthresh;
		cc->cubic_epoch_start = 0;
		cc->cubic_k = 0;
		break;

	case TQUIC_CC_BBR:
		/* BBR doesn't reduce cwnd on loss during normal operation */
		/* Only track the loss for bandwidth estimation */
		break;

	case TQUIC_CC_BBR2:
		/* BBRv2 responds to loss more aggressively */
		if (cc->bbr_mode != BBR_MODE_PROBE_RTT) {
			u64 bdp = 0;
			if (cc->bbr_bw > 0 && cc->bbr_min_rtt < U64_MAX)
				bdp = div64_u64(cc->bbr_bw * cc->bbr_min_rtt,
						USEC_PER_SEC);
			/* Reduce cwnd to inflight_lo */
			cc->cwnd = (bdp * BBR2_INFLIGHT_LO_SCALE) >> BBR_SCALE;
			cc->cwnd = max(cc->cwnd, (u64)TQUIC_MIN_CWND);
		}
		break;
	}

	cc->congestion_window = cc->cwnd;

	/* Update pacing rate */
	if (cc->algo == TQUIC_CC_RENO || cc->algo == TQUIC_CC_CUBIC) {
		cc->pacing_rate = div64_u64(cc->cwnd * USEC_PER_SEC *
					    TQUIC_PACING_MULTIPLIER_NUM,
					    TQUIC_INITIAL_RTT_US *
					    TQUIC_PACING_MULTIPLIER_DEN);
	}
}
EXPORT_SYMBOL_GPL(tquic_cc_on_loss);

/*
 * Handle congestion event (ECN CE marking)
 * Similar to loss handling per RFC 9002
 */
void tquic_cc_on_congestion_event(struct tquic_cc_state *cc)
{
	ktime_t now = ktime_get();

	/* Don't respond if already in recovery */
	if (cc->in_recovery)
		return;

	/* Enter recovery */
	cc->in_recovery = 1;
	cc->congestion_recovery_start = now;

	switch (cc->algo) {
	case TQUIC_CC_RENO:
		cc->ssthresh = max(cc->cwnd / TQUIC_LOSS_REDUCTION_FACTOR,
				   (u64)TQUIC_MIN_CWND);
		cc->cwnd = cc->ssthresh;
		cc->in_slow_start = 0;
		break;

	case TQUIC_CC_CUBIC:
		cc->ssthresh = (cc->cwnd * CUBIC_BETA) / CUBIC_BETA_SCALE;
		cc->ssthresh = max(cc->ssthresh, (u64)TQUIC_MIN_CWND);
		cc->cwnd = cc->ssthresh;
		cc->in_slow_start = 0;
		cc->cubic_origin_point = cc->ssthresh;
		cc->cubic_epoch_start = 0;
		cc->cubic_k = 0;
		break;

	case TQUIC_CC_BBR:
		/* BBR treats ECN similarly to loss for the drain mechanism */
		if (cc->bbr_mode == BBR_MODE_STARTUP)
			cc->bbr_mode = BBR_MODE_DRAIN;
		break;

	case TQUIC_CC_BBR2:
		/* BBRv2 uses ECN to reduce inflight */
		if (cc->bbr_bw > 0 && cc->bbr_min_rtt < U64_MAX) {
			u64 bdp = div64_u64(cc->bbr_bw * cc->bbr_min_rtt,
					    USEC_PER_SEC);
			cc->cwnd = (bdp * BBR2_INFLIGHT_LO_SCALE) >> BBR_SCALE;
			cc->cwnd = max(cc->cwnd, (u64)TQUIC_MIN_CWND);
		}
		if (cc->bbr_mode == BBR_MODE_STARTUP)
			cc->bbr_mode = BBR_MODE_DRAIN;
		break;
	}

	cc->congestion_window = cc->cwnd;
}
EXPORT_SYMBOL_GPL(tquic_cc_on_congestion_event);

/*
 * Calculate pacing delay for sending the next packet
 * Returns delay in nanoseconds
 */
u64 tquic_cc_pacing_delay(struct tquic_cc_state *cc, u32 bytes)
{
	u64 delay_ns;

	if (cc->pacing_rate == 0)
		return 0;

	/* delay = bytes / pacing_rate (pacing_rate is in bytes/sec) */
	delay_ns = div64_u64((u64)bytes * NSEC_PER_SEC, cc->pacing_rate);

	/* During slow start, pace more aggressively */
	if (cc->in_slow_start && (cc->algo == TQUIC_CC_RENO ||
				  cc->algo == TQUIC_CC_CUBIC)) {
		delay_ns = delay_ns / 2;
	}

	return delay_ns;
}
EXPORT_SYMBOL_GPL(tquic_cc_pacing_delay);

/*
 * PRR: Calculate how many bytes can be sent during recovery
 * Implements RFC 6937 Proportional Rate Reduction
 *
 * Returns the number of bytes allowed to send. The caller should
 * use this to limit transmission during loss recovery.
 *
 * Algorithm (RFC 6937 Section 4):
 *   snd_cnt = CEIL(prr_delivered * ssthresh / recov_start_pipe) - prr_out
 *
 * This ensures sending is proportional to ACKs received, converging
 * smoothly to ssthresh by the end of recovery.
 */
u64 tquic_cc_prr_get_snd_cnt(struct tquic_cc_state *cc)
{
	u64 snd_cnt;
	u64 pipe;		/* Current bytes in flight */
	u64 prr_target;		/* Target based on proportional reduction */

	/* PRR only applies during recovery for Reno/CUBIC */
	if (!cc->in_recovery)
		return U64_MAX;	/* No limit outside recovery */

	/* BBR/BBRv2 don't use PRR */
	if (cc->algo == TQUIC_CC_BBR || cc->algo == TQUIC_CC_BBR2)
		return U64_MAX;

	pipe = cc->bytes_in_flight;

	/*
	 * Guard against division by zero.
	 * If recov_start_pipe is 0, we're in a degenerate state.
	 */
	if (cc->recov_start_pipe == 0)
		return TQUIC_MAX_PACKET_SIZE;

	/*
	 * RFC 6937 PRR-SSRB (Slow Start Reduction Bound):
	 * prr_target = CEIL(prr_delivered * ssthresh / recov_start_pipe)
	 * snd_cnt = prr_target - prr_out
	 *
	 * Use DIV_ROUND_UP equivalent for ceiling division
	 */
	prr_target = div64_u64(cc->prr_delivered * cc->ssthresh +
			       cc->recov_start_pipe - 1,
			       cc->recov_start_pipe);

	if (prr_target > cc->prr_out)
		snd_cnt = prr_target - cc->prr_out;
	else
		snd_cnt = 0;

	/*
	 * RFC 6937 Section 4.2: PRR-SSRB modification
	 * If pipe < ssthresh, we can send more aggressively to reach ssthresh.
	 * limit = max(prr_target - prr_out, 1) to ensure at least 1 MSS.
	 */
	if (pipe < cc->ssthresh) {
		u64 deficit = cc->ssthresh - pipe;
		/*
		 * Allow at least 1 MSS when below ssthresh to ensure recovery
		 * can make forward progress.
		 */
		snd_cnt = max_t(u64, snd_cnt, min(deficit, (u64)TQUIC_MAX_PACKET_SIZE));
	}

	/*
	 * Ensure at least 1 MSS can be sent per ACK to avoid stalls.
	 * This is the "Reduction Bound" part of PRR-SSRB.
	 */
	if (snd_cnt == 0 && cc->prr_delivered > 0)
		snd_cnt = TQUIC_MAX_PACKET_SIZE;

	return snd_cnt;
}
EXPORT_SYMBOL_GPL(tquic_cc_prr_get_snd_cnt);

/*
 * Check if congestion control allows sending
 * Returns true if the given number of bytes can be sent
 */
bool tquic_cc_can_send(struct tquic_cc_state *cc, u32 bytes)
{
	/* Always allow at least one packet (for probes, PTO, etc.) */
	if (bytes <= TQUIC_MAX_PACKET_SIZE && cc->bytes_in_flight == 0)
		return true;

	/*
	 * PRR: During recovery, use PRR to limit sending
	 * This provides smooth cwnd reduction per RFC 6937
	 */
	if (cc->in_recovery && (cc->algo == TQUIC_CC_RENO ||
				cc->algo == TQUIC_CC_CUBIC)) {
		u64 snd_cnt = tquic_cc_prr_get_snd_cnt(cc);
		return bytes <= snd_cnt;
	}

	/* Check against congestion window */
	if (cc->bytes_in_flight + bytes <= cc->cwnd)
		return true;

	/* BBR modes may have different rules */
	if (cc->algo == TQUIC_CC_BBR || cc->algo == TQUIC_CC_BBR2) {
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
EXPORT_SYMBOL_GPL(tquic_cc_can_send);

/*
 * Reset congestion state after persistent congestion
 * Per RFC 9002 Section 7.6.2
 */
void tquic_cc_on_persistent_congestion(struct tquic_cc_state *cc)
{
	/* Reset to minimum window */
	cc->cwnd = TQUIC_MIN_CWND;
	cc->congestion_window = cc->cwnd;
	cc->ssthresh = cc->cwnd;
	cc->in_slow_start = 1;
	cc->in_recovery = 0;
	cc->bytes_in_flight = 0;

	/* Reset PRR state */
	cc->prr_delivered = 0;
	cc->prr_out = 0;
	cc->recov_start_pipe = 0;

	/* Reset algorithm-specific state */
	switch (cc->algo) {
	case TQUIC_CC_CUBIC:
		cc->cubic_epoch_start = 0;
		cc->cubic_origin_point = 0;
		cc->cubic_k = 0;
		break;

	case TQUIC_CC_BBR:
	case TQUIC_CC_BBR2:
		cc->bbr_mode = BBR_MODE_STARTUP;
		cc->bbr_cycle_index = 0;
		cc->bbr_full_bw = 0;
		cc->bbr_full_bw_count = 0;
		/* Keep bandwidth and RTT estimates */
		break;

	default:
		break;
	}

	/* Reset pacing to initial rate */
	cc->pacing_rate = div64_u64(cc->cwnd * USEC_PER_SEC,
				    TQUIC_INITIAL_RTT_US);
}
EXPORT_SYMBOL_GPL(tquic_cc_on_persistent_congestion);

/*
 * Handle PTO (probe timeout) expiration
 * Per RFC 9002 Section 6.2
 */
void tquic_cc_on_pto(struct tquic_cc_state *cc)
{
	cc->pto_count++;

	/*
	 * BBR and BBRv2 don't modify cwnd on PTO
	 * Reno and CUBIC also don't modify cwnd on PTO per RFC 9002
	 * The probe packets are sent even if it exceeds cwnd
	 */
}
EXPORT_SYMBOL_GPL(tquic_cc_on_pto);

/*
 * Get current congestion control statistics
 */
void tquic_cc_get_info(struct tquic_cc_state *cc, struct tquic_stats *stats)
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
EXPORT_SYMBOL_GPL(tquic_cc_get_info);

/*
 * Set application limited state
 * Called when application isn't providing data fast enough
 */
void tquic_cc_set_app_limited(struct tquic_cc_state *cc, bool limited)
{
	cc->app_limited = limited ? 1 : 0;
}
EXPORT_SYMBOL_GPL(tquic_cc_set_app_limited);

/*
 * Check if connection is in slow start
 */
bool tquic_cc_in_slow_start(struct tquic_cc_state *cc)
{
	return cc->in_slow_start;
}
EXPORT_SYMBOL_GPL(tquic_cc_in_slow_start);

/*
 * Check if connection is in recovery
 */
bool tquic_cc_in_recovery(struct tquic_cc_state *cc)
{
	return cc->in_recovery;
}
EXPORT_SYMBOL_GPL(tquic_cc_in_recovery);

/*
 * Exit recovery state manually (e.g., after undo)
 */
void tquic_cc_exit_recovery(struct tquic_cc_state *cc)
{
	if (!cc->in_recovery)
		return;

	cc->in_recovery = 0;

	/* Reset PRR state */
	cc->prr_delivered = 0;
	cc->prr_out = 0;
	cc->recov_start_pipe = 0;

	/*
	 * Set cwnd to ssthresh on recovery exit.
	 * PRR has gradually reduced the effective sending rate,
	 * now make cwnd match the target.
	 */
	if (cc->algo == TQUIC_CC_RENO || cc->algo == TQUIC_CC_CUBIC) {
		cc->cwnd = cc->ssthresh;
		cc->congestion_window = cc->cwnd;
	}

	/* For CUBIC, reset epoch to allow proper growth */
	if (cc->algo == TQUIC_CC_CUBIC) {
		cc->cubic_epoch_start = 0;
	}
}
EXPORT_SYMBOL_GPL(tquic_cc_exit_recovery);

/*
 * Get the current congestion window in bytes
 */
u64 tquic_cc_get_cwnd(struct tquic_cc_state *cc)
{
	return cc->cwnd;
}
EXPORT_SYMBOL_GPL(tquic_cc_get_cwnd);

/*
 * Get the current pacing rate in bytes per second
 */
u64 tquic_cc_get_pacing_rate(struct tquic_cc_state *cc)
{
	return cc->pacing_rate;
}
EXPORT_SYMBOL_GPL(tquic_cc_get_pacing_rate);

/*
 * Get the slow start threshold
 */
u64 tquic_cc_get_ssthresh(struct tquic_cc_state *cc)
{
	return cc->ssthresh;
}
EXPORT_SYMBOL_GPL(tquic_cc_get_ssthresh);

/*
 * Get the current bytes in flight
 */
u64 tquic_cc_get_bytes_in_flight(struct tquic_cc_state *cc)
{
	return cc->bytes_in_flight;
}
EXPORT_SYMBOL_GPL(tquic_cc_get_bytes_in_flight);

/*
 * Manually set the congestion window (for testing or special cases)
 */
void tquic_cc_set_cwnd(struct tquic_cc_state *cc, u64 cwnd)
{
	cc->cwnd = max(cwnd, (u64)TQUIC_MIN_CWND);
	cc->congestion_window = cc->cwnd;
}
EXPORT_SYMBOL_GPL(tquic_cc_set_cwnd);

/*
 * Change the congestion control algorithm
 */
void tquic_cc_set_algo(struct tquic_cc_state *cc, enum tquic_cc_algo algo)
{
	u64 saved_cwnd = cc->cwnd;
	u64 saved_ssthresh = cc->ssthresh;
	u64 saved_bytes_in_flight = cc->bytes_in_flight;

	/* Re-initialize with new algorithm */
	tquic_cc_init(cc, algo);

	/* Restore window state */
	cc->cwnd = saved_cwnd;
	cc->ssthresh = saved_ssthresh;
	cc->bytes_in_flight = saved_bytes_in_flight;
	cc->congestion_window = cc->cwnd;
}
EXPORT_SYMBOL_GPL(tquic_cc_set_algo);

/*
 * Debug function to get algorithm name
 */
const char *tquic_cc_algo_name(enum tquic_cc_algo algo)
{
	switch (algo) {
	case TQUIC_CC_RENO:
		return "reno";
	case TQUIC_CC_CUBIC:
		return "cubic";
	case TQUIC_CC_BBR:
		return "bbr";
	case TQUIC_CC_BBR2:
		return "bbr2";
	default:
		return "unknown";
	}
}
EXPORT_SYMBOL_GPL(tquic_cc_algo_name);

MODULE_AUTHOR("Linux QUIC Authors");
MODULE_DESCRIPTION("TQUIC Congestion Control Implementation");
MODULE_LICENSE("GPL");
