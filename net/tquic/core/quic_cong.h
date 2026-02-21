/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: Congestion Control Declarations
 *
 * Exposes the tquic_cc_state, tquic_rtt, and tquic_stats types together
 * with the full set of exported CC functions so that out-of-file callers
 * (e.g. quic_loss.c, frame_process.c, tquic_output.c) can call the
 * EXPORT_SYMBOL_GPL functions defined in core/quic_cong.c.
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 */

#ifndef _TQUIC_QUIC_CONG_H
#define _TQUIC_QUIC_CONG_H

#include <linux/types.h>
#include <linux/ktime.h>

/*
 * Congestion control algorithm selector
 */
enum tquic_cc_algo {
	TQUIC_CC_RENO	= 0,
	TQUIC_CC_CUBIC	= 1,
	TQUIC_CC_BBR	= 2,
	TQUIC_CC_BBR2	= 3,
};

/*
 * RTT measurement structure used by the CC layer.
 *
 * Mirrors the local struct inside quic_cong.c.  Any change there MUST be
 * reflected here.
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
 * Congestion control state (per-path).
 *
 * Mirrors the local struct inside quic_cong.c.  Any change there MUST be
 * reflected here.
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
	/* PRR (Proportional Rate Reduction) per RFC 6937 */
	u64		prr_delivered;
	u64		prr_out;
	u64		recov_start_pipe;
	/* BBR specific */
	u64		bbr_bw;
	u64		bbr_min_rtt;
	u64		bbr_full_bw;
	u32		bbr_cycle_index;
	u32		bbr_full_bw_count;
	u8		bbr_mode;
	/* CUBIC specific */
	u64		cubic_k;
	u64		cubic_origin_point;
	ktime_t		cubic_epoch_start;
};

/*
 * CC statistics snapshot for getsockopt / diagnostics
 */
struct tquic_stats {
	u64		cwnd;
	u64		bytes_in_flight;
	u8		congestion_state;
};

/* Lifecycle */
void tquic_cc_init(struct tquic_cc_state *cc, enum tquic_cc_algo algo);
void tquic_cc_set_algo(struct tquic_cc_state *cc, enum tquic_cc_algo algo);
const char *tquic_cc_algo_name(enum tquic_cc_algo algo);

/* Send-path helpers */
bool tquic_cc_can_send(struct tquic_cc_state *cc, u32 bytes);
u64 tquic_cc_pacing_delay(struct tquic_cc_state *cc, u32 bytes);
u64 tquic_cc_prr_get_snd_cnt(struct tquic_cc_state *cc);

/* Event handlers */
void tquic_cc_on_packet_sent(struct tquic_cc_state *cc, u32 bytes);
void tquic_cc_on_ack(struct tquic_cc_state *cc, u64 acked_bytes,
		     struct tquic_rtt *rtt);
void tquic_cc_on_loss(struct tquic_cc_state *cc, u64 lost_bytes);
void tquic_cc_on_congestion_event(struct tquic_cc_state *cc);
void tquic_cc_on_persistent_congestion(struct tquic_cc_state *cc);
void tquic_cc_on_pto(struct tquic_cc_state *cc);

/* State queries */
bool tquic_cc_in_slow_start(struct tquic_cc_state *cc);
bool tquic_cc_in_recovery(struct tquic_cc_state *cc);
void tquic_cc_exit_recovery(struct tquic_cc_state *cc);
u64 tquic_cc_get_cwnd(struct tquic_cc_state *cc);
u64 tquic_cc_get_pacing_rate(struct tquic_cc_state *cc);
u64 tquic_cc_get_ssthresh(struct tquic_cc_state *cc);
u64 tquic_cc_get_bytes_in_flight(struct tquic_cc_state *cc);

/* Configuration */
void tquic_cc_set_app_limited(struct tquic_cc_state *cc, bool limited);
void tquic_cc_set_cwnd(struct tquic_cc_state *cc, u64 cwnd);

/* Diagnostics */
void tquic_cc_get_info(struct tquic_cc_state *cc, struct tquic_stats *stats);

#endif /* _TQUIC_QUIC_CONG_H */
