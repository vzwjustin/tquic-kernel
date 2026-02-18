/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * QUIC Coupled Congestion Control for Multipath
 *
 * Based on RFC 6356 (Coupled Congestion Control for MPTCP)
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 */

#ifndef _NET_QUIC_CONG_COUPLED_H
#define _NET_QUIC_CONG_COUPLED_H

#include <linux/types.h>
#include <net/tquic.h>

/* Forward declarations */
struct coupled_cc_ctx;
struct tquic_connection;
struct tquic_path;

/* Alpha scaling factor for fixed-point arithmetic */
#define COUPLED_ALPHA_SCALE	1024

/*
 * Congestion control state structure for coupled CC integration.
 * This mirrors the basic CC state used by the congestion control algorithms.
 */
struct tquic_cc_state {
	u64 cwnd;		/* Congestion window in bytes */
	u64 ssthresh;		/* Slow-start threshold */
	u64 bytes_in_flight;	/* Bytes currently in flight */
	bool in_slow_start;	/* True if in slow-start phase */
	bool in_recovery;	/* True if in recovery phase */
	ktime_t recovery_start;	/* Start of recovery period */
};

/*
 * RTT measurement structure for coupled CC integration.
 * Compatible with tquic_rtt_state from include/net/tquic.h
 */
struct tquic_rtt {
	u64 smoothed_rtt;	/* Smoothed RTT in microseconds */
	u64 rtt_var;		/* RTT variance */
	u64 min_rtt;		/* Minimum RTT observed */
	u64 latest_rtt;		/* Most recent RTT sample */
	bool has_sample;	/* True if RTT sample is valid */
};

/*
 * ============================================================================
 * Context Lifecycle
 * ============================================================================
 */

/**
 * coupled_cc_alloc - Allocate coupled CC context
 * @conn: TQUIC connection
 * @gfp: Memory allocation flags
 *
 * Returns allocated context or NULL on failure.
 */
struct coupled_cc_ctx *coupled_cc_alloc(struct tquic_connection *conn, gfp_t gfp);

/**
 * coupled_cc_free - Free coupled CC context
 * @ctx: Context to free
 */
void coupled_cc_free(struct coupled_cc_ctx *ctx);

/**
 * coupled_cc_enable - Enable coupled congestion control
 * @ctx: Coupled CC context
 *
 * Called when entering multipath mode (2+ paths active).
 */
void coupled_cc_enable(struct coupled_cc_ctx *ctx);

/**
 * coupled_cc_disable - Disable coupled congestion control
 * @ctx: Coupled CC context
 *
 * Called when returning to single-path mode.
 */
void coupled_cc_disable(struct coupled_cc_ctx *ctx);

#endif /* _NET_QUIC_CONG_COUPLED_H */
