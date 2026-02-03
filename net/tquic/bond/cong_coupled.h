/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * QUIC Coupled Congestion Control for Multipath
 *
 * Based on RFC 6356 (Coupled Congestion Control for MPTCP)
 *
 * Copyright (c) 2024-2026 Linux Foundation
 */

#ifndef _NET_QUIC_CONG_COUPLED_H
#define _NET_QUIC_CONG_COUPLED_H

#include <linux/types.h>
#include <net/tquic.h>

/* Forward declarations */
struct coupled_cc_ctx;
struct tquic_connection;

/* Alpha scaling factor for fixed-point arithmetic */
#define COUPLED_ALPHA_SCALE	1024

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

/**
 * coupled_cc_is_enabled - Check if coupled CC is enabled
 * @ctx: Coupled CC context
 *
 * Returns true if coupled CC is active.
 */
bool coupled_cc_is_enabled(struct coupled_cc_ctx *ctx);

/*
 * ============================================================================
 * Core Coupled CC Operations
 * ============================================================================
 */

/**
 * coupled_cc_increase - Calculate coupled window increase (LIA)
 * @ctx: Coupled CC context
 * @path_id: Path that received ACK
 * @acked_bytes: Bytes acknowledged
 * @mss: Maximum segment size
 *
 * LIA increase formula:
 *   delta = (alpha * bytes_acked * MSS) / total_cwnd
 *
 * Returns: Number of bytes to increase cwnd by
 */
u64 coupled_cc_increase(struct coupled_cc_ctx *ctx, u8 path_id,
			u64 acked_bytes, u32 mss);

/**
 * coupled_cc_decrease - Handle loss event (standard halving)
 * @ctx: Coupled CC context
 * @path_id: Path that detected loss
 *
 * Uses standard AIMD decrease: cwnd = cwnd / 2
 */
void coupled_cc_decrease(struct coupled_cc_ctx *ctx, u8 path_id);

/**
 * coupled_cc_update_rtt - Update RTT for a path
 * @ctx: Coupled CC context
 * @path_id: Path identifier
 * @rtt_us: New RTT sample in microseconds
 *
 * RTT updates trigger alpha recalculation.
 */
void coupled_cc_update_rtt(struct coupled_cc_ctx *ctx, u8 path_id, u64 rtt_us);

/*
 * ============================================================================
 * Path Management
 * ============================================================================
 */

/**
 * coupled_cc_add_path - Add a path to coupled CC tracking
 * @ctx: Coupled CC context
 * @path_id: Path identifier
 * @cwnd: Initial congestion window
 * @rtt_us: Initial RTT in microseconds
 *
 * Returns 0 on success, -EEXIST if path exists, -ENOSPC if at capacity.
 */
int coupled_cc_add_path(struct coupled_cc_ctx *ctx, u8 path_id,
			u64 cwnd, u64 rtt_us);

/**
 * coupled_cc_remove_path - Remove a path from coupled CC tracking
 * @ctx: Coupled CC context
 * @path_id: Path identifier
 */
void coupled_cc_remove_path(struct coupled_cc_ctx *ctx, u8 path_id);

/**
 * coupled_cc_update_path - Update path state
 * @ctx: Coupled CC context
 * @path_id: Path identifier
 * @cwnd: New congestion window
 * @rtt_us: New RTT in microseconds
 */
void coupled_cc_update_path(struct coupled_cc_ctx *ctx, u8 path_id,
			    u64 cwnd, u64 rtt_us);

/*
 * ============================================================================
 * Integration with Base Congestion Control
 * ============================================================================
 */

/**
 * coupled_cc_on_ack - Process ACK with coupled congestion control
 * @ctx: Coupled CC context
 * @cc: Base congestion control state
 * @path_id: Path that received ACK
 * @acked_bytes: Bytes acknowledged
 * @rtt: RTT measurements
 *
 * Wraps base CC on_ack to apply coupled increase during congestion avoidance.
 */
void coupled_cc_on_ack(struct coupled_cc_ctx *ctx, struct tquic_cc_state *cc,
		       u8 path_id, u64 acked_bytes, struct tquic_rtt *rtt);

/**
 * coupled_cc_on_loss - Process loss with coupled congestion control
 * @ctx: Coupled CC context
 * @cc: Base congestion control state
 * @path_id: Path that detected loss
 */
void coupled_cc_on_loss(struct coupled_cc_ctx *ctx, struct tquic_cc_state *cc,
			u8 path_id);

/*
 * ============================================================================
 * OLIA Variant
 * ============================================================================
 */

/**
 * olia_cc_increase - Calculate OLIA window increase
 * @ctx: Coupled CC context
 * @path_id: Path that received ACK
 * @acked_bytes: Bytes acknowledged
 * @mss: Maximum segment size
 *
 * OLIA (Opportunistic LIA) variant that better handles paths with
 * very different RTTs.
 *
 * Returns: Number of bytes to increase cwnd by
 */
u64 olia_cc_increase(struct coupled_cc_ctx *ctx, u8 path_id,
		     u64 acked_bytes, u32 mss);

/*
 * ============================================================================
 * Statistics and Debugging
 * ============================================================================
 */

/**
 * coupled_cc_get_alpha - Get current alpha value
 * @ctx: Coupled CC context
 *
 * Returns alpha scaled by COUPLED_ALPHA_SCALE.
 */
u64 coupled_cc_get_alpha(struct coupled_cc_ctx *ctx);

/**
 * coupled_cc_get_total_cwnd - Get total cwnd across all paths
 * @ctx: Coupled CC context
 *
 * Returns sum of all path congestion windows.
 */
u64 coupled_cc_get_total_cwnd(struct coupled_cc_ctx *ctx);

/**
 * struct coupled_cc_stats - Coupled CC statistics for reporting
 */
struct coupled_cc_stats {
	bool		enabled;
	int		num_paths;
	u64		total_cwnd;
	u64		alpha;
	u64		min_rtt_us;
	u64		max_rtt_us;
	u64		coupled_increases;
	u64		alpha_updates;
};

/**
 * coupled_cc_get_stats - Get current coupled CC statistics
 * @ctx: Coupled CC context
 * @stats: Output statistics structure
 */
void coupled_cc_get_stats(struct coupled_cc_ctx *ctx,
			  struct coupled_cc_stats *stats);

#endif /* _NET_QUIC_CONG_COUPLED_H */
