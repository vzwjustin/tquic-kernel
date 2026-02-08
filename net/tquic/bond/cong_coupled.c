// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * QUIC Coupled Congestion Control for Multipath
 *
 * Implementation of coupled congestion control for multipath QUIC connections.
 * Based on RFC 6356 (Coupled Congestion Control for MPTCP) and research papers
 * on multipath congestion control.
 *
 * Without coupling: multipath gets N times bandwidth of single-path TCP
 * With coupling: multipath gets fair share at shared bottleneck
 *
 * This implements the LIA (Linked Increase Algorithm):
 *   - Coupled increase: delta = (alpha * bytes_acked * MSS) / total_cwnd
 *   - Standard decrease: cwnd = cwnd / 2 (on loss)
 *   - Alpha calculation ensures fairness with competing single-path flows
 *
 * References:
 *   - RFC 6356: Coupled Congestion Control for Multipath Transport Protocols
 *   - "Improving Multipath TCP" (SIGCOMM 2011) - Raiciu et al.
 *   - draft-ietf-quic-multipath: Multipath Extension for QUIC
 *
 * Copyright (c) 2024-2026 Linux Foundation
 */

#define pr_fmt(fmt) "TQUIC-CC: " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
#include <linux/math64.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <net/tquic.h>

#include "../multipath/tquic_sched.h"
#include "tquic_bonding.h"
#include "cong_coupled.h"

/*
 * Coupled congestion control constants
 */

/* LIA alpha scaling factor (for fixed-point arithmetic) */
#define COUPLED_ALPHA_SCALE		1024
#define COUPLED_ALPHA_MAX		(COUPLED_ALPHA_SCALE * 4)

/* Maximum packet size for QUIC */
#ifndef QUIC_MAX_PACKET_SIZE
#define QUIC_MAX_PACKET_SIZE		1500
#endif

/* Minimum cwnd to prevent starvation (RFC 6356 recommendation) */
#define COUPLED_MIN_CWND		(2 * QUIC_MAX_PACKET_SIZE)

/* Smoothing factor for alpha calculation (1/8 weight for new sample) */
#define COUPLED_ALPHA_SMOOTHING		8

/* Default initial RTT in microseconds (333ms per RFC 9002) */
#define QUIC_INITIAL_RTT_US		333000

/* Maximum paths for coupled CC */
#define COUPLED_MAX_PATHS		8

/* RTT scaling for fixed-point calculations (microseconds) */
#define RTT_SCALE			1000000ULL

/*
 * Per-path coupled congestion control state
 *
 * This supplements the base tquic_cc_state with multipath-specific data
 * needed for coupled window increase calculations.
 */
struct coupled_path_state {
	u8		path_id;
	u64		cwnd;		/* Current congestion window */
	u64		rtt_us;		/* Smoothed RTT in microseconds */
	u64		capacity;	/* cwnd / rtt (rate) */
	u32		weight;		/* Derived weight (0-1000) */
	bool		active;		/* Path is active for scheduling */
	ktime_t		last_update;	/* Last state update time */
};

/*
 * Connection-level coupled congestion control context
 *
 * This is allocated per-connection when coupled CC is enabled.
 * It maintains aggregate state across all paths for alpha calculation.
 */
struct coupled_cc_ctx {
	spinlock_t		lock;
	bool			enabled;

	/* Aggregate state across all paths */
	u64			total_cwnd;		/* Sum of all path cwnds */
	u64			alpha;			/* LIA alpha parameter (scaled) */
	u64			alpha_smoothed;		/* EWMA of alpha */

	/* Per-path state */
	int			num_paths;
	struct coupled_path_state paths[COUPLED_MAX_PATHS];

	/* RTT statistics for alpha calculation */
	u64			min_rtt_us;		/* Minimum RTT across paths */
	u64			max_rtt_us;		/* Maximum RTT across paths */

	/* Statistics */
	u64			coupled_increases;	/* Count of coupled increases */
	u64			alpha_updates;		/* Count of alpha recalculations */

	/* Back pointer */
	struct tquic_connection	*conn;
};

/*
 * ============================================================================
 * Alpha Calculation (RFC 6356 Section 3.3)
 * ============================================================================
 *
 * The alpha parameter ensures fairness with competing single-path flows.
 * It is computed so that the aggregate rate increase of all subflows
 * is no more aggressive than a single TCP flow.
 *
 * Formula:
 *   alpha = cwnd_total * max(cwnd_i/rtt_i^2) / (sum(cwnd_j/rtt_j))^2
 *
 * Where:
 *   cwnd_total = sum of all path cwnds
 *   rtt_i = smoothed RTT of path i (in microseconds)
 *
 * This ensures that:
 *   1. Paths with better RTT get more bandwidth
 *   2. Total increase is bounded by single-path TCP
 *   3. Paths converge to weighted fair allocation
 */

/**
 * coupled_calc_alpha - Calculate LIA alpha parameter
 * @ctx: Coupled CC context
 *
 * Must be called with ctx->lock held.
 * Updates ctx->alpha with the new value.
 */
static void coupled_calc_alpha(struct coupled_cc_ctx *ctx)
{
	u64 max_cwnd_rtt2 = 0;	/* max(cwnd_i / rtt_i^2) */
	u64 sum_cwnd_rtt = 0;	/* sum(cwnd_j / rtt_j) */
	u64 sum_cwnd_rtt_sq;	/* (sum(cwnd_j / rtt_j))^2 */
	u64 alpha_new;
	int i;

	/* Need at least 2 paths for coupling */
	if (ctx->num_paths < 2 || ctx->total_cwnd == 0) {
		ctx->alpha = COUPLED_ALPHA_SCALE;  /* Uncoupled: alpha = 1 */
		return;
	}

	/* Calculate components for each active path */
	for (i = 0; i < ctx->num_paths; i++) {
		struct coupled_path_state *path = &ctx->paths[i];
		u64 cwnd_rtt;
		u64 cwnd_rtt2;

		if (!path->active || path->cwnd == 0 || path->rtt_us == 0)
			continue;

		/* cwnd_i / rtt_i (scaled by RTT_SCALE for precision) */
		cwnd_rtt = div64_u64(path->cwnd * RTT_SCALE, path->rtt_us);
		sum_cwnd_rtt += cwnd_rtt;

		/* cwnd_i / rtt_i^2 (scaled by RTT_SCALE^2) */
		cwnd_rtt2 = div64_u64(path->cwnd * RTT_SCALE * RTT_SCALE,
				      path->rtt_us * path->rtt_us);
		if (cwnd_rtt2 > max_cwnd_rtt2)
			max_cwnd_rtt2 = cwnd_rtt2;
	}

	/* Avoid division by zero */
	if (sum_cwnd_rtt == 0) {
		ctx->alpha = COUPLED_ALPHA_SCALE;
		return;
	}

	/* (sum(cwnd_j/rtt_j))^2 - need to prevent overflow */
	if (sum_cwnd_rtt > (1ULL << 32)) {
		/* Scale down if too large */
		u64 scale_factor = sum_cwnd_rtt >> 32;
		sum_cwnd_rtt = sum_cwnd_rtt / scale_factor;
		max_cwnd_rtt2 = max_cwnd_rtt2 / scale_factor;
	}
	sum_cwnd_rtt_sq = sum_cwnd_rtt * sum_cwnd_rtt;

	/* Avoid division by zero */
	if (sum_cwnd_rtt_sq == 0) {
		ctx->alpha = COUPLED_ALPHA_SCALE;
		return;
	}

	/*
	 * alpha = cwnd_total * max(cwnd_i/rtt_i^2) / (sum(cwnd_j/rtt_j))^2
	 *
	 * Scale by COUPLED_ALPHA_SCALE for fixed-point representation.
	 * max_cwnd_rtt2 is scaled by RTT_SCALE^2
	 * sum_cwnd_rtt_sq is scaled by RTT_SCALE^2
	 * These cancel out in the division.
	 */
	alpha_new = div64_u64(ctx->total_cwnd * max_cwnd_rtt2 * COUPLED_ALPHA_SCALE,
			      sum_cwnd_rtt_sq);

	/* Clamp alpha to reasonable range */
	if (alpha_new > COUPLED_ALPHA_MAX)
		alpha_new = COUPLED_ALPHA_MAX;
	if (alpha_new == 0)
		alpha_new = 1;  /* Minimum alpha */

	/* Smooth alpha using EWMA */
	if (ctx->alpha_smoothed == 0)
		ctx->alpha_smoothed = alpha_new;
	else
		ctx->alpha_smoothed = (ctx->alpha_smoothed *
				       (COUPLED_ALPHA_SMOOTHING - 1) +
				       alpha_new) / COUPLED_ALPHA_SMOOTHING;

	ctx->alpha = ctx->alpha_smoothed;
	ctx->alpha_updates++;

	pr_debug("alpha updated: raw=%llu smoothed=%llu total_cwnd=%llu paths=%d\n",
		 alpha_new, ctx->alpha, ctx->total_cwnd, ctx->num_paths);
}

/*
 * ============================================================================
 * Path State Management
 * ============================================================================
 */

/**
 * coupled_find_path - Find path state by ID
 * @ctx: Coupled CC context
 * @path_id: Path identifier
 *
 * Returns path state or NULL if not found.
 * Must be called with ctx->lock held.
 */
static struct coupled_path_state *coupled_find_path(struct coupled_cc_ctx *ctx,
						    u8 path_id)
{
	int i;

	for (i = 0; i < ctx->num_paths; i++) {
		if (ctx->paths[i].path_id == path_id)
			return &ctx->paths[i];
	}
	return NULL;
}

/**
 * coupled_cc_add_path - Add a new path to coupled CC
 * @ctx: Coupled CC context
 * @path_id: Path identifier
 * @cwnd: Initial congestion window
 * @rtt_us: Initial RTT in microseconds
 *
 * Returns 0 on success, negative error on failure.
 */
int coupled_cc_add_path(struct coupled_cc_ctx *ctx, u8 path_id,
			u64 cwnd, u64 rtt_us)
{
	struct coupled_path_state *path;

	spin_lock_bh(&ctx->lock);

	/* Check if path already exists */
	path = coupled_find_path(ctx, path_id);
	if (path) {
		spin_unlock_bh(&ctx->lock);
		return -EEXIST;
	}

	/* Check capacity */
	if (ctx->num_paths >= COUPLED_MAX_PATHS) {
		spin_unlock_bh(&ctx->lock);
		return -ENOSPC;
	}

	/* Add new path */
	path = &ctx->paths[ctx->num_paths];
	path->path_id = path_id;
	path->cwnd = cwnd;
	path->rtt_us = rtt_us > 0 ? rtt_us : QUIC_INITIAL_RTT_US;
	path->active = true;
	path->last_update = ktime_get();
	path->capacity = rtt_us > 0 ? div64_u64(cwnd * USEC_PER_SEC, rtt_us) : 0;

	ctx->num_paths++;
	ctx->total_cwnd += cwnd;

	/* Recalculate alpha with new path */
	coupled_calc_alpha(ctx);

	spin_unlock_bh(&ctx->lock);

	pr_debug("path %u added to coupled CC: cwnd=%llu rtt=%llu us\n",
		 path_id, cwnd, rtt_us);

	return 0;
}
EXPORT_SYMBOL_GPL(coupled_cc_add_path);

/**
 * coupled_cc_remove_path - Remove a path from coupled CC
 * @ctx: Coupled CC context
 * @path_id: Path identifier
 */
void coupled_cc_remove_path(struct coupled_cc_ctx *ctx, u8 path_id)
{
	struct coupled_path_state *path;
	int i, idx = -1;

	spin_lock_bh(&ctx->lock);

	/* Find path */
	for (i = 0; i < ctx->num_paths; i++) {
		if (ctx->paths[i].path_id == path_id) {
			idx = i;
			break;
		}
	}

	if (idx < 0) {
		spin_unlock_bh(&ctx->lock);
		return;
	}

	path = &ctx->paths[idx];
	ctx->total_cwnd -= path->cwnd;

	/* Shift remaining paths */
	for (i = idx; i < ctx->num_paths - 1; i++)
		ctx->paths[i] = ctx->paths[i + 1];

	ctx->num_paths--;

	/* Recalculate alpha */
	if (ctx->num_paths > 0)
		coupled_calc_alpha(ctx);

	spin_unlock_bh(&ctx->lock);

	pr_debug("path %u removed from coupled CC\n", path_id);
}
EXPORT_SYMBOL_GPL(coupled_cc_remove_path);

/**
 * coupled_cc_update_path - Update path state after RTT/cwnd change
 * @ctx: Coupled CC context
 * @path_id: Path identifier
 * @cwnd: New congestion window
 * @rtt_us: New RTT in microseconds
 */
void coupled_cc_update_path(struct coupled_cc_ctx *ctx, u8 path_id,
			    u64 cwnd, u64 rtt_us)
{
	struct coupled_path_state *path;
	u64 old_cwnd;
	int i;

	spin_lock_bh(&ctx->lock);

	path = coupled_find_path(ctx, path_id);
	if (!path) {
		spin_unlock_bh(&ctx->lock);
		return;
	}

	old_cwnd = path->cwnd;
	path->cwnd = cwnd;
	if (rtt_us > 0)
		path->rtt_us = rtt_us;
	path->last_update = ktime_get();

	/* Update capacity */
	if (path->rtt_us > 0)
		path->capacity = div64_u64(cwnd * USEC_PER_SEC, path->rtt_us);

	/* Update total cwnd */
	ctx->total_cwnd = ctx->total_cwnd - old_cwnd + cwnd;

	/* Update RTT bounds */
	ctx->min_rtt_us = U64_MAX;
	ctx->max_rtt_us = 0;
	for (i = 0; i < ctx->num_paths; i++) {
		if (ctx->paths[i].active && ctx->paths[i].rtt_us > 0) {
			if (ctx->paths[i].rtt_us < ctx->min_rtt_us)
				ctx->min_rtt_us = ctx->paths[i].rtt_us;
			if (ctx->paths[i].rtt_us > ctx->max_rtt_us)
				ctx->max_rtt_us = ctx->paths[i].rtt_us;
		}
	}

	spin_unlock_bh(&ctx->lock);
}
EXPORT_SYMBOL_GPL(coupled_cc_update_path);

/*
 * ============================================================================
 * Coupled Congestion Control Operations
 * ============================================================================
 */

/**
 * coupled_cc_increase - Calculate coupled window increase
 * @ctx: Coupled CC context
 * @path_id: Path that received ACK
 * @acked_bytes: Bytes acknowledged
 * @mss: Maximum segment size
 *
 * Returns: Number of bytes to increase cwnd by
 *
 * LIA increase formula:
 *   delta = (alpha * bytes_acked * MSS) / total_cwnd
 *
 * This ensures the aggregate increase across all paths is at most
 * what a single TCP flow would achieve.
 */
u64 coupled_cc_increase(struct coupled_cc_ctx *ctx, u8 path_id,
			u64 acked_bytes, u32 mss)
{
	struct coupled_path_state *path;
	u64 increase;

	if (!ctx || !ctx->enabled)
		return acked_bytes;  /* Uncoupled increase */

	spin_lock_bh(&ctx->lock);

	path = coupled_find_path(ctx, path_id);
	if (!path || ctx->total_cwnd == 0) {
		spin_unlock_bh(&ctx->lock);
		return acked_bytes;
	}

	/*
	 * LIA increase: delta = (alpha * bytes_acked * MSS) / total_cwnd
	 *
	 * alpha is scaled by COUPLED_ALPHA_SCALE, so we divide by that.
	 */
	increase = div64_u64((u64)ctx->alpha * acked_bytes * mss,
			     ctx->total_cwnd * COUPLED_ALPHA_SCALE);

	/* Ensure minimum increase of 1 byte per ACK */
	if (increase == 0 && acked_bytes > 0)
		increase = 1;

	/* Update path cwnd */
	path->cwnd += increase;
	ctx->total_cwnd += increase;

	ctx->coupled_increases++;

	spin_unlock_bh(&ctx->lock);

	pr_debug("path %u: coupled increase=%llu (alpha=%llu total_cwnd=%llu acked=%llu)\n",
		 path_id, increase, ctx->alpha, ctx->total_cwnd, acked_bytes);

	return increase;
}
EXPORT_SYMBOL_GPL(coupled_cc_increase);

/**
 * coupled_cc_decrease - Handle loss event (standard halving)
 * @ctx: Coupled CC context
 * @path_id: Path that detected loss
 *
 * LIA uses standard AIMD decrease: cwnd = cwnd / 2
 * This is NOT coupled - each path responds independently to loss.
 */
void coupled_cc_decrease(struct coupled_cc_ctx *ctx, u8 path_id)
{
	struct coupled_path_state *path;
	u64 old_cwnd, new_cwnd;

	if (!ctx || !ctx->enabled)
		return;

	spin_lock_bh(&ctx->lock);

	path = coupled_find_path(ctx, path_id);
	if (!path) {
		spin_unlock_bh(&ctx->lock);
		return;
	}

	old_cwnd = path->cwnd;
	new_cwnd = max(old_cwnd / 2, (u64)COUPLED_MIN_CWND);
	path->cwnd = new_cwnd;

	/* Update total cwnd */
	ctx->total_cwnd = ctx->total_cwnd - old_cwnd + new_cwnd;

	/* Recalculate alpha after loss */
	coupled_calc_alpha(ctx);

	spin_unlock_bh(&ctx->lock);

	pr_debug("path %u: loss response cwnd %llu -> %llu\n",
		 path_id, old_cwnd, new_cwnd);
}
EXPORT_SYMBOL_GPL(coupled_cc_decrease);

/**
 * coupled_cc_update_rtt - Update RTT for a path
 * @ctx: Coupled CC context
 * @path_id: Path identifier
 * @rtt_us: New RTT sample in microseconds
 *
 * RTT updates trigger alpha recalculation since alpha depends on RTT.
 */
void coupled_cc_update_rtt(struct coupled_cc_ctx *ctx, u8 path_id, u64 rtt_us)
{
	struct coupled_path_state *path;

	if (!ctx || !ctx->enabled || rtt_us == 0)
		return;

	spin_lock_bh(&ctx->lock);

	path = coupled_find_path(ctx, path_id);
	if (!path) {
		spin_unlock_bh(&ctx->lock);
		return;
	}

	path->rtt_us = rtt_us;
	path->last_update = ktime_get();

	/* Update capacity estimate */
	if (path->cwnd > 0)
		path->capacity = div64_u64(path->cwnd * USEC_PER_SEC, rtt_us);

	/* Recalculate alpha with new RTT */
	coupled_calc_alpha(ctx);

	spin_unlock_bh(&ctx->lock);
}
EXPORT_SYMBOL_GPL(coupled_cc_update_rtt);

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
struct coupled_cc_ctx *coupled_cc_alloc(struct tquic_connection *conn, gfp_t gfp)
{
	struct coupled_cc_ctx *ctx;

	ctx = kzalloc(sizeof(*ctx), gfp);
	if (!ctx)
		return NULL;

	spin_lock_init(&ctx->lock);
	ctx->conn = conn;
	ctx->enabled = false;
	ctx->alpha = COUPLED_ALPHA_SCALE;  /* Start with alpha = 1 */
	ctx->alpha_smoothed = COUPLED_ALPHA_SCALE;
	ctx->min_rtt_us = U64_MAX;

	pr_debug("coupled CC context allocated\n");

	return ctx;
}
EXPORT_SYMBOL_GPL(coupled_cc_alloc);

/**
 * coupled_cc_free - Free coupled CC context
 * @ctx: Context to free
 */
void coupled_cc_free(struct coupled_cc_ctx *ctx)
{
	if (!ctx)
		return;

	pr_debug("coupled CC freed: increases=%llu alpha_updates=%llu\n",
		 ctx->coupled_increases, ctx->alpha_updates);

	kfree(ctx);
}
EXPORT_SYMBOL_GPL(coupled_cc_free);

/**
 * coupled_cc_enable - Enable coupled congestion control
 * @ctx: Coupled CC context
 *
 * Called when entering multipath mode (2+ paths active).
 */
void coupled_cc_enable(struct coupled_cc_ctx *ctx)
{
	if (!ctx)
		return;

	spin_lock_bh(&ctx->lock);

	if (ctx->enabled) {
		spin_unlock_bh(&ctx->lock);
		return;
	}

	ctx->enabled = true;

	/* Initial alpha calculation */
	coupled_calc_alpha(ctx);

	spin_unlock_bh(&ctx->lock);

	pr_info("coupled CC enabled: %d paths, alpha=%llu\n",
		ctx->num_paths, ctx->alpha);
}
EXPORT_SYMBOL_GPL(coupled_cc_enable);

/**
 * coupled_cc_disable - Disable coupled congestion control
 * @ctx: Coupled CC context
 *
 * Called when returning to single-path mode.
 */
void coupled_cc_disable(struct coupled_cc_ctx *ctx)
{
	if (!ctx)
		return;

	spin_lock_bh(&ctx->lock);
	ctx->enabled = false;
	ctx->alpha = COUPLED_ALPHA_SCALE;
	spin_unlock_bh(&ctx->lock);

	pr_info("coupled CC disabled\n");
}
EXPORT_SYMBOL_GPL(coupled_cc_disable);

/**
 * coupled_cc_is_enabled - Check if coupled CC is enabled
 * @ctx: Coupled CC context
 *
 * Returns true if coupled CC is active.
 */
bool coupled_cc_is_enabled(struct coupled_cc_ctx *ctx)
{
	return ctx && ctx->enabled;
}
EXPORT_SYMBOL_GPL(coupled_cc_is_enabled);

/*
 * ============================================================================
 * Integration with Base Congestion Control
 * ============================================================================
 *
 * These functions integrate coupled CC with the base congestion control
 * algorithms (Reno, CUBIC, BBR). The coupling only affects the increase
 * phase during congestion avoidance.
 */

/**
 * coupled_cc_on_ack - Process ACK with coupled congestion control
 * @ctx: Coupled CC context
 * @cc: Base congestion control state (may be NULL for internal tracking)
 * @path_id: Path that received ACK
 * @acked_bytes: Bytes acknowledged
 * @rtt: RTT measurements (may be NULL if no new RTT sample)
 *
 * This wraps the base CC on_ack to apply coupled increase.
 * If cc is NULL, updates only the internal coupled CC tracking.
 */
void coupled_cc_on_ack(struct coupled_cc_ctx *ctx, struct tquic_cc_state *cc,
		       u8 path_id, u64 acked_bytes, struct tquic_rtt *rtt)
{
	u64 coupled_delta;
	struct coupled_path_state *path_state;

	if (!ctx || !ctx->enabled)
		return;

	/* Update RTT in coupled state if we have a sample */
	if (rtt && rtt->has_sample)
		coupled_cc_update_rtt(ctx, path_id, rtt->smoothed_rtt);

	/* If no base CC state, just update internal tracking */
	if (!cc) {
		spin_lock_bh(&ctx->lock);
		path_state = coupled_find_path(ctx, path_id);
		if (path_state) {
			coupled_cc_update_path(ctx, path_id, path_state->cwnd,
					       rtt ? rtt->smoothed_rtt : 0);
		}
		spin_unlock_bh(&ctx->lock);
		return;
	}

	/* Only couple during congestion avoidance (not slow start) */
	if (cc->in_slow_start) {
		/* Slow start: uncoupled exponential growth */
		coupled_cc_update_path(ctx, path_id, cc->cwnd,
				       rtt ? rtt->smoothed_rtt : 0);
		return;
	}

	/* Calculate coupled increase */
	coupled_delta = coupled_cc_increase(ctx, path_id, acked_bytes,
					    QUIC_MAX_PACKET_SIZE);

	/*
	 * For Reno: uncoupled increase would be (acked * MSS) / cwnd
	 * For CUBIC: use CUBIC's time-based function
	 *
	 * We use the coupled increase instead of the uncoupled one.
	 * The base CC state is updated by the caller after this returns.
	 */

	/* Update path state */
	coupled_cc_update_path(ctx, path_id, cc->cwnd + coupled_delta,
			       rtt ? rtt->smoothed_rtt : 0);
}
EXPORT_SYMBOL_GPL(coupled_cc_on_ack);

/**
 * coupled_cc_on_loss - Process loss with coupled congestion control
 * @ctx: Coupled CC context
 * @cc: Base congestion control state (may be NULL for internal tracking)
 * @path_id: Path that detected loss
 *
 * Loss handling is NOT coupled - each path responds independently.
 * This updates the coupled state to reflect the loss.
 */
void coupled_cc_on_loss(struct coupled_cc_ctx *ctx, struct tquic_cc_state *cc,
			u8 path_id)
{
	if (!ctx || !ctx->enabled)
		return;

	/* Update coupled state with new cwnd after loss */
	coupled_cc_decrease(ctx, path_id);
}
EXPORT_SYMBOL_GPL(coupled_cc_on_loss);

/*
 * ============================================================================
 * Statistics and Debugging
 * ============================================================================
 */

/**
 * coupled_cc_get_stats - Get current coupled CC statistics
 * @ctx: Coupled CC context
 * @stats: Output statistics structure
 */
void coupled_cc_get_stats(struct coupled_cc_ctx *ctx,
			  struct coupled_cc_stats *stats)
{
	if (!ctx || !stats)
		return;

	memset(stats, 0, sizeof(*stats));

	spin_lock_bh(&ctx->lock);

	stats->enabled = ctx->enabled;
	stats->num_paths = ctx->num_paths;
	stats->total_cwnd = ctx->total_cwnd;
	stats->alpha = ctx->alpha;
	stats->min_rtt_us = ctx->min_rtt_us;
	stats->max_rtt_us = ctx->max_rtt_us;
	stats->coupled_increases = ctx->coupled_increases;
	stats->alpha_updates = ctx->alpha_updates;

	spin_unlock_bh(&ctx->lock);
}
EXPORT_SYMBOL_GPL(coupled_cc_get_stats);

/**
 * coupled_cc_get_alpha - Get current alpha value
 * @ctx: Coupled CC context
 *
 * Returns alpha scaled by COUPLED_ALPHA_SCALE.
 */
u64 coupled_cc_get_alpha(struct coupled_cc_ctx *ctx)
{
	u64 alpha;

	if (!ctx)
		return COUPLED_ALPHA_SCALE;

	spin_lock_bh(&ctx->lock);
	alpha = ctx->alpha;
	spin_unlock_bh(&ctx->lock);

	return alpha;
}
EXPORT_SYMBOL_GPL(coupled_cc_get_alpha);

/**
 * coupled_cc_get_total_cwnd - Get total cwnd across all paths
 * @ctx: Coupled CC context
 *
 * Returns sum of all path congestion windows.
 */
u64 coupled_cc_get_total_cwnd(struct coupled_cc_ctx *ctx)
{
	u64 total;

	if (!ctx)
		return 0;

	spin_lock_bh(&ctx->lock);
	total = ctx->total_cwnd;
	spin_unlock_bh(&ctx->lock);

	return total;
}
EXPORT_SYMBOL_GPL(coupled_cc_get_total_cwnd);

/*
 * ============================================================================
 * OLIA (Opportunistic LIA) Variant
 * ============================================================================
 *
 * OLIA improves on LIA by:
 * 1. Being more responsive to path changes
 * 2. Better handling of paths with very different RTTs
 *
 * The key difference is in the increase formula:
 *   delta = (alpha / total_cwnd + epsilon_i) * bytes_acked * MSS
 *
 * Where epsilon_i provides path-specific adjustments.
 */

/**
 * olia_cc_increase - Calculate OLIA window increase
 * @ctx: Coupled CC context
 * @path_id: Path that received ACK
 * @acked_bytes: Bytes acknowledged
 * @mss: Maximum segment size
 *
 * Returns: Number of bytes to increase cwnd by
 */
u64 olia_cc_increase(struct coupled_cc_ctx *ctx, u8 path_id,
		     u64 acked_bytes, u32 mss)
{
	struct coupled_path_state *path;
	u64 increase;
	u64 epsilon;
	u64 best_capacity = 0;
	int best_path_idx = -1;
	int i;

	if (!ctx || !ctx->enabled)
		return acked_bytes;

	spin_lock_bh(&ctx->lock);

	path = coupled_find_path(ctx, path_id);
	if (!path || ctx->total_cwnd == 0) {
		spin_unlock_bh(&ctx->lock);
		return acked_bytes;
	}

	/* Find path with best capacity (max cwnd/rtt) */
	for (i = 0; i < ctx->num_paths; i++) {
		if (ctx->paths[i].active && ctx->paths[i].capacity > best_capacity) {
			best_capacity = ctx->paths[i].capacity;
			best_path_idx = i;
		}
	}

	/*
	 * OLIA epsilon calculation:
	 * - Paths with capacity < max get epsilon > 0 (more aggressive)
	 * - Path with max capacity gets epsilon = 0
	 *
	 * epsilon_i = (max_capacity - capacity_i) / total_capacity^2
	 *
	 * This allows underperforming paths to catch up while
	 * limiting the best path's growth.
	 */
	if (best_path_idx >= 0 && path->capacity < best_capacity &&
	    ctx->total_cwnd > 0) {
		u64 diff = best_capacity - path->capacity;
		u64 total_cap_sq = ctx->total_cwnd * ctx->total_cwnd /
				   (path->rtt_us * path->rtt_us);
		if (total_cap_sq > 0)
			epsilon = div64_u64(diff * COUPLED_ALPHA_SCALE, total_cap_sq);
		else
			epsilon = 0;
	} else {
		epsilon = 0;
	}

	/*
	 * OLIA increase: delta = (alpha/total_cwnd + epsilon) * acked * MSS
	 */
	increase = div64_u64(ctx->alpha * acked_bytes * mss,
			     ctx->total_cwnd * COUPLED_ALPHA_SCALE);
	increase += div64_u64(epsilon * acked_bytes * mss, COUPLED_ALPHA_SCALE);

	if (increase == 0 && acked_bytes > 0)
		increase = 1;

	path->cwnd += increase;
	ctx->total_cwnd += increase;
	ctx->coupled_increases++;

	spin_unlock_bh(&ctx->lock);

	return increase;
}
EXPORT_SYMBOL_GPL(olia_cc_increase);

/*
 * ============================================================================
 * Module Initialization
 * ============================================================================
 */

int __init coupled_cc_init_module(void)
{
	pr_info("TQUIC coupled congestion control initialized\n");
	return 0;
}

void __exit coupled_cc_exit_module(void)
{
	pr_info("TQUIC coupled congestion control unloaded\n");
}

/* Note: module_init/exit handled by main protocol.c */
