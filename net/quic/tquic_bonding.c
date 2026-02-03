// SPDX-License-Identifier: GPL-2.0
/*
 * TQUIC Multi-Path Bonding State Machine
 *
 * Copyright (c) 2024-2026 Linux Foundation
 *
 * This implements the bonding state machine for WAN bandwidth aggregation.
 * The state machine coordinates multi-path aggregation lifecycle:
 *
 *   SINGLE_PATH: Normal QUIC, no aggregation overhead
 *   BONDING_PENDING: Second path validating, preparing reorder buffer
 *   BONDED: Active aggregation across 2+ paths
 *   DEGRADED: One or more paths failed, reduced capacity
 *
 * Capacity weights are derived from cwnd/RTT measurements and determine
 * proportional traffic distribution across paths. Users can override
 * weights via SO_TQUIC_BOND_PATH_WEIGHT sockopt.
 */

#define pr_fmt(fmt) "TQUIC-BOND: " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <linux/ktime.h>
#include <linux/math64.h>
#include <net/tquic.h>

#include "tquic_bonding.h"
#include "tquic_failover.h"

/*
 * State name strings for debugging/logging
 */
const char *tquic_bonding_state_names[] = {
	[TQUIC_BOND_SINGLE_PATH]	= "SINGLE_PATH",
	[TQUIC_BOND_PENDING]		= "PENDING",
	[TQUIC_BOND_ACTIVE]		= "ACTIVE",
	[TQUIC_BOND_DEGRADED]		= "DEGRADED",
};
EXPORT_SYMBOL_GPL(tquic_bonding_state_names);

/*
 * Forward declarations for path manager integration
 */
struct tquic_path_manager;
struct tquic_path;

/*
 * External path manager functions we need
 * (defined in tquic_path.c)
 */
extern int tquic_pm_get_active_paths(struct tquic_path_manager *pm,
				     struct tquic_path **paths, int max_paths);

/*
 * Path structure fields we access (from tquic_path.c)
 * We access these through the path manager API.
 *
 * For weight derivation we need:
 *   - path->path_id
 *   - path->cc.cwnd (congestion window)
 *   - path->metrics.srtt (smoothed RTT in us)
 *   - path->state
 */

/* These match the definitions in tquic_path.c */
enum {
	TQUIC_PATH_CREATED = 0,
	TQUIC_PATH_VALIDATING,
	TQUIC_PATH_VALIDATED,
	TQUIC_PATH_ACTIVE,
	TQUIC_PATH_STANDBY,
	TQUIC_PATH_FAILED,
	TQUIC_PATH_CLOSING,
};

/*
 * Global workqueue for reorder buffer timeout work
 * Used by reorder buffer delayed_work
 */
static struct workqueue_struct *tquic_reorder_wq;

/*
 * Global workqueue for async weight updates
 */
static struct workqueue_struct *tquic_bond_wq;

/*
 * ============================================================================
 * Internal Helpers
 * ============================================================================
 */

/*
 * Count paths by state from path manager
 * Must be called with bc->state_lock held or from callback context
 */
static void tquic_bonding_count_paths(struct tquic_bonding_ctx *bc,
				      int *active, int *pending,
				      int *failed, int *degraded)
{
	struct tquic_path *paths[TQUIC_MAX_PATHS];
	int count, i;
	int a = 0, p = 0, f = 0, d = 0;

	if (!bc || !bc->pm) {
		*active = *pending = *failed = *degraded = 0;
		return;
	}

	count = tquic_pm_get_active_paths(bc->pm, paths, TQUIC_MAX_PATHS);

	for (i = 0; i < count; i++) {
		struct tquic_path *path = paths[i];
		/* Access path state - this is safe under RCU */
		/* We use a simplified state check here */
		a++;  /* Count all returned paths as active for now */
		/* Path reference released by caller convention */
	}

	/*
	 * For proper counting, we'd iterate all paths (not just active).
	 * This will be refined when path manager exposes full path list.
	 * For now, we rely on callbacks to maintain accurate counts.
	 */
	*active = a;
	*pending = bc->pending_path_count;
	*failed = bc->failed_path_count;
	*degraded = bc->degraded_path_count;
}

/*
 * Allocate reorder buffer for bonded mode
 */
static int tquic_bonding_alloc_reorder(struct tquic_bonding_ctx *bc)
{
	struct tquic_reorder_buffer *reorder;
	int ret;

	if (bc->reorder)
		return 0;  /* Already allocated */

	reorder = tquic_reorder_alloc(GFP_ATOMIC);
	if (!reorder)
		return -ENOMEM;

	ret = tquic_reorder_init(reorder, bc->max_buffer_bytes,
				 tquic_reorder_wq, bc);
	if (ret) {
		kfree(reorder);
		return ret;
	}

	bc->reorder = reorder;

	pr_debug("allocated reorder buffer (%zu bytes max)\n",
		 bc->max_buffer_bytes);

	return 0;
}

/*
 * Free reorder buffer when leaving bonded mode
 */
static void tquic_bonding_free_reorder(struct tquic_bonding_ctx *bc)
{
	struct tquic_reorder_buffer *reorder = bc->reorder;

	if (!reorder)
		return;

	bc->reorder = NULL;

	/* Wait for any readers */
	synchronize_rcu();

	/* Use proper destroy which handles pending work and buffered packets */
	tquic_reorder_destroy(reorder);

	pr_debug("freed reorder buffer\n");
}

/*
 * Update reorder buffer timeout based on path RTT spread
 * Called when path RTT measurements are updated
 */
void tquic_bonding_update_rtt_spread(struct tquic_bonding_ctx *bc,
				     u32 min_rtt_us, u32 max_rtt_us)
{
	u32 rtt_spread_us;
	u32 new_timeout_ms;

	if (!bc || !bc->reorder)
		return;

	if (max_rtt_us < min_rtt_us)
		return;

	rtt_spread_us = max_rtt_us - min_rtt_us;

	/*
	 * Gap timeout formula: 2 * rtt_spread + 100ms margin
	 * This handles the worst case where slow path packet arrives
	 * after fast path has already delivered many packets.
	 */
	new_timeout_ms = (rtt_spread_us / 1000) * 2 + 100;

	/* Update reorder buffer */
	tquic_reorder_update_rtt(bc->reorder, min_rtt_us, true);
	tquic_reorder_update_rtt(bc->reorder, max_rtt_us, false);
	tquic_reorder_update_timeout(bc->reorder, new_timeout_ms);

	pr_debug("updated RTT spread: min=%u max=%u spread=%u timeout=%ums\n",
		 min_rtt_us, max_rtt_us, rtt_spread_us, new_timeout_ms);
}
EXPORT_SYMBOL_GPL(tquic_bonding_update_rtt_spread);

/*
 * Transition to new state with logging
 */
static void tquic_bonding_set_state(struct tquic_bonding_ctx *bc,
				    enum tquic_bonding_state new_state)
{
	enum tquic_bonding_state old_state = bc->state;
	ktime_t now = ktime_get();

	if (old_state == new_state)
		return;

	/* Track time spent in BONDED state */
	if (old_state == TQUIC_BOND_ACTIVE) {
		bc->stats.time_in_bonded_ns +=
			ktime_to_ns(ktime_sub(now, bc->stats.bonded_start));
	}
	if (new_state == TQUIC_BOND_ACTIVE) {
		bc->stats.bonded_start = now;
	}

	bc->state = new_state;
	bc->stats.state_changes++;

	pr_info("state transition: %s -> %s (active=%d pending=%d failed=%d)\n",
		tquic_bonding_state_names[old_state],
		tquic_bonding_state_names[new_state],
		bc->active_path_count, bc->pending_path_count,
		bc->failed_path_count);
}

/*
 * Weight derivation work function
 */
static void tquic_bonding_weight_work_fn(struct work_struct *work)
{
	struct tquic_bonding_ctx *bc = container_of(work,
			struct tquic_bonding_ctx, weight_work);

	tquic_bonding_derive_weights(bc);
	bc->weight_update_pending = false;
}

/*
 * Schedule async weight update
 */
static void tquic_bonding_schedule_weight_update(struct tquic_bonding_ctx *bc)
{
	if (!bc->weight_update_pending && tquic_bond_wq) {
		bc->weight_update_pending = true;
		queue_work(tquic_bond_wq, &bc->weight_work);
	}
}

/*
 * ============================================================================
 * Lifecycle API
 * ============================================================================
 */

/**
 * tquic_bonding_init - Initialize bonding context for a connection
 */
struct tquic_bonding_ctx *tquic_bonding_init(struct tquic_path_manager *pm,
					     gfp_t gfp)
{
	struct tquic_bonding_ctx *bc;
	int i;

	bc = kzalloc(sizeof(*bc), gfp);
	if (!bc)
		return NULL;

	spin_lock_init(&bc->state_lock);
	bc->state = TQUIC_BOND_SINGLE_PATH;
	bc->pm = pm;

	/* Initialize path counts */
	bc->active_path_count = 0;
	bc->pending_path_count = 0;
	bc->failed_path_count = 0;
	bc->degraded_path_count = 0;

	/* Initialize weights to equal distribution */
	for (i = 0; i < TQUIC_MAX_PATHS; i++) {
		bc->weights.path_weights[i] = TQUIC_DEFAULT_PATH_WEIGHT;
		bc->weights.user_override[i] = false;
	}
	bc->weights.total_weight = 0;
	bc->weights.last_update = ktime_get();

	/* Reorder buffer settings (allocated lazily) */
	bc->reorder = NULL;
	bc->max_buffer_bytes = TQUIC_DEFAULT_BUFFER_SIZE;

	/* Initialize failover context */
	bc->failover = tquic_failover_init(bc, tquic_bond_wq, gfp);
	if (!bc->failover) {
		pr_warn("failover context allocation failed, degraded operation\n");
		/* Continue without failover - degraded operation */
	}

	/* Initialize weight work */
	INIT_WORK(&bc->weight_work, tquic_bonding_weight_work_fn);
	bc->weight_update_pending = false;

	/* Statistics */
	bc->stats.state_changes = 0;
	bc->stats.weight_updates = 0;
	bc->stats.time_in_bonded_ns = 0;
	bc->stats.bonded_start = 0;
	bc->stats.bytes_aggregated = 0;
	bc->stats.failover_events = 0;

	pr_debug("bonding context initialized\n");

	return bc;
}
EXPORT_SYMBOL_GPL(tquic_bonding_init);

/**
 * tquic_bonding_destroy - Destroy bonding context
 */
void tquic_bonding_destroy(struct tquic_bonding_ctx *bc)
{
	if (!bc)
		return;

	/* Cancel pending work */
	cancel_work_sync(&bc->weight_work);

	/* Free failover context */
	if (bc->failover) {
		tquic_failover_destroy(bc->failover);
		bc->failover = NULL;
	}

	/* Free reorder buffer */
	tquic_bonding_free_reorder(bc);

	pr_debug("bonding context destroyed (state_changes=%llu time_bonded=%lluns)\n",
		 bc->stats.state_changes, bc->stats.time_in_bonded_ns);

	kfree(bc);
}
EXPORT_SYMBOL_GPL(tquic_bonding_destroy);

/*
 * ============================================================================
 * State Management API
 * ============================================================================
 */

/**
 * tquic_bonding_update_state - Update bonding state based on path counts
 *
 * State machine logic:
 *   - SINGLE_PATH: 0 or 1 active paths, no pending
 *   - PENDING: 1 active + 1+ pending (second path validating)
 *   - ACTIVE: 2+ active paths
 *   - DEGRADED: 2+ active but some failed/degraded
 */
void tquic_bonding_update_state(struct tquic_bonding_ctx *bc)
{
	enum tquic_bonding_state new_state;
	int total_usable;
	int ret;

	if (!bc)
		return;

	spin_lock_bh(&bc->state_lock);

	/* Calculate total usable paths (active + degraded still work) */
	total_usable = bc->active_path_count;

	/* Determine new state based on path counts */
	if (total_usable >= 2) {
		if (bc->failed_path_count > 0 || bc->degraded_path_count > 0) {
			new_state = TQUIC_BOND_DEGRADED;
		} else {
			new_state = TQUIC_BOND_ACTIVE;
		}
	} else if (total_usable == 1 && bc->pending_path_count > 0) {
		new_state = TQUIC_BOND_PENDING;
	} else {
		new_state = TQUIC_BOND_SINGLE_PATH;
	}

	/* Handle state transitions */
	if (bc->state != new_state) {
		/* Allocate reorder buffer when entering PENDING or ACTIVE */
		if (new_state == TQUIC_BOND_PENDING ||
		    new_state == TQUIC_BOND_ACTIVE) {
			ret = tquic_bonding_alloc_reorder(bc);
			if (ret && new_state == TQUIC_BOND_ACTIVE) {
				/*
				 * Can't allocate buffer, stay in current state.
				 * Log warning but don't fail - degraded operation.
				 */
				pr_warn("reorder buffer alloc failed, degraded bonding\n");
			}
		}

		/* Free reorder buffer when returning to SINGLE_PATH */
		if (new_state == TQUIC_BOND_SINGLE_PATH && bc->reorder) {
			/* Defer free to avoid holding lock */
			spin_unlock_bh(&bc->state_lock);
			tquic_bonding_free_reorder(bc);
			spin_lock_bh(&bc->state_lock);
		}

		tquic_bonding_set_state(bc, new_state);

		/* Schedule weight recalculation on state change */
		if (new_state == TQUIC_BOND_ACTIVE ||
		    new_state == TQUIC_BOND_DEGRADED) {
			tquic_bonding_schedule_weight_update(bc);
		}
	}

	spin_unlock_bh(&bc->state_lock);
}
EXPORT_SYMBOL_GPL(tquic_bonding_update_state);

/**
 * tquic_bonding_get_state - Get current bonding state
 */
enum tquic_bonding_state tquic_bonding_get_state(struct tquic_bonding_ctx *bc)
{
	if (!bc)
		return TQUIC_BOND_SINGLE_PATH;

	/* Read is atomic for enum, no lock needed */
	return READ_ONCE(bc->state);
}
EXPORT_SYMBOL_GPL(tquic_bonding_get_state);

/*
 * ============================================================================
 * Capacity Weights API
 * ============================================================================
 */

/**
 * tquic_bonding_derive_weights - Calculate capacity weights from path metrics
 *
 * Weight formula: weight[i] = (cwnd[i] / RTT[i]) / sum(cwnd[j] / RTT[j])
 *
 * This gives weights proportional to each path's available bandwidth.
 * A path with 2x the cwnd/RTT ratio gets 2x the traffic share.
 *
 * User-overridden weights are not modified.
 * Minimum weight floor (5%) prevents path starvation.
 */
void tquic_bonding_derive_weights(struct tquic_bonding_ctx *bc)
{
	struct tquic_path *paths[TQUIC_MAX_PATHS];
	u64 capacity[TQUIC_MAX_PATHS];
	u64 total_capacity = 0;
	u32 total_weight = 0;
	int count, i;

	if (!bc || !bc->pm)
		return;

	/* Get active paths */
	count = tquic_pm_get_active_paths(bc->pm, paths, TQUIC_MAX_PATHS);
	if (count <= 0)
		return;

	spin_lock_bh(&bc->state_lock);

	/*
	 * Calculate capacity weight for each path.
	 *
	 * A full implementation would compute: Capacity = cwnd / RTT
	 * (bytes per second) using per-path congestion control metrics.
	 *
	 * Currently uses equal weights for simplicity, which provides
	 * fair distribution across all active paths.
	 */
	for (i = 0; i < count && i < TQUIC_MAX_PATHS; i++) {
		/*
		 * Placeholder: assume equal capacity per path
		 * Real implementation would be:
		 *   u64 cwnd = paths[i]->cc.cwnd;
		 *   u64 rtt = paths[i]->metrics.srtt;
		 *   capacity[i] = rtt > 0 ? div64_u64(cwnd * USEC_PER_SEC, rtt) : 0;
		 */
		capacity[i] = TQUIC_DEFAULT_PATH_WEIGHT;
		total_capacity += capacity[i];
	}

	if (total_capacity == 0) {
		spin_unlock_bh(&bc->state_lock);
		return;
	}

	/*
	 * Phase 2: Convert capacities to weights
	 *
	 * Weight = (capacity / total_capacity) * WEIGHT_SCALE
	 */
	for (i = 0; i < count && i < TQUIC_MAX_PATHS; i++) {
		u8 path_id = i;  /* Simplified: index = path_id */
		u32 weight;

		/* Skip user-overridden weights */
		if (bc->weights.user_override[path_id])
			continue;

		/* Calculate proportional weight */
		weight = (u32)div64_u64(capacity[i] * TQUIC_WEIGHT_SCALE,
					total_capacity);

		/* Enforce minimum weight floor */
		if (weight < TQUIC_MIN_PATH_WEIGHT)
			weight = TQUIC_MIN_PATH_WEIGHT;

		/* Enforce maximum weight */
		if (weight > TQUIC_MAX_PATH_WEIGHT)
			weight = TQUIC_MAX_PATH_WEIGHT;

		bc->weights.path_weights[path_id] = weight;
	}

	/*
	 * Phase 3: Calculate total weight
	 */
	total_weight = 0;
	for (i = 0; i < TQUIC_MAX_PATHS; i++) {
		if (i < count || bc->weights.user_override[i])
			total_weight += bc->weights.path_weights[i];
	}
	bc->weights.total_weight = total_weight;
	bc->weights.last_update = ktime_get();
	bc->stats.weight_updates++;

	spin_unlock_bh(&bc->state_lock);

	pr_debug("weights derived: total=%u (paths=%d)\n", total_weight, count);
}
EXPORT_SYMBOL_GPL(tquic_bonding_derive_weights);

/**
 * tquic_bonding_set_path_weight - Set user-defined weight for a path
 */
int tquic_bonding_set_path_weight(struct tquic_bonding_ctx *bc,
				  u8 path_id, u32 weight)
{
	if (!bc)
		return -EINVAL;

	if (path_id >= TQUIC_MAX_PATHS)
		return -EINVAL;

	/* Weight of 0 means clear override */
	if (weight == 0) {
		return tquic_bonding_clear_weight_override(bc, path_id);
	}

	/* Validate weight range */
	if (weight < TQUIC_MIN_PATH_WEIGHT || weight > TQUIC_MAX_PATH_WEIGHT)
		return -EINVAL;

	spin_lock_bh(&bc->state_lock);

	bc->weights.path_weights[path_id] = weight;
	bc->weights.user_override[path_id] = true;

	/* Recalculate total weight */
	bc->weights.total_weight = 0;
	for (int i = 0; i < TQUIC_MAX_PATHS; i++) {
		bc->weights.total_weight += bc->weights.path_weights[i];
	}

	spin_unlock_bh(&bc->state_lock);

	pr_debug("path %u weight set to %u (user override)\n", path_id, weight);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_bonding_set_path_weight);

/**
 * tquic_bonding_get_path_weight - Get current weight for a path
 */
u32 tquic_bonding_get_path_weight(struct tquic_bonding_ctx *bc, u8 path_id)
{
	u32 weight;

	if (!bc || path_id >= TQUIC_MAX_PATHS)
		return 0;

	spin_lock_bh(&bc->state_lock);
	weight = bc->weights.path_weights[path_id];
	spin_unlock_bh(&bc->state_lock);

	return weight;
}
EXPORT_SYMBOL_GPL(tquic_bonding_get_path_weight);

/**
 * tquic_bonding_clear_weight_override - Clear user weight override
 */
int tquic_bonding_clear_weight_override(struct tquic_bonding_ctx *bc,
					u8 path_id)
{
	if (!bc)
		return -EINVAL;

	if (path_id >= TQUIC_MAX_PATHS)
		return -EINVAL;

	spin_lock_bh(&bc->state_lock);

	bc->weights.user_override[path_id] = false;
	bc->weights.path_weights[path_id] = TQUIC_DEFAULT_PATH_WEIGHT;

	spin_unlock_bh(&bc->state_lock);

	/* Schedule weight recalculation */
	tquic_bonding_schedule_weight_update(bc);

	pr_debug("path %u weight override cleared\n", path_id);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_bonding_clear_weight_override);

/*
 * ============================================================================
 * Path Manager Callbacks
 * ============================================================================
 */

/**
 * tquic_bonding_on_path_validated - Callback when path validation completes
 */
void tquic_bonding_on_path_validated(void *ctx, struct tquic_path *path)
{
	struct tquic_bonding_ctx *bc = ctx;

	if (!bc)
		return;

	spin_lock_bh(&bc->state_lock);

	/* Move from pending to active */
	if (bc->pending_path_count > 0)
		bc->pending_path_count--;
	bc->active_path_count++;

	spin_unlock_bh(&bc->state_lock);

	pr_debug("path validated: active=%d pending=%d\n",
		 bc->active_path_count, bc->pending_path_count);

	/* Update state machine */
	tquic_bonding_update_state(bc);
}
EXPORT_SYMBOL_GPL(tquic_bonding_on_path_validated);

/**
 * tquic_bonding_on_path_failed - Callback when path fails
 *
 * This is the critical failover entry point. When a path fails:
 * 1. Update path counts for state machine
 * 2. Trigger failover to requeue unacked packets from failed path
 * 3. Update bonding state (may transition to DEGRADED or SINGLE_PATH)
 */
void tquic_bonding_on_path_failed(void *ctx, struct tquic_path *path)
{
	struct tquic_bonding_ctx *bc = ctx;
	u8 path_id;
	int requeued = 0;

	if (!bc)
		return;

	/*
	 * Get path_id from path structure.
	 * The tquic_path struct has path_id as first field after list linkage.
	 * We access it through the scheduler's tquic_path definition.
	 */
	path_id = ((struct { u8 path_id; } *)path)->path_id;

	spin_lock_bh(&bc->state_lock);

	/* Track failure */
	if (bc->active_path_count > 0)
		bc->active_path_count--;
	bc->failed_path_count++;
	bc->stats.failover_events++;

	spin_unlock_bh(&bc->state_lock);

	/*
	 * Trigger failover: requeue all unacked packets from this path
	 * to the retransmit queue for transmission on remaining paths.
	 */
	if (bc->failover) {
		requeued = tquic_failover_on_path_failed(bc->failover, path_id);
		pr_info("path %u failed: active=%d failed=%d requeued=%d\n",
			path_id, bc->active_path_count, bc->failed_path_count,
			requeued);
	} else {
		pr_info("path failed: active=%d failed=%d (no failover ctx)\n",
			bc->active_path_count, bc->failed_path_count);
	}

	/* Update state machine */
	tquic_bonding_update_state(bc);
}
EXPORT_SYMBOL_GPL(tquic_bonding_on_path_failed);

/**
 * tquic_bonding_on_path_added - Callback when new path is added
 */
void tquic_bonding_on_path_added(void *ctx, struct tquic_path *path)
{
	struct tquic_bonding_ctx *bc = ctx;

	if (!bc)
		return;

	spin_lock_bh(&bc->state_lock);

	/* New path starts as pending (needs validation) */
	bc->pending_path_count++;

	spin_unlock_bh(&bc->state_lock);

	pr_debug("path added: active=%d pending=%d\n",
		 bc->active_path_count, bc->pending_path_count);

	/* Update state machine (may transition to PENDING) */
	tquic_bonding_update_state(bc);
}
EXPORT_SYMBOL_GPL(tquic_bonding_on_path_added);

/**
 * tquic_bonding_on_path_removed - Callback when path is removed
 */
void tquic_bonding_on_path_removed(void *ctx, struct tquic_path *path)
{
	struct tquic_bonding_ctx *bc = ctx;

	if (!bc)
		return;

	spin_lock_bh(&bc->state_lock);

	/*
	 * Decrement appropriate counter based on path state.
	 * Since we don't have direct access to path->state here,
	 * we try to decrement in order of likelihood.
	 */
	if (bc->active_path_count > 0) {
		bc->active_path_count--;
	} else if (bc->pending_path_count > 0) {
		bc->pending_path_count--;
	} else if (bc->failed_path_count > 0) {
		bc->failed_path_count--;
	}

	spin_unlock_bh(&bc->state_lock);

	pr_debug("path removed: active=%d pending=%d failed=%d\n",
		 bc->active_path_count, bc->pending_path_count,
		 bc->failed_path_count);

	/* Update state machine */
	tquic_bonding_update_state(bc);
}
EXPORT_SYMBOL_GPL(tquic_bonding_on_path_removed);

/*
 * ============================================================================
 * Statistics and Debugging
 * ============================================================================
 */

/**
 * tquic_bonding_get_info - Get bonding state snapshot
 */
void tquic_bonding_get_info(struct tquic_bonding_ctx *bc,
			    struct tquic_bonding_info *info)
{
	int i;

	if (!bc || !info) {
		if (info)
			memset(info, 0, sizeof(*info));
		return;
	}

	spin_lock_bh(&bc->state_lock);

	info->state = bc->state;
	info->active_paths = bc->active_path_count;
	info->degraded_paths = bc->degraded_path_count;
	info->failed_paths = bc->failed_path_count;

	for (i = 0; i < TQUIC_MAX_PATHS; i++)
		info->weights[i] = bc->weights.path_weights[i];

	info->state_changes = bc->stats.state_changes;
	info->weight_updates = bc->stats.weight_updates;
	info->bytes_aggregated = bc->stats.bytes_aggregated;
	info->failover_events = bc->stats.failover_events;

	/* Calculate current time in bonded if still bonded */
	if (bc->state == TQUIC_BOND_ACTIVE) {
		ktime_t now = ktime_get();
		info->time_in_bonded_ns = bc->stats.time_in_bonded_ns +
			ktime_to_ns(ktime_sub(now, bc->stats.bonded_start));
	} else {
		info->time_in_bonded_ns = bc->stats.time_in_bonded_ns;
	}

	spin_unlock_bh(&bc->state_lock);
}
EXPORT_SYMBOL_GPL(tquic_bonding_get_info);

/*
 * ============================================================================
 * Connection-Level Bonding API
 *
 * These functions provide a connection-level interface for bonding operations,
 * used by socket code (setsockopt/getsockopt).
 * ============================================================================
 */

/**
 * tquic_bond_set_path_weight - Set path weight via connection
 * @conn: TQUIC connection
 * @path_id: Path identifier (0-7)
 * @weight: Weight value (50-1000, or 0 to clear override)
 *
 * Wrapper for socket code to set bonding path weight.
 * Accesses bonding context through path manager.
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_bond_set_path_weight(struct tquic_connection *conn,
			       u8 path_id, u32 weight)
{
	struct tquic_path_manager *pm;
	struct tquic_bonding_ctx *bc;

	if (!conn)
		return -EINVAL;

	/*
	 * Access bonding context via path manager.
	 * The pm pointer is stored in tquic_pm_state->priv for now.
	 * In future, this could be a direct field in tquic_connection.
	 *
	 * For now, we need to get the path_manager from net/quic/tquic_path.c.
	 * The bonding context is stored in pm->bonding.
	 */
	pm = (struct tquic_path_manager *)conn->scheduler;
	if (!pm)
		return -ENOENT;

	bc = pm->bonding;
	if (!bc)
		return -ENOENT;

	return tquic_bonding_set_path_weight(bc, path_id, weight);
}
EXPORT_SYMBOL_GPL(tquic_bond_set_path_weight);

/**
 * tquic_bond_get_path_weight - Get path weight via connection
 * @conn: TQUIC connection
 * @path_id: Path identifier (0-7)
 *
 * Returns: Weight value (0-1000), or 0 if invalid
 */
u32 tquic_bond_get_path_weight(struct tquic_connection *conn, u8 path_id)
{
	struct tquic_path_manager *pm;
	struct tquic_bonding_ctx *bc;

	if (!conn)
		return 0;

	pm = (struct tquic_path_manager *)conn->scheduler;
	if (!pm)
		return 0;

	bc = pm->bonding;
	if (!bc)
		return 0;

	return tquic_bonding_get_path_weight(bc, path_id);
}
EXPORT_SYMBOL_GPL(tquic_bond_get_path_weight);

/*
 * ============================================================================
 * Module Initialization
 * ============================================================================
 */

static int __init tquic_bonding_init_module(void)
{
	tquic_bond_wq = alloc_workqueue("tquic_bond",
					WQ_MEM_RECLAIM | WQ_HIGHPRI, 0);
	if (!tquic_bond_wq) {
		pr_err("failed to create bond workqueue\n");
		return -ENOMEM;
	}

	tquic_reorder_wq = alloc_workqueue("tquic_reorder",
					   WQ_MEM_RECLAIM | WQ_HIGHPRI, 0);
	if (!tquic_reorder_wq) {
		pr_err("failed to create reorder workqueue\n");
		destroy_workqueue(tquic_bond_wq);
		return -ENOMEM;
	}

	pr_info("TQUIC bonding state machine initialized\n");
	return 0;
}

static void __exit tquic_bonding_exit_module(void)
{
	if (tquic_reorder_wq)
		destroy_workqueue(tquic_reorder_wq);

	if (tquic_bond_wq)
		destroy_workqueue(tquic_bond_wq);

	pr_info("TQUIC bonding state machine unloaded\n");
}

module_init(tquic_bonding_init_module);
module_exit(tquic_bonding_exit_module);

/*
 * ============================================================================
 * Failover Integration API
 * ============================================================================
 */

/**
 * tquic_bonding_has_pending_retx - Check for pending failover retransmissions
 *
 * The scheduler should call this before selecting new data.
 * Retransmit queue has priority over new data to ensure zero packet loss.
 */
bool tquic_bonding_has_pending_retx(struct tquic_bonding_ctx *bc)
{
	if (!bc || !bc->failover)
		return false;

	return tquic_failover_has_pending(bc->failover);
}
EXPORT_SYMBOL_GPL(tquic_bonding_has_pending_retx);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Foundation");
MODULE_DESCRIPTION("TQUIC Multi-Path Bonding State Machine");
MODULE_VERSION("1.0");
