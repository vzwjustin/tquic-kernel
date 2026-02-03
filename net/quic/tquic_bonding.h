/* SPDX-License-Identifier: GPL-2.0 */
/*
 * TQUIC Multi-Path Bonding State Machine
 *
 * Copyright (c) 2024-2026 Linux Foundation
 *
 * This implements the bonding state machine for WAN bandwidth aggregation.
 * Coordinates multi-path aggregation lifecycle, capacity weight derivation,
 * and failover mechanics.
 *
 * State machine: SINGLE_PATH -> BONDING_PENDING -> BONDED -> DEGRADED
 */

#ifndef _NET_TQUIC_BONDING_H
#define _NET_TQUIC_BONDING_H

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/ktime.h>
#include <linux/workqueue.h>

/* Forward declarations */
struct tquic_path;
struct tquic_path_manager;
struct tquic_reorder_buffer;  /* Defined in tquic_bonding.c, implemented in 05-02 */
struct tquic_failover_ctx;    /* Defined in tquic_failover.h, implemented in 05-03 */

/*
 * Maximum number of paths per bonded connection
 */
#define TQUIC_MAX_PATHS			8

/*
 * Capacity weight constants
 *
 * Weights are scaled 0-1000, with 1000 = 100% of traffic.
 * Minimum weight floor prevents starvation of slower paths
 * (per RESEARCH.md pitfall #4 - don't starve paths).
 */
#define TQUIC_MIN_PATH_WEIGHT		50	/* 5% minimum floor */
#define TQUIC_MAX_PATH_WEIGHT		1000	/* 100% maximum */
#define TQUIC_DEFAULT_PATH_WEIGHT	100	/* Equal weight default */
#define TQUIC_WEIGHT_SCALE		1000	/* Weight denominator */

/*
 * Reorder buffer defaults
 *
 * Buffer must handle 600ms latency difference (fiber + satellite scenario).
 * Memory limit prevents unbounded growth per connection.
 */
#define TQUIC_DEFAULT_BUFFER_SIZE	(4 * 1024 * 1024)	/* 4MB default */
#define TQUIC_MIN_BUFFER_SIZE		(64 * 1024)		/* 64KB minimum */
#define TQUIC_MAX_BUFFER_SIZE		(64 * 1024 * 1024)	/* 64MB maximum */

/*
 * Bonding state machine states
 *
 * Per CONTEXT.md decisions:
 * - SINGLE_PATH: normal QUIC operation, no aggregation overhead
 * - BONDING_PENDING: second path validating, prepare reorder buffer
 * - BONDED: active aggregation across 2+ paths
 * - DEGRADED: one or more paths failed, reduced capacity
 *
 * State transitions:
 *   SINGLE_PATH -> PENDING (second path added, validating)
 *   PENDING -> BONDED (second path validated)
 *   PENDING -> SINGLE_PATH (validation failed, only one path remains)
 *   BONDED -> DEGRADED (path failed, but 2+ paths remain)
 *   BONDED -> SINGLE_PATH (only one path remains)
 *   DEGRADED -> BONDED (failed path recovered)
 *   DEGRADED -> SINGLE_PATH (down to one path)
 */
enum tquic_bonding_state {
	TQUIC_BOND_SINGLE_PATH = 0,	/* Normal QUIC, no aggregation overhead */
	TQUIC_BOND_PENDING,		/* Second path validating, prepare buffer */
	TQUIC_BOND_ACTIVE,		/* Aggregating across 2+ paths */
	TQUIC_BOND_DEGRADED,		/* One or more paths failed, reduced capacity */

	__TQUIC_BOND_STATE_MAX
};

/*
 * State name strings for debugging/logging
 */
extern const char *tquic_bonding_state_names[];

/*
 * Capacity weights structure
 *
 * Weights are derived from cwnd/RTT measurements and determine
 * proportional traffic distribution across paths.
 *
 * user_override[i] = true means weight[i] was set via sockopt
 * and should not be auto-updated by derive_weights().
 */
struct tquic_capacity_weights {
	u32 path_weights[TQUIC_MAX_PATHS];	/* Per-path weights (0-1000) */
	u32 total_weight;			/* Sum of all weights */
	bool user_override[TQUIC_MAX_PATHS];	/* User-set weights via sockopt */
	ktime_t last_update;			/* Last weight recalculation */
};

/*
 * Bonding context flags for tracking degraded capabilities
 */
#define TQUIC_BOND_F_FAILOVER_DISABLED	BIT(0)	/* Failover init failed */
#define TQUIC_BOND_F_REORDER_DISABLED	BIT(1)	/* Reorder buffer alloc failed */
#define TQUIC_BOND_F_REORDER_RETRY	BIT(2)	/* Retry reorder alloc scheduled */
#define TQUIC_BOND_F_COUPLED_CC		BIT(3)	/* Coupled CC enabled */

/* Forward declaration for coupled congestion control */
struct coupled_cc_ctx;

/*
 * Bonding context structure
 *
 * Per-connection bonding state machine context.
 * Created by tquic_bonding_init(), destroyed by tquic_bonding_destroy().
 *
 * LOCKING: state_lock protects state and path counts.
 *          weights use RCU for read-side, state_lock for write.
 */
struct tquic_bonding_ctx {
	enum tquic_bonding_state state;
	spinlock_t state_lock;
	u32 flags;			/* TQUIC_BOND_F_* capability flags */

	/* Path tracking */
	int active_path_count;		/* Paths in ACTIVE/VALIDATED state */
	int degraded_path_count;	/* Paths in DEGRADED state */
	int failed_path_count;		/* Paths in FAILED state */
	int pending_path_count;		/* Paths in VALIDATING state */

	/* Capacity weights */
	struct tquic_capacity_weights weights;

	/* Reorder buffer (allocated lazily in BOND_PENDING state) */
	struct tquic_reorder_buffer *reorder;
	size_t max_buffer_bytes;	/* Configurable via sysctl */

	/* Failover context for seamless retransmission */
	struct tquic_failover_ctx *failover;	/* Allocated with bonding */

	/* Coupled congestion control context (RFC 6356) */
	struct coupled_cc_ctx *coupled_cc;	/* LIA/OLIA for multipath fairness */

	/* Work for async weight updates */
	struct work_struct weight_work;
	bool weight_update_pending;

	/* Back pointer to path manager */
	struct tquic_path_manager *pm;

	/* Statistics */
	struct {
		u64 state_changes;		/* Total state transitions */
		u64 weight_updates;		/* Weight recalculations */
		u64 time_in_bonded_ns;		/* Time spent in BONDED state */
		ktime_t bonded_start;		/* When entered BONDED state */
		u64 bytes_aggregated;		/* Bytes sent via aggregation */
		u64 failover_events;		/* Failover count */
	} stats;
};

/*
 * ============================================================================
 * Lifecycle API
 * ============================================================================
 */

/**
 * tquic_bonding_init - Initialize bonding context for a connection
 * @pm: Path manager this bonding context belongs to
 * @gfp: Memory allocation flags
 *
 * Creates and initializes a bonding context in SINGLE_PATH state.
 * Call after path manager is initialized.
 *
 * Returns: Allocated bonding context, or NULL on failure
 */
struct tquic_bonding_ctx *tquic_bonding_init(struct tquic_path_manager *pm,
					     gfp_t gfp);

/**
 * tquic_bonding_destroy - Destroy bonding context
 * @bc: Bonding context to destroy
 *
 * Frees all resources including reorder buffer.
 * Safe to call with NULL.
 */
void tquic_bonding_destroy(struct tquic_bonding_ctx *bc);

/*
 * ============================================================================
 * State Management API
 * ============================================================================
 */

/**
 * tquic_bonding_update_state - Update bonding state based on path counts
 * @bc: Bonding context
 *
 * Called after path state changes (validation, failure, etc.).
 * Automatically transitions state machine based on:
 *   - Number of validated paths
 *   - Number of failed/degraded paths
 *
 * May allocate/free reorder buffer on state transitions.
 */
void tquic_bonding_update_state(struct tquic_bonding_ctx *bc);

/**
 * tquic_bonding_get_state - Get current bonding state
 * @bc: Bonding context
 *
 * Returns current state without locking (for fast path checks).
 * For consistent state + counts, use tquic_bonding_get_info().
 */
enum tquic_bonding_state tquic_bonding_get_state(struct tquic_bonding_ctx *bc);

/**
 * tquic_bonding_is_active - Check if bonding is actively aggregating
 * @bc: Bonding context
 *
 * Returns true if in BONDED state (can use multi-path scheduling).
 */
static inline bool tquic_bonding_is_active(struct tquic_bonding_ctx *bc)
{
	return bc && bc->state == TQUIC_BOND_ACTIVE;
}

/*
 * ============================================================================
 * Capacity Weights API
 * ============================================================================
 */

/**
 * tquic_bonding_derive_weights - Calculate capacity weights from path metrics
 * @bc: Bonding context
 *
 * Derives weights from each path's cwnd and RTT measurements.
 * Weight formula: weight[i] = (cwnd[i] / RTT[i]) / sum(cwnd[j] / RTT[j])
 *
 * User-overridden weights (set via sockopt) are not recalculated.
 * Enforces minimum weight floor to prevent path starvation.
 */
void tquic_bonding_derive_weights(struct tquic_bonding_ctx *bc);

/**
 * tquic_bonding_set_path_weight - Set user-defined weight for a path
 * @bc: Bonding context
 * @path_id: Path identifier
 * @weight: Weight value (TQUIC_MIN_PATH_WEIGHT to TQUIC_MAX_PATH_WEIGHT)
 *
 * Sets a user-override weight for the specified path.
 * The weight will not be auto-updated by derive_weights().
 * Set weight=0 to clear override and return to automatic derivation.
 *
 * Returns: 0 on success, -EINVAL for invalid path_id or weight
 */
int tquic_bonding_set_path_weight(struct tquic_bonding_ctx *bc,
				  u8 path_id, u32 weight);

/**
 * tquic_bonding_get_path_weight - Get current weight for a path
 * @bc: Bonding context
 * @path_id: Path identifier
 *
 * Returns current weight (0-1000), or 0 if path_id invalid.
 */
u32 tquic_bonding_get_path_weight(struct tquic_bonding_ctx *bc, u8 path_id);

/**
 * tquic_bonding_clear_weight_override - Clear user weight override
 * @bc: Bonding context
 * @path_id: Path identifier
 *
 * Clears user override for path, returning to automatic derivation.
 *
 * Returns: 0 on success, -EINVAL for invalid path_id
 */
int tquic_bonding_clear_weight_override(struct tquic_bonding_ctx *bc,
					u8 path_id);

/*
 * ============================================================================
 * Path Manager Callbacks
 *
 * These functions are registered with the path manager to receive
 * notifications of path state changes.
 * ============================================================================
 */

/**
 * tquic_bonding_on_path_validated - Callback when path validation completes
 * @ctx: Bonding context (as void* for callback signature)
 * @path: The path that was validated
 *
 * Called by path manager when PATH_RESPONSE received.
 * May trigger state transition to BONDED.
 */
void tquic_bonding_on_path_validated(void *ctx, struct tquic_path *path);

/**
 * tquic_bonding_on_path_failed - Callback when path fails
 * @ctx: Bonding context (as void* for callback signature)
 * @path: The path that failed
 *
 * Called by path manager when path fails (timeout, etc.).
 * May trigger state transition to DEGRADED or SINGLE_PATH.
 */
void tquic_bonding_on_path_failed(void *ctx, struct tquic_path *path);

/**
 * tquic_bonding_on_path_added - Callback when new path is added
 * @ctx: Bonding context (as void* for callback signature)
 * @path: The newly added path
 *
 * Called by path manager when path is added.
 * May trigger state transition to PENDING.
 */
void tquic_bonding_on_path_added(void *ctx, struct tquic_path *path);

/**
 * tquic_bonding_on_path_removed - Callback when path is removed
 * @ctx: Bonding context (as void* for callback signature)
 * @path: The path being removed
 *
 * Called by path manager before path removal.
 * May trigger state transition based on remaining paths.
 */
void tquic_bonding_on_path_removed(void *ctx, struct tquic_path *path);

/**
 * tquic_bonding_on_ack_received - Callback when ACK is received on a path
 * @bc: Bonding context
 * @path: The path that received the ACK
 * @acked_bytes: Number of bytes acknowledged
 *
 * Called from congestion control when ACK is processed.
 * Forwards the notification to the multipath scheduler for
 * feedback-driven path selection algorithms.
 */
void tquic_bonding_on_ack_received(struct tquic_bonding_ctx *bc,
				   struct tquic_path *path,
				   u64 acked_bytes);

/**
 * tquic_bonding_on_loss_detected - Callback when loss is detected on a path
 * @bc: Bonding context
 * @path: The path that detected loss
 * @lost_bytes: Number of bytes lost
 *
 * Called from congestion control when loss is detected.
 * Forwards the notification to the multipath scheduler for
 * feedback-driven path selection algorithms.
 */
void tquic_bonding_on_loss_detected(struct tquic_bonding_ctx *bc,
				    struct tquic_path *path,
				    u64 lost_bytes);

/*
 * ============================================================================
 * Reorder Buffer Integration
 * ============================================================================
 */

/**
 * tquic_bonding_update_rtt_spread - Update reorder timeout from path RTTs
 * @bc: Bonding context
 * @min_rtt_us: Minimum path RTT in microseconds
 * @max_rtt_us: Maximum path RTT in microseconds
 *
 * Updates the reorder buffer gap timeout based on the RTT spread
 * across paths. Timeout = 2 * (max_rtt - min_rtt) + 100ms margin.
 *
 * Call when path RTT measurements are updated.
 */
void tquic_bonding_update_rtt_spread(struct tquic_bonding_ctx *bc,
				     u32 min_rtt_us, u32 max_rtt_us);

/**
 * tquic_bonding_get_reorder - Get reorder buffer for packet insertion
 * @bc: Bonding context
 *
 * Returns reorder buffer if bonding is active, NULL otherwise.
 * Caller must check for NULL before using.
 */
static inline struct tquic_reorder_buffer *
tquic_bonding_get_reorder(struct tquic_bonding_ctx *bc)
{
	if (!bc || bc->state == TQUIC_BOND_SINGLE_PATH)
		return NULL;
	return bc->reorder;
}

/*
 * ============================================================================
 * Statistics and Debugging
 * ============================================================================
 */

/**
 * struct tquic_bonding_info - Bonding state snapshot for reporting
 */
struct tquic_bonding_info {
	enum tquic_bonding_state state;
	int active_paths;
	int degraded_paths;
	int failed_paths;
	u32 weights[TQUIC_MAX_PATHS];
	u64 state_changes;
	u64 weight_updates;
	u64 time_in_bonded_ns;
	u64 bytes_aggregated;
	u64 failover_events;
};

/**
 * tquic_bonding_get_info - Get bonding state snapshot
 * @bc: Bonding context
 * @info: Output structure
 *
 * Fills info with consistent snapshot of bonding state.
 */
void tquic_bonding_get_info(struct tquic_bonding_ctx *bc,
			    struct tquic_bonding_info *info);

/*
 * ============================================================================
 * Failover Integration
 * ============================================================================
 */

/**
 * tquic_bonding_get_failover - Get failover context for sent packet tracking
 * @bc: Bonding context
 *
 * Returns failover context if bonding is active, NULL otherwise.
 */
static inline struct tquic_failover_ctx *
tquic_bonding_get_failover(struct tquic_bonding_ctx *bc)
{
	if (!bc)
		return NULL;
	return bc->failover;
}

/**
 * tquic_bonding_has_pending_retx - Check if there are pending retransmissions
 * @bc: Bonding context
 *
 * Returns true if the failover context has packets awaiting retransmission.
 * The scheduler should check this before selecting new data to send.
 */
bool tquic_bonding_has_pending_retx(struct tquic_bonding_ctx *bc);

/*
 * ============================================================================
 * Coupled Congestion Control Integration (RFC 6356)
 * ============================================================================
 */

/**
 * tquic_bonding_get_coupled_cc - Get coupled CC context
 * @bc: Bonding context
 *
 * Returns coupled CC context if bonding is active, NULL otherwise.
 * Used by congestion control code to apply LIA/OLIA algorithms.
 */
static inline struct coupled_cc_ctx *
tquic_bonding_get_coupled_cc(struct tquic_bonding_ctx *bc)
{
	if (!bc)
		return NULL;
	return bc->coupled_cc;
}

/**
 * tquic_bonding_coupled_cc_enabled - Check if coupled CC is enabled
 * @bc: Bonding context
 *
 * Returns true if coupled congestion control is active.
 */
static inline bool tquic_bonding_coupled_cc_enabled(struct tquic_bonding_ctx *bc)
{
	return bc && (bc->flags & TQUIC_BOND_F_COUPLED_CC);
}

#endif /* _NET_TQUIC_BONDING_H */
