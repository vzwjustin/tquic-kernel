// SPDX-License-Identifier: GPL-2.0
/*
 * TQUIC MinRTT Scheduler
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Selects the path with minimum smoothed RTT for each packet.
 * Uses a tolerance band to prevent path flapping when RTTs are similar.
 *
 * Per RESEARCH.md: 10% default tolerance band to avoid oscillation
 * when paths have nearly identical latencies.
 *
 * This module also provides a simple round-robin scheduler as a
 * baseline comparison for testing and simple use cases.
 */

#define pr_fmt(fmt) "TQUIC: " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/ktime.h>
#include <linux/rculist.h>
#include <linux/spinlock.h>
#include <net/tquic.h>

#include "tquic_sched.h"
#include "../tquic_debug.h"
#include "../tquic_init.h"

/*
 * Default RTT value when no measurements available (100ms in microseconds)
 */
#define TQUIC_DEFAULT_RTT_US 100000

/*
 * Module parameter for RTT tolerance percentage.
 * When RTTs differ by less than this percentage, the scheduler
 * stays with the current path to avoid unnecessary switching.
 *
 * Valid range: 0-100 (percentage)
 */
#define MINRTT_TOLERANCE_PCT_MAX 100
#define MINRTT_TOLERANCE_PCT_DEFAULT 10

static unsigned int minrtt_tolerance_pct = MINRTT_TOLERANCE_PCT_DEFAULT;
module_param_named(tolerance_pct, minrtt_tolerance_pct, uint, 0644);
MODULE_PARM_DESC(
	tolerance_pct,
	"RTT tolerance percentage for path switching, 0-100 (default 10)");

static inline unsigned int minrtt_get_validated_tolerance(void)
{
	unsigned int val = READ_ONCE(minrtt_tolerance_pct);

	if (val > MINRTT_TOLERANCE_PCT_MAX) {
		pr_warn_once(
			"minrtt: tolerance_pct %u exceeds max %u, using %u\n",
			val, MINRTT_TOLERANCE_PCT_MAX,
			MINRTT_TOLERANCE_PCT_DEFAULT);
		return MINRTT_TOLERANCE_PCT_DEFAULT;
	}
	return val;
}

/* =========================================================================
 * MinRTT Scheduler Implementation
 * ========================================================================= */

/**
 * struct minrtt_sched_data - MinRTT scheduler private state
 * @lock: Spinlock protecting scheduler state from concurrent access
 * @current_path_id: Currently selected path ID (0xFF = none)
 * @current_rtt_us: RTT of current path in microseconds
 * @last_switch: Time of last path switch (for statistics)
 * @switch_count: Number of path switches (for diagnostics)
 *
 * This structure tracks the scheduler's current path selection
 * state, allowing hysteresis via the tolerance band.
 *
 * Locking: The lock protects all mutable fields from concurrent access
 * between get_path() (send path), ack_received() (ACK processing), and
 * path_removed() (connection management). The RCU read lock for path
 * list traversal is held separately.
 */
struct minrtt_sched_data {
	spinlock_t lock; /* Protects scheduler state */
	u8 current_path_id; /* Currently selected path */
	u64 current_rtt_us; /* RTT of current path */
	ktime_t last_switch; /* Time of last path switch */
	u32 switch_count; /* Number of path switches */
};

/**
 * minrtt_init - Initialize MinRTT scheduler for a connection
 * @conn: Connection to initialize
 *
 * Allocates and initializes the per-connection scheduler state.
 */
static int minrtt_init(struct tquic_connection *conn)
{
	struct minrtt_sched_data *sd;

	sd = kzalloc(sizeof(*sd), GFP_ATOMIC);
	if (!sd)
		return -ENOMEM;

	spin_lock_init(&sd->lock);
	sd->current_path_id = TQUIC_INVALID_PATH_ID;
	sd->current_rtt_us = U64_MAX;
	sd->last_switch = ktime_get();
	sd->switch_count = 0;

	conn->sched_priv = sd;
	return 0;
}

/**
 * minrtt_release - Release MinRTT scheduler resources
 * @conn: Connection to release
 */
static void minrtt_release(struct tquic_connection *conn)
{
	kfree(conn->sched_priv);
	conn->sched_priv = NULL;
}

/**
 * minrtt_get_path - Select path with minimum RTT
 * @conn: Connection to select path for
 * @result: Path selection result (output)
 * @flags: Scheduling flags
 *
 * Selects the path with the lowest smoothed RTT, applying a tolerance
 * band to prevent oscillation when paths have similar latencies.
 *
 * The tolerance band works as follows:
 *   - If current path is still usable, only switch to a new path if
 *     new_rtt < current_rtt * (100 - tolerance_pct) / 100
 *   - This prevents flapping between paths with nearly identical RTTs
 *
 * Returns 0 on success, -EINVAL if no state, -ENOENT if no paths.
 */
static int minrtt_get_path(struct tquic_connection *conn,
			   struct tquic_mp_sched_path_result *result, u32 flags)
{
	struct minrtt_sched_data *sd = conn->sched_priv;
	struct tquic_path *path, *best = NULL, *curr_path = NULL;
	u64 min_rtt = U64_MAX;
	u64 tolerance_threshold;
	u8 current_path_id;
	u64 current_rtt_us;
	unsigned long irqflags;

	if (!sd)
		return -EINVAL;

	/* Read current state under lock */
	spin_lock_irqsave(&sd->lock, irqflags);
	current_path_id = sd->current_path_id;
	current_rtt_us = sd->current_rtt_us;
	spin_unlock_irqrestore(&sd->lock, irqflags);

	rcu_read_lock();

	/*
	 * Find current path and best path by RTT.
	 *
	 * SECURITY: When checking current_path_id, we must verify that:
	 * 1. The path_id matches
	 * 2. The path is still ACTIVE (not removed/failed)
	 *
	 * This prevents use-after-free if path_id is reused after a path
	 * is removed and a new path is added with the same ID.
	 */
	list_for_each_entry_rcu(path, &conn->paths, list) {
		u64 rtt;

		if (path->state != TQUIC_PATH_ACTIVE)
			continue;

		/*
		 * Track current path for tolerance comparison.
		 * Only match if path_id is valid (not TQUIC_INVALID_PATH_ID).
		 */
		if (current_path_id != TQUIC_INVALID_PATH_ID &&
		    path->path_id == current_path_id)
			curr_path = path;

		/* Get smoothed RTT, use default if no measurement yet */
		rtt = path->cc.smoothed_rtt_us;
		if (rtt == 0)
			rtt = TQUIC_DEFAULT_RTT_US;

		if (rtt < min_rtt) {
			min_rtt = rtt;
			best = path;
		}
	}

	if (!best) {
		rcu_read_unlock();
		return -ENOENT;
	}

	/*
	 * Tolerance band: Only switch to a new path if its RTT is
	 * significantly better than current path. This prevents
	 * oscillation when paths have similar latencies.
	 *
	 * Switch if: new_rtt < current_rtt * (100 - tolerance) / 100
	 *
	 * Example with 10% tolerance:
	 *   current_rtt = 50ms, threshold = 45ms
	 *   Only switch if new path has RTT < 45ms
	 *
	 * SECURITY: Double-check that curr_path is still active before
	 * using it. This prevents race conditions where path was removed
	 * between our RCU list walk above and this check.
	 */
	if (curr_path && curr_path->state == TQUIC_PATH_ACTIVE &&
	    curr_path->path_id == current_path_id) {
		unsigned int tolerance = minrtt_get_validated_tolerance();

		tolerance_threshold = current_rtt_us * (100 - tolerance) / 100;

		if (min_rtt >= tolerance_threshold) {
			/* Stay with current path - RTT difference not significant */
			best = curr_path;
		}
	}

	/* Update state if switching paths - under lock */
	spin_lock_irqsave(&sd->lock, irqflags);
	if (best->path_id != sd->current_path_id) {
		pr_debug(
			"minrtt: switching from path %u (rtt=%llu) to path %u (rtt=%llu)\n",
			sd->current_path_id, sd->current_rtt_us, best->path_id,
			best->cc.smoothed_rtt_us);

		sd->current_path_id = best->path_id;
		sd->current_rtt_us = best->cc.smoothed_rtt_us;
		if (sd->current_rtt_us == 0)
			sd->current_rtt_us = TQUIC_DEFAULT_RTT_US;
		sd->last_switch = ktime_get();
		sd->switch_count++;
	}
	spin_unlock_irqrestore(&sd->lock, irqflags);

	/*
	 * Take a reference on the selected path before leaving the RCU
	 * read section. Callers must call tquic_path_put() when done.
	 */
	if (!tquic_path_get(best)) {
		rcu_read_unlock();
		return -ENOENT;
	}

	result->primary = best;
	result->backup = NULL; /* MinRTT doesn't use backup path */
	result->flags = 0;

	rcu_read_unlock();
	return 0;
}

/**
 * minrtt_path_added - Handle new path notification
 * @conn: Connection
 * @path: Newly added path
 *
 * New path might have better RTT - will be evaluated on next get_path().
 */
static void minrtt_path_added(struct tquic_connection *conn,
			      struct tquic_path *path)
{
	pr_debug("minrtt: path %u added (ifindex=%d)\n", path->path_id,
		 path->ifindex);
}

/**
 * minrtt_path_removed - Handle path removal notification
 * @conn: Connection
 * @path: Path being removed
 *
 * If the current path is being removed, invalidate our state so
 * get_path() will select a new path on the next call.
 */
static void minrtt_path_removed(struct tquic_connection *conn,
				struct tquic_path *path)
{
	struct minrtt_sched_data *sd = conn->sched_priv;
	unsigned long irqflags;

	if (!sd)
		return;

	spin_lock_irqsave(&sd->lock, irqflags);
	if (sd->current_path_id == path->path_id) {
		sd->current_path_id = TQUIC_INVALID_PATH_ID;
		sd->current_rtt_us = U64_MAX;
		pr_debug("minrtt: current path %u removed, will reselect\n",
			 path->path_id);
	}
	spin_unlock_irqrestore(&sd->lock, irqflags);
}

/**
 * minrtt_ack_received - Handle ACK feedback
 * @conn: Connection
 * @path: Path that received ACK
 * @acked_bytes: Number of bytes acknowledged
 *
 * Update our cached RTT for the current path when ACKs arrive.
 */
static void minrtt_ack_received(struct tquic_connection *conn,
				struct tquic_path *path, u64 acked_bytes)
{
	struct minrtt_sched_data *sd = conn->sched_priv;
	unsigned long irqflags;

	if (!sd)
		return;

	spin_lock_irqsave(&sd->lock, irqflags);
	if (path->path_id == sd->current_path_id) {
		/* Update cached RTT from path's smoothed RTT */
		sd->current_rtt_us = path->cc.smoothed_rtt_us;
		if (sd->current_rtt_us == 0)
			sd->current_rtt_us = TQUIC_DEFAULT_RTT_US;
	}
	spin_unlock_irqrestore(&sd->lock, irqflags);
}

/**
 * minrtt_loss_detected - Handle loss feedback
 * @conn: Connection
 * @path: Path that detected loss
 * @lost_bytes: Number of bytes lost
 *
 * Loss on the current path may indicate congestion or path degradation.
 * If the current path experiences significant loss, invalidate our
 * selection to trigger a fresh path evaluation on the next get_path().
 */
static void minrtt_loss_detected(struct tquic_connection *conn,
				 struct tquic_path *path, u64 lost_bytes)
{
	struct minrtt_sched_data *sd = conn->sched_priv;

	if (!sd)
		return;

	/*
	 * If loss occurs on current path, force path re-evaluation.
	 * The path's RTT may now be stale due to congestion.
	 */
	if (path->path_id == sd->current_path_id) {
		pr_debug("minrtt: loss on current path %u, will re-evaluate\n",
			 path->path_id);
		/* Don't invalidate immediately - let RTT updates decide */
	}
}

/**
 * MinRTT scheduler operations structure
 */
static struct tquic_mp_sched_ops tquic_sched_minrtt = {
	.name = "minrtt",
	.owner = THIS_MODULE,
	.get_path = minrtt_get_path,
	.init = minrtt_init,
	.release = minrtt_release,
	.path_added = minrtt_path_added,
	.path_removed = minrtt_path_removed,
	.ack_received = minrtt_ack_received,
	.loss_detected = minrtt_loss_detected,
};

/* =========================================================================
 * Round-Robin Scheduler Implementation
 * ========================================================================= */

/**
 * struct rr_sched_data - Round-robin scheduler private state
 * @lock: Spinlock protecting scheduler state
 * @next_index: Index counter for round-robin selection
 *
 * Simple state: just track which path to use next.
 *
 * Locking: The lock protects next_index from concurrent increments
 * in get_path() calls from multiple contexts.
 */
struct rr_sched_data {
	spinlock_t lock; /* Protects next_index */
	u32 next_index; /* Next path index to use */
};

/**
 * rr_init - Initialize round-robin scheduler for a connection
 * @conn: Connection to initialize
 */
static int rr_init(struct tquic_connection *conn)
{
	struct rr_sched_data *rd;

	rd = kzalloc(sizeof(*rd), GFP_ATOMIC);
	if (!rd)
		return -ENOMEM;

	spin_lock_init(&rd->lock);
	rd->next_index = 0;
	conn->sched_priv = rd;
	return 0;
}

/**
 * rr_release - Release round-robin scheduler resources
 * @conn: Connection to release
 */
static void rr_release(struct tquic_connection *conn)
{
	kfree(conn->sched_priv);
	conn->sched_priv = NULL;
}

/**
 * rr_get_path - Select path using round-robin
 * @conn: Connection to select path for
 * @result: Path selection result (output)
 * @flags: Scheduling flags
 *
 * Distributes packets evenly across all active paths using a simple
 * index-based round-robin. The next_index counter increments with
 * each call, and we select path at (next_index % active_count).
 *
 * Returns 0 on success, -EINVAL if no state, -ENOENT if no active paths.
 */
static int rr_get_path(struct tquic_connection *conn,
		       struct tquic_mp_sched_path_result *result, u32 flags)
{
	struct rr_sched_data *rd = conn->sched_priv;
	struct tquic_path *path;
	int active_count = 0;
	int target_index;
	int current_index = 0;
	u32 next_idx;
	unsigned long irqflags;

	if (!rd)
		return -EINVAL;

	rcu_read_lock();

	/* Count active paths */
	list_for_each_entry_rcu(path, &conn->paths, list) {
		if (path->state == TQUIC_PATH_ACTIVE)
			active_count++;
	}

	if (active_count == 0) {
		rcu_read_unlock();
		return -ENOENT;
	}

	/* Get and increment index atomically under lock */
	spin_lock_irqsave(&rd->lock, irqflags);
	next_idx = rd->next_index;
	rd->next_index++;
	spin_unlock_irqrestore(&rd->lock, irqflags);

	/* Round-robin: select path at (next_index % active_count) */
	target_index = next_idx % active_count;

	/* Find the target path */
	list_for_each_entry_rcu(path, &conn->paths, list) {
		if (path->state != TQUIC_PATH_ACTIVE)
			continue;

		if (current_index == target_index) {
			/*
			 * Take a reference before leaving RCU section.
			 * Callers must call tquic_path_put() when done.
			 */
			if (!tquic_path_get(path))
				break;
			result->primary = path;
			result->backup = NULL;
			result->flags = 0;
			rcu_read_unlock();
			return 0;
		}
		current_index++;
	}

	rcu_read_unlock();
	return -ENOENT;
}

/**
 * Round-robin scheduler operations structure
 */
static struct tquic_mp_sched_ops tquic_sched_rr = {
	.name = "rr",
	.owner = THIS_MODULE,
	.get_path = rr_get_path,
	.init = rr_init,
	.release = rr_release,
};

/* =========================================================================
 * Module Initialization
 * ========================================================================= */

int __init tquic_sched_minrtt_init(void)
{
	int ret;

	pr_info("Initializing TQUIC MinRTT and Round-Robin schedulers\n");

	/* Register MinRTT scheduler */
	ret = tquic_mp_register_scheduler(&tquic_sched_minrtt);
	if (ret) {
		pr_err("Failed to register minrtt scheduler: %d\n", ret);
		return ret;
	}

	/* Register Round-Robin scheduler */
	ret = tquic_mp_register_scheduler(&tquic_sched_rr);
	if (ret) {
		pr_err("Failed to register rr scheduler: %d\n", ret);
		tquic_mp_unregister_scheduler(&tquic_sched_minrtt);
		return ret;
	}

	pr_info("TQUIC MinRTT scheduler (tolerance=%u%%) registered\n",
		minrtt_tolerance_pct);
	pr_info("TQUIC Round-Robin scheduler registered\n");

	return 0;
}

void tquic_sched_minrtt_exit(void)
{
	pr_info("Unloading TQUIC MinRTT and Round-Robin schedulers\n");

	tquic_mp_unregister_scheduler(&tquic_sched_rr);
	tquic_mp_unregister_scheduler(&tquic_sched_minrtt);
}

/* Note: module_init/exit handled by main protocol.c */
