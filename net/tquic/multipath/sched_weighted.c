// SPDX-License-Identifier: GPL-2.0
/*
 * TQUIC Weighted Scheduler
 *
 * Respects user-defined path weights for traffic distribution.
 * Uses Deficit Round-Robin (DRR) algorithm for fair weighted scheduling.
 *
 * Weights are set via PM netlink (per-path priorities).
 * Higher weight = more packets on that path.
 *
 * DRR Algorithm:
 * - Each path has a deficit counter and a weight
 * - On each scheduling decision, quantum * weight is added to deficit
 * - Path with positive deficit is selected and deficit decremented
 * - Ensures long-term traffic matches configured weight ratios
 *
 * Copyright (c) 2026 Linux Foundation
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/rcupdate.h>
#include <net/tquic.h>

#include "tquic_sched.h"
#include "../bond/tquic_bonding.h"
#include "../tquic_debug.h"

/*
 * Deficit Round-Robin constants
 */
#define TQUIC_DRR_QUANTUM       1500    /* ~1 MTU per quantum */
#define TQUIC_DEFAULT_WEIGHT    100     /* Default weight if not configured */

/*
 * Per-path state for weighted scheduling
 */
struct weighted_path_state {
	u32 weight;             /* User-configured weight (1-1000) */
	s32 deficit;            /* Deficit counter (can go negative) */
};

/*
 * Weighted scheduler private state
 *
 * Tracks deficit counters for each path and the current position
 * in the round-robin cycle.
 */
struct weighted_sched_data {
	spinlock_t lock;	/* Protects paths[], current_path_idx */
	struct weighted_path_state paths[TQUIC_MAX_PATHS];
	u8 current_path_idx;    /* Current position in RR cycle */
};

/*
 * Select path using Deficit Round-Robin algorithm
 *
 * DRR ensures that over time, traffic on each path matches the
 * configured weight ratios. Paths with higher weights get more
 * deficit credit per round, allowing more packets.
 *
 * Returns 0 on success with result filled in, -ENOENT if no active paths.
 */
static int weighted_get_path(struct tquic_connection *conn,
			     struct tquic_sched_path_result *result,
			     u32 flags)
{
	struct weighted_sched_data *sd = conn->sched_priv;
	struct tquic_path *path;
	int idx, start_idx;
	int active_count = 0;
	int ret = -ENOENT;

	if (!sd)
		return -EINVAL;

	rcu_read_lock();
	spin_lock_bh(&sd->lock);

	/* Count active paths and sync weights from path structure */
	idx = 0;
	list_for_each_entry_rcu(path, &conn->paths, list) {
		if (idx >= TQUIC_MAX_PATHS)
			break;

		if (path->state == TQUIC_PATH_ACTIVE) {
			active_count++;
			/* Sync weight from path structure (set via PM netlink) */
			if (path->weight > 0 && path->weight <= 1000)
				sd->paths[idx].weight = path->weight;
			else
				sd->paths[idx].weight = TQUIC_DEFAULT_WEIGHT;
		}
		idx++;
	}

	if (active_count == 0)
		goto out;

	/* Deficit Round-Robin: find path with positive deficit */
	start_idx = sd->current_path_idx % TQUIC_MAX_PATHS;
	idx = start_idx;

	do {
		struct weighted_path_state *ps = &sd->paths[idx];
		struct tquic_path *candidate = NULL;
		int path_idx = 0;

		/* Find path at this index */
		list_for_each_entry_rcu(path, &conn->paths, list) {
			if (path_idx == idx) {
				candidate = path;
				break;
			}
			path_idx++;
		}

		if (candidate && candidate->state == TQUIC_PATH_ACTIVE) {
			/* Add quantum weighted by path weight */
			ps->deficit += (TQUIC_DRR_QUANTUM * ps->weight) / 100;

			if (ps->deficit > 0) {
				/* This path can send */
				ps->deficit -= TQUIC_DRR_QUANTUM;
				sd->current_path_idx = (idx + 1) % TQUIC_MAX_PATHS;

				result->primary = candidate;
				result->backup = NULL;
				result->flags = 0;

				ret = 0;
				goto out;
			}
		}

		idx = (idx + 1) % TQUIC_MAX_PATHS;
	} while (idx != start_idx);

	/* No path with positive deficit, reset all and try again */
	for (idx = 0; idx < TQUIC_MAX_PATHS; idx++)
		sd->paths[idx].deficit = 0;

	/* Find any active path as fallback */
	list_for_each_entry_rcu(path, &conn->paths, list) {
		if (path->state == TQUIC_PATH_ACTIVE) {
			result->primary = path;
			result->backup = NULL;
			result->flags = 0;
			ret = 0;
			goto out;
		}
	}

out:
	/*
	 * Take a reference on the selected path while the spinlock is
	 * still held to prevent the path from being freed between
	 * unlock and the tquic_path_get() call.
	 */
	if (ret == 0 && result->primary) {
		if (!tquic_path_get(result->primary)) {
			result->primary = NULL;
			ret = -ENOENT;
		}
	}

	spin_unlock_bh(&sd->lock);
	rcu_read_unlock();
	return ret;
}

/*
 * Initialize weighted scheduler for a connection
 */
static int weighted_init(struct tquic_connection *conn)
{
	struct weighted_sched_data *sd;
	int i;

	sd = kzalloc(sizeof(*sd), GFP_ATOMIC);
	if (!sd)
		return -ENOMEM;

	spin_lock_init(&sd->lock);
	for (i = 0; i < TQUIC_MAX_PATHS; i++) {
		sd->paths[i].weight = TQUIC_DEFAULT_WEIGHT;
		sd->paths[i].deficit = 0;
	}

	conn->sched_priv = sd;
	return 0;
}

/*
 * Release weighted scheduler resources for a connection
 */
static void weighted_release(struct tquic_connection *conn)
{
	kfree(conn->sched_priv);
	conn->sched_priv = NULL;
}

/*
 * Path added notification
 *
 * Weights are synced from path->weight in get_path, so no action needed.
 */
static void weighted_path_added(struct tquic_connection *conn,
				struct tquic_path *path)
{
	/* Weights synced from path->weight in get_path */
}

/*
 * Path removed notification - reset round-robin position
 */
static void weighted_path_removed(struct tquic_connection *conn,
				  struct tquic_path *path)
{
	struct weighted_sched_data *sd = conn->sched_priv;

	if (sd) {
		spin_lock_bh(&sd->lock);
		sd->current_path_idx = 0;
		spin_unlock_bh(&sd->lock);
	}
}

/*
 * ACK received notification
 *
 * The weighted scheduler uses static user-configured weights, so ACK
 * feedback does not affect scheduling decisions. This callback is
 * provided for completeness but performs no action.
 */
static void weighted_ack_received(struct tquic_connection *conn,
				  struct tquic_path *path,
				  u64 acked_bytes)
{
	/* Weighted scheduler uses static weights - no feedback needed */
}

/*
 * Loss detected notification
 *
 * The weighted scheduler uses static user-configured weights, so loss
 * feedback does not affect scheduling decisions. This callback is
 * provided for completeness but performs no action.
 */
static void weighted_loss_detected(struct tquic_connection *conn,
				   struct tquic_path *path,
				   u64 lost_bytes)
{
	/* Weighted scheduler uses static weights - no feedback needed */
}

/*
 * Weighted scheduler operations structure
 */
static struct tquic_mp_sched_ops tquic_mp_sched_weighted = {
	.name           = "weighted",
	.owner          = THIS_MODULE,
	.get_path       = weighted_get_path,
	.init           = weighted_init,
	.release        = weighted_release,
	.path_added     = weighted_path_added,
	.path_removed   = weighted_path_removed,
	.ack_received   = weighted_ack_received,
	.loss_detected  = weighted_loss_detected,
};

int __init tquic_sched_weighted_init(void)
{
	return tquic_mp_register_scheduler(&tquic_mp_sched_weighted);
}

void __exit tquic_sched_weighted_exit(void)
{
	tquic_mp_unregister_scheduler(&tquic_mp_sched_weighted);
}

/* Note: module_init/exit handled by main protocol.c */
