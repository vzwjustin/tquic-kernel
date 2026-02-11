// SPDX-License-Identifier: GPL-2.0
/*
 * TQUIC Aggregate Scheduler
 *
 * Maximizes combined throughput by selecting paths proportional to
 * their capacity (cwnd/RTT). This is the default scheduler for WAN
 * bonding use cases.
 *
 * Features:
 * - Capacity-proportional path selection (cwnd/RTT)
 * - 5% minimum weight floor to prevent path starvation
 * - Integration with bonding capacity weights from tquic_bonding
 * - Primary + backup path for failover
 *
 * Copyright (c) 2026 Linux Foundation
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/atomic.h>
#include <linux/list.h>
#include <linux/rcupdate.h>
#include <linux/ktime.h>
#include <linux/spinlock.h>
#include <net/tquic.h>

#include "tquic_sched.h"
#include "../bond/tquic_bonding.h"
#include "../tquic_debug.h"

/*
 * Capacity calculation constants
 */
#define TQUIC_MIN_WEIGHT_FLOOR      50      /* 5% of 1000 scale */
#define TQUIC_WEIGHT_SCALE          1000
#define TQUIC_DEFAULT_RTT_US        100000  /* 100ms default RTT */
#define TQUIC_CAPACITY_UPDATE_MS    10      /* Update interval */
#define TQUIC_INITIAL_CWND          12000   /* 10 * 1200 MSS */

/*
 * Aggregate scheduler private state
 *
 * Maintains cached capacity calculations for each path to avoid
 * recalculating on every packet. Updates periodically based on
 * cwnd and RTT changes.
 *
 * Locking: The lock protects capacity data from concurrent access between
 * get_path() (send path) and path_added()/path_removed()/loss_detected()
 * (connection management and feedback paths).
 */
struct aggregate_sched_data {
	spinlock_t lock;			 /* Protects scheduler state */
	u32 path_capacities[TQUIC_MAX_PATHS];    /* Cached cwnd/RTT */
	u32 total_capacity;                      /* Sum for proportional selection */
	ktime_t last_capacity_update;            /* Avoid recalc every packet */
};

/*
 * Calculate path capacity as cwnd/RTT
 *
 * Returns capacity scaled by TQUIC_WEIGHT_SCALE to avoid floating point.
 * Higher capacity = more bandwidth available on this path.
 *
 * Formula: capacity = (cwnd * scale * 1e6) / rtt_us
 * This gives bytes/second equivalent, scaled for integer math.
 */
static u32 calc_path_capacity(struct tquic_path *path)
{
	u64 cwnd = READ_ONCE(path->cc.cwnd);
	u64 rtt_us = READ_ONCE(path->cc.smoothed_rtt_us);
	u64 capacity;

	/* Use default values if metrics not yet available */
	if (cwnd == 0)
		cwnd = TQUIC_INITIAL_CWND;  /* Initial window: 10 * MSS */

	if (rtt_us == 0)
		rtt_us = TQUIC_DEFAULT_RTT_US;

	/* capacity = cwnd / rtt, scaled to avoid fractional values */
	capacity = (cwnd * TQUIC_WEIGHT_SCALE * 1000000ULL) / rtt_us;

	/* Cap at reasonable value to prevent overflow in calculations */
	if (capacity > TQUIC_WEIGHT_SCALE * 1000)
		capacity = TQUIC_WEIGHT_SCALE * 1000;

	return (u32)capacity;
}

/*
 * Update capacity calculations for all paths
 *
 * Recalculates capacity weights for each active path and enforces
 * the 5% minimum weight floor per RESEARCH.md to prevent path starvation.
 *
 * The minimum floor ensures slower paths (e.g., cellular backup) still
 * receive some traffic, keeping them "warm" for failover.
 *
 * Must be called with rcu_read_lock() AND sd->lock held.
 */
static void update_capacities_locked(struct tquic_connection *conn,
				     struct aggregate_sched_data *sd)
{
	struct tquic_path *path;
	u32 total = 0;
	int idx = 0;

	/* First pass: calculate raw capacities */
	list_for_each_entry_rcu(path, &conn->paths, list) {
		if (idx >= TQUIC_MAX_PATHS)
			break;

		if (path->state == TQUIC_PATH_ACTIVE) {
			sd->path_capacities[idx] = calc_path_capacity(path);
			total += sd->path_capacities[idx];
		} else {
			sd->path_capacities[idx] = 0;
		}
		idx++;
	}

	if (total == 0) {
		sd->total_capacity = 0;
		return;
	}

	/* Second pass: enforce 5% minimum weight floor per RESEARCH.md */
	idx = 0;
	list_for_each_entry_rcu(path, &conn->paths, list) {
		if (idx >= TQUIC_MAX_PATHS)
			break;

		if (path->state == TQUIC_PATH_ACTIVE) {
			u32 min_weight = (total * TQUIC_MIN_WEIGHT_FLOOR) / TQUIC_WEIGHT_SCALE;
			if (sd->path_capacities[idx] < min_weight) {
				/* Boost to minimum floor */
				total += (min_weight - sd->path_capacities[idx]);
				sd->path_capacities[idx] = min_weight;
			}
		}
		idx++;
	}

	sd->total_capacity = total;
	sd->last_capacity_update = ktime_get();
}

/*
 * Select path with highest available capacity
 *
 * Returns primary path (highest capacity with cwnd available) and
 * backup path (second highest) for failover support per CONTEXT.md.
 *
 * Congestion-limited paths (in_flight >= cwnd) are scored at 0
 * to avoid sending on blocked paths.
 */
static int aggregate_get_path(struct tquic_connection *conn,
			      struct tquic_sched_path_result *result,
			      u32 flags)
{
	struct aggregate_sched_data *sd = conn->sched_priv;
	struct tquic_path *path, *best = NULL, *backup = NULL;
	u32 max_capacity = 0;
	u32 second_capacity = 0;
	int idx = 0;
	unsigned long irqflags;

	if (!sd)
		return -EINVAL;

	rcu_read_lock();
	spin_lock_irqsave(&sd->lock, irqflags);

	/* Update capacities periodically (not every packet) */
	if (ktime_ms_delta(ktime_get(), sd->last_capacity_update) >
	    TQUIC_CAPACITY_UPDATE_MS)
		update_capacities_locked(conn, sd);

	if (sd->total_capacity == 0) {
		spin_unlock_irqrestore(&sd->lock, irqflags);
		rcu_read_unlock();
		return -ENOENT;
	}

	/* Find paths with highest available capacity */
	list_for_each_entry_rcu(path, &conn->paths, list) {
		u32 capacity;
		u32 available;
		u32 cwnd;

		if (idx >= TQUIC_MAX_PATHS)
			break;

		if (path->state != TQUIC_PATH_ACTIVE) {
			idx++;
			continue;
		}

		capacity = sd->path_capacities[idx];

		/* Check if path has cwnd available (not congestion limited) */
		cwnd = READ_ONCE(path->cc.cwnd);
		if (cwnd > 0) {
			u32 in_flight = READ_ONCE(path->cc.bytes_in_flight);

			if (in_flight < cwnd)
				available = capacity;
			else
				available = 0;  /* Congestion limited */
		} else {
			available = capacity;
		}

		if (available > max_capacity) {
			/* New best path, old best becomes backup */
			backup = best;
			second_capacity = max_capacity;
			best = path;
			max_capacity = available;
		} else if (available > second_capacity) {
			/* New second-best path */
			backup = path;
			second_capacity = available;
		}

		idx++;
	}

	spin_unlock_irqrestore(&sd->lock, irqflags);

	if (!best) {
		rcu_read_unlock();
		return -ENOENT;
	}

	/*
	 * Take references on path pointers before leaving RCU section.
	 * Callers must call tquic_path_put() when done with the result.
	 */
	if (!tquic_path_get(best)) {
		rcu_read_unlock();
		return -ENOENT;
	}
	if (backup && !tquic_path_get(backup))
		backup = NULL;

	result->primary = best;
	result->backup = backup;
	result->flags = 0;

	rcu_read_unlock();
	return 0;
}

/*
 * Initialize aggregate scheduler for a connection
 */
static int aggregate_init(struct tquic_connection *conn)
{
	struct aggregate_sched_data *sd;

	sd = kzalloc(sizeof(*sd), GFP_ATOMIC);
	if (!sd)
		return -ENOMEM;

	spin_lock_init(&sd->lock);
	sd->last_capacity_update = ktime_get();
	conn->sched_priv = sd;
	return 0;
}

/*
 * Release aggregate scheduler resources for a connection
 */
static void aggregate_release(struct tquic_connection *conn)
{
	kfree(conn->sched_priv);
	conn->sched_priv = NULL;
}

/*
 * Path added notification - force capacity recalculation
 */
static void aggregate_path_added(struct tquic_connection *conn,
				 struct tquic_path *path)
{
	struct aggregate_sched_data *sd = conn->sched_priv;
	unsigned long irqflags;

	if (!sd)
		return;

	spin_lock_irqsave(&sd->lock, irqflags);
	sd->last_capacity_update = 0;  /* Force recalc */
	spin_unlock_irqrestore(&sd->lock, irqflags);
}

/*
 * Path removed notification - force capacity recalculation
 */
static void aggregate_path_removed(struct tquic_connection *conn,
				   struct tquic_path *path)
{
	struct aggregate_sched_data *sd = conn->sched_priv;
	unsigned long irqflags;

	if (!sd)
		return;

	spin_lock_irqsave(&sd->lock, irqflags);
	sd->last_capacity_update = 0;  /* Force recalc */
	spin_unlock_irqrestore(&sd->lock, irqflags);
}

/*
 * ACK received notification
 *
 * RTT and cwnd are updated externally; they will be picked up
 * at the next periodic capacity update.
 */
static void aggregate_ack_received(struct tquic_connection *conn,
				   struct tquic_path *path,
				   u64 acked_bytes)
{
	/* RTT/cwnd updated externally, will be picked up next capacity update */
}

/*
 * Loss detected notification
 *
 * Trigger capacity recalculation on loss events since cwnd changes.
 * The aggregate scheduler relies on cwnd/RTT ratios for capacity,
 * so loss-induced cwnd reductions should trigger recalculation.
 */
static void aggregate_loss_detected(struct tquic_connection *conn,
				    struct tquic_path *path,
				    u64 lost_bytes)
{
	struct aggregate_sched_data *sd = conn->sched_priv;
	unsigned long irqflags;

	if (!sd)
		return;

	/* Force capacity recalculation on loss (cwnd will have changed) */
	spin_lock_irqsave(&sd->lock, irqflags);
	sd->last_capacity_update = 0;
	spin_unlock_irqrestore(&sd->lock, irqflags);
}

/*
 * Aggregate scheduler operations structure
 *
 * Exported as the default scheduler for TQUIC WAN bonding.
 */
struct tquic_mp_sched_ops tquic_mp_sched_aggregate = {
	.name           = "aggregate",
	.owner          = THIS_MODULE,
	.get_path       = aggregate_get_path,
	.init           = aggregate_init,
	.release        = aggregate_release,
	.path_added     = aggregate_path_added,
	.path_removed   = aggregate_path_removed,
	.ack_received   = aggregate_ack_received,
	.loss_detected  = aggregate_loss_detected,
};
EXPORT_SYMBOL_GPL(tquic_mp_sched_aggregate);

int __init tquic_sched_aggregate_init(void)
{
	int ret;

	ret = tquic_mp_register_scheduler(&tquic_mp_sched_aggregate);
	if (ret == 0)
		pr_info("TQUIC: aggregate scheduler registered (default)\n");
	return ret;
}

void __exit tquic_sched_aggregate_exit(void)
{
	tquic_mp_unregister_scheduler(&tquic_mp_sched_aggregate);
}

/* Note: module_init/exit handled by main protocol.c */
