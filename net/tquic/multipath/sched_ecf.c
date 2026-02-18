// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC ECF Scheduler (Earliest Completion First)
 *
 * Selects the path with the earliest estimated completion time for
 * the next segment.
 *
 * Algorithm (from ACM SIGMETRICS 2017):
 * - For each path: est_completion = (inflight + segment_size) / send_rate + RTT
 * - Choose path with minimum est_completion
 * - Considers both bandwidth and RTT (not just RTT like MinRTT)
 * - Better utilization under path heterogeneity
 *
 * Reference: "ECF: An MPTCP Path Scheduler to Manage Heterogeneous Paths"
 * (ACM SIGMETRICS 2017)
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
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
 * Default values for ECF calculations
 */
#define ECF_DEFAULT_SEGMENT_SIZE 1200 /* Default segment size */
#define ECF_DEFAULT_RTT_US 100000 /* 100ms default RTT */
#define ECF_MIN_SEND_RATE 1000 /* Minimum 1KB/s to avoid div0 */
#define ECF_RATE_UPDATE_INTERVAL_MS 10 /* Rate update interval */

/**
 * struct ecf_path_state - Per-path state for ECF scheduling
 * @inflight_bytes: Bytes in flight on this path
 * @send_rate: Estimated send rate (bytes/second)
 * @rtt_us: Path RTT in microseconds
 * @path_id: Path identifier for matching
 * @valid: Whether this state is valid
 * @last_rate_update: Last time send rate was updated
 *
 * ECF tracks both inflight data and send rate to calculate
 * accurate completion time estimates.
 */
struct ecf_path_state {
	u64 inflight_bytes; /* Bytes in flight on this path */
	u64 send_rate; /* Estimated send rate (bytes/s) */
	u32 rtt_us; /* Path RTT */
	u8 path_id; /* Path identifier */
	bool valid; /* Whether this state is valid */
	ktime_t last_rate_update; /* Last rate update time */
};

/**
 * struct ecf_sched_data - ECF scheduler private state
 * @lock: Spinlock protecting scheduler state
 * @paths: Per-path state array
 * @segment_size: Default segment size for estimation
 * @current_path_id: Currently selected path (for statistics)
 * @path_switches: Number of path switches (for diagnostics)
 *
 * Locking: The lock protects paths[], current_path_id, and path_switches
 * from concurrent access between get_path(), ack_received(), loss_detected(),
 * path_added(), and path_removed().
 */
struct ecf_sched_data {
	spinlock_t lock; /* Protects scheduler state */
	struct ecf_path_state paths[TQUIC_MAX_PATHS];
	u32 segment_size; /* Default segment size for estimation */
	u8 current_path_id; /* Currently selected path */
	u32 path_switches; /* Path switch counter */
};

static inline bool ecf_path_usable(const struct tquic_path *path)
{
	return path->state == TQUIC_PATH_ACTIVE ||
	       path->state == TQUIC_PATH_VALIDATED;
}

/**
 * ecf_find_path_state - Find path state for a given path ID
 * @sd: ECF scheduler data
 * @path_id: Path ID to find
 *
 * Returns pointer to path state, or NULL if not found.
 */
static struct ecf_path_state *ecf_find_path_state(struct ecf_sched_data *sd,
						  u8 path_id)
{
	int i;

	for (i = 0; i < TQUIC_MAX_PATHS; i++) {
		if (sd->paths[i].valid && sd->paths[i].path_id == path_id)
			return &sd->paths[i];
	}
	return NULL;
}

/**
 * ecf_alloc_path_state - Allocate a new path state slot
 * @sd: ECF scheduler data
 * @path_id: Path ID for new state
 *
 * Returns pointer to newly allocated path state, or NULL if no space.
 */
static struct ecf_path_state *ecf_alloc_path_state(struct ecf_sched_data *sd,
						   u8 path_id)
{
	int i;

	for (i = 0; i < TQUIC_MAX_PATHS; i++) {
		if (!sd->paths[i].valid) {
			sd->paths[i].valid = true;
			sd->paths[i].path_id = path_id;
			sd->paths[i].inflight_bytes = 0;
			sd->paths[i].send_rate = ECF_MIN_SEND_RATE;
			sd->paths[i].rtt_us = ECF_DEFAULT_RTT_US;
			sd->paths[i].last_rate_update = ktime_get();
			return &sd->paths[i];
		}
	}
	return NULL;
}

/**
 * ecf_completion_time - Calculate estimated completion time for a segment
 * @ps: Path state
 * @segment_size: Size of segment to send
 *
 * Completion time calculation per ECF paper:
 *   completion_time = (inflight + segment_size) / send_rate + RTT
 *
 * This represents the time from now until the segment would be
 * acknowledged by the receiver, considering:
 * - Queue delay: time to transmit inflight + new segment
 * - Propagation delay: RTT for the segment to reach receiver and ACK back
 *
 * Returns time in microseconds, or U64_MAX if path unavailable.
 */
static u64 ecf_completion_time(struct ecf_path_state *ps, u32 segment_size)
{
	u64 queue_time;
	u64 propagation_time;

	if (!ps || ps->send_rate == 0)
		return U64_MAX; /* Unknown rate, avoid this path */

	tquic_dbg("sched_ecf: completion_time inflight=%llu rate=%llu rtt=%u\n",
		  ps->inflight_bytes, ps->send_rate, ps->rtt_us);

	/*
	 * Queue time: time for inflight + new segment to be transmitted
	 * = (inflight_bytes + segment_size) / send_rate
	 *
	 * Convert to microseconds: multiply by 1e6
	 */
	queue_time = ((ps->inflight_bytes + segment_size) * 1000000ULL) /
		     ps->send_rate;

	/* Add RTT for propagation delay */
	propagation_time = ps->rtt_us;

	return queue_time + propagation_time;
}

/**
 * ecf_update_rate_from_path - Update send rate from path metrics
 * @ps: Path state to update
 * @path: Connection path with current metrics
 *
 * Updates send rate estimate from the path's delivery rate or
 * cwnd/RTT if delivery rate is not available.
 */
static void ecf_update_rate_from_path(struct ecf_path_state *ps,
				      struct tquic_path *path)
{
	tquic_dbg("sched_ecf: update_rate path=%u cur_rate=%llu\n",
		  path->path_id, ps->send_rate);

	/* Prefer explicit bandwidth measurement */
	if (path->cc.bandwidth > 0) {
		ps->send_rate = path->cc.bandwidth;
	} else if (path->cc.cwnd > 0 && ps->rtt_us > 0) {
		/* Estimate from cwnd/RTT */
		ps->send_rate = (u64)path->cc.cwnd * 1000000ULL / ps->rtt_us;
	}

	/* Ensure minimum rate */
	if (ps->send_rate < ECF_MIN_SEND_RATE)
		ps->send_rate = ECF_MIN_SEND_RATE;

	/* Update RTT */
	if (path->cc.smoothed_rtt_us > 0)
		ps->rtt_us = path->cc.smoothed_rtt_us;

	ps->last_rate_update = ktime_get();
}

/**
 * ecf_get_path - Select path with minimum completion time (ECF algorithm)
 * @conn: Connection to select path for
 * @result: Path selection result (output)
 * @flags: Scheduling flags
 *
 * ECF algorithm:
 * 1. For each active path, calculate estimated completion time
 * 2. Select the path with minimum completion time
 * 3. Completion time considers both bandwidth (send_rate) and latency (RTT)
 *
 * This approach handles heterogeneous paths better than MinRTT because
 * a fast path with a full queue might have longer completion time than
 * a slower path with an empty queue.
 *
 * Returns 0 on success, -EINVAL if no state, -ENOENT if no paths.
 */
static int ecf_get_path(struct tquic_connection *conn,
			struct tquic_sched_path_result *result, u32 flags)
{
	struct ecf_sched_data *sd = conn->sched_priv;
	struct tquic_path *path, *best = NULL, *second_best = NULL;
	u64 min_completion = U64_MAX;
	u64 second_completion = U64_MAX;
	int active_count = 0;

	if (!sd)
		return -EINVAL;

	tquic_dbg("sched_ecf: get_path flags=0x%x\n", flags);

	rcu_read_lock();

	/*
	 * For each path, calculate completion time and find minimum.
	 * Also track second-best for backup path.
	 */
	/*
	 * Hold sd->lock for the entire path evaluation loop.
	 * This serializes find-or-alloc of path state entries with
	 * ecf_path_added/ecf_path_removed, preventing duplicate
	 * allocations and data races on the paths[] array.
	 */
	spin_lock_bh(&sd->lock);

	list_for_each_entry_rcu(path, &conn->paths, list) {
		struct ecf_path_state *ps;
		u64 completion;

		if (!ecf_path_usable(path))
			continue;

		active_count++;

		ps = ecf_find_path_state(sd, path->path_id);
		if (!ps) {
			/* Path not yet tracked, allocate state */
			ps = ecf_alloc_path_state(sd, path->path_id);
			if (ps)
				ecf_update_rate_from_path(ps, path);
		}

		if (!ps)
			continue;

		/*
		 * Update rate periodically from path metrics.
		 * This allows the scheduler to adapt to changing conditions.
		 */
		if (ktime_ms_delta(ktime_get(), ps->last_rate_update) >
		    ECF_RATE_UPDATE_INTERVAL_MS) {
			ecf_update_rate_from_path(ps, path);
		}

		/* Calculate completion time */
		completion = ecf_completion_time(ps, sd->segment_size);

		if (completion < min_completion) {
			/* New best - old best becomes second best */
			second_best = best;
			second_completion = min_completion;
			best = path;
			min_completion = completion;
		} else if (completion < second_completion) {
			/* New second best */
			second_best = path;
			second_completion = completion;
		}
	}

	if (!best) {
		spin_unlock_bh(&sd->lock);
		rcu_read_unlock();
		return -ENOENT;
	}

	/* Track path switches for diagnostics */
	if (sd->current_path_id != best->path_id) {
		pr_debug(
			"ecf: switching to path %u (completion=%llu us), was path %u\n",
			best->path_id, min_completion, sd->current_path_id);
		sd->current_path_id = best->path_id;
		sd->path_switches++;
	}

	spin_unlock_bh(&sd->lock);

	/*
	 * Take references on path pointers before leaving RCU section.
	 * Callers must call tquic_path_put() when done with the result.
	 */
	if (!tquic_path_get(best)) {
		rcu_read_unlock();
		return -ENOENT;
	}
	if (second_best && !tquic_path_get(second_best))
		second_best = NULL;

	result->primary = best;
	result->backup = second_best;
	result->flags = 0;

	rcu_read_unlock();
	return 0;
}

/**
 * ecf_init - Initialize ECF scheduler for a connection
 * @conn: Connection to initialize
 */
static int ecf_init(struct tquic_connection *conn)
{
	struct ecf_sched_data *sd;

	tquic_dbg("sched_ecf: init\n");

	sd = kzalloc(sizeof(*sd), GFP_ATOMIC);
	if (!sd)
		return -ENOMEM;

	spin_lock_init(&sd->lock);
	sd->segment_size = ECF_DEFAULT_SEGMENT_SIZE;
	sd->current_path_id = TQUIC_INVALID_PATH_ID;
	sd->path_switches = 0;

	conn->sched_priv = sd;
	return 0;
}

/**
 * ecf_release - Release ECF scheduler resources
 * @conn: Connection to release
 */
static void ecf_release(struct tquic_connection *conn)
{
	kfree(conn->sched_priv);
	conn->sched_priv = NULL;
}

/**
 * ecf_path_added - Handle new path notification
 * @conn: Connection
 * @path: Newly added path
 *
 * Allocate state and initialize rate estimate for the new path.
 */
static void ecf_path_added(struct tquic_connection *conn,
			   struct tquic_path *path)
{
	struct ecf_sched_data *sd = conn->sched_priv;
	struct ecf_path_state *ps;

	if (!sd)
		return;

	tquic_dbg("sched_ecf: path_added path=%u\n", path->path_id);

	/*
	 * Hold sd->lock around the find-or-alloc to prevent a
	 * concurrent ecf_get_path() from allocating a duplicate
	 * slot for the same path_id.
	 */
	spin_lock_bh(&sd->lock);
	ps = ecf_find_path_state(sd, path->path_id);
	if (!ps)
		ps = ecf_alloc_path_state(sd, path->path_id);

	if (ps) {
		ecf_update_rate_from_path(ps, path);
		pr_debug("ecf: path %u added (rtt=%u us, rate=%llu bytes/s)\n",
			 path->path_id, ps->rtt_us, ps->send_rate);
	}
	spin_unlock_bh(&sd->lock);
}

/**
 * ecf_path_removed - Handle path removal notification
 * @conn: Connection
 * @path: Path being removed
 *
 * Clear state for the removed path.
 */
static void ecf_path_removed(struct tquic_connection *conn,
			     struct tquic_path *path)
{
	struct ecf_sched_data *sd = conn->sched_priv;
	struct ecf_path_state *ps;

	if (!sd)
		return;

	tquic_dbg("sched_ecf: path_removed path=%u\n", path->path_id);

	spin_lock_bh(&sd->lock);
	ps = ecf_find_path_state(sd, path->path_id);
	if (ps) {
		ps->valid = false;
		pr_debug("ecf: path %u removed\n", path->path_id);
	}

	/* If current path was removed, invalidate selection */
	if (sd->current_path_id == path->path_id)
		sd->current_path_id = TQUIC_INVALID_PATH_ID;
	spin_unlock_bh(&sd->lock);
}

/**
 * ecf_packet_sent - Handle packet send to update inflight tracking
 * @conn: Connection
 * @path: Path the packet was sent on
 * @sent_bytes: Number of bytes sent
 *
 * Increase inflight for this path so that completion time estimates
 * accurately reflect the queue depth.
 */
static void ecf_packet_sent(struct tquic_connection *conn,
			    struct tquic_path *path, u32 sent_bytes)
{
	struct ecf_sched_data *sd = conn->sched_priv;
	struct ecf_path_state *ps;

	if (!sd)
		return;

	tquic_dbg("sched_ecf: packet_sent path=%u bytes=%u\n",
		  path->path_id, sent_bytes);

	spin_lock_bh(&sd->lock);
	ps = ecf_find_path_state(sd, path->path_id);
	if (!ps) {
		ps = ecf_alloc_path_state(sd, path->path_id);
		if (ps)
			ecf_update_rate_from_path(ps, path);
	}

	if (ps)
		ps->inflight_bytes += sent_bytes;
	spin_unlock_bh(&sd->lock);
}

/**
 * ecf_ack_received - Handle ACK feedback to update inflight and rate
 * @conn: Connection
 * @path: Path that received ACK
 * @acked_bytes: Number of bytes acknowledged
 *
 * Decrease inflight for this path and potentially update send rate.
 */
static void ecf_ack_received(struct tquic_connection *conn,
			     struct tquic_path *path, u64 acked_bytes)
{
	struct ecf_sched_data *sd = conn->sched_priv;
	struct ecf_path_state *ps;

	if (!sd)
		return;

	tquic_dbg("sched_ecf: ack_received path=%u bytes=%llu\n",
		  path->path_id, acked_bytes);

	spin_lock_bh(&sd->lock);
	ps = ecf_find_path_state(sd, path->path_id);
	if (!ps) {
		spin_unlock_bh(&sd->lock);
		return;
	}

	/* Decrease inflight by acknowledged bytes */
	if (ps->inflight_bytes >= acked_bytes)
		ps->inflight_bytes -= acked_bytes;
	else
		ps->inflight_bytes = 0;

	/* Update rate from path metrics */
	ecf_update_rate_from_path(ps, path);
	spin_unlock_bh(&sd->lock);
}

/**
 * ecf_loss_detected - Handle loss feedback to update inflight
 * @conn: Connection
 * @path: Path that detected loss
 * @lost_bytes: Number of bytes lost
 *
 * Decrease inflight for lost packets (they're no longer in flight).
 */
static void ecf_loss_detected(struct tquic_connection *conn,
			      struct tquic_path *path, u64 lost_bytes)
{
	struct ecf_sched_data *sd = conn->sched_priv;
	struct ecf_path_state *ps;

	if (!sd)
		return;

	tquic_dbg("sched_ecf: loss_detected path=%u lost=%llu\n",
		  path->path_id, lost_bytes);

	spin_lock_bh(&sd->lock);
	ps = ecf_find_path_state(sd, path->path_id);
	if (!ps) {
		spin_unlock_bh(&sd->lock);
		return;
	}

	/* Lost packets are no longer in flight */
	if (ps->inflight_bytes >= lost_bytes)
		ps->inflight_bytes -= lost_bytes;
	else
		ps->inflight_bytes = 0;

	pr_debug("ecf: path %u loss %llu bytes, inflight now %llu\n",
		 path->path_id, lost_bytes, ps->inflight_bytes);
	spin_unlock_bh(&sd->lock);
}

/**
 * ECF scheduler operations structure
 */
static struct tquic_mp_sched_ops tquic_mp_sched_ecf = {
	.name = "ecf",
	.owner = THIS_MODULE,
	.get_path = ecf_get_path,
	.init = ecf_init,
	.release = ecf_release,
	.path_added = ecf_path_added,
	.path_removed = ecf_path_removed,
	.packet_sent = ecf_packet_sent,
	.ack_received = ecf_ack_received,
	.loss_detected = ecf_loss_detected,
};

/* =========================================================================
 * Module Initialization
 * ========================================================================= */

int __init tquic_sched_ecf_init(void)
{
	int ret;

	pr_info("Initializing TQUIC ECF scheduler\n");

	ret = tquic_mp_register_scheduler(&tquic_mp_sched_ecf);
	if (ret) {
		pr_err("Failed to register ecf scheduler: %d\n", ret);
		return ret;
	}

	pr_info("TQUIC ECF scheduler registered (Earliest Completion First)\n");

	return 0;
}

void tquic_sched_ecf_exit(void)
{
	pr_info("Unloading TQUIC ECF scheduler\n");
	tquic_mp_unregister_scheduler(&tquic_mp_sched_ecf);
}

/* Note: module_init/exit handled by tquic_main.c */
