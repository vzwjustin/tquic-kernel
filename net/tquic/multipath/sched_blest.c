// SPDX-License-Identifier: GPL-2.0
/*
 * TQUIC BLEST Scheduler (Blocking Estimation-based)
 *
 * Estimates blocking delay for each path and waits for fast path
 * if it will complete sooner than slow path send time.
 *
 * Algorithm (from IFIP 2016 paper):
 * - Track inflight data per path
 * - Estimate completion time = (inflight + new_data) / bandwidth
 * - If fast path completion < slow path send time, wait for fast path
 * - Reduces head-of-line blocking at receiver
 *
 * Reference: "BLEST: Blocking estimation-based MPTCP scheduler for
 * heterogeneous networks" (IFIP Networking 2016)
 *
 * Copyright (c) 2026 Linux Foundation
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

/*
 * Default values for BLEST calculations
 */
#define BLEST_DEFAULT_SEGMENT_SIZE	1200	/* Default segment size */
#define BLEST_DEFAULT_RTT_US		100000	/* 100ms default RTT */
#define BLEST_MIN_SEND_RATE		1000	/* Minimum 1KB/s to avoid div0 */

/**
 * struct blest_path_state - Per-path state for BLEST scheduling
 * @inflight_bytes: Bytes in flight on this path
 * @last_send_time_us: Timestamp of last send in microseconds
 * @send_rate: Estimated send rate (bytes/second)
 * @rtt_us: Path RTT in microseconds
 * @path_id: Path identifier for matching
 *
 * BLEST tracks inflight data to estimate how long it will take
 * for the receiver to be ready for new data on this path.
 */
struct blest_path_state {
	u64 inflight_bytes;		/* Bytes in flight on this path */
	u64 last_send_time_us;		/* Timestamp of last send */
	u64 send_rate;			/* Estimated send rate (bytes/s) */
	u32 rtt_us;			/* Path RTT */
	u8 path_id;			/* Path identifier */
	bool valid;			/* Whether this state is valid */
};

/**
 * struct blest_sched_data - BLEST scheduler private state
 * @lock: Spinlock protecting scheduler state
 * @paths: Per-path state array
 * @segment_size: Default segment size for estimation
 * @current_path_id: Currently selected path (for hysteresis)
 * @blocking_threshold_us: Minimum blocking time to trigger wait
 *
 * The blocking threshold prevents oscillation when blocking times
 * are very small (sub-millisecond).
 *
 * Locking: The lock protects paths[] array and current_path_id from
 * concurrent access between get_path(), ack_received(), loss_detected(),
 * path_added(), and path_removed().
 */
struct blest_sched_data {
	spinlock_t lock;		/* Protects scheduler state */
	struct blest_path_state paths[TQUIC_MAX_PATHS];
	u32 segment_size;		/* Default segment size for estimation */
	u8 current_path_id;		/* Currently selected path */
	u64 blocking_threshold_us;	/* Minimum blocking to trigger wait */
};

/*
 * Module parameter for blocking threshold (microseconds).
 * Only wait for fast path if blocking would exceed this threshold.
 *
 * Valid range: 0 - 10000000 (0 to 10 seconds in microseconds)
 * - 0 means never wait (always use available capacity)
 * - Higher values mean more tolerance for head-of-line blocking
 */
#define BLEST_THRESHOLD_MAX_US		10000000	/* 10 seconds */
#define BLEST_THRESHOLD_DEFAULT_US	1000		/* 1 ms */

static unsigned int blest_blocking_threshold_us = BLEST_THRESHOLD_DEFAULT_US;
module_param_named(blocking_threshold, blest_blocking_threshold_us, uint, 0644);
MODULE_PARM_DESC(blocking_threshold,
	"Minimum blocking time (us) to wait for fast path, 0-10000000 (default 1000)");

/*
 * blest_get_validated_threshold - Get validated blocking threshold
 *
 * Returns threshold clamped to valid range [0, 10000000].
 */
static inline u64 blest_get_validated_threshold(void)
{
	unsigned int val = READ_ONCE(blest_blocking_threshold_us);

	if (val > BLEST_THRESHOLD_MAX_US) {
		pr_warn_once("blest: blocking_threshold %u exceeds max %u, "
			     "using max\n", val, BLEST_THRESHOLD_MAX_US);
		return BLEST_THRESHOLD_MAX_US;
	}
	return val;
}

/**
 * blest_find_path_state - Find or create path state for a path
 * @sd: BLEST scheduler data
 * @path_id: Path ID to find
 *
 * Returns pointer to path state, or NULL if not found and no space.
 */
static struct blest_path_state *blest_find_path_state(struct blest_sched_data *sd,
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
 * blest_alloc_path_state - Allocate a new path state slot
 * @sd: BLEST scheduler data
 * @path_id: Path ID for new state
 *
 * Returns pointer to newly allocated path state, or NULL if no space.
 */
static struct blest_path_state *blest_alloc_path_state(struct blest_sched_data *sd,
						       u8 path_id)
{
	int i;

	for (i = 0; i < TQUIC_MAX_PATHS; i++) {
		if (!sd->paths[i].valid) {
			sd->paths[i].valid = true;
			sd->paths[i].path_id = path_id;
			sd->paths[i].inflight_bytes = 0;
			sd->paths[i].send_rate = BLEST_MIN_SEND_RATE;
			sd->paths[i].rtt_us = BLEST_DEFAULT_RTT_US;
			return &sd->paths[i];
		}
	}
	return NULL;
}

/**
 * blest_blocking_estimate - Calculate blocking time if we send on slow_path
 * @sd: BLEST scheduler data
 * @slow_path: Path we're considering sending on
 * @fast_path: Path with inflight data that might block
 * @segment_size: Size of segment we're sending
 *
 * Blocking occurs when:
 * - We send on slow path
 * - Fast path has inflight data that will arrive first
 * - Slow path packet blocks reassembly at receiver
 *
 * Blocking time = (slow_send_time + slow_rtt) - (fast_complete_time)
 *
 * Returns blocking estimate in microseconds (negative means no blocking).
 */
static s64 blest_blocking_estimate(struct blest_sched_data *sd,
				   struct blest_path_state *slow,
				   struct blest_path_state *fast,
				   u32 segment_size)
{
	u64 slow_arrival_time;
	u64 fast_completion_time;

	if (!fast || !slow)
		return 0;

	if (fast->send_rate == 0 || slow->rtt_us == 0)
		return 0;

	/*
	 * Slow path: time for new segment to arrive at receiver
	 * = RTT (we're sending now, it arrives after RTT)
	 */
	slow_arrival_time = slow->rtt_us;

	/*
	 * Fast path: time for all inflight data to be delivered
	 * = (inflight_bytes / send_rate) + remaining_rtt
	 *
	 * The fast path already has data in flight. How long until
	 * all that data arrives at the receiver?
	 *
	 * transmission_time = inflight / bandwidth
	 * arrival_time = transmission_time + rtt/2 (data already in transit)
	 *
	 * Simplified: we use full RTT as conservative estimate
	 */
	if (fast->inflight_bytes > 0 && fast->send_rate > 0) {
		fast_completion_time = (fast->inflight_bytes * 1000000ULL) /
				       fast->send_rate;
		/* Add RTT for propagation (data still needs to reach receiver) */
		fast_completion_time += fast->rtt_us;
	} else {
		/* No inflight on fast path, no blocking concern */
		return 0;
	}

	/*
	 * If slow path data arrives BEFORE fast path completes its inflight,
	 * the slow path data will block at the receiver, waiting for the
	 * fast path data to arrive first (head-of-line blocking).
	 *
	 * Blocking time = how long the slow path packet waits at receiver
	 */
	if (slow_arrival_time < fast_completion_time)
		return (s64)(fast_completion_time - slow_arrival_time);

	return 0;
}

/**
 * blest_get_path - Select path using BLEST algorithm
 * @conn: Connection to select path for
 * @result: Path selection result (output)
 * @flags: Scheduling flags
 *
 * BLEST algorithm:
 * 1. Find fastest path (lowest RTT)
 * 2. For each other path, estimate blocking if we send there
 * 3. If blocking exceeds threshold, wait for fastest path
 * 4. Otherwise, use path with most available capacity
 *
 * Returns 0 on success, -EINVAL if no state, -ENOENT if no paths.
 */
static int blest_get_path(struct tquic_connection *conn,
			  struct tquic_sched_path_result *result,
			  u32 flags)
{
	struct blest_sched_data *sd = conn->sched_priv;
	struct tquic_path *path, *best = NULL, *fast_path = NULL;
	struct blest_path_state *fast_state = NULL;
	u32 min_rtt = U32_MAX;
	u32 max_cwnd_avail = 0;
	int active_count = 0;
	unsigned long irqflags;

	if (!sd)
		return -EINVAL;

	rcu_read_lock();
	spin_lock_irqsave(&sd->lock, irqflags);

	/*
	 * First pass: Find the fastest path (lowest RTT) and count actives.
	 * The fastest path is the reference for blocking estimation.
	 */
	list_for_each_entry_rcu(path, &conn->paths, list) {
		u32 rtt;

		if (path->state != TQUIC_PATH_ACTIVE)
			continue;

		active_count++;

		rtt = path->cc.smoothed_rtt_us;
		if (rtt == 0)
			rtt = BLEST_DEFAULT_RTT_US;

		if (rtt < min_rtt) {
			min_rtt = rtt;
			fast_path = path;
		}
	}

	if (active_count == 0 || !fast_path) {
		spin_unlock_irqrestore(&sd->lock, irqflags);
		rcu_read_unlock();
		return -ENOENT;
	}

	/* Single path: no blocking estimation needed */
	if (active_count == 1) {
		spin_unlock_irqrestore(&sd->lock, irqflags);
		if (!tquic_path_get(fast_path)) {
			rcu_read_unlock();
			return -ENOENT;
		}
		result->primary = fast_path;
		result->backup = NULL;
		result->flags = 0;
		rcu_read_unlock();
		return 0;
	}

	/* Get state for fastest path */
	fast_state = blest_find_path_state(sd, fast_path->path_id);

	/*
	 * Second pass: For each path, check if sending would cause blocking.
	 * If all paths would cause blocking > threshold, wait for fast path.
	 * Otherwise, select path with highest available cwnd.
	 */
	list_for_each_entry_rcu(path, &conn->paths, list) {
		struct blest_path_state *ps;
		s64 blocking;
		u32 cwnd_avail;

		if (path->state != TQUIC_PATH_ACTIVE)
			continue;

		ps = blest_find_path_state(sd, path->path_id);

		/* Fast path is always a candidate */
		if (path == fast_path) {
			best = path;
			max_cwnd_avail = path->cc.cwnd;
			continue;
		}

		/*
		 * Calculate blocking estimate for this path.
		 * If blocking is significant, skip this path.
		 */
		blocking = blest_blocking_estimate(sd, ps, fast_state,
						   sd->segment_size);

		if (blocking > (s64)blest_get_validated_threshold()) {
			pr_debug("blest: path %u would block for %lld us, skipping\n",
				 path->path_id, blocking);
			continue;
		}

		/*
		 * Path won't cause significant blocking.
		 * Select if it has more cwnd available than current best.
		 */
		cwnd_avail = path->cc.cwnd;
		if (path->cc.bytes_in_flight < cwnd_avail)
			cwnd_avail -= path->cc.bytes_in_flight;
		else
			cwnd_avail = 0;

		if (cwnd_avail > max_cwnd_avail) {
			max_cwnd_avail = cwnd_avail;
			best = path;
		}
	}

	if (!best)
		best = fast_path;  /* Default to fast path if all block */

	/* Update current path tracking */
	sd->current_path_id = best->path_id;

	spin_unlock_irqrestore(&sd->lock, irqflags);

	/*
	 * Take references on path pointers before leaving RCU section.
	 * Callers must call tquic_path_put() when done with the result.
	 */
	if (!tquic_path_get(best)) {
		rcu_read_unlock();
		return -ENOENT;
	}

	result->primary = best;
	result->backup = NULL;
	result->flags = 0;

	if (best != fast_path && fast_path) {
		if (tquic_path_get(fast_path))
			result->backup = fast_path;
	}

	rcu_read_unlock();
	return 0;
}

/**
 * blest_init - Initialize BLEST scheduler for a connection
 * @conn: Connection to initialize
 */
static int blest_init(struct tquic_connection *conn)
{
	struct blest_sched_data *sd;

	sd = kzalloc(sizeof(*sd), GFP_ATOMIC);
	if (!sd)
		return -ENOMEM;

	spin_lock_init(&sd->lock);
	sd->segment_size = BLEST_DEFAULT_SEGMENT_SIZE;
	sd->current_path_id = TQUIC_INVALID_PATH_ID;
	sd->blocking_threshold_us = blest_get_validated_threshold();

	conn->sched_priv = sd;
	return 0;
}

/**
 * blest_release - Release BLEST scheduler resources
 * @conn: Connection to release
 */
static void blest_release(struct tquic_connection *conn)
{
	kfree(conn->sched_priv);
	conn->sched_priv = NULL;
}

/**
 * blest_path_added - Handle new path notification
 * @conn: Connection
 * @path: Newly added path
 *
 * Allocate state for the new path.
 */
static void blest_path_added(struct tquic_connection *conn,
			     struct tquic_path *path)
{
	struct blest_sched_data *sd = conn->sched_priv;
	struct blest_path_state *ps;
	unsigned long irqflags;

	if (!sd)
		return;

	spin_lock_irqsave(&sd->lock, irqflags);
	ps = blest_alloc_path_state(sd, path->path_id);
	if (ps) {
		ps->rtt_us = path->cc.smoothed_rtt_us;
		if (ps->rtt_us == 0)
			ps->rtt_us = BLEST_DEFAULT_RTT_US;

		/* Estimate initial send rate from cwnd/RTT */
		if (path->cc.cwnd > 0 && ps->rtt_us > 0) {
			ps->send_rate = (u64)path->cc.cwnd * 1000000ULL /
					ps->rtt_us;
		} else {
			ps->send_rate = BLEST_MIN_SEND_RATE;
		}

		pr_debug("blest: path %u added (rtt=%u us, rate=%llu bytes/s)\n",
			 path->path_id, ps->rtt_us, ps->send_rate);
	}
	spin_unlock_irqrestore(&sd->lock, irqflags);
}

/**
 * blest_path_removed - Handle path removal notification
 * @conn: Connection
 * @path: Path being removed
 *
 * Clear state for the removed path.
 */
static void blest_path_removed(struct tquic_connection *conn,
			       struct tquic_path *path)
{
	struct blest_sched_data *sd = conn->sched_priv;
	struct blest_path_state *ps;
	unsigned long irqflags;

	if (!sd)
		return;

	spin_lock_irqsave(&sd->lock, irqflags);
	ps = blest_find_path_state(sd, path->path_id);
	if (ps) {
		ps->valid = false;
		pr_debug("blest: path %u removed\n", path->path_id);
	}

	/* If current path was removed, invalidate selection */
	if (sd->current_path_id == path->path_id)
		sd->current_path_id = TQUIC_INVALID_PATH_ID;
	spin_unlock_irqrestore(&sd->lock, irqflags);
}

/**
 * blest_packet_sent - Handle packet send to update inflight tracking
 * @conn: Connection
 * @path: Path the packet was sent on
 * @sent_bytes: Number of bytes sent
 *
 * Increase inflight for this path and update send timestamp.
 */
static void blest_packet_sent(struct tquic_connection *conn,
			      struct tquic_path *path,
			      u32 sent_bytes)
{
	struct blest_sched_data *sd = conn->sched_priv;
	struct blest_path_state *ps;
	unsigned long irqflags;

	if (!sd)
		return;

	spin_lock_irqsave(&sd->lock, irqflags);
	ps = blest_find_path_state(sd, path->path_id);
	if (!ps) {
		ps = blest_alloc_path_state(sd, path->path_id);
		if (ps) {
			ps->rtt_us = path->cc.smoothed_rtt_us;
			if (ps->rtt_us == 0)
				ps->rtt_us = BLEST_DEFAULT_RTT_US;
			if (path->cc.cwnd > 0 && ps->rtt_us > 0)
				ps->send_rate = (u64)path->cc.cwnd *
						1000000ULL / ps->rtt_us;
			else
				ps->send_rate = BLEST_MIN_SEND_RATE;
		}
	}

	if (ps) {
		ps->inflight_bytes += sent_bytes;
		ps->last_send_time_us = ktime_get_ns() / 1000;
	}
	spin_unlock_irqrestore(&sd->lock, irqflags);
}

/**
 * blest_ack_received - Handle ACK feedback to update inflight tracking
 * @conn: Connection
 * @path: Path that received ACK
 * @acked_bytes: Number of bytes acknowledged
 *
 * Decrease inflight for this path and update send rate estimate.
 */
static void blest_ack_received(struct tquic_connection *conn,
			       struct tquic_path *path,
			       u64 acked_bytes)
{
	struct blest_sched_data *sd = conn->sched_priv;
	struct blest_path_state *ps;
	unsigned long irqflags;

	if (!sd)
		return;

	spin_lock_irqsave(&sd->lock, irqflags);
	ps = blest_find_path_state(sd, path->path_id);
	if (!ps) {
		spin_unlock_irqrestore(&sd->lock, irqflags);
		return;
	}

	/* Decrease inflight by acknowledged bytes */
	if (ps->inflight_bytes >= acked_bytes)
		ps->inflight_bytes -= acked_bytes;
	else
		ps->inflight_bytes = 0;

	/* Update RTT from path */
	if (path->cc.smoothed_rtt_us > 0)
		ps->rtt_us = path->cc.smoothed_rtt_us;

	/* Update send rate estimate from delivery rate if available */
	if (path->cc.bandwidth > 0) {
		ps->send_rate = path->cc.bandwidth;
	} else if (path->cc.cwnd > 0 && ps->rtt_us > 0) {
		/* Fallback: estimate from cwnd/RTT */
		ps->send_rate = (u64)path->cc.cwnd * 1000000ULL / ps->rtt_us;
	}

	if (ps->send_rate < BLEST_MIN_SEND_RATE)
		ps->send_rate = BLEST_MIN_SEND_RATE;
	spin_unlock_irqrestore(&sd->lock, irqflags);
}

/**
 * blest_loss_detected - Handle loss feedback to update inflight tracking
 * @conn: Connection
 * @path: Path that detected loss
 * @lost_bytes: Number of bytes lost
 *
 * Decrease inflight for lost packets (they're no longer in flight).
 */
static void blest_loss_detected(struct tquic_connection *conn,
				struct tquic_path *path,
				u64 lost_bytes)
{
	struct blest_sched_data *sd = conn->sched_priv;
	struct blest_path_state *ps;
	unsigned long irqflags;

	if (!sd)
		return;

	spin_lock_irqsave(&sd->lock, irqflags);
	ps = blest_find_path_state(sd, path->path_id);
	if (!ps) {
		spin_unlock_irqrestore(&sd->lock, irqflags);
		return;
	}

	/* Lost packets are no longer in flight */
	if (ps->inflight_bytes >= lost_bytes)
		ps->inflight_bytes -= lost_bytes;
	else
		ps->inflight_bytes = 0;

	pr_debug("blest: path %u loss %llu bytes, inflight now %llu\n",
		 path->path_id, lost_bytes, ps->inflight_bytes);
	spin_unlock_irqrestore(&sd->lock, irqflags);
}

/**
 * BLEST scheduler operations structure
 */
static struct tquic_mp_sched_ops tquic_mp_sched_blest = {
	.name		= "blest",
	.owner		= THIS_MODULE,
	.get_path	= blest_get_path,
	.init		= blest_init,
	.release	= blest_release,
	.path_added	= blest_path_added,
	.path_removed	= blest_path_removed,
	.packet_sent	= blest_packet_sent,
	.ack_received	= blest_ack_received,
	.loss_detected	= blest_loss_detected,
};

/* =========================================================================
 * Module Initialization
 * ========================================================================= */

int __init tquic_sched_blest_init(void)
{
	int ret;

	pr_info("Initializing TQUIC BLEST scheduler\n");

	ret = tquic_mp_register_scheduler(&tquic_mp_sched_blest);
	if (ret) {
		pr_err("Failed to register blest scheduler: %d\n", ret);
		return ret;
	}

	pr_info("TQUIC BLEST scheduler registered (blocking_threshold=%llu us)\n",
		blest_get_validated_threshold());

	return 0;
}

void __exit tquic_sched_blest_exit(void)
{
	pr_info("Unloading TQUIC BLEST scheduler\n");
	tquic_mp_unregister_scheduler(&tquic_mp_sched_blest);
}

/* Note: module_init/exit handled by main protocol.c */
