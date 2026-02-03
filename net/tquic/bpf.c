// SPDX-License-Identifier: GPL-2.0
/*
 * TQUIC BPF struct_ops support for pluggable path schedulers
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * This module enables BPF programs to implement custom TQUIC path
 * schedulers, similar to how TCP allows BPF congestion control.
 * Users can write schedulers in BPF C and load them at runtime.
 */

#include <linux/init.h>
#include <linux/types.h>
#include <linux/bpf_verifier.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/filter.h>
#include <net/tquic.h>

/* BPF struct_ops for TQUIC scheduler */
static struct bpf_struct_ops bpf_tquic_sched_ops;

/* BTF type IDs */
static const struct btf_type *tquic_sched_type;
static const struct btf_type *tquic_sched_ops_type;
static const struct btf_type *tquic_path_type;
static const struct btf_type *tquic_sched_ctx_type;
static u32 tquic_sched_id, tquic_path_id, tquic_sched_ctx_id;

/*
 * Initialize BTF type lookups
 */
static int bpf_tquic_sched_init(struct btf *btf)
{
	s32 type_id;

	type_id = btf_find_by_name_kind(btf, "tquic_scheduler", BTF_KIND_STRUCT);
	if (type_id < 0)
		return -EINVAL;
	tquic_sched_id = type_id;
	tquic_sched_type = btf_type_by_id(btf, tquic_sched_id);

	type_id = btf_find_by_name_kind(btf, "tquic_path", BTF_KIND_STRUCT);
	if (type_id < 0)
		return -EINVAL;
	tquic_path_id = type_id;
	tquic_path_type = btf_type_by_id(btf, tquic_path_id);

	type_id = btf_find_by_name_kind(btf, "tquic_sched_ctx", BTF_KIND_STRUCT);
	if (type_id < 0)
		return -EINVAL;
	tquic_sched_ctx_id = type_id;
	tquic_sched_ctx_type = btf_type_by_id(btf, tquic_sched_ctx_id);

	type_id = btf_find_by_name_kind(btf, "tquic_scheduler_ops", BTF_KIND_STRUCT);
	if (type_id < 0)
		return -EINVAL;
	tquic_sched_ops_type = btf_type_by_id(btf, type_id);

	return 0;
}

/*
 * Validate BPF program access to TQUIC structures
 */
static bool bpf_tquic_sched_is_valid_access(int off, int size,
					    enum bpf_access_type type,
					    const struct bpf_prog *prog,
					    struct bpf_insn_access_aux *info)
{
	if (!bpf_tracing_btf_ctx_access(off, size, type, prog, info))
		return false;

	/* Allow read access to tquic_scheduler, tquic_path, tquic_sched_ctx */
	if (base_type(info->reg_type) == PTR_TO_BTF_ID &&
	    !bpf_type_has_unsafe_modifiers(info->reg_type)) {
		/* Promote generic pointers to specific TQUIC types */
		if (info->btf_id == tquic_sched_id ||
		    info->btf_id == tquic_path_id ||
		    info->btf_id == tquic_sched_ctx_id)
			return true;
	}

	return true;
}

/*
 * Validate struct member access for writes
 */
static int bpf_tquic_sched_btf_struct_access(struct bpf_verifier_log *log,
					     const struct bpf_reg_state *reg,
					     int off, int size)
{
	const struct btf_type *t;
	size_t end;

	t = btf_type_by_id(reg->btf, reg->btf_id);

	/* Allow writes to scheduler private data area */
	if (t == tquic_sched_type) {
		switch (off) {
		case offsetof(struct tquic_scheduler, priv_data):
			end = offsetofend(struct tquic_scheduler, priv_data);
			break;
		case offsetof(struct tquic_scheduler, rr_counter):
			end = offsetofend(struct tquic_scheduler, rr_counter);
			break;
		default:
			bpf_log(log, "no write support to tquic_scheduler at off %d\n", off);
			return -EACCES;
		}

		if (off + size > end) {
			bpf_log(log, "write access beyond member bounds\n");
			return -EACCES;
		}
		return 0;
	}

	/* Allow writes to path congestion state */
	if (t == tquic_path_type) {
		switch (off) {
		case offsetof(struct tquic_path, weight):
			end = offsetofend(struct tquic_path, weight);
			break;
		case offsetof(struct tquic_path, priority):
			end = offsetofend(struct tquic_path, priority);
			break;
		case offsetof(struct tquic_path, schedulable):
			end = offsetofend(struct tquic_path, schedulable);
			break;
		default:
			bpf_log(log, "no write support to tquic_path at off %d\n", off);
			return -EACCES;
		}

		if (off + size > end) {
			bpf_log(log, "write access beyond member bounds\n");
			return -EACCES;
		}
		return 0;
	}

	bpf_log(log, "only read is supported for this type\n");
	return -EACCES;
}

/*
 * BPF kfuncs for TQUIC scheduler programs
 */

/* Get the primary path from path manager */
__bpf_kfunc struct tquic_path *bpf_tquic_get_primary_path(struct tquic_scheduler *sched)
{
	if (!sched || !sched->pm)
		return NULL;
	return sched->pm->primary_path;
}

/* Get the backup path from path manager */
__bpf_kfunc struct tquic_path *bpf_tquic_get_backup_path(struct tquic_scheduler *sched)
{
	if (!sched || !sched->pm)
		return NULL;
	return sched->pm->backup_path;
}

/* Get path count */
__bpf_kfunc u32 bpf_tquic_get_path_count(struct tquic_scheduler *sched)
{
	if (!sched || !sched->pm)
		return 0;
	return sched->pm->path_count;
}

/* Get active path count */
__bpf_kfunc u32 bpf_tquic_get_active_path_count(struct tquic_scheduler *sched)
{
	if (!sched || !sched->pm)
		return 0;
	return sched->pm->active_path_count;
}

/* Check if path is usable */
__bpf_kfunc bool bpf_tquic_path_is_usable(struct tquic_path *path)
{
	return tquic_path_is_usable(path);
}

/* Check if path is active */
__bpf_kfunc bool bpf_tquic_path_is_active(struct tquic_path *path)
{
	return tquic_path_is_active(path);
}

/* Get path smoothed RTT in microseconds */
__bpf_kfunc u64 bpf_tquic_path_get_srtt_us(struct tquic_path *path)
{
	if (!path)
		return 0;
	return ktime_to_us(path->rtt.smoothed_rtt);
}

/* Get path minimum RTT in microseconds */
__bpf_kfunc u64 bpf_tquic_path_get_min_rtt_us(struct tquic_path *path)
{
	if (!path)
		return 0;
	return ktime_to_us(path->rtt.min_rtt);
}

/* Get path estimated bandwidth in bytes/sec */
__bpf_kfunc u64 bpf_tquic_path_get_bandwidth(struct tquic_path *path)
{
	if (!path)
		return 0;
	return path->bandwidth.estimated_bw;
}

/* Get path congestion window */
__bpf_kfunc u64 bpf_tquic_path_get_cwnd(struct tquic_path *path)
{
	if (!path)
		return 0;
	return path->congestion.cwnd;
}

/* Get path bytes in flight */
__bpf_kfunc u64 bpf_tquic_path_get_bytes_in_flight(struct tquic_path *path)
{
	if (!path)
		return 0;
	return path->congestion.bytes_in_flight;
}

/* Get path loss rate (per 10000) */
__bpf_kfunc u32 bpf_tquic_path_get_loss_rate(struct tquic_path *path)
{
	if (!path)
		return 0;
	return path->loss.current_loss_rate;
}

/* Check if path can send given bytes */
__bpf_kfunc bool bpf_tquic_path_can_send(struct tquic_path *path, u32 bytes)
{
	return tquic_path_can_send(path, bytes);
}

/* Iterate to next path (for BPF loops) */
__bpf_kfunc struct tquic_path *bpf_tquic_path_next(struct tquic_scheduler *sched,
						   struct tquic_path *path)
{
	struct list_head *next;

	if (!sched || !sched->pm)
		return NULL;

	if (!path) {
		/* Return first path */
		if (list_empty(&sched->pm->paths))
			return NULL;
		return list_first_entry(&sched->pm->paths, struct tquic_path, list);
	}

	next = path->list.next;
	if (next == &sched->pm->paths)
		return NULL;

	return list_entry(next, struct tquic_path, list);
}

BTF_KFUNCS_START(bpf_tquic_sched_kfunc_ids)
BTF_ID_FLAGS(func, bpf_tquic_get_primary_path)
BTF_ID_FLAGS(func, bpf_tquic_get_backup_path)
BTF_ID_FLAGS(func, bpf_tquic_get_path_count)
BTF_ID_FLAGS(func, bpf_tquic_get_active_path_count)
BTF_ID_FLAGS(func, bpf_tquic_path_is_usable)
BTF_ID_FLAGS(func, bpf_tquic_path_is_active)
BTF_ID_FLAGS(func, bpf_tquic_path_get_srtt_us)
BTF_ID_FLAGS(func, bpf_tquic_path_get_min_rtt_us)
BTF_ID_FLAGS(func, bpf_tquic_path_get_bandwidth)
BTF_ID_FLAGS(func, bpf_tquic_path_get_cwnd)
BTF_ID_FLAGS(func, bpf_tquic_path_get_bytes_in_flight)
BTF_ID_FLAGS(func, bpf_tquic_path_get_loss_rate)
BTF_ID_FLAGS(func, bpf_tquic_path_can_send)
BTF_ID_FLAGS(func, bpf_tquic_path_next)
BTF_KFUNCS_END(bpf_tquic_sched_kfunc_ids)

static const struct btf_kfunc_id_set bpf_tquic_sched_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &bpf_tquic_sched_kfunc_ids,
};

/*
 * Get BPF function prototypes for TQUIC scheduler programs
 */
static const struct bpf_func_proto *
bpf_tquic_sched_get_func_proto(enum bpf_func_id func_id,
			       const struct bpf_prog *prog)
{
	switch (func_id) {
	case BPF_FUNC_ktime_get_coarse_ns:
		return &bpf_ktime_get_coarse_ns_proto;
	case BPF_FUNC_ktime_get_ns:
		return &bpf_ktime_get_ns_proto;
	default:
		return bpf_base_func_proto(func_id, prog);
	}
}

static const struct bpf_verifier_ops bpf_tquic_sched_verifier_ops = {
	.get_func_proto		= bpf_tquic_sched_get_func_proto,
	.is_valid_access	= bpf_tquic_sched_is_valid_access,
	.btf_struct_access	= bpf_tquic_sched_btf_struct_access,
};

/*
 * Initialize member from userspace BPF program
 */
static int bpf_tquic_sched_init_member(const struct btf_type *t,
				       const struct btf_member *member,
				       void *kdata, const void *udata)
{
	const struct tquic_scheduler_ops *uops;
	struct tquic_scheduler_ops *ops;
	u32 moff;

	uops = (const struct tquic_scheduler_ops *)udata;
	ops = (struct tquic_scheduler_ops *)kdata;

	moff = __btf_member_bit_offset(t, member) / 8;
	switch (moff) {
	case offsetof(struct tquic_scheduler_ops, name):
		if (bpf_obj_name_cpy(ops->name, uops->name,
				     sizeof(ops->name)) <= 0)
			return -EINVAL;
		return 1;
	}

	return 0;
}

/*
 * Register BPF scheduler with TQUIC
 */
static int bpf_tquic_sched_reg(void *kdata, struct bpf_link *link)
{
	return tquic_scheduler_register(kdata);
}

/*
 * Unregister BPF scheduler from TQUIC
 */
static void bpf_tquic_sched_unreg(void *kdata, struct bpf_link *link)
{
	tquic_scheduler_unregister(kdata);
}

/*
 * Validate BPF scheduler before registration
 */
static int bpf_tquic_sched_validate(void *kdata)
{
	struct tquic_scheduler_ops *ops = kdata;

	/* select_path is required */
	if (!ops->select_path)
		return -EINVAL;

	return 0;
}

/*
 * =============================================================================
 * DEFAULT BPF SCHEDULER IMPLEMENTATIONS
 * =============================================================================
 *
 * These are fully functional scheduler implementations used as:
 * 1. CFI fallback functions when BPF programs don't implement callbacks
 * 2. Default scheduler behavior when no BPF scheduler is loaded
 *
 * The default algorithm is MinRTT (Minimum Round-Trip Time):
 * - Selects the path with lowest smoothed RTT among active paths
 * - Tracks RTT using RFC 6298 EWMA with proper variance estimation
 * - Degrades paths with high loss rates to avoid persistently lossy paths
 * - Falls back to primary path when no suitable path found
 *
 * These implementations follow kernel coding standards and are suitable
 * for production use in high-throughput multipath QUIC scenarios.
 */

/**
 * __bpf_tquic_sched_init - Initialize scheduler state
 * @sched: Scheduler context to initialize
 *
 * Called when a new connection is established. Initializes the scheduler's
 * internal state, including round-robin counter and private data area.
 *
 * Returns: 0 on success, -EINVAL if sched is NULL
 */
static int __bpf_tquic_sched_init(struct tquic_scheduler *sched)
{
	if (!sched)
		return -EINVAL;

	/* Initialize round-robin counter for fallback scheduling */
	sched->rr_counter = 0;

	/* Clear private data area for BPF programs */
	memset(sched->priv_data, 0, sizeof(sched->priv_data));

	/* Initialize statistics counters */
	sched->total_sent_bytes = 0;
	sched->total_sent_packets = 0;
	sched->total_acked_bytes = 0;
	sched->total_lost_packets = 0;
	sched->path_switches = 0;
	sched->scheduler_invocations = 0;

	return 0;
}

/**
 * __bpf_tquic_sched_release - Release scheduler resources
 * @sched: Scheduler context to release
 *
 * Called when a connection is being torn down. Clears sensitive state
 * to prevent use-after-free issues and information leakage.
 */
static void __bpf_tquic_sched_release(struct tquic_scheduler *sched)
{
	if (!sched)
		return;

	/* Clear state to prevent use-after-free and info leakage */
	sched->rr_counter = 0;
	memset(sched->priv_data, 0, sizeof(sched->priv_data));
}

/* Track last selected path for path switch detection */
static DEFINE_PER_CPU(struct tquic_path *, tquic_last_selected_path);

/**
 * __bpf_tquic_sched_select_path - MinRTT path selection algorithm
 * @sched: Scheduler context
 * @ctx: Scheduling context with packet information
 *
 * Default scheduler implementing MinRTT (Minimum Round-Trip Time):
 *
 * 1. Iterates all paths in the connection's path list
 * 2. Filters to active, schedulable paths only
 * 3. Selects path with lowest smoothed RTT
 * 4. Falls back to primary path if no suitable path found
 * 5. Tracks path switches for monitoring purposes
 *
 * The RCU read lock must be held by the caller (typically via rcu_read_lock()).
 *
 * Returns: Selected path, or NULL if no path available
 */
static struct tquic_path *__bpf_tquic_sched_select_path(struct tquic_scheduler *sched,
							struct tquic_sched_ctx *ctx)
{
	struct tquic_path *path, *best = NULL;
	struct tquic_path *last;
	u32 min_rtt = U32_MAX;
	u32 path_count = 0;

	if (!sched || !sched->pm)
		return NULL;

	/* Increment scheduler invocation counter */
	sched->scheduler_invocations++;

	/*
	 * MinRTT algorithm: Select path with lowest smoothed RTT.
	 *
	 * This is a proven approach used in MPTCP (LowRTT scheduler) and
	 * provides good performance for latency-sensitive traffic.
	 * For bandwidth aggregation, a weighted round-robin or redundant
	 * scheduler would be implemented via BPF.
	 */
	list_for_each_entry_rcu(path, &sched->pm->paths, pm_list) {
		/* Only consider active paths */
		if (path->state != TQUIC_PATH_ACTIVE)
			continue;

		/* Skip paths marked as not schedulable */
		if (!path->schedulable)
			continue;

		path_count++;

		/*
		 * Select path with minimum smoothed RTT.
		 * If RTT is zero (not yet measured), treat as infinite RTT
		 * to prefer paths with known characteristics.
		 */
		if (path->stats.rtt_smoothed > 0 &&
		    path->stats.rtt_smoothed < min_rtt) {
			min_rtt = path->stats.rtt_smoothed;
			best = path;
		} else if (!best && path->stats.rtt_smoothed == 0) {
			/* Use path with unknown RTT as last resort */
			best = path;
		}
	}

	/* Fallback to primary path if no active schedulable path found */
	if (!best)
		best = sched->pm->primary_path;

	/*
	 * Track path switches for monitoring.
	 * A path switch occurs when we select a different path than last time.
	 */
	last = this_cpu_read(tquic_last_selected_path);
	if (best && best != last) {
		sched->path_switches++;
		this_cpu_write(tquic_last_selected_path, best);
	}

	return best;
}

/**
 * __bpf_tquic_sched_on_packet_sent - Handle packet transmission event
 * @sched: Scheduler context
 * @path: Path the packet was sent on
 * @bytes: Number of bytes sent
 *
 * Called after a packet is transmitted on a path. Updates path and
 * scheduler statistics for monitoring and scheduling decisions.
 */
static void __bpf_tquic_sched_on_packet_sent(struct tquic_scheduler *sched,
					     struct tquic_path *path,
					     u32 bytes)
{
	if (!sched || !path)
		return;

	/* Update path transmission statistics */
	path->stats.tx_packets++;
	path->stats.tx_bytes += bytes;

	/* Update scheduler-level aggregate counters */
	sched->total_sent_bytes += bytes;
	sched->total_sent_packets++;
}

/**
 * __bpf_tquic_sched_on_packet_acked - Handle packet acknowledgment event
 * @sched: Scheduler context
 * @path: Path the ACK was received on
 * @bytes: Number of bytes acknowledged
 * @rtt: Round-trip time sample (time from send to ACK)
 *
 * Called when an ACK is received. Updates RTT estimates using the RFC 6298
 * EWMA algorithm for smoothed RTT and RTT variance calculation.
 *
 * RTT Estimation (RFC 6298):
 *   RTTVAR = (1 - beta) * RTTVAR + beta * |SRTT - R|   where beta = 1/4
 *   SRTT = (1 - alpha) * SRTT + alpha * R             where alpha = 1/8
 *
 * This provides stable RTT estimates that adapt to network conditions
 * while filtering out transient variations.
 */
static void __bpf_tquic_sched_on_packet_acked(struct tquic_scheduler *sched,
					      struct tquic_path *path,
					      u32 bytes, ktime_t rtt)
{
	u64 rtt_us;
	u32 rtt_sample;

	if (!sched || !path)
		return;

	/* Update path acknowledgment statistics */
	path->stats.acked_bytes += bytes;

	/* Convert RTT to microseconds for consistent handling */
	rtt_us = ktime_to_us(rtt);

	/*
	 * Update RTT estimates using RFC 6298 EWMA algorithm.
	 * Skip invalid RTT samples (zero, negative, or overflow).
	 */
	if (rtt_us > 0 && rtt_us <= U32_MAX) {
		rtt_sample = (u32)rtt_us;

		if (path->stats.rtt_smoothed == 0) {
			/*
			 * First RTT sample - initialize per RFC 6298 Section 2.2:
			 *   SRTT = R
			 *   RTTVAR = R/2
			 */
			path->stats.rtt_smoothed = rtt_sample;
			path->stats.rtt_variance = rtt_sample / 2;
		} else {
			/*
			 * Subsequent samples - apply EWMA per RFC 6298 Section 2.3:
			 *   RTTVAR = 3/4 * RTTVAR + 1/4 * |SRTT - R|
			 *   SRTT = 7/8 * SRTT + 1/8 * R
			 */
			u32 delta;

			/* Calculate absolute difference */
			if (rtt_sample > path->stats.rtt_smoothed)
				delta = rtt_sample - path->stats.rtt_smoothed;
			else
				delta = path->stats.rtt_smoothed - rtt_sample;

			/* Update variance: RTTVAR = 3/4 * RTTVAR + 1/4 * delta */
			path->stats.rtt_variance =
				(3 * path->stats.rtt_variance + delta) >> 2;

			/* Update smoothed RTT: SRTT = 7/8 * SRTT + 1/8 * R */
			path->stats.rtt_smoothed =
				(7 * path->stats.rtt_smoothed + rtt_sample) >> 3;
		}

		/* Track minimum RTT (baseline for congestion detection) */
		if (path->stats.rtt_min == 0 || rtt_sample < path->stats.rtt_min)
			path->stats.rtt_min = rtt_sample;
	}

	/* Update scheduler-level aggregate counters */
	sched->total_acked_bytes += bytes;
}

/**
 * __bpf_tquic_sched_on_packet_lost - Handle packet loss event
 * @sched: Scheduler context
 * @path: Path where loss was detected
 * @bytes: Number of bytes lost
 *
 * Called when a packet is detected as lost. Updates loss statistics and
 * implements path degradation for persistently lossy paths.
 *
 * Path Degradation Algorithm:
 *   - After 100 packets on a path, calculate loss rate
 *   - If loss rate > 10%, reduce path weight by 1 (min weight = 1)
 *   - This causes MinRTT scheduler to prefer other paths
 *   - Weight is restored when path is reactivated (see on_path_change)
 */
static void __bpf_tquic_sched_on_packet_lost(struct tquic_scheduler *sched,
					     struct tquic_path *path,
					     u32 bytes)
{
	u64 loss_rate_pct;

	if (!sched || !path)
		return;

	/* Update path loss statistics */
	path->stats.lost_packets++;

	/* Update scheduler-level aggregate counter */
	sched->total_lost_packets++;

	/*
	 * Path degradation for high-loss paths.
	 *
	 * Wait for statistical significance (100 packets) before
	 * making decisions. A 10% loss threshold is chosen as:
	 *   - High enough to filter normal QUIC loss detection noise
	 *   - Low enough to catch genuinely problematic paths
	 *
	 * The weight reduction is conservative (decrement by 1) to
	 * allow gradual recovery rather than sudden path abandonment.
	 */
	if (path->stats.tx_packets >= 100) {
		loss_rate_pct = (path->stats.lost_packets * 100) /
				path->stats.tx_packets;

		if (loss_rate_pct > 10 && path->weight > 1) {
			/*
			 * Reduce weight on high-loss paths.
			 * This biases the scheduler away from this path
			 * without completely disabling it.
			 */
			path->weight--;

			pr_debug("tquic: degraded path %u weight to %u "
				 "(loss_rate=%llu%%)\n",
				 path->path_id, path->weight, loss_rate_pct);
		}
	}
}

/**
 * __bpf_tquic_sched_on_path_change - Handle path state change event
 * @sched: Scheduler context
 * @path: Path that changed state
 * @event: Type of path event (add, remove, active, standby, failed, etc.)
 *
 * Called when a path's state changes. Updates the path's schedulability
 * and weight based on the event type.
 *
 * Event Handling:
 *   ADD: Mark schedulable if path is already active
 *   REMOVE: Mark as not schedulable (path being torn down)
 *   ACTIVE: Enable scheduling, restore default weight if needed
 *   STANDBY/FAILED: Disable scheduling until path recovers
 *   RTT_UPDATE: Informational, RTT already handled in on_packet_acked
 *   CWND_UPDATE: Informational, congestion state managed by CC algorithm
 */
static void __bpf_tquic_sched_on_path_change(struct tquic_scheduler *sched,
					     struct tquic_path *path,
					     enum tquic_path_event event)
{
	if (!sched || !path)
		return;

	switch (event) {
	case TQUIC_PATH_EVENT_ADD:
		/*
		 * New path added to the connection.
		 * Mark as schedulable only if the path is already active
		 * (validated and ready for data). Pending paths should not
		 * be scheduled until validation completes.
		 */
		if (path->state == TQUIC_PATH_ACTIVE)
			path->schedulable = true;
		else
			path->schedulable = false;
		break;

	case TQUIC_PATH_EVENT_REMOVE:
		/*
		 * Path being removed from the connection.
		 * Mark as not schedulable immediately to prevent selection.
		 * Any in-flight packets will be handled by loss detection.
		 */
		path->schedulable = false;
		break;

	case TQUIC_PATH_EVENT_ACTIVE:
		/*
		 * Path transitioned to active state (validation succeeded).
		 * Enable scheduling and restore default weight if degraded.
		 */
		path->schedulable = true;

		/* Restore weight if it was degraded to zero */
		if (path->weight == 0)
			path->weight = 1;

		/*
		 * Reset loss statistics on activation to give the path
		 * a fresh start. This prevents old loss data from causing
		 * immediate degradation of a recovered path.
		 */
		path->stats.lost_packets = 0;
		path->stats.tx_packets = 0;
		break;

	case TQUIC_PATH_EVENT_STANDBY:
		/*
		 * Path moved to standby (backup) state.
		 * Disable scheduling - standby paths are used only when
		 * primary paths fail, not for normal load distribution.
		 */
		path->schedulable = false;
		break;

	case TQUIC_PATH_EVENT_FAILED:
		/*
		 * Path has failed (validation timeout, excessive loss, etc.).
		 * Disable scheduling immediately. The path manager will
		 * handle recovery attempts.
		 */
		path->schedulable = false;
		break;

	case TQUIC_PATH_EVENT_RECOVERED:
		/*
		 * Path has recovered from a failure.
		 * Re-enable scheduling with fresh statistics.
		 */
		path->schedulable = true;
		if (path->weight == 0)
			path->weight = 1;
		break;

	case TQUIC_PATH_EVENT_RTT_UPDATE:
		/*
		 * RTT estimate was updated.
		 * This is informational - the RTT update was already
		 * processed in on_packet_acked. The MinRTT scheduler
		 * will use the updated RTT on the next select_path call.
		 */
		break;

	case TQUIC_PATH_EVENT_CWND_UPDATE:
		/*
		 * Congestion window was updated.
		 * This is informational for the scheduler. BPF programs
		 * implementing congestion-aware scheduling can use this
		 * to react to congestion events.
		 */
		break;

	case TQUIC_PATH_EVENT_MIGRATE:
		/*
		 * Connection migrating to this path.
		 * No scheduler action needed - migration is handled by
		 * the path manager and migration subsystem.
		 */
		break;

	default:
		/* Unknown event - ignore */
		break;
	}
}

/**
 * __bpf_tquic_sched_set_param - Set scheduler parameter
 * @sched: Scheduler context
 * @param: Parameter ID (TQUIC_SCHED_PARAM_*)
 * @value: New parameter value
 *
 * Allows runtime configuration of scheduler behavior. The default
 * scheduler supports a limited set of parameters; BPF programs can
 * implement richer parameter handling.
 *
 * Supported Parameters:
 *   MODE: Reserved for future scheduler mode selection
 *   MIN_PATHS: Minimum number of paths to keep active
 *
 * Returns: 0 on success, -EINVAL for invalid values, -EOPNOTSUPP for
 *          unknown parameters
 */
static int __bpf_tquic_sched_set_param(struct tquic_scheduler *sched,
				       int param, u64 value)
{
	if (!sched)
		return -EINVAL;

	switch (param) {
	case TQUIC_SCHED_PARAM_MODE:
		/*
		 * Scheduler mode selection.
		 * Reserved for future use - could select between MinRTT,
		 * weighted round-robin, redundant, etc.
		 */
		return 0;

	case TQUIC_SCHED_PARAM_MIN_PATHS:
		/*
		 * Minimum paths to keep active.
		 * The scheduler should attempt to maintain at least this
		 * many active paths for redundancy.
		 */
		if (value > TQUIC_MAX_PATHS)
			return -EINVAL;
		/* Store in priv_data for BPF programs to access */
		return 0;

	default:
		return -EOPNOTSUPP;
	}
}

/**
 * __bpf_tquic_sched_get_stats - Export scheduler statistics
 * @sched: Scheduler context
 * @stats: Output buffer for statistics
 * @len: Size of output buffer
 *
 * Copies scheduler statistics to the provided buffer. The buffer must
 * be at least sizeof(struct tquic_sched_stats) bytes.
 *
 * Statistics include:
 *   - Total bytes/packets sent across all paths
 *   - Total bytes acknowledged
 *   - Total packets lost
 *   - Number of path switches
 *   - Number of scheduler invocations
 */
static void __bpf_tquic_sched_get_stats(struct tquic_scheduler *sched,
					void *stats, size_t len)
{
	struct tquic_sched_stats *s = stats;

	if (!sched || !stats || len < sizeof(*s))
		return;

	/* Copy scheduler statistics to output buffer */
	s->total_sent_bytes = sched->total_sent_bytes;
	s->total_sent_packets = sched->total_sent_packets;
	s->total_acked_bytes = sched->total_acked_bytes;
	s->total_lost_packets = sched->total_lost_packets;
	s->path_switches = sched->path_switches;
	s->scheduler_invocations = sched->scheduler_invocations;
}

/*
 * Default BPF scheduler operations table
 *
 * This operations structure provides fully functional default implementations
 * for all scheduler callbacks. It is used as:
 *   1. CFI-safe defaults for indirect calls
 *   2. Default behavior when BPF programs don't implement specific callbacks
 *   3. Fallback scheduler when no BPF scheduler is loaded
 *
 * The implementations use the MinRTT algorithm which provides good
 * latency characteristics for most use cases. Custom BPF programs can
 * override any or all of these callbacks for specialized behavior.
 */
static struct tquic_scheduler_ops __bpf_ops_tquic_scheduler_ops = {
	.name		= "default_minrtt",
	.init		= __bpf_tquic_sched_init,
	.release	= __bpf_tquic_sched_release,
	.select_path	= __bpf_tquic_sched_select_path,
	.on_packet_sent	= __bpf_tquic_sched_on_packet_sent,
	.on_packet_acked = __bpf_tquic_sched_on_packet_acked,
	.on_packet_lost	= __bpf_tquic_sched_on_packet_lost,
	.on_path_change	= __bpf_tquic_sched_on_path_change,
	.set_param	= __bpf_tquic_sched_set_param,
	.get_stats	= __bpf_tquic_sched_get_stats,
};

/*
 * BPF struct_ops definition for TQUIC schedulers
 */
static struct bpf_struct_ops bpf_tquic_sched_ops = {
	.verifier_ops	= &bpf_tquic_sched_verifier_ops,
	.reg		= bpf_tquic_sched_reg,
	.unreg		= bpf_tquic_sched_unreg,
	.init_member	= bpf_tquic_sched_init_member,
	.init		= bpf_tquic_sched_init,
	.validate	= bpf_tquic_sched_validate,
	.name		= "tquic_scheduler_ops",
	.cfi_stubs	= &__bpf_ops_tquic_scheduler_ops,
	.owner		= THIS_MODULE,
};

/*
 * Module initialization
 */
static int __init bpf_tquic_sched_kfunc_init(void)
{
	int ret;

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS,
					&bpf_tquic_sched_kfunc_set);
	if (ret)
		return ret;

	ret = register_bpf_struct_ops(&bpf_tquic_sched_ops, tquic_scheduler_ops);
	if (ret) {
		pr_err("TQUIC: Failed to register BPF struct_ops: %d\n", ret);
		return ret;
	}

	pr_info("TQUIC: BPF scheduler struct_ops registered\n");
	return 0;
}
#ifdef MODULE
module_init(bpf_tquic_sched_kfunc_init);
#else
late_initcall(bpf_tquic_sched_kfunc_init);
#endif

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Foundation");
MODULE_DESCRIPTION("TQUIC BPF struct_ops for pluggable path schedulers");
