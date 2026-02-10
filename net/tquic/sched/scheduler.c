// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Multipath Packet Scheduler Framework
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Provides a pluggable scheduler framework for distributing packets
 * across multiple WAN paths for true bandwidth aggregation.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/spinlock.h>
#include <net/sock.h>
#include <net/tquic.h>

#include "../core/one_way_delay.h"
#include "../tquic_debug.h"

/* Registered schedulers */
static LIST_HEAD(tquic_sched_list);
static DEFINE_SPINLOCK(tquic_sched_lock);

/* Default scheduler */
static struct tquic_sched_ops *default_scheduler;

/*
 * Internal scheduler registration (always available).
 * Adds a scheduler to the sched_list used by tquic_sched_default().
 */
static int __tquic_sched_register(struct tquic_sched_ops *ops)
{
	if (!ops || !ops->name || !ops->select)
		return -EINVAL;

	spin_lock_bh(&tquic_sched_lock);
	list_add_tail_rcu(&ops->list, &tquic_sched_list);

	/* First registered becomes default */
	if (!default_scheduler)
		default_scheduler = ops;

	spin_unlock_bh(&tquic_sched_lock);

	tquic_info("registered scheduler '%s'\n", ops->name);
	return 0;
}

static void __tquic_sched_unregister(struct tquic_sched_ops *ops)
{
	spin_lock_bh(&tquic_sched_lock);

	list_del_rcu(&ops->list);

	if (default_scheduler == ops) {
		default_scheduler = list_first_entry_or_null(
			&tquic_sched_list, struct tquic_sched_ops, list);
	}

	spin_unlock_bh(&tquic_sched_lock);

	synchronize_rcu();

	tquic_info("unregistered scheduler '%s'\n", ops->name);
}

/*
 * Exported scheduler registration (in-tree only to avoid duplicate
 * symbol with multipath/tquic_scheduler.c in consolidated builds).
 */
#ifndef TQUIC_OUT_OF_TREE
int tquic_register_scheduler(struct tquic_sched_ops *ops)
{
	return __tquic_sched_register(ops);
}
EXPORT_SYMBOL_GPL(tquic_register_scheduler);

int tquic_sched_register(struct tquic_sched_ops *ops)
{
	return __tquic_sched_register(ops);
}
EXPORT_SYMBOL_GPL(tquic_sched_register);

void tquic_unregister_scheduler(struct tquic_sched_ops *ops)
{
	__tquic_sched_unregister(ops);
}
EXPORT_SYMBOL_GPL(tquic_unregister_scheduler);

void tquic_sched_unregister(struct tquic_sched_ops *ops)
{
	__tquic_sched_unregister(ops);
}
EXPORT_SYMBOL_GPL(tquic_sched_unregister);
#endif /* !TQUIC_OUT_OF_TREE */

/*
 * Find scheduler by name
 */
struct tquic_sched_ops *tquic_sched_find(const char *name)
{
	struct tquic_sched_ops *ops;

	rcu_read_lock();
	list_for_each_entry_rcu(ops, &tquic_sched_list, list) {
		if (strcmp(ops->name, name) == 0) {
			if (!try_module_get(ops->owner)) {
				ops = NULL;
			}
			rcu_read_unlock();
			return ops;
		}
	}
	rcu_read_unlock();

	return NULL;
}
EXPORT_SYMBOL_GPL(tquic_sched_find);

/**
 * tquic_sched_get_default - Get the default scheduler name
 * @net: Network namespace (unused for now, global default)
 *
 * Returns the name of the default scheduler.
 */
const char *tquic_sched_get_default(struct net *net)
{
	const char *name = "ecf";  /* Default scheduler name */

	rcu_read_lock();
	if (default_scheduler && default_scheduler->name)
		name = default_scheduler->name;
	rcu_read_unlock();

	return name;
}
EXPORT_SYMBOL_GPL(tquic_sched_get_default);

/*
 * Get default scheduler
 */
struct tquic_sched_ops *tquic_sched_default(void)
{
	struct tquic_sched_ops *ops;

	rcu_read_lock();
	ops = rcu_dereference(default_scheduler);
	if (ops) {
		pr_debug("tquic_sched: default_scheduler='%s'\n",
			 ops->name);
		if (!try_module_get(ops->owner)) {
			pr_warn("tquic_sched: try_module_get FAILED\n");
			ops = NULL;
		}
	} else {
		pr_warn("tquic_sched: default_scheduler is NULL!\n");
	}
	rcu_read_unlock();

	return ops;
}
EXPORT_SYMBOL_GPL(tquic_sched_default);

/*
 * Set default scheduler
 */
int tquic_sched_set_default(const char *name)
{
	struct tquic_sched_ops *ops;

	ops = tquic_sched_find(name);
	if (!ops)
		return -ENOENT;

	spin_lock_bh(&tquic_sched_lock);
	default_scheduler = ops;
	spin_unlock_bh(&tquic_sched_lock);

	module_put(ops->owner);

	tquic_info("set default scheduler to '%s'\n", name);
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_sched_set_default);

/*
 * Initialize scheduler for a connection
 */
void *tquic_sched_init_conn(struct tquic_connection *conn,
			    struct tquic_sched_ops *ops)
{
	void *result;

	pr_debug("tquic_sched: init_conn called\n");

	if (!ops) {
		ops = tquic_sched_default();
		pr_debug("tquic_sched: using default ops\n");
	}

	if (!ops) {
		pr_debug("tquic_sched: no ops available, returning NULL\n");
		return NULL;
	}

	pr_debug("tquic_sched: using scheduler '%s'\n", ops->name);

	if (ops->init) {
		result = ops->init(conn);
		pr_debug("tquic_sched: init() completed\n");
		return result;
	}

	pr_debug("tquic_sched: no init callback\n");
	return ops;  /* Return ops as state if no init needed */
}
EXPORT_SYMBOL_GPL(tquic_sched_init_conn);

/*
 * Release scheduler for a connection
 */
void tquic_sched_release_conn(struct tquic_sched_ops *ops, void *state)
{
	if (ops && ops->release)
		ops->release(state);

	if (ops)
		module_put(ops->owner);
}
EXPORT_SYMBOL_GPL(tquic_sched_release_conn);

/*
 * =============================================================================
 * Built-in Schedulers
 * =============================================================================
 */

/*
 * Round-Robin Scheduler
 */
struct rr_sched_data {
	atomic_t counter;
};

static void *rr_init(struct tquic_connection *conn)
{
	struct rr_sched_data *data;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (data)
		atomic_set(&data->counter, 0);

	return data;
}

static void rr_release(void *state)
{
	kfree(state);
}

static struct tquic_path *rr_select(void *state, struct tquic_connection *conn,
				    struct sk_buff *skb)
{
	struct rr_sched_data *data = state;
	struct tquic_path *path;
	u32 idx = 0;
	u32 target;

	if (!data)
		return conn->active_path;

	target = atomic_inc_return(&data->counter) % conn->num_paths;

	list_for_each_entry(path, &conn->paths, list) {
		if (path->state != TQUIC_PATH_ACTIVE)
			continue;

		if (idx++ == target)
			return path;
	}

	return conn->active_path;
}

static struct tquic_sched_ops __maybe_unused tquic_sched_rr = {
	.name = "roundrobin",
	.init = rr_init,
	.release = rr_release,
	.select = rr_select,
};

/*
 * Minimum RTT Scheduler
 */
static struct tquic_path *minrtt_select(void *state, struct tquic_connection *conn,
					struct sk_buff *skb)
{
	struct tquic_path *path, *best = NULL;
	u32 min_rtt = UINT_MAX;

	list_for_each_entry(path, &conn->paths, list) {
		if (path->state != TQUIC_PATH_ACTIVE)
			continue;

		if (path->stats.rtt_smoothed < min_rtt) {
			min_rtt = path->stats.rtt_smoothed;
			best = path;
		}
	}

	return best ?: conn->active_path;
}

static struct tquic_sched_ops __maybe_unused tquic_sched_minrtt = {
	.name = "minrtt",
	.select = minrtt_select,
};

/*
 * Weighted Round-Robin Scheduler
 */
struct wrr_sched_data {
	atomic_t counter;
	u32 total_weight;
};

static void *wrr_init(struct tquic_connection *conn)
{
	struct wrr_sched_data *data;
	struct tquic_path *path;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return NULL;

	atomic_set(&data->counter, 0);

	/* Calculate total weight */
	list_for_each_entry(path, &conn->paths, list) {
		if (path->state == TQUIC_PATH_ACTIVE)
			data->total_weight += path->weight;
	}

	return data;
}

static void wrr_release(void *state)
{
	kfree(state);
}

static struct tquic_path *wrr_select(void *state, struct tquic_connection *conn,
				     struct sk_buff *skb)
{
	struct wrr_sched_data *data = state;
	struct tquic_path *path;
	u32 target, cumulative = 0;
	u32 tw;

	if (!data)
		return conn->active_path;

	/*
	 * Recompute total_weight from the current path list to avoid
	 * stale values after path add/remove events.
	 */
	tw = 0;
	list_for_each_entry(path, &conn->paths, list) {
		if (path->state == TQUIC_PATH_ACTIVE)
			tw += path->weight;
	}
	data->total_weight = tw;

	if (tw == 0)
		return conn->active_path;

	target = atomic_inc_return(&data->counter) % tw;

	list_for_each_entry(path, &conn->paths, list) {
		if (path->state != TQUIC_PATH_ACTIVE)
			continue;

		cumulative += path->weight;
		if (target < cumulative)
			return path;
	}

	return conn->active_path;
}

static void wrr_feedback(void *state, struct tquic_path *path,
			 struct sk_buff *skb, bool success)
{
	struct wrr_sched_data *data = state;

	if (!data)
		return;

	/* Recalculate total weight on path changes */
	/* This is a simplified implementation */
}

static struct tquic_sched_ops __maybe_unused tquic_sched_wrr = {
	.name = "weighted",
	.init = wrr_init,
	.release = wrr_release,
	.select = wrr_select,
	.feedback = wrr_feedback,
};

/*
 * BLEST (BLocking ESTimation) Scheduler
 * Designed to minimize head-of-line blocking in multipath scenarios
 */
struct blest_sched_data {
	u64 lambda;  /* Smoothing factor */
};

static void *blest_init(struct tquic_connection *conn)
{
	struct blest_sched_data *data;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (data)
		data->lambda = 1000;  /* Default lambda value */

	return data;
}

static void blest_release(void *state)
{
	kfree(state);
}

static struct tquic_path *blest_select(void *state, struct tquic_connection *conn,
				       struct sk_buff *skb)
{
	struct tquic_path *path, *best = NULL;
	u64 min_blocking = ULLONG_MAX;

	list_for_each_entry(path, &conn->paths, list) {
		u64 blocking_time;
		u64 owd_diff;

		if (path->state != TQUIC_PATH_ACTIVE)
			continue;

		/* Estimate blocking time */
		/* OWD = RTT/2 (simplified) */
		owd_diff = 0;
		if (conn->active_path && path != conn->active_path) {
			s64 diff = (s64)path->stats.rtt_smoothed -
				   (s64)conn->active_path->stats.rtt_smoothed;
			if (diff > 0)
				owd_diff = diff / 2;
		}

		/* Calculate blocking estimate */
		blocking_time = owd_diff;

		/* Add queuing delay estimate based on cwnd utilization */
		if (path->stats.cwnd > 0) {
			/* Simplified: assume some bytes in flight */
			u64 queue_delay = (skb->len * path->stats.rtt_smoothed) /
					  path->stats.cwnd;
			blocking_time += queue_delay;
		}

		if (blocking_time < min_blocking) {
			min_blocking = blocking_time;
			best = path;
		}
	}

	return best ?: conn->active_path;
}

static struct tquic_sched_ops __maybe_unused tquic_sched_blest = {
	.name = "blest",
	.init = blest_init,
	.release = blest_release,
	.select = blest_select,
};

/*
 * Redundant Scheduler - sends on all paths
 */
static struct tquic_path *redundant_select(void *state,
					   struct tquic_connection *conn,
					   struct sk_buff *skb)
{
	/* For redundant mode, we return NULL to indicate
	 * the caller should send on ALL active paths */
	return NULL;
}

static struct tquic_sched_ops __maybe_unused tquic_sched_redundant = {
	.name = "redundant",
	.select = redundant_select,
};

/*
 * ECF (Earliest Completion First) Scheduler
 *
 * The ECF scheduler achieves true bandwidth aggregation by selecting the
 * path that will deliver the packet earliest. This is CRITICAL for WAN
 * bonding to achieve aggregated throughput (e.g., 1.5Gbps from 1Gbps + 500Mbps).
 *
 * Formula: Completion_Time = RTT + (In_Flight_Bytes + Packet_Size) / Bandwidth
 *
 * Where:
 *   - RTT: Full round-trip time for the path (microseconds)
 *   - In_Flight_Bytes: Bytes sent but not yet acknowledged
 *   - Packet_Size: Size of the packet to be sent
 *   - Bandwidth: Estimated path bandwidth (bytes/second)
 *
 * The formula accounts for:
 *   1. Propagation delay (RTT) - time for the packet to reach destination
 *   2. Queuing delay (In_Flight / Bandwidth) - time to drain existing queue
 *   3. Transmission delay (Packet_Size / Bandwidth) - time to transmit packet
 */
struct ecf_sched_data {
	/* Per-path in-flight tracking for more accurate estimates */
	u64 last_update_jiffies;
};

static void *ecf_init(struct tquic_connection *conn)
{
	struct ecf_sched_data *data;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (data)
		data->last_update_jiffies = jiffies;

	return data;
}

static void ecf_release(void *state)
{
	kfree(state);
}

static struct tquic_path *ecf_select(void *state, struct tquic_connection *conn,
				     struct sk_buff *skb)
{
	struct tquic_path *path, *best = NULL;
	u64 min_completion = ULLONG_MAX;
	u32 pkt_size = skb->len;

	rcu_read_lock();
	list_for_each_entry_rcu(path, &conn->paths, list) {
		u64 completion_time;
		u64 in_flight_bytes;
		u64 queue_drain_time;
		u64 rtt_us;
		u64 bandwidth;

		if (path->state != TQUIC_PATH_ACTIVE)
			continue;

		/*
		 * Calculate in-flight bytes.
		 * In-flight = transmitted bytes - acknowledged bytes
		 * This represents data that is "on the wire" or in network queues.
		 */
		if (path->stats.tx_bytes > path->stats.acked_bytes)
			in_flight_bytes = path->stats.tx_bytes - path->stats.acked_bytes;
		else
			in_flight_bytes = 0;

		/*
		 * Clamp in-flight to congestion window.
		 * If our tracking shows more in-flight than cwnd allows,
		 * some packets were likely lost - use cwnd as upper bound.
		 */
		if (in_flight_bytes > path->stats.cwnd)
			in_flight_bytes = path->stats.cwnd;

		/* Get RTT in microseconds (full RTT, not half) */
		rtt_us = path->stats.rtt_smoothed;
		if (rtt_us == 0)
			rtt_us = 100000;  /* 100ms default if no RTT samples */

		/* Get bandwidth in bytes/second */
		bandwidth = path->stats.bandwidth;
		if (bandwidth == 0) {
			/*
			 * No bandwidth estimate yet.
			 * Use a conservative estimate based on cwnd and RTT:
			 * BW ≈ cwnd / RTT
			 */
			if (path->stats.cwnd > 0 && rtt_us > 0)
				bandwidth = (u64)path->stats.cwnd * 1000000ULL / rtt_us;
			else
				bandwidth = 125000;  /* 1 Mbps default */
		}

		/*
		 * Calculate completion time using ECF formula:
		 * Completion_Time = RTT + (In_Flight + Pkt_Size) / Bandwidth
		 *
		 * Convert to common unit (microseconds):
		 * - RTT is already in microseconds
		 * - (bytes / (bytes/sec)) = seconds, multiply by 1M for microseconds
		 */
		queue_drain_time = ((in_flight_bytes + pkt_size) * 1000000ULL) / bandwidth;
		completion_time = rtt_us + queue_drain_time;

		/*
		 * Apply a small penalty for paths with high loss rates.
		 * Completion time estimate should account for potential
		 * retransmissions: effective_time ≈ time / (1 - loss_rate)
		 */
		if (path->stats.tx_packets > 100) {
			u64 loss_rate_pct = (path->stats.lost_packets * 100) /
					    path->stats.tx_packets;
			if (loss_rate_pct > 0 && loss_rate_pct < 50) {
				/* Scale up completion time by 1/(1-loss_rate) */
				completion_time = completion_time * 100 / (100 - loss_rate_pct);
			}
		}

		if (completion_time < min_completion) {
			min_completion = completion_time;
			best = path;
		}
	}
	rcu_read_unlock();

	return best ?: conn->active_path;
}

static void ecf_feedback(void *state, struct tquic_path *path,
			 struct sk_buff *skb, bool success)
{
	/*
	 * ECF feedback is handled implicitly through the path statistics
	 * updates (tx_bytes, acked_bytes, lost_packets, bandwidth, rtt).
	 * The congestion control module updates these on ACK/loss events.
	 */
}

static struct tquic_sched_ops __maybe_unused tquic_sched_ecf = {
	.name = "ecf",
	.init = ecf_init,
	.release = ecf_release,
	.select = ecf_select,
	.feedback = ecf_feedback,
};

/*
 * OWD-Aware Scheduler (One-Way Delay)
 *
 * This scheduler leverages one-way delay measurements to make better
 * path selection decisions, especially for asymmetric links. It considers:
 * - Forward delay for uploads (data flowing from sender to receiver)
 * - Reverse delay for downloads (ACKs and responses)
 * - Asymmetry detection for optimal traffic steering
 *
 * The scheduler is particularly useful for scenarios like:
 * - Satellite links with significant propagation asymmetry
 * - Cellular networks with different uplink/downlink characteristics
 * - Mixed wired/wireless paths in WAN bonding
 */
struct owd_sched_data {
	struct tquic_owd_state *owd_state;	/* Per-path OWD states */
	bool prefer_forward;			/* Optimize for upload traffic */
	u32 asymmetry_threshold_pct;		/* Threshold for asymmetry detection */
	u64 last_path_switch_time;		/* To avoid path flapping */
	u32 min_switch_interval_ms;		/* Minimum time between switches */
};

static void *owd_init(struct tquic_connection *conn)
{
	struct owd_sched_data *data;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return NULL;

	/* Default settings */
	data->prefer_forward = true;  /* Default to upload optimization */
	data->asymmetry_threshold_pct = 20;  /* 20% difference triggers asymmetry */
	data->min_switch_interval_ms = 100;  /* Avoid rapid path switching */

	return data;
}

static void owd_release(void *state)
{
	kfree(state);
}

/**
 * owd_select - Select path based on one-way delay characteristics
 * @state: Scheduler state
 * @conn: Connection
 * @skb: Packet being scheduled
 *
 * Path selection algorithm:
 * 1. If OWD data is available, use directional delays
 * 2. For upload-heavy traffic, prefer paths with lower forward delay
 * 3. For download/ACK traffic, prefer paths with lower reverse delay
 * 4. Fall back to RTT/2 estimate if no OWD data
 * 5. Apply hysteresis to avoid path flapping
 */
static struct tquic_path *owd_select(void *state, struct tquic_connection *conn,
				     struct sk_buff *skb)
{
	struct owd_sched_data *data = state;
	struct tquic_path *path, *best = NULL;
	struct tquic_owd_path_info info __maybe_unused;
	s64 best_delay = S64_MAX;
	ktime_t now = ktime_get();
	u64 time_since_switch_ms;

	if (!data)
		return conn->active_path;

	/* Check if enough time has passed since last path switch */
	time_since_switch_ms = ktime_ms_delta(now,
					      ns_to_ktime(data->last_path_switch_time * NSEC_PER_MSEC));

	rcu_read_lock();
	list_for_each_entry_rcu(path, &conn->paths, list) {
		s64 effective_delay;
		int ret __maybe_unused;

		if (path->state != TQUIC_PATH_ACTIVE)
			continue;

		/*
		 * Estimate one-way delay using RTT/2.
		 *
		 * When OWD measurement (draft-huitema-quic-1wd) is negotiated
		 * and active on the connection, we can use directional delay
		 * measurements from tquic_owd_get_path_info() for more accurate
		 * path selection, especially on asymmetric links. For now, we
		 * use the symmetric RTT/2 approximation.
		 */
		effective_delay = path->stats.rtt_smoothed / 2;

		/*
		 * Apply hysteresis: if this is the current path, give it
		 * a 10% advantage to avoid unnecessary switching.
		 */
		if (path == conn->active_path &&
		    time_since_switch_ms < data->min_switch_interval_ms) {
			effective_delay = effective_delay * 90 / 100;
		}

		/*
		 * Factor in congestion window utilization.
		 * A path with available capacity is preferred even if
		 * it has slightly higher delay.
		 */
		if (path->stats.cwnd > 0) {
			u64 in_flight = 0;

			if (path->stats.tx_bytes > path->stats.acked_bytes)
				in_flight = path->stats.tx_bytes - path->stats.acked_bytes;

			/* If path has spare capacity, reduce effective delay */
			if (in_flight < path->stats.cwnd / 2)
				effective_delay = effective_delay * 85 / 100;
		}

		if (effective_delay < best_delay) {
			best_delay = effective_delay;
			best = path;
		}
	}
	rcu_read_unlock();

	/* Update last switch time if we're changing paths */
	if (best && best != conn->active_path)
		data->last_path_switch_time = ktime_to_ms(now);

	return best ?: conn->active_path;
}

static void owd_feedback(void *state, struct tquic_path *path,
			 struct sk_buff *skb, bool success)
{
	/*
	 * OWD feedback is handled through the OWD state updates
	 * when ACK_1WD frames are processed. The scheduler will
	 * automatically adapt to new delay measurements.
	 */
}

static struct tquic_sched_ops __maybe_unused tquic_sched_owd = {
	.name = "owd",
	.init = owd_init,
	.release = owd_release,
	.select = owd_select,
	.feedback = owd_feedback,
};

/*
 * OWD-ECF Hybrid Scheduler
 *
 * Combines ECF (Earliest Completion First) with OWD awareness.
 * Uses one-way delay measurements when available for more accurate
 * completion time estimation, especially on asymmetric paths.
 */
struct owd_ecf_sched_data {
	u64 last_update_jiffies;
	bool owd_available;
};

static void *owd_ecf_init(struct tquic_connection *conn)
{
	struct owd_ecf_sched_data *data;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (data)
		data->last_update_jiffies = jiffies;

	return data;
}

static void owd_ecf_release(void *state)
{
	kfree(state);
}

/**
 * owd_ecf_select - ECF scheduler enhanced with OWD information
 *
 * Enhanced ECF formula when OWD is available:
 *   Completion_Time = Forward_OWD + (In_Flight + Pkt_Size) / Bandwidth
 *
 * This is more accurate than RTT-based ECF because:
 * - On asymmetric links, forward delay may differ significantly from RTT/2
 * - Download ACKs (reverse path) don't affect data delivery time
 */
static struct tquic_path *owd_ecf_select(void *state __maybe_unused,
					 struct tquic_connection *conn,
					 struct sk_buff *skb)
{
	struct tquic_path *path, *best = NULL;
	u64 min_completion = ULLONG_MAX;
	u32 pkt_size = skb->len;

	rcu_read_lock();
	list_for_each_entry_rcu(path, &conn->paths, list) {
		u64 completion_time;
		u64 in_flight_bytes;
		u64 queue_drain_time;
		s64 delay_us;
		u64 bandwidth;

		if (path->state != TQUIC_PATH_ACTIVE)
			continue;

		/* Calculate in-flight bytes */
		if (path->stats.tx_bytes > path->stats.acked_bytes)
			in_flight_bytes = path->stats.tx_bytes - path->stats.acked_bytes;
		else
			in_flight_bytes = 0;

		if (in_flight_bytes > path->stats.cwnd)
			in_flight_bytes = path->stats.cwnd;

		/*
		 * Estimate one-way delay for completion time calculation.
		 * When OWD measurement is integrated, use forward_delay_us
		 * from tquic_owd_get_path_info() for accurate delivery time.
		 */
		delay_us = path->stats.rtt_smoothed / 2;

		if (delay_us <= 0)
			delay_us = 50000;  /* 50ms default */

		/* Get bandwidth estimate */
		bandwidth = path->stats.bandwidth;
		if (bandwidth == 0) {
			if (path->stats.cwnd > 0 && path->stats.rtt_smoothed > 0)
				bandwidth = (u64)path->stats.cwnd * 1000000ULL /
					    path->stats.rtt_smoothed;
			else
				bandwidth = 125000;  /* 1 Mbps default */
		}

		/* Calculate completion time */
		queue_drain_time = ((in_flight_bytes + pkt_size) * 1000000ULL) / bandwidth;
		completion_time = (u64)delay_us + queue_drain_time;

		/* Apply loss rate penalty */
		if (path->stats.tx_packets > 100) {
			u64 loss_rate_pct = (path->stats.lost_packets * 100) /
					    path->stats.tx_packets;
			if (loss_rate_pct > 0 && loss_rate_pct < 50)
				completion_time = completion_time * 100 / (100 - loss_rate_pct);
		}

		if (completion_time < min_completion) {
			min_completion = completion_time;
			best = path;
		}
	}
	rcu_read_unlock();

	return best ?: conn->active_path;
}

static struct tquic_sched_ops __maybe_unused tquic_sched_owd_ecf = {
	.name = "owd-ecf",
	.init = owd_ecf_init,
	.release = owd_ecf_release,
	.select = owd_ecf_select,
};

/*
 * Module initialization - always compiled so built-in schedulers
 * are available for both in-tree and out-of-tree builds.
 */
#ifndef TQUIC_OUT_OF_TREE
static int __init tquic_sched_module_init(void)
{
	/* Register built-in schedulers */
	__tquic_sched_register(&tquic_sched_rr);
	__tquic_sched_register(&tquic_sched_minrtt);
	__tquic_sched_register(&tquic_sched_wrr);
	__tquic_sched_register(&tquic_sched_blest);
	__tquic_sched_register(&tquic_sched_redundant);
	__tquic_sched_register(&tquic_sched_ecf);

	/* Register OWD-aware schedulers (draft-huitema-quic-1wd) */
	__tquic_sched_register(&tquic_sched_owd);
	__tquic_sched_register(&tquic_sched_owd_ecf);

	/* Set minrtt as default */
	tquic_sched_set_default("minrtt");

	tquic_info("scheduler framework initialized\n");
	return 0;
}

static void __exit tquic_sched_module_exit(void)
{
	/* Unregister OWD-aware schedulers */
	__tquic_sched_unregister(&tquic_sched_owd_ecf);
	__tquic_sched_unregister(&tquic_sched_owd);

	/* Unregister built-in schedulers */
	__tquic_sched_unregister(&tquic_sched_ecf);
	__tquic_sched_unregister(&tquic_sched_redundant);
	__tquic_sched_unregister(&tquic_sched_blest);
	__tquic_sched_unregister(&tquic_sched_wrr);
	__tquic_sched_unregister(&tquic_sched_minrtt);
	__tquic_sched_unregister(&tquic_sched_rr);

	tquic_info("scheduler framework cleanup complete\n");
}

module_init(tquic_sched_module_init);
module_exit(tquic_sched_module_exit);

MODULE_DESCRIPTION("TQUIC Multipath Packet Scheduler Framework");
MODULE_LICENSE("GPL");
#else /* TQUIC_OUT_OF_TREE */
/*
 * Out-of-tree: register built-in schedulers via explicit init/exit
 * called from tquic_main.c (no separate module_init).
 */
int tquic_sched_framework_init(void)
{
	__tquic_sched_register(&tquic_sched_rr);
	__tquic_sched_register(&tquic_sched_minrtt);
	__tquic_sched_register(&tquic_sched_wrr);
	__tquic_sched_register(&tquic_sched_blest);
	__tquic_sched_register(&tquic_sched_redundant);
	__tquic_sched_register(&tquic_sched_ecf);
	__tquic_sched_register(&tquic_sched_owd);
	__tquic_sched_register(&tquic_sched_owd_ecf);

	tquic_sched_set_default("minrtt");

	tquic_info("scheduler framework initialized\n");
	return 0;
}

void tquic_sched_framework_exit(void)
{
	__tquic_sched_unregister(&tquic_sched_owd_ecf);
	__tquic_sched_unregister(&tquic_sched_owd);
	__tquic_sched_unregister(&tquic_sched_ecf);
	__tquic_sched_unregister(&tquic_sched_redundant);
	__tquic_sched_unregister(&tquic_sched_blest);
	__tquic_sched_unregister(&tquic_sched_wrr);
	__tquic_sched_unregister(&tquic_sched_minrtt);
	__tquic_sched_unregister(&tquic_sched_rr);

	tquic_info("scheduler framework cleanup complete\n");
}
#endif
