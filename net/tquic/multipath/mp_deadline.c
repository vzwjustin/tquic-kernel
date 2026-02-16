// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Multipath Deadline Integration
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Integrates deadline-aware scheduling with QUIC multipath extension.
 * Provides per-path deadline capability tracking and cross-path
 * coordination for deadline meeting.
 *
 * Key features:
 *   - Per-path deadline capability tracking
 *   - Cross-path deadline coordination
 *   - Path quality monitoring for deadline decisions
 *   - Dynamic path selection based on deadline requirements
 *   - Fallback path handling when primary cannot meet deadline
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/math64.h>
#include <linux/jhash.h>
#include <linux/ktime.h>
#include <linux/workqueue.h>
#include <linux/limits.h>
#include <net/tquic.h>

#include "mp_frame.h"
#include "mp_deadline.h"
#include "../sched/deadline_aware.h"
#include "../tquic_debug.h"
#include "../tquic_init.h"

/*
 * =============================================================================
 * Data Structures
 * =============================================================================
 */

/**
 * struct tquic_mp_deadline_path_info - Per-path deadline info
 * @path: Associated path
 * @deadline_capable: Whether path supports deadline scheduling
 * @min_feasible_deadline_us: Minimum feasible deadline
 * @current_load: Current deadline load on path (bytes pending)
 * @pending_deadlines: Number of pending deadlines
 * @deadline_miss_rate: Recent deadline miss rate (0-100)
 * @jitter_estimate_us: Estimated path jitter
 * @last_update: Last update timestamp
 * @stats: Per-path deadline statistics
 * @list: Link in connection's path info list
 * @rcu_head: RCU callback head
 */
struct tquic_mp_deadline_path_info {
	struct tquic_path *path;
	bool deadline_capable;
	u64 min_feasible_deadline_us;
	u64 current_load;
	u32 pending_deadlines;
	u8 deadline_miss_rate;
	u64 jitter_estimate_us;
	ktime_t last_update;

	struct {
		u64 deadlines_assigned;
		u64 deadlines_met;
		u64 deadlines_missed;
		u64 bytes_scheduled;
		u64 avg_delivery_us;
	} stats;

	struct list_head list;
	struct rcu_head rcu_head;
};

/**
 * struct tquic_mp_deadline_coordinator - Cross-path coordinator
 * @conn: Associated connection
 * @path_infos: List of per-path info structures
 * @num_paths: Number of tracked paths
 * @enabled: Whether coordination is enabled
 * @lock: Coordinator lock
 * @total_deadline_load: Total deadline bytes across all paths
 * @rebalance_threshold: Threshold for load rebalancing
 * @rebalance_work: Work item for async rebalancing
 * @stats: Coordinator statistics
 */
struct tquic_mp_deadline_coordinator {
	struct tquic_connection *conn;
	struct list_head path_infos;
	u32 num_paths;
	bool enabled;
	spinlock_t lock;

	u64 total_deadline_load;
	u64 rebalance_threshold;
	struct work_struct rebalance_work;

	struct {
		u64 assignments;
		u64 rebalances;
		u64 cross_path_switches;
		u64 coordination_decisions;
	} stats;
};

/* Memory cache for path info */
static struct kmem_cache *mp_deadline_info_cache;

/* Workqueue for coordination */
static struct workqueue_struct *mp_deadline_wq;

static inline bool mp_deadline_path_usable(const struct tquic_path *path)
{
	return path &&
	       (path->state == TQUIC_PATH_ACTIVE ||
		path->state == TQUIC_PATH_VALIDATED);
}

/*
 * =============================================================================
 * Path Info Management
 * =============================================================================
 */

/**
 * mp_deadline_alloc_path_info - Allocate path info structure
 * @path: Path to track
 */
static struct tquic_mp_deadline_path_info *
mp_deadline_alloc_path_info(struct tquic_path *path)
{
	struct tquic_mp_deadline_path_info *info;

	info = kmem_cache_zalloc(mp_deadline_info_cache, GFP_KERNEL);
	if (!info)
		return NULL;

	info->path = path;
	info->deadline_capable = true;
	info->last_update = ktime_get();
	INIT_LIST_HEAD(&info->list);

	return info;
}

/**
 * mp_deadline_free_path_info - Free path info structure
 * @info: Info to free
 */
static void mp_deadline_free_path_info(struct tquic_mp_deadline_path_info *info)
{
	if (info)
		kmem_cache_free(mp_deadline_info_cache, info);
}

/**
 * mp_deadline_free_path_info_rcu - RCU callback for free
 */
static void mp_deadline_free_path_info_rcu(struct rcu_head *head)
{
	struct tquic_mp_deadline_path_info *info;

	info = container_of(head, struct tquic_mp_deadline_path_info, rcu_head);
	mp_deadline_free_path_info(info);
}

/**
 * mp_deadline_find_path_info - Find info for path
 * @coord: Coordinator
 * @path: Path to find
 *
 * Must be called with RCU read lock or coordinator lock held.
 */
static struct tquic_mp_deadline_path_info *
mp_deadline_find_path_info(struct tquic_mp_deadline_coordinator *coord,
			   struct tquic_path *path)
{
	struct tquic_mp_deadline_path_info *info;

	list_for_each_entry_rcu(info, &coord->path_infos, list) {
		if (info->path == path)
			return info;
	}

	return NULL;
}

/*
 * =============================================================================
 * Path Capability Assessment
 * =============================================================================
 */

/**
 * mp_deadline_update_path_capabilities - Update path deadline capabilities
 * @coord: Coordinator
 * @path: Path to update
 *
 * Updates the deadline capability assessment for a path based on
 * current RTT, bandwidth, jitter, and loss statistics.
 */
static void mp_deadline_update_path_capabilities(
	struct tquic_mp_deadline_coordinator *coord, struct tquic_path *path)
{
	struct tquic_mp_deadline_path_info *info;
	u64 rtt_us, bandwidth, jitter_us;
	u64 min_deadline_us;

	tquic_dbg("mp_deadline: update_capabilities path=%u\n",
		  path ? path->path_id : 0);

	if (!coord || !path)
		return;

	spin_lock_bh(&coord->lock);

	info = mp_deadline_find_path_info(coord, path);
	if (!info) {
		/* Create new info */
		info = mp_deadline_alloc_path_info(path);
		if (!info) {
			spin_unlock_bh(&coord->lock);
			return;
		}
		list_add_tail_rcu(&info->list, &coord->path_infos);
		coord->num_paths++;
	}

	/* Get path metrics */
	rtt_us = path->stats.rtt_smoothed;
	if (rtt_us == 0)
		rtt_us = 100000; /* 100ms default */

	bandwidth = path->stats.bandwidth;
	if (bandwidth == 0)
		bandwidth = 125000; /* 1 Mbps default */

	jitter_us = path->stats.rtt_variance;
	info->jitter_estimate_us = jitter_us;

	/*
	 * Calculate minimum feasible deadline:
	 * min_deadline = RTT + (MTU / bandwidth) + 3*jitter
	 *
	 * The 3x jitter factor provides safety margin for
	 * deadline meeting probability.
	 */
	min_deadline_us = rtt_us;
	min_deadline_us += div64_u64(path->mtu * 1000000ULL, bandwidth);
	min_deadline_us += 3 * jitter_us;

	info->min_feasible_deadline_us = min_deadline_us;

	/* Assess deadline capability */
	if (!mp_deadline_path_usable(path)) {
		info->deadline_capable = false;
	} else if (jitter_us > rtt_us) {
		/* High jitter relative to RTT - unreliable for deadlines */
		info->deadline_capable = false;
	} else {
		info->deadline_capable = true;
	}

	/* Update miss rate from statistics */
	if (info->stats.deadlines_assigned > 10) {
		u64 miss_rate = div64_u64(info->stats.deadlines_missed * 100,
					  info->stats.deadlines_assigned);
		info->deadline_miss_rate = min_t(u64, miss_rate, 100);

		/* Disable deadline capability if miss rate too high */
		if (info->deadline_miss_rate > 30)
			info->deadline_capable = false;
	}

	info->last_update = ktime_get();

	spin_unlock_bh(&coord->lock);
}

/*
 * =============================================================================
 * Cross-Path Coordination
 * =============================================================================
 */

/**
 * mp_deadline_select_best_path - Select best path for deadline
 * @coord: Coordinator
 * @deadline_us: Deadline in microseconds
 * @data_len: Amount of data
 *
 * Selects the optimal path considering:
 *   - Path capability to meet deadline
 *   - Current load on each path
 *   - Jitter characteristics
 *   - Historical miss rates
 *
 * Returns: Best path, or NULL if no path can meet deadline
 */
struct tquic_path *
mp_deadline_select_best_path(struct tquic_mp_deadline_coordinator *coord,
			     u64 deadline_us, size_t data_len)
{
	struct tquic_mp_deadline_path_info *info;
	struct tquic_path *best_path = NULL;
	u64 best_score = ULLONG_MAX;

	tquic_dbg("mp_deadline: select_best deadline=%llu data_len=%zu\n",
		  deadline_us, data_len);

	if (!coord || !coord->enabled)
		return NULL;

	rcu_read_lock();

	list_for_each_entry_rcu(info, &coord->path_infos, list) {
		u64 score;
		u64 delivery_estimate;
		u64 bandwidth;

		if (!info->deadline_capable)
			continue;

		if (!mp_deadline_path_usable(info->path))
			continue;

		/* Check if path can meet deadline */
		if (info->min_feasible_deadline_us > deadline_us)
			continue;

		/* Calculate delivery estimate */
		bandwidth = info->path->stats.bandwidth;
		if (bandwidth == 0)
			bandwidth = 125000;

		delivery_estimate = info->path->stats.rtt_smoothed;
		delivery_estimate +=
			div64_u64(data_len * 1000000ULL, bandwidth);
		delivery_estimate += info->jitter_estimate_us * 2;

		if (delivery_estimate > deadline_us)
			continue;

		/*
		 * Scoring factors:
		 * - Delivery time (lower is better)
		 * - Current load (lower is better)
		 * - Miss rate (lower is better)
		 * - Slack time (higher is better)
		 */
		score = delivery_estimate;

		/* Load factor - penalize heavily loaded paths */
		if (info->current_load > 0) {
			u64 load_penalty =
				div64_u64(info->current_load * 100, bandwidth);
			score += load_penalty;
		}

		/* Miss rate penalty */
		score += info->deadline_miss_rate * 1000;

		/* Slack bonus */
		if (deadline_us > delivery_estimate) {
			u64 slack = deadline_us - delivery_estimate;
			u64 slack_bonus =
				min_t(u64, slack / 2, delivery_estimate / 2);
			score -= slack_bonus;
		}

		if (score < best_score) {
			best_score = score;
			best_path = info->path;
		}
	}

	rcu_read_unlock();

	if (best_path)
		coord->stats.assignments++;

	return best_path;
}
EXPORT_SYMBOL_GPL(mp_deadline_select_best_path);

/**
 * mp_deadline_coordinate_deadlines - Coordinate deadlines across paths
 * @coord: Coordinator
 * @deadlines: Array of pending deadlines
 * @num_deadlines: Number of deadlines
 *
 * Distributes pending deadlines across available paths to maximize
 * the probability of meeting all deadlines.
 *
 * Algorithm:
 *   1. Sort deadlines by urgency (earliest first)
 *   2. For each deadline, select best path
 *   3. Track load on each path
 *   4. Rebalance if load becomes uneven
 */
static void
mp_deadline_coordinate_deadlines(struct tquic_mp_deadline_coordinator *coord)
{
	/* This would be called periodically or on deadline arrival
	 * to optimize deadline distribution across paths.
	 *
	 * For now, we rely on per-deadline path selection.
	 */
	coord->stats.coordination_decisions++;
}

/**
 * mp_deadline_rebalance_work_fn - Work function for load rebalancing
 */
static void mp_deadline_rebalance_work_fn(struct work_struct *work)
{
	struct tquic_mp_deadline_coordinator *coord;

	coord = container_of(work, struct tquic_mp_deadline_coordinator,
			     rebalance_work);

	mp_deadline_coordinate_deadlines(coord);
	coord->stats.rebalances++;
}

/**
 * mp_deadline_check_rebalance - Check if rebalancing is needed
 * @coord: Coordinator
 *
 * Triggers rebalancing if load becomes too uneven across paths.
 */
static void
mp_deadline_check_rebalance(struct tquic_mp_deadline_coordinator *coord)
{
	struct tquic_mp_deadline_path_info *info;
	u64 max_load = 0;
	u64 min_load = ULLONG_MAX;

	if (!coord || coord->num_paths < 2)
		return;

	rcu_read_lock();
	list_for_each_entry_rcu(info, &coord->path_infos, list) {
		if (!info->deadline_capable)
			continue;

		if (info->current_load > max_load)
			max_load = info->current_load;
		if (info->current_load < min_load)
			min_load = info->current_load;
	}
	rcu_read_unlock();

	/* Rebalance if load difference exceeds threshold */
	if (max_load > min_load + coord->rebalance_threshold) {
		queue_work(mp_deadline_wq, &coord->rebalance_work);
	}
}

/*
 * =============================================================================
 * Path Quality Monitoring
 * =============================================================================
 */

/**
 * struct tquic_path_quality_sample - Path quality measurement
 * @rtt_us: RTT sample
 * @jitter_us: Jitter observation
 * @loss_detected: Whether loss was detected
 * @timestamp: Sample timestamp
 */
struct tquic_path_quality_sample {
	u64 rtt_us;
	u64 jitter_us;
	bool loss_detected;
	ktime_t timestamp;
};

/**
 * mp_deadline_record_quality_sample - Record path quality sample
 * @coord: Coordinator
 * @path: Path sampled
 * @sample: Quality sample
 */
static void
mp_deadline_record_quality_sample(struct tquic_mp_deadline_coordinator *coord,
				  struct tquic_path *path,
				  struct tquic_path_quality_sample *sample)
{
	struct tquic_mp_deadline_path_info *info;

	tquic_dbg("mp_deadline: quality_sample path=%u rtt=%llu jitter=%llu\n",
		  path ? path->path_id : 0,
		  sample ? sample->rtt_us : 0,
		  sample ? sample->jitter_us : 0);

	if (!coord || !path || !sample)
		return;

	spin_lock_bh(&coord->lock);

	info = mp_deadline_find_path_info(coord, path);
	if (info) {
		/* Update jitter estimate with exponential averaging */
		if (info->jitter_estimate_us == 0) {
			info->jitter_estimate_us = sample->jitter_us;
		} else {
			info->jitter_estimate_us =
				(info->jitter_estimate_us * 7 +
				 sample->jitter_us) /
				8;
		}

		/* Loss affects deadline capability */
		if (sample->loss_detected) {
			info->stats.deadlines_missed++;
		}

		/* Recalculate min feasible deadline */
		info->min_feasible_deadline_us =
			sample->rtt_us + 3 * info->jitter_estimate_us;
	}

	spin_unlock_bh(&coord->lock);
}

/**
 * mp_deadline_record_delivery - Record deadline delivery result
 * @coord: Coordinator
 * @path: Path used
 * @deadline_met: Whether deadline was met
 * @delivery_time_us: Actual delivery time
 */
void mp_deadline_record_delivery(struct tquic_mp_deadline_coordinator *coord,
				 struct tquic_path *path, bool deadline_met,
				 u64 delivery_time_us)
{
	struct tquic_mp_deadline_path_info *info;

	tquic_dbg("mp_deadline: record_delivery path=%u met=%d time=%llu\n",
		  path ? path->path_id : 0, deadline_met, delivery_time_us);

	if (!coord || !path)
		return;

	spin_lock_bh(&coord->lock);

	info = mp_deadline_find_path_info(coord, path);
	if (info) {
		info->stats.deadlines_assigned++;

		if (deadline_met) {
			info->stats.deadlines_met++;
		} else {
			info->stats.deadlines_missed++;
		}

		/* Update average delivery time */
		if (info->stats.avg_delivery_us == 0) {
			info->stats.avg_delivery_us = delivery_time_us;
		} else {
			info->stats.avg_delivery_us =
				(info->stats.avg_delivery_us * 7 +
				 delivery_time_us) /
				8;
		}

		/* Update miss rate */
		if (info->stats.deadlines_assigned > 0) {
			info->deadline_miss_rate =
				div64_u64(info->stats.deadlines_missed * 100,
					  info->stats.deadlines_assigned);
		}
	}

	spin_unlock_bh(&coord->lock);
}
EXPORT_SYMBOL_GPL(mp_deadline_record_delivery);

/*
 * =============================================================================
 * Coordinator API
 * =============================================================================
 */

/**
 * tquic_mp_deadline_coordinator_create - Create coordinator
 * @conn: Connection
 *
 * Returns: New coordinator, or NULL on failure
 */
struct tquic_mp_deadline_coordinator *
tquic_mp_deadline_coordinator_create(struct tquic_connection *conn)
{
	struct tquic_mp_deadline_coordinator *coord;
	struct tquic_path *path;

	tquic_dbg("mp_deadline: coordinator_create\n");

	if (!conn)
		return NULL;

	coord = kzalloc(sizeof(*coord), GFP_KERNEL);
	if (!coord)
		return NULL;

	coord->conn = conn;
	INIT_LIST_HEAD(&coord->path_infos);
	spin_lock_init(&coord->lock);
	INIT_WORK(&coord->rebalance_work, mp_deadline_rebalance_work_fn);
	coord->rebalance_threshold = 1024 * 1024; /* 1 MB */
	coord->enabled = true;

	/* Initialize path infos for existing paths */
	list_for_each_entry(path, &conn->paths, list) {
		mp_deadline_update_path_capabilities(coord, path);
	}

	return coord;
}
EXPORT_SYMBOL_GPL(tquic_mp_deadline_coordinator_create);

/**
 * tquic_mp_deadline_coordinator_destroy - Destroy coordinator
 * @coord: Coordinator to destroy
 */
void tquic_mp_deadline_coordinator_destroy(
	struct tquic_mp_deadline_coordinator *coord)
{
	struct tquic_mp_deadline_path_info *info, *tmp;

	tquic_dbg("mp_deadline: coordinator_destroy num_paths=%u\n",
		  coord ? coord->num_paths : 0);

	if (!coord)
		return;

	cancel_work_sync(&coord->rebalance_work);

	spin_lock_bh(&coord->lock);

	list_for_each_entry_safe(info, tmp, &coord->path_infos, list) {
		list_del_rcu(&info->list);
		call_rcu(&info->rcu_head, mp_deadline_free_path_info_rcu);
	}

	spin_unlock_bh(&coord->lock);

	/* Wait for RCU grace period */
	synchronize_rcu();

	pr_info("tquic_mp_deadline: Coordinator stats - "
		"assignments=%llu rebalances=%llu switches=%llu\n",
		coord->stats.assignments, coord->stats.rebalances,
		coord->stats.cross_path_switches);

	kfree(coord);
}
EXPORT_SYMBOL_GPL(tquic_mp_deadline_coordinator_destroy);

/**
 * tquic_mp_deadline_path_added - Notify of new path
 * @coord: Coordinator
 * @path: New path
 */
void tquic_mp_deadline_path_added(struct tquic_mp_deadline_coordinator *coord,
				  struct tquic_path *path)
{
	if (!coord || !path)
		return;

	mp_deadline_update_path_capabilities(coord, path);
}
EXPORT_SYMBOL_GPL(tquic_mp_deadline_path_added);

/**
 * tquic_mp_deadline_path_removed - Notify of path removal
 * @coord: Coordinator
 * @path: Removed path
 */
void tquic_mp_deadline_path_removed(struct tquic_mp_deadline_coordinator *coord,
				    struct tquic_path *path)
{
	struct tquic_mp_deadline_path_info *info;

	tquic_dbg("mp_deadline: path_removed path=%u\n",
		  path ? path->path_id : 0);

	if (!coord || !path)
		return;

	spin_lock_bh(&coord->lock);

	info = mp_deadline_find_path_info(coord, path);
	if (info) {
		list_del_rcu(&info->list);
		coord->num_paths--;
		call_rcu(&info->rcu_head, mp_deadline_free_path_info_rcu);
	}

	spin_unlock_bh(&coord->lock);
}
EXPORT_SYMBOL_GPL(tquic_mp_deadline_path_removed);

/**
 * tquic_mp_deadline_path_state_changed - Notify of path state change
 * @coord: Coordinator
 * @path: Changed path
 * @new_state: New state
 */
void tquic_mp_deadline_path_state_changed(
	struct tquic_mp_deadline_coordinator *coord, struct tquic_path *path,
	enum tquic_path_state new_state)
{
	tquic_dbg("mp_deadline: path_state_changed path=%u state=%d\n",
		  path ? path->path_id : 0, new_state);

	if (!coord || !path)
		return;

	mp_deadline_update_path_capabilities(coord, path);

	/* Trigger rebalance on path failure */
	if (new_state == TQUIC_PATH_FAILED ||
	    new_state == TQUIC_PATH_UNAVAILABLE) {
		coord->stats.cross_path_switches++;
		mp_deadline_check_rebalance(coord);
	}
}
EXPORT_SYMBOL_GPL(tquic_mp_deadline_path_state_changed);

/**
 * tquic_mp_deadline_assign_load - Assign deadline load to path
 * @coord: Coordinator
 * @path: Target path
 * @bytes: Bytes to add
 */
void tquic_mp_deadline_assign_load(struct tquic_mp_deadline_coordinator *coord,
				   struct tquic_path *path, u64 bytes)
{
	struct tquic_mp_deadline_path_info *info;

	if (!coord || !path)
		return;

	spin_lock_bh(&coord->lock);

	info = mp_deadline_find_path_info(coord, path);
	if (info) {
		info->current_load += bytes;
		info->pending_deadlines++;
		info->stats.bytes_scheduled += bytes;
		coord->total_deadline_load += bytes;
	}

	spin_unlock_bh(&coord->lock);

	mp_deadline_check_rebalance(coord);
}
EXPORT_SYMBOL_GPL(tquic_mp_deadline_assign_load);

/**
 * tquic_mp_deadline_complete_load - Complete deadline load on path
 * @coord: Coordinator
 * @path: Target path
 * @bytes: Bytes completed
 */
void tquic_mp_deadline_complete_load(struct tquic_mp_deadline_coordinator *coord,
				     struct tquic_path *path, u64 bytes)
{
	struct tquic_mp_deadline_path_info *info;

	if (!coord || !path)
		return;

	spin_lock_bh(&coord->lock);

	info = mp_deadline_find_path_info(coord, path);
	if (info) {
		if (info->current_load >= bytes)
			info->current_load -= bytes;
		else
			info->current_load = 0;

		if (info->pending_deadlines > 0)
			info->pending_deadlines--;

		if (coord->total_deadline_load >= bytes)
			coord->total_deadline_load -= bytes;
		else
			coord->total_deadline_load = 0;
	}

	spin_unlock_bh(&coord->lock);
}
EXPORT_SYMBOL_GPL(tquic_mp_deadline_complete_load);

/*
 * =============================================================================
 * Statistics
 * =============================================================================
 */

/**
 * struct tquic_mp_deadline_stats - Multipath deadline statistics
 */
struct tquic_mp_deadline_stats {
	u32 num_paths;
	u32 deadline_capable_paths;
	u64 total_load;
	u64 assignments;
	u64 rebalances;
	u64 cross_path_switches;
};

/**
 * tquic_mp_deadline_get_stats - Get multipath deadline statistics
 * @coord: Coordinator
 * @stats: Output statistics
 */
void tquic_mp_deadline_get_stats(struct tquic_mp_deadline_coordinator *coord,
				 struct tquic_mp_deadline_stats *stats)
{
	struct tquic_mp_deadline_path_info *info;

	if (!coord || !stats)
		return;

	memset(stats, 0, sizeof(*stats));

	rcu_read_lock();

	stats->num_paths = coord->num_paths;
	stats->total_load = coord->total_deadline_load;
	stats->assignments = coord->stats.assignments;
	stats->rebalances = coord->stats.rebalances;
	stats->cross_path_switches = coord->stats.cross_path_switches;

	list_for_each_entry_rcu(info, &coord->path_infos, list) {
		if (info->deadline_capable)
			stats->deadline_capable_paths++;
	}

	rcu_read_unlock();
}
EXPORT_SYMBOL_GPL(tquic_mp_deadline_get_stats);

/*
 * =============================================================================
 * Module Initialization
 * =============================================================================
 */

int __init tquic_mp_deadline_init(void)
{
	mp_deadline_info_cache =
		kmem_cache_create("tquic_mp_deadline_info",
				  sizeof(struct tquic_mp_deadline_path_info), 0,
				  SLAB_HWCACHE_ALIGN, NULL);
	if (!mp_deadline_info_cache)
		return -ENOMEM;

	mp_deadline_wq = alloc_workqueue("tquic_mp_deadline", WQ_UNBOUND, 0);
	if (!mp_deadline_wq) {
		kmem_cache_destroy(mp_deadline_info_cache);
		return -ENOMEM;
	}

	pr_info("tquic: Multipath deadline coordination initialized\n");
	return 0;
}

void tquic_mp_deadline_exit(void)
{
	if (mp_deadline_wq)
		destroy_workqueue(mp_deadline_wq);

	if (mp_deadline_info_cache)
		kmem_cache_destroy(mp_deadline_info_cache);

	pr_info("tquic: Multipath deadline coordination cleaned up\n");
}

#ifndef TQUIC_OUT_OF_TREE
MODULE_DESCRIPTION("TQUIC Multipath Deadline Coordination");
MODULE_LICENSE("GPL");
#endif
