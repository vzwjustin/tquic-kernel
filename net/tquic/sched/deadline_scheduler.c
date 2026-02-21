// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Earliest Deadline First (EDF) Scheduler
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Implements the Earliest Deadline First scheduling algorithm for
 * deadline-aware multipath QUIC. This is the core scheduling engine
 * that determines packet ordering based on deadlines.
 *
 * Key features:
 *   - EDF scheduling within streams for optimal deadline meeting
 *   - Deadline-aware path selection based on RTT, bandwidth, jitter
 *   - Admission control for deadline feasibility
 *   - Graceful degradation for missed deadlines
 *   - Integration with ECF and BLEST for non-deadline traffic
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/rbtree.h>
#include <linux/math64.h>
#include <linux/rculist.h>
#include <linux/rcupdate.h>
#include <linux/sort.h>
#include <net/tquic.h>

#include "deadline_aware.h"
#include "../tquic_debug.h"
#ifdef CONFIG_TQUIC_MULTIPATH
#include "../multipath/mp_deadline.h"
#endif

/* Forward declarations for exported functions not in a public header */
struct tquic_edf_scheduler;
struct tquic_edf_stats;
struct tquic_edf_scheduler *
tquic_edf_scheduler_create(struct tquic_connection *conn, u32 max_entries);
void tquic_edf_scheduler_destroy(struct tquic_edf_scheduler *sched);
int tquic_edf_enqueue(struct tquic_edf_scheduler *sched, struct sk_buff *skb,
		      u64 stream_id, u64 deadline_us, u8 priority);
struct sk_buff *tquic_edf_dequeue(struct tquic_edf_scheduler *sched,
				  struct tquic_path **path);
struct sk_buff *tquic_edf_peek(struct tquic_edf_scheduler *sched);
ktime_t tquic_edf_get_next_deadline(struct tquic_edf_scheduler *sched);
int tquic_edf_cancel_stream(struct tquic_edf_scheduler *sched, u64 stream_id);
void tquic_edf_update_path(struct tquic_edf_scheduler *sched,
			   struct tquic_path *path);
void tquic_edf_get_stats(struct tquic_edf_scheduler *sched,
			 struct tquic_edf_stats *stats);

/*
 * =============================================================================
 * EDF Scheduler Data Structures
 * =============================================================================
 */

/**
 * struct tquic_edf_entry - Entry in EDF scheduling queue
 * @deadline: Absolute deadline (ktime)
 * @stream_id: Associated stream
 * @skb: Packet to be scheduled
 * @data_offset: Offset of data in stream
 * @data_len: Length of data
 * @priority: Scheduling priority
 * @node: RB-tree node for deadline ordering
 * @list_node: List node for per-stream queue
 * @selected_path: Path selected for this entry
 * @scheduled: Whether entry has been scheduled
 * @retransmit: Whether this is a retransmission
 */
struct tquic_edf_entry {
	ktime_t deadline;
	u64 stream_id;
	struct sk_buff *skb;
	u64 data_offset;
	size_t data_len;
	u8 priority;
	struct rb_node node;
	struct list_head list_node;
	struct tquic_path *selected_path;
	bool scheduled;
	bool retransmit;
};

/**
 * struct tquic_edf_scheduler - EDF scheduler state
 * @conn: Associated connection
 * @edf_tree: RB-tree for EDF ordering (earliest deadline first)
 * @entry_count: Number of entries in scheduler
 * @max_entries: Maximum entries allowed
 * @lock: Scheduler lock
 * @stream_queues: Per-stream entry lists
 * @stats: Scheduler statistics
 */
struct tquic_edf_scheduler {
	struct tquic_connection *conn;
	struct rb_root edf_tree;
	u32 entry_count;
	u32 max_entries;
	spinlock_t lock;
	struct list_head stream_queues;

	struct {
		u64 entries_scheduled;
		u64 entries_dropped;
		u64 deadlines_met;
		u64 deadlines_missed;
		u64 path_switches;
		ktime_t avg_lateness;
	} stats;
};

static inline bool edf_path_usable(const struct tquic_path *path)
{
	return path &&
	       (path->state == TQUIC_PATH_ACTIVE ||
		path->state == TQUIC_PATH_VALIDATED);
}

/**
 * struct tquic_stream_edf_queue - Per-stream EDF queue
 * @stream_id: Stream identifier
 * @entries: List of EDF entries for this stream
 * @entry_count: Number of entries
 * @total_bytes: Total bytes pending
 * @list_node: Link in scheduler's stream_queues list
 */
struct tquic_stream_edf_queue {
	u64 stream_id;
	struct list_head entries;
	u32 entry_count;
	u64 total_bytes;
	struct list_head list_node;
};

/* Memory cache for EDF entries */
static struct kmem_cache *edf_entry_cache;
static struct kmem_cache *edf_stream_queue_cache;

/*
 * =============================================================================
 * EDF Tree Operations
 * =============================================================================
 */

/**
 * edf_tree_insert - Insert entry into EDF tree
 * @root: RB-tree root
 * @entry: Entry to insert
 *
 * Inserts entry maintaining earliest-deadline-first order.
 * Ties are broken by priority (lower priority value = higher priority).
 */
static void edf_tree_insert(struct rb_root *root, struct tquic_edf_entry *entry)
{
	struct rb_node **new = &root->rb_node;
	struct rb_node *parent = NULL;

	while (*new) {
		struct tquic_edf_entry *this;
		int cmp;

		this = rb_entry(*new, struct tquic_edf_entry, node);
		parent = *new;

		/* Compare by deadline first */
		if (ktime_before(entry->deadline, this->deadline))
			cmp = -1;
		else if (ktime_after(entry->deadline, this->deadline))
			cmp = 1;
		else
			/* Deadline tie - use priority (lower = higher priority) */
			cmp = (int)entry->priority - (int)this->priority;

		if (cmp < 0)
			new = &((*new)->rb_left);
		else
			new = &((*new)->rb_right);
	}

	rb_link_node(&entry->node, parent, new);
	rb_insert_color(&entry->node, root);
}

/**
 * edf_tree_first - Get entry with earliest deadline
 * @root: RB-tree root
 *
 * Returns: First (earliest deadline) entry, or NULL if empty
 */
static struct tquic_edf_entry *edf_tree_first(struct rb_root *root)
{
	struct rb_node *node = rb_first(root);

	if (!node)
		return NULL;

	return rb_entry(node, struct tquic_edf_entry, node);
}

/**
 * edf_tree_remove - Remove entry from EDF tree
 * @root: RB-tree root
 * @entry: Entry to remove
 */
static void edf_tree_remove(struct rb_root *root, struct tquic_edf_entry *entry)
{
	rb_erase(&entry->node, root);
	RB_CLEAR_NODE(&entry->node);
}

/*
 * =============================================================================
 * Path Selection for EDF
 * =============================================================================
 */

/**
 * struct path_score - Path scoring for selection
 * @path: The path being scored
 * @score: Computed score (lower is better)
 * @can_meet_deadline: Whether path can meet the deadline
 * @estimated_delivery_us: Estimated delivery time
 * @slack_us: Slack time (deadline - estimated delivery)
 */
struct path_score {
	struct tquic_path *path;
	u64 score;
	bool can_meet_deadline;
	u64 estimated_delivery_us;
	s64 slack_us;
};

/**
 * edf_estimate_path_delivery - Estimate delivery time on path
 * @path: Target path
 * @data_len: Amount of data
 *
 * Comprehensive estimation including:
 *   - RTT (propagation + processing delay)
 *   - Transmission delay (data / bandwidth)
 *   - Queuing delay (in-flight / bandwidth)
 *   - Jitter margin (2x RTT variance)
 *   - Loss retransmission overhead
 *
 * Returns: Estimated delivery time in microseconds
 */
static u64 edf_estimate_path_delivery(struct tquic_path *path, size_t data_len)
{
	u64 rtt_us;
	u64 tx_delay_us;
	u64 queue_delay_us;
	u64 jitter_us;
	u64 loss_overhead_us = 0;
	u64 bandwidth;
	u64 in_flight;

	if (!edf_path_usable(path))
		return ULLONG_MAX;

	/* Base RTT */
	rtt_us = path->stats.rtt_smoothed;
	if (rtt_us == 0)
		rtt_us = 100000; /* 100ms default */

	/* Bandwidth estimate */
	bandwidth = path->stats.bandwidth;
	if (bandwidth == 0) {
		/* Derive from cwnd and RTT */
		if (path->stats.cwnd > 0 && rtt_us > 0)
			bandwidth = div64_u64(
				(u64)path->stats.cwnd * 1000000ULL, rtt_us);
		else
			bandwidth = 125000; /* 1 Mbps default */
	}

	/* Transmission delay */
	tx_delay_us = div64_u64(data_len * 1000000ULL, bandwidth);

	/* Queuing delay (bytes in flight) */
	if (path->stats.tx_bytes > path->stats.acked_bytes)
		in_flight = path->stats.tx_bytes - path->stats.acked_bytes;
	else
		in_flight = 0;

	if (in_flight > path->stats.cwnd)
		in_flight = path->stats.cwnd;
	queue_delay_us = div64_u64(in_flight * 1000000ULL, bandwidth);

	/* Jitter margin (2x RTT variance) */
	jitter_us = 2 * path->stats.rtt_variance;

	/* Loss overhead - probability of retransmit */
	if (path->stats.tx_packets > 100) {
		u64 loss_rate = div64_u64(path->stats.lost_packets * 100,
					  path->stats.tx_packets);
		if (loss_rate > 0 && loss_rate < 50) {
			/* Expected extra RTT for retransmit */
			loss_overhead_us = div64_u64(rtt_us * loss_rate, 100);
		}
	}

	return rtt_us + tx_delay_us + queue_delay_us + jitter_us +
	       loss_overhead_us;
}

/**
 * edf_score_path - Score a path for deadline meeting
 * @path: Path to score
 * @deadline: Target deadline
 * @data_len: Amount of data
 * @score: Output score structure
 */
static void edf_score_path(struct tquic_path *path, ktime_t deadline,
			   size_t data_len, struct path_score *score)
{
	ktime_t now = ktime_get();
	s64 time_remaining_us;
	u64 delivery_us;

	memset(score, 0, sizeof(*score));
	score->path = path;

	if (!edf_path_usable(path)) {
		score->score = ULLONG_MAX;
		return;
	}

	time_remaining_us = ktime_us_delta(deadline, now);
	delivery_us = edf_estimate_path_delivery(path, data_len);

	score->estimated_delivery_us = delivery_us;

	if (time_remaining_us <= 0) {
		/* Deadline already passed */
		score->can_meet_deadline = false;
		score->slack_us = time_remaining_us;
		score->score = delivery_us + 1000000; /* 1s penalty */
	} else if (delivery_us <= (u64)time_remaining_us) {
		/* Can meet deadline */
		score->can_meet_deadline = true;
		score->slack_us = time_remaining_us - delivery_us;

		/*
		 * Score formula:
		 * - Base: delivery time
		 * - Bonus: for having slack (can absorb jitter)
		 * - Penalty: none if we can meet deadline
		 *
		 * Lower score is better.
		 */
		score->score = delivery_us;

		/* Slack bonus - prefer paths with more margin */
		if (score->slack_us > 0) {
			u64 slack_bonus = min_t(u64, score->slack_us / 4,
						delivery_us / 2);
			score->score -= slack_bonus;
		}
	} else {
		/* Cannot meet deadline */
		score->can_meet_deadline = false;
		score->slack_us = time_remaining_us - delivery_us;

		/* Penalty proportional to how much we miss by */
		score->score =
			delivery_us + (delivery_us - time_remaining_us) * 2;
	}
}

/**
 * edf_select_path - Select best path for deadline
 * @sched: EDF scheduler
 * @entry: Entry to schedule
 *
 * Evaluates all paths and selects the one most likely to meet the deadline.
 *
 * Selection criteria:
 *   1. Prefer paths that can meet deadline
 *   2. Among feasible paths, prefer those with more slack
 *   3. Among infeasible paths, prefer fastest delivery
 *
 * Returns: Selected path, or NULL if no suitable path
 */
static struct tquic_path *edf_select_path(struct tquic_edf_scheduler *sched,
					  struct tquic_edf_entry *entry)
{
	struct tquic_path *path, *best_path = NULL;
	struct path_score best_score = { .score = ULLONG_MAX };
	struct path_score current_score;

	if (!sched || !sched->conn || !entry)
		return NULL;

	list_for_each_entry(path, &sched->conn->paths, list) {
		if (!edf_path_usable(path))
			continue;

		edf_score_path(path, entry->deadline, entry->data_len,
			       &current_score);

		/*
		 * Priority-weighted scoring:
		 * Higher priority (lower number) gets score reduction
		 */
		current_score.score >>= (TQUIC_DEADLINE_PRIO_LEVELS - 1 -
					 min_t(u8, entry->priority,
					       TQUIC_DEADLINE_PRIO_LEVELS - 1));

		if (current_score.score < best_score.score) {
			best_score = current_score;
			best_path = path;
		}
	}

	/* Track statistics */
	if (best_path) {
		if (best_score.can_meet_deadline)
			sched->stats.deadlines_met++;
		else
			sched->stats.deadlines_missed++;

		if (entry->selected_path && entry->selected_path != best_path)
			sched->stats.path_switches++;
	}

	return best_path;
}

/*
 * =============================================================================
 * Admission Control
 * =============================================================================
 */

/**
 * edf_check_admission - Check if new deadline can be admitted
 * @sched: EDF scheduler
 * @deadline_us: Relative deadline in microseconds
 * @data_len: Amount of data
 * @priority: Scheduling priority
 *
 * Performs admission control to determine if a new deadline should be
 * accepted. Considers:
 *   - Feasibility on at least one path
 *   - Scheduler capacity (max entries)
 *   - Impact on existing deadlines
 *
 * Returns: true if deadline should be admitted
 */
static bool edf_check_admission(struct tquic_edf_scheduler *sched,
				u64 deadline_us, size_t data_len, u8 priority)
{
	struct tquic_path *path;
	ktime_t deadline;
	bool feasible = false;

	if (!sched || !sched->conn)
		return false;

	/* Check capacity */
	if (sched->entry_count >= sched->max_entries)
		return false;

	/* Check feasibility on any path */
	deadline = ktime_add_us(ktime_get(), deadline_us);

	list_for_each_entry(path, &sched->conn->paths, list) {
		struct path_score score;

		if (!edf_path_usable(path))
			continue;

		edf_score_path(path, deadline, data_len, &score);
		if (score.can_meet_deadline) {
			feasible = true;
			break;
		}
	}

	/*
	 * Even if not feasible, admit high-priority deadlines
	 * for best-effort delivery
	 */
	if (!feasible && priority >= TQUIC_DEADLINE_PRIO_NORMAL)
		return false;

	return true;
}

/*
 * =============================================================================
 * EDF Scheduler API
 * =============================================================================
 */

/**
 * tquic_edf_scheduler_create - Create EDF scheduler
 * @conn: Connection
 * @max_entries: Maximum scheduling entries
 *
 * Returns: New scheduler, or NULL on failure
 */
struct tquic_edf_scheduler *
tquic_edf_scheduler_create(struct tquic_connection *conn, u32 max_entries)
{
	struct tquic_edf_scheduler *sched;

	if (!conn)
		return NULL;

	sched = kzalloc(sizeof(*sched), GFP_KERNEL);
	if (!sched)
		return NULL;

	sched->conn = conn;
	sched->edf_tree = RB_ROOT;
	sched->max_entries = max_entries ?: 1024;
	spin_lock_init(&sched->lock);
	INIT_LIST_HEAD(&sched->stream_queues);

	return sched;
}
EXPORT_SYMBOL_GPL(tquic_edf_scheduler_create);

/**
 * tquic_edf_scheduler_destroy - Destroy EDF scheduler
 * @sched: Scheduler to destroy
 */
void tquic_edf_scheduler_destroy(struct tquic_edf_scheduler *sched)
{
	struct tquic_edf_entry *entry;
	struct tquic_stream_edf_queue *queue, *tmp_queue;
	struct rb_node *node;

	if (!sched)
		return;

	spin_lock_bh(&sched->lock);

	/* Free all entries */
	while ((node = rb_first(&sched->edf_tree))) {
		entry = rb_entry(node, struct tquic_edf_entry, node);
		rb_erase(node, &sched->edf_tree);
		kmem_cache_free(edf_entry_cache, entry);
	}

	/* Free stream queues */
	list_for_each_entry_safe(queue, tmp_queue, &sched->stream_queues,
				 list_node) {
		list_del_init(&queue->list_node);
		kmem_cache_free(edf_stream_queue_cache, queue);
	}

	spin_unlock_bh(&sched->lock);

	pr_info("tquic_edf: Scheduler stats - scheduled=%llu met=%llu missed=%llu\n",
		sched->stats.entries_scheduled, sched->stats.deadlines_met,
		sched->stats.deadlines_missed);

	kfree(sched);
}
EXPORT_SYMBOL_GPL(tquic_edf_scheduler_destroy);

/**
 * tquic_edf_enqueue - Enqueue packet with deadline
 * @sched: EDF scheduler
 * @skb: Packet to schedule
 * @stream_id: Stream ID
 * @deadline_us: Relative deadline in microseconds
 * @priority: Scheduling priority
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_edf_enqueue(struct tquic_edf_scheduler *sched, struct sk_buff *skb,
		      u64 stream_id, u64 deadline_us, u8 priority)
{
	struct tquic_edf_entry *entry;

	if (!sched || !skb)
		return -EINVAL;

	/* Admission control */
	if (!edf_check_admission(sched, deadline_us, skb->len, priority)) {
		sched->stats.entries_dropped++;
		return -ENOSPC;
	}

	/* Allocate entry */
	entry = kmem_cache_zalloc(edf_entry_cache, GFP_ATOMIC);
	if (!entry)
		return -ENOMEM;

	entry->deadline = ktime_add_us(ktime_get(), deadline_us);
	entry->stream_id = stream_id;
	entry->skb = skb;
	entry->data_len = skb->len;
	entry->priority = priority;
	entry->scheduled = false;
	entry->retransmit = false;
	INIT_LIST_HEAD(&entry->list_node);
	RB_CLEAR_NODE(&entry->node);

	/* Insert into EDF tree and select path under lock */
	spin_lock_bh(&sched->lock);
	entry->selected_path = edf_select_path(sched, entry);
	edf_tree_insert(&sched->edf_tree, entry);
	sched->entry_count++;
	spin_unlock_bh(&sched->lock);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_edf_enqueue);

/**
 * tquic_edf_dequeue - Dequeue next packet to send
 * @sched: EDF scheduler
 * @path: Output selected path
 *
 * Returns: Next packet to send, or NULL if queue empty
 */
struct sk_buff *tquic_edf_dequeue(struct tquic_edf_scheduler *sched,
				  struct tquic_path **path)
{
	struct tquic_edf_entry *entry;
	struct sk_buff *skb = NULL;

	if (!sched)
		return NULL;

	spin_lock_bh(&sched->lock);

	entry = edf_tree_first(&sched->edf_tree);
	if (!entry) {
		spin_unlock_bh(&sched->lock);
		return NULL;
	}

	/* Remove from tree */
	edf_tree_remove(&sched->edf_tree, entry);
	sched->entry_count--;

	/* Get packet and path */
	skb = entry->skb;
	if (path)
		*path = entry->selected_path;

	entry->scheduled = true;
	sched->stats.entries_scheduled++;

	spin_unlock_bh(&sched->lock);

	/* Free entry (packet ownership transfers to caller) */
	kmem_cache_free(edf_entry_cache, entry);

	return skb;
}
EXPORT_SYMBOL_GPL(tquic_edf_dequeue);

/**
 * tquic_edf_peek - Peek at next packet without dequeuing
 * @sched: EDF scheduler
 *
 * Returns: Next packet, or NULL if empty (does not transfer ownership)
 */
struct sk_buff *tquic_edf_peek(struct tquic_edf_scheduler *sched)
{
	struct tquic_edf_entry *entry;
	struct sk_buff *skb = NULL;

	if (!sched)
		return NULL;

	spin_lock_bh(&sched->lock);
	entry = edf_tree_first(&sched->edf_tree);
	if (entry)
		skb = entry->skb;
	spin_unlock_bh(&sched->lock);

	return skb;
}
EXPORT_SYMBOL_GPL(tquic_edf_peek);

/**
 * tquic_edf_get_next_deadline - Get deadline of next packet
 * @sched: EDF scheduler
 *
 * Returns: Next deadline, or KTIME_MAX if queue empty
 */
ktime_t tquic_edf_get_next_deadline(struct tquic_edf_scheduler *sched)
{
	struct tquic_edf_entry *entry;
	ktime_t deadline = KTIME_MAX;

	if (!sched)
		return KTIME_MAX;

	spin_lock_bh(&sched->lock);
	entry = edf_tree_first(&sched->edf_tree);
	if (entry)
		deadline = entry->deadline;
	spin_unlock_bh(&sched->lock);

	return deadline;
}
EXPORT_SYMBOL_GPL(tquic_edf_get_next_deadline);

/**
 * tquic_edf_cancel_stream - Cancel all entries for a stream
 * @sched: EDF scheduler
 * @stream_id: Stream to cancel
 *
 * Returns: Number of entries cancelled
 */
int tquic_edf_cancel_stream(struct tquic_edf_scheduler *sched, u64 stream_id)
{
	struct tquic_edf_entry *entry;
	struct rb_node *node, *next;
	int cancelled = 0;

	if (!sched)
		return 0;

	spin_lock_bh(&sched->lock);

	/* Walk tree and remove matching entries */
	for (node = rb_first(&sched->edf_tree); node; node = next) {
		next = rb_next(node);
		entry = rb_entry(node, struct tquic_edf_entry, node);

		if (entry->stream_id == stream_id) {
			edf_tree_remove(&sched->edf_tree, entry);
			sched->entry_count--;

			/* Free the skb if we own it */
			if (entry->skb)
				kfree_skb(entry->skb);

			kmem_cache_free(edf_entry_cache, entry);
			cancelled++;
		}
	}

	spin_unlock_bh(&sched->lock);

	return cancelled;
}
EXPORT_SYMBOL_GPL(tquic_edf_cancel_stream);

/**
 * tquic_edf_update_path - Update path selection after path change
 * @sched: EDF scheduler
 * @path: Path that changed
 *
 * Re-evaluates path selection for all entries that were using the
 * changed path.
 */
void tquic_edf_update_path(struct tquic_edf_scheduler *sched,
			   struct tquic_path *path)
{
	struct tquic_edf_entry *entry;
	struct rb_node *node;

	if (!sched || !path)
		return;

	spin_lock_bh(&sched->lock);

	for (node = rb_first(&sched->edf_tree); node; node = rb_next(node)) {
		entry = rb_entry(node, struct tquic_edf_entry, node);

		if (entry->selected_path == path) {
			/* Re-select path */
			entry->selected_path = edf_select_path(sched, entry);
		}
	}

	spin_unlock_bh(&sched->lock);
}
EXPORT_SYMBOL_GPL(tquic_edf_update_path);

/*
 * =============================================================================
 * Statistics
 * =============================================================================
 */

/*
 * struct tquic_edf_stats - EDF scheduler statistics
 *
 * Canonical definition is in <net/tquic.h> so that callers outside
 * this file can declare local variables of this type.
 */
#ifndef _TQUIC_EDF_STATS_DEFINED
#define _TQUIC_EDF_STATS_DEFINED
struct tquic_edf_stats {
	u64 entries_scheduled;
	u64 entries_dropped;
	u64 deadlines_met;
	u64 deadlines_missed;
	u64 path_switches;
	u32 current_entries;
};
#endif /* _TQUIC_EDF_STATS_DEFINED */

/**
 * tquic_edf_get_stats - Get EDF scheduler statistics
 * @sched: Scheduler
 * @stats: Output statistics
 */
void tquic_edf_get_stats(struct tquic_edf_scheduler *sched,
			 struct tquic_edf_stats *stats)
{
	if (!sched || !stats)
		return;

	spin_lock_bh(&sched->lock);
	stats->entries_scheduled = sched->stats.entries_scheduled;
	stats->entries_dropped = sched->stats.entries_dropped;
	stats->deadlines_met = sched->stats.deadlines_met;
	stats->deadlines_missed = sched->stats.deadlines_missed;
	stats->path_switches = sched->stats.path_switches;
	stats->current_entries = sched->entry_count;
	spin_unlock_bh(&sched->lock);
}
EXPORT_SYMBOL_GPL(tquic_edf_get_stats);

/*
 * =============================================================================
 * Scheduler Integration (Pluggable Ops)
 * =============================================================================
 */

/**
 * EDF scheduler as a tquic_sched_ops implementation
 *
 * This allows EDF to be registered as a pluggable scheduler
 * through the standard scheduler framework.
 */

struct edf_sched_priv {
	struct tquic_edf_scheduler *sched;
	struct tquic_connection *conn;
};

static struct tquic_path *edf_sched_active_path_get(struct tquic_connection *conn)
{
	struct tquic_path *path;

	rcu_read_lock();
	path = rcu_dereference(conn->active_path);
	if (path && !tquic_path_get(path))
		path = NULL;
	rcu_read_unlock();

	return path;
}

static void *edf_sched_init(struct tquic_connection *conn)
{
	struct tquic_deadline_params params = {
		.enable_deadline_aware = true,
		.deadline_granularity  = TQUIC_DEADLINE_GRANULARITY_MS,
		.max_deadline_streams  = TQUIC_MAX_DEADLINE_STREAMS,
		.miss_policy           = TQUIC_DEADLINE_MISS_BEST_EFFORT,
	};
	struct edf_sched_priv *priv;

	priv = kzalloc(sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return NULL;

	priv->conn = conn;

	priv->sched = tquic_edf_scheduler_create(conn, 1024);
	if (!priv->sched) {
		kfree(priv);
		return NULL;
	}

	/*
	 * Initialise the deadline-aware layer.  Store per-connection state
	 * in conn->sched_priv; tquic_deadline_sched_init() does this.
	 * Errors here are non-fatal — the EDF scheduler continues to work
	 * without full deadline awareness.
	 */
	tquic_deadline_sched_init(conn, &params);

	return priv;
}

static void edf_sched_release(void *state)
{
	struct edf_sched_priv *priv = state;

	if (priv) {
		/*
		 * Release the deadline-aware layer before destroying the EDF
		 * tree so all deadline entries are freed while the cache is
		 * still alive.
		 */
		if (priv->conn)
			tquic_deadline_sched_release(priv->conn);

		tquic_edf_scheduler_destroy(priv->sched);
		kfree(priv);
	}
}

/*
 * edf_sched_feedback - Post-send feedback for deadline-aware scheduling
 *
 * Called after a packet is sent or when an ACK/loss event is processed.
 * Provides stream-level feedback to the deadline layer so it can update
 * delivery statistics and feasibility assessments.
 *
 * On success: notify deadline_aware layer via on_ack, complete load
 * tracking in the multipath deadline coordinator, and record delivery
 * result for per-path miss-rate accounting.
 *
 * On failure: notify deadline_aware layer via on_loss so it can
 * re-evaluate path feasibility.
 */
static void edf_sched_feedback(void *state, struct tquic_path *path,
				struct sk_buff *skb, bool success)
{
	struct edf_sched_priv *priv = state;
	struct tquic_deadline_sched_state *ds;
	struct tquic_stream_skb_cb *scb;
	u64 stream_id;
	u64 offset;

	if (!priv || !priv->conn || !skb)
		return;

	ds = tquic_deadline_get_state(priv->conn);
	if (!ds)
		return;

	scb = tquic_stream_skb_cb(skb);
	stream_id = 0; /* non-stream packet */
	offset = scb ? scb->stream_offset : 0;

	if (success) {
		tquic_deadline_on_ack(ds, stream_id, offset, ktime_get());
#ifdef CONFIG_TQUIC_MULTIPATH
		/*
		 * Complete load tracking so the coordinator can rebalance
		 * after the bytes have been acknowledged on this path.
		 */
		if (path && priv->conn->deadline_coord) {
			tquic_mp_deadline_complete_load(priv->conn->deadline_coord,
							path, (u64)skb->len);
			mp_deadline_record_delivery(priv->conn->deadline_coord,
						    path, true,
						    ktime_us_delta(ktime_get(),
								   skb->tstamp));
		}
#endif /* CONFIG_TQUIC_MULTIPATH */
	} else {
		tquic_deadline_on_loss(ds, stream_id, offset);
#ifdef CONFIG_TQUIC_MULTIPATH
		if (path && priv->conn->deadline_coord) {
			tquic_mp_deadline_complete_load(priv->conn->deadline_coord,
							path, (u64)skb->len);
			mp_deadline_record_delivery(priv->conn->deadline_coord,
						    path, false, 0);
		}
#endif /* CONFIG_TQUIC_MULTIPATH */
	}
}

static struct tquic_path *edf_sched_select(void *state,
					   struct tquic_connection *conn,
					   struct sk_buff *skb)
{
	struct edf_sched_priv *priv = state;
	struct tquic_deadline_sched_state *ds;
	struct tquic_path *path = NULL;

	if (!priv || !skb)
		return edf_sched_active_path_get(conn);

	/*
	 * Step 1: Try the deadline-aware layer.
	 * tquic_deadline_schedule_packet() selects a path that can meet
	 * the earliest pending deadline for this packet's stream.
	 * stream_id=0 means "any stream".
	 */
	ds = tquic_deadline_get_state(conn);
	if (ds) {
		path = tquic_deadline_schedule_packet(ds, skb, 0);
		if (path)
			goto out_assign_load;
	}

#ifdef CONFIG_TQUIC_MULTIPATH
	/*
	 * Step 2: Try cross-path deadline coordination.
	 * mp_deadline_select_best_path() picks the path that can deliver
	 * data within the tightest remaining deadline across all paths,
	 * considering current load and jitter on each path.
	 *
	 * We use TQUIC_DEFAULT_DEADLINE_US as a conservative deadline
	 * budget when no explicit per-stream deadline is set.
	 */
	if (!path && conn->deadline_coord) {
		struct tquic_path *mp_path;

		mp_path = mp_deadline_select_best_path(conn->deadline_coord,
						       TQUIC_DEFAULT_DEADLINE_US,
						       (size_t)skb->len);
		if (mp_path) {
			if (tquic_path_get(mp_path))
				path = mp_path;
		}
		if (path)
			goto out_assign_load;
	}
#endif /* CONFIG_TQUIC_MULTIPATH */

	/*
	 * Step 3: Fall back to ECF-style selection: choose the path with
	 * the shortest estimated delivery time for the packet.
	 */
	if (priv->sched) {
		struct tquic_path *best = NULL;
		u64 min_completion = ULLONG_MAX;

		rcu_read_lock();
		list_for_each_entry_rcu(path, &conn->paths, list) {
			u64 completion;

			if (!edf_path_usable(path))
				continue;

			completion = edf_estimate_path_delivery(path, skb->len);
			if (completion < min_completion) {
				min_completion = completion;
				best = path;
			}
		}
		if (best && !tquic_path_get(best))
			best = NULL;
		rcu_read_unlock();

		path = best ?: edf_sched_active_path_get(conn);
	}

	if (!path)
		path = edf_sched_active_path_get(conn);

out_assign_load:
#ifdef CONFIG_TQUIC_MULTIPATH
	/*
	 * Track outstanding deadline bytes on the selected path so the
	 * coordinator can rebalance when load becomes uneven.
	 */
	if (path && conn->deadline_coord)
		tquic_mp_deadline_assign_load(conn->deadline_coord, path,
					      (u64)skb->len);
#endif /* CONFIG_TQUIC_MULTIPATH */

	return path;
}

static struct tquic_sched_ops tquic_sched_edf = {
	.name     = "edf",
	.init     = edf_sched_init,
	.release  = edf_sched_release,
	.select   = edf_sched_select,
	.feedback = edf_sched_feedback,
};

/*
 * =============================================================================
 * Module Initialization
 * =============================================================================
 */

static int __init tquic_edf_scheduler_init(void)
{
	/* Create memory caches */
	edf_entry_cache = kmem_cache_create("tquic_edf_entry",
					    sizeof(struct tquic_edf_entry), 0,
					    SLAB_HWCACHE_ALIGN, NULL);
	if (!edf_entry_cache)
		return -ENOMEM;

	edf_stream_queue_cache = kmem_cache_create(
		"tquic_edf_stream_queue", sizeof(struct tquic_stream_edf_queue),
		0, SLAB_HWCACHE_ALIGN, NULL);
	if (!edf_stream_queue_cache) {
		kmem_cache_destroy(edf_entry_cache);
		return -ENOMEM;
	}

	/* Register as pluggable scheduler */
	tquic_register_scheduler(&tquic_sched_edf);

	tquic_info("EDF (Earliest Deadline First) scheduler initialized\n");
	return 0;
}

static void __exit tquic_edf_scheduler_exit(void)
{
	tquic_unregister_scheduler(&tquic_sched_edf);

	if (edf_stream_queue_cache)
		kmem_cache_destroy(edf_stream_queue_cache);

	if (edf_entry_cache)
		kmem_cache_destroy(edf_entry_cache);

	tquic_info("EDF scheduler cleaned up\n");
}

MODULE_DESCRIPTION("TQUIC EDF (Earliest Deadline First) Scheduler");
MODULE_LICENSE("GPL");
