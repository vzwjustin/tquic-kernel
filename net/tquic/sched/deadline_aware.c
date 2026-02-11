// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Deadline-Aware Multipath Scheduling - Core Implementation
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Implements deadline-aware packet scheduling for QUIC multipath,
 * based on draft-tjohn-quic-multipath-dmtp-01.
 *
 * Key features:
 *   - Earliest Deadline First (EDF) scheduling within streams
 *   - Path selection based on RTT, bandwidth, and jitter
 *   - Deadline feasibility calculation
 *   - Integration with ECF and BLEST schedulers
 *   - Deadline miss detection and statistics
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/rbtree.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <linux/math64.h>
#include <net/tquic.h>

#include "../tquic_compat.h"

#include "deadline_aware.h"
#include "../core/varint.h"
#include "../tquic_debug.h"

/* Memory caches */
static struct kmem_cache *deadline_cache;
static struct kmem_cache *path_caps_cache;

/* Workqueue for deferred deadline processing */
static struct workqueue_struct *deadline_wq;

/*
 * =============================================================================
 * Variable-length Integer Helpers
 * =============================================================================
 */

static inline size_t deadline_varint_size(u64 val)
{
	if (val <= 63)
		return 1;
	if (val <= 16383)
		return 2;
	if (val <= 1073741823)
		return 4;
	return 8;
}

static int deadline_varint_decode(const u8 *buf, size_t len, u64 *val,
				  size_t *consumed)
{
	size_t varint_len;
	u64 v;

	if (!buf || !val || len < 1)
		return -EINVAL;

	varint_len = 1 << ((buf[0] & 0xc0) >> 6);

	if (len < varint_len)
		return -ENODATA;

	switch (varint_len) {
	case 1:
		v = buf[0] & 0x3f;
		break;
	case 2:
		v = ((u64)(buf[0] & 0x3f) << 8) | buf[1];
		break;
	case 4:
		v = ((u64)(buf[0] & 0x3f) << 24) |
		    ((u64)buf[1] << 16) |
		    ((u64)buf[2] << 8) |
		    buf[3];
		break;
	case 8:
		v = ((u64)(buf[0] & 0x3f) << 56) |
		    ((u64)buf[1] << 48) |
		    ((u64)buf[2] << 40) |
		    ((u64)buf[3] << 32) |
		    ((u64)buf[4] << 24) |
		    ((u64)buf[5] << 16) |
		    ((u64)buf[6] << 8) |
		    buf[7];
		break;
	default:
		return -EINVAL;
	}

	*val = v;
	if (consumed)
		*consumed = varint_len;

	return 0;
}

static int deadline_varint_encode(u64 val, u8 *buf, size_t len)
{
	size_t needed = deadline_varint_size(val);

	if (len < needed)
		return -ENOSPC;

	switch (needed) {
	case 1:
		buf[0] = (u8)val;
		break;
	case 2:
		buf[0] = 0x40 | (u8)(val >> 8);
		buf[1] = (u8)val;
		break;
	case 4:
		buf[0] = 0x80 | (u8)(val >> 24);
		buf[1] = (u8)(val >> 16);
		buf[2] = (u8)(val >> 8);
		buf[3] = (u8)val;
		break;
	case 8:
		buf[0] = 0xc0 | (u8)(val >> 56);
		buf[1] = (u8)(val >> 48);
		buf[2] = (u8)(val >> 40);
		buf[3] = (u8)(val >> 32);
		buf[4] = (u8)(val >> 24);
		buf[5] = (u8)(val >> 16);
		buf[6] = (u8)(val >> 8);
		buf[7] = (u8)val;
		break;
	}

	return (int)needed;
}

/*
 * =============================================================================
 * RB-Tree Helpers for EDF Ordering
 * =============================================================================
 */

static void deadline_rb_insert(struct rb_root *root,
			       struct tquic_stream_deadline *deadline)
{
	struct rb_node **new = &root->rb_node;
	struct rb_node *parent = NULL;

	while (*new) {
		struct tquic_stream_deadline *this;

		this = rb_entry(*new, struct tquic_stream_deadline, node);
		parent = *new;

		/* Earlier deadline goes left */
		if (ktime_before(deadline->deadline, this->deadline))
			new = &((*new)->rb_left);
		else
			new = &((*new)->rb_right);
	}

	rb_link_node(&deadline->node, parent, new);
	rb_insert_color(&deadline->node, root);
}

static struct tquic_stream_deadline *deadline_rb_first(struct rb_root *root)
{
	struct rb_node *node = rb_first(root);

	if (!node)
		return NULL;

	return rb_entry(node, struct tquic_stream_deadline, node);
}

/*
 * =============================================================================
 * Path Capability Management
 * =============================================================================
 */

static struct tquic_path_deadline_caps *
deadline_alloc_path_caps(struct tquic_path *path)
{
	struct tquic_path_deadline_caps *caps;

	caps = kmem_cache_zalloc(path_caps_cache, GFP_KERNEL);
	if (!caps)
		return NULL;

	caps->path = path;
	caps->deadline_support = true;
	INIT_LIST_HEAD(&caps->list);

	return caps;
}

static void deadline_free_path_caps(struct tquic_path_deadline_caps *caps)
{
	if (caps) {
		list_del(&caps->list);
		kmem_cache_free(path_caps_cache, caps);
	}
}

static void deadline_update_path_caps(struct tquic_deadline_sched_state *state,
				      struct tquic_path *path)
{
	struct tquic_path_deadline_caps *caps;

	list_for_each_entry(caps, &state->path_caps, list) {
		if (caps->path == path) {
			/* Update capabilities from path stats */
			caps->avg_rtt_us = path->stats.rtt_smoothed;
			caps->rtt_variance_us = path->stats.rtt_variance;
			caps->estimated_capacity_bps = path->stats.bandwidth * 8;

			/* Calculate minimum feasible deadline */
			/* min_deadline = RTT + (MTU / bandwidth) + 2*jitter */
			if (path->stats.bandwidth > 0) {
				u64 tx_time = div64_u64(path->mtu * 1000000ULL,
							path->stats.bandwidth);
				caps->min_feasible_deadline_us =
					caps->avg_rtt_us + tx_time +
					2 * caps->rtt_variance_us;
			} else {
				caps->min_feasible_deadline_us = UINT_MAX;
			}

			/* Update jitter tracking */
			if (caps->rtt_variance_us > caps->max_jitter_us)
				caps->max_jitter_us = caps->rtt_variance_us;

			return;
		}
	}

	/* Path not found, add it */
	caps = deadline_alloc_path_caps(path);
	if (caps) {
		caps->avg_rtt_us = path->stats.rtt_smoothed;
		caps->rtt_variance_us = path->stats.rtt_variance;
		list_add_tail(&caps->list, &state->path_caps);
	}
}

/*
 * =============================================================================
 * Deadline Feasibility Calculation
 * =============================================================================
 */

/**
 * deadline_estimate_delivery_time - Estimate time to deliver data on path
 * @path: Target path
 * @data_len: Amount of data to send
 *
 * Estimates the time needed to deliver data including:
 *   - RTT (round-trip for acknowledgment)
 *   - Transmission time (data_len / bandwidth)
 *   - Queuing delay (based on cwnd utilization)
 *   - Safety margin (2x RTT variance for jitter)
 *
 * Returns: Estimated delivery time in microseconds
 */
static u64 deadline_estimate_delivery_time(struct tquic_path *path,
					   size_t data_len)
{
	u64 rtt_us;
	u64 tx_time_us;
	u64 queue_delay_us;
	u64 jitter_margin_us;
	u64 in_flight;
	u64 bandwidth;

	rtt_us = path->stats.rtt_smoothed;
	if (rtt_us == 0)
		rtt_us = 100000;  /* 100ms default */

	bandwidth = path->stats.bandwidth;
	if (bandwidth == 0) {
		/* Estimate from cwnd and RTT */
		if (path->stats.cwnd > 0 && rtt_us > 0)
			bandwidth = div64_u64((u64)path->stats.cwnd * 1000000ULL,
					      rtt_us);
		else
			bandwidth = 125000;  /* 1 Mbps default */
	}

	/* Transmission time */
	tx_time_us = div64_u64(data_len * 1000000ULL, bandwidth);

	/* Queue delay based on bytes in flight -- guard underflow */
	if (path->stats.tx_bytes > path->stats.acked_bytes)
		in_flight = path->stats.tx_bytes - path->stats.acked_bytes;
	else
		in_flight = 0;
	if (in_flight > path->stats.cwnd)
		in_flight = path->stats.cwnd;
	queue_delay_us = div64_u64(in_flight * 1000000ULL, bandwidth);

	/* Jitter margin (2x variance) */
	jitter_margin_us = 2 * path->stats.rtt_variance;

	return rtt_us + tx_time_us + queue_delay_us + jitter_margin_us;
}

/**
 * tquic_deadline_check_feasibility - Check if deadline can be met
 */
bool tquic_deadline_check_feasibility(struct tquic_deadline_sched_state *state,
				      u64 deadline_us,
				      size_t data_len,
				      struct tquic_path *path)
{
	struct tquic_path *check_path;
	u64 delivery_time;

	if (!state || !state->enabled)
		return false;

	if (deadline_us < TQUIC_MIN_DEADLINE_US)
		return false;

	if (path) {
		/* Check specific path */
		if (path->state != TQUIC_PATH_ACTIVE)
			return false;

		delivery_time = deadline_estimate_delivery_time(path, data_len);
		return delivery_time <= deadline_us;
	}

	/* Check all paths */
	list_for_each_entry(check_path, &state->conn->paths, list) {
		if (check_path->state != TQUIC_PATH_ACTIVE)
			continue;

		delivery_time = deadline_estimate_delivery_time(check_path,
								data_len);
		if (delivery_time <= deadline_us)
			return true;
	}

	return false;
}
EXPORT_SYMBOL_GPL(tquic_deadline_check_feasibility);

/*
 * =============================================================================
 * Path Selection for Deadline Meeting
 * =============================================================================
 */

/**
 * tquic_deadline_select_path - Select best path to meet deadline
 */
struct tquic_path *tquic_deadline_select_path(
	struct tquic_deadline_sched_state *state,
	struct tquic_stream_deadline *deadline,
	size_t data_len)
{
	struct tquic_path *path, *best_path = NULL;
	ktime_t now = ktime_get();
	s64 time_remaining_us;
	u64 best_score = ULLONG_MAX;
	u64 delivery_time;
	u64 score;

	if (!state || !deadline)
		return NULL;

	/* Calculate remaining time to deadline */
	time_remaining_us = ktime_us_delta(deadline->deadline, now);
	if (time_remaining_us <= 0) {
		/* Deadline already missed, mark it */
		deadline->flags |= TQUIC_DEADLINE_FLAG_MISSED;
		state->stats.deadlines_missed++;

		/* Check miss policy */
		if (deadline->miss_policy == TQUIC_DEADLINE_MISS_DROP) {
			deadline->flags |= TQUIC_DEADLINE_FLAG_DROPPED;
			state->stats.packets_dropped++;
			return NULL;
		}

		/* Best effort - continue with fastest path */
		time_remaining_us = TQUIC_DEFAULT_DEADLINE_US;
	}

	/* Evaluate all active paths */
	list_for_each_entry(path, &state->conn->paths, list) {
		if (path->state != TQUIC_PATH_ACTIVE)
			continue;

		delivery_time = deadline_estimate_delivery_time(path, data_len);

		/*
		 * Scoring function:
		 * - Prefer paths that can meet deadline with margin
		 * - Among feasible paths, prefer lower delivery time
		 * - Penalize paths close to deadline (less slack)
		 */
		if (delivery_time <= (u64)time_remaining_us) {
			/* Path can meet deadline */
			u64 slack = time_remaining_us - delivery_time;

			/*
			 * Score = delivery_time - (slack bonus)
			 * Lower score is better
			 * Bonus for having slack reduces score
			 */
			score = delivery_time;
			if (slack > 0)
				score = delivery_time - min(slack / 4, delivery_time / 2);
		} else {
			/* Path cannot meet deadline, large penalty */
			score = delivery_time + 1000000;  /* 1 second penalty */
		}

		/* Apply priority weighting */
		score = score >> (3 - min_t(u8, deadline->priority, 3));

		if (score < best_score) {
			best_score = score;
			best_path = path;
		}
	}

	if (best_path)
		state->stats.packets_scheduled++;

	return best_path;
}
EXPORT_SYMBOL_GPL(tquic_deadline_select_path);

/*
 * =============================================================================
 * Core Scheduler Operations
 * =============================================================================
 */

/**
 * deadline_sched_timer_cb - Periodic deadline maintenance timer callback
 * @t: Timer list structure
 *
 * Performs periodic maintenance for the deadline scheduler:
 * - Detects expired deadlines and marks them as MISSED
 * - Updates path capability metrics for better scheduling decisions
 * - Re-evaluates deadline feasibility based on current network conditions
 * - Cleans up completed deadline entries
 *
 * This proactive approach complements the reactive event handlers
 * (on_ack, on_loss, on_path_change) by catching deadlines that expire
 * without explicit network events.
 */
static void deadline_sched_timer_cb(struct timer_list *t)
{
	struct tquic_deadline_sched_state *state;
	struct tquic_stream_deadline *deadline, *tmp;
	struct tquic_path *path;
	ktime_t now;
	unsigned long flags;
	bool has_active = false;

	state = from_timer(state, t, scheduler_timer);

	/* Bail out if scheduler is not enabled */
	if (!state->enabled)
		return;

	now = ktime_get();

	spin_lock_irqsave(&state->lock, flags);

	/* Scan deadline tree for expired deadlines */
	list_for_each_entry_safe(deadline, tmp, &state->streams_with_deadlines,
				 list) {
		/* Skip if already delivered or dropped */
		if (deadline->flags & (TQUIC_DEADLINE_FLAG_DELIVERED |
				       TQUIC_DEADLINE_FLAG_DROPPED))
			continue;

		/* Check if deadline has expired */
		if (ktime_before(deadline->deadline, now)) {
			/* Mark as missed if still pending */
			if (deadline->flags & TQUIC_DEADLINE_FLAG_PENDING) {
				deadline->flags |= TQUIC_DEADLINE_FLAG_MISSED;
				state->stats.deadlines_missed++;

				/* Apply miss policy */
				if (state->miss_policy == TQUIC_DEADLINE_MISS_DROP) {
					deadline->flags |= TQUIC_DEADLINE_FLAG_DROPPED;
					state->stats.packets_dropped++;
				}
			}
		} else {
			/* Still has active deadline */
			has_active = true;
		}
	}

	/* Update path capabilities from current network statistics */
	if (state->conn) {
		list_for_each_entry(path, &state->conn->paths, list) {
			deadline_update_path_caps(state, path);
		}
	}

	spin_unlock_irqrestore(&state->lock, flags);

	/*
	 * Reschedule timer if there are active deadlines.
	 * Use the configured granularity for check interval.
	 */
	if (has_active && state->conn) {
		mod_timer(&state->scheduler_timer,
			  jiffies + usecs_to_jiffies(state->granularity_us));
	}
}

/**
 * tquic_deadline_sched_init - Initialize deadline scheduler
 */
int tquic_deadline_sched_init(struct tquic_connection *conn,
			      const struct tquic_deadline_params *params)
{
	struct tquic_deadline_sched_state *state;
	struct tquic_path *path;

	if (!conn)
		return -EINVAL;

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return -ENOMEM;

	state->conn = conn;
	state->enabled = params ? params->enable_deadline_aware : false;
	state->granularity_us = params ? params->deadline_granularity :
					 TQUIC_DEADLINE_GRANULARITY_MS;
	state->miss_policy = params ? params->miss_policy :
				      TQUIC_DEADLINE_MISS_BEST_EFFORT;
	state->max_deadline_streams = params ? params->max_deadline_streams :
					       TQUIC_MAX_DEADLINE_STREAMS;

	state->deadline_tree = RB_ROOT;
	INIT_LIST_HEAD(&state->streams_with_deadlines);
	INIT_LIST_HEAD(&state->path_caps);
	spin_lock_init(&state->lock);

	/* Initialize timer for periodic deadline checks */
	timer_setup(&state->scheduler_timer, deadline_sched_timer_cb, 0);

	/* Initialize path capabilities */
	list_for_each_entry(path, &conn->paths, list) {
		deadline_update_path_caps(state, path);
	}

	/* Set up integration with base schedulers */
	state->integration.base_sched = NULL;
	state->integration.base_state = NULL;
	state->integration.ecf_fallback = true;
	state->integration.blest_aware = true;

	/*
	 * Store state in connection's scheduler field.
	 * This uses the generic scheduler pointer since the deadline
	 * scheduler is the primary scheduler for deadline-aware connections.
	 */
	conn->scheduler = state;

	tquic_info("Deadline scheduler initialized for connection "
		   "(granularity=%u us, max_streams=%u)\n",
		   state->granularity_us, state->max_deadline_streams);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_deadline_sched_init);

/**
 * tquic_deadline_sched_release - Release deadline scheduler
 */
void tquic_deadline_sched_release(struct tquic_connection *conn)
{
	struct tquic_deadline_sched_state *state;
	struct tquic_stream_deadline *deadline, *tmp_deadline;
	struct tquic_path_deadline_caps *caps, *tmp_caps;
	struct rb_node *node;

	state = tquic_deadline_get_state(conn);
	if (!state)
		return;

	/* Cancel timer */
	del_timer_sync(&state->scheduler_timer);

	/* Free all deadlines */
	spin_lock_bh(&state->lock);

	while ((node = rb_first(&state->deadline_tree))) {
		deadline = rb_entry(node, struct tquic_stream_deadline, node);
		rb_erase(node, &state->deadline_tree);
		kmem_cache_free(deadline_cache, deadline);
	}

	/* Free stream deadline lists */
	list_for_each_entry_safe(deadline, tmp_deadline,
				 &state->streams_with_deadlines, stream_node) {
		list_del(&deadline->stream_node);
	}

	/* Free path capabilities */
	list_for_each_entry_safe(caps, tmp_caps, &state->path_caps, list) {
		deadline_free_path_caps(caps);
	}

	spin_unlock_bh(&state->lock);

	/* Log final statistics */
	tquic_info("Deadline scheduler stats - total=%llu met=%llu missed=%llu\n",
		   state->stats.total_deadlines,
		   state->stats.deadlines_met,
		   state->stats.deadlines_missed);

	kfree(state);
}
EXPORT_SYMBOL_GPL(tquic_deadline_sched_release);

/**
 * tquic_deadline_set_stream_deadline - Set deadline for stream data
 */
int tquic_deadline_set_stream_deadline(struct tquic_connection *conn,
				       u64 stream_id,
				       u64 deadline_us,
				       u64 offset,
				       u64 length,
				       u8 priority,
				       u32 flags)
{
	struct tquic_deadline_sched_state *state;
	struct tquic_stream_deadline *deadline;
	ktime_t now;

	state = tquic_deadline_get_state(conn);
	if (!state || !state->enabled)
		return -EOPNOTSUPP;

	/* Validate deadline */
	if (deadline_us < TQUIC_MIN_DEADLINE_US ||
	    deadline_us > TQUIC_MAX_DEADLINE_US)
		return -EINVAL;

	/* Check capacity */
	if (state->deadline_count >= state->max_deadline_streams)
		return -ENOSPC;

	/* Check feasibility */
	if (!tquic_deadline_check_feasibility(state, deadline_us, length, NULL)) {
		state->stats.infeasible_count++;
		if (state->miss_policy == TQUIC_DEADLINE_MISS_DROP)
			return -ETIMEDOUT;
		/* Continue anyway for best effort */
	}

	/* Allocate deadline entry */
	deadline = kmem_cache_zalloc(deadline_cache, GFP_ATOMIC);
	if (!deadline)
		return -ENOMEM;

	now = ktime_get();

	deadline->stream_id = stream_id;
	deadline->relative_deadline_us = deadline_us;
	deadline->creation_time = now;
	deadline->deadline = ktime_add_us(now, deadline_us);
	deadline->priority = priority;
	deadline->miss_policy = state->miss_policy;
	deadline->data_offset = offset;
	deadline->data_length = length;
	deadline->flags = TQUIC_DEADLINE_FLAG_ACTIVE | TQUIC_DEADLINE_FLAG_PENDING;
	deadline->feasible = true;

	/* Insert into EDF tree */
	spin_lock_bh(&state->lock);
	deadline_rb_insert(&state->deadline_tree, deadline);
	list_add_tail(&deadline->stream_node, &state->streams_with_deadlines);
	state->deadline_count++;
	state->stats.total_deadlines++;

	/* Start periodic timer if this is the first active deadline */
	if (state->deadline_count == 1) {
		mod_timer(&state->scheduler_timer,
			  jiffies + usecs_to_jiffies(state->granularity_us));
	}

	spin_unlock_bh(&state->lock);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_deadline_set_stream_deadline);

/**
 * tquic_deadline_cancel_stream_deadline - Cancel deadline
 */
int tquic_deadline_cancel_stream_deadline(struct tquic_connection *conn,
					  u64 stream_id,
					  u64 offset)
{
	struct tquic_deadline_sched_state *state;
	struct tquic_stream_deadline *deadline, *tmp;
	int cancelled = 0;

	state = tquic_deadline_get_state(conn);
	if (!state)
		return 0;

	spin_lock_bh(&state->lock);

	list_for_each_entry_safe(deadline, tmp,
				 &state->streams_with_deadlines, stream_node) {
		if (deadline->stream_id != stream_id)
			continue;

		if (offset != 0 && deadline->data_offset != offset)
			continue;

		rb_erase(&deadline->node, &state->deadline_tree);
		list_del(&deadline->stream_node);
		state->deadline_count--;
		kmem_cache_free(deadline_cache, deadline);
		cancelled++;
	}

	spin_unlock_bh(&state->lock);

	return cancelled;
}
EXPORT_SYMBOL_GPL(tquic_deadline_cancel_stream_deadline);

/**
 * tquic_deadline_schedule_packet - Schedule packet with deadline awareness
 */
struct tquic_path *tquic_deadline_schedule_packet(
	struct tquic_deadline_sched_state *state,
	struct sk_buff *skb,
	u64 stream_id)
{
	struct tquic_stream_deadline *deadline;
	struct tquic_path *selected_path = NULL;
	size_t data_len;

	if (!state || !state->enabled || !skb)
		return NULL;

	data_len = skb->len;

	spin_lock_bh(&state->lock);

	/* Find earliest deadline for this stream */
	deadline = deadline_rb_first(&state->deadline_tree);

	while (deadline) {
		if (stream_id == 0 || deadline->stream_id == stream_id) {
			/* Found relevant deadline */
			selected_path = tquic_deadline_select_path(state,
								   deadline,
								   data_len);
			if (selected_path) {
				/* Update deadline state */
				deadline->flags &= ~TQUIC_DEADLINE_FLAG_PENDING;
			}
			break;
		}

		/* Check next deadline */
		deadline = rb_entry_safe(rb_next(&deadline->node),
					 struct tquic_stream_deadline, node);
	}

	state->stats.last_schedule_time = ktime_get();

	spin_unlock_bh(&state->lock);

	/* Fall back to ECF scheduler if no deadline path selected */
	if (!selected_path && state->integration.ecf_fallback) {
		/* Use ECF fallback - would integrate with actual ECF here */
		if (state->conn->active_path)
			selected_path = state->conn->active_path;
	}

	return selected_path;
}
EXPORT_SYMBOL_GPL(tquic_deadline_schedule_packet);

/*
 * =============================================================================
 * Event Handlers
 * =============================================================================
 */

/**
 * tquic_deadline_on_ack - Handle ACK event
 */
void tquic_deadline_on_ack(struct tquic_deadline_sched_state *state,
			   u64 stream_id, u64 offset, ktime_t ack_time)
{
	struct tquic_stream_deadline *deadline, *tmp;
	s64 delivery_time_us;

	if (!state)
		return;

	spin_lock_bh(&state->lock);

	list_for_each_entry_safe(deadline, tmp,
				 &state->streams_with_deadlines, stream_node) {
		if (deadline->stream_id != stream_id)
			continue;

		/* Check if this ACK covers the deadline's data */
		if (offset < deadline->data_offset + deadline->data_length &&
		    offset + 1 > deadline->data_offset) {
			/* Calculate delivery time */
			delivery_time_us = ktime_us_delta(ack_time,
							  deadline->creation_time);

			/* Check if deadline was met */
			if (ktime_before(ack_time, deadline->deadline)) {
				deadline->flags |= TQUIC_DEADLINE_FLAG_DELIVERED;
				state->stats.deadlines_met++;
				deadline->hit_count++;
			} else {
				deadline->flags |= TQUIC_DEADLINE_FLAG_MISSED;
				state->stats.deadlines_missed++;
				deadline->miss_count++;
			}

			/* Update average latency */
			if (deadline->avg_latency_us == 0)
				deadline->avg_latency_us = delivery_time_us;
			else
				deadline->avg_latency_us =
					(deadline->avg_latency_us * 7 +
					 delivery_time_us) / 8;

			/* Remove completed deadline */
			rb_erase(&deadline->node, &state->deadline_tree);
			list_del(&deadline->stream_node);
			state->deadline_count--;
			kmem_cache_free(deadline_cache, deadline);
		}
	}

	spin_unlock_bh(&state->lock);
}
EXPORT_SYMBOL_GPL(tquic_deadline_on_ack);

/**
 * tquic_deadline_on_loss - Handle loss event
 */
void tquic_deadline_on_loss(struct tquic_deadline_sched_state *state,
			    u64 stream_id, u64 offset)
{
	struct tquic_stream_deadline *deadline;

	if (!state)
		return;

	spin_lock_bh(&state->lock);

	list_for_each_entry(deadline, &state->streams_with_deadlines,
			    stream_node) {
		if (deadline->stream_id != stream_id)
			continue;

		if (offset >= deadline->data_offset &&
		    offset < deadline->data_offset + deadline->data_length) {
			s64 remaining;

			/* Mark for retransmission */
			deadline->flags |= TQUIC_DEADLINE_FLAG_RETRANSMIT;
			deadline->flags |= TQUIC_DEADLINE_FLAG_PENDING;

			/* Recheck feasibility with remaining time */
			remaining = ktime_us_delta(deadline->deadline,
						   ktime_get());
			if (remaining > 0) {
				deadline->feasible =
					tquic_deadline_check_feasibility(
						state, remaining,
						deadline->data_length, NULL);
			} else {
				deadline->feasible = false;
			}
		}
	}

	spin_unlock_bh(&state->lock);
}
EXPORT_SYMBOL_GPL(tquic_deadline_on_loss);

/**
 * tquic_deadline_on_path_change - Handle path state change
 */
void tquic_deadline_on_path_change(struct tquic_deadline_sched_state *state,
				   struct tquic_path *path,
				   enum tquic_path_state new_state)
{
	struct tquic_stream_deadline *deadline;

	if (!state || !path)
		return;

	/* Update path capabilities */
	deadline_update_path_caps(state, path);

	if (new_state == TQUIC_PATH_FAILED ||
	    new_state == TQUIC_PATH_UNAVAILABLE) {
		/* Path went down - recheck all deadline feasibilities */
		spin_lock_bh(&state->lock);

		list_for_each_entry(deadline, &state->streams_with_deadlines,
				    stream_node) {
			if (deadline->flags & TQUIC_DEADLINE_FLAG_PENDING) {
				s64 remaining;

				remaining = ktime_us_delta(deadline->deadline,
							   ktime_get());
				if (remaining > 0) {
					deadline->feasible =
						tquic_deadline_check_feasibility(
							state, remaining,
							deadline->data_length,
							NULL);
				}
			}
		}

		state->stats.path_switches++;
		spin_unlock_bh(&state->lock);
	}
}
EXPORT_SYMBOL_GPL(tquic_deadline_on_path_change);

/*
 * =============================================================================
 * Statistics
 * =============================================================================
 */

int tquic_deadline_get_stats(struct tquic_deadline_sched_state *state,
			     struct tquic_deadline_stats *stats)
{
	if (!state || !stats)
		return -EINVAL;

	spin_lock_bh(&state->lock);

	stats->total_deadlines = state->stats.total_deadlines;
	stats->deadlines_met = state->stats.deadlines_met;
	stats->deadlines_missed = state->stats.deadlines_missed;
	stats->packets_scheduled = state->stats.packets_scheduled;
	stats->packets_dropped = state->stats.packets_dropped;
	stats->path_switches = state->stats.path_switches;
	stats->infeasible_count = state->stats.infeasible_count;

	/* Calculate averages from active deadlines */
	stats->avg_delivery_time_us = 0;
	stats->avg_slack_us = 0;

	spin_unlock_bh(&state->lock);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_deadline_get_stats);

/*
 * =============================================================================
 * Frame Parsing and Generation
 * =============================================================================
 */

/**
 * tquic_deadline_parse_frame - Parse STREAM_DEADLINE frame
 */
int tquic_deadline_parse_frame(const u8 *buf, size_t len,
			       struct tquic_deadline_frame *frame)
{
	size_t offset = 0;
	size_t consumed;
	u64 frame_type;
	int ret;

	if (!buf || !frame || len < 1)
		return -EINVAL;

	memset(frame, 0, sizeof(*frame));

	/* Frame Type */
	ret = deadline_varint_decode(buf, len, &frame_type, &consumed);
	if (ret < 0)
		return ret;
	if (frame_type != TQUIC_FRAME_STREAM_DEADLINE)
		return -EINVAL;
	offset = consumed;

	/* Stream ID */
	ret = deadline_varint_decode(buf + offset, len - offset,
				     &frame->stream_id, &consumed);
	if (ret < 0)
		return ret;
	offset += consumed;

	/* Deadline */
	ret = deadline_varint_decode(buf + offset, len - offset,
				     &frame->deadline_us, &consumed);
	if (ret < 0)
		return ret;
	offset += consumed;

	/* Priority (1 byte) */
	if (len - offset < 1)
		return -ENODATA;
	frame->priority = buf[offset++];

	/* Offset */
	ret = deadline_varint_decode(buf + offset, len - offset,
				     &frame->offset, &consumed);
	if (ret < 0)
		return ret;
	offset += consumed;

	/* Length */
	ret = deadline_varint_decode(buf + offset, len - offset,
				     &frame->length, &consumed);
	if (ret < 0)
		return ret;
	offset += consumed;

	/* Flags (1 byte) */
	if (len - offset < 1)
		return -ENODATA;
	frame->flags = buf[offset++];

	return (int)offset;
}
EXPORT_SYMBOL_GPL(tquic_deadline_parse_frame);

/**
 * tquic_deadline_write_frame - Write STREAM_DEADLINE frame
 */
int tquic_deadline_write_frame(const struct tquic_deadline_frame *frame,
			       u8 *buf, size_t len)
{
	size_t offset = 0;
	int ret;

	if (!frame || !buf)
		return -EINVAL;

	/* Frame Type */
	ret = deadline_varint_encode(TQUIC_FRAME_STREAM_DEADLINE,
				     buf + offset, len - offset);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Stream ID */
	ret = deadline_varint_encode(frame->stream_id, buf + offset,
				     len - offset);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Deadline */
	ret = deadline_varint_encode(frame->deadline_us, buf + offset,
				     len - offset);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Priority (1 byte) */
	if (len - offset < 1)
		return -ENOSPC;
	buf[offset++] = frame->priority;

	/* Offset */
	ret = deadline_varint_encode(frame->offset, buf + offset,
				     len - offset);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Length */
	ret = deadline_varint_encode(frame->length, buf + offset,
				     len - offset);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Flags (1 byte) */
	if (len - offset < 1)
		return -ENOSPC;
	buf[offset++] = frame->flags;

	return (int)offset;
}
EXPORT_SYMBOL_GPL(tquic_deadline_write_frame);

/**
 * tquic_deadline_frame_size - Calculate frame size
 */
size_t tquic_deadline_frame_size(const struct tquic_deadline_frame *frame)
{
	size_t size = 0;

	if (!frame)
		return 0;

	size += deadline_varint_size(TQUIC_FRAME_STREAM_DEADLINE);
	size += deadline_varint_size(frame->stream_id);
	size += deadline_varint_size(frame->deadline_us);
	size += 1;  /* priority */
	size += deadline_varint_size(frame->offset);
	size += deadline_varint_size(frame->length);
	size += 1;  /* flags */

	return size;
}
EXPORT_SYMBOL_GPL(tquic_deadline_frame_size);

/**
 * tquic_deadline_parse_ack_frame - Parse DEADLINE_ACK frame
 */
int tquic_deadline_parse_ack_frame(const u8 *buf, size_t len,
				   struct tquic_deadline_ack_frame *frame)
{
	size_t offset = 0;
	size_t consumed;
	u64 frame_type;
	int ret;

	if (!buf || !frame || len < 1)
		return -EINVAL;

	memset(frame, 0, sizeof(*frame));

	/* Frame Type */
	ret = deadline_varint_decode(buf, len, &frame_type, &consumed);
	if (ret < 0)
		return ret;
	if (frame_type != TQUIC_FRAME_DEADLINE_ACK)
		return -EINVAL;
	offset = consumed;

	/* Stream ID */
	ret = deadline_varint_decode(buf + offset, len - offset,
				     &frame->stream_id, &consumed);
	if (ret < 0)
		return ret;
	offset += consumed;

	/* Offset */
	ret = deadline_varint_decode(buf + offset, len - offset,
				     &frame->offset, &consumed);
	if (ret < 0)
		return ret;
	offset += consumed;

	/* Delivery Time */
	ret = deadline_varint_decode(buf + offset, len - offset,
				     &frame->delivery_time_us, &consumed);
	if (ret < 0)
		return ret;
	offset += consumed;

	return (int)offset;
}
EXPORT_SYMBOL_GPL(tquic_deadline_parse_ack_frame);

/**
 * tquic_deadline_write_ack_frame - Write DEADLINE_ACK frame
 */
int tquic_deadline_write_ack_frame(const struct tquic_deadline_ack_frame *frame,
				   u8 *buf, size_t len)
{
	size_t offset = 0;
	int ret;

	if (!frame || !buf)
		return -EINVAL;

	ret = deadline_varint_encode(TQUIC_FRAME_DEADLINE_ACK,
				     buf + offset, len - offset);
	if (ret < 0)
		return ret;
	offset += ret;

	ret = deadline_varint_encode(frame->stream_id, buf + offset,
				     len - offset);
	if (ret < 0)
		return ret;
	offset += ret;

	ret = deadline_varint_encode(frame->offset, buf + offset,
				     len - offset);
	if (ret < 0)
		return ret;
	offset += ret;

	ret = deadline_varint_encode(frame->delivery_time_us, buf + offset,
				     len - offset);
	if (ret < 0)
		return ret;
	offset += ret;

	return (int)offset;
}
EXPORT_SYMBOL_GPL(tquic_deadline_write_ack_frame);

/**
 * tquic_deadline_parse_miss_frame - Parse DEADLINE_MISS frame
 */
int tquic_deadline_parse_miss_frame(const u8 *buf, size_t len,
				    struct tquic_deadline_miss_frame *frame)
{
	size_t offset = 0;
	size_t consumed;
	u64 frame_type;
	int ret;

	if (!buf || !frame || len < 1)
		return -EINVAL;

	memset(frame, 0, sizeof(*frame));

	/* Frame Type */
	ret = deadline_varint_decode(buf, len, &frame_type, &consumed);
	if (ret < 0)
		return ret;
	if (frame_type != TQUIC_FRAME_DEADLINE_MISS)
		return -EINVAL;
	offset = consumed;

	/* Stream ID */
	ret = deadline_varint_decode(buf + offset, len - offset,
				     &frame->stream_id, &consumed);
	if (ret < 0)
		return ret;
	offset += consumed;

	/* Offset */
	ret = deadline_varint_decode(buf + offset, len - offset,
				     &frame->offset, &consumed);
	if (ret < 0)
		return ret;
	offset += consumed;

	/* Miss Amount */
	ret = deadline_varint_decode(buf + offset, len - offset,
				     &frame->miss_amount_us, &consumed);
	if (ret < 0)
		return ret;
	offset += consumed;

	/* Reason (1 byte) */
	if (len - offset < 1)
		return -ENODATA;
	frame->reason = buf[offset++];

	return (int)offset;
}
EXPORT_SYMBOL_GPL(tquic_deadline_parse_miss_frame);

/**
 * tquic_deadline_write_miss_frame - Write DEADLINE_MISS frame
 */
int tquic_deadline_write_miss_frame(const struct tquic_deadline_miss_frame *frame,
				    u8 *buf, size_t len)
{
	size_t offset = 0;
	int ret;

	if (!frame || !buf)
		return -EINVAL;

	ret = deadline_varint_encode(TQUIC_FRAME_DEADLINE_MISS,
				     buf + offset, len - offset);
	if (ret < 0)
		return ret;
	offset += ret;

	ret = deadline_varint_encode(frame->stream_id, buf + offset,
				     len - offset);
	if (ret < 0)
		return ret;
	offset += ret;

	ret = deadline_varint_encode(frame->offset, buf + offset,
				     len - offset);
	if (ret < 0)
		return ret;
	offset += ret;

	ret = deadline_varint_encode(frame->miss_amount_us, buf + offset,
				     len - offset);
	if (ret < 0)
		return ret;
	offset += ret;

	if (len - offset < 1)
		return -ENOSPC;
	buf[offset++] = frame->reason;

	return (int)offset;
}
EXPORT_SYMBOL_GPL(tquic_deadline_write_miss_frame);

/*
 * =============================================================================
 * Helper Functions
 * =============================================================================
 */

/**
 * tquic_deadline_get_state - Get scheduler state from connection
 * @conn: QUIC connection
 *
 * Retrieves the deadline scheduler state from the connection's
 * scheduler field. Returns NULL if the connection doesn't have
 * deadline scheduling enabled.
 */
struct tquic_deadline_sched_state *tquic_deadline_get_state(
	struct tquic_connection *conn)
{
	struct tquic_deadline_sched_state *state;

	if (!conn || !conn->scheduler)
		return NULL;

	/*
	 * Retrieve state from connection's scheduler field.
	 * The state is stored there by tquic_deadline_sched_init().
	 */
	state = (struct tquic_deadline_sched_state *)conn->scheduler;

	/* Verify this is actually a deadline scheduler state by checking conn backref */
	if (state->conn != conn)
		return NULL;

	return state;
}
EXPORT_SYMBOL_GPL(tquic_deadline_get_state);

/*
 * =============================================================================
 * Module Initialization
 * =============================================================================
 */

int __init tquic_deadline_sched_module_init(void)
{
	/* Create memory caches */
	deadline_cache = kmem_cache_create("tquic_deadline",
					   sizeof(struct tquic_stream_deadline),
					   0, SLAB_HWCACHE_ALIGN, NULL);
	if (!deadline_cache)
		return -ENOMEM;

	path_caps_cache = kmem_cache_create("tquic_deadline_path_caps",
					    sizeof(struct tquic_path_deadline_caps),
					    0, SLAB_HWCACHE_ALIGN, NULL);
	if (!path_caps_cache) {
		kmem_cache_destroy(deadline_cache);
		return -ENOMEM;
	}

	/* Create workqueue */
	deadline_wq = alloc_workqueue("tquic_deadline", WQ_UNBOUND, 0);
	if (!deadline_wq) {
		kmem_cache_destroy(path_caps_cache);
		kmem_cache_destroy(deadline_cache);
		return -ENOMEM;
	}

	tquic_info("Deadline-aware multipath scheduler initialized "
		   "(draft-tjohn-quic-multipath-dmtp-01)\n");

	return 0;
}

void __exit tquic_deadline_sched_module_exit(void)
{
	if (deadline_wq)
		destroy_workqueue(deadline_wq);

	if (path_caps_cache)
		kmem_cache_destroy(path_caps_cache);

	if (deadline_cache)
		kmem_cache_destroy(deadline_cache);

	tquic_info("Deadline-aware scheduler cleaned up\n");
}

MODULE_DESCRIPTION("TQUIC Deadline-Aware Multipath Scheduler");
MODULE_LICENSE("GPL");
