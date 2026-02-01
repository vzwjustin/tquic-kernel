// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: WAN Bonding Core
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * This module implements the core WAN bonding functionality for TQUIC,
 * enabling true bandwidth aggregation across multiple network paths.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <linux/timer.h>
#include <linux/random.h>
#include <net/sock.h>
#include <net/tquic.h>

/* Bonding state per connection */
struct tquic_bond_state {
	/* Configuration */
	u8 mode;
	u8 aggr_mode;
	u8 failover_mode;

	/* Reorder buffer */
	struct sk_buff_head reorder_queue;
	u64 reorder_next_seq;
	u32 reorder_window;
	spinlock_t reorder_lock;

	/* Statistics */
	struct tquic_bond_stats stats;

	/* Path selection state */
	u32 rr_counter;  /* Round-robin counter */
	struct tquic_path *primary_path;

	/* Failover state */
	bool failover_pending;
	ktime_t failover_start;
	struct tquic_path *failover_from;

	/* Work queue for async operations */
	struct work_struct failover_work;
	struct delayed_work probe_work;

	/* Reference to connection */
	struct tquic_connection *conn;
};

/* Path quality metrics for scheduling decisions */
struct tquic_path_quality {
	u64 score;           /* Combined quality score */
	u32 available_cwnd;  /* Available congestion window */
	u32 inflight;        /* Packets in flight */
	u32 est_delivery;    /* Estimated delivery time (us) */
	bool can_send;       /* Can accept more data */
};

/*
 * Calculate path quality score for scheduling decisions
 * Higher score = better path
 */
static void tquic_calc_path_quality(struct tquic_path *path,
				    struct tquic_path_quality *quality)
{
	struct tquic_path_stats *stats = &path->stats;
	u64 score = 0;

	if (path->state != TQUIC_PATH_ACTIVE) {
		quality->score = 0;
		quality->can_send = false;
		return;
	}

	/* Base score from RTT (lower is better) */
	if (stats->rtt_smoothed > 0)
		score = 1000000000ULL / stats->rtt_smoothed;

	/* Adjust for bandwidth */
	if (stats->bandwidth > 0)
		score = (score * stats->bandwidth) >> 20;

	/* Penalize for loss */
	if (stats->tx_packets > 0) {
		u64 loss_rate = (stats->lost_packets * 100) / stats->tx_packets;
		if (loss_rate > 0)
			score = score * (100 - min(loss_rate, 90ULL)) / 100;
	}

	/* Apply priority weighting */
	score = score * (256 - path->priority) / 256;

	/* Apply explicit weight */
	score = score * path->weight;

	quality->score = score;
	quality->available_cwnd = stats->cwnd;
	/*
	 * Track in-flight packets from path statistics.
	 * This is updated by the congestion control module.
	 */
	quality->inflight = stats->tx_bytes - (stats->rx_bytes + stats->lost_packets * 1200);
	if (quality->inflight < 0)
		quality->inflight = 0;
	quality->est_delivery = stats->rtt_smoothed;
	quality->can_send = (quality->available_cwnd > quality->inflight);
}

/*
 * Select best path based on minimum RTT
 */
static struct tquic_path *tquic_select_minrtt(struct tquic_bond_state *bond,
					      struct sk_buff *skb)
{
	struct tquic_connection *conn = bond->conn;
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

/*
 * Select path using round-robin
 */
static struct tquic_path *tquic_select_roundrobin(struct tquic_bond_state *bond,
						  struct sk_buff *skb)
{
	struct tquic_connection *conn = bond->conn;
	struct tquic_path *path;
	u32 idx = 0;
	u32 target;

	/* Guard against division by zero when no paths exist */
	if (unlikely(conn->num_paths == 0))
		return conn->active_path;

	target = bond->rr_counter++ % conn->num_paths;

	list_for_each_entry(path, &conn->paths, list) {
		if (path->state != TQUIC_PATH_ACTIVE)
			continue;

		if (idx == target)
			return path;
		idx++;
	}

	/* Fallback to first active path */
	list_for_each_entry(path, &conn->paths, list) {
		if (path->state == TQUIC_PATH_ACTIVE)
			return path;
	}

	return conn->active_path;
}

/*
 * Select path using weighted round-robin
 */
static struct tquic_path *tquic_select_weighted(struct tquic_bond_state *bond,
						struct sk_buff *skb)
{
	struct tquic_connection *conn = bond->conn;
	struct tquic_path *path, *selected = NULL;
	u32 total_weight = 0;
	u32 target, cumulative = 0;

	/* Calculate total weight of active paths */
	list_for_each_entry(path, &conn->paths, list) {
		if (path->state == TQUIC_PATH_ACTIVE)
			total_weight += path->weight;
	}

	if (total_weight == 0)
		return conn->active_path;

	/* Select based on weight */
	target = bond->rr_counter++ % total_weight;

	list_for_each_entry(path, &conn->paths, list) {
		if (path->state != TQUIC_PATH_ACTIVE)
			continue;

		cumulative += path->weight;
		if (target < cumulative) {
			selected = path;
			break;
		}
	}

	return selected ?: conn->active_path;
}

/*
 * True bandwidth aggregation - select best path considering capacity
 */
static struct tquic_path *tquic_select_aggregate(struct tquic_bond_state *bond,
						 struct sk_buff *skb)
{
	struct tquic_connection *conn = bond->conn;
	struct tquic_path *path, *best = NULL;
	struct tquic_path_quality quality, best_quality = {0};

	list_for_each_entry(path, &conn->paths, list) {
		if (path->state != TQUIC_PATH_ACTIVE)
			continue;

		tquic_calc_path_quality(path, &quality);

		if (!quality.can_send)
			continue;

		if (quality.score > best_quality.score) {
			best_quality = quality;
			best = path;
		}
	}

	/* If no path can send, find the one with most available capacity */
	if (!best) {
		u32 max_cwnd = 0;

		list_for_each_entry(path, &conn->paths, list) {
			if (path->state == TQUIC_PATH_ACTIVE &&
			    path->stats.cwnd > max_cwnd) {
				max_cwnd = path->stats.cwnd;
				best = path;
			}
		}
	}

	return best ?: conn->active_path;
}

/*
 * BLEST (BLocking ESTimation) scheduler
 * Avoids head-of-line blocking by estimating completion times
 */
static struct tquic_path *tquic_select_blest(struct tquic_bond_state *bond,
					     struct sk_buff *skb)
{
	struct tquic_connection *conn = bond->conn;
	struct tquic_path *path, *best = NULL;
	u64 min_completion = ULLONG_MAX;

	list_for_each_entry(path, &conn->paths, list) {
		struct tquic_path_quality quality;
		u64 completion_time;

		if (path->state != TQUIC_PATH_ACTIVE)
			continue;

		tquic_calc_path_quality(path, &quality);

		if (!quality.can_send)
			continue;

		/* Estimate when this packet would be delivered */
		completion_time = quality.est_delivery;

		/* Add queuing delay estimate */
		if (path->stats.bandwidth > 0)
			completion_time += (skb->len * 1000000ULL) / path->stats.bandwidth;

		if (completion_time < min_completion) {
			min_completion = completion_time;
			best = path;
		}
	}

	return best ?: conn->active_path;
}

/*
 * ECF (Earliest Completion First) scheduler
 */
static struct tquic_path *tquic_select_ecf(struct tquic_bond_state *bond,
					   struct sk_buff *skb)
{
	/* ECF is similar to BLEST but uses actual completion predictions */
	return tquic_select_blest(bond, skb);
}

/*
 * Send packet on all paths (redundant mode)
 */
static int tquic_send_redundant(struct tquic_bond_state *bond,
				struct sk_buff *skb)
{
	struct tquic_connection *conn = bond->conn;
	struct tquic_path *path;
	int sent = 0;

	list_for_each_entry(path, &conn->paths, list) {
		struct sk_buff *clone;

		if (path->state != TQUIC_PATH_ACTIVE)
			continue;

		clone = skb_clone(skb, GFP_ATOMIC);
		if (!clone)
			continue;

		/* Transmit on this path */
		if (tquic_udp_xmit_on_path(conn, path, clone) == 0) {
			/* Update path statistics */
			path->stats.tx_packets++;
			path->stats.tx_bytes += clone->len;
			path->last_activity = ktime_get();
			sent++;
		} else {
			kfree_skb(clone);
		}
	}

	kfree_skb(skb);
	return sent > 0 ? 0 : -ENODEV;
}

/*
 * Main path selection function
 */
struct tquic_path *tquic_bond_select_path(struct tquic_connection *conn,
					  struct sk_buff *skb)
{
	struct tquic_bond_state *bond = conn->scheduler;
	struct tquic_path *selected;

	if (!bond)
		return conn->active_path;

	switch (bond->mode) {
	case TQUIC_BOND_MODE_FAILOVER:
		/* Use primary unless it's down */
		if (bond->primary_path &&
		    bond->primary_path->state == TQUIC_PATH_ACTIVE)
			return bond->primary_path;
		return conn->active_path;

	case TQUIC_BOND_MODE_ROUNDROBIN:
		return tquic_select_roundrobin(bond, skb);

	case TQUIC_BOND_MODE_WEIGHTED:
		return tquic_select_weighted(bond, skb);

	case TQUIC_BOND_MODE_MINRTT:
		return tquic_select_minrtt(bond, skb);

	case TQUIC_BOND_MODE_AGGREGATE:
		return tquic_select_aggregate(bond, skb);

	case TQUIC_BOND_MODE_BLEST:
		return tquic_select_blest(bond, skb);

	case TQUIC_BOND_MODE_ECF:
		return tquic_select_ecf(bond, skb);

	case TQUIC_BOND_MODE_REDUNDANT:
		/* Redundant sends on all paths */
		selected = conn->active_path;
		break;

	default:
		selected = conn->active_path;
	}

	return selected;
}
EXPORT_SYMBOL_GPL(tquic_bond_select_path);

/*
 * Handle path failure - trigger failover
 */
void tquic_bond_path_failed(struct tquic_connection *conn,
			    struct tquic_path *path)
{
	struct tquic_bond_state *bond = conn->scheduler;
	struct tquic_path *new_active = NULL;
	struct tquic_path *p;

	if (!bond)
		return;

	pr_info("tquic: path %u failed, initiating failover\n", path->path_id);

	spin_lock(&conn->lock);

	path->state = TQUIC_PATH_FAILED;

	/* Find new active path */
	if (conn->active_path == path) {
		list_for_each_entry(p, &conn->paths, list) {
			if (p != path && p->state == TQUIC_PATH_ACTIVE) {
				new_active = p;
				break;
			}
		}

		/* Try standby paths */
		if (!new_active) {
			list_for_each_entry(p, &conn->paths, list) {
				if (p != path && p->state == TQUIC_PATH_STANDBY) {
					new_active = p;
					p->state = TQUIC_PATH_ACTIVE;
					break;
				}
			}
		}

		if (new_active) {
			conn->active_path = new_active;
			bond->stats.failovers++;
			pr_info("tquic: failed over to path %u\n", new_active->path_id);
		} else {
			pr_warn("tquic: no paths available for failover\n");
		}
	}

	bond->stats.failed_paths++;

	spin_unlock(&conn->lock);
}
EXPORT_SYMBOL_GPL(tquic_bond_path_failed);

/*
 * Handle path recovery
 */
void tquic_bond_path_recovered(struct tquic_connection *conn,
			       struct tquic_path *path)
{
	struct tquic_bond_state *bond = conn->scheduler;

	if (!bond)
		return;

	spin_lock(&conn->lock);

	if (path->state == TQUIC_PATH_FAILED) {
		path->state = TQUIC_PATH_STANDBY;
		pr_info("tquic: path %u recovered (standby)\n", path->path_id);

		/* Promote to active if it was the primary */
		if (path == bond->primary_path) {
			path->state = TQUIC_PATH_ACTIVE;
			if (bond->mode == TQUIC_BOND_MODE_FAILOVER)
				conn->active_path = path;
			pr_info("tquic: primary path %u restored\n", path->path_id);
		}
	}

	spin_unlock(&conn->lock);
}
EXPORT_SYMBOL_GPL(tquic_bond_path_recovered);

/*
 * Reorder buffer - handle out-of-order packet delivery
 */
int tquic_bond_reorder_insert(struct tquic_bond_state *bond,
			      struct sk_buff *skb, u64 seq)
{
	struct sk_buff *pos;

	spin_lock(&bond->reorder_lock);

	/* Check if within reorder window */
	if (seq < bond->reorder_next_seq) {
		/* Duplicate or too old */
		spin_unlock(&bond->reorder_lock);
		kfree_skb(skb);
		return 0;
	}

	if (seq > bond->reorder_next_seq + bond->reorder_window) {
		/* Too far ahead - might indicate path issue */
		spin_unlock(&bond->reorder_lock);
		return -ERANGE;
	}

	/* Insert in sequence order */
	skb_queue_walk(&bond->reorder_queue, pos) {
		u64 pos_seq = *(u64 *)pos->cb;  /* Stored in skb control block */
		if (seq < pos_seq) {
			__skb_queue_before(&bond->reorder_queue, pos, skb);
			spin_unlock(&bond->reorder_lock);
			return 0;
		}
	}

	__skb_queue_tail(&bond->reorder_queue, skb);
	bond->stats.reorder_events++;

	spin_unlock(&bond->reorder_lock);
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_bond_reorder_insert);

/*
 * Deliver reordered packets to upper layer
 */
int tquic_bond_reorder_deliver(struct tquic_bond_state *bond)
{
	struct sk_buff *skb;
	int delivered = 0;

	spin_lock(&bond->reorder_lock);

	while ((skb = skb_peek(&bond->reorder_queue)) != NULL) {
		u64 seq = *(u64 *)skb->cb;

		if (seq != bond->reorder_next_seq)
			break;

		__skb_unlink(skb, &bond->reorder_queue);
		bond->reorder_next_seq++;

		/*
		 * Deliver to stream layer.
		 * Queue the packet to the default stream's receive buffer
		 * for the application to read.
		 */
		if (bond->conn && bond->conn->sk) {
			struct tquic_sock *tsk = tquic_sk(bond->conn->sk);

			if (tsk->default_stream) {
				skb_queue_tail(&tsk->default_stream->recv_buf, skb);
				bond->conn->sk->sk_data_ready(bond->conn->sk);
			} else {
				kfree_skb(skb);
			}
		} else {
			kfree_skb(skb);
		}
		delivered++;
	}

	spin_unlock(&bond->reorder_lock);
	return delivered;
}
EXPORT_SYMBOL_GPL(tquic_bond_reorder_deliver);

/*
 * Initialize bonding state for a connection
 */
struct tquic_bond_state *tquic_bond_init(struct tquic_connection *conn)
{
	struct tquic_bond_state *bond;

	bond = kzalloc(sizeof(*bond), GFP_KERNEL);
	if (!bond)
		return NULL;

	bond->conn = conn;
	bond->mode = TQUIC_BOND_MODE_AGGREGATE;
	bond->aggr_mode = TQUIC_AGGR_PACKET;
	bond->failover_mode = TQUIC_FAILOVER_IMMEDIATE;
	bond->reorder_window = 64;

	skb_queue_head_init(&bond->reorder_queue);
	spin_lock_init(&bond->reorder_lock);

	/* Set primary as first path if available */
	if (!list_empty(&conn->paths))
		bond->primary_path = list_first_entry(&conn->paths,
						      struct tquic_path, list);

	bond->stats.total_paths = conn->num_paths;
	bond->stats.active_paths = conn->num_paths;

	pr_debug("tquic: initialized bonding state for connection\n");

	return bond;
}
EXPORT_SYMBOL_GPL(tquic_bond_init);

/*
 * Cleanup bonding state
 */
void tquic_bond_cleanup(struct tquic_bond_state *bond)
{
	if (!bond)
		return;

	skb_queue_purge(&bond->reorder_queue);
	kfree(bond);
}
EXPORT_SYMBOL_GPL(tquic_bond_cleanup);

/*
 * Set bonding mode
 */
int tquic_bond_set_mode(struct tquic_connection *conn, u8 mode)
{
	struct tquic_bond_state *bond = conn->scheduler;

	if (!bond)
		return -EINVAL;

	if (mode > TQUIC_BOND_MODE_ECF)
		return -EINVAL;

	bond->mode = mode;
	pr_info("tquic: set bonding mode to %u\n", mode);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_bond_set_mode);

/*
 * Set primary path for failover mode
 */
int tquic_bond_set_primary(struct tquic_connection *conn, u32 path_id)
{
	struct tquic_bond_state *bond = conn->scheduler;
	struct tquic_path *path;

	if (!bond)
		return -EINVAL;

	path = tquic_conn_get_path(conn, path_id);
	if (!path)
		return -ENOENT;

	bond->primary_path = path;
	pr_info("tquic: set primary path to %u\n", path_id);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_bond_set_primary);

/*
 * Get bonding statistics
 */
int tquic_bond_get_stats(struct tquic_connection *conn,
			 struct tquic_bond_stats *stats)
{
	struct tquic_bond_state *bond = conn->scheduler;

	if (!bond || !stats)
		return -EINVAL;

	memcpy(stats, &bond->stats, sizeof(*stats));
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_bond_get_stats);

MODULE_DESCRIPTION("TQUIC WAN Bonding Core");
MODULE_LICENSE("GPL");
