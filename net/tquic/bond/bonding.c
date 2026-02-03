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

/* Path quality metrics for scheduling decisions */
struct tquic_path_quality {
	u64 score;           /* Combined quality score */
	u32 available_cwnd;  /* Available congestion window */
	s64 inflight;        /* Bytes in flight (signed to detect underflow) */
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
	 * Track in-flight bytes from path statistics.
	 * This is updated by the congestion control module.
	 * Use signed arithmetic to detect underflow.
	 */
	quality->inflight = (s64)stats->tx_bytes -
			    ((s64)stats->rx_bytes + (s64)stats->lost_packets * 1200);
	if (quality->inflight < 0)
		quality->inflight = 0;
	quality->est_delivery = stats->rtt_smoothed;
	quality->can_send = (quality->available_cwnd > (u64)quality->inflight);
}

/*
 * Select best path based on minimum RTT
 * Caller must hold conn->lock to protect path list iteration.
 */
static struct tquic_path *tquic_select_minrtt(struct tquic_bond_state *bond,
					      struct sk_buff *skb)
{
	struct tquic_connection *conn = bond->conn;
	struct tquic_path *path, *best = NULL;
	u32 min_rtt = UINT_MAX;

	/* conn->lock must be held by caller */
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
 * Caller must hold conn->lock to protect path list iteration.
 */
static struct tquic_path *tquic_select_roundrobin(struct tquic_bond_state *bond,
						  struct sk_buff *skb)
{
	struct tquic_connection *conn = bond->conn;
	struct tquic_path *path;
	u32 idx = 0;
	u32 target;
	u32 active_count = 0;

	/* conn->lock must be held by caller */
	/* Count active paths first to avoid bias from inactive paths */
	list_for_each_entry(path, &conn->paths, list) {
		if (path->state == TQUIC_PATH_ACTIVE)
			active_count++;
	}

	/* Guard against division by zero when no active paths exist */
	if (unlikely(active_count == 0))
		return conn->active_path;

	target = bond->rr_counter++ % active_count;

	/* Select the target'th active path */
	list_for_each_entry(path, &conn->paths, list) {
		if (path->state != TQUIC_PATH_ACTIVE)
			continue;

		if (idx == target)
			return path;
		idx++;
	}

	/* Fallback should not be reached, but handle defensively */
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
 * ECF (Earliest Completion First) Scheduler
 *
 * True bandwidth aggregation scheduler that selects the path with the
 * earliest predicted packet completion time.
 *
 * Formula: Completion_Time = RTT + (In_Flight_Bytes + Packet_Size) / Bandwidth
 *
 * This formula considers:
 *   - RTT: Full round-trip propagation delay
 *   - In_Flight: Bytes already sent but not acknowledged (queuing)
 *   - Packet_Size: The current packet to be transmitted
 *   - Bandwidth: Estimated path throughput capacity
 *
 * Example: For 1Gbps Fiber (5ms RTT) + 100Mbps LTE (50ms RTT):
 *   - Fiber with 50KB in-flight: 5ms + (50KB + 1.5KB) / 125MB/s = 5.4ms
 *   - LTE with 5KB in-flight:   50ms + (5KB + 1.5KB) / 12.5MB/s = 50.5ms
 *   → Fiber is selected (faster completion despite more in-flight data)
 */
static struct tquic_path *tquic_select_ecf(struct tquic_bond_state *bond,
					   struct sk_buff *skb)
{
	struct tquic_connection *conn = bond->conn;
	struct tquic_path *path, *best = NULL;
	u64 min_completion = ULLONG_MAX;
	u32 pkt_size = skb->len;

	list_for_each_entry(path, &conn->paths, list) {
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
		 * This is data "on the wire" waiting for ACK.
		 */
		if (path->stats.tx_bytes > path->stats.acked_bytes)
			in_flight_bytes = path->stats.tx_bytes - path->stats.acked_bytes;
		else
			in_flight_bytes = 0;

		/*
		 * Clamp in-flight to congestion window.
		 * We shouldn't have more in-flight than cwnd allows;
		 * if tracking shows this, packets were likely lost.
		 */
		if (in_flight_bytes > path->stats.cwnd)
			in_flight_bytes = path->stats.cwnd;

		/* Get RTT in microseconds (full RTT for completion estimate) */
		rtt_us = path->stats.rtt_smoothed;
		if (rtt_us == 0)
			rtt_us = 100000;  /* 100ms default */

		/* Get bandwidth in bytes/second */
		bandwidth = path->stats.bandwidth;
		if (bandwidth == 0) {
			/*
			 * No bandwidth estimate available yet.
			 * Derive from congestion window and RTT:
			 * BW ≈ cwnd / RTT (basic BDP relationship)
			 */
			if (path->stats.cwnd > 0 && rtt_us > 0)
				bandwidth = (u64)path->stats.cwnd * 1000000ULL / rtt_us;
			else
				bandwidth = 125000;  /* 1 Mbps fallback */
		}

		/*
		 * ECF completion time formula:
		 * Completion_Time = RTT + (In_Flight + Pkt_Size) / Bandwidth
		 *
		 * Units: RTT is microseconds, bandwidth is bytes/sec
		 * (bytes / bytes_per_sec) = seconds → *1000000 for microseconds
		 */
		queue_drain_time = ((in_flight_bytes + pkt_size) * 1000000ULL) / bandwidth;
		completion_time = rtt_us + queue_drain_time;

		/*
		 * Penalize lossy paths.
		 * A path with loss requires retransmissions, effectively
		 * multiplying completion time by 1/(1-loss_rate).
		 */
		if (path->stats.tx_packets > 100 && path->stats.lost_packets > 0) {
			u64 loss_pct = (path->stats.lost_packets * 100) /
				       path->stats.tx_packets;
			if (loss_pct > 0 && loss_pct < 50)
				completion_time = (completion_time * 100) / (100 - loss_pct);
		}

		if (completion_time < min_completion) {
			min_completion = completion_time;
			best = path;
		}
	}

	return best ?: conn->active_path;
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
 * Caller must hold conn->lock to protect path list iteration.
 * Called from tquic_select_path() which acquires the lock.
 */
struct tquic_path *tquic_bond_select_path(struct tquic_connection *conn,
					  struct sk_buff *skb)
{
	struct tquic_bond_state *bond = conn->scheduler;
	struct tquic_path *selected;

	/* conn->lock must be held by caller (tquic_select_path) */
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

/**
 * tquic_bond_set_path_weight - Set the scheduling weight for a path
 * @conn: Connection
 * @path_id: Path identifier
 * @weight: New weight (0-100)
 *
 * Sets the relative weight of a path for weighted scheduling algorithms.
 * Higher weight means more traffic is directed to that path.
 *
 * Returns 0 on success, negative error on failure.
 */
int tquic_bond_set_path_weight(struct tquic_connection *conn, u32 path_id, u32 weight)
{
	struct tquic_path *path;

	if (!conn || weight > 100)
		return -EINVAL;

	list_for_each_entry(path, &conn->paths, list) {
		if (path->path_id == path_id) {
			path->weight = weight;
			pr_debug("tquic_bond: path %u weight set to %u\n",
				 path_id, weight);
			return 0;
		}
	}

	return -ENOENT;
}
EXPORT_SYMBOL_GPL(tquic_bond_set_path_weight);

/**
 * tquic_bond_interface_down - Handle network interface going down
 * @conn: QUIC connection
 * @dev: Network device that went down
 *
 * Called by the path manager when a network interface goes down.
 * Marks all paths using this interface as failed and triggers failover.
 */
void tquic_bond_interface_down(struct tquic_connection *conn,
			       struct net_device *dev)
{
	struct tquic_bond_state *bond;
	struct tquic_path *path;
	int failed_count = 0;

	if (!conn)
		return;

	bond = conn->scheduler;
	if (!bond)
		return;

	spin_lock(&conn->lock);

	/* Mark all paths using this interface as failed */
	list_for_each_entry(path, &conn->paths, list) {
		if (path->dev == dev && path->state == TQUIC_PATH_ACTIVE) {
			path->state = TQUIC_PATH_FAILED;
			failed_count++;
			bond->stats.failed_paths++;

			pr_debug("tquic: path %u failed (interface %s down)\n",
				 path->path_id, dev->name);
		}
	}

	/* If primary path failed, trigger failover */
	if (bond->primary_path && bond->primary_path->dev == dev) {
		struct tquic_path *new_primary = NULL;

		/* Find first active path as new primary */
		list_for_each_entry(path, &conn->paths, list) {
			if (path->state == TQUIC_PATH_ACTIVE && path != bond->primary_path) {
				new_primary = path;
				break;
			}
		}

		if (new_primary) {
			bond->primary_path = new_primary;
			conn->active_path = new_primary;
			bond->stats.failovers++;
			pr_info("tquic: failover to path %u after interface %s down\n",
				new_primary->path_id, dev->name);
		} else {
			bond->primary_path = NULL;
			pr_warn("tquic: no available paths after interface %s down\n",
				dev->name);
		}
	}

	spin_unlock(&conn->lock);
}
EXPORT_SYMBOL_GPL(tquic_bond_interface_down);

static int __init tquic_bond_module_init(void)
{
	pr_info("tquic_bond: module loaded\n");
	return 0;
}

static void __exit tquic_bond_module_exit(void)
{
	pr_info("tquic_bond: module unloaded\n");
}

module_init(tquic_bond_module_init);
module_exit(tquic_bond_module_exit);

MODULE_DESCRIPTION("TQUIC WAN Bonding Core");
MODULE_LICENSE("GPL");
