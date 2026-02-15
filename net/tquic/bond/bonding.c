// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: WAN Bonding Core
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * This module implements the core WAN bonding functionality for TQUIC,
 * enabling true bandwidth aggregation across multiple network paths.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/lockdep.h>
#include <linux/workqueue.h>
#include <linux/timer.h>
#include <linux/random.h>
#include <linux/unaligned.h>
#include <linux/rcupdate.h>
#include <net/sock.h>
#include <net/tquic.h>

#include "../tquic_debug.h"
#include "../protocol.h"
#include "tquic_bonding.h"

/* Path quality metrics for scheduling decisions */
struct tquic_path_quality {
	u64 score;           /* Combined quality score */
	u32 available_cwnd;  /* Available congestion window */
	s64 inflight;        /* Bytes in flight (signed to detect underflow) */
	u32 est_delivery;    /* Estimated delivery time (us) */
	bool can_send;       /* Can accept more data */
};

static inline bool tquic_path_state_usable(int state)
{
	return state == TQUIC_PATH_ACTIVE || state == TQUIC_PATH_VALIDATED;
}

static inline bool tquic_path_usable(const struct tquic_path *path)
{
	return tquic_path_state_usable(READ_ONCE(path->state));
}

/*
 * Calculate path quality score for scheduling decisions
 * Higher score = better path
 */
static void tquic_calc_path_quality(struct tquic_path *path,
				    struct tquic_path_quality *quality)
{
	struct tquic_path_stats *stats = &path->stats;
	u64 score = 0;

	if (!tquic_path_usable(path)) {
		quality->score = 0;
		quality->can_send = false;
		return;
	}

	/* Base score from RTT (lower is better) */
	{
		u32 rtt = READ_ONCE(stats->rtt_smoothed);

		if (rtt > 0)
			score = 1000000000ULL / rtt;
	}

	/* Adjust for bandwidth */
	{
		u64 bw = READ_ONCE(stats->bandwidth);

		if (bw > 0)
			score = (score * bw) >> 20;
	}

	/* Penalize for loss */
	if (READ_ONCE(stats->tx_packets) > 0) {
		u64 tx_pkts = READ_ONCE(stats->tx_packets);
		u64 lost_pkts = READ_ONCE(stats->lost_packets);
		u64 loss_rate = (lost_pkts * 100) / tx_pkts;

		if (loss_rate > 0)
			score = score * (100 - min(loss_rate, 90ULL)) / 100;
	}

	/* Apply priority weighting */
	score = score * (256 - min_t(u32, path->priority, 255)) / 256;

	/* Apply explicit weight, guard overflow */
	if (path->weight > 0 && score <= div64_u64(U64_MAX, path->weight))
		score = score * path->weight;
	else
		score = U64_MAX;

	quality->score = score;
	quality->available_cwnd = READ_ONCE(stats->cwnd);
	/*
	 * Track in-flight bytes from path statistics.
	 * Use unsigned arithmetic with underflow guard to avoid
	 * s64 overflow when u64 counters exceed S64_MAX.
	 */
	{
		u64 tx = READ_ONCE(stats->tx_bytes);
		u64 rx = READ_ONCE(stats->rx_bytes);
		u64 lost_pkts = READ_ONCE(stats->lost_packets);
		u64 lost_est;
		u64 acked;

		/* Guard multiplication overflow */
		if (lost_pkts > U64_MAX / 1200)
			lost_est = U64_MAX;
		else
			lost_est = lost_pkts * 1200;

		/* Saturating addition for rx + lost_est */
		if (check_add_overflow(rx, lost_est, &acked))
			acked = U64_MAX;

		if (tx > acked)
			quality->inflight = (s64)min(tx - acked,
						     (u64)S64_MAX);
		else
			quality->inflight = 0;
	}
	quality->est_delivery = READ_ONCE(stats->rtt_smoothed);
	quality->can_send = (quality->available_cwnd > (u64)quality->inflight);
}

/*
 * Resolve bond->primary_path under conn->paths_lock.
 * If the cached pointer is no longer present in conn->paths, clear it.
 */
static struct tquic_path *tquic_bond_primary_path_locked(struct tquic_connection *conn,
							 struct tquic_bond_state *bond)
{
	struct tquic_path *path;
	struct tquic_path *primary = bond->primary_path;

	lockdep_assert_held(&conn->paths_lock);

	if (!primary)
		return NULL;

	list_for_each_entry(path, &conn->paths, list) {
		if (path == primary)
			return path;
	}

	bond->primary_path = NULL;
	return NULL;
}

/*
 * Select best path based on minimum RTT
 * Caller must hold conn->paths_lock to protect path list iteration.
 */
static struct tquic_path *tquic_select_minrtt(struct tquic_bond_state *bond,
					      struct sk_buff *skb)
{
	struct tquic_connection *conn = bond->conn;
	struct tquic_path *path, *best = NULL;
	u32 min_rtt = UINT_MAX;

	lockdep_assert_held(&conn->paths_lock);

	list_for_each_entry(path, &conn->paths, list) {
		u32 rtt;

		if (!tquic_path_usable(path))
			continue;

		rtt = READ_ONCE(path->stats.rtt_smoothed);
		if (rtt < min_rtt) {
			min_rtt = rtt;
			best = path;
		}
	}

	/* Return referenced path per API contract */
	if (best && tquic_path_get(best))
		return best;

	rcu_read_lock();
	best = rcu_dereference(conn->active_path);
	if (best && !tquic_path_get(best))
		best = NULL;
	rcu_read_unlock();

	return best;
}

/*
 * Select path using round-robin
 * Caller must hold conn->paths_lock to protect path list iteration.
 */
static struct tquic_path *tquic_select_roundrobin(struct tquic_bond_state *bond,
						  struct sk_buff *skb)
{
	struct tquic_connection *conn = bond->conn;
	struct tquic_path *path, *selected = NULL;
	u32 counter;
	u32 usable_count = 0;
	u32 idx = 0;
	u32 target;

	lockdep_assert_held(&conn->paths_lock);

	/*
	 * Two-pass selection under conn->paths_lock:
	 * 1) count usable paths,
	 * 2) pick (counter % usable_count)-th usable path.
	 */
	counter = (u32)atomic_inc_return(&bond->rr_counter);

	list_for_each_entry(path, &conn->paths, list) {
		if (!tquic_path_usable(path))
			continue;

		usable_count++;
	}

	if (!usable_count)
		goto fallback;

	target = counter % usable_count;

	list_for_each_entry(path, &conn->paths, list) {
		if (!tquic_path_usable(path))
			continue;

		if (idx++ == target) {
			selected = path;
			break;
		}
	}

	/* Return referenced path per API contract */
	if (selected && tquic_path_get(selected))
		return selected;

	fallback:
	rcu_read_lock();
	selected = rcu_dereference(conn->active_path);
	if (selected && !tquic_path_get(selected))
		selected = NULL;
	rcu_read_unlock();

	return selected;
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

	lockdep_assert_held(&conn->paths_lock);

	/*
	 * CF-307: Calculate total weight of active paths with overflow
	 * guard. Clamp individual weights to prevent corrupt values from
	 * causing wraparound.
	 */
	list_for_each_entry(path, &conn->paths, list) {
		if (tquic_path_usable(path))
			total_weight += min_t(u32, path->weight, 1000);
	}

	if (total_weight == 0) {
		/* Return referenced path per API contract */
		rcu_read_lock();
		path = rcu_dereference(conn->active_path);
		if (path && !tquic_path_get(path))
			path = NULL;
		rcu_read_unlock();

		return path;
	}

	/* Select based on weight */
	target = (u32)atomic_inc_return(&bond->rr_counter) % total_weight;

	list_for_each_entry(path, &conn->paths, list) {
		if (!tquic_path_usable(path))
			continue;

		cumulative += min_t(u32, path->weight, 1000);
		if (target < cumulative) {
			selected = path;
			break;
		}
	}

	/* Return referenced path per API contract */
	if (selected && tquic_path_get(selected))
		return selected;

	rcu_read_lock();
	selected = rcu_dereference(conn->active_path);
	if (selected && !tquic_path_get(selected))
		selected = NULL;
	rcu_read_unlock();

	return selected;
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

	lockdep_assert_held(&conn->paths_lock);

	list_for_each_entry(path, &conn->paths, list) {
		if (!tquic_path_usable(path))
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
			u32 pcwnd = READ_ONCE(path->stats.cwnd);

			if (tquic_path_usable(path) &&
			    pcwnd > max_cwnd) {
				max_cwnd = pcwnd;
				best = path;
			}
		}
	}

	/* Return referenced path per API contract */
	if (best && tquic_path_get(best))
		return best;

	rcu_read_lock();
	best = rcu_dereference(conn->active_path);
	if (best && !tquic_path_get(best))
		best = NULL;
	rcu_read_unlock();

	return best;
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
	u32 pkt_len = skb ? skb->len : 0;

	lockdep_assert_held(&conn->paths_lock);

	list_for_each_entry(path, &conn->paths, list) {
		struct tquic_path_quality quality;
		u64 completion_time;
		u64 bw;

		if (!tquic_path_usable(path))
			continue;

		tquic_calc_path_quality(path, &quality);

		if (!quality.can_send)
			continue;

		/* Estimate when this packet would be delivered */
		completion_time = quality.est_delivery;

		/* Add queuing delay estimate */
		bw = READ_ONCE(path->stats.bandwidth);
		if (bw > 0)
			completion_time += ((u64)pkt_len * 1000000ULL) / bw;

		if (completion_time < min_completion) {
			min_completion = completion_time;
			best = path;
		}
	}

	/* Return referenced path per API contract */
	if (best && tquic_path_get(best))
		return best;

	rcu_read_lock();
	best = rcu_dereference(conn->active_path);
	if (best && !tquic_path_get(best))
		best = NULL;
	rcu_read_unlock();

	return best;
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
	u32 pkt_size = skb ? skb->len : 0;

	list_for_each_entry(path, &conn->paths, list) {
		u64 completion_time;
		u64 in_flight_bytes;
		u64 queue_drain_time;
		u64 rtt_us;
		u64 bandwidth;
		u64 tx_bytes, acked_bytes;
		u32 cwnd;

		if (!tquic_path_usable(path))
			continue;

		/*
		 * Calculate in-flight bytes.
		 * In-flight = transmitted bytes - acknowledged bytes
		 * This is data "on the wire" waiting for ACK.
		 */
		tx_bytes = READ_ONCE(path->stats.tx_bytes);
		acked_bytes = READ_ONCE(path->stats.acked_bytes);
		if (tx_bytes > acked_bytes)
			in_flight_bytes = tx_bytes - acked_bytes;
		else
			in_flight_bytes = 0;

		/*
		 * Clamp in-flight to congestion window.
		 * We shouldn't have more in-flight than cwnd allows;
		 * if tracking shows this, packets were likely lost.
		 */
		cwnd = READ_ONCE(path->stats.cwnd);
		if (in_flight_bytes > cwnd)
			in_flight_bytes = cwnd;

		/* Get RTT in microseconds (full RTT for completion estimate) */
		rtt_us = READ_ONCE(path->stats.rtt_smoothed);
		if (rtt_us == 0)
			rtt_us = 100000;  /* 100ms default */

		/* Get bandwidth in bytes/second */
		bandwidth = READ_ONCE(path->stats.bandwidth);
		if (bandwidth == 0) {
			/*
			 * No bandwidth estimate available yet.
			 * Derive from congestion window and RTT:
			 * BW = cwnd / RTT (basic BDP relationship)
			 */
			if (cwnd > 0 && rtt_us > 0)
				bandwidth = (u64)cwnd * 1000000ULL / rtt_us;
			else
				bandwidth = 125000;  /* 1 Mbps fallback */
		}

		/*
		 * ECF completion time formula:
		 * Completion_Time = RTT + (In_Flight + Pkt_Size) / Bandwidth
		 *
		 * Units: RTT is microseconds, bandwidth is bytes/sec
		 * (bytes / bytes_per_sec) = seconds -> *1000000 for microseconds
		 */
		queue_drain_time = ((in_flight_bytes + pkt_size) * 1000000ULL) / bandwidth;
		completion_time = rtt_us + queue_drain_time;

		/*
		 * Penalize lossy paths.
		 * A path with loss requires retransmissions, effectively
		 * multiplying completion time by 1/(1-loss_rate).
		 */
		if (READ_ONCE(path->stats.tx_packets) > 100 &&
		    READ_ONCE(path->stats.lost_packets) > 0) {
			u64 tx_pkts = READ_ONCE(path->stats.tx_packets);
			u64 lost_pkts = READ_ONCE(path->stats.lost_packets);
			u64 loss_pct = (lost_pkts * 100) / tx_pkts;

			if (loss_pct > 0 && loss_pct < 50)
				completion_time = (completion_time * 100) / (100 - loss_pct);
		}

		if (completion_time < min_completion) {
			min_completion = completion_time;
			best = path;
		}
	}

	/* Return referenced path per API contract */
	if (best && tquic_path_get(best))
		return best;

	rcu_read_lock();
	best = rcu_dereference(conn->active_path);
	if (best && !tquic_path_get(best))
		best = NULL;
	rcu_read_unlock();

	return best;
}

/*
 * Send packet on all paths (redundant mode)
 */
static int __maybe_unused tquic_send_redundant(struct tquic_bond_state *bond,
				struct sk_buff *skb)
{
	struct tquic_connection *conn = bond->conn;
	struct tquic_path *path;
	int sent = 0;

	list_for_each_entry(path, &conn->paths, list) {
		struct sk_buff *clone;

		if (!tquic_path_usable(path))
			continue;

		clone = skb_clone(skb, GFP_ATOMIC);
		if (!clone)
			continue;

		/* Transmit on this path */
		if (tquic_udp_xmit_on_path(conn, path, clone) == 0) {
			sent++;
		}
	}

	kfree_skb(skb);
	return sent > 0 ? 0 : -ENODEV;
}

/*
 * Main path selection function
 * Caller must hold conn->paths_lock to protect path list iteration.
 * Called from tquic_select_path() which acquires the lock.
 */
struct tquic_path *tquic_bond_select_path(struct tquic_connection *conn,
					  struct sk_buff *skb)
{
	struct tquic_bond_state *bond = conn->scheduler;
	struct tquic_path *selected;
	struct tquic_path *fallback;
	struct tquic_path *primary;

	/* conn->paths_lock must be held by caller (tquic_select_path) */
	if (!bond) {
		struct tquic_path *path;

		/* Return referenced path per API contract */
		rcu_read_lock();
		path = rcu_dereference(conn->active_path);
		if (path && !tquic_path_get(path))
			path = NULL;
		rcu_read_unlock();

		return path;
	}

	/*
	 * Safety: If PM init failed and no paths were added, fall back to
	 * active_path. This prevents NULL deref when iterating empty list.
	 */
	if (list_empty(&conn->paths)) {
		struct tquic_path *path;

		rcu_read_lock();
		path = rcu_dereference(conn->active_path);
		if (path && !tquic_path_get(path))
			path = NULL;
		rcu_read_unlock();

		return path;
	}

	switch (bond->mode) {
	case TQUIC_BOND_MODE_FAILOVER:
		/* Use primary unless it's down */
		primary = tquic_bond_primary_path_locked(conn, bond);
		if (primary && tquic_path_usable(primary)) {
			selected = primary;
			if (!tquic_path_get(selected))
				selected = NULL;
		} else {
			rcu_read_lock();
			selected = rcu_dereference(conn->active_path);
			if (selected && !tquic_path_get(selected))
				selected = NULL;
			rcu_read_unlock();
		}
		break;

	case TQUIC_BOND_MODE_ROUNDROBIN:
		selected = tquic_select_roundrobin(bond, skb);
		break;

	case TQUIC_BOND_MODE_WEIGHTED:
		selected = tquic_select_weighted(bond, skb);
		break;

	case TQUIC_BOND_MODE_MINRTT:
		selected = tquic_select_minrtt(bond, skb);
		break;

	case TQUIC_BOND_MODE_AGGREGATE:
		selected = tquic_select_aggregate(bond, skb);
		break;

	case TQUIC_BOND_MODE_BLEST:
		selected = tquic_select_blest(bond, skb);
		break;

	case TQUIC_BOND_MODE_ECF:
		selected = tquic_select_ecf(bond, skb);
		break;

	case TQUIC_BOND_MODE_REDUNDANT:
		/* Redundant sends on all paths */
		rcu_read_lock();
		selected = rcu_dereference(conn->active_path);
		if (selected && !tquic_path_get(selected))
			selected = NULL;
		rcu_read_unlock();
		break;

	default:
		rcu_read_lock();
		selected = rcu_dereference(conn->active_path);
		if (selected && !tquic_path_get(selected))
			selected = NULL;
		rcu_read_unlock();
	}

	/*
	 * RFC 9000 §8.1: Check anti-amplification limit on unvalidated paths.
	 * If the selected path exceeds the 3x amplification limit, try to
	 * find an alternate path that can send.
	 */
	if (selected && selected->anti_amplification.active &&
	    !tquic_path_anti_amplification_check(selected,
						 skb ? skb->len : 0)) {
		struct tquic_path *candidate = NULL;

		/* Safety check: don't iterate empty list (PM init failed case) */
		if (list_empty(&conn->paths)) {
			tquic_path_put(selected);
			return NULL;
		}

		fallback = NULL;
		list_for_each_entry(fallback, &conn->paths, list) {
			if (fallback == selected)
				continue;
			if (!tquic_path_usable(fallback))
				continue;

			if (!tquic_path_get(fallback))
				continue;

			if (fallback->anti_amplification.active &&
			    !tquic_path_anti_amplification_check(fallback,
								 skb ? skb->len : 0)) {
				tquic_path_put(fallback);
				continue;
			}

			candidate = fallback;
			break;
		}

		/*
		 * Release blocked path ref. If no alternate path is available,
		 * return NULL so callers defer transmission.
		 */
		tquic_path_put(selected);
		selected = candidate;
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

	tquic_warn("path %u failed, initiating failover\n", path->path_id);
	tquic_trace_failover(conn, path->path_id, 0, 0, 0);

	spin_lock_bh(&conn->paths_lock);

	WRITE_ONCE(path->state, TQUIC_PATH_FAILED);

	/* Find new active path */
	if (READ_ONCE(conn->active_path) == path) {
		list_for_each_entry(p, &conn->paths, list) {
			if (p == path || !tquic_path_usable(p))
				continue;

			if (READ_ONCE(p->state) == TQUIC_PATH_VALIDATED)
				WRITE_ONCE(p->state, TQUIC_PATH_ACTIVE);

			new_active = p;
			break;
		}

		/*
		 * Try standby paths if no other active path exists.
		 */
		if (!new_active) {
			list_for_each_entry(p, &conn->paths, list) {
				if (p != path && p->state == TQUIC_PATH_STANDBY) {
					new_active = p;
					WRITE_ONCE(p->state, TQUIC_PATH_ACTIVE);
					break;
				}
			}
		}

		if (new_active) {
			rcu_assign_pointer(conn->active_path, new_active);
			bond->stats.failovers++;
			tquic_info("failed over to path %u\n",
				   new_active->path_id);
			tquic_trace_failover(conn, path->path_id,
					     new_active->path_id, 0, 0);
		} else {
			tquic_warn("no paths available for failover\n");
		}
	}

	bond->stats.failed_paths++;

	spin_unlock_bh(&conn->paths_lock);
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

	spin_lock_bh(&conn->paths_lock);

	if (path->state == TQUIC_PATH_FAILED) {
		WRITE_ONCE(path->state, TQUIC_PATH_STANDBY);
		tquic_info("path %u recovered (standby)\n", path->path_id);

		/* Promote to active if it was the primary */
		if (path == bond->primary_path) {
			WRITE_ONCE(path->state, TQUIC_PATH_ACTIVE);
			if (bond->mode == TQUIC_BOND_MODE_FAILOVER)
				rcu_assign_pointer(conn->active_path, path);
			tquic_info("primary path %u restored\n",
				   path->path_id);
		}
	}

	spin_unlock_bh(&conn->paths_lock);
}
EXPORT_SYMBOL_GPL(tquic_bond_path_recovered);

/*
 * Reorder buffer - handle out-of-order packet delivery
 */
int tquic_bond_reorder_insert(struct tquic_bond_state *bond,
			      struct sk_buff *skb, u64 seq)
{
	struct sk_buff *pos;

	/* Store sequence number in skb cb using put_unaligned for safety */
	BUILD_BUG_ON(sizeof(u64) > sizeof(skb->cb));
	put_unaligned(seq, (u64 *)skb->cb);

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
		u64 pos_seq = get_unaligned((u64 *)pos->cb);
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
		u64 seq = get_unaligned((u64 *)skb->cb);

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
			struct sock *sk = bond->conn->sk;
			struct tquic_sock *tsk = tquic_sk(sk);
			struct tquic_stream *stream;

			stream = tquic_sock_default_stream_get(tsk);
			if (stream) {
				skb_queue_tail(&stream->recv_buf, skb);
				sk->sk_data_ready(sk);
				tquic_stream_put(stream);
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
	spin_lock_bh(&conn->paths_lock);
	if (!list_empty(&conn->paths))
		bond->primary_path = list_first_entry(&conn->paths,
						      struct tquic_path, list);
	spin_unlock_bh(&conn->paths_lock);

	bond->stats.total_paths = conn->num_paths;
	bond->stats.active_paths = conn->num_paths;

	tquic_info("initialized bonding state mode=%u reorder_window=%u\n",
		   bond->mode, bond->reorder_window);

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
	tquic_info("set bonding mode to %u\n", mode);

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
	int ret = -ENOENT;

	if (!bond)
		return -EINVAL;

	spin_lock_bh(&conn->paths_lock);
	list_for_each_entry(path, &conn->paths, list) {
		if (path->path_id == path_id) {
			bond->primary_path = path;
			ret = 0;
			break;
		}
	}
	spin_unlock_bh(&conn->paths_lock);

	if (!ret)
		tquic_info("set primary path to %u\n", path_id);

	return ret;
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
	int ret = -ENOENT;

	if (!conn || weight > 100)
		return -EINVAL;

	spin_lock_bh(&conn->paths_lock);
	list_for_each_entry(path, &conn->paths, list) {
		if (path->path_id == path_id) {
			path->weight = weight;
			tquic_dbg("bond: path %u weight set to %u\n",
				  path_id, weight);
			ret = 0;
			break;
		}
	}
	spin_unlock_bh(&conn->paths_lock);

	return ret;
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
	struct tquic_path *primary;
	u32 old_primary_id = 0;
	int failed_count = 0;

	if (!conn)
		return;

	bond = conn->scheduler;
	if (!bond)
		return;

	spin_lock_bh(&conn->paths_lock);

	/* Mark all paths using this interface as failed */
	list_for_each_entry(path, &conn->paths, list) {
		if (path->dev == dev && tquic_path_usable(path)) {
			WRITE_ONCE(path->state, TQUIC_PATH_FAILED);
			failed_count++;
			bond->stats.failed_paths++;

			tquic_warn("path %u failed (interface %s down)\n",
				   path->path_id, dev->name);
		}
	}

	/* If primary path failed, trigger failover */
	primary = tquic_bond_primary_path_locked(conn, bond);
	if (primary && primary->dev == dev) {
		struct tquic_path *new_primary = NULL;
		old_primary_id = primary->path_id;

		/* Find first usable path as new primary */
		list_for_each_entry(path, &conn->paths, list) {
			if (path == primary || !tquic_path_usable(path))
				continue;

			if (READ_ONCE(path->state) == TQUIC_PATH_VALIDATED)
				WRITE_ONCE(path->state, TQUIC_PATH_ACTIVE);

			new_primary = path;
			break;
		}

		if (new_primary) {
			bond->primary_path = new_primary;
			rcu_assign_pointer(conn->active_path, new_primary);
			bond->stats.failovers++;
			tquic_warn("failover to path %u after interface %s down\n",
				   new_primary->path_id, dev->name);
			tquic_trace_failover(conn,
					     old_primary_id,
					     new_primary->path_id, 2, 0);
		} else {
			bond->primary_path = NULL;
			tquic_err("no available paths after interface %s down\n",
				  dev->name);
		}
	}

	spin_unlock_bh(&conn->paths_lock);
}
EXPORT_SYMBOL_GPL(tquic_bond_interface_down);

/*
 * Note: Module init/exit handled by tquic_main.c when built into tquic.ko
 * If building as standalone module, uncomment below:
 *
 * static int __init tquic_bond_module_init(void) { return 0; }
 * static void __exit tquic_bond_module_exit(void) { }
 * module_init(tquic_bond_module_init);
 * module_exit(tquic_bond_module_exit);
 * MODULE_DESCRIPTION("TQUIC WAN Bonding Core");
 * MODULE_LICENSE("GPL");
 */
