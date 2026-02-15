// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Congestion Control Framework
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Central CC registry and path lifecycle integration for TQUIC.
 *
 * This module provides:
 * - CC algorithm registration/unregistration
 * - RCU-protected algorithm lookup by name
 * - Per-path CC state initialization and release
 * - Callback dispatch for ACK/loss/RTT events
 *
 * The framework follows the kernel tcp_cong.c pattern with adaptations
 * for TQUIC's per-path congestion control model.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/rcupdate.h>
#include <linux/jhash.h>
#include <net/tquic.h>
#include <net/net_namespace.h>
#include "../protocol.h"
#include "../tquic_debug.h"
#include "tquic_cong.h"
#include "coupled.h"

/*
 * Global CC algorithm registry
 * Protected by tquic_cong_list_lock for modifications,
 * RCU for read access.
 */
static DEFINE_SPINLOCK(tquic_cong_list_lock);
static LIST_HEAD(tquic_cong_list);

/*
 * Default initial cwnd when no CC algorithm is available
 */
#define TQUIC_DEFAULT_CWND	(10 * 1200)	/* 10 packets */

/*
 * =============================================================================
 * Path Degradation on Consecutive Losses
 * =============================================================================
 *
 * Per RESEARCH.md: "5 consecutive lost packets in same round" triggers
 * path degradation. This implements loss tracking per path and signals
 * the bonding layer when the threshold is exceeded.
 */

/* Default threshold - 5 consecutive losses per RESEARCH.md */
#define TQUIC_PATH_DEGRADE_LOSS_THRESHOLD_DEFAULT	5

/*
 * Get threshold from netns or use default
 */
static int tquic_get_path_degrade_threshold(struct tquic_path *path)
{
	struct net *net = NULL;

	if (path && path->conn) {
		struct sock *sk = READ_ONCE(path->conn->sk);

		if (sk)
			net = sock_net(sk);
	}

	if (net) {
		struct tquic_net *tn = tquic_pernet(net);
		if (tn && tn->path_degrade_threshold > 0)
			return tn->path_degrade_threshold;
	}

	return TQUIC_PATH_DEGRADE_LOSS_THRESHOLD_DEFAULT;
}

/*
 * tquic_register_cong - Register a CC algorithm
 * @ca: Pointer to the CC algorithm ops structure
 *
 * Adds the CC algorithm to the global registry.
 * The algorithm must have a unique name.
 *
 * Return: 0 on success, -EEXIST if name already registered
 */
int tquic_register_cong(struct tquic_cong_ops *ca)
{
	struct tquic_cong_ops *existing;
	int ret = 0;

	if (!ca || !ca->name || !ca->init || !ca->release)
		return -EINVAL;

	/* Compute key for fast lookup */
	ca->key = jhash(ca->name, strlen(ca->name), 0);

	spin_lock(&tquic_cong_list_lock);

	/* Check for duplicate */
	list_for_each_entry(existing, &tquic_cong_list, list) {
		if (strcmp(existing->name, ca->name) == 0) {
			pr_notice("tquic_cong: %s already registered\n",
				  ca->name);
			ret = -EEXIST;
			goto out_unlock;
		}
	}

	/* Add to list (RCU-safe) */
	list_add_tail_rcu(&ca->list, &tquic_cong_list);
	tquic_info("cc: %s algorithm registered\n", ca->name);

out_unlock:
	spin_unlock(&tquic_cong_list_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_register_cong);

/*
 * tquic_unregister_cong - Unregister a CC algorithm
 * @ca: Pointer to the CC algorithm ops structure to unregister
 *
 * Removes the CC algorithm from the global registry.
 * Callers must ensure no paths are using this algorithm.
 */
void tquic_unregister_cong(struct tquic_cong_ops *ca)
{
	if (!ca)
		return;

	spin_lock(&tquic_cong_list_lock);
	list_del_rcu(&ca->list);
	spin_unlock(&tquic_cong_list_lock);

	/* Wait for RCU grace period before returning */
	synchronize_rcu();

	tquic_info("cc: %s algorithm unregistered\n", ca->name);
}
EXPORT_SYMBOL_GPL(tquic_unregister_cong);

/*
 * tquic_cong_find - Find CC algorithm by name
 * @name: Name of the CC algorithm to find
 *
 * RCU-protected lookup of registered CC algorithms.
 *
 * Return: Pointer to CC ops if found, NULL otherwise
 */
struct tquic_cong_ops *tquic_cong_find(const char *name)
{
	struct tquic_cong_ops *ca;

	if (!name || strlen(name) == 0)
		return NULL;

	rcu_read_lock();
	list_for_each_entry_rcu(ca, &tquic_cong_list, list) {
		if (strcmp(ca->name, name) == 0) {
			/* Try to get module reference */
			if (ca->owner && !try_module_get(ca->owner)) {
				rcu_read_unlock();
				return NULL;
			}
			rcu_read_unlock();
			return ca;
		}
	}
	rcu_read_unlock();

	return NULL;
}
EXPORT_SYMBOL_GPL(tquic_cong_find);

/*
 * tquic_cong_find_key - Find CC algorithm by precomputed key
 * @key: Hash key of the algorithm name
 *
 * Used for faster lookup when key is already computed.
 *
 * Return: Pointer to CC ops if found, NULL otherwise
 */
static struct tquic_cong_ops __maybe_unused *tquic_cong_find_key(u32 key)
{
	struct tquic_cong_ops *ca;

	rcu_read_lock();
	list_for_each_entry_rcu(ca, &tquic_cong_list, list) {
		if (ca->key == key) {
			if (ca->owner && !try_module_get(ca->owner)) {
				rcu_read_unlock();
				return NULL;
			}
			rcu_read_unlock();
			return ca;
		}
	}
	rcu_read_unlock();

	return NULL;
}

/*
 * tquic_cong_put - Release CC algorithm module reference
 * @ca: CC algorithm ops to release
 */
static void tquic_cong_put(struct tquic_cong_ops *ca)
{
	if (ca && ca->owner)
		module_put(ca->owner);
}

/*
 * tquic_cong_init_path_with_rtt - Initialize CC state for a path with RTT auto-selection
 * @path: Path to initialize CC for
 * @net: Network namespace for per-netns defaults and BBR threshold
 * @name: CC algorithm name (NULL for default, "auto" for RTT-based)
 * @rtt_us: Initial RTT estimate in microseconds (for auto-selection)
 *
 * This function supports BBR auto-selection for high-RTT paths:
 * - If name is "auto" and RTT >= bbr_rtt_threshold_ms, BBR is selected
 * - If name is "auto" and RTT < threshold, per-netns default is used
 * - If name is specified (not "auto"), that algorithm is used
 * - If name is NULL, per-netns default is used
 *
 * Return: 0 on success, -errno on failure
 */
int tquic_cong_init_path_with_rtt(struct tquic_path *path, struct net *net,
				  const char *name, u64 rtt_us)
{
	struct tquic_cong_ops *ca;
	void *cong_state;
	const char *algo_name;
	bool auto_select = false;

	if (!path)
		return -EINVAL;

	/* Handle auto-selection mode */
	if (name && strcmp(name, "auto") == 0) {
		auto_select = true;
		algo_name = tquic_cong_select_for_rtt(net, rtt_us);
		tquic_dbg("cc: auto-selected '%s' for path %u (rtt=%llu us)\n",
			 algo_name, path->path_id, rtt_us);
	} else if (name) {
		algo_name = name;
	} else if (net) {
		/* Use per-netns default */
		algo_name = tquic_cong_get_default_name(net);
	} else {
		algo_name = TQUIC_DEFAULT_CC_NAME;
	}

	/* Find the CC algorithm */
	ca = tquic_cong_find(algo_name);
	if (!ca) {
		/* Try to auto-load the module */
		request_module("tquic-cong-%s", algo_name);
		ca = tquic_cong_find(algo_name);
	}

	if (!ca) {
		tquic_warn("cc: algorithm '%s' not found, trying default\n",
			algo_name);
		/* Fall back to default */
		if (strcmp(algo_name, TQUIC_DEFAULT_CC_NAME) != 0) {
			ca = tquic_cong_find(TQUIC_DEFAULT_CC_NAME);
			if (!ca) {
				request_module("tquic-cong-%s",
					       TQUIC_DEFAULT_CC_NAME);
				ca = tquic_cong_find(TQUIC_DEFAULT_CC_NAME);
			}
		}
	}

	if (!ca) {
		tquic_warn("cc: no algorithm available for path %u\n",
			path->path_id);
		/* Initialize with default cwnd, no CC ops */
		path->cong = NULL;
		path->cong_ops = NULL;
		path->stats.cwnd = TQUIC_DEFAULT_CWND;
		return 0;  /* Not fatal - path can operate without CC */
	}

	/* Initialize per-path CC state */
	cong_state = ca->init(path);
	if (!cong_state) {
		tquic_cong_put(ca);
		tquic_warn("cc: failed to init %s for path %u\n",
			ca->name, path->path_id);
		return -ENOMEM;
	}

	/* Store CC state and ops in path */
	path->cong = cong_state;
	path->cong_ops = ca;

	/* Initialize cwnd from CC algorithm */
	if (ca->get_cwnd)
		path->stats.cwnd = ca->get_cwnd(cong_state);
	else
		path->stats.cwnd = TQUIC_DEFAULT_CWND;

	tquic_dbg("cc: initialized %s for path %u (cwnd=%u, auto=%d)\n",
		  ca->name, path->path_id, path->stats.cwnd, auto_select);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_cong_init_path_with_rtt);

/*
 * tquic_cong_init_path - Initialize CC state for a path
 * @path: Path to initialize CC for
 * @name: CC algorithm name (NULL for default)
 *
 * Return: 0 on success, -errno on failure
 */
int tquic_cong_init_path(struct tquic_path *path, const char *name)
{
	struct tquic_cong_ops *ca;
	void *cong_state;
	const char *algo_name;

	if (!path)
		return -EINVAL;

	/* Use default if no name specified */
	algo_name = name ? name : TQUIC_DEFAULT_CC_NAME;

	/* Find the CC algorithm */
	ca = tquic_cong_find(algo_name);
	if (!ca) {
		/* Try to auto-load the module */
		request_module("tquic-cong-%s", algo_name);
		ca = tquic_cong_find(algo_name);
	}

	if (!ca) {
		tquic_warn("cc: algorithm '%s' not found, trying default\n",
			algo_name);
		/* Fall back to default */
		if (strcmp(algo_name, TQUIC_DEFAULT_CC_NAME) != 0) {
			ca = tquic_cong_find(TQUIC_DEFAULT_CC_NAME);
			if (!ca) {
				request_module("tquic-cong-%s",
					       TQUIC_DEFAULT_CC_NAME);
				ca = tquic_cong_find(TQUIC_DEFAULT_CC_NAME);
			}
		}
	}

	if (!ca) {
		tquic_warn("cc: no algorithm available for path %u\n",
			path->path_id);
		/* Initialize with default cwnd, no CC ops */
		path->cong = NULL;
		path->cong_ops = NULL;
		path->stats.cwnd = TQUIC_DEFAULT_CWND;
		return 0;  /* Not fatal - path can operate without CC */
	}

	/* Initialize per-path CC state */
	cong_state = ca->init(path);
	if (!cong_state) {
		tquic_cong_put(ca);
		tquic_warn("cc: failed to init %s for path %u\n",
			ca->name, path->path_id);
		return -ENOMEM;
	}

	/* Store CC state and ops in path */
	path->cong = cong_state;
	path->cong_ops = ca;

	/* Initialize cwnd from CC algorithm */
	if (ca->get_cwnd)
		path->stats.cwnd = ca->get_cwnd(cong_state);
	else
		path->stats.cwnd = TQUIC_DEFAULT_CWND;

	tquic_dbg("cc: initialized %s for path %u (cwnd=%u)\n",
		  ca->name, path->path_id, path->stats.cwnd);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_cong_init_path);

/*
 * tquic_cong_release_path - Release CC state for a path
 * @path: Path whose CC state should be released
 */
void tquic_cong_release_path(struct tquic_path *path)
{
	struct tquic_cong_ops *ca;

	if (!path)
		return;

	ca = path->cong_ops;
	if (ca && path->cong) {
		/* Call CC algorithm's release function */
		if (ca->release)
			ca->release(path->cong);

		/* Release module reference */
		tquic_cong_put(ca);

		tquic_dbg("cc: released %s for path %u\n",
			  ca->name, path->path_id);
	}

	/* Clear path's CC state */
	path->cong = NULL;
	path->cong_ops = NULL;
}
EXPORT_SYMBOL_GPL(tquic_cong_release_path);

/*
 * tquic_cong_on_ack - Dispatch ACK event to path's CC algorithm
 * @path: Path that received the ACK
 * @bytes_acked: Number of bytes acknowledged
 * @rtt_us: RTT sample in microseconds
 *
 * This also resets the consecutive loss counter since a successful
 * ACK indicates the path is functioning.
 */
void tquic_cong_on_ack(struct tquic_path *path, u64 bytes_acked, u64 rtt_us)
{
	struct tquic_cong_ops *ca;

	if (!path)
		return;

	/* Reset consecutive loss counter on successful ACK */
	spin_lock_bh(&path->loss_tracker.lock);
	if (path->loss_tracker.consecutive_losses > 0) {
		tquic_dbg("cc: path %u loss counter reset on ACK\n",
			 path->path_id);
		path->loss_tracker.consecutive_losses = 0;
	}
	spin_unlock_bh(&path->loss_tracker.lock);

	ca = path->cong_ops;
	if (ca && ca->on_ack && path->cong) {
		ca->on_ack(path->cong, bytes_acked, rtt_us);

		/* Update path stats from CC state */
		if (ca->get_cwnd)
			path->stats.cwnd = ca->get_cwnd(path->cong);
	}

	/* Update pacing rate after CC state change */
	if (path->conn && path->conn->sk)
		tquic_update_pacing(path->conn->sk, path);
}
EXPORT_SYMBOL_GPL(tquic_cong_on_ack);

/*
 * tquic_cong_on_loss - Dispatch loss event to path's CC algorithm
 * @path: Path that experienced loss
 * @bytes_lost: Number of bytes detected as lost
 *
 * This also tracks consecutive losses for path degradation detection.
 * Per RESEARCH.md: "5 consecutive lost packets in same round" triggers
 * path degradation and failover to other paths.
 *
 * A "round" is approximated by the number of packets that can fit in
 * one cwnd. When tx_packets advances by cwnd/mss, we start a new round.
 */
void tquic_cong_on_loss(struct tquic_path *path, u64 bytes_lost)
{
	struct tquic_cong_ops *ca;
	struct tquic_connection *conn;
	int threshold;
	bool degraded = false;
	u32 packets_per_cwnd;

	if (!path)
		return;

	conn = READ_ONCE(path->conn);

	/* Track consecutive losses for path degradation under path-local lock */
	spin_lock_bh(&path->loss_tracker.lock);

	/* Calculate packets per cwnd (for round detection) */
	packets_per_cwnd = (path->stats.cwnd ?: TQUIC_DEFAULT_CWND) / 1200;
	if (packets_per_cwnd == 0)
		packets_per_cwnd = 10;

	/* Check if this is in the same round */
	if (path->stats.tx_packets > path->loss_tracker.round_start_tx + packets_per_cwnd) {
		/* New round - reset counter */
		path->loss_tracker.consecutive_losses = 0;
		path->loss_tracker.round_start_tx = path->stats.tx_packets;
		tquic_dbg("cc: path %u new loss round, tx=%llu\n",
			 path->path_id, path->stats.tx_packets);
	}

	/* Count this loss */
	path->loss_tracker.consecutive_losses++;
	path->loss_tracker.last_loss_tx = path->stats.tx_packets;

	tquic_dbg("cc: loss on path %u, consecutive=%u (round_start=%llu)\n",
		 path->path_id, path->loss_tracker.consecutive_losses,
		 path->loss_tracker.round_start_tx);

	/* Check for degradation threshold */
	threshold = tquic_get_path_degrade_threshold(path);
	if (path->loss_tracker.consecutive_losses >= threshold) {
		tquic_warn("cc: path %u degraded after %u consecutive losses\n",
			path->path_id, path->loss_tracker.consecutive_losses);
		path->loss_tracker.consecutive_losses = 0;
		degraded = true;
	}
	spin_unlock_bh(&path->loss_tracker.lock);

	/* Signal path manager outside the lock */
	if (degraded && conn)
		tquic_bond_path_failed(conn, path);

	/* Call CC's on_loss */
	ca = path->cong_ops;
	if (ca && ca->on_loss && path->cong) {
		ca->on_loss(path->cong, bytes_lost);

		/* Update path stats from CC state */
		if (ca->get_cwnd)
			path->stats.cwnd = ca->get_cwnd(path->cong);
	}
}
EXPORT_SYMBOL_GPL(tquic_cong_on_loss);

/*
 * =============================================================================
 * Persistent Congestion Detection (RFC 9002 Section 7.6)
 * =============================================================================
 *
 * When packets spanning the persistent congestion period are all lost,
 * the sender declares persistent congestion and resets cwnd to minimum.
 *
 * This is integrated with loss detection - when declaring losses after
 * a PTO timeout, check if persistent congestion has occurred.
 */
#include "persistent_cong.h"

/*
 * tquic_cong_on_persistent_congestion - Handle persistent congestion event
 * @path: Path that experienced persistent congestion
 * @info: Persistent congestion info (min_cwnd, timestamps, etc.)
 *
 * Called when persistent congestion is detected on a path.
 * Dispatches to the CC algorithm's on_persistent_congestion callback.
 *
 * Per RFC 9002 Section 7.6:
 * "When persistent congestion is established, the sender's congestion
 * window MUST be reduced to the minimum congestion window."
 */
void tquic_cong_on_persistent_congestion(struct tquic_path *path,
					 struct tquic_persistent_cong_info *info)
{
	struct tquic_cong_ops *ca;

	if (!path || !info)
		return;

	ca = path->cong_ops;

	/* Call CC algorithm's persistent congestion handler */
	if (ca && ca->on_persistent_congestion && path->cong) {
		ca->on_persistent_congestion(path->cong, info);

		/* Update path stats from CC state */
		if (ca->get_cwnd)
			path->stats.cwnd = ca->get_cwnd(path->cong);

		tquic_warn("cc: persistent congestion on path %u, new cwnd=%u\n",
			   path->path_id, path->stats.cwnd);
	} else {
		/*
		 * Default behavior if CC doesn't implement callback:
		 * Reset cwnd to minimum
		 */
		path->stats.cwnd = (u32)info->min_cwnd;
		tquic_warn("cc: persistent congestion on path %u (default), cwnd=%u\n",
			   path->path_id, path->stats.cwnd);
	}

	/* Update pacing rate after persistent congestion */
	if (path->conn && path->conn->sk)
		tquic_update_pacing(path->conn->sk, path);
}
EXPORT_SYMBOL_GPL(tquic_cong_on_persistent_congestion);

/*
 * tquic_cong_check_persistent_congestion - Check for and handle persistent congestion
 * @path: Path to check
 * @lost_packets: Array of lost packet information
 * @num_lost: Number of lost packets
 * @smoothed_rtt: Smoothed RTT in microseconds
 * @rtt_var: RTT variance in microseconds
 *
 * Called from loss detection after declaring packet losses.
 * Checks if the lost packets span the persistent congestion period
 * and if so, triggers persistent congestion handling.
 *
 * Return: true if persistent congestion was detected, false otherwise
 */
bool tquic_cong_check_persistent_congestion(struct tquic_path *path,
					    struct tquic_lost_packet *lost_packets,
					    int num_lost,
					    u64 smoothed_rtt, u64 rtt_var)
{
	struct tquic_persistent_cong_state pc_state;
	struct tquic_persistent_cong_info info;
	struct net *net = NULL;
	ktime_t earliest = ns_to_ktime(LLONG_MAX);
	ktime_t latest = ns_to_ktime(0);
	int i;

	if (!path || !lost_packets || num_lost < 2)
		return false;

	/* Get network namespace */
	if (path->conn) {
		struct sock *sk = READ_ONCE(path->conn->sk);

		if (sk)
			net = sock_net(sk);
	}

	/* Initialize persistent congestion state from current RTT */
	tquic_persistent_cong_init(&pc_state);
	tquic_persistent_cong_update_rtt(&pc_state, smoothed_rtt, rtt_var);

	/* Check for persistent congestion */
	if (!tquic_check_persistent_cong(&pc_state, lost_packets, num_lost, net))
		return false;

	/*
	 * Persistent congestion detected - find earliest and latest
	 * ACK-eliciting packet times for the info structure
	 */
	for (i = 0; i < num_lost; i++) {
		if (!lost_packets[i].ack_eliciting)
			continue;

		if (ktime_before(lost_packets[i].send_time, earliest))
			earliest = lost_packets[i].send_time;
		if (ktime_after(lost_packets[i].send_time, latest))
			latest = lost_packets[i].send_time;
	}

	/* Build info structure for CC callback */
	info.min_cwnd = tquic_min_cwnd(TQUIC_DEFAULT_MAX_DATAGRAM_SIZE);
	info.max_datagram_size = TQUIC_DEFAULT_MAX_DATAGRAM_SIZE;
	info.earliest_send_time = earliest;
	info.latest_send_time = latest;
	info.duration_us = ktime_us_delta(latest, earliest);

	/* Handle persistent congestion */
	tquic_cong_on_persistent_congestion(path, &info);

	return true;
}
EXPORT_SYMBOL_GPL(tquic_cong_check_persistent_congestion);

/*
 * tquic_cong_on_rtt - Dispatch RTT update to path's CC algorithm
 * @path: Path with RTT update
 * @rtt_us: RTT sample in microseconds
 */
void tquic_cong_on_rtt(struct tquic_path *path, u64 rtt_us)
{
	struct tquic_cong_ops *ca;

	if (!path)
		return;

	ca = path->cong_ops;
	if (ca && ca->on_rtt_update && path->cong)
		ca->on_rtt_update(path->cong, rtt_us);
}
EXPORT_SYMBOL_GPL(tquic_cong_on_rtt);

/*
 * tquic_cong_get_cwnd - Get current cwnd from path's CC algorithm
 * @path: Path to query
 *
 * Return: Current congestion window in bytes
 */
u64 tquic_cong_get_cwnd(struct tquic_path *path)
{
	struct tquic_cong_ops *ca;

	if (!path)
		return TQUIC_DEFAULT_CWND;

	ca = path->cong_ops;
	if (ca && ca->get_cwnd && path->cong)
		return ca->get_cwnd(path->cong);

	return path->stats.cwnd ?: TQUIC_DEFAULT_CWND;
}
EXPORT_SYMBOL_GPL(tquic_cong_get_cwnd);

/*
 * Minimum pacing rate: 1 MSS per 10ms = 120KB/s
 * This prevents pacing from becoming a bottleneck on very slow paths.
 */
#define TQUIC_MIN_PACING_RATE	120000

/*
 * tquic_cong_get_pacing_rate - Get pacing rate for a path (bytes/sec)
 * @path: Path to query
 *
 * Uses bandwidth estimation when available (BBR-style from CC algorithm),
 * falls back to cwnd/RTT approximation when CC doesn't provide pacing.
 *
 * Return: Current pacing rate in bytes/sec
 */
u64 tquic_cong_get_pacing_rate(struct tquic_path *path)
{
	struct tquic_cong_ops *ca;
	u64 rate = 0;

	if (!path)
		return TQUIC_MIN_PACING_RATE;

	/* First try CC-provided pacing rate (bandwidth-based) */
	ca = path->cong_ops;
	if (ca && ca->get_pacing_rate && path->cong)
		rate = ca->get_pacing_rate(path->cong);

	/* Fallback: cwnd / RTT approximation */
	if (rate == 0 && path->stats.rtt_smoothed > 0) {
		u64 cwnd = path->stats.cwnd ?: (10 * 1200);  /* Default 10 packets */

		/* rate = cwnd / RTT (in bytes/sec)
		 * cwnd is in bytes, RTT is in microseconds
		 * rate = cwnd * USEC_PER_SEC / rtt_us
		 *
		 * Cap cwnd before multiplication to prevent u64 overflow.
		 */
		cwnd = min_t(u64, cwnd, U64_MAX / USEC_PER_SEC);
		rate = div64_u64(cwnd * USEC_PER_SEC, path->stats.rtt_smoothed);
	}

	/* Enforce minimum pacing rate */
	if (rate < TQUIC_MIN_PACING_RATE)
		rate = TQUIC_MIN_PACING_RATE;

	return rate;
}
EXPORT_SYMBOL_GPL(tquic_cong_get_pacing_rate);

/*
 * tquic_cong_on_packet_sent - Notify CC of packet transmission
 * @path: Path the packet was sent on
 * @bytes: Number of bytes sent
 * @sent_time: Time the packet was sent
 */
static void tquic_cong_on_packet_sent(struct tquic_path *path, u64 bytes,
				      ktime_t sent_time)
{
	struct tquic_cong_ops *ca;

	if (!path)
		return;

	ca = path->cong_ops;
	if (ca && ca->on_packet_sent && path->cong)
		ca->on_packet_sent(path->cong, bytes, sent_time);
}

/*
 * =============================================================================
 * Per-Network Namespace CC Configuration
 * =============================================================================
 */

/*
 * tquic_cong_set_default - Set default CC algorithm for a network namespace
 * @net: Network namespace
 * @name: CC algorithm name
 *
 * Return: 0 on success, -ENOENT if algorithm not found, -EBUSY if module fails
 */
int tquic_cong_set_default(struct net *net, const char *name)
{
	struct tquic_cong_ops *ca, *old_ca;

	if (!net || !name)
		return -EINVAL;

	/* Find and get reference to the CC algorithm */
	ca = tquic_cong_find(name);
	if (!ca) {
		/* Try to load the module */
		request_module("tquic-cong-%s", name);
		ca = tquic_cong_find(name);
		if (!ca) {
			tquic_warn("cc: algorithm '%s' not found\n", name);
			return -ENOENT;
		}
	}

	{
		struct tquic_net *tn = tquic_pernet(net);
		if (!tn)
			return -EINVAL;

		/* Store name in netns buffer */
		strscpy(tn->cc_name, name, TQUIC_NET_CC_NAME_MAX);

		/* Swap default CC algorithm (RCU protected) */
		spin_lock(&tquic_cong_list_lock);
		old_ca = rcu_dereference_protected(tn->default_cong,
						   lockdep_is_held(&tquic_cong_list_lock));
		rcu_assign_pointer(tn->default_cong, ca);
		spin_unlock(&tquic_cong_list_lock);
	}

	/* Wait for any RCU readers to finish using the old algorithm */
	if (old_ca)
		synchronize_rcu();

	/* Release old CC algorithm's module reference */
	if (old_ca && old_ca->owner)
		module_put(old_ca->owner);

	tquic_dbg("cc: netns default CC set to '%s'\n", name);
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_cong_set_default);

/*
 * tquic_cong_get_default - Get default CC algorithm for a network namespace
 * @net: Network namespace
 *
 * Return: Pointer to default CC ops, or NULL if none set
 */
struct tquic_cong_ops *tquic_cong_get_default(struct net *net)
{
	struct tquic_net *tn;

	if (!net)
		return NULL;

	tn = tquic_pernet(net);
	if (!tn)
		return NULL;

	return rcu_dereference(tn->default_cong);
}
EXPORT_SYMBOL_GPL(tquic_cong_get_default);

/*
 * tquic_cong_get_default_name - Get default CC algorithm name for a netns
 * @net: Network namespace
 *
 * Return: CC algorithm name string, or "cubic" as fallback
 */
const char *tquic_cong_get_default_name(struct net *net)
{
	struct tquic_cong_ops *ca;
	struct tquic_net *tn;

	if (!net)
		return TQUIC_DEFAULT_CC_NAME;

	tn = tquic_pernet(net);
	if (!tn)
		return TQUIC_DEFAULT_CC_NAME;

	/*
	 * CF-132: Return the per-netns cc_name buffer which is always
	 * valid for the lifetime of the netns. The previous code
	 * returned ca->name from an RCU-protected algorithm struct,
	 * which could be freed after rcu_read_unlock() if the CC
	 * module was unloaded.
	 *
	 * tquic_cong_set_default() always populates tn->cc_name
	 * before setting tn->default_cong, so cc_name is authoritative.
	 * As a safety fallback, if cc_name is empty but an algorithm
	 * is registered, copy its name to the stable buffer.
	 */
	if (tn->cc_name[0])
		return tn->cc_name;

	rcu_read_lock();
	ca = rcu_dereference(tn->default_cong);
	if (ca && ca->name) {
		strscpy(tn->cc_name, ca->name, TQUIC_NET_CC_NAME_MAX);
		rcu_read_unlock();
		return tn->cc_name;
	}
	rcu_read_unlock();

	return TQUIC_DEFAULT_CC_NAME;
}
EXPORT_SYMBOL_GPL(tquic_cong_get_default_name);

/*
 * tquic_cong_is_bbr_preferred - Check if BBR should be used for RTT
 * @net: Network namespace
 * @rtt_us: Path RTT in microseconds
 *
 * Return: true if RTT exceeds the BBR auto-selection threshold
 */
bool tquic_cong_is_bbr_preferred(struct net *net, u64 rtt_us)
{
	struct tquic_net *tn;
	u32 threshold_us;

	if (!net)
		return false;

	tn = tquic_pernet(net);
	if (!tn)
		return false;

	/* Convert threshold from ms to us */
	threshold_us = tn->bbr_rtt_threshold_ms * 1000;

	/* BBR is preferred for high-RTT paths */
	return rtt_us >= threshold_us;
}
EXPORT_SYMBOL_GPL(tquic_cong_is_bbr_preferred);

/*
 * tquic_cong_select_for_rtt - Select CC algorithm based on RTT
 * @net: Network namespace for configuration
 * @rtt_us: Path RTT in microseconds
 *
 * Return: CC algorithm name to use for this path
 */
const char *tquic_cong_select_for_rtt(struct net *net, u64 rtt_us)
{
	struct tquic_net *tn;

	/* If BBR is preferred for high RTT and threshold is set */
	if (net) {
		tn = tquic_pernet(net);
		if (tn && tn->bbr_rtt_threshold_ms > 0 &&
		    tquic_cong_is_bbr_preferred(net, rtt_us)) {
			return "bbr";
		}
	}

	/* Otherwise use the per-netns default */
	return tquic_cong_get_default_name(net);
}
EXPORT_SYMBOL_GPL(tquic_cong_select_for_rtt);

/*
 * =============================================================================
 * Coupled CC Coordination Layer
 * =============================================================================
 *
 * These functions enable connection-level coupled congestion control using
 * OLIA/LIA/BALIA algorithms. Coupled CC ensures TCP-fairness at shared
 * bottlenecks while utilizing full aggregate bandwidth.
 *
 * Per CONTEXT.md: "Coupled CC is opt-in via sysctl/sockopt (per-path CC by default)"
 * Per CONTEXT.md: "Loss on one path affects only that path's CWND"
 * Per RESEARCH.md: "OLIA as default" coupled algorithm
 */

/*
 * tquic_cong_enable_coupling - Enable coupled CC for a connection
 * @conn: Connection to enable coupling on
 * @algo: Coupled algorithm (TQUIC_COUPLED_OLIA, LIA, or BALIA)
 *
 * Creates coupled CC state and attaches all existing paths.
 * OLIA is the default per RESEARCH.md recommendation.
 *
 * Return: 0 on success, -errno on failure
 */
int tquic_cong_enable_coupling(struct tquic_connection *conn,
			       enum tquic_coupled_algo algo)
{
	struct tquic_coupled_state *state;
	struct tquic_path *path;
	int ret;

	if (!conn)
		return -EINVAL;

	/* Already enabled? */
	if (conn->coupled_cc) {
		tquic_dbg("cc: coupled CC already enabled\n");
		return -EEXIST;
	}

	/* Use OLIA as default if unspecified (per RESEARCH.md) */
	if (algo == TQUIC_COUPLED_NONE)
		algo = TQUIC_COUPLED_OLIA;

	/* Create coupled state */
	state = tquic_coupled_create(conn, algo);
	if (!state)
		return -ENOMEM;

	/* Attach all existing paths */
	spin_lock_bh(&conn->paths_lock);
	list_for_each_entry(path, &conn->paths, list) {
		if (path->state == TQUIC_PATH_ACTIVE ||
		    path->state == TQUIC_PATH_VALIDATED) {
			ret = tquic_coupled_attach_path(state, path);
			if (ret < 0) {
				tquic_warn("cc: failed to attach path %u: %d\n",
					path->path_id, ret);
				/* Continue with other paths */
			}
		}
	}
	spin_unlock_bh(&conn->paths_lock);

	/* Store coupled state in connection */
	conn->coupled_cc = state;

	tquic_info("cc: enabled coupled CC (algo=%d) for connection\n", algo);
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_cong_enable_coupling);

/*
 * tquic_cong_disable_coupling - Disable coupled CC for a connection
 * @conn: Connection to disable coupling on
 *
 * Detaches all paths from coupled state and destroys it.
 * Paths continue using their individual CC algorithms.
 */
void tquic_cong_disable_coupling(struct tquic_connection *conn)
{
	struct tquic_coupled_state *state;
	struct tquic_path *path;

	if (!conn)
		return;

	state = conn->coupled_cc;
	if (!state) {
		tquic_dbg("cc: coupled CC not enabled\n");
		return;
	}

	/* Detach all paths */
	spin_lock_bh(&conn->paths_lock);
	list_for_each_entry(path, &conn->paths, list) {
		tquic_coupled_detach_path(state, path);
	}
	spin_unlock_bh(&conn->paths_lock);

	/* Clear connection reference and destroy state */
	conn->coupled_cc = NULL;
	tquic_coupled_destroy(state);

	tquic_info("cc: disabled coupled CC for connection\n");
}
EXPORT_SYMBOL_GPL(tquic_cong_disable_coupling);

/*
 * tquic_cong_is_coupling_enabled - Check if coupled CC is enabled
 * @conn: Connection to check
 *
 * Return: true if coupled CC is active, false otherwise
 */
bool tquic_cong_is_coupling_enabled(struct tquic_connection *conn)
{
	if (!conn)
		return false;

	return conn->coupled_cc != NULL;
}
EXPORT_SYMBOL_GPL(tquic_cong_is_coupling_enabled);

/*
 * =============================================================================
 * ECN Support
 * =============================================================================
 *
 * ECN (Explicit Congestion Notification) provides early congestion signals
 * via IP header marking rather than packet loss.
 *
 * Per CONTEXT.md: "ECN support: available but off by default (enable via sysctl)"
 */

/*
 * tquic_cong_on_ecn - Dispatch ECN CE event to path's CC algorithm
 * @path: Path that received ECN CE marking
 * @ecn_ce_count: Number of ECN CE marks reported in ACK
 *
 * ECN CE (Congestion Experienced) marks indicate congestion without loss.
 * Per RFC 9002 Section 7.1, each increase in the ECN-CE counter is a
 * signal of congestion that the sender should respond to.
 *
 * Per CONTEXT.md: "Loss on one path reduces only that path's CWND"
 * This applies to ECN as well - ECN on one path affects only that path.
 *
 * This function dispatches to the CC algorithm's on_ecn callback if
 * available, otherwise falls back to on_loss with estimated bytes.
 */
void tquic_cong_on_ecn(struct tquic_path *path, u64 ecn_ce_count)
{
	struct tquic_cong_ops *ca;
	struct net *net = NULL;

	if (!path || ecn_ce_count == 0)
		return;

	/* Check if ECN is enabled at netns level */
	if (path->conn && path->conn->sk) {
		struct tquic_net *tn;

		net = sock_net(path->conn->sk);
		tn = net ? tquic_pernet(net) : NULL;
		if (tn && !tn->ecn_enabled) {
			/* ECN disabled for this namespace, ignore CE marks */
			tquic_dbg("cc: ECN CE ignored (ecn_enabled=0)\n");
			return;
		}
	}

	ca = path->cong_ops;
	if (!ca || !path->cong)
		return;

	/*
	 * Per RFC 9002 Section 7.1:
	 * "Each increase in the ECN-CE counter is a signal of congestion.
	 * The sender SHOULD reduce the congestion window using the approach
	 * described in Section 7.3 or an equivalent approach."
	 *
	 * Prefer the dedicated on_ecn callback if available, as it allows
	 * CC algorithms to implement ECN-specific responses (e.g., different
	 * reduction factors, different timing constraints).
	 *
	 * Fall back to on_loss if on_ecn is not implemented.
	 */
	if (ca->on_ecn) {
		/* Use dedicated ECN handler */
		ca->on_ecn(path->cong, ecn_ce_count);

		/* Update path stats from CC state */
		if (ca->get_cwnd)
			path->stats.cwnd = ca->get_cwnd(path->cong);

		tquic_dbg("cc: ECN CE on path %u via on_ecn, ce_count=%llu, new_cwnd=%u\n",
			 path->path_id, ecn_ce_count, path->stats.cwnd);
	} else if (ca->on_loss) {
		/*
		 * Fallback: Treat ECN CE similar to loss.
		 * Estimate 1200 bytes (MTU) per CE mark for CWND reduction.
		 */
		u64 ecn_bytes;

		/* CF-337: Guard against multiplication overflow */
		if (check_mul_overflow(ecn_ce_count, (u64)1200, &ecn_bytes))
			ecn_bytes = U64_MAX;
		ca->on_loss(path->cong, ecn_bytes);

		/* Update path stats from CC state */
		if (ca->get_cwnd)
			path->stats.cwnd = ca->get_cwnd(path->cong);

		tquic_dbg("cc: ECN CE on path %u via on_loss fallback, ce_count=%llu, new_cwnd=%u\n",
			 path->path_id, ecn_ce_count, path->stats.cwnd);
	}

	/* Update pacing rate after congestion response */
	if (path->conn && path->conn->sk)
		tquic_update_pacing(path->conn->sk, path);
}
EXPORT_SYMBOL_GPL(tquic_cong_on_ecn);

MODULE_DESCRIPTION("TQUIC Congestion Control Framework");
MODULE_LICENSE("GPL");
