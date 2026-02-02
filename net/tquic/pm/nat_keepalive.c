// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC NAT Keepalive Implementation
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Implements NAT keepalive optimization per RFC 9308 Section 3.5.
 *
 * RFC 9308 states: "QUIC endpoints that want to keep NAT bindings alive
 * can send keepalive packets. A PING frame is a small keepalive that
 * triggers an ACK from the peer, thereby keeping the NAT binding open."
 *
 * This implementation provides:
 * - Minimal keepalive packets (single PING frame = 1 byte frame overhead)
 * - Adaptive interval estimation to match actual NAT timeout
 * - Per-path keepalive state for multipath support
 * - Power-aware operation for mobile devices
 * - Integration with path manager timer infrastructure
 *
 * Battery Impact Considerations:
 * - Each keepalive wakes the radio for mobile networks
 * - Batching keepalives with other traffic reduces wake-ups
 * - Longer intervals save battery but risk NAT timeout
 * - Mobile-aware mode detects cellular vs WiFi and adjusts
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <linux/jiffies.h>
#include <linux/random.h>
#include <linux/netdevice.h>
#include <net/sock.h>
#include <net/tquic.h>

#include "nat_keepalive.h"
#include "../protocol.h"

/*
 * =============================================================================
 * Global State
 * =============================================================================
 */

/* Global statistics */
struct tquic_nat_keepalive_stats tquic_nat_keepalive_global_stats;
EXPORT_SYMBOL_GPL(tquic_nat_keepalive_global_stats);

/* Workqueue for deferred keepalive operations */
static struct workqueue_struct *tquic_nat_keepalive_wq;

/*
 * =============================================================================
 * Internal Helper Functions
 * =============================================================================
 */

/**
 * tquic_nat_keepalive_get_state - Get keepalive state from path
 * @path: Path to get state from
 *
 * Return: Keepalive state pointer or NULL if not initialized
 */
static inline struct tquic_nat_keepalive_state *
tquic_nat_keepalive_get_state(struct tquic_path *path)
{
	if (!path)
		return NULL;
	return path->nat_keepalive_state;
}

/**
 * tquic_nat_keepalive_should_send - Check if keepalive should be sent
 * @state: Keepalive state
 *
 * Determines whether a keepalive should be sent based on last activity
 * and current interval configuration.
 *
 * Return: true if keepalive should be sent, false otherwise
 */
static bool tquic_nat_keepalive_should_send(struct tquic_nat_keepalive_state *state)
{
	ktime_t now = ktime_get();
	s64 idle_ms;
	s64 since_keepalive_ms;

	if (!state || !state->initialized || state->suspended)
		return false;

	if (!state->config || !state->config->enabled)
		return false;

	/* Check if we're already waiting for an ACK */
	if (state->pending_ack)
		return false;

	/* Calculate idle time since last activity */
	idle_ms = ktime_ms_delta(now, state->last_activity);

	/* Calculate time since last keepalive */
	since_keepalive_ms = ktime_ms_delta(now, state->last_keepalive);

	/*
	 * Send keepalive if:
	 * 1. Path has been idle for >= 75% of the interval, AND
	 * 2. Time since last keepalive >= interval
	 *
	 * The 75% threshold allows some margin while avoiding
	 * sending redundant keepalives on active paths.
	 */
	if (idle_ms >= (state->current_interval_ms * 3) / 4 &&
	    since_keepalive_ms >= state->current_interval_ms)
		return true;

	return false;
}

/**
 * tquic_nat_keepalive_adaptive_adjust - Adjust interval based on feedback
 * @state: Keepalive state
 * @success: Whether the last keepalive was successful (ACKed)
 *
 * Implements the adaptive interval algorithm:
 * - On success: Gradually increase interval (NAT may have longer timeout)
 * - On failure: Decrease interval (NAT has shorter timeout than expected)
 *
 * This helps find the optimal interval that keeps NAT alive while
 * minimizing unnecessary traffic.
 */
static void tquic_nat_keepalive_adaptive_adjust(
	struct tquic_nat_keepalive_state *state,
	bool success)
{
	struct tquic_nat_keepalive_config *config;
	u32 new_interval;

	if (!state || !state->config || !state->config->adaptive_mode)
		return;

	config = state->config;

	spin_lock_bh(&state->lock);

	if (success) {
		state->consecutive_failures = 0;
		state->consecutive_successes++;

		/* Increase interval after threshold consecutive successes */
		if (state->consecutive_successes >= TQUIC_NAT_KEEPALIVE_STABILITY_THRESHOLD) {
			new_interval = state->current_interval_ms *
				       TQUIC_NAT_KEEPALIVE_PROBE_MULTIPLIER;

			if (new_interval > config->max_interval_ms)
				new_interval = config->max_interval_ms;

			if (new_interval != state->current_interval_ms) {
				state->current_interval_ms = new_interval;
				state->estimated_timeout_ms = new_interval * 2;
				atomic64_inc(&tquic_nat_keepalive_global_stats.adaptive_increases);

				pr_debug("tquic: NAT keepalive interval increased to %u ms (path %u)\n",
					 new_interval, state->path->path_id);
			}

			state->consecutive_successes = 0;
		}
	} else {
		state->consecutive_successes = 0;
		state->consecutive_failures++;

		/* Decrease interval after failure threshold */
		if (state->consecutive_failures >= TQUIC_NAT_KEEPALIVE_FAILURE_THRESHOLD) {
			new_interval = state->current_interval_ms /
				       TQUIC_NAT_KEEPALIVE_BACKOFF_DIVISOR;

			if (new_interval < config->min_interval_ms)
				new_interval = config->min_interval_ms;

			if (new_interval != state->current_interval_ms) {
				state->current_interval_ms = new_interval;
				state->estimated_timeout_ms = new_interval * 2;
				atomic64_inc(&tquic_nat_keepalive_global_stats.adaptive_decreases);

				pr_warn("tquic: NAT keepalive interval decreased to %u ms (path %u)\n",
					new_interval, state->path->path_id);
			}

			state->consecutive_failures = 0;
		}
	}

	spin_unlock_bh(&state->lock);
}

/**
 * tquic_nat_keepalive_is_mobile_network - Check if path uses mobile network
 * @path: Path to check
 *
 * Detects if the path is over a mobile/cellular network for power optimization.
 *
 * Return: true if mobile network, false otherwise
 */
static bool tquic_nat_keepalive_is_mobile_network(struct tquic_path *path)
{
	struct net_device *dev;

	if (!path || !path->dev)
		return false;

	dev = path->dev;

	/*
	 * Heuristic: Check device type for cellular indicators.
	 * Mobile devices typically use ARPHRD_RAWIP or similar.
	 * WiFi uses ARPHRD_ETHER.
	 */
	if (dev->type != ARPHRD_ETHER)
		return true;

	/* Check device name patterns for known mobile interfaces */
	if (strncmp(dev->name, "rmnet", 5) == 0 ||  /* Qualcomm */
	    strncmp(dev->name, "ccmni", 5) == 0 ||  /* MediaTek */
	    strncmp(dev->name, "wwan", 4) == 0)     /* Generic WWAN */
		return true;

	return false;
}

/**
 * tquic_nat_keepalive_calc_interval - Calculate actual keepalive interval
 * @state: Keepalive state
 *
 * Calculates the interval considering power mode and network type.
 *
 * Return: Interval in milliseconds
 */
static u32 tquic_nat_keepalive_calc_interval(struct tquic_nat_keepalive_state *state)
{
	u32 interval;
	bool is_mobile;

	if (!state || !state->config)
		return TQUIC_NAT_KEEPALIVE_DEFAULT_INTERVAL_MS;

	interval = state->current_interval_ms;
	is_mobile = state->config->mobile_aware &&
		    tquic_nat_keepalive_is_mobile_network(state->path);

	switch (state->config->power_mode) {
	case TQUIC_NAT_KEEPALIVE_POWER_SAVING:
		/* Increase interval by 50% for power saving */
		if (is_mobile)
			interval = (interval * 3) / 2;
		break;

	case TQUIC_NAT_KEEPALIVE_POWER_AGGRESSIVE:
		/* Decrease interval by 25% for reliability */
		interval = (interval * 3) / 4;
		break;

	case TQUIC_NAT_KEEPALIVE_POWER_NORMAL:
	default:
		/* Use calculated interval as-is */
		break;
	}

	/* Clamp to allowed range */
	if (interval < state->config->min_interval_ms)
		interval = state->config->min_interval_ms;
	if (interval > state->config->max_interval_ms)
		interval = state->config->max_interval_ms;

	return interval;
}

/**
 * tquic_nat_keepalive_build_ping_packet - Build minimal PING packet
 * @conn: Connection
 * @path: Path to send on
 * @pn: Output - assigned packet number
 *
 * Builds a minimal QUIC packet containing only a PING frame.
 * Per RFC 9000, PING is type 0x01 with no additional data (1 byte total).
 *
 * The packet consists of:
 * - Short header (~5-21 bytes depending on CID length)
 * - PING frame (1 byte)
 * - AEAD tag (16 bytes)
 *
 * Total: ~22-38 bytes, minimal possible ACK-eliciting packet.
 *
 * Return: sk_buff with packet data, or NULL on failure
 */
static struct sk_buff *tquic_nat_keepalive_build_ping_packet(
	struct tquic_connection *conn,
	struct tquic_path *path,
	u64 *pn)
{
	struct sk_buff *skb;
	u8 *p;
	size_t header_len;
	size_t total_len;
	u8 pn_len = 2;  /* Use 2-byte packet number for keepalive */
	u8 dcid_len;

	if (!conn || !path)
		return NULL;

	/* Get destination CID length */
	dcid_len = path->remote_cid.len;

	/*
	 * Short header format:
	 * - Header Form (0) + Fixed Bit (1) + Spin Bit (1) + Reserved (2) +
	 *   Key Phase (1) + PN Length (2) = 1 byte
	 * - Destination CID (0-20 bytes)
	 * - Packet Number (1-4 bytes)
	 */
	header_len = 1 + dcid_len + pn_len;

	/* Total: header + PING frame (1 byte) + AEAD tag (16 bytes) */
	total_len = header_len + 1 + 16;

	/* Allocate skb */
	skb = alloc_skb(total_len + 64, GFP_ATOMIC);  /* +64 for headroom */
	if (!skb)
		return NULL;

	skb_reserve(skb, 32);  /* Reserve headroom for lower layers */
	p = skb_put(skb, total_len - 16);  /* Exclude AEAD tag for now */

	/* Get next packet number atomically */
	*pn = atomic64_inc_return(&conn->pkt_num_tx);

	/* Build short header */
	p[0] = 0x40;  /* Fixed bit set, header form 0 (short) */
	p[0] |= (pn_len - 1) & 0x03;  /* PN length encoding */

	/* Copy destination CID */
	if (dcid_len > 0)
		memcpy(p + 1, path->remote_cid.id, dcid_len);

	/* Encode packet number (truncated, 2 bytes) */
	p[1 + dcid_len] = (*pn >> 8) & 0xff;
	p[1 + dcid_len + 1] = *pn & 0xff;

	/* PING frame type (0x01) - just one byte, no payload */
	p[header_len] = 0x01;

	/*
	 * Note: Actual encryption happens in tquic_output.c before transmission.
	 * We leave space for the 16-byte AEAD tag but don't fill it here.
	 * The encryption layer will:
	 * 1. Encrypt the payload (PING frame)
	 * 2. Append AEAD tag
	 * 3. Apply header protection
	 *
	 * Packet metadata (path, packet number, ack-eliciting flag) is passed
	 * separately to the output function or stored in skb->cb[] directly.
	 */

	return skb;
}

/*
 * =============================================================================
 * Timer Callback
 * =============================================================================
 */

/**
 * tquic_nat_keepalive_timer_fn - Timer callback for keepalive
 * @t: Timer that fired
 *
 * Called when the keepalive timer expires. Checks if a keepalive
 * should actually be sent (may have had activity since timer was armed).
 */
static void tquic_nat_keepalive_timer_fn(struct timer_list *t)
{
	struct tquic_nat_keepalive_state *state =
		from_timer(state, t, timer);

	if (!state || !state->initialized)
		return;

	/* Check if we should send keepalive */
	if (tquic_nat_keepalive_should_send(state)) {
		/* Send keepalive (may defer to workqueue if needed) */
		tquic_nat_keepalive_send(state);
	}

	/* Reschedule timer */
	tquic_nat_keepalive_schedule(state);
}

/*
 * =============================================================================
 * Public API Implementation
 * =============================================================================
 */

int tquic_nat_keepalive_init(struct tquic_path *path,
			     struct tquic_connection *conn)
{
	struct tquic_nat_keepalive_state *state;
	struct tquic_nat_keepalive_config *config;

	if (!path || !conn)
		return -EINVAL;

	/* Check if already initialized */
	if (path->nat_keepalive_state)
		return 0;

	/* Allocate state */
	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return -ENOMEM;

	/* Allocate config */
	config = kzalloc(sizeof(*config), GFP_KERNEL);
	if (!config) {
		kfree(state);
		return -ENOMEM;
	}

	/* Initialize config from sysctls */
	config->enabled = tquic_sysctl_get_nat_keepalive_enabled();
	config->adaptive_mode = tquic_sysctl_get_nat_keepalive_adaptive();
	config->interval_ms = tquic_sysctl_get_nat_keepalive_interval();
	config->min_interval_ms = TQUIC_NAT_KEEPALIVE_MIN_INTERVAL_MS;
	config->max_interval_ms = TQUIC_NAT_KEEPALIVE_MAX_INTERVAL_MS;
	config->power_mode = TQUIC_NAT_KEEPALIVE_POWER_NORMAL;
	config->mobile_aware = true;
	config->probe_on_activity = false;

	/* Initialize state */
	state->config = config;
	state->path = path;
	state->conn = conn;
	state->current_interval_ms = config->interval_ms;
	state->estimated_timeout_ms = config->interval_ms * 2;
	state->last_activity = ktime_get();
	state->last_keepalive = ktime_get();
	spin_lock_init(&state->lock);
	timer_setup(&state->timer, tquic_nat_keepalive_timer_fn, 0);
	state->initialized = true;

	/* Store in path */
	path->nat_keepalive_state = state;

	/* Update global stats */
	if (config->enabled)
		atomic_inc(&tquic_nat_keepalive_global_stats.paths_with_keepalive);

	/* Schedule first keepalive if enabled */
	if (config->enabled)
		tquic_nat_keepalive_schedule(state);

	pr_debug("tquic: NAT keepalive initialized for path %u (interval=%u ms)\n",
		 path->path_id, config->interval_ms);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_nat_keepalive_init);

void tquic_nat_keepalive_cleanup(struct tquic_path *path)
{
	struct tquic_nat_keepalive_state *state;

	if (!path)
		return;

	state = path->nat_keepalive_state;
	if (!state)
		return;

	/* Cancel timer */
	del_timer_sync(&state->timer);

	/* Update global stats */
	if (state->config && state->config->enabled)
		atomic_dec(&tquic_nat_keepalive_global_stats.paths_with_keepalive);

	/* Free config and state */
	kfree(state->config);
	kfree(state);
	path->nat_keepalive_state = NULL;

	pr_debug("tquic: NAT keepalive cleaned up for path %u\n", path->path_id);
}
EXPORT_SYMBOL_GPL(tquic_nat_keepalive_cleanup);

u32 tquic_nat_keepalive_estimate_timeout(struct tquic_nat_keepalive_state *state)
{
	u32 timeout;

	if (!state)
		return TQUIC_NAT_KEEPALIVE_DEFAULT_INTERVAL_MS * 2;

	spin_lock_bh(&state->lock);
	timeout = state->estimated_timeout_ms;
	spin_unlock_bh(&state->lock);

	return timeout;
}
EXPORT_SYMBOL_GPL(tquic_nat_keepalive_estimate_timeout);

void tquic_nat_keepalive_schedule(struct tquic_nat_keepalive_state *state)
{
	unsigned long interval_jiffies;
	ktime_t now;
	s64 since_activity_ms;
	u32 interval_ms;
	u32 delay_ms;

	if (!state || !state->initialized || state->suspended)
		return;

	if (!state->config || !state->config->enabled)
		return;

	/* Calculate interval considering power mode */
	interval_ms = tquic_nat_keepalive_calc_interval(state);

	/* Calculate how long until we need to send */
	now = ktime_get();
	since_activity_ms = ktime_ms_delta(now, state->last_activity);

	if (since_activity_ms >= interval_ms) {
		/* Already past the interval, send soon but with small jitter */
		delay_ms = prandom_u32_max(100) + 10;  /* 10-110ms jitter */
	} else {
		/* Schedule for remaining time */
		delay_ms = interval_ms - since_activity_ms;

		/* Add some jitter to prevent synchronization */
		delay_ms += prandom_u32_max(delay_ms / 10 + 1);
	}

	interval_jiffies = msecs_to_jiffies(delay_ms);

	/* Arm/rearm the timer */
	mod_timer(&state->timer, jiffies + interval_jiffies);

	pr_debug("tquic: NAT keepalive scheduled in %u ms for path %u\n",
		 delay_ms, state->path->path_id);
}
EXPORT_SYMBOL_GPL(tquic_nat_keepalive_schedule);

int tquic_nat_keepalive_send(struct tquic_nat_keepalive_state *state)
{
	struct tquic_connection *conn;
	struct tquic_path *path;
	struct sk_buff *skb;
	u64 pn;
	int ret;

	if (!state || !state->initialized || state->suspended)
		return -EINVAL;

	if (!state->config || !state->config->enabled)
		return -ENOENT;

	conn = state->conn;
	path = state->path;

	if (!conn || !path)
		return -EINVAL;

	/* Check path state - don't send on failed/closed paths */
	if (path->state == TQUIC_PATH_FAILED ||
	    path->state == TQUIC_PATH_CLOSED ||
	    path->state == TQUIC_PATH_UNUSED)
		return -ENETUNREACH;

	/* Build minimal PING packet */
	skb = tquic_nat_keepalive_build_ping_packet(conn, path, &pn);
	if (!skb)
		return -ENOMEM;

	/* Mark that we're waiting for ACK */
	spin_lock_bh(&state->lock);
	state->pending_ack = true;
	state->pending_pn = pn;
	state->last_keepalive = ktime_get();
	state->total_sent++;
	spin_unlock_bh(&state->lock);

	/* Send the packet */
	ret = tquic_output_packet(conn, path, skb);
	if (ret < 0) {
		spin_lock_bh(&state->lock);
		state->pending_ack = false;
		spin_unlock_bh(&state->lock);
		kfree_skb(skb);
		return ret;
	}

	/* Update global statistics */
	atomic64_inc(&tquic_nat_keepalive_global_stats.total_keepalives_sent);
	atomic64_add(skb->len, &tquic_nat_keepalive_global_stats.total_bytes_sent);

	pr_debug("tquic: NAT keepalive sent on path %u (pn=%llu)\n",
		 path->path_id, pn);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_nat_keepalive_send);

void tquic_nat_keepalive_on_activity(struct tquic_path *path)
{
	struct tquic_nat_keepalive_state *state;

	if (!path)
		return;

	state = tquic_nat_keepalive_get_state(path);
	if (!state || !state->initialized)
		return;

	/* Update last activity timestamp */
	spin_lock_bh(&state->lock);
	state->last_activity = ktime_get();
	spin_unlock_bh(&state->lock);

	/*
	 * Note: We don't reschedule the timer here because that would
	 * require canceling and rearming on every packet, which is expensive.
	 * Instead, the timer callback checks last_activity to determine
	 * if a keepalive is actually needed.
	 */
}
EXPORT_SYMBOL_GPL(tquic_nat_keepalive_on_activity);

void tquic_nat_keepalive_on_ack(struct tquic_path *path, u64 pn)
{
	struct tquic_nat_keepalive_state *state;

	if (!path)
		return;

	state = tquic_nat_keepalive_get_state(path);
	if (!state || !state->initialized)
		return;

	spin_lock_bh(&state->lock);

	/* Check if this ACK is for our pending keepalive */
	if (state->pending_ack && pn >= state->pending_pn) {
		state->pending_ack = false;
		state->total_acked++;

		spin_unlock_bh(&state->lock);

		/* Update global stats */
		atomic64_inc(&tquic_nat_keepalive_global_stats.total_keepalives_acked);

		/* Adaptive adjustment for success */
		tquic_nat_keepalive_adaptive_adjust(state, true);

		pr_debug("tquic: NAT keepalive ACKed on path %u (pn=%llu)\n",
			 path->path_id, pn);
	} else {
		spin_unlock_bh(&state->lock);
	}
}
EXPORT_SYMBOL_GPL(tquic_nat_keepalive_on_ack);

void tquic_nat_keepalive_on_timeout(struct tquic_path *path)
{
	struct tquic_nat_keepalive_state *state;

	if (!path)
		return;

	state = tquic_nat_keepalive_get_state(path);
	if (!state || !state->initialized)
		return;

	spin_lock_bh(&state->lock);

	if (state->pending_ack) {
		state->pending_ack = false;
		state->total_timeouts++;

		spin_unlock_bh(&state->lock);

		/* Update global stats */
		atomic64_inc(&tquic_nat_keepalive_global_stats.total_nat_timeouts);

		/* Adaptive adjustment for failure */
		tquic_nat_keepalive_adaptive_adjust(state, false);

		pr_warn("tquic: NAT keepalive timeout on path %u\n", path->path_id);

		/* Reschedule with shorter interval */
		tquic_nat_keepalive_schedule(state);
	} else {
		spin_unlock_bh(&state->lock);
	}
}
EXPORT_SYMBOL_GPL(tquic_nat_keepalive_on_timeout);

void tquic_nat_keepalive_suspend(struct tquic_path *path)
{
	struct tquic_nat_keepalive_state *state;

	if (!path)
		return;

	state = tquic_nat_keepalive_get_state(path);
	if (!state || !state->initialized)
		return;

	spin_lock_bh(&state->lock);
	state->suspended = true;
	spin_unlock_bh(&state->lock);

	/* Cancel the timer */
	del_timer(&state->timer);

	pr_debug("tquic: NAT keepalive suspended for path %u\n", path->path_id);
}
EXPORT_SYMBOL_GPL(tquic_nat_keepalive_suspend);

void tquic_nat_keepalive_resume(struct tquic_path *path)
{
	struct tquic_nat_keepalive_state *state;

	if (!path)
		return;

	state = tquic_nat_keepalive_get_state(path);
	if (!state || !state->initialized)
		return;

	spin_lock_bh(&state->lock);
	state->suspended = false;
	state->last_activity = ktime_get();  /* Reset activity timestamp */
	spin_unlock_bh(&state->lock);

	/* Reschedule the timer */
	tquic_nat_keepalive_schedule(state);

	pr_debug("tquic: NAT keepalive resumed for path %u\n", path->path_id);
}
EXPORT_SYMBOL_GPL(tquic_nat_keepalive_resume);

int tquic_nat_keepalive_set_config(struct tquic_path *path,
				   const struct tquic_nat_keepalive_config *config)
{
	struct tquic_nat_keepalive_state *state;
	bool was_enabled;
	bool is_enabled;

	if (!path || !config)
		return -EINVAL;

	state = tquic_nat_keepalive_get_state(path);
	if (!state || !state->initialized)
		return -ENOENT;

	spin_lock_bh(&state->lock);

	was_enabled = state->config->enabled;

	/* Copy new configuration */
	state->config->enabled = config->enabled;
	state->config->adaptive_mode = config->adaptive_mode;
	state->config->interval_ms = config->interval_ms;
	state->config->min_interval_ms = config->min_interval_ms;
	state->config->max_interval_ms = config->max_interval_ms;
	state->config->power_mode = config->power_mode;
	state->config->mobile_aware = config->mobile_aware;
	state->config->probe_on_activity = config->probe_on_activity;

	/* Reset current interval if configured interval changed significantly */
	if (state->current_interval_ms > config->interval_ms * 2 ||
	    state->current_interval_ms < config->interval_ms / 2)
		state->current_interval_ms = config->interval_ms;

	is_enabled = config->enabled;

	spin_unlock_bh(&state->lock);

	/* Update global path count */
	if (was_enabled && !is_enabled)
		atomic_dec(&tquic_nat_keepalive_global_stats.paths_with_keepalive);
	else if (!was_enabled && is_enabled)
		atomic_inc(&tquic_nat_keepalive_global_stats.paths_with_keepalive);

	/* Handle timer based on enabled state change */
	if (is_enabled && !was_enabled) {
		tquic_nat_keepalive_schedule(state);
	} else if (!is_enabled && was_enabled) {
		del_timer(&state->timer);
	} else if (is_enabled) {
		/* Enabled before and after - reschedule with new interval */
		tquic_nat_keepalive_schedule(state);
	}

	pr_debug("tquic: NAT keepalive config updated for path %u\n",
		 path->path_id);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_nat_keepalive_set_config);

void tquic_nat_keepalive_get_stats(struct tquic_path *path,
				   u64 *sent, u64 *acked, u64 *timeouts)
{
	struct tquic_nat_keepalive_state *state;

	if (!path) {
		if (sent)
			*sent = 0;
		if (acked)
			*acked = 0;
		if (timeouts)
			*timeouts = 0;
		return;
	}

	state = tquic_nat_keepalive_get_state(path);
	if (!state || !state->initialized) {
		if (sent)
			*sent = 0;
		if (acked)
			*acked = 0;
		if (timeouts)
			*timeouts = 0;
		return;
	}

	spin_lock_bh(&state->lock);
	if (sent)
		*sent = state->total_sent;
	if (acked)
		*acked = state->total_acked;
	if (timeouts)
		*timeouts = state->total_timeouts;
	spin_unlock_bh(&state->lock);
}
EXPORT_SYMBOL_GPL(tquic_nat_keepalive_get_stats);

int tquic_nat_keepalive_set_power_mode(struct tquic_path *path, u8 mode)
{
	struct tquic_nat_keepalive_state *state;

	if (!path)
		return -EINVAL;

	if (mode > TQUIC_NAT_KEEPALIVE_POWER_AGGRESSIVE)
		return -EINVAL;

	state = tquic_nat_keepalive_get_state(path);
	if (!state || !state->initialized || !state->config)
		return -ENOENT;

	spin_lock_bh(&state->lock);
	state->config->power_mode = mode;
	spin_unlock_bh(&state->lock);

	/* Reschedule with new power mode settings */
	if (state->config->enabled)
		tquic_nat_keepalive_schedule(state);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_nat_keepalive_set_power_mode);

/*
 * Note: Sysctl accessor functions are defined in tquic_sysctl.c:
 * - tquic_sysctl_get_nat_keepalive_enabled()
 * - tquic_sysctl_get_nat_keepalive_interval()
 * - tquic_sysctl_get_nat_keepalive_adaptive()
 */

/*
 * =============================================================================
 * Module Init/Exit
 * =============================================================================
 */

int __init tquic_nat_keepalive_module_init(void)
{
	/* Initialize global statistics */
	atomic64_set(&tquic_nat_keepalive_global_stats.total_keepalives_sent, 0);
	atomic64_set(&tquic_nat_keepalive_global_stats.total_keepalives_acked, 0);
	atomic64_set(&tquic_nat_keepalive_global_stats.total_nat_timeouts, 0);
	atomic64_set(&tquic_nat_keepalive_global_stats.total_bytes_sent, 0);
	atomic64_set(&tquic_nat_keepalive_global_stats.adaptive_increases, 0);
	atomic64_set(&tquic_nat_keepalive_global_stats.adaptive_decreases, 0);
	atomic_set(&tquic_nat_keepalive_global_stats.paths_with_keepalive, 0);
	atomic64_set(&tquic_nat_keepalive_global_stats.mobile_savings, 0);

	/* Create workqueue for deferred operations */
	tquic_nat_keepalive_wq = alloc_workqueue("tquic_nat_keepalive",
						  WQ_UNBOUND | WQ_MEM_RECLAIM,
						  0);
	if (!tquic_nat_keepalive_wq) {
		pr_err("tquic: failed to create NAT keepalive workqueue\n");
		return -ENOMEM;
	}

	pr_info("tquic: NAT keepalive subsystem initialized (default interval=%u ms)\n",
		tquic_nat_keepalive_interval_ms);

	return 0;
}

void __exit tquic_nat_keepalive_module_exit(void)
{
	/* Destroy workqueue */
	if (tquic_nat_keepalive_wq) {
		destroy_workqueue(tquic_nat_keepalive_wq);
		tquic_nat_keepalive_wq = NULL;
	}

	pr_info("tquic: NAT keepalive subsystem cleaned up\n");
}

MODULE_DESCRIPTION("TQUIC NAT Keepalive (RFC 9308 Section 3.5)");
MODULE_LICENSE("GPL");
