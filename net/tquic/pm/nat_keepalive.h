/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC NAT Keepalive Header
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * NAT Keepalive implementation per RFC 9308 Section 3.5.
 *
 * NAT devices maintain UDP binding state that maps internal to external
 * addresses. These bindings have limited lifetimes (typically 30-300 seconds).
 * When a binding expires, the external address changes, breaking the QUIC
 * connection. This module prevents binding expiration by sending minimal
 * PING frames before the timeout occurs.
 *
 * Key features:
 * - Adaptive timeout estimation based on observed NAT behavior
 * - Minimal packet size (single PING frame) to conserve bandwidth/battery
 * - Per-path keepalive state for multipath scenarios
 * - Integration with path manager timers
 * - Mobile-aware power optimization
 */

#ifndef _TQUIC_NAT_KEEPALIVE_H
#define _TQUIC_NAT_KEEPALIVE_H

#include <linux/types.h>
#include <linux/timer.h>
#include <linux/spinlock.h>
#include <linux/ktime.h>

/* Forward declarations */
struct tquic_connection;
struct tquic_path;

/*
 * NAT timeout estimation bounds
 *
 * Per RFC 9308 Section 3.5: NAT binding timeouts vary widely (30s-300s+).
 * The minimum is typically 30s for conservative NATs, while some allow
 * several minutes. Default target is 25s to provide safe margin for 30s NATs.
 *
 * For mobile devices, longer intervals conserve battery but risk timeout.
 * For desktop/server, shorter intervals are acceptable.
 */
#define TQUIC_NAT_KEEPALIVE_MIN_INTERVAL_MS	5000	/* 5 seconds minimum */
#define TQUIC_NAT_KEEPALIVE_MAX_INTERVAL_MS	120000	/* 120 seconds maximum */
#define TQUIC_NAT_KEEPALIVE_DEFAULT_INTERVAL_MS	25000	/* 25 seconds default */

/* Adaptive estimation parameters */
#define TQUIC_NAT_KEEPALIVE_PROBE_MULTIPLIER	2	/* Double interval on success */
#define TQUIC_NAT_KEEPALIVE_BACKOFF_DIVISOR	2	/* Halve on failure */
#define TQUIC_NAT_KEEPALIVE_STABILITY_THRESHOLD	3	/* Consecutive successes before adapting */
#define TQUIC_NAT_KEEPALIVE_FAILURE_THRESHOLD	2	/* Failures before backoff */

/* Power mode optimization */
#define TQUIC_NAT_KEEPALIVE_POWER_NORMAL	0	/* Normal operation */
#define TQUIC_NAT_KEEPALIVE_POWER_SAVING	1	/* Longer intervals, batching */
#define TQUIC_NAT_KEEPALIVE_POWER_AGGRESSIVE	2	/* Shortest safe intervals */

/**
 * struct tquic_nat_keepalive_config - NAT keepalive configuration
 * @enabled: Whether keepalive is enabled
 * @adaptive_mode: Use adaptive interval estimation
 * @interval_ms: Current/configured keepalive interval (milliseconds)
 * @min_interval_ms: Minimum allowed interval
 * @max_interval_ms: Maximum allowed interval
 * @power_mode: Power optimization mode
 * @mobile_aware: Adjust behavior for mobile networks
 * @probe_on_activity: Send probes even when path is active
 *
 * Configuration can be set per-connection or use global sysctls.
 * The adaptive algorithm adjusts interval_ms between min and max
 * based on observed NAT timeout behavior.
 */
struct tquic_nat_keepalive_config {
	bool enabled;
	bool adaptive_mode;
	u32 interval_ms;
	u32 min_interval_ms;
	u32 max_interval_ms;
	u8 power_mode;
	bool mobile_aware;
	bool probe_on_activity;
};

/**
 * struct tquic_nat_keepalive_state - Per-path NAT keepalive state
 * @config: Configuration (may point to connection-wide config)
 * @timer: Keepalive timer
 * @lock: Protects state modifications
 * @path: Associated path
 * @conn: Associated connection
 * @last_activity: Timestamp of last path activity
 * @last_keepalive: Timestamp of last keepalive sent
 * @estimated_timeout_ms: Estimated NAT binding timeout
 * @current_interval_ms: Current adaptive interval
 * @consecutive_successes: Consecutive successful keepalives
 * @consecutive_failures: Consecutive failed keepalives (no ACK received)
 * @pending_ack: Waiting for ACK after sending keepalive
 * @pending_pn: Packet number of pending keepalive
 * @total_sent: Statistics - total keepalives sent
 * @total_acked: Statistics - total keepalives acknowledged
 * @total_timeouts: Statistics - total timeout events
 * @initialized: State has been initialized
 * @suspended: Keepalive temporarily suspended
 *
 * Each path maintains its own keepalive state because different paths
 * may traverse different NATs with different timeout characteristics.
 */
struct tquic_nat_keepalive_state {
	struct tquic_nat_keepalive_config *config;
	struct timer_list timer;
	spinlock_t lock;
	struct tquic_path *path;
	struct tquic_connection *conn;

	/* Timing */
	ktime_t last_activity;
	ktime_t last_keepalive;
	u32 estimated_timeout_ms;
	u32 current_interval_ms;

	/* Adaptive state */
	u8 consecutive_successes;
	u8 consecutive_failures;
	bool pending_ack;
	u64 pending_pn;

	/* Statistics */
	u64 total_sent;
	u64 total_acked;
	u64 total_timeouts;

	/* Flags */
	bool initialized;
	bool suspended;
};

/**
 * struct tquic_nat_keepalive_stats - Global NAT keepalive statistics
 * @total_keepalives_sent: Total keepalive packets sent
 * @total_keepalives_acked: Total keepalives that received ACK
 * @total_nat_timeouts: Total detected NAT timeout events
 * @total_bytes_sent: Total bytes used for keepalive (efficiency metric)
 * @adaptive_increases: Times interval was increased (NAT is lenient)
 * @adaptive_decreases: Times interval was decreased (NAT is aggressive)
 * @paths_with_keepalive: Current paths with active keepalive
 * @mobile_savings: Estimated battery savings (deferred keepalives)
 *
 * Global statistics aggregated across all connections for monitoring.
 */
struct tquic_nat_keepalive_stats {
	atomic64_t total_keepalives_sent;
	atomic64_t total_keepalives_acked;
	atomic64_t total_nat_timeouts;
	atomic64_t total_bytes_sent;
	atomic64_t adaptive_increases;
	atomic64_t adaptive_decreases;
	atomic_t paths_with_keepalive;
	atomic64_t mobile_savings;
};

/* Global statistics instance */
extern struct tquic_nat_keepalive_stats tquic_nat_keepalive_global_stats;

/*
 * =============================================================================
 * API Functions
 * =============================================================================
 */

/**
 * tquic_nat_keepalive_init - Initialize NAT keepalive for a path
 * @path: Path to initialize keepalive for
 * @conn: Parent connection
 *
 * Initializes the keepalive state for a path based on global sysctl
 * configuration. The timer is armed if keepalive is enabled.
 *
 * Context: Process context, may sleep
 * Return: 0 on success, negative error code on failure
 */
int tquic_nat_keepalive_init(struct tquic_path *path,
			     struct tquic_connection *conn);

/**
 * tquic_nat_keepalive_cleanup - Clean up NAT keepalive state
 * @path: Path to clean up
 *
 * Cancels the keepalive timer and frees associated state.
 * Safe to call even if keepalive was not initialized.
 *
 * Context: Process context
 */
void tquic_nat_keepalive_cleanup(struct tquic_path *path);

/**
 * tquic_nat_keepalive_estimate_timeout - Estimate NAT binding timeout
 * @state: Keepalive state
 *
 * Estimates the NAT binding timeout based on observed behavior.
 * Uses the adaptive algorithm to refine the estimate over time.
 *
 * Context: Any (uses spinlock internally)
 * Return: Estimated timeout in milliseconds
 */
u32 tquic_nat_keepalive_estimate_timeout(struct tquic_nat_keepalive_state *state);

/**
 * tquic_nat_keepalive_schedule - Schedule next keepalive
 * @state: Keepalive state
 *
 * Schedules the next keepalive based on current interval and last activity.
 * If path has been active recently, the timer is deferred.
 *
 * Context: Any (timer-safe)
 */
void tquic_nat_keepalive_schedule(struct tquic_nat_keepalive_state *state);

/**
 * tquic_nat_keepalive_send - Send minimal keepalive PING frame
 * @state: Keepalive state
 *
 * Sends a minimal packet containing only a PING frame to keep the
 * NAT binding alive. This is the most efficient keepalive mechanism
 * (smallest possible packet that elicits an ACK).
 *
 * Per RFC 9308: "QUIC implementations SHOULD use PING frames for
 * keepalives when possible, as they are smaller than PATH_CHALLENGE."
 *
 * Context: Softirq or process context
 * Return: 0 on success, negative error code on failure
 */
int tquic_nat_keepalive_send(struct tquic_nat_keepalive_state *state);

/**
 * tquic_nat_keepalive_on_activity - Reset timer on path activity
 * @path: Path with activity
 *
 * Called when any packet is sent or received on the path. Resets the
 * keepalive timer since the NAT binding has been refreshed by the
 * regular traffic.
 *
 * Context: Any (softirq-safe)
 */
void tquic_nat_keepalive_on_activity(struct tquic_path *path);

/**
 * tquic_nat_keepalive_on_ack - Handle ACK for keepalive
 * @path: Path that received ACK
 * @pn: Packet number that was acknowledged
 *
 * Called when an ACK is received that may acknowledge a keepalive.
 * Updates adaptive state if the ACK was for a keepalive packet.
 *
 * Context: Softirq context
 */
void tquic_nat_keepalive_on_ack(struct tquic_path *path, u64 pn);

/**
 * tquic_nat_keepalive_on_timeout - Handle keepalive timeout
 * @path: Path that experienced timeout
 *
 * Called when a keepalive was sent but no ACK received within expected time.
 * This may indicate NAT binding loss or path degradation.
 *
 * Context: Timer/softirq context
 */
void tquic_nat_keepalive_on_timeout(struct tquic_path *path);

/**
 * tquic_nat_keepalive_suspend - Temporarily suspend keepalive
 * @path: Path to suspend keepalive for
 *
 * Suspends keepalive during path validation or when path is known to be down.
 * Prevents unnecessary packets during recovery procedures.
 *
 * Context: Any
 */
void tquic_nat_keepalive_suspend(struct tquic_path *path);

/**
 * tquic_nat_keepalive_resume - Resume keepalive after suspension
 * @path: Path to resume keepalive for
 *
 * Resumes keepalive operation and reschedules the timer.
 *
 * Context: Any
 */
void tquic_nat_keepalive_resume(struct tquic_path *path);

/**
 * tquic_nat_keepalive_set_config - Update keepalive configuration
 * @path: Path to configure
 * @config: New configuration
 *
 * Updates the keepalive configuration for a path. If the new interval
 * is shorter than the current timer, the timer is rearmed.
 *
 * Context: Process context
 * Return: 0 on success, negative error code on failure
 */
int tquic_nat_keepalive_set_config(struct tquic_path *path,
				   const struct tquic_nat_keepalive_config *config);

/**
 * tquic_nat_keepalive_get_stats - Get per-path keepalive statistics
 * @path: Path to get stats for
 * @sent: Output - total keepalives sent
 * @acked: Output - total keepalives acknowledged
 * @timeouts: Output - total timeouts
 *
 * Context: Any
 */
void tquic_nat_keepalive_get_stats(struct tquic_path *path,
				   u64 *sent, u64 *acked, u64 *timeouts);

/**
 * tquic_nat_keepalive_set_power_mode - Set power optimization mode
 * @path: Path to configure
 * @mode: Power mode (NORMAL, SAVING, or AGGRESSIVE)
 *
 * Adjusts keepalive behavior for power optimization:
 * - NORMAL: Standard intervals and behavior
 * - SAVING: Longer intervals, batch with other traffic when possible
 * - AGGRESSIVE: Shortest safe intervals for reliability
 *
 * Context: Any
 * Return: 0 on success, -EINVAL for invalid mode
 */
int tquic_nat_keepalive_set_power_mode(struct tquic_path *path, u8 mode);

/*
 * =============================================================================
 * NAT Lifecycle Integration API
 * =============================================================================
 *
 * These functions integrate the basic keepalive with the advanced NAT
 * lifecycle management module for enhanced NAT handling.
 */

/* Include lifecycle header for enum definitions */
#include "nat_lifecycle.h"

/**
 * tquic_nat_keepalive_sync_with_lifecycle - Synchronize with lifecycle module
 * @state: Keepalive state
 *
 * Updates keepalive interval based on lifecycle recommendations.
 * Should be called after NAT type detection or timeout estimation updates.
 *
 * Context: Any
 */
void tquic_nat_keepalive_sync_with_lifecycle(struct tquic_nat_keepalive_state *state);

/**
 * tquic_nat_keepalive_get_binding_state - Get current NAT binding state
 * @state: Keepalive state
 *
 * Returns the current binding state from the lifecycle module.
 * Useful for determining if a keepalive should be sent urgently.
 *
 * Context: Any
 * Return: Binding state (ACTIVE, EXPIRING, EXPIRED, etc.)
 */
enum tquic_nat_binding_state tquic_nat_keepalive_get_binding_state(
	struct tquic_nat_keepalive_state *state);

/**
 * tquic_nat_keepalive_get_nat_type - Get detected NAT type
 * @state: Keepalive state
 *
 * Returns the NAT type detected by the lifecycle module.
 * Useful for adjusting application behavior based on NAT restrictiveness.
 *
 * Context: Any
 * Return: NAT type (FULL_CONE, RESTRICTED, SYMMETRIC, etc.)
 */
enum tquic_nat_type tquic_nat_keepalive_get_nat_type(
	struct tquic_nat_keepalive_state *state);

/**
 * tquic_nat_keepalive_force_binding_refresh - Force immediate binding refresh
 * @state: Keepalive state
 *
 * Triggers an immediate keepalive to refresh the NAT binding.
 * Use when binding expiry is imminent or before critical operations.
 *
 * Context: Softirq or process context
 * Return: 0 on success, negative error code on failure
 */
int tquic_nat_keepalive_force_binding_refresh(
	struct tquic_nat_keepalive_state *state);

/*
 * =============================================================================
 * Sysctl Accessors
 * =============================================================================
 */

/**
 * tquic_sysctl_get_nat_keepalive_enabled - Get global keepalive enabled state
 * Return: 1 if enabled, 0 if disabled
 */
int tquic_sysctl_get_nat_keepalive_enabled(void);

/**
 * tquic_sysctl_get_nat_keepalive_interval - Get global keepalive interval
 * Return: Interval in milliseconds
 */
u32 tquic_sysctl_get_nat_keepalive_interval(void);

/**
 * tquic_sysctl_get_nat_keepalive_adaptive - Get adaptive mode setting
 * Return: 1 if adaptive mode enabled, 0 if disabled
 */
int tquic_sysctl_get_nat_keepalive_adaptive(void);

/*
 * =============================================================================
 * Module Init/Exit
 * =============================================================================
 */

/**
 * tquic_nat_keepalive_module_init - Initialize NAT keepalive subsystem
 * Return: 0 on success, negative error code on failure
 */
int __init tquic_nat_keepalive_module_init(void);

/**
 * tquic_nat_keepalive_module_exit - Clean up NAT keepalive subsystem
 */
void tquic_nat_keepalive_module_exit(void);

#endif /* _TQUIC_NAT_KEEPALIVE_H */
