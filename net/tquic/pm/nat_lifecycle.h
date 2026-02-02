/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC NAT Lifecycle Management Header
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Advanced NAT lifecycle management for QUIC connections including:
 * - NAT binding timeout detection and prediction
 * - Adaptive keepalive interval adjustment
 * - NAT type detection (Full Cone, Restricted, Port-Restricted, Symmetric)
 * - Proactive binding refresh strategies
 * - Multiple/cascaded NAT traversal handling
 * - STUN-like lightweight probing for NAT characteristic detection
 *
 * This module extends the basic nat_keepalive functionality with more
 * sophisticated NAT behavior analysis and optimization.
 *
 * References:
 * - RFC 9308: Applicability of the QUIC Transport Protocol (Section 3.5)
 * - RFC 5389: STUN - Session Traversal Utilities for NAT
 * - RFC 4787: NAT Behavioral Requirements for UDP
 */

#ifndef _TQUIC_NAT_LIFECYCLE_H
#define _TQUIC_NAT_LIFECYCLE_H

#include <linux/types.h>
#include <linux/timer.h>
#include <linux/spinlock.h>
#include <linux/ktime.h>
#include <linux/workqueue.h>
#include <linux/rbtree.h>

/* Forward declarations */
struct tquic_connection;
struct tquic_path;
struct tquic_nat_keepalive_state;

/*
 * =============================================================================
 * NAT Type Classification
 * =============================================================================
 *
 * Per RFC 4787 and RFC 5389, NAT devices exhibit different behaviors:
 *
 * FULL_CONE (Endpoint-Independent Mapping):
 *   - Same external mapping for all destinations
 *   - Any external host can send to the mapped address
 *   - Most permissive, easiest to work with
 *
 * RESTRICTED_CONE (Address-Dependent Filtering):
 *   - Same external mapping for all destinations
 *   - Only hosts we've sent to can send back
 *   - Requires outbound traffic to "open" the path
 *
 * PORT_RESTRICTED (Address+Port-Dependent Filtering):
 *   - Same external mapping for all destinations
 *   - Only hosts/ports we've sent to can send back
 *   - Common in consumer NAT devices
 *
 * SYMMETRIC (Address+Port-Dependent Mapping):
 *   - Different external mapping per destination
 *   - Most restrictive, hardest for P2P
 *   - Requires careful connection ID handling
 *
 * UNKNOWN: Not yet determined or detection failed
 */
enum tquic_nat_type {
	TQUIC_NAT_TYPE_UNKNOWN		= 0,
	TQUIC_NAT_TYPE_NONE		= 1,	/* Direct connection (no NAT) */
	TQUIC_NAT_TYPE_FULL_CONE	= 2,
	TQUIC_NAT_TYPE_RESTRICTED_CONE	= 3,
	TQUIC_NAT_TYPE_PORT_RESTRICTED	= 4,
	TQUIC_NAT_TYPE_SYMMETRIC	= 5,
	TQUIC_NAT_TYPE_CARRIER_GRADE	= 6,	/* CGNAT - often symmetric + short timeout */
};

/*
 * NAT binding state - tracks individual NAT binding lifecycle
 */
enum tquic_nat_binding_state {
	TQUIC_NAT_BINDING_UNKNOWN	= 0,
	TQUIC_NAT_BINDING_ACTIVE	= 1,	/* Binding confirmed active */
	TQUIC_NAT_BINDING_EXPIRING	= 2,	/* Approaching timeout */
	TQUIC_NAT_BINDING_EXPIRED	= 3,	/* Binding lost */
	TQUIC_NAT_BINDING_REFRESHING	= 4,	/* Refresh in progress */
};

/*
 * Probing phases for NAT detection
 */
enum tquic_nat_probe_phase {
	TQUIC_NAT_PROBE_IDLE		= 0,
	TQUIC_NAT_PROBE_INITIAL		= 1,	/* Initial binding test */
	TQUIC_NAT_PROBE_MAPPING		= 2,	/* Test endpoint-independent mapping */
	TQUIC_NAT_PROBE_FILTERING	= 3,	/* Test filtering behavior */
	TQUIC_NAT_PROBE_TIMEOUT_EST	= 4,	/* Estimate binding timeout */
	TQUIC_NAT_PROBE_COMPLETE	= 5,
};

/*
 * =============================================================================
 * Configuration Constants
 * =============================================================================
 */

/* Timeout estimation parameters */
#define TQUIC_NAT_MIN_TIMEOUT_MS		10000	/* 10 seconds minimum */
#define TQUIC_NAT_MAX_TIMEOUT_MS		600000	/* 10 minutes maximum */
#define TQUIC_NAT_DEFAULT_TIMEOUT_MS		30000	/* 30 seconds default */
#define TQUIC_NAT_CGNAT_TIMEOUT_MS		20000	/* CGNAT often ~20 seconds */

/* Probing parameters */
#define TQUIC_NAT_PROBE_INTERVAL_MS		500	/* Between probe packets */
#define TQUIC_NAT_PROBE_MAX_ATTEMPTS		5
#define TQUIC_NAT_PROBE_TIMEOUT_MS		2000	/* Per-probe timeout */

/* Binding refresh safety margin */
#define TQUIC_NAT_REFRESH_MARGIN_PERCENT	25	/* Refresh at 75% of timeout */
#define TQUIC_NAT_EXPIRY_WARNING_PERCENT	10	/* Warn at 90% of timeout */

/* Adaptive interval parameters */
#define TQUIC_NAT_INTERVAL_INCREASE_FACTOR	125	/* 1.25x on success */
#define TQUIC_NAT_INTERVAL_DECREASE_FACTOR	50	/* 0.5x on failure */
#define TQUIC_NAT_INTERVAL_STABILITY_COUNT	5	/* Successes before increase */

/* Cascaded NAT detection */
#define TQUIC_NAT_MAX_HOPS			4	/* Max NAT devices in path */
#define TQUIC_NAT_HOP_TIMEOUT_VARIANCE_MS	5000	/* Variance suggesting extra hop */

/* STUN-like probe magic */
#define TQUIC_NAT_PROBE_MAGIC			0x51554943	/* "QUIC" */

/*
 * =============================================================================
 * Data Structures
 * =============================================================================
 */

/**
 * struct tquic_nat_timeout_sample - Single timeout observation
 * @timestamp: When this sample was taken
 * @measured_timeout_ms: Observed timeout value
 * @was_refresh: True if this was a proactive refresh test
 * @confidence: Confidence level (0-100)
 */
struct tquic_nat_timeout_sample {
	ktime_t timestamp;
	u32 measured_timeout_ms;
	bool was_refresh;
	u8 confidence;
};

/**
 * struct tquic_nat_timeout_estimator - Timeout estimation state
 * @samples: Ring buffer of timeout samples
 * @sample_count: Number of valid samples
 * @sample_index: Next write position in ring
 * @estimated_timeout_ms: Current best estimate
 * @min_observed_ms: Minimum observed timeout
 * @max_observed_ms: Maximum observed timeout
 * @variance_ms: Observed variance
 * @confidence: Overall confidence (0-100)
 * @last_update: When estimate was last updated
 *
 * Maintains a sliding window of timeout observations to estimate
 * the NAT binding timeout with confidence intervals.
 */
#define TQUIC_NAT_TIMEOUT_SAMPLE_COUNT	8

struct tquic_nat_timeout_estimator {
	struct tquic_nat_timeout_sample samples[TQUIC_NAT_TIMEOUT_SAMPLE_COUNT];
	u8 sample_count;
	u8 sample_index;
	u32 estimated_timeout_ms;
	u32 min_observed_ms;
	u32 max_observed_ms;
	u32 variance_ms;
	u8 confidence;
	ktime_t last_update;
};

/**
 * struct tquic_nat_probe_state - STUN-like probing state
 * @phase: Current probe phase
 * @attempt: Current attempt number
 * @probe_sent: When probe was sent
 * @probe_data: Random data for probe validation
 * @mapping_addr: Observed external mapping (for comparison)
 * @filtering_test_pending: Waiting for filtering test response
 * @timer: Probe timeout timer
 *
 * Used for active probing to determine NAT type and behavior.
 */
struct tquic_nat_probe_state {
	enum tquic_nat_probe_phase phase;
	u8 attempt;
	ktime_t probe_sent;
	u8 probe_data[8];
	struct sockaddr_storage mapping_addr;
	bool filtering_test_pending;
	struct timer_list timer;
};

/**
 * struct tquic_nat_hop_info - Information about a single NAT hop
 * @timeout_ms: Estimated timeout for this hop
 * @type: NAT type at this hop
 * @detected: Whether this hop has been detected
 * @external_addr: External address after this NAT
 */
struct tquic_nat_hop_info {
	u32 timeout_ms;
	enum tquic_nat_type type;
	bool detected;
	struct sockaddr_storage external_addr;
};

/**
 * struct tquic_nat_cascade_state - Cascaded NAT tracking
 * @hop_count: Number of detected NAT hops
 * @hops: Per-hop information
 * @effective_timeout_ms: Minimum timeout across all hops
 * @detection_complete: All hops detected
 *
 * Handles scenarios where traffic traverses multiple NAT devices,
 * such as home router + carrier-grade NAT.
 */
struct tquic_nat_cascade_state {
	u8 hop_count;
	struct tquic_nat_hop_info hops[TQUIC_NAT_MAX_HOPS];
	u32 effective_timeout_ms;
	bool detection_complete;
};

/**
 * struct tquic_nat_lifecycle_config - Lifecycle management configuration
 * @enabled: Enable lifecycle management
 * @auto_detect_type: Automatically detect NAT type
 * @adaptive_refresh: Use adaptive refresh timing
 * @cascade_detection: Enable cascaded NAT detection
 * @aggressive_refresh: Use shorter refresh intervals
 * @probe_on_path_change: Probe when path changes
 * @min_refresh_interval_ms: Minimum refresh interval
 * @max_refresh_interval_ms: Maximum refresh interval
 * @probe_interval_ms: Interval between probes
 * @timeout_safety_margin_percent: Safety margin for refresh
 */
struct tquic_nat_lifecycle_config {
	bool enabled;
	bool auto_detect_type;
	bool adaptive_refresh;
	bool cascade_detection;
	bool aggressive_refresh;
	bool probe_on_path_change;
	u32 min_refresh_interval_ms;
	u32 max_refresh_interval_ms;
	u32 probe_interval_ms;
	u8 timeout_safety_margin_percent;
};

/**
 * struct tquic_nat_lifecycle_state - Per-path NAT lifecycle state
 * @config: Configuration
 * @lock: Protects state modifications
 * @path: Associated path
 * @conn: Associated connection
 * @nat_type: Detected NAT type
 * @binding_state: Current binding state
 * @timeout_est: Timeout estimator
 * @probe: Probing state
 * @cascade: Cascaded NAT state
 * @last_binding_refresh: When binding was last refreshed
 * @next_refresh_time: When next refresh should occur
 * @refresh_interval_ms: Current refresh interval
 * @consecutive_refreshes: Consecutive successful refreshes
 * @consecutive_failures: Consecutive refresh failures
 * @binding_changes: Number of binding changes detected
 * @refresh_timer: Timer for scheduled refreshes
 * @probe_work: Deferred work for probing
 * @initialized: State initialized
 * @probing_active: Active probing in progress
 *
 * Statistics:
 * @stats_probes_sent: Total probes sent
 * @stats_probes_successful: Successful probe responses
 * @stats_binding_refreshes: Total binding refreshes
 * @stats_binding_losses: Detected binding losses
 * @stats_type_changes: NAT type changed during session
 */
struct tquic_nat_lifecycle_state {
	struct tquic_nat_lifecycle_config config;
	spinlock_t lock;
	struct tquic_path *path;
	struct tquic_connection *conn;

	/* NAT characteristics */
	enum tquic_nat_type nat_type;
	enum tquic_nat_binding_state binding_state;

	/* Timeout estimation */
	struct tquic_nat_timeout_estimator timeout_est;

	/* Probing */
	struct tquic_nat_probe_state probe;

	/* Cascaded NAT */
	struct tquic_nat_cascade_state cascade;

	/* Refresh timing */
	ktime_t last_binding_refresh;
	ktime_t next_refresh_time;
	u32 refresh_interval_ms;
	u16 consecutive_refreshes;
	u16 consecutive_failures;
	u32 binding_changes;

	/* Timers and work */
	struct timer_list refresh_timer;
	struct work_struct probe_work;

	/* Flags */
	bool initialized;
	bool probing_active;

	/* Statistics */
	atomic64_t stats_probes_sent;
	atomic64_t stats_probes_successful;
	atomic64_t stats_binding_refreshes;
	atomic64_t stats_binding_losses;
	atomic_t stats_type_changes;
};

/**
 * struct tquic_nat_lifecycle_stats - Global NAT lifecycle statistics
 * @nat_type_counts: Count of each NAT type detected
 * @total_bindings_tracked: Total bindings tracked
 * @total_binding_losses: Total binding losses
 * @avg_timeout_ms: Average observed timeout
 * @cascade_nat_count: Connections with cascaded NAT
 * @probe_success_rate: Probe success rate (percent)
 */
struct tquic_nat_lifecycle_stats {
	atomic_t nat_type_counts[7];
	atomic64_t total_bindings_tracked;
	atomic64_t total_binding_losses;
	atomic_t avg_timeout_ms;
	atomic_t cascade_nat_count;
	atomic_t probe_success_rate;
};

/* Global statistics instance */
extern struct tquic_nat_lifecycle_stats tquic_nat_lifecycle_global_stats;

/*
 * =============================================================================
 * API Functions
 * =============================================================================
 */

/**
 * tquic_nat_lifecycle_init - Initialize NAT lifecycle management for a path
 * @path: Path to manage
 * @conn: Parent connection
 *
 * Allocates and initializes lifecycle state for the path.
 * Should be called after path creation and NAT keepalive init.
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_nat_lifecycle_init(struct tquic_path *path,
			     struct tquic_connection *conn);

/**
 * tquic_nat_lifecycle_cleanup - Clean up NAT lifecycle state
 * @path: Path to clean up
 */
void tquic_nat_lifecycle_cleanup(struct tquic_path *path);

/**
 * tquic_nat_lifecycle_start_detection - Start NAT type detection
 * @state: Lifecycle state
 *
 * Begins active probing to determine NAT type and timeout.
 * Results are reported asynchronously via callbacks.
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_nat_lifecycle_start_detection(struct tquic_nat_lifecycle_state *state);

/**
 * tquic_nat_lifecycle_get_type - Get detected NAT type
 * @state: Lifecycle state
 *
 * Return: Detected NAT type, or UNKNOWN if not yet determined
 */
enum tquic_nat_type tquic_nat_lifecycle_get_type(
	struct tquic_nat_lifecycle_state *state);

/**
 * tquic_nat_lifecycle_get_timeout - Get estimated NAT binding timeout
 * @state: Lifecycle state
 *
 * Return: Estimated timeout in milliseconds
 */
u32 tquic_nat_lifecycle_get_timeout(struct tquic_nat_lifecycle_state *state);

/**
 * tquic_nat_lifecycle_get_refresh_interval - Get recommended refresh interval
 * @state: Lifecycle state
 *
 * Returns the recommended interval for keepalive/refresh based on
 * detected NAT behavior and timeout estimation.
 *
 * Return: Refresh interval in milliseconds
 */
u32 tquic_nat_lifecycle_get_refresh_interval(
	struct tquic_nat_lifecycle_state *state);

/**
 * tquic_nat_lifecycle_binding_check - Check binding state
 * @state: Lifecycle state
 *
 * Checks current binding state and triggers refresh if needed.
 * Called periodically or on-demand.
 *
 * Return: Current binding state
 */
enum tquic_nat_binding_state tquic_nat_lifecycle_binding_check(
	struct tquic_nat_lifecycle_state *state);

/**
 * tquic_nat_lifecycle_on_packet_sent - Called when packet is sent
 * @state: Lifecycle state
 *
 * Updates binding refresh timestamp on outbound traffic.
 */
void tquic_nat_lifecycle_on_packet_sent(struct tquic_nat_lifecycle_state *state);

/**
 * tquic_nat_lifecycle_on_packet_received - Called when packet is received
 * @state: Lifecycle state
 * @from_addr: Source address of received packet
 *
 * Updates binding state and detects potential rebinding.
 */
void tquic_nat_lifecycle_on_packet_received(
	struct tquic_nat_lifecycle_state *state,
	const struct sockaddr_storage *from_addr);

/**
 * tquic_nat_lifecycle_on_keepalive_ack - Called when keepalive is acknowledged
 * @state: Lifecycle state
 * @rtt_ms: Round-trip time of the keepalive
 *
 * Updates timeout estimation based on successful keepalive.
 */
void tquic_nat_lifecycle_on_keepalive_ack(
	struct tquic_nat_lifecycle_state *state,
	u32 rtt_ms);

/**
 * tquic_nat_lifecycle_on_keepalive_timeout - Called when keepalive times out
 * @state: Lifecycle state
 *
 * Updates binding state and potentially triggers rebinding detection.
 */
void tquic_nat_lifecycle_on_keepalive_timeout(
	struct tquic_nat_lifecycle_state *state);

/**
 * tquic_nat_lifecycle_on_path_change - Called when path characteristics change
 * @state: Lifecycle state
 *
 * Triggers re-detection of NAT characteristics after significant changes.
 */
void tquic_nat_lifecycle_on_path_change(struct tquic_nat_lifecycle_state *state);

/**
 * tquic_nat_lifecycle_schedule_refresh - Schedule proactive binding refresh
 * @state: Lifecycle state
 *
 * Schedules a keepalive to refresh the binding before timeout.
 */
void tquic_nat_lifecycle_schedule_refresh(struct tquic_nat_lifecycle_state *state);

/**
 * tquic_nat_lifecycle_force_refresh - Force immediate binding refresh
 * @state: Lifecycle state
 *
 * Immediately sends a keepalive to refresh the binding.
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_nat_lifecycle_force_refresh(struct tquic_nat_lifecycle_state *state);

/**
 * tquic_nat_lifecycle_detect_cascade - Detect cascaded NAT topology
 * @state: Lifecycle state
 *
 * Initiates detection of multiple NAT hops in the path.
 *
 * Return: Number of detected NAT hops, or negative on error
 */
int tquic_nat_lifecycle_detect_cascade(struct tquic_nat_lifecycle_state *state);

/**
 * tquic_nat_lifecycle_get_cascade_count - Get number of NAT hops
 * @state: Lifecycle state
 *
 * Return: Number of detected NAT hops
 */
int tquic_nat_lifecycle_get_cascade_count(
	struct tquic_nat_lifecycle_state *state);

/**
 * tquic_nat_lifecycle_set_config - Update lifecycle configuration
 * @state: Lifecycle state
 * @config: New configuration
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_nat_lifecycle_set_config(struct tquic_nat_lifecycle_state *state,
				   const struct tquic_nat_lifecycle_config *config);

/**
 * tquic_nat_lifecycle_get_stats - Get per-path lifecycle statistics
 * @state: Lifecycle state
 * @probes_sent: Output - probes sent
 * @binding_refreshes: Output - binding refreshes
 * @binding_losses: Output - binding losses
 */
void tquic_nat_lifecycle_get_stats(struct tquic_nat_lifecycle_state *state,
				   u64 *probes_sent,
				   u64 *binding_refreshes,
				   u64 *binding_losses);

/*
 * =============================================================================
 * Integration with NAT Keepalive
 * =============================================================================
 */

/**
 * tquic_nat_lifecycle_update_keepalive - Update keepalive from lifecycle
 * @lifecycle_state: Lifecycle state
 * @keepalive_state: Keepalive state to update
 *
 * Propagates lifecycle decisions to the keepalive subsystem.
 */
void tquic_nat_lifecycle_update_keepalive(
	struct tquic_nat_lifecycle_state *lifecycle_state,
	struct tquic_nat_keepalive_state *keepalive_state);

/**
 * tquic_nat_lifecycle_from_keepalive - Get lifecycle state from keepalive
 * @keepalive_state: Keepalive state
 *
 * Return: Associated lifecycle state, or NULL
 */
struct tquic_nat_lifecycle_state *tquic_nat_lifecycle_from_keepalive(
	struct tquic_nat_keepalive_state *keepalive_state);

/*
 * =============================================================================
 * Sysctl Accessors
 * =============================================================================
 */

/**
 * Sysctl parameter accessors for NAT lifecycle configuration.
 * These are used to get global defaults that can be overridden per-path.
 */
int tquic_sysctl_get_nat_lifecycle_enabled(void);
int tquic_sysctl_get_nat_cascade_detection(void);
u32 tquic_sysctl_get_nat_probe_interval(void);
u32 tquic_sysctl_get_nat_min_timeout(void);
u32 tquic_sysctl_get_nat_max_timeout(void);

/* Sysctl parameters - defined in tquic_sysctl.c */
extern int tquic_nat_lifecycle_enabled;
extern int tquic_nat_cascade_detection;
extern u32 tquic_nat_probe_interval_ms;
extern u32 tquic_nat_min_timeout_ms;
extern u32 tquic_nat_max_timeout_ms;

/*
 * =============================================================================
 * Module Init/Exit
 * =============================================================================
 */

/**
 * tquic_nat_lifecycle_module_init - Initialize NAT lifecycle subsystem
 * Return: 0 on success, negative error code on failure
 */
int __init tquic_nat_lifecycle_module_init(void);

/**
 * tquic_nat_lifecycle_module_exit - Clean up NAT lifecycle subsystem
 */
void __exit tquic_nat_lifecycle_module_exit(void);

/*
 * =============================================================================
 * Helper Functions for NAT Type Strings
 * =============================================================================
 */

/**
 * tquic_nat_type_to_string - Convert NAT type to human-readable string
 * @type: NAT type
 * Return: String representation
 */
static inline const char *tquic_nat_type_to_string(enum tquic_nat_type type)
{
	switch (type) {
	case TQUIC_NAT_TYPE_NONE:
		return "None (Direct)";
	case TQUIC_NAT_TYPE_FULL_CONE:
		return "Full Cone";
	case TQUIC_NAT_TYPE_RESTRICTED_CONE:
		return "Restricted Cone";
	case TQUIC_NAT_TYPE_PORT_RESTRICTED:
		return "Port Restricted";
	case TQUIC_NAT_TYPE_SYMMETRIC:
		return "Symmetric";
	case TQUIC_NAT_TYPE_CARRIER_GRADE:
		return "Carrier-Grade (CGNAT)";
	case TQUIC_NAT_TYPE_UNKNOWN:
	default:
		return "Unknown";
	}
}

/**
 * tquic_nat_binding_state_to_string - Convert binding state to string
 * @state: Binding state
 * Return: String representation
 */
static inline const char *tquic_nat_binding_state_to_string(
	enum tquic_nat_binding_state state)
{
	switch (state) {
	case TQUIC_NAT_BINDING_ACTIVE:
		return "Active";
	case TQUIC_NAT_BINDING_EXPIRING:
		return "Expiring";
	case TQUIC_NAT_BINDING_EXPIRED:
		return "Expired";
	case TQUIC_NAT_BINDING_REFRESHING:
		return "Refreshing";
	case TQUIC_NAT_BINDING_UNKNOWN:
	default:
		return "Unknown";
	}
}

#endif /* _TQUIC_NAT_LIFECYCLE_H */
