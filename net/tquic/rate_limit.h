/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: Connection Rate Limiting for DoS Protection
 *
 * Copyright (c) 2026 Linux Foundation
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * This header provides connection rate limiting using a token bucket
 * algorithm with per-IP tracking for DoS protection on QUIC servers.
 *
 * Architecture:
 *   - Global rate limiter: Controls overall connection rate to the server
 *   - Per-IP rate limiter: Controls connection rate from individual IPs
 *   - Token bucket algorithm: Smooth rate limiting with burst support
 *   - RCU-based hash table: Lock-free reads for high performance
 *   - Automatic cleanup: Stale entries are garbage collected
 *
 * Sysctl Parameters:
 *   - net.tquic.rate_limit_enabled: Enable/disable rate limiting
 *   - net.tquic.max_connections_per_second: Global connection rate limit
 *   - net.tquic.max_connections_burst: Global burst capacity
 *   - net.tquic.per_ip_rate_limit: Per-IP connection rate limit
 */

#ifndef _NET_TQUIC_RATE_LIMIT_H
#define _NET_TQUIC_RATE_LIMIT_H

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/rhashtable.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <linux/atomic.h>
#include <linux/rcupdate.h>
#include <net/tquic.h>

/*
 * =============================================================================
 * Constants
 * =============================================================================
 */

/* Default sysctl values (matching user requirements) */
#define TQUIC_RATE_LIMIT_DEFAULT_ENABLED		1
#define TQUIC_RATE_LIMIT_DEFAULT_MAX_CONN_PER_SEC	10000
#define TQUIC_RATE_LIMIT_DEFAULT_MAX_BURST		1000
#define TQUIC_RATE_LIMIT_DEFAULT_PER_IP_LIMIT		100

/* Hash table configuration */
#define TQUIC_RATE_LIMIT_HASH_BITS		14
#define TQUIC_RATE_LIMIT_HASH_SIZE		(1 << TQUIC_RATE_LIMIT_HASH_BITS)

/* Timing constants */
#define TQUIC_RATE_LIMIT_GC_INTERVAL_MS		30000	/* 30 seconds */
#define TQUIC_RATE_LIMIT_ENTRY_TIMEOUT_MS	120000	/* 2 minutes */
#define TQUIC_RATE_LIMIT_REFILL_INTERVAL_MS	100	/* Token refill granularity */

/* Token scale factor for sub-token precision */
#define TQUIC_RATE_LIMIT_TOKEN_SCALE		1000

/*
 * =============================================================================
 * Rate Limit Configuration
 * =============================================================================
 */

/**
 * struct tquic_rate_limit_config - Rate limiter configuration
 * @enabled: Rate limiting enabled (0/1)
 * @max_connections_per_second: Global connection rate limit
 * @max_connections_burst: Maximum burst size (tokens)
 * @per_ip_rate_limit: Per-IP connection rate limit
 *
 * Configured via sysctl at net.tquic.*
 */
struct tquic_rate_limit_config {
	int enabled;
	int max_connections_per_second;
	int max_connections_burst;
	int per_ip_rate_limit;
};

/* Global configuration instance */
extern struct tquic_rate_limit_config tquic_rate_limit_config;

/*
 * =============================================================================
 * Token Bucket Implementation
 * =============================================================================
 */

/**
 * struct tquic_rate_limiter - Token bucket rate limiter
 * @tokens: Current token count (scaled by TQUIC_RATE_LIMIT_TOKEN_SCALE)
 * @max_tokens: Maximum bucket capacity (scaled)
 * @refill_rate: Tokens per millisecond (scaled)
 * @last_refill: Timestamp of last token refill (jiffies)
 * @lock: Spinlock protecting token updates
 *
 * Token bucket algorithm:
 *   - Tokens are replenished over time at refill_rate
 *   - Each connection consumes 1 token (scaled)
 *   - Connection allowed if tokens >= 1, denied otherwise
 *   - Burst handling: bucket can hold up to max_tokens
 */
struct tquic_rate_limiter {
	atomic64_t tokens;
	s64 max_tokens;
	s64 refill_rate;
	unsigned long last_refill;
	spinlock_t lock;
};

/*
 * =============================================================================
 * Per-IP Rate Limiting Structures
 * =============================================================================
 */

/**
 * struct tquic_per_ip_entry - Per-IP rate limit tracking entry
 * @node: RCU hash table linkage
 * @addr: Source IP address (IPv4 or IPv6)
 * @limiter: Token bucket for this IP
 * @conn_count: Total connection attempts from this IP
 * @drop_count: Total dropped connections from this IP
 * @first_seen: Timestamp when this IP was first seen
 * @last_seen: Timestamp of most recent connection attempt
 * @lock: Per-entry spinlock for updates
 * @rcu_head: RCU callback head for deferred freeing
 *
 * Each unique source IP gets its own rate limiting bucket.
 * Entries are garbage collected after TQUIC_RATE_LIMIT_ENTRY_TIMEOUT_MS
 * of inactivity.
 */
struct tquic_per_ip_entry {
	struct rhash_head node;
	struct sockaddr_storage addr;

	struct tquic_rate_limiter limiter;

	atomic64_t conn_count;
	atomic64_t drop_count;

	ktime_t first_seen;
	ktime_t last_seen;

	spinlock_t lock;
	struct rcu_head rcu_head;
};

/*
 * =============================================================================
 * Rate Limiter State
 * =============================================================================
 */

/**
 * struct tquic_rate_limit_stats - Rate limiting statistics
 * @total_checked: Total connection attempts checked
 * @total_allowed: Total connections allowed
 * @total_denied: Total connections denied (global limit)
 * @total_per_ip_denied: Total connections denied (per-IP limit)
 * @current_rate: Current connection rate (per second)
 * @peak_rate: Peak connection rate observed
 * @active_entries: Number of active per-IP entries
 */
struct tquic_rate_limit_stats {
	atomic64_t total_checked;
	atomic64_t total_allowed;
	atomic64_t total_denied;
	atomic64_t total_per_ip_denied;
	atomic_t current_rate;
	atomic_t peak_rate;
	atomic_t active_entries;
};

/**
 * struct tquic_rate_limit_state - Global rate limiter state
 * @global_limiter: Global token bucket for overall rate
 * @per_ip_ht: RCU-safe hash table for per-IP entries
 * @ht_params: Hash table parameters
 * @stats: Statistics
 * @gc_work: Garbage collection work item
 * @rate_calc_work: Rate calculation work item
 * @rate_window_start: Start of current rate calculation window
 * @rate_window_count: Connections in current window
 * @net: Network namespace
 * @initialized: State is initialized
 * @lock: Global state lock
 * @max_ip_entries: Maximum per-IP hash table entries (0 = unlimited)
 * @ip_entry_count: Current number of per-IP entries
 */
struct tquic_rate_limit_state {
	struct tquic_rate_limiter global_limiter;

	struct rhashtable per_ip_ht;
	struct rhashtable_params ht_params;

	struct tquic_rate_limit_stats stats;

	struct delayed_work gc_work;
	struct delayed_work rate_calc_work;

	unsigned long rate_window_start;
	atomic_t rate_window_count;

	struct net *net;
	bool initialized;

	spinlock_t lock;

	u32 max_ip_entries;
	atomic_t ip_entry_count;
};

/*
 * =============================================================================
 * API Functions
 * =============================================================================
 */

/**
 * tquic_rate_limiter_init - Initialize a rate limiter
 * @limiter: Rate limiter to initialize
 * @rate_per_second: Token replenishment rate (tokens/second)
 * @burst: Maximum bucket capacity (tokens)
 *
 * Initializes a token bucket rate limiter with the specified rate and
 * burst capacity. The bucket starts full to allow initial burst.
 */
void tquic_rate_limiter_init(struct tquic_rate_limiter *limiter,
			     u32 rate_per_second, u32 burst);

/**
 * tquic_rate_limiter_allow - Check if connection is allowed
 * @limiter: Rate limiter to check
 *
 * Attempts to consume a token from the bucket. If successful, the
 * connection is allowed. If the bucket is empty, the connection is denied.
 *
 * This function uses atomic operations for lock-free read path when
 * possible, falling back to spinlock for refill operations.
 *
 * Return: true if allowed, false if rate limited
 */
bool tquic_rate_limiter_allow(struct tquic_rate_limiter *limiter);

/**
 * tquic_rate_limiter_cleanup - Cleanup a rate limiter
 * @limiter: Rate limiter to cleanup
 *
 * Releases any resources associated with the rate limiter.
 * Safe to call on an already-cleaned or uninitialized limiter.
 */
void tquic_rate_limiter_cleanup(struct tquic_rate_limiter *limiter);

/**
 * tquic_rate_limiter_update_config - Update rate limiter configuration
 * @limiter: Rate limiter to update
 * @rate_per_second: New token rate
 * @burst: New burst capacity
 *
 * Dynamically updates the rate limiter configuration. Current tokens
 * are preserved up to the new maximum.
 */
void tquic_rate_limiter_update_config(struct tquic_rate_limiter *limiter,
				      u32 rate_per_second, u32 burst);

/*
 * =============================================================================
 * Global Rate Limit API
 * =============================================================================
 */

/**
 * tquic_rate_limit_init - Initialize rate limit subsystem for netns
 * @net: Network namespace
 *
 * Initializes the rate limiting subsystem for a network namespace.
 * This includes the global rate limiter, per-IP hash table, and
 * background workers.
 *
 * Return: 0 on success, -errno on failure
 */
int tquic_rate_limit_init(struct net *net);

/**
 * tquic_rate_limit_exit - Cleanup rate limit subsystem for netns
 * @net: Network namespace
 *
 * Releases all rate limiting resources for the network namespace.
 * Stops background workers and frees all entries.
 */
void tquic_rate_limit_exit(struct net *net);

/**
 * tquic_rate_limit_check - Check if connection should be rate limited
 * @net: Network namespace
 * @src_addr: Source address of connection attempt
 *
 * Performs both global and per-IP rate limit checks:
 * 1. Global check: Is overall server connection rate within limits?
 * 2. Per-IP check: Is this specific IP within its rate limit?
 *
 * Both checks must pass for the connection to be allowed.
 *
 * Return: true if connection allowed, false if rate limited
 */
bool tquic_rate_limit_check(struct net *net,
			    const struct sockaddr_storage *src_addr);

/**
 * tquic_rate_limit_check_initial - Check rate limit for Initial packet
 * @net: Network namespace
 * @src_addr: Source address
 * @dcid: Destination Connection ID from packet
 * @dcid_len: DCID length
 *
 * Specialized rate limit check for QUIC Initial packets (new connections).
 * This is called before allocating any connection state.
 *
 * Return: true if allowed, false if rate limited
 */
bool tquic_rate_limit_check_initial(struct net *net,
				    const struct sockaddr_storage *src_addr,
				    const u8 *dcid, u8 dcid_len);

/**
 * tquic_rate_limit_get_stats - Get rate limiting statistics
 * @net: Network namespace
 * @stats: Output statistics structure
 *
 * Copies current statistics to caller-provided structure.
 */
void tquic_rate_limit_get_stats(struct net *net,
				struct tquic_rate_limit_stats *stats);

/**
 * tquic_rate_limit_cleanup_expired - Force cleanup of expired entries
 * @net: Network namespace
 *
 * Forces immediate cleanup of expired per-IP entries.
 * Normally called automatically by the GC worker.
 *
 * Return: Number of entries cleaned up
 */
int tquic_rate_limit_cleanup_expired(struct net *net);

/*
 * =============================================================================
 * Sysctl Accessors
 * =============================================================================
 */

/**
 * tquic_sysctl_get_rate_limit_enabled - Check if rate limiting is enabled
 *
 * Return: 1 if enabled, 0 if disabled
 */
int tquic_sysctl_get_rate_limit_enabled(void);

/**
 * tquic_sysctl_get_max_connections_per_second - Get global rate limit
 *
 * Return: Maximum connections per second
 */
int tquic_sysctl_get_max_connections_per_second(void);

/**
 * tquic_sysctl_get_max_connections_burst - Get global burst limit
 *
 * Return: Maximum burst size
 */
int tquic_sysctl_get_max_connections_burst(void);

/**
 * tquic_sysctl_get_per_ip_rate_limit - Get per-IP rate limit
 *
 * Return: Per-IP rate limit (connections per second)
 */
int tquic_sysctl_get_per_ip_rate_limit(void);

/*
 * =============================================================================
 * Module Init/Exit
 * =============================================================================
 */

/**
 * tquic_rate_limit_module_init - Initialize rate limit module
 *
 * Called during TQUIC module initialization.
 *
 * Return: 0 on success, -errno on failure
 */
int __init tquic_rate_limit_module_init(void);

/**
 * tquic_rate_limit_module_exit - Cleanup rate limit module
 *
 * Called during TQUIC module unload.
 */
void __exit tquic_rate_limit_module_exit(void);

#endif /* _NET_TQUIC_RATE_LIMIT_H */
