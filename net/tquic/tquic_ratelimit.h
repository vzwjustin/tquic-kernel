/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: Connection Rate Limiting for DDoS Protection
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * This header provides connection rate limiting using a token bucket
 * algorithm with per-IP tracking for DDoS protection on QUIC servers.
 *
 * Features:
 *   - Per-source-IP rate limiting with hash table tracking
 *   - Token bucket algorithm for smooth rate limiting with burst support
 *   - SYN cookie-style validation for QUIC Initial packets under attack
 *   - Automatic cleanup of stale rate limit entries via RCU
 *   - Rate-limited logging to prevent log floods
 *   - Sysctl tunables for max_conn_rate, rate_limit_window, burst_limit
 *   - Integration with netfilter hooks
 *
 * Architecture:
 *   The rate limiter uses a lockless hash table (rhashtable) for O(1)
 *   per-IP lookups with RCU for read-side scalability. Write operations
 *   use per-bucket spinlocks to minimize contention.
 *
 * Token Bucket Algorithm:
 *   Each source IP has a token bucket with:
 *   - tokens: Current token count (atomic for lock-free reads)
 *   - last_refill: Timestamp of last token refill
 *   - Tokens are replenished at rate = max_conn_rate / rate_limit_window
 *   - Burst capacity = burst_limit tokens
 */

#ifndef _NET_TQUIC_RATELIMIT_H
#define _NET_TQUIC_RATELIMIT_H

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/rhashtable.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <linux/atomic.h>
#include <linux/ratelimit.h>
#include <net/tquic.h>

/*
 * Rate limit constants
 */
#define TQUIC_RL_HASH_BITS		14		/* 16K buckets */
#define TQUIC_RL_HASH_SIZE		(1 << TQUIC_RL_HASH_BITS)
#define TQUIC_RL_GC_INTERVAL_MS		10000		/* 10 seconds */
#define TQUIC_RL_ENTRY_TIMEOUT_MS	60000		/* 1 minute stale timeout */
#define TQUIC_RL_LOG_INTERVAL_MS	1000		/* Log at most once per second */

/* Default sysctl values */
#define TQUIC_RL_DEFAULT_MAX_CONN_RATE	1000		/* connections/sec */
#define TQUIC_RL_DEFAULT_RATE_WINDOW_MS	1000		/* 1 second window */
#define TQUIC_RL_DEFAULT_BURST_LIMIT	50		/* burst capacity */
#define TQUIC_RL_DEFAULT_ENABLED	1		/* enabled by default */

/* SYN cookie validation constants */
#define TQUIC_COOKIE_LIFETIME_MS	60000		/* 1 minute */
#define TQUIC_COOKIE_SECRET_LEN		32		/* 256-bit secret */
#define TQUIC_COOKIE_ROTATE_INTERVAL_MS	300000		/* 5 minutes */

/* Maximum number of rate limit buckets to prevent memory exhaustion */
#define TQUIC_RATELIMIT_MAX_BUCKETS	65536

/* Attack detection thresholds */
#define TQUIC_RL_ATTACK_THRESHOLD	10000		/* conn/sec triggers attack mode */
#define TQUIC_RL_ATTACK_HYSTERESIS_MS	30000		/* 30 sec hysteresis */

/**
 * enum tquic_rl_action - Rate limit decision
 * @TQUIC_RL_ACCEPT: Accept the connection attempt
 * @TQUIC_RL_RATE_LIMITED: Drop due to rate limit exceeded
 * @TQUIC_RL_COOKIE_REQUIRED: Require SYN cookie validation
 * @TQUIC_RL_BLACKLISTED: Source is blacklisted
 */
enum tquic_rl_action {
	TQUIC_RL_ACCEPT = 0,
	TQUIC_RL_RATE_LIMITED,
	TQUIC_RL_COOKIE_REQUIRED,
	TQUIC_RL_BLACKLISTED,
};

/**
 * struct tquic_rl_bucket - Token bucket state for a source IP
 * @node: RCU hash table linkage
 * @addr: Source IP address (IPv4 or IPv6)
 * @tokens: Current token count (scaled by 1000 for precision)
 * @last_refill: Timestamp of last token refill (jiffies)
 * @conn_count: Total connection attempts from this IP
 * @drop_count: Total dropped connections from this IP
 * @first_seen: Timestamp when this IP was first seen
 * @last_seen: Timestamp of most recent packet
 * @blacklisted: Set if IP is blacklisted
 * @cookie_required: Set if requiring cookie validation
 * @lock: Per-bucket spinlock for updates
 * @rcu_head: RCU callback head for deferred freeing
 */
struct tquic_rl_bucket {
	struct rhash_head node;
	struct sockaddr_storage addr;

	atomic_t tokens;		/* Scaled by 1000 */
	unsigned long last_refill;

	atomic64_t conn_count;
	atomic64_t drop_count;

	ktime_t first_seen;
	ktime_t last_seen;

	bool blacklisted;
	ktime_t blacklist_expires;	/* 0 = permanent blacklist */
	bool cookie_required;

	spinlock_t lock;
	struct rcu_head rcu_head;
};

/**
 * struct tquic_rl_cookie_secret - SYN cookie cryptographic secret
 * @secret: 256-bit secret for cookie generation
 * @generation: Secret generation for rotation
 * @valid_until: Timestamp when secret expires
 * @lock: Protects secret during rotation
 */
struct tquic_rl_cookie_secret {
	u8 secret[TQUIC_COOKIE_SECRET_LEN];
	u32 generation;
	ktime_t valid_until;
	spinlock_t lock;
};

/**
 * struct tquic_rl_stats - Global rate limiting statistics
 * @total_checked: Total connection attempts checked
 * @total_accepted: Total connections accepted
 * @total_rate_limited: Total connections rate limited
 * @total_cookie_required: Total connections requiring cookie
 * @total_cookie_validated: Total cookies validated successfully
 * @total_cookie_failed: Total cookie validation failures
 * @total_blacklisted: Total connections from blacklisted IPs
 * @attack_mode_entered: Times attack mode was entered
 * @current_rate: Current connection rate (per second)
 * @peak_rate: Peak connection rate observed
 */
struct tquic_rl_stats {
	atomic64_t total_checked;
	atomic64_t total_accepted;
	atomic64_t total_rate_limited;
	atomic64_t total_cookie_required;
	atomic64_t total_cookie_validated;
	atomic64_t total_cookie_failed;
	atomic64_t total_blacklisted;
	atomic64_t attack_mode_entered;
	atomic_t current_rate;
	atomic_t peak_rate;
};

/**
 * struct tquic_rl_state - Global rate limiter state
 * @ht: RCU-safe hash table for per-IP buckets
 * @ht_params: Hash table parameters
 * @stats: Global statistics
 * @secrets: Cookie secrets (current and previous for rotation)
 * @gc_work: Garbage collection work item
 * @gc_timer: Garbage collection timer
 * @rate_calc_work: Rate calculation work item
 * @rate_calc_timer: Rate calculation timer
 * @attack_mode: Currently in attack mode
 * @attack_start: When attack mode was entered
 * @rate_window_start: Start of current rate calculation window
 * @rate_window_count: Connections in current window
 * @log_ratelimit: Rate limiter for log messages
 * @net: Network namespace
 * @enabled: Rate limiting enabled
 * @initialized: State is initialized
 * @lock: Global state lock
 */
struct tquic_rl_state {
	struct rhashtable ht;
	struct rhashtable_params ht_params;
	atomic_t bucket_count;

	struct tquic_rl_stats stats;

	struct tquic_rl_cookie_secret secrets[2];
	int current_secret;

	struct delayed_work gc_work;
	struct delayed_work rate_calc_work;

	bool attack_mode;
	ktime_t attack_start;

	unsigned long rate_window_start;
	atomic_t rate_window_count;

	struct ratelimit_state log_ratelimit;

	struct net *net;
	bool enabled;
	bool initialized;

	spinlock_t lock;
};

/*
 * =============================================================================
 * Sysctl Parameters
 * =============================================================================
 */

/**
 * struct tquic_rl_params - Configurable rate limit parameters
 * @enabled: Rate limiting enabled (0/1)
 * @max_conn_rate: Maximum connections per second per IP
 * @rate_limit_window_ms: Rate limit time window in milliseconds
 * @burst_limit: Maximum burst size (tokens)
 * @attack_threshold: Connections/sec to trigger attack mode
 * @cookie_lifetime_ms: SYN cookie validity duration
 * @gc_interval_ms: Garbage collection interval
 * @entry_timeout_ms: Stale entry timeout
 */
struct tquic_rl_params {
	int enabled;
	int max_conn_rate;
	int rate_limit_window_ms;
	int burst_limit;
	int attack_threshold;
	int cookie_lifetime_ms;
	int gc_interval_ms;
	int entry_timeout_ms;
};

/* Global parameters (set via sysctl) */
extern struct tquic_rl_params tquic_rl_params;

/*
 * =============================================================================
 * API Functions
 * =============================================================================
 */

/**
 * tquic_ratelimit_init - Initialize rate limiter subsystem
 * @net: Network namespace
 *
 * Allocates and initializes the rate limiter state including hash table,
 * cookie secrets, and garbage collection timers.
 *
 * Return: 0 on success, -errno on failure
 */
int tquic_ratelimit_init(struct net *net);

/**
 * tquic_ratelimit_exit - Cleanup rate limiter subsystem
 * @net: Network namespace
 *
 * Stops timers, frees all entries, and releases resources.
 */
void tquic_ratelimit_exit(struct net *net);

/**
 * tquic_ratelimit_check - Check if connection should be rate limited
 * @net: Network namespace
 * @src_addr: Source address of connection attempt
 * @is_initial: True if this is an Initial packet (new connection)
 *
 * Performs token bucket check for the source IP. Consumes one token
 * on success, returns rate limited if no tokens available.
 *
 * Return: TQUIC_RL_ACCEPT if allowed, TQUIC_RL_RATE_LIMITED if denied,
 *         TQUIC_RL_COOKIE_REQUIRED if cookie validation needed
 */
enum tquic_rl_action tquic_ratelimit_check(struct net *net,
					   const struct sockaddr_storage *src_addr,
					   bool is_initial);

/**
 * tquic_ratelimit_check_initial - Check rate limit for Initial packet
 * @net: Network namespace
 * @src_addr: Source address
 * @dcid: Destination Connection ID from packet
 * @dcid_len: DCID length
 * @token: Token from Initial packet (may be cookie)
 * @token_len: Token length
 *
 * Specialized check for Initial packets with optional cookie validation.
 *
 * Return: TQUIC_RL_ACCEPT, TQUIC_RL_RATE_LIMITED, or TQUIC_RL_COOKIE_REQUIRED
 */
enum tquic_rl_action tquic_ratelimit_check_initial(
	struct net *net,
	const struct sockaddr_storage *src_addr,
	const u8 *dcid, u8 dcid_len,
	const u8 *token, size_t token_len);

/**
 * tquic_ratelimit_generate_cookie - Generate SYN cookie for validation
 * @net: Network namespace
 * @src_addr: Source address
 * @dcid: Original DCID from Initial packet
 * @dcid_len: DCID length
 * @cookie: Output buffer for cookie (must be at least 32 bytes)
 * @cookie_len: Output cookie length
 *
 * Generates a cryptographic cookie encoding source IP, timestamp, and
 * DCID for SYN cookie-style validation of QUIC Initial packets.
 *
 * Return: 0 on success, -errno on failure
 */
int tquic_ratelimit_generate_cookie(struct net *net,
				    const struct sockaddr_storage *src_addr,
				    const u8 *dcid, u8 dcid_len,
				    u8 *cookie, size_t *cookie_len);

/**
 * tquic_ratelimit_validate_cookie - Validate SYN cookie
 * @net: Network namespace
 * @src_addr: Source address
 * @dcid: DCID from retry Initial packet
 * @dcid_len: DCID length
 * @cookie: Cookie from Initial packet token
 * @cookie_len: Cookie length
 * @original_dcid: Output original DCID if validation succeeds
 * @original_dcid_len: Output original DCID length
 *
 * Validates a cookie received in an Initial packet's token field.
 *
 * Return: 0 if valid, -EINVAL if invalid, -ETIMEDOUT if expired
 */
int tquic_ratelimit_validate_cookie(struct net *net,
				    const struct sockaddr_storage *src_addr,
				    const u8 *dcid, u8 dcid_len,
				    const u8 *cookie, size_t cookie_len,
				    u8 *original_dcid, u8 *original_dcid_len);

/**
 * tquic_ratelimit_blacklist_add - Add IP to blacklist
 * @net: Network namespace
 * @addr: Address to blacklist
 * @duration_ms: Blacklist duration (0 = permanent until manual remove)
 *
 * Immediately blacklists an IP address.
 *
 * Return: 0 on success, -errno on failure
 */
int tquic_ratelimit_blacklist_add(struct net *net,
				  const struct sockaddr_storage *addr,
				  u32 duration_ms);

/**
 * tquic_ratelimit_blacklist_remove - Remove IP from blacklist
 * @net: Network namespace
 * @addr: Address to remove from blacklist
 *
 * Return: 0 on success, -ENOENT if not found
 */
int tquic_ratelimit_blacklist_remove(struct net *net,
				     const struct sockaddr_storage *addr);

/**
 * tquic_ratelimit_get_stats - Get rate limiting statistics
 * @net: Network namespace
 * @stats: Output statistics structure
 *
 * Copies current statistics to caller-provided structure.
 */
void tquic_ratelimit_get_stats(struct net *net, struct tquic_rl_stats *stats);

/**
 * tquic_ratelimit_is_attack_mode - Check if in attack mode
 * @net: Network namespace
 *
 * Return: true if attack mode is active
 */
bool tquic_ratelimit_is_attack_mode(struct net *net);

/**
 * tquic_ratelimit_rotate_secret - Rotate cookie secrets
 * @net: Network namespace
 *
 * Forces immediate rotation of cookie secrets.
 *
 * Return: 0 on success
 */
int tquic_ratelimit_rotate_secret(struct net *net);

/*
 * =============================================================================
 * Sysctl Interface
 * =============================================================================
 */

/**
 * tquic_ratelimit_sysctl_init - Register sysctl parameters
 *
 * Registers rate limiting sysctls under net.tquic.ratelimit.*
 *
 * Return: 0 on success, -errno on failure
 */
int tquic_ratelimit_sysctl_init(void);

/**
 * tquic_ratelimit_sysctl_exit - Unregister sysctl parameters
 */
void tquic_ratelimit_sysctl_exit(void);

/* Sysctl accessors */
int tquic_sysctl_get_ratelimit_enabled(void);
int tquic_sysctl_get_max_conn_rate(void);
int tquic_sysctl_get_rate_limit_window(void);
int tquic_sysctl_get_burst_limit(void);

/*
 * =============================================================================
 * Netfilter Integration
 * =============================================================================
 */

/**
 * tquic_ratelimit_nf_check - Netfilter hook rate limit check
 * @skb: Packet buffer
 * @src_addr: Parsed source address
 *
 * Called from netfilter hooks for early rate limiting.
 *
 * Return: NF_ACCEPT or NF_DROP
 */
unsigned int tquic_ratelimit_nf_check(struct sk_buff *skb,
				      const struct sockaddr_storage *src_addr);

/*
 * =============================================================================
 * Proc Interface
 * =============================================================================
 */

/**
 * tquic_ratelimit_proc_show - Show rate limit state in /proc
 * @seq: Seq file
 *
 * Outputs current rate limit state and statistics.
 */
int tquic_ratelimit_proc_show(struct seq_file *seq, void *v);

/*
 * =============================================================================
 * MIB Counters - Note: MIB fields are defined in tquic_mib.h as enum members:
 * TQUIC_MIB_RATELIMIT_CHECKED, TQUIC_MIB_RATELIMIT_ACCEPTED, etc.
 * =============================================================================
 */

/*
 * =============================================================================
 * Module Init/Exit
 * =============================================================================
 */

/**
 * tquic_ratelimit_module_init - Initialize rate limiter module
 *
 * Called during TQUIC module initialization. Sets up crypto,
 * registers pernet operations and sysctls.
 *
 * Return: 0 on success, -errno on failure
 */
int __init tquic_ratelimit_module_init(void);

/**
 * tquic_ratelimit_module_exit - Cleanup rate limiter module
 *
 * Called during TQUIC module unload. Cleans up all resources.
 */
void __exit tquic_ratelimit_module_exit(void);

#endif /* _NET_TQUIC_RATELIMIT_H */
