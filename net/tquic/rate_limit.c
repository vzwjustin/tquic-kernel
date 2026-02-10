// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Connection Rate Limiting for DoS Protection
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Implements connection rate limiting using a token bucket algorithm with
 * per-IP tracking for DoS protection on QUIC servers. Uses RCU for lock-free
 * read path and automatic cleanup of stale entries.
 *
 * Features:
 *   - Global rate limiting: Controls overall server connection rate
 *   - Per-IP rate limiting: Prevents single IP from exhausting resources
 *   - Token bucket algorithm: Smooth rate limiting with burst support
 *   - RCU-based lookups: High performance under heavy load
 *   - Automatic garbage collection: Cleans stale per-IP entries
 *
 * The rate limiter is designed to be the first line of defense against
 * connection flood attacks, operating before any connection state is allocated.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": rate_limit: " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/rhashtable.h>
#include <linux/jhash.h>
#include <linux/random.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/workqueue.h>
#include <linux/ratelimit.h>
#include <net/sock.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/tquic.h>

#include "rate_limit.h"
#include "tquic_mib.h"
#include "tquic_debug.h"
#include "protocol.h"

/*
 * =============================================================================
 * Global Configuration
 * =============================================================================
 */

/* Default rate limit configuration */
struct tquic_rate_limit_config tquic_rate_limit_config = {
	.enabled = TQUIC_RATE_LIMIT_DEFAULT_ENABLED,
	.max_connections_per_second = TQUIC_RATE_LIMIT_DEFAULT_MAX_CONN_PER_SEC,
	.max_connections_burst = TQUIC_RATE_LIMIT_DEFAULT_MAX_BURST,
	.per_ip_rate_limit = TQUIC_RATE_LIMIT_DEFAULT_PER_IP_LIMIT,
};
EXPORT_SYMBOL_GPL(tquic_rate_limit_config);

/* Per-network namespace state */
static unsigned int tquic_rate_limit_net_id;

static struct tquic_rate_limit_state *tquic_rate_limit_pernet(struct net *net)
{
	return net_generic(net, tquic_rate_limit_net_id);
}

/* Rate limit logging */
static DEFINE_RATELIMIT_STATE(rate_limit_log_rs, HZ, 5);

/*
 * =============================================================================
 * Token Bucket Implementation
 * =============================================================================
 */

/**
 * tquic_rate_limiter_init - Initialize a rate limiter
 */
void tquic_rate_limiter_init(struct tquic_rate_limiter *limiter,
			     u32 rate_per_second, u32 burst)
{
	s64 scaled_burst;
	s64 scaled_rate;

	spin_lock_init(&limiter->lock);

	/* Scale values for precision */
	scaled_burst = (s64)burst * TQUIC_RATE_LIMIT_TOKEN_SCALE;
	scaled_rate = ((s64)rate_per_second * TQUIC_RATE_LIMIT_TOKEN_SCALE) / 1000;

	limiter->max_tokens = scaled_burst;
	limiter->refill_rate = scaled_rate;  /* tokens per millisecond */
	limiter->last_refill = jiffies;

	/* Start with full bucket */
	atomic64_set(&limiter->tokens, scaled_burst);
}
EXPORT_SYMBOL_GPL(tquic_rate_limiter_init);

/**
 * tquic_rate_limiter_refill - Refill tokens based on elapsed time
 * @limiter: Rate limiter
 *
 * Must be called with limiter->lock held.
 */
static void tquic_rate_limiter_refill(struct tquic_rate_limiter *limiter)
{
	unsigned long now = jiffies;
	unsigned long elapsed_jiffies;
	unsigned long elapsed_ms;
	s64 tokens, new_tokens;

	if (!time_after(now, limiter->last_refill))
		return;

	elapsed_jiffies = now - limiter->last_refill;
	elapsed_ms = jiffies_to_msecs(elapsed_jiffies);

	if (elapsed_ms == 0)
		return;

	/* Calculate tokens to add; cast elapsed_ms to s64 for 32-bit safety */
	new_tokens = (s64)elapsed_ms * limiter->refill_rate;
	if (new_tokens <= 0)
		return;

	tokens = atomic64_read(&limiter->tokens);
	tokens = min(tokens + new_tokens, limiter->max_tokens);
	atomic64_set(&limiter->tokens, tokens);

	limiter->last_refill = now;
}

/**
 * tquic_rate_limiter_allow - Check if connection is allowed
 */
bool tquic_rate_limiter_allow(struct tquic_rate_limiter *limiter)
{
	s64 tokens;
	s64 cost = TQUIC_RATE_LIMIT_TOKEN_SCALE;
	unsigned long flags;
	bool allowed;

	/*
	 * Fast path: Try atomic compare-and-swap without lock.
	 * This avoids the race where multiple CPUs see sufficient
	 * tokens and all subtract, driving the count deeply negative.
	 */
	do {
		tokens = atomic64_read(&limiter->tokens);
		if (tokens < cost)
			break;  /* Not enough tokens - fall to slow path */
		if (atomic64_try_cmpxchg(&limiter->tokens, &tokens,
					  tokens - cost))
			return true;
		/* CAS failed - another CPU modified tokens, retry */
	} while (tokens >= cost);

	/*
	 * Slow path: Need to refill and/or check more carefully.
	 */
	spin_lock_irqsave(&limiter->lock, flags);

	/* Refill based on elapsed time */
	tquic_rate_limiter_refill(limiter);

	/* Check if we have tokens now */
	tokens = atomic64_read(&limiter->tokens);
	if (tokens >= cost) {
		atomic64_sub(cost, &limiter->tokens);
		allowed = true;
	} else {
		allowed = false;
	}

	spin_unlock_irqrestore(&limiter->lock, flags);

	return allowed;
}
EXPORT_SYMBOL_GPL(tquic_rate_limiter_allow);

/**
 * tquic_rate_limiter_cleanup - Cleanup a rate limiter
 */
void tquic_rate_limiter_cleanup(struct tquic_rate_limiter *limiter)
{
	/* Nothing to free - all inline */
}
EXPORT_SYMBOL_GPL(tquic_rate_limiter_cleanup);

/**
 * tquic_rate_limiter_update_config - Update rate limiter configuration
 */
void tquic_rate_limiter_update_config(struct tquic_rate_limiter *limiter,
				      u32 rate_per_second, u32 burst)
{
	s64 scaled_burst;
	s64 scaled_rate;
	s64 current_tokens;
	unsigned long flags;

	scaled_burst = (s64)burst * TQUIC_RATE_LIMIT_TOKEN_SCALE;
	scaled_rate = ((s64)rate_per_second * TQUIC_RATE_LIMIT_TOKEN_SCALE) / 1000;

	spin_lock_irqsave(&limiter->lock, flags);

	limiter->max_tokens = scaled_burst;
	limiter->refill_rate = scaled_rate;

	/* Cap current tokens to new max */
	current_tokens = atomic64_read(&limiter->tokens);
	if (current_tokens > scaled_burst)
		atomic64_set(&limiter->tokens, scaled_burst);

	spin_unlock_irqrestore(&limiter->lock, flags);
}
EXPORT_SYMBOL_GPL(tquic_rate_limiter_update_config);

/*
 * =============================================================================
 * Per-IP Hash Table Operations
 * =============================================================================
 */

static u32 tquic_rate_limit_addr_hash(const struct sockaddr_storage *addr)
{
	if (addr->ss_family == AF_INET) {
		const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
		return jhash_1word(sin->sin_addr.s_addr, 0);
	}
#if IS_ENABLED(CONFIG_IPV6)
	if (addr->ss_family == AF_INET6) {
		const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;
		return jhash2((u32 *)&sin6->sin6_addr, 4, 0);
	}
#endif
	return 0;
}

static u32 tquic_rate_limit_entry_hash(const void *data, u32 len, u32 seed)
{
	const struct tquic_per_ip_entry *entry = data;
	return tquic_rate_limit_addr_hash(&entry->addr);
}

static u32 tquic_rate_limit_key_hash(const void *data, u32 len, u32 seed)
{
	const struct sockaddr_storage *addr = data;
	return tquic_rate_limit_addr_hash(addr);
}

static int tquic_rate_limit_entry_cmp(struct rhashtable_compare_arg *arg,
				      const void *obj)
{
	const struct sockaddr_storage *addr = arg->key;
	const struct tquic_per_ip_entry *entry = obj;

	if (addr->ss_family != entry->addr.ss_family)
		return 1;

	if (addr->ss_family == AF_INET) {
		const struct sockaddr_in *a = (const struct sockaddr_in *)addr;
		const struct sockaddr_in *b = (const struct sockaddr_in *)&entry->addr;
		return a->sin_addr.s_addr != b->sin_addr.s_addr;
	}
#if IS_ENABLED(CONFIG_IPV6)
	if (addr->ss_family == AF_INET6) {
		const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)addr;
		const struct sockaddr_in6 *b = (const struct sockaddr_in6 *)&entry->addr;
		return !ipv6_addr_equal(&a->sin6_addr, &b->sin6_addr);
	}
#endif
	return 1;
}

static const struct rhashtable_params tquic_rate_limit_ht_params = {
	.key_len = 0,  /* Custom compare */
	.key_offset = offsetof(struct tquic_per_ip_entry, addr),
	.head_offset = offsetof(struct tquic_per_ip_entry, node),
	.hashfn = tquic_rate_limit_key_hash,
	.obj_hashfn = tquic_rate_limit_entry_hash,
	.obj_cmpfn = tquic_rate_limit_entry_cmp,
	.automatic_shrinking = true,
};

/*
 * =============================================================================
 * Per-IP Entry Management
 * =============================================================================
 */

static struct tquic_per_ip_entry *
tquic_rate_limit_entry_alloc(const struct sockaddr_storage *addr)
{
	struct tquic_per_ip_entry *entry;

	entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
	if (!entry)
		return NULL;

	memcpy(&entry->addr, addr, sizeof(entry->addr));
	spin_lock_init(&entry->lock);

	/* Initialize per-IP rate limiter with configured limit */
	tquic_rate_limiter_init(&entry->limiter,
				tquic_rate_limit_config.per_ip_rate_limit,
				tquic_rate_limit_config.per_ip_rate_limit);

	entry->first_seen = ktime_get();
	entry->last_seen = entry->first_seen;

	atomic64_set(&entry->conn_count, 0);
	atomic64_set(&entry->drop_count, 0);

	return entry;
}

static void tquic_rate_limit_entry_free_rcu(struct rcu_head *head)
{
	struct tquic_per_ip_entry *entry =
		container_of(head, struct tquic_per_ip_entry, rcu_head);

	tquic_rate_limiter_cleanup(&entry->limiter);
	kfree(entry);
}

static void tquic_rate_limit_entry_put(struct tquic_per_ip_entry *entry)
{
	call_rcu(&entry->rcu_head, tquic_rate_limit_entry_free_rcu);
}

/*
 * =============================================================================
 * Rate Limit Check Implementation
 * =============================================================================
 */

/**
 * tquic_rate_limit_check_global - Check global rate limit
 * @state: Rate limiter state
 *
 * Return: true if allowed, false if rate limited
 */
static bool tquic_rate_limit_check_global(struct tquic_rate_limit_state *state)
{
	return tquic_rate_limiter_allow(&state->global_limiter);
}

/**
 * tquic_rate_limit_check_per_ip - Check per-IP rate limit
 * @state: Rate limiter state
 * @addr: Source address
 *
 * Return: true if allowed, false if rate limited
 */
static bool tquic_rate_limit_check_per_ip(struct tquic_rate_limit_state *state,
					  const struct sockaddr_storage *addr)
{
	struct tquic_per_ip_entry *entry;
	bool allowed;

	/* Lookup existing entry under RCU */
	rcu_read_lock();
	entry = rhashtable_lookup(&state->per_ip_ht, addr,
				  tquic_rate_limit_ht_params);

	if (!entry) {
		rcu_read_unlock();

		/*
		 * Enforce per-IP entry cap to prevent unbounded memory
		 * growth under DDoS.  When the limit is reached, fall
		 * back to global-only rate limiting (return true here
		 * so the caller still checks the global limiter).
		 */
		if (state->max_ip_entries &&
		    atomic_read(&state->ip_entry_count) >=
		    (int)state->max_ip_entries)
			return true;  /* fall back to global limit */

		/* Allocate new entry */
		entry = tquic_rate_limit_entry_alloc(addr);
		if (!entry) {
			/*
			 * Memory pressure - fail closed to prevent bypass.
			 * Under DDoS conditions, allowing all connections when
			 * memory is scarce would defeat the rate limiter.
			 */
			atomic64_inc(&state->stats.total_per_ip_denied);
			return false;
		}

		/* Insert into hash table */
		if (rhashtable_insert_fast(&state->per_ip_ht, &entry->node,
					   tquic_rate_limit_ht_params)) {
			/* Race - another entry was inserted */
			kfree(entry);

			rcu_read_lock();
			entry = rhashtable_lookup(&state->per_ip_ht, addr,
						  tquic_rate_limit_ht_params);
			if (!entry) {
				rcu_read_unlock();
				return false;  /* Fail closed */
			}
		} else {
			/* Successfully inserted - track entry count */
			atomic_inc(&state->ip_entry_count);
			atomic_inc(&state->stats.active_entries);

			rcu_read_lock();
			entry = rhashtable_lookup(&state->per_ip_ht, addr,
						  tquic_rate_limit_ht_params);
			if (!entry) {
				rcu_read_unlock();
				return false;  /* Fail closed */
			}
		}
	}

	/* Update last seen time */
	entry->last_seen = ktime_get();

	/* Increment connection attempt count */
	atomic64_inc(&entry->conn_count);

	/* Check per-IP rate limit */
	allowed = tquic_rate_limiter_allow(&entry->limiter);

	if (!allowed) {
		atomic64_inc(&entry->drop_count);
		atomic64_inc(&state->stats.total_per_ip_denied);

		/* Log if rate limiting is happening */
		if (__ratelimit(&rate_limit_log_rs)) {
			if (addr->ss_family == AF_INET) {
				const struct sockaddr_in *sin =
					(const struct sockaddr_in *)addr;
				tquic_info("per-IP rate limit: %pI4 (attempts=%lld, drops=%lld)\n",
					&sin->sin_addr,
					atomic64_read(&entry->conn_count),
					atomic64_read(&entry->drop_count));
			}
#if IS_ENABLED(CONFIG_IPV6)
			else if (addr->ss_family == AF_INET6) {
				const struct sockaddr_in6 *sin6 =
					(const struct sockaddr_in6 *)addr;
				tquic_info("per-IP rate limit: %pI6c (attempts=%lld, drops=%lld)\n",
					&sin6->sin6_addr,
					atomic64_read(&entry->conn_count),
					atomic64_read(&entry->drop_count));
			}
#endif
		}
	}

	rcu_read_unlock();

	return allowed;
}

bool tquic_rate_limit_check(struct net *net,
			    const struct sockaddr_storage *src_addr)
{
	struct tquic_rate_limit_state *state;
	bool global_ok, per_ip_ok;

	state = tquic_rate_limit_pernet(net);
	if (!state || !state->initialized)
		return true;

	if (!tquic_rate_limit_config.enabled)
		return true;

	/* Update statistics */
	atomic64_inc(&state->stats.total_checked);
	atomic_inc(&state->rate_window_count);

	/* Check global rate limit first */
	global_ok = tquic_rate_limit_check_global(state);
	if (!global_ok) {
		atomic64_inc(&state->stats.total_denied);
		return false;
	}

	/* Check per-IP rate limit */
	per_ip_ok = tquic_rate_limit_check_per_ip(state, src_addr);
	if (!per_ip_ok)
		return false;

	/* Both checks passed */
	atomic64_inc(&state->stats.total_allowed);
	return true;
}
EXPORT_SYMBOL_GPL(tquic_rate_limit_check);

bool tquic_rate_limit_check_initial(struct net *net,
				    const struct sockaddr_storage *src_addr,
				    const u8 *dcid, u8 dcid_len)
{
	/* For Initial packets, use the standard rate limit check */
	return tquic_rate_limit_check(net, src_addr);
}
EXPORT_SYMBOL_GPL(tquic_rate_limit_check_initial);

/*
 * =============================================================================
 * Garbage Collection
 * =============================================================================
 */

static void tquic_rate_limit_gc_work_fn(struct work_struct *work)
{
	struct tquic_rate_limit_state *state =
		container_of(work, struct tquic_rate_limit_state, gc_work.work);
	struct tquic_per_ip_entry *entry;
	struct rhashtable_iter iter;
	ktime_t now = ktime_get();
	ktime_t timeout_ns;
	int removed = 0;

	if (!state->initialized)
		return;

	timeout_ns = ms_to_ktime(TQUIC_RATE_LIMIT_ENTRY_TIMEOUT_MS);

	rhashtable_walk_enter(&state->per_ip_ht, &iter);
	rhashtable_walk_start(&iter);

	while ((entry = rhashtable_walk_next(&iter)) != NULL) {
		if (IS_ERR(entry))
			continue;

		/* Check if entry is stale */
		if (ktime_after(now, ktime_add(entry->last_seen, timeout_ns))) {
			/* Remove from hash table */
			if (rhashtable_remove_fast(&state->per_ip_ht,
						   &entry->node,
						   tquic_rate_limit_ht_params) == 0) {
				tquic_rate_limit_entry_put(entry);
				atomic_dec(&state->ip_entry_count);
				atomic_dec(&state->stats.active_entries);
				removed++;
			}
		}
	}

	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);

	if (removed > 0)
		tquic_dbg("garbage collected %d stale entries\n", removed);

	/* Reschedule */
	if (state->initialized) {
		schedule_delayed_work(&state->gc_work,
				      msecs_to_jiffies(TQUIC_RATE_LIMIT_GC_INTERVAL_MS));
	}
}

int tquic_rate_limit_cleanup_expired(struct net *net)
{
	struct tquic_rate_limit_state *state = tquic_rate_limit_pernet(net);

	if (!state || !state->initialized)
		return 0;

	/* Cancel pending work and run immediately */
	cancel_delayed_work_sync(&state->gc_work);
	tquic_rate_limit_gc_work_fn(&state->gc_work.work);

	/* Reschedule for future */
	if (state->initialized) {
		schedule_delayed_work(&state->gc_work,
				      msecs_to_jiffies(TQUIC_RATE_LIMIT_GC_INTERVAL_MS));
	}

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_rate_limit_cleanup_expired);

/*
 * =============================================================================
 * Rate Calculation
 * =============================================================================
 */

static void tquic_rate_limit_rate_calc_work_fn(struct work_struct *work)
{
	struct tquic_rate_limit_state *state =
		container_of(work, struct tquic_rate_limit_state, rate_calc_work.work);
	unsigned long now = jiffies;
	unsigned long elapsed_ms;
	int count, rate;

	if (!state->initialized)
		return;

	elapsed_ms = jiffies_to_msecs(now - state->rate_window_start);
	if (elapsed_ms == 0)
		elapsed_ms = 1;

	count = atomic_xchg(&state->rate_window_count, 0);
	/*
	 * Cast count to s64 before multiplying by 1000 to prevent
	 * integer overflow when count exceeds INT_MAX/1000 (~2.1M).
	 */
	rate = (int)(((s64)count * 1000) / elapsed_ms);

	state->rate_window_start = now;

	atomic_set(&state->stats.current_rate, rate);

	/* Update peak rate */
	if (rate > atomic_read(&state->stats.peak_rate))
		atomic_set(&state->stats.peak_rate, rate);

	/* Reschedule */
	if (state->initialized) {
		schedule_delayed_work(&state->rate_calc_work,
				      msecs_to_jiffies(1000));  /* 1 second */
	}
}

/*
 * =============================================================================
 * Statistics
 * =============================================================================
 */

void tquic_rate_limit_get_stats(struct net *net,
				struct tquic_rate_limit_stats *stats)
{
	struct tquic_rate_limit_state *state = tquic_rate_limit_pernet(net);

	if (!state || !state->initialized) {
		memset(stats, 0, sizeof(*stats));
		return;
	}

	/* Copy atomic values */
	atomic64_set(&stats->total_checked,
		     atomic64_read(&state->stats.total_checked));
	atomic64_set(&stats->total_allowed,
		     atomic64_read(&state->stats.total_allowed));
	atomic64_set(&stats->total_denied,
		     atomic64_read(&state->stats.total_denied));
	atomic64_set(&stats->total_per_ip_denied,
		     atomic64_read(&state->stats.total_per_ip_denied));
	atomic_set(&stats->current_rate,
		   atomic_read(&state->stats.current_rate));
	atomic_set(&stats->peak_rate,
		   atomic_read(&state->stats.peak_rate));
	atomic_set(&stats->active_entries,
		   atomic_read(&state->stats.active_entries));
}
EXPORT_SYMBOL_GPL(tquic_rate_limit_get_stats);

/*
 * =============================================================================
 * Sysctl Accessors
 * =============================================================================
 */

int tquic_sysctl_get_rate_limit_enabled(void)
{
	return tquic_rate_limit_config.enabled;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_rate_limit_enabled);

int tquic_sysctl_get_max_connections_per_second(void)
{
	return tquic_rate_limit_config.max_connections_per_second;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_max_connections_per_second);

int tquic_sysctl_get_max_connections_burst(void)
{
	return tquic_rate_limit_config.max_connections_burst;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_max_connections_burst);

int tquic_sysctl_get_per_ip_rate_limit(void)
{
	return tquic_rate_limit_config.per_ip_rate_limit;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_per_ip_rate_limit);

/*
 * =============================================================================
 * Initialization and Cleanup
 * =============================================================================
 */

int tquic_rate_limit_init(struct net *net)
{
	struct tquic_rate_limit_state *state;
	int ret;

	state = tquic_rate_limit_pernet(net);
	if (!state)
		return -EINVAL;

	memset(state, 0, sizeof(*state));
	spin_lock_init(&state->lock);
	state->net = net;

	/* Initialize global rate limiter */
	tquic_rate_limiter_init(&state->global_limiter,
				tquic_rate_limit_config.max_connections_per_second,
				tquic_rate_limit_config.max_connections_burst);

	/* Initialize per-IP hash table */
	ret = rhashtable_init(&state->per_ip_ht, &tquic_rate_limit_ht_params);
	if (ret) {
		tquic_err("failed to initialize per-IP hash table: %d\n", ret);
		return ret;
	}

	/* Initialize work items */
	INIT_DELAYED_WORK(&state->gc_work, tquic_rate_limit_gc_work_fn);
	INIT_DELAYED_WORK(&state->rate_calc_work, tquic_rate_limit_rate_calc_work_fn);

	/* Initialize rate window */
	state->rate_window_start = jiffies;
	atomic_set(&state->rate_window_count, 0);

	/* Cap per-IP hash table to prevent unbounded memory growth */
	state->max_ip_entries = 100000;
	atomic_set(&state->ip_entry_count, 0);

	state->initialized = true;

	/* Start workers */
	schedule_delayed_work(&state->gc_work,
			      msecs_to_jiffies(TQUIC_RATE_LIMIT_GC_INTERVAL_MS));
	schedule_delayed_work(&state->rate_calc_work,
			      msecs_to_jiffies(1000));

	tquic_info("initialized for net namespace\n");
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_rate_limit_init);

void tquic_rate_limit_exit(struct net *net)
{
	struct tquic_rate_limit_state *state = tquic_rate_limit_pernet(net);
	struct tquic_per_ip_entry *entry;
	struct rhashtable_iter iter;

	if (!state || !state->initialized)
		return;

	state->initialized = false;

	/* Cancel workers */
	cancel_delayed_work_sync(&state->gc_work);
	cancel_delayed_work_sync(&state->rate_calc_work);

	/* Free all entries */
	rhashtable_walk_enter(&state->per_ip_ht, &iter);
	rhashtable_walk_start(&iter);

	while ((entry = rhashtable_walk_next(&iter)) != NULL) {
		if (IS_ERR(entry))
			continue;
		rhashtable_remove_fast(&state->per_ip_ht, &entry->node,
				       tquic_rate_limit_ht_params);
		tquic_rate_limit_entry_put(entry);
	}

	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);

	/* Destroy hash table */
	rhashtable_destroy(&state->per_ip_ht);

	/* Cleanup global limiter */
	tquic_rate_limiter_cleanup(&state->global_limiter);

	tquic_info("cleaned up for net namespace\n");
}
EXPORT_SYMBOL_GPL(tquic_rate_limit_exit);

/*
 * =============================================================================
 * Module Init/Exit
 * =============================================================================
 */

static int __net_init tquic_rate_limit_net_init(struct net *net)
{
	return tquic_rate_limit_init(net);
}

static void __net_exit tquic_rate_limit_net_exit(struct net *net)
{
	tquic_rate_limit_exit(net);
}

static struct pernet_operations tquic_rate_limit_net_ops = {
	.init = tquic_rate_limit_net_init,
	.exit = tquic_rate_limit_net_exit,
	.id = &tquic_rate_limit_net_id,
	.size = sizeof(struct tquic_rate_limit_state),
};

int __init tquic_rate_limit_module_init(void)
{
	int ret;

	ret = register_pernet_subsys(&tquic_rate_limit_net_ops);
	if (ret) {
		tquic_err("rate_limit: failed to register pernet operations: %d\n", ret);
		return ret;
	}

	tquic_info("rate_limit: initialized (global=%d/s burst=%d, per-ip=%d/s)\n",
		   tquic_rate_limit_config.max_connections_per_second,
		   tquic_rate_limit_config.max_connections_burst,
		   tquic_rate_limit_config.per_ip_rate_limit);

	return 0;
}

void __exit tquic_rate_limit_module_exit(void)
{
	unregister_pernet_subsys(&tquic_rate_limit_net_ops);

	/* Wait for RCU callbacks */
	synchronize_rcu();

	tquic_info("rate_limit: module exited\n");
}

MODULE_DESCRIPTION("TQUIC Connection Rate Limiting for DoS Protection");
MODULE_LICENSE("GPL");
