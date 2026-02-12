// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Connection Rate Limiting for DDoS Protection
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Implements per-IP connection rate limiting using a token bucket algorithm
 * with RCU-based hash table for scalable lookups. Provides SYN cookie-style
 * validation for QUIC Initial packets under attack conditions.
 *
 * The rate limiter is designed for production deployment on high-traffic
 * QUIC servers with the following properties:
 *   - O(1) per-IP lookups via rhashtable
 *   - Lock-free reads using RCU
 *   - Per-bucket spinlocks for minimal write contention
 *   - Automatic garbage collection of stale entries
 *   - Attack detection with automatic cookie enforcement
 *   - Rate-limited logging to prevent log floods
 *
 * Token Bucket Implementation:
 *   - Tokens replenish at rate = max_conn_rate / rate_limit_window_ms
 *   - Each connection attempt consumes 1 token
 *   - Bucket capacity = burst_limit tokens
 *   - Tokens are stored scaled by 1000 for sub-token precision
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": ratelimit: " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/rhashtable.h>
#include <linux/jhash.h>
#include <linux/random.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/workqueue.h>
#include <linux/timer.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/sysctl.h>
#include <linux/netfilter.h>
#include <crypto/hash.h>
#include <crypto/utils.h>
#include <net/sock.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/tquic.h>

#include "tquic_ratelimit.h"
#include "tquic_mib.h"
#include "tquic_debug.h"
#include "protocol.h"
#include "tquic_compat.h"

/*
 * =============================================================================
 * Global State and Parameters
 * =============================================================================
 */

/* Default rate limit parameters */
struct tquic_rl_params tquic_rl_params = {
	.enabled = TQUIC_RL_DEFAULT_ENABLED,
	.max_conn_rate = TQUIC_RL_DEFAULT_MAX_CONN_RATE,
	.rate_limit_window_ms = TQUIC_RL_DEFAULT_RATE_WINDOW_MS,
	.burst_limit = TQUIC_RL_DEFAULT_BURST_LIMIT,
	.attack_threshold = TQUIC_RL_ATTACK_THRESHOLD,
	.cookie_lifetime_ms = TQUIC_COOKIE_LIFETIME_MS,
	.gc_interval_ms = TQUIC_RL_GC_INTERVAL_MS,
	.entry_timeout_ms = TQUIC_RL_ENTRY_TIMEOUT_MS,
};
EXPORT_SYMBOL_GPL(tquic_rl_params);

/* Per-network namespace rate limiter state */
static unsigned int tquic_rl_net_id;

static struct tquic_rl_state *tquic_rl_pernet(struct net *net)
{
	return net_generic(net, tquic_rl_net_id);
}

/* Token scale factor for sub-token precision */
#define TOKEN_SCALE 1000

/*
 * =============================================================================
 * Hash Table Operations
 * =============================================================================
 */

static u32 tquic_rl_addr_hash(const struct sockaddr_storage *addr)
{
	if (addr->ss_family == AF_INET) {
		const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
		return jhash_1word(sin->sin_addr.s_addr, 0);
	}
#if IS_ENABLED(CONFIG_IPV6)
	else if (addr->ss_family == AF_INET6) {
		const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;
		return jhash2((u32 *)&sin6->sin6_addr, 4, 0);
	}
#endif
	return 0;
}

static u32 tquic_rl_bucket_hash(const void *data, u32 len, u32 seed)
{
	const struct tquic_rl_bucket *bucket = data;
	return tquic_rl_addr_hash(&bucket->addr);
}

static u32 tquic_rl_key_hash(const void *data, u32 len, u32 seed)
{
	const struct sockaddr_storage *addr = data;
	return tquic_rl_addr_hash(addr);
}

static int tquic_rl_bucket_cmp(struct rhashtable_compare_arg *arg,
			       const void *obj)
{
	const struct sockaddr_storage *addr = arg->key;
	const struct tquic_rl_bucket *bucket = obj;

	if (addr->ss_family != bucket->addr.ss_family)
		return 1;

	if (addr->ss_family == AF_INET) {
		const struct sockaddr_in *a = (const struct sockaddr_in *)addr;
		const struct sockaddr_in *b = (const struct sockaddr_in *)&bucket->addr;
		return a->sin_addr.s_addr != b->sin_addr.s_addr;
	}
#if IS_ENABLED(CONFIG_IPV6)
	else if (addr->ss_family == AF_INET6) {
		const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)addr;
		const struct sockaddr_in6 *b = (const struct sockaddr_in6 *)&bucket->addr;
		return !ipv6_addr_equal(&a->sin6_addr, &b->sin6_addr);
	}
#endif
	return 1;
}

static const struct rhashtable_params tquic_rl_ht_params = {
	.key_len = 0,  /* Use custom compare */
	.key_offset = offsetof(struct tquic_rl_bucket, addr),
	.head_offset = offsetof(struct tquic_rl_bucket, node),
	.hashfn = tquic_rl_key_hash,
	.obj_hashfn = tquic_rl_bucket_hash,
	.obj_cmpfn = tquic_rl_bucket_cmp,
	.automatic_shrinking = true,
};

/*
 * =============================================================================
 * Bucket Management
 * =============================================================================
 */

static struct tquic_rl_bucket *tquic_rl_bucket_alloc(
	const struct sockaddr_storage *addr)
{
	struct tquic_rl_bucket *bucket;

	bucket = kzalloc(sizeof(*bucket), GFP_ATOMIC);
	if (!bucket)
		return NULL;

	memcpy(&bucket->addr, addr, sizeof(bucket->addr));
	spin_lock_init(&bucket->lock);

	/* Initialize with full bucket of tokens */
	atomic_set(&bucket->tokens, tquic_rl_params.burst_limit * TOKEN_SCALE);
	bucket->last_refill = jiffies;

	bucket->first_seen = ktime_get();
	bucket->last_seen = bucket->first_seen;

	atomic64_set(&bucket->conn_count, 0);
	atomic64_set(&bucket->drop_count, 0);

	return bucket;
}

static void tquic_rl_bucket_free_rcu(struct rcu_head *head)
{
	struct tquic_rl_bucket *bucket = container_of(head,
		struct tquic_rl_bucket, rcu_head);
	kfree(bucket);
}

static void tquic_rl_bucket_put(struct tquic_rl_bucket *bucket)
{
	call_rcu(&bucket->rcu_head, tquic_rl_bucket_free_rcu);
}

/*
 * =============================================================================
 * Token Bucket Algorithm
 * =============================================================================
 */

/**
 * tquic_rl_refill_tokens - Refill tokens based on elapsed time
 * @bucket: Rate limit bucket
 *
 * Called under bucket->lock. Refills tokens proportional to elapsed
 * time since last refill.
 */
static void tquic_rl_refill_tokens(struct tquic_rl_bucket *bucket)
{
	unsigned long now = jiffies;
	unsigned long elapsed_ms;
	int tokens, new_tokens, max_tokens;

	if (!time_after(now, bucket->last_refill))
		return;

	elapsed_ms = jiffies_to_msecs(now - bucket->last_refill);
	if (elapsed_ms == 0)
		return;

	/*
	 * Calculate tokens to add based on rate.
	 *
	 * Use s64 arithmetic to prevent integer overflow:
	 * max_conn_rate can be up to 1,000,000 and TOKEN_SCALE is 1000,
	 * so tokens_per_sec can be up to 1,000,000,000. Multiplying by
	 * elapsed_ms (which can be large after idle periods) would
	 * overflow int32. Cap elapsed_ms to prevent excessive refill
	 * after long idle periods.
	 */
	if (elapsed_ms > 10000)
		elapsed_ms = 10000;

	{
		s64 tokens_per_sec_64 = (s64)tquic_rl_params.max_conn_rate *
					TOKEN_SCALE;
		s64 new_tokens_64 = (tokens_per_sec_64 * elapsed_ms) / 1000;

		if (new_tokens_64 <= 0)
			return;

		new_tokens = (int)min_t(s64, new_tokens_64, INT_MAX);
	}

	tokens = atomic_read(&bucket->tokens);
	max_tokens = tquic_rl_params.burst_limit * TOKEN_SCALE;

	/* Clamp tokens to max_tokens first to handle any prior overshoot */
	if (tokens > max_tokens)
		tokens = max_tokens;

	/* Clamp new_tokens to prevent int overflow in addition */
	new_tokens = min_t(int, new_tokens, max_tokens - tokens);
	atomic_set(&bucket->tokens, tokens + new_tokens);
	bucket->last_refill = now;
}

/**
 * tquic_rl_try_consume_token - Try to consume a token from bucket
 * @bucket: Rate limit bucket
 *
 * Returns true if token was consumed (connection allowed),
 * false if bucket is empty (rate limited).
 */
static bool tquic_rl_try_consume_token(struct tquic_rl_bucket *bucket)
{
	int tokens;
	unsigned long flags;
	bool allowed;

	spin_lock_irqsave(&bucket->lock, flags);

	/* Refill tokens first */
	tquic_rl_refill_tokens(bucket);

	tokens = atomic_read(&bucket->tokens);

	if (tokens >= TOKEN_SCALE) {
		/* Held under lock -- use atomic_set to prevent underflow */
		atomic_set(&bucket->tokens, tokens - TOKEN_SCALE);
		allowed = true;
	} else {
		allowed = false;
	}

	bucket->last_seen = ktime_get();

	spin_unlock_irqrestore(&bucket->lock, flags);

	return allowed;
}

/*
 * =============================================================================
 * Cookie Generation and Validation
 * =============================================================================
 *
 * Implements SYN cookie-style validation for QUIC Initial packets.
 * The cookie encodes:
 *   - Timestamp (seconds, 32-bit)
 *   - Original DCID (for retry)
 *   - HMAC-SHA256 of above fields with secret
 */

static struct crypto_shash *tquic_rl_hmac_tfm;

static int tquic_rl_init_crypto(void)
{
	tquic_rl_hmac_tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);
	if (IS_ERR(tquic_rl_hmac_tfm)) {
		tquic_err("failed to allocate HMAC transform\n");
		return PTR_ERR(tquic_rl_hmac_tfm);
	}
	return 0;
}

static void tquic_rl_exit_crypto(void)
{
	if (tquic_rl_hmac_tfm && !IS_ERR(tquic_rl_hmac_tfm))
		crypto_free_shash(tquic_rl_hmac_tfm);
}

/**
 * tquic_rl_rotate_secret - Rotate cookie secrets
 * @state: Rate limiter state
 *
 * Generates new secret, moves current to previous slot.
 */
static void tquic_rl_rotate_secret_internal(struct tquic_rl_state *state)
{
	int prev, next;
	unsigned long flags;

	prev = state->current_secret;
	next = (prev + 1) % 2;

	spin_lock_irqsave(&state->secrets[next].lock, flags);

	get_random_bytes(state->secrets[next].secret, TQUIC_COOKIE_SECRET_LEN);
	state->secrets[next].generation++;
	state->secrets[next].valid_until = ktime_add_ms(ktime_get(),
		tquic_rl_params.cookie_lifetime_ms * 2);

	spin_unlock_irqrestore(&state->secrets[next].lock, flags);

	/* Atomically switch to new secret */
	WRITE_ONCE(state->current_secret, next);

	tquic_dbg("rotated cookie secret to generation %u\n",
		 state->secrets[next].generation);
}

int tquic_ratelimit_rotate_secret(struct net *net)
{
	struct tquic_rl_state *state = tquic_rl_pernet(net);

	if (!state || !state->initialized)
		return -EINVAL;

	tquic_rl_rotate_secret_internal(state);
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_ratelimit_rotate_secret);

/**
 * tquic_rl_compute_cookie - Compute cookie HMAC
 * @secret: Secret key
 * @addr: Source address
 * @dcid: Original DCID
 * @dcid_len: DCID length
 * @timestamp: Cookie timestamp
 * @output: Output buffer (32 bytes)
 */
static int tquic_rl_compute_cookie(const u8 *secret,
				   const struct sockaddr_storage *addr,
				   const u8 *dcid, u8 dcid_len,
				   u32 timestamp,
				   u8 *output)
{
	SHASH_DESC_ON_STACK(desc, tquic_rl_hmac_tfm);
	u8 addr_bytes[16];
	int addr_len;
	int ret;

	desc->tfm = tquic_rl_hmac_tfm;

	ret = crypto_shash_setkey(tquic_rl_hmac_tfm, secret,
				  TQUIC_COOKIE_SECRET_LEN);
	if (ret)
		return ret;

	ret = crypto_shash_init(desc);
	if (ret)
		return ret;

	/* Hash timestamp */
	ret = crypto_shash_update(desc, (u8 *)&timestamp, sizeof(timestamp));
	if (ret)
		return ret;

	/* Hash address */
	if (addr->ss_family == AF_INET) {
		const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
		memcpy(addr_bytes, &sin->sin_addr.s_addr, 4);
		addr_len = 4;
	}
#if IS_ENABLED(CONFIG_IPV6)
	else if (addr->ss_family == AF_INET6) {
		const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;
		memcpy(addr_bytes, &sin6->sin6_addr, 16);
		addr_len = 16;
	}
#endif
	else {
		return -EAFNOSUPPORT;
	}

	ret = crypto_shash_update(desc, addr_bytes, addr_len);
	if (ret)
		return ret;

	/* Hash DCID */
	if (dcid && dcid_len > 0) {
		ret = crypto_shash_update(desc, &dcid_len, 1);
		if (ret)
			return ret;
		ret = crypto_shash_update(desc, dcid, dcid_len);
		if (ret)
			return ret;
	}

	ret = crypto_shash_final(desc, output);

	shash_desc_zero(desc);

	return ret;
}

int tquic_ratelimit_generate_cookie(struct net *net,
				    const struct sockaddr_storage *src_addr,
				    const u8 *dcid, u8 dcid_len,
				    u8 *cookie, size_t *cookie_len)
{
	struct tquic_rl_state *state = tquic_rl_pernet(net);
	struct tquic_rl_cookie_secret *secret;
	u32 timestamp;
	u8 hmac[32];
	int ret;

	if (!state || !state->initialized)
		return -EINVAL;

	if (*cookie_len < 4 + 1 + dcid_len + 16)
		return -ENOSPC;

	/* Get current timestamp (seconds) */
	timestamp = (u32)(ktime_get_real_seconds() & 0xFFFFFFFF);

	/* Get current secret */
	secret = &state->secrets[READ_ONCE(state->current_secret)];

	/* Compute HMAC */
	ret = tquic_rl_compute_cookie(secret->secret, src_addr, dcid, dcid_len,
				      timestamp, hmac);
	if (ret)
		return ret;

	/*
	 * Cookie format:
	 *   timestamp (4 bytes, big-endian)
	 *   dcid_len (1 byte)
	 *   dcid (dcid_len bytes)
	 *   hmac truncated (16 bytes)
	 */
	cookie[0] = (timestamp >> 24) & 0xff;
	cookie[1] = (timestamp >> 16) & 0xff;
	cookie[2] = (timestamp >> 8) & 0xff;
	cookie[3] = timestamp & 0xff;
	cookie[4] = dcid_len;
	if (dcid_len > 0)
		memcpy(cookie + 5, dcid, dcid_len);
	memcpy(cookie + 5 + dcid_len, hmac, 16);

	*cookie_len = 5 + dcid_len + 16;

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_ratelimit_generate_cookie);

int tquic_ratelimit_validate_cookie(struct net *net,
				    const struct sockaddr_storage *src_addr,
				    const u8 *dcid, u8 dcid_len,
				    const u8 *cookie, size_t cookie_len,
				    u8 *original_dcid, u8 *original_dcid_len)
{
	struct tquic_rl_state *state = tquic_rl_pernet(net);
	u32 timestamp, now;
	u8 stored_dcid_len;
	u8 hmac[32];
	int secret_idx;
	int ret;

	if (!state || !state->initialized)
		return -EINVAL;

	if (cookie_len < 22)  /* 4 + 1 + 0 + 16 minimum */
		return -EINVAL;

	/* Parse timestamp */
	timestamp = ((u32)cookie[0] << 24) | ((u32)cookie[1] << 16) |
		    ((u32)cookie[2] << 8) | cookie[3];

	/* Check expiry */
	now = (u32)(ktime_get_real_seconds() & 0xFFFFFFFF);
	if ((now - timestamp) * 1000 > tquic_rl_params.cookie_lifetime_ms) {
		atomic64_inc(&state->stats.total_cookie_failed);
		return -ETIMEDOUT;
	}

	/* Parse stored DCID - validate against max CID length per RFC 9000 */
	stored_dcid_len = cookie[4];
	if (stored_dcid_len > TQUIC_MAX_CID_LEN)
		return -EINVAL;
	if (cookie_len < 5 + stored_dcid_len + 16)
		return -EINVAL;

	/* Try both current and previous secret */
	for (secret_idx = 0; secret_idx < 2; secret_idx++) {
		int idx = (state->current_secret + secret_idx) % 2;
		struct tquic_rl_cookie_secret *secret = &state->secrets[idx];

		ret = tquic_rl_compute_cookie(secret->secret, src_addr,
					      cookie + 5, stored_dcid_len,
					      timestamp, hmac);
		if (ret)
			continue;

		/* Compare truncated HMAC (constant-time) */
		if (crypto_memneq(hmac, cookie + 5 + stored_dcid_len, 16) == 0) {
			/* Valid cookie */
			if (original_dcid && original_dcid_len) {
				*original_dcid_len = stored_dcid_len;
				if (stored_dcid_len > 0)
					memcpy(original_dcid, cookie + 5, stored_dcid_len);
			}

			atomic64_inc(&state->stats.total_cookie_validated);
			return 0;
		}
	}

	atomic64_inc(&state->stats.total_cookie_failed);
	return -EINVAL;
}
EXPORT_SYMBOL_GPL(tquic_ratelimit_validate_cookie);

/*
 * =============================================================================
 * Rate Limit Check
 * =============================================================================
 */

enum tquic_rl_action tquic_ratelimit_check(struct net *net,
					   const struct sockaddr_storage *src_addr,
					   bool is_initial)
{
	struct tquic_rl_state *state;
	struct tquic_rl_bucket *bucket;
	enum tquic_rl_action action;
	bool allowed;

	state = tquic_rl_pernet(net);
	if (!state || !state->initialized || !state->enabled)
		return TQUIC_RL_ACCEPT;

	atomic64_inc(&state->stats.total_checked);
	atomic_inc(&state->rate_window_count);

	/* Look up or create bucket */
	rcu_read_lock();
	bucket = rhashtable_lookup(&state->ht, src_addr, tquic_rl_ht_params);

	if (!bucket) {
		rcu_read_unlock();

		/* Check if bucket count exceeds maximum */
		if (atomic_read(&state->bucket_count) >= TQUIC_RATELIMIT_MAX_BUCKETS) {
			/* Too many buckets - fail closed to prevent memory exhaustion */
			return TQUIC_RL_RATE_LIMITED;
		}

		/* Allocate new bucket */
		bucket = tquic_rl_bucket_alloc(src_addr);
		if (!bucket) {
			/* Memory pressure - fail closed for safety */
			return TQUIC_RL_RATE_LIMITED;
		}

		/* Insert into hash table */
		if (rhashtable_insert_fast(&state->ht, &bucket->node,
					   tquic_rl_ht_params)) {
			/* Race - another bucket was inserted */
			kfree(bucket);

			rcu_read_lock();
			bucket = rhashtable_lookup(&state->ht, src_addr,
						   tquic_rl_ht_params);
			if (!bucket) {
				rcu_read_unlock();
				/* Lookup error - fail closed */
				return TQUIC_RL_RATE_LIMITED;
			}
		} else {
			/* Successfully inserted */
			atomic_inc(&state->bucket_count);

			/* Lookup again under RCU */
			rcu_read_lock();
			bucket = rhashtable_lookup(&state->ht, src_addr,
						   tquic_rl_ht_params);
			if (!bucket) {
				rcu_read_unlock();
				/* Lookup error - fail closed */
				return TQUIC_RL_RATE_LIMITED;
			}
		}
	}

	/* Check blacklist (with expiration support) */
	if (bucket->blacklisted) {
		ktime_t expires = READ_ONCE(bucket->blacklist_expires);

		/* Check if timed blacklist has expired */
		if (expires != 0 && ktime_after(ktime_get(), expires)) {
			unsigned long flags;

			spin_lock_irqsave(&bucket->lock, flags);
			bucket->blacklisted = false;
			bucket->blacklist_expires = 0;
			spin_unlock_irqrestore(&bucket->lock, flags);
		} else {
			rcu_read_unlock();
			atomic64_inc(&state->stats.total_blacklisted);
			return TQUIC_RL_BLACKLISTED;
		}
	}

	/* Count connection attempt */
	atomic64_inc(&bucket->conn_count);

	/* Attack mode - require cookie for Initial packets */
	if (READ_ONCE(state->attack_mode) && is_initial && !bucket->cookie_required) {
		rcu_read_unlock();
		atomic64_inc(&state->stats.total_cookie_required);
		return TQUIC_RL_COOKIE_REQUIRED;
	}

	/* Try to consume a token */
	allowed = tquic_rl_try_consume_token(bucket);

	rcu_read_unlock();

	if (allowed) {
		atomic64_inc(&state->stats.total_accepted);
		action = TQUIC_RL_ACCEPT;
	} else {
		atomic64_inc(&bucket->drop_count);
		atomic64_inc(&state->stats.total_rate_limited);
		action = TQUIC_RL_RATE_LIMITED;

		/* Rate-limited logging */
		if (__ratelimit(&state->log_ratelimit)) {
			if (src_addr->ss_family == AF_INET) {
				const struct sockaddr_in *sin =
					(const struct sockaddr_in *)src_addr;
				tquic_info("rate limited %pI4 (count=%lld, drops=%lld)\n",
					&sin->sin_addr,
					atomic64_read(&bucket->conn_count),
					atomic64_read(&bucket->drop_count));
			}
#if IS_ENABLED(CONFIG_IPV6)
			else if (src_addr->ss_family == AF_INET6) {
				const struct sockaddr_in6 *sin6 =
					(const struct sockaddr_in6 *)src_addr;
				tquic_info("rate limited %pI6c (count=%lld, drops=%lld)\n",
					&sin6->sin6_addr,
					atomic64_read(&bucket->conn_count),
					atomic64_read(&bucket->drop_count));
			}
#endif
		}
	}

	return action;
}
EXPORT_SYMBOL_GPL(tquic_ratelimit_check);

enum tquic_rl_action tquic_ratelimit_check_initial(
	struct net *net,
	const struct sockaddr_storage *src_addr,
	const u8 *dcid, u8 dcid_len,
	const u8 *token, size_t token_len)
{
	struct tquic_rl_state *state = tquic_rl_pernet(net);
	enum tquic_rl_action action;
	u8 original_dcid[TQUIC_MAX_CID_LEN];
	u8 original_dcid_len;
	int ret;

	/* First check basic rate limit */
	action = tquic_ratelimit_check(net, src_addr, true);

	if (action == TQUIC_RL_COOKIE_REQUIRED && token && token_len > 0) {
		/* Try to validate token as cookie */
		ret = tquic_ratelimit_validate_cookie(net, src_addr,
						      dcid, dcid_len,
						      token, token_len,
						      original_dcid,
						      &original_dcid_len);
		if (ret == 0) {
			/* Cookie validated - mark bucket as validated */
			struct tquic_rl_bucket *bucket;

			rcu_read_lock();
			bucket = rhashtable_lookup(&state->ht, src_addr,
						   tquic_rl_ht_params);
			if (bucket) {
				unsigned long flags;
				spin_lock_irqsave(&bucket->lock, flags);
				bucket->cookie_required = false;
				spin_unlock_irqrestore(&bucket->lock, flags);
			}
			rcu_read_unlock();

			action = TQUIC_RL_ACCEPT;
		}
	}

	return action;
}
EXPORT_SYMBOL_GPL(tquic_ratelimit_check_initial);

/*
 * =============================================================================
 * Blacklist Management
 * =============================================================================
 */

int tquic_ratelimit_blacklist_add(struct net *net,
				  const struct sockaddr_storage *addr,
				  u32 duration_ms)
{
	struct tquic_rl_state *state = tquic_rl_pernet(net);
	struct tquic_rl_bucket *bucket;
	unsigned long flags;

	if (!state || !state->initialized)
		return -EINVAL;

	rcu_read_lock();
	bucket = rhashtable_lookup(&state->ht, addr, tquic_rl_ht_params);

	if (!bucket) {
		rcu_read_unlock();

		/* Create new bucket */
		bucket = tquic_rl_bucket_alloc(addr);
		if (!bucket)
			return -ENOMEM;

		if (rhashtable_insert_fast(&state->ht, &bucket->node,
					   tquic_rl_ht_params)) {
			kfree(bucket);
			return -EEXIST;
		}

		rcu_read_lock();
		bucket = rhashtable_lookup(&state->ht, addr, tquic_rl_ht_params);
		if (!bucket) {
			rcu_read_unlock();
			return -ENOENT;
		}
	}

	spin_lock_irqsave(&bucket->lock, flags);
	bucket->blacklisted = true;
	if (duration_ms > 0)
		bucket->blacklist_expires = ktime_add_ms(ktime_get(), duration_ms);
	else
		bucket->blacklist_expires = 0; /* Permanent blacklist */
	spin_unlock_irqrestore(&bucket->lock, flags);

	rcu_read_unlock();

	if (duration_ms > 0)
		tquic_info("blacklisted source address for %u ms\n", duration_ms);
	else
		tquic_info("permanently blacklisted source address\n");
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_ratelimit_blacklist_add);

int tquic_ratelimit_blacklist_remove(struct net *net,
				     const struct sockaddr_storage *addr)
{
	struct tquic_rl_state *state = tquic_rl_pernet(net);
	struct tquic_rl_bucket *bucket;
	unsigned long flags;

	if (!state || !state->initialized)
		return -EINVAL;

	rcu_read_lock();
	bucket = rhashtable_lookup(&state->ht, addr, tquic_rl_ht_params);

	if (!bucket) {
		rcu_read_unlock();
		return -ENOENT;
	}

	spin_lock_irqsave(&bucket->lock, flags);
	bucket->blacklisted = false;
	spin_unlock_irqrestore(&bucket->lock, flags);

	rcu_read_unlock();

	tquic_info("removed source from blacklist\n");
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_ratelimit_blacklist_remove);

/*
 * =============================================================================
 * Attack Detection
 * =============================================================================
 */

static void tquic_rl_check_attack_mode(struct tquic_rl_state *state)
{
	int current_rate = atomic_read(&state->stats.current_rate);
	bool attack_mode = READ_ONCE(state->attack_mode);
	ktime_t now = ktime_get();

	if (!attack_mode) {
		/* Check if we should enter attack mode */
		if (current_rate > tquic_rl_params.attack_threshold) {
			WRITE_ONCE(state->attack_mode, true);
			state->attack_start = now;
			atomic64_inc(&state->stats.attack_mode_entered);
			tquic_warn("entering attack mode: rate=%d threshold=%d\n",
				   current_rate, tquic_rl_params.attack_threshold);
		}
	} else {
		/* Check if we should exit attack mode */
		ktime_t elapsed = ktime_sub(now, state->attack_start);

		if (ktime_to_ms(elapsed) > TQUIC_RL_ATTACK_HYSTERESIS_MS &&
		    current_rate < tquic_rl_params.attack_threshold / 2) {
			WRITE_ONCE(state->attack_mode, false);
			tquic_info("exiting attack mode: rate=%d\n", current_rate);
		}
	}
}

/*
 * =============================================================================
 * Garbage Collection
 * =============================================================================
 */

static void tquic_rl_gc_work_fn(struct work_struct *work)
{
	struct tquic_rl_state *state = container_of(work,
		struct tquic_rl_state, gc_work.work);
	struct tquic_rl_bucket *bucket;
	struct rhashtable_iter iter;
	ktime_t now = ktime_get();
	ktime_t timeout_ns;
	int removed = 0;

	if (!state->initialized)
		return;

	timeout_ns = ms_to_ktime(tquic_rl_params.entry_timeout_ms);

	rhashtable_walk_enter(&state->ht, &iter);
	rhashtable_walk_start(&iter);

	while ((bucket = rhashtable_walk_next(&iter)) != NULL) {
		if (IS_ERR(bucket))
			continue;

		/* Check for expired timed blacklists */
		if (bucket->blacklisted && bucket->blacklist_expires != 0) {
			if (ktime_after(now, bucket->blacklist_expires)) {
				unsigned long flags;

				spin_lock_irqsave(&bucket->lock, flags);
				bucket->blacklisted = false;
				bucket->blacklist_expires = 0;
				spin_unlock_irqrestore(&bucket->lock, flags);
			}
		}

		/* Skip permanently blacklisted entries */
		if (bucket->blacklisted)
			continue;

		/* Check if entry is stale */
		if (ktime_after(now, ktime_add(bucket->last_seen, timeout_ns))) {
			/* Remove from hash table */
			rhashtable_remove_fast(&state->ht, &bucket->node,
					       tquic_rl_ht_params);
			atomic_dec(&state->bucket_count);
			tquic_rl_bucket_put(bucket);
			removed++;
		}
	}

	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);

	if (removed > 0)
		tquic_dbg("garbage collected %d stale entries\n", removed);

	/* Reschedule */
	if (state->initialized) {
		schedule_delayed_work(&state->gc_work,
			msecs_to_jiffies(tquic_rl_params.gc_interval_ms));
	}
}

/*
 * =============================================================================
 * Rate Calculation
 * =============================================================================
 */

static void tquic_rl_rate_calc_work_fn(struct work_struct *work)
{
	struct tquic_rl_state *state = container_of(work,
		struct tquic_rl_state, rate_calc_work.work);
	unsigned long now = jiffies;
	unsigned long elapsed_ms;
	int count, rate;

	if (!state->initialized)
		return;

	/*
	 * Use time_after() for safe jiffies comparison to handle
	 * wrap-around correctly.
	 */
	if (!time_after(now, state->rate_window_start)) {
		/* Timer wrapped or no time elapsed - reset window */
		state->rate_window_start = now;
		atomic_set(&state->rate_window_count, 0);
		goto reschedule;
	}

	elapsed_ms = jiffies_to_msecs(now - state->rate_window_start);

	/* Cap elapsed_ms to a reasonable maximum (10 seconds) */
	if (elapsed_ms > 10000)
		elapsed_ms = 10000;

	if (elapsed_ms == 0)
		elapsed_ms = 1;

	count = atomic_xchg(&state->rate_window_count, 0);
	rate = (count * 1000) / elapsed_ms;

	state->rate_window_start = now;

	atomic_set(&state->stats.current_rate, rate);

	/* Update peak */
	if (rate > atomic_read(&state->stats.peak_rate))
		atomic_set(&state->stats.peak_rate, rate);

	/* Check attack mode */
	tquic_rl_check_attack_mode(state);

reschedule:
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

void tquic_ratelimit_get_stats(struct net *net, struct tquic_rl_stats *stats)
{
	struct tquic_rl_state *state = tquic_rl_pernet(net);

	if (!state || !state->initialized) {
		memset(stats, 0, sizeof(*stats));
		return;
	}

	memcpy(stats, &state->stats, sizeof(*stats));
}
EXPORT_SYMBOL_GPL(tquic_ratelimit_get_stats);

bool tquic_ratelimit_is_attack_mode(struct net *net)
{
	struct tquic_rl_state *state = tquic_rl_pernet(net);

	if (!state || !state->initialized)
		return false;

	return READ_ONCE(state->attack_mode);
}
EXPORT_SYMBOL_GPL(tquic_ratelimit_is_attack_mode);

/*
 * =============================================================================
 * Proc Interface
 * =============================================================================
 */

int tquic_ratelimit_proc_show(struct seq_file *seq, void *v)
{
	struct net *net;
	struct tquic_rl_state *state;
	struct tquic_rl_stats *stats;

	/*
	 * This proc entry is opened via single_open(..., pde_data(inode)),
	 * so seq->private carries the netns pointer.
	 */
	net = seq ? seq->private : NULL;
	if (!net) {
		seq_puts(seq, "Rate limiter netns unavailable\n");
		return 0;
	}
	state = tquic_rl_pernet(net);

	if (!state || !state->initialized) {
		seq_puts(seq, "Rate limiter not initialized\n");
		return 0;
	}

	stats = &state->stats;

	seq_puts(seq, "# TQUIC Rate Limiter Statistics\n");
	seq_printf(seq, "enabled: %d\n", tquic_rl_params.enabled);
	seq_printf(seq, "attack_mode: %d\n", READ_ONCE(state->attack_mode));
	seq_printf(seq, "max_conn_rate: %d\n", tquic_rl_params.max_conn_rate);
	seq_printf(seq, "burst_limit: %d\n", tquic_rl_params.burst_limit);
	seq_printf(seq, "rate_window_ms: %d\n", tquic_rl_params.rate_limit_window_ms);
	seq_puts(seq, "\n");

	seq_printf(seq, "current_rate: %d conn/s\n",
		   atomic_read(&stats->current_rate));
	seq_printf(seq, "peak_rate: %d conn/s\n",
		   atomic_read(&stats->peak_rate));
	seq_puts(seq, "\n");

	seq_printf(seq, "total_checked: %lld\n",
		   atomic64_read(&stats->total_checked));
	seq_printf(seq, "total_accepted: %lld\n",
		   atomic64_read(&stats->total_accepted));
	seq_printf(seq, "total_rate_limited: %lld\n",
		   atomic64_read(&stats->total_rate_limited));
	seq_printf(seq, "total_cookie_required: %lld\n",
		   atomic64_read(&stats->total_cookie_required));
	seq_printf(seq, "total_cookie_validated: %lld\n",
		   atomic64_read(&stats->total_cookie_validated));
	seq_printf(seq, "total_cookie_failed: %lld\n",
		   atomic64_read(&stats->total_cookie_failed));
	seq_printf(seq, "total_blacklisted: %lld\n",
		   atomic64_read(&stats->total_blacklisted));
	seq_printf(seq, "attack_mode_entered: %lld\n",
		   atomic64_read(&stats->attack_mode_entered));

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_ratelimit_proc_show);

/*
 * =============================================================================
 * Netfilter Integration
 * =============================================================================
 */

unsigned int tquic_ratelimit_nf_check(struct sk_buff *skb,
				      const struct sockaddr_storage *src_addr)
{
	struct net *net;
	enum tquic_rl_action action;

	if (!skb->sk)
		return NF_ACCEPT;

	net = sock_net(skb->sk);
	action = tquic_ratelimit_check(net, src_addr, false);

	switch (action) {
	case TQUIC_RL_ACCEPT:
		return NF_ACCEPT;
	case TQUIC_RL_RATE_LIMITED:
	case TQUIC_RL_BLACKLISTED:
		return NF_DROP;
	case TQUIC_RL_COOKIE_REQUIRED:
		/* Let packet through - cookie handling is at QUIC layer */
		return NF_ACCEPT;
	default:
		return NF_ACCEPT;
	}
}
EXPORT_SYMBOL_GPL(tquic_ratelimit_nf_check);

/*
 * =============================================================================
 * Sysctl Interface
 * =============================================================================
 */

static struct ctl_table_header *tquic_rl_sysctl_header;

/* Min/max values */
static int zero;
static int one = 1;
static int max_rate = 1000000;		/* 1M conn/s */
static int max_burst = 10000;		/* 10K burst */
static int max_window = 60000;		/* 60 seconds */
static int max_threshold = 10000000;	/* 10M conn/s */
static int max_timeout = 3600000;	/* 1 hour */

static struct ctl_table tquic_rl_sysctl_table[] = {
	{
		.procname	= "ratelimit_enabled",
		.data		= &tquic_rl_params.enabled,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &zero,
		.extra2		= &one,
	},
	{
		.procname	= "max_conn_rate",
		.data		= &tquic_rl_params.max_conn_rate,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &one,
		.extra2		= &max_rate,
	},
	{
		.procname	= "rate_limit_window_ms",
		.data		= &tquic_rl_params.rate_limit_window_ms,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &one,
		.extra2		= &max_window,
	},
	{
		.procname	= "burst_limit",
		.data		= &tquic_rl_params.burst_limit,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &one,
		.extra2		= &max_burst,
	},
	{
		.procname	= "attack_threshold",
		.data		= &tquic_rl_params.attack_threshold,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &one,
		.extra2		= &max_threshold,
	},
	{
		.procname	= "cookie_lifetime_ms",
		.data		= &tquic_rl_params.cookie_lifetime_ms,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &one,
		.extra2		= &max_timeout,
	},
	{
		.procname	= "gc_interval_ms",
		.data		= &tquic_rl_params.gc_interval_ms,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &one,
		.extra2		= &max_timeout,
	},
	{
		.procname	= "entry_timeout_ms",
		.data		= &tquic_rl_params.entry_timeout_ms,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &one,
		.extra2		= &max_timeout,
	},
	{ }
};

/* Number of valid entries (exclude the null terminator). */
#define TQUIC_RL_SYSCTL_TABLE_ENTRIES (ARRAY_SIZE(tquic_rl_sysctl_table) - 1)

/* Sysctl accessor functions */
int tquic_sysctl_get_ratelimit_enabled(void)
{
	return tquic_rl_params.enabled;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_ratelimit_enabled);

int tquic_sysctl_get_max_conn_rate(void)
{
	return tquic_rl_params.max_conn_rate;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_max_conn_rate);

int tquic_sysctl_get_rate_limit_window(void)
{
	return tquic_rl_params.rate_limit_window_ms;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_rate_limit_window);

int tquic_sysctl_get_burst_limit(void)
{
	return tquic_rl_params.burst_limit;
}
EXPORT_SYMBOL_GPL(tquic_sysctl_get_burst_limit);

int tquic_ratelimit_sysctl_init(void)
{
	tquic_rl_sysctl_header = register_net_sysctl_sz(&init_net, "net/tquic",
							tquic_rl_sysctl_table,
							TQUIC_RL_SYSCTL_TABLE_ENTRIES);
	if (!tquic_rl_sysctl_header)
		return -ENOMEM;

	tquic_info("sysctl parameters registered at /proc/sys/net/tquic/\n");
	return 0;
}

void tquic_ratelimit_sysctl_exit(void)
{
	if (tquic_rl_sysctl_header)
		unregister_net_sysctl_table(tquic_rl_sysctl_header);
}

/*
 * =============================================================================
 * Initialization and Cleanup
 * =============================================================================
 */

int tquic_ratelimit_init(struct net *net)
{
	struct tquic_rl_state *state;
	int ret;

	state = tquic_rl_pernet(net);
	if (!state)
		return -EINVAL;

	memset(state, 0, sizeof(*state));
	spin_lock_init(&state->lock);
	atomic_set(&state->bucket_count, 0);
	state->net = net;

	/* Initialize hash table */
	ret = rhashtable_init(&state->ht, &tquic_rl_ht_params);
	if (ret) {
		tquic_err("failed to initialize hash table: %d\n", ret);
		return ret;
	}

	/* Initialize cookie secrets */
	spin_lock_init(&state->secrets[0].lock);
	spin_lock_init(&state->secrets[1].lock);
	get_random_bytes(state->secrets[0].secret, TQUIC_COOKIE_SECRET_LEN);
	get_random_bytes(state->secrets[1].secret, TQUIC_COOKIE_SECRET_LEN);
	state->secrets[0].generation = 1;
	state->secrets[1].generation = 0;
	state->secrets[0].valid_until = ktime_add_ms(ktime_get(),
		TQUIC_COOKIE_ROTATE_INTERVAL_MS);
	state->current_secret = 0;

	/* Initialize work items */
	INIT_DELAYED_WORK(&state->gc_work, tquic_rl_gc_work_fn);
	INIT_DELAYED_WORK(&state->rate_calc_work, tquic_rl_rate_calc_work_fn);

	/* Initialize log rate limiter */
	ratelimit_state_init(&state->log_ratelimit,
			     TQUIC_RL_LOG_INTERVAL_MS * HZ / 1000, 5);

	/* Initialize rate window */
	state->rate_window_start = jiffies;
	atomic_set(&state->rate_window_count, 0);

	state->enabled = true;
	state->initialized = true;

	/* Start workers */
	schedule_delayed_work(&state->gc_work,
		msecs_to_jiffies(tquic_rl_params.gc_interval_ms));
	schedule_delayed_work(&state->rate_calc_work,
		msecs_to_jiffies(1000));

	tquic_info("initialized for net namespace\n");
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_ratelimit_init);

void tquic_ratelimit_exit(struct net *net)
{
	struct tquic_rl_state *state = tquic_rl_pernet(net);
	struct tquic_rl_bucket *bucket;
	struct rhashtable_iter iter;

	if (!state || !state->initialized)
		return;

	state->initialized = false;

	/* Cancel workers */
	cancel_delayed_work_sync(&state->gc_work);
	cancel_delayed_work_sync(&state->rate_calc_work);

	/* Free all buckets */
	rhashtable_walk_enter(&state->ht, &iter);
	rhashtable_walk_start(&iter);

	while ((bucket = rhashtable_walk_next(&iter)) != NULL) {
		if (IS_ERR(bucket))
			continue;
		rhashtable_remove_fast(&state->ht, &bucket->node,
				       tquic_rl_ht_params);
		atomic_dec(&state->bucket_count);
		tquic_rl_bucket_put(bucket);
	}

	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);

	/* Destroy hash table */
	rhashtable_destroy(&state->ht);

	/* Clear secrets */
	memzero_explicit(state->secrets[0].secret, TQUIC_COOKIE_SECRET_LEN);
	memzero_explicit(state->secrets[1].secret, TQUIC_COOKIE_SECRET_LEN);

	tquic_info("cleaned up for net namespace\n");
}
EXPORT_SYMBOL_GPL(tquic_ratelimit_exit);

/*
 * =============================================================================
 * Module Init/Exit
 * =============================================================================
 */

static int __net_init tquic_rl_net_init(struct net *net)
{
	return tquic_ratelimit_init(net);
}

static void __net_exit tquic_rl_net_exit(struct net *net)
{
	tquic_ratelimit_exit(net);
}

static struct pernet_operations tquic_rl_net_ops = {
	.init = tquic_rl_net_init,
	.exit = tquic_rl_net_exit,
	.id = &tquic_rl_net_id,
	.size = sizeof(struct tquic_rl_state),
};

int __init tquic_ratelimit_module_init(void)
{
	int ret;

	ret = tquic_rl_init_crypto();
	if (ret)
		return ret;

	ret = register_pernet_subsys(&tquic_rl_net_ops);
	if (ret) {
		tquic_rl_exit_crypto();
		return ret;
	}

	ret = tquic_ratelimit_sysctl_init();
	if (ret) {
		unregister_pernet_subsys(&tquic_rl_net_ops);
		tquic_rl_exit_crypto();
		return ret;
	}

	tquic_info("rate limiter initialized\n");
	return 0;
}

void tquic_ratelimit_module_exit(void)
{
	tquic_ratelimit_sysctl_exit();
	unregister_pernet_subsys(&tquic_rl_net_ops);
	tquic_rl_exit_crypto();

	/* Wait for RCU callbacks */
	synchronize_rcu();

	tquic_info("rate limiter exited\n");
}

MODULE_DESCRIPTION("TQUIC Connection Rate Limiting for DDoS Protection");
MODULE_LICENSE("GPL");
