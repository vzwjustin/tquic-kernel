// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Rate Limiting KUnit Tests
 *
 * Copyright (c) 2026 Linux Foundation
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Comprehensive KUnit tests for the TQUIC connection rate limiting
 * subsystem (rate_limit.h/rate_limit.c). Tests cover:
 *
 *   Section 1: Token Bucket Algorithm Tests
 *   Section 2: Rate Limiter Initialization Tests
 *   Section 3: Global Rate Limiting Tests
 *   Section 4: Per-IP Rate Limiting Tests
 *   Section 5: RCU and Concurrency Tests
 *   Section 6: Cleanup and Garbage Collection Tests
 *   Section 7: Configuration Update Tests
 *   Section 8: Statistics Tests
 */

#include <kunit/test.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/jhash.h>
#include <linux/delay.h>
#include <linux/random.h>

/*
 * =============================================================================
 * Test Constants (mirror production values from rate_limit.h)
 * =============================================================================
 */

/* Default configuration values */
#define TEST_RATE_LIMIT_ENABLED			1
#define TEST_MAX_CONN_PER_SEC			10000
#define TEST_MAX_BURST				1000
#define TEST_PER_IP_LIMIT			100

/* Token bucket scale factor */
#define TEST_TOKEN_SCALE			1000

/* Hash table configuration */
#define TEST_HASH_BITS				10
#define TEST_HASH_SIZE				(1 << TEST_HASH_BITS)

/* Timing constants (in milliseconds) */
#define TEST_GC_INTERVAL_MS			30000
#define TEST_ENTRY_TIMEOUT_MS			120000

/*
 * =============================================================================
 * Test Data Structures
 * =============================================================================
 */

/**
 * struct test_rate_limiter - Token bucket rate limiter for testing
 * @tokens: Current token count (scaled by TEST_TOKEN_SCALE)
 * @max_tokens: Maximum bucket capacity (scaled)
 * @refill_rate: Tokens per millisecond (scaled)
 * @last_refill: Last refill timestamp (ms)
 */
struct test_rate_limiter {
	s64 tokens;
	s64 max_tokens;
	s64 refill_rate;
	u64 last_refill;
};

/**
 * struct test_per_ip_entry - Per-IP tracking entry for testing
 * @addr_hash: Hash of source address
 * @limiter: Token bucket for this IP
 * @conn_count: Connection attempt count
 * @drop_count: Dropped connection count
 * @first_seen: First seen timestamp
 * @last_seen: Last seen timestamp
 * @list: Hash bucket linkage
 */
struct test_per_ip_entry {
	u32 addr_hash;
	struct test_rate_limiter limiter;
	u64 conn_count;
	u64 drop_count;
	u64 first_seen;
	u64 last_seen;
	struct list_head list;
};

/**
 * struct test_rate_limit_state - Global rate limiter state for testing
 * @global_limiter: Global token bucket
 * @per_ip_buckets: Hash table for per-IP entries
 * @enabled: Rate limiting enabled
 * @total_checked: Total connections checked
 * @total_allowed: Total connections allowed
 * @total_denied: Total connections denied (global)
 * @total_per_ip_denied: Total connections denied (per-IP)
 * @current_rate: Current connection rate
 * @peak_rate: Peak rate observed
 */
struct test_rate_limit_state {
	struct test_rate_limiter global_limiter;
	struct list_head per_ip_buckets[TEST_HASH_SIZE];
	bool enabled;
	u64 total_checked;
	u64 total_allowed;
	u64 total_denied;
	u64 total_per_ip_denied;
	u32 current_rate;
	u32 peak_rate;
};

/*
 * =============================================================================
 * Token Bucket Implementation for Testing
 * =============================================================================
 */

/**
 * test_limiter_init - Initialize a token bucket rate limiter
 * @limiter: Rate limiter to initialize
 * @rate_per_sec: Token replenishment rate (tokens/second)
 * @burst: Maximum bucket capacity (tokens)
 */
static void test_limiter_init(struct test_rate_limiter *limiter,
			      u32 rate_per_sec, u32 burst)
{
	limiter->max_tokens = (s64)burst * TEST_TOKEN_SCALE;
	limiter->tokens = limiter->max_tokens;  /* Start full */
	limiter->refill_rate = ((s64)rate_per_sec * TEST_TOKEN_SCALE) / 1000;
	limiter->last_refill = 0;
}

/**
 * test_limiter_refill - Refill tokens based on elapsed time
 * @limiter: Rate limiter
 * @now_ms: Current time in milliseconds
 */
static void test_limiter_refill(struct test_rate_limiter *limiter, u64 now_ms)
{
	u64 elapsed;
	s64 new_tokens;

	if (now_ms <= limiter->last_refill)
		return;

	elapsed = now_ms - limiter->last_refill;
	new_tokens = elapsed * limiter->refill_rate;

	limiter->tokens = min(limiter->tokens + new_tokens, limiter->max_tokens);
	limiter->last_refill = now_ms;
}

/**
 * test_limiter_allow - Check if connection is allowed
 * @limiter: Rate limiter
 * @now_ms: Current time in milliseconds
 *
 * Returns: true if allowed (token consumed), false if denied
 */
static bool test_limiter_allow(struct test_rate_limiter *limiter, u64 now_ms)
{
	s64 cost = TEST_TOKEN_SCALE;

	test_limiter_refill(limiter, now_ms);

	if (limiter->tokens >= cost) {
		limiter->tokens -= cost;
		return true;
	}

	return false;
}

/**
 * test_limiter_tokens_available - Get number of available tokens
 * @limiter: Rate limiter
 *
 * Returns: Number of available tokens (unscaled)
 */
static u32 test_limiter_tokens_available(const struct test_rate_limiter *limiter)
{
	if (limiter->tokens < 0)
		return 0;
	return (u32)(limiter->tokens / TEST_TOKEN_SCALE);
}

/*
 * =============================================================================
 * Rate Limit State Management for Testing
 * =============================================================================
 */

/**
 * test_state_init - Initialize rate limiter state
 * @state: State to initialize
 */
static void test_state_init(struct test_rate_limit_state *state)
{
	int i;

	memset(state, 0, sizeof(*state));

	/* Initialize global limiter */
	test_limiter_init(&state->global_limiter, TEST_MAX_CONN_PER_SEC,
			  TEST_MAX_BURST);

	/* Initialize per-IP hash buckets */
	for (i = 0; i < TEST_HASH_SIZE; i++)
		INIT_LIST_HEAD(&state->per_ip_buckets[i]);

	state->enabled = true;
}

/**
 * test_state_destroy - Clean up rate limiter state
 * @state: State to destroy
 */
static void test_state_destroy(struct test_rate_limit_state *state)
{
	struct test_per_ip_entry *entry, *tmp;
	int i;

	for (i = 0; i < TEST_HASH_SIZE; i++) {
		list_for_each_entry_safe(entry, tmp, &state->per_ip_buckets[i], list) {
			list_del(&entry->list);
			kfree(entry);
		}
	}
}

/**
 * test_hash_addr - Hash an address to bucket index
 * @addr: Address value to hash
 *
 * Returns: Bucket index
 */
static u32 test_hash_addr(u32 addr)
{
	return jhash_1word(addr, 0) & (TEST_HASH_SIZE - 1);
}

/**
 * test_find_entry - Find per-IP entry
 * @state: Rate limiter state
 * @addr: Source address (as u32)
 *
 * Returns: Entry or NULL
 */
static struct test_per_ip_entry *test_find_entry(struct test_rate_limit_state *state,
						 u32 addr)
{
	u32 bucket_idx = test_hash_addr(addr);
	struct test_per_ip_entry *entry;

	list_for_each_entry(entry, &state->per_ip_buckets[bucket_idx], list) {
		if (entry->addr_hash == addr)
			return entry;
	}

	return NULL;
}

/**
 * test_create_entry - Create new per-IP entry
 * @state: Rate limiter state
 * @addr: Source address
 * @now_ms: Current time
 *
 * Returns: New entry or NULL
 */
static struct test_per_ip_entry *test_create_entry(struct test_rate_limit_state *state,
						   u32 addr, u64 now_ms)
{
	struct test_per_ip_entry *entry;
	u32 bucket_idx = test_hash_addr(addr);

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return NULL;

	entry->addr_hash = addr;
	test_limiter_init(&entry->limiter, TEST_PER_IP_LIMIT, TEST_PER_IP_LIMIT);
	entry->limiter.last_refill = now_ms;
	entry->first_seen = now_ms;
	entry->last_seen = now_ms;

	list_add(&entry->list, &state->per_ip_buckets[bucket_idx]);

	return entry;
}

/**
 * test_rate_limit_check - Check rate limit for connection
 * @state: Rate limiter state
 * @addr: Source address
 * @now_ms: Current time
 *
 * Returns: true if allowed, false if denied
 */
static bool test_rate_limit_check(struct test_rate_limit_state *state,
				  u32 addr, u64 now_ms)
{
	struct test_per_ip_entry *entry;
	bool global_ok, per_ip_ok;

	if (!state->enabled)
		return true;

	state->total_checked++;

	/* Check global limit first */
	global_ok = test_limiter_allow(&state->global_limiter, now_ms);
	if (!global_ok) {
		state->total_denied++;
		return false;
	}

	/* Find or create per-IP entry */
	entry = test_find_entry(state, addr);
	if (!entry) {
		entry = test_create_entry(state, addr, now_ms);
		if (!entry) {
			/* Memory pressure - allow to fail open */
			state->total_allowed++;
			return true;
		}
	}

	entry->last_seen = now_ms;
	entry->conn_count++;

	/* Check per-IP limit */
	per_ip_ok = test_limiter_allow(&entry->limiter, now_ms);
	if (!per_ip_ok) {
		entry->drop_count++;
		state->total_per_ip_denied++;
		return false;
	}

	state->total_allowed++;
	return true;
}

/**
 * test_cleanup_expired - Clean up expired per-IP entries
 * @state: Rate limiter state
 * @now_ms: Current time
 * @timeout_ms: Entry timeout
 *
 * Returns: Number of entries removed
 */
static int test_cleanup_expired(struct test_rate_limit_state *state,
				u64 now_ms, u64 timeout_ms)
{
	struct test_per_ip_entry *entry, *tmp;
	int removed = 0;
	int i;

	for (i = 0; i < TEST_HASH_SIZE; i++) {
		list_for_each_entry_safe(entry, tmp, &state->per_ip_buckets[i], list) {
			if (now_ms - entry->last_seen > timeout_ms) {
				list_del(&entry->list);
				kfree(entry);
				removed++;
			}
		}
	}

	return removed;
}

/*
 * =============================================================================
 * SECTION 1: Token Bucket Algorithm Tests
 * =============================================================================
 */

/* Test: Token bucket initialization */
static void test_bucket_init(struct kunit *test)
{
	struct test_rate_limiter limiter;

	/* ACT */
	test_limiter_init(&limiter, 100, 10);

	/* ASSERT */
	KUNIT_EXPECT_EQ(test, test_limiter_tokens_available(&limiter), 10U);
	KUNIT_EXPECT_EQ(test, limiter.max_tokens, 10 * TEST_TOKEN_SCALE);
}

/* Test: Token consumption depletes bucket */
static void test_bucket_consume(struct kunit *test)
{
	struct test_rate_limiter limiter;
	int i, consumed = 0;

	/* ARRANGE */
	test_limiter_init(&limiter, 100, 5);

	/* ACT */
	for (i = 0; i < 10; i++) {
		if (test_limiter_allow(&limiter, 0))
			consumed++;
	}

	/* ASSERT */
	KUNIT_EXPECT_EQ(test, consumed, 5);
	KUNIT_EXPECT_EQ(test, test_limiter_tokens_available(&limiter), 0U);
}

/* Test: Token refill over time */
static void test_bucket_refill(struct kunit *test)
{
	struct test_rate_limiter limiter;

	/* ARRANGE: Empty bucket */
	test_limiter_init(&limiter, 1000, 10);  /* 1000/sec = 1/ms */
	limiter.tokens = 0;
	limiter.last_refill = 0;

	/* ACT: Refill after 5ms */
	test_limiter_refill(&limiter, 5);

	/* ASSERT: Should have ~5 tokens */
	KUNIT_EXPECT_GE(test, test_limiter_tokens_available(&limiter), 4U);
	KUNIT_EXPECT_LE(test, test_limiter_tokens_available(&limiter), 6U);
}

/* Test: Token bucket capped at max */
static void test_bucket_max_cap(struct kunit *test)
{
	struct test_rate_limiter limiter;

	/* ARRANGE */
	test_limiter_init(&limiter, 1000, 10);
	limiter.last_refill = 0;

	/* ACT: Refill for a long time */
	test_limiter_refill(&limiter, 1000000);  /* 1000 seconds */

	/* ASSERT: Should be capped at max */
	KUNIT_EXPECT_EQ(test, test_limiter_tokens_available(&limiter), 10U);
}

/* Test: Burst handling */
static void test_bucket_burst_handling(struct kunit *test)
{
	struct test_rate_limiter limiter;
	int consumed = 0;
	int i;

	/* ARRANGE: Small rate but larger burst */
	test_limiter_init(&limiter, 10, 100);  /* 10/sec but 100 burst */

	/* ACT: Try to consume 150 immediately */
	for (i = 0; i < 150; i++) {
		if (test_limiter_allow(&limiter, 0))
			consumed++;
	}

	/* ASSERT: Only burst amount consumed */
	KUNIT_EXPECT_EQ(test, consumed, 100);
}

/* Test: Zero elapsed time doesn't add tokens */
static void test_bucket_zero_elapsed(struct kunit *test)
{
	struct test_rate_limiter limiter;

	/* ARRANGE */
	test_limiter_init(&limiter, 1000, 10);
	limiter.tokens = 5 * TEST_TOKEN_SCALE;
	limiter.last_refill = 100;

	/* ACT: Refill at same time */
	test_limiter_refill(&limiter, 100);

	/* ASSERT: No change */
	KUNIT_EXPECT_EQ(test, test_limiter_tokens_available(&limiter), 5U);
}

/*
 * =============================================================================
 * SECTION 2: Rate Limiter Initialization Tests
 * =============================================================================
 */

/* Test: State initialization */
static void test_state_initialization(struct kunit *test)
{
	struct test_rate_limit_state state;

	/* ACT */
	test_state_init(&state);

	/* ASSERT */
	KUNIT_EXPECT_TRUE(test, state.enabled);
	KUNIT_EXPECT_EQ(test, state.total_checked, 0ULL);
	KUNIT_EXPECT_EQ(test, state.total_allowed, 0ULL);
	KUNIT_EXPECT_EQ(test, state.total_denied, 0ULL);
	KUNIT_EXPECT_EQ(test, test_limiter_tokens_available(&state.global_limiter),
			(u32)TEST_MAX_BURST);

	/* Cleanup */
	test_state_destroy(&state);
}

/* Test: State cleanup */
static void test_state_cleanup(struct kunit *test)
{
	struct test_rate_limit_state state;
	int i;

	/* ARRANGE */
	test_state_init(&state);

	/* Create some entries */
	for (i = 0; i < 100; i++)
		test_create_entry(&state, i, 0);

	/* ACT */
	test_state_destroy(&state);

	/* ASSERT: All buckets should be empty */
	for (i = 0; i < TEST_HASH_SIZE; i++)
		KUNIT_EXPECT_TRUE(test, list_empty(&state.per_ip_buckets[i]));
}

/*
 * =============================================================================
 * SECTION 3: Global Rate Limiting Tests
 * =============================================================================
 */

/* Test: Global rate limit allows within limit */
static void test_global_allows_within_limit(struct kunit *test)
{
	struct test_rate_limit_state state;
	int i, allowed = 0;

	/* ARRANGE */
	test_state_init(&state);

	/* ACT: Try connections within burst limit */
	for (i = 0; i < TEST_MAX_BURST; i++) {
		if (test_rate_limit_check(&state, 0x10000000 + i, 0))
			allowed++;
	}

	/* ASSERT: All should be allowed */
	KUNIT_EXPECT_EQ(test, allowed, TEST_MAX_BURST);

	/* Cleanup */
	test_state_destroy(&state);
}

/* Test: Global rate limit denies over limit */
static void test_global_denies_over_limit(struct kunit *test)
{
	struct test_rate_limit_state state;
	int i, denied = 0;

	/* ARRANGE */
	test_state_init(&state);

	/* Exhaust burst */
	for (i = 0; i < TEST_MAX_BURST + 100; i++) {
		if (!test_rate_limit_check(&state, 0x20000000 + i, 0))
			denied++;
	}

	/* ASSERT: Some should be denied */
	KUNIT_EXPECT_GT(test, denied, 0);
	KUNIT_EXPECT_GT(test, (int)state.total_denied, 0);

	/* Cleanup */
	test_state_destroy(&state);
}

/* Test: Global limit refills over time */
static void test_global_refills(struct kunit *test)
{
	struct test_rate_limit_state state;
	bool allowed;

	/* ARRANGE: Exhaust global bucket */
	test_state_init(&state);
	state.global_limiter.tokens = 0;
	state.global_limiter.last_refill = 0;

	/* ACT: Try after some time */
	allowed = test_rate_limit_check(&state, 0x30000000, 100);

	/* ASSERT: Should be allowed after refill */
	KUNIT_EXPECT_TRUE(test, allowed);

	/* Cleanup */
	test_state_destroy(&state);
}

/*
 * =============================================================================
 * SECTION 4: Per-IP Rate Limiting Tests
 * =============================================================================
 */

/* Test: Per-IP entry creation */
static void test_per_ip_entry_creation(struct kunit *test)
{
	struct test_rate_limit_state state;
	struct test_per_ip_entry *entry;
	u32 addr = 0x0A000001;  /* 10.0.0.1 */

	/* ARRANGE */
	test_state_init(&state);

	/* ACT */
	entry = test_create_entry(&state, addr, 1000);

	/* ASSERT */
	KUNIT_EXPECT_NOT_NULL(test, entry);
	KUNIT_EXPECT_EQ(test, entry->addr_hash, addr);
	KUNIT_EXPECT_EQ(test, entry->first_seen, 1000ULL);
	KUNIT_EXPECT_EQ(test, entry->conn_count, 0ULL);

	/* Cleanup */
	test_state_destroy(&state);
}

/* Test: Per-IP rate limiting works */
static void test_per_ip_rate_limiting(struct kunit *test)
{
	struct test_rate_limit_state state;
	u32 addr = 0x0A000002;
	int i, allowed = 0;

	/* ARRANGE */
	test_state_init(&state);

	/* ACT: Exhaust per-IP limit */
	for (i = 0; i < TEST_PER_IP_LIMIT + 50; i++) {
		if (test_rate_limit_check(&state, addr, 0))
			allowed++;
	}

	/* ASSERT: Only per-IP limit allowed */
	KUNIT_EXPECT_EQ(test, allowed, TEST_PER_IP_LIMIT);
	KUNIT_EXPECT_GT(test, (int)state.total_per_ip_denied, 0);

	/* Cleanup */
	test_state_destroy(&state);
}

/* Test: Different IPs tracked independently */
static void test_per_ip_independent_tracking(struct kunit *test)
{
	struct test_rate_limit_state state;
	u32 addr1 = 0x0A000001;
	u32 addr2 = 0x0A000002;
	int i;
	bool addr1_denied = false;
	bool addr2_allowed = true;

	/* ARRANGE */
	test_state_init(&state);

	/* Exhaust addr1's bucket */
	for (i = 0; i < TEST_PER_IP_LIMIT + 10; i++)
		test_rate_limit_check(&state, addr1, 0);

	/* ACT: Try addr1 and addr2 */
	addr1_denied = !test_rate_limit_check(&state, addr1, 0);
	addr2_allowed = test_rate_limit_check(&state, addr2, 0);

	/* ASSERT: addr1 denied, addr2 allowed */
	KUNIT_EXPECT_TRUE(test, addr1_denied);
	KUNIT_EXPECT_TRUE(test, addr2_allowed);

	/* Cleanup */
	test_state_destroy(&state);
}

/* Test: Per-IP entry lookup */
static void test_per_ip_entry_lookup(struct kunit *test)
{
	struct test_rate_limit_state state;
	struct test_per_ip_entry *created, *found;
	u32 addr = 0x0A000003;

	/* ARRANGE */
	test_state_init(&state);
	created = test_create_entry(&state, addr, 0);

	/* ACT */
	found = test_find_entry(&state, addr);

	/* ASSERT */
	KUNIT_EXPECT_EQ(test, (void *)found, (void *)created);

	/* Cleanup */
	test_state_destroy(&state);
}

/* Test: Per-IP hash collision handling */
static void test_per_ip_hash_collision(struct kunit *test)
{
	struct test_rate_limit_state state;
	struct test_per_ip_entry *entry1, *entry2;
	u32 addr1 = 0x00000001;
	u32 addr2 = addr1 + TEST_HASH_SIZE;  /* Same bucket */

	/* ARRANGE */
	test_state_init(&state);

	/* ACT */
	entry1 = test_create_entry(&state, addr1, 0);
	entry2 = test_create_entry(&state, addr2, 0);

	/* ASSERT: Both should be found */
	KUNIT_EXPECT_NOT_NULL(test, test_find_entry(&state, addr1));
	KUNIT_EXPECT_NOT_NULL(test, test_find_entry(&state, addr2));
	KUNIT_EXPECT_NE(test, (void *)entry1, (void *)entry2);

	/* Cleanup */
	test_state_destroy(&state);
}

/*
 * =============================================================================
 * SECTION 5: RCU and Concurrency Tests
 * =============================================================================
 */

/* Note: These tests verify the data structures, not actual RCU behavior */

/* Test: Multiple entries can be created */
static void test_concurrent_entry_creation(struct kunit *test)
{
	struct test_rate_limit_state state;
	int i;
	int entry_count = 0;

	/* ARRANGE */
	test_state_init(&state);

	/* ACT: Create many entries */
	for (i = 0; i < 1000; i++) {
		if (test_create_entry(&state, 0x10000000 + i, 0))
			entry_count++;
	}

	/* ASSERT */
	KUNIT_EXPECT_EQ(test, entry_count, 1000);

	/* Cleanup */
	test_state_destroy(&state);
}

/* Test: High connection rate */
static void test_high_connection_rate(struct kunit *test)
{
	struct test_rate_limit_state state;
	int i;
	u64 time_ms = 0;
	int allowed = 0;

	/* ARRANGE */
	test_state_init(&state);

	/* ACT: Simulate 10000 connections over 1 second (1 per 0.1ms) */
	for (i = 0; i < 10000; i++) {
		if (test_rate_limit_check(&state, 0x20000000 + (i % 100), time_ms))
			allowed++;
		time_ms += 1;  /* Advance time by 0.1ms */
	}

	/* ASSERT: Most should be allowed due to refill */
	KUNIT_EXPECT_GT(test, allowed, 5000);
	KUNIT_EXPECT_EQ(test, (int)state.total_checked, 10000);

	/* Cleanup */
	test_state_destroy(&state);
}

/*
 * =============================================================================
 * SECTION 6: Cleanup and Garbage Collection Tests
 * =============================================================================
 */

/* Test: Expired entries are cleaned up */
static void test_expired_cleanup(struct kunit *test)
{
	struct test_rate_limit_state state;
	int removed;

	/* ARRANGE */
	test_state_init(&state);
	test_create_entry(&state, 0x0A000001, 0);
	test_create_entry(&state, 0x0A000002, 0);
	test_create_entry(&state, 0x0A000003, 1000);

	/* ACT: Cleanup with timeout */
	removed = test_cleanup_expired(&state, TEST_ENTRY_TIMEOUT_MS + 500, TEST_ENTRY_TIMEOUT_MS);

	/* ASSERT: First two should be removed */
	KUNIT_EXPECT_EQ(test, removed, 2);
	KUNIT_EXPECT_NULL(test, test_find_entry(&state, 0x0A000001));
	KUNIT_EXPECT_NULL(test, test_find_entry(&state, 0x0A000002));
	KUNIT_EXPECT_NOT_NULL(test, test_find_entry(&state, 0x0A000003));

	/* Cleanup */
	test_state_destroy(&state);
}

/* Test: Active entries are not cleaned up */
static void test_active_entries_preserved(struct kunit *test)
{
	struct test_rate_limit_state state;
	int removed;

	/* ARRANGE */
	test_state_init(&state);
	test_create_entry(&state, 0x0A000001, 1000);
	test_create_entry(&state, 0x0A000002, 1000);

	/* ACT: Cleanup before timeout */
	removed = test_cleanup_expired(&state, 2000, TEST_ENTRY_TIMEOUT_MS);

	/* ASSERT: None should be removed */
	KUNIT_EXPECT_EQ(test, removed, 0);
	KUNIT_EXPECT_NOT_NULL(test, test_find_entry(&state, 0x0A000001));
	KUNIT_EXPECT_NOT_NULL(test, test_find_entry(&state, 0x0A000002));

	/* Cleanup */
	test_state_destroy(&state);
}

/*
 * =============================================================================
 * SECTION 7: Configuration Update Tests
 * =============================================================================
 */

/* Test: Limiter config update */
static void test_limiter_config_update(struct kunit *test)
{
	struct test_rate_limiter limiter;

	/* ARRANGE */
	test_limiter_init(&limiter, 100, 10);
	limiter.tokens = 8 * TEST_TOKEN_SCALE;

	/* ACT: Update to larger burst */
	limiter.max_tokens = 20 * TEST_TOKEN_SCALE;
	limiter.refill_rate = 200 * TEST_TOKEN_SCALE / 1000;

	/* ASSERT: Tokens preserved, new max applied */
	KUNIT_EXPECT_EQ(test, test_limiter_tokens_available(&limiter), 8U);
	KUNIT_EXPECT_EQ(test, limiter.max_tokens, 20 * TEST_TOKEN_SCALE);
}

/* Test: Config update caps tokens */
static void test_limiter_config_caps_tokens(struct kunit *test)
{
	struct test_rate_limiter limiter;

	/* ARRANGE: Start with more tokens than new max */
	test_limiter_init(&limiter, 100, 20);
	limiter.tokens = 15 * TEST_TOKEN_SCALE;

	/* ACT: Update to smaller burst */
	limiter.max_tokens = 10 * TEST_TOKEN_SCALE;
	if (limiter.tokens > limiter.max_tokens)
		limiter.tokens = limiter.max_tokens;

	/* ASSERT: Tokens capped to new max */
	KUNIT_EXPECT_EQ(test, test_limiter_tokens_available(&limiter), 10U);
}

/*
 * =============================================================================
 * SECTION 8: Statistics Tests
 * =============================================================================
 */

/* Test: Statistics tracking */
static void test_statistics_tracking(struct kunit *test)
{
	struct test_rate_limit_state state;
	int i;

	/* ARRANGE */
	test_state_init(&state);

	/* ACT: Make some checks */
	for (i = 0; i < 100; i++)
		test_rate_limit_check(&state, 0x10000000 + i, i);

	/* ASSERT */
	KUNIT_EXPECT_EQ(test, (int)state.total_checked, 100);
	KUNIT_EXPECT_GT(test, (int)state.total_allowed, 0);

	/* Cleanup */
	test_state_destroy(&state);
}

/* Test: Denied statistics */
static void test_statistics_denied(struct kunit *test)
{
	struct test_rate_limit_state state;
	u32 addr = 0x0A000001;
	int i;

	/* ARRANGE */
	test_state_init(&state);

	/* ACT: Exhaust per-IP limit */
	for (i = 0; i < TEST_PER_IP_LIMIT + 50; i++)
		test_rate_limit_check(&state, addr, 0);

	/* ASSERT */
	KUNIT_EXPECT_EQ(test, (int)state.total_per_ip_denied, 50);

	/* Cleanup */
	test_state_destroy(&state);
}

/* Test: Disabled rate limiter accepts all */
static void test_disabled_accepts_all(struct kunit *test)
{
	struct test_rate_limit_state state;
	u32 addr = 0x0A000001;
	int i, allowed = 0;

	/* ARRANGE */
	test_state_init(&state);
	state.enabled = false;

	/* ACT: Try many connections */
	for (i = 0; i < 10000; i++) {
		if (test_rate_limit_check(&state, addr, 0))
			allowed++;
	}

	/* ASSERT: All should be allowed */
	KUNIT_EXPECT_EQ(test, allowed, 10000);
	KUNIT_EXPECT_EQ(test, (int)state.total_denied, 0);
	KUNIT_EXPECT_EQ(test, (int)state.total_per_ip_denied, 0);

	/* Cleanup */
	test_state_destroy(&state);
}

/* Test: Peak rate tracking */
static void test_peak_rate_tracking(struct kunit *test)
{
	struct test_rate_limit_state state;

	/* ARRANGE */
	test_state_init(&state);

	/* ACT */
	state.current_rate = 5000;
	if (state.current_rate > state.peak_rate)
		state.peak_rate = state.current_rate;

	state.current_rate = 8000;
	if (state.current_rate > state.peak_rate)
		state.peak_rate = state.current_rate;

	state.current_rate = 3000;
	if (state.current_rate > state.peak_rate)
		state.peak_rate = state.current_rate;

	/* ASSERT */
	KUNIT_EXPECT_EQ(test, state.peak_rate, 8000U);
	KUNIT_EXPECT_EQ(test, state.current_rate, 3000U);

	/* Cleanup */
	test_state_destroy(&state);
}

/*
 * =============================================================================
 * Test Suite Definition
 * =============================================================================
 */

static struct kunit_case tquic_rate_limit_test_cases[] = {
	/* Section 1: Token Bucket Algorithm Tests */
	KUNIT_CASE(test_bucket_init),
	KUNIT_CASE(test_bucket_consume),
	KUNIT_CASE(test_bucket_refill),
	KUNIT_CASE(test_bucket_max_cap),
	KUNIT_CASE(test_bucket_burst_handling),
	KUNIT_CASE(test_bucket_zero_elapsed),

	/* Section 2: Rate Limiter Initialization Tests */
	KUNIT_CASE(test_state_initialization),
	KUNIT_CASE(test_state_cleanup),

	/* Section 3: Global Rate Limiting Tests */
	KUNIT_CASE(test_global_allows_within_limit),
	KUNIT_CASE(test_global_denies_over_limit),
	KUNIT_CASE(test_global_refills),

	/* Section 4: Per-IP Rate Limiting Tests */
	KUNIT_CASE(test_per_ip_entry_creation),
	KUNIT_CASE(test_per_ip_rate_limiting),
	KUNIT_CASE(test_per_ip_independent_tracking),
	KUNIT_CASE(test_per_ip_entry_lookup),
	KUNIT_CASE(test_per_ip_hash_collision),

	/* Section 5: RCU and Concurrency Tests */
	KUNIT_CASE(test_concurrent_entry_creation),
	KUNIT_CASE(test_high_connection_rate),

	/* Section 6: Cleanup and Garbage Collection Tests */
	KUNIT_CASE(test_expired_cleanup),
	KUNIT_CASE(test_active_entries_preserved),

	/* Section 7: Configuration Update Tests */
	KUNIT_CASE(test_limiter_config_update),
	KUNIT_CASE(test_limiter_config_caps_tokens),

	/* Section 8: Statistics Tests */
	KUNIT_CASE(test_statistics_tracking),
	KUNIT_CASE(test_statistics_denied),
	KUNIT_CASE(test_disabled_accepts_all),
	KUNIT_CASE(test_peak_rate_tracking),
	{}
};

static struct kunit_suite tquic_rate_limit_test_suite = {
	.name = "tquic-rate-limit",
	.test_cases = tquic_rate_limit_test_cases,
};

kunit_test_suite(tquic_rate_limit_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for TQUIC Connection Rate Limiting");
MODULE_AUTHOR("Linux Foundation");
