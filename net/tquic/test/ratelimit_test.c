// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Rate Limiting KUnit Tests
 *
 * Copyright (c) 2026 Linux Foundation
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Comprehensive tests for TQUIC connection rate limiting:
 *   - Token bucket algorithm
 *   - Per-IP tracking with hash table
 *   - Attack mode detection
 *   - SYN cookie-style validation
 *   - Blacklist management
 *
 * Test Structure:
 *   Section 1: Token Bucket Algorithm Tests
 *   Section 2: Per-IP Tracking Tests
 *   Section 3: Attack Mode Detection Tests
 *   Section 4: Cookie Validation Tests
 *   Section 5: Blacklist Tests
 *   Section 6: Statistics Tests
 */

#include <kunit/test.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/jhash.h>

/*
 * =============================================================================
 * Constants (mirror production values)
 * =============================================================================
 */

/* Token bucket parameters */
#define RL_DEFAULT_MAX_CONN_RATE	1000	/* connections/sec */
#define RL_DEFAULT_RATE_WINDOW_MS	1000	/* 1 second */
#define RL_DEFAULT_BURST_LIMIT		50	/* burst capacity */
#define RL_TOKEN_SCALE			1000	/* Scale factor for precision */

/* Attack detection */
#define RL_ATTACK_THRESHOLD		10000	/* conn/sec triggers attack mode */
#define RL_ATTACK_HYSTERESIS_MS		30000	/* 30 sec to exit attack mode */

/* Cookie parameters */
#define RL_COOKIE_LIFETIME_MS		60000	/* 1 minute */
#define RL_COOKIE_SECRET_LEN		32

/* Hash table */
#define RL_HASH_BITS			10
#define RL_HASH_SIZE			(1 << RL_HASH_BITS)

/* Limits */
#define RL_ENTRY_TIMEOUT_MS		60000
#define RL_GC_INTERVAL_MS		10000

/*
 * =============================================================================
 * Rate Limiting Action Codes
 * =============================================================================
 */

enum test_rl_action {
	TEST_RL_ACCEPT = 0,
	TEST_RL_RATE_LIMITED,
	TEST_RL_COOKIE_REQUIRED,
	TEST_RL_BLACKLISTED,
};

/*
 * =============================================================================
 * Test Data Structures
 * =============================================================================
 */

/**
 * struct test_token_bucket - Token bucket state
 * @tokens: Current token count (scaled by RL_TOKEN_SCALE)
 * @last_refill: Last refill timestamp (ms)
 * @max_tokens: Maximum bucket capacity (scaled)
 * @refill_rate: Tokens per ms (scaled)
 */
struct test_token_bucket {
	s64 tokens;
	u64 last_refill;
	s64 max_tokens;
	s64 refill_rate;
};

/**
 * struct test_rl_entry - Per-IP rate limit entry
 * @addr_hash: Hash of IP address
 * @bucket: Token bucket for this IP
 * @conn_count: Total connection attempts
 * @drop_count: Total dropped connections
 * @first_seen: First seen timestamp
 * @last_seen: Last seen timestamp
 * @blacklisted: IP is blacklisted
 * @cookie_required: Requires cookie validation
 * @list: Hash bucket linkage
 */
struct test_rl_entry {
	u32 addr_hash;
	struct test_token_bucket bucket;
	u64 conn_count;
	u64 drop_count;
	u64 first_seen;
	u64 last_seen;
	bool blacklisted;
	bool cookie_required;
	struct list_head list;
};

/**
 * struct test_rl_state - Global rate limiter state
 * @buckets: Hash table buckets
 * @enabled: Rate limiting enabled
 * @attack_mode: Currently in attack mode
 * @attack_start: When attack mode started
 * @current_rate: Current connection rate
 * @peak_rate: Peak rate observed
 * @cookie_secret: Cookie generation secret
 * @total_checked: Total connections checked
 * @total_accepted: Total connections accepted
 * @total_rate_limited: Total rate limited
 * @total_cookie_required: Total requiring cookie
 * @total_blacklisted: Total blacklisted
 * @attack_mode_entered: Times attack mode entered
 */
struct test_rl_state {
	struct list_head buckets[RL_HASH_SIZE];
	bool enabled;
	bool attack_mode;
	u64 attack_start;
	u32 current_rate;
	u32 peak_rate;
	u8 cookie_secret[RL_COOKIE_SECRET_LEN];
	u64 total_checked;
	u64 total_accepted;
	u64 total_rate_limited;
	u64 total_cookie_required;
	u64 total_blacklisted;
	u64 attack_mode_entered;
};

/*
 * =============================================================================
 * Token Bucket Implementation
 * =============================================================================
 */

/**
 * test_bucket_init - Initialize token bucket
 * @bucket: Bucket to initialize
 * @max_tokens: Maximum tokens (unscaled)
 * @refill_rate_per_sec: Tokens per second (unscaled)
 */
static void test_bucket_init(struct test_token_bucket *bucket,
			     u32 max_tokens, u32 refill_rate_per_sec)
{
	bucket->max_tokens = (s64)max_tokens * RL_TOKEN_SCALE;
	bucket->tokens = bucket->max_tokens;  /* Start full */
	bucket->refill_rate = ((s64)refill_rate_per_sec * RL_TOKEN_SCALE) / 1000;
	bucket->last_refill = 0;
}

/**
 * test_bucket_refill - Refill tokens based on elapsed time
 * @bucket: Token bucket
 * @now_ms: Current time in ms
 */
static void test_bucket_refill(struct test_token_bucket *bucket, u64 now_ms)
{
	u64 elapsed;
	s64 new_tokens;

	if (now_ms <= bucket->last_refill)
		return;

	elapsed = now_ms - bucket->last_refill;
	new_tokens = elapsed * bucket->refill_rate;

	bucket->tokens = min(bucket->tokens + new_tokens, bucket->max_tokens);
	bucket->last_refill = now_ms;
}

/**
 * test_bucket_consume - Try to consume a token
 * @bucket: Token bucket
 * @now_ms: Current time in ms
 *
 * Returns: true if token consumed, false if empty
 */
static bool test_bucket_consume(struct test_token_bucket *bucket, u64 now_ms)
{
	test_bucket_refill(bucket, now_ms);

	if (bucket->tokens >= RL_TOKEN_SCALE) {
		bucket->tokens -= RL_TOKEN_SCALE;
		return true;
	}

	return false;
}

/**
 * test_bucket_tokens_available - Get available tokens
 * @bucket: Token bucket
 *
 * Returns: Number of available tokens (unscaled)
 */
static u32 test_bucket_tokens_available(const struct test_token_bucket *bucket)
{
	return bucket->tokens / RL_TOKEN_SCALE;
}

/*
 * =============================================================================
 * Rate Limiter State Management
 * =============================================================================
 */

/**
 * test_rl_state_init - Initialize rate limiter state
 * @state: State to initialize
 */
static void test_rl_state_init(struct test_rl_state *state)
{
	int i;

	memset(state, 0, sizeof(*state));
	for (i = 0; i < RL_HASH_SIZE; i++)
		INIT_LIST_HEAD(&state->buckets[i]);

	state->enabled = true;
	memset(state->cookie_secret, 0x42, RL_COOKIE_SECRET_LEN);
}

/**
 * test_rl_state_destroy - Clean up rate limiter state
 * @state: State to destroy
 */
static void test_rl_state_destroy(struct test_rl_state *state)
{
	struct test_rl_entry *entry, *tmp;
	int i;

	for (i = 0; i < RL_HASH_SIZE; i++) {
		list_for_each_entry_safe(entry, tmp, &state->buckets[i], list) {
			list_del(&entry->list);
			kfree(entry);
		}
	}
}

/**
 * test_rl_hash_addr - Hash an IP address
 * @addr: IP address (4 bytes for IPv4, 16 for IPv6)
 * @len: Address length
 *
 * Returns: Hash value
 */
static u32 test_rl_hash_addr(const u8 *addr, size_t len)
{
	return jhash(addr, len, 0) & (RL_HASH_SIZE - 1);
}

/**
 * test_rl_find_entry - Find entry for address
 * @state: Rate limiter state
 * @addr_hash: Address hash
 *
 * Returns: Entry or NULL
 */
static struct test_rl_entry *test_rl_find_entry(struct test_rl_state *state,
						u32 addr_hash)
{
	struct test_rl_entry *entry;
	u32 bucket_idx = addr_hash & (RL_HASH_SIZE - 1);

	list_for_each_entry(entry, &state->buckets[bucket_idx], list) {
		if (entry->addr_hash == addr_hash)
			return entry;
	}

	return NULL;
}

/**
 * test_rl_create_entry - Create new entry
 * @state: Rate limiter state
 * @addr_hash: Address hash
 * @now_ms: Current time
 *
 * Returns: New entry or NULL
 */
static struct test_rl_entry *test_rl_create_entry(struct test_rl_state *state,
						  u32 addr_hash, u64 now_ms)
{
	struct test_rl_entry *entry;
	u32 bucket_idx = addr_hash & (RL_HASH_SIZE - 1);

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return NULL;

	entry->addr_hash = addr_hash;
	test_bucket_init(&entry->bucket, RL_DEFAULT_BURST_LIMIT,
			 RL_DEFAULT_MAX_CONN_RATE);
	entry->bucket.last_refill = now_ms;
	entry->first_seen = now_ms;
	entry->last_seen = now_ms;

	list_add(&entry->list, &state->buckets[bucket_idx]);

	return entry;
}

/**
 * test_rl_check - Check rate limit for address
 * @state: Rate limiter state
 * @addr_hash: Address hash
 * @now_ms: Current time
 *
 * Returns: Rate limit action
 */
static enum test_rl_action test_rl_check(struct test_rl_state *state,
					 u32 addr_hash, u64 now_ms)
{
	struct test_rl_entry *entry;
	enum test_rl_action action = TEST_RL_ACCEPT;

	if (!state->enabled)
		return TEST_RL_ACCEPT;

	state->total_checked++;

	entry = test_rl_find_entry(state, addr_hash);
	if (!entry) {
		entry = test_rl_create_entry(state, addr_hash, now_ms);
		if (!entry)
			return TEST_RL_RATE_LIMITED;  /* Fail closed */
	}

	entry->last_seen = now_ms;
	entry->conn_count++;

	/* Check blacklist */
	if (entry->blacklisted) {
		state->total_blacklisted++;
		entry->drop_count++;
		return TEST_RL_BLACKLISTED;
	}

	/* Check if cookie required (attack mode) */
	if (state->attack_mode && entry->cookie_required) {
		state->total_cookie_required++;
		return TEST_RL_COOKIE_REQUIRED;
	}

	/* Token bucket check */
	if (!test_bucket_consume(&entry->bucket, now_ms)) {
		state->total_rate_limited++;
		entry->drop_count++;

		/* In attack mode, require cookie after rate limit */
		if (state->attack_mode)
			entry->cookie_required = true;

		return TEST_RL_RATE_LIMITED;
	}

	state->total_accepted++;
	return TEST_RL_ACCEPT;
}

/**
 * test_rl_blacklist_add - Add address to blacklist
 * @state: Rate limiter state
 * @addr_hash: Address hash
 * @now_ms: Current time
 *
 * Returns: 0 on success
 */
static int test_rl_blacklist_add(struct test_rl_state *state,
				 u32 addr_hash, u64 now_ms)
{
	struct test_rl_entry *entry;

	entry = test_rl_find_entry(state, addr_hash);
	if (!entry)
		entry = test_rl_create_entry(state, addr_hash, now_ms);

	if (!entry)
		return -ENOMEM;

	entry->blacklisted = true;
	return 0;
}

/**
 * test_rl_blacklist_remove - Remove address from blacklist
 * @state: Rate limiter state
 * @addr_hash: Address hash
 *
 * Returns: 0 on success, -ENOENT if not found
 */
static int test_rl_blacklist_remove(struct test_rl_state *state, u32 addr_hash)
{
	struct test_rl_entry *entry;

	entry = test_rl_find_entry(state, addr_hash);
	if (!entry || !entry->blacklisted)
		return -ENOENT;

	entry->blacklisted = false;
	return 0;
}

/**
 * test_rl_enter_attack_mode - Enter attack mode
 * @state: Rate limiter state
 * @now_ms: Current time
 */
static void test_rl_enter_attack_mode(struct test_rl_state *state, u64 now_ms)
{
	if (!state->attack_mode) {
		state->attack_mode = true;
		state->attack_start = now_ms;
		state->attack_mode_entered++;
	}
}

/**
 * test_rl_exit_attack_mode - Exit attack mode
 * @state: Rate limiter state
 * @now_ms: Current time
 *
 * Returns: true if exited, false if hysteresis period not passed
 */
static bool test_rl_exit_attack_mode(struct test_rl_state *state, u64 now_ms)
{
	if (!state->attack_mode)
		return true;

	if (now_ms - state->attack_start >= RL_ATTACK_HYSTERESIS_MS) {
		state->attack_mode = false;
		return true;
	}

	return false;
}

/**
 * test_rl_update_rate - Update current connection rate
 * @state: Rate limiter state
 * @rate: New rate
 */
static void test_rl_update_rate(struct test_rl_state *state, u32 rate)
{
	state->current_rate = rate;
	if (rate > state->peak_rate)
		state->peak_rate = rate;

	/* Check if we should enter attack mode */
	if (rate >= RL_ATTACK_THRESHOLD)
		test_rl_enter_attack_mode(state, 0);  /* Time 0 for test */
}

/*
 * =============================================================================
 * Cookie Validation Helpers
 * =============================================================================
 */

/**
 * test_cookie_generate - Generate a validation cookie
 * @secret: Secret key
 * @addr_hash: Source address hash
 * @timestamp: Current timestamp
 * @cookie: Output cookie buffer (16 bytes)
 */
static void test_cookie_generate(const u8 *secret, u32 addr_hash,
				 u64 timestamp, u8 *cookie)
{
	/* Simple hash-based cookie for testing */
	u32 hash1 = jhash(secret, 16, addr_hash);
	u32 hash2 = jhash(secret + 16, 16, (u32)timestamp);
	u32 hash3 = jhash(&hash1, sizeof(hash1), hash2);
	u32 hash4 = jhash(&timestamp, sizeof(timestamp), hash1);

	memcpy(cookie, &hash1, 4);
	memcpy(cookie + 4, &hash2, 4);
	memcpy(cookie + 8, &hash3, 4);
	memcpy(cookie + 12, &hash4, 4);
}

/**
 * test_cookie_validate - Validate a cookie
 * @secret: Secret key
 * @addr_hash: Source address hash
 * @timestamp: Cookie timestamp
 * @now_ms: Current time
 * @cookie: Cookie to validate
 *
 * Returns: 0 if valid, -EINVAL if invalid, -ETIMEDOUT if expired
 */
static int test_cookie_validate(const u8 *secret, u32 addr_hash,
				u64 timestamp, u64 now_ms, const u8 *cookie)
{
	u8 expected[16];

	/* Check expiry */
	if (now_ms > timestamp + RL_COOKIE_LIFETIME_MS)
		return -ETIMEDOUT;

	/* Regenerate expected cookie */
	test_cookie_generate(secret, addr_hash, timestamp, expected);

	/* Compare */
	if (memcmp(cookie, expected, 16) != 0)
		return -EINVAL;

	return 0;
}

/*
 * =============================================================================
 * SECTION 1: Token Bucket Algorithm Tests
 * =============================================================================
 */

/* Test: Token bucket initialization */
static void test_bucket_init_state(struct kunit *test)
{
	struct test_token_bucket bucket;

	/* ACT */
	test_bucket_init(&bucket, 50, 1000);

	/* ASSERT */
	KUNIT_EXPECT_EQ(test, test_bucket_tokens_available(&bucket), 50U);
	KUNIT_EXPECT_EQ(test, bucket.max_tokens, 50 * RL_TOKEN_SCALE);
}

/* Test: Token consumption */
static void test_bucket_consume_tokens(struct kunit *test)
{
	struct test_token_bucket bucket;
	int i;

	/* ARRANGE */
	test_bucket_init(&bucket, 5, 1000);

	/* ACT/ASSERT: Consume all tokens */
	for (i = 0; i < 5; i++) {
		KUNIT_EXPECT_TRUE(test, test_bucket_consume(&bucket, 0));
	}

	/* ASSERT: Next consumption should fail */
	KUNIT_EXPECT_FALSE(test, test_bucket_consume(&bucket, 0));
	KUNIT_EXPECT_EQ(test, test_bucket_tokens_available(&bucket), 0U);
}

/* Test: Token refill over time */
static void test_bucket_refill_tokens(struct kunit *test)
{
	struct test_token_bucket bucket;

	/* ARRANGE: Empty bucket */
	test_bucket_init(&bucket, 10, 1000);  /* 1000/sec = 1/ms */
	bucket.tokens = 0;
	bucket.last_refill = 0;

	/* ACT: Refill after 5ms */
	test_bucket_refill(&bucket, 5);

	/* ASSERT: Should have ~5 tokens */
	KUNIT_EXPECT_GE(test, test_bucket_tokens_available(&bucket), 4U);
	KUNIT_EXPECT_LE(test, test_bucket_tokens_available(&bucket), 6U);
}

/* Test: Token bucket cap at max */
static void test_bucket_max_cap(struct kunit *test)
{
	struct test_token_bucket bucket;

	/* ARRANGE */
	test_bucket_init(&bucket, 10, 1000);
	bucket.last_refill = 0;

	/* ACT: Refill for a long time */
	test_bucket_refill(&bucket, 1000000);  /* 1000 seconds */

	/* ASSERT: Should be capped at max */
	KUNIT_EXPECT_EQ(test, test_bucket_tokens_available(&bucket), 10U);
}

/* Test: Burst handling */
static void test_bucket_burst(struct kunit *test)
{
	struct test_token_bucket bucket;
	int consumed = 0;
	int i;

	/* ARRANGE: Bucket with burst capacity */
	test_bucket_init(&bucket, 10, 100);  /* 100/sec but 10 burst */

	/* ACT: Try to consume 20 in burst */
	for (i = 0; i < 20; i++) {
		if (test_bucket_consume(&bucket, 0))
			consumed++;
	}

	/* ASSERT: Only burst amount consumed */
	KUNIT_EXPECT_EQ(test, consumed, 10);
}

/*
 * =============================================================================
 * SECTION 2: Per-IP Tracking Tests
 * =============================================================================
 */

/* Test: Entry creation */
static void test_per_ip_entry_creation(struct kunit *test)
{
	struct test_rl_state state;
	struct test_rl_entry *entry;
	u32 addr_hash = 0x12345678;

	/* ARRANGE */
	test_rl_state_init(&state);

	/* ACT */
	entry = test_rl_create_entry(&state, addr_hash, 1000);

	/* ASSERT */
	KUNIT_EXPECT_NOT_NULL(test, entry);
	KUNIT_EXPECT_EQ(test, entry->addr_hash, addr_hash);
	KUNIT_EXPECT_EQ(test, entry->first_seen, 1000ULL);
	KUNIT_EXPECT_FALSE(test, entry->blacklisted);

	/* Cleanup */
	test_rl_state_destroy(&state);
}

/* Test: Entry lookup */
static void test_per_ip_entry_lookup(struct kunit *test)
{
	struct test_rl_state state;
	struct test_rl_entry *created, *found;
	u32 addr_hash = 0xDEADBEEF;

	/* ARRANGE */
	test_rl_state_init(&state);
	created = test_rl_create_entry(&state, addr_hash, 0);

	/* ACT */
	found = test_rl_find_entry(&state, addr_hash);

	/* ASSERT */
	KUNIT_EXPECT_EQ(test, found, created);

	/* Cleanup */
	test_rl_state_destroy(&state);
}

/* Test: Multiple IPs tracked independently */
static void test_per_ip_independent(struct kunit *test)
{
	struct test_rl_state state;
	enum test_rl_action action;
	u32 addr1 = 0x11111111;
	u32 addr2 = 0x22222222;
	int i;

	/* ARRANGE */
	test_rl_state_init(&state);

	/* ACT: Exhaust addr1's bucket */
	for (i = 0; i < 100; i++) {
		test_rl_check(&state, addr1, 0);
	}

	/* ASSERT: addr1 should be rate limited, addr2 should be accepted */
	action = test_rl_check(&state, addr1, 0);
	KUNIT_EXPECT_EQ(test, action, TEST_RL_RATE_LIMITED);

	action = test_rl_check(&state, addr2, 0);
	KUNIT_EXPECT_EQ(test, action, TEST_RL_ACCEPT);

	/* Cleanup */
	test_rl_state_destroy(&state);
}

/* Test: Hash collision handling */
static void test_per_ip_hash_collision(struct kunit *test)
{
	struct test_rl_state state;
	struct test_rl_entry *entry1, *entry2;
	u32 addr1 = 0x00000001;
	u32 addr2 = addr1 + RL_HASH_SIZE;  /* Same bucket, different hash */

	/* ARRANGE */
	test_rl_state_init(&state);

	/* ACT */
	entry1 = test_rl_create_entry(&state, addr1, 0);
	entry2 = test_rl_create_entry(&state, addr2, 0);

	/* ASSERT: Both should be found */
	KUNIT_EXPECT_NOT_NULL(test, test_rl_find_entry(&state, addr1));
	KUNIT_EXPECT_NOT_NULL(test, test_rl_find_entry(&state, addr2));
	KUNIT_EXPECT_NE(test, (void *)entry1, (void *)entry2);

	/* Cleanup */
	test_rl_state_destroy(&state);
}

/*
 * =============================================================================
 * SECTION 3: Attack Mode Detection Tests
 * =============================================================================
 */

/* Test: Attack mode triggered by high rate */
static void test_attack_mode_trigger(struct kunit *test)
{
	struct test_rl_state state;

	/* ARRANGE */
	test_rl_state_init(&state);
	KUNIT_EXPECT_FALSE(test, state.attack_mode);

	/* ACT */
	test_rl_update_rate(&state, RL_ATTACK_THRESHOLD);

	/* ASSERT */
	KUNIT_EXPECT_TRUE(test, state.attack_mode);
	KUNIT_EXPECT_EQ(test, state.attack_mode_entered, 1ULL);
}

/* Test: Attack mode not triggered below threshold */
static void test_attack_mode_below_threshold(struct kunit *test)
{
	struct test_rl_state state;

	/* ARRANGE */
	test_rl_state_init(&state);

	/* ACT */
	test_rl_update_rate(&state, RL_ATTACK_THRESHOLD - 1);

	/* ASSERT */
	KUNIT_EXPECT_FALSE(test, state.attack_mode);
}

/* Test: Attack mode hysteresis */
static void test_attack_mode_hysteresis(struct kunit *test)
{
	struct test_rl_state state;

	/* ARRANGE */
	test_rl_state_init(&state);
	test_rl_enter_attack_mode(&state, 1000);

	/* ACT/ASSERT: Cannot exit before hysteresis period */
	KUNIT_EXPECT_FALSE(test, test_rl_exit_attack_mode(&state, 1000 + RL_ATTACK_HYSTERESIS_MS - 1));
	KUNIT_EXPECT_TRUE(test, state.attack_mode);

	/* ACT/ASSERT: Can exit after hysteresis period */
	KUNIT_EXPECT_TRUE(test, test_rl_exit_attack_mode(&state, 1000 + RL_ATTACK_HYSTERESIS_MS));
	KUNIT_EXPECT_FALSE(test, state.attack_mode);
}

/* Test: Peak rate tracking */
static void test_peak_rate_tracking(struct kunit *test)
{
	struct test_rl_state state;

	/* ARRANGE */
	test_rl_state_init(&state);

	/* ACT */
	test_rl_update_rate(&state, 5000);
	test_rl_update_rate(&state, 8000);
	test_rl_update_rate(&state, 3000);

	/* ASSERT */
	KUNIT_EXPECT_EQ(test, state.peak_rate, 8000U);
	KUNIT_EXPECT_EQ(test, state.current_rate, 3000U);
}

/* Test: Attack mode requires cookie */
static void test_attack_mode_cookie_required(struct kunit *test)
{
	struct test_rl_state state;
	u32 addr_hash = 0x12345678;
	enum test_rl_action action;
	int i;

	/* ARRANGE: Enable attack mode */
	test_rl_state_init(&state);
	test_rl_enter_attack_mode(&state, 0);

	/* Exhaust tokens to trigger rate limit */
	for (i = 0; i < 100; i++) {
		test_rl_check(&state, addr_hash, 0);
	}

	/* ACT: Next check should require cookie */
	action = test_rl_check(&state, addr_hash, 0);

	/* ASSERT */
	KUNIT_EXPECT_EQ(test, action, TEST_RL_COOKIE_REQUIRED);

	/* Cleanup */
	test_rl_state_destroy(&state);
}

/*
 * =============================================================================
 * SECTION 4: Cookie Validation Tests
 * =============================================================================
 */

/* Test: Valid cookie accepted */
static void test_cookie_valid(struct kunit *test)
{
	u8 secret[RL_COOKIE_SECRET_LEN];
	u8 cookie[16];
	u32 addr_hash = 0xABCDEF00;
	u64 timestamp = 1000;
	int ret;

	/* ARRANGE */
	memset(secret, 0x42, sizeof(secret));
	test_cookie_generate(secret, addr_hash, timestamp, cookie);

	/* ACT */
	ret = test_cookie_validate(secret, addr_hash, timestamp, 1500, cookie);

	/* ASSERT */
	KUNIT_EXPECT_EQ(test, ret, 0);
}

/* Test: Expired cookie rejected */
static void test_cookie_expired(struct kunit *test)
{
	u8 secret[RL_COOKIE_SECRET_LEN];
	u8 cookie[16];
	u32 addr_hash = 0xABCDEF00;
	u64 timestamp = 1000;
	int ret;

	/* ARRANGE */
	memset(secret, 0x42, sizeof(secret));
	test_cookie_generate(secret, addr_hash, timestamp, cookie);

	/* ACT: Validate after expiry */
	ret = test_cookie_validate(secret, addr_hash, timestamp,
				   timestamp + RL_COOKIE_LIFETIME_MS + 1, cookie);

	/* ASSERT */
	KUNIT_EXPECT_EQ(test, ret, -ETIMEDOUT);
}

/* Test: Invalid cookie rejected */
static void test_cookie_invalid(struct kunit *test)
{
	u8 secret[RL_COOKIE_SECRET_LEN];
	u8 cookie[16];
	u32 addr_hash = 0xABCDEF00;
	u64 timestamp = 1000;
	int ret;

	/* ARRANGE */
	memset(secret, 0x42, sizeof(secret));
	memset(cookie, 0xFF, sizeof(cookie));  /* Invalid cookie */

	/* ACT */
	ret = test_cookie_validate(secret, addr_hash, timestamp, 1500, cookie);

	/* ASSERT */
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

/* Test: Cookie for wrong address rejected */
static void test_cookie_wrong_address(struct kunit *test)
{
	u8 secret[RL_COOKIE_SECRET_LEN];
	u8 cookie[16];
	u32 addr_hash1 = 0xABCDEF00;
	u32 addr_hash2 = 0x12345678;
	u64 timestamp = 1000;
	int ret;

	/* ARRANGE: Generate cookie for addr1 */
	memset(secret, 0x42, sizeof(secret));
	test_cookie_generate(secret, addr_hash1, timestamp, cookie);

	/* ACT: Validate with addr2 */
	ret = test_cookie_validate(secret, addr_hash2, timestamp, 1500, cookie);

	/* ASSERT */
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

/*
 * =============================================================================
 * SECTION 5: Blacklist Tests
 * =============================================================================
 */

/* Test: Add to blacklist */
static void test_blacklist_add(struct kunit *test)
{
	struct test_rl_state state;
	u32 addr_hash = 0x11111111;
	enum test_rl_action action;
	int ret;

	/* ARRANGE */
	test_rl_state_init(&state);

	/* ACT */
	ret = test_rl_blacklist_add(&state, addr_hash, 0);

	/* ASSERT */
	KUNIT_EXPECT_EQ(test, ret, 0);
	action = test_rl_check(&state, addr_hash, 0);
	KUNIT_EXPECT_EQ(test, action, TEST_RL_BLACKLISTED);

	/* Cleanup */
	test_rl_state_destroy(&state);
}

/* Test: Remove from blacklist */
static void test_blacklist_remove(struct kunit *test)
{
	struct test_rl_state state;
	u32 addr_hash = 0x22222222;
	enum test_rl_action action;
	int ret;

	/* ARRANGE */
	test_rl_state_init(&state);
	test_rl_blacklist_add(&state, addr_hash, 0);

	/* ACT */
	ret = test_rl_blacklist_remove(&state, addr_hash);

	/* ASSERT */
	KUNIT_EXPECT_EQ(test, ret, 0);
	action = test_rl_check(&state, addr_hash, 0);
	KUNIT_EXPECT_EQ(test, action, TEST_RL_ACCEPT);

	/* Cleanup */
	test_rl_state_destroy(&state);
}

/* Test: Remove non-existent blacklist entry */
static void test_blacklist_remove_not_found(struct kunit *test)
{
	struct test_rl_state state;
	int ret;

	/* ARRANGE */
	test_rl_state_init(&state);

	/* ACT */
	ret = test_rl_blacklist_remove(&state, 0x99999999);

	/* ASSERT */
	KUNIT_EXPECT_EQ(test, ret, -ENOENT);

	/* Cleanup */
	test_rl_state_destroy(&state);
}

/* Test: Blacklist takes precedence */
static void test_blacklist_precedence(struct kunit *test)
{
	struct test_rl_state state;
	u32 addr_hash = 0x33333333;
	enum test_rl_action action;

	/* ARRANGE: Create entry with tokens, then blacklist */
	test_rl_state_init(&state);
	test_rl_check(&state, addr_hash, 0);  /* Create entry */
	test_rl_blacklist_add(&state, addr_hash, 0);

	/* ACT */
	action = test_rl_check(&state, addr_hash, 0);

	/* ASSERT: Blacklist should take precedence over rate limit */
	KUNIT_EXPECT_EQ(test, action, TEST_RL_BLACKLISTED);

	/* Cleanup */
	test_rl_state_destroy(&state);
}

/*
 * =============================================================================
 * SECTION 6: Statistics Tests
 * =============================================================================
 */

/* Test: Statistics tracking */
static void test_statistics_tracking(struct kunit *test)
{
	struct test_rl_state state;
	u32 addr_hash = 0x44444444;
	int i;

	/* ARRANGE */
	test_rl_state_init(&state);

	/* ACT: Make some checks */
	for (i = 0; i < 10; i++) {
		test_rl_check(&state, addr_hash, i);
	}

	/* ASSERT */
	KUNIT_EXPECT_EQ(test, state.total_checked, 10ULL);
	KUNIT_EXPECT_GT(test, state.total_accepted, 0ULL);

	/* Cleanup */
	test_rl_state_destroy(&state);
}

/* Test: Rate limited count */
static void test_statistics_rate_limited(struct kunit *test)
{
	struct test_rl_state state;
	u32 addr_hash = 0x55555555;
	int i;

	/* ARRANGE */
	test_rl_state_init(&state);

	/* ACT: Exhaust tokens */
	for (i = 0; i < 100; i++) {
		test_rl_check(&state, addr_hash, 0);
	}

	/* ASSERT */
	KUNIT_EXPECT_GT(test, state.total_rate_limited, 0ULL);

	/* Cleanup */
	test_rl_state_destroy(&state);
}

/* Test: Blacklisted count */
static void test_statistics_blacklisted(struct kunit *test)
{
	struct test_rl_state state;
	u32 addr_hash = 0x66666666;

	/* ARRANGE */
	test_rl_state_init(&state);
	test_rl_blacklist_add(&state, addr_hash, 0);

	/* ACT */
	test_rl_check(&state, addr_hash, 0);
	test_rl_check(&state, addr_hash, 0);
	test_rl_check(&state, addr_hash, 0);

	/* ASSERT */
	KUNIT_EXPECT_EQ(test, state.total_blacklisted, 3ULL);

	/* Cleanup */
	test_rl_state_destroy(&state);
}

/* Test: Disabled rate limiter accepts all */
static void test_disabled_accepts_all(struct kunit *test)
{
	struct test_rl_state state;
	u32 addr_hash = 0x77777777;
	enum test_rl_action action;
	int i;

	/* ARRANGE */
	test_rl_state_init(&state);
	state.enabled = false;

	/* ACT: Many checks */
	for (i = 0; i < 1000; i++) {
		action = test_rl_check(&state, addr_hash, 0);
		KUNIT_EXPECT_EQ(test, action, TEST_RL_ACCEPT);
	}

	/* ASSERT */
	KUNIT_EXPECT_EQ(test, state.total_rate_limited, 0ULL);

	/* Cleanup */
	test_rl_state_destroy(&state);
}

/*
 * =============================================================================
 * Test Suite Definition
 * =============================================================================
 */

static struct kunit_case tquic_ratelimit_test_cases[] = {
	/* Token Bucket Tests */
	KUNIT_CASE(test_bucket_init_state),
	KUNIT_CASE(test_bucket_consume_tokens),
	KUNIT_CASE(test_bucket_refill_tokens),
	KUNIT_CASE(test_bucket_max_cap),
	KUNIT_CASE(test_bucket_burst),

	/* Per-IP Tracking Tests */
	KUNIT_CASE(test_per_ip_entry_creation),
	KUNIT_CASE(test_per_ip_entry_lookup),
	KUNIT_CASE(test_per_ip_independent),
	KUNIT_CASE(test_per_ip_hash_collision),

	/* Attack Mode Tests */
	KUNIT_CASE(test_attack_mode_trigger),
	KUNIT_CASE(test_attack_mode_below_threshold),
	KUNIT_CASE(test_attack_mode_hysteresis),
	KUNIT_CASE(test_peak_rate_tracking),
	KUNIT_CASE(test_attack_mode_cookie_required),

	/* Cookie Validation Tests */
	KUNIT_CASE(test_cookie_valid),
	KUNIT_CASE(test_cookie_expired),
	KUNIT_CASE(test_cookie_invalid),
	KUNIT_CASE(test_cookie_wrong_address),

	/* Blacklist Tests */
	KUNIT_CASE(test_blacklist_add),
	KUNIT_CASE(test_blacklist_remove),
	KUNIT_CASE(test_blacklist_remove_not_found),
	KUNIT_CASE(test_blacklist_precedence),

	/* Statistics Tests */
	KUNIT_CASE(test_statistics_tracking),
	KUNIT_CASE(test_statistics_rate_limited),
	KUNIT_CASE(test_statistics_blacklisted),
	KUNIT_CASE(test_disabled_accepts_all),
	{}
};

static struct kunit_suite tquic_ratelimit_test_suite = {
	.name = "tquic-ratelimit",
	.test_cases = tquic_ratelimit_test_cases,
};

kunit_test_suite(tquic_ratelimit_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for TQUIC Rate Limiting");
MODULE_AUTHOR("Linux Foundation");
