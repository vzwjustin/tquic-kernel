// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC QUIC-Exfil Mitigation KUnit Tests
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Tests for QUIC-Exfil mitigation features:
 * - Timing normalization
 * - Constant-time operations
 * - Traffic analysis protection
 * - Spin bit randomization
 * - Packet timing jitter
 *
 * Reference: draft-iab-quic-exfil-01
 */

#include <kunit/test.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/random.h>

#include "../security/quic_exfil.h"

/*
 * =============================================================================
 * Test Fixtures
 * =============================================================================
 */

struct exfil_test_context {
	struct tquic_timing_normalizer timing;
	struct tquic_traffic_shaper shaper;
	struct tquic_spin_randomizer spin_rand;
	struct tquic_packet_jitter jitter;
	struct tquic_exfil_ctx *ctx;
	struct sk_buff *test_skb;
};

static int exfil_test_init(struct kunit *test)
{
	struct exfil_test_context *ctx;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);

	/* Allocate test skb */
	ctx->test_skb = alloc_skb(1500, GFP_KERNEL);
	if (ctx->test_skb) {
		skb_put(ctx->test_skb, 100);
		memset(ctx->test_skb->data, 0xAA, 100);
	}

	test->priv = ctx;
	return 0;
}

static void exfil_test_exit(struct kunit *test)
{
	struct exfil_test_context *ctx = test->priv;

	if (ctx && ctx->test_skb)
		kfree_skb(ctx->test_skb);
}

/*
 * =============================================================================
 * Timing Normalization Tests
 * =============================================================================
 */

static void test_timing_normalizer_init_none(struct kunit *test)
{
	struct exfil_test_context *ctx = test->priv;
	int ret;

	ret = tquic_timing_normalizer_init(&ctx->timing, TQUIC_EXFIL_LEVEL_NONE);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_FALSE(test, ctx->timing.enabled);
	KUNIT_EXPECT_EQ(test, ctx->timing.delay_max_us, 0);

	tquic_timing_normalizer_destroy(&ctx->timing);
}

static void test_timing_normalizer_init_medium(struct kunit *test)
{
	struct exfil_test_context *ctx = test->priv;
	int ret;

	ret = tquic_timing_normalizer_init(&ctx->timing, TQUIC_EXFIL_LEVEL_MEDIUM);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_TRUE(test, ctx->timing.enabled);
	KUNIT_EXPECT_EQ(test, ctx->timing.delay_max_us,
			TQUIC_EXFIL_DELAY_MEDIUM_MAX_US);

	tquic_timing_normalizer_destroy(&ctx->timing);
}

static void test_timing_normalizer_init_paranoid(struct kunit *test)
{
	struct exfil_test_context *ctx = test->priv;
	int ret;

	ret = tquic_timing_normalizer_init(&ctx->timing, TQUIC_EXFIL_LEVEL_PARANOID);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_TRUE(test, ctx->timing.enabled);
	KUNIT_EXPECT_EQ(test, ctx->timing.delay_min_us,
			TQUIC_EXFIL_DELAY_PARANOID_BASE_US);

	tquic_timing_normalizer_destroy(&ctx->timing);
}

static void test_timing_normalizer_set_level(struct kunit *test)
{
	struct exfil_test_context *ctx = test->priv;
	int ret;

	ret = tquic_timing_normalizer_init(&ctx->timing, TQUIC_EXFIL_LEVEL_LOW);
	KUNIT_ASSERT_EQ(test, ret, 0);

	KUNIT_EXPECT_EQ(test, ctx->timing.delay_max_us,
			TQUIC_EXFIL_DELAY_LOW_MAX_US);

	tquic_timing_normalizer_set_level(&ctx->timing, TQUIC_EXFIL_LEVEL_HIGH);
	KUNIT_EXPECT_EQ(test, ctx->timing.delay_max_us,
			TQUIC_EXFIL_DELAY_HIGH_MAX_US);

	tquic_timing_normalizer_set_level(&ctx->timing, TQUIC_EXFIL_LEVEL_NONE);
	KUNIT_EXPECT_FALSE(test, ctx->timing.enabled);

	tquic_timing_normalizer_destroy(&ctx->timing);
}

static void test_timing_normalizer_process(struct kunit *test)
{
	struct exfil_test_context *ctx = test->priv;
	int ret;
	u64 delays_before, delays_after;

	/* Test with disabled normalizer */
	ret = tquic_timing_normalizer_init(&ctx->timing, TQUIC_EXFIL_LEVEL_NONE);
	KUNIT_ASSERT_EQ(test, ret, 0);

	delays_before = atomic64_read(&ctx->timing.total_delays);
	tquic_timing_normalize_process(&ctx->timing);
	delays_after = atomic64_read(&ctx->timing.total_delays);

	KUNIT_EXPECT_EQ(test, delays_before, delays_after);

	tquic_timing_normalizer_destroy(&ctx->timing);

	/* Test with enabled normalizer (low level for speed) */
	ret = tquic_timing_normalizer_init(&ctx->timing, TQUIC_EXFIL_LEVEL_LOW);
	KUNIT_ASSERT_EQ(test, ret, 0);

	delays_before = atomic64_read(&ctx->timing.total_delays);
	tquic_timing_normalize_process(&ctx->timing);
	delays_after = atomic64_read(&ctx->timing.total_delays);

	KUNIT_EXPECT_GT(test, delays_after, delays_before);

	tquic_timing_normalizer_destroy(&ctx->timing);
}

/*
 * =============================================================================
 * Constant-Time Operations Tests
 * =============================================================================
 */

static void test_ct_memcmp_equal(struct kunit *test)
{
	u8 buf1[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		       0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
	u8 buf2[16];
	int result;

	memcpy(buf2, buf1, sizeof(buf1));

	result = tquic_ct_memcmp(buf1, buf2, sizeof(buf1));
	KUNIT_EXPECT_EQ(test, result, 0);
}

static void test_ct_memcmp_different(struct kunit *test)
{
	u8 buf1[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		       0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
	u8 buf2[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		       0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0xFF};
	int result;

	result = tquic_ct_memcmp(buf1, buf2, sizeof(buf1));
	KUNIT_EXPECT_NE(test, result, 0);
}

static void test_ct_memcmp_first_byte(struct kunit *test)
{
	u8 buf1[16] = {0x00};
	u8 buf2[16] = {0xFF};
	int result;

	memset(buf1, 0, sizeof(buf1));
	memset(buf2, 0, sizeof(buf2));
	buf2[0] = 0xFF;

	result = tquic_ct_memcmp(buf1, buf2, sizeof(buf1));
	KUNIT_EXPECT_NE(test, result, 0);
}

static void test_ct_memcpy(struct kunit *test)
{
	u8 src[32];
	u8 dst[32];
	int i;

	for (i = 0; i < 32; i++)
		src[i] = (u8)i;

	memset(dst, 0xFF, sizeof(dst));

	tquic_ct_memcpy(dst, src, sizeof(src));

	KUNIT_EXPECT_EQ(test, tquic_ct_memcmp(src, dst, sizeof(src)), 0);
}

static void test_ct_select(struct kunit *test)
{
	u8 a[8] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
	u8 b[8] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11};
	u8 dst[8];

	/* Select a (sel != 0) */
	tquic_ct_select(dst, a, b, sizeof(a), 1);
	KUNIT_EXPECT_EQ(test, tquic_ct_memcmp(dst, a, sizeof(a)), 0);

	/* Select b (sel == 0) */
	tquic_ct_select(dst, a, b, sizeof(a), 0);
	KUNIT_EXPECT_EQ(test, tquic_ct_memcmp(dst, b, sizeof(b)), 0);
}

static void test_ct_validate_cid(struct kunit *test)
{
	u8 cid[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
	u8 expected[8] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
	u8 different[8] = {0xFF, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
	bool result;

	/* Matching CID */
	result = tquic_ct_validate_cid(cid, 8, expected, 8);
	KUNIT_EXPECT_TRUE(test, result);

	/* Different CID */
	result = tquic_ct_validate_cid(cid, 8, different, 8);
	KUNIT_EXPECT_FALSE(test, result);

	/* Different length */
	result = tquic_ct_validate_cid(cid, 8, expected, 7);
	KUNIT_EXPECT_FALSE(test, result);
}

static void test_ct_decode_pn(struct kunit *test)
{
	u8 pn_1byte[1] = {0x42};
	u8 pn_2byte[2] = {0x12, 0x34};
	u8 pn_4byte[4] = {0x00, 0x01, 0x02, 0x03};
	u64 result;
	struct tquic_ct_ops ops = {0};

	/* 1-byte packet number */
	result = tquic_ct_decode_pn(pn_1byte, 1, 0x40, &ops);
	KUNIT_EXPECT_EQ(test, result, 0x42ULL);

	/* 2-byte packet number */
	result = tquic_ct_decode_pn(pn_2byte, 2, 0x1200, &ops);
	KUNIT_EXPECT_EQ(test, result, 0x1234ULL);

	/* 4-byte packet number */
	result = tquic_ct_decode_pn(pn_4byte, 4, 0, &ops);
	KUNIT_EXPECT_EQ(test, result, 0x00010203ULL);
}

/*
 * =============================================================================
 * Traffic Analysis Protection Tests
 * =============================================================================
 */

static void test_traffic_shaper_init(struct kunit *test)
{
	struct exfil_test_context *ctx = test->priv;
	int ret;

	ret = tquic_traffic_shaper_init(&ctx->shaper, TQUIC_EXFIL_LEVEL_MEDIUM);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, ctx->shaper.strategy, TQUIC_PAD_RANDOM);
	KUNIT_EXPECT_EQ(test, ctx->shaper.pad_probability, 25);

	tquic_traffic_shaper_destroy(&ctx->shaper);
}

static void test_traffic_shaper_padding_none(struct kunit *test)
{
	struct exfil_test_context *ctx = test->priv;
	u16 padding;
	int ret;

	ret = tquic_traffic_shaper_init(&ctx->shaper, TQUIC_EXFIL_LEVEL_NONE);
	KUNIT_ASSERT_EQ(test, ret, 0);

	padding = tquic_traffic_shaper_calc_padding(&ctx->shaper, 500);
	KUNIT_EXPECT_EQ(test, padding, 0);

	tquic_traffic_shaper_destroy(&ctx->shaper);
}

static void test_traffic_shaper_padding_max(struct kunit *test)
{
	struct exfil_test_context *ctx = test->priv;
	u16 padding;
	int ret;
	int padded_count = 0;
	int i;

	ret = tquic_traffic_shaper_init(&ctx->shaper, TQUIC_EXFIL_LEVEL_PARANOID);
	KUNIT_ASSERT_EQ(test, ret, 0);

	ctx->shaper.mtu = 1200;

	/* With PAD_MAX and 100% probability, all packets should be padded */
	for (i = 0; i < 100; i++) {
		padding = tquic_traffic_shaper_calc_padding(&ctx->shaper, 500);
		if (padding > 0)
			padded_count++;
	}

	/* Should be 100% padded */
	KUNIT_EXPECT_EQ(test, padded_count, 100);

	tquic_traffic_shaper_destroy(&ctx->shaper);
}

static void test_traffic_shaper_padding_block(struct kunit *test)
{
	struct exfil_test_context *ctx = test->priv;
	int ret;

	ret = tquic_traffic_shaper_init(&ctx->shaper, TQUIC_EXFIL_LEVEL_HIGH);
	KUNIT_ASSERT_EQ(test, ret, 0);

	KUNIT_EXPECT_EQ(test, ctx->shaper.strategy, TQUIC_PAD_BLOCK);

	tquic_traffic_shaper_destroy(&ctx->shaper);
}

static void test_traffic_shaper_set_mtu(struct kunit *test)
{
	struct exfil_test_context *ctx = test->priv;
	int ret;

	ret = tquic_traffic_shaper_init(&ctx->shaper, TQUIC_EXFIL_LEVEL_MEDIUM);
	KUNIT_ASSERT_EQ(test, ret, 0);

	tquic_traffic_shaper_set_mtu(&ctx->shaper, 1400);
	KUNIT_EXPECT_EQ(test, ctx->shaper.mtu, 1400);

	tquic_traffic_shaper_destroy(&ctx->shaper);
}

/*
 * =============================================================================
 * Spin Bit Randomization Tests
 * =============================================================================
 */

static void test_spin_randomizer_init_off(struct kunit *test)
{
	struct exfil_test_context *ctx = test->priv;
	int ret;

	ret = tquic_spin_randomizer_init(&ctx->spin_rand, TQUIC_EXFIL_LEVEL_NONE);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, ctx->spin_rand.mode, TQUIC_SPIN_RANDOM_OFF);

	tquic_spin_randomizer_destroy(&ctx->spin_rand);
}

static void test_spin_randomizer_get_off(struct kunit *test)
{
	struct exfil_test_context *ctx = test->priv;
	u8 result;
	int ret;
	int i;

	ret = tquic_spin_randomizer_init(&ctx->spin_rand, TQUIC_EXFIL_LEVEL_NONE);
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* With OFF mode, should always return calculated value */
	for (i = 0; i < 100; i++) {
		result = tquic_spin_randomizer_get(&ctx->spin_rand, 1);
		KUNIT_EXPECT_EQ(test, result, 1);

		result = tquic_spin_randomizer_get(&ctx->spin_rand, 0);
		KUNIT_EXPECT_EQ(test, result, 0);
	}

	tquic_spin_randomizer_destroy(&ctx->spin_rand);
}

static void test_spin_randomizer_get_prob(struct kunit *test)
{
	struct exfil_test_context *ctx = test->priv;
	int ret;
	int randomized = 0;
	int i;
	u8 result;

	ret = tquic_spin_randomizer_init(&ctx->spin_rand, TQUIC_EXFIL_LEVEL_MEDIUM);
	KUNIT_ASSERT_EQ(test, ret, 0);

	KUNIT_EXPECT_EQ(test, ctx->spin_rand.mode, TQUIC_SPIN_RANDOM_PROB);

	/* Count randomized values */
	for (i = 0; i < 1000; i++) {
		result = tquic_spin_randomizer_get(&ctx->spin_rand, 1);
		if (result != 1)
			randomized++;
	}

	/* With 15% probability, expect roughly 10-20% randomized */
	KUNIT_EXPECT_GT(test, randomized, 50);
	KUNIT_EXPECT_LT(test, randomized, 300);

	kunit_info(test, "Spin bit randomized: %d/1000 (expect ~15%%)\n",
		   randomized);

	tquic_spin_randomizer_destroy(&ctx->spin_rand);
}

static void test_spin_randomizer_get_full(struct kunit *test)
{
	struct exfil_test_context *ctx = test->priv;
	int ret;
	int ones = 0;
	int zeros = 0;
	int i;
	u8 result;

	ret = tquic_spin_randomizer_init(&ctx->spin_rand, TQUIC_EXFIL_LEVEL_PARANOID);
	KUNIT_ASSERT_EQ(test, ret, 0);

	KUNIT_EXPECT_EQ(test, ctx->spin_rand.mode, TQUIC_SPIN_RANDOM_FULL);

	/* With FULL mode, should be roughly 50/50 */
	for (i = 0; i < 1000; i++) {
		result = tquic_spin_randomizer_get(&ctx->spin_rand, 1);
		if (result == 1)
			ones++;
		else
			zeros++;
	}

	/* Expect roughly 50/50 */
	KUNIT_EXPECT_GT(test, ones, 400);
	KUNIT_EXPECT_LT(test, ones, 600);
	KUNIT_EXPECT_GT(test, zeros, 400);
	KUNIT_EXPECT_LT(test, zeros, 600);

	kunit_info(test, "Spin bit full random: %d ones, %d zeros\n",
		   ones, zeros);

	tquic_spin_randomizer_destroy(&ctx->spin_rand);
}

static void test_spin_randomizer_freeze(struct kunit *test)
{
	struct exfil_test_context *ctx = test->priv;
	int ret;
	bool frozen;

	ret = tquic_spin_randomizer_init(&ctx->spin_rand, TQUIC_EXFIL_LEVEL_HIGH);
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Initially not frozen */
	frozen = tquic_spin_randomizer_is_frozen(&ctx->spin_rand);
	KUNIT_EXPECT_FALSE(test, frozen);

	/* Trigger freeze */
	tquic_spin_randomizer_freeze(&ctx->spin_rand, 1000);
	frozen = tquic_spin_randomizer_is_frozen(&ctx->spin_rand);
	KUNIT_EXPECT_TRUE(test, frozen);

	tquic_spin_randomizer_destroy(&ctx->spin_rand);
}

/*
 * =============================================================================
 * Packet Timing Jitter Tests
 * =============================================================================
 */

static void test_packet_jitter_init_none(struct kunit *test)
{
	struct exfil_test_context *ctx = test->priv;
	int ret;

	ret = tquic_packet_jitter_init(&ctx->jitter, TQUIC_EXFIL_LEVEL_NONE);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, ctx->jitter.mode, TQUIC_JITTER_NONE);

	tquic_packet_jitter_destroy(&ctx->jitter);
}

static void test_packet_jitter_init_medium(struct kunit *test)
{
	struct exfil_test_context *ctx = test->priv;
	int ret;

	ret = tquic_packet_jitter_init(&ctx->jitter, TQUIC_EXFIL_LEVEL_MEDIUM);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, ctx->jitter.mode, TQUIC_JITTER_UNIFORM);
	KUNIT_EXPECT_EQ(test, ctx->jitter.max_jitter_us, 500);

	tquic_packet_jitter_destroy(&ctx->jitter);
}

static void test_packet_jitter_calc_none(struct kunit *test)
{
	struct exfil_test_context *ctx = test->priv;
	u32 jitter;
	int ret;

	ret = tquic_packet_jitter_init(&ctx->jitter, TQUIC_EXFIL_LEVEL_NONE);
	KUNIT_ASSERT_EQ(test, ret, 0);

	jitter = tquic_packet_jitter_calc(&ctx->jitter);
	KUNIT_EXPECT_EQ(test, jitter, 0);

	tquic_packet_jitter_destroy(&ctx->jitter);
}

static void test_packet_jitter_calc_uniform(struct kunit *test)
{
	struct exfil_test_context *ctx = test->priv;
	u32 jitter;
	int ret;
	int i;
	u32 min_seen = UINT_MAX, max_seen = 0;

	ret = tquic_packet_jitter_init(&ctx->jitter, TQUIC_EXFIL_LEVEL_MEDIUM);
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Sample jitter values */
	for (i = 0; i < 100; i++) {
		jitter = tquic_packet_jitter_calc(&ctx->jitter);
		KUNIT_EXPECT_LE(test, jitter, ctx->jitter.max_jitter_us);
		KUNIT_EXPECT_GE(test, jitter, ctx->jitter.min_jitter_us);

		if (jitter < min_seen)
			min_seen = jitter;
		if (jitter > max_seen)
			max_seen = jitter;
	}

	kunit_info(test, "Jitter range: %u - %u us (configured max %u)\n",
		   min_seen, max_seen, ctx->jitter.max_jitter_us);

	tquic_packet_jitter_destroy(&ctx->jitter);
}

static void test_packet_jitter_set_range(struct kunit *test)
{
	struct exfil_test_context *ctx = test->priv;
	int ret;

	ret = tquic_packet_jitter_init(&ctx->jitter, TQUIC_EXFIL_LEVEL_LOW);
	KUNIT_ASSERT_EQ(test, ret, 0);

	tquic_packet_jitter_set_range(&ctx->jitter, 100, 200);
	KUNIT_EXPECT_EQ(test, ctx->jitter.min_jitter_us, 100);
	KUNIT_EXPECT_EQ(test, ctx->jitter.max_jitter_us, 200);

	tquic_packet_jitter_destroy(&ctx->jitter);
}

static void test_packet_jitter_set_mode(struct kunit *test)
{
	struct exfil_test_context *ctx = test->priv;
	int ret;

	ret = tquic_packet_jitter_init(&ctx->jitter, TQUIC_EXFIL_LEVEL_LOW);
	KUNIT_ASSERT_EQ(test, ret, 0);

	tquic_packet_jitter_set_mode(&ctx->jitter, TQUIC_JITTER_GAUSSIAN);
	KUNIT_EXPECT_EQ(test, ctx->jitter.mode, TQUIC_JITTER_GAUSSIAN);

	tquic_packet_jitter_destroy(&ctx->jitter);
}

/*
 * =============================================================================
 * Unified Context Tests
 * =============================================================================
 */

static void test_exfil_ctx_alloc_free(struct kunit *test)
{
	struct tquic_exfil_ctx *ctx;

	ctx = tquic_exfil_ctx_alloc(TQUIC_EXFIL_LEVEL_MEDIUM);
	KUNIT_ASSERT_NOT_NULL(test, ctx);
	KUNIT_EXPECT_TRUE(test, ctx->enabled);
	KUNIT_EXPECT_EQ(test, ctx->level, TQUIC_EXFIL_LEVEL_MEDIUM);

	tquic_exfil_ctx_free(ctx);
}

static void test_exfil_ctx_ref_count(struct kunit *test)
{
	struct tquic_exfil_ctx *ctx;

	ctx = tquic_exfil_ctx_alloc(TQUIC_EXFIL_LEVEL_LOW);
	KUNIT_ASSERT_NOT_NULL(test, ctx);

	/* Initial refcount should be 1 */
	KUNIT_EXPECT_EQ(test, refcount_read(&ctx->ref), 1);

	/* Increment refcount */
	tquic_exfil_ctx_get(ctx);
	KUNIT_EXPECT_EQ(test, refcount_read(&ctx->ref), 2);

	/* Decrement refcount (should not free) */
	tquic_exfil_ctx_put(ctx);
	KUNIT_EXPECT_EQ(test, refcount_read(&ctx->ref), 1);

	/* Final put should free (we can't check this directly) */
	tquic_exfil_ctx_put(ctx);
}

static void test_exfil_ctx_set_level(struct kunit *test)
{
	struct tquic_exfil_ctx *ctx;

	ctx = tquic_exfil_ctx_alloc(TQUIC_EXFIL_LEVEL_LOW);
	KUNIT_ASSERT_NOT_NULL(test, ctx);

	KUNIT_EXPECT_EQ(test, ctx->level, TQUIC_EXFIL_LEVEL_LOW);

	tquic_exfil_ctx_set_level(ctx, TQUIC_EXFIL_LEVEL_HIGH);
	KUNIT_EXPECT_EQ(test, ctx->level, TQUIC_EXFIL_LEVEL_HIGH);

	tquic_exfil_ctx_set_level(ctx, TQUIC_EXFIL_LEVEL_NONE);
	KUNIT_EXPECT_EQ(test, ctx->level, TQUIC_EXFIL_LEVEL_NONE);
	KUNIT_EXPECT_FALSE(test, ctx->enabled);

	tquic_exfil_ctx_free(ctx);
}

static void test_exfil_ctx_enable_disable(struct kunit *test)
{
	struct tquic_exfil_ctx *ctx;

	ctx = tquic_exfil_ctx_alloc(TQUIC_EXFIL_LEVEL_MEDIUM);
	KUNIT_ASSERT_NOT_NULL(test, ctx);

	KUNIT_EXPECT_TRUE(test, ctx->enabled);

	tquic_exfil_ctx_disable(ctx);
	KUNIT_EXPECT_FALSE(test, ctx->enabled);

	tquic_exfil_ctx_enable(ctx);
	KUNIT_EXPECT_TRUE(test, ctx->enabled);

	tquic_exfil_ctx_free(ctx);
}

static void test_exfil_ctx_get_stats(struct kunit *test)
{
	struct tquic_exfil_ctx *ctx;
	u64 total_delays, total_delay_ns;
	u64 padded_packets, padding_bytes;
	u64 jittered_packets, jitter_ns;

	ctx = tquic_exfil_ctx_alloc(TQUIC_EXFIL_LEVEL_MEDIUM);
	KUNIT_ASSERT_NOT_NULL(test, ctx);

	/* Get initial stats (should be zero) */
	tquic_exfil_get_stats(ctx, &total_delays, &total_delay_ns,
			      &padded_packets, &padding_bytes,
			      &jittered_packets, &jitter_ns);

	KUNIT_EXPECT_EQ(test, total_delays, 0);
	KUNIT_EXPECT_EQ(test, padded_packets, 0);
	KUNIT_EXPECT_EQ(test, jittered_packets, 0);

	tquic_exfil_ctx_free(ctx);
}

/*
 * =============================================================================
 * Protection Level Configuration Tests
 * =============================================================================
 */

static void test_protection_level_none(struct kunit *test)
{
	struct tquic_exfil_ctx *ctx;

	ctx = tquic_exfil_ctx_alloc(TQUIC_EXFIL_LEVEL_NONE);
	KUNIT_ASSERT_NOT_NULL(test, ctx);

	KUNIT_EXPECT_FALSE(test, ctx->enabled);
	KUNIT_EXPECT_FALSE(test, ctx->timing.enabled);
	KUNIT_EXPECT_FALSE(test, ctx->ct_ops.enabled);
	KUNIT_EXPECT_EQ(test, ctx->shaper.strategy, TQUIC_PAD_NONE);
	KUNIT_EXPECT_EQ(test, ctx->spin_rand.mode, TQUIC_SPIN_RANDOM_OFF);
	KUNIT_EXPECT_EQ(test, ctx->jitter.mode, TQUIC_JITTER_NONE);

	tquic_exfil_ctx_free(ctx);
}

static void test_protection_level_paranoid(struct kunit *test)
{
	struct tquic_exfil_ctx *ctx;

	ctx = tquic_exfil_ctx_alloc(TQUIC_EXFIL_LEVEL_PARANOID);
	KUNIT_ASSERT_NOT_NULL(test, ctx);

	KUNIT_EXPECT_TRUE(test, ctx->enabled);
	KUNIT_EXPECT_TRUE(test, ctx->timing.enabled);
	KUNIT_EXPECT_TRUE(test, ctx->ct_ops.enabled);
	KUNIT_EXPECT_EQ(test, ctx->shaper.strategy, TQUIC_PAD_MAX);
	KUNIT_EXPECT_EQ(test, ctx->shaper.pad_probability, 100);
	KUNIT_EXPECT_EQ(test, ctx->spin_rand.mode, TQUIC_SPIN_RANDOM_FULL);
	KUNIT_EXPECT_EQ(test, ctx->jitter.mode, TQUIC_JITTER_EXPONENTIAL);

	tquic_exfil_ctx_free(ctx);
}

/*
 * =============================================================================
 * Test Suite Registration
 * =============================================================================
 */

static struct kunit_case timing_normalizer_cases[] = {
	KUNIT_CASE(test_timing_normalizer_init_none),
	KUNIT_CASE(test_timing_normalizer_init_medium),
	KUNIT_CASE(test_timing_normalizer_init_paranoid),
	KUNIT_CASE(test_timing_normalizer_set_level),
	KUNIT_CASE(test_timing_normalizer_process),
	{}
};

static struct kunit_suite timing_normalizer_suite = {
	.name = "tquic_exfil_timing",
	.init = exfil_test_init,
	.exit = exfil_test_exit,
	.test_cases = timing_normalizer_cases,
};

static struct kunit_case ct_ops_cases[] = {
	KUNIT_CASE(test_ct_memcmp_equal),
	KUNIT_CASE(test_ct_memcmp_different),
	KUNIT_CASE(test_ct_memcmp_first_byte),
	KUNIT_CASE(test_ct_memcpy),
	KUNIT_CASE(test_ct_select),
	KUNIT_CASE(test_ct_validate_cid),
	KUNIT_CASE(test_ct_decode_pn),
	{}
};

static struct kunit_suite ct_ops_suite = {
	.name = "tquic_exfil_ct_ops",
	.init = exfil_test_init,
	.exit = exfil_test_exit,
	.test_cases = ct_ops_cases,
};

static struct kunit_case traffic_shaper_cases[] = {
	KUNIT_CASE(test_traffic_shaper_init),
	KUNIT_CASE(test_traffic_shaper_padding_none),
	KUNIT_CASE(test_traffic_shaper_padding_max),
	KUNIT_CASE(test_traffic_shaper_padding_block),
	KUNIT_CASE(test_traffic_shaper_set_mtu),
	{}
};

static struct kunit_suite traffic_shaper_suite = {
	.name = "tquic_exfil_traffic_shaper",
	.init = exfil_test_init,
	.exit = exfil_test_exit,
	.test_cases = traffic_shaper_cases,
};

static struct kunit_case spin_randomizer_cases[] = {
	KUNIT_CASE(test_spin_randomizer_init_off),
	KUNIT_CASE(test_spin_randomizer_get_off),
	KUNIT_CASE(test_spin_randomizer_get_prob),
	KUNIT_CASE(test_spin_randomizer_get_full),
	KUNIT_CASE(test_spin_randomizer_freeze),
	{}
};

static struct kunit_suite spin_randomizer_suite = {
	.name = "tquic_exfil_spin_randomizer",
	.init = exfil_test_init,
	.exit = exfil_test_exit,
	.test_cases = spin_randomizer_cases,
};

static struct kunit_case packet_jitter_cases[] = {
	KUNIT_CASE(test_packet_jitter_init_none),
	KUNIT_CASE(test_packet_jitter_init_medium),
	KUNIT_CASE(test_packet_jitter_calc_none),
	KUNIT_CASE(test_packet_jitter_calc_uniform),
	KUNIT_CASE(test_packet_jitter_set_range),
	KUNIT_CASE(test_packet_jitter_set_mode),
	{}
};

static struct kunit_suite packet_jitter_suite = {
	.name = "tquic_exfil_packet_jitter",
	.init = exfil_test_init,
	.exit = exfil_test_exit,
	.test_cases = packet_jitter_cases,
};

static struct kunit_case exfil_ctx_cases[] = {
	KUNIT_CASE(test_exfil_ctx_alloc_free),
	KUNIT_CASE(test_exfil_ctx_ref_count),
	KUNIT_CASE(test_exfil_ctx_set_level),
	KUNIT_CASE(test_exfil_ctx_enable_disable),
	KUNIT_CASE(test_exfil_ctx_get_stats),
	KUNIT_CASE(test_protection_level_none),
	KUNIT_CASE(test_protection_level_paranoid),
	{}
};

static struct kunit_suite exfil_ctx_suite = {
	.name = "tquic_exfil_ctx",
	.init = exfil_test_init,
	.exit = exfil_test_exit,
	.test_cases = exfil_ctx_cases,
};

kunit_test_suites(&timing_normalizer_suite,
		  &ct_ops_suite,
		  &traffic_shaper_suite,
		  &spin_randomizer_suite,
		  &packet_jitter_suite,
		  &exfil_ctx_suite);

MODULE_DESCRIPTION("TQUIC QUIC-Exfil Mitigation KUnit Tests");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Foundation");
