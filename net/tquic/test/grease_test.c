// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: GREASE (RFC 9287) Unit Tests
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * KUnit tests for GREASE (Generate Random Extensions And Sustain Extensibility)
 * functionality including transport parameter encoding, version generation,
 * and fixed bit GREASE.
 */

#include <kunit/test.h>
#include <linux/random.h>
#include "../grease.h"

/*
 * Test reserved transport parameter ID generation
 */
static void grease_test_tp_id_generation(struct kunit *test)
{
	u64 tp_id;
	int i;

	/* Generate multiple IDs and verify they follow 31*N + 27 pattern */
	for (i = 0; i < 100; i++) {
		tp_id = tquic_grease_generate_tp_id();

		/* Verify the ID follows the reserved pattern */
		KUNIT_EXPECT_TRUE(test, tquic_grease_is_reserved_tp_id(tp_id));

		/* Verify the formula: (tp_id - 27) % 31 == 0 */
		KUNIT_EXPECT_EQ(test, (tp_id - 27) % 31, 0ULL);
	}
}

/*
 * Test reserved transport parameter ID validation
 */
static void grease_test_tp_id_validation(struct kunit *test)
{
	/* Test some known reserved IDs */
	KUNIT_EXPECT_TRUE(test, tquic_grease_is_reserved_tp_id(27));      /* N=0 */
	KUNIT_EXPECT_TRUE(test, tquic_grease_is_reserved_tp_id(58));      /* N=1 */
	KUNIT_EXPECT_TRUE(test, tquic_grease_is_reserved_tp_id(89));      /* N=2 */
	KUNIT_EXPECT_TRUE(test, tquic_grease_is_reserved_tp_id(120));     /* N=3 */

	/* Test some non-reserved IDs */
	KUNIT_EXPECT_FALSE(test, tquic_grease_is_reserved_tp_id(0));
	KUNIT_EXPECT_FALSE(test, tquic_grease_is_reserved_tp_id(1));
	KUNIT_EXPECT_FALSE(test, tquic_grease_is_reserved_tp_id(26));
	KUNIT_EXPECT_FALSE(test, tquic_grease_is_reserved_tp_id(28));
	KUNIT_EXPECT_FALSE(test, tquic_grease_is_reserved_tp_id(0x0e));   /* active_cid_limit */
	KUNIT_EXPECT_FALSE(test, tquic_grease_is_reserved_tp_id(0x2ab2)); /* grease_quic_bit */
}

/*
 * Test GREASE version generation (0x?a?a?a?a pattern)
 */
static void grease_test_version_generation(struct kunit *test)
{
	u32 version;
	int i;

	/* Generate multiple versions and verify they follow the pattern */
	for (i = 0; i < 100; i++) {
		version = tquic_grease_generate_version();

		/* Verify the 0x?a?a?a?a pattern */
		KUNIT_EXPECT_TRUE(test, tquic_grease_is_reserved_version(version));

		/* Verify each 'a' nibble */
		KUNIT_EXPECT_EQ(test, (version >> 24) & 0x0f, 0x0aU);
		KUNIT_EXPECT_EQ(test, (version >> 16) & 0x0f, 0x0aU);
		KUNIT_EXPECT_EQ(test, (version >> 8) & 0x0f, 0x0aU);
		KUNIT_EXPECT_EQ(test, version & 0x0f, 0x0aU);
	}
}

/*
 * Test GREASE version validation
 */
static void grease_test_version_validation(struct kunit *test)
{
	/* Test valid GREASE versions */
	KUNIT_EXPECT_TRUE(test, tquic_grease_is_reserved_version(0x0a0a0a0a));
	KUNIT_EXPECT_TRUE(test, tquic_grease_is_reserved_version(0x1a2a3a4a));
	KUNIT_EXPECT_TRUE(test, tquic_grease_is_reserved_version(0xfafafafaU));

	/* Test invalid versions (not matching 0x?a?a?a?a) */
	KUNIT_EXPECT_FALSE(test, tquic_grease_is_reserved_version(0x00000001)); /* QUICv1 */
	KUNIT_EXPECT_FALSE(test, tquic_grease_is_reserved_version(0x6b3343cf)); /* QUICv2 */
	KUNIT_EXPECT_FALSE(test, tquic_grease_is_reserved_version(0x00000000)); /* VN */
	KUNIT_EXPECT_FALSE(test, tquic_grease_is_reserved_version(0x0b0a0a0a)); /* Wrong nibble */
	KUNIT_EXPECT_FALSE(test, tquic_grease_is_reserved_version(0x0a0b0a0a)); /* Wrong nibble */
}

/*
 * Test GREASE state initialization
 */
static void grease_test_state_init(struct kunit *test)
{
	struct tquic_grease_state state;
	int ret;

	memset(&state, 0xff, sizeof(state));  /* Fill with garbage */

	/* Initialize without a network namespace (will use default) */
	ret = tquic_grease_state_init(&state, NULL);

	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_TRUE(test, state.grease_enabled);  /* Default enabled */
	KUNIT_EXPECT_TRUE(test, state.local_grease_quic_bit);
	KUNIT_EXPECT_FALSE(test, state.peer_grease_quic_bit);  /* Not yet known */
	KUNIT_EXPECT_EQ(test, state.grease_tp_count, 0);
}

/*
 * Test GREASE bit decision when peer doesn't support
 */
static void grease_test_should_grease_bit_no_peer_support(struct kunit *test)
{
	struct tquic_grease_state state;
	bool should_grease;
	int i;

	memset(&state, 0, sizeof(state));
	state.grease_enabled = true;
	state.peer_grease_quic_bit = false;  /* Peer doesn't support */

	/* Should never GREASE if peer doesn't support */
	for (i = 0; i < 1000; i++) {
		should_grease = tquic_grease_should_grease_bit(&state);
		KUNIT_EXPECT_FALSE(test, should_grease);
	}
}

/*
 * Test GREASE bit decision when GREASE is disabled
 */
static void grease_test_should_grease_bit_disabled(struct kunit *test)
{
	struct tquic_grease_state state;
	bool should_grease;
	int i;

	memset(&state, 0, sizeof(state));
	state.grease_enabled = false;  /* GREASE disabled */
	state.peer_grease_quic_bit = true;  /* Peer supports */

	/* Should never GREASE if disabled */
	for (i = 0; i < 1000; i++) {
		should_grease = tquic_grease_should_grease_bit(&state);
		KUNIT_EXPECT_FALSE(test, should_grease);
	}
}

/*
 * Test GREASE bit decision with full support
 * Note: This test is probabilistic - with 1/16 probability, approximately
 * 6.25% of calls should return true.
 */
static void grease_test_should_grease_bit_with_support(struct kunit *test)
{
	struct tquic_grease_state state;
	int grease_count = 0;
	int total = 10000;
	int i;

	memset(&state, 0, sizeof(state));
	state.grease_enabled = true;
	state.peer_grease_quic_bit = true;  /* Full support */

	for (i = 0; i < total; i++) {
		if (tquic_grease_should_grease_bit(&state))
			grease_count++;
	}

	/*
	 * With 1/16 probability, we expect ~625 hits out of 10000.
	 * Allow some variance (300-900 range = ~3-9%)
	 */
	KUNIT_EXPECT_GT(test, grease_count, 300);
	KUNIT_EXPECT_LT(test, grease_count, 900);
}

/*
 * Test GREASE transport parameter count distribution
 */
static void grease_test_tp_count_distribution(struct kunit *test)
{
	int counts[4] = {0};
	int total = 10000;
	int i;
	u8 count;

	for (i = 0; i < total; i++) {
		count = tquic_grease_tp_count();
		KUNIT_EXPECT_LE(test, count, 3);
		counts[count]++;
	}

	/*
	 * Expected distribution:
	 *   0: ~50% (5000)
	 *   1: ~30% (3000)
	 *   2: ~15% (1500)
	 *   3: ~5% (500)
	 * Allow significant variance due to randomness
	 */
	KUNIT_EXPECT_GT(test, counts[0], 4000);  /* 0 should be most common */
	KUNIT_EXPECT_GT(test, counts[1], 2000);
	KUNIT_EXPECT_GT(test, counts[2], 1000);
	KUNIT_EXPECT_GT(test, counts[3], 200);
}

/*
 * Test GREASE transport parameter value length distribution
 */
static void grease_test_tp_value_len_distribution(struct kunit *test)
{
	int total = 10000;
	int i;
	u8 len;
	int zero_count = 0;
	int max_count = 0;

	for (i = 0; i < total; i++) {
		len = tquic_grease_tp_value_len();
		KUNIT_EXPECT_LE(test, len, TQUIC_GREASE_TP_MAX_LEN);

		if (len == 0)
			zero_count++;
		if (len == TQUIC_GREASE_TP_MAX_LEN)
			max_count++;
	}

	/*
	 * With uniform distribution over 0-16, each value should appear
	 * approximately 1/17 = ~5.9% of the time.
	 * Allow variance but ensure we see both 0 and max values.
	 */
	KUNIT_EXPECT_GT(test, zero_count, 100);
	KUNIT_EXPECT_GT(test, max_count, 100);
}

/*
 * Test null pointer handling
 */
static void grease_test_null_handling(struct kunit *test)
{
	/* Should handle NULL gracefully */
	KUNIT_EXPECT_FALSE(test, tquic_grease_should_grease_bit(NULL));

	/* These should not crash with NULL */
	tquic_grease_state_set_peer(NULL, true);
}

static struct kunit_case grease_test_cases[] = {
	KUNIT_CASE(grease_test_tp_id_generation),
	KUNIT_CASE(grease_test_tp_id_validation),
	KUNIT_CASE(grease_test_version_generation),
	KUNIT_CASE(grease_test_version_validation),
	KUNIT_CASE(grease_test_state_init),
	KUNIT_CASE(grease_test_should_grease_bit_no_peer_support),
	KUNIT_CASE(grease_test_should_grease_bit_disabled),
	KUNIT_CASE(grease_test_should_grease_bit_with_support),
	KUNIT_CASE(grease_test_tp_count_distribution),
	KUNIT_CASE(grease_test_tp_value_len_distribution),
	KUNIT_CASE(grease_test_null_handling),
	{}
};

static struct kunit_suite grease_test_suite = {
	.name = "tquic_grease",
	.test_cases = grease_test_cases,
};

kunit_test_suite(grease_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TQUIC GREASE (RFC 9287) Unit Tests");
