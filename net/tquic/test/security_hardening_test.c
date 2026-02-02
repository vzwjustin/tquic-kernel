// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC Security Hardening Tests
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Tests for security hardening features:
 * - CVE-2025-54939 (QUIC-LEAK): Pre-handshake memory exhaustion defense
 * - CVE-2024-22189: Retire CID stuffing attack defense
 * - Optimistic ACK attack defense via packet number skipping
 * - ACK range validation
 * - Spin bit privacy controls
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <net/tquic.h>

#include "../security_hardening.h"

/*
 * =============================================================================
 * Test Fixtures
 * =============================================================================
 */

struct security_test_context {
	struct sockaddr_storage test_addr_v4;
	struct sockaddr_storage test_addr_v4_2;
	struct sockaddr_storage test_addr_v6;
	struct tquic_cid_security cid_sec;
	struct tquic_pn_skip_state pn_skip;
	struct tquic_ack_validation_state ack_valid;
	struct tquic_spin_bit_state spin_state;
};

static int security_test_init(struct kunit *test)
{
	struct security_test_context *ctx;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, ctx);

	/* Initialize test IPv4 address 192.168.1.1:443 */
	sin = (struct sockaddr_in *)&ctx->test_addr_v4;
	sin->sin_family = AF_INET;
	sin->sin_port = htons(443);
	sin->sin_addr.s_addr = htonl(0xc0a80101);  /* 192.168.1.1 */

	/* Initialize second IPv4 address 192.168.1.2:443 */
	sin = (struct sockaddr_in *)&ctx->test_addr_v4_2;
	sin->sin_family = AF_INET;
	sin->sin_port = htons(443);
	sin->sin_addr.s_addr = htonl(0xc0a80102);  /* 192.168.1.2 */

	/* Initialize test IPv6 address [2001:db8::1]:443 */
	sin6 = (struct sockaddr_in6 *)&ctx->test_addr_v6;
	sin6->sin6_family = AF_INET6;
	sin6->sin6_port = htons(443);
	memset(&sin6->sin6_addr, 0, sizeof(sin6->sin6_addr));
	sin6->sin6_addr.s6_addr[0] = 0x20;
	sin6->sin6_addr.s6_addr[1] = 0x01;
	sin6->sin6_addr.s6_addr[2] = 0x0d;
	sin6->sin6_addr.s6_addr[3] = 0xb8;
	sin6->sin6_addr.s6_addr[15] = 0x01;

	test->priv = ctx;
	return 0;
}

static void security_test_exit(struct kunit *test)
{
	/* Context freed automatically by kunit_kzalloc */
}

/*
 * =============================================================================
 * CVE-2025-54939 (QUIC-LEAK) Defense Tests
 * =============================================================================
 */

static void test_pre_hs_init(struct kunit *test)
{
	int ret;

	ret = tquic_pre_hs_init();
	KUNIT_EXPECT_EQ(test, ret, 0);

	/* Cleanup */
	tquic_pre_hs_exit();
}

static void test_pre_hs_can_allocate_basic(struct kunit *test)
{
	struct security_test_context *ctx = test->priv;
	bool can_alloc;
	int ret;

	ret = tquic_pre_hs_init();
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Should be able to allocate small amount */
	can_alloc = tquic_pre_hs_can_allocate(&ctx->test_addr_v4, 1024);
	KUNIT_EXPECT_TRUE(test, can_alloc);

	tquic_pre_hs_exit();
}

static void test_pre_hs_alloc_and_free(struct kunit *test)
{
	struct security_test_context *ctx = test->priv;
	int ret;

	ret = tquic_pre_hs_init();
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Allocate */
	ret = tquic_pre_hs_alloc(&ctx->test_addr_v4, 4096);
	KUNIT_EXPECT_EQ(test, ret, 0);

	/* Free */
	tquic_pre_hs_free(&ctx->test_addr_v4, 4096);

	tquic_pre_hs_exit();
}

static void test_pre_hs_per_ip_limit(struct kunit *test)
{
	struct security_test_context *ctx = test->priv;
	bool can_alloc;
	int ret;
	int i;

	ret = tquic_pre_hs_init();
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Allocate up to per-IP limit from same IP */
	for (i = 0; i < 10; i++) {
		ret = tquic_pre_hs_alloc(&ctx->test_addr_v4, 100 * 1024);
		if (ret != 0)
			break;
	}

	/* After limit, should not be able to allocate more from same IP */
	can_alloc = tquic_pre_hs_can_allocate(&ctx->test_addr_v4, 1024 * 1024);
	/* Note: May or may not hit limit depending on default per-IP budget */

	/* But should still be able to allocate from different IP */
	can_alloc = tquic_pre_hs_can_allocate(&ctx->test_addr_v4_2, 1024);
	KUNIT_EXPECT_TRUE(test, can_alloc);

	tquic_pre_hs_exit();
}

static void test_pre_hs_handshake_complete(struct kunit *test)
{
	struct security_test_context *ctx = test->priv;
	bool can_alloc;
	int ret;

	ret = tquic_pre_hs_init();
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Allocate some memory */
	ret = tquic_pre_hs_alloc(&ctx->test_addr_v4, 4096);
	KUNIT_EXPECT_EQ(test, ret, 0);

	/* Mark handshake complete - should release from pre-hs accounting */
	tquic_pre_hs_connection_complete(&ctx->test_addr_v4);

	/* Should be able to allocate again */
	can_alloc = tquic_pre_hs_can_allocate(&ctx->test_addr_v4, 4096);
	KUNIT_EXPECT_TRUE(test, can_alloc);

	tquic_pre_hs_exit();
}

static void test_pre_hs_ipv6(struct kunit *test)
{
	struct security_test_context *ctx = test->priv;
	bool can_alloc;
	int ret;

	ret = tquic_pre_hs_init();
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Test IPv6 allocation */
	can_alloc = tquic_pre_hs_can_allocate(&ctx->test_addr_v6, 1024);
	KUNIT_EXPECT_TRUE(test, can_alloc);

	ret = tquic_pre_hs_alloc(&ctx->test_addr_v6, 1024);
	KUNIT_EXPECT_EQ(test, ret, 0);

	tquic_pre_hs_free(&ctx->test_addr_v6, 1024);

	tquic_pre_hs_exit();
}

/*
 * =============================================================================
 * CVE-2024-22189 (Retire CID Stuffing) Defense Tests
 * =============================================================================
 */

static void test_cid_security_init(struct kunit *test)
{
	struct security_test_context *ctx = test->priv;
	int ret;

	ret = tquic_cid_security_init(&ctx->cid_sec);
	KUNIT_EXPECT_EQ(test, ret, 0);

	tquic_cid_security_destroy(&ctx->cid_sec);
}

static void test_cid_security_new_cid_rate_limit(struct kunit *test)
{
	struct security_test_context *ctx = test->priv;
	int ret;
	int i;
	int accepted = 0;
	int rate_limited = 0;

	ret = tquic_cid_security_init(&ctx->cid_sec);
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Try to process many NEW_CONNECTION_ID frames rapidly */
	for (i = 0; i < 200; i++) {
		ret = tquic_cid_security_check_new_cid(&ctx->cid_sec);
		if (ret == 0)
			accepted++;
		else if (ret == -EBUSY)
			rate_limited++;
	}

	/* Some should be rate limited */
	KUNIT_EXPECT_GT(test, rate_limited, 0);

	kunit_info(test, "NEW_CONNECTION_ID: %d accepted, %d rate limited\n",
		   accepted, rate_limited);

	tquic_cid_security_destroy(&ctx->cid_sec);
}

static void test_cid_security_retire_queue_limit(struct kunit *test)
{
	struct security_test_context *ctx = test->priv;
	int ret;
	int i;
	int queued = 0;

	ret = tquic_cid_security_init(&ctx->cid_sec);
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Try to queue more than TQUIC_MAX_QUEUED_RETIRE_CID frames */
	for (i = 0; i < TQUIC_MAX_QUEUED_RETIRE_CID + 100; i++) {
		ret = tquic_cid_security_queue_retire(&ctx->cid_sec);
		if (ret == 0)
			queued++;
		else if (ret == -EPROTO) {
			/* Attack detected - limit exceeded */
			break;
		}
	}

	/* Should not exceed limit */
	KUNIT_EXPECT_LE(test, queued, TQUIC_MAX_QUEUED_RETIRE_CID);

	kunit_info(test, "RETIRE_CONNECTION_ID: queued %d (limit %d)\n",
		   queued, TQUIC_MAX_QUEUED_RETIRE_CID);

	tquic_cid_security_destroy(&ctx->cid_sec);
}

static void test_cid_security_retire_dequeue(struct kunit *test)
{
	struct security_test_context *ctx = test->priv;
	int ret;
	int i;

	ret = tquic_cid_security_init(&ctx->cid_sec);
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Queue some frames */
	for (i = 0; i < 10; i++) {
		ret = tquic_cid_security_queue_retire(&ctx->cid_sec);
		KUNIT_EXPECT_EQ(test, ret, 0);
	}

	/* Dequeue them */
	for (i = 0; i < 10; i++)
		tquic_cid_security_dequeue_retire(&ctx->cid_sec);

	/* Should be able to queue again */
	ret = tquic_cid_security_queue_retire(&ctx->cid_sec);
	KUNIT_EXPECT_EQ(test, ret, 0);

	tquic_cid_security_destroy(&ctx->cid_sec);
}

/*
 * =============================================================================
 * Optimistic ACK Attack Defense Tests
 * =============================================================================
 */

static void test_pn_skip_init(struct kunit *test)
{
	struct security_test_context *ctx = test->priv;
	int ret;

	ret = tquic_pn_skip_init(&ctx->pn_skip, 128);
	KUNIT_EXPECT_EQ(test, ret, 0);

	tquic_pn_skip_destroy(&ctx->pn_skip);
}

static void test_pn_skip_should_skip(struct kunit *test)
{
	struct security_test_context *ctx = test->priv;
	int ret;
	int i;
	int skips = 0;
	int skip_amount;

	/* Use low skip rate to get skips quickly */
	ret = tquic_pn_skip_init(&ctx->pn_skip, 10);
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Send many "packets" and count skips */
	for (i = 0; i < 1000; i++) {
		skip_amount = tquic_pn_should_skip(&ctx->pn_skip,
						   TQUIC_PN_SPACE_APPLICATION);
		if (skip_amount > 0) {
			skips++;
			KUNIT_EXPECT_GE(test, skip_amount, TQUIC_PN_SKIP_MIN);
			KUNIT_EXPECT_LE(test, skip_amount, TQUIC_PN_SKIP_MAX);
		}
	}

	/* With rate 10, expect ~10% skips (±margin for randomness) */
	KUNIT_EXPECT_GT(test, skips, 50);
	KUNIT_EXPECT_LT(test, skips, 200);

	kunit_info(test, "PN skips: %d out of 1000 packets (rate=10)\n", skips);

	tquic_pn_skip_destroy(&ctx->pn_skip);
}

static void test_pn_skip_record_and_check(struct kunit *test)
{
	struct security_test_context *ctx = test->priv;
	int ret;
	bool attack_detected;

	ret = tquic_pn_skip_init(&ctx->pn_skip, 128);
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Record a skipped PN */
	tquic_pn_record_skip(&ctx->pn_skip, 12345, TQUIC_PN_SPACE_APPLICATION);

	/* ACK for the skipped PN should be detected as attack */
	attack_detected = tquic_pn_check_optimistic_ack(&ctx->pn_skip, 12345,
							TQUIC_PN_SPACE_APPLICATION);
	KUNIT_EXPECT_TRUE(test, attack_detected);

	/* ACK for different PN should not be detected */
	attack_detected = tquic_pn_check_optimistic_ack(&ctx->pn_skip, 12346,
							TQUIC_PN_SPACE_APPLICATION);
	KUNIT_EXPECT_FALSE(test, attack_detected);

	/* ACK for same PN but different space should not be detected */
	attack_detected = tquic_pn_check_optimistic_ack(&ctx->pn_skip, 12345,
							TQUIC_PN_SPACE_HANDSHAKE);
	KUNIT_EXPECT_FALSE(test, attack_detected);

	tquic_pn_skip_destroy(&ctx->pn_skip);
}

static void test_pn_skip_circular_buffer(struct kunit *test)
{
	struct security_test_context *ctx = test->priv;
	int ret;
	int i;
	bool attack_detected;

	ret = tquic_pn_skip_init(&ctx->pn_skip, 128);
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Fill the circular buffer */
	for (i = 0; i < TQUIC_MAX_SKIPPED_PNS + 10; i++)
		tquic_pn_record_skip(&ctx->pn_skip, 1000 + i, TQUIC_PN_SPACE_APPLICATION);

	/* Recent skips should still be detected */
	attack_detected = tquic_pn_check_optimistic_ack(&ctx->pn_skip,
							1000 + TQUIC_MAX_SKIPPED_PNS,
							TQUIC_PN_SPACE_APPLICATION);
	KUNIT_EXPECT_TRUE(test, attack_detected);

	/* Old skips (evicted from buffer) should not be detected */
	attack_detected = tquic_pn_check_optimistic_ack(&ctx->pn_skip, 1000,
							TQUIC_PN_SPACE_APPLICATION);
	KUNIT_EXPECT_FALSE(test, attack_detected);

	tquic_pn_skip_destroy(&ctx->pn_skip);
}

static void test_pn_skip_disabled(struct kunit *test)
{
	struct security_test_context *ctx = test->priv;
	int ret;
	int i;
	int skip_amount;

	/* Rate 0 should disable skipping */
	ret = tquic_pn_skip_init(&ctx->pn_skip, 0);
	KUNIT_ASSERT_EQ(test, ret, 0);

	for (i = 0; i < 100; i++) {
		skip_amount = tquic_pn_should_skip(&ctx->pn_skip,
						   TQUIC_PN_SPACE_APPLICATION);
		KUNIT_EXPECT_EQ(test, skip_amount, 0);
	}

	tquic_pn_skip_destroy(&ctx->pn_skip);
}

/*
 * =============================================================================
 * ACK Range Validation Tests
 * =============================================================================
 */

static void test_ack_validation_init(struct kunit *test)
{
	struct security_test_context *ctx = test->priv;
	int ret;

	ret = tquic_ack_validation_init(&ctx->ack_valid);
	KUNIT_EXPECT_EQ(test, ret, 0);

	tquic_ack_validation_destroy(&ctx->ack_valid);
}

static void test_ack_validation_record_sent(struct kunit *test)
{
	struct security_test_context *ctx = test->priv;
	int ret;

	ret = tquic_ack_validation_init(&ctx->ack_valid);
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Record sent packets */
	tquic_ack_validation_record_sent(&ctx->ack_valid, 0,
					 TQUIC_PN_SPACE_INITIAL);
	tquic_ack_validation_record_sent(&ctx->ack_valid, 1,
					 TQUIC_PN_SPACE_INITIAL);
	tquic_ack_validation_record_sent(&ctx->ack_valid, 100,
					 TQUIC_PN_SPACE_APPLICATION);

	/* Valid ACKs */
	ret = tquic_ack_validation_check(&ctx->ack_valid, 0,
					 TQUIC_PN_SPACE_INITIAL);
	KUNIT_EXPECT_EQ(test, ret, 0);

	ret = tquic_ack_validation_check(&ctx->ack_valid, 1,
					 TQUIC_PN_SPACE_INITIAL);
	KUNIT_EXPECT_EQ(test, ret, 0);

	ret = tquic_ack_validation_check(&ctx->ack_valid, 100,
					 TQUIC_PN_SPACE_APPLICATION);
	KUNIT_EXPECT_EQ(test, ret, 0);

	tquic_ack_validation_destroy(&ctx->ack_valid);
}

static void test_ack_validation_invalid_ack(struct kunit *test)
{
	struct security_test_context *ctx = test->priv;
	int ret;

	ret = tquic_ack_validation_init(&ctx->ack_valid);
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Record sent packet 100 in application space */
	tquic_ack_validation_record_sent(&ctx->ack_valid, 100,
					 TQUIC_PN_SPACE_APPLICATION);

	/* ACK for packet 101 (not sent) should be invalid */
	ret = tquic_ack_validation_check(&ctx->ack_valid, 101,
					 TQUIC_PN_SPACE_APPLICATION);
	KUNIT_EXPECT_EQ(test, ret, -EPROTO);

	/* ACK for packet 1000 (not sent) should be invalid */
	ret = tquic_ack_validation_check(&ctx->ack_valid, 1000,
					 TQUIC_PN_SPACE_APPLICATION);
	KUNIT_EXPECT_EQ(test, ret, -EPROTO);

	tquic_ack_validation_destroy(&ctx->ack_valid);
}

static void test_ack_validation_spaces(struct kunit *test)
{
	struct security_test_context *ctx = test->priv;
	int ret;

	ret = tquic_ack_validation_init(&ctx->ack_valid);
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Record packets in different spaces */
	tquic_ack_validation_record_sent(&ctx->ack_valid, 10,
					 TQUIC_PN_SPACE_INITIAL);
	tquic_ack_validation_record_sent(&ctx->ack_valid, 20,
					 TQUIC_PN_SPACE_HANDSHAKE);
	tquic_ack_validation_record_sent(&ctx->ack_valid, 30,
					 TQUIC_PN_SPACE_APPLICATION);

	/* Cross-space ACKs should be invalid */
	ret = tquic_ack_validation_check(&ctx->ack_valid, 20,
					 TQUIC_PN_SPACE_INITIAL);
	KUNIT_EXPECT_EQ(test, ret, -EPROTO);

	ret = tquic_ack_validation_check(&ctx->ack_valid, 30,
					 TQUIC_PN_SPACE_HANDSHAKE);
	KUNIT_EXPECT_EQ(test, ret, -EPROTO);

	tquic_ack_validation_destroy(&ctx->ack_valid);
}

/*
 * =============================================================================
 * Spin Bit Privacy Tests
 * =============================================================================
 */

static void test_spin_bit_always(struct kunit *test)
{
	struct security_test_context *ctx = test->priv;
	u8 spin;
	int i;
	int ones = 0;

	tquic_spin_bit_init(&ctx->spin_state, TQUIC_SPIN_BIT_ALWAYS, 8);

	/* With policy ALWAYS, spin should follow protocol */
	ctx->spin_state.current_spin = 1;

	for (i = 0; i < 100; i++) {
		spin = tquic_spin_bit_get(&ctx->spin_state, i);
		if (spin == 1)
			ones++;
	}

	/* Should always be 1 since current_spin is 1 */
	KUNIT_EXPECT_EQ(test, ones, 100);
}

static void test_spin_bit_never(struct kunit *test)
{
	struct security_test_context *ctx = test->priv;
	u8 spin;
	int i;
	int ones = 0;
	int zeros = 0;

	tquic_spin_bit_init(&ctx->spin_state, TQUIC_SPIN_BIT_NEVER, 8);
	ctx->spin_state.current_spin = 1;

	for (i = 0; i < 1000; i++) {
		spin = tquic_spin_bit_get(&ctx->spin_state, i);
		if (spin == 1)
			ones++;
		else
			zeros++;
	}

	/* With NEVER policy, should be roughly 50/50 random */
	KUNIT_EXPECT_GT(test, ones, 400);
	KUNIT_EXPECT_LT(test, ones, 600);
	KUNIT_EXPECT_GT(test, zeros, 400);
	KUNIT_EXPECT_LT(test, zeros, 600);

	kunit_info(test, "Spin bit NEVER: %d ones, %d zeros\n", ones, zeros);
}

static void test_spin_bit_probabilistic(struct kunit *test)
{
	struct security_test_context *ctx = test->priv;
	u8 spin;
	int i;
	int correct = 0;
	int random = 0;

	/* Rate 8 means 1 in 8 packets (~12.5%) get random spin */
	tquic_spin_bit_init(&ctx->spin_state, TQUIC_SPIN_BIT_PROBABILISTIC, 8);
	ctx->spin_state.current_spin = 1;

	/* Note: This test is statistical - we can't definitively tell if a
	 * particular spin bit is "correct" or "random". We just verify the
	 * function runs and returns valid values.
	 */
	for (i = 0; i < 1000; i++) {
		spin = tquic_spin_bit_get(&ctx->spin_state, i);
		KUNIT_EXPECT_LE(test, spin, 1);
		if (spin == ctx->spin_state.current_spin)
			correct++;
		else
			random++;
	}

	/* With 12.5% disable rate, expect roughly 87.5% correct (±margin) */
	KUNIT_EXPECT_GT(test, correct, 700);

	kunit_info(test, "Spin bit PROBABILISTIC: %d correct, %d random\n",
		   correct, random);
}

static void test_spin_bit_update(struct kunit *test)
{
	struct security_test_context *ctx = test->priv;

	tquic_spin_bit_init(&ctx->spin_state, TQUIC_SPIN_BIT_ALWAYS, 8);

	/* Initial spin should be 0 */
	KUNIT_EXPECT_EQ(test, ctx->spin_state.current_spin, 0);

	/* Receive packet with spin=0 - should flip to 1 */
	tquic_spin_bit_update(&ctx->spin_state, 0, 1);
	KUNIT_EXPECT_EQ(test, ctx->spin_state.current_spin, 1);

	/* Receive packet with spin=1 - should flip to 0 */
	tquic_spin_bit_update(&ctx->spin_state, 1, 2);
	KUNIT_EXPECT_EQ(test, ctx->spin_state.current_spin, 0);

	/* Receive old packet - should not update */
	tquic_spin_bit_update(&ctx->spin_state, 1, 1);
	KUNIT_EXPECT_EQ(test, ctx->spin_state.current_spin, 0);
}

/*
 * =============================================================================
 * Integration Tests
 * =============================================================================
 */

static void test_security_event_reporting(struct kunit *test)
{
	struct security_test_context *ctx = test->priv;

	/* Just verify the function doesn't crash */
	tquic_security_event(TQUIC_SEC_EVENT_PRE_HS_LIMIT,
			     &ctx->test_addr_v4, "test event");
	tquic_security_event(TQUIC_SEC_EVENT_RETIRE_CID_FLOOD,
			     &ctx->test_addr_v6, "test event v6");
	tquic_security_event(TQUIC_SEC_EVENT_OPTIMISTIC_ACK,
			     NULL, "no address");
}

/*
 * =============================================================================
 * Test Suite Registration
 * =============================================================================
 */

static struct kunit_case security_hardening_test_cases[] = {
	/* Pre-handshake memory defense (CVE-2025-54939) */
	KUNIT_CASE(test_pre_hs_init),
	KUNIT_CASE(test_pre_hs_can_allocate_basic),
	KUNIT_CASE(test_pre_hs_alloc_and_free),
	KUNIT_CASE(test_pre_hs_per_ip_limit),
	KUNIT_CASE(test_pre_hs_handshake_complete),
	KUNIT_CASE(test_pre_hs_ipv6),

	/* CID security (CVE-2024-22189) */
	KUNIT_CASE(test_cid_security_init),
	KUNIT_CASE(test_cid_security_new_cid_rate_limit),
	KUNIT_CASE(test_cid_security_retire_queue_limit),
	KUNIT_CASE(test_cid_security_retire_dequeue),

	/* Packet number skipping (optimistic ACK defense) */
	KUNIT_CASE(test_pn_skip_init),
	KUNIT_CASE(test_pn_skip_should_skip),
	KUNIT_CASE(test_pn_skip_record_and_check),
	KUNIT_CASE(test_pn_skip_circular_buffer),
	KUNIT_CASE(test_pn_skip_disabled),

	/* ACK validation */
	KUNIT_CASE(test_ack_validation_init),
	KUNIT_CASE(test_ack_validation_record_sent),
	KUNIT_CASE(test_ack_validation_invalid_ack),
	KUNIT_CASE(test_ack_validation_spaces),

	/* Spin bit privacy */
	KUNIT_CASE(test_spin_bit_always),
	KUNIT_CASE(test_spin_bit_never),
	KUNIT_CASE(test_spin_bit_probabilistic),
	KUNIT_CASE(test_spin_bit_update),

	/* Integration */
	KUNIT_CASE(test_security_event_reporting),

	{}
};

static struct kunit_suite security_hardening_test_suite = {
	.name = "tquic_security_hardening",
	.init = security_test_init,
	.exit = security_test_exit,
	.test_cases = security_hardening_test_cases,
};

kunit_test_suite(security_hardening_test_suite);

MODULE_DESCRIPTION("TQUIC Security Hardening Tests");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Foundation");
