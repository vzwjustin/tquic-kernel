// SPDX-License-Identifier: GPL-2.0
/*
 * KUnit tests for TQUIC failover packet transfer semantics.
 */

#include <kunit/test.h>
#include <linux/skbuff.h>
#include <linux/workqueue.h>

#include "../bond/tquic_failover.h"

struct failover_test_ctx {
	struct tquic_failover_ctx *fc;
	struct workqueue_struct *wq;
};

static struct failover_test_ctx *failover_test_ctx_create(struct kunit *test)
{
	struct failover_test_ctx *ctx;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);

	ctx->wq = alloc_workqueue("tquic_failover_test_wq", WQ_UNBOUND, 0);
	KUNIT_ASSERT_NOT_NULL(test, ctx->wq);

	ctx->fc = tquic_failover_init(NULL, ctx->wq, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx->fc);

	return ctx;
}

static void failover_test_ctx_destroy(struct failover_test_ctx *ctx)
{
	if (!ctx)
		return;

	if (ctx->fc)
		tquic_failover_destroy(ctx->fc);
	if (ctx->wq)
		destroy_workqueue(ctx->wq);
}

static struct sk_buff *failover_test_alloc_skb(struct kunit *test, u32 len)
{
	struct sk_buff *skb;
	u8 *data;

	skb = alloc_skb(len, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, skb);

	data = skb_put(skb, len);
	memset(data, 0x5a, len);

	return skb;
}

static void tquic_failover_test_late_ack_removes_requeued_packet(struct kunit *test)
{
	struct failover_test_ctx *ctx;
	struct sk_buff *skb;
	int ret;

	ctx = failover_test_ctx_create(test);
	skb = failover_test_alloc_skb(test, 128);

	ret = tquic_failover_track_sent(ctx->fc, skb, 100, 1);
	KUNIT_ASSERT_EQ(test, ret, 0);

	ret = tquic_failover_on_path_failed(ctx->fc, 1);
	KUNIT_ASSERT_EQ(test, ret, 1);
	KUNIT_EXPECT_EQ(test, tquic_failover_retx_count(ctx->fc), (u32)1);

	/* Late ACK after failover transfer should purge from retx queue. */
	ret = tquic_failover_on_ack(ctx->fc, 100);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, tquic_failover_retx_count(ctx->fc), (u32)0);
	KUNIT_EXPECT_PTR_EQ(test, tquic_failover_get_next(ctx->fc), NULL);

	kfree_skb(skb);
	failover_test_ctx_destroy(ctx);
}

static void tquic_failover_test_only_failed_path_is_requeued(struct kunit *test)
{
	struct failover_test_ctx *ctx;
	struct sk_buff *skb1;
	struct sk_buff *skb2;
	struct tquic_failover_packet *sp;
	int ret;

	ctx = failover_test_ctx_create(test);
	skb1 = failover_test_alloc_skb(test, 96);
	skb2 = failover_test_alloc_skb(test, 96);

	ret = tquic_failover_track_sent(ctx->fc, skb1, 200, 1);
	KUNIT_ASSERT_EQ(test, ret, 0);
	ret = tquic_failover_track_sent(ctx->fc, skb2, 201, 2);
	KUNIT_ASSERT_EQ(test, ret, 0);

	ret = tquic_failover_on_path_failed(ctx->fc, 1);
	KUNIT_ASSERT_EQ(test, ret, 1);

	sp = tquic_failover_get_next(ctx->fc);
	KUNIT_ASSERT_NOT_NULL(test, sp);
	KUNIT_EXPECT_EQ(test, sp->packet_number, (u64)200);
	KUNIT_EXPECT_EQ(test, sp->path_id, (u8)1);

	/* Simulate scheduler consuming retransmit entry. */
	tquic_failover_put_packet(sp);

	/* Packet on unaffected path should still ACK normally. */
	ret = tquic_failover_on_ack(ctx->fc, 201);
	KUNIT_EXPECT_EQ(test, ret, 0);

	kfree_skb(skb1);
	kfree_skb(skb2);
	failover_test_ctx_destroy(ctx);
}

static struct kunit_case tquic_failover_test_cases[] = {
	KUNIT_CASE(tquic_failover_test_late_ack_removes_requeued_packet),
	KUNIT_CASE(tquic_failover_test_only_failed_path_is_requeued),
	{}
};

static struct kunit_suite tquic_failover_test_suite = {
	.name = "tquic_failover_test",
	.test_cases = tquic_failover_test_cases,
};

kunit_test_suite(tquic_failover_test_suite);

MODULE_LICENSE("GPL");
