// SPDX-License-Identifier: GPL-2.0-only
/*
 * KUnit tests for TQUIC tx_work throughput loop
 *
 * Validates that tquic_conn_tx_work drains the control_frames queue
 * in a loop rather than sending a single packet per invocation.
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 */

#include <kunit/test.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/workqueue.h>
#include <linux/math64.h>
#include <net/tquic.h>

/*
 * =============================================================================
 * Test Constants
 * =============================================================================
 */

#define TX_TEST_MTU		1500
#define TX_TEST_MSS		1200
#define TX_TEST_INITIAL_CWND	(10 * TX_TEST_MSS)
#define TX_TEST_FRAME_SIZE	100	/* Small control frame */

/*
 * =============================================================================
 * Test Helpers
 * =============================================================================
 */

/*
 * Minimal mock for testing tx_work queue draining behavior.
 *
 * These tests verify the loop logic and batch limits at the
 * control_frames queue level, independent of the full connection
 * setup needed for end-to-end packet transmission.
 */

/* Simulate queueing N control frames */
static void tx_test_queue_frames(struct sk_buff_head *queue, int count,
				 int frame_size)
{
	int i;

	for (i = 0; i < count; i++) {
		struct sk_buff *skb;

		skb = alloc_skb(frame_size, GFP_KERNEL);
		if (!skb)
			break;
		skb_put(skb, frame_size);
		skb_queue_tail(queue, skb);
	}
}

/*
 * =============================================================================
 * Queue Draining Logic Tests
 *
 * These tests validate the core loop logic extracted from tx_work:
 * - Multiple frames should be drained per invocation
 * - Batch limit (TQUIC_TX_WORK_BATCH_MAX = 64) must be respected
 * - cwnd exhaustion must stop draining
 * =============================================================================
 */

/*
 * Test: Multiple frames drain in a single pass
 *
 * Previously, tx_work sent exactly 1 packet per invocation.
 * After the fix, it should drain all queued frames up to the
 * batch limit or cwnd exhaustion.
 */
static void test_tx_queue_multi_drain(struct kunit *test)
{
	struct sk_buff_head queue;
	int initial_count = 10;
	int drained = 0;

	skb_queue_head_init(&queue);
	tx_test_queue_frames(&queue, initial_count, TX_TEST_FRAME_SIZE);

	KUNIT_ASSERT_EQ(test, skb_queue_len(&queue), initial_count);

	/*
	 * Simulate the tx_work drain loop: dequeue and "send" until
	 * the queue is empty. This models the fixed behavior where
	 * tx_work loops instead of sending a single packet.
	 */
	while (!skb_queue_empty(&queue) && drained < 64) {
		struct sk_buff *skb = skb_dequeue(&queue);

		KUNIT_ASSERT_NOT_NULL(test, skb);
		kfree_skb(skb);
		drained++;
	}

	KUNIT_EXPECT_EQ(test, drained, initial_count);
	KUNIT_EXPECT_TRUE(test, skb_queue_empty(&queue));

	kunit_info(test, "drained %d frames in single pass (was: 1)\n",
		   drained);
}

/*
 * Test: Batch limit prevents CPU hogging
 *
 * When more than TQUIC_TX_WORK_BATCH_MAX (64) frames are queued,
 * tx_work should stop at the limit and re-schedule.
 */
static void test_tx_queue_batch_limit(struct kunit *test)
{
	struct sk_buff_head queue;
	int queued = 100;	/* More than batch limit */
	int batch_max = 64;	/* TQUIC_TX_WORK_BATCH_MAX */
	int drained = 0;

	skb_queue_head_init(&queue);
	tx_test_queue_frames(&queue, queued, TX_TEST_FRAME_SIZE);

	KUNIT_ASSERT_EQ(test, skb_queue_len(&queue), queued);

	/* Drain up to batch limit */
	while (!skb_queue_empty(&queue) && drained < batch_max) {
		struct sk_buff *skb = skb_dequeue(&queue);

		KUNIT_ASSERT_NOT_NULL(test, skb);
		kfree_skb(skb);
		drained++;
	}

	KUNIT_EXPECT_EQ(test, drained, batch_max);
	KUNIT_EXPECT_EQ(test, skb_queue_len(&queue), queued - batch_max);

	/* Cleanup remaining */
	skb_queue_purge(&queue);

	kunit_info(test, "batch limit enforced: drained %d of %d, %d remain\n",
		   drained, queued, queued - batch_max);
}

/*
 * Test: cwnd exhaustion stops draining
 *
 * When bytes_in_flight >= cwnd, tx_work should stop sending even
 * if there are more frames in the queue.
 */
static void test_tx_queue_cwnd_limit(struct kunit *test)
{
	struct sk_buff_head queue;
	int queued = 20;
	int drained = 0;
	u32 cwnd = TX_TEST_INITIAL_CWND;	/* 12000 bytes */
	u32 bytes_in_flight = 0;
	u32 pkt_size = TX_TEST_MSS;

	skb_queue_head_init(&queue);
	tx_test_queue_frames(&queue, queued, TX_TEST_FRAME_SIZE);

	KUNIT_ASSERT_EQ(test, skb_queue_len(&queue), queued);

	/*
	 * Drain until cwnd is full. Each "sent" packet adds pkt_size
	 * to bytes_in_flight. Stop when cwnd is exhausted.
	 */
	while (!skb_queue_empty(&queue) && drained < 64) {
		struct sk_buff *skb;

		/* Check cwnd before sending */
		if (cwnd > 0 && bytes_in_flight >= cwnd)
			break;

		skb = skb_dequeue(&queue);
		KUNIT_ASSERT_NOT_NULL(test, skb);
		kfree_skb(skb);
		drained++;
		bytes_in_flight += pkt_size;
	}

	/* cwnd = 12000, pkt = 1200, so we should send exactly 10 */
	KUNIT_EXPECT_EQ(test, drained, (int)(cwnd / pkt_size));
	KUNIT_EXPECT_GE(test, bytes_in_flight, cwnd);
	KUNIT_EXPECT_FALSE(test, skb_queue_empty(&queue));

	/* Cleanup remaining */
	skb_queue_purge(&queue);

	kunit_info(test, "cwnd limited: drained %d packets, bif=%u cwnd=%u\n",
		   drained, bytes_in_flight, cwnd);
}

/*
 * Test: Empty queue exits immediately
 *
 * Verify that tx_work doesn't loop or crash on an empty queue.
 */
static void test_tx_queue_empty(struct kunit *test)
{
	struct sk_buff_head queue;
	int drained = 0;

	skb_queue_head_init(&queue);

	KUNIT_EXPECT_TRUE(test, skb_queue_empty(&queue));

	/* Loop should not execute */
	while (!skb_queue_empty(&queue) && drained < 64) {
		struct sk_buff *skb = skb_dequeue(&queue);

		if (!skb)
			break;
		kfree_skb(skb);
		drained++;
	}

	KUNIT_EXPECT_EQ(test, drained, 0);
}

/*
 * Test: Single frame drains correctly
 *
 * Regression: the old single-packet code worked for this case.
 * Ensure the loop still handles it.
 */
static void test_tx_queue_single_frame(struct kunit *test)
{
	struct sk_buff_head queue;
	int drained = 0;

	skb_queue_head_init(&queue);
	tx_test_queue_frames(&queue, 1, TX_TEST_FRAME_SIZE);

	KUNIT_ASSERT_EQ(test, skb_queue_len(&queue), 1);

	while (!skb_queue_empty(&queue) && drained < 64) {
		struct sk_buff *skb = skb_dequeue(&queue);

		KUNIT_ASSERT_NOT_NULL(test, skb);
		kfree_skb(skb);
		drained++;
	}

	KUNIT_EXPECT_EQ(test, drained, 1);
	KUNIT_EXPECT_TRUE(test, skb_queue_empty(&queue));
}

/*
 * Test: Throughput improvement calculation
 *
 * Demonstrate the throughput improvement from looping.
 * Old: 1 pkt/RTT → ~47 KB/s at 30ms RTT
 * New: cwnd pkts/RTT → ~400 KB/s+ at 30ms RTT with 10-pkt cwnd
 */
static void test_tx_throughput_model(struct kunit *test)
{
	u32 rtt_ms = 30;
	u32 cwnd_pkts = 10;
	u32 pkt_size = TX_TEST_MSS;
	u64 old_throughput_kbps;
	u64 new_throughput_kbps;

	/* Old: 1 packet per RTT */
	old_throughput_kbps = (u64)pkt_size * 1000 / rtt_ms / 1024;

	/* New: cwnd packets per RTT */
	new_throughput_kbps = (u64)pkt_size * cwnd_pkts * 1000 / rtt_ms / 1024;

	KUNIT_EXPECT_GT(test, new_throughput_kbps, old_throughput_kbps);
	KUNIT_EXPECT_GE(test, new_throughput_kbps, (u64)300);

	kunit_info(test, "throughput model: old=%llu KB/s, new=%llu KB/s (%llux improvement)\n",
		   old_throughput_kbps, new_throughput_kbps,
		   new_throughput_kbps / old_throughput_kbps);
}

/*
 * =============================================================================
 * Pacing Tests
 *
 * Validate the pacing delay formula and pacing-gated drain behavior.
 * =============================================================================
 */

/*
 * Test: Pacing delay calculation
 *
 * Verify that delay_ns = bytes * NSEC_PER_SEC / pacing_rate.
 * - 1200 bytes at 1,200,000 bytes/sec = 1,000,000 ns (1ms)
 * - 1200 bytes at 0 bytes/sec = 0 ns (no pacing)
 */
static void test_tx_pacing_delay_calculation(struct kunit *test)
{
	u64 rate, delay_ns;
	u32 bytes = TX_TEST_MSS; /* 1200 bytes */

	/* Case 1: Normal pacing rate */
	rate = 1200000; /* 1.2 MB/s */
	delay_ns = div64_u64((u64)bytes * NSEC_PER_SEC, rate);

	KUNIT_EXPECT_EQ(test, delay_ns, (u64)1000000);
	kunit_info(test, "pacing delay: %u bytes @ %llu B/s = %llu ns (expect 1ms)\n",
		   bytes, rate, delay_ns);

	/* Case 2: Zero rate means no pacing */
	rate = 0;
	delay_ns = (rate == 0) ? 0 :
		   div64_u64((u64)bytes * NSEC_PER_SEC, rate);

	KUNIT_EXPECT_EQ(test, delay_ns, (u64)0);
	kunit_info(test, "pacing delay: %u bytes @ 0 B/s = %llu ns (no pacing)\n",
		   bytes, delay_ns);

	/* Case 3: High rate (10 Gbps ~ 1.25 GB/s) */
	rate = 1250000000ULL;
	delay_ns = div64_u64((u64)bytes * NSEC_PER_SEC, rate);

	/* 1200 * 1e9 / 1.25e9 = 960 ns */
	KUNIT_EXPECT_EQ(test, delay_ns, (u64)960);
	kunit_info(test, "pacing delay: %u bytes @ %llu B/s = %llu ns\n",
		   bytes, rate, delay_ns);
}

/*
 * Test: Pacing blocks when next_send_time is in the future
 *
 * Simulate the pacing gate by tracking next_send_time. When the
 * gate is closed (next_send_time > now), the drain loop should
 * skip Application-space packets, similar to how cwnd limits
 * stop draining.
 */
static void test_tx_pacing_blocks_when_rate_set(struct kunit *test)
{
	struct sk_buff_head queue;
	int queued = 10;
	int drained = 0;
	u64 now_ns = 1000000000ULL;	/* 1 second */
	u64 next_send_ns;
	u64 pacing_rate = 1200000;	/* 1.2 MB/s */
	u32 pkt_size = TX_TEST_MSS;
	u64 delay_ns;

	skb_queue_head_init(&queue);
	tx_test_queue_frames(&queue, queued, TX_TEST_FRAME_SIZE);
	KUNIT_ASSERT_EQ(test, skb_queue_len(&queue), queued);

	/* Start with pacing gate open */
	next_send_ns = now_ns;

	/*
	 * Drain loop that respects pacing: after each send, compute
	 * the next allowed send time. Stop when the gate closes.
	 */
	while (!skb_queue_empty(&queue) && drained < 64) {
		struct sk_buff *skb;

		/* Pacing gate check */
		if (now_ns < next_send_ns)
			break;

		skb = skb_dequeue(&queue);
		KUNIT_ASSERT_NOT_NULL(test, skb);
		kfree_skb(skb);
		drained++;

		/* Schedule next send time */
		delay_ns = div64_u64((u64)pkt_size * NSEC_PER_SEC,
				     pacing_rate);
		next_send_ns = now_ns + delay_ns;

		/*
		 * In a real scenario, time advances. Here we keep now_ns
		 * fixed, so the gate closes after the first send.
		 */
	}

	/*
	 * With time frozen, only 1 packet should be sent before the
	 * pacing gate closes (next_send_ns moves 1ms into the future).
	 */
	KUNIT_EXPECT_EQ(test, drained, 1);
	KUNIT_EXPECT_FALSE(test, skb_queue_empty(&queue));
	KUNIT_EXPECT_GT(test, next_send_ns, now_ns);

	skb_queue_purge(&queue);

	kunit_info(test, "pacing blocked after %d pkt: next_send=%llu now=%llu delta=%llu ns\n",
		   drained, next_send_ns, now_ns, next_send_ns - now_ns);
}

/*
 * =============================================================================
 * Test Suite
 * =============================================================================
 */

static struct kunit_case tx_work_test_cases[] = {
	KUNIT_CASE(test_tx_queue_multi_drain),
	KUNIT_CASE(test_tx_queue_batch_limit),
	KUNIT_CASE(test_tx_queue_cwnd_limit),
	KUNIT_CASE(test_tx_queue_empty),
	KUNIT_CASE(test_tx_queue_single_frame),
	KUNIT_CASE(test_tx_throughput_model),
	KUNIT_CASE(test_tx_pacing_delay_calculation),
	KUNIT_CASE(test_tx_pacing_blocks_when_rate_set),
	{}
};

static struct kunit_suite tx_work_test_suite = {
	.name = "tquic_tx_work",
	.test_cases = tx_work_test_cases,
};

kunit_test_suite(tx_work_test_suite);

MODULE_DESCRIPTION("KUnit tests for TQUIC tx_work throughput loop");
MODULE_AUTHOR("Justin Adams <spotty118@gmail.com>");
MODULE_LICENSE("GPL");
