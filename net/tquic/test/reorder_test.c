// SPDX-License-Identifier: GPL-2.0-only
/*
 * KUnit tests for TQUIC packet reorder buffer (WAN bonding)
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Tests the reorder buffer used to reassemble packets that arrive
 * out of order when using multiple WAN paths with different latencies.
 */

#include <kunit/test.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/rbtree.h>

/* Reorder buffer configuration */
#define TEST_REORDER_DEFAULT_SIZE	256
#define TEST_REORDER_MAX_SIZE		4096
#define TEST_REORDER_DEFAULT_WINDOW	64

/* Reorder entry for testing */
struct test_reorder_entry {
	struct rb_node node;
	u64 pkt_num;
	void *data;
	size_t len;
};

/* Reorder buffer state */
struct test_reorder_buf {
	struct rb_root entries;
	u64 next_expected;
	u64 highest_received;
	u32 max_size;
	u32 current_size;
	u32 window;

	/* Statistics */
	u64 in_order_count;
	u64 reordered_count;
	u64 dropped_count;
	u64 delivered_count;
};

/**
 * reorder_buf_init - Initialize reorder buffer
 * @buf: Buffer to initialize
 * @window: Reorder window size
 */
static void reorder_buf_init(struct test_reorder_buf *buf, u32 window)
{
	buf->entries = RB_ROOT;
	buf->next_expected = 0;
	buf->highest_received = 0;
	buf->max_size = TEST_REORDER_DEFAULT_SIZE;
	buf->current_size = 0;
	buf->window = window ?: TEST_REORDER_DEFAULT_WINDOW;
	buf->in_order_count = 0;
	buf->reordered_count = 0;
	buf->dropped_count = 0;
	buf->delivered_count = 0;
}

/**
 * reorder_buf_insert - Insert packet into reorder buffer
 * @buf: Reorder buffer
 * @pkt_num: Packet number
 * @data: Packet data (for testing, just track the pointer)
 * @len: Data length
 *
 * Returns: 0 on success, negative on error
 */
static int reorder_buf_insert(struct test_reorder_buf *buf, u64 pkt_num,
			      void *data, size_t len)
{
	struct test_reorder_entry *entry, *existing;
	struct rb_node **link, *parent = NULL;

	/* Check for duplicate */
	link = &buf->entries.rb_node;
	while (*link) {
		parent = *link;
		existing = rb_entry(parent, struct test_reorder_entry, node);

		if (pkt_num < existing->pkt_num) {
			link = &parent->rb_left;
		} else if (pkt_num > existing->pkt_num) {
			link = &parent->rb_right;
		} else {
			return -EEXIST;  /* Duplicate */
		}
	}

	/* Check buffer capacity */
	if (buf->current_size >= buf->max_size) {
		buf->dropped_count++;
		return -ENOSPC;
	}

	/* Allocate and insert */
	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;

	entry->pkt_num = pkt_num;
	entry->data = data;
	entry->len = len;

	rb_link_node(&entry->node, parent, link);
	rb_insert_color(&entry->node, &buf->entries);
	buf->current_size++;

	/* Update highest received */
	if (pkt_num > buf->highest_received)
		buf->highest_received = pkt_num;

	return 0;
}

/**
 * reorder_buf_deliver - Deliver consecutive packets starting from next_expected
 * @buf: Reorder buffer
 *
 * Returns: Number of packets delivered
 */
static int reorder_buf_deliver(struct test_reorder_buf *buf)
{
	struct rb_node *node;
	int delivered = 0;

	while ((node = rb_first(&buf->entries)) != NULL) {
		struct test_reorder_entry *entry;

		entry = rb_entry(node, struct test_reorder_entry, node);

		if (entry->pkt_num != buf->next_expected)
			break;

		rb_erase(node, &buf->entries);
		buf->current_size--;
		buf->next_expected++;
		buf->delivered_count++;
		delivered++;

		kfree(entry);
	}

	return delivered;
}

/**
 * reorder_buf_receive - Process incoming packet
 * @buf: Reorder buffer
 * @pkt_num: Packet number
 * @data: Packet data
 * @len: Data length
 *
 * Returns: Number of packets delivered (including this one if in-order)
 */
static int reorder_buf_receive(struct test_reorder_buf *buf, u64 pkt_num,
			       void *data, size_t len)
{
	int delivered = 0;

	/* Check if packet is too old */
	if (pkt_num < buf->next_expected)
		return 0;  /* Already delivered or duplicate */

	/* Check if packet is in order */
	if (pkt_num == buf->next_expected) {
		buf->next_expected++;
		buf->in_order_count++;
		buf->delivered_count++;
		delivered = 1;

		/* Deliver any buffered consecutive packets */
		delivered += reorder_buf_deliver(buf);
	} else {
		/* Out of order - buffer it */
		int ret = reorder_buf_insert(buf, pkt_num, data, len);
		if (ret == 0) {
			buf->reordered_count++;
		} else if (ret == -EEXIST) {
			return 0;  /* Duplicate */
		} else {
			return ret;  /* Error */
		}
	}

	return delivered;
}

/**
 * reorder_buf_flush - Flush all buffered packets
 * @buf: Reorder buffer
 *
 * Returns: Number of packets flushed
 */
static int reorder_buf_flush(struct test_reorder_buf *buf)
{
	struct rb_node *node, *next;
	int flushed = 0;

	for (node = rb_first(&buf->entries); node; node = next) {
		struct test_reorder_entry *entry;

		next = rb_next(node);
		entry = rb_entry(node, struct test_reorder_entry, node);

		rb_erase(node, &buf->entries);
		buf->current_size--;
		buf->delivered_count++;
		flushed++;

		kfree(entry);
	}

	if (flushed > 0)
		buf->next_expected = buf->highest_received + 1;

	return flushed;
}

/**
 * reorder_buf_get_gap - Get current gap in packet sequence
 * @buf: Reorder buffer
 *
 * Returns: Number of missing packets
 */
static u64 reorder_buf_get_gap(struct test_reorder_buf *buf)
{
	if (buf->highest_received < buf->next_expected)
		return 0;
	return buf->highest_received - buf->next_expected;
}

/**
 * reorder_buf_cleanup - Free all entries
 * @buf: Reorder buffer
 */
static void reorder_buf_cleanup(struct test_reorder_buf *buf)
{
	struct rb_node *node;

	while ((node = rb_first(&buf->entries)) != NULL) {
		struct test_reorder_entry *entry;

		entry = rb_entry(node, struct test_reorder_entry, node);
		rb_erase(node, &buf->entries);
		kfree(entry);
	}
	buf->current_size = 0;
}

/* Test fixture */
struct reorder_test_ctx {
	struct test_reorder_buf buf;
};

static int reorder_test_init(struct kunit *test)
{
	struct reorder_test_ctx *ctx;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);

	reorder_buf_init(&ctx->buf, TEST_REORDER_DEFAULT_WINDOW);
	test->priv = ctx;

	return 0;
}

static void reorder_test_exit(struct kunit *test)
{
	struct reorder_test_ctx *ctx = test->priv;

	if (ctx)
		reorder_buf_cleanup(&ctx->buf);
}

/* Test: Initial buffer state */
static void tquic_reorder_test_init(struct kunit *test)
{
	struct reorder_test_ctx *ctx = test->priv;
	struct test_reorder_buf *buf = &ctx->buf;

	KUNIT_EXPECT_EQ(test, buf->next_expected, 0ULL);
	KUNIT_EXPECT_EQ(test, buf->current_size, 0U);
	KUNIT_EXPECT_EQ(test, buf->in_order_count, 0ULL);
	KUNIT_EXPECT_EQ(test, buf->reordered_count, 0ULL);
	KUNIT_EXPECT_EQ(test, buf->dropped_count, 0ULL);
	KUNIT_EXPECT_TRUE(test, RB_EMPTY_ROOT(&buf->entries));
}

/* Test: In-order packet delivery */
static void tquic_reorder_test_in_order(struct kunit *test)
{
	struct reorder_test_ctx *ctx = test->priv;
	struct test_reorder_buf *buf = &ctx->buf;
	int delivered;

	/* Send packets 0, 1, 2, 3 in order */
	delivered = reorder_buf_receive(buf, 0, NULL, 0);
	KUNIT_EXPECT_EQ(test, delivered, 1);

	delivered = reorder_buf_receive(buf, 1, NULL, 0);
	KUNIT_EXPECT_EQ(test, delivered, 1);

	delivered = reorder_buf_receive(buf, 2, NULL, 0);
	KUNIT_EXPECT_EQ(test, delivered, 1);

	delivered = reorder_buf_receive(buf, 3, NULL, 0);
	KUNIT_EXPECT_EQ(test, delivered, 1);

	/* All should be delivered in order */
	KUNIT_EXPECT_EQ(test, buf->next_expected, 4ULL);
	KUNIT_EXPECT_EQ(test, buf->in_order_count, 4ULL);
	KUNIT_EXPECT_EQ(test, buf->reordered_count, 0ULL);
	KUNIT_EXPECT_EQ(test, buf->current_size, 0U);
}

/* Test: Simple reordering */
static void tquic_reorder_test_simple_reorder(struct kunit *test)
{
	struct reorder_test_ctx *ctx = test->priv;
	struct test_reorder_buf *buf = &ctx->buf;
	int delivered;

	/* Receive packet 0 */
	delivered = reorder_buf_receive(buf, 0, NULL, 0);
	KUNIT_EXPECT_EQ(test, delivered, 1);
	KUNIT_EXPECT_EQ(test, buf->next_expected, 1ULL);

	/* Receive packet 2 (out of order, 1 is missing) */
	delivered = reorder_buf_receive(buf, 2, NULL, 0);
	KUNIT_EXPECT_EQ(test, delivered, 0);
	KUNIT_EXPECT_EQ(test, buf->next_expected, 1ULL);  /* Still waiting for 1 */
	KUNIT_EXPECT_EQ(test, buf->current_size, 1U);

	/* Receive packet 1 - should deliver both 1 and 2 */
	delivered = reorder_buf_receive(buf, 1, NULL, 0);
	KUNIT_EXPECT_EQ(test, delivered, 2);  /* 1 plus buffered 2 */
	KUNIT_EXPECT_EQ(test, buf->next_expected, 3ULL);
	KUNIT_EXPECT_EQ(test, buf->current_size, 0U);
}

/* Test: Multiple out-of-order packets */
static void tquic_reorder_test_multiple_ooo(struct kunit *test)
{
	struct reorder_test_ctx *ctx = test->priv;
	struct test_reorder_buf *buf = &ctx->buf;
	int delivered;

	/* Receive packets 0, 3, 4, 2 (missing 1) */
	delivered = reorder_buf_receive(buf, 0, NULL, 0);
	KUNIT_EXPECT_EQ(test, delivered, 1);

	delivered = reorder_buf_receive(buf, 3, NULL, 0);
	KUNIT_EXPECT_EQ(test, delivered, 0);

	delivered = reorder_buf_receive(buf, 4, NULL, 0);
	KUNIT_EXPECT_EQ(test, delivered, 0);

	delivered = reorder_buf_receive(buf, 2, NULL, 0);
	KUNIT_EXPECT_EQ(test, delivered, 0);

	KUNIT_EXPECT_EQ(test, buf->next_expected, 1ULL);
	KUNIT_EXPECT_EQ(test, buf->current_size, 3U);  /* 2, 3, 4 buffered */

	/* Now receive 1 - should deliver 1, 2, 3, 4 */
	delivered = reorder_buf_receive(buf, 1, NULL, 0);
	KUNIT_EXPECT_EQ(test, delivered, 4);
	KUNIT_EXPECT_EQ(test, buf->next_expected, 5ULL);
	KUNIT_EXPECT_EQ(test, buf->current_size, 0U);
}

/* Test: Duplicate packet handling */
static void tquic_reorder_test_duplicate(struct kunit *test)
{
	struct reorder_test_ctx *ctx = test->priv;
	struct test_reorder_buf *buf = &ctx->buf;
	int delivered;

	/* Receive packet 0 */
	delivered = reorder_buf_receive(buf, 0, NULL, 0);
	KUNIT_EXPECT_EQ(test, delivered, 1);

	/* Receive duplicate packet 0 */
	delivered = reorder_buf_receive(buf, 0, NULL, 0);
	KUNIT_EXPECT_EQ(test, delivered, 0);  /* Ignored */

	/* Receive packet 2, then duplicate 2 */
	delivered = reorder_buf_receive(buf, 2, NULL, 0);
	KUNIT_EXPECT_EQ(test, delivered, 0);  /* Buffered */

	delivered = reorder_buf_receive(buf, 2, NULL, 0);
	KUNIT_EXPECT_EQ(test, delivered, 0);  /* Duplicate ignored */

	KUNIT_EXPECT_EQ(test, buf->current_size, 1U);  /* Only one copy of 2 */
}

/* Test: Old packet handling */
static void tquic_reorder_test_old_packet(struct kunit *test)
{
	struct reorder_test_ctx *ctx = test->priv;
	struct test_reorder_buf *buf = &ctx->buf;
	int delivered;

	/* Receive packets 0, 1, 2 */
	reorder_buf_receive(buf, 0, NULL, 0);
	reorder_buf_receive(buf, 1, NULL, 0);
	reorder_buf_receive(buf, 2, NULL, 0);

	KUNIT_EXPECT_EQ(test, buf->next_expected, 3ULL);

	/* Now receive "old" packet 1 again */
	delivered = reorder_buf_receive(buf, 1, NULL, 0);
	KUNIT_EXPECT_EQ(test, delivered, 0);  /* Too old */

	/* Receive "old" packet 0 */
	delivered = reorder_buf_receive(buf, 0, NULL, 0);
	KUNIT_EXPECT_EQ(test, delivered, 0);  /* Too old */

	/* State should be unchanged */
	KUNIT_EXPECT_EQ(test, buf->next_expected, 3ULL);
}

/* Test: Buffer flush */
static void tquic_reorder_test_flush(struct kunit *test)
{
	struct reorder_test_ctx *ctx = test->priv;
	struct test_reorder_buf *buf = &ctx->buf;
	int flushed;

	/* Receive packets 0, 2, 4, 6 (gaps) */
	reorder_buf_receive(buf, 0, NULL, 0);
	reorder_buf_receive(buf, 2, NULL, 0);
	reorder_buf_receive(buf, 4, NULL, 0);
	reorder_buf_receive(buf, 6, NULL, 0);

	KUNIT_EXPECT_EQ(test, buf->current_size, 3U);  /* 2, 4, 6 buffered */
	KUNIT_EXPECT_EQ(test, buf->next_expected, 1ULL);

	/* Flush buffer */
	flushed = reorder_buf_flush(buf);
	KUNIT_EXPECT_EQ(test, flushed, 3);
	KUNIT_EXPECT_EQ(test, buf->current_size, 0U);
	KUNIT_EXPECT_EQ(test, buf->next_expected, 7ULL);  /* Highest + 1 */
}

/* Test: Gap calculation */
static void tquic_reorder_test_gap(struct kunit *test)
{
	struct reorder_test_ctx *ctx = test->priv;
	struct test_reorder_buf *buf = &ctx->buf;
	u64 gap;

	/* Initial state - no gap */
	gap = reorder_buf_get_gap(buf);
	KUNIT_EXPECT_EQ(test, gap, 0ULL);

	/* Receive packet 0 */
	reorder_buf_receive(buf, 0, NULL, 0);
	gap = reorder_buf_get_gap(buf);
	KUNIT_EXPECT_EQ(test, gap, 0ULL);

	/* Receive packet 5 (gap of 4 packets: 1, 2, 3, 4) */
	reorder_buf_receive(buf, 5, NULL, 0);
	gap = reorder_buf_get_gap(buf);
	KUNIT_EXPECT_EQ(test, gap, 4ULL);

	/* Receive packet 10 (larger gap) */
	reorder_buf_receive(buf, 10, NULL, 0);
	gap = reorder_buf_get_gap(buf);
	KUNIT_EXPECT_EQ(test, gap, 9ULL);  /* 10 - 1 = 9 */
}

/* Test: Buffer capacity limit */
static void tquic_reorder_test_capacity(struct kunit *test)
{
	struct reorder_test_ctx *ctx = test->priv;
	struct test_reorder_buf *buf = &ctx->buf;
	int i;

	/* Set small capacity */
	buf->max_size = 10;

	/* Fill buffer */
	reorder_buf_receive(buf, 0, NULL, 0);  /* Delivered immediately */
	for (i = 2; i < 12; i++) {
		reorder_buf_receive(buf, i, NULL, 0);
	}

	KUNIT_EXPECT_EQ(test, buf->current_size, 10U);

	/* Try to add more - should fail */
	int ret = reorder_buf_insert(buf, 15, NULL, 0);
	KUNIT_EXPECT_EQ(test, ret, -ENOSPC);
	KUNIT_EXPECT_EQ(test, buf->dropped_count, 1ULL);
}

/* Test: Reverse order arrival */
static void tquic_reorder_test_reverse_order(struct kunit *test)
{
	struct reorder_test_ctx *ctx = test->priv;
	struct test_reorder_buf *buf = &ctx->buf;
	int delivered;

	/* Receive packets in reverse: 4, 3, 2, 1, 0 */
	delivered = reorder_buf_receive(buf, 4, NULL, 0);
	KUNIT_EXPECT_EQ(test, delivered, 0);

	delivered = reorder_buf_receive(buf, 3, NULL, 0);
	KUNIT_EXPECT_EQ(test, delivered, 0);

	delivered = reorder_buf_receive(buf, 2, NULL, 0);
	KUNIT_EXPECT_EQ(test, delivered, 0);

	delivered = reorder_buf_receive(buf, 1, NULL, 0);
	KUNIT_EXPECT_EQ(test, delivered, 0);

	KUNIT_EXPECT_EQ(test, buf->current_size, 4U);

	/* Finally receive packet 0 - all should be delivered */
	delivered = reorder_buf_receive(buf, 0, NULL, 0);
	KUNIT_EXPECT_EQ(test, delivered, 5);
	KUNIT_EXPECT_EQ(test, buf->current_size, 0U);
	KUNIT_EXPECT_EQ(test, buf->next_expected, 5ULL);
}

/* Test: Interleaved arrivals */
static void tquic_reorder_test_interleaved(struct kunit *test)
{
	struct reorder_test_ctx *ctx = test->priv;
	struct test_reorder_buf *buf = &ctx->buf;
	int delivered;

	/* Receive even packets first: 0, 2, 4 */
	delivered = reorder_buf_receive(buf, 0, NULL, 0);
	KUNIT_EXPECT_EQ(test, delivered, 1);

	delivered = reorder_buf_receive(buf, 2, NULL, 0);
	KUNIT_EXPECT_EQ(test, delivered, 0);

	delivered = reorder_buf_receive(buf, 4, NULL, 0);
	KUNIT_EXPECT_EQ(test, delivered, 0);

	/* Now odd packets: 1, 3 */
	delivered = reorder_buf_receive(buf, 1, NULL, 0);
	KUNIT_EXPECT_EQ(test, delivered, 2);  /* 1 and 2 */

	delivered = reorder_buf_receive(buf, 3, NULL, 0);
	KUNIT_EXPECT_EQ(test, delivered, 2);  /* 3 and 4 */

	KUNIT_EXPECT_EQ(test, buf->next_expected, 5ULL);
	KUNIT_EXPECT_EQ(test, buf->current_size, 0U);
}

/* Test: Statistics tracking */
static void tquic_reorder_test_statistics(struct kunit *test)
{
	struct reorder_test_ctx *ctx = test->priv;
	struct test_reorder_buf *buf = &ctx->buf;

	/* Send in-order */
	reorder_buf_receive(buf, 0, NULL, 0);
	reorder_buf_receive(buf, 1, NULL, 0);

	/* Send out of order */
	reorder_buf_receive(buf, 3, NULL, 0);
	reorder_buf_receive(buf, 4, NULL, 0);
	reorder_buf_receive(buf, 2, NULL, 0);  /* Triggers delivery of 2, 3, 4 */

	KUNIT_EXPECT_EQ(test, buf->in_order_count, 3ULL);  /* 0, 1, 2 */
	KUNIT_EXPECT_EQ(test, buf->reordered_count, 2ULL); /* 3, 4 */
	KUNIT_EXPECT_EQ(test, buf->delivered_count, 5ULL);
}

/* Test: Large gap handling */
static void tquic_reorder_test_large_gap(struct kunit *test)
{
	struct reorder_test_ctx *ctx = test->priv;
	struct test_reorder_buf *buf = &ctx->buf;
	u64 gap;

	/* Receive packet 0 */
	reorder_buf_receive(buf, 0, NULL, 0);

	/* Receive packet far in the future */
	reorder_buf_receive(buf, 1000, NULL, 0);

	gap = reorder_buf_get_gap(buf);
	KUNIT_EXPECT_EQ(test, gap, 999ULL);

	/* Buffer should have the out-of-order packet */
	KUNIT_EXPECT_EQ(test, buf->current_size, 1U);
	KUNIT_EXPECT_EQ(test, buf->highest_received, 1000ULL);
}

/* Test: Window-based delivery */
static void tquic_reorder_test_window_delivery(struct kunit *test)
{
	struct reorder_test_ctx *ctx = test->priv;
	struct test_reorder_buf *buf = &ctx->buf;

	buf->window = 3;  /* Small window for testing */

	/* Receive packet 0 */
	reorder_buf_receive(buf, 0, NULL, 0);

	/* Receive packets 2, 3, 4 (1 is missing) */
	reorder_buf_receive(buf, 2, NULL, 0);
	reorder_buf_receive(buf, 3, NULL, 0);
	reorder_buf_receive(buf, 4, NULL, 0);

	KUNIT_EXPECT_EQ(test, buf->current_size, 3U);

	/* Window is 3, so if we receive packet beyond window,
	 * we might need to force delivery */
	u64 gap = reorder_buf_get_gap(buf);
	KUNIT_EXPECT_EQ(test, gap, 3ULL);  /* 4 - 1 = 3 */
}

/* Test: Empty buffer operations */
static void tquic_reorder_test_empty_ops(struct kunit *test)
{
	struct reorder_test_ctx *ctx = test->priv;
	struct test_reorder_buf *buf = &ctx->buf;
	int result;

	/* Flush empty buffer */
	result = reorder_buf_flush(buf);
	KUNIT_EXPECT_EQ(test, result, 0);

	/* Deliver from empty buffer */
	result = reorder_buf_deliver(buf);
	KUNIT_EXPECT_EQ(test, result, 0);

	/* Gap of empty buffer */
	result = reorder_buf_get_gap(buf);
	KUNIT_EXPECT_EQ(test, result, 0);
}

/* Test: Stress test with many packets */
static void tquic_reorder_test_stress(struct kunit *test)
{
	struct reorder_test_ctx *ctx = test->priv;
	struct test_reorder_buf *buf = &ctx->buf;
	int i;

	/* Send 100 packets in order */
	for (i = 0; i < 100; i++) {
		reorder_buf_receive(buf, i, NULL, 0);
	}

	KUNIT_EXPECT_EQ(test, buf->next_expected, 100ULL);
	KUNIT_EXPECT_EQ(test, buf->in_order_count, 100ULL);
	KUNIT_EXPECT_EQ(test, buf->current_size, 0U);
}

/* Test: Alternating gaps */
static void tquic_reorder_test_alternating_gaps(struct kunit *test)
{
	struct reorder_test_ctx *ctx = test->priv;
	struct test_reorder_buf *buf = &ctx->buf;

	/* 0, gap, 2, gap, 4, gap, 6, then fill gaps */
	reorder_buf_receive(buf, 0, NULL, 0);
	reorder_buf_receive(buf, 2, NULL, 0);
	reorder_buf_receive(buf, 4, NULL, 0);
	reorder_buf_receive(buf, 6, NULL, 0);

	KUNIT_EXPECT_EQ(test, buf->current_size, 3U);  /* 2, 4, 6 buffered */

	/* Fill gaps in order: 1, 3, 5 */
	reorder_buf_receive(buf, 1, NULL, 0);
	KUNIT_EXPECT_EQ(test, buf->next_expected, 3ULL);

	reorder_buf_receive(buf, 3, NULL, 0);
	KUNIT_EXPECT_EQ(test, buf->next_expected, 5ULL);

	reorder_buf_receive(buf, 5, NULL, 0);
	KUNIT_EXPECT_EQ(test, buf->next_expected, 7ULL);

	KUNIT_EXPECT_EQ(test, buf->current_size, 0U);
}

/* Test: Configuration defaults */
static void tquic_reorder_test_config(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, TEST_REORDER_DEFAULT_SIZE, 256);
	KUNIT_EXPECT_EQ(test, TEST_REORDER_MAX_SIZE, 4096);
	KUNIT_EXPECT_EQ(test, TEST_REORDER_DEFAULT_WINDOW, 64);
}

static struct kunit_case tquic_reorder_test_cases[] = {
	KUNIT_CASE(tquic_reorder_test_init),
	KUNIT_CASE(tquic_reorder_test_in_order),
	KUNIT_CASE(tquic_reorder_test_simple_reorder),
	KUNIT_CASE(tquic_reorder_test_multiple_ooo),
	KUNIT_CASE(tquic_reorder_test_duplicate),
	KUNIT_CASE(tquic_reorder_test_old_packet),
	KUNIT_CASE(tquic_reorder_test_flush),
	KUNIT_CASE(tquic_reorder_test_gap),
	KUNIT_CASE(tquic_reorder_test_capacity),
	KUNIT_CASE(tquic_reorder_test_reverse_order),
	KUNIT_CASE(tquic_reorder_test_interleaved),
	KUNIT_CASE(tquic_reorder_test_statistics),
	KUNIT_CASE(tquic_reorder_test_large_gap),
	KUNIT_CASE(tquic_reorder_test_window_delivery),
	KUNIT_CASE(tquic_reorder_test_empty_ops),
	KUNIT_CASE(tquic_reorder_test_stress),
	KUNIT_CASE(tquic_reorder_test_alternating_gaps),
	KUNIT_CASE(tquic_reorder_test_config),
	{}
};

static struct kunit_suite tquic_reorder_test_suite = {
	.name = "tquic-reorder",
	.test_cases = tquic_reorder_test_cases,
	.init = reorder_test_init,
	.exit = reorder_test_exit,
};

kunit_test_suite(tquic_reorder_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for TQUIC packet reorder buffer");
