// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: QUIC Datagram Extension KUnit Tests (RFC 9221)
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Comprehensive tests for QUIC Datagram extension:
 *   - DATAGRAM frame encoding/decoding
 *   - Receive queue management
 *   - Queue limits and backpressure
 *   - Size validation
 *   - Statistics tracking
 *
 * Test Structure:
 *   Section 1: Frame Encoding/Decoding Tests
 *   Section 2: Receive Queue Tests
 *   Section 3: Queue Limits Tests
 *   Section 4: Size Validation Tests
 *   Section 5: Statistics Tests
 */

#include <kunit/test.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/list.h>

/*
 * =============================================================================
 * Constants (mirror production values)
 * =============================================================================
 */

/* DATAGRAM frame types (RFC 9221) */
#define TQUIC_FRAME_DATAGRAM		0x30
#define TQUIC_FRAME_DATAGRAM_LEN	0x31

/* Transport parameter ID */
#define TQUIC_TP_MAX_DATAGRAM_FRAME_SIZE	0x20

/* Limits */
#define TQUIC_DATAGRAM_MAX_SIZE		65535
#define TQUIC_DATAGRAM_DEFAULT_QUEUE_SIZE	16
#define TQUIC_DATAGRAM_MAX_QUEUE_SIZE		256

/*
 * =============================================================================
 * Test Data Structures
 * =============================================================================
 */

/**
 * struct test_datagram - Simulated datagram entry
 * @data: Datagram payload
 * @len: Payload length
 * @list: Queue linkage
 */
struct test_datagram {
	u8 *data;
	size_t len;
	struct list_head list;
};

/**
 * struct test_datagram_queue - Simulated datagram receive queue
 * @head: Queue head
 * @count: Number of datagrams in queue
 * @max_count: Maximum queue size
 * @max_datagram_size: Maximum single datagram size
 * @total_bytes: Total bytes in queue
 * @max_bytes: Maximum bytes in queue
 */
struct test_datagram_queue {
	struct list_head head;
	u32 count;
	u32 max_count;
	size_t max_datagram_size;
	size_t total_bytes;
	size_t max_bytes;
};

/**
 * struct test_datagram_stats - Datagram statistics
 * @rx_datagrams: Received datagrams
 * @tx_datagrams: Transmitted datagrams
 * @rx_bytes: Total received bytes
 * @tx_bytes: Total transmitted bytes
 * @dropped_size: Dropped due to size limit
 * @dropped_queue_full: Dropped due to queue full
 * @dropped_disabled: Dropped because datagrams disabled
 */
struct test_datagram_stats {
	u64 rx_datagrams;
	u64 tx_datagrams;
	u64 rx_bytes;
	u64 tx_bytes;
	u64 dropped_size;
	u64 dropped_queue_full;
	u64 dropped_disabled;
};

/*
 * =============================================================================
 * Variable-Length Integer Helpers
 * =============================================================================
 */

static size_t test_varint_size(u64 value)
{
	if (value <= 63)
		return 1;
	if (value <= 16383)
		return 2;
	if (value <= 1073741823ULL)
		return 4;
	return 8;
}

static int test_varint_encode(u8 *buf, size_t buf_len, u64 value)
{
	size_t len = test_varint_size(value);

	if (buf_len < len)
		return -ENOBUFS;

	if (len == 1) {
		buf[0] = (u8)value;
	} else if (len == 2) {
		buf[0] = (u8)(0x40 | (value >> 8));
		buf[1] = (u8)(value & 0xff);
	} else if (len == 4) {
		buf[0] = (u8)(0x80 | (value >> 24));
		buf[1] = (u8)((value >> 16) & 0xff);
		buf[2] = (u8)((value >> 8) & 0xff);
		buf[3] = (u8)(value & 0xff);
	} else {
		buf[0] = (u8)(0xc0 | (value >> 56));
		buf[1] = (u8)((value >> 48) & 0xff);
		buf[2] = (u8)((value >> 40) & 0xff);
		buf[3] = (u8)((value >> 32) & 0xff);
		buf[4] = (u8)((value >> 24) & 0xff);
		buf[5] = (u8)((value >> 16) & 0xff);
		buf[6] = (u8)((value >> 8) & 0xff);
		buf[7] = (u8)(value & 0xff);
	}

	return len;
}

static int test_varint_decode(const u8 *buf, size_t buf_len, u64 *value)
{
	size_t len;
	u8 prefix;

	if (buf_len < 1)
		return -EINVAL;

	prefix = buf[0] >> 6;
	len = 1 << prefix;

	if (buf_len < len)
		return -EINVAL;

	switch (len) {
	case 1:
		*value = buf[0] & 0x3f;
		break;
	case 2:
		*value = ((u64)(buf[0] & 0x3f) << 8) | buf[1];
		break;
	case 4:
		*value = ((u64)(buf[0] & 0x3f) << 24) |
			 ((u64)buf[1] << 16) |
			 ((u64)buf[2] << 8) |
			 buf[3];
		break;
	case 8:
		*value = ((u64)(buf[0] & 0x3f) << 56) |
			 ((u64)buf[1] << 48) |
			 ((u64)buf[2] << 40) |
			 ((u64)buf[3] << 32) |
			 ((u64)buf[4] << 24) |
			 ((u64)buf[5] << 16) |
			 ((u64)buf[6] << 8) |
			 buf[7];
		break;
	}

	return len;
}

/*
 * =============================================================================
 * Datagram Frame Encoding/Decoding
 * =============================================================================
 */

/**
 * test_datagram_encode - Encode DATAGRAM frame
 * @buf: Output buffer
 * @buf_len: Buffer length
 * @data: Datagram payload
 * @data_len: Payload length
 * @include_length: If true, use DATAGRAM_LEN type (0x31)
 *
 * Returns: Bytes written, or negative error
 */
static int test_datagram_encode(u8 *buf, size_t buf_len,
				const u8 *data, size_t data_len,
				bool include_length)
{
	size_t offset = 0;
	int ret;
	u64 frame_type = include_length ? TQUIC_FRAME_DATAGRAM_LEN :
					  TQUIC_FRAME_DATAGRAM;

	/* Frame type */
	ret = test_varint_encode(buf + offset, buf_len - offset, frame_type);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Length field (only for DATAGRAM_LEN) */
	if (include_length) {
		ret = test_varint_encode(buf + offset, buf_len - offset, data_len);
		if (ret < 0)
			return ret;
		offset += ret;
	}

	/* Payload */
	if (buf_len - offset < data_len)
		return -ENOBUFS;
	memcpy(buf + offset, data, data_len);
	offset += data_len;

	return offset;
}

/**
 * test_datagram_decode - Decode DATAGRAM frame
 * @buf: Input buffer
 * @buf_len: Buffer length (remaining in packet for no-length variant)
 * @data: Output pointer to payload
 * @data_len: Output payload length
 *
 * Returns: Bytes consumed, or negative error
 */
static int test_datagram_decode(const u8 *buf, size_t buf_len,
				const u8 **data, size_t *data_len)
{
	size_t offset = 0;
	u64 frame_type;
	u64 length;
	int ret;

	/* Frame type */
	ret = test_varint_decode(buf + offset, buf_len - offset, &frame_type);
	if (ret < 0)
		return ret;
	offset += ret;

	if (frame_type == TQUIC_FRAME_DATAGRAM_LEN) {
		/* Length field present */
		ret = test_varint_decode(buf + offset, buf_len - offset, &length);
		if (ret < 0)
			return ret;
		offset += ret;

		if (offset + length > buf_len)
			return -EINVAL;

		*data = buf + offset;
		*data_len = length;
		return offset + length;
	} else if (frame_type == TQUIC_FRAME_DATAGRAM) {
		/* No length field - data extends to end of packet */
		*data = buf + offset;
		*data_len = buf_len - offset;
		return buf_len;
	}

	return -EINVAL;  /* Unknown frame type */
}

/*
 * =============================================================================
 * Queue Management
 * =============================================================================
 */

/**
 * test_datagram_queue_init - Initialize datagram queue
 * @queue: Queue to initialize
 * @max_count: Maximum datagram count
 * @max_datagram_size: Maximum single datagram size
 * @max_bytes: Maximum total bytes in queue
 */
static void test_datagram_queue_init(struct test_datagram_queue *queue,
				     u32 max_count,
				     size_t max_datagram_size,
				     size_t max_bytes)
{
	INIT_LIST_HEAD(&queue->head);
	queue->count = 0;
	queue->max_count = max_count;
	queue->max_datagram_size = max_datagram_size;
	queue->total_bytes = 0;
	queue->max_bytes = max_bytes;
}

/**
 * test_datagram_queue_push - Add datagram to queue
 * @queue: Queue
 * @data: Datagram data
 * @len: Data length
 * @stats: Statistics to update
 *
 * Returns: 0 on success, negative error on failure
 */
static int test_datagram_queue_push(struct test_datagram_queue *queue,
				    const u8 *data, size_t len,
				    struct test_datagram_stats *stats)
{
	struct test_datagram *dg;

	/* Check size limit */
	if (len > queue->max_datagram_size) {
		if (stats)
			stats->dropped_size++;
		return -EMSGSIZE;
	}

	/* Check queue count limit */
	if (queue->count >= queue->max_count) {
		if (stats)
			stats->dropped_queue_full++;
		return -ENOBUFS;
	}

	/* Check total bytes limit */
	if (queue->total_bytes + len > queue->max_bytes) {
		if (stats)
			stats->dropped_queue_full++;
		return -ENOBUFS;
	}

	/* Allocate and copy */
	dg = kzalloc(sizeof(*dg), GFP_KERNEL);
	if (!dg)
		return -ENOMEM;

	dg->data = kmalloc(len, GFP_KERNEL);
	if (!dg->data) {
		kfree(dg);
		return -ENOMEM;
	}

	memcpy(dg->data, data, len);
	dg->len = len;

	/* Add to queue */
	list_add_tail(&dg->list, &queue->head);
	queue->count++;
	queue->total_bytes += len;

	/* Update stats */
	if (stats) {
		stats->rx_datagrams++;
		stats->rx_bytes += len;
	}

	return 0;
}

/**
 * test_datagram_queue_pop - Remove datagram from queue
 * @queue: Queue
 * @buf: Output buffer
 * @buf_len: Buffer length
 *
 * Returns: Bytes copied, or negative error
 */
static int test_datagram_queue_pop(struct test_datagram_queue *queue,
				   u8 *buf, size_t buf_len)
{
	struct test_datagram *dg;
	size_t len;

	if (list_empty(&queue->head))
		return -EAGAIN;

	dg = list_first_entry(&queue->head, struct test_datagram, list);

	if (buf_len < dg->len)
		return -ENOBUFS;

	len = dg->len;
	memcpy(buf, dg->data, len);

	/* Remove from queue */
	list_del(&dg->list);
	queue->count--;
	queue->total_bytes -= len;

	kfree(dg->data);
	kfree(dg);

	return len;
}

/**
 * test_datagram_queue_peek - Peek at first datagram without removing
 * @queue: Queue
 *
 * Returns: Pointer to first datagram, or NULL if empty
 */
static struct test_datagram *test_datagram_queue_peek(
	struct test_datagram_queue *queue)
{
	if (list_empty(&queue->head))
		return NULL;

	return list_first_entry(&queue->head, struct test_datagram, list);
}

/**
 * test_datagram_queue_destroy - Free all datagrams in queue
 * @queue: Queue to destroy
 */
static void test_datagram_queue_destroy(struct test_datagram_queue *queue)
{
	struct test_datagram *dg, *tmp;

	list_for_each_entry_safe(dg, tmp, &queue->head, list) {
		list_del(&dg->list);
		kfree(dg->data);
		kfree(dg);
	}
	queue->count = 0;
	queue->total_bytes = 0;
}

/*
 * =============================================================================
 * SECTION 1: Frame Encoding/Decoding Tests
 * =============================================================================
 */

/* Test: Encode DATAGRAM frame without length */
static void test_datagram_encode_no_length(struct kunit *test)
{
	u8 buf[64];
	u8 payload[] = "Hello, QUIC Datagram!";
	int ret;

	/* ACT */
	ret = test_datagram_encode(buf, sizeof(buf), payload,
				   sizeof(payload) - 1, false);

	/* ASSERT */
	KUNIT_EXPECT_GT(test, ret, 0);
	KUNIT_EXPECT_EQ(test, buf[0], (u8)TQUIC_FRAME_DATAGRAM);
	/* Payload follows immediately */
	KUNIT_EXPECT_EQ(test, memcmp(buf + 1, payload, sizeof(payload) - 1), 0);
}

/* Test: Encode DATAGRAM frame with length */
static void test_datagram_encode_with_length(struct kunit *test)
{
	u8 buf[64];
	u8 payload[] = "Test payload";
	int ret;

	/* ACT */
	ret = test_datagram_encode(buf, sizeof(buf), payload,
				   sizeof(payload) - 1, true);

	/* ASSERT */
	KUNIT_EXPECT_GT(test, ret, 0);
	KUNIT_EXPECT_EQ(test, buf[0], (u8)TQUIC_FRAME_DATAGRAM_LEN);
	/* Length follows frame type */
	KUNIT_EXPECT_EQ(test, buf[1], sizeof(payload) - 1);
}

/* Test: Decode DATAGRAM frame without length */
static void test_datagram_decode_no_length(struct kunit *test)
{
	u8 buf[64];
	u8 payload[] = "Decode test";
	const u8 *decoded_data;
	size_t decoded_len;
	int encode_ret, decode_ret;

	/* ARRANGE: Encode frame */
	encode_ret = test_datagram_encode(buf, sizeof(buf), payload,
					  sizeof(payload) - 1, false);
	KUNIT_EXPECT_GT(test, encode_ret, 0);

	/* ACT: Decode frame */
	decode_ret = test_datagram_decode(buf, encode_ret,
					  &decoded_data, &decoded_len);

	/* ASSERT */
	KUNIT_EXPECT_EQ(test, decode_ret, encode_ret);
	KUNIT_EXPECT_EQ(test, decoded_len, sizeof(payload) - 1);
	KUNIT_EXPECT_EQ(test, memcmp(decoded_data, payload, decoded_len), 0);
}

/* Test: Decode DATAGRAM frame with length */
static void test_datagram_decode_with_length(struct kunit *test)
{
	u8 buf[64];
	u8 payload[] = "Length test";
	const u8 *decoded_data;
	size_t decoded_len;
	int encode_ret, decode_ret;

	/* ARRANGE */
	encode_ret = test_datagram_encode(buf, sizeof(buf), payload,
					  sizeof(payload) - 1, true);
	KUNIT_EXPECT_GT(test, encode_ret, 0);

	/* ACT */
	decode_ret = test_datagram_decode(buf, encode_ret,
					  &decoded_data, &decoded_len);

	/* ASSERT */
	KUNIT_EXPECT_EQ(test, decode_ret, encode_ret);
	KUNIT_EXPECT_EQ(test, decoded_len, sizeof(payload) - 1);
	KUNIT_EXPECT_EQ(test, memcmp(decoded_data, payload, decoded_len), 0);
}

/* Test: Empty datagram */
static void test_datagram_encode_empty(struct kunit *test)
{
	u8 buf[16];
	const u8 *decoded_data;
	size_t decoded_len;
	int ret;

	/* ARRANGE/ACT: Encode empty datagram */
	ret = test_datagram_encode(buf, sizeof(buf), NULL, 0, true);
	KUNIT_EXPECT_GT(test, ret, 0);

	/* ACT: Decode */
	ret = test_datagram_decode(buf, ret, &decoded_data, &decoded_len);

	/* ASSERT */
	KUNIT_EXPECT_GT(test, ret, 0);
	KUNIT_EXPECT_EQ(test, decoded_len, 0UL);
}

/* Test: Buffer too small for encoding */
static void test_datagram_encode_buffer_too_small(struct kunit *test)
{
	u8 buf[4];
	u8 payload[100];
	int ret;

	memset(payload, 'A', sizeof(payload));

	/* ACT/ASSERT */
	ret = test_datagram_encode(buf, sizeof(buf), payload,
				   sizeof(payload), true);
	KUNIT_EXPECT_LT(test, ret, 0);
}

/* Test: Invalid frame type during decode */
static void test_datagram_decode_invalid_type(struct kunit *test)
{
	u8 buf[] = {0x00, 0x05, 'H', 'e', 'l', 'l', 'o'};  /* Type 0 is not DATAGRAM */
	const u8 *decoded_data;
	size_t decoded_len;
	int ret;

	/* ACT/ASSERT */
	ret = test_datagram_decode(buf, sizeof(buf), &decoded_data, &decoded_len);
	KUNIT_EXPECT_LT(test, ret, 0);
}

/*
 * =============================================================================
 * SECTION 2: Receive Queue Tests
 * =============================================================================
 */

/* Test: Basic queue operations */
static void test_queue_basic_operations(struct kunit *test)
{
	struct test_datagram_queue queue;
	struct test_datagram_stats stats = {0};
	u8 data1[] = "First datagram";
	u8 data2[] = "Second datagram";
	u8 recv_buf[64];
	int ret;

	/* ARRANGE */
	test_datagram_queue_init(&queue, 16, 1000, 10000);

	/* ACT: Push two datagrams */
	ret = test_datagram_queue_push(&queue, data1, sizeof(data1), &stats);
	KUNIT_EXPECT_EQ(test, ret, 0);

	ret = test_datagram_queue_push(&queue, data2, sizeof(data2), &stats);
	KUNIT_EXPECT_EQ(test, ret, 0);

	/* ASSERT: Queue state */
	KUNIT_EXPECT_EQ(test, queue.count, 2U);
	KUNIT_EXPECT_EQ(test, stats.rx_datagrams, 2ULL);

	/* ACT: Pop first datagram (FIFO) */
	ret = test_datagram_queue_pop(&queue, recv_buf, sizeof(recv_buf));
	KUNIT_EXPECT_EQ(test, ret, (int)sizeof(data1));
	KUNIT_EXPECT_EQ(test, memcmp(recv_buf, data1, sizeof(data1)), 0);

	/* ASSERT: Queue state after pop */
	KUNIT_EXPECT_EQ(test, queue.count, 1U);

	/* Cleanup */
	test_datagram_queue_destroy(&queue);
}

/* Test: Queue is FIFO */
static void test_queue_fifo_order(struct kunit *test)
{
	struct test_datagram_queue queue;
	u8 data1[] = "First";
	u8 data2[] = "Second";
	u8 data3[] = "Third";
	u8 recv_buf[64];
	int ret;

	/* ARRANGE */
	test_datagram_queue_init(&queue, 16, 1000, 10000);
	test_datagram_queue_push(&queue, data1, sizeof(data1), NULL);
	test_datagram_queue_push(&queue, data2, sizeof(data2), NULL);
	test_datagram_queue_push(&queue, data3, sizeof(data3), NULL);

	/* ACT/ASSERT: Pop in order */
	ret = test_datagram_queue_pop(&queue, recv_buf, sizeof(recv_buf));
	KUNIT_EXPECT_EQ(test, memcmp(recv_buf, data1, sizeof(data1)), 0);

	ret = test_datagram_queue_pop(&queue, recv_buf, sizeof(recv_buf));
	KUNIT_EXPECT_EQ(test, memcmp(recv_buf, data2, sizeof(data2)), 0);

	ret = test_datagram_queue_pop(&queue, recv_buf, sizeof(recv_buf));
	KUNIT_EXPECT_EQ(test, memcmp(recv_buf, data3, sizeof(data3)), 0);

	/* Cleanup */
	test_datagram_queue_destroy(&queue);
}

/* Test: Pop from empty queue */
static void test_queue_pop_empty(struct kunit *test)
{
	struct test_datagram_queue queue;
	u8 recv_buf[64];
	int ret;

	/* ARRANGE */
	test_datagram_queue_init(&queue, 16, 1000, 10000);

	/* ACT/ASSERT */
	ret = test_datagram_queue_pop(&queue, recv_buf, sizeof(recv_buf));
	KUNIT_EXPECT_EQ(test, ret, -EAGAIN);
}

/* Test: Peek without removing */
static void test_queue_peek(struct kunit *test)
{
	struct test_datagram_queue queue;
	struct test_datagram *peeked;
	u8 data[] = "Peek test";

	/* ARRANGE */
	test_datagram_queue_init(&queue, 16, 1000, 10000);
	test_datagram_queue_push(&queue, data, sizeof(data), NULL);

	/* ACT */
	peeked = test_datagram_queue_peek(&queue);

	/* ASSERT: Peek returns data but doesn't remove */
	KUNIT_EXPECT_NOT_NULL(test, peeked);
	KUNIT_EXPECT_EQ(test, peeked->len, sizeof(data));
	KUNIT_EXPECT_EQ(test, memcmp(peeked->data, data, sizeof(data)), 0);
	KUNIT_EXPECT_EQ(test, queue.count, 1U);  /* Still in queue */

	/* Cleanup */
	test_datagram_queue_destroy(&queue);
}

/* Test: Peek on empty queue */
static void test_queue_peek_empty(struct kunit *test)
{
	struct test_datagram_queue queue;
	struct test_datagram *peeked;

	/* ARRANGE */
	test_datagram_queue_init(&queue, 16, 1000, 10000);

	/* ACT/ASSERT */
	peeked = test_datagram_queue_peek(&queue);
	KUNIT_EXPECT_NULL(test, peeked);
}

/*
 * =============================================================================
 * SECTION 3: Queue Limits Tests
 * =============================================================================
 */

/* Test: Queue count limit enforced */
static void test_queue_count_limit(struct kunit *test)
{
	struct test_datagram_queue queue;
	struct test_datagram_stats stats = {0};
	u8 data[] = "Test";
	int i, ret;

	/* ARRANGE: Queue with max 3 datagrams */
	test_datagram_queue_init(&queue, 3, 1000, 10000);

	/* ACT: Fill queue */
	for (i = 0; i < 3; i++) {
		ret = test_datagram_queue_push(&queue, data, sizeof(data), &stats);
		KUNIT_EXPECT_EQ(test, ret, 0);
	}

	/* ACT: Try to exceed limit */
	ret = test_datagram_queue_push(&queue, data, sizeof(data), &stats);

	/* ASSERT */
	KUNIT_EXPECT_EQ(test, ret, -ENOBUFS);
	KUNIT_EXPECT_EQ(test, queue.count, 3U);
	KUNIT_EXPECT_EQ(test, stats.dropped_queue_full, 1ULL);

	/* Cleanup */
	test_datagram_queue_destroy(&queue);
}

/* Test: Queue byte limit enforced */
static void test_queue_byte_limit(struct kunit *test)
{
	struct test_datagram_queue queue;
	struct test_datagram_stats stats = {0};
	u8 data[50];
	int ret;

	memset(data, 'A', sizeof(data));

	/* ARRANGE: Queue with max 100 bytes */
	test_datagram_queue_init(&queue, 100, 1000, 100);

	/* ACT: Add datagrams until byte limit */
	ret = test_datagram_queue_push(&queue, data, sizeof(data), &stats);
	KUNIT_EXPECT_EQ(test, ret, 0);

	ret = test_datagram_queue_push(&queue, data, sizeof(data), &stats);
	KUNIT_EXPECT_EQ(test, ret, 0);

	/* ACT: Third would exceed 100 bytes */
	ret = test_datagram_queue_push(&queue, data, sizeof(data), &stats);

	/* ASSERT */
	KUNIT_EXPECT_EQ(test, ret, -ENOBUFS);
	KUNIT_EXPECT_EQ(test, queue.total_bytes, 100UL);

	/* Cleanup */
	test_datagram_queue_destroy(&queue);
}

/* Test: Backpressure - queue full behavior */
static void test_queue_backpressure(struct kunit *test)
{
	struct test_datagram_queue queue;
	struct test_datagram_stats stats = {0};
	u8 data[] = "Test";
	u8 recv_buf[64];
	int ret;

	/* ARRANGE: Small queue */
	test_datagram_queue_init(&queue, 2, 1000, 10000);

	/* Fill queue */
	test_datagram_queue_push(&queue, data, sizeof(data), &stats);
	test_datagram_queue_push(&queue, data, sizeof(data), &stats);

	/* ACT: Try to add when full */
	ret = test_datagram_queue_push(&queue, data, sizeof(data), &stats);
	KUNIT_EXPECT_EQ(test, ret, -ENOBUFS);

	/* ACT: Pop one */
	test_datagram_queue_pop(&queue, recv_buf, sizeof(recv_buf));

	/* ACT: Now we can add again */
	ret = test_datagram_queue_push(&queue, data, sizeof(data), &stats);
	KUNIT_EXPECT_EQ(test, ret, 0);

	/* Cleanup */
	test_datagram_queue_destroy(&queue);
}

/*
 * =============================================================================
 * SECTION 4: Size Validation Tests
 * =============================================================================
 */

/* Test: Datagram size limit enforced */
static void test_datagram_size_limit(struct kunit *test)
{
	struct test_datagram_queue queue;
	struct test_datagram_stats stats = {0};
	u8 data[200];
	int ret;

	memset(data, 'B', sizeof(data));

	/* ARRANGE: Queue with max datagram size 100 */
	test_datagram_queue_init(&queue, 16, 100, 10000);

	/* ACT: Try to add oversized datagram */
	ret = test_datagram_queue_push(&queue, data, sizeof(data), &stats);

	/* ASSERT */
	KUNIT_EXPECT_EQ(test, ret, -EMSGSIZE);
	KUNIT_EXPECT_EQ(test, stats.dropped_size, 1ULL);
	KUNIT_EXPECT_EQ(test, queue.count, 0U);

	/* Cleanup */
	test_datagram_queue_destroy(&queue);
}

/* Test: Datagram at exactly max size is accepted */
static void test_datagram_exact_max_size(struct kunit *test)
{
	struct test_datagram_queue queue;
	struct test_datagram_stats stats = {0};
	u8 data[100];
	int ret;

	memset(data, 'C', sizeof(data));

	/* ARRANGE: Queue with max datagram size 100 */
	test_datagram_queue_init(&queue, 16, 100, 10000);

	/* ACT: Add datagram at exactly max size */
	ret = test_datagram_queue_push(&queue, data, sizeof(data), &stats);

	/* ASSERT */
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, queue.count, 1U);

	/* Cleanup */
	test_datagram_queue_destroy(&queue);
}

/* Test: Zero-size datagram */
static void test_datagram_zero_size(struct kunit *test)
{
	struct test_datagram_queue queue;
	struct test_datagram_stats stats = {0};
	u8 recv_buf[16];
	int ret;

	/* ARRANGE */
	test_datagram_queue_init(&queue, 16, 1000, 10000);

	/* ACT: Add zero-size datagram */
	ret = test_datagram_queue_push(&queue, NULL, 0, &stats);
	KUNIT_EXPECT_EQ(test, ret, 0);

	/* ASSERT */
	KUNIT_EXPECT_EQ(test, queue.count, 1U);
	KUNIT_EXPECT_EQ(test, queue.total_bytes, 0UL);

	/* Pop and verify */
	ret = test_datagram_queue_pop(&queue, recv_buf, sizeof(recv_buf));
	KUNIT_EXPECT_EQ(test, ret, 0);  /* Zero bytes */

	/* Cleanup */
	test_datagram_queue_destroy(&queue);
}

/* Test: Large datagram encoding */
static void test_datagram_large_encode(struct kunit *test)
{
	u8 *buf;
	u8 *payload;
	const u8 *decoded_data;
	size_t decoded_len;
	size_t payload_size = 1200;  /* MTU-sized payload */
	int encode_ret, decode_ret;

	/* ARRANGE */
	buf = kzalloc(payload_size + 16, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buf);
	payload = kzalloc(payload_size, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, payload);
	memset(payload, 'D', payload_size);

	/* ACT: Encode */
	encode_ret = test_datagram_encode(buf, payload_size + 16,
					  payload, payload_size, true);
	KUNIT_EXPECT_GT(test, encode_ret, 0);

	/* ACT: Decode */
	decode_ret = test_datagram_decode(buf, encode_ret,
					  &decoded_data, &decoded_len);

	/* ASSERT */
	KUNIT_EXPECT_EQ(test, decode_ret, encode_ret);
	KUNIT_EXPECT_EQ(test, decoded_len, payload_size);
	KUNIT_EXPECT_EQ(test, memcmp(decoded_data, payload, payload_size), 0);

	kfree(payload);
	kfree(buf);
}

/*
 * =============================================================================
 * SECTION 5: Statistics Tests
 * =============================================================================
 */

/* Test: Statistics tracking on push */
static void test_stats_on_push(struct kunit *test)
{
	struct test_datagram_queue queue;
	struct test_datagram_stats stats = {0};
	u8 data1[100];
	u8 data2[50];

	memset(data1, 'E', sizeof(data1));
	memset(data2, 'F', sizeof(data2));

	/* ARRANGE */
	test_datagram_queue_init(&queue, 16, 1000, 10000);

	/* ACT */
	test_datagram_queue_push(&queue, data1, sizeof(data1), &stats);
	test_datagram_queue_push(&queue, data2, sizeof(data2), &stats);

	/* ASSERT */
	KUNIT_EXPECT_EQ(test, stats.rx_datagrams, 2ULL);
	KUNIT_EXPECT_EQ(test, stats.rx_bytes, sizeof(data1) + sizeof(data2));

	/* Cleanup */
	test_datagram_queue_destroy(&queue);
}

/* Test: Statistics tracking on drop */
static void test_stats_on_drop(struct kunit *test)
{
	struct test_datagram_queue queue;
	struct test_datagram_stats stats = {0};
	u8 small_data[10];
	u8 big_data[200];

	memset(small_data, 'G', sizeof(small_data));
	memset(big_data, 'H', sizeof(big_data));

	/* ARRANGE: Queue with small max size and count */
	test_datagram_queue_init(&queue, 1, 50, 10000);

	/* ACT: Add valid datagram */
	test_datagram_queue_push(&queue, small_data, sizeof(small_data), &stats);

	/* ACT: Try oversized datagram */
	test_datagram_queue_push(&queue, big_data, sizeof(big_data), &stats);

	/* ACT: Try when queue full */
	test_datagram_queue_push(&queue, small_data, sizeof(small_data), &stats);

	/* ASSERT */
	KUNIT_EXPECT_EQ(test, stats.rx_datagrams, 1ULL);
	KUNIT_EXPECT_EQ(test, stats.dropped_size, 1ULL);
	KUNIT_EXPECT_EQ(test, stats.dropped_queue_full, 1ULL);

	/* Cleanup */
	test_datagram_queue_destroy(&queue);
}

/* Test: Total bytes tracking */
static void test_stats_total_bytes(struct kunit *test)
{
	struct test_datagram_queue queue;
	u8 data1[100];
	u8 data2[200];
	u8 recv_buf[256];

	memset(data1, 'I', sizeof(data1));
	memset(data2, 'J', sizeof(data2));

	/* ARRANGE */
	test_datagram_queue_init(&queue, 16, 1000, 10000);

	/* ACT: Push datagrams */
	test_datagram_queue_push(&queue, data1, sizeof(data1), NULL);
	test_datagram_queue_push(&queue, data2, sizeof(data2), NULL);

	/* ASSERT */
	KUNIT_EXPECT_EQ(test, queue.total_bytes,
			sizeof(data1) + sizeof(data2));

	/* ACT: Pop one */
	test_datagram_queue_pop(&queue, recv_buf, sizeof(recv_buf));

	/* ASSERT: Total bytes updated */
	KUNIT_EXPECT_EQ(test, queue.total_bytes, sizeof(data2));

	/* Cleanup */
	test_datagram_queue_destroy(&queue);
}

/* Test: Queue destroy cleans up properly */
static void test_queue_destroy_cleanup(struct kunit *test)
{
	struct test_datagram_queue queue;
	u8 data[] = "Cleanup test";
	int i;

	/* ARRANGE */
	test_datagram_queue_init(&queue, 16, 1000, 10000);

	for (i = 0; i < 10; i++) {
		test_datagram_queue_push(&queue, data, sizeof(data), NULL);
	}

	KUNIT_EXPECT_EQ(test, queue.count, 10U);

	/* ACT */
	test_datagram_queue_destroy(&queue);

	/* ASSERT: Queue is empty */
	KUNIT_EXPECT_EQ(test, queue.count, 0U);
	KUNIT_EXPECT_EQ(test, queue.total_bytes, 0UL);
	KUNIT_EXPECT_TRUE(test, list_empty(&queue.head));
}

/*
 * =============================================================================
 * Test Suite Definition
 * =============================================================================
 */

static struct kunit_case tquic_datagram_test_cases[] = {
	/* Frame Encoding/Decoding */
	KUNIT_CASE(test_datagram_encode_no_length),
	KUNIT_CASE(test_datagram_encode_with_length),
	KUNIT_CASE(test_datagram_decode_no_length),
	KUNIT_CASE(test_datagram_decode_with_length),
	KUNIT_CASE(test_datagram_encode_empty),
	KUNIT_CASE(test_datagram_encode_buffer_too_small),
	KUNIT_CASE(test_datagram_decode_invalid_type),

	/* Receive Queue */
	KUNIT_CASE(test_queue_basic_operations),
	KUNIT_CASE(test_queue_fifo_order),
	KUNIT_CASE(test_queue_pop_empty),
	KUNIT_CASE(test_queue_peek),
	KUNIT_CASE(test_queue_peek_empty),

	/* Queue Limits */
	KUNIT_CASE(test_queue_count_limit),
	KUNIT_CASE(test_queue_byte_limit),
	KUNIT_CASE(test_queue_backpressure),

	/* Size Validation */
	KUNIT_CASE(test_datagram_size_limit),
	KUNIT_CASE(test_datagram_exact_max_size),
	KUNIT_CASE(test_datagram_zero_size),
	KUNIT_CASE(test_datagram_large_encode),

	/* Statistics */
	KUNIT_CASE(test_stats_on_push),
	KUNIT_CASE(test_stats_on_drop),
	KUNIT_CASE(test_stats_total_bytes),
	KUNIT_CASE(test_queue_destroy_cleanup),
	{}
};

static struct kunit_suite tquic_datagram_test_suite = {
	.name = "tquic-datagram",
	.test_cases = tquic_datagram_test_cases,
};

kunit_test_suite(tquic_datagram_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for TQUIC QUIC Datagram Extension (RFC 9221)");
MODULE_AUTHOR("Linux Foundation");
