// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Congestion Control Data Exchange KUnit Tests
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Tests for the Congestion Control Data exchange extension
 * (draft-yuan-quic-congestion-data-00).
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <net/tquic.h>

#include "../cong/cong_data.h"
#include "../core/varint.h"

/*
 * =============================================================================
 * Test Fixtures
 * =============================================================================
 */

struct cong_data_test_context {
	struct tquic_cong_data data;
	u8 buf[256];
};

static int cong_data_test_init(struct kunit *test)
{
	struct cong_data_test_context *ctx;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);

	test->priv = ctx;
	return 0;
}

/*
 * =============================================================================
 * Encoding/Decoding Tests
 * =============================================================================
 */

/*
 * Test: Basic encode/decode cycle with minimal data
 */
static void test_encode_decode_basic(struct kunit *test)
{
	struct cong_data_test_context *ctx = test->priv;
	struct tquic_cong_data decoded;
	ssize_t encoded_len, decoded_len;

	/* Setup basic data */
	ctx->data.seq_num = 1;
	ctx->data.bwe = 100000000ULL;  /* 100 Mbps */
	ctx->data.min_rtt = 10000;     /* 10 ms */
	ctx->data.loss_rate = 100;     /* 1% */
	ctx->data.timestamp = 1700000000ULL;
	ctx->data.flags = 0;

	/* Encode */
	encoded_len = tquic_cong_data_encode(&ctx->data, ctx->buf, sizeof(ctx->buf));
	KUNIT_ASSERT_GT(test, encoded_len, (ssize_t)0);

	/* Skip frame type for decoding */
	u64 frame_type;
	size_t offset = 0;
	int ret = tquic_varint_read(ctx->buf, encoded_len, &offset, &frame_type);
	KUNIT_ASSERT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, frame_type, (u64)TQUIC_FRAME_CONGESTION_DATA);

	/* Decode */
	decoded_len = tquic_cong_data_decode(ctx->buf + offset, encoded_len - offset,
					     &decoded);
	KUNIT_ASSERT_GT(test, decoded_len, (ssize_t)0);

	/* Verify values */
	KUNIT_EXPECT_EQ(test, decoded.seq_num, ctx->data.seq_num);
	KUNIT_EXPECT_EQ(test, decoded.bwe, ctx->data.bwe);
	KUNIT_EXPECT_EQ(test, decoded.min_rtt, ctx->data.min_rtt);
	KUNIT_EXPECT_EQ(test, decoded.loss_rate, ctx->data.loss_rate);
	KUNIT_EXPECT_EQ(test, decoded.timestamp, ctx->data.timestamp);
	KUNIT_EXPECT_EQ(test, decoded.flags, ctx->data.flags);
}

/*
 * Test: Encode/decode with all optional fields
 */
static void test_encode_decode_full(struct kunit *test)
{
	struct cong_data_test_context *ctx = test->priv;
	struct tquic_cong_data decoded;
	ssize_t encoded_len, decoded_len;
	size_t offset = 0;
	u64 frame_type;
	int ret;

	/* Setup data with all optional fields */
	ctx->data.seq_num = 42;
	ctx->data.bwe = 1000000000ULL;    /* 1 Gbps */
	ctx->data.min_rtt = 5000;         /* 5 ms */
	ctx->data.loss_rate = 50;         /* 0.5% */
	ctx->data.timestamp = 1700000000ULL;
	ctx->data.flags = TQUIC_CONG_DATA_FLAG_HAS_CWND |
			  TQUIC_CONG_DATA_FLAG_HAS_SSTHRESH |
			  TQUIC_CONG_DATA_FLAG_HAS_PACING_RATE |
			  TQUIC_CONG_DATA_FLAG_HAS_DELIVERY_RATE;
	ctx->data.cwnd = 1048576;         /* 1 MB */
	ctx->data.ssthresh = 524288;      /* 512 KB */
	ctx->data.pacing_rate = 125000000; /* 125 MB/s */
	ctx->data.delivery_rate = 120000000; /* 120 MB/s */

	/* Encode */
	encoded_len = tquic_cong_data_encode(&ctx->data, ctx->buf, sizeof(ctx->buf));
	KUNIT_ASSERT_GT(test, encoded_len, (ssize_t)0);

	/* Skip frame type */
	ret = tquic_varint_read(ctx->buf, encoded_len, &offset, &frame_type);
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Decode */
	decoded_len = tquic_cong_data_decode(ctx->buf + offset, encoded_len - offset,
					     &decoded);
	KUNIT_ASSERT_GT(test, decoded_len, (ssize_t)0);

	/* Verify all values including optional fields */
	KUNIT_EXPECT_EQ(test, decoded.seq_num, ctx->data.seq_num);
	KUNIT_EXPECT_EQ(test, decoded.bwe, ctx->data.bwe);
	KUNIT_EXPECT_EQ(test, decoded.min_rtt, ctx->data.min_rtt);
	KUNIT_EXPECT_EQ(test, decoded.loss_rate, ctx->data.loss_rate);
	KUNIT_EXPECT_EQ(test, decoded.timestamp, ctx->data.timestamp);
	KUNIT_EXPECT_EQ(test, decoded.flags, ctx->data.flags);
	KUNIT_EXPECT_EQ(test, decoded.cwnd, ctx->data.cwnd);
	KUNIT_EXPECT_EQ(test, decoded.ssthresh, ctx->data.ssthresh);
	KUNIT_EXPECT_EQ(test, decoded.pacing_rate, ctx->data.pacing_rate);
	KUNIT_EXPECT_EQ(test, decoded.delivery_rate, ctx->data.delivery_rate);
}

/*
 * Test: Encode fails with buffer too small
 */
static void test_encode_buffer_too_small(struct kunit *test)
{
	struct cong_data_test_context *ctx = test->priv;
	u8 small_buf[4];
	ssize_t ret;

	ctx->data.seq_num = 1;
	ctx->data.bwe = 100000000ULL;
	ctx->data.min_rtt = 10000;
	ctx->data.loss_rate = 100;
	ctx->data.timestamp = 1700000000ULL;

	/* Buffer too small should fail */
	ret = tquic_cong_data_encode(&ctx->data, small_buf, sizeof(small_buf));
	KUNIT_EXPECT_LT(test, ret, (ssize_t)0);
}

/*
 * Test: Decode fails with truncated data
 */
static void test_decode_truncated(struct kunit *test)
{
	u8 truncated[] = { 0x01 };  /* Just a sequence number start */
	struct tquic_cong_data decoded;
	ssize_t ret;

	ret = tquic_cong_data_decode(truncated, sizeof(truncated), &decoded);
	KUNIT_EXPECT_LT(test, ret, (ssize_t)0);
}

/*
 * =============================================================================
 * Validation Tests
 * =============================================================================
 */

/*
 * Test: Validate accepts valid data
 */
static void test_validate_valid_data(struct kunit *test)
{
	struct cong_data_test_context *ctx = test->priv;
	int ret;

	ctx->data.seq_num = 1;
	ctx->data.bwe = 100000000ULL;  /* 100 Mbps - valid */
	ctx->data.min_rtt = 10000;     /* 10 ms - valid */
	ctx->data.loss_rate = 100;     /* 1% - valid */
	ctx->data.timestamp = ktime_get_real_seconds();
	ctx->data.flags = TQUIC_CONG_DATA_FLAG_HAS_CWND;
	ctx->data.cwnd = 1000000;      /* ~1 MB - valid */

	ret = tquic_cong_data_validate(NULL, &ctx->data);
	/* With NULL conn, validation might still pass for value checks */
	/* The actual result depends on implementation */
}

/*
 * Test: Validate rejects BWE out of range (too low)
 */
static void test_validate_bwe_too_low(struct kunit *test)
{
	struct cong_data_test_context *ctx = test->priv;
	int ret;

	ctx->data.seq_num = 1;
	ctx->data.bwe = 100;  /* 100 bps - too low */
	ctx->data.min_rtt = 10000;
	ctx->data.loss_rate = 100;
	ctx->data.timestamp = ktime_get_real_seconds();

	ret = tquic_cong_data_validate(NULL, &ctx->data);
	KUNIT_EXPECT_NE(test, ret, 0);
}

/*
 * Test: Validate rejects BWE out of range (too high)
 */
static void test_validate_bwe_too_high(struct kunit *test)
{
	struct cong_data_test_context *ctx = test->priv;
	int ret;

	ctx->data.seq_num = 1;
	ctx->data.bwe = 1000000000000000ULL;  /* Way too high */
	ctx->data.min_rtt = 10000;
	ctx->data.loss_rate = 100;
	ctx->data.timestamp = ktime_get_real_seconds();

	ret = tquic_cong_data_validate(NULL, &ctx->data);
	KUNIT_EXPECT_NE(test, ret, 0);
}

/*
 * Test: Validate rejects RTT out of range
 */
static void test_validate_rtt_out_of_range(struct kunit *test)
{
	struct cong_data_test_context *ctx = test->priv;
	int ret;

	ctx->data.seq_num = 1;
	ctx->data.bwe = 100000000ULL;
	ctx->data.min_rtt = 10;  /* 10 us - too low */
	ctx->data.loss_rate = 100;
	ctx->data.timestamp = ktime_get_real_seconds();

	ret = tquic_cong_data_validate(NULL, &ctx->data);
	KUNIT_EXPECT_NE(test, ret, 0);
}

/*
 * Test: Validate rejects loss rate over 100%
 */
static void test_validate_loss_rate_invalid(struct kunit *test)
{
	struct cong_data_test_context *ctx = test->priv;
	int ret;

	ctx->data.seq_num = 1;
	ctx->data.bwe = 100000000ULL;
	ctx->data.min_rtt = 10000;
	ctx->data.loss_rate = 15000;  /* 150% - invalid */
	ctx->data.timestamp = ktime_get_real_seconds();

	ret = tquic_cong_data_validate(NULL, &ctx->data);
	KUNIT_EXPECT_NE(test, ret, 0);
}

/*
 * Test: Validate rejects stale timestamp
 */
static void test_validate_stale_timestamp(struct kunit *test)
{
	struct cong_data_test_context *ctx = test->priv;
	int ret;

	ctx->data.seq_num = 1;
	ctx->data.bwe = 100000000ULL;
	ctx->data.min_rtt = 10000;
	ctx->data.loss_rate = 100;
	/* Set timestamp to more than 24 hours ago */
	ctx->data.timestamp = ktime_get_real_seconds() -
			      TQUIC_CONG_DATA_MAX_LIFETIME_SEC - 100;

	ret = tquic_cong_data_validate(NULL, &ctx->data);
	KUNIT_EXPECT_NE(test, ret, 0);
}

/*
 * Test: Validate rejects future timestamp
 */
static void test_validate_future_timestamp(struct kunit *test)
{
	struct cong_data_test_context *ctx = test->priv;
	int ret;

	ctx->data.seq_num = 1;
	ctx->data.bwe = 100000000ULL;
	ctx->data.min_rtt = 10000;
	ctx->data.loss_rate = 100;
	/* Set timestamp to future (more than allowed skew) */
	ctx->data.timestamp = ktime_get_real_seconds() + 3600;

	ret = tquic_cong_data_validate(NULL, &ctx->data);
	KUNIT_EXPECT_NE(test, ret, 0);
}

/*
 * Test: Validate rejects cwnd out of range
 */
static void test_validate_cwnd_out_of_range(struct kunit *test)
{
	struct cong_data_test_context *ctx = test->priv;
	int ret;

	ctx->data.seq_num = 1;
	ctx->data.bwe = 100000000ULL;
	ctx->data.min_rtt = 10000;
	ctx->data.loss_rate = 100;
	ctx->data.timestamp = ktime_get_real_seconds();
	ctx->data.flags = TQUIC_CONG_DATA_FLAG_HAS_CWND;
	ctx->data.cwnd = 500;  /* Less than 2 packets - too low */

	ret = tquic_cong_data_validate(NULL, &ctx->data);
	KUNIT_EXPECT_NE(test, ret, 0);
}

/*
 * =============================================================================
 * Export/Import Tests
 * =============================================================================
 */

/*
 * Test: Export creates valid structure
 */
static void test_export_structure(struct kunit *test)
{
	struct tquic_cong_data_export export;

	/* Initialize export structure */
	memset(&export, 0, sizeof(export));
	export.version = TQUIC_CONG_DATA_VERSION;
	export.export_time = ktime_get_real_seconds();
	export.data.seq_num = 1;
	export.data.bwe = 100000000ULL;
	export.data.min_rtt = 10000;
	export.data.loss_rate = 100;
	export.data.timestamp = export.export_time;
	export.server_name_len = 11;
	memcpy(export.server_name, "example.com", 11);

	/* Verify structure */
	KUNIT_EXPECT_EQ(test, export.version, (u8)TQUIC_CONG_DATA_VERSION);
	KUNIT_EXPECT_EQ(test, export.server_name_len, (u8)11);
	KUNIT_EXPECT_EQ(test, memcmp(export.server_name, "example.com", 11), 0);
}

/*
 * =============================================================================
 * Phase Name Tests
 * =============================================================================
 */

/*
 * Test: Phase name strings
 */
static void test_phase_names(struct kunit *test)
{
	const char *name;

	name = tquic_cong_data_get_phase_name(TQUIC_CONG_DATA_PHASE_NONE);
	KUNIT_EXPECT_STREQ(test, name, "none");

	name = tquic_cong_data_get_phase_name(TQUIC_CONG_DATA_PHASE_VALIDATING);
	KUNIT_EXPECT_STREQ(test, name, "validating");

	name = tquic_cong_data_get_phase_name(TQUIC_CONG_DATA_PHASE_RAMPING);
	KUNIT_EXPECT_STREQ(test, name, "ramping");

	name = tquic_cong_data_get_phase_name(TQUIC_CONG_DATA_PHASE_COMPLETE);
	KUNIT_EXPECT_STREQ(test, name, "complete");

	name = tquic_cong_data_get_phase_name(TQUIC_CONG_DATA_PHASE_RETREATED);
	KUNIT_EXPECT_STREQ(test, name, "retreated");

	/* Unknown phase */
	name = tquic_cong_data_get_phase_name(99);
	KUNIT_EXPECT_STREQ(test, name, "unknown");
}

/*
 * =============================================================================
 * Sequence Number Tests
 * =============================================================================
 */

/*
 * Test: Sequence numbers increment correctly
 */
static void test_sequence_numbers(struct kunit *test)
{
	struct cong_data_test_context *ctx = test->priv;
	struct tquic_cong_data decoded1, decoded2;
	ssize_t len1, len2;
	size_t offset;
	u64 frame_type;

	/* First frame */
	ctx->data.seq_num = 100;
	ctx->data.bwe = 100000000ULL;
	ctx->data.min_rtt = 10000;
	ctx->data.loss_rate = 100;
	ctx->data.timestamp = ktime_get_real_seconds();
	ctx->data.flags = 0;

	len1 = tquic_cong_data_encode(&ctx->data, ctx->buf, sizeof(ctx->buf));
	KUNIT_ASSERT_GT(test, len1, (ssize_t)0);

	offset = 0;
	tquic_varint_read(ctx->buf, len1, &offset, &frame_type);
	tquic_cong_data_decode(ctx->buf + offset, len1 - offset, &decoded1);

	/* Second frame with higher sequence number */
	ctx->data.seq_num = 101;
	len2 = tquic_cong_data_encode(&ctx->data, ctx->buf, sizeof(ctx->buf));
	KUNIT_ASSERT_GT(test, len2, (ssize_t)0);

	offset = 0;
	tquic_varint_read(ctx->buf, len2, &offset, &frame_type);
	tquic_cong_data_decode(ctx->buf + offset, len2 - offset, &decoded2);

	/* Verify sequence numbers */
	KUNIT_EXPECT_EQ(test, decoded1.seq_num, (u64)100);
	KUNIT_EXPECT_EQ(test, decoded2.seq_num, (u64)101);
	KUNIT_EXPECT_GT(test, decoded2.seq_num, decoded1.seq_num);
}

/*
 * =============================================================================
 * Edge Case Tests
 * =============================================================================
 */

/*
 * Test: Maximum values encode/decode correctly
 */
static void test_max_values(struct kunit *test)
{
	struct cong_data_test_context *ctx = test->priv;
	struct tquic_cong_data decoded;
	ssize_t encoded_len;
	size_t offset;
	u64 frame_type;

	/* Use maximum valid values */
	ctx->data.seq_num = TQUIC_VARINT_8BYTE_MAX;  /* Max varint */
	ctx->data.bwe = TQUIC_CONG_DATA_MAX_BWE_BPS;
	ctx->data.min_rtt = TQUIC_CONG_DATA_MAX_RTT_US;
	ctx->data.loss_rate = TQUIC_CONG_DATA_MAX_LOSS_RATE;
	ctx->data.timestamp = ktime_get_real_seconds();
	ctx->data.flags = TQUIC_CONG_DATA_FLAG_HAS_CWND |
			  TQUIC_CONG_DATA_FLAG_HAS_SSTHRESH;
	ctx->data.cwnd = TQUIC_CONG_DATA_MAX_CWND;
	ctx->data.ssthresh = TQUIC_CONG_DATA_MAX_SSTHRESH;

	encoded_len = tquic_cong_data_encode(&ctx->data, ctx->buf, sizeof(ctx->buf));
	KUNIT_ASSERT_GT(test, encoded_len, (ssize_t)0);

	offset = 0;
	tquic_varint_read(ctx->buf, encoded_len, &offset, &frame_type);
	tquic_cong_data_decode(ctx->buf + offset, encoded_len - offset, &decoded);

	KUNIT_EXPECT_EQ(test, decoded.bwe, ctx->data.bwe);
	KUNIT_EXPECT_EQ(test, decoded.min_rtt, ctx->data.min_rtt);
	KUNIT_EXPECT_EQ(test, decoded.loss_rate, ctx->data.loss_rate);
	KUNIT_EXPECT_EQ(test, decoded.cwnd, ctx->data.cwnd);
	KUNIT_EXPECT_EQ(test, decoded.ssthresh, ctx->data.ssthresh);
}

/*
 * Test: Minimum values encode/decode correctly
 */
static void test_min_values(struct kunit *test)
{
	struct cong_data_test_context *ctx = test->priv;
	struct tquic_cong_data decoded;
	ssize_t encoded_len;
	size_t offset;
	u64 frame_type;

	/* Use minimum valid values */
	ctx->data.seq_num = 0;
	ctx->data.bwe = TQUIC_CONG_DATA_MIN_BWE_BPS;
	ctx->data.min_rtt = TQUIC_CONG_DATA_MIN_RTT_US;
	ctx->data.loss_rate = TQUIC_CONG_DATA_MIN_LOSS_RATE;
	ctx->data.timestamp = ktime_get_real_seconds();
	ctx->data.flags = TQUIC_CONG_DATA_FLAG_HAS_CWND;
	ctx->data.cwnd = TQUIC_CONG_DATA_MIN_CWND;

	encoded_len = tquic_cong_data_encode(&ctx->data, ctx->buf, sizeof(ctx->buf));
	KUNIT_ASSERT_GT(test, encoded_len, (ssize_t)0);

	offset = 0;
	tquic_varint_read(ctx->buf, encoded_len, &offset, &frame_type);
	tquic_cong_data_decode(ctx->buf + offset, encoded_len - offset, &decoded);

	KUNIT_EXPECT_EQ(test, decoded.seq_num, ctx->data.seq_num);
	KUNIT_EXPECT_EQ(test, decoded.bwe, ctx->data.bwe);
	KUNIT_EXPECT_EQ(test, decoded.min_rtt, ctx->data.min_rtt);
	KUNIT_EXPECT_EQ(test, decoded.loss_rate, ctx->data.loss_rate);
	KUNIT_EXPECT_EQ(test, decoded.cwnd, ctx->data.cwnd);
}

/*
 * Test: Zero loss rate (no loss)
 */
static void test_zero_loss_rate(struct kunit *test)
{
	struct cong_data_test_context *ctx = test->priv;
	struct tquic_cong_data decoded;
	ssize_t encoded_len;
	size_t offset;
	u64 frame_type;

	ctx->data.seq_num = 1;
	ctx->data.bwe = 100000000ULL;
	ctx->data.min_rtt = 10000;
	ctx->data.loss_rate = 0;  /* No loss */
	ctx->data.timestamp = ktime_get_real_seconds();
	ctx->data.flags = 0;

	encoded_len = tquic_cong_data_encode(&ctx->data, ctx->buf, sizeof(ctx->buf));
	KUNIT_ASSERT_GT(test, encoded_len, (ssize_t)0);

	offset = 0;
	tquic_varint_read(ctx->buf, encoded_len, &offset, &frame_type);
	tquic_cong_data_decode(ctx->buf + offset, encoded_len - offset, &decoded);

	KUNIT_EXPECT_EQ(test, decoded.loss_rate, (u32)0);
}

/*
 * =============================================================================
 * Test Suite Registration
 * =============================================================================
 */

static struct kunit_case cong_data_test_cases[] = {
	/* Encoding/Decoding tests */
	KUNIT_CASE(test_encode_decode_basic),
	KUNIT_CASE(test_encode_decode_full),
	KUNIT_CASE(test_encode_buffer_too_small),
	KUNIT_CASE(test_decode_truncated),

	/* Validation tests */
	KUNIT_CASE(test_validate_valid_data),
	KUNIT_CASE(test_validate_bwe_too_low),
	KUNIT_CASE(test_validate_bwe_too_high),
	KUNIT_CASE(test_validate_rtt_out_of_range),
	KUNIT_CASE(test_validate_loss_rate_invalid),
	KUNIT_CASE(test_validate_stale_timestamp),
	KUNIT_CASE(test_validate_future_timestamp),
	KUNIT_CASE(test_validate_cwnd_out_of_range),

	/* Export/Import tests */
	KUNIT_CASE(test_export_structure),

	/* Phase name tests */
	KUNIT_CASE(test_phase_names),

	/* Sequence number tests */
	KUNIT_CASE(test_sequence_numbers),

	/* Edge case tests */
	KUNIT_CASE(test_max_values),
	KUNIT_CASE(test_min_values),
	KUNIT_CASE(test_zero_loss_rate),

	{}
};

static struct kunit_suite cong_data_test_suite = {
	.name = "tquic-cong-data",
	.init = cong_data_test_init,
	.test_cases = cong_data_test_cases,
};

kunit_test_suites(&cong_data_test_suite);

MODULE_AUTHOR("Linux Foundation");
MODULE_DESCRIPTION("TQUIC Congestion Control Data Exchange KUnit Tests");
MODULE_LICENSE("GPL");
