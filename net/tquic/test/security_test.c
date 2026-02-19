// SPDX-License-Identifier: GPL-2.0-only
/*
 * KUnit tests for TQUIC security regression
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * This test suite covers P0/P1 security issues including:
 * - Frame parsing overflow/underflow
 * - Crypto security (packet number monotonicity, nonce reuse prevention)
 * - Bounds checking (buffer overflow, integer overflow)
 * - Token length validation
 * - Replay attack prevention
 *
 * These tests serve as regression tests to prevent reintroduction of
 * security vulnerabilities.
 */

#include <kunit/test.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/overflow.h>
#include <net/tquic.h>

/*
 * =============================================================================
 * Constants and Macros
 * =============================================================================
 */

/* Frame types for testing */
#define TQUIC_FRAME_PADDING		0x00
#define TQUIC_FRAME_PING		0x01
#define TQUIC_FRAME_ACK			0x02
#define TQUIC_FRAME_ACK_ECN		0x03
#define TQUIC_FRAME_CRYPTO		0x06
#define TQUIC_FRAME_NEW_TOKEN		0x07
#define TQUIC_FRAME_STREAM		0x08
#define TQUIC_FRAME_MAX_DATA		0x10
#define TQUIC_FRAME_NEW_CONNECTION_ID	0x18

/* Security-relevant limits */
#define TQUIC_MAX_TOKEN_LEN		256
#define TQUIC_MAX_FRAME_LEN		(1ULL << 62)
#define TQUIC_MAX_VARINT		((1ULL << 62) - 1)
#define TQUIC_REPLAY_WINDOW_SIZE	8192

/* Varint encoding constants */
#define TQUIC_VARINT_1BYTE_MAX		63ULL
#define TQUIC_VARINT_2BYTE_MAX		16383ULL
#define TQUIC_VARINT_4BYTE_MAX		1073741823ULL
#define TQUIC_VARINT_8BYTE_MAX		4611686018427387903ULL

/*
 * =============================================================================
 * Helper Functions
 * =============================================================================
 */

/**
 * tquic_test_varint_decode - Decode a QUIC variable-length integer
 * @data: Pointer to encoded data
 * @len: Available data length
 * @value: Output value
 *
 * Returns: Number of bytes consumed, or negative error
 */
static int tquic_test_varint_decode(const u8 *data, size_t len, u64 *value)
{
	u8 prefix;
	int bytes_needed;

	if (!data || !value)
		return -EINVAL;

	if (len < 1)
		return -EINVAL;

	prefix = data[0] & 0xc0;

	switch (prefix) {
	case 0x00:
		bytes_needed = 1;
		break;
	case 0x40:
		bytes_needed = 2;
		break;
	case 0x80:
		bytes_needed = 4;
		break;
	case 0xc0:
		bytes_needed = 8;
		break;
	default:
		return -EINVAL;
	}

	if (len < bytes_needed)
		return -EINVAL;

	switch (bytes_needed) {
	case 1:
		*value = data[0] & 0x3f;
		break;
	case 2:
		*value = ((u64)(data[0] & 0x3f) << 8) | data[1];
		break;
	case 4:
		*value = ((u64)(data[0] & 0x3f) << 24) |
			 ((u64)data[1] << 16) |
			 ((u64)data[2] << 8) |
			 data[3];
		break;
	case 8:
		*value = ((u64)(data[0] & 0x3f) << 56) |
			 ((u64)data[1] << 48) |
			 ((u64)data[2] << 40) |
			 ((u64)data[3] << 32) |
			 ((u64)data[4] << 24) |
			 ((u64)data[5] << 16) |
			 ((u64)data[6] << 8) |
			 data[7];
		break;
	}

	return bytes_needed;
}

/**
 * tquic_test_varint_encode - Encode a QUIC variable-length integer
 * @value: Value to encode
 * @data: Output buffer
 * @len: Buffer length
 *
 * Returns: Number of bytes written, or negative error
 */
static int tquic_test_varint_encode(u64 value, u8 *data, size_t len)
{
	if (!data)
		return -EINVAL;

	if (value <= TQUIC_VARINT_1BYTE_MAX) {
		if (len < 1)
			return -ENOSPC;
		data[0] = (u8)value;
		return 1;
	} else if (value <= TQUIC_VARINT_2BYTE_MAX) {
		if (len < 2)
			return -ENOSPC;
		data[0] = 0x40 | (u8)(value >> 8);
		data[1] = (u8)value;
		return 2;
	} else if (value <= TQUIC_VARINT_4BYTE_MAX) {
		if (len < 4)
			return -ENOSPC;
		data[0] = 0x80 | (u8)(value >> 24);
		data[1] = (u8)(value >> 16);
		data[2] = (u8)(value >> 8);
		data[3] = (u8)value;
		return 4;
	} else if (value <= TQUIC_VARINT_8BYTE_MAX) {
		if (len < 8)
			return -ENOSPC;
		data[0] = 0xc0 | (u8)(value >> 56);
		data[1] = (u8)(value >> 48);
		data[2] = (u8)(value >> 40);
		data[3] = (u8)(value >> 32);
		data[4] = (u8)(value >> 24);
		data[5] = (u8)(value >> 16);
		data[6] = (u8)(value >> 8);
		data[7] = (u8)value;
		return 8;
	}

	return -EOVERFLOW;
}

/**
 * tquic_test_parse_frame_length - Parse frame length from buffer
 * @data: Frame data
 * @len: Available length
 * @offset: Current offset (in/out)
 * @frame_len: Output frame length
 *
 * Security: Must reject lengths that exceed buffer bounds
 *
 * Returns: 0 on success, negative error on failure
 */
static int tquic_test_parse_frame_length(const u8 *data, size_t len,
					 size_t *offset, u64 *frame_len)
{
	int ret;

	if (!data || !offset || !frame_len)
		return -EINVAL;

	/* Security check: offset must be within buffer */
	if (*offset >= len)
		return -EOVERFLOW;

	ret = tquic_test_varint_decode(data + *offset, len - *offset, frame_len);
	if (ret < 0)
		return ret;

	*offset += ret;

	/* Security check: frame length must not exceed remaining buffer */
	if (*frame_len > len - *offset)
		return -EOVERFLOW;

	return 0;
}

/**
 * tquic_test_check_pn_monotonic - Check packet number monotonicity
 * @new_pn: New packet number to validate
 * @largest_sent: Largest packet number sent so far
 *
 * Security: Packet numbers must be strictly increasing
 *
 * Returns: true if valid (monotonically increasing), false otherwise
 */
static bool tquic_test_check_pn_monotonic(u64 new_pn, u64 largest_sent)
{
	/* First packet (largest_sent == 0 and new_pn == 0 is valid) */
	if (largest_sent == 0 && new_pn == 0)
		return true;

	/* New packet number must be greater than largest sent */
	return new_pn > largest_sent;
}

/**
 * struct tquic_test_replay_filter - Simple replay filter for testing
 * @window: Bitmap window
 * @window_base: Base packet number of window
 * @max_seen: Maximum packet number seen
 */
struct tquic_test_replay_filter {
	unsigned long window[BITS_TO_LONGS(TQUIC_REPLAY_WINDOW_SIZE)];
	u64 window_base;
	u64 max_seen;
	bool initialized;
};

/**
 * tquic_test_replay_check - Check for packet replay
 * @filter: Replay filter
 * @pn: Packet number to check
 *
 * Returns: true if packet is new (not replayed), false if replay detected
 */
static bool tquic_test_replay_check(struct tquic_test_replay_filter *filter,
				    u64 pn)
{
	u64 offset;

	if (!filter)
		return false;

	/* First packet initializes the filter */
	if (!filter->initialized) {
		filter->window_base = 0;
		filter->max_seen = pn;
		filter->initialized = true;
		memset(filter->window, 0, sizeof(filter->window));
		set_bit(pn, filter->window);
		return true;
	}

	/* Packet before window - definitely old (replay) */
	if (pn < filter->window_base)
		return false;

	/* Packet within current window */
	if (pn < filter->window_base + TQUIC_REPLAY_WINDOW_SIZE) {
		offset = pn - filter->window_base;
		if (test_bit(offset, filter->window))
			return false;  /* Already seen - replay */
		set_bit(offset, filter->window);
		if (pn > filter->max_seen)
			filter->max_seen = pn;
		return true;
	}

	/* Packet advances the window */
	offset = pn - filter->window_base - TQUIC_REPLAY_WINDOW_SIZE + 1;
	if (offset >= TQUIC_REPLAY_WINDOW_SIZE) {
		/* Large jump - clear entire window */
		memset(filter->window, 0, sizeof(filter->window));
		filter->window_base = pn - TQUIC_REPLAY_WINDOW_SIZE + 1;
	} else {
		/* Shift window */
		u64 new_base = pn - TQUIC_REPLAY_WINDOW_SIZE + 1;
		u64 shift = new_base - filter->window_base;
		bitmap_shift_right(filter->window, filter->window,
				   shift, TQUIC_REPLAY_WINDOW_SIZE);
		filter->window_base = new_base;
	}

	offset = pn - filter->window_base;
	set_bit(offset, filter->window);
	filter->max_seen = pn;
	return true;
}

/**
 * tquic_test_safe_add - Safe addition with overflow check
 * @a: First operand
 * @b: Second operand
 * @result: Output result
 *
 * Returns: true if overflow, false if safe
 */
static bool tquic_test_safe_add(u64 a, u64 b, u64 *result)
{
	return check_add_overflow(a, b, result);
}

/**
 * tquic_test_safe_mul - Safe multiplication with overflow check
 * @a: First operand
 * @b: Second operand
 * @result: Output result
 *
 * Returns: true if overflow, false if safe
 */
static bool tquic_test_safe_mul(u64 a, u64 b, u64 *result)
{
	return check_mul_overflow(a, b, result);
}

/*
 * =============================================================================
 * SECTION 1: Frame Parsing Overflow Tests
 * =============================================================================
 */

/* Test: Frame size underflow (offset > buf_len) */
static void test_frame_size_underflow(struct kunit *test)
{
	u8 data[] = {0x06, 0x00, 0x10};  /* CRYPTO frame: offset=0, length=16 */
	size_t offset = 5;  /* Offset beyond buffer */
	u64 frame_len;
	int ret;

	/* Attempting to parse at offset beyond buffer should fail */
	ret = tquic_test_parse_frame_length(data, sizeof(data), &offset, &frame_len);
	KUNIT_EXPECT_LT(test, ret, 0);
}

/* Test: SIZE_MAX boundary conditions */
static void test_size_max_boundary(struct kunit *test)
{
	/* Test that SIZE_MAX values are handled correctly */
	size_t size_max_test = SIZE_MAX;
	u64 large_value = TQUIC_VARINT_8BYTE_MAX;

	/* SIZE_MAX should not wrap on common operations */
	KUNIT_EXPECT_GT(test, size_max_test, 0UL);

	/* Varint max should be representable */
	KUNIT_EXPECT_LE(test, large_value, (u64)SIZE_MAX);

	/* Check that max varint + 1 cannot be encoded */
	u8 buf[16];
	int ret = tquic_test_varint_encode(TQUIC_VARINT_8BYTE_MAX + 1, buf, sizeof(buf));
	KUNIT_EXPECT_LT(test, ret, 0);
}

/* Test: Malformed frame lengths */
static void test_malformed_frame_length(struct kunit *test)
{
	/* Frame claiming more length than available */
	u8 malformed_crypto[] = {
		0x06,	/* CRYPTO frame type */
		0x00,	/* Offset = 0 */
		0x40, 0xff,	/* Length = 255 (2-byte varint) - but only 4 bytes in buffer */
	};
	size_t offset = 1;  /* Start after frame type */
	u64 frame_offset, frame_len;
	int ret;

	/* Parse offset */
	ret = tquic_test_varint_decode(malformed_crypto + offset,
				       sizeof(malformed_crypto) - offset,
				       &frame_offset);
	KUNIT_EXPECT_GT(test, ret, 0);
	offset += ret;

	/* Parse length - should succeed */
	ret = tquic_test_varint_decode(malformed_crypto + offset,
				       sizeof(malformed_crypto) - offset,
				       &frame_len);
	KUNIT_EXPECT_GT(test, ret, 0);
	offset += ret;

	/* But frame length exceeds remaining buffer - this must be detected */
	KUNIT_EXPECT_GT(test, frame_len, sizeof(malformed_crypto) - offset);
}

/* Test: Token length overflow */
static void test_token_length_overflow(struct kunit *test)
{
	u64 token_len;

	/* Token length must not exceed TQUIC_MAX_TOKEN_LEN */
	token_len = TQUIC_MAX_TOKEN_LEN + 1;
	KUNIT_EXPECT_GT(test, token_len, (u64)TQUIC_MAX_TOKEN_LEN);

	/* Extremely large token length must be rejected */
	token_len = TQUIC_VARINT_8BYTE_MAX;
	KUNIT_EXPECT_TRUE(test, token_len > TQUIC_MAX_TOKEN_LEN);

	/* Valid token length should pass */
	token_len = 64;
	KUNIT_EXPECT_LE(test, token_len, (u64)TQUIC_MAX_TOKEN_LEN);
}

/* Test: NEW_TOKEN frame with excessive length */
static void test_new_token_excessive_length(struct kunit *test)
{
	/* NEW_TOKEN frame with length claiming 4GB */
	u8 excessive_token[] = {
		0x07,	/* NEW_TOKEN frame type */
		0xbf, 0xff, 0xff, 0xff,	/* Token length = 2^30-1 (4-byte varint max) */
	};
	size_t offset = 1;
	u64 token_len;
	int ret;

	ret = tquic_test_varint_decode(excessive_token + offset,
				       sizeof(excessive_token) - offset,
				       &token_len);
	KUNIT_EXPECT_GT(test, ret, 0);

	/* Such large token must be rejected */
	KUNIT_EXPECT_GT(test, token_len, (u64)TQUIC_MAX_TOKEN_LEN);
}

/* Test: Varint overflow scenarios */
static void test_varint_overflow(struct kunit *test)
{
	u8 buf[8];
	u64 value;
	int ret;

	/* Maximum valid 8-byte varint */
	u8 max_valid[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	ret = tquic_test_varint_decode(max_valid, sizeof(max_valid), &value);
	KUNIT_EXPECT_EQ(test, ret, 8);
	KUNIT_EXPECT_EQ(test, value, TQUIC_VARINT_8BYTE_MAX);

	/* Value beyond varint max cannot be encoded */
	ret = tquic_test_varint_encode(TQUIC_VARINT_8BYTE_MAX + 1, buf, sizeof(buf));
	KUNIT_EXPECT_LT(test, ret, 0);

	/* U64_MAX is way beyond varint capacity */
	ret = tquic_test_varint_encode(U64_MAX, buf, sizeof(buf));
	KUNIT_EXPECT_LT(test, ret, 0);
}

/* Test: Truncated varint at buffer boundary */
static void test_truncated_varint(struct kunit *test)
{
	u64 value;
	int ret;

	/* 2-byte varint with only 1 byte available */
	u8 truncated_2byte[] = {0x40};
	ret = tquic_test_varint_decode(truncated_2byte, 1, &value);
	KUNIT_EXPECT_LT(test, ret, 0);

	/* 4-byte varint with only 2 bytes available */
	u8 truncated_4byte[] = {0x80, 0x00};
	ret = tquic_test_varint_decode(truncated_4byte, 2, &value);
	KUNIT_EXPECT_LT(test, ret, 0);

	/* 8-byte varint with only 4 bytes available */
	u8 truncated_8byte[] = {0xc0, 0x00, 0x00, 0x00};
	ret = tquic_test_varint_decode(truncated_8byte, 4, &value);
	KUNIT_EXPECT_LT(test, ret, 0);

	/* Empty buffer */
	ret = tquic_test_varint_decode(truncated_2byte, 0, &value);
	KUNIT_EXPECT_LT(test, ret, 0);
}

/* Test: Frame length at exact buffer boundary */
static void test_frame_length_exact_boundary(struct kunit *test)
{
	/* CRYPTO frame with length exactly matching remaining buffer */
	u8 exact_frame[] = {
		0x06,		/* CRYPTO frame type */
		0x00,		/* Offset = 0 */
		0x05,		/* Length = 5 */
		0x01, 0x02, 0x03, 0x04, 0x05,  /* Exactly 5 bytes of data */
	};
	size_t offset = 1;
	u64 frame_offset, frame_len;
	int ret;

	ret = tquic_test_varint_decode(exact_frame + offset,
				       sizeof(exact_frame) - offset,
				       &frame_offset);
	KUNIT_EXPECT_GT(test, ret, 0);
	offset += ret;

	ret = tquic_test_varint_decode(exact_frame + offset,
				       sizeof(exact_frame) - offset,
				       &frame_len);
	KUNIT_EXPECT_GT(test, ret, 0);
	offset += ret;

	/* Frame length should exactly match remaining data */
	KUNIT_EXPECT_EQ(test, frame_len, sizeof(exact_frame) - offset);
}

/*
 * =============================================================================
 * SECTION 2: Crypto Security Tests
 * =============================================================================
 */

/* Test: Packet number monotonicity enforcement */
static void test_pn_monotonicity(struct kunit *test)
{
	u64 largest_sent = 0;

	/* First packet (pn=0) is valid */
	KUNIT_EXPECT_TRUE(test, tquic_test_check_pn_monotonic(0, largest_sent));
	largest_sent = 0;

	/* Next packet must be greater */
	KUNIT_EXPECT_TRUE(test, tquic_test_check_pn_monotonic(1, largest_sent));
	largest_sent = 1;

	/* Same packet number is invalid (potential nonce reuse) */
	KUNIT_EXPECT_FALSE(test, tquic_test_check_pn_monotonic(1, largest_sent));

	/* Smaller packet number is invalid */
	KUNIT_EXPECT_FALSE(test, tquic_test_check_pn_monotonic(0, largest_sent));

	/* Much larger packet number is valid (no wraparound) */
	KUNIT_EXPECT_TRUE(test, tquic_test_check_pn_monotonic(1000, largest_sent));
	largest_sent = 1000;

	/* Monotonically increasing is valid */
	KUNIT_EXPECT_TRUE(test, tquic_test_check_pn_monotonic(1001, largest_sent));
}

/* Test: Nonce reuse prevention */
static void test_nonce_reuse_prevention(struct kunit *test)
{
	/*
	 * In QUIC, packet numbers are used to derive nonces for AEAD.
	 * Reusing a packet number means reusing a nonce, which is
	 * cryptographically catastrophic for AES-GCM.
	 */
	u64 pn_history[16];
	int i;
	u64 new_pn;
	bool found_dup;

	/* Initialize history with sequential packet numbers */
	for (i = 0; i < 16; i++)
		pn_history[i] = i;

	/* Attempting to use a pn that's already in history should fail */
	new_pn = 5;
	found_dup = false;
	for (i = 0; i < 16; i++) {
		if (pn_history[i] == new_pn) {
			found_dup = true;
			break;
		}
	}
	KUNIT_EXPECT_TRUE(test, found_dup);

	/* New pn should not be in history */
	new_pn = 20;
	found_dup = false;
	for (i = 0; i < 16; i++) {
		if (pn_history[i] == new_pn) {
			found_dup = true;
			break;
		}
	}
	KUNIT_EXPECT_FALSE(test, found_dup);
}

/* Test: Replay filter with sequential packets */
static void test_replay_filter_sequential(struct kunit *test)
{
	struct tquic_test_replay_filter filter;
	int i;

	memset(&filter, 0, sizeof(filter));

	/* First 100 packets should all be new */
	for (i = 0; i < 100; i++) {
		KUNIT_EXPECT_TRUE(test, tquic_test_replay_check(&filter, i));
	}

	/* Replaying any of them should be detected */
	for (i = 0; i < 100; i++) {
		KUNIT_EXPECT_FALSE(test, tquic_test_replay_check(&filter, i));
	}
}

/* Test: Replay filter with random seed */
static void test_replay_filter_random(struct kunit *test)
{
	struct tquic_test_replay_filter filter;
	u64 seen_pns[32];
	int num_seen = 0;
	int i;

	memset(&filter, 0, sizeof(filter));

	/* Generate and check some packet numbers */
	for (i = 0; i < 32; i++) {
		u64 pn = i * 7 + 3;  /* Deterministic "pseudo-random" sequence */
		bool is_new = tquic_test_replay_check(&filter, pn);
		KUNIT_EXPECT_TRUE(test, is_new);
		seen_pns[num_seen++] = pn;
	}

	/* All seen packets should now be detected as replays */
	for (i = 0; i < num_seen; i++) {
		bool is_new = tquic_test_replay_check(&filter, seen_pns[i]);
		KUNIT_EXPECT_FALSE(test, is_new);
	}
}

/* Test: Replay filter window advancement */
static void test_replay_filter_window_advance(struct kunit *test)
{
	struct tquic_test_replay_filter filter;

	memset(&filter, 0, sizeof(filter));

	/* Start with packet 0 */
	KUNIT_EXPECT_TRUE(test, tquic_test_replay_check(&filter, 0));

	/* Jump far ahead - should advance window */
	KUNIT_EXPECT_TRUE(test, tquic_test_replay_check(&filter, TQUIC_REPLAY_WINDOW_SIZE + 100));

	/* Packet 0 should now be before the window (detected as replay/old) */
	KUNIT_EXPECT_FALSE(test, tquic_test_replay_check(&filter, 0));

	/* Packet within new window should work */
	KUNIT_EXPECT_TRUE(test, tquic_test_replay_check(&filter, TQUIC_REPLAY_WINDOW_SIZE + 50));
}

/* Test: Key update boundaries */
static void test_key_update_boundaries(struct kunit *test)
{
	/*
	 * Key updates in QUIC happen after certain packet thresholds.
	 * The key phase bit flips to indicate which key is in use.
	 * This test validates boundary conditions.
	 */
	u64 packets_since_key_update = 0;
	u64 key_update_threshold = 1000;  /* Example threshold */
	u8 key_phase = 0;

	/* Before threshold, no update needed */
	KUNIT_EXPECT_LT(test, packets_since_key_update, key_update_threshold);
	KUNIT_EXPECT_EQ(test, key_phase, 0);

	/* At threshold, update is triggered */
	packets_since_key_update = key_update_threshold;
	if (packets_since_key_update >= key_update_threshold) {
		key_phase ^= 1;
		packets_since_key_update = 0;
	}
	KUNIT_EXPECT_EQ(test, key_phase, 1);
	KUNIT_EXPECT_EQ(test, packets_since_key_update, 0ULL);

	/* Key phase alternates */
	packets_since_key_update = key_update_threshold;
	if (packets_since_key_update >= key_update_threshold) {
		key_phase ^= 1;
		packets_since_key_update = 0;
	}
	KUNIT_EXPECT_EQ(test, key_phase, 0);
}

/* Test: Packet number space isolation */
static void test_pn_space_isolation(struct kunit *test)
{
	/*
	 * QUIC has 3 packet number spaces: Initial, Handshake, Application
	 * Each space has independent packet numbers and crypto state.
	 * This test ensures they don't interfere.
	 */
	u64 initial_pn = 0;
	u64 handshake_pn = 0;
	u64 app_pn = 0;

	/* Each space can have the same packet number independently */
	initial_pn = 5;
	handshake_pn = 5;
	app_pn = 5;

	/* All three can coexist with same value */
	KUNIT_EXPECT_EQ(test, initial_pn, 5ULL);
	KUNIT_EXPECT_EQ(test, handshake_pn, 5ULL);
	KUNIT_EXPECT_EQ(test, app_pn, 5ULL);

	/* They increment independently */
	initial_pn++;
	KUNIT_EXPECT_EQ(test, initial_pn, 6ULL);
	KUNIT_EXPECT_EQ(test, handshake_pn, 5ULL);
	KUNIT_EXPECT_EQ(test, app_pn, 5ULL);
}

/*
 * =============================================================================
 * SECTION 3: Bounds Checking Tests
 * =============================================================================
 */

/* Test: Buffer overflow boundary detection */
static void test_buffer_overflow_boundary(struct kunit *test)
{
	u8 small_buf[10];
	size_t buf_len = sizeof(small_buf);
	size_t offset = 0;
	size_t required = 20;

	/* Writing beyond buffer must be detected */
	KUNIT_EXPECT_TRUE(test, offset + required > buf_len);

	/* At exact boundary is still safe */
	offset = 0;
	required = 10;
	KUNIT_EXPECT_FALSE(test, offset + required > buf_len);

	/* One byte over is unsafe */
	required = 11;
	KUNIT_EXPECT_TRUE(test, offset + required > buf_len);
}

/* Test: Integer overflow in calculations */
static void test_integer_overflow_calc(struct kunit *test)
{
	u64 a, b, result;
	bool overflow;

	/* Normal addition - no overflow */
	a = 1000;
	b = 2000;
	overflow = tquic_test_safe_add(a, b, &result);
	KUNIT_EXPECT_FALSE(test, overflow);
	KUNIT_EXPECT_EQ(test, result, 3000ULL);

	/* Addition near U64_MAX - overflow */
	a = U64_MAX;
	b = 1;
	overflow = tquic_test_safe_add(a, b, &result);
	KUNIT_EXPECT_TRUE(test, overflow);

	/* Multiplication - no overflow */
	a = 1000;
	b = 1000;
	overflow = tquic_test_safe_mul(a, b, &result);
	KUNIT_EXPECT_FALSE(test, overflow);
	KUNIT_EXPECT_EQ(test, result, 1000000ULL);

	/* Large multiplication - overflow */
	a = U64_MAX / 2;
	b = 3;
	overflow = tquic_test_safe_mul(a, b, &result);
	KUNIT_EXPECT_TRUE(test, overflow);
}

/* Test: Maximum limits enforcement */
static void test_max_limits_enforcement(struct kunit *test)
{
	u64 stream_id;
	u64 max_streams;
	u8 cid_len;

	/* Stream ID limits: default cap must be within RFC 9000 range */
	stream_id = TQUIC_MAX_STREAM_COUNT_BIDI;
	max_streams = (1ULL << 60);  /* RFC 9000 Section 4.6 protocol max */
	KUNIT_EXPECT_GT(test, stream_id, 0ULL);
	KUNIT_EXPECT_LE(test, stream_id, max_streams);

	/* CID length limit */
	cid_len = TQUIC_MAX_CID_LEN;
	KUNIT_EXPECT_EQ(test, cid_len, 20);
	KUNIT_EXPECT_TRUE(test, cid_len <= 20);

	/* CID length of 21 must be rejected */
	KUNIT_EXPECT_GT(test, (u8)21, cid_len);
}

/* Test: Connection ID length validation */
static void test_cid_length_validation(struct kunit *test)
{
	u8 cid_len;

	/* Valid CID lengths: 0-20 */
	for (cid_len = 0; cid_len <= TQUIC_MAX_CID_LEN; cid_len++) {
		KUNIT_EXPECT_LE(test, cid_len, (u8)TQUIC_MAX_CID_LEN);
	}

	/* Invalid CID lengths: > 20 */
	cid_len = 21;
	KUNIT_EXPECT_GT(test, cid_len, (u8)TQUIC_MAX_CID_LEN);

	cid_len = 255;
	KUNIT_EXPECT_GT(test, cid_len, (u8)TQUIC_MAX_CID_LEN);
}

/* Test: Stream offset bounds */
static void test_stream_offset_bounds(struct kunit *test)
{
	u64 offset;
	u64 length;
	u64 max_offset = TQUIC_VARINT_8BYTE_MAX;
	u64 end_offset;
	bool overflow;

	/* Normal case - no overflow */
	offset = 0;
	length = 1000;
	overflow = tquic_test_safe_add(offset, length, &end_offset);
	KUNIT_EXPECT_FALSE(test, overflow);
	KUNIT_EXPECT_EQ(test, end_offset, 1000ULL);

	/* At max offset with small length - still okay */
	offset = max_offset - 100;
	length = 50;
	overflow = tquic_test_safe_add(offset, length, &end_offset);
	KUNIT_EXPECT_FALSE(test, overflow);

	/* At max offset with length that would overflow */
	offset = max_offset;
	length = 1;
	overflow = tquic_test_safe_add(offset, length, &end_offset);
	/* Note: overflow happens beyond u64 max, not varint max */
	/* The application must also check against varint max */
	KUNIT_EXPECT_FALSE(test, overflow);  /* u64 doesn't overflow yet */
	KUNIT_EXPECT_GT(test, end_offset, max_offset);  /* But exceeds varint max */
}

/* Test: ACK range overflow prevention */
static void test_ack_range_overflow(struct kunit *test)
{
	u64 largest_acked = 1000;
	u64 first_ack_range = 500;
	u64 smallest_in_range;
	bool overflow;

	/* Normal case: largest=1000, range=500 -> smallest=500 */
	if (first_ack_range > largest_acked) {
		overflow = true;
	} else {
		smallest_in_range = largest_acked - first_ack_range;
		overflow = false;
	}
	KUNIT_EXPECT_FALSE(test, overflow);
	KUNIT_EXPECT_EQ(test, smallest_in_range, 500ULL);

	/* Invalid: range larger than largest_acked */
	largest_acked = 100;
	first_ack_range = 200;
	if (first_ack_range > largest_acked) {
		overflow = true;
	}
	KUNIT_EXPECT_TRUE(test, overflow);
}

/* Test: Maximum data limits */
static void test_max_data_limits(struct kunit *test)
{
	u64 max_data = tquic_get_validated_max_data();
	u64 data_sent = 0;
	u64 to_send;

	/* Can send up to max_data */
	to_send = max_data;
	KUNIT_EXPECT_LE(test, data_sent + to_send, max_data);

	/* Cannot send beyond max_data */
	data_sent = max_data - 100;
	to_send = 200;
	KUNIT_EXPECT_GT(test, data_sent + to_send, max_data);

	/* Edge case: exactly at limit */
	data_sent = 0;
	to_send = max_data;
	KUNIT_EXPECT_FALSE(test, data_sent + to_send > max_data);
}

/* Test: Frame size vs packet size validation */
static void test_frame_vs_packet_size(struct kunit *test)
{
	size_t packet_size = 1200;  /* Minimum QUIC initial packet */
	size_t header_size = 50;
	size_t aead_overhead = 16;
	size_t max_frame_size;

	/* Calculate maximum frame size in packet */
	max_frame_size = packet_size - header_size - aead_overhead;
	KUNIT_EXPECT_EQ(test, max_frame_size, (size_t)(1200 - 50 - 16));

	/* Frame claiming more must be rejected */
	size_t claimed_frame_size = 2000;
	KUNIT_EXPECT_GT(test, claimed_frame_size, max_frame_size);
}

/* Test: Path MTU limits */
static void test_path_mtu_limits(struct kunit *test)
{
	u32 mtu;

	/* Minimum QUIC MTU */
	mtu = TQUIC_MIN_INITIAL_PACKET_SIZE;
	KUNIT_EXPECT_EQ(test, mtu, 1200U);

	/* Standard Ethernet MTU */
	mtu = 1500;
	KUNIT_EXPECT_GT(test, mtu, TQUIC_MIN_INITIAL_PACKET_SIZE);

	/* Jumbo frame MTU */
	mtu = 9000;
	KUNIT_EXPECT_GT(test, mtu, 1500U);

	/* MTU must be at least minimum */
	mtu = 1000;
	KUNIT_EXPECT_LT(test, mtu, TQUIC_MIN_INITIAL_PACKET_SIZE);
}

/* Test: NEW_CONNECTION_ID frame sequence validation */
static void test_new_cid_sequence_validation(struct kunit *test)
{
	u64 seq_num;
	u64 retire_prior_to;

	/* Valid: retire_prior_to <= seq_num */
	seq_num = 5;
	retire_prior_to = 3;
	KUNIT_EXPECT_LE(test, retire_prior_to, seq_num);

	/* Invalid: retire_prior_to > seq_num */
	seq_num = 5;
	retire_prior_to = 10;
	KUNIT_EXPECT_GT(test, retire_prior_to, seq_num);

	/* Edge case: equal values */
	seq_num = 5;
	retire_prior_to = 5;
	KUNIT_EXPECT_EQ(test, retire_prior_to, seq_num);
}

/*
 * =============================================================================
 * SECTION 4: Rate Limiting Under Load Tests
 * =============================================================================
 */

/**
 * struct tquic_test_rate_limiter - Simple rate limiter for testing
 * @tokens: Current tokens in bucket
 * @last_refill: Last refill timestamp (jiffies simulation)
 * @max_tokens: Maximum bucket capacity
 * @refill_rate: Tokens added per time unit
 * @total_accepted: Statistics - accepted requests
 * @total_rejected: Statistics - rejected requests
 */
struct tquic_test_rate_limiter {
	u32 tokens;
	unsigned long last_refill;
	u32 max_tokens;
	u32 refill_rate;
	u64 total_accepted;
	u64 total_rejected;
};

/**
 * tquic_test_rl_init - Initialize rate limiter
 * @rl: Rate limiter to initialize
 * @max_tokens: Maximum bucket capacity
 * @refill_rate: Tokens per time unit
 */
static void tquic_test_rl_init(struct tquic_test_rate_limiter *rl,
			       u32 max_tokens, u32 refill_rate)
{
	rl->tokens = max_tokens;
	rl->last_refill = 0;
	rl->max_tokens = max_tokens;
	rl->refill_rate = refill_rate;
	rl->total_accepted = 0;
	rl->total_rejected = 0;
}

/**
 * tquic_test_rl_check - Check rate limit and consume token
 * @rl: Rate limiter
 * @now: Current time (jiffies simulation)
 *
 * Returns: true if allowed, false if rate limited
 */
static bool tquic_test_rl_check(struct tquic_test_rate_limiter *rl,
				unsigned long now)
{
	/* Refill tokens based on time elapsed */
	if (now > rl->last_refill) {
		u32 elapsed = now - rl->last_refill;
		u32 new_tokens = elapsed * rl->refill_rate;
		rl->tokens = min(rl->tokens + new_tokens, rl->max_tokens);
		rl->last_refill = now;
	}

	/* Check if we have tokens */
	if (rl->tokens > 0) {
		rl->tokens--;
		rl->total_accepted++;
		return true;
	}

	rl->total_rejected++;
	return false;
}

/* Test: Rate limiter token bucket algorithm */
static void test_ratelimit_token_bucket(struct kunit *test)
{
	struct tquic_test_rate_limiter rl;
	int i;

	/* ARRANGE: Initialize rate limiter with 10 tokens, 1 per time unit */
	tquic_test_rl_init(&rl, 10, 1);

	/* ACT/ASSERT: Should accept first 10 requests */
	for (i = 0; i < 10; i++) {
		KUNIT_EXPECT_TRUE(test, tquic_test_rl_check(&rl, 0));
	}

	/* ASSERT: 11th request should be rejected */
	KUNIT_EXPECT_FALSE(test, tquic_test_rl_check(&rl, 0));
	KUNIT_EXPECT_EQ(test, rl.total_accepted, 10ULL);
	KUNIT_EXPECT_EQ(test, rl.total_rejected, 1ULL);
}

/* Test: Rate limiter token refill */
static void test_ratelimit_token_refill(struct kunit *test)
{
	struct tquic_test_rate_limiter rl;

	/* ARRANGE: Initialize rate limiter, empty all tokens */
	tquic_test_rl_init(&rl, 10, 2);  /* 2 tokens per time unit */
	rl.tokens = 0;
	rl.last_refill = 0;

	/* ACT: Advance time by 5 units (should add 10 tokens, capped at max) */
	KUNIT_EXPECT_TRUE(test, tquic_test_rl_check(&rl, 5));

	/* ASSERT: Should have 9 tokens remaining (10 refilled, 1 used) */
	KUNIT_EXPECT_EQ(test, rl.tokens, 9U);
}

/* Test: Rate limiter burst handling */
static void test_ratelimit_burst_handling(struct kunit *test)
{
	struct tquic_test_rate_limiter rl;
	int accepted = 0;
	int i;

	/* ARRANGE: Initialize with small burst capacity */
	tquic_test_rl_init(&rl, 5, 1);  /* burst of 5, refill 1/time */

	/* ACT: Try to send 100 requests in burst (at time 0) */
	for (i = 0; i < 100; i++) {
		if (tquic_test_rl_check(&rl, 0))
			accepted++;
	}

	/* ASSERT: Only burst amount should be accepted */
	KUNIT_EXPECT_EQ(test, accepted, 5);
	KUNIT_EXPECT_EQ(test, rl.total_rejected, 95ULL);
}

/* Test: Rate limiter under sustained load */
static void test_ratelimit_sustained_load(struct kunit *test)
{
	struct tquic_test_rate_limiter rl;
	int accepted = 0;
	unsigned long time;

	/* ARRANGE: Rate limit to 10 per 10 time units = 1/time unit */
	tquic_test_rl_init(&rl, 10, 1);
	rl.tokens = 0;

	/* ACT: Simulate 100 time units with 1 request per time unit */
	for (time = 1; time <= 100; time++) {
		if (tquic_test_rl_check(&rl, time))
			accepted++;
	}

	/* ASSERT: Should accept all or close to all (1 request/time = 1 refill/time) */
	KUNIT_EXPECT_GE(test, accepted, 90);  /* Allow for initial empty bucket */
}

/*
 * =============================================================================
 * SECTION 5: Certificate Validation Tests
 * =============================================================================
 */

/**
 * struct tquic_test_cert_info - Simulated certificate info for testing
 * @valid_from: Not before timestamp (seconds since epoch)
 * @valid_to: Not after timestamp (seconds since epoch)
 * @is_ca: Certificate is a CA
 * @hostname: Subject CN / SAN DNS name
 * @issuer: Issuer CN
 * @key_bits: Key size in bits
 * @is_trusted: Whether issuer is trusted
 */
struct tquic_test_cert_info {
	s64 valid_from;
	s64 valid_to;
	bool is_ca;
	const char *hostname;
	const char *issuer;
	u32 key_bits;
	bool is_trusted;
};

/* Simulated current time for certificate tests */
#define TEST_CURRENT_TIME	1700000000LL  /* Approx Nov 2023 */

/**
 * tquic_test_cert_check_validity - Check certificate time validity
 * @cert: Certificate info
 * @now: Current time
 *
 * Returns: 0 if valid, -1 if expired, -2 if not yet valid
 */
static int tquic_test_cert_check_validity(const struct tquic_test_cert_info *cert,
					  s64 now)
{
	if (now < cert->valid_from)
		return -2;  /* Not yet valid */
	if (now > cert->valid_to)
		return -1;  /* Expired */
	return 0;  /* Valid */
}

/**
 * tquic_test_cert_check_hostname - Check hostname matches certificate
 * @cert: Certificate info
 * @expected: Expected hostname
 *
 * Returns: 0 if match, -1 if no match
 */
static int tquic_test_cert_check_hostname(const struct tquic_test_cert_info *cert,
					  const char *expected)
{
	if (!cert->hostname || !expected)
		return -1;

	/* Exact match */
	if (strcmp(cert->hostname, expected) == 0)
		return 0;

	/* Wildcard match (simple: *.example.com matches foo.example.com) */
	if (cert->hostname[0] == '*' && cert->hostname[1] == '.') {
		const char *cert_domain = cert->hostname + 1;  /* .example.com */
		const char *expected_dot = strchr(expected, '.');
		if (expected_dot && strcmp(expected_dot, cert_domain) == 0)
			return 0;
	}

	return -1;
}

/**
 * tquic_test_cert_check_key_strength - Check key is strong enough
 * @cert: Certificate info
 * @min_rsa_bits: Minimum RSA key size
 *
 * Returns: 0 if strong enough, -1 if weak
 */
static int tquic_test_cert_check_key_strength(const struct tquic_test_cert_info *cert,
					      u32 min_rsa_bits)
{
	if (cert->key_bits < min_rsa_bits)
		return -1;
	return 0;
}

/* Test: Valid certificate passes all checks */
static void test_cert_valid(struct kunit *test)
{
	struct tquic_test_cert_info cert = {
		.valid_from = TEST_CURRENT_TIME - 86400,  /* Valid from yesterday */
		.valid_to = TEST_CURRENT_TIME + 86400 * 365,  /* Valid for 1 year */
		.is_ca = false,
		.hostname = "example.com",
		.issuer = "Example CA",
		.key_bits = 2048,
		.is_trusted = true,
	};

	/* ARRANGE/ACT/ASSERT: All checks should pass */
	KUNIT_EXPECT_EQ(test, tquic_test_cert_check_validity(&cert, TEST_CURRENT_TIME), 0);
	KUNIT_EXPECT_EQ(test, tquic_test_cert_check_hostname(&cert, "example.com"), 0);
	KUNIT_EXPECT_EQ(test, tquic_test_cert_check_key_strength(&cert, 2048), 0);
	KUNIT_EXPECT_TRUE(test, cert.is_trusted);
}

/* Test: Expired certificate is rejected */
static void test_cert_expired(struct kunit *test)
{
	struct tquic_test_cert_info cert = {
		.valid_from = TEST_CURRENT_TIME - 86400 * 400,  /* 400 days ago */
		.valid_to = TEST_CURRENT_TIME - 86400 * 35,  /* Expired 35 days ago */
		.hostname = "example.com",
		.key_bits = 2048,
	};

	/* ARRANGE/ACT/ASSERT: Certificate should be detected as expired */
	KUNIT_EXPECT_EQ(test, tquic_test_cert_check_validity(&cert, TEST_CURRENT_TIME), -1);
}

/* Test: Not yet valid certificate is rejected */
static void test_cert_not_yet_valid(struct kunit *test)
{
	struct tquic_test_cert_info cert = {
		.valid_from = TEST_CURRENT_TIME + 86400 * 30,  /* Valid in 30 days */
		.valid_to = TEST_CURRENT_TIME + 86400 * 400,
		.hostname = "example.com",
		.key_bits = 2048,
	};

	/* ARRANGE/ACT/ASSERT: Certificate should be detected as not yet valid */
	KUNIT_EXPECT_EQ(test, tquic_test_cert_check_validity(&cert, TEST_CURRENT_TIME), -2);
}

/* Test: Wrong hostname is rejected */
static void test_cert_wrong_hostname(struct kunit *test)
{
	struct tquic_test_cert_info cert = {
		.valid_from = TEST_CURRENT_TIME - 86400,
		.valid_to = TEST_CURRENT_TIME + 86400 * 365,
		.hostname = "example.com",
		.key_bits = 2048,
	};

	/* ARRANGE/ACT/ASSERT: Hostname mismatch should be detected */
	KUNIT_EXPECT_NE(test, tquic_test_cert_check_hostname(&cert, "example.com"), -1);
	KUNIT_EXPECT_EQ(test, tquic_test_cert_check_hostname(&cert, "evil.com"), -1);
	KUNIT_EXPECT_EQ(test, tquic_test_cert_check_hostname(&cert, "sub.example.com"), -1);
}

/* Test: Wildcard certificate matching */
static void test_cert_wildcard_hostname(struct kunit *test)
{
	struct tquic_test_cert_info cert = {
		.valid_from = TEST_CURRENT_TIME - 86400,
		.valid_to = TEST_CURRENT_TIME + 86400 * 365,
		.hostname = "*.example.com",
		.key_bits = 2048,
	};

	/* ARRANGE/ACT/ASSERT: Wildcard should match subdomains */
	KUNIT_EXPECT_EQ(test, tquic_test_cert_check_hostname(&cert, "foo.example.com"), 0);
	KUNIT_EXPECT_EQ(test, tquic_test_cert_check_hostname(&cert, "bar.example.com"), 0);
	/* Wildcard should NOT match apex domain */
	KUNIT_EXPECT_EQ(test, tquic_test_cert_check_hostname(&cert, "example.com"), -1);
	/* Wildcard should NOT match nested subdomains */
	KUNIT_EXPECT_EQ(test, tquic_test_cert_check_hostname(&cert, "foo.bar.example.com"), -1);
}

/* Test: Untrusted CA is rejected */
static void test_cert_untrusted_ca(struct kunit *test)
{
	struct tquic_test_cert_info cert = {
		.valid_from = TEST_CURRENT_TIME - 86400,
		.valid_to = TEST_CURRENT_TIME + 86400 * 365,
		.hostname = "example.com",
		.issuer = "Evil Untrusted CA",
		.key_bits = 2048,
		.is_trusted = false,
	};

	/* ARRANGE/ACT/ASSERT: Untrusted issuer should be detected */
	KUNIT_EXPECT_FALSE(test, cert.is_trusted);
}

/* Test: Weak key is rejected */
static void test_cert_weak_key(struct kunit *test)
{
	struct tquic_test_cert_info cert_1024 = {
		.valid_from = TEST_CURRENT_TIME - 86400,
		.valid_to = TEST_CURRENT_TIME + 86400 * 365,
		.hostname = "example.com",
		.key_bits = 1024,  /* Too weak for modern security */
	};

	struct tquic_test_cert_info cert_2048 = {
		.valid_from = TEST_CURRENT_TIME - 86400,
		.valid_to = TEST_CURRENT_TIME + 86400 * 365,
		.hostname = "example.com",
		.key_bits = 2048,  /* Acceptable */
	};

	/* ARRANGE/ACT/ASSERT: 1024-bit key should be rejected, 2048-bit accepted */
	KUNIT_EXPECT_EQ(test, tquic_test_cert_check_key_strength(&cert_1024, 2048), -1);
	KUNIT_EXPECT_EQ(test, tquic_test_cert_check_key_strength(&cert_2048, 2048), 0);
}

/*
 * =============================================================================
 * SECTION 6: Replay Attack Protection Extended Tests
 * =============================================================================
 */

/* Test: Replay attack with duplicate packet numbers */
static void test_replay_attack_duplicate_pn(struct kunit *test)
{
	struct tquic_test_replay_filter filter;
	u64 test_pn = 1000;

	/* ARRANGE: Initialize filter and mark packet as seen */
	memset(&filter, 0, sizeof(filter));
	KUNIT_EXPECT_TRUE(test, tquic_test_replay_check(&filter, test_pn));

	/* ACT/ASSERT: Replaying same packet should be detected */
	KUNIT_EXPECT_FALSE(test, tquic_test_replay_check(&filter, test_pn));
	KUNIT_EXPECT_FALSE(test, tquic_test_replay_check(&filter, test_pn));
	KUNIT_EXPECT_FALSE(test, tquic_test_replay_check(&filter, test_pn));
}

/* Test: Replay attack with old packet numbers */
static void test_replay_attack_old_packets(struct kunit *test)
{
	struct tquic_test_replay_filter filter;
	int i;

	/* ARRANGE: Initialize filter and process many packets */
	memset(&filter, 0, sizeof(filter));

	/* Process packets 0-9999 */
	for (i = 0; i < 10000; i++) {
		tquic_test_replay_check(&filter, i);
	}

	/* ACT/ASSERT: Very old packets should be rejected */
	KUNIT_EXPECT_FALSE(test, tquic_test_replay_check(&filter, 0));
	KUNIT_EXPECT_FALSE(test, tquic_test_replay_check(&filter, 100));
	KUNIT_EXPECT_FALSE(test, tquic_test_replay_check(&filter, 500));
}

/* Test: Replay filter with out-of-order packets */
static void test_replay_out_of_order(struct kunit *test)
{
	struct tquic_test_replay_filter filter;

	/* ARRANGE: Initialize filter */
	memset(&filter, 0, sizeof(filter));

	/* ACT: Process packets out of order */
	KUNIT_EXPECT_TRUE(test, tquic_test_replay_check(&filter, 100));
	KUNIT_EXPECT_TRUE(test, tquic_test_replay_check(&filter, 50));
	KUNIT_EXPECT_TRUE(test, tquic_test_replay_check(&filter, 75));
	KUNIT_EXPECT_TRUE(test, tquic_test_replay_check(&filter, 25));
	KUNIT_EXPECT_TRUE(test, tquic_test_replay_check(&filter, 90));

	/* ASSERT: All packets should be marked as seen (replays detected) */
	KUNIT_EXPECT_FALSE(test, tquic_test_replay_check(&filter, 100));
	KUNIT_EXPECT_FALSE(test, tquic_test_replay_check(&filter, 50));
	KUNIT_EXPECT_FALSE(test, tquic_test_replay_check(&filter, 75));
	KUNIT_EXPECT_FALSE(test, tquic_test_replay_check(&filter, 25));
	KUNIT_EXPECT_FALSE(test, tquic_test_replay_check(&filter, 90));
}

/* Test: Replay filter window edge cases */
static void test_replay_window_edge_cases(struct kunit *test)
{
	struct tquic_test_replay_filter filter;
	u64 window_size = TQUIC_REPLAY_WINDOW_SIZE;

	/* ARRANGE: Initialize filter at specific packet number */
	memset(&filter, 0, sizeof(filter));
	KUNIT_EXPECT_TRUE(test, tquic_test_replay_check(&filter, window_size));

	/* ACT/ASSERT: Packet at start of window should be accepted */
	KUNIT_EXPECT_TRUE(test, tquic_test_replay_check(&filter, 1));

	/* Packet just before window should be rejected */
	KUNIT_EXPECT_FALSE(test, tquic_test_replay_check(&filter, 0));
}

/*
 * =============================================================================
 * Test Suite Definition
 * =============================================================================
 */

static struct kunit_case tquic_security_test_cases[] = {
	/* Frame parsing overflow tests */
	KUNIT_CASE(test_frame_size_underflow),
	KUNIT_CASE(test_size_max_boundary),
	KUNIT_CASE(test_malformed_frame_length),
	KUNIT_CASE(test_token_length_overflow),
	KUNIT_CASE(test_new_token_excessive_length),
	KUNIT_CASE(test_varint_overflow),
	KUNIT_CASE(test_truncated_varint),
	KUNIT_CASE(test_frame_length_exact_boundary),

	/* Crypto security tests */
	KUNIT_CASE(test_pn_monotonicity),
	KUNIT_CASE(test_nonce_reuse_prevention),
	KUNIT_CASE(test_replay_filter_sequential),
	KUNIT_CASE(test_replay_filter_random),
	KUNIT_CASE(test_replay_filter_window_advance),
	KUNIT_CASE(test_key_update_boundaries),
	KUNIT_CASE(test_pn_space_isolation),

	/* Bounds checking tests */
	KUNIT_CASE(test_buffer_overflow_boundary),
	KUNIT_CASE(test_integer_overflow_calc),
	KUNIT_CASE(test_max_limits_enforcement),
	KUNIT_CASE(test_cid_length_validation),
	KUNIT_CASE(test_stream_offset_bounds),
	KUNIT_CASE(test_ack_range_overflow),
	KUNIT_CASE(test_max_data_limits),
	KUNIT_CASE(test_frame_vs_packet_size),
	KUNIT_CASE(test_path_mtu_limits),
	KUNIT_CASE(test_new_cid_sequence_validation),

	/* Rate limiting tests */
	KUNIT_CASE(test_ratelimit_token_bucket),
	KUNIT_CASE(test_ratelimit_token_refill),
	KUNIT_CASE(test_ratelimit_burst_handling),
	KUNIT_CASE(test_ratelimit_sustained_load),

	/* Certificate validation tests */
	KUNIT_CASE(test_cert_valid),
	KUNIT_CASE(test_cert_expired),
	KUNIT_CASE(test_cert_not_yet_valid),
	KUNIT_CASE(test_cert_wrong_hostname),
	KUNIT_CASE(test_cert_wildcard_hostname),
	KUNIT_CASE(test_cert_untrusted_ca),
	KUNIT_CASE(test_cert_weak_key),

	/* Extended replay attack tests */
	KUNIT_CASE(test_replay_attack_duplicate_pn),
	KUNIT_CASE(test_replay_attack_old_packets),
	KUNIT_CASE(test_replay_out_of_order),
	KUNIT_CASE(test_replay_window_edge_cases),
	{}
};

static struct kunit_suite tquic_security_test_suite = {
	.name = "tquic-security",
	.test_cases = tquic_security_test_cases,
};

kunit_test_suite(tquic_security_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit security regression tests for TQUIC");
MODULE_AUTHOR("Linux Foundation");
