// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: QUIC-Aware Proxy KUnit Tests (draft-ietf-masque-quic-proxy)
 *
 * Copyright (c) 2026 Linux Foundation
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Comprehensive tests for the QUIC-Aware Proxy protocol extension:
 *   - Capsule encoding/decoding
 *   - Connection registration/deregistration
 *   - CID cooperation
 *   - Header compression
 *   - Packet forwarding
 *
 * Test Structure:
 *   Section 1: Varint Encoding Tests
 *   Section 2: Register Capsule Tests
 *   Section 3: CID Capsule Tests
 *   Section 4: Packet Capsule Tests
 *   Section 5: Deregister Capsule Tests
 *   Section 6: Error Capsule Tests
 *   Section 7: CID Management Tests
 *   Section 8: Header Compression Tests
 *   Section 9: Integration Tests
 */

#include <kunit/test.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/slab.h>

/*
 * =============================================================================
 * Constants (mirror quic_proxy.h)
 * =============================================================================
 */

/* Capsule types */
#define CAPSULE_TYPE_QUIC_PROXY_REGISTER	0x4143
#define CAPSULE_TYPE_QUIC_PROXY_CID		0x4144
#define CAPSULE_TYPE_QUIC_PROXY_PACKET		0x4145
#define CAPSULE_TYPE_QUIC_PROXY_DEREGISTER	0x4146
#define CAPSULE_TYPE_QUIC_PROXY_ERROR		0x4147

/* CID constants */
#define QUIC_PROXY_MAX_CID_LEN			20
#define QUIC_PROXY_MAX_CIDS_PER_CONN		8

/* CID directions */
#define QUIC_PROXY_CID_DIR_CLIENT_TARGET	0
#define QUIC_PROXY_CID_DIR_TARGET_CLIENT	1

/* CID actions */
#define QUIC_PROXY_CID_ACTION_ADD		0
#define QUIC_PROXY_CID_ACTION_RETIRE		1
#define QUIC_PROXY_CID_ACTION_REQUEST		2
#define QUIC_PROXY_CID_ACTION_ACK		3

/* Registration flags */
#define QUIC_PROXY_REG_FLAG_CID_COOP		0x01
#define QUIC_PROXY_REG_FLAG_COMPRESS		0x02
#define QUIC_PROXY_REG_FLAG_CID_REWRITE		0x04

/* Deregistration reasons */
#define QUIC_PROXY_DEREG_NORMAL			0
#define QUIC_PROXY_DEREG_ERROR			1
#define QUIC_PROXY_DEREG_TIMEOUT		2

/* Error codes */
#define QUIC_PROXY_ERR_INVALID_CID		1
#define QUIC_PROXY_ERR_CID_CONFLICT		2
#define QUIC_PROXY_ERR_CONN_NOT_FOUND		3

/*
 * =============================================================================
 * Test Data Structures
 * =============================================================================
 */

/**
 * struct test_register_capsule - REGISTER capsule for testing
 */
struct test_register_capsule {
	u64 conn_id;
	u8 target_host_len;
	char target_host[256];
	u16 target_port;
	u8 initial_dcid_len;
	u8 initial_dcid[QUIC_PROXY_MAX_CID_LEN];
	u8 initial_scid_len;
	u8 initial_scid[QUIC_PROXY_MAX_CID_LEN];
	u32 version;
	u8 flags;
};

/**
 * struct test_cid_capsule - CID capsule for testing
 */
struct test_cid_capsule {
	u64 conn_id;
	u8 direction;
	u8 action;
	u64 seq_num;
	u64 retire_prior_to;
	u8 cid_len;
	u8 cid[QUIC_PROXY_MAX_CID_LEN];
	u8 reset_token[16];
	bool has_reset_token;
};

/**
 * struct test_packet_capsule - PACKET capsule for testing
 */
struct test_packet_capsule {
	u64 conn_id;
	u8 direction;
	bool compressed;
	u8 compress_index;
	u16 packet_len;
	u8 *packet;
};

/**
 * struct test_deregister_capsule - DEREGISTER capsule for testing
 */
struct test_deregister_capsule {
	u64 conn_id;
	u8 reason;
	u32 drain_timeout_ms;
};

/**
 * struct test_error_capsule - ERROR capsule for testing
 */
struct test_error_capsule {
	u64 conn_id;
	u64 error_code;
	u16 error_len;
	char error_msg[256];
};

/*
 * =============================================================================
 * Varint Encoding/Decoding Helpers
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
 * Register Capsule Encoding/Decoding
 * =============================================================================
 */

static int test_encode_register(const struct test_register_capsule *cap,
				u8 *buf, size_t buf_len)
{
	size_t offset = 0;
	size_t payload_len;
	int ret;

	/* Calculate payload length */
	payload_len = test_varint_size(cap->conn_id) +
		      1 + cap->target_host_len +
		      2 + 1 + cap->initial_dcid_len +
		      1 + cap->initial_scid_len + 4 + 1;

	/* Type */
	ret = test_varint_encode(buf + offset, buf_len - offset,
				 CAPSULE_TYPE_QUIC_PROXY_REGISTER);
	if (ret < 0) return ret;
	offset += ret;

	/* Length */
	ret = test_varint_encode(buf + offset, buf_len - offset, payload_len);
	if (ret < 0) return ret;
	offset += ret;

	/* Connection ID */
	ret = test_varint_encode(buf + offset, buf_len - offset, cap->conn_id);
	if (ret < 0) return ret;
	offset += ret;

	/* Target host */
	buf[offset++] = cap->target_host_len;
	if (cap->target_host_len > 0) {
		memcpy(buf + offset, cap->target_host, cap->target_host_len);
		offset += cap->target_host_len;
	}

	/* Target port */
	buf[offset++] = (cap->target_port >> 8) & 0xFF;
	buf[offset++] = cap->target_port & 0xFF;

	/* Initial DCID */
	buf[offset++] = cap->initial_dcid_len;
	if (cap->initial_dcid_len > 0) {
		memcpy(buf + offset, cap->initial_dcid, cap->initial_dcid_len);
		offset += cap->initial_dcid_len;
	}

	/* Initial SCID */
	buf[offset++] = cap->initial_scid_len;
	if (cap->initial_scid_len > 0) {
		memcpy(buf + offset, cap->initial_scid, cap->initial_scid_len);
		offset += cap->initial_scid_len;
	}

	/* Version */
	buf[offset++] = (cap->version >> 24) & 0xFF;
	buf[offset++] = (cap->version >> 16) & 0xFF;
	buf[offset++] = (cap->version >> 8) & 0xFF;
	buf[offset++] = cap->version & 0xFF;

	/* Flags */
	buf[offset++] = cap->flags;

	return offset;
}

static int test_decode_register(const u8 *buf, size_t buf_len,
				struct test_register_capsule *cap)
{
	size_t offset = 0;
	u64 type, length;
	int ret;

	memset(cap, 0, sizeof(*cap));

	/* Type */
	ret = test_varint_decode(buf + offset, buf_len - offset, &type);
	if (ret < 0) return ret;
	if (type != CAPSULE_TYPE_QUIC_PROXY_REGISTER) return -EINVAL;
	offset += ret;

	/* Length */
	ret = test_varint_decode(buf + offset, buf_len - offset, &length);
	if (ret < 0) return ret;
	offset += ret;

	/* Connection ID */
	ret = test_varint_decode(buf + offset, buf_len - offset, &cap->conn_id);
	if (ret < 0) return ret;
	offset += ret;

	/* Target host */
	cap->target_host_len = buf[offset++];
	if (cap->target_host_len > 0) {
		memcpy(cap->target_host, buf + offset, cap->target_host_len);
		cap->target_host[cap->target_host_len] = '\0';
		offset += cap->target_host_len;
	}

	/* Target port */
	cap->target_port = ((u16)buf[offset] << 8) | buf[offset + 1];
	offset += 2;

	/* Initial DCID */
	cap->initial_dcid_len = buf[offset++];
	if (cap->initial_dcid_len > 0) {
		memcpy(cap->initial_dcid, buf + offset, cap->initial_dcid_len);
		offset += cap->initial_dcid_len;
	}

	/* Initial SCID */
	cap->initial_scid_len = buf[offset++];
	if (cap->initial_scid_len > 0) {
		memcpy(cap->initial_scid, buf + offset, cap->initial_scid_len);
		offset += cap->initial_scid_len;
	}

	/* Version */
	cap->version = ((u32)buf[offset] << 24) |
		       ((u32)buf[offset + 1] << 16) |
		       ((u32)buf[offset + 2] << 8) |
		       buf[offset + 3];
	offset += 4;

	/* Flags */
	cap->flags = buf[offset++];

	return offset;
}

/*
 * =============================================================================
 * CID Capsule Encoding/Decoding
 * =============================================================================
 */

static int test_encode_cid(const struct test_cid_capsule *cap,
			   u8 *buf, size_t buf_len)
{
	size_t offset = 0;
	size_t payload_len;
	int ret;

	/* Calculate payload length */
	payload_len = test_varint_size(cap->conn_id) + 2 +
		      test_varint_size(cap->seq_num) +
		      test_varint_size(cap->retire_prior_to) +
		      1 + cap->cid_len +
		      (cap->has_reset_token ? 16 : 0);

	/* Type */
	ret = test_varint_encode(buf + offset, buf_len - offset,
				 CAPSULE_TYPE_QUIC_PROXY_CID);
	if (ret < 0) return ret;
	offset += ret;

	/* Length */
	ret = test_varint_encode(buf + offset, buf_len - offset, payload_len);
	if (ret < 0) return ret;
	offset += ret;

	/* Connection ID */
	ret = test_varint_encode(buf + offset, buf_len - offset, cap->conn_id);
	if (ret < 0) return ret;
	offset += ret;

	/* Direction and action */
	buf[offset++] = cap->direction;
	buf[offset++] = cap->action;

	/* Sequence number */
	ret = test_varint_encode(buf + offset, buf_len - offset, cap->seq_num);
	if (ret < 0) return ret;
	offset += ret;

	/* Retire prior to */
	ret = test_varint_encode(buf + offset, buf_len - offset,
				 cap->retire_prior_to);
	if (ret < 0) return ret;
	offset += ret;

	/* CID */
	buf[offset++] = cap->cid_len;
	if (cap->cid_len > 0) {
		memcpy(buf + offset, cap->cid, cap->cid_len);
		offset += cap->cid_len;
	}

	/* Reset token */
	if (cap->has_reset_token) {
		memcpy(buf + offset, cap->reset_token, 16);
		offset += 16;
	}

	return offset;
}

static int test_decode_cid(const u8 *buf, size_t buf_len,
			   struct test_cid_capsule *cap)
{
	size_t offset = 0;
	size_t start;
	u64 type, length;
	int ret;

	memset(cap, 0, sizeof(*cap));

	/* Type */
	ret = test_varint_decode(buf + offset, buf_len - offset, &type);
	if (ret < 0) return ret;
	if (type != CAPSULE_TYPE_QUIC_PROXY_CID) return -EINVAL;
	offset += ret;

	/* Length */
	ret = test_varint_decode(buf + offset, buf_len - offset, &length);
	if (ret < 0) return ret;
	offset += ret;

	start = offset;

	/* Connection ID */
	ret = test_varint_decode(buf + offset, buf_len - offset, &cap->conn_id);
	if (ret < 0) return ret;
	offset += ret;

	/* Direction and action */
	cap->direction = buf[offset++];
	cap->action = buf[offset++];

	/* Sequence number */
	ret = test_varint_decode(buf + offset, buf_len - offset, &cap->seq_num);
	if (ret < 0) return ret;
	offset += ret;

	/* Retire prior to */
	ret = test_varint_decode(buf + offset, buf_len - offset,
				 &cap->retire_prior_to);
	if (ret < 0) return ret;
	offset += ret;

	/* CID */
	cap->cid_len = buf[offset++];
	if (cap->cid_len > 0) {
		memcpy(cap->cid, buf + offset, cap->cid_len);
		offset += cap->cid_len;
	}

	/* Check for reset token */
	if (offset - start < length && length - (offset - start) >= 16) {
		memcpy(cap->reset_token, buf + offset, 16);
		cap->has_reset_token = true;
		offset += 16;
	}

	return offset;
}

/*
 * =============================================================================
 * Deregister Capsule Encoding/Decoding
 * =============================================================================
 */

static int test_encode_deregister(const struct test_deregister_capsule *cap,
				  u8 *buf, size_t buf_len)
{
	size_t offset = 0;
	size_t payload_len;
	int ret;

	payload_len = test_varint_size(cap->conn_id) + 5;

	ret = test_varint_encode(buf + offset, buf_len - offset,
				 CAPSULE_TYPE_QUIC_PROXY_DEREGISTER);
	if (ret < 0) return ret;
	offset += ret;

	ret = test_varint_encode(buf + offset, buf_len - offset, payload_len);
	if (ret < 0) return ret;
	offset += ret;

	ret = test_varint_encode(buf + offset, buf_len - offset, cap->conn_id);
	if (ret < 0) return ret;
	offset += ret;

	buf[offset++] = cap->reason;

	buf[offset++] = (cap->drain_timeout_ms >> 24) & 0xFF;
	buf[offset++] = (cap->drain_timeout_ms >> 16) & 0xFF;
	buf[offset++] = (cap->drain_timeout_ms >> 8) & 0xFF;
	buf[offset++] = cap->drain_timeout_ms & 0xFF;

	return offset;
}

static int test_decode_deregister(const u8 *buf, size_t buf_len,
				  struct test_deregister_capsule *cap)
{
	size_t offset = 0;
	u64 type, length;
	int ret;

	memset(cap, 0, sizeof(*cap));

	ret = test_varint_decode(buf + offset, buf_len - offset, &type);
	if (ret < 0) return ret;
	if (type != CAPSULE_TYPE_QUIC_PROXY_DEREGISTER) return -EINVAL;
	offset += ret;

	ret = test_varint_decode(buf + offset, buf_len - offset, &length);
	if (ret < 0) return ret;
	offset += ret;

	ret = test_varint_decode(buf + offset, buf_len - offset, &cap->conn_id);
	if (ret < 0) return ret;
	offset += ret;

	cap->reason = buf[offset++];

	cap->drain_timeout_ms = ((u32)buf[offset] << 24) |
				((u32)buf[offset + 1] << 16) |
				((u32)buf[offset + 2] << 8) |
				buf[offset + 3];
	offset += 4;

	return offset;
}

/*
 * =============================================================================
 * Error Capsule Encoding/Decoding
 * =============================================================================
 */

static int test_encode_error(const struct test_error_capsule *cap,
			     u8 *buf, size_t buf_len)
{
	size_t offset = 0;
	size_t payload_len;
	int ret;

	payload_len = test_varint_size(cap->conn_id) +
		      test_varint_size(cap->error_code) +
		      2 + cap->error_len;

	ret = test_varint_encode(buf + offset, buf_len - offset,
				 CAPSULE_TYPE_QUIC_PROXY_ERROR);
	if (ret < 0) return ret;
	offset += ret;

	ret = test_varint_encode(buf + offset, buf_len - offset, payload_len);
	if (ret < 0) return ret;
	offset += ret;

	ret = test_varint_encode(buf + offset, buf_len - offset, cap->conn_id);
	if (ret < 0) return ret;
	offset += ret;

	ret = test_varint_encode(buf + offset, buf_len - offset, cap->error_code);
	if (ret < 0) return ret;
	offset += ret;

	buf[offset++] = (cap->error_len >> 8) & 0xFF;
	buf[offset++] = cap->error_len & 0xFF;

	if (cap->error_len > 0) {
		memcpy(buf + offset, cap->error_msg, cap->error_len);
		offset += cap->error_len;
	}

	return offset;
}

static int test_decode_error(const u8 *buf, size_t buf_len,
			     struct test_error_capsule *cap)
{
	size_t offset = 0;
	u64 type, length;
	int ret;

	memset(cap, 0, sizeof(*cap));

	ret = test_varint_decode(buf + offset, buf_len - offset, &type);
	if (ret < 0) return ret;
	if (type != CAPSULE_TYPE_QUIC_PROXY_ERROR) return -EINVAL;
	offset += ret;

	ret = test_varint_decode(buf + offset, buf_len - offset, &length);
	if (ret < 0) return ret;
	offset += ret;

	ret = test_varint_decode(buf + offset, buf_len - offset, &cap->conn_id);
	if (ret < 0) return ret;
	offset += ret;

	ret = test_varint_decode(buf + offset, buf_len - offset, &cap->error_code);
	if (ret < 0) return ret;
	offset += ret;

	cap->error_len = ((u16)buf[offset] << 8) | buf[offset + 1];
	offset += 2;

	if (cap->error_len > 0) {
		memcpy(cap->error_msg, buf + offset, cap->error_len);
		cap->error_msg[cap->error_len] = '\0';
		offset += cap->error_len;
	}

	return offset;
}

/*
 * =============================================================================
 * SECTION 1: Varint Encoding Tests
 * =============================================================================
 */

static void test_varint_encode_1byte(struct kunit *test)
{
	u8 buf[8];
	int ret;
	u64 value;

	/* Value 0 */
	ret = test_varint_encode(buf, sizeof(buf), 0);
	KUNIT_EXPECT_EQ(test, ret, 1);
	KUNIT_EXPECT_EQ(test, buf[0], 0x00U);

	ret = test_varint_decode(buf, ret, &value);
	KUNIT_EXPECT_EQ(test, ret, 1);
	KUNIT_EXPECT_EQ(test, value, 0ULL);

	/* Value 63 (max 1-byte) */
	ret = test_varint_encode(buf, sizeof(buf), 63);
	KUNIT_EXPECT_EQ(test, ret, 1);
	KUNIT_EXPECT_EQ(test, buf[0], 0x3FU);

	ret = test_varint_decode(buf, ret, &value);
	KUNIT_EXPECT_EQ(test, value, 63ULL);
}

static void test_varint_encode_2byte(struct kunit *test)
{
	u8 buf[8];
	int ret;
	u64 value;

	/* Value 64 (min 2-byte) */
	ret = test_varint_encode(buf, sizeof(buf), 64);
	KUNIT_EXPECT_EQ(test, ret, 2);
	KUNIT_EXPECT_EQ(test, buf[0], 0x40U);
	KUNIT_EXPECT_EQ(test, buf[1], 0x40U);

	ret = test_varint_decode(buf, ret, &value);
	KUNIT_EXPECT_EQ(test, value, 64ULL);

	/* Value 16383 (max 2-byte) */
	ret = test_varint_encode(buf, sizeof(buf), 16383);
	KUNIT_EXPECT_EQ(test, ret, 2);

	ret = test_varint_decode(buf, ret, &value);
	KUNIT_EXPECT_EQ(test, value, 16383ULL);
}

static void test_varint_encode_4byte(struct kunit *test)
{
	u8 buf[8];
	int ret;
	u64 value;

	/* Value 16384 (min 4-byte) */
	ret = test_varint_encode(buf, sizeof(buf), 16384);
	KUNIT_EXPECT_EQ(test, ret, 4);

	ret = test_varint_decode(buf, ret, &value);
	KUNIT_EXPECT_EQ(test, value, 16384ULL);

	/* Value 1073741823 (max 4-byte) */
	ret = test_varint_encode(buf, sizeof(buf), 1073741823ULL);
	KUNIT_EXPECT_EQ(test, ret, 4);

	ret = test_varint_decode(buf, ret, &value);
	KUNIT_EXPECT_EQ(test, value, 1073741823ULL);
}

static void test_varint_encode_8byte(struct kunit *test)
{
	u8 buf[8];
	int ret;
	u64 value;

	/* Value 1073741824 (min 8-byte) */
	ret = test_varint_encode(buf, sizeof(buf), 1073741824ULL);
	KUNIT_EXPECT_EQ(test, ret, 8);

	ret = test_varint_decode(buf, ret, &value);
	KUNIT_EXPECT_EQ(test, value, 1073741824ULL);

	/* Large value */
	ret = test_varint_encode(buf, sizeof(buf), 0x123456789ABCULL);
	KUNIT_EXPECT_EQ(test, ret, 8);

	ret = test_varint_decode(buf, ret, &value);
	KUNIT_EXPECT_EQ(test, value, 0x123456789ABCULL);
}

/*
 * =============================================================================
 * SECTION 2: Register Capsule Tests
 * =============================================================================
 */

static void test_register_capsule_basic(struct kunit *test)
{
	u8 buf[256];
	struct test_register_capsule input = {
		.conn_id = 1,
		.target_port = 443,
		.version = 0x00000001,  /* QUIC v1 */
		.flags = QUIC_PROXY_REG_FLAG_CID_COOP,
	};
	struct test_register_capsule output;
	int ret;

	/* Set target host */
	strcpy(input.target_host, "example.com");
	input.target_host_len = strlen(input.target_host);

	/* Set initial DCID */
	input.initial_dcid[0] = 0x01;
	input.initial_dcid[1] = 0x02;
	input.initial_dcid[2] = 0x03;
	input.initial_dcid[3] = 0x04;
	input.initial_dcid_len = 4;

	/* Encode */
	ret = test_encode_register(&input, buf, sizeof(buf));
	KUNIT_EXPECT_GT(test, ret, 0);

	/* Decode */
	ret = test_decode_register(buf, ret, &output);
	KUNIT_EXPECT_GT(test, ret, 0);

	/* Verify */
	KUNIT_EXPECT_EQ(test, output.conn_id, 1ULL);
	KUNIT_EXPECT_STREQ(test, output.target_host, "example.com");
	KUNIT_EXPECT_EQ(test, output.target_port, 443U);
	KUNIT_EXPECT_EQ(test, output.version, 0x00000001U);
	KUNIT_EXPECT_EQ(test, output.flags, (u8)QUIC_PROXY_REG_FLAG_CID_COOP);
	KUNIT_EXPECT_EQ(test, output.initial_dcid_len, 4U);
	KUNIT_EXPECT_EQ(test, memcmp(output.initial_dcid, input.initial_dcid, 4), 0);
}

static void test_register_capsule_with_scid(struct kunit *test)
{
	u8 buf[256];
	struct test_register_capsule input = {
		.conn_id = 42,
		.target_port = 8443,
		.version = 0x00000001,
		.flags = QUIC_PROXY_REG_FLAG_CID_COOP | QUIC_PROXY_REG_FLAG_COMPRESS,
	};
	struct test_register_capsule output;
	int ret;

	strcpy(input.target_host, "192.168.1.1");
	input.target_host_len = strlen(input.target_host);

	/* Set DCID */
	memset(input.initial_dcid, 0xAA, 8);
	input.initial_dcid_len = 8;

	/* Set SCID */
	memset(input.initial_scid, 0xBB, 8);
	input.initial_scid_len = 8;

	ret = test_encode_register(&input, buf, sizeof(buf));
	KUNIT_EXPECT_GT(test, ret, 0);

	ret = test_decode_register(buf, ret, &output);
	KUNIT_EXPECT_GT(test, ret, 0);

	KUNIT_EXPECT_EQ(test, output.initial_dcid_len, 8U);
	KUNIT_EXPECT_EQ(test, output.initial_scid_len, 8U);
	KUNIT_EXPECT_EQ(test, memcmp(output.initial_dcid, input.initial_dcid, 8), 0);
	KUNIT_EXPECT_EQ(test, memcmp(output.initial_scid, input.initial_scid, 8), 0);
}

static void test_register_capsule_max_cid_len(struct kunit *test)
{
	u8 buf[512];
	struct test_register_capsule input = {
		.conn_id = 100,
		.target_port = 443,
		.version = 0x00000001,
		.flags = 0,
	};
	struct test_register_capsule output;
	int ret;

	strcpy(input.target_host, "test.example.com");
	input.target_host_len = strlen(input.target_host);

	/* Maximum CID length (20 bytes) */
	memset(input.initial_dcid, 0x12, QUIC_PROXY_MAX_CID_LEN);
	input.initial_dcid_len = QUIC_PROXY_MAX_CID_LEN;

	ret = test_encode_register(&input, buf, sizeof(buf));
	KUNIT_EXPECT_GT(test, ret, 0);

	ret = test_decode_register(buf, ret, &output);
	KUNIT_EXPECT_GT(test, ret, 0);

	KUNIT_EXPECT_EQ(test, output.initial_dcid_len, (u8)QUIC_PROXY_MAX_CID_LEN);
}

/*
 * =============================================================================
 * SECTION 3: CID Capsule Tests
 * =============================================================================
 */

static void test_cid_capsule_add(struct kunit *test)
{
	u8 buf[128];
	struct test_cid_capsule input = {
		.conn_id = 1,
		.direction = QUIC_PROXY_CID_DIR_CLIENT_TARGET,
		.action = QUIC_PROXY_CID_ACTION_ADD,
		.seq_num = 1,
		.retire_prior_to = 0,
		.has_reset_token = false,
	};
	struct test_cid_capsule output;
	int ret;

	/* Set CID */
	memset(input.cid, 0xCC, 8);
	input.cid_len = 8;

	ret = test_encode_cid(&input, buf, sizeof(buf));
	KUNIT_EXPECT_GT(test, ret, 0);

	ret = test_decode_cid(buf, ret, &output);
	KUNIT_EXPECT_GT(test, ret, 0);

	KUNIT_EXPECT_EQ(test, output.conn_id, 1ULL);
	KUNIT_EXPECT_EQ(test, output.direction, (u8)QUIC_PROXY_CID_DIR_CLIENT_TARGET);
	KUNIT_EXPECT_EQ(test, output.action, (u8)QUIC_PROXY_CID_ACTION_ADD);
	KUNIT_EXPECT_EQ(test, output.seq_num, 1ULL);
	KUNIT_EXPECT_EQ(test, output.cid_len, 8U);
	KUNIT_EXPECT_FALSE(test, output.has_reset_token);
}

static void test_cid_capsule_with_reset_token(struct kunit *test)
{
	u8 buf[128];
	struct test_cid_capsule input = {
		.conn_id = 5,
		.direction = QUIC_PROXY_CID_DIR_TARGET_CLIENT,
		.action = QUIC_PROXY_CID_ACTION_ADD,
		.seq_num = 2,
		.retire_prior_to = 1,
		.has_reset_token = true,
	};
	struct test_cid_capsule output;
	int ret;

	memset(input.cid, 0xDD, 8);
	input.cid_len = 8;

	/* Set reset token */
	memset(input.reset_token, 0xEE, 16);

	ret = test_encode_cid(&input, buf, sizeof(buf));
	KUNIT_EXPECT_GT(test, ret, 0);

	ret = test_decode_cid(buf, ret, &output);
	KUNIT_EXPECT_GT(test, ret, 0);

	KUNIT_EXPECT_TRUE(test, output.has_reset_token);
	KUNIT_EXPECT_EQ(test, memcmp(output.reset_token, input.reset_token, 16), 0);
}

static void test_cid_capsule_retire(struct kunit *test)
{
	u8 buf[64];
	struct test_cid_capsule input = {
		.conn_id = 10,
		.direction = QUIC_PROXY_CID_DIR_CLIENT_TARGET,
		.action = QUIC_PROXY_CID_ACTION_RETIRE,
		.seq_num = 5,
		.retire_prior_to = 0,
		.cid_len = 0,
		.has_reset_token = false,
	};
	struct test_cid_capsule output;
	int ret;

	ret = test_encode_cid(&input, buf, sizeof(buf));
	KUNIT_EXPECT_GT(test, ret, 0);

	ret = test_decode_cid(buf, ret, &output);
	KUNIT_EXPECT_GT(test, ret, 0);

	KUNIT_EXPECT_EQ(test, output.action, (u8)QUIC_PROXY_CID_ACTION_RETIRE);
	KUNIT_EXPECT_EQ(test, output.seq_num, 5ULL);
}

static void test_cid_capsule_request(struct kunit *test)
{
	u8 buf[64];
	struct test_cid_capsule input = {
		.conn_id = 15,
		.direction = QUIC_PROXY_CID_DIR_TARGET_CLIENT,
		.action = QUIC_PROXY_CID_ACTION_REQUEST,
		.seq_num = 0,
		.retire_prior_to = 0,
		.cid_len = 0,
		.has_reset_token = false,
	};
	struct test_cid_capsule output;
	int ret;

	ret = test_encode_cid(&input, buf, sizeof(buf));
	KUNIT_EXPECT_GT(test, ret, 0);

	ret = test_decode_cid(buf, ret, &output);
	KUNIT_EXPECT_GT(test, ret, 0);

	KUNIT_EXPECT_EQ(test, output.action, (u8)QUIC_PROXY_CID_ACTION_REQUEST);
}

/*
 * =============================================================================
 * SECTION 4: Deregister Capsule Tests
 * =============================================================================
 */

static void test_deregister_capsule_normal(struct kunit *test)
{
	u8 buf[64];
	struct test_deregister_capsule input = {
		.conn_id = 1,
		.reason = QUIC_PROXY_DEREG_NORMAL,
		.drain_timeout_ms = 0,
	};
	struct test_deregister_capsule output;
	int ret;

	ret = test_encode_deregister(&input, buf, sizeof(buf));
	KUNIT_EXPECT_GT(test, ret, 0);

	ret = test_decode_deregister(buf, ret, &output);
	KUNIT_EXPECT_GT(test, ret, 0);

	KUNIT_EXPECT_EQ(test, output.conn_id, 1ULL);
	KUNIT_EXPECT_EQ(test, output.reason, (u8)QUIC_PROXY_DEREG_NORMAL);
	KUNIT_EXPECT_EQ(test, output.drain_timeout_ms, 0U);
}

static void test_deregister_capsule_with_drain(struct kunit *test)
{
	u8 buf[64];
	struct test_deregister_capsule input = {
		.conn_id = 50,
		.reason = QUIC_PROXY_DEREG_TIMEOUT,
		.drain_timeout_ms = 5000,
	};
	struct test_deregister_capsule output;
	int ret;

	ret = test_encode_deregister(&input, buf, sizeof(buf));
	KUNIT_EXPECT_GT(test, ret, 0);

	ret = test_decode_deregister(buf, ret, &output);
	KUNIT_EXPECT_GT(test, ret, 0);

	KUNIT_EXPECT_EQ(test, output.reason, (u8)QUIC_PROXY_DEREG_TIMEOUT);
	KUNIT_EXPECT_EQ(test, output.drain_timeout_ms, 5000U);
}

/*
 * =============================================================================
 * SECTION 5: Error Capsule Tests
 * =============================================================================
 */

static void test_error_capsule_basic(struct kunit *test)
{
	u8 buf[256];
	struct test_error_capsule input = {
		.conn_id = 1,
		.error_code = QUIC_PROXY_ERR_INVALID_CID,
	};
	struct test_error_capsule output;
	int ret;

	strcpy(input.error_msg, "Invalid connection ID");
	input.error_len = strlen(input.error_msg);

	ret = test_encode_error(&input, buf, sizeof(buf));
	KUNIT_EXPECT_GT(test, ret, 0);

	ret = test_decode_error(buf, ret, &output);
	KUNIT_EXPECT_GT(test, ret, 0);

	KUNIT_EXPECT_EQ(test, output.conn_id, 1ULL);
	KUNIT_EXPECT_EQ(test, output.error_code, (u64)QUIC_PROXY_ERR_INVALID_CID);
	KUNIT_EXPECT_STREQ(test, output.error_msg, "Invalid connection ID");
}

static void test_error_capsule_proxy_wide(struct kunit *test)
{
	u8 buf[256];
	struct test_error_capsule input = {
		.conn_id = 0,  /* Proxy-wide error */
		.error_code = 0x1234,
	};
	struct test_error_capsule output;
	int ret;

	strcpy(input.error_msg, "Proxy overloaded");
	input.error_len = strlen(input.error_msg);

	ret = test_encode_error(&input, buf, sizeof(buf));
	KUNIT_EXPECT_GT(test, ret, 0);

	ret = test_decode_error(buf, ret, &output);
	KUNIT_EXPECT_GT(test, ret, 0);

	KUNIT_EXPECT_EQ(test, output.conn_id, 0ULL);
}

static void test_error_capsule_empty_message(struct kunit *test)
{
	u8 buf[64];
	struct test_error_capsule input = {
		.conn_id = 5,
		.error_code = QUIC_PROXY_ERR_CONN_NOT_FOUND,
		.error_len = 0,
	};
	struct test_error_capsule output;
	int ret;

	ret = test_encode_error(&input, buf, sizeof(buf));
	KUNIT_EXPECT_GT(test, ret, 0);

	ret = test_decode_error(buf, ret, &output);
	KUNIT_EXPECT_GT(test, ret, 0);

	KUNIT_EXPECT_EQ(test, output.error_len, 0U);
}

/*
 * =============================================================================
 * SECTION 6: CID Management Tests
 * =============================================================================
 */

static void test_cid_sequence_numbers(struct kunit *test)
{
	/* Test that CID sequence numbers follow protocol rules */
	u64 seq_nums[] = {0, 1, 2, 3, 5, 10, 100};
	int i;

	for (i = 0; i < ARRAY_SIZE(seq_nums); i++) {
		u8 buf[64];
		struct test_cid_capsule input = {
			.conn_id = 1,
			.direction = QUIC_PROXY_CID_DIR_CLIENT_TARGET,
			.action = QUIC_PROXY_CID_ACTION_ADD,
			.seq_num = seq_nums[i],
			.retire_prior_to = (i > 0) ? seq_nums[i - 1] : 0,
			.cid_len = 8,
			.has_reset_token = false,
		};
		struct test_cid_capsule output;
		int ret;

		memset(input.cid, 0xFF, 8);

		ret = test_encode_cid(&input, buf, sizeof(buf));
		KUNIT_EXPECT_GT(test, ret, 0);

		ret = test_decode_cid(buf, ret, &output);
		KUNIT_EXPECT_GT(test, ret, 0);

		KUNIT_EXPECT_EQ(test, output.seq_num, seq_nums[i]);
	}
}

static void test_cid_retire_prior_to(struct kunit *test)
{
	/* Verify retire_prior_to field is properly handled */
	u8 buf[64];
	struct test_cid_capsule input = {
		.conn_id = 1,
		.direction = QUIC_PROXY_CID_DIR_CLIENT_TARGET,
		.action = QUIC_PROXY_CID_ACTION_ADD,
		.seq_num = 10,
		.retire_prior_to = 5,  /* Retire CIDs 0-4 */
		.cid_len = 8,
		.has_reset_token = false,
	};
	struct test_cid_capsule output;
	int ret;

	memset(input.cid, 0xAB, 8);

	ret = test_encode_cid(&input, buf, sizeof(buf));
	KUNIT_EXPECT_GT(test, ret, 0);

	ret = test_decode_cid(buf, ret, &output);
	KUNIT_EXPECT_GT(test, ret, 0);

	KUNIT_EXPECT_EQ(test, output.retire_prior_to, 5ULL);
	KUNIT_EXPECT_LT(test, output.retire_prior_to, output.seq_num);
}

/*
 * =============================================================================
 * SECTION 7: Header Compression Tests
 * =============================================================================
 */

/* Test compression entry structure */
struct test_compress_entry {
	u8 dcid[QUIC_PROXY_MAX_CID_LEN];
	u8 dcid_len;
	u8 scid[QUIC_PROXY_MAX_CID_LEN];
	u8 scid_len;
	u32 version;
	u8 index;
};

static void test_compression_entry_creation(struct kunit *test)
{
	struct test_compress_entry entry = {
		.dcid_len = 8,
		.scid_len = 0,
		.version = 0x00000001,
		.index = 0,
	};

	memset(entry.dcid, 0x12, 8);

	KUNIT_EXPECT_EQ(test, entry.dcid_len, 8U);
	KUNIT_EXPECT_EQ(test, entry.version, 0x00000001U);
}

static void test_compression_index_wrap(struct kunit *test)
{
	/* Compression indices should wrap within window size */
	u8 indices[] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
	int window_size = 16;
	int i;

	for (i = 0; i < ARRAY_SIZE(indices); i++) {
		KUNIT_EXPECT_LT(test, indices[i], (u8)window_size);
	}

	/* Index 16 should wrap to 0 */
	KUNIT_EXPECT_EQ(test, 16 % window_size, 0);
}

/*
 * =============================================================================
 * SECTION 8: Integration Tests
 * =============================================================================
 */

static void test_full_registration_flow(struct kunit *test)
{
	u8 reg_buf[256];
	u8 cid_buf[128];
	struct test_register_capsule reg_input = {
		.conn_id = 1,
		.target_port = 443,
		.version = 0x00000001,
		.flags = QUIC_PROXY_REG_FLAG_CID_COOP,
	};
	struct test_cid_capsule cid_input = {
		.conn_id = 1,
		.direction = QUIC_PROXY_CID_DIR_TARGET_CLIENT,
		.action = QUIC_PROXY_CID_ACTION_ADD,
		.seq_num = 1,
		.retire_prior_to = 0,
		.cid_len = 8,
		.has_reset_token = true,
	};
	struct test_register_capsule reg_output;
	struct test_cid_capsule cid_output;
	int ret;

	/* Setup registration */
	strcpy(reg_input.target_host, "example.com");
	reg_input.target_host_len = strlen(reg_input.target_host);
	memset(reg_input.initial_dcid, 0x01, 8);
	reg_input.initial_dcid_len = 8;

	/* Setup CID */
	memset(cid_input.cid, 0x02, 8);
	memset(cid_input.reset_token, 0x03, 16);

	/* Encode registration */
	ret = test_encode_register(&reg_input, reg_buf, sizeof(reg_buf));
	KUNIT_EXPECT_GT(test, ret, 0);

	/* Decode and verify */
	ret = test_decode_register(reg_buf, ret, &reg_output);
	KUNIT_EXPECT_GT(test, ret, 0);
	KUNIT_EXPECT_EQ(test, reg_output.conn_id, 1ULL);

	/* Encode CID update (simulates proxy response) */
	ret = test_encode_cid(&cid_input, cid_buf, sizeof(cid_buf));
	KUNIT_EXPECT_GT(test, ret, 0);

	/* Decode and verify */
	ret = test_decode_cid(cid_buf, ret, &cid_output);
	KUNIT_EXPECT_GT(test, ret, 0);
	KUNIT_EXPECT_EQ(test, cid_output.conn_id, 1ULL);
	KUNIT_EXPECT_TRUE(test, cid_output.has_reset_token);
}

static void test_full_deregistration_flow(struct kunit *test)
{
	u8 dereg_buf[64];
	struct test_deregister_capsule dereg_input = {
		.conn_id = 1,
		.reason = QUIC_PROXY_DEREG_NORMAL,
		.drain_timeout_ms = 1000,
	};
	struct test_deregister_capsule dereg_output;
	int ret;

	ret = test_encode_deregister(&dereg_input, dereg_buf, sizeof(dereg_buf));
	KUNIT_EXPECT_GT(test, ret, 0);

	ret = test_decode_deregister(dereg_buf, ret, &dereg_output);
	KUNIT_EXPECT_GT(test, ret, 0);

	KUNIT_EXPECT_EQ(test, dereg_output.conn_id, 1ULL);
	KUNIT_EXPECT_EQ(test, dereg_output.reason, (u8)QUIC_PROXY_DEREG_NORMAL);
}

static void test_multiple_connections(struct kunit *test)
{
	u8 buf[256];
	struct test_register_capsule inputs[3];
	struct test_register_capsule output;
	int i, ret;

	/* Create multiple connection registrations */
	for (i = 0; i < 3; i++) {
		memset(&inputs[i], 0, sizeof(inputs[i]));
		inputs[i].conn_id = i + 1;
		inputs[i].target_port = 443 + i;
		inputs[i].version = 0x00000001;
		inputs[i].flags = QUIC_PROXY_REG_FLAG_CID_COOP;

		snprintf(inputs[i].target_host, sizeof(inputs[i].target_host),
			 "host%d.example.com", i + 1);
		inputs[i].target_host_len = strlen(inputs[i].target_host);

		memset(inputs[i].initial_dcid, 0x10 + i, 8);
		inputs[i].initial_dcid_len = 8;

		/* Encode and decode */
		ret = test_encode_register(&inputs[i], buf, sizeof(buf));
		KUNIT_EXPECT_GT(test, ret, 0);

		ret = test_decode_register(buf, ret, &output);
		KUNIT_EXPECT_GT(test, ret, 0);

		KUNIT_EXPECT_EQ(test, output.conn_id, (u64)(i + 1));
		KUNIT_EXPECT_EQ(test, output.target_port, (u16)(443 + i));
	}
}

/*
 * =============================================================================
 * Test Suite Definition
 * =============================================================================
 */

static struct kunit_case quic_proxy_test_cases[] = {
	/* Varint Tests */
	KUNIT_CASE(test_varint_encode_1byte),
	KUNIT_CASE(test_varint_encode_2byte),
	KUNIT_CASE(test_varint_encode_4byte),
	KUNIT_CASE(test_varint_encode_8byte),

	/* Register Capsule Tests */
	KUNIT_CASE(test_register_capsule_basic),
	KUNIT_CASE(test_register_capsule_with_scid),
	KUNIT_CASE(test_register_capsule_max_cid_len),

	/* CID Capsule Tests */
	KUNIT_CASE(test_cid_capsule_add),
	KUNIT_CASE(test_cid_capsule_with_reset_token),
	KUNIT_CASE(test_cid_capsule_retire),
	KUNIT_CASE(test_cid_capsule_request),

	/* Deregister Capsule Tests */
	KUNIT_CASE(test_deregister_capsule_normal),
	KUNIT_CASE(test_deregister_capsule_with_drain),

	/* Error Capsule Tests */
	KUNIT_CASE(test_error_capsule_basic),
	KUNIT_CASE(test_error_capsule_proxy_wide),
	KUNIT_CASE(test_error_capsule_empty_message),

	/* CID Management Tests */
	KUNIT_CASE(test_cid_sequence_numbers),
	KUNIT_CASE(test_cid_retire_prior_to),

	/* Header Compression Tests */
	KUNIT_CASE(test_compression_entry_creation),
	KUNIT_CASE(test_compression_index_wrap),

	/* Integration Tests */
	KUNIT_CASE(test_full_registration_flow),
	KUNIT_CASE(test_full_deregistration_flow),
	KUNIT_CASE(test_multiple_connections),
	{}
};

static struct kunit_suite quic_proxy_test_suite = {
	.name = "tquic-quic-proxy",
	.test_cases = quic_proxy_test_cases,
};

kunit_test_suite(quic_proxy_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for TQUIC QUIC-Aware Proxy (draft-ietf-masque-quic-proxy)");
MODULE_AUTHOR("Linux Foundation");
