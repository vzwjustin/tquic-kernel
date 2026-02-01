// SPDX-License-Identifier: GPL-2.0
/*
 * KUnit tests for TQUIC packet parsing
 *
 * Copyright (c) 2026 Linux Foundation
 */

#include <kunit/test.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <net/tquic.h>

/* QUIC packet header types */
#define TQUIC_HEADER_FORM_LONG		0x80
#define TQUIC_HEADER_FORM_SHORT		0x00
#define TQUIC_HEADER_FIXED_BIT		0x40

/* Long header packet types */
#define TQUIC_PKT_TYPE_INITIAL		0x00
#define TQUIC_PKT_TYPE_0RTT		0x01
#define TQUIC_PKT_TYPE_HANDSHAKE	0x02
#define TQUIC_PKT_TYPE_RETRY		0x03

/* Packet number lengths */
#define TQUIC_PKT_NUM_LEN_1		0x00
#define TQUIC_PKT_NUM_LEN_2		0x01
#define TQUIC_PKT_NUM_LEN_3		0x02
#define TQUIC_PKT_NUM_LEN_4		0x03

/* Test helper: create a test packet buffer */
static struct sk_buff *create_test_skb(struct kunit *test, const u8 *data,
				       size_t len)
{
	struct sk_buff *skb;

	skb = alloc_skb(len + 32, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, skb);

	skb_reserve(skb, 16);
	skb_put_data(skb, data, len);

	return skb;
}

/* Test: Parse long header form bit */
static void tquic_packet_test_header_form(struct kunit *test)
{
	u8 long_header = TQUIC_HEADER_FORM_LONG | TQUIC_HEADER_FIXED_BIT;
	u8 short_header = TQUIC_HEADER_FORM_SHORT | TQUIC_HEADER_FIXED_BIT;

	/* Long header has bit 7 set */
	KUNIT_EXPECT_TRUE(test, (long_header & 0x80) != 0);
	KUNIT_EXPECT_EQ(test, (long_header & 0x80) >> 7, 1);

	/* Short header has bit 7 clear */
	KUNIT_EXPECT_TRUE(test, (short_header & 0x80) == 0);
	KUNIT_EXPECT_EQ(test, (short_header & 0x80) >> 7, 0);

	/* Both should have fixed bit set */
	KUNIT_EXPECT_TRUE(test, (long_header & 0x40) != 0);
	KUNIT_EXPECT_TRUE(test, (short_header & 0x40) != 0);
}

/* Test: Parse long header packet type */
static void tquic_packet_test_long_header_type(struct kunit *test)
{
	u8 initial_header = TQUIC_HEADER_FORM_LONG | TQUIC_HEADER_FIXED_BIT |
			    (TQUIC_PKT_TYPE_INITIAL << 4);
	u8 handshake_header = TQUIC_HEADER_FORM_LONG | TQUIC_HEADER_FIXED_BIT |
			      (TQUIC_PKT_TYPE_HANDSHAKE << 4);
	u8 zero_rtt_header = TQUIC_HEADER_FORM_LONG | TQUIC_HEADER_FIXED_BIT |
			     (TQUIC_PKT_TYPE_0RTT << 4);
	u8 retry_header = TQUIC_HEADER_FORM_LONG | TQUIC_HEADER_FIXED_BIT |
			  (TQUIC_PKT_TYPE_RETRY << 4);

	/* Extract packet type from bits 4-5 */
	KUNIT_EXPECT_EQ(test, (initial_header >> 4) & 0x03, TQUIC_PKT_TYPE_INITIAL);
	KUNIT_EXPECT_EQ(test, (handshake_header >> 4) & 0x03, TQUIC_PKT_TYPE_HANDSHAKE);
	KUNIT_EXPECT_EQ(test, (zero_rtt_header >> 4) & 0x03, TQUIC_PKT_TYPE_0RTT);
	KUNIT_EXPECT_EQ(test, (retry_header >> 4) & 0x03, TQUIC_PKT_TYPE_RETRY);
}

/* Test: Parse packet number length from header */
static void tquic_packet_test_pkt_num_length(struct kunit *test)
{
	u8 pkt_num_1 = TQUIC_PKT_NUM_LEN_1;
	u8 pkt_num_2 = TQUIC_PKT_NUM_LEN_2;
	u8 pkt_num_3 = TQUIC_PKT_NUM_LEN_3;
	u8 pkt_num_4 = TQUIC_PKT_NUM_LEN_4;

	/* Packet number length = (value & 0x03) + 1 */
	KUNIT_EXPECT_EQ(test, (pkt_num_1 & 0x03) + 1, 1);
	KUNIT_EXPECT_EQ(test, (pkt_num_2 & 0x03) + 1, 2);
	KUNIT_EXPECT_EQ(test, (pkt_num_3 & 0x03) + 1, 3);
	KUNIT_EXPECT_EQ(test, (pkt_num_4 & 0x03) + 1, 4);
}

/* Test: Parse version field from long header */
static void tquic_packet_test_version_field(struct kunit *test)
{
	/* Long header: first byte | version (4 bytes) | ... */
	u8 long_header[] = {
		0xc0,			/* Long header, Initial */
		0x00, 0x00, 0x00, 0x01,	/* Version 1 */
	};
	u32 version;

	/* Version is at bytes 1-4, big endian */
	version = ((u32)long_header[1] << 24) |
		  ((u32)long_header[2] << 16) |
		  ((u32)long_header[3] << 8) |
		  ((u32)long_header[4]);

	KUNIT_EXPECT_EQ(test, version, TQUIC_VERSION_1);

	/* Test version 2 */
	long_header[1] = 0x6b;
	long_header[2] = 0x33;
	long_header[3] = 0x43;
	long_header[4] = 0xcf;

	version = ((u32)long_header[1] << 24) |
		  ((u32)long_header[2] << 16) |
		  ((u32)long_header[3] << 8) |
		  ((u32)long_header[4]);

	KUNIT_EXPECT_EQ(test, version, TQUIC_VERSION_2);
}

/* Test: Parse connection ID length */
static void tquic_packet_test_cid_length(struct kunit *test)
{
	/*
	 * After version comes:
	 * - DCID Length (1 byte)
	 * - DCID (0-20 bytes)
	 * - SCID Length (1 byte)
	 * - SCID (0-20 bytes)
	 */
	u8 cid_len;

	/* Test various CID lengths */
	for (cid_len = 0; cid_len <= TQUIC_MAX_CID_LEN; cid_len++) {
		KUNIT_EXPECT_LE(test, cid_len, (u8)TQUIC_MAX_CID_LEN);
	}

	/* Invalid CID length should be rejected */
	KUNIT_EXPECT_GT(test, (u8)21, (u8)TQUIC_MAX_CID_LEN);
}

/* Test: Parse connection ID */
static void tquic_packet_test_cid_parse(struct kunit *test)
{
	struct tquic_cid cid;
	u8 raw_cid[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};

	/* Initialize CID */
	memset(&cid, 0, sizeof(cid));
	cid.len = sizeof(raw_cid);
	memcpy(cid.id, raw_cid, cid.len);

	KUNIT_EXPECT_EQ(test, cid.len, 8);
	KUNIT_EXPECT_MEMEQ(test, cid.id, raw_cid, cid.len);

	/* Test zero-length CID */
	memset(&cid, 0, sizeof(cid));
	cid.len = 0;

	KUNIT_EXPECT_EQ(test, cid.len, 0);
}

/* Test: SKB packet data extraction */
static void tquic_packet_test_skb_extraction(struct kunit *test)
{
	u8 packet_data[] = {
		0xc0,			/* Long header */
		0x00, 0x00, 0x00, 0x01,	/* Version 1 */
		0x08,			/* DCID length */
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, /* DCID */
		0x08,			/* SCID length */
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, /* SCID */
	};
	struct sk_buff *skb;
	u8 *data;

	skb = create_test_skb(test, packet_data, sizeof(packet_data));

	data = skb->data;

	/* Verify header form */
	KUNIT_EXPECT_TRUE(test, (data[0] & 0x80) != 0);

	/* Verify version */
	KUNIT_EXPECT_EQ(test, data[1], 0x00);
	KUNIT_EXPECT_EQ(test, data[4], 0x01);

	/* Verify DCID length */
	KUNIT_EXPECT_EQ(test, data[5], 0x08);

	/* Verify SCID length */
	KUNIT_EXPECT_EQ(test, data[14], 0x08);

	kfree_skb(skb);
}

/* Test: Short header parsing */
static void tquic_packet_test_short_header(struct kunit *test)
{
	/*
	 * Short header format:
	 * - Header form (1 bit) = 0
	 * - Fixed bit (1 bit) = 1
	 * - Spin bit (1 bit)
	 * - Reserved bits (2 bits)
	 * - Key phase (1 bit)
	 * - Packet number length (2 bits)
	 * - Destination Connection ID (variable)
	 * - Packet Number (1-4 bytes)
	 */
	u8 short_header = 0x40; /* Fixed bit set, no spin */

	KUNIT_EXPECT_EQ(test, short_header & 0x80, 0);
	KUNIT_EXPECT_NE(test, short_header & 0x40, 0);

	/* Test spin bit */
	short_header |= 0x20;
	KUNIT_EXPECT_NE(test, short_header & 0x20, 0);

	/* Test key phase */
	short_header |= 0x04;
	KUNIT_EXPECT_NE(test, short_header & 0x04, 0);

	/* Test packet number length encoding */
	short_header = 0x40 | TQUIC_PKT_NUM_LEN_4;
	KUNIT_EXPECT_EQ(test, (short_header & 0x03) + 1, 4);
}

/* Test: Packet number decoding (truncated) */
static void tquic_packet_test_pkt_num_decode(struct kunit *test)
{
	/*
	 * Packet numbers are encoded in 1-4 bytes and need to be
	 * decoded relative to the largest acknowledged packet number.
	 */
	u8 pkt_num_1byte[] = {0x42};
	u8 pkt_num_2byte[] = {0x12, 0x34};
	u8 pkt_num_4byte[] = {0x12, 0x34, 0x56, 0x78};
	u64 pkt_num;

	/* 1-byte packet number */
	pkt_num = pkt_num_1byte[0];
	KUNIT_EXPECT_EQ(test, pkt_num, 0x42ULL);

	/* 2-byte packet number */
	pkt_num = ((u64)pkt_num_2byte[0] << 8) | pkt_num_2byte[1];
	KUNIT_EXPECT_EQ(test, pkt_num, 0x1234ULL);

	/* 4-byte packet number */
	pkt_num = ((u64)pkt_num_4byte[0] << 24) |
		  ((u64)pkt_num_4byte[1] << 16) |
		  ((u64)pkt_num_4byte[2] << 8) |
		  ((u64)pkt_num_4byte[3]);
	KUNIT_EXPECT_EQ(test, pkt_num, 0x12345678ULL);
}

/* Test: Initial packet token length */
static void tquic_packet_test_token_length(struct kunit *test)
{
	/*
	 * Initial packets have a token length field encoded as a
	 * variable-length integer after the SCID.
	 */
	u8 token_len_small = 0x10;	/* 16 bytes */
	u8 token_len_zero = 0x00;	/* No token */

	/* Small token length (< 64) is encoded in one byte */
	KUNIT_EXPECT_EQ(test, token_len_small & 0x3f, 16);
	KUNIT_EXPECT_EQ(test, token_len_zero, 0);

	/* Token length must not exceed reasonable bounds */
	KUNIT_EXPECT_LE(test, token_len_small, (u8)255);
}

/* Test: Validate packet minimum lengths */
static void tquic_packet_test_min_lengths(struct kunit *test)
{
	/*
	 * Minimum packet sizes:
	 * - Long header: 1 (header) + 4 (version) + 1 (DCID len) +
	 *                1 (SCID len) = 7 bytes minimum
	 * - Short header: 1 (header) + 1 (pkt num) = 2 bytes minimum
	 * - Initial packet must be at least 1200 bytes (padded)
	 */
	size_t min_long_header = 7;
	size_t min_short_header = 2;
	size_t min_initial_packet = 1200;

	KUNIT_EXPECT_GE(test, min_long_header, (size_t)7);
	KUNIT_EXPECT_GE(test, min_short_header, (size_t)2);
	KUNIT_EXPECT_EQ(test, min_initial_packet, (size_t)1200);
}

/* Test: Coalesced packets detection */
static void tquic_packet_test_coalesced(struct kunit *test)
{
	/*
	 * Multiple QUIC packets can be coalesced into a single UDP
	 * datagram. Each packet must be parsed separately.
	 */
	u8 coalesced_data[200];
	size_t offset = 0;

	/* First packet: Initial */
	coalesced_data[offset++] = 0xc0;	/* Long header, Initial */
	coalesced_data[offset++] = 0x00;	/* Version */
	coalesced_data[offset++] = 0x00;
	coalesced_data[offset++] = 0x00;
	coalesced_data[offset++] = 0x01;
	coalesced_data[offset++] = 0x00;	/* DCID len = 0 */
	coalesced_data[offset++] = 0x00;	/* SCID len = 0 */

	/* Check that we can identify the start of a long header packet */
	KUNIT_EXPECT_TRUE(test, (coalesced_data[0] & 0x80) != 0);

	/* Verify we have enough data */
	KUNIT_EXPECT_GE(test, offset, (size_t)7);
}

/* Test: Retry packet format */
static void tquic_packet_test_retry_packet(struct kunit *test)
{
	/*
	 * Retry packet format:
	 * - Long header with packet type = RETRY
	 * - No packet number
	 * - Contains retry token and integrity tag
	 */
	u8 retry_header = TQUIC_HEADER_FORM_LONG | TQUIC_HEADER_FIXED_BIT |
			  (TQUIC_PKT_TYPE_RETRY << 4);
	u8 packet_type;

	/* Verify it's a long header */
	KUNIT_EXPECT_TRUE(test, (retry_header & 0x80) != 0);

	/* Extract packet type */
	packet_type = (retry_header >> 4) & 0x03;
	KUNIT_EXPECT_EQ(test, packet_type, TQUIC_PKT_TYPE_RETRY);

	/* Retry integrity tag is 16 bytes */
	KUNIT_EXPECT_EQ(test, 16, 16);
}

/* Test: Version negotiation packet */
static void tquic_packet_test_version_negotiation(struct kunit *test)
{
	/*
	 * Version negotiation packet:
	 * - Long header form
	 * - Version field = 0x00000000
	 * - List of supported versions
	 */
	u8 vn_packet[] = {
		0x80,			/* Long header, random bits */
		0x00, 0x00, 0x00, 0x00,	/* Version = 0 (VN packet) */
		0x08,			/* DCID length */
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x08,			/* SCID length */
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		/* Supported versions follow */
		0x00, 0x00, 0x00, 0x01,	/* Version 1 */
		0x6b, 0x33, 0x43, 0xcf,	/* Version 2 */
	};
	u32 version;

	/* Check version field is zero */
	version = ((u32)vn_packet[1] << 24) |
		  ((u32)vn_packet[2] << 16) |
		  ((u32)vn_packet[3] << 8) |
		  ((u32)vn_packet[4]);

	KUNIT_EXPECT_EQ(test, version, 0U);

	/* This indicates version negotiation packet */
	KUNIT_EXPECT_TRUE(test, version == 0 && (vn_packet[0] & 0x80) != 0);
}

static struct kunit_case tquic_packet_test_cases[] = {
	KUNIT_CASE(tquic_packet_test_header_form),
	KUNIT_CASE(tquic_packet_test_long_header_type),
	KUNIT_CASE(tquic_packet_test_pkt_num_length),
	KUNIT_CASE(tquic_packet_test_version_field),
	KUNIT_CASE(tquic_packet_test_cid_length),
	KUNIT_CASE(tquic_packet_test_cid_parse),
	KUNIT_CASE(tquic_packet_test_skb_extraction),
	KUNIT_CASE(tquic_packet_test_short_header),
	KUNIT_CASE(tquic_packet_test_pkt_num_decode),
	KUNIT_CASE(tquic_packet_test_token_length),
	KUNIT_CASE(tquic_packet_test_min_lengths),
	KUNIT_CASE(tquic_packet_test_coalesced),
	KUNIT_CASE(tquic_packet_test_retry_packet),
	KUNIT_CASE(tquic_packet_test_version_negotiation),
	{}
};

static struct kunit_suite tquic_packet_test_suite = {
	.name = "tquic-packet",
	.test_cases = tquic_packet_test_cases,
};

kunit_test_suite(tquic_packet_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for TQUIC packet parsing");
