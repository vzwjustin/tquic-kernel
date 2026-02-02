// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Additional Addresses Transport Parameter Extension - KUnit Tests
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Unit tests for the additional_addresses transport parameter extension
 * (draft-piraux-quic-additional-addresses).
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <net/tquic.h>

#include "../core/additional_addresses.h"

/*
 * =============================================================================
 * TEST FIXTURES AND HELPERS
 * =============================================================================
 */

static struct tquic_additional_addresses *create_test_addrs(struct kunit *test)
{
	struct tquic_additional_addresses *addrs;

	addrs = kunit_kzalloc(test, sizeof(*addrs), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, addrs);

	tquic_additional_addr_init(addrs);

	return addrs;
}

static void make_ipv4_addr(struct sockaddr_in *sin, u32 ip, u16 port)
{
	memset(sin, 0, sizeof(*sin));
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = htonl(ip);
	sin->sin_port = htons(port);
}

static void make_ipv6_addr(struct sockaddr_in6 *sin6, const u8 *ip, u16 port)
{
	memset(sin6, 0, sizeof(*sin6));
	sin6->sin6_family = AF_INET6;
	memcpy(&sin6->sin6_addr, ip, 16);
	sin6->sin6_port = htons(port);
}

static void make_cid(struct tquic_cid *cid, u8 len, u8 fill)
{
	cid->len = len;
	memset(cid->id, fill, len);
}

/*
 * =============================================================================
 * INITIALIZATION TESTS
 * =============================================================================
 */

static void test_additional_addr_init(struct kunit *test)
{
	struct tquic_additional_addresses addrs;

	tquic_additional_addr_init(&addrs);

	KUNIT_EXPECT_EQ(test, addrs.count, (u8)0);
	KUNIT_EXPECT_EQ(test, addrs.max_count, (u8)TQUIC_MAX_ADDITIONAL_ADDRESSES);
	KUNIT_EXPECT_EQ(test, addrs.seq_num_base, (u64)2);
	KUNIT_EXPECT_TRUE(test, list_empty(&addrs.addresses));
}

static void test_additional_addr_cleanup(struct kunit *test)
{
	struct tquic_additional_addresses *addrs;
	struct sockaddr_in sin;
	struct tquic_cid cid;
	int ret;

	addrs = create_test_addrs(test);

	/* Add some addresses */
	make_ipv4_addr(&sin, 0xC0A80101, 4433);  /* 192.168.1.1:4433 */
	make_cid(&cid, 8, 0x42);

	ret = tquic_additional_addr_add_ipv4(addrs, &sin, &cid, NULL);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, addrs->count, (u8)1);

	/* Cleanup */
	tquic_additional_addr_cleanup(addrs);

	KUNIT_EXPECT_EQ(test, addrs->count, (u8)0);
	KUNIT_EXPECT_TRUE(test, list_empty(&addrs->addresses));
}

/*
 * =============================================================================
 * ADDRESS MANAGEMENT TESTS
 * =============================================================================
 */

static void test_additional_addr_add_ipv4(struct kunit *test)
{
	struct tquic_additional_addresses *addrs;
	struct sockaddr_in sin;
	struct tquic_cid cid;
	int ret;

	addrs = create_test_addrs(test);

	make_ipv4_addr(&sin, 0xC0A80101, 4433);
	make_cid(&cid, 8, 0x42);

	ret = tquic_additional_addr_add_ipv4(addrs, &sin, &cid, NULL);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, addrs->count, (u8)1);

	tquic_additional_addr_cleanup(addrs);
}

static void test_additional_addr_add_ipv6(struct kunit *test)
{
	struct tquic_additional_addresses *addrs;
	struct sockaddr_in6 sin6;
	struct tquic_cid cid;
	u8 ipv6_addr[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
			     0, 0, 0, 0, 0, 0, 0, 1 };
	int ret;

	addrs = create_test_addrs(test);

	make_ipv6_addr(&sin6, ipv6_addr, 4433);
	make_cid(&cid, 8, 0x43);

	ret = tquic_additional_addr_add_ipv6(addrs, &sin6, &cid, NULL);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, addrs->count, (u8)1);

	tquic_additional_addr_cleanup(addrs);
}

static void test_additional_addr_add_multiple(struct kunit *test)
{
	struct tquic_additional_addresses *addrs;
	struct sockaddr_in sin;
	struct tquic_cid cid;
	int ret, i;

	addrs = create_test_addrs(test);

	for (i = 0; i < 4; i++) {
		make_ipv4_addr(&sin, 0xC0A80101 + i, 4433 + i);
		make_cid(&cid, 8, 0x40 + i);

		ret = tquic_additional_addr_add_ipv4(addrs, &sin, &cid, NULL);
		KUNIT_EXPECT_EQ(test, ret, 0);
	}

	KUNIT_EXPECT_EQ(test, addrs->count, (u8)4);

	tquic_additional_addr_cleanup(addrs);
}

static void test_additional_addr_add_duplicate(struct kunit *test)
{
	struct tquic_additional_addresses *addrs;
	struct sockaddr_in sin;
	struct tquic_cid cid;
	int ret;

	addrs = create_test_addrs(test);

	make_ipv4_addr(&sin, 0xC0A80101, 4433);
	make_cid(&cid, 8, 0x42);

	ret = tquic_additional_addr_add_ipv4(addrs, &sin, &cid, NULL);
	KUNIT_EXPECT_EQ(test, ret, 0);

	/* Try to add duplicate */
	ret = tquic_additional_addr_add_ipv4(addrs, &sin, &cid, NULL);
	KUNIT_EXPECT_EQ(test, ret, -EEXIST);
	KUNIT_EXPECT_EQ(test, addrs->count, (u8)1);

	tquic_additional_addr_cleanup(addrs);
}

static void test_additional_addr_add_max_exceeded(struct kunit *test)
{
	struct tquic_additional_addresses *addrs;
	struct sockaddr_in sin;
	struct tquic_cid cid;
	int ret, i;

	addrs = create_test_addrs(test);
	addrs->max_count = 3;  /* Limit to 3 for testing */

	for (i = 0; i < 3; i++) {
		make_ipv4_addr(&sin, 0xC0A80100 + i, 4433 + i);
		make_cid(&cid, 8, 0x40 + i);

		ret = tquic_additional_addr_add_ipv4(addrs, &sin, &cid, NULL);
		KUNIT_EXPECT_EQ(test, ret, 0);
	}

	/* Try to add one more */
	make_ipv4_addr(&sin, 0xC0A80199, 5000);
	make_cid(&cid, 8, 0x99);

	ret = tquic_additional_addr_add_ipv4(addrs, &sin, &cid, NULL);
	KUNIT_EXPECT_EQ(test, ret, -ENOSPC);
	KUNIT_EXPECT_EQ(test, addrs->count, (u8)3);

	tquic_additional_addr_cleanup(addrs);
}

static void test_additional_addr_remove(struct kunit *test)
{
	struct tquic_additional_addresses *addrs;
	struct sockaddr_storage ss;
	struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
	struct tquic_cid cid;
	int ret;

	addrs = create_test_addrs(test);

	make_ipv4_addr(sin, 0xC0A80101, 4433);
	make_cid(&cid, 8, 0x42);

	ret = tquic_additional_addr_add_ipv4(addrs, sin, &cid, NULL);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, addrs->count, (u8)1);

	ret = tquic_additional_addr_remove(addrs, &ss);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, addrs->count, (u8)0);

	tquic_additional_addr_cleanup(addrs);
}

static void test_additional_addr_remove_not_found(struct kunit *test)
{
	struct tquic_additional_addresses *addrs;
	struct sockaddr_storage ss;
	struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
	struct tquic_cid cid;
	int ret;

	addrs = create_test_addrs(test);

	make_ipv4_addr(sin, 0xC0A80101, 4433);
	make_cid(&cid, 8, 0x42);

	ret = tquic_additional_addr_add_ipv4(addrs, sin, &cid, NULL);
	KUNIT_EXPECT_EQ(test, ret, 0);

	/* Try to remove different address */
	make_ipv4_addr(sin, 0xC0A80199, 5000);
	ret = tquic_additional_addr_remove(addrs, &ss);
	KUNIT_EXPECT_EQ(test, ret, -ENOENT);
	KUNIT_EXPECT_EQ(test, addrs->count, (u8)1);

	tquic_additional_addr_cleanup(addrs);
}

static void test_additional_addr_find(struct kunit *test)
{
	struct tquic_additional_addresses *addrs;
	struct tquic_additional_address *found;
	struct sockaddr_storage ss;
	struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
	struct tquic_cid cid;
	int ret;

	addrs = create_test_addrs(test);

	make_ipv4_addr(sin, 0xC0A80101, 4433);
	make_cid(&cid, 8, 0x42);

	ret = tquic_additional_addr_add_ipv4(addrs, sin, &cid, NULL);
	KUNIT_EXPECT_EQ(test, ret, 0);

	found = tquic_additional_addr_find(addrs, &ss);
	KUNIT_ASSERT_NOT_NULL(test, found);
	KUNIT_EXPECT_EQ(test, found->ip_version, (u8)TQUIC_ADDR_IP_VERSION_4);
	KUNIT_EXPECT_EQ(test, found->cid.len, (u8)8);

	tquic_additional_addr_cleanup(addrs);
}

static void test_additional_addr_find_by_cid(struct kunit *test)
{
	struct tquic_additional_addresses *addrs;
	struct tquic_additional_address *found;
	struct sockaddr_in sin;
	struct tquic_cid cid;
	int ret;

	addrs = create_test_addrs(test);

	make_ipv4_addr(&sin, 0xC0A80101, 4433);
	make_cid(&cid, 8, 0x42);

	ret = tquic_additional_addr_add_ipv4(addrs, &sin, &cid, NULL);
	KUNIT_EXPECT_EQ(test, ret, 0);

	found = tquic_additional_addr_find_by_cid(addrs, &cid);
	KUNIT_ASSERT_NOT_NULL(test, found);
	KUNIT_EXPECT_EQ(test, found->ip_version, (u8)TQUIC_ADDR_IP_VERSION_4);

	/* Search for non-existent CID */
	make_cid(&cid, 8, 0x99);
	found = tquic_additional_addr_find_by_cid(addrs, &cid);
	KUNIT_EXPECT_NULL(test, found);

	tquic_additional_addr_cleanup(addrs);
}

/*
 * =============================================================================
 * ENCODING AND DECODING TESTS
 * =============================================================================
 */

static void test_additional_addr_encode_empty(struct kunit *test)
{
	struct tquic_additional_addresses addrs;
	u8 buf[256];
	ssize_t len;

	tquic_additional_addr_init(&addrs);

	len = tquic_additional_addr_encode(&addrs, buf, sizeof(buf));
	KUNIT_EXPECT_EQ(test, len, (ssize_t)0);
}

static void test_additional_addr_encode_ipv4(struct kunit *test)
{
	struct tquic_additional_addresses *addrs;
	struct sockaddr_in sin;
	struct tquic_cid cid;
	u8 *buf;
	ssize_t len;
	int ret;

	addrs = create_test_addrs(test);
	buf = kunit_kzalloc(test, 256, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buf);

	make_ipv4_addr(&sin, 0xC0A80101, 4433);  /* 192.168.1.1:4433 */
	make_cid(&cid, 8, 0x42);

	ret = tquic_additional_addr_add_ipv4(addrs, &sin, &cid, NULL);
	KUNIT_EXPECT_EQ(test, ret, 0);

	len = tquic_additional_addr_encode(addrs, buf, 256);
	KUNIT_ASSERT_GT(test, len, (ssize_t)0);

	/* Verify structure:
	 * 1 byte IP version + 4 bytes addr + 2 bytes port +
	 * 1 byte CID len + 8 bytes CID + 16 bytes token = 32 bytes
	 */
	KUNIT_EXPECT_EQ(test, len, (ssize_t)32);

	/* Verify IP version */
	KUNIT_EXPECT_EQ(test, buf[0], (u8)TQUIC_ADDR_IP_VERSION_4);

	/* Verify address (network byte order) */
	KUNIT_EXPECT_EQ(test, buf[1], (u8)0xC0);  /* 192 */
	KUNIT_EXPECT_EQ(test, buf[2], (u8)0xA8);  /* 168 */
	KUNIT_EXPECT_EQ(test, buf[3], (u8)0x01);  /* 1 */
	KUNIT_EXPECT_EQ(test, buf[4], (u8)0x01);  /* 1 */

	/* Verify port (big-endian) */
	KUNIT_EXPECT_EQ(test, buf[5], (u8)0x11);  /* 4433 >> 8 */
	KUNIT_EXPECT_EQ(test, buf[6], (u8)0x51);  /* 4433 & 0xff */

	/* Verify CID length */
	KUNIT_EXPECT_EQ(test, buf[7], (u8)8);

	tquic_additional_addr_cleanup(addrs);
}

static void test_additional_addr_encode_ipv6(struct kunit *test)
{
	struct tquic_additional_addresses *addrs;
	struct sockaddr_in6 sin6;
	struct tquic_cid cid;
	u8 ipv6_addr[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
			     0, 0, 0, 0, 0, 0, 0, 1 };
	u8 *buf;
	ssize_t len;
	int ret;

	addrs = create_test_addrs(test);
	buf = kunit_kzalloc(test, 256, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buf);

	make_ipv6_addr(&sin6, ipv6_addr, 4433);
	make_cid(&cid, 8, 0x43);

	ret = tquic_additional_addr_add_ipv6(addrs, &sin6, &cid, NULL);
	KUNIT_EXPECT_EQ(test, ret, 0);

	len = tquic_additional_addr_encode(addrs, buf, 256);
	KUNIT_ASSERT_GT(test, len, (ssize_t)0);

	/* Verify structure:
	 * 1 byte IP version + 16 bytes addr + 2 bytes port +
	 * 1 byte CID len + 8 bytes CID + 16 bytes token = 44 bytes
	 */
	KUNIT_EXPECT_EQ(test, len, (ssize_t)44);

	/* Verify IP version */
	KUNIT_EXPECT_EQ(test, buf[0], (u8)TQUIC_ADDR_IP_VERSION_6);

	tquic_additional_addr_cleanup(addrs);
}

static void test_additional_addr_encode_decode_roundtrip(struct kunit *test)
{
	struct tquic_additional_addresses *orig, *decoded;
	struct sockaddr_in sin;
	struct tquic_cid cid;
	u8 token[16] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };
	u8 *buf;
	ssize_t encoded_len;
	int ret;

	orig = create_test_addrs(test);
	decoded = create_test_addrs(test);
	buf = kunit_kzalloc(test, 256, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buf);

	/* Add address to original */
	make_ipv4_addr(&sin, 0xC0A80101, 4433);
	make_cid(&cid, 8, 0x42);

	ret = tquic_additional_addr_add_ipv4(orig, &sin, &cid, token);
	KUNIT_EXPECT_EQ(test, ret, 0);

	/* Encode */
	encoded_len = tquic_additional_addr_encode(orig, buf, 256);
	KUNIT_ASSERT_GT(test, encoded_len, (ssize_t)0);

	/* Decode */
	ret = tquic_additional_addr_decode(buf, encoded_len, decoded);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, decoded->count, (u8)1);

	/* Verify decoded content */
	{
		struct tquic_additional_address *entry;
		struct sockaddr_in *decoded_sin;

		entry = list_first_entry(&decoded->addresses,
					 struct tquic_additional_address, list);
		KUNIT_ASSERT_NOT_NULL(test, entry);

		KUNIT_EXPECT_EQ(test, entry->ip_version, (u8)TQUIC_ADDR_IP_VERSION_4);
		KUNIT_EXPECT_EQ(test, entry->cid.len, (u8)8);

		decoded_sin = (struct sockaddr_in *)&entry->addr;
		KUNIT_EXPECT_EQ(test, decoded_sin->sin_addr.s_addr,
				htonl(0xC0A80101));
		KUNIT_EXPECT_EQ(test, ntohs(decoded_sin->sin_port), (u16)4433);

		KUNIT_EXPECT_EQ(test, memcmp(entry->stateless_reset_token, token, 16), 0);
	}

	tquic_additional_addr_cleanup(orig);
	tquic_additional_addr_cleanup(decoded);
}

static void test_additional_addr_decode_multiple(struct kunit *test)
{
	struct tquic_additional_addresses *orig, *decoded;
	struct sockaddr_in sin;
	struct tquic_cid cid;
	u8 *buf;
	ssize_t encoded_len;
	int ret, i;

	orig = create_test_addrs(test);
	decoded = create_test_addrs(test);
	buf = kunit_kzalloc(test, 512, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buf);

	/* Add multiple addresses */
	for (i = 0; i < 3; i++) {
		make_ipv4_addr(&sin, 0xC0A80101 + i, 4433 + i);
		make_cid(&cid, 8, 0x40 + i);

		ret = tquic_additional_addr_add_ipv4(orig, &sin, &cid, NULL);
		KUNIT_EXPECT_EQ(test, ret, 0);
	}

	/* Encode */
	encoded_len = tquic_additional_addr_encode(orig, buf, 512);
	KUNIT_ASSERT_GT(test, encoded_len, (ssize_t)0);

	/* Decode */
	ret = tquic_additional_addr_decode(buf, encoded_len, decoded);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, decoded->count, (u8)3);

	tquic_additional_addr_cleanup(orig);
	tquic_additional_addr_cleanup(decoded);
}

static void test_additional_addr_decode_malformed(struct kunit *test)
{
	struct tquic_additional_addresses *decoded;
	u8 buf[4] = { 0x04, 0xC0, 0xA8, 0x01 };  /* Truncated IPv4 */
	int ret;

	decoded = create_test_addrs(test);

	ret = tquic_additional_addr_decode(buf, sizeof(buf), decoded);
	KUNIT_EXPECT_NE(test, ret, 0);
	KUNIT_EXPECT_EQ(test, decoded->count, (u8)0);

	tquic_additional_addr_cleanup(decoded);
}

static void test_additional_addr_decode_invalid_version(struct kunit *test)
{
	struct tquic_additional_addresses *decoded;
	u8 buf[40];
	int ret;

	decoded = create_test_addrs(test);

	/* Create buffer with invalid IP version (5) */
	memset(buf, 0, sizeof(buf));
	buf[0] = 5;  /* Invalid IP version */

	ret = tquic_additional_addr_decode(buf, sizeof(buf), decoded);
	KUNIT_EXPECT_NE(test, ret, 0);

	tquic_additional_addr_cleanup(decoded);
}

/*
 * =============================================================================
 * ADDRESS VALIDATION TESTS
 * =============================================================================
 */

static void test_additional_addr_is_valid_ipv4(struct kunit *test)
{
	struct sockaddr_in sin;

	/* Valid address */
	make_ipv4_addr(&sin, 0xC0A80101, 4433);
	KUNIT_EXPECT_TRUE(test, tquic_additional_addr_is_valid_ipv4(&sin));

	/* Invalid: zero address */
	make_ipv4_addr(&sin, 0x00000000, 4433);
	KUNIT_EXPECT_FALSE(test, tquic_additional_addr_is_valid_ipv4(&sin));

	/* Invalid: zero port */
	make_ipv4_addr(&sin, 0xC0A80101, 0);
	KUNIT_EXPECT_FALSE(test, tquic_additional_addr_is_valid_ipv4(&sin));

	/* Invalid: loopback */
	make_ipv4_addr(&sin, 0x7F000001, 4433);  /* 127.0.0.1 */
	KUNIT_EXPECT_FALSE(test, tquic_additional_addr_is_valid_ipv4(&sin));

	/* Invalid: broadcast */
	make_ipv4_addr(&sin, 0xFFFFFFFF, 4433);
	KUNIT_EXPECT_FALSE(test, tquic_additional_addr_is_valid_ipv4(&sin));
}

static void test_additional_addr_is_valid_ipv6(struct kunit *test)
{
	struct sockaddr_in6 sin6;
	u8 valid_addr[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
			      0, 0, 0, 0, 0, 0, 0, 1 };
	u8 loopback[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
	u8 unspec[16] = { 0 };
	u8 linklocal[16] = { 0xfe, 0x80, 0, 0, 0, 0, 0, 0,
			     0, 0, 0, 0, 0, 0, 0, 1 };

	/* Valid address */
	make_ipv6_addr(&sin6, valid_addr, 4433);
	KUNIT_EXPECT_TRUE(test, tquic_additional_addr_is_valid_ipv6(&sin6));

	/* Invalid: unspecified (::) */
	make_ipv6_addr(&sin6, unspec, 4433);
	KUNIT_EXPECT_FALSE(test, tquic_additional_addr_is_valid_ipv6(&sin6));

	/* Invalid: loopback (::1) */
	make_ipv6_addr(&sin6, loopback, 4433);
	KUNIT_EXPECT_FALSE(test, tquic_additional_addr_is_valid_ipv6(&sin6));

	/* Invalid: zero port */
	make_ipv6_addr(&sin6, valid_addr, 0);
	KUNIT_EXPECT_FALSE(test, tquic_additional_addr_is_valid_ipv6(&sin6));

	/* Invalid: link-local */
	make_ipv6_addr(&sin6, linklocal, 4433);
	KUNIT_EXPECT_FALSE(test, tquic_additional_addr_is_valid_ipv6(&sin6));
}

/*
 * =============================================================================
 * ADDRESS SELECTION TESTS
 * =============================================================================
 */

static void test_additional_addr_select_priority(struct kunit *test)
{
	struct tquic_additional_addresses *addrs;
	struct tquic_additional_address *selected;
	struct sockaddr_in sin;
	struct tquic_cid cid;
	int i;

	addrs = create_test_addrs(test);

	/* Add addresses with different priorities */
	for (i = 0; i < 3; i++) {
		make_ipv4_addr(&sin, 0xC0A80101 + i, 4433 + i);
		make_cid(&cid, 8, 0x40 + i);
		tquic_additional_addr_add_ipv4(addrs, &sin, &cid, NULL);
	}

	/* Set priorities (index 1 has lowest = best) */
	{
		struct tquic_additional_address *entry;
		u8 prio = 10;

		list_for_each_entry(entry, &addrs->addresses, list) {
			entry->priority = prio;
			prio -= 3;  /* 10, 7, 4 */
		}
	}

	selected = tquic_additional_addr_select(addrs, TQUIC_ADDR_SELECT_PRIORITY,
						AF_UNSPEC);
	KUNIT_ASSERT_NOT_NULL(test, selected);
	KUNIT_EXPECT_EQ(test, selected->priority, (u8)4);

	tquic_additional_addr_cleanup(addrs);
}

static void test_additional_addr_select_same_family(struct kunit *test)
{
	struct tquic_additional_addresses *addrs;
	struct tquic_additional_address *selected;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
	struct tquic_cid cid;
	u8 ipv6_addr[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
			     0, 0, 0, 0, 0, 0, 0, 1 };

	addrs = create_test_addrs(test);

	/* Add IPv6 first */
	make_ipv6_addr(&sin6, ipv6_addr, 4433);
	make_cid(&cid, 8, 0x60);
	tquic_additional_addr_add_ipv6(addrs, &sin6, &cid, NULL);

	/* Add IPv4 second */
	make_ipv4_addr(&sin, 0xC0A80101, 4433);
	make_cid(&cid, 8, 0x40);
	tquic_additional_addr_add_ipv4(addrs, &sin, &cid, NULL);

	/* Select same family as IPv4 */
	selected = tquic_additional_addr_select(addrs, TQUIC_ADDR_SELECT_SAME_FAMILY,
						AF_INET);
	KUNIT_ASSERT_NOT_NULL(test, selected);
	KUNIT_EXPECT_EQ(test, selected->ip_version, (u8)TQUIC_ADDR_IP_VERSION_4);

	/* Select same family as IPv6 */
	selected = tquic_additional_addr_select(addrs, TQUIC_ADDR_SELECT_SAME_FAMILY,
						AF_INET6);
	KUNIT_ASSERT_NOT_NULL(test, selected);
	KUNIT_EXPECT_EQ(test, selected->ip_version, (u8)TQUIC_ADDR_IP_VERSION_6);

	tquic_additional_addr_cleanup(addrs);
}

static void test_additional_addr_select_best_rtt(struct kunit *test)
{
	struct tquic_additional_addresses *addrs;
	struct tquic_additional_address *selected, *entry;
	struct sockaddr_in sin;
	struct tquic_cid cid;
	int i;
	u32 rtts[] = { 50000, 10000, 30000 };  /* RTTs in microseconds */

	addrs = create_test_addrs(test);

	/* Add addresses */
	for (i = 0; i < 3; i++) {
		make_ipv4_addr(&sin, 0xC0A80101 + i, 4433 + i);
		make_cid(&cid, 8, 0x40 + i);
		tquic_additional_addr_add_ipv4(addrs, &sin, &cid, NULL);
	}

	/* Set RTT estimates and mark as validated */
	i = 0;
	list_for_each_entry(entry, &addrs->addresses, list) {
		entry->rtt_estimate = rtts[i++];
		entry->validated = true;
	}

	/* Select best RTT (should be 10000) */
	selected = tquic_additional_addr_select(addrs, TQUIC_ADDR_SELECT_BEST_RTT,
						AF_UNSPEC);
	KUNIT_ASSERT_NOT_NULL(test, selected);
	KUNIT_EXPECT_EQ(test, selected->rtt_estimate, (u32)10000);

	tquic_additional_addr_cleanup(addrs);
}

/*
 * =============================================================================
 * VALIDATION STATE TESTS
 * =============================================================================
 */

static void test_additional_addr_validate_invalidate(struct kunit *test)
{
	struct tquic_additional_addresses *addrs;
	struct tquic_additional_address *entry;
	struct sockaddr_in sin;
	struct tquic_cid cid;

	addrs = create_test_addrs(test);

	make_ipv4_addr(&sin, 0xC0A80101, 4433);
	make_cid(&cid, 8, 0x42);
	tquic_additional_addr_add_ipv4(addrs, &sin, &cid, NULL);

	entry = list_first_entry(&addrs->addresses,
				 struct tquic_additional_address, list);

	/* Initially not validated */
	KUNIT_EXPECT_FALSE(test, entry->validated);
	KUNIT_EXPECT_TRUE(test, entry->active);

	/* Validate */
	tquic_additional_addr_validate(entry);
	KUNIT_EXPECT_TRUE(test, entry->validated);
	KUNIT_EXPECT_TRUE(test, entry->active);

	/* Invalidate */
	tquic_additional_addr_invalidate(entry);
	KUNIT_EXPECT_FALSE(test, entry->validated);
	KUNIT_EXPECT_FALSE(test, entry->active);

	tquic_additional_addr_cleanup(addrs);
}

static void test_additional_addr_update_rtt(struct kunit *test)
{
	struct tquic_additional_addresses *addrs;
	struct tquic_additional_address *entry;
	struct sockaddr_in sin;
	struct tquic_cid cid;

	addrs = create_test_addrs(test);

	make_ipv4_addr(&sin, 0xC0A80101, 4433);
	make_cid(&cid, 8, 0x42);
	tquic_additional_addr_add_ipv4(addrs, &sin, &cid, NULL);

	entry = list_first_entry(&addrs->addresses,
				 struct tquic_additional_address, list);

	/* Initially zero */
	KUNIT_EXPECT_EQ(test, entry->rtt_estimate, (u32)0);

	/* First update sets directly */
	tquic_additional_addr_update_rtt(entry, 10000);
	KUNIT_EXPECT_EQ(test, entry->rtt_estimate, (u32)10000);

	/* Subsequent updates use exponential smoothing */
	tquic_additional_addr_update_rtt(entry, 20000);
	/* (10000 * 7 + 20000) / 8 = 11250 */
	KUNIT_EXPECT_EQ(test, entry->rtt_estimate, (u32)11250);

	tquic_additional_addr_cleanup(addrs);
}

/*
 * =============================================================================
 * ENCODED SIZE TESTS
 * =============================================================================
 */

static void test_additional_addr_encoded_size(struct kunit *test)
{
	struct tquic_additional_addresses *addrs;
	struct sockaddr_in sin;
	struct sockaddr_in6 sin6;
	struct tquic_cid cid;
	u8 ipv6_addr[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
			     0, 0, 0, 0, 0, 0, 0, 1 };
	size_t size;

	addrs = create_test_addrs(test);

	/* Empty list */
	size = tquic_additional_addr_encoded_size(addrs);
	KUNIT_EXPECT_EQ(test, size, (size_t)0);

	/* Add IPv4 (8-byte CID) */
	make_ipv4_addr(&sin, 0xC0A80101, 4433);
	make_cid(&cid, 8, 0x42);
	tquic_additional_addr_add_ipv4(addrs, &sin, &cid, NULL);

	/* 1 + 4 + 2 + 1 + 8 + 16 = 32 */
	size = tquic_additional_addr_encoded_size(addrs);
	KUNIT_EXPECT_EQ(test, size, (size_t)32);

	/* Add IPv6 (8-byte CID) */
	make_ipv6_addr(&sin6, ipv6_addr, 4434);
	make_cid(&cid, 8, 0x43);
	tquic_additional_addr_add_ipv6(addrs, &sin6, &cid, NULL);

	/* 32 + (1 + 16 + 2 + 1 + 8 + 16) = 32 + 44 = 76 */
	size = tquic_additional_addr_encoded_size(addrs);
	KUNIT_EXPECT_EQ(test, size, (size_t)76);

	tquic_additional_addr_cleanup(addrs);
}

/*
 * =============================================================================
 * TEST SUITE DEFINITION
 * =============================================================================
 */

static struct kunit_case additional_addresses_test_cases[] = {
	/* Initialization tests */
	KUNIT_CASE(test_additional_addr_init),
	KUNIT_CASE(test_additional_addr_cleanup),

	/* Address management tests */
	KUNIT_CASE(test_additional_addr_add_ipv4),
	KUNIT_CASE(test_additional_addr_add_ipv6),
	KUNIT_CASE(test_additional_addr_add_multiple),
	KUNIT_CASE(test_additional_addr_add_duplicate),
	KUNIT_CASE(test_additional_addr_add_max_exceeded),
	KUNIT_CASE(test_additional_addr_remove),
	KUNIT_CASE(test_additional_addr_remove_not_found),
	KUNIT_CASE(test_additional_addr_find),
	KUNIT_CASE(test_additional_addr_find_by_cid),

	/* Encoding/decoding tests */
	KUNIT_CASE(test_additional_addr_encode_empty),
	KUNIT_CASE(test_additional_addr_encode_ipv4),
	KUNIT_CASE(test_additional_addr_encode_ipv6),
	KUNIT_CASE(test_additional_addr_encode_decode_roundtrip),
	KUNIT_CASE(test_additional_addr_decode_multiple),
	KUNIT_CASE(test_additional_addr_decode_malformed),
	KUNIT_CASE(test_additional_addr_decode_invalid_version),

	/* Address validation tests */
	KUNIT_CASE(test_additional_addr_is_valid_ipv4),
	KUNIT_CASE(test_additional_addr_is_valid_ipv6),

	/* Address selection tests */
	KUNIT_CASE(test_additional_addr_select_priority),
	KUNIT_CASE(test_additional_addr_select_same_family),
	KUNIT_CASE(test_additional_addr_select_best_rtt),

	/* Validation state tests */
	KUNIT_CASE(test_additional_addr_validate_invalidate),
	KUNIT_CASE(test_additional_addr_update_rtt),

	/* Encoded size tests */
	KUNIT_CASE(test_additional_addr_encoded_size),

	{}
};

static struct kunit_suite additional_addresses_test_suite = {
	.name = "tquic-additional-addresses",
	.test_cases = additional_addresses_test_cases,
};

kunit_test_suites(&additional_addresses_test_suite);

MODULE_AUTHOR("Linux Foundation");
MODULE_DESCRIPTION("TQUIC Additional Addresses Transport Parameter KUnit Tests");
MODULE_LICENSE("GPL");
