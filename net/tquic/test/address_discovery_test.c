// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Address Discovery Extension KUnit Tests
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Tests for the QUIC Address Discovery extension implementation
 * (draft-ietf-quic-address-discovery).
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <net/tquic.h>

#include "../core/address_discovery.h"
#include "../core/transport_params.h"

/*
 * =============================================================================
 * Test Fixtures
 * =============================================================================
 */

struct address_discovery_test_context {
	struct tquic_addr_discovery_state state;
	u8 encode_buf[256];
	u8 decode_buf[256];
};

static int address_discovery_test_init(struct kunit *test)
{
	struct address_discovery_test_context *ctx;

	ctx = kunit_kzalloc(test, sizeof(*ctx), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, ctx);

	test->priv = ctx;
	return 0;
}

/*
 * =============================================================================
 * State Initialization Tests
 * =============================================================================
 */

static void test_addr_discovery_init(struct kunit *test)
{
	struct address_discovery_test_context *ctx = test->priv;
	int ret;

	ret = tquic_addr_discovery_init(&ctx->state);
	KUNIT_EXPECT_EQ(test, ret, 0);

	/* Check default configuration */
	KUNIT_EXPECT_FALSE(test, ctx->state.config.enabled);
	KUNIT_EXPECT_TRUE(test, ctx->state.config.report_on_change);
	KUNIT_EXPECT_FALSE(test, ctx->state.config.report_periodically);

	/* Check initial state */
	KUNIT_EXPECT_EQ(test, ctx->state.local_send_seq, (u64)0);
	KUNIT_EXPECT_EQ(test, ctx->state.remote_recv_seq, (u64)0);
	KUNIT_EXPECT_FALSE(test, ctx->state.current_observed_valid);
	KUNIT_EXPECT_FALSE(test, ctx->state.reported_addr_valid);
	KUNIT_EXPECT_FALSE(test, ctx->state.nat_rebind_detected);

	/* Check statistics */
	KUNIT_EXPECT_EQ(test, ctx->state.frames_sent, (u64)0);
	KUNIT_EXPECT_EQ(test, ctx->state.frames_received, (u64)0);
	KUNIT_EXPECT_EQ(test, ctx->state.frames_rejected, (u64)0);

	tquic_addr_discovery_cleanup(&ctx->state);
}

static void test_addr_discovery_init_null(struct kunit *test)
{
	int ret;

	ret = tquic_addr_discovery_init(NULL);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

static void test_addr_discovery_set_config(struct kunit *test)
{
	struct address_discovery_test_context *ctx = test->priv;
	struct tquic_addr_discovery_config config;
	int ret;

	ret = tquic_addr_discovery_init(&ctx->state);
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Set new config */
	config.enabled = true;
	config.report_on_change = true;
	config.report_periodically = true;
	config.report_interval_ms = 2000;
	config.max_rate_ms = 500;

	ret = tquic_addr_discovery_set_config(&ctx->state, &config);
	KUNIT_EXPECT_EQ(test, ret, 0);

	KUNIT_EXPECT_TRUE(test, ctx->state.config.enabled);
	KUNIT_EXPECT_TRUE(test, ctx->state.config.report_periodically);
	KUNIT_EXPECT_EQ(test, ctx->state.config.report_interval_ms, (u32)2000);
	KUNIT_EXPECT_EQ(test, ctx->state.config.max_rate_ms, (u32)500);

	tquic_addr_discovery_cleanup(&ctx->state);
}

static void test_addr_discovery_config_rate_limit_validation(struct kunit *test)
{
	struct address_discovery_test_context *ctx = test->priv;
	struct tquic_addr_discovery_config config;
	int ret;

	ret = tquic_addr_discovery_init(&ctx->state);
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Rate limit below minimum (100ms) should fail */
	config.enabled = true;
	config.report_on_change = true;
	config.report_periodically = false;
	config.report_interval_ms = 1000;
	config.max_rate_ms = 50;  /* Below minimum */

	ret = tquic_addr_discovery_set_config(&ctx->state, &config);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);

	tquic_addr_discovery_cleanup(&ctx->state);
}

/*
 * =============================================================================
 * Frame Encoding Tests
 * =============================================================================
 */

static void test_encode_observed_address_ipv4(struct kunit *test)
{
	struct address_discovery_test_context *ctx = test->priv;
	struct tquic_frame_observed_address frame;
	ssize_t encoded_len;

	/* Set up IPv4 frame */
	frame.seq = 42;
	frame.ip_version = TQUIC_ADDR_DISC_IPV4;
	frame.addr.v4 = htonl(0xC0A80164);  /* 192.168.1.100 */
	frame.port = htons(4433);

	encoded_len = tquic_encode_observed_address(ctx->encode_buf,
						    sizeof(ctx->encode_buf),
						    &frame);

	/* Frame type (2) + seq (1) + version (1) + addr (4) + port (2) = 10 min */
	KUNIT_EXPECT_GT(test, encoded_len, (ssize_t)0);
	KUNIT_EXPECT_LE(test, encoded_len, (ssize_t)16);  /* Max reasonable size */
}

static void test_encode_observed_address_ipv6(struct kunit *test)
{
	struct address_discovery_test_context *ctx = test->priv;
	struct tquic_frame_observed_address frame;
	ssize_t encoded_len;

	/* Set up IPv6 frame */
	frame.seq = 1000;
	frame.ip_version = TQUIC_ADDR_DISC_IPV6;
	memset(&frame.addr.v6, 0, sizeof(frame.addr.v6));
	frame.addr.v6.s6_addr[15] = 1;  /* ::1 */
	frame.port = htons(8443);

	encoded_len = tquic_encode_observed_address(ctx->encode_buf,
						    sizeof(ctx->encode_buf),
						    &frame);

	/* Frame type (2) + seq (2) + version (1) + addr (16) + port (2) = 23 min */
	KUNIT_EXPECT_GT(test, encoded_len, (ssize_t)0);
	KUNIT_EXPECT_LE(test, encoded_len, (ssize_t)32);  /* Max reasonable size */
}

static void test_encode_observed_address_invalid_version(struct kunit *test)
{
	struct address_discovery_test_context *ctx = test->priv;
	struct tquic_frame_observed_address frame;
	ssize_t encoded_len;

	/* Set up frame with invalid IP version */
	frame.seq = 1;
	frame.ip_version = 5;  /* Invalid */
	frame.addr.v4 = htonl(0x7F000001);
	frame.port = htons(80);

	encoded_len = tquic_encode_observed_address(ctx->encode_buf,
						    sizeof(ctx->encode_buf),
						    &frame);

	KUNIT_EXPECT_EQ(test, encoded_len, (ssize_t)-EINVAL);
}

static void test_encode_observed_address_buffer_too_small(struct kunit *test)
{
	struct tquic_frame_observed_address frame;
	u8 small_buf[4];  /* Too small */
	ssize_t encoded_len;

	frame.seq = 1;
	frame.ip_version = TQUIC_ADDR_DISC_IPV4;
	frame.addr.v4 = htonl(0x7F000001);
	frame.port = htons(80);

	encoded_len = tquic_encode_observed_address(small_buf, sizeof(small_buf),
						    &frame);

	KUNIT_EXPECT_EQ(test, encoded_len, (ssize_t)-ENOSPC);
}

/*
 * =============================================================================
 * Frame Decoding Tests
 * =============================================================================
 */

static void test_decode_observed_address_ipv4(struct kunit *test)
{
	struct address_discovery_test_context *ctx = test->priv;
	struct tquic_frame_observed_address original, decoded;
	ssize_t encoded_len, decoded_len;

	/* Set up and encode */
	original.seq = 42;
	original.ip_version = TQUIC_ADDR_DISC_IPV4;
	original.addr.v4 = htonl(0xC0A80164);  /* 192.168.1.100 */
	original.port = htons(4433);

	encoded_len = tquic_encode_observed_address(ctx->encode_buf,
						    sizeof(ctx->encode_buf),
						    &original);
	KUNIT_ASSERT_GT(test, encoded_len, (ssize_t)0);

	/* Skip frame type (2 bytes for 0x9f00) */
	decoded_len = tquic_decode_observed_address(ctx->encode_buf + 2,
						    encoded_len - 2,
						    &decoded);
	KUNIT_ASSERT_GT(test, decoded_len, (ssize_t)0);

	/* Verify decoded values */
	KUNIT_EXPECT_EQ(test, decoded.seq, original.seq);
	KUNIT_EXPECT_EQ(test, decoded.ip_version, (u8)TQUIC_ADDR_DISC_IPV4);
	KUNIT_EXPECT_EQ(test, decoded.addr.v4, original.addr.v4);
	KUNIT_EXPECT_EQ(test, decoded.port, original.port);
}

static void test_decode_observed_address_ipv6(struct kunit *test)
{
	struct address_discovery_test_context *ctx = test->priv;
	struct tquic_frame_observed_address original, decoded;
	ssize_t encoded_len, decoded_len;

	/* Set up and encode */
	original.seq = 999;
	original.ip_version = TQUIC_ADDR_DISC_IPV6;
	memset(&original.addr.v6, 0, sizeof(original.addr.v6));
	original.addr.v6.s6_addr[0] = 0x20;
	original.addr.v6.s6_addr[1] = 0x01;
	original.addr.v6.s6_addr[15] = 0x01;
	original.port = htons(443);

	encoded_len = tquic_encode_observed_address(ctx->encode_buf,
						    sizeof(ctx->encode_buf),
						    &original);
	KUNIT_ASSERT_GT(test, encoded_len, (ssize_t)0);

	/* Skip frame type */
	decoded_len = tquic_decode_observed_address(ctx->encode_buf + 2,
						    encoded_len - 2,
						    &decoded);
	KUNIT_ASSERT_GT(test, decoded_len, (ssize_t)0);

	/* Verify decoded values */
	KUNIT_EXPECT_EQ(test, decoded.seq, original.seq);
	KUNIT_EXPECT_EQ(test, decoded.ip_version, (u8)TQUIC_ADDR_DISC_IPV6);
	KUNIT_EXPECT_EQ(test, memcmp(&decoded.addr.v6, &original.addr.v6, 16), 0);
	KUNIT_EXPECT_EQ(test, decoded.port, original.port);
}

static void test_decode_observed_address_truncated(struct kunit *test)
{
	u8 buf[] = { 0x01 };  /* Just sequence number, truncated */
	struct tquic_frame_observed_address decoded;
	ssize_t decoded_len;

	decoded_len = tquic_decode_observed_address(buf, sizeof(buf), &decoded);
	KUNIT_EXPECT_LT(test, decoded_len, (ssize_t)0);
}

static void test_decode_observed_address_invalid_ip_version(struct kunit *test)
{
	/* seq=1 (1 byte), version=7 (invalid), addr (4 bytes), port (2 bytes) */
	u8 buf[] = { 0x01, 0x07, 0xc0, 0xa8, 0x01, 0x01, 0x00, 0x50 };
	struct tquic_frame_observed_address decoded;
	ssize_t decoded_len;

	decoded_len = tquic_decode_observed_address(buf, sizeof(buf), &decoded);
	KUNIT_EXPECT_EQ(test, decoded_len, (ssize_t)-EPROTO);
}

/*
 * =============================================================================
 * Frame Size Calculation Tests
 * =============================================================================
 */

static void test_frame_size_ipv4(struct kunit *test)
{
	struct tquic_frame_observed_address frame;
	size_t size;

	frame.seq = 63;  /* 1-byte varint */
	frame.ip_version = TQUIC_ADDR_DISC_IPV4;
	frame.addr.v4 = htonl(0x7F000001);
	frame.port = htons(80);

	size = tquic_observed_address_frame_size(&frame);

	/* Type (2) + seq (1) + version (1) + addr (4) + port (2) = 10 */
	KUNIT_EXPECT_EQ(test, size, (size_t)10);
}

static void test_frame_size_ipv6(struct kunit *test)
{
	struct tquic_frame_observed_address frame;
	size_t size;

	frame.seq = 63;  /* 1-byte varint */
	frame.ip_version = TQUIC_ADDR_DISC_IPV6;
	memset(&frame.addr.v6, 0, 16);
	frame.port = htons(80);

	size = tquic_observed_address_frame_size(&frame);

	/* Type (2) + seq (1) + version (1) + addr (16) + port (2) = 22 */
	KUNIT_EXPECT_EQ(test, size, (size_t)22);
}

static void test_frame_size_large_seq(struct kunit *test)
{
	struct tquic_frame_observed_address frame;
	size_t size;

	frame.seq = 0x4000;  /* 4-byte varint */
	frame.ip_version = TQUIC_ADDR_DISC_IPV4;
	frame.addr.v4 = htonl(0x7F000001);
	frame.port = htons(80);

	size = tquic_observed_address_frame_size(&frame);

	/* Type (2) + seq (4) + version (1) + addr (4) + port (2) = 13 */
	KUNIT_EXPECT_EQ(test, size, (size_t)13);
}

static void test_frame_size_invalid_version(struct kunit *test)
{
	struct tquic_frame_observed_address frame;
	size_t size;

	frame.seq = 1;
	frame.ip_version = 99;  /* Invalid */
	frame.addr.v4 = htonl(0x7F000001);
	frame.port = htons(80);

	size = tquic_observed_address_frame_size(&frame);
	KUNIT_EXPECT_EQ(test, size, (size_t)0);
}

/*
 * =============================================================================
 * Address Conversion Tests
 * =============================================================================
 */

static void test_sockaddr_to_observed_ipv4(struct kunit *test)
{
	struct sockaddr_storage addr;
	struct sockaddr_in *sin = (struct sockaddr_in *)&addr;
	struct tquic_observed_address obs;
	int ret;

	memset(&addr, 0, sizeof(addr));
	sin->sin_family = AF_INET;
	sin->sin_addr.s_addr = htonl(0x0A000001);  /* 10.0.0.1 */
	sin->sin_port = htons(12345);

	ret = tquic_sockaddr_to_observed(&addr, &obs);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, obs.ip_version, (u8)TQUIC_ADDR_DISC_IPV4);
	KUNIT_EXPECT_EQ(test, obs.addr.v4, sin->sin_addr.s_addr);
	KUNIT_EXPECT_EQ(test, obs.port, sin->sin_port);
}

static void test_sockaddr_to_observed_ipv6(struct kunit *test)
{
	struct sockaddr_storage addr;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&addr;
	struct tquic_observed_address obs;
	int ret;

	memset(&addr, 0, sizeof(addr));
	sin6->sin6_family = AF_INET6;
	sin6->sin6_addr.s6_addr[0] = 0xfe;
	sin6->sin6_addr.s6_addr[1] = 0x80;
	sin6->sin6_addr.s6_addr[15] = 0x01;
	sin6->sin6_port = htons(54321);

	ret = tquic_sockaddr_to_observed(&addr, &obs);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, obs.ip_version, (u8)TQUIC_ADDR_DISC_IPV6);
	KUNIT_EXPECT_EQ(test, memcmp(&obs.addr.v6, &sin6->sin6_addr, 16), 0);
	KUNIT_EXPECT_EQ(test, obs.port, sin6->sin6_port);
}

static void test_sockaddr_to_observed_unsupported(struct kunit *test)
{
	struct sockaddr_storage addr;
	struct tquic_observed_address obs;
	int ret;

	memset(&addr, 0, sizeof(addr));
	addr.ss_family = AF_UNIX;  /* Unsupported */

	ret = tquic_sockaddr_to_observed(&addr, &obs);
	KUNIT_EXPECT_EQ(test, ret, -EAFNOSUPPORT);
}

static void test_observed_to_sockaddr_ipv4(struct kunit *test)
{
	struct tquic_observed_address obs;
	struct sockaddr_storage addr;
	struct sockaddr_in *sin = (struct sockaddr_in *)&addr;
	int ret;

	obs.ip_version = TQUIC_ADDR_DISC_IPV4;
	obs.addr.v4 = htonl(0x08080808);  /* 8.8.8.8 */
	obs.port = htons(53);

	ret = tquic_observed_to_sockaddr(&obs, &addr);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, sin->sin_family, AF_INET);
	KUNIT_EXPECT_EQ(test, sin->sin_addr.s_addr, obs.addr.v4);
	KUNIT_EXPECT_EQ(test, sin->sin_port, obs.port);
}

static void test_observed_to_sockaddr_ipv6(struct kunit *test)
{
	struct tquic_observed_address obs;
	struct sockaddr_storage addr;
	struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&addr;
	int ret;

	obs.ip_version = TQUIC_ADDR_DISC_IPV6;
	memset(&obs.addr.v6, 0, 16);
	obs.addr.v6.s6_addr[0] = 0x20;
	obs.addr.v6.s6_addr[1] = 0x01;
	obs.port = htons(443);

	ret = tquic_observed_to_sockaddr(&obs, &addr);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, sin6->sin6_family, AF_INET6);
	KUNIT_EXPECT_EQ(test, memcmp(&sin6->sin6_addr, &obs.addr.v6, 16), 0);
	KUNIT_EXPECT_EQ(test, sin6->sin6_port, obs.port);
}

/*
 * =============================================================================
 * Address Comparison Tests
 * =============================================================================
 */

static void test_observed_address_equal_same_ipv4(struct kunit *test)
{
	struct tquic_observed_address a, b;

	a.ip_version = TQUIC_ADDR_DISC_IPV4;
	a.addr.v4 = htonl(0xC0A80001);
	a.port = htons(4433);

	b.ip_version = TQUIC_ADDR_DISC_IPV4;
	b.addr.v4 = htonl(0xC0A80001);
	b.port = htons(4433);

	KUNIT_EXPECT_TRUE(test, tquic_observed_address_equal(&a, &b));
}

static void test_observed_address_equal_different_addr(struct kunit *test)
{
	struct tquic_observed_address a, b;

	a.ip_version = TQUIC_ADDR_DISC_IPV4;
	a.addr.v4 = htonl(0xC0A80001);
	a.port = htons(4433);

	b.ip_version = TQUIC_ADDR_DISC_IPV4;
	b.addr.v4 = htonl(0xC0A80002);  /* Different */
	b.port = htons(4433);

	KUNIT_EXPECT_FALSE(test, tquic_observed_address_equal(&a, &b));
}

static void test_observed_address_equal_different_port(struct kunit *test)
{
	struct tquic_observed_address a, b;

	a.ip_version = TQUIC_ADDR_DISC_IPV4;
	a.addr.v4 = htonl(0xC0A80001);
	a.port = htons(4433);

	b.ip_version = TQUIC_ADDR_DISC_IPV4;
	b.addr.v4 = htonl(0xC0A80001);
	b.port = htons(8443);  /* Different */

	KUNIT_EXPECT_FALSE(test, tquic_observed_address_equal(&a, &b));
}

static void test_observed_address_equal_different_version(struct kunit *test)
{
	struct tquic_observed_address a, b;

	a.ip_version = TQUIC_ADDR_DISC_IPV4;
	a.addr.v4 = htonl(0xC0A80001);
	a.port = htons(4433);

	b.ip_version = TQUIC_ADDR_DISC_IPV6;  /* Different */
	memset(&b.addr.v6, 0, 16);
	b.port = htons(4433);

	KUNIT_EXPECT_FALSE(test, tquic_observed_address_equal(&a, &b));
}

static void test_observed_address_equal_same_ipv6(struct kunit *test)
{
	struct tquic_observed_address a, b;

	a.ip_version = TQUIC_ADDR_DISC_IPV6;
	memset(&a.addr.v6, 0, 16);
	a.addr.v6.s6_addr[15] = 1;
	a.port = htons(443);

	b.ip_version = TQUIC_ADDR_DISC_IPV6;
	memset(&b.addr.v6, 0, 16);
	b.addr.v6.s6_addr[15] = 1;
	b.port = htons(443);

	KUNIT_EXPECT_TRUE(test, tquic_observed_address_equal(&a, &b));
}

/*
 * =============================================================================
 * Statistics Tests
 * =============================================================================
 */

static void test_get_stats(struct kunit *test)
{
	struct address_discovery_test_context *ctx = test->priv;
	u64 sent, received, rejected;
	u32 changes;
	int ret;

	ret = tquic_addr_discovery_init(&ctx->state);
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Initial stats should be zero */
	tquic_addr_discovery_get_stats(&ctx->state, &sent, &received,
				       &rejected, &changes);

	KUNIT_EXPECT_EQ(test, sent, (u64)0);
	KUNIT_EXPECT_EQ(test, received, (u64)0);
	KUNIT_EXPECT_EQ(test, rejected, (u64)0);
	KUNIT_EXPECT_EQ(test, changes, (u32)0);

	tquic_addr_discovery_cleanup(&ctx->state);
}

/*
 * =============================================================================
 * NAT Rebinding Detection Tests
 * =============================================================================
 */

static void test_nat_rebind_flag_operations(struct kunit *test)
{
	struct address_discovery_test_context *ctx = test->priv;
	int ret;

	ret = tquic_addr_discovery_init(&ctx->state);
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Initially not detected */
	KUNIT_EXPECT_FALSE(test,
		tquic_addr_discovery_nat_rebind_detected(&ctx->state));

	/* Manually set for testing */
	ctx->state.nat_rebind_detected = true;
	KUNIT_EXPECT_TRUE(test,
		tquic_addr_discovery_nat_rebind_detected(&ctx->state));

	/* Clear the flag */
	tquic_addr_discovery_clear_nat_rebind(&ctx->state);
	KUNIT_EXPECT_FALSE(test,
		tquic_addr_discovery_nat_rebind_detected(&ctx->state));

	tquic_addr_discovery_cleanup(&ctx->state);
}

/*
 * =============================================================================
 * Transport Parameter Tests
 * =============================================================================
 */

static void test_tp_address_discovery_negotiation_both_enabled(struct kunit *test)
{
	struct tquic_transport_params local, remote;
	struct tquic_negotiated_params result;
	int ret;

	tquic_tp_set_defaults_client(&local);
	tquic_tp_set_defaults_server(&remote);

	local.enable_address_discovery = true;
	remote.enable_address_discovery = true;

	ret = tquic_tp_negotiate(&local, &remote, &result);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_TRUE(test, result.address_discovery_enabled);
}

static void test_tp_address_discovery_negotiation_local_only(struct kunit *test)
{
	struct tquic_transport_params local, remote;
	struct tquic_negotiated_params result;
	int ret;

	tquic_tp_set_defaults_client(&local);
	tquic_tp_set_defaults_server(&remote);

	local.enable_address_discovery = true;
	remote.enable_address_discovery = false;

	ret = tquic_tp_negotiate(&local, &remote, &result);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_FALSE(test, result.address_discovery_enabled);
}

static void test_tp_address_discovery_negotiation_remote_only(struct kunit *test)
{
	struct tquic_transport_params local, remote;
	struct tquic_negotiated_params result;
	int ret;

	tquic_tp_set_defaults_client(&local);
	tquic_tp_set_defaults_server(&remote);

	local.enable_address_discovery = false;
	remote.enable_address_discovery = true;

	ret = tquic_tp_negotiate(&local, &remote, &result);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_FALSE(test, result.address_discovery_enabled);
}

static void test_tp_address_discovery_negotiation_neither(struct kunit *test)
{
	struct tquic_transport_params local, remote;
	struct tquic_negotiated_params result;
	int ret;

	tquic_tp_set_defaults_client(&local);
	tquic_tp_set_defaults_server(&remote);

	local.enable_address_discovery = false;
	remote.enable_address_discovery = false;

	ret = tquic_tp_negotiate(&local, &remote, &result);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_FALSE(test, result.address_discovery_enabled);
}

/*
 * =============================================================================
 * Test Suite Registration
 * =============================================================================
 */

static struct kunit_case address_discovery_test_cases[] = {
	/* State initialization tests */
	KUNIT_CASE(test_addr_discovery_init),
	KUNIT_CASE(test_addr_discovery_init_null),
	KUNIT_CASE(test_addr_discovery_set_config),
	KUNIT_CASE(test_addr_discovery_config_rate_limit_validation),

	/* Frame encoding tests */
	KUNIT_CASE(test_encode_observed_address_ipv4),
	KUNIT_CASE(test_encode_observed_address_ipv6),
	KUNIT_CASE(test_encode_observed_address_invalid_version),
	KUNIT_CASE(test_encode_observed_address_buffer_too_small),

	/* Frame decoding tests */
	KUNIT_CASE(test_decode_observed_address_ipv4),
	KUNIT_CASE(test_decode_observed_address_ipv6),
	KUNIT_CASE(test_decode_observed_address_truncated),
	KUNIT_CASE(test_decode_observed_address_invalid_ip_version),

	/* Frame size calculation tests */
	KUNIT_CASE(test_frame_size_ipv4),
	KUNIT_CASE(test_frame_size_ipv6),
	KUNIT_CASE(test_frame_size_large_seq),
	KUNIT_CASE(test_frame_size_invalid_version),

	/* Address conversion tests */
	KUNIT_CASE(test_sockaddr_to_observed_ipv4),
	KUNIT_CASE(test_sockaddr_to_observed_ipv6),
	KUNIT_CASE(test_sockaddr_to_observed_unsupported),
	KUNIT_CASE(test_observed_to_sockaddr_ipv4),
	KUNIT_CASE(test_observed_to_sockaddr_ipv6),

	/* Address comparison tests */
	KUNIT_CASE(test_observed_address_equal_same_ipv4),
	KUNIT_CASE(test_observed_address_equal_different_addr),
	KUNIT_CASE(test_observed_address_equal_different_port),
	KUNIT_CASE(test_observed_address_equal_different_version),
	KUNIT_CASE(test_observed_address_equal_same_ipv6),

	/* Statistics tests */
	KUNIT_CASE(test_get_stats),

	/* NAT rebinding tests */
	KUNIT_CASE(test_nat_rebind_flag_operations),

	/* Transport parameter negotiation tests */
	KUNIT_CASE(test_tp_address_discovery_negotiation_both_enabled),
	KUNIT_CASE(test_tp_address_discovery_negotiation_local_only),
	KUNIT_CASE(test_tp_address_discovery_negotiation_remote_only),
	KUNIT_CASE(test_tp_address_discovery_negotiation_neither),

	{}
};

static struct kunit_suite address_discovery_test_suite = {
	.name = "tquic-address-discovery",
	.init = address_discovery_test_init,
	.test_cases = address_discovery_test_cases,
};

kunit_test_suites(&address_discovery_test_suite);

MODULE_AUTHOR("Linux Foundation");
MODULE_DESCRIPTION("TQUIC Address Discovery Extension KUnit Tests");
MODULE_LICENSE("GPL");
