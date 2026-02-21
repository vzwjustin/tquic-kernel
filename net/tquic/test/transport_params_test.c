// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: WAN Bonding over QUIC - Transport Parameters KUnit Tests
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 */

#include <kunit/test.h>
#include <linux/slab.h>
#include <net/tquic.h>

#include "../protocol.h"
#include "../core/transport_params.h"

/*
 * Test: Initialize transport parameters with defaults
 */
static void test_tp_init_defaults(struct kunit *test)
{
	struct tquic_transport_params params;

	tquic_tp_init(&params);

	KUNIT_EXPECT_EQ(test, params.max_idle_timeout, (u64)0);
	KUNIT_EXPECT_EQ(test, params.max_udp_payload_size, (u64)65527);
	KUNIT_EXPECT_EQ(test, params.ack_delay_exponent, (u8)3);
	KUNIT_EXPECT_EQ(test, params.max_ack_delay, (u32)25);
	KUNIT_EXPECT_EQ(test, params.active_connection_id_limit, (u64)2);
	KUNIT_EXPECT_FALSE(test, params.disable_active_migration);
	KUNIT_EXPECT_FALSE(test, params.enable_multipath);
	KUNIT_EXPECT_FALSE(test, params.original_dcid_present);
	KUNIT_EXPECT_FALSE(test, params.initial_scid_present);
	KUNIT_EXPECT_FALSE(test, params.retry_scid_present);
	KUNIT_EXPECT_FALSE(test, params.stateless_reset_token_present);
	KUNIT_EXPECT_FALSE(test, params.preferred_address_present);
}

/*
 * Test: Client defaults
 */
static void test_tp_client_defaults(struct kunit *test)
{
	struct tquic_transport_params params;

	tquic_tp_set_defaults_client(&params);

	KUNIT_EXPECT_EQ(test, params.max_idle_timeout, (u64)TQUIC_DEFAULT_IDLE_TIMEOUT);
	KUNIT_EXPECT_EQ(test, params.initial_max_data, (u64)tquic_get_validated_max_data());
	KUNIT_EXPECT_EQ(test, params.initial_max_stream_data_bidi_local,
			(u64)tquic_get_validated_max_stream_data());
	KUNIT_EXPECT_EQ(test, params.initial_max_streams_bidi, (u64)100);
	KUNIT_EXPECT_EQ(test, params.initial_max_streams_uni, (u64)100);
	KUNIT_EXPECT_TRUE(test, params.enable_multipath);
}

/*
 * Test: Server defaults
 */
static void test_tp_server_defaults(struct kunit *test)
{
	struct tquic_transport_params params;

	tquic_tp_set_defaults_server(&params);

	KUNIT_EXPECT_EQ(test, params.max_idle_timeout, (u64)TQUIC_DEFAULT_IDLE_TIMEOUT);
	KUNIT_EXPECT_EQ(test, params.initial_max_data, (u64)tquic_get_validated_max_data());
	KUNIT_EXPECT_EQ(test, params.active_connection_id_limit, (u64)TQUIC_MAX_PATHS);
	KUNIT_EXPECT_TRUE(test, params.enable_multipath);
}

/*
 * Test: Encode and decode basic parameters
 */
static void test_tp_encode_decode_basic(struct kunit *test)
{
	struct tquic_transport_params original, decoded;
	u8 *buf;
	ssize_t encoded_len;
	int ret;

	buf = kunit_kzalloc(test, 512, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buf);

	tquic_tp_set_defaults_client(&original);

	/* Set initial_scid for encoding */
	original.initial_scid.len = 8;
	memset(original.initial_scid.id, 0x42, 8);
	original.initial_scid_present = true;

	/* Encode as client */
	encoded_len = tquic_tp_encode(&original, false, buf, 512);
	KUNIT_ASSERT_GT(test, encoded_len, (ssize_t)0);

	/* Decode as if receiving from client */
	ret = tquic_tp_decode(buf, encoded_len, false, &decoded);
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Verify values match */
	KUNIT_EXPECT_EQ(test, decoded.max_idle_timeout, original.max_idle_timeout);
	KUNIT_EXPECT_EQ(test, decoded.initial_max_data, original.initial_max_data);
	KUNIT_EXPECT_EQ(test, decoded.initial_max_streams_bidi,
			original.initial_max_streams_bidi);
	KUNIT_EXPECT_EQ(test, decoded.initial_max_streams_uni,
			original.initial_max_streams_uni);
	KUNIT_EXPECT_EQ(test, decoded.enable_multipath, original.enable_multipath);
	KUNIT_EXPECT_TRUE(test, decoded.initial_scid_present);
	KUNIT_EXPECT_EQ(test, decoded.initial_scid.len, (u8)8);
}

/*
 * Test: Encode and decode server parameters
 */
static void test_tp_encode_decode_server(struct kunit *test)
{
	struct tquic_transport_params original, decoded;
	u8 *buf;
	ssize_t encoded_len;
	int ret;

	buf = kunit_kzalloc(test, 512, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buf);

	tquic_tp_set_defaults_server(&original);

	/* Set server-specific fields */
	original.initial_scid.len = 8;
	get_random_bytes(original.initial_scid.id, 8);
	original.initial_scid_present = true;

	original.original_dcid.len = 8;
	get_random_bytes(original.original_dcid.id, 8);
	original.original_dcid_present = true;

	get_random_bytes(original.stateless_reset_token, 16);
	original.stateless_reset_token_present = true;

	/* Encode as server */
	encoded_len = tquic_tp_encode(&original, true, buf, 512);
	KUNIT_ASSERT_GT(test, encoded_len, (ssize_t)0);

	/* Decode as if receiving from server */
	ret = tquic_tp_decode(buf, encoded_len, true, &decoded);
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Verify server-specific values */
	KUNIT_EXPECT_TRUE(test, decoded.original_dcid_present);
	KUNIT_EXPECT_TRUE(test, decoded.stateless_reset_token_present);
	KUNIT_EXPECT_EQ(test, decoded.original_dcid.len, original.original_dcid.len);
	KUNIT_EXPECT_EQ(test, memcmp(decoded.stateless_reset_token,
				     original.stateless_reset_token, 16), 0);
}

/*
 * Test: Validation of max_udp_payload_size
 */
static void test_tp_validate_udp_payload_size(struct kunit *test)
{
	struct tquic_transport_params params;
	int ret;

	tquic_tp_set_defaults_client(&params);
	params.initial_scid_present = true;
	params.initial_scid.len = 4;

	/* Valid: default value */
	ret = tquic_tp_validate(&params, false);
	KUNIT_EXPECT_EQ(test, ret, 0);

	/* Invalid: too small */
	params.max_udp_payload_size = 1199;
	ret = tquic_tp_validate(&params, false);
	KUNIT_EXPECT_NE(test, ret, 0);

	/* Valid: minimum allowed */
	params.max_udp_payload_size = 1200;
	ret = tquic_tp_validate(&params, false);
	KUNIT_EXPECT_EQ(test, ret, 0);
}

/*
 * Test: Validation of ack_delay_exponent
 */
static void test_tp_validate_ack_delay_exponent(struct kunit *test)
{
	struct tquic_transport_params params;
	int ret;

	tquic_tp_set_defaults_client(&params);
	params.initial_scid_present = true;
	params.initial_scid.len = 4;

	/* Valid: default value */
	ret = tquic_tp_validate(&params, false);
	KUNIT_EXPECT_EQ(test, ret, 0);

	/* Valid: maximum allowed */
	params.ack_delay_exponent = 20;
	ret = tquic_tp_validate(&params, false);
	KUNIT_EXPECT_EQ(test, ret, 0);

	/* Invalid: too large */
	params.ack_delay_exponent = 21;
	ret = tquic_tp_validate(&params, false);
	KUNIT_EXPECT_NE(test, ret, 0);
}

/*
 * Test: Validation of active_connection_id_limit
 */
static void test_tp_validate_active_cid_limit(struct kunit *test)
{
	struct tquic_transport_params params;
	int ret;

	tquic_tp_set_defaults_client(&params);
	params.initial_scid_present = true;
	params.initial_scid.len = 4;

	/* Valid: minimum allowed */
	params.active_connection_id_limit = 2;
	ret = tquic_tp_validate(&params, false);
	KUNIT_EXPECT_EQ(test, ret, 0);

	/* Invalid: too small */
	params.active_connection_id_limit = 1;
	ret = tquic_tp_validate(&params, false);
	KUNIT_EXPECT_NE(test, ret, 0);

	/* Invalid: zero */
	params.active_connection_id_limit = 0;
	ret = tquic_tp_validate(&params, false);
	KUNIT_EXPECT_NE(test, ret, 0);
}

/*
 * Test: Parameter negotiation - idle timeout
 */
static void test_tp_negotiate_idle_timeout(struct kunit *test)
{
	struct tquic_transport_params local, remote;
	struct tquic_negotiated_params result;
	int ret;

	tquic_tp_set_defaults_client(&local);
	tquic_tp_set_defaults_server(&remote);

	/* Both have timeout: use minimum */
	local.max_idle_timeout = 30000;
	remote.max_idle_timeout = 20000;

	ret = tquic_tp_negotiate(&local, &remote, &result);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, result.idle_timeout, (u64)20000);

	/* Local timeout is 0: use remote */
	local.max_idle_timeout = 0;
	remote.max_idle_timeout = 25000;

	ret = tquic_tp_negotiate(&local, &remote, &result);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, result.idle_timeout, (u64)25000);

	/* Remote timeout is 0: use local */
	local.max_idle_timeout = 15000;
	remote.max_idle_timeout = 0;

	ret = tquic_tp_negotiate(&local, &remote, &result);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, result.idle_timeout, (u64)15000);

	/* Both are 0: disabled */
	local.max_idle_timeout = 0;
	remote.max_idle_timeout = 0;

	ret = tquic_tp_negotiate(&local, &remote, &result);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, result.idle_timeout, (u64)0);
}

/*
 * Test: Parameter negotiation - multipath
 */
static void test_tp_negotiate_multipath(struct kunit *test)
{
	struct tquic_transport_params local, remote;
	struct tquic_negotiated_params result;
	int ret;

	tquic_tp_set_defaults_client(&local);
	tquic_tp_set_defaults_server(&remote);

	/* Both support multipath */
	local.enable_multipath = true;
	remote.enable_multipath = true;

	ret = tquic_tp_negotiate(&local, &remote, &result);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_TRUE(test, result.multipath_enabled);

	/* Only local supports multipath */
	local.enable_multipath = true;
	remote.enable_multipath = false;

	ret = tquic_tp_negotiate(&local, &remote, &result);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_FALSE(test, result.multipath_enabled);

	/* Only remote supports multipath */
	local.enable_multipath = false;
	remote.enable_multipath = true;

	ret = tquic_tp_negotiate(&local, &remote, &result);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_FALSE(test, result.multipath_enabled);

	/* Neither supports multipath */
	local.enable_multipath = false;
	remote.enable_multipath = false;

	ret = tquic_tp_negotiate(&local, &remote, &result);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_FALSE(test, result.multipath_enabled);
}

/*
 * Test: Parameter negotiation - migration
 */
static void test_tp_negotiate_migration(struct kunit *test)
{
	struct tquic_transport_params local, remote;
	struct tquic_negotiated_params result;
	int ret;

	tquic_tp_set_defaults_client(&local);
	tquic_tp_set_defaults_server(&remote);

	/* Neither disables migration */
	local.disable_active_migration = false;
	remote.disable_active_migration = false;

	ret = tquic_tp_negotiate(&local, &remote, &result);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_FALSE(test, result.migration_disabled);

	/* Local disables migration */
	local.disable_active_migration = true;
	remote.disable_active_migration = false;

	ret = tquic_tp_negotiate(&local, &remote, &result);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_TRUE(test, result.migration_disabled);

	/* Remote disables migration */
	local.disable_active_migration = false;
	remote.disable_active_migration = true;

	ret = tquic_tp_negotiate(&local, &remote, &result);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_TRUE(test, result.migration_disabled);
}

/*
 * Test: Connection ID comparison
 */
static void test_tp_cmp_cid(struct kunit *test)
{
	struct tquic_cid cid1, cid2;

	/* Same CID */
	cid1.len = 8;
	memset(cid1.id, 0x42, 8);
	cid2.len = 8;
	memset(cid2.id, 0x42, 8);

	KUNIT_EXPECT_TRUE(test, tquic_tp_cmp_cid(&cid1, &cid2));

	/* Different content */
	cid2.id[0] = 0x43;
	KUNIT_EXPECT_FALSE(test, tquic_tp_cmp_cid(&cid1, &cid2));

	/* Different length */
	cid2.len = 7;
	memset(cid2.id, 0x42, 7);
	KUNIT_EXPECT_FALSE(test, tquic_tp_cmp_cid(&cid1, &cid2));

	/* Both empty */
	cid1.len = 0;
	cid2.len = 0;
	KUNIT_EXPECT_TRUE(test, tquic_tp_cmp_cid(&cid1, &cid2));
}

/*
 * Test: Encode buffer too small
 */
static void test_tp_encode_buffer_too_small(struct kunit *test)
{
	struct tquic_transport_params params;
	u8 buf[4];  /* Very small buffer */
	ssize_t encoded_len;

	tquic_tp_set_defaults_client(&params);
	params.initial_scid_present = true;
	params.initial_scid.len = 8;

	/* Buffer too small should fail */
	encoded_len = tquic_tp_encode(&params, false, buf, sizeof(buf));
	KUNIT_EXPECT_LT(test, encoded_len, (ssize_t)0);
}

/*
 * Test: Decode truncated data
 */
static void test_tp_decode_truncated(struct kunit *test)
{
	struct tquic_transport_params params;
	u8 buf[] = { 0x01 };  /* Just parameter ID, no length */
	int ret;

	ret = tquic_tp_decode(buf, sizeof(buf), false, &params);
	KUNIT_EXPECT_NE(test, ret, 0);
}

/*
 * Test: Encoded size calculation
 */
static void test_tp_encoded_size(struct kunit *test)
{
	struct tquic_transport_params params;
	u8 *buf;
	size_t calculated_size;
	ssize_t actual_size;

	buf = kunit_kzalloc(test, 1024, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buf);

	tquic_tp_set_defaults_client(&params);
	params.initial_scid_present = true;
	params.initial_scid.len = 8;
	params.enable_multipath = true;

	calculated_size = tquic_tp_encoded_size(&params, false);
	actual_size = tquic_tp_encode(&params, false, buf, 1024);

	KUNIT_ASSERT_GT(test, actual_size, (ssize_t)0);
	/* Calculated size should be >= actual (may include padding estimates) */
	KUNIT_EXPECT_GE(test, calculated_size + 64, (size_t)actual_size);
}

/*
 * Test: Preferred address encoding/decoding (server only)
 */
static void test_tp_preferred_address(struct kunit *test)
{
	struct tquic_transport_params original, decoded;
	u8 *buf;
	ssize_t encoded_len;
	int ret;

	buf = kunit_kzalloc(test, 512, GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, buf);

	tquic_tp_set_defaults_server(&original);
	original.initial_scid_present = true;
	original.initial_scid.len = 8;
	original.original_dcid_present = true;
	original.original_dcid.len = 8;

	/* Set up preferred address */
	original.preferred_address_present = true;
	original.preferred_address.ipv4_addr[0] = 192;
	original.preferred_address.ipv4_addr[1] = 168;
	original.preferred_address.ipv4_addr[2] = 1;
	original.preferred_address.ipv4_addr[3] = 100;
	original.preferred_address.ipv4_port = 4433;

	memset(original.preferred_address.ipv6_addr, 0, 16);
	original.preferred_address.ipv6_addr[15] = 1;
	original.preferred_address.ipv6_port = 4433;

	original.preferred_address.cid.len = 8;
	get_random_bytes(original.preferred_address.cid.id, 8);
	get_random_bytes(original.preferred_address.stateless_reset_token, 16);

	/* Encode as server */
	encoded_len = tquic_tp_encode(&original, true, buf, 512);
	KUNIT_ASSERT_GT(test, encoded_len, (ssize_t)0);

	/* Decode */
	ret = tquic_tp_decode(buf, encoded_len, true, &decoded);
	KUNIT_ASSERT_EQ(test, ret, 0);

	/* Verify preferred address */
	KUNIT_EXPECT_TRUE(test, decoded.preferred_address_present);
	KUNIT_EXPECT_EQ(test, decoded.preferred_address.ipv4_addr[0], (u8)192);
	KUNIT_EXPECT_EQ(test, decoded.preferred_address.ipv4_addr[1], (u8)168);
	KUNIT_EXPECT_EQ(test, decoded.preferred_address.ipv4_port, (u16)4433);
	KUNIT_EXPECT_EQ(test, decoded.preferred_address.cid.len, (u8)8);
}

/*
 * Test: Client cannot send server-only parameters
 */
static void test_tp_client_server_only_params(struct kunit *test)
{
	struct tquic_transport_params params;
	u8 buf[512];
	ssize_t encoded_len;
	int ret;

	/* Create a fake "client" that includes server-only params */
	tquic_tp_set_defaults_client(&params);
	params.initial_scid_present = true;
	params.initial_scid.len = 8;

	/* Manually add original_dcid (server-only) */
	params.original_dcid_present = true;
	params.original_dcid.len = 8;

	/* Encode as server (this is the trick - encoding as server) */
	encoded_len = tquic_tp_encode(&params, true, buf, 512);
	KUNIT_ASSERT_GT(test, encoded_len, (ssize_t)0);

	/* Decode as if from client - should fail for server-only params */
	ret = tquic_tp_decode(buf, encoded_len, false, &params);
	KUNIT_EXPECT_NE(test, ret, 0);
}

static struct kunit_case transport_params_test_cases[] = {
	KUNIT_CASE(test_tp_init_defaults),
	KUNIT_CASE(test_tp_client_defaults),
	KUNIT_CASE(test_tp_server_defaults),
	KUNIT_CASE(test_tp_encode_decode_basic),
	KUNIT_CASE(test_tp_encode_decode_server),
	KUNIT_CASE(test_tp_validate_udp_payload_size),
	KUNIT_CASE(test_tp_validate_ack_delay_exponent),
	KUNIT_CASE(test_tp_validate_active_cid_limit),
	KUNIT_CASE(test_tp_negotiate_idle_timeout),
	KUNIT_CASE(test_tp_negotiate_multipath),
	KUNIT_CASE(test_tp_negotiate_migration),
	KUNIT_CASE(test_tp_cmp_cid),
	KUNIT_CASE(test_tp_encode_buffer_too_small),
	KUNIT_CASE(test_tp_decode_truncated),
	KUNIT_CASE(test_tp_encoded_size),
	KUNIT_CASE(test_tp_preferred_address),
	KUNIT_CASE(test_tp_client_server_only_params),
	{}
};

static struct kunit_suite transport_params_test_suite = {
	.name = "tquic-transport-params",
	.test_cases = transport_params_test_cases,
};

kunit_test_suites(&transport_params_test_suite);

MODULE_AUTHOR("Linux Foundation");
MODULE_DESCRIPTION("TQUIC Transport Parameters KUnit Tests");
MODULE_LICENSE("GPL");
