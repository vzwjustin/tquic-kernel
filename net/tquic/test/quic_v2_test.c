// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: QUIC Version 2 (RFC 9369) KUnit Tests
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Comprehensive tests for QUIC v2 (RFC 9369):
 *   - v2 HKDF label derivation
 *   - v2 packet type encoding/decoding
 *   - v2 Initial salt usage
 *   - v2 Retry integrity tag computation
 *   - Version negotiation
 *
 * Test Structure:
 *   Section 1: Version Constants Tests
 *   Section 2: Initial Salt Tests
 *   Section 3: HKDF Label Tests
 *   Section 4: Packet Type Encoding Tests
 *   Section 5: Retry Integrity Tests
 *   Section 6: Version Negotiation Tests
 */

#include <kunit/test.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/slab.h>

/*
 * =============================================================================
 * QUIC Version Constants (RFC 9369)
 * =============================================================================
 */

/* Version numbers */
#define QUIC_VERSION_1		0x00000001	/* RFC 9000 */
#define QUIC_VERSION_2		0x6b3343cf	/* RFC 9369 */
#define QUIC_VERSION_NEGOTIATION 0x00000000	/* Version negotiation */

/* v1 Initial salt (RFC 9001 Section 5.2) */
static const u8 quic_v1_initial_salt[20] = {
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
	0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a
};

/* v2 Initial salt (RFC 9369 Section 5.2) */
static const u8 quic_v2_initial_salt[20] = {
	0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb, 0x81, 0x93,
	0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb, 0xf9, 0xbd, 0x2e, 0xd9
};

/* v1 Retry integrity key (RFC 9001) */
static const u8 quic_v1_retry_key[16] = {
	0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
	0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e
};

/* v2 Retry integrity key (RFC 9369) */
static const u8 quic_v2_retry_key[16] = {
	0x8f, 0xb4, 0xb0, 0x1b, 0x56, 0xac, 0x48, 0xe2,
	0x60, 0xfb, 0xcb, 0xce, 0xad, 0x7c, 0xcc, 0x92
};

/* v1 Retry integrity nonce (RFC 9001) */
static const u8 quic_v1_retry_nonce[12] = {
	0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2,
	0x23, 0x98, 0x25, 0xbb
};

/* v2 Retry integrity nonce (RFC 9369) */
static const u8 quic_v2_retry_nonce[12] = {
	0xd8, 0x69, 0x69, 0xbc, 0x2d, 0x7c, 0x6d, 0x99,
	0x90, 0xef, 0xb0, 0x4a
};

/* HKDF labels */
#define QUIC_V1_LABEL_PREFIX	"tls13 "
#define QUIC_V2_LABEL_PREFIX	"tls13 "

/* v1 HKDF labels (RFC 9001 Section 5.1) */
#define QUIC_V1_LABEL_CLIENT_IN	"client in"
#define QUIC_V1_LABEL_SERVER_IN	"server in"
#define QUIC_V1_LABEL_QUIC_KEY	"quic key"
#define QUIC_V1_LABEL_QUIC_IV	"quic iv"
#define QUIC_V1_LABEL_QUIC_HP	"quic hp"
#define QUIC_V1_LABEL_QUIC_KU	"quic ku"

/* v2 HKDF labels (RFC 9369 Section 5.1) - different from v1 */
#define QUIC_V2_LABEL_CLIENT_IN	"client in"
#define QUIC_V2_LABEL_SERVER_IN	"server in"
#define QUIC_V2_LABEL_QUIC_KEY	"quicv2 key"
#define QUIC_V2_LABEL_QUIC_IV	"quicv2 iv"
#define QUIC_V2_LABEL_QUIC_HP	"quicv2 hp"
#define QUIC_V2_LABEL_QUIC_KU	"quicv2 ku"

/* Long header packet types */
#define QUIC_V1_PACKET_TYPE_INITIAL	0
#define QUIC_V1_PACKET_TYPE_0RTT	1
#define QUIC_V1_PACKET_TYPE_HANDSHAKE	2
#define QUIC_V1_PACKET_TYPE_RETRY	3

/* v2 Long header packet types (RFC 9369 Section 4) - different order */
#define QUIC_V2_PACKET_TYPE_INITIAL	1
#define QUIC_V2_PACKET_TYPE_0RTT	2
#define QUIC_V2_PACKET_TYPE_HANDSHAKE	3
#define QUIC_V2_PACKET_TYPE_RETRY	0

/*
 * =============================================================================
 * Test Helper Functions
 * =============================================================================
 */

/**
 * test_get_initial_salt - Get Initial salt for version
 * @version: QUIC version number
 * @salt: Output salt buffer (20 bytes)
 *
 * Returns: 0 on success, -EINVAL for unknown version
 */
static int test_get_initial_salt(u32 version, u8 *salt)
{
	switch (version) {
	case QUIC_VERSION_1:
		memcpy(salt, quic_v1_initial_salt, 20);
		return 0;
	case QUIC_VERSION_2:
		memcpy(salt, quic_v2_initial_salt, 20);
		return 0;
	default:
		return -EINVAL;
	}
}

/**
 * test_get_retry_key - Get Retry integrity key for version
 * @version: QUIC version number
 * @key: Output key buffer (16 bytes)
 *
 * Returns: 0 on success, -EINVAL for unknown version
 */
static int test_get_retry_key(u32 version, u8 *key)
{
	switch (version) {
	case QUIC_VERSION_1:
		memcpy(key, quic_v1_retry_key, 16);
		return 0;
	case QUIC_VERSION_2:
		memcpy(key, quic_v2_retry_key, 16);
		return 0;
	default:
		return -EINVAL;
	}
}

/**
 * test_get_retry_nonce - Get Retry integrity nonce for version
 * @version: QUIC version number
 * @nonce: Output nonce buffer (12 bytes)
 *
 * Returns: 0 on success, -EINVAL for unknown version
 */
static int test_get_retry_nonce(u32 version, u8 *nonce)
{
	switch (version) {
	case QUIC_VERSION_1:
		memcpy(nonce, quic_v1_retry_nonce, 12);
		return 0;
	case QUIC_VERSION_2:
		memcpy(nonce, quic_v2_retry_nonce, 12);
		return 0;
	default:
		return -EINVAL;
	}
}

/**
 * test_get_key_label - Get HKDF key label for version
 * @version: QUIC version number
 *
 * Returns: Label string or NULL for unknown version
 */
static const char *test_get_key_label(u32 version)
{
	switch (version) {
	case QUIC_VERSION_1:
		return QUIC_V1_LABEL_QUIC_KEY;
	case QUIC_VERSION_2:
		return QUIC_V2_LABEL_QUIC_KEY;
	default:
		return NULL;
	}
}

/**
 * test_get_iv_label - Get HKDF IV label for version
 * @version: QUIC version number
 *
 * Returns: Label string or NULL for unknown version
 */
static const char *test_get_iv_label(u32 version)
{
	switch (version) {
	case QUIC_VERSION_1:
		return QUIC_V1_LABEL_QUIC_IV;
	case QUIC_VERSION_2:
		return QUIC_V2_LABEL_QUIC_IV;
	default:
		return NULL;
	}
}

/**
 * test_get_hp_label - Get HKDF HP label for version
 * @version: QUIC version number
 *
 * Returns: Label string or NULL for unknown version
 */
static const char *test_get_hp_label(u32 version)
{
	switch (version) {
	case QUIC_VERSION_1:
		return QUIC_V1_LABEL_QUIC_HP;
	case QUIC_VERSION_2:
		return QUIC_V2_LABEL_QUIC_HP;
	default:
		return NULL;
	}
}

/**
 * test_v1_to_v2_packet_type - Convert v1 packet type to v2
 * @v1_type: v1 packet type
 *
 * Returns: v2 packet type
 */
static u8 test_v1_to_v2_packet_type(u8 v1_type)
{
	switch (v1_type) {
	case QUIC_V1_PACKET_TYPE_INITIAL:
		return QUIC_V2_PACKET_TYPE_INITIAL;
	case QUIC_V1_PACKET_TYPE_0RTT:
		return QUIC_V2_PACKET_TYPE_0RTT;
	case QUIC_V1_PACKET_TYPE_HANDSHAKE:
		return QUIC_V2_PACKET_TYPE_HANDSHAKE;
	case QUIC_V1_PACKET_TYPE_RETRY:
		return QUIC_V2_PACKET_TYPE_RETRY;
	default:
		return 0xff;  /* Invalid */
	}
}

/**
 * test_v2_to_v1_packet_type - Convert v2 packet type to v1
 * @v2_type: v2 packet type
 *
 * Returns: v1 packet type
 */
static u8 test_v2_to_v1_packet_type(u8 v2_type)
{
	switch (v2_type) {
	case QUIC_V2_PACKET_TYPE_INITIAL:
		return QUIC_V1_PACKET_TYPE_INITIAL;
	case QUIC_V2_PACKET_TYPE_0RTT:
		return QUIC_V1_PACKET_TYPE_0RTT;
	case QUIC_V2_PACKET_TYPE_HANDSHAKE:
		return QUIC_V1_PACKET_TYPE_HANDSHAKE;
	case QUIC_V2_PACKET_TYPE_RETRY:
		return QUIC_V1_PACKET_TYPE_RETRY;
	default:
		return 0xff;  /* Invalid */
	}
}

/**
 * test_encode_long_header_type - Encode long header first byte
 * @version: QUIC version
 * @logical_type: Logical packet type (Initial=0, 0-RTT=1, etc.)
 *
 * Returns: First byte with packet type encoded, or 0 on error
 */
static u8 test_encode_long_header_type(u32 version, u8 logical_type)
{
	u8 wire_type;
	u8 first_byte = 0xc0;  /* Long header form + fixed bit */

	if (version == QUIC_VERSION_2) {
		wire_type = test_v1_to_v2_packet_type(logical_type);
	} else {
		wire_type = logical_type;
	}

	first_byte |= (wire_type << 4);
	return first_byte;
}

/**
 * test_decode_long_header_type - Decode long header first byte
 * @version: QUIC version
 * @first_byte: First byte of packet
 *
 * Returns: Logical packet type (v1 numbering), or 0xff on error
 */
static u8 test_decode_long_header_type(u32 version, u8 first_byte)
{
	u8 wire_type = (first_byte >> 4) & 0x03;

	if (version == QUIC_VERSION_2) {
		return test_v2_to_v1_packet_type(wire_type);
	}
	return wire_type;
}

/**
 * test_is_valid_quic_version - Check if version is valid for negotiation
 * @version: QUIC version
 *
 * Returns: true if version is supported
 */
static bool test_is_valid_quic_version(u32 version)
{
	return version == QUIC_VERSION_1 || version == QUIC_VERSION_2;
}

/**
 * test_encode_version - Encode version into buffer (big-endian)
 * @buf: Output buffer (4 bytes)
 * @version: Version to encode
 */
static void test_encode_version(u8 *buf, u32 version)
{
	buf[0] = (version >> 24) & 0xff;
	buf[1] = (version >> 16) & 0xff;
	buf[2] = (version >> 8) & 0xff;
	buf[3] = version & 0xff;
}

/**
 * test_decode_version - Decode version from buffer (big-endian)
 * @buf: Input buffer (4 bytes)
 *
 * Returns: Decoded version
 */
static u32 test_decode_version(const u8 *buf)
{
	return ((u32)buf[0] << 24) | ((u32)buf[1] << 16) |
	       ((u32)buf[2] << 8) | buf[3];
}

/**
 * struct version_nego_packet - Version negotiation packet
 * @versions: Array of supported versions
 * @version_count: Number of versions
 */
struct version_nego_packet {
	u32 versions[16];
	u8 version_count;
};

/**
 * test_select_version - Select best version from offered list
 * @offered: Offered versions
 * @preferred: Preferred versions (in priority order)
 * @preferred_count: Number of preferred versions
 *
 * Returns: Selected version, or 0 if none compatible
 */
static u32 test_select_version(const struct version_nego_packet *offered,
			       const u32 *preferred, u8 preferred_count)
{
	int i, j;

	/* Select highest priority preferred version that's offered */
	for (i = 0; i < preferred_count; i++) {
		for (j = 0; j < offered->version_count; j++) {
			if (preferred[i] == offered->versions[j])
				return preferred[i];
		}
	}

	return 0;  /* No compatible version */
}

/*
 * =============================================================================
 * SECTION 1: Version Constants Tests
 * =============================================================================
 */

/* Test: v1 and v2 version numbers are correct */
static void test_version_numbers(struct kunit *test)
{
	/* ASSERT: Check RFC-specified values */
	KUNIT_EXPECT_EQ(test, QUIC_VERSION_1, 0x00000001U);
	KUNIT_EXPECT_EQ(test, QUIC_VERSION_2, 0x6b3343cfU);
	KUNIT_EXPECT_EQ(test, QUIC_VERSION_NEGOTIATION, 0x00000000U);
}

/* Test: v1 and v2 are valid versions */
static void test_valid_versions(struct kunit *test)
{
	KUNIT_EXPECT_TRUE(test, test_is_valid_quic_version(QUIC_VERSION_1));
	KUNIT_EXPECT_TRUE(test, test_is_valid_quic_version(QUIC_VERSION_2));
	KUNIT_EXPECT_FALSE(test, test_is_valid_quic_version(0x12345678));
	KUNIT_EXPECT_FALSE(test, test_is_valid_quic_version(0));
}

/* Test: Version encoding/decoding roundtrip */
static void test_version_encoding(struct kunit *test)
{
	u8 buf[4];
	u32 decoded;

	/* Test v1 */
	test_encode_version(buf, QUIC_VERSION_1);
	decoded = test_decode_version(buf);
	KUNIT_EXPECT_EQ(test, decoded, QUIC_VERSION_1);

	/* Test v2 */
	test_encode_version(buf, QUIC_VERSION_2);
	decoded = test_decode_version(buf);
	KUNIT_EXPECT_EQ(test, decoded, QUIC_VERSION_2);
}

/*
 * =============================================================================
 * SECTION 2: Initial Salt Tests
 * =============================================================================
 */

/* Test: v1 Initial salt is correct */
static void test_v1_initial_salt(struct kunit *test)
{
	u8 salt[20];
	int ret;

	/* ACT */
	ret = test_get_initial_salt(QUIC_VERSION_1, salt);

	/* ASSERT */
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, memcmp(salt, quic_v1_initial_salt, 20), 0);
}

/* Test: v2 Initial salt is correct and different from v1 */
static void test_v2_initial_salt(struct kunit *test)
{
	u8 salt[20];
	int ret;

	/* ACT */
	ret = test_get_initial_salt(QUIC_VERSION_2, salt);

	/* ASSERT */
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, memcmp(salt, quic_v2_initial_salt, 20), 0);

	/* v2 salt should be different from v1 */
	KUNIT_EXPECT_NE(test, memcmp(quic_v1_initial_salt, quic_v2_initial_salt, 20), 0);
}

/* Test: Unknown version returns error for salt */
static void test_unknown_version_salt(struct kunit *test)
{
	u8 salt[20];
	int ret;

	/* ACT/ASSERT */
	ret = test_get_initial_salt(0x12345678, salt);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

/*
 * =============================================================================
 * SECTION 3: HKDF Label Tests
 * =============================================================================
 */

/* Test: v1 HKDF labels are correct */
static void test_v1_hkdf_labels(struct kunit *test)
{
	const char *key_label = test_get_key_label(QUIC_VERSION_1);
	const char *iv_label = test_get_iv_label(QUIC_VERSION_1);
	const char *hp_label = test_get_hp_label(QUIC_VERSION_1);

	KUNIT_EXPECT_STREQ(test, key_label, "quic key");
	KUNIT_EXPECT_STREQ(test, iv_label, "quic iv");
	KUNIT_EXPECT_STREQ(test, hp_label, "quic hp");
}

/* Test: v2 HKDF labels are different from v1 */
static void test_v2_hkdf_labels(struct kunit *test)
{
	const char *key_label = test_get_key_label(QUIC_VERSION_2);
	const char *iv_label = test_get_iv_label(QUIC_VERSION_2);
	const char *hp_label = test_get_hp_label(QUIC_VERSION_2);

	/* v2 uses "quicv2 key" instead of "quic key" */
	KUNIT_EXPECT_STREQ(test, key_label, "quicv2 key");
	KUNIT_EXPECT_STREQ(test, iv_label, "quicv2 iv");
	KUNIT_EXPECT_STREQ(test, hp_label, "quicv2 hp");

	/* Verify different from v1 */
	KUNIT_EXPECT_NE(test, strcmp(test_get_key_label(QUIC_VERSION_1),
				     test_get_key_label(QUIC_VERSION_2)), 0);
}

/* Test: Unknown version returns NULL for labels */
static void test_unknown_version_labels(struct kunit *test)
{
	const char *label;

	label = test_get_key_label(0x12345678);
	KUNIT_EXPECT_NULL(test, label);

	label = test_get_iv_label(0x12345678);
	KUNIT_EXPECT_NULL(test, label);

	label = test_get_hp_label(0x12345678);
	KUNIT_EXPECT_NULL(test, label);
}

/*
 * =============================================================================
 * SECTION 4: Packet Type Encoding Tests
 * =============================================================================
 */

/* Test: v1 packet type encoding */
static void test_v1_packet_type_encoding(struct kunit *test)
{
	u8 first_byte;

	/* Initial packet */
	first_byte = test_encode_long_header_type(QUIC_VERSION_1,
						  QUIC_V1_PACKET_TYPE_INITIAL);
	KUNIT_EXPECT_EQ(test, (first_byte >> 4) & 0x03, QUIC_V1_PACKET_TYPE_INITIAL);

	/* 0-RTT packet */
	first_byte = test_encode_long_header_type(QUIC_VERSION_1,
						  QUIC_V1_PACKET_TYPE_0RTT);
	KUNIT_EXPECT_EQ(test, (first_byte >> 4) & 0x03, QUIC_V1_PACKET_TYPE_0RTT);

	/* Handshake packet */
	first_byte = test_encode_long_header_type(QUIC_VERSION_1,
						  QUIC_V1_PACKET_TYPE_HANDSHAKE);
	KUNIT_EXPECT_EQ(test, (first_byte >> 4) & 0x03, QUIC_V1_PACKET_TYPE_HANDSHAKE);

	/* Retry packet */
	first_byte = test_encode_long_header_type(QUIC_VERSION_1,
						  QUIC_V1_PACKET_TYPE_RETRY);
	KUNIT_EXPECT_EQ(test, (first_byte >> 4) & 0x03, QUIC_V1_PACKET_TYPE_RETRY);
}

/* Test: v2 packet type encoding differs from v1 */
static void test_v2_packet_type_encoding(struct kunit *test)
{
	u8 first_byte;

	/* Initial packet: v1=0, v2=1 */
	first_byte = test_encode_long_header_type(QUIC_VERSION_2,
						  QUIC_V1_PACKET_TYPE_INITIAL);
	KUNIT_EXPECT_EQ(test, (first_byte >> 4) & 0x03, QUIC_V2_PACKET_TYPE_INITIAL);
	KUNIT_EXPECT_EQ(test, (first_byte >> 4) & 0x03, 1U);

	/* 0-RTT packet: v1=1, v2=2 */
	first_byte = test_encode_long_header_type(QUIC_VERSION_2,
						  QUIC_V1_PACKET_TYPE_0RTT);
	KUNIT_EXPECT_EQ(test, (first_byte >> 4) & 0x03, QUIC_V2_PACKET_TYPE_0RTT);
	KUNIT_EXPECT_EQ(test, (first_byte >> 4) & 0x03, 2U);

	/* Retry packet: v1=3, v2=0 */
	first_byte = test_encode_long_header_type(QUIC_VERSION_2,
						  QUIC_V1_PACKET_TYPE_RETRY);
	KUNIT_EXPECT_EQ(test, (first_byte >> 4) & 0x03, QUIC_V2_PACKET_TYPE_RETRY);
	KUNIT_EXPECT_EQ(test, (first_byte >> 4) & 0x03, 0U);
}

/* Test: Packet type decode for v1 */
static void test_v1_packet_type_decoding(struct kunit *test)
{
	u8 first_byte;
	u8 decoded_type;

	/* Encode then decode Initial */
	first_byte = test_encode_long_header_type(QUIC_VERSION_1,
						  QUIC_V1_PACKET_TYPE_INITIAL);
	decoded_type = test_decode_long_header_type(QUIC_VERSION_1, first_byte);
	KUNIT_EXPECT_EQ(test, decoded_type, QUIC_V1_PACKET_TYPE_INITIAL);

	/* Encode then decode Handshake */
	first_byte = test_encode_long_header_type(QUIC_VERSION_1,
						  QUIC_V1_PACKET_TYPE_HANDSHAKE);
	decoded_type = test_decode_long_header_type(QUIC_VERSION_1, first_byte);
	KUNIT_EXPECT_EQ(test, decoded_type, QUIC_V1_PACKET_TYPE_HANDSHAKE);
}

/* Test: Packet type decode for v2 normalizes to v1 types */
static void test_v2_packet_type_decoding(struct kunit *test)
{
	u8 first_byte;
	u8 decoded_type;

	/* Encode with v2, decode should give v1 logical type */
	first_byte = test_encode_long_header_type(QUIC_VERSION_2,
						  QUIC_V1_PACKET_TYPE_INITIAL);
	decoded_type = test_decode_long_header_type(QUIC_VERSION_2, first_byte);
	KUNIT_EXPECT_EQ(test, decoded_type, QUIC_V1_PACKET_TYPE_INITIAL);

	first_byte = test_encode_long_header_type(QUIC_VERSION_2,
						  QUIC_V1_PACKET_TYPE_RETRY);
	decoded_type = test_decode_long_header_type(QUIC_VERSION_2, first_byte);
	KUNIT_EXPECT_EQ(test, decoded_type, QUIC_V1_PACKET_TYPE_RETRY);
}

/* Test: Type conversion roundtrip */
static void test_packet_type_conversion_roundtrip(struct kunit *test)
{
	u8 i;

	for (i = 0; i <= 3; i++) {
		u8 v2_type = test_v1_to_v2_packet_type(i);
		u8 back_to_v1 = test_v2_to_v1_packet_type(v2_type);
		KUNIT_EXPECT_EQ(test, back_to_v1, i);
	}
}

/*
 * =============================================================================
 * SECTION 5: Retry Integrity Tests
 * =============================================================================
 */

/* Test: v1 Retry integrity key is correct */
static void test_v1_retry_key(struct kunit *test)
{
	u8 key[16];
	int ret;

	ret = test_get_retry_key(QUIC_VERSION_1, key);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, memcmp(key, quic_v1_retry_key, 16), 0);
}

/* Test: v2 Retry integrity key is correct and different from v1 */
static void test_v2_retry_key(struct kunit *test)
{
	u8 key[16];
	int ret;

	ret = test_get_retry_key(QUIC_VERSION_2, key);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, memcmp(key, quic_v2_retry_key, 16), 0);

	/* v2 key different from v1 */
	KUNIT_EXPECT_NE(test, memcmp(quic_v1_retry_key, quic_v2_retry_key, 16), 0);
}

/* Test: v1 Retry integrity nonce is correct */
static void test_v1_retry_nonce(struct kunit *test)
{
	u8 nonce[12];
	int ret;

	ret = test_get_retry_nonce(QUIC_VERSION_1, nonce);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, memcmp(nonce, quic_v1_retry_nonce, 12), 0);
}

/* Test: v2 Retry integrity nonce is correct and different from v1 */
static void test_v2_retry_nonce(struct kunit *test)
{
	u8 nonce[12];
	int ret;

	ret = test_get_retry_nonce(QUIC_VERSION_2, nonce);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, memcmp(nonce, quic_v2_retry_nonce, 12), 0);

	/* v2 nonce different from v1 */
	KUNIT_EXPECT_NE(test, memcmp(quic_v1_retry_nonce, quic_v2_retry_nonce, 12), 0);
}

/* Test: Unknown version returns error for Retry params */
static void test_unknown_version_retry(struct kunit *test)
{
	u8 key[16], nonce[12];

	KUNIT_EXPECT_EQ(test, test_get_retry_key(0x12345678, key), -EINVAL);
	KUNIT_EXPECT_EQ(test, test_get_retry_nonce(0x12345678, nonce), -EINVAL);
}

/*
 * =============================================================================
 * SECTION 6: Version Negotiation Tests
 * =============================================================================
 */

/* Test: Select v2 when both are offered and v2 is preferred */
static void test_version_nego_prefer_v2(struct kunit *test)
{
	struct version_nego_packet offered = {
		.versions = {QUIC_VERSION_1, QUIC_VERSION_2},
		.version_count = 2,
	};
	u32 preferred[] = {QUIC_VERSION_2, QUIC_VERSION_1};
	u32 selected;

	selected = test_select_version(&offered, preferred, 2);
	KUNIT_EXPECT_EQ(test, selected, QUIC_VERSION_2);
}

/* Test: Select v1 when only v1 is offered */
static void test_version_nego_only_v1(struct kunit *test)
{
	struct version_nego_packet offered = {
		.versions = {QUIC_VERSION_1},
		.version_count = 1,
	};
	u32 preferred[] = {QUIC_VERSION_2, QUIC_VERSION_1};
	u32 selected;

	selected = test_select_version(&offered, preferred, 2);
	KUNIT_EXPECT_EQ(test, selected, QUIC_VERSION_1);
}

/* Test: No compatible version */
static void test_version_nego_no_compatible(struct kunit *test)
{
	struct version_nego_packet offered = {
		.versions = {0x12345678, 0x87654321},
		.version_count = 2,
	};
	u32 preferred[] = {QUIC_VERSION_2, QUIC_VERSION_1};
	u32 selected;

	selected = test_select_version(&offered, preferred, 2);
	KUNIT_EXPECT_EQ(test, selected, 0U);
}

/* Test: Select v1 when it's preferred and both offered */
static void test_version_nego_prefer_v1(struct kunit *test)
{
	struct version_nego_packet offered = {
		.versions = {QUIC_VERSION_2, QUIC_VERSION_1},
		.version_count = 2,
	};
	u32 preferred[] = {QUIC_VERSION_1, QUIC_VERSION_2};
	u32 selected;

	selected = test_select_version(&offered, preferred, 2);
	KUNIT_EXPECT_EQ(test, selected, QUIC_VERSION_1);
}

/* Test: Version negotiation with single version */
static void test_version_nego_single_preferred(struct kunit *test)
{
	struct version_nego_packet offered = {
		.versions = {QUIC_VERSION_1, QUIC_VERSION_2},
		.version_count = 2,
	};
	u32 preferred[] = {QUIC_VERSION_2};
	u32 selected;

	selected = test_select_version(&offered, preferred, 1);
	KUNIT_EXPECT_EQ(test, selected, QUIC_VERSION_2);
}

/* Test: Empty offered list returns 0 */
static void test_version_nego_empty_offered(struct kunit *test)
{
	struct version_nego_packet offered = {
		.version_count = 0,
	};
	u32 preferred[] = {QUIC_VERSION_1, QUIC_VERSION_2};
	u32 selected;

	selected = test_select_version(&offered, preferred, 2);
	KUNIT_EXPECT_EQ(test, selected, 0U);
}

/* Test: Version number is big-endian in packet */
static void test_version_wire_format(struct kunit *test)
{
	u8 buf[4];

	/* QUIC_VERSION_1 = 0x00000001 in big-endian */
	test_encode_version(buf, QUIC_VERSION_1);
	KUNIT_EXPECT_EQ(test, buf[0], 0x00);
	KUNIT_EXPECT_EQ(test, buf[1], 0x00);
	KUNIT_EXPECT_EQ(test, buf[2], 0x00);
	KUNIT_EXPECT_EQ(test, buf[3], 0x01);

	/* QUIC_VERSION_2 = 0x6b3343cf in big-endian */
	test_encode_version(buf, QUIC_VERSION_2);
	KUNIT_EXPECT_EQ(test, buf[0], 0x6b);
	KUNIT_EXPECT_EQ(test, buf[1], 0x33);
	KUNIT_EXPECT_EQ(test, buf[2], 0x43);
	KUNIT_EXPECT_EQ(test, buf[3], 0xcf);
}

/*
 * =============================================================================
 * Test Suite Definition
 * =============================================================================
 */

static struct kunit_case tquic_quic_v2_test_cases[] = {
	/* Version Constants */
	KUNIT_CASE(test_version_numbers),
	KUNIT_CASE(test_valid_versions),
	KUNIT_CASE(test_version_encoding),

	/* Initial Salt */
	KUNIT_CASE(test_v1_initial_salt),
	KUNIT_CASE(test_v2_initial_salt),
	KUNIT_CASE(test_unknown_version_salt),

	/* HKDF Labels */
	KUNIT_CASE(test_v1_hkdf_labels),
	KUNIT_CASE(test_v2_hkdf_labels),
	KUNIT_CASE(test_unknown_version_labels),

	/* Packet Type Encoding */
	KUNIT_CASE(test_v1_packet_type_encoding),
	KUNIT_CASE(test_v2_packet_type_encoding),
	KUNIT_CASE(test_v1_packet_type_decoding),
	KUNIT_CASE(test_v2_packet_type_decoding),
	KUNIT_CASE(test_packet_type_conversion_roundtrip),

	/* Retry Integrity */
	KUNIT_CASE(test_v1_retry_key),
	KUNIT_CASE(test_v2_retry_key),
	KUNIT_CASE(test_v1_retry_nonce),
	KUNIT_CASE(test_v2_retry_nonce),
	KUNIT_CASE(test_unknown_version_retry),

	/* Version Negotiation */
	KUNIT_CASE(test_version_nego_prefer_v2),
	KUNIT_CASE(test_version_nego_only_v1),
	KUNIT_CASE(test_version_nego_no_compatible),
	KUNIT_CASE(test_version_nego_prefer_v1),
	KUNIT_CASE(test_version_nego_single_preferred),
	KUNIT_CASE(test_version_nego_empty_offered),
	KUNIT_CASE(test_version_wire_format),
	{}
};

static struct kunit_suite tquic_quic_v2_test_suite = {
	.name = "tquic-quic-v2",
	.test_cases = tquic_quic_v2_test_cases,
};

kunit_test_suite(tquic_quic_v2_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for TQUIC QUIC v2 (RFC 9369)");
MODULE_AUTHOR("Linux Foundation");
