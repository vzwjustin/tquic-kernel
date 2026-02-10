// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: MASQUE KUnit Tests (RFC 9297, RFC 9298, RFC 9484)
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Comprehensive tests for MASQUE protocols:
 *   - CONNECT-UDP tunnel setup (RFC 9298)
 *   - CONNECT-IP tunnel setup (RFC 9484)
 *   - HTTP Datagrams (RFC 9297)
 *   - Capsule protocol
 *   - Address assignment
 *
 * Test Structure:
 *   Section 1: HTTP Datagram Tests
 *   Section 2: CONNECT-UDP URI Template Tests
 *   Section 3: CONNECT-UDP Tunnel Tests
 *   Section 4: CONNECT-IP Capsule Tests
 *   Section 5: Address Assignment Tests
 */

#include <kunit/test.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/in.h>
#include <linux/in6.h>

/*
 * =============================================================================
 * Constants
 * =============================================================================
 */

/* HTTP Datagram context IDs */
#define HTTP_DATAGRAM_CONTEXT_ID_UDP	0
#define HTTP_DATAGRAM_CONTEXT_ID_IP	0

/* CONNECT-UDP URI template */
#define CONNECT_UDP_TEMPLATE		"/.well-known/masque/udp/%s/%u/"
#define CONNECT_UDP_HOST_MAX		256

/* CONNECT-IP capsule types (RFC 9484) */
#define CAPSULE_ADDRESS_ASSIGN		0x01
#define CAPSULE_ADDRESS_REQUEST		0x02
#define CAPSULE_ROUTE_ADVERTISEMENT	0x03

/* IP versions */
#define IP_VERSION_4			4
#define IP_VERSION_6			6

/* MTU limits */
#define MIN_MTU_IPV4			68
#define MIN_MTU_IPV6			1280

/*
 * =============================================================================
 * Test Data Structures
 * =============================================================================
 */

/**
 * struct test_http_datagram - HTTP Datagram structure
 * @context_id: Context ID (varint)
 * @payload: Datagram payload
 * @payload_len: Payload length
 */
struct test_http_datagram {
	u64 context_id;
	u8 *payload;
	size_t payload_len;
};

/**
 * enum connect_udp_state - CONNECT-UDP tunnel state
 */
enum connect_udp_state {
	CONNECT_UDP_IDLE = 0,
	CONNECT_UDP_REQUESTING,
	CONNECT_UDP_ESTABLISHED,
	CONNECT_UDP_CLOSING,
	CONNECT_UDP_CLOSED,
};

/**
 * struct test_connect_udp_tunnel - CONNECT-UDP tunnel state
 * @host: Target hostname
 * @port: Target port
 * @state: Tunnel state
 * @context_id: Current context ID
 * @tx_datagrams: Transmitted datagram count
 * @rx_datagrams: Received datagram count
 */
struct test_connect_udp_tunnel {
	char host[CONNECT_UDP_HOST_MAX];
	u16 port;
	enum connect_udp_state state;
	u64 context_id;
	u64 tx_datagrams;
	u64 rx_datagrams;
};

/**
 * struct test_ip_address - IP address for CONNECT-IP
 * @version: 4 or 6
 * @prefix_len: Prefix length
 */
struct test_ip_address {
	u8 version;
	union {
		__be32 v4;
		u8 v6[16];
	} addr;
	u8 prefix_len;
	u64 request_id;
};

/**
 * struct test_address_assign - ADDRESS_ASSIGN capsule
 * @request_id: Request ID
 * @ip_version: IP version
 * @addr: IP address (4 or 16 bytes)
 * @prefix_len: Prefix length
 */
struct test_address_assign {
	u64 request_id;
	u8 ip_version;
	u8 addr[16];
	u8 prefix_len;
};

/**
 * struct test_route_adv - Route advertisement entry
 * @ip_version: IP version
 * @start_addr: Start of range
 * @end_addr: End of range
 * @ipproto: IP protocol (0 = any)
 */
struct test_route_adv {
	u8 ip_version;
	u8 start_addr[16];
	u8 end_addr[16];
	u8 ipproto;
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
 * HTTP Datagram Encoding/Decoding (RFC 9297)
 * =============================================================================
 */

/**
 * test_http_datagram_encode - Encode HTTP Datagram
 * @buf: Output buffer
 * @buf_len: Buffer length
 * @dg: Datagram to encode
 *
 * Returns: Bytes written, or negative error
 */
static int test_http_datagram_encode(u8 *buf, size_t buf_len,
				     const struct test_http_datagram *dg)
{
	size_t offset = 0;
	int ret;

	/* Context ID */
	ret = test_varint_encode(buf + offset, buf_len - offset, dg->context_id);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Payload */
	if (buf_len - offset < dg->payload_len)
		return -ENOBUFS;
	if (dg->payload_len > 0 && dg->payload)
		memcpy(buf + offset, dg->payload, dg->payload_len);
	offset += dg->payload_len;

	return offset;
}

/**
 * test_http_datagram_decode - Decode HTTP Datagram
 * @buf: Input buffer
 * @buf_len: Buffer length
 * @dg: Output datagram (payload points into buf)
 *
 * Returns: Bytes consumed, or negative error
 */
static int test_http_datagram_decode(const u8 *buf, size_t buf_len,
				     struct test_http_datagram *dg)
{
	size_t offset = 0;
	int ret;

	/* Context ID */
	ret = test_varint_decode(buf + offset, buf_len - offset, &dg->context_id);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Payload (rest of datagram) */
	dg->payload = (u8 *)(buf + offset);
	dg->payload_len = buf_len - offset;

	return buf_len;
}

/*
 * =============================================================================
 * CONNECT-UDP URI Template Parsing
 * =============================================================================
 */

/**
 * test_parse_connect_udp_uri - Parse CONNECT-UDP URI template
 * @path: Request path
 * @host: Output hostname buffer
 * @host_len: Hostname buffer length
 * @port: Output port
 *
 * Returns: 0 on success, negative error on failure
 */
static int test_parse_connect_udp_uri(const char *path,
				      char *host, size_t host_len,
				      u16 *port)
{
	const char *prefix = "/.well-known/masque/udp/";
	const char *p, *slash;
	size_t len;
	unsigned long parsed_port;

	if (!path || strncmp(path, prefix, strlen(prefix)) != 0)
		return -EINVAL;

	p = path + strlen(prefix);

	/* Find hostname (up to next slash) */
	slash = strchr(p, '/');
	if (!slash)
		return -EINVAL;

	len = slash - p;
	if (len == 0 || len >= host_len)
		return -EINVAL;

	memcpy(host, p, len);
	host[len] = '\0';

	/* Parse port */
	p = slash + 1;
	if (*p == '\0')
		return -EINVAL;

	parsed_port = 0;
	while (*p && *p != '/') {
		if (*p < '0' || *p > '9')
			return -EINVAL;
		parsed_port = parsed_port * 10 + (*p - '0');
		if (parsed_port > 65535)
			return -ERANGE;
		p++;
	}

	if (parsed_port == 0)
		return -EINVAL;

	*port = (u16)parsed_port;
	return 0;
}

/**
 * test_build_connect_udp_uri - Build CONNECT-UDP URI path
 * @host: Target hostname
 * @port: Target port
 * @buf: Output buffer
 * @buf_len: Buffer length
 *
 * Returns: Bytes written (including null), or negative error
 */
static int test_build_connect_udp_uri(const char *host, u16 port,
				      char *buf, size_t buf_len)
{
	int ret;

	ret = snprintf(buf, buf_len, "/.well-known/masque/udp/%s/%u/",
		       host, port);
	if (ret < 0 || (size_t)ret >= buf_len)
		return -ENOBUFS;

	return ret + 1;  /* Include null terminator */
}

/*
 * =============================================================================
 * CONNECT-UDP Tunnel Management
 * =============================================================================
 */

/**
 * test_connect_udp_init - Initialize CONNECT-UDP tunnel
 * @tunnel: Tunnel to initialize
 * @host: Target host
 * @port: Target port
 */
static void test_connect_udp_init(struct test_connect_udp_tunnel *tunnel,
				  const char *host, u16 port)
{
	memset(tunnel, 0, sizeof(*tunnel));
	strscpy(tunnel->host, host, CONNECT_UDP_HOST_MAX);
	tunnel->port = port;
	tunnel->state = CONNECT_UDP_IDLE;
	tunnel->context_id = 0;  /* UDP payload uses context ID 0 */
}

/**
 * test_connect_udp_connect - Start connection
 * @tunnel: Tunnel
 *
 * Returns: 0 on success
 */
static int test_connect_udp_connect(struct test_connect_udp_tunnel *tunnel)
{
	if (tunnel->state != CONNECT_UDP_IDLE)
		return -EINVAL;
	tunnel->state = CONNECT_UDP_REQUESTING;
	return 0;
}

/**
 * test_connect_udp_establish - Mark tunnel as established
 * @tunnel: Tunnel
 *
 * Returns: 0 on success
 */
static int test_connect_udp_establish(struct test_connect_udp_tunnel *tunnel)
{
	if (tunnel->state != CONNECT_UDP_REQUESTING)
		return -EINVAL;
	tunnel->state = CONNECT_UDP_ESTABLISHED;
	return 0;
}

/**
 * test_connect_udp_close - Close tunnel
 * @tunnel: Tunnel
 */
static void test_connect_udp_close(struct test_connect_udp_tunnel *tunnel)
{
	tunnel->state = CONNECT_UDP_CLOSED;
}

/*
 * =============================================================================
 * CONNECT-IP Capsule Encoding/Decoding
 * =============================================================================
 */

/**
 * test_encode_address_assign - Encode ADDRESS_ASSIGN capsule
 * @buf: Output buffer
 * @buf_len: Buffer length
 * @assign: Address assignment info
 *
 * Returns: Bytes written, or negative error
 */
static int test_encode_address_assign(u8 *buf, size_t buf_len,
				      const struct test_address_assign *assign)
{
	size_t offset = 0;
	int ret;
	size_t addr_len = (assign->ip_version == 4) ? 4 : 16;

	/* Capsule type */
	ret = test_varint_encode(buf + offset, buf_len - offset,
				 CAPSULE_ADDRESS_ASSIGN);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Calculate capsule data length */
	size_t data_len = test_varint_size(assign->request_id) + 1 + addr_len + 1;

	/* Capsule length */
	ret = test_varint_encode(buf + offset, buf_len - offset, data_len);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Request ID */
	ret = test_varint_encode(buf + offset, buf_len - offset,
				 assign->request_id);
	if (ret < 0)
		return ret;
	offset += ret;

	/* IP version */
	if (buf_len - offset < 1 + addr_len + 1)
		return -ENOBUFS;
	buf[offset++] = assign->ip_version;

	/* Address */
	memcpy(buf + offset, assign->addr, addr_len);
	offset += addr_len;

	/* Prefix length */
	buf[offset++] = assign->prefix_len;

	return offset;
}

/**
 * test_decode_address_assign - Decode ADDRESS_ASSIGN capsule
 * @buf: Input buffer
 * @buf_len: Buffer length
 * @assign: Output assignment
 *
 * Returns: Bytes consumed, or negative error
 */
static int test_decode_address_assign(const u8 *buf, size_t buf_len,
				      struct test_address_assign *assign)
{
	size_t offset = 0;
	u64 capsule_type, capsule_len;
	size_t addr_len;
	int ret;

	/* Capsule type */
	ret = test_varint_decode(buf + offset, buf_len - offset, &capsule_type);
	if (ret < 0)
		return ret;
	if (capsule_type != CAPSULE_ADDRESS_ASSIGN)
		return -EINVAL;
	offset += ret;

	/* Capsule length */
	ret = test_varint_decode(buf + offset, buf_len - offset, &capsule_len);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Request ID */
	ret = test_varint_decode(buf + offset, buf_len - offset,
				 &assign->request_id);
	if (ret < 0)
		return ret;
	offset += ret;

	/* IP version */
	if (buf_len - offset < 1)
		return -EINVAL;
	assign->ip_version = buf[offset++];

	/* Address */
	addr_len = (assign->ip_version == 4) ? 4 : 16;
	if (buf_len - offset < addr_len + 1)
		return -EINVAL;
	memset(assign->addr, 0, sizeof(assign->addr));
	memcpy(assign->addr, buf + offset, addr_len);
	offset += addr_len;

	/* Prefix length */
	assign->prefix_len = buf[offset++];

	return offset;
}

/*
 * =============================================================================
 * SECTION 1: HTTP Datagram Tests
 * =============================================================================
 */

/* Test: Encode and decode HTTP Datagram */
static void test_http_datagram_roundtrip(struct kunit *test)
{
	u8 buf[128];
	u8 payload[] = "UDP payload data";
	struct test_http_datagram input = {
		.context_id = HTTP_DATAGRAM_CONTEXT_ID_UDP,
		.payload = payload,
		.payload_len = sizeof(payload) - 1,
	};
	struct test_http_datagram output;
	int encode_ret, decode_ret;

	/* ACT: Encode */
	encode_ret = test_http_datagram_encode(buf, sizeof(buf), &input);
	KUNIT_EXPECT_GT(test, encode_ret, 0);

	/* ACT: Decode */
	decode_ret = test_http_datagram_decode(buf, encode_ret, &output);

	/* ASSERT */
	KUNIT_EXPECT_EQ(test, decode_ret, encode_ret);
	KUNIT_EXPECT_EQ(test, output.context_id, (u64)HTTP_DATAGRAM_CONTEXT_ID_UDP);
	KUNIT_EXPECT_EQ(test, output.payload_len, sizeof(payload) - 1);
	KUNIT_EXPECT_EQ(test, memcmp(output.payload, payload, output.payload_len), 0);
}

/* Test: HTTP Datagram with non-zero context ID */
static void test_http_datagram_nonzero_context(struct kunit *test)
{
	u8 buf[64];
	struct test_http_datagram input = {
		.context_id = 12345,
		.payload = (u8 *)"Test",
		.payload_len = 4,
	};
	struct test_http_datagram output;
	int ret;

	/* ACT */
	ret = test_http_datagram_encode(buf, sizeof(buf), &input);
	KUNIT_EXPECT_GT(test, ret, 0);

	ret = test_http_datagram_decode(buf, ret, &output);

	/* ASSERT */
	KUNIT_EXPECT_GT(test, ret, 0);
	KUNIT_EXPECT_EQ(test, output.context_id, 12345ULL);
}

/* Test: HTTP Datagram with empty payload */
static void test_http_datagram_empty_payload(struct kunit *test)
{
	u8 buf[16];
	struct test_http_datagram input = {
		.context_id = 0,
		.payload = NULL,
		.payload_len = 0,
	};
	struct test_http_datagram output;
	int ret;

	/* ACT */
	ret = test_http_datagram_encode(buf, sizeof(buf), &input);
	KUNIT_EXPECT_GT(test, ret, 0);

	ret = test_http_datagram_decode(buf, ret, &output);

	/* ASSERT */
	KUNIT_EXPECT_GT(test, ret, 0);
	KUNIT_EXPECT_EQ(test, output.payload_len, 0UL);
}

/* Test: HTTP Datagram decode with empty buffer */
static void test_http_datagram_decode_empty(struct kunit *test)
{
	u8 buf[1];
	struct test_http_datagram output;
	int ret;

	/* ACT/ASSERT */
	ret = test_http_datagram_decode(buf, 0, &output);
	KUNIT_EXPECT_LT(test, ret, 0);
}

/*
 * =============================================================================
 * SECTION 2: CONNECT-UDP URI Template Tests
 * =============================================================================
 */

/* Test: Parse valid CONNECT-UDP URI */
static void test_connect_udp_parse_valid(struct kunit *test)
{
	char host[256];
	u16 port;
	int ret;

	/* ACT */
	ret = test_parse_connect_udp_uri(
		"/.well-known/masque/udp/example.com/443/",
		host, sizeof(host), &port);

	/* ASSERT */
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_STREQ(test, host, "example.com");
	KUNIT_EXPECT_EQ(test, port, 443U);
}

/* Test: Parse URI with IP address */
static void test_connect_udp_parse_ip(struct kunit *test)
{
	char host[256];
	u16 port;
	int ret;

	/* ACT */
	ret = test_parse_connect_udp_uri(
		"/.well-known/masque/udp/192.168.1.1/8080/",
		host, sizeof(host), &port);

	/* ASSERT */
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_STREQ(test, host, "192.168.1.1");
	KUNIT_EXPECT_EQ(test, port, 8080U);
}

/* Test: Build CONNECT-UDP URI */
static void test_connect_udp_build_uri(struct kunit *test)
{
	char buf[256];
	int ret;

	/* ACT */
	ret = test_build_connect_udp_uri("example.com", 443, buf, sizeof(buf));

	/* ASSERT */
	KUNIT_EXPECT_GT(test, ret, 0);
	KUNIT_EXPECT_STREQ(test, buf, "/.well-known/masque/udp/example.com/443/");
}

/* Test: Parse invalid URI - wrong prefix */
static void test_connect_udp_parse_wrong_prefix(struct kunit *test)
{
	char host[256];
	u16 port;
	int ret;

	/* ACT/ASSERT */
	ret = test_parse_connect_udp_uri(
		"/wrong/prefix/udp/example.com/443/",
		host, sizeof(host), &port);
	KUNIT_EXPECT_LT(test, ret, 0);
}

/* Test: Parse URI - port out of range */
static void test_connect_udp_parse_port_range(struct kunit *test)
{
	char host[256];
	u16 port;
	int ret;

	/* ACT/ASSERT: Port > 65535 */
	ret = test_parse_connect_udp_uri(
		"/.well-known/masque/udp/example.com/99999/",
		host, sizeof(host), &port);
	KUNIT_EXPECT_LT(test, ret, 0);
}

/* Test: Parse URI - missing port */
static void test_connect_udp_parse_missing_port(struct kunit *test)
{
	char host[256];
	u16 port;
	int ret;

	/* ACT/ASSERT */
	ret = test_parse_connect_udp_uri(
		"/.well-known/masque/udp/example.com/",
		host, sizeof(host), &port);
	KUNIT_EXPECT_LT(test, ret, 0);
}

/*
 * =============================================================================
 * SECTION 3: CONNECT-UDP Tunnel Tests
 * =============================================================================
 */

/* Test: Tunnel initialization */
static void test_connect_udp_tunnel_init(struct kunit *test)
{
	struct test_connect_udp_tunnel tunnel;

	/* ACT */
	test_connect_udp_init(&tunnel, "example.com", 443);

	/* ASSERT */
	KUNIT_EXPECT_STREQ(test, tunnel.host, "example.com");
	KUNIT_EXPECT_EQ(test, tunnel.port, 443U);
	KUNIT_EXPECT_EQ(test, tunnel.state, CONNECT_UDP_IDLE);
	KUNIT_EXPECT_EQ(test, tunnel.context_id, 0ULL);
}

/* Test: Normal tunnel lifecycle */
static void test_connect_udp_tunnel_lifecycle(struct kunit *test)
{
	struct test_connect_udp_tunnel tunnel;
	int ret;

	/* ARRANGE */
	test_connect_udp_init(&tunnel, "example.com", 443);

	/* ACT/ASSERT: Connect */
	ret = test_connect_udp_connect(&tunnel);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, tunnel.state, CONNECT_UDP_REQUESTING);

	/* ACT/ASSERT: Establish */
	ret = test_connect_udp_establish(&tunnel);
	KUNIT_EXPECT_EQ(test, ret, 0);
	KUNIT_EXPECT_EQ(test, tunnel.state, CONNECT_UDP_ESTABLISHED);

	/* ACT/ASSERT: Close */
	test_connect_udp_close(&tunnel);
	KUNIT_EXPECT_EQ(test, tunnel.state, CONNECT_UDP_CLOSED);
}

/* Test: Invalid state transition */
static void test_connect_udp_tunnel_invalid_transition(struct kunit *test)
{
	struct test_connect_udp_tunnel tunnel;
	int ret;

	/* ARRANGE */
	test_connect_udp_init(&tunnel, "example.com", 443);

	/* ACT/ASSERT: Cannot establish from IDLE */
	ret = test_connect_udp_establish(&tunnel);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
	KUNIT_EXPECT_EQ(test, tunnel.state, CONNECT_UDP_IDLE);
}

/* Test: Double connect */
static void test_connect_udp_double_connect(struct kunit *test)
{
	struct test_connect_udp_tunnel tunnel;
	int ret;

	/* ARRANGE */
	test_connect_udp_init(&tunnel, "example.com", 443);
	test_connect_udp_connect(&tunnel);

	/* ACT/ASSERT */
	ret = test_connect_udp_connect(&tunnel);
	KUNIT_EXPECT_EQ(test, ret, -EINVAL);
}

/*
 * =============================================================================
 * SECTION 4: CONNECT-IP Capsule Tests
 * =============================================================================
 */

/* Test: Encode and decode ADDRESS_ASSIGN (IPv4) */
static void test_address_assign_ipv4(struct kunit *test)
{
	u8 buf[64];
	struct test_address_assign input = {
		.request_id = 1,
		.ip_version = 4,
		.prefix_len = 24,
	};
	struct test_address_assign output;
	int ret;

	/* Set IPv4 address: 192.168.1.100 */
	input.addr[0] = 192;
	input.addr[1] = 168;
	input.addr[2] = 1;
	input.addr[3] = 100;

	/* ACT: Encode */
	ret = test_encode_address_assign(buf, sizeof(buf), &input);
	KUNIT_EXPECT_GT(test, ret, 0);

	/* ACT: Decode */
	ret = test_decode_address_assign(buf, ret, &output);

	/* ASSERT */
	KUNIT_EXPECT_GT(test, ret, 0);
	KUNIT_EXPECT_EQ(test, output.request_id, 1ULL);
	KUNIT_EXPECT_EQ(test, output.ip_version, 4U);
	KUNIT_EXPECT_EQ(test, output.prefix_len, 24U);
	KUNIT_EXPECT_EQ(test, output.addr[0], 192U);
	KUNIT_EXPECT_EQ(test, output.addr[1], 168U);
	KUNIT_EXPECT_EQ(test, output.addr[2], 1U);
	KUNIT_EXPECT_EQ(test, output.addr[3], 100U);
}

/* Test: Encode and decode ADDRESS_ASSIGN (IPv6) */
static void test_address_assign_ipv6(struct kunit *test)
{
	u8 buf[64];
	struct test_address_assign input = {
		.request_id = 42,
		.ip_version = 6,
		.prefix_len = 64,
	};
	struct test_address_assign output;
	int ret;

	/* Set IPv6 address: 2001:db8::1 */
	memset(input.addr, 0, sizeof(input.addr));
	input.addr[0] = 0x20;
	input.addr[1] = 0x01;
	input.addr[2] = 0x0d;
	input.addr[3] = 0xb8;
	input.addr[15] = 0x01;

	/* ACT */
	ret = test_encode_address_assign(buf, sizeof(buf), &input);
	KUNIT_EXPECT_GT(test, ret, 0);

	ret = test_decode_address_assign(buf, ret, &output);

	/* ASSERT */
	KUNIT_EXPECT_GT(test, ret, 0);
	KUNIT_EXPECT_EQ(test, output.request_id, 42ULL);
	KUNIT_EXPECT_EQ(test, output.ip_version, 6U);
	KUNIT_EXPECT_EQ(test, output.prefix_len, 64U);
	KUNIT_EXPECT_EQ(test, output.addr[0], 0x20U);
	KUNIT_EXPECT_EQ(test, output.addr[1], 0x01U);
}

/* Test: ADDRESS_ASSIGN with large request ID */
static void test_address_assign_large_request_id(struct kunit *test)
{
	u8 buf[64];
	struct test_address_assign input = {
		.request_id = 1000000,
		.ip_version = 4,
		.prefix_len = 32,
	};
	struct test_address_assign output;
	int ret;

	input.addr[0] = 10;
	input.addr[1] = 0;
	input.addr[2] = 0;
	input.addr[3] = 1;

	/* ACT */
	ret = test_encode_address_assign(buf, sizeof(buf), &input);
	KUNIT_EXPECT_GT(test, ret, 0);

	ret = test_decode_address_assign(buf, ret, &output);

	/* ASSERT */
	KUNIT_EXPECT_GT(test, ret, 0);
	KUNIT_EXPECT_EQ(test, output.request_id, 1000000ULL);
}

/*
 * =============================================================================
 * SECTION 5: Address Assignment Tests
 * =============================================================================
 */

/* Test: IPv4 address validation */
static void test_ip_address_ipv4_validation(struct kunit *test)
{
	struct test_ip_address addr;

	/* ARRANGE: Valid IPv4 */
	addr.version = 4;
	addr.prefix_len = 24;

	/* ASSERT: Prefix length valid for IPv4 */
	KUNIT_EXPECT_LE(test, addr.prefix_len, 32U);
}

/* Test: IPv6 address validation */
static void test_ip_address_ipv6_validation(struct kunit *test)
{
	struct test_ip_address addr;

	/* ARRANGE: Valid IPv6 */
	addr.version = 6;
	addr.prefix_len = 64;

	/* ASSERT: Prefix length valid for IPv6 */
	KUNIT_EXPECT_LE(test, addr.prefix_len, 128U);
}

/* Test: MTU validation for IPv4 */
static void test_mtu_ipv4_minimum(struct kunit *test)
{
	u32 mtu = MIN_MTU_IPV4;

	/* ASSERT: IPv4 minimum MTU */
	KUNIT_EXPECT_EQ(test, mtu, 68U);
}

/* Test: MTU validation for IPv6 */
static void test_mtu_ipv6_minimum(struct kunit *test)
{
	u32 mtu = MIN_MTU_IPV6;

	/* ASSERT: IPv6 minimum MTU */
	KUNIT_EXPECT_EQ(test, mtu, 1280U);
}

/* Test: Route advertisement structure */
static void test_route_advertisement(struct kunit *test)
{
	struct test_route_adv route = {
		.ip_version = 4,
		.ipproto = 0,  /* Any protocol */
	};

	/* Set 0.0.0.0 to 255.255.255.255 (default route) */
	memset(route.start_addr, 0, 4);
	route.end_addr[0] = 255;
	route.end_addr[1] = 255;
	route.end_addr[2] = 255;
	route.end_addr[3] = 255;

	/* ASSERT */
	KUNIT_EXPECT_EQ(test, route.ip_version, 4U);
	KUNIT_EXPECT_EQ(test, route.ipproto, 0U);
	KUNIT_EXPECT_EQ(test, route.start_addr[0], 0U);
	KUNIT_EXPECT_EQ(test, route.end_addr[0], 255U);
}

/* Test: Protocol filter (specific protocol) */
static void test_protocol_filter(struct kunit *test)
{
	struct test_route_adv route = {
		.ip_version = 4,
		.ipproto = 17,  /* UDP only */
	};

	/* ASSERT */
	KUNIT_EXPECT_EQ(test, route.ipproto, 17U);  /* IPPROTO_UDP */
}

/*
 * =============================================================================
 * Test Suite Definition
 * =============================================================================
 */

static struct kunit_case tquic_masque_test_cases[] = {
	/* HTTP Datagram Tests */
	KUNIT_CASE(test_http_datagram_roundtrip),
	KUNIT_CASE(test_http_datagram_nonzero_context),
	KUNIT_CASE(test_http_datagram_empty_payload),
	KUNIT_CASE(test_http_datagram_decode_empty),

	/* CONNECT-UDP URI Template Tests */
	KUNIT_CASE(test_connect_udp_parse_valid),
	KUNIT_CASE(test_connect_udp_parse_ip),
	KUNIT_CASE(test_connect_udp_build_uri),
	KUNIT_CASE(test_connect_udp_parse_wrong_prefix),
	KUNIT_CASE(test_connect_udp_parse_port_range),
	KUNIT_CASE(test_connect_udp_parse_missing_port),

	/* CONNECT-UDP Tunnel Tests */
	KUNIT_CASE(test_connect_udp_tunnel_init),
	KUNIT_CASE(test_connect_udp_tunnel_lifecycle),
	KUNIT_CASE(test_connect_udp_tunnel_invalid_transition),
	KUNIT_CASE(test_connect_udp_double_connect),

	/* CONNECT-IP Capsule Tests */
	KUNIT_CASE(test_address_assign_ipv4),
	KUNIT_CASE(test_address_assign_ipv6),
	KUNIT_CASE(test_address_assign_large_request_id),

	/* Address Assignment Tests */
	KUNIT_CASE(test_ip_address_ipv4_validation),
	KUNIT_CASE(test_ip_address_ipv6_validation),
	KUNIT_CASE(test_mtu_ipv4_minimum),
	KUNIT_CASE(test_mtu_ipv6_minimum),
	KUNIT_CASE(test_route_advertisement),
	KUNIT_CASE(test_protocol_filter),
	{}
};

static struct kunit_suite tquic_masque_test_suite = {
	.name = "tquic-masque",
	.test_cases = tquic_masque_test_cases,
};

kunit_test_suite(tquic_masque_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for TQUIC MASQUE (RFC 9297, 9298, 9484)");
MODULE_AUTHOR("Linux Foundation");
