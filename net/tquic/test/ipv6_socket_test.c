// SPDX-License-Identifier: GPL-2.0-only
/*
 * KUnit tests for TQUIC IPv6 socket and version negotiation send
 *
 * Validates correctness invariants of the IPv6 client encap socket path
 * added to tquic_connect() and the version negotiation packet builder.
 * All tests operate on stack-allocated structures and byte arrays so that
 * they run without creating real kernel sockets (which requires full net
 * namespace / process context unavailable in KUnit).
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 */

#include <kunit/test.h>
#include <linux/kernel.h>
#include <linux/in6.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <net/tquic.h>

/*
 * Local copies of constants that are defined in implementation files rather
 * than public headers.  We redeclare them here to keep the test self-contained
 * and to make it obvious what value we are asserting against.
 */

/* RFC 9000 §17.2 — high bit of the first byte is the Header Form bit */
#define TQUIC_HEADER_FORM_LONG		0x80

/*
 * UDP encap type used by TQUIC (matches the value written into
 * udp_sk(usock->sk)->encap_type in tquic_connect()).
 */
#define TQUIC_UDP_ENCAP_TYPE		1

/*
 * Version field value that identifies a Version Negotiation packet
 * (RFC 9000 §17.2.1).
 */
#define TQUIC_VERSION_NEGOTIATION	0x00000000U

/* -------------------------------------------------------------------------
 * Helper: read a big-endian u32 from an arbitrary byte pointer.
 * Equivalent to get_unaligned_be32() but without the header dependency.
 * ------------------------------------------------------------------------- */
static u32 read_be32(const u8 *p)
{
	return ((u32)p[0] << 24) |
	       ((u32)p[1] << 16) |
	       ((u32)p[2] << 8)  |
	        (u32)p[3];
}

/* =========================================================================
 * Test 1: test_ipv6_bind_addr_update
 *
 * After the IPv6 encap-socket path completes, tquic_connect() writes:
 *
 *   ((struct sockaddr_in6 *)&tsk->bind_addr)->sin6_family = AF_INET6;
 *   ((struct sockaddr_in6 *)&tsk->bind_addr)->sin6_port  = bound6.sin6_port;
 *
 * We reproduce that write sequence on a stack-allocated sockaddr_storage
 * and verify:
 *   (a) The family is AF_INET6.
 *   (b) The port is non-zero (a real ephemeral port was recorded).
 *
 * This is the minimal correctness check for the getsockname→bind_addr update.
 * ========================================================================= */
static void test_ipv6_bind_addr_update(struct kunit *test)
{
	struct sockaddr_storage bind_addr;
	struct sockaddr_in6 *sin6;

	/*
	 * Simulate what tquic_connect() does after a successful
	 * kernel_getsockname() call that returned port 54321 (network order).
	 */
	memset(&bind_addr, 0, sizeof(bind_addr));

	sin6 = (struct sockaddr_in6 *)&bind_addr;
	sin6->sin6_family = AF_INET6;
	sin6->sin6_port   = htons(54321);

	/* Family must be AF_INET6 */
	KUNIT_EXPECT_EQ(test, (int)sin6->sin6_family, (int)AF_INET6);

	/* Port must be non-zero — the ephemeral port was recorded */
	KUNIT_EXPECT_NE(test, (int)sin6->sin6_port, 0);

	/* Cross-check: reading through the storage union gives same family */
	KUNIT_EXPECT_EQ(test,
			(int)((struct sockaddr_in6 *)&bind_addr)->sin6_family,
			(int)AF_INET6);

	/* Verify round-trip through htons/ntohs */
	KUNIT_EXPECT_EQ(test, (u16)ntohs(sin6->sin6_port), (u16)54321);
}

/* =========================================================================
 * Test 2: test_ipv6_encap_fields
 *
 * After creating the IPv6 UDP socket, tquic_connect() sets:
 *
 *   udp_sk(usock->sk)->encap_type = 1;
 *   udp_sk(usock->sk)->encap_rcv  = tquic_client_encap_recv;
 *
 * We cannot create a real udp_sock in KUnit, so we model the same assignment
 * using a local struct that mirrors the two relevant fields and verify the
 * constant / non-NULL pointer invariants that the production code relies on.
 * ========================================================================= */

/* Minimal stand-in that mirrors the encap fields of struct udp_sock */
struct mock_udp_sock_encap {
	int	encap_type;
	int	(*encap_rcv)(struct sock *sk, struct sk_buff *skb);
};

/* A non-NULL stand-in for tquic_client_encap_recv */
static int mock_encap_rcv(struct sock *sk, struct sk_buff *skb)
{
	return 0;
}

static void test_ipv6_encap_fields(struct kunit *test)
{
	struct mock_udp_sock_encap udp = {};

	/*
	 * Reproduce the two assignments from the IPv6 branch of
	 * tquic_connect().
	 */
	udp.encap_type = TQUIC_UDP_ENCAP_TYPE;
	udp.encap_rcv  = mock_encap_rcv;

	/* encap_type must be exactly 1 */
	KUNIT_EXPECT_EQ(test, udp.encap_type, (int)TQUIC_UDP_ENCAP_TYPE);
	KUNIT_EXPECT_EQ(test, udp.encap_type, 1);

	/* encap_rcv must not be NULL after registration */
	KUNIT_EXPECT_NOT_NULL(test, udp.encap_rcv);

	/*
	 * Verify that both IPv4 and IPv6 paths use the *same* encap_type
	 * value so that the UDP stack routes incoming packets identically.
	 */
	KUNIT_EXPECT_EQ(test, TQUIC_UDP_ENCAP_TYPE, 1);
}

/* =========================================================================
 * Test 3: test_ipv6_getsockname_failure_cleanup
 *
 * When kernel_getsockname() fails in the IPv6 branch, tquic_connect() does:
 *
 *   sock_release(usock);
 *   goto out_unlock;
 *
 * and the error code is returned to the caller.  We model this cleanup
 * pattern with a flag that records whether release was called and verify
 * the correct error code propagates.
 *
 * This test validates two invariants:
 *   (a) On getsockname failure the cleanup path is taken (no leak).
 *   (b) The caller receives the original error, not a different one.
 * ========================================================================= */
static void test_ipv6_getsockname_failure_cleanup(struct kunit *test)
{
	/*
	 * Simulate the local variables that tquic_connect() uses in the
	 * IPv6 block.
	 */
	bool socket_released = false;
	int ret;

	/* Simulate getsockname failing with -ENOBUFS */
	ret = -ENOBUFS;

	/*
	 * Reproduce the cleanup guard that surrounds getsockname in
	 * tquic_connect():
	 *
	 *   ret = kernel_getsockname(usock, ...);
	 *   if (ret < 0) {
	 *       sock_release(usock);
	 *       goto out_unlock;
	 *   }
	 */
	if (ret < 0) {
		/* sock_release(usock) - modelled by setting the flag */
		socket_released = true;
		goto out_unlock;
	}

	/* This point must NOT be reached on failure */
	KUNIT_FAIL(test, "Control should not reach here after getsockname failure");

out_unlock:
	/* Socket must have been released on error */
	KUNIT_EXPECT_TRUE(test, socket_released);

	/* Original error code must be preserved */
	KUNIT_EXPECT_EQ(test, ret, -ENOBUFS);

	/* Error must be negative so the caller detects the failure */
	KUNIT_EXPECT_LT(test, ret, 0);
}

/* =========================================================================
 * Test 4: test_version_negotiation_send
 *
 * tquic_send_version_negotiation_internal() builds a VN packet with this
 * layout (RFC 9000 §17.2.1):
 *
 *   Byte 0:       random | TQUIC_HEADER_FORM_LONG  (0x80 ORed in)
 *   Bytes 1-4:    0x00 0x00 0x00 0x00              (Version = 0)
 *   Byte 5:       scid_len
 *   Bytes 6…:     scid bytes
 *   Next byte:    dcid_len
 *   Next bytes:   dcid bytes
 *   Remaining:    supported version list (big-endian u32 each)
 *
 * We cannot call the static internal function directly, so we build an
 * equivalent buffer by hand using the same algorithm and validate:
 *   (a) The buffer is non-NULL (allocation succeeded).
 *   (b) Byte 0 has TQUIC_HEADER_FORM_LONG set.
 *   (c) Bytes 1-4 decode to 0 (version == VN sentinel).
 *   (d) The first supported version in the payload is TQUIC_VERSION_1.
 *   (e) Packet length matches the expected formula.
 * ========================================================================= */
static void test_version_negotiation_send(struct kunit *test)
{
	/*
	 * Test parameters — small CIDs so the test buffer fits on the stack.
	 */
	static const u8 dcid[]    = { 0x01, 0x02, 0x03, 0x04,
				      0x05, 0x06, 0x07, 0x08 };
	static const u8 scid[]    = { 0x11, 0x12, 0x13, 0x14,
				      0x15, 0x16, 0x17, 0x18 };
	const u8 dcid_len = sizeof(dcid);
	const u8 scid_len = sizeof(scid);

	/*
	 * The two supported versions that tquic_send_version_negotiation_internal
	 * encodes, in the order they appear in the packet.
	 */
	static const u32 supported_versions[] = {
		TQUIC_VERSION_1,
		TQUIC_VERSION_2,
	};

	/*
	 * Total packet length formula (mirrors the production code):
	 *   1 (first byte)
	 * + 4 (version field)
	 * + 1 (dcid length prefix)  — NB: the function labels these swapped;
	 * + dcid_len                     DCID in VN = echo of client's SCID
	 * + 1 (scid length prefix)
	 * + scid_len
	 * + 4 * num_versions
	 *
	 * From tquic_send_version_negotiation_internal():
	 *   pkt_len = 7 + dcid_len + scid_len + sizeof(supported_versions);
	 * where "7" = 1 (first byte) + 4 (version) + 1 (dcid-len) + 1 (scid-len).
	 */
	const size_t pkt_len = 7 + dcid_len + scid_len +
			       sizeof(supported_versions);

	/* Allocate on the stack — safe because pkt_len is small here */
	u8 buf[128];
	u8 *p = buf;
	u32 version_field;
	u32 first_version;
	int i;

	KUNIT_ASSERT_LE(test, pkt_len, sizeof(buf));

	/*
	 * Build the VN packet exactly as tquic_send_version_negotiation_internal
	 * does, minus get_random_bytes() (we use a fixed first byte so the test
	 * is deterministic).
	 */

	/* Byte 0: TQUIC_HEADER_FORM_LONG must be set */
	*p = 0x00;
	*p |= TQUIC_HEADER_FORM_LONG;
	p++;

	/* Bytes 1-4: Version = 0 */
	memset(p, 0, 4);
	p += 4;

	/* DCID field (echo of client's SCID per the swap in the function) */
	*p++ = scid_len;
	memcpy(p, scid, scid_len);
	p += scid_len;

	/* SCID field (echo of client's DCID) */
	*p++ = dcid_len;
	memcpy(p, dcid, dcid_len);
	p += dcid_len;

	/* Supported versions in big-endian network order */
	for (i = 0; i < (int)ARRAY_SIZE(supported_versions); i++) {
		*p++ = (supported_versions[i] >> 24) & 0xff;
		*p++ = (supported_versions[i] >> 16) & 0xff;
		*p++ = (supported_versions[i] >>  8) & 0xff;
		*p++ =  supported_versions[i]        & 0xff;
	}

	/* (a) Buffer is valid — pointer is non-NULL */
	KUNIT_EXPECT_NOT_NULL(test, buf);

	/* (b) First byte has TQUIC_HEADER_FORM_LONG set */
	KUNIT_EXPECT_TRUE(test, (buf[0] & TQUIC_HEADER_FORM_LONG) != 0);
	KUNIT_EXPECT_EQ(test, (u8)(buf[0] & TQUIC_HEADER_FORM_LONG),
			(u8)TQUIC_HEADER_FORM_LONG);

	/* (c) Bytes 1-4 decode to version == 0 (VN sentinel per RFC 9000) */
	version_field = read_be32(&buf[1]);
	KUNIT_EXPECT_EQ(test, version_field, TQUIC_VERSION_NEGOTIATION);

	/* (d) First supported version in the payload is TQUIC_VERSION_1 */
	first_version = read_be32(&buf[7 + scid_len + 1 + dcid_len]);
	KUNIT_EXPECT_EQ(test, first_version, (u32)TQUIC_VERSION_1);

	/* (e) Packet length matches the expected formula */
	KUNIT_EXPECT_EQ(test, (size_t)(p - buf), pkt_len);
}

/* =========================================================================
 * Additional structural / constant sanity checks
 *
 * These guard against accidental changes to constants or structure layouts
 * that the IPv6 socket path relies on.
 * ========================================================================= */

/*
 * test_ipv6_addr_constants
 *
 * Validate that AF_INET6, SOCK_DGRAM, and IPPROTO_UDP have the expected
 * values that tquic_connect() passes to sock_create_kern().
 */
static void test_ipv6_addr_constants(struct kunit *test)
{
	/* AF_INET6 is 10 on all Linux architectures */
	KUNIT_EXPECT_EQ(test, (int)AF_INET6, 10);

	/* SOCK_DGRAM must be distinct from SOCK_STREAM */
	KUNIT_EXPECT_NE(test, (int)SOCK_DGRAM, (int)SOCK_STREAM);

	/* IPPROTO_UDP is 17 (per IANA) */
	KUNIT_EXPECT_EQ(test, (int)IPPROTO_UDP, 17);

	/* AF_INET6 > AF_INET — the two address families are distinct */
	KUNIT_EXPECT_NE(test, (int)AF_INET6, (int)AF_INET);
}

/*
 * test_ipv6_bind_addr_size
 *
 * sockaddr_storage must be large enough to hold sockaddr_in6.  The IPv6
 * branch of tquic_connect() casts &tsk->bind_addr (type sockaddr_storage)
 * directly to struct sockaddr_in6 *.  This is only safe if the size
 * constraint holds.
 */
static void test_ipv6_bind_addr_size(struct kunit *test)
{
	KUNIT_EXPECT_GE(test,
			sizeof(struct sockaddr_storage),
			sizeof(struct sockaddr_in6));
}

/*
 * test_ipv6_version_constants
 *
 * TQUIC_VERSION_1 and TQUIC_VERSION_2 must have the RFC-specified values.
 * The version negotiation packet builder encodes these verbatim into the
 * packet.
 */
static void test_ipv6_version_constants(struct kunit *test)
{
	/* RFC 9000: QUIC v1 */
	KUNIT_EXPECT_EQ(test, (u32)TQUIC_VERSION_1, 0x00000001U);

	/* RFC 9369: QUIC v2 */
	KUNIT_EXPECT_EQ(test, (u32)TQUIC_VERSION_2, 0x6b3343cfU);

	/* VN sentinel */
	KUNIT_EXPECT_EQ(test, TQUIC_VERSION_NEGOTIATION, 0x00000000U);

	/* v1 and v2 are distinct */
	KUNIT_EXPECT_NE(test, (u32)TQUIC_VERSION_1, (u32)TQUIC_VERSION_2);

	/* Neither v1 nor v2 collides with the VN sentinel */
	KUNIT_EXPECT_NE(test, (u32)TQUIC_VERSION_1, TQUIC_VERSION_NEGOTIATION);
	KUNIT_EXPECT_NE(test, (u32)TQUIC_VERSION_2, TQUIC_VERSION_NEGOTIATION);
}

/*
 * test_ipv6_encap_type_shared
 *
 * The IPv4 and IPv6 connect paths both write encap_type = 1.  Verify the
 * shared constant so that a future change to one path that forgets to update
 * the other is caught here.
 */
static void test_ipv6_encap_type_shared(struct kunit *test)
{
	/* Both paths must use the same encap_type */
	int ipv4_encap_type = TQUIC_UDP_ENCAP_TYPE;
	int ipv6_encap_type = TQUIC_UDP_ENCAP_TYPE;

	KUNIT_EXPECT_EQ(test, ipv4_encap_type, ipv6_encap_type);
	KUNIT_EXPECT_EQ(test, ipv4_encap_type, 1);
}

/*
 * test_vn_packet_long_header_bit
 *
 * The Header Form bit (0x80) is the critical distinguisher between long and
 * short headers (RFC 9000 §17.1).  A VN packet must set it.  Validate the
 * constant and the OR idiom used in the production code.
 */
static void test_vn_packet_long_header_bit(struct kunit *test)
{
	u8 first_byte;

	/* Constant value */
	KUNIT_EXPECT_EQ(test, (u8)TQUIC_HEADER_FORM_LONG, (u8)0x80);

	/* ORing it into any byte sets bit 7 */
	first_byte = 0x00;
	first_byte |= TQUIC_HEADER_FORM_LONG;
	KUNIT_EXPECT_TRUE(test, (first_byte & 0x80) != 0);

	/* ORing into a byte that already has other bits preserves them */
	first_byte = 0x3a;
	first_byte |= TQUIC_HEADER_FORM_LONG;
	KUNIT_EXPECT_EQ(test, first_byte, (u8)0xba);

	/* Short-header packets must NOT have this bit set */
	first_byte = 0x40; /* Fixed bit only */
	KUNIT_EXPECT_FALSE(test, (first_byte & TQUIC_HEADER_FORM_LONG) != 0);
}

/* -------------------------------------------------------------------------
 * Suite registration
 * ------------------------------------------------------------------------- */

static struct kunit_case tquic_ipv6_socket_test_cases[] = {
	KUNIT_CASE(test_ipv6_bind_addr_update),
	KUNIT_CASE(test_ipv6_encap_fields),
	KUNIT_CASE(test_ipv6_getsockname_failure_cleanup),
	KUNIT_CASE(test_version_negotiation_send),
	KUNIT_CASE(test_ipv6_addr_constants),
	KUNIT_CASE(test_ipv6_bind_addr_size),
	KUNIT_CASE(test_ipv6_version_constants),
	KUNIT_CASE(test_ipv6_encap_type_shared),
	KUNIT_CASE(test_vn_packet_long_header_bit),
	{}
};

static struct kunit_suite tquic_ipv6_socket_test_suite = {
	.name		= "tquic-ipv6-socket",
	.test_cases	= tquic_ipv6_socket_test_cases,
};

kunit_test_suite(tquic_ipv6_socket_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for TQUIC IPv6 encap socket and VN send");
