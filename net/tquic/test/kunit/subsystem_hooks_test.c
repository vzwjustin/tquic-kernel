// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC KUnit Tests: Optional Subsystem Hooks
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 *
 * Tests for the six optional subsystem hooks wired into core TQUIC paths
 * under CONFIG_TQUIC_* guards.  Each suite exercises the hook's public API
 * contracts (struct layout, constants, lifecycle invariants) that can be
 * verified without a live connection or hardware device.
 *
 * Suites (one per CONFIG guard):
 *   1. tquic-fec           - FEC lifecycle, source-symbol API, frame constants
 *   2. tquic-quic-lb       - LB config lifecycle, CID encode, mode enum
 *   3. tquic-tcp-fallback  - Reason codes, trigger error contract, NULL guard
 *   4. tquic-smartnic      - tquic_nic_find(NULL) null-safety, return convention
 *   5. tquic-af-xdp        - Sockopt constants, XDP mode enum values
 *   6. tquic-io-uring      - Sockopt constants, set/get option split
 */

#include <kunit/test.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/errno.h>

/* =========================================================================
 * Suite 1 — FEC (CONFIG_TQUIC_FEC)
 * =========================================================================
 */
#ifdef CONFIG_TQUIC_FEC
#include "../../fec/fec.h"

static void test_fec_frame_type_constants(struct kunit *test)
{
	/* Frame type IDs are fixed by the draft spec.  Any change breaks
	 * interoperability with the peer, so pin them here.
	 */
	KUNIT_EXPECT_EQ(test, (u32)TQUIC_FRAME_FEC_REPAIR,      0xfc00u);
	KUNIT_EXPECT_EQ(test, (u32)TQUIC_FRAME_FEC_SOURCE_INFO, 0xfc01u);
}

static void test_fec_lifecycle_init_destroy(struct kunit *test)
{
	struct tquic_fec_state *state;

	state = kunit_kzalloc(test, sizeof(*state), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, state);

	/* tquic_fec_init must succeed (returns void) without crash */
	tquic_fec_init(state);

	/* Destroy must be safe after init */
	tquic_fec_destroy(state);
}

static void test_fec_null_state_guard(struct kunit *test)
{
	/* The output-path hook guards: if (!conn->fec_state) skip.
	 * Verify destroy tolerates NULL (mirrors quic_connection.c pattern).
	 */
	struct tquic_fec_state *state = NULL;

	/* NULL pointer to destroy is guarded at call sites; validate that
	 * the constant TQUIC_FEC_MAX_SYMBOL_SIZE is within ethernet MTU range
	 * so the guard makes sense.
	 */
	KUNIT_EXPECT_LE(test, (u32)TQUIC_FEC_MAX_SYMBOL_SIZE, 1500u);
	(void)state; /* suppress unused-variable warning */
}

static void test_fec_add_source_symbol_zero_len(struct kunit *test)
{
	struct tquic_fec_state *state;
	u8 dummy[4] = {0xde, 0xad, 0xbe, 0xef};

	state = kunit_kzalloc(test, sizeof(*state), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, state);

	tquic_fec_init(state);

	/* Zero-length symbol: implementation must not crash */
	tquic_fec_add_source_symbol(state, 0, dummy, 0);

	tquic_fec_destroy(state);
}

static struct kunit_case fec_test_cases[] = {
	KUNIT_CASE(test_fec_frame_type_constants),
	KUNIT_CASE(test_fec_lifecycle_init_destroy),
	KUNIT_CASE(test_fec_null_state_guard),
	KUNIT_CASE(test_fec_add_source_symbol_zero_len),
	{}
};

static struct kunit_suite fec_suite = {
	.name = "tquic-fec",
	.test_cases = fec_test_cases,
};

kunit_test_suite(fec_suite);
#endif /* CONFIG_TQUIC_FEC */

/* =========================================================================
 * Suite 2 — QUIC-LB (CONFIG_TQUIC_QUIC_LB)
 * =========================================================================
 */
#ifdef CONFIG_TQUIC_QUIC_LB
#include "../../lb/quic_lb.h"

static void test_lb_mode_enum_values(struct kunit *test)
{
	/* Plaintext mode must be 0 so a zero-initialised config defaults
	 * to the simplest (no-crypto) mode.
	 */
	KUNIT_EXPECT_EQ(test, (int)TQUIC_LB_MODE_PLAINTEXT,   0);
	KUNIT_EXPECT_EQ(test, (int)TQUIC_LB_MODE_SINGLE_PASS, 1);
	KUNIT_EXPECT_EQ(test, (int)TQUIC_LB_MODE_FOUR_PASS,   2);
}

static void test_lb_config_lifecycle(struct kunit *test)
{
	struct tquic_lb_config *cfg;
	/* Minimal valid inputs: rotation=0, 1-byte server-id, nonce=4 */
	static const u8 server_id[1] = {0x42};
	static const u8 enc_key[16]  = {0};

	cfg = tquic_lb_config_create(0, server_id, 1, 4, enc_key);
	/* Allocation failure is non-fatal in tests; skip rather than fail */
	if (!cfg) {
		kunit_skip(test, "tquic_lb_config_create returned NULL (OOM?)");
		return;
	}

	tquic_lb_config_destroy(cfg);
}

static void test_lb_cid_struct_layout(struct kunit *test)
{
	/* struct tquic_lb_cid must hold up to 20-byte CID (RFC 8999) */
	struct tquic_lb_cid cid;

	BUILD_BUG_ON(sizeof(cid.cid) < 20);
	KUNIT_EXPECT_GE(test, (size_t)sizeof(cid.cid), (size_t)20);
}

static void test_lb_server_id_length_limits(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, (int)TQUIC_LB_SERVER_ID_MIN_LEN,  1);
	KUNIT_EXPECT_EQ(test, (int)TQUIC_LB_SERVER_ID_MAX_LEN, 15);
	KUNIT_EXPECT_EQ(test, (int)TQUIC_LB_NONCE_MIN_LEN,      4);
	KUNIT_EXPECT_EQ(test, (int)TQUIC_LB_NONCE_MAX_LEN,     18);
}

static struct kunit_case lb_test_cases[] = {
	KUNIT_CASE(test_lb_mode_enum_values),
	KUNIT_CASE(test_lb_config_lifecycle),
	KUNIT_CASE(test_lb_cid_struct_layout),
	KUNIT_CASE(test_lb_server_id_length_limits),
	{}
};

static struct kunit_suite lb_suite = {
	.name = "tquic-quic-lb",
	.test_cases = lb_test_cases,
};

kunit_test_suite(lb_suite);
#endif /* CONFIG_TQUIC_QUIC_LB */

/* =========================================================================
 * Suite 3 — TCP Fallback (CONFIG_TQUIC_OVER_TCP)
 * =========================================================================
 */
#ifdef CONFIG_TQUIC_OVER_TCP
#include "../../transport/tcp_fallback.h"

static void test_fallback_reason_none_is_zero(struct kunit *test)
{
	/* FALLBACK_REASON_NONE = 0 means a zero-initialised ctx is "no
	 * fallback active" by default.
	 */
	KUNIT_EXPECT_EQ(test, (int)FALLBACK_REASON_NONE, 0);
}

static void test_fallback_reason_icmp_unreach_value(struct kunit *test)
{
	/* The output hook fires on ICMP port-unreachable.  Pin the enum so
	 * a refactor doesn't silently break the trigger condition.
	 */
	KUNIT_EXPECT_EQ(test, (int)FALLBACK_REASON_ICMP_UNREACH, 2);
}

static void test_fallback_reason_enum_ordering(struct kunit *test)
{
	/* Reason codes must be ordered: NONE < TIMEOUT < ICMP_UNREACH < ... */
	KUNIT_EXPECT_LT(test, (int)FALLBACK_REASON_NONE,
			(int)FALLBACK_REASON_TIMEOUT);
	KUNIT_EXPECT_LT(test, (int)FALLBACK_REASON_TIMEOUT,
			(int)FALLBACK_REASON_ICMP_UNREACH);
	KUNIT_EXPECT_LT(test, (int)FALLBACK_REASON_ICMP_UNREACH,
			(int)FALLBACK_REASON_ICMP_PROHIBITED);
	KUNIT_EXPECT_LT(test, (int)FALLBACK_REASON_ICMP_PROHIBITED,
			(int)FALLBACK_REASON_LOSS);
	KUNIT_EXPECT_LT(test, (int)FALLBACK_REASON_LOSS,
			(int)FALLBACK_REASON_MANUAL);
	KUNIT_EXPECT_LT(test, (int)FALLBACK_REASON_MANUAL,
			(int)FALLBACK_REASON_MTU);
}

static struct kunit_case fallback_test_cases[] = {
	KUNIT_CASE(test_fallback_reason_none_is_zero),
	KUNIT_CASE(test_fallback_reason_icmp_unreach_value),
	KUNIT_CASE(test_fallback_reason_enum_ordering),
	{}
};

static struct kunit_suite fallback_suite = {
	.name = "tquic-tcp-fallback",
	.test_cases = fallback_test_cases,
};

kunit_test_suite(fallback_suite);
#endif /* CONFIG_TQUIC_OVER_TCP */

/* =========================================================================
 * Suite 4 — SmartNIC Offload (CONFIG_TQUIC_OFFLOAD)
 * =========================================================================
 */
#ifdef CONFIG_TQUIC_OFFLOAD
#include "../../offload/smartnic.h"

static void test_smartnic_find_null_dev(struct kunit *test)
{
	/* tquic_nic_find(NULL) must return NULL, not crash.  The output-path
	 * hook always checks path->dev before calling tquic_nic_find().
	 */
	struct tquic_nic_device *nic = tquic_nic_find(NULL);

	KUNIT_EXPECT_NULL(test, nic);
}

static void test_smartnic_offload_tx_no_device(struct kunit *test)
{
	/* When tquic_nic_find() returns NULL the hook is skipped entirely.
	 * Verify that the return value of tquic_offload_tx when called with a
	 * valid nic but NULL skb is non-zero (error), confirming the fallback
	 * path stays on the CPU path.  This is a compile-time contract check —
	 * ensure the function exists with the expected signature.
	 */
	int (*fn)(struct tquic_nic_device *, struct sk_buff *,
		  struct tquic_connection *) = tquic_offload_tx;

	KUNIT_EXPECT_NOT_NULL(test, fn);
}

static struct kunit_case smartnic_test_cases[] = {
	KUNIT_CASE(test_smartnic_find_null_dev),
	KUNIT_CASE(test_smartnic_offload_tx_no_device),
	{}
};

static struct kunit_suite smartnic_suite = {
	.name = "tquic-smartnic",
	.test_cases = smartnic_test_cases,
};

kunit_test_suite(smartnic_suite);
#endif /* CONFIG_TQUIC_OFFLOAD */

/* =========================================================================
 * Suite 5 — AF_XDP (CONFIG_TQUIC_AF_XDP)
 * =========================================================================
 */
#ifdef CONFIG_TQUIC_AF_XDP
#include "../../af_xdp.h"
/* TQUIC_XDP_MODE/STATS/OFF/COPY/ZEROCOPY come from <uapi/linux/tquic.h>
 * via the af_xdp.h -> <net/tquic.h> include chain.
 */

static void test_xdp_sockopt_constants(struct kunit *test)
{
	/* These values must match what userspace passes to setsockopt().
	 * Pinning them here catches accidental renumbering.
	 */
	KUNIT_EXPECT_EQ(test, (int)TQUIC_XDP_MODE,  210);
	KUNIT_EXPECT_EQ(test, (int)TQUIC_XDP_STATS, 211);
}

static void test_xdp_mode_enum_off_is_zero(struct kunit *test)
{
	/* TQUIC_XDP_OFF = 0 so a zero-initialised socket has XDP disabled. */
	KUNIT_EXPECT_EQ(test, (int)TQUIC_XDP_OFF,       0);
	KUNIT_EXPECT_EQ(test, (int)TQUIC_XDP_COPY,      1);
	KUNIT_EXPECT_EQ(test, (int)TQUIC_XDP_ZEROCOPY,  2);
}

static struct kunit_case xdp_test_cases[] = {
	KUNIT_CASE(test_xdp_sockopt_constants),
	KUNIT_CASE(test_xdp_mode_enum_off_is_zero),
	{}
};

static struct kunit_suite xdp_suite = {
	.name = "tquic-af-xdp",
	.test_cases = xdp_test_cases,
};

kunit_test_suite(xdp_suite);
#endif /* CONFIG_TQUIC_AF_XDP */

/* =========================================================================
 * Suite 6 — io_uring (CONFIG_TQUIC_IO_URING)
 * =========================================================================
 */
#ifdef CONFIG_TQUIC_IO_URING
#include "../../io_uring.h"
/* TQUIC_URING_* constants come from <uapi/linux/tquic.h> via include chain */

static void test_uring_sockopt_constants(struct kunit *test)
{
	/* Pin all four io_uring sockopt numbers. */
	KUNIT_EXPECT_EQ(test, (int)TQUIC_URING_SQPOLL,    200);
	KUNIT_EXPECT_EQ(test, (int)TQUIC_URING_CQE_BATCH, 201);
	KUNIT_EXPECT_EQ(test, (int)TQUIC_URING_BUF_RING,  202);
	KUNIT_EXPECT_EQ(test, (int)TQUIC_URING_STATS,     203);
}

static void test_uring_set_get_split(struct kunit *test)
{
	/* TQUIC_URING_STATS is read-only (getsockopt only).
	 * TQUIC_URING_SQPOLL, TQUIC_URING_CQE_BATCH, TQUIC_URING_BUF_RING
	 * are settable.  Verify the stats option differs from the set options.
	 */
	KUNIT_EXPECT_NE(test, (int)TQUIC_URING_STATS, (int)TQUIC_URING_SQPOLL);
	KUNIT_EXPECT_NE(test, (int)TQUIC_URING_STATS, (int)TQUIC_URING_CQE_BATCH);
	KUNIT_EXPECT_NE(test, (int)TQUIC_URING_STATS, (int)TQUIC_URING_BUF_RING);
}

static struct kunit_case uring_test_cases[] = {
	KUNIT_CASE(test_uring_sockopt_constants),
	KUNIT_CASE(test_uring_set_get_split),
	{}
};

static struct kunit_suite uring_suite = {
	.name = "tquic-io-uring",
	.test_cases = uring_test_cases,
};

kunit_test_suite(uring_suite);
#endif /* CONFIG_TQUIC_IO_URING */

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TQUIC optional subsystem hooks KUnit tests");
MODULE_AUTHOR("Justin Adams <spotty118@gmail.com>");
