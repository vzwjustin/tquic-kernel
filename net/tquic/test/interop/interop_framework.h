/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC Interoperability Testing Framework
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * This framework provides comprehensive interoperability testing capabilities
 * for the TQUIC implementation. It enables testing against RFC 9000/9001/9002
 * compliance, version negotiation, transport parameters, and edge cases.
 *
 * Test Categories:
 * - Handshake tests (Initial, Handshake, 0-RTT, 1-RTT)
 * - Version negotiation
 * - Transport parameters
 * - Frame encoding/decoding
 * - Flow control
 * - Loss recovery
 * - Connection migration
 * - Multipath
 */

#ifndef _TQUIC_INTEROP_H
#define _TQUIC_INTEROP_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/ktime.h>
#include <linux/workqueue.h>

/*
 * =============================================================================
 * Test Configuration
 * =============================================================================
 */

/* Test result codes */
#define TQUIC_TEST_PASS		0
#define TQUIC_TEST_FAIL		1
#define TQUIC_TEST_SKIP		2
#define TQUIC_TEST_TIMEOUT	3
#define TQUIC_TEST_ERROR	4

/* Test categories */
#define TQUIC_TEST_CAT_HANDSHAKE	BIT(0)
#define TQUIC_TEST_CAT_VERSION		BIT(1)
#define TQUIC_TEST_CAT_TRANSPORT	BIT(2)
#define TQUIC_TEST_CAT_FRAME		BIT(3)
#define TQUIC_TEST_CAT_FLOW		BIT(4)
#define TQUIC_TEST_CAT_LOSS		BIT(5)
#define TQUIC_TEST_CAT_MIGRATION	BIT(6)
#define TQUIC_TEST_CAT_MULTIPATH	BIT(7)
#define TQUIC_TEST_CAT_SECURITY		BIT(8)
#define TQUIC_TEST_CAT_HTTP3		BIT(9)
#define TQUIC_TEST_CAT_DATAGRAM		BIT(10)
#define TQUIC_TEST_CAT_FEC		BIT(11)
#define TQUIC_TEST_CAT_ALL		0xFFFFFFFF

/* Test timeout (ms) */
#define TQUIC_TEST_TIMEOUT_DEFAULT	30000
#define TQUIC_TEST_TIMEOUT_HANDSHAKE	10000
#define TQUIC_TEST_TIMEOUT_MIGRATION	60000

/*
 * =============================================================================
 * Test Case Definition
 * =============================================================================
 */

struct tquic_test_ctx;

/**
 * struct tquic_test_case - Single test case definition
 * @name:        Test name (for reporting)
 * @description: Test description
 * @category:    Test category flags
 * @rfc_section: Relevant RFC section
 * @run:         Test execution function
 * @setup:       Optional setup function
 * @teardown:    Optional teardown function
 * @timeout_ms:  Test timeout in milliseconds
 * @flags:       Test flags
 * @list:        Test list linkage
 */
struct tquic_test_case {
	const char *name;
	const char *description;
	u32 category;
	const char *rfc_section;
	int (*run)(struct tquic_test_ctx *ctx);
	int (*setup)(struct tquic_test_ctx *ctx);
	void (*teardown)(struct tquic_test_ctx *ctx);
	u32 timeout_ms;
	u32 flags;
	struct list_head list;
};

/**
 * struct tquic_test_ctx - Test execution context
 * @test:         Current test case
 * @conn_client:  Client connection
 * @conn_server:  Server connection
 * @start_time:   Test start time
 * @result:       Test result code
 * @error_msg:    Error message buffer
 * @error_len:    Error message length
 * @packets_tx:   Packets transmitted
 * @packets_rx:   Packets received
 * @bytes_tx:     Bytes transmitted
 * @bytes_rx:     Bytes received
 * @priv:         Test private data
 */
struct tquic_test_ctx {
	struct tquic_test_case *test;
	struct tquic_connection *conn_client;
	struct tquic_connection *conn_server;
	ktime_t start_time;
	int result;
	char error_msg[256];
	size_t error_len;
	u64 packets_tx;
	u64 packets_rx;
	u64 bytes_tx;
	u64 bytes_rx;
	void *priv;
};

/**
 * struct tquic_test_results - Test run summary
 * @total:        Total tests run
 * @passed:       Tests passed
 * @failed:       Tests failed
 * @skipped:      Tests skipped
 * @errors:       Tests with errors
 * @duration_ms:  Total duration
 * @failed_tests: List of failed test names
 */
struct tquic_test_results {
	u32 total;
	u32 passed;
	u32 failed;
	u32 skipped;
	u32 errors;
	u64 duration_ms;
	char **failed_tests;
	u32 failed_count;
};

/*
 * =============================================================================
 * Test Registration
 * =============================================================================
 */

/**
 * tquic_test_register - Register a test case
 * @test: Test case to register
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_test_register(struct tquic_test_case *test);

/**
 * tquic_test_unregister - Unregister a test case
 * @test: Test case to unregister
 */
void tquic_test_unregister(struct tquic_test_case *test);

/**
 * TQUIC_TEST - Macro to define a test case
 */
#define TQUIC_TEST(_name, _cat, _rfc)				\
	static int _name##_run(struct tquic_test_ctx *ctx);	\
	static struct tquic_test_case _name##_test = {		\
		.name = #_name,					\
		.category = _cat,				\
		.rfc_section = _rfc,				\
		.run = _name##_run,				\
		.timeout_ms = TQUIC_TEST_TIMEOUT_DEFAULT,	\
	};							\
	static int _name##_run(struct tquic_test_ctx *ctx)

/**
 * TQUIC_TEST_INIT - Initialize and register test at module load
 */
#define TQUIC_TEST_INIT(_name) \
	tquic_test_register(&_name##_test)

/**
 * TQUIC_TEST_EXIT - Unregister test at module unload
 */
#define TQUIC_TEST_EXIT(_name) \
	tquic_test_unregister(&_name##_test)

/*
 * =============================================================================
 * Test Execution
 * =============================================================================
 */

/**
 * tquic_test_run_all - Run all registered tests
 * @categories: Category flags to run (TQUIC_TEST_CAT_ALL for all)
 * @results: Output results structure
 *
 * Returns: 0 if all tests passed, positive count of failures
 */
int tquic_test_run_all(u32 categories, struct tquic_test_results *results);

/**
 * tquic_test_run_single - Run a single test by name
 * @name: Test name
 * @results: Output results
 *
 * Returns: Test result code
 */
int tquic_test_run_single(const char *name, struct tquic_test_results *results);

/**
 * tquic_test_list - List all registered tests
 * @buf: Output buffer
 * @size: Buffer size
 *
 * Returns: Number of bytes written
 */
int tquic_test_list(char *buf, size_t size);

/*
 * =============================================================================
 * Test Assertions
 * =============================================================================
 */

/**
 * tquic_test_fail - Mark test as failed
 */
#define TQUIC_TEST_FAIL(ctx, fmt, ...) do {				\
	(ctx)->result = TQUIC_TEST_FAIL;				\
	snprintf((ctx)->error_msg, sizeof((ctx)->error_msg),		\
		 fmt, ##__VA_ARGS__);					\
	pr_err("TQUIC TEST FAIL [%s]: " fmt "\n",			\
	       (ctx)->test->name, ##__VA_ARGS__);			\
	return TQUIC_TEST_FAIL;						\
} while (0)

/**
 * tquic_test_assert - Assert condition or fail
 */
#define TQUIC_TEST_ASSERT(ctx, cond, fmt, ...) do {			\
	if (!(cond))							\
		TQUIC_TEST_FAIL(ctx, "Assertion failed: " fmt,		\
				##__VA_ARGS__);				\
} while (0)

/**
 * tquic_test_assert_eq - Assert equality
 */
#define TQUIC_TEST_ASSERT_EQ(ctx, a, b, fmt) do {			\
	if ((a) != (b))							\
		TQUIC_TEST_FAIL(ctx, fmt ": expected %lld, got %lld",	\
				(long long)(b), (long long)(a));	\
} while (0)

/**
 * tquic_test_skip - Skip test
 */
#define TQUIC_TEST_SKIP(ctx, fmt, ...) do {				\
	(ctx)->result = TQUIC_TEST_SKIP;				\
	pr_info("TQUIC TEST SKIP [%s]: " fmt "\n",			\
		(ctx)->test->name, ##__VA_ARGS__);			\
	return TQUIC_TEST_SKIP;						\
} while (0)

/*
 * =============================================================================
 * Test Utilities
 * =============================================================================
 */

/**
 * tquic_test_create_connection - Create test connection pair
 * @ctx: Test context
 * @is_server: Create server (vs client) connection
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_test_create_connection(struct tquic_test_ctx *ctx, bool is_server);

/**
 * tquic_test_complete_handshake - Complete handshake between connections
 * @ctx: Test context
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_test_complete_handshake(struct tquic_test_ctx *ctx);

/**
 * tquic_test_send_data - Send test data
 * @ctx: Test context
 * @stream_id: Stream ID
 * @data: Data to send
 * @len: Data length
 *
 * Returns: Bytes sent, negative errno on failure
 */
int tquic_test_send_data(struct tquic_test_ctx *ctx, u64 stream_id,
			 const void *data, size_t len);

/**
 * tquic_test_recv_data - Receive test data
 * @ctx: Test context
 * @stream_id: Stream ID
 * @buf: Receive buffer
 * @len: Buffer size
 *
 * Returns: Bytes received, negative errno on failure
 */
int tquic_test_recv_data(struct tquic_test_ctx *ctx, u64 stream_id,
			 void *buf, size_t len);

/**
 * tquic_test_inject_packet - Inject raw packet into connection
 * @ctx: Test context
 * @data: Packet data
 * @len: Packet length
 * @to_server: Send to server (vs client)
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_test_inject_packet(struct tquic_test_ctx *ctx,
			     const void *data, size_t len, bool to_server);

/**
 * tquic_test_drop_next_packet - Configure next packet drop
 * @ctx: Test context
 * @from_server: Drop packet from server
 *
 * Returns: 0 on success
 */
int tquic_test_drop_next_packet(struct tquic_test_ctx *ctx, bool from_server);

/**
 * tquic_test_delay_packet - Add delay to packets
 * @ctx: Test context
 * @delay_ms: Delay in milliseconds
 *
 * Returns: 0 on success
 */
int tquic_test_delay_packet(struct tquic_test_ctx *ctx, u32 delay_ms);

/**
 * tquic_test_corrupt_packet - Corrupt next packet
 * @ctx: Test context
 * @from_server: Corrupt packet from server
 *
 * Returns: 0 on success
 */
int tquic_test_corrupt_packet(struct tquic_test_ctx *ctx, bool from_server);

/*
 * =============================================================================
 * Module Init/Exit
 * =============================================================================
 */

int tquic_interop_init(void);
void tquic_interop_exit(void);

#endif /* _TQUIC_INTEROP_H */
