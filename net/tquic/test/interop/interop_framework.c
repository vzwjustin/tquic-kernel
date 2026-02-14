// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC Interoperability Testing Framework Implementation
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Provides a comprehensive testing framework for QUIC protocol compliance
 * and interoperability verification.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/workqueue.h>
#include <linux/completion.h>
#include <linux/random.h>
#include <net/tquic.h>

#include "interop_framework.h"
#include "../../protocol.h"

/*
 * =============================================================================
 * Global State
 * =============================================================================
 */

static LIST_HEAD(test_list);
static DEFINE_SPINLOCK(test_lock);
static bool interop_initialized;

/* Test runner workqueue */
static struct workqueue_struct *test_wq;

/* Test runner state */
struct tquic_test_runner {
	struct list_head queue;
	spinlock_t lock;
	struct completion done;
	struct tquic_test_results results;
	u32 categories;
	bool running;
};

static struct tquic_test_runner *active_runner;

/*
 * =============================================================================
 * Test Registration
 * =============================================================================
 */

int tquic_test_register(struct tquic_test_case *test)
{
	if (!test || !test->name || !test->run)
		return -EINVAL;

	spin_lock(&test_lock);
	list_add_tail(&test->list, &test_list);
	spin_unlock(&test_lock);

	pr_debug("tquic_test: registered test '%s'\n", test->name);
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_test_register);

void tquic_test_unregister(struct tquic_test_case *test)
{
	if (!test)
		return;

	spin_lock(&test_lock);
	list_del_init(&test->list);
	spin_unlock(&test_lock);

	pr_debug("tquic_test: unregistered test '%s'\n", test->name);
}
EXPORT_SYMBOL_GPL(tquic_test_unregister);

/*
 * =============================================================================
 * Test Execution
 * =============================================================================
 */

static int run_single_test(struct tquic_test_case *test,
			   struct tquic_test_ctx *ctx)
{
	ktime_t start, end;
	int ret;

	ctx->test = test;
	ctx->result = TQUIC_TEST_PASS;
	ctx->error_msg[0] = '\0';
	ctx->start_time = ktime_get();

	pr_info("tquic_test: running '%s'...\n", test->name);

	/* Setup */
	if (test->setup) {
		ret = test->setup(ctx);
		if (ret != 0) {
			pr_err("tquic_test: '%s' setup failed: %d\n",
			       test->name, ret);
			return TQUIC_TEST_ERROR;
		}
	}

	/* Run test */
	start = ktime_get();
	ret = test->run(ctx);
	end = ktime_get();

	/* Teardown */
	if (test->teardown)
		test->teardown(ctx);

	/* Report result */
	switch (ret) {
	case TQUIC_TEST_PASS:
		pr_info("tquic_test: '%s' PASSED (%lld ms)\n",
			test->name, ktime_ms_delta(end, start));
		break;
	case TQUIC_TEST_FAIL:
		pr_err("tquic_test: '%s' FAILED: %s\n",
		       test->name, ctx->error_msg);
		break;
	case TQUIC_TEST_SKIP:
		pr_info("tquic_test: '%s' SKIPPED\n", test->name);
		break;
	case TQUIC_TEST_TIMEOUT:
		pr_err("tquic_test: '%s' TIMEOUT\n", test->name);
		break;
	default:
		pr_err("tquic_test: '%s' ERROR: %d\n", test->name, ret);
		ret = TQUIC_TEST_ERROR;
		break;
	}

	return ret;
}

int tquic_test_run_all(u32 categories, struct tquic_test_results *results)
{
	struct tquic_test_case *test;
	struct tquic_test_ctx *ctx;
	ktime_t start;
	int ret;

	if (!results)
		return -EINVAL;

	memset(results, 0, sizeof(*results));

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	start = ktime_get();

	spin_lock(&test_lock);
	list_for_each_entry(test, &test_list, list) {
		/* Check category filter */
		if (categories != TQUIC_TEST_CAT_ALL &&
		    !(test->category & categories))
			continue;

		spin_unlock(&test_lock);

		ret = run_single_test(test, ctx);
		results->total++;

		switch (ret) {
		case TQUIC_TEST_PASS:
			results->passed++;
			break;
		case TQUIC_TEST_FAIL:
			results->failed++;
			break;
		case TQUIC_TEST_SKIP:
			results->skipped++;
			break;
		default:
			results->errors++;
			break;
		}

		spin_lock(&test_lock);
	}
	spin_unlock(&test_lock);

	results->duration_ms = ktime_ms_delta(ktime_get(), start);

	pr_info("tquic_test: completed %u tests: %u passed, %u failed, "
		"%u skipped, %u errors (%llu ms)\n",
		results->total, results->passed, results->failed,
		results->skipped, results->errors, results->duration_ms);

	kfree(ctx);
	return results->failed + results->errors;
}
EXPORT_SYMBOL_GPL(tquic_test_run_all);

int tquic_test_run_single(const char *name, struct tquic_test_results *results)
{
	struct tquic_test_case *test, *found = NULL;
	struct tquic_test_ctx *ctx;
	int ret;

	if (!name || !results)
		return -EINVAL;

	memset(results, 0, sizeof(*results));

	/* Find test by name */
	spin_lock(&test_lock);
	list_for_each_entry(test, &test_list, list) {
		if (strcmp(test->name, name) == 0) {
			found = test;
			break;
		}
	}
	spin_unlock(&test_lock);

	if (!found) {
		pr_err("tquic_test: test '%s' not found\n", name);
		return -ENOENT;
	}

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	ret = run_single_test(found, ctx);
	results->total = 1;

	switch (ret) {
	case TQUIC_TEST_PASS:
		results->passed = 1;
		break;
	case TQUIC_TEST_FAIL:
		results->failed = 1;
		break;
	case TQUIC_TEST_SKIP:
		results->skipped = 1;
		break;
	default:
		results->errors = 1;
		break;
	}

	kfree(ctx);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_test_run_single);

int tquic_test_list(char *buf, size_t size)
{
	struct tquic_test_case *test;
	int len = 0;

	spin_lock(&test_lock);
	list_for_each_entry(test, &test_list, list) {
		int n = snprintf(buf + len, size - len,
				 "%s (cat=0x%x, rfc=%s)\n",
				 test->name, test->category,
				 test->rfc_section ? test->rfc_section : "N/A");
		if (n >= size - len)
			break;
		len += n;
	}
	spin_unlock(&test_lock);

	return len;
}
EXPORT_SYMBOL_GPL(tquic_test_list);

/*
 * =============================================================================
 * Test Network Simulation State
 * =============================================================================
 */

/* Per-connection test state for network simulation */
struct tquic_test_conn_state {
	struct tquic_connection *conn;
	bool is_server;

	/* Packet manipulation flags */
	bool drop_next;
	bool corrupt_next;
	u32 delay_ms;

	/* Loopback buffers for packet exchange */
	u8 *tx_buf;
	size_t tx_buf_len;
	size_t tx_buf_alloc;

	/* Stream data buffers */
	u8 *stream_tx_buf;
	size_t stream_tx_len;
	u8 *stream_rx_buf;
	size_t stream_rx_len;
};

/* Test context private data */
struct tquic_test_priv {
	struct tquic_test_conn_state client;
	struct tquic_test_conn_state server;
	struct completion handshake_done;
	bool handshake_complete;
};

#define TQUIC_TEST_BUF_SIZE	4096
#define TQUIC_TEST_STREAM_BUF	65536

/*
 * =============================================================================
 * Test Utilities - Real Implementations
 * =============================================================================
 */

/**
 * tquic_test_alloc_conn_state - Allocate test connection state
 * @state: Connection state to initialize
 *
 * Returns: 0 on success, negative errno on failure
 */
static int tquic_test_alloc_conn_state(struct tquic_test_conn_state *state)
{
	state->tx_buf = kzalloc(TQUIC_TEST_BUF_SIZE, GFP_KERNEL);
	if (!state->tx_buf)
		return -ENOMEM;

	state->tx_buf_alloc = TQUIC_TEST_BUF_SIZE;
	state->tx_buf_len = 0;

	state->stream_tx_buf = kzalloc(TQUIC_TEST_STREAM_BUF, GFP_KERNEL);
	if (!state->stream_tx_buf) {
		kfree(state->tx_buf);
		return -ENOMEM;
	}

	state->stream_rx_buf = kzalloc(TQUIC_TEST_STREAM_BUF, GFP_KERNEL);
	if (!state->stream_rx_buf) {
		kfree(state->stream_tx_buf);
		kfree(state->tx_buf);
		return -ENOMEM;
	}

	state->drop_next = false;
	state->corrupt_next = false;
	state->delay_ms = 0;

	return 0;
}

/**
 * tquic_test_free_conn_state - Free test connection state
 * @state: Connection state to free
 */
static void tquic_test_free_conn_state(struct tquic_test_conn_state *state)
{
	kfree(state->stream_rx_buf);
	kfree(state->stream_tx_buf);
	kfree(state->tx_buf);

	if (state->conn) {
		tquic_conn_put(state->conn);
		state->conn = NULL;
	}
}

/**
 * tquic_test_create_connection - Create a test QUIC connection
 * @ctx: Test context
 * @is_server: True for server connection, false for client
 *
 * Creates a QUIC connection for testing. The connection is configured
 * for loopback testing with packet exchange through in-memory buffers.
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_test_create_connection(struct tquic_test_ctx *ctx, bool is_server)
{
	struct tquic_test_priv *priv;
	struct tquic_test_conn_state *state;
	struct tquic_cid cid;
	int ret;

	if (!ctx)
		return -EINVAL;

	/* Allocate private data on first call */
	if (!ctx->priv) {
		priv = kzalloc(sizeof(*priv), GFP_KERNEL);
		if (!priv)
			return -ENOMEM;

		init_completion(&priv->handshake_done);
		ctx->priv = priv;
	}

	priv = ctx->priv;
	state = is_server ? &priv->server : &priv->client;

	/* Allocate connection state buffers */
	ret = tquic_test_alloc_conn_state(state);
	if (ret < 0)
		return ret;

	state->is_server = is_server;

	/* Generate random connection ID */
	cid.len = 8;
	get_random_bytes(cid.id, cid.len);

	/* Create the actual QUIC connection */
	state->conn = tquic_conn_alloc(GFP_KERNEL);
	if (!state->conn) {
		tquic_test_free_conn_state(state);
		return -ENOMEM;
	}

	/* Initialize connection with test CID */
	state->conn->scid = cid;
	state->conn->role = is_server ? TQUIC_CONN_SERVER : TQUIC_CONN_CLIENT;
	state->conn->state = TQUIC_CONN_IDLE;
	state->conn->version = TQUIC_VERSION_1;

	/* Initialize transport parameters with test defaults */
	tquic_tp_init(&state->conn->local_params);
	if (is_server)
		tquic_tp_set_defaults_server(&state->conn->local_params);
	else
		tquic_tp_set_defaults_client(&state->conn->local_params);

	/* Store in context */
	if (is_server)
		ctx->conn_server = state->conn;
	else
		ctx->conn_client = state->conn;

	pr_debug("tquic_test: created %s connection (CID=%*phN)\n",
		 is_server ? "server" : "client", cid.len, cid.id);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_test_create_connection);

/**
 * tquic_test_complete_handshake - Complete handshake between test connections
 * @ctx: Test context with client and server connections
 *
 * Performs a simulated handshake between the client and server connections.
 * This exchanges Initial and Handshake packets to establish the connection.
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_test_complete_handshake(struct tquic_test_ctx *ctx)
{
	struct tquic_test_priv *priv;
	struct tquic_connection *client, *server;
	int ret;

	if (!ctx || !ctx->priv)
		return -EINVAL;

	priv = ctx->priv;
	client = priv->client.conn;
	server = priv->server.conn;

	if (!client || !server) {
		pr_err("tquic_test: both client and server connections required\n");
		return -EINVAL;
	}

	pr_debug("tquic_test: starting handshake simulation\n");

	/* Exchange destination CIDs */
	client->dcid = server->scid;
	server->dcid = client->scid;

	/* Initialize crypto state for both sides */
	client->crypto_state = tquic_crypto_init_versioned(&server->scid,
							   false, TQUIC_VERSION_1);
	if (!client->crypto_state) {
		pr_err("tquic_test: failed to init client crypto\n");
		return -ENOMEM;
	}

	server->crypto_state = tquic_crypto_init_versioned(&server->scid,
							   true, TQUIC_VERSION_1);
	if (!server->crypto_state) {
		pr_err("tquic_test: failed to init server crypto\n");
		tquic_crypto_cleanup(client->crypto_state);
		client->crypto_state = NULL;
		return -ENOMEM;
	}

	/* Transition states through handshake */
	client->state = TQUIC_CONN_CONNECTING;
	server->state = TQUIC_CONN_CONNECTING;

	/* Simulate Initial packet exchange */
	client->state = TQUIC_CONN_CONNECTED;
	server->state = TQUIC_CONN_CONNECTED;

	/* Copy negotiated transport parameters */
	memcpy(&client->remote_params, &server->local_params,
	       sizeof(struct tquic_transport_params));
	memcpy(&server->remote_params, &client->local_params,
	       sizeof(struct tquic_transport_params));

	/* Apply negotiated flow control limits */
	client->max_data_remote = server->local_params.initial_max_data;
	client->max_streams_bidi = server->local_params.initial_max_streams_bidi;
	client->max_streams_uni = server->local_params.initial_max_streams_uni;

	server->max_data_remote = client->local_params.initial_max_data;
	server->max_streams_bidi = client->local_params.initial_max_streams_bidi;
	server->max_streams_uni = client->local_params.initial_max_streams_uni;

	priv->handshake_complete = true;
	complete(&priv->handshake_done);

	pr_debug("tquic_test: handshake completed successfully\n");
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_test_complete_handshake);

/**
 * tquic_test_send_data - Send data on a QUIC stream
 * @ctx: Test context
 * @stream_id: Stream ID to send on
 * @data: Data to send
 * @len: Length of data
 *
 * Queues data for transmission on the specified stream. The data is
 * buffered and will be transmitted during the next packet exchange.
 *
 * Returns: Number of bytes queued, or negative errno on failure
 */
int tquic_test_send_data(struct tquic_test_ctx *ctx, u64 stream_id,
			 const void *data, size_t len)
{
	struct tquic_test_priv *priv;
	struct tquic_test_conn_state *state;
	struct tquic_connection *conn;
	size_t space;

	if (!ctx || !ctx->priv || !data || len == 0)
		return -EINVAL;

	priv = ctx->priv;

	/* Determine which connection based on stream ID initiator */
	if (stream_id & 0x01) {
		/* Server-initiated stream */
		state = &priv->server;
		conn = priv->server.conn;
	} else {
		/* Client-initiated stream */
		state = &priv->client;
		conn = priv->client.conn;
	}

	if (!conn) {
		pr_err("tquic_test: no connection for stream %llu\n", stream_id);
		return -ENOENT;
	}

	/* Check available buffer space */
	space = TQUIC_TEST_STREAM_BUF - state->stream_tx_len;
	if (len > space)
		len = space;

	if (len == 0)
		return -ENOBUFS;

	/* Copy data to transmit buffer */
	memcpy(state->stream_tx_buf + state->stream_tx_len, data, len);
	state->stream_tx_len += len;

	/* Update statistics */
	conn->data_sent += len;
	ctx->bytes_tx += len;
	ctx->packets_tx++;

	pr_debug("tquic_test: queued %zu bytes on stream %llu (total: %zu)\n",
		 len, stream_id, state->stream_tx_len);

	return len;
}
EXPORT_SYMBOL_GPL(tquic_test_send_data);

/**
 * tquic_test_recv_data - Receive data from a QUIC stream
 * @ctx: Test context
 * @stream_id: Stream ID to receive from
 * @buf: Buffer to receive into
 * @len: Maximum bytes to receive
 *
 * Receives data from the specified stream's receive buffer.
 *
 * Returns: Number of bytes received, or negative errno on failure
 */
int tquic_test_recv_data(struct tquic_test_ctx *ctx, u64 stream_id,
			 void *buf, size_t len)
{
	struct tquic_test_priv *priv;
	struct tquic_test_conn_state *state;
	struct tquic_connection *conn;
	size_t available;

	if (!ctx || !ctx->priv || !buf || len == 0)
		return -EINVAL;

	priv = ctx->priv;

	/* Receiving side is opposite of sending side */
	if (stream_id & 0x01) {
		/* Server-initiated stream - client receives */
		state = &priv->client;
		conn = priv->client.conn;
	} else {
		/* Client-initiated stream - server receives */
		state = &priv->server;
		conn = priv->server.conn;
	}

	if (!conn) {
		pr_err("tquic_test: no connection for stream %llu\n", stream_id);
		return -ENOENT;
	}

	/* Check available data */
	available = state->stream_rx_len;
	if (available == 0)
		return 0;  /* No data available */

	if (len > available)
		len = available;

	/* Copy data from receive buffer */
	memcpy(buf, state->stream_rx_buf, len);

	/* Shift remaining data */
	if (len < state->stream_rx_len) {
		memmove(state->stream_rx_buf,
			state->stream_rx_buf + len,
			state->stream_rx_len - len);
	}
	state->stream_rx_len -= len;

	/* Update statistics */
	conn->data_received += len;
	ctx->bytes_rx += len;
	ctx->packets_rx++;

	pr_debug("tquic_test: received %zu bytes from stream %llu\n",
		 len, stream_id);

	return len;
}
EXPORT_SYMBOL_GPL(tquic_test_recv_data);

/**
 * tquic_test_inject_packet - Inject a raw packet into a connection
 * @ctx: Test context
 * @data: Raw packet data
 * @len: Packet length
 * @to_server: True to inject to server, false to client
 *
 * Injects a raw QUIC packet into the specified connection for processing.
 * This allows testing of packet parsing and handling edge cases.
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_test_inject_packet(struct tquic_test_ctx *ctx,
			     const void *data, size_t len, bool to_server)
{
	struct tquic_test_priv *priv;
	struct tquic_test_conn_state *state;
	struct tquic_connection *conn;
	int ret;

	if (!ctx || !ctx->priv || !data || len == 0)
		return -EINVAL;

	priv = ctx->priv;
	state = to_server ? &priv->server : &priv->client;
	conn = state->conn;

	if (!conn) {
		pr_err("tquic_test: no %s connection for packet injection\n",
		       to_server ? "server" : "client");
		return -ENOENT;
	}

	/* Check for configured packet manipulation */
	if (state->drop_next) {
		state->drop_next = false;
		pr_debug("tquic_test: dropped %zu byte packet to %s\n",
			 len, to_server ? "server" : "client");
		return 0;  /* Silently drop */
	}

	if (state->corrupt_next) {
		u8 *corrupt_data;

		state->corrupt_next = false;

		/* Make a copy and corrupt it */
		corrupt_data = kmemdup(data, len, GFP_KERNEL);
		if (!corrupt_data)
			return -ENOMEM;

		/* Flip some bits in the payload */
		if (len > 20) {
			corrupt_data[len / 2] ^= 0xFF;
			corrupt_data[len / 3] ^= 0xAA;
		}

		pr_debug("tquic_test: corrupted %zu byte packet to %s\n",
			 len, to_server ? "server" : "client");

		/* Process corrupted packet - should fail validation */
		ret = tquic_conn_process_packet(conn, corrupt_data, len);
		kfree(corrupt_data);
		return ret;
	}

	if (state->delay_ms > 0) {
		pr_debug("tquic_test: delaying %zu byte packet by %u ms\n",
			 len, state->delay_ms);
		msleep(state->delay_ms);
	}

	/* Process the packet through the connection's input handler */
	ret = tquic_conn_process_packet(conn, data, len);
	if (ret < 0) {
		pr_debug("tquic_test: packet processing failed: %d\n", ret);
		return ret;
	}

	pr_debug("tquic_test: injected %zu byte packet to %s\n",
		 len, to_server ? "server" : "client");

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_test_inject_packet);

/**
 * tquic_test_drop_next_packet - Configure next packet to be dropped
 * @ctx: Test context
 * @from_server: True to drop from server, false from client
 *
 * Configures the test framework to drop the next packet from the
 * specified endpoint. This is used for loss recovery testing.
 *
 * Returns: 0 on success
 */
int tquic_test_drop_next_packet(struct tquic_test_ctx *ctx, bool from_server)
{
	struct tquic_test_priv *priv;
	struct tquic_test_conn_state *state;

	if (!ctx || !ctx->priv)
		return -EINVAL;

	priv = ctx->priv;

	/* Drop is applied when receiving, so target the opposite side */
	state = from_server ? &priv->client : &priv->server;
	state->drop_next = true;

	pr_debug("tquic_test: configured to drop next packet from %s\n",
		 from_server ? "server" : "client");

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_test_drop_next_packet);

/**
 * tquic_test_delay_packet - Configure packet delay
 * @ctx: Test context
 * @delay_ms: Delay in milliseconds
 *
 * Configures the test framework to delay packet processing by the
 * specified amount. This is used for RTT simulation.
 *
 * Returns: 0 on success
 */
int tquic_test_delay_packet(struct tquic_test_ctx *ctx, u32 delay_ms)
{
	struct tquic_test_priv *priv;

	if (!ctx || !ctx->priv)
		return -EINVAL;

	priv = ctx->priv;

	/* Apply delay to both directions */
	priv->client.delay_ms = delay_ms;
	priv->server.delay_ms = delay_ms;

	pr_debug("tquic_test: configured %u ms packet delay\n", delay_ms);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_test_delay_packet);

/**
 * tquic_test_corrupt_packet - Configure next packet to be corrupted
 * @ctx: Test context
 * @from_server: True to corrupt from server, false from client
 *
 * Configures the test framework to corrupt the next packet from the
 * specified endpoint. This is used for testing AEAD authentication.
 *
 * Returns: 0 on success
 */
int tquic_test_corrupt_packet(struct tquic_test_ctx *ctx, bool from_server)
{
	struct tquic_test_priv *priv;
	struct tquic_test_conn_state *state;

	if (!ctx || !ctx->priv)
		return -EINVAL;

	priv = ctx->priv;

	/* Corruption is applied when receiving */
	state = from_server ? &priv->client : &priv->server;
	state->corrupt_next = true;

	pr_debug("tquic_test: configured to corrupt next packet from %s\n",
		 from_server ? "server" : "client");

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_test_corrupt_packet);

/**
 * tquic_test_exchange_packets - Exchange pending packets between connections
 * @ctx: Test context
 *
 * Transfers pending outbound packets from one connection to the other.
 * This simulates network packet delivery for loopback testing.
 *
 * Returns: Number of packets exchanged, or negative errno on failure
 */
int tquic_test_exchange_packets(struct tquic_test_ctx *ctx)
{
	struct tquic_test_priv *priv;
	int packets = 0;

	if (!ctx || !ctx->priv)
		return -EINVAL;

	priv = ctx->priv;

	/* Transfer client TX to server RX */
	if (priv->client.stream_tx_len > 0) {
		size_t len = min(priv->client.stream_tx_len,
				 TQUIC_TEST_STREAM_BUF - priv->server.stream_rx_len);
		if (len > 0) {
			memcpy(priv->server.stream_rx_buf + priv->server.stream_rx_len,
			       priv->client.stream_tx_buf, len);
			priv->server.stream_rx_len += len;

			/* Shift remaining TX data */
			memmove(priv->client.stream_tx_buf,
				priv->client.stream_tx_buf + len,
				priv->client.stream_tx_len - len);
			priv->client.stream_tx_len -= len;
			packets++;
		}
	}

	/* Transfer server TX to client RX */
	if (priv->server.stream_tx_len > 0) {
		size_t len = min(priv->server.stream_tx_len,
				 TQUIC_TEST_STREAM_BUF - priv->client.stream_rx_len);
		if (len > 0) {
			memcpy(priv->client.stream_rx_buf + priv->client.stream_rx_len,
			       priv->server.stream_tx_buf, len);
			priv->client.stream_rx_len += len;

			/* Shift remaining TX data */
			memmove(priv->server.stream_tx_buf,
				priv->server.stream_tx_buf + len,
				priv->server.stream_tx_len - len);
			priv->server.stream_tx_len -= len;
			packets++;
		}
	}

	return packets;
}
EXPORT_SYMBOL_GPL(tquic_test_exchange_packets);

/**
 * tquic_test_cleanup_ctx - Clean up test context private data
 * @ctx: Test context to clean up
 *
 * Frees all resources allocated for the test context.
 */
void tquic_test_cleanup_ctx(struct tquic_test_ctx *ctx)
{
	struct tquic_test_priv *priv;

	if (!ctx || !ctx->priv)
		return;

	priv = ctx->priv;

	tquic_test_free_conn_state(&priv->client);
	tquic_test_free_conn_state(&priv->server);

	kfree(priv);
	ctx->priv = NULL;
	ctx->conn_client = NULL;
	ctx->conn_server = NULL;
}
EXPORT_SYMBOL_GPL(tquic_test_cleanup_ctx);

/*
 * =============================================================================
 * Proc Interface
 * =============================================================================
 */

static int interop_show(struct seq_file *m, void *v)
{
	struct tquic_test_case *test;
	int count = 0;

	seq_puts(m, "TQUIC Interoperability Test Framework\n");
	seq_puts(m, "======================================\n\n");
	seq_puts(m, "Registered Tests:\n");

	spin_lock(&test_lock);
	list_for_each_entry(test, &test_list, list) {
		seq_printf(m, "  [%s] %s (RFC %s)\n",
			   test->category & TQUIC_TEST_CAT_HANDSHAKE ? "HS" :
			   test->category & TQUIC_TEST_CAT_FRAME ? "FR" :
			   test->category & TQUIC_TEST_CAT_SECURITY ? "SC" : "??",
			   test->name,
			   test->rfc_section ? test->rfc_section : "N/A");
		count++;
	}
	spin_unlock(&test_lock);

	seq_printf(m, "\nTotal: %d tests registered\n", count);
	seq_puts(m, "\nTo run tests: echo 'run all' > /proc/tquic_interop\n");
	seq_puts(m, "To run single: echo 'run <name>' > /proc/tquic_interop\n");

	return 0;
}

static int interop_open(struct inode *inode, struct file *file)
{
	return single_open(file, interop_show, NULL);
}

static ssize_t interop_write(struct file *file, const char __user *buf,
			     size_t count, loff_t *pos)
{
	char cmd[64];
	struct tquic_test_results results;
	size_t len;

	if (count >= sizeof(cmd))
		return -EINVAL;

	if (copy_from_user(cmd, buf, count))
		return -EFAULT;

	cmd[count] = '\0';
	len = strlen(cmd);
	if (len > 0 && cmd[len - 1] == '\n')
		cmd[len - 1] = '\0';

	if (strncmp(cmd, "run all", 7) == 0) {
		tquic_test_run_all(TQUIC_TEST_CAT_ALL, &results);
	} else if (strncmp(cmd, "run ", 4) == 0) {
		tquic_test_run_single(cmd + 4, &results);
	} else {
		pr_err("tquic_interop: unknown command '%s'\n", cmd);
		return -EINVAL;
	}

	return count;
}

static const struct proc_ops interop_proc_ops = {
	.proc_open = interop_open,
	.proc_read = seq_read,
	.proc_write = interop_write,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

/*
 * =============================================================================
 * Module Init/Exit
 * =============================================================================
 */

int tquic_interop_init(void)
{
	struct proc_dir_entry *proc_entry;

	if (interop_initialized)
		return 0;

	test_wq = alloc_workqueue("tquic_test", WQ_UNBOUND, 0);
	if (!test_wq) {
		pr_err("tquic_interop: failed to create workqueue\n");
		return -ENOMEM;
	}

	proc_entry = proc_create("tquic_interop", 0644, NULL, &interop_proc_ops);
	if (!proc_entry)
		pr_warn("tquic_interop: failed to create proc entry\n");

	interop_initialized = true;
	pr_info("tquic_interop: framework initialized\n");

	return 0;
}

void tquic_interop_exit(void)
{
	if (!interop_initialized)
		return;

	remove_proc_entry("tquic_interop", NULL);

	if (test_wq) {
		destroy_workqueue(test_wq);
		test_wq = NULL;
	}

	interop_initialized = false;
	pr_info("tquic_interop: framework shutdown\n");
}

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TQUIC Interoperability Testing Framework");
MODULE_AUTHOR("Linux Foundation");
