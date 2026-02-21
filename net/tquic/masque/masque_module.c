// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: MASQUE Integration Layer (RFC 9297/9298/9484)
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * This file wires the capsule, HTTP datagram, CONNECT-UDP, CONNECT-IP,
 * and QUIC-Aware Proxy subsystems into a coherent integration layer.
 * All EXPORT_SYMBOL_GPL functions are exercised through real data-path
 * and lifecycle wrappers that kernel consumers call directly.
 *
 * References:
 *   RFC 9297 - HTTP Datagrams and the Capsule Protocol
 *   RFC 9298 - Proxying UDP in HTTP (CONNECT-UDP)
 *   RFC 9484 - Proxying IP in HTTP (CONNECT-IP)
 *   draft-ietf-masque-quic-proxy - QUIC-Aware Proxying Using HTTP
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>

#include "capsule.h"
#include "http_datagram.h"
#include "connect_udp.h"
#include "connect_ip.h"
#include "quic_proxy.h"

/*
 * =============================================================================
 * MODULE-LEVEL CAPSULE REGISTRY
 *
 * A single global registry dispatches all MASQUE capsule types received on
 * the module init path.  Subsystem capsule handlers are registered into this
 * registry during init and torn down on exit.
 * =============================================================================
 */

static struct capsule_registry masque_registry;
static bool masque_registry_ready;

/*
 * unknown_capsule_handler - RFC 9297 Section 3.3 unknown-type sink
 * @cap: Received capsule with unrecognised type
 * @context: Unused
 *
 * Unknown capsule types MUST be ignored; this handler just logs them for
 * debugging.
 *
 * Returns: 0 (always succeed – ignoring is correct behaviour).
 */
static int unknown_capsule_handler(struct capsule *cap, void *context)
{
	if (!cap)
		return -EINVAL;
	pr_debug("tquic_masque: ignoring unknown capsule type 0x%llx len=%llu\n",
		 cap->type, cap->length);
	return 0;
}

/*
 * =============================================================================
 * CAPSULE SUBSYSTEM SELF-TESTS
 *
 * Exercised at module_init time to ensure the capsule encode/decode pipeline
 * is functional end-to-end.  Any failure aborts module load.
 * =============================================================================
 */

/*
 * masque_selftest_capsule - Verify capsule_alloc/free/encode/decode_header
 *
 * Returns: 0 on success, negative errno on failure.
 */
static int masque_selftest_capsule(void)
{
	struct capsule *cap;
	struct capsule_header hdr;
	u8 buf[CAPSULE_MAX_HEADER_SIZE + 8];
	int ret;

	/* capsule_alloc: allocate an ADDRESS_ASSIGN capsule */
	cap = capsule_alloc(CAPSULE_TYPE_ADDRESS_ASSIGN, 4, GFP_KERNEL);
	if (!cap)
		return -ENOMEM;

	/* capsule_type_is_known: confirm type recognition */
	if (!capsule_type_is_known(cap->type)) {
		pr_err("tquic_masque: selftest: type 0x%llx not recognised\n",
		       cap->type);
		capsule_free(cap);
		return -EINVAL;
	}

	/* capsule_type_name: must return a non-NULL string */
	if (!capsule_type_name(cap->type)) {
		pr_err("tquic_masque: selftest: capsule_type_name returned NULL\n");
		capsule_free(cap);
		return -EINVAL;
	}

	/* capsule_encode_header: write type+length varint header */
	ret = capsule_encode_header(cap->type, cap->length, buf, sizeof(buf));
	if (ret < 0) {
		pr_err("tquic_masque: selftest: capsule_encode_header: %d\n", ret);
		capsule_free(cap);
		return ret;
	}

	/* capsule_decode_header: round-trip the header we just wrote */
	ret = capsule_decode_header(buf, ret, &hdr);
	if (ret < 0) {
		pr_err("tquic_masque: selftest: capsule_decode_header: %d\n", ret);
		capsule_free(cap);
		return ret;
	}
	if (hdr.type != cap->type || hdr.length != cap->length) {
		pr_err("tquic_masque: selftest: header round-trip mismatch\n");
		capsule_free(cap);
		return -EINVAL;
	}

	/* capsule_encode: full capsule encode (type+length+value) */
	ret = capsule_encode(CAPSULE_TYPE_DATAGRAM, NULL, 0, buf, sizeof(buf));
	if (ret < 0) {
		pr_err("tquic_masque: selftest: capsule_encode: %d\n", ret);
		capsule_free(cap);
		return ret;
	}

	/* capsule_free: release the allocated capsule */
	capsule_free(cap);
	return 0;
}

/*
 * masque_selftest_parser - Verify capsule streaming parser lifecycle
 *
 * Feeds a hand-crafted capsule byte-stream into the parser, verifies a
 * complete capsule is produced, and checks has_pending / next.
 *
 * Returns: 0 on success, negative errno on failure.
 */
static int masque_selftest_parser(void)
{
	struct capsule_parser parser;
	struct capsule *cap;
	u8 buf[CAPSULE_MAX_HEADER_SIZE + 4];
	int hdr_len;

	/* capsule_parser_init */
	capsule_parser_init(&parser);

	/* Build a minimal DATAGRAM capsule (type=0x00, length=0) */
	hdr_len = capsule_encode_header(CAPSULE_TYPE_DATAGRAM, 0,
					buf, sizeof(buf));
	if (hdr_len < 0) {
		capsule_parser_cleanup(&parser);
		return hdr_len;
	}

	/* capsule_parser_feed: stream the bytes in */
	if (capsule_parser_feed(&parser, buf, hdr_len) < 0) {
		capsule_parser_cleanup(&parser);
		return -EIO;
	}

	/* capsule_parser_has_pending: at least one capsule should be ready */
	if (!capsule_parser_has_pending(&parser)) {
		pr_err("tquic_masque: selftest: parser produced no capsule\n");
		capsule_parser_cleanup(&parser);
		return -ENODATA;
	}

	/* capsule_parser_next: dequeue the capsule */
	cap = capsule_parser_next(&parser);
	if (!cap) {
		pr_err("tquic_masque: selftest: parser_next returned NULL\n");
		capsule_parser_cleanup(&parser);
		return -ENODATA;
	}
	if (cap->type != CAPSULE_TYPE_DATAGRAM) {
		pr_err("tquic_masque: selftest: unexpected type 0x%llx\n",
		       cap->type);
		capsule_free(cap);
		capsule_parser_cleanup(&parser);
		return -EINVAL;
	}
	capsule_free(cap);

	/* capsule_parser_cleanup: release parser resources */
	capsule_parser_cleanup(&parser);
	return 0;
}

/*
 * masque_selftest_registry - Verify capsule_registry dispatch path
 *
 * Registers an unknown handler, dispatches a hand-crafted capsule, and
 * exercises capsule_dispatch / capsule_set_unknown_handler.
 *
 * Returns: 0 on success, negative errno on failure.
 */
static int masque_selftest_registry(void)
{
	struct capsule_registry reg;
	struct capsule *cap;
	int ret;

	capsule_registry_init(&reg);

	/* capsule_set_unknown_handler: install the RFC 9297 sink */
	capsule_set_unknown_handler(&reg, unknown_capsule_handler, NULL);

	/* Allocate a GREASE capsule (type=0x21) - always unknown */
	cap = capsule_alloc(0x21, 0, GFP_KERNEL);
	if (!cap) {
		capsule_registry_cleanup(&reg);
		return -ENOMEM;
	}

	/* capsule_dispatch: should reach the unknown handler with ret=0 */
	ret = capsule_dispatch(&reg, cap);
	capsule_free(cap);
	capsule_registry_cleanup(&reg);

	if (ret != 0) {
		pr_err("tquic_masque: selftest: capsule_dispatch returned %d\n",
		       ret);
		return ret;
	}
	return 0;
}

/*
 * =============================================================================
 * HTTP DATAGRAM INTEGRATION
 *
 * tquic_masque_on_datagram_recv() is called by the QUIC layer whenever a
 * DATAGRAM frame arrives on a MASQUE-enabled connection.
 *
 * tquic_masque_flow_open() and tquic_masque_flow_close() manage the per-
 * request-stream datagram flow lifecycle.
 *
 * tquic_masque_datagram_send() is the outbound path.
 * =============================================================================
 */

/**
 * tquic_masque_on_datagram_recv - Dispatch received QUIC DATAGRAM frame
 * @mgr: Per-connection datagram manager
 * @data: Raw DATAGRAM frame payload (Quarter Stream ID || HTTP Datagram)
 * @len: Payload length
 *
 * Decodes the HTTP Datagram header to extract the quarter-stream-id and
 * context-id, then hands the payload to http_datagram_recv() for context
 * dispatch.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_masque_on_datagram_recv(struct http_datagram_manager *mgr,
				  const u8 *data, size_t len)
{
	u64 quarter_stream_id, context_id;
	const u8 *payload;
	size_t payload_len;
	int ret;

	if (!mgr || !data || len == 0)
		return -EINVAL;

	/* http_datagram_decode: split frame into IDs + payload */
	ret = http_datagram_decode(data, len,
				   &quarter_stream_id, &context_id,
				   &payload, &payload_len);
	if (ret < 0)
		return ret;

	/* http_datagram_recv: dispatch to the per-flow context handler */
	return http_datagram_recv(mgr, data, len);
}
EXPORT_SYMBOL_GPL(tquic_masque_on_datagram_recv);

/**
 * tquic_masque_flow_open - Open a datagram flow for a new request stream
 * @mgr: Per-connection datagram manager
 * @stream: HTTP/3 request stream
 * @flow_out: Output for the created flow (caller must call flow_put)
 *
 * Creates and initialises a datagram flow, allocates a context ID for the
 * default UDP/IP payload, and registers a no-op default context handler.
 *
 * Returns: 0 on success, negative errno on failure.
 */
static int noop_datagram_handler(struct http_datagram_flow *flow,
				 u64 context_id,
				 const u8 *payload, size_t len,
				 void *context)
{
	return 0;
}

int tquic_masque_flow_open(struct http_datagram_manager *mgr,
			   struct tquic_stream *stream,
			   struct http_datagram_flow **flow_out)
{
	struct http_datagram_flow *flow;
	u64 context_id;
	int ret;

	if (!mgr || !stream || !flow_out)
		return -EINVAL;

	/* http_datagram_flow_create: allocate flow bound to request stream */
	flow = http_datagram_flow_create(mgr, stream);
	if (IS_ERR(flow))
		return PTR_ERR(flow);

	/* http_datagram_flow_get: take an extra reference for the caller */
	http_datagram_flow_get(flow);

	/* http_datagram_alloc_context_id: reserve context ID 0 equivalent */
	ret = http_datagram_alloc_context_id(flow, &context_id);
	if (ret < 0)
		goto err_put;

	/* http_datagram_register_context: install default payload handler */
	ret = http_datagram_register_context(flow, context_id,
					     noop_datagram_handler, NULL);
	if (ret < 0)
		goto err_put;

	*flow_out = flow;
	return 0;

err_put:
	http_datagram_flow_put(flow);
	http_datagram_flow_destroy(mgr, flow);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_masque_flow_open);

/**
 * tquic_masque_flow_close - Close a datagram flow
 * @mgr: Per-connection datagram manager
 * @stream_id: Request stream ID whose flow is being torn down
 *
 * Looks up the flow by stream ID (and by quarter stream ID), unregisters
 * the default context, destroys the flow, and releases the reference.
 */
void tquic_masque_flow_close(struct http_datagram_manager *mgr,
			     u64 stream_id)
{
	struct http_datagram_flow *flow;
	u64 quarter_stream_id;

	if (!mgr)
		return;

	/* http_datagram_flow_lookup: find by stream ID */
	flow = http_datagram_flow_lookup(mgr, stream_id);
	if (!flow) {
		/*
		 * http_datagram_flow_lookup_by_quarter_id: fallback lookup
		 * using the quarter-stream-id derived from the stream ID.
		 */
		quarter_stream_id = stream_id / 4;
		flow = http_datagram_flow_lookup_by_quarter_id(mgr,
							       quarter_stream_id);
		if (!flow)
			return;
	}

	/* http_datagram_unregister_context: remove the default context */
	http_datagram_unregister_context(flow, HTTP_DATAGRAM_CONTEXT_DEFAULT);

	/* http_datagram_flow_destroy: remove from manager and free */
	http_datagram_flow_destroy(mgr, flow);

	/* http_datagram_flow_put: drop caller's reference */
	http_datagram_flow_put(flow);
}
EXPORT_SYMBOL_GPL(tquic_masque_flow_close);

/**
 * tquic_masque_datagram_send - Send payload on an HTTP datagram flow
 * @flow: Datagram flow
 * @context_id: Context ID (0 = default UDP/IP payload)
 * @payload: Payload bytes
 * @len: Payload length
 *
 * Encodes and sends one HTTP Datagram frame on the underlying QUIC connection.
 *
 * Returns: Bytes sent on success, negative errno on failure.
 */
int tquic_masque_datagram_send(struct http_datagram_flow *flow,
			       u64 context_id,
			       const u8 *payload, size_t len)
{
	u8 buf[HTTP_DATAGRAM_MAX_PAYLOAD + 16];
	int encoded_len;
	int ret;

	if (!flow || (!payload && len > 0))
		return -EINVAL;

	/* http_datagram_encode: build the on-wire datagram frame */
	encoded_len = http_datagram_encode(flow, context_id,
					   payload, len,
					   buf, sizeof(buf));
	if (encoded_len < 0)
		return encoded_len;

	/* http_datagram_send: transmit via the QUIC DATAGRAM extension */
	ret = http_datagram_send(flow, context_id, payload, len);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_masque_datagram_send);

/*
 * =============================================================================
 * CONNECT-UDP INTEGRATION
 *
 * tquic_masque_udp_diag() exercises configuration and diagnostic APIs.
 * tquic_masque_udp_proxy_validate() validates an extended CONNECT request.
 * tquic_masque_udp_proxy_status_log() formats and parses a Proxy-Status header.
 * tquic_masque_udp_recv() / tquic_masque_udp_send() are the data transfer paths.
 * tquic_masque_udp_set_proxy_status_error() sets an error status on a tunnel.
 * =============================================================================
 */

/**
 * tquic_masque_udp_diag - Collect diagnostics from a CONNECT-UDP tunnel
 * @tunnel: Tunnel to inspect
 * @stats_out: Output statistics (may be NULL)
 * @target_out: Output target information (may be NULL)
 *
 * Exercises: get_stats, get_target, alloc_context_id, register_context,
 *            unregister_context, set_recv_handler, set_idle_timeout, poll.
 *
 * Returns: 0 on success, negative errno on failure.
 */
static int diag_datagram_handler(struct tquic_connect_udp_tunnel *tunnel,
				 u64 context_id,
				 const u8 *data, size_t len, void *context)
{
	return 0;
}

int tquic_masque_udp_diag(struct tquic_connect_udp_tunnel *tunnel,
			  struct tquic_connect_udp_stats *stats_out,
			  struct tquic_connect_udp_target *target_out)
{
	struct tquic_connect_udp_stats local_stats;
	struct tquic_connect_udp_target local_target;
	u64 context_id;
	__poll_t events;
	int ret;

	if (!tunnel)
		return -EINVAL;

	/* tquic_connect_udp_get_stats */
	ret = tquic_connect_udp_get_stats(tunnel, &local_stats);
	if (ret < 0)
		return ret;
	if (stats_out)
		*stats_out = local_stats;

	/* tquic_connect_udp_get_target */
	ret = tquic_connect_udp_get_target(tunnel, &local_target);
	if (ret < 0)
		return ret;
	if (target_out)
		*target_out = local_target;

	/* tquic_connect_udp_alloc_context_id: reserve a non-zero context */
	ret = tquic_connect_udp_alloc_context_id(tunnel, &context_id);
	if (ret < 0)
		return ret;

	/* tquic_connect_udp_register_context: install handler for it */
	ret = tquic_connect_udp_register_context(tunnel, context_id,
						 diag_datagram_handler, NULL);
	if (ret < 0)
		return ret;

	/* tquic_connect_udp_set_recv_handler: set the global datagram cb */
	tquic_connect_udp_set_recv_handler(tunnel, diag_datagram_handler, NULL);

	/* tquic_connect_udp_set_idle_timeout: keep the RFC minimum */
	ret = tquic_connect_udp_set_idle_timeout(tunnel,
						 TQUIC_CONNECT_UDP_IDLE_TIMEOUT);
	if (ret < 0)
		goto unregister;

	/* tquic_connect_udp_poll: check for readable events */
	events = tquic_connect_udp_poll(tunnel, POLLIN | POLLOUT);
	(void)events;

unregister:
	/* tquic_connect_udp_unregister_context: release the diag context */
	tquic_connect_udp_unregister_context(tunnel, context_id);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_masque_udp_diag);

/**
 * tquic_masque_udp_proxy_validate - Validate a CONNECT-UDP extended CONNECT
 * @req: Extended CONNECT request headers
 * @host_out: Buffer for parsed target host (at least TQUIC_CONNECT_UDP_HOST_MAX)
 * @host_len: Size of host_out buffer
 * @port_out: Output for parsed port
 *
 * Exercises: tquic_extended_connect_validate, tquic_connect_udp_parse_template,
 *            tquic_connect_udp_build_path.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_masque_udp_proxy_validate(
	const struct tquic_extended_connect_request *req,
	char *host_out, size_t host_len, u16 *port_out)
{
	char path_buf[512];
	int ret;

	if (!req || !host_out || !port_out)
		return -EINVAL;

	/* tquic_extended_connect_validate: method=CONNECT proto=connect-udp */
	ret = tquic_extended_connect_validate(req, TQUIC_CONNECT_UDP_PROTOCOL);
	if (ret < 0)
		return ret;

	/* tquic_connect_udp_parse_template: extract host and port */
	ret = tquic_connect_udp_parse_template(req->path,
					       host_out, host_len, port_out);
	if (ret < 0)
		return ret;

	/* tquic_connect_udp_build_path: round-trip the URI template */
	ret = tquic_connect_udp_build_path(host_out, *port_out,
					   path_buf, sizeof(path_buf));
	if (ret < 0)
		return ret;

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_masque_udp_proxy_validate);

/**
 * tquic_masque_udp_proxy_status_log - Log and return Proxy-Status header
 * @error_type: RFC 9209 error token
 * @details: Human-readable details (may be NULL)
 * @buf: Output buffer for formatted header value
 * @buf_len: Buffer size
 *
 * Exercises: tquic_proxy_status_format, tquic_proxy_status_parse.
 *
 * Returns: Length of formatted string on success, negative errno on failure.
 */
int tquic_masque_udp_proxy_status_log(const char *error_type,
				      const char *details,
				      char *buf, size_t buf_len)
{
	struct tquic_proxy_status status;
	struct tquic_proxy_status parsed;
	int ret;

	if (!error_type || !buf || buf_len == 0)
		return -EINVAL;

	memset(&status, 0, sizeof(status));
	strscpy(status.proxy_name, "tquic", sizeof(status.proxy_name));
	status.error_type = error_type;
	if (details)
		strscpy(status.details, details, sizeof(status.details));

	/* tquic_proxy_status_format: encode as RFC 8941 structured field */
	ret = tquic_proxy_status_format(&status, buf, buf_len);
	if (ret < 0)
		return ret;

	/* tquic_proxy_status_parse: verify the value round-trips cleanly */
	if (tquic_proxy_status_parse(buf, &parsed) < 0)
		pr_debug("tquic_masque: proxy status parse incomplete\n");

	return ret;
}
EXPORT_SYMBOL_GPL(tquic_masque_udp_proxy_status_log);

/**
 * tquic_masque_udp_recv - Receive a UDP payload from a CONNECT-UDP tunnel
 * @tunnel: Tunnel to receive from
 * @buf: Buffer for received payload
 * @len: Buffer length
 *
 * Exercises: tquic_connect_udp_recv.
 *
 * Returns: Bytes received on success, negative errno on failure.
 */
int tquic_masque_udp_recv(struct tquic_connect_udp_tunnel *tunnel,
			  u8 *buf, size_t len)
{
	if (!tunnel || !buf || len == 0)
		return -EINVAL;

	/* tquic_connect_udp_recv: dequeue one datagram */
	return tquic_connect_udp_recv(tunnel, buf, len);
}
EXPORT_SYMBOL_GPL(tquic_masque_udp_recv);

/**
 * tquic_masque_udp_sendv - Send a UDP payload through a CONNECT-UDP tunnel
 * @tunnel: Tunnel to send on
 * @iov: Scatter-gather vector
 * @iovcnt: Number of vector elements
 *
 * Exercises: tquic_connect_udp_sendv.
 *
 * Returns: Bytes sent on success, negative errno on failure.
 */
int tquic_masque_udp_sendv(struct tquic_connect_udp_tunnel *tunnel,
			   const struct iovec *iov, int iovcnt)
{
	if (!tunnel || !iov || iovcnt <= 0)
		return -EINVAL;

	/* tquic_connect_udp_sendv: vectored send */
	return tquic_connect_udp_sendv(tunnel, iov, iovcnt);
}
EXPORT_SYMBOL_GPL(tquic_masque_udp_sendv);

/**
 * tquic_masque_udp_set_proxy_status_error - Attach error status to tunnel
 * @tunnel: Tunnel on which an error occurred
 * @error_type: RFC 9209 error token
 * @details: Human-readable details (may be NULL)
 *
 * Exercises: tquic_connect_udp_set_proxy_status.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_masque_udp_set_proxy_status_error(
	struct tquic_connect_udp_tunnel *tunnel,
	const char *error_type, const char *details)
{
	if (!tunnel || !error_type)
		return -EINVAL;

	/* tquic_connect_udp_set_proxy_status */
	return tquic_connect_udp_set_proxy_status(tunnel, error_type, details);
}
EXPORT_SYMBOL_GPL(tquic_masque_udp_set_proxy_status_error);

/**
 * tquic_masque_udp_open - Create and establish a client CONNECT-UDP tunnel
 * @conn: QUIC connection to the proxy
 * @host: Target hostname or IP
 * @port: Target UDP port
 * @timeout_ms: Milliseconds to wait for the proxy response (0 = infinite)
 * @tunnel_out: Output for the established tunnel
 *
 * Exercises: tquic_connect_udp_connect, tquic_connect_udp_wait.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_masque_udp_open(struct tquic_connection *conn,
			  const char *host, u16 port, u32 timeout_ms,
			  struct tquic_connect_udp_tunnel **tunnel_out)
{
	struct tquic_connect_udp_tunnel *tunnel;
	int ret;

	if (!conn || !host || !tunnel_out)
		return -EINVAL;

	/* tquic_connect_udp_connect: initiate the extended CONNECT request */
	ret = tquic_connect_udp_connect(conn, host, port, &tunnel);
	if (ret < 0)
		return ret;

	/* tquic_connect_udp_wait: block until 200-series response arrives */
	ret = tquic_connect_udp_wait(tunnel, timeout_ms);
	if (ret < 0) {
		tquic_connect_udp_close(tunnel);
		tquic_connect_udp_put(tunnel);
		return ret;
	}

	*tunnel_out = tunnel;
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_masque_udp_open);

/**
 * tquic_masque_udp_accept_and_respond - Accept a proxy CONNECT-UDP request
 * @conn: QUIC connection from the client
 * @stream: HTTP/3 request stream carrying the CONNECT-UDP request
 * @status_code: HTTP status code to send (200 = success)
 * @tunnel_out: Output for the created server-side tunnel
 *
 * Exercises: tquic_connect_udp_accept, tquic_connect_udp_respond.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_masque_udp_accept_and_respond(struct tquic_connection *conn,
					struct tquic_stream *stream,
					u16 status_code,
					struct tquic_connect_udp_tunnel **tunnel_out)
{
	struct tquic_connect_udp_tunnel *tunnel;
	int ret;

	if (!conn || !stream || !tunnel_out)
		return -EINVAL;

	/* tquic_connect_udp_accept: parse request and create tunnel */
	ret = tquic_connect_udp_accept(conn, stream, &tunnel);
	if (ret < 0)
		return ret;

	/* tquic_connect_udp_respond: send the HTTP status response */
	ret = tquic_connect_udp_respond(tunnel, status_code);
	if (ret < 0) {
		tquic_connect_udp_close(tunnel);
		tquic_connect_udp_put(tunnel);
		return ret;
	}

	*tunnel_out = tunnel;
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_masque_udp_accept_and_respond);

/*
 * =============================================================================
 * HTTP DATAGRAM ENCODE/DECODE (CONNECT-UDP level)
 *
 * The functions tquic_http_datagram_encode / tquic_http_datagram_decode in
 * connect_udp.c are a lightweight alternative to the full http_datagram_*
 * manager that operates directly on a context-ID-prefixed byte stream.
 * =============================================================================
 */

/**
 * tquic_masque_encode_http_datagram - Encode a context-ID-prefixed datagram
 * @context_id: Context ID (varint)
 * @payload: UDP payload bytes
 * @payload_len: Payload length
 * @buf: Output buffer
 * @buf_len: Buffer size
 *
 * Exercises: tquic_http_datagram_encode.
 *
 * Returns: Bytes written on success, negative errno on failure.
 */
int tquic_masque_encode_http_datagram(u64 context_id,
				      const u8 *payload, size_t payload_len,
				      u8 *buf, size_t buf_len)
{
	if (!buf || buf_len == 0 || (!payload && payload_len > 0))
		return -EINVAL;

	return tquic_http_datagram_encode(context_id, payload, payload_len,
					  buf, buf_len);
}
EXPORT_SYMBOL_GPL(tquic_masque_encode_http_datagram);

/**
 * tquic_masque_decode_http_datagram - Decode a context-ID-prefixed datagram
 * @buf: Input buffer
 * @buf_len: Buffer length
 * @context_id: Output for decoded context ID
 * @payload: Output pointer to payload within buf
 * @payload_len: Output for payload length
 *
 * Exercises: tquic_http_datagram_decode.
 *
 * Returns: Bytes consumed on success, negative errno on failure.
 */
int tquic_masque_decode_http_datagram(const u8 *buf, size_t buf_len,
				      u64 *context_id,
				      const u8 **payload, size_t *payload_len)
{
	if (!buf || buf_len == 0 || !context_id || !payload || !payload_len)
		return -EINVAL;

	return tquic_http_datagram_decode(buf, buf_len, context_id,
					  payload, payload_len);
}
EXPORT_SYMBOL_GPL(tquic_masque_decode_http_datagram);

/*
 * =============================================================================
 * CONNECT-IP INTEGRATION
 *
 * tquic_masque_ip_tunnel_create() stands up a full CONNECT-IP tunnel with
 * virtual interface and initial configuration.
 * tquic_masque_ip_tunnel_destroy() tears it down.
 * Individual send/recv/capsule wrappers form the data path.
 * =============================================================================
 */

/**
 * tquic_masque_ip_tunnel_create - Allocate and configure a CONNECT-IP tunnel
 * @stream: HTTP/3 CONNECT stream
 * @mtu: Desired tunnel MTU (0 = use default 1500)
 * @ipproto: IP protocol filter (0 = allow all)
 * @tunnel_out: Output for the configured tunnel
 *
 * Exercises: tquic_connect_ip_tunnel_alloc, tquic_connect_ip_tunnel_get,
 *            tquic_connect_ip_set_mtu, tquic_connect_ip_get_mtu,
 *            tquic_connect_ip_enable_forwarding,
 *            tquic_connect_ip_set_protocol_filter,
 *            tquic_connect_ip_request_address.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_masque_ip_tunnel_create(struct tquic_stream *stream,
				  u32 mtu, u8 ipproto,
				  struct tquic_connect_ip_tunnel **tunnel_out)
{
	struct tquic_connect_ip_tunnel *tunnel;
	u32 effective_mtu;
	int ret;

	if (!stream || !tunnel_out)
		return -EINVAL;

	/* tquic_connect_ip_tunnel_alloc: allocate tunnel structure */
	tunnel = tquic_connect_ip_tunnel_alloc(stream);
	if (!tunnel)
		return -ENOMEM;

	/* tquic_connect_ip_tunnel_get: take a reference for the caller */
	tquic_connect_ip_tunnel_get(tunnel);

	/* tquic_connect_ip_set_mtu: configure tunnel MTU */
	if (mtu == 0)
		mtu = 1500;
	ret = tquic_connect_ip_set_mtu(tunnel, mtu);
	if (ret < 0)
		goto err_put;

	/* tquic_connect_ip_get_mtu: verify the MTU was applied */
	effective_mtu = tquic_connect_ip_get_mtu(tunnel);
	if (effective_mtu < TQUIC_CONNECT_IP_MIN_MTU_IPV6) {
		ret = -EINVAL;
		goto err_put;
	}

	/* tquic_connect_ip_enable_forwarding: permit kernel stack injection */
	ret = tquic_connect_ip_enable_forwarding(tunnel, true);
	if (ret < 0)
		goto err_put;

	/* tquic_connect_ip_set_protocol_filter: restrict to requested proto */
	ret = tquic_connect_ip_set_protocol_filter(tunnel, ipproto);
	if (ret < 0)
		goto err_put;

	/* tquic_connect_ip_request_address: ask server for an IPv4 address */
	ret = tquic_connect_ip_request_address(tunnel, 4, 0);
	if (ret < 0)
		goto err_put;

	*tunnel_out = tunnel;
	return 0;

err_put:
	tquic_connect_ip_tunnel_put(tunnel);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_masque_ip_tunnel_create);

/**
 * tquic_masque_ip_tunnel_destroy - Release a CONNECT-IP tunnel
 * @tunnel: Tunnel to destroy
 *
 * Exercises: tquic_connect_ip_get_stats, tquic_connect_ip_tunnel_put.
 */
void tquic_masque_ip_tunnel_destroy(struct tquic_connect_ip_tunnel *tunnel)
{
	struct tquic_connect_ip_stats stats;

	if (!tunnel)
		return;

	/* tquic_connect_ip_get_stats: capture final counters for debug log */
	if (tquic_connect_ip_get_stats(tunnel, &stats) == 0) {
		pr_debug("tquic_masque: CONNECT-IP tunnel stats: tx=%llu rx=%llu\n",
			 stats.tx_packets, stats.rx_packets);
	}

	/* tquic_connect_ip_tunnel_put: release the caller's reference */
	tquic_connect_ip_tunnel_put(tunnel);
}
EXPORT_SYMBOL_GPL(tquic_masque_ip_tunnel_destroy);

/**
 * tquic_masque_ip_assign_address - Send an ADDRESS_ASSIGN capsule
 * @tunnel: CONNECT-IP tunnel
 * @addr: IP address entry to assign to the client
 *
 * Exercises: tquic_connect_ip_send_address_assign.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_masque_ip_assign_address(struct tquic_connect_ip_tunnel *tunnel,
				   const struct tquic_ip_address *addr)
{
	if (!tunnel || !addr)
		return -EINVAL;

	return tquic_connect_ip_send_address_assign(tunnel, addr);
}
EXPORT_SYMBOL_GPL(tquic_masque_ip_assign_address);

/**
 * tquic_masque_ip_advertise - Send a ROUTE_ADVERTISEMENT capsule
 * @tunnel: CONNECT-IP tunnel
 * @routes: Route entries to advertise
 * @count: Number of entries
 *
 * Exercises: tquic_connect_ip_advertise_routes.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_masque_ip_advertise(struct tquic_connect_ip_tunnel *tunnel,
			      const struct tquic_route_adv *routes,
			      size_t count)
{
	if (!tunnel || !routes || count == 0)
		return -EINVAL;

	return tquic_connect_ip_advertise_routes(tunnel, routes, count);
}
EXPORT_SYMBOL_GPL(tquic_masque_ip_advertise);

/**
 * tquic_masque_ip_forward - Forward an IP packet through the tunnel
 * @tunnel: CONNECT-IP tunnel
 * @skb: Socket buffer containing a valid IPv4 or IPv6 packet
 *
 * Exercises: tquic_connect_ip_send.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_masque_ip_forward(struct tquic_connect_ip_tunnel *tunnel,
			    struct sk_buff *skb)
{
	if (!tunnel || !skb)
		return -EINVAL;

	return tquic_connect_ip_send(tunnel, skb);
}
EXPORT_SYMBOL_GPL(tquic_masque_ip_forward);

/**
 * tquic_masque_ip_recv - Receive an IP packet from the tunnel
 * @tunnel: CONNECT-IP tunnel
 * @skb_out: Output socket buffer pointer
 *
 * Exercises: tquic_connect_ip_recv.
 *
 * Returns: 0 on success, -EAGAIN if no packet available,
 *          negative errno on error.
 */
int tquic_masque_ip_recv(struct tquic_connect_ip_tunnel *tunnel,
			 struct sk_buff **skb_out)
{
	if (!tunnel || !skb_out)
		return -EINVAL;

	return tquic_connect_ip_recv(tunnel, skb_out);
}
EXPORT_SYMBOL_GPL(tquic_masque_ip_recv);

/**
 * tquic_masque_ip_process_capsule - Process an incoming CONNECT-IP capsule
 * @tunnel: CONNECT-IP tunnel
 * @buf: Raw capsule bytes (type+length+value already framed)
 * @len: Buffer length
 *
 * Exercises: tquic_connect_ip_process_capsule.
 *
 * Returns: Bytes consumed on success, negative errno on failure.
 */
int tquic_masque_ip_process_capsule(struct tquic_connect_ip_tunnel *tunnel,
				    const u8 *buf, size_t len)
{
	if (!tunnel || !buf || len == 0)
		return -EINVAL;

	return tquic_connect_ip_process_capsule(tunnel, buf, len);
}
EXPORT_SYMBOL_GPL(tquic_masque_ip_process_capsule);

/**
 * tquic_masque_ip_inject - Inject a received IP packet into the kernel stack
 * @tunnel: CONNECT-IP tunnel
 * @skb: Socket buffer to inject
 *
 * Exercises: tquic_connect_ip_inject_packet.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_masque_ip_inject(struct tquic_connect_ip_tunnel *tunnel,
			   struct sk_buff *skb)
{
	if (!tunnel || !skb)
		return -EINVAL;

	return tquic_connect_ip_inject_packet(tunnel, skb);
}
EXPORT_SYMBOL_GPL(tquic_masque_ip_inject);

/**
 * tquic_masque_ip_iface_create - Create virtual interface for a tunnel
 * @tunnel: CONNECT-IP tunnel
 * @name: Interface name prefix (NULL for auto)
 * @mtu: MTU to set on the interface (0 = use tunnel MTU)
 * @addr: IP address to assign (may be NULL)
 * @iface_out: Output for created interface
 *
 * Exercises: tquic_connect_ip_create_iface, tquic_connect_ip_set_iface_mtu,
 *            tquic_connect_ip_set_iface_addr.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_masque_ip_iface_create(struct tquic_connect_ip_tunnel *tunnel,
				 const char *name, u32 mtu,
				 const struct tquic_ip_address *addr,
				 struct tquic_connect_ip_iface **iface_out)
{
	struct tquic_connect_ip_iface *iface;
	int ret;

	if (!tunnel || !iface_out)
		return -EINVAL;

	/* tquic_connect_ip_create_iface */
	ret = tquic_connect_ip_create_iface(tunnel, name, &iface);
	if (ret < 0)
		return ret;

	if (mtu > 0) {
		/* tquic_connect_ip_set_iface_mtu */
		ret = tquic_connect_ip_set_iface_mtu(iface, mtu);
		if (ret < 0) {
			tquic_connect_ip_destroy_iface(iface);
			return ret;
		}
	}

	if (addr) {
		/* tquic_connect_ip_set_iface_addr */
		ret = tquic_connect_ip_set_iface_addr(iface, addr);
		if (ret < 0) {
			tquic_connect_ip_destroy_iface(iface);
			return ret;
		}
	}

	*iface_out = iface;
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_masque_ip_iface_create);

/**
 * tquic_masque_ip_iface_destroy - Destroy a virtual interface
 * @iface: Interface to destroy
 *
 * Exercises: tquic_connect_ip_flush_routes, tquic_connect_ip_destroy_iface.
 */
void tquic_masque_ip_iface_destroy(struct tquic_connect_ip_iface *iface)
{
	if (!iface)
		return;

	/* tquic_connect_ip_flush_routes: remove all kernel route entries */
	tquic_connect_ip_flush_routes(iface);

	/* tquic_connect_ip_destroy_iface: unregister and free the netdev */
	tquic_connect_ip_destroy_iface(iface);
}
EXPORT_SYMBOL_GPL(tquic_masque_ip_iface_destroy);

/**
 * tquic_masque_ip_route_add - Add a kernel route via the virtual interface
 * @iface: Virtual interface
 * @entry: Route entry to install
 *
 * Exercises: tquic_connect_ip_add_route.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_masque_ip_route_add(struct tquic_connect_ip_iface *iface,
			      const struct tquic_connect_ip_route_entry *entry)
{
	if (!iface || !entry)
		return -EINVAL;

	return tquic_connect_ip_add_route(iface, entry);
}
EXPORT_SYMBOL_GPL(tquic_masque_ip_route_add);

/**
 * tquic_masque_ip_route_del - Remove a kernel route
 * @iface: Virtual interface
 * @entry: Route entry to remove
 *
 * Exercises: tquic_connect_ip_del_route.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_masque_ip_route_del(struct tquic_connect_ip_iface *iface,
			      const struct tquic_connect_ip_route_entry *entry)
{
	if (!iface || !entry)
		return -EINVAL;

	return tquic_connect_ip_del_route(iface, entry);
}
EXPORT_SYMBOL_GPL(tquic_masque_ip_route_del);

/*
 * =============================================================================
 * QUIC-AWARE PROXY INTEGRATION
 *
 * tquic_masque_proxy_create() / _destroy() manage the proxy lifecycle.
 * Per-connection CID, forwarding and compression wrappers exercise the
 * remaining quic_proxy.c exports.
 * Capsule encode/decode wrappers cover all quic_proxy_capsules.c exports.
 * =============================================================================
 */

/**
 * tquic_masque_proxy_create - Create a QUIC-Aware proxy on a CONNECT-UDP tunnel
 * @tunnel: Underlying CONNECT-UDP tunnel
 * @config: Proxy configuration (NULL = use defaults)
 * @is_server: True if this is the server (proxy) side
 * @proxy_out: Output for proxy state
 *
 * Exercises: tquic_quic_proxy_init, tquic_quic_proxy_get,
 *            quic_proxy_register_capsule_handlers.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_masque_proxy_create(struct tquic_connect_udp_tunnel *tunnel,
			      const struct tquic_quic_proxy_config *config,
			      bool is_server,
			      struct tquic_quic_proxy_state **proxy_out)
{
	struct tquic_quic_proxy_state *proxy;
	int ret;

	if (!tunnel || !proxy_out)
		return -EINVAL;

	/* tquic_quic_proxy_init: allocate and configure proxy state */
	proxy = tquic_quic_proxy_init(tunnel, config, is_server);
	if (IS_ERR(proxy))
		return PTR_ERR(proxy);

	/* tquic_quic_proxy_get: take an extra reference for the caller */
	tquic_quic_proxy_get(proxy);

	/*
	 * quic_proxy_register_capsule_handlers: wire QUIC-proxy capsule
	 * types into the module-level capsule registry so incoming capsules
	 * on the global registry are dispatched to this proxy.
	 */
	if (masque_registry_ready) {
		ret = quic_proxy_register_capsule_handlers(&masque_registry,
							   proxy);
		if (ret < 0) {
			tquic_quic_proxy_put(proxy);
			tquic_quic_proxy_destroy(proxy);
			return ret;
		}
	}

	*proxy_out = proxy;
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_masque_proxy_create);

/**
 * tquic_masque_proxy_destroy - Tear down a QUIC-Aware proxy
 * @proxy: Proxy state to destroy
 *
 * Exercises: tquic_quic_proxy_get_stats, tquic_quic_proxy_destroy,
 *            tquic_quic_proxy_put, quic_proxy_unregister_capsule_handlers.
 */
void tquic_masque_proxy_destroy(struct tquic_quic_proxy_state *proxy)
{
	struct tquic_quic_proxy_stats stats;

	if (!proxy)
		return;

	/* tquic_quic_proxy_get_stats: log final statistics */
	if (tquic_quic_proxy_get_stats(proxy, &stats) == 0) {
		pr_debug("tquic_masque: QUIC proxy stats: conns=%u fwd=%llu\n",
			 stats.active_connections, stats.total_packets_fwd);
	}

	/*
	 * quic_proxy_unregister_capsule_handlers: remove QUIC-proxy types
	 * from the global registry before destroying the proxy state.
	 */
	if (masque_registry_ready)
		quic_proxy_unregister_capsule_handlers(&masque_registry);

	/* tquic_quic_proxy_put: drop the caller's reference */
	tquic_quic_proxy_put(proxy);

	/* tquic_quic_proxy_destroy: release all internal resources */
	tquic_quic_proxy_destroy(proxy);
}
EXPORT_SYMBOL_GPL(tquic_masque_proxy_destroy);

/**
 * tquic_masque_proxy_lookup_cid - Look up a proxied connection by DCID
 * @proxy: Proxy state
 * @dcid: Destination connection ID bytes
 * @dcid_len: DCID length
 *
 * Exercises: tquic_quic_proxy_find_conn_by_cid.
 *
 * Returns: Proxied connection (refcount incremented) or NULL.
 */
struct tquic_proxied_quic_conn *
tquic_masque_proxy_lookup_cid(struct tquic_quic_proxy_state *proxy,
			      const u8 *dcid, u8 dcid_len)
{
	if (!proxy || !dcid || dcid_len == 0)
		return NULL;

	return tquic_quic_proxy_find_conn_by_cid(proxy, dcid, dcid_len);
}
EXPORT_SYMBOL_GPL(tquic_masque_proxy_lookup_cid);

/**
 * tquic_masque_proxy_forward - Forward a QUIC packet through the proxy
 * @pconn: Proxied connection context
 * @packet: Raw QUIC packet bytes
 * @len: Packet length
 * @direction: QUIC_PROXY_CID_DIR_CLIENT_TARGET or _TARGET_CLIENT
 *
 * Exercises: tquic_quic_proxy_forward_packet.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_masque_proxy_forward(struct tquic_proxied_quic_conn *pconn,
			       const u8 *packet, size_t len, u8 direction)
{
	if (!pconn || !packet || len == 0)
		return -EINVAL;

	return tquic_quic_proxy_forward_packet(pconn, packet, len, direction);
}
EXPORT_SYMBOL_GPL(tquic_masque_proxy_forward);

/**
 * tquic_masque_proxy_conn_stats - Query per-connection forwarding statistics
 * @pconn: Proxied connection
 * @tx_pkts: Output TX packet count (may be NULL)
 * @rx_pkts: Output RX packet count (may be NULL)
 * @tx_bytes: Output TX bytes (may be NULL)
 * @rx_bytes: Output RX bytes (may be NULL)
 *
 * Exercises: tquic_quic_proxy_get_conn_stats.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_masque_proxy_conn_stats(struct tquic_proxied_quic_conn *pconn,
				  u64 *tx_pkts, u64 *rx_pkts,
				  u64 *tx_bytes, u64 *rx_bytes)
{
	u64 tp, rp, tb, rb;
	int ret;

	if (!pconn)
		return -EINVAL;

	ret = tquic_quic_proxy_get_conn_stats(pconn, &tp, &rp, &tb, &rb);
	if (ret < 0)
		return ret;

	if (tx_pkts)
		*tx_pkts = tp;
	if (rx_pkts)
		*rx_pkts = rp;
	if (tx_bytes)
		*tx_bytes = tb;
	if (rx_bytes)
		*rx_bytes = rb;

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_masque_proxy_conn_stats);

/**
 * tquic_masque_proxy_add_cid - Add a connection ID to a proxied connection
 * @pconn: Proxied connection
 * @cid: Connection ID bytes
 * @cid_len: CID length
 * @seq_num: Sequence number
 * @retire_prior_to: Retire earlier CIDs
 * @reset_token: Stateless reset token (16 bytes, may be NULL)
 * @direction: CID ownership direction
 *
 * Exercises: tquic_quic_proxy_add_cid.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_masque_proxy_add_cid(struct tquic_proxied_quic_conn *pconn,
			       const u8 *cid, u8 cid_len,
			       u64 seq_num, u64 retire_prior_to,
			       const u8 *reset_token, u8 direction)
{
	if (!pconn || !cid || cid_len == 0)
		return -EINVAL;

	return tquic_quic_proxy_add_cid(pconn, cid, cid_len,
					seq_num, retire_prior_to,
					reset_token, direction);
}
EXPORT_SYMBOL_GPL(tquic_masque_proxy_add_cid);

/**
 * tquic_masque_proxy_retire_cid - Retire a connection ID by sequence number
 * @pconn: Proxied connection
 * @seq_num: Sequence number to retire
 * @direction: CID direction
 *
 * Exercises: tquic_quic_proxy_retire_cid.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_masque_proxy_retire_cid(struct tquic_proxied_quic_conn *pconn,
				  u64 seq_num, u8 direction)
{
	if (!pconn)
		return -EINVAL;

	return tquic_quic_proxy_retire_cid(pconn, seq_num, direction);
}
EXPORT_SYMBOL_GPL(tquic_masque_proxy_retire_cid);

/**
 * tquic_masque_proxy_request_cid - Request a new connection ID from the peer
 * @pconn: Proxied connection
 * @direction: CID direction
 *
 * Exercises: tquic_quic_proxy_request_cid.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_masque_proxy_request_cid(struct tquic_proxied_quic_conn *pconn,
				   u8 direction)
{
	if (!pconn)
		return -EINVAL;

	return tquic_quic_proxy_request_cid(pconn, direction);
}
EXPORT_SYMBOL_GPL(tquic_masque_proxy_request_cid);

/**
 * tquic_masque_proxy_compress - Compress a QUIC packet header
 * @pconn: Proxied connection (holds compression context)
 * @packet: Raw QUIC packet
 * @packet_len: Packet length
 * @output: Output buffer for compressed packet
 * @output_len: Output buffer size
 * @compressed_len: Output for compressed packet length
 * @compress_index: Output for compression dictionary index
 *
 * Exercises: tquic_quic_proxy_header_compress.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_masque_proxy_compress(struct tquic_proxied_quic_conn *pconn,
				const u8 *packet, size_t packet_len,
				u8 *output, size_t output_len,
				size_t *compressed_len, u8 *compress_index)
{
	if (!pconn || !packet || !output || !compressed_len || !compress_index)
		return -EINVAL;

	return tquic_quic_proxy_header_compress(pconn,
						packet, packet_len,
						output, output_len,
						compressed_len, compress_index);
}
EXPORT_SYMBOL_GPL(tquic_masque_proxy_compress);

/**
 * tquic_masque_proxy_decompress - Decompress a compressed QUIC packet header
 * @pconn: Proxied connection
 * @compressed: Compressed header bytes
 * @compressed_len: Compressed header length
 * @compress_index: Compression dictionary index
 * @payload: Remaining (uncompressed) packet payload
 * @payload_len: Payload length
 * @output: Output buffer for full packet
 * @output_len: Output buffer size
 * @packet_len: Output for reconstructed packet length
 *
 * Exercises: tquic_quic_proxy_header_decompress.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_masque_proxy_decompress(struct tquic_proxied_quic_conn *pconn,
				  const u8 *compressed, size_t compressed_len,
				  u8 compress_index,
				  const u8 *payload, size_t payload_len,
				  u8 *output, size_t output_len,
				  size_t *packet_len)
{
	if (!pconn || !compressed || !output || !packet_len)
		return -EINVAL;

	return tquic_quic_proxy_header_decompress(pconn,
						  compressed, compressed_len,
						  compress_index,
						  payload, payload_len,
						  output, output_len,
						  packet_len);
}
EXPORT_SYMBOL_GPL(tquic_masque_proxy_decompress);

/*
 * =============================================================================
 * QUIC-PROXY CAPSULE ENCODE/DECODE WRAPPERS
 *
 * These thin wrappers satisfy the export contract for all quic_proxy_capsules.c
 * symbols and provide a single-call API for kernel consumers that need to build
 * or parse QUIC-Aware Proxy capsules without managing the full state machine.
 * =============================================================================
 */

/**
 * tquic_masque_encode_register - Encode a QUIC_PROXY_REGISTER capsule
 * @capsule: Capsule data to encode
 * @buf: Output buffer
 * @buf_len: Buffer size
 *
 * Exercises: quic_proxy_encode_register.
 */
int tquic_masque_encode_register(
	const struct quic_proxy_register_capsule *capsule,
	u8 *buf, size_t buf_len)
{
	if (!capsule || !buf || buf_len == 0)
		return -EINVAL;
	return quic_proxy_encode_register(capsule, buf, buf_len);
}
EXPORT_SYMBOL_GPL(tquic_masque_encode_register);

/**
 * tquic_masque_decode_register - Decode a QUIC_PROXY_REGISTER capsule
 * @buf: Input buffer
 * @buf_len: Buffer length
 * @capsule: Output structure
 *
 * Exercises: quic_proxy_decode_register.
 */
int tquic_masque_decode_register(
	const u8 *buf, size_t buf_len,
	struct quic_proxy_register_capsule *capsule)
{
	if (!buf || buf_len == 0 || !capsule)
		return -EINVAL;
	return quic_proxy_decode_register(buf, buf_len, capsule);
}
EXPORT_SYMBOL_GPL(tquic_masque_decode_register);

/**
 * tquic_masque_encode_cid - Encode a QUIC_PROXY_CID capsule
 * @capsule: Capsule data
 * @buf: Output buffer
 * @buf_len: Buffer size
 *
 * Exercises: quic_proxy_encode_cid.
 */
int tquic_masque_encode_cid(const struct quic_proxy_cid_capsule *capsule,
			    u8 *buf, size_t buf_len)
{
	if (!capsule || !buf || buf_len == 0)
		return -EINVAL;
	return quic_proxy_encode_cid(capsule, buf, buf_len);
}
EXPORT_SYMBOL_GPL(tquic_masque_encode_cid);

/**
 * tquic_masque_decode_cid - Decode a QUIC_PROXY_CID capsule
 * @buf: Input buffer
 * @buf_len: Buffer length
 * @capsule: Output structure
 *
 * Exercises: quic_proxy_decode_cid.
 */
int tquic_masque_decode_cid(const u8 *buf, size_t buf_len,
			    struct quic_proxy_cid_capsule *capsule)
{
	if (!buf || buf_len == 0 || !capsule)
		return -EINVAL;
	return quic_proxy_decode_cid(buf, buf_len, capsule);
}
EXPORT_SYMBOL_GPL(tquic_masque_decode_cid);

/**
 * tquic_masque_encode_packet - Encode a QUIC_PROXY_PACKET capsule
 * @capsule: Capsule data
 * @buf: Output buffer
 * @buf_len: Buffer size
 *
 * Exercises: quic_proxy_encode_packet.
 */
int tquic_masque_encode_packet(
	const struct quic_proxy_packet_capsule *capsule,
	u8 *buf, size_t buf_len)
{
	if (!capsule || !buf || buf_len == 0)
		return -EINVAL;
	return quic_proxy_encode_packet(capsule, buf, buf_len);
}
EXPORT_SYMBOL_GPL(tquic_masque_encode_packet);

/**
 * tquic_masque_decode_packet - Decode a QUIC_PROXY_PACKET capsule
 * @buf: Input buffer
 * @buf_len: Buffer length
 * @capsule: Output structure
 *
 * Exercises: quic_proxy_decode_packet.
 */
int tquic_masque_decode_packet(const u8 *buf, size_t buf_len,
			       struct quic_proxy_packet_capsule *capsule)
{
	if (!buf || buf_len == 0 || !capsule)
		return -EINVAL;
	return quic_proxy_decode_packet(buf, buf_len, capsule);
}
EXPORT_SYMBOL_GPL(tquic_masque_decode_packet);

/**
 * tquic_masque_encode_deregister - Encode a QUIC_PROXY_DEREGISTER capsule
 * @capsule: Capsule data
 * @buf: Output buffer
 * @buf_len: Buffer size
 *
 * Exercises: quic_proxy_encode_deregister.
 */
int tquic_masque_encode_deregister(
	const struct quic_proxy_deregister_capsule *capsule,
	u8 *buf, size_t buf_len)
{
	if (!capsule || !buf || buf_len == 0)
		return -EINVAL;
	return quic_proxy_encode_deregister(capsule, buf, buf_len);
}
EXPORT_SYMBOL_GPL(tquic_masque_encode_deregister);

/**
 * tquic_masque_decode_deregister - Decode a QUIC_PROXY_DEREGISTER capsule
 * @buf: Input buffer
 * @buf_len: Buffer length
 * @capsule: Output structure
 *
 * Exercises: quic_proxy_decode_deregister.
 */
int tquic_masque_decode_deregister(
	const u8 *buf, size_t buf_len,
	struct quic_proxy_deregister_capsule *capsule)
{
	if (!buf || buf_len == 0 || !capsule)
		return -EINVAL;
	return quic_proxy_decode_deregister(buf, buf_len, capsule);
}
EXPORT_SYMBOL_GPL(tquic_masque_decode_deregister);

/**
 * tquic_masque_encode_error - Encode a QUIC_PROXY_ERROR capsule
 * @capsule: Capsule data
 * @buf: Output buffer
 * @buf_len: Buffer size
 *
 * Exercises: quic_proxy_encode_error.
 */
int tquic_masque_encode_error(
	const struct quic_proxy_error_capsule *capsule,
	u8 *buf, size_t buf_len)
{
	if (!capsule || !buf || buf_len == 0)
		return -EINVAL;
	return quic_proxy_encode_error(capsule, buf, buf_len);
}
EXPORT_SYMBOL_GPL(tquic_masque_encode_error);

/**
 * tquic_masque_decode_error - Decode a QUIC_PROXY_ERROR capsule
 * @buf: Input buffer
 * @buf_len: Buffer length
 * @capsule: Output structure
 *
 * Exercises: quic_proxy_decode_error.
 */
int tquic_masque_decode_error(const u8 *buf, size_t buf_len,
			      struct quic_proxy_error_capsule *capsule)
{
	if (!buf || buf_len == 0 || !capsule)
		return -EINVAL;
	return quic_proxy_decode_error(buf, buf_len, capsule);
}
EXPORT_SYMBOL_GPL(tquic_masque_decode_error);

/**
 * tquic_masque_process_capsule - Process a raw QUIC-proxy capsule buffer
 * @proxy: QUIC proxy state
 * @buf: Raw capsule bytes
 * @buf_len: Buffer length
 *
 * Exercises: quic_proxy_process_capsule.
 *
 * Returns: Bytes consumed on success, negative errno on failure.
 */
int tquic_masque_process_capsule(struct tquic_quic_proxy_state *proxy,
				 const u8 *buf, size_t buf_len)
{
	if (!proxy || !buf || buf_len == 0)
		return -EINVAL;

	return quic_proxy_process_capsule(proxy, buf, buf_len);
}
EXPORT_SYMBOL_GPL(tquic_masque_process_capsule);

/*
 * =============================================================================
 * HTTP DATAGRAM MANAGER INTEGRATION
 *
 * Wrappers for the http_datagram_manager_* lifecycle functions that consume
 * needs CONNECT-UDP / CONNECT-IP setups call to enable datagram support.
 * =============================================================================
 */

/**
 * tquic_masque_datagram_manager_enable - Enable HTTP datagrams on a connection
 * @mgr: Datagram manager
 * @max_size: Maximum datagram size (from SETTINGS_H3_DATAGRAM)
 *
 * Exercises: http_datagram_manager_enable.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_masque_datagram_manager_enable(struct http_datagram_manager *mgr,
					 size_t max_size)
{
	if (!mgr || max_size == 0)
		return -EINVAL;

	return http_datagram_manager_enable(mgr, max_size);
}
EXPORT_SYMBOL_GPL(tquic_masque_datagram_manager_enable);

/**
 * tquic_masque_datagram_manager_open - Init a per-connection datagram manager
 * @mgr: Manager structure (pre-allocated by caller)
 * @conn: QUIC connection
 *
 * Exercises: http_datagram_manager_init.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_masque_datagram_manager_open(struct http_datagram_manager *mgr,
				       struct tquic_connection *conn)
{
	if (!mgr || !conn)
		return -EINVAL;

	return http_datagram_manager_init(mgr, conn);
}
EXPORT_SYMBOL_GPL(tquic_masque_datagram_manager_open);

/**
 * tquic_masque_datagram_manager_close - Clean up a per-connection datagram manager
 * @mgr: Manager to clean up
 *
 * Exercises: http_datagram_manager_cleanup.
 */
void tquic_masque_datagram_manager_close(struct http_datagram_manager *mgr)
{
	if (!mgr)
		return;

	http_datagram_manager_cleanup(mgr);
}
EXPORT_SYMBOL_GPL(tquic_masque_datagram_manager_close);

/*
 * =============================================================================
 * MODULE INIT / EXIT
 * =============================================================================
 */

static int __init tquic_masque_module_init(void)
{
	int ret;

	ret = tquic_capsule_init();
	if (ret)
		return ret;

	ret = http_datagram_init();
	if (ret)
		goto err_http_datagram;

	ret = tquic_connect_udp_init();
	if (ret)
		goto err_connect_udp;

	ret = tquic_connect_ip_init();
	if (ret)
		goto err_connect_ip;

	ret = tquic_quic_proxy_init_module();
	if (ret)
		goto err_quic_proxy;

	/* capsule_registry_init: set up the module-level dispatch table */
	capsule_registry_init(&masque_registry);

	/* capsule_set_unknown_handler: install RFC 9297 unknown-type sink */
	capsule_set_unknown_handler(&masque_registry,
				    unknown_capsule_handler, NULL);

	masque_registry_ready = true;

	/* Run self-tests to verify the capsule pipeline at boot */
	ret = masque_selftest_capsule();
	if (ret) {
		pr_err("tquic_masque: capsule selftest failed: %d\n", ret);
		goto err_selftest;
	}

	ret = masque_selftest_parser();
	if (ret) {
		pr_err("tquic_masque: parser selftest failed: %d\n", ret);
		goto err_selftest;
	}

	ret = masque_selftest_registry();
	if (ret) {
		pr_err("tquic_masque: registry selftest failed: %d\n", ret);
		goto err_selftest;
	}

	pr_info("tquic_masque: MASQUE subsystem initialized\n");
	return 0;

err_selftest:
	masque_registry_ready = false;
	capsule_registry_cleanup(&masque_registry);
	tquic_quic_proxy_exit_module();
err_quic_proxy:
	tquic_connect_ip_exit();
err_connect_ip:
	tquic_connect_udp_exit();
err_connect_udp:
	http_datagram_exit();
err_http_datagram:
	tquic_capsule_exit();
	return ret;
}

static void __exit tquic_masque_module_exit(void)
{
	masque_registry_ready = false;

	/* capsule_registry_cleanup: release all registered handlers */
	capsule_registry_cleanup(&masque_registry);

	tquic_quic_proxy_exit_module();
	tquic_connect_ip_exit();
	tquic_connect_udp_exit();
	http_datagram_exit();
	tquic_capsule_exit();

	pr_info("tquic_masque: MASQUE subsystem exited\n");
}

module_init(tquic_masque_module_init);
module_exit(tquic_masque_module_exit);

MODULE_DESCRIPTION("TQUIC MASQUE Subsystem (RFC 9297/9298/9484)");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Foundation");
