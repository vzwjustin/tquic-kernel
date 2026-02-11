/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC MASQUE: HTTP Datagrams (RFC 9297)
 *
 * Copyright (c) 2026 Linux Foundation
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * HTTP Datagrams provide a mechanism for transmitting unreliable data
 * between HTTP endpoints. They are transmitted using QUIC DATAGRAM frames
 * (RFC 9221) and associated with HTTP requests via the DATAGRAM frame
 * flow identifier.
 *
 * Key concepts:
 *
 * 1. Quarter Stream ID Encoding:
 *    The flow identifier in QUIC DATAGRAM frames uses "Quarter Stream ID"
 *    encoding to associate datagrams with HTTP request streams:
 *      Flow ID = Stream ID / 4
 *    This works because client-initiated bidirectional streams (request
 *    streams) have IDs: 0, 4, 8, 12, ... so dividing by 4 gives: 0, 1, 2, 3, ...
 *
 * 2. Context ID:
 *    Within a datagram flow, the Context ID identifies the payload type:
 *      - Context ID 0: Default payload (UDP for CONNECT-UDP, IP for CONNECT-IP)
 *      - Other values: Extension-defined contexts
 *
 * 3. HTTP Datagram Format:
 *    Context ID (varint) || Payload
 *
 * 4. DATAGRAM Frame Format:
 *    Quarter Stream ID (varint) || HTTP Datagram
 *
 * References:
 *   RFC 9297 - HTTP Datagrams and the Capsule Protocol
 *   RFC 9221 - An Unreliable Datagram Extension to QUIC
 *   RFC 9298 - Proxying UDP in HTTP (CONNECT-UDP)
 *   RFC 9484 - Proxying IP in HTTP (CONNECT-IP)
 */

#ifndef _TQUIC_MASQUE_HTTP_DATAGRAM_H
#define _TQUIC_MASQUE_HTTP_DATAGRAM_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/spinlock.h>
#include <net/tquic.h>

/*
 * =============================================================================
 * CONSTANTS
 * =============================================================================
 */

/* Default context ID for MASQUE protocols */
#define HTTP_DATAGRAM_CONTEXT_DEFAULT	0

/* Maximum context ID value (62-bit varint) */
#define HTTP_DATAGRAM_CONTEXT_MAX	((1ULL << 62) - 1)

/* Context ID allocation: even = client, odd = server (RFC 9298 Section 4) */
#define HTTP_DATAGRAM_CONTEXT_IS_CLIENT(id)	(((id) & 1) == 0)
#define HTTP_DATAGRAM_CONTEXT_IS_SERVER(id)	(((id) & 1) != 0)

/* Maximum datagram payload size (excluding context ID) */
#define HTTP_DATAGRAM_MAX_PAYLOAD	65527

/* Maximum QUIC DATAGRAM frame payload */
#define QUIC_DATAGRAM_MAX_SIZE		65535

/*
 * =============================================================================
 * DATA STRUCTURES
 * =============================================================================
 */

/**
 * struct http_datagram_flow - HTTP Datagram flow state
 * @stream_id: Associated HTTP request stream ID
 * @quarter_stream_id: Flow identifier (stream_id / 4)
 * @contexts: RB-tree of registered context handlers
 * @num_contexts: Number of registered contexts
 * @next_context_id: Next context ID to allocate
 * @is_server: True if server side (allocates odd context IDs)
 * @stats: Flow statistics
 * @lock: Flow lock
 * @refcnt: Reference count
 * @node: RB-tree node for connection's flow tree
 *
 * Represents a datagram flow associated with an HTTP request stream.
 */
struct http_datagram_flow {
	u64 stream_id;
	u64 quarter_stream_id;

	/* Parent manager reference for accessing connection */
	struct http_datagram_manager *mgr;

	/* Context management */
	struct rb_root contexts;
	u32 num_contexts;
	u64 next_context_id;
	bool is_server;

	/* Statistics */
	struct {
		u64 tx_datagrams;
		u64 rx_datagrams;
		u64 tx_bytes;
		u64 rx_bytes;
		u64 tx_errors;
		u64 rx_errors;
		u64 unknown_contexts;
	} stats;

	spinlock_t lock;
	refcount_t refcnt;
	struct rb_node node;
};

/**
 * struct http_datagram_context - Context handler registration
 * @context_id: Context ID
 * @handler: Callback for received datagrams
 * @context: Handler-specific context
 * @node: RB-tree node
 */
struct http_datagram_context {
	u64 context_id;
	int (*handler)(struct http_datagram_flow *flow,
		       u64 context_id,
		       const u8 *payload, size_t len,
		       void *context);
	void *context;
	struct rb_node node;
};

/**
 * struct http_datagram_manager - Per-connection datagram manager
 * @conn: Associated QUIC connection
 * @flows: RB-tree of datagram flows by quarter stream ID
 * @num_flows: Number of active flows
 * @enabled: True if HTTP datagrams are negotiated
 * @max_datagram_size: Maximum datagram size from transport
 * @lock: Manager lock
 */
struct http_datagram_manager {
	struct tquic_connection *conn;
	struct rb_root flows;
	u32 num_flows;
	bool enabled;
	size_t max_datagram_size;
	spinlock_t lock;
};

/*
 * =============================================================================
 * QUARTER STREAM ID ENCODING
 * =============================================================================
 *
 * Client-initiated bidirectional streams (HTTP request streams):
 *   Stream ID: 0, 4, 8, 12, 16, ...
 *   Quarter Stream ID: 0, 1, 2, 3, 4, ...
 *
 * The conversion is simple division/multiplication by 4.
 */

/**
 * http_datagram_stream_to_flow_id - Convert stream ID to flow ID
 * @stream_id: QUIC stream ID
 *
 * Computes the Quarter Stream ID for use as DATAGRAM flow identifier.
 *
 * Returns: Flow identifier (Quarter Stream ID).
 */
static inline u64 http_datagram_stream_to_flow_id(u64 stream_id)
{
	return stream_id / 4;
}

/**
 * http_datagram_flow_to_stream_id - Convert flow ID to stream ID
 * @flow_id: Quarter Stream ID (flow identifier)
 *
 * Returns: QUIC stream ID.
 */
static inline u64 http_datagram_flow_to_stream_id(u64 flow_id)
{
	return flow_id * 4;
}

/**
 * http_datagram_is_request_stream - Check if stream ID is a request stream
 * @stream_id: QUIC stream ID
 *
 * Request streams are client-initiated bidirectional streams:
 * IDs 0, 4, 8, 12, ... (low 2 bits = 0x00)
 *
 * Returns: true if this is a request stream.
 */
static inline bool http_datagram_is_request_stream(u64 stream_id)
{
	return (stream_id & 0x03) == 0x00;
}

/*
 * =============================================================================
 * MANAGER API
 * =============================================================================
 */

/**
 * http_datagram_manager_init - Initialize datagram manager
 * @mgr: Manager to initialize
 * @conn: QUIC connection
 *
 * Returns: 0 on success, negative errno on failure.
 */
int http_datagram_manager_init(struct http_datagram_manager *mgr,
			       struct tquic_connection *conn);

/**
 * http_datagram_manager_cleanup - Clean up datagram manager
 * @mgr: Manager to clean up
 */
void http_datagram_manager_cleanup(struct http_datagram_manager *mgr);

/**
 * http_datagram_manager_enable - Enable HTTP datagrams
 * @mgr: Manager
 * @max_size: Maximum datagram size
 *
 * Called when SETTINGS_H3_DATAGRAM is negotiated.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int http_datagram_manager_enable(struct http_datagram_manager *mgr,
				 size_t max_size);

/*
 * =============================================================================
 * FLOW API
 * =============================================================================
 */

/**
 * http_datagram_flow_create - Create datagram flow for stream
 * @mgr: Datagram manager
 * @stream: HTTP request stream
 *
 * Creates a datagram flow associated with the given request stream.
 *
 * Returns: Flow on success, ERR_PTR on failure.
 */
struct http_datagram_flow *http_datagram_flow_create(
	struct http_datagram_manager *mgr,
	struct tquic_stream *stream);

/**
 * http_datagram_flow_lookup - Find flow by stream ID
 * @mgr: Datagram manager
 * @stream_id: Request stream ID
 *
 * Returns: Flow on success, NULL if not found.
 */
struct http_datagram_flow *http_datagram_flow_lookup(
	struct http_datagram_manager *mgr,
	u64 stream_id);

/**
 * http_datagram_flow_lookup_by_quarter_id - Find flow by Quarter Stream ID
 * @mgr: Datagram manager
 * @quarter_stream_id: Quarter Stream ID (flow identifier)
 *
 * Returns: Flow on success, NULL if not found.
 */
struct http_datagram_flow *http_datagram_flow_lookup_by_quarter_id(
	struct http_datagram_manager *mgr,
	u64 quarter_stream_id);

/**
 * http_datagram_flow_get - Increment flow reference count
 * @flow: Flow to reference
 */
void http_datagram_flow_get(struct http_datagram_flow *flow);

/**
 * http_datagram_flow_put - Decrement flow reference count
 * @flow: Flow to dereference
 */
void http_datagram_flow_put(struct http_datagram_flow *flow);

/**
 * http_datagram_flow_destroy - Destroy datagram flow
 * @mgr: Datagram manager
 * @flow: Flow to destroy
 */
void http_datagram_flow_destroy(struct http_datagram_manager *mgr,
				struct http_datagram_flow *flow);

/*
 * =============================================================================
 * CONTEXT API
 * =============================================================================
 */

/**
 * http_datagram_register_context - Register context handler
 * @flow: Datagram flow
 * @context_id: Context ID to register
 * @handler: Handler callback
 * @context: Handler context
 *
 * Registers a handler for datagrams with the specified context ID.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int http_datagram_register_context(struct http_datagram_flow *flow,
				   u64 context_id,
				   int (*handler)(struct http_datagram_flow *,
						  u64, const u8 *, size_t,
						  void *),
				   void *context);

/**
 * http_datagram_unregister_context - Unregister context handler
 * @flow: Datagram flow
 * @context_id: Context ID to unregister
 */
void http_datagram_unregister_context(struct http_datagram_flow *flow,
				      u64 context_id);

/**
 * http_datagram_alloc_context_id - Allocate new context ID
 * @flow: Datagram flow
 * @context_id: Output for allocated context ID
 *
 * Allocates the next available context ID. Client allocates even IDs,
 * server allocates odd IDs.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int http_datagram_alloc_context_id(struct http_datagram_flow *flow,
				   u64 *context_id);

/*
 * =============================================================================
 * SEND/RECEIVE API
 * =============================================================================
 */

/**
 * http_datagram_send - Send HTTP datagram
 * @flow: Datagram flow
 * @context_id: Context ID
 * @payload: Payload data
 * @len: Payload length
 *
 * Sends a datagram with the specified context ID. The datagram is
 * encoded as: Quarter Stream ID || Context ID || Payload
 *
 * Returns: Number of bytes sent on success, negative errno on failure.
 */
int http_datagram_send(struct http_datagram_flow *flow,
		       u64 context_id,
		       const u8 *payload, size_t len);

/**
 * http_datagram_send_default - Send datagram with default context
 * @flow: Datagram flow
 * @payload: Payload data
 * @len: Payload length
 *
 * Convenience function to send with context ID 0.
 *
 * Returns: Number of bytes sent on success, negative errno on failure.
 */
static inline int http_datagram_send_default(struct http_datagram_flow *flow,
					     const u8 *payload, size_t len)
{
	return http_datagram_send(flow, HTTP_DATAGRAM_CONTEXT_DEFAULT,
				  payload, len);
}

/**
 * http_datagram_recv - Process received QUIC DATAGRAM
 * @mgr: Datagram manager
 * @data: DATAGRAM frame payload
 * @len: Payload length
 *
 * Parses the DATAGRAM frame, finds the associated flow, and dispatches
 * to the appropriate context handler.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int http_datagram_recv(struct http_datagram_manager *mgr,
		       const u8 *data, size_t len);

/*
 * =============================================================================
 * ENCODING/DECODING
 * =============================================================================
 */

/**
 * http_datagram_encode - Encode HTTP datagram for transmission
 * @flow: Datagram flow
 * @context_id: Context ID
 * @payload: Payload data
 * @payload_len: Payload length
 * @buf: Output buffer
 * @buf_len: Buffer size
 *
 * Encodes: Quarter Stream ID || Context ID || Payload
 *
 * Returns: Total encoded length on success, negative errno on failure.
 */
int http_datagram_encode(struct http_datagram_flow *flow,
			 u64 context_id,
			 const u8 *payload, size_t payload_len,
			 u8 *buf, size_t buf_len);

/**
 * http_datagram_decode - Decode received DATAGRAM
 * @data: Input data
 * @len: Data length
 * @quarter_stream_id: Output for Quarter Stream ID
 * @context_id: Output for context ID
 * @payload: Output for payload pointer
 * @payload_len: Output for payload length
 *
 * Decodes: Quarter Stream ID || Context ID || Payload
 *
 * Returns: 0 on success, negative errno on failure.
 */
int http_datagram_decode(const u8 *data, size_t len,
			 u64 *quarter_stream_id,
			 u64 *context_id,
			 const u8 **payload, size_t *payload_len);

/*
 * =============================================================================
 * STATISTICS
 * =============================================================================
 */

/**
 * http_datagram_flow_get_stats - Get flow statistics
 * @flow: Datagram flow
 * @tx_datagrams: Output for TX count
 * @rx_datagrams: Output for RX count
 * @tx_bytes: Output for TX bytes
 * @rx_bytes: Output for RX bytes
 *
 * Returns: 0 on success.
 */
int http_datagram_flow_get_stats(struct http_datagram_flow *flow,
				 u64 *tx_datagrams, u64 *rx_datagrams,
				 u64 *tx_bytes, u64 *rx_bytes);

/*
 * =============================================================================
 * MODULE INITIALIZATION
 * =============================================================================
 */

int __init http_datagram_init(void);
void __exit http_datagram_exit(void);

#endif /* _TQUIC_MASQUE_HTTP_DATAGRAM_H */
