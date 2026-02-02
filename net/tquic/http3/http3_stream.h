/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC HTTP/3: Stream Type Mapping
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * HTTP/3 stream type mapping per RFC 9114 Section 6.
 * Provides stream type identification and management for HTTP/3.
 *
 * Stream Types (RFC 9114 Section 6.2):
 *   Bidirectional:
 *     - Request streams: Carry HTTP request/response pairs
 *
 *   Unidirectional (identified by stream type byte):
 *     - 0x00: Control stream (one per endpoint, required)
 *     - 0x01: Push stream (server to client only)
 *     - 0x02: QPACK Encoder stream
 *     - 0x03: QPACK Decoder stream
 *
 * Stream ID Encoding (inherited from QUIC RFC 9000 Section 2.1):
 *   - Client-initiated bidi: 0, 4, 8, 12, ...
 *   - Server-initiated bidi: 1, 5, 9, 13, ...
 *   - Client-initiated uni:  2, 6, 10, 14, ...
 *   - Server-initiated uni:  3, 7, 11, 15, ...
 */

#ifndef _TQUIC_HTTP3_STREAM_H
#define _TQUIC_HTTP3_STREAM_H

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/rbtree.h>
#include <net/tquic.h>

/*
 * HTTP/3 Error Codes (RFC 9114 Section 8.1)
 *
 * Error code range: 0x100-0x1FF (256-511)
 */
#define H3_NO_ERROR			0x100
#define H3_GENERAL_PROTOCOL_ERROR	0x101
#define H3_INTERNAL_ERROR		0x102
#define H3_STREAM_CREATION_ERROR	0x103
#define H3_CLOSED_CRITICAL_STREAM	0x104
#define H3_FRAME_UNEXPECTED		0x105
#define H3_FRAME_ERROR			0x106
#define H3_EXCESSIVE_LOAD		0x107
#define H3_ID_ERROR			0x108
#define H3_SETTINGS_ERROR		0x109
#define H3_MISSING_SETTINGS		0x10a
#define H3_REQUEST_REJECTED		0x10b
#define H3_REQUEST_CANCELLED		0x10c
#define H3_REQUEST_INCOMPLETE		0x10d
#define H3_MESSAGE_ERROR		0x10e
#define H3_CONNECT_ERROR		0x10f
#define H3_VERSION_FALLBACK		0x110

/*
 * QPACK Error Codes (RFC 9204 Section 6)
 */
#define QPACK_DECOMPRESSION_FAILED	0x200
#define QPACK_ENCODER_STREAM_ERROR	0x201
#define QPACK_DECODER_STREAM_ERROR	0x202

/*
 * HTTP/3 Unidirectional Stream Types (RFC 9114 Section 6.2)
 */
#define H3_STREAM_TYPE_CONTROL		0x00
#define H3_STREAM_TYPE_PUSH		0x01
#define H3_STREAM_TYPE_QPACK_ENCODER	0x02
#define H3_STREAM_TYPE_QPACK_DECODER	0x03

/* Reserved stream types for GREASE (RFC 9114 Section 7.2.8) */
#define H3_STREAM_TYPE_RESERVED_MASK	0x1f
#define H3_STREAM_TYPE_IS_GREASE(t)	(((t) - 0x21) % 0x1f == 0)

/*
 * HTTP/3 Frame Types (RFC 9114 Section 7.2)
 */
#define H3_FRAME_DATA			0x00
#define H3_FRAME_HEADERS		0x01
#define H3_FRAME_CANCEL_PUSH		0x03
#define H3_FRAME_SETTINGS		0x04
#define H3_FRAME_PUSH_PROMISE		0x05
#define H3_FRAME_GOAWAY			0x07
#define H3_FRAME_MAX_PUSH_ID		0x0d

/*
 * HTTP/3 Settings Parameters (RFC 9114 Section 7.2.4.1)
 */
#define H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY	0x01
#define H3_SETTINGS_MAX_FIELD_SECTION_SIZE	0x06
#define H3_SETTINGS_QPACK_BLOCKED_STREAMS	0x07

/* Default settings values */
#define H3_DEFAULT_QPACK_MAX_TABLE_CAPACITY	0
#define H3_DEFAULT_MAX_FIELD_SECTION_SIZE	0  /* Unlimited */
#define H3_DEFAULT_QPACK_BLOCKED_STREAMS	0

/*
 * Request Stream States (RFC 9114 Section 4.1)
 *
 * State machine for HTTP/3 request streams:
 *   IDLE -> HEADERS_RECEIVED -> DATA -> TRAILERS -> COMPLETE
 *             |                  |
 *             +-> COMPLETE       +-> TRAILERS -> COMPLETE
 */
enum h3_request_state {
	H3_REQUEST_IDLE = 0,		/* Initial state */
	H3_REQUEST_HEADERS_RECEIVED,	/* Received HEADERS frame */
	H3_REQUEST_DATA,		/* Receiving DATA frames */
	H3_REQUEST_TRAILERS,		/* Received trailing HEADERS */
	H3_REQUEST_COMPLETE,		/* Request fully received */
	H3_REQUEST_ERROR,		/* Error state */
};

/*
 * Push Stream States (RFC 9114 Section 4.6)
 */
enum h3_push_state {
	H3_PUSH_IDLE = 0,
	H3_PUSH_PROMISED,		/* PUSH_PROMISE received */
	H3_PUSH_ACTIVE,			/* Push stream opened */
	H3_PUSH_CANCELLED,		/* Push cancelled */
	H3_PUSH_COMPLETE,		/* Push complete */
};

/**
 * struct h3_stream_type_info - Information about an HTTP/3 stream type
 * @type: Stream type value (0x00-0x03 or GREASE)
 * @is_critical: True if stream is critical (error on close)
 * @is_server_only: True if only server can initiate
 * @name: Human-readable name for debugging
 */
struct h3_stream_type_info {
	u64 type;
	bool is_critical;
	bool is_server_only;
	const char *name;
};

/**
 * struct h3_settings - HTTP/3 settings
 * @qpack_max_table_capacity: QPACK dynamic table capacity
 * @max_field_section_size: Maximum header field section size
 * @qpack_blocked_streams: Maximum blocked QPACK streams
 * @received: True if SETTINGS frame has been received
 */
struct h3_settings {
	u64 qpack_max_table_capacity;
	u64 max_field_section_size;
	u64 qpack_blocked_streams;
	bool received;
};

/**
 * struct h3_stream - HTTP/3 stream state
 * @base: Underlying QUIC stream
 * @type: HTTP/3 stream type (for unidirectional streams)
 * @request_state: Request state (for request streams)
 * @push_state: Push state (for push streams)
 * @push_id: Push ID (for push streams)
 * @is_request_stream: True if this is a request stream
 * @is_uni: True if unidirectional
 * @type_sent: True if stream type byte has been sent
 * @type_received: True if stream type byte has been received
 * @headers_sent: True if HEADERS frame has been sent
 * @headers_received: True if HEADERS frame has been received
 * @data_offset: Current data offset for DATA frames
 * @content_length: Expected content length (-1 if unknown)
 * @bytes_received: Total bytes received on this stream
 * @bytes_sent: Total bytes sent on this stream
 * @node: RB-tree node for connection's HTTP/3 stream tree
 * @list: List node for scheduling
 * @lock: Per-stream lock
 */
struct h3_stream {
	struct tquic_stream *base;

	/* Stream type (unidirectional streams only) */
	u64 type;

	/* State machines */
	enum h3_request_state request_state;
	enum h3_push_state push_state;
	u64 push_id;

	/* Flags */
	bool is_request_stream;
	bool is_uni;
	bool type_sent;
	bool type_received;
	bool headers_sent;
	bool headers_received;
	bool trailers_received;
	bool fin_received;
	bool fin_sent;

	/* Content tracking */
	u64 data_offset;
	s64 content_length;
	u64 bytes_received;
	u64 bytes_sent;

	/*
	 * RFC 9218 Extensible Priority
	 *
	 * Urgency (0-7): 0 is highest priority, 7 is lowest, default is 3
	 * Incremental: hint for interleaved delivery (default false)
	 */
	u8 priority_urgency;
	bool priority_incremental;
	bool priority_valid;		/* True if priority explicitly set */

	/* Tree linkage */
	struct rb_node node;
	struct list_head list;

	spinlock_t lock;
};

/**
 * struct h3_connection - HTTP/3 connection state
 * @conn: Underlying QUIC connection
 * @is_server: True if this is a server connection
 *
 * Control streams (RFC 9114 Section 6.2.1):
 * @local_control: Our control stream
 * @peer_control: Peer's control stream
 * @control_stream_opened: True if control stream has been opened
 * @peer_control_received: True if peer's control stream received
 *
 * QPACK streams (RFC 9114 Section 6.2.1):
 * @local_qpack_enc: Our QPACK encoder stream
 * @local_qpack_dec: Our QPACK decoder stream
 * @peer_qpack_enc: Peer's QPACK encoder stream
 * @peer_qpack_dec: Peer's QPACK decoder stream
 *
 * Settings:
 * @local_settings: Our settings
 * @peer_settings: Peer's settings
 *
 * Push handling:
 * @max_push_id: Maximum push ID we've advertised
 * @next_push_id: Next push ID to use (server only)
 * @push_enabled: True if push is enabled
 *
 * Stream management:
 * @streams: RB-tree of HTTP/3 streams
 * @stream_count: Number of active HTTP/3 streams
 *
 * Connection state:
 * @goaway_sent: True if GOAWAY has been sent
 * @goaway_received: True if GOAWAY has been received
 * @goaway_id: ID from GOAWAY frame
 * @error_code: Error code if connection is closing
 *
 * @lock: Connection lock
 */
struct h3_connection {
	struct tquic_connection *conn;
	bool is_server;

	/* Control stream (one per endpoint) */
	struct h3_stream *local_control;
	struct h3_stream *peer_control;
	bool control_stream_opened;
	bool peer_control_received;

	/* QPACK streams */
	struct h3_stream *local_qpack_enc;
	struct h3_stream *local_qpack_dec;
	struct h3_stream *peer_qpack_enc;
	struct h3_stream *peer_qpack_dec;

	/* Settings */
	struct h3_settings local_settings;
	struct h3_settings peer_settings;

	/* Push handling (RFC 9114 Section 4.6) */
	u64 max_push_id;
	u64 next_push_id;
	bool push_enabled;

	/* Stream management */
	struct rb_root streams;
	u32 stream_count;

	/* GOAWAY handling (RFC 9114 Section 5.2) */
	bool goaway_sent;
	bool goaway_received;
	u64 goaway_id;
	u64 error_code;

	spinlock_t lock;
};

/*
 * =============================================================================
 * Stream Type Validation and Classification
 * =============================================================================
 */

/**
 * h3_stream_id_is_client_initiated - Check if stream ID is client-initiated
 * @stream_id: QUIC stream ID
 *
 * Per RFC 9000 Section 2.1, client-initiated streams have even IDs.
 *
 * Return: true if client-initiated
 */
static inline bool h3_stream_id_is_client_initiated(u64 stream_id)
{
	return (stream_id & 0x01) == 0;
}

/**
 * h3_stream_id_is_server_initiated - Check if stream ID is server-initiated
 * @stream_id: QUIC stream ID
 *
 * Return: true if server-initiated
 */
static inline bool h3_stream_id_is_server_initiated(u64 stream_id)
{
	return (stream_id & 0x01) != 0;
}

/**
 * h3_stream_id_is_bidi - Check if stream ID is bidirectional
 * @stream_id: QUIC stream ID
 *
 * Per RFC 9000 Section 2.1, bidirectional streams have bit 1 = 0.
 *
 * Return: true if bidirectional
 */
static inline bool h3_stream_id_is_bidi(u64 stream_id)
{
	return (stream_id & 0x02) == 0;
}

/**
 * h3_stream_id_is_uni - Check if stream ID is unidirectional
 * @stream_id: QUIC stream ID
 *
 * Return: true if unidirectional
 */
static inline bool h3_stream_id_is_uni(u64 stream_id)
{
	return (stream_id & 0x02) != 0;
}

/**
 * h3_stream_id_is_request - Check if stream ID is a request stream
 * @stream_id: QUIC stream ID
 *
 * Request streams are client-initiated bidirectional streams.
 * Stream IDs: 0, 4, 8, 12, ...
 *
 * Return: true if this is a request stream
 */
static inline bool h3_stream_id_is_request(u64 stream_id)
{
	return h3_stream_id_is_bidi(stream_id) &&
	       h3_stream_id_is_client_initiated(stream_id);
}

/**
 * h3_validate_request_stream_id - Validate client-initiated bidi stream ID
 * @stream_id: QUIC stream ID
 * @is_server: True if we are the server
 *
 * Validates that the stream ID follows the expected sequence for
 * client-initiated bidirectional streams (0, 4, 8, 12, ...).
 *
 * Return: 0 on success, -errno on error
 */
static inline int h3_validate_request_stream_id(u64 stream_id, bool is_server)
{
	/* Request streams must be client-initiated bidirectional */
	if (!h3_stream_id_is_bidi(stream_id))
		return -EINVAL;

	if (!h3_stream_id_is_client_initiated(stream_id))
		return -EINVAL;

	/* Stream ID must be properly aligned (0, 4, 8, 12, ...) */
	if ((stream_id & 0x03) != 0x00)
		return -EINVAL;

	return 0;
}

/**
 * h3_stream_type_is_valid - Check if stream type is valid
 * @type: Stream type value
 *
 * Return: true if type is a known or reserved type
 */
static inline bool h3_stream_type_is_valid(u64 type)
{
	/* Known types */
	if (type <= H3_STREAM_TYPE_QPACK_DECODER)
		return true;

	/* GREASE values - must be ignored per RFC 9114 Section 7.2.8 */
	if (H3_STREAM_TYPE_IS_GREASE(type))
		return true;

	return false;
}

/**
 * h3_stream_type_is_critical - Check if stream type is critical
 * @type: Stream type value
 *
 * Critical streams must not be closed before connection close.
 * Closing a critical stream is a connection error (H3_CLOSED_CRITICAL_STREAM).
 *
 * Return: true if stream type is critical
 */
static inline bool h3_stream_type_is_critical(u64 type)
{
	return type == H3_STREAM_TYPE_CONTROL ||
	       type == H3_STREAM_TYPE_QPACK_ENCODER ||
	       type == H3_STREAM_TYPE_QPACK_DECODER;
}

/**
 * h3_stream_type_name - Get human-readable stream type name
 * @type: Stream type value
 *
 * Return: Stream type name string
 */
static inline const char *h3_stream_type_name(u64 type)
{
	switch (type) {
	case H3_STREAM_TYPE_CONTROL:
		return "Control";
	case H3_STREAM_TYPE_PUSH:
		return "Push";
	case H3_STREAM_TYPE_QPACK_ENCODER:
		return "QPACK Encoder";
	case H3_STREAM_TYPE_QPACK_DECODER:
		return "QPACK Decoder";
	default:
		if (H3_STREAM_TYPE_IS_GREASE(type))
			return "GREASE";
		return "Unknown";
	}
}

/*
 * =============================================================================
 * HTTP/3 Connection API
 * =============================================================================
 */

/* Connection lifecycle */
struct h3_connection *h3_connection_create(struct tquic_connection *conn,
					   bool is_server);
void h3_connection_destroy(struct h3_connection *h3conn);

/* Connection initialization */
int h3_connection_init(struct h3_connection *h3conn);
int h3_connection_open_control_streams(struct h3_connection *h3conn);

/* Settings management */
int h3_connection_set_settings(struct h3_connection *h3conn,
			       const struct h3_settings *settings);
int h3_connection_send_settings(struct h3_connection *h3conn);
int h3_connection_recv_settings(struct h3_connection *h3conn,
				const u8 *data, size_t len);

/* GOAWAY handling */
int h3_connection_send_goaway(struct h3_connection *h3conn, u64 stream_id);
int h3_connection_recv_goaway(struct h3_connection *h3conn, u64 stream_id);
bool h3_connection_is_going_away(struct h3_connection *h3conn);

/* Push ID handling */
int h3_connection_set_max_push_id(struct h3_connection *h3conn, u64 push_id);
int h3_connection_send_max_push_id(struct h3_connection *h3conn, u64 push_id);

/*
 * =============================================================================
 * HTTP/3 Stream API
 * =============================================================================
 */

/* Stream creation */
struct h3_stream *h3_stream_create_request(struct h3_connection *h3conn);
struct h3_stream *h3_stream_create_push(struct h3_connection *h3conn,
					u64 push_id);
struct h3_stream *h3_stream_accept(struct h3_connection *h3conn,
				   struct tquic_stream *base);

/* Stream type handling for unidirectional streams */
int h3_stream_send_type(struct h3_stream *h3s);
int h3_stream_recv_type(struct h3_stream *h3s, const u8 *data, size_t len,
			u64 *type_out);

/* Stream lookup */
struct h3_stream *h3_stream_lookup(struct h3_connection *h3conn, u64 stream_id);
struct h3_stream *h3_stream_lookup_by_push_id(struct h3_connection *h3conn,
					      u64 push_id);

/* Stream state transitions */
int h3_stream_transition_state(struct h3_stream *h3s,
			       enum h3_request_state new_state);

/* Stream close */
void h3_stream_close(struct h3_connection *h3conn, struct h3_stream *h3s);
int h3_stream_reset(struct h3_connection *h3conn, struct h3_stream *h3s,
		    u64 error_code);

/* Frame validation */
int h3_stream_validate_frame(struct h3_stream *h3s, u64 frame_type);

/*
 * =============================================================================
 * HTTP/3 Request Stream API
 * =============================================================================
 */

/* Request sending (client) */
int h3_request_send_headers(struct h3_stream *h3s, const void *headers,
			    size_t len);
int h3_request_send_data(struct h3_stream *h3s, const void *data, size_t len);
int h3_request_send_trailers(struct h3_stream *h3s, const void *trailers,
			     size_t len);
int h3_request_finish(struct h3_stream *h3s);

/* Response sending (server) */
int h3_response_send_headers(struct h3_stream *h3s, const void *headers,
			     size_t len);
int h3_response_send_data(struct h3_stream *h3s, const void *data, size_t len);
int h3_response_send_trailers(struct h3_stream *h3s, const void *trailers,
			      size_t len);
int h3_response_finish(struct h3_stream *h3s);

/* Receiving */
int h3_stream_recv_headers(struct h3_stream *h3s, void *buf, size_t len);
int h3_stream_recv_data(struct h3_stream *h3s, void *buf, size_t len);

/*
 * =============================================================================
 * Control Stream API
 * =============================================================================
 */

/* Control stream frame handling */
int h3_control_send_settings(struct h3_stream *h3s,
			     const struct h3_settings *settings);
int h3_control_send_goaway(struct h3_stream *h3s, u64 stream_id);
int h3_control_send_max_push_id(struct h3_stream *h3s, u64 push_id);

int h3_control_recv_frame(struct h3_stream *h3s, u64 frame_type,
			  const u8 *data, size_t len);

/*
 * =============================================================================
 * Push Stream API
 * =============================================================================
 */

/* Push promise (server only) */
int h3_push_promise_send(struct h3_stream *request_stream,
			 struct h3_stream *push_stream,
			 const void *headers, size_t len);

/* Push cancellation */
int h3_push_cancel(struct h3_connection *h3conn, u64 push_id);

/*
 * =============================================================================
 * Error Handling
 * =============================================================================
 */

/**
 * h3_error_name - Get human-readable error code name
 * @error_code: HTTP/3 error code
 *
 * Return: Error name string
 */
const char *h3_error_name(u64 error_code);

/**
 * h3_is_connection_error - Check if error is connection-level
 * @error_code: HTTP/3 error code
 *
 * Return: true if this error should close the connection
 */
bool h3_is_connection_error(u64 error_code);

/*
 * =============================================================================
 * Module API
 * =============================================================================
 */

int __init tquic_http3_init(void);
void __exit tquic_http3_exit(void);

#endif /* _TQUIC_HTTP3_STREAM_H */
