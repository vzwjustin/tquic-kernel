/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC WebTransport Support (RFC 9220)
 *
 * Copyright (c) 2026 Linux Foundation
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * WebTransport enables bidirectional stream-based communication over HTTP/3.
 * It uses CONNECT requests with the :protocol pseudo-header set to "webtransport"
 * to establish a WebTransport session.
 *
 * Key features:
 * - Bidirectional and unidirectional streams
 * - Unreliable datagrams (RFC 9297)
 * - Session-level flow control
 * - Graceful session close
 */

#ifndef _TQUIC_WEBTRANSPORT_H
#define _TQUIC_WEBTRANSPORT_H

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/rbtree.h>
#include <net/tquic.h>
#include <net/tquic_http3.h>

/*
 * =============================================================================
 * WebTransport Constants (RFC 9220)
 * =============================================================================
 */

/* SETTINGS parameter for WebTransport */
#define WEBTRANSPORT_SETTINGS_ENABLE		0x2b603742ULL

/* Extended CONNECT protocol name */
#define WEBTRANSPORT_PROTOCOL			"webtransport"

/* Stream type prefixes (RFC 9220 Section 5.1) */
#define WEBTRANSPORT_STREAM_UNI			0x54
#define WEBTRANSPORT_STREAM_BIDI		0x41

/* Capsule types (RFC 9297 Capsule Protocol and RFC 9220 Section 4.5) */
#define CAPSULE_DATAGRAM			0x00
#define CAPSULE_REGISTER_DATAGRAM_CONTEXT	0x01
#define CAPSULE_CLOSE_DATAGRAM_CONTEXT		0x02
#define WEBTRANSPORT_CAPSULE_CLOSE_SESSION	0x2843
#define WEBTRANSPORT_CAPSULE_DRAIN_SESSION	0x78ae

/* WebTransport stream capsule types (draft-ietf-webtrans-http3) */
#define WT_CAPSULE_STREAM			0x190b4d38
#define WT_CAPSULE_STREAM_FIN			0x190b4d39
#define WT_CAPSULE_DATAGRAM			0x190b4d3a

/* WebTransport flow control capsule types */
#define WT_CAPSULE_MAX_DATA			0x190b4d3b
#define WT_CAPSULE_MAX_STREAMS_BIDI		0x190b4d3c
#define WT_CAPSULE_MAX_STREAMS_UNIDI		0x190b4d3d
#define WT_CAPSULE_DATA_BLOCKED			0x190b4d3e
#define WT_CAPSULE_STREAMS_BLOCKED_BIDI		0x190b4d3f
#define WT_CAPSULE_STREAMS_BLOCKED_UNIDI	0x190b4d40
#define WT_CAPSULE_STREAM_DATA_BLOCKED		0x190b4d41
#define WT_CAPSULE_RESET_STREAM			0x190b4d42
#define WT_CAPSULE_STOP_SENDING			0x190b4d43

/* Error codes (RFC 9220 Section 4.6) */
#define WEBTRANSPORT_ERROR_NO_ERROR			0x00
#define WEBTRANSPORT_ERROR_SESSION_GONE			0x01
#define WEBTRANSPORT_ERROR_BUFFERED_STREAM_REJECTED	0x52e4a40fa8db
#define WEBTRANSPORT_ERROR_SESSION_CLOSED		0x52e4a40fa8dc

/* Maximum URL length */
#define WEBTRANSPORT_MAX_URL_LEN		8192

/* Maximum number of sessions per connection */
#define WEBTRANSPORT_MAX_SESSIONS		256

/*
 * =============================================================================
 * WebTransport Structures
 * =============================================================================
 */

/**
 * enum webtransport_session_state - Session state machine
 * @WT_SESSION_CONNECTING: CONNECT request sent, waiting for response
 * @WT_SESSION_OPEN: Session established, streams can be opened
 * @WT_SESSION_DRAINING: DRAIN capsule sent/received, no new streams
 * @WT_SESSION_CLOSING: CLOSE capsule sent, waiting for FIN
 * @WT_SESSION_CLOSED: Session fully closed
 */
enum webtransport_session_state {
	WT_SESSION_CONNECTING,
	WT_SESSION_OPEN,
	WT_SESSION_DRAINING,
	WT_SESSION_CLOSING,
	WT_SESSION_CLOSED,
};

/**
 * struct webtransport_session - WebTransport session state
 * @session_id: Stream ID of the CONNECT request (session stream)
 * @state: Current session state
 * @h3conn: Parent HTTP/3 connection
 * @session_stream: The bidirectional stream carrying the session
 * @url: Session URL (dynamically allocated)
 * @url_len: Length of URL
 * @close_code: Application error code for session close
 * @close_msg: Application close message (dynamically allocated)
 * @close_msg_len: Length of close message
 * @streams: RB-tree of streams belonging to this session
 * @stream_count: Number of open streams
 * @datagrams_enabled: Whether HTTP Datagrams are enabled
 * @tree_node: RB-tree node for session lookup
 * @list: List node for iteration
 * @lock: Spinlock protecting session state
 * @refcnt: Reference count
 */
struct webtransport_session {
	u64 session_id;
	enum webtransport_session_state state;
	struct tquic_http3_conn *h3conn;
	struct tquic_stream *session_stream;
	struct webtransport_context *ctx;

	/* URL */
	char *url;
	size_t url_len;

	/* Close info */
	u32 close_code;
	char *close_msg;
	size_t close_msg_len;

	/* Streams */
	struct rb_root streams;
	u32 stream_count;
	u32 max_streams_bidi;
	u32 max_streams_uni;

	/* Flow control (session-level) */
	struct wt_flow_control flow;

	/* Datagrams */
	bool datagrams_enabled;
	struct webtransport_datagram_queue dgram_recv_queue;
	u64 dgram_context_id;

	/* Capsule parsing state */
	u8 *capsule_buf;
	size_t capsule_buf_len;
	size_t capsule_buf_used;
	bool capsule_header_complete;
	u64 capsule_type;
	u64 capsule_length;

	/* Lookup and management */
	struct rb_node tree_node;
	struct list_head list;

	/* Synchronization */
	spinlock_t lock;
	refcount_t refcnt;
};

/**
 * struct webtransport_stream - Stream within a WebTransport session
 * @stream_id: QUIC stream ID
 * @session: Parent session
 * @quic_stream: Underlying QUIC stream
 * @is_bidirectional: True for bidirectional, false for unidirectional
 * @is_incoming: True if opened by peer
 * @tree_node: RB-tree node for stream lookup
 */
struct webtransport_stream {
	u64 stream_id;
	struct webtransport_session *session;
	struct tquic_stream *quic_stream;
	bool is_bidirectional;
	bool is_incoming;
	struct rb_node tree_node;
};

/**
 * struct wt_capsule - Generic capsule structure (RFC 9297)
 * @type: Capsule type (varint encoded on wire)
 * @length: Payload length
 * @payload: Pointer to payload data
 */
struct wt_capsule {
	u64 type;
	u64 length;
	const u8 *payload;
};

/**
 * struct wt_capsule_close_session - CLOSE_WEBTRANSPORT_SESSION capsule
 * @error_code: Application error code (32-bit)
 * @reason: Close reason string (optional)
 * @reason_len: Length of reason string
 */
struct wt_capsule_close_session {
	u32 error_code;
	char *reason;
	size_t reason_len;
};

/**
 * struct wt_capsule_datagram - WT_DATAGRAM capsule payload
 * @context_id: Datagram context identifier (quarter stream ID)
 * @data: Datagram payload
 * @data_len: Payload length
 */
struct wt_capsule_datagram {
	u64 context_id;
	const u8 *data;
	size_t data_len;
};

/**
 * struct wt_capsule_stream - WT_STREAM capsule payload
 * @stream_id: WebTransport stream ID
 * @fin: Final frame indicator
 * @data: Stream data
 * @data_len: Data length
 */
struct wt_capsule_stream {
	u64 stream_id;
	bool fin;
	const u8 *data;
	size_t data_len;
};

/**
 * struct wt_flow_control - Session-level flow control state
 * @max_data_local: Maximum data we allow peer to send
 * @max_data_remote: Maximum data peer allows us to send
 * @data_sent: Total data sent on session
 * @data_recv: Total data received on session
 * @max_streams_bidi_local: Max bidi streams we allow
 * @max_streams_bidi_remote: Max bidi streams peer allows
 * @max_streams_uni_local: Max unidi streams we allow
 * @max_streams_uni_remote: Max unidi streams peer allows
 * @streams_bidi_opened: Bidi streams opened
 * @streams_uni_opened: Unidi streams opened
 * @blocked_on_data: True if blocked on session data limit
 * @blocked_on_bidi: True if blocked on bidi stream limit
 * @blocked_on_uni: True if blocked on unidi stream limit
 */
struct wt_flow_control {
	u64 max_data_local;
	u64 max_data_remote;
	u64 data_sent;
	u64 data_recv;

	u64 max_streams_bidi_local;
	u64 max_streams_bidi_remote;
	u64 max_streams_uni_local;
	u64 max_streams_uni_remote;

	u64 streams_bidi_opened;
	u64 streams_uni_opened;

	bool blocked_on_data;
	bool blocked_on_bidi;
	bool blocked_on_uni;
};

/**
 * struct webtransport_datagram_queue - Datagram receive queue
 * @head: Head of datagram list
 * @tail: Tail of datagram list
 * @count: Number of datagrams in queue
 * @max_count: Maximum queue length
 * @total_bytes: Total bytes in queue
 * @max_bytes: Maximum bytes allowed
 * @lock: Spinlock protecting queue
 */
struct webtransport_datagram_queue {
	struct list_head datagrams;
	u32 count;
	u32 max_count;
	u64 total_bytes;
	u64 max_bytes;
	spinlock_t lock;
};

/**
 * struct webtransport_datagram - Single datagram in queue
 * @data: Datagram payload
 * @len: Payload length
 * @list: List linkage
 */
struct webtransport_datagram {
	u8 *data;
	size_t len;
	struct list_head list;
};

/**
 * struct webtransport_context - WebTransport context for a connection
 * @h3conn: Parent HTTP/3 connection
 * @enabled: WebTransport is enabled (SETTINGS received)
 * @sessions: RB-tree of all sessions
 * @session_list: List of sessions for iteration
 * @session_count: Number of active sessions
 * @max_sessions: Maximum allowed sessions
 * @settings_sent: True if we sent SETTINGS_ENABLE_WEBTRANSPORT
 * @settings_received: True if peer sent SETTINGS_ENABLE_WEBTRANSPORT
 * @lock: Spinlock protecting context
 */
struct webtransport_context {
	struct tquic_http3_conn *h3conn;
	bool enabled;
	struct rb_root sessions;
	struct list_head session_list;
	u32 session_count;
	u32 max_sessions;
	bool settings_sent;
	bool settings_received;
	spinlock_t lock;
};

/*
 * =============================================================================
 * WebTransport API
 * =============================================================================
 */

/**
 * webtransport_init - Initialize WebTransport module
 *
 * Returns: 0 on success, negative error on failure
 */
int webtransport_init(void);

/**
 * webtransport_exit - Cleanup WebTransport module
 */
void webtransport_exit(void);

/**
 * webtransport_context_create - Create WebTransport context for connection
 * @h3conn: HTTP/3 connection
 * @gfp: Allocation flags
 *
 * Returns: Pointer to context, or ERR_PTR on failure
 */
struct webtransport_context *webtransport_context_create(
	struct tquic_http3_conn *h3conn, gfp_t gfp);

/**
 * webtransport_context_destroy - Destroy WebTransport context
 * @ctx: Context to destroy
 */
void webtransport_context_destroy(struct webtransport_context *ctx);

/**
 * webtransport_connect - Open a new WebTransport session (client)
 * @ctx: WebTransport context
 * @url: Session URL
 * @url_len: URL length
 *
 * Sends an extended CONNECT request to establish a session.
 *
 * Returns: Session on success, ERR_PTR on failure
 */
struct webtransport_session *webtransport_connect(
	struct webtransport_context *ctx,
	const char *url, size_t url_len);

/**
 * webtransport_accept - Accept incoming WebTransport session (server)
 * @ctx: WebTransport context
 * @stream_id: Stream ID of CONNECT request
 * @headers: Request headers
 *
 * Returns: Session on success, ERR_PTR on failure
 */
struct webtransport_session *webtransport_accept(
	struct webtransport_context *ctx,
	u64 stream_id,
	const struct qpack_header_list *headers);

/**
 * webtransport_session_close - Close a WebTransport session
 * @session: Session to close
 * @code: Application error code
 * @msg: Close message (may be NULL)
 * @msg_len: Message length
 *
 * Sends a CLOSE_WEBTRANSPORT_SESSION capsule.
 *
 * Returns: 0 on success, negative error on failure
 */
int webtransport_session_close(struct webtransport_session *session,
			       u32 code, const char *msg, size_t msg_len);

/**
 * webtransport_open_stream - Open a new stream in session
 * @session: WebTransport session
 * @bidirectional: True for bidirectional stream
 *
 * Returns: Stream on success, ERR_PTR on failure
 */
struct webtransport_stream *webtransport_open_stream(
	struct webtransport_session *session, bool bidirectional);

/**
 * webtransport_stream_send - Send data on a stream
 * @stream: WebTransport stream
 * @data: Data to send
 * @len: Data length
 * @fin: True to send FIN
 *
 * Returns: Number of bytes sent, or negative error
 */
ssize_t webtransport_stream_send(struct webtransport_stream *stream,
				 const void *data, size_t len, bool fin);

/**
 * webtransport_stream_recv - Receive data from a stream
 * @stream: WebTransport stream
 * @buf: Buffer for received data
 * @len: Buffer length
 * @fin: Output: true if FIN received
 *
 * Returns: Number of bytes received, or negative error
 */
ssize_t webtransport_stream_recv(struct webtransport_stream *stream,
				 void *buf, size_t len, bool *fin);

/**
 * webtransport_send_datagram - Send a datagram
 * @session: WebTransport session
 * @data: Datagram payload
 * @len: Payload length
 *
 * Returns: 0 on success, negative error on failure
 */
int webtransport_send_datagram(struct webtransport_session *session,
			       const void *data, size_t len);

/**
 * webtransport_recv_datagram - Receive a datagram
 * @session: WebTransport session
 * @buf: Buffer for datagram
 * @len: Buffer length
 *
 * Returns: Number of bytes received, -EAGAIN if none available
 */
ssize_t webtransport_recv_datagram(struct webtransport_session *session,
				   void *buf, size_t len);

/**
 * webtransport_handle_settings - Process SETTINGS_ENABLE_WEBTRANSPORT
 * @ctx: WebTransport context
 * @enabled: Value from SETTINGS
 *
 * Returns: 0 on success, negative error on failure
 */
int webtransport_handle_settings(struct webtransport_context *ctx,
				 bool enabled);

/**
 * webtransport_handle_stream - Handle incoming WebTransport stream
 * @ctx: WebTransport context
 * @stream_id: QUIC stream ID
 * @data: Initial data on stream (stream type byte)
 * @len: Data length
 *
 * Returns: 0 on success, negative error on failure
 */
int webtransport_handle_stream(struct webtransport_context *ctx,
			       u64 stream_id, const u8 *data, size_t len);

/*
 * =============================================================================
 * Capsule Protocol API (RFC 9297)
 * =============================================================================
 */

/**
 * wt_capsule_encode - Encode a capsule to buffer
 * @type: Capsule type
 * @payload: Payload data
 * @payload_len: Payload length
 * @buf: Output buffer
 * @buf_len: Buffer size
 *
 * Returns: Number of bytes written, or negative error
 */
int wt_capsule_encode(u64 type, const void *payload, size_t payload_len,
		      u8 *buf, size_t buf_len);

/**
 * wt_capsule_decode - Decode a capsule from buffer
 * @buf: Input buffer
 * @buf_len: Buffer length
 * @capsule: Output capsule structure
 * @consumed: Bytes consumed from buffer
 *
 * Returns: 0 on success, -EAGAIN if need more data, negative error otherwise
 */
int wt_capsule_decode(const u8 *buf, size_t buf_len,
		      struct wt_capsule *capsule, size_t *consumed);

/**
 * wt_capsule_header_size - Calculate capsule header size
 * @type: Capsule type
 * @payload_len: Payload length
 *
 * Returns: Header size in bytes
 */
size_t wt_capsule_header_size(u64 type, size_t payload_len);

/**
 * wt_send_close_session_capsule - Send CLOSE_WEBTRANSPORT_SESSION capsule
 * @session: Session to close
 * @error_code: Application error code
 * @reason: Close reason (may be NULL)
 * @reason_len: Reason length
 *
 * Returns: 0 on success, negative error on failure
 */
int wt_send_close_session_capsule(struct webtransport_session *session,
				  u32 error_code, const char *reason,
				  size_t reason_len);

/**
 * wt_send_drain_session_capsule - Send DRAIN_WEBTRANSPORT_SESSION capsule
 * @session: Session to drain
 *
 * Returns: 0 on success, negative error on failure
 */
int wt_send_drain_session_capsule(struct webtransport_session *session);

/**
 * wt_handle_capsule - Handle received capsule
 * @session: WebTransport session
 * @capsule: Decoded capsule
 *
 * Returns: 0 on success, negative error on failure
 */
int wt_handle_capsule(struct webtransport_session *session,
		      const struct wt_capsule *capsule);

/*
 * =============================================================================
 * Flow Control Capsules API
 * =============================================================================
 */

/**
 * wt_send_max_data - Send WT_MAX_DATA capsule
 * @session: WebTransport session
 * @max_data: New maximum data limit
 *
 * Returns: 0 on success, negative error on failure
 */
int wt_send_max_data(struct webtransport_session *session, u64 max_data);

/**
 * wt_send_max_streams - Send WT_MAX_STREAMS_BIDI or WT_MAX_STREAMS_UNIDI capsule
 * @session: WebTransport session
 * @max_streams: New maximum stream count
 * @bidirectional: True for bidi, false for unidi
 *
 * Returns: 0 on success, negative error on failure
 */
int wt_send_max_streams(struct webtransport_session *session,
			u64 max_streams, bool bidirectional);

/**
 * wt_send_data_blocked - Send WT_DATA_BLOCKED capsule
 * @session: WebTransport session
 * @limit: The data limit we are blocked at
 *
 * Returns: 0 on success, negative error on failure
 */
int wt_send_data_blocked(struct webtransport_session *session, u64 limit);

/**
 * wt_send_streams_blocked - Send WT_STREAMS_BLOCKED capsule
 * @session: WebTransport session
 * @limit: The stream limit we are blocked at
 * @bidirectional: True for bidi, false for unidi
 *
 * Returns: 0 on success, negative error on failure
 */
int wt_send_streams_blocked(struct webtransport_session *session,
			    u64 limit, bool bidirectional);

/**
 * wt_send_stream_data_blocked - Send WT_STREAM_DATA_BLOCKED capsule
 * @stream: WebTransport stream
 * @limit: The stream data limit we are blocked at
 *
 * Returns: 0 on success, negative error on failure
 */
int wt_send_stream_data_blocked(struct webtransport_stream *stream, u64 limit);

/**
 * wt_send_reset_stream - Send WT_RESET_STREAM capsule
 * @stream: WebTransport stream
 * @error_code: Application error code
 *
 * Returns: 0 on success, negative error on failure
 */
int wt_send_reset_stream(struct webtransport_stream *stream, u64 error_code);

/**
 * wt_send_stop_sending - Send WT_STOP_SENDING capsule
 * @stream: WebTransport stream
 * @error_code: Application error code
 *
 * Returns: 0 on success, negative error on failure
 */
int wt_send_stop_sending(struct webtransport_stream *stream, u64 error_code);

/*
 * =============================================================================
 * Extended CONNECT Validation
 * =============================================================================
 */

/**
 * wt_validate_connect_request - Validate Extended CONNECT request for WebTransport
 * @headers: Request headers
 *
 * Validates that the headers contain:
 *   - :method = CONNECT
 *   - :protocol = webtransport
 *   - :scheme (must be https)
 *   - :authority and :path
 *
 * Returns: 0 if valid, negative error code if invalid
 */
int wt_validate_connect_request(const struct qpack_header_list *headers);

/**
 * wt_validate_connect_response - Validate Extended CONNECT response
 * @headers: Response headers
 *
 * Validates that the response is 200 OK.
 *
 * Returns: 0 if valid, negative error code if invalid
 */
int wt_validate_connect_response(const struct qpack_header_list *headers);

/*
 * =============================================================================
 * Datagram Queue Operations
 * =============================================================================
 */

/**
 * wt_datagram_queue_init - Initialize datagram receive queue
 * @queue: Queue to initialize
 * @max_count: Maximum datagrams to queue
 * @max_bytes: Maximum bytes to queue
 */
void wt_datagram_queue_init(struct webtransport_datagram_queue *queue,
			    u32 max_count, u64 max_bytes);

/**
 * wt_datagram_queue_destroy - Free all datagrams and cleanup queue
 * @queue: Queue to destroy
 */
void wt_datagram_queue_destroy(struct webtransport_datagram_queue *queue);

/**
 * wt_datagram_queue_push - Add datagram to queue
 * @queue: Target queue
 * @data: Datagram data
 * @len: Data length
 * @gfp: Allocation flags
 *
 * Returns: 0 on success, -ENOSPC if queue full, -ENOMEM on alloc failure
 */
int wt_datagram_queue_push(struct webtransport_datagram_queue *queue,
			   const void *data, size_t len, gfp_t gfp);

/**
 * wt_datagram_queue_pop - Remove and return next datagram from queue
 * @queue: Source queue
 * @buf: Output buffer
 * @buf_len: Buffer size
 *
 * Returns: Number of bytes copied, or -EAGAIN if queue empty
 */
ssize_t wt_datagram_queue_pop(struct webtransport_datagram_queue *queue,
			      void *buf, size_t buf_len);

/*
 * =============================================================================
 * Session Helpers
 * =============================================================================
 */

/**
 * webtransport_session_get - Increment session reference count
 * @session: Session to reference
 */
static inline void webtransport_session_get(struct webtransport_session *session)
{
	if (session)
		refcount_inc(&session->refcnt);
}

/**
 * webtransport_session_put - Decrement session reference count
 * @session: Session to dereference
 *
 * When count reaches 0, session is freed.
 */
void webtransport_session_put(struct webtransport_session *session);

/**
 * webtransport_session_find - Find session by ID
 * @ctx: WebTransport context
 * @session_id: Session stream ID
 *
 * Returns: Session with incremented refcount, or NULL
 */
struct webtransport_session *webtransport_session_find(
	struct webtransport_context *ctx, u64 session_id);

/*
 * =============================================================================
 * Flow Control Helpers
 * =============================================================================
 */

/**
 * wt_flow_control_init - Initialize flow control state for session
 * @flow: Flow control structure to initialize
 */
void wt_flow_control_init(struct wt_flow_control *flow);

/**
 * wt_can_send_data - Check if session can send more data
 * @session: WebTransport session
 * @len: Number of bytes to send
 *
 * Returns: true if data can be sent, false otherwise
 */
bool wt_can_send_data(struct webtransport_session *session, size_t len);

/**
 * wt_can_open_stream - Check if session can open another stream
 * @session: WebTransport session
 * @bidirectional: True for bidi, false for unidi
 *
 * Returns: true if stream can be opened, false otherwise
 */
bool wt_can_open_stream(struct webtransport_session *session, bool bidirectional);

/*
 * =============================================================================
 * Session Stream Processing
 * =============================================================================
 */

/**
 * wt_process_session_stream_data - Process data on session stream
 * @session: WebTransport session
 * @data: Data received
 * @len: Data length
 *
 * Called when data arrives on the session CONNECT stream. Parses capsules
 * and dispatches them to appropriate handlers.
 *
 * Returns: 0 on success, negative error on failure
 */
int wt_process_session_stream_data(struct webtransport_session *session,
				   const u8 *data, size_t len);

/**
 * wt_handle_incoming_datagram - Handle incoming QUIC datagram for WebTransport
 * @ctx: WebTransport context
 * @data: Datagram data (including quarter stream ID header)
 * @len: Data length
 *
 * Called when a QUIC DATAGRAM frame is received. Demultiplexes the datagram
 * to the appropriate WebTransport session based on Quarter Stream ID.
 *
 * Returns: 0 on success, negative error on failure
 */
int wt_handle_incoming_datagram(struct webtransport_context *ctx,
				const u8 *data, size_t len);

#endif /* _TQUIC_WEBTRANSPORT_H */
