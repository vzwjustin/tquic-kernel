/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC WebTransport Support (RFC 9220)
 *
 * Copyright (c) 2026 Linux Foundation
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

/* Capsule types (RFC 9220 Section 4.5) */
#define WEBTRANSPORT_CAPSULE_CLOSE_SESSION	0x2843
#define WEBTRANSPORT_CAPSULE_DRAIN_SESSION	0x78ae

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

	/* Datagrams */
	bool datagrams_enabled;

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
 * struct webtransport_context - WebTransport context for a connection
 * @h3conn: Parent HTTP/3 connection
 * @enabled: WebTransport is enabled (SETTINGS received)
 * @sessions: RB-tree of all sessions
 * @session_list: List of sessions for iteration
 * @session_count: Number of active sessions
 * @lock: Spinlock protecting context
 */
struct webtransport_context {
	struct tquic_http3_conn *h3conn;
	bool enabled;
	struct rb_root sessions;
	struct list_head session_list;
	u32 session_count;
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

#endif /* _TQUIC_WEBTRANSPORT_H */
