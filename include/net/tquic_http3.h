/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC HTTP/3 - Public API
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * This header provides the public HTTP/3 API for kernel consumers,
 * implementing RFC 9114 HTTP/3 over QUIC transport.
 *
 * HTTP/3 uses QUIC streams for multiplexing HTTP requests and responses.
 * It uses QPACK (RFC 9204) for header compression and defines specific
 * frame types for HTTP semantics carried over QUIC streams.
 */

#ifndef _NET_TQUIC_HTTP3_H
#define _NET_TQUIC_HTTP3_H

#include <linux/types.h>
#include <linux/errno.h>

/* Forward declarations */
struct tquic_connection;
struct tquic_stream;
struct tquic_http3_conn;

/*
 * =============================================================================
 * HTTP/3 Frame Types (RFC 9114 Section 7.2)
 * =============================================================================
 *
 * HTTP/3 frames are carried on QUIC streams. Each frame has the format:
 *   Frame Type (varint) || Frame Length (varint) || Frame Payload
 *
 * Note: Unlike QUIC frames, HTTP/3 frame types use varint encoding.
 */

/* HTTP/3 frame type values */
#define H3_FRAME_DATA			0x00
#define H3_FRAME_HEADERS		0x01
#define H3_FRAME_CANCEL_PUSH		0x03
#define H3_FRAME_SETTINGS		0x04
#define H3_FRAME_PUSH_PROMISE		0x05
#define H3_FRAME_GOAWAY			0x07
#define H3_FRAME_MAX_PUSH_ID		0x0d

/* RFC 9218: PRIORITY_UPDATE frame type */
#define TQUIC_H3_FRAME_PRIORITY_UPDATE	0x0f

/* Reserved frame types for GREASE (RFC 9114 Section 7.2.8) */
#define H3_FRAME_GREASE_MASK		0x1f
#define H3_FRAME_GREASE_BASE		0x21

/*
 * =============================================================================
 * HTTP/3 Settings (RFC 9114 Section 7.2.4.1)
 * =============================================================================
 *
 * Settings are conveyed in the SETTINGS frame on the control stream.
 * Each setting is a (identifier, value) pair using varint encoding.
 */

/* Settings identifier values */
#define H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY	0x01
#define H3_SETTINGS_MAX_FIELD_SECTION_SIZE	0x06
#define H3_SETTINGS_QPACK_BLOCKED_STREAMS	0x07

/* RFC 9218: Extensible Priorities setting */
#define TQUIC_H3_SETTINGS_ENABLE_PRIORITY	0x11

/* Default settings values */
#define H3_DEFAULT_QPACK_MAX_TABLE_CAPACITY	0
#define H3_DEFAULT_MAX_FIELD_SECTION_SIZE	(16 * 1024)
#define H3_DEFAULT_QPACK_BLOCKED_STREAMS	0

/* Maximum settings values */
#define H3_MAX_QPACK_TABLE_CAPACITY		(1ULL << 30)
#define H3_MAX_FIELD_SECTION_SIZE		(1ULL << 62)
#define H3_MAX_QPACK_BLOCKED_STREAMS		(1ULL << 16)
#define H3_MAX_SETTINGS_COUNT			256

/*
 * =============================================================================
 * HTTP/3 Error Codes (RFC 9114 Section 8.1)
 * =============================================================================
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
 * =============================================================================
 * HTTP/3 Stream Types (RFC 9114 Section 6)
 * =============================================================================
 *
 * HTTP/3 uses different unidirectional stream types:
 *   - Control stream (type 0x00): Carries SETTINGS and control frames
 *   - Push stream (type 0x01): Server push (if enabled)
 *   - QPACK encoder stream (type 0x02): QPACK dynamic table updates
 *   - QPACK decoder stream (type 0x03): QPACK acknowledgments
 */

#define H3_STREAM_TYPE_CONTROL		0x00
#define H3_STREAM_TYPE_PUSH		0x01
#define H3_STREAM_TYPE_QPACK_ENCODER	0x02
#define H3_STREAM_TYPE_QPACK_DECODER	0x03

/*
 * =============================================================================
 * HTTP/3 Extensible Priorities (RFC 9218)
 * =============================================================================
 */

/* Priority urgency range */
#define TQUIC_H3_PRIORITY_URGENCY_MIN		0
#define TQUIC_H3_PRIORITY_URGENCY_MAX		7
#define TQUIC_H3_PRIORITY_URGENCY_DEFAULT	3

/**
 * struct tquic_h3_priority - RFC 9218 priority parameters
 * @urgency: Urgency level (0-7, 0 = highest priority, default 3)
 * @incremental: Incremental delivery hint (default false)
 *
 * These parameters are used in the Priority header field and
 * PRIORITY_UPDATE frames per RFC 9218.
 */
struct tquic_h3_priority {
	u8 urgency;		/* 0-7, default 3 */
	bool incremental;	/* default false */
};

/**
 * struct tquic_h3_priority_update - PRIORITY_UPDATE frame (type 0x0f)
 * @element_id: Stream ID being updated
 * @priority: New priority parameters
 *
 * PRIORITY_UPDATE allows a client to update the priority of a request
 * stream after the initial request has been sent.
 */
struct tquic_h3_priority_update {
	u64 element_id;		/* Stream ID */
	struct tquic_h3_priority priority;
};

/*
 * =============================================================================
 * HTTP/3 Settings Structure
 * =============================================================================
 */

/**
 * struct tquic_h3_settings - HTTP/3 connection settings
 * @qpack_max_table_capacity: Max size of QPACK dynamic table (bytes)
 * @max_field_section_size: Max size of encoded header section (bytes)
 * @qpack_blocked_streams: Max streams that can be blocked by QPACK
 * @enable_priority: RFC 9218 extensible priorities enabled
 *
 * These settings are exchanged via SETTINGS frames on the control stream.
 * They apply to the connection and affect QPACK encoding/decoding limits.
 */
struct tquic_h3_settings {
	u64 qpack_max_table_capacity;
	u64 max_field_section_size;
	u64 qpack_blocked_streams;
	bool enable_priority;		/* RFC 9218 */
};

/*
 * =============================================================================
 * HTTP/3 Frame Structures
 * =============================================================================
 */

/**
 * struct tquic_h3_frame_data - DATA frame (0x00)
 * @data: Pointer to payload data
 * @len: Length of payload data
 *
 * DATA frames carry HTTP message body content. The frame payload
 * is the raw data without any additional framing.
 */
struct tquic_h3_frame_data {
	const u8 *data;
	u64 len;
};

/**
 * struct tquic_h3_frame_headers - HEADERS frame (0x01)
 * @data: QPACK-encoded header block
 * @len: Length of encoded block
 *
 * HEADERS frames carry HTTP header fields using QPACK compression.
 * The payload is the QPACK-encoded header section.
 */
struct tquic_h3_frame_headers {
	const u8 *data;
	u64 len;
};

/**
 * struct tquic_h3_frame_cancel_push - CANCEL_PUSH frame (0x03)
 * @push_id: Push ID being cancelled
 *
 * CANCEL_PUSH allows either endpoint to cancel a server push before
 * the PUSH_PROMISE is received or before push data is processed.
 */
struct tquic_h3_frame_cancel_push {
	u64 push_id;
};

/**
 * struct tquic_h3_frame_settings_entry - Single settings entry
 * @id: Settings identifier
 * @value: Settings value
 */
struct tquic_h3_frame_settings_entry {
	u64 id;
	u64 value;
};

/**
 * struct tquic_h3_frame_settings - SETTINGS frame (0x04)
 * @entries: Array of settings entries
 * @count: Number of entries
 *
 * SETTINGS frames convey configuration parameters. Must be sent
 * as the first frame on the control stream. Each identifier may
 * appear only once.
 */
struct tquic_h3_frame_settings {
	struct tquic_h3_frame_settings_entry *entries;
	u32 count;
};

/**
 * struct tquic_h3_frame_push_promise - PUSH_PROMISE frame (0x05)
 * @push_id: Unique push identifier
 * @data: QPACK-encoded request headers
 * @len: Length of encoded headers
 *
 * PUSH_PROMISE is sent on the request stream to notify the client
 * of an upcoming server push.
 */
struct tquic_h3_frame_push_promise {
	u64 push_id;
	const u8 *data;
	u64 len;
};

/**
 * struct tquic_h3_frame_goaway - GOAWAY frame (0x07)
 * @id: Stream ID (client) or Push ID (server)
 *
 * GOAWAY initiates graceful shutdown. Indicates the last processed
 * request/push, allowing in-flight requests to complete.
 */
struct tquic_h3_frame_goaway {
	u64 id;
};

/**
 * struct tquic_h3_frame_max_push_id - MAX_PUSH_ID frame (0x0d)
 * @push_id: Maximum push ID the server may use
 *
 * Client sends MAX_PUSH_ID to control server push. Server may not
 * initiate pushes with IDs greater than this value.
 */
struct tquic_h3_frame_max_push_id {
	u64 push_id;
};

/**
 * struct tquic_h3_frame - Generic HTTP/3 frame
 * @type: Frame type (H3_FRAME_*)
 * @raw_len: Total frame length on wire (including type and length fields)
 *
 * Union of all HTTP/3 frame types for generic handling.
 */
struct tquic_h3_frame {
	u64 type;
	u64 raw_len;
	union {
		struct tquic_h3_frame_data data;
		struct tquic_h3_frame_headers headers;
		struct tquic_h3_frame_cancel_push cancel_push;
		struct tquic_h3_frame_settings settings;
		struct tquic_h3_frame_push_promise push_promise;
		struct tquic_h3_frame_goaway goaway;
		struct tquic_h3_frame_max_push_id max_push_id;
	};
};

/*
 * =============================================================================
 * HTTP/3 Connection Structure
 * =============================================================================
 */

/**
 * enum tquic_h3_conn_state - HTTP/3 connection state
 * @H3_CONN_IDLE: Initial state
 * @H3_CONN_CONNECTING: Control streams being established
 * @H3_CONN_CONNECTED: Settings exchanged, connection ready
 * @H3_CONN_GOAWAY_SENT: GOAWAY sent, draining
 * @H3_CONN_GOAWAY_RECVD: GOAWAY received, draining
 * @H3_CONN_CLOSED: Connection closed
 */
enum tquic_h3_conn_state {
	H3_CONN_IDLE = 0,
	H3_CONN_CONNECTING,
	H3_CONN_CONNECTED,
	H3_CONN_GOAWAY_SENT,
	H3_CONN_GOAWAY_RECVD,
	H3_CONN_CLOSED,
};

/**
 * struct tquic_http3_conn - HTTP/3 connection state
 * @qconn: Underlying QUIC connection
 * @state: Connection state
 * @is_server: True if server-side connection
 * @local_settings: Settings we advertise
 * @peer_settings: Settings received from peer
 * @peer_settings_received: True after receiving peer's SETTINGS
 * @ctrl_stream_local: Local control stream
 * @ctrl_stream_remote: Remote control stream
 * @qpack_enc_stream: QPACK encoder stream
 * @qpack_dec_stream: QPACK decoder stream
 * @next_push_id: Next push ID to use (server only)
 * @max_push_id: Maximum push ID from client
 * @goaway_id: ID from GOAWAY frame
 * @lock: Connection lock
 * @refcnt: Reference counter
 *
 * Manages HTTP/3 protocol state layered on a QUIC connection.
 */
struct tquic_http3_conn {
	struct tquic_connection *qconn;
	enum tquic_h3_conn_state state;
	bool is_server;

	/* Settings */
	struct tquic_h3_settings local_settings;
	struct tquic_h3_settings peer_settings;
	bool peer_settings_received;

	/* Control streams (unidirectional) */
	struct tquic_stream *ctrl_stream_local;
	struct tquic_stream *ctrl_stream_remote;

	/* QPACK streams (unidirectional) */
	struct tquic_stream *qpack_enc_stream;
	struct tquic_stream *qpack_dec_stream;

	/* Server push state */
	u64 next_push_id;
	u64 max_push_id;
	bool push_enabled;

	/* GOAWAY state */
	u64 goaway_id;

	/* Synchronization */
	spinlock_t lock;
	refcount_t refcnt;
};

/*
 * =============================================================================
 * HTTP/3 Connection API
 * =============================================================================
 */

/**
 * tquic_h3_conn_create - Create HTTP/3 connection over QUIC
 * @qconn: Underlying QUIC connection (must be established)
 * @is_server: True if server-side
 * @settings: Local settings (or NULL for defaults)
 * @gfp: Memory allocation flags
 *
 * Creates an HTTP/3 connection and opens the required control streams.
 * The QUIC connection must be established before calling this.
 *
 * Returns: HTTP/3 connection on success, ERR_PTR on failure.
 */
struct tquic_http3_conn *tquic_h3_conn_create(struct tquic_connection *qconn,
					      bool is_server,
					      const struct tquic_h3_settings *settings,
					      gfp_t gfp);

/**
 * tquic_h3_conn_destroy - Destroy HTTP/3 connection
 * @h3conn: HTTP/3 connection to destroy
 *
 * Closes control streams and frees resources. Does not close the
 * underlying QUIC connection.
 */
void tquic_h3_conn_destroy(struct tquic_http3_conn *h3conn);

/**
 * tquic_h3_conn_get - Increment reference count
 * @h3conn: HTTP/3 connection
 */
static inline void tquic_h3_conn_get(struct tquic_http3_conn *h3conn)
{
	refcount_inc(&h3conn->refcnt);
}

/**
 * tquic_h3_conn_put - Decrement reference count
 * @h3conn: HTTP/3 connection
 *
 * When the reference count reaches zero, the connection is destroyed.
 */
void tquic_h3_conn_put(struct tquic_http3_conn *h3conn);

/**
 * tquic_h3_conn_poll - Process pending HTTP/3 events
 * @h3conn: HTTP/3 connection
 *
 * Processes data on control streams and handles incoming frames.
 * Should be called when data is available on the QUIC connection.
 *
 * Returns: 0 on success, negative error code on failure.
 */
int tquic_h3_conn_poll(struct tquic_http3_conn *h3conn);

/**
 * tquic_h3_send_goaway - Initiate graceful shutdown
 * @h3conn: HTTP/3 connection
 * @id: Last stream/push ID to process
 *
 * Sends a GOAWAY frame to initiate graceful shutdown.
 *
 * Returns: 0 on success, negative error code on failure.
 */
int tquic_h3_send_goaway(struct tquic_http3_conn *h3conn, u64 id);

/**
 * tquic_h3_set_max_push_id - Set maximum push ID (client only)
 * @h3conn: HTTP/3 connection
 * @push_id: Maximum push ID to allow
 *
 * Sends MAX_PUSH_ID frame to enable/control server push.
 *
 * Returns: 0 on success, negative error code on failure.
 */
int tquic_h3_set_max_push_id(struct tquic_http3_conn *h3conn, u64 push_id);

/*
 * =============================================================================
 * HTTP/3 Settings API
 * =============================================================================
 */

/**
 * tquic_h3_settings_init - Initialize settings to defaults
 * @settings: Settings structure to initialize
 */
void tquic_h3_settings_init(struct tquic_h3_settings *settings);

/**
 * tquic_h3_get_peer_settings - Get peer's settings
 * @h3conn: HTTP/3 connection
 * @settings: Output parameter for settings
 *
 * Returns: 0 on success, -EAGAIN if settings not yet received.
 */
int tquic_h3_get_peer_settings(struct tquic_http3_conn *h3conn,
			       struct tquic_h3_settings *settings);

/*
 * =============================================================================
 * HTTP/3 Frame API
 * =============================================================================
 */

/**
 * tquic_h3_parse_frame - Parse HTTP/3 frame from buffer
 * @buf: Input buffer
 * @len: Buffer length
 * @frame: Output frame structure
 * @entries_buf: Buffer for settings entries (if parsing SETTINGS)
 * @max_entries: Maximum entries in buffer
 *
 * Parses a single HTTP/3 frame from the buffer. For SETTINGS frames,
 * the entries are stored in entries_buf.
 *
 * Returns: Number of bytes consumed on success, negative error on failure.
 *   -EAGAIN: Need more data
 *   -EINVAL: Invalid frame format
 *   -H3_FRAME_ERROR: Protocol error
 */
int tquic_h3_parse_frame(const u8 *buf, size_t len,
			 struct tquic_h3_frame *frame,
			 struct tquic_h3_frame_settings_entry *entries_buf,
			 u32 max_entries);

/**
 * tquic_h3_frame_size - Calculate wire size of frame
 * @frame: Frame to calculate size for
 *
 * Returns: Wire size in bytes, or 0 on error.
 */
size_t tquic_h3_frame_size(const struct tquic_h3_frame *frame);

/**
 * tquic_h3_write_frame - Write HTTP/3 frame to buffer
 * @buf: Output buffer
 * @len: Buffer length
 * @frame: Frame to write
 *
 * Writes the frame including type and length fields.
 *
 * Returns: Number of bytes written on success, negative error on failure.
 *   -ENOSPC: Buffer too small
 *   -EINVAL: Invalid frame
 */
int tquic_h3_write_frame(u8 *buf, size_t len,
			 const struct tquic_h3_frame *frame);

/**
 * tquic_h3_send_frame - Send HTTP/3 frame on stream
 * @h3conn: HTTP/3 connection
 * @stream: QUIC stream to send on
 * @frame: Frame to send
 *
 * Convenience function to serialize and send a frame.
 *
 * Returns: 0 on success, negative error on failure.
 */
int tquic_h3_send_frame(struct tquic_http3_conn *h3conn,
			struct tquic_stream *stream,
			const struct tquic_h3_frame *frame);

/*
 * =============================================================================
 * HTTP/3 Frame Construction Helpers
 * =============================================================================
 */

/* Write individual frame types */
int tquic_h3_write_data_frame(u8 *buf, size_t len,
			      const u8 *data, u64 data_len);
int tquic_h3_write_headers_frame(u8 *buf, size_t len,
				 const u8 *data, u64 data_len);
int tquic_h3_write_cancel_push_frame(u8 *buf, size_t len, u64 push_id);
int tquic_h3_write_settings_frame(u8 *buf, size_t len,
				  const struct tquic_h3_settings *settings);
int tquic_h3_write_push_promise_frame(u8 *buf, size_t len,
				      u64 push_id,
				      const u8 *headers, u64 headers_len);
int tquic_h3_write_goaway_frame(u8 *buf, size_t len, u64 id);
int tquic_h3_write_max_push_id_frame(u8 *buf, size_t len, u64 push_id);

/* Calculate frame sizes */
size_t tquic_h3_data_frame_size(u64 data_len);
size_t tquic_h3_headers_frame_size(u64 headers_len);
size_t tquic_h3_cancel_push_frame_size(u64 push_id);
size_t tquic_h3_settings_frame_size(const struct tquic_h3_settings *settings);
size_t tquic_h3_push_promise_frame_size(u64 push_id, u64 headers_len);
size_t tquic_h3_goaway_frame_size(u64 id);
size_t tquic_h3_max_push_id_frame_size(u64 push_id);

/*
 * =============================================================================
 * HTTP/3 Utility Functions
 * =============================================================================
 */

/**
 * tquic_h3_frame_type_name - Get human-readable frame type name
 * @type: Frame type value
 *
 * Returns: Static string name, or "UNKNOWN" for unknown types.
 */
const char *tquic_h3_frame_type_name(u64 type);

/**
 * tquic_h3_error_name - Get human-readable error name
 * @error: Error code value
 *
 * Returns: Static string name, or "UNKNOWN" for unknown errors.
 */
const char *tquic_h3_error_name(u64 error);

/**
 * tquic_h3_is_grease_id - Check if value is a GREASE identifier
 * @id: Value to check
 *
 * GREASE identifiers follow the pattern 0x1f * N + 0x21.
 *
 * Returns: True if id is a GREASE value.
 */
static inline bool tquic_h3_is_grease_id(u64 id)
{
	return ((id - 0x21) % 0x1f) == 0;
}

/*
 * =============================================================================
 * HTTP/3 Extensible Priorities API (RFC 9218)
 * =============================================================================
 */

/* Forward declaration for stream type */
struct tquic_h3_stream;

/**
 * tquic_h3_send_priority_update - Send PRIORITY_UPDATE frame
 * @conn: HTTP/3 connection
 * @stream_id: Stream ID to update priority for
 * @pri: New priority parameters
 *
 * Sends a PRIORITY_UPDATE frame (type 0x0f) on the control stream
 * to update the priority of the specified request stream.
 *
 * Returns: 0 on success, negative error code on failure
 */
int tquic_h3_send_priority_update(struct tquic_http3_conn *conn,
				  u64 stream_id,
				  const struct tquic_h3_priority *pri);

/**
 * tquic_h3_handle_priority_update - Handle received PRIORITY_UPDATE frame
 * @conn: HTTP/3 connection
 * @data: Frame payload (after frame type and length)
 * @len: Payload length
 *
 * Processes a PRIORITY_UPDATE frame received from the peer.
 *
 * Returns: 0 on success, negative error code on failure
 */
int tquic_h3_handle_priority_update(struct tquic_http3_conn *conn,
				    const u8 *data, size_t len);

/**
 * tquic_h3_parse_priority_header - Parse "Priority: u=X, i" header
 * @value: Header field value string
 * @len: Value length
 * @pri: Output priority parameters
 *
 * Parses the Priority header field from an HTTP request/response
 * per RFC 9218 Section 4 (Structured Field Dictionary format).
 *
 * Examples:
 *   "u=2, i"  -> urgency=2, incremental=true
 *   "u=5"     -> urgency=5, incremental=false
 *   "i"       -> urgency=3 (default), incremental=true
 *
 * Returns: 0 on success, negative error code on invalid format
 */
int tquic_h3_parse_priority_header(const char *value, size_t len,
				   struct tquic_h3_priority *pri);

/**
 * tquic_h3_format_priority_header - Format priority as header value
 * @pri: Priority parameters to format
 * @buf: Output buffer
 * @len: Buffer size
 *
 * Formats priority parameters as a Priority header field value.
 *
 * Returns: Number of bytes written on success, negative error on failure
 */
int tquic_h3_format_priority_header(const struct tquic_h3_priority *pri,
				    char *buf, size_t len);

/**
 * tquic_h3_priority_next - Get next stream to send based on priority
 * @conn: HTTP/3 connection
 *
 * Returns the highest priority stream that has data ready to send.
 * Scheduling uses urgency-based buckets with round-robin for
 * incremental streams at the same urgency level.
 *
 * Returns: Pointer to next stream, or NULL if none ready
 */
struct tquic_h3_stream *tquic_h3_priority_next(struct tquic_http3_conn *conn);

/**
 * tquic_h3_stream_set_priority - Update stream priority
 * @stream: HTTP/3 stream
 * @pri: New priority parameters
 *
 * Updates the priority for a stream. This affects scheduling order.
 */
void tquic_h3_stream_set_priority(struct tquic_h3_stream *stream,
				  const struct tquic_h3_priority *pri);

/**
 * tquic_h3_stream_get_priority - Get current stream priority
 * @stream: HTTP/3 stream
 * @pri: Output priority parameters
 *
 * Returns: 0 on success, negative error code on failure
 */
int tquic_h3_stream_get_priority(struct tquic_h3_stream *stream,
				 struct tquic_h3_priority *pri);

/**
 * tquic_h3_priority_init - Initialize priority to defaults
 * @pri: Priority structure to initialize
 *
 * Sets urgency=3 and incremental=false per RFC 9218.
 */
static inline void tquic_h3_priority_init(struct tquic_h3_priority *pri)
{
	pri->urgency = TQUIC_H3_PRIORITY_URGENCY_DEFAULT;
	pri->incremental = false;
}

/*
 * =============================================================================
 * HTTP/3 Module Init/Exit
 * =============================================================================
 */

int __init tquic_http3_init(void);
void __exit tquic_http3_exit(void);

#endif /* _NET_TQUIC_HTTP3_H */
