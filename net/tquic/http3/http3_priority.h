/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC HTTP/3 Extensible Priorities (RFC 9218)
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * This header provides HTTP/3 Extensible Priorities support per RFC 9218.
 * The priority scheme uses:
 * - Urgency (u): 0-7, where 0 is highest priority, 7 is lowest (default: 3)
 * - Incremental (i): boolean, signals whether incremental delivery is useful
 *
 * PRIORITY_UPDATE frame types:
 * - 0xf0700: Priority update for request streams
 * - 0xf0701: Priority update for push streams
 */

#ifndef _TQUIC_HTTP3_PRIORITY_H
#define _TQUIC_HTTP3_PRIORITY_H

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/rbtree.h>
#include <linux/list.h>
#include <net/tquic.h>

/*
 * HTTP/3 Frame Types for Priority
 */
#define HTTP3_FRAME_PRIORITY_UPDATE_REQUEST	0xf0700ULL
#define HTTP3_FRAME_PRIORITY_UPDATE_PUSH	0xf0701ULL

/*
 * Priority Field Value Parsing Constants
 */
#define HTTP3_PRIORITY_URGENCY_MIN		0
#define HTTP3_PRIORITY_URGENCY_MAX		7
#define HTTP3_PRIORITY_URGENCY_DEFAULT		3
#define HTTP3_PRIORITY_INCREMENTAL_DEFAULT	false

/*
 * Priority field value structured header keys
 */
#define HTTP3_PRIORITY_KEY_URGENCY		'u'
#define HTTP3_PRIORITY_KEY_INCREMENTAL		'i'

/*
 * Maximum priority field value length (RFC 9218 recommends keeping it short)
 */
#define HTTP3_PRIORITY_FIELD_MAX_LEN		256

/*
 * Stream scheduling priority buckets (urgency 0-7)
 */
#define HTTP3_PRIORITY_NUM_BUCKETS		8

/**
 * struct http3_priority - HTTP/3 priority parameters
 * @urgency: Urgency level (0-7, 0 = highest, 7 = lowest)
 * @incremental: Incremental delivery hint
 * @valid: Whether this priority has been explicitly set
 *
 * Per RFC 9218, the default priority is urgency=3, incremental=false.
 */
struct http3_priority {
	u8 urgency;
	bool incremental;
	bool valid;
};

/**
 * struct http3_priority_stream - Priority state for a single stream
 * @stream_id: The stream ID this priority applies to
 * @priority: Current priority parameters
 * @bucket_node: Linkage in urgency bucket
 * @tree_node: RB-tree node for stream lookup
 * @update_pending: PRIORITY_UPDATE frame needs to be sent
 * @update_count: Number of priority updates received
 */
struct http3_priority_stream {
	u64 stream_id;
	struct http3_priority priority;
	struct list_head bucket_node;
	struct rb_node tree_node;
	bool update_pending;
	u32 update_count;
};

/**
 * struct http3_priority_state - Priority state for a connection
 * @buckets: Urgency-based scheduling buckets (0-7)
 * @streams: RB-tree of all stream priorities for lookup
 * @stream_count: Total number of streams with priority state
 * @lock: Spinlock protecting priority state
 * @enabled: HTTP/3 priorities enabled for this connection
 * @conn: Back-pointer to TQUIC connection
 * @cache: SLAB cache for priority stream allocation
 *
 * The bucket array provides O(1) access to streams at each urgency level,
 * while the RB-tree allows O(log n) lookup by stream ID.
 */
struct http3_priority_state {
	struct list_head buckets[HTTP3_PRIORITY_NUM_BUCKETS];
	struct rb_root streams;
	u32 stream_count;
	spinlock_t lock;
	bool enabled;
	struct tquic_connection *conn;
	struct kmem_cache *cache;
};

/**
 * struct http3_priority_update_frame - Parsed PRIORITY_UPDATE frame
 * @element_id: Stream ID (0xf0700) or Push ID (0xf0701)
 * @priority: Parsed priority parameters
 * @is_push: True if this is a push stream priority update
 */
struct http3_priority_update_frame {
	u64 element_id;
	struct http3_priority priority;
	bool is_push;
};

/*
 * Sysctl accessor
 */
bool http3_priorities_enabled(struct net *net);

/*
 * Priority State Management
 */

/**
 * http3_priority_state_init - Initialize priority state for a connection
 * @conn: TQUIC connection
 *
 * Allocates and initializes the HTTP/3 priority state for a connection.
 * This should be called after the HTTP/3 layer is established.
 *
 * Returns: 0 on success, negative error code on failure
 */
int http3_priority_state_init(struct tquic_connection *conn);

/**
 * http3_priority_state_destroy - Destroy priority state for a connection
 * @conn: TQUIC connection
 *
 * Frees all resources associated with HTTP/3 priority tracking.
 */
void http3_priority_state_destroy(struct tquic_connection *conn);

/*
 * Stream Priority Operations
 */

/**
 * http3_priority_stream_init - Initialize priority for a new stream
 * @conn: TQUIC connection
 * @stream_id: Stream ID
 * @initial: Initial priority (NULL for default)
 *
 * Creates priority state for a new stream. If initial is NULL, the
 * default priority (urgency=3, incremental=false) is used.
 *
 * Returns: 0 on success, negative error code on failure
 */
int http3_priority_stream_init(struct tquic_connection *conn,
			       u64 stream_id,
			       const struct http3_priority *initial);

/**
 * http3_priority_stream_destroy - Remove priority state for a stream
 * @conn: TQUIC connection
 * @stream_id: Stream ID
 *
 * Removes and frees priority state when a stream is closed.
 */
void http3_priority_stream_destroy(struct tquic_connection *conn,
				   u64 stream_id);

/**
 * http3_priority_stream_get - Get current priority for a stream
 * @conn: TQUIC connection
 * @stream_id: Stream ID
 * @priority: Output priority parameters
 *
 * Returns: 0 on success, -ENOENT if stream not found
 */
int http3_priority_stream_get(struct tquic_connection *conn,
			      u64 stream_id,
			      struct http3_priority *priority);

/**
 * http3_priority_stream_set - Set priority for a stream
 * @conn: TQUIC connection
 * @stream_id: Stream ID
 * @priority: New priority parameters
 *
 * Updates the priority for an existing stream. This may trigger
 * reordering in the scheduling buckets.
 *
 * Returns: 0 on success, -ENOENT if stream not found
 */
int http3_priority_stream_set(struct tquic_connection *conn,
			      u64 stream_id,
			      const struct http3_priority *priority);

/*
 * PRIORITY_UPDATE Frame Handling
 */

/**
 * http3_priority_parse_frame - Parse a PRIORITY_UPDATE frame
 * @data: Frame payload (after frame type)
 * @len: Payload length
 * @frame: Output parsed frame
 * @is_push: True if frame type was 0xf0701 (push streams)
 *
 * Parses the PRIORITY_UPDATE frame format:
 *   Element ID (varint) || Priority Field Value (...)
 *
 * Returns: Number of bytes consumed on success, negative error on failure
 */
int http3_priority_parse_frame(const u8 *data, size_t len,
			       struct http3_priority_update_frame *frame,
			       bool is_push);

/**
 * http3_priority_encode_frame - Encode a PRIORITY_UPDATE frame
 * @buf: Output buffer
 * @buf_len: Buffer size
 * @element_id: Stream ID or Push ID
 * @priority: Priority to encode
 * @is_push: True for push stream priority (0xf0701)
 *
 * Encodes a complete PRIORITY_UPDATE frame including the frame type.
 *
 * Returns: Number of bytes written on success, negative error on failure
 */
int http3_priority_encode_frame(u8 *buf, size_t buf_len,
				u64 element_id,
				const struct http3_priority *priority,
				bool is_push);

/**
 * http3_priority_handle_update - Handle received PRIORITY_UPDATE frame
 * @conn: TQUIC connection
 * @frame: Parsed PRIORITY_UPDATE frame
 *
 * Processes a PRIORITY_UPDATE frame received from the peer.
 * Updates the local priority state for the specified stream.
 *
 * Returns: 0 on success, negative error on failure
 */
int http3_priority_handle_update(struct tquic_connection *conn,
				 const struct http3_priority_update_frame *frame);

/**
 * http3_priority_send_update - Send a PRIORITY_UPDATE frame
 * @conn: TQUIC connection
 * @stream_id: Stream to update priority for
 * @priority: New priority parameters
 *
 * Queues a PRIORITY_UPDATE frame to be sent to the peer.
 *
 * Returns: 0 on success, negative error on failure
 */
int http3_priority_send_update(struct tquic_connection *conn,
			       u64 stream_id,
			       const struct http3_priority *priority);

/*
 * Priority Field Value Parsing (RFC 9218 Section 4)
 *
 * The Priority field value is a Structured Field Dictionary (RFC 8941).
 * Example: "u=2, i" means urgency=2, incremental=true
 *          "u=5" means urgency=5, incremental=false (default)
 */

/**
 * http3_priority_parse_field - Parse a Priority field value
 * @field: Priority field value string
 * @len: Field length
 * @priority: Output priority parameters
 *
 * Parses a Priority header field or priority field value from
 * PRIORITY_UPDATE frame using Structured Field Dictionary format.
 *
 * Returns: 0 on success, negative error on invalid format
 */
int http3_priority_parse_field(const char *field, size_t len,
			       struct http3_priority *priority);

/**
 * http3_priority_encode_field - Encode a Priority field value
 * @buf: Output buffer
 * @buf_len: Buffer size
 * @priority: Priority to encode
 *
 * Encodes priority parameters as a Structured Field Dictionary.
 * Output format examples: "u=3", "u=0, i", "u=5, i"
 *
 * Returns: Number of bytes written on success, negative error on failure
 */
int http3_priority_encode_field(char *buf, size_t buf_len,
				const struct http3_priority *priority);

/*
 * Scheduler Integration
 */

/**
 * http3_priority_get_next_stream - Get highest priority stream with data
 * @conn: TQUIC connection
 * @incremental_only: If true, only return incremental streams
 *
 * Returns the stream ID of the highest priority stream that has data
 * ready to send. Streams are ordered first by urgency (0-7), then
 * by creation order within each urgency level.
 *
 * If incremental_only is true, only streams marked as incremental
 * are considered. This allows round-robin among incremental streams
 * at the same urgency level.
 *
 * Returns: Stream ID, or 0 if no suitable stream found
 */
u64 http3_priority_get_next_stream(struct tquic_connection *conn,
				   bool incremental_only);

/**
 * http3_priority_get_streams_at_urgency - Get all streams at urgency level
 * @conn: TQUIC connection
 * @urgency: Urgency level (0-7)
 * @stream_ids: Output array of stream IDs
 * @max_streams: Maximum streams to return
 *
 * Returns: Number of streams added to array
 */
int http3_priority_get_streams_at_urgency(struct tquic_connection *conn,
					  u8 urgency,
					  u64 *stream_ids,
					  int max_streams);

/**
 * http3_priority_should_interleave - Check if streams should interleave
 * @conn: TQUIC connection
 * @stream_id: Stream ID to check
 *
 * Returns true if the specified stream is marked as incremental and
 * should participate in round-robin scheduling with other incremental
 * streams at the same urgency level.
 *
 * Returns: true if stream should interleave, false otherwise
 */
bool http3_priority_should_interleave(struct tquic_connection *conn,
				      u64 stream_id);

/*
 * HTTP Request/Response Integration
 */

/**
 * http3_priority_from_header - Parse Priority header from HTTP request
 * @header_value: The Priority header value
 * @len: Header value length
 * @priority: Output priority parameters
 *
 * Parses a Priority header field from an HTTP request. The sender
 * should use this to extract the client's priority preference.
 *
 * Returns: 0 on success, negative error on invalid format
 */
int http3_priority_from_header(const char *header_value, size_t len,
			       struct http3_priority *priority);

/**
 * http3_priority_to_header - Format Priority header for HTTP response
 * @buf: Output buffer
 * @buf_len: Buffer size
 * @priority: Priority to format
 *
 * Formats priority parameters as a Priority header value for
 * inclusion in HTTP responses (if the server wants to echo priority).
 *
 * Returns: Number of bytes written on success, negative error on failure
 */
int http3_priority_to_header(char *buf, size_t buf_len,
			     const struct http3_priority *priority);

/*
 * Debugging and Statistics
 */

/**
 * http3_priority_dump - Dump priority state for debugging
 * @conn: TQUIC connection
 *
 * Prints priority state to kernel log for debugging.
 */
void http3_priority_dump(struct tquic_connection *conn);

/**
 * struct http3_priority_stats - Priority statistics
 * @streams_tracked: Total streams with priority state
 * @updates_received: PRIORITY_UPDATE frames received
 * @updates_sent: PRIORITY_UPDATE frames sent
 * @headers_parsed: Priority headers parsed from requests
 * @parse_errors: Priority field parse errors
 */
struct http3_priority_stats {
	u64 streams_tracked;
	u64 updates_received;
	u64 updates_sent;
	u64 headers_parsed;
	u64 parse_errors;
};

/**
 * http3_priority_get_stats - Get priority statistics
 * @conn: TQUIC connection
 * @stats: Output statistics
 */
void http3_priority_get_stats(struct tquic_connection *conn,
			      struct http3_priority_stats *stats);

/*
 * Default Priority Helpers
 */

/**
 * http3_priority_default - Get default priority parameters
 * @priority: Output priority structure
 *
 * Sets priority to the RFC 9218 default: urgency=3, incremental=false
 */
static inline void http3_priority_default(struct http3_priority *priority)
{
	priority->urgency = HTTP3_PRIORITY_URGENCY_DEFAULT;
	priority->incremental = HTTP3_PRIORITY_INCREMENTAL_DEFAULT;
	priority->valid = true;
}

/**
 * http3_priority_is_default - Check if priority is the default
 * @priority: Priority to check
 *
 * Returns: true if priority matches the default values
 */
static inline bool http3_priority_is_default(const struct http3_priority *priority)
{
	return priority->urgency == HTTP3_PRIORITY_URGENCY_DEFAULT &&
	       priority->incremental == HTTP3_PRIORITY_INCREMENTAL_DEFAULT;
}

/**
 * http3_priority_compare - Compare two priorities
 * @a: First priority
 * @b: Second priority
 *
 * Returns: negative if a > b (higher priority), positive if a < b,
 *          0 if equal. Lower urgency number means higher priority.
 */
static inline int http3_priority_compare(const struct http3_priority *a,
					 const struct http3_priority *b)
{
	if (a->urgency != b->urgency)
		return (int)a->urgency - (int)b->urgency;
	/* At same urgency, incremental streams may be interleaved */
	return 0;
}

/*
 * Module initialization
 */
int __init http3_priority_init(void);
void __exit http3_priority_exit(void);

#endif /* _TQUIC_HTTP3_PRIORITY_H */
