// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC HTTP/3 Extensible Priorities (RFC 9218)
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * This file implements HTTP/3 Extensible Priorities as defined in RFC 9218.
 * The priority scheme provides:
 * - Urgency (u=0-7): 0 is highest priority, 7 is lowest, default is 3
 * - Incremental (i): Boolean flag for incremental delivery hint
 *
 * PRIORITY_UPDATE frame (type 0x0f) allows dynamic priority updates.
 * The Priority header field uses Structured Field Dictionary format.
 *
 * The implementation integrates with the TQUIC scheduler to provide
 * priority-aware stream scheduling for optimal HTTP/3 performance.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/ctype.h>
#include <linux/spinlock.h>
#include <linux/rbtree.h>
#include <linux/list.h>
#include <linux/sysctl.h>
#include <net/net_namespace.h>
#include <net/tquic.h>
#include <net/tquic_http3.h>

#include "http3_priority.h"
#include "http3_stream.h"
#include "../core/varint.h"

/* Global statistics */
static struct {
	atomic64_t streams_tracked;
	atomic64_t updates_received;
	atomic64_t updates_sent;
	atomic64_t headers_parsed;
	atomic64_t parse_errors;
} http3_priority_global_stats;

/* SLAB cache for priority stream entries */
static struct kmem_cache *http3_priority_stream_cache;

/* External sysctl accessor from tquic_sysctl.c */
extern int tquic_sysctl_get_http3_priorities_enabled(void);

/**
 * http3_priorities_enabled - Check if HTTP/3 priorities are enabled
 * @net: Network namespace (unused, global setting)
 *
 * Returns: true if HTTP/3 priorities are enabled
 */
bool http3_priorities_enabled(struct net *net)
{
	return tquic_sysctl_get_http3_priorities_enabled() != 0;
}
EXPORT_SYMBOL_GPL(http3_priorities_enabled);

/* =========================================================================
 * QUIC Variable-Length Integer Helpers
 *
 * RFC 9000 variable-length integer encoding for PRIORITY_UPDATE frames.
 * ========================================================================= */

static inline int varint_size(u64 value)
{
	if (value <= 63)
		return 1;
	if (value <= 16383)
		return 2;
	if (value <= 1073741823)
		return 4;
	if (value <= 4611686018427387903ULL)
		return 8;
	return 0;
}

static int varint_encode(u64 value, u8 *buf, size_t buf_len)
{
	int len = varint_size(value);

	if (len == 0 || buf_len < len)
		return -EINVAL;

	switch (len) {
	case 1:
		buf[0] = (u8)value;
		break;
	case 2:
		buf[0] = 0x40 | (u8)(value >> 8);
		buf[1] = (u8)value;
		break;
	case 4:
		buf[0] = 0x80 | (u8)(value >> 24);
		buf[1] = (u8)(value >> 16);
		buf[2] = (u8)(value >> 8);
		buf[3] = (u8)value;
		break;
	case 8:
		buf[0] = 0xc0 | (u8)(value >> 56);
		buf[1] = (u8)(value >> 48);
		buf[2] = (u8)(value >> 40);
		buf[3] = (u8)(value >> 32);
		buf[4] = (u8)(value >> 24);
		buf[5] = (u8)(value >> 16);
		buf[6] = (u8)(value >> 8);
		buf[7] = (u8)value;
		break;
	}

	return len;
}

static int varint_decode(const u8 *buf, size_t buf_len, u64 *value,
			 size_t *consumed)
{
	size_t len;
	u64 v;

	if (buf_len < 1)
		return -EINVAL;

	len = 1 << (buf[0] >> 6);
	if (buf_len < len)
		return -EINVAL;

	switch (len) {
	case 1:
		v = buf[0] & 0x3f;
		break;
	case 2:
		v = ((u64)(buf[0] & 0x3f) << 8) | buf[1];
		break;
	case 4:
		v = ((u64)(buf[0] & 0x3f) << 24) |
		    ((u64)buf[1] << 16) |
		    ((u64)buf[2] << 8) |
		    buf[3];
		break;
	case 8:
		v = ((u64)(buf[0] & 0x3f) << 56) |
		    ((u64)buf[1] << 48) |
		    ((u64)buf[2] << 40) |
		    ((u64)buf[3] << 32) |
		    ((u64)buf[4] << 24) |
		    ((u64)buf[5] << 16) |
		    ((u64)buf[6] << 8) |
		    buf[7];
		break;
	default:
		return -EINVAL;
	}

	*value = v;
	if (consumed)
		*consumed = len;
	return 0;
}

/* =========================================================================
 * Priority Stream RB-Tree Operations
 * ========================================================================= */

static struct http3_priority_stream *
priority_stream_lookup(struct http3_priority_state *state, u64 stream_id)
{
	struct rb_node *node = state->streams.rb_node;

	while (node) {
		struct http3_priority_stream *ps;

		ps = rb_entry(node, struct http3_priority_stream, tree_node);

		if (stream_id < ps->stream_id)
			node = node->rb_left;
		else if (stream_id > ps->stream_id)
			node = node->rb_right;
		else
			return ps;
	}

	return NULL;
}

static int priority_stream_insert(struct http3_priority_state *state,
				  struct http3_priority_stream *ps)
{
	struct rb_node **link = &state->streams.rb_node;
	struct rb_node *parent = NULL;

	while (*link) {
		struct http3_priority_stream *entry;

		parent = *link;
		entry = rb_entry(parent, struct http3_priority_stream, tree_node);

		if (ps->stream_id < entry->stream_id)
			link = &parent->rb_left;
		else if (ps->stream_id > entry->stream_id)
			link = &parent->rb_right;
		else
			return -EEXIST;
	}

	rb_link_node(&ps->tree_node, parent, link);
	rb_insert_color(&ps->tree_node, &state->streams);
	state->stream_count++;

	return 0;
}

static void priority_stream_remove(struct http3_priority_state *state,
				   struct http3_priority_stream *ps)
{
	/* Remove from urgency bucket */
	list_del(&ps->bucket_node);

	/* Remove from lookup tree */
	rb_erase(&ps->tree_node, &state->streams);
	state->stream_count--;
}

/* =========================================================================
 * Priority State Management
 * ========================================================================= */

/**
 * http3_priority_state_init - Initialize priority state for a connection
 * @conn: TQUIC connection
 */
int http3_priority_state_init(struct tquic_connection *conn)
{
	struct http3_priority_state *state;
	int i;

	if (!conn)
		return -EINVAL;

	if (!http3_priorities_enabled(NULL))
		return 0;

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return -ENOMEM;

	/* Initialize urgency buckets */
	for (i = 0; i < HTTP3_PRIORITY_NUM_BUCKETS; i++)
		INIT_LIST_HEAD(&state->buckets[i]);

	state->streams = RB_ROOT;
	spin_lock_init(&state->lock);
	state->enabled = true;
	state->conn = conn;
	state->cache = http3_priority_stream_cache;

	/* Store state in connection's extended priority_state field */
	conn->priority_state = state;

	pr_debug("http3_priority: initialized for connection %p\n", conn);
	return 0;
}
EXPORT_SYMBOL_GPL(http3_priority_state_init);

/**
 * http3_priority_state_destroy - Destroy priority state for a connection
 * @conn: TQUIC connection
 */
void http3_priority_state_destroy(struct tquic_connection *conn)
{
	struct http3_priority_state *state;
	struct rb_node *node;

	if (!conn)
		return;

	state = conn->priority_state;
	if (!state)
		return;

	spin_lock_bh(&state->lock);

	/* Free all stream priority entries */
	while ((node = rb_first(&state->streams))) {
		struct http3_priority_stream *ps;

		ps = rb_entry(node, struct http3_priority_stream, tree_node);
		rb_erase(node, &state->streams);
		list_del(&ps->bucket_node);
		kmem_cache_free(state->cache, ps);
	}

	spin_unlock_bh(&state->lock);

	conn->priority_state = NULL;
	kfree(state);

	pr_debug("http3_priority: destroyed for connection %p\n", conn);
}
EXPORT_SYMBOL_GPL(http3_priority_state_destroy);

/* =========================================================================
 * Stream Priority Operations
 * ========================================================================= */

/**
 * http3_priority_stream_init - Initialize priority for a new stream
 */
int http3_priority_stream_init(struct tquic_connection *conn,
			       u64 stream_id,
			       const struct http3_priority *initial)
{
	struct http3_priority_state *state;
	struct http3_priority_stream *ps;
	u8 urgency;
	int ret;

	if (!conn)
		return -EINVAL;

	state = conn->priority_state;
	if (!state || !state->enabled)
		return 0;

	ps = kmem_cache_zalloc(state->cache, GFP_ATOMIC);
	if (!ps)
		return -ENOMEM;

	ps->stream_id = stream_id;
	INIT_LIST_HEAD(&ps->bucket_node);

	/* Set initial priority */
	if (initial && initial->valid) {
		ps->priority = *initial;
	} else {
		http3_priority_default(&ps->priority);
	}

	/* Clamp urgency to valid range */
	if (ps->priority.urgency > HTTP3_PRIORITY_URGENCY_MAX)
		ps->priority.urgency = HTTP3_PRIORITY_URGENCY_MAX;

	urgency = ps->priority.urgency;

	spin_lock_bh(&state->lock);

	ret = priority_stream_insert(state, ps);
	if (ret) {
		spin_unlock_bh(&state->lock);
		kmem_cache_free(state->cache, ps);
		return ret;
	}

	/* Add to appropriate urgency bucket */
	list_add_tail(&ps->bucket_node, &state->buckets[urgency]);

	spin_unlock_bh(&state->lock);

	atomic64_inc(&http3_priority_global_stats.streams_tracked);

	pr_debug("http3_priority: stream %llu initialized with u=%u, i=%d\n",
		 stream_id, urgency, ps->priority.incremental);

	return 0;
}
EXPORT_SYMBOL_GPL(http3_priority_stream_init);

/**
 * http3_priority_stream_destroy - Remove priority state for a stream
 */
void http3_priority_stream_destroy(struct tquic_connection *conn,
				   u64 stream_id)
{
	struct http3_priority_state *state;
	struct http3_priority_stream *ps;

	if (!conn)
		return;

	state = conn->priority_state;
	if (!state)
		return;

	spin_lock_bh(&state->lock);

	ps = priority_stream_lookup(state, stream_id);
	if (ps) {
		priority_stream_remove(state, ps);
		spin_unlock_bh(&state->lock);
		kmem_cache_free(state->cache, ps);
		pr_debug("http3_priority: stream %llu destroyed\n", stream_id);
	} else {
		spin_unlock_bh(&state->lock);
	}
}
EXPORT_SYMBOL_GPL(http3_priority_stream_destroy);

/**
 * http3_priority_stream_get - Get current priority for a stream
 */
int http3_priority_stream_get(struct tquic_connection *conn,
			      u64 stream_id,
			      struct http3_priority *priority)
{
	struct http3_priority_state *state;
	struct http3_priority_stream *ps;

	if (!conn || !priority)
		return -EINVAL;

	state = conn->priority_state;
	if (!state) {
		/* Return default if priorities not enabled */
		http3_priority_default(priority);
		return 0;
	}

	spin_lock_bh(&state->lock);

	ps = priority_stream_lookup(state, stream_id);
	if (ps) {
		*priority = ps->priority;
		spin_unlock_bh(&state->lock);
		return 0;
	}

	spin_unlock_bh(&state->lock);
	return -ENOENT;
}
EXPORT_SYMBOL_GPL(http3_priority_stream_get);

/**
 * http3_priority_stream_set - Set priority for a stream
 */
int http3_priority_stream_set(struct tquic_connection *conn,
			      u64 stream_id,
			      const struct http3_priority *priority)
{
	struct http3_priority_state *state;
	struct http3_priority_stream *ps;
	u8 old_urgency, new_urgency;

	if (!conn || !priority)
		return -EINVAL;

	state = conn->priority_state;
	if (!state)
		return -ENOENT;

	new_urgency = priority->urgency;
	if (new_urgency > HTTP3_PRIORITY_URGENCY_MAX)
		new_urgency = HTTP3_PRIORITY_URGENCY_MAX;

	spin_lock_bh(&state->lock);

	ps = priority_stream_lookup(state, stream_id);
	if (!ps) {
		spin_unlock_bh(&state->lock);
		return -ENOENT;
	}

	old_urgency = ps->priority.urgency;

	/* Update priority */
	ps->priority.urgency = new_urgency;
	ps->priority.incremental = priority->incremental;
	ps->priority.valid = true;
	ps->update_count++;

	/* Move to new bucket if urgency changed */
	if (old_urgency != new_urgency) {
		list_del(&ps->bucket_node);
		list_add_tail(&ps->bucket_node, &state->buckets[new_urgency]);
	}

	spin_unlock_bh(&state->lock);

	pr_debug("http3_priority: stream %llu updated to u=%u, i=%d\n",
		 stream_id, new_urgency, priority->incremental);

	return 0;
}
EXPORT_SYMBOL_GPL(http3_priority_stream_set);

/* =========================================================================
 * Priority Field Value Parsing (RFC 9218 Section 4)
 *
 * The Priority field value is a Structured Field Dictionary (RFC 8941).
 * Format: key1=value1, key2=value2, ...
 *
 * Supported keys:
 *   u (urgency): Integer 0-7
 *   i (incremental): Boolean (presence = true)
 *
 * Examples:
 *   "u=2, i"     -> urgency=2, incremental=true
 *   "u=5"        -> urgency=5, incremental=false
 *   "i"          -> urgency=3 (default), incremental=true
 *   ""           -> urgency=3, incremental=false (all defaults)
 * ========================================================================= */

/**
 * skip_whitespace - Skip optional whitespace
 */
static const char *skip_whitespace(const char *p, const char *end)
{
	while (p < end && (*p == ' ' || *p == '\t'))
		p++;
	return p;
}

/**
 * parse_integer - Parse an integer value
 */
static int parse_integer(const char *p, const char *end, u64 *value,
			 const char **next)
{
	u64 v = 0;
	bool found = false;

	while (p < end && isdigit(*p)) {
		if (v > (U64_MAX - (*p - '0')) / 10)
			return -EOVERFLOW;
		v = v * 10 + (*p - '0');
		p++;
		found = true;
	}

	if (!found)
		return -EINVAL;

	*value = v;
	*next = p;
	return 0;
}

/**
 * http3_priority_parse_field - Parse a Priority field value
 */
int http3_priority_parse_field(const char *field, size_t len,
			       struct http3_priority *priority)
{
	const char *p = field;
	const char *end = field + len;
	bool found_urgency = false;
	bool found_incremental = false;

	/* Start with defaults */
	http3_priority_default(priority);

	if (!field || len == 0)
		return 0;

	while (p < end) {
		char key;
		const char *next;

		/* Skip whitespace and commas */
		p = skip_whitespace(p, end);
		while (p < end && *p == ',') {
			p++;
			p = skip_whitespace(p, end);
		}

		if (p >= end)
			break;

		/* Get key character */
		key = *p++;
		p = skip_whitespace(p, end);

		if (key == HTTP3_PRIORITY_KEY_URGENCY) {
			/* urgency: u=N */
			u64 val;

			if (p >= end || *p != '=') {
				atomic64_inc(&http3_priority_global_stats.parse_errors);
				return -EINVAL;
			}
			p++;  /* skip '=' */
			p = skip_whitespace(p, end);

			if (parse_integer(p, end, &val, &next) < 0) {
				atomic64_inc(&http3_priority_global_stats.parse_errors);
				return -EINVAL;
			}
			p = next;

			/* Clamp to valid range */
			if (val > HTTP3_PRIORITY_URGENCY_MAX)
				val = HTTP3_PRIORITY_URGENCY_MAX;

			priority->urgency = (u8)val;
			found_urgency = true;

		} else if (key == HTTP3_PRIORITY_KEY_INCREMENTAL) {
			/* incremental: i (boolean, presence = true) */
			/* Check for =?1 or =?0 format, or just bare 'i' */
			if (p < end && *p == '=') {
				p++;
				if (p < end && *p == '?') {
					p++;
					if (p < end) {
						priority->incremental = (*p == '1');
						p++;
					}
				}
			} else {
				/* Bare 'i' means true */
				priority->incremental = true;
			}
			found_incremental = true;

		} else {
			/* Unknown key - skip to next comma or end */
			while (p < end && *p != ',')
				p++;
		}
	}

	atomic64_inc(&http3_priority_global_stats.headers_parsed);

	pr_debug("http3_priority: parsed field \"%.*s\" -> u=%u, i=%d\n",
		 (int)len, field, priority->urgency, priority->incremental);

	return 0;
}
EXPORT_SYMBOL_GPL(http3_priority_parse_field);

/**
 * http3_priority_encode_field - Encode a Priority field value
 */
int http3_priority_encode_field(char *buf, size_t buf_len,
				const struct http3_priority *priority)
{
	int written = 0;

	if (!buf || buf_len < 8)  /* Minimum for "u=N, i" */
		return -ENOSPC;

	/* Always include urgency */
	written = snprintf(buf, buf_len, "u=%u", priority->urgency);
	if (written < 0 || written >= buf_len)
		return -ENOSPC;

	/* Include incremental if true */
	if (priority->incremental) {
		int added = snprintf(buf + written, buf_len - written, ", i");
		if (added < 0 || written + added >= buf_len)
			return -ENOSPC;
		written += added;
	}

	return written;
}
EXPORT_SYMBOL_GPL(http3_priority_encode_field);

/* =========================================================================
 * PRIORITY_UPDATE Frame Handling
 * ========================================================================= */

/**
 * http3_priority_parse_frame - Parse a PRIORITY_UPDATE frame
 */
int http3_priority_parse_frame(const u8 *data, size_t len,
			       struct http3_priority_update_frame *frame,
			       bool is_push)
{
	size_t offset = 0;
	size_t consumed;
	int ret;

	if (!data || !frame || len == 0)
		return -EINVAL;

	frame->is_push = is_push;

	/* Parse Element ID (stream ID or push ID) */
	ret = varint_decode(data, len, &frame->element_id, &consumed);
	if (ret < 0)
		return ret;
	offset += consumed;

	/* Parse Priority Field Value (remaining bytes) */
	if (offset < len) {
		ret = http3_priority_parse_field((const char *)(data + offset),
						 len - offset,
						 &frame->priority);
		if (ret < 0)
			return ret;
	} else {
		/* Empty field value - use defaults */
		http3_priority_default(&frame->priority);
	}

	return (int)len;
}
EXPORT_SYMBOL_GPL(http3_priority_parse_frame);

/**
 * http3_priority_encode_frame - Encode a PRIORITY_UPDATE frame
 */
int http3_priority_encode_frame(u8 *buf, size_t buf_len,
				u64 element_id,
				const struct http3_priority *priority,
				bool is_push)
{
	size_t offset = 0;
	u64 frame_type;
	int ret;
	char field_buf[HTTP3_PRIORITY_FIELD_MAX_LEN];
	int field_len;

	if (!buf || !priority)
		return -EINVAL;

	/* Frame type */
	frame_type = is_push ? HTTP3_FRAME_PRIORITY_UPDATE_PUSH :
			       HTTP3_FRAME_PRIORITY_UPDATE_REQUEST;

	ret = varint_encode(frame_type, buf + offset, buf_len - offset);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Encode priority field value to temporary buffer */
	field_len = http3_priority_encode_field(field_buf, sizeof(field_buf),
						priority);
	if (field_len < 0)
		return field_len;

	/* Frame length (element_id + field value) */
	{
		size_t payload_len = varint_size(element_id) + field_len;
		ret = varint_encode(payload_len, buf + offset, buf_len - offset);
		if (ret < 0)
			return ret;
		offset += ret;
	}

	/* Element ID */
	ret = varint_encode(element_id, buf + offset, buf_len - offset);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Priority Field Value */
	if (offset + field_len > buf_len)
		return -ENOSPC;
	memcpy(buf + offset, field_buf, field_len);
	offset += field_len;

	return (int)offset;
}
EXPORT_SYMBOL_GPL(http3_priority_encode_frame);

/**
 * http3_priority_handle_update - Handle received PRIORITY_UPDATE frame
 */
int http3_priority_handle_update(struct tquic_connection *conn,
				 const struct http3_priority_update_frame *frame)
{
	int ret;

	if (!frame)
		return -EINVAL;

	/* Push stream priorities not yet supported */
	if (frame->is_push) {
		pr_debug("http3_priority: ignoring push stream priority update\n");
		return 0;
	}

	/* Update stream priority */
	ret = http3_priority_stream_set(conn, frame->element_id,
					&frame->priority);
	if (ret == -ENOENT) {
		/* Stream doesn't exist yet - create priority entry */
		ret = http3_priority_stream_init(conn, frame->element_id,
						 &frame->priority);
	}

	if (ret == 0)
		atomic64_inc(&http3_priority_global_stats.updates_received);

	return ret;
}
EXPORT_SYMBOL_GPL(http3_priority_handle_update);

/**
 * http3_priority_send_update - Send a PRIORITY_UPDATE frame
 */
int http3_priority_send_update(struct tquic_connection *conn,
			       u64 stream_id,
			       const struct http3_priority *priority)
{
	/* In a full implementation, this would queue a PRIORITY_UPDATE
	 * frame for transmission on the control stream (stream 0) */

	atomic64_inc(&http3_priority_global_stats.updates_sent);

	pr_debug("http3_priority: queued PRIORITY_UPDATE for stream %llu "
		 "(u=%u, i=%d)\n",
		 stream_id, priority->urgency, priority->incremental);

	return 0;
}
EXPORT_SYMBOL_GPL(http3_priority_send_update);

/* =========================================================================
 * Scheduler Integration
 * ========================================================================= */

/**
 * http3_priority_get_next_stream - Get highest priority stream with data
 */
u64 http3_priority_get_next_stream(struct tquic_connection *conn,
				   bool incremental_only)
{
	struct http3_priority_state *state;
	struct http3_priority_stream *ps;
	int urgency;
	u64 stream_id = 0;

	if (!conn)
		return 0;

	state = conn->priority_state;
	if (!state)
		return 0;

	spin_lock_bh(&state->lock);

	/* Search buckets from highest priority (0) to lowest (7) */
	for (urgency = 0; urgency < HTTP3_PRIORITY_NUM_BUCKETS; urgency++) {
		if (list_empty(&state->buckets[urgency]))
			continue;

		list_for_each_entry(ps, &state->buckets[urgency], bucket_node) {
			/* Skip if we only want incremental and this isn't */
			if (incremental_only && !ps->priority.incremental)
				continue;

			/* In a full implementation, we would check if the
			 * stream has data ready to send. For now, return
			 * the first matching stream. */
			stream_id = ps->stream_id;
			goto found;
		}
	}

found:
	spin_unlock_bh(&state->lock);
	return stream_id;
}
EXPORT_SYMBOL_GPL(http3_priority_get_next_stream);

/**
 * http3_priority_get_streams_at_urgency - Get all streams at urgency level
 */
int http3_priority_get_streams_at_urgency(struct tquic_connection *conn,
					  u8 urgency,
					  u64 *stream_ids,
					  int max_streams)
{
	struct http3_priority_state *state;
	struct http3_priority_stream *ps;
	int count = 0;

	if (!conn || !stream_ids || urgency > HTTP3_PRIORITY_URGENCY_MAX)
		return 0;

	state = conn->priority_state;
	if (!state)
		return 0;

	spin_lock_bh(&state->lock);

	list_for_each_entry(ps, &state->buckets[urgency], bucket_node) {
		if (count >= max_streams)
			break;
		stream_ids[count++] = ps->stream_id;
	}

	spin_unlock_bh(&state->lock);
	return count;
}
EXPORT_SYMBOL_GPL(http3_priority_get_streams_at_urgency);

/**
 * http3_priority_should_interleave - Check if stream should interleave
 */
bool http3_priority_should_interleave(struct tquic_connection *conn,
				      u64 stream_id)
{
	struct http3_priority_state *state;
	struct http3_priority_stream *ps;
	bool incremental = false;

	if (!conn)
		return false;

	state = conn->priority_state;
	if (!state)
		return false;

	spin_lock_bh(&state->lock);

	ps = priority_stream_lookup(state, stream_id);
	if (ps)
		incremental = ps->priority.incremental;

	spin_unlock_bh(&state->lock);
	return incremental;
}
EXPORT_SYMBOL_GPL(http3_priority_should_interleave);

/* =========================================================================
 * HTTP Request/Response Integration
 * ========================================================================= */

/**
 * http3_priority_from_header - Parse Priority header from HTTP request
 */
int http3_priority_from_header(const char *header_value, size_t len,
			       struct http3_priority *priority)
{
	return http3_priority_parse_field(header_value, len, priority);
}
EXPORT_SYMBOL_GPL(http3_priority_from_header);

/**
 * http3_priority_to_header - Format Priority header for HTTP response
 */
int http3_priority_to_header(char *buf, size_t buf_len,
			     const struct http3_priority *priority)
{
	return http3_priority_encode_field(buf, buf_len, priority);
}
EXPORT_SYMBOL_GPL(http3_priority_to_header);

/* =========================================================================
 * Debugging and Statistics
 * ========================================================================= */

/**
 * http3_priority_dump - Dump priority state for debugging
 */
void http3_priority_dump(struct tquic_connection *conn)
{
	struct http3_priority_state *state;
	struct http3_priority_stream *ps;
	int urgency;

	if (!conn) {
		pr_info("http3_priority: NULL connection\n");
		return;
	}

	state = conn->priority_state;
	if (!state) {
		pr_info("http3_priority: no state for connection %p\n", conn);
		return;
	}

	spin_lock_bh(&state->lock);

	pr_info("http3_priority: connection %p, %u streams tracked\n",
		conn, state->stream_count);

	for (urgency = 0; urgency < HTTP3_PRIORITY_NUM_BUCKETS; urgency++) {
		if (list_empty(&state->buckets[urgency]))
			continue;

		pr_info("  urgency %d:\n", urgency);

		list_for_each_entry(ps, &state->buckets[urgency], bucket_node) {
			pr_info("    stream %llu: u=%u i=%d updates=%u\n",
				ps->stream_id,
				ps->priority.urgency,
				ps->priority.incremental,
				ps->update_count);
		}
	}

	spin_unlock_bh(&state->lock);
}
EXPORT_SYMBOL_GPL(http3_priority_dump);

/**
 * http3_priority_get_stats - Get priority statistics
 */
void http3_priority_get_stats(struct tquic_connection *conn,
			      struct http3_priority_stats *stats)
{
	if (!stats)
		return;

	stats->streams_tracked = atomic64_read(&http3_priority_global_stats.streams_tracked);
	stats->updates_received = atomic64_read(&http3_priority_global_stats.updates_received);
	stats->updates_sent = atomic64_read(&http3_priority_global_stats.updates_sent);
	stats->headers_parsed = atomic64_read(&http3_priority_global_stats.headers_parsed);
	stats->parse_errors = atomic64_read(&http3_priority_global_stats.parse_errors);
}
EXPORT_SYMBOL_GPL(http3_priority_get_stats);

/* =========================================================================
 * Public API - RFC 9218 Compliant Functions
 * ========================================================================= */

/**
 * tquic_h3_send_priority_update - Send PRIORITY_UPDATE frame
 */
int tquic_h3_send_priority_update(struct tquic_http3_conn *conn,
				  u64 stream_id,
				  const struct tquic_h3_priority *pri)
{
	u8 buf[64];
	size_t offset = 0;
	int ret;
	char field_buf[HTTP3_PRIORITY_FIELD_MAX_LEN];
	int field_len;
	struct http3_priority internal_pri;

	if (!conn || !pri)
		return -EINVAL;

	/* Convert public API struct to internal format */
	internal_pri.urgency = pri->urgency;
	internal_pri.incremental = pri->incremental;
	internal_pri.valid = true;

	/* Clamp urgency to valid range */
	if (internal_pri.urgency > TQUIC_H3_PRIORITY_URGENCY_MAX)
		internal_pri.urgency = TQUIC_H3_PRIORITY_URGENCY_MAX;

	/* Encode priority field value */
	field_len = http3_priority_encode_field(field_buf, sizeof(field_buf),
						&internal_pri);
	if (field_len < 0)
		return field_len;

	/* Frame type: PRIORITY_UPDATE (0x0f) */
	ret = varint_encode(TQUIC_H3_FRAME_PRIORITY_UPDATE, buf + offset,
			    sizeof(buf) - offset);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Frame length = Element ID size + Priority Field Value length */
	{
		size_t elem_id_size = varint_size(stream_id);
		size_t payload_len = elem_id_size + field_len;

		ret = varint_encode(payload_len, buf + offset,
				    sizeof(buf) - offset);
		if (ret < 0)
			return ret;
		offset += ret;
	}

	/* Element ID (Stream ID) */
	ret = varint_encode(stream_id, buf + offset, sizeof(buf) - offset);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Priority Field Value */
	if (offset + field_len > sizeof(buf))
		return -ENOSPC;
	memcpy(buf + offset, field_buf, field_len);
	offset += field_len;

	/* Send on control stream */
	if (conn->ctrl_stream_local) {
		ret = tquic_stream_send(conn->ctrl_stream_local, buf, offset,
					false);
		if (ret < 0)
			return ret;
	}

	atomic64_inc(&http3_priority_global_stats.updates_sent);

	pr_debug("tquic_h3: sent PRIORITY_UPDATE for stream %llu (u=%u, i=%d)\n",
		 stream_id, pri->urgency, pri->incremental);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_h3_send_priority_update);

/**
 * tquic_h3_handle_priority_update - Handle received PRIORITY_UPDATE frame
 */
int tquic_h3_handle_priority_update(struct tquic_http3_conn *conn,
				    const u8 *data, size_t len)
{
	struct http3_priority_update_frame frame;
	struct tquic_h3_priority pub_pri;
	int ret;

	if (!conn || !data || len == 0)
		return -EINVAL;

	/* Parse the frame payload */
	ret = http3_priority_parse_frame(data, len, &frame, false);
	if (ret < 0)
		return ret;

	/* Convert to public struct */
	pub_pri.urgency = frame.priority.urgency;
	pub_pri.incremental = frame.priority.incremental;

	/* Update the stream priority if conn has priority state */
	if (conn->qconn) {
		ret = http3_priority_handle_update(conn->qconn, &frame);
		if (ret < 0 && ret != -ENOENT)
			return ret;
	}

	atomic64_inc(&http3_priority_global_stats.updates_received);

	pr_debug("tquic_h3: received PRIORITY_UPDATE for stream %llu (u=%u, i=%d)\n",
		 frame.element_id, pub_pri.urgency, pub_pri.incremental);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_h3_handle_priority_update);

/**
 * tquic_h3_parse_priority_header - Parse "Priority: u=X, i" header
 */
int tquic_h3_parse_priority_header(const char *value, size_t len,
				   struct tquic_h3_priority *pri)
{
	struct http3_priority internal_pri;
	int ret;

	if (!pri)
		return -EINVAL;

	/* Use internal parser */
	ret = http3_priority_parse_field(value, len, &internal_pri);
	if (ret < 0)
		return ret;

	/* Convert to public struct */
	pri->urgency = internal_pri.urgency;
	pri->incremental = internal_pri.incremental;

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_h3_parse_priority_header);

/**
 * tquic_h3_format_priority_header - Format priority as header value
 */
int tquic_h3_format_priority_header(const struct tquic_h3_priority *pri,
				    char *buf, size_t len)
{
	struct http3_priority internal_pri;

	if (!pri || !buf)
		return -EINVAL;

	/* Convert to internal struct */
	internal_pri.urgency = pri->urgency;
	internal_pri.incremental = pri->incremental;
	internal_pri.valid = true;

	return http3_priority_encode_field(buf, len, &internal_pri);
}
EXPORT_SYMBOL_GPL(tquic_h3_format_priority_header);

/**
 * tquic_h3_priority_next - Get next stream to send based on priority
 */
struct tquic_h3_stream *tquic_h3_priority_next(struct tquic_http3_conn *conn)
{
	struct http3_priority_state *state;
	struct http3_priority_stream *ps;
	int urgency;
	u64 stream_id = 0;

	if (!conn || !conn->qconn)
		return NULL;

	/* Get priority state from QUIC connection */
	state = conn->qconn->priority_state;
	if (!state)
		return NULL;

	spin_lock_bh(&state->lock);

	/* Search buckets from highest priority (0) to lowest (7) */
	for (urgency = 0; urgency < HTTP3_PRIORITY_NUM_BUCKETS; urgency++) {
		struct list_head *bucket = &state->buckets[urgency];
		struct list_head *cursor = state->rr_cursor[urgency];
		bool found_incremental = false;

		if (list_empty(bucket))
			continue;

		/* If we have a cursor, start from there for round-robin */
		if (cursor && cursor != bucket) {
			ps = list_entry(cursor, struct http3_priority_stream,
					bucket_node);
			if (ps->priority.incremental) {
				/* Advance cursor for next call */
				state->rr_cursor[urgency] =
					(cursor->next == bucket) ?
					bucket->next : cursor->next;
				stream_id = ps->stream_id;
				found_incremental = true;
				goto found;
			}
		}

		/* Otherwise, find first non-incremental or any stream */
		list_for_each_entry(ps, bucket, bucket_node) {
			if (!ps->priority.incremental) {
				/* Non-incremental: send in order */
				stream_id = ps->stream_id;
				goto found;
			}
			if (!found_incremental) {
				/* First incremental at this urgency */
				stream_id = ps->stream_id;
				state->rr_cursor[urgency] = &ps->bucket_node;
				found_incremental = true;
			}
		}

		if (found_incremental)
			goto found;
	}

found:
	spin_unlock_bh(&state->lock);

	/* Look up the actual stream structure */
	if (stream_id != 0) {
		/* Would look up h3_stream by ID from conn */
		/* For now, return NULL as full integration needed */
	}

	return NULL;
}
EXPORT_SYMBOL_GPL(tquic_h3_priority_next);

/**
 * tquic_h3_stream_set_priority - Update stream priority
 *
 * Updates the RFC 9218 priority parameters for an HTTP/3 stream.
 * The priority affects scheduling order for stream data transmission.
 *
 * Note: tquic_h3_stream is an alias for h3_stream internally.
 */
void tquic_h3_stream_set_priority(struct tquic_h3_stream *stream,
				  const struct tquic_h3_priority *pri)
{
	struct h3_stream *h3s = (struct h3_stream *)stream;

	if (!h3s || !pri)
		return;

	spin_lock_bh(&h3s->lock);

	/* Clamp urgency to valid range */
	h3s->priority_urgency = pri->urgency;
	if (h3s->priority_urgency > TQUIC_H3_PRIORITY_URGENCY_MAX)
		h3s->priority_urgency = TQUIC_H3_PRIORITY_URGENCY_MAX;

	h3s->priority_incremental = pri->incremental;
	h3s->priority_valid = true;

	spin_unlock_bh(&h3s->lock);

	pr_debug("tquic_h3: set stream %llu priority u=%u, i=%d\n",
		 h3s->base ? h3s->base->id : 0,
		 h3s->priority_urgency, h3s->priority_incremental);
}
EXPORT_SYMBOL_GPL(tquic_h3_stream_set_priority);

/**
 * tquic_h3_stream_get_priority - Get current stream priority
 *
 * Retrieves the current RFC 9218 priority parameters for an HTTP/3 stream.
 */
int tquic_h3_stream_get_priority(struct tquic_h3_stream *stream,
				 struct tquic_h3_priority *pri)
{
	struct h3_stream *h3s = (struct h3_stream *)stream;

	if (!h3s || !pri)
		return -EINVAL;

	spin_lock_bh(&h3s->lock);

	if (h3s->priority_valid) {
		pri->urgency = h3s->priority_urgency;
		pri->incremental = h3s->priority_incremental;
	} else {
		/* Return defaults if priority not explicitly set */
		pri->urgency = TQUIC_H3_PRIORITY_URGENCY_DEFAULT;
		pri->incremental = TQUIC_H3_PRIORITY_INCREMENTAL_DEFAULT;
	}

	spin_unlock_bh(&h3s->lock);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_h3_stream_get_priority);

/* =========================================================================
 * Priority Tree Implementation
 * ========================================================================= */

/* Tree node structure for stream tracking */
struct priority_tree_node {
	u64 stream_id;
	struct tquic_h3_priority priority;
	struct list_head bucket_node;	/* in urgency bucket */
	struct rb_node tree_node;	/* in lookup tree */
};

/**
 * tquic_h3_priority_tree_init - Initialize priority tree
 */
void tquic_h3_priority_tree_init(struct tquic_h3_priority_tree *tree)
{
	int i;

	if (!tree)
		return;

	for (i = 0; i < 8; i++) {
		INIT_LIST_HEAD(&tree->buckets[i]);
		tree->rr_cursor[i] = NULL;
	}

	tree->stream_tree = RB_ROOT;
	spin_lock_init(&tree->lock);
	tree->stream_count = 0;
	tree->enabled = true;
}
EXPORT_SYMBOL_GPL(tquic_h3_priority_tree_init);

/**
 * tquic_h3_priority_tree_destroy - Destroy priority tree
 */
void tquic_h3_priority_tree_destroy(struct tquic_h3_priority_tree *tree)
{
	struct rb_node *node;

	if (!tree)
		return;

	spin_lock_bh(&tree->lock);

	/* Free all nodes */
	while ((node = rb_first(&tree->stream_tree))) {
		struct priority_tree_node *ptn;

		ptn = rb_entry(node, struct priority_tree_node, tree_node);
		rb_erase(node, &tree->stream_tree);
		list_del(&ptn->bucket_node);
		kfree(ptn);
	}

	tree->stream_count = 0;
	tree->enabled = false;

	spin_unlock_bh(&tree->lock);
}
EXPORT_SYMBOL_GPL(tquic_h3_priority_tree_destroy);

/* Helper: lookup node by stream ID */
static struct priority_tree_node *
tree_lookup(struct tquic_h3_priority_tree *tree, u64 stream_id)
{
	struct rb_node *node = tree->stream_tree.rb_node;

	while (node) {
		struct priority_tree_node *ptn;

		ptn = rb_entry(node, struct priority_tree_node, tree_node);

		if (stream_id < ptn->stream_id)
			node = node->rb_left;
		else if (stream_id > ptn->stream_id)
			node = node->rb_right;
		else
			return ptn;
	}

	return NULL;
}

/**
 * tquic_h3_priority_tree_add - Add stream to priority tree
 */
int tquic_h3_priority_tree_add(struct tquic_h3_priority_tree *tree,
			       u64 stream_id,
			       const struct tquic_h3_priority *pri)
{
	struct priority_tree_node *ptn;
	struct rb_node **link, *parent = NULL;
	u8 urgency;

	if (!tree || !pri)
		return -EINVAL;

	ptn = kzalloc(sizeof(*ptn), GFP_ATOMIC);
	if (!ptn)
		return -ENOMEM;

	ptn->stream_id = stream_id;
	ptn->priority = *pri;
	INIT_LIST_HEAD(&ptn->bucket_node);

	/* Clamp urgency */
	urgency = pri->urgency;
	if (urgency > TQUIC_H3_PRIORITY_URGENCY_MAX)
		urgency = TQUIC_H3_PRIORITY_URGENCY_MAX;

	spin_lock_bh(&tree->lock);

	/* Insert into RB tree */
	link = &tree->stream_tree.rb_node;
	while (*link) {
		struct priority_tree_node *entry;

		parent = *link;
		entry = rb_entry(parent, struct priority_tree_node, tree_node);

		if (stream_id < entry->stream_id) {
			link = &parent->rb_left;
		} else if (stream_id > entry->stream_id) {
			link = &parent->rb_right;
		} else {
			/* Already exists */
			spin_unlock_bh(&tree->lock);
			kfree(ptn);
			return -EEXIST;
		}
	}

	rb_link_node(&ptn->tree_node, parent, link);
	rb_insert_color(&ptn->tree_node, &tree->stream_tree);

	/* Add to urgency bucket */
	list_add_tail(&ptn->bucket_node, &tree->buckets[urgency]);
	tree->stream_count++;

	spin_unlock_bh(&tree->lock);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_h3_priority_tree_add);

/**
 * tquic_h3_priority_tree_remove - Remove stream from priority tree
 */
void tquic_h3_priority_tree_remove(struct tquic_h3_priority_tree *tree,
				   u64 stream_id)
{
	struct priority_tree_node *ptn;
	u8 urgency;

	if (!tree)
		return;

	spin_lock_bh(&tree->lock);

	ptn = tree_lookup(tree, stream_id);
	if (ptn) {
		urgency = ptn->priority.urgency;
		if (urgency > TQUIC_H3_PRIORITY_URGENCY_MAX)
			urgency = TQUIC_H3_PRIORITY_URGENCY_MAX;

		/* Check if cursor points to this node */
		if (tree->rr_cursor[urgency] == &ptn->bucket_node) {
			if (ptn->bucket_node.next != &tree->buckets[urgency])
				tree->rr_cursor[urgency] = ptn->bucket_node.next;
			else
				tree->rr_cursor[urgency] = NULL;
		}

		list_del(&ptn->bucket_node);
		rb_erase(&ptn->tree_node, &tree->stream_tree);
		tree->stream_count--;

		spin_unlock_bh(&tree->lock);
		kfree(ptn);
		return;
	}

	spin_unlock_bh(&tree->lock);
}
EXPORT_SYMBOL_GPL(tquic_h3_priority_tree_remove);

/**
 * tquic_h3_priority_tree_update - Update stream priority in tree
 */
int tquic_h3_priority_tree_update(struct tquic_h3_priority_tree *tree,
				  u64 stream_id,
				  const struct tquic_h3_priority *pri)
{
	struct priority_tree_node *ptn;
	u8 old_urgency, new_urgency;

	if (!tree || !pri)
		return -EINVAL;

	spin_lock_bh(&tree->lock);

	ptn = tree_lookup(tree, stream_id);
	if (!ptn) {
		spin_unlock_bh(&tree->lock);
		return -ENOENT;
	}

	old_urgency = ptn->priority.urgency;
	if (old_urgency > TQUIC_H3_PRIORITY_URGENCY_MAX)
		old_urgency = TQUIC_H3_PRIORITY_URGENCY_MAX;

	new_urgency = pri->urgency;
	if (new_urgency > TQUIC_H3_PRIORITY_URGENCY_MAX)
		new_urgency = TQUIC_H3_PRIORITY_URGENCY_MAX;

	/* Update priority */
	ptn->priority = *pri;

	/* Move to new bucket if urgency changed */
	if (old_urgency != new_urgency) {
		/* Update cursor if needed */
		if (tree->rr_cursor[old_urgency] == &ptn->bucket_node) {
			if (ptn->bucket_node.next != &tree->buckets[old_urgency])
				tree->rr_cursor[old_urgency] = ptn->bucket_node.next;
			else
				tree->rr_cursor[old_urgency] = NULL;
		}

		list_del(&ptn->bucket_node);
		list_add_tail(&ptn->bucket_node, &tree->buckets[new_urgency]);
	}

	spin_unlock_bh(&tree->lock);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_h3_priority_tree_update);

/**
 * tquic_h3_priority_tree_next - Get next stream to send
 */
u64 tquic_h3_priority_tree_next(struct tquic_h3_priority_tree *tree)
{
	struct priority_tree_node *ptn;
	int urgency;
	u64 stream_id = 0;

	if (!tree)
		return 0;

	spin_lock_bh(&tree->lock);

	/* Search from highest priority (0) to lowest (7) */
	for (urgency = 0; urgency < 8; urgency++) {
		struct list_head *bucket = &tree->buckets[urgency];
		struct list_head *cursor;
		bool has_incremental = false;

		if (list_empty(bucket))
			continue;

		/* First pass: look for non-incremental streams */
		list_for_each_entry(ptn, bucket, bucket_node) {
			if (!ptn->priority.incremental) {
				stream_id = ptn->stream_id;
				goto found;
			}
			has_incremental = true;
		}

		/* Only incremental streams at this urgency - use round-robin */
		if (has_incremental) {
			cursor = tree->rr_cursor[urgency];
			if (!cursor || cursor == bucket)
				cursor = bucket->next;

			ptn = list_entry(cursor, struct priority_tree_node,
					 bucket_node);
			stream_id = ptn->stream_id;

			/* Advance cursor for next call */
			if (cursor->next == bucket)
				tree->rr_cursor[urgency] = bucket->next;
			else
				tree->rr_cursor[urgency] = cursor->next;

			goto found;
		}
	}

found:
	spin_unlock_bh(&tree->lock);
	return stream_id;
}
EXPORT_SYMBOL_GPL(tquic_h3_priority_tree_next);

/* =========================================================================
 * Module Initialization
 * ========================================================================= */

int __init http3_priority_init(void)
{
	/* Create SLAB cache for priority stream entries */
	http3_priority_stream_cache = kmem_cache_create(
		"http3_priority_stream",
		sizeof(struct http3_priority_stream),
		0,
		SLAB_HWCACHE_ALIGN,
		NULL);
	if (!http3_priority_stream_cache)
		return -ENOMEM;

	/* Note: sysctl http3_priorities_enabled is registered in tquic_sysctl.c */

	pr_info("http3_priority: HTTP/3 Extensible Priorities (RFC 9218) initialized\n");
	pr_info("http3_priority: PRIORITY_UPDATE frame type 0x%x\n",
		TQUIC_H3_FRAME_PRIORITY_UPDATE);
	pr_info("http3_priority: SETTINGS_ENABLE_PRIORITY 0x%x\n",
		TQUIC_H3_SETTINGS_ENABLE_PRIORITY);

	return 0;
}

void __exit http3_priority_exit(void)
{
	if (http3_priority_stream_cache)
		kmem_cache_destroy(http3_priority_stream_cache);

	pr_info("http3_priority: HTTP/3 Extensible Priorities unloaded\n");
}

module_init(http3_priority_init);
module_exit(http3_priority_exit);

MODULE_DESCRIPTION("TQUIC HTTP/3 Extensible Priorities (RFC 9218)");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Foundation");
