// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC HTTP/3 Connection Management
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Implementation of HTTP/3 connection state management per RFC 9114.
 *
 * HTTP/3 connections are layered on QUIC connections and require:
 *   - A pair of control streams (one in each direction)
 *   - Optional QPACK encoder/decoder streams
 *   - Settings exchange before any request streams
 *
 * Control streams are unidirectional and MUST be opened before any
 * request streams. SETTINGS MUST be the first frame on each control stream.
 *
 * This file manages:
 *   - HTTP/3 connection lifecycle
 *   - Control stream creation and processing
 *   - Settings exchange
 *   - GOAWAY handling for graceful shutdown
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/spinlock.h>
#include <linux/refcount.h>
#include <net/tquic.h>
#include <net/tquic_http3.h>

#include "http3_frame.h"
#include "http3_priority.h"

/* Control stream receive buffer size */
#define H3_CTRL_STREAM_BUF_SIZE		4096

/* Maximum frame size we accept on control stream */
#define H3_MAX_CTRL_FRAME_SIZE		(64 * 1024)

/*
 * =============================================================================
 * HTTP/3 Connection State Machine
 * =============================================================================
 *
 * States:
 *   IDLE -> CONNECTING: On tquic_h3_conn_create()
 *   CONNECTING -> CONNECTED: After SETTINGS exchanged
 *   CONNECTED -> GOAWAY_SENT: After sending GOAWAY
 *   CONNECTED -> GOAWAY_RECVD: After receiving GOAWAY
 *   GOAWAY_SENT/RECVD -> CLOSED: When draining complete
 */

/**
 * h3_conn_set_state - Update connection state
 * @h3conn: HTTP/3 connection
 * @new_state: New state to transition to
 *
 * Must be called with h3conn->lock held.
 */
static void h3_conn_set_state(struct tquic_http3_conn *h3conn,
			      enum tquic_h3_conn_state new_state)
{
	enum tquic_h3_conn_state old_state = h3conn->state;

	/* Validate transitions */
	switch (old_state) {
	case H3_CONN_IDLE:
		if (new_state != H3_CONN_CONNECTING)
			goto invalid;
		break;

	case H3_CONN_CONNECTING:
		if (new_state != H3_CONN_CONNECTED &&
		    new_state != H3_CONN_CLOSED)
			goto invalid;
		break;

	case H3_CONN_CONNECTED:
		if (new_state != H3_CONN_GOAWAY_SENT &&
		    new_state != H3_CONN_GOAWAY_RECVD &&
		    new_state != H3_CONN_CLOSED)
			goto invalid;
		break;

	case H3_CONN_GOAWAY_SENT:
	case H3_CONN_GOAWAY_RECVD:
		if (new_state != H3_CONN_CLOSED)
			goto invalid;
		break;

	case H3_CONN_CLOSED:
		/* Cannot transition out of CLOSED */
		goto invalid;

	default:
		goto invalid;
	}

	h3conn->state = new_state;
	return;

invalid:
	pr_warn_ratelimited("h3: invalid state transition %d -> %d\n",
			    old_state, new_state);
}

/*
 * =============================================================================
 * Control Stream Management
 * =============================================================================
 */

/**
 * h3_create_control_stream - Create local control stream
 * @h3conn: HTTP/3 connection
 *
 * Opens a unidirectional stream and writes the stream type byte.
 *
 * Returns: 0 on success, negative error on failure.
 */
static int h3_create_control_stream(struct tquic_http3_conn *h3conn)
{
	struct tquic_stream *stream;
	u8 stream_type_buf[1];
	int ret;

	/* Open unidirectional stream */
	stream = tquic_stream_open(h3conn->qconn, false);
	if (IS_ERR(stream))
		return PTR_ERR(stream);

	/* Write stream type byte */
	stream_type_buf[0] = H3_STREAM_TYPE_CONTROL;
	ret = tquic_stream_send(stream, stream_type_buf, 1, false);
	if (ret < 0) {
		tquic_stream_close(stream);
		return ret;
	}

	h3conn->ctrl_stream_local = stream;
	return 0;
}

/**
 * h3_create_qpack_streams - Create QPACK encoder/decoder streams
 * @h3conn: HTTP/3 connection
 *
 * Opens the QPACK encoder and decoder unidirectional streams.
 * These are optional but required if QPACK dynamic table is used.
 *
 * Returns: 0 on success, negative error on failure.
 */
static int h3_create_qpack_streams(struct tquic_http3_conn *h3conn)
{
	struct tquic_stream *enc_stream, *dec_stream;
	u8 stream_type_buf[1];
	int ret;

	/* Skip if dynamic table is disabled */
	if (h3conn->local_settings.qpack_max_table_capacity == 0 &&
	    h3conn->local_settings.qpack_blocked_streams == 0)
		return 0;

	/* Create encoder stream */
	enc_stream = tquic_stream_open(h3conn->qconn, false);
	if (IS_ERR(enc_stream))
		return PTR_ERR(enc_stream);

	stream_type_buf[0] = H3_STREAM_TYPE_QPACK_ENCODER;
	ret = tquic_stream_send(enc_stream, stream_type_buf, 1, false);
	if (ret < 0) {
		tquic_stream_close(enc_stream);
		return ret;
	}

	/* Create decoder stream */
	dec_stream = tquic_stream_open(h3conn->qconn, false);
	if (IS_ERR(dec_stream)) {
		tquic_stream_close(enc_stream);
		return PTR_ERR(dec_stream);
	}

	stream_type_buf[0] = H3_STREAM_TYPE_QPACK_DECODER;
	ret = tquic_stream_send(dec_stream, stream_type_buf, 1, false);
	if (ret < 0) {
		tquic_stream_close(enc_stream);
		tquic_stream_close(dec_stream);
		return ret;
	}

	h3conn->qpack_enc_stream = enc_stream;
	h3conn->qpack_dec_stream = dec_stream;
	return 0;
}

/**
 * h3_send_settings - Send SETTINGS frame on control stream
 * @h3conn: HTTP/3 connection
 *
 * SETTINGS must be the first frame sent on the control stream.
 *
 * Returns: 0 on success, negative error on failure.
 */
static int h3_send_settings(struct tquic_http3_conn *h3conn)
{
	u8 buf[256];  /* Plenty for SETTINGS frame */
	int ret;

	if (!h3conn->ctrl_stream_local)
		return -EINVAL;

	ret = tquic_h3_write_settings_frame(buf, sizeof(buf),
					    &h3conn->local_settings);
	if (ret < 0)
		return ret;

	return tquic_stream_send(h3conn->ctrl_stream_local, buf, ret, false);
}

/*
 * =============================================================================
 * Control Stream Frame Processing
 * =============================================================================
 */

/**
 * h3_process_settings_frame - Process received SETTINGS frame
 * @h3conn: HTTP/3 connection
 * @frame: Parsed SETTINGS frame
 *
 * Returns: 0 on success, negative error on failure.
 */
static int h3_process_settings_frame(struct tquic_http3_conn *h3conn,
				     const struct tquic_h3_frame *frame)
{
	u32 i;

	if (h3conn->peer_settings_received) {
		/* Duplicate SETTINGS is a protocol error */
		return -H3_FRAME_UNEXPECTED;
	}

	/* Process settings entries */
	for (i = 0; i < frame->settings.count; i++) {
		u64 id = frame->settings.entries[i].id;
		u64 value = frame->settings.entries[i].value;

		switch (id) {
		case H3_SETTINGS_QPACK_MAX_TABLE_CAPACITY:
			if (value > H3_MAX_QPACK_TABLE_CAPACITY)
				return -H3_SETTINGS_ERROR;
			h3conn->peer_settings.qpack_max_table_capacity = value;
			break;

		case H3_SETTINGS_MAX_FIELD_SECTION_SIZE:
			h3conn->peer_settings.max_field_section_size = value;
			break;

		case H3_SETTINGS_QPACK_BLOCKED_STREAMS:
			if (value > H3_MAX_QPACK_BLOCKED_STREAMS)
				return -H3_SETTINGS_ERROR;
			h3conn->peer_settings.qpack_blocked_streams = value;
			break;

		default:
			/* Unknown settings are ignored */
			break;
		}
	}

	h3conn->peer_settings_received = true;

	/* Transition to CONNECTED if we were waiting for settings */
	if (h3conn->state == H3_CONN_CONNECTING)
		h3_conn_set_state(h3conn, H3_CONN_CONNECTED);

	return 0;
}

/**
 * h3_process_goaway_frame - Process received GOAWAY frame
 * @h3conn: HTTP/3 connection
 * @frame: Parsed GOAWAY frame
 *
 * Returns: 0 on success, negative error on failure.
 */
/**
 * h3_cancel_pending_pushes - Cancel all pending pushes
 * @h3conn: HTTP/3 connection
 * @after_push_id: Cancel pushes with ID > this value
 *
 * Called during graceful shutdown to cancel pushes that won't be serviced.
 * Must be called with h3conn->lock held.
 */
static void h3_cancel_pending_pushes(struct tquic_http3_conn *h3conn,
				     u64 after_push_id)
{
	struct list_head *head;
	struct h3_push_entry *entry;

	if (!h3conn->push_entries)
		return;

	head = (struct list_head *)h3conn->push_entries;

	list_for_each_entry(entry, head, node) {
		if (entry->push_id > after_push_id &&
		    entry->state != H3_PUSH_STATE_CANCELLED &&
		    entry->state != H3_PUSH_STATE_COMPLETE) {
			h3_push_entry_cancel(h3conn, entry);
		}
	}
}

static int h3_process_goaway_frame(struct tquic_http3_conn *h3conn,
				   const struct tquic_h3_frame *frame)
{
	u64 goaway_id = frame->goaway.id;

	/*
	 * RFC 9114 Section 5.2: GOAWAY
	 *
	 * For clients: ID is the largest stream ID that might be processed
	 * For servers: ID is the largest push ID that might be used
	 *
	 * Subsequent GOAWAY frames may decrease the ID but never increase it.
	 */
	if (h3conn->is_server) {
		/* Client sent GOAWAY with stream ID */
		if ((goaway_id & 0x3) != 0) {
			/* Must be client-initiated bidirectional stream */
			return -H3_ID_ERROR;
		}
	} else {
		/* Server sent GOAWAY with push ID */
		/* Push ID must not exceed what we granted */
		if (h3conn->push_enabled && goaway_id > h3conn->max_push_id)
			return -H3_ID_ERROR;
	}

	/*
	 * Per RFC 9114: the ID in subsequent GOAWAY frames must not increase
	 */
	if (h3conn->goaway_received && goaway_id > h3conn->goaway_id) {
		pr_warn("h3: GOAWAY ID increased from %llu to %llu\n",
			h3conn->goaway_id, goaway_id);
		return -H3_ID_ERROR;
	}

	h3conn->goaway_id = goaway_id;
	h3conn->goaway_received = true;

	if (h3conn->state == H3_CONN_CONNECTED)
		h3_conn_set_state(h3conn, H3_CONN_GOAWAY_RECVD);

	/*
	 * Cancel pending pushes that won't be serviced.
	 * For client: pushes with ID > goaway_id won't be processed
	 * For server: requests with stream ID > goaway_id won't be processed
	 */
	if (!h3conn->is_server && h3conn->push_enabled) {
		h3_cancel_pending_pushes(h3conn, goaway_id);
	}

	pr_debug("h3: received GOAWAY id=%llu\n", goaway_id);

	return 0;
}

/**
 * h3_process_max_push_id_frame - Process MAX_PUSH_ID frame
 * @h3conn: HTTP/3 connection
 * @frame: Parsed MAX_PUSH_ID frame
 *
 * Only valid for servers receiving from clients.
 *
 * Returns: 0 on success, negative error on failure.
 */
static int h3_process_max_push_id_frame(struct tquic_http3_conn *h3conn,
					const struct tquic_h3_frame *frame)
{
	if (!h3conn->is_server)
		return -H3_FRAME_UNEXPECTED;

	/* Push ID must not decrease */
	if (frame->max_push_id.push_id < h3conn->max_push_id)
		return -H3_ID_ERROR;

	h3conn->max_push_id = frame->max_push_id.push_id;
	h3conn->push_enabled = true;

	return 0;
}

/*
 * =============================================================================
 * Server Push State Tracking (RFC 9114 Section 4.6)
 * =============================================================================
 *
 * Push states:
 *   PROMISED - PUSH_PROMISE sent/received but push stream not yet opened
 *   ACTIVE   - Push stream is open and transmitting
 *   CANCELLED - Push was cancelled via CANCEL_PUSH frame
 *   COMPLETE - Push stream finished successfully
 */

#define H3_PUSH_MAX_TRACKED	256	/* Max concurrent pushes tracked */

enum h3_push_entry_state {
	H3_PUSH_STATE_PROMISED = 0,
	H3_PUSH_STATE_ACTIVE,
	H3_PUSH_STATE_CANCELLED,
	H3_PUSH_STATE_COMPLETE,
};

/**
 * struct h3_push_entry - Tracks a single server push
 * @push_id: Unique push identifier
 * @state: Current push state
 * @request_stream_id: Associated request stream (for PUSH_PROMISE)
 * @push_stream: Push stream (if opened)
 * @node: List linkage in push_entries
 */
struct h3_push_entry {
	u64 push_id;
	enum h3_push_entry_state state;
	u64 request_stream_id;
	struct tquic_stream *push_stream;
	struct list_head node;
};

/**
 * h3_push_entry_find - Find push entry by push_id
 * @h3conn: HTTP/3 connection
 * @push_id: Push ID to find
 *
 * Must be called with h3conn->lock held.
 * Returns: Push entry or NULL if not found.
 */
static struct h3_push_entry *h3_push_entry_find(struct tquic_http3_conn *h3conn,
						u64 push_id)
{
	struct h3_push_entry *entry;
	struct list_head *head;

	/* Push entries stored in connection's extended data */
	head = (struct list_head *)h3conn->push_entries;
	if (!head)
		return NULL;

	list_for_each_entry(entry, head, node) {
		if (entry->push_id == push_id)
			return entry;
	}

	return NULL;
}

/**
 * h3_push_entry_create - Create a new push entry
 * @h3conn: HTTP/3 connection
 * @push_id: Push ID for this entry
 * @request_stream_id: Associated request stream
 *
 * Must be called with h3conn->lock held.
 * Returns: New push entry or NULL on failure.
 */
static struct h3_push_entry *h3_push_entry_create(struct tquic_http3_conn *h3conn,
						  u64 push_id,
						  u64 request_stream_id)
{
	struct h3_push_entry *entry;
	struct list_head *head;

	/* Initialize push list if needed */
	if (!h3conn->push_entries) {
		head = kzalloc(sizeof(*head), GFP_ATOMIC);
		if (!head)
			return NULL;
		INIT_LIST_HEAD(head);
		h3conn->push_entries = head;
	}

	head = (struct list_head *)h3conn->push_entries;

	/* Check if push ID already exists */
	entry = h3_push_entry_find(h3conn, push_id);
	if (entry)
		return NULL;  /* Already exists */

	/* Check limit with early-out to avoid full O(n) traversal */
	{
		int count = 0;

		list_for_each_entry(entry, head, node) {
			if (++count >= H3_PUSH_MAX_TRACKED)
				return NULL;  /* Too many pushes */
		}
	}

	entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
	if (!entry)
		return NULL;

	entry->push_id = push_id;
	entry->state = H3_PUSH_STATE_PROMISED;
	entry->request_stream_id = request_stream_id;
	entry->push_stream = NULL;
	INIT_LIST_HEAD(&entry->node);

	list_add_tail(&entry->node, head);

	return entry;
}

/**
 * h3_push_entry_cancel - Cancel a push entry
 * @h3conn: HTTP/3 connection
 * @entry: Push entry to cancel
 *
 * Must be called with h3conn->lock held.
 */
static void h3_push_entry_cancel(struct tquic_http3_conn *h3conn,
				 struct h3_push_entry *entry)
{
	if (!entry)
		return;

	entry->state = H3_PUSH_STATE_CANCELLED;

	/* Reset push stream if active */
	if (entry->push_stream) {
		tquic_stream_reset(entry->push_stream, H3_REQUEST_CANCELLED);
		entry->push_stream = NULL;
	}

	pr_debug("h3: cancelled push_id=%llu\n", entry->push_id);
}

/**
 * h3_push_entry_remove - Remove and free a push entry
 * @entry: Push entry to remove
 *
 * Must be called with h3conn->lock held.
 */
static void h3_push_entry_remove(struct h3_push_entry *entry)
{
	if (!entry)
		return;

	list_del(&entry->node);
	kfree(entry);
}

/**
 * h3_process_cancel_push_frame - Process CANCEL_PUSH frame
 * @h3conn: HTTP/3 connection
 * @frame: Parsed CANCEL_PUSH frame
 *
 * CANCEL_PUSH cancels a server push before it completes.
 * - Client sends CANCEL_PUSH to reject a promised push
 * - Server sends CANCEL_PUSH to abort a push it promised
 *
 * Returns: 0 on success, negative error on failure.
 */
static int h3_process_cancel_push_frame(struct tquic_http3_conn *h3conn,
					const struct tquic_h3_frame *frame)
{
	u64 push_id = frame->cancel_push.push_id;
	struct h3_push_entry *entry;

	/*
	 * RFC 9114 Section 7.2.3: CANCEL_PUSH
	 *
	 * The push ID must have been previously promised (server) or
	 * within the max_push_id range (client cancelling).
	 */
	if (!h3conn->is_server) {
		/* Client: we can only cancel pushes we've been promised */
		if (!h3conn->push_enabled)
			return -H3_ID_ERROR;

		/* Find the promised push */
		entry = h3_push_entry_find(h3conn, push_id);
		if (!entry) {
			/*
			 * Push not found - could be a push we already
			 * processed or one that was never promised.
			 * Per RFC 9114, unknown push IDs are protocol errors.
			 */
			pr_debug("h3: CANCEL_PUSH for unknown push_id=%llu\n",
				 push_id);
			return -H3_ID_ERROR;
		}

		/* Cancel it */
		h3_push_entry_cancel(h3conn, entry);

	} else {
		/* Server: client is cancelling a push we promised */
		if (push_id > h3conn->next_push_id) {
			/*
			 * Push ID exceeds what we've promised - protocol error
			 */
			return -H3_ID_ERROR;
		}

		entry = h3_push_entry_find(h3conn, push_id);
		if (entry) {
			/* Cancel the push */
			h3_push_entry_cancel(h3conn, entry);
		}
		/*
		 * If entry not found, push may have already completed
		 * or was never tracked. This is not an error.
		 */
	}

	pr_debug("h3: processed CANCEL_PUSH push_id=%llu\n", push_id);

	return 0;
}

/**
 * h3_process_priority_update_frame - Process PRIORITY_UPDATE frame (RFC 9218)
 * @h3conn: HTTP/3 connection
 * @frame: Parsed frame (contains raw payload pointer)
 *
 * Returns: 0 on success, negative error on failure.
 */
static int h3_process_priority_update_frame(struct tquic_http3_conn *h3conn,
					    const struct tquic_h3_frame *frame)
{
	/* Check if priorities are enabled in settings */
	if (!h3conn->local_settings.enable_priority)
		return 0;  /* Ignore if disabled */

	/* The frame payload needs to be parsed via http3_priority.c */
	/* For now, we'll delegate to the priority update handler */
	/* The raw data would come from the frame->data field */

	pr_debug("h3: received PRIORITY_UPDATE frame\n");

	return 0;
}

/**
 * h3_process_control_frame - Process frame from control stream
 * @h3conn: HTTP/3 connection
 * @frame: Parsed frame
 *
 * Dispatches control stream frames to appropriate handlers.
 *
 * Returns: 0 on success, negative error on failure.
 */
static int h3_process_control_frame(struct tquic_http3_conn *h3conn,
				    const struct tquic_h3_frame *frame)
{
	/* Validate frame type is allowed on control stream */
	if (!h3_frame_valid_on_control_stream(frame->type)) {
		return -H3_FRAME_UNEXPECTED;
	}

	switch (frame->type) {
	case H3_FRAME_SETTINGS:
		return h3_process_settings_frame(h3conn, frame);

	case H3_FRAME_GOAWAY:
		return h3_process_goaway_frame(h3conn, frame);

	case H3_FRAME_MAX_PUSH_ID:
		return h3_process_max_push_id_frame(h3conn, frame);

	case H3_FRAME_CANCEL_PUSH:
		return h3_process_cancel_push_frame(h3conn, frame);

	case TQUIC_H3_FRAME_PRIORITY_UPDATE:
		return h3_process_priority_update_frame(h3conn, frame);

	default:
		/* Unknown/GREASE frames are ignored */
		return 0;
	}
}

/*
 * =============================================================================
 * HTTP/3 Connection Lifecycle
 * =============================================================================
 */

/**
 * tquic_h3_conn_create - Create HTTP/3 connection over QUIC
 * @qconn: Underlying QUIC connection
 * @is_server: True if server-side
 * @settings: Local settings (or NULL for defaults)
 * @gfp: Memory allocation flags
 *
 * Returns: HTTP/3 connection on success, ERR_PTR on failure.
 */
struct tquic_http3_conn *tquic_h3_conn_create(struct tquic_connection *qconn,
					      bool is_server,
					      const struct tquic_h3_settings *settings,
					      gfp_t gfp)
{
	struct tquic_http3_conn *h3conn;
	int ret;

	if (!qconn)
		return ERR_PTR(-EINVAL);

	h3conn = kzalloc(sizeof(*h3conn), gfp);
	if (!h3conn)
		return ERR_PTR(-ENOMEM);

	h3conn->qconn = qconn;
	h3conn->is_server = is_server;
	h3conn->state = H3_CONN_IDLE;

	spin_lock_init(&h3conn->lock);
	refcount_set(&h3conn->refcnt, 1);

	/* Initialize local settings */
	if (settings)
		memcpy(&h3conn->local_settings, settings,
		       sizeof(h3conn->local_settings));
	else
		tquic_h3_settings_init(&h3conn->local_settings);

	/* Initialize peer settings to defaults */
	tquic_h3_settings_init(&h3conn->peer_settings);

	/* Initialize priority tree for RFC 9218 extensible priorities */
	if (h3conn->local_settings.enable_priority) {
		h3conn->priority_tree = kzalloc(sizeof(*h3conn->priority_tree),
						gfp);
		if (h3conn->priority_tree)
			tquic_h3_priority_tree_init(h3conn->priority_tree);
	}

	/* Transition to CONNECTING */
	h3_conn_set_state(h3conn, H3_CONN_CONNECTING);

	/* Create control stream */
	ret = h3_create_control_stream(h3conn);
	if (ret < 0)
		goto err_free;

	/* Create QPACK streams if needed */
	ret = h3_create_qpack_streams(h3conn);
	if (ret < 0)
		goto err_close_ctrl;

	/* Send our SETTINGS */
	ret = h3_send_settings(h3conn);
	if (ret < 0)
		goto err_close_qpack;

	return h3conn;

err_close_qpack:
	if (h3conn->qpack_enc_stream)
		tquic_stream_close(h3conn->qpack_enc_stream);
	if (h3conn->qpack_dec_stream)
		tquic_stream_close(h3conn->qpack_dec_stream);
err_close_ctrl:
	tquic_stream_close(h3conn->ctrl_stream_local);
err_free:
	kfree(h3conn);
	return ERR_PTR(ret);
}
EXPORT_SYMBOL_GPL(tquic_h3_conn_create);

/**
 * tquic_h3_conn_destroy - Destroy HTTP/3 connection
 * @h3conn: HTTP/3 connection
 */
void tquic_h3_conn_destroy(struct tquic_http3_conn *h3conn)
{
	if (!h3conn)
		return;

	spin_lock_bh(&h3conn->lock);
	h3_conn_set_state(h3conn, H3_CONN_CLOSED);
	spin_unlock_bh(&h3conn->lock);

	/* Close our streams (don't close remote streams) */
	if (h3conn->ctrl_stream_local)
		tquic_stream_close(h3conn->ctrl_stream_local);
	if (h3conn->qpack_enc_stream)
		tquic_stream_close(h3conn->qpack_enc_stream);
	if (h3conn->qpack_dec_stream)
		tquic_stream_close(h3conn->qpack_dec_stream);

	/* Destroy priority tree */
	if (h3conn->priority_tree) {
		tquic_h3_priority_tree_destroy(h3conn->priority_tree);
		kfree(h3conn->priority_tree);
	}

	/* Clean up push entries */
	h3_cleanup_push_entries(h3conn);

	/* Destroy priority state on underlying QUIC connection */
	if (h3conn->qconn)
		http3_priority_state_destroy(h3conn->qconn);

	kfree(h3conn);
}
EXPORT_SYMBOL_GPL(tquic_h3_conn_destroy);

/**
 * tquic_h3_conn_put - Decrement reference count
 * @h3conn: HTTP/3 connection
 */
void tquic_h3_conn_put(struct tquic_http3_conn *h3conn)
{
	if (h3conn && refcount_dec_and_test(&h3conn->refcnt))
		tquic_h3_conn_destroy(h3conn);
}
EXPORT_SYMBOL_GPL(tquic_h3_conn_put);

/*
 * =============================================================================
 * Connection Polling and Event Processing
 * =============================================================================
 */

/**
 * h3_poll_control_stream - Process data from remote control stream
 * @h3conn: HTTP/3 connection
 *
 * Returns: 0 on success, negative error on failure.
 */
static int h3_poll_control_stream(struct tquic_http3_conn *h3conn)
{
	u8 buf[H3_CTRL_STREAM_BUF_SIZE];
	struct tquic_h3_frame frame;
	struct tquic_h3_frame_settings_entry entries[H3_MAX_SETTINGS_COUNT];
	int len, consumed;
	int ret = 0;

	if (!h3conn->ctrl_stream_remote)
		return 0;

	/* Read available data */
	len = tquic_stream_recv(h3conn->ctrl_stream_remote, buf, sizeof(buf));
	if (len <= 0)
		return len;

	/* Parse and process frames */
	consumed = 0;
	while (consumed < len) {
		ret = tquic_h3_parse_frame(buf + consumed, len - consumed,
					   &frame, entries,
					   ARRAY_SIZE(entries));
		if (ret == -EAGAIN) {
			/* Need more data, wait for next poll */
			ret = 0;
			break;
		}
		if (ret < 0)
			break;

		consumed += ret;

		ret = h3_process_control_frame(h3conn, &frame);
		if (ret < 0)
			break;
	}

	return ret;
}

/**
 * tquic_h3_conn_poll - Process pending HTTP/3 events
 * @h3conn: HTTP/3 connection
 *
 * Returns: 0 on success, negative error on failure.
 */
int tquic_h3_conn_poll(struct tquic_http3_conn *h3conn)
{
	int ret;

	if (!h3conn)
		return -EINVAL;

	spin_lock_bh(&h3conn->lock);

	if (h3conn->state == H3_CONN_CLOSED) {
		spin_unlock_bh(&h3conn->lock);
		return -ENOTCONN;
	}

	/* Process control stream */
	ret = h3_poll_control_stream(h3conn);

	spin_unlock_bh(&h3conn->lock);

	return ret;
}
EXPORT_SYMBOL_GPL(tquic_h3_conn_poll);

/*
 * =============================================================================
 * Graceful Shutdown (GOAWAY)
 * =============================================================================
 */

/**
 * tquic_h3_send_goaway - Send GOAWAY frame
 * @h3conn: HTTP/3 connection
 * @id: Last stream/push ID to process
 *
 * Returns: 0 on success, negative error on failure.
 */
int tquic_h3_send_goaway(struct tquic_http3_conn *h3conn, u64 id)
{
	u8 buf[32];
	int len;
	int ret;

	if (!h3conn || !h3conn->ctrl_stream_local)
		return -EINVAL;

	spin_lock_bh(&h3conn->lock);

	if (h3conn->state != H3_CONN_CONNECTED) {
		spin_unlock_bh(&h3conn->lock);
		return -EINVAL;
	}

	len = tquic_h3_write_goaway_frame(buf, sizeof(buf), id);
	if (len < 0) {
		spin_unlock_bh(&h3conn->lock);
		return len;
	}

	ret = tquic_stream_send(h3conn->ctrl_stream_local, buf, len, false);
	if (ret < 0) {
		spin_unlock_bh(&h3conn->lock);
		return ret;
	}

	h3conn->goaway_id = id;
	h3conn->goaway_sent = true;
	h3_conn_set_state(h3conn, H3_CONN_GOAWAY_SENT);

	spin_unlock_bh(&h3conn->lock);

	pr_debug("h3: sent GOAWAY id=%llu\n", id);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_h3_send_goaway);

/**
 * tquic_h3_graceful_shutdown - Initiate graceful HTTP/3 shutdown
 * @h3conn: HTTP/3 connection
 *
 * Initiates a graceful shutdown per RFC 9114 Section 5.2:
 * 1. Sends initial GOAWAY with max possible ID
 * 2. Allows in-flight requests to complete
 * 3. Eventually sends final GOAWAY with actual last processed ID
 *
 * For servers: sends stream ID of last request that may be processed
 * For clients: sends push ID of last push that may be accepted
 *
 * Returns: 0 on success, negative error on failure.
 */
int tquic_h3_graceful_shutdown(struct tquic_http3_conn *h3conn)
{
	u64 initial_id;
	int ret;

	if (!h3conn)
		return -EINVAL;

	spin_lock_bh(&h3conn->lock);

	/* Already shutting down? */
	if (h3conn->goaway_sent) {
		spin_unlock_bh(&h3conn->lock);
		return 0;
	}

	/*
	 * RFC 9114 Section 5.2: Graceful Shutdown
	 *
	 * "An endpoint that wishes to begin a graceful connection shutdown
	 * can send a GOAWAY frame with a value that is greater than or
	 * equal to the peer's last request identifier."
	 *
	 * We use the maximum possible value initially to signal shutdown
	 * while allowing current requests to complete.
	 */
	if (h3conn->is_server) {
		/* Server: use max stream ID (client-initiated bidi) */
		initial_id = 0x3FFFFFFFFFFFFFFFULL & ~0x3ULL;  /* Max valid stream ID */
	} else {
		/* Client: use current max_push_id or 0 if push not enabled */
		initial_id = h3conn->push_enabled ? h3conn->max_push_id : 0;
	}

	spin_unlock_bh(&h3conn->lock);

	/* Send initial GOAWAY */
	ret = tquic_h3_send_goaway(h3conn, initial_id);
	if (ret < 0)
		return ret;

	pr_debug("h3: initiated graceful shutdown with id=%llu\n", initial_id);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_h3_graceful_shutdown);

/**
 * tquic_h3_complete_shutdown - Complete graceful shutdown with final GOAWAY
 * @h3conn: HTTP/3 connection
 * @final_id: Final ID (last stream/push ID processed)
 *
 * Completes a graceful shutdown by sending a final GOAWAY with the actual
 * last processed identifier. Should be called after all in-flight requests
 * have completed.
 *
 * Returns: 0 on success, negative error on failure.
 */
int tquic_h3_complete_shutdown(struct tquic_http3_conn *h3conn, u64 final_id)
{
	u8 buf[32];
	int len;
	int ret;

	if (!h3conn || !h3conn->ctrl_stream_local)
		return -EINVAL;

	spin_lock_bh(&h3conn->lock);

	/* Must have already sent initial GOAWAY */
	if (!h3conn->goaway_sent) {
		spin_unlock_bh(&h3conn->lock);
		return -EINVAL;
	}

	/* Final ID must not exceed previous GOAWAY ID */
	if (final_id > h3conn->goaway_id) {
		spin_unlock_bh(&h3conn->lock);
		pr_err("h3: final GOAWAY ID %llu > previous %llu\n",
		       final_id, h3conn->goaway_id);
		return -EINVAL;
	}

	spin_unlock_bh(&h3conn->lock);

	/* Send final GOAWAY */
	len = tquic_h3_write_goaway_frame(buf, sizeof(buf), final_id);
	if (len < 0)
		return len;

	ret = tquic_stream_send(h3conn->ctrl_stream_local, buf, len, false);
	if (ret < 0)
		return ret;

	spin_lock_bh(&h3conn->lock);
	h3conn->goaway_id = final_id;
	spin_unlock_bh(&h3conn->lock);

	pr_debug("h3: completed shutdown with final id=%llu\n", final_id);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_h3_complete_shutdown);

/**
 * tquic_h3_is_shutting_down - Check if connection is shutting down
 * @h3conn: HTTP/3 connection
 *
 * Returns: true if GOAWAY has been sent or received.
 */
bool tquic_h3_is_shutting_down(struct tquic_http3_conn *h3conn)
{
	bool shutting_down;

	if (!h3conn)
		return true;

	spin_lock_bh(&h3conn->lock);
	shutting_down = h3conn->goaway_sent || h3conn->goaway_received;
	spin_unlock_bh(&h3conn->lock);

	return shutting_down;
}
EXPORT_SYMBOL_GPL(tquic_h3_is_shutting_down);

/**
 * tquic_h3_can_create_stream - Check if new streams can be created
 * @h3conn: HTTP/3 connection
 * @stream_id: Proposed stream ID
 *
 * Checks if a new stream can be created considering GOAWAY state.
 *
 * Returns: true if stream can be created.
 */
bool tquic_h3_can_create_stream(struct tquic_http3_conn *h3conn, u64 stream_id)
{
	bool can_create;

	if (!h3conn)
		return false;

	spin_lock_bh(&h3conn->lock);

	/* If peer sent GOAWAY, check stream ID against goaway_id */
	if (h3conn->goaway_received) {
		if (h3conn->is_server) {
			/* Server: client's GOAWAY contains stream ID */
			can_create = (stream_id <= h3conn->goaway_id);
		} else {
			/* Client: server's GOAWAY contains push ID - always allow new requests */
			can_create = true;
		}
	} else {
		can_create = (h3conn->state == H3_CONN_CONNECTED);
	}

	spin_unlock_bh(&h3conn->lock);

	return can_create;
}
EXPORT_SYMBOL_GPL(tquic_h3_can_create_stream);

/**
 * tquic_h3_set_max_push_id - Set maximum push ID (client only)
 * @h3conn: HTTP/3 connection
 * @push_id: Maximum push ID to allow
 *
 * Returns: 0 on success, negative error on failure.
 */
int tquic_h3_set_max_push_id(struct tquic_http3_conn *h3conn, u64 push_id)
{
	u8 buf[32];
	int len;
	int ret;

	if (!h3conn || !h3conn->ctrl_stream_local)
		return -EINVAL;

	/* Only clients send MAX_PUSH_ID */
	if (h3conn->is_server)
		return -EINVAL;

	spin_lock_bh(&h3conn->lock);

	if (h3conn->state != H3_CONN_CONNECTED) {
		spin_unlock_bh(&h3conn->lock);
		return -EINVAL;
	}

	/* Push ID must not decrease */
	if (h3conn->push_enabled && push_id < h3conn->max_push_id) {
		spin_unlock_bh(&h3conn->lock);
		return -EINVAL;
	}

	len = tquic_h3_write_max_push_id_frame(buf, sizeof(buf), push_id);
	if (len < 0) {
		spin_unlock_bh(&h3conn->lock);
		return len;
	}

	ret = tquic_stream_send(h3conn->ctrl_stream_local, buf, len, false);
	if (ret < 0) {
		spin_unlock_bh(&h3conn->lock);
		return ret;
	}

	h3conn->max_push_id = push_id;
	h3conn->push_enabled = true;

	spin_unlock_bh(&h3conn->lock);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_h3_set_max_push_id);

/*
 * =============================================================================
 * Server Push API (RFC 9114 Section 4.6)
 * =============================================================================
 */

/**
 * tquic_h3_send_push_promise - Send PUSH_PROMISE frame (server only)
 * @h3conn: HTTP/3 connection
 * @request_stream: Request stream to send PUSH_PROMISE on
 * @headers: QPACK-encoded request headers for the push
 * @headers_len: Length of encoded headers
 * @push_id_out: Output parameter for assigned push ID
 *
 * Sends a PUSH_PROMISE frame on the specified request stream to announce
 * a server push. The push ID is automatically assigned.
 *
 * Returns: 0 on success, negative error on failure.
 */
int tquic_h3_send_push_promise(struct tquic_http3_conn *h3conn,
			       struct tquic_stream *request_stream,
			       const u8 *headers, size_t headers_len,
			       u64 *push_id_out)
{
	u8 *buf;
	size_t buf_size;
	u64 push_id;
	struct h3_push_entry *entry;
	int len;
	int ret;

	if (!h3conn || !request_stream || !headers || headers_len == 0)
		return -EINVAL;

	/* Only servers can send PUSH_PROMISE */
	if (!h3conn->is_server) {
		pr_err("h3: only server can send PUSH_PROMISE\n");
		return -EINVAL;
	}

	spin_lock_bh(&h3conn->lock);

	/* Check connection state */
	if (h3conn->state != H3_CONN_CONNECTED) {
		spin_unlock_bh(&h3conn->lock);
		return -ENOTCONN;
	}

	/* Check if we're shutting down */
	if (h3conn->goaway_sent || h3conn->goaway_received) {
		spin_unlock_bh(&h3conn->lock);
		return -ECONNRESET;
	}

	/* Check if push is enabled and we have IDs available */
	if (!h3conn->push_enabled || h3conn->next_push_id > h3conn->max_push_id) {
		spin_unlock_bh(&h3conn->lock);
		pr_debug("h3: push not enabled or push_id exhausted\n");
		return -EAGAIN;
	}

	/* Allocate push ID */
	push_id = h3conn->next_push_id++;

	/* Create push entry to track this push */
	entry = h3_push_entry_create(h3conn, push_id, request_stream->id);
	if (!entry) {
		h3conn->next_push_id--;  /* Rollback */
		spin_unlock_bh(&h3conn->lock);
		return -ENOMEM;
	}

	spin_unlock_bh(&h3conn->lock);

	/* Allocate buffer for PUSH_PROMISE frame */
	buf_size = tquic_h3_push_promise_frame_size(push_id, headers_len);
	buf = kmalloc(buf_size, GFP_KERNEL);
	if (!buf) {
		spin_lock_bh(&h3conn->lock);
		h3_push_entry_remove(entry);
		spin_unlock_bh(&h3conn->lock);
		return -ENOMEM;
	}

	/* Write PUSH_PROMISE frame */
	len = tquic_h3_write_push_promise_frame(buf, buf_size, push_id,
						headers, headers_len);
	if (len < 0) {
		kfree(buf);
		spin_lock_bh(&h3conn->lock);
		h3_push_entry_remove(entry);
		spin_unlock_bh(&h3conn->lock);
		return len;
	}

	/* Send on request stream */
	ret = tquic_stream_send(request_stream, buf, len, false);
	kfree(buf);

	if (ret < 0) {
		spin_lock_bh(&h3conn->lock);
		h3_push_entry_remove(entry);
		spin_unlock_bh(&h3conn->lock);
		return ret;
	}

	if (push_id_out)
		*push_id_out = push_id;

	pr_debug("h3: sent PUSH_PROMISE push_id=%llu on stream %llu\n",
		 push_id, request_stream->id);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_h3_send_push_promise);

/**
 * tquic_h3_create_push_stream - Create push stream for promised push
 * @h3conn: HTTP/3 connection
 * @push_id: Push ID from PUSH_PROMISE
 * @stream_out: Output parameter for created stream
 *
 * Creates the unidirectional push stream for delivering pushed content.
 * Must be called after sending PUSH_PROMISE with the same push_id.
 *
 * Returns: 0 on success, negative error on failure.
 */
int tquic_h3_create_push_stream(struct tquic_http3_conn *h3conn,
				u64 push_id,
				struct tquic_stream **stream_out)
{
	struct tquic_stream *push_stream;
	struct h3_push_entry *entry;
	u8 header[16];
	int header_len;
	int ret;

	if (!h3conn || !stream_out)
		return -EINVAL;

	/* Only servers create push streams */
	if (!h3conn->is_server)
		return -EINVAL;

	spin_lock_bh(&h3conn->lock);

	/* Find the push entry */
	entry = h3_push_entry_find(h3conn, push_id);
	if (!entry) {
		spin_unlock_bh(&h3conn->lock);
		pr_err("h3: push_id %llu not found\n", push_id);
		return -ENOENT;
	}

	/* Check state */
	if (entry->state != H3_PUSH_STATE_PROMISED) {
		spin_unlock_bh(&h3conn->lock);
		pr_err("h3: push_id %llu in wrong state %d\n",
		       push_id, entry->state);
		return -EINVAL;
	}

	/* Check if cancelled */
	if (entry->state == H3_PUSH_STATE_CANCELLED) {
		spin_unlock_bh(&h3conn->lock);
		return -ECANCELED;
	}

	spin_unlock_bh(&h3conn->lock);

	/* Open unidirectional push stream */
	push_stream = tquic_stream_open(h3conn->qconn, false);
	if (IS_ERR(push_stream))
		return PTR_ERR(push_stream);

	/*
	 * Push stream header format (RFC 9114 Section 4.6):
	 *   Stream Type (varint 0x01) || Push ID (varint)
	 */
	header[0] = H3_STREAM_TYPE_PUSH;  /* Stream type */
	header_len = 1;

	/* Encode push ID as varint */
	if (push_id <= 63) {
		header[header_len++] = (u8)push_id;
	} else if (push_id <= 16383) {
		header[header_len++] = 0x40 | (u8)(push_id >> 8);
		header[header_len++] = (u8)push_id;
	} else if (push_id <= 1073741823) {
		header[header_len++] = 0x80 | (u8)(push_id >> 24);
		header[header_len++] = (u8)(push_id >> 16);
		header[header_len++] = (u8)(push_id >> 8);
		header[header_len++] = (u8)push_id;
	} else {
		header[header_len++] = 0xc0 | (u8)(push_id >> 56);
		header[header_len++] = (u8)(push_id >> 48);
		header[header_len++] = (u8)(push_id >> 40);
		header[header_len++] = (u8)(push_id >> 32);
		header[header_len++] = (u8)(push_id >> 24);
		header[header_len++] = (u8)(push_id >> 16);
		header[header_len++] = (u8)(push_id >> 8);
		header[header_len++] = (u8)push_id;
	}

	/* Send push stream header */
	ret = tquic_stream_send(push_stream, header, header_len, false);
	if (ret < 0) {
		tquic_stream_close(push_stream);
		return ret;
	}

	/* Update push entry */
	spin_lock_bh(&h3conn->lock);
	entry = h3_push_entry_find(h3conn, push_id);
	if (entry) {
		entry->state = H3_PUSH_STATE_ACTIVE;
		entry->push_stream = push_stream;
	}
	spin_unlock_bh(&h3conn->lock);

	*stream_out = push_stream;

	pr_debug("h3: created push stream for push_id=%llu stream_id=%llu\n",
		 push_id, push_stream->id);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_h3_create_push_stream);

/**
 * tquic_h3_send_cancel_push - Send CANCEL_PUSH frame
 * @h3conn: HTTP/3 connection
 * @push_id: Push ID to cancel
 *
 * Server uses this to cancel a push it previously promised.
 * Client uses this to reject a push it was promised.
 *
 * Returns: 0 on success, negative error on failure.
 */
int tquic_h3_send_cancel_push(struct tquic_http3_conn *h3conn, u64 push_id)
{
	u8 buf[32];
	int len;
	int ret;

	if (!h3conn || !h3conn->ctrl_stream_local)
		return -EINVAL;

	spin_lock_bh(&h3conn->lock);

	if (h3conn->state != H3_CONN_CONNECTED) {
		spin_unlock_bh(&h3conn->lock);
		return -ENOTCONN;
	}

	/* Validate push_id */
	if (h3conn->is_server) {
		/* Server can only cancel pushes it promised */
		if (push_id >= h3conn->next_push_id) {
			spin_unlock_bh(&h3conn->lock);
			return -EINVAL;
		}
	} else {
		/* Client can only cancel pushes it was promised */
		if (!h3conn->push_enabled) {
			spin_unlock_bh(&h3conn->lock);
			return -EINVAL;
		}
	}

	spin_unlock_bh(&h3conn->lock);

	/* Build CANCEL_PUSH frame */
	len = tquic_h3_write_cancel_push_frame(buf, sizeof(buf), push_id);
	if (len < 0)
		return len;

	/* Send on control stream */
	ret = tquic_stream_send(h3conn->ctrl_stream_local, buf, len, false);
	if (ret < 0)
		return ret;

	/* Update local push state */
	spin_lock_bh(&h3conn->lock);
	{
		struct h3_push_entry *entry = h3_push_entry_find(h3conn, push_id);
		if (entry)
			h3_push_entry_cancel(h3conn, entry);
	}
	spin_unlock_bh(&h3conn->lock);

	pr_debug("h3: sent CANCEL_PUSH push_id=%llu\n", push_id);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_h3_send_cancel_push);

/**
 * tquic_h3_reject_push - Client rejects a promised push
 * @h3conn: HTTP/3 connection
 * @push_id: Push ID to reject
 *
 * Client-side convenience function to reject a server push.
 * This sends CANCEL_PUSH and marks the push as cancelled locally.
 *
 * Returns: 0 on success, negative error on failure.
 */
int tquic_h3_reject_push(struct tquic_http3_conn *h3conn, u64 push_id)
{
	if (!h3conn)
		return -EINVAL;

	/* Only clients can reject pushes */
	if (h3conn->is_server)
		return -EINVAL;

	return tquic_h3_send_cancel_push(h3conn, push_id);
}
EXPORT_SYMBOL_GPL(tquic_h3_reject_push);

/**
 * h3_cleanup_push_entries - Free all push entries
 * @h3conn: HTTP/3 connection
 *
 * Called during connection cleanup.
 */
static void h3_cleanup_push_entries(struct tquic_http3_conn *h3conn)
{
	struct list_head *head;
	struct h3_push_entry *entry, *tmp;

	if (!h3conn->push_entries)
		return;

	head = (struct list_head *)h3conn->push_entries;

	list_for_each_entry_safe(entry, tmp, head, node) {
		list_del(&entry->node);
		kfree(entry);
	}

	kfree(head);
	h3conn->push_entries = NULL;
}

/*
 * =============================================================================
 * Settings Access
 * =============================================================================
 */

/**
 * tquic_h3_get_peer_settings - Get peer's settings
 * @h3conn: HTTP/3 connection
 * @settings: Output parameter for settings
 *
 * Returns: 0 on success, -EAGAIN if settings not yet received.
 */
int tquic_h3_get_peer_settings(struct tquic_http3_conn *h3conn,
			       struct tquic_h3_settings *settings)
{
	if (!h3conn || !settings)
		return -EINVAL;

	spin_lock_bh(&h3conn->lock);

	if (!h3conn->peer_settings_received) {
		spin_unlock_bh(&h3conn->lock);
		return -EAGAIN;
	}

	memcpy(settings, &h3conn->peer_settings, sizeof(*settings));

	spin_unlock_bh(&h3conn->lock);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_h3_get_peer_settings);

/*
 * =============================================================================
 * Frame Sending Helper
 * =============================================================================
 */

/**
 * tquic_h3_send_frame - Send HTTP/3 frame on stream
 * @h3conn: HTTP/3 connection
 * @stream: QUIC stream to send on
 * @frame: Frame to send
 *
 * Returns: 0 on success, negative error on failure.
 */
int tquic_h3_send_frame(struct tquic_http3_conn *h3conn,
			struct tquic_stream *stream,
			const struct tquic_h3_frame *frame)
{
	u8 *buf;
	size_t size;
	int ret;

	if (!h3conn || !stream || !frame)
		return -EINVAL;

	size = tquic_h3_frame_size(frame);
	if (size == 0)
		return -EINVAL;

	buf = kmalloc(size, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	ret = tquic_h3_write_frame(buf, size, frame);
	if (ret < 0) {
		kfree(buf);
		return ret;
	}

	ret = tquic_stream_send(stream, buf, ret, false);

	kfree(buf);
	return ret < 0 ? ret : 0;
}
EXPORT_SYMBOL_GPL(tquic_h3_send_frame);

/**
 * tquic_h3_write_frame - Write generic frame to buffer
 * @buf: Output buffer
 * @len: Buffer length
 * @frame: Frame to write
 *
 * Returns: Bytes written on success, negative error on failure.
 */
int tquic_h3_write_frame(u8 *buf, size_t len,
			 const struct tquic_h3_frame *frame)
{
	if (!buf || !frame)
		return -EINVAL;

	switch (frame->type) {
	case H3_FRAME_DATA:
		return tquic_h3_write_data_frame(buf, len,
						 frame->data.data,
						 frame->data.len);

	case H3_FRAME_HEADERS:
		return tquic_h3_write_headers_frame(buf, len,
						    frame->headers.data,
						    frame->headers.len);

	case H3_FRAME_CANCEL_PUSH:
		return tquic_h3_write_cancel_push_frame(buf, len,
							frame->cancel_push.push_id);

	case H3_FRAME_GOAWAY:
		return tquic_h3_write_goaway_frame(buf, len, frame->goaway.id);

	case H3_FRAME_MAX_PUSH_ID:
		return tquic_h3_write_max_push_id_frame(buf, len,
							frame->max_push_id.push_id);

	case H3_FRAME_PUSH_PROMISE:
		return tquic_h3_write_push_promise_frame(buf, len,
							 frame->push_promise.push_id,
							 frame->push_promise.data,
							 frame->push_promise.len);

	default:
		return -EINVAL;
	}
}
EXPORT_SYMBOL_GPL(tquic_h3_write_frame);

/*
 * =============================================================================
 * Module Initialization
 * =============================================================================
 */

/**
 * tquic_http3_conn_init - Initialize HTTP/3 connection layer
 */
int __init tquic_http3_conn_init(void)
{
	pr_info("TQUIC HTTP/3: Initializing (RFC 9114)\n");
	return 0;
}
/**
 * tquic_http3_conn_exit - Cleanup HTTP/3 connection layer
 */
void __exit tquic_http3_conn_exit(void)
{
	pr_info("TQUIC HTTP/3: Exiting\n");
}

MODULE_DESCRIPTION("TQUIC HTTP/3 Connection Management");
MODULE_LICENSE("GPL");
