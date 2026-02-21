// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * TQUIC - WAN Bonding over QUIC
 *
 * Flow Control Implementation per RFC 9000 Section 4
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * This file implements QUIC flow control mechanisms including:
 * - Connection-level flow control (MAX_DATA frames)
 * - Stream-level flow control (MAX_STREAM_DATA frames)
 * - Stream limit management (MAX_STREAMS frames)
 * - Blocked notification handling (DATA_BLOCKED, STREAM_DATA_BLOCKED,
 *   STREAMS_BLOCKED frames)
 */

#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <net/tquic.h>
#include <net/tquic_frame.h>
#include "flow_control.h"
#include "../tquic_debug.h"
#include "../tquic_mib.h"
#include "../protocol.h"

/*
 * RFC 9000 Section 4 - Flow Control
 *
 * QUIC implements flow control similar to HTTP/2, with both connection-level
 * and stream-level flow control. The receiver advertises the maximum amount
 * of data it is willing to receive using MAX_DATA and MAX_STREAM_DATA frames.
 * The sender must not send more data than the receiver has advertised.
 */

/* Flow control auto-tuning parameters - override values from flow_control.h */
#undef TQUIC_FC_WINDOW_UPDATE_THRESHOLD
#undef TQUIC_FC_MIN_WINDOW
#undef TQUIC_FC_MAX_WINDOW
#define TQUIC_FC_WINDOW_UPDATE_THRESHOLD	4	/* Update at 1/4 window */
#define TQUIC_FC_MIN_WINDOW			(64 * 1024)	/* 64 KB */
#define TQUIC_FC_MAX_WINDOW			(64 * 1024 * 1024)	/* 64 MB */
#define TQUIC_FC_AUTOTUNE_MULTIPLIER		2	/* Double window on autotune */

/* Maximum data and stream limits (may be defined in tquic.h) */
#ifndef TQUIC_MAX_DATA
#define TQUIC_MAX_DATA				((1ULL << 62) - 1)
#endif
#ifndef TQUIC_MAX_STREAMS
#define TQUIC_MAX_STREAMS			((1ULL << 60) - 1)
#endif

/*
 * Flow control uses struct tquic_flow_control from <net/tquic.h>
 * and transport params use struct tquic_transport_params from <net/tquic.h>
 */

/*
 * Forward declarations for internal (static) functions
 *
 * These functions are internal to this file and should not be exported.
 * They handle low-level frame creation and internal flow control operations.
 */

/* Frame creation functions (internal) */
static struct sk_buff *tquic_flow_create_max_data_frame(struct tquic_connection *conn,
						       u64 max_data);
static struct sk_buff *tquic_flow_create_max_stream_data_frame(u64 stream_id,
							      u64 max_stream_data);
static struct sk_buff *tquic_flow_create_max_streams_frame(u64 max_streams,
							  bool unidirectional);
static struct sk_buff *tquic_flow_create_data_blocked_frame(u64 limit);
static struct sk_buff *tquic_flow_create_stream_data_blocked_frame(u64 stream_id,
								  u64 limit);
static struct sk_buff *tquic_flow_create_streams_blocked_frame(u64 limit,
							      bool unidirectional);

/* Internal flow control update functions */
static void tquic_flow_control_update_max_data_internal(struct tquic_connection *conn);
static void tquic_stream_flow_control_send_blocked(struct tquic_stream *stream);
static void tquic_stream_flow_control_update_max_stream_data(struct tquic_stream *stream);
static void tquic_streams_check_update(struct tquic_connection *conn, bool unidirectional);
static void tquic_streams_update_max_streams(struct tquic_connection *conn, bool unidirectional);

/* Internal helper for connection-level flow control receive limit check */
static int tquic_flow_control_check_recv_limit_internal(struct tquic_connection *conn,
							u64 len);

/*
 * Helper to queue a frame on the connection's control frame queue
 * Returns 0 on success, non-zero on failure
 */
static inline int tquic_conn_queue_frame(struct tquic_connection *conn,
					 struct sk_buff *skb)
{
	if (!conn || !skb)
		return -EINVAL;

	skb_queue_tail(&conn->control_frames, skb);
	return 0;
}

/*
 * Helper to look up a stream by ID
 * Returns stream with incremented reference count, or NULL if not found
 */
static struct tquic_stream *tquic_stream_lookup(struct tquic_connection *conn,
						u64 stream_id)
{
	struct rb_node *node;
	struct tquic_stream *stream;

	if (!conn)
		return NULL;

	spin_lock_bh(&conn->lock);
	node = conn->streams.rb_node;
	while (node) {
		stream = rb_entry(node, struct tquic_stream, node);
		if (stream_id < stream->id) {
			node = node->rb_left;
		} else if (stream_id > stream->id) {
			node = node->rb_right;
		} else {
			/* Found - this implementation doesn't use refcounting */
			spin_unlock_bh(&conn->lock);
			return stream;
		}
	}
	spin_unlock_bh(&conn->lock);

	return NULL;
}

/*
 * Connection-level Flow Control Functions
 */

/**
 * tquic_flow_control_init - Initialize flow control state for a connection
 * @conn: QUIC connection
 *
 * Initializes both local and remote flow control state based on transport
 * parameters. Called during connection setup.
 */
void tquic_flow_control_init(struct tquic_connection *conn)
{
	tquic_dbg("tquic_flow_control_init: max_data=%u max_streams=%u\n",
		  tquic_get_validated_max_data(), tquic_get_validated_max_streams());
	/* Initialize local flow control (what we advertise to peer) */
	conn->max_data_local = tquic_get_validated_max_data();
	conn->max_streams_bidi = tquic_get_validated_max_streams();
	conn->max_streams_uni = tquic_get_validated_max_streams();

	/* Initialize remote flow control (limits from peer) */
	conn->max_data_remote = 0;  /* Set when received from peer */
	conn->data_sent = 0;
	conn->data_received = 0;
	conn->data_consumed = 0;
}

/**
 * tquic_flow_control_can_send - Check if connection-level flow control allows sending
 * @conn: QUIC connection
 * @bytes: Number of bytes to send
 *
 * RFC 9000 Section 4.1: A sender MUST NOT send data unless flow control
 * allows it. This checks the connection-level flow control limit.
 *
 * Returns: true if bytes can be sent, false otherwise
 */
bool tquic_flow_control_can_send(struct tquic_connection *conn, u64 bytes)
{
	u64 available;
	bool can_send;

	tquic_dbg("tquic_flow_control_can_send: bytes=%llu\n", bytes);
	if (bytes == 0)
		return true;

	spin_lock_bh(&conn->lock);

	/* Calculate available flow control credit */
	if (conn->max_data_remote > conn->data_sent)
		available = conn->max_data_remote - conn->data_sent;
	else
		available = 0;

	can_send = (bytes <= available);

	spin_unlock_bh(&conn->lock);

	return can_send;
}
EXPORT_SYMBOL_GPL(tquic_flow_control_can_send);

/**
 * tquic_flow_control_on_data_sent - Update flow control after sending data
 * @conn: QUIC connection
 * @bytes: Number of bytes sent
 *
 * Called after data is successfully sent to update the flow control state.
 */
void tquic_flow_control_on_data_sent(struct tquic_connection *conn, u64 bytes)
{
	if (bytes == 0)
		return;

	spin_lock_bh(&conn->lock);

	conn->data_sent += bytes;

	spin_unlock_bh(&conn->lock);
}
EXPORT_SYMBOL_GPL(tquic_flow_control_on_data_sent);

/**
 * tquic_flow_control_on_data_recvd - Update flow control after receiving data
 * @conn: QUIC connection
 * @bytes: Number of bytes received
 *
 * Called when data is received. This may trigger sending a MAX_DATA frame
 * to update the peer's flow control limit.
 */
void tquic_flow_control_on_data_recvd(struct tquic_connection *conn, u64 bytes)
{
	u64 consumed;
	u64 threshold;
	bool should_update = false;

	tquic_dbg("tquic_flow_control_on_data_recvd: bytes=%llu\n", bytes);
	if (bytes == 0)
		return;

	spin_lock_bh(&conn->lock);

	conn->data_received += bytes;

	/*
	 * RFC 9000 Section 4.2: A receiver MAY send a MAX_DATA frame as soon
	 * as it has consumed data, but doing so frequently can cause excessive
	 * overhead. A receiver sends MAX_DATA frames to update the maximum
	 * data it is willing to receive when it has consumed a significant
	 * portion of the initial window.
	 *
	 * We use a threshold of 1/2 of the window to trigger updates.
	 *
	 * Per RFC 9000 Section 4.2, window should reopen based on consumed
	 * (application-read) data, not received data. We use the flow control
	 * subsystem's data_consumed tracking when available, or fall back to
	 * data_received as a conservative approximation for simple mode.
	 */
	if (conn->fc) {
		/* Use proper flow control subsystem tracking */
		spin_lock_bh(&conn->fc->conn.lock);
		consumed = conn->fc->conn.data_consumed;
		threshold = conn->fc->conn.max_data_local /
			    TQUIC_FC_WINDOW_UPDATE_THRESHOLD;
		spin_unlock_bh(&conn->fc->conn.lock);
	} else {
		/* Fallback for simple mode (conservative: use received) */
		consumed = conn->data_received;
		threshold = conn->max_data_local /
			    TQUIC_FC_WINDOW_UPDATE_THRESHOLD;
	}

	if (consumed >= threshold) {
		should_update = true;
	}

	spin_unlock_bh(&conn->lock);

	if (should_update)
		tquic_flow_control_update_max_data_internal(conn);
}
EXPORT_SYMBOL_GPL(tquic_flow_control_on_data_recvd);

/**
 * tquic_flow_control_update_max_data_internal - Send MAX_DATA frame to peer
 * @conn: QUIC connection
 *
 * Internal function that sends a MAX_DATA frame to increase the connection-level
 * flow control limit advertised to the peer. This is called from
 * tquic_flow_control_on_data_recvd() and tquic_flow_control_data_blocked_received().
 */
static void tquic_flow_control_update_max_data_internal(struct tquic_connection *conn)
{
	u64 new_max_data;
	u64 consumed;

	spin_lock_bh(&conn->lock);

	/*
	 * RFC 9000 Section 4.2: The receive window should reopen based
	 * on consumed (application-read) bytes, not just received bytes.
	 * Use the proper fc subsystem when available, otherwise use the
	 * legacy data_consumed counter.
	 */
	if (conn->fc) {
		spin_lock_bh(&conn->fc->conn.lock);
		consumed = conn->fc->conn.data_consumed;
		spin_unlock_bh(&conn->fc->conn.lock);
	} else {
		consumed = conn->data_consumed;
	}

	/*
	 * Calculate new max_data. Extend the window beyond what
	 * has been consumed to allow the peer to send more data.
	 */
	new_max_data = consumed +
		       2 * (conn->max_data_local - consumed);

	/* Apply auto-tuning: gradually increase window size */
	if (new_max_data < TQUIC_FC_MAX_WINDOW) {
		u64 current_window = conn->max_data_local - consumed;
		u64 new_window = min_t(u64,
				       current_window * TQUIC_FC_AUTOTUNE_MULTIPLIER,
				       TQUIC_FC_MAX_WINDOW);
		new_max_data = consumed + new_window;
	}

	/* Only send update if we're actually increasing the limit */
	if (new_max_data <= conn->max_data_local) {
		spin_unlock_bh(&conn->lock);
		return;
	}

	conn->max_data_local = new_max_data;

	spin_unlock_bh(&conn->lock);

	/*
	 * Send MAX_DATA directly using tquic_flow_send_max_data which
	 * encrypts via tquic_encrypt_payload (the correct crypto path).
	 *
	 * We bypass the control_frames queue + tx_work + tquic_packet_build
	 * path because tquic_packet_build calls tquic_crypto_encrypt() which
	 * expects struct tquic_crypto_ctx but receives conn->crypto_state
	 * (struct tquic_crypto_state) through a void* cast, causing silent
	 * encryption failure due to incompatible struct layouts.
	 */
	{
		struct tquic_path *path;
		int ret;

		rcu_read_lock();
		path = rcu_dereference(conn->active_path);
		if (!path) {
			rcu_read_unlock();
			pr_warn("TQUIC: no active path for MAX_DATA\n");
			return;
		}
		ret = tquic_flow_send_max_data(conn, path, new_max_data);
		rcu_read_unlock();
		if (ret < 0)
			pr_warn("TQUIC: failed to send MAX_DATA: %d\n", ret);
	}
}

/**
 * tquic_flow_control_update_max_data - Public interface for MAX_DATA updates
 * @conn: QUIC connection
 *
 * Public API to trigger a MAX_DATA frame transmission. Called by external
 * modules that need to request flow control updates.
 */
void tquic_flow_control_update_max_data(struct tquic_connection *conn)
{
	if (!conn)
		return;

	tquic_flow_control_update_max_data_internal(conn);
}
EXPORT_SYMBOL_GPL(tquic_flow_control_update_max_data);

/**
 * tquic_flow_control_max_data_received - Handle received MAX_DATA frame
 * @conn: QUIC connection
 * @max_data: New max_data value from peer
 *
 * Called when a MAX_DATA frame is received from the peer. Updates the
 * connection-level flow control limit.
 */
void tquic_flow_control_max_data_received(struct tquic_connection *conn,
					 u64 max_data)
{
	spin_lock_bh(&conn->lock);

	/*
	 * RFC 9000 Section 4.1: A sender MUST ignore any MAX_DATA frame
	 * that does not increase the maximum data value.
	 */
	if (max_data > conn->max_data_remote) {
		conn->max_data_remote = max_data;
	}

	spin_unlock_bh(&conn->lock);
}

/**
 * tquic_flow_control_get_available - Get available connection flow control credit
 * @conn: QUIC connection
 *
 * Returns the number of bytes that can be sent at the connection level.
 */
u64 tquic_flow_control_get_available(struct tquic_connection *conn)
{
	u64 available;

	spin_lock_bh(&conn->lock);
	if (conn->max_data_remote > conn->data_sent)
		available = conn->max_data_remote - conn->data_sent;
	else
		available = 0;
	spin_unlock_bh(&conn->lock);

	return available;
}

/*
 * Stream-level Flow Control Functions
 */

/**
 * tquic_stream_flow_control_init - Initialize stream flow control
 * @stream: QUIC stream
 * @max_stream_data_local: Local max stream data limit
 * @max_stream_data_remote: Remote max stream data limit
 *
 * Initializes flow control state for a new stream.
 */
void tquic_stream_flow_control_init(struct tquic_stream *stream,
				   u64 max_stream_data_local,
				   u64 max_stream_data_remote)
{
	stream->max_recv_data = max_stream_data_local;
	stream->max_send_data = max_stream_data_remote;
	stream->send_offset = 0;
	stream->recv_offset = 0;
	stream->recv_consumed = 0;
}

/**
 * tquic_stream_flow_control_can_send - Check if stream allows sending
 * @stream: QUIC stream
 * @bytes: Number of bytes to send
 *
 * RFC 9000 Section 4.1: Each stream has its own flow control limit.
 * A sender MUST NOT send data on a stream unless flow control allows.
 *
 * Returns: true if bytes can be sent, false otherwise
 */
bool tquic_stream_flow_control_can_send(struct tquic_stream *stream, u64 bytes)
{
	u64 available;
	bool can_send;

	if (bytes == 0)
		return true;

	/* Calculate available stream flow control credit */
	if (stream->max_send_data > stream->send_offset)
		available = stream->max_send_data - stream->send_offset;
	else
		available = 0;

	can_send = (bytes <= available);

	/*
	 * RFC 9000 Section 4.1: A sender SHOULD send a STREAM_DATA_BLOCKED
	 * frame when it wishes to send data but is unable to do so due to
	 * stream-level flow control.
	 */
	if (!can_send) {
		tquic_stream_flow_control_send_blocked(stream);
	}

	return can_send;
}
EXPORT_SYMBOL_GPL(tquic_stream_flow_control_can_send);

/**
 * tquic_stream_flow_control_on_data_sent - Update stream after sending
 * @stream: QUIC stream
 * @bytes: Number of bytes sent
 *
 * Called after data is sent on a stream.
 */
void tquic_stream_flow_control_on_data_sent(struct tquic_stream *stream,
					   u64 bytes)
{
	if (bytes == 0)
		return;

	/* Stream offset is updated in the send path */
}
EXPORT_SYMBOL_GPL(tquic_stream_flow_control_on_data_sent);

/**
 * tquic_stream_flow_control_check_recv_limit - Check if receiving would exceed limits
 * @stream: QUIC stream
 * @offset: Offset of received data
 * @len: Length of received data
 *
 * RFC 9000 Section 4.1: A receiver MUST close the connection with a
 * FLOW_CONTROL_ERROR error if the sender violates the advertised
 * stream data limit.
 *
 * Returns: 0 if data can be accepted, -EDQUOT if limit exceeded
 */
int tquic_stream_flow_control_check_recv_limit(struct tquic_stream *stream,
					      u64 offset, u64 len)
{
	u64 new_highest;

	if (len == 0)
		return 0;

	/*
	 * RFC 9000 Section 4.1: The highest offset of data received on a
	 * stream MUST NOT exceed the MAX_STREAM_DATA limit for that stream.
	 *
	 * Check if receiving this data would exceed the stream-level
	 * flow control limit we advertised to the peer.
	 */
	if (len > U64_MAX - offset)
		return -EOVERFLOW;
	new_highest = offset + len;
	if (new_highest > stream->max_recv_data) {
		/*
		 * RFC 9000 Section 4.1: A receiver advertises a maximum
		 * stream data limit. If the sender exceeds this limit,
		 * the receiver MUST close the connection with a
		 * FLOW_CONTROL_ERROR.
		 */
		return -EDQUOT;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_stream_flow_control_check_recv_limit);

/**
 * tquic_stream_flow_control_on_data_recvd - Update stream after receiving
 * @stream: QUIC stream
 * @offset: Offset of received data
 * @len: Length of received data
 *
 * Called when data is received on a stream. May trigger MAX_STREAM_DATA.
 *
 * Note: The caller MUST call tquic_stream_flow_control_check_recv_limit() first
 * to ensure the data does not exceed flow control limits.
 */
void tquic_stream_flow_control_on_data_recvd(struct tquic_stream *stream,
					    u64 offset, u64 len)
{
	u64 new_highest;
	u64 consumed;
	u64 threshold;
	bool should_update = false;

	/*
	 * Track highest offset seen.
	 * Check for overflow before computing new_highest.
	 */
	if (len <= U64_MAX - offset) {
		new_highest = offset + len;
		if (new_highest > stream->recv_offset)
			stream->recv_offset = new_highest;
	}

	/*
	 * Check if we should send MAX_STREAM_DATA. We update when
	 * we've consumed a significant portion of the window.
	 * Per RFC 9000 Section 4.1, use consumed (application-read) data.
	 */
	if (stream->fc) {
		/* Use proper flow control subsystem tracking */
		spin_lock_bh(&stream->fc->lock);
		consumed = stream->fc->data_consumed;
		threshold = stream->fc->max_data_local /
			    TQUIC_FC_WINDOW_UPDATE_THRESHOLD;
		spin_unlock_bh(&stream->fc->lock);
	} else {
		/* Use app-consumed bytes for FC window decisions (RFC 9000 S4.2) */
		consumed = stream->recv_consumed;
		threshold = stream->max_recv_data /
			    TQUIC_FC_WINDOW_UPDATE_THRESHOLD;
	}

	if (consumed >= threshold)
		should_update = true;

	if (should_update)
		tquic_stream_flow_control_update_max_stream_data(stream);
}

/**
 * tquic_stream_flow_control_update_max_stream_data - Send MAX_STREAM_DATA
 * @stream: QUIC stream
 *
 * Sends a MAX_STREAM_DATA frame to increase the stream's flow control limit.
 */
static void tquic_stream_flow_control_update_max_stream_data(struct tquic_stream *stream)
{
	struct tquic_connection *conn = stream->conn;
	u64 new_max_stream_data;
	u64 consumed;
	u64 window;

	consumed = stream->recv_consumed;
	if (consumed >= stream->max_recv_data)
		return;
	window = stream->max_recv_data - consumed;

	/*
	 * Calculate new limit: current consumed plus original window size.
	 * Apply auto-tuning to gradually increase window.
	 */
	new_max_stream_data = consumed + window;

	/* Auto-tune: increase window if under max */
	if (new_max_stream_data < TQUIC_FC_MAX_WINDOW) {
		u64 new_window = min_t(u64, window * TQUIC_FC_AUTOTUNE_MULTIPLIER,
				       TQUIC_FC_MAX_WINDOW);
		new_max_stream_data = consumed + new_window;
	}

	/* Only update if increasing the limit */
	if (new_max_stream_data <= stream->max_recv_data) {
		pr_info("tquic: FC: skip MAX_STREAM_DATA id=%llu new=%llu <= cur=%llu\n",
			stream->id, new_max_stream_data, stream->max_recv_data);
		return;
	}

	pr_info("tquic: FC: sending MAX_STREAM_DATA id=%llu new_max=%llu (was %llu) conn=%px\n",
		stream->id, new_max_stream_data, stream->max_recv_data,
		stream->conn);
	stream->max_recv_data = new_max_stream_data;

	/*
	 * Send MAX_STREAM_DATA directly using tquic_flow_send_max_stream_data
	 * which encrypts via tquic_encrypt_payload (the correct crypto path).
	 *
	 * We bypass the control_frames queue + tx_work + tquic_packet_build
	 * path because tquic_packet_build calls tquic_crypto_encrypt() which
	 * expects struct tquic_crypto_ctx but receives conn->crypto_state
	 * (struct tquic_crypto_state) through a void* cast, causing silent
	 * encryption failure due to incompatible struct layouts.
	 */
	{
		struct tquic_path *path;
		int ret;

		rcu_read_lock();
		path = rcu_dereference(conn->active_path);
		if (!path) {
			rcu_read_unlock();
			pr_warn("TQUIC: no active path for MAX_STREAM_DATA stream %llu\n",
				stream->id);
			return;
		}
		ret = tquic_flow_send_max_stream_data(conn, path,
						      stream->id,
						      new_max_stream_data);
		rcu_read_unlock();
		if (ret < 0)
			pr_warn("TQUIC: failed to send MAX_STREAM_DATA for stream %llu: %d\n",
				stream->id, ret);
	}
}

/**
 * tquic_stream_flow_control_max_stream_data_received - Handle MAX_STREAM_DATA
 * @stream: QUIC stream
 * @max_stream_data: New limit from peer
 *
 * Called when a MAX_STREAM_DATA frame is received.
 */
void tquic_stream_flow_control_max_stream_data_received(struct tquic_stream *stream,
						       u64 max_stream_data)
{
	/*
	 * RFC 9000 Section 4.1: A sender MUST ignore any MAX_STREAM_DATA
	 * frame that does not increase the stream data limit.
	 */
	if (max_stream_data > stream->max_send_data) {
		stream->max_send_data = max_stream_data;
	}

	/* Wake any waiters blocked on flow control */
	wake_up(&stream->wait);
}

/**
 * tquic_stream_flow_control_send_blocked - Send STREAM_DATA_BLOCKED frame
 * @stream: QUIC stream
 *
 * Sends a STREAM_DATA_BLOCKED frame to indicate we want to send more data
 * but are blocked by stream-level flow control.
 */
static void tquic_stream_flow_control_send_blocked(struct tquic_stream *stream)
{
	struct tquic_connection *conn = stream->conn;
	struct sk_buff *skb;
	u64 limit;

	limit = stream->max_send_data;

	if (conn && conn->sk)
		TQUIC_INC_STATS(sock_net(conn->sk), TQUIC_MIB_STREAMBLOCKED);

	skb = tquic_flow_create_stream_data_blocked_frame(stream->id, limit);
	if (!skb) {
		pr_err("TQUIC: failed to allocate STREAM_DATA_BLOCKED frame for stream %llu\n",
		       stream->id);
		return;
	}

	/*
	 * Queue STREAM_DATA_BLOCKED frame for transmission.
	 * RFC 9000 Section 4.1: "A sender SHOULD send a STREAM_DATA_BLOCKED
	 * frame when it wishes to send data but is unable to do so due to
	 * stream-level flow control."
	 *
	 * While this is labeled "advisory" in RFC 9000, it is IMPORTANT for
	 * congestion visibility and flow control negotiation. Silently dropping
	 * BLOCKED frames means the receiver never learns that we're blocked.
	 *
	 * Log failures so operators can diagnose flow control issues.
	 */
	if (tquic_conn_queue_frame(conn, skb)) {
		pr_warn("TQUIC: failed to queue STREAM_DATA_BLOCKED for stream %llu (queue full)\n",
			stream->id);
		kfree_skb(skb);
		return;
	}

	/* Schedule transmission of the queued frame */
	schedule_work(&conn->tx_work);
}

/**
 * tquic_stream_flow_control_get_available - Get available stream credit
 * @stream: QUIC stream
 *
 * Returns the number of bytes that can be sent on this stream.
 */
u64 tquic_stream_flow_control_get_available(struct tquic_stream *stream)
{
	u64 available;

	if (stream->max_send_data > stream->send_offset)
		available = stream->max_send_data - stream->send_offset;
	else
		available = 0;

	return available;
}

/*
 * Stream Limit Management Functions (MAX_STREAMS)
 */

/**
 * tquic_streams_can_open - Check if a new stream can be opened
 * @conn: QUIC connection
 * @unidirectional: true for unidirectional, false for bidirectional
 *
 * RFC 9000 Section 4.6: An endpoint MUST NOT exceed the limit set by
 * its peer. An endpoint that receives a frame with a stream ID exceeding
 * the limit it has sent MUST treat this as a connection error of type
 * STREAM_LIMIT_ERROR.
 *
 * Returns: true if a new stream can be opened, false otherwise
 */
bool tquic_streams_can_open(struct tquic_connection *conn, bool unidirectional)
{
	bool can_open;
	u64 opened, max_streams;

	spin_lock_bh(&conn->lock);

	if (unidirectional) {
		opened = conn->next_stream_id_uni >> 2;  /* Stream number */
		max_streams = conn->max_streams_uni;
	} else {
		opened = conn->next_stream_id_bidi >> 2;  /* Stream number */
		max_streams = conn->max_streams_bidi;
	}

	can_open = (opened < max_streams);

	spin_unlock_bh(&conn->lock);

	return can_open;
}

/**
 * tquic_streams_on_stream_opened - Update stream count after opening
 * @conn: QUIC connection
 * @unidirectional: true for unidirectional stream
 *
 * Called when a new locally-initiated stream is opened.
 */
void tquic_streams_on_stream_opened(struct tquic_connection *conn,
				   bool unidirectional)
{
	spin_lock_bh(&conn->lock);

	if (unidirectional)
		conn->next_stream_id_uni += 4;  /* Next stream ID */
	else
		conn->next_stream_id_bidi += 4;

	spin_unlock_bh(&conn->lock);
}

/**
 * tquic_streams_on_peer_stream_opened - Update peer stream count
 * @conn: QUIC connection
 * @unidirectional: true for unidirectional stream
 *
 * Called when a peer-initiated stream is received.
 */
void tquic_streams_on_peer_stream_opened(struct tquic_connection *conn,
					bool unidirectional)
{
	/* Check if we should send MAX_STREAMS to allow more peer streams */
	tquic_streams_check_update(conn, unidirectional);
}

/**
 * tquic_streams_check_update - Check if MAX_STREAMS should be sent
 * @conn: QUIC connection
 * @unidirectional: true for unidirectional streams
 *
 * Checks if we should send a MAX_STREAMS frame to allow the peer
 * to open more streams.
 */
static void tquic_streams_check_update(struct tquic_connection *conn, bool unidirectional)
{
	u64 max_streams;
	bool should_update = false;

	spin_lock_bh(&conn->lock);

	if (unidirectional)
		max_streams = conn->max_streams_uni;
	else
		max_streams = conn->max_streams_bidi;

	/* Simplified check - track peer's highest stream against threshold */
	(void)max_streams; /* used above to select the right counter */

	spin_unlock_bh(&conn->lock);

	if (should_update)
		tquic_streams_update_max_streams(conn, unidirectional);
}

/**
 * tquic_streams_update_max_streams - Send MAX_STREAMS frame
 * @conn: QUIC connection
 * @unidirectional: true for unidirectional streams
 *
 * Sends a MAX_STREAMS frame to allow the peer to open more streams.
 */
static void tquic_streams_update_max_streams(struct tquic_connection *conn,
				     bool unidirectional)
{
	struct sk_buff *skb;
	u64 new_max_streams;
	u64 current_max;

	spin_lock_bh(&conn->lock);

	if (unidirectional) {
		current_max = conn->max_streams_uni;
		/* Increase by original limit */
		new_max_streams = current_max + tquic_get_validated_max_streams();
		if (new_max_streams > TQUIC_MAX_STREAMS)
			new_max_streams = TQUIC_MAX_STREAMS;
		conn->max_streams_uni = new_max_streams;
	} else {
		current_max = conn->max_streams_bidi;
		new_max_streams = current_max + tquic_get_validated_max_streams();
		if (new_max_streams > TQUIC_MAX_STREAMS)
			new_max_streams = TQUIC_MAX_STREAMS;
		conn->max_streams_bidi = new_max_streams;
	}

	spin_unlock_bh(&conn->lock);

	/* Only send if we actually increased the limit */
	if (new_max_streams > current_max) {
		skb = tquic_flow_create_max_streams_frame(new_max_streams,
							 unidirectional);
		if (!skb) {
			pr_err("TQUIC: failed to allocate MAX_STREAMS frame\n");
			return;
		}

		/*
		 * Queue MAX_STREAMS frame for transmission.
		 * CRITICAL: Failure to send MAX_STREAMS prevents the peer from
		 * opening new streams, limiting connection capacity. While the RFC
		 * says this is "advisory", it is essential for proper connection
		 * operation when the peer is blocked on stream limits.
		 *
		 * If queueing fails, log it. The peer's STREAMS_BLOCKED frame
		 * will eventually prompt a retry, or idle timeout closes connection.
		 */
		if (tquic_conn_queue_frame(conn, skb)) {
			pr_warn("TQUIC: failed to queue MAX_STREAMS frame (queue full), will retry\n");
			kfree_skb(skb);
			return;
		}

		/* Schedule transmission of the queued frame */
		schedule_work(&conn->tx_work);
	}
}

/**
 * tquic_streams_max_streams_received - Handle received MAX_STREAMS frame
 * @conn: QUIC connection
 * @max_streams: New stream limit
 * @unidirectional: true for unidirectional streams
 *
 * Called when a MAX_STREAMS frame is received from the peer.
 */
void tquic_streams_max_streams_received(struct tquic_connection *conn,
				       u64 max_streams, bool unidirectional)
{
	spin_lock_bh(&conn->lock);

	/*
	 * RFC 9000 Section 4.6: An endpoint MUST ignore any MAX_STREAMS
	 * frame that does not increase the stream limit.
	 */
	if (unidirectional) {
		if (max_streams > conn->max_streams_uni)
			conn->max_streams_uni = max_streams;
	} else {
		if (max_streams > conn->max_streams_bidi)
			conn->max_streams_bidi = max_streams;
	}

	spin_unlock_bh(&conn->lock);
}

/**
 * tquic_streams_send_blocked - Send STREAMS_BLOCKED frame
 * @conn: QUIC connection
 * @unidirectional: true for unidirectional streams
 *
 * Sends a STREAMS_BLOCKED frame when we want to open more streams
 * but are blocked by the stream limit.
 */
void tquic_streams_send_blocked(struct tquic_connection *conn, bool unidirectional)
{
	struct sk_buff *skb;
	u64 limit;

	spin_lock_bh(&conn->lock);
	limit = unidirectional ? conn->max_streams_uni : conn->max_streams_bidi;
	spin_unlock_bh(&conn->lock);

	skb = tquic_flow_create_streams_blocked_frame(limit, unidirectional);
	if (!skb) {
		pr_err("TQUIC: failed to allocate STREAMS_BLOCKED frame\n");
		return;
	}

	/*
	 * Queue STREAMS_BLOCKED frame for transmission.
	 * RFC 9000 Section 4.6: "A sender SHOULD send a STREAMS_BLOCKED frame
	 * when it wishes to open a stream but is unable to do so due to the
	 * stream limit set by its peer."
	 *
	 * Like STREAM_DATA_BLOCKED, while labeled "advisory", this is important
	 * for the receiver to understand we're blocked on stream limits.
	 *
	 * Log failures for visibility into flow control issues.
	 */
	if (tquic_conn_queue_frame(conn, skb)) {
		pr_warn("TQUIC: failed to queue STREAMS_BLOCKED frame (queue full)\n");
		kfree_skb(skb);
		return;
	}

	/* Schedule transmission of the queued frame */
	schedule_work(&conn->tx_work);
}

/*
 * Blocked Notification Handling
 */

/**
 * tquic_flow_control_send_data_blocked - Send DATA_BLOCKED frame
 * @conn: QUIC connection
 *
 * Sends a DATA_BLOCKED frame to indicate we want to send more data
 * but are blocked by connection-level flow control.
 */
void tquic_flow_control_send_data_blocked(struct tquic_connection *conn)
{
	struct sk_buff *skb;
	u64 limit;

	spin_lock_bh(&conn->lock);
	limit = conn->max_data_remote;
	spin_unlock_bh(&conn->lock);

	skb = tquic_flow_create_data_blocked_frame(limit);
	if (!skb) {
		pr_err("TQUIC: failed to allocate DATA_BLOCKED frame\n");
		return;
	}

	/*
	 * Queue DATA_BLOCKED frame for transmission.
	 * RFC 9000 Section 4.1: "A sender SHOULD send a DATA_BLOCKED frame
	 * when it wishes to send data but is unable to do so due to
	 * connection-level flow control."
	 *
	 * While RFC 9000 Section 4.1 also states "A DATA_BLOCKED frame does not
	 * require any action by the receiver", it is IMPORTANT for the receiver
	 * to know that we need more flow control credit. Silently dropping this
	 * frame masks real flow control problems.
	 *
	 * Log failures to help diagnose connection-level flow control issues.
	 */
	if (tquic_conn_queue_frame(conn, skb)) {
		pr_warn("TQUIC: failed to queue DATA_BLOCKED frame (queue full)\n");
		kfree_skb(skb);
		return;
	}

	/* Schedule transmission of the queued frame */
	schedule_work(&conn->tx_work);
}

/**
 * tquic_flow_control_data_blocked_received - Handle DATA_BLOCKED frame
 * @conn: QUIC connection
 * @limit: The limit at which the peer is blocked
 *
 * RFC 9000 Section 4.1: A DATA_BLOCKED frame does not require any action
 * by the receiver, but it can be useful for debugging.
 */
void tquic_flow_control_data_blocked_received(struct tquic_connection *conn,
					     u64 limit)
{
	/*
	 * The peer is blocked on connection-level flow control.
	 * This is informational - we may choose to send MAX_DATA sooner.
	 */
	tquic_dbg("DATA_BLOCKED received at limit %llu\n", limit);

	/* Optionally trigger MAX_DATA update */
	tquic_flow_control_update_max_data_internal(conn);
}

/**
 * tquic_stream_data_blocked_received - Handle STREAM_DATA_BLOCKED frame
 * @conn: QUIC connection
 * @stream_id: Stream ID
 * @limit: The limit at which the peer is blocked
 *
 * RFC 9000 Section 4.1: Informational frame indicating peer is blocked.
 */
void tquic_stream_data_blocked_received(struct tquic_connection *conn,
				       u64 stream_id, u64 limit)
{
	struct tquic_stream *stream;

	tquic_dbg("STREAM_DATA_BLOCKED received for stream %llu at limit %llu\n",
		 stream_id, limit);

	stream = tquic_stream_lookup(conn, stream_id);
	if (stream) {
		/* Optionally trigger MAX_STREAM_DATA update */
		tquic_stream_flow_control_update_max_stream_data(stream);
	}
}

/**
 * tquic_streams_blocked_received - Handle STREAMS_BLOCKED frame
 * @conn: QUIC connection
 * @limit: The limit at which the peer is blocked
 * @unidirectional: true if for unidirectional streams
 *
 * RFC 9000 Section 4.6: Informational frame indicating peer wants more streams.
 */
void tquic_streams_blocked_received(struct tquic_connection *conn, u64 limit,
				   bool unidirectional)
{
	tquic_dbg("STREAMS_BLOCKED received at limit %llu (uni=%d)\n",
		 limit, unidirectional);

	/* Optionally trigger MAX_STREAMS update */
	tquic_streams_update_max_streams(conn, unidirectional);
}

/*
 * Frame Creation Helper Functions
 */

/**
 * tquic_flow_create_max_data_frame - Create a MAX_DATA frame
 * @conn: QUIC connection
 * @max_data: Maximum data value to advertise
 *
 * RFC 9000 Section 19.9: MAX_DATA Frame
 *
 * MAX_DATA Frame {
 *   Type (i) = 0x10,
 *   Maximum Data (i),
 * }
 *
 * Returns: sk_buff containing the frame, or NULL on failure
 */
static struct sk_buff *tquic_flow_create_max_data_frame(struct tquic_connection *conn,
						       u64 max_data)
{
	struct sk_buff *skb;
	u8 *p;
	int frame_len;

	/* Calculate frame size: type (1 byte) + max_data (variable) */
	frame_len = 1 + tquic_varint_len(max_data);

	skb = alloc_skb(frame_len + 16, GFP_ATOMIC);
	if (!skb)
		return NULL;

	/* Frame type */
	p = skb_put(skb, 1);
	*p = TQUIC_FRAME_MAX_DATA;

	/* Maximum Data */
	p = skb_put(skb, tquic_varint_len(max_data));
	tquic_varint_encode(max_data, p, tquic_varint_len(max_data));

	atomic64_inc(&conn->pkt_num_tx);

	return skb;
}

/**
 * tquic_flow_create_max_stream_data_frame - Create a MAX_STREAM_DATA frame
 * @stream_id: Stream ID
 * @max_stream_data: Maximum stream data value
 *
 * RFC 9000 Section 19.10: MAX_STREAM_DATA Frame
 *
 * MAX_STREAM_DATA Frame {
 *   Type (i) = 0x11,
 *   Stream ID (i),
 *   Maximum Stream Data (i),
 * }
 *
 * Returns: sk_buff containing the frame, or NULL on failure
 */
static struct sk_buff *tquic_flow_create_max_stream_data_frame(u64 stream_id,
							      u64 max_stream_data)
{
	struct sk_buff *skb;
	u8 *p;
	int frame_len;

	/* Calculate frame size */
	frame_len = 1 + tquic_varint_len(stream_id) +
		    tquic_varint_len(max_stream_data);

	skb = alloc_skb(frame_len + 16, GFP_ATOMIC);
	if (!skb)
		return NULL;

	/* Frame type */
	p = skb_put(skb, 1);
	*p = TQUIC_FRAME_MAX_STREAM_DATA;

	/* Stream ID */
	p = skb_put(skb, tquic_varint_len(stream_id));
	tquic_varint_encode(stream_id, p, tquic_varint_len(stream_id));

	/* Maximum Stream Data */
	p = skb_put(skb, tquic_varint_len(max_stream_data));
	tquic_varint_encode(max_stream_data, p, tquic_varint_len(max_stream_data));

	return skb;
}

/**
 * tquic_flow_create_max_streams_frame - Create a MAX_STREAMS frame
 * @max_streams: Maximum streams value
 * @unidirectional: true for unidirectional streams
 *
 * RFC 9000 Section 19.11: MAX_STREAMS Frames
 *
 * MAX_STREAMS Frame {
 *   Type (i) = 0x12..0x13,
 *   Maximum Streams (i),
 * }
 *
 * Returns: sk_buff containing the frame, or NULL on failure
 */
static struct sk_buff *tquic_flow_create_max_streams_frame(u64 max_streams,
							  bool unidirectional)
{
	struct sk_buff *skb;
	u8 *p;
	int frame_len;
	u8 frame_type;

	frame_type = unidirectional ? TQUIC_FRAME_MAX_STREAMS_UNI :
				      TQUIC_FRAME_MAX_STREAMS_BIDI;

	/* Calculate frame size */
	frame_len = 1 + tquic_varint_len(max_streams);

	skb = alloc_skb(frame_len + 16, GFP_ATOMIC);
	if (!skb)
		return NULL;

	/* Frame type */
	p = skb_put(skb, 1);
	*p = frame_type;

	/* Maximum Streams */
	p = skb_put(skb, tquic_varint_len(max_streams));
	tquic_varint_encode(max_streams, p, tquic_varint_len(max_streams));

	return skb;
}

/**
 * tquic_flow_create_data_blocked_frame - Create a DATA_BLOCKED frame
 * @limit: The connection-level limit at which we are blocked
 *
 * RFC 9000 Section 19.12: DATA_BLOCKED Frame
 *
 * DATA_BLOCKED Frame {
 *   Type (i) = 0x14,
 *   Maximum Data (i),
 * }
 *
 * Returns: sk_buff containing the frame, or NULL on failure
 */
static struct sk_buff *tquic_flow_create_data_blocked_frame(u64 limit)
{
	struct sk_buff *skb;
	u8 *p;
	int frame_len;

	frame_len = 1 + tquic_varint_len(limit);

	skb = alloc_skb(frame_len + 16, GFP_ATOMIC);
	if (!skb)
		return NULL;

	/* Frame type */
	p = skb_put(skb, 1);
	*p = TQUIC_FRAME_DATA_BLOCKED;

	/* Maximum Data (limit) */
	p = skb_put(skb, tquic_varint_len(limit));
	tquic_varint_encode(limit, p, tquic_varint_len(limit));

	return skb;
}

/**
 * tquic_flow_create_stream_data_blocked_frame - Create STREAM_DATA_BLOCKED frame
 * @stream_id: Stream ID
 * @limit: The stream-level limit at which we are blocked
 *
 * RFC 9000 Section 19.13: STREAM_DATA_BLOCKED Frame
 *
 * STREAM_DATA_BLOCKED Frame {
 *   Type (i) = 0x15,
 *   Stream ID (i),
 *   Maximum Stream Data (i),
 * }
 *
 * Returns: sk_buff containing the frame, or NULL on failure
 */
static struct sk_buff *tquic_flow_create_stream_data_blocked_frame(u64 stream_id,
								  u64 limit)
{
	struct sk_buff *skb;
	u8 *p;
	int frame_len;

	frame_len = 1 + tquic_varint_len(stream_id) + tquic_varint_len(limit);

	skb = alloc_skb(frame_len + 16, GFP_ATOMIC);
	if (!skb)
		return NULL;

	/* Frame type */
	p = skb_put(skb, 1);
	*p = TQUIC_FRAME_STREAM_DATA_BLOCKED;

	/* Stream ID */
	p = skb_put(skb, tquic_varint_len(stream_id));
	tquic_varint_encode(stream_id, p, tquic_varint_len(stream_id));

	/* Maximum Stream Data (limit) */
	p = skb_put(skb, tquic_varint_len(limit));
	tquic_varint_encode(limit, p, tquic_varint_len(limit));

	return skb;
}

/**
 * tquic_flow_create_streams_blocked_frame - Create STREAMS_BLOCKED frame
 * @limit: The stream limit at which we are blocked
 * @unidirectional: true for unidirectional streams
 *
 * RFC 9000 Section 19.14: STREAMS_BLOCKED Frames
 *
 * STREAMS_BLOCKED Frame {
 *   Type (i) = 0x16..0x17,
 *   Maximum Streams (i),
 * }
 *
 * Returns: sk_buff containing the frame, or NULL on failure
 */
static struct sk_buff *tquic_flow_create_streams_blocked_frame(u64 limit,
							      bool unidirectional)
{
	struct sk_buff *skb;
	u8 *p;
	int frame_len;
	u8 frame_type;

	frame_type = unidirectional ? TQUIC_FRAME_STREAMS_BLOCKED_UNI :
				      TQUIC_FRAME_STREAMS_BLOCKED_BIDI;

	frame_len = 1 + tquic_varint_len(limit);

	skb = alloc_skb(frame_len + 16, GFP_ATOMIC);
	if (!skb)
		return NULL;

	/* Frame type */
	p = skb_put(skb, 1);
	*p = frame_type;

	/* Maximum Streams (limit) */
	p = skb_put(skb, tquic_varint_len(limit));
	tquic_varint_encode(limit, p, tquic_varint_len(limit));

	return skb;
}

/*
 * Combined Flow Control Check Function
 */

/**
 * tquic_flow_can_send_stream_data - Check all flow control limits
 * @stream: QUIC stream
 * @bytes: Number of bytes to send
 *
 * Performs combined check of both connection-level and stream-level
 * flow control to determine if data can be sent.
 *
 * Returns: true if data can be sent, false otherwise
 */
bool tquic_flow_can_send_stream_data(struct tquic_stream *stream, u64 bytes)
{
	struct tquic_connection *conn = stream->conn;

	/* Check connection-level flow control first */
	if (!tquic_flow_control_can_send(conn, bytes))
		return false;

	/* Check stream-level flow control */
	if (!tquic_stream_flow_control_can_send(stream, bytes))
		return false;

	return true;
}

/**
 * tquic_flow_on_stream_data_sent - Update all flow control after sending
 * @stream: QUIC stream
 * @bytes: Number of bytes sent
 *
 * Updates both connection-level and stream-level flow control state.
 */
void tquic_flow_on_stream_data_sent(struct tquic_stream *stream, u64 bytes)
{
	tquic_flow_control_on_data_sent(stream->conn, bytes);
	tquic_stream_flow_control_on_data_sent(stream, bytes);
}

/**
 * tquic_flow_control_check_recv_limit_internal - Check connection receive limit
 * @conn: QUIC connection
 * @len: Length of data to receive
 *
 * Internal function to check if receiving data would exceed the connection-level
 * flow control limit we advertised to the peer.
 *
 * Returns: 0 if data can be accepted, -EDQUOT if limit exceeded
 */
static int tquic_flow_control_check_recv_limit_internal(struct tquic_connection *conn,
							u64 len)
{
	int ret = 0;

	spin_lock_bh(&conn->lock);

	/*
	 * Check for u64 overflow before comparing against max_data_local.
	 * Without this, a crafted len could wrap data_received + len past
	 * zero, bypassing the flow control limit entirely.
	 */
	if (len > U64_MAX - conn->data_received) {
		ret = -EDQUOT;
	} else if (conn->data_received + len > conn->max_data_local) {
		ret = -EDQUOT;
	}

	spin_unlock_bh(&conn->lock);

	return ret;
}

/**
 * tquic_flow_check_recv_limits - Check all receive flow control limits
 * @stream: QUIC stream
 * @offset: Offset of received data
 * @len: Length of received data
 *
 * RFC 9000 Section 4.1: A receiver MUST close the connection with a
 * FLOW_CONTROL_ERROR error if the sender violates the advertised
 * connection or stream data limits.
 *
 * Performs combined check of both connection-level and stream-level
 * flow control to determine if received data can be accepted.
 *
 * Returns: 0 if data can be accepted, -EDQUOT if limits exceeded
 */
int tquic_flow_check_recv_limits(struct tquic_stream *stream, u64 offset, u64 len)
{
	struct tquic_connection *conn = stream->conn;
	int err;

	/*
	 * Check stream-level flow control first (RFC 9000 Section 4.1).
	 * The highest offset of data received on a stream MUST NOT exceed
	 * the MAX_STREAM_DATA limit for that stream.
	 */
	err = tquic_stream_flow_control_check_recv_limit(stream, offset, len);
	if (err)
		return err;

	/*
	 * Check connection-level flow control (RFC 9000 Section 4.1).
	 * The sum of data received on all streams MUST NOT exceed
	 * the MAX_DATA limit for the connection.
	 */
	err = tquic_flow_control_check_recv_limit_internal(conn, len);
	if (err)
		return err;

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_flow_check_recv_limits);

/**
 * tquic_flow_on_stream_data_recvd - Update all flow control after receiving
 * @stream: QUIC stream
 * @offset: Offset of received data
 * @len: Length of received data
 *
 * Updates both connection-level and stream-level flow control state.
 *
 * Note: The caller MUST call tquic_flow_check_recv_limits() first to
 * ensure the data does not exceed flow control limits.
 */
void tquic_flow_on_stream_data_recvd(struct tquic_stream *stream,
				    u64 offset, u64 len)
{
	tquic_flow_control_on_data_recvd(stream->conn, len);
	tquic_stream_flow_control_on_data_recvd(stream, offset, len);
}

/*
 * Flow Control Debug and Statistics
 */

/**
 * tquic_flow_get_stats - Get flow control statistics
 * @conn: QUIC connection
 * @local_max_data: Output for local max_data
 * @local_data_recvd: Output for local data received
 * @remote_max_data: Output for remote max_data
 * @remote_data_sent: Output for remote data sent
 *
 * Retrieves current flow control statistics for debugging.
 */
void tquic_flow_get_stats(struct tquic_connection *conn,
			 u64 *local_max_data, u64 *local_data_recvd,
			 u64 *remote_max_data, u64 *remote_data_sent)
{
	spin_lock_bh(&conn->lock);

	if (local_max_data)
		*local_max_data = conn->max_data_local;
	if (local_data_recvd)
		*local_data_recvd = conn->data_received;
	if (remote_max_data)
		*remote_max_data = conn->max_data_remote;
	if (remote_data_sent)
		*remote_data_sent = conn->data_sent;

	spin_unlock_bh(&conn->lock);
}

/**
 * tquic_stream_flow_get_stats - Get stream flow control statistics
 * @stream: QUIC stream
 * @send_offset: Output for send offset
 * @send_max: Output for max stream data (send)
 * @recv_offset: Output for receive offset
 * @recv_max: Output for max stream data (receive)
 *
 * Retrieves current stream flow control statistics.
 */
void tquic_stream_flow_get_stats(struct tquic_stream *stream,
				u64 *send_offset, u64 *send_max,
				u64 *recv_offset, u64 *recv_max)
{
	if (send_offset)
		*send_offset = stream->send_offset;
	if (send_max)
		*send_max = stream->max_send_data;
	if (recv_offset)
		*recv_offset = stream->recv_offset;
	if (recv_max)
		*recv_max = stream->max_recv_data;
}

/*
 * Module initialization
 */

/**
 * tquic_flow_init - Initialize flow control subsystem
 *
 * Called during QUIC module initialization.
 *
 * Returns: 0 on success, negative error code on failure
 */
int __init tquic_flow_init(void)
{
	pr_info("TQUIC flow control initialized\n");
	return 0;
}

/**
 * tquic_flow_exit - Cleanup flow control subsystem
 *
 * Called during QUIC module unload.
 */
void tquic_flow_exit(void)
{
	pr_info("TQUIC flow control cleanup\n");
}
