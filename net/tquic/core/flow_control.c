// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: QUIC Flow Control Implementation
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * This module implements QUIC flow control as specified in RFC 9000 Section 4.
 * It provides:
 *   - Connection-level flow control (MAX_DATA)
 *   - Stream-level flow control (MAX_STREAM_DATA)
 *   - Stream count limits (MAX_STREAMS)
 *   - Credit management for send operations
 *   - Automatic receive window tuning
 *   - Blocked state detection and signaling
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/ktime.h>
#include <net/tquic.h>

#include "flow_control.h"

/*
 * ==========================================================================
 * Flow Control State Initialization and Cleanup
 * ==========================================================================
 */

/**
 * tquic_fc_init - Initialize flow control state for a connection
 * @conn: The QUIC connection
 * @config: Optional configuration (NULL for defaults)
 *
 * Allocates and initializes the flow control state structure.
 * Must be called before any other flow control operations.
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_fc_init(struct tquic_connection *conn, struct tquic_fc_config *config)
{
	struct tquic_fc_state *fc;

	if (!conn)
		return -EINVAL;

	fc = kzalloc(sizeof(*fc), GFP_KERNEL);
	if (!fc)
		return -ENOMEM;

	/* Apply configuration or use defaults */
	if (config) {
		memcpy(&fc->config, config, sizeof(fc->config));
	} else {
		fc->config.initial_max_data = TQUIC_FC_DEFAULT_MAX_DATA;
		fc->config.initial_max_stream_data_bidi_local =
			TQUIC_FC_DEFAULT_MAX_STREAM_DATA_BIDI_LOCAL;
		fc->config.initial_max_stream_data_bidi_remote =
			TQUIC_FC_DEFAULT_MAX_STREAM_DATA_BIDI_REMOTE;
		fc->config.initial_max_stream_data_uni =
			TQUIC_FC_DEFAULT_MAX_STREAM_DATA_UNI;
		fc->config.initial_max_streams_bidi =
			TQUIC_FC_DEFAULT_MAX_STREAMS_BIDI;
		fc->config.initial_max_streams_uni =
			TQUIC_FC_DEFAULT_MAX_STREAMS_UNI;
		fc->config.autotune_enabled = true;
		fc->config.min_window = TQUIC_FC_MIN_WINDOW;
		fc->config.max_window = TQUIC_FC_MAX_WINDOW;
	}

	/* Initialize connection-level flow control */
	spin_lock_init(&fc->conn.lock);
	fc->conn.max_data_local = fc->config.initial_max_data;
	fc->conn.max_data_next = fc->config.initial_max_data;
	fc->conn.last_max_data_sent = fc->config.initial_max_data;
	fc->conn.max_data_remote = 0;  /* Set when received from peer */
	fc->conn.data_sent = 0;
	fc->conn.data_received = 0;
	fc->conn.data_consumed = 0;
	fc->conn.needs_max_data = false;
	fc->conn.data_blocked_sent = false;
	fc->conn.data_blocked_received = false;

	/* Initialize stream count flow control */
	spin_lock_init(&fc->streams.lock);
	fc->streams.max_streams_bidi_local = fc->config.initial_max_streams_bidi;
	fc->streams.max_streams_uni_local = fc->config.initial_max_streams_uni;
	fc->streams.max_streams_bidi_remote = 0;  /* Set when received */
	fc->streams.max_streams_uni_remote = 0;
	fc->streams.streams_bidi_opened = 0;
	fc->streams.streams_uni_opened = 0;
	fc->streams.streams_bidi_received = 0;
	fc->streams.streams_uni_received = 0;
	fc->streams.needs_max_streams_bidi = false;
	fc->streams.needs_max_streams_uni = false;
	fc->streams.streams_blocked_bidi_sent = false;
	fc->streams.streams_blocked_uni_sent = false;

	/* Initialize auto-tuning state */
	fc->autotune.enabled = fc->config.autotune_enabled;
	fc->autotune.last_update = ktime_get();
	fc->autotune.rtt_us = TQUIC_DEFAULT_RTT * 1000;
	fc->autotune.bandwidth = 0;
	fc->autotune.target_window = fc->config.initial_max_data;
	fc->autotune.bytes_since_update = 0;
	fc->autotune.growth_rate = 256;  /* 1.0 in 8.8 fixed point */

	fc->blocked_flags = 0;

	/* Zero out statistics */
	memset(&fc->stats, 0, sizeof(fc->stats));

	/* Store in connection structure */
	conn->fc = fc;

	pr_debug("tquic_fc: initialized flow control state for connection\n");

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_fc_init);

/**
 * tquic_fc_cleanup - Cleanup flow control state
 * @conn: The QUIC connection
 *
 * Frees all flow control resources associated with the connection.
 */
void tquic_fc_cleanup(struct tquic_connection *conn)
{
	if (!conn)
		return;

	if (conn->fc) {
		kfree(conn->fc);
		conn->fc = NULL;
	}

	pr_debug("tquic_fc: cleaned up flow control state\n");
}
EXPORT_SYMBOL_GPL(tquic_fc_cleanup);

/**
 * tquic_fc_stream_init - Initialize flow control for a stream
 * @stream: The QUIC stream
 * @fc_state: Parent connection's flow control state
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_fc_stream_init(struct tquic_stream *stream,
			 struct tquic_fc_state *fc_state)
{
	struct tquic_fc_stream_state *sfc;
	u64 initial_max;

	if (!stream || !fc_state)
		return -EINVAL;

	sfc = kzalloc(sizeof(*sfc), GFP_KERNEL);
	if (!sfc)
		return -ENOMEM;

	spin_lock_init(&sfc->lock);
	sfc->stream_id = stream->id;

	/* Determine initial MAX_STREAM_DATA based on stream type */
	initial_max = tquic_fc_get_initial_max_stream_data(fc_state,
							   stream->id, false);
	sfc->max_data_local = initial_max;
	sfc->max_data_next = initial_max;
	sfc->last_max_data_sent = initial_max;
	sfc->max_data_remote = 0;  /* Set when received from peer */

	sfc->data_sent = 0;
	sfc->data_received = 0;
	sfc->data_consumed = 0;
	sfc->needs_max_stream_data = false;
	sfc->data_blocked_sent = false;
	sfc->data_blocked_received = false;
	sfc->final_size = 0;
	sfc->final_size_known = false;

	/* Store the allocated flow control state in the stream */
	stream->fc = sfc;

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_fc_stream_init);

/**
 * tquic_fc_stream_cleanup - Cleanup stream flow control state
 * @stream: The QUIC stream
 */
void tquic_fc_stream_cleanup(struct tquic_stream *stream)
{
	if (!stream)
		return;

	if (stream->fc) {
		kfree(stream->fc);
		stream->fc = NULL;
	}
}
EXPORT_SYMBOL_GPL(tquic_fc_stream_cleanup);

/*
 * ==========================================================================
 * Connection-level Flow Control (MAX_DATA / DATA_BLOCKED)
 * RFC 9000 Section 4.1
 * ==========================================================================
 */

/**
 * tquic_fc_conn_can_send - Check if connection has credit to send
 * @fc: Flow control state
 * @bytes: Number of bytes to send
 *
 * Checks if the connection-level flow control window allows sending
 * the specified number of bytes.
 *
 * Return: true if sending is allowed, false if blocked
 */
bool tquic_fc_conn_can_send(struct tquic_fc_state *fc, u64 bytes)
{
	bool can_send;
	unsigned long flags;

	if (unlikely(!fc))
		return false;

	spin_lock_irqsave(&fc->conn.lock, flags);
	can_send = (fc->conn.data_sent + bytes) <= fc->conn.max_data_remote;
	spin_unlock_irqrestore(&fc->conn.lock, flags);

	return can_send;
}
EXPORT_SYMBOL_GPL(tquic_fc_conn_can_send);

/**
 * tquic_fc_conn_get_credit - Get available connection-level credit
 * @fc: Flow control state
 *
 * Return: Number of bytes that can be sent at connection level
 */
u64 tquic_fc_conn_get_credit(struct tquic_fc_state *fc)
{
	u64 credit;
	unsigned long flags;

	if (unlikely(!fc))
		return 0;

	spin_lock_irqsave(&fc->conn.lock, flags);
	if (fc->conn.max_data_remote > fc->conn.data_sent)
		credit = fc->conn.max_data_remote - fc->conn.data_sent;
	else
		credit = 0;
	spin_unlock_irqrestore(&fc->conn.lock, flags);

	return credit;
}
EXPORT_SYMBOL_GPL(tquic_fc_conn_get_credit);

/**
 * tquic_fc_conn_data_sent - Record data sent at connection level
 * @fc: Flow control state
 * @bytes: Number of bytes sent
 *
 * Updates the connection-level flow control state to account for
 * transmitted data. Detects if we become blocked.
 *
 * Return: 0 on success, -ENOSPC if would exceed limit
 */
int tquic_fc_conn_data_sent(struct tquic_fc_state *fc, u64 bytes)
{
	unsigned long flags;
	int ret = 0;

	if (unlikely(!fc))
		return -EINVAL;

	spin_lock_irqsave(&fc->conn.lock, flags);

	/* Check if this would exceed the limit */
	if (fc->conn.data_sent + bytes > fc->conn.max_data_remote) {
		/* Record that we're blocked */
		fc->conn.blocked_at = fc->conn.max_data_remote;
		fc->blocked_flags |= TQUIC_FC_BLOCKED_CONN_DATA;
		ret = -ENOSPC;
	} else {
		fc->conn.data_sent += bytes;

		/* Check if we're now at the limit */
		if (fc->conn.data_sent >= fc->conn.max_data_remote) {
			fc->conn.blocked_at = fc->conn.max_data_remote;
			fc->blocked_flags |= TQUIC_FC_BLOCKED_CONN_DATA;
		}
	}

	spin_unlock_irqrestore(&fc->conn.lock, flags);

	return ret;
}
EXPORT_SYMBOL_GPL(tquic_fc_conn_data_sent);

/**
 * tquic_fc_conn_data_received - Record data received at connection level
 * @fc: Flow control state
 * @bytes: Number of bytes received
 *
 * Updates connection-level receive tracking. Enforces that the peer
 * does not exceed our advertised limit.
 *
 * Return: 0 on success, -EPROTO if peer violated flow control
 */
int tquic_fc_conn_data_received(struct tquic_fc_state *fc, u64 bytes)
{
	unsigned long flags;
	int ret = 0;

	if (!fc)
		return -EINVAL;

	spin_lock_irqsave(&fc->conn.lock, flags);

	/* Check if peer is violating our limit */
	if (fc->conn.data_received + bytes > fc->conn.max_data_local) {
		pr_warn("tquic_fc: peer exceeded MAX_DATA limit\n");
		ret = -EPROTO;  /* FLOW_CONTROL_ERROR */
	} else {
		fc->conn.data_received += bytes;
		fc->autotune.bytes_since_update += bytes;
	}

	spin_unlock_irqrestore(&fc->conn.lock, flags);

	return ret;
}
EXPORT_SYMBOL_GPL(tquic_fc_conn_data_received);

/**
 * tquic_fc_conn_data_consumed - Mark connection data as consumed
 * @fc: Flow control state
 * @bytes: Number of bytes consumed by application
 *
 * Called when the application reads data. This opens up the receive
 * window and may trigger a MAX_DATA update.
 */
void tquic_fc_conn_data_consumed(struct tquic_fc_state *fc, u64 bytes)
{
	unsigned long flags;

	if (!fc)
		return;

	spin_lock_irqsave(&fc->conn.lock, flags);

	fc->conn.data_consumed += bytes;

	/* Check if we should update the window */
	if (tquic_fc_should_update_conn_window(fc)) {
		fc->conn.max_data_next = tquic_fc_calc_conn_window(fc);
		fc->conn.needs_max_data = true;
	}

	spin_unlock_irqrestore(&fc->conn.lock, flags);
}
EXPORT_SYMBOL_GPL(tquic_fc_conn_data_consumed);

/**
 * tquic_fc_handle_max_data - Handle received MAX_DATA frame
 * @fc: Flow control state
 * @max_data: New max data limit from peer
 *
 * Processes a MAX_DATA frame received from the peer, updating
 * our send limit.
 *
 * Return: 0 on success
 */
int tquic_fc_handle_max_data(struct tquic_fc_state *fc, u64 max_data)
{
	unsigned long flags;

	if (!fc)
		return -EINVAL;

	spin_lock_irqsave(&fc->conn.lock, flags);

	/* MAX_DATA can only increase the limit (RFC 9000 Section 4.1) */
	if (max_data > fc->conn.max_data_remote) {
		fc->conn.max_data_remote = max_data;

		/* Clear blocked state if we now have credit */
		if (fc->conn.data_sent < max_data) {
			fc->blocked_flags &= ~TQUIC_FC_BLOCKED_CONN_DATA;
			fc->conn.data_blocked_sent = false;
		}

		fc->stats.max_data_frames_received++;
		pr_debug("tquic_fc: received MAX_DATA=%llu\n", max_data);
	}

	spin_unlock_irqrestore(&fc->conn.lock, flags);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_fc_handle_max_data);

/**
 * tquic_fc_handle_data_blocked - Handle received DATA_BLOCKED frame
 * @fc: Flow control state
 * @max_data: The limit at which peer is blocked
 *
 * Processes a DATA_BLOCKED frame indicating the peer is blocked
 * on our flow control limit.
 */
void tquic_fc_handle_data_blocked(struct tquic_fc_state *fc, u64 max_data)
{
	unsigned long flags;

	if (!fc)
		return;

	spin_lock_irqsave(&fc->conn.lock, flags);

	fc->conn.data_blocked_received = true;
	fc->stats.data_blocked_frames_received++;

	/*
	 * Peer is blocked - we might want to increase our window
	 * This is a hint that our window might be too small
	 */
	if (fc->autotune.enabled && max_data >= fc->conn.max_data_local) {
		/* Consider increasing window */
		fc->autotune.growth_rate = min(fc->autotune.growth_rate + 64,
					       512U);  /* Max 2x growth */
		pr_debug("tquic_fc: peer blocked at %llu, may increase window\n",
			 max_data);
	}

	spin_unlock_irqrestore(&fc->conn.lock, flags);
}
EXPORT_SYMBOL_GPL(tquic_fc_handle_data_blocked);

/**
 * tquic_fc_needs_max_data - Check if MAX_DATA frame should be sent
 * @fc: Flow control state
 *
 * Return: true if a MAX_DATA frame should be sent
 */
bool tquic_fc_needs_max_data(struct tquic_fc_state *fc)
{
	bool needs;
	unsigned long flags;

	if (!fc)
		return false;

	spin_lock_irqsave(&fc->conn.lock, flags);
	needs = fc->conn.needs_max_data &&
		(fc->conn.max_data_next > fc->conn.last_max_data_sent);
	spin_unlock_irqrestore(&fc->conn.lock, flags);

	return needs;
}
EXPORT_SYMBOL_GPL(tquic_fc_needs_max_data);

/**
 * tquic_fc_get_max_data - Get MAX_DATA value to send
 * @fc: Flow control state
 *
 * Return: The MAX_DATA value to include in a frame
 */
u64 tquic_fc_get_max_data(struct tquic_fc_state *fc)
{
	u64 max_data;
	unsigned long flags;

	if (!fc)
		return 0;

	spin_lock_irqsave(&fc->conn.lock, flags);
	max_data = fc->conn.max_data_next;
	spin_unlock_irqrestore(&fc->conn.lock, flags);

	return max_data;
}
EXPORT_SYMBOL_GPL(tquic_fc_get_max_data);

/**
 * tquic_fc_max_data_sent - Mark MAX_DATA as sent
 * @fc: Flow control state
 * @max_data: The value that was sent
 */
void tquic_fc_max_data_sent(struct tquic_fc_state *fc, u64 max_data)
{
	unsigned long flags;

	if (!fc)
		return;

	spin_lock_irqsave(&fc->conn.lock, flags);

	fc->conn.last_max_data_sent = max_data;
	fc->conn.max_data_local = max_data;
	fc->conn.needs_max_data = false;
	fc->stats.max_data_frames_sent++;

	spin_unlock_irqrestore(&fc->conn.lock, flags);

	pr_debug("tquic_fc: sent MAX_DATA=%llu\n", max_data);
}
EXPORT_SYMBOL_GPL(tquic_fc_max_data_sent);

/**
 * tquic_fc_needs_data_blocked - Check if DATA_BLOCKED should be sent
 * @fc: Flow control state
 *
 * Return: true if we should send DATA_BLOCKED
 */
bool tquic_fc_needs_data_blocked(struct tquic_fc_state *fc)
{
	bool needs;
	unsigned long flags;

	if (!fc)
		return false;

	spin_lock_irqsave(&fc->conn.lock, flags);
	needs = (fc->blocked_flags & TQUIC_FC_BLOCKED_CONN_DATA) &&
		!fc->conn.data_blocked_sent;
	spin_unlock_irqrestore(&fc->conn.lock, flags);

	return needs;
}
EXPORT_SYMBOL_GPL(tquic_fc_needs_data_blocked);

/**
 * tquic_fc_get_data_blocked - Get DATA_BLOCKED value
 * @fc: Flow control state
 *
 * Return: The offset at which we are blocked
 */
u64 tquic_fc_get_data_blocked(struct tquic_fc_state *fc)
{
	u64 blocked_at;
	unsigned long flags;

	if (!fc)
		return 0;

	spin_lock_irqsave(&fc->conn.lock, flags);
	blocked_at = fc->conn.blocked_at;
	spin_unlock_irqrestore(&fc->conn.lock, flags);

	return blocked_at;
}
EXPORT_SYMBOL_GPL(tquic_fc_get_data_blocked);

/**
 * tquic_fc_data_blocked_sent - Mark DATA_BLOCKED as sent
 * @fc: Flow control state
 */
void tquic_fc_data_blocked_sent(struct tquic_fc_state *fc)
{
	unsigned long flags;

	if (!fc)
		return;

	spin_lock_irqsave(&fc->conn.lock, flags);
	fc->conn.data_blocked_sent = true;
	fc->stats.data_blocked_frames_sent++;
	spin_unlock_irqrestore(&fc->conn.lock, flags);

	pr_debug("tquic_fc: sent DATA_BLOCKED\n");
}
EXPORT_SYMBOL_GPL(tquic_fc_data_blocked_sent);

/*
 * ==========================================================================
 * Stream-level Flow Control (MAX_STREAM_DATA / STREAM_DATA_BLOCKED)
 * RFC 9000 Section 4.1
 * ==========================================================================
 */

/**
 * tquic_fc_stream_can_send - Check if stream has credit to send
 * @stream: Stream flow control state
 * @bytes: Number of bytes to send
 *
 * Return: true if sending is allowed on this stream
 */
bool tquic_fc_stream_can_send(struct tquic_fc_stream_state *stream, u64 bytes)
{
	bool can_send;
	unsigned long flags;

	if (unlikely(!stream))
		return false;

	spin_lock_irqsave(&stream->lock, flags);
	can_send = (stream->data_sent + bytes) <= stream->max_data_remote;
	spin_unlock_irqrestore(&stream->lock, flags);

	return can_send;
}
EXPORT_SYMBOL_GPL(tquic_fc_stream_can_send);

/**
 * tquic_fc_stream_get_credit - Get available stream-level credit
 * @stream: Stream flow control state
 *
 * Return: Number of bytes that can be sent on this stream
 */
u64 tquic_fc_stream_get_credit(struct tquic_fc_stream_state *stream)
{
	u64 credit;
	unsigned long flags;

	if (!stream)
		return 0;

	spin_lock_irqsave(&stream->lock, flags);
	if (stream->max_data_remote > stream->data_sent)
		credit = stream->max_data_remote - stream->data_sent;
	else
		credit = 0;
	spin_unlock_irqrestore(&stream->lock, flags);

	return credit;
}
EXPORT_SYMBOL_GPL(tquic_fc_stream_get_credit);

/**
 * tquic_fc_stream_data_sent - Record data sent on stream
 * @stream: Stream flow control state
 * @bytes: Number of bytes sent
 *
 * Return: 0 on success, -ENOSPC if blocked
 */
int tquic_fc_stream_data_sent(struct tquic_fc_stream_state *stream, u64 bytes)
{
	unsigned long flags;
	int ret = 0;

	if (!stream)
		return -EINVAL;

	spin_lock_irqsave(&stream->lock, flags);

	if (stream->data_sent + bytes > stream->max_data_remote) {
		stream->blocked_at = stream->max_data_remote;
		ret = -ENOSPC;
	} else {
		stream->data_sent += bytes;

		if (stream->data_sent >= stream->max_data_remote)
			stream->blocked_at = stream->max_data_remote;
	}

	spin_unlock_irqrestore(&stream->lock, flags);

	return ret;
}
EXPORT_SYMBOL_GPL(tquic_fc_stream_data_sent);

/**
 * tquic_fc_stream_data_received - Record data received on stream
 * @stream: Stream flow control state
 * @offset: Starting offset of data
 * @length: Length of data received
 * @fin: Whether FIN flag was set
 *
 * Handles potentially out-of-order data reception.
 *
 * Return: 0 on success, -EPROTO if flow control violated
 */
int tquic_fc_stream_data_received(struct tquic_fc_stream_state *stream,
				  u64 offset, u64 length, bool fin)
{
	unsigned long flags;
	u64 end_offset;
	int ret = 0;

	if (unlikely(!stream))
		return -EINVAL;

	end_offset = offset + length;

	spin_lock_irqsave(&stream->lock, flags);

	/* Check for flow control violation */
	if (end_offset > stream->max_data_local) {
		pr_warn("tquic_fc: stream %llu exceeded MAX_STREAM_DATA\n",
			stream->stream_id);
		ret = -EPROTO;
		goto out;
	}

	/* Track highest offset received */
	if (end_offset > stream->data_received)
		stream->data_received = end_offset;

	/* Handle FIN */
	if (fin) {
		if (stream->final_size_known) {
			/* Verify consistent final size */
			if (end_offset != stream->final_size) {
				pr_warn("tquic_fc: inconsistent final size\n");
				ret = -EPROTO;
				goto out;
			}
		} else {
			stream->final_size = end_offset;
			stream->final_size_known = true;
		}
	}

out:
	spin_unlock_irqrestore(&stream->lock, flags);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_fc_stream_data_received);

/**
 * tquic_fc_stream_data_consumed - Mark stream data as consumed
 * @stream: Stream flow control state
 * @bytes: Bytes consumed by application
 */
void tquic_fc_stream_data_consumed(struct tquic_fc_stream_state *stream,
				   u64 bytes)
{
	unsigned long flags;

	if (!stream)
		return;

	spin_lock_irqsave(&stream->lock, flags);

	stream->data_consumed += bytes;

	/*
	 * Check if window should be updated
	 * Update when consumed data exceeds threshold of current window
	 */
	{
		u64 consumed_since_update = stream->data_consumed -
			(stream->last_max_data_sent - stream->max_data_local);
		u64 threshold = stream->max_data_local /
			TQUIC_FC_WINDOW_UPDATE_THRESHOLD;

		if (consumed_since_update >= threshold) {
			stream->max_data_next = stream->data_consumed +
				stream->max_data_local;
			stream->needs_max_stream_data = true;
		}
	}

	spin_unlock_irqrestore(&stream->lock, flags);
}
EXPORT_SYMBOL_GPL(tquic_fc_stream_data_consumed);

/**
 * tquic_fc_handle_max_stream_data - Handle MAX_STREAM_DATA frame
 * @stream: Stream flow control state
 * @max_data: New limit from peer
 *
 * Return: 0 on success
 */
int tquic_fc_handle_max_stream_data(struct tquic_fc_stream_state *stream,
				    u64 max_data)
{
	unsigned long flags;

	if (!stream)
		return -EINVAL;

	spin_lock_irqsave(&stream->lock, flags);

	/* Can only increase */
	if (max_data > stream->max_data_remote) {
		stream->max_data_remote = max_data;

		/* Clear blocked state */
		if (stream->data_sent < max_data)
			stream->data_blocked_sent = false;

		pr_debug("tquic_fc: stream %llu MAX_STREAM_DATA=%llu\n",
			 stream->stream_id, max_data);
	}

	spin_unlock_irqrestore(&stream->lock, flags);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_fc_handle_max_stream_data);

/**
 * tquic_fc_handle_stream_data_blocked - Handle STREAM_DATA_BLOCKED frame
 * @stream: Stream flow control state
 * @max_data: Limit where peer is blocked
 */
void tquic_fc_handle_stream_data_blocked(struct tquic_fc_stream_state *stream,
					 u64 max_data)
{
	unsigned long flags;

	if (!stream)
		return;

	spin_lock_irqsave(&stream->lock, flags);
	stream->data_blocked_received = true;
	spin_unlock_irqrestore(&stream->lock, flags);

	pr_debug("tquic_fc: stream %llu blocked at %llu\n",
		 stream->stream_id, max_data);
}
EXPORT_SYMBOL_GPL(tquic_fc_handle_stream_data_blocked);

/**
 * tquic_fc_needs_max_stream_data - Check if MAX_STREAM_DATA needed
 * @stream: Stream flow control state
 *
 * Return: true if MAX_STREAM_DATA should be sent
 */
bool tquic_fc_needs_max_stream_data(struct tquic_fc_stream_state *stream)
{
	bool needs;
	unsigned long flags;

	if (!stream)
		return false;

	spin_lock_irqsave(&stream->lock, flags);
	needs = stream->needs_max_stream_data &&
		(stream->max_data_next > stream->last_max_data_sent);
	spin_unlock_irqrestore(&stream->lock, flags);

	return needs;
}
EXPORT_SYMBOL_GPL(tquic_fc_needs_max_stream_data);

/**
 * tquic_fc_get_max_stream_data - Get MAX_STREAM_DATA value
 * @stream: Stream flow control state
 *
 * Return: Value for MAX_STREAM_DATA frame
 */
u64 tquic_fc_get_max_stream_data(struct tquic_fc_stream_state *stream)
{
	u64 max_data;
	unsigned long flags;

	if (!stream)
		return 0;

	spin_lock_irqsave(&stream->lock, flags);
	max_data = stream->max_data_next;
	spin_unlock_irqrestore(&stream->lock, flags);

	return max_data;
}
EXPORT_SYMBOL_GPL(tquic_fc_get_max_stream_data);

/**
 * tquic_fc_max_stream_data_sent - Mark MAX_STREAM_DATA as sent
 * @stream: Stream flow control state
 * @max_data: Value that was sent
 */
void tquic_fc_max_stream_data_sent(struct tquic_fc_stream_state *stream,
				   u64 max_data)
{
	unsigned long flags;

	if (!stream)
		return;

	spin_lock_irqsave(&stream->lock, flags);
	stream->last_max_data_sent = max_data;
	stream->max_data_local = max_data;
	stream->needs_max_stream_data = false;
	spin_unlock_irqrestore(&stream->lock, flags);
}
EXPORT_SYMBOL_GPL(tquic_fc_max_stream_data_sent);

/**
 * tquic_fc_needs_stream_data_blocked - Check if STREAM_DATA_BLOCKED needed
 * @stream: Stream flow control state
 *
 * Return: true if STREAM_DATA_BLOCKED should be sent
 */
bool tquic_fc_needs_stream_data_blocked(struct tquic_fc_stream_state *stream)
{
	bool needs;
	unsigned long flags;

	if (!stream)
		return false;

	spin_lock_irqsave(&stream->lock, flags);
	needs = (stream->data_sent >= stream->max_data_remote) &&
		!stream->data_blocked_sent;
	spin_unlock_irqrestore(&stream->lock, flags);

	return needs;
}
EXPORT_SYMBOL_GPL(tquic_fc_needs_stream_data_blocked);

/**
 * tquic_fc_get_stream_data_blocked - Get STREAM_DATA_BLOCKED value
 * @stream: Stream flow control state
 *
 * Return: Offset for STREAM_DATA_BLOCKED frame
 */
u64 tquic_fc_get_stream_data_blocked(struct tquic_fc_stream_state *stream)
{
	u64 blocked_at;
	unsigned long flags;

	if (!stream)
		return 0;

	spin_lock_irqsave(&stream->lock, flags);
	blocked_at = stream->blocked_at;
	spin_unlock_irqrestore(&stream->lock, flags);

	return blocked_at;
}
EXPORT_SYMBOL_GPL(tquic_fc_get_stream_data_blocked);

/**
 * tquic_fc_stream_data_blocked_sent - Mark STREAM_DATA_BLOCKED as sent
 * @stream: Stream flow control state
 */
void tquic_fc_stream_data_blocked_sent(struct tquic_fc_stream_state *stream)
{
	unsigned long flags;

	if (!stream)
		return;

	spin_lock_irqsave(&stream->lock, flags);
	stream->data_blocked_sent = true;
	spin_unlock_irqrestore(&stream->lock, flags);
}
EXPORT_SYMBOL_GPL(tquic_fc_stream_data_blocked_sent);

/*
 * ==========================================================================
 * Stream Count Limits (MAX_STREAMS / STREAMS_BLOCKED)
 * RFC 9000 Section 4.6
 * ==========================================================================
 */

/**
 * tquic_fc_can_open_bidi_stream - Check if new bidi stream can be opened
 * @fc: Flow control state
 *
 * Return: true if opening is allowed
 */
bool tquic_fc_can_open_bidi_stream(struct tquic_fc_state *fc)
{
	bool can_open;
	unsigned long flags;

	if (!fc)
		return false;

	spin_lock_irqsave(&fc->streams.lock, flags);
	can_open = fc->streams.streams_bidi_opened <
		   fc->streams.max_streams_bidi_remote;
	spin_unlock_irqrestore(&fc->streams.lock, flags);

	return can_open;
}
EXPORT_SYMBOL_GPL(tquic_fc_can_open_bidi_stream);

/**
 * tquic_fc_can_open_uni_stream - Check if new uni stream can be opened
 * @fc: Flow control state
 *
 * Return: true if opening is allowed
 */
bool tquic_fc_can_open_uni_stream(struct tquic_fc_state *fc)
{
	bool can_open;
	unsigned long flags;

	if (!fc)
		return false;

	spin_lock_irqsave(&fc->streams.lock, flags);
	can_open = fc->streams.streams_uni_opened <
		   fc->streams.max_streams_uni_remote;
	spin_unlock_irqrestore(&fc->streams.lock, flags);

	return can_open;
}
EXPORT_SYMBOL_GPL(tquic_fc_can_open_uni_stream);

/**
 * tquic_fc_bidi_stream_opened - Record opening a bidi stream
 * @fc: Flow control state
 *
 * Return: 0 on success, -ENOSPC if limit reached
 */
int tquic_fc_bidi_stream_opened(struct tquic_fc_state *fc)
{
	unsigned long flags;
	int ret = 0;

	if (!fc)
		return -EINVAL;

	spin_lock_irqsave(&fc->streams.lock, flags);

	if (fc->streams.streams_bidi_opened >= fc->streams.max_streams_bidi_remote) {
		fc->streams.blocked_bidi_at = fc->streams.max_streams_bidi_remote;
		fc->blocked_flags |= TQUIC_FC_BLOCKED_STREAMS_BIDI;
		ret = -ENOSPC;
	} else {
		fc->streams.streams_bidi_opened++;

		if (fc->streams.streams_bidi_opened >=
		    fc->streams.max_streams_bidi_remote) {
			fc->streams.blocked_bidi_at =
				fc->streams.max_streams_bidi_remote;
			fc->blocked_flags |= TQUIC_FC_BLOCKED_STREAMS_BIDI;
		}
	}

	spin_unlock_irqrestore(&fc->streams.lock, flags);

	return ret;
}
EXPORT_SYMBOL_GPL(tquic_fc_bidi_stream_opened);

/**
 * tquic_fc_uni_stream_opened - Record opening a uni stream
 * @fc: Flow control state
 *
 * Return: 0 on success, -ENOSPC if limit reached
 */
int tquic_fc_uni_stream_opened(struct tquic_fc_state *fc)
{
	unsigned long flags;
	int ret = 0;

	if (!fc)
		return -EINVAL;

	spin_lock_irqsave(&fc->streams.lock, flags);

	if (fc->streams.streams_uni_opened >= fc->streams.max_streams_uni_remote) {
		fc->streams.blocked_uni_at = fc->streams.max_streams_uni_remote;
		fc->blocked_flags |= TQUIC_FC_BLOCKED_STREAMS_UNI;
		ret = -ENOSPC;
	} else {
		fc->streams.streams_uni_opened++;

		if (fc->streams.streams_uni_opened >=
		    fc->streams.max_streams_uni_remote) {
			fc->streams.blocked_uni_at =
				fc->streams.max_streams_uni_remote;
			fc->blocked_flags |= TQUIC_FC_BLOCKED_STREAMS_UNI;
		}
	}

	spin_unlock_irqrestore(&fc->streams.lock, flags);

	return ret;
}
EXPORT_SYMBOL_GPL(tquic_fc_uni_stream_opened);

/**
 * tquic_fc_bidi_stream_received - Record receiving a peer-initiated bidi stream
 * @fc: Flow control state
 * @stream_id: The stream ID received
 *
 * Return: 0 on success, -EPROTO if limit violated
 */
int tquic_fc_bidi_stream_received(struct tquic_fc_state *fc, u64 stream_id)
{
	unsigned long flags;
	u64 stream_num;
	int ret = 0;

	if (!fc)
		return -EINVAL;

	stream_num = tquic_fc_stream_num(stream_id);

	spin_lock_irqsave(&fc->streams.lock, flags);

	/* Check if this would exceed our limit */
	if (stream_num >= fc->streams.max_streams_bidi_local) {
		pr_warn("tquic_fc: peer exceeded MAX_STREAMS (bidi)\n");
		ret = -EPROTO;
	} else {
		/* Track highest stream number seen */
		if (stream_num >= fc->streams.streams_bidi_received)
			fc->streams.streams_bidi_received = stream_num + 1;
	}

	spin_unlock_irqrestore(&fc->streams.lock, flags);

	return ret;
}
EXPORT_SYMBOL_GPL(tquic_fc_bidi_stream_received);

/**
 * tquic_fc_uni_stream_received - Record receiving a peer-initiated uni stream
 * @fc: Flow control state
 * @stream_id: The stream ID received
 *
 * Return: 0 on success, -EPROTO if limit violated
 */
int tquic_fc_uni_stream_received(struct tquic_fc_state *fc, u64 stream_id)
{
	unsigned long flags;
	u64 stream_num;
	int ret = 0;

	if (!fc)
		return -EINVAL;

	stream_num = tquic_fc_stream_num(stream_id);

	spin_lock_irqsave(&fc->streams.lock, flags);

	if (stream_num >= fc->streams.max_streams_uni_local) {
		pr_warn("tquic_fc: peer exceeded MAX_STREAMS (uni)\n");
		ret = -EPROTO;
	} else {
		if (stream_num >= fc->streams.streams_uni_received)
			fc->streams.streams_uni_received = stream_num + 1;
	}

	spin_unlock_irqrestore(&fc->streams.lock, flags);

	return ret;
}
EXPORT_SYMBOL_GPL(tquic_fc_uni_stream_received);

/**
 * tquic_fc_handle_max_streams - Handle MAX_STREAMS frame
 * @fc: Flow control state
 * @max_streams: New stream limit
 * @bidi: true for bidirectional, false for unidirectional
 *
 * Return: 0 on success
 */
int tquic_fc_handle_max_streams(struct tquic_fc_state *fc, u64 max_streams,
				bool bidi)
{
	unsigned long flags;

	if (!fc)
		return -EINVAL;

	spin_lock_irqsave(&fc->streams.lock, flags);

	if (bidi) {
		if (max_streams > fc->streams.max_streams_bidi_remote) {
			fc->streams.max_streams_bidi_remote = max_streams;

			if (fc->streams.streams_bidi_opened < max_streams) {
				fc->blocked_flags &= ~TQUIC_FC_BLOCKED_STREAMS_BIDI;
				fc->streams.streams_blocked_bidi_sent = false;
			}

			fc->stats.max_streams_frames_received++;
		}
	} else {
		if (max_streams > fc->streams.max_streams_uni_remote) {
			fc->streams.max_streams_uni_remote = max_streams;

			if (fc->streams.streams_uni_opened < max_streams) {
				fc->blocked_flags &= ~TQUIC_FC_BLOCKED_STREAMS_UNI;
				fc->streams.streams_blocked_uni_sent = false;
			}

			fc->stats.max_streams_frames_received++;
		}
	}

	spin_unlock_irqrestore(&fc->streams.lock, flags);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_fc_handle_max_streams);

/**
 * tquic_fc_handle_streams_blocked - Handle STREAMS_BLOCKED frame
 * @fc: Flow control state
 * @max_streams: Limit where peer is blocked
 * @bidi: true for bidirectional
 */
void tquic_fc_handle_streams_blocked(struct tquic_fc_state *fc, u64 max_streams,
				     bool bidi)
{
	unsigned long flags;

	if (!fc)
		return;

	spin_lock_irqsave(&fc->streams.lock, flags);

	fc->stats.streams_blocked_frames_received++;

	/*
	 * Peer is blocked on stream creation - consider increasing limit
	 * This could trigger a MAX_STREAMS update
	 */
	if (bidi) {
		if (max_streams >= fc->streams.max_streams_bidi_local)
			fc->streams.needs_max_streams_bidi = true;
	} else {
		if (max_streams >= fc->streams.max_streams_uni_local)
			fc->streams.needs_max_streams_uni = true;
	}

	spin_unlock_irqrestore(&fc->streams.lock, flags);

	pr_debug("tquic_fc: peer STREAMS_BLOCKED at %llu (%s)\n",
		 max_streams, bidi ? "bidi" : "uni");
}
EXPORT_SYMBOL_GPL(tquic_fc_handle_streams_blocked);

/**
 * tquic_fc_needs_max_streams - Check if MAX_STREAMS should be sent
 * @fc: Flow control state
 * @bidi: Output - true if bidi MAX_STREAMS needed
 *
 * Return: true if any MAX_STREAMS frame should be sent
 */
bool tquic_fc_needs_max_streams(struct tquic_fc_state *fc, bool *bidi)
{
	bool needs = false;
	unsigned long flags;

	if (!fc)
		return false;

	spin_lock_irqsave(&fc->streams.lock, flags);

	if (fc->streams.needs_max_streams_bidi) {
		needs = true;
		if (bidi)
			*bidi = true;
	} else if (fc->streams.needs_max_streams_uni) {
		needs = true;
		if (bidi)
			*bidi = false;
	}

	spin_unlock_irqrestore(&fc->streams.lock, flags);

	return needs;
}
EXPORT_SYMBOL_GPL(tquic_fc_needs_max_streams);

/**
 * tquic_fc_get_max_streams - Get MAX_STREAMS value to send
 * @fc: Flow control state
 * @bidi: true for bidirectional
 *
 * Return: MAX_STREAMS value
 */
u64 tquic_fc_get_max_streams(struct tquic_fc_state *fc, bool bidi)
{
	u64 max_streams;
	unsigned long flags;

	if (!fc)
		return 0;

	spin_lock_irqsave(&fc->streams.lock, flags);
	if (bidi)
		max_streams = fc->streams.max_streams_bidi_local;
	else
		max_streams = fc->streams.max_streams_uni_local;
	spin_unlock_irqrestore(&fc->streams.lock, flags);

	return max_streams;
}
EXPORT_SYMBOL_GPL(tquic_fc_get_max_streams);

/**
 * tquic_fc_max_streams_sent - Mark MAX_STREAMS as sent
 * @fc: Flow control state
 * @max_streams: Value that was sent
 * @bidi: true for bidirectional
 */
void tquic_fc_max_streams_sent(struct tquic_fc_state *fc, u64 max_streams,
			       bool bidi)
{
	unsigned long flags;

	if (!fc)
		return;

	spin_lock_irqsave(&fc->streams.lock, flags);

	if (bidi) {
		fc->streams.max_streams_bidi_local = max_streams;
		fc->streams.needs_max_streams_bidi = false;
	} else {
		fc->streams.max_streams_uni_local = max_streams;
		fc->streams.needs_max_streams_uni = false;
	}

	fc->stats.max_streams_frames_sent++;

	spin_unlock_irqrestore(&fc->streams.lock, flags);
}
EXPORT_SYMBOL_GPL(tquic_fc_max_streams_sent);

/**
 * tquic_fc_needs_streams_blocked - Check if STREAMS_BLOCKED needed
 * @fc: Flow control state
 * @bidi: Output - which type is blocked
 *
 * Return: true if STREAMS_BLOCKED should be sent
 */
bool tquic_fc_needs_streams_blocked(struct tquic_fc_state *fc, bool *bidi)
{
	bool needs = false;
	unsigned long flags;

	if (!fc)
		return false;

	spin_lock_irqsave(&fc->streams.lock, flags);

	if ((fc->blocked_flags & TQUIC_FC_BLOCKED_STREAMS_BIDI) &&
	    !fc->streams.streams_blocked_bidi_sent) {
		needs = true;
		if (bidi)
			*bidi = true;
	} else if ((fc->blocked_flags & TQUIC_FC_BLOCKED_STREAMS_UNI) &&
		   !fc->streams.streams_blocked_uni_sent) {
		needs = true;
		if (bidi)
			*bidi = false;
	}

	spin_unlock_irqrestore(&fc->streams.lock, flags);

	return needs;
}
EXPORT_SYMBOL_GPL(tquic_fc_needs_streams_blocked);

/**
 * tquic_fc_get_streams_blocked - Get STREAMS_BLOCKED value
 * @fc: Flow control state
 * @bidi: true for bidirectional
 *
 * Return: Stream count for STREAMS_BLOCKED frame
 */
u64 tquic_fc_get_streams_blocked(struct tquic_fc_state *fc, bool bidi)
{
	u64 blocked_at;
	unsigned long flags;

	if (!fc)
		return 0;

	spin_lock_irqsave(&fc->streams.lock, flags);
	if (bidi)
		blocked_at = fc->streams.blocked_bidi_at;
	else
		blocked_at = fc->streams.blocked_uni_at;
	spin_unlock_irqrestore(&fc->streams.lock, flags);

	return blocked_at;
}
EXPORT_SYMBOL_GPL(tquic_fc_get_streams_blocked);

/**
 * tquic_fc_streams_blocked_sent - Mark STREAMS_BLOCKED as sent
 * @fc: Flow control state
 * @bidi: true for bidirectional
 */
void tquic_fc_streams_blocked_sent(struct tquic_fc_state *fc, bool bidi)
{
	unsigned long flags;

	if (!fc)
		return;

	spin_lock_irqsave(&fc->streams.lock, flags);

	if (bidi)
		fc->streams.streams_blocked_bidi_sent = true;
	else
		fc->streams.streams_blocked_uni_sent = true;

	fc->stats.streams_blocked_frames_sent++;

	spin_unlock_irqrestore(&fc->streams.lock, flags);
}
EXPORT_SYMBOL_GPL(tquic_fc_streams_blocked_sent);

/*
 * ==========================================================================
 * Credit Management
 * ==========================================================================
 */

/**
 * tquic_fc_get_credit - Get combined credit for sending
 * @fc: Flow control state
 * @stream: Stream flow control state
 * @credit: Output credit information
 *
 * Calculates the effective credit available considering both
 * connection-level and stream-level limits.
 */
void tquic_fc_get_credit(struct tquic_fc_state *fc,
			 struct tquic_fc_stream_state *stream,
			 struct tquic_fc_credit *credit)
{
	unsigned long flags;

	if (!fc || !stream || !credit) {
		if (credit)
			memset(credit, 0, sizeof(*credit));
		return;
	}

	/* Get connection-level credit */
	spin_lock_irqsave(&fc->conn.lock, flags);
	if (fc->conn.max_data_remote > fc->conn.data_sent)
		credit->conn_credit = fc->conn.max_data_remote - fc->conn.data_sent;
	else
		credit->conn_credit = 0;
	credit->conn_blocked = (credit->conn_credit == 0);
	spin_unlock_irqrestore(&fc->conn.lock, flags);

	/* Get stream-level credit */
	spin_lock_irqsave(&stream->lock, flags);
	if (stream->max_data_remote > stream->data_sent)
		credit->stream_credit = stream->max_data_remote - stream->data_sent;
	else
		credit->stream_credit = 0;
	credit->stream_blocked = (credit->stream_credit == 0);
	spin_unlock_irqrestore(&stream->lock, flags);

	/* Effective credit is minimum of both */
	credit->effective_credit = min(credit->conn_credit, credit->stream_credit);
}
EXPORT_SYMBOL_GPL(tquic_fc_get_credit);

/**
 * tquic_fc_reserve_credit - Reserve credit for pending transmission
 * @fc: Flow control state
 * @stream: Stream flow control state
 * @bytes: Bytes to reserve
 *
 * Return: 0 on success, -ENOSPC if insufficient credit
 */
int tquic_fc_reserve_credit(struct tquic_fc_state *fc,
			    struct tquic_fc_stream_state *stream,
			    u64 bytes)
{
	struct tquic_fc_credit credit;

	if (!fc || !stream)
		return -EINVAL;

	tquic_fc_get_credit(fc, stream, &credit);

	if (bytes > credit.effective_credit)
		return -ENOSPC;

	/* Credit will be committed when transmission succeeds */
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_fc_reserve_credit);

/**
 * tquic_fc_release_credit - Release reserved credit (transmission failed)
 * @fc: Flow control state
 * @stream: Stream flow control state
 * @bytes: Bytes to release
 *
 * Called when a transmission fails and reserved credit should be returned.
 */
void tquic_fc_release_credit(struct tquic_fc_state *fc,
			     struct tquic_fc_stream_state *stream,
			     u64 bytes)
{
	/* Credits are not actually reserved until committed */
	/* This is a no-op in our implementation */
}
EXPORT_SYMBOL_GPL(tquic_fc_release_credit);

/**
 * tquic_fc_commit_credit - Commit credit usage (transmission succeeded)
 * @fc: Flow control state
 * @stream: Stream flow control state
 * @bytes: Bytes transmitted
 *
 * Called when transmission succeeds to update flow control state.
 */
void tquic_fc_commit_credit(struct tquic_fc_state *fc,
			    struct tquic_fc_stream_state *stream,
			    u64 bytes)
{
	if (!fc || !stream)
		return;

	/* Update connection level */
	tquic_fc_conn_data_sent(fc, bytes);

	/* Update stream level */
	tquic_fc_stream_data_sent(stream, bytes);
}
EXPORT_SYMBOL_GPL(tquic_fc_commit_credit);

/*
 * ==========================================================================
 * Window Update Logic
 * ==========================================================================
 */

/**
 * tquic_fc_should_update_conn_window - Check if connection window should update
 * @fc: Flow control state
 *
 * Determines if enough data has been consumed to warrant sending
 * a MAX_DATA update. Uses threshold-based approach.
 *
 * Return: true if window should be updated
 *
 * Note: Caller must hold fc->conn.lock
 */
bool tquic_fc_should_update_conn_window(struct tquic_fc_state *fc)
{
	u64 available_window;
	u64 consumed_since_update;
	u64 update_threshold;

	if (!fc)
		return false;

	/* Calculate how much window is still available */
	available_window = fc->conn.max_data_local - fc->conn.data_received;

	/* Calculate how much was consumed since last update */
	consumed_since_update = fc->conn.data_consumed -
		(fc->conn.last_max_data_sent - fc->conn.max_data_local);

	/*
	 * RFC 9000 recommends sending MAX_DATA when the receiver has consumed
	 * a significant portion of the window. We use a configurable threshold.
	 */
	update_threshold = fc->conn.max_data_local / TQUIC_FC_WINDOW_UPDATE_THRESHOLD;

	return consumed_since_update >= update_threshold;
}
EXPORT_SYMBOL_GPL(tquic_fc_should_update_conn_window);

/**
 * tquic_fc_should_update_stream_window - Check if stream window should update
 * @stream: Stream flow control state
 * @fc: Connection flow control state
 *
 * Return: true if stream window should be updated
 */
bool tquic_fc_should_update_stream_window(struct tquic_fc_stream_state *stream,
					  struct tquic_fc_state *fc)
{
	u64 consumed_since_update;
	u64 update_threshold;
	bool should_update;
	unsigned long flags;

	if (!stream || !fc)
		return false;

	spin_lock_irqsave(&stream->lock, flags);

	consumed_since_update = stream->data_consumed -
		(stream->last_max_data_sent - stream->max_data_local);

	update_threshold = stream->max_data_local / TQUIC_FC_WINDOW_UPDATE_THRESHOLD;

	should_update = consumed_since_update >= update_threshold;

	spin_unlock_irqrestore(&stream->lock, flags);

	return should_update;
}
EXPORT_SYMBOL_GPL(tquic_fc_should_update_stream_window);

/**
 * tquic_fc_calc_conn_window - Calculate new connection window size
 * @fc: Flow control state
 *
 * Calculates the new MAX_DATA value to advertise, potentially
 * using auto-tuning based on network conditions.
 *
 * Return: New window size
 *
 * Note: Caller must hold fc->conn.lock
 */
u64 tquic_fc_calc_conn_window(struct tquic_fc_state *fc)
{
	u64 new_window;
	u64 base_window;

	if (!fc)
		return TQUIC_FC_DEFAULT_MAX_DATA;

	/* Start with current window as base */
	base_window = fc->conn.max_data_local - fc->conn.data_received +
		      fc->conn.data_consumed;

	if (fc->autotune.enabled) {
		/*
		 * Auto-tune based on BDP (Bandwidth-Delay Product)
		 * Target window = bandwidth * RTT * multiplier
		 */
		if (fc->autotune.bandwidth > 0 && fc->autotune.rtt_us > 0) {
			u64 bdp = (fc->autotune.bandwidth * fc->autotune.rtt_us) /
				  1000000ULL;
			u64 target = bdp * TQUIC_FC_AUTOTUNE_RTT_MULTIPLIER;

			/* Apply growth rate */
			target = (target * fc->autotune.growth_rate) >> 8;

			/* Clamp to configured limits */
			target = clamp(target, fc->config.min_window,
				       fc->config.max_window);

			if (target > base_window)
				new_window = target;
			else
				new_window = base_window;

			fc->autotune.target_window = new_window;
		} else {
			new_window = base_window;
		}
	} else {
		new_window = base_window;
	}

	/* Ensure monotonically increasing */
	new_window = max(new_window, fc->conn.max_data_local);

	/* Apply maximum limit */
	new_window = min(new_window, fc->config.max_window);

	/* Calculate actual MAX_DATA value */
	return fc->conn.data_consumed + new_window;
}
EXPORT_SYMBOL_GPL(tquic_fc_calc_conn_window);

/**
 * tquic_fc_calc_stream_window - Calculate new stream window size
 * @stream: Stream flow control state
 * @fc: Connection flow control state
 *
 * Return: New stream window size
 */
u64 tquic_fc_calc_stream_window(struct tquic_fc_stream_state *stream,
				struct tquic_fc_state *fc)
{
	u64 new_window;
	unsigned long flags;

	if (!stream || !fc)
		return TQUIC_FC_DEFAULT_MAX_STREAM_DATA_BIDI_LOCAL;

	spin_lock_irqsave(&stream->lock, flags);

	/* Simple calculation: consumed + current window size */
	new_window = stream->data_consumed +
		     (stream->max_data_local - stream->data_received +
		      stream->data_consumed);

	/* Ensure monotonically increasing */
	new_window = max(new_window, stream->max_data_local);

	spin_unlock_irqrestore(&stream->lock, flags);

	return new_window;
}
EXPORT_SYMBOL_GPL(tquic_fc_calc_stream_window);

/*
 * ==========================================================================
 * Auto-tuning
 * ==========================================================================
 */

/**
 * tquic_fc_update_rtt - Update RTT for auto-tuning
 * @fc: Flow control state
 * @rtt_us: RTT sample in microseconds
 */
void tquic_fc_update_rtt(struct tquic_fc_state *fc, u32 rtt_us)
{
	if (!fc || !fc->autotune.enabled)
		return;

	/* Simple EWMA for RTT */
	if (fc->autotune.rtt_us == 0)
		fc->autotune.rtt_us = rtt_us;
	else
		fc->autotune.rtt_us = (fc->autotune.rtt_us * 7 + rtt_us) / 8;
}
EXPORT_SYMBOL_GPL(tquic_fc_update_rtt);

/**
 * tquic_fc_update_bandwidth - Update bandwidth estimate
 * @fc: Flow control state
 * @bandwidth: Bandwidth in bytes per second
 */
void tquic_fc_update_bandwidth(struct tquic_fc_state *fc, u64 bandwidth)
{
	if (!fc || !fc->autotune.enabled)
		return;

	/* Simple EWMA for bandwidth */
	if (fc->autotune.bandwidth == 0)
		fc->autotune.bandwidth = bandwidth;
	else
		fc->autotune.bandwidth = (fc->autotune.bandwidth * 7 + bandwidth) / 8;
}
EXPORT_SYMBOL_GPL(tquic_fc_update_bandwidth);

/**
 * tquic_fc_autotune - Perform auto-tune calculation
 * @fc: Flow control state
 *
 * Should be called periodically to adjust receive windows based
 * on observed network conditions.
 */
void tquic_fc_autotune(struct tquic_fc_state *fc)
{
	ktime_t now;
	s64 elapsed_ms;
	unsigned long flags;

	if (!fc || !fc->autotune.enabled)
		return;

	now = ktime_get();
	elapsed_ms = ktime_ms_delta(now, fc->autotune.last_update);

	if (elapsed_ms < TQUIC_FC_AUTOTUNE_INTERVAL_MS)
		return;

	spin_lock_irqsave(&fc->conn.lock, flags);

	/*
	 * Adjust growth rate based on observed conditions:
	 * - If we're receiving data steadily, maintain or increase
	 * - If peer sent DATA_BLOCKED, increase more aggressively
	 * - If data rate dropped, decrease conservatively
	 */
	if (fc->conn.data_blocked_received) {
		/* Peer was blocked, increase window */
		fc->autotune.growth_rate = min(fc->autotune.growth_rate + 32,
					       512U);
		fc->conn.data_blocked_received = false;
	} else if (fc->autotune.bytes_since_update > 0) {
		/* Normal operation, maintain current rate */
		/* Slight increase to probe for more capacity */
		if (fc->autotune.growth_rate < 384)
			fc->autotune.growth_rate += 4;
	} else {
		/* No data received, slowly decrease */
		if (fc->autotune.growth_rate > 256)
			fc->autotune.growth_rate -= 8;
	}

	/* Calculate new window if appropriate */
	if (tquic_fc_should_update_conn_window(fc)) {
		fc->conn.max_data_next = tquic_fc_calc_conn_window(fc);
		fc->conn.needs_max_data = true;
		fc->stats.autotune_adjustments++;
	}

	fc->autotune.bytes_since_update = 0;
	fc->autotune.last_update = now;

	spin_unlock_irqrestore(&fc->conn.lock, flags);
}
EXPORT_SYMBOL_GPL(tquic_fc_autotune);

/**
 * tquic_fc_set_autotune - Enable or disable auto-tuning
 * @fc: Flow control state
 * @enabled: true to enable, false to disable
 */
void tquic_fc_set_autotune(struct tquic_fc_state *fc, bool enabled)
{
	if (!fc)
		return;

	fc->autotune.enabled = enabled;

	if (enabled) {
		fc->autotune.last_update = ktime_get();
		fc->autotune.bytes_since_update = 0;
	}
}
EXPORT_SYMBOL_GPL(tquic_fc_set_autotune);

/*
 * ==========================================================================
 * Utility Functions
 * ==========================================================================
 */

/**
 * tquic_fc_get_initial_max_stream_data - Get initial stream window
 * @fc: Flow control state
 * @stream_id: Stream identifier
 * @is_server: true if we are the server
 *
 * Determines the appropriate initial MAX_STREAM_DATA based on
 * stream type and who initiated it.
 *
 * Return: Initial MAX_STREAM_DATA value
 */
u64 tquic_fc_get_initial_max_stream_data(struct tquic_fc_state *fc,
					 u64 stream_id, bool is_server)
{
	bool is_bidi = tquic_fc_stream_is_bidi(stream_id);
	bool is_local = tquic_fc_stream_is_local(stream_id, is_server);

	if (!fc)
		return TQUIC_FC_DEFAULT_MAX_STREAM_DATA_BIDI_LOCAL;

	if (is_bidi) {
		if (is_local)
			return fc->config.initial_max_stream_data_bidi_local;
		else
			return fc->config.initial_max_stream_data_bidi_remote;
	} else {
		return fc->config.initial_max_stream_data_uni;
	}
}
EXPORT_SYMBOL_GPL(tquic_fc_get_initial_max_stream_data);

/**
 * tquic_fc_reset - Reset flow control state (0-RTT rejection)
 * @fc: Flow control state
 *
 * Resets flow control state to initial values when 0-RTT is rejected.
 */
void tquic_fc_reset(struct tquic_fc_state *fc)
{
	unsigned long flags;

	if (!fc)
		return;

	/* Reset connection-level state */
	spin_lock_irqsave(&fc->conn.lock, flags);
	fc->conn.data_sent = 0;
	fc->conn.data_received = 0;
	fc->conn.data_consumed = 0;
	fc->conn.max_data_local = fc->config.initial_max_data;
	fc->conn.max_data_next = fc->config.initial_max_data;
	fc->conn.last_max_data_sent = fc->config.initial_max_data;
	fc->conn.max_data_remote = 0;
	fc->conn.needs_max_data = false;
	fc->conn.data_blocked_sent = false;
	fc->conn.data_blocked_received = false;
	spin_unlock_irqrestore(&fc->conn.lock, flags);

	/* Reset stream count state */
	spin_lock_irqsave(&fc->streams.lock, flags);
	fc->streams.streams_bidi_opened = 0;
	fc->streams.streams_uni_opened = 0;
	fc->streams.streams_bidi_received = 0;
	fc->streams.streams_uni_received = 0;
	fc->streams.max_streams_bidi_remote = 0;
	fc->streams.max_streams_uni_remote = 0;
	fc->streams.needs_max_streams_bidi = false;
	fc->streams.needs_max_streams_uni = false;
	fc->streams.streams_blocked_bidi_sent = false;
	fc->streams.streams_blocked_uni_sent = false;
	spin_unlock_irqrestore(&fc->streams.lock, flags);

	fc->blocked_flags = 0;

	pr_debug("tquic_fc: flow control state reset\n");
}
EXPORT_SYMBOL_GPL(tquic_fc_reset);

/**
 * tquic_fc_get_stats - Get flow control statistics
 * @fc: Flow control state
 * @stats: Buffer to copy stats into
 * @len: Size of stats buffer
 */
void tquic_fc_get_stats(struct tquic_fc_state *fc, void *stats, size_t len)
{
	if (!fc || !stats)
		return;

	len = min(len, sizeof(fc->stats));
	memcpy(stats, &fc->stats, len);
}
EXPORT_SYMBOL_GPL(tquic_fc_get_stats);

/*
 * ==========================================================================
 * Stream Layer Integration
 * ==========================================================================
 */

/**
 * tquic_fc_stream_check_recv - Validate incoming stream data
 * @fc: Connection flow control state
 * @stream_fc: Stream flow control state
 * @offset: Data offset
 * @length: Data length
 * @fin: FIN flag
 *
 * Performs all flow control checks for incoming stream data.
 *
 * Return: 0 on success, negative error on flow control violation
 */
int tquic_fc_stream_check_recv(struct tquic_fc_state *fc,
			       struct tquic_fc_stream_state *stream_fc,
			       u64 offset, u64 length, bool fin)
{
	u64 end_offset = offset + length;
	int ret;

	if (!fc || !stream_fc)
		return -EINVAL;

	/* Check stream-level limit */
	ret = tquic_fc_stream_data_received(stream_fc, offset, length, fin);
	if (ret < 0)
		return ret;

	/* Check connection-level limit */
	ret = tquic_fc_conn_data_received(fc, length);
	if (ret < 0)
		return ret;

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_fc_stream_check_recv);

/**
 * tquic_fc_stream_check_send - Validate outgoing stream data
 * @fc: Connection flow control state
 * @stream_fc: Stream flow control state
 * @length: Data length to send
 *
 * Checks if sending the specified amount of data is allowed.
 *
 * Return: 0 on success, -ENOSPC if blocked
 */
int tquic_fc_stream_check_send(struct tquic_fc_state *fc,
			       struct tquic_fc_stream_state *stream_fc,
			       u64 length)
{
	struct tquic_fc_credit credit;

	if (!fc || !stream_fc)
		return -EINVAL;

	tquic_fc_get_credit(fc, stream_fc, &credit);

	if (length > credit.effective_credit)
		return -ENOSPC;

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_fc_stream_check_send);

/**
 * tquic_fc_on_stream_consumed - Called when application consumes stream data
 * @fc: Connection flow control state
 * @stream_fc: Stream flow control state
 * @bytes: Bytes consumed
 *
 * Updates both stream and connection level consumption tracking.
 */
void tquic_fc_on_stream_consumed(struct tquic_fc_state *fc,
				 struct tquic_fc_stream_state *stream_fc,
				 u64 bytes)
{
	if (!fc || !stream_fc)
		return;

	/* Update stream level */
	tquic_fc_stream_data_consumed(stream_fc, bytes);

	/* Update connection level */
	tquic_fc_conn_data_consumed(fc, bytes);
}
EXPORT_SYMBOL_GPL(tquic_fc_on_stream_consumed);

/**
 * tquic_fc_collect_frames - Collect pending flow control frames
 * @fc: Connection flow control state
 * @max_data: Output - MAX_DATA to send (0 if none)
 * @data_blocked: Output - DATA_BLOCKED to send (0 if none)
 * @max_streams_bidi: Output - MAX_STREAMS bidi to send (0 if none)
 * @max_streams_uni: Output - MAX_STREAMS uni to send (0 if none)
 *
 * Collects all pending connection-level flow control frames
 * that need to be sent.
 */
void tquic_fc_collect_frames(struct tquic_fc_state *fc,
			     u64 *max_data, u64 *data_blocked,
			     u64 *max_streams_bidi, u64 *max_streams_uni)
{
	if (!fc)
		return;

	if (max_data)
		*max_data = tquic_fc_needs_max_data(fc) ?
			    tquic_fc_get_max_data(fc) : 0;

	if (data_blocked)
		*data_blocked = tquic_fc_needs_data_blocked(fc) ?
				tquic_fc_get_data_blocked(fc) : 0;

	if (max_streams_bidi)
		*max_streams_bidi = tquic_fc_needs_max_streams(fc, NULL) ?
				    tquic_fc_get_max_streams(fc, true) : 0;

	if (max_streams_uni)
		*max_streams_uni = tquic_fc_needs_max_streams(fc, NULL) ?
				   tquic_fc_get_max_streams(fc, false) : 0;
}
EXPORT_SYMBOL_GPL(tquic_fc_collect_frames);

MODULE_DESCRIPTION("TQUIC QUIC Flow Control (RFC 9000 Section 4)");
MODULE_AUTHOR("Linux Foundation");
MODULE_LICENSE("GPL");
