// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: ACK Frequency Extension (RFC 9002 Appendix A.7)
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Connection-level wrappers for ACK Frequency extension.
 *
 * This file provides the connection-level API that wraps the core
 * ACK frequency implementation in core/ack_frequency.c. It manages
 * the ack_freq_state field in tquic_connection and provides the
 * interface used by the TQUIC protocol implementation.
 *
 * Frame Types:
 *   - ACK_FREQUENCY (0xaf): Request peer adjust ACK behavior
 *   - IMMEDIATE_ACK (0x1f): Request immediate ACK from peer
 *
 * Transport Parameter:
 *   - min_ack_delay (0xff04de1a): Minimum ACK delay in microseconds
 *
 * Features:
 *   - Full integration with tquic_connection structure
 *   - Automatic state management during connection lifecycle
 *   - Congestion control integration callbacks
 *   - Dynamic ACK frequency adjustment
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <net/tquic.h>

#include "tquic_ack_frequency.h"
#include "tquic_mib.h"
#include "tquic_debug.h"
#include "core/ack_frequency.h"

/* Bounds for received ACK_FREQUENCY frame parameters */
#define TQUIC_MIN_ACK_DELAY_US		1000	/* 1ms minimum */
#define TQUIC_MAX_ACK_THRESHOLD		256	/* max ack-eliciting threshold */

/*
 * =============================================================================
 * Variable Length Integer Helpers (RFC 9000 Section 16)
 * =============================================================================
 */

static inline size_t varint_len(u64 val)
{
	if (val <= 63)
		return 1;
	if (val <= 16383)
		return 2;
	if (val <= 1073741823)
		return 4;
	return 8;
}

static inline int varint_encode(u8 *buf, size_t buf_len, u64 val)
{
	size_t len = varint_len(val);

	if (buf_len < len)
		return -ENOSPC;

	switch (len) {
	case 1:
		buf[0] = (u8)val;
		break;
	case 2:
		buf[0] = 0x40 | (u8)(val >> 8);
		buf[1] = (u8)val;
		break;
	case 4:
		buf[0] = 0x80 | (u8)(val >> 24);
		buf[1] = (u8)(val >> 16);
		buf[2] = (u8)(val >> 8);
		buf[3] = (u8)val;
		break;
	case 8:
		buf[0] = 0xc0 | (u8)(val >> 56);
		buf[1] = (u8)(val >> 48);
		buf[2] = (u8)(val >> 40);
		buf[3] = (u8)(val >> 32);
		buf[4] = (u8)(val >> 24);
		buf[5] = (u8)(val >> 16);
		buf[6] = (u8)(val >> 8);
		buf[7] = (u8)val;
		break;
	}

	return (int)len;
}

static inline int varint_decode(const u8 *buf, size_t buf_len, u64 *val)
{
	u8 prefix;
	size_t len;

	if (buf_len < 1)
		return -EINVAL;

	prefix = buf[0] >> 6;
	len = 1 << prefix;

	if (buf_len < len)
		return -EINVAL;

	switch (len) {
	case 1:
		*val = buf[0] & 0x3f;
		break;
	case 2:
		*val = ((u64)(buf[0] & 0x3f) << 8) | buf[1];
		break;
	case 4:
		*val = ((u64)(buf[0] & 0x3f) << 24) |
		       ((u64)buf[1] << 16) |
		       ((u64)buf[2] << 8) |
		       buf[3];
		break;
	case 8:
		*val = ((u64)(buf[0] & 0x3f) << 56) |
		       ((u64)buf[1] << 48) |
		       ((u64)buf[2] << 40) |
		       ((u64)buf[3] << 32) |
		       ((u64)buf[4] << 24) |
		       ((u64)buf[5] << 16) |
		       ((u64)buf[6] << 8) |
		       buf[7];
		break;
	}

	return (int)len;
}

/*
 * =============================================================================
 * Helper Functions
 * =============================================================================
 */

/**
 * conn_get_ack_freq_state - Get ACK frequency state from connection
 * @conn: Connection
 *
 * Returns the ACK frequency state, or NULL if not initialized.
 */
static inline struct tquic_ack_frequency_state *
conn_get_ack_freq_state(struct tquic_connection *conn)
{
	if (!conn)
		return NULL;
	return (struct tquic_ack_frequency_state *)conn->ack_freq_state;
}

/*
 * =============================================================================
 * Connection-Level State Management
 * =============================================================================
 */

/**
 * tquic_ack_freq_conn_init - Initialize ACK frequency state for a connection
 * @conn: Connection to initialize
 *
 * Allocates and initializes the ACK frequency state, storing it in
 * conn->ack_freq_state.
 *
 * Return: 0 on success, negative error on failure
 */
int tquic_ack_freq_conn_init(struct tquic_connection *conn)
{
	struct tquic_ack_frequency_state *state;

	if (!conn)
		return -EINVAL;

	/* Check if already initialized */
	if (conn->ack_freq_state)
		return 0;

	/* Check if ACK frequency is globally enabled */
	if (!tquic_sysctl_get_ack_frequency_enabled()) {
		conn->ack_freq_state = NULL;
		return 0;
	}

	/* Use core implementation to create state */
	state = tquic_ack_freq_state_create(conn);
	if (!state)
		return -ENOMEM;

	/* Set default min_ack_delay from sysctl */
	state->min_ack_delay_us = tquic_sysctl_get_default_ack_delay_us();

	/* Store in connection */
	conn->ack_freq_state = state;

	tquic_dbg("ACK frequency state initialized for connection\n");

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_conn_init);

/**
 * tquic_ack_freq_conn_cleanup - Clean up ACK frequency state
 * @conn: Connection to clean up
 */
void tquic_ack_freq_conn_cleanup(struct tquic_connection *conn)
{
	struct tquic_ack_frequency_state *state;

	if (!conn)
		return;

	state = conn_get_ack_freq_state(conn);
	if (!state)
		return;

	/* Use core implementation to destroy state */
	tquic_ack_freq_state_destroy(state);
	conn->ack_freq_state = NULL;

	tquic_dbg("ACK frequency state cleaned up for connection\n");
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_conn_cleanup);

/**
 * tquic_ack_freq_conn_enable - Enable ACK frequency extension
 * @conn: Connection
 * @peer_min_ack_delay: Peer's min_ack_delay transport parameter (microseconds)
 */
void tquic_ack_freq_conn_enable(struct tquic_connection *conn,
				u64 peer_min_ack_delay)
{
	struct tquic_ack_frequency_state *state;

	if (!conn)
		return;

	state = conn_get_ack_freq_state(conn);
	if (!state)
		return;

	/* Use core implementation to enable */
	tquic_ack_freq_enable(state, peer_min_ack_delay);

	tquic_dbg("ACK frequency enabled for connection, "
		 "peer_min_ack_delay=%llu us\n", peer_min_ack_delay);
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_conn_enable);

/**
 * tquic_ack_freq_conn_is_enabled - Check if ACK frequency is enabled
 * @conn: Connection to check
 *
 * Return: true if ACK frequency extension is negotiated and enabled
 */
bool tquic_ack_freq_conn_is_enabled(struct tquic_connection *conn)
{
	struct tquic_ack_frequency_state *state;

	if (!conn)
		return false;

	/* Check global sysctl first */
	if (!tquic_sysctl_get_ack_frequency_enabled())
		return false;

	state = conn_get_ack_freq_state(conn);
	if (!state)
		return false;

	return tquic_ack_freq_is_enabled(state);
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_conn_is_enabled);

/*
 * =============================================================================
 * Legacy API (for backward compatibility)
 * =============================================================================
 */

/*
 * Legacy wrapper functions removed - they conflicted with core API.
 * Use the _conn suffix versions:
 *   - tquic_ack_freq_conn_init()
 *   - tquic_ack_freq_conn_cleanup()
 *   - tquic_ack_freq_conn_enable()
 *   - tquic_ack_freq_conn_is_enabled()
 */

/* tquic_ack_freq_conn_is_enabled is already defined above */

/*
 * =============================================================================
 * Frame Size Calculation
 * =============================================================================
 */

/*
 * For out-of-tree builds, frame size/parse functions provided by core/ack_frequency.c
 */
#ifndef TQUIC_OUT_OF_TREE
/**
 * tquic_ack_frequency_frame_size - Calculate ACK_FREQUENCY frame size
 * @ack_eliciting_threshold: ACK-eliciting threshold value
 * @request_max_ack_delay: Max ACK delay value
 * @reorder_threshold: Reorder threshold value
 * @seq_num: Sequence number value
 *
 * Return: Size in bytes needed for the frame
 */
size_t tquic_ack_frequency_frame_size(u64 ack_eliciting_threshold,
				      u64 request_max_ack_delay,
				      u64 reorder_threshold,
				      u64 seq_num)
{
	size_t size = 0;

	/* Frame type (0xaf requires 2 bytes as varint) */
	size += varint_len(TQUIC_FRAME_ACK_FREQUENCY);

	/* Sequence Number */
	size += varint_len(seq_num);

	/* Ack-Eliciting Threshold */
	size += varint_len(ack_eliciting_threshold);

	/* Request Max Ack Delay */
	size += varint_len(request_max_ack_delay);

	/* Reorder Threshold */
	size += varint_len(reorder_threshold);

	return size;
}
EXPORT_SYMBOL_GPL(tquic_ack_frequency_frame_size);
#endif /* !TQUIC_OUT_OF_TREE */

/*
 * =============================================================================
 * Frame Generation
 * =============================================================================
 */

/**
 * tquic_gen_ack_frequency_frame - Generate ACK_FREQUENCY frame
 * @conn: Connection
 * @buf: Output buffer
 * @buf_len: Buffer length
 * @ack_eliciting_threshold: ACK-eliciting packets before ACK required
 * @request_max_ack_delay: Requested max ACK delay (microseconds)
 * @reorder_threshold: Reorder threshold (packets)
 * @seq_num: Output sequence number assigned
 *
 * Return: Number of bytes written, or negative error code
 */
int tquic_gen_ack_frequency_frame(struct tquic_connection *conn,
				  u8 *buf, size_t buf_len,
				  u64 ack_eliciting_threshold,
				  u64 request_max_ack_delay,
				  u64 reorder_threshold,
				  u64 *seq_num)
{
	struct tquic_ack_frequency_state *state;
	u8 *p = buf;
	int ret;
	size_t required_size;
	u64 next_seq;

	if (!conn || !buf || !seq_num)
		return -EINVAL;

	state = conn_get_ack_freq_state(conn);
	if (!state) {
		/* Fallback: use connection stats for sequence */
		spin_lock_bh(&conn->lock);
		next_seq = conn->stats.tx_packets & 0xFFFF;
		spin_unlock_bh(&conn->lock);
	} else {
		/* Get next sequence number from state */
		spin_lock_bh(&state->lock);
		next_seq = ++state->last_sent_seq;
		spin_unlock_bh(&state->lock);
	}

	/* Calculate required size */
	required_size = tquic_ack_frequency_frame_size(ack_eliciting_threshold,
						       request_max_ack_delay,
						       reorder_threshold,
						       next_seq);
	if (buf_len < required_size)
		return -ENOSPC;

	/* Frame type (0xaf) */
	ret = varint_encode(p, buf_len - (p - buf), TQUIC_FRAME_ACK_FREQUENCY);
	if (ret < 0)
		return ret;
	p += ret;

	/* Sequence Number */
	ret = varint_encode(p, buf_len - (p - buf), next_seq);
	if (ret < 0)
		return ret;
	p += ret;

	/* Ack-Eliciting Threshold */
	ret = varint_encode(p, buf_len - (p - buf), ack_eliciting_threshold);
	if (ret < 0)
		return ret;
	p += ret;

	/* Request Max Ack Delay */
	ret = varint_encode(p, buf_len - (p - buf), request_max_ack_delay);
	if (ret < 0)
		return ret;
	p += ret;

	/* Reorder Threshold */
	ret = varint_encode(p, buf_len - (p - buf), reorder_threshold);
	if (ret < 0)
		return ret;
	p += ret;

	*seq_num = next_seq;

	/* Update statistics */
	if (state) {
		spin_lock_bh(&state->lock);
		state->frames_sent++;
		spin_unlock_bh(&state->lock);
	}

	tquic_dbg("generated ACK_FREQUENCY frame: seq=%llu threshold=%llu "
		 "max_delay=%llu reorder=%llu\n",
		 next_seq, ack_eliciting_threshold,
		 request_max_ack_delay, reorder_threshold);

	return (int)(p - buf);
}
EXPORT_SYMBOL_GPL(tquic_gen_ack_frequency_frame);

/**
 * tquic_gen_immediate_ack_frame - Generate IMMEDIATE_ACK frame
 * @buf: Output buffer
 * @buf_len: Buffer length
 *
 * Return: Number of bytes written, or negative error code
 */
int tquic_gen_immediate_ack_frame(u8 *buf, size_t buf_len)
{
	int ret;

	if (!buf)
		return -EINVAL;

	/* Frame type (0x1f) */
	ret = varint_encode(buf, buf_len, TQUIC_FRAME_IMMEDIATE_ACK);
	if (ret < 0)
		return ret;

	tquic_dbg("generated IMMEDIATE_ACK frame\n");

	return ret;
}
EXPORT_SYMBOL_GPL(tquic_gen_immediate_ack_frame);

/*
 * =============================================================================
 * Frame Parsing
 * =============================================================================
 */

#ifndef TQUIC_OUT_OF_TREE
/**
 * tquic_parse_ack_frequency_frame - Parse ACK_FREQUENCY frame
 * @buf: Input buffer (starting after frame type byte)
 * @buf_len: Buffer length
 * @frame: Output frame structure
 *
 * Return: Bytes consumed on success, negative error on failure
 */
int tquic_parse_ack_frequency_frame(const u8 *buf, size_t buf_len,
				    struct tquic_ack_frequency_frame *frame)
{
	const u8 *p = buf;
	size_t remaining = buf_len;
	int ret;

	if (!buf || !frame)
		return -EINVAL;

	/* Sequence Number */
	ret = varint_decode(p, remaining, &frame->sequence_number);
	if (ret < 0)
		return ret;
	p += ret;
	remaining -= ret;

	/* Ack-Eliciting Threshold */
	ret = varint_decode(p, remaining, &frame->ack_eliciting_threshold);
	if (ret < 0)
		return ret;
	p += ret;
	remaining -= ret;

	/* Validate threshold - must be non-zero */
	if (frame->ack_eliciting_threshold == 0) {
		tquic_warn("ACK_FREQUENCY with zero threshold is invalid\n");
		return -EINVAL;
	}

	/* Request Max Ack Delay */
	ret = varint_decode(p, remaining, &frame->request_max_ack_delay);
	if (ret < 0)
		return ret;
	p += ret;
	remaining -= ret;

	/* Reorder Threshold */
	ret = varint_decode(p, remaining, &frame->reorder_threshold);
	if (ret < 0)
		return ret;
	p += ret;

	tquic_dbg("parsed ACK_FREQUENCY frame: seq=%llu threshold=%llu "
		 "max_delay=%llu reorder=%llu\n",
		 frame->sequence_number, frame->ack_eliciting_threshold,
		 frame->request_max_ack_delay, frame->reorder_threshold);

	return (int)(p - buf);
}
EXPORT_SYMBOL_GPL(tquic_parse_ack_frequency_frame);

/**
 * tquic_parse_immediate_ack_frame - Parse IMMEDIATE_ACK frame
 * @buf: Input buffer (starting at frame type byte)
 * @buf_len: Buffer length
 *
 * Return: Bytes consumed on success, negative error on failure
 */
int tquic_parse_immediate_ack_frame(const u8 *buf, size_t buf_len)
{
	u64 frame_type;
	int ret;

	if (!buf || buf_len < 1)
		return -EINVAL;

	/* Validate frame type */
	ret = varint_decode(buf, buf_len, &frame_type);
	if (ret < 0)
		return ret;

	if (frame_type != TQUIC_FRAME_IMMEDIATE_ACK) {
		tquic_warn("expected IMMEDIATE_ACK (0x1f), got 0x%llx\n",
			frame_type);
		return -EINVAL;
	}

	tquic_dbg("parsed IMMEDIATE_ACK frame\n");

	return ret;
}
EXPORT_SYMBOL_GPL(tquic_parse_immediate_ack_frame);
#endif /* !TQUIC_OUT_OF_TREE */

/*
 * =============================================================================
 * Frame Handling
 * =============================================================================
 */

/**
 * tquic_conn_handle_ack_frequency_frame - Process received ACK_FREQUENCY frame
 * @conn: Connection
 * @frame: Parsed frame
 *
 * Connection-level wrapper that delegates to core state-level function.
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_conn_handle_ack_frequency_frame(struct tquic_connection *conn,
					  const struct tquic_ack_frequency_frame *frame)
{
	struct tquic_ack_frequency_state *state;
	struct tquic_ack_frequency_frame clamped;

	if (!conn || !frame)
		return -EINVAL;

	/* Validate the frame */
	if (frame->ack_eliciting_threshold == 0) {
		tquic_warn("ACK_FREQUENCY with zero threshold is invalid\n");
		return -EINVAL;
	}

	/*
	 * Clamp received parameters to safe bounds before applying.
	 * This prevents a peer from setting extreme values that could
	 * degrade ACK responsiveness or waste resources.
	 */
	clamped = *frame;
	if (clamped.request_max_ack_delay < TQUIC_MIN_ACK_DELAY_US)
		clamped.request_max_ack_delay = TQUIC_MIN_ACK_DELAY_US;
	if (clamped.ack_eliciting_threshold > TQUIC_MAX_ACK_THRESHOLD)
		clamped.ack_eliciting_threshold = TQUIC_MAX_ACK_THRESHOLD;

	state = conn_get_ack_freq_state(conn);
	if (state) {
		/* Use core state-level implementation */
		int ret = tquic_handle_ack_frequency_frame(state, &clamped);
		if (ret < 0)
			return ret;
	} else {
		/* Extension not fully initialized - just log */
		tquic_dbg("received ACK_FREQUENCY but state not initialized\n");
	}

	/* Update MIB counter */
	if (conn->sk)
		TQUIC_INC_STATS(sock_net(conn->sk), TQUIC_MIB_PACKETSRX);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_conn_handle_ack_frequency_frame);

/**
 * tquic_conn_handle_immediate_ack_frame - Process received IMMEDIATE_ACK frame
 * @conn: Connection
 *
 * Connection-level wrapper that delegates to core state-level function.
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_conn_handle_immediate_ack_frame(struct tquic_connection *conn)
{
	struct tquic_ack_frequency_state *state;

	if (!conn)
		return -EINVAL;

	state = conn_get_ack_freq_state(conn);
	if (state) {
		/* Use core state-level implementation */
		return tquic_handle_immediate_ack_frame(state);
	}

	/* Extension not fully initialized - just log */
	tquic_dbg("received IMMEDIATE_ACK, will ACK next packet immediately\n");

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_conn_handle_immediate_ack_frame);

/*
 * =============================================================================
 * ACK Decision Logic
 * =============================================================================
 */

/**
 * tquic_ack_freq_on_packet_received - Notify ACK frequency of packet receipt
 * @conn: Connection
 * @ack_eliciting: Whether the packet was ack-eliciting
 * @pkt_num: Packet number received
 * @expected_pkt_num: Expected next packet number (for reorder detection)
 *
 * Return: true if an ACK should be sent
 */
bool tquic_ack_freq_on_packet_received(struct tquic_connection *conn,
				       bool ack_eliciting,
				       u64 pkt_num,
				       u64 expected_pkt_num)
{
	struct tquic_ack_frequency_state *state;

	if (!conn)
		return true;  /* Default: ACK everything */

	if (!ack_eliciting)
		return false;  /* Non-ack-eliciting packets don't trigger ACKs */

	state = conn_get_ack_freq_state(conn);
	if (state) {
		/* Use core implementation */
		return tquic_ack_freq_should_ack(state, pkt_num, ack_eliciting);
	}

	/* Default behavior: ACK every 2 packets */
	spin_lock_bh(&conn->lock);
	conn->stats.rx_packets++;
	spin_unlock_bh(&conn->lock);

	return (conn->stats.rx_packets % 2) == 0;
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_on_packet_received);

/**
 * tquic_ack_freq_conn_on_ack_sent - Notify ACK frequency that ACK was sent
 * @conn: Connection
 *
 * Connection-level wrapper that delegates to core state-level function.
 */
void tquic_ack_freq_conn_on_ack_sent(struct tquic_connection *conn)
{
	struct tquic_ack_frequency_state *state;

	if (!conn)
		return;

	state = conn_get_ack_freq_state(conn);
	if (state) {
		/* Use core state-level implementation */
		tquic_ack_freq_on_ack_sent(state);
	}
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_conn_on_ack_sent);

/**
 * tquic_ack_freq_should_ack_immediately - Check if immediate ACK needed
 * @conn: Connection
 *
 * Return: true if immediate ACK should be sent
 */
bool tquic_ack_freq_should_ack_immediately(struct tquic_connection *conn)
{
	struct tquic_ack_frequency_state *state;
	bool immediate = false;

	if (!conn)
		return true;

	state = conn_get_ack_freq_state(conn);
	if (state) {
		spin_lock_bh(&state->lock);
		immediate = state->immediate_ack_pending;
		spin_unlock_bh(&state->lock);
	}

	return immediate;
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_should_ack_immediately);

#ifndef TQUIC_OUT_OF_TREE
/**
 * tquic_ack_freq_should_ack - Determine if ACK should be sent (state-based)
 * @state: ACK frequency state
 * @pn: Packet number just received
 * @ack_eliciting: Whether the packet was ack-eliciting
 *
 * Return: true if an ACK should be sent
 */
bool tquic_ack_freq_should_ack(struct tquic_ack_frequency_state *state,
			       u64 pn, bool ack_eliciting)
{
	bool should_ack = false;
	u64 threshold;
	u64 gap;

	if (!state)
		return true;  /* Default to ACK everything */

	if (!ack_eliciting)
		return false;  /* Non-ack-eliciting packets don't trigger ACKs */

	spin_lock_bh(&state->lock);

	/* Extension not enabled - use default behavior */
	if (!state->enabled) {
		/* Default: ACK every 2 packets */
		state->packets_since_ack++;
		if (state->packets_since_ack >= 2)
			should_ack = true;
		goto out;
	}

	/* Check for pending IMMEDIATE_ACK */
	if (state->immediate_ack_pending) {
		state->immediate_ack_pending = false;
		should_ack = true;
		goto out;
	}

	/* During congestion, ACK more frequently */
	if (state->in_congestion) {
		threshold = state->dynamic_params.congestion_threshold;
	} else {
		threshold = state->current_threshold;
	}

	/* Increment packet counter */
	state->packets_since_ack++;

	/* Check reorder threshold before updating largest (if not ignoring order) */
	if (!state->ignore_order && state->current_reorder_threshold > 0) {
		if (pn < state->largest_pn_received) {
			gap = state->largest_pn_received - pn;
			if (gap >= state->current_reorder_threshold) {
				tquic_dbg("reorder threshold exceeded "
					 "(gap=%llu >= %llu)\n",
					 gap, state->current_reorder_threshold);
				state->reordering_detected = true;
				should_ack = true;
				goto out;
			}
		}
	}

	/* Update largest received -- must happen for every packet */
	if (pn > state->largest_pn_received)
		state->largest_pn_received = pn;

	/* Check ack-eliciting threshold */
	if (state->packets_since_ack >= threshold) {
		should_ack = true;
		goto out;
	}

out:
	spin_unlock_bh(&state->lock);
	return should_ack;
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_should_ack);
#endif /* !TQUIC_OUT_OF_TREE */

/**
 * tquic_ack_freq_conn_get_max_delay - Get current max ACK delay
 * @conn: Connection
 *
 * Connection-level wrapper that delegates to core state-level function.
 *
 * Return: Maximum ACK delay in microseconds
 */
u64 tquic_ack_freq_conn_get_max_delay(struct tquic_connection *conn)
{
	struct tquic_ack_frequency_state *state;

	if (!conn)
		return TQUIC_DEFAULT_MAX_ACK_DELAY_US;

	state = conn_get_ack_freq_state(conn);
	if (state) {
		/* Use core state-level implementation */
		return tquic_ack_freq_get_max_delay(state);
	}

	return tquic_sysctl_get_default_ack_delay_us();
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_conn_get_max_delay);

/*
 * =============================================================================
 * Transport Parameter Support
 * =============================================================================
 */

#ifndef TQUIC_OUT_OF_TREE
/**
 * tquic_ack_freq_encode_tp - Encode min_ack_delay transport parameter
 * @min_ack_delay_us: Minimum ACK delay in microseconds
 * @buf: Output buffer
 * @buf_len: Buffer length
 *
 * Return: Bytes written, or negative error code
 */
int tquic_ack_freq_encode_tp(u64 min_ack_delay_us, u8 *buf, size_t buf_len)
{
	u8 *p = buf;
	int ret;
	size_t value_len = varint_len(min_ack_delay_us);

	if (!buf)
		return -EINVAL;

	/* Validate value */
	if (min_ack_delay_us < TQUIC_MIN_ACK_DELAY_MIN_US ||
	    min_ack_delay_us > TQUIC_MIN_ACK_DELAY_MAX_US)
		return -EINVAL;

	/* Parameter ID (0xff04de1a) */
	ret = varint_encode(p, buf_len - (p - buf), TQUIC_TP_MIN_ACK_DELAY);
	if (ret < 0)
		return ret;
	p += ret;

	/* Length */
	ret = varint_encode(p, buf_len - (p - buf), value_len);
	if (ret < 0)
		return ret;
	p += ret;

	/* Value */
	ret = varint_encode(p, buf_len - (p - buf), min_ack_delay_us);
	if (ret < 0)
		return ret;
	p += ret;

	return (int)(p - buf);
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_encode_tp);

/**
 * tquic_ack_freq_decode_tp - Decode min_ack_delay transport parameter
 * @buf: Input buffer (parameter value only)
 * @buf_len: Value length
 * @min_ack_delay_us: Output minimum ACK delay
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_ack_freq_decode_tp(const u8 *buf, size_t buf_len, u64 *min_ack_delay_us)
{
	int ret;

	if (!buf || !min_ack_delay_us)
		return -EINVAL;

	ret = varint_decode(buf, buf_len, min_ack_delay_us);
	if (ret < 0)
		return ret;

	/* Validate range */
	if (*min_ack_delay_us < TQUIC_MIN_ACK_DELAY_MIN_US ||
	    *min_ack_delay_us > TQUIC_MIN_ACK_DELAY_MAX_US) {
		tquic_warn("min_ack_delay out of range: %llu\n",
			*min_ack_delay_us);
		return -EINVAL;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_decode_tp);
#endif /* !TQUIC_OUT_OF_TREE */

/*
 * =============================================================================
 * Sender Control API
 * =============================================================================
 */

/**
 * tquic_ack_freq_conn_request_update - Request peer update ACK behavior
 * @conn: Connection
 * @ack_elicit_threshold: Desired ack-eliciting threshold
 * @max_ack_delay_us: Desired max ACK delay (microseconds)
 * @reorder_threshold: Desired reorder threshold
 *
 * Connection-level wrapper that delegates to core state-level function.
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_ack_freq_conn_request_update(struct tquic_connection *conn,
				       u64 ack_elicit_threshold,
				       u64 max_ack_delay_us,
				       u64 reorder_threshold)
{
	struct tquic_ack_frequency_state *state;

	if (!conn)
		return -EINVAL;

	if (!tquic_ack_freq_conn_is_enabled(conn))
		return -EAGAIN;

	/* Validate parameters */
	if (ack_elicit_threshold == 0)
		return -EINVAL;

	state = conn_get_ack_freq_state(conn);
	if (state) {
		/* Use core state-level implementation */
		return tquic_ack_freq_request_update(state, ack_elicit_threshold,
						     max_ack_delay_us,
						     reorder_threshold);
	}

	tquic_dbg("scheduled ACK_FREQUENCY update: threshold=%llu "
		 "delay=%llu reorder=%llu\n",
		 ack_elicit_threshold, max_ack_delay_us, reorder_threshold);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_conn_request_update);

/**
 * tquic_ack_freq_conn_request_immediate_ack - Request immediate ACK from peer
 * @conn: Connection
 *
 * Connection-level wrapper.
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_ack_freq_conn_request_immediate_ack(struct tquic_connection *conn)
{
	struct tquic_ack_frequency_state *state;

	if (!conn)
		return -EINVAL;

	if (!tquic_ack_freq_conn_is_enabled(conn))
		return -EAGAIN;

	state = conn_get_ack_freq_state(conn);
	if (state) {
		spin_lock_bh(&state->lock);
		state->immediate_ack_request = true;
		spin_unlock_bh(&state->lock);
		return 0;
	}

	tquic_dbg("scheduled IMMEDIATE_ACK request\n");

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_conn_request_immediate_ack);

/**
 * tquic_ack_freq_has_pending_frames - Check for pending ACK frequency frames
 * @conn: Connection
 *
 * Return: true if frames need to be sent
 */
bool tquic_ack_freq_has_pending_frames(struct tquic_connection *conn)
{
	struct tquic_ack_frequency_state *state;

	if (!conn)
		return false;

	state = conn_get_ack_freq_state(conn);
	if (state) {
		/* Use core implementation */
		return tquic_ack_freq_has_pending(state);
	}

	return false;
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_has_pending_frames);

/**
 * tquic_ack_freq_generate_pending_frames - Generate pending frames
 * @conn: Connection
 * @buf: Output buffer
 * @buf_len: Buffer length
 *
 * Return: Bytes written, or negative error code
 */
int tquic_ack_freq_generate_pending_frames(struct tquic_connection *conn,
					   u8 *buf, size_t buf_len)
{
	struct tquic_ack_frequency_state *state;

	if (!conn || !buf)
		return -EINVAL;

	state = conn_get_ack_freq_state(conn);
	if (state) {
		/* Use core implementation */
		return tquic_ack_freq_generate_pending(state, buf, buf_len);
	}

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_generate_pending_frames);

/*
 * =============================================================================
 * Congestion Control Integration
 * =============================================================================
 */

/**
 * tquic_ack_freq_conn_on_congestion - Notify of congestion event
 * @conn: Connection
 * @in_recovery: Whether CC is in recovery state
 */
void tquic_ack_freq_conn_on_congestion(struct tquic_connection *conn,
				       bool in_recovery)
{
	struct tquic_ack_frequency_state *state;

	if (!conn)
		return;

	state = conn_get_ack_freq_state(conn);
	if (state) {
		/* Use core implementation */
		tquic_ack_freq_on_congestion_event(state, in_recovery);
	}
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_conn_on_congestion);

/**
 * tquic_ack_freq_conn_on_rtt_update - Notify of RTT update
 * @conn: Connection
 * @rtt_us: Smoothed RTT in microseconds
 * @rtt_var_us: RTT variance in microseconds
 */
void tquic_ack_freq_conn_on_rtt_update(struct tquic_connection *conn,
				       u64 rtt_us, u64 rtt_var_us)
{
	struct tquic_ack_frequency_state *state;

	if (!conn)
		return;

	state = conn_get_ack_freq_state(conn);
	if (state) {
		/* Use core implementation */
		tquic_ack_freq_on_rtt_update(state, rtt_us, rtt_var_us);
	}
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_conn_on_rtt_update);

/**
 * tquic_ack_freq_conn_on_bandwidth_update - Notify of bandwidth estimate update
 * @conn: Connection
 * @bandwidth_bps: Estimated bandwidth in bytes per second
 */
void tquic_ack_freq_conn_on_bandwidth_update(struct tquic_connection *conn,
					     u64 bandwidth_bps)
{
	struct tquic_ack_frequency_state *state;

	if (!conn)
		return;

	state = conn_get_ack_freq_state(conn);
	if (state) {
		/* Use core implementation */
		tquic_ack_freq_on_bandwidth_update(state, bandwidth_bps);
	}
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_conn_on_bandwidth_update);

/**
 * tquic_ack_freq_conn_on_reordering - Notify of packet reordering detection
 * @conn: Connection
 * @gap: Reorder gap in packets
 */
void tquic_ack_freq_conn_on_reordering(struct tquic_connection *conn, u64 gap)
{
	struct tquic_ack_frequency_state *state;

	if (!conn)
		return;

	state = conn_get_ack_freq_state(conn);
	if (state) {
		/* Use core implementation */
		tquic_ack_freq_on_reordering(state, gap);
	}
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_conn_on_reordering);

/**
 * tquic_ack_freq_conn_on_ecn - Notify of ECN congestion signal
 * @conn: Connection
 */
void tquic_ack_freq_conn_on_ecn(struct tquic_connection *conn)
{
	struct tquic_ack_frequency_state *state;

	if (!conn)
		return;

	state = conn_get_ack_freq_state(conn);
	if (state) {
		/* Use core implementation */
		tquic_ack_freq_on_ecn(state);
	}
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_conn_on_ecn);

/**
 * tquic_ack_freq_conn_set_app_hint - Set application-level hint
 * @conn: Connection
 * @latency_sensitive: True if application is latency-sensitive
 * @throughput_focused: True if application prioritizes throughput
 */
void tquic_ack_freq_conn_set_app_hint(struct tquic_connection *conn,
				      bool latency_sensitive,
				      bool throughput_focused)
{
	struct tquic_ack_frequency_state *state;

	if (!conn)
		return;

	state = conn_get_ack_freq_state(conn);
	if (state) {
		/* Use core implementation */
		tquic_ack_freq_set_application_hint(state, latency_sensitive,
						    throughput_focused);
	}
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_conn_set_app_hint);

/*
 * =============================================================================
 * Module Initialization
 * =============================================================================
 */

/**
 * tquic_ack_freq_module_init - Initialize ACK frequency module
 *
 * Called during TQUIC module initialization.
 *
 * Return: 0 on success, negative error on failure
 */
int __init tquic_ack_freq_module_init(void)
{
	int ret;

	/* Initialize core ACK frequency module */
	ret = tquic_ack_freq_init();
	if (ret) {
		tquic_err("failed to initialize ACK frequency core: %d\n",
			  ret);
		return ret;
	}

	tquic_info("ACK frequency extension module initialized\n");
	return 0;
}

/**
 * tquic_ack_freq_module_exit - Clean up ACK frequency module
 *
 * Called during TQUIC module unload.
 */
void tquic_ack_freq_module_exit(void)
{
	/* Clean up core ACK frequency module */
	tquic_ack_freq_exit();

	tquic_info("ACK frequency extension module cleaned up\n");
}

/*
 * =============================================================================
 * Module Information
 * =============================================================================
 */

MODULE_DESCRIPTION("TQUIC ACK Frequency Extension (RFC 9002 Appendix A.7)");
MODULE_LICENSE("GPL");
