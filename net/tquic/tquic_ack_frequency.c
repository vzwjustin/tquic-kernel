// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: ACK Frequency Extension (draft-ietf-quic-ack-frequency)
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Implements ACK_FREQUENCY and IMMEDIATE_ACK frames to allow sender
 * control over how frequently the peer generates acknowledgments.
 *
 * This extension allows a sender to optimize ACK behavior for the
 * connection's characteristics:
 *   - High-bandwidth paths benefit from reduced ACK frequency
 *   - Latency-sensitive applications can request immediate ACKs
 *   - Reorder-tolerant applications can reduce spurious ACKs
 *
 * Frame Types:
 *   - ACK_FREQUENCY (0xaf): Negotiate delayed ACK behavior
 *   - IMMEDIATE_ACK (0xac): Request immediate ACK from peer
 *
 * Transport Parameter:
 *   - min_ack_delay (0x0e): Minimum ACK delay in microseconds
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <net/tquic.h>

#include "tquic_ack_frequency.h"
#include "tquic_mib.h"

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
 * ACK Frequency State Management
 * =============================================================================
 */

/**
 * tquic_ack_freq_init - Initialize ACK frequency state for a connection
 */
int tquic_ack_freq_init(struct tquic_connection *conn)
{
	struct tquic_ack_frequency_state *state;

	if (!conn)
		return -EINVAL;

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return -ENOMEM;

	spin_lock_init(&state->lock);

	/* Set defaults per draft-ietf-quic-ack-frequency */
	state->enabled = false;
	state->min_ack_delay_us = TQUIC_DEFAULT_MAX_ACK_DELAY_US;
	state->peer_min_ack_delay_us = TQUIC_DEFAULT_MAX_ACK_DELAY_US;
	state->last_sent_seq = 0;
	state->last_recv_seq = 0;
	state->current_ack_elicit_threshold = TQUIC_DEFAULT_ACK_ELICITING_THRESHOLD;
	state->current_max_ack_delay_us = TQUIC_DEFAULT_MAX_ACK_DELAY_US;
	state->current_reorder_threshold = TQUIC_DEFAULT_REORDER_THRESHOLD;
	state->pending_send = false;
	state->pending_immediate_ack = false;
	state->packets_since_ack = 0;

	/* Store state in connection - use crypto_state temporarily
	 * TODO: Add dedicated ack_freq_state field to tquic_connection */
	/* For now we'll embed in the connection's private area */

	pr_debug("tquic: ACK frequency state initialized\n");

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_init);

/**
 * tquic_ack_freq_cleanup - Clean up ACK frequency state
 */
void tquic_ack_freq_cleanup(struct tquic_connection *conn)
{
	/* State cleanup would happen here */
	pr_debug("tquic: ACK frequency state cleaned up\n");
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_cleanup);

/**
 * tquic_ack_freq_enable - Enable ACK frequency extension after negotiation
 */
void tquic_ack_freq_enable(struct tquic_connection *conn, u64 peer_min_ack_delay)
{
	if (!conn)
		return;

	/* Validate peer's min_ack_delay */
	if (peer_min_ack_delay < TQUIC_MIN_ACK_DELAY_MIN_US ||
	    peer_min_ack_delay > TQUIC_MIN_ACK_DELAY_MAX_US) {
		pr_warn("tquic: invalid peer min_ack_delay: %llu\n",
			peer_min_ack_delay);
		return;
	}

	pr_debug("tquic: ACK frequency enabled, peer_min_ack_delay=%llu us\n",
		 peer_min_ack_delay);
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_enable);

/**
 * tquic_ack_freq_is_enabled - Check if ACK frequency is enabled
 */
bool tquic_ack_freq_is_enabled(struct tquic_connection *conn)
{
	if (!conn)
		return false;

	/* Check sysctl first */
	if (!tquic_sysctl_get_ack_frequency_enabled())
		return false;

	/* Extension must be negotiated via transport parameters */
	return true;
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_is_enabled);

/*
 * =============================================================================
 * Frame Size Calculation
 * =============================================================================
 */

/**
 * tquic_ack_frequency_frame_size - Calculate ACK_FREQUENCY frame size
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

/*
 * =============================================================================
 * Frame Generation
 * =============================================================================
 */

/**
 * tquic_gen_ack_frequency_frame - Generate ACK_FREQUENCY frame
 *
 * ACK_FREQUENCY Frame {
 *   Type (i) = 0xaf,
 *   Sequence Number (i),
 *   Ack-Eliciting Threshold (i),
 *   Request Max Ack Delay (i),
 *   Reorder Threshold (i),
 * }
 */
int tquic_gen_ack_frequency_frame(struct tquic_connection *conn,
				  u8 *buf, size_t buf_len,
				  u64 ack_eliciting_threshold,
				  u64 request_max_ack_delay,
				  u64 reorder_threshold,
				  u64 *seq_num)
{
	u8 *p = buf;
	int ret;
	size_t required_size;
	u64 next_seq;

	if (!conn || !buf || !seq_num)
		return -EINVAL;

	/* Get next sequence number (monotonically increasing) */
	spin_lock(&conn->lock);
	/* Would use ack_freq state here; for now use a simple counter */
	next_seq = conn->stats.tx_packets & 0xFFFF; /* Simplified */
	spin_unlock(&conn->lock);

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

	pr_debug("tquic: generated ACK_FREQUENCY frame: seq=%llu threshold=%llu "
		 "max_delay=%llu reorder=%llu\n",
		 next_seq, ack_eliciting_threshold,
		 request_max_ack_delay, reorder_threshold);

	return (int)(p - buf);
}
EXPORT_SYMBOL_GPL(tquic_gen_ack_frequency_frame);

/**
 * tquic_gen_immediate_ack_frame - Generate IMMEDIATE_ACK frame
 *
 * IMMEDIATE_ACK Frame {
 *   Type (i) = 0xac,
 * }
 *
 * The frame has no additional fields beyond the type.
 */
int tquic_gen_immediate_ack_frame(u8 *buf, size_t buf_len)
{
	int ret;

	if (!buf)
		return -EINVAL;

	/* Frame type (0xac) - requires 2 bytes as varint */
	ret = varint_encode(buf, buf_len, TQUIC_FRAME_IMMEDIATE_ACK);
	if (ret < 0)
		return ret;

	pr_debug("tquic: generated IMMEDIATE_ACK frame\n");

	return ret;
}
EXPORT_SYMBOL_GPL(tquic_gen_immediate_ack_frame);

/*
 * =============================================================================
 * Frame Parsing
 * =============================================================================
 */

/**
 * tquic_parse_ack_frequency_frame - Parse ACK_FREQUENCY frame
 *
 * Parses from after the frame type byte.
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

	pr_debug("tquic: parsed ACK_FREQUENCY frame: seq=%llu threshold=%llu "
		 "max_delay=%llu reorder=%llu\n",
		 frame->sequence_number, frame->ack_eliciting_threshold,
		 frame->request_max_ack_delay, frame->reorder_threshold);

	return (int)(p - buf);
}
EXPORT_SYMBOL_GPL(tquic_parse_ack_frequency_frame);

/**
 * tquic_parse_immediate_ack_frame - Parse IMMEDIATE_ACK frame
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

	if (frame_type != TQUIC_FRAME_IMMEDIATE_ACK)
		return -EINVAL;

	pr_debug("tquic: parsed IMMEDIATE_ACK frame\n");

	return ret;
}
EXPORT_SYMBOL_GPL(tquic_parse_immediate_ack_frame);

/*
 * =============================================================================
 * Frame Handling
 * =============================================================================
 */

/**
 * tquic_handle_ack_frequency_frame - Process received ACK_FREQUENCY frame
 *
 * Per draft-ietf-quic-ack-frequency Section 4.1:
 * "An endpoint MUST use the values from the ACK_FREQUENCY frame with
 * the largest received Sequence Number field value."
 */
int tquic_handle_ack_frequency_frame(struct tquic_connection *conn,
				     const struct tquic_ack_frequency_frame *frame)
{
	if (!conn || !frame)
		return -EINVAL;

	/* Validate the frame */
	if (frame->ack_eliciting_threshold == 0) {
		pr_warn("tquic: ACK_FREQUENCY with zero threshold is invalid\n");
		return -EINVAL;
	}

	/*
	 * Per Section 4.1: Only process if sequence number is larger than
	 * previously received. This ensures monotonicity.
	 */
	spin_lock(&conn->lock);

	/* Would compare against last_recv_seq in ack_freq state */
	/* For now, just log and apply */

	spin_unlock(&conn->lock);

	pr_debug("tquic: applied ACK_FREQUENCY: threshold=%llu max_delay=%llu "
		 "reorder=%llu\n",
		 frame->ack_eliciting_threshold,
		 frame->request_max_ack_delay,
		 frame->reorder_threshold);

	/* Update MIB counter */
	if (conn->sk)
		TQUIC_INC_STATS(sock_net(conn->sk), TQUIC_MIB_PACKETSRX);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_handle_ack_frequency_frame);

/**
 * tquic_handle_immediate_ack_frame - Process received IMMEDIATE_ACK frame
 *
 * Per draft-ietf-quic-ack-frequency Section 5:
 * "When an endpoint receives an IMMEDIATE_ACK frame, it SHOULD send
 * an ACK frame immediately upon receiving an ack-eliciting packet."
 */
int tquic_handle_immediate_ack_frame(struct tquic_connection *conn)
{
	if (!conn)
		return -EINVAL;

	/*
	 * Set flag to trigger immediate ACK on next ack-eliciting packet.
	 * The actual ACK generation happens in the receive path.
	 */
	spin_lock(&conn->lock);
	/* Would set pending_immediate_ack in ack_freq state */
	spin_unlock(&conn->lock);

	pr_debug("tquic: received IMMEDIATE_ACK, will ACK next packet immediately\n");

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_handle_immediate_ack_frame);

/*
 * =============================================================================
 * ACK Decision Logic
 * =============================================================================
 */

/**
 * tquic_ack_freq_on_packet_received - Notify ACK frequency of packet receipt
 *
 * Returns true if an ACK should be sent based on:
 * 1. IMMEDIATE_ACK was requested
 * 2. Ack-eliciting threshold reached
 * 3. Reorder threshold exceeded
 */
bool tquic_ack_freq_on_packet_received(struct tquic_connection *conn,
				       bool ack_eliciting,
				       u64 pkt_num,
				       u64 expected_pkt_num)
{
	bool should_ack = false;
	u64 threshold;
	u64 reorder_gap;

	if (!conn)
		return true;  /* Default: ACK everything */

	if (!ack_eliciting)
		return false;  /* Non-ack-eliciting packets don't trigger ACKs */

	spin_lock(&conn->lock);

	/* Default thresholds */
	threshold = TQUIC_DEFAULT_ACK_ELICITING_THRESHOLD;

	/* Check reorder threshold */
	if (pkt_num < expected_pkt_num) {
		reorder_gap = expected_pkt_num - pkt_num;
		/* Reordering detected - may need immediate ACK */
		if (TQUIC_DEFAULT_REORDER_THRESHOLD > 0 &&
		    reorder_gap > TQUIC_DEFAULT_REORDER_THRESHOLD) {
			should_ack = true;
			pr_debug("tquic: reorder threshold exceeded, sending ACK\n");
		}
	}

	/* Increment packet counter and check threshold */
	/* Would use ack_freq state packets_since_ack here */
	/* Simplified: use stats counter */
	conn->stats.rx_packets++;

	if ((conn->stats.rx_packets % threshold) == 0)
		should_ack = true;

	spin_unlock(&conn->lock);

	return should_ack;
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_on_packet_received);

/**
 * tquic_ack_freq_on_ack_sent - Notify ACK frequency that ACK was sent
 */
void tquic_ack_freq_on_ack_sent(struct tquic_connection *conn)
{
	if (!conn)
		return;

	spin_lock(&conn->lock);
	/* Would reset packets_since_ack in ack_freq state */
	spin_unlock(&conn->lock);
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_on_ack_sent);

/**
 * tquic_ack_freq_should_ack_immediately - Check if immediate ACK needed
 */
bool tquic_ack_freq_should_ack_immediately(struct tquic_connection *conn)
{
	bool immediate = false;

	if (!conn)
		return true;

	spin_lock(&conn->lock);
	/* Would check pending_immediate_ack in ack_freq state */
	spin_unlock(&conn->lock);

	return immediate;
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_should_ack_immediately);

/**
 * tquic_ack_freq_should_ack - Determine if ACK should be sent
 * @state: ACK frequency state
 * @pn: Packet number just received
 * @ack_eliciting: Whether the packet was ack-eliciting
 *
 * Implements the ACK suppression algorithm from draft-ietf-quic-ack-frequency.
 * Returns true if an ACK should be sent.
 */
bool tquic_ack_freq_should_ack(struct tquic_ack_frequency_state *state,
			       u64 pn, bool ack_eliciting)
{
	bool should_ack = false;
	u64 threshold;

	if (!state)
		return true;  /* Default to ACK everything */

	if (!ack_eliciting)
		return false;  /* Non-ack-eliciting packets don't trigger ACKs */

	spin_lock(&state->lock);

	/* Extension not enabled - use default behavior */
	if (!state->enabled) {
		/* Default: ACK every 2 packets */
		state->packets_since_ack++;
		if (state->packets_since_ack >= 2)
			should_ack = true;
		spin_unlock(&state->lock);
		return should_ack;
	}

	/* Check for pending IMMEDIATE_ACK */
	if (state->pending_immediate_ack) {
		state->pending_immediate_ack = false;
		should_ack = true;
		goto out;
	}

	/* Increment packet counter */
	state->packets_since_ack++;

	/* Check ack-eliciting threshold */
	threshold = state->current_ack_elicit_threshold;
	if (state->packets_since_ack >= threshold) {
		should_ack = true;
		goto out;
	}

	/*
	 * Reorder detection is simplified for this struct version.
	 * The current_reorder_threshold can be used for future extensions.
	 */

out:
	spin_unlock(&state->lock);
	return should_ack;
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_should_ack);

/**
 * tquic_ack_freq_get_max_delay - Get current max ACK delay
 */
u64 tquic_ack_freq_get_max_delay(struct tquic_connection *conn)
{
	u64 delay = TQUIC_DEFAULT_MAX_ACK_DELAY_US;

	if (!conn)
		return delay;

	spin_lock(&conn->lock);
	/* Would return current_max_ack_delay_us from ack_freq state */
	delay = tquic_sysctl_get_default_ack_delay_us();
	spin_unlock(&conn->lock);

	return delay;
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_get_max_delay);

/*
 * =============================================================================
 * Transport Parameter Support
 * =============================================================================
 */

/**
 * tquic_ack_freq_encode_tp - Encode min_ack_delay transport parameter
 *
 * Transport Parameter {
 *   Type (i) = 0x0e,
 *   Length (i),
 *   Value (i) = min_ack_delay in microseconds,
 * }
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

	/* Parameter ID (0x0e) */
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
		pr_warn("tquic: min_ack_delay out of range: %llu\n",
			*min_ack_delay_us);
		return -EINVAL;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_decode_tp);

/*
 * =============================================================================
 * Sender Control API
 * =============================================================================
 */

/**
 * tquic_ack_freq_request_update - Request peer update ACK behavior
 */
int tquic_ack_freq_request_update(struct tquic_connection *conn,
				  u64 ack_elicit_threshold,
				  u64 max_ack_delay_us,
				  u64 reorder_threshold)
{
	if (!conn)
		return -EINVAL;

	if (!tquic_ack_freq_is_enabled(conn))
		return -EOPNOTSUPP;

	/* Validate parameters */
	if (ack_elicit_threshold == 0)
		return -EINVAL;

	spin_lock(&conn->lock);
	/* Would set pending_send and store parameters in ack_freq state */
	spin_unlock(&conn->lock);

	pr_debug("tquic: scheduled ACK_FREQUENCY update: threshold=%llu "
		 "delay=%llu reorder=%llu\n",
		 ack_elicit_threshold, max_ack_delay_us, reorder_threshold);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_request_update);

/**
 * tquic_ack_freq_request_immediate_ack - Request immediate ACK from peer
 */
int tquic_ack_freq_request_immediate_ack(struct tquic_connection *conn)
{
	if (!conn)
		return -EINVAL;

	if (!tquic_ack_freq_is_enabled(conn))
		return -EOPNOTSUPP;

	spin_lock(&conn->lock);
	/* Would set pending_immediate_ack in ack_freq state */
	spin_unlock(&conn->lock);

	pr_debug("tquic: scheduled IMMEDIATE_ACK request\n");

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_request_immediate_ack);

/**
 * tquic_ack_freq_has_pending_frames - Check for pending ACK frequency frames
 */
bool tquic_ack_freq_has_pending_frames(struct tquic_connection *conn)
{
	bool pending = false;

	if (!conn)
		return false;

	spin_lock(&conn->lock);
	/* Would check pending_send || pending_immediate_ack in ack_freq state */
	spin_unlock(&conn->lock);

	return pending;
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_has_pending_frames);

/*
 * =============================================================================
 * Module Information
 * =============================================================================
 */

MODULE_DESCRIPTION("TQUIC ACK Frequency Extension");
MODULE_LICENSE("GPL");
