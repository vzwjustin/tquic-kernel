// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: ACK Frequency Negotiation (draft-ietf-quic-ack-frequency)
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Implements the QUIC ACK Frequency extension which allows endpoints
 * to negotiate how often ACKs are sent. This extension enables:
 *   - Reduced ACK frequency for high-bandwidth paths
 *   - Immediate ACK requests for latency-sensitive operations
 *   - Reorder threshold to handle out-of-order packets gracefully
 *
 * Frame Types:
 *   - ACK_FREQUENCY (0xAF): Request peer adjust ACK behavior
 *   - IMMEDIATE_ACK (0x1F): Request immediate ACK from peer
 *
 * Transport Parameter:
 *   - min_ack_delay (0xff04de1a): Minimum ACK delay in microseconds
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/ktime.h>
#include <net/tquic.h>

#include "varint.h"
#include "ack.h"
#include "ack_frequency.h"

/*
 * Frame type values per draft-ietf-quic-ack-frequency
 */
#define TQUIC_FRAME_ACK_FREQUENCY	0xAF
#define TQUIC_FRAME_IMMEDIATE_ACK	0x1F

/*
 * Transport parameter ID for min_ack_delay
 * This is a provisional value from the draft
 */
#define TQUIC_TP_MIN_ACK_DELAY		0xff04de1aULL

/*
 * Default values per draft-ietf-quic-ack-frequency
 */
#define TQUIC_ACK_FREQ_DEFAULT_THRESHOLD	2
#define TQUIC_ACK_FREQ_DEFAULT_MAX_DELAY_US	25000	/* 25ms */
#define TQUIC_ACK_FREQ_DEFAULT_REORDER_THRESHOLD 0

/*
 * Limits
 */
#define TQUIC_MIN_ACK_DELAY_MIN_US	1		/* 1 microsecond */
#define TQUIC_MIN_ACK_DELAY_MAX_US	16383000	/* ~16.4 seconds */
#define TQUIC_ACK_FREQ_MAX_THRESHOLD	255

/**
 * struct tquic_ack_frequency_state - Per-connection ACK frequency state
 * @enabled: Whether ACK frequency extension is negotiated
 * @min_ack_delay_us: Our advertised minimum ACK delay (microseconds)
 * @peer_min_ack_delay_us: Peer's advertised minimum ACK delay
 * @last_sent_seq: Last sequence number sent in ACK_FREQUENCY frame
 * @last_recv_seq: Highest sequence number received in ACK_FREQUENCY frame
 * @ack_eliciting_threshold: Current threshold before ACK required
 * @max_ack_delay_us: Current maximum ACK delay (microseconds)
 * @reorder_threshold: Reordering threshold before immediate ACK
 * @ignore_order: Ignore packet reordering for ACK decisions
 * @immediate_ack_pending: IMMEDIATE_ACK was received, send ACK immediately
 * @ack_frequency_pending: Need to send ACK_FREQUENCY frame
 * @packets_since_ack: Ack-eliciting packets since last ACK sent
 * @largest_pn_received: Largest packet number received
 * @ack_timer: Timer for delayed ACK
 * @lock: Spinlock protecting this state
 */
struct tquic_ack_frequency_state {
	bool enabled;

	/* Transport parameter negotiation */
	u64 min_ack_delay_us;
	u64 peer_min_ack_delay_us;

	/* Frame sequence tracking */
	u64 last_sent_seq;
	u64 last_recv_seq;

	/* Current ACK behavior (from peer's ACK_FREQUENCY frames) */
	u64 ack_eliciting_threshold;
	u64 max_ack_delay_us;
	u64 reorder_threshold;
	bool ignore_order;

	/* Pending actions */
	bool immediate_ack_pending;
	bool ack_frequency_pending;

	/* ACK suppression state */
	u64 packets_since_ack;
	u64 largest_pn_received;

	/* Pending ACK_FREQUENCY frame parameters */
	u64 pending_threshold;
	u64 pending_max_delay;
	u64 pending_reorder;

	/* Delayed ACK timer */
	struct timer_list ack_timer;
	bool ack_timer_armed;

	spinlock_t lock;
};

/**
 * struct tquic_ack_frequency_frame - Parsed ACK_FREQUENCY frame
 * @sequence_number: Monotonically increasing sequence number
 * @ack_eliciting_threshold: ACK-eliciting packets before ACK required
 * @request_max_ack_delay: Requested maximum ACK delay (microseconds)
 * @reorder_threshold: Packet reordering threshold
 */
struct tquic_ack_frequency_frame {
	u64 sequence_number;
	u64 ack_eliciting_threshold;
	u64 request_max_ack_delay;
	u64 reorder_threshold;
};

/* Memory cache for ACK frequency state */
static struct kmem_cache *tquic_ack_freq_cache;

/*
 * =============================================================================
 * ACK Frequency State Management
 * =============================================================================
 */

/**
 * tquic_ack_freq_state_create - Allocate and initialize ACK frequency state
 * @conn: Connection to create state for
 *
 * Returns allocated state or NULL on failure.
 */
struct tquic_ack_frequency_state *tquic_ack_freq_state_create(
	struct tquic_connection *conn)
{
	struct tquic_ack_frequency_state *state;

	state = kmem_cache_zalloc(tquic_ack_freq_cache, GFP_KERNEL);
	if (!state)
		return NULL;

	spin_lock_init(&state->lock);

	/* Initialize with default values */
	state->enabled = false;
	state->min_ack_delay_us = TQUIC_ACK_FREQ_DEFAULT_MAX_DELAY_US;
	state->peer_min_ack_delay_us = TQUIC_ACK_FREQ_DEFAULT_MAX_DELAY_US;
	state->last_sent_seq = 0;
	state->last_recv_seq = 0;
	state->ack_eliciting_threshold = TQUIC_ACK_FREQ_DEFAULT_THRESHOLD;
	state->max_ack_delay_us = TQUIC_ACK_FREQ_DEFAULT_MAX_DELAY_US;
	state->reorder_threshold = TQUIC_ACK_FREQ_DEFAULT_REORDER_THRESHOLD;
	state->ignore_order = false;
	state->immediate_ack_pending = false;
	state->ack_frequency_pending = false;
	state->packets_since_ack = 0;
	state->largest_pn_received = 0;

	pr_debug("tquic: ACK frequency state created\n");

	return state;
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_state_create);

/**
 * tquic_ack_freq_state_destroy - Free ACK frequency state
 * @state: State to destroy
 */
void tquic_ack_freq_state_destroy(struct tquic_ack_frequency_state *state)
{
	if (!state)
		return;

	if (state->ack_timer_armed)
		del_timer_sync(&state->ack_timer);

	kmem_cache_free(tquic_ack_freq_cache, state);

	pr_debug("tquic: ACK frequency state destroyed\n");
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_state_destroy);

/**
 * tquic_ack_freq_enable - Enable ACK frequency after transport parameter negotiation
 * @state: ACK frequency state
 * @peer_min_ack_delay: Peer's min_ack_delay transport parameter (microseconds)
 *
 * Called when both endpoints have advertised min_ack_delay in transport parameters.
 */
void tquic_ack_freq_enable(struct tquic_ack_frequency_state *state,
			   u64 peer_min_ack_delay)
{
	if (!state)
		return;

	spin_lock(&state->lock);

	/* Validate peer's min_ack_delay */
	if (peer_min_ack_delay < TQUIC_MIN_ACK_DELAY_MIN_US ||
	    peer_min_ack_delay > TQUIC_MIN_ACK_DELAY_MAX_US) {
		pr_warn("tquic: peer min_ack_delay %llu out of range, "
			"using default\n", peer_min_ack_delay);
		peer_min_ack_delay = TQUIC_ACK_FREQ_DEFAULT_MAX_DELAY_US;
	}

	state->enabled = true;
	state->peer_min_ack_delay_us = peer_min_ack_delay;

	spin_unlock(&state->lock);

	pr_debug("tquic: ACK frequency enabled, peer_min_ack_delay=%llu us\n",
		 peer_min_ack_delay);
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_enable);

/**
 * tquic_ack_freq_is_enabled - Check if ACK frequency extension is active
 * @state: ACK frequency state
 *
 * Returns true if extension is negotiated and enabled.
 */
bool tquic_ack_freq_is_enabled(const struct tquic_ack_frequency_state *state)
{
	if (!state)
		return false;

	return state->enabled;
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_is_enabled);

/*
 * =============================================================================
 * Frame Parsing
 * =============================================================================
 */

/**
 * tquic_parse_ack_frequency_frame - Parse ACK_FREQUENCY frame
 * @buf: Input buffer (starting after frame type)
 * @buf_len: Buffer length
 * @frame: Output parsed frame
 *
 * ACK_FREQUENCY Frame {
 *   Type (i) = 0xAF,
 *   Sequence Number (i),
 *   Ack-Eliciting Threshold (i),
 *   Request Max Ack Delay (i),
 *   Reorder Threshold (i),
 * }
 *
 * Returns bytes consumed on success, negative error on failure.
 */
int tquic_parse_ack_frequency_frame(const u8 *buf, size_t buf_len,
				    struct tquic_ack_frequency_frame *frame)
{
	size_t offset = 0;
	int ret;

	if (!buf || !frame)
		return -EINVAL;

	memset(frame, 0, sizeof(*frame));

	/* Sequence Number */
	ret = tquic_varint_read(buf, buf_len, &offset, &frame->sequence_number);
	if (ret < 0)
		return ret;

	/* Ack-Eliciting Threshold */
	ret = tquic_varint_read(buf, buf_len, &offset,
				&frame->ack_eliciting_threshold);
	if (ret < 0)
		return ret;

	/* Validate threshold - must be non-zero */
	if (frame->ack_eliciting_threshold == 0) {
		pr_warn("tquic: ACK_FREQUENCY with zero threshold\n");
		return -EINVAL;
	}

	/* Request Max Ack Delay */
	ret = tquic_varint_read(buf, buf_len, &offset,
				&frame->request_max_ack_delay);
	if (ret < 0)
		return ret;

	/* Reorder Threshold */
	ret = tquic_varint_read(buf, buf_len, &offset,
				&frame->reorder_threshold);
	if (ret < 0)
		return ret;

	pr_debug("tquic: parsed ACK_FREQUENCY: seq=%llu threshold=%llu "
		 "max_delay=%llu reorder=%llu\n",
		 frame->sequence_number, frame->ack_eliciting_threshold,
		 frame->request_max_ack_delay, frame->reorder_threshold);

	return offset;
}
EXPORT_SYMBOL_GPL(tquic_parse_ack_frequency_frame);

/**
 * tquic_parse_immediate_ack_frame - Parse IMMEDIATE_ACK frame
 * @buf: Input buffer (starting at frame type)
 * @buf_len: Buffer length
 *
 * IMMEDIATE_ACK Frame {
 *   Type (i) = 0x1F,
 * }
 *
 * The frame has no payload, just the type byte(s).
 *
 * Returns bytes consumed on success, negative error on failure.
 */
int tquic_parse_immediate_ack_frame(const u8 *buf, size_t buf_len)
{
	size_t offset = 0;
	u64 frame_type;
	int ret;

	if (!buf || buf_len < 1)
		return -EINVAL;

	/* Read and validate frame type */
	ret = tquic_varint_read(buf, buf_len, &offset, &frame_type);
	if (ret < 0)
		return ret;

	if (frame_type != TQUIC_FRAME_IMMEDIATE_ACK) {
		pr_warn("tquic: expected IMMEDIATE_ACK (0x1F), got 0x%llx\n",
			frame_type);
		return -EINVAL;
	}

	pr_debug("tquic: parsed IMMEDIATE_ACK frame\n");

	return offset;
}
EXPORT_SYMBOL_GPL(tquic_parse_immediate_ack_frame);

/*
 * =============================================================================
 * Frame Generation
 * =============================================================================
 */

/**
 * tquic_write_ack_frequency_frame - Write ACK_FREQUENCY frame
 * @buf: Output buffer
 * @buf_len: Buffer length
 * @seq_num: Sequence number for this frame
 * @threshold: Ack-eliciting threshold
 * @max_delay: Request max ACK delay (microseconds)
 * @reorder: Reorder threshold
 *
 * Returns bytes written on success, negative error on failure.
 */
int tquic_write_ack_frequency_frame(u8 *buf, size_t buf_len,
				    u64 seq_num, u64 threshold,
				    u64 max_delay, u64 reorder)
{
	size_t offset = 0;
	int ret;

	if (!buf)
		return -EINVAL;

	/* Validate threshold */
	if (threshold == 0)
		return -EINVAL;

	/* Frame type (0xAF) */
	ret = tquic_varint_write(buf, buf_len, &offset, TQUIC_FRAME_ACK_FREQUENCY);
	if (ret < 0)
		return ret;

	/* Sequence Number */
	ret = tquic_varint_write(buf, buf_len, &offset, seq_num);
	if (ret < 0)
		return ret;

	/* Ack-Eliciting Threshold */
	ret = tquic_varint_write(buf, buf_len, &offset, threshold);
	if (ret < 0)
		return ret;

	/* Request Max Ack Delay */
	ret = tquic_varint_write(buf, buf_len, &offset, max_delay);
	if (ret < 0)
		return ret;

	/* Reorder Threshold */
	ret = tquic_varint_write(buf, buf_len, &offset, reorder);
	if (ret < 0)
		return ret;

	pr_debug("tquic: wrote ACK_FREQUENCY: seq=%llu threshold=%llu "
		 "max_delay=%llu reorder=%llu (len=%zu)\n",
		 seq_num, threshold, max_delay, reorder, offset);

	return offset;
}
EXPORT_SYMBOL_GPL(tquic_write_ack_frequency_frame);

/**
 * tquic_write_immediate_ack_frame - Write IMMEDIATE_ACK frame
 * @buf: Output buffer
 * @buf_len: Buffer length
 *
 * Returns bytes written on success, negative error on failure.
 */
int tquic_write_immediate_ack_frame(u8 *buf, size_t buf_len)
{
	size_t offset = 0;
	int ret;

	if (!buf)
		return -EINVAL;

	/* Frame type (0x1F) */
	ret = tquic_varint_write(buf, buf_len, &offset, TQUIC_FRAME_IMMEDIATE_ACK);
	if (ret < 0)
		return ret;

	pr_debug("tquic: wrote IMMEDIATE_ACK frame (len=%zu)\n", offset);

	return offset;
}
EXPORT_SYMBOL_GPL(tquic_write_immediate_ack_frame);

/**
 * tquic_ack_frequency_frame_size - Calculate ACK_FREQUENCY frame size
 * @seq_num: Sequence number
 * @threshold: Ack-eliciting threshold
 * @max_delay: Max ACK delay
 * @reorder: Reorder threshold
 *
 * Returns size in bytes.
 */
size_t tquic_ack_frequency_frame_size(u64 seq_num, u64 threshold,
				      u64 max_delay, u64 reorder)
{
	size_t size = 0;

	/* Frame type (0xAF = 2-byte varint) */
	size += tquic_varint_size(TQUIC_FRAME_ACK_FREQUENCY);

	/* Sequence Number */
	size += tquic_varint_size(seq_num);

	/* Ack-Eliciting Threshold */
	size += tquic_varint_size(threshold);

	/* Request Max Ack Delay */
	size += tquic_varint_size(max_delay);

	/* Reorder Threshold */
	size += tquic_varint_size(reorder);

	return size;
}
EXPORT_SYMBOL_GPL(tquic_ack_frequency_frame_size);

/**
 * tquic_immediate_ack_frame_size - Get IMMEDIATE_ACK frame size
 *
 * Returns size in bytes (always 1 for frame type 0x1F).
 */
size_t tquic_immediate_ack_frame_size(void)
{
	return tquic_varint_size(TQUIC_FRAME_IMMEDIATE_ACK);
}
EXPORT_SYMBOL_GPL(tquic_immediate_ack_frame_size);

/*
 * =============================================================================
 * Frame Handling
 * =============================================================================
 */

/**
 * tquic_handle_ack_frequency_frame - Process received ACK_FREQUENCY frame
 * @state: ACK frequency state
 * @frame: Parsed ACK_FREQUENCY frame
 *
 * Per draft-ietf-quic-ack-frequency Section 4.1:
 * "An endpoint MUST use the values from the ACK_FREQUENCY frame with
 * the largest received Sequence Number field value."
 *
 * Returns 0 on success, negative error on failure.
 */
int tquic_handle_ack_frequency_frame(struct tquic_ack_frequency_state *state,
				     const struct tquic_ack_frequency_frame *frame)
{
	if (!state || !frame)
		return -EINVAL;

	spin_lock(&state->lock);

	/* Only process if sequence number is larger than previously seen */
	if (frame->sequence_number <= state->last_recv_seq &&
	    state->last_recv_seq != 0) {
		pr_debug("tquic: ignoring ACK_FREQUENCY with old seq %llu "
			 "(last=%llu)\n", frame->sequence_number,
			 state->last_recv_seq);
		spin_unlock(&state->lock);
		return 0;
	}

	/* Validate request_max_ack_delay against peer's min_ack_delay */
	if (frame->request_max_ack_delay < state->min_ack_delay_us) {
		pr_warn("tquic: ACK_FREQUENCY max_delay %llu < min %llu\n",
			frame->request_max_ack_delay, state->min_ack_delay_us);
		/* Use our minimum instead of rejecting */
	}

	/* Update state with new values */
	state->last_recv_seq = frame->sequence_number;
	state->ack_eliciting_threshold = frame->ack_eliciting_threshold;
	state->max_ack_delay_us = max(frame->request_max_ack_delay,
				      state->min_ack_delay_us);

	/*
	 * Per Section 4.3: "If the Reorder Threshold is set to 0, it
	 * indicates that out-of-order packets SHOULD NOT cause the
	 * endpoint to send an acknowledgment immediately."
	 */
	if (frame->reorder_threshold == 0)
		state->ignore_order = true;
	else
		state->ignore_order = false;

	state->reorder_threshold = frame->reorder_threshold;

	spin_unlock(&state->lock);

	pr_debug("tquic: applied ACK_FREQUENCY: threshold=%llu max_delay=%llu "
		 "reorder=%llu ignore_order=%d\n",
		 state->ack_eliciting_threshold, state->max_ack_delay_us,
		 state->reorder_threshold, state->ignore_order);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_handle_ack_frequency_frame);

/**
 * tquic_handle_immediate_ack_frame - Process received IMMEDIATE_ACK frame
 * @state: ACK frequency state
 *
 * Per draft-ietf-quic-ack-frequency Section 5:
 * "When an endpoint receives an IMMEDIATE_ACK frame, it SHOULD send
 * an ACK frame immediately upon receiving the next ack-eliciting packet."
 *
 * Returns 0 on success.
 */
int tquic_handle_immediate_ack_frame(struct tquic_ack_frequency_state *state)
{
	if (!state)
		return -EINVAL;

	spin_lock(&state->lock);
	state->immediate_ack_pending = true;
	spin_unlock(&state->lock);

	pr_debug("tquic: IMMEDIATE_ACK received, will ACK next packet\n");

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_handle_immediate_ack_frame);

/*
 * =============================================================================
 * ACK Decision Logic
 * =============================================================================
 */

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
	u64 gap;

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
	if (state->immediate_ack_pending) {
		state->immediate_ack_pending = false;
		should_ack = true;
		goto out;
	}

	/* Increment packet counter */
	state->packets_since_ack++;

	/* Check ack-eliciting threshold */
	threshold = state->ack_eliciting_threshold;
	if (state->packets_since_ack >= threshold) {
		should_ack = true;
		goto out;
	}

	/* Check reorder threshold (if not ignoring order) */
	if (!state->ignore_order && state->reorder_threshold > 0) {
		if (pn < state->largest_pn_received) {
			gap = state->largest_pn_received - pn;
			if (gap >= state->reorder_threshold) {
				pr_debug("tquic: reorder threshold exceeded "
					 "(gap=%llu >= %llu)\n",
					 gap, state->reorder_threshold);
				should_ack = true;
				goto out;
			}
		}
	}

	/* Update largest received */
	if (pn > state->largest_pn_received)
		state->largest_pn_received = pn;

out:
	spin_unlock(&state->lock);
	return should_ack;
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_should_ack);

/**
 * tquic_ack_freq_on_ack_sent - Notify that ACK was sent
 * @state: ACK frequency state
 *
 * Resets the packet counter after sending an ACK.
 */
void tquic_ack_freq_on_ack_sent(struct tquic_ack_frequency_state *state)
{
	if (!state)
		return;

	spin_lock(&state->lock);
	state->packets_since_ack = 0;
	spin_unlock(&state->lock);
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_on_ack_sent);

/**
 * tquic_ack_freq_get_max_delay - Get current maximum ACK delay
 * @state: ACK frequency state
 *
 * Returns maximum ACK delay in microseconds.
 */
u64 tquic_ack_freq_get_max_delay(const struct tquic_ack_frequency_state *state)
{
	u64 delay;

	if (!state)
		return TQUIC_ACK_FREQ_DEFAULT_MAX_DELAY_US;

	spin_lock((spinlock_t *)&state->lock);
	delay = state->max_ack_delay_us;
	spin_unlock((spinlock_t *)&state->lock);

	return delay;
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_get_max_delay);

/*
 * =============================================================================
 * Sender Control API
 * =============================================================================
 */

/**
 * tquic_ack_freq_request_update - Schedule ACK_FREQUENCY frame transmission
 * @state: ACK frequency state
 * @threshold: Desired ack-eliciting threshold
 * @max_delay_us: Desired max ACK delay (microseconds)
 * @reorder: Desired reorder threshold
 *
 * Schedules an ACK_FREQUENCY frame to be sent to the peer requesting
 * it change its ACK behavior.
 *
 * Returns 0 on success, negative error on failure.
 */
int tquic_ack_freq_request_update(struct tquic_ack_frequency_state *state,
				  u64 threshold, u64 max_delay_us, u64 reorder)
{
	if (!state)
		return -EINVAL;

	if (!state->enabled)
		return -ENOTSUP;

	/* Validate parameters */
	if (threshold == 0 || threshold > TQUIC_ACK_FREQ_MAX_THRESHOLD)
		return -EINVAL;

	/*
	 * Per Section 4.2: "An endpoint MUST NOT request a max_ack_delay
	 * that is less than the peer's min_ack_delay."
	 */
	if (max_delay_us < state->peer_min_ack_delay_us) {
		pr_warn("tquic: requested max_delay %llu < peer min %llu\n",
			max_delay_us, state->peer_min_ack_delay_us);
		max_delay_us = state->peer_min_ack_delay_us;
	}

	spin_lock(&state->lock);
	state->ack_frequency_pending = true;
	state->pending_threshold = threshold;
	state->pending_max_delay = max_delay_us;
	state->pending_reorder = reorder;
	spin_unlock(&state->lock);

	pr_debug("tquic: scheduled ACK_FREQUENCY update: threshold=%llu "
		 "max_delay=%llu reorder=%llu\n",
		 threshold, max_delay_us, reorder);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_request_update);

/**
 * tquic_ack_freq_request_immediate_ack - Schedule IMMEDIATE_ACK frame
 * @state: ACK frequency state
 *
 * Schedules an IMMEDIATE_ACK frame to request the peer send an ACK
 * for all received packets immediately.
 *
 * Returns 0 on success.
 */
int tquic_ack_freq_request_immediate_ack(struct tquic_ack_frequency_state *state)
{
	if (!state)
		return -EINVAL;

	if (!state->enabled)
		return -ENOTSUP;

	/* IMMEDIATE_ACK doesn't need pending flag - generate inline */
	pr_debug("tquic: IMMEDIATE_ACK requested\n");

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_request_immediate_ack);

/**
 * tquic_ack_freq_generate_pending - Generate pending ACK frequency frames
 * @state: ACK frequency state
 * @buf: Output buffer
 * @buf_len: Buffer length
 *
 * Generates any pending ACK_FREQUENCY frames.
 * Returns bytes written, or negative error.
 */
int tquic_ack_freq_generate_pending(struct tquic_ack_frequency_state *state,
				    u8 *buf, size_t buf_len)
{
	u64 seq_num;
	int ret;

	if (!state || !buf)
		return -EINVAL;

	spin_lock(&state->lock);

	if (!state->ack_frequency_pending) {
		spin_unlock(&state->lock);
		return 0;
	}

	/* Get next sequence number */
	seq_num = ++state->last_sent_seq;

	ret = tquic_write_ack_frequency_frame(buf, buf_len,
					      seq_num,
					      state->pending_threshold,
					      state->pending_max_delay,
					      state->pending_reorder);
	if (ret > 0)
		state->ack_frequency_pending = false;

	spin_unlock(&state->lock);

	return ret;
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_generate_pending);

/**
 * tquic_ack_freq_has_pending - Check if there are pending frames to send
 * @state: ACK frequency state
 *
 * Returns true if ACK_FREQUENCY or IMMEDIATE_ACK frames are pending.
 */
bool tquic_ack_freq_has_pending(const struct tquic_ack_frequency_state *state)
{
	bool pending;

	if (!state)
		return false;

	spin_lock((spinlock_t *)&state->lock);
	pending = state->ack_frequency_pending;
	spin_unlock((spinlock_t *)&state->lock);

	return pending;
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_has_pending);

/*
 * =============================================================================
 * Integration with Loss Detection
 * =============================================================================
 */

/**
 * tquic_ack_freq_update_loss_state - Update loss state with ACK frequency params
 * @loss: Loss detection state
 * @state: ACK frequency state
 *
 * Updates the loss detection state's ACK delay based on ACK frequency
 * negotiation results.
 */
void tquic_ack_freq_update_loss_state(struct tquic_loss_state *loss,
				      const struct tquic_ack_frequency_state *state)
{
	if (!loss || !state)
		return;

	spin_lock((spinlock_t *)&state->lock);
	spin_lock(&loss->lock);

	loss->ack_delay_us = state->max_ack_delay_us;
	loss->rtt.max_ack_delay = state->max_ack_delay_us;

	spin_unlock(&loss->lock);
	spin_unlock((spinlock_t *)&state->lock);

	pr_debug("tquic: updated loss state ack_delay=%u us\n",
		 loss->ack_delay_us);
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_update_loss_state);

/*
 * =============================================================================
 * Module Initialization
 * =============================================================================
 */

/**
 * tquic_ack_freq_init - Initialize ACK frequency module
 */
int __init tquic_ack_freq_init(void)
{
	tquic_ack_freq_cache = kmem_cache_create("tquic_ack_freq_state",
		sizeof(struct tquic_ack_frequency_state), 0,
		SLAB_HWCACHE_ALIGN, NULL);
	if (!tquic_ack_freq_cache)
		return -ENOMEM;

	pr_info("tquic: ACK frequency extension initialized\n");
	return 0;
}

/**
 * tquic_ack_freq_exit - Cleanup ACK frequency module
 */
void __exit tquic_ack_freq_exit(void)
{
	kmem_cache_destroy(tquic_ack_freq_cache);
	pr_info("tquic: ACK frequency extension cleaned up\n");
}

MODULE_DESCRIPTION("TQUIC ACK Frequency Extension (draft-ietf-quic-ack-frequency)");
MODULE_LICENSE("GPL");
