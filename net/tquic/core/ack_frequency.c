// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: ACK Frequency Negotiation (RFC 9002 Appendix A.7)
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Complete implementation of QUIC ACK Frequency extension including:
 *   - Transport parameter: min_ack_delay (0xff04de1a)
 *   - ACK_FREQUENCY frame (0xaf) encoding/decoding
 *   - IMMEDIATE_ACK frame (0x1f) encoding/decoding
 *   - Full negotiation state machine
 *   - Dynamic frequency adjustment based on:
 *     - Congestion state (CC integration)
 *     - Packet reordering
 *     - RTT characteristics
 *     - Bandwidth estimates
 *     - Application hints
 *
 * Per RFC 9002 Appendix A.7: "Receivers determine how frequently to send
 * acknowledgments based on the ack-eliciting threshold and the reorder
 * threshold."
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/ktime.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <net/tquic.h>

#include "varint.h"
#include "ack.h"
#include "ack_frequency.h"
#include "../tquic_compat.h"

/*
 * =============================================================================
 * Module Configuration
 * =============================================================================
 */

/* Memory cache for ACK frequency state */
static struct kmem_cache *tquic_ack_freq_cache;

/* Workqueue for deferred adjustments */
static struct workqueue_struct *tquic_ack_freq_wq;

/*
 * Dynamic adjustment thresholds
 */
#define TQUIC_ACK_FREQ_HIGH_BW_THRESHOLD	10000000ULL  /* 10 MB/s */
#define TQUIC_ACK_FREQ_LOW_RTT_US		10000        /* 10ms */
#define TQUIC_ACK_FREQ_HIGH_RTT_US		200000       /* 200ms */

/*
 * Congestion state adjustment parameters
 */
#define TQUIC_ACK_FREQ_CONGESTION_THRESHOLD	1      /* ACK every packet */
#define TQUIC_ACK_FREQ_CONGESTION_MAX_DELAY	5000   /* 5ms during congestion */
#define TQUIC_ACK_FREQ_HIGH_BW_PACKETS		10     /* ACK every 10 packets */
#define TQUIC_ACK_FREQ_HIGH_BW_MAX_DELAY	50000  /* 50ms for high bandwidth */

/*
 * =============================================================================
 * Timer Callback
 * =============================================================================
 */

static void tquic_ack_freq_timer_callback(struct timer_list *t)
{
	struct tquic_ack_frequency_state *state =
		from_timer(state, t, ack_timer);

	spin_lock(&state->lock);
	state->ack_timer_armed = false;
	/*
	 * Timer expired - the connection should send an ACK now.
	 * Signal this by setting immediate_ack_pending.
	 */
	state->immediate_ack_pending = true;
	spin_unlock(&state->lock);

	pr_debug("tquic: ACK delay timer expired, immediate ACK needed\n");
}

/*
 * =============================================================================
 * Work Queue Callback for Dynamic Adjustment
 * =============================================================================
 */

static void tquic_ack_freq_adjustment_work(struct work_struct *work)
{
	struct tquic_ack_frequency_state *state =
		container_of(work, struct tquic_ack_frequency_state,
			     adjustment_work);
	u64 new_threshold;
	u64 new_max_delay;
	u64 new_reorder;
	bool should_update = false;

	spin_lock(&state->lock);

	if (!state->enabled ||
	    state->nego_state != TQUIC_ACK_FREQ_STATE_ACTIVE) {
		spin_unlock(&state->lock);
		return;
	}

	/*
	 * Determine new parameters based on current state
	 */
	if (state->in_congestion) {
		/* During congestion: more frequent ACKs */
		new_threshold = state->dynamic_params.congestion_threshold;
		new_max_delay = state->dynamic_params.congestion_max_delay_us;
		new_reorder = 1;  /* Immediate ACK on any reorder */
	} else if (state->latency_sensitive) {
		/* Latency-sensitive: lower thresholds */
		new_threshold = 2;
		new_max_delay = state->dynamic_params.normal_max_delay_us / 2;
		new_reorder = 1;
	} else if (state->throughput_focused) {
		/* Throughput-focused: higher thresholds */
		new_threshold = state->dynamic_params.high_bw_threshold;
		new_max_delay = state->dynamic_params.high_bw_max_delay_us;
		new_reorder = state->dynamic_params.reorder_threshold;
	} else {
		/* Normal operation */
		new_threshold = state->dynamic_params.normal_threshold;
		new_max_delay = state->dynamic_params.normal_max_delay_us;
		new_reorder = state->dynamic_params.reorder_threshold;
	}

	/* Check if parameters changed significantly */
	if (new_threshold != state->pending_frame.ack_eliciting_threshold ||
	    new_max_delay != state->pending_frame.request_max_ack_delay ||
	    new_reorder != state->pending_frame.reorder_threshold) {
		/* Ensure max_delay respects peer's min_ack_delay */
		if (new_max_delay < state->peer_min_ack_delay_us)
			new_max_delay = state->peer_min_ack_delay_us;

		state->pending_frame.sequence_number = ++state->last_sent_seq;
		state->pending_frame.ack_eliciting_threshold = new_threshold;
		state->pending_frame.request_max_ack_delay = new_max_delay;
		state->pending_frame.reorder_threshold = new_reorder;
		state->ack_frequency_pending = true;
		state->adjustments_made++;
		should_update = true;
	}

	spin_unlock(&state->lock);

	if (should_update)
		pr_debug("tquic: scheduled ACK frequency adjustment: "
			 "threshold=%llu max_delay=%llu reorder=%llu\n",
			 new_threshold, new_max_delay, new_reorder);
}

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

	/* Initialize state machine */
	state->nego_state = TQUIC_ACK_FREQ_STATE_DISABLED;
	state->enabled = false;

	/* Initialize transport parameter values */
	state->min_ack_delay_us = TQUIC_ACK_FREQ_DEFAULT_MAX_DELAY_US;
	state->peer_min_ack_delay_us = TQUIC_ACK_FREQ_DEFAULT_MAX_DELAY_US;
	state->ack_delay_exponent = 3;  /* Default per RFC 9000 */
	state->max_ack_delay_tp_us = TQUIC_ACK_FREQ_DEFAULT_MAX_DELAY_US;

	/* Initialize frame sequence tracking */
	state->last_sent_seq = 0;
	state->last_recv_seq = 0;

	/* Initialize current ACK behavior with defaults */
	state->current_threshold = TQUIC_ACK_FREQ_DEFAULT_THRESHOLD;
	state->current_max_delay_us = TQUIC_ACK_FREQ_DEFAULT_MAX_DELAY_US;
	state->current_reorder_threshold = TQUIC_ACK_FREQ_DEFAULT_REORDER_THRESHOLD;
	state->ignore_order = false;

	/* Initialize pending actions */
	state->immediate_ack_pending = false;
	state->ack_frequency_pending = false;
	state->immediate_ack_request = false;
	memset(&state->pending_frame, 0, sizeof(state->pending_frame));

	/* Initialize ACK suppression state */
	state->packets_since_ack = 0;
	state->largest_pn_received = 0;
	state->last_ack_sent_time = ktime_get();

	/* Initialize dynamic adjustment parameters */
	state->dynamic_params.congestion_threshold = TQUIC_ACK_FREQ_CONGESTION_THRESHOLD;
	state->dynamic_params.congestion_max_delay_us = TQUIC_ACK_FREQ_CONGESTION_MAX_DELAY;
	state->dynamic_params.normal_threshold = TQUIC_ACK_FREQ_DEFAULT_THRESHOLD;
	state->dynamic_params.normal_max_delay_us = TQUIC_ACK_FREQ_DEFAULT_MAX_DELAY_US;
	state->dynamic_params.high_bw_threshold = TQUIC_ACK_FREQ_HIGH_BW_PACKETS;
	state->dynamic_params.high_bw_max_delay_us = TQUIC_ACK_FREQ_HIGH_BW_MAX_DELAY;
	state->dynamic_params.low_rtt_threshold_us = TQUIC_ACK_FREQ_LOW_RTT_US;
	state->dynamic_params.high_rtt_threshold_us = TQUIC_ACK_FREQ_HIGH_RTT_US;
	state->dynamic_params.reorder_threshold = TQUIC_ACK_FREQ_DEFAULT_REORDER_THRESHOLD;

	/* Initialize dynamic state */
	state->last_adjustment_reason = TQUIC_ACK_FREQ_REASON_NONE;
	state->in_congestion = false;
	state->reordering_detected = false;
	state->latency_sensitive = false;
	state->throughput_focused = false;

	/* Initialize timer */
	timer_setup(&state->ack_timer, tquic_ack_freq_timer_callback, 0);
	state->ack_timer_armed = false;

	/* Initialize work queue */
	INIT_WORK(&state->adjustment_work, tquic_ack_freq_adjustment_work);

	/* Initialize statistics */
	state->frames_sent = 0;
	state->frames_received = 0;
	state->immediate_ack_sent = 0;
	state->immediate_ack_received = 0;
	state->adjustments_made = 0;

	/* Store back-pointer */
	state->conn = conn;

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

	/* Cancel pending timer */
	if (state->ack_timer_armed)
		del_timer_sync(&state->ack_timer);

	/* Cancel pending work */
	cancel_work_sync(&state->adjustment_work);

	kmem_cache_free(tquic_ack_freq_cache, state);

	pr_debug("tquic: ACK frequency state destroyed\n");
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_state_destroy);

/**
 * tquic_ack_freq_enable - Enable ACK frequency after transport parameter negotiation
 * @state: ACK frequency state
 * @peer_min_ack_delay: Peer's min_ack_delay transport parameter (microseconds)
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
	state->nego_state = TQUIC_ACK_FREQ_STATE_NEGOTIATED;
	state->peer_min_ack_delay_us = peer_min_ack_delay;

	/* Initialize pending frame with reasonable defaults */
	state->pending_frame.ack_eliciting_threshold = state->current_threshold;
	state->pending_frame.request_max_ack_delay = max(state->current_max_delay_us,
							 peer_min_ack_delay);
	state->pending_frame.reorder_threshold = state->current_reorder_threshold;

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

/**
 * tquic_ack_freq_get_nego_state - Get current negotiation state
 * @state: ACK frequency state
 *
 * Returns current state machine state.
 */
enum tquic_ack_freq_nego_state tquic_ack_freq_get_nego_state(
	const struct tquic_ack_frequency_state *state)
{
	if (!state)
		return TQUIC_ACK_FREQ_STATE_DISABLED;

	return state->nego_state;
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_get_nego_state);

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
 *   Type (i) = 0xaf,
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

	/* Validate threshold - must be non-zero per spec */
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

	return (int)offset;
}
EXPORT_SYMBOL_GPL(tquic_parse_ack_frequency_frame);

/**
 * tquic_parse_immediate_ack_frame - Parse IMMEDIATE_ACK frame
 * @buf: Input buffer (starting at frame type)
 * @buf_len: Buffer length
 *
 * IMMEDIATE_ACK Frame {
 *   Type (i) = 0x1f,
 * }
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
		pr_warn("tquic: expected IMMEDIATE_ACK (0x1f), got 0x%llx\n",
			frame_type);
		return -EINVAL;
	}

	pr_debug("tquic: parsed IMMEDIATE_ACK frame\n");

	return (int)offset;
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

	/* Frame type (0xaf) */
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

	return (int)offset;
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

	/* Frame type (0x1f) */
	ret = tquic_varint_write(buf, buf_len, &offset, TQUIC_FRAME_IMMEDIATE_ACK);
	if (ret < 0)
		return ret;

	pr_debug("tquic: wrote IMMEDIATE_ACK frame (len=%zu)\n", offset);

	return (int)offset;
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

	/* Frame type (0xaf = 2-byte varint) */
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
 * Returns size in bytes (1 for frame type 0x1f).
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

	/* Validate request_max_ack_delay against our min_ack_delay */
	if (frame->request_max_ack_delay < state->min_ack_delay_us) {
		pr_warn("tquic: ACK_FREQUENCY max_delay %llu < min %llu, "
			"using min\n", frame->request_max_ack_delay,
			state->min_ack_delay_us);
		/* Continue but use our minimum instead */
	}

	/* Update state with new values, clamped to safe bounds */
	state->last_recv_seq = frame->sequence_number;
	state->current_threshold = min_t(u64, frame->ack_eliciting_threshold,
					 TQUIC_ACK_FREQ_MAX_THRESHOLD);
	state->current_max_delay_us = min_t(u64,
		max(frame->request_max_ack_delay, state->min_ack_delay_us),
		TQUIC_MIN_ACK_DELAY_MAX_US);

	/*
	 * Per Section 4.3: "If the Reorder Threshold is set to 0, it
	 * indicates that out-of-order packets SHOULD NOT cause the
	 * endpoint to send an acknowledgment immediately."
	 */
	if (frame->reorder_threshold == TQUIC_ACK_FREQ_IGNORE_ORDER_SENTINEL) {
		state->ignore_order = true;
		state->current_reorder_threshold = 0;
	} else {
		state->ignore_order = false;
		state->current_reorder_threshold = min_t(u64,
			frame->reorder_threshold,
			TQUIC_ACK_FREQ_MAX_REORDER);
	}

	/* Transition to active state on first frame */
	if (state->nego_state == TQUIC_ACK_FREQ_STATE_NEGOTIATED)
		state->nego_state = TQUIC_ACK_FREQ_STATE_ACTIVE;

	state->frames_received++;

	spin_unlock(&state->lock);

	pr_debug("tquic: applied ACK_FREQUENCY: threshold=%llu max_delay=%llu "
		 "reorder=%llu ignore_order=%d\n",
		 state->current_threshold, state->current_max_delay_us,
		 state->current_reorder_threshold, state->ignore_order);

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
	state->immediate_ack_received++;
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
				pr_debug("tquic: reorder threshold exceeded "
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
	state->last_ack_sent_time = ktime_get();

	/* Cancel any pending ACK timer */
	if (state->ack_timer_armed) {
		del_timer(&state->ack_timer);
		state->ack_timer_armed = false;
	}
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
	if (state->in_congestion)
		delay = state->dynamic_params.congestion_max_delay_us;
	else
		delay = state->current_max_delay_us;
	spin_unlock((spinlock_t *)&state->lock);

	return delay;
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_get_max_delay);

/**
 * tquic_ack_freq_get_delay_timer - Get time until ACK should be sent
 * @state: ACK frequency state
 *
 * Returns delay in nanoseconds until ACK timer should fire.
 */
u64 tquic_ack_freq_get_delay_timer(const struct tquic_ack_frequency_state *state)
{
	u64 max_delay_ns;
	ktime_t now;
	ktime_t elapsed;
	s64 remaining_ns;

	if (!state)
		return TQUIC_ACK_FREQ_DEFAULT_MAX_DELAY_US * 1000ULL;

	spin_lock((spinlock_t *)&state->lock);
	max_delay_ns = state->current_max_delay_us * 1000ULL;
	now = ktime_get();
	elapsed = ktime_sub(now, state->last_ack_sent_time);
	remaining_ns = max_delay_ns - ktime_to_ns(elapsed);
	spin_unlock((spinlock_t *)&state->lock);

	if (remaining_ns < 0)
		return 0;

	return (u64)remaining_ns;
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_get_delay_timer);

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
 * Returns 0 on success, negative error on failure.
 */
int tquic_ack_freq_request_update(struct tquic_ack_frequency_state *state,
				  u64 threshold, u64 max_delay_us, u64 reorder)
{
	if (!state)
		return -EINVAL;

	if (!state->enabled)
		return -EOPNOTSUPP;

	/* Validate parameters */
	if (threshold == 0 || threshold > TQUIC_ACK_FREQ_MAX_THRESHOLD)
		return -EINVAL;

	spin_lock(&state->lock);

	/*
	 * Per Section 4.2: "An endpoint MUST NOT request a max_ack_delay
	 * that is less than the peer's min_ack_delay."
	 */
	if (max_delay_us < state->peer_min_ack_delay_us) {
		pr_debug("tquic: adjusting max_delay %llu to peer min %llu\n",
			 max_delay_us, state->peer_min_ack_delay_us);
		max_delay_us = state->peer_min_ack_delay_us;
	}

	/* Set up pending frame */
	state->pending_frame.sequence_number = ++state->last_sent_seq;
	state->pending_frame.ack_eliciting_threshold = threshold;
	state->pending_frame.request_max_ack_delay = max_delay_us;
	state->pending_frame.reorder_threshold = reorder;
	state->ack_frequency_pending = true;

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
 * Returns 0 on success.
 */
int tquic_ack_freq_request_immediate_ack(struct tquic_ack_frequency_state *state)
{
	if (!state)
		return -EINVAL;

	if (!state->enabled)
		return -EOPNOTSUPP;

	spin_lock(&state->lock);
	state->immediate_ack_request = true;
	spin_unlock(&state->lock);

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
 * Returns bytes written, or negative error.
 */
int tquic_ack_freq_generate_pending(struct tquic_ack_frequency_state *state,
				    u8 *buf, size_t buf_len)
{
	u8 *p = buf;
	int ret;

	if (!state || !buf)
		return -EINVAL;

	spin_lock(&state->lock);

	/* Generate IMMEDIATE_ACK if requested */
	if (state->immediate_ack_request) {
		ret = tquic_write_immediate_ack_frame(p, buf_len - (p - buf));
		if (ret > 0) {
			p += ret;
			state->immediate_ack_request = false;
			state->immediate_ack_sent++;
		}
	}

	/* Generate ACK_FREQUENCY if pending */
	if (state->ack_frequency_pending) {
		ret = tquic_write_ack_frequency_frame(
			p, buf_len - (p - buf),
			state->pending_frame.sequence_number,
			state->pending_frame.ack_eliciting_threshold,
			state->pending_frame.request_max_ack_delay,
			state->pending_frame.reorder_threshold);
		if (ret > 0) {
			p += ret;
			state->ack_frequency_pending = false;
			state->frames_sent++;

			/* Transition to active state */
			if (state->nego_state == TQUIC_ACK_FREQ_STATE_NEGOTIATED)
				state->nego_state = TQUIC_ACK_FREQ_STATE_ACTIVE;
		}
	}

	spin_unlock(&state->lock);

	return (int)(p - buf);
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
	pending = state->ack_frequency_pending || state->immediate_ack_request;
	spin_unlock((spinlock_t *)&state->lock);

	return pending;
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_has_pending);

/*
 * =============================================================================
 * Dynamic Adjustment API (Congestion Control Integration)
 * =============================================================================
 */

/**
 * tquic_ack_freq_on_congestion_event - Notify of congestion event
 * @state: ACK frequency state
 * @in_recovery: Whether CC is in recovery state
 */
void tquic_ack_freq_on_congestion_event(struct tquic_ack_frequency_state *state,
					bool in_recovery)
{
	if (!state)
		return;

	spin_lock(&state->lock);

	if (state->in_congestion != in_recovery) {
		state->in_congestion = in_recovery;
		state->last_adjustment_reason = TQUIC_ACK_FREQ_REASON_CONGESTION;

		/*
		 * During congestion, request more frequent ACKs from peer
		 * to improve congestion control feedback loop.
		 */
		if (state->enabled && in_recovery) {
			state->pending_frame.ack_eliciting_threshold =
				state->dynamic_params.congestion_threshold;
			state->pending_frame.request_max_ack_delay =
				max(state->dynamic_params.congestion_max_delay_us,
				    state->peer_min_ack_delay_us);
			state->pending_frame.reorder_threshold = 1;
			state->pending_frame.sequence_number = ++state->last_sent_seq;
			state->ack_frequency_pending = true;
			state->adjustments_made++;
		}
	}

	spin_unlock(&state->lock);

	if (in_recovery)
		pr_debug("tquic: entered congestion recovery, adjusting ACK freq\n");
	else
		pr_debug("tquic: exited congestion recovery\n");
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_on_congestion_event);

/**
 * tquic_ack_freq_on_rtt_update - Notify of RTT update
 * @state: ACK frequency state
 * @rtt_us: Smoothed RTT in microseconds
 * @rtt_var_us: RTT variance in microseconds
 */
void tquic_ack_freq_on_rtt_update(struct tquic_ack_frequency_state *state,
				  u64 rtt_us, u64 rtt_var_us)
{
	u64 new_max_delay;

	if (!state || !state->enabled)
		return;

	spin_lock(&state->lock);

	/*
	 * Adjust max ACK delay based on RTT:
	 * - Low RTT: use lower delays for better responsiveness
	 * - High RTT: use higher delays to reduce overhead
	 */
	if (rtt_us < state->dynamic_params.low_rtt_threshold_us) {
		/* Low RTT path - reduce ACK delay */
		new_max_delay = rtt_us / 4;  /* 1/4 RTT */
		state->last_adjustment_reason = TQUIC_ACK_FREQ_REASON_LOW_RTT;
	} else if (rtt_us > state->dynamic_params.high_rtt_threshold_us) {
		/* High RTT path - increase ACK delay */
		new_max_delay = rtt_us / 2;  /* 1/2 RTT */
		state->last_adjustment_reason = TQUIC_ACK_FREQ_REASON_HIGH_RTT;
	} else {
		/* Normal RTT */
		new_max_delay = state->dynamic_params.normal_max_delay_us;
		state->last_adjustment_reason = TQUIC_ACK_FREQ_REASON_NONE;
	}

	/* Clamp to valid range */
	if (new_max_delay < state->peer_min_ack_delay_us)
		new_max_delay = state->peer_min_ack_delay_us;
	if (new_max_delay > TQUIC_MIN_ACK_DELAY_MAX_US)
		new_max_delay = TQUIC_MIN_ACK_DELAY_MAX_US;

	/* Only update if significantly different (>20% change) */
	if (state->dynamic_params.normal_max_delay_us > 0) {
		s64 diff = (s64)new_max_delay -
			   (s64)state->dynamic_params.normal_max_delay_us;
		if (diff < 0)
			diff = -diff;
		if ((u64)diff > state->dynamic_params.normal_max_delay_us / 5) {
			state->dynamic_params.normal_max_delay_us = new_max_delay;
			/* Queue async adjustment work */
			if (tquic_ack_freq_wq)
				queue_work(tquic_ack_freq_wq,
					   &state->adjustment_work);
		}
	}

	spin_unlock(&state->lock);
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_on_rtt_update);

/**
 * tquic_ack_freq_on_bandwidth_update - Notify of bandwidth estimate update
 * @state: ACK frequency state
 * @bandwidth_bps: Estimated bandwidth in bytes per second
 */
void tquic_ack_freq_on_bandwidth_update(struct tquic_ack_frequency_state *state,
					u64 bandwidth_bps)
{
	if (!state || !state->enabled)
		return;

	spin_lock(&state->lock);

	/*
	 * High bandwidth paths can tolerate less frequent ACKs.
	 * This reduces ACK overhead and improves throughput.
	 */
	if (bandwidth_bps > TQUIC_ACK_FREQ_HIGH_BW_THRESHOLD) {
		state->dynamic_params.normal_threshold =
			state->dynamic_params.high_bw_threshold;
		state->dynamic_params.normal_max_delay_us =
			state->dynamic_params.high_bw_max_delay_us;
		state->last_adjustment_reason = TQUIC_ACK_FREQ_REASON_BANDWIDTH;
		if (tquic_ack_freq_wq)
			queue_work(tquic_ack_freq_wq, &state->adjustment_work);
	} else {
		/* Reset to normal thresholds */
		state->dynamic_params.normal_threshold =
			TQUIC_ACK_FREQ_DEFAULT_THRESHOLD;
		state->dynamic_params.normal_max_delay_us =
			TQUIC_ACK_FREQ_DEFAULT_MAX_DELAY_US;
	}

	spin_unlock(&state->lock);
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_on_bandwidth_update);

/**
 * tquic_ack_freq_on_reordering - Notify of packet reordering detection
 * @state: ACK frequency state
 * @gap: Reorder gap in packets
 */
void tquic_ack_freq_on_reordering(struct tquic_ack_frequency_state *state,
				  u64 gap)
{
	if (!state || !state->enabled)
		return;

	spin_lock(&state->lock);

	state->reordering_detected = true;
	state->last_adjustment_reason = TQUIC_ACK_FREQ_REASON_REORDERING;

	/*
	 * If we observe reordering, increase the reorder threshold
	 * to avoid excessive ACKs due to reordering.
	 */
	if (gap > state->dynamic_params.reorder_threshold) {
		state->dynamic_params.reorder_threshold = min(gap + 1,
			(u64)TQUIC_ACK_FREQ_MAX_REORDER);
		state->adjustments_made++;
		if (tquic_ack_freq_wq)
			queue_work(tquic_ack_freq_wq, &state->adjustment_work);

		pr_debug("tquic: increased reorder threshold to %llu due to gap %llu\n",
			 state->dynamic_params.reorder_threshold, gap);
	}

	spin_unlock(&state->lock);
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_on_reordering);

/**
 * tquic_ack_freq_on_ecn - Notify of ECN congestion signal
 * @state: ACK frequency state
 */
void tquic_ack_freq_on_ecn(struct tquic_ack_frequency_state *state)
{
	if (!state || !state->enabled)
		return;

	spin_lock(&state->lock);

	state->last_adjustment_reason = TQUIC_ACK_FREQ_REASON_ECN;

	/*
	 * ECN signals congestion - increase ACK frequency
	 * similar to packet loss.
	 */
	if (!state->in_congestion) {
		state->in_congestion = true;
		state->adjustments_made++;
		if (tquic_ack_freq_wq)
			queue_work(tquic_ack_freq_wq, &state->adjustment_work);
	}

	spin_unlock(&state->lock);

	pr_debug("tquic: ECN signal received, increasing ACK frequency\n");
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_on_ecn);

/**
 * tquic_ack_freq_set_application_hint - Set application-level hint
 * @state: ACK frequency state
 * @latency_sensitive: True if application is latency-sensitive
 * @throughput_focused: True if application prioritizes throughput
 */
void tquic_ack_freq_set_application_hint(struct tquic_ack_frequency_state *state,
					 bool latency_sensitive,
					 bool throughput_focused)
{
	if (!state)
		return;

	spin_lock(&state->lock);

	state->latency_sensitive = latency_sensitive;
	state->throughput_focused = throughput_focused;
	state->last_adjustment_reason = TQUIC_ACK_FREQ_REASON_APPLICATION;

	if (state->enabled) {
		state->adjustments_made++;
		if (tquic_ack_freq_wq)
			queue_work(tquic_ack_freq_wq, &state->adjustment_work);
	}

	spin_unlock(&state->lock);

	pr_debug("tquic: application hint set: latency_sensitive=%d "
		 "throughput_focused=%d\n",
		 latency_sensitive, throughput_focused);
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_set_application_hint);

/*
 * =============================================================================
 * Integration with Loss Detection
 * =============================================================================
 */

/**
 * tquic_ack_freq_update_loss_state - Update loss state with ACK frequency params
 * @loss: Loss detection state
 * @state: ACK frequency state
 */
void tquic_ack_freq_update_loss_state(struct tquic_loss_state *loss,
				      const struct tquic_ack_frequency_state *state)
{
	u64 max_delay;

	if (!loss || !state)
		return;

	/*
	 * Read ACK frequency state first, then update loss state.
	 * Avoids nested locking (state->lock then loss->lock) which
	 * could deadlock with tquic_loss_state_set_ack_freq() that
	 * acquires loss->lock then calls into ACK freq under state->lock.
	 */
	spin_lock((spinlock_t *)&state->lock);
	max_delay = state->current_max_delay_us;
	spin_unlock((spinlock_t *)&state->lock);

	spin_lock(&loss->lock);
	loss->ack_delay_us = (u32)min_t(u64, max_delay, U32_MAX);
	loss->rtt.max_ack_delay = max_delay;
	spin_unlock(&loss->lock);

	pr_debug("tquic: updated loss state ack_delay=%u us\n",
		 loss->ack_delay_us);
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_update_loss_state);

/*
 * =============================================================================
 * Transport Parameter Support
 * =============================================================================
 */

/**
 * tquic_ack_freq_encode_tp - Encode min_ack_delay transport parameter
 * @min_ack_delay_us: Minimum ACK delay in microseconds
 * @buf: Output buffer
 * @buf_len: Buffer length
 *
 * Returns bytes written on success, negative error on failure.
 */
int tquic_ack_freq_encode_tp(u64 min_ack_delay_us, u8 *buf, size_t buf_len)
{
	size_t offset = 0;
	int ret;
	size_t value_len;

	if (!buf)
		return -EINVAL;

	/* Validate range */
	if (min_ack_delay_us < TQUIC_MIN_ACK_DELAY_MIN_US ||
	    min_ack_delay_us > TQUIC_MIN_ACK_DELAY_MAX_US)
		return -EINVAL;

	value_len = tquic_varint_size(min_ack_delay_us);

	/* Parameter ID */
	ret = tquic_varint_write(buf, buf_len, &offset, TQUIC_TP_MIN_ACK_DELAY);
	if (ret < 0)
		return ret;

	/* Length */
	ret = tquic_varint_write(buf, buf_len, &offset, value_len);
	if (ret < 0)
		return ret;

	/* Value */
	ret = tquic_varint_write(buf, buf_len, &offset, min_ack_delay_us);
	if (ret < 0)
		return ret;

	return (int)offset;
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_encode_tp);

/**
 * tquic_ack_freq_decode_tp - Decode min_ack_delay transport parameter
 * @buf: Input buffer (parameter value only)
 * @buf_len: Value length
 * @min_ack_delay_us: Output minimum ACK delay
 *
 * Returns 0 on success, negative error on failure.
 */
int tquic_ack_freq_decode_tp(const u8 *buf, size_t buf_len,
			     u64 *min_ack_delay_us)
{
	size_t offset = 0;
	int ret;

	if (!buf || !min_ack_delay_us)
		return -EINVAL;

	ret = tquic_varint_read(buf, buf_len, &offset, min_ack_delay_us);
	if (ret < 0)
		return ret;

	/* Validate range */
	if (*min_ack_delay_us < TQUIC_MIN_ACK_DELAY_MIN_US ||
	    *min_ack_delay_us > TQUIC_MIN_ACK_DELAY_MAX_US) {
		pr_warn("tquic: min_ack_delay %llu out of range\n",
			*min_ack_delay_us);
		return -ERANGE;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_decode_tp);

/**
 * tquic_ack_freq_tp_size - Get size needed for min_ack_delay transport param
 * @min_ack_delay_us: Minimum ACK delay value
 *
 * Returns size in bytes.
 */
size_t tquic_ack_freq_tp_size(u64 min_ack_delay_us)
{
	size_t size = 0;

	/* Parameter ID */
	size += tquic_varint_size(TQUIC_TP_MIN_ACK_DELAY);

	/* Length field */
	size += tquic_varint_size(tquic_varint_size(min_ack_delay_us));

	/* Value */
	size += tquic_varint_size(min_ack_delay_us);

	return size;
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_tp_size);

/*
 * =============================================================================
 * Statistics
 * =============================================================================
 */

/**
 * tquic_ack_freq_get_stats - Get ACK frequency statistics
 * @state: ACK frequency state
 * @stats: Output statistics structure
 */
void tquic_ack_freq_get_stats(const struct tquic_ack_frequency_state *state,
			      struct tquic_ack_freq_stats *stats)
{
	if (!state || !stats) {
		if (stats)
			memset(stats, 0, sizeof(*stats));
		return;
	}

	spin_lock((spinlock_t *)&state->lock);
	stats->frames_sent = state->frames_sent;
	stats->frames_received = state->frames_received;
	stats->immediate_ack_sent = state->immediate_ack_sent;
	stats->immediate_ack_received = state->immediate_ack_received;
	stats->adjustments_made = state->adjustments_made;
	stats->last_reason = state->last_adjustment_reason;
	spin_unlock((spinlock_t *)&state->lock);
}
EXPORT_SYMBOL_GPL(tquic_ack_freq_get_stats);

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
		SLAB_HWCACHE_ALIGN | SLAB_PANIC, NULL);
	if (!tquic_ack_freq_cache)
		return -ENOMEM;

	tquic_ack_freq_wq = alloc_workqueue("tquic_ack_freq",
		WQ_UNBOUND | WQ_HIGHPRI, 0);
	if (!tquic_ack_freq_wq) {
		kmem_cache_destroy(tquic_ack_freq_cache);
		return -ENOMEM;
	}

	pr_info("tquic: ACK frequency extension initialized\n");
	return 0;
}

/**
 * tquic_ack_freq_exit - Cleanup ACK frequency module
 */
void __exit tquic_ack_freq_exit(void)
{
	if (tquic_ack_freq_wq) {
		flush_workqueue(tquic_ack_freq_wq);
		destroy_workqueue(tquic_ack_freq_wq);
	}

	kmem_cache_destroy(tquic_ack_freq_cache);
	pr_info("tquic: ACK frequency extension cleaned up\n");
}

MODULE_DESCRIPTION("TQUIC ACK Frequency Extension (RFC 9002 Appendix A.7)");
MODULE_LICENSE("GPL");
