/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: ACK Frequency Extension Header (RFC 9002 Appendix A.7)
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Complete ACK Frequency negotiation implementation including:
 *   - Transport parameter: min_ack_delay (0xff04de1a)
 *   - ACK_FREQUENCY frame (0xaf) encoding/decoding
 *   - IMMEDIATE_ACK frame (0x1f) encoding/decoding
 *   - Dynamic frequency adjustment based on CC state
 *   - Full negotiation state machine
 *   - Congestion control integration
 *
 * Frame Types:
 *   - ACK_FREQUENCY (0xaf): Request peer adjust ACK behavior
 *   - IMMEDIATE_ACK (0x1f): Request immediate ACK from peer
 *
 * Transport Parameter:
 *   - min_ack_delay (0xff04de1a): Minimum ACK delay in microseconds
 */

#ifndef _TQUIC_CORE_ACK_FREQUENCY_H
#define _TQUIC_CORE_ACK_FREQUENCY_H

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/timer.h>
#include <linux/ktime.h>
#include <linux/workqueue.h>

/* Forward declarations */
struct tquic_connection;
struct tquic_path;
struct tquic_loss_state;

/*
 * =============================================================================
 * Frame Type Constants
 * =============================================================================
 */

#define TQUIC_FRAME_ACK_FREQUENCY	0xafULL
#define TQUIC_FRAME_IMMEDIATE_ACK	0x1fULL

/*
 * Transport parameter ID for min_ack_delay (draft-ietf-quic-ack-frequency)
 */
#define TQUIC_TP_MIN_ACK_DELAY		0xff04de1aULL

/*
 * =============================================================================
 * Default Values (per draft-ietf-quic-ack-frequency)
 * =============================================================================
 */

#define TQUIC_ACK_FREQ_DEFAULT_THRESHOLD	2	/* ACK every 2 packets */
#define TQUIC_ACK_FREQ_DEFAULT_MAX_DELAY_US	25000	/* 25ms default */
#define TQUIC_ACK_FREQ_DEFAULT_REORDER_THRESHOLD 1
#define TQUIC_ACK_FREQ_IGNORE_ORDER_SENTINEL	0	/* 0 = ignore reordering */

/*
 * =============================================================================
 * Limits
 * =============================================================================
 */

#define TQUIC_MIN_ACK_DELAY_MIN_US	1		/* 1 microsecond minimum */
#define TQUIC_MIN_ACK_DELAY_MAX_US	16383000	/* ~16.4 seconds max */
#define TQUIC_ACK_FREQ_MAX_THRESHOLD	255		/* Max packets before ACK */
#define TQUIC_ACK_FREQ_MAX_REORDER	255		/* Max reorder threshold */

/*
 * =============================================================================
 * Negotiation State Machine
 * =============================================================================
 */

/**
 * enum tquic_ack_freq_nego_state - ACK frequency negotiation states
 * @TQUIC_ACK_FREQ_STATE_DISABLED: Extension not enabled/negotiated
 * @TQUIC_ACK_FREQ_STATE_PENDING: Transport parameter sent, awaiting response
 * @TQUIC_ACK_FREQ_STATE_NEGOTIATED: Both sides exchanged min_ack_delay
 * @TQUIC_ACK_FREQ_STATE_ACTIVE: ACK_FREQUENCY frames in use
 * @TQUIC_ACK_FREQ_STATE_ERROR: Protocol error occurred
 */
enum tquic_ack_freq_nego_state {
	TQUIC_ACK_FREQ_STATE_DISABLED = 0,
	TQUIC_ACK_FREQ_STATE_PENDING,
	TQUIC_ACK_FREQ_STATE_NEGOTIATED,
	TQUIC_ACK_FREQ_STATE_ACTIVE,
	TQUIC_ACK_FREQ_STATE_ERROR,
};

/**
 * enum tquic_ack_freq_adjustment_reason - Reasons for ACK frequency changes
 * @TQUIC_ACK_FREQ_REASON_NONE: No adjustment
 * @TQUIC_ACK_FREQ_REASON_CONGESTION: CC entered recovery/loss state
 * @TQUIC_ACK_FREQ_REASON_HIGH_RTT: High RTT detected
 * @TQUIC_ACK_FREQ_REASON_LOW_RTT: Low RTT detected
 * @TQUIC_ACK_FREQ_REASON_REORDERING: Packet reordering detected
 * @TQUIC_ACK_FREQ_REASON_APPLICATION: Application requested change
 * @TQUIC_ACK_FREQ_REASON_BANDWIDTH: Bandwidth-based adjustment
 * @TQUIC_ACK_FREQ_REASON_ECN: ECN congestion signal received
 */
enum tquic_ack_freq_adjustment_reason {
	TQUIC_ACK_FREQ_REASON_NONE = 0,
	TQUIC_ACK_FREQ_REASON_CONGESTION,
	TQUIC_ACK_FREQ_REASON_HIGH_RTT,
	TQUIC_ACK_FREQ_REASON_LOW_RTT,
	TQUIC_ACK_FREQ_REASON_REORDERING,
	TQUIC_ACK_FREQ_REASON_APPLICATION,
	TQUIC_ACK_FREQ_REASON_BANDWIDTH,
	TQUIC_ACK_FREQ_REASON_ECN,
};

/*
 * =============================================================================
 * Frame Structures
 * =============================================================================
 */

/**
 * struct tquic_ack_frequency_frame - Parsed ACK_FREQUENCY frame
 * @sequence_number: Monotonically increasing sequence number
 * @ack_eliciting_threshold: ACK-eliciting packets before ACK required
 * @request_max_ack_delay: Requested maximum ACK delay (microseconds)
 * @reorder_threshold: Packet reordering threshold (0 = ignore order)
 *
 * Per draft-ietf-quic-ack-frequency Section 4:
 *
 * ACK_FREQUENCY Frame {
 *   Type (i) = 0xaf,
 *   Sequence Number (i),
 *   Ack-Eliciting Threshold (i),
 *   Request Max Ack Delay (i),
 *   Reorder Threshold (i),
 * }
 */
struct tquic_ack_frequency_frame {
	u64 sequence_number;
	u64 ack_eliciting_threshold;
	u64 request_max_ack_delay;
	u64 reorder_threshold;
};

/*
 * =============================================================================
 * Dynamic Adjustment Parameters
 * =============================================================================
 */

/**
 * struct tquic_ack_freq_dynamic_params - Parameters for dynamic adjustment
 * @congestion_threshold: Threshold when in congestion
 * @congestion_max_delay_us: Max delay during congestion
 * @normal_threshold: Normal threshold
 * @normal_max_delay_us: Normal max delay
 * @high_bw_threshold: Threshold for high bandwidth paths
 * @high_bw_max_delay_us: Max delay for high bandwidth
 * @low_rtt_threshold_us: RTT below which to use lower delays
 * @high_rtt_threshold_us: RTT above which to use higher delays
 * @reorder_threshold: Reorder threshold for reordering paths
 */
struct tquic_ack_freq_dynamic_params {
	u64 congestion_threshold;
	u64 congestion_max_delay_us;
	u64 normal_threshold;
	u64 normal_max_delay_us;
	u64 high_bw_threshold;
	u64 high_bw_max_delay_us;
	u32 low_rtt_threshold_us;
	u32 high_rtt_threshold_us;
	u64 reorder_threshold;
};

/*
 * =============================================================================
 * ACK Frequency State (per-connection)
 * =============================================================================
 */

/**
 * struct tquic_ack_frequency_state - Per-connection ACK frequency state
 * @nego_state: Current negotiation state
 * @enabled: Whether ACK frequency extension is negotiated
 *
 * Transport parameter negotiation:
 * @min_ack_delay_us: Our advertised minimum ACK delay (microseconds)
 * @peer_min_ack_delay_us: Peer's advertised minimum ACK delay
 * @ack_delay_exponent: ACK delay exponent from transport params
 * @max_ack_delay_tp_us: max_ack_delay from transport params (microseconds)
 *
 * Frame sequence tracking:
 * @last_sent_seq: Last sequence number sent in ACK_FREQUENCY frame
 * @last_recv_seq: Highest sequence number received in ACK_FREQUENCY frame
 *
 * Current ACK behavior (from peer's ACK_FREQUENCY frames):
 * @current_threshold: Current ack-eliciting threshold
 * @current_max_delay_us: Current maximum ACK delay (microseconds)
 * @current_reorder_threshold: Current reorder threshold
 * @ignore_order: Whether to ignore packet reordering
 *
 * Pending actions:
 * @immediate_ack_pending: IMMEDIATE_ACK was received, send ACK immediately
 * @ack_frequency_pending: Need to send ACK_FREQUENCY frame
 * @immediate_ack_request: Need to send IMMEDIATE_ACK frame
 * @pending_frame: Pending ACK_FREQUENCY frame to send
 *
 * ACK suppression state:
 * @packets_since_ack: Ack-eliciting packets since last ACK sent
 * @largest_pn_received: Largest packet number received
 * @last_ack_sent_time: Time of last ACK sent
 *
 * Dynamic adjustment:
 * @dynamic_params: Parameters for dynamic adjustment
 * @last_adjustment_reason: Reason for last adjustment
 * @in_congestion: Currently in congestion state
 * @reordering_detected: Reordering detected on path
 * @latency_sensitive: Application hint for latency sensitivity
 * @throughput_focused: Application hint for throughput focus
 *
 * Delayed ACK timer:
 * @ack_timer: Timer for delayed ACK
 * @ack_timer_armed: Whether timer is currently running
 *
 * Work queue for deferred operations:
 * @adjustment_work: Work item for async adjustments
 *
 * Statistics:
 * @frames_sent: ACK_FREQUENCY frames sent
 * @frames_received: ACK_FREQUENCY frames received
 * @immediate_ack_sent: IMMEDIATE_ACK frames sent
 * @immediate_ack_received: IMMEDIATE_ACK frames received
 * @adjustments_made: Number of dynamic adjustments
 *
 * @conn: Back-pointer to connection
 * @lock: Spinlock protecting this state
 */
struct tquic_ack_frequency_state {
	enum tquic_ack_freq_nego_state nego_state;
	bool enabled;

	/* Transport parameter negotiation */
	u64 min_ack_delay_us;
	u64 peer_min_ack_delay_us;
	u8 ack_delay_exponent;
	u64 max_ack_delay_tp_us;

	/* Frame sequence tracking */
	u64 last_sent_seq;
	u64 last_recv_seq;

	/* Current ACK behavior */
	u64 current_threshold;
	u64 current_max_delay_us;
	u64 current_reorder_threshold;
	bool ignore_order;

	/* Pending actions */
	bool immediate_ack_pending;
	bool ack_frequency_pending;
	bool immediate_ack_request;
	struct tquic_ack_frequency_frame pending_frame;

	/* ACK suppression state */
	u64 packets_since_ack;
	u64 largest_pn_received;
	ktime_t last_ack_sent_time;

	/* Dynamic adjustment */
	struct tquic_ack_freq_dynamic_params dynamic_params;
	enum tquic_ack_freq_adjustment_reason last_adjustment_reason;
	bool in_congestion;
	bool reordering_detected;
	bool latency_sensitive;
	bool throughput_focused;

	/* Delayed ACK timer */
	struct timer_list ack_timer;
	bool ack_timer_armed;

	/* Work queue */
	struct work_struct adjustment_work;

	/* Statistics */
	u64 frames_sent;
	u64 frames_received;
	u64 immediate_ack_sent;
	u64 immediate_ack_received;
	u64 adjustments_made;

	/* Back-pointer */
	struct tquic_connection *conn;

	/* Synchronization */
	spinlock_t lock;
};

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
	struct tquic_connection *conn);

/**
 * tquic_ack_freq_state_destroy - Free ACK frequency state
 * @state: State to destroy
 */
void tquic_ack_freq_state_destroy(struct tquic_ack_frequency_state *state);

/**
 * tquic_ack_freq_enable - Enable ACK frequency after transport param negotiation
 * @state: ACK frequency state
 * @peer_min_ack_delay: Peer's min_ack_delay transport parameter (microseconds)
 *
 * Called when both endpoints have advertised min_ack_delay.
 */
void tquic_ack_freq_enable(struct tquic_ack_frequency_state *state,
			   u64 peer_min_ack_delay);

/**
 * tquic_ack_freq_is_enabled - Check if ACK frequency extension is active
 * @state: ACK frequency state
 *
 * Returns true if extension is negotiated and enabled.
 */
bool tquic_ack_freq_is_enabled(const struct tquic_ack_frequency_state *state);

/**
 * tquic_ack_freq_get_nego_state - Get current negotiation state
 * @state: ACK frequency state
 *
 * Returns current state machine state.
 */
enum tquic_ack_freq_nego_state tquic_ack_freq_get_nego_state(
	const struct tquic_ack_frequency_state *state);

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
 * Returns bytes consumed on success, negative error on failure.
 */
int tquic_parse_ack_frequency_frame(const u8 *buf, size_t buf_len,
				    struct tquic_ack_frequency_frame *frame);

/**
 * tquic_parse_immediate_ack_frame - Parse IMMEDIATE_ACK frame
 * @buf: Input buffer (starting at frame type)
 * @buf_len: Buffer length
 *
 * IMMEDIATE_ACK has no payload beyond the frame type.
 *
 * Returns bytes consumed on success, negative error on failure.
 */
int tquic_parse_immediate_ack_frame(const u8 *buf, size_t buf_len);

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
				    u64 max_delay, u64 reorder);

/**
 * tquic_write_immediate_ack_frame - Write IMMEDIATE_ACK frame
 * @buf: Output buffer
 * @buf_len: Buffer length
 *
 * Returns bytes written on success, negative error on failure.
 */
int tquic_write_immediate_ack_frame(u8 *buf, size_t buf_len);

/**
 * tquic_ack_frequency_frame_size - Calculate ACK_FREQUENCY frame size
 * @seq_num: Sequence number
 * @threshold: Ack-eliciting threshold
 * @max_delay: Max ACK delay
 * @reorder: Reorder threshold
 *
 * Returns size in bytes needed for the frame.
 */
size_t tquic_ack_frequency_frame_size(u64 seq_num, u64 threshold,
				      u64 max_delay, u64 reorder);

/**
 * tquic_immediate_ack_frame_size - Get IMMEDIATE_ACK frame size
 *
 * Returns size in bytes (1 for frame type 0x1F).
 */
size_t tquic_immediate_ack_frame_size(void);

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
 * Only processes frames with sequence numbers larger than previously seen.
 *
 * Returns 0 on success, negative error on failure.
 */
int tquic_handle_ack_frequency_frame(struct tquic_ack_frequency_state *state,
				     const struct tquic_ack_frequency_frame *frame);

/**
 * tquic_handle_immediate_ack_frame - Process received IMMEDIATE_ACK frame
 * @state: ACK frequency state
 *
 * Triggers immediate ACK on next ack-eliciting packet.
 *
 * Returns 0 on success.
 */
int tquic_handle_immediate_ack_frame(struct tquic_ack_frequency_state *state);

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
 * Implements ACK suppression algorithm considering:
 * - IMMEDIATE_ACK pending
 * - Ack-eliciting threshold
 * - Reorder threshold
 * - Congestion state
 *
 * Returns true if an ACK should be sent immediately.
 */
bool tquic_ack_freq_should_ack(struct tquic_ack_frequency_state *state,
			       u64 pn, bool ack_eliciting);

/**
 * tquic_ack_freq_on_ack_sent - Notify that ACK was sent
 * @state: ACK frequency state
 *
 * Resets the packet counter after sending an ACK.
 */
void tquic_ack_freq_on_ack_sent(struct tquic_ack_frequency_state *state);

/**
 * tquic_ack_freq_get_max_delay - Get current maximum ACK delay
 * @state: ACK frequency state
 *
 * Returns maximum ACK delay in microseconds.
 */
u64 tquic_ack_freq_get_max_delay(struct tquic_ack_frequency_state *state);

/**
 * tquic_ack_freq_get_delay_timer - Get time until ACK should be sent
 * @state: ACK frequency state
 *
 * Returns delay in nanoseconds until ACK timer should fire.
 */
u64 tquic_ack_freq_get_delay_timer(struct tquic_ack_frequency_state *state);

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
				  u64 threshold, u64 max_delay_us, u64 reorder);

/**
 * tquic_ack_freq_request_immediate_ack - Schedule IMMEDIATE_ACK frame
 * @state: ACK frequency state
 *
 * Returns 0 on success.
 */
int tquic_ack_freq_request_immediate_ack(struct tquic_ack_frequency_state *state);

/**
 * tquic_ack_freq_generate_pending - Generate pending ACK frequency frames
 * @state: ACK frequency state
 * @buf: Output buffer
 * @buf_len: Buffer length
 *
 * Returns bytes written, or negative error.
 */
int tquic_ack_freq_generate_pending(struct tquic_ack_frequency_state *state,
				    u8 *buf, size_t buf_len);

/**
 * tquic_ack_freq_has_pending - Check if there are pending frames to send
 * @state: ACK frequency state
 *
 * Returns true if ACK_FREQUENCY or IMMEDIATE_ACK frames are pending.
 */
bool tquic_ack_freq_has_pending(struct tquic_ack_frequency_state *state);

/*
 * =============================================================================
 * Dynamic Adjustment API (Congestion Control Integration)
 * =============================================================================
 */

/**
 * tquic_ack_freq_on_congestion_event - Notify of congestion event
 * @state: ACK frequency state
 * @in_recovery: Whether CC is in recovery state
 *
 * Called by congestion control when entering/exiting recovery.
 * Adjusts ACK frequency to provide more feedback during congestion.
 */
void tquic_ack_freq_on_congestion_event(struct tquic_ack_frequency_state *state,
					bool in_recovery);

/**
 * tquic_ack_freq_on_rtt_update - Notify of RTT update
 * @state: ACK frequency state
 * @rtt_us: Smoothed RTT in microseconds
 * @rtt_var_us: RTT variance in microseconds
 *
 * Adjusts ACK frequency based on path RTT characteristics.
 */
void tquic_ack_freq_on_rtt_update(struct tquic_ack_frequency_state *state,
				  u64 rtt_us, u64 rtt_var_us);

/**
 * tquic_ack_freq_on_bandwidth_update - Notify of bandwidth estimate update
 * @state: ACK frequency state
 * @bandwidth_bps: Estimated bandwidth in bytes per second
 *
 * Adjusts ACK frequency based on path bandwidth.
 */
void tquic_ack_freq_on_bandwidth_update(struct tquic_ack_frequency_state *state,
					u64 bandwidth_bps);

/**
 * tquic_ack_freq_on_reordering - Notify of packet reordering detection
 * @state: ACK frequency state
 * @gap: Reorder gap in packets
 *
 * Adjusts reorder threshold based on observed reordering.
 */
void tquic_ack_freq_on_reordering(struct tquic_ack_frequency_state *state,
				  u64 gap);

/**
 * tquic_ack_freq_on_ecn - Notify of ECN congestion signal
 * @state: ACK frequency state
 *
 * Adjusts ACK frequency in response to ECN-CE marks.
 */
void tquic_ack_freq_on_ecn(struct tquic_ack_frequency_state *state);

/**
 * tquic_ack_freq_set_application_hint - Set application-level hint
 * @state: ACK frequency state
 * @latency_sensitive: True if application is latency-sensitive
 * @throughput_focused: True if application prioritizes throughput
 *
 * Allows application to influence ACK frequency decisions.
 */
void tquic_ack_freq_set_application_hint(struct tquic_ack_frequency_state *state,
					 bool latency_sensitive,
					 bool throughput_focused);

/*
 * =============================================================================
 * Integration with Loss Detection
 * =============================================================================
 */

/**
 * tquic_ack_freq_update_loss_state - Update loss state with ACK freq params
 * @loss: Loss detection state
 * @state: ACK frequency state
 *
 * Updates loss detection's ACK delay based on negotiated parameters.
 */
void tquic_ack_freq_update_loss_state(struct tquic_loss_state *loss,
				      struct tquic_ack_frequency_state *state);

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
int tquic_ack_freq_encode_tp(u64 min_ack_delay_us, u8 *buf, size_t buf_len);

/**
 * tquic_ack_freq_decode_tp - Decode min_ack_delay transport parameter
 * @buf: Input buffer (parameter value only)
 * @buf_len: Value length
 * @min_ack_delay_us: Output minimum ACK delay
 *
 * Returns 0 on success, negative error on failure.
 */
int tquic_ack_freq_decode_tp(const u8 *buf, size_t buf_len,
			     u64 *min_ack_delay_us);

/**
 * tquic_ack_freq_tp_size - Get size needed for min_ack_delay transport param
 * @min_ack_delay_us: Minimum ACK delay value
 *
 * Returns size in bytes.
 */
size_t tquic_ack_freq_tp_size(u64 min_ack_delay_us);

/*
 * =============================================================================
 * Statistics
 * =============================================================================
 */

/**
 * struct tquic_ack_freq_stats - ACK frequency statistics
 * @frames_sent: ACK_FREQUENCY frames sent
 * @frames_received: ACK_FREQUENCY frames received
 * @immediate_ack_sent: IMMEDIATE_ACK frames sent
 * @immediate_ack_received: IMMEDIATE_ACK frames received
 * @adjustments_made: Dynamic adjustments made
 * @last_reason: Last adjustment reason
 */
struct tquic_ack_freq_stats {
	u64 frames_sent;
	u64 frames_received;
	u64 immediate_ack_sent;
	u64 immediate_ack_received;
	u64 adjustments_made;
	enum tquic_ack_freq_adjustment_reason last_reason;
};

/**
 * tquic_ack_freq_get_stats - Get ACK frequency statistics
 * @state: ACK frequency state
 * @stats: Output statistics structure
 */
void tquic_ack_freq_get_stats(struct tquic_ack_frequency_state *state,
			      struct tquic_ack_freq_stats *stats);

/*
 * =============================================================================
 * Module Initialization
 * =============================================================================
 */

/**
 * tquic_ack_freq_init - Initialize ACK frequency module
 *
 * Returns 0 on success, negative error on failure.
 */
int __init tquic_ack_freq_init(void);

/**
 * tquic_ack_freq_exit - Cleanup ACK frequency module
 */
void tquic_ack_freq_exit(void);

#endif /* _TQUIC_CORE_ACK_FREQUENCY_H */
