/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: ACK Processing and Loss Detection Header
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * API definitions for QUIC loss detection and congestion control
 * as specified in RFC 9002.
 */

#ifndef _TQUIC_ACK_H
#define _TQUIC_ACK_H

#include <linux/types.h>
#include <linux/ktime.h>
#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/spinlock.h>
#include <linux/timer.h>
#include <net/tquic.h>

/*
 * RFC 9002 Constants
 */

/* kPacketThreshold: Maximum reordering in packets before considering lost */
#define TQUIC_PACKET_THRESHOLD 3

/* kTimeThreshold: Maximum reordering in time as factor of RTT (9/8) */
#define TQUIC_TIME_THRESHOLD_NUM 9
#define TQUIC_TIME_THRESHOLD_DEN 8

/* kGranularity: Timer granularity in microseconds */
#define TQUIC_TIMER_GRANULARITY_US 1000

/* kInitialRtt: Default initial RTT in microseconds */
#define TQUIC_INITIAL_RTT_US 333000 /* 333 ms */

/* kMaxAckDelay: Maximum ACK delay in microseconds */
#define TQUIC_MAX_ACK_DELAY_US 25000 /* 25 ms */

/* Persistent congestion threshold as multiple of PTO */
#define TQUIC_PERSISTENT_CONG_THRESHOLD 3

/* Maximum number of ACK ranges to track */
#define TQUIC_MAX_ACK_RANGES 256

/*
 * ACK Frame type codes (RFC 9000 Section 19.3)
 */
#define TQUIC_FRAME_ACK 0x02
#define TQUIC_FRAME_ACK_ECN 0x03

/* ACK frame types with Receive Timestamps (draft-smith-quic-receive-ts-03) */
#define TQUIC_FRAME_ACK_RECEIVE_TS 0xffa0
#define TQUIC_FRAME_ACK_ECN_RECEIVE_TS 0xffa1

/*
 * Packet metadata flags
 */
#define TQUIC_PKT_FLAG_ACK_ELICITING BIT(0)
#define TQUIC_PKT_FLAG_IN_FLIGHT BIT(1)
#define TQUIC_PKT_FLAG_HAS_CRYPTO BIT(2)
#define TQUIC_PKT_FLAG_RETRANSMITTABLE BIT(3)
#define TQUIC_PKT_FLAG_PATH_CHALLENGE BIT(4)
#define TQUIC_PKT_FLAG_PATH_RESPONSE BIT(5)
#define TQUIC_PKT_FLAG_MTU_PROBE BIT(6)
#define TQUIC_PKT_FLAG_ECN_CE BIT(7)

/* Forward declarations */
struct tquic_loss_state;
struct tquic_sent_packet;
struct tquic_ack_frame;
struct tquic_ack_frequency_state;
struct tquic_ack_frequency_frame;
struct tquic_receive_ts_state;

/**
 * struct tquic_ack_range - A range of acknowledged packet numbers
 * @start: First packet number in range (inclusive)
 * @end: Last packet number in range (inclusive)
 * @list: List linkage
 *
 * This is the internal ACK range tracking struct used for loss detection.
 * Not to be confused with tquic_ack_range in tquic_frame.h which is for
 * encoding/decoding ACK frames on the wire.
 */
struct tquic_ack_range {
	u64 start;
	u64 end;
	struct list_head list;
};

/**
 * struct tquic_ecn_counts - ECN counters
 * @ect0: ECT(0) counter
 * @ect1: ECT(1) counter
 * @ce: ECN-CE counter
 */
struct tquic_ecn_counts {
	u64 ect0;
	u64 ect1;
	u64 ce;
};

/**
 * struct tquic_rtt_state - RTT measurement state
 * @latest_rtt: Most recent RTT sample
 * @smoothed_rtt: Exponentially weighted moving average
 * @rtt_var: RTT variance (mean deviation)
 * @min_rtt: Minimum RTT observed
 * @max_ack_delay: Maximum ACK delay from peer
 * @first_rtt_sample: Time of first RTT sample
 * @samples: Number of RTT samples collected
 *
 * Note: Primary definition is in include/net/tquic.h
 */
#ifndef TQUIC_RTT_STATE_DEFINED
struct tquic_rtt_state {
	u64 latest_rtt;
	u64 smoothed_rtt;
	u64 rtt_var;
	u64 min_rtt;
	u64 max_ack_delay;
	ktime_t first_rtt_sample;
	u32 samples;
};
#endif

/**
 * struct tquic_ack_frame - Parsed ACK frame
 * @largest_acked: Largest acknowledged packet number
 * @ack_delay: ACK delay in microseconds
 * @first_range: Size of first ACK range
 * @ranges: Array of additional ACK ranges (gap, length pairs)
 * @range_count: Number of additional ranges
 * @ecn: ECN counts (if present)
 * @has_ecn: Whether ECN counts are present
 */
struct tquic_ack_frame {
	u64 largest_acked;
	u64 ack_delay;
	u64 first_range;
	struct {
		u64 gap;
		u64 length;
	} ranges[TQUIC_MAX_ACK_RANGES];
	u32 range_count;
	struct tquic_ecn_counts ecn;
	bool has_ecn;
};

/**
 * struct tquic_loss_state - Per-path loss detection state
 * @path: Associated path
 * @rtt: RTT measurement state
 * @loss_time: Time at which next packet is considered lost (per space)
 * @time_of_last_ack_eliciting_packet: Time of last ACK-eliciting send
 * @largest_acked_packet: Largest acked packet number (per space)
 * @loss_detection_timer: Loss detection timer
 * @pto_count: Consecutive PTO count for exponential backoff
 * @congestion_recovery_start_time: Start of current recovery period
 * @bytes_in_flight: Bytes currently in flight
 * @packets_in_flight: Packets currently in flight
 * @ecn_sent: ECN counts for sent packets
 * @ecn_acked: ECN counts from ACK frames
 * @ecn_validated: Whether ECN is validated for this path
 * @ecn_capable: Whether ECN is enabled
 * @sent_packets: RB-tree of sent packets (per space)
 * @sent_packets_list: Time-ordered list of sent packets (per space)
 * @num_sent_packets: Count of tracked sent packets (per space)
 * @ack_ranges: List of ACK ranges for outgoing ACK frames
 * @num_ack_ranges: Number of ACK ranges
 * @largest_received: Largest received packet number (per space)
 * @largest_received_time: Time largest packet was received
 * @ack_delay_us: Delay before sending ACK
 * @ack_eliciting_in_flight: ACK-eliciting packets in flight (per space)
 * @persistent_congestion_start: Start time for persistent congestion
 * @in_persistent_congestion: Currently in persistent congestion
 * @lock: Spinlock for synchronization
 */
struct tquic_loss_state {
	struct tquic_path *path;

	/* RTT estimation */
	struct tquic_rtt_state rtt;

	/* Loss detection state per packet number space */
	ktime_t loss_time[TQUIC_PN_SPACE_COUNT];
	ktime_t time_of_last_ack_eliciting_packet[TQUIC_PN_SPACE_COUNT];

	/* Largest acknowledged packet per space */
	u64 largest_acked_packet[TQUIC_PN_SPACE_COUNT];

	/* Timer */
	struct timer_list loss_detection_timer;

	/* PTO state */
	u32 pto_count;
	ktime_t congestion_recovery_start_time;

	/* In-flight tracking */
	u64 bytes_in_flight;
	u32 packets_in_flight;

	/* ECN state */
	struct tquic_ecn_counts ecn_sent;
	struct tquic_ecn_counts ecn_acked;
	bool ecn_validated;
	bool ecn_capable;

	/* Sent packet tracking per packet number space */
	struct rb_root sent_packets[TQUIC_PN_SPACE_COUNT];
	struct list_head sent_packets_list[TQUIC_PN_SPACE_COUNT];
	u32 num_sent_packets[TQUIC_PN_SPACE_COUNT];

	/* Received packet tracking for ACK generation */
	struct list_head ack_ranges[TQUIC_PN_SPACE_COUNT];
	u32 num_ack_ranges[TQUIC_PN_SPACE_COUNT];
	u64 largest_received[TQUIC_PN_SPACE_COUNT];
	ktime_t largest_received_time[TQUIC_PN_SPACE_COUNT];
	u32 ack_delay_us;
	u32 ack_eliciting_in_flight[TQUIC_PN_SPACE_COUNT];

	/* Persistent congestion */
	ktime_t persistent_congestion_start;
	bool in_persistent_congestion;

	/*
	 * ACK Frequency extension state (draft-ietf-quic-ack-frequency)
	 * When non-NULL, contains negotiated ACK frequency parameters
	 * that override default ACK timing behavior.
	 */
	struct tquic_ack_frequency_state *ack_freq;

	spinlock_t lock;
};

/*
 * Loss State Management
 */

/**
 * tquic_loss_state_create - Create loss detection state for a path
 * @path: Path to create state for
 *
 * Returns allocated loss state or NULL on failure.
 */
struct tquic_loss_state *tquic_loss_state_create(struct tquic_path *path);

/**
 * tquic_loss_state_destroy - Destroy loss detection state
 * @loss: Loss state to destroy
 */
void tquic_loss_state_destroy(struct tquic_loss_state *loss);

/**
 * tquic_loss_state_reset - Reset loss state (e.g., for connection migration)
 * @loss: Loss state to reset
 */
void tquic_loss_state_reset(struct tquic_loss_state *loss);

/*
 * Packet Reception and ACK Generation
 */

/**
 * tquic_record_received_packet - Record receipt of a packet for ACK generation
 * @loss: Loss state
 * @pn_space: Packet number space
 * @pn: Packet number received
 * @is_ack_eliciting: Whether packet requires an ACK
 *
 * Returns 0 on success or negative error.
 */
int tquic_record_received_packet(struct tquic_loss_state *loss, int pn_space,
				 u64 pn, bool is_ack_eliciting);

/**
 * tquic_generate_ack_frame - Generate an ACK frame
 * @loss: Loss state
 * @pn_space: Packet number space
 * @buf: Output buffer
 * @buf_len: Buffer length
 * @include_ecn: Whether to include ECN counts
 *
 * Returns number of bytes written or negative error.
 */
int tquic_generate_ack_frame(struct tquic_loss_state *loss, int pn_space,
			     u8 *buf, size_t buf_len, bool include_ecn);

/**
 * tquic_generate_ack_frame_with_timestamps - Generate ACK with receive timestamps
 * @loss: Loss state
 * @pn_space: Packet number space
 * @buf: Output buffer
 * @buf_len: Buffer length
 * @include_ecn: Whether to include ECN counts
 * @ts_state: Receive timestamps state (may be NULL to disable timestamps)
 *
 * Generates an ACK frame including receive timestamps if the extension
 * is negotiated. Uses frame type 0xffa0 (or 0xffa1 with ECN) as specified
 * in draft-smith-quic-receive-ts-03.
 *
 * Returns number of bytes written or negative error.
 */
int tquic_generate_ack_frame_with_timestamps(
	struct tquic_loss_state *loss, int pn_space, u8 *buf, size_t buf_len,
	bool include_ecn, struct tquic_receive_ts_state *ts_state);

/*
 * ACK Frame Processing
 */

/**
 * tquic_parse_ack_frame - Parse an ACK frame from wire format
 * @buf: Input buffer
 * @len: Buffer length
 * @frame: Output parsed frame
 * @ack_delay_exponent: ACK delay exponent (typically 3)
 *
 * Returns number of bytes consumed or negative error.
 */
int tquic_parse_ack_frame(const u8 *buf, size_t len,
			  struct tquic_ack_frame *frame, u8 ack_delay_exponent);

/**
 * tquic_on_ack_received - Process a received ACK frame
 * @loss: Loss state
 * @pn_space: Packet number space
 * @frame: Parsed ACK frame
 * @conn: Connection (for congestion control callbacks)
 * @path: Path the ACK was received on
 *
 * Returns 0 on success or negative error.
 */
int tquic_on_ack_received(struct tquic_loss_state *loss, int pn_space,
			  const struct tquic_ack_frame *frame,
			  struct tquic_connection *conn,
			  struct tquic_path *path);

/*
 * Packet Sending Interface
 */

/**
 * tquic_on_packet_sent - Record a sent packet for loss detection
 * @loss: Loss state
 * @pn_space: Packet number space
 * @pn: Packet number
 * @sent_bytes: Size of packet
 * @is_ack_eliciting: Whether packet requires ACK
 * @in_flight: Whether packet counts as in-flight
 * @path_id: Path the packet was sent on
 * @frames: Bitmask of frame types in packet
 *
 * Returns 0 on success or negative error.
 */
int tquic_on_packet_sent(struct tquic_loss_state *loss, int pn_space, u64 pn,
			 u32 sent_bytes, bool is_ack_eliciting, bool in_flight,
			 u32 path_id, u32 frames);

/*
 * Timer Management
 */

/**
 * tquic_set_loss_detection_timer - Set or update the loss detection timer
 * @conn: Connection
 */
void tquic_set_loss_detection_timer(struct tquic_connection *conn);

/*
 * ECN Processing
 */

/**
 * tquic_process_ecn - Process ECN feedback from ACK frame
 * @loss: Loss state
 * @frame: ACK frame with ECN counts
 * @path: Path the ACK was received on
 */
void tquic_process_ecn(struct tquic_loss_state *loss,
		       const struct tquic_ack_frame *frame,
		       struct tquic_path *path);

/**
 * tquic_ecn_mark_sent - Record ECN marking of sent packet
 * @loss: Loss state
 * @ecn_codepoint: ECN codepoint used (0=Not-ECT, 1=ECT(1), 2=ECT(0), 3=CE)
 */
void tquic_ecn_mark_sent(struct tquic_loss_state *loss, u8 ecn_codepoint);

/*
 * Statistics and Debugging
 */

/**
 * tquic_loss_get_rtt_stats - Get RTT statistics
 * @loss: Loss state
 * @latest: Output for latest RTT (us)
 * @smoothed: Output for smoothed RTT (us)
 * @variance: Output for RTT variance (us)
 * @min_rtt: Output for minimum RTT (us)
 */
void tquic_loss_get_rtt_stats(struct tquic_loss_state *loss, u64 *latest,
			      u64 *smoothed, u64 *variance, u64 *min_rtt);

/**
 * tquic_loss_get_in_flight - Get bytes and packets in flight
 * @loss: Loss state
 * @bytes: Output for bytes in flight
 * @packets: Output for packets in flight
 */
void tquic_loss_get_in_flight(struct tquic_loss_state *loss, u64 *bytes,
			      u32 *packets);

/*
 * ACK Frequency Integration
 */

/**
 * tquic_loss_state_set_ack_freq - Associate ACK frequency state with loss state
 * @loss: Loss detection state
 * @ack_freq: ACK frequency state (may be NULL to disable)
 *
 * Associates an ACK frequency state with the loss state to enable
 * ACK suppression based on negotiated parameters.
 */
void tquic_loss_state_set_ack_freq(struct tquic_loss_state *loss,
				   struct tquic_ack_frequency_state *ack_freq);

/**
 * tquic_should_send_ack - Determine if ACK should be sent
 * @loss: Loss detection state
 * @pn: Packet number just received
 * @ack_eliciting: Whether the packet was ack-eliciting
 *
 * Checks ACK frequency state (if available) to determine whether
 * an ACK should be sent. Falls back to default behavior if ACK
 * frequency is not enabled.
 *
 * Returns true if an ACK should be sent immediately.
 */
bool tquic_should_send_ack(struct tquic_loss_state *loss, u64 pn,
			   bool ack_eliciting);

/**
 * tquic_get_ack_delay - Get current ACK delay for timer
 * @loss: Loss detection state
 *
 * Returns the current ACK delay in microseconds, considering
 * ACK frequency negotiation if active.
 */
u64 tquic_get_ack_delay(struct tquic_loss_state *loss);

/*
 * ACK Processing Functions
 */

/**
 * tquic_ack_on_packet_received - Record packet reception for ACK processing
 * @conn: Connection
 * @pn: Packet number received
 * @pn_space: Packet number space
 */
void tquic_ack_on_packet_received(struct tquic_connection *conn, u64 pn,
				  u8 pn_space);

/**
 * tquic_ack_should_send - Check if ACK frame should be sent
 * @conn: Connection
 * @pn_space: Packet number space
 *
 * Returns true if an ACK should be sent for the given packet number space.
 */
bool tquic_ack_should_send(struct tquic_connection *conn, u8 pn_space);

/**
 * tquic_ack_create - Create an ACK frame
 * @conn: Connection
 * @pn_space: Packet number space
 * @skb: Socket buffer to write ACK frame into
 *
 * Returns number of bytes written or negative error.
 */
int tquic_ack_create(struct tquic_connection *conn, u8 pn_space,
		     struct sk_buff *skb);

/*
 * Module Initialization
 */

/**
 * tquic_ack_init - Initialize ACK/loss detection module
 */
int __init tquic_ack_init(void);

/**
 * tquic_ack_exit - Cleanup ACK/loss detection module
 */
void tquic_ack_exit(void);

#endif /* _TQUIC_ACK_H */
