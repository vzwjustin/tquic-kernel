/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: QUIC Receive Timestamps Extension Header
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Implements the QUIC Receive Timestamps extension as specified in
 * draft-smith-quic-receive-ts-03. This extension allows endpoints to
 * report packet receive timestamps in ACK frames for improved RTT
 * estimation, congestion control, and one-way delay measurement.
 *
 * Transport Parameters:
 *   - max_receive_timestamps_per_ack (0xff0a002): Maximum timestamps per ACK
 *   - receive_timestamps_exponent (0xff0a003): Delta encoding exponent
 */

#ifndef _TQUIC_RECEIVE_TIMESTAMPS_H
#define _TQUIC_RECEIVE_TIMESTAMPS_H

#include <linux/types.h>
#include <linux/ktime.h>
#include <linux/spinlock.h>

/*
 * Transport Parameter IDs for Receive Timestamps Extension
 * (draft-smith-quic-receive-ts-03 Section 3)
 */
#define TQUIC_TP_MAX_RECEIVE_TIMESTAMPS_PER_ACK	0xff0a002ULL
#define TQUIC_TP_RECEIVE_TIMESTAMPS_EXPONENT	0xff0a003ULL

/*
 * ACK Frame type codes with timestamps
 * (draft-smith-quic-receive-ts-03 Section 4)
 */
#define TQUIC_FRAME_ACK_RECEIVE_TIMESTAMPS		0xffa0
#define TQUIC_FRAME_ACK_ECN_RECEIVE_TIMESTAMPS		0xffa1

/*
 * Default and limit values
 */

/* Default maximum timestamps per ACK frame */
#define TQUIC_DEFAULT_MAX_RECEIVE_TIMESTAMPS	255

/* Maximum timestamps we can encode in a single ACK (practical limit) */
#define TQUIC_MAX_RECEIVE_TIMESTAMPS		1024

/* Default receive timestamps exponent (microsecond precision) */
#define TQUIC_DEFAULT_RECEIVE_TS_EXPONENT	0

/* Maximum allowed exponent value */
#define TQUIC_MAX_RECEIVE_TS_EXPONENT		20

/* Ring buffer size for tracking received packet timestamps */
#define TQUIC_RECEIVE_TS_RINGBUF_SIZE		2048

/* Invalid/unset timestamp marker */
#define TQUIC_TIMESTAMP_INVALID			0

/**
 * struct tquic_timestamp_range - A range of packet timestamps
 * @gap: Number of unacknowledged packets before this range minus 1
 * @timestamp_delta_count: Number of timestamps in this range
 * @timestamp_deltas: Array of delta-encoded timestamps
 *
 * Represents a contiguous sequence of received packets with their
 * timestamps encoded as deltas from a reference point.
 *
 * The encoding uses delta compression:
 * - First timestamp in range is delta from timestamp_basis
 * - Subsequent timestamps are deltas from the previous timestamp
 */
struct tquic_timestamp_range {
	u64 gap;
	u64 timestamp_delta_count;
	u64 *timestamp_deltas;
};

/**
 * struct tquic_receive_ts_params - Receive timestamps transport parameters
 * @max_receive_timestamps_per_ack: Maximum timestamps peer wants in ACK
 * @receive_timestamps_exponent: Exponent for delta encoding
 * @enabled: Whether the extension is negotiated
 *
 * These parameters are exchanged during the handshake to negotiate
 * receive timestamp support and encoding precision.
 */
struct tquic_receive_ts_params {
	u64 max_receive_timestamps_per_ack;
	u8 receive_timestamps_exponent;
	bool enabled;
};

/**
 * struct tquic_pkt_timestamp - Timestamp record for a received packet
 * @pn: Packet number
 * @recv_time: Receive timestamp in microseconds since timestamp_basis
 * @valid: Whether this entry is valid
 */
struct tquic_pkt_timestamp {
	u64 pn;
	u64 recv_time_us;
	bool valid;
};

/**
 * struct tquic_receive_ts_state - Per-connection receive timestamps state
 * @params: Negotiated parameters
 * @timestamp_basis: Session-wide reference point (ktime)
 * @timestamp_basis_us: Timestamp basis in microseconds (for encoding)
 * @timestamp_basis_pn: Packet number of the timestamp basis
 * @timestamp_basis_set: Whether the basis has been established
 * @ring_buffer: Ring buffer of recent packet timestamps
 * @ring_head: Head index of ring buffer (next write position)
 * @ring_count: Number of valid entries in ring buffer
 * @exponent: Negotiated exponent for delta encoding
 * @max_timestamps: Maximum timestamps to include per ACK
 * @timestamps_sent: Total timestamps sent
 * @timestamps_received: Total timestamps received from peer
 * @lock: Spinlock for state protection
 *
 * Maintains state for tracking received packet timestamps and
 * encoding them into ACK frames.
 */
struct tquic_receive_ts_state {
	struct tquic_receive_ts_params params;

	/* Timestamp basis (reference point for delta encoding) */
	ktime_t timestamp_basis;
	u64 timestamp_basis_us;
	u64 timestamp_basis_pn;
	bool timestamp_basis_set;

	/* Ring buffer for recent packet timestamps */
	struct tquic_pkt_timestamp *ring_buffer;
	u32 ring_head;
	u32 ring_count;

	/* Encoding parameters */
	u8 exponent;
	u32 max_timestamps;

	/* Statistics */
	u64 timestamps_sent;
	u64 timestamps_received;

	spinlock_t lock;
};

/**
 * struct tquic_ack_timestamps - Decoded timestamps from ACK frame
 * @timestamp_range_count: Number of timestamp ranges
 * @ranges: Array of timestamp ranges
 * @largest_acked_timestamp: Receive timestamp of largest acked packet
 * @timestamp_basis_delta: Delta from peer's timestamp basis
 *
 * Used when parsing an ACK frame with receive timestamps.
 */
struct tquic_ack_timestamps {
	u32 timestamp_range_count;
	struct tquic_timestamp_range *ranges;
	u64 largest_acked_timestamp;
	u64 timestamp_basis_delta;
};

/*
 * =============================================================================
 * Initialization and Cleanup
 * =============================================================================
 */

/**
 * tquic_receive_ts_init - Initialize receive timestamps state
 * @state: State structure to initialize
 *
 * Initializes the receive timestamps state with default values.
 * Must be called before using any other receive timestamp functions.
 *
 * Returns 0 on success, negative error code on failure.
 */
int tquic_receive_ts_init(struct tquic_receive_ts_state *state);

/**
 * tquic_receive_ts_destroy - Destroy receive timestamps state
 * @state: State to destroy
 *
 * Frees all resources associated with the receive timestamps state.
 */
void tquic_receive_ts_destroy(struct tquic_receive_ts_state *state);

/**
 * tquic_receive_ts_reset - Reset receive timestamps state
 * @state: State to reset
 *
 * Resets the state while preserving negotiated parameters.
 * Called on connection migration or path change.
 */
void tquic_receive_ts_reset(struct tquic_receive_ts_state *state);

/*
 * =============================================================================
 * Parameter Negotiation
 * =============================================================================
 */

/**
 * tquic_receive_ts_set_local_params - Set local receive timestamp parameters
 * @state: Receive timestamps state
 * @max_timestamps: Maximum timestamps we want per ACK
 * @exponent: Desired timestamps exponent
 *
 * Configures local parameters before handshake. These will be
 * advertised to the peer in transport parameters.
 */
void tquic_receive_ts_set_local_params(struct tquic_receive_ts_state *state,
				       u32 max_timestamps, u8 exponent);

/**
 * tquic_receive_ts_set_peer_params - Set peer's receive timestamp parameters
 * @state: Receive timestamps state
 * @max_timestamps: Peer's maximum timestamps per ACK
 * @exponent: Peer's timestamps exponent
 *
 * Called when peer's transport parameters are received.
 * After both local and peer params are set, negotiation occurs.
 */
void tquic_receive_ts_set_peer_params(struct tquic_receive_ts_state *state,
				      u64 max_timestamps, u8 exponent);

/**
 * tquic_receive_ts_negotiate - Negotiate receive timestamp parameters
 * @state: Receive timestamps state
 *
 * Called after both local and peer parameters are set.
 * Determines final negotiated values.
 *
 * Returns true if extension is enabled, false otherwise.
 */
bool tquic_receive_ts_negotiate(struct tquic_receive_ts_state *state);

/**
 * tquic_receive_ts_is_enabled - Check if receive timestamps are enabled
 * @state: Receive timestamps state
 *
 * Returns true if the extension was successfully negotiated.
 */
bool tquic_receive_ts_is_enabled(struct tquic_receive_ts_state *state);

/*
 * =============================================================================
 * Timestamp Recording
 * =============================================================================
 */

/**
 * tquic_receive_ts_record - Record receive timestamp for a packet
 * @state: Receive timestamps state
 * @pn: Packet number of received packet
 * @recv_time: Receive timestamp (ktime)
 *
 * Records the receive timestamp for an incoming packet. The timestamp
 * is stored in the ring buffer for later inclusion in ACK frames.
 *
 * This should be called as early as possible when receiving a packet
 * to capture accurate timing.
 *
 * Returns 0 on success, negative error code on failure.
 */
int tquic_receive_ts_record(struct tquic_receive_ts_state *state,
			    u64 pn, ktime_t recv_time);

/**
 * tquic_receive_ts_lookup - Look up timestamp for a packet number
 * @state: Receive timestamps state
 * @pn: Packet number to look up
 * @recv_time_us: Output: receive timestamp in microseconds
 *
 * Looks up the stored receive timestamp for a given packet number.
 *
 * Returns 0 on success, -ENOENT if not found.
 */
int tquic_receive_ts_lookup(struct tquic_receive_ts_state *state,
			    u64 pn, u64 *recv_time_us);

/*
 * =============================================================================
 * ACK Frame Encoding
 * =============================================================================
 */

/**
 * tquic_receive_ts_encode - Encode timestamps into ACK frame
 * @state: Receive timestamps state
 * @ack_ranges: ACK ranges to include timestamps for
 * @num_ranges: Number of ACK ranges
 * @largest_acked: Largest acknowledged packet number
 * @buf: Output buffer for encoded timestamps
 * @buf_len: Length of output buffer
 *
 * Encodes receive timestamps for the acknowledged packets into the
 * wire format specified by draft-smith-quic-receive-ts-03.
 *
 * The encoding uses delta compression:
 * 1. Timestamp basis delta (from session-wide reference point)
 * 2. Timestamp range count
 * 3. For each range: gap, delta count, deltas
 *
 * Returns number of bytes written, or negative error code.
 */
ssize_t tquic_receive_ts_encode(struct tquic_receive_ts_state *state,
				const struct list_head *ack_ranges,
				u32 num_ranges, u64 largest_acked,
				u8 *buf, size_t buf_len);

/**
 * tquic_receive_ts_get_frame_type - Get appropriate ACK frame type
 * @state: Receive timestamps state
 * @include_ecn: Whether to include ECN counts
 *
 * Returns the frame type code for ACK with receive timestamps.
 * If receive timestamps are not enabled, returns standard ACK type.
 */
u64 tquic_receive_ts_get_frame_type(struct tquic_receive_ts_state *state,
				    bool include_ecn);

/*
 * =============================================================================
 * ACK Frame Decoding
 * =============================================================================
 */

/**
 * tquic_receive_ts_decode - Decode timestamps from ACK frame
 * @state: Receive timestamps state
 * @buf: Input buffer containing encoded timestamps
 * @len: Length of input buffer
 * @timestamps: Output structure for decoded timestamps
 *
 * Decodes receive timestamps from an ACK frame. The caller must
 * free the allocated timestamp_deltas arrays in the ranges.
 *
 * Returns number of bytes consumed, or negative error code.
 */
ssize_t tquic_receive_ts_decode(struct tquic_receive_ts_state *state,
				const u8 *buf, size_t len,
				struct tquic_ack_timestamps *timestamps);

/**
 * tquic_receive_ts_free_decoded - Free decoded timestamps structure
 * @timestamps: Decoded timestamps to free
 *
 * Frees memory allocated during decoding.
 */
void tquic_receive_ts_free_decoded(struct tquic_ack_timestamps *timestamps);

/**
 * tquic_receive_ts_get_owd - Calculate one-way delay from timestamps
 * @state: Receive timestamps state
 * @sent_time: Time the packet was sent (local time)
 * @peer_recv_timestamp: Peer's receive timestamp (from ACK)
 *
 * Calculates one-way delay using the peer's reported receive timestamp.
 * Note: This requires clock synchronization for accurate results.
 *
 * Returns one-way delay in microseconds, or negative error.
 */
s64 tquic_receive_ts_get_owd(struct tquic_receive_ts_state *state,
			     ktime_t sent_time, u64 peer_recv_timestamp);

/*
 * =============================================================================
 * Timestamp Basis Management
 * =============================================================================
 */

/**
 * tquic_receive_ts_set_basis - Set the timestamp basis
 * @state: Receive timestamps state
 * @basis_time: Reference time point
 * @basis_pn: Packet number at basis time
 *
 * Sets the session-wide reference point for delta encoding.
 * Typically set when the first packet is received.
 */
void tquic_receive_ts_set_basis(struct tquic_receive_ts_state *state,
				ktime_t basis_time, u64 basis_pn);

/**
 * tquic_receive_ts_get_basis - Get the timestamp basis
 * @state: Receive timestamps state
 * @basis_time: Output: basis time
 * @basis_pn: Output: basis packet number
 *
 * Returns true if basis is set, false otherwise.
 */
bool tquic_receive_ts_get_basis(struct tquic_receive_ts_state *state,
				ktime_t *basis_time, u64 *basis_pn);

/*
 * =============================================================================
 * Statistics
 * =============================================================================
 */

/**
 * tquic_receive_ts_get_stats - Get receive timestamps statistics
 * @state: Receive timestamps state
 * @timestamps_sent: Output: timestamps sent in ACKs
 * @timestamps_received: Output: timestamps received from peer
 * @ring_utilization: Output: ring buffer utilization (0-100)
 */
void tquic_receive_ts_get_stats(struct tquic_receive_ts_state *state,
				u64 *timestamps_sent,
				u64 *timestamps_received,
				u32 *ring_utilization);

/*
 * =============================================================================
 * Module Init/Exit
 * =============================================================================
 */

/**
 * tquic_receive_ts_module_init - Initialize receive timestamps module
 */
int __init tquic_receive_ts_module_init(void);

/**
 * tquic_receive_ts_module_exit - Cleanup receive timestamps module
 */
void __exit tquic_receive_ts_module_exit(void);

#endif /* _TQUIC_RECEIVE_TIMESTAMPS_H */
