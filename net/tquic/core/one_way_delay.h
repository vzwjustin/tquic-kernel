/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: One-Way Delay Measurement Extension Header
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Implementation of draft-huitema-quic-1wd (One-Way Delay Measurement)
 * for QUIC. This extension enables accurate measurement of one-way delays
 * by embedding timestamps in ACK frames.
 *
 * Key features:
 * - ACK_1WD frame type (0x1a02) with timestamp for one-way delay measurement
 * - ACK_1WD_ECN frame type (0x1a03) with ECN counts and timestamp
 * - Clock skew estimation and compensation
 * - Integration with RTT estimation for improved accuracy
 * - Support for asymmetric link detection in multipath scenarios
 */

#ifndef _TQUIC_ONE_WAY_DELAY_H
#define _TQUIC_ONE_WAY_DELAY_H

#include <linux/types.h>
#include <linux/ktime.h>
#include <linux/spinlock.h>
#include <linux/list.h>

/*
 * Frame Types (draft-huitema-quic-1wd)
 *
 * ACK_1WD frames include a timestamp field that indicates the time at which
 * the largest acknowledged packet was received. This enables the sender to
 * calculate the one-way delay from sender to receiver.
 */
#define TQUIC_FRAME_ACK_1WD		0x1a02ULL
#define TQUIC_FRAME_ACK_1WD_ECN		0x1a03ULL

/*
 * Transport Parameter (draft-huitema-quic-1wd)
 *
 * enable_one_way_delay (0xff02de1a):
 * Indicates the endpoint is willing to receive ACK_1WD frames.
 * Value is a varint representing the timestamp resolution in microseconds.
 * A value of 0 means the extension is disabled.
 */
#define TQUIC_TP_ENABLE_ONE_WAY_DELAY	0xff02de1aULL

/*
 * Default and limit values
 */
#define TQUIC_OWD_DEFAULT_RESOLUTION_US		1000	/* 1ms default resolution */
#define TQUIC_OWD_MIN_RESOLUTION_US		1	/* 1 microsecond minimum */
#define TQUIC_OWD_MAX_RESOLUTION_US		1000000	/* 1 second maximum */

/* Maximum clock skew we'll attempt to compensate (10 seconds) */
#define TQUIC_OWD_MAX_CLOCK_SKEW_US		10000000ULL

/* Number of samples for clock skew estimation */
#define TQUIC_OWD_SKEW_SAMPLE_COUNT		16

/* Minimum samples needed before using OWD estimates */
#define TQUIC_OWD_MIN_SAMPLES			4

/* OWD smoothing factor (alpha = 1/8 = 0.125 for EWMA) */
#define TQUIC_OWD_ALPHA_SHIFT			3

/* Maximum OWD values array size for history tracking */
#define TQUIC_OWD_HISTORY_SIZE			32

/* Forward declarations */
struct tquic_connection;
struct tquic_path;
struct tquic_loss_state;

/**
 * enum tquic_owd_state_flags - State flags for OWD measurement
 * @TQUIC_OWD_FLAG_ENABLED: OWD measurement is negotiated and enabled
 * @TQUIC_OWD_FLAG_ACTIVE: Actively collecting OWD samples
 * @TQUIC_OWD_FLAG_SKEW_VALID: Clock skew estimate is valid
 * @TQUIC_OWD_FLAG_FORWARD_VALID: Forward delay estimate is valid
 * @TQUIC_OWD_FLAG_REVERSE_VALID: Reverse delay estimate is valid
 * @TQUIC_OWD_FLAG_ASYMMETRIC: Detected asymmetric link
 */
enum tquic_owd_state_flags {
	TQUIC_OWD_FLAG_ENABLED		= BIT(0),
	TQUIC_OWD_FLAG_ACTIVE		= BIT(1),
	TQUIC_OWD_FLAG_SKEW_VALID	= BIT(2),
	TQUIC_OWD_FLAG_FORWARD_VALID	= BIT(3),
	TQUIC_OWD_FLAG_REVERSE_VALID	= BIT(4),
	TQUIC_OWD_FLAG_ASYMMETRIC	= BIT(5),
};

/**
 * struct tquic_owd_sample - Single OWD measurement sample
 * @timestamp: Timestamp when sample was collected (ktime)
 * @forward_delay_us: Measured forward one-way delay (us)
 * @reverse_delay_us: Measured reverse one-way delay (us)
 * @rtt_us: Corresponding RTT measurement (us)
 * @pn: Packet number this sample corresponds to
 * @valid: Whether this sample is valid
 */
struct tquic_owd_sample {
	ktime_t timestamp;
	s64 forward_delay_us;
	s64 reverse_delay_us;
	u64 rtt_us;
	u64 pn;
	bool valid;
};

/**
 * struct tquic_owd_timestamp_record - Sent packet timestamp record
 * @node: RB-tree node for lookup by packet number
 * @list: List node for time-based cleanup
 * @pn: Packet number
 * @send_time: Time when packet was sent
 * @path_id: Path the packet was sent on
 */
struct tquic_owd_timestamp_record {
	struct rb_node node;
	struct list_head list;
	u64 pn;
	ktime_t send_time;
	u32 path_id;
};

/**
 * struct tquic_owd_skew_estimator - Clock skew estimation state
 * @samples: Array of clock offset samples
 * @sample_count: Number of samples collected
 * @sample_idx: Current sample index (circular buffer)
 * @estimated_skew_us: Estimated clock skew (remote - local)
 * @skew_variance_us: Variance of clock skew estimate
 * @last_update: Time of last skew update
 * @stable: Whether the skew estimate has stabilized
 */
struct tquic_owd_skew_estimator {
	s64 samples[TQUIC_OWD_SKEW_SAMPLE_COUNT];
	u32 sample_count;
	u32 sample_idx;
	s64 estimated_skew_us;
	u64 skew_variance_us;
	ktime_t last_update;
	bool stable;
};

/**
 * struct tquic_owd_state - Per-connection one-way delay state
 * @flags: State flags (enum tquic_owd_state_flags)
 * @local_resolution_us: Our timestamp resolution in microseconds
 * @peer_resolution_us: Peer's timestamp resolution in microseconds
 * @effective_resolution_us: Negotiated effective resolution
 * @forward_delay_us: Smoothed forward one-way delay estimate (us)
 * @reverse_delay_us: Smoothed reverse one-way delay estimate (us)
 * @forward_delay_var_us: Forward delay variance (us)
 * @reverse_delay_var_us: Reverse delay variance (us)
 * @min_forward_us: Minimum observed forward delay (us)
 * @min_reverse_us: Minimum observed reverse delay (us)
 * @skew: Clock skew estimator state
 * @history: Recent OWD samples for analysis
 * @history_idx: Current index in history buffer
 * @sample_count: Total number of samples collected
 * @ts_records_root: RB-tree root for timestamp records
 * @ts_records_list: List of timestamp records (for cleanup)
 * @ts_records_count: Number of active timestamp records
 * @reference_time: Reference time for timestamp calculations
 * @last_send_ts: Timestamp included in last sent ACK_1WD
 * @last_recv_ts: Timestamp from last received ACK_1WD
 * @lock: Spinlock for state protection
 */
struct tquic_owd_state {
	/* Negotiation state */
	u32 flags;
	u64 local_resolution_us;
	u64 peer_resolution_us;
	u64 effective_resolution_us;

	/* One-way delay estimates (microseconds) */
	s64 forward_delay_us;
	s64 reverse_delay_us;
	u64 forward_delay_var_us;
	u64 reverse_delay_var_us;
	s64 min_forward_us;
	s64 min_reverse_us;

	/* Clock skew estimation */
	struct tquic_owd_skew_estimator skew;

	/* Sample history */
	struct tquic_owd_sample history[TQUIC_OWD_HISTORY_SIZE];
	u32 history_idx;
	u64 sample_count;

	/* Timestamp records for sent packets */
	struct rb_root ts_records_root;
	struct list_head ts_records_list;
	u32 ts_records_count;

	/* Timestamp management */
	ktime_t reference_time;
	u64 last_send_ts;
	u64 last_recv_ts;

	/* Synchronization */
	spinlock_t lock;
};

/**
 * struct tquic_ack_1wd_frame - Parsed ACK_1WD frame
 * @largest_acked: Largest acknowledged packet number
 * @ack_delay: ACK delay in microseconds
 * @first_range: Size of first ACK range
 * @ranges: Array of additional ACK ranges
 * @range_count: Number of additional ranges
 * @ecn: ECN counts (if ACK_1WD_ECN)
 * @has_ecn: Whether ECN counts are present
 * @receive_timestamp: Timestamp when largest_acked was received
 */
struct tquic_ack_1wd_frame {
	u64 largest_acked;
	u64 ack_delay;
	u64 first_range;
	struct {
		u64 gap;
		u64 length;
	} ranges[256];  /* TQUIC_MAX_ACK_RANGES */
	u32 range_count;
	struct {
		u64 ect0;
		u64 ect1;
		u64 ce;
	} ecn;
	bool has_ecn;
	u64 receive_timestamp;
};

/**
 * struct tquic_owd_path_info - Per-path OWD information for scheduler
 * @path_id: Path identifier
 * @forward_delay_us: Forward one-way delay in microseconds
 * @reverse_delay_us: Reverse one-way delay in microseconds
 * @asymmetry_ratio: Ratio of forward/reverse delay (scaled by 1000)
 * @is_asymmetric: Whether path has significant asymmetry
 * @confidence: Confidence level in estimates (0-100)
 */
struct tquic_owd_path_info {
	u32 path_id;
	s64 forward_delay_us;
	s64 reverse_delay_us;
	u32 asymmetry_ratio;
	bool is_asymmetric;
	u8 confidence;
};

/*
 * =============================================================================
 * Core OWD State Management API
 * =============================================================================
 */

/**
 * tquic_owd_state_create - Create OWD measurement state for a connection
 * @conn: Connection to create state for
 *
 * Allocates and initializes one-way delay measurement state.
 * The state is not enabled until transport parameters are negotiated.
 *
 * Returns: Allocated OWD state, or NULL on failure
 */
struct tquic_owd_state *tquic_owd_state_create(struct tquic_connection *conn);

/**
 * tquic_owd_state_destroy - Destroy OWD measurement state
 * @owd: OWD state to destroy (may be NULL)
 */
void tquic_owd_state_destroy(struct tquic_owd_state *owd);

/**
 * tquic_owd_init - Initialize OWD state for a connection
 * @owd: OWD state to initialize
 * @local_resolution_us: Local timestamp resolution in microseconds
 *
 * Initializes OWD state with the local resolution. Called during
 * transport parameter setup before negotiation.
 *
 * Returns: 0 on success, negative error code on failure
 */
int tquic_owd_init(struct tquic_owd_state *owd, u64 local_resolution_us);

/**
 * tquic_owd_enable - Enable OWD measurement after negotiation
 * @owd: OWD state
 * @peer_resolution_us: Peer's advertised timestamp resolution
 *
 * Called when transport parameters are received and both endpoints
 * support the one-way delay extension.
 *
 * Returns: 0 on success, negative error code on failure
 */
int tquic_owd_enable(struct tquic_owd_state *owd, u64 peer_resolution_us);

/**
 * tquic_owd_reset - Reset OWD state (e.g., for connection migration)
 * @owd: OWD state to reset
 *
 * Resets all OWD measurements while keeping the negotiated parameters.
 */
void tquic_owd_reset(struct tquic_owd_state *owd);

/*
 * =============================================================================
 * ACK_1WD Frame Generation and Parsing
 * =============================================================================
 */

/**
 * tquic_owd_encode_ack_timestamp - Encode timestamp for ACK_1WD frame
 * @owd: OWD state
 * @recv_time: Time when the packet being acknowledged was received
 * @buf: Output buffer
 * @buf_len: Buffer length
 *
 * Encodes the receive timestamp in the format expected by ACK_1WD frames.
 * The timestamp is relative to the connection's reference time.
 *
 * Returns: Number of bytes written, or negative error code
 */
int tquic_owd_encode_ack_timestamp(struct tquic_owd_state *owd,
				   ktime_t recv_time,
				   u8 *buf, size_t buf_len);

/**
 * tquic_owd_decode_ack_timestamp - Decode timestamp from ACK_1WD frame
 * @owd: OWD state
 * @buf: Input buffer containing timestamp
 * @buf_len: Buffer length
 * @recv_timestamp: Output decoded timestamp (relative units)
 *
 * Decodes the receive timestamp from an ACK_1WD frame.
 *
 * Returns: Number of bytes consumed, or negative error code
 */
int tquic_owd_decode_ack_timestamp(struct tquic_owd_state *owd,
				   const u8 *buf, size_t buf_len,
				   u64 *recv_timestamp);

/**
 * tquic_owd_generate_ack_1wd - Generate complete ACK_1WD frame
 * @owd: OWD state
 * @loss: Loss state (for ACK ranges)
 * @pn_space: Packet number space
 * @buf: Output buffer
 * @buf_len: Buffer length
 * @include_ecn: Whether to generate ACK_1WD_ECN
 * @recv_time: Time the largest packet was received
 *
 * Generates a complete ACK_1WD or ACK_1WD_ECN frame.
 *
 * Returns: Number of bytes written, or negative error code
 */
int tquic_owd_generate_ack_1wd(struct tquic_owd_state *owd,
			       struct tquic_loss_state *loss,
			       int pn_space, u8 *buf, size_t buf_len,
			       bool include_ecn, ktime_t recv_time);

/**
 * tquic_owd_parse_ack_1wd - Parse ACK_1WD frame from wire format
 * @buf: Input buffer
 * @len: Buffer length
 * @frame: Output parsed frame
 * @ack_delay_exponent: ACK delay exponent
 *
 * Returns: Number of bytes consumed, or negative error code
 */
int tquic_owd_parse_ack_1wd(const u8 *buf, size_t len,
			    struct tquic_ack_1wd_frame *frame,
			    u8 ack_delay_exponent);

/*
 * =============================================================================
 * One-Way Delay Calculation
 * =============================================================================
 */

/**
 * tquic_owd_on_packet_sent - Record timestamp for sent packet
 * @owd: OWD state
 * @pn: Packet number
 * @send_time: Time the packet was sent
 * @path_id: Path the packet was sent on
 *
 * Records the send timestamp for a packet to enable OWD calculation
 * when the corresponding ACK_1WD is received.
 *
 * Returns: 0 on success, negative error code on failure
 */
int tquic_owd_on_packet_sent(struct tquic_owd_state *owd, u64 pn,
			     ktime_t send_time, u32 path_id);

/**
 * tquic_owd_on_ack_1wd_received - Process received ACK_1WD frame
 * @owd: OWD state
 * @frame: Parsed ACK_1WD frame
 * @recv_time: Time the ACK_1WD was received
 * @path: Path the ACK was received on
 *
 * Processes the ACK_1WD frame to calculate and update OWD estimates.
 *
 * Returns: 0 on success, negative error code on failure
 */
int tquic_owd_on_ack_1wd_received(struct tquic_owd_state *owd,
				  const struct tquic_ack_1wd_frame *frame,
				  ktime_t recv_time,
				  struct tquic_path *path);

/**
 * tquic_owd_calculate - Calculate one-way delays from ACK_1WD
 * @owd: OWD state
 * @send_time: Time the acked packet was sent
 * @remote_recv_ts: Remote receive timestamp from ACK_1WD
 * @ack_recv_time: Time the ACK_1WD was received
 * @sample: Output OWD sample
 *
 * Calculates forward and reverse one-way delays using the timestamps.
 * Accounts for clock skew if a valid estimate is available.
 *
 * Forward delay = (remote_recv_ts - skew) - send_time
 * Reverse delay = ack_recv_time - (remote_recv_ts - skew)
 *
 * Returns: 0 on success, negative error code on failure
 */
int tquic_owd_calculate(struct tquic_owd_state *owd,
			ktime_t send_time, u64 remote_recv_ts,
			ktime_t ack_recv_time,
			struct tquic_owd_sample *sample);

/*
 * =============================================================================
 * Clock Skew Estimation
 * =============================================================================
 */

/**
 * tquic_owd_update_skew - Update clock skew estimate
 * @owd: OWD state
 * @local_time: Local timestamp
 * @remote_time_us: Remote timestamp in microseconds
 * @rtt_us: Current RTT measurement in microseconds
 *
 * Updates the clock skew estimate using a new timing sample.
 * Uses the minimum offset method to filter out queuing delays.
 */
void tquic_owd_update_skew(struct tquic_owd_state *owd,
			   ktime_t local_time, u64 remote_time_us,
			   u64 rtt_us);

/**
 * tquic_owd_get_skew - Get current clock skew estimate
 * @owd: OWD state
 * @skew_us: Output clock skew in microseconds (remote - local)
 *
 * Returns: true if a valid skew estimate is available
 */
bool tquic_owd_get_skew(const struct tquic_owd_state *owd, s64 *skew_us);

/*
 * =============================================================================
 * OWD Query API
 * =============================================================================
 */

/**
 * tquic_owd_get_forward_delay - Get forward one-way delay estimate
 * @owd: OWD state
 * @delay_us: Output forward delay in microseconds
 *
 * Returns the smoothed forward (sender to receiver) one-way delay.
 *
 * Returns: true if a valid estimate is available
 */
bool tquic_owd_get_forward_delay(const struct tquic_owd_state *owd,
				 s64 *delay_us);

/**
 * tquic_owd_get_reverse_delay - Get reverse one-way delay estimate
 * @owd: OWD state
 * @delay_us: Output reverse delay in microseconds
 *
 * Returns the smoothed reverse (receiver to sender) one-way delay.
 *
 * Returns: true if a valid estimate is available
 */
bool tquic_owd_get_reverse_delay(const struct tquic_owd_state *owd,
				 s64 *delay_us);

/**
 * tquic_owd_get_delays - Get both one-way delay estimates
 * @owd: OWD state
 * @forward_us: Output forward delay in microseconds
 * @reverse_us: Output reverse delay in microseconds
 *
 * Returns: true if valid estimates are available for both directions
 */
bool tquic_owd_get_delays(const struct tquic_owd_state *owd,
			  s64 *forward_us, s64 *reverse_us);

/**
 * tquic_owd_get_min_delays - Get minimum observed one-way delays
 * @owd: OWD state
 * @min_forward_us: Output minimum forward delay
 * @min_reverse_us: Output minimum reverse delay
 *
 * Returns the minimum observed delays, which are useful for
 * detecting baseline path characteristics.
 *
 * Returns: true if valid measurements are available
 */
bool tquic_owd_get_min_delays(const struct tquic_owd_state *owd,
			      s64 *min_forward_us, s64 *min_reverse_us);

/**
 * tquic_owd_is_asymmetric - Check if path shows significant asymmetry
 * @owd: OWD state
 * @threshold_pct: Threshold percentage for asymmetry detection
 *
 * Returns true if the difference between forward and reverse delays
 * exceeds the threshold percentage of the RTT.
 */
bool tquic_owd_is_asymmetric(const struct tquic_owd_state *owd,
			     u32 threshold_pct);

/**
 * tquic_owd_get_asymmetry_ratio - Get asymmetry ratio
 * @owd: OWD state
 *
 * Returns the ratio of forward/reverse delay scaled by 1000.
 * A value of 1000 indicates symmetric path.
 * Values > 1000 indicate forward-heavy asymmetry.
 * Values < 1000 indicate reverse-heavy asymmetry.
 *
 * Returns: Asymmetry ratio, or 1000 if estimates unavailable
 */
u32 tquic_owd_get_asymmetry_ratio(const struct tquic_owd_state *owd);

/*
 * =============================================================================
 * Multipath Scheduler Integration
 * =============================================================================
 */

/**
 * tquic_owd_get_path_info - Get OWD information for path scheduling
 * @owd: OWD state
 * @path: Path to get information for
 * @info: Output path information structure
 *
 * Fills in OWD-related path information for use by the scheduler.
 *
 * Returns: 0 on success, negative error code on failure
 */
int tquic_owd_get_path_info(struct tquic_owd_state *owd,
			    struct tquic_path *path,
			    struct tquic_owd_path_info *info);

/**
 * tquic_owd_compare_paths - Compare paths based on OWD characteristics
 * @owd: OWD state
 * @path_a: First path
 * @path_b: Second path
 * @prefer_forward: True to optimize for forward delay (uploads)
 *
 * Compares two paths based on their one-way delay characteristics.
 *
 * Returns: Negative if path_a is better, positive if path_b is better,
 *          0 if paths are equivalent
 */
int tquic_owd_compare_paths(struct tquic_owd_state *owd,
			    struct tquic_path *path_a,
			    struct tquic_path *path_b,
			    bool prefer_forward);

/*
 * =============================================================================
 * RTT Integration
 * =============================================================================
 */

/**
 * tquic_owd_update_from_rtt - Update OWD state using RTT measurement
 * @owd: OWD state
 * @rtt_us: RTT measurement in microseconds
 *
 * When OWD measurements are unavailable, use RTT/2 as approximation
 * and validate OWD estimates against RTT bounds.
 */
void tquic_owd_update_from_rtt(struct tquic_owd_state *owd, u64 rtt_us);

/**
 * tquic_owd_validate_against_rtt - Validate OWD estimates against RTT
 * @owd: OWD state
 * @rtt_us: Current RTT measurement
 *
 * Validates that forward + reverse OWD approximately equals RTT.
 * Marks estimates invalid if they diverge significantly.
 *
 * Returns: true if OWD estimates are consistent with RTT
 */
bool tquic_owd_validate_against_rtt(struct tquic_owd_state *owd, u64 rtt_us);

/*
 * =============================================================================
 * Statistics and Debugging
 * =============================================================================
 */

/**
 * tquic_owd_get_statistics - Get OWD measurement statistics
 * @owd: OWD state
 * @sample_count: Output total samples collected
 * @forward_var_us: Output forward delay variance
 * @reverse_var_us: Output reverse delay variance
 */
void tquic_owd_get_statistics(const struct tquic_owd_state *owd,
			      u64 *sample_count,
			      u64 *forward_var_us,
			      u64 *reverse_var_us);

/**
 * tquic_owd_get_recent_sample - Get most recent OWD sample
 * @owd: OWD state
 * @sample: Output sample
 *
 * Returns: true if a recent sample is available
 */
bool tquic_owd_get_recent_sample(const struct tquic_owd_state *owd,
				 struct tquic_owd_sample *sample);

/**
 * tquic_owd_debug_print - Print OWD state for debugging
 * @owd: OWD state
 * @prefix: Log message prefix
 */
void tquic_owd_debug_print(const struct tquic_owd_state *owd,
			   const char *prefix);

/*
 * =============================================================================
 * Module Initialization
 * =============================================================================
 */

/**
 * tquic_owd_module_init - Initialize OWD measurement module
 *
 * Returns: 0 on success, negative error code on failure
 */
int __init tquic_owd_module_init(void);

/**
 * tquic_owd_module_exit - Cleanup OWD measurement module
 */
void __exit tquic_owd_module_exit(void);

/*
 * =============================================================================
 * Inline Helpers
 * =============================================================================
 */

/**
 * tquic_owd_is_enabled - Check if OWD measurement is enabled
 * @owd: OWD state (may be NULL)
 *
 * Returns: true if OWD is enabled and active
 */
static inline bool tquic_owd_is_enabled(const struct tquic_owd_state *owd)
{
	return owd && (owd->flags & TQUIC_OWD_FLAG_ENABLED);
}

/**
 * tquic_owd_has_valid_estimates - Check if OWD estimates are valid
 * @owd: OWD state (may be NULL)
 *
 * Returns: true if both forward and reverse estimates are valid
 */
static inline bool tquic_owd_has_valid_estimates(const struct tquic_owd_state *owd)
{
	if (!owd)
		return false;
	return (owd->flags & TQUIC_OWD_FLAG_FORWARD_VALID) &&
	       (owd->flags & TQUIC_OWD_FLAG_REVERSE_VALID);
}

/**
 * tquic_owd_ktime_to_timestamp - Convert ktime to OWD timestamp
 * @owd: OWD state
 * @time: Time to convert
 *
 * Converts a ktime value to the timestamp format used in ACK_1WD frames.
 * The timestamp is relative to the reference time and scaled by resolution.
 *
 * Returns: Timestamp value for wire format
 */
static inline u64 tquic_owd_ktime_to_timestamp(const struct tquic_owd_state *owd,
					       ktime_t time)
{
	s64 delta_us;

	if (!owd || owd->effective_resolution_us == 0)
		return 0;

	delta_us = ktime_us_delta(time, owd->reference_time);
	if (delta_us < 0)
		delta_us = 0;

	return (u64)delta_us / owd->effective_resolution_us;
}

/**
 * tquic_owd_timestamp_to_us - Convert OWD timestamp to microseconds
 * @owd: OWD state
 * @timestamp: Timestamp from ACK_1WD frame
 *
 * Converts a timestamp from ACK_1WD format to microseconds relative
 * to the reference time.
 *
 * Returns: Microseconds since reference time
 */
static inline s64 tquic_owd_timestamp_to_us(const struct tquic_owd_state *owd,
					    u64 timestamp)
{
	if (!owd || owd->effective_resolution_us == 0)
		return 0;

	return (s64)timestamp * owd->effective_resolution_us;
}

#endif /* _TQUIC_ONE_WAY_DELAY_H */
