/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: Deadline-Aware Multipath Scheduling
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Implementation of Deadline-Aware Multipath Transport Protocol (DMTP)
 * based on draft-tjohn-quic-multipath-dmtp-01.
 *
 * This provides deadline-aware packet scheduling for real-time applications
 * using QUIC multipath, enabling QoS guarantees for time-sensitive traffic.
 */

#ifndef _TQUIC_DEADLINE_AWARE_H
#define _TQUIC_DEADLINE_AWARE_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/spinlock.h>
#include <linux/ktime.h>
#include <net/tquic.h>

/*
 * Transport Parameters (draft-tjohn-quic-multipath-dmtp-01)
 *
 * These parameters are negotiated during the QUIC handshake to enable
 * deadline-aware scheduling between endpoints.
 */

/* Transport parameter IDs for deadline-aware scheduling */
#define TQUIC_TP_ENABLE_DEADLINE_AWARE		0x0f10	/* Enable deadline scheduling */
#define TQUIC_TP_DEADLINE_GRANULARITY		0x0f11	/* Deadline time granularity */
#define TQUIC_TP_MAX_DEADLINE_STREAMS		0x0f12	/* Max deadline-aware streams */
#define TQUIC_TP_DEADLINE_MISS_POLICY		0x0f13	/* Policy for missed deadlines */

/*
 * Deadline granularity values (in microseconds)
 *
 * Defines the resolution at which deadlines are specified.
 * Finer granularity enables more precise scheduling but increases overhead.
 */
#define TQUIC_DEADLINE_GRANULARITY_MS		1000	/* 1 ms (default) */
#define TQUIC_DEADLINE_GRANULARITY_100US	100	/* 100 us (high precision) */
#define TQUIC_DEADLINE_GRANULARITY_US		1	/* 1 us (ultra precision) */

/*
 * Deadline miss policy values
 *
 * Defines behavior when a packet's deadline cannot be met.
 */
#define TQUIC_DEADLINE_MISS_DROP		0	/* Drop data if deadline missed */
#define TQUIC_DEADLINE_MISS_BEST_EFFORT		1	/* Deliver with best effort */
#define TQUIC_DEADLINE_MISS_NOTIFY		2	/* Notify and let app decide */
#define TQUIC_DEADLINE_MISS_DEGRADE		3	/* Degrade to lower priority */

/*
 * Frame Extensions
 *
 * STREAM_DEADLINE frame type for communicating deadline requirements.
 */

/* STREAM_DEADLINE frame type (0x15c10 in draft) */
#define TQUIC_FRAME_STREAM_DEADLINE		0x15c10

/* DEADLINE_ACK frame for acknowledging deadline-aware packets */
#define TQUIC_FRAME_DEADLINE_ACK		0x15c11

/* DEADLINE_MISS frame to signal deadline misses */
#define TQUIC_FRAME_DEADLINE_MISS		0x15c12

/*
 * Maximum values
 */
#define TQUIC_MAX_DEADLINE_STREAMS		256	/* Max deadline-tracked streams */
#define TQUIC_MAX_DEADLINE_US			(60 * 1000000ULL)  /* 60 seconds max */
#define TQUIC_MIN_DEADLINE_US			100	/* 100 us minimum */
#define TQUIC_DEFAULT_DEADLINE_US		(50 * 1000)	/* 50 ms default */

/*
 * Priority levels for deadline scheduling
 */
#define TQUIC_DEADLINE_PRIO_CRITICAL		0	/* Hard real-time */
#define TQUIC_DEADLINE_PRIO_HIGH		1	/* Soft real-time */
#define TQUIC_DEADLINE_PRIO_NORMAL		2	/* Normal priority */
#define TQUIC_DEADLINE_PRIO_LOW			3	/* Background */
#define TQUIC_DEADLINE_PRIO_LEVELS		4

/**
 * struct tquic_stream_deadline - Per-stream deadline information
 * @stream_id: Associated stream ID
 * @deadline_us: Absolute deadline (ktime in microseconds)
 * @relative_deadline_us: Relative deadline from creation time
 * @creation_time: When the deadline was set
 * @priority: Deadline priority level
 * @miss_policy: Policy when deadline is missed
 * @slack_us: Allowed slack time (for jitter tolerance)
 * @data_offset: Offset of data covered by this deadline
 * @data_length: Length of data covered by this deadline
 * @node: RB-tree node for deadline ordering
 * @stream_node: List node for per-stream deadline list
 * @flags: Deadline flags
 * @feasible: Whether deadline is currently feasible
 * @miss_count: Number of deadline misses for this stream
 * @hit_count: Number of deadline hits
 * @avg_latency_us: Average delivery latency
 */
struct tquic_stream_deadline {
	u64 stream_id;
	ktime_t deadline;		/* Absolute deadline */
	u64 relative_deadline_us;	/* Relative from creation */
	ktime_t creation_time;
	u8 priority;
	u8 miss_policy;
	u32 slack_us;
	u64 data_offset;
	u64 data_length;

	struct rb_node node;		/* EDF ordering in scheduler */
	struct list_head list;		/* Scheduler-level deadline list */
	struct list_head stream_node;	/* Per-stream deadline list */

	u32 flags;
	bool feasible;

	/* Statistics */
	u64 miss_count;
	u64 hit_count;
	u64 avg_latency_us;
};

/* Deadline flags */
#define TQUIC_DEADLINE_FLAG_ACTIVE		(1 << 0)  /* Deadline is active */
#define TQUIC_DEADLINE_FLAG_PENDING		(1 << 1)  /* Data pending */
#define TQUIC_DEADLINE_FLAG_MISSED		(1 << 2)  /* Deadline was missed */
#define TQUIC_DEADLINE_FLAG_DELIVERED		(1 << 3)  /* Data delivered */
#define TQUIC_DEADLINE_FLAG_DROPPED		(1 << 4)  /* Data was dropped */
#define TQUIC_DEADLINE_FLAG_RETRANSMIT		(1 << 5)  /* Needs retransmit */

/**
 * struct tquic_path_deadline_caps - Per-path deadline capabilities
 * @path: Associated path
 * @min_feasible_deadline_us: Minimum feasible deadline on this path
 * @max_jitter_us: Maximum observed jitter
 * @deadline_support: Whether path supports deadline scheduling
 * @estimated_capacity_bps: Estimated path capacity in bits/sec
 * @utilization: Current path utilization (0-100)
 * @avg_rtt_us: Average RTT on this path
 * @rtt_variance_us: RTT variance (jitter indicator)
 * @pending_deadline_bytes: Bytes pending with deadlines
 * @list: Connection's path capabilities list
 */
struct tquic_path_deadline_caps {
	struct tquic_path *path;
	u64 min_feasible_deadline_us;
	u64 max_jitter_us;
	bool deadline_support;
	u64 estimated_capacity_bps;
	u8 utilization;
	u64 avg_rtt_us;
	u64 rtt_variance_us;
	u64 pending_deadline_bytes;
	struct list_head list;
};

/**
 * struct tquic_deadline_sched_state - Scheduler state for deadline-awareness
 * @conn: Associated connection
 * @enabled: Deadline scheduling enabled
 * @granularity_us: Time granularity in microseconds
 * @miss_policy: Default miss policy
 * @deadline_tree: RB-tree of active deadlines (EDF ordered)
 * @deadline_count: Number of active deadlines
 * @streams_with_deadlines: Streams with active deadlines
 * @path_caps: List of per-path capabilities
 * @lock: Scheduler lock
 * @scheduler_timer: Timer for deadline checks
 * @work: Work item for deferred processing
 * @stats: Scheduler statistics
 * @integration: Integration with base schedulers
 */
struct tquic_deadline_sched_state {
	struct tquic_connection *conn;
	bool enabled;
	u32 granularity_us;
	u8 miss_policy;

	/* EDF deadline tree - sorted by absolute deadline */
	struct rb_root deadline_tree;
	u32 deadline_count;
	u32 max_deadline_streams;

	/* Stream tracking */
	struct list_head streams_with_deadlines;

	/* Path capabilities */
	struct list_head path_caps;

	spinlock_t lock;
	struct timer_list scheduler_timer;
	struct work_struct work;

	/* Statistics */
	struct {
		u64 total_deadlines;
		u64 deadlines_met;
		u64 deadlines_missed;
		u64 packets_scheduled;
		u64 packets_dropped;
		u64 path_switches;
		u64 infeasible_count;
		ktime_t last_schedule_time;
	} stats;

	/* Base scheduler integration */
	struct {
		struct tquic_sched_ops *base_sched;
		void *base_state;
		bool ecf_fallback;	/* Fall back to ECF for non-deadline */
		bool blest_aware;	/* Use BLEST for blocking estimation */
	} integration;
};

/**
 * struct tquic_deadline_frame - STREAM_DEADLINE frame structure
 * @stream_id: Target stream ID
 * @deadline_us: Deadline in microseconds (relative to frame send time)
 * @priority: Deadline priority
 * @offset: Data offset this deadline applies to
 * @length: Data length covered by deadline
 * @flags: Frame flags
 *
 * STREAM_DEADLINE Frame {
 *   Type (i) = 0x15c10,
 *   Stream ID (i),
 *   Deadline (i),        // microseconds from now
 *   Priority (8),
 *   Offset (i),
 *   Length (i),
 *   Flags (8),
 * }
 */
struct tquic_deadline_frame {
	u64 stream_id;
	u64 deadline_us;
	u8 priority;
	u64 offset;
	u64 length;
	u8 flags;
};

/* Frame flags */
#define TQUIC_DEADLINE_FRAME_FLAG_URGENT	(1 << 0)
#define TQUIC_DEADLINE_FRAME_FLAG_ALLOW_DROP	(1 << 1)
#define TQUIC_DEADLINE_FRAME_FLAG_PERIODIC	(1 << 2)

/**
 * struct tquic_deadline_ack_frame - DEADLINE_ACK frame structure
 * @stream_id: Stream that was acknowledged
 * @offset: Data offset that met deadline
 * @delivery_time_us: Actual delivery time
 */
struct tquic_deadline_ack_frame {
	u64 stream_id;
	u64 offset;
	u64 delivery_time_us;
};

/**
 * struct tquic_deadline_miss_frame - DEADLINE_MISS frame structure
 * @stream_id: Stream that missed deadline
 * @offset: Data offset that missed
 * @miss_amount_us: How much the deadline was missed by
 * @reason: Reason code for miss
 */
struct tquic_deadline_miss_frame {
	u64 stream_id;
	u64 offset;
	u64 miss_amount_us;
	u8 reason;
};

/* Deadline miss reasons */
#define TQUIC_DEADLINE_MISS_CONGESTION		0x01
#define TQUIC_DEADLINE_MISS_PATH_FAILURE	0x02
#define TQUIC_DEADLINE_MISS_LOSS		0x03
#define TQUIC_DEADLINE_MISS_SCHEDULING		0x04
#define TQUIC_DEADLINE_MISS_INFEASIBLE		0x05

/**
 * struct tquic_deadline_params - Transport parameter structure
 * @enable_deadline_aware: Enable deadline scheduling
 * @deadline_granularity: Time granularity in microseconds
 * @max_deadline_streams: Maximum deadline-tracked streams
 * @miss_policy: Default deadline miss policy
 */
struct tquic_deadline_params {
	bool enable_deadline_aware;
	u32 deadline_granularity;
	u32 max_deadline_streams;
	u8 miss_policy;
};

/*
 * =============================================================================
 * Core Scheduler API
 * =============================================================================
 */

/**
 * tquic_deadline_sched_init - Initialize deadline scheduler for connection
 * @conn: Connection to initialize scheduler for
 * @params: Deadline parameters (from transport params negotiation)
 *
 * Allocates and initializes the deadline scheduler state. Must be called
 * after transport parameters have been negotiated and both endpoints
 * support deadline-aware scheduling.
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_deadline_sched_init(struct tquic_connection *conn,
			      const struct tquic_deadline_params *params);

/**
 * tquic_deadline_sched_release - Release deadline scheduler state
 * @conn: Connection to release scheduler for
 *
 * Frees all deadline scheduler resources. Any pending deadlines are
 * cancelled and statistics are logged.
 */
void tquic_deadline_sched_release(struct tquic_connection *conn);

/**
 * tquic_deadline_set_stream_deadline - Set deadline for stream data
 * @conn: Connection
 * @stream_id: Target stream
 * @deadline_us: Relative deadline in microseconds from now
 * @offset: Data offset deadline applies to
 * @length: Data length deadline covers
 * @priority: Deadline priority
 * @flags: Deadline flags
 *
 * Sets a deadline for the specified stream data. The scheduler will
 * attempt to ensure the data is delivered before the deadline.
 *
 * Returns: 0 on success, -ENOSPC if max deadlines reached,
 *          -EINVAL if deadline is infeasible
 */
int tquic_deadline_set_stream_deadline(struct tquic_connection *conn,
				       u64 stream_id,
				       u64 deadline_us,
				       u64 offset,
				       u64 length,
				       u8 priority,
				       u32 flags);

/**
 * tquic_deadline_cancel_stream_deadline - Cancel deadline for stream
 * @conn: Connection
 * @stream_id: Target stream
 * @offset: Data offset to cancel deadline for (0 for all)
 *
 * Cancels pending deadlines for the specified stream.
 *
 * Returns: Number of deadlines cancelled
 */
int tquic_deadline_cancel_stream_deadline(struct tquic_connection *conn,
					  u64 stream_id,
					  u64 offset);

/**
 * tquic_deadline_select_path - Select best path to meet deadline
 * @state: Scheduler state
 * @deadline: Deadline to meet
 * @data_len: Amount of data to send
 *
 * Selects the best path to meet the given deadline, considering:
 *   - Path RTT and jitter
 *   - Available bandwidth
 *   - Current congestion state
 *   - Other pending deadlines
 *
 * Returns: Selected path (referenced; caller must call tquic_path_put()),
 *          or NULL if no path can meet deadline
 */
struct tquic_path *tquic_deadline_select_path(
	struct tquic_deadline_sched_state *state,
	struct tquic_stream_deadline *deadline,
	size_t data_len);

/**
 * tquic_deadline_schedule_packet - Schedule packet with deadline awareness
 * @state: Scheduler state
 * @skb: Packet to schedule
 * @stream_id: Stream ID (0 for non-stream data)
 *
 * Main entry point for deadline-aware packet scheduling. Determines
 * the best path and priority for the packet based on active deadlines.
 *
 * Returns: Selected path (referenced; caller must call tquic_path_put()),
 *          or NULL if scheduling failed
 */
struct tquic_path *tquic_deadline_schedule_packet(
	struct tquic_deadline_sched_state *state,
	struct sk_buff *skb,
	u64 stream_id);

/**
 * tquic_deadline_check_feasibility - Check if deadline is feasible
 * @state: Scheduler state
 * @deadline_us: Deadline in microseconds
 * @data_len: Amount of data
 * @path: Specific path (NULL for any path)
 *
 * Checks whether the given deadline can be met with current conditions.
 *
 * Returns: true if feasible, false otherwise
 */
bool tquic_deadline_check_feasibility(
	struct tquic_deadline_sched_state *state,
	u64 deadline_us,
	size_t data_len,
	struct tquic_path *path);

/*
 * =============================================================================
 * Statistics and Monitoring
 * =============================================================================
 */

/**
 * struct tquic_deadline_stats - Deadline scheduling statistics
 */
struct tquic_deadline_stats {
	u64 total_deadlines;
	u64 deadlines_met;
	u64 deadlines_missed;
	u64 packets_scheduled;
	u64 packets_dropped;
	u64 path_switches;
	u64 infeasible_count;
	u64 avg_delivery_time_us;
	u64 avg_slack_us;
	u64 max_lateness_us;
};

/**
 * tquic_deadline_get_stats - Get deadline scheduling statistics
 * @state: Scheduler state
 * @stats: Output statistics structure
 *
 * Returns: 0 on success
 */
int tquic_deadline_get_stats(struct tquic_deadline_sched_state *state,
			     struct tquic_deadline_stats *stats);

/*
 * =============================================================================
 * Frame Parsing and Generation
 * =============================================================================
 */

/**
 * tquic_deadline_parse_frame - Parse STREAM_DEADLINE frame
 * @buf: Input buffer
 * @len: Buffer length
 * @frame: Output frame structure
 *
 * Returns: Bytes consumed on success, negative error on failure
 */
int tquic_deadline_parse_frame(const u8 *buf, size_t len,
			       struct tquic_deadline_frame *frame);

/**
 * tquic_deadline_write_frame - Write STREAM_DEADLINE frame
 * @frame: Frame to write
 * @buf: Output buffer
 * @len: Buffer length
 *
 * Returns: Bytes written on success, negative error on failure
 */
int tquic_deadline_write_frame(const struct tquic_deadline_frame *frame,
			       u8 *buf, size_t len);

/**
 * tquic_deadline_frame_size - Calculate encoded frame size
 * @frame: Frame to measure
 *
 * Returns: Encoded size in bytes
 */
size_t tquic_deadline_frame_size(const struct tquic_deadline_frame *frame);

/**
 * tquic_deadline_parse_ack_frame - Parse DEADLINE_ACK frame
 */
int tquic_deadline_parse_ack_frame(const u8 *buf, size_t len,
				   struct tquic_deadline_ack_frame *frame);

/**
 * tquic_deadline_write_ack_frame - Write DEADLINE_ACK frame
 */
int tquic_deadline_write_ack_frame(const struct tquic_deadline_ack_frame *frame,
				   u8 *buf, size_t len);

/**
 * tquic_deadline_parse_miss_frame - Parse DEADLINE_MISS frame
 */
int tquic_deadline_parse_miss_frame(const u8 *buf, size_t len,
				    struct tquic_deadline_miss_frame *frame);

/**
 * tquic_deadline_write_miss_frame - Write DEADLINE_MISS frame
 */
int tquic_deadline_write_miss_frame(const struct tquic_deadline_miss_frame *frame,
				    u8 *buf, size_t len);

/*
 * =============================================================================
 * Event Handling
 * =============================================================================
 */

/**
 * tquic_deadline_on_ack - Handle ACK event for deadline tracking
 * @state: Scheduler state
 * @stream_id: Stream that was acknowledged
 * @offset: Acknowledged data offset
 * @ack_time: Time ACK was received
 */
void tquic_deadline_on_ack(struct tquic_deadline_sched_state *state,
			   u64 stream_id, u64 offset, ktime_t ack_time);

/**
 * tquic_deadline_on_loss - Handle loss event for deadline tracking
 * @state: Scheduler state
 * @stream_id: Stream with loss
 * @offset: Lost data offset
 */
void tquic_deadline_on_loss(struct tquic_deadline_sched_state *state,
			    u64 stream_id, u64 offset);

/**
 * tquic_deadline_on_path_change - Handle path state change
 * @state: Scheduler state
 * @path: Path that changed
 * @new_state: New path state
 */
void tquic_deadline_on_path_change(struct tquic_deadline_sched_state *state,
				   struct tquic_path *path,
				   enum tquic_path_state new_state);

/*
 * =============================================================================
 * Integration Helpers
 * =============================================================================
 */

/**
 * tquic_deadline_is_deadline_frame - Check if frame type is deadline-related
 * @frame_type: Frame type to check
 *
 * Returns: true if frame is deadline-related
 */
static inline bool tquic_deadline_is_deadline_frame(u64 frame_type)
{
	return frame_type == TQUIC_FRAME_STREAM_DEADLINE ||
	       frame_type == TQUIC_FRAME_DEADLINE_ACK ||
	       frame_type == TQUIC_FRAME_DEADLINE_MISS;
}

/**
 * tquic_deadline_get_state - Get deadline scheduler state from connection
 * @conn: Connection
 *
 * Returns: Scheduler state, or NULL if not enabled
 */
struct tquic_deadline_sched_state *tquic_deadline_get_state(
	struct tquic_connection *conn);

/*
 * =============================================================================
 * Module Initialization
 * =============================================================================
 */

/**
 * tquic_deadline_sched_module_init - Initialize deadline scheduler module
 */
int __init tquic_deadline_sched_module_init(void);

/**
 * tquic_deadline_sched_module_exit - Cleanup deadline scheduler module
 */
void __exit tquic_deadline_sched_module_exit(void);

#endif /* _TQUIC_DEADLINE_AWARE_H */
