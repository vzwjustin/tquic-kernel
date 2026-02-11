/* SPDX-License-Identifier: GPL-2.0 */
/*
 * TQUIC Qlog Internal Definitions
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Internal structures and functions for qlog tracing support.
 * Implements draft-ietf-quic-qlog-quic-events-12 event logging.
 */

#ifndef _NET_TQUIC_QLOG_H
#define _NET_TQUIC_QLOG_H

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/file.h>
#include <net/tquic.h>
#include <uapi/linux/tquic_qlog.h>

/* Forward declarations */
struct tquic_connection;
struct tquic_path;

/*
 * =============================================================================
 * Event Category Helpers (draft-12 Section 4)
 * =============================================================================
 */

/**
 * tquic_qlog_event_category - Get category for event type
 * @event: Event type
 *
 * Return: Category enum value for the event
 */
static inline u8 tquic_qlog_event_category(enum tquic_qlog_event event)
{
	if (event <= QLOG_CONNECTIVITY_PATH_UPDATED)
		return TQUIC_QLOG_CAT_CONNECTIVITY;
	if (event >= QLOG_TRANSPORT_VERSION_INFORMATION &&
	    event <= QLOG_TRANSPORT_DATA_MOVED)
		return TQUIC_QLOG_CAT_TRANSPORT;
	if (event >= QLOG_RECOVERY_PARAMETERS_SET &&
	    event <= QLOG_RECOVERY_ECN_STATE_UPDATED)
		return TQUIC_QLOG_CAT_RECOVERY;
	if (event >= QLOG_SECURITY_KEY_UPDATED &&
	    event <= QLOG_SECURITY_KEY_DISCARDED)
		return TQUIC_QLOG_CAT_SECURITY;
	return 0;
}

/**
 * tquic_qlog_event_severity - Get default severity for event type
 * @event: Event type
 *
 * Return: Default severity level for the event
 */
static inline u8 tquic_qlog_event_severity(enum tquic_qlog_event event)
{
	switch (event) {
	/* Core events - always logged */
	case QLOG_CONNECTIVITY_CONNECTION_STARTED:
	case QLOG_CONNECTIVITY_CONNECTION_CLOSED:
	case QLOG_TRANSPORT_PACKET_SENT:
	case QLOG_TRANSPORT_PACKET_RECEIVED:
	case QLOG_TRANSPORT_PACKET_DROPPED:
	case QLOG_RECOVERY_PACKET_LOST:
	case QLOG_SECURITY_KEY_UPDATED:
		return TQUIC_QLOG_SEV_CORE;

	/* Base events - commonly logged */
	case QLOG_CONNECTIVITY_PATH_UPDATED:
	case QLOG_TRANSPORT_PACKET_BUFFERED:
	case QLOG_RECOVERY_METRICS_UPDATED:
	case QLOG_RECOVERY_CONGESTION_STATE_UPDATED:
	case QLOG_RECOVERY_LOSS_TIMER_UPDATED:
		return TQUIC_QLOG_SEV_BASE;

	/* Extra events */
	case QLOG_CONNECTIVITY_CONNECTION_ID_UPDATED:
	case QLOG_CONNECTIVITY_SPIN_BIT_UPDATED:
	case QLOG_TRANSPORT_PACKETS_ACKED:
	case QLOG_RECOVERY_MARKED_FOR_RETRANSMIT:
	case QLOG_SECURITY_KEY_DISCARDED:
		return TQUIC_QLOG_SEV_EXTRA;

	/* Debug events */
	default:
		return TQUIC_QLOG_SEV_DEBUG;
	}
}

/*
 * =============================================================================
 * Qlog Context Structure
 * =============================================================================
 */

/**
 * struct tquic_qlog - Qlog context for a connection
 * @conn: Parent connection
 * @ring: Ring buffer for event storage
 * @ring_size: Number of entries in ring buffer
 * @ring_mask: Mask for ring index (ring_size - 1)
 * @head: Next write position
 * @tail: Next read position
 * @event_mask: Bitmask of enabled events
 * @severity_filter: Minimum severity to log
 * @mode: Output mode (disabled, ring, netlink)
 * @relay_to_userspace: Enable netlink relay
 * @lock: Protects ring buffer access
 * @stats: Event statistics
 * @refcnt: Reference counter
 *
 * The qlog context manages event capture and storage for a QUIC
 * connection. Events are stored in a lock-free ring buffer for
 * efficiency in the fast path.
 */
struct tquic_qlog {
	struct tquic_connection *conn;

	/* Ring buffer for events */
	struct tquic_qlog_event_entry *ring;
	u32 ring_size;
	u32 ring_mask;
	atomic_t head;
	atomic_t tail;

	/* Filtering */
	u64 event_mask;
	u8 severity_filter;

	/* Output mode */
	u32 mode;
	bool relay_to_userspace;

	/* Lock for concurrent access */
	spinlock_t lock;

	/* Statistics */
	struct tquic_qlog_stats stats;

	/* Reference counting */
	refcount_t refcnt;
};

/*
 * =============================================================================
 * Qlog Context Management
 * =============================================================================
 */

/**
 * tquic_qlog_create - Create qlog context for connection
 * @conn: Connection to attach qlog to
 * @args: Configuration from userspace
 *
 * Creates and initializes a qlog context. The context is attached
 * to the connection and will be freed when the connection closes.
 *
 * Return: Pointer to qlog context on success, ERR_PTR on failure
 */
struct tquic_qlog *tquic_qlog_create(struct tquic_connection *conn,
				     const struct tquic_qlog_args *args);

/**
 * tquic_qlog_destroy - Destroy qlog context
 * @qlog: Context to destroy
 *
 * Releases all resources associated with the qlog context.
 */
void tquic_qlog_destroy(struct tquic_qlog *qlog);

/**
 * tquic_qlog_get - Get reference to qlog context
 * @qlog: Context to reference
 *
 * Increments reference count.
 */
static inline void tquic_qlog_get(struct tquic_qlog *qlog)
{
	if (qlog)
		refcount_inc(&qlog->refcnt);
}

/**
 * tquic_qlog_put - Release reference to qlog context
 * @qlog: Context to release
 *
 * Decrements reference count, frees when it reaches zero.
 */
void tquic_qlog_put(struct tquic_qlog *qlog);

/**
 * tquic_qlog_enabled - Check if qlog is enabled for event
 * @qlog: Qlog context (may be NULL)
 * @event: Event type to check
 *
 * Return: true if qlog is enabled and event type is not filtered
 */
static inline bool tquic_qlog_enabled(struct tquic_qlog *qlog,
				      enum tquic_qlog_event event)
{
	if (!qlog || qlog->mode == TQUIC_QLOG_MODE_DISABLED)
		return false;
	if (!(qlog->event_mask & QLOG_EVENT_BIT(event)))
		return false;
	if (tquic_qlog_event_severity(event) > qlog->severity_filter)
		return false;
	return true;
}

/**
 * tquic_qlog_set_mask - Update event filter mask
 * @qlog: Qlog context
 * @mask: New event mask
 *
 * Atomically updates the event filter mask.
 */
void tquic_qlog_set_mask(struct tquic_qlog *qlog, u64 mask);

/**
 * tquic_qlog_set_severity - Update severity filter
 * @qlog: Qlog context
 * @severity: Minimum severity to log
 */
void tquic_qlog_set_severity(struct tquic_qlog *qlog, u8 severity);

/*
 * =============================================================================
 * Transport Events (draft-12 Section 6)
 * =============================================================================
 */

/**
 * struct tquic_qlog_packet_info - Full packet info for logging
 * @packet_number: Packet number
 * @packet_type: enum tquic_qlog_packet_type
 * @packet_size: Total packet size
 * @payload_length: Payload length
 * @version: QUIC version
 * @key_phase: Key phase bit
 * @spin_bit: Spin bit value
 * @path_id: Path ID
 * @frames_count: Number of frames
 * @ack_eliciting: Whether ACK-eliciting
 * @in_flight: Whether in-flight
 * @is_coalesced: Whether coalesced
 * @is_mtu_probe: Whether MTU probe
 * @ecn: ECN marking
 */
struct tquic_qlog_packet_info {
	u64 packet_number;
	u32 packet_type;
	u32 packet_size;
	u32 payload_length;
	u32 version;
	u8 key_phase;
	u8 spin_bit;
	u32 path_id;
	u16 frames_count;
	bool ack_eliciting;
	bool in_flight;
	bool is_coalesced;
	bool is_mtu_probe;
	u8 ecn;
};

/**
 * tquic_qlog_packet_sent - Log transport:packet_sent event (draft-12 6.5)
 * @qlog: Qlog context
 * @info: Packet information
 *
 * Logs a packet sent event with full header and metadata.
 */
void tquic_qlog_packet_sent(struct tquic_qlog *qlog,
			    const struct tquic_qlog_packet_info *info);

/**
 * tquic_qlog_packet_sent_simple - Log packet_sent with minimal info
 * @qlog: Qlog context
 * @pkt_num: Packet number
 * @pkt_type: Packet type
 * @size: Packet size
 * @path_id: Path ID
 * @frames: Frame count
 * @ack_eliciting: ACK-eliciting flag
 *
 * Simplified API for common case.
 */
void tquic_qlog_packet_sent_simple(struct tquic_qlog *qlog,
				   u64 pkt_num, u32 pkt_type, size_t size,
				   u32 path_id, u16 frames, bool ack_eliciting);

/**
 * tquic_qlog_packet_received - Log transport:packet_received (draft-12 6.6)
 * @qlog: Qlog context
 * @info: Packet information
 */
void tquic_qlog_packet_received(struct tquic_qlog *qlog,
				const struct tquic_qlog_packet_info *info);

/**
 * tquic_qlog_packet_received_simple - Log packet_received with minimal info
 */
void tquic_qlog_packet_received_simple(struct tquic_qlog *qlog,
				       u64 pkt_num, u32 pkt_type, size_t size,
				       u32 path_id);

/**
 * tquic_qlog_packet_dropped - Log transport:packet_dropped (draft-12 6.7)
 * @qlog: Qlog context
 * @pkt_type: Packet type (if known)
 * @size: Packet size
 * @reason: Drop reason (enum tquic_qlog_packet_drop_reason)
 * @path_id: Path ID
 */
void tquic_qlog_packet_dropped(struct tquic_qlog *qlog,
			       u32 pkt_type, size_t size,
			       u32 reason, u32 path_id);

/**
 * tquic_qlog_packet_buffered - Log transport:packet_buffered (draft-12 6.8)
 * @qlog: Qlog context
 * @pkt_num: Packet number
 * @pkt_type: Packet type
 * @size: Packet size
 * @reason: Buffer reason (enum tquic_qlog_packet_buffer_reason)
 * @path_id: Path ID
 */
void tquic_qlog_packet_buffered(struct tquic_qlog *qlog,
				u64 pkt_num, u32 pkt_type, size_t size,
				u32 reason, u32 path_id);

/*
 * =============================================================================
 * Recovery Events (draft-12 Section 7)
 * =============================================================================
 */

/**
 * struct tquic_qlog_metrics_info - CC metrics for logging
 * @min_rtt: Minimum RTT (us)
 * @smoothed_rtt: Smoothed RTT (us)
 * @latest_rtt: Latest RTT sample (us)
 * @rtt_variance: RTT variance (us)
 * @cwnd: Congestion window (bytes)
 * @bytes_in_flight: Bytes in flight
 * @ssthresh: Slow start threshold
 * @pacing_rate: Pacing rate (bytes/sec)
 * @pto_count: PTO count
 * @packets_in_flight: Packets in flight
 * @path_id: Path ID
 */
struct tquic_qlog_metrics_info {
	u64 min_rtt;
	u64 smoothed_rtt;
	u64 latest_rtt;
	u64 rtt_variance;
	u64 cwnd;
	u64 bytes_in_flight;
	u64 ssthresh;
	u64 pacing_rate;
	u32 pto_count;
	u32 packets_in_flight;
	u32 path_id;
};

/**
 * tquic_qlog_metrics_updated - Log recovery:metrics_updated (draft-12 7.2)
 * @qlog: Qlog context
 * @metrics: Metrics information
 */
void tquic_qlog_metrics_updated(struct tquic_qlog *qlog,
				const struct tquic_qlog_metrics_info *metrics);

/**
 * tquic_qlog_metrics_updated_simple - Log metrics with common fields
 * @qlog: Qlog context
 * @cwnd: Congestion window
 * @bytes_in_flight: Bytes in flight
 * @min_rtt: Minimum RTT
 * @smoothed_rtt: Smoothed RTT
 * @path_id: Path ID
 */
void tquic_qlog_metrics_updated_simple(struct tquic_qlog *qlog,
				       u64 cwnd, u64 bytes_in_flight,
				       u64 min_rtt, u64 smoothed_rtt,
				       u32 path_id);

/**
 * tquic_qlog_congestion_state_updated - Log recovery:congestion_state_updated (draft-12 7.3)
 * @qlog: Qlog context
 * @old_state: Previous CC state (enum tquic_qlog_cc_state)
 * @new_state: New CC state
 * @trigger: What triggered the transition (enum tquic_qlog_cc_trigger)
 * @path_id: Path ID
 */
void tquic_qlog_congestion_state_updated(struct tquic_qlog *qlog,
					 u32 old_state, u32 new_state,
					 u32 trigger, u32 path_id);

/* Legacy alias */
#define tquic_qlog_congestion_state tquic_qlog_congestion_state_updated

/**
 * tquic_qlog_loss_timer_updated - Log recovery:loss_timer_updated (draft-12 7.4)
 * @qlog: Qlog context
 * @timer_type: Timer type (enum tquic_qlog_timer_type)
 * @timer_event: Timer event (enum tquic_qlog_timer_event)
 * @delta_us: Time until timer fires (us), 0 if cancelled
 * @pn_space: Packet number space
 * @path_id: Path ID
 */
void tquic_qlog_loss_timer_updated(struct tquic_qlog *qlog,
				   u32 timer_type, u32 timer_event,
				   u64 delta_us, u32 pn_space, u32 path_id);

/**
 * tquic_qlog_packet_lost - Log recovery:packet_lost (draft-12 7.5)
 * @qlog: Qlog context
 * @pkt_num: Lost packet number
 * @pkt_type: Packet type
 * @size: Packet size
 * @trigger: Loss detection trigger
 * @path_id: Path ID
 */
void tquic_qlog_packet_lost(struct tquic_qlog *qlog,
			    u64 pkt_num, u32 pkt_type, size_t size,
			    u32 trigger, u32 path_id);

/*
 * =============================================================================
 * Connectivity Events (draft-12 Section 5)
 * =============================================================================
 */

/**
 * tquic_qlog_connection_started - Log connectivity:connection_started (draft-12 5.2)
 * @qlog: Qlog context
 * @version: QUIC version
 */
void tquic_qlog_connection_started(struct tquic_qlog *qlog, u32 version);

/**
 * tquic_qlog_connection_closed - Log connectivity:connection_closed (draft-12 5.3)
 * @qlog: Qlog context
 * @error_code: Error code (0 for clean close)
 * @reason: Optional reason phrase (may be NULL)
 * @reason_len: Reason phrase length
 */
void tquic_qlog_connection_closed(struct tquic_qlog *qlog, u64 error_code,
				  const char *reason, size_t reason_len);

/**
 * tquic_qlog_connection_state_updated - Log connection state transition
 * @qlog: Qlog context
 * @old_state: Previous state
 * @new_state: New state
 *
 * Legacy API - internally maps to path_updated for primary path.
 */
void tquic_qlog_connection_state_updated(struct tquic_qlog *qlog,
					 u32 old_state, u32 new_state);

/**
 * tquic_qlog_path_updated - Log connectivity:path_updated (draft-12 5.6)
 * @qlog: Qlog context
 * @path_id: Path ID
 * @old_state: Previous path state
 * @new_state: New path state
 * @mtu: Path MTU (0 if not changed)
 */
void tquic_qlog_path_updated(struct tquic_qlog *qlog, u32 path_id,
			     u32 old_state, u32 new_state, u32 mtu);

/*
 * =============================================================================
 * Security Events (draft-12 Section 8)
 * =============================================================================
 */

/**
 * tquic_qlog_key_updated - Log security:key_updated (draft-12 8.1)
 * @qlog: Qlog context
 * @key_type: Type of key (enum tquic_qlog_key_type)
 * @key_phase: Current key phase
 * @generation: Key generation number
 * @trigger: Update trigger (enum tquic_qlog_key_trigger)
 */
void tquic_qlog_key_updated(struct tquic_qlog *qlog,
			    u32 key_type, u32 key_phase,
			    u32 generation, u32 trigger);

/**
 * tquic_qlog_key_discarded - Log security:key_discarded (draft-12 8.2)
 * @qlog: Qlog context
 * @key_type: Type of key discarded
 * @key_phase: Key phase
 * @generation: Key generation number
 * @trigger: Discard trigger
 */
void tquic_qlog_key_discarded(struct tquic_qlog *qlog,
			      u32 key_type, u32 key_phase,
			      u32 generation, u32 trigger);

/* Legacy alias */
#define tquic_qlog_key_retired tquic_qlog_key_discarded

/*
 * =============================================================================
 * JSON Output
 * =============================================================================
 */

/**
 * tquic_qlog_emit_json - Emit event as JSON line
 * @qlog: Qlog context
 * @entry: Event entry to format
 * @buf: Output buffer
 * @buflen: Buffer size
 *
 * Formats an event entry as a JSON-SEQ line per qlog specification.
 *
 * Return: Number of bytes written, or negative error
 */
int tquic_qlog_emit_json(struct tquic_qlog *qlog,
			 const struct tquic_qlog_event_entry *entry,
			 char *buf, size_t buflen);

/*
 * =============================================================================
 * Netlink Interface
 * =============================================================================
 */

/**
 * tquic_qlog_nl_event - Send event via netlink
 * @qlog: Qlog context
 * @entry: Event entry to send
 *
 * Sends an event to userspace via the TQUIC generic netlink family.
 *
 * Return: 0 on success, negative errno on failure
 */
int tquic_qlog_nl_event(struct tquic_qlog *qlog,
			const struct tquic_qlog_event_entry *entry);

/*
 * =============================================================================
 * Ring Buffer Access
 * =============================================================================
 */

/**
 * tquic_qlog_read_events - Read events from ring buffer
 * @qlog: Qlog context
 * @buf: User buffer to read into
 * @count: Maximum bytes to read
 *
 * Reads available events from the ring buffer to userspace.
 * Used for poll/read on qlog file descriptor.
 *
 * Return: Number of bytes read, or negative error
 */
ssize_t tquic_qlog_read_events(struct tquic_qlog *qlog,
			       char __user *buf, size_t count);

/**
 * tquic_qlog_poll - Poll for available events
 * @qlog: Qlog context
 *
 * Return: Poll flags (EPOLLIN if events available)
 */
__poll_t tquic_qlog_poll(struct tquic_qlog *qlog);

/*
 * =============================================================================
 * Module Init/Exit
 * =============================================================================
 */

int __init tquic_qlog_init(void);
void __exit tquic_qlog_exit(void);

#endif /* _NET_TQUIC_QLOG_H */
