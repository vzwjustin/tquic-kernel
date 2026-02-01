/* SPDX-License-Identifier: GPL-2.0 */
/*
 * TQUIC Qlog Internal Definitions
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Internal structures and functions for qlog tracing support.
 * Implements draft-ietf-quic-qlog-main-schema event logging.
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

/**
 * struct tquic_qlog - Qlog context for a connection
 * @conn: Parent connection
 * @ring: Ring buffer for event storage
 * @ring_size: Number of entries in ring buffer
 * @ring_mask: Mask for ring index (ring_size - 1)
 * @head: Next write position
 * @tail: Next read position
 * @event_mask: Bitmask of enabled events
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
	return !!(qlog->event_mask & QLOG_EVENT_BIT(event));
}

/**
 * tquic_qlog_set_mask - Update event filter mask
 * @qlog: Qlog context
 * @mask: New event mask
 *
 * Atomically updates the event filter mask.
 */
void tquic_qlog_set_mask(struct tquic_qlog *qlog, u64 mask);

/*
 * =============================================================================
 * Event Logging Functions
 * =============================================================================
 */

/**
 * tquic_qlog_packet_sent - Log packet sent event
 * @qlog: Qlog context
 * @pkt_num: Packet number
 * @pkt_type: Packet type (enum tquic_qlog_packet_type)
 * @size: Packet size in bytes
 * @path_id: Path ID
 * @frames: Number of frames in packet
 * @ack_eliciting: Whether packet is ACK-eliciting
 *
 * Logs a QLOG_PACKET_SENT event.
 */
void tquic_qlog_packet_sent(struct tquic_qlog *qlog,
			    u64 pkt_num, u32 pkt_type, size_t size,
			    u32 path_id, u16 frames, bool ack_eliciting);

/**
 * tquic_qlog_packet_received - Log packet received event
 * @qlog: Qlog context
 * @pkt_num: Packet number
 * @pkt_type: Packet type
 * @size: Packet size in bytes
 * @path_id: Path ID
 *
 * Logs a QLOG_PACKET_RECEIVED event.
 */
void tquic_qlog_packet_received(struct tquic_qlog *qlog,
				u64 pkt_num, u32 pkt_type, size_t size,
				u32 path_id);

/**
 * tquic_qlog_packet_dropped - Log packet dropped event
 * @qlog: Qlog context
 * @pkt_type: Packet type
 * @size: Packet size in bytes
 * @reason: Drop reason (string for JSON output)
 *
 * Logs a QLOG_PACKET_DROPPED event.
 */
void tquic_qlog_packet_dropped(struct tquic_qlog *qlog,
			       u32 pkt_type, size_t size,
			       const char *reason);

/**
 * tquic_qlog_packet_lost - Log packet loss detection
 * @qlog: Qlog context
 * @pkt_num: Lost packet number
 * @pkt_type: Packet type
 * @size: Packet size in bytes
 * @path_id: Path ID
 *
 * Logs a QLOG_PACKET_LOST event.
 */
void tquic_qlog_packet_lost(struct tquic_qlog *qlog,
			    u64 pkt_num, u32 pkt_type, size_t size,
			    u32 path_id);

/**
 * tquic_qlog_metrics_updated - Log CC metrics update
 * @qlog: Qlog context
 * @cwnd: Congestion window (bytes)
 * @bytes_in_flight: Bytes in flight
 * @min_rtt: Minimum RTT (us)
 * @smoothed_rtt: Smoothed RTT (us)
 * @path_id: Path ID
 *
 * Logs a QLOG_METRICS_UPDATED event.
 */
void tquic_qlog_metrics_updated(struct tquic_qlog *qlog,
				u64 cwnd, u64 bytes_in_flight,
				u64 min_rtt, u64 smoothed_rtt,
				u32 path_id);

/**
 * tquic_qlog_congestion_state - Log CC state transition
 * @qlog: Qlog context
 * @old_state: Previous CC state
 * @new_state: New CC state
 * @trigger: What triggered the transition
 * @path_id: Path ID
 *
 * Logs a QLOG_CONGESTION_STATE_UPDATED event.
 */
void tquic_qlog_congestion_state(struct tquic_qlog *qlog,
				 u32 old_state, u32 new_state,
				 u32 trigger, u32 path_id);

/**
 * tquic_qlog_loss_timer_updated - Log loss timer event
 * @qlog: Qlog context
 * @timer_type: Timer type (QLOG_TIMER_*)
 * @delta_us: Time until timer fires (us), 0 if cancelled
 * @path_id: Path ID
 *
 * Logs a QLOG_LOSS_TIMER_UPDATED event.
 */
void tquic_qlog_loss_timer_updated(struct tquic_qlog *qlog,
				   u32 timer_type, u64 delta_us,
				   u32 path_id);

/**
 * tquic_qlog_key_updated - Log key update event
 * @qlog: Qlog context
 * @key_phase: Current key phase
 * @generation: Key generation number
 * @trigger: Update trigger
 *
 * Logs a QLOG_KEY_UPDATED event.
 */
void tquic_qlog_key_updated(struct tquic_qlog *qlog,
			    u32 key_phase, u32 generation, u32 trigger);

/**
 * tquic_qlog_key_retired - Log key retirement
 * @qlog: Qlog context
 * @key_phase: Retired key phase
 * @generation: Key generation number
 *
 * Logs a QLOG_KEY_RETIRED event.
 */
void tquic_qlog_key_retired(struct tquic_qlog *qlog,
			    u32 key_phase, u32 generation);

/**
 * tquic_qlog_connection_started - Log connection start
 * @qlog: Qlog context
 * @version: QUIC version
 *
 * Logs a QLOG_CONNECTION_STARTED event.
 */
void tquic_qlog_connection_started(struct tquic_qlog *qlog, u32 version);

/**
 * tquic_qlog_connection_closed - Log connection close
 * @qlog: Qlog context
 * @error_code: Error code (0 for clean close)
 *
 * Logs a QLOG_CONNECTION_CLOSED event.
 */
void tquic_qlog_connection_closed(struct tquic_qlog *qlog, u64 error_code);

/**
 * tquic_qlog_connection_state_updated - Log connection state change
 * @qlog: Qlog context
 * @old_state: Previous connection state
 * @new_state: New connection state
 *
 * Logs a QLOG_CONNECTION_STATE_UPDATED event.
 */
void tquic_qlog_connection_state_updated(struct tquic_qlog *qlog,
					 u32 old_state, u32 new_state);

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
