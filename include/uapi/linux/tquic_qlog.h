/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * TQUIC Qlog Interface - User API
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Qlog is a logging format for QUIC connections defined by:
 *   draft-ietf-quic-qlog-main-schema
 *   draft-ietf-quic-qlog-quic-events
 *
 * This interface allows userspace applications to receive QUIC
 * diagnostic events in a structured format for debugging, analysis,
 * and performance monitoring.
 */

#ifndef _UAPI_LINUX_TQUIC_QLOG_H
#define _UAPI_LINUX_TQUIC_QLOG_H

#include <linux/types.h>

/*
 * Socket option to enable/configure qlog
 *
 * Used with setsockopt(SOL_TQUIC, TQUIC_QLOG_ENABLE, &args, sizeof(args))
 * to enable qlog tracing on a TQUIC socket.
 */
#define TQUIC_QLOG_ENABLE		250
#define SO_TQUIC_QLOG_ENABLE		TQUIC_QLOG_ENABLE

/* Get qlog statistics (read-only) */
#define TQUIC_QLOG_STATS		251
#define SO_TQUIC_QLOG_STATS		TQUIC_QLOG_STATS

/* Set event filter mask */
#define TQUIC_QLOG_FILTER		252
#define SO_TQUIC_QLOG_FILTER		TQUIC_QLOG_FILTER

/*
 * Qlog event categories per draft-ietf-quic-qlog-main-schema
 */
#define TQUIC_QLOG_CAT_CONNECTIVITY	0x01	/* Connection events */
#define TQUIC_QLOG_CAT_TRANSPORT	0x02	/* Transport layer events */
#define TQUIC_QLOG_CAT_RECOVERY		0x04	/* Loss recovery events */
#define TQUIC_QLOG_CAT_SECURITY		0x08	/* Security/crypto events */
#define TQUIC_QLOG_CAT_HTTP		0x10	/* HTTP/3 events */

/* Default: log connectivity, transport, and recovery */
#define TQUIC_QLOG_CAT_DEFAULT		(TQUIC_QLOG_CAT_CONNECTIVITY | \
					 TQUIC_QLOG_CAT_TRANSPORT | \
					 TQUIC_QLOG_CAT_RECOVERY)

/*
 * Qlog event types per draft-ietf-quic-qlog-quic-events
 *
 * Bit positions for event filtering via event_mask.
 */
enum tquic_qlog_event {
	/* Connectivity category */
	QLOG_CONNECTION_STARTED = 0,	/* Connection attempt started */
	QLOG_CONNECTION_CLOSED,		/* Connection terminated */
	QLOG_CONNECTION_STATE_UPDATED,	/* State machine transition */

	/* Transport category */
	QLOG_PACKET_SENT = 10,		/* Packet transmitted */
	QLOG_PACKET_RECEIVED,		/* Packet received */
	QLOG_PACKET_DROPPED,		/* Packet dropped */
	QLOG_FRAMES_PROCESSED,		/* Frames parsed/generated */

	/* Recovery category */
	QLOG_METRICS_UPDATED = 20,	/* CC metrics changed */
	QLOG_CONGESTION_STATE_UPDATED,	/* CC state transition */
	QLOG_LOSS_TIMER_UPDATED,	/* Loss timer set/cancelled */
	QLOG_PACKET_LOST,		/* Packet declared lost */

	/* Security category */
	QLOG_KEY_UPDATED = 30,		/* Key phase change */
	QLOG_KEY_RETIRED,		/* Key discarded */

	__QLOG_EVENT_MAX,
};

#define QLOG_EVENT_MAX	(__QLOG_EVENT_MAX - 1)

/*
 * Event mask macros for filtering
 */
#define QLOG_EVENT_BIT(ev)		(1ULL << (ev))

/* Connectivity events */
#define QLOG_MASK_CONNECTIVITY		(QLOG_EVENT_BIT(QLOG_CONNECTION_STARTED) | \
					 QLOG_EVENT_BIT(QLOG_CONNECTION_CLOSED) | \
					 QLOG_EVENT_BIT(QLOG_CONNECTION_STATE_UPDATED))

/* Transport events */
#define QLOG_MASK_TRANSPORT		(QLOG_EVENT_BIT(QLOG_PACKET_SENT) | \
					 QLOG_EVENT_BIT(QLOG_PACKET_RECEIVED) | \
					 QLOG_EVENT_BIT(QLOG_PACKET_DROPPED) | \
					 QLOG_EVENT_BIT(QLOG_FRAMES_PROCESSED))

/* Recovery events */
#define QLOG_MASK_RECOVERY		(QLOG_EVENT_BIT(QLOG_METRICS_UPDATED) | \
					 QLOG_EVENT_BIT(QLOG_CONGESTION_STATE_UPDATED) | \
					 QLOG_EVENT_BIT(QLOG_LOSS_TIMER_UPDATED) | \
					 QLOG_EVENT_BIT(QLOG_PACKET_LOST))

/* Security events */
#define QLOG_MASK_SECURITY		(QLOG_EVENT_BIT(QLOG_KEY_UPDATED) | \
					 QLOG_EVENT_BIT(QLOG_KEY_RETIRED))

/* All events */
#define QLOG_MASK_ALL			(QLOG_MASK_CONNECTIVITY | \
					 QLOG_MASK_TRANSPORT | \
					 QLOG_MASK_RECOVERY | \
					 QLOG_MASK_SECURITY)

/*
 * Qlog output modes
 */
#define TQUIC_QLOG_MODE_DISABLED	0	/* Qlog disabled */
#define TQUIC_QLOG_MODE_RING		1	/* Store in ring buffer */
#define TQUIC_QLOG_MODE_NETLINK		2	/* Relay to userspace via netlink */

/**
 * struct tquic_qlog_args - Qlog configuration
 * @mode: Output mode (TQUIC_QLOG_MODE_*)
 * @ring_size: Ring buffer size in entries (power of 2, mode=RING only)
 * @event_mask: Bitmask of events to capture (QLOG_EVENT_BIT)
 * @flags: Additional flags (reserved, must be 0)
 *
 * Used with setsockopt(TQUIC_QLOG_ENABLE) to configure qlog.
 *
 * Example - enable all events with ring buffer:
 *   struct tquic_qlog_args args = {
 *       .mode = TQUIC_QLOG_MODE_RING,
 *       .ring_size = 1024,
 *       .event_mask = QLOG_MASK_ALL,
 *   };
 *   setsockopt(fd, SOL_TQUIC, TQUIC_QLOG_ENABLE, &args, sizeof(args));
 *
 * Example - enable recovery events with netlink relay:
 *   struct tquic_qlog_args args = {
 *       .mode = TQUIC_QLOG_MODE_NETLINK,
 *       .event_mask = QLOG_MASK_RECOVERY,
 *   };
 *   setsockopt(fd, SOL_TQUIC, TQUIC_QLOG_ENABLE, &args, sizeof(args));
 */
struct tquic_qlog_args {
	__u32	mode;		/* TQUIC_QLOG_MODE_* */
	__u32	ring_size;	/* Ring buffer entries (mode=RING) */
	__u64	event_mask;	/* Events to capture */
	__u32	flags;		/* Reserved, must be 0 */
	__u32	reserved;	/* Reserved for alignment */
};

/**
 * struct tquic_qlog_stats - Qlog statistics
 * @events_logged: Total events logged
 * @events_dropped: Events dropped (ring full, allocation failed)
 * @events_relayed: Events sent to userspace via netlink
 * @ring_overflows: Ring buffer overflow count
 * @netlink_errors: Netlink send errors
 *
 * Used with getsockopt(TQUIC_QLOG_STATS) to retrieve statistics.
 */
struct tquic_qlog_stats {
	__u64	events_logged;
	__u64	events_dropped;
	__u64	events_relayed;
	__u64	ring_overflows;
	__u64	netlink_errors;
};

/*
 * Netlink interface for qlog events
 *
 * Qlog events can be relayed to userspace via the generic netlink
 * family TQUIC_GENL_NAME with a new multicast group.
 */

/* Netlink command for qlog events */
#define TQUIC_CMD_QLOG_EVENT		20

/* Netlink multicast group for qlog */
#define TQUIC_NL_GRP_QLOG		3

/*
 * Netlink attributes for qlog events
 */
enum {
	TQUIC_QLOG_ATTR_UNSPEC,
	TQUIC_QLOG_ATTR_EVENT_TYPE,	/* __u32 enum tquic_qlog_event */
	TQUIC_QLOG_ATTR_TIMESTAMP,	/* __u64 nanoseconds since boot */
	TQUIC_QLOG_ATTR_CONN_ID,	/* binary: connection ID */
	TQUIC_QLOG_ATTR_PATH_ID,	/* __u32 path ID */
	TQUIC_QLOG_ATTR_DATA,		/* binary: event-specific data */
	TQUIC_QLOG_ATTR_JSON,		/* string: JSON-formatted event */

	__TQUIC_QLOG_ATTR_MAX,
};

#define TQUIC_QLOG_ATTR_MAX	(__TQUIC_QLOG_ATTR_MAX - 1)

/*
 * Packet types for QLOG_PACKET_SENT/RECEIVED/DROPPED/LOST
 */
enum tquic_qlog_packet_type {
	QLOG_PKT_INITIAL = 0,
	QLOG_PKT_HANDSHAKE,
	QLOG_PKT_0RTT,
	QLOG_PKT_1RTT,
	QLOG_PKT_RETRY,
	QLOG_PKT_VERSION_NEG,
};

/**
 * struct tquic_qlog_packet_event - Packet event data
 * @packet_number: Packet number
 * @packet_type: Packet type (enum tquic_qlog_packet_type)
 * @packet_size: Packet size in bytes
 * @path_id: Path ID for multipath
 * @frames_count: Number of frames in packet
 * @ack_eliciting: Whether packet is ACK-eliciting
 * @in_flight: Whether packet counts as in-flight
 *
 * Used for QLOG_PACKET_SENT, QLOG_PACKET_RECEIVED, QLOG_PACKET_DROPPED,
 * and QLOG_PACKET_LOST events.
 */
struct tquic_qlog_packet_event {
	__u64	packet_number;
	__u32	packet_type;
	__u32	packet_size;
	__u32	path_id;
	__u16	frames_count;
	__u8	ack_eliciting;
	__u8	in_flight;
};

/**
 * struct tquic_qlog_metrics_event - CC metrics update event
 * @cwnd: Congestion window (bytes)
 * @bytes_in_flight: Bytes currently in flight
 * @min_rtt: Minimum RTT (microseconds)
 * @smoothed_rtt: Smoothed RTT (microseconds)
 * @rtt_variance: RTT variance (microseconds)
 * @ssthresh: Slow start threshold (bytes)
 * @pacing_rate: Pacing rate (bytes/second)
 * @path_id: Path ID for multipath
 *
 * Used for QLOG_METRICS_UPDATED events.
 */
struct tquic_qlog_metrics_event {
	__u64	cwnd;
	__u64	bytes_in_flight;
	__u64	min_rtt;
	__u64	smoothed_rtt;
	__u64	rtt_variance;
	__u64	ssthresh;
	__u64	pacing_rate;
	__u32	path_id;
	__u32	reserved;
};

/**
 * struct tquic_qlog_congestion_event - CC state change event
 * @old_state: Previous CC state (algorithm-specific)
 * @new_state: New CC state
 * @trigger: What triggered the state change
 * @path_id: Path ID for multipath
 *
 * CC states are algorithm-specific strings passed as triggers.
 */
struct tquic_qlog_congestion_event {
	__u32	old_state;
	__u32	new_state;
	__u32	trigger;
	__u32	path_id;
};

/* Congestion states (generic) */
#define QLOG_CC_SLOW_START		0
#define QLOG_CC_CONGESTION_AVOIDANCE	1
#define QLOG_CC_APPLICATION_LIMITED	2
#define QLOG_CC_RECOVERY		3

/* Congestion triggers */
#define QLOG_CC_TRIGGER_ACK		0
#define QLOG_CC_TRIGGER_LOSS		1
#define QLOG_CC_TRIGGER_ECN		2
#define QLOG_CC_TRIGGER_PTO		3
#define QLOG_CC_TRIGGER_PERSISTENT_CONG	4

/**
 * struct tquic_qlog_loss_timer_event - Loss timer event
 * @timer_type: Timer type (QLOG_TIMER_*)
 * @delta: Time until timer fires (microseconds)
 * @path_id: Path ID for multipath
 *
 * Used for QLOG_LOSS_TIMER_UPDATED events.
 */
struct tquic_qlog_loss_timer_event {
	__u32	timer_type;
	__u32	path_id;
	__u64	delta;
};

/* Timer types */
#define QLOG_TIMER_ACK		0
#define QLOG_TIMER_PTO		1
#define QLOG_TIMER_IDLE		2
#define QLOG_TIMER_HANDSHAKE	3

/**
 * struct tquic_qlog_key_event - Key update event
 * @key_phase: Current key phase
 * @generation: Key generation number
 * @trigger: What triggered the key event
 *
 * Used for QLOG_KEY_UPDATED and QLOG_KEY_RETIRED events.
 */
struct tquic_qlog_key_event {
	__u32	key_phase;
	__u32	generation;
	__u32	trigger;
	__u32	reserved;
};

/* Key triggers */
#define QLOG_KEY_TRIGGER_LOCAL		0	/* Local initiated */
#define QLOG_KEY_TRIGGER_REMOTE		1	/* Remote initiated */
#define QLOG_KEY_TRIGGER_AEAD_LIMIT	2	/* AEAD limit reached */

/**
 * struct tquic_qlog_connection_event - Connection state event
 * @old_state: Previous connection state
 * @new_state: New connection state
 * @error_code: Error code if closing (0 otherwise)
 * @version: QUIC version
 *
 * Used for QLOG_CONNECTION_STARTED, QLOG_CONNECTION_CLOSED, and
 * QLOG_CONNECTION_STATE_UPDATED events.
 */
struct tquic_qlog_connection_event {
	__u32	old_state;
	__u32	new_state;
	__u64	error_code;
	__u32	version;
	__u32	reserved;
};

/* Connection states (matches enum tquic_conn_state) */
#define QLOG_CONN_IDLE			0
#define QLOG_CONN_CONNECTING		1
#define QLOG_CONN_CONNECTED		2
#define QLOG_CONN_CLOSING		3
#define QLOG_CONN_DRAINING		4
#define QLOG_CONN_CLOSED		5

/*
 * Ring buffer entry format for TQUIC_QLOG_MODE_RING
 *
 * Events are stored in a fixed-size ring buffer that can be
 * read via read() on a qlog file descriptor.
 */

/**
 * struct tquic_qlog_event_entry - Ring buffer entry
 * @timestamp_ns: Timestamp in nanoseconds since boot
 * @event_type: Event type (enum tquic_qlog_event)
 * @data_len: Length of event-specific data
 * @path_id: Path ID (for path-specific events)
 * @data: Event-specific data (union of event structs)
 *
 * Ring buffer entries are variable-length. Use data_len to
 * determine the actual size of each entry.
 */
struct tquic_qlog_event_entry {
	__u64	timestamp_ns;
	__u32	event_type;
	__u16	data_len;
	__u16	path_id;
	union {
		struct tquic_qlog_packet_event packet;
		struct tquic_qlog_metrics_event metrics;
		struct tquic_qlog_congestion_event congestion;
		struct tquic_qlog_loss_timer_event timer;
		struct tquic_qlog_key_event key;
		struct tquic_qlog_connection_event connection;
		__u8 raw[64];
	} data;
};

/* Ring buffer limits */
#define TQUIC_QLOG_RING_MIN		64	/* Minimum ring entries */
#define TQUIC_QLOG_RING_MAX		16384	/* Maximum ring entries */
#define TQUIC_QLOG_RING_DEFAULT		1024	/* Default ring entries */

#endif /* _UAPI_LINUX_TQUIC_QLOG_H */
