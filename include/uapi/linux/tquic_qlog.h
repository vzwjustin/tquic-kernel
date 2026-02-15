/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * TQUIC Qlog Interface - User API
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Qlog is a logging format for QUIC connections defined by:
 *   draft-ietf-quic-qlog-main-schema
 *   draft-ietf-quic-qlog-quic-events-12
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
 * =============================================================================
 * Event Categories per draft-ietf-quic-qlog-quic-events-12
 * =============================================================================
 */

/**
 * enum tquic_qlog_category - Qlog event categories
 *
 * Categories as defined in draft-ietf-quic-qlog-quic-events-12 Section 4
 */
enum tquic_qlog_category {
	TQUIC_QLOG_CAT_CONNECTIVITY	= 0x01,	/* Connection lifecycle events */
	TQUIC_QLOG_CAT_TRANSPORT	= 0x02,	/* Transport layer events */
	TQUIC_QLOG_CAT_RECOVERY		= 0x04,	/* Loss recovery events */
	TQUIC_QLOG_CAT_SECURITY		= 0x08,	/* Security/crypto events */
	TQUIC_QLOG_CAT_HTTP		= 0x10,	/* HTTP/3 events (future) */
};

/* Default: log connectivity, transport, and recovery */
#define TQUIC_QLOG_CAT_DEFAULT		(TQUIC_QLOG_CAT_CONNECTIVITY | \
					 TQUIC_QLOG_CAT_TRANSPORT | \
					 TQUIC_QLOG_CAT_RECOVERY)

/*
 * =============================================================================
 * Event Severity Levels per draft-ietf-quic-qlog-quic-events-12
 * =============================================================================
 */

/**
 * enum tquic_qlog_severity - Event importance level
 *
 * Used to filter events by importance. Matches qlog main schema.
 */
enum tquic_qlog_severity {
	TQUIC_QLOG_SEV_CORE	= 0,	/* Core protocol events, always logged */
	TQUIC_QLOG_SEV_BASE	= 1,	/* Base events, commonly logged */
	TQUIC_QLOG_SEV_EXTRA	= 2,	/* Extra detail events */
	TQUIC_QLOG_SEV_DEBUG	= 3,	/* Debug/trace level events */
};

/*
 * =============================================================================
 * Event Types per draft-ietf-quic-qlog-quic-events-12
 * =============================================================================
 *
 * Event types organized by category as defined in the draft.
 * Bit positions for event filtering via event_mask.
 */
enum tquic_qlog_event {
	/*
	 * Connectivity category (connectivity:*)
	 * Section 5 of draft-12
	 */
	QLOG_CONNECTIVITY_SERVER_LISTENING = 0,	/* Server started listening */
	QLOG_CONNECTIVITY_CONNECTION_STARTED,	/* Connection attempt initiated */
	QLOG_CONNECTIVITY_CONNECTION_CLOSED,	/* Connection terminated */
	QLOG_CONNECTIVITY_CONNECTION_ID_UPDATED, /* CID changed */
	QLOG_CONNECTIVITY_SPIN_BIT_UPDATED,	/* Spin bit value changed */
	QLOG_CONNECTIVITY_PATH_UPDATED,		/* Path state changed */

	/*
	 * Transport category (transport:*)
	 * Section 6 of draft-12
	 */
	QLOG_TRANSPORT_VERSION_INFORMATION = 10, /* Version negotiation info */
	QLOG_TRANSPORT_ALPN_INFORMATION,	/* ALPN selected */
	QLOG_TRANSPORT_PARAMETERS_SET,		/* Transport params set */
	QLOG_TRANSPORT_PARAMETERS_RESTORED,	/* 0-RTT params restored */
	QLOG_TRANSPORT_PACKET_SENT,		/* Packet transmitted */
	QLOG_TRANSPORT_PACKET_RECEIVED,		/* Packet received */
	QLOG_TRANSPORT_PACKET_DROPPED,		/* Packet dropped */
	QLOG_TRANSPORT_PACKET_BUFFERED,		/* Packet buffered */
	QLOG_TRANSPORT_PACKETS_ACKED,		/* Packets acknowledged */
	QLOG_TRANSPORT_DATAGRAMS_SENT,		/* Datagrams sent */
	QLOG_TRANSPORT_DATAGRAMS_RECEIVED,	/* Datagrams received */
	QLOG_TRANSPORT_DATAGRAM_DROPPED,	/* Datagram dropped */
	QLOG_TRANSPORT_STREAM_STATE_UPDATED,	/* Stream state changed */
	QLOG_TRANSPORT_FRAMES_PROCESSED,	/* Frames parsed/generated */
	QLOG_TRANSPORT_DATA_MOVED,		/* Data moved to/from app */

	/*
	 * Recovery category (recovery:*)
	 * Section 7 of draft-12
	 */
	QLOG_RECOVERY_PARAMETERS_SET = 30,	/* Recovery params configured */
	QLOG_RECOVERY_METRICS_UPDATED,		/* CC metrics changed */
	QLOG_RECOVERY_CONGESTION_STATE_UPDATED,	/* CC state transition */
	QLOG_RECOVERY_LOSS_TIMER_UPDATED,	/* Loss timer set/cancelled */
	QLOG_RECOVERY_PACKET_LOST,		/* Packet declared lost */
	QLOG_RECOVERY_MARKED_FOR_RETRANSMIT,	/* Data marked for retransmit */
	QLOG_RECOVERY_ECN_STATE_UPDATED,	/* ECN state changed */

	/*
	 * Security category (security:*)
	 * Section 8 of draft-12
	 */
	QLOG_SECURITY_KEY_UPDATED = 40,		/* Key phase change */
	QLOG_SECURITY_KEY_DISCARDED,		/* Key retired/discarded */

	__QLOG_EVENT_MAX,
};

#define QLOG_EVENT_MAX	(__QLOG_EVENT_MAX - 1)

/* Legacy aliases for compatibility */
#define QLOG_CONNECTION_STARTED		QLOG_CONNECTIVITY_CONNECTION_STARTED
#define QLOG_CONNECTION_CLOSED		QLOG_CONNECTIVITY_CONNECTION_CLOSED
#define QLOG_CONNECTION_STATE_UPDATED	QLOG_CONNECTIVITY_PATH_UPDATED
#define QLOG_PACKET_SENT		QLOG_TRANSPORT_PACKET_SENT
#define QLOG_PACKET_RECEIVED		QLOG_TRANSPORT_PACKET_RECEIVED
#define QLOG_PACKET_DROPPED		QLOG_TRANSPORT_PACKET_DROPPED
#define QLOG_FRAMES_PROCESSED		QLOG_TRANSPORT_FRAMES_PROCESSED
#define QLOG_METRICS_UPDATED		QLOG_RECOVERY_METRICS_UPDATED
#define QLOG_CONGESTION_STATE_UPDATED	QLOG_RECOVERY_CONGESTION_STATE_UPDATED
#define QLOG_LOSS_TIMER_UPDATED		QLOG_RECOVERY_LOSS_TIMER_UPDATED
#define QLOG_PACKET_LOST		QLOG_RECOVERY_PACKET_LOST
#define QLOG_KEY_UPDATED		QLOG_SECURITY_KEY_UPDATED
#define QLOG_KEY_RETIRED		QLOG_SECURITY_KEY_DISCARDED

/*
 * =============================================================================
 * Event Mask Macros
 * =============================================================================
 */
#define QLOG_EVENT_BIT(ev)		(1ULL << (ev))

/* Connectivity events */
#define QLOG_MASK_CONNECTIVITY		(QLOG_EVENT_BIT(QLOG_CONNECTIVITY_SERVER_LISTENING) | \
					 QLOG_EVENT_BIT(QLOG_CONNECTIVITY_CONNECTION_STARTED) | \
					 QLOG_EVENT_BIT(QLOG_CONNECTIVITY_CONNECTION_CLOSED) | \
					 QLOG_EVENT_BIT(QLOG_CONNECTIVITY_CONNECTION_ID_UPDATED) | \
					 QLOG_EVENT_BIT(QLOG_CONNECTIVITY_SPIN_BIT_UPDATED) | \
					 QLOG_EVENT_BIT(QLOG_CONNECTIVITY_PATH_UPDATED))

/* Transport events */
#define QLOG_MASK_TRANSPORT		(QLOG_EVENT_BIT(QLOG_TRANSPORT_VERSION_INFORMATION) | \
					 QLOG_EVENT_BIT(QLOG_TRANSPORT_ALPN_INFORMATION) | \
					 QLOG_EVENT_BIT(QLOG_TRANSPORT_PARAMETERS_SET) | \
					 QLOG_EVENT_BIT(QLOG_TRANSPORT_PARAMETERS_RESTORED) | \
					 QLOG_EVENT_BIT(QLOG_TRANSPORT_PACKET_SENT) | \
					 QLOG_EVENT_BIT(QLOG_TRANSPORT_PACKET_RECEIVED) | \
					 QLOG_EVENT_BIT(QLOG_TRANSPORT_PACKET_DROPPED) | \
					 QLOG_EVENT_BIT(QLOG_TRANSPORT_PACKET_BUFFERED) | \
					 QLOG_EVENT_BIT(QLOG_TRANSPORT_PACKETS_ACKED) | \
					 QLOG_EVENT_BIT(QLOG_TRANSPORT_DATAGRAMS_SENT) | \
					 QLOG_EVENT_BIT(QLOG_TRANSPORT_DATAGRAMS_RECEIVED) | \
					 QLOG_EVENT_BIT(QLOG_TRANSPORT_DATAGRAM_DROPPED) | \
					 QLOG_EVENT_BIT(QLOG_TRANSPORT_STREAM_STATE_UPDATED) | \
					 QLOG_EVENT_BIT(QLOG_TRANSPORT_FRAMES_PROCESSED) | \
					 QLOG_EVENT_BIT(QLOG_TRANSPORT_DATA_MOVED))

/* Recovery events */
#define QLOG_MASK_RECOVERY		(QLOG_EVENT_BIT(QLOG_RECOVERY_PARAMETERS_SET) | \
					 QLOG_EVENT_BIT(QLOG_RECOVERY_METRICS_UPDATED) | \
					 QLOG_EVENT_BIT(QLOG_RECOVERY_CONGESTION_STATE_UPDATED) | \
					 QLOG_EVENT_BIT(QLOG_RECOVERY_LOSS_TIMER_UPDATED) | \
					 QLOG_EVENT_BIT(QLOG_RECOVERY_PACKET_LOST) | \
					 QLOG_EVENT_BIT(QLOG_RECOVERY_MARKED_FOR_RETRANSMIT) | \
					 QLOG_EVENT_BIT(QLOG_RECOVERY_ECN_STATE_UPDATED))

/* Security events */
#define QLOG_MASK_SECURITY		(QLOG_EVENT_BIT(QLOG_SECURITY_KEY_UPDATED) | \
					 QLOG_EVENT_BIT(QLOG_SECURITY_KEY_DISCARDED))

/* All events */
#define QLOG_MASK_ALL			(QLOG_MASK_CONNECTIVITY | \
					 QLOG_MASK_TRANSPORT | \
					 QLOG_MASK_RECOVERY | \
					 QLOG_MASK_SECURITY)

/*
 * =============================================================================
 * Output Modes
 * =============================================================================
 */
#define TQUIC_QLOG_MODE_DISABLED	0	/* Qlog disabled */
#define TQUIC_QLOG_MODE_RING		1	/* Store in ring buffer */
#define TQUIC_QLOG_MODE_NETLINK		2	/* Relay to userspace via netlink */

/*
 * =============================================================================
 * Packet Types (draft-12 Section 6.5)
 * =============================================================================
 */
enum tquic_qlog_packet_type {
	QLOG_PKT_INITIAL = 0,		/* Initial packet */
	QLOG_PKT_HANDSHAKE,		/* Handshake packet */
	QLOG_PKT_0RTT,			/* 0-RTT packet */
	QLOG_PKT_1RTT,			/* 1-RTT (short header) packet */
	QLOG_PKT_RETRY,			/* Retry packet */
	QLOG_PKT_VERSION_NEG,		/* Version negotiation packet */
	QLOG_PKT_STATELESS_RESET,	/* Stateless reset */
	QLOG_PKT_UNKNOWN,		/* Unknown packet type */
};

/*
 * =============================================================================
 * Packet Drop Reasons (draft-12 Section 6.7)
 * =============================================================================
 */
enum tquic_qlog_packet_drop_reason {
	QLOG_DROP_UNKNOWN = 0,			/* Unknown reason */
	QLOG_DROP_INTERNAL_ERROR,		/* Internal error */
	QLOG_DROP_INVALID,			/* Invalid packet */
	QLOG_DROP_INVALID_LENGTH,		/* Invalid length */
	QLOG_DROP_UNSUPPORTED_VERSION,		/* Unsupported version */
	QLOG_DROP_UNEXPECTED_PACKET,		/* Unexpected packet type */
	QLOG_DROP_UNEXPECTED_SOURCE_CID,	/* Source CID mismatch */
	QLOG_DROP_UNEXPECTED_VERSION,		/* Version mismatch */
	QLOG_DROP_DUPLICATE,			/* Duplicate packet */
	QLOG_DROP_KEY_UNAVAILABLE,		/* Decryption key unavailable */
	QLOG_DROP_DECRYPTION_FAILURE,		/* Decryption failed */
	QLOG_DROP_HEADER_PARSE_ERROR,		/* Header parse error */
	QLOG_DROP_PAYLOAD_PARSE_ERROR,		/* Payload parse error */
	QLOG_DROP_PROTOCOL_VIOLATION,		/* Protocol violation */
	QLOG_DROP_CONGESTION_CONTROL,		/* Dropped by CC */
	QLOG_DROP_CONNECTION_UNKNOWN,		/* Connection not found */
	QLOG_DROP_DOS_PREVENTION,		/* DoS prevention */
	QLOG_DROP_NO_LISTENER,			/* No matching listener */
};

/*
 * =============================================================================
 * Packet Buffered Reasons (draft-12 Section 6.8)
 * =============================================================================
 */
enum tquic_qlog_packet_buffer_reason {
	QLOG_BUFFER_UNKNOWN = 0,		/* Unknown reason */
	QLOG_BUFFER_BACKPRESSURE,		/* Backpressure from CC */
	QLOG_BUFFER_KEYS_UNAVAILABLE,		/* Keys not yet available */
};

/*
 * =============================================================================
 * Congestion Control States (draft-12 Section 7.3)
 * =============================================================================
 */
enum tquic_qlog_cc_state {
	QLOG_CC_SLOW_START = 0,			/* Slow start phase */
	QLOG_CC_CONGESTION_AVOIDANCE,		/* Congestion avoidance */
	QLOG_CC_APPLICATION_LIMITED,		/* App-limited */
	QLOG_CC_RECOVERY,			/* Loss recovery */
};

/*
 * =============================================================================
 * Congestion State Triggers (draft-12 Section 7.3)
 * =============================================================================
 */
enum tquic_qlog_cc_trigger {
	QLOG_CC_TRIGGER_ACK = 0,		/* ACK received */
	QLOG_CC_TRIGGER_LOSS,			/* Packet loss detected */
	QLOG_CC_TRIGGER_ECN,			/* ECN-CE received */
	QLOG_CC_TRIGGER_PTO,			/* PTO expired */
	QLOG_CC_TRIGGER_PERSISTENT_CONG,	/* Persistent congestion */
	QLOG_CC_TRIGGER_PACING,			/* Pacing delay */
};

/*
 * =============================================================================
 * Loss Timer Types (draft-12 Section 7.4)
 * =============================================================================
 */
enum tquic_qlog_timer_type {
	QLOG_TIMER_ACK = 0,		/* ACK delay timer */
	QLOG_TIMER_PTO,			/* Probe timeout */
	QLOG_TIMER_IDLE,		/* Idle timeout */
	QLOG_TIMER_HANDSHAKE,		/* Handshake timeout */
};

/*
 * =============================================================================
 * Loss Timer Events (draft-12 Section 7.4)
 * =============================================================================
 */
enum tquic_qlog_timer_event {
	QLOG_TIMER_SET = 0,		/* Timer set/armed */
	QLOG_TIMER_EXPIRED,		/* Timer expired */
	QLOG_TIMER_CANCELLED,		/* Timer cancelled */
};

/*
 * =============================================================================
 * Key Types (draft-12 Section 8.1)
 * =============================================================================
 */
enum tquic_qlog_key_type {
	QLOG_KEY_SERVER_INITIAL_SECRET = 0,
	QLOG_KEY_CLIENT_INITIAL_SECRET,
	QLOG_KEY_SERVER_HANDSHAKE_SECRET,
	QLOG_KEY_CLIENT_HANDSHAKE_SECRET,
	QLOG_KEY_SERVER_0RTT_SECRET,
	QLOG_KEY_CLIENT_0RTT_SECRET,
	QLOG_KEY_SERVER_1RTT_SECRET,
	QLOG_KEY_CLIENT_1RTT_SECRET,
};

/*
 * =============================================================================
 * Key Update Triggers (draft-12 Section 8.1)
 * =============================================================================
 */
enum tquic_qlog_key_trigger {
	QLOG_KEY_TRIGGER_TLS = 0,		/* TLS handshake */
	QLOG_KEY_TRIGGER_REMOTE_UPDATE,		/* Remote initiated */
	QLOG_KEY_TRIGGER_LOCAL_UPDATE,		/* Local initiated */
	QLOG_KEY_TRIGGER_AEAD_LIMIT,		/* AEAD limit reached */
};

/* Legacy aliases */
#define QLOG_KEY_TRIGGER_LOCAL		QLOG_KEY_TRIGGER_LOCAL_UPDATE
#define QLOG_KEY_TRIGGER_REMOTE		QLOG_KEY_TRIGGER_REMOTE_UPDATE

/*
 * =============================================================================
 * Connection States (draft-12 Section 5.2)
 * =============================================================================
 */
enum tquic_qlog_conn_state {
	QLOG_CONN_IDLE = 0,		/* Idle, no connection */
	QLOG_CONN_CONNECTING,		/* Connection in progress */
	QLOG_CONN_HANDSHAKE,		/* Handshake in progress */
	QLOG_CONN_CONNECTED,		/* Connection established */
	QLOG_CONN_CLOSING,		/* Closing initiated */
	QLOG_CONN_DRAINING,		/* Draining period */
	QLOG_CONN_CLOSED,		/* Connection closed */
};

/*
 * =============================================================================
 * Path States (draft-12 Section 5.6)
 * =============================================================================
 */
enum tquic_qlog_path_state {
	QLOG_PATH_NEW = 0,		/* New path */
	QLOG_PATH_VALIDATING,		/* Path validation in progress */
	QLOG_PATH_VALIDATED,		/* Path validated */
	QLOG_PATH_ACTIVE,		/* Path active */
	QLOG_PATH_STANDBY,		/* Path standby */
	QLOG_PATH_DEGRADED,		/* Path degraded */
	QLOG_PATH_CLOSED,		/* Path closed */
};

/*
 * =============================================================================
 * ECN States (draft-12 Section 7.7)
 * =============================================================================
 */
enum tquic_qlog_ecn_state {
	QLOG_ECN_UNKNOWN = 0,		/* ECN capability unknown */
	QLOG_ECN_TESTING,		/* ECN testing in progress */
	QLOG_ECN_CAPABLE,		/* ECN capable */
	QLOG_ECN_FAILED,		/* ECN validation failed */
};

/*
 * =============================================================================
 * Configuration Structures
 * =============================================================================
 */

/**
 * struct tquic_qlog_args - Qlog configuration
 * @mode: Output mode (TQUIC_QLOG_MODE_*)
 * @ring_size: Ring buffer size in entries (power of 2, mode=RING only)
 * @event_mask: Bitmask of events to capture (QLOG_EVENT_BIT)
 * @severity: Minimum severity level to log
 * @flags: Additional flags (reserved, must be 0)
 *
 * Used with setsockopt(TQUIC_QLOG_ENABLE) to configure qlog.
 */
struct tquic_qlog_args {
	__u32	mode;		/* TQUIC_QLOG_MODE_* */
	__u32	ring_size;	/* Ring buffer entries (mode=RING) */
	__u64	event_mask;	/* Events to capture */
	__u32	severity;	/* Minimum severity (enum tquic_qlog_severity) */
	__u32	flags;		/* Reserved, must be 0 */
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
 * =============================================================================
 * Netlink Interface
 * =============================================================================
 */

/* Netlink command for qlog events */
#define TQUIC_CMD_QLOG_EVENT		20

/* Netlink multicast group for qlog */
#define TQUIC_NL_GRP_QLOG		3

/* Netlink attributes for qlog events */
enum {
	TQUIC_QLOG_ATTR_UNSPEC,
	TQUIC_QLOG_ATTR_EVENT_TYPE,	/* __u32 enum tquic_qlog_event */
	TQUIC_QLOG_ATTR_TIMESTAMP,	/* __u64 nanoseconds since boot */
	TQUIC_QLOG_ATTR_CONN_ID,	/* binary: connection ID */
	TQUIC_QLOG_ATTR_PATH_ID,	/* __u32 path ID */
	TQUIC_QLOG_ATTR_DATA,		/* binary: event-specific data */
	TQUIC_QLOG_ATTR_JSON,		/* string: JSON-formatted event */
	TQUIC_QLOG_ATTR_SEVERITY,	/* __u32 enum tquic_qlog_severity */
	TQUIC_QLOG_ATTR_CATEGORY,	/* __u32 enum tquic_qlog_category */

	__TQUIC_QLOG_ATTR_MAX,
};

#define TQUIC_QLOG_ATTR_MAX	(__TQUIC_QLOG_ATTR_MAX - 1)

/*
 * =============================================================================
 * Event Data Structures (draft-12 compliant)
 * =============================================================================
 */

/**
 * struct tquic_qlog_packet_header - Packet header info (draft-12 Section 6.5)
 * @packet_number: QUIC packet number
 * @packet_type: enum tquic_qlog_packet_type
 * @packet_size: Total packet size in bytes
 * @payload_length: Payload length (excluding header)
 * @version: QUIC version (for long headers)
 * @scid_length: Source CID length
 * @dcid_length: Destination CID length
 * @key_phase: Key phase bit (for 1-RTT)
 * @spin_bit: Spin bit value (for 1-RTT)
 *
 * Common header structure used by packet events.
 */
struct tquic_qlog_packet_header {
	__u64	packet_number;
	__u32	packet_type;
	__u32	packet_size;
	__u32	payload_length;
	__u32	version;
	__u8	scid_length;
	__u8	dcid_length;
	__u8	key_phase;
	__u8	spin_bit;
};

/**
 * struct tquic_qlog_packet_event - Packet sent/received event (draft-12 Section 6.5-6.6)
 * @header: Packet header information
 * @path_id: Path ID for multipath
 * @frames_count: Number of frames in packet
 * @is_coalesced: Whether packet is coalesced with others
 * @is_mtu_probe: Whether this is an MTU probe packet
 * @trigger: What triggered this packet (for sent)
 * @ecn: ECN marking (for received)
 * @ack_eliciting: Whether packet is ACK-eliciting
 * @in_flight: Whether packet counts as in-flight
 */
struct tquic_qlog_packet_event {
	struct tquic_qlog_packet_header header;
	__u32	path_id;
	__u16	frames_count;
	__u8	is_coalesced;
	__u8	is_mtu_probe;
	__u32	trigger;
	__u8	ecn;
	__u8	ack_eliciting;
	__u8	in_flight;
	__u8	reserved;
};

/* Legacy structure for backward compatibility */
struct tquic_qlog_packet_event_legacy {
	__u64	packet_number;
	__u32	packet_type;
	__u32	packet_size;
	__u32	path_id;
	__u16	frames_count;
	__u8	ack_eliciting;
	__u8	in_flight;
};

/**
 * struct tquic_qlog_packet_dropped_event - Packet dropped event (draft-12 Section 6.7)
 * @header: Packet header (if available)
 * @raw_length: Raw packet length
 * @drop_reason: enum tquic_qlog_packet_drop_reason
 * @path_id: Path ID
 */
struct tquic_qlog_packet_dropped_event {
	struct tquic_qlog_packet_header header;
	__u32	raw_length;
	__u32	drop_reason;
	__u32	path_id;
	__u32	reserved;
};

/**
 * struct tquic_qlog_packet_buffered_event - Packet buffered event (draft-12 Section 6.8)
 * @header: Packet header
 * @buffer_reason: enum tquic_qlog_packet_buffer_reason
 * @path_id: Path ID
 */
struct tquic_qlog_packet_buffered_event {
	struct tquic_qlog_packet_header header;
	__u32	buffer_reason;
	__u32	path_id;
};

/**
 * struct tquic_qlog_metrics_event - Recovery metrics (draft-12 Section 7.2)
 * @min_rtt: Minimum RTT (microseconds)
 * @smoothed_rtt: Smoothed RTT (microseconds)
 * @latest_rtt: Latest RTT sample (microseconds)
 * @rtt_variance: RTT variance (microseconds)
 * @cwnd: Congestion window (bytes)
 * @bytes_in_flight: Bytes currently in flight
 * @ssthresh: Slow start threshold (bytes)
 * @pacing_rate: Pacing rate (bytes/second)
 * @pto_count: Number of PTOs
 * @packets_in_flight: Number of packets in flight
 * @path_id: Path ID for multipath
 */
struct tquic_qlog_metrics_event {
	__u64	min_rtt;
	__u64	smoothed_rtt;
	__u64	latest_rtt;
	__u64	rtt_variance;
	__u64	cwnd;
	__u64	bytes_in_flight;
	__u64	ssthresh;
	__u64	pacing_rate;
	__u32	pto_count;
	__u32	packets_in_flight;
	__u32	path_id;
	__u32	reserved;
};

/**
 * struct tquic_qlog_congestion_event - CC state change (draft-12 Section 7.3)
 * @old_state: Previous CC state (enum tquic_qlog_cc_state)
 * @new_state: New CC state
 * @trigger: What triggered the transition (enum tquic_qlog_cc_trigger)
 * @path_id: Path ID for multipath
 */
struct tquic_qlog_congestion_event {
	__u32	old_state;
	__u32	new_state;
	__u32	trigger;
	__u32	path_id;
};

/**
 * struct tquic_qlog_loss_timer_event - Loss timer event (draft-12 Section 7.4)
 * @timer_type: Timer type (enum tquic_qlog_timer_type)
 * @timer_event: Timer event (enum tquic_qlog_timer_event)
 * @path_id: Path ID for multipath
 * @delta: Time until timer fires (microseconds), 0 if cancelled
 * @packet_number_space: Packet number space (for PTO)
 */
struct tquic_qlog_loss_timer_event {
	__u32	timer_type;
	__u32	timer_event;
	__u32	path_id;
	__u32	packet_number_space;
	__u64	delta;
};

/**
 * struct tquic_qlog_packet_lost_event - Packet lost event (draft-12 Section 7.5)
 * @header: Lost packet header
 * @path_id: Path ID
 * @trigger: What triggered loss detection
 */
struct tquic_qlog_packet_lost_event {
	struct tquic_qlog_packet_header header;
	__u32	path_id;
	__u32	trigger;
};

/**
 * struct tquic_qlog_key_event - Key update event (draft-12 Section 8.1)
 * @key_type: Type of key (enum tquic_qlog_key_type)
 * @key_phase: Key phase bit
 * @generation: Key generation number
 * @trigger: What triggered the key event (enum tquic_qlog_key_trigger)
 */
struct tquic_qlog_key_event {
	__u32	key_type;
	__u32	key_phase;
	__u32	generation;
	__u32	trigger;
};

/**
 * struct tquic_qlog_connection_event - Connection state event (draft-12 Section 5.2)
 * @old_state: Previous connection state (enum tquic_qlog_conn_state)
 * @new_state: New connection state
 * @version: QUIC version
 * @error_code: Error code (for close events)
 * @reason_phrase_len: Length of reason phrase
 */
struct tquic_qlog_connection_event {
	__u32	old_state;
	__u32	new_state;
	__u32	version;
	__u32	reserved;
	__u64	error_code;
	__u32	reason_phrase_len;
	__u32	reserved2;
};

/**
 * struct tquic_qlog_path_event - Path update event (draft-12 Section 5.6)
 * @old_state: Previous path state (enum tquic_qlog_path_state)
 * @new_state: New path state
 * @path_id: Path identifier
 * @mtu: Path MTU
 * @local_addr_len: Length of local address
 * @remote_addr_len: Length of remote address
 */
struct tquic_qlog_path_event {
	__u32	old_state;
	__u32	new_state;
	__u32	path_id;
	__u32	mtu;
	__u16	local_addr_len;
	__u16	remote_addr_len;
	__u32	reserved;
};

/**
 * struct tquic_qlog_ecn_event - ECN state event (draft-12 Section 7.7)
 * @old_state: Previous ECN state (enum tquic_qlog_ecn_state)
 * @new_state: New ECN state
 * @path_id: Path ID
 * @ect0_count: ECT(0) packets count
 * @ect1_count: ECT(1) packets count
 * @ce_count: CE packets count
 */
struct tquic_qlog_ecn_event {
	__u32	old_state;
	__u32	new_state;
	__u32	path_id;
	__u32	reserved;
	__u64	ect0_count;
	__u64	ect1_count;
	__u64	ce_count;
};

/*
 * =============================================================================
 * Ring Buffer Entry
 * =============================================================================
 */

/**
 * struct tquic_qlog_event_entry - Ring buffer entry
 * @timestamp_ns: Timestamp in nanoseconds since boot
 * @event_type: Event type (enum tquic_qlog_event)
 * @severity: Event severity (enum tquic_qlog_severity)
 * @category: Event category (enum tquic_qlog_category)
 * @data_len: Length of event-specific data
 * @path_id: Path ID (for path-specific events)
 * @data: Event-specific data (union of event structs)
 */
struct tquic_qlog_event_entry {
	__u64	timestamp_ns;
	__u32	event_type;
	__u8	severity;
	__u8	category;
	__u16	data_len;
	__u32	path_id;
	__u32	reserved;
	union {
		struct tquic_qlog_packet_event packet;
		struct tquic_qlog_packet_dropped_event packet_dropped;
		struct tquic_qlog_packet_buffered_event packet_buffered;
		struct tquic_qlog_packet_lost_event packet_lost;
		struct tquic_qlog_metrics_event metrics;
		struct tquic_qlog_congestion_event congestion;
		struct tquic_qlog_loss_timer_event timer;
		struct tquic_qlog_key_event key;
		struct tquic_qlog_connection_event connection;
		struct tquic_qlog_path_event path;
		struct tquic_qlog_ecn_event ecn;
		__u8 raw[128];
	} data;
};

/* Ring buffer limits */
#define TQUIC_QLOG_RING_MIN		64	/* Minimum ring entries */
#define TQUIC_QLOG_RING_MAX		16384	/* Maximum ring entries */
#define TQUIC_QLOG_RING_DEFAULT		1024	/* Default ring entries */

#endif /* _UAPI_LINUX_TQUIC_QLOG_H */
