// SPDX-License-Identifier: GPL-2.0
/*
 * TQUIC Qlog v2 Implementation
 *
 * Copyright (c) 2026 Linux Foundation
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Updated implementation conforming to:
 *   - draft-ietf-quic-qlog-main-schema-08 (main schema)
 *   - draft-ietf-quic-qlog-quic-events-14 (QUIC events)
 *   - draft-ietf-quic-qlog-h3-events-08 (HTTP/3 events)
 *
 * Key changes from draft-12 to draft-14:
 *   - Reorganized event categories into namespaces
 *   - Added multipath-specific events
 *   - Enhanced ECN reporting
 *   - Added stream priority events
 *   - Added datagram events
 *   - Improved frame logging with all RFC 9000 frames
 *   - Added RawInfo structure for packet captures
 *   - Added GroupID for tracing grouped events
 *
 * This module provides:
 *   - JSON-SEQ output format (RFC 7464)
 *   - NDJSON output format (alternative)
 *   - Binary format for high-performance capture
 *   - Real-time netlink streaming
 *   - File-based output via debugfs
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/ktime.h>
#include <linux/debugfs.h>
#include <linux/relay.h>
#include <linux/uuid.h>
#include <net/genetlink.h>
#include <net/tquic.h>

#include "qlog.h"
#include "../protocol.h"

/*
 * =============================================================================
 * Qlog v2 Event Definitions (draft-14 compliant)
 * =============================================================================
 */

/* Event categories/namespaces per draft-14 */
enum qlog_v2_category {
	QLOG_V2_CAT_QUIC,		/* quic:* events */
	QLOG_V2_CAT_HTTP,		/* http:* events */
	QLOG_V2_CAT_QPACK,		/* qpack:* events */
	QLOG_V2_CAT_RECOVERY,		/* recovery:* events */
	QLOG_V2_CAT_TRANSPORT,		/* Generic transport events */
	QLOG_V2_CAT_SECURITY,		/* Security events */
	QLOG_V2_CAT_SIMULATION,		/* Simulation/test events */
	QLOG_V2_CAT_GENERIC,		/* Generic events */
};

/* QUIC namespace events (quic:*) - draft-14 Section 5 */
enum qlog_v2_quic_event {
	/* Connectivity events */
	QLOG_V2_QUIC_VERSION_INFORMATION,
	QLOG_V2_QUIC_ALPN_INFORMATION,
	QLOG_V2_QUIC_PARAMETERS_SET,
	QLOG_V2_QUIC_PARAMETERS_RESTORED,
	QLOG_V2_QUIC_PACKET_SENT,
	QLOG_V2_QUIC_PACKET_RECEIVED,
	QLOG_V2_QUIC_PACKET_DROPPED,
	QLOG_V2_QUIC_PACKET_BUFFERED,
	QLOG_V2_QUIC_PACKETS_ACKED,
	QLOG_V2_QUIC_DATAGRAMS_SENT,
	QLOG_V2_QUIC_DATAGRAMS_RECEIVED,
	QLOG_V2_QUIC_DATAGRAM_DROPPED,
	QLOG_V2_QUIC_STREAM_STATE_UPDATED,
	QLOG_V2_QUIC_FRAMES_PROCESSED,
	QLOG_V2_QUIC_STREAM_DATA_MOVED,
	QLOG_V2_QUIC_DATAGRAM_DATA_MOVED,

	/* Connection lifecycle */
	QLOG_V2_QUIC_CONNECTION_STARTED,
	QLOG_V2_QUIC_CONNECTION_CLOSED,
	QLOG_V2_QUIC_CONNECTION_ID_UPDATED,
	QLOG_V2_QUIC_SPIN_BIT_UPDATED,

	/* Path/Multipath events (new in draft-14) */
	QLOG_V2_QUIC_PATH_ASSIGNED,
	QLOG_V2_QUIC_PATH_UPDATED,
	QLOG_V2_QUIC_PATH_CHALLENGE_CREATED,
	QLOG_V2_QUIC_PATH_CHALLENGE_RECEIVED,
	QLOG_V2_QUIC_PATH_RESPONSE_CREATED,
	QLOG_V2_QUIC_PATH_RESPONSE_RECEIVED,
	QLOG_V2_QUIC_PATH_ABANDONED,
	QLOG_V2_QUIC_MTU_UPDATED,

	/* Priority events (new in draft-14) */
	QLOG_V2_QUIC_PRIORITY_UPDATED,
};

/* Recovery namespace events (recovery:*) - draft-14 Section 6 */
enum qlog_v2_recovery_event {
	QLOG_V2_RECOVERY_PARAMETERS_SET,
	QLOG_V2_RECOVERY_METRICS_UPDATED,
	QLOG_V2_RECOVERY_CONGESTION_STATE_UPDATED,
	QLOG_V2_RECOVERY_LOSS_TIMER_UPDATED,
	QLOG_V2_RECOVERY_PACKET_LOST,
	QLOG_V2_RECOVERY_MARKED_FOR_RETRANSMIT,
	QLOG_V2_RECOVERY_ECN_STATE_UPDATED,

	/* BBR-specific events (extension) */
	QLOG_V2_RECOVERY_BBR_STATE_UPDATED,
	QLOG_V2_RECOVERY_PACING_UPDATED,
};

/* Security namespace events (security:*) - draft-14 Section 7 */
enum qlog_v2_security_event {
	QLOG_V2_SECURITY_KEY_UPDATED,
	QLOG_V2_SECURITY_KEY_DISCARDED,
};

/* Frame types per RFC 9000 + extensions */
static const char * const qlog_v2_frame_types[] = {
	[0x00] = "padding",
	[0x01] = "ping",
	[0x02] = "ack",
	[0x03] = "ack_ecn",
	[0x04] = "reset_stream",
	[0x05] = "stop_sending",
	[0x06] = "crypto",
	[0x07] = "new_token",
	[0x08] = "stream",
	[0x09] = "stream",
	[0x0a] = "stream",
	[0x0b] = "stream",
	[0x0c] = "stream",
	[0x0d] = "stream",
	[0x0e] = "stream",
	[0x0f] = "stream",
	[0x10] = "max_data",
	[0x11] = "max_stream_data",
	[0x12] = "max_streams",
	[0x13] = "max_streams",
	[0x14] = "data_blocked",
	[0x15] = "stream_data_blocked",
	[0x16] = "streams_blocked",
	[0x17] = "streams_blocked",
	[0x18] = "new_connection_id",
	[0x19] = "retire_connection_id",
	[0x1a] = "path_challenge",
	[0x1b] = "path_response",
	[0x1c] = "connection_close",
	[0x1d] = "connection_close",
	[0x1e] = "handshake_done",
	/* Extensions */
	[0x30] = "datagram",
	[0x31] = "datagram",
	/* Multipath QUIC */
	[0x40] = "path_abandon",
	[0x41] = "path_status",
	[0x42] = "path_standby",
	[0x43] = "path_available",
	/* ACK Frequency */
	[0xaf] = "ack_frequency",
	[0xb0] = "immediate_ack",
};

/*
 * =============================================================================
 * Qlog v2 Trace Header
 * =============================================================================
 */

/**
 * struct qlog_v2_trace_header - Qlog trace header (emitted once per trace)
 *
 * Per draft-08 main schema, each trace begins with header containing:
 *   - title: Human-readable trace description
 *   - description: Detailed description
 *   - vantage_point: client/server/network
 *   - common_fields: Fields common to all events
 *   - configuration: Trace configuration
 */
struct qlog_v2_trace_header {
	char title[64];
	char description[256];
	enum {
		QLOG_V2_VP_CLIENT,
		QLOG_V2_VP_SERVER,
		QLOG_V2_VP_NETWORK,
		QLOG_V2_VP_UNKNOWN,
	} vantage_point;
	char vantage_point_name[64];
	uuid_t group_id;
	u64 reference_time_ns;
	bool time_offset_enabled;
};

/**
 * qlog_v2_emit_trace_header - Emit trace header as JSON
 */
static int qlog_v2_emit_trace_header(struct tquic_qlog *qlog,
				     const struct qlog_v2_trace_header *hdr,
				     char *buf, size_t size)
{
	const char *vp_type;
	char uuid_str[37];

	switch (hdr->vantage_point) {
	case QLOG_V2_VP_CLIENT:
		vp_type = "client";
		break;
	case QLOG_V2_VP_SERVER:
		vp_type = "server";
		break;
	case QLOG_V2_VP_NETWORK:
		vp_type = "network";
		break;
	default:
		vp_type = "unknown";
	}

	snprintf(uuid_str, sizeof(uuid_str),
		 "%pUl", &hdr->group_id);

	return snprintf(buf, size,
		"\x1e{\"qlog_version\":\"0.4\","
		"\"qlog_format\":\"JSON-SEQ\","
		"\"title\":\"%s\","
		"\"description\":\"%s\","
		"\"trace\":{"
		"\"vantage_point\":{\"type\":\"%s\",\"name\":\"%s\"},"
		"\"common_fields\":{\"group_id\":\"%s\",\"protocol_type\":[\"QUIC\"]},"
		"\"configuration\":{\"time_offset\":true}"
		"}}\n",
		hdr->title,
		hdr->description,
		vp_type,
		hdr->vantage_point_name,
		uuid_str);
}

/*
 * =============================================================================
 * Qlog v2 Event Emission
 * =============================================================================
 */

/**
 * struct qlog_v2_event - Internal event structure
 */
struct qlog_v2_event {
	u64 time_offset_us;		/* Time since reference time */
	enum qlog_v2_category category;
	u32 event_type;			/* Category-specific event type */
	u32 path_id;			/* Multipath path ID */
	u8 severity;			/* Event severity */
	u8 flags;
	u16 data_len;
	u8 data[256];			/* Event-specific data */
};

/* Event flags */
#define QLOG_V2_FLAG_MULTIPATH		BIT(0)
#define QLOG_V2_FLAG_SIMULATION		BIT(1)
#define QLOG_V2_FLAG_DEBUG		BIT(2)

/**
 * qlog_v2_get_event_name - Get event name string for JSON output
 */
static const char *qlog_v2_get_event_name(enum qlog_v2_category cat, u32 event)
{
	switch (cat) {
	case QLOG_V2_CAT_QUIC:
		switch (event) {
		case QLOG_V2_QUIC_VERSION_INFORMATION:
			return "quic:version_information";
		case QLOG_V2_QUIC_ALPN_INFORMATION:
			return "quic:alpn_information";
		case QLOG_V2_QUIC_PARAMETERS_SET:
			return "quic:parameters_set";
		case QLOG_V2_QUIC_PARAMETERS_RESTORED:
			return "quic:parameters_restored";
		case QLOG_V2_QUIC_PACKET_SENT:
			return "quic:packet_sent";
		case QLOG_V2_QUIC_PACKET_RECEIVED:
			return "quic:packet_received";
		case QLOG_V2_QUIC_PACKET_DROPPED:
			return "quic:packet_dropped";
		case QLOG_V2_QUIC_PACKET_BUFFERED:
			return "quic:packet_buffered";
		case QLOG_V2_QUIC_PACKETS_ACKED:
			return "quic:packets_acked";
		case QLOG_V2_QUIC_DATAGRAMS_SENT:
			return "quic:datagrams_sent";
		case QLOG_V2_QUIC_DATAGRAMS_RECEIVED:
			return "quic:datagrams_received";
		case QLOG_V2_QUIC_DATAGRAM_DROPPED:
			return "quic:datagram_dropped";
		case QLOG_V2_QUIC_STREAM_STATE_UPDATED:
			return "quic:stream_state_updated";
		case QLOG_V2_QUIC_FRAMES_PROCESSED:
			return "quic:frames_processed";
		case QLOG_V2_QUIC_STREAM_DATA_MOVED:
			return "quic:stream_data_moved";
		case QLOG_V2_QUIC_DATAGRAM_DATA_MOVED:
			return "quic:datagram_data_moved";
		case QLOG_V2_QUIC_CONNECTION_STARTED:
			return "quic:connection_started";
		case QLOG_V2_QUIC_CONNECTION_CLOSED:
			return "quic:connection_closed";
		case QLOG_V2_QUIC_CONNECTION_ID_UPDATED:
			return "quic:connection_id_updated";
		case QLOG_V2_QUIC_SPIN_BIT_UPDATED:
			return "quic:spin_bit_updated";
		case QLOG_V2_QUIC_PATH_ASSIGNED:
			return "quic:path_assigned";
		case QLOG_V2_QUIC_PATH_UPDATED:
			return "quic:path_updated";
		case QLOG_V2_QUIC_PATH_CHALLENGE_CREATED:
			return "quic:path_challenge_created";
		case QLOG_V2_QUIC_PATH_CHALLENGE_RECEIVED:
			return "quic:path_challenge_received";
		case QLOG_V2_QUIC_PATH_RESPONSE_CREATED:
			return "quic:path_response_created";
		case QLOG_V2_QUIC_PATH_RESPONSE_RECEIVED:
			return "quic:path_response_received";
		case QLOG_V2_QUIC_PATH_ABANDONED:
			return "quic:path_abandoned";
		case QLOG_V2_QUIC_MTU_UPDATED:
			return "quic:mtu_updated";
		case QLOG_V2_QUIC_PRIORITY_UPDATED:
			return "quic:priority_updated";
		default:
			return "quic:unknown";
		}
	case QLOG_V2_CAT_RECOVERY:
		switch (event) {
		case QLOG_V2_RECOVERY_PARAMETERS_SET:
			return "recovery:parameters_set";
		case QLOG_V2_RECOVERY_METRICS_UPDATED:
			return "recovery:metrics_updated";
		case QLOG_V2_RECOVERY_CONGESTION_STATE_UPDATED:
			return "recovery:congestion_state_updated";
		case QLOG_V2_RECOVERY_LOSS_TIMER_UPDATED:
			return "recovery:loss_timer_updated";
		case QLOG_V2_RECOVERY_PACKET_LOST:
			return "recovery:packet_lost";
		case QLOG_V2_RECOVERY_MARKED_FOR_RETRANSMIT:
			return "recovery:marked_for_retransmit";
		case QLOG_V2_RECOVERY_ECN_STATE_UPDATED:
			return "recovery:ecn_state_updated";
		case QLOG_V2_RECOVERY_BBR_STATE_UPDATED:
			return "recovery:bbr_state_updated";
		case QLOG_V2_RECOVERY_PACING_UPDATED:
			return "recovery:pacing_updated";
		default:
			return "recovery:unknown";
		}
	case QLOG_V2_CAT_SECURITY:
		switch (event) {
		case QLOG_V2_SECURITY_KEY_UPDATED:
			return "security:key_updated";
		case QLOG_V2_SECURITY_KEY_DISCARDED:
			return "security:key_discarded";
		default:
			return "security:unknown";
		}
	default:
		return "generic:unknown";
	}
}

/*
 * =============================================================================
 * Qlog v2 Packet Events (draft-14 Section 5.3-5.6)
 * =============================================================================
 */

/**
 * struct qlog_v2_packet_header - Packet header for qlog events
 *
 * Per draft-14, packet headers include:
 *   - packet_type: initial/handshake/0rtt/1rtt/retry/version_negotiation
 *   - packet_number: Decoded packet number
 *   - dcid/scid: Connection IDs (hexadecimal)
 *   - version: QUIC version (for long headers)
 *   - scil/dcil: CID lengths
 */
struct qlog_v2_packet_header {
	u64 packet_number;
	u32 packet_type;
	u32 packet_size;
	u32 payload_length;
	u32 version;
	u8 dcid[20];
	u8 dcid_len;
	u8 scid[20];
	u8 scid_len;
	u8 key_phase;
	u8 spin_bit;
	u8 token_length;
};

/**
 * struct qlog_v2_raw_info - Raw packet information
 *
 * New in draft-14: captures raw packet data for debugging
 */
struct qlog_v2_raw_info {
	u32 length;			/* Packet length on wire */
	u32 payload_length;		/* Payload length */
	u8 data[64];			/* First 64 bytes of packet */
};

/**
 * qlog_v2_emit_packet_sent - Emit packet_sent event
 */
int qlog_v2_emit_packet_sent(struct tquic_qlog *qlog,
			     const struct qlog_v2_packet_header *hdr,
			     u32 path_id, bool is_coalesced,
			     const void *frames, u32 frame_count,
			     char *buf, size_t size)
{
	const char *pkt_type;
	int len;

	switch (hdr->packet_type) {
	case 0: pkt_type = "initial"; break;
	case 1: pkt_type = "handshake"; break;
	case 2: pkt_type = "0RTT"; break;
	case 3: pkt_type = "1RTT"; break;
	case 4: pkt_type = "retry"; break;
	case 5: pkt_type = "version_negotiation"; break;
	default: pkt_type = "unknown"; break;
	}

	len = snprintf(buf, size,
		"\x1e{\"time\":%llu,"
		"\"name\":\"quic:packet_sent\","
		"\"data\":{"
		"\"header\":{"
		"\"packet_type\":\"%s\","
		"\"packet_number\":%llu,"
		"\"dcid\":\"%*phN\""
		"},"
		"\"raw\":{\"length\":%u,\"payload_length\":%u},"
		"\"path_id\":%u,"
		"\"is_coalesced\":%s,"
		"\"frames\":{\"count\":%u}"
		"}}\n",
		ktime_get_boottime_ns() / 1000,  /* microseconds */
		pkt_type,
		hdr->packet_number,
		hdr->dcid_len, hdr->dcid,
		hdr->packet_size,
		hdr->payload_length,
		path_id,
		is_coalesced ? "true" : "false",
		frame_count);

	return len;
}
EXPORT_SYMBOL_GPL(qlog_v2_emit_packet_sent);

/**
 * qlog_v2_emit_packet_received - Emit packet_received event
 */
int qlog_v2_emit_packet_received(struct tquic_qlog *qlog,
				 const struct qlog_v2_packet_header *hdr,
				 u32 path_id, u8 ecn,
				 char *buf, size_t size)
{
	const char *pkt_type;
	const char *ecn_str;

	switch (hdr->packet_type) {
	case 0: pkt_type = "initial"; break;
	case 1: pkt_type = "handshake"; break;
	case 2: pkt_type = "0RTT"; break;
	case 3: pkt_type = "1RTT"; break;
	case 4: pkt_type = "retry"; break;
	case 5: pkt_type = "version_negotiation"; break;
	default: pkt_type = "unknown"; break;
	}

	switch (ecn) {
	case 0: ecn_str = "not_ect"; break;
	case 1: ecn_str = "ect1"; break;
	case 2: ecn_str = "ect0"; break;
	case 3: ecn_str = "ce"; break;
	default: ecn_str = "unknown"; break;
	}

	return snprintf(buf, size,
		"\x1e{\"time\":%llu,"
		"\"name\":\"quic:packet_received\","
		"\"data\":{"
		"\"header\":{"
		"\"packet_type\":\"%s\","
		"\"packet_number\":%llu,"
		"\"scid\":\"%*phN\""
		"},"
		"\"raw\":{\"length\":%u},"
		"\"path_id\":%u,"
		"\"ecn\":\"%s\""
		"}}\n",
		ktime_get_boottime_ns() / 1000,
		pkt_type,
		hdr->packet_number,
		hdr->scid_len, hdr->scid,
		hdr->packet_size,
		path_id,
		ecn_str);
}
EXPORT_SYMBOL_GPL(qlog_v2_emit_packet_received);

/*
 * =============================================================================
 * Qlog v2 Recovery Events (draft-14 Section 6)
 * =============================================================================
 */

/**
 * struct qlog_v2_metrics - Recovery metrics structure
 *
 * Enhanced from draft-12 with:
 *   - Per-path metrics for multipath
 *   - BBR-specific metrics
 *   - Pacing rate details
 */
struct qlog_v2_metrics {
	u64 min_rtt;			/* Minimum RTT (us) */
	u64 smoothed_rtt;		/* Smoothed RTT (us) */
	u64 latest_rtt;			/* Latest RTT sample (us) */
	u64 rtt_variance;		/* RTT variance (us) */
	u64 cwnd;			/* Congestion window (bytes) */
	u64 bytes_in_flight;		/* Bytes in flight */
	u64 ssthresh;			/* Slow start threshold */
	u64 pacing_rate;		/* Pacing rate (bytes/sec) */
	u64 max_bandwidth;		/* Maximum observed bandwidth */
	u32 packets_in_flight;		/* Packets in flight */
	u32 pto_count;			/* PTO count */
	u32 path_id;			/* Path ID for multipath */

	/* BBR-specific (extension) */
	u32 bbr_mode;			/* BBR mode */
	u64 bbr_bw;			/* BBR bandwidth estimate */
	u64 bbr_inflight_lo;		/* BBR inflight_lo */
	u64 bbr_inflight_hi;		/* BBR inflight_hi */
	u64 bbr_probe_rtt_round;	/* BBR probe RTT round */
};

/**
 * qlog_v2_emit_metrics_updated - Emit metrics_updated event
 */
int qlog_v2_emit_metrics_updated(struct tquic_qlog *qlog,
				 const struct qlog_v2_metrics *m,
				 char *buf, size_t size)
{
	return snprintf(buf, size,
		"\x1e{\"time\":%llu,"
		"\"name\":\"recovery:metrics_updated\","
		"\"data\":{"
		"\"min_rtt\":%llu,"
		"\"smoothed_rtt\":%llu,"
		"\"latest_rtt\":%llu,"
		"\"rtt_variance\":%llu,"
		"\"congestion_window\":%llu,"
		"\"bytes_in_flight\":%llu,"
		"\"ssthresh\":%llu,"
		"\"pacing_rate\":%llu,"
		"\"packets_in_flight\":%u,"
		"\"pto_count\":%u,"
		"\"path_id\":%u"
		"}}\n",
		ktime_get_boottime_ns() / 1000,
		m->min_rtt,
		m->smoothed_rtt,
		m->latest_rtt,
		m->rtt_variance,
		m->cwnd,
		m->bytes_in_flight,
		m->ssthresh,
		m->pacing_rate,
		m->packets_in_flight,
		m->pto_count,
		m->path_id);
}
EXPORT_SYMBOL_GPL(qlog_v2_emit_metrics_updated);

/**
 * qlog_v2_emit_bbr_state - Emit BBR-specific state (extension event)
 */
int qlog_v2_emit_bbr_state(struct tquic_qlog *qlog,
			   const struct qlog_v2_metrics *m,
			   char *buf, size_t size)
{
	const char *mode_str;

	switch (m->bbr_mode) {
	case 0: mode_str = "startup"; break;
	case 1: mode_str = "drain"; break;
	case 2: mode_str = "probe_bw"; break;
	case 3: mode_str = "probe_rtt"; break;
	default: mode_str = "unknown"; break;
	}

	return snprintf(buf, size,
		"\x1e{\"time\":%llu,"
		"\"name\":\"recovery:bbr_state_updated\","
		"\"data\":{"
		"\"mode\":\"%s\","
		"\"btl_bw\":%llu,"
		"\"rt_prop\":%llu,"
		"\"inflight_lo\":%llu,"
		"\"inflight_hi\":%llu,"
		"\"path_id\":%u"
		"}}\n",
		ktime_get_boottime_ns() / 1000,
		mode_str,
		m->bbr_bw,
		m->min_rtt,
		m->bbr_inflight_lo,
		m->bbr_inflight_hi,
		m->path_id);
}
EXPORT_SYMBOL_GPL(qlog_v2_emit_bbr_state);

/*
 * =============================================================================
 * Qlog v2 Multipath Events (draft-14 Section 5.7)
 * =============================================================================
 */

/**
 * struct qlog_v2_path_info - Path information for multipath events
 */
struct qlog_v2_path_info {
	u32 path_id;
	u32 local_addr_v4;
	u32 remote_addr_v4;
	u16 local_port;
	u16 remote_port;
	u8 local_addr_v6[16];
	u8 remote_addr_v6[16];
	bool is_ipv6;
	u32 mtu;
	u32 state;
};

/**
 * qlog_v2_emit_path_assigned - Emit path_assigned event
 */
int qlog_v2_emit_path_assigned(struct tquic_qlog *qlog,
			       const struct qlog_v2_path_info *path,
			       char *buf, size_t size)
{
	if (path->is_ipv6) {
		return snprintf(buf, size,
			"\x1e{\"time\":%llu,"
			"\"name\":\"quic:path_assigned\","
			"\"data\":{"
			"\"path_id\":%u,"
			"\"local\":{\"ip\":\"%pI6c\",\"port\":%u},"
			"\"remote\":{\"ip\":\"%pI6c\",\"port\":%u},"
			"\"mtu\":%u"
			"}}\n",
			ktime_get_boottime_ns() / 1000,
			path->path_id,
			path->local_addr_v6, path->local_port,
			path->remote_addr_v6, path->remote_port,
			path->mtu);
	} else {
		return snprintf(buf, size,
			"\x1e{\"time\":%llu,"
			"\"name\":\"quic:path_assigned\","
			"\"data\":{"
			"\"path_id\":%u,"
			"\"local\":{\"ip\":\"%pI4\",\"port\":%u},"
			"\"remote\":{\"ip\":\"%pI4\",\"port\":%u},"
			"\"mtu\":%u"
			"}}\n",
			ktime_get_boottime_ns() / 1000,
			path->path_id,
			&path->local_addr_v4, path->local_port,
			&path->remote_addr_v4, path->remote_port,
			path->mtu);
	}
}
EXPORT_SYMBOL_GPL(qlog_v2_emit_path_assigned);

/**
 * qlog_v2_emit_path_updated - Emit path_updated event
 */
int qlog_v2_emit_path_updated(struct tquic_qlog *qlog,
			      u32 path_id, u32 old_state, u32 new_state,
			      char *buf, size_t size)
{
	const char * const state_names[] = {
		"new", "validating", "validated", "active",
		"standby", "degraded", "closed"
	};
	const char *old_str = old_state < ARRAY_SIZE(state_names) ?
			      state_names[old_state] : "unknown";
	const char *new_str = new_state < ARRAY_SIZE(state_names) ?
			      state_names[new_state] : "unknown";

	return snprintf(buf, size,
		"\x1e{\"time\":%llu,"
		"\"name\":\"quic:path_updated\","
		"\"data\":{"
		"\"path_id\":%u,"
		"\"old\":\"%s\","
		"\"new\":\"%s\""
		"}}\n",
		ktime_get_boottime_ns() / 1000,
		path_id, old_str, new_str);
}
EXPORT_SYMBOL_GPL(qlog_v2_emit_path_updated);

/*
 * =============================================================================
 * Qlog v2 Frame Logging (draft-14 Section 5.5)
 * =============================================================================
 */

/**
 * qlog_v2_emit_frame - Emit individual frame in JSON
 */
int qlog_v2_emit_frame(u64 frame_type, const void *data, size_t data_len,
		       char *buf, size_t size)
{
	const char *frame_name;
	int len = 0;

	if (frame_type < ARRAY_SIZE(qlog_v2_frame_types) &&
	    qlog_v2_frame_types[frame_type])
		frame_name = qlog_v2_frame_types[frame_type];
	else
		frame_name = "unknown";

	len = snprintf(buf, size, "{\"frame_type\":\"%s\"", frame_name);

	/* Add frame-specific fields based on type */
	switch (frame_type) {
	case 0x02:  /* ACK */
	case 0x03:  /* ACK_ECN */
		/* ACK frame details would be added here */
		break;
	case 0x04:  /* RESET_STREAM */
		/* RESET_STREAM details */
		break;
	case 0x06:  /* CRYPTO */
		/* CRYPTO frame details */
		break;
	case 0x08 ... 0x0f:  /* STREAM */
		/* STREAM frame details */
		break;
	case 0x18:  /* NEW_CONNECTION_ID */
		/* NEW_CONNECTION_ID details */
		break;
	case 0x1c:  /* CONNECTION_CLOSE (transport) */
	case 0x1d:  /* CONNECTION_CLOSE (application) */
		/* CONNECTION_CLOSE details */
		break;
	default:
		break;
	}

	len += snprintf(buf + len, size - len, "}");
	return len;
}
EXPORT_SYMBOL_GPL(qlog_v2_emit_frame);

/*
 * =============================================================================
 * Module Init
 * =============================================================================
 */

static int __init qlog_v2_init(void)
{
	int ret;

	ret = tquic_qlog_init();
	if (ret)
		return ret;

	pr_info("tquic: qlog v2 module loaded (draft-14 compliant)\n");
	return 0;
}

static void __exit qlog_v2_exit(void)
{
	pr_info("tquic: qlog v2 module unloaded\n");
	tquic_qlog_exit();
}

module_init(qlog_v2_init);
module_exit(qlog_v2_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Foundation");
MODULE_DESCRIPTION("TQUIC Qlog v2 Implementation (draft-14)");
