// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC Qlog Tracing Support
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Implements qlog event logging for QUIC connections per:
 *   draft-ietf-quic-qlog-main-schema
 *   draft-ietf-quic-qlog-quic-events-12
 *
 * Qlog provides structured logging of QUIC protocol events for
 * debugging, performance analysis, and interoperability testing.
 *
 * Features:
 *   - Ring buffer storage for efficient event capture
 *   - Netlink relay for real-time event streaming
 *   - JSON-SEQ output format for qlog tooling compatibility
 *   - Per-event filtering via bitmask and severity
 *   - Lock-free ring buffer for fast-path logging
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/ktime.h>
#include <linux/poll.h>
#include <linux/uaccess.h>
#include <net/genetlink.h>
#include <net/sock.h>
#include <net/tquic.h>
#include <uapi/linux/tquic_qlog.h>
#include "qlog.h"
#include "../protocol.h"

/*
 * Netlink family for qlog events (extend existing TQUIC family)
 */
extern struct genl_family tquic_genl_family;

/*
 * Multicast group for qlog events
 */
static const struct genl_multicast_group tquic_qlog_mcgrps[] __maybe_unused = {
	[0] = { .name = "qlog", },
};

/*
 * =============================================================================
 * Event Name Tables (draft-12 compliant)
 * =============================================================================
 */

/* Event type names for JSON output per draft-12 */
static const char * const qlog_event_names[] = {
	/* Connectivity events */
	[QLOG_CONNECTIVITY_SERVER_LISTENING]	= "connectivity:server_listening",
	[QLOG_CONNECTIVITY_CONNECTION_STARTED]	= "connectivity:connection_started",
	[QLOG_CONNECTIVITY_CONNECTION_CLOSED]	= "connectivity:connection_closed",
	[QLOG_CONNECTIVITY_CONNECTION_ID_UPDATED] = "connectivity:connection_id_updated",
	[QLOG_CONNECTIVITY_SPIN_BIT_UPDATED]	= "connectivity:spin_bit_updated",
	[QLOG_CONNECTIVITY_PATH_UPDATED]	= "connectivity:path_updated",

	/* Transport events */
	[QLOG_TRANSPORT_VERSION_INFORMATION]	= "transport:version_information",
	[QLOG_TRANSPORT_ALPN_INFORMATION]	= "transport:alpn_information",
	[QLOG_TRANSPORT_PARAMETERS_SET]		= "transport:parameters_set",
	[QLOG_TRANSPORT_PARAMETERS_RESTORED]	= "transport:parameters_restored",
	[QLOG_TRANSPORT_PACKET_SENT]		= "transport:packet_sent",
	[QLOG_TRANSPORT_PACKET_RECEIVED]	= "transport:packet_received",
	[QLOG_TRANSPORT_PACKET_DROPPED]		= "transport:packet_dropped",
	[QLOG_TRANSPORT_PACKET_BUFFERED]	= "transport:packet_buffered",
	[QLOG_TRANSPORT_PACKETS_ACKED]		= "transport:packets_acked",
	[QLOG_TRANSPORT_DATAGRAMS_SENT]		= "transport:datagrams_sent",
	[QLOG_TRANSPORT_DATAGRAMS_RECEIVED]	= "transport:datagrams_received",
	[QLOG_TRANSPORT_DATAGRAM_DROPPED]	= "transport:datagram_dropped",
	[QLOG_TRANSPORT_STREAM_STATE_UPDATED]	= "transport:stream_state_updated",
	[QLOG_TRANSPORT_FRAMES_PROCESSED]	= "transport:frames_processed",
	[QLOG_TRANSPORT_DATA_MOVED]		= "transport:data_moved",

	/* Recovery events */
	[QLOG_RECOVERY_PARAMETERS_SET]		= "recovery:parameters_set",
	[QLOG_RECOVERY_METRICS_UPDATED]		= "recovery:metrics_updated",
	[QLOG_RECOVERY_CONGESTION_STATE_UPDATED] = "recovery:congestion_state_updated",
	[QLOG_RECOVERY_LOSS_TIMER_UPDATED]	= "recovery:loss_timer_updated",
	[QLOG_RECOVERY_PACKET_LOST]		= "recovery:packet_lost",
	[QLOG_RECOVERY_MARKED_FOR_RETRANSMIT]	= "recovery:marked_for_retransmit",
	[QLOG_RECOVERY_ECN_STATE_UPDATED]	= "recovery:ecn_state_updated",

	/* Security events */
	[QLOG_SECURITY_KEY_UPDATED]		= "security:key_updated",
	[QLOG_SECURITY_KEY_DISCARDED]		= "security:key_discarded",
};

/* Packet type names (draft-12 Section 6.5) */
static const char * const qlog_packet_type_names[] = {
	[QLOG_PKT_INITIAL]		= "initial",
	[QLOG_PKT_HANDSHAKE]		= "handshake",
	[QLOG_PKT_0RTT]			= "0RTT",
	[QLOG_PKT_1RTT]			= "1RTT",
	[QLOG_PKT_RETRY]		= "retry",
	[QLOG_PKT_VERSION_NEG]		= "version_negotiation",
	[QLOG_PKT_STATELESS_RESET]	= "stateless_reset",
	[QLOG_PKT_UNKNOWN]		= "unknown",
};

/* Packet drop reason names (draft-12 Section 6.7) */
static const char * const qlog_drop_reason_names[] = {
	[QLOG_DROP_UNKNOWN]			= "unknown",
	[QLOG_DROP_INTERNAL_ERROR]		= "internal_error",
	[QLOG_DROP_INVALID]			= "invalid",
	[QLOG_DROP_INVALID_LENGTH]		= "invalid_length",
	[QLOG_DROP_UNSUPPORTED_VERSION]		= "unsupported_version",
	[QLOG_DROP_UNEXPECTED_PACKET]		= "unexpected_packet",
	[QLOG_DROP_UNEXPECTED_SOURCE_CID]	= "unexpected_source_connection_id",
	[QLOG_DROP_UNEXPECTED_VERSION]		= "unexpected_version",
	[QLOG_DROP_DUPLICATE]			= "duplicate",
	[QLOG_DROP_KEY_UNAVAILABLE]		= "key_unavailable",
	[QLOG_DROP_DECRYPTION_FAILURE]		= "decryption_failure",
	[QLOG_DROP_HEADER_PARSE_ERROR]		= "header_parse_error",
	[QLOG_DROP_PAYLOAD_PARSE_ERROR]		= "payload_parse_error",
	[QLOG_DROP_PROTOCOL_VIOLATION]		= "protocol_violation",
	[QLOG_DROP_CONGESTION_CONTROL]		= "congestion_control",
	[QLOG_DROP_CONNECTION_UNKNOWN]		= "connection_unknown",
	[QLOG_DROP_DOS_PREVENTION]		= "dos_prevention",
	[QLOG_DROP_NO_LISTENER]			= "no_listener",
};

/* CC state names (draft-12 Section 7.3) */
static const char * const qlog_cc_state_names[] = {
	[QLOG_CC_SLOW_START]		= "slow_start",
	[QLOG_CC_CONGESTION_AVOIDANCE]	= "congestion_avoidance",
	[QLOG_CC_APPLICATION_LIMITED]	= "application_limited",
	[QLOG_CC_RECOVERY]		= "recovery",
};

/* Timer type names (draft-12 Section 7.4) */
static const char * const qlog_timer_type_names[] = {
	[QLOG_TIMER_ACK]	= "ack",
	[QLOG_TIMER_PTO]	= "pto",
	[QLOG_TIMER_IDLE]	= "idle",
	[QLOG_TIMER_HANDSHAKE]	= "handshake",
};

/* Timer event names */
static const char * const qlog_timer_event_names[] = {
	[QLOG_TIMER_SET]	= "set",
	[QLOG_TIMER_EXPIRED]	= "expired",
	[QLOG_TIMER_CANCELLED]	= "cancelled",
};

/* Key type names (draft-12 Section 8.1) */
static const char * const qlog_key_type_names[] = {
	[QLOG_KEY_SERVER_INITIAL_SECRET]	= "server_initial_secret",
	[QLOG_KEY_CLIENT_INITIAL_SECRET]	= "client_initial_secret",
	[QLOG_KEY_SERVER_HANDSHAKE_SECRET]	= "server_handshake_secret",
	[QLOG_KEY_CLIENT_HANDSHAKE_SECRET]	= "client_handshake_secret",
	[QLOG_KEY_SERVER_0RTT_SECRET]		= "server_0rtt_secret",
	[QLOG_KEY_CLIENT_0RTT_SECRET]		= "client_0rtt_secret",
	[QLOG_KEY_SERVER_1RTT_SECRET]		= "server_1rtt_secret",
	[QLOG_KEY_CLIENT_1RTT_SECRET]		= "client_1rtt_secret",
};

/*
 * =============================================================================
 * Ring Buffer Implementation
 * =============================================================================
 *
 * Lock-free single-producer ring buffer for event storage.
 * Uses atomic operations for head/tail to allow concurrent read/write.
 */

/**
 * ring_buffer_full - Check if ring buffer is full
 * @qlog: Qlog context
 *
 * Return: true if ring buffer is full
 */
static inline bool ring_buffer_full(struct tquic_qlog *qlog)
{
	u32 head = atomic_read(&qlog->head);
	u32 tail = atomic_read(&qlog->tail);
	u32 next_head = (head + 1) & qlog->ring_mask;

	return next_head == tail;
}

/**
 * ring_buffer_empty - Check if ring buffer is empty
 * @qlog: Qlog context
 *
 * Return: true if ring buffer is empty
 */
static inline bool ring_buffer_empty(struct tquic_qlog *qlog)
{
	return atomic_read(&qlog->head) == atomic_read(&qlog->tail);
}

/**
 * ring_buffer_count - Get number of entries in ring buffer
 * @qlog: Qlog context
 *
 * Return: Number of entries available for reading
 */
static inline u32 ring_buffer_count(struct tquic_qlog *qlog)
{
	u32 head = atomic_read(&qlog->head);
	u32 tail = atomic_read(&qlog->tail);

	if (head >= tail)
		return head - tail;
	return qlog->ring_size - tail + head;
}

/**
 * ring_buffer_alloc_entry - Allocate ring buffer slot
 * @qlog: Qlog context
 *
 * Allocates a slot in the ring buffer for writing.
 * If buffer is full, overwrites oldest entry (lossy).
 *
 * Return: Pointer to entry slot
 */
static struct tquic_qlog_event_entry *ring_buffer_alloc_entry(
						struct tquic_qlog *qlog)
{
	u32 head, next_head, tail;
	struct tquic_qlog_event_entry *entry;

	/*
	 * Use cmpxchg loop for proper lock-free multi-producer safety.
	 * smp_load_acquire / atomic_cmpxchg ensure visibility across CPUs.
	 */
	do {
		head = smp_load_acquire(&qlog->head.counter);
		next_head = (head + 1) & qlog->ring_mask;
		tail = smp_load_acquire(&qlog->tail.counter);

		/* Check if buffer is full */
		if (next_head == tail) {
			u32 new_tail;

			/* Lossy mode: advance tail to overwrite oldest */
			qlog->stats.ring_overflows++;
			qlog->stats.events_dropped++;
			new_tail = (tail + 1) & qlog->ring_mask;
			atomic_cmpxchg(&qlog->tail, tail, new_tail);
		}
	} while (atomic_cmpxchg(&qlog->head, head, next_head) != head);

	entry = &qlog->ring[head];

	return entry;
}

/**
 * qlog_json_escape - Write a JSON-escaped string to a buffer
 * @dst: Destination buffer
 * @dst_len: Destination buffer size
 * @src: Source string (NUL-terminated)
 *
 * Escapes \, ", and control characters (< 0x20) for JSON output.
 * Return: Number of bytes written (excluding NUL), or -ENOSPC.
 */
static int qlog_json_escape(char *dst, size_t dst_len, const char *src)
{
	size_t i = 0;
	const char *s;

	if (!src || !dst || dst_len == 0)
		return 0;

	for (s = src; *s != '\0'; s++) {
		unsigned char c = (unsigned char)*s;

		if (c == '"' || c == '\\') {
			if (i + 2 >= dst_len)
				return -ENOSPC;
			dst[i++] = '\\';
			dst[i++] = c;
		} else if (c < 0x20) {
			/* Encode control chars as \uXXXX */
			if (i + 6 >= dst_len)
				return -ENOSPC;
			i += snprintf(dst + i, dst_len - i, "\\u%04x", c);
		} else {
			if (i + 1 >= dst_len)
				return -ENOSPC;
			dst[i++] = c;
		}
	}
	dst[i] = '\0';
	return i;
}

/*
 * =============================================================================
 * Qlog Context Management
 * =============================================================================
 */

/**
 * tquic_qlog_create - Create qlog context
 * @conn: Connection to attach qlog to
 * @args: Configuration from userspace
 *
 * Return: Pointer to qlog context, or ERR_PTR on failure
 */
struct tquic_qlog *tquic_qlog_create(struct tquic_connection *conn,
				     const struct tquic_qlog_args *args)
{
	struct tquic_qlog *qlog;
	u32 ring_size;

	if (!conn)
		return ERR_PTR(-EINVAL);

	/* Validate and normalize ring size to power of 2 */
	ring_size = args->ring_size;
	if (ring_size == 0)
		ring_size = TQUIC_QLOG_RING_DEFAULT;
	if (ring_size < TQUIC_QLOG_RING_MIN)
		ring_size = TQUIC_QLOG_RING_MIN;
	if (ring_size > TQUIC_QLOG_RING_MAX)
		ring_size = TQUIC_QLOG_RING_MAX;

	/* Round up to power of 2 */
	ring_size = roundup_pow_of_two(ring_size);

	qlog = kzalloc(sizeof(*qlog), GFP_KERNEL);
	if (!qlog)
		return ERR_PTR(-ENOMEM);

	qlog->ring = kvcalloc(ring_size, sizeof(struct tquic_qlog_event_entry),
			      GFP_KERNEL);
	if (!qlog->ring) {
		kfree(qlog);
		return ERR_PTR(-ENOMEM);
	}

	qlog->conn = conn;
	qlog->ring_size = ring_size;
	qlog->ring_mask = ring_size - 1;
	atomic_set(&qlog->head, 0);
	atomic_set(&qlog->tail, 0);

	qlog->event_mask = args->event_mask;
	if (qlog->event_mask == 0)
		qlog->event_mask = QLOG_MASK_ALL;

	qlog->severity_filter = args->severity;
	if (qlog->severity_filter == 0)
		qlog->severity_filter = TQUIC_QLOG_SEV_DEBUG; /* Log all */

	qlog->mode = args->mode;
	qlog->relay_to_userspace = (args->mode == TQUIC_QLOG_MODE_NETLINK);

	spin_lock_init(&qlog->lock);
	refcount_set(&qlog->refcnt, 1);

	memset(&qlog->stats, 0, sizeof(qlog->stats));

	pr_debug("tquic: qlog created, ring_size=%u, mask=0x%llx, severity=%u\n",
		 ring_size, qlog->event_mask, qlog->severity_filter);

	return qlog;
}
EXPORT_SYMBOL_GPL(tquic_qlog_create);

/**
 * tquic_qlog_destroy - Destroy qlog context
 * @qlog: Context to destroy
 */
void tquic_qlog_destroy(struct tquic_qlog *qlog)
{
	if (!qlog)
		return;

	kvfree(qlog->ring);
	kfree(qlog);
}
EXPORT_SYMBOL_GPL(tquic_qlog_destroy);

/**
 * tquic_qlog_put - Release reference to qlog context
 * @qlog: Context to release
 */
void tquic_qlog_put(struct tquic_qlog *qlog)
{
	if (!qlog)
		return;

	if (refcount_dec_and_test(&qlog->refcnt))
		tquic_qlog_destroy(qlog);
}
EXPORT_SYMBOL_GPL(tquic_qlog_put);

/**
 * tquic_qlog_set_mask - Update event filter mask
 * @qlog: Qlog context
 * @mask: New event mask
 */
void tquic_qlog_set_mask(struct tquic_qlog *qlog, u64 mask)
{
	if (!qlog)
		return;

	WRITE_ONCE(qlog->event_mask, mask);
}
EXPORT_SYMBOL_GPL(tquic_qlog_set_mask);

/**
 * tquic_qlog_set_severity - Update severity filter
 * @qlog: Qlog context
 * @severity: Minimum severity to log
 */
void tquic_qlog_set_severity(struct tquic_qlog *qlog, u8 severity)
{
	if (!qlog)
		return;

	WRITE_ONCE(qlog->severity_filter, severity);
}
EXPORT_SYMBOL_GPL(tquic_qlog_set_severity);

/*
 * =============================================================================
 * Internal Event Logging Helpers
 * =============================================================================
 */

/**
 * log_event_common - Common event logging setup
 * @qlog: Qlog context
 * @event_type: Event type
 *
 * Return: Pointer to allocated entry, or NULL if logging disabled/failed
 */
static struct tquic_qlog_event_entry *log_event_common(
					struct tquic_qlog *qlog,
					enum tquic_qlog_event event_type)
{
	struct tquic_qlog_event_entry *entry;
	unsigned long flags;

	if (!tquic_qlog_enabled(qlog, event_type))
		return NULL;

	spin_lock_irqsave(&qlog->lock, flags);
	entry = ring_buffer_alloc_entry(qlog);
	entry->timestamp_ns = ktime_get_boottime_ns();
	entry->event_type = event_type;
	entry->severity = tquic_qlog_event_severity(event_type);
	entry->category = tquic_qlog_event_category(event_type);
	qlog->stats.events_logged++;
	spin_unlock_irqrestore(&qlog->lock, flags);

	return entry;
}

/**
 * relay_event - Relay event to userspace if enabled
 * @qlog: Qlog context
 * @entry: Event entry to relay
 */
static void relay_event(struct tquic_qlog *qlog,
			const struct tquic_qlog_event_entry *entry)
{
	int ret;

	if (!qlog->relay_to_userspace)
		return;

	ret = tquic_qlog_nl_event(qlog, entry);
	if (ret == 0) {
		qlog->stats.events_relayed++;
	} else {
		qlog->stats.netlink_errors++;
		qlog->stats.events_dropped++;
	}
}

/*
 * =============================================================================
 * Transport Events (draft-12 Section 6)
 * =============================================================================
 */

/**
 * fill_packet_header - Fill packet header structure
 */
static void fill_packet_header(struct tquic_qlog_packet_header *hdr,
			       const struct tquic_qlog_packet_info *info)
{
	hdr->packet_number = info->packet_number;
	hdr->packet_type = info->packet_type;
	hdr->packet_size = info->packet_size;
	hdr->payload_length = info->payload_length;
	hdr->version = info->version;
	hdr->key_phase = info->key_phase;
	hdr->spin_bit = info->spin_bit;
	hdr->scid_length = 0;  /* Could be filled from conn */
	hdr->dcid_length = 0;
}

void tquic_qlog_packet_sent(struct tquic_qlog *qlog,
			    const struct tquic_qlog_packet_info *info)
{
	struct tquic_qlog_event_entry *entry;

	entry = log_event_common(qlog, QLOG_TRANSPORT_PACKET_SENT);
	if (!entry)
		return;

	entry->path_id = info->path_id;
	entry->data_len = sizeof(entry->data.packet);

	fill_packet_header(&entry->data.packet.header, info);
	entry->data.packet.path_id = info->path_id;
	entry->data.packet.frames_count = info->frames_count;
	entry->data.packet.is_coalesced = info->is_coalesced ? 1 : 0;
	entry->data.packet.is_mtu_probe = info->is_mtu_probe ? 1 : 0;
	entry->data.packet.ecn = info->ecn;
	entry->data.packet.ack_eliciting = info->ack_eliciting ? 1 : 0;
	entry->data.packet.in_flight = info->in_flight ? 1 : 0;

	relay_event(qlog, entry);
}
EXPORT_SYMBOL_GPL(tquic_qlog_packet_sent);

void tquic_qlog_packet_sent_simple(struct tquic_qlog *qlog,
				   u64 pkt_num, u32 pkt_type, size_t size,
				   u32 path_id, u16 frames, bool ack_eliciting)
{
	struct tquic_qlog_packet_info info = {
		.packet_number = pkt_num,
		.packet_type = pkt_type,
		.packet_size = size,
		.path_id = path_id,
		.frames_count = frames,
		.ack_eliciting = ack_eliciting,
		.in_flight = ack_eliciting,
	};

	tquic_qlog_packet_sent(qlog, &info);
}
EXPORT_SYMBOL_GPL(tquic_qlog_packet_sent_simple);

void tquic_qlog_packet_received(struct tquic_qlog *qlog,
				const struct tquic_qlog_packet_info *info)
{
	struct tquic_qlog_event_entry *entry;

	entry = log_event_common(qlog, QLOG_TRANSPORT_PACKET_RECEIVED);
	if (!entry)
		return;

	entry->path_id = info->path_id;
	entry->data_len = sizeof(entry->data.packet);

	fill_packet_header(&entry->data.packet.header, info);
	entry->data.packet.path_id = info->path_id;
	entry->data.packet.frames_count = info->frames_count;
	entry->data.packet.is_coalesced = info->is_coalesced ? 1 : 0;
	entry->data.packet.ecn = info->ecn;
	entry->data.packet.ack_eliciting = 0;
	entry->data.packet.in_flight = 0;

	relay_event(qlog, entry);
}
EXPORT_SYMBOL_GPL(tquic_qlog_packet_received);

void tquic_qlog_packet_received_simple(struct tquic_qlog *qlog,
				       u64 pkt_num, u32 pkt_type, size_t size,
				       u32 path_id)
{
	struct tquic_qlog_packet_info info = {
		.packet_number = pkt_num,
		.packet_type = pkt_type,
		.packet_size = size,
		.path_id = path_id,
	};

	tquic_qlog_packet_received(qlog, &info);
}
EXPORT_SYMBOL_GPL(tquic_qlog_packet_received_simple);

void tquic_qlog_packet_dropped(struct tquic_qlog *qlog,
			       u32 pkt_type, size_t size,
			       u32 reason, u32 path_id)
{
	struct tquic_qlog_event_entry *entry;

	entry = log_event_common(qlog, QLOG_TRANSPORT_PACKET_DROPPED);
	if (!entry)
		return;

	entry->path_id = path_id;
	entry->data_len = sizeof(entry->data.packet_dropped);
	entry->data.packet_dropped.header.packet_number = 0;
	entry->data.packet_dropped.header.packet_type = pkt_type;
	entry->data.packet_dropped.header.packet_size = size;
	entry->data.packet_dropped.raw_length = size;
	entry->data.packet_dropped.drop_reason = reason;
	entry->data.packet_dropped.path_id = path_id;

	relay_event(qlog, entry);
}
EXPORT_SYMBOL_GPL(tquic_qlog_packet_dropped);

void tquic_qlog_packet_buffered(struct tquic_qlog *qlog,
				u64 pkt_num, u32 pkt_type, size_t size,
				u32 reason, u32 path_id)
{
	struct tquic_qlog_event_entry *entry;

	entry = log_event_common(qlog, QLOG_TRANSPORT_PACKET_BUFFERED);
	if (!entry)
		return;

	entry->path_id = path_id;
	entry->data_len = sizeof(entry->data.packet_buffered);
	entry->data.packet_buffered.header.packet_number = pkt_num;
	entry->data.packet_buffered.header.packet_type = pkt_type;
	entry->data.packet_buffered.header.packet_size = size;
	entry->data.packet_buffered.buffer_reason = reason;
	entry->data.packet_buffered.path_id = path_id;

	relay_event(qlog, entry);
}
EXPORT_SYMBOL_GPL(tquic_qlog_packet_buffered);

/*
 * =============================================================================
 * Recovery Events (draft-12 Section 7)
 * =============================================================================
 */

void tquic_qlog_metrics_updated(struct tquic_qlog *qlog,
				const struct tquic_qlog_metrics_info *metrics)
{
	struct tquic_qlog_event_entry *entry;

	entry = log_event_common(qlog, QLOG_RECOVERY_METRICS_UPDATED);
	if (!entry)
		return;

	entry->path_id = metrics->path_id;
	entry->data_len = sizeof(entry->data.metrics);
	entry->data.metrics.min_rtt = metrics->min_rtt;
	entry->data.metrics.smoothed_rtt = metrics->smoothed_rtt;
	entry->data.metrics.latest_rtt = metrics->latest_rtt;
	entry->data.metrics.rtt_variance = metrics->rtt_variance;
	entry->data.metrics.cwnd = metrics->cwnd;
	entry->data.metrics.bytes_in_flight = metrics->bytes_in_flight;
	entry->data.metrics.ssthresh = metrics->ssthresh;
	entry->data.metrics.pacing_rate = metrics->pacing_rate;
	entry->data.metrics.pto_count = metrics->pto_count;
	entry->data.metrics.packets_in_flight = metrics->packets_in_flight;
	entry->data.metrics.path_id = metrics->path_id;

	relay_event(qlog, entry);
}
EXPORT_SYMBOL_GPL(tquic_qlog_metrics_updated);

void tquic_qlog_metrics_updated_simple(struct tquic_qlog *qlog,
				       u64 cwnd, u64 bytes_in_flight,
				       u64 min_rtt, u64 smoothed_rtt,
				       u32 path_id)
{
	struct tquic_qlog_metrics_info metrics = {
		.min_rtt = min_rtt,
		.smoothed_rtt = smoothed_rtt,
		.cwnd = cwnd,
		.bytes_in_flight = bytes_in_flight,
		.path_id = path_id,
	};

	tquic_qlog_metrics_updated(qlog, &metrics);
}
EXPORT_SYMBOL_GPL(tquic_qlog_metrics_updated_simple);

void tquic_qlog_congestion_state_updated(struct tquic_qlog *qlog,
					 u32 old_state, u32 new_state,
					 u32 trigger, u32 path_id)
{
	struct tquic_qlog_event_entry *entry;

	entry = log_event_common(qlog, QLOG_RECOVERY_CONGESTION_STATE_UPDATED);
	if (!entry)
		return;

	entry->path_id = path_id;
	entry->data_len = sizeof(entry->data.congestion);
	entry->data.congestion.old_state = old_state;
	entry->data.congestion.new_state = new_state;
	entry->data.congestion.trigger = trigger;
	entry->data.congestion.path_id = path_id;

	relay_event(qlog, entry);
}
EXPORT_SYMBOL_GPL(tquic_qlog_congestion_state_updated);

void tquic_qlog_loss_timer_updated(struct tquic_qlog *qlog,
				   u32 timer_type, u32 timer_event,
				   u64 delta_us, u32 pn_space, u32 path_id)
{
	struct tquic_qlog_event_entry *entry;

	entry = log_event_common(qlog, QLOG_RECOVERY_LOSS_TIMER_UPDATED);
	if (!entry)
		return;

	entry->path_id = path_id;
	entry->data_len = sizeof(entry->data.timer);
	entry->data.timer.timer_type = timer_type;
	entry->data.timer.timer_event = timer_event;
	entry->data.timer.delta = delta_us;
	entry->data.timer.packet_number_space = pn_space;
	entry->data.timer.path_id = path_id;

	relay_event(qlog, entry);
}
EXPORT_SYMBOL_GPL(tquic_qlog_loss_timer_updated);

void tquic_qlog_packet_lost(struct tquic_qlog *qlog,
			    u64 pkt_num, u32 pkt_type, size_t size,
			    u32 trigger, u32 path_id)
{
	struct tquic_qlog_event_entry *entry;

	entry = log_event_common(qlog, QLOG_RECOVERY_PACKET_LOST);
	if (!entry)
		return;

	entry->path_id = path_id;
	entry->data_len = sizeof(entry->data.packet_lost);
	entry->data.packet_lost.header.packet_number = pkt_num;
	entry->data.packet_lost.header.packet_type = pkt_type;
	entry->data.packet_lost.header.packet_size = size;
	entry->data.packet_lost.path_id = path_id;
	entry->data.packet_lost.trigger = trigger;

	relay_event(qlog, entry);
}
EXPORT_SYMBOL_GPL(tquic_qlog_packet_lost);

/*
 * =============================================================================
 * Connectivity Events (draft-12 Section 5)
 * =============================================================================
 */

void tquic_qlog_connection_started(struct tquic_qlog *qlog, u32 version)
{
	struct tquic_qlog_event_entry *entry;

	entry = log_event_common(qlog, QLOG_CONNECTIVITY_CONNECTION_STARTED);
	if (!entry)
		return;

	entry->path_id = 0;
	entry->data_len = sizeof(entry->data.connection);
	entry->data.connection.old_state = QLOG_CONN_IDLE;
	entry->data.connection.new_state = QLOG_CONN_CONNECTING;
	entry->data.connection.version = version;
	entry->data.connection.error_code = 0;
	entry->data.connection.reason_phrase_len = 0;

	relay_event(qlog, entry);
}
EXPORT_SYMBOL_GPL(tquic_qlog_connection_started);

void tquic_qlog_connection_closed(struct tquic_qlog *qlog, u64 error_code,
				  const char *reason, size_t reason_len)
{
	struct tquic_qlog_event_entry *entry;

	entry = log_event_common(qlog, QLOG_CONNECTIVITY_CONNECTION_CLOSED);
	if (!entry)
		return;

	entry->path_id = 0;
	entry->data_len = sizeof(entry->data.connection);
	entry->data.connection.old_state = QLOG_CONN_CONNECTED;
	entry->data.connection.new_state = QLOG_CONN_CLOSED;
	entry->data.connection.version = 0;
	entry->data.connection.error_code = error_code;
	entry->data.connection.reason_phrase_len = reason_len;

	relay_event(qlog, entry);
}
EXPORT_SYMBOL_GPL(tquic_qlog_connection_closed);

void tquic_qlog_connection_state_updated(struct tquic_qlog *qlog,
					 u32 old_state, u32 new_state)
{
	/* Map to path_updated for primary path (path_id=0) */
	tquic_qlog_path_updated(qlog, 0, old_state, new_state, 0);
}
EXPORT_SYMBOL_GPL(tquic_qlog_connection_state_updated);

void tquic_qlog_path_updated(struct tquic_qlog *qlog, u32 path_id,
			     u32 old_state, u32 new_state, u32 mtu)
{
	struct tquic_qlog_event_entry *entry;

	entry = log_event_common(qlog, QLOG_CONNECTIVITY_PATH_UPDATED);
	if (!entry)
		return;

	entry->path_id = path_id;
	entry->data_len = sizeof(entry->data.path);
	entry->data.path.old_state = old_state;
	entry->data.path.new_state = new_state;
	entry->data.path.path_id = path_id;
	entry->data.path.mtu = mtu;
	entry->data.path.local_addr_len = 0;
	entry->data.path.remote_addr_len = 0;

	relay_event(qlog, entry);
}
EXPORT_SYMBOL_GPL(tquic_qlog_path_updated);

/*
 * =============================================================================
 * Security Events (draft-12 Section 8)
 * =============================================================================
 */

void tquic_qlog_key_updated(struct tquic_qlog *qlog,
			    u32 key_type, u32 key_phase,
			    u32 generation, u32 trigger)
{
	struct tquic_qlog_event_entry *entry;

	entry = log_event_common(qlog, QLOG_SECURITY_KEY_UPDATED);
	if (!entry)
		return;

	entry->path_id = 0;
	entry->data_len = sizeof(entry->data.key);
	entry->data.key.key_type = key_type;
	entry->data.key.key_phase = key_phase;
	entry->data.key.generation = generation;
	entry->data.key.trigger = trigger;

	relay_event(qlog, entry);
}
EXPORT_SYMBOL_GPL(tquic_qlog_key_updated);

void tquic_qlog_key_discarded(struct tquic_qlog *qlog,
			      u32 key_type, u32 key_phase,
			      u32 generation, u32 trigger)
{
	struct tquic_qlog_event_entry *entry;

	entry = log_event_common(qlog, QLOG_SECURITY_KEY_DISCARDED);
	if (!entry)
		return;

	entry->path_id = 0;
	entry->data_len = sizeof(entry->data.key);
	entry->data.key.key_type = key_type;
	entry->data.key.key_phase = key_phase;
	entry->data.key.generation = generation;
	entry->data.key.trigger = trigger;

	relay_event(qlog, entry);
}
EXPORT_SYMBOL_GPL(tquic_qlog_key_discarded);

/*
 * =============================================================================
 * JSON Output (draft-12 compliant JSON-SEQ format)
 * =============================================================================
 *
 * Generates JSON-SEQ formatted events per draft-ietf-quic-qlog-main-schema.
 * Each line starts with ASCII Record Separator (0x1E) for JSON-SEQ.
 */

/**
 * get_event_name - Get event name string
 * @event_type: Event type
 *
 * Return: Event name string or "unknown"
 */
static const char *get_event_name(u32 event_type)
{
	if (event_type < ARRAY_SIZE(qlog_event_names) &&
	    qlog_event_names[event_type])
		return qlog_event_names[event_type];
	return "unknown:unknown";
}

/**
 * get_packet_type_name - Get packet type string
 * @pkt_type: Packet type
 *
 * Return: Packet type name or "unknown"
 */
static const char *get_packet_type_name(u32 pkt_type)
{
	if (pkt_type < ARRAY_SIZE(qlog_packet_type_names))
		return qlog_packet_type_names[pkt_type];
	return "unknown";
}

/**
 * get_drop_reason_name - Get drop reason string
 * @reason: Drop reason
 *
 * Return: Reason string or "unknown"
 */
static const char *get_drop_reason_name(u32 reason)
{
	if (reason < ARRAY_SIZE(qlog_drop_reason_names))
		return qlog_drop_reason_names[reason];
	return "unknown";
}

/**
 * get_cc_state_name - Get CC state string
 * @state: CC state
 *
 * Return: State name or "unknown"
 */
static const char *get_cc_state_name(u32 state)
{
	if (state < ARRAY_SIZE(qlog_cc_state_names))
		return qlog_cc_state_names[state];
	return "unknown";
}

/**
 * tquic_qlog_emit_json - Emit event as JSON line
 * @qlog: Qlog context
 * @entry: Event entry to format
 * @buf: Output buffer
 * @buflen: Buffer size
 *
 * Return: Number of bytes written, or negative error
 */
int tquic_qlog_emit_json(struct tquic_qlog *qlog,
			 const struct tquic_qlog_event_entry *entry,
			 char *buf, size_t buflen)
{
	const char *event_name;
	char escaped_name[64];
	int len = 0;
	u64 time_ms;

	if (!entry)
		return -EINVAL;

	event_name = get_event_name(entry->event_type);

	/* JSON-escape the event name to prevent malformed output */
	if (qlog_json_escape(escaped_name, sizeof(escaped_name),
			     event_name) < 0)
		return -ENOSPC;

	/* Convert timestamp to milliseconds with 3 decimal places */
	time_ms = entry->timestamp_ns / 1000000;

	/* JSON-SEQ record separator + opening brace */
	len = snprintf(buf, buflen,
		       "\x1e{\"time\":%llu.%03llu,\"name\":\"%s\",\"data\":{",
		       time_ms, (entry->timestamp_ns / 1000) % 1000,
		       escaped_name);

	if (len >= buflen)
		return -ENOSPC;

	/*
	 * CF-419: All subsequent snprintf calls use buflen - len.
	 * Clamp len to buflen to prevent size_t underflow in
	 * the (buflen - len) argument when snprintf returns a
	 * value indicating truncation.
	 */
#define QLOG_CLAMP_LEN() do { if (len >= buflen) len = buflen - 1; } while (0)

	/* Event-specific data per draft-12 */
	switch (entry->event_type) {
	case QLOG_TRANSPORT_PACKET_SENT:
	case QLOG_TRANSPORT_PACKET_RECEIVED: {
		const struct tquic_qlog_packet_event *pkt = &entry->data.packet;
		const char *pkt_type = get_packet_type_name(pkt->header.packet_type);

		len += snprintf(buf + len, buflen - len,
				"\"header\":{\"packet_type\":\"%s\","
				"\"packet_number\":%llu},"
				"\"raw\":{\"length\":%u},"
				"\"is_coalesced\":%s",
				pkt_type, pkt->header.packet_number,
				pkt->header.packet_size,
				pkt->is_coalesced ? "true" : "false");
		QLOG_CLAMP_LEN();

		if (entry->event_type == QLOG_TRANSPORT_PACKET_SENT) {
			len += snprintf(buf + len, buflen - len,
					",\"frames\":{\"count\":%u},"
					"\"is_mtu_probe_packet\":%s",
					pkt->frames_count,
					pkt->is_mtu_probe ? "true" : "false");
		}
		break;
	}

	case QLOG_TRANSPORT_PACKET_DROPPED: {
		const struct tquic_qlog_packet_dropped_event *drop =
			&entry->data.packet_dropped;
		const char *pkt_type = get_packet_type_name(drop->header.packet_type);
		const char *reason = get_drop_reason_name(drop->drop_reason);

		len += snprintf(buf + len, buflen - len,
				"\"header\":{\"packet_type\":\"%s\"},"
				"\"raw\":{\"length\":%u},"
				"\"trigger\":\"%s\"",
				pkt_type, drop->raw_length, reason);
		break;
	}

	case QLOG_TRANSPORT_PACKET_BUFFERED: {
		const struct tquic_qlog_packet_buffered_event *buf_ev =
			&entry->data.packet_buffered;
		const char *pkt_type = get_packet_type_name(buf_ev->header.packet_type);

		len += snprintf(buf + len, buflen - len,
				"\"header\":{\"packet_type\":\"%s\","
				"\"packet_number\":%llu},"
				"\"raw\":{\"length\":%u},"
				"\"trigger\":\"%s\"",
				pkt_type, buf_ev->header.packet_number,
				buf_ev->header.packet_size,
				buf_ev->buffer_reason == QLOG_BUFFER_KEYS_UNAVAILABLE ?
				"keys_unavailable" : "backpressure");
		break;
	}

	case QLOG_RECOVERY_METRICS_UPDATED: {
		const struct tquic_qlog_metrics_event *m = &entry->data.metrics;

		len += snprintf(buf + len, buflen - len,
				"\"min_rtt\":%llu,"
				"\"smoothed_rtt\":%llu,"
				"\"latest_rtt\":%llu,"
				"\"rtt_variance\":%llu,"
				"\"congestion_window\":%llu,"
				"\"bytes_in_flight\":%llu,"
				"\"ssthresh\":%llu",
				m->min_rtt, m->smoothed_rtt, m->latest_rtt,
				m->rtt_variance, m->cwnd, m->bytes_in_flight,
				m->ssthresh);

		if (m->pacing_rate > 0) {
			len += snprintf(buf + len, buflen - len,
					",\"pacing_rate\":%llu", m->pacing_rate);
		}
		if (m->pto_count > 0) {
			len += snprintf(buf + len, buflen - len,
					",\"pto_count\":%u", m->pto_count);
		}
		break;
	}

	case QLOG_RECOVERY_CONGESTION_STATE_UPDATED: {
		const struct tquic_qlog_congestion_event *c = &entry->data.congestion;
		const char *old_name = get_cc_state_name(c->old_state);
		const char *new_name = get_cc_state_name(c->new_state);

		len += snprintf(buf + len, buflen - len,
				"\"old\":\"%s\",\"new\":\"%s\"",
				old_name, new_name);
		break;
	}

	case QLOG_RECOVERY_LOSS_TIMER_UPDATED: {
		const struct tquic_qlog_loss_timer_event *t = &entry->data.timer;
		const char *timer_type = "unknown";
		const char *timer_event = "unknown";

		if (t->timer_type < ARRAY_SIZE(qlog_timer_type_names))
			timer_type = qlog_timer_type_names[t->timer_type];
		if (t->timer_event < ARRAY_SIZE(qlog_timer_event_names))
			timer_event = qlog_timer_event_names[t->timer_event];

		len += snprintf(buf + len, buflen - len,
				"\"timer_type\":\"%s\",\"event_type\":\"%s\"",
				timer_type, timer_event);

		if (t->timer_event == QLOG_TIMER_SET) {
			len += snprintf(buf + len, buflen - len,
					",\"delta\":%llu", t->delta);
		}
		break;
	}

	case QLOG_RECOVERY_PACKET_LOST: {
		const struct tquic_qlog_packet_lost_event *lost = &entry->data.packet_lost;
		const char *pkt_type = get_packet_type_name(lost->header.packet_type);

		len += snprintf(buf + len, buflen - len,
				"\"header\":{\"packet_type\":\"%s\","
				"\"packet_number\":%llu}",
				pkt_type, lost->header.packet_number);
		break;
	}

	case QLOG_SECURITY_KEY_UPDATED:
	case QLOG_SECURITY_KEY_DISCARDED: {
		const struct tquic_qlog_key_event *k = &entry->data.key;
		const char *key_type = "unknown";

		if (k->key_type < ARRAY_SIZE(qlog_key_type_names))
			key_type = qlog_key_type_names[k->key_type];

		len += snprintf(buf + len, buflen - len,
				"\"key_type\":\"%s\",\"generation\":%u",
				key_type, k->generation);

		if (k->key_phase > 0) {
			len += snprintf(buf + len, buflen - len,
					",\"key_phase\":%u", k->key_phase);
		}
		break;
	}

	case QLOG_CONNECTIVITY_CONNECTION_STARTED:
	case QLOG_CONNECTIVITY_CONNECTION_CLOSED: {
		const struct tquic_qlog_connection_event *c = &entry->data.connection;

		if (c->version != 0) {
			len += snprintf(buf + len, buflen - len,
					"\"quic_version\":\"0x%08x\"", c->version);
		}
		if (c->error_code != 0) {
			if (c->version != 0)
				len += snprintf(buf + len, buflen - len, ",");
			len += snprintf(buf + len, buflen - len,
					"\"error_code\":%llu", c->error_code);
		}
		break;
	}

	case QLOG_CONNECTIVITY_PATH_UPDATED: {
		const struct tquic_qlog_path_event *p = &entry->data.path;

		len += snprintf(buf + len, buflen - len,
				"\"path_id\":%u,\"old\":%u,\"new\":%u",
				p->path_id, p->old_state, p->new_state);

		if (p->mtu > 0) {
			len += snprintf(buf + len, buflen - len,
					",\"mtu\":%u", p->mtu);
		}
		break;
	}

	default:
		/* No specific data for this event type */
		break;
	}

	/* Close JSON object */
	len += snprintf(buf + len, buflen - len, "}}\n");

	if (len >= buflen)
		return -ENOSPC;

	return len;
}
EXPORT_SYMBOL_GPL(tquic_qlog_emit_json);

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
 * Return: 0 on success, negative errno on failure
 */
int tquic_qlog_nl_event(struct tquic_qlog *qlog,
			const struct tquic_qlog_event_entry *entry)
{
	struct sk_buff *skb;
	void *hdr;
	char json_buf[1024];
	int json_len;
	int ret = 0;

	if (!qlog || !qlog->conn)
		return -EINVAL;

	skb = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_ATOMIC);
	if (!skb)
		return -ENOMEM;

	hdr = genlmsg_put(skb, 0, 0, &tquic_genl_family, 0,
			  TQUIC_CMD_QLOG_EVENT);
	if (!hdr) {
		nlmsg_free(skb);
		return -EMSGSIZE;
	}

	/* Add event type */
	if (nla_put_u32(skb, TQUIC_QLOG_ATTR_EVENT_TYPE, entry->event_type))
		goto nla_put_failure;

	/* Add timestamp */
	if (nla_put_u64_64bit(skb, TQUIC_QLOG_ATTR_TIMESTAMP,
			      entry->timestamp_ns, TQUIC_QLOG_ATTR_UNSPEC))
		goto nla_put_failure;

	/* Add severity */
	if (nla_put_u32(skb, TQUIC_QLOG_ATTR_SEVERITY, entry->severity))
		goto nla_put_failure;

	/* Add category */
	if (nla_put_u32(skb, TQUIC_QLOG_ATTR_CATEGORY, entry->category))
		goto nla_put_failure;

	/* Add connection ID */
	if (qlog->conn->scid.len > 0) {
		if (nla_put(skb, TQUIC_QLOG_ATTR_CONN_ID,
			    qlog->conn->scid.len, qlog->conn->scid.id))
			goto nla_put_failure;
	}

	/* Add path ID */
	if (nla_put_u32(skb, TQUIC_QLOG_ATTR_PATH_ID, entry->path_id))
		goto nla_put_failure;

	/* Add JSON-formatted event for easy consumption */
	json_len = tquic_qlog_emit_json(qlog, entry, json_buf, sizeof(json_buf));
	if (json_len > 0) {
		if (nla_put_string(skb, TQUIC_QLOG_ATTR_JSON, json_buf))
			goto nla_put_failure;
	}

	genlmsg_end(skb, hdr);

	/* Send to qlog multicast group */
	ret = genlmsg_multicast(&tquic_genl_family, skb, 0,
				TQUIC_NL_GRP_QLOG, GFP_ATOMIC);
	if (ret == -ESRCH) {
		/* No listeners - not an error */
		ret = 0;
	}

	return ret;

nla_put_failure:
	genlmsg_cancel(skb, hdr);
	nlmsg_free(skb);
	return -EMSGSIZE;
}
EXPORT_SYMBOL_GPL(tquic_qlog_nl_event);

/*
 * =============================================================================
 * Ring Buffer Access for Userspace
 * =============================================================================
 */

/**
 * tquic_qlog_read_events - Read events from ring buffer
 * @qlog: Qlog context
 * @buf: User buffer
 * @count: Maximum bytes to read
 *
 * Return: Number of bytes read, or negative error
 */
ssize_t tquic_qlog_read_events(struct tquic_qlog *qlog,
			       char __user *buf, size_t count)
{
	char *json_buf;
	size_t total = 0;
	int json_len;
	u32 tail, head;
	unsigned long flags;

	if (!qlog || !qlog->ring)
		return -EINVAL;

	json_buf = kmalloc(1024, GFP_KERNEL);
	if (!json_buf)
		return -ENOMEM;

	spin_lock_irqsave(&qlog->lock, flags);

	head = atomic_read(&qlog->head);
	tail = atomic_read(&qlog->tail);

	while (tail != head && total < count) {
		struct tquic_qlog_event_entry *entry = &qlog->ring[tail];

		/*
		 * Format the entry as JSON under the lock, then advance
		 * the tail pointer.  This ensures the entry is read
		 * consistently before it could be overwritten by writers.
		 */
		json_len = tquic_qlog_emit_json(qlog, entry,
						json_buf, 1024);
		if (json_len <= 0)
			break;

		if (total + json_len > count)
			break;

		/* Advance tail while still holding the lock */
		tail = (tail + 1) & qlog->ring_mask;
		atomic_set(&qlog->tail, tail);

		spin_unlock_irqrestore(&qlog->lock, flags);

		if (copy_to_user(buf + total, json_buf, json_len)) {
			kfree(json_buf);
			return total > 0 ? total : -EFAULT;
		}

		total += json_len;

		spin_lock_irqsave(&qlog->lock, flags);
		head = atomic_read(&qlog->head);
	}

	spin_unlock_irqrestore(&qlog->lock, flags);

	kfree(json_buf);
	return total;
}
EXPORT_SYMBOL_GPL(tquic_qlog_read_events);

/**
 * tquic_qlog_poll - Poll for available events
 * @qlog: Qlog context
 *
 * Return: Poll flags
 */
__poll_t tquic_qlog_poll(struct tquic_qlog *qlog)
{
	if (!qlog)
		return 0;

	if (!ring_buffer_empty(qlog))
		return EPOLLIN | EPOLLRDNORM;

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_qlog_poll);

/*
 * =============================================================================
 * Module Init/Exit
 * =============================================================================
 */

int tquic_qlog_init(void)
{
	pr_info("tquic: qlog tracing initialized (draft-ietf-quic-qlog-quic-events-12)\n");
	return 0;
}

void tquic_qlog_exit(void)
{
	pr_info("tquic: qlog tracing cleanup\n");
}

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TQUIC Qlog Tracing Support (draft-12)");
