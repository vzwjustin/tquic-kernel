// SPDX-License-Identifier: GPL-2.0
/*
 * TQUIC Qlog Tracing Support
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Implements qlog event logging for QUIC connections per:
 *   draft-ietf-quic-qlog-main-schema
 *   draft-ietf-quic-qlog-quic-events
 *
 * Qlog provides structured logging of QUIC protocol events for
 * debugging, performance analysis, and interoperability testing.
 *
 * Features:
 *   - Ring buffer storage for efficient event capture
 *   - Netlink relay for real-time event streaming
 *   - JSON-SEQ output format for qlog tooling compatibility
 *   - Per-event filtering via bitmask
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
static const struct genl_multicast_group tquic_qlog_mcgrps[] = {
	[0] = { .name = "qlog", },
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
	u32 head, next_head;
	struct tquic_qlog_event_entry *entry;

	head = atomic_read(&qlog->head);
	next_head = (head + 1) & qlog->ring_mask;

	/* Check if buffer is full */
	if (next_head == atomic_read(&qlog->tail)) {
		/* Lossy mode: advance tail to overwrite oldest */
		qlog->stats.ring_overflows++;
		qlog->stats.events_dropped++;
		atomic_set(&qlog->tail,
			   (atomic_read(&qlog->tail) + 1) & qlog->ring_mask);
	}

	entry = &qlog->ring[head];
	atomic_set(&qlog->head, next_head);

	return entry;
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

	qlog->mode = args->mode;
	qlog->relay_to_userspace = (args->mode == TQUIC_QLOG_MODE_NETLINK);

	spin_lock_init(&qlog->lock);
	refcount_set(&qlog->refcnt, 1);

	memset(&qlog->stats, 0, sizeof(qlog->stats));

	pr_debug("tquic: qlog created, ring_size=%u, mask=0x%llx\n",
		 ring_size, qlog->event_mask);

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

	if (!qlog || qlog->mode == TQUIC_QLOG_MODE_DISABLED)
		return NULL;

	if (!(qlog->event_mask & QLOG_EVENT_BIT(event_type)))
		return NULL;

	spin_lock_irqsave(&qlog->lock, flags);
	entry = ring_buffer_alloc_entry(qlog);
	entry->timestamp_ns = ktime_get_boottime_ns();
	entry->event_type = event_type;
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
 * Packet Events
 * =============================================================================
 */

void tquic_qlog_packet_sent(struct tquic_qlog *qlog,
			    u64 pkt_num, u32 pkt_type, size_t size,
			    u32 path_id, u16 frames, bool ack_eliciting)
{
	struct tquic_qlog_event_entry *entry;

	entry = log_event_common(qlog, QLOG_PACKET_SENT);
	if (!entry)
		return;

	entry->path_id = path_id;
	entry->data_len = sizeof(entry->data.packet);
	entry->data.packet.packet_number = pkt_num;
	entry->data.packet.packet_type = pkt_type;
	entry->data.packet.packet_size = size;
	entry->data.packet.path_id = path_id;
	entry->data.packet.frames_count = frames;
	entry->data.packet.ack_eliciting = ack_eliciting ? 1 : 0;
	entry->data.packet.in_flight = 1;

	relay_event(qlog, entry);
}
EXPORT_SYMBOL_GPL(tquic_qlog_packet_sent);

void tquic_qlog_packet_received(struct tquic_qlog *qlog,
				u64 pkt_num, u32 pkt_type, size_t size,
				u32 path_id)
{
	struct tquic_qlog_event_entry *entry;

	entry = log_event_common(qlog, QLOG_PACKET_RECEIVED);
	if (!entry)
		return;

	entry->path_id = path_id;
	entry->data_len = sizeof(entry->data.packet);
	entry->data.packet.packet_number = pkt_num;
	entry->data.packet.packet_type = pkt_type;
	entry->data.packet.packet_size = size;
	entry->data.packet.path_id = path_id;
	entry->data.packet.frames_count = 0;  /* Unknown at receive time */
	entry->data.packet.ack_eliciting = 0;
	entry->data.packet.in_flight = 0;

	relay_event(qlog, entry);
}
EXPORT_SYMBOL_GPL(tquic_qlog_packet_received);

void tquic_qlog_packet_dropped(struct tquic_qlog *qlog,
			       u32 pkt_type, size_t size,
			       const char *reason)
{
	struct tquic_qlog_event_entry *entry;

	entry = log_event_common(qlog, QLOG_PACKET_DROPPED);
	if (!entry)
		return;

	entry->path_id = 0;
	entry->data_len = sizeof(entry->data.packet);
	entry->data.packet.packet_number = 0;  /* Unknown for dropped */
	entry->data.packet.packet_type = pkt_type;
	entry->data.packet.packet_size = size;
	entry->data.packet.path_id = 0;
	entry->data.packet.frames_count = 0;
	entry->data.packet.ack_eliciting = 0;
	entry->data.packet.in_flight = 0;

	relay_event(qlog, entry);
}
EXPORT_SYMBOL_GPL(tquic_qlog_packet_dropped);

void tquic_qlog_packet_lost(struct tquic_qlog *qlog,
			    u64 pkt_num, u32 pkt_type, size_t size,
			    u32 path_id)
{
	struct tquic_qlog_event_entry *entry;

	entry = log_event_common(qlog, QLOG_PACKET_LOST);
	if (!entry)
		return;

	entry->path_id = path_id;
	entry->data_len = sizeof(entry->data.packet);
	entry->data.packet.packet_number = pkt_num;
	entry->data.packet.packet_type = pkt_type;
	entry->data.packet.packet_size = size;
	entry->data.packet.path_id = path_id;
	entry->data.packet.frames_count = 0;
	entry->data.packet.ack_eliciting = 1;  /* Lost packets are ack-eliciting */
	entry->data.packet.in_flight = 1;

	relay_event(qlog, entry);
}
EXPORT_SYMBOL_GPL(tquic_qlog_packet_lost);

/*
 * =============================================================================
 * Recovery Events
 * =============================================================================
 */

void tquic_qlog_metrics_updated(struct tquic_qlog *qlog,
				u64 cwnd, u64 bytes_in_flight,
				u64 min_rtt, u64 smoothed_rtt,
				u32 path_id)
{
	struct tquic_qlog_event_entry *entry;

	entry = log_event_common(qlog, QLOG_METRICS_UPDATED);
	if (!entry)
		return;

	entry->path_id = path_id;
	entry->data_len = sizeof(entry->data.metrics);
	entry->data.metrics.cwnd = cwnd;
	entry->data.metrics.bytes_in_flight = bytes_in_flight;
	entry->data.metrics.min_rtt = min_rtt;
	entry->data.metrics.smoothed_rtt = smoothed_rtt;
	entry->data.metrics.rtt_variance = 0;  /* Not passed in basic API */
	entry->data.metrics.ssthresh = 0;
	entry->data.metrics.pacing_rate = 0;
	entry->data.metrics.path_id = path_id;

	relay_event(qlog, entry);
}
EXPORT_SYMBOL_GPL(tquic_qlog_metrics_updated);

void tquic_qlog_congestion_state(struct tquic_qlog *qlog,
				 u32 old_state, u32 new_state,
				 u32 trigger, u32 path_id)
{
	struct tquic_qlog_event_entry *entry;

	entry = log_event_common(qlog, QLOG_CONGESTION_STATE_UPDATED);
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
EXPORT_SYMBOL_GPL(tquic_qlog_congestion_state);

void tquic_qlog_loss_timer_updated(struct tquic_qlog *qlog,
				   u32 timer_type, u64 delta_us,
				   u32 path_id)
{
	struct tquic_qlog_event_entry *entry;

	entry = log_event_common(qlog, QLOG_LOSS_TIMER_UPDATED);
	if (!entry)
		return;

	entry->path_id = path_id;
	entry->data_len = sizeof(entry->data.timer);
	entry->data.timer.timer_type = timer_type;
	entry->data.timer.delta = delta_us;
	entry->data.timer.path_id = path_id;

	relay_event(qlog, entry);
}
EXPORT_SYMBOL_GPL(tquic_qlog_loss_timer_updated);

/*
 * =============================================================================
 * Security Events
 * =============================================================================
 */

void tquic_qlog_key_updated(struct tquic_qlog *qlog,
			    u32 key_phase, u32 generation, u32 trigger)
{
	struct tquic_qlog_event_entry *entry;

	entry = log_event_common(qlog, QLOG_KEY_UPDATED);
	if (!entry)
		return;

	entry->path_id = 0;
	entry->data_len = sizeof(entry->data.key);
	entry->data.key.key_phase = key_phase;
	entry->data.key.generation = generation;
	entry->data.key.trigger = trigger;

	relay_event(qlog, entry);
}
EXPORT_SYMBOL_GPL(tquic_qlog_key_updated);

void tquic_qlog_key_retired(struct tquic_qlog *qlog,
			    u32 key_phase, u32 generation)
{
	struct tquic_qlog_event_entry *entry;

	entry = log_event_common(qlog, QLOG_KEY_RETIRED);
	if (!entry)
		return;

	entry->path_id = 0;
	entry->data_len = sizeof(entry->data.key);
	entry->data.key.key_phase = key_phase;
	entry->data.key.generation = generation;
	entry->data.key.trigger = QLOG_KEY_TRIGGER_LOCAL;

	relay_event(qlog, entry);
}
EXPORT_SYMBOL_GPL(tquic_qlog_key_retired);

/*
 * =============================================================================
 * Connection Events
 * =============================================================================
 */

void tquic_qlog_connection_started(struct tquic_qlog *qlog, u32 version)
{
	struct tquic_qlog_event_entry *entry;

	entry = log_event_common(qlog, QLOG_CONNECTION_STARTED);
	if (!entry)
		return;

	entry->path_id = 0;
	entry->data_len = sizeof(entry->data.connection);
	entry->data.connection.old_state = QLOG_CONN_IDLE;
	entry->data.connection.new_state = QLOG_CONN_CONNECTING;
	entry->data.connection.error_code = 0;
	entry->data.connection.version = version;

	relay_event(qlog, entry);
}
EXPORT_SYMBOL_GPL(tquic_qlog_connection_started);

void tquic_qlog_connection_closed(struct tquic_qlog *qlog, u64 error_code)
{
	struct tquic_qlog_event_entry *entry;

	entry = log_event_common(qlog, QLOG_CONNECTION_CLOSED);
	if (!entry)
		return;

	entry->path_id = 0;
	entry->data_len = sizeof(entry->data.connection);
	entry->data.connection.old_state = QLOG_CONN_CONNECTED;
	entry->data.connection.new_state = QLOG_CONN_CLOSED;
	entry->data.connection.error_code = error_code;
	entry->data.connection.version = 0;

	relay_event(qlog, entry);
}
EXPORT_SYMBOL_GPL(tquic_qlog_connection_closed);

void tquic_qlog_connection_state_updated(struct tquic_qlog *qlog,
					 u32 old_state, u32 new_state)
{
	struct tquic_qlog_event_entry *entry;

	entry = log_event_common(qlog, QLOG_CONNECTION_STATE_UPDATED);
	if (!entry)
		return;

	entry->path_id = 0;
	entry->data_len = sizeof(entry->data.connection);
	entry->data.connection.old_state = old_state;
	entry->data.connection.new_state = new_state;
	entry->data.connection.error_code = 0;
	entry->data.connection.version = 0;

	relay_event(qlog, entry);
}
EXPORT_SYMBOL_GPL(tquic_qlog_connection_state_updated);

/*
 * =============================================================================
 * JSON Output
 * =============================================================================
 *
 * Generates JSON-SEQ formatted events per draft-ietf-quic-qlog-main-schema.
 * Each line starts with ASCII Record Separator (0x1E) for JSON-SEQ.
 */

/* Event type names for JSON output */
static const char * const qlog_event_names[] = {
	[QLOG_CONNECTION_STARTED]	= "connectivity:connection_started",
	[QLOG_CONNECTION_CLOSED]	= "connectivity:connection_closed",
	[QLOG_CONNECTION_STATE_UPDATED]	= "connectivity:connection_state_updated",
	[QLOG_PACKET_SENT]		= "transport:packet_sent",
	[QLOG_PACKET_RECEIVED]		= "transport:packet_received",
	[QLOG_PACKET_DROPPED]		= "transport:packet_dropped",
	[QLOG_FRAMES_PROCESSED]		= "transport:frames_processed",
	[QLOG_METRICS_UPDATED]		= "recovery:metrics_updated",
	[QLOG_CONGESTION_STATE_UPDATED]	= "recovery:congestion_state_updated",
	[QLOG_LOSS_TIMER_UPDATED]	= "recovery:loss_timer_updated",
	[QLOG_PACKET_LOST]		= "recovery:packet_lost",
	[QLOG_KEY_UPDATED]		= "security:key_updated",
	[QLOG_KEY_RETIRED]		= "security:key_retired",
};

/* Packet type names */
static const char * const qlog_packet_type_names[] = {
	[QLOG_PKT_INITIAL]	= "initial",
	[QLOG_PKT_HANDSHAKE]	= "handshake",
	[QLOG_PKT_0RTT]		= "0rtt",
	[QLOG_PKT_1RTT]		= "1rtt",
	[QLOG_PKT_RETRY]	= "retry",
	[QLOG_PKT_VERSION_NEG]	= "version_negotiation",
};

/* CC state names */
static const char * const qlog_cc_state_names[] = {
	[QLOG_CC_SLOW_START]		= "slow_start",
	[QLOG_CC_CONGESTION_AVOIDANCE]	= "congestion_avoidance",
	[QLOG_CC_APPLICATION_LIMITED]	= "application_limited",
	[QLOG_CC_RECOVERY]		= "recovery",
};

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
	int len = 0;
	u64 time_ms;

	if (!entry || entry->event_type >= ARRAY_SIZE(qlog_event_names))
		return -EINVAL;

	event_name = qlog_event_names[entry->event_type];
	if (!event_name)
		return -EINVAL;

	/* Convert to milliseconds with 3 decimal places */
	time_ms = entry->timestamp_ns / 1000000;

	/* JSON-SEQ record separator + opening brace */
	len = snprintf(buf, buflen,
		       "\x1e{\"time\":%llu.%03llu,\"name\":\"%s\",\"data\":{",
		       time_ms, (entry->timestamp_ns / 1000) % 1000,
		       event_name);

	if (len >= buflen)
		return -ENOSPC;

	/* Event-specific data */
	switch (entry->event_type) {
	case QLOG_PACKET_SENT:
	case QLOG_PACKET_RECEIVED:
	case QLOG_PACKET_DROPPED:
	case QLOG_PACKET_LOST: {
		const struct tquic_qlog_packet_event *pkt = &entry->data.packet;
		const char *pkt_type = "unknown";

		if (pkt->packet_type < ARRAY_SIZE(qlog_packet_type_names))
			pkt_type = qlog_packet_type_names[pkt->packet_type];

		len += snprintf(buf + len, buflen - len,
				"\"header\":{\"packet_type\":\"%s\",\"packet_number\":%llu},"
				"\"raw\":{\"length\":%u},\"path_id\":%u",
				pkt_type, pkt->packet_number,
				pkt->packet_size, pkt->path_id);
		break;
	}

	case QLOG_METRICS_UPDATED: {
		const struct tquic_qlog_metrics_event *m = &entry->data.metrics;

		len += snprintf(buf + len, buflen - len,
				"\"congestion_window\":%llu,"
				"\"bytes_in_flight\":%llu,"
				"\"min_rtt\":%llu,"
				"\"smoothed_rtt\":%llu,"
				"\"path_id\":%u",
				m->cwnd, m->bytes_in_flight,
				m->min_rtt, m->smoothed_rtt, m->path_id);
		break;
	}

	case QLOG_CONGESTION_STATE_UPDATED: {
		const struct tquic_qlog_congestion_event *c = &entry->data.congestion;
		const char *old_name = "unknown";
		const char *new_name = "unknown";

		if (c->old_state < ARRAY_SIZE(qlog_cc_state_names))
			old_name = qlog_cc_state_names[c->old_state];
		if (c->new_state < ARRAY_SIZE(qlog_cc_state_names))
			new_name = qlog_cc_state_names[c->new_state];

		len += snprintf(buf + len, buflen - len,
				"\"old\":\"%s\",\"new\":\"%s\",\"path_id\":%u",
				old_name, new_name, c->path_id);
		break;
	}

	case QLOG_LOSS_TIMER_UPDATED: {
		const struct tquic_qlog_loss_timer_event *t = &entry->data.timer;
		static const char * const timer_names[] = {
			"ack", "pto", "idle", "handshake"
		};
		const char *timer_name = "unknown";

		if (t->timer_type < ARRAY_SIZE(timer_names))
			timer_name = timer_names[t->timer_type];

		len += snprintf(buf + len, buflen - len,
				"\"timer_type\":\"%s\",\"delta\":%llu,\"path_id\":%u",
				timer_name, t->delta, t->path_id);
		break;
	}

	case QLOG_KEY_UPDATED:
	case QLOG_KEY_RETIRED: {
		const struct tquic_qlog_key_event *k = &entry->data.key;

		len += snprintf(buf + len, buflen - len,
				"\"key_phase\":%u,\"generation\":%u",
				k->key_phase, k->generation);
		break;
	}

	case QLOG_CONNECTION_STARTED:
	case QLOG_CONNECTION_CLOSED:
	case QLOG_CONNECTION_STATE_UPDATED: {
		const struct tquic_qlog_connection_event *c = &entry->data.connection;

		len += snprintf(buf + len, buflen - len,
				"\"old\":%u,\"new\":%u",
				c->old_state, c->new_state);
		if (c->error_code != 0)
			len += snprintf(buf + len, buflen - len,
					",\"error_code\":%llu", c->error_code);
		if (c->version != 0)
			len += snprintf(buf + len, buflen - len,
					",\"version\":\"0x%08x\"", c->version);
		break;
	}

	default:
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
	char json_buf[512];
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

	json_buf = kmalloc(512, GFP_KERNEL);
	if (!json_buf)
		return -ENOMEM;

	spin_lock_irqsave(&qlog->lock, flags);

	head = atomic_read(&qlog->head);
	tail = atomic_read(&qlog->tail);

	while (tail != head && total < count) {
		struct tquic_qlog_event_entry *entry = &qlog->ring[tail];

		/* Format as JSON */
		json_len = tquic_qlog_emit_json(qlog, entry,
						json_buf, 512);
		if (json_len <= 0)
			break;

		if (total + json_len > count)
			break;

		spin_unlock_irqrestore(&qlog->lock, flags);

		if (copy_to_user(buf + total, json_buf, json_len)) {
			kfree(json_buf);
			return total > 0 ? total : -EFAULT;
		}

		total += json_len;

		spin_lock_irqsave(&qlog->lock, flags);
		tail = (tail + 1) & qlog->ring_mask;
		atomic_set(&qlog->tail, tail);
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

int __init tquic_qlog_init(void)
{
	pr_info("tquic: qlog tracing initialized\n");
	return 0;
}

void __exit tquic_qlog_exit(void)
{
	pr_info("tquic: qlog tracing cleanup\n");
}

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TQUIC Qlog Tracing Support");
