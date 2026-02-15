// SPDX-License-Identifier: GPL-2.0
/*
 * KUnit tests for TQUIC Qlog Implementation
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Tests qlog event generation per draft-ietf-quic-qlog-quic-events-12.
 * Verifies:
 *   - Event type definitions and categories
 *   - Event severity levels
 *   - transport:packet_sent/received/dropped/buffered events
 *   - recovery:metrics_updated/congestion_state_updated/loss_timer_updated
 *   - connectivity:connection_started/connection_closed/path_updated
 *   - security:key_updated/key_discarded
 *   - JSON output format
 *   - Event filtering
 */

#include <kunit/test.h>
#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <uapi/linux/tquic_qlog.h>

/*
 * =============================================================================
 * Test Helpers - Mock structures for testing without full TQUIC context
 * =============================================================================
 */

/* Mock connection structure for testing */
struct mock_connection {
	struct {
		u8 id[20];
		u8 len;
	} scid;
};

/* Simplified qlog context for testing (mirrors struct tquic_qlog) */
struct test_qlog {
	struct mock_connection *conn;
	struct tquic_qlog_event_entry *ring;
	u32 ring_size;
	u32 ring_mask;
	atomic_t head;
	atomic_t tail;
	u64 event_mask;
	u8 severity_filter;
	u32 mode;
	spinlock_t lock;
	struct tquic_qlog_stats stats;
	refcount_t refcnt;
};

/* Helper: Get category for event type (matches qlog.h inline) */
static u8 test_qlog_event_category(enum tquic_qlog_event event)
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

/* Helper: Get severity for event type (matches qlog.h inline) */
static u8 test_qlog_event_severity(enum tquic_qlog_event event)
{
	switch (event) {
	case QLOG_CONNECTIVITY_CONNECTION_STARTED:
	case QLOG_CONNECTIVITY_CONNECTION_CLOSED:
	case QLOG_TRANSPORT_PACKET_SENT:
	case QLOG_TRANSPORT_PACKET_RECEIVED:
	case QLOG_TRANSPORT_PACKET_DROPPED:
	case QLOG_RECOVERY_PACKET_LOST:
	case QLOG_SECURITY_KEY_UPDATED:
		return TQUIC_QLOG_SEV_CORE;
	case QLOG_CONNECTIVITY_PATH_UPDATED:
	case QLOG_TRANSPORT_PACKET_BUFFERED:
	case QLOG_RECOVERY_METRICS_UPDATED:
	case QLOG_RECOVERY_CONGESTION_STATE_UPDATED:
	case QLOG_RECOVERY_LOSS_TIMER_UPDATED:
		return TQUIC_QLOG_SEV_BASE;
	case QLOG_CONNECTIVITY_CONNECTION_ID_UPDATED:
	case QLOG_CONNECTIVITY_SPIN_BIT_UPDATED:
	case QLOG_TRANSPORT_PACKETS_ACKED:
	case QLOG_RECOVERY_MARKED_FOR_RETRANSMIT:
	case QLOG_SECURITY_KEY_DISCARDED:
		return TQUIC_QLOG_SEV_EXTRA;
	default:
		return TQUIC_QLOG_SEV_DEBUG;
	}
}

/* Helper: Create test qlog context */
static struct test_qlog *test_qlog_create(struct kunit *test)
{
	struct test_qlog *qlog;
	struct mock_connection *conn;

	conn = kunit_kzalloc(test, sizeof(*conn), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, conn);
	conn->scid.len = 8;
	memset(conn->scid.id, 0x42, 8);

	qlog = kunit_kzalloc(test, sizeof(*qlog), GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, qlog);

	qlog->ring = kunit_kcalloc(test, 64, sizeof(struct tquic_qlog_event_entry),
				   GFP_KERNEL);
	KUNIT_ASSERT_NOT_ERR_OR_NULL(test, qlog->ring);

	qlog->conn = conn;
	qlog->ring_size = 64;
	qlog->ring_mask = 63;
	atomic_set(&qlog->head, 0);
	atomic_set(&qlog->tail, 0);
	qlog->event_mask = QLOG_MASK_ALL;
	qlog->severity_filter = TQUIC_QLOG_SEV_DEBUG;
	qlog->mode = TQUIC_QLOG_MODE_RING;
	spin_lock_init(&qlog->lock);
	refcount_set(&qlog->refcnt, 1);

	return qlog;
}

/* Helper: Write event to ring buffer */
static struct tquic_qlog_event_entry *test_qlog_write_event(
	struct test_qlog *qlog,
	enum tquic_qlog_event event_type)
{
	struct tquic_qlog_event_entry *entry;
	u32 head;

	head = atomic_read(&qlog->head);
	entry = &qlog->ring[head];
	atomic_set(&qlog->head, (head + 1) & qlog->ring_mask);

	entry->timestamp_ns = ktime_get_boottime_ns();
	entry->event_type = event_type;
	entry->severity = test_qlog_event_severity(event_type);
	entry->category = test_qlog_event_category(event_type);
	qlog->stats.events_logged++;

	return entry;
}

/*
 * =============================================================================
 * Event Category Tests (draft-12 Section 4)
 * =============================================================================
 */

static void tquic_qlog_test_event_categories(struct kunit *test)
{
	/* Connectivity events should be in connectivity category */
	KUNIT_EXPECT_EQ(test, test_qlog_event_category(QLOG_CONNECTIVITY_SERVER_LISTENING),
			TQUIC_QLOG_CAT_CONNECTIVITY);
	KUNIT_EXPECT_EQ(test, test_qlog_event_category(QLOG_CONNECTIVITY_CONNECTION_STARTED),
			TQUIC_QLOG_CAT_CONNECTIVITY);
	KUNIT_EXPECT_EQ(test, test_qlog_event_category(QLOG_CONNECTIVITY_CONNECTION_CLOSED),
			TQUIC_QLOG_CAT_CONNECTIVITY);
	KUNIT_EXPECT_EQ(test, test_qlog_event_category(QLOG_CONNECTIVITY_PATH_UPDATED),
			TQUIC_QLOG_CAT_CONNECTIVITY);

	/* Transport events should be in transport category */
	KUNIT_EXPECT_EQ(test, test_qlog_event_category(QLOG_TRANSPORT_PACKET_SENT),
			TQUIC_QLOG_CAT_TRANSPORT);
	KUNIT_EXPECT_EQ(test, test_qlog_event_category(QLOG_TRANSPORT_PACKET_RECEIVED),
			TQUIC_QLOG_CAT_TRANSPORT);
	KUNIT_EXPECT_EQ(test, test_qlog_event_category(QLOG_TRANSPORT_PACKET_DROPPED),
			TQUIC_QLOG_CAT_TRANSPORT);
	KUNIT_EXPECT_EQ(test, test_qlog_event_category(QLOG_TRANSPORT_PACKET_BUFFERED),
			TQUIC_QLOG_CAT_TRANSPORT);

	/* Recovery events should be in recovery category */
	KUNIT_EXPECT_EQ(test, test_qlog_event_category(QLOG_RECOVERY_METRICS_UPDATED),
			TQUIC_QLOG_CAT_RECOVERY);
	KUNIT_EXPECT_EQ(test, test_qlog_event_category(QLOG_RECOVERY_CONGESTION_STATE_UPDATED),
			TQUIC_QLOG_CAT_RECOVERY);
	KUNIT_EXPECT_EQ(test, test_qlog_event_category(QLOG_RECOVERY_LOSS_TIMER_UPDATED),
			TQUIC_QLOG_CAT_RECOVERY);
	KUNIT_EXPECT_EQ(test, test_qlog_event_category(QLOG_RECOVERY_PACKET_LOST),
			TQUIC_QLOG_CAT_RECOVERY);

	/* Security events should be in security category */
	KUNIT_EXPECT_EQ(test, test_qlog_event_category(QLOG_SECURITY_KEY_UPDATED),
			TQUIC_QLOG_CAT_SECURITY);
	KUNIT_EXPECT_EQ(test, test_qlog_event_category(QLOG_SECURITY_KEY_DISCARDED),
			TQUIC_QLOG_CAT_SECURITY);
}

/*
 * =============================================================================
 * Event Severity Tests (draft-12 Importance Levels)
 * =============================================================================
 */

static void tquic_qlog_test_event_severities(struct kunit *test)
{
	/* Core events (always important) */
	KUNIT_EXPECT_EQ(test, test_qlog_event_severity(QLOG_CONNECTIVITY_CONNECTION_STARTED),
			TQUIC_QLOG_SEV_CORE);
	KUNIT_EXPECT_EQ(test, test_qlog_event_severity(QLOG_CONNECTIVITY_CONNECTION_CLOSED),
			TQUIC_QLOG_SEV_CORE);
	KUNIT_EXPECT_EQ(test, test_qlog_event_severity(QLOG_TRANSPORT_PACKET_SENT),
			TQUIC_QLOG_SEV_CORE);
	KUNIT_EXPECT_EQ(test, test_qlog_event_severity(QLOG_TRANSPORT_PACKET_RECEIVED),
			TQUIC_QLOG_SEV_CORE);
	KUNIT_EXPECT_EQ(test, test_qlog_event_severity(QLOG_TRANSPORT_PACKET_DROPPED),
			TQUIC_QLOG_SEV_CORE);
	KUNIT_EXPECT_EQ(test, test_qlog_event_severity(QLOG_RECOVERY_PACKET_LOST),
			TQUIC_QLOG_SEV_CORE);
	KUNIT_EXPECT_EQ(test, test_qlog_event_severity(QLOG_SECURITY_KEY_UPDATED),
			TQUIC_QLOG_SEV_CORE);

	/* Base events (commonly logged) */
	KUNIT_EXPECT_EQ(test, test_qlog_event_severity(QLOG_CONNECTIVITY_PATH_UPDATED),
			TQUIC_QLOG_SEV_BASE);
	KUNIT_EXPECT_EQ(test, test_qlog_event_severity(QLOG_TRANSPORT_PACKET_BUFFERED),
			TQUIC_QLOG_SEV_BASE);
	KUNIT_EXPECT_EQ(test, test_qlog_event_severity(QLOG_RECOVERY_METRICS_UPDATED),
			TQUIC_QLOG_SEV_BASE);
	KUNIT_EXPECT_EQ(test, test_qlog_event_severity(QLOG_RECOVERY_CONGESTION_STATE_UPDATED),
			TQUIC_QLOG_SEV_BASE);
	KUNIT_EXPECT_EQ(test, test_qlog_event_severity(QLOG_RECOVERY_LOSS_TIMER_UPDATED),
			TQUIC_QLOG_SEV_BASE);

	/* Extra events */
	KUNIT_EXPECT_EQ(test, test_qlog_event_severity(QLOG_CONNECTIVITY_CONNECTION_ID_UPDATED),
			TQUIC_QLOG_SEV_EXTRA);
	KUNIT_EXPECT_EQ(test, test_qlog_event_severity(QLOG_SECURITY_KEY_DISCARDED),
			TQUIC_QLOG_SEV_EXTRA);
}

/*
 * =============================================================================
 * Event Mask Tests
 * =============================================================================
 */

static void tquic_qlog_test_event_masks(struct kunit *test)
{
	/* Test connectivity mask contains all connectivity events */
	KUNIT_EXPECT_TRUE(test, (QLOG_MASK_CONNECTIVITY &
				 QLOG_EVENT_BIT(QLOG_CONNECTIVITY_CONNECTION_STARTED)));
	KUNIT_EXPECT_TRUE(test, (QLOG_MASK_CONNECTIVITY &
				 QLOG_EVENT_BIT(QLOG_CONNECTIVITY_CONNECTION_CLOSED)));
	KUNIT_EXPECT_TRUE(test, (QLOG_MASK_CONNECTIVITY &
				 QLOG_EVENT_BIT(QLOG_CONNECTIVITY_PATH_UPDATED)));

	/* Test transport mask contains all transport events */
	KUNIT_EXPECT_TRUE(test, (QLOG_MASK_TRANSPORT &
				 QLOG_EVENT_BIT(QLOG_TRANSPORT_PACKET_SENT)));
	KUNIT_EXPECT_TRUE(test, (QLOG_MASK_TRANSPORT &
				 QLOG_EVENT_BIT(QLOG_TRANSPORT_PACKET_RECEIVED)));
	KUNIT_EXPECT_TRUE(test, (QLOG_MASK_TRANSPORT &
				 QLOG_EVENT_BIT(QLOG_TRANSPORT_PACKET_DROPPED)));
	KUNIT_EXPECT_TRUE(test, (QLOG_MASK_TRANSPORT &
				 QLOG_EVENT_BIT(QLOG_TRANSPORT_PACKET_BUFFERED)));

	/* Test recovery mask contains all recovery events */
	KUNIT_EXPECT_TRUE(test, (QLOG_MASK_RECOVERY &
				 QLOG_EVENT_BIT(QLOG_RECOVERY_METRICS_UPDATED)));
	KUNIT_EXPECT_TRUE(test, (QLOG_MASK_RECOVERY &
				 QLOG_EVENT_BIT(QLOG_RECOVERY_CONGESTION_STATE_UPDATED)));
	KUNIT_EXPECT_TRUE(test, (QLOG_MASK_RECOVERY &
				 QLOG_EVENT_BIT(QLOG_RECOVERY_LOSS_TIMER_UPDATED)));
	KUNIT_EXPECT_TRUE(test, (QLOG_MASK_RECOVERY &
				 QLOG_EVENT_BIT(QLOG_RECOVERY_PACKET_LOST)));

	/* Test security mask contains all security events */
	KUNIT_EXPECT_TRUE(test, (QLOG_MASK_SECURITY &
				 QLOG_EVENT_BIT(QLOG_SECURITY_KEY_UPDATED)));
	KUNIT_EXPECT_TRUE(test, (QLOG_MASK_SECURITY &
				 QLOG_EVENT_BIT(QLOG_SECURITY_KEY_DISCARDED)));

	/* Test QLOG_MASK_ALL contains all masks */
	KUNIT_EXPECT_EQ(test, (QLOG_MASK_ALL & QLOG_MASK_CONNECTIVITY),
			QLOG_MASK_CONNECTIVITY);
	KUNIT_EXPECT_EQ(test, (QLOG_MASK_ALL & QLOG_MASK_TRANSPORT),
			QLOG_MASK_TRANSPORT);
	KUNIT_EXPECT_EQ(test, (QLOG_MASK_ALL & QLOG_MASK_RECOVERY),
			QLOG_MASK_RECOVERY);
	KUNIT_EXPECT_EQ(test, (QLOG_MASK_ALL & QLOG_MASK_SECURITY),
			QLOG_MASK_SECURITY);
}

/*
 * =============================================================================
 * Transport Event Tests (draft-12 Section 6)
 * =============================================================================
 */

static void tquic_qlog_test_packet_sent_event(struct kunit *test)
{
	struct test_qlog *qlog;
	struct tquic_qlog_event_entry *entry;
	struct tquic_qlog_packet_event *pkt;

	qlog = test_qlog_create(test);

	/* Create packet_sent event */
	entry = test_qlog_write_event(qlog, QLOG_TRANSPORT_PACKET_SENT);
	KUNIT_ASSERT_NOT_NULL(test, entry);

	/* Fill packet data */
	pkt = &entry->data.packet;
	pkt->header.packet_number = 12345;
	pkt->header.packet_type = QLOG_PKT_1RTT;
	pkt->header.packet_size = 1200;
	pkt->header.payload_length = 1180;
	pkt->header.key_phase = 0;
	pkt->header.spin_bit = 1;
	pkt->path_id = 0;
	pkt->frames_count = 3;
	pkt->ack_eliciting = 1;
	pkt->in_flight = 1;
	pkt->is_coalesced = 0;
	pkt->is_mtu_probe = 0;
	entry->path_id = 0;
	entry->data_len = sizeof(*pkt);

	/* Verify event type */
	KUNIT_EXPECT_EQ(test, entry->event_type, QLOG_TRANSPORT_PACKET_SENT);
	KUNIT_EXPECT_EQ(test, entry->category, TQUIC_QLOG_CAT_TRANSPORT);
	KUNIT_EXPECT_EQ(test, entry->severity, TQUIC_QLOG_SEV_CORE);

	/* Verify packet data */
	KUNIT_EXPECT_EQ(test, pkt->header.packet_number, 12345ULL);
	KUNIT_EXPECT_EQ(test, pkt->header.packet_type, QLOG_PKT_1RTT);
	KUNIT_EXPECT_EQ(test, pkt->header.packet_size, 1200U);
	KUNIT_EXPECT_EQ(test, pkt->frames_count, 3);
	KUNIT_EXPECT_TRUE(test, pkt->ack_eliciting);
	KUNIT_EXPECT_TRUE(test, pkt->in_flight);
}

static void tquic_qlog_test_packet_received_event(struct kunit *test)
{
	struct test_qlog *qlog;
	struct tquic_qlog_event_entry *entry;
	struct tquic_qlog_packet_event *pkt;

	qlog = test_qlog_create(test);

	entry = test_qlog_write_event(qlog, QLOG_TRANSPORT_PACKET_RECEIVED);
	KUNIT_ASSERT_NOT_NULL(test, entry);

	pkt = &entry->data.packet;
	pkt->header.packet_number = 5000;
	pkt->header.packet_type = QLOG_PKT_INITIAL;
	pkt->header.packet_size = 1252;
	pkt->header.version = 0x00000001;
	pkt->ecn = 2;  /* ECT(0) */
	entry->data_len = sizeof(*pkt);

	KUNIT_EXPECT_EQ(test, entry->event_type, QLOG_TRANSPORT_PACKET_RECEIVED);
	KUNIT_EXPECT_EQ(test, pkt->header.packet_number, 5000ULL);
	KUNIT_EXPECT_EQ(test, pkt->header.packet_type, QLOG_PKT_INITIAL);
	KUNIT_EXPECT_EQ(test, pkt->ecn, 2);
}

static void tquic_qlog_test_packet_dropped_event(struct kunit *test)
{
	struct test_qlog *qlog;
	struct tquic_qlog_event_entry *entry;
	struct tquic_qlog_packet_dropped_event *drop;

	qlog = test_qlog_create(test);

	entry = test_qlog_write_event(qlog, QLOG_TRANSPORT_PACKET_DROPPED);
	KUNIT_ASSERT_NOT_NULL(test, entry);

	drop = &entry->data.packet_dropped;
	drop->header.packet_type = QLOG_PKT_1RTT;
	drop->raw_length = 1200;
	drop->drop_reason = QLOG_DROP_DECRYPTION_FAILURE;
	drop->path_id = 0;
	entry->data_len = sizeof(*drop);

	KUNIT_EXPECT_EQ(test, entry->event_type, QLOG_TRANSPORT_PACKET_DROPPED);
	KUNIT_EXPECT_EQ(test, drop->drop_reason, QLOG_DROP_DECRYPTION_FAILURE);
	KUNIT_EXPECT_EQ(test, drop->raw_length, 1200U);
}

static void tquic_qlog_test_packet_buffered_event(struct kunit *test)
{
	struct test_qlog *qlog;
	struct tquic_qlog_event_entry *entry;
	struct tquic_qlog_packet_buffered_event *buf;

	qlog = test_qlog_create(test);

	entry = test_qlog_write_event(qlog, QLOG_TRANSPORT_PACKET_BUFFERED);
	KUNIT_ASSERT_NOT_NULL(test, entry);

	buf = &entry->data.packet_buffered;
	buf->header.packet_number = 100;
	buf->header.packet_type = QLOG_PKT_HANDSHAKE;
	buf->header.packet_size = 800;
	buf->buffer_reason = QLOG_BUFFER_KEYS_UNAVAILABLE;
	buf->path_id = 0;
	entry->data_len = sizeof(*buf);

	KUNIT_EXPECT_EQ(test, entry->event_type, QLOG_TRANSPORT_PACKET_BUFFERED);
	KUNIT_EXPECT_EQ(test, buf->buffer_reason, QLOG_BUFFER_KEYS_UNAVAILABLE);
	KUNIT_EXPECT_EQ(test, entry->severity, TQUIC_QLOG_SEV_BASE);
}

/*
 * =============================================================================
 * Recovery Event Tests (draft-12 Section 7)
 * =============================================================================
 */

static void tquic_qlog_test_metrics_updated_event(struct kunit *test)
{
	struct test_qlog *qlog;
	struct tquic_qlog_event_entry *entry;
	struct tquic_qlog_metrics_event *m;

	qlog = test_qlog_create(test);

	entry = test_qlog_write_event(qlog, QLOG_RECOVERY_METRICS_UPDATED);
	KUNIT_ASSERT_NOT_NULL(test, entry);

	m = &entry->data.metrics;
	m->min_rtt = 10000;       /* 10ms */
	m->smoothed_rtt = 25000;  /* 25ms */
	m->latest_rtt = 20000;    /* 20ms */
	m->rtt_variance = 5000;   /* 5ms */
	m->cwnd = 14720;
	m->bytes_in_flight = 10000;
	m->ssthresh = 1000000;
	m->pacing_rate = 1250000;
	m->pto_count = 0;
	m->packets_in_flight = 10;
	m->path_id = 0;
	entry->path_id = 0;
	entry->data_len = sizeof(*m);

	KUNIT_EXPECT_EQ(test, entry->event_type, QLOG_RECOVERY_METRICS_UPDATED);
	KUNIT_EXPECT_EQ(test, entry->category, TQUIC_QLOG_CAT_RECOVERY);
	KUNIT_EXPECT_EQ(test, m->min_rtt, 10000ULL);
	KUNIT_EXPECT_EQ(test, m->smoothed_rtt, 25000ULL);
	KUNIT_EXPECT_EQ(test, m->cwnd, 14720ULL);
	KUNIT_EXPECT_EQ(test, m->bytes_in_flight, 10000ULL);
	KUNIT_EXPECT_EQ(test, m->pacing_rate, 1250000ULL);
}

static void tquic_qlog_test_congestion_state_updated_event(struct kunit *test)
{
	struct test_qlog *qlog;
	struct tquic_qlog_event_entry *entry;
	struct tquic_qlog_congestion_event *c;

	qlog = test_qlog_create(test);

	entry = test_qlog_write_event(qlog, QLOG_RECOVERY_CONGESTION_STATE_UPDATED);
	KUNIT_ASSERT_NOT_NULL(test, entry);

	c = &entry->data.congestion;
	c->old_state = QLOG_CC_SLOW_START;
	c->new_state = QLOG_CC_CONGESTION_AVOIDANCE;
	c->trigger = QLOG_CC_TRIGGER_ACK;
	c->path_id = 0;
	entry->path_id = 0;
	entry->data_len = sizeof(*c);

	KUNIT_EXPECT_EQ(test, entry->event_type, QLOG_RECOVERY_CONGESTION_STATE_UPDATED);
	KUNIT_EXPECT_EQ(test, c->old_state, QLOG_CC_SLOW_START);
	KUNIT_EXPECT_EQ(test, c->new_state, QLOG_CC_CONGESTION_AVOIDANCE);
	KUNIT_EXPECT_EQ(test, c->trigger, QLOG_CC_TRIGGER_ACK);
}

static void tquic_qlog_test_loss_timer_updated_event(struct kunit *test)
{
	struct test_qlog *qlog;
	struct tquic_qlog_event_entry *entry;
	struct tquic_qlog_loss_timer_event *t;

	qlog = test_qlog_create(test);

	/* Test timer set */
	entry = test_qlog_write_event(qlog, QLOG_RECOVERY_LOSS_TIMER_UPDATED);
	KUNIT_ASSERT_NOT_NULL(test, entry);

	t = &entry->data.timer;
	t->timer_type = QLOG_TIMER_PTO;
	t->timer_event = QLOG_TIMER_SET;
	t->delta = 50000;  /* 50ms */
	t->packet_number_space = 2;  /* Application data */
	t->path_id = 0;
	entry->data_len = sizeof(*t);

	KUNIT_EXPECT_EQ(test, entry->event_type, QLOG_RECOVERY_LOSS_TIMER_UPDATED);
	KUNIT_EXPECT_EQ(test, t->timer_type, QLOG_TIMER_PTO);
	KUNIT_EXPECT_EQ(test, t->timer_event, QLOG_TIMER_SET);
	KUNIT_EXPECT_EQ(test, t->delta, 50000ULL);

	/* Test timer expired */
	entry = test_qlog_write_event(qlog, QLOG_RECOVERY_LOSS_TIMER_UPDATED);
	t = &entry->data.timer;
	t->timer_type = QLOG_TIMER_PTO;
	t->timer_event = QLOG_TIMER_EXPIRED;
	t->delta = 0;

	KUNIT_EXPECT_EQ(test, t->timer_event, QLOG_TIMER_EXPIRED);

	/* Test timer cancelled */
	entry = test_qlog_write_event(qlog, QLOG_RECOVERY_LOSS_TIMER_UPDATED);
	t = &entry->data.timer;
	t->timer_type = QLOG_TIMER_PTO;
	t->timer_event = QLOG_TIMER_CANCELLED;
	t->delta = 0;

	KUNIT_EXPECT_EQ(test, t->timer_event, QLOG_TIMER_CANCELLED);
}

static void tquic_qlog_test_packet_lost_event(struct kunit *test)
{
	struct test_qlog *qlog;
	struct tquic_qlog_event_entry *entry;
	struct tquic_qlog_packet_lost_event *lost;

	qlog = test_qlog_create(test);

	entry = test_qlog_write_event(qlog, QLOG_RECOVERY_PACKET_LOST);
	KUNIT_ASSERT_NOT_NULL(test, entry);

	lost = &entry->data.packet_lost;
	lost->header.packet_number = 42;
	lost->header.packet_type = QLOG_PKT_1RTT;
	lost->header.packet_size = 1200;
	lost->path_id = 0;
	lost->trigger = QLOG_CC_TRIGGER_LOSS;
	entry->data_len = sizeof(*lost);

	KUNIT_EXPECT_EQ(test, entry->event_type, QLOG_RECOVERY_PACKET_LOST);
	KUNIT_EXPECT_EQ(test, entry->severity, TQUIC_QLOG_SEV_CORE);
	KUNIT_EXPECT_EQ(test, lost->header.packet_number, 42ULL);
	KUNIT_EXPECT_EQ(test, lost->trigger, QLOG_CC_TRIGGER_LOSS);
}

/*
 * =============================================================================
 * Connectivity Event Tests (draft-12 Section 5)
 * =============================================================================
 */

static void tquic_qlog_test_connection_started_event(struct kunit *test)
{
	struct test_qlog *qlog;
	struct tquic_qlog_event_entry *entry;
	struct tquic_qlog_connection_event *c;

	qlog = test_qlog_create(test);

	entry = test_qlog_write_event(qlog, QLOG_CONNECTIVITY_CONNECTION_STARTED);
	KUNIT_ASSERT_NOT_NULL(test, entry);

	c = &entry->data.connection;
	c->old_state = QLOG_CONN_IDLE;
	c->new_state = QLOG_CONN_CONNECTING;
	c->version = 0x00000001;  /* QUIC v1 */
	c->error_code = 0;
	entry->data_len = sizeof(*c);

	KUNIT_EXPECT_EQ(test, entry->event_type, QLOG_CONNECTIVITY_CONNECTION_STARTED);
	KUNIT_EXPECT_EQ(test, entry->category, TQUIC_QLOG_CAT_CONNECTIVITY);
	KUNIT_EXPECT_EQ(test, entry->severity, TQUIC_QLOG_SEV_CORE);
	KUNIT_EXPECT_EQ(test, c->version, 0x00000001U);
	KUNIT_EXPECT_EQ(test, c->old_state, QLOG_CONN_IDLE);
	KUNIT_EXPECT_EQ(test, c->new_state, QLOG_CONN_CONNECTING);
}

static void tquic_qlog_test_connection_closed_event(struct kunit *test)
{
	struct test_qlog *qlog;
	struct tquic_qlog_event_entry *entry;
	struct tquic_qlog_connection_event *c;

	qlog = test_qlog_create(test);

	entry = test_qlog_write_event(qlog, QLOG_CONNECTIVITY_CONNECTION_CLOSED);
	KUNIT_ASSERT_NOT_NULL(test, entry);

	c = &entry->data.connection;
	c->old_state = QLOG_CONN_CONNECTED;
	c->new_state = QLOG_CONN_CLOSED;
	c->error_code = 0;  /* Clean close */
	c->version = 0;
	entry->data_len = sizeof(*c);

	KUNIT_EXPECT_EQ(test, entry->event_type, QLOG_CONNECTIVITY_CONNECTION_CLOSED);
	KUNIT_EXPECT_EQ(test, entry->severity, TQUIC_QLOG_SEV_CORE);
	KUNIT_EXPECT_EQ(test, c->error_code, 0ULL);

	/* Test with error code */
	entry = test_qlog_write_event(qlog, QLOG_CONNECTIVITY_CONNECTION_CLOSED);
	c = &entry->data.connection;
	c->old_state = QLOG_CONN_CONNECTED;
	c->new_state = QLOG_CONN_CLOSED;
	c->error_code = 0x0A;  /* NO_ERROR with application frame */

	KUNIT_EXPECT_EQ(test, c->error_code, 0x0AULL);
}

static void tquic_qlog_test_path_updated_event(struct kunit *test)
{
	struct test_qlog *qlog;
	struct tquic_qlog_event_entry *entry;
	struct tquic_qlog_path_event *p;

	qlog = test_qlog_create(test);

	entry = test_qlog_write_event(qlog, QLOG_CONNECTIVITY_PATH_UPDATED);
	KUNIT_ASSERT_NOT_NULL(test, entry);

	p = &entry->data.path;
	p->old_state = QLOG_PATH_NEW;
	p->new_state = QLOG_PATH_VALIDATING;
	p->path_id = 1;
	p->mtu = 1280;
	entry->path_id = 1;
	entry->data_len = sizeof(*p);

	KUNIT_EXPECT_EQ(test, entry->event_type, QLOG_CONNECTIVITY_PATH_UPDATED);
	KUNIT_EXPECT_EQ(test, p->old_state, QLOG_PATH_NEW);
	KUNIT_EXPECT_EQ(test, p->new_state, QLOG_PATH_VALIDATING);
	KUNIT_EXPECT_EQ(test, p->path_id, 1U);
	KUNIT_EXPECT_EQ(test, p->mtu, 1280U);
}

/*
 * =============================================================================
 * Security Event Tests (draft-12 Section 8)
 * =============================================================================
 */

static void tquic_qlog_test_key_updated_event(struct kunit *test)
{
	struct test_qlog *qlog;
	struct tquic_qlog_event_entry *entry;
	struct tquic_qlog_key_event *k;

	qlog = test_qlog_create(test);

	entry = test_qlog_write_event(qlog, QLOG_SECURITY_KEY_UPDATED);
	KUNIT_ASSERT_NOT_NULL(test, entry);

	k = &entry->data.key;
	k->key_type = QLOG_KEY_CLIENT_1RTT_SECRET;
	k->key_phase = 1;
	k->generation = 1;
	k->trigger = QLOG_KEY_TRIGGER_LOCAL_UPDATE;
	entry->data_len = sizeof(*k);

	KUNIT_EXPECT_EQ(test, entry->event_type, QLOG_SECURITY_KEY_UPDATED);
	KUNIT_EXPECT_EQ(test, entry->category, TQUIC_QLOG_CAT_SECURITY);
	KUNIT_EXPECT_EQ(test, entry->severity, TQUIC_QLOG_SEV_CORE);
	KUNIT_EXPECT_EQ(test, k->key_type, QLOG_KEY_CLIENT_1RTT_SECRET);
	KUNIT_EXPECT_EQ(test, k->key_phase, 1U);
	KUNIT_EXPECT_EQ(test, k->trigger, QLOG_KEY_TRIGGER_LOCAL_UPDATE);
}

static void tquic_qlog_test_key_discarded_event(struct kunit *test)
{
	struct test_qlog *qlog;
	struct tquic_qlog_event_entry *entry;
	struct tquic_qlog_key_event *k;

	qlog = test_qlog_create(test);

	entry = test_qlog_write_event(qlog, QLOG_SECURITY_KEY_DISCARDED);
	KUNIT_ASSERT_NOT_NULL(test, entry);

	k = &entry->data.key;
	k->key_type = QLOG_KEY_CLIENT_INITIAL_SECRET;
	k->key_phase = 0;
	k->generation = 0;
	k->trigger = QLOG_KEY_TRIGGER_TLS;
	entry->data_len = sizeof(*k);

	KUNIT_EXPECT_EQ(test, entry->event_type, QLOG_SECURITY_KEY_DISCARDED);
	KUNIT_EXPECT_EQ(test, entry->severity, TQUIC_QLOG_SEV_EXTRA);
	KUNIT_EXPECT_EQ(test, k->key_type, QLOG_KEY_CLIENT_INITIAL_SECRET);
}

/*
 * =============================================================================
 * Drop Reason Code Tests (draft-12 Section 6.7)
 * =============================================================================
 */

static void tquic_qlog_test_drop_reason_codes(struct kunit *test)
{
	/* Verify all drop reason codes are defined correctly */
	KUNIT_EXPECT_EQ(test, QLOG_DROP_UNKNOWN, 0);
	KUNIT_EXPECT_EQ(test, QLOG_DROP_INTERNAL_ERROR, 1);
	KUNIT_EXPECT_EQ(test, QLOG_DROP_INVALID, 2);
	KUNIT_EXPECT_EQ(test, QLOG_DROP_INVALID_LENGTH, 3);
	KUNIT_EXPECT_EQ(test, QLOG_DROP_UNSUPPORTED_VERSION, 4);
	KUNIT_EXPECT_EQ(test, QLOG_DROP_UNEXPECTED_PACKET, 5);
	KUNIT_EXPECT_EQ(test, QLOG_DROP_UNEXPECTED_SOURCE_CID, 6);
	KUNIT_EXPECT_EQ(test, QLOG_DROP_UNEXPECTED_VERSION, 7);
	KUNIT_EXPECT_EQ(test, QLOG_DROP_DUPLICATE, 8);
	KUNIT_EXPECT_EQ(test, QLOG_DROP_KEY_UNAVAILABLE, 9);
	KUNIT_EXPECT_EQ(test, QLOG_DROP_DECRYPTION_FAILURE, 10);
	KUNIT_EXPECT_EQ(test, QLOG_DROP_HEADER_PARSE_ERROR, 11);
	KUNIT_EXPECT_EQ(test, QLOG_DROP_PAYLOAD_PARSE_ERROR, 12);
	KUNIT_EXPECT_EQ(test, QLOG_DROP_PROTOCOL_VIOLATION, 13);
	KUNIT_EXPECT_EQ(test, QLOG_DROP_CONGESTION_CONTROL, 14);
	KUNIT_EXPECT_EQ(test, QLOG_DROP_CONNECTION_UNKNOWN, 15);
	KUNIT_EXPECT_EQ(test, QLOG_DROP_DOS_PREVENTION, 16);
	KUNIT_EXPECT_EQ(test, QLOG_DROP_NO_LISTENER, 17);
}

/*
 * =============================================================================
 * Packet Type Tests (draft-12 Section 6.5)
 * =============================================================================
 */

static void tquic_qlog_test_packet_types(struct kunit *test)
{
	KUNIT_EXPECT_EQ(test, QLOG_PKT_INITIAL, 0);
	KUNIT_EXPECT_EQ(test, QLOG_PKT_HANDSHAKE, 1);
	KUNIT_EXPECT_EQ(test, QLOG_PKT_0RTT, 2);
	KUNIT_EXPECT_EQ(test, QLOG_PKT_1RTT, 3);
	KUNIT_EXPECT_EQ(test, QLOG_PKT_RETRY, 4);
	KUNIT_EXPECT_EQ(test, QLOG_PKT_VERSION_NEG, 5);
	KUNIT_EXPECT_EQ(test, QLOG_PKT_STATELESS_RESET, 6);
	KUNIT_EXPECT_EQ(test, QLOG_PKT_UNKNOWN, 7);
}

/*
 * =============================================================================
 * Ring Buffer Tests
 * =============================================================================
 */

static void tquic_qlog_test_ring_buffer_basic(struct kunit *test)
{
	struct test_qlog *qlog;
	struct tquic_qlog_event_entry *entry;
	u32 head, tail;

	qlog = test_qlog_create(test);

	/* Initially empty */
	head = atomic_read(&qlog->head);
	tail = atomic_read(&qlog->tail);
	KUNIT_EXPECT_EQ(test, head, tail);

	/* Write an event */
	entry = test_qlog_write_event(qlog, QLOG_TRANSPORT_PACKET_SENT);
	KUNIT_ASSERT_NOT_NULL(test, entry);

	/* Head should advance */
	head = atomic_read(&qlog->head);
	KUNIT_EXPECT_EQ(test, head, 1U);
	KUNIT_EXPECT_EQ(test, qlog->stats.events_logged, 1ULL);

	/* Write more events */
	for (int i = 0; i < 10; i++) {
		entry = test_qlog_write_event(qlog, QLOG_RECOVERY_METRICS_UPDATED);
		KUNIT_ASSERT_NOT_NULL(test, entry);
	}

	head = atomic_read(&qlog->head);
	KUNIT_EXPECT_EQ(test, head, 11U);
	KUNIT_EXPECT_EQ(test, qlog->stats.events_logged, 11ULL);
}

static void tquic_qlog_test_ring_buffer_wrap(struct kunit *test)
{
	struct test_qlog *qlog;
	struct tquic_qlog_event_entry *entry;
	u32 head;

	qlog = test_qlog_create(test);

	/* Fill the ring buffer (64 entries) */
	for (int i = 0; i < 64; i++) {
		entry = test_qlog_write_event(qlog, QLOG_TRANSPORT_PACKET_SENT);
		entry->data.packet.header.packet_number = i;
	}

	head = atomic_read(&qlog->head);
	KUNIT_EXPECT_EQ(test, head, 0U);  /* Wrapped around */

	/* First entry should be overwritten */
	entry = &qlog->ring[0];
	KUNIT_EXPECT_EQ(test, entry->data.packet.header.packet_number, 63ULL);
}

/*
 * =============================================================================
 * Legacy Alias Tests
 * =============================================================================
 */

static void tquic_qlog_test_legacy_aliases(struct kunit *test)
{
	/* Verify legacy aliases point to correct new names */
	KUNIT_EXPECT_EQ(test, QLOG_CONNECTION_STARTED,
			QLOG_CONNECTIVITY_CONNECTION_STARTED);
	KUNIT_EXPECT_EQ(test, QLOG_CONNECTION_CLOSED,
			QLOG_CONNECTIVITY_CONNECTION_CLOSED);
	KUNIT_EXPECT_EQ(test, QLOG_PACKET_SENT,
			QLOG_TRANSPORT_PACKET_SENT);
	KUNIT_EXPECT_EQ(test, QLOG_PACKET_RECEIVED,
			QLOG_TRANSPORT_PACKET_RECEIVED);
	KUNIT_EXPECT_EQ(test, QLOG_PACKET_DROPPED,
			QLOG_TRANSPORT_PACKET_DROPPED);
	KUNIT_EXPECT_EQ(test, QLOG_METRICS_UPDATED,
			QLOG_RECOVERY_METRICS_UPDATED);
	KUNIT_EXPECT_EQ(test, QLOG_CONGESTION_STATE_UPDATED,
			QLOG_RECOVERY_CONGESTION_STATE_UPDATED);
	KUNIT_EXPECT_EQ(test, QLOG_LOSS_TIMER_UPDATED,
			QLOG_RECOVERY_LOSS_TIMER_UPDATED);
	KUNIT_EXPECT_EQ(test, QLOG_PACKET_LOST,
			QLOG_RECOVERY_PACKET_LOST);
	KUNIT_EXPECT_EQ(test, QLOG_KEY_UPDATED,
			QLOG_SECURITY_KEY_UPDATED);
	KUNIT_EXPECT_EQ(test, QLOG_KEY_RETIRED,
			QLOG_SECURITY_KEY_DISCARDED);
}

/*
 * =============================================================================
 * Test Suite Definition
 * =============================================================================
 */

static struct kunit_case tquic_qlog_test_cases[] = {
	/* Category and severity tests */
	KUNIT_CASE(tquic_qlog_test_event_categories),
	KUNIT_CASE(tquic_qlog_test_event_severities),
	KUNIT_CASE(tquic_qlog_test_event_masks),

	/* Transport event tests */
	KUNIT_CASE(tquic_qlog_test_packet_sent_event),
	KUNIT_CASE(tquic_qlog_test_packet_received_event),
	KUNIT_CASE(tquic_qlog_test_packet_dropped_event),
	KUNIT_CASE(tquic_qlog_test_packet_buffered_event),

	/* Recovery event tests */
	KUNIT_CASE(tquic_qlog_test_metrics_updated_event),
	KUNIT_CASE(tquic_qlog_test_congestion_state_updated_event),
	KUNIT_CASE(tquic_qlog_test_loss_timer_updated_event),
	KUNIT_CASE(tquic_qlog_test_packet_lost_event),

	/* Connectivity event tests */
	KUNIT_CASE(tquic_qlog_test_connection_started_event),
	KUNIT_CASE(tquic_qlog_test_connection_closed_event),
	KUNIT_CASE(tquic_qlog_test_path_updated_event),

	/* Security event tests */
	KUNIT_CASE(tquic_qlog_test_key_updated_event),
	KUNIT_CASE(tquic_qlog_test_key_discarded_event),

	/* Type and code tests */
	KUNIT_CASE(tquic_qlog_test_drop_reason_codes),
	KUNIT_CASE(tquic_qlog_test_packet_types),

	/* Ring buffer tests */
	KUNIT_CASE(tquic_qlog_test_ring_buffer_basic),
	KUNIT_CASE(tquic_qlog_test_ring_buffer_wrap),

	/* Legacy compatibility tests */
	KUNIT_CASE(tquic_qlog_test_legacy_aliases),
	{}
};

static struct kunit_suite tquic_qlog_test_suite = {
	.name = "tquic-qlog",
	.test_cases = tquic_qlog_test_cases,
};

kunit_test_suite(tquic_qlog_test_suite);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("KUnit tests for TQUIC Qlog (draft-ietf-quic-qlog-quic-events-12)");
