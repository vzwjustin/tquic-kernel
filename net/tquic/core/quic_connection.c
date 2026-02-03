// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * QUIC - Quick UDP Internet Connections
 *
 * Connection management implementation
 *
 * Copyright (c) 2024 Linux QUIC Authors
 */

#include <linux/slab.h>
#include <linux/random.h>
#include <net/quic.h>
#include "../diag/trace.h"

static struct kmem_cache *quic_conn_cache __read_mostly;
static struct kmem_cache *quic_cid_cache __read_mostly;

/* Hash table for connection ID lookups */
#define QUIC_CID_HASH_BITS	12
#define QUIC_CID_HASH_SIZE	(1 << QUIC_CID_HASH_BITS)

static struct hlist_head quic_cid_hash[QUIC_CID_HASH_SIZE];
static DEFINE_SPINLOCK(quic_cid_hash_lock);

static u32 quic_cid_hash_fn(const struct quic_connection_id *cid)
{
	u32 hash = 0;
	int i;

	for (i = 0; i < cid->len; i++)
		hash = hash * 31 + cid->data[i];

	return hash & (QUIC_CID_HASH_SIZE - 1);
}

int quic_cid_hash_init(void)
{
	int i;

	for (i = 0; i < QUIC_CID_HASH_SIZE; i++)
		INIT_HLIST_HEAD(&quic_cid_hash[i]);

	quic_cid_cache = kmem_cache_create("quic_cid",
					   sizeof(struct quic_cid_entry), 0,
					   SLAB_HWCACHE_ALIGN, NULL);
	if (!quic_cid_cache)
		return -ENOMEM;

	return 0;
}

void quic_cid_hash_cleanup(void)
{
	kmem_cache_destroy(quic_cid_cache);
}

int quic_cid_hash_add(struct quic_cid_entry *entry)
{
	u32 hash = quic_cid_hash_fn(&entry->cid);

	spin_lock_bh(&quic_cid_hash_lock);
	hlist_add_head(&entry->hash_node, &quic_cid_hash[hash]);
	spin_unlock_bh(&quic_cid_hash_lock);

	return 0;
}

void quic_cid_hash_del(struct quic_cid_entry *entry)
{
	spin_lock_bh(&quic_cid_hash_lock);
	hlist_del_init(&entry->hash_node);
	spin_unlock_bh(&quic_cid_hash_lock);
}

struct quic_cid_entry *quic_cid_hash_lookup(struct quic_connection_id *cid)
{
	u32 hash = quic_cid_hash_fn(cid);
	struct quic_cid_entry *entry;

	spin_lock_bh(&quic_cid_hash_lock);
	hlist_for_each_entry(entry, &quic_cid_hash[hash], hash_node) {
		if (entry->cid.len == cid->len &&
		    memcmp(entry->cid.data, cid->data, cid->len) == 0) {
			spin_unlock_bh(&quic_cid_hash_lock);
			return entry;
		}
	}
	spin_unlock_bh(&quic_cid_hash_lock);

	return NULL;
}

struct quic_connection *quic_conn_lookup(struct quic_connection_id *cid)
{
	struct quic_cid_entry *entry;

	entry = quic_cid_hash_lookup(cid);
	if (entry) {
		struct quic_connection *conn;
		conn = container_of(entry->list.next, struct quic_connection, scid_list);
		return conn;
	}

	return NULL;
}

static void quic_conn_generate_cid(struct quic_connection_id *cid, u8 len)
{
	cid->len = len;
	get_random_bytes(cid->data, len);
}

static struct quic_cid_entry *quic_cid_entry_create(
	struct quic_connection_id *cid, u64 seq)
{
	struct quic_cid_entry *entry;

	entry = kmem_cache_alloc(quic_cid_cache, GFP_KERNEL);
	if (!entry)
		return NULL;

	memcpy(&entry->cid, cid, sizeof(*cid));
	entry->sequence_number = seq;
	entry->retire_prior_to = 0;
	entry->used = 0;
	INIT_LIST_HEAD(&entry->list);
	INIT_HLIST_NODE(&entry->hash_node);
	get_random_bytes(entry->stateless_reset_token, 16);

	return entry;
}

static void quic_cid_entry_destroy(struct quic_cid_entry *entry)
{
	list_del(&entry->list);
	quic_cid_hash_del(entry);
	kmem_cache_free(quic_cid_cache, entry);
}

static void quic_pn_space_init(struct quic_pn_space *pn_space)
{
	spin_lock_init(&pn_space->lock);
	pn_space->next_pn = 0;
	pn_space->largest_acked_pn = 0;
	pn_space->largest_recv_pn = 0;
	pn_space->loss_time = 0;
	pn_space->last_ack_time = 0;
	pn_space->ack_eliciting_in_flight = 0;
	INIT_LIST_HEAD(&pn_space->sent_packets);
	INIT_LIST_HEAD(&pn_space->lost_packets);
	memset(&pn_space->recv_ack_info, 0, sizeof(pn_space->recv_ack_info));
	pn_space->keys_available = 0;
	pn_space->keys_discarded = 0;
}

static void quic_pn_space_destroy(struct quic_pn_space *pn_space)
{
	struct quic_sent_packet *pkt, *tmp;

	list_for_each_entry_safe(pkt, tmp, &pn_space->sent_packets, list) {
		list_del(&pkt->list);
		if (pkt->skb)
			kfree_skb(pkt->skb);
		kfree(pkt);
	}

	list_for_each_entry_safe(pkt, tmp, &pn_space->lost_packets, list) {
		list_del(&pkt->list);
		if (pkt->skb)
			kfree_skb(pkt->skb);
		kfree(pkt);
	}
}

static void quic_conn_init_local_params(struct quic_connection *conn,
					struct quic_config *config)
{
	struct quic_transport_params *params = &conn->local_params;

	params->max_idle_timeout = config->max_idle_timeout_ms;
	params->max_udp_payload_size = QUIC_MAX_PACKET_SIZE;
	params->initial_max_data = config->initial_max_data;
	params->initial_max_stream_data_bidi_local =
		config->initial_max_stream_data_bidi_local;
	params->initial_max_stream_data_bidi_remote =
		config->initial_max_stream_data_bidi_remote;
	params->initial_max_stream_data_uni =
		config->initial_max_stream_data_uni;
	params->initial_max_streams_bidi = config->initial_max_streams_bidi;
	params->initial_max_streams_uni = config->initial_max_streams_uni;
	params->ack_delay_exponent = config->ack_delay_exponent;
	params->max_ack_delay = config->max_ack_delay_ms;
	params->disable_active_migration = config->disable_active_migration;
	params->active_connection_id_limit = config->max_connection_ids;
	params->max_datagram_frame_size = config->max_datagram_size;
}

static void quic_conn_init_flow_control(struct quic_connection *conn)
{
	struct quic_flow_control *local = &conn->local_fc;
	struct quic_flow_control *remote = &conn->remote_fc;

	/* Local flow control limits (what we advertise to peer) */
	local->max_data = conn->local_params.initial_max_data;
	local->data_sent = 0;
	local->data_received = 0;
	local->max_streams_bidi = conn->local_params.initial_max_streams_bidi;
	local->max_streams_uni = conn->local_params.initial_max_streams_uni;
	local->streams_opened_bidi = 0;
	local->streams_opened_uni = 0;
	local->blocked = 0;

	/* Remote flow control limits (what peer advertises to us) */
	remote->max_data = 0;  /* Updated when we receive transport params */
	remote->data_sent = 0;
	remote->data_received = 0;
	remote->max_streams_bidi = 0;
	remote->max_streams_uni = 0;
	remote->streams_opened_bidi = 0;
	remote->streams_opened_uni = 0;
	remote->blocked = 0;
}

static void quic_timer_loss_cb(struct timer_list *t)
{
	struct quic_connection *conn = from_timer(conn, t, timers[QUIC_TIMER_LOSS]);

	quic_loss_detection_on_timeout(conn);
	quic_timer_update(conn);
}

static void quic_timer_ack_cb(struct timer_list *t)
{
	struct quic_connection *conn = from_timer(conn, t, timers[QUIC_TIMER_ACK]);
	int i;

	for (i = 0; i < QUIC_PN_SPACE_MAX; i++) {
		if (quic_ack_should_send(conn, i)) {
			struct sk_buff *skb = alloc_skb(256, GFP_ATOMIC);
			if (skb)
				quic_ack_create(conn, i, skb);
		}
	}
}

static void quic_timer_idle_cb(struct timer_list *t)
{
	struct quic_connection *conn = from_timer(conn, t, timers[QUIC_TIMER_IDLE]);
	unsigned long flags;

	spin_lock_irqsave(&conn->lock, flags);
	if (conn->state != QUIC_STATE_CLOSED) {
		conn->state = QUIC_STATE_CLOSED;
		spin_unlock_irqrestore(&conn->lock, flags);
		if (conn->qsk)
			wake_up(&conn->qsk->event_wait);
		return;
	}
	spin_unlock_irqrestore(&conn->lock, flags);
}

static void quic_timer_handshake_cb(struct timer_list *t)
{
	struct quic_connection *conn = from_timer(conn, t, timers[QUIC_TIMER_HANDSHAKE]);
	unsigned long flags;

	spin_lock_irqsave(&conn->lock, flags);
	if (!conn->handshake_complete && conn->state == QUIC_STATE_CONNECTING) {
		conn->error_code = QUIC_ERROR_INTERNAL_ERROR;
		conn->state = QUIC_STATE_CLOSED;
		spin_unlock_irqrestore(&conn->lock, flags);
		if (conn->qsk)
			wake_up(&conn->qsk->event_wait);
		return;
	}
	spin_unlock_irqrestore(&conn->lock, flags);
}

static void quic_timer_path_probe_cb(struct timer_list *t)
{
	struct quic_connection *conn = from_timer(conn, t, timers[QUIC_TIMER_PATH_PROBE]);
	struct quic_path *path;

	list_for_each_entry(path, &conn->paths, list) {
		if (path->challenge_pending && !path->validated) {
			quic_path_challenge(path);
		}
	}
}

static void quic_conn_tx_work(struct work_struct *work)
{
	struct quic_connection *conn = container_of(work, struct quic_connection, tx_work);
	struct sk_buff *skb;
	int i;

	for (i = QUIC_PN_SPACE_APPLICATION; i >= QUIC_PN_SPACE_INITIAL; i--) {
		struct quic_pn_space *pn_space = &conn->pn_spaces[i];

		if (!pn_space->keys_available || pn_space->keys_discarded)
			continue;

		skb = quic_packet_build(conn, pn_space);
		if (skb) {
			int err = quic_udp_send(conn->qsk, skb,
						(struct sockaddr *)&conn->active_path->remote_addr);
			if (err < 0)
				kfree_skb(skb);
		}
	}
}

static void quic_conn_rx_work(struct work_struct *work)
{
	struct quic_connection *conn = container_of(work, struct quic_connection, rx_work);
	struct sk_buff *skb;

	while ((skb = skb_dequeue(&conn->pending_frames)) != NULL) {
		quic_packet_process(conn, skb);
		kfree_skb(skb);
	}
}

static void quic_conn_close_work(struct work_struct *work)
{
	struct quic_connection *conn = container_of(work, struct quic_connection, close_work);
	unsigned long flags;

	spin_lock_irqsave(&conn->lock, flags);
	if (conn->state == QUIC_STATE_DRAINING) {
		conn->state = QUIC_STATE_CLOSED;
		spin_unlock_irqrestore(&conn->lock, flags);
		if (conn->qsk)
			wake_up(&conn->qsk->event_wait);
		return;
	}
	spin_unlock_irqrestore(&conn->lock, flags);
}

struct quic_connection *quic_conn_create(struct quic_sock *qsk, bool is_server)
{
	struct quic_connection *conn;
	struct quic_cid_entry *scid_entry;
	struct quic_path *path;
	int i;

	conn = kzalloc(sizeof(*conn), GFP_KERNEL);
	if (!conn)
		return NULL;

	conn->qsk = qsk;
	spin_lock_init(&conn->lock);
	conn->state = QUIC_STATE_IDLE;
	conn->version = qsk->config.version;
	conn->is_server = is_server;

	/* Generate source connection ID */
	quic_conn_generate_cid(&conn->scid, 8);
	INIT_LIST_HEAD(&conn->scid_list);
	INIT_LIST_HEAD(&conn->dcid_list);

	/* Create initial source CID entry */
	scid_entry = quic_cid_entry_create(&conn->scid, 0);
	if (!scid_entry)
		goto err_free_conn;

	list_add(&scid_entry->list, &conn->scid_list);
	quic_cid_hash_add(scid_entry);
	conn->next_scid_seq = 1;

	/* Initialize packet number spaces */
	for (i = 0; i < QUIC_PN_SPACE_MAX; i++)
		quic_pn_space_init(&conn->pn_spaces[i]);

	/* Initialize crypto contexts */
	for (i = 0; i < QUIC_CRYPTO_MAX; i++) {
		memset(&conn->crypto[i], 0, sizeof(conn->crypto[i]));
	}
	conn->crypto_level = QUIC_CRYPTO_INITIAL;

	/* Initialize streams */
	conn->streams = RB_ROOT;
	spin_lock_init(&conn->streams_lock);

	if (is_server) {
		conn->next_stream_id_bidi = 1;  /* Server-initiated bidi starts at 1 */
		conn->next_stream_id_uni = 3;   /* Server-initiated uni starts at 3 */
	} else {
		conn->next_stream_id_bidi = 0;  /* Client-initiated bidi starts at 0 */
		conn->next_stream_id_uni = 2;   /* Client-initiated uni starts at 2 */
	}

	/* Initialize flow control */
	quic_conn_init_local_params(conn, &qsk->config);
	quic_conn_init_flow_control(conn);

	/* Initialize paths */
	INIT_LIST_HEAD(&conn->paths);
	path = quic_path_create(conn, NULL, NULL);
	if (!path)
		goto err_free_cid;
	conn->active_path = path;
	conn->num_paths = 1;

	/* Initialize timers */
	timer_setup(&conn->timers[QUIC_TIMER_LOSS], quic_timer_loss_cb, 0);
	timer_setup(&conn->timers[QUIC_TIMER_ACK], quic_timer_ack_cb, 0);
	timer_setup(&conn->timers[QUIC_TIMER_IDLE], quic_timer_idle_cb, 0);
	timer_setup(&conn->timers[QUIC_TIMER_HANDSHAKE], quic_timer_handshake_cb, 0);
	timer_setup(&conn->timers[QUIC_TIMER_PATH_PROBE], quic_timer_path_probe_cb, 0);

	/* Initialize work queues */
	INIT_WORK(&conn->tx_work, quic_conn_tx_work);
	INIT_WORK(&conn->rx_work, quic_conn_rx_work);
	INIT_WORK(&conn->close_work, quic_conn_close_work);

	/* Initialize loss detection */
	quic_loss_detection_init(conn);

	/* Initialize pending frame queues */
	skb_queue_head_init(&conn->pending_frames);
	for (i = 0; i < QUIC_CRYPTO_MAX; i++)
		skb_queue_head_init(&conn->crypto_buffer[i]);

	/* Initialize stream priority scheduler (RFC 9218) */
	quic_sched_init(conn);

	/* Initialize pacing state */
	skb_queue_head_init(&conn->pacing_queue);
	conn->pacing_next_send = 0;

	/* Initialize 0-RTT early data state (RFC 9001 Section 4.6) */
	skb_queue_head_init(&conn->early_data_buffer);
	conn->early_data_enabled = 0;
	conn->early_data_accepted = 0;
	conn->early_data_rejected = 0;
	conn->max_early_data = 0;
	conn->early_data_sent = 0;

	/* Initialize statistics */
	memset(&conn->stats, 0, sizeof(conn->stats));

	refcount_set(&conn->refcnt, 1);

	trace_quic_conn_create(quic_trace_conn_id(&conn->scid), is_server);

	return conn;

err_free_cid:
	quic_cid_entry_destroy(scid_entry);
err_free_conn:
	kfree(conn);
	return NULL;
}

void quic_conn_destroy(struct quic_connection *conn)
{
	struct quic_cid_entry *entry, *tmp_entry;
	struct quic_path *path, *tmp_path;
	struct quic_stream *stream, *tmp_stream;
	struct rb_node *node;
	int i;

	if (!conn)
		return;

	trace_quic_conn_destroy(quic_trace_conn_id(&conn->scid),
				conn->close_error_code);

	/* Cancel all timers */
	for (i = 0; i < QUIC_TIMER_MAX; i++)
		del_timer_sync(&conn->timers[i]);

	/* Cancel work */
	cancel_work_sync(&conn->tx_work);
	cancel_work_sync(&conn->rx_work);
	cancel_work_sync(&conn->close_work);

	/* Destroy streams */
	spin_lock(&conn->streams_lock);
	node = rb_first(&conn->streams);
	while (node) {
		stream = rb_entry(node, struct quic_stream, node);
		node = rb_next(node);
		rb_erase(&stream->node, &conn->streams);
		quic_stream_destroy(stream);
	}
	spin_unlock(&conn->streams_lock);

	/* Destroy paths */
	list_for_each_entry_safe(path, tmp_path, &conn->paths, list) {
		quic_path_destroy(path);
	}

	/* Destroy connection IDs */
	list_for_each_entry_safe(entry, tmp_entry, &conn->scid_list, list) {
		quic_cid_entry_destroy(entry);
	}
	list_for_each_entry_safe(entry, tmp_entry, &conn->dcid_list, list) {
		quic_cid_entry_destroy(entry);
	}

	/* Destroy packet number spaces */
	for (i = 0; i < QUIC_PN_SPACE_MAX; i++)
		quic_pn_space_destroy(&conn->pn_spaces[i]);

	/* Destroy crypto contexts */
	for (i = 0; i < QUIC_CRYPTO_MAX; i++)
		quic_crypto_destroy(&conn->crypto[i]);

	/* Free pending frames, pacing queue, and early data buffer */
	skb_queue_purge(&conn->pending_frames);
	skb_queue_purge(&conn->pacing_queue);
	skb_queue_purge(&conn->early_data_buffer);
	for (i = 0; i < QUIC_CRYPTO_MAX; i++)
		skb_queue_purge(&conn->crypto_buffer[i]);

	kfree(conn->reason_phrase);
	kfree(conn);
}

int quic_conn_connect(struct quic_connection *conn,
		      struct sockaddr *addr, int addr_len)
{
	struct quic_sock *qsk = conn->qsk;
	struct quic_path *path = conn->active_path;
	int err;

	spin_lock_bh(&conn->lock);
	if (conn->state != QUIC_STATE_IDLE) {
		spin_unlock_bh(&conn->lock);
		return -EINVAL;
	}
	spin_unlock_bh(&conn->lock);

	/* Set remote address */
	memcpy(&path->remote_addr, addr, addr_len);

	/* Create UDP socket for encapsulation if not exists */
	if (!qsk->udp_sock) {
		err = quic_udp_encap_init(qsk);
		if (err)
			return err;
	}

	/* Derive initial secrets from destination connection ID */
	err = quic_crypto_derive_initial_secrets(conn, &conn->dcid);
	if (err)
		return err;

	spin_lock_bh(&conn->lock);
	conn->pn_spaces[QUIC_PN_SPACE_INITIAL].keys_available = 1;
	conn->state = QUIC_STATE_CONNECTING;
	spin_unlock_bh(&conn->lock);

	/* Start handshake timer */
	quic_timer_set(conn, QUIC_TIMER_HANDSHAKE,
		       ktime_add_ms(ktime_get(), qsk->config.handshake_timeout_ms));

	/* Queue TX work to send Initial packet */
	schedule_work(&conn->tx_work);

	return 0;
}

int quic_conn_accept(struct quic_connection *conn)
{
	spin_lock_bh(&conn->lock);
	if (conn->state != QUIC_STATE_IDLE) {
		spin_unlock_bh(&conn->lock);
		return -EINVAL;
	}

	conn->state = QUIC_STATE_HANDSHAKE;
	spin_unlock_bh(&conn->lock);
	return 0;
}

int quic_conn_close(struct quic_connection *conn, u64 error_code,
		    const char *reason, u32 reason_len, bool app_error)
{
	spin_lock_bh(&conn->lock);
	if (conn->state == QUIC_STATE_CLOSED ||
	    conn->state == QUIC_STATE_DRAINING) {
		spin_unlock_bh(&conn->lock);
		return -EINVAL;
	}

	conn->error_code = error_code;
	conn->app_error = app_error ? 1 : 0;

	if (reason && reason_len > 0) {
		char *phrase = kmemdup(reason, reason_len, GFP_ATOMIC);

		if (phrase) {
			kfree(conn->reason_phrase);
			conn->reason_phrase = phrase;
			conn->reason_len = reason_len;
		}
		/* On allocation failure, proceed without reason phrase */
	}

	conn->state = QUIC_STATE_CLOSING;
	spin_unlock_bh(&conn->lock);

	/* Send CONNECTION_CLOSE frame */
	schedule_work(&conn->tx_work);

	/* Start draining timer (3 * PTO) */
	quic_timer_set(conn, QUIC_TIMER_IDLE,
		       ktime_add_ms(ktime_get(),
				    3 * quic_rtt_pto(&conn->active_path->rtt)));

	return 0;
}

void quic_conn_set_state(struct quic_connection *conn, enum quic_state state)
{
	enum quic_state old_state;

	spin_lock_bh(&conn->lock);
	old_state = conn->state;
	conn->state = state;

	trace_quic_conn_state_change(quic_trace_conn_id(&conn->scid),
				     old_state, state);

	switch (state) {
	case QUIC_STATE_CONNECTED:
		conn->handshake_complete = 1;
		conn->pn_spaces[QUIC_PN_SPACE_INITIAL].keys_discarded = 1;
		conn->pn_spaces[QUIC_PN_SPACE_HANDSHAKE].keys_discarded = 1;
		atomic64_set(&conn->stats.handshake_time_us, ktime_to_us(ktime_get()));
		spin_unlock_bh(&conn->lock);

		trace_quic_handshake_complete(quic_trace_conn_id(&conn->scid),
					      atomic64_read(&conn->stats.handshake_time_us));

		quic_timer_cancel(conn, QUIC_TIMER_HANDSHAKE);
		quic_crypto_destroy(&conn->crypto[QUIC_CRYPTO_INITIAL]);
		quic_crypto_destroy(&conn->crypto[QUIC_CRYPTO_HANDSHAKE]);

		if (conn->qsk)
			wake_up(&conn->qsk->event_wait);
		goto out;

	case QUIC_STATE_DRAINING:
		conn->draining = 1;
		spin_unlock_bh(&conn->lock);
		/* Schedule close after draining period */
		quic_timer_set(conn, QUIC_TIMER_IDLE,
			       ktime_add_ms(ktime_get(),
					    3 * quic_rtt_pto(&conn->active_path->rtt)));
		goto out;

	case QUIC_STATE_CLOSED:
		spin_unlock_bh(&conn->lock);
		/* Cancel all timers except idle */
		quic_timer_cancel(conn, QUIC_TIMER_LOSS);
		quic_timer_cancel(conn, QUIC_TIMER_ACK);
		quic_timer_cancel(conn, QUIC_TIMER_HANDSHAKE);
		quic_timer_cancel(conn, QUIC_TIMER_PATH_PROBE);

		if (conn->qsk)
			wake_up(&conn->qsk->event_wait);
		goto out;

	default:
		break;
	}
	spin_unlock_bh(&conn->lock);
out:
	return;
}

/* Generate new connection ID */
int quic_conn_new_cid(struct quic_connection *conn,
		      struct quic_connection_id *new_cid)
{
	struct quic_cid_entry *entry;
	u64 seq = conn->next_scid_seq++;

	quic_conn_generate_cid(new_cid, 8);

	entry = quic_cid_entry_create(new_cid, seq);
	if (!entry)
		return -ENOMEM;

	list_add_tail(&entry->list, &conn->scid_list);
	quic_cid_hash_add(entry);

	return 0;
}

/* Retire a connection ID */
int quic_conn_retire_cid(struct quic_connection *conn, u64 seq)
{
	struct quic_cid_entry *entry, *tmp;

	list_for_each_entry_safe(entry, tmp, &conn->scid_list, list) {
		if (entry->sequence_number == seq) {
			quic_cid_entry_destroy(entry);
			return 0;
		}
	}

	return -ENOENT;
}

/* Process NEW_CONNECTION_ID from peer */
int quic_conn_add_peer_cid(struct quic_connection *conn,
			   struct quic_connection_id *cid,
			   u64 seq, u64 retire_prior_to,
			   const u8 *reset_token)
{
	struct quic_cid_entry *entry, *tmp;

	/* Retire CIDs with sequence < retire_prior_to */
	list_for_each_entry_safe(entry, tmp, &conn->dcid_list, list) {
		if (entry->sequence_number < retire_prior_to) {
			list_del(&entry->list);
			kfree(entry);
		}
	}

	conn->retire_dcid_prior_to = retire_prior_to;

	/* Add new CID */
	entry = quic_cid_entry_create(cid, seq);
	if (!entry)
		return -ENOMEM;

	if (reset_token)
		memcpy(entry->stateless_reset_token, reset_token, 16);

	list_add_tail(&entry->list, &conn->dcid_list);

	return 0;
}

/* Get active destination CID */
struct quic_connection_id *quic_conn_get_dcid(struct quic_connection *conn)
{
	return &conn->dcid;
}

/* Rotate to next destination CID */
int quic_conn_rotate_dcid(struct quic_connection *conn)
{
	struct quic_cid_entry *entry;

	list_for_each_entry(entry, &conn->dcid_list, list) {
		if (!entry->used) {
			memcpy(&conn->dcid, &entry->cid, sizeof(conn->dcid));
			entry->used = 1;
			return 0;
		}
	}

	return -ENOENT;  /* No available CIDs */
}

/*
 * quic_conn_migrate_to_preferred_address - Initiate migration to server's
 *                                          preferred address
 * @conn: QUIC connection
 *
 * RFC 9000 Section 9.6: Use of Preferred Address
 *
 * This function initiates path validation to the server's preferred address.
 * The client MAY choose to use either IPv4 or IPv6, or both. The client
 * initiates path validation to the preferred address and migrates the
 * connection if validation succeeds.
 *
 * Returns 0 on success (path validation initiated), negative error code
 * on failure. Failure to validate the preferred address does not cause
 * connection failure per RFC 9000.
 */
static int quic_conn_migrate_to_preferred_address(struct quic_connection *conn)
{
	struct quic_preferred_address *pa;
	struct quic_path *new_path = NULL;
	struct sockaddr_storage remote_addr;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	struct quic_connection_id new_cid;
	int ret;

	pa = &conn->remote_params.preferred_address;

	/*
	 * Validate that we have a usable preferred address.
	 * Per RFC 9000, at least one address family should be provided.
	 */

	/* Try IPv6 first if available (and if IPv6 is not all zeros) */
	memset(&remote_addr, 0, sizeof(remote_addr));
	sin6 = (struct sockaddr_in6 *)&remote_addr;

	if (pa->ipv6_port != 0 &&
	    memcmp(pa->ipv6_addr, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16) != 0) {
		/* Use IPv6 preferred address */
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = pa->ipv6_port;
		memcpy(&sin6->sin6_addr, pa->ipv6_addr, 16);

		pr_debug("QUIC: Attempting migration to IPv6 preferred address\n");
	} else if (pa->ipv4_port != 0 &&
		   memcmp(pa->ipv4_addr, "\0\0\0\0", 4) != 0) {
		/* Use IPv4 preferred address */
		sin = (struct sockaddr_in *)&remote_addr;
		sin->sin_family = AF_INET;
		sin->sin_port = pa->ipv4_port;
		memcpy(&sin->sin_addr, pa->ipv4_addr, 4);

		pr_debug("QUIC: Attempting migration to IPv4 preferred address\n");
	} else {
		/* No valid address provided */
		pr_debug("QUIC: No valid preferred address provided\n");
		return -EINVAL;
	}

	/*
	 * Create new path to preferred address.
	 * The path uses the local address from the active path.
	 */
	if (!conn->active_path)
		return -EINVAL;

	new_path = quic_path_create(conn,
				     (struct sockaddr *)&conn->active_path->local_addr,
				     (struct sockaddr *)&remote_addr);
	if (!new_path) {
		pr_err("QUIC: Failed to create path to preferred address\n");
		return -ENOMEM;
	}

	/* Mark this path as being for preferred address migration */
	new_path->is_preferred_addr = 1;

	/*
	 * Add the new connection ID from preferred address.
	 * Per RFC 9000: "The sequence number of the connection ID supplied in
	 * the preferred_address transport parameter is 1."
	 */
	if (pa->connection_id_len > 0) {
		new_cid.len = pa->connection_id_len;
		memcpy(new_cid.data, pa->connection_id, pa->connection_id_len);

		ret = quic_conn_add_peer_cid(conn, &new_cid, 1, 0,
					      pa->stateless_reset_token);
		if (ret < 0) {
			pr_err("QUIC: Failed to add preferred address CID: %d\n",
			       ret);
			quic_path_destroy(new_path);
			return ret;
		}

		/* Switch to the new connection ID for this path */
		memcpy(&conn->dcid, &new_cid, sizeof(conn->dcid));
	}

	/*
	 * Initiate path validation per RFC 9000 Section 8.2.
	 * The connection will migrate to this path after validation succeeds.
	 */
	ret = quic_path_validate(new_path);
	if (ret < 0) {
		pr_err("QUIC: Failed to start path validation: %d\n", ret);
		quic_path_destroy(new_path);
		return ret;
	}

	pr_debug("QUIC: Path validation to preferred address initiated\n");

	/*
	 * Note: The actual migration (calling quic_path_migrate) happens
	 * when the PATH_RESPONSE is received and the path is validated.
	 * See quic_path_on_validated() for migration completion.
	 */

	return 0;
}

/*
 * Transport Parameter IDs per RFC 9000 Section 18.2
 */
#define QUIC_TP_ORIGINAL_DESTINATION_CID		0x00
#define QUIC_TP_MAX_IDLE_TIMEOUT			0x01
#define QUIC_TP_STATELESS_RESET_TOKEN			0x02
#define QUIC_TP_MAX_UDP_PAYLOAD_SIZE			0x03
#define QUIC_TP_INITIAL_MAX_DATA			0x04
#define QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL	0x05
#define QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE	0x06
#define QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI		0x07
#define QUIC_TP_INITIAL_MAX_STREAMS_BIDI		0x08
#define QUIC_TP_INITIAL_MAX_STREAMS_UNI			0x09
#define QUIC_TP_ACK_DELAY_EXPONENT			0x0a
#define QUIC_TP_MAX_ACK_DELAY				0x0b
#define QUIC_TP_DISABLE_ACTIVE_MIGRATION		0x0c
#define QUIC_TP_PREFERRED_ADDRESS			0x0d
#define QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT		0x0e
#define QUIC_TP_INITIAL_SOURCE_CID			0x0f
#define QUIC_TP_RETRY_SOURCE_CID			0x10
#define QUIC_TP_MAX_DATAGRAM_FRAME_SIZE			0x20
#define QUIC_TP_GREASE_QUIC_BIT				0x2ab2

/*
 * RFC 9000 Section 18.2 Limits for transport parameters
 */
#define QUIC_TP_MAX_UDP_PAYLOAD_SIZE_MIN	1200
#define QUIC_TP_MAX_UDP_PAYLOAD_SIZE_MAX	65527
#define QUIC_TP_ACK_DELAY_EXPONENT_MAX		20
#define QUIC_TP_MAX_ACK_DELAY_MAX		(1ULL << 14)  /* 16384 ms */
#define QUIC_TP_ACTIVE_CID_LIMIT_MIN		2
#define QUIC_TP_MAX_STREAMS_MAX			(1ULL << 60)
#define QUIC_TP_MAX_DATA_MAX			(1ULL << 62)

/**
 * quic_transport_param_parse - Parse transport parameters from TLS extension
 * @conn: QUIC connection
 * @data: Raw transport parameter data from TLS extension
 * @len: Length of data
 *
 * Parses transport parameters encoded per RFC 9000 Section 18.
 * Each parameter: parameter_id (varint) | length (varint) | value
 *
 * Returns 0 on success, negative error code on failure:
 *   -EINVAL: Malformed data or invalid encoding
 *   -EPROTO: Protocol violation (invalid parameter value per RFC 9000)
 */
int quic_transport_param_parse(struct quic_connection *conn,
			       const u8 *data, size_t len)
{
	struct quic_transport_params *params = &conn->remote_params;
	size_t offset = 0;
	u64 param_id;
	u64 param_len;
	int varint_len;
	bool seen_params[32] = {0};

	/* Initialize with RFC 9000 defaults */
	memset(params, 0, sizeof(*params));
	params->max_udp_payload_size = 65527;
	params->ack_delay_exponent = 3;
	params->max_ack_delay = 25;
	params->active_connection_id_limit = 2;

	while (offset < len) {
		const u8 *param_data;
		u64 value;

		/* Parse parameter ID */
		varint_len = quic_varint_decode(data + offset, len - offset,
						&param_id);
		if (varint_len < 0)
			return -EINVAL;
		offset += varint_len;

		/* Parse parameter length */
		if (offset >= len)
			return -EINVAL;
		varint_len = quic_varint_decode(data + offset, len - offset,
						&param_len);
		if (varint_len < 0)
			return -EINVAL;
		offset += varint_len;

		if (param_len > len - offset)
			return -EINVAL;

		param_data = data + offset;

		/* Check for duplicate parameters (RFC 9000 Section 7.4) */
		if (param_id < 32) {
			if (seen_params[param_id])
				return -EPROTO;
			seen_params[param_id] = true;
		}

		switch (param_id) {
		case QUIC_TP_ORIGINAL_DESTINATION_CID:
			if (param_len > QUIC_MAX_CONNECTION_ID_LEN)
				return -EPROTO;
			if (!conn->is_server)
				params->original_destination_connection_id_len =
					param_len;
			break;

		case QUIC_TP_MAX_IDLE_TIMEOUT:
			if (param_len > 8)
				return -EINVAL;
			varint_len = quic_varint_decode(param_data, param_len,
							&value);
			if (varint_len < 0 || (size_t)varint_len != param_len)
				return -EINVAL;
			params->max_idle_timeout = value;
			break;

		case QUIC_TP_STATELESS_RESET_TOKEN:
			if (param_len != 16)
				return -EPROTO;
			if (conn->is_server)
				return -EPROTO;
			memcpy(params->stateless_reset_token, param_data, 16);
			break;

		case QUIC_TP_MAX_UDP_PAYLOAD_SIZE:
			if (param_len > 8)
				return -EINVAL;
			varint_len = quic_varint_decode(param_data, param_len,
							&value);
			if (varint_len < 0 || (size_t)varint_len != param_len)
				return -EINVAL;
			if (value < QUIC_TP_MAX_UDP_PAYLOAD_SIZE_MIN)
				return -EPROTO;
			if (value > QUIC_TP_MAX_UDP_PAYLOAD_SIZE_MAX)
				value = QUIC_TP_MAX_UDP_PAYLOAD_SIZE_MAX;
			params->max_udp_payload_size = value;
			break;

		case QUIC_TP_INITIAL_MAX_DATA:
			if (param_len > 8)
				return -EINVAL;
			varint_len = quic_varint_decode(param_data, param_len,
							&value);
			if (varint_len < 0 || (size_t)varint_len != param_len)
				return -EINVAL;
			if (value > QUIC_TP_MAX_DATA_MAX)
				return -EPROTO;
			params->initial_max_data = value;
			break;

		case QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL:
			if (param_len > 8)
				return -EINVAL;
			varint_len = quic_varint_decode(param_data, param_len,
							&value);
			if (varint_len < 0 || (size_t)varint_len != param_len)
				return -EINVAL;
			if (value > QUIC_TP_MAX_DATA_MAX)
				return -EPROTO;
			params->initial_max_stream_data_bidi_local = value;
			break;

		case QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE:
			if (param_len > 8)
				return -EINVAL;
			varint_len = quic_varint_decode(param_data, param_len,
							&value);
			if (varint_len < 0 || (size_t)varint_len != param_len)
				return -EINVAL;
			if (value > QUIC_TP_MAX_DATA_MAX)
				return -EPROTO;
			params->initial_max_stream_data_bidi_remote = value;
			break;

		case QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI:
			if (param_len > 8)
				return -EINVAL;
			varint_len = quic_varint_decode(param_data, param_len,
							&value);
			if (varint_len < 0 || (size_t)varint_len != param_len)
				return -EINVAL;
			if (value > QUIC_TP_MAX_DATA_MAX)
				return -EPROTO;
			params->initial_max_stream_data_uni = value;
			break;

		case QUIC_TP_INITIAL_MAX_STREAMS_BIDI:
			if (param_len > 8)
				return -EINVAL;
			varint_len = quic_varint_decode(param_data, param_len,
							&value);
			if (varint_len < 0 || (size_t)varint_len != param_len)
				return -EINVAL;
			if (value > QUIC_TP_MAX_STREAMS_MAX)
				return -EPROTO;
			params->initial_max_streams_bidi = value;
			break;

		case QUIC_TP_INITIAL_MAX_STREAMS_UNI:
			if (param_len > 8)
				return -EINVAL;
			varint_len = quic_varint_decode(param_data, param_len,
							&value);
			if (varint_len < 0 || (size_t)varint_len != param_len)
				return -EINVAL;
			if (value > QUIC_TP_MAX_STREAMS_MAX)
				return -EPROTO;
			params->initial_max_streams_uni = value;
			break;

		case QUIC_TP_ACK_DELAY_EXPONENT:
			if (param_len > 8)
				return -EINVAL;
			varint_len = quic_varint_decode(param_data, param_len,
							&value);
			if (varint_len < 0 || (size_t)varint_len != param_len)
				return -EINVAL;
			if (value > QUIC_TP_ACK_DELAY_EXPONENT_MAX)
				return -EPROTO;
			params->ack_delay_exponent = value;
			break;

		case QUIC_TP_MAX_ACK_DELAY:
			if (param_len > 8)
				return -EINVAL;
			varint_len = quic_varint_decode(param_data, param_len,
							&value);
			if (varint_len < 0 || (size_t)varint_len != param_len)
				return -EINVAL;
			if (value >= QUIC_TP_MAX_ACK_DELAY_MAX)
				return -EPROTO;
			params->max_ack_delay = value;
			break;

		case QUIC_TP_DISABLE_ACTIVE_MIGRATION:
			if (param_len != 0)
				return -EPROTO;
			params->disable_active_migration = 1;
			break;

		case QUIC_TP_PREFERRED_ADDRESS:
			/*
			 * RFC 9000 Section 18.2: PREFERRED_ADDRESS transport parameter
			 * is only sent by servers. Format (41+ bytes):
			 *   - IPv4 Address (4 bytes)
			 *   - IPv4 Port (2 bytes, network byte order)
			 *   - IPv6 Address (16 bytes)
			 *   - IPv6 Port (2 bytes, network byte order)
			 *   - Connection ID Length (1 byte varint)
			 *   - Connection ID (0-20 bytes)
			 *   - Stateless Reset Token (16 bytes)
			 */
			if (conn->is_server)
				return -EPROTO;
			if (param_len < 41)
				return -EINVAL;

			/* Parse preferred address data */
			{
				struct quic_preferred_address *pa = &params->preferred_address;
				const u8 *p = param_data;
				u8 cid_len;

				/* IPv4 address and port */
				memcpy(pa->ipv4_addr, p, 4);
				p += 4;
				memcpy(&pa->ipv4_port, p, 2);
				p += 2;

				/* IPv6 address and port */
				memcpy(pa->ipv6_addr, p, 16);
				p += 16;
				memcpy(&pa->ipv6_port, p, 2);
				p += 2;

				/* Connection ID length and data */
				cid_len = *p++;
				if (cid_len > 20)
					return -EPROTO;
				if (param_len < 41 + cid_len)
					return -EINVAL;

				pa->connection_id_len = cid_len;
				if (cid_len > 0)
					memcpy(pa->connection_id, p, cid_len);
				p += cid_len;

				/* Stateless reset token */
				memcpy(pa->stateless_reset_token, p, 16);

				params->preferred_address_present = 1;
			}
			break;

		case QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT:
			if (param_len > 8)
				return -EINVAL;
			varint_len = quic_varint_decode(param_data, param_len,
							&value);
			if (varint_len < 0 || (size_t)varint_len != param_len)
				return -EINVAL;
			if (value < QUIC_TP_ACTIVE_CID_LIMIT_MIN)
				return -EPROTO;
			params->active_connection_id_limit = value;
			break;

		case QUIC_TP_INITIAL_SOURCE_CID:
			if (param_len > QUIC_MAX_CONNECTION_ID_LEN)
				return -EPROTO;
			params->initial_source_connection_id_len = param_len;
			break;

		case QUIC_TP_RETRY_SOURCE_CID:
			if (conn->is_server)
				return -EPROTO;
			if (param_len > QUIC_MAX_CONNECTION_ID_LEN)
				return -EPROTO;
			params->retry_source_connection_id_len = param_len;
			break;

		case QUIC_TP_MAX_DATAGRAM_FRAME_SIZE:
			if (param_len > 8)
				return -EINVAL;
			varint_len = quic_varint_decode(param_data, param_len,
							&value);
			if (varint_len < 0 || (size_t)varint_len != param_len)
				return -EINVAL;
			params->max_datagram_frame_size = value;
			break;

		case QUIC_TP_GREASE_QUIC_BIT:
			if (param_len != 0)
				return -EPROTO;
			params->grease_quic_bit = 1;
			break;

		default:
			/* RFC 9000: ignore unknown parameters */
			break;
		}

		offset += param_len;
	}

	return 0;
}
EXPORT_SYMBOL(quic_transport_param_parse);

/**
 * quic_transport_param_apply - Apply parsed transport params to connection
 * @conn: QUIC connection with populated remote_params
 *
 * Returns 0 on success, negative error code on failure.
 */
int quic_transport_param_apply(struct quic_connection *conn)
{
	struct quic_transport_params *params = &conn->remote_params;

	/* Apply remote flow control limits */
	conn->remote_fc.max_data = params->initial_max_data;
	conn->remote_fc.max_streams_bidi = params->initial_max_streams_bidi;
	conn->remote_fc.max_streams_uni = params->initial_max_streams_uni;

	/* Update stream limits */
	if (conn->is_server) {
		conn->max_stream_id_bidi =
			params->initial_max_streams_bidi * 4 + 1;
		conn->max_stream_id_uni =
			params->initial_max_streams_uni * 4 + 3;
	} else {
		conn->max_stream_id_bidi =
			params->initial_max_streams_bidi * 4;
		conn->max_stream_id_uni =
			params->initial_max_streams_uni * 4 + 2;
	}

	/* Apply idle timeout (minimum of both endpoints) */
	if (params->max_idle_timeout > 0) {
		u64 local_timeout = conn->local_params.max_idle_timeout;
		u64 effective_timeout;

		if (local_timeout == 0)
			effective_timeout = params->max_idle_timeout;
		else if (params->max_idle_timeout < local_timeout)
			effective_timeout = params->max_idle_timeout;
		else
			effective_timeout = local_timeout;

		quic_timer_set(conn, QUIC_TIMER_IDLE,
			       ktime_add_ms(ktime_get(), effective_timeout));
	}

	/* Apply path MTU limit */
	if (conn->active_path) {
		u32 max_payload = params->max_udp_payload_size;

		if (max_payload < conn->active_path->mtu)
			conn->active_path->mtu = max_payload;
	}

	conn->migration_disabled = params->disable_active_migration;

	/*
	 * RFC 9000 Section 9.6: Use of Preferred Address
	 *
	 * If the server has sent a preferred_address transport parameter, a
	 * client that chooses to use the preferred address initiates path
	 * validation (Section 8.2) of the preferred address.
	 *
	 * Only clients process preferred addresses; servers MUST NOT send
	 * a preferred_address to other servers.
	 */
	if (!conn->is_server && params->preferred_address_present) {
		int ret = quic_conn_migrate_to_preferred_address(conn);
		if (ret < 0) {
			pr_debug("QUIC: Failed to initiate preferred address migration: %d\n",
				 ret);
			/* Per RFC 9000: Failure to validate does not cause
			 * connection failure; just continue on current path.
			 */
		}
	}

	return 0;
}
EXPORT_SYMBOL(quic_transport_param_apply);

/**
 * quic_transport_param_encode - Encode local transport parameters
 * @conn: QUIC connection
 * @buf: Output buffer for encoded parameters
 * @buf_len: Size of output buffer
 * @out_len: Returns actual encoded length
 *
 * Returns 0 on success, -ENOBUFS if buffer too small.
 */
int quic_transport_param_encode(struct quic_connection *conn,
				u8 *buf, size_t buf_len, size_t *out_len)
{
	struct quic_transport_params *params = &conn->local_params;
	size_t offset = 0;
	int id_len, val_len, len_len;

#define ENCODE_VARINT_PARAM(id, val) do {				\
	u64 _val = (val);						\
	id_len = quic_varint_len(id);					\
	val_len = quic_varint_len(_val);				\
	len_len = quic_varint_len(val_len);				\
	if (offset + id_len + len_len + val_len > buf_len)		\
		return -ENOBUFS;					\
	offset += quic_varint_encode(id, buf + offset);			\
	offset += quic_varint_encode(val_len, buf + offset);		\
	offset += quic_varint_encode(_val, buf + offset);		\
} while (0)

#define ENCODE_EMPTY_PARAM(id) do {					\
	id_len = quic_varint_len(id);					\
	if (offset + id_len + 1 > buf_len)				\
		return -ENOBUFS;					\
	offset += quic_varint_encode(id, buf + offset);			\
	buf[offset++] = 0;						\
} while (0)

	/* original_destination_connection_id - server only */
	if (conn->is_server && conn->original_dcid.len > 0) {
		id_len = quic_varint_len(QUIC_TP_ORIGINAL_DESTINATION_CID);
		len_len = quic_varint_len(conn->original_dcid.len);
		if (offset + id_len + len_len + conn->original_dcid.len >
		    buf_len)
			return -ENOBUFS;
		offset += quic_varint_encode(QUIC_TP_ORIGINAL_DESTINATION_CID,
					     buf + offset);
		offset += quic_varint_encode(conn->original_dcid.len,
					     buf + offset);
		memcpy(buf + offset, conn->original_dcid.data,
		       conn->original_dcid.len);
		offset += conn->original_dcid.len;
	}

	if (params->max_idle_timeout > 0)
		ENCODE_VARINT_PARAM(QUIC_TP_MAX_IDLE_TIMEOUT,
				    params->max_idle_timeout);

	if (params->max_udp_payload_size != 65527)
		ENCODE_VARINT_PARAM(QUIC_TP_MAX_UDP_PAYLOAD_SIZE,
				    params->max_udp_payload_size);

	if (params->initial_max_data > 0)
		ENCODE_VARINT_PARAM(QUIC_TP_INITIAL_MAX_DATA,
				    params->initial_max_data);

	if (params->initial_max_stream_data_bidi_local > 0)
		ENCODE_VARINT_PARAM(QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
				    params->initial_max_stream_data_bidi_local);

	if (params->initial_max_stream_data_bidi_remote > 0)
		ENCODE_VARINT_PARAM(QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
				    params->initial_max_stream_data_bidi_remote);

	if (params->initial_max_stream_data_uni > 0)
		ENCODE_VARINT_PARAM(QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI,
				    params->initial_max_stream_data_uni);

	if (params->initial_max_streams_bidi > 0)
		ENCODE_VARINT_PARAM(QUIC_TP_INITIAL_MAX_STREAMS_BIDI,
				    params->initial_max_streams_bidi);

	if (params->initial_max_streams_uni > 0)
		ENCODE_VARINT_PARAM(QUIC_TP_INITIAL_MAX_STREAMS_UNI,
				    params->initial_max_streams_uni);

	if (params->ack_delay_exponent != 3)
		ENCODE_VARINT_PARAM(QUIC_TP_ACK_DELAY_EXPONENT,
				    params->ack_delay_exponent);

	if (params->max_ack_delay != 25)
		ENCODE_VARINT_PARAM(QUIC_TP_MAX_ACK_DELAY,
				    params->max_ack_delay);

	if (params->disable_active_migration)
		ENCODE_EMPTY_PARAM(QUIC_TP_DISABLE_ACTIVE_MIGRATION);

	if (params->active_connection_id_limit > 2)
		ENCODE_VARINT_PARAM(QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT,
				    params->active_connection_id_limit);

	/* initial_source_connection_id */
	id_len = quic_varint_len(QUIC_TP_INITIAL_SOURCE_CID);
	len_len = quic_varint_len(conn->scid.len);
	if (offset + id_len + len_len + conn->scid.len > buf_len)
		return -ENOBUFS;
	offset += quic_varint_encode(QUIC_TP_INITIAL_SOURCE_CID, buf + offset);
	offset += quic_varint_encode(conn->scid.len, buf + offset);
	memcpy(buf + offset, conn->scid.data, conn->scid.len);
	offset += conn->scid.len;

	if (params->max_datagram_frame_size > 0)
		ENCODE_VARINT_PARAM(QUIC_TP_MAX_DATAGRAM_FRAME_SIZE,
				    params->max_datagram_frame_size);

#undef ENCODE_VARINT_PARAM
#undef ENCODE_EMPTY_PARAM

	*out_len = offset;
	return 0;
}
EXPORT_SYMBOL(quic_transport_param_encode);

/**
 * quic_transport_param_validate - Validate transport parameters
 * @conn: QUIC connection with populated remote_params
 *
 * Returns 0 on success, -EPROTO on protocol violation.
 */
int quic_transport_param_validate(struct quic_connection *conn)
{
	struct quic_transport_params *params = &conn->remote_params;

	/* Validate original_destination_connection_id matches */
	if (!conn->is_server &&
	    params->original_destination_connection_id_len > 0) {
		if (params->original_destination_connection_id_len !=
		    conn->original_dcid.len)
			return -EPROTO;
	}

	return 0;
}
EXPORT_SYMBOL(quic_transport_param_validate);
