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

	if (conn->state != QUIC_STATE_CLOSED) {
		conn->state = QUIC_STATE_CLOSED;
		if (conn->qsk)
			wake_up(&conn->qsk->event_wait);
	}
}

static void quic_timer_handshake_cb(struct timer_list *t)
{
	struct quic_connection *conn = from_timer(conn, t, timers[QUIC_TIMER_HANDSHAKE]);

	if (!conn->handshake_complete && conn->state == QUIC_STATE_CONNECTING) {
		conn->error_code = QUIC_ERROR_INTERNAL_ERROR;
		conn->state = QUIC_STATE_CLOSED;
		if (conn->qsk)
			wake_up(&conn->qsk->event_wait);
	}
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

	if (conn->state == QUIC_STATE_DRAINING) {
		conn->state = QUIC_STATE_CLOSED;
		if (conn->qsk)
			wake_up(&conn->qsk->event_wait);
	}
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

	/* Initialize statistics */
	memset(&conn->stats, 0, sizeof(conn->stats));

	refcount_set(&conn->refcnt, 1);

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

	/* Free pending frames */
	skb_queue_purge(&conn->pending_frames);
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

	if (conn->state != QUIC_STATE_IDLE)
		return -EINVAL;

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

	conn->pn_spaces[QUIC_PN_SPACE_INITIAL].keys_available = 1;
	conn->state = QUIC_STATE_CONNECTING;

	/* Start handshake timer */
	quic_timer_set(conn, QUIC_TIMER_HANDSHAKE,
		       ktime_add_ms(ktime_get(), qsk->config.handshake_timeout_ms));

	/* Queue TX work to send Initial packet */
	schedule_work(&conn->tx_work);

	return 0;
}

int quic_conn_accept(struct quic_connection *conn)
{
	if (conn->state != QUIC_STATE_IDLE)
		return -EINVAL;

	conn->state = QUIC_STATE_HANDSHAKE;
	return 0;
}

int quic_conn_close(struct quic_connection *conn, u64 error_code,
		    const char *reason, u32 reason_len, bool app_error)
{
	if (conn->state == QUIC_STATE_CLOSED ||
	    conn->state == QUIC_STATE_DRAINING)
		return -EINVAL;

	conn->error_code = error_code;
	conn->app_error = app_error ? 1 : 0;

	if (reason && reason_len > 0) {
		char *phrase = kmemdup(reason, reason_len, GFP_KERNEL);

		if (phrase) {
			kfree(conn->reason_phrase);
			conn->reason_phrase = phrase;
			conn->reason_len = reason_len;
		}
		/* On allocation failure, proceed without reason phrase */
	}

	conn->state = QUIC_STATE_CLOSING;

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
	enum quic_state old_state = conn->state;

	conn->state = state;

	switch (state) {
	case QUIC_STATE_CONNECTED:
		conn->handshake_complete = 1;
		quic_timer_cancel(conn, QUIC_TIMER_HANDSHAKE);

		/* Discard handshake keys */
		conn->pn_spaces[QUIC_PN_SPACE_INITIAL].keys_discarded = 1;
		conn->pn_spaces[QUIC_PN_SPACE_HANDSHAKE].keys_discarded = 1;
		quic_crypto_destroy(&conn->crypto[QUIC_CRYPTO_INITIAL]);
		quic_crypto_destroy(&conn->crypto[QUIC_CRYPTO_HANDSHAKE]);

		/* Record handshake time */
		conn->stats.handshake_time_us = ktime_to_us(ktime_get());

		if (conn->qsk)
			wake_up(&conn->qsk->event_wait);
		break;

	case QUIC_STATE_DRAINING:
		conn->draining = 1;
		/* Schedule close after draining period */
		quic_timer_set(conn, QUIC_TIMER_IDLE,
			       ktime_add_ms(ktime_get(),
					    3 * quic_rtt_pto(&conn->active_path->rtt)));
		break;

	case QUIC_STATE_CLOSED:
		/* Cancel all timers except idle */
		quic_timer_cancel(conn, QUIC_TIMER_LOSS);
		quic_timer_cancel(conn, QUIC_TIMER_ACK);
		quic_timer_cancel(conn, QUIC_TIMER_HANDSHAKE);
		quic_timer_cancel(conn, QUIC_TIMER_PATH_PROBE);

		if (conn->qsk)
			wake_up(&conn->qsk->event_wait);
		break;

	default:
		break;
	}

	(void)old_state;
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
