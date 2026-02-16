// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * TQUIC - True QUIC with WAN Bonding
 *
 * Connection management implementation
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 */

#include <linux/slab.h>
#include <linux/jhash.h>
#include <linux/random.h>
#include <linux/rcupdate.h>
#include <net/tquic.h>

/* QUIC constants (originally from uapi/linux/quic.h, now defined locally) */
#define QUIC_MAX_PACKET_SIZE 1500
#define QUIC_ERROR_INTERNAL_ERROR 0x01
#include "transport_params.h"
#include "../tquic_cid.h"
#include "../tquic_debug.h"
#include "../diag/trace.h"
#include "../tquic_compat.h"
#include "../protocol.h"
#include "../tquic_init.h"
static const struct rhashtable_params tquic_conn_table_params = {
	.key_len = sizeof(struct tquic_cid),
	.key_offset = offsetof(struct tquic_connection, scid),
	.head_offset = offsetof(struct tquic_connection, node),
	.automatic_shrinking = true,
};

static struct tquic_path *
tquic_conn_active_path_get(struct tquic_connection *conn)
{
	struct tquic_path *path;

	rcu_read_lock();
	path = rcu_dereference(conn->active_path);
	if (path && !tquic_path_get(path))
		path = NULL;
	rcu_read_unlock();

	return path;
}

static u32 tquic_conn_draining_timeout_ms(struct tquic_connection *conn)
{
	struct tquic_path *path;
	u32 timeout_ms;

	tquic_dbg("tquic_conn_draining_timeout_ms: computing drain timeout\n");
	path = tquic_conn_active_path_get(conn);
	if (!path)
		return 3000;

	timeout_ms = 3 * tquic_rtt_pto(&path->rtt);
	tquic_path_put(path);

	return timeout_ms;
}

/* Forward declarations for functions defined in other compilation units */
void tquic_loss_detection_on_timeout(struct tquic_connection *conn);
bool tquic_ack_should_send(struct tquic_connection *conn, u8 pn_space);
int tquic_ack_create(struct tquic_connection *conn, u8 pn_space,
		     struct sk_buff *skb);
void tquic_crypto_discard_old_keys(struct tquic_connection *conn);
void tquic_crypto_revert_key_update(struct tquic_connection *conn);
void tquic_key_update_timeout(struct tquic_connection *conn);

/*
 * struct tquic_sent_packet - Tracks a sent packet for loss detection
 *
 * This structure is used internally for tracking packets in the
 * loss detection and ACK processing code. Must match definition in quic_loss.c.
 */
struct tquic_sent_packet {
	struct list_head list;
	struct rb_node node;
	u64 pn;
	ktime_t sent_time;
	u32 sent_bytes;
	u32 size; /* Alias for sent_bytes for API compatibility */
	u8 pn_space;
	u32 path_id;
	bool ack_eliciting;
	bool in_flight;
	bool retransmitted; /* Packet has been retransmitted */
	u32 frames;
	struct sk_buff *skb;
};

/*
 * tquic_trace_conn_id - Extract connection ID as u64 for tracing
 * @cid: Connection ID (tquic_cid structure)
 *
 * Returns: First 8 bytes of CID as u64 for trace events.
 *
 * This is the tquic version of tquic_trace_conn_id() for use with
 * struct tquic_cid which has id[] instead of data[].
 */
static inline u64 tquic_trace_conn_id(const struct tquic_cid *cid)
{
	u64 id = 0;
	int i;
	int len = cid->len > 8 ? 8 : cid->len;

	for (i = 0; i < len; i++)
		id = (id << 8) | cid->id[i];

	return id;
}

static struct kmem_cache *tquic_cid_cache __read_mostly;

static u32 tquic_cid_rht_hashfn(const void *data, u32 len, u32 seed)
{
	const struct tquic_cid *cid = data;
	u8 key_len = min_t(u8, cid->len, TQUIC_MAX_CID_LEN);

	return jhash(cid->id, key_len, seed);
}

static u32 tquic_cid_rht_obj_hashfn(const void *data, u32 len, u32 seed)
{
	const struct tquic_cid_entry *entry = data;
	u8 key_len = min_t(u8, entry->cid.len, TQUIC_MAX_CID_LEN);

	return jhash(entry->cid.id, key_len, seed);
}

static int tquic_cid_rht_obj_cmpfn(struct rhashtable_compare_arg *arg,
				   const void *obj)
{
	const struct tquic_cid *cid = arg->key;
	const struct tquic_cid_entry *entry = obj;

	if (cid->len > TQUIC_MAX_CID_LEN || entry->cid.len > TQUIC_MAX_CID_LEN)
		return 1;

	if (cid->len != entry->cid.len)
		return 1;

	return memcmp(cid->id, entry->cid.id, cid->len);
}

/* rhashtable parameters for connection ID lookup */
static const struct rhashtable_params tquic_cid_rht_params = {
	.key_len = sizeof(struct tquic_cid),
	.key_offset = offsetof(struct tquic_cid_entry, cid),
	.head_offset = offsetof(struct tquic_cid_entry, node),
	.hashfn = tquic_cid_rht_hashfn,
	.obj_hashfn = tquic_cid_rht_obj_hashfn,
	.obj_cmpfn = tquic_cid_rht_obj_cmpfn,
};

static struct rhashtable tquic_cid_rht;
static spinlock_t __maybe_unused tquic_cid_rht_lock =
	__SPIN_LOCK_UNLOCKED(tquic_cid_rht_lock);

int tquic_cid_hash_init(void)
{
	int err;

	tquic_dbg("tquic_cid_hash_init: initializing CID hash table\n");
	err = rhashtable_init(&tquic_cid_rht, &tquic_cid_rht_params);
	if (err)
		return err;

	tquic_cid_cache = kmem_cache_create("tquic_cid",
					    sizeof(struct tquic_cid_entry), 0,
					    SLAB_HWCACHE_ALIGN, NULL);
	if (!tquic_cid_cache) {
		rhashtable_destroy(&tquic_cid_rht);
		return -ENOMEM;
	}

	return 0;
}

void tquic_cid_hash_cleanup(void)
{
	rhashtable_destroy(&tquic_cid_rht);
	kmem_cache_destroy(tquic_cid_cache);
}

static int tquic_cid_hash_add(struct tquic_cid_entry *entry)
{
	return rhashtable_insert_fast(&tquic_cid_rht, &entry->node,
				      tquic_cid_rht_params);
}

static void tquic_cid_hash_del(struct tquic_cid_entry *entry)
{
	rhashtable_remove_fast(&tquic_cid_rht, &entry->node,
			       tquic_cid_rht_params);
}

static struct tquic_cid_entry *tquic_cid_hash_lookup(struct tquic_cid *cid)
{
	/*
	 * SECURITY FIX (CF-120): rhashtable_lookup_fast() requires
	 * the caller to hold rcu_read_lock(). The RCU read-side lock
	 * ensures the hash bucket chain is not freed mid-traversal.
	 */
	return rhashtable_lookup_fast(&tquic_cid_rht, cid,
				      tquic_cid_rht_params);
}

static struct tquic_connection *tquic_conn_lookup(struct tquic_cid *cid)
{
	struct tquic_cid_entry *entry;
	struct tquic_connection *conn = NULL;

	/*
	 * SECURITY FIX (CF-120): Hold rcu_read_lock() across the
	 * lookup and take a reference on the connection before
	 * returning, preventing use-after-free if the connection
	 * is destroyed concurrently.
	 */
	rcu_read_lock();
	entry = tquic_cid_hash_lookup(cid);
	if (entry) {
		conn = entry->conn;
		if (conn && !refcount_inc_not_zero(&conn->refcnt))
			conn = NULL;
	}
	rcu_read_unlock();

	return conn;
}

/**
 * tquic_cid_rht_lookup - Look up connection by CID in the rhashtable
 *
 * Searches the CID rhashtable (populated by tquic_conn_create).
 * Exported for use as a fallback in the global lookup chain.
 */
struct tquic_connection *tquic_cid_rht_lookup(const struct tquic_cid *cid)
{
	struct tquic_cid lookup_cid;
	struct tquic_connection *conn;

	if (!cid || cid->len == 0)
		return NULL;

	/* Copy to mutable struct for rhashtable API */
	memcpy(&lookup_cid, cid, sizeof(lookup_cid));
	conn = tquic_conn_lookup(&lookup_cid);
	pr_warn("tquic_cid_rht_lookup: len=%u id=%*phN result=%p\n",
		cid->len, min_t(int, cid->len, 8), cid->id, conn);
	return conn;
}
EXPORT_SYMBOL_GPL(tquic_cid_rht_lookup);

static void tquic_conn_generate_cid(struct tquic_cid *cid, u8 len)
{
	cid->len = len;
	get_random_bytes(cid->id, len);
}

static struct tquic_cid_entry *tquic_cid_entry_create(struct tquic_cid *cid,
						      u64 seq)
{
	struct tquic_cid_entry *entry;

	entry = kmem_cache_alloc(tquic_cid_cache, GFP_KERNEL);
	if (!entry)
		return NULL;

	memcpy(&entry->cid, cid, sizeof(*cid));
	entry->seq_num = seq;
	entry->retire_prior_to = 0;
	entry->state = CID_STATE_ACTIVE;
	entry->conn = NULL;
	entry->path = NULL;
	INIT_LIST_HEAD(&entry->list);
	get_random_bytes(entry->reset_token, TQUIC_STATELESS_RESET_TOKEN_LEN);

	return entry;
}

static void tquic_cid_entry_rcu_free(struct rcu_head *head)
{
	struct tquic_cid_entry *entry =
		container_of(head, struct tquic_cid_entry, rcu);

	kmem_cache_free(tquic_cid_cache, entry);
}

static void tquic_cid_entry_destroy(struct tquic_cid_entry *entry)
{
	tquic_dbg("tquic_cid_entry_destroy: seq=%llu\n", entry->seq_num);
	list_del_init(&entry->list);
	tquic_cid_hash_del(entry);
	/*
	 * Defer freeing until an RCU grace period has elapsed so that
	 * concurrent rcu_read_lock() holders in tquic_conn_lookup()
	 * do not access freed memory.
	 */
	call_rcu(&entry->rcu, tquic_cid_entry_rcu_free);
}

static void tquic_pn_space_init(struct tquic_pn_space *pn_space)
{
	tquic_dbg("tquic_pn_space_init: initializing packet number space\n");
	spin_lock_init(&pn_space->lock);
	pn_space->next_pn = 0;
	pn_space->largest_acked = 0;
	pn_space->largest_sent = 0;
	pn_space->largest_recv_pn = 0;
	pn_space->loss_time = 0;
	pn_space->last_ack_time = 0;
	pn_space->ack_eliciting_in_flight = 0;
	pn_space->sent_packets = RB_ROOT;
	INIT_LIST_HEAD(&pn_space->sent_list);
	INIT_LIST_HEAD(&pn_space->lost_packets);
	pn_space->pending_acks = NULL;
	pn_space->pending_ack_count = 0;
	pn_space->pending_ack_capacity = 0;
	memset(&pn_space->recv_ack_info, 0, sizeof(pn_space->recv_ack_info));
	pn_space->keys_available = 0;
	pn_space->keys_discarded = 0;
}

static void __maybe_unused
tquic_pn_space_destroy(struct tquic_pn_space *pn_space)
{
	struct tquic_sent_packet *pkt, *tmp;

	list_for_each_entry_safe(pkt, tmp, &pn_space->sent_list, list) {
		list_del_init(&pkt->list);
		if (pkt->skb)
			kfree_skb(pkt->skb);
		kfree(pkt);
	}

	list_for_each_entry_safe(pkt, tmp, &pn_space->lost_packets, list) {
		list_del_init(&pkt->list);
		if (pkt->skb)
			kfree_skb(pkt->skb);
		kfree(pkt);
	}

	kfree(pn_space->pending_acks);
	pn_space->pending_acks = NULL;
}

static void tquic_conn_init_local_params(struct tquic_connection *conn,
					 struct tquic_config *config)
{
	struct tquic_transport_params *params = &conn->local_params;

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

static void tquic_conn_init_flow_control(struct tquic_connection *conn)
{
	struct tquic_flow_control *local = &conn->local_fc;
	struct tquic_flow_control *remote = &conn->remote_fc;
	tquic_dbg("tquic_conn_init_flow_control: max_data=%llu\n",
		  conn->local_params.initial_max_data);

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
	remote->max_data = 0; /* Updated when we receive transport params */
	remote->data_sent = 0;
	remote->data_received = 0;
	remote->max_streams_bidi = 0;
	remote->max_streams_uni = 0;
	remote->streams_opened_bidi = 0;
	remote->streams_opened_uni = 0;
	remote->blocked = 0;

	/*
	 * Initialize legacy flow control fields still used by
	 * tquic_flow_control_check_recv_limit_internal() and
	 * tquic_process_stream_frame().
	 */
	conn->max_data_local = conn->local_params.initial_max_data;
	conn->max_data_remote = 0;
	conn->data_sent = 0;
	conn->data_received = 0;
}

static void tquic_timer_loss_cb(struct timer_list *t)
{
	struct tquic_connection *conn =
		from_timer(conn, t, timers[TQUIC_TIMER_LOSS]);

	if (READ_ONCE(conn->state) == TQUIC_CONN_CLOSED)
		return;

	tquic_loss_detection_on_timeout(conn);
	tquic_timer_update(conn);
}

static void tquic_timer_ack_cb(struct timer_list *t)
{
	struct tquic_connection *conn =
		from_timer(conn, t, timers[TQUIC_TIMER_ACK]);
	int i;

	if (READ_ONCE(conn->state) == TQUIC_CONN_CLOSED)
		return;

	for (i = 0; i < TQUIC_PN_SPACE_COUNT; i++) {
		if (tquic_ack_should_send(conn, i)) {
			struct sk_buff *skb = alloc_skb(256, GFP_ATOMIC);
			if (skb)
				tquic_ack_create(conn, i, skb);
		}
	}
}

static void tquic_timer_idle_cb(struct timer_list *t)
{
	struct tquic_connection *conn =
		from_timer(conn, t, timers[TQUIC_TIMER_IDLE]);
	unsigned long flags;

	spin_lock_irqsave(&conn->lock, flags);
	if (conn->state != TQUIC_CONN_CLOSED) {
		conn->state = TQUIC_CONN_CLOSED;
		spin_unlock_irqrestore(&conn->lock, flags);
		if (conn->tsk)
			wake_up(&conn->tsk->event_wait);
		return;
	}
	spin_unlock_irqrestore(&conn->lock, flags);
}

static void tquic_timer_handshake_cb(struct timer_list *t)
{
	struct tquic_connection *conn =
		from_timer(conn, t, timers[TQUIC_TIMER_HANDSHAKE]);
	unsigned long flags;

	spin_lock_irqsave(&conn->lock, flags);
	if (!conn->handshake_complete && conn->state == TQUIC_CONN_CONNECTING) {
		conn->error_code = QUIC_ERROR_INTERNAL_ERROR;
		conn->state = TQUIC_CONN_CLOSED;
		spin_unlock_irqrestore(&conn->lock, flags);
		if (conn->tsk)
			wake_up(&conn->tsk->event_wait);
		return;
	}
	spin_unlock_irqrestore(&conn->lock, flags);
}

static void tquic_timer_path_probe_cb(struct timer_list *t)
{
	struct tquic_connection *conn =
		from_timer(conn, t, timers[TQUIC_TIMER_PATH_PROBE]);
	struct tquic_path *path;

	spin_lock_bh(&conn->paths_lock);
	list_for_each_entry(path, &conn->paths, list) {
		if (path->validation.challenge_pending &&
		    path->state != TQUIC_PATH_VALIDATED) {
			tquic_path_challenge(path);
		}
	}
	spin_unlock_bh(&conn->paths_lock);
}

static void tquic_timer_key_discard_cb(struct timer_list *t)
{
	struct tquic_connection *conn =
		from_timer(conn, t, timers[TQUIC_TIMER_KEY_DISCARD]);

	if (!conn)
		return;

	tquic_crypto_discard_old_keys(conn);
}

/*
 * tquic_timer_key_update_cb - Key update timeout callback
 *
 * If we initiated a key update and the peer has not responded with
 * a packet bearing the new key phase within 3 * PTO, revert the
 * key update to prevent the connection from being permanently stuck
 * in the update_pending state.
 *
 * Per RFC 9001 Section 6.5, an endpoint SHOULD retain old keys for
 * some time after a key update to allow for packet reordering.
 * If the peer never responds, the connection is likely dead, but
 * reverting the key state at least allows the local side to attempt
 * continued communication or clean up gracefully.
 */
static void tquic_timer_key_update_cb(struct timer_list *t)
{
	struct tquic_connection *conn =
		from_timer(conn, t, timers[TQUIC_TIMER_KEY_UPDATE]);

	if (!conn)
		return;

	/*
	 * Revert key update via both crypto layers.
	 * The core layer (quic_key_update.c) uses crypto[APPLICATION],
	 * while the crypto layer (crypto/key_update.c) uses crypto_state.
	 * Call both; each is a no-op if that layer has no pending update.
	 */
	tquic_crypto_revert_key_update(conn);
	tquic_key_update_timeout(conn);
}

static void tquic_conn_tx_work(struct work_struct *work)
{
	struct tquic_connection *conn =
		container_of(work, struct tquic_connection, tx_work);
	struct sk_buff *skb;
	int i;

	for (i = TQUIC_PN_SPACE_APPLICATION; i >= TQUIC_PN_SPACE_INITIAL; i--) {
		struct tquic_pn_space *pn_space = &conn->pn_spaces[i];

		if (!pn_space->keys_available || pn_space->keys_discarded)
			continue;

		skb = tquic_packet_build(conn, i);
		if (skb) {
			struct tquic_path *path =
				tquic_conn_active_path_get(conn);
			int ret = tquic_udp_send(conn->tsk, skb, path);

			if (ret < 0)
				tquic_conn_err(
					conn,
					"tx_work: send failed on path %u: %d\n",
					path ? path->path_id : 0, ret);

			if (path)
				tquic_path_put(path);
		}
	}
}

static void tquic_conn_rx_work(struct work_struct *work)
{
	struct tquic_connection *conn =
		container_of(work, struct tquic_connection, rx_work);
	struct sk_buff *skb;
	tquic_dbg("tquic_conn_rx_work: processing pending frames\n");

	while ((skb = skb_dequeue(&conn->pending_frames)) != NULL) {
		tquic_packet_process(conn, skb);
		kfree_skb(skb);
	}
}

static void tquic_conn_close_work(struct work_struct *work)
{
	struct tquic_connection *conn =
		container_of(work, struct tquic_connection, close_work);
	unsigned long flags;
	tquic_dbg("tquic_conn_close_work: processing connection close\n");

	spin_lock_irqsave(&conn->lock, flags);
	if (conn->state == TQUIC_CONN_DRAINING) {
		conn->state = TQUIC_CONN_CLOSED;
		spin_unlock_irqrestore(&conn->lock, flags);
		if (conn->tsk)
			wake_up(&conn->tsk->event_wait);
		return;
	}
	spin_unlock_irqrestore(&conn->lock, flags);
}

struct tquic_connection *tquic_conn_create(struct tquic_sock *tsk,
					   bool is_server)
{
	struct tquic_connection *conn;
	struct tquic_cid_entry *scid_entry;
	int i;

	conn = kmem_cache_zalloc(tquic_conn_cache, GFP_KERNEL);
	if (!conn)
		return NULL;

	conn->tsk = tsk;
	spin_lock_init(&conn->lock);
	conn->state = TQUIC_CONN_IDLE;
	conn->version = tsk->config.version ? tsk->config.version
					     : TQUIC_VERSION_1;
	conn->is_server = is_server;

	/* Generate source connection ID */
	tquic_conn_generate_cid(&conn->scid, 8);
	INIT_LIST_HEAD(&conn->scid_list);
	INIT_LIST_HEAD(&conn->dcid_list);

	/* Initialize path list/limits; actual path(s) are created on connect/accept. */
	INIT_LIST_HEAD(&conn->paths);
	spin_lock_init(&conn->paths_lock);
	RCU_INIT_POINTER(conn->active_path, NULL);
	conn->num_paths = 0;
	conn->max_paths = TQUIC_MAX_PATHS;

	/* Create initial source CID entry */
	scid_entry = tquic_cid_entry_create(&conn->scid, 0);
	if (!scid_entry)
		goto err_free_conn;

	scid_entry->conn = conn; /* Associate CID with connection for lookup */
	list_add(&scid_entry->list, &conn->scid_list);
	tquic_cid_hash_add(scid_entry);
	conn->next_scid_seq = 1;
	pr_warn("tquic_conn_create: SCID#1 (cid_table) len=%u id=%*phN is_server=%d\n",
		conn->scid.len, min_t(int, conn->scid.len, 8),
		conn->scid.id, is_server);

	/* Allocate and initialize packet number spaces */
	conn->pn_spaces = kcalloc(TQUIC_PN_SPACE_COUNT,
				  sizeof(*conn->pn_spaces), GFP_KERNEL);
	if (!conn->pn_spaces)
		goto err_free_scid; /* scid was just added, need to remove it */

	for (i = 0; i < TQUIC_PN_SPACE_COUNT; i++)
		tquic_pn_space_init(&conn->pn_spaces[i]);

	/* Initialize crypto level (crypto[] pointers already zeroed by kzalloc) */
	conn->crypto_level = TQUIC_CRYPTO_INITIAL;

	/* Initialize streams */
	conn->streams = RB_ROOT;
	spin_lock_init(&conn->streams_lock);

	if (is_server) {
		conn->next_stream_id_bidi =
			1; /* Server-initiated bidi starts at 1 */
		conn->next_stream_id_uni =
			3; /* Server-initiated uni starts at 3 */
	} else {
		conn->next_stream_id_bidi =
			0; /* Client-initiated bidi starts at 0 */
		conn->next_stream_id_uni =
			2; /* Client-initiated uni starts at 2 */
	}

	/* Initialize flow control */
	tquic_conn_init_local_params(conn, &tsk->config);
	tquic_conn_init_flow_control(conn);

	/* Initialize timers */
	timer_setup(&conn->timers[TQUIC_TIMER_LOSS], tquic_timer_loss_cb, 0);
	timer_setup(&conn->timers[TQUIC_TIMER_ACK], tquic_timer_ack_cb, 0);
	timer_setup(&conn->timers[TQUIC_TIMER_IDLE], tquic_timer_idle_cb, 0);
	timer_setup(&conn->timers[TQUIC_TIMER_HANDSHAKE],
		    tquic_timer_handshake_cb, 0);
	timer_setup(&conn->timers[TQUIC_TIMER_PATH_PROBE],
		    tquic_timer_path_probe_cb, 0);
	timer_setup(&conn->timers[TQUIC_TIMER_KEY_DISCARD],
		    tquic_timer_key_discard_cb, 0);
	timer_setup(&conn->timers[TQUIC_TIMER_KEY_UPDATE],
		    tquic_timer_key_update_cb, 0);

	/* Initialize work queues */
	INIT_WORK(&conn->tx_work, tquic_conn_tx_work);
	INIT_WORK(&conn->rx_work, tquic_conn_rx_work);
	INIT_WORK(&conn->close_work, tquic_conn_close_work);

	/* Initialize loss detection */
	if (tquic_loss_detection_init(conn) < 0)
		goto err_free_pn_spaces;

	/* Initialize pending frame queues */
	skb_queue_head_init(&conn->pending_frames);
	for (i = 0; i < TQUIC_PN_SPACE_COUNT; i++)
		skb_queue_head_init(&conn->crypto_buffer[i]);

	/* Initialize stream priority scheduler (RFC 9218) */
	tquic_sched_init(conn);

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

	/* Initialize datagram state (wait queue, recv queue, etc.) */
	tquic_datagram_init(conn);

	/* Initialize statistics */
	memset(&conn->stats, 0, sizeof(conn->stats));

	refcount_set(&conn->refcnt, 1);

	/*
	 * SECURITY FIX (CF-098): Insert into the global connection
	 * hash table so that diagnostics, proc, and debug interfaces
	 * can find the connection. Without this, rhashtable_remove_fast()
	 * in tquic_conn_destroy() operates on an un-inserted element.
	 */
	if (rhashtable_insert_fast(&tquic_conn_table, &conn->node,
				   tquic_conn_table_params)) {
		pr_warn("tquic: failed to insert conn into global table\n");
		/* Non-fatal: diagnostics will miss this connection */
	}

	trace_quic_conn_create(tquic_trace_conn_id(&conn->scid), is_server);

	return conn;

err_free_pn_spaces:
	/* Clean up timers initialized above */
	for (i = 0; i < TQUIC_TIMER_MAX; i++)
		del_timer_sync(&conn->timers[i]);
	kfree(conn->pn_spaces);
err_free_scid:
	tquic_cid_entry_destroy(scid_entry);
err_free_conn:
	kmem_cache_free(tquic_conn_cache, conn);
	return NULL;
}
EXPORT_SYMBOL_GPL(tquic_conn_create);

#ifndef TQUIC_OUT_OF_TREE
void tquic_conn_destroy(struct tquic_connection *conn)
{
	struct tquic_cid_entry *entry, *tmp_entry;
	struct tquic_path *path, *tmp_path;
	struct tquic_stream *stream;
	struct rb_node *node;
	int i;

	if (!conn)
		return;

	tquic_conn_dbg(conn, "tquic_conn_destroy: tearing down connection\n");

	/*
	 * SECURITY FIX (CF-119): This function must only be called from
	 * tquic_conn_put() when the refcount has already reached zero.
	 * Direct callers must use tquic_conn_put() instead.
	 */
	WARN_ON_ONCE(refcount_read(&conn->refcnt) != 0);

	/* Unbind from server client tracking before teardown */
	tquic_server_unbind_client(conn);

	/* Release path manager state if still attached */
	tquic_pm_conn_release(conn);

	/* Clean up state machine (CIDs, work items, challenges) */
	if (conn->state_machine) {
		u32 magic = *(u32 *)conn->state_machine;

		switch (magic) {
		case TQUIC_SM_MAGIC_CONN_STATE:
			tquic_conn_state_cleanup(conn);
			break;
		case TQUIC_SM_MAGIC_MIGRATION:
			tquic_migration_cleanup(conn);
			break;
		case TQUIC_SM_MAGIC_SESSION:
			tquic_session_cleanup(conn);
			break;
		default:
			WARN_ON_ONCE(1);
			kfree(conn->state_machine);
			conn->state_machine = NULL;
			break;
		}
	}

	/* Remove from global connection hash table */
	rhashtable_remove_fast(&tquic_conn_table, &conn->node,
			       tquic_conn_table_params);

	trace_quic_conn_destroy(tquic_trace_conn_id(&conn->scid),
				conn->error_code);

	/* Cancel all timers */
	for (i = 0; i < TQUIC_TIMER_MAX; i++)
		del_timer_sync(&conn->timers[i]);

	/* Cancel work */
	cancel_work_sync(&conn->tx_work);
	cancel_work_sync(&conn->rx_work);
	cancel_work_sync(&conn->close_work);

	/*
	 * Destroy streams with refcount safety.
	 *
	 * Removing from the rb-tree prevents new lookups. Purge buffers while
	 * conn/sk are still valid, then detach stream->conn so a delayed final
	 * tquic_stream_put() can't touch freed connection memory.
	 */
	spin_lock_bh(&conn->lock);
	while ((node = rb_first(&conn->streams))) {
		struct sk_buff *skb;
		u64 queued = 0;

		stream = rb_entry(node, struct tquic_stream, node);
		rb_erase(node, &conn->streams);
		RB_CLEAR_NODE(&stream->node);
		spin_unlock_bh(&conn->lock);

		while ((skb = skb_dequeue(&stream->send_buf)) != NULL) {
			queued += skb->len;
			if (conn->sk)
				sk_mem_uncharge(conn->sk, skb->truesize);
			kfree_skb(skb);
		}

		if (queued) {
			spin_lock_bh(&conn->lock);
			if (conn->fc_data_reserved >= queued)
				conn->fc_data_reserved -= queued;
			else
				conn->fc_data_reserved = 0;
			spin_unlock_bh(&conn->lock);
		}

		while ((skb = skb_dequeue(&stream->recv_buf)) != NULL) {
			if (conn->sk)
				sk_mem_uncharge(conn->sk, skb->truesize);
			kfree_skb(skb);
		}

		WRITE_ONCE(stream->conn, NULL);
		tquic_stream_put(stream);

		spin_lock_bh(&conn->lock);
	}
	spin_unlock_bh(&conn->lock);

	/* Destroy paths */
	list_for_each_entry_safe(path, tmp_path, &conn->paths, list) {
		tquic_path_destroy(path);
	}

	/* Destroy connection IDs */
	list_for_each_entry_safe(entry, tmp_entry, &conn->scid_list, list) {
		tquic_cid_entry_destroy(entry);
	}
	list_for_each_entry_safe(entry, tmp_entry, &conn->dcid_list, list) {
		tquic_cid_entry_destroy(entry);
	}

	/* Destroy packet number spaces */
	if (conn->pn_spaces) {
		for (i = 0; i < TQUIC_PN_SPACE_COUNT; i++)
			tquic_pn_space_destroy(&conn->pn_spaces[i]);
		kfree(conn->pn_spaces);
	}

	/* Destroy crypto contexts */
	for (i = 0; i < TQUIC_CRYPTO_MAX; i++)
		tquic_crypto_destroy(conn->crypto[i]);

	/* Free zerocopy state if allocated */
	if (conn->zc_state)
		tquic_zc_state_free(conn);

	/* Free pending frames, pacing queue, and early data buffer */
	skb_queue_purge(&conn->pending_frames);
	skb_queue_purge(&conn->pacing_queue);
	skb_queue_purge(&conn->early_data_buffer);
	for (i = 0; i < TQUIC_PN_SPACE_COUNT; i++)
		skb_queue_purge(&conn->crypto_buffer[i]);

	kfree(conn->reason_phrase);
	kmem_cache_free(tquic_conn_cache, conn);
}
#endif /* TQUIC_OUT_OF_TREE */

static int tquic_conn_connect(struct tquic_connection *conn,
			      struct sockaddr *addr, int addr_len)
{
	struct tquic_sock *tsk = conn->tsk;
	struct tquic_path *path;
	int err;

	spin_lock_bh(&conn->lock);
	if (conn->state != TQUIC_CONN_IDLE) {
		spin_unlock_bh(&conn->lock);
		return -EINVAL;
	}
	spin_unlock_bh(&conn->lock);

	path = tquic_conn_active_path_get(conn);
	if (!path)
		return -ENETUNREACH;

	if (addr_len <= 0 || addr_len > sizeof(path->remote_addr)) {
		tquic_path_put(path);
		return -EINVAL;
	}

	/* Set remote address */
	memset(&path->remote_addr, 0, sizeof(path->remote_addr));
	memcpy(&path->remote_addr, addr, addr_len);
	tquic_path_put(path);

	/* Create UDP socket for encapsulation if not exists */
	if (!tsk->udp_sock) {
		err = tquic_udp_encap_init(tsk);
		if (err)
			return err;
	}

	/* Derive initial secrets from destination connection ID */
	err = tquic_crypto_derive_initial_secrets(conn, &conn->dcid);
	if (err)
		return err;

	spin_lock_bh(&conn->lock);
	conn->pn_spaces[TQUIC_PN_SPACE_INITIAL].keys_available = 1;
	spin_unlock_bh(&conn->lock);

	err = tquic_conn_set_state(conn, TQUIC_CONN_CONNECTING,
				   TQUIC_REASON_NORMAL);
	if (err)
		return err;

	/* Start handshake timer */
	tquic_timer_set(conn, TQUIC_TIMER_HANDSHAKE,
			ktime_add_ms(ktime_get(),
				     tsk->config.handshake_timeout_ms));

	/* Queue TX work to send Initial packet */
	schedule_work(&conn->tx_work);

	return 0;
}

static int tquic_conn_accept(struct tquic_connection *conn)
{
	return tquic_conn_set_state(conn, TQUIC_CONN_CONNECTING,
				    TQUIC_REASON_NORMAL);
}

static int tquic_conn_close(struct tquic_connection *conn, u64 error_code,
			    const char *reason, u32 reason_len, bool app_error)
{
	bool already_closing;

	spin_lock_bh(&conn->lock);
	if (conn->state == TQUIC_CONN_CLOSED ||
	    conn->state == TQUIC_CONN_DRAINING) {
		spin_unlock_bh(&conn->lock);
		return -EINVAL;
	}
	already_closing = (conn->state == TQUIC_CONN_CLOSING);

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

	spin_unlock_bh(&conn->lock);

	if (!already_closing)
		tquic_conn_set_state(conn, TQUIC_CONN_CLOSING,
				     app_error ? TQUIC_REASON_APPLICATION :
				     TQUIC_REASON_NORMAL);

	/* Send CONNECTION_CLOSE frame */
	schedule_work(&conn->tx_work);

	/* Start draining timer (3 * PTO) */
	tquic_timer_set(conn, TQUIC_TIMER_IDLE,
			ktime_add_ms(ktime_get(),
				     tquic_conn_draining_timeout_ms(conn)));

	return 0;
}

static void tquic_conn_set_state_local(struct tquic_connection *conn,
			      enum tquic_conn_state state)
{
	tquic_conn_set_state(conn, state, TQUIC_REASON_NORMAL);
}

/* Generate new connection ID */
static int tquic_conn_new_cid(struct tquic_connection *conn,
			      struct tquic_cid *new_cid)
{
	struct tquic_cid_entry *entry;
	u64 seq = conn->next_scid_seq++;

	tquic_conn_generate_cid(new_cid, 8);

	entry = tquic_cid_entry_create(new_cid, seq);
	if (!entry)
		return -ENOMEM;

	entry->conn = conn; /* Associate CID with connection for lookup */
	list_add_tail(&entry->list, &conn->scid_list);
	tquic_cid_hash_add(entry);

	return 0;
}

/* Retire a connection ID */
#ifndef TQUIC_OUT_OF_TREE
int tquic_conn_retire_cid(struct tquic_connection *conn, u64 seq, bool is_local)
{
	struct tquic_cid_entry *entry, *tmp;
	struct list_head *list;

	tquic_conn_dbg(conn, "tquic_conn_retire_cid: seq=%llu local=%d\n",
		       seq, is_local);

	/* Select list based on whether it's a local or remote CID */
	list = is_local ? &conn->scid_list : &conn->dcid_list;

	list_for_each_entry_safe(entry, tmp, list, list) {
		if (entry->seq_num == seq) {
			tquic_cid_entry_destroy(entry);
			return 0;
		}
	}

	return -ENOENT;
}
#endif /* TQUIC_OUT_OF_TREE */

/* Process NEW_CONNECTION_ID from peer */
static int tquic_conn_add_peer_cid(struct tquic_connection *conn,
				   struct tquic_cid *cid, u64 seq,
				   u64 retire_prior_to, const u8 *reset_token)
{
	struct tquic_cid_entry *entry, *tmp;

	/* Retire CIDs with sequence < retire_prior_to */
	list_for_each_entry_safe(entry, tmp, &conn->dcid_list, list) {
		if (entry->seq_num < retire_prior_to) {
			list_del_init(&entry->list);
			kmem_cache_free(tquic_cid_cache, entry);
		}
	}

	conn->retire_dcid_prior_to = retire_prior_to;

	/* Add new CID */
	entry = tquic_cid_entry_create(cid, seq);
	if (!entry)
		return -ENOMEM;

	entry->conn = conn; /* Associate CID with connection */
	if (reset_token)
		memcpy(entry->reset_token, reset_token,
		       TQUIC_STATELESS_RESET_TOKEN_LEN);

	list_add_tail(&entry->list, &conn->dcid_list);

	return 0;
}

/* Get active destination CID */
static struct tquic_cid *tquic_conn_get_dcid(struct tquic_connection *conn)
{
	return &conn->dcid;
}

/* Rotate to next destination CID */
static int tquic_conn_rotate_dcid(struct tquic_connection *conn)
{
	struct tquic_cid_entry *entry;
	tquic_conn_dbg(conn, "tquic_conn_rotate_dcid: rotating destination CID\n");

	list_for_each_entry(entry, &conn->dcid_list, list) {
		if (entry->state == CID_STATE_ACTIVE) {
			memcpy(&conn->dcid, &entry->cid, sizeof(conn->dcid));
			return 0;
		}
	}

	return -ENOENT; /* No available CIDs */
}

/*
 * tquic_conn_migrate_to_preferred_address - Initiate migration to server's
 *                                           preferred address
 * @conn: TQUIC connection
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
static int
tquic_conn_migrate_to_preferred_address(struct tquic_connection *conn)
{
	struct tquic_preferred_address *pa;
	struct tquic_path *active_path;
	struct tquic_path *new_path = NULL;
	struct sockaddr_storage local_addr;
	struct sockaddr_storage remote_addr;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	struct tquic_cid new_cid;
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
	    memcmp(pa->ipv6_addr, "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0", 16) !=
		    0) {
		/* Use IPv6 preferred address */
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = pa->ipv6_port;
		memcpy(&sin6->sin6_addr, pa->ipv6_addr, 16);

		pr_debug(
			"TQUIC: Attempting migration to IPv6 preferred address\n");
	} else if (pa->ipv4_port != 0 &&
		   memcmp(pa->ipv4_addr, "\0\0\0\0", 4) != 0) {
		/* Use IPv4 preferred address */
		sin = (struct sockaddr_in *)&remote_addr;
		sin->sin_family = AF_INET;
		sin->sin_port = pa->ipv4_port;
		memcpy(&sin->sin_addr, pa->ipv4_addr, 4);

		pr_debug(
			"TQUIC: Attempting migration to IPv4 preferred address\n");
	} else {
		/* No valid address provided */
		pr_debug("TQUIC: No valid preferred address provided\n");
		return -EINVAL;
	}

	/*
	 * Create new path to preferred address.
	 * The path uses the local address from the active path.
	 */
	active_path = tquic_conn_active_path_get(conn);
	if (!active_path)
		return -EINVAL;

	memcpy(&local_addr, &active_path->local_addr, sizeof(local_addr));
	tquic_path_put(active_path);

	new_path = tquic_path_create(conn, &local_addr, &remote_addr);
	if (!new_path) {
		pr_err("TQUIC: Failed to create path to preferred address\n");
		return -ENOMEM;
	}

	/* Mark this path as being for preferred address migration */
	new_path->is_preferred_addr = 1;

	/*
	 * Add the new connection ID from preferred address.
	 * Per RFC 9000: "The sequence number of the connection ID supplied in
	 * the preferred_address transport parameter is 1."
	 */
	if (pa->cid.len > 0) {
		memcpy(&new_cid, &pa->cid, sizeof(new_cid));

		ret = tquic_conn_add_peer_cid(conn, &new_cid, 1, 0,
					      pa->stateless_reset_token);
		if (ret < 0) {
			pr_err("TQUIC: Failed to add preferred address CID: %d\n",
			       ret);
			tquic_path_destroy(new_path);
			return ret;
		}

		/* Switch to the new connection ID for this path */
		memcpy(&conn->dcid, &new_cid, sizeof(conn->dcid));
	}

	/*
	 * Initiate path validation per RFC 9000 Section 8.2.
	 * The connection will migrate to this path after validation succeeds.
	 */
	ret = tquic_path_validate_start(new_path);
	if (ret < 0) {
		pr_err("TQUIC: Failed to start path validation: %d\n", ret);
		tquic_path_destroy(new_path);
		return ret;
	}

	pr_debug("TQUIC: Path validation to preferred address initiated\n");

	/*
	 * Note: The actual migration (calling tquic_path_migrate) happens
	 * when the PATH_RESPONSE is received and the path is validated.
	 * See tquic_path_on_validated() for migration completion.
	 */

	return 0;
}

/*
 * Transport Parameter IDs per RFC 9000 Section 18.2
 */
#define TQUIC_TP_ORIGINAL_DESTINATION_CID 0x00
#define TQUIC_TP_MAX_IDLE_TIMEOUT 0x01
#define TQUIC_TP_STATELESS_RESET_TOKEN 0x02
#define TQUIC_TP_MAX_UDP_PAYLOAD_SIZE 0x03
#define TQUIC_TP_INITIAL_MAX_DATA 0x04
#define TQUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL 0x05
#define TQUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE 0x06
#define TQUIC_TP_INITIAL_MAX_STREAM_DATA_UNI 0x07
#define TQUIC_TP_INITIAL_MAX_STREAMS_BIDI 0x08
#define TQUIC_TP_INITIAL_MAX_STREAMS_UNI 0x09
#define TQUIC_TP_ACK_DELAY_EXPONENT 0x0a
#define TQUIC_TP_MAX_ACK_DELAY 0x0b
#define TQUIC_TP_DISABLE_ACTIVE_MIGRATION 0x0c
#define TQUIC_TP_PREFERRED_ADDRESS 0x0d
#define TQUIC_TP_ACTIVE_CONNECTION_ID_LIMIT 0x0e
#define TQUIC_TP_INITIAL_SOURCE_CID 0x0f
#define TQUIC_TP_RETRY_SOURCE_CID 0x10
#define TQUIC_TP_MAX_DATAGRAM_FRAME_SIZE 0x20
#define TQUIC_TP_GREASE_QUIC_BIT 0x2ab2

/*
 * RFC 9000 Section 18.2 Limits for transport parameters
 */
#define TQUIC_TP_MAX_UDP_PAYLOAD_SIZE_MIN 1200
#define TQUIC_TP_MAX_UDP_PAYLOAD_SIZE_MAX 65527
#define TQUIC_TP_ACK_DELAY_EXPONENT_MAX 20
#define TQUIC_TP_MAX_ACK_DELAY_MAX (1ULL << 14) /* 16384 ms */
#define TQUIC_TP_ACTIVE_CID_LIMIT_MIN 2
#define TQUIC_TP_MAX_STREAMS_MAX (1ULL << 60)
#define TQUIC_TP_MAX_DATA_MAX (1ULL << 62)

/**
 * tquic_transport_param_parse - Parse transport parameters from TLS extension
 * @conn: TQUIC connection
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
int tquic_transport_param_parse(struct tquic_connection *conn, const u8 *data,
				size_t len)
{
	struct tquic_transport_params *params = &conn->remote_params;
	size_t offset = 0;
	u64 param_id;
	u64 param_len;
	int varint_len;
	bool seen_params[32] = { 0 };

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
		varint_len = tquic_varint_decode(data + offset, len - offset,
						 &param_id);
		if (varint_len < 0)
			return -EINVAL;
		offset += varint_len;

		/* Parse parameter length */
		if (offset >= len)
			return -EINVAL;
		varint_len = tquic_varint_decode(data + offset, len - offset,
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
		case TQUIC_TP_ORIGINAL_DESTINATION_CID:
			if (param_len > TQUIC_MAX_CID_LEN)
				return -EPROTO;
			if (!conn->is_server) {
				params->original_dcid.len = param_len;
				if (param_len > 0)
					memcpy(params->original_dcid.id,
					       param_data, param_len);
				params->original_dcid_present = true;
			}
			break;

		case TQUIC_TP_MAX_IDLE_TIMEOUT:
			if (param_len > 8)
				return -EINVAL;
			varint_len = tquic_varint_decode(param_data, param_len,
							 &value);
			if (varint_len < 0 || (size_t)varint_len != param_len)
				return -EINVAL;
			params->max_idle_timeout = value;
			break;

		case TQUIC_TP_STATELESS_RESET_TOKEN:
			if (param_len != 16)
				return -EPROTO;
			if (conn->is_server)
				return -EPROTO;
			memcpy(params->stateless_reset_token, param_data, 16);
			break;

		case TQUIC_TP_MAX_UDP_PAYLOAD_SIZE:
			if (param_len > 8)
				return -EINVAL;
			varint_len = tquic_varint_decode(param_data, param_len,
							 &value);
			if (varint_len < 0 || (size_t)varint_len != param_len)
				return -EINVAL;
			if (value < TQUIC_TP_MAX_UDP_PAYLOAD_SIZE_MIN)
				return -EPROTO;
			if (value > TQUIC_TP_MAX_UDP_PAYLOAD_SIZE_MAX)
				value = TQUIC_TP_MAX_UDP_PAYLOAD_SIZE_MAX;
			params->max_udp_payload_size = value;
			break;

		case TQUIC_TP_INITIAL_MAX_DATA:
			if (param_len > 8)
				return -EINVAL;
			varint_len = tquic_varint_decode(param_data, param_len,
							 &value);
			if (varint_len < 0 || (size_t)varint_len != param_len)
				return -EINVAL;
			if (value > TQUIC_TP_MAX_DATA_MAX)
				return -EPROTO;
			params->initial_max_data = value;
			break;

		case TQUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL:
			if (param_len > 8)
				return -EINVAL;
			varint_len = tquic_varint_decode(param_data, param_len,
							 &value);
			if (varint_len < 0 || (size_t)varint_len != param_len)
				return -EINVAL;
			if (value > TQUIC_TP_MAX_DATA_MAX)
				return -EPROTO;
			params->initial_max_stream_data_bidi_local = value;
			break;

		case TQUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE:
			if (param_len > 8)
				return -EINVAL;
			varint_len = tquic_varint_decode(param_data, param_len,
							 &value);
			if (varint_len < 0 || (size_t)varint_len != param_len)
				return -EINVAL;
			if (value > TQUIC_TP_MAX_DATA_MAX)
				return -EPROTO;
			params->initial_max_stream_data_bidi_remote = value;
			break;

		case TQUIC_TP_INITIAL_MAX_STREAM_DATA_UNI:
			if (param_len > 8)
				return -EINVAL;
			varint_len = tquic_varint_decode(param_data, param_len,
							 &value);
			if (varint_len < 0 || (size_t)varint_len != param_len)
				return -EINVAL;
			if (value > TQUIC_TP_MAX_DATA_MAX)
				return -EPROTO;
			params->initial_max_stream_data_uni = value;
			break;

		case TQUIC_TP_INITIAL_MAX_STREAMS_BIDI:
			if (param_len > 8)
				return -EINVAL;
			varint_len = tquic_varint_decode(param_data, param_len,
							 &value);
			if (varint_len < 0 || (size_t)varint_len != param_len)
				return -EINVAL;
			if (value > TQUIC_TP_MAX_STREAMS_MAX)
				return -EPROTO;
			params->initial_max_streams_bidi = value;
			break;

		case TQUIC_TP_INITIAL_MAX_STREAMS_UNI:
			if (param_len > 8)
				return -EINVAL;
			varint_len = tquic_varint_decode(param_data, param_len,
							 &value);
			if (varint_len < 0 || (size_t)varint_len != param_len)
				return -EINVAL;
			if (value > TQUIC_TP_MAX_STREAMS_MAX)
				return -EPROTO;
			params->initial_max_streams_uni = value;
			break;

		case TQUIC_TP_ACK_DELAY_EXPONENT:
			if (param_len > 8)
				return -EINVAL;
			varint_len = tquic_varint_decode(param_data, param_len,
							 &value);
			if (varint_len < 0 || (size_t)varint_len != param_len)
				return -EINVAL;
			if (value > TQUIC_TP_ACK_DELAY_EXPONENT_MAX)
				return -EPROTO;
			params->ack_delay_exponent = value;
			break;

		case TQUIC_TP_MAX_ACK_DELAY:
			if (param_len > 8)
				return -EINVAL;
			varint_len = tquic_varint_decode(param_data, param_len,
							 &value);
			if (varint_len < 0 || (size_t)varint_len != param_len)
				return -EINVAL;
			if (value >= TQUIC_TP_MAX_ACK_DELAY_MAX)
				return -EPROTO;
			params->max_ack_delay = value;
			break;

		case TQUIC_TP_DISABLE_ACTIVE_MIGRATION:
			if (param_len != 0)
				return -EPROTO;
			params->disable_active_migration = 1;
			break;

		case TQUIC_TP_PREFERRED_ADDRESS:
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
				struct tquic_preferred_address *pa =
					&params->preferred_address;
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
				if (cid_len > TQUIC_MAX_CID_LEN)
					return -EPROTO;
				if (param_len < 41 + cid_len)
					return -EINVAL;

				pa->cid.len = cid_len;
				if (cid_len > 0)
					memcpy(pa->cid.id, p, cid_len);
				p += cid_len;

				/* Stateless reset token */
				memcpy(pa->stateless_reset_token, p,
				       TQUIC_STATELESS_RESET_TOKEN_LEN);

				params->preferred_address_present = 1;
			}
			break;

		case TQUIC_TP_ACTIVE_CONNECTION_ID_LIMIT:
			if (param_len > 8)
				return -EINVAL;
			varint_len = tquic_varint_decode(param_data, param_len,
							 &value);
			if (varint_len < 0 || (size_t)varint_len != param_len)
				return -EINVAL;
			if (value < TQUIC_TP_ACTIVE_CID_LIMIT_MIN)
				return -EPROTO;
			params->active_connection_id_limit = value;
			break;

		case TQUIC_TP_INITIAL_SOURCE_CID:
			if (param_len > TQUIC_MAX_CID_LEN)
				return -EPROTO;
			params->initial_scid.len = param_len;
			if (param_len > 0)
				memcpy(params->initial_scid.id, param_data,
				       param_len);
			params->initial_scid_present = true;
			break;

		case TQUIC_TP_RETRY_SOURCE_CID:
			if (conn->is_server)
				return -EPROTO;
			if (param_len > TQUIC_MAX_CID_LEN)
				return -EPROTO;
			params->retry_scid.len = param_len;
			if (param_len > 0)
				memcpy(params->retry_scid.id, param_data,
				       param_len);
			params->retry_scid_present = true;
			break;

		case TQUIC_TP_MAX_DATAGRAM_FRAME_SIZE:
			if (param_len > 8)
				return -EINVAL;
			varint_len = tquic_varint_decode(param_data, param_len,
							 &value);
			if (varint_len < 0 || (size_t)varint_len != param_len)
				return -EINVAL;
			params->max_datagram_frame_size = value;
			break;

		case TQUIC_TP_GREASE_QUIC_BIT:
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
EXPORT_SYMBOL(tquic_transport_param_parse);

/**
 * tquic_transport_param_apply - Apply parsed transport params to connection
 * @conn: TQUIC connection with populated remote_params
 *
 * Returns 0 on success, negative error code on failure.
 */
int tquic_transport_param_apply(struct tquic_connection *conn)
{
	struct tquic_transport_params *params = &conn->remote_params;

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
		conn->max_stream_id_bidi = params->initial_max_streams_bidi * 4;
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

		tquic_timer_set(conn, TQUIC_TIMER_IDLE,
				ktime_add_ms(ktime_get(), effective_timeout));
	}

	/* Apply path MTU limit */
	{
		struct tquic_path *active_path;
		u32 max_payload = params->max_udp_payload_size;

		active_path = tquic_conn_active_path_get(conn);
		if (active_path) {
			if (max_payload < active_path->mtu)
				active_path->mtu = max_payload;
			tquic_path_put(active_path);
		}
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
		int ret = tquic_conn_migrate_to_preferred_address(conn);
		if (ret < 0) {
			pr_debug(
				"TQUIC: Failed to initiate preferred address migration: %d\n",
				ret);
			/* Per RFC 9000: Failure to validate does not cause
			 * connection failure; just continue on current path.
			 */
		}
	}

	return 0;
}
EXPORT_SYMBOL(tquic_transport_param_apply);

/**
 * tquic_transport_param_encode - Encode local transport parameters
 * @conn: TQUIC connection
 * @buf: Output buffer for encoded parameters
 * @buf_len: Size of output buffer
 * @out_len: Returns actual encoded length
 *
 * Returns 0 on success, -ENOBUFS if buffer too small.
 */
int tquic_transport_param_encode(struct tquic_connection *conn, u8 *buf,
				 size_t buf_len, size_t *out_len)
{
	struct tquic_transport_params *params = &conn->local_params;
	size_t offset = 0;
	int id_len, val_len, len_len;

#define ENCODE_VARINT_PARAM(id, val)                                 \
	do {                                                         \
		u64 _val = (val);                                    \
		id_len = tquic_varint_len(id);                       \
		val_len = tquic_varint_len(_val);                    \
		len_len = tquic_varint_len(val_len);                 \
		if (offset + id_len + len_len + val_len > buf_len)   \
			return -ENOBUFS;                             \
		offset += tquic_varint_encode(id, buf + offset,      \
					      buf_len - offset);     \
		offset += tquic_varint_encode(val_len, buf + offset, \
					      buf_len - offset);     \
		offset += tquic_varint_encode(_val, buf + offset,    \
					      buf_len - offset);     \
	} while (0)

#define ENCODE_EMPTY_PARAM(id)                                   \
	do {                                                     \
		id_len = tquic_varint_len(id);                   \
		if (offset + id_len + 1 > buf_len)               \
			return -ENOBUFS;                         \
		offset += tquic_varint_encode(id, buf + offset,  \
					      buf_len - offset); \
		buf[offset++] = 0;                               \
	} while (0)

	/* original_destination_connection_id - server only */
	if (conn->is_server && conn->original_dcid.len > 0) {
		id_len = tquic_varint_len(TQUIC_TP_ORIGINAL_DESTINATION_CID);
		len_len = tquic_varint_len(conn->original_dcid.len);
		if (offset + id_len + len_len + conn->original_dcid.len >
		    buf_len)
			return -ENOBUFS;
		offset += tquic_varint_encode(TQUIC_TP_ORIGINAL_DESTINATION_CID,
					      buf + offset, buf_len - offset);
		offset += tquic_varint_encode(conn->original_dcid.len,
					      buf + offset, buf_len - offset);
		memcpy(buf + offset, conn->original_dcid.id,
		       conn->original_dcid.len);
		offset += conn->original_dcid.len;
	}

	if (params->max_idle_timeout > 0)
		ENCODE_VARINT_PARAM(TQUIC_TP_MAX_IDLE_TIMEOUT,
				    params->max_idle_timeout);

	if (params->max_udp_payload_size != 65527)
		ENCODE_VARINT_PARAM(TQUIC_TP_MAX_UDP_PAYLOAD_SIZE,
				    params->max_udp_payload_size);

	if (params->initial_max_data > 0)
		ENCODE_VARINT_PARAM(TQUIC_TP_INITIAL_MAX_DATA,
				    params->initial_max_data);

	if (params->initial_max_stream_data_bidi_local > 0)
		ENCODE_VARINT_PARAM(TQUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
				    params->initial_max_stream_data_bidi_local);

	if (params->initial_max_stream_data_bidi_remote > 0)
		ENCODE_VARINT_PARAM(
			TQUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
			params->initial_max_stream_data_bidi_remote);

	if (params->initial_max_stream_data_uni > 0)
		ENCODE_VARINT_PARAM(TQUIC_TP_INITIAL_MAX_STREAM_DATA_UNI,
				    params->initial_max_stream_data_uni);

	if (params->initial_max_streams_bidi > 0)
		ENCODE_VARINT_PARAM(TQUIC_TP_INITIAL_MAX_STREAMS_BIDI,
				    params->initial_max_streams_bidi);

	if (params->initial_max_streams_uni > 0)
		ENCODE_VARINT_PARAM(TQUIC_TP_INITIAL_MAX_STREAMS_UNI,
				    params->initial_max_streams_uni);

	if (params->ack_delay_exponent != 3)
		ENCODE_VARINT_PARAM(TQUIC_TP_ACK_DELAY_EXPONENT,
				    params->ack_delay_exponent);

	if (params->max_ack_delay != 25)
		ENCODE_VARINT_PARAM(TQUIC_TP_MAX_ACK_DELAY,
				    params->max_ack_delay);

	if (params->disable_active_migration)
		ENCODE_EMPTY_PARAM(TQUIC_TP_DISABLE_ACTIVE_MIGRATION);

	if (params->active_connection_id_limit > 2)
		ENCODE_VARINT_PARAM(TQUIC_TP_ACTIVE_CONNECTION_ID_LIMIT,
				    params->active_connection_id_limit);

	/* initial_source_connection_id */
	id_len = tquic_varint_len(TQUIC_TP_INITIAL_SOURCE_CID);
	len_len = tquic_varint_len(conn->scid.len);
	if (offset + id_len + len_len + conn->scid.len > buf_len)
		return -ENOBUFS;
	offset += tquic_varint_encode(TQUIC_TP_INITIAL_SOURCE_CID, buf + offset,
				      buf_len - offset);
	offset += tquic_varint_encode(conn->scid.len, buf + offset,
				      buf_len - offset);
	memcpy(buf + offset, conn->scid.id, conn->scid.len);
	offset += conn->scid.len;

	if (params->max_datagram_frame_size > 0)
		ENCODE_VARINT_PARAM(TQUIC_TP_MAX_DATAGRAM_FRAME_SIZE,
				    params->max_datagram_frame_size);

#undef ENCODE_VARINT_PARAM
#undef ENCODE_EMPTY_PARAM

	*out_len = offset;
	return 0;
}
EXPORT_SYMBOL(tquic_transport_param_encode);

/**
 * tquic_transport_param_validate - Validate transport parameters
 * @conn: TQUIC connection with populated remote_params
 *
 * Returns 0 on success, -EPROTO on protocol violation.
 */
int tquic_transport_param_validate(struct tquic_connection *conn)
{
	struct tquic_transport_params *params = &conn->remote_params;
	tquic_conn_dbg(conn, "tquic_transport_param_validate: validating remote params\n");

	/* Validate original_destination_connection_id matches */
	if (!conn->is_server && params->original_dcid_present) {
		if (params->original_dcid.len != conn->original_dcid.len)
			return -EPROTO;
		if (memcmp(params->original_dcid.id, conn->original_dcid.id,
			   params->original_dcid.len) != 0)
			return -EPROTO;
	}

	return 0;
}
EXPORT_SYMBOL(tquic_transport_param_validate);
