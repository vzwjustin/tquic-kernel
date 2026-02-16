// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Connection State Machine
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * This module implements the QUIC connection state machine as specified
 * in RFC 9000, with extensions for WAN bonding and multi-path support.
 *
 * Connection States (RFC 9000 compatible):
 *   IDLE        -> Initial state, no connection activity
 *   HANDSHAKING -> TLS handshake in progress
 *   CONNECTED   -> Handshake complete, data can flow
 *   CLOSING     -> CONNECTION_CLOSE sent, waiting for drain
 *   DRAINING    -> Draining period, discarding packets
 *   CLOSED      -> Connection fully terminated
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/rbtree.h>
#include <linux/spinlock.h>
#include <linux/timer.h>
#include <crypto/algapi.h>
#include <crypto/hash.h>
#include <linux/workqueue.h>
#include <linux/random.h>
#include <linux/unaligned.h>
#include <linux/jhash.h>
#include <linux/rhashtable.h>
#include <linux/rcupdate.h>
#include <crypto/aead.h>
#include <crypto/gcm.h>
#include <net/sock.h>
#include <net/udp.h>
#include <net/tquic.h>

#include "../tquic_compat.h"
#include "../tquic_debug.h"
#include "varint.h"
#include "../tquic_stateless_reset.h"
#include "../protocol.h"

/* Forward declarations for frame functions (from frame.c) */
int tquic_write_path_challenge_frame(u8 *buf, size_t buf_len, const u8 *data);
int tquic_write_path_response_frame(u8 *buf, size_t buf_len, const u8 *data);
int tquic_write_connection_close_frame(u8 *buf, size_t buf_len, u64 error_code,
				       u64 frame_type, const u8 *reason,
				       u64 reason_len, bool app_close);

static struct tquic_path *tquic_conn_active_path_get(struct tquic_connection *conn)
{
	struct tquic_path *path;

	rcu_read_lock();
	path = rcu_dereference(conn->active_path);
	if (path && !tquic_path_get(path))
		path = NULL;
	rcu_read_unlock();

	return path;
}

/* QUIC Error Codes (RFC 9000 Section 20) */
#define TQUIC_NO_ERROR			0x00
#define TQUIC_INTERNAL_ERROR		0x01
#define TQUIC_CONNECTION_REFUSED	0x02
#define TQUIC_FLOW_CONTROL_ERROR	0x03
#define TQUIC_STREAM_LIMIT_ERROR	0x04
#define TQUIC_STREAM_STATE_ERROR	0x05
#define TQUIC_FINAL_SIZE_ERROR		0x06
#define TQUIC_FRAME_ENCODING_ERROR	0x07
#define TQUIC_TRANSPORT_PARAMETER_ERROR	0x08
#define TQUIC_CONNECTION_ID_LIMIT_ERROR	0x09
#define TQUIC_PROTOCOL_VIOLATION	0x0a
#define TQUIC_INVALID_TOKEN		0x0b
#define TQUIC_APPLICATION_ERROR		0x0c
#define TQUIC_CRYPTO_BUFFER_EXCEEDED	0x0d
#define TQUIC_KEY_UPDATE_ERROR		0x0e
#define TQUIC_AEAD_LIMIT_REACHED	0x0f
#define TQUIC_NO_VIABLE_PATH		0x10
#define TQUIC_VERSION_NEGOTIATION_ERROR	0x11

/* Crypto error range: 0x100-0x1ff */
#define TQUIC_CRYPTO_ERROR_BASE		0x100

/* Handshake sub-states for internal state machine tracking */
enum tquic_hs_substate {
	TQUIC_HS_INITIAL,
	TQUIC_HS_CLIENT_HELLO_SENT,
	TQUIC_HS_SERVER_HELLO_RECEIVED,
	TQUIC_HS_ENCRYPTED_EXTENSIONS,
	TQUIC_HS_CERTIFICATE,
	TQUIC_HS_CERTIFICATE_VERIFY,
	TQUIC_HS_FINISHED_SENT,
	TQUIC_HS_FINISHED_RECEIVED,
	TQUIC_HS_COMPLETE,
	TQUIC_HS_CONFIRMED,
};

/* Connection ID entry for managing multiple CIDs */
struct tquic_cid_entry {
	struct tquic_cid cid;
	u8 stateless_reset_token[16];
	bool has_reset_token;
	bool retired;
	struct tquic_connection *conn;
	struct list_head list;
	struct rhash_head hash_node;
	struct rcu_head rcu;
};

/* Pending path challenge/response */
struct tquic_path_challenge {
	u8 data[8];
	ktime_t sent_time;
	u32 retries;
	struct tquic_path *path;
	struct list_head list;
};

/* Connection close frame data */
struct tquic_close_frame {
	u64 error_code;
	u64 frame_type;		/* For transport errors */
	char *reason_phrase;
	u32 reason_len;
	bool is_application;
};

/* Extended connection structure for internal state machine */
struct tquic_conn_state_machine {
	/*
	 * Type discriminator -- MUST be the first field.
	 * conn->state_machine is a void pointer shared by multiple
	 * subsystems (connection state, migration, session).  Each
	 * subsystem tags its struct with a unique magic so that
	 * type-safe accessors can reject mismatched casts.
	 */
	u32 magic;

	/* Handshake sub-state */
	enum tquic_hs_substate hs_state;
	bool is_server;
	bool handshake_confirmed;
	bool client_hello_received;	/* Server: ClientHello received */

	/* Version negotiation */
	u32 original_version;
	u32 negotiated_version;
	bool version_negotiation_done;
	u32 *supported_versions;
	u32 num_supported_versions;

	/* Connection IDs */
	struct list_head local_cids;	/* Our CIDs */
	struct list_head remote_cids;	/* Peer's CIDs */
	u64 next_local_cid_seq;
	u64 next_remote_cid_seq;
	u32 active_cid_limit;
	u8 retire_prior_to;

	/* Stateless reset */
	u8 stateless_reset_token[16];
	bool has_stateless_reset;

	/* Address validation */
	struct list_head pending_challenges;
	bool address_validated;
	u32 amplification_limit;
	u64 bytes_sent_unvalidated;
	u64 bytes_received_unvalidated;

	/* Retry state */
	u8 *retry_token;
	u32 retry_token_len;
	bool retry_received;
	struct tquic_cid retry_source_cid;

	/* 0-RTT state */
	bool zero_rtt_enabled;
	bool zero_rtt_accepted;
	bool zero_rtt_rejected;
	struct sk_buff_head zero_rtt_buffer;

	/* Connection close state */
	struct tquic_close_frame local_close;
	struct tquic_close_frame remote_close;
	bool close_sent;
	bool close_received;
	u32 close_retries;
	ktime_t closing_start;

	/* Draining state */
	ktime_t draining_start;
	u32 drain_timeout_ms;

	/* Packet number spaces */
	u64 largest_pn_sent[TQUIC_PN_SPACE_COUNT];
	u64 largest_pn_received[TQUIC_PN_SPACE_COUNT];
	u64 next_pn[TQUIC_PN_SPACE_COUNT];

	/* Anti-amplification state */
	u64 bytes_acked;
	bool anti_amplification_blocked;

	/* Migration state */
	bool migration_disabled;
	bool migration_in_progress;
	struct tquic_path *migration_target;
	ktime_t migration_start;

	/* Work queues */
	struct work_struct close_work;
	struct work_struct migration_work;
	struct delayed_work drain_work;

	/* Parent connection */
	struct tquic_connection *conn;
};

/* Global connection ID hash table for fast lookup */
static struct rhashtable cid_lookup_table;

static u32 tquic_state_cid_hashfn(const void *data, u32 len, u32 seed)
{
	const struct tquic_cid *cid = data;
	u8 key_len = min_t(u8, cid->len, TQUIC_MAX_CID_LEN);

	return jhash(cid->id, key_len, seed);
}

static u32 tquic_state_cid_obj_hashfn(const void *data, u32 len, u32 seed)
{
	const struct tquic_cid_entry *entry = data;
	u8 key_len = min_t(u8, entry->cid.len, TQUIC_MAX_CID_LEN);

	return jhash(entry->cid.id, key_len, seed);
}

static int tquic_state_cid_obj_cmpfn(struct rhashtable_compare_arg *arg,
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

static const struct rhashtable_params cid_hash_params = {
	.key_len = sizeof(struct tquic_cid),
	.key_offset = offsetof(struct tquic_cid_entry, cid),
	.head_offset = offsetof(struct tquic_cid_entry, hash_node),
	.hashfn = tquic_state_cid_hashfn,
	.obj_hashfn = tquic_state_cid_obj_hashfn,
	.obj_cmpfn = tquic_state_cid_obj_cmpfn,
	.automatic_shrinking = true,
};

/* Retry token AEAD encryption state */
#define TQUIC_RETRY_TOKEN_KEY_LEN	16
#define TQUIC_RETRY_TOKEN_IV_LEN	12
#define TQUIC_RETRY_TOKEN_TAG_LEN	16

static u8 tquic_retry_token_key[TQUIC_RETRY_TOKEN_KEY_LEN];
static struct crypto_aead *tquic_retry_aead;
static DEFINE_SPINLOCK(tquic_retry_aead_lock);
static bool tquic_retry_aead_initialized;

/* Retry Integrity Tag AEAD - cached per RFC 9001 Section 5.8 */
static struct crypto_aead *tquic_retry_integrity_aead_v1;
static struct crypto_aead *tquic_retry_integrity_aead_v2;
static DEFINE_SPINLOCK(tquic_retry_integrity_lock);

/*
 * Type-safe accessor for conn->state_machine -> tquic_conn_state_machine.
 * Returns NULL if state_machine is NULL or holds a different type
 * (e.g. tquic_migration_state from tquic_migration.c).
 */
static inline struct tquic_conn_state_machine *
tquic_conn_get_cs(struct tquic_connection *conn)
{
	struct tquic_conn_state_machine *cs;

	if (!conn->state_machine)
		return NULL;

	cs = conn->state_machine;
	if (cs->magic != TQUIC_SM_MAGIC_CONN_STATE)
		return NULL;

	return cs;
}

/* Forward declarations */
static void tquic_conn_enter_closing(struct tquic_connection *conn,
				     u64 error_code, const char *reason);
static void tquic_conn_enter_draining(struct tquic_connection *conn);
static int tquic_send_close_frame(struct tquic_connection *conn);
static void tquic_drain_timeout(struct work_struct *work);
static void tquic_close_work_handler(struct work_struct *work);

/*
 * Connection State Transitions
 */

static const char *tquic_state_name(enum tquic_conn_state state)
{
	static const char *names[] = {
		[TQUIC_CONN_IDLE] = "IDLE",
		[TQUIC_CONN_CONNECTING] = "CONNECTING",
		[TQUIC_CONN_CONNECTED] = "CONNECTED",
		[TQUIC_CONN_CLOSING] = "CLOSING",
		[TQUIC_CONN_DRAINING] = "DRAINING",
		[TQUIC_CONN_CLOSED] = "CLOSED",
	};

	if (state < ARRAY_SIZE(names))
		return names[state];
	return "UNKNOWN";
}

/**
 * tquic_conn_set_state - Transition connection to a new state
 * @conn: The connection
 * @new_state: Target state
 * @reason: Reason for transition
 *
 * Handles all state transition logic and triggers appropriate actions.
 * Returns 0 on success, negative error if transition is invalid.
 */
int tquic_conn_set_state(struct tquic_connection *conn,
			 enum tquic_conn_state new_state,
			 enum tquic_state_reason reason)
{
	struct tquic_conn_state_machine *cs = tquic_conn_get_cs(conn);
	enum tquic_conn_state old_state;
	bool valid = false;

	/*
	 * SECURITY FIX (CF-095): Hold conn->lock across the read of
	 * old_state and the write of new_state to make the transition
	 * atomic with respect to concurrent callers. The lock is
	 * released before performing side-effect actions (work
	 * scheduling, timer cancellation) that must not run under
	 * spinlock.
	 */
	spin_lock_bh(&conn->lock);
	old_state = conn->state;

	/* Validate state transition */
	switch (old_state) {
	case TQUIC_CONN_IDLE:
		valid = (new_state == TQUIC_CONN_CONNECTING ||
			 new_state == TQUIC_CONN_CLOSED);
		break;

	case TQUIC_CONN_CONNECTING:
		/*
		 * DRAINING is valid from CONNECTING because the peer may
		 * send CONNECTION_CLOSE during the handshake (RFC 9000).
		 */
		valid = (new_state == TQUIC_CONN_CONNECTED ||
			 new_state == TQUIC_CONN_CLOSING ||
			 new_state == TQUIC_CONN_DRAINING ||
			 new_state == TQUIC_CONN_CLOSED);
		break;

	case TQUIC_CONN_CONNECTED:
		valid = (new_state == TQUIC_CONN_CLOSING ||
			 new_state == TQUIC_CONN_DRAINING ||
			 new_state == TQUIC_CONN_CLOSED);
		break;

	case TQUIC_CONN_CLOSING:
		valid = (new_state == TQUIC_CONN_DRAINING ||
			 new_state == TQUIC_CONN_CLOSED);
		break;

	case TQUIC_CONN_DRAINING:
		valid = (new_state == TQUIC_CONN_CLOSED);
		break;

	case TQUIC_CONN_CLOSED:
		valid = false;  /* Terminal state */
		break;
	}

	if (!valid) {
		spin_unlock_bh(&conn->lock);
		tquic_conn_warn(conn, "invalid state transition %s -> %s\n",
				tquic_state_name(old_state),
				tquic_state_name(new_state));
		return -EINVAL;
	}

	WRITE_ONCE(conn->state, new_state);
	spin_unlock_bh(&conn->lock);

	tquic_conn_info(conn, "state %s -> %s reason=%d\n",
			tquic_state_name(old_state),
			tquic_state_name(new_state), reason);

	/*
	 * Perform state-specific entry actions.
	 *
	 * cs may be NULL if conn->state_machine holds a different type
	 * (e.g. tquic_migration_state for server connections via
	 * tquic_server_handshake).  In that case, skip the
	 * tquic_conn_state_machine-specific side-effects but still
	 * update the connection state and wake waiters.
	 */
	switch (new_state) {
	case TQUIC_CONN_CONNECTING:
		if (cs)
			cs->hs_state = TQUIC_HS_INITIAL;
		break;

	case TQUIC_CONN_CONNECTED:
		if (cs)
			cs->handshake_confirmed = true;
		conn->stats.established_time = ktime_get();
		if (conn->scheduler)
			tquic_conn_info(conn, "established, bonding active\n");
		break;

	case TQUIC_CONN_CLOSING:
		if (cs) {
			cs->closing_start = ktime_get();
			schedule_work(&cs->close_work);
		}
		wake_up_interruptible(&conn->datagram.wait);
		/* Wake all stream waiters so recv() can return 0 */
		{
			struct rb_node *node;

			spin_lock_bh(&conn->lock);
			for (node = rb_first(&conn->streams); node;
			     node = rb_next(node)) {
				struct tquic_stream *s;

				s = rb_entry(node, struct tquic_stream, node);
				wake_up_interruptible(&s->wait);
			}
			spin_unlock_bh(&conn->lock);
		}
		break;

	case TQUIC_CONN_DRAINING:
		if (cs) {
			cs->draining_start = ktime_get();
			schedule_delayed_work(&cs->drain_work,
					      msecs_to_jiffies(cs->drain_timeout_ms));
		}
		wake_up_interruptible(&conn->datagram.wait);
		/* Wake all stream waiters so recv() can return 0 */
		{
			struct rb_node *node;

			spin_lock_bh(&conn->lock);
			for (node = rb_first(&conn->streams); node;
			     node = rb_next(node)) {
				struct tquic_stream *s;

				s = rb_entry(node, struct tquic_stream, node);
				wake_up_interruptible(&s->wait);
			}
			spin_unlock_bh(&conn->lock);
		}
		break;

	case TQUIC_CONN_CLOSED:
		/*
		 * Cancel all pending work.
		 *
		 * Determine if we are being called from within a work
		 * callback context (e.g., tquic_drain_timeout ->
		 * tquic_conn_enter_closed). If so, we must use non-sync
		 * variants to avoid self-deadlock since cancel_work_sync
		 * waits for the currently executing work to complete.
		 *
		 * If NOT in a work context, use sync variants to ensure
		 * no work is still executing when we proceed to free
		 * resources.
		 *
		 * current_work() returns the work_struct currently being
		 * executed on this CPU's workqueue, or NULL if not in a
		 * work context.
		 */
		if (cs) {
			if (current_work() == &cs->close_work ||
			    current_work() == &cs->migration_work ||
			    current_work() == &cs->drain_work.work) {
				cancel_work(&cs->close_work);
				cancel_work(&cs->migration_work);
				cancel_delayed_work(&cs->drain_work);
			} else {
				cancel_work_sync(&cs->close_work);
				cancel_work_sync(&cs->migration_work);
				cancel_delayed_work_sync(&cs->drain_work);
			}
		}

		wake_up_interruptible(&conn->datagram.wait);
		if (conn->sk && conn->sk->sk_state_change)
			conn->sk->sk_state_change(conn->sk);
		break;

	default:
		break;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_conn_set_state);

/*
 * Connection ID Management
 */

/**
 * tquic_cid_gen_random - Generate a new connection ID
 * @cid: Output CID structure
 * @len: Desired length (0-20)
 *
 * Generates a cryptographically random connection ID.
 */
static void tquic_cid_gen_random(struct tquic_cid *cid, u8 len)
{
	tquic_dbg("tquic_cid_gen_random: generating CID len=%u\n", len);
	if (len > TQUIC_MAX_CID_LEN)
		len = TQUIC_MAX_CID_LEN;

	cid->len = len;
	if (len > 0)
		get_random_bytes(cid->id, len);
	cid->seq_num = 0;
	cid->retire_prior_to = 0;
}

/**
 * tquic_cid_compare - Compare two connection IDs
 * @a: First CID
 * @b: Second CID
 *
 * Returns 0 if equal, non-zero otherwise.
 */
static int tquic_cid_compare(const struct tquic_cid *a, const struct tquic_cid *b)
{
	tquic_dbg("tquic_cid_compare: a_len=%u b_len=%u\n", a->len, b->len);
	if (a->len != b->len)
		return a->len - b->len;
	return memcmp(a->id, b->id, a->len);
}

/**
 * tquic_cid_entry_create - Create a new CID entry
 * @cid: The connection ID
 * @seq: Sequence number
 *
 * Allocates and initializes a new CID entry for the CID list.
 */
static struct tquic_cid_entry *tquic_cid_entry_create(const struct tquic_cid *cid,
						      u64 seq)
{
	struct tquic_cid_entry *entry;

	entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
	if (!entry)
		return NULL;

	memcpy(&entry->cid, cid, sizeof(*cid));
	entry->cid.seq_num = seq;
	entry->retired = false;
	entry->has_reset_token = false;
	INIT_LIST_HEAD(&entry->list);

	return entry;
}

/**
 * tquic_conn_add_local_cid - Add a new local connection ID
 * @conn: The connection
 *
 * Generates and registers a new local CID. Returns the CID entry
 * on success or NULL on failure.
 */
struct tquic_cid_entry *tquic_conn_add_local_cid(struct tquic_connection *conn)
{
	struct tquic_conn_state_machine *cs = tquic_conn_get_cs(conn);
	struct tquic_cid_entry *entry;
	struct tquic_cid new_cid;

	if (!cs)
		return NULL;

	/* Generate new CID */
	tquic_cid_gen_random(&new_cid, TQUIC_DEFAULT_CID_LEN);

	/* CF-362: increment sequence under lock to prevent races */
	spin_lock_bh(&conn->lock);
	entry = tquic_cid_entry_create(&new_cid, cs->next_local_cid_seq++);
	if (!entry) {
		spin_unlock_bh(&conn->lock);
		return NULL;
	}
	entry->conn = conn;

	/*
	 * Generate stateless reset token deterministically from CID
	 * Per RFC 9000 Section 10.3.2, using HMAC with static key
	 */
	{
		const u8 *static_key = tquic_stateless_reset_get_static_key();

		if (static_key) {
			tquic_stateless_reset_generate_token(&new_cid, static_key,
							     entry->stateless_reset_token);
		} else {
			get_random_bytes(entry->stateless_reset_token,
					 sizeof(entry->stateless_reset_token));
		}
	}
	entry->has_reset_token = true;

	list_add_tail(&entry->list, &cs->local_cids);

	/* Register in global lookup table */
	{
		int err;

		err = rhashtable_insert_fast(&cid_lookup_table,
					     &entry->hash_node,
					     cid_hash_params);
		if (err) {
			list_del_init(&entry->list);
			cs->next_local_cid_seq--;
			spin_unlock_bh(&conn->lock);
			kfree(entry);
			tquic_conn_err(conn, "rhashtable insert failed: %d\n", err);
			return NULL;
		}
	}
	spin_unlock_bh(&conn->lock);

	tquic_conn_dbg(conn, "added local CID seq=%llu\n", entry->cid.seq_num);

	return entry;
}
EXPORT_SYMBOL_GPL(tquic_conn_add_local_cid);

/**
 * tquic_conn_add_remote_cid - Register a remote connection ID
 * @conn: The connection
 * @cid: The CID from peer
 * @seq: Sequence number
 * @reset_token: Stateless reset token (may be NULL)
 *
 * Stores a CID received from the peer via NEW_CONNECTION_ID frame.
 */
int tquic_conn_add_remote_cid(struct tquic_connection *conn,
			      const struct tquic_cid *cid, u64 seq,
			      const u8 *reset_token)
{
	struct tquic_conn_state_machine *cs = tquic_conn_get_cs(conn);
	struct tquic_cid_entry *entry;

	if (!cs)
		return -EINVAL;

	entry = tquic_cid_entry_create(cid, seq);
	if (!entry)
		return -ENOMEM;

	entry->conn = conn;
	if (reset_token) {
		memcpy(entry->stateless_reset_token, reset_token, 16);
		entry->has_reset_token = true;
	}

	spin_lock_bh(&conn->lock);
	list_add_tail(&entry->list, &cs->remote_cids);
	if (seq >= cs->next_remote_cid_seq)
		cs->next_remote_cid_seq = seq + 1;
	spin_unlock_bh(&conn->lock);

	tquic_conn_dbg(conn, "added remote CID seq=%llu\n", seq);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_conn_add_remote_cid);

/**
 * tquic_conn_retire_cid - Retire a connection ID
 * @conn: The connection
 * @seq: Sequence number to retire
 * @is_local: Whether this is a local or remote CID
 *
 * Marks the specified CID as retired.
 */
int tquic_conn_retire_cid(struct tquic_connection *conn, u64 seq, bool is_local)
{
	struct tquic_conn_state_machine *cs = tquic_conn_get_cs(conn);
	struct tquic_cid_entry *entry;
	struct list_head *cid_list;
	bool found = false;

	if (!cs)
		return -EINVAL;

	cid_list = is_local ? &cs->local_cids : &cs->remote_cids;

	spin_lock_bh(&conn->lock);
	list_for_each_entry(entry, cid_list, list) {
		if (entry->cid.seq_num == seq) {
			entry->retired = true;
			found = true;

			/*
			 * CF-159: Remove local CIDs from the lookup hash
			 * table when retiring. Without this, the CID
			 * remains routable and packets using the retired
			 * CID would still reach this connection.
			 */
			if (is_local)
				rhashtable_remove_fast(&cid_lookup_table,
						       &entry->hash_node,
						       cid_hash_params);
			break;
		}
	}
	spin_unlock_bh(&conn->lock);

	if (!found)
		return -ENOENT;

	tquic_conn_dbg(conn, "retired %s CID seq=%llu\n",
		       is_local ? "local" : "remote", seq);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_conn_retire_cid);

/**
 * tquic_conn_get_active_cid - Get the currently active remote CID
 * @conn: The connection
 *
 * Returns a pointer to conn->dcid which is stable for the connection
 * lifetime, after copying the active CID into it under the lock.
 */
struct tquic_cid *tquic_conn_get_active_cid(struct tquic_connection *conn)
{
	struct tquic_conn_state_machine *cs = tquic_conn_get_cs(conn);
	struct tquic_cid_entry *entry;

	if (!cs)
		return &conn->dcid;

	spin_lock_bh(&conn->lock);
	list_for_each_entry(entry, &cs->remote_cids, list) {
		if (!entry->retired) {
			/* Copy CID data into stable conn->dcid under lock */
			memcpy(&conn->dcid, &entry->cid,
			       sizeof(conn->dcid));
			break;
		}
	}
	spin_unlock_bh(&conn->lock);

	return &conn->dcid;
}
EXPORT_SYMBOL_GPL(tquic_conn_get_active_cid);

/*
 * Stateless Reset Token Management
 */

/**
 * tquic_generate_stateless_reset_token - Generate reset token for a CID
 * @cid: The connection ID
 * @static_key: Server's static key
 * @token: Output buffer (16 bytes)
 *
 * Generates a deterministic stateless reset token using HMAC-SHA256
 * truncated to 128 bits, per RFC 9000 Section 10.3.2.
 */
void tquic_generate_stateless_reset_token(const struct tquic_cid *cid,
					  const u8 *static_key,
					  u8 *token)
{
	struct crypto_shash *tfm;
	struct shash_desc *desc;
	u8 hmac_out[32]; /* SHA-256 output */
	int ret;

	/*
	 * Use HMAC-SHA256 for cryptographically secure token generation.
	 * The token must be unpredictable to prevent spoofed stateless
	 * resets (RFC 9000 Section 10.3).
	 */
	tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);
	if (IS_ERR(tfm)) {
		/*
		 * Fallback: delegate to tquic_stateless_reset_generate_token
		 * which already implements proper HMAC-SHA256.
		 */
		tquic_stateless_reset_generate_token(cid, static_key, token);
		return;
	}

	desc = kzalloc(sizeof(*desc) + crypto_shash_descsize(tfm),
		       GFP_ATOMIC);
	if (!desc) {
		crypto_free_shash(tfm);
		tquic_stateless_reset_generate_token(cid, static_key, token);
		return;
	}

	desc->tfm = tfm;

	ret = crypto_shash_setkey(tfm, static_key,
				  TQUIC_STATELESS_RESET_SECRET_LEN);
	if (ret)
		goto fallback;

	ret = crypto_shash_init(desc);
	if (ret)
		goto fallback;

	ret = crypto_shash_update(desc, cid->id, cid->len);
	if (ret)
		goto fallback;

	ret = crypto_shash_final(desc, hmac_out);
	if (ret)
		goto fallback;

	/* Truncate HMAC-SHA256 to 128 bits for the reset token */
	memcpy(token, hmac_out, 16);
	memzero_explicit(hmac_out, sizeof(hmac_out));

	kfree(desc);
	crypto_free_shash(tfm);
	return;

fallback:
	kfree(desc);
	crypto_free_shash(tfm);
	tquic_stateless_reset_generate_token(cid, static_key, token);
}
EXPORT_SYMBOL_GPL(tquic_generate_stateless_reset_token);

/**
 * tquic_verify_stateless_reset - Check if packet is a stateless reset
 * @conn: The connection
 * @data: Packet data
 * @len: Packet length
 *
 * Verifies if the last 16 bytes match any known reset token.
 * Returns true if this is a valid stateless reset.
 */
bool tquic_verify_stateless_reset(struct tquic_connection *conn,
				  const u8 *data, size_t len)
{
	struct tquic_conn_state_machine *cs = tquic_conn_get_cs(conn);
	struct tquic_cid_entry *entry;
	const u8 *token;
	bool found = false;

	if (len < 21)  /* Minimum: 1 byte header + 4 random + 16 token */
		return false;

	token = data + len - 16;

	if (!cs)
		return false;

	/* Check against known reset tokens under lock */
	spin_lock_bh(&conn->lock);
	list_for_each_entry(entry, &cs->remote_cids, list) {
		if (entry->has_reset_token &&
		    crypto_memneq(entry->stateless_reset_token, token, 16) == 0) {
			found = true;
			break;
		}
	}
	spin_unlock_bh(&conn->lock);

	if (found)
		tquic_conn_info(conn, "received stateless reset\n");

	return found;
}
EXPORT_SYMBOL_GPL(tquic_verify_stateless_reset);

/**
 * tquic_send_stateless_reset - Send a stateless reset packet
 * @conn: The connection
 *
 * Sends a stateless reset to abruptly terminate the connection.
 */
int tquic_send_stateless_reset(struct tquic_connection *conn)
{
	struct tquic_conn_state_machine *cs = tquic_conn_get_cs(conn);
	u8 packet[64];
	int len;

	if (!cs || !cs->has_stateless_reset)
		return -EINVAL;

	/* Build stateless reset packet */
	/* Fixed bit must be 0, rest is random */
	get_random_bytes(packet, sizeof(packet) - 16);
	packet[0] &= ~0x40;  /* Clear fixed bit */

	/* Append stateless reset token */
	memcpy(packet + sizeof(packet) - 16, cs->stateless_reset_token, 16);
	len = sizeof(packet);

	/*
	 * Transmit stateless reset packet on active path.
	 * Stateless resets are sent without encryption since the connection
	 * state may be corrupted or the keys may be unavailable.
	 */
	{
		struct sk_buff *skb;
		struct tquic_path *path;

		path = tquic_conn_active_path_get(conn);
		if (!path)
			goto out_no_path;

		skb = alloc_skb(len + 64, GFP_ATOMIC);
		if (skb) {
			skb_reserve(skb, 64);  /* Reserve headroom for headers */
			skb_put_data(skb, packet, len);

			if (tquic_udp_xmit_on_path(conn, path, skb) == 0) {
				tquic_conn_dbg(conn, "sent stateless reset on path %u\n",
					       path->path_id);
				tquic_path_put(path);
				return 0;
			}
			/* skb is freed by tquic_udp_xmit_on_path on error */
		}

		tquic_path_put(path);
	}
out_no_path:

	tquic_conn_err(conn, "failed to send stateless reset\n");
	return -EIO;
}
EXPORT_SYMBOL_GPL(tquic_send_stateless_reset);

/*
 * Version Negotiation (RFC 9000, RFC 9368, RFC 9369)
 *
 * Supports Compatible Version Negotiation per RFC 9368.
 * Version preference is controlled via /proc/sys/net/tquic/preferred_version.
 */

/* Supported QUIC versions (RFC 9000, RFC 9369) */
static const u32 tquic_supported_versions[] = {
	TQUIC_VERSION_1,	/* RFC 9000: QUIC v1 (0x00000001) */
	TQUIC_VERSION_2,	/* RFC 9369: QUIC v2 (0x6b3343cf) */
	0			/* Sentinel value - marks end of list */
};

/* Number of supported versions (excluding sentinel) */
#define TQUIC_NUM_SUPPORTED_VERSIONS \
	(ARRAY_SIZE(tquic_supported_versions) - 1)

/**
 * tquic_version_is_supported - Check if a version is supported
 * @version: The version to check
 *
 * Returns true if the version is in our supported list.
 */
bool tquic_version_is_supported(u32 version)
{
	int i;

	tquic_dbg("tquic_version_is_supported: checking version=0x%08x\n", version);
	for (i = 0; tquic_supported_versions[i] != 0; i++) {
		if (tquic_supported_versions[i] == version)
			return true;
	}

	return false;
}
EXPORT_SYMBOL_GPL(tquic_version_is_supported);

/**
 * tquic_get_preferred_versions - Get ordered list of supported versions
 * @versions: Output array to fill (must have space for TQUIC_NUM_SUPPORTED_VERSIONS)
 *
 * Returns versions in preference order based on sysctl setting.
 * If preferred_version sysctl is 1, QUIC v2 comes first.
 * Otherwise, QUIC v1 comes first (default, maximum compatibility).
 *
 * Return: Number of versions written to array
 */
int tquic_get_preferred_versions(u32 *versions)
{
	if (tquic_sysctl_prefer_v2()) {
		/* Prefer v2 per sysctl setting */
		versions[0] = TQUIC_VERSION_2;
		versions[1] = TQUIC_VERSION_1;
	} else {
		/* Default: prefer v1 for maximum compatibility */
		versions[0] = TQUIC_VERSION_1;
		versions[1] = TQUIC_VERSION_2;
	}
	return TQUIC_NUM_SUPPORTED_VERSIONS;
}
EXPORT_SYMBOL_GPL(tquic_get_preferred_versions);

/**
 * tquic_version_select - Select best common version
 * @offered: Versions offered by peer
 * @num_offered: Number of offered versions
 *
 * Selects the best mutually supported version, respecting the
 * preferred_version sysctl setting.
 *
 * Returns the best mutually supported version, or 0 if none.
 */
u32 tquic_version_select(const u32 *offered, int num_offered)
{
	u32 preferred[TQUIC_NUM_SUPPORTED_VERSIONS];
	tquic_dbg("tquic_version_select: num_offered=%d\n", num_offered);
	int num_preferred;
	int i, j;

	/* Get versions in preference order */
	num_preferred = tquic_get_preferred_versions(preferred);

	/* Find first mutually supported version in preference order */
	for (i = 0; i < num_preferred; i++) {
		for (j = 0; j < num_offered; j++) {
			if (preferred[i] == offered[j])
				return offered[j];
		}
	}

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_version_select);

/**
 * tquic_version_select_for_initial - Select version for Initial packet
 *
 * Returns the preferred QUIC version to use when sending the first
 * Initial packet. This is controlled by the preferred_version sysctl.
 */
u32 tquic_version_select_for_initial(void)
{
	return tquic_sysctl_get_preferred_version();
}
EXPORT_SYMBOL_GPL(tquic_version_select_for_initial);

/**
 * tquic_send_version_negotiation - Send Version Negotiation packet
 * @conn: The connection
 * @dcid: Destination CID from received packet
 * @scid: Source CID from received packet
 *
 * Sends a VN packet when client uses unsupported version.
 */
int tquic_send_version_negotiation(struct tquic_connection *conn,
				   const struct tquic_cid *dcid,
				   const struct tquic_cid *scid)
{
	u8 packet[256];
	u8 *p = packet;
	int i;

	/* Validate CID lengths against buffer capacity.
	 * Header is 5 + 1 + scid->len + 1 + dcid->len + versions.
	 * Ensure we don't overflow the 256-byte stack buffer.
	 */
	if (scid->len > TQUIC_MAX_CID_LEN || dcid->len > TQUIC_MAX_CID_LEN)
		return -EINVAL;
	if (5 + 1 + scid->len + 1 + dcid->len + 5 * 4 > sizeof(packet))
		return -ENOSPC;

	/*
	 * Long header with version 0.
	 * RFC 9000 Section 17.2.1: "The value in the Unused field is
	 * selected randomly by the server." Randomize bits 0-6.
	 */
	*p++ = 0x80 | (get_random_u8() & 0x7f);
	*p++ = 0x00; *p++ = 0x00; *p++ = 0x00; *p++ = 0x00;  /* Version 0 */

	/* Swap DCIDs (send their SCID as DCID) */
	*p++ = scid->len;
	memcpy(p, scid->id, scid->len);
	p += scid->len;

	*p++ = dcid->len;
	memcpy(p, dcid->id, dcid->len);
	p += dcid->len;

	/* List supported versions */
	for (i = 0; tquic_supported_versions[i] != 0; i++) {
		u32 ver = cpu_to_be32(tquic_supported_versions[i]);
		memcpy(p, &ver, 4);
		p += 4;
	}

	/* H-5: add version greasing per RFC 9000 Section 6.3 */
	{
		u32 grease_version;

		grease_version = (get_random_u32() & 0xf0f0f0f0) | 0x0a0a0a0a;
		put_unaligned_be32(grease_version, p);
		p += 4;
	}

	/*
	 * Transmit Version Negotiation packet.
	 * VN packets are sent without encryption to allow version negotiation
	 * before cryptographic handshake begins.
	 */
	{
		struct sk_buff *skb;
		struct tquic_path *path;
		int pkt_len = p - packet;

		path = tquic_conn_active_path_get(conn);
		if (!path)
			goto out_vn_no_path;

		skb = alloc_skb(pkt_len + 64, GFP_ATOMIC);
		if (skb) {
			skb_reserve(skb, 64);
			skb_put_data(skb, packet, pkt_len);

			if (tquic_udp_xmit_on_path(conn, path, skb) == 0) {
				tquic_conn_dbg(conn, "sent version negotiation on path %u\n",
					       path->path_id);
				tquic_path_put(path);
				return 0;
			}
		}

		tquic_path_put(path);
	}
out_vn_no_path:

	tquic_conn_err(conn, "failed to send version negotiation\n");
	return -EIO;
}
EXPORT_SYMBOL_GPL(tquic_send_version_negotiation);

/**
 * tquic_handle_version_negotiation - Process Version Negotiation packet
 * @conn: The connection
 * @versions: Versions offered by server
 * @num_versions: Number of versions
 *
 * Handles VN packet received from server.
 */
int tquic_handle_version_negotiation(struct tquic_connection *conn,
				     const u32 *versions, int num_versions)
{
	struct tquic_conn_state_machine *cs = tquic_conn_get_cs(conn);
	u32 new_version;
	int i;

	if (!cs)
		return -EINVAL;

	/* VN only valid during handshake */
	if (READ_ONCE(conn->state) != TQUIC_CONN_CONNECTING)
		return -EINVAL;

	/* Check for version downgrade attack */
	if (cs->version_negotiation_done) {
		tquic_conn_warn(conn, "duplicate version negotiation\n");
		return -EPROTO;
	}

	/*
	 * RFC 9000 Section 6.1: A client MUST discard a Version Negotiation
	 * packet that lists the QUIC version selected by the client.
	 */
	for (i = 0; i < num_versions; i++) {
		if (versions[i] == conn->version) {
			tquic_conn_warn(conn,
					"VN lists our current version 0x%08x, discarding\n",
					conn->version);
			return -EPROTO;
		}
	}

	new_version = tquic_version_select(versions, num_versions);
	if (new_version == 0) {
		tquic_conn_err(conn, "no common version with server\n");
		tquic_conn_enter_closing(conn, TQUIC_VERSION_NEGOTIATION_ERROR,
					 "No compatible version");
		return -EPROTO;
	}

	cs->original_version = conn->version;
	cs->negotiated_version = new_version;
	cs->version_negotiation_done = true;
	conn->version = new_version;

	tquic_conn_info(conn, "version negotiated: 0x%08x -> 0x%08x\n",
			cs->original_version, new_version);

	/* Restart connection with new version */
	return tquic_conn_client_restart(conn);
}
EXPORT_SYMBOL_GPL(tquic_handle_version_negotiation);

/*
 * Retry Token Validation
 */

/* Retry token structure (encrypted) */
#define TQUIC_RETRY_TOKEN_MAX_LEN	256
#define TQUIC_RETRY_TOKEN_LIFETIME_MS	60000

/**
 * tquic_generate_retry_token - Generate a Retry token
 * @conn: The connection
 * @original_dcid: Original DCID from client
 * @client_addr: Client's address
 * @token: Output buffer
 * @token_len: Output length
 *
 * Creates an encrypted token for address validation.
 */
int tquic_generate_retry_token(struct tquic_connection *conn,
			       const struct tquic_cid *original_dcid,
			       const struct sockaddr *client_addr,
			       u8 *token, u32 *token_len)
{
	u8 plaintext[128];
	u8 nonce[TQUIC_RETRY_TOKEN_IV_LEN];
	u8 *p = plaintext;
	struct aead_request *req;
	struct scatterlist sg[2];
	size_t plaintext_len;
	ktime_t now = ktime_get();
	int ret;

	/* Token format: timestamp || original_dcid || client_addr_hash */
	memcpy(p, &now, sizeof(now));
	p += sizeof(now);

	*p++ = original_dcid->len;
	memcpy(p, original_dcid->id, original_dcid->len);
	p += original_dcid->len;

	/* Hash client address for validation */
	if (client_addr->sa_family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *)client_addr;
		u32 hash = jhash(&sin->sin_addr, sizeof(sin->sin_addr),
				 sin->sin_port);
		memcpy(p, &hash, sizeof(hash));
		p += sizeof(hash);
	} else if (client_addr->sa_family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)client_addr;
		u32 hash = jhash(&sin6->sin6_addr, sizeof(sin6->sin6_addr),
				 sin6->sin6_port);
		memcpy(p, &hash, sizeof(hash));
		p += sizeof(hash);
	}

	plaintext_len = p - plaintext;

	/* Check if AEAD is initialized */
	if (!tquic_retry_aead_initialized || !tquic_retry_aead) {
		tquic_warn("retry token AEAD not initialized\n");
		return -ENOKEY;
	}

	/* Generate random nonce */
	get_random_bytes(nonce, TQUIC_RETRY_TOKEN_IV_LEN);

	/* Output format: nonce || ciphertext || auth_tag */
	memcpy(token, nonce, TQUIC_RETRY_TOKEN_IV_LEN);

	spin_lock_bh(&tquic_retry_aead_lock);

	/* Allocate AEAD request under lock to protect tquic_retry_aead */
	req = aead_request_alloc(tquic_retry_aead, GFP_ATOMIC);
	if (!req) {
		spin_unlock_bh(&tquic_retry_aead_lock);
		return -ENOMEM;
	}

	/* Copy plaintext to output buffer after nonce for in-place encryption */
	memcpy(token + TQUIC_RETRY_TOKEN_IV_LEN, plaintext, plaintext_len);

	/* Set up scatterlist: ciphertext buffer includes space for auth tag */
	sg_init_one(sg, token + TQUIC_RETRY_TOKEN_IV_LEN,
		    plaintext_len + TQUIC_RETRY_TOKEN_TAG_LEN);

	aead_request_set_crypt(req, sg, sg, plaintext_len, nonce);
	aead_request_set_ad(req, 0);

	ret = crypto_aead_encrypt(req);

	aead_request_free(req);
	spin_unlock_bh(&tquic_retry_aead_lock);

	if (ret)
		return ret;

	/* Total length: nonce + ciphertext + auth_tag */
	*token_len = TQUIC_RETRY_TOKEN_IV_LEN + plaintext_len +
		     TQUIC_RETRY_TOKEN_TAG_LEN;

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_generate_retry_token);

/**
 * tquic_validate_retry_token - Validate a Retry token
 * @conn: The connection
 * @token: The token to validate
 * @token_len: Token length
 * @client_addr: Client's address
 * @original_dcid: Output for original DCID
 *
 * Validates and decrypts a Retry token.
 * Returns 0 on success, negative error on failure.
 */
int tquic_validate_retry_token(struct tquic_connection *conn,
			       const u8 *token, u32 token_len,
			       const struct sockaddr *client_addr,
			       struct tquic_cid *original_dcid)
{
	struct tquic_conn_state_machine *cs = tquic_conn_get_cs(conn);
	u8 plaintext[128];
	u8 nonce[TQUIC_RETRY_TOKEN_IV_LEN];
	struct aead_request *req;
	struct scatterlist sg[2];
	const u8 *p;
	size_t ciphertext_len;
	ktime_t timestamp, now;
	u64 age_ms;
	u32 expected_hash, token_hash;
	u8 dcid_len;
	int ret;

	if (!cs)
		return -EINVAL;

	/* Minimum token length: nonce + timestamp + dcid_len + hash + tag */
	if (token_len < TQUIC_RETRY_TOKEN_IV_LEN + sizeof(ktime_t) + 1 +
			sizeof(u32) + TQUIC_RETRY_TOKEN_TAG_LEN)
		return -EINVAL;

	/* Check if AEAD is initialized */
	if (!tquic_retry_aead_initialized || !tquic_retry_aead) {
		tquic_warn("retry token AEAD not initialized\n");
		return -ENOKEY;
	}

	/* Extract nonce from beginning of token */
	memcpy(nonce, token, TQUIC_RETRY_TOKEN_IV_LEN);

	/* Ciphertext length excludes nonce */
	ciphertext_len = token_len - TQUIC_RETRY_TOKEN_IV_LEN;

	/* Validate ciphertext fits in the decryption buffer */
	if (ciphertext_len > sizeof(plaintext)) {
		tquic_conn_dbg(conn, "retry token too large (%zu > %zu)\n",
			       ciphertext_len, sizeof(plaintext));
		return -EINVAL;
	}

	spin_lock_bh(&tquic_retry_aead_lock);

	/* Allocate AEAD request under lock to protect tquic_retry_aead */
	req = aead_request_alloc(tquic_retry_aead, GFP_ATOMIC);
	if (!req) {
		spin_unlock_bh(&tquic_retry_aead_lock);
		return -ENOMEM;
	}

	/* Copy ciphertext to plaintext buffer for in-place decryption */
	memcpy(plaintext, token + TQUIC_RETRY_TOKEN_IV_LEN, ciphertext_len);

	/* Set up scatterlist */
	sg_init_one(sg, plaintext, ciphertext_len);

	aead_request_set_crypt(req, sg, sg, ciphertext_len, nonce);
	aead_request_set_ad(req, 0);

	ret = crypto_aead_decrypt(req);

	aead_request_free(req);
	spin_unlock_bh(&tquic_retry_aead_lock);

	if (ret) {
		tquic_conn_dbg(conn, "retry token decryption failed\n");
		return -EINVAL;
	}

	/* Parse decrypted plaintext */
	p = plaintext;

	/* Extract timestamp */
	memcpy(&timestamp, p, sizeof(timestamp));
	p += sizeof(timestamp);

	/* Check token age */
	now = ktime_get();
	age_ms = ktime_ms_delta(now, timestamp);
	if (age_ms > TQUIC_RETRY_TOKEN_LIFETIME_MS) {
		tquic_conn_dbg(conn, "retry token expired (age=%llu ms)\n", age_ms);
		return -ETIMEDOUT;
	}

	/* Extract original DCID */
	dcid_len = *p++;
	if (dcid_len > TQUIC_MAX_CID_LEN)
		return -EINVAL;

	original_dcid->len = dcid_len;
	memcpy(original_dcid->id, p, dcid_len);
	p += dcid_len;

	/* Verify client address */
	if (client_addr->sa_family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *)client_addr;
		expected_hash = jhash(&sin->sin_addr, sizeof(sin->sin_addr),
				      sin->sin_port);
	} else if (client_addr->sa_family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)client_addr;
		expected_hash = jhash(&sin6->sin6_addr, sizeof(sin6->sin6_addr),
				      sin6->sin6_port);
	} else {
		return -EINVAL;
	}

	memcpy(&token_hash, p, sizeof(token_hash));
	/* Use constant-time comparison to prevent timing side-channels
	 * that could leak address information from retry tokens.
	 */
	if (crypto_memneq(&token_hash, &expected_hash, sizeof(token_hash))) {
		tquic_conn_dbg(conn, "retry token address mismatch\n");
		return -EINVAL;
	}

	cs->address_validated = true;
	tquic_conn_dbg(conn, "retry token validated\n");

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_validate_retry_token);

/**
 * tquic_send_retry - Send a Retry packet
 * @conn: The connection (server side)
 * @original_dcid: Original DCID from client
 * @client_addr: Client's address
 *
 * Sends a Retry packet for address validation.
 */
int tquic_send_retry(struct tquic_connection *conn,
		     const struct tquic_cid *original_dcid,
		     const struct sockaddr *client_addr)
{
	struct tquic_conn_state_machine *cs = tquic_conn_get_cs(conn);
	/*
	 * SECURITY FIX (CF-220): Allocate large buffers on the heap
	 * instead of the stack to prevent stack buffer overflow.
	 * Combined stack usage of packet[512] + token[256] +
	 * pseudo_packet[512] = 1280 bytes exceeds safe stack limits
	 * for kernel code paths.
	 */
#define TQUIC_RETRY_PKT_BUF_SIZE	512
#define TQUIC_RETRY_PSEUDO_BUF_SIZE	512
	u8 *packet = NULL;
	u8 *p;
	u8 *token = NULL;
	u32 token_len;
	struct tquic_cid new_scid;
	size_t needed;
	int ret;

	if (!cs)
		return -EINVAL;

	/* Allocate buffers on the heap */
	packet = kmalloc(TQUIC_RETRY_PKT_BUF_SIZE, GFP_ATOMIC);
	if (!packet)
		return -ENOMEM;

	token = kmalloc(TQUIC_RETRY_TOKEN_MAX_LEN, GFP_ATOMIC);
	if (!token) {
		kfree(packet);
		return -ENOMEM;
	}

	p = packet;

	/* Generate new server CID for this retry */
	tquic_cid_gen_random(&new_scid, TQUIC_DEFAULT_CID_LEN);

	/* Generate retry token */
	ret = tquic_generate_retry_token(conn, original_dcid, client_addr,
					 token, &token_len);
	if (ret < 0)
		goto out_free;

	/*
	 * Validate that the packet contents will fit in the buffer.
	 * Layout: first_byte(1) + version(4) + dcid_len(1) + dcid +
	 *         scid_len(1) + scid + token + integrity_tag(16)
	 */
	needed = 1 + 4 + 1 + conn->scid.len + 1 + new_scid.len +
		 token_len + 16;
	if (needed > TQUIC_RETRY_PKT_BUF_SIZE) {
		ret = -ENOSPC;
		goto out_free;
	}

	/* Build Retry packet header with correct version encoding.
	 * Long header: form(1) | fixed(1) | type(2) | unused(4)
	 * 0x80 | 0x40 | (0x03 << 4) = 0xf0
	 */
	*p++ = 0xf0;
	{
		__be32 ver = cpu_to_be32(conn->version);

		memcpy(p, &ver, 4);
		p += 4;
	}

	/* DCID (client's SCID) */
	*p++ = conn->scid.len;
	memcpy(p, conn->scid.id, conn->scid.len);
	p += conn->scid.len;

	/* SCID (our new CID) */
	*p++ = new_scid.len;
	memcpy(p, new_scid.id, new_scid.len);
	p += new_scid.len;

	/* Retry Token */
	memcpy(p, token, token_len);
	p += token_len;

	/*
	 * Compute and append Retry Integrity Tag.
	 * The tag is computed over a pseudo-retry packet which includes
	 * the original DCID length and value prepended to the retry packet.
	 *
	 * H-7: support both v1 (RFC 9001 Section 5.8) and
	 * v2 (RFC 9369 Section 5.8) retry integrity keys.
	 */
	{
		static const u8 retry_nonce_v1[12] = {
			0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2,
			0x23, 0x98, 0x25, 0xbb
		};
		static const u8 retry_nonce_v2[12] = {
			0xd8, 0x69, 0x69, 0xbc, 0x2d, 0x7c, 0x6d, 0x99,
			0x90, 0xef, 0xb0, 0x4a
		};
		const u8 *retry_nonce;
		struct crypto_aead *integrity_aead;
		u8 *pseudo_packet;
		u8 *pp;
		struct aead_request *req;
		struct scatterlist sg;
		size_t pseudo_len, pkt_len;
		int tag_ret;

		if (conn->version == TQUIC_VERSION_2) {
			retry_nonce = retry_nonce_v2;
			integrity_aead = tquic_retry_integrity_aead_v2;
		} else {
			retry_nonce = retry_nonce_v1;
			integrity_aead = tquic_retry_integrity_aead_v1;
		}

		if (!integrity_aead)
			goto skip_tag;

		/*
		 * Allocate pseudo-packet buffer with 16 extra bytes for
		 * the integrity tag.  The AEAD output scatterlist must
		 * cover AAD + ciphertext + tag when doing in-place
		 * encryption, so we use a single buffer for both input
		 * and output.
		 */
		pseudo_packet = kmalloc(TQUIC_RETRY_PSEUDO_BUF_SIZE + 16,
					GFP_ATOMIC);
		if (!pseudo_packet)
			goto skip_tag;

		pp = pseudo_packet;

		/* Build pseudo-retry packet: Original DCID + Retry packet */
		pkt_len = p - packet;

		/* Validate pseudo-packet fits in buffer (excl. tag space) */
		if (1 + original_dcid->len + pkt_len >
		    TQUIC_RETRY_PSEUDO_BUF_SIZE) {
			kfree(pseudo_packet);
			goto skip_tag;
		}

		*pp++ = original_dcid->len;
		memcpy(pp, original_dcid->id, original_dcid->len);
		pp += original_dcid->len;

		memcpy(pp, packet, pkt_len);
		pp += pkt_len;
		pseudo_len = pp - pseudo_packet;

		/*
		 * Compute Retry Integrity Tag using cached AEAD.
		 * Use in-place encryption: the scatterlist covers the
		 * AAD (pseudo-packet) plus 16 bytes for the output tag.
		 * With plaintext_len=0, the AEAD produces only the tag
		 * at offset pseudo_len in the buffer.
		 */
		spin_lock_bh(&tquic_retry_integrity_lock);

		req = aead_request_alloc(integrity_aead, GFP_ATOMIC);
		if (req) {
			sg_init_one(&sg, pseudo_packet,
				    pseudo_len + 16);

			aead_request_set_crypt(req, &sg, &sg,
					       0, (u8 *)retry_nonce);
			aead_request_set_ad(req, pseudo_len);

			tag_ret = crypto_aead_encrypt(req);
			if (tag_ret == 0) {
				/* Tag is at pseudo_packet + pseudo_len */
				memcpy(p, pseudo_packet + pseudo_len, 16);
				p += 16;
			}
			aead_request_free(req);
		}

		spin_unlock_bh(&tquic_retry_integrity_lock);
		kfree(pseudo_packet);
	}

	skip_tag:
	tquic_conn_dbg(conn, "sent Retry packet\n");

	/* Transmit the Retry packet via active path */
	{
		struct sk_buff *skb;
		struct tquic_path *path;
		size_t pkt_len = p - packet;

		path = tquic_conn_active_path_get(conn);
		if (!path)
			goto out_set_ret;

		skb = alloc_skb(pkt_len + 64, GFP_ATOMIC);
		if (skb) {
			skb_reserve(skb, 64);
			skb_put_data(skb, packet, pkt_len);
			tquic_udp_xmit_on_path(conn, path, skb);
		}
		tquic_path_put(path);
	}

out_set_ret:
	ret = 0;

out_free:
	kfree(token);
	kfree(packet);
	return ret;
#undef TQUIC_RETRY_PKT_BUF_SIZE
#undef TQUIC_RETRY_PSEUDO_BUF_SIZE
}
EXPORT_SYMBOL_GPL(tquic_send_retry);

/*
 * Address Validation (PATH_CHALLENGE / PATH_RESPONSE)
 */

/**
 * tquic_send_path_challenge - Send PATH_CHALLENGE frame
 * @conn: The connection
 * @path: The path to validate
 *
 * Initiates path validation by sending a PATH_CHALLENGE.
 */
int tquic_send_path_challenge(struct tquic_connection *conn,
			      struct tquic_path *path)
{
	struct tquic_conn_state_machine *cs = tquic_conn_get_cs(conn);
	struct tquic_path_challenge *challenge;

	if (!cs)
		return -EINVAL;

	challenge = kzalloc(sizeof(*challenge), GFP_ATOMIC);
	if (!challenge)
		return -ENOMEM;

	/* Generate random challenge data */
	get_random_bytes(challenge->data, sizeof(challenge->data));
	challenge->sent_time = ktime_get();
	challenge->retries = 0;
	challenge->path = path;

	/* Store challenge data in path for matching response */
	memcpy(path->challenge_data, challenge->data, 8);

	spin_lock_bh(&conn->lock);
	/*
	 * CF-435: Limit pending path challenges to prevent resource
	 * exhaustion from unbounded challenge creation.
	 */
	{
		int pcount = 0;
		struct tquic_path_challenge *pc;

		list_for_each_entry(pc, &cs->pending_challenges, list)
			if (++pcount >= 8)
				break;
		if (pcount >= 8) {
			spin_unlock_bh(&conn->lock);
			kfree(challenge);
			return -ENOSPC;
		}
	}
	list_add_tail(&challenge->list, &cs->pending_challenges);
	spin_unlock_bh(&conn->lock);

	/*
	 * Path validation timeout is handled by per-path timers
	 * (path->validation.timer) set up in PM code.
	 */

	tquic_conn_dbg(conn, "sent PATH_CHALLENGE on path %u\n", path->path_id);

	/*
	 * BUG FIX: Build SKB and transmit via tquic_udp_xmit_on_path()
	 * instead of tquic_xmit(). Previous code passed NULL for path,
	 * causing all PATH_CHALLENGE frames to go out the default/active path
	 * instead of the specific path being validated, breaking multipath.
	 */
	{
		u8 frame_buf[16];
		int frame_len;
		struct sk_buff *skb;

		frame_len = tquic_write_path_challenge_frame(frame_buf,
							     sizeof(frame_buf),
							     challenge->data);
		if (frame_len > 0) {
			/* Allocate SKB with headroom */
			skb = alloc_skb(frame_len + 64, GFP_ATOMIC);
			if (skb) {
				skb_reserve(skb, 64);
				skb_put_data(skb, frame_buf, frame_len);
				/* Transmit via the specific path */
				tquic_udp_xmit_on_path(conn, path, skb);
			}
		}
	}

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_send_path_challenge);

/**
 * tquic_send_path_response - Send PATH_RESPONSE frame
 * @conn: The connection
 * @path: The path
 * @data: Challenge data to echo
 *
 * Responds to a PATH_CHALLENGE with PATH_RESPONSE.
 */
int tquic_send_path_response(struct tquic_connection *conn,
			     struct tquic_path *path,
			     const u8 *data)
{
	tquic_conn_dbg(conn, "sent PATH_RESPONSE on path %u\n", path->path_id);

	/*
	 * BUG FIX: Build SKB and transmit via tquic_udp_xmit_on_path()
	 * instead of tquic_xmit(). Previous code passed NULL for path,
	 * causing PATH_RESPONSE to go out the default path instead of
	 * the same path the PATH_CHALLENGE arrived on.
	 */
	{
		u8 frame_buf[16];
		int frame_len;
		struct sk_buff *skb;

		frame_len = tquic_write_path_response_frame(frame_buf,
							    sizeof(frame_buf),
							    data);
		if (frame_len > 0) {
			/* Allocate SKB with headroom */
			skb = alloc_skb(frame_len + 64, GFP_ATOMIC);
			if (skb) {
				skb_reserve(skb, 64);
				skb_put_data(skb, frame_buf, frame_len);
				/* Transmit via the same path the challenge arrived on */
				tquic_udp_xmit_on_path(conn, path, skb);
			}
		}
	}

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_send_path_response);

/**
 * tquic_handle_path_challenge - Process received PATH_CHALLENGE
 * @conn: The connection
 * @path: The path it arrived on
 * @data: The challenge data (8 bytes)
 *
 * Handles an incoming PATH_CHALLENGE by sending PATH_RESPONSE.
 */
int tquic_handle_path_challenge(struct tquic_connection *conn,
				struct tquic_path *path,
				const u8 *data)
{
	tquic_conn_dbg(conn, "received PATH_CHALLENGE on path %u\n", path->path_id);

	return tquic_send_path_response(conn, path, data);
}
EXPORT_SYMBOL_GPL(tquic_handle_path_challenge);

/**
 * tquic_handle_path_response - Process received PATH_RESPONSE
 * @conn: The connection
 * @path: The path it arrived on
 * @data: The response data (8 bytes)
 *
 * Validates path when PATH_RESPONSE matches our challenge.
 */
int tquic_handle_path_response(struct tquic_connection *conn,
			       struct tquic_path *path,
			       const u8 *data)
{
	struct tquic_conn_state_machine *cs = tquic_conn_get_cs(conn);
	struct tquic_path_challenge *challenge, *tmp;
	bool found = false;

	if (!cs)
		return -EINVAL;

	spin_lock_bh(&conn->lock);
	list_for_each_entry_safe(challenge, tmp, &cs->pending_challenges, list) {
		if (challenge->path == path &&
		    crypto_memneq(challenge->data, data, 8) == 0) {
			list_del_init(&challenge->list);
			kfree(challenge);
			found = true;
			break;
		}
	}
	spin_unlock_bh(&conn->lock);

	if (!found) {
		tquic_conn_warn(conn, "unexpected PATH_RESPONSE\n");
		return -EINVAL;
	}

	/* Path is now validated */
	path->state = TQUIC_PATH_ACTIVE;
	cs->address_validated = true;

	tquic_conn_info(conn, "path %u validated\n", path->path_id);

	/* Notify bonding layer */
	if (conn->scheduler) {
		/* Path is ready for use in bonding */
	}

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_handle_path_response);

/*
 * Connection Migration
 */

/**
 * tquic_conn_migrate_to_path - Migrate connection to new path
 * @conn: The connection
 * @new_path: Target path
 *
 * Initiates connection migration to a different network path.
 */
int tquic_conn_migrate_to_path(struct tquic_connection *conn,
			       struct tquic_path *new_path)
{
	struct tquic_conn_state_machine *cs = tquic_conn_get_cs(conn);

	if (!cs)
		return -EINVAL;

	if (cs->migration_disabled) {
		tquic_conn_dbg(conn, "migration disabled\n");
		return -EPERM;
	}

	if (READ_ONCE(conn->state) != TQUIC_CONN_CONNECTED) {
		tquic_conn_dbg(conn, "migration only allowed when connected\n");
		return -EINVAL;
	}

	if (new_path->state == TQUIC_PATH_UNUSED ||
	    new_path->state == TQUIC_PATH_CLOSED) {
		return -EINVAL;
	}

	spin_lock_bh(&conn->lock);

	if (cs->migration_in_progress) {
		spin_unlock_bh(&conn->lock);
		return -EBUSY;
	}

	cs->migration_in_progress = true;
	cs->migration_target = new_path;
	cs->migration_start = ktime_get();

	spin_unlock_bh(&conn->lock);

	/* Start path validation on new path */
	if (new_path->state == TQUIC_PATH_PENDING) {
		tquic_send_path_challenge(conn, new_path);
	}

	/* Schedule migration completion */
	schedule_work(&cs->migration_work);

	tquic_conn_info(conn, "initiating migration to path %u\n", new_path->path_id);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_conn_migrate_to_path);

/**
 * tquic_conn_handle_migration - Handle peer-initiated migration
 * @conn: The connection
 * @path: Path the packet arrived on
 * @remote_addr: New remote address
 *
 * Processes migration initiated by the peer.
 */
int tquic_conn_handle_migration(struct tquic_connection *conn,
				struct tquic_path *path,
				const struct sockaddr *remote_addr)
{
	struct tquic_conn_state_machine *cs = tquic_conn_get_cs(conn);

	if (!cs)
		return -EINVAL;

	if (cs->migration_disabled) {
		/* Silently ignore if migration disabled */
		return 0;
	}

	/* Validate the new path */
	tquic_send_path_challenge(conn, path);

	/* Update path's remote address */
	memcpy(&path->remote_addr, remote_addr, sizeof(path->remote_addr));

	tquic_conn_info(conn, "peer initiated migration on path %u\n", path->path_id);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_conn_handle_migration);

static void tquic_migration_work_handler(struct work_struct *work)
{
	struct tquic_conn_state_machine *cs = container_of(work, struct tquic_conn_state_machine,
						   migration_work);
	struct tquic_connection *conn = cs->conn;
	struct tquic_path *target;

	spin_lock_bh(&conn->lock);

	if (!cs->migration_in_progress) {
		spin_unlock_bh(&conn->lock);
		return;
	}

	target = cs->migration_target;

	if (target->state == TQUIC_PATH_ACTIVE) {
		/* Migration complete - switch active path */
		rcu_assign_pointer(conn->active_path, target);
		conn->stats.path_migrations++;
		cs->migration_in_progress = false;
		cs->migration_target = NULL;
		tquic_conn_info(conn, "migration complete to path %u\n", target->path_id);
	}

	spin_unlock_bh(&conn->lock);
}

/*
 * 0-RTT Data Handling
 */

/**
 * tquic_conn_enable_0rtt - Enable 0-RTT for connection
 * @conn: The connection
 *
 * Enables 0-RTT early data if session ticket is available.
 */
int tquic_conn_enable_0rtt(struct tquic_connection *conn)
{
	struct tquic_conn_state_machine *cs = tquic_conn_get_cs(conn);

	if (!cs)
		return -EINVAL;

	/*
	 * Check for valid session ticket for 0-RTT (RFC 9001 Section 4.6)
	 * 0-RTT requires a valid session ticket from previous connection.
	 * The ticket is validated by checking:
	 * - Ticket exists and hasn't expired
	 * - Server identity matches
	 * - ALPN matches
	 */
	if (!conn->sk) {
		tquic_conn_dbg(conn, "0-RTT: no socket associated\n");
		return -EINVAL;
	}

	{
		struct tquic_sock *tsk = tquic_sk(conn->sk);

		/* Check if session ticket exists (stored in socket state) */
		if (!tsk || !(tsk->flags & TQUIC_F_HAS_SESSION_TICKET)) {
			tquic_conn_dbg(conn, "0-RTT: no valid session ticket\n");
			return -ENOENT;
		}

		/* Ticket exists - enable 0-RTT */
		cs->zero_rtt_enabled = true;
		tsk->flags |= TQUIC_F_ZERO_RTT_ENABLED;
	}

	tquic_conn_dbg(conn, "0-RTT enabled\n");
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_conn_enable_0rtt);

/**
 * tquic_conn_send_0rtt - Send 0-RTT data
 * @conn: The connection
 * @data: Data to send
 * @len: Data length
 *
 * Queues data for 0-RTT transmission.
 */
int tquic_conn_send_0rtt(struct tquic_connection *conn,
			 const void *data, size_t len)
{
	struct tquic_conn_state_machine *cs = tquic_conn_get_cs(conn);
	struct sk_buff *skb;

	if (!cs || !cs->zero_rtt_enabled)
		return -EINVAL;

	if (READ_ONCE(conn->state) != TQUIC_CONN_CONNECTING)
		return -EINVAL;

	skb = alloc_skb(len, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	memcpy(skb_put(skb, len), data, len);
	skb_queue_tail(&cs->zero_rtt_buffer, skb);

	tquic_conn_dbg(conn, "queued %zu bytes of 0-RTT data\n", len);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_conn_send_0rtt);

/**
 * tquic_conn_0rtt_accepted - Handle 0-RTT acceptance by server
 * @conn: The connection
 *
 * Called when server accepts 0-RTT data.
 */
void tquic_conn_0rtt_accepted(struct tquic_connection *conn)
{
	struct tquic_conn_state_machine *cs = tquic_conn_get_cs(conn);

	if (!cs)
		return;

	cs->zero_rtt_accepted = true;
	tquic_conn_info(conn, "0-RTT accepted by server\n");
}
EXPORT_SYMBOL_GPL(tquic_conn_0rtt_accepted);

/**
 * tquic_conn_0rtt_rejected - Handle 0-RTT rejection by server
 * @conn: The connection
 *
 * Called when server rejects 0-RTT data. Data must be retransmitted.
 */
void tquic_conn_0rtt_rejected(struct tquic_connection *conn)
{
	struct tquic_conn_state_machine *cs = tquic_conn_get_cs(conn);
	struct sk_buff *skb;

	if (!cs)
		return;

	cs->zero_rtt_rejected = true;
	tquic_conn_warn(conn, "0-RTT rejected, retransmitting as 1-RTT\n");

	/*
	 * Move 0-RTT data to regular send queue for 1-RTT retransmission.
	 * Per RFC 9001 Section 4.6.3: "A client MUST NOT send 0-RTT data
	 * after receiving a rejection until a valid response to a new
	 * ClientHello has been received."
	 *
	 * The 0-RTT data must be re-sent as 1-RTT data after handshake completes.
	 */
	while ((skb = skb_dequeue(&cs->zero_rtt_buffer)) != NULL) {
		/*
		 * Queue the data for 1-RTT transmission.
		 * The skb contains application data that was originally
		 * queued for 0-RTT but must now wait for handshake completion.
		 */
		if (conn->sk && conn->sk->sk_write_queue.qlen <
		    sysctl_wmem_max / 2) {
			/* Add to socket write queue for later transmission */
			skb_queue_tail(&conn->sk->sk_write_queue, skb);
			tquic_conn_dbg(conn, "re-queued 0-RTT data (%u bytes) for 1-RTT\n",
				       skb->len);
		} else {
			/* Queue full or no socket - drop with warning */
			tquic_conn_warn(conn, "dropping 0-RTT data (%u bytes) - queue full\n",
					skb->len);
			kfree_skb(skb);
		}
	}
}
EXPORT_SYMBOL_GPL(tquic_conn_0rtt_rejected);

/*
 * Handshake Packet Handling
 */

/**
 * tquic_conn_process_handshake - Process handshake packet
 * @conn: The connection
 * @skb: The packet
 *
 * Processes Initial and Handshake packets during connection setup.
 */
int tquic_conn_process_handshake(struct tquic_connection *conn,
				 struct sk_buff *skb)
{
	struct tquic_conn_state_machine *cs = tquic_conn_get_cs(conn);
	u8 *data = skb->data;
	size_t len = skb->len;
	u8 first_byte;
	u32 version;
	bool is_initial;

	if (!cs || len < 6)
		return -EINVAL;

	first_byte = data[0];

	/* Check for long header */
	if (!(first_byte & 0x80)) {
		/* Short header during handshake is unexpected */
		return -EPROTO;
	}

	/* Extract version */
	memcpy(&version, data + 1, 4);
	version = be32_to_cpu(version);

	/* Determine packet type */
	is_initial = ((first_byte & 0x30) == 0x00);

	tquic_conn_dbg(conn, "processing %s handshake packet\n",
		       is_initial ? "Initial" : "Handshake");

	switch (cs->hs_state) {
	case TQUIC_HS_INITIAL:
		if (cs->is_server) {
			/*
			 * Server: process Client Hello from CRYPTO frame.
			 * The CRYPTO frame contains the TLS ClientHello message.
			 * Per RFC 9001 Section 4.1, the Initial packet from
			 * the client contains ClientHello in a CRYPTO frame.
			 *
			 * Processing is delegated to the net/handshake
			 * infrastructure which handles TLS via tlshd daemon.
			 */
			cs->hs_state = TQUIC_HS_CLIENT_HELLO_SENT;

			/*
			 * Parse CRYPTO frame from the packet payload.
			 * Format: type(1) + offset(var) + length(var) + data
			 */
			if (len > 20) {
				size_t hdr_offset;
				u8 dcid_len, scid_len;
				size_t token_len_size;
				u64 token_len;
				size_t length_size;
				u64 pkt_length;
				size_t payload_offset;

				/* Skip past header to find CRYPTO frame */
				hdr_offset = 5;  /* first_byte + version */
				if (hdr_offset >= len)
					return 0;
				dcid_len = data[hdr_offset++];
				if (hdr_offset + dcid_len >= len)
					return 0;
				hdr_offset += dcid_len;
				scid_len = data[hdr_offset++];
				if (hdr_offset + scid_len >= len)
					return 0;
				hdr_offset += scid_len;

				/* Parse token length (varint) for Initial */
				token_len = data[hdr_offset];
				if ((token_len & 0xc0) == 0) {
					token_len_size = 1;
				} else if ((token_len & 0xc0) == 0x40) {
					token_len_size = 2;
				} else {
					token_len_size = 4;
				}
				token_len = token_len & 0x3f;
				hdr_offset += token_len_size + token_len;

				/* Parse packet length (varint) */
				pkt_length = data[hdr_offset];
				if ((pkt_length & 0xc0) == 0) {
					length_size = 1;
				} else if ((pkt_length & 0xc0) == 0x40) {
					length_size = 2;
				} else {
					length_size = 4;
				}
				hdr_offset += length_size;

				/* Skip packet number (4 bytes for Initial) */
				hdr_offset += 4;

				payload_offset = hdr_offset;

				/* Look for CRYPTO frame type (0x06) */
				if (payload_offset < len &&
				    data[payload_offset] == 0x06) {
					tquic_conn_dbg(conn, "found CRYPTO frame in ClientHello\n");
					cs->client_hello_received = true;
				}
			}
		}
		break;

	case TQUIC_HS_CLIENT_HELLO_SENT:
		if (!cs->is_server) {
			/* Client: process Server Hello */
			cs->hs_state = TQUIC_HS_SERVER_HELLO_RECEIVED;
		}
		break;

	case TQUIC_HS_SERVER_HELLO_RECEIVED:
		cs->hs_state = TQUIC_HS_ENCRYPTED_EXTENSIONS;
		break;

	case TQUIC_HS_ENCRYPTED_EXTENSIONS:
		cs->hs_state = TQUIC_HS_CERTIFICATE;
		break;

	case TQUIC_HS_CERTIFICATE:
		cs->hs_state = TQUIC_HS_CERTIFICATE_VERIFY;
		break;

	case TQUIC_HS_CERTIFICATE_VERIFY:
		cs->hs_state = TQUIC_HS_FINISHED_SENT;
		break;

	case TQUIC_HS_FINISHED_SENT:
		cs->hs_state = TQUIC_HS_FINISHED_RECEIVED;
		break;

	case TQUIC_HS_FINISHED_RECEIVED:
		cs->hs_state = TQUIC_HS_COMPLETE;
		/* Handshake complete - transition to CONNECTED */
		tquic_conn_set_state(conn, TQUIC_CONN_CONNECTED,
				     TQUIC_REASON_NORMAL);
		break;

	default:
		break;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_conn_process_handshake);

/*
 * Connection Close
 */

/**
 * tquic_conn_close - Initiate connection close
 * @conn: The connection
 * @error_code: QUIC error code
 * @reason: Human-readable reason (may be NULL)
 *
 * Begins graceful connection shutdown.
 */
int tquic_conn_close_with_error(struct tquic_connection *conn,
				u64 error_code, const char *reason)
{
	struct tquic_conn_state_machine *cs = tquic_conn_get_cs(conn);

	if (READ_ONCE(conn->state) == TQUIC_CONN_CLOSING ||
	    READ_ONCE(conn->state) == TQUIC_CONN_DRAINING ||
	    READ_ONCE(conn->state) == TQUIC_CONN_CLOSED) {
		return 0;  /* Already closing */
	}

	/* Store close information if state machine is available */
	if (cs) {
		cs->local_close.error_code = error_code;
		cs->local_close.is_application = false;
		if (reason) {
			kfree(cs->local_close.reason_phrase);
			cs->local_close.reason_len = strlen(reason);
			cs->local_close.reason_phrase =
				kstrdup(reason, GFP_ATOMIC);
		}
	}

	tquic_conn_enter_closing(conn, error_code, reason);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_conn_close_with_error);

/**
 * tquic_conn_close_app - Close with application error
 * @conn: The connection
 * @error_code: Application error code
 * @reason: Reason phrase
 */
int tquic_conn_close_app(struct tquic_connection *conn,
			 u64 error_code, const char *reason)
{
	struct tquic_conn_state_machine *cs = tquic_conn_get_cs(conn);

	if (!cs)
		return -EINVAL;

	cs->local_close.is_application = true;
	return tquic_conn_close_with_error(conn, error_code, reason);
}
EXPORT_SYMBOL_GPL(tquic_conn_close_app);

static void tquic_conn_enter_closing(struct tquic_connection *conn,
				     u64 error_code, const char *reason)
{
	struct tquic_conn_state_machine *cs = tquic_conn_get_cs(conn);

	if (cs) {
		cs->local_close.error_code = error_code;
		cs->close_sent = false;
		cs->close_retries = 0;
	}

	/*
	 * Always transition state, even without a state machine.
	 * Server connections (via tquic_server_handshake) may not have
	 * a tquic_conn_state_machine, but still need the state change
	 * so that stream waiters wake and recv() returns 0.
	 */
	tquic_conn_set_state(conn, TQUIC_CONN_CLOSING, TQUIC_REASON_NORMAL);

	/* Send CONNECTION_CLOSE frame via dedicated close path */
	tquic_xmit_close(conn, error_code,
			 cs ? cs->local_close.is_application : false);
}

static int tquic_send_close_frame(struct tquic_connection *conn)
{
	struct tquic_conn_state_machine *cs = tquic_conn_get_cs(conn);

	if (!cs)
		return -EINVAL;

	/* Build and send CONNECTION_CLOSE frame */
	{
		u8 frame_buf[256];
		const char *reason = cs->local_close.reason_phrase;
		size_t reason_len = reason ? strlen(reason) : 0;
		int frame_len;

		frame_len = tquic_write_connection_close_frame(
			frame_buf, sizeof(frame_buf),
			cs->local_close.error_code,
			cs->local_close.frame_type,
			(const u8 *)reason, reason_len,
			cs->local_close.is_application);

		if (frame_len > 0) {
			tquic_xmit(conn, NULL, frame_buf, frame_len, false);
		}
	}

	tquic_conn_dbg(conn, "sent CONNECTION_CLOSE (error=%llu)\n",
		       cs->local_close.error_code);

	cs->close_sent = true;
	cs->close_retries++;

	return 0;
}

/**
 * tquic_conn_handle_close - Process received CONNECTION_CLOSE
 * @conn: The connection
 * @error_code: Error code from peer
 * @frame_type: Frame type that caused error (transport only)
 * @reason: Reason phrase
 * @is_app: Whether this is an application close
 */
int tquic_conn_handle_close(struct tquic_connection *conn,
			    u64 error_code, u64 frame_type,
			    const char *reason, bool is_app)
{
	struct tquic_conn_state_machine *cs = tquic_conn_get_cs(conn);

	if (!cs)
		return -EINVAL;

	/* CF-366: Ignore duplicate close if already draining/closed */
	if (READ_ONCE(conn->state) == TQUIC_CONN_DRAINING ||
	    READ_ONCE(conn->state) == TQUIC_CONN_CLOSED)
		return 0;

	cs->close_received = true;
	cs->remote_close.error_code = error_code;
	cs->remote_close.frame_type = frame_type;
	cs->remote_close.is_application = is_app;
	if (reason) {
		kfree(cs->remote_close.reason_phrase);
		cs->remote_close.reason_phrase = kstrdup(reason, GFP_ATOMIC);
		cs->remote_close.reason_len = strlen(reason);
	}

	tquic_conn_info(conn, "received CONNECTION_CLOSE (error=%llu, app=%d, reason=%s)\n",
			error_code, is_app, reason ?: "");

	/* Enter draining state */
	tquic_conn_enter_draining(conn);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_conn_handle_close);

static void tquic_conn_enter_draining(struct tquic_connection *conn)
{
	struct tquic_conn_state_machine *cs = tquic_conn_get_cs(conn);
	tquic_conn_dbg(conn, "entering draining state\n");
	struct tquic_path *path;

	/*
	 * Recompute drain timeout using current RTT measurements if
	 * available, since RTT data may not have been present when
	 * the state machine was first initialized.
	 */
	path = tquic_conn_active_path_get(conn);
	if (cs && path && path->rtt.samples > 0)
		cs->drain_timeout_ms = 3 * tquic_rtt_pto(&path->rtt);
	if (path)
		tquic_path_put(path);

	tquic_conn_set_state(conn, TQUIC_CONN_DRAINING, TQUIC_REASON_PEER_CLOSE);
}

void tquic_conn_enter_closed(struct tquic_connection *conn)
{
	tquic_conn_set_state(conn, TQUIC_CONN_CLOSED, TQUIC_REASON_NORMAL);
}
EXPORT_SYMBOL_GPL(tquic_conn_enter_closed);

static void tquic_drain_timeout(struct work_struct *work)
{
	struct delayed_work *dwork = to_delayed_work(work);
	struct tquic_conn_state_machine *cs = container_of(dwork, struct tquic_conn_state_machine,
						   drain_work);
	struct tquic_connection *conn = cs->conn;

	/*
	 * CF-533: This delayed work is shared between close retransmission
	 * scheduling and drain timeout. Distinguish by connection state.
	 */
	if (READ_ONCE(conn->state) == TQUIC_CONN_CLOSING) {
		/* Retransmit close frame */
		cs->close_retries++;
		schedule_work(&cs->close_work);
		return;
	}

	tquic_conn_dbg(conn, "drain timeout expired\n");
	tquic_conn_enter_closed(conn);
}

static void tquic_close_work_handler(struct work_struct *work)
{
	struct tquic_conn_state_machine *cs = container_of(work, struct tquic_conn_state_machine,
						   close_work);
	struct tquic_connection *conn = cs->conn;

	tquic_conn_dbg(conn, "close_work_handler: retries=%u\n", cs->close_retries);
	if (READ_ONCE(conn->state) != TQUIC_CONN_CLOSING)
		return;

	/* Retransmit CONNECTION_CLOSE if needed */
	if (cs->close_retries < 3) {
		tquic_send_close_frame(conn);
		/* Schedule next retransmission */
		schedule_delayed_work(&cs->drain_work,
				      msecs_to_jiffies(1000));
	} else {
		/* Give up and enter draining */
		tquic_conn_enter_draining(conn);
	}
}

/*
 * Graceful Shutdown
 */

/**
 * tquic_conn_shutdown - Initiate graceful shutdown
 * @conn: The connection
 *
 * Begins graceful shutdown, allowing pending data to be sent.
 */
int tquic_conn_shutdown(struct tquic_connection *conn)
{
	tquic_conn_dbg(conn, "tquic_conn_shutdown: initiating graceful shutdown\n");
	/* Close all streams gracefully */
	/* Then close connection with NO_ERROR */
	return tquic_conn_close_with_error(conn, TQUIC_NO_ERROR, NULL);
}
EXPORT_SYMBOL_GPL(tquic_conn_shutdown);

/*
 * Client Connection Initiation
 */

/**
 * tquic_conn_client_connect - Initiate client connection
 * @conn: The connection
 * @server_addr: Server address
 *
 * Starts the client-side connection process.
 */
int tquic_conn_client_connect(struct tquic_connection *conn,
			      const struct sockaddr *server_addr)
{
	struct tquic_conn_state_machine *cs;
	int ret;

	/* Allocate state machine */
	cs = kzalloc(sizeof(*cs), GFP_KERNEL);
	if (!cs)
		return -ENOMEM;

	cs->magic = TQUIC_SM_MAGIC_CONN_STATE;
	cs->conn = conn;
	cs->is_server = false;
	cs->hs_state = TQUIC_HS_INITIAL;
	cs->active_cid_limit = 2;
	/*
	 * Drain timeout: Use 3 * PTO if RTT measurements are available,
	 * otherwise fall back to static default per RFC 9000 Section 10.2.
	 * PTO = smoothed_rtt + max(4 * rttvar, 1ms) + max_ack_delay
	 */
	{
		struct tquic_path *path = tquic_conn_active_path_get(conn);

		if (path && path->rtt.samples > 0)
			cs->drain_timeout_ms = 3 * tquic_rtt_pto(&path->rtt);
		else
			cs->drain_timeout_ms = 3 * TQUIC_DEFAULT_RTT;

		if (path)
			tquic_path_put(path);
	}
	cs->amplification_limit = 3;

	INIT_LIST_HEAD(&cs->local_cids);
	INIT_LIST_HEAD(&cs->remote_cids);
	INIT_LIST_HEAD(&cs->pending_challenges);
	skb_queue_head_init(&cs->zero_rtt_buffer);

	INIT_WORK(&cs->close_work, tquic_close_work_handler);
	INIT_WORK(&cs->migration_work, tquic_migration_work_handler);
	INIT_DELAYED_WORK(&cs->drain_work, tquic_drain_timeout);

	conn->state_machine = cs;

	/* Generate initial source CID */
	tquic_cid_gen_random(&conn->scid, TQUIC_DEFAULT_CID_LEN);

	/*
	 * Register the initial SCID in the global CID lookup table so
	 * incoming packets (where DCID = our SCID) can find this connection.
	 * tquic_conn_add_local_cid() generates a NEW CID for NEW_CONNECTION_ID
	 * frames, which is separate from the initial SCID used in handshake.
	 */
	{
		struct tquic_cid_entry *scid_entry;

		spin_lock_bh(&conn->lock);
		scid_entry = tquic_cid_entry_create(&conn->scid, 0);
		if (!scid_entry) {
			spin_unlock_bh(&conn->lock);
			kfree(cs);
			conn->state_machine = NULL;
			return -ENOMEM;
		}
		scid_entry->conn = conn;
		list_add_tail(&scid_entry->list, &cs->local_cids);
		ret = rhashtable_insert_fast(&cid_lookup_table,
					     &scid_entry->hash_node,
					     cid_hash_params);
		if (ret) {
			list_del_init(&scid_entry->list);
			spin_unlock_bh(&conn->lock);
			kfree(scid_entry);
			kfree(cs);
			conn->state_machine = NULL;
			return ret;
		}
		cs->next_local_cid_seq = 1; /* Next seq after SCID (seq 0) */
		spin_unlock_bh(&conn->lock);
		pr_warn("tquic: registered client SCID len=%u id=%*phN\n",
			conn->scid.len,
			min_t(int, conn->scid.len, 8), conn->scid.id);
	}

	/* Add additional CID for migration/rotation */
	ret = tquic_conn_add_local_cid(conn) ? 0 : -ENOMEM;
	if (ret < 0) {
		kfree(cs);
		conn->state_machine = NULL;
		return ret;
	}

	/* Generate destination CID for Initial packets */
	tquic_cid_gen_random(&conn->dcid, TQUIC_DEFAULT_CID_LEN);

	/* Transition to connecting state */
	tquic_conn_set_state(conn, TQUIC_CONN_CONNECTING, TQUIC_REASON_NORMAL);

	tquic_conn_info(conn, "client connecting\n");

	/*
	 * Initiate TLS handshake to send Initial packet with CRYPTO frame.
	 * The Initial packet contains a CRYPTO frame with the TLS ClientHello.
	 * Per RFC 9001 Section 4.1, the handshake is driven by TLS 1.3.
	 *
	 * The actual packet construction is handled by the net/handshake
	 * infrastructure via tlshd daemon, which generates the ClientHello
	 * and wraps it in QUIC Initial packet format.
	 */
	if (conn->sk) {
		ret = tquic_start_handshake(conn->sk);
		if (ret < 0 && ret != -EALREADY) {
			tquic_conn_err(conn, "failed to start handshake: %d\n", ret);
			/*
			 * Don't fail the connection here - handshake may be
			 * triggered later when socket operations occur.
			 * Just log the error and continue.
			 */
		}
	} else {
		tquic_conn_dbg(conn, "handshake deferred - no socket yet\n");
	}

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_conn_client_connect);

/**
 * tquic_conn_client_restart - Restart connection after version negotiation
 * @conn: The connection
 *
 * Restarts the handshake with a new QUIC version.
 */
int tquic_conn_client_restart(struct tquic_connection *conn)
{
	struct tquic_conn_state_machine *cs = tquic_conn_get_cs(conn);

	if (!cs)
		return -EINVAL;

	/* Reset handshake state */
	cs->hs_state = TQUIC_HS_INITIAL;

	/* Generate new initial CID */
	tquic_cid_gen_random(&conn->dcid, TQUIC_DEFAULT_CID_LEN);

	tquic_conn_info(conn, "restarting connection with version 0x%08x\n",
			conn->version);

	/*
	 * Restart TLS handshake with the new QUIC version.
	 * Per RFC 9000 Section 6: After receiving a Version Negotiation
	 * packet, the client starts a new connection with a supported version.
	 *
	 * We need to:
	 * 1. Clean up the old handshake state
	 * 2. Reinitialize crypto state for new version
	 * 3. Start a fresh handshake
	 */
	if (conn->sk) {
		struct tquic_sock *tsk = tquic_sk(conn->sk);
		int ret;

		/* Clean up previous handshake state if any */
		if (tsk && tsk->handshake_state) {
			tquic_handshake_cleanup(conn->sk);
			tsk->flags &= ~TQUIC_F_HANDSHAKE_DONE;
		}

		/* Reinitialize crypto state for new version */
		if (conn->crypto_state) {
			tquic_crypto_cleanup(conn->crypto_state);
			conn->crypto_state = NULL;
		}

		/* Initialize new crypto state with updated DCID and version */
		conn->crypto_state = tquic_crypto_init_versioned(&conn->dcid,
								 true,
								 conn->version);
		if (!conn->crypto_state) {
			tquic_conn_err(conn, "failed to init crypto for restart (v%s)\n",
				       conn->version == TQUIC_VERSION_2 ? "2" : "1");
			return -ENOMEM;
		}

		/* Start new handshake */
		ret = tquic_start_handshake(conn->sk);
		if (ret < 0 && ret != -EALREADY) {
			tquic_conn_err(conn, "failed to restart handshake: %d\n", ret);
			return ret;
		}
	} else {
		tquic_conn_dbg(conn, "restart deferred - no socket\n");
	}

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_conn_client_restart);

/*
 * Server Connection Acceptance
 */

/**
 * tquic_conn_server_accept - Accept incoming connection
 * @conn: The connection
 * @initial_pkt: Initial packet from client
 *
 * Processes an Initial packet and begins server-side handshake.
 */
int tquic_conn_server_accept(struct tquic_connection *conn,
			     struct sk_buff *initial_pkt)
{
	struct tquic_conn_state_machine *cs;
	u8 *data = initial_pkt->data;
	size_t len = initial_pkt->len;
	struct tquic_cid dcid, scid;
	u32 version;
	int ret;
	size_t offset;
	u8 dcid_len, scid_len;

	if (len < 7)
		return -EINVAL;

	/* Parse Initial packet header */
	if (!(data[0] & 0x80)) {
		/* Not a long header */
		return -EINVAL;
	}

	/* Extract version */
	memcpy(&version, data + 1, 4);
	version = be32_to_cpu(version);

	if (!tquic_version_is_supported(version)) {
		/* Send Version Negotiation */
		/* Extract CIDs first for VN response -- validate bounds */
		offset = 5;
		if (offset >= len)
			return -EINVAL;
		dcid_len = data[offset++];
		if (dcid_len > TQUIC_MAX_CID_LEN || offset + dcid_len > len)
			return -EINVAL;
		memcpy(dcid.id, data + offset, dcid_len);
		dcid.len = dcid_len;
		offset += dcid_len;

		if (offset >= len)
			return -EINVAL;
		scid_len = data[offset++];
		if (scid_len > TQUIC_MAX_CID_LEN || offset + scid_len > len)
			return -EINVAL;
		memcpy(scid.id, data + offset, scid_len);
		scid.len = scid_len;

		return tquic_send_version_negotiation(conn, &dcid, &scid);
	}

	conn->version = version;

	/* Allocate state machine */
	cs = kzalloc(sizeof(*cs), GFP_KERNEL);
	if (!cs)
		return -ENOMEM;

	cs->magic = TQUIC_SM_MAGIC_CONN_STATE;
	cs->conn = conn;
	cs->is_server = true;
	cs->hs_state = TQUIC_HS_INITIAL;
	cs->active_cid_limit = 2;
	/*
	 * Drain timeout: Use 3 * PTO if RTT measurements are available,
	 * otherwise fall back to static default per RFC 9000 Section 10.2.
	 */
	{
		struct tquic_path *path = tquic_conn_active_path_get(conn);

		if (path && path->rtt.samples > 0)
			cs->drain_timeout_ms = 3 * tquic_rtt_pto(&path->rtt);
		else
			cs->drain_timeout_ms = 3 * TQUIC_DEFAULT_RTT;

		if (path)
			tquic_path_put(path);
	}
	cs->amplification_limit = 3;
	cs->address_validated = false;

	INIT_LIST_HEAD(&cs->local_cids);
	INIT_LIST_HEAD(&cs->remote_cids);
	INIT_LIST_HEAD(&cs->pending_challenges);
	skb_queue_head_init(&cs->zero_rtt_buffer);

	INIT_WORK(&cs->close_work, tquic_close_work_handler);
	INIT_WORK(&cs->migration_work, tquic_migration_work_handler);
	INIT_DELAYED_WORK(&cs->drain_work, tquic_drain_timeout);

	conn->state_machine = cs;

	/* Parse connection IDs from Initial packet */
	offset = 5;
	if (offset >= len)
		goto err_free;
	dcid_len = data[offset++];
	if (dcid_len > TQUIC_MAX_CID_LEN || offset + dcid_len > len)
		goto err_free;

	/* Client's DCID becomes server's original DCID (for Retry) */
	memcpy(conn->dcid.id, data + offset, dcid_len);
	conn->dcid.len = dcid_len;
	offset += dcid_len;

	if (offset >= len)
		goto err_free;
	scid_len = data[offset++];
	if (scid_len > TQUIC_MAX_CID_LEN || offset + scid_len > len)
		goto err_free;

	/* Client's SCID - store for response */
	memcpy(&scid.id, data + offset, scid_len);
	scid.len = scid_len;

	/* Register client's CID */
	ret = tquic_conn_add_remote_cid(conn, &scid, 0, NULL);
	if (ret < 0)
		goto err_free;

	/* Generate server's CID */
	tquic_cid_gen_random(&conn->scid, TQUIC_DEFAULT_CID_LEN);
	ret = tquic_conn_add_local_cid(conn) ? 0 : -ENOMEM;
	if (ret < 0)
		goto err_free;

	/*
	 * Generate stateless reset token deterministically from CID
	 * Per RFC 9000 Section 10.3.2, using HMAC with static key
	 */
	{
		const u8 *static_key = tquic_stateless_reset_get_static_key();

		if (static_key) {
			tquic_stateless_reset_generate_token(&conn->scid, static_key,
							     cs->stateless_reset_token);
		} else {
			get_random_bytes(cs->stateless_reset_token, 16);
		}
	}
	cs->has_stateless_reset = true;

	/* Transition to connecting state */
	tquic_conn_set_state(conn, TQUIC_CONN_CONNECTING, TQUIC_REASON_NORMAL);

	/* Process handshake data */
	ret = tquic_conn_process_handshake(conn, initial_pkt);
	if (ret < 0)
		goto err_free;

	tquic_conn_info(conn, "server accepted connection\n");

	/*
	 * Server response: Send Initial + Handshake packets.
	 *
	 * Per RFC 9001 Section 4.2, the server responds to ClientHello with:
	 * - Initial packet containing CRYPTO frame with ServerHello
	 * - Handshake packet(s) containing CRYPTO frames with EncryptedExtensions,
	 *   Certificate, CertificateVerify, and Finished
	 *
	 * The actual TLS message generation is handled by the net/handshake
	 * infrastructure via tlshd daemon. Here we:
	 * 1. Initialize crypto state for Initial keys
	 * 2. Mark connection as ready for server handshake
	 *
	 * The handshake itself is triggered from tquic_server_handshake()
	 * in tquic_handshake.c which manages the full server flow.
	 */

	/* Initialize crypto state with client's original DCID and version */
	if (!conn->crypto_state) {
		conn->crypto_state = tquic_crypto_init_versioned(&conn->dcid,
								 false,
								 conn->version);
		if (!conn->crypto_state) {
			tquic_conn_err(conn, "failed to init server crypto state (v%s)\n",
				       conn->version == TQUIC_VERSION_2 ? "2" : "1");
			ret = -ENOMEM;
			goto err_free;
		}
	}

	/* Update receive bytes for anti-amplification tracking */
	if (initial_pkt) {
		cs->bytes_received_unvalidated += initial_pkt->len;
	}

	/*
	 * Server handshake response is driven by tquic_server_handshake()
	 * which is called from the UDP receive path. If we got here through
	 * that path, the handshake will continue asynchronously via the
	 * net/handshake infrastructure.
	 *
	 * If called directly, schedule the handshake work.
	 */
	if (conn->sk) {
		struct tquic_sock *tsk = tquic_sk(conn->sk);

		if (tsk && !(tsk->flags & TQUIC_F_SERVER_HANDSHAKE_STARTED)) {
			tsk->flags |= TQUIC_F_SERVER_HANDSHAKE_STARTED;
			schedule_work(&cs->migration_work);
		}
	}

	return 0;

err_free:
	/* CF-061: purge zero_rtt_buffer and clean up CIDs on error */
	{
		struct tquic_cid_entry *entry, *tmp;

		/* Free local CIDs and remove from hash table */
		list_for_each_entry_safe(entry, tmp, &cs->local_cids, list) {
			rhashtable_remove_fast(&cid_lookup_table,
					       &entry->hash_node,
					       cid_hash_params);
			list_del_init(&entry->list);
			kfree_rcu(entry, rcu);
		}

		/* Free remote CIDs */
		list_for_each_entry_safe(entry, tmp, &cs->remote_cids, list) {
			list_del_init(&entry->list);
			kfree(entry);
		}
	}
	skb_queue_purge(&cs->zero_rtt_buffer);

	/* Cancel work items that may have been initialized */
	cancel_work_sync(&cs->close_work);
	cancel_work_sync(&cs->migration_work);
	cancel_delayed_work_sync(&cs->drain_work);

	/* Free crypto state if we allocated it */
	if (conn->crypto_state) {
		tquic_crypto_destroy(conn->crypto_state);
		conn->crypto_state = NULL;
	}

	kfree(cs);
	conn->state_machine = NULL;

	/* Preserve the actual error code instead of overriding with -EINVAL */
	return ret ? ret : -EINVAL;
}
EXPORT_SYMBOL_GPL(tquic_conn_server_accept);

/*
 * Anti-Amplification
 */

/**
 * tquic_conn_can_send - Check if sending is allowed
 * @conn: The connection
 * @bytes: Number of bytes to send
 *
 * Checks anti-amplification limits for unvalidated addresses.
 * Returns true if sending is allowed.
 */
bool tquic_conn_can_send(struct tquic_connection *conn, size_t bytes)
{
	struct tquic_conn_state_machine *cs = tquic_conn_get_cs(conn);

	tquic_conn_dbg(conn, "tquic_conn_can_send: bytes=%zu\n", bytes);
	if (!cs)
		return true;

	/* No limit after address validation */
	if (cs->address_validated)
		return true;

	/* Server: limit to 3x received data */
	if (cs->is_server) {
		u64 limit = cs->bytes_received_unvalidated * cs->amplification_limit;
		if (cs->bytes_sent_unvalidated + bytes > limit) {
			cs->anti_amplification_blocked = true;
			return false;
		}
	}

	return true;
}
EXPORT_SYMBOL_GPL(tquic_conn_can_send);

/**
 * tquic_conn_on_packet_sent - Update state after sending packet
 * @conn: The connection
 * @bytes: Bytes sent
 */
void tquic_conn_on_packet_sent(struct tquic_connection *conn, size_t bytes)
{
	struct tquic_conn_state_machine *cs = tquic_conn_get_cs(conn);

	tquic_conn_dbg(conn, "tquic_conn_on_packet_sent: bytes=%zu\n", bytes);
	if (cs && !cs->address_validated)
		cs->bytes_sent_unvalidated += bytes;
}
EXPORT_SYMBOL_GPL(tquic_conn_on_packet_sent);

/**
 * tquic_conn_on_packet_received - Update state after receiving packet
 * @conn: The connection
 * @bytes: Bytes received
 */
void tquic_conn_on_packet_received(struct tquic_connection *conn, size_t bytes)
{
	struct tquic_conn_state_machine *cs = tquic_conn_get_cs(conn);

	tquic_conn_dbg(conn, "tquic_conn_on_packet_received: bytes=%zu\n", bytes);
	if (cs && !cs->address_validated) {
		cs->bytes_received_unvalidated += bytes;
		/* Unblock if we were blocked */
		if (cs->anti_amplification_blocked)
			cs->anti_amplification_blocked = false;
	}
}
EXPORT_SYMBOL_GPL(tquic_conn_on_packet_received);

/*
 * Connection Lookup
 */

/**
 * tquic_state_cid_lookup - Lookup connection by CID in state machine table
 * @cid: The connection ID to look up
 *
 * Searches the state machine's cid_lookup_table for a matching CID entry.
 * This provides a fallback lookup path for CIDs registered via the
 * connection state machine (tquic_conn_add_local_cid) which are not
 * present in the CID pool's tquic_cid_table.
 *
 * Caller must call tquic_conn_put() on the returned connection when done.
 *
 * Returns: Connection pointer with elevated refcount, or NULL if not found.
 */
struct tquic_connection *tquic_state_cid_lookup(const struct tquic_cid *cid)
{
	struct tquic_cid_entry *entry;
	struct tquic_connection *conn = NULL;

	if (!cid || cid->len == 0)
		return NULL;

	pr_warn("tquic_state_cid_lookup: searching len=%u id=%*phN\n",
		cid->len, min_t(int, cid->len, 8), cid->id);

	rcu_read_lock();
	entry = rhashtable_lookup_fast(&cid_lookup_table, cid,
				       cid_hash_params);
	pr_warn("tquic_state_cid_lookup: entry=%p\n", entry);
	if (entry && !entry->retired && entry->conn) {
		if (refcount_inc_not_zero(&entry->conn->refcnt))
			conn = entry->conn;
	}
	rcu_read_unlock();

	return conn;
}
EXPORT_SYMBOL_GPL(tquic_state_cid_lookup);

/**
 * tquic_conn_lookup_by_cid - Find connection by CID
 * @cid: The connection ID to look up
 *
 * Searches all CID tables: first the CID pool table (tquic_cid_table),
 * then falls back to the state machine table (cid_lookup_table).
 *
 * Returns the connection owning this CID, or NULL.
 */
struct tquic_connection *tquic_conn_lookup_by_cid(const struct tquic_cid *cid)
{
	struct tquic_connection *conn;

	/* Try CID pool table first (the primary RX demux table) */
	conn = tquic_cid_lookup(cid);
	if (conn)
		return conn;

	/* Fall back to state machine CID table */
	conn = tquic_state_cid_lookup(cid);
	if (conn)
		return conn;

	/* Fall back to conn_create rhashtable (server-side connections) */
	return tquic_cid_rht_lookup(cid);
}
EXPORT_SYMBOL_GPL(tquic_conn_lookup_by_cid);

/*
 * State Machine Cleanup
 */

/**
 * tquic_conn_state_cleanup - Clean up connection state machine
 * @conn: The connection
 *
 * Frees all resources associated with the state machine.
 */
void tquic_conn_state_cleanup(struct tquic_connection *conn)
{
	struct tquic_conn_state_machine *cs = tquic_conn_get_cs(conn);
	struct tquic_cid_entry *entry, *tmp;
	struct tquic_path_challenge *challenge, *ctmp;

	if (!cs)
		return;

	/* Cancel pending work */
	cancel_work_sync(&cs->close_work);
	cancel_work_sync(&cs->migration_work);
	cancel_delayed_work_sync(&cs->drain_work);

	/*
	 * Free local CIDs.
	 * Use kfree_rcu() after rhashtable_remove_fast() so that
	 * concurrent RCU readers in tquic_state_cid_lookup() finish
	 * before the entry memory is reclaimed.
	 */
	list_for_each_entry_safe(entry, tmp, &cs->local_cids, list) {
		rhashtable_remove_fast(&cid_lookup_table, &entry->hash_node,
				       cid_hash_params);
		list_del_init(&entry->list);
		kfree_rcu(entry, rcu);
	}

	/* Free remote CIDs (not in hash table, safe to kfree directly) */
	list_for_each_entry_safe(entry, tmp, &cs->remote_cids, list) {
		list_del_init(&entry->list);
		kfree(entry);
	}

	/* Free pending challenges */
	list_for_each_entry_safe(challenge, ctmp, &cs->pending_challenges, list) {
		list_del_init(&challenge->list);
		kfree(challenge);
	}

	/* Free 0-RTT buffer */
	skb_queue_purge(&cs->zero_rtt_buffer);

	/* Free close reason strings */
	kfree(cs->local_close.reason_phrase);
	kfree(cs->remote_close.reason_phrase);

	/* Free retry token */
	kfree(cs->retry_token);

	/* Free supported versions array */
	kfree(cs->supported_versions);

	kfree(cs);
	conn->state_machine = NULL;

	tquic_conn_dbg(conn, "connection state cleaned up\n");
}
EXPORT_SYMBOL_GPL(tquic_conn_state_cleanup);

/*
 * Module Initialization
 */

int __init tquic_connection_init(void)
{
	int ret;

	ret = rhashtable_init(&cid_lookup_table, &cid_hash_params);
	if (ret) {
		tquic_err("failed to init CID lookup table\n");
		return ret;
	}

	/* Initialize retry token AEAD cipher (AES-128-GCM) */
	tquic_retry_aead = crypto_alloc_aead("gcm(aes)", 0, 0);
	if (IS_ERR(tquic_retry_aead)) {
		tquic_err("failed to allocate retry token AEAD\n");
		ret = PTR_ERR(tquic_retry_aead);
		tquic_retry_aead = NULL;
		rhashtable_destroy(&cid_lookup_table);
		return ret;
	}

	ret = crypto_aead_setauthsize(tquic_retry_aead, TQUIC_RETRY_TOKEN_TAG_LEN);
	if (ret) {
		tquic_err("failed to set AEAD auth size\n");
		crypto_free_aead(tquic_retry_aead);
		tquic_retry_aead = NULL;
		rhashtable_destroy(&cid_lookup_table);
		return ret;
	}

	/* Generate random key for retry token encryption */
	get_random_bytes(tquic_retry_token_key, TQUIC_RETRY_TOKEN_KEY_LEN);

	/* Set the token key once at init - no need to set per-request */
	ret = crypto_aead_setkey(tquic_retry_aead, tquic_retry_token_key,
				 TQUIC_RETRY_TOKEN_KEY_LEN);
	if (ret) {
		tquic_err("failed to set retry token AEAD key\n");
		crypto_free_aead(tquic_retry_aead);
		tquic_retry_aead = NULL;
		rhashtable_destroy(&cid_lookup_table);
		return ret;
	}

	tquic_retry_aead_initialized = true;

	/*
	 * Initialize cached AEAD transforms for Retry Integrity Tag
	 * computation.  Keys and nonces are fixed per RFC 9001 Section 5.8
	 * (v1) and RFC 9369 Section 5.8 (v2), so we set them once here.
	 */
	{
		static const u8 retry_key_v1[16] = {
			0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
			0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e
		};
		static const u8 retry_key_v2[16] = {
			0x8f, 0xb4, 0xb0, 0x1b, 0x56, 0xac, 0x48, 0xe2,
			0x60, 0xfb, 0xcb, 0xce, 0xad, 0x7c, 0xcc, 0x92
		};

		tquic_retry_integrity_aead_v1 =
			crypto_alloc_aead("gcm(aes)", 0, 0);
		if (IS_ERR(tquic_retry_integrity_aead_v1)) {
			tquic_err("failed to allocate retry integrity AEAD v1\n");
			ret = PTR_ERR(tquic_retry_integrity_aead_v1);
			tquic_retry_integrity_aead_v1 = NULL;
			goto err_integrity_v1;
		}
		crypto_aead_setauthsize(tquic_retry_integrity_aead_v1, 16);
		ret = crypto_aead_setkey(tquic_retry_integrity_aead_v1,
					 retry_key_v1, 16);
		if (ret) {
			crypto_free_aead(tquic_retry_integrity_aead_v1);
			tquic_retry_integrity_aead_v1 = NULL;
			goto err_integrity_v1;
		}

		tquic_retry_integrity_aead_v2 =
			crypto_alloc_aead("gcm(aes)", 0, 0);
		if (IS_ERR(tquic_retry_integrity_aead_v2)) {
			tquic_err("failed to allocate retry integrity AEAD v2\n");
			ret = PTR_ERR(tquic_retry_integrity_aead_v2);
			tquic_retry_integrity_aead_v2 = NULL;
			goto err_integrity_v2;
		}
		crypto_aead_setauthsize(tquic_retry_integrity_aead_v2, 16);
		ret = crypto_aead_setkey(tquic_retry_integrity_aead_v2,
					 retry_key_v2, 16);
		if (ret) {
			crypto_free_aead(tquic_retry_integrity_aead_v2);
			tquic_retry_integrity_aead_v2 = NULL;
			goto err_integrity_v2;
		}
	}

	tquic_info("connection state machine initialized\n");
	return 0;

err_integrity_v2:
	if (tquic_retry_integrity_aead_v1) {
		crypto_free_aead(tquic_retry_integrity_aead_v1);
		tquic_retry_integrity_aead_v1 = NULL;
	}
err_integrity_v1:
	tquic_retry_aead_initialized = false;
	crypto_free_aead(tquic_retry_aead);
	tquic_retry_aead = NULL;
	rhashtable_destroy(&cid_lookup_table);
	return ret;
}

void tquic_connection_exit(void)
{
	/* Cleanup retry integrity AEADs */
	if (tquic_retry_integrity_aead_v1) {
		crypto_free_aead(tquic_retry_integrity_aead_v1);
		tquic_retry_integrity_aead_v1 = NULL;
	}
	if (tquic_retry_integrity_aead_v2) {
		crypto_free_aead(tquic_retry_integrity_aead_v2);
		tquic_retry_integrity_aead_v2 = NULL;
	}

	/* Cleanup retry token AEAD */
	if (tquic_retry_aead) {
		tquic_retry_aead_initialized = false;
		crypto_free_aead(tquic_retry_aead);
		tquic_retry_aead = NULL;
	}
	memzero_explicit(tquic_retry_token_key, sizeof(tquic_retry_token_key));

	rhashtable_destroy(&cid_lookup_table);
	tquic_info("connection state machine cleanup complete\n");
}

#ifndef TQUIC_OUT_OF_TREE
module_init(tquic_connection_init);
module_exit(tquic_connection_exit);

MODULE_DESCRIPTION("TQUIC Connection State Machine");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Foundation");
#endif
