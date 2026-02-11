// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Connection ID Management
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Implements CID pool management per RFC 9000 Section 5.1.
 * Supports CID rotation, retirement, and lookup for packet demuxing.
 *
 * CID Pool Overview:
 * - Each connection maintains a pool of local CIDs (2-8 per RFC 9000)
 * - CIDs are issued to peer via NEW_CONNECTION_ID frames
 * - Peer uses any active CID to send packets (enables migration)
 * - CIDs can be retired via RETIRE_CONNECTION_ID frames
 * - Global rhashtable enables O(1) CID->connection lookup for packet demux
 *
 * Frame Transmission:
 * - NEW_CONNECTION_ID frame (0x18): Advertise new CID to peer
 * - RETIRE_CONNECTION_ID frame (0x19): Request peer retire a CID
 *
 * CID Rotation:
 * - Periodic rotation based on packets sent or time elapsed
 * - Respects active_cid_limit from peer's transport parameters
 * - Coordinates with path management for multipath
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/rhashtable.h>
#include <linux/jhash.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <linux/skbuff.h>
#include <net/tquic.h>
#include "protocol.h"
#include "tquic_debug.h"
#include "tquic_stateless_reset.h"
#include "security_hardening.h"

#include "tquic_compat.h"

/* Frame type constants */
#define TQUIC_FRAME_NEW_CONNECTION_ID		0x18
#define TQUIC_FRAME_RETIRE_CONNECTION_ID	0x19

/* CID rotation configuration */
#define TQUIC_CID_ROTATION_PACKETS	100000	/* Rotate every 100k packets */
#define TQUIC_CID_ROTATION_MS		60000	/* Or every 60 seconds */
#define TQUIC_CID_MIN_POOL_SIZE		2	/* Minimum CIDs to maintain */

/* Maximum varint encoding sizes */
#define TQUIC_VARINT_MAX_LEN		8

/* QUIC Error Code for protocol violation (RFC 9000 Section 20) */
#define TQUIC_PROTOCOL_VIOLATION	0x0a

/* Forward declaration for connection close */
int tquic_conn_close_with_error(struct tquic_connection *conn,
				u64 error_code, const char *reason);

/* Forward declarations */
static void tquic_cid_rotation_work(struct work_struct *work);
static void tquic_cid_rotation_timer_cb(struct timer_list *t);

/*
 * CID entry states
 */
enum tquic_cid_state {
	CID_STATE_UNUSED = 0,
	CID_STATE_ACTIVE,
	CID_STATE_RETIRED,
};

/**
 * struct tquic_cid_entry - Connection ID entry in pool
 * @cid: The connection ID
 * @seq_num: Sequence number for this CID
 * @retire_prior_to: Retire CIDs before this sequence
 * @reset_token: Stateless reset token (16 bytes per RFC 9000)
 * @conn: Associated connection
 * @state: CID state (active, retired, etc.)
 * @path: Path this CID is assigned to (for multipath)
 * @node: Hash table linkage for global CID lookup
 * @list: Pool list linkage
 */
struct tquic_cid_entry {
	struct tquic_cid cid;
	u64 seq_num;
	u64 retire_prior_to;
	u8 reset_token[TQUIC_STATELESS_RESET_TOKEN_LEN];
	struct tquic_connection *conn;
	enum tquic_cid_state state;
	struct tquic_path *path;
	struct rhash_head node;
	struct list_head list;
	struct rcu_head rcu;
};

/**
 * struct tquic_cid_pool - Connection ID pool
 * @lock: Pool lock (BH-safe spinlock)
 * @local_cids: List of local CIDs (we issue to peer)
 * @remote_cids: List of remote CIDs (peer issues to us)
 * @next_seq: Next sequence number for new local CID
 * @retire_prior_to: Current retire_prior_to value to send
 * @peer_retire_prior_to: retire_prior_to value received from peer
 * @active_count: Number of active local CIDs
 * @remote_active_count: Number of active remote CIDs
 * @cid_len: Length of CIDs in this pool
 * @active_cid_limit: Max active CIDs (from peer transport param)
 * @packets_since_rotation: Packets sent since last CID rotation
 * @last_rotation_time: Timestamp of last CID rotation
 * @rotation_timer: Timer for time-based rotation
 * @rotation_work: Work struct for rotation processing
 * @rotation_enabled: Whether automatic rotation is enabled
 * @conn: Back-pointer to parent connection
 */
struct tquic_cid_pool {
	spinlock_t lock;
	struct list_head local_cids;
	struct list_head remote_cids;
	u64 next_seq;
	u64 retire_prior_to;
	u64 peer_retire_prior_to;
	u32 active_count;
	u32 remote_active_count;
	u8 cid_len;
	u8 active_cid_limit;

	/* CID rotation state */
	u64 packets_since_rotation;
	ktime_t last_rotation_time;
	struct timer_list rotation_timer;
	struct work_struct rotation_work;
	bool rotation_enabled;
	struct tquic_connection *conn;

	/* Security hardening (CVE-2024-22189 defense) */
	struct tquic_cid_security security;
};

/*
 * Global CID hash table for connection lookup
 *
 * This table enables O(1) lookup of connection by CID for incoming
 * packet demultiplexing. All active local CIDs are registered here.
 */
static struct rhashtable tquic_cid_table;
static bool cid_table_initialized;

/*
 * Hash function for CID lookup
 * Uses jhash for good distribution across CID bytes
 */
static u32 tquic_cid_hash(const void *data, u32 len, u32 seed)
{
	const struct tquic_cid *cid = data;

	return jhash(cid->id, cid->len, seed);
}

/*
 * Comparison function for CID lookup
 * Returns 0 on match, non-zero on mismatch
 */
static int tquic_cid_obj_cmp(struct rhashtable_compare_arg *arg,
			     const void *obj)
{
	const struct tquic_cid *cid = arg->key;
	const struct tquic_cid_entry *entry = obj;

	if (cid->len != entry->cid.len)
		return 1;
	return memcmp(cid->id, entry->cid.id, cid->len);
}

static const struct rhashtable_params cid_rht_params = {
	.head_offset = offsetof(struct tquic_cid_entry, node),
	.key_offset = offsetof(struct tquic_cid_entry, cid),
	.key_len = sizeof(struct tquic_cid),
	.hashfn = tquic_cid_hash,
	.obj_cmpfn = tquic_cid_obj_cmp,
	.automatic_shrinking = true,
};

/*
 * =============================================================================
 * Variable Length Integer Encoding (QUIC RFC 9000 Section 16)
 * =============================================================================
 *
 * Note: tquic_varint_len() is exported from tquic_output.c
 */

static int tquic_encode_varint(u8 *buf, size_t buf_len, u64 val)
{
	int len = tquic_varint_len(val);

	if ((size_t)len > buf_len)
		return -ENOSPC;

	switch (len) {
	case 1:
		buf[0] = (u8)val;
		break;
	case 2:
		buf[0] = 0x40 | ((val >> 8) & 0x3f);
		buf[1] = (u8)val;
		break;
	case 4:
		buf[0] = 0x80 | ((val >> 24) & 0x3f);
		buf[1] = (val >> 16) & 0xff;
		buf[2] = (val >> 8) & 0xff;
		buf[3] = (u8)val;
		break;
	case 8:
		buf[0] = 0xc0 | ((val >> 56) & 0x3f);
		buf[1] = (val >> 48) & 0xff;
		buf[2] = (val >> 40) & 0xff;
		buf[3] = (val >> 32) & 0xff;
		buf[4] = (val >> 24) & 0xff;
		buf[5] = (val >> 16) & 0xff;
		buf[6] = (val >> 8) & 0xff;
		buf[7] = (u8)val;
		break;
	}

	return len;
}

/**
 * tquic_cid_pool_init - Initialize CID pool for connection
 * @conn: Connection to initialize pool for
 *
 * Called during connection creation. Allocates pool structure and
 * generates initial local CID. The initial CID is registered in
 * the global hash table for packet demuxing.
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_cid_pool_init(struct tquic_connection *conn)
{
	struct tquic_cid_pool *pool;
	struct tquic_cid_entry *entry;
	int ret;

	pool = kzalloc(sizeof(*pool), GFP_KERNEL);
	if (!pool)
		return -ENOMEM;

	spin_lock_init(&pool->lock);
	INIT_LIST_HEAD(&pool->local_cids);
	INIT_LIST_HEAD(&pool->remote_cids);
	pool->next_seq = 0;
	pool->retire_prior_to = 0;
	pool->peer_retire_prior_to = 0;
	pool->active_count = 0;
	pool->remote_active_count = 0;
	pool->cid_len = TQUIC_DEFAULT_CID_LEN;
	pool->active_cid_limit = TQUIC_ACTIVE_CID_LIMIT;
	pool->conn = conn;

	/* Initialize CID rotation state */
	pool->packets_since_rotation = 0;
	pool->last_rotation_time = ktime_get();
	pool->rotation_enabled = true;
	INIT_WORK(&pool->rotation_work, tquic_cid_rotation_work);
	timer_setup(&pool->rotation_timer, tquic_cid_rotation_timer_cb, 0);

	/* Initialize security state (CVE-2024-22189 defense) */
	tquic_cid_security_init(&pool->security);

	/* Generate initial local CID */
	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry) {
		/* CF-426: Cancel timer/work before freeing pool */
		del_timer_sync(&pool->rotation_timer);
		cancel_work_sync(&pool->rotation_work);
		kfree(pool);
		return -ENOMEM;
	}

	entry->cid.len = pool->cid_len;
	get_random_bytes(entry->cid.id, pool->cid_len);
	entry->seq_num = pool->next_seq++;
	entry->cid.seq_num = entry->seq_num;
	entry->conn = conn;
	entry->state = CID_STATE_ACTIVE;
	entry->path = NULL;

	/*
	 * Generate stateless reset token deterministically using HMAC
	 * Per RFC 9000 Section 10.3.2, tokens must be generated from
	 * a static key so they can be regenerated after state loss.
	 */
	{
		const u8 *static_key = tquic_stateless_reset_get_static_key();

		if (static_key) {
			tquic_stateless_reset_generate_token(&entry->cid,
							     static_key,
							     entry->reset_token);
		} else {
			/* Fallback if stateless reset not initialized yet */
			get_random_bytes(entry->reset_token,
					 TQUIC_STATELESS_RESET_TOKEN_LEN);
		}
	}

	/* Add to global hash table for packet demux lookup */
	if (cid_table_initialized) {
		ret = rhashtable_insert_fast(&tquic_cid_table, &entry->node,
					     cid_rht_params);
		if (ret < 0) {
			kfree(entry);
			/* CF-426: Cancel timer/work before freeing pool */
			del_timer_sync(&pool->rotation_timer);
			cancel_work_sync(&pool->rotation_work);
			kfree(pool);
			return ret;
		}
	}

	list_add(&entry->list, &pool->local_cids);
	pool->active_count++;

	/* Store pool in connection */
	conn->cid_pool = pool;

	/* Copy initial CID to connection for easy access */
	memcpy(&conn->scid, &entry->cid, sizeof(struct tquic_cid));

	tquic_dbg("CID pool initialized, initial CID seq=%llu len=%u\n",
		 entry->seq_num, entry->cid.len);

	return 0;
}

/**
 * tquic_cid_pool_destroy - Free CID pool and all entries
 * @conn: Connection whose pool to destroy
 *
 * Removes all CIDs from global hash table and frees pool memory.
 * Called during connection teardown.
 */
void tquic_cid_pool_destroy(struct tquic_connection *conn)
{
	struct tquic_cid_pool *pool = conn->cid_pool;
	struct tquic_cid_entry *entry, *tmp;

	if (!pool)
		return;

	/* Stop rotation timer and cancel pending work */
	del_timer_sync(&pool->rotation_timer);
	cancel_work_sync(&pool->rotation_work);

	/* Cleanup security state */
	tquic_cid_security_destroy(&pool->security);

	spin_lock_bh(&pool->lock);

	/*
	 * Remove all local CIDs from hash and free.
	 * Use kfree_rcu() after rhashtable_remove_fast() to ensure
	 * concurrent RCU readers (tquic_cid_lookup) have finished
	 * before the entry memory is reclaimed.
	 */
	list_for_each_entry_safe(entry, tmp, &pool->local_cids, list) {
		if (cid_table_initialized && entry->state == CID_STATE_ACTIVE)
			rhashtable_remove_fast(&tquic_cid_table, &entry->node,
					       cid_rht_params);
		list_del(&entry->list);
		kfree_rcu(entry, rcu);
	}

	/* Free remote CIDs (not in global hash, safe to kfree directly) */
	list_for_each_entry_safe(entry, tmp, &pool->remote_cids, list) {
		list_del(&entry->list);
		kfree(entry);
	}

	spin_unlock_bh(&pool->lock);

	kfree(pool);
	conn->cid_pool = NULL;

	tquic_dbg("CID pool destroyed\n");
}

/**
 * tquic_cid_issue - Issue new connection ID to peer
 * @conn: Connection
 * @cid: OUT - The new CID
 *
 * Creates a new CID, adds to pool, registers in global hash table,
 * and queues NEW_CONNECTION_ID frame to be sent to peer.
 *
 * Returns: 0 on success, -ENOSPC if at limit, negative errno on error
 */
int tquic_cid_issue(struct tquic_connection *conn, struct tquic_cid *cid)
{
	struct tquic_cid_pool *pool = conn->cid_pool;
	struct tquic_cid_entry *entry;
	int ret;

	if (!pool)
		return -EINVAL;

	spin_lock_bh(&pool->lock);

	/* Check active CID limit (per RFC 9000, peer sets via transport param) */
	if (pool->active_count >= pool->active_cid_limit) {
		spin_unlock_bh(&pool->lock);
		tquic_dbg("CID pool at limit (%u)\n", pool->active_count);
		return -ENOSPC;
	}

	entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
	if (!entry) {
		spin_unlock_bh(&pool->lock);
		return -ENOMEM;
	}

	/* Generate new CID with random bytes */
	entry->cid.len = pool->cid_len;
	get_random_bytes(entry->cid.id, pool->cid_len);
	entry->seq_num = pool->next_seq++;
	entry->cid.seq_num = entry->seq_num;
	entry->conn = conn;
	entry->state = CID_STATE_ACTIVE;
	entry->path = NULL;

	/*
	 * Generate stateless reset token deterministically using HMAC
	 * Per RFC 9000 Section 10.3.2, tokens must be generated from
	 * a static key so they can be regenerated after state loss.
	 */
	{
		const u8 *static_key = tquic_stateless_reset_get_static_key();

		if (static_key) {
			tquic_stateless_reset_generate_token(&entry->cid,
							     static_key,
							     entry->reset_token);
		} else {
			/* Fallback if not initialized */
			get_random_bytes(entry->reset_token,
					 TQUIC_STATELESS_RESET_TOKEN_LEN);
		}
	}

	/* Register in global hash table */
	if (cid_table_initialized) {
		ret = rhashtable_insert_fast(&tquic_cid_table, &entry->node,
					     cid_rht_params);
		if (ret < 0) {
			spin_unlock_bh(&pool->lock);
			kfree(entry);
			return ret;
		}
	}

	list_add(&entry->list, &pool->local_cids);
	pool->active_count++;

	spin_unlock_bh(&pool->lock);

	/* Copy to output */
	memcpy(cid, &entry->cid, sizeof(struct tquic_cid));

	/* Queue NEW_CONNECTION_ID frame to notify peer */
	tquic_send_new_connection_id(conn, cid, entry->reset_token);

	tquic_dbg("issued new CID seq=%llu, active=%u\n",
		 entry->seq_num, pool->active_count);

	return 0;
}

/**
 * tquic_cid_retire - Retire connection ID by sequence number
 * @conn: Connection
 * @seq_num: Sequence number of CID to retire
 *
 * Marks CID as retired, removes from global hash table.
 * Called when peer sends RETIRE_CONNECTION_ID frame.
 *
 * Returns: 0 on success, -ENOENT if CID not found
 */
int tquic_cid_retire(struct tquic_connection *conn, u64 seq_num)
{
	struct tquic_cid_pool *pool = conn->cid_pool;
	struct tquic_cid_entry *entry;
	bool found = false;

	if (!pool)
		return -EINVAL;

	spin_lock_bh(&pool->lock);

	list_for_each_entry(entry, &pool->local_cids, list) {
		if (entry->seq_num == seq_num) {
			if (entry->state == CID_STATE_ACTIVE) {
				entry->state = CID_STATE_RETIRED;
				pool->active_count--;
				if (cid_table_initialized)
					rhashtable_remove_fast(&tquic_cid_table,
							       &entry->node,
							       cid_rht_params);
				tquic_dbg("retired CID seq=%llu, active=%u\n",
					 seq_num, pool->active_count);
			}
			found = true;
			break;
		}
	}

	spin_unlock_bh(&pool->lock);

	if (!found) {
		tquic_dbg("CID seq=%llu not found for retire\n", seq_num);
		return -ENOENT;
	}

	/*
	 * Peer asked to retire our local CID. We do NOT send
	 * RETIRE_CONNECTION_ID back (that's for retiring REMOTE CIDs).
	 * Instead, issue a replacement CID if we have room.
	 */
	if (pool->active_count < pool->active_cid_limit)
		tquic_cid_issue(conn, NULL);

	return 0;
}

/**
 * tquic_cid_lookup - Lookup connection by CID
 * @cid: Connection ID to look up
 *
 * Performs O(1) lookup in global hash table for packet demuxing.
 * Only returns connections with active (non-retired) CIDs.
 *
 * Returns: Connection pointer or NULL if not found
 */
struct tquic_connection *tquic_cid_lookup(const struct tquic_cid *cid)
{
	struct tquic_cid_entry *entry;
	struct tquic_connection *conn = NULL;

	if (!cid_table_initialized || !cid || cid->len == 0)
		return NULL;

	rcu_read_lock();
	entry = rhashtable_lookup_fast(&tquic_cid_table, cid, cid_rht_params);
	if (entry && entry->state == CID_STATE_ACTIVE) {
		conn = entry->conn;
		if (conn && !refcount_inc_not_zero(&conn->refcnt))
			conn = NULL;
	}
	rcu_read_unlock();

	return conn;
}

/**
 * tquic_cid_get_for_migration - Get unused CID for connection migration
 * @conn: Connection
 * @cid: OUT - Available CID for migration
 *
 * Finds a remote CID (received from peer) that is not currently assigned
 * to any path. Used during connection migration to get a fresh CID.
 *
 * Returns: 0 on success with CID copied to @cid, -ENOENT if no CID available
 */
int tquic_cid_get_for_migration(struct tquic_connection *conn,
				struct tquic_cid *cid)
{
	struct tquic_cid_pool *pool = conn->cid_pool;
	struct tquic_cid_entry *entry;
	int ret = -ENOENT;

	if (!pool)
		return -EINVAL;

	spin_lock_bh(&pool->lock);

	/* Find remote CID not assigned to a path */
	list_for_each_entry(entry, &pool->remote_cids, list) {
		if (entry->state == CID_STATE_ACTIVE && !entry->path) {
			memcpy(cid, &entry->cid, sizeof(struct tquic_cid));
			ret = 0;
			tquic_dbg("found CID for migration seq=%llu\n",
				 entry->seq_num);
			break;
		}
	}

	spin_unlock_bh(&pool->lock);

	if (ret < 0)
		tquic_dbg("no CID available for migration (need NEW_CONNECTION_ID from peer)\n");

	return ret;
}

/**
 * tquic_cid_add_remote - Add remote CID received from peer
 * @conn: Connection
 * @cid: CID received in NEW_CONNECTION_ID frame
 * @seq_num: Sequence number from frame
 * @retire_prior_to: Retire prior to value from frame
 * @reset_token: Stateless reset token from frame
 *
 * Called when processing NEW_CONNECTION_ID frame from peer.
 * Stores the CID for use when sending packets to peer.
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_cid_add_remote(struct tquic_connection *conn,
			 const struct tquic_cid *cid,
			 u64 seq_num, u64 retire_prior_to,
			 const u8 *reset_token)
{
	struct tquic_cid_pool *pool = conn->cid_pool;
	struct tquic_cid_entry *entry, *tmp;
	int ret;

	if (!pool)
		return -EINVAL;

	/*
	 * CVE-2024-22189 Defense: Rate limit NEW_CONNECTION_ID processing
	 *
	 * An attacker can flood the connection with NEW_CONNECTION_ID frames
	 * with high retire_prior_to values, causing excessive RETIRE_CONNECTION_ID
	 * frames to be queued and potentially exhausting memory.
	 */
	ret = tquic_cid_security_check_new_cid(&pool->security);
	if (ret) {
		if (ret == -EBUSY) {
			tquic_dbg("NEW_CONNECTION_ID rate limited\n");
			tquic_security_event(TQUIC_SEC_EVENT_NEW_CID_RATE_LIMIT,
					     NULL, "rate limit exceeded");
		}
		return ret;
	}

	entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
	if (!entry)
		return -ENOMEM;

	memcpy(&entry->cid, cid, sizeof(struct tquic_cid));
	entry->seq_num = seq_num;
	entry->cid.seq_num = seq_num;
	entry->retire_prior_to = retire_prior_to;
	entry->conn = conn;
	entry->state = CID_STATE_ACTIVE;
	entry->path = NULL;
	if (reset_token)
		memcpy(entry->reset_token, reset_token,
		       TQUIC_STATELESS_RESET_TOKEN_LEN);

	spin_lock_bh(&pool->lock);

	/*
	 * Enforce active_connection_id_limit (RFC 9000 Section 5.1.1).
	 * Count active (non-retired) remote CIDs and reject if at limit.
	 */
	{
		struct tquic_cid_entry *iter;
		u32 active_count = 0;

		list_for_each_entry(iter, &pool->remote_cids, list) {
			if (iter->state == CID_STATE_ACTIVE)
				active_count++;
		}
		if (active_count >= conn->remote_params.active_connection_id_limit) {
			spin_unlock_bh(&pool->lock);
			kfree(entry);
			return -EPROTO;
		}
	}

	list_add(&entry->list, &pool->remote_cids);

	/* Handle retire_prior_to: retire CIDs with seq < retire_prior_to */
	if (retire_prior_to > 0) {
		list_for_each_entry_safe(entry, tmp, &pool->remote_cids, list) {
			if (entry->seq_num < retire_prior_to &&
			    entry->state == CID_STATE_ACTIVE) {
				entry->state = CID_STATE_RETIRED;
				tquic_dbg("auto-retired remote CID seq=%llu (prior_to=%llu)\n",
					 entry->seq_num, retire_prior_to);
			}
		}
	}

	spin_unlock_bh(&pool->lock);

	tquic_dbg("added remote CID seq=%llu len=%u\n", seq_num, cid->len);

	return 0;
}

/*
 * =============================================================================
 * NEW_CONNECTION_ID Frame Transmission (RFC 9000 Section 19.15)
 * =============================================================================
 *
 * Frame format:
 *   Type (i) = 0x18
 *   Sequence Number (i)
 *   Retire Prior To (i)
 *   Length (8) = CID length (1 byte, value 1-20)
 *   Connection ID (0..20)
 *   Stateless Reset Token (128 bits = 16 bytes)
 */

/**
 * tquic_build_new_connection_id_frame - Build NEW_CONNECTION_ID frame
 * @buf: Output buffer
 * @buf_len: Buffer length
 * @cid: The new CID to advertise
 * @seq_num: Sequence number for this CID
 * @retire_prior_to: Retire CIDs with sequence < this
 * @reset_token: Stateless reset token (16 bytes)
 *
 * Returns: Number of bytes written, or negative error code
 */
static int tquic_build_new_connection_id_frame(u8 *buf, size_t buf_len,
					       const struct tquic_cid *cid,
					       u64 seq_num, u64 retire_prior_to,
					       const u8 *reset_token)
{
	size_t offset = 0;
	int ret;

	/* Calculate minimum required size */
	size_t min_size = 1 +				/* Frame type */
			  tquic_varint_len(seq_num) +	/* Sequence Number */
			  tquic_varint_len(retire_prior_to) + /* Retire Prior To */
			  1 +				/* CID Length */
			  cid->len +			/* Connection ID */
			  TQUIC_STATELESS_RESET_TOKEN_LEN; /* Reset Token */

	if (buf_len < min_size)
		return -ENOSPC;

	/* Frame type (0x18) */
	buf[offset++] = TQUIC_FRAME_NEW_CONNECTION_ID;

	/* Sequence Number (varint) */
	ret = tquic_encode_varint(buf + offset, buf_len - offset, seq_num);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Retire Prior To (varint) */
	ret = tquic_encode_varint(buf + offset, buf_len - offset, retire_prior_to);
	if (ret < 0)
		return ret;
	offset += ret;

	/* CID Length (1 byte, value 1-20) */
	if (cid->len < 1 || cid->len > TQUIC_MAX_CID_LEN)
		return -EINVAL;
	buf[offset++] = cid->len;

	/* Connection ID */
	if (offset + cid->len > buf_len)
		return -ENOSPC;
	memcpy(buf + offset, cid->id, cid->len);
	offset += cid->len;

	/* Stateless Reset Token (16 bytes) */
	if (offset + TQUIC_STATELESS_RESET_TOKEN_LEN > buf_len)
		return -ENOSPC;
	memcpy(buf + offset, reset_token, TQUIC_STATELESS_RESET_TOKEN_LEN);
	offset += TQUIC_STATELESS_RESET_TOKEN_LEN;

	return offset;
}

/**
 * tquic_send_new_connection_id - Send NEW_CONNECTION_ID frame
 * @conn: Connection
 * @cid: The new CID to advertise
 * @reset_token: Stateless reset token for the CID
 *
 * Builds and queues a NEW_CONNECTION_ID frame for transmission to the peer.
 * This frame advertises a new connection ID that the peer can use
 * when sending packets to us.
 *
 * Per RFC 9000 Section 5.1.1, each issued CID must have a unique
 * sequence number and the retire_prior_to value must not decrease.
 */
void tquic_send_new_connection_id(struct tquic_connection *conn,
				  const struct tquic_cid *cid,
				  const u8 *reset_token)
{
	struct tquic_cid_pool *pool = conn->cid_pool;
	struct sk_buff *skb;
	u8 *frame_buf;
	int frame_len;
	u64 retire_prior_to;

	if (!conn || !cid || !reset_token || !pool)
		return;

	if (!conn->active_path) {
		tquic_dbg("NEW_CONNECTION_ID: no active path\n");
		return;
	}

	/* Allocate frame buffer */
	frame_buf = kmalloc(128, GFP_ATOMIC);
	if (!frame_buf)
		return;

	/* Get current retire_prior_to value */
	spin_lock_bh(&pool->lock);
	retire_prior_to = pool->retire_prior_to;
	spin_unlock_bh(&pool->lock);

	/* Build frame */
	frame_len = tquic_build_new_connection_id_frame(frame_buf, 128, cid,
							cid->seq_num,
							retire_prior_to,
							reset_token);
	if (frame_len < 0) {
		tquic_dbg("NEW_CONNECTION_ID: frame build failed (%d)\n",
			 frame_len);
		kfree(frame_buf);
		return;
	}

	/*
	 * Queue frame for transmission via the connection's control frame queue.
	 * The frame will be included in the next outgoing packet and properly
	 * encrypted and transmitted by the output path.
	 */
	skb = alloc_skb(frame_len + 32, GFP_ATOMIC);
	if (!skb) {
		kfree(frame_buf);
		return;
	}

	/* Reserve headroom for potential header additions */
	skb_reserve(skb, 16);

	/* Copy frame data */
	skb_put_data(skb, frame_buf, frame_len);
	kfree(frame_buf);

	/* Queue for transmission */
	spin_lock_bh(&conn->lock);
	skb_queue_tail(&conn->control_frames, skb);
	spin_unlock_bh(&conn->lock);

	/* Trigger transmission */
	if (!work_pending(&conn->tx_work))
		schedule_work(&conn->tx_work);

	tquic_dbg("NEW_CONNECTION_ID queued seq=%llu len=%u retire_prior_to=%llu\n",
		 cid->seq_num, cid->len, retire_prior_to);
}

/*
 * =============================================================================
 * RETIRE_CONNECTION_ID Frame Transmission (RFC 9000 Section 19.16)
 * =============================================================================
 *
 * Frame format:
 *   Type (i) = 0x19
 *   Sequence Number (i)
 */

/**
 * tquic_build_retire_connection_id_frame - Build RETIRE_CONNECTION_ID frame
 * @buf: Output buffer
 * @buf_len: Buffer length
 * @seq_num: Sequence number of CID to retire
 *
 * Returns: Number of bytes written, or negative error code
 */
static int tquic_build_retire_connection_id_frame(u8 *buf, size_t buf_len,
						  u64 seq_num)
{
	size_t offset = 0;
	int ret;

	/* Calculate required size */
	size_t min_size = 1 + tquic_varint_len(seq_num);

	if (buf_len < min_size)
		return -ENOSPC;

	/* Frame type (0x19) */
	buf[offset++] = TQUIC_FRAME_RETIRE_CONNECTION_ID;

	/* Sequence Number (varint) */
	ret = tquic_encode_varint(buf + offset, buf_len - offset, seq_num);
	if (ret < 0)
		return ret;
	offset += ret;

	return offset;
}

/**
 * tquic_send_retire_connection_id - Send RETIRE_CONNECTION_ID frame
 * @conn: Connection
 * @seq_num: Sequence number of CID to retire
 *
 * Builds and transmits a RETIRE_CONNECTION_ID frame to the peer.
 * This frame indicates that we will no longer use the specified
 * connection ID when sending to the peer.
 *
 * Per RFC 9000 Section 5.1.2:
 * - An endpoint cannot retire a CID until it has another CID to use
 * - The sequence number must refer to a CID the peer previously issued
 */
void tquic_send_retire_connection_id(struct tquic_connection *conn, u64 seq_num)
{
	struct tquic_cid_pool *pool;
	struct tquic_path *path;
	struct sk_buff *skb;
	u8 *frame_buf;
	u8 *pkt_buf;
	int frame_len;
	size_t pkt_len;
	int ret;

	if (!conn)
		return;

	/*
	 * CVE-2024-22189 Defense: Limit queued RETIRE_CONNECTION_ID frames
	 *
	 * An attacker can send many NEW_CONNECTION_ID frames with high
	 * retire_prior_to values, forcing us to queue many RETIRE_CONNECTION_ID
	 * frames. We limit the queue to prevent memory exhaustion.
	 */
	pool = conn->cid_pool;
	if (pool) {
		ret = tquic_cid_security_queue_retire(&pool->security);
		if (ret == -EPROTO) {
			tquic_warn("RETIRE_CONNECTION_ID stuffing attack detected "
				"(queued >= %d)\n", TQUIC_MAX_QUEUED_RETIRE_CID);
			tquic_security_event(TQUIC_SEC_EVENT_RETIRE_CID_FLOOD,
					     NULL, "queue limit exceeded - closing connection");
			/* Close connection with PROTOCOL_VIOLATION per RFC 9000 */
			tquic_conn_close_with_error(conn, TQUIC_PROTOCOL_VIOLATION,
						    "RETIRE_CID stuffing attack");
			return;
		}
	}

	path = conn->active_path;
	if (!path) {
		tquic_dbg("RETIRE_CONNECTION_ID: no active path\n");
		if (pool)
			tquic_cid_security_dequeue_retire(&pool->security);
		return;
	}

	/* Allocate frame buffer */
	frame_buf = kmalloc(16, GFP_ATOMIC);
	if (!frame_buf) {
		if (pool)
			tquic_cid_security_dequeue_retire(&pool->security);
		return;
	}

	/* Build frame */
	frame_len = tquic_build_retire_connection_id_frame(frame_buf, 16, seq_num);
	if (frame_len < 0) {
		tquic_dbg("RETIRE_CONNECTION_ID: frame build failed (%d)\n",
			 frame_len);
		kfree(frame_buf);
		return;
	}

	/* Build packet */
	pkt_len = 64 + frame_len;
	skb = alloc_skb(pkt_len + 128, GFP_ATOMIC);
	if (!skb) {
		kfree(frame_buf);
		return;
	}

	skb_reserve(skb, 128);

	/* Build minimal short header */
	pkt_buf = skb_put(skb, 1 + path->remote_cid.len);
	pkt_buf[0] = 0x40;  /* Fixed bit set */
	if (path->remote_cid.len > 0)
		memcpy(pkt_buf + 1, path->remote_cid.id, path->remote_cid.len);

	/* Packet number */
	{
		u8 pkt_num_byte;

		spin_lock_bh(&conn->lock);
		pkt_num_byte = (u8)(conn->stats.tx_packets++ & 0xff);
		spin_unlock_bh(&conn->lock);

		skb_put_u8(skb, pkt_num_byte);
	}

	/* Append frame payload */
	skb_put_data(skb, frame_buf, frame_len);
	kfree(frame_buf);

	if (conn->sk && path->dev) {
		skb->dev = path->dev;
		skb->sk = conn->sk;

		tquic_dbg("RETIRE_CONNECTION_ID sent seq=%llu\n", seq_num);
	}

	/* In production, hand off to output path */
	kfree_skb(skb);
}

/*
 * =============================================================================
 * CID Rotation Logic
 * =============================================================================
 *
 * CID rotation helps prevent tracking by changing the connection ID
 * periodically. Rotation can be triggered by:
 * 1. Packet count threshold (TQUIC_CID_ROTATION_PACKETS)
 * 2. Time elapsed (TQUIC_CID_ROTATION_MS)
 * 3. Explicit request (e.g., connection migration)
 */

/**
 * tquic_cid_check_rotation - Check if CID rotation is needed
 * @conn: Connection to check
 *
 * Called after sending packets to check rotation thresholds.
 * Returns: true if rotation was triggered
 */
bool tquic_cid_check_rotation(struct tquic_connection *conn)
{
	struct tquic_cid_pool *pool;
	ktime_t now;
	s64 elapsed_ms;
	bool need_rotation = false;

	if (!conn || !conn->cid_pool)
		return false;

	pool = conn->cid_pool;

	spin_lock_bh(&pool->lock);

	if (!pool->rotation_enabled) {
		spin_unlock_bh(&pool->lock);
		return false;
	}

	pool->packets_since_rotation++;

	/* Check packet threshold */
	if (pool->packets_since_rotation >= TQUIC_CID_ROTATION_PACKETS)
		need_rotation = true;

	/* Check time threshold */
	now = ktime_get();
	elapsed_ms = ktime_ms_delta(now, pool->last_rotation_time);
	if (elapsed_ms >= TQUIC_CID_ROTATION_MS)
		need_rotation = true;

	spin_unlock_bh(&pool->lock);

	if (need_rotation)
		schedule_work(&pool->rotation_work);

	return need_rotation;
}

/**
 * tquic_cid_rotate - Perform CID rotation
 * @conn: Connection
 *
 * Issues a new CID and updates retire_prior_to to retire old CIDs.
 * Called from work queue context.
 *
 * Returns: 0 on success, negative error on failure
 */
int tquic_cid_rotate(struct tquic_connection *conn)
{
	struct tquic_cid_pool *pool;
	struct tquic_cid_entry *entry, *oldest = NULL;
	struct tquic_cid new_cid;
	u64 oldest_seq = U64_MAX;
	int ret;

	if (!conn || !conn->cid_pool)
		return -EINVAL;

	pool = conn->cid_pool;

	spin_lock_bh(&pool->lock);

	/* Check if we have room for a new CID */
	if (pool->active_count >= pool->active_cid_limit) {
		/* Find oldest active CID to retire */
		list_for_each_entry(entry, &pool->local_cids, list) {
			if (entry->state == CID_STATE_ACTIVE &&
			    entry->seq_num < oldest_seq) {
				oldest_seq = entry->seq_num;
				oldest = entry;
			}
		}

		if (oldest) {
			/* Update retire_prior_to to retire this CID */
			pool->retire_prior_to = oldest->seq_num + 1;
			tquic_dbg("CID rotation: updating retire_prior_to=%llu\n",
				 pool->retire_prior_to);
		}
	}

	/* Reset rotation counters */
	pool->packets_since_rotation = 0;
	pool->last_rotation_time = ktime_get();

	spin_unlock_bh(&pool->lock);

	/* Issue new CID (this will send NEW_CONNECTION_ID frame) */
	ret = tquic_cid_issue(conn, &new_cid);
	if (ret < 0 && ret != -ENOSPC) {
		tquic_dbg("CID rotation: issue failed (%d)\n", ret);
		return ret;
	}

	tquic_dbg("CID rotation complete, new CID seq=%llu\n",
		 new_cid.seq_num);

	return 0;
}

/**
 * tquic_cid_rotation_work - Work function for CID rotation
 * @work: Work struct embedded in pool
 */
static void tquic_cid_rotation_work(struct work_struct *work)
{
	struct tquic_cid_pool *pool = container_of(work, struct tquic_cid_pool,
						   rotation_work);

	if (pool && pool->conn)
		tquic_cid_rotate(pool->conn);
}

/**
 * tquic_cid_rotation_timer_cb - Timer callback for time-based rotation
 * @t: Timer list entry
 */
static void tquic_cid_rotation_timer_cb(struct timer_list *t)
{
	struct tquic_cid_pool *pool = from_timer(pool, t, rotation_timer);

	if (pool && pool->rotation_enabled)
		schedule_work(&pool->rotation_work);
}

/**
 * tquic_cid_set_rotation_enabled - Enable or disable automatic CID rotation
 * @conn: Connection
 * @enabled: Whether to enable rotation
 */
void tquic_cid_set_rotation_enabled(struct tquic_connection *conn, bool enabled)
{
	struct tquic_cid_pool *pool;

	if (!conn || !conn->cid_pool)
		return;

	pool = conn->cid_pool;

	spin_lock_bh(&pool->lock);
	pool->rotation_enabled = enabled;
	spin_unlock_bh(&pool->lock);

	if (enabled) {
		/* Start rotation timer */
		mod_timer(&pool->rotation_timer,
			  jiffies + msecs_to_jiffies(TQUIC_CID_ROTATION_MS));
	} else {
		/* Stop rotation timer */
		del_timer(&pool->rotation_timer);
	}
}

/**
 * tquic_cid_update_active_limit - Update active CID limit from transport params
 * @conn: Connection
 * @limit: New active CID limit from peer
 *
 * Called when transport parameters are negotiated to update the limit.
 */
void tquic_cid_update_active_limit(struct tquic_connection *conn, u8 limit)
{
	struct tquic_cid_pool *pool;

	if (!conn || !conn->cid_pool)
		return;

	pool = conn->cid_pool;

	/* Minimum of 2 per RFC 9000 */
	if (limit < 2)
		limit = 2;

	spin_lock_bh(&pool->lock);
	pool->active_cid_limit = limit;
	spin_unlock_bh(&pool->lock);

	tquic_dbg("CID active limit updated to %u\n", limit);
}

/*
 * =============================================================================
 * Sequence Number Tracking
 * =============================================================================
 */

/**
 * tquic_cid_get_next_seq - Get and increment next sequence number
 * @conn: Connection
 *
 * Returns: Next sequence number to use for a new CID
 */
u64 tquic_cid_get_next_seq(struct tquic_connection *conn)
{
	struct tquic_cid_pool *pool;
	u64 seq;

	if (!conn || !conn->cid_pool)
		return 0;

	pool = conn->cid_pool;

	spin_lock_bh(&pool->lock);
	seq = pool->next_seq++;
	spin_unlock_bh(&pool->lock);

	return seq;
}

/**
 * tquic_cid_get_retire_prior_to - Get current retire_prior_to value
 * @conn: Connection
 *
 * Returns: Current retire_prior_to value
 */
u64 tquic_cid_get_retire_prior_to(struct tquic_connection *conn)
{
	struct tquic_cid_pool *pool;
	u64 retire_prior_to;

	if (!conn || !conn->cid_pool)
		return 0;

	pool = conn->cid_pool;

	spin_lock_bh(&pool->lock);
	retire_prior_to = pool->retire_prior_to;
	spin_unlock_bh(&pool->lock);

	return retire_prior_to;
}

/**
 * tquic_cid_handle_peer_retire_prior_to - Handle peer's retire_prior_to
 * @conn: Connection
 * @retire_prior_to: Value from peer's NEW_CONNECTION_ID frame
 *
 * Retires all local CIDs with sequence number less than retire_prior_to.
 */
void tquic_cid_handle_peer_retire_prior_to(struct tquic_connection *conn,
					   u64 retire_prior_to)
{
	struct tquic_cid_pool *pool;
	struct tquic_cid_entry *entry, *tmp;
	u64 retired_count = 0;

	if (!conn || !conn->cid_pool)
		return;

	pool = conn->cid_pool;

	spin_lock_bh(&pool->lock);

	/* Only process if this is a new retire_prior_to value */
	if (retire_prior_to <= pool->peer_retire_prior_to) {
		spin_unlock_bh(&pool->lock);
		return;
	}

	pool->peer_retire_prior_to = retire_prior_to;

	/* Retire all local CIDs with seq < retire_prior_to */
	list_for_each_entry_safe(entry, tmp, &pool->local_cids, list) {
		if (entry->seq_num < retire_prior_to &&
		    entry->state == CID_STATE_ACTIVE) {
			entry->state = CID_STATE_RETIRED;
			pool->active_count--;

			if (cid_table_initialized)
				rhashtable_remove_fast(&tquic_cid_table,
						       &entry->node,
						       cid_rht_params);
			retired_count++;
		}
	}

	spin_unlock_bh(&pool->lock);

	if (retired_count > 0) {
		u32 current_count;

		tquic_dbg("retired %llu CIDs due to peer retire_prior_to=%llu\n",
			 retired_count, retire_prior_to);

		/* Issue new CIDs to maintain pool size */
		spin_lock_bh(&pool->lock);
		current_count = pool->active_count;
		spin_unlock_bh(&pool->lock);

		while (current_count < TQUIC_CID_MIN_POOL_SIZE) {
			struct tquic_cid new_cid;

			if (tquic_cid_issue(conn, &new_cid) < 0)
				break;

			spin_lock_bh(&pool->lock);
			current_count = pool->active_count;
			spin_unlock_bh(&pool->lock);
		}
	}
}

/*
 * =============================================================================
 * Path Integration for Multipath CID Management
 * =============================================================================
 */

/**
 * tquic_cid_assign_to_path - Assign a CID to a specific path
 * @conn: Connection
 * @path: Path to assign CID to
 * @cid: OUT - Assigned CID
 *
 * Per RFC 9000 Section 9.5, each path should use a different CID
 * for unlinkability. This function assigns an unused remote CID
 * to the specified path.
 *
 * Returns: 0 on success, -ENOENT if no CID available
 */
int tquic_cid_assign_to_path(struct tquic_connection *conn,
			     struct tquic_path *path,
			     struct tquic_cid *cid)
{
	struct tquic_cid_pool *pool;
	struct tquic_cid_entry *entry;
	int ret = -ENOENT;

	if (!conn || !conn->cid_pool || !path || !cid)
		return -EINVAL;

	pool = conn->cid_pool;

	spin_lock_bh(&pool->lock);

	/* Find an unassigned remote CID */
	list_for_each_entry(entry, &pool->remote_cids, list) {
		if (entry->state == CID_STATE_ACTIVE && !entry->path) {
			/* Assign to this path */
			entry->path = path;
			memcpy(cid, &entry->cid, sizeof(*cid));
			ret = 0;

			tquic_dbg("assigned CID seq=%llu to path %u\n",
				 entry->seq_num, path->path_id);
			break;
		}
	}

	spin_unlock_bh(&pool->lock);

	return ret;
}

/**
 * tquic_cid_release_from_path - Release CID assignment from a path
 * @conn: Connection
 * @path: Path to release CID from
 *
 * Called when a path is being removed or migrated.
 */
void tquic_cid_release_from_path(struct tquic_connection *conn,
				 struct tquic_path *path)
{
	struct tquic_cid_pool *pool;
	struct tquic_cid_entry *entry;

	if (!conn || !conn->cid_pool || !path)
		return;

	pool = conn->cid_pool;

	spin_lock_bh(&pool->lock);

	/* Find and release CID assigned to this path */
	list_for_each_entry(entry, &pool->remote_cids, list) {
		if (entry->path == path) {
			entry->path = NULL;
			tquic_dbg("released CID seq=%llu from path %u\n",
				 entry->seq_num, path->path_id);
			break;
		}
	}

	spin_unlock_bh(&pool->lock);
}

/**
 * tquic_cid_get_path_cid - Get the CID assigned to a path
 * @conn: Connection
 * @path: Path to query
 * @cid: OUT - The assigned CID
 *
 * Returns: 0 on success, -ENOENT if no CID assigned
 */
int tquic_cid_get_path_cid(struct tquic_connection *conn,
			   struct tquic_path *path,
			   struct tquic_cid *cid)
{
	struct tquic_cid_pool *pool;
	struct tquic_cid_entry *entry;
	int ret = -ENOENT;

	if (!conn || !conn->cid_pool || !path || !cid)
		return -EINVAL;

	pool = conn->cid_pool;

	spin_lock_bh(&pool->lock);

	list_for_each_entry(entry, &pool->remote_cids, list) {
		if (entry->path == path && entry->state == CID_STATE_ACTIVE) {
			memcpy(cid, &entry->cid, sizeof(*cid));
			ret = 0;
			break;
		}
	}

	spin_unlock_bh(&pool->lock);

	return ret;
}

/**
 * tquic_cid_retire_remote - Request retirement of a remote CID
 * @conn: Connection
 * @seq_num: Sequence number of remote CID to retire
 *
 * Marks the remote CID as retired and sends RETIRE_CONNECTION_ID frame.
 */
void tquic_cid_retire_remote(struct tquic_connection *conn, u64 seq_num)
{
	struct tquic_cid_pool *pool;
	struct tquic_cid_entry *entry;
	bool found = false;

	if (!conn || !conn->cid_pool)
		return;

	pool = conn->cid_pool;

	spin_lock_bh(&pool->lock);

	list_for_each_entry(entry, &pool->remote_cids, list) {
		if (entry->seq_num == seq_num &&
		    entry->state == CID_STATE_ACTIVE) {
			entry->state = CID_STATE_RETIRED;
			entry->path = NULL;
			pool->remote_active_count--;
			found = true;
			break;
		}
	}

	spin_unlock_bh(&pool->lock);

	if (found) {
		/* Send RETIRE_CONNECTION_ID frame to peer */
		tquic_send_retire_connection_id(conn, seq_num);
		tquic_dbg("retiring remote CID seq=%llu\n", seq_num);
	}
}

/**
 * tquic_cid_table_init - Initialize global CID hash table
 *
 * Called during module initialization.
 * Returns: 0 on success, negative errno on failure
 */
int __init tquic_cid_table_init(void)
{
	int ret;

	ret = rhashtable_init(&tquic_cid_table, &cid_rht_params);
	if (ret == 0) {
		cid_table_initialized = true;
		tquic_info("CID hash table initialized\n");
	} else {
		tquic_err("failed to init CID hash table: %d\n", ret);
	}
	return ret;
}

/**
 * tquic_cid_table_exit - Destroy global CID hash table
 *
 * Called during module exit.
 */
void __exit tquic_cid_table_exit(void)
{
	if (cid_table_initialized) {
		rhashtable_destroy(&tquic_cid_table);
		cid_table_initialized = false;
		tquic_info("CID hash table destroyed\n");
	}
}

MODULE_DESCRIPTION("TQUIC Connection ID Management");
MODULE_LICENSE("GPL");
