// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Connection ID Management
 *
 * Copyright (c) 2026 Linux Foundation
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
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/rhashtable.h>
#include <linux/jhash.h>
#include <net/tquic.h>
#include "protocol.h"

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
};

/**
 * struct tquic_cid_pool - Connection ID pool
 * @lock: Pool lock (BH-safe spinlock)
 * @local_cids: List of local CIDs (we issue to peer)
 * @remote_cids: List of remote CIDs (peer issues to us)
 * @next_seq: Next sequence number for new local CID
 * @active_count: Number of active local CIDs
 * @cid_len: Length of CIDs in this pool
 * @active_cid_limit: Max active CIDs (from peer transport param)
 */
struct tquic_cid_pool {
	spinlock_t lock;
	struct list_head local_cids;
	struct list_head remote_cids;
	u64 next_seq;
	u32 active_count;
	u8 cid_len;
	u8 active_cid_limit;
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
	pool->active_count = 0;
	pool->cid_len = TQUIC_DEFAULT_CID_LEN;
	pool->active_cid_limit = TQUIC_ACTIVE_CID_LIMIT;

	/* Generate initial local CID */
	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry) {
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

	/* Generate stateless reset token */
	get_random_bytes(entry->reset_token, TQUIC_STATELESS_RESET_TOKEN_LEN);

	/* Add to global hash table for packet demux lookup */
	if (cid_table_initialized) {
		ret = rhashtable_insert_fast(&tquic_cid_table, &entry->node,
					     cid_rht_params);
		if (ret < 0) {
			kfree(entry);
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

	pr_debug("tquic: CID pool initialized, initial CID seq=%llu len=%u\n",
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

	spin_lock_bh(&pool->lock);

	/* Remove all local CIDs from hash and free */
	list_for_each_entry_safe(entry, tmp, &pool->local_cids, list) {
		if (cid_table_initialized && entry->state == CID_STATE_ACTIVE)
			rhashtable_remove_fast(&tquic_cid_table, &entry->node,
					       cid_rht_params);
		list_del(&entry->list);
		kfree(entry);
	}

	/* Free remote CIDs (not in global hash) */
	list_for_each_entry_safe(entry, tmp, &pool->remote_cids, list) {
		list_del(&entry->list);
		kfree(entry);
	}

	spin_unlock_bh(&pool->lock);

	kfree(pool);
	conn->cid_pool = NULL;

	pr_debug("tquic: CID pool destroyed\n");
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
		pr_debug("tquic: CID pool at limit (%u)\n", pool->active_count);
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

	/* Generate stateless reset token */
	get_random_bytes(entry->reset_token, TQUIC_STATELESS_RESET_TOKEN_LEN);

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

	pr_debug("tquic: issued new CID seq=%llu, active=%u\n",
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
				pr_debug("tquic: retired CID seq=%llu, active=%u\n",
					 seq_num, pool->active_count);
			}
			found = true;
			break;
		}
	}

	spin_unlock_bh(&pool->lock);

	if (!found) {
		pr_debug("tquic: CID seq=%llu not found for retire\n", seq_num);
		return -ENOENT;
	}

	/* Queue RETIRE_CONNECTION_ID acknowledgment frame */
	tquic_send_retire_connection_id(conn, seq_num);

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

	if (!cid_table_initialized || !cid || cid->len == 0)
		return NULL;

	entry = rhashtable_lookup_fast(&tquic_cid_table, cid, cid_rht_params);
	if (entry && entry->state == CID_STATE_ACTIVE)
		return entry->conn;

	return NULL;
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
			pr_debug("tquic: found CID for migration seq=%llu\n",
				 entry->seq_num);
			break;
		}
	}

	spin_unlock_bh(&pool->lock);

	if (ret < 0)
		pr_debug("tquic: no CID available for migration (need NEW_CONNECTION_ID from peer)\n");

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

	if (!pool)
		return -EINVAL;

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

	list_add(&entry->list, &pool->remote_cids);

	/* Handle retire_prior_to: retire CIDs with seq < retire_prior_to */
	if (retire_prior_to > 0) {
		list_for_each_entry_safe(entry, tmp, &pool->remote_cids, list) {
			if (entry->seq_num < retire_prior_to &&
			    entry->state == CID_STATE_ACTIVE) {
				entry->state = CID_STATE_RETIRED;
				pr_debug("tquic: auto-retired remote CID seq=%llu (prior_to=%llu)\n",
					 entry->seq_num, retire_prior_to);
			}
		}
	}

	spin_unlock_bh(&pool->lock);

	pr_debug("tquic: added remote CID seq=%llu len=%u\n", seq_num, cid->len);

	return 0;
}

/**
 * tquic_send_new_connection_id - Queue NEW_CONNECTION_ID frame
 * @conn: Connection
 * @cid: The new CID to advertise
 * @reset_token: Stateless reset token for the CID
 *
 * Stub implementation - full implementation in Phase 3 (packet I/O).
 * The frame will be built and queued for transmission.
 */
void tquic_send_new_connection_id(struct tquic_connection *conn,
				  const struct tquic_cid *cid,
				  const u8 *reset_token)
{
	/* TODO Phase 3: Build and queue NEW_CONNECTION_ID frame
	 *
	 * Frame format per RFC 9000 Section 19.15:
	 *   Type (i) = 0x18
	 *   Sequence Number (i)
	 *   Retire Prior To (i)
	 *   Length (8) = CID length
	 *   Connection ID (0..20)
	 *   Stateless Reset Token (128) = 16 bytes
	 */
	pr_debug("tquic: NEW_CONNECTION_ID queued (stub) seq=%llu len=%u\n",
		 cid->seq_num, cid->len);
}

/**
 * tquic_send_retire_connection_id - Queue RETIRE_CONNECTION_ID frame
 * @conn: Connection
 * @seq_num: Sequence number of CID to retire
 *
 * Stub implementation - full implementation in Phase 3 (packet I/O).
 */
void tquic_send_retire_connection_id(struct tquic_connection *conn, u64 seq_num)
{
	/* TODO Phase 3: Build and queue RETIRE_CONNECTION_ID frame
	 *
	 * Frame format per RFC 9000 Section 19.16:
	 *   Type (i) = 0x19
	 *   Sequence Number (i)
	 */
	pr_debug("tquic: RETIRE_CONNECTION_ID queued (stub) seq=%llu\n", seq_num);
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
		pr_info("tquic: CID hash table initialized\n");
	} else {
		pr_err("tquic: failed to init CID hash table: %d\n", ret);
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
		pr_info("tquic: CID hash table destroyed\n");
	}
}
