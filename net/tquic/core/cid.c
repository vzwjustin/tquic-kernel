// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Connection ID Management
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Connection ID management is critical for QUIC connection migration and
 * multipath support. This module handles:
 * - Local CID generation with cryptographic randomness
 * - Local CID pool management
 * - Remote CID tracking
 * - NEW_CONNECTION_ID frame generation
 * - RETIRE_CONNECTION_ID handling
 * - Stateless reset token generation and validation
 * - CID rotation logic
 * - Per-path CID assignment for multipath WAN bonding
 * - CID-to-connection lookup via rhashtable
 * - Preferred address CID handling
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/rhashtable.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <linux/refcount.h>
#include <crypto/hash.h>
#include <crypto/hmac.h>
#include <crypto/utils.h>
#include <net/tquic.h>

/* CID pool configuration */
#define TQUIC_CID_POOL_MIN		4	/* Minimum CIDs to maintain */
#define TQUIC_CID_POOL_MAX		16	/* Maximum CIDs per connection */
#define TQUIC_CID_POOL_THRESHOLD	2	/* Replenish when below this */
#define TQUIC_CID_RETIRE_DELAY_MS	100	/* Delay before retiring CIDs */

/* Stateless reset token size (RFC 9000) */
#define TQUIC_RESET_TOKEN_LEN		16

/* CID rotation configuration */
#define TQUIC_CID_ROTATION_INTERVAL_MS	60000	/* Rotate every 60 seconds */
#define TQUIC_CID_ROTATION_PACKETS	100000	/* Or every 100k packets */

/* Static key for HMAC-based token generation */
static u8 tquic_cid_secret[32];
static bool tquic_cid_secret_initialized;
static DEFINE_SPINLOCK(tquic_cid_secret_lock);

/* Global CID lookup table */
static struct rhashtable tquic_cid_table;
static bool tquic_cid_table_initialized;
static DEFINE_MUTEX(tquic_cid_table_lock);

/* Slab cache for CID entries */
static struct kmem_cache *tquic_cid_cache;

/**
 * struct tquic_cid_entry - A single connection ID entry
 * @cid: The connection ID value
 * @seq_num: Sequence number of this CID
 * @retire_prior_to: Retire CIDs with sequence number less than this
 * @reset_token: Stateless reset token for this CID
 * @conn: Associated connection
 * @path: Associated path (for multipath)
 * @state: CID state (active, pending retirement, retired)
 * @created: Time when CID was created
 * @last_used: Time when CID was last used
 * @packets_used: Number of packets using this CID
 * @node: Hash table node for CID lookup
 * @list: List linkage for pool management
 * @refcnt: Reference count
 * @is_local: True if this is a local CID (we generated it)
 */
struct tquic_cid_entry {
	struct tquic_cid cid;
	u64 seq_num;
	u64 retire_prior_to;
	u8 reset_token[TQUIC_RESET_TOKEN_LEN];

	struct tquic_connection *conn;
	struct tquic_path *path;

	enum {
		TQUIC_CID_STATE_ACTIVE = 0,
		TQUIC_CID_STATE_PENDING_RETIRE,
		TQUIC_CID_STATE_RETIRED,
		TQUIC_CID_STATE_ISSUED,	/* Sent to peer but not yet active */
	} state;

	ktime_t created;
	ktime_t last_used;
	u64 packets_used;

	struct rhash_head node;
	struct list_head list;
	refcount_t refcnt;
	bool is_local;
};

/**
 * struct tquic_cid_manager - Per-connection CID management state
 * @conn: Parent connection
 * @local_cids: Pool of local CIDs we've issued
 * @remote_cids: Pool of remote CIDs we've received
 * @local_cid_count: Number of local CIDs in pool
 * @remote_cid_count: Number of remote CIDs in pool
 * @next_local_seq: Next sequence number for local CIDs
 * @next_remote_seq: Expected next sequence from peer
 * @retire_prior_to_send: Value to send in NEW_CONNECTION_ID
 * @retire_prior_to_recv: Received retire_prior_to from peer
 * @active_local_cid: Currently active local CID
 * @active_remote_cid: Currently active remote CID
 * @preferred_addr_cid: CID for preferred address (server)
 * @lock: Protects CID pool access
 * @rotation_timer: Timer for CID rotation
 * @rotation_work: Work for CID rotation
 * @packets_since_rotation: Packets since last rotation
 * @rotation_enabled: Whether automatic rotation is enabled
 * @path_cid_map: Map of paths to their assigned CIDs
 * @cid_len: Length of CIDs to generate
 */
struct tquic_cid_manager {
	struct tquic_connection *conn;

	struct list_head local_cids;
	struct list_head remote_cids;
	u32 local_cid_count;
	u32 remote_cid_count;

	u64 next_local_seq;
	u64 next_remote_seq;
	u64 retire_prior_to_send;
	u64 retire_prior_to_recv;

	struct tquic_cid_entry *active_local_cid;
	struct tquic_cid_entry *active_remote_cid;
	struct tquic_cid_entry *preferred_addr_cid;

	spinlock_t lock;

	struct timer_list rotation_timer;
	struct work_struct rotation_work;
	u64 packets_since_rotation;
	bool rotation_enabled;

	/* Per-path CID assignments for multipath */
	struct tquic_cid_entry *path_local_cids[TQUIC_MAX_PATHS];
	struct tquic_cid_entry *path_remote_cids[TQUIC_MAX_PATHS];

	u8 cid_len;
};

/* Hash table parameters for CID lookup */
static u32 tquic_cid_hash(const void *data, u32 len, u32 seed)
{
	const struct tquic_cid *cid = data;

	return jhash(cid->id, cid->len, seed);
}

static u32 tquic_cid_entry_hash(const void *data, u32 len, u32 seed)
{
	const struct tquic_cid_entry *entry = data;

	return jhash(entry->cid.id, entry->cid.len, seed);
}

static int tquic_cid_compare(struct rhashtable_compare_arg *arg,
			     const void *obj)
{
	const struct tquic_cid *cid = arg->key;
	const struct tquic_cid_entry *entry = obj;

	if (cid->len != entry->cid.len)
		return 1;

	return memcmp(cid->id, entry->cid.id, cid->len);
}

static const struct rhashtable_params tquic_cid_table_params = {
	.key_len = sizeof(struct tquic_cid),
	.key_offset = offsetof(struct tquic_cid_entry, cid),
	.head_offset = offsetof(struct tquic_cid_entry, node),
	.hashfn = tquic_cid_hash,
	.obj_hashfn = tquic_cid_entry_hash,
	.obj_cmpfn = tquic_cid_compare,
	.automatic_shrinking = true,
};

/*
 * Initialize the global CID secret used for token generation
 */
static void tquic_cid_init_secret(void)
{
	spin_lock(&tquic_cid_secret_lock);
	if (!tquic_cid_secret_initialized) {
		get_random_bytes(tquic_cid_secret, sizeof(tquic_cid_secret));
		tquic_cid_secret_initialized = true;
	}
	spin_unlock(&tquic_cid_secret_lock);
}

/**
 * tquic_cid_generate - Generate a new random connection ID
 * @cid: Output CID structure
 * @len: Desired CID length (0-20 bytes)
 *
 * Generates a cryptographically random connection ID.
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_cid_generate(struct tquic_cid *cid, u8 len)
{
	if (len > TQUIC_MAX_CID_LEN)
		return -EINVAL;

	memset(cid, 0, sizeof(*cid));
	cid->len = len;

	if (len > 0)
		get_random_bytes(cid->id, len);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_cid_generate);

/**
 * tquic_cid_generate_reset_token - Generate stateless reset token
 * @cid: Connection ID to derive token from
 * @token: Output buffer for token (TQUIC_RESET_TOKEN_LEN bytes)
 *
 * Generates a deterministic stateless reset token using HMAC-SHA256.
 * The same CID always produces the same token.
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_cid_generate_reset_token(const struct tquic_cid *cid, u8 *token)
{
	struct crypto_shash *tfm;
	SHASH_DESC_ON_STACK(desc, tfm);
	u8 hmac_out[32];
	int ret;

	tquic_cid_init_secret();

	tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	desc->tfm = tfm;

	ret = crypto_shash_setkey(tfm, tquic_cid_secret,
				  sizeof(tquic_cid_secret));
	if (ret)
		goto out;

	ret = crypto_shash_init(desc);
	if (ret)
		goto out;

	/* Include CID length and value in HMAC input */
	ret = crypto_shash_update(desc, &cid->len, sizeof(cid->len));
	if (ret)
		goto out;

	if (cid->len > 0) {
		ret = crypto_shash_update(desc, cid->id, cid->len);
		if (ret)
			goto out;
	}

	ret = crypto_shash_final(desc, hmac_out);
	if (ret)
		goto out;

	/* Use first 16 bytes of HMAC as reset token */
	memcpy(token, hmac_out, TQUIC_RESET_TOKEN_LEN);

out:
	crypto_free_shash(tfm);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_cid_generate_reset_token);

/**
 * tquic_cid_validate_reset_token - Validate a stateless reset token
 * @cid: Connection ID the token should match
 * @token: Token to validate
 *
 * Return: true if token is valid, false otherwise
 */
bool tquic_cid_validate_reset_token(const struct tquic_cid *cid,
				    const u8 *token)
{
	u8 expected[TQUIC_RESET_TOKEN_LEN];
	int ret;

	ret = tquic_cid_generate_reset_token(cid, expected);
	if (ret)
		return false;

	return crypto_memneq(token, expected, TQUIC_RESET_TOKEN_LEN) == 0;
}
EXPORT_SYMBOL_GPL(tquic_cid_validate_reset_token);

/*
 * Allocate a new CID entry
 */
static struct tquic_cid_entry *tquic_cid_entry_alloc(gfp_t gfp)
{
	struct tquic_cid_entry *entry;

	entry = kmem_cache_zalloc(tquic_cid_cache, gfp);
	if (!entry)
		return NULL;

	INIT_LIST_HEAD(&entry->list);
	refcount_set(&entry->refcnt, 1);
	entry->created = ktime_get();
	entry->state = TQUIC_CID_STATE_ACTIVE;

	return entry;
}

/*
 * Free a CID entry
 */
static void tquic_cid_entry_free(struct tquic_cid_entry *entry)
{
	if (!entry)
		return;

	kmem_cache_free(tquic_cid_cache, entry);
}

/*
 * Get a reference to a CID entry
 */
static void tquic_cid_entry_get(struct tquic_cid_entry *entry)
{
	refcount_inc(&entry->refcnt);
}

/*
 * Put a reference to a CID entry
 */
static void tquic_cid_entry_put(struct tquic_cid_entry *entry)
{
	if (refcount_dec_and_test(&entry->refcnt))
		tquic_cid_entry_free(entry);
}

/**
 * tquic_cid_lookup - Look up a connection by CID
 * @cid: Connection ID to look up
 *
 * Performs a fast hash table lookup to find the connection
 * associated with a connection ID.
 *
 * Return: Connection pointer with reference, or NULL if not found
 */
struct tquic_connection *tquic_cid_lookup(const struct tquic_cid *cid)
{
	struct tquic_cid_entry *entry;

	if (!tquic_cid_table_initialized)
		return NULL;

	rcu_read_lock();
	entry = rhashtable_lookup(&tquic_cid_table, cid,
				  tquic_cid_table_params);
	if (entry && entry->conn) {
		struct tquic_connection *conn = entry->conn;

		/* Take reference on connection */
		if (refcount_inc_not_zero(&conn->refcnt)) {
			rcu_read_unlock();
			return conn;
		}
	}
	rcu_read_unlock();

	return NULL;
}
EXPORT_SYMBOL_GPL(tquic_cid_lookup);

/**
 * tquic_cid_lookup_entry - Look up a CID entry
 * @cid: Connection ID to look up
 *
 * Return: CID entry with reference, or NULL if not found
 */
struct tquic_cid_entry *tquic_cid_lookup_entry(const struct tquic_cid *cid)
{
	struct tquic_cid_entry *entry;

	if (!tquic_cid_table_initialized)
		return NULL;

	rcu_read_lock();
	entry = rhashtable_lookup(&tquic_cid_table, cid,
				  tquic_cid_table_params);
	if (entry)
		tquic_cid_entry_get(entry);
	rcu_read_unlock();

	return entry;
}
EXPORT_SYMBOL_GPL(tquic_cid_lookup_entry);

/*
 * Register a CID in the global lookup table
 */
static int tquic_cid_register(struct tquic_cid_entry *entry)
{
	int ret;

	if (!tquic_cid_table_initialized)
		return -ENODEV;

	ret = rhashtable_insert_fast(&tquic_cid_table, &entry->node,
				     tquic_cid_table_params);
	if (ret)
		pr_debug("tquic_cid: failed to register CID (err=%d)\n", ret);

	return ret;
}

/*
 * Unregister a CID from the global lookup table
 */
static void tquic_cid_unregister(struct tquic_cid_entry *entry)
{
	if (!tquic_cid_table_initialized)
		return;

	rhashtable_remove_fast(&tquic_cid_table, &entry->node,
			       tquic_cid_table_params);
}

/*
 * Create a new local CID for the connection
 */
static struct tquic_cid_entry *tquic_cid_create_local(
	struct tquic_cid_manager *mgr)
{
	struct tquic_cid_entry *entry;
	int ret;

	entry = tquic_cid_entry_alloc(GFP_KERNEL);
	if (!entry)
		return NULL;

	/* Generate random CID */
	ret = tquic_cid_generate(&entry->cid, mgr->cid_len);
	if (ret) {
		tquic_cid_entry_free(entry);
		return NULL;
	}

	entry->seq_num = mgr->next_local_seq++;
	entry->cid.seq_num = entry->seq_num;
	entry->conn = mgr->conn;
	entry->is_local = true;

	/* Generate stateless reset token */
	ret = tquic_cid_generate_reset_token(&entry->cid, entry->reset_token);
	if (ret) {
		tquic_cid_entry_free(entry);
		return NULL;
	}

	/* Register in global table */
	ret = tquic_cid_register(entry);
	if (ret) {
		tquic_cid_entry_free(entry);
		return NULL;
	}

	return entry;
}

/**
 * tquic_cid_manager_create - Create CID manager for a connection
 * @conn: The connection
 * @cid_len: Desired CID length
 *
 * Return: CID manager pointer, or NULL on failure
 */
struct tquic_cid_manager *tquic_cid_manager_create(
	struct tquic_connection *conn, u8 cid_len)
{
	struct tquic_cid_manager *mgr;
	struct tquic_cid_entry *entry;
	int i;

	if (cid_len > TQUIC_MAX_CID_LEN)
		return NULL;

	mgr = kzalloc(sizeof(*mgr), GFP_KERNEL);
	if (!mgr)
		return NULL;

	mgr->conn = conn;
	mgr->cid_len = cid_len;
	spin_lock_init(&mgr->lock);
	INIT_LIST_HEAD(&mgr->local_cids);
	INIT_LIST_HEAD(&mgr->remote_cids);

	/* Initialize path CID map */
	for (i = 0; i < TQUIC_MAX_PATHS; i++) {
		mgr->path_local_cids[i] = NULL;
		mgr->path_remote_cids[i] = NULL;
	}

	/* Create initial local CID pool */
	for (i = 0; i < TQUIC_CID_POOL_MIN; i++) {
		entry = tquic_cid_create_local(mgr);
		if (!entry) {
			pr_warn("tquic_cid: failed to create initial CID %d\n", i);
			continue;
		}

		list_add_tail(&entry->list, &mgr->local_cids);
		mgr->local_cid_count++;

		/* First CID becomes active */
		if (!mgr->active_local_cid)
			mgr->active_local_cid = entry;
	}

	if (mgr->local_cid_count == 0) {
		kfree(mgr);
		return NULL;
	}

	pr_debug("tquic_cid: created manager with %u local CIDs\n",
		 mgr->local_cid_count);

	return mgr;
}
EXPORT_SYMBOL_GPL(tquic_cid_manager_create);

/**
 * tquic_cid_manager_destroy - Destroy CID manager
 * @mgr: CID manager to destroy
 */
void tquic_cid_manager_destroy(struct tquic_cid_manager *mgr)
{
	struct tquic_cid_entry *entry, *tmp;

	if (!mgr)
		return;

	/* Cancel rotation timer */
	del_timer_sync(&mgr->rotation_timer);

	spin_lock(&mgr->lock);

	/* Free all local CIDs */
	list_for_each_entry_safe(entry, tmp, &mgr->local_cids, list) {
		list_del(&entry->list);
		tquic_cid_unregister(entry);
		tquic_cid_entry_put(entry);
	}

	/* Free all remote CIDs */
	list_for_each_entry_safe(entry, tmp, &mgr->remote_cids, list) {
		list_del(&entry->list);
		tquic_cid_entry_put(entry);
	}

	spin_unlock(&mgr->lock);

	kfree(mgr);
}
EXPORT_SYMBOL_GPL(tquic_cid_manager_destroy);

/**
 * tquic_cid_pool_replenish - Ensure CID pool has enough entries
 * @mgr: CID manager
 *
 * Called periodically or after CID retirement to maintain pool.
 *
 * Return: Number of CIDs added
 */
int tquic_cid_pool_replenish(struct tquic_cid_manager *mgr)
{
	struct tquic_cid_entry *entry;
	int added = 0;

	spin_lock(&mgr->lock);

	while (mgr->local_cid_count < TQUIC_CID_POOL_MIN &&
	       mgr->local_cid_count < TQUIC_CID_POOL_MAX) {
		spin_unlock(&mgr->lock);

		entry = tquic_cid_create_local(mgr);
		if (!entry) {
			spin_lock(&mgr->lock);
			break;
		}

		spin_lock(&mgr->lock);
		list_add_tail(&entry->list, &mgr->local_cids);
		mgr->local_cid_count++;
		added++;
	}

	spin_unlock(&mgr->lock);

	if (added > 0)
		pr_debug("tquic_cid: replenished pool with %d CIDs\n", added);

	return added;
}
EXPORT_SYMBOL_GPL(tquic_cid_pool_replenish);

/**
 * tquic_cid_get_unused_local - Get an unused local CID
 * @mgr: CID manager
 *
 * Returns a local CID that is not currently assigned to any path.
 *
 * Return: CID entry with reference, or NULL if none available
 */
struct tquic_cid_entry *tquic_cid_get_unused_local(struct tquic_cid_manager *mgr)
{
	struct tquic_cid_entry *entry;

	spin_lock(&mgr->lock);

	list_for_each_entry(entry, &mgr->local_cids, list) {
		if (entry->state == TQUIC_CID_STATE_ACTIVE && !entry->path) {
			tquic_cid_entry_get(entry);
			spin_unlock(&mgr->lock);
			return entry;
		}
	}

	spin_unlock(&mgr->lock);

	/* Try to replenish pool */
	tquic_cid_pool_replenish(mgr);

	spin_lock(&mgr->lock);
	list_for_each_entry(entry, &mgr->local_cids, list) {
		if (entry->state == TQUIC_CID_STATE_ACTIVE && !entry->path) {
			tquic_cid_entry_get(entry);
			spin_unlock(&mgr->lock);
			return entry;
		}
	}
	spin_unlock(&mgr->lock);

	return NULL;
}
EXPORT_SYMBOL_GPL(tquic_cid_get_unused_local);

/**
 * struct tquic_new_cid_frame - NEW_CONNECTION_ID frame data
 * @seq_num: Sequence number of this CID
 * @retire_prior_to: Peer should retire CIDs before this sequence
 * @cid: The connection ID
 * @reset_token: Stateless reset token
 */
struct tquic_new_cid_frame {
	u64 seq_num;
	u64 retire_prior_to;
	struct tquic_cid cid;
	u8 reset_token[TQUIC_RESET_TOKEN_LEN];
};

/**
 * tquic_cid_build_new_cid_frame - Build a NEW_CONNECTION_ID frame
 * @mgr: CID manager
 * @frame: Output frame structure
 *
 * Prepares data for a NEW_CONNECTION_ID frame to send to the peer.
 *
 * Return: 0 on success, negative error if no CID available
 */
int tquic_cid_build_new_cid_frame(struct tquic_cid_manager *mgr,
				  struct tquic_new_cid_frame *frame)
{
	struct tquic_cid_entry *entry;

	spin_lock(&mgr->lock);

	/* Find an issued CID that hasn't been sent yet, or create new */
	list_for_each_entry(entry, &mgr->local_cids, list) {
		if (entry->state == TQUIC_CID_STATE_ISSUED) {
			goto found;
		}
	}

	/* Need to create a new CID */
	spin_unlock(&mgr->lock);
	entry = tquic_cid_create_local(mgr);
	if (!entry)
		return -ENOMEM;

	spin_lock(&mgr->lock);
	list_add_tail(&entry->list, &mgr->local_cids);
	mgr->local_cid_count++;
	entry->state = TQUIC_CID_STATE_ISSUED;

found:
	frame->seq_num = entry->seq_num;
	frame->retire_prior_to = mgr->retire_prior_to_send;
	memcpy(&frame->cid, &entry->cid, sizeof(frame->cid));
	memcpy(frame->reset_token, entry->reset_token, TQUIC_RESET_TOKEN_LEN);

	spin_unlock(&mgr->lock);

	pr_debug("tquic_cid: built NEW_CONNECTION_ID frame seq=%llu\n",
		 frame->seq_num);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_cid_build_new_cid_frame);

/**
 * tquic_cid_handle_new_cid - Handle received NEW_CONNECTION_ID frame
 * @mgr: CID manager
 * @seq_num: Sequence number from frame
 * @retire_prior_to: Retire prior to value from frame
 * @cid: Connection ID from frame
 * @reset_token: Stateless reset token from frame
 *
 * Processes a NEW_CONNECTION_ID frame from the peer.
 *
 * Return: 0 on success, negative error on failure
 */
int tquic_cid_handle_new_cid(struct tquic_cid_manager *mgr,
			     u64 seq_num, u64 retire_prior_to,
			     const struct tquic_cid *cid,
			     const u8 *reset_token)
{
	struct tquic_cid_entry *entry, *tmp;
	int ret = 0;

	/* Validate retire_prior_to */
	if (retire_prior_to > seq_num) {
		pr_warn("tquic_cid: invalid retire_prior_to > seq_num\n");
		return -EINVAL;
	}

	spin_lock(&mgr->lock);

	/* Check for duplicate */
	list_for_each_entry(entry, &mgr->remote_cids, list) {
		if (entry->seq_num == seq_num) {
			/* Verify CID matches */
			if (cid->len != entry->cid.len ||
			    memcmp(cid->id, entry->cid.id, cid->len) != 0) {
				ret = -EINVAL;
				goto out;
			}
			/* Duplicate, ignore */
			goto out;
		}
	}

	/* Check pool limit */
	if (mgr->remote_cid_count >= TQUIC_CID_POOL_MAX) {
		pr_warn("tquic_cid: remote CID pool full\n");
		ret = -ENOSPC;
		goto out;
	}

	/* Create new entry */
	spin_unlock(&mgr->lock);
	entry = tquic_cid_entry_alloc(GFP_KERNEL);
	if (!entry)
		return -ENOMEM;

	memcpy(&entry->cid, cid, sizeof(entry->cid));
	entry->seq_num = seq_num;
	entry->cid.seq_num = seq_num;
	entry->retire_prior_to = retire_prior_to;
	memcpy(entry->reset_token, reset_token, TQUIC_RESET_TOKEN_LEN);
	entry->conn = mgr->conn;
	entry->is_local = false;

	spin_lock(&mgr->lock);

	/* Insert in sequence order */
	list_for_each_entry(tmp, &mgr->remote_cids, list) {
		if (seq_num < tmp->seq_num) {
			list_add_tail(&entry->list, &tmp->list);
			goto added;
		}
	}
	list_add_tail(&entry->list, &mgr->remote_cids);

added:
	mgr->remote_cid_count++;

	/* Update retire_prior_to */
	if (retire_prior_to > mgr->retire_prior_to_recv)
		mgr->retire_prior_to_recv = retire_prior_to;

	/* Retire old CIDs */
	list_for_each_entry_safe(entry, tmp, &mgr->remote_cids, list) {
		if (entry->seq_num < mgr->retire_prior_to_recv &&
		    entry->state == TQUIC_CID_STATE_ACTIVE) {
			entry->state = TQUIC_CID_STATE_PENDING_RETIRE;
			pr_debug("tquic_cid: marking remote CID seq=%llu for retirement\n",
				 entry->seq_num);
		}
	}

	/* Set active remote CID if needed */
	if (!mgr->active_remote_cid) {
		list_for_each_entry(entry, &mgr->remote_cids, list) {
			if (entry->state == TQUIC_CID_STATE_ACTIVE) {
				mgr->active_remote_cid = entry;
				break;
			}
		}
	}

out:
	spin_unlock(&mgr->lock);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_cid_handle_new_cid);

/**
 * struct tquic_retire_cid_frame - RETIRE_CONNECTION_ID frame data
 * @seq_num: Sequence number of CID to retire
 */
struct tquic_retire_cid_frame {
	u64 seq_num;
};

/**
 * tquic_cid_build_retire_frame - Build RETIRE_CONNECTION_ID frame
 * @mgr: CID manager
 * @frame: Output frame structure
 *
 * Finds a local CID that should be retired and builds the frame.
 *
 * Return: 0 on success, -ENOENT if nothing to retire
 */
int tquic_cid_build_retire_frame(struct tquic_cid_manager *mgr,
				 struct tquic_retire_cid_frame *frame)
{
	struct tquic_cid_entry *entry;

	spin_lock(&mgr->lock);

	list_for_each_entry(entry, &mgr->remote_cids, list) {
		if (entry->state == TQUIC_CID_STATE_PENDING_RETIRE) {
			frame->seq_num = entry->seq_num;
			spin_unlock(&mgr->lock);

			pr_debug("tquic_cid: built RETIRE_CONNECTION_ID seq=%llu\n",
				 frame->seq_num);
			return 0;
		}
	}

	spin_unlock(&mgr->lock);
	return -ENOENT;
}
EXPORT_SYMBOL_GPL(tquic_cid_build_retire_frame);

/**
 * tquic_cid_handle_retire - Handle received RETIRE_CONNECTION_ID frame
 * @mgr: CID manager
 * @seq_num: Sequence number to retire
 *
 * Processes a RETIRE_CONNECTION_ID frame from the peer.
 *
 * Return: 0 on success, negative error on failure
 */
int tquic_cid_handle_retire(struct tquic_cid_manager *mgr, u64 seq_num)
{
	struct tquic_cid_entry *entry, *tmp;
	bool found = false;

	spin_lock(&mgr->lock);

	/* Cannot retire CID that hasn't been issued */
	if (seq_num >= mgr->next_local_seq) {
		spin_unlock(&mgr->lock);
		pr_warn("tquic_cid: retire request for unissued seq=%llu\n",
			seq_num);
		return -EINVAL;
	}

	/* Find and retire the CID */
	list_for_each_entry_safe(entry, tmp, &mgr->local_cids, list) {
		if (entry->seq_num == seq_num) {
			found = true;

			/* Don't retire if it's the only active CID */
			if (entry == mgr->active_local_cid &&
			    mgr->local_cid_count <= 1) {
				spin_unlock(&mgr->lock);
				pr_warn("tquic_cid: cannot retire last CID\n");
				return -EINVAL;
			}

			entry->state = TQUIC_CID_STATE_RETIRED;

			/* Update active if needed */
			if (entry == mgr->active_local_cid) {
				mgr->active_local_cid = NULL;
				list_for_each_entry(tmp, &mgr->local_cids, list) {
					if (tmp->state == TQUIC_CID_STATE_ACTIVE) {
						mgr->active_local_cid = tmp;
						break;
					}
				}
			}

			/* Remove from path assignment */
			if (entry->path) {
				int i;
				for (i = 0; i < TQUIC_MAX_PATHS; i++) {
					if (mgr->path_local_cids[i] == entry)
						mgr->path_local_cids[i] = NULL;
				}
			}

			/* Remove from table and free */
			list_del(&entry->list);
			mgr->local_cid_count--;
			tquic_cid_unregister(entry);
			tquic_cid_entry_put(entry);

			break;
		}
	}

	spin_unlock(&mgr->lock);

	if (!found) {
		pr_debug("tquic_cid: retire request for unknown seq=%llu\n",
			 seq_num);
		return 0;  /* Not an error per RFC 9000 */
	}

	pr_debug("tquic_cid: retired local CID seq=%llu\n", seq_num);

	/* Replenish pool */
	tquic_cid_pool_replenish(mgr);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_cid_handle_retire);

/**
 * tquic_cid_complete_retire - Complete pending CID retirement
 * @mgr: CID manager
 * @seq_num: Sequence number that was acknowledged
 *
 * Called when peer acknowledges our RETIRE_CONNECTION_ID frame.
 */
void tquic_cid_complete_retire(struct tquic_cid_manager *mgr, u64 seq_num)
{
	struct tquic_cid_entry *entry, *tmp;

	spin_lock(&mgr->lock);

	list_for_each_entry_safe(entry, tmp, &mgr->remote_cids, list) {
		if (entry->seq_num == seq_num &&
		    entry->state == TQUIC_CID_STATE_PENDING_RETIRE) {
			entry->state = TQUIC_CID_STATE_RETIRED;
			list_del(&entry->list);
			mgr->remote_cid_count--;
			tquic_cid_entry_put(entry);

			pr_debug("tquic_cid: completed retirement of remote CID seq=%llu\n",
				 seq_num);
			break;
		}
	}

	spin_unlock(&mgr->lock);
}
EXPORT_SYMBOL_GPL(tquic_cid_complete_retire);

/*
 * CID rotation timer callback
 */
static void tquic_cid_rotation_timer(struct timer_list *t)
{
	struct tquic_cid_manager *mgr = from_timer(mgr, t, rotation_timer);

	schedule_work(&mgr->rotation_work);
}

/*
 * CID rotation work handler
 */
static void tquic_cid_rotation_work(struct work_struct *work)
{
	struct tquic_cid_manager *mgr = container_of(work,
						     struct tquic_cid_manager,
						     rotation_work);
	struct tquic_cid_entry *old_cid, *new_cid;

	spin_lock(&mgr->lock);

	if (!mgr->rotation_enabled) {
		spin_unlock(&mgr->lock);
		return;
	}

	old_cid = mgr->active_local_cid;
	new_cid = NULL;

	/* Find next available CID */
	if (old_cid) {
		struct tquic_cid_entry *entry;
		bool found_current = false;

		list_for_each_entry(entry, &mgr->local_cids, list) {
			if (entry == old_cid) {
				found_current = true;
				continue;
			}
			if (found_current && entry->state == TQUIC_CID_STATE_ACTIVE) {
				new_cid = entry;
				break;
			}
		}

		/* Wrap around if needed */
		if (!new_cid) {
			list_for_each_entry(entry, &mgr->local_cids, list) {
				if (entry != old_cid &&
				    entry->state == TQUIC_CID_STATE_ACTIVE) {
					new_cid = entry;
					break;
				}
			}
		}
	}

	if (new_cid) {
		mgr->active_local_cid = new_cid;
		mgr->packets_since_rotation = 0;

		/* Mark old CID for retirement after delay */
		if (old_cid && old_cid != new_cid) {
			old_cid->state = TQUIC_CID_STATE_PENDING_RETIRE;
			mgr->retire_prior_to_send = old_cid->seq_num + 1;
		}

		pr_debug("tquic_cid: rotated from seq=%llu to seq=%llu\n",
			 old_cid ? old_cid->seq_num : 0, new_cid->seq_num);
	}

	spin_unlock(&mgr->lock);

	/* Replenish pool */
	tquic_cid_pool_replenish(mgr);

	/* Reschedule timer */
	if (mgr->rotation_enabled) {
		mod_timer(&mgr->rotation_timer,
			  jiffies + msecs_to_jiffies(TQUIC_CID_ROTATION_INTERVAL_MS));
	}
}

/**
 * tquic_cid_enable_rotation - Enable automatic CID rotation
 * @mgr: CID manager
 */
void tquic_cid_enable_rotation(struct tquic_cid_manager *mgr)
{
	spin_lock(&mgr->lock);

	if (mgr->rotation_enabled) {
		spin_unlock(&mgr->lock);
		return;
	}

	mgr->rotation_enabled = true;
	INIT_WORK(&mgr->rotation_work, tquic_cid_rotation_work);
	timer_setup(&mgr->rotation_timer, tquic_cid_rotation_timer, 0);

	spin_unlock(&mgr->lock);

	mod_timer(&mgr->rotation_timer,
		  jiffies + msecs_to_jiffies(TQUIC_CID_ROTATION_INTERVAL_MS));

	pr_debug("tquic_cid: enabled CID rotation\n");
}
EXPORT_SYMBOL_GPL(tquic_cid_enable_rotation);

/**
 * tquic_cid_disable_rotation - Disable automatic CID rotation
 * @mgr: CID manager
 */
void tquic_cid_disable_rotation(struct tquic_cid_manager *mgr)
{
	spin_lock(&mgr->lock);
	mgr->rotation_enabled = false;
	spin_unlock(&mgr->lock);

	del_timer_sync(&mgr->rotation_timer);
	cancel_work_sync(&mgr->rotation_work);

	pr_debug("tquic_cid: disabled CID rotation\n");
}
EXPORT_SYMBOL_GPL(tquic_cid_disable_rotation);

/**
 * tquic_cid_rotate_now - Force immediate CID rotation
 * @mgr: CID manager
 *
 * Return: 0 on success, negative error if rotation not possible
 */
int tquic_cid_rotate_now(struct tquic_cid_manager *mgr)
{
	/* Trigger rotation work immediately */
	schedule_work(&mgr->rotation_work);
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_cid_rotate_now);

/**
 * tquic_cid_on_packet_sent - Update CID state on packet transmission
 * @mgr: CID manager
 *
 * Called when a packet is sent, may trigger rotation.
 */
void tquic_cid_on_packet_sent(struct tquic_cid_manager *mgr)
{
	spin_lock(&mgr->lock);

	mgr->packets_since_rotation++;

	if (mgr->active_local_cid)
		mgr->active_local_cid->packets_used++;

	/* Check if packet-based rotation threshold reached */
	if (mgr->rotation_enabled &&
	    mgr->packets_since_rotation >= TQUIC_CID_ROTATION_PACKETS) {
		spin_unlock(&mgr->lock);
		schedule_work(&mgr->rotation_work);
		return;
	}

	spin_unlock(&mgr->lock);
}
EXPORT_SYMBOL_GPL(tquic_cid_on_packet_sent);

/**
 * tquic_cidmgr_assign_to_path - Assign CIDs to a path for multipath
 * @mgr: CID manager
 * @path: Path to assign CIDs to
 *
 * Assigns both local and remote CIDs to a path for multipath operation.
 *
 * Return: 0 on success, negative error on failure
 */
int tquic_cidmgr_assign_to_path(struct tquic_cid_manager *mgr,
			     struct tquic_path *path)
{
	struct tquic_cid_entry *local_entry = NULL;
	struct tquic_cid_entry *remote_entry = NULL;
	struct tquic_cid_entry *entry;

	if (path->path_id >= TQUIC_MAX_PATHS)
		return -EINVAL;

	spin_lock(&mgr->lock);

	/* Find unused local CID */
	list_for_each_entry(entry, &mgr->local_cids, list) {
		if (entry->state == TQUIC_CID_STATE_ACTIVE && !entry->path) {
			local_entry = entry;
			break;
		}
	}

	/* Find unused remote CID */
	list_for_each_entry(entry, &mgr->remote_cids, list) {
		if (entry->state == TQUIC_CID_STATE_ACTIVE && !entry->path) {
			remote_entry = entry;
			break;
		}
	}

	if (!local_entry) {
		spin_unlock(&mgr->lock);

		/* Try to get more local CIDs */
		tquic_cid_pool_replenish(mgr);

		spin_lock(&mgr->lock);
		list_for_each_entry(entry, &mgr->local_cids, list) {
			if (entry->state == TQUIC_CID_STATE_ACTIVE && !entry->path) {
				local_entry = entry;
				break;
			}
		}

		if (!local_entry) {
			spin_unlock(&mgr->lock);
			pr_warn("tquic_cid: no local CID available for path %u\n",
				path->path_id);
			return -ENOSPC;
		}
	}

	/* Assign CIDs to path */
	local_entry->path = path;
	mgr->path_local_cids[path->path_id] = local_entry;
	memcpy(&path->local_cid, &local_entry->cid, sizeof(path->local_cid));

	if (remote_entry) {
		remote_entry->path = path;
		mgr->path_remote_cids[path->path_id] = remote_entry;
		memcpy(&path->remote_cid, &remote_entry->cid,
		       sizeof(path->remote_cid));
	}

	spin_unlock(&mgr->lock);

	pr_debug("tquic_cid: assigned CIDs to path %u (local seq=%llu)\n",
		 path->path_id, local_entry->seq_num);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_cidmgr_assign_to_path);

/**
 * tquic_cidmgr_release_from_path - Release CIDs from a path
 * @mgr: CID manager
 * @path: Path to release CIDs from
 */
void tquic_cidmgr_release_from_path(struct tquic_cid_manager *mgr,
				 struct tquic_path *path)
{
	struct tquic_cid_entry *entry;

	if (path->path_id >= TQUIC_MAX_PATHS)
		return;

	spin_lock(&mgr->lock);

	entry = mgr->path_local_cids[path->path_id];
	if (entry) {
		entry->path = NULL;
		mgr->path_local_cids[path->path_id] = NULL;
	}

	entry = mgr->path_remote_cids[path->path_id];
	if (entry) {
		entry->path = NULL;
		mgr->path_remote_cids[path->path_id] = NULL;
	}

	spin_unlock(&mgr->lock);

	pr_debug("tquic_cid: released CIDs from path %u\n", path->path_id);
}
EXPORT_SYMBOL_GPL(tquic_cidmgr_release_from_path);

/**
 * tquic_cid_get_for_path - Get the local CID for a specific path
 * @mgr: CID manager
 * @path_id: Path identifier
 *
 * Return: Pointer to CID, or NULL if not assigned
 */
const struct tquic_cid *tquic_cid_get_for_path(struct tquic_cid_manager *mgr,
					       u32 path_id)
{
	struct tquic_cid_entry *entry;
	const struct tquic_cid *cid = NULL;

	if (path_id >= TQUIC_MAX_PATHS)
		return NULL;

	spin_lock(&mgr->lock);
	entry = mgr->path_local_cids[path_id];
	if (entry)
		cid = &entry->cid;
	spin_unlock(&mgr->lock);

	return cid;
}
EXPORT_SYMBOL_GPL(tquic_cid_get_for_path);

/**
 * tquic_cid_set_preferred_addr - Set CID for preferred address
 * @mgr: CID manager
 * @cid: Connection ID for preferred address
 * @reset_token: Stateless reset token
 *
 * Used by servers to set the CID included in the preferred_address
 * transport parameter.
 *
 * Return: 0 on success, negative error on failure
 */
int tquic_cid_set_preferred_addr(struct tquic_cid_manager *mgr,
				 const struct tquic_cid *cid,
				 const u8 *reset_token)
{
	struct tquic_cid_entry *entry;
	int ret;

	entry = tquic_cid_entry_alloc(GFP_KERNEL);
	if (!entry)
		return -ENOMEM;

	memcpy(&entry->cid, cid, sizeof(entry->cid));
	entry->seq_num = mgr->next_local_seq++;
	entry->cid.seq_num = entry->seq_num;
	entry->conn = mgr->conn;
	entry->is_local = true;

	if (reset_token) {
		memcpy(entry->reset_token, reset_token, TQUIC_RESET_TOKEN_LEN);
	} else {
		ret = tquic_cid_generate_reset_token(cid, entry->reset_token);
		if (ret) {
			tquic_cid_entry_free(entry);
			return ret;
		}
	}

	ret = tquic_cid_register(entry);
	if (ret) {
		tquic_cid_entry_free(entry);
		return ret;
	}

	spin_lock(&mgr->lock);

	/* Free old preferred address CID if any */
	if (mgr->preferred_addr_cid) {
		tquic_cid_unregister(mgr->preferred_addr_cid);
		tquic_cid_entry_put(mgr->preferred_addr_cid);
	}

	mgr->preferred_addr_cid = entry;
	list_add_tail(&entry->list, &mgr->local_cids);
	mgr->local_cid_count++;

	spin_unlock(&mgr->lock);

	pr_debug("tquic_cid: set preferred address CID seq=%llu\n",
		 entry->seq_num);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_cid_set_preferred_addr);

/**
 * tquic_cid_handle_preferred_addr - Handle preferred address from server
 * @mgr: CID manager
 * @cid: Connection ID from preferred_address parameter
 * @reset_token: Stateless reset token from parameter
 *
 * Called by clients when processing server's preferred_address transport
 * parameter.
 *
 * Return: 0 on success, negative error on failure
 */
int tquic_cid_handle_preferred_addr(struct tquic_cid_manager *mgr,
				    const struct tquic_cid *cid,
				    const u8 *reset_token)
{
	/* Treat as a NEW_CONNECTION_ID with sequence 1 */
	return tquic_cid_handle_new_cid(mgr, 1, 0, cid, reset_token);
}
EXPORT_SYMBOL_GPL(tquic_cid_handle_preferred_addr);

/**
 * tquic_cid_get_active_local - Get the active local CID
 * @mgr: CID manager
 *
 * Return: Pointer to active local CID, or NULL
 */
const struct tquic_cid *tquic_cid_get_active_local(struct tquic_cid_manager *mgr)
{
	const struct tquic_cid *cid = NULL;

	spin_lock(&mgr->lock);
	if (mgr->active_local_cid)
		cid = &mgr->active_local_cid->cid;
	spin_unlock(&mgr->lock);

	return cid;
}
EXPORT_SYMBOL_GPL(tquic_cid_get_active_local);

/**
 * tquic_cid_get_active_remote - Get the active remote CID
 * @mgr: CID manager
 *
 * Return: Pointer to active remote CID, or NULL
 */
const struct tquic_cid *tquic_cid_get_active_remote(struct tquic_cid_manager *mgr)
{
	const struct tquic_cid *cid = NULL;

	spin_lock(&mgr->lock);
	if (mgr->active_remote_cid)
		cid = &mgr->active_remote_cid->cid;
	spin_unlock(&mgr->lock);

	return cid;
}
EXPORT_SYMBOL_GPL(tquic_cid_get_active_remote);

/**
 * tquic_cid_set_active_remote - Set the active remote CID
 * @mgr: CID manager
 * @cid: CID to make active
 *
 * Return: 0 on success, -ENOENT if CID not found
 */
int tquic_cid_set_active_remote(struct tquic_cid_manager *mgr,
				const struct tquic_cid *cid)
{
	struct tquic_cid_entry *entry;
	int ret = -ENOENT;

	spin_lock(&mgr->lock);

	list_for_each_entry(entry, &mgr->remote_cids, list) {
		if (entry->cid.len == cid->len &&
		    memcmp(entry->cid.id, cid->id, cid->len) == 0) {
			if (entry->state == TQUIC_CID_STATE_ACTIVE) {
				mgr->active_remote_cid = entry;
				ret = 0;
			}
			break;
		}
	}

	spin_unlock(&mgr->lock);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_cid_set_active_remote);

/**
 * tquic_cid_get_reset_token - Get reset token for a local CID
 * @mgr: CID manager
 * @cid: Connection ID
 * @token: Output buffer for token
 *
 * Return: 0 on success, -ENOENT if CID not found
 */
int tquic_cid_get_reset_token(struct tquic_cid_manager *mgr,
			      const struct tquic_cid *cid,
			      u8 *token)
{
	struct tquic_cid_entry *entry;
	int ret = -ENOENT;

	spin_lock(&mgr->lock);

	list_for_each_entry(entry, &mgr->local_cids, list) {
		if (entry->cid.len == cid->len &&
		    memcmp(entry->cid.id, cid->id, cid->len) == 0) {
			memcpy(token, entry->reset_token, TQUIC_RESET_TOKEN_LEN);
			ret = 0;
			break;
		}
	}

	spin_unlock(&mgr->lock);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_cid_get_reset_token);

/**
 * tquic_cid_check_stateless_reset - Check if packet is a stateless reset
 * @mgr: CID manager
 * @token: Last 16 bytes of received packet
 *
 * Return: true if token matches any of our remote CIDs
 */
bool tquic_cid_check_stateless_reset(struct tquic_cid_manager *mgr,
				     const u8 *token)
{
	struct tquic_cid_entry *entry;
	bool found = false;

	spin_lock(&mgr->lock);

	list_for_each_entry(entry, &mgr->remote_cids, list) {
		if (crypto_memneq(token, entry->reset_token,
				  TQUIC_RESET_TOKEN_LEN) == 0) {
			found = true;
			break;
		}
	}

	spin_unlock(&mgr->lock);

	if (found)
		pr_debug("tquic_cid: detected stateless reset\n");

	return found;
}
EXPORT_SYMBOL_GPL(tquic_cid_check_stateless_reset);

/**
 * tquic_cid_get_stats - Get CID manager statistics
 * @mgr: CID manager
 * @local_count: Output for local CID count
 * @remote_count: Output for remote CID count
 * @local_seq: Output for next local sequence
 */
void tquic_cid_get_stats(struct tquic_cid_manager *mgr,
			 u32 *local_count, u32 *remote_count,
			 u64 *local_seq)
{
	spin_lock(&mgr->lock);

	if (local_count)
		*local_count = mgr->local_cid_count;
	if (remote_count)
		*remote_count = mgr->remote_cid_count;
	if (local_seq)
		*local_seq = mgr->next_local_seq;

	spin_unlock(&mgr->lock);
}
EXPORT_SYMBOL_GPL(tquic_cid_get_stats);

/**
 * tquic_cid_compare - Compare two connection IDs
 * @a: First CID
 * @b: Second CID
 *
 * Return: 0 if equal, non-zero if different
 */
int tquic_cid_cmp(const struct tquic_cid *a, const struct tquic_cid *b)
{
	if (a->len != b->len)
		return a->len - b->len;

	return memcmp(a->id, b->id, a->len);
}
EXPORT_SYMBOL_GPL(tquic_cid_cmp);

/**
 * tquic_cid_copy - Copy a connection ID
 * @dst: Destination CID
 * @src: Source CID
 */
void tquic_cid_copy(struct tquic_cid *dst, const struct tquic_cid *src)
{
	memcpy(dst, src, sizeof(*dst));
}
EXPORT_SYMBOL_GPL(tquic_cid_copy);

/**
 * tquic_cid_is_zero - Check if CID is zero-length
 * @cid: CID to check
 *
 * Return: true if zero-length
 */
bool tquic_cid_is_zero(const struct tquic_cid *cid)
{
	return cid->len == 0;
}
EXPORT_SYMBOL_GPL(tquic_cid_is_zero);

/*
 * Module initialization
 */
int __init tquic_cid_init(void)
{
	int ret;

	/* Initialize global CID secret */
	tquic_cid_init_secret();

	/* Create slab cache */
	tquic_cid_cache = kmem_cache_create("tquic_cid_entry",
					    sizeof(struct tquic_cid_entry),
					    0, SLAB_HWCACHE_ALIGN, NULL);
	if (!tquic_cid_cache) {
		pr_err("tquic_cid: failed to create slab cache\n");
		return -ENOMEM;
	}

	/* Initialize global CID lookup table */
	mutex_lock(&tquic_cid_table_lock);
	ret = rhashtable_init(&tquic_cid_table, &tquic_cid_table_params);
	if (ret) {
		mutex_unlock(&tquic_cid_table_lock);
		kmem_cache_destroy(tquic_cid_cache);
		pr_err("tquic_cid: failed to init CID table\n");
		return ret;
	}
	tquic_cid_table_initialized = true;
	mutex_unlock(&tquic_cid_table_lock);

	pr_info("tquic_cid: CID management subsystem initialized\n");
	return 0;
}

/*
 * Module cleanup
 */
void __exit tquic_cid_exit(void)
{
	mutex_lock(&tquic_cid_table_lock);
	if (tquic_cid_table_initialized) {
		rhashtable_destroy(&tquic_cid_table);
		tquic_cid_table_initialized = false;
	}
	mutex_unlock(&tquic_cid_table_lock);

	if (tquic_cid_cache)
		kmem_cache_destroy(tquic_cid_cache);

	pr_info("tquic_cid: CID management subsystem cleaned up\n");
}

MODULE_DESCRIPTION("TQUIC Connection ID Management");
MODULE_LICENSE("GPL");
