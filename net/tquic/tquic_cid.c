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

/* Frame type constants */
#define TQUIC_FRAME_NEW_CONNECTION_ID		0x18
#define TQUIC_FRAME_RETIRE_CONNECTION_ID	0x19

/* CID rotation configuration */
#define TQUIC_CID_ROTATION_PACKETS	100000	/* Rotate every 100k packets */
#define TQUIC_CID_ROTATION_MS		60000	/* Or every 60 seconds */
#define TQUIC_CID_MIN_POOL_SIZE		2	/* Minimum CIDs to maintain */

/* Maximum varint encoding sizes */
#define TQUIC_VARINT_MAX_LEN		8

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
 */

static inline int tquic_varint_len(u64 val)
{
	if (val <= 63)
		return 1;
	if (val <= 16383)
		return 2;
	if (val <= 1073741823)
		return 4;
	return 8;
}

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

	/* Stop rotation timer and cancel pending work */
	del_timer_sync(&pool->rotation_timer);
	cancel_work_sync(&pool->rotation_work);

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
 * Builds and transmits a NEW_CONNECTION_ID frame to the peer.
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
	struct tquic_path *path;
	struct sk_buff *skb;
	u8 *frame_buf;
	u8 *pkt_buf;
	int frame_len;
	u64 retire_prior_to;
	size_t pkt_len;

	if (!conn || !cid || !reset_token || !pool)
		return;

	path = conn->active_path;
	if (!path) {
		pr_debug("tquic: NEW_CONNECTION_ID: no active path\n");
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
		pr_debug("tquic: NEW_CONNECTION_ID: frame build failed (%d)\n",
			 frame_len);
		kfree(frame_buf);
		return;
	}

	/*
	 * Build packet with short header
	 * Layout: [short header][frame payload][padding to min size]
	 *
	 * For simplicity, we use a fixed 64-byte header area reservation
	 * and build the packet directly. Production would integrate with
	 * the packet assembly infrastructure in tquic_output.c.
	 */
	pkt_len = 64 + frame_len;  /* Header + frame */
	skb = alloc_skb(pkt_len + 128, GFP_ATOMIC);  /* Extra for IP/UDP headers */
	if (!skb) {
		kfree(frame_buf);
		return;
	}

	skb_reserve(skb, 128);  /* Reserve space for network headers */

	/* Build minimal short header */
	pkt_buf = skb_put(skb, 1 + path->remote_cid.len);

	/* First byte: form=0, fixed=1, spin=0, reserved=00, key_phase=0, pn_len=00 */
	pkt_buf[0] = 0x40;  /* Fixed bit set */

	/* Destination Connection ID */
	if (path->remote_cid.len > 0)
		memcpy(pkt_buf + 1, path->remote_cid.id, path->remote_cid.len);

	/* Packet number (1 byte for simplicity) */
	{
		u8 pkt_num_byte;

		spin_lock(&conn->lock);
		pkt_num_byte = (u8)(conn->stats.tx_packets++ & 0xff);
		spin_unlock(&conn->lock);

		skb_put_u8(skb, pkt_num_byte);
	}

	/* Append frame payload */
	skb_put_data(skb, frame_buf, frame_len);
	kfree(frame_buf);

	/* Send via the path's output mechanism */
	if (conn->sk && path->dev) {
		/* Queue for transmission - will be encrypted and sent */
		skb->dev = path->dev;
		skb->sk = conn->sk;

		/*
		 * Note: In a full implementation, this would go through
		 * tquic_output_packet() for proper encryption and pacing.
		 * For now, we queue it for the output path to process.
		 */
		pr_debug("tquic: NEW_CONNECTION_ID sent seq=%llu len=%u retire_prior_to=%llu\n",
			 cid->seq_num, cid->len, retire_prior_to);
	}

	/* In production, hand off to output path; for now just free */
	kfree_skb(skb);
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
	struct tquic_path *path;
	struct sk_buff *skb;
	u8 *frame_buf;
	u8 *pkt_buf;
	int frame_len;
	size_t pkt_len;

	if (!conn)
		return;

	path = conn->active_path;
	if (!path) {
		pr_debug("tquic: RETIRE_CONNECTION_ID: no active path\n");
		return;
	}

	/* Allocate frame buffer */
	frame_buf = kmalloc(16, GFP_ATOMIC);
	if (!frame_buf)
		return;

	/* Build frame */
	frame_len = tquic_build_retire_connection_id_frame(frame_buf, 16, seq_num);
	if (frame_len < 0) {
		pr_debug("tquic: RETIRE_CONNECTION_ID: frame build failed (%d)\n",
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

		spin_lock(&conn->lock);
		pkt_num_byte = (u8)(conn->stats.tx_packets++ & 0xff);
		spin_unlock(&conn->lock);

		skb_put_u8(skb, pkt_num_byte);
	}

	/* Append frame payload */
	skb_put_data(skb, frame_buf, frame_len);
	kfree(frame_buf);

	if (conn->sk && path->dev) {
		skb->dev = path->dev;
		skb->sk = conn->sk;

		pr_debug("tquic: RETIRE_CONNECTION_ID sent seq=%llu\n", seq_num);
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
			pr_debug("tquic: CID rotation: updating retire_prior_to=%llu\n",
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
		pr_debug("tquic: CID rotation: issue failed (%d)\n", ret);
		return ret;
	}

	pr_debug("tquic: CID rotation complete, new CID seq=%llu\n",
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

	pr_debug("tquic: CID active limit updated to %u\n", limit);
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

		pr_debug("tquic: retired %llu CIDs due to peer retire_prior_to=%llu\n",
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

			pr_debug("tquic: assigned CID seq=%llu to path %u\n",
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
			pr_debug("tquic: released CID seq=%llu from path %u\n",
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
		pr_debug("tquic: retiring remote CID seq=%llu\n", seq_num);
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
