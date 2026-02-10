// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Path Abandonment Logic for QUIC Multipath
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Implementation of path abandonment for QUIC Multipath Extension (RFC 9369).
 * This module handles:
 *   - PATH_ABANDON frame processing
 *   - Path abandonment initiation
 *   - Graceful path closure
 *   - Connection ID retirement on path abandonment
 *   - Path status updates
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/workqueue.h>
#include <linux/timer.h>
#include <linux/random.h>
#include <net/tquic.h>

#include "../tquic_compat.h"
#include "../tquic_debug.h"

#include "mp_frame.h"
#include "path_abandon.h"

/*
 * Path abandonment error codes (RFC 9369)
 */
#define TQUIC_MP_PATH_ERR_NONE			0x00
#define TQUIC_MP_PATH_ERR_ADMIN_SHUTDOWN	0x01
#define TQUIC_MP_PATH_ERR_INTERFACE_DOWN	0x02
#define TQUIC_MP_PATH_ERR_PATH_FAILED		0x03
#define TQUIC_MP_PATH_ERR_CAPACITY_EXCEEDED	0x04
#define TQUIC_MP_PATH_ERR_INTERNAL		0x05

/*
 * Path abandonment states
 */
enum tquic_mp_abandon_state {
	TQUIC_MP_ABANDON_NONE = 0,	/* No abandonment in progress */
	TQUIC_MP_ABANDON_PENDING,	/* PATH_ABANDON sent, awaiting ack */
	TQUIC_MP_ABANDON_RECEIVED,	/* PATH_ABANDON received from peer */
	TQUIC_MP_ABANDON_COMPLETE,	/* Path fully abandoned */
};

/*
 * Path status sequence tracking
 */
struct tquic_mp_path_status_seq {
	u64 local_seq;		/* Local sequence number for PATH_STATUS */
	u64 remote_seq;		/* Last received PATH_STATUS sequence */
	u64 last_status;	/* Last reported status */
	u64 last_priority;	/* Last reported priority */
};

/**
 * struct tquic_mp_path_abandon_state - Per-path abandonment state
 * @path: Associated path
 * @path_id: Path identifier
 * @abandon_state: Current abandonment state
 * @error_code: Error code for abandonment
 * @reason: Reason phrase for abandonment
 * @reason_len: Length of reason phrase
 * @status_seq: PATH_STATUS sequence tracking
 * @cids_to_retire: List of CIDs to retire on abandonment
 * @num_cids_to_retire: Number of CIDs to retire
 * @abandon_timer: Timer for abandonment timeout
 * @work: Work item for deferred processing
 * @lock: Spinlock for synchronization
 */
struct tquic_mp_path_abandon_state {
	struct tquic_path *path;
	u64 path_id;
	enum tquic_mp_abandon_state abandon_state;
	u64 error_code;
	u8 reason[TQUIC_MP_MAX_REASON_LEN];
	u64 reason_len;
	struct tquic_mp_path_status_seq status_seq;
	struct list_head cids_to_retire;
	u32 num_cids_to_retire;
	struct timer_list abandon_timer;
	struct work_struct work;
	spinlock_t lock;
};

/**
 * struct tquic_mp_cid_retire_entry - CID to retire on abandonment
 * @path_id: Path the CID belongs to
 * @seq_num: Sequence number of the CID
 * @list: List linkage
 */
struct tquic_mp_cid_retire_entry {
	u64 path_id;
	u64 seq_num;
	struct list_head list;
};

/**
 * struct tquic_mp_remote_cid - Remote CID entry for multipath
 * @seq_num: Sequence number of this CID
 * @path_id: Path this CID is associated with
 * @cid_len: Length of the connection ID
 * @cid: The connection ID bytes
 * @reset_token: Stateless reset token (16 bytes)
 * @retired: Whether this CID has been retired
 * @list: List linkage
 *
 * Tracks remote CIDs received via MP_NEW_CONNECTION_ID frames.
 * Per RFC 9000 Section 5.1.2, we must track all CIDs and retire
 * those with sequence numbers below retire_prior_to.
 */
struct tquic_mp_remote_cid {
	u64 seq_num;
	u64 path_id;
	u8 cid_len;
	u8 cid[TQUIC_MAX_CID_LEN];
	u8 reset_token[TQUIC_MP_RESET_TOKEN_LEN];
	bool retired;
	struct list_head list;
};

/**
 * struct tquic_mp_local_cid - Local CID entry for multipath
 * @seq_num: Sequence number of this CID
 * @path_id: Path this CID is associated with
 * @cid_len: Length of the connection ID
 * @cid: The connection ID bytes
 * @reset_token: Stateless reset token (16 bytes)
 * @retired: Whether peer has retired this CID
 * @list: List linkage
 *
 * Tracks local CIDs we've issued via MP_NEW_CONNECTION_ID frames.
 * When peer sends MP_RETIRE_CONNECTION_ID, we mark the CID as retired
 * and may issue a replacement.
 */
struct tquic_mp_local_cid {
	u64 seq_num;
	u64 path_id;
	u8 cid_len;
	u8 cid[TQUIC_MAX_CID_LEN];
	u8 reset_token[TQUIC_MP_RESET_TOKEN_LEN];
	bool retired;
	struct list_head list;
};

/**
 * struct tquic_mp_cid_state - Per-path CID management state for multipath
 * @remote_cids: List of remote CIDs (received from peer)
 * @local_cids: List of local CIDs (issued to peer)
 * @pending_retirements: Queue of RETIRE_CONNECTION_ID frames to send
 * @remote_cid_count: Number of active remote CIDs
 * @local_cid_count: Number of active local CIDs
 * @next_local_seq: Next sequence number for local CIDs
 * @retire_prior_to: Latest retire_prior_to received from peer
 * @lock: Spinlock for CID state access
 *
 * Manages CID pools for multipath connections. Each path can have
 * multiple CIDs, and the retire_prior_to mechanism ensures CID
 * retirement happens atomically across the connection.
 */
struct tquic_mp_cid_state {
	struct list_head remote_cids;
	struct list_head local_cids;
	struct list_head pending_retirements;
	u32 remote_cid_count;
	u32 local_cid_count;
	u64 next_local_seq;
	u64 retire_prior_to;
	spinlock_t lock;
};

/* Memory cache for CID entries */
static struct kmem_cache *mp_remote_cid_cache;
static struct kmem_cache *mp_local_cid_cache;

/* Memory caches */
static struct kmem_cache *mp_abandon_state_cache;
static struct kmem_cache *mp_cid_retire_cache;
static struct kmem_cache *mp_cid_state_cache;

/* SKB reserve size for QUIC packet headers */
#define TQUIC_SKB_RESERVE	128

/*
 * =============================================================================
 * Helper Functions
 * =============================================================================
 */

/**
 * tquic_mp_send_control_frame - Send a control frame on a path
 * @conn: Connection
 * @path: Path to send on
 * @frame_buf: Encoded frame data
 * @frame_len: Length of frame data
 *
 * Helper function to encapsulate the common logic for creating and
 * transmitting a QUIC packet containing a control frame. This consolidates
 * duplicated code from tquic_mp_initiate_path_abandon, tquic_mp_retire_path_cids,
 * tquic_mp_issue_path_cid, and tquic_mp_send_path_status.
 *
 * tquic_build_short_header builds the complete packet (header + payload)
 * into a buffer, so we pass the frame data as the payload parameter.
 *
 * Returns 0 on success or negative error code on failure.
 */
static int tquic_mp_send_control_frame(struct tquic_connection *conn,
				       struct tquic_path *path,
				       const u8 *frame_buf, int frame_len)
{
	struct sk_buff *skb;
	int pkt_len;
	u8 *pkt_buf;
	size_t pkt_buf_len;
	u64 pkt_num;
	int pn_len;
	int ret;

	if (!conn || !path || !frame_buf || frame_len <= 0)
		return -EINVAL;

	/* Get packet number atomically */
	spin_lock_bh(&conn->lock);
	pkt_num = conn->stats.tx_packets++;
	spin_unlock_bh(&conn->lock);

	/* Calculate packet number length (1-4 bytes based on value) */
	if (pkt_num < 0x100)
		pn_len = 1;
	else if (pkt_num < 0x10000)
		pn_len = 2;
	else if (pkt_num < 0x1000000)
		pn_len = 3;
	else
		pn_len = 4;

	/*
	 * Calculate buffer size for packet:
	 * - 1 byte first byte
	 * - dcid_len bytes for DCID
	 * - pn_len bytes for packet number
	 * - frame_len bytes for payload
	 */
	pkt_buf_len = 1 + conn->dcid.len + pn_len + frame_len;
	pkt_buf = kmalloc(pkt_buf_len, GFP_KERNEL);
	if (!pkt_buf)
		return -ENOMEM;

	/* Build complete short header packet (header + payload) */
	pkt_len = tquic_build_short_header(conn->dcid.id, conn->dcid.len,
					   pkt_num, pn_len,
					   0, 0,  /* key_phase, spin_bit */
					   frame_buf, frame_len,
					   pkt_buf, pkt_buf_len);
	if (pkt_len < 0) {
		kfree(pkt_buf);
		return pkt_len;
	}

	/* Allocate skb for the complete packet */
	skb = alloc_skb(pkt_len + MAX_HEADER, GFP_KERNEL);
	if (!skb) {
		kfree(pkt_buf);
		return -ENOMEM;
	}

	skb_reserve(skb, MAX_HEADER);
	skb_put_data(skb, pkt_buf, pkt_len);
	kfree(pkt_buf);

	ret = tquic_output_packet(conn, path, skb);
	if (ret < 0) {
		pr_debug("tquic_mp: failed to send control frame: %d\n", ret);
		return ret;
	}

	return 0;
}

/*
 * =============================================================================
 * Path Abandonment State Management
 * =============================================================================
 */

/**
 * tquic_mp_abandon_state_create - Create path abandonment state
 * @path: Path to create state for
 *
 * Returns allocated state or NULL on failure.
 */
struct tquic_mp_path_abandon_state *tquic_mp_abandon_state_create(
	struct tquic_path *path)
{
	struct tquic_mp_path_abandon_state *state;

	state = kmem_cache_zalloc(mp_abandon_state_cache, GFP_KERNEL);
	if (!state)
		return NULL;

	state->path = path;
	state->path_id = path ? path->path_id : 0;
	state->abandon_state = TQUIC_MP_ABANDON_NONE;
	INIT_LIST_HEAD(&state->cids_to_retire);
	spin_lock_init(&state->lock);

	pr_debug("tquic_mp: created abandonment state for path %llu\n",
		 state->path_id);

	return state;
}
EXPORT_SYMBOL_GPL(tquic_mp_abandon_state_create);

/**
 * tquic_mp_abandon_state_destroy - Destroy path abandonment state
 * @state: State to destroy
 */
void tquic_mp_abandon_state_destroy(struct tquic_mp_path_abandon_state *state)
{
	struct tquic_mp_cid_retire_entry *entry, *tmp;

	if (!state)
		return;

	del_timer_sync(&state->abandon_timer);

	spin_lock_bh(&state->lock);

	/* Free CID retire entries */
	list_for_each_entry_safe(entry, tmp, &state->cids_to_retire, list) {
		list_del(&entry->list);
		kmem_cache_free(mp_cid_retire_cache, entry);
	}

	spin_unlock_bh(&state->lock);

	kmem_cache_free(mp_abandon_state_cache, state);
}
EXPORT_SYMBOL_GPL(tquic_mp_abandon_state_destroy);

/*
 * =============================================================================
 * PATH_ABANDON Frame Processing
 * =============================================================================
 */

/**
 * tquic_mp_handle_path_abandon - Handle received PATH_ABANDON frame
 * @conn: Connection
 * @frame: Parsed PATH_ABANDON frame
 *
 * RFC 9369 Section 5.3: When a PATH_ABANDON frame is received, the endpoint
 * MUST stop using the path for new data transmission and SHOULD retire
 * connection IDs associated with the path.
 *
 * Returns 0 on success or negative error.
 */
int tquic_mp_handle_path_abandon(struct tquic_connection *conn,
				 const struct tquic_mp_path_abandon *frame)
{
	struct tquic_path *path;
	struct tquic_mp_path_abandon_state *abandon_state;
	bool found = false;

	if (!conn || !frame)
		return -EINVAL;

	pr_debug("tquic_mp: received PATH_ABANDON for path %llu, error=%llu\n",
		 frame->path_id, frame->error_code);

	/* Find the path */
	spin_lock(&conn->paths_lock);
	list_for_each_entry(path, &conn->paths, list) {
		if (path->path_id == frame->path_id) {
			found = true;
			break;
		}
	}
	spin_unlock(&conn->paths_lock);

	if (!found) {
		pr_debug("tquic_mp: PATH_ABANDON for unknown path %llu\n",
			 frame->path_id);
		/* RFC 9369: Ignore PATH_ABANDON for unknown paths */
		return 0;
	}

	/* Get or create abandonment state */
	abandon_state = path->abandon_state;
	if (!abandon_state) {
		abandon_state = tquic_mp_abandon_state_create(path);
		if (!abandon_state)
			return -ENOMEM;
		path->abandon_state = abandon_state;
	}

	spin_lock(&abandon_state->lock);

	/* Check if already abandoned */
	if (abandon_state->abandon_state == TQUIC_MP_ABANDON_COMPLETE) {
		spin_unlock(&abandon_state->lock);
		return 0;
	}

	/* Store abandonment info */
	abandon_state->error_code = frame->error_code;
	abandon_state->reason_len = min_t(u64, frame->reason_len,
					  TQUIC_MP_MAX_REASON_LEN);
	if (abandon_state->reason_len > 0)
		memcpy(abandon_state->reason, frame->reason,
		       abandon_state->reason_len);

	abandon_state->abandon_state = TQUIC_MP_ABANDON_RECEIVED;

	spin_unlock(&abandon_state->lock);

	/* Mark path as closed */
	path->state = TQUIC_PATH_CLOSED;

	/* Retire CIDs associated with this path */
	tquic_mp_retire_path_cids(conn, path);

	/* Check if this was the active path */
	if (conn->active_path == path) {
		/* Select a new active path */
		tquic_mp_select_new_active_path(conn, path);
	}

	tquic_warn("path %llu abandoned by peer (error=%llu)\n",
		   frame->path_id, frame->error_code);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_mp_handle_path_abandon);

/**
 * tquic_mp_initiate_path_abandon - Initiate path abandonment
 * @conn: Connection
 * @path: Path to abandon
 * @error_code: Error code for abandonment
 * @reason: Reason phrase (can be NULL)
 * @reason_len: Length of reason phrase
 *
 * Initiates abandonment of a path by sending PATH_ABANDON frame.
 *
 * Returns 0 on success or negative error.
 */
int tquic_mp_initiate_path_abandon(struct tquic_connection *conn,
				   struct tquic_path *path,
				   u64 error_code,
				   const char *reason, size_t reason_len)
{
	struct tquic_mp_path_abandon_state *abandon_state;
	struct tquic_mp_path_abandon frame;
	u8 buf[256];
	int len;

	if (!conn || !path)
		return -EINVAL;

	/* Get or create abandonment state */
	abandon_state = path->abandon_state;
	if (!abandon_state) {
		abandon_state = tquic_mp_abandon_state_create(path);
		if (!abandon_state)
			return -ENOMEM;
		path->abandon_state = abandon_state;
	}

	spin_lock_bh(&abandon_state->lock);

	/* Check if already abandoning */
	if (abandon_state->abandon_state != TQUIC_MP_ABANDON_NONE) {
		spin_unlock_bh(&abandon_state->lock);
		return -EALREADY;
	}

	abandon_state->abandon_state = TQUIC_MP_ABANDON_PENDING;
	abandon_state->error_code = error_code;

	spin_unlock_bh(&abandon_state->lock);

	/* Build PATH_ABANDON frame */
	memset(&frame, 0, sizeof(frame));
	frame.path_id = path->path_id;
	frame.error_code = error_code;

	if (reason && reason_len > 0) {
		frame.reason_len = min_t(size_t, reason_len,
					 TQUIC_MP_MAX_REASON_LEN);
		memcpy(frame.reason, reason, frame.reason_len);
	}

	/* Encode frame */
	len = tquic_mp_write_path_abandon(&frame, buf, sizeof(buf));
	if (len < 0)
		return len;

	/* Send PATH_ABANDON via active path (not the path being abandoned) */
	{
		int ret = tquic_mp_send_control_frame(conn, conn->active_path,
						      buf, len);
		if (ret < 0) {
			pr_warn("tquic_mp: failed to send PATH_ABANDON: %d\n",
				ret);
			return ret;
		}
	}

	pr_debug("tquic_mp: sent PATH_ABANDON for path %u (error=%llu)\n",
		 path->path_id, error_code);

	/* Mark path for closing */
	path->state = TQUIC_PATH_CLOSED;

	/* Update connection stats */
	if (conn->active_path == path) {
		tquic_mp_select_new_active_path(conn, path);
	}

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_mp_initiate_path_abandon);

/*
 * =============================================================================
 * Connection ID Management for Multipath
 * =============================================================================
 */

/**
 * tquic_mp_retire_path_cids - Retire CIDs associated with a path
 * @conn: Connection
 * @path: Path whose CIDs to retire
 *
 * When a path is abandoned, all connection IDs associated with that path
 * should be retired (RFC 9369).
 *
 * Returns 0 on success or negative error.
 */
int tquic_mp_retire_path_cids(struct tquic_connection *conn,
			      struct tquic_path *path)
{
	struct tquic_mp_retire_connection_id frame;
	u8 buf[32];
	int len;

	if (!conn || !path)
		return -EINVAL;

	/* Build MP_RETIRE_CONNECTION_ID frame for local CID */
	memset(&frame, 0, sizeof(frame));
	frame.path_id = path->path_id;
	frame.seq_num = path->local_cid.seq_num;

	len = tquic_mp_write_retire_connection_id(&frame, buf, sizeof(buf));
	if (len < 0)
		return len;

	pr_debug("tquic_mp: retiring CID seq=%llu for path %llu\n",
		 frame.seq_num, frame.path_id);

	/* Send MP_RETIRE_CONNECTION_ID via active path */
	return tquic_mp_send_control_frame(conn, conn->active_path, buf, len);
}
EXPORT_SYMBOL_GPL(tquic_mp_retire_path_cids);

/**
 * tquic_mp_issue_path_cid - Issue a new CID for a path
 * @conn: Connection
 * @path: Path to issue CID for
 *
 * Issues a new connection ID specific to a path using MP_NEW_CONNECTION_ID.
 *
 * Returns 0 on success or negative error.
 */
int tquic_mp_issue_path_cid(struct tquic_connection *conn,
			    struct tquic_path *path)
{
	struct tquic_mp_new_connection_id frame;
	u8 buf[64];
	int len;

	if (!conn || !path)
		return -EINVAL;

	/* Generate new CID */
	memset(&frame, 0, sizeof(frame));
	frame.path_id = path->path_id;
	frame.seq_num = path->local_cid.seq_num + 1;
	frame.retire_prior_to = path->local_cid.seq_num;
	frame.cid_len = TQUIC_DEFAULT_CID_LEN;

	/* Generate random CID */
	get_random_bytes(frame.cid, frame.cid_len);

	/* Generate stateless reset token */
	get_random_bytes(frame.stateless_reset_token, TQUIC_MP_RESET_TOKEN_LEN);

	/* Encode frame */
	len = tquic_mp_write_new_connection_id(&frame, buf, sizeof(buf));
	if (len < 0)
		return len;

	/* Update path's local CID */
	path->local_cid.seq_num = frame.seq_num;
	memcpy(path->local_cid.id, frame.cid, frame.cid_len);
	path->local_cid.len = frame.cid_len;

	pr_debug("tquic_mp: issued new CID seq=%llu for path %llu\n",
		 frame.seq_num, frame.path_id);

	/* Send MP_NEW_CONNECTION_ID on the path */
	return tquic_mp_send_control_frame(conn, path, buf, len);
}
EXPORT_SYMBOL_GPL(tquic_mp_issue_path_cid);

/**
 * struct tquic_mp_pending_retire - Pending RETIRE_CONNECTION_ID frame
 * @path_id: Path the CID belongs to
 * @seq_num: Sequence number of the CID to retire
 * @list: List linkage for pending retirements queue
 *
 * Tracks CIDs that need RETIRE_CONNECTION_ID frames sent to peer.
 * Per RFC 9000 Section 5.1.2, when we receive a NEW_CONNECTION_ID
 * frame with retire_prior_to, we MUST send RETIRE_CONNECTION_ID
 * for each CID we're retiring.
 */
struct tquic_mp_pending_retire {
	u64 path_id;
	u64 seq_num;
	struct list_head list;
};

/* Memory cache for pending retirement entries */
static struct kmem_cache *mp_pending_retire_cache;

/**
 * tquic_mp_cid_state_create - Create CID state for a path
 * @path: Path to create state for
 *
 * Returns allocated CID state or NULL on failure.
 *
 * Note: This function is provided for future CID pool expansion where
 * multiple CIDs may be tracked per path. Currently unused but reserved
 * for full RFC 9000 multi-CID pool support.
 */
static struct tquic_mp_cid_state * __maybe_unused
tquic_mp_cid_state_create(struct tquic_path *path)
{
	struct tquic_mp_cid_state *state;

	if (!mp_cid_state_cache)
		return NULL;

	state = kmem_cache_zalloc(mp_cid_state_cache, GFP_KERNEL);
	if (!state)
		return NULL;

	INIT_LIST_HEAD(&state->remote_cids);
	INIT_LIST_HEAD(&state->local_cids);
	INIT_LIST_HEAD(&state->pending_retirements);
	spin_lock_init(&state->lock);
	state->retire_prior_to = 0;
	state->next_local_seq = 0;

	return state;
}

/**
 * tquic_mp_cid_state_destroy - Destroy CID state for a path
 * @state: CID state to destroy
 *
 * Note: This function is provided for future CID pool expansion where
 * multiple CIDs may be tracked per path. Currently unused but reserved
 * for full RFC 9000 multi-CID pool support.
 */
static void __maybe_unused
tquic_mp_cid_state_destroy(struct tquic_mp_cid_state *state)
{
	struct tquic_mp_remote_cid *rcid, *rtmp;
	struct tquic_mp_local_cid *lcid, *ltmp;
	struct tquic_mp_pending_retire *pret, *ptmp;

	if (!state)
		return;

	spin_lock_bh(&state->lock);

	/* Free all remote CIDs */
	list_for_each_entry_safe(rcid, rtmp, &state->remote_cids, list) {
		list_del(&rcid->list);
		if (mp_remote_cid_cache)
			kmem_cache_free(mp_remote_cid_cache, rcid);
	}

	/* Free all local CIDs */
	list_for_each_entry_safe(lcid, ltmp, &state->local_cids, list) {
		list_del(&lcid->list);
		if (mp_local_cid_cache)
			kmem_cache_free(mp_local_cid_cache, lcid);
	}

	/* Free all pending retirements */
	list_for_each_entry_safe(pret, ptmp, &state->pending_retirements, list) {
		list_del(&pret->list);
		if (mp_pending_retire_cache)
			kmem_cache_free(mp_pending_retire_cache, pret);
	}

	spin_unlock_bh(&state->lock);

	if (mp_cid_state_cache)
		kmem_cache_free(mp_cid_state_cache, state);
}

/**
 * tquic_mp_get_or_create_cid_state - Get or create CID state for a path
 * @path: Path to get/create CID state for
 *
 * Returns CID state pointer or NULL on failure.
 *
 * Note: This function is provided for future CID pool expansion where
 * multiple CIDs may be tracked per path. Currently returns NULL as we
 * use path->local_cid/remote_cid directly for the simplified single-CID
 * per path model.
 */
static struct tquic_mp_cid_state * __maybe_unused
tquic_mp_get_or_create_cid_state(struct tquic_path *path)
{
	/* For now, we use the path's local/remote CID directly
	 * In a full implementation, each path would have a dedicated
	 * CID state structure. Here we'll allocate one lazily.
	 */
	return NULL;  /* Using path->local_cid/remote_cid directly */
}

/**
 * tquic_mp_send_retire_cid_frame - Send RETIRE_CONNECTION_ID frame
 * @conn: Connection
 * @path_id: Path the CID belongs to
 * @seq_num: Sequence number of CID to retire
 *
 * Builds and sends an MP_RETIRE_CONNECTION_ID frame to notify the peer
 * that we will no longer use the specified CID.
 *
 * Returns 0 on success or negative error.
 */
static int tquic_mp_send_retire_cid_frame(struct tquic_connection *conn,
					  u64 path_id, u64 seq_num)
{
	struct tquic_mp_retire_connection_id frame;
	u8 buf[32];
	int len;

	if (!conn || !conn->active_path)
		return -EINVAL;

	/* Build MP_RETIRE_CONNECTION_ID frame */
	memset(&frame, 0, sizeof(frame));
	frame.path_id = path_id;
	frame.seq_num = seq_num;

	/* Encode frame */
	len = tquic_mp_write_retire_connection_id(&frame, buf, sizeof(buf));
	if (len < 0)
		return len;

	pr_debug("tquic_mp: sending RETIRE_CONNECTION_ID path=%llu seq=%llu\n",
		 path_id, seq_num);

	/* Send via active path */
	return tquic_mp_send_control_frame(conn, conn->active_path, buf, len);
}

/**
 * tquic_mp_retire_cids_prior_to - Retire all CIDs with seq < retire_prior_to
 * @conn: Connection
 * @path: Path whose CIDs to check
 * @retire_prior_to: Sequence number threshold
 *
 * Per RFC 9000 Section 5.1.2, when we receive a NEW_CONNECTION_ID frame
 * with a retire_prior_to value greater than what we've seen before,
 * we MUST:
 * 1. Stop using CIDs with sequence numbers < retire_prior_to
 * 2. Send RETIRE_CONNECTION_ID frames for each such CID
 *
 * Returns number of CIDs retired or negative error.
 */
static int tquic_mp_retire_cids_prior_to(struct tquic_connection *conn,
					 struct tquic_path *path,
					 u64 retire_prior_to)
{
	int retired_count = 0;
	u64 seq;

	if (!conn || !path)
		return -EINVAL;

	/* Check if we need to retire the current remote CID */
	if (path->remote_cid.seq_num < retire_prior_to) {
		/* The current CID needs to be retired - but we should already
		 * have a replacement from the NEW_CONNECTION_ID frame.
		 * Send RETIRE_CONNECTION_ID for the old CID.
		 */
		seq = path->remote_cid.seq_num;

		pr_debug("tquic_mp: retiring current remote CID seq=%llu (prior_to=%llu) on path %u\n",
			 seq, retire_prior_to, path->path_id);

		/* Send RETIRE_CONNECTION_ID frame for the old CID */
		tquic_mp_send_retire_cid_frame(conn, path->path_id, seq);
		retired_count++;
	}

	/*
	 * In a full implementation with CID pools, we would iterate through
	 * all remote CIDs associated with this path and retire those with
	 * seq_num < retire_prior_to. Since we're using the simplified
	 * single-CID-per-path model, we just handle the current CID above.
	 *
	 * For multipath scenarios with multiple CIDs per path, this would
	 * look like:
	 *
	 * spin_lock(&path->cid_state->lock);
	 * list_for_each_entry_safe(rcid, tmp, &path->cid_state->remote_cids, list) {
	 *     if (rcid->seq_num < retire_prior_to && !rcid->retired) {
	 *         rcid->retired = true;
	 *         // Queue RETIRE_CONNECTION_ID frame
	 *         tquic_mp_send_retire_cid_frame(conn, path->path_id, rcid->seq_num);
	 *         retired_count++;
	 *     }
	 * }
	 * spin_unlock(&path->cid_state->lock);
	 */

	return retired_count;
}

/**
 * tquic_mp_handle_new_connection_id - Handle MP_NEW_CONNECTION_ID frame
 * @conn: Connection
 * @frame: Parsed MP_NEW_CONNECTION_ID frame
 *
 * Per RFC 9000 Section 5.1.1 and RFC 9369 for multipath:
 * - Store the new CID for future use on the specified path
 * - The retire_prior_to field indicates CIDs that must be retired
 * - We MUST send RETIRE_CONNECTION_ID for each CID being retired
 *
 * Returns 0 on success or negative error.
 */
int tquic_mp_handle_new_connection_id(struct tquic_connection *conn,
				      const struct tquic_mp_new_connection_id *frame)
{
	struct tquic_path *path;
	bool found = false;
	u64 old_retire_prior_to;
	int ret = 0;

	if (!conn || !frame)
		return -EINVAL;

	/* Validate frame fields per RFC 9000 Section 19.15 */
	if (frame->retire_prior_to > frame->seq_num) {
		pr_warn("tquic_mp: invalid NEW_CONNECTION_ID: retire_prior_to (%llu) > seq_num (%llu)\n",
			frame->retire_prior_to, frame->seq_num);
		return -EINVAL;
	}

	if (frame->cid_len < 1 || frame->cid_len > TQUIC_MAX_CID_LEN) {
		pr_warn("tquic_mp: invalid NEW_CONNECTION_ID: cid_len=%u\n",
			frame->cid_len);
		return -EINVAL;
	}

	pr_debug("tquic_mp: received MP_NEW_CONNECTION_ID path=%llu seq=%llu retire_prior_to=%llu\n",
		 frame->path_id, frame->seq_num, frame->retire_prior_to);

	/* Find the path */
	spin_lock(&conn->paths_lock);
	list_for_each_entry(path, &conn->paths, list) {
		if (path->path_id == frame->path_id) {
			found = true;
			break;
		}
	}

	if (!found) {
		spin_unlock(&conn->paths_lock);
		pr_debug("tquic_mp: MP_NEW_CONNECTION_ID for unknown path %llu\n",
			 frame->path_id);
		return -ENOENT;
	}

	/* Save old retire_prior_to to check if we need to retire CIDs */
	old_retire_prior_to = path->remote_cid.retire_prior_to;

	/* Update remote CID for this path if this is a newer CID */
	if (frame->seq_num > path->remote_cid.seq_num) {
		path->remote_cid.seq_num = frame->seq_num;
		path->remote_cid.len = frame->cid_len;
		memcpy(path->remote_cid.id, frame->cid, frame->cid_len);
		path->remote_cid.retire_prior_to = frame->retire_prior_to;

		pr_debug("tquic_mp: updated remote CID for path %llu: seq=%llu len=%u\n",
			 frame->path_id, frame->seq_num, frame->cid_len);
	}

	spin_unlock(&conn->paths_lock);

	/*
	 * RFC 9000 Section 5.1.2: CID Retirement
	 *
	 * Upon receipt of an increased retire_prior_to field, the peer MUST
	 * stop using the corresponding connection IDs and MUST send
	 * RETIRE_CONNECTION_ID frames to indicate that the CIDs are retired.
	 *
	 * Process CID retirement if retire_prior_to has increased.
	 */
	if (frame->retire_prior_to > old_retire_prior_to) {
		int retired;

		pr_debug("tquic_mp: retire_prior_to increased from %llu to %llu on path %llu\n",
			 old_retire_prior_to, frame->retire_prior_to, frame->path_id);

		retired = tquic_mp_retire_cids_prior_to(conn, path,
						       frame->retire_prior_to);
		if (retired < 0) {
			pr_warn("tquic_mp: CID retirement failed: %d\n", retired);
			ret = retired;
		} else if (retired > 0) {
			pr_debug("tquic_mp: retired %d CIDs on path %llu\n",
				 retired, frame->path_id);
		}
	}

	return ret;
}
EXPORT_SYMBOL_GPL(tquic_mp_handle_new_connection_id);

/**
 * tquic_mp_handle_retire_connection_id - Handle MP_RETIRE_CONNECTION_ID frame
 * @conn: Connection
 * @frame: Parsed MP_RETIRE_CONNECTION_ID frame
 *
 * Per RFC 9000 Section 5.1.2 and RFC 9369 for multipath:
 * - When peer sends RETIRE_CONNECTION_ID, they are indicating they will
 *   no longer use that CID to send packets to us
 * - We SHOULD remove the CID from our local CID set
 * - We MAY issue a new CID to replace the retired one
 *
 * Returns 0 on success or negative error.
 */
int tquic_mp_handle_retire_connection_id(struct tquic_connection *conn,
					 const struct tquic_mp_retire_connection_id *frame)
{
	struct tquic_path *path;
	bool found = false;
	bool cid_matched = false;
	int ret = 0;

	if (!conn || !frame)
		return -EINVAL;

	pr_debug("tquic_mp: received MP_RETIRE_CONNECTION_ID path=%llu seq=%llu\n",
		 frame->path_id, frame->seq_num);

	/* Find the path */
	spin_lock(&conn->paths_lock);
	list_for_each_entry(path, &conn->paths, list) {
		if (path->path_id == frame->path_id) {
			found = true;
			break;
		}
	}

	if (!found) {
		spin_unlock(&conn->paths_lock);
		pr_debug("tquic_mp: MP_RETIRE_CONNECTION_ID for unknown path %llu\n",
			 frame->path_id);
		/*
		 * RFC 9000: If the sequence number refers to a CID that was
		 * not issued, this is a protocol violation. However, we may
		 * have already removed the path, so just log and return.
		 */
		return -ENOENT;
	}

	/*
	 * Check if this retirement request refers to our current local CID.
	 *
	 * Per RFC 9000 Section 5.1.2, an endpoint should not retire a CID
	 * that has not been issued to the peer. Check if seq_num matches
	 * a CID we've issued.
	 */
	if (path->local_cid.seq_num == frame->seq_num) {
		cid_matched = true;
		pr_debug("tquic_mp: peer retiring our CID seq=%llu on path %u\n",
			 frame->seq_num, path->path_id);
	}

	spin_unlock(&conn->paths_lock);

	if (!cid_matched) {
		/*
		 * The sequence number doesn't match our current CID for this path.
		 * This could mean:
		 * 1. The CID was already retired (duplicate frame)
		 * 2. The CID was never issued (protocol violation)
		 *
		 * Per RFC 9000, receiving a RETIRE_CONNECTION_ID for an unknown
		 * sequence number is not necessarily an error - it might be a
		 * duplicate or refer to an already-retired CID.
		 */
		pr_debug("tquic_mp: RETIRE_CONNECTION_ID seq=%llu doesn't match current CID seq=%llu\n",
			 frame->seq_num, path->local_cid.seq_num);

		/* Not an error - might be duplicate or already retired */
		return 0;
	}

	/*
	 * The peer has retired our current CID for this path.
	 * We MUST issue a new CID so the path can continue to function.
	 *
	 * Per RFC 9000 Section 5.1.1:
	 * "An endpoint MAY send connection IDs that temporarily exceed a
	 * peer's limit if the NEW_CONNECTION_ID frame also requires the
	 * retirement of any excess, by including a sufficiently large value
	 * in the Retire Prior To field."
	 *
	 * Issue a replacement CID for this path.
	 */
	pr_info("tquic_mp: issuing replacement CID for path %llu after peer retirement of seq=%llu\n",
		frame->path_id, frame->seq_num);

	ret = tquic_mp_issue_path_cid(conn, path);
	if (ret < 0) {
		pr_warn("tquic_mp: failed to issue replacement CID for path %llu: %d\n",
			frame->path_id, ret);
		return ret;
	}

	/* Update statistics */
	spin_lock_bh(&conn->lock);
	/* Could track CID retirements in connection stats here */
	spin_unlock_bh(&conn->lock);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_mp_handle_retire_connection_id);

/*
 * =============================================================================
 * PATH_STATUS Frame Processing
 * =============================================================================
 */

/**
 * tquic_mp_handle_path_status - Handle received PATH_STATUS frame
 * @conn: Connection
 * @frame: Parsed PATH_STATUS frame
 *
 * RFC 9369 Section 5.6: PATH_STATUS frames are used to communicate path
 * preferences between endpoints.
 *
 * Returns 0 on success or negative error.
 */
int tquic_mp_handle_path_status(struct tquic_connection *conn,
				const struct tquic_mp_path_status *frame)
{
	struct tquic_path *path;
	struct tquic_mp_path_abandon_state *abandon_state;
	bool found = false;

	if (!conn || !frame)
		return -EINVAL;

	pr_debug("tquic_mp: received PATH_STATUS path=%llu status=%llu priority=%llu\n",
		 frame->path_id, frame->status, frame->priority);

	/* Find the path */
	spin_lock(&conn->paths_lock);
	list_for_each_entry(path, &conn->paths, list) {
		if (path->path_id == frame->path_id) {
			found = true;
			break;
		}
	}

	if (!found) {
		spin_unlock(&conn->paths_lock);
		pr_debug("tquic_mp: PATH_STATUS for unknown path %llu\n",
			 frame->path_id);
		return -ENOENT;
	}

	/* Get abandonment state for sequence tracking */
	abandon_state = path->abandon_state;
	if (abandon_state) {
		spin_lock(&abandon_state->lock);

		/* Check sequence number - ignore old status updates */
		if (frame->seq_num <= abandon_state->status_seq.remote_seq) {
			spin_unlock(&abandon_state->lock);
			spin_unlock(&conn->paths_lock);
			return 0;
		}

		abandon_state->status_seq.remote_seq = frame->seq_num;
		spin_unlock(&abandon_state->lock);
	}

	/* Update path based on status */
	switch (frame->status) {
	case TQUIC_PATH_STATUS_STANDBY:
		if (path->state == TQUIC_PATH_ACTIVE)
			path->state = TQUIC_PATH_STANDBY;
		break;

	case TQUIC_PATH_STATUS_AVAILABLE:
		if (path->state == TQUIC_PATH_STANDBY ||
		    path->state == TQUIC_PATH_VALIDATED)
			path->state = TQUIC_PATH_ACTIVE;
		break;

	case TQUIC_PATH_STATUS_ABANDONED:
		path->state = TQUIC_PATH_CLOSED;
		break;

	default:
		pr_debug("tquic_mp: unknown PATH_STATUS value %llu\n",
			 frame->status);
	}

	/* Update priority */
	path->priority = (u8)min_t(u64, frame->priority, 255);

	spin_unlock(&conn->paths_lock);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_mp_handle_path_status);

/**
 * tquic_mp_send_path_status - Send PATH_STATUS frame
 * @conn: Connection
 * @path: Path to report status for
 * @status: Path status value
 *
 * Returns 0 on success or negative error.
 */
int tquic_mp_send_path_status(struct tquic_connection *conn,
			      struct tquic_path *path, u64 status)
{
	struct tquic_mp_path_abandon_state *abandon_state;
	struct tquic_mp_path_status frame;
	u8 buf[32];
	int len;

	if (!conn || !path)
		return -EINVAL;

	/* Get abandonment state for sequence tracking */
	abandon_state = path->abandon_state;
	if (!abandon_state) {
		abandon_state = tquic_mp_abandon_state_create(path);
		if (!abandon_state)
			return -ENOMEM;
		path->abandon_state = abandon_state;
	}

	spin_lock_bh(&abandon_state->lock);
	abandon_state->status_seq.local_seq++;

	/* Build PATH_STATUS frame */
	memset(&frame, 0, sizeof(frame));
	frame.path_id = path->path_id;
	frame.seq_num = abandon_state->status_seq.local_seq;
	frame.status = status;
	frame.priority = path->priority;

	abandon_state->status_seq.last_status = status;

	spin_unlock_bh(&abandon_state->lock);

	/* Encode frame */
	len = tquic_mp_write_path_status(&frame, buf, sizeof(buf));
	if (len < 0)
		return len;

	pr_debug("tquic_mp: sending PATH_STATUS path=%llu status=%llu seq=%llu\n",
		 frame.path_id, frame.status, frame.seq_num);

	/* Send PATH_STATUS on the path */
	return tquic_mp_send_control_frame(conn, path, buf, len);
}
EXPORT_SYMBOL_GPL(tquic_mp_send_path_status);

/*
 * =============================================================================
 * Active Path Selection
 * =============================================================================
 */

/**
 * tquic_mp_select_new_active_path - Select a new active path
 * @conn: Connection
 * @excluded_path: Path to exclude from selection (being closed)
 *
 * Called when the current active path is being abandoned or has failed.
 * Selects the best available path as the new active path.
 *
 * Returns 0 on success or negative error if no path available.
 */
int tquic_mp_select_new_active_path(struct tquic_connection *conn,
				    struct tquic_path *excluded_path)
{
	struct tquic_path *path, *best_path = NULL;
	u64 best_score = 0;

	if (!conn)
		return -EINVAL;

	spin_lock(&conn->paths_lock);

	list_for_each_entry(path, &conn->paths, list) {
		u64 score;

		/* Skip excluded path */
		if (path == excluded_path)
			continue;

		/* Only consider active or validated paths */
		if (path->state != TQUIC_PATH_ACTIVE &&
		    path->state != TQUIC_PATH_VALIDATED &&
		    path->state != TQUIC_PATH_STANDBY)
			continue;

		/* Calculate score based on RTT and bandwidth */
		score = path->stats.bandwidth;
		if (path->stats.rtt_smoothed > 0)
			score = score / path->stats.rtt_smoothed;

		/* Apply priority weighting (lower priority = higher preference) */
		score = score * (256 - path->priority) / 256;

		if (score > best_score || !best_path) {
			best_score = score;
			best_path = path;
		}
	}

	if (best_path) {
		conn->active_path = best_path;
		if (best_path->state == TQUIC_PATH_STANDBY)
			best_path->state = TQUIC_PATH_ACTIVE;

		pr_info("tquic_mp: selected new active path %u\n",
			best_path->path_id);
	} else {
		conn->active_path = NULL;
		pr_warn("tquic_mp: no available paths after abandonment\n");
	}

	spin_unlock(&conn->paths_lock);

	return best_path ? 0 : -ENOENT;
}
EXPORT_SYMBOL_GPL(tquic_mp_select_new_active_path);

/*
 * =============================================================================
 * Module Initialization
 * =============================================================================
 */

/**
 * tquic_mp_abandon_init - Initialize path abandonment module
 */
int __init tquic_mp_abandon_init(void)
{
	mp_abandon_state_cache = kmem_cache_create("tquic_mp_abandon_state",
		sizeof(struct tquic_mp_path_abandon_state), 0,
		SLAB_HWCACHE_ALIGN, NULL);
	if (!mp_abandon_state_cache)
		goto err_abandon_state;

	mp_cid_retire_cache = kmem_cache_create("tquic_mp_cid_retire",
		sizeof(struct tquic_mp_cid_retire_entry), 0,
		SLAB_HWCACHE_ALIGN, NULL);
	if (!mp_cid_retire_cache)
		goto err_cid_retire;

	mp_cid_state_cache = kmem_cache_create("tquic_mp_cid_state",
		sizeof(struct tquic_mp_cid_state), 0,
		SLAB_HWCACHE_ALIGN, NULL);
	if (!mp_cid_state_cache)
		goto err_cid_state;

	mp_remote_cid_cache = kmem_cache_create("tquic_mp_remote_cid",
		sizeof(struct tquic_mp_remote_cid), 0,
		SLAB_HWCACHE_ALIGN, NULL);
	if (!mp_remote_cid_cache)
		goto err_remote_cid;

	mp_local_cid_cache = kmem_cache_create("tquic_mp_local_cid",
		sizeof(struct tquic_mp_local_cid), 0,
		SLAB_HWCACHE_ALIGN, NULL);
	if (!mp_local_cid_cache)
		goto err_local_cid;

	mp_pending_retire_cache = kmem_cache_create("tquic_mp_pending_retire",
		sizeof(struct tquic_mp_pending_retire), 0,
		SLAB_HWCACHE_ALIGN, NULL);
	if (!mp_pending_retire_cache)
		goto err_pending_retire;

	pr_info("tquic: Multipath path abandonment and CID management initialized (RFC 9369)\n");
	return 0;

err_pending_retire:
	kmem_cache_destroy(mp_local_cid_cache);
err_local_cid:
	kmem_cache_destroy(mp_remote_cid_cache);
err_remote_cid:
	kmem_cache_destroy(mp_cid_state_cache);
err_cid_state:
	kmem_cache_destroy(mp_cid_retire_cache);
err_cid_retire:
	kmem_cache_destroy(mp_abandon_state_cache);
err_abandon_state:
	return -ENOMEM;
}

/**
 * tquic_mp_abandon_exit - Cleanup path abandonment module
 */
void __exit tquic_mp_abandon_exit(void)
{
	kmem_cache_destroy(mp_pending_retire_cache);
	kmem_cache_destroy(mp_local_cid_cache);
	kmem_cache_destroy(mp_remote_cid_cache);
	kmem_cache_destroy(mp_cid_state_cache);
	kmem_cache_destroy(mp_cid_retire_cache);
	kmem_cache_destroy(mp_abandon_state_cache);

	pr_info("tquic: Multipath path abandonment and CID management cleaned up\n");
}

#ifndef TQUIC_OUT_OF_TREE
MODULE_DESCRIPTION("TQUIC Path Abandonment for Multipath (RFC 9369)");
MODULE_LICENSE("GPL");
#endif
