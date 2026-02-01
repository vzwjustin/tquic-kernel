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

#include "mp_frame.h"

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

/* Memory cache */
static struct kmem_cache *mp_abandon_state_cache;
static struct kmem_cache *mp_cid_retire_cache;

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

	spin_lock(&state->lock);

	/* Free CID retire entries */
	list_for_each_entry_safe(entry, tmp, &state->cids_to_retire, list) {
		list_del(&entry->list);
		kmem_cache_free(mp_cid_retire_cache, entry);
	}

	spin_unlock(&state->lock);

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

	pr_info("tquic_mp: path %llu abandoned by peer (error=%llu)\n",
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

	spin_lock(&abandon_state->lock);

	/* Check if already abandoning */
	if (abandon_state->abandon_state != TQUIC_MP_ABANDON_NONE) {
		spin_unlock(&abandon_state->lock);
		return -EALREADY;
	}

	abandon_state->abandon_state = TQUIC_MP_ABANDON_PENDING;
	abandon_state->error_code = error_code;

	spin_unlock(&abandon_state->lock);

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

	/* Send the frame - TODO: queue for transmission */
	pr_debug("tquic_mp: sending PATH_ABANDON for path %llu (error=%llu)\n",
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

	/* TODO: Queue frame for transmission */

	return 0;
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

	/* TODO: Queue frame for transmission */

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_mp_issue_path_cid);

/**
 * tquic_mp_handle_new_connection_id - Handle MP_NEW_CONNECTION_ID frame
 * @conn: Connection
 * @frame: Parsed MP_NEW_CONNECTION_ID frame
 *
 * Returns 0 on success or negative error.
 */
int tquic_mp_handle_new_connection_id(struct tquic_connection *conn,
				      const struct tquic_mp_new_connection_id *frame)
{
	struct tquic_path *path;
	bool found = false;

	if (!conn || !frame)
		return -EINVAL;

	pr_debug("tquic_mp: received MP_NEW_CONNECTION_ID path=%llu seq=%llu\n",
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
		pr_debug("tquic_mp: MP_NEW_CONNECTION_ID for unknown path %llu\n",
			 frame->path_id);
		return -ENOENT;
	}

	/* Update remote CID for this path */
	if (frame->seq_num > path->remote_cid.seq_num) {
		path->remote_cid.seq_num = frame->seq_num;
		path->remote_cid.len = frame->cid_len;
		memcpy(path->remote_cid.id, frame->cid, frame->cid_len);
		path->remote_cid.retire_prior_to = frame->retire_prior_to;
	}

	spin_unlock(&conn->paths_lock);

	/* Retire CIDs with sequence < retire_prior_to */
	/* TODO: Implement CID retirement queue */

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_mp_handle_new_connection_id);

/**
 * tquic_mp_handle_retire_connection_id - Handle MP_RETIRE_CONNECTION_ID frame
 * @conn: Connection
 * @frame: Parsed MP_RETIRE_CONNECTION_ID frame
 *
 * Returns 0 on success or negative error.
 */
int tquic_mp_handle_retire_connection_id(struct tquic_connection *conn,
					 const struct tquic_mp_retire_connection_id *frame)
{
	struct tquic_path *path;
	bool found = false;

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
	spin_unlock(&conn->paths_lock);

	if (!found) {
		pr_debug("tquic_mp: MP_RETIRE_CONNECTION_ID for unknown path %llu\n",
			 frame->path_id);
		return -ENOENT;
	}

	/* Mark CID as retired - peer will no longer use it */
	/* TODO: Remove from active CID set */

	/* Issue a new CID to replace the retired one */
	return tquic_mp_issue_path_cid(conn, path);
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

	spin_lock(&abandon_state->lock);
	abandon_state->status_seq.local_seq++;

	/* Build PATH_STATUS frame */
	memset(&frame, 0, sizeof(frame));
	frame.path_id = path->path_id;
	frame.seq_num = abandon_state->status_seq.local_seq;
	frame.status = status;
	frame.priority = path->priority;

	abandon_state->status_seq.last_status = status;

	spin_unlock(&abandon_state->lock);

	/* Encode frame */
	len = tquic_mp_write_path_status(&frame, buf, sizeof(buf));
	if (len < 0)
		return len;

	pr_debug("tquic_mp: sending PATH_STATUS path=%llu status=%llu seq=%llu\n",
		 frame.path_id, frame.status, frame.seq_num);

	/* TODO: Queue frame for transmission */

	return 0;
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

	pr_info("tquic: Multipath path abandonment initialized (RFC 9369)\n");
	return 0;

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
	kmem_cache_destroy(mp_cid_retire_cache);
	kmem_cache_destroy(mp_abandon_state_cache);

	pr_info("tquic: Multipath path abandonment cleaned up\n");
}

MODULE_DESCRIPTION("TQUIC Path Abandonment for Multipath (RFC 9369)");
MODULE_LICENSE("GPL");
