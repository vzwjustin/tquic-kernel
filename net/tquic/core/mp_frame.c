// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * TQUIC Multipath Extension Frame Processing
 *
 * Implementation of PATH_ABANDON, PATH_STATUS_BACKUP, and PATH_STATUS_AVAILABLE
 * frames per draft-ietf-quic-multipath-16.
 *
 * Copyright (c) 2024-2026 Linux QUIC Authors
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/workqueue.h>
#include <net/tquic.h>
#include "varint.h"
#include "../tquic_debug.h"
#define _TQUIC_MP_FRAME_ALIASES	/* suppress macro aliases; we provide symbol aliases below */
#include "mp_frame.h"
#include "../bond/tquic_bonding.h"

/*
 * Multipath Extension Frame Types (draft-ietf-quic-multipath-16)
 *
 * These are the experimental values used for implementation testing.
 * Final IANA-assigned values will be shorter (TBD-02 through TBD-04).
 */
#define TQUIC_FRAME_PATH_ABANDON		0x15228c05
#define TQUIC_FRAME_PATH_STATUS_BACKUP		0x15228c07
#define TQUIC_FRAME_PATH_STATUS_AVAILABLE	0x15228c08

/* Forward declarations for path management */
extern const char *tquic_path_state_names[];
extern int tquic_path_set_state(struct tquic_path *path,
				enum tquic_path_state new_state);
extern struct tquic_path *tquic_pm_get_path(struct tquic_pm_state *pm,
					    u32 path_id);
extern void tquic_path_put(struct tquic_path *path);

/* Forward declaration for scheduler ops */
struct tquic_scheduler_ops;

/*
 * Helper to queue a control frame for transmission
 */
static int tquic_mp_queue_frame(struct tquic_connection *conn, struct sk_buff *skb)
{
	if (!conn || !skb)
		return -EINVAL;

	spin_lock_bh(&conn->lock);
	skb_queue_tail(&conn->control_frames, skb);
	spin_unlock_bh(&conn->lock);

	return 0;
}

/*
 * ============================================================================
 * Multipath Extension Frame Processing (draft-ietf-quic-multipath-16)
 * ============================================================================
 */

/**
 * tquic_frame_process_path_abandon - Process PATH_ABANDON frame
 * @conn: TQUIC connection
 * @data: Frame data
 * @len: Length of frame data
 *
 * PATH_ABANDON frame format (draft-ietf-quic-multipath-16 Section 4.2):
 *   PATH_ABANDON Frame {
 *     Type (i) = 0x15228c05,
 *     Path Identifier (i),
 *     Error Code (i),
 *     Reason Phrase Length (i),
 *     Reason Phrase (..),
 *   }
 *
 * Returns the number of bytes consumed, or negative error code.
 */
int tquic_frame_process_path_abandon(struct tquic_connection *conn,
				     const u8 *data, int len)
{
	int offset = 0;
	u64 frame_type;
	u64 path_id;
	u64 error_code;
	u64 reason_len;
	int varint_len;

	/* Parse frame type (variable length) */
	varint_len = tquic_varint_decode(data + offset, len - offset, &frame_type);
	if (varint_len < 0)
		return varint_len;
	offset += varint_len;

	/* Path Identifier */
	varint_len = tquic_varint_decode(data + offset, len - offset, &path_id);
	if (varint_len < 0)
		return varint_len;
	offset += varint_len;

	/* Error Code */
	varint_len = tquic_varint_decode(data + offset, len - offset, &error_code);
	if (varint_len < 0)
		return varint_len;
	offset += varint_len;

	/* Reason Phrase Length */
	varint_len = tquic_varint_decode(data + offset, len - offset, &reason_len);
	if (varint_len < 0)
		return varint_len;
	offset += varint_len;

	/* Validate reason phrase fits in remaining data */
	if (reason_len > len - offset)
		return -EINVAL;

	/* Skip reason phrase (for logging, we could store it) */
	offset += reason_len;

	tquic_conn_info(conn, "PATH_ABANDON path=%llu error=%llu\n",
			path_id, error_code);

	/*
	 * Handle path abandonment per draft-ietf-quic-multipath:
	 * 1. Transition path to CLOSED state
	 * 2. Stop scheduling packets on this path
	 * 3. Notify bonding context for state machine update
	 * 4. Trigger failover if this was an active path
	 */
	if (conn->pm) {
		struct tquic_path *path = tquic_pm_get_path(conn->pm, (u32)path_id);
		struct tquic_bonding_ctx *bc;

		if (!path) {
			tquic_conn_warn(conn, "PATH_ABANDON for unknown path %llu\n",
					path_id);
			return offset;
		}

		/* Transition to CLOSED state (terminal state for abandoned paths) */
		if (tquic_path_set_state(path, TQUIC_PATH_CLOSED) < 0) {
			tquic_conn_warn(conn,
					"invalid transition to CLOSED path %u\n",
					path->path_id);
		}

		/*
		 * Notify bonding context that path is being abandoned.
		 * This triggers:
		 * - Bonding state machine update (may transition to DEGRADED)
		 * - Failover if this was primary path
		 * - Weight recalculation for remaining paths
		 */
		bc = (struct tquic_bonding_ctx *)conn->pm;
		if (bc) {
			tquic_bonding_on_path_failed(bc, path);
		}

		/*
		 * Notify scheduler that path is being removed.
		 * conn->scheduler is void*, need to check if scheduler has callbacks.
		 */

		tquic_path_put(path);
	}

	return offset;
}
EXPORT_SYMBOL_GPL(tquic_frame_process_path_abandon);

/**
 * tquic_frame_process_path_status - Process PATH_STATUS_BACKUP/PATH_STATUS_AVAILABLE frame
 * @conn: TQUIC connection
 * @data: Frame data
 * @len: Length of frame data
 * @backup: true for PATH_STATUS_BACKUP (0x15228c07), false for PATH_STATUS_AVAILABLE (0x15228c08)
 *
 * PATH_STATUS frame format (draft-ietf-quic-multipath-16 Section 4.3):
 *   PATH_STATUS Frame {
 *     Type (i) = 0x15228c07 (backup) or 0x15228c08 (available),
 *     Path Identifier (i),
 *     Path Status Sequence Number (i),
 *   }
 *
 * Returns the number of bytes consumed, or negative error code.
 */
int tquic_frame_process_path_status(struct tquic_connection *conn,
				    const u8 *data, int len, bool backup)
{
	int offset = 0;
	u64 frame_type;
	u64 path_id;
	u64 seq_num;
	int varint_len;

	/* Parse frame type (variable length) */
	varint_len = tquic_varint_decode(data + offset, len - offset, &frame_type);
	if (varint_len < 0)
		return varint_len;
	offset += varint_len;

	/* Path Identifier */
	varint_len = tquic_varint_decode(data + offset, len - offset, &path_id);
	if (varint_len < 0)
		return varint_len;
	offset += varint_len;

	/* Path Status Sequence Number */
	varint_len = tquic_varint_decode(data + offset, len - offset, &seq_num);
	if (varint_len < 0)
		return varint_len;
	offset += varint_len;

	tquic_conn_dbg(conn, "received %s path_id=%llu seq=%llu\n",
		 backup ? "PATH_STATUS_BACKUP" : "PATH_STATUS_AVAILABLE",
		 path_id, seq_num);

	/*
	 * Handle path status update per draft-ietf-quic-multipath:
	 * - PATH_STATUS_BACKUP: Mark path as backup, prefer other paths for traffic
	 * - PATH_STATUS_AVAILABLE: Mark path as active, can be used for traffic
	 *
	 * Sequence numbers prevent reordering issues (RFC 9000 Section 13.3)
	 */
	if (conn->pm) {
		struct tquic_path *path = tquic_pm_get_path(conn->pm, (u32)path_id);
		struct tquic_bonding_ctx *bc;
		enum tquic_path_state old_state, new_state;
		bool state_changed = false;

		if (!path) {
			tquic_conn_warn(conn, "PATH_STATUS unknown path %llu\n",
					path_id);
			return offset;
		}

		/*
		 * Use connection lock to protect path state since struct tquic_path
		 * in the main header doesn't have a dedicated state_lock.
		 */
		spin_lock_bh(&conn->lock);

		/*
		 * Only apply status if sequence number is newer than
		 * what we've seen before (prevents reordering issues).
		 * Per draft-ietf-quic-multipath, sequence numbers MUST
		 * be monotonically increasing.
		 */
		if (seq_num < path->status_seq_num) {
			spin_unlock_bh(&conn->lock);
			tquic_conn_dbg(conn, "ignoring old PATH_STATUS seq=%llu cur=%llu\n",
				 seq_num, path->status_seq_num);
			tquic_path_put(path);
			return offset;
		}

		path->status_seq_num = seq_num;
		old_state = path->state;

		/*
		 * Determine new state based on frame type.
		 * Only transition if path is in a valid state.
		 */
		if (backup) {
			new_state = TQUIC_PATH_STANDBY;
			path->is_backup = true;
		} else {
			new_state = TQUIC_PATH_ACTIVE;
			path->is_backup = false;
		}

		/*
		 * Valid transitions for PATH_STATUS frames:
		 * - VALIDATED -> ACTIVE/STANDBY
		 * - ACTIVE <-> STANDBY
		 */
		if (path->state == TQUIC_PATH_VALIDATED ||
		    path->state == TQUIC_PATH_ACTIVE ||
		    path->state == TQUIC_PATH_STANDBY) {
			if (old_state != new_state) {
				path->state = new_state;
				path->last_activity = ktime_get();
				state_changed = true;

				tquic_conn_dbg(conn, "path %u: %s via %s frame\n",
					 path->path_id,
					 tquic_path_state_names[new_state],
					 backup ? "PATH_STATUS_BACKUP" : "PATH_STATUS_AVAILABLE");
			}
		} else {
			tquic_conn_warn(conn, "PATH_STATUS bad state path %u state %d\n",
				path->path_id, path->state);
		}

		spin_unlock_bh(&conn->lock);

		/*
		 * Notify bonding context of state change.
		 * Must be done outside spinlock to avoid deadlock.
		 */
		if (state_changed) {
			bc = (struct tquic_bonding_ctx *)conn->pm;

			/* Update bonding state machine */
			if (bc) {
				if (new_state == TQUIC_PATH_ACTIVE) {
					/* Path became active - may trigger BONDED state */
					tquic_bonding_on_path_validated(bc, path);
					tquic_bonding_update_state(bc);
				} else if (new_state == TQUIC_PATH_STANDBY) {
					/* Path demoted to standby - recalculate weights */
					tquic_bonding_derive_weights(bc);
					tquic_bonding_update_state(bc);
				}
			}
		}

		tquic_path_put(path);
	}

	return offset;
}
EXPORT_SYMBOL_GPL(tquic_frame_process_path_status);

/*
 * ============================================================================
 * Multipath Frame Generation
 * ============================================================================
 */

/**
 * tquic_frame_create_path_abandon - Create PATH_ABANDON frame
 * @path_id: Path identifier to abandon
 * @error_code: Error code for abandonment reason
 * @reason: Optional reason phrase (may be NULL)
 * @reason_len: Length of reason phrase
 *
 * Returns sk_buff containing the frame, or NULL on error.
 */
struct sk_buff *tquic_frame_create_path_abandon(u64 path_id, u64 error_code,
						const char *reason, u32 reason_len)
{
	struct sk_buff *skb;
	u8 *p;
	int frame_len;
	int type_len, path_len, err_len, rlen_len;
	int ret;

	/* Calculate frame size */
	type_len = tquic_varint_len(TQUIC_FRAME_PATH_ABANDON);
	path_len = tquic_varint_len(path_id);
	err_len = tquic_varint_len(error_code);
	rlen_len = tquic_varint_len(reason_len);
	frame_len = type_len + path_len + err_len + rlen_len + reason_len;

	skb = alloc_skb(frame_len + 16, GFP_ATOMIC);
	if (!skb)
		return NULL;

	p = skb_put(skb, frame_len);

	/* Frame Type */
	ret = tquic_varint_encode(TQUIC_FRAME_PATH_ABANDON, p, type_len);
	if (ret < 0)
		goto err_free;
	p += ret;

	/* Path Identifier */
	ret = tquic_varint_encode(path_id, p, path_len);
	if (ret < 0)
		goto err_free;
	p += ret;

	/* Error Code */
	ret = tquic_varint_encode(error_code, p, err_len);
	if (ret < 0)
		goto err_free;
	p += ret;

	/* Reason Phrase Length */
	ret = tquic_varint_encode(reason_len, p, rlen_len);
	if (ret < 0)
		goto err_free;
	p += ret;

	/* Reason Phrase */
	if (reason_len > 0 && reason)
		memcpy(p, reason, reason_len);

	return skb;

err_free:
	kfree_skb(skb);
	return NULL;
}
EXPORT_SYMBOL_GPL(tquic_frame_create_path_abandon);

/**
 * tquic_frame_create_path_status_backup - Create PATH_STATUS_BACKUP frame
 * @path_id: Path identifier to mark as backup
 * @seq_num: Path status sequence number
 *
 * Returns sk_buff containing the frame, or NULL on error.
 */
struct sk_buff *tquic_frame_create_path_status_backup(u64 path_id, u64 seq_num)
{
	struct sk_buff *skb;
	u8 *p;
	int frame_len;
	int type_len, path_len, seq_len;
	int ret;

	/* Calculate frame size */
	type_len = tquic_varint_len(TQUIC_FRAME_PATH_STATUS_BACKUP);
	path_len = tquic_varint_len(path_id);
	seq_len = tquic_varint_len(seq_num);
	frame_len = type_len + path_len + seq_len;

	skb = alloc_skb(frame_len + 16, GFP_ATOMIC);
	if (!skb)
		return NULL;

	p = skb_put(skb, frame_len);

	/* Frame Type */
	ret = tquic_varint_encode(TQUIC_FRAME_PATH_STATUS_BACKUP, p, type_len);
	if (ret < 0)
		goto err_free;
	p += ret;

	/* Path Identifier */
	ret = tquic_varint_encode(path_id, p, path_len);
	if (ret < 0)
		goto err_free;
	p += ret;

	/* Path Status Sequence Number */
	ret = tquic_varint_encode(seq_num, p, seq_len);
	if (ret < 0)
		goto err_free;

	return skb;

err_free:
	kfree_skb(skb);
	return NULL;
}
EXPORT_SYMBOL_GPL(tquic_frame_create_path_status_backup);

/**
 * tquic_frame_create_path_status_available - Create PATH_STATUS_AVAILABLE frame
 * @path_id: Path identifier to mark as available
 * @seq_num: Path status sequence number
 *
 * Returns sk_buff containing the frame, or NULL on error.
 */
struct sk_buff *tquic_frame_create_path_status_available(u64 path_id, u64 seq_num)
{
	struct sk_buff *skb;
	u8 *p;
	int frame_len;
	int type_len, path_len, seq_len;
	int ret;

	/* Calculate frame size */
	type_len = tquic_varint_len(TQUIC_FRAME_PATH_STATUS_AVAILABLE);
	path_len = tquic_varint_len(path_id);
	seq_len = tquic_varint_len(seq_num);
	frame_len = type_len + path_len + seq_len;

	skb = alloc_skb(frame_len + 16, GFP_ATOMIC);
	if (!skb)
		return NULL;

	p = skb_put(skb, frame_len);

	/* Frame Type */
	ret = tquic_varint_encode(TQUIC_FRAME_PATH_STATUS_AVAILABLE, p, type_len);
	if (ret < 0)
		goto err_free;
	p += ret;

	/* Path Identifier */
	ret = tquic_varint_encode(path_id, p, path_len);
	if (ret < 0)
		goto err_free;
	p += ret;

	/* Path Status Sequence Number */
	ret = tquic_varint_encode(seq_num, p, seq_len);
	if (ret < 0)
		goto err_free;

	return skb;

err_free:
	kfree_skb(skb);
	return NULL;
}
EXPORT_SYMBOL_GPL(tquic_frame_create_path_status_available);

/**
 * tquic_send_path_abandon - Send PATH_ABANDON frame for a path
 * @conn: TQUIC connection
 * @path: Path to abandon
 * @error_code: Error code for abandonment
 *
 * Queues a PATH_ABANDON frame for transmission.
 * Returns 0 on success, negative error code on failure.
 */
int tquic_send_path_abandon(struct tquic_connection *conn, struct tquic_path *path,
			    u64 error_code)
{
	struct sk_buff *skb;
	int ret;

	if (!conn || !path)
		return -EINVAL;

	/* Transition path to CLOSED state */
	ret = tquic_path_set_state(path, TQUIC_PATH_CLOSED);
	if (ret < 0) {
		tquic_conn_warn(conn, "path %u transition to CLOSED failed: %d\n",
			path->path_id, ret);
		/* Continue anyway - still send the frame to peer */
	}

	skb = tquic_frame_create_path_abandon(path->path_id, error_code, NULL, 0);
	if (!skb)
		return -ENOMEM;

	ret = tquic_mp_queue_frame(conn, skb);
	if (ret) {
		kfree_skb(skb);
		return ret;
	}

	if (!work_pending(&conn->tx_work))
		schedule_work(&conn->tx_work);

	tquic_conn_dbg(conn, "queued PATH_ABANDON path %u error=%llu\n",
		 path->path_id, error_code);

	/*
	 * Notify bonding context that path is being abandoned.
	 * This triggers failover and state machine updates.
	 */
	if (conn->pm) {
		struct tquic_bonding_ctx *bc = (struct tquic_bonding_ctx *)conn->pm;
		tquic_bonding_on_path_failed(bc, path);
		tquic_bonding_update_state(bc);
	}

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_send_path_abandon);

/**
 * tquic_send_path_status_backup - Send PATH_STATUS_BACKUP frame for a path
 * @conn: TQUIC connection
 * @path: Path to mark as backup
 *
 * Queues a PATH_STATUS_BACKUP frame for transmission.
 * Returns 0 on success, negative error code on failure.
 */
int tquic_send_path_status_backup(struct tquic_connection *conn, struct tquic_path *path)
{
	struct sk_buff *skb;
	u64 seq_num;
	int ret;

	if (!conn || !path)
		return -EINVAL;

	/* Use connection lock to protect path state */
	spin_lock_bh(&conn->lock);

	/* Can only mark as backup if currently VALIDATED or ACTIVE */
	if (path->state != TQUIC_PATH_VALIDATED &&
	    path->state != TQUIC_PATH_ACTIVE) {
		spin_unlock_bh(&conn->lock);
		tquic_conn_warn(conn, "BACKUP bad state path %u state %d\n",
			path->path_id, path->state);
		return -EINVAL;
	}

	/* Increment sequence number for this status update */
	seq_num = ++path->status_seq_num;

	/* Update local state */
	path->state = TQUIC_PATH_STANDBY;
	path->is_backup = true;
	path->last_activity = ktime_get();

	spin_unlock_bh(&conn->lock);

	skb = tquic_frame_create_path_status_backup(path->path_id, seq_num);
	if (!skb)
		return -ENOMEM;

	ret = tquic_mp_queue_frame(conn, skb);
	if (ret) {
		kfree_skb(skb);
		return ret;
	}

	if (!work_pending(&conn->tx_work))
		schedule_work(&conn->tx_work);

	tquic_conn_dbg(conn, "queued PATH_STATUS_BACKUP path %u seq=%llu\n",
		 path->path_id, seq_num);

	/*
	 * Notify bonding context that path is now backup.
	 * This ensures traffic is redirected away from this path.
	 */
	if (conn->pm) {
		struct tquic_bonding_ctx *bc = (struct tquic_bonding_ctx *)conn->pm;
		tquic_bonding_derive_weights(bc);
		tquic_bonding_update_state(bc);
	}

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_send_path_status_backup);

/**
 * tquic_send_path_status_available - Send PATH_STATUS_AVAILABLE frame for a path
 * @conn: TQUIC connection
 * @path: Path to mark as available
 *
 * Queues a PATH_STATUS_AVAILABLE frame for transmission.
 * Returns 0 on success, negative error code on failure.
 */
int tquic_send_path_status_available(struct tquic_connection *conn, struct tquic_path *path)
{
	struct sk_buff *skb;
	u64 seq_num;
	int ret;

	if (!conn || !path)
		return -EINVAL;

	/* Use connection lock to protect path state */
	spin_lock_bh(&conn->lock);

	/* Can only mark as available if currently VALIDATED or STANDBY */
	if (path->state != TQUIC_PATH_VALIDATED &&
	    path->state != TQUIC_PATH_STANDBY) {
		spin_unlock_bh(&conn->lock);
		tquic_conn_warn(conn, "AVAILABLE bad state path %u state %d\n",
			path->path_id, path->state);
		return -EINVAL;
	}

	/* Increment sequence number for this status update */
	seq_num = ++path->status_seq_num;

	/* Update local state */
	path->state = TQUIC_PATH_ACTIVE;
	path->is_backup = false;
	path->last_activity = ktime_get();

	spin_unlock_bh(&conn->lock);

	skb = tquic_frame_create_path_status_available(path->path_id, seq_num);
	if (!skb)
		return -ENOMEM;

	ret = tquic_mp_queue_frame(conn, skb);
	if (ret) {
		kfree_skb(skb);
		return ret;
	}

	if (!work_pending(&conn->tx_work))
		schedule_work(&conn->tx_work);

	tquic_conn_dbg(conn, "queued PATH_STATUS_AVAILABLE path %u seq=%llu\n",
		 path->path_id, seq_num);

	/*
	 * Notify bonding context that path is now active.
	 * This may trigger transition to BONDED state if we now have
	 * multiple active paths.
	 */
	if (conn->pm) {
		struct tquic_bonding_ctx *bc = (struct tquic_bonding_ctx *)conn->pm;
		tquic_bonding_on_path_validated(bc, path);
		tquic_bonding_derive_weights(bc);
		tquic_bonding_update_state(bc);
	}

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_send_path_status_available);

/**
 * tquic_mp_frame_is_multipath - Check if first byte could be multipath frame
 * @first_byte: First byte of frame data
 *
 * Multipath frame types start with specific prefixes. This is a quick
 * check before doing full varint decoding.
 *
 * Returns true if frame could be a multipath extension frame.
 */
bool tquic_mp_frame_is_multipath(u8 first_byte)
{
	/*
	 * Multipath frames have type 0x15228c05-0x15228c08.
	 * These start with 0xc0 | 0x15 = 0xd5 when varint encoded.
	 * (4-byte varint prefix is 0xc0)
	 */
	return (first_byte == 0xd5);
}
EXPORT_SYMBOL_GPL(tquic_mp_frame_is_multipath);

/**
 * tquic_mp_frame_process - Try to process frame as multipath extension
 * @conn: TQUIC connection
 * @data: Frame data
 * @len: Length of frame data
 *
 * Attempts to decode and process the frame as a multipath extension frame.
 * Returns positive bytes consumed on success, 0 if not a multipath frame,
 * or negative error code on failure.
 */
int tquic_mp_frame_process(struct tquic_connection *conn, const u8 *data, int len)
{
	u64 frame_type;
	int varint_len;

	if (len < 1)
		return 0;

	/* Quick check for multipath frame prefix */
	if (!tquic_mp_frame_is_multipath(data[0]))
		return 0;

	/* Decode frame type */
	varint_len = tquic_varint_decode(data, len, &frame_type);
	if (varint_len < 0)
		return 0;  /* Not a valid varint, let standard handler deal with it */

	switch (frame_type) {
	case TQUIC_FRAME_PATH_ABANDON:
		return tquic_frame_process_path_abandon(conn, data, len);

	case TQUIC_FRAME_PATH_STATUS_BACKUP:
		return tquic_frame_process_path_status(conn, data, len, true);

	case TQUIC_FRAME_PATH_STATUS_AVAILABLE:
		return tquic_frame_process_path_status(conn, data, len, false);

	default:
		/* Not a known multipath frame */
		return 0;
	}
}
EXPORT_SYMBOL_GPL(tquic_mp_frame_process);

/*
 * Compatibility aliases for old function names
 * These allow existing code that uses quic_* names to still compile
 */

/* Forward declarations for alias targets */
int quic_frame_process_path_abandon(struct tquic_connection *conn,
				    const u8 *data, int len);
int quic_frame_process_path_status(struct tquic_connection *conn,
				   const u8 *data, int len, bool backup);
bool quic_mp_frame_is_multipath(u8 first_byte);
int quic_mp_frame_process(struct tquic_connection *conn,
			  const u8 *data, int len);

int quic_frame_process_path_abandon(struct tquic_connection *conn,
				    const u8 *data, int len)
	__attribute__((alias("tquic_frame_process_path_abandon")));
EXPORT_SYMBOL_GPL(quic_frame_process_path_abandon);

int quic_frame_process_path_status(struct tquic_connection *conn,
				   const u8 *data, int len, bool backup)
	__attribute__((alias("tquic_frame_process_path_status")));
EXPORT_SYMBOL_GPL(quic_frame_process_path_status);

bool quic_mp_frame_is_multipath(u8 first_byte)
	__attribute__((alias("tquic_mp_frame_is_multipath")));
EXPORT_SYMBOL_GPL(quic_mp_frame_is_multipath);

int quic_mp_frame_process(struct tquic_connection *conn, const u8 *data, int len)
	__attribute__((alias("tquic_mp_frame_process")));
EXPORT_SYMBOL_GPL(quic_mp_frame_process);
