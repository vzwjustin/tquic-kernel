// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * QUIC Multipath Extension Frame Processing
 *
 * Implementation of PATH_ABANDON, PATH_STANDBY, and PATH_AVAILABLE frames
 * per draft-ietf-quic-multipath.
 *
 * Copyright (c) 2024 Linux QUIC Authors
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <net/quic.h>

/*
 * ============================================================================
 * Multipath Extension Frame Processing (draft-ietf-quic-multipath)
 * ============================================================================
 */

/**
 * quic_frame_process_path_abandon - Process PATH_ABANDON frame
 * @conn: QUIC connection
 * @data: Frame data
 * @len: Length of frame data
 *
 * PATH_ABANDON frame format (draft-ietf-quic-multipath Section 9):
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
int quic_frame_process_path_abandon(struct quic_connection *conn,
				    const u8 *data, int len)
{
	int offset = 0;
	u64 frame_type;
	u64 path_id;
	u64 error_code;
	u64 reason_len;
	int varint_len;

	/* Parse frame type (variable length) */
	varint_len = quic_varint_decode(data + offset, len - offset, &frame_type);
	if (varint_len < 0)
		return varint_len;
	offset += varint_len;

	/* Path Identifier */
	varint_len = quic_varint_decode(data + offset, len - offset, &path_id);
	if (varint_len < 0)
		return varint_len;
	offset += varint_len;

	/* Error Code */
	varint_len = quic_varint_decode(data + offset, len - offset, &error_code);
	if (varint_len < 0)
		return varint_len;
	offset += varint_len;

	/* Reason Phrase Length */
	varint_len = quic_varint_decode(data + offset, len - offset, &reason_len);
	if (varint_len < 0)
		return varint_len;
	offset += varint_len;

	/* Validate reason phrase fits in remaining data */
	if (reason_len > len - offset)
		return -EINVAL;

	/* Skip reason phrase (for logging, we could store it) */
	offset += reason_len;

	pr_debug("QUIC: received PATH_ABANDON path_id=%llu error=%llu\n",
		 path_id, error_code);

	/*
	 * Handle path abandonment:
	 * - Stop sending data on this path
	 * - Transition path to abandoned/closed state
	 * - Notify path manager
	 */
	if (conn->pm) {
		struct tquic_path *path = tquic_pm_get_path(conn->pm, (u32)path_id);

		if (path) {
			tquic_path_set_state(path, TQUIC_PATH_CLOSING);
			tquic_path_put(path);
		}
	}

	return offset;
}
EXPORT_SYMBOL_GPL(quic_frame_process_path_abandon);

/**
 * quic_frame_process_path_status - Process PATH_STANDBY/PATH_AVAILABLE frame
 * @conn: QUIC connection
 * @data: Frame data
 * @len: Length of frame data
 * @standby: true for PATH_STANDBY (0x15228c07), false for PATH_AVAILABLE (0x15228c08)
 *
 * PATH_STANDBY/PATH_AVAILABLE frame format (draft-ietf-quic-multipath):
 *   PATH_STATUS Frame {
 *     Type (i) = 0x15228c07 (standby) or 0x15228c08 (available),
 *     Path Identifier (i),
 *     Path Status Sequence Number (i),
 *   }
 *
 * Returns the number of bytes consumed, or negative error code.
 */
int quic_frame_process_path_status(struct quic_connection *conn,
				   const u8 *data, int len, bool standby)
{
	int offset = 0;
	u64 frame_type;
	u64 path_id;
	u64 seq_num;
	int varint_len;

	/* Parse frame type (variable length) */
	varint_len = quic_varint_decode(data + offset, len - offset, &frame_type);
	if (varint_len < 0)
		return varint_len;
	offset += varint_len;

	/* Path Identifier */
	varint_len = quic_varint_decode(data + offset, len - offset, &path_id);
	if (varint_len < 0)
		return varint_len;
	offset += varint_len;

	/* Path Status Sequence Number */
	varint_len = quic_varint_decode(data + offset, len - offset, &seq_num);
	if (varint_len < 0)
		return varint_len;
	offset += varint_len;

	pr_debug("QUIC: received %s path_id=%llu seq=%llu\n",
		 standby ? "PATH_STANDBY" : "PATH_AVAILABLE", path_id, seq_num);

	/*
	 * Handle path status update:
	 * - PATH_STANDBY: Mark path as backup, prefer other paths for traffic
	 * - PATH_AVAILABLE: Mark path as active, can be used for traffic
	 */
	if (conn->pm) {
		struct tquic_path *path = tquic_pm_get_path(conn->pm, (u32)path_id);

		if (path) {
			enum tquic_path_state new_state;

			/*
			 * Only apply status if sequence number is newer than
			 * what we've seen before (prevents reordering issues).
			 */
			if (seq_num >= path->status_seq_num) {
				path->status_seq_num = seq_num;

				if (standby) {
					new_state = TQUIC_PATH_STANDBY;
					path->is_backup = true;
				} else {
					new_state = TQUIC_PATH_ACTIVE;
					path->is_backup = false;
				}

				if (path->state == TQUIC_PATH_VALIDATED ||
				    path->state == TQUIC_PATH_ACTIVE ||
				    path->state == TQUIC_PATH_STANDBY) {
					tquic_path_set_state(path, new_state);
				}
			}
			tquic_path_put(path);
		}
	}

	return offset;
}
EXPORT_SYMBOL_GPL(quic_frame_process_path_status);

/*
 * ============================================================================
 * Multipath Frame Generation
 * ============================================================================
 */

/**
 * quic_frame_create_path_abandon - Create PATH_ABANDON frame
 * @path_id: Path identifier to abandon
 * @error_code: Error code for abandonment reason
 * @reason: Optional reason phrase (may be NULL)
 * @reason_len: Length of reason phrase
 *
 * Returns sk_buff containing the frame, or NULL on error.
 */
struct sk_buff *quic_frame_create_path_abandon(u64 path_id, u64 error_code,
					       const char *reason, u32 reason_len)
{
	struct sk_buff *skb;
	u8 *p;
	int frame_len;
	int type_len, path_len, err_len, rlen_len;

	/* Calculate frame size */
	type_len = quic_varint_len(QUIC_FRAME_PATH_ABANDON);
	path_len = quic_varint_len(path_id);
	err_len = quic_varint_len(error_code);
	rlen_len = quic_varint_len(reason_len);
	frame_len = type_len + path_len + err_len + rlen_len + reason_len;

	skb = alloc_skb(frame_len + 16, GFP_ATOMIC);
	if (!skb)
		return NULL;

	p = skb_put(skb, frame_len);

	/* Frame Type */
	p += quic_varint_encode(QUIC_FRAME_PATH_ABANDON, p);

	/* Path Identifier */
	p += quic_varint_encode(path_id, p);

	/* Error Code */
	p += quic_varint_encode(error_code, p);

	/* Reason Phrase Length */
	p += quic_varint_encode(reason_len, p);

	/* Reason Phrase */
	if (reason_len > 0 && reason)
		memcpy(p, reason, reason_len);

	return skb;
}
EXPORT_SYMBOL_GPL(quic_frame_create_path_abandon);

/**
 * quic_frame_create_path_standby - Create PATH_STANDBY frame
 * @path_id: Path identifier to mark as standby
 * @seq_num: Path status sequence number
 *
 * Returns sk_buff containing the frame, or NULL on error.
 */
struct sk_buff *quic_frame_create_path_standby(u64 path_id, u64 seq_num)
{
	struct sk_buff *skb;
	u8 *p;
	int frame_len;
	int type_len, path_len, seq_len;

	/* Calculate frame size */
	type_len = quic_varint_len(QUIC_FRAME_PATH_STANDBY);
	path_len = quic_varint_len(path_id);
	seq_len = quic_varint_len(seq_num);
	frame_len = type_len + path_len + seq_len;

	skb = alloc_skb(frame_len + 16, GFP_ATOMIC);
	if (!skb)
		return NULL;

	p = skb_put(skb, frame_len);

	/* Frame Type */
	p += quic_varint_encode(QUIC_FRAME_PATH_STANDBY, p);

	/* Path Identifier */
	p += quic_varint_encode(path_id, p);

	/* Path Status Sequence Number */
	quic_varint_encode(seq_num, p);

	return skb;
}
EXPORT_SYMBOL_GPL(quic_frame_create_path_standby);

/**
 * quic_frame_create_path_available - Create PATH_AVAILABLE frame
 * @path_id: Path identifier to mark as available
 * @seq_num: Path status sequence number
 *
 * Returns sk_buff containing the frame, or NULL on error.
 */
struct sk_buff *quic_frame_create_path_available(u64 path_id, u64 seq_num)
{
	struct sk_buff *skb;
	u8 *p;
	int frame_len;
	int type_len, path_len, seq_len;

	/* Calculate frame size */
	type_len = quic_varint_len(QUIC_FRAME_PATH_AVAILABLE);
	path_len = quic_varint_len(path_id);
	seq_len = quic_varint_len(seq_num);
	frame_len = type_len + path_len + seq_len;

	skb = alloc_skb(frame_len + 16, GFP_ATOMIC);
	if (!skb)
		return NULL;

	p = skb_put(skb, frame_len);

	/* Frame Type */
	p += quic_varint_encode(QUIC_FRAME_PATH_AVAILABLE, p);

	/* Path Identifier */
	p += quic_varint_encode(path_id, p);

	/* Path Status Sequence Number */
	quic_varint_encode(seq_num, p);

	return skb;
}
EXPORT_SYMBOL_GPL(quic_frame_create_path_available);

/**
 * quic_send_path_abandon - Send PATH_ABANDON frame for a path
 * @conn: QUIC connection
 * @path: Path to abandon
 * @error_code: Error code for abandonment
 *
 * Queues a PATH_ABANDON frame for transmission.
 * Returns 0 on success, negative error code on failure.
 */
int quic_send_path_abandon(struct quic_connection *conn, struct tquic_path *path,
			   u64 error_code)
{
	struct sk_buff *skb;

	if (!conn || !path)
		return -EINVAL;

	skb = quic_frame_create_path_abandon(path->path_id, error_code, NULL, 0);
	if (!skb)
		return -ENOMEM;

	if (quic_conn_queue_frame(conn, skb))
		return -ENOBUFS;
	schedule_work(&conn->tx_work);

	pr_debug("QUIC: queued PATH_ABANDON for path %u error=%llu\n",
		 path->path_id, error_code);

	return 0;
}
EXPORT_SYMBOL_GPL(quic_send_path_abandon);

/**
 * quic_send_path_standby - Send PATH_STANDBY frame for a path
 * @conn: QUIC connection
 * @path: Path to mark as standby
 *
 * Queues a PATH_STANDBY frame for transmission.
 * Returns 0 on success, negative error code on failure.
 */
int quic_send_path_standby(struct quic_connection *conn, struct tquic_path *path)
{
	struct sk_buff *skb;
	u64 seq_num;

	if (!conn || !path)
		return -EINVAL;

	/* Increment sequence number for this status update */
	seq_num = ++path->status_seq_num;

	skb = quic_frame_create_path_standby(path->path_id, seq_num);
	if (!skb)
		return -ENOMEM;

	if (quic_conn_queue_frame(conn, skb))
		return -ENOBUFS;
	schedule_work(&conn->tx_work);

	pr_debug("QUIC: queued PATH_STANDBY for path %u seq=%llu\n",
		 path->path_id, seq_num);

	return 0;
}
EXPORT_SYMBOL_GPL(quic_send_path_standby);

/**
 * quic_send_path_available - Send PATH_AVAILABLE frame for a path
 * @conn: QUIC connection
 * @path: Path to mark as available
 *
 * Queues a PATH_AVAILABLE frame for transmission.
 * Returns 0 on success, negative error code on failure.
 */
int quic_send_path_available(struct quic_connection *conn, struct tquic_path *path)
{
	struct sk_buff *skb;
	u64 seq_num;

	if (!conn || !path)
		return -EINVAL;

	/* Increment sequence number for this status update */
	seq_num = ++path->status_seq_num;

	skb = quic_frame_create_path_available(path->path_id, seq_num);
	if (!skb)
		return -ENOMEM;

	if (quic_conn_queue_frame(conn, skb))
		return -ENOBUFS;
	schedule_work(&conn->tx_work);

	pr_debug("QUIC: queued PATH_AVAILABLE for path %u seq=%llu\n",
		 path->path_id, seq_num);

	return 0;
}
EXPORT_SYMBOL_GPL(quic_send_path_available);

/**
 * quic_mp_frame_is_multipath - Check if first byte could be multipath frame
 * @first_byte: First byte of frame data
 *
 * Multipath frame types start with specific prefixes. This is a quick
 * check before doing full varint decoding.
 *
 * Returns true if frame could be a multipath extension frame.
 */
bool quic_mp_frame_is_multipath(u8 first_byte)
{
	/*
	 * Multipath frames have type 0x15228c05-0x15228c08.
	 * These start with 0xc0 | 0x15 = 0xd5 when varint encoded.
	 * (4-byte varint prefix is 0xc0)
	 */
	return (first_byte == 0xd5);
}
EXPORT_SYMBOL_GPL(quic_mp_frame_is_multipath);

/**
 * quic_mp_frame_process - Try to process frame as multipath extension
 * @conn: QUIC connection
 * @data: Frame data
 * @len: Length of frame data
 *
 * Attempts to decode and process the frame as a multipath extension frame.
 * Returns positive bytes consumed on success, 0 if not a multipath frame,
 * or negative error code on failure.
 */
int quic_mp_frame_process(struct quic_connection *conn, const u8 *data, int len)
{
	u64 frame_type;
	int varint_len;

	if (len < 1)
		return 0;

	/* Quick check for multipath frame prefix */
	if (!quic_mp_frame_is_multipath(data[0]))
		return 0;

	/* Decode frame type */
	varint_len = quic_varint_decode(data, len, &frame_type);
	if (varint_len < 0)
		return 0;  /* Not a valid varint, let standard handler deal with it */

	switch (frame_type) {
	case QUIC_FRAME_PATH_ABANDON:
		return quic_frame_process_path_abandon(conn, data, len);

	case QUIC_FRAME_PATH_STANDBY:
		return quic_frame_process_path_status(conn, data, len, true);

	case QUIC_FRAME_PATH_AVAILABLE:
		return quic_frame_process_path_status(conn, data, len, false);

	default:
		/* Not a known multipath frame */
		return 0;
	}
}
EXPORT_SYMBOL_GPL(quic_mp_frame_process);
