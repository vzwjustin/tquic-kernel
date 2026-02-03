/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * QUIC Multipath Extension Frame Definitions
 *
 * Frame types and processing functions for PATH_ABANDON, PATH_STANDBY,
 * and PATH_AVAILABLE frames per draft-ietf-quic-multipath.
 *
 * Copyright (c) 2024 Linux QUIC Authors
 */

#ifndef _QUIC_MP_FRAME_H
#define _QUIC_MP_FRAME_H

#include <linux/types.h>
#include <linux/skbuff.h>

struct quic_connection;
struct tquic_path;

/*
 * Multipath frame type constants (draft-ietf-quic-multipath)
 * These are the actual wire format values.
 */
#define QUIC_MP_FRAME_PATH_ABANDON	0x15228c05ULL
#define QUIC_MP_FRAME_PATH_STANDBY	0x15228c07ULL
#define QUIC_MP_FRAME_PATH_AVAILABLE	0x15228c08ULL

/*
 * PATH_ABANDON error codes (draft-ietf-quic-multipath Section 9)
 */
#define QUIC_MP_PATH_ERR_NO_ERROR		0x00
#define QUIC_MP_PATH_ERR_NO_VIABLE_PATH		0x10

/*
 * Frame processing functions
 */

/**
 * quic_frame_process_path_abandon - Process PATH_ABANDON frame
 * @conn: QUIC connection
 * @data: Frame data (starting with frame type)
 * @len: Length of frame data
 *
 * Processes a PATH_ABANDON frame received from peer.
 * Transitions the specified path to CLOSING state.
 *
 * Returns number of bytes consumed, or negative error code.
 */
int quic_frame_process_path_abandon(struct quic_connection *conn,
				    const u8 *data, int len);

/**
 * quic_frame_process_path_status - Process PATH_STANDBY or PATH_AVAILABLE frame
 * @conn: QUIC connection
 * @data: Frame data (starting with frame type)
 * @len: Length of frame data
 * @standby: true for PATH_STANDBY, false for PATH_AVAILABLE
 *
 * Processes a PATH_STANDBY or PATH_AVAILABLE frame.
 * Updates the path's state and backup flag accordingly.
 *
 * Returns number of bytes consumed, or negative error code.
 */
int quic_frame_process_path_status(struct quic_connection *conn,
				   const u8 *data, int len, bool standby);

/*
 * Frame creation functions
 */

/**
 * quic_frame_create_path_abandon - Create PATH_ABANDON frame
 * @path_id: Path identifier to abandon
 * @error_code: Error code (e.g., QUIC_MP_PATH_ERR_NO_ERROR)
 * @reason: Optional reason phrase (may be NULL)
 * @reason_len: Length of reason phrase
 *
 * Creates an sk_buff containing a properly formatted PATH_ABANDON frame.
 *
 * Returns sk_buff on success, NULL on allocation failure.
 */
struct sk_buff *quic_frame_create_path_abandon(u64 path_id, u64 error_code,
					       const char *reason, u32 reason_len);

/**
 * quic_frame_create_path_standby - Create PATH_STANDBY frame
 * @path_id: Path identifier to mark as standby
 * @seq_num: Path status sequence number
 *
 * Creates an sk_buff containing a properly formatted PATH_STANDBY frame.
 * The sequence number is used to order status updates and prevent
 * reordering issues.
 *
 * Returns sk_buff on success, NULL on allocation failure.
 */
struct sk_buff *quic_frame_create_path_standby(u64 path_id, u64 seq_num);

/**
 * quic_frame_create_path_available - Create PATH_AVAILABLE frame
 * @path_id: Path identifier to mark as available
 * @seq_num: Path status sequence number
 *
 * Creates an sk_buff containing a properly formatted PATH_AVAILABLE frame.
 *
 * Returns sk_buff on success, NULL on allocation failure.
 */
struct sk_buff *quic_frame_create_path_available(u64 path_id, u64 seq_num);

/*
 * Frame transmission helpers
 */

/**
 * quic_send_path_abandon - Send PATH_ABANDON frame
 * @conn: QUIC connection
 * @path: Path to abandon
 * @error_code: Error code for abandonment
 *
 * Creates and queues a PATH_ABANDON frame for transmission.
 * The path will be transitioned to CLOSING state.
 *
 * Returns 0 on success, negative error code on failure.
 */
int quic_send_path_abandon(struct quic_connection *conn, struct tquic_path *path,
			   u64 error_code);

/**
 * quic_send_path_standby - Send PATH_STANDBY frame
 * @conn: QUIC connection
 * @path: Path to mark as standby (backup)
 *
 * Creates and queues a PATH_STANDBY frame for transmission.
 * Automatically increments the path's status sequence number.
 * After sending, the peer should prefer other paths for traffic.
 *
 * Returns 0 on success, negative error code on failure.
 */
int quic_send_path_standby(struct quic_connection *conn, struct tquic_path *path);

/**
 * quic_send_path_available - Send PATH_AVAILABLE frame
 * @conn: QUIC connection
 * @path: Path to mark as available (active)
 *
 * Creates and queues a PATH_AVAILABLE frame for transmission.
 * Automatically increments the path's status sequence number.
 * After sending, the peer may use this path for traffic.
 *
 * Returns 0 on success, negative error code on failure.
 */
int quic_send_path_available(struct quic_connection *conn, struct tquic_path *path);

/*
 * Frame detection and dispatch
 */

/**
 * quic_mp_frame_is_multipath - Check if frame could be multipath extension
 * @first_byte: First byte of frame data
 *
 * Quick check based on the first byte to determine if the frame
 * might be a multipath extension frame. This avoids full varint
 * decoding for most standard frames.
 *
 * Returns true if frame could be a multipath extension frame.
 */
bool quic_mp_frame_is_multipath(u8 first_byte);

/**
 * quic_mp_frame_process - Try to process frame as multipath extension
 * @conn: QUIC connection
 * @data: Frame data
 * @len: Length of frame data
 *
 * Attempts to decode and process the frame as a multipath extension
 * frame. Should be called from the main frame processing loop when
 * quic_mp_frame_is_multipath() returns true.
 *
 * Returns positive bytes consumed on success, 0 if not a recognized
 * multipath frame, or negative error code on processing failure.
 */
int quic_mp_frame_process(struct quic_connection *conn, const u8 *data, int len);

#endif /* _QUIC_MP_FRAME_H */
