/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * TQUIC Multipath Extension Frame Definitions
 *
 * Frame types and processing functions for PATH_ABANDON, PATH_STATUS_BACKUP,
 * and PATH_STATUS_AVAILABLE frames per RFC 9369.
 *
 * Copyright (c) 2024-2026 Linux QUIC Authors
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 */

#ifndef _TQUIC_MP_FRAME_H
#define _TQUIC_MP_FRAME_H

#include <linux/types.h>
#include <linux/skbuff.h>

struct tquic_connection;
struct tquic_path;

/*
 * Multipath frame type constants (RFC 9369)
 */
#define TQUIC_MP_FRAME_PATH_ABANDON		0x15c0
#define TQUIC_MP_FRAME_PATH_STATUS_BACKUP	0x15c2
#define TQUIC_MP_FRAME_PATH_STATUS_AVAILABLE	0x15c3

/*
 * PATH_ABANDON error codes (RFC 9369 Section 5.3)
 */
#define TQUIC_MP_PATH_ERR_NO_ERROR		0x00
#define TQUIC_MP_PATH_ERR_NO_VIABLE_PATH	0x10

/*
 * Frame processing functions
 */

/**
 * tquic_frame_process_path_abandon - Process PATH_ABANDON frame
 * @conn: TQUIC connection
 * @data: Frame data (starting with frame type)
 * @len: Length of frame data
 *
 * Processes a PATH_ABANDON frame received from peer.
 * Transitions the specified path to CLOSED state.
 *
 * Returns number of bytes consumed, or negative error code.
 */
int tquic_frame_process_path_abandon(struct tquic_connection *conn,
				     const u8 *data, int len);

/**
 * tquic_frame_process_path_status - Process PATH_STATUS_BACKUP or PATH_STATUS_AVAILABLE frame
 * @conn: TQUIC connection
 * @data: Frame data (starting with frame type)
 * @len: Length of frame data
 * @backup: true for PATH_STATUS_BACKUP, false for PATH_STATUS_AVAILABLE
 *
 * Processes a PATH_STATUS frame.
 * Updates the path's state and backup flag accordingly.
 *
 * Returns number of bytes consumed, or negative error code.
 */
int tquic_frame_process_path_status(struct tquic_connection *conn,
				    const u8 *data, int len, bool backup);

/*
 * Frame creation functions
 */

/**
 * tquic_frame_create_path_abandon - Create PATH_ABANDON frame
 * @path_id: Path identifier to abandon
 * @error_code: Error code (e.g., TQUIC_MP_PATH_ERR_NO_ERROR)
 * @reason: Optional reason phrase (may be NULL)
 * @reason_len: Length of reason phrase
 *
 * Creates an sk_buff containing a properly formatted PATH_ABANDON frame.
 *
 * Returns sk_buff on success, NULL on allocation failure.
 */
struct sk_buff *tquic_frame_create_path_abandon(u64 path_id, u64 error_code,
						const char *reason, u32 reason_len);

/**
 * tquic_frame_create_path_status_backup - Create PATH_STATUS_BACKUP frame
 * @path_id: Path identifier to mark as backup
 * @seq_num: Path status sequence number
 *
 * Creates an sk_buff containing a properly formatted PATH_STATUS_BACKUP frame.
 * The sequence number is used to order status updates and prevent
 * reordering issues.
 *
 * Returns sk_buff on success, NULL on allocation failure.
 */
struct sk_buff *tquic_frame_create_path_status_backup(u64 path_id, u64 seq_num);

/**
 * tquic_frame_create_path_status_available - Create PATH_STATUS_AVAILABLE frame
 * @path_id: Path identifier to mark as available
 * @seq_num: Path status sequence number
 *
 * Creates an sk_buff containing a properly formatted PATH_STATUS_AVAILABLE frame.
 *
 * Returns sk_buff on success, NULL on allocation failure.
 */
struct sk_buff *tquic_frame_create_path_status_available(u64 path_id, u64 seq_num);

/*
 * Frame transmission helpers
 */

/**
 * tquic_send_path_abandon - Send PATH_ABANDON frame
 * @conn: TQUIC connection
 * @path: Path to abandon
 * @error_code: Error code for abandonment
 *
 * Creates and queues a PATH_ABANDON frame for transmission.
 * The path will be transitioned to CLOSED state.
 *
 * Returns 0 on success, negative error code on failure.
 */
int tquic_send_path_abandon(struct tquic_connection *conn, struct tquic_path *path,
			    u64 error_code);

/**
 * tquic_send_path_status_backup - Send PATH_STATUS_BACKUP frame
 * @conn: TQUIC connection
 * @path: Path to mark as backup
 *
 * Creates and queues a PATH_STATUS_BACKUP frame for transmission.
 * Automatically increments the path's status sequence number.
 * After sending, the peer should prefer other paths for traffic.
 *
 * Returns 0 on success, negative error code on failure.
 */
int tquic_send_path_status_backup(struct tquic_connection *conn, struct tquic_path *path);

/**
 * tquic_send_path_status_available - Send PATH_STATUS_AVAILABLE frame
 * @conn: TQUIC connection
 * @path: Path to mark as available (active)
 *
 * Creates and queues a PATH_STATUS_AVAILABLE frame for transmission.
 * Automatically increments the path's status sequence number.
 * After sending, the peer may use this path for traffic.
 *
 * Returns 0 on success, negative error code on failure.
 */
int tquic_send_path_status_available(struct tquic_connection *conn, struct tquic_path *path);

/*
 * Frame detection and dispatch
 */

/**
 * tquic_mp_frame_is_multipath - Check if frame could be multipath extension
 * @first_byte: First byte of frame data
 *
 * Quick check based on the first byte to determine if the frame
 * might be a multipath extension frame. This avoids full varint
 * decoding for most standard frames.
 *
 * Returns true if frame could be a multipath extension frame.
 */
bool tquic_mp_frame_is_multipath(u8 first_byte);

/**
 * tquic_mp_frame_process - Try to process frame as multipath extension
 * @conn: TQUIC connection
 * @data: Frame data
 * @len: Length of frame data
 *
 * Attempts to decode and process the frame as a multipath extension
 * frame. Should be called from the main frame processing loop when
 * tquic_mp_frame_is_multipath() returns true.
 *
 * Returns positive bytes consumed on success, 0 if not a recognized
 * multipath frame, or negative error code on processing failure.
 */
int tquic_mp_frame_process(struct tquic_connection *conn, const u8 *data, int len);

/*
 * Compatibility aliases for code using old quic_* naming.
 *
 * When the implementation file (mp_frame.c) provides these as proper
 * symbol aliases via __attribute__((alias)), it defines
 * _TQUIC_MP_FRAME_ALIASES to suppress these macros and avoid
 * redefinition conflicts.
 */
#ifndef _TQUIC_MP_FRAME_ALIASES
#define quic_frame_process_path_abandon		tquic_frame_process_path_abandon
#define quic_frame_process_path_status		tquic_frame_process_path_status
#define quic_mp_frame_is_multipath		tquic_mp_frame_is_multipath
#define quic_mp_frame_process			tquic_mp_frame_process
#endif

/* Legacy constant aliases */
#define QUIC_MP_FRAME_PATH_ABANDON		TQUIC_MP_FRAME_PATH_ABANDON
#define QUIC_MP_FRAME_PATH_STANDBY		TQUIC_MP_FRAME_PATH_STATUS_BACKUP
#define QUIC_MP_FRAME_PATH_AVAILABLE		TQUIC_MP_FRAME_PATH_STATUS_AVAILABLE
#define QUIC_MP_PATH_ERR_NO_ERROR		TQUIC_MP_PATH_ERR_NO_ERROR
#define QUIC_MP_PATH_ERR_NO_VIABLE_PATH		TQUIC_MP_PATH_ERR_NO_VIABLE_PATH

#endif /* _TQUIC_MP_FRAME_H */
