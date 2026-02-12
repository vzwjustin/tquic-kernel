/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: Path Abandonment Header for QUIC Multipath
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * API definitions for path abandonment in QUIC Multipath Extension (RFC 9369).
 */

#ifndef _TQUIC_PATH_ABANDON_H
#define _TQUIC_PATH_ABANDON_H

#include <linux/types.h>
#include <net/tquic.h>

#include "mp_frame.h"

/* Forward declaration */
struct tquic_mp_path_abandon_state;

/*
 * Path abandonment error codes
 */
#define TQUIC_MP_PATH_ERR_NONE			0x00
#define TQUIC_MP_PATH_ERR_ADMIN_SHUTDOWN	0x01
#define TQUIC_MP_PATH_ERR_INTERFACE_DOWN	0x02
#define TQUIC_MP_PATH_ERR_PATH_FAILED		0x03
#define TQUIC_MP_PATH_ERR_CAPACITY_EXCEEDED	0x04
#define TQUIC_MP_PATH_ERR_INTERNAL		0x05

/*
 * Path Abandonment State Management
 */

/**
 * tquic_mp_abandon_state_create - Create path abandonment state
 * @path: Path to create state for
 *
 * Returns allocated state or NULL on failure.
 */
struct tquic_mp_path_abandon_state *tquic_mp_abandon_state_create(
	struct tquic_path *path);

/**
 * tquic_mp_abandon_state_destroy - Destroy path abandonment state
 * @state: State to destroy
 */
void tquic_mp_abandon_state_destroy(struct tquic_mp_path_abandon_state *state);

/*
 * PATH_ABANDON Frame Handling
 */

/**
 * tquic_mp_handle_path_abandon - Handle received PATH_ABANDON frame
 * @conn: Connection
 * @frame: Parsed PATH_ABANDON frame
 *
 * Returns 0 on success or negative error.
 */
int tquic_mp_handle_path_abandon(struct tquic_connection *conn,
				 const struct tquic_mp_path_abandon *frame);

/**
 * tquic_mp_initiate_path_abandon - Initiate path abandonment
 * @conn: Connection
 * @path: Path to abandon
 * @error_code: Error code for abandonment
 * @reason: Reason phrase (can be NULL)
 * @reason_len: Length of reason phrase
 *
 * Returns 0 on success or negative error.
 */
int tquic_mp_initiate_path_abandon(struct tquic_connection *conn,
				   struct tquic_path *path,
				   u64 error_code,
				   const char *reason, size_t reason_len);

/*
 * Connection ID Management for Multipath
 */

/**
 * tquic_mp_retire_path_cids - Retire CIDs associated with a path
 * @conn: Connection
 * @path: Path whose CIDs to retire
 *
 * Returns 0 on success or negative error.
 */
int tquic_mp_retire_path_cids(struct tquic_connection *conn,
			      struct tquic_path *path);

/**
 * tquic_mp_issue_path_cid - Issue a new CID for a path
 * @conn: Connection
 * @path: Path to issue CID for
 *
 * Returns 0 on success or negative error.
 */
int tquic_mp_issue_path_cid(struct tquic_connection *conn,
			    struct tquic_path *path);

/**
 * tquic_mp_handle_new_connection_id - Handle MP_NEW_CONNECTION_ID frame
 * @conn: Connection
 * @frame: Parsed MP_NEW_CONNECTION_ID frame
 *
 * Returns 0 on success or negative error.
 */
int tquic_mp_handle_new_connection_id(struct tquic_connection *conn,
				      const struct tquic_mp_new_connection_id *frame);

/**
 * tquic_mp_handle_retire_connection_id - Handle MP_RETIRE_CONNECTION_ID frame
 * @conn: Connection
 * @frame: Parsed MP_RETIRE_CONNECTION_ID frame
 *
 * Returns 0 on success or negative error.
 */
int tquic_mp_handle_retire_connection_id(struct tquic_connection *conn,
					 const struct tquic_mp_retire_connection_id *frame);

/*
 * PATH_STATUS Frame Handling
 */

/**
 * tquic_mp_handle_path_status - Handle received PATH_STATUS frame
 * @conn: Connection
 * @frame: Parsed PATH_STATUS frame
 *
 * Returns 0 on success or negative error.
 */
int tquic_mp_handle_path_status(struct tquic_connection *conn,
				const struct tquic_mp_path_status *frame);

/**
 * tquic_mp_send_path_status - Send PATH_STATUS frame
 * @conn: Connection
 * @path: Path to report status for
 * @status: Path status value
 *
 * Returns 0 on success or negative error.
 */
int tquic_mp_send_path_status(struct tquic_connection *conn,
			      struct tquic_path *path, u64 status);

/*
 * Active Path Selection
 */

/**
 * tquic_mp_select_new_active_path - Select a new active path
 * @conn: Connection
 * @excluded_path: Path to exclude from selection
 *
 * Returns 0 on success or negative error if no path available.
 */
int tquic_mp_select_new_active_path(struct tquic_connection *conn,
				    struct tquic_path *excluded_path);

/*
 * Module Initialization
 */

/**
 * tquic_mp_abandon_init - Initialize path abandonment module
 */
int __init tquic_mp_abandon_init(void);

/**
 * tquic_mp_abandon_exit - Cleanup path abandonment module
 */
void tquic_mp_abandon_exit(void);

#endif /* _TQUIC_PATH_ABANDON_H */
