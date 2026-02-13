/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: Path Manager Declarations
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 */

#ifndef _TQUIC_PATH_MANAGER_H
#define _TQUIC_PATH_MANAGER_H

struct tquic_connection;
struct tquic_path;

/* Path manager response handling */
int tquic_pm_send_response(struct tquic_connection *conn,
			   struct tquic_path *path,
			   const u8 *challenge_data);
int tquic_pm_handle_response(struct tquic_connection *conn,
			     struct tquic_path *path, const u8 *data);

/* Path selection */
struct tquic_path *tquic_pm_select_path(struct tquic_connection *conn);

#endif /* _TQUIC_PATH_MANAGER_H */
