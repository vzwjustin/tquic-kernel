/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: Path Manager Declarations
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 */

#ifndef _TQUIC_PATH_MANAGER_H
#define _TQUIC_PATH_MANAGER_H

#include <linux/types.h>
#include <linux/socket.h>

struct tquic_connection;
struct tquic_path;
struct tquic_additional_address;
struct tquic_cid;
enum tquic_addr_select_policy;

/* Path manager response handling */
int tquic_pm_send_response(struct tquic_connection *conn,
			   struct tquic_path *path,
			   const u8 *challenge_data);
int tquic_pm_handle_response(struct tquic_connection *conn,
			     struct tquic_path *path, const u8 *data);

/* Path selection */
struct tquic_path *tquic_pm_select_path(struct tquic_connection *conn);

/* Path weight */
int tquic_path_set_weight(struct tquic_path *path, u8 weight);

/* Path probe */
int tquic_path_probe(struct tquic_connection *conn, struct tquic_path *path);

/* Path lookup */
struct tquic_path *tquic_conn_get_path_locked(struct tquic_connection *conn,
					      u32 path_id);
int tquic_conn_add_path_safe(struct tquic_connection *conn,
			     struct sockaddr *local, struct sockaddr *remote);

/* Address discovery */
int tquic_pm_init_address_discovery(struct tquic_connection *conn);
void tquic_pm_cleanup_address_discovery(struct tquic_connection *conn);
int tquic_pm_discover_addresses(struct tquic_connection *conn,
				struct sockaddr_storage *addrs, int max_addrs);

/* Additional address management */
int tquic_pm_init_additional_addresses(struct tquic_connection *conn);
void tquic_pm_cleanup_additional_addresses(struct tquic_connection *conn);
int tquic_pm_add_local_additional_address(struct tquic_connection *conn,
					  const struct sockaddr_storage *addr,
					  const struct tquic_cid *cid);
int tquic_pm_remove_local_additional_address(
	struct tquic_connection *conn, const struct sockaddr_storage *addr);
int tquic_pm_validate_additional_address(
	struct tquic_connection *conn,
	struct tquic_additional_address *addr_entry);
int tquic_pm_notify_observed_address(struct tquic_connection *conn,
				     struct tquic_path *path);
bool tquic_pm_check_address_change(struct tquic_connection *conn,
				   const struct sockaddr_storage *from_addr,
				   struct tquic_path *path);

/* Path to additional address */
struct tquic_path *tquic_pm_create_path_to_additional(
	struct tquic_connection *conn,
	struct tquic_additional_address *addr_entry);
struct tquic_additional_address *tquic_pm_get_best_additional_address(
	struct tquic_connection *conn,
	enum tquic_addr_select_policy policy);
int tquic_pm_coordinate_preferred_and_additional(struct tquic_connection *conn);

/* PM alloc/free path IDs */
u32 tquic_pm_alloc_path_id(struct net *net);
void tquic_pm_free_path_id(struct net *net, u32 path_id);

#endif /* _TQUIC_PATH_MANAGER_H */
