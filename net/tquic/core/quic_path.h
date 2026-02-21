/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: Path Management Declarations
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 */

#ifndef _TQUIC_QUIC_PATH_H
#define _TQUIC_QUIC_PATH_H

#include <linux/types.h>
#include <net/tquic.h>

struct tquic_connection;
struct tquic_path;
struct tquic_path_info;

/* Module lifecycle */
int __init tquic_path_init(void);
void tquic_path_exit(void);

/* RTT and PTO */
void tquic_path_rtt_update(struct tquic_path *path, u32 latest_rtt_us,
			   u32 ack_delay_us);
u32 tquic_path_pto(struct tquic_path *path);

/* MTU discovery (RFC 8899 DPLPMTUD) */
void tquic_path_mtu_discovery_start(struct tquic_path *path);
int tquic_path_mtu_probe(struct tquic_path *path);
void tquic_path_mtu_probe_acked(struct tquic_path *path, u32 probe_size);
void tquic_path_mtu_probe_lost(struct tquic_path *path, u32 probe_size);

/* Path validation (RFC 9000 Section 8.2) */
bool tquic_path_verify_response(struct tquic_path *path, const u8 *data);
void tquic_path_on_validated(struct tquic_path *path);
bool tquic_path_needs_probe(struct tquic_path *path);
void tquic_path_on_probe_timeout(struct tquic_path *path);

/* Path lookup and info */
struct tquic_path *tquic_path_find(struct tquic_connection *conn,
				   struct sockaddr *remote);
int tquic_path_get_info(struct tquic_path *path, struct tquic_path_info *info);

#endif /* _TQUIC_QUIC_PATH_H */
