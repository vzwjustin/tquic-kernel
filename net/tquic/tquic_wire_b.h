/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: Private declarations for tquic_wire_b.c
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 *
 * Functions declared here are EXPORT_SYMBOL_GPL'd from their
 * respective .c files but are not yet exposed in a public header.
 * Once promoted to a public API they should move to include/net/tquic.h.
 */

#ifndef _TQUIC_WIRE_B_H
#define _TQUIC_WIRE_B_H

#include <linux/types.h>
#include <linux/gfp.h>
#include <net/tquic.h>

/*
 * tquic_netlink.c — event notification helpers.
 * tquic_nl_path_info is private to tquic_netlink.c so only the
 * path-info-free variants are listed here.
 */
int tquic_nl_send_event(struct net *net, enum tquic_event_type event,
			u64 conn_id, u32 path_id, u32 reason, gfp_t gfp);
int tquic_nl_migration_event(struct net *net, u64 conn_id, u32 old_path_id,
			     u32 new_path_id, u32 reason, gfp_t gfp);
bool tquic_nl_has_listeners(struct net *net);
void tquic_nl_notify_migration(struct net *net, u64 conn_id, u32 old_path_id,
			       u32 new_path_id, u32 reason);

#endif /* _TQUIC_WIRE_B_H */
