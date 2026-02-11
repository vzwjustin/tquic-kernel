/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * TQUIC - True QUIC with WAN Bonding
 *
 * 0-RTT Early Data Support Header (RFC 9001 Section 4.6)
 *
 * Copyright (c) 2026 Linux Foundation
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 */

#ifndef _NET_TQUIC_EARLY_DATA_H
#define _NET_TQUIC_EARLY_DATA_H

#include <linux/types.h>
#include <linux/skbuff.h>
#include <net/tquic.h>

/* Forward declarations */
struct tquic_connection;
struct tquic_sock;
struct tquic_session_ticket;
struct tquic_pn_space;

/*
 * 0-RTT Anti-Replay Protection (RFC 9001 Section 8)
 */
void tquic_anti_replay_init(void);
void tquic_anti_replay_cleanup(void);
bool tquic_anti_replay_check(const u8 *ticket, u32 ticket_len);

/*
 * 0-RTT Key Derivation (RFC 9001 Section 5.1)
 */
int tquic_early_data_derive_keys(struct tquic_connection *conn,
				 const struct tquic_session_ticket *ticket);

/*
 * 0-RTT Frame Validation (RFC 9001 Section 4.6.3)
 */
bool tquic_early_data_frame_allowed(u8 frame_type);

/*
 * 0-RTT Packet Building and Processing
 */
struct sk_buff *tquic_early_data_build_packet(struct tquic_connection *conn,
					      struct tquic_pn_space *pn_space);
int tquic_early_data_process_packet(struct tquic_connection *conn,
				    struct sk_buff *skb);

/*
 * 0-RTT Acceptance/Rejection
 */
void tquic_early_data_reject(struct tquic_connection *conn);
void tquic_early_data_accept(struct tquic_connection *conn);

/*
 * 0-RTT Connection State
 */
int tquic_early_data_init(struct tquic_connection *conn,
			  const struct tquic_session_ticket *ticket);
void tquic_early_data_cleanup(struct tquic_connection *conn);

/*
 * Session Ticket Management (RFC 9001 Section 4.6.1)
 */
int tquic_session_ticket_store(struct tquic_sock *tsk,
			       const struct tquic_session_ticket *ticket);
struct tquic_session_ticket *tquic_session_ticket_retrieve(struct tquic_sock *tsk);
bool tquic_session_ticket_valid(const struct tquic_session_ticket *ticket);

/*
 * Helper to check if 0-RTT is enabled and valid.
 *
 * LOCKING: Caller must hold conn->lock to ensure early_data_sent and
 * max_early_data are read atomically with respect to concurrent updates
 * from the transmit path.
 *
 * The pn_spaces array (not the void *crypto[] array) holds the
 * keys_available flag for each packet number space.
 */
static inline bool tquic_can_send_early_data(struct tquic_connection *conn)
{
	struct tquic_pn_space *pn;

	if (!conn->early_data_enabled || conn->early_data_rejected)
		return false;

	if (conn->early_data_sent >= conn->max_early_data)
		return false;

	if (!conn->pn_spaces)
		return false;

	pn = &conn->pn_spaces[TQUIC_PN_SPACE_APPLICATION];
	return pn->keys_available;
}

#endif /* _NET_TQUIC_EARLY_DATA_H */
