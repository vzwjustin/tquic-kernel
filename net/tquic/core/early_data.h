/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * QUIC - Quick UDP Internet Connections
 *
 * 0-RTT Early Data Support Header (RFC 9001 Section 4.6)
 *
 * Copyright (c) 2024 Linux QUIC Authors
 */

#ifndef _NET_QUIC_EARLY_DATA_H
#define _NET_QUIC_EARLY_DATA_H

#include <linux/types.h>
#include <linux/skbuff.h>
#include <net/quic.h>

/*
 * 0-RTT Anti-Replay Protection (RFC 9001 Section 8)
 */
void quic_anti_replay_init(void);
void quic_anti_replay_cleanup(void);
bool quic_anti_replay_check(const u8 *ticket, u32 ticket_len);

/*
 * 0-RTT Key Derivation (RFC 9001 Section 5.1)
 */
int quic_early_data_derive_keys(struct quic_connection *conn,
				const struct quic_session_ticket *ticket);

/*
 * 0-RTT Frame Validation (RFC 9001 Section 4.6.3)
 */
bool quic_early_data_frame_allowed(u8 frame_type);

/*
 * 0-RTT Packet Building and Processing
 */
struct sk_buff *quic_early_data_build_packet(struct quic_connection *conn,
					     struct quic_pn_space *pn_space);
int quic_early_data_process_packet(struct quic_connection *conn,
				   struct sk_buff *skb);

/*
 * 0-RTT Acceptance/Rejection
 */
void quic_early_data_reject(struct quic_connection *conn);
void quic_early_data_accept(struct quic_connection *conn);

/*
 * 0-RTT Connection State
 */
int quic_early_data_init(struct quic_connection *conn,
			 const struct quic_session_ticket *ticket);
void quic_early_data_cleanup(struct quic_connection *conn);

/*
 * Session Ticket Management (RFC 9001 Section 4.6.1)
 */
int quic_session_ticket_store(struct quic_sock *qsk,
			      const struct quic_session_ticket *ticket);
struct quic_session_ticket *quic_session_ticket_retrieve(struct quic_sock *qsk);
bool quic_session_ticket_valid(const struct quic_session_ticket *ticket);

/*
 * Helper macro to check if 0-RTT is enabled and valid
 */
#define quic_can_send_early_data(conn) \
	((conn)->early_data_enabled && \
	 !(conn)->early_data_rejected && \
	 (conn)->early_data_sent < (conn)->max_early_data && \
	 (conn)->crypto[QUIC_CRYPTO_EARLY_DATA].keys_available)

#endif /* _NET_QUIC_EARLY_DATA_H */
