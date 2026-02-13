/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: Loss Detection and Recovery Declarations
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 */

#ifndef _TQUIC_QUIC_LOSS_H
#define _TQUIC_QUIC_LOSS_H

#include <linux/types.h>
#include <linux/ktime.h>

struct tquic_connection;
struct tquic_sent_packet;
struct tquic_rtt_state;

/* Cache management */
int __init tquic_loss_cache_init(void);
void tquic_loss_cache_destroy(void);

/* Sent packet management */
struct tquic_sent_packet *tquic_sent_packet_alloc(gfp_t gfp);
void tquic_sent_packet_init(struct tquic_sent_packet *pkt,
			    u64 pn, u32 size, bool ack_eliciting);
void tquic_sent_packet_free(struct tquic_sent_packet *pkt);

/* RTT tracking */
void tquic_rtt_update(struct tquic_rtt_state *rtt, u64 latest_rtt,
		      u64 ack_delay);

/* Loss detection state machine */
void tquic_loss_detection_on_packet_sent(struct tquic_connection *conn,
					 struct tquic_sent_packet *pkt);
void tquic_loss_detection_on_ack_received(struct tquic_connection *conn,
					  u8 pn_space_idx);
void tquic_loss_detection_on_timeout(struct tquic_connection *conn);
void tquic_loss_on_packet_number_space_discarded(struct tquic_connection *conn,
						 u8 pn_space_idx);
void tquic_loss_mark_packet_lost(struct tquic_connection *conn,
				 struct tquic_sent_packet *pkt);

/* Statistics and queries */
u64 tquic_loss_get_bytes_in_flight(struct tquic_connection *conn);
ktime_t tquic_loss_get_oldest_unacked_time(struct tquic_connection *conn);

/* Recovery actions */
void tquic_loss_retransmit_unacked(struct tquic_connection *conn);
bool tquic_loss_check_persistent_congestion(struct tquic_connection *conn);

/* Cleanup */
void tquic_loss_cleanup_space(struct tquic_connection *conn, u8 pn_space_idx);
void tquic_loss_cleanup(struct tquic_connection *conn);

#endif /* _TQUIC_QUIC_LOSS_H */
