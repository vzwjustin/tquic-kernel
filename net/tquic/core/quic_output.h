/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: Packet Output Path Declarations
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 */

#ifndef _TQUIC_QUIC_OUTPUT_H
#define _TQUIC_QUIC_OUTPUT_H

#include <linux/skbuff.h>

struct tquic_connection;
struct tquic_sent_packet;
struct tquic_stream;

/* SKB allocation and freeing */
struct sk_buff *tquic_alloc_tx_skb(struct tquic_connection *conn, u32 size);
void tquic_free_tx_skb(struct sk_buff *skb);

/* Packet output functions */
int tquic_output(struct tquic_connection *conn, struct sk_buff *skb);
int tquic_output_batch(struct tquic_connection *conn,
		       struct sk_buff_head *queue);
int tquic_output_paced(struct tquic_connection *conn, struct sk_buff *skb);
int tquic_output_gso(struct tquic_connection *conn,
		     struct sk_buff_head *queue);
struct sk_buff *tquic_coalesce_skbs(struct sk_buff_head *packets);
int tquic_output_coalesced(struct tquic_connection *conn,
			   struct sk_buff_head *packets);

/* Retransmission */
int tquic_retransmit(struct tquic_connection *conn,
		     struct tquic_sent_packet *pkt);

/* Send message */
int tquic_do_sendmsg(struct sock *sk, struct msghdr *msg, size_t len);

/* Stream handling */
void tquic_stream_handle_reset(struct tquic_stream *stream, u64 error_code,
			       u64 final_size);
void tquic_stream_handle_stop_sending(struct tquic_stream *stream,
				      u64 error_code);

/* Frame processing */
int tquic_frame_process_new_cid(struct tquic_connection *conn,
				const u8 *data, u32 len);

#endif /* _TQUIC_QUIC_OUTPUT_H */
