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

struct tquic_rate_limiter;
struct tquic_token_key;
struct tquic_retry_state;
struct tquic_tunnel;
struct tquic_client;

/*
 * tquic_netlink.c -- event notification helpers.
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

/*
 * tquic_wire_b.c -- cross-file wiring hooks for dead exports (group B).
 */

/* ACK / Loss / TX notification hooks */
void tquic_wire_b_on_ack(struct tquic_connection *conn,
			 struct tquic_path *path, u32 pkt_size,
			 u64 pkt_num, bool is_probe_ack);
void tquic_wire_b_on_loss(struct tquic_connection *conn,
			  struct tquic_path *path, u32 pkt_size,
			  u64 pkt_num, bool is_probe_loss);
void tquic_wire_b_on_send(struct tquic_connection *conn,
			  struct tquic_path *path, u32 pkt_size);

/* Connection lifecycle hooks */
void tquic_wire_b_conn_init(struct sock *sk);
void tquic_wire_b_conn_close(struct tquic_connection *conn, struct sock *sk);

/* Path lifecycle hooks */
void tquic_wire_b_path_init(struct tquic_connection *conn,
			    struct tquic_path *path);
void tquic_wire_b_path_down(struct tquic_connection *conn,
			    struct tquic_path *path);

/* Retry state hooks */
struct tquic_retry_state *tquic_wire_b_retry_alloc(void);
void tquic_wire_b_retry_free(struct tquic_retry_state *state);
bool tquic_wire_b_retry_verify(u32 version, const u8 *odcid, u8 odcid_len,
			       const u8 *retry_pkt, size_t retry_len,
			       const u8 *tag);

/* Token API hooks */
int tquic_wire_b_token_ops(struct tquic_token_key *key,
			   const struct sockaddr_storage *client_addr,
			   u8 *token_out, u32 *token_len_out);

/* Stateless reset hooks */
void tquic_wire_b_stateless_reset_ops(struct tquic_connection *conn,
				      const struct tquic_cid *cid,
				      const u8 *token);

/* Rate limiter hooks */
bool tquic_wire_b_rate_limit_ops(struct tquic_rate_limiter *limiter,
				 struct net *net,
				 const struct sockaddr_storage *src_addr);

/* QoS hooks */
u8 tquic_wire_b_qos_ops(struct tquic_tunnel *tunnel);

/* Forward hooks */
int tquic_wire_b_forward_ops(struct tquic_client *client,
			     struct tquic_connection *conn,
			     struct net_device *dev);
u32 tquic_wire_b_forward_mtu(struct tquic_tunnel *tunnel);

/* Tunnel hooks */
void tquic_wire_b_tunnel_ops(struct tquic_tunnel *tunnel);
int tquic_wire_b_tunnel_icmp(struct tquic_tunnel *tunnel,
			     struct sk_buff *skb, int direction,
			     u8 icmp_type, u8 icmp_code, u32 icmp_info);

/* Netlink notification hooks */
void tquic_wire_b_nl_ops(struct net *net, u64 conn_id,
			 u32 old_path_id, u32 new_path_id);

/* Migration sub-API hooks */
void tquic_wire_b_migration_ops(struct tquic_connection *conn,
				const struct sockaddr_storage *new_addr,
				struct sk_buff *skb);
int tquic_wire_b_session_resume(struct tquic_connection *conn,
				const u8 *session_id, u32 session_id_len);

/* Server PSK / handshake hooks */
int tquic_wire_b_server_psk(struct sock *sk, struct sk_buff *initial_pkt,
			    const char *identity, u8 identity_len,
			    u8 *psk_out);
void tquic_wire_b_zero_rtt_response(struct sock *sk, bool accepted);
int tquic_wire_b_store_ticket(struct sock *sk, const char *server_name,
			      u8 server_name_len, const u8 *ticket_data,
			      u32 ticket_len, const u8 *psk, u32 psk_len,
			      u16 cipher_suite, u32 max_age);

/* Sysctl accessor hook */
int tquic_wire_b_per_ip_limit(void);

/* IPv6 path hooks (CONFIG_TQUIC_IPV6) */
#if IS_ENABLED(CONFIG_TQUIC_IPV6)
int tquic_wire_b_v6_add_path(struct tquic_connection *conn,
			     struct sockaddr_in6 *local,
			     struct sockaddr_in6 *remote);
int tquic_wire_b_v6_discover(struct tquic_connection *conn,
			     struct sockaddr_storage *addrs, int max_addrs);
#endif

#endif /* _TQUIC_WIRE_B_H */
