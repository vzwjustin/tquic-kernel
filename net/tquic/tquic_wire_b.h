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
#include <linux/list.h>
#include <linux/rcupdate.h>
#include <linux/refcount.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <net/tquic.h>

struct tquic_rate_limiter;
struct tquic_token_key;
struct tquic_retry_state;
struct tquic_tunnel;
struct tquic_client;

/*
 * Event type enum shared between tquic_netlink.c and callers.
 * Guard prevents double-definition when tquic_netlink.c also defines it.
 */
#ifndef _TQUIC_EVENT_TYPE_DEFINED
#define _TQUIC_EVENT_TYPE_DEFINED
enum tquic_event_type {
	TQUIC_EVENT_UNSPEC,
	TQUIC_EVENT_PATH_UP,		/* Path became available */
	TQUIC_EVENT_PATH_DOWN,		/* Path failed */
	TQUIC_EVENT_PATH_CHANGE,	/* Path metrics changed */
	TQUIC_EVENT_MIGRATION,		/* Connection migrated */

	__TQUIC_EVENT_MAX,
};
#define TQUIC_EVENT_MAX (__TQUIC_EVENT_MAX - 1)
#endif /* _TQUIC_EVENT_TYPE_DEFINED */

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
 * struct tquic_nl_path_info - Netlink path information snapshot.
 *
 * Used to communicate path state between the TQUIC core and the
 * generic netlink interface.  Canonical definition; guarded by
 * _TQUIC_NL_PATH_INFO_DEFINED to prevent double-definition in
 * tquic_netlink.c where this struct originated.
 */
#ifndef _TQUIC_NL_PATH_INFO_DEFINED
#define _TQUIC_NL_PATH_INFO_DEFINED
struct tquic_nl_path_info {
	struct list_head list;
	struct rcu_head rcu;
	refcount_t refcnt;

	u32 path_id;
	u8 state;
	u8 priority;
	u16 family;
	s32 ifindex;
	u32 flags;
	u32 weight;

	/* Addresses */
	union {
		struct in_addr local_addr4;
		struct in6_addr local_addr6;
	};
	union {
		struct in_addr remote_addr4;
		struct in6_addr remote_addr6;
	};
	__be16 local_port;
	__be16 remote_port;

	/* Metrics */
	u32 rtt;		/* RTT in microseconds */
	u64 bandwidth;		/* Bandwidth in bps */
	u32 loss_rate;		/* Loss rate in 0.01% */

	/* Statistics */
	u64 tx_packets;
	u64 rx_packets;
	u64 tx_bytes;
	u64 rx_bytes;
	u64 retransmissions;
	u64 spurious_retrans;
	u32 cwnd;
	u32 srtt;
	u32 rttvar;
};
#endif /* _TQUIC_NL_PATH_INFO_DEFINED */

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
