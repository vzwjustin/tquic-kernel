// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Protocol Handler Registration
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * This file implements the protocol handler registration for TQUIC,
 * including inet_protosw registration, network namespace support,
 * proc/sysctl per-netns registration, and socket creation callbacks.
 *
 * Based on patterns from net/sctp/protocol.c and net/ipv4/tcp_ipv4.c
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/sysctl.h>
#include <linux/inetdevice.h>

#include <linux/icmp.h>
#include <net/net_namespace.h>
#include <net/netns/generic.h>
#include <net/sock.h>
#include <net/protocol.h>
#include <net/ip.h>
#include <net/inet_common.h>
#include <net/inet_connection_sock.h>
#include <net/inet_hashtables.h>
#include <net/inet_sock.h>
#include <net/tcp.h>

#if IS_ENABLED(CONFIG_IPV6)
#include <net/ipv6.h>
#include <net/ip6_route.h>
#include <net/addrconf.h>
#include <net/transp_v6.h>
#endif

#include <net/tquic.h>

/* Tracepoints disabled for out-of-tree build - struct field mismatches */
#if 0
#define CREATE_TRACE_POINTS
#include <trace/events/tquic.h>
#endif

/* Stub out trace macros when disabled */
#define trace_tquic_conn_create(...)    do { } while (0)
#define trace_tquic_conn_destroy(...)   do { } while (0)
#define trace_tquic_handshake_start(...) do { } while (0)
#define trace_tquic_handshake_complete(...) do { } while (0)
#define trace_tquic_path_add(...)       do { } while (0)
#define trace_tquic_path_remove(...)    do { } while (0)
#define trace_tquic_path_state(...)     do { } while (0)
#define trace_tquic_migration(...)      do { } while (0)
#define trace_tquic_tx(...)             do { } while (0)
#define trace_tquic_rx(...)             do { } while (0)
#define trace_tquic_cong_event(...)     do { } while (0)
#define trace_tquic_rtt_update(...)     do { } while (0)
#define trace_tquic_loss_detected(...)  do { } while (0)

#include "protocol.h"

/* Network namespace identifier */
static unsigned int tquic_net_id __read_mostly;

/*
 * Per-network namespace TQUIC data
 */
struct tquic_net {
	/* Sysctl parameters */
	int enabled;
	int bond_mode;
	int max_paths;
	int reorder_window;
	int probe_interval;
	int failover_timeout;
	int idle_timeout;
	int initial_rtt;
	int initial_cwnd;
	int debug_level;

	/* Proc entries */
	struct proc_dir_entry *proc_net_tquic;

	/* Sysctl header */
	struct ctl_table_header *sysctl_header;

	/* Connection tracking for this namespace */
	struct list_head connections;
	spinlock_t conn_lock;
	atomic_t conn_count;

	/* Statistics */
	atomic64_t total_tx_bytes;
	atomic64_t total_rx_bytes;
	atomic64_t total_connections;
};

/* Access per-netns data */
static inline struct tquic_net *tquic_pernet(const struct net *net)
{
	return net_generic(net, tquic_net_id);
}

/*
 * TQUIC memory management (cannot use TCP's unexported symbols)
 */
static DEFINE_PER_CPU(int, tquic_sockets_allocated);
static struct percpu_counter tquic_sockets_allocated_counter;
static atomic_long_t tquic_memory_allocated;
static unsigned long tquic_memory_pressure;

/* TQUIC sysctl memory limits (in pages) */
static long sysctl_tquic_mem[3] = {
	768 * 1024,	/* Low threshold */
	1024 * 1024,	/* Pressure threshold */
	1536 * 1024	/* Hard limit */
};
static int sysctl_tquic_wmem[3] = { 4096, 16384, 4194304 };
static int sysctl_tquic_rmem[3] = { 4096, 131072, 6291456 };

/*
 * Forward declarations
 */
static int tquic_v4_rcv(struct sk_buff *skb);
static int tquic_v4_err(struct sk_buff *skb, u32 info);
static struct proto tquic_prot;
static const struct proto_ops tquic_inet_ops;

#if IS_ENABLED(CONFIG_IPV6)
static int tquic_v6_rcv(struct sk_buff *skb);
static int tquic_v6_err(struct sk_buff *skb, struct inet6_skb_parm *opt,
			u8 type, u8 code, int offset, __be32 info);
#endif

/* Scheduler/congestion helper stubs if not defined elsewhere */
__weak struct tquic_sched_ops *tquic_sched_find(const char *name)
{
	return NULL;
}

__weak void tquic_sched_set_default(const char *name)
{
}

__weak struct tquic_bond_state *tquic_bond_init(struct tquic_connection *conn)
{
	return NULL;
}

__weak void tquic_bond_cleanup(struct tquic_bond_state *bond)
{
}

__weak int tquic_bond_set_mode(struct tquic_connection *conn, u8 mode)
{
	return 0;
}

__weak int tquic_bond_get_stats(struct tquic_connection *conn,
				struct tquic_bond_stats *stats)
{
	memset(stats, 0, sizeof(*stats));
	return 0;
}

/*
 * IPv4 Protocol Handler
 */

/* IPv4 receive handler */
static int tquic_v4_rcv(struct sk_buff *skb)
{
	struct net *net = dev_net(skb->dev);
	struct tquic_net *tn = tquic_pernet(net);

	if (!tn->enabled) {
		kfree_skb(skb);
		return 0;
	}

	/*
	 * Process incoming QUIC packet:
	 * 1. Parse header to extract connection ID
	 * 2. Lookup connection by CID
	 * 3. Deliver to connection for processing
	 */
	atomic64_add(skb->len, &tn->total_rx_bytes);

	if (skb->len < 1) {
		kfree_skb(skb);
		return 0;
	}

	/* Check if long header (bit 7 set) or short header */
	if (skb->data[0] & 0x80) {
		/* Long header - extract DCID for lookup */
		struct tquic_cid dcid;
		struct tquic_connection *conn;
		u8 dcid_len;

		if (skb->len < 6) {
			kfree_skb(skb);
			return 0;
		}

		dcid_len = skb->data[5];
		if (dcid_len > TQUIC_MAX_CID_LEN || skb->len < 6 + dcid_len) {
			kfree_skb(skb);
			return 0;
		}

		dcid.len = dcid_len;
		memcpy(dcid.id, skb->data + 6, dcid_len);

		conn = tquic_conn_lookup_by_cid(&dcid);
		if (conn) {
			/* Deliver to connection's active path */
			tquic_udp_deliver_to_conn(conn, conn->active_path, skb);
			return 0;
		}
	} else {
		/* Short header - DCID starts at byte 1 */
		struct tquic_cid dcid;
		struct tquic_connection *conn;

		/* Use default CID length for short headers */
		if (skb->len < 1 + TQUIC_DEFAULT_CID_LEN) {
			kfree_skb(skb);
			return 0;
		}

		dcid.len = TQUIC_DEFAULT_CID_LEN;
		memcpy(dcid.id, skb->data + 1, TQUIC_DEFAULT_CID_LEN);

		conn = tquic_conn_lookup_by_cid(&dcid);
		if (conn) {
			tquic_udp_deliver_to_conn(conn, conn->active_path, skb);
			return 0;
		}
	}

	pr_debug("received TQUIC packet for unknown connection, len=%u\n",
		 skb->len);
	kfree_skb(skb);
	return 0;
}

/* IPv4 error handler */
static int tquic_v4_err(struct sk_buff *skb, u32 info)
{
	const struct iphdr *iph = ip_hdr(skb);
	struct tquic_connection *conn;
	struct tquic_path *path;

	pr_debug("received ICMP error for TQUIC, info=%u\n", info);

	/*
	 * Handle ICMP errors for TQUIC connections:
	 * - ICMP_DEST_UNREACH: Mark path as failed
	 * - ICMP_FRAG_NEEDED: Update path MTU
	 */
	switch (icmp_hdr(skb)->type) {
	case ICMP_DEST_UNREACH:
		if (icmp_hdr(skb)->code == ICMP_FRAG_NEEDED) {
			/* Path MTU discovery */
			u16 mtu = ntohs(icmp_hdr(skb)->un.frag.mtu);

			/* Find connection by destination IP */
			/* For now, log the event */
			pr_debug("TQUIC PMTUD: new MTU=%u for %pI4\n",
				 mtu, &iph->daddr);
		} else {
			/* Destination unreachable - path may have failed */
			pr_debug("TQUIC path unreachable: %pI4\n", &iph->daddr);
		}
		break;

	case ICMP_TIME_EXCEEDED:
		pr_debug("TQUIC TTL exceeded for %pI4\n", &iph->daddr);
		break;
	}

	return 0;
}

/* IPv4 net_protocol definition */
static const struct net_protocol tquic_protocol = {
	.handler	= tquic_v4_rcv,
	.err_handler	= tquic_v4_err,
	.no_policy	= 1,
};

/*
 * IPv6 Protocol Handler
 */
#if IS_ENABLED(CONFIG_IPV6)

/* IPv6 receive handler */
static int tquic_v6_rcv(struct sk_buff *skb)
{
	struct net *net = dev_net(skb->dev);
	struct tquic_net *tn = tquic_pernet(net);

	if (!tn->enabled) {
		kfree_skb(skb);
		return 0;
	}

	/*
	 * Process incoming QUIC packet over IPv6:
	 * Same logic as IPv4 handler.
	 */
	atomic64_add(skb->len, &tn->total_rx_bytes);

	if (skb->len < 1) {
		kfree_skb(skb);
		return 0;
	}

	/* Check if long header (bit 7 set) or short header */
	if (skb->data[0] & 0x80) {
		/* Long header - extract DCID for lookup */
		struct tquic_cid dcid;
		struct tquic_connection *conn;
		u8 dcid_len;

		if (skb->len < 6) {
			kfree_skb(skb);
			return 0;
		}

		dcid_len = skb->data[5];
		if (dcid_len > TQUIC_MAX_CID_LEN || skb->len < 6 + dcid_len) {
			kfree_skb(skb);
			return 0;
		}

		dcid.len = dcid_len;
		memcpy(dcid.id, skb->data + 6, dcid_len);

		conn = tquic_conn_lookup_by_cid(&dcid);
		if (conn) {
			tquic_udp_deliver_to_conn(conn, conn->active_path, skb);
			return 0;
		}
	} else {
		/* Short header - DCID starts at byte 1 */
		struct tquic_cid dcid;
		struct tquic_connection *conn;

		if (skb->len < 1 + TQUIC_DEFAULT_CID_LEN) {
			kfree_skb(skb);
			return 0;
		}

		dcid.len = TQUIC_DEFAULT_CID_LEN;
		memcpy(dcid.id, skb->data + 1, TQUIC_DEFAULT_CID_LEN);

		conn = tquic_conn_lookup_by_cid(&dcid);
		if (conn) {
			tquic_udp_deliver_to_conn(conn, conn->active_path, skb);
			return 0;
		}
	}

	pr_debug("received TQUIC v6 packet for unknown connection, len=%u\n",
		 skb->len);
	kfree_skb(skb);
	return 0;
}

/* IPv6 error handler */
static int tquic_v6_err(struct sk_buff *skb, struct inet6_skb_parm *opt,
			u8 type, u8 code, int offset, __be32 info)
{
	const struct ipv6hdr *ip6h = ipv6_hdr(skb);

	pr_debug("received ICMPv6 error for TQUIC, type=%u code=%u\n",
		 type, code);

	/*
	 * Handle ICMPv6 errors for TQUIC connections:
	 * - ICMPV6_DEST_UNREACH: Mark path as failed
	 * - ICMPV6_PKT_TOOBIG: Update path MTU
	 */
	switch (type) {
	case ICMPV6_DEST_UNREACH:
		pr_debug("TQUIC path unreachable: %pI6c\n", &ip6h->daddr);
		break;

	case ICMPV6_PKT_TOOBIG:
		/* Path MTU discovery for IPv6 */
		pr_debug("TQUIC PMTUD v6: new MTU=%u for %pI6c\n",
			 ntohl(info), &ip6h->daddr);
		break;

	case ICMPV6_TIME_EXCEED:
		pr_debug("TQUIC hop limit exceeded for %pI6c\n", &ip6h->daddr);
		break;
	}

	return 0;
}

/* IPv6 net_protocol definition */
static const struct inet6_protocol tquicv6_protocol = {
	.handler	= tquic_v6_rcv,
	.err_handler	= tquic_v6_err,
	.flags		= INET6_PROTO_NOPOLICY | INET6_PROTO_FINAL,
};

#endif /* CONFIG_IPV6 */

/*
 * Socket Creation Callback
 */
static int tquic_create_socket(struct net *net, struct socket *sock,
			       int protocol, int kern)
{
	struct tquic_net *tn = tquic_pernet(net);
	struct sock *sk;

	if (!tn->enabled)
		return -EPROTONOSUPPORT;

	/* Validate socket type */
	if (sock->type != SOCK_STREAM && sock->type != SOCK_DGRAM)
		return -ESOCKTNOSUPPORT;

	sock->state = SS_UNCONNECTED;

	/* Allocate sock structure */
	sk = sk_alloc(net, PF_INET, GFP_KERNEL, &tquic_prot, kern);
	if (!sk)
		return -ENOBUFS;

	sock_init_data(sock, sk);
	sk->sk_protocol = protocol;
	sock->ops = &tquic_inet_ops;

	/* Additional TQUIC-specific socket initialization */
	atomic64_inc(&tn->total_connections);

	pr_debug("created TQUIC socket, protocol=%d\n", protocol);

	return 0;
}

/*
 * IPv4 Socket Operations
 */

/* Socket release */
static int tquic_inet_release(struct socket *sock)
{
	struct sock *sk = sock->sk;

	if (!sk)
		return 0;

	return inet_release(sock);
}

/* IPv4 proto_ops */
static const struct proto_ops tquic_inet_ops = {
	.family		= PF_INET,
	.owner		= THIS_MODULE,
	.release	= tquic_inet_release,
	.bind		= inet_bind,
	.connect	= inet_stream_connect,
	.socketpair	= sock_no_socketpair,
	.accept		= inet_accept,
	.getname	= inet_getname,
	.poll		= tcp_poll,
	.ioctl		= inet_ioctl,
	.listen		= inet_listen,
	.shutdown	= inet_shutdown,
	.setsockopt	= sock_common_setsockopt,
	.getsockopt	= sock_common_getsockopt,
	.sendmsg	= inet_sendmsg,
	.recvmsg	= inet_recvmsg,
	.mmap		= sock_no_mmap,
};

/* TQUIC protocol definition for IPv4 */
static struct proto tquic_prot = {
	.name		= "TQUIC",
	.owner		= THIS_MODULE,
	.obj_size	= sizeof(struct tquic_sock),
	.close		= tquic_close,
	.connect	= tquic_connect,
	.sendmsg	= tquic_sendmsg,
	.recvmsg	= tquic_recvmsg,
	.hash		= inet_hash,
	.unhash		= inet_unhash,
	.get_port	= inet_csk_get_port,
	.sockets_allocated = &tquic_sockets_allocated_counter,
	.memory_allocated = &tquic_memory_allocated,
	.memory_pressure = &tquic_memory_pressure,
	.sysctl_mem	= sysctl_tquic_mem,
	.sysctl_wmem	= sysctl_tquic_wmem,
	.sysctl_rmem	= sysctl_tquic_rmem,
};

/* inet_protosw for TQUIC over IPv4 - SOCK_STREAM */
static struct inet_protosw tquic_stream_protosw = {
	.type		= SOCK_STREAM,
	.protocol	= IPPROTO_TQUIC,
	.prot		= &tquic_prot,
	.ops		= &tquic_inet_ops,
	.flags		= INET_PROTOSW_PERMANENT | INET_PROTOSW_ICSK,
};

/* inet_protosw for TQUIC over IPv4 - SOCK_DGRAM (for connectionless mode) */
static struct inet_protosw tquic_dgram_protosw = {
	.type		= SOCK_DGRAM,
	.protocol	= IPPROTO_TQUIC,
	.prot		= &tquic_prot,
	.ops		= &tquic_inet_ops,
	.flags		= INET_PROTOSW_PERMANENT,
};

/*
 * IPv6 Socket Operations
 */
#if IS_ENABLED(CONFIG_IPV6)

/* IPv6 proto_ops */
static const struct proto_ops tquic_inet6_ops = {
	.family		= PF_INET6,
	.owner		= THIS_MODULE,
	.release	= tquic_inet_release,
	.bind		= inet6_bind,
	.connect	= inet_stream_connect,
	.socketpair	= sock_no_socketpair,
	.accept		= inet_accept,
	.getname	= inet6_getname,
	.poll		= tcp_poll,
	.ioctl		= inet6_ioctl,
	.listen		= inet_listen,
	.shutdown	= inet_shutdown,
	.setsockopt	= sock_common_setsockopt,
	.getsockopt	= sock_common_getsockopt,
	.sendmsg	= inet_sendmsg,
	.recvmsg	= inet_recvmsg,
	.mmap		= sock_no_mmap,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= inet6_compat_ioctl,
#endif
};

/* TQUIC protocol definition for IPv6 */
static struct proto tquicv6_prot = {
	.name		= "TQUICv6",
	.owner		= THIS_MODULE,
	.obj_size	= sizeof(struct tquic_sock),
	.close		= tquic_close,
	.connect	= tquic_connect,
	.sendmsg	= tquic_sendmsg,
	.recvmsg	= tquic_recvmsg,
	.hash		= inet_hash,
	.unhash		= inet_unhash,
	.get_port	= inet_csk_get_port,
	.sockets_allocated = &tquic_sockets_allocated_counter,
	.memory_allocated = &tquic_memory_allocated,
	.memory_pressure = &tquic_memory_pressure,
	.sysctl_mem	= sysctl_tquic_mem,
	.sysctl_wmem	= sysctl_tquic_wmem,
	.sysctl_rmem	= sysctl_tquic_rmem,
};

/* inet6_protosw for TQUIC over IPv6 - SOCK_STREAM */
static struct inet_protosw tquicv6_stream_protosw = {
	.type		= SOCK_STREAM,
	.protocol	= IPPROTO_TQUIC,
	.prot		= &tquicv6_prot,
	.ops		= &tquic_inet6_ops,
	.flags		= INET_PROTOSW_PERMANENT | INET_PROTOSW_ICSK,
};

/* inet6_protosw for TQUIC over IPv6 - SOCK_DGRAM */
static struct inet_protosw tquicv6_dgram_protosw = {
	.type		= SOCK_DGRAM,
	.protocol	= IPPROTO_TQUIC,
	.prot		= &tquicv6_prot,
	.ops		= &tquic_inet6_ops,
	.flags		= INET_PROTOSW_PERMANENT,
};

#endif /* CONFIG_IPV6 */

/*
 * Net Protocol Family
 */
static const struct net_proto_family tquic_family_ops = {
	.family		= PF_INET,
	.create		= tquic_create_socket,
	.owner		= THIS_MODULE,
};

/*
 * Per-Network Namespace Sysctl
 */

/* Sysctl min/max values */
static int sysctl_zero;
static int sysctl_one = 1;
static int sysctl_max_paths = TQUIC_MAX_PATHS;
static int sysctl_max_reorder = 1024;
static int sysctl_max_timeout = 60000;
static int sysctl_max_rtt = 10000;
static int sysctl_max_cwnd = 10000;
static int sysctl_max_bond_mode = TQUIC_BOND_MODE_ECF;

/* Per-netns sysctl table template */
static struct ctl_table tquic_net_sysctl_table[] = {
	{
		.procname	= "enabled",
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &sysctl_zero,
		.extra2		= &sysctl_one,
	},
	{
		.procname	= "default_bond_mode",
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &sysctl_zero,
		.extra2		= &sysctl_max_bond_mode,
	},
	{
		.procname	= "max_paths",
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &sysctl_one,
		.extra2		= &sysctl_max_paths,
	},
	{
		.procname	= "reorder_window",
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &sysctl_one,
		.extra2		= &sysctl_max_reorder,
	},
	{
		.procname	= "probe_interval_ms",
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &sysctl_one,
		.extra2		= &sysctl_max_timeout,
	},
	{
		.procname	= "failover_timeout_ms",
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &sysctl_one,
		.extra2		= &sysctl_max_timeout,
	},
	{
		.procname	= "idle_timeout_ms",
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &sysctl_one,
		.extra2		= &sysctl_max_timeout,
	},
	{
		.procname	= "initial_rtt_ms",
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &sysctl_one,
		.extra2		= &sysctl_max_rtt,
	},
	{
		.procname	= "initial_cwnd_packets",
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &sysctl_one,
		.extra2		= &sysctl_max_cwnd,
	},
	{
		.procname	= "debug_level",
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{ }
};

static int tquic_net_sysctl_register(struct net *net)
{
	struct tquic_net *tn = tquic_pernet(net);
	struct ctl_table *table;
	int i;

	table = kmemdup(tquic_net_sysctl_table, sizeof(tquic_net_sysctl_table),
			GFP_KERNEL);
	if (!table)
		return -ENOMEM;

	/* Link sysctl entries to per-netns data */
	i = 0;
	table[i++].data = &tn->enabled;
	table[i++].data = &tn->bond_mode;
	table[i++].data = &tn->max_paths;
	table[i++].data = &tn->reorder_window;
	table[i++].data = &tn->probe_interval;
	table[i++].data = &tn->failover_timeout;
	table[i++].data = &tn->idle_timeout;
	table[i++].data = &tn->initial_rtt;
	table[i++].data = &tn->initial_cwnd;
	table[i++].data = &tn->debug_level;

	tn->sysctl_header = register_net_sysctl(net, "net/tquic", table);
	if (!tn->sysctl_header) {
		kfree(table);
		return -ENOMEM;
	}

	return 0;
}

static void tquic_net_sysctl_unregister(struct net *net)
{
	struct tquic_net *tn = tquic_pernet(net);
	struct ctl_table *table;

	if (tn->sysctl_header) {
		table = tn->sysctl_header->ctl_table_arg;
		unregister_net_sysctl_table(tn->sysctl_header);
		kfree(table);
		tn->sysctl_header = NULL;
	}
}

/*
 * Per-Network Namespace Proc Entries
 */

/* /proc/net/tquic/connections */
static int tquic_proc_connections_show(struct seq_file *s, void *v)
{
	struct net *net = seq_file_net(s);
	struct tquic_net *tn = tquic_pernet(net);

	seq_puts(s, "# TQUIC Connections (per-netns)\n");
	seq_puts(s, "# SCID State Paths Streams TxBytes RxBytes\n");

	spin_lock(&tn->conn_lock);
	/* TODO: Iterate through per-netns connection list */
	spin_unlock(&tn->conn_lock);

	seq_printf(s, "# Total connections: %d\n", atomic_read(&tn->conn_count));

	return 0;
}

/* /proc/net/tquic/paths */
static int tquic_proc_paths_show(struct seq_file *s, void *v)
{
	struct net *net = seq_file_net(s);
	struct tquic_net *tn = tquic_pernet(net);

	seq_puts(s, "# TQUIC Paths (WAN Bonding)\n");
	seq_puts(s, "# ConnID PathID State Prio Weight RTT(us) BW(Bps)\n");

	spin_lock(&tn->conn_lock);
	/* TODO: Iterate through paths */
	spin_unlock(&tn->conn_lock);

	return 0;
}

/* /proc/net/tquic/stats */
static int tquic_proc_stats_show(struct seq_file *s, void *v)
{
	struct net *net = seq_file_net(s);
	struct tquic_net *tn = tquic_pernet(net);

	seq_puts(s, "TQUIC Statistics (per-netns)\n");
	seq_puts(s, "============================\n");
	seq_printf(s, "Enabled:            %d\n", tn->enabled);
	seq_printf(s, "Active connections: %d\n", atomic_read(&tn->conn_count));
	seq_printf(s, "Total connections:  %llu\n",
		   atomic64_read(&tn->total_connections));
	seq_printf(s, "Bytes transmitted:  %llu\n",
		   atomic64_read(&tn->total_tx_bytes));
	seq_printf(s, "Bytes received:     %llu\n",
		   atomic64_read(&tn->total_rx_bytes));
	seq_printf(s, "Default bond mode:  %d\n", tn->bond_mode);
	seq_printf(s, "Max paths:          %d\n", tn->max_paths);
	seq_printf(s, "Reorder window:     %d\n", tn->reorder_window);
	seq_printf(s, "Probe interval:     %d ms\n", tn->probe_interval);
	seq_printf(s, "Failover timeout:   %d ms\n", tn->failover_timeout);
	seq_printf(s, "Idle timeout:       %d ms\n", tn->idle_timeout);
	seq_printf(s, "Initial RTT:        %d ms\n", tn->initial_rtt);
	seq_printf(s, "Initial cwnd:       %d\n", tn->initial_cwnd);

	return 0;
}

DEFINE_PROC_SHOW_ATTRIBUTE(tquic_proc_connections);
DEFINE_PROC_SHOW_ATTRIBUTE(tquic_proc_paths);
DEFINE_PROC_SHOW_ATTRIBUTE(tquic_proc_stats);

static int tquic_net_proc_init(struct net *net)
{
	struct tquic_net *tn = tquic_pernet(net);

	tn->proc_net_tquic = proc_net_mkdir(net, "tquic", net->proc_net);
	if (!tn->proc_net_tquic)
		return -ENOMEM;

	if (!proc_create_net_single("connections", 0444, tn->proc_net_tquic,
				    tquic_proc_connections_show, NULL))
		goto err;

	if (!proc_create_net_single("paths", 0444, tn->proc_net_tquic,
				    tquic_proc_paths_show, NULL))
		goto err;

	if (!proc_create_net_single("stats", 0444, tn->proc_net_tquic,
				    tquic_proc_stats_show, NULL))
		goto err;

	return 0;

err:
	remove_proc_subtree("tquic", net->proc_net);
	tn->proc_net_tquic = NULL;
	return -ENOMEM;
}

static void tquic_net_proc_exit(struct net *net)
{
	struct tquic_net *tn = tquic_pernet(net);

	if (tn->proc_net_tquic) {
		remove_proc_subtree("tquic", net->proc_net);
		tn->proc_net_tquic = NULL;
	}
}

/*
 * Per-Network Namespace Init/Exit
 */

/* Initialize per-netns TQUIC data and default values */
static int __net_init tquic_net_init(struct net *net)
{
	struct tquic_net *tn = tquic_pernet(net);
	int ret;

	/* Initialize default values */
	tn->enabled = 1;
	tn->bond_mode = TQUIC_BOND_MODE_AGGREGATE;
	tn->max_paths = TQUIC_MAX_PATHS;
	tn->reorder_window = 64;
	tn->probe_interval = 1000;
	tn->failover_timeout = 3000;
	tn->idle_timeout = 30000;
	tn->initial_rtt = 100;
	tn->initial_cwnd = 10;
	tn->debug_level = 0;

	/* Initialize connection tracking */
	INIT_LIST_HEAD(&tn->connections);
	spin_lock_init(&tn->conn_lock);
	atomic_set(&tn->conn_count, 0);

	/* Initialize statistics */
	atomic64_set(&tn->total_tx_bytes, 0);
	atomic64_set(&tn->total_rx_bytes, 0);
	atomic64_set(&tn->total_connections, 0);

	/* Register sysctl */
	ret = tquic_net_sysctl_register(net);
	if (ret)
		return ret;

#ifdef CONFIG_PROC_FS
	/* Initialize proc entries */
	ret = tquic_net_proc_init(net);
	if (ret)
		goto err_proc;
#endif

	pr_debug("TQUIC initialized for netns\n");
	return 0;

#ifdef CONFIG_PROC_FS
err_proc:
	tquic_net_sysctl_unregister(net);
	return ret;
#endif
}

/* Cleanup per-netns TQUIC data */
static void __net_exit tquic_net_exit(struct net *net)
{
	struct tquic_net *tn = tquic_pernet(net);

	/* TODO: Close all connections in this namespace */

#ifdef CONFIG_PROC_FS
	tquic_net_proc_exit(net);
#endif
	tquic_net_sysctl_unregister(net);

	/* Verify all connections are cleaned up */
	WARN_ON(atomic_read(&tn->conn_count) != 0);

	pr_debug("TQUIC exited for netns\n");
}

/* pernet_operations for TQUIC defaults */
static struct pernet_operations tquic_net_ops = {
	.init	= tquic_net_init,
	.exit	= tquic_net_exit,
	.id	= &tquic_net_id,
	.size	= sizeof(struct tquic_net),
};

/*
 * IPv4 Protocol Registration
 */
static int tquic_v4_protosw_init(void)
{
	int ret;

	ret = proto_register(&tquic_prot, 1);
	if (ret)
		return ret;

	/* Register TQUIC with socket layer */
	inet_register_protosw(&tquic_stream_protosw);
	inet_register_protosw(&tquic_dgram_protosw);

	pr_info("TQUIC IPv4 protosw registered\n");
	return 0;
}

static void tquic_v4_protosw_exit(void)
{
	inet_unregister_protosw(&tquic_dgram_protosw);
	inet_unregister_protosw(&tquic_stream_protosw);
	proto_unregister(&tquic_prot);
}

static int tquic_v4_add_protocol(void)
{
	if (inet_add_protocol(&tquic_protocol, IPPROTO_TQUIC) < 0) {
		pr_err("Failed to register TQUIC protocol handler\n");
		return -EAGAIN;
	}

	pr_info("TQUIC IPv4 protocol handler registered\n");
	return 0;
}

static void tquic_v4_del_protocol(void)
{
	inet_del_protocol(&tquic_protocol, IPPROTO_TQUIC);
}

/*
 * IPv6 Protocol Registration
 */
#if IS_ENABLED(CONFIG_IPV6)

static int tquic_v6_protosw_init(void)
{
	int ret;

	ret = proto_register(&tquicv6_prot, 1);
	if (ret)
		return ret;

	/* Register TQUICv6 with socket layer */
	inet6_register_protosw(&tquicv6_stream_protosw);
	inet6_register_protosw(&tquicv6_dgram_protosw);

	pr_info("TQUIC IPv6 protosw registered\n");
	return 0;
}

static void tquic_v6_protosw_exit(void)
{
	inet6_unregister_protosw(&tquicv6_dgram_protosw);
	inet6_unregister_protosw(&tquicv6_stream_protosw);
	proto_unregister(&tquicv6_prot);
}

static int tquic_v6_add_protocol(void)
{
	if (inet6_add_protocol(&tquicv6_protocol, IPPROTO_TQUIC) < 0) {
		pr_err("Failed to register TQUICv6 protocol handler\n");
		return -EAGAIN;
	}

	pr_info("TQUIC IPv6 protocol handler registered\n");
	return 0;
}

static void tquic_v6_del_protocol(void)
{
	inet6_del_protocol(&tquicv6_protocol, IPPROTO_TQUIC);
}

#else /* !CONFIG_IPV6 */

static inline int tquic_v6_protosw_init(void) { return 0; }
static inline void tquic_v6_protosw_exit(void) { }
static inline int tquic_v6_add_protocol(void) { return 0; }
static inline void tquic_v6_del_protocol(void) { }

#endif /* CONFIG_IPV6 */

/*
 * Module Init/Exit
 */
int __init tquic_proto_init(void)
{
	int ret;

	pr_info("TQUIC protocol handler initializing\n");

	/* Register pernet operations first */
	ret = register_pernet_subsys(&tquic_net_ops);
	if (ret)
		goto err_pernet;

	/* Register IPv4 protosw */
	ret = tquic_v4_protosw_init();
	if (ret)
		goto err_v4_protosw;

	/* Register IPv6 protosw */
	ret = tquic_v6_protosw_init();
	if (ret)
		goto err_v6_protosw;

	/* Register IPv4 protocol handler */
	ret = tquic_v4_add_protocol();
	if (ret)
		goto err_v4_protocol;

	/* Register IPv6 protocol handler */
	ret = tquic_v6_add_protocol();
	if (ret)
		goto err_v6_protocol;

	pr_info("TQUIC protocol handler initialized successfully\n");
	return 0;

err_v6_protocol:
	tquic_v4_del_protocol();
err_v4_protocol:
	tquic_v6_protosw_exit();
err_v6_protosw:
	tquic_v4_protosw_exit();
err_v4_protosw:
	unregister_pernet_subsys(&tquic_net_ops);
err_pernet:
	pr_err("TQUIC protocol handler initialization failed: %d\n", ret);
	return ret;
}

void __exit tquic_proto_exit(void)
{
	pr_info("TQUIC protocol handler exiting\n");

	/* Unregister protocol handlers */
	tquic_v6_del_protocol();
	tquic_v4_del_protocol();

	/* Unregister protosw */
	tquic_v6_protosw_exit();
	tquic_v4_protosw_exit();

	/* Unregister pernet operations */
	unregister_pernet_subsys(&tquic_net_ops);

	pr_info("TQUIC protocol handler exited\n");
}

/*
 * Accessor functions for per-netns sysctl values
 */
int tquic_net_get_enabled(struct net *net)
{
	return tquic_pernet(net)->enabled;
}
EXPORT_SYMBOL_GPL(tquic_net_get_enabled);

int tquic_net_get_bond_mode(struct net *net)
{
	return tquic_pernet(net)->bond_mode;
}
EXPORT_SYMBOL_GPL(tquic_net_get_bond_mode);

int tquic_net_get_max_paths(struct net *net)
{
	return tquic_pernet(net)->max_paths;
}
EXPORT_SYMBOL_GPL(tquic_net_get_max_paths);

int tquic_net_get_reorder_window(struct net *net)
{
	return tquic_pernet(net)->reorder_window;
}
EXPORT_SYMBOL_GPL(tquic_net_get_reorder_window);

int tquic_net_get_probe_interval(struct net *net)
{
	return tquic_pernet(net)->probe_interval;
}
EXPORT_SYMBOL_GPL(tquic_net_get_probe_interval);

int tquic_net_get_failover_timeout(struct net *net)
{
	return tquic_pernet(net)->failover_timeout;
}
EXPORT_SYMBOL_GPL(tquic_net_get_failover_timeout);

int tquic_net_get_idle_timeout(struct net *net)
{
	return tquic_pernet(net)->idle_timeout;
}
EXPORT_SYMBOL_GPL(tquic_net_get_idle_timeout);

int tquic_net_get_initial_rtt(struct net *net)
{
	return tquic_pernet(net)->initial_rtt;
}
EXPORT_SYMBOL_GPL(tquic_net_get_initial_rtt);

int tquic_net_get_initial_cwnd(struct net *net)
{
	return tquic_pernet(net)->initial_cwnd;
}
EXPORT_SYMBOL_GPL(tquic_net_get_initial_cwnd);

int tquic_net_get_debug_level(struct net *net)
{
	return tquic_pernet(net)->debug_level;
}
EXPORT_SYMBOL_GPL(tquic_net_get_debug_level);

void tquic_net_update_tx_stats(struct net *net, u64 bytes)
{
	atomic64_add(bytes, &tquic_pernet(net)->total_tx_bytes);
}
EXPORT_SYMBOL_GPL(tquic_net_update_tx_stats);

void tquic_net_update_rx_stats(struct net *net, u64 bytes)
{
	atomic64_add(bytes, &tquic_pernet(net)->total_rx_bytes);
}
EXPORT_SYMBOL_GPL(tquic_net_update_rx_stats);
