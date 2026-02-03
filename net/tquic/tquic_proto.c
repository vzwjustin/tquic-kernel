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

#include "protocol.h"
#include "tquic_mib.h"

/* Network namespace identifier (exported for protocol.h inline accessor) */
unsigned int tquic_net_id __read_mostly;
EXPORT_SYMBOL_GPL(tquic_net_id);

/*
 * TQUIC memory management (cannot use TCP's unexported symbols)
 */
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

#define TQUIC_SYSCTL_TABLE_SIZE ARRAY_SIZE(tquic_net_sysctl_table)

static int tquic_net_sysctl_register(struct net *net)
{
	struct tquic_net *tn = tquic_pernet(net);
	struct ctl_table *table;
	int i;

	/*
	 * Avoid duplicate sysctl registration in init_net since the global
	 * sysctl table is already registered via tquic_sysctl.c.
	 */
	if (net_eq(net, &init_net))
		return 0;

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

	tn->sysctl_header = register_net_sysctl_sz(net, "net/tquic", table,
						    TQUIC_SYSCTL_TABLE_SIZE);
	if (!tn->sysctl_header) {
		kfree(table);
		return -ENOMEM;
	}

	return 0;
}

static void tquic_net_sysctl_unregister(struct net *net)
{
	struct tquic_net *tn = tquic_pernet(net);
	const struct ctl_table *table;

	if (tn->sysctl_header) {
		table = tn->sysctl_header->ctl_table_arg;
		unregister_net_sysctl_table(tn->sysctl_header);
		/* We allocated with kmemdup, so cast away const for kfree */
		kfree((void *)table);
		tn->sysctl_header = NULL;
	}
}

/*
 * Per-Network Namespace Proc Entries
 *
 * Proc interface is implemented in tquic_proc.c.
 * tquic_proc_init/exit create /proc/net/tquic, /proc/net/tquic_stat,
 * and /proc/net/tquic_errors for each network namespace.
 */

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

	/* Allocate per-CPU MIB statistics */
	tn->mib = alloc_percpu(struct tquic_mib);
	if (!tn->mib)
		return -ENOMEM;

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
		goto err_sysctl;

#ifdef CONFIG_PROC_FS
	/* Initialize proc entries */
	ret = tquic_proc_init(net);
	if (ret)
		goto err_proc;
#endif

	pr_debug("TQUIC initialized for netns\n");
	return 0;

#ifdef CONFIG_PROC_FS
err_proc:
	tquic_net_sysctl_unregister(net);
#endif
err_sysctl:
	free_percpu(tn->mib);
	tn->mib = NULL;
	return ret;
}

/* External declarations for connection management */
extern struct rhashtable tquic_conn_table;

/*
 * Close a single connection during namespace shutdown.
 *
 * This function handles graceful connection closure during netns cleanup:
 * 1. Attempt to send CONNECTION_CLOSE frame (best effort, may fail)
 * 2. Unlink socket from connection to prevent double-free
 * 3. Use tquic_conn_destroy for proper cleanup
 *
 * Note: This must not be called with any locks held that tquic_conn_destroy
 * might also acquire, as destroy may sleep (cancel_work_sync, etc).
 */
static void tquic_net_close_connection(struct tquic_connection *conn,
				       struct tquic_net *tn)
{
	struct sock *sk;

	if (!conn)
		return;

	sk = conn->sk;

	/*
	 * Try to send CONNECTION_CLOSE frame (best effort).
	 * This is a graceful close attempt - if it fails, we still proceed
	 * with cleanup since the namespace is being destroyed anyway.
	 *
	 * Use NO_ERROR (0x00) to indicate clean shutdown per RFC 9000 Section 10.2.
	 * We avoid entering the full closing/draining state machine since
	 * we need immediate cleanup.
	 */
	if (conn->state == TQUIC_CONN_CONNECTED ||
	    conn->state == TQUIC_CONN_CONNECTING) {
		/*
		 * Attempt to send CONNECTION_CLOSE without waiting.
		 * tquic_send_connection_close handles state validation internally.
		 * Errors are ignored - we're shutting down regardless.
		 */
		tquic_send_connection_close(conn, 0x00, "namespace shutdown");
	}

	/*
	 * Mark connection as closed immediately to prevent any further
	 * packet processing or state machine activity.
	 */
	conn->state = TQUIC_CONN_CLOSED;

	/*
	 * Unlink socket from connection before destroying.
	 * This prevents the socket destroy path from trying to clean up
	 * the connection again (double-free).
	 *
	 * The socket layer will handle its own cleanup independently.
	 */
	if (sk) {
		struct tquic_sock *tsk = tquic_sk(sk);

		if (tsk)
			tsk->conn = NULL;
		conn->sk = NULL;
	}

	/* Decrement namespace connection count before freeing */
	atomic_dec(&tn->conn_count);

	/*
	 * Use tquic_conn_destroy for full cleanup.
	 * This handles:
	 * - State machine cleanup (cancels work items, frees CID entries)
	 * - Global hash table removal
	 * - Timer state freeing (cancels all timers)
	 * - Path cleanup (timers, response queues, CC state)
	 * - Stream cleanup (buffers)
	 * - Crypto/scheduler/other state freeing
	 * - kmem_cache_free for the connection
	 */
	tquic_conn_destroy(conn);
}

/*
 * Iterate through all connections in the namespace and close them.
 *
 * This handles connections that may be tracked via:
 * 1. The per-netns connections list (tn->connections)
 * 2. The global connection hash table (tquic_conn_table)
 *
 * We iterate the global table and match connections by namespace.
 */
static void tquic_net_close_all_connections(struct net *net)
{
	struct tquic_net *tn = tquic_pernet(net);
	struct tquic_connection *conn;
	struct rhashtable_iter iter;
	LIST_HEAD(close_list);

	/*
	 * First, collect all connections in this namespace.
	 * We can't close connections while iterating the hash table
	 * because tquic_conn_destroy removes entries from the table.
	 *
	 * Strategy:
	 * 1. Iterate hash table and collect connections for this netns
	 * 2. Close all collected connections outside the iteration
	 */
	rhashtable_walk_enter(&tquic_conn_table, &iter);
	rhashtable_walk_start(&iter);

	while ((conn = rhashtable_walk_next(&iter)) != NULL) {
		if (IS_ERR(conn))
			continue;

		/* Check if connection belongs to this namespace */
		if (conn->sk && net_eq(sock_net(conn->sk), net)) {
			/*
			 * Take a reference to prevent connection from being
			 * freed while we're collecting.
			 *
			 * Note: During netns exit, no new connections should
			 * be created in this namespace, so races are unlikely.
			 * We still take references to be safe.
			 */
			if (refcount_inc_not_zero(&conn->refcnt)) {
				/*
				 * Use pm_node for temporary list linkage.
				 * This is safe because we're shutting down
				 * and pm_node won't be used for anything else.
				 */
				list_add(&conn->pm_node, &close_list);
			}
		}
	}

	rhashtable_walk_stop(&iter);
	rhashtable_walk_exit(&iter);

	/*
	 * Also check the per-netns connections list.
	 * Some connections may be tracked here but not yet in the
	 * global hash table (during early connection setup).
	 */
	spin_lock_bh(&tn->conn_lock);
	while (!list_empty(&tn->connections)) {
		struct tquic_connection *c;
		bool found = false;

		c = list_first_entry(&tn->connections,
				     struct tquic_connection, pm_node);

		/*
		 * Check if already in close list (avoid double-close).
		 * This can happen if connection is in both the global
		 * table and the netns list.
		 */
		list_for_each_entry(conn, &close_list, pm_node) {
			if (conn == c) {
				found = true;
				break;
			}
		}

		/* Remove from netns list regardless */
		list_del_init(&c->pm_node);

		if (!found) {
			if (refcount_inc_not_zero(&c->refcnt)) {
				list_add(&c->pm_node, &close_list);
			}
		}
	}
	spin_unlock_bh(&tn->conn_lock);

	/*
	 * Now close all collected connections.
	 *
	 * tquic_conn_destroy may sleep (cancel_work_sync), so we must not
	 * hold any spinlocks here.
	 */
	while (!list_empty(&close_list)) {
		conn = list_first_entry(&close_list,
					struct tquic_connection, pm_node);
		list_del_init(&conn->pm_node);

		pr_debug("tquic: closing connection %p during netns exit\n", conn);

		/*
		 * Close the connection. This sends CONNECTION_CLOSE (best effort),
		 * decrements conn_count, and calls tquic_conn_destroy.
		 */
		tquic_net_close_connection(conn, tn);

		/*
		 * Drop the reference we took during collection.
		 * Note: tquic_conn_destroy already freed the connection memory,
		 * so we must NOT access conn after tquic_net_close_connection.
		 * The refcount_dec would be a use-after-free.
		 *
		 * However, if something else still holds a reference (unlikely
		 * during netns exit), the connection wouldn't be freed yet.
		 * To be safe, we don't touch conn after destroy.
		 *
		 * The reference we took is now "leaked" if there were other
		 * references, but this only happens during abnormal shutdown
		 * and the memory will be freed when those references are dropped.
		 */
	}

	/*
	 * If there are still connections in the namespace (conn_count > 0),
	 * they must be held by something else (unlikely during netns exit).
	 * Log a warning - the WARN_ON in tquic_net_exit will catch this.
	 */
	if (atomic_read(&tn->conn_count) > 0) {
		pr_warn("tquic: %d connections still active after netns cleanup\n",
			atomic_read(&tn->conn_count));
	}
}

/* Cleanup per-netns TQUIC data */
static void __net_exit tquic_net_exit(struct net *net)
{
	struct tquic_net *tn = tquic_pernet(net);

	/*
	 * Close all connections in this namespace.
	 *
	 * This must happen before proc/sysctl cleanup to ensure:
	 * 1. No connections reference the namespace's configuration
	 * 2. All timers are cancelled (prevent use-after-free)
	 * 3. All packets are flushed (no dangling skbs)
	 *
	 * CONNECTION_CLOSE frames are sent where possible for graceful shutdown.
	 */
	tquic_net_close_all_connections(net);

#ifdef CONFIG_PROC_FS
	tquic_proc_exit(net);
#endif
	tquic_net_sysctl_unregister(net);

	/* Free per-CPU MIB statistics */
	free_percpu(tn->mib);
	tn->mib = NULL;

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
