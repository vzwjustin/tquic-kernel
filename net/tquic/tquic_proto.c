// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Protocol Handler Registration
 *
 * Copyright (c) 2026 Linux Foundation
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
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
#include <linux/security.h>
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
#include <net/tquic_pmtud.h>

#include "protocol.h"
#include "tquic_mib.h"
#include "tquic_compat.h"
#include "tquic_debug.h"

/*
 * On < 5.9, sockptr_t doesn't exist in <net/tquic.h> (parsed before
 * tquic_compat.h).  Forward-declare with the polyfilled type here.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
int tquic_sock_setsockopt(struct socket *sock, int level, int optname,
			  sockptr_t optval, unsigned int optlen);
#endif

/* Network namespace identifier (exported for protocol.h inline accessor) */
unsigned int tquic_net_id __read_mostly;
EXPORT_SYMBOL_GPL(tquic_net_id);

/*
 * TQUIC memory management (cannot use TCP's unexported symbols)
 */
static struct percpu_counter tquic_sockets_allocated_counter;
static atomic_long_t tquic_memory_allocated;
static unsigned long tquic_memory_pressure;
static DEFINE_PER_CPU(int, tquic_memory_per_cpu_fw_alloc);

/* TQUIC sysctl memory limits (in pages) */
static TQUIC_SYSCTL_MEM_TYPE sysctl_tquic_mem[3] = {
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
			struct tquic_path *apath = READ_ONCE(conn->active_path);

			/* Deliver to connection's active path */
			tquic_udp_deliver_to_conn(conn, apath, skb);
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
			struct tquic_path *apath = READ_ONCE(conn->active_path);

			tquic_udp_deliver_to_conn(conn, apath, skb);
			return 0;
		}
	}

	tquic_dbg("received packet for unknown connection, len=%u\n",
		  skb->len);
	kfree_skb(skb);
	return 0;
}

/* IPv4 error handler */
static int tquic_v4_err(struct sk_buff *skb, u32 info)
{
	const struct iphdr *iph = ip_hdr(skb);

	tquic_dbg("received ICMP error, info=%u\n", info);

	/*
	 * Handle ICMP errors for TQUIC connections:
	 * - ICMP_DEST_UNREACH: Mark path as failed
	 * - ICMP_FRAG_NEEDED: Update path MTU
	 */
	switch (icmp_hdr(skb)->type) {
	case ICMP_DEST_UNREACH:
		if (icmp_hdr(skb)->code == ICMP_FRAG_NEEDED) {
			/* Path MTU discovery - ICMP Frag Needed */
			u32 icmp_mtu = ntohs(icmp_hdr(skb)->un.frag.mtu);
			u32 quic_mtu;
			struct tquic_connection *conn;
			struct tquic_cid dcid;
			struct tquic_path *apath;

			/*
			 * Validate ICMP-reported MTU:
			 * - Must be at least 68 bytes (IPv4 minimum)
			 * - Subtract IP+UDP overhead to get QUIC payload MTU
			 * - Clamp to QUIC minimum of 1200 bytes
			 *
			 * An attacker can forge ICMP messages with arbitrary
			 * MTU values, so we treat this as advisory only.
			 */
			if (icmp_mtu < 68) {
				tquic_dbg("PMTUD: ignoring bogus ICMP MTU=%u\n",
					  icmp_mtu);
				break;
			}

			if (icmp_mtu > TQUIC_IPV4_UDP_OVERHEAD)
				quic_mtu = icmp_mtu - TQUIC_IPV4_UDP_OVERHEAD;
			else
				quic_mtu = TQUIC_PMTUD_BASE_MTU;

			tquic_dbg("PMTUD: ICMP frag-needed MTU=%u (QUIC=%u) for %pI4\n",
				  icmp_mtu, quic_mtu, &iph->daddr);

			/*
			 * Try to find the connection and update its path MTU.
			 * The inner packet (after ICMP header) contains our
			 * original QUIC header from which we extract the DCID.
			 */
			/* Skip to inner IP + UDP payload for QUIC header */
			if (skb->len >= sizeof(struct iphdr) + 8 + 1) {
				const u8 *quic_hdr = (const u8 *)(iph + 1) + 8;

				if (!(quic_hdr[0] & 0x80)) {
					/* Short header - DCID at byte 1 */
					dcid.len = TQUIC_DEFAULT_CID_LEN;
					if (skb->len >= sizeof(struct iphdr) +
					    8 + 1 + dcid.len) {
						memcpy(dcid.id, quic_hdr + 1,
						       dcid.len);
						conn = tquic_conn_lookup_by_cid(
								&dcid);
						if (conn) {
							apath = READ_ONCE(conn->active_path);
							if (apath)
								tquic_pmtud_on_icmp_mtu_update(
									apath,
									quic_mtu);
						}
					}
				}
			}
		} else {
			/* Destination unreachable - path may have failed */
			tquic_dbg("path unreachable: %pI4\n", &iph->daddr);
		}
		break;

	case ICMP_TIME_EXCEEDED:
		tquic_dbg("TTL exceeded for %pI4\n", &iph->daddr);
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
			struct tquic_path *apath = READ_ONCE(conn->active_path);

			tquic_udp_deliver_to_conn(conn, apath, skb);
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
			struct tquic_path *apath = READ_ONCE(conn->active_path);

			tquic_udp_deliver_to_conn(conn, apath, skb);
			return 0;
		}
	}

	tquic_dbg("received v6 packet for unknown connection, len=%u\n",
		  skb->len);
	kfree_skb(skb);
	return 0;
}

/* IPv6 error handler */
static int tquic_v6_err(struct sk_buff *skb, struct inet6_skb_parm *opt,
			u8 type, u8 code, int offset, __be32 info)
{
	const struct ipv6hdr *ip6h = ipv6_hdr(skb);

	tquic_dbg("received ICMPv6 error, type=%u code=%u\n",
		  type, code);

	/*
	 * Handle ICMPv6 errors for TQUIC connections:
	 * - ICMPV6_DEST_UNREACH: Mark path as failed
	 * - ICMPV6_PKT_TOOBIG: Update path MTU
	 */
	switch (type) {
	case ICMPV6_DEST_UNREACH:
		tquic_dbg("path unreachable: %pI6c\n", &ip6h->daddr);
		break;

	case ICMPV6_PKT_TOOBIG: {
		/* Path MTU discovery for IPv6 */
		u32 icmp_mtu = ntohl(info);
		u32 quic_mtu;
		struct tquic_connection *conn;
		struct tquic_cid dcid;
		struct tquic_path *apath;

		/*
		 * Validate ICMP-reported MTU:
		 * - IPv6 minimum MTU is 1280 bytes
		 * - Subtract IPv6+UDP overhead to get QUIC payload MTU
		 * - Clamp to QUIC minimum of 1200 bytes
		 */
		if (icmp_mtu < 1280) {
			tquic_dbg("PMTUD v6: ignoring bogus MTU=%u\n",
				  icmp_mtu);
			break;
		}

		if (icmp_mtu > TQUIC_IPV6_UDP_OVERHEAD)
			quic_mtu = icmp_mtu - TQUIC_IPV6_UDP_OVERHEAD;
		else
			quic_mtu = TQUIC_PMTUD_BASE_MTU;

		tquic_dbg("PMTUD v6: pkt-too-big MTU=%u (QUIC=%u) for %pI6c\n",
			  icmp_mtu, quic_mtu, &ip6h->daddr);

		/*
		 * Try to find the connection and update its path MTU.
		 * The inner packet after ICMPv6 header contains our
		 * original IPv6+UDP+QUIC packet.
		 */
		if (skb->len >= sizeof(struct ipv6hdr) + 8 + 1) {
			const u8 *quic_hdr = (const u8 *)(ip6h + 1) + 8;

			if (!(quic_hdr[0] & 0x80)) {
				/* Short header - DCID at byte 1 */
				dcid.len = TQUIC_DEFAULT_CID_LEN;
				if (skb->len >= sizeof(struct ipv6hdr) +
				    8 + 1 + dcid.len) {
					memcpy(dcid.id, quic_hdr + 1,
					       dcid.len);
					conn = tquic_conn_lookup_by_cid(&dcid);
					if (conn) {
						apath = READ_ONCE(conn->active_path);
						if (apath)
							tquic_pmtud_on_icmp_mtu_update(
								apath,
								quic_mtu);
					}
				}
			}
		}
		break;
	}

	case ICMPV6_TIME_EXCEED:
		tquic_dbg("hop limit exceeded for %pI6c\n", &ip6h->daddr);
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
#if IS_ENABLED(CONFIG_IPV6)
static struct proto tquicv6_prot;
static const struct proto_ops tquic_inet6_ops;
#endif
static int tquic_create_socket(struct net *net, struct socket *sock,
			       int protocol, int kern)
{
	struct tquic_net *tn = tquic_pernet(net);
	struct proto *prot;
	const struct proto_ops *ops;
	struct sock *sk;
	int family;

	if (!tn->enabled)
		return -EPROTONOSUPPORT;

	/* Validate socket type */
	if (sock->type != SOCK_STREAM && sock->type != SOCK_DGRAM)
		return -ESOCKTNOSUPPORT;

	sock->state = SS_UNCONNECTED;

	/*
	 * Select the correct protocol struct and ops based on socket family.
	 * Using the wrong proto for IPv6 causes inet6_sk() to compute
	 * a bad offset, leading to a crash in __ipv6_sock_ac_close().
	 */
	family = sock->ops ? sock->ops->family : PF_INET;

#if IS_ENABLED(CONFIG_IPV6)
	if (family == PF_INET6) {
		prot = &tquicv6_prot;
		ops = &tquic_inet6_ops;
	} else
#endif
	{
		prot = &tquic_prot;
		ops = &tquic_inet_ops;
	}

	/* Invoke LSM security hooks -- required for SELinux, AppArmor, etc.
	 * Without this, TQUIC sockets bypass mandatory access controls.
	 */
	{
		int err = security_socket_create(family, sock->type, protocol, kern);
		if (err)
			return err;
	}

	/* Allocate sock structure */
	sk = sk_alloc(net, family, GFP_KERNEL, prot, kern);
	if (!sk)
		return -ENOBUFS;

	sock_init_data(sock, sk);
	sk->sk_protocol = protocol;
	sock->ops = ops;

	/* Additional TQUIC-specific socket initialization */
	atomic64_inc(&tn->total_connections);

	tquic_dbg("created socket, family=%d protocol=%d\n",
		  family, protocol);

	return 0;
}

/*
 * IPv4 Socket Operations
 */

/* Socket release helpers */
static int tquic_inet_release(struct socket *sock)
{
	if (!sock->sk)
		return 0;

	return inet_release(sock);
}

#if IS_ENABLED(CONFIG_IPV6)
static int tquic_inet6_release(struct socket *sock)
{
	if (!sock->sk)
		return 0;

	return inet6_release(sock);
}
#endif

/* Compat wrapper for proto_ops.setsockopt on kernels < 5.9 (no sockptr_t) */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
static int tquic_sock_setsockopt_compat(struct socket *sock, int level,
					int optname, char __user *optval,
					unsigned int optlen)
{
	return tquic_sock_setsockopt(sock, level, optname,
				     USER_SOCKPTR(optval), optlen);
}
#endif

/* IPv4 proto_ops */
static const struct proto_ops tquic_inet_ops = {
	.family		= PF_INET,
	.owner		= THIS_MODULE,
	.release	= tquic_inet_release,
	.bind		= tquic_sock_bind,
	.connect	= tquic_connect_socket,
	.socketpair	= sock_no_socketpair,
	.accept		= tquic_accept_socket,
	.getname	= tquic_sock_getname,
	.poll		= tquic_poll_socket,
	.ioctl		= tquic_sock_ioctl,
	.listen		= tquic_sock_listen,
	.shutdown	= tquic_sock_shutdown,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
	.setsockopt	= tquic_sock_setsockopt,
#else
	.setsockopt	= tquic_sock_setsockopt_compat,
#endif
	.getsockopt	= tquic_sock_getsockopt,
	.sendmsg	= tquic_sendmsg_socket,
	.recvmsg	= tquic_recvmsg_socket,
	.mmap		= sock_no_mmap,
	.splice_read	= tquic_splice_read_socket,
};

/*
 * QUIC uses UDP encapsulation, so we don't participate in the inet
 * hash tables.  Provide simple no-op stubs for .hash / .unhash.
 */
static TQUIC_PROTO_HASH_RET tquic_proto_hash(struct sock *sk)
{
	TQUIC_PROTO_HASH_RETURN;
}

static void tquic_proto_unhash(struct sock *sk)
{
}

/* Compat wrapper for proto.recvmsg on kernels < 5.19 (6-arg signature) */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 19, 0)
TQUIC_DEFINE_RECVMSG_WRAPPER(tquic_recvmsg_compat, tquic_recvmsg)
#endif

/* TQUIC protocol definition for IPv4 */
static struct proto tquic_prot = {
	.name		= "TQUIC",
	.owner		= THIS_MODULE,
	.obj_size	= sizeof(struct tquic_sock),
	.init		= tquic_init_sock,
	.destroy	= tquic_destroy_sock,
	.close		= tquic_close,
	.connect	= tquic_connect,
	.sendmsg	= tquic_sendmsg,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 19, 0)
	.recvmsg	= tquic_recvmsg,
#else
	.recvmsg	= tquic_recvmsg_compat,
#endif
	.hash		= tquic_proto_hash,
	.unhash		= tquic_proto_unhash,
	.get_port	= inet_csk_get_port,
	.sockets_allocated = &tquic_sockets_allocated_counter,
	.memory_allocated = &tquic_memory_allocated,
	.memory_pressure = &tquic_memory_pressure,
	TQUIC_PROTO_PER_CPU_FW_ALLOC(&tquic_memory_per_cpu_fw_alloc)
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
	.flags		= INET_PROTOSW_ICSK,
};

/* inet_protosw for TQUIC over IPv4 - SOCK_DGRAM (for connectionless mode) */
static struct inet_protosw tquic_dgram_protosw = {
	.type		= SOCK_DGRAM,
	.protocol	= IPPROTO_TQUIC,
	.prot		= &tquic_prot,
	.ops		= &tquic_inet_ops,
	.flags		= 0,
};

/*
 * IPv6 Socket Operations
 */
#if IS_ENABLED(CONFIG_IPV6)

/* IPv6 proto_ops */
static const struct proto_ops tquic_inet6_ops = {
	.family		= PF_INET6,
	.owner		= THIS_MODULE,
	.release	= tquic_inet6_release,
	.bind		= tquic_sock_bind,
	.connect	= tquic_connect_socket,
	.socketpair	= sock_no_socketpair,
	.accept		= tquic_accept_socket,
	.getname	= tquic_sock_getname,
	.poll		= tquic_poll_socket,
	.ioctl		= tquic_sock_ioctl,
	.listen		= tquic_sock_listen,
	.shutdown	= tquic_sock_shutdown,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
	.setsockopt	= tquic_sock_setsockopt,
#else
	.setsockopt	= tquic_sock_setsockopt_compat,
#endif
	.getsockopt	= tquic_sock_getsockopt,
	.sendmsg	= tquic_sendmsg_socket,
	.recvmsg	= tquic_recvmsg_socket,
	.mmap		= sock_no_mmap,
	.splice_read	= tquic_splice_read_socket,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= inet6_compat_ioctl,
#endif
};

/* TQUIC protocol definition for IPv6 */
static struct proto tquicv6_prot = {
	.name		= "TQUICv6",
	.owner		= THIS_MODULE,
	.obj_size	= sizeof(struct tquic6_sock),
	TQUIC_PROTO_IPV6_PINFO_OFFSET(struct tquic6_sock, inet6)
	.init		= tquic_init_sock,
	.destroy	= tquic_destroy_sock,
	.close		= tquic_close,
	.connect	= tquic_connect,
	.sendmsg	= tquic_sendmsg,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 19, 0)
	.recvmsg	= tquic_recvmsg,
#else
	.recvmsg	= tquic_recvmsg_compat,
#endif
	.hash		= tquic_proto_hash,
	.unhash		= tquic_proto_unhash,
	.get_port	= inet_csk_get_port,
	.sockets_allocated = &tquic_sockets_allocated_counter,
	.memory_allocated = &tquic_memory_allocated,
	.memory_pressure = &tquic_memory_pressure,
	TQUIC_PROTO_PER_CPU_FW_ALLOC(&tquic_memory_per_cpu_fw_alloc)
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
	.flags		= INET_PROTOSW_ICSK,
};

/* inet6_protosw for TQUIC over IPv6 - SOCK_DGRAM */
static struct inet_protosw tquicv6_dgram_protosw = {
	.type		= SOCK_DGRAM,
	.protocol	= IPPROTO_TQUIC,
	.prot		= &tquicv6_prot,
	.ops		= &tquic_inet6_ops,
	.flags		= 0,
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

/* Number of valid entries (exclude the null terminator). */
#define TQUIC_SYSCTL_TABLE_SIZE (ARRAY_SIZE(tquic_net_sysctl_table) - 1)

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
	TQUIC_CTL_TABLE *table;

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

	tquic_dbg("initialized for netns\n");
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
	spin_lock_bh(&conn->lock);
	if (conn->state == TQUIC_CONN_CONNECTED ||
	    conn->state == TQUIC_CONN_CONNECTING) {
		/*
		 * Attempt to send CONNECTION_CLOSE without waiting.
		 * tquic_send_connection_close handles state validation
		 * internally.  Drop the lock while sending since it may
		 * sleep or acquire other locks.
		 * Errors are ignored - we're shutting down regardless.
		 */
		spin_unlock_bh(&conn->lock);
		tquic_send_connection_close(conn, 0x00,
					    "namespace shutdown");
		spin_lock_bh(&conn->lock);
	}

	/*
	 * Mark connection as closed immediately to prevent any further
	 * packet processing or state machine activity.
	 */
	WRITE_ONCE(conn->state, TQUIC_CONN_CLOSED);
	spin_unlock_bh(&conn->lock);

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
			WRITE_ONCE(tsk->conn, NULL);
		conn->sk = NULL;
	}

	/* Decrement namespace connection count before freeing */
	atomic_dec(&tn->conn_count);

	/*
	 * Do NOT call tquic_conn_destroy() here.  The caller holds a
	 * reference taken during collection and will drop it via
	 * tquic_conn_put().  When the refcount reaches zero,
	 * tquic_conn_put() triggers tquic_conn_destroy() which handles:
	 * - State machine cleanup (cancels work items, frees CID entries)
	 * - Global hash table removal
	 * - Timer state freeing (cancels all timers)
	 * - Path cleanup (timers, response queues, CC state)
	 * - Stream cleanup (buffers)
	 * - Crypto/scheduler/other state freeing
	 * - kmem_cache_free for the connection
	 */
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

		tquic_dbg("closing connection %p during netns exit\n", conn);

		/*
		 * Close the connection. This sends CONNECTION_CLOSE (best
		 * effort), decrements conn_count, and marks the connection
		 * as CLOSED.  It does NOT call tquic_conn_destroy directly
		 * any more -- destruction is handled by tquic_conn_put()
		 * when the refcount reaches zero.
		 */
		tquic_net_close_connection(conn, tn);

		/*
		 * Drop the reference we took during collection.
		 * tquic_conn_put() will call tquic_conn_destroy() if
		 * this is the last reference, avoiding the previous
		 * use-after-free on the refcount.
		 */
		tquic_conn_put(conn);
	}

	/*
	 * If there are still connections in the namespace (conn_count > 0),
	 * they must be held by something else (unlikely during netns exit).
	 * Log a warning - the WARN_ON in tquic_net_exit will catch this.
	 */
	if (atomic_read(&tn->conn_count) > 0) {
		tquic_warn("%d connections still active after netns cleanup\n",
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

	tquic_dbg("exited for netns\n");
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

	tquic_info("IPv4 protosw registered\n");
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
	/*
	 * TQUIC uses UDP encapsulation (like standard QUIC per RFC 9000).
	 * Raw IP protocol handlers are only for protocols < 256.
	 * IPPROTO_TQUIC (263) is used for socket creation identification
	 * but packets are received via UDP, not raw IP.
	 *
	 * Skip raw protocol registration - UDP encap is handled in tquic_udp.c
	 */
	tquic_info("uses UDP encapsulation, no raw IP protocol handler needed\n");
	return 0;
}

static void tquic_v4_del_protocol(void)
{
	/* Nothing to unregister - UDP encapsulation doesn't use inet_add_protocol */
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

	tquic_info("IPv6 protosw registered\n");
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
	/*
	 * TQUIC uses UDP encapsulation (like standard QUIC per RFC 9000).
	 * Skip raw protocol registration - UDP encap is handled in tquic_udp.c
	 */
	tquic_info("v6 uses UDP encapsulation, no raw IP protocol handler needed\n");
	return 0;
}

static void tquic_v6_del_protocol(void)
{
	/* Nothing to unregister - UDP encapsulation doesn't use inet6_add_protocol */
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

	tquic_info("protocol handler initializing\n");

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

	tquic_info("protocol handler initialized successfully\n");
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
	tquic_err("protocol handler initialization failed: %d\n", ret);
	return ret;
}

void __exit tquic_proto_exit(void)
{
	tquic_info("protocol handler exiting\n");

	/* Unregister protocol handlers */
	tquic_v6_del_protocol();
	tquic_v4_del_protocol();

	/* Unregister protosw */
	tquic_v6_protosw_exit();
	tquic_v4_protosw_exit();

	/* Unregister pernet operations */
	unregister_pernet_subsys(&tquic_net_ops);

	tquic_info("protocol handler exited\n");
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
