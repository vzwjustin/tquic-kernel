// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Netfilter Integration for Stateful Firewall Support
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * This module provides Netfilter/conntrack integration for TQUIC connections,
 * enabling stateful firewall support, NAT traversal, and connection tracking
 * for multi-path WAN bonding scenarios.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/hashtable.h>
#include <linux/jhash.h>
#include <linux/rculist.h>
#include <linux/timer.h>
#include <net/net_namespace.h>

#if IS_ENABLED(CONFIG_IPV6)
#include <linux/ipv6.h>
#include <linux/netfilter_ipv6.h>
#endif

#if IS_ENABLED(CONFIG_NF_CONNTRACK)
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_core.h>
#include <net/netfilter/nf_conntrack_helper.h>
#include <net/netfilter/nf_conntrack_zones.h>
#include <net/netfilter/nf_nat.h>
#endif

#include <net/tquic.h>

#include "tquic_compat.h"
#include "tquic_debug.h"

/* QUIC packet header constants */
#define QUIC_FORM_BIT			0x80	/* Long vs Short header */
#define QUIC_FIXED_BIT			0x40	/* Must be 1 */
#define QUIC_LONG_HEADER_TYPE_MASK	0x30
#define QUIC_LONG_HEADER_TYPE_SHIFT	4

/* QUIC long header types */
#define QUIC_LH_TYPE_INITIAL		0x00
#define QUIC_LH_TYPE_0RTT		0x01
#define QUIC_LH_TYPE_HANDSHAKE		0x02
#define QUIC_LH_TYPE_RETRY		0x03

/* QUIC short header spin bit */
#define QUIC_SH_SPIN_BIT		0x20

/* Connection tracking hash table */
#define TQUIC_NF_HASH_BITS		12
#define TQUIC_NF_HASH_SIZE		(1 << TQUIC_NF_HASH_BITS)

/* Connection timeout (seconds) */
#define TQUIC_NF_TIMEOUT_ESTABLISHED	300
#define TQUIC_NF_TIMEOUT_HANDSHAKE	30
#define TQUIC_NF_TIMEOUT_IDLE		60

/* Maximum tracked connections to prevent memory exhaustion from spoofed IPs */
#define TQUIC_NF_MAX_CONNECTIONS	65536

/* Maximum connection ID length */
#define QUIC_MAX_CID_LEN		20

/**
 * struct tquic_nf_cid - QUIC Connection ID
 * @id: Connection ID bytes
 * @len: Length of connection ID
 */
struct tquic_nf_cid {
	u8 id[QUIC_MAX_CID_LEN];
	u8 len;
};

/**
 * struct tquic_nf_conn - Netfilter QUIC connection tracking entry
 * @hash_node: Hash table linkage by CID
 * @addr_node: Hash table linkage by address
 * @rcu: RCU head for safe deletion
 * @scid: Source connection ID
 * @dcid: Destination connection ID
 * @local_addr: Local address/port
 * @remote_addr: Remote address/port
 * @state: Connection state
 * @is_server: Server or client connection
 * @timeout: Expiration time
 * @packets: Packet count
 * @bytes: Byte count
 * @last_seen: Last packet timestamp
 * @refcnt: Reference count
 */
struct tquic_nf_conn {
	struct hlist_node hash_node;
	struct hlist_node addr_node;
	struct rcu_head rcu;

	struct tquic_nf_cid scid;
	struct tquic_nf_cid dcid;

	struct sockaddr_storage local_addr;
	struct sockaddr_storage remote_addr;

	u8 state;
#define TQUIC_NF_STATE_NEW		0
#define TQUIC_NF_STATE_HANDSHAKE	1
#define TQUIC_NF_STATE_ESTABLISHED	2
#define TQUIC_NF_STATE_CLOSING		3

	bool is_server;
	unsigned long timeout;

	atomic64_t packets;
	atomic64_t bytes;
	ktime_t last_seen;

	refcount_t refcnt;
};

/* Hash tables for connection tracking */
static DEFINE_HASHTABLE(tquic_nf_cid_hash, TQUIC_NF_HASH_BITS);
static DEFINE_HASHTABLE(tquic_nf_addr_hash, TQUIC_NF_HASH_BITS);
static DEFINE_SPINLOCK(tquic_nf_lock);

/* Garbage collection timer */
static struct timer_list tquic_nf_gc_timer;
static struct work_struct tquic_nf_gc_work;

/* Statistics */
static atomic64_t tquic_nf_conn_count = ATOMIC64_INIT(0);
static atomic64_t tquic_nf_packets_seen = ATOMIC64_INIT(0);

/*
 * Hash functions
 */

static u32 tquic_nf_hash_secret __read_mostly;

static u32 tquic_nf_cid_hash_fn(const struct tquic_nf_cid *cid)
{
	net_get_random_once(&tquic_nf_hash_secret,
			    sizeof(tquic_nf_hash_secret));
	return jhash(cid->id, cid->len, tquic_nf_hash_secret);
}

static u32 tquic_nf_addr_hash_fn(const struct sockaddr_storage *addr)
{
	net_get_random_once(&tquic_nf_hash_secret,
			    sizeof(tquic_nf_hash_secret));
	if (addr->ss_family == AF_INET) {
		const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
		return jhash_2words(sin->sin_addr.s_addr,
				    (__force u32)sin->sin_port,
				    tquic_nf_hash_secret);
	}
#if IS_ENABLED(CONFIG_IPV6)
	else if (addr->ss_family == AF_INET6) {
		const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;
		return jhash(&sin6->sin6_addr, sizeof(sin6->sin6_addr),
			     (__force u32)sin6->sin6_port);
	}
#endif
	return 0;
}

/*
 * Connection tracking operations
 */

static struct tquic_nf_conn *tquic_nf_conn_alloc(void)
{
	struct tquic_nf_conn *conn;

	conn = kzalloc(sizeof(*conn), GFP_ATOMIC);
	if (!conn)
		return NULL;

	refcount_set(&conn->refcnt, 1);
	INIT_HLIST_NODE(&conn->hash_node);
	INIT_HLIST_NODE(&conn->addr_node);
	conn->state = TQUIC_NF_STATE_NEW;
	conn->last_seen = ktime_get();
	conn->timeout = jiffies + TQUIC_NF_TIMEOUT_HANDSHAKE * HZ;

	atomic64_inc(&tquic_nf_conn_count);

	return conn;
}

static void tquic_nf_conn_free_rcu(struct rcu_head *head)
{
	struct tquic_nf_conn *conn = container_of(head, struct tquic_nf_conn, rcu);
	kfree(conn);
}

static void tquic_nf_conn_put(struct tquic_nf_conn *conn)
{
	if (refcount_dec_and_test(&conn->refcnt)) {
		atomic64_dec(&tquic_nf_conn_count);
		call_rcu(&conn->rcu, tquic_nf_conn_free_rcu);
	}
}

static void tquic_nf_conn_get(struct tquic_nf_conn *conn)
{
	refcount_inc(&conn->refcnt);
}

/**
 * tquic_nf_conn_find_by_cid - Find connection by connection ID
 * @cid: Connection ID to search for
 *
 * Returns: Connection if found (with reference), NULL otherwise
 */
static struct tquic_nf_conn *tquic_nf_conn_find_by_cid(const struct tquic_nf_cid *cid)
{
	struct tquic_nf_conn *conn;
	u32 hash = tquic_nf_cid_hash_fn(cid);

	rcu_read_lock();
	hash_for_each_possible_rcu(tquic_nf_cid_hash, conn, hash_node, hash) {
		if (conn->scid.len == cid->len &&
		    memcmp(conn->scid.id, cid->id, cid->len) == 0) {
			/*
			 * CF-494: Use refcount_inc_not_zero under RCU to
			 * handle the case where the connection's refcount
			 * has already hit zero but the RCU callback has
			 * not yet freed it.
			 */
			if (!refcount_inc_not_zero(&conn->refcnt))
				continue;
			rcu_read_unlock();
			return conn;
		}
		if (conn->dcid.len == cid->len &&
		    memcmp(conn->dcid.id, cid->id, cid->len) == 0) {
			if (!refcount_inc_not_zero(&conn->refcnt))
				continue;
			rcu_read_unlock();
			return conn;
		}
	}
	rcu_read_unlock();

	return NULL;
}

/**
 * tquic_nf_conn_insert - Insert connection into tracking tables
 * @conn: Connection to insert
 */
static void tquic_nf_conn_insert(struct tquic_nf_conn *conn)
{
	u32 cid_hash, addr_hash;

	cid_hash = tquic_nf_cid_hash_fn(&conn->scid);
	addr_hash = tquic_nf_addr_hash_fn(&conn->local_addr);

	spin_lock_bh(&tquic_nf_lock);
	hash_add_rcu(tquic_nf_cid_hash, &conn->hash_node, cid_hash);
	hash_add_rcu(tquic_nf_addr_hash, &conn->addr_node, addr_hash);
	spin_unlock_bh(&tquic_nf_lock);
}

/**
 * tquic_nf_conn_remove - Remove connection from tracking tables
 * @conn: Connection to remove
 */
static void tquic_nf_conn_remove(struct tquic_nf_conn *conn)
{
	spin_lock_bh(&tquic_nf_lock);
	hash_del_rcu(&conn->hash_node);
	hash_del_rcu(&conn->addr_node);
	spin_unlock_bh(&tquic_nf_lock);

	tquic_nf_conn_put(conn);
}

/*
 * QUIC packet parsing
 */

/**
 * struct tquic_nf_pkt_info - Parsed QUIC packet information
 * @is_long_header: True if long header format
 * @pkt_type: Packet type (for long headers)
 * @version: QUIC version (for long headers)
 * @dcid: Destination connection ID
 * @scid: Source connection ID (for long headers)
 * @spin_bit: Spin bit value (for short headers)
 * @payload_off: Offset to payload
 */
struct tquic_nf_pkt_info {
	bool is_long_header;
	u8 pkt_type;
	u32 version;
	struct tquic_nf_cid dcid;
	struct tquic_nf_cid scid;
	bool spin_bit;
	int payload_off;
};

/**
 * tquic_nf_parse_packet - Parse QUIC packet header
 * @data: Packet data
 * @len: Data length
 * @info: Output packet info structure
 *
 * Returns: 0 on success, negative error on failure
 */
static int tquic_nf_parse_packet(const u8 *data, size_t len,
				 struct tquic_nf_pkt_info *info)
{
	const u8 *p = data;
	u8 first_byte;

	if (len < 1)
		return -EINVAL;

	memset(info, 0, sizeof(*info));
	first_byte = *p++;
	len--;

	/* Check fixed bit (QUIC invariant) */
	if (!(first_byte & QUIC_FIXED_BIT))
		return -EINVAL;

	info->is_long_header = !!(first_byte & QUIC_FORM_BIT);

	if (info->is_long_header) {
		/* Long header format */
		if (len < 6)	/* Version(4) + DCID len(1) + SCID len(1) */
			return -EINVAL;

		info->pkt_type = (first_byte & QUIC_LONG_HEADER_TYPE_MASK)
				 >> QUIC_LONG_HEADER_TYPE_SHIFT;

		/* Version */
		info->version = get_unaligned_be32(p);
		p += 4;
		len -= 4;

		/* DCID length and value */
		info->dcid.len = *p++;
		len--;
		if (info->dcid.len > QUIC_MAX_CID_LEN || len < info->dcid.len)
			return -EINVAL;
		memcpy(info->dcid.id, p, info->dcid.len);
		p += info->dcid.len;
		len -= info->dcid.len;

		/* SCID length and value */
		if (len < 1)
			return -EINVAL;
		info->scid.len = *p++;
		len--;
		if (info->scid.len > QUIC_MAX_CID_LEN || len < info->scid.len)
			return -EINVAL;
		memcpy(info->scid.id, p, info->scid.len);
		p += info->scid.len;
		len -= info->scid.len;

		info->payload_off = p - data;
	} else {
		/* Short header format */
		info->spin_bit = !!(first_byte & QUIC_SH_SPIN_BIT);

		/* For short headers, we need to know the expected DCID length.
		 * Use a default of 8 bytes for stateless parsing but
		 * require at least that many bytes to avoid truncated CIDs.
		 */
		info->dcid.len = 8;
		if (len < info->dcid.len)
			return -EINVAL;
		memcpy(info->dcid.id, p, info->dcid.len);
		p += info->dcid.len;

		info->payload_off = p - data;
	}

	return 0;
}

/*
 * Netfilter hooks
 */

/**
 * tquic_nf_hook_in - Input hook for QUIC packets
 * @priv: Hook private data
 * @skb: Packet buffer
 * @state: Hook state
 *
 * Returns: NF_ACCEPT to allow, NF_DROP to drop
 */
static unsigned int tquic_nf_hook_in(void *priv, struct sk_buff *skb,
				     const struct nf_hook_state *state)
{
	struct iphdr *iph;
	struct udphdr *uh;
	struct tquic_nf_pkt_info pkt_info;
	struct tquic_nf_conn *conn;
	const u8 *quic_data;
	unsigned int udp_len_host;
	size_t quic_len;
	int udp_offset;
	int total_pull;
	__be16 dport;

	if (!skb)
		return NF_ACCEPT;

	/* Only process UDP packets */
	iph = ip_hdr(skb);
	if (iph->protocol != IPPROTO_UDP)
		return NF_ACCEPT;

	/* Get UDP header */
	udp_offset = iph->ihl * 4;
	if (!pskb_may_pull(skb, udp_offset + sizeof(struct udphdr)))
		return NF_ACCEPT;

	/* Re-fetch iph after pskb_may_pull may have reallocated */
	iph = ip_hdr(skb);
	uh = (struct udphdr *)(skb->data + udp_offset);
	dport = uh->dest;

	/* Quick check for common QUIC ports */
	if (dport != htons(443) && dport != htons(8443) && dport != htons(4433))
		return NF_ACCEPT;

	/*
	 * Validate UDP length to prevent integer underflow.
	 * uh->len includes the UDP header itself and must be at least
	 * sizeof(struct udphdr) + 1 for a minimal QUIC packet.
	 */
	udp_len_host = ntohs(uh->len);
	if (udp_len_host <= sizeof(struct udphdr))
		return NF_ACCEPT;

	quic_len = udp_len_host - sizeof(struct udphdr);

	/*
	 * Pull the full UDP payload into the linear region so that
	 * quic_data pointer is valid. Without this, data in skb page
	 * frags would be inaccessible via direct pointer.
	 */
	total_pull = udp_offset + udp_len_host;
	if (total_pull > skb->len)
		total_pull = skb->len;

	if (!pskb_may_pull(skb, total_pull))
		return NF_ACCEPT;

	/* Re-fetch headers after potential reallocation */
	iph = ip_hdr(skb);
	uh = (struct udphdr *)(skb->data + udp_offset);

	/* Get QUIC payload - now guaranteed to be in linear region */
	quic_data = (u8 *)uh + sizeof(struct udphdr);

	/* Parse QUIC header */
	if (tquic_nf_parse_packet(quic_data, quic_len, &pkt_info) < 0)
		return NF_ACCEPT;

	atomic64_inc(&tquic_nf_packets_seen);

	/* Look up existing connection */
	conn = tquic_nf_conn_find_by_cid(&pkt_info.dcid);
	if (conn) {
		/* Update connection state */
		atomic64_inc(&conn->packets);
		atomic64_add(skb->len, &conn->bytes);
		conn->last_seen = ktime_get();

		/* Update timeout based on state */
		if (conn->state == TQUIC_NF_STATE_ESTABLISHED)
			conn->timeout = jiffies + TQUIC_NF_TIMEOUT_ESTABLISHED * HZ;

		/* Handle state transitions */
		if (pkt_info.is_long_header) {
			if (pkt_info.pkt_type == QUIC_LH_TYPE_HANDSHAKE &&
			    conn->state == TQUIC_NF_STATE_NEW) {
				conn->state = TQUIC_NF_STATE_HANDSHAKE;
			}
		} else {
			/* Short header means connection is established */
			if (conn->state != TQUIC_NF_STATE_ESTABLISHED) {
				conn->state = TQUIC_NF_STATE_ESTABLISHED;
				conn->timeout = jiffies + TQUIC_NF_TIMEOUT_ESTABLISHED * HZ;
			}
		}

		tquic_nf_conn_put(conn);
		return NF_ACCEPT;
	}

	/* New connection - create tracking entry for Initial packets */
	if (pkt_info.is_long_header && pkt_info.pkt_type == QUIC_LH_TYPE_INITIAL) {
		/* Enforce maximum connection tracking limit */
		if (atomic64_read(&tquic_nf_conn_count) >= TQUIC_NF_MAX_CONNECTIONS)
			return NF_ACCEPT;

		conn = tquic_nf_conn_alloc();
		if (conn) {
			conn->dcid = pkt_info.dcid;
			conn->scid = pkt_info.scid;
			conn->is_server = false;

			/* Store addresses */
			if (skb->protocol == htons(ETH_P_IP)) {
				struct sockaddr_in *local, *remote;

				local = (struct sockaddr_in *)&conn->local_addr;
				remote = (struct sockaddr_in *)&conn->remote_addr;

				local->sin_family = AF_INET;
				local->sin_addr.s_addr = iph->daddr;
				local->sin_port = uh->dest;

				remote->sin_family = AF_INET;
				remote->sin_addr.s_addr = iph->saddr;
				remote->sin_port = uh->source;
			}

			tquic_nf_conn_insert(conn);
			tquic_dbg("nf:new connection tracked\n");
		}
	}

	return NF_ACCEPT;
}

/**
 * tquic_nf_hook_out - Output hook for QUIC packets
 * @priv: Hook private data
 * @skb: Packet buffer
 * @state: Hook state
 *
 * Returns: NF_ACCEPT to allow, NF_DROP to drop
 */
static unsigned int tquic_nf_hook_out(void *priv, struct sk_buff *skb,
				      const struct nf_hook_state *state)
{
	/* For output, we primarily track locally originated connections */
	/* Similar logic to input hook but for outgoing packets */
	return NF_ACCEPT;
}

#if IS_ENABLED(CONFIG_IPV6)
/**
 * tquic_nf_hook_in6 - IPv6 input hook for QUIC packets
 */
static unsigned int tquic_nf_hook_in6(void *priv, struct sk_buff *skb,
				      const struct nf_hook_state *state)
{
	struct ipv6hdr *ip6h;
	struct udphdr *uh;
	struct tquic_nf_pkt_info pkt_info;
	struct tquic_nf_conn *conn;
	const u8 *quic_data;
	unsigned int udp_len_host;
	size_t quic_len;
	int total_pull;
	__be16 dport;

	if (!skb)
		return NF_ACCEPT;

	ip6h = ipv6_hdr(skb);

	/*
	 * Only handle direct UDP next header. IPv6 extension headers
	 * would require walking the extension header chain which is
	 * complex and not needed for basic QUIC tracking.
	 */
	if (ip6h->nexthdr != IPPROTO_UDP)
		return NF_ACCEPT;

	if (!pskb_may_pull(skb, sizeof(struct ipv6hdr) + sizeof(struct udphdr)))
		return NF_ACCEPT;

	/* Re-fetch after potential reallocation */
	ip6h = ipv6_hdr(skb);
	uh = (struct udphdr *)(skb->data + sizeof(struct ipv6hdr));
	dport = uh->dest;

	/* Quick check for common QUIC ports */
	if (dport != htons(443) && dport != htons(8443) && dport != htons(4433))
		return NF_ACCEPT;

	/* Validate UDP length to prevent integer underflow */
	udp_len_host = ntohs(uh->len);
	if (udp_len_host <= sizeof(struct udphdr))
		return NF_ACCEPT;

	quic_len = udp_len_host - sizeof(struct udphdr);

	/* Pull full UDP payload into linear region for safe access */
	total_pull = sizeof(struct ipv6hdr) + udp_len_host;
	if (total_pull > skb->len)
		total_pull = skb->len;

	if (!pskb_may_pull(skb, total_pull))
		return NF_ACCEPT;

	/* Re-fetch after potential reallocation */
	ip6h = ipv6_hdr(skb);
	uh = (struct udphdr *)(skb->data + sizeof(struct ipv6hdr));

	quic_data = (u8 *)uh + sizeof(struct udphdr);

	if (tquic_nf_parse_packet(quic_data, quic_len, &pkt_info) < 0)
		return NF_ACCEPT;

	atomic64_inc(&tquic_nf_packets_seen);

	conn = tquic_nf_conn_find_by_cid(&pkt_info.dcid);
	if (conn) {
		atomic64_inc(&conn->packets);
		atomic64_add(skb->len, &conn->bytes);
		conn->last_seen = ktime_get();

		if (conn->state == TQUIC_NF_STATE_ESTABLISHED)
			conn->timeout = jiffies + TQUIC_NF_TIMEOUT_ESTABLISHED * HZ;

		if (!pkt_info.is_long_header &&
		    conn->state != TQUIC_NF_STATE_ESTABLISHED) {
			conn->state = TQUIC_NF_STATE_ESTABLISHED;
			conn->timeout = jiffies + TQUIC_NF_TIMEOUT_ESTABLISHED * HZ;
		}

		tquic_nf_conn_put(conn);
		return NF_ACCEPT;
	}

	/* New IPv6 connection */
	if (pkt_info.is_long_header && pkt_info.pkt_type == QUIC_LH_TYPE_INITIAL) {
		/* Enforce maximum connection tracking limit */
		if (atomic64_read(&tquic_nf_conn_count) >= TQUIC_NF_MAX_CONNECTIONS)
			return NF_ACCEPT;

		conn = tquic_nf_conn_alloc();
		if (conn) {
			struct sockaddr_in6 *local, *remote;

			conn->dcid = pkt_info.dcid;
			conn->scid = pkt_info.scid;
			conn->is_server = false;

			local = (struct sockaddr_in6 *)&conn->local_addr;
			remote = (struct sockaddr_in6 *)&conn->remote_addr;

			local->sin6_family = AF_INET6;
			local->sin6_addr = ip6h->daddr;
			local->sin6_port = uh->dest;

			remote->sin6_family = AF_INET6;
			remote->sin6_addr = ip6h->saddr;
			remote->sin6_port = uh->source;

			tquic_nf_conn_insert(conn);
		}
	}

	return NF_ACCEPT;
}

/**
 * tquic_nf_hook_out6 - IPv6 output hook for QUIC packets
 */
static unsigned int tquic_nf_hook_out6(void *priv, struct sk_buff *skb,
				       const struct nf_hook_state *state)
{
	return NF_ACCEPT;
}
#endif /* CONFIG_IPV6 */

/*
 * Garbage collection
 */

static void tquic_nf_gc_work_fn(struct work_struct *work)
{
	struct tquic_nf_conn *conn;
	struct hlist_node *tmp;
	unsigned long now = jiffies;
	int bkt;

	spin_lock_bh(&tquic_nf_lock);
	hash_for_each_safe(tquic_nf_cid_hash, bkt, tmp, conn, hash_node) {
		if (time_after(now, conn->timeout)) {
			hash_del_rcu(&conn->hash_node);
			hash_del_rcu(&conn->addr_node);
			tquic_nf_conn_put(conn);
		}
	}
	spin_unlock_bh(&tquic_nf_lock);
}

static void tquic_nf_gc_timer_fn(struct timer_list *t)
{
	schedule_work(&tquic_nf_gc_work);
	mod_timer(&tquic_nf_gc_timer, jiffies + 30 * HZ);
}

/*
 * Netfilter hook operations
 */

static const struct nf_hook_ops tquic_nf_hooks[] = {
	{
		.hook		= tquic_nf_hook_in,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_PRE_ROUTING,
		.priority	= NF_IP_PRI_CONNTRACK + 1,
	},
	{
		.hook		= tquic_nf_hook_out,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_LOCAL_OUT,
		.priority	= NF_IP_PRI_CONNTRACK + 1,
	},
#if IS_ENABLED(CONFIG_IPV6)
	{
		.hook		= tquic_nf_hook_in6,
		.pf		= NFPROTO_IPV6,
		.hooknum	= NF_INET_PRE_ROUTING,
		.priority	= NF_IP6_PRI_CONNTRACK + 1,
	},
	{
		.hook		= tquic_nf_hook_out6,
		.pf		= NFPROTO_IPV6,
		.hooknum	= NF_INET_LOCAL_OUT,
		.priority	= NF_IP6_PRI_CONNTRACK + 1,
	},
#endif
};

/* CF-039: register netfilter hooks in all network namespaces */
static int __net_init tquic_nf_net_init(struct net *net)
{
	return nf_register_net_hooks(net, tquic_nf_hooks,
				     ARRAY_SIZE(tquic_nf_hooks));
}

static void __net_exit tquic_nf_net_exit(struct net *net)
{
	nf_unregister_net_hooks(net, tquic_nf_hooks,
				ARRAY_SIZE(tquic_nf_hooks));
}

static struct pernet_operations tquic_nf_net_ops = {
	.init = tquic_nf_net_init,
	.exit = tquic_nf_net_exit,
};

/*
 * Proc interface for connection listing
 */

#ifdef CONFIG_PROC_FS
#include <linux/proc_fs.h>
#include <linux/seq_file.h>

static int tquic_nf_proc_show(struct seq_file *m, void *v)
{
	struct tquic_nf_conn *conn;
	int bkt;

	seq_puts(m, "# TQUIC Netfilter Connection Tracking\n");
	seq_puts(m, "# State Packets Bytes LastSeen(ms) DCID\n");

	rcu_read_lock();
	hash_for_each_rcu(tquic_nf_cid_hash, bkt, conn, hash_node) {
		seq_printf(m, "%u %llu %llu %lld ",
			   conn->state,
			   atomic64_read(&conn->packets),
			   atomic64_read(&conn->bytes),
			   ktime_to_ms(ktime_sub(ktime_get(), conn->last_seen)));

		/* Print DCID as hex */
		seq_printf(m, "%*phN\n", conn->dcid.len, conn->dcid.id);
	}
	rcu_read_unlock();

	seq_printf(m, "# Total connections: %lld\n",
		   atomic64_read(&tquic_nf_conn_count));
	seq_printf(m, "# Total packets seen: %lld\n",
		   atomic64_read(&tquic_nf_packets_seen));

	return 0;
}

static int tquic_nf_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, tquic_nf_proc_show, NULL);
}

static const struct proc_ops tquic_nf_proc_ops = {
	.proc_open	= tquic_nf_proc_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};
#endif /* CONFIG_PROC_FS */

/*
 * Module initialization
 */

static struct proc_dir_entry *tquic_nf_proc_entry;

int __init tquic_nf_init(void)
{
	int ret;

	tquic_info("netfilter integration initializing\n");

	/* Initialize hash tables */
	hash_init(tquic_nf_cid_hash);
	hash_init(tquic_nf_addr_hash);

	/* CF-039: register hooks in all network namespaces via pernet_operations */
	ret = register_pernet_subsys(&tquic_nf_net_ops);
	if (ret) {
		tquic_err("failed to register netfilter hooks: %d\n", ret);
		return ret;
	}

	/* Initialize garbage collection */
	INIT_WORK(&tquic_nf_gc_work, tquic_nf_gc_work_fn);
	timer_setup(&tquic_nf_gc_timer, tquic_nf_gc_timer_fn, 0);
	mod_timer(&tquic_nf_gc_timer, jiffies + 30 * HZ);

#ifdef CONFIG_PROC_FS
	tquic_nf_proc_entry = proc_create("tquic_conntrack", 0444, init_net.proc_net,
					  &tquic_nf_proc_ops);
#endif

	tquic_info("netfilter integration initialized\n");
	return 0;
}

void __exit tquic_nf_exit(void)
{
	struct tquic_nf_conn *conn;
	struct hlist_node *tmp;
	int bkt;

	tquic_info("netfilter integration exiting\n");

#ifdef CONFIG_PROC_FS
	if (tquic_nf_proc_entry)
		proc_remove(tquic_nf_proc_entry);
#endif

	/* Stop garbage collection */
	del_timer_sync(&tquic_nf_gc_timer);
	cancel_work_sync(&tquic_nf_gc_work);

	/* CF-039: unregister hooks from all network namespaces */
	unregister_pernet_subsys(&tquic_nf_net_ops);

	/* Free all connections */
	spin_lock_bh(&tquic_nf_lock);
	hash_for_each_safe(tquic_nf_cid_hash, bkt, tmp, conn, hash_node) {
		hash_del_rcu(&conn->hash_node);
		hash_del_rcu(&conn->addr_node);
		tquic_nf_conn_put(conn);
	}
	spin_unlock_bh(&tquic_nf_lock);

	/* Wait for RCU grace period */
	synchronize_rcu();

	tquic_info("netfilter integration exited\n");
}

EXPORT_SYMBOL_GPL(tquic_nf_init);
EXPORT_SYMBOL_GPL(tquic_nf_exit);

module_init(tquic_nf_init);
module_exit(tquic_nf_exit);

MODULE_DESCRIPTION("TQUIC Netfilter Integration");
MODULE_LICENSE("GPL");
