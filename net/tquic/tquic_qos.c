// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: QoS Traffic Classification
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * This file implements QoS classification for TCP-over-QUIC tunnels.
 * The VPS uses router-provided hints plus port-based heuristics to
 * classify traffic into 4 classes for tc HTB scheduling.
 *
 * Per CONTEXT.md:
 *   - VPS-side QoS classification with 4 traffic classes
 *   - Router hints for flow classification
 *   - Traffic shaping (delay packets) when exceeding limits
 *
 * Traffic Classes:
 *   0: Real-time (VoIP/video) - DSCP EF (46)
 *   1: Interactive (gaming) - DSCP AF41 (34)
 *   2: Bulk (downloads) - DSCP BE (0)
 *   3: Background - DSCP CS1 (8)
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <net/tquic.h>
#include <net/dsfield.h>
#include <net/inet_ecn.h>

#include "protocol.h"
#include "tquic_debug.h"

/*
 * Forward declaration for tunnel structure
 * (full definition in tquic_tunnel.c)
 */
struct tquic_tunnel;

/* External access to tunnel fields needed for QoS */
extern u8 tquic_tunnel_get_traffic_class(struct tquic_tunnel *tunnel);
extern __be16 tquic_tunnel_get_dest_port(struct tquic_tunnel *tunnel);

/*
 * =============================================================================
 * DSCP VALUE DEFINITIONS
 * =============================================================================
 *
 * DSCP (Differentiated Services Code Point) values for traffic marking.
 * These are the 6-bit DSCP values shifted into the TOS field position.
 */

#define DSCP_EF		0xB8	/* Expedited Forwarding (46 << 2) */
#define DSCP_AF41	0x88	/* Assured Forwarding 41 (34 << 2) */
#define DSCP_BE		0x00	/* Best Effort (0) */
#define DSCP_CS1	0x20	/* Class Selector 1 (8 << 2) */

/* Traffic class to DSCP mapping */
static const u8 tquic_dscp_map[4] = {
	DSCP_EF,	/* 0: Real-time */
	DSCP_AF41,	/* 1: Interactive */
	DSCP_BE,	/* 2: Bulk */
	DSCP_CS1,	/* 3: Background */
};

/*
 * =============================================================================
 * PORT-BASED CLASSIFICATION OVERRIDES
 * =============================================================================
 *
 * Some ports have well-known traffic characteristics that override
 * the router hint. This provides a safety net for correct classification.
 */

/* Real-time ports (VoIP) */
static const __be16 realtime_ports[] = {
	__constant_htons(5060),		/* SIP */
	__constant_htons(5061),		/* SIP TLS */
	__constant_htons(3478),		/* STUN/TURN */
	__constant_htons(3479),		/* STUN/TURN alt */
	__constant_htons(19302),	/* Google STUN */
	0,
};

/* Interactive ports (gaming, SSH) */
static const __be16 interactive_ports[] = {
	__constant_htons(22),		/* SSH */
	__constant_htons(23),		/* Telnet */
	__constant_htons(3389),		/* RDP */
	0,
};

/* Background ports (low priority) */
static const __be16 background_ports[] = {
	__constant_htons(6881),		/* BitTorrent */
	__constant_htons(6882),
	__constant_htons(6883),
	__constant_htons(6884),
	__constant_htons(6885),
	__constant_htons(6886),
	__constant_htons(6887),
	__constant_htons(6888),
	__constant_htons(6889),
	0,
};

/**
 * tquic_port_in_list - Check if port is in list
 * @port: Port to check (network byte order)
 * @list: NULL-terminated list of ports
 *
 * Returns: true if port is in list
 */
static bool tquic_port_in_list(__be16 port, const __be16 *list)
{
	while (*list) {
		if (port == *list)
			return true;
		list++;
	}
	return false;
}

/*
 * =============================================================================
 * QOS CLASSIFICATION API
 * =============================================================================
 */

/**
 * tquic_qos_classify - Classify tunnel traffic based on router hint and port
 * @tunnel: Tunnel to classify
 * @router_hint: QoS hint from router (0-3)
 *
 * Per CONTEXT.md: Router hints for flow classification, VPS honors hints.
 * However, certain ports override hints for safety (e.g., SIP is always realtime).
 *
 * Returns: Assigned traffic class (0-3)
 */
int tquic_qos_classify(void *tunnel_ptr, u8 router_hint)
{
	struct tquic_tunnel *tunnel = tunnel_ptr;
	__be16 dest_port;
	u8 traffic_class;

	if (!tunnel)
		return 2;  /* Default to bulk */

	/* Validate router hint */
	if (router_hint > 3)
		router_hint = 2;  /* Default to bulk */

	/* Start with router hint */
	traffic_class = router_hint;

	/* Get destination port for override checks */
	dest_port = tquic_tunnel_get_dest_port(tunnel);

	/*
	 * Port-based overrides for safety
	 * These override the router hint to ensure correct classification
	 */

	/* Real-time ports (VoIP/SIP) always get realtime class */
	if (tquic_port_in_list(dest_port, realtime_ports)) {
		traffic_class = 0;  /* Real-time */
		goto done;
	}

	/* Interactive ports get at least interactive class */
	if (tquic_port_in_list(dest_port, interactive_ports)) {
		if (traffic_class > 1)
			traffic_class = 1;  /* Interactive */
		goto done;
	}

	/* Background ports (BitTorrent) never get better than bulk */
	if (tquic_port_in_list(dest_port, background_ports)) {
		if (traffic_class < 2)
			traffic_class = 3;  /* Background */
		goto done;
	}

done:
	return traffic_class;
}
EXPORT_SYMBOL_GPL(tquic_qos_classify);

/**
 * tquic_qos_mark_skb - Apply QoS marking to outbound packet
 * @skb: Packet to mark
 * @tunnel: Tunnel context for traffic class lookup
 *
 * Sets:
 *   - skb->priority for tc HTB class selection
 *   - IP TOS/DSCP for external network QoS
 *
 * Per CONTEXT.md: VPS-side QoS classification with 4 traffic classes.
 */
void tquic_qos_mark_skb(struct sk_buff *skb, void *tunnel_ptr)
{
	struct tquic_tunnel *tunnel = tunnel_ptr;
	u8 traffic_class;
	u8 dscp;
	struct iphdr *iph;
	struct ipv6hdr *ip6h;

	if (!skb || !tunnel)
		return;

	traffic_class = tquic_tunnel_get_traffic_class(tunnel);
	if (traffic_class > 3)
		traffic_class = 2;

	dscp = tquic_dscp_map[traffic_class];

	/*
	 * Set skb->priority for tc HTB class selection
	 *
	 * HTB classes are typically set up as:
	 *   1:10 = Real-time (prio 0)
	 *   1:20 = Interactive (prio 1)
	 *   1:30 = Bulk (prio 2)
	 *   1:40 = Background (prio 3)
	 *
	 * nftables can use meta mark to select class, or we can
	 * use skb->priority directly with the skbedit action.
	 */
	skb->priority = traffic_class;

	/*
	 * Set DSCP in IP header for external QoS.
	 *
	 * Use INET_ECN_MASK (0x03) as the preserve mask to keep the
	 * ECN bits intact. A mask of 0 would destroy ECN signaling
	 * which is critical for QUIC congestion control (especially
	 * Prague/L4S). The dsfield functions apply: new = (old & mask) | dscp,
	 * so mask=0x03 preserves the low 2 ECN bits while replacing DSCP.
	 */
	if (skb->protocol == htons(ETH_P_IP)) {
		if (!pskb_may_pull(skb, sizeof(struct iphdr)))
			return;

		iph = ip_hdr(skb);
		ipv4_change_dsfield(iph, INET_ECN_MASK, dscp);

	} else if (skb->protocol == htons(ETH_P_IPV6)) {
		if (!pskb_may_pull(skb, sizeof(struct ipv6hdr)))
			return;

		ip6h = ipv6_hdr(skb);
		ipv6_change_dsfield(ip6h, INET_ECN_MASK, dscp);
	}
}
EXPORT_SYMBOL_GPL(tquic_qos_mark_skb);

/**
 * tquic_qos_get_dscp - Get DSCP value for traffic class
 * @traffic_class: Traffic class (0-3)
 *
 * Returns: DSCP value for the traffic class
 */
u8 tquic_qos_get_dscp(u8 traffic_class)
{
	if (traffic_class > 3)
		traffic_class = 2;
	return tquic_dscp_map[traffic_class];
}
EXPORT_SYMBOL_GPL(tquic_qos_get_dscp);

/**
 * tquic_qos_get_priority - Get skb priority for traffic class
 * @traffic_class: Traffic class (0-3)
 *
 * Returns: Priority value for skb->priority
 */
u32 tquic_qos_get_priority(u8 traffic_class)
{
	if (traffic_class > 3)
		traffic_class = 2;
	return traffic_class;
}
EXPORT_SYMBOL_GPL(tquic_qos_get_priority);

/*
 * =============================================================================
 * QOS STATISTICS
 * =============================================================================
 */

/**
 * struct tquic_qos_stats - Per-class traffic statistics
 * @packets: Packets in this class
 * @bytes: Bytes in this class
 * @drops: Packets dropped due to shaping
 *
 * All fields use atomic64_t to prevent torn reads/writes on 32-bit
 * architectures and data races from concurrent updates.
 */
struct tquic_qos_stats {
	atomic64_t packets;
	atomic64_t bytes;
	atomic64_t drops;
};

/* Per-netns QoS stats would go here */
static struct tquic_qos_stats qos_stats[4];

/**
 * tquic_qos_update_stats - Update per-class statistics
 * @traffic_class: Traffic class (0-3)
 * @bytes: Bytes transmitted
 */
void tquic_qos_update_stats(u8 traffic_class, u64 bytes)
{
	if (traffic_class > 3)
		return;

	atomic64_inc(&qos_stats[traffic_class].packets);
	atomic64_add(bytes, &qos_stats[traffic_class].bytes);
}
EXPORT_SYMBOL_GPL(tquic_qos_update_stats);

/**
 * tquic_qos_get_stats - Get per-class statistics
 * @traffic_class: Traffic class (0-3)
 * @packets: OUT - Packet count
 * @bytes: OUT - Byte count
 * @drops: OUT - Drop count
 */
void tquic_qos_get_stats(u8 traffic_class, u64 *packets, u64 *bytes, u64 *drops)
{
	if (traffic_class > 3)
		return;

	if (packets)
		*packets = atomic64_read(&qos_stats[traffic_class].packets);
	if (bytes)
		*bytes = atomic64_read(&qos_stats[traffic_class].bytes);
	if (drops)
		*drops = atomic64_read(&qos_stats[traffic_class].drops);
}
EXPORT_SYMBOL_GPL(tquic_qos_get_stats);

/*
 * =============================================================================
 * MODULE INIT/EXIT
 * =============================================================================
 */

/**
 * tquic_qos_init - Initialize QoS subsystem
 */
int __init tquic_qos_init(void)
{
	int i;

	for (i = 0; i < 4; i++) {
		atomic64_set(&qos_stats[i].packets, 0);
		atomic64_set(&qos_stats[i].bytes, 0);
		atomic64_set(&qos_stats[i].drops, 0);
	}
	tquic_info("QoS classification initialized\n");
	return 0;
}

/**
 * tquic_qos_exit - Cleanup QoS subsystem
 */
void __exit tquic_qos_exit(void)
{
	tquic_info("QoS classification cleaned up\n");
}

/*
 * =============================================================================
 * EXTERNAL TUNNEL ACCESSORS
 * =============================================================================
 *
 * These functions are implemented in tquic_tunnel.c and provide
 * type-safe access to tunnel fields.
 */

/* Declarations for tunnel accessors (implemented in tquic_tunnel.c) */
extern u8 tquic_tunnel_get_traffic_class(struct tquic_tunnel *tunnel);
extern __be16 tquic_tunnel_get_dest_port(struct tquic_tunnel *tunnel);
