// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC Generic Receive Offload (GRO) Support
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Implements GRO for TQUIC to aggregate multiple incoming packets into
 * larger buffers for efficient processing. This is the receive-side
 * counterpart to GSO (Generic Segmentation Offload) on transmit.
 *
 * GRO aggregation criteria for QUIC:
 * - Same destination connection ID (same QUIC connection)
 * - Same encryption level
 * - Total aggregated size within limits
 *
 * The implementation follows the UDP GRO pattern (net/ipv4/udp_offload.c)
 * but with QUIC-specific coalescing logic.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/netdevice.h>
#include <linux/seq_file.h>
#include <net/sock.h>
#include <net/udp.h>
#include <net/protocol.h>
#include <net/gro.h>
#include <net/gso.h>
#include <net/ip6_checksum.h>
#include <net/udp_tunnel.h>
#include <net/tquic.h>

#include <linux/percpu.h>

#include "tquic_compat.h"
#include "tquic_debug.h"
#include "tquic_mib.h"

/* GRO configuration */
#define TQUIC_GRO_MAX_COUNT		64	/* Max packets in single GRO flow */
#define TQUIC_GRO_MAX_SIZE		65535	/* Max aggregated size */
#define TQUIC_GRO_FLUSH_TIMEOUT_NS	1000000	/* 1ms flush timeout */

/* QUIC header constants */
#define TQUIC_HEADER_FORM_LONG		0x80
#define TQUIC_HEADER_FIXED_BIT		0x40
#define TQUIC_HEADER_KEY_PHASE		0x04

/* Maximum CID length for comparison */
#define TQUIC_MAX_CID_LEN		20

/*
 * GRO statistics - per-CPU counters to avoid cache-line bouncing on
 * the hot path (incremented on every received packet).  Readers sum
 * across all CPUs when reporting via /proc.
 */
struct tquic_gro_stats_cpu {
	u64 coalesced_packets;
	u64 gro_flush_count;
	u64 gro_held_count;
	u64 total_aggregation;
	u64 aggregation_samples;
};

static DEFINE_PER_CPU(struct tquic_gro_stats_cpu, tquic_gro_stats_cpu);

/*
 * =============================================================================
 * QUIC Header Parsing for GRO
 * =============================================================================
 */

/**
 * struct tquic_gro_header - Parsed header info for GRO decisions
 * @is_long_header: True if long header format
 * @dcid: Destination connection ID
 * @dcid_len: Length of destination CID
 * @pkt_type: Packet type for long headers
 * @header_len: Total header length (including packet number)
 */
struct tquic_gro_header {
	bool is_long_header;
	u8 dcid[TQUIC_MAX_CID_LEN];
	u8 dcid_len;
	u8 pkt_type;
	u16 header_len;
};

/**
 * tquic_gro_parse_header - Parse QUIC header for GRO
 * @data: Pointer to packet data
 * @len: Length of packet
 * @hdr: Output parsed header structure
 *
 * Parses just enough of the QUIC header to make GRO coalescing decisions.
 * For long headers, extracts version and DCID. For short headers, extracts
 * DCID based on connection state or minimum expected length.
 *
 * Returns: 0 on success, negative errno on failure
 */
static int tquic_gro_parse_header(const u8 *data, size_t len,
				  struct tquic_gro_header *hdr)
{
	u8 first_byte;

	if (len < 1)
		return -EINVAL;

	first_byte = data[0];
	memset(hdr, 0, sizeof(*hdr));

	if (first_byte & TQUIC_HEADER_FORM_LONG) {
		/* Long header format */
		u8 dcid_len;

		hdr->is_long_header = true;

		/* Minimum long header: 1 + 4 (version) + 1 (dcid_len) = 6 */
		if (len < 6)
			return -EINVAL;

		/* Skip version (4 bytes) */
		dcid_len = data[5];
		if (dcid_len > TQUIC_MAX_CID_LEN)
			return -EINVAL;

		if (len < 6 + dcid_len)
			return -EINVAL;

		hdr->dcid_len = dcid_len;
		memcpy(hdr->dcid, data + 6, dcid_len);

		/* Packet type from first byte */
		hdr->pkt_type = (first_byte & 0x30) >> 4;

		/* Approximate header length - actual parsing happens later */
		hdr->header_len = 6 + dcid_len;
	} else {
		/* Short header format */
		hdr->is_long_header = false;

		/*
		 * For short headers, DCID length is negotiated per-connection.
		 * Use default length (8 bytes) for GRO matching.
		 * Actual DCID length will be determined during full processing.
		 */
		hdr->dcid_len = TQUIC_DEFAULT_CID_LEN;

		if (len < 1 + hdr->dcid_len)
			return -EINVAL;

		memcpy(hdr->dcid, data + 1, hdr->dcid_len);

		/* Approximate header length */
		hdr->header_len = 1 + hdr->dcid_len;
	}

	return 0;
}

/**
 * tquic_gro_same_flow - Check if two packets belong to same GRO flow
 * @hdr1: First packet header
 * @hdr2: Second packet header
 *
 * Packets can be coalesced if they have the same DCID (same connection).
 * For long headers, also require same packet type (encryption level).
 *
 * Returns: true if packets can be coalesced
 */
static bool tquic_gro_same_flow(const struct tquic_gro_header *hdr1,
				const struct tquic_gro_header *hdr2)
{
	/* Must match header form */
	if (hdr1->is_long_header != hdr2->is_long_header)
		return false;

	/* DCID length must match */
	if (hdr1->dcid_len != hdr2->dcid_len)
		return false;

	/* DCID content must match */
	if (memcmp(hdr1->dcid, hdr2->dcid, hdr1->dcid_len) != 0)
		return false;

	/* For long headers, packet type must match (same encryption level) */
	if (hdr1->is_long_header && hdr1->pkt_type != hdr2->pkt_type)
		return false;

	return true;
}

/*
 * =============================================================================
 * TQUIC GRO Receive Callback
 * =============================================================================
 */

/**
 * tquic_gro_receive_segment - GRO receive for QUIC packet segments
 * @head: List of held packets
 * @skb: Incoming packet
 *
 * This is the core GRO receive function for TQUIC. It attempts to coalesce
 * the incoming packet with already-held packets that belong to the same
 * QUIC connection.
 *
 * Unlike TCP GRO, QUIC packets are independently encrypted, so we use
 * frag_list aggregation rather than payload merging. Each QUIC packet
 * in the aggregated skb will be processed separately.
 *
 * Returns: Packet to flush (if any), or NULL
 */
static struct sk_buff *tquic_gro_receive_segment(struct list_head *head,
						 struct sk_buff *skb)
{
	struct tquic_gro_header new_hdr;
	struct sk_buff *pp = NULL;
	struct sk_buff *p;
	unsigned int gro_len;
	int ret;

	/* Parse header of incoming packet */
	ret = tquic_gro_parse_header(skb->data + skb_gro_offset(skb),
				     skb_gro_len(skb), &new_hdr);
	if (ret < 0) {
		NAPI_GRO_CB(skb)->flush = 1;
		return NULL;
	}

	gro_len = skb_gro_len(skb);

	/* Search for matching flow in held packets */
	list_for_each_entry(p, head, list) {
		struct tquic_gro_header held_hdr;

		if (!NAPI_GRO_CB(p)->same_flow)
			continue;

		/* Parse held packet header */
		ret = tquic_gro_parse_header(p->data + skb_gro_offset(p),
					     skb_gro_len(p), &held_hdr);
		if (ret < 0) {
			NAPI_GRO_CB(p)->same_flow = 0;
			continue;
		}

		/* Check if same QUIC flow */
		if (!tquic_gro_same_flow(&held_hdr, &new_hdr)) {
			NAPI_GRO_CB(p)->same_flow = 0;
			continue;
		}

		/* Check size limit */
		if (p->len + gro_len > TQUIC_GRO_MAX_SIZE) {
			pp = p;
			break;
		}

		/* Check count limit */
		if (NAPI_GRO_CB(p)->count >= TQUIC_GRO_MAX_COUNT) {
			pp = p;
			break;
		}

		/*
		 * Use frag_list aggregation for QUIC packets.
		 * Each packet remains independently processable.
		 */
		if (!pskb_may_pull(skb, skb_gro_offset(skb))) {
			NAPI_GRO_CB(skb)->flush = 1;
			return NULL;
		}

#if !TQUIC_HAS_GRO_RECEIVE_LIST || defined(TQUIC_OUT_OF_TREE)
		/*
		 * skb_gro_receive_list is not available on pre-5.6 kernels
		 * or not exported for out-of-tree modules.
		 * Flush this packet instead of coalescing.
		 */
		NAPI_GRO_CB(skb)->flush = 1;
		return pp;
#else
		/* Set up for frag_list receive */
		skb_set_network_header(skb, skb_gro_receive_network_offset(skb));
		ret = skb_gro_receive_list(p, skb);
		if (ret) {
			NAPI_GRO_CB(skb)->flush = 1;
			return NULL;
		}
#endif

		/* Update statistics */
		this_cpu_inc(tquic_gro_stats_cpu.coalesced_packets);

		return pp;
	}

	/* No match found - packet will be held */
	this_cpu_inc(tquic_gro_stats_cpu.gro_held_count);

	return NULL;
}

/**
 * tquic_gro_receive - Main GRO receive entry point
 * @head: List of held packets
 * @skb: Incoming packet
 * @uh: UDP header (QUIC runs over UDP)
 * @sk: Socket (may be NULL)
 *
 * Called by the network stack when a QUIC packet arrives. Determines
 * whether to aggregate with held packets or flush.
 *
 * Returns: Packet to flush, or NULL
 */
struct sk_buff *tquic_gro_receive(struct list_head *head, struct sk_buff *skb,
				  struct udphdr *uh, struct sock *sk)
{
	struct sk_buff *pp = NULL;
	int flush = 1;

	/* Set up for frag_list GRO */
	TQUIC_NAPI_GRO_CB_SET_IS_FLIST(skb, 1);

	/* Validate UDP length */
	if (ntohs(uh->len) < sizeof(*uh)) {
		NAPI_GRO_CB(skb)->flush = 1;
		return NULL;
	}

	/* Skip UDP header for QUIC processing */
	skb_gro_pull(skb, sizeof(struct udphdr));

	/* Attempt to receive/coalesce */
	pp = call_gro_receive(tquic_gro_receive_segment, head, skb);

	flush = 0;

	skb_gro_flush_final(skb, pp, flush);
	return pp;
}
EXPORT_SYMBOL_GPL(tquic_gro_receive);

/*
 * =============================================================================
 * TQUIC GRO Complete Callback
 * =============================================================================
 */

/**
 * tquic_gro_complete - Finalize GRO aggregated packet
 * @skb: Aggregated packet
 * @nhoff: Network header offset
 *
 * Called when an aggregated packet is ready to be delivered to the stack.
 * Sets up GSO information so the stack can properly handle the aggregated
 * packet or segment it if needed.
 *
 * Returns: 0 on success
 */
int tquic_gro_complete(struct sk_buff *skb, int nhoff)
{
	struct udphdr *uh = (struct udphdr *)(skb->data + nhoff);
	u16 aggregation_count;

	/* Update UDP length for aggregated packet */
	uh->len = htons(skb->len - nhoff);

	/* Mark as frag_list GSO for transmit path */
	skb_shinfo(skb)->gso_type |= (SKB_GSO_FRAGLIST | SKB_GSO_UDP_L4);
	aggregation_count = NAPI_GRO_CB(skb)->count;
	skb_shinfo(skb)->gso_segs = aggregation_count;

	/* Mark checksum as unnecessary (already validated) */
	__skb_incr_checksum_unnecessary(skb);

	/* Update statistics */
	this_cpu_inc(tquic_gro_stats_cpu.gro_flush_count);
	this_cpu_add(tquic_gro_stats_cpu.total_aggregation, aggregation_count);
	this_cpu_inc(tquic_gro_stats_cpu.aggregation_samples);
	this_cpu_sub(tquic_gro_stats_cpu.gro_held_count, aggregation_count);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_gro_complete);

/*
 * =============================================================================
 * IPv4 TQUIC GRO Callbacks
 * =============================================================================
 */

/**
 * tquic4_gro_receive - IPv4 GRO receive for TQUIC
 * @head: List of held packets
 * @skb: Incoming packet
 *
 * Called by the network stack for IPv4 UDP packets destined for TQUIC.
 *
 * Returns: Packet to flush, or NULL
 */
static struct sk_buff *tquic4_gro_receive(struct list_head *head,
					  struct sk_buff *skb)
{
	struct udphdr *uh = udp_gro_udphdr(skb);
	struct sock *sk = NULL;

	if (unlikely(!uh))
		goto flush;

	/* Don't bother if we're going to flush anyway */
	if (NAPI_GRO_CB(skb)->flush)
		goto skip;

	/* Validate checksum */
	if (skb_gro_checksum_validate_zero_check(skb, IPPROTO_UDP, uh->check,
						 inet_gro_compute_pseudo))
		goto flush;
	else if (uh->check)
		tquic_gro_checksum_try_convert(skb, IPPROTO_UDP,
					       inet_gro_compute_pseudo);

skip:
	return tquic_gro_receive(head, skb, uh, sk);

flush:
	NAPI_GRO_CB(skb)->flush = 1;
	return NULL;
}

/**
 * tquic4_gro_complete - IPv4 GRO complete for TQUIC
 * @skb: Aggregated packet
 * @nhoff: Network header offset
 *
 * Returns: 0 on success
 */
static int tquic4_gro_complete(struct sk_buff *skb, int nhoff)
{
	const u16 offset = TQUIC_GRO_NETWORK_OFFSET(skb);
	const struct iphdr *iph = (struct iphdr *)(skb->data + offset);
	struct udphdr *uh = (struct udphdr *)(skb->data + nhoff);

	/* Update UDP checksum for aggregated length */
	if (uh->check)
		uh->check = ~udp_v4_check(skb->len - nhoff, iph->saddr,
					  iph->daddr, 0);

	return tquic_gro_complete(skb, nhoff);
}

/*
 * =============================================================================
 * IPv6 TQUIC GRO Callbacks
 * =============================================================================
 */

#if IS_ENABLED(CONFIG_IPV6)
/**
 * tquic6_gro_receive - IPv6 GRO receive for TQUIC
 * @head: List of held packets
 * @skb: Incoming packet
 *
 * Returns: Packet to flush, or NULL
 */
static struct sk_buff *tquic6_gro_receive(struct list_head *head,
					  struct sk_buff *skb)
{
	struct udphdr *uh = udp_gro_udphdr(skb);
	struct sock *sk = NULL;

	if (unlikely(!uh))
		goto flush;

	if (NAPI_GRO_CB(skb)->flush)
		goto skip;

	if (skb_gro_checksum_validate_zero_check(skb, IPPROTO_UDP, uh->check,
						 ip6_gro_compute_pseudo))
		goto flush;
	else if (uh->check)
		tquic_gro_checksum_try_convert(skb, IPPROTO_UDP,
					       ip6_gro_compute_pseudo);

skip:
	return tquic_gro_receive(head, skb, uh, sk);

flush:
	NAPI_GRO_CB(skb)->flush = 1;
	return NULL;
}

/**
 * tquic6_gro_complete - IPv6 GRO complete for TQUIC
 * @skb: Aggregated packet
 * @nhoff: Network header offset
 *
 * Returns: 0 on success
 */
static int tquic6_gro_complete(struct sk_buff *skb, int nhoff)
{
	const u16 offset = TQUIC_GRO_NETWORK_OFFSET(skb);
	const struct ipv6hdr *ipv6h = (struct ipv6hdr *)(skb->data + offset);
	struct udphdr *uh = (struct udphdr *)(skb->data + nhoff);

	if (uh->check)
		uh->check = ~udp_v6_check(skb->len - nhoff, &ipv6h->saddr,
					  &ipv6h->daddr, 0);

	return tquic_gro_complete(skb, nhoff);
}
#endif /* CONFIG_IPV6 */

/*
 * =============================================================================
 * TQUIC GSO Segment Callback
 * =============================================================================
 */

/**
 * tquic_gso_segment - GSO segmentation for TQUIC
 * @skb: Packet to segment
 * @features: Device features
 *
 * Handles GSO segmentation for TQUIC packets. Since QUIC packets in
 * a frag_list are already individually valid, we can use the standard
 * UDP GSO segmentation path.
 *
 * Returns: Segmented skb chain, or error pointer
 */
static struct sk_buff *tquic_gso_segment(struct sk_buff *skb,
					 netdev_features_t features)
{
	struct sk_buff *segs = ERR_PTR(-EINVAL);

	if (!(skb_shinfo(skb)->gso_type & (SKB_GSO_UDP_L4 | SKB_GSO_FRAGLIST)))
		return segs;

	/* Use standard UDP GSO segmentation */
#if TQUIC_HAS_SKB_SEGMENT_LIST
	if (skb_shinfo(skb)->gso_type & SKB_GSO_FRAGLIST) {
		/* Frag list case - segment by list elements */
		segs = skb_segment_list(skb, features, skb_mac_header_len(skb));
	} else
#endif
	{
		/* Standard UDP L4 GSO */
		segs = TQUIC_UDP_GSO_SEGMENT(skb, features,
					     skb->protocol == htons(ETH_P_IPV6));
	}

	return segs;
}

/*
 * =============================================================================
 * Offload Registration
 * =============================================================================
 */

/* IPv4 TQUIC offload structure */
static struct net_offload __maybe_unused tquic4_offload = {
	.callbacks = {
		.gso_segment	= tquic_gso_segment,
		.gro_receive	= tquic4_gro_receive,
		.gro_complete	= tquic4_gro_complete,
	},
};

#if IS_ENABLED(CONFIG_IPV6)
/* IPv6 TQUIC offload structure */
static struct net_offload __maybe_unused tquic6_offload = {
	.callbacks = {
		.gso_segment	= tquic_gso_segment,
		.gro_receive	= tquic6_gro_receive,
		.gro_complete	= tquic6_gro_complete,
	},
};
#endif

/*
 * =============================================================================
 * Statistics Export via /proc
 * =============================================================================
 */

/**
 * tquic_gro_stats_show - Show GRO statistics in proc output
 * @seq: Seq file for output
 *
 * Appends GRO statistics to the /proc/net/tquic/stats output.
 */
void tquic_gro_stats_show(struct seq_file *seq)
{
	u64 coalesced = 0, flushes = 0, held = 0;
	u64 total_agg = 0, samples = 0, avg_agg = 0;
	int cpu;

	for_each_possible_cpu(cpu) {
		const struct tquic_gro_stats_cpu *s;

		s = per_cpu_ptr(&tquic_gro_stats_cpu, cpu);
		coalesced += READ_ONCE(s->coalesced_packets);
		flushes   += READ_ONCE(s->gro_flush_count);
		held      += READ_ONCE(s->gro_held_count);
		total_agg += READ_ONCE(s->total_aggregation);
		samples   += READ_ONCE(s->aggregation_samples);
	}

	if (samples > 0)
		avg_agg = total_agg / samples;

	seq_puts(seq, "\nGRO Statistics\n");
	seq_puts(seq, "==============\n");
	seq_printf(seq, "Packets coalesced:     %llu\n", coalesced);
	seq_printf(seq, "GRO flushes:           %llu\n", flushes);
	seq_printf(seq, "Currently held:        %llu\n", held);
	seq_printf(seq, "Average aggregation:   %llu\n", avg_agg);
}
EXPORT_SYMBOL_GPL(tquic_gro_stats_show);

/**
 * tquic_gro_get_stats - Get GRO statistics
 * @coalesced: Output for coalesced packet count
 * @flushes: Output for flush count
 * @avg_aggregation: Output for average aggregation factor
 */
void tquic_gro_get_stats(u64 *coalesced, u64 *flushes, u64 *avg_aggregation)
{
	u64 tot_coalesced = 0, tot_flushes = 0;
	u64 total_agg = 0, samples = 0;
	int cpu;

	for_each_possible_cpu(cpu) {
		const struct tquic_gro_stats_cpu *s;

		s = per_cpu_ptr(&tquic_gro_stats_cpu, cpu);
		tot_coalesced += READ_ONCE(s->coalesced_packets);
		tot_flushes   += READ_ONCE(s->gro_flush_count);
		total_agg     += READ_ONCE(s->total_aggregation);
		samples       += READ_ONCE(s->aggregation_samples);
	}

	if (coalesced)
		*coalesced = tot_coalesced;
	if (flushes)
		*flushes = tot_flushes;
	if (avg_aggregation) {
		if (samples > 0)
			*avg_aggregation = total_agg / samples;
		else
			*avg_aggregation = 0;
	}
}
EXPORT_SYMBOL_GPL(tquic_gro_get_stats);

/*
 * =============================================================================
 * UDP Tunnel GRO Integration
 * =============================================================================
 */

/**
 * tquic_gro_receive_udp - GRO callback for UDP tunnel sockets
 * @sk: UDP socket
 * @head: List of held packets
 * @skb: Incoming packet
 *
 * This is registered as the gro_receive callback for TQUIC UDP sockets.
 * It enables GRO for QUIC packets received on the tunnel socket.
 *
 * Returns: Packet to flush, or NULL
 */
struct sk_buff *tquic_gro_receive_udp(struct sock *sk, struct list_head *head,
				      struct sk_buff *skb)
{
	struct udphdr *uh = udp_hdr(skb);

	/* Use the generic TQUIC GRO receive */
	return tquic_gro_receive(head, skb, uh, sk);
}
EXPORT_SYMBOL_GPL(tquic_gro_receive_udp);

/**
 * tquic_gro_complete_udp - GRO complete callback for UDP tunnel sockets
 * @sk: UDP socket
 * @skb: Aggregated packet
 * @nhoff: Network header offset
 *
 * This is registered as the gro_complete callback for TQUIC UDP sockets.
 *
 * Returns: 0 on success
 */
int tquic_gro_complete_udp(struct sock *sk, struct sk_buff *skb, int nhoff)
{
	return tquic_gro_complete(skb, nhoff);
}
EXPORT_SYMBOL_GPL(tquic_gro_complete_udp);

/**
 * tquic_setup_gro - Enable GRO on a TQUIC socket
 * @sk: Socket to enable GRO on
 *
 * Registers GRO callbacks for the UDP socket used by TQUIC.
 * This should be called when setting up a TQUIC connection.
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_setup_gro(struct sock *sk)
{
	struct udp_sock *up;

	if (!sk)
		return -EINVAL;

	up = udp_sk(sk);

	/* Set GRO callbacks */
	up->gro_receive = tquic_gro_receive_udp;
	up->gro_complete = tquic_gro_complete_udp;

	/* Enable GRO for this socket */
	tquic_udp_tunnel_encap_enable(sk);

	tquic_dbg("GRO enabled for socket %p\n", sk);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_setup_gro);

/**
 * tquic_clear_gro - Disable GRO on a TQUIC socket
 * @sk: Socket to disable GRO on
 */
void tquic_clear_gro(struct sock *sk)
{
	struct udp_sock *up;

	if (!sk)
		return;

	up = udp_sk(sk);
	up->gro_receive = NULL;
	up->gro_complete = NULL;
}
EXPORT_SYMBOL_GPL(tquic_clear_gro);

/*
 * =============================================================================
 * Module Initialization / Cleanup
 * =============================================================================
 */

/**
 * tquic_offload_init - Initialize TQUIC offload support
 *
 * Registers GRO/GSO callbacks with the network stack. Called during
 * TQUIC module initialization.
 *
 * Returns: 0 on success, negative errno on failure
 */
int __init tquic_offload_init(void)
{
	tquic_info("initializing GRO/GSO offload support\n");

	/* Per-CPU stats are zero-initialized by DEFINE_PER_CPU */

	/*
	 * Note: TQUIC runs over UDP, so we leverage the existing UDP
	 * offload infrastructure rather than registering a new IP protocol.
	 * The GRO/GSO callbacks are set per-socket via tquic_setup_gro().
	 *
	 * For hardware offload support, device drivers can check for
	 * TQUIC-specific features and optimize accordingly.
	 */

	tquic_info("GRO/GSO offload support initialized\n");

	return 0;
}

/**
 * tquic_offload_exit - Cleanup TQUIC offload support
 *
 * Unregisters GRO/GSO callbacks. Called during TQUIC module cleanup.
 */
void __exit tquic_offload_exit(void)
{
	tquic_info("removing GRO/GSO offload support\n");

	/*
	 * Per-socket GRO callbacks are cleaned up when sockets close.
	 * No global cleanup needed for UDP-based offload.
	 */

	tquic_info("GRO/GSO offload support removed\n");
}

MODULE_DESCRIPTION("TQUIC GRO/GSO Offload Support");
MODULE_LICENSE("GPL");
