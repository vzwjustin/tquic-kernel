// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * TQUIC ECN (Explicit Congestion Notification) Implementation
 *
 * Per RFC 9000 Section 13.4 - ECN allows routers to signal congestion
 * without dropping packets by marking the ECN field in the IP header.
 *
 * Flow:
 * 1. Sender marks packets with ECT(0) or ECT(1) in IP header
 * 2. Congested router changes ECT to CE (Congestion Experienced)
 * 3. Receiver reports ECN counts in ACK_ECN frames (frame type 0x03)
 * 4. Sender uses feedback to reduce sending rate
 *
 * Copyright (c) 2024-2026 Linux QUIC Authors
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/if_ether.h>
#include <net/tquic.h>
#include <net/inet_ecn.h>

/* Forward declaration for ack.h types */
#include "ack.h"

/*
 * ECN codepoint values from IP header (RFC 3168)
 * These are the 2-bit values in the IP TOS/Traffic Class field
 */
#define ECN_NOT_ECT	0x00	/* Not ECN-Capable Transport */
#define ECN_ECT_1	0x01	/* ECN Capable Transport(1) */
#define ECN_ECT_0	0x02	/* ECN Capable Transport(0) */
#define ECN_CE		0x03	/* Congestion Experienced */

/* ECN field mask in IP TOS byte */
#define ECN_MASK	0x03

/*
 * tquic_ecn_init - Initialize ECN state for a path
 * @path: The path to initialize
 *
 * Sets up ECN testing mode. QUIC endpoints should test ECN capability
 * by initially marking packets with ECT(0) and checking if the counts
 * are correctly reflected in ACK_ECN frames.
 */
void tquic_ecn_init(struct tquic_path *path)
{
	if (!path)
		return;

	memset(&path->ecn, 0, sizeof(path->ecn));

	/*
	 * Per RFC 9000 Section 13.4.2: ECN validation
	 * Start in testing mode, marking packets with ECT(0)
	 */
	path->ecn.ecn_testing = 1;
	path->ecn.ecn_marking = TQUIC_ECN_ECT_0;
}
EXPORT_SYMBOL(tquic_ecn_init);

/*
 * tquic_ecn_get_marking - Get ECN marking for outgoing packets
 * @path: The path being used
 *
 * Returns the ECN codepoint to use for marking outgoing packets,
 * or TQUIC_ECN_NOT_ECT if ECN is disabled or failed validation.
 */
u8 tquic_ecn_get_marking(struct tquic_path *path)
{
	if (!path)
		return TQUIC_ECN_NOT_ECT;

	/* Don't mark if ECN failed validation */
	if (path->ecn.ecn_failed)
		return TQUIC_ECN_NOT_ECT;

	/* Use configured marking if ECN is capable or testing */
	if (path->ecn.ecn_capable || path->ecn.ecn_testing)
		return path->ecn.ecn_marking;

	return TQUIC_ECN_NOT_ECT;
}
EXPORT_SYMBOL(tquic_ecn_get_marking);

/*
 * tquic_ecn_on_packet_sent - Track ECN-marked packet sent
 * @path: The path packet was sent on
 * @ecn_marking: The ECN marking used (ECT(0), ECT(1), or Not-ECT)
 *
 * Updates the count of ECN-marked packets sent on this path.
 * Called from output.c after marking a packet.
 */
void tquic_ecn_on_packet_sent(struct tquic_path *path, u8 ecn_marking)
{
	if (!path)
		return;

	switch (ecn_marking) {
	case TQUIC_ECN_ECT_0:
		path->ecn.ect0_sent++;
		break;
	case TQUIC_ECN_ECT_1:
		path->ecn.ect1_sent++;
		break;
	default:
		/* Not-ECT or CE (shouldn't happen for sent packets) */
		break;
	}
}
EXPORT_SYMBOL(tquic_ecn_on_packet_sent);

/*
 * tquic_ecn_validate_ack - Validate ECN counts from ACK_ECN frame
 * @path: The path to validate
 * @ack: ACK information containing ECN counts
 *
 * Per RFC 9000 Section 13.4.2.1: ECN validation ensures the path
 * correctly handles ECN. Validation fails if:
 * - ECN counts decrease
 * - Sum of ECN counts doesn't match packets sent
 * - CE count increases but no congestion event triggered
 *
 * Returns 0 if valid, -EINVAL if validation fails.
 */
int tquic_ecn_validate_ack(struct tquic_path *path, struct tquic_ack_frame *ack)
{
	u64 total_ect_sent;
	u64 total_ect_acked;
	u64 new_ce_count;

	if (!path || !ack)
		return -EINVAL;

	/* ECN already failed, nothing to validate */
	if (path->ecn.ecn_failed)
		return 0;

	/*
	 * Per RFC 9000 Section 13.4.2.1:
	 * ECN counts MUST NOT decrease
	 */
	if (ack->ecn.ect0 < path->ecn.ect0_acked ||
	    ack->ecn.ect1 < path->ecn.ect1_acked ||
	    ack->ecn.ce < path->ecn.ce_acked) {
		pr_debug("TQUIC: ECN validation failed: counts decreased\n");
		path->ecn.ecn_failed = 1;
		path->ecn.ecn_testing = 0;
		path->ecn.ecn_capable = 0;
		return -EINVAL;
	}

	/*
	 * Per RFC 9000 Section 13.4.2.1:
	 * The total increase in ECN-CE, ECT(0), and ECT(1) counts MUST
	 * be at least the number of newly acknowledged packets that were
	 * originally sent with an ECT codepoint.
	 */
	total_ect_sent = path->ecn.ect0_sent + path->ecn.ect1_sent;
	total_ect_acked = ack->ecn.ect0 + ack->ecn.ect1 + ack->ecn.ce;

	/*
	 * Allow some tolerance for reordering - the acked count should
	 * not exceed what we sent.
	 */
	if (total_ect_acked > total_ect_sent) {
		pr_debug("TQUIC: ECN validation failed: more acked than sent\n");
		path->ecn.ecn_failed = 1;
		path->ecn.ecn_testing = 0;
		path->ecn.ecn_capable = 0;
		return -EINVAL;
	}

	/* Calculate new CE packets reported */
	new_ce_count = ack->ecn.ce - path->ecn.ce_acked;

	/* Update stored counts */
	path->ecn.ect0_acked = ack->ecn.ect0;
	path->ecn.ect1_acked = ack->ecn.ect1;
	path->ecn.ce_acked = ack->ecn.ce;

	/*
	 * If we're in testing mode and received valid ECN feedback,
	 * mark the path as ECN capable.
	 */
	if (path->ecn.ecn_testing && total_ect_acked > 0) {
		path->ecn.ecn_validated = 1;
		path->ecn.ecn_capable = 1;
		path->ecn.ecn_testing = 0;
		pr_debug("TQUIC: ECN validation successful for path\n");
	}

	return new_ce_count > 0 ? new_ce_count : 0;
}
EXPORT_SYMBOL(tquic_ecn_validate_ack);

/*
 * tquic_ecn_process_ce - Process ECN-CE events from ACK
 * @conn: The TQUIC connection
 * @path: The path that received CE feedback
 * @ce_count: Number of new CE markings reported
 *
 * Called when ACK_ECN frame indicates new CE markings.
 * Triggers congestion control response.
 */
void tquic_ecn_process_ce(struct tquic_connection *conn,
			  struct tquic_path *path, u64 ce_count)
{
	if (!conn || !path || ce_count == 0)
		return;

	/*
	 * Per RFC 9000 Section 13.4.2:
	 * An increase in ECN-CE count indicates congestion.
	 * The sender MUST reduce its congestion window.
	 */
	pr_debug("TQUIC: ECN-CE received, count=%llu, triggering congestion\n",
		 ce_count);

	/*
	 * Trigger congestion control response via the tquic cong framework.
	 * tquic_cong_on_ecn() dispatches to the path's CC algorithm
	 * which will reduce the congestion window appropriately.
	 */
	if (path->cong_ops && path->cong_ops->on_ecn)
		path->cong_ops->on_ecn(path->cong, ce_count);
}
EXPORT_SYMBOL(tquic_ecn_process_ce);

/*
 * tquic_ecn_mark_packet - Set ECN bits in IP header
 * @skb: The packet buffer
 * @ecn_marking: ECN codepoint to set (ECT(0), ECT(1), or Not-ECT)
 *
 * Sets the ECN field in the IP/IPv6 header.
 * Returns 0 on success, negative error on failure.
 */
int tquic_ecn_mark_packet(struct sk_buff *skb, u8 ecn_marking)
{
	struct iphdr *iph;
	struct ipv6hdr *ip6h;
	u8 old_tos, new_tos;

	if (!skb)
		return -EINVAL;

	/* Only mark with ECT codepoints, not CE */
	if (ecn_marking != TQUIC_ECN_ECT_0 && ecn_marking != TQUIC_ECN_ECT_1)
		return 0;

	if (skb->protocol == htons(ETH_P_IP)) {
		if (skb->len < sizeof(struct iphdr))
			return -EINVAL;

		iph = ip_hdr(skb);
		old_tos = iph->tos;
		new_tos = (old_tos & ~ECN_MASK) | ecn_marking;

		if (old_tos != new_tos) {
			/* Update checksum for TOS change */
			csum_replace2(&iph->check, htons(old_tos),
				      htons(new_tos));
			iph->tos = new_tos;
		}
	} else if (skb->protocol == htons(ETH_P_IPV6)) {
		if (skb->len < sizeof(struct ipv6hdr))
			return -EINVAL;

		ip6h = ipv6_hdr(skb);

		/*
		 * IPv6 traffic class is in the first 4 bits of flow_lbl[0]
		 * combined with the version/priority field.
		 * Format: version(4) + traffic_class(8) + flow_label(20)
		 */
		new_tos = ipv6_get_dsfield(ip6h);
		new_tos = (new_tos & ~ECN_MASK) | ecn_marking;
		ipv6_change_dsfield(ip6h, ~ECN_MASK, ecn_marking);
	} else {
		return -EPROTONOSUPPORT;
	}

	return 0;
}
EXPORT_SYMBOL(tquic_ecn_mark_packet);

/*
 * tquic_ecn_read_marking - Read ECN field from received packet
 * @skb: The received packet buffer
 *
 * Extracts the ECN codepoint from the IP header.
 * Returns ECN codepoint (0-3) or 0 on error.
 */
u8 tquic_ecn_read_marking(struct sk_buff *skb)
{
	struct iphdr *iph;
	struct ipv6hdr *ip6h;

	if (!skb)
		return TQUIC_ECN_NOT_ECT;

	if (skb->protocol == htons(ETH_P_IP)) {
		if (skb->len < sizeof(struct iphdr))
			return TQUIC_ECN_NOT_ECT;

		iph = ip_hdr(skb);
		return iph->tos & ECN_MASK;
	} else if (skb->protocol == htons(ETH_P_IPV6)) {
		if (skb->len < sizeof(struct ipv6hdr))
			return TQUIC_ECN_NOT_ECT;

		ip6h = ipv6_hdr(skb);
		return ipv6_get_dsfield(ip6h) & ECN_MASK;
	}

	return TQUIC_ECN_NOT_ECT;
}
EXPORT_SYMBOL(tquic_ecn_read_marking);

/*
 * tquic_ecn_disable - Disable ECN for a path
 * @path: The path to disable ECN on
 *
 * Called when ECN validation fails or when explicitly disabled.
 */
void tquic_ecn_disable(struct tquic_path *path)
{
	if (!path)
		return;

	path->ecn.ecn_failed = 1;
	path->ecn.ecn_capable = 0;
	path->ecn.ecn_testing = 0;
	path->ecn.ecn_marking = TQUIC_ECN_NOT_ECT;

	pr_debug("TQUIC: ECN disabled for path\n");
}
EXPORT_SYMBOL(tquic_ecn_disable);

/*
 * tquic_ecn_is_capable - Check if path is ECN capable
 * @path: The path to check
 *
 * Returns true if the path has successfully validated ECN.
 */
bool tquic_ecn_is_capable(struct tquic_path *path)
{
	if (!path)
		return false;

	return path->ecn.ecn_capable && !path->ecn.ecn_failed;
}
EXPORT_SYMBOL(tquic_ecn_is_capable);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux QUIC Authors");
MODULE_DESCRIPTION("TQUIC ECN (Explicit Congestion Notification) Implementation");
