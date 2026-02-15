// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: L4S (Low Latency Low Loss Scalable) Support
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Implementation of L4S ECN marking and detection per RFC 9330/9331.
 * Provides automatic detection of L4S-capable paths and appropriate
 * ECN codepoint selection (ECT(1) for L4S, ECT(0) for classic).
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/inet_ecn.h>

#include "l4s.h"
#include "../tquic_debug.h"

/* ECN mask - 2 bits for ECN codepoint in TOS/DSCP field */
#ifndef INET_ECN_MASK
#define INET_ECN_MASK	0x03
#endif

/* Alpha EWMA smoothing factor (1/16 = 6.25%) */
#define TQUIC_L4S_ALPHA_SHIFT		4
#define TQUIC_L4S_ALPHA_SCALE		1024

/* Probing parameters */
#define TQUIC_L4S_PROBE_ROUNDS		3
#define TQUIC_L4S_PROBE_PACKETS		100

/**
 * tquic_l4s_init - Initialize L4S context
 * @ctx: L4S context to initialize
 *
 * Initializes the L4S context to unknown state with detection disabled.
 */
void tquic_l4s_init(struct tquic_l4s_ctx *ctx)
{
	if (!ctx)
		return;

	memset(ctx, 0, sizeof(*ctx));
	ctx->state = TQUIC_L4S_UNKNOWN;
	ctx->enabled = false;
	ctx->capable = false;
	ctx->alpha = 0;
}
EXPORT_SYMBOL_GPL(tquic_l4s_init);

/**
 * tquic_l4s_enable - Enable or disable L4S marking
 * @ctx: L4S context
 * @enable: Whether to enable L4S
 *
 * When enabled, starts probing for L4S support on the path.
 */
void tquic_l4s_enable(struct tquic_l4s_ctx *ctx, bool enable)
{
	if (!ctx)
		return;

	ctx->enabled = enable;

	if (enable && ctx->state == TQUIC_L4S_UNKNOWN) {
		/* Start probing for L4S support */
		ctx->state = TQUIC_L4S_PROBING;
		ctx->probe_round = 0;
		ctx->ce_count = 0;
		ctx->loss_count = 0;
	} else if (!enable) {
		ctx->state = TQUIC_L4S_DISABLED;
		ctx->capable = false;
	}
}
EXPORT_SYMBOL_GPL(tquic_l4s_enable);

/**
 * tquic_l4s_get_ecn_codepoint - Get ECN codepoint for outgoing packet
 * @ctx: L4S context
 *
 * Returns the appropriate ECN codepoint based on current L4S state:
 * - ECT(1) if L4S is enabled and path is capable
 * - ECT(0) if L4S is disabled or path is not capable
 * - ECT(1) during probing to test L4S support
 *
 * Return: ECN codepoint (0-3)
 */
u8 tquic_l4s_get_ecn_codepoint(struct tquic_l4s_ctx *ctx)
{
	if (!ctx || !ctx->enabled)
		return TQUIC_ECN_ECT0;

	switch (ctx->state) {
	case TQUIC_L4S_ENABLED:
		return TQUIC_ECN_ECT1;

	case TQUIC_L4S_PROBING:
		/* Use ECT(1) during probing to detect L4S AQM */
		return TQUIC_ECN_ECT1;

	case TQUIC_L4S_DISABLED:
	case TQUIC_L4S_UNKNOWN:
	default:
		return TQUIC_ECN_ECT0;
	}
}
EXPORT_SYMBOL_GPL(tquic_l4s_get_ecn_codepoint);

/**
 * tquic_l4s_mark_skb - Mark sk_buff with appropriate ECN codepoint
 * @ctx: L4S context
 * @skb: Socket buffer to mark
 *
 * Sets the ECN bits in the IP header based on L4S state.
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_l4s_mark_skb(struct tquic_l4s_ctx *ctx, struct sk_buff *skb)
{
	u8 ecn;
	struct iphdr *iph;
	struct ipv6hdr *ip6h;

	if (!ctx || !skb)
		return -EINVAL;

	ecn = tquic_l4s_get_ecn_codepoint(ctx);

	/* Update statistics */
	if (ecn == TQUIC_ECN_ECT1)
		ctx->stats.ect1_sent++;
	else if (ecn == TQUIC_ECN_ECT0)
		ctx->stats.ect0_sent++;

	/* Mark the packet */
	switch (skb->protocol) {
	case htons(ETH_P_IP):
		iph = ip_hdr(skb);
		if (iph) {
			/* Clear existing ECN bits and set new ones */
			iph->tos = (iph->tos & ~INET_ECN_MASK) | ecn;
			/* Recalculate checksum */
			ip_send_check(iph);
		}
		break;

	case htons(ETH_P_IPV6):
		ip6h = ipv6_hdr(skb);
		if (ip6h) {
			/* IPv6 traffic class contains ECN in low 2 bits */
			u32 flow = ntohl(*(__be32 *)ip6h);
			flow = (flow & ~(INET_ECN_MASK << 20)) | (ecn << 20);
			*(__be32 *)ip6h = htonl(flow);
		}
		break;

	default:
		return -EPROTONOSUPPORT;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_l4s_mark_skb);

/**
 * tquic_l4s_update_alpha - Update EWMA of CE fraction
 * @ctx: L4S context
 * @ce_fraction: Current CE fraction (scaled by ALPHA_SCALE)
 *
 * Updates the exponentially weighted moving average of the CE fraction
 * using the formula: alpha = (1 - g) * alpha + g * ce_fraction
 * where g = 1/16 for smooth adaptation.
 */
static void tquic_l4s_update_alpha(struct tquic_l4s_ctx *ctx, u32 ce_fraction)
{
	/* EWMA: alpha = alpha - (alpha >> 4) + (ce_fraction >> 4) */
	ctx->alpha = ctx->alpha - (ctx->alpha >> TQUIC_L4S_ALPHA_SHIFT) +
		     (ce_fraction >> TQUIC_L4S_ALPHA_SHIFT);

	/* Clamp to valid range */
	if (ctx->alpha > TQUIC_L4S_ALPHA_SCALE)
		ctx->alpha = TQUIC_L4S_ALPHA_SCALE;
}

/**
 * tquic_l4s_on_ack - Process ECN feedback from ACK
 * @ctx: L4S context
 * @ect0_count: Cumulative ECT(0) count from peer
 * @ect1_count: Cumulative ECT(1) count from peer
 * @ce_count: Cumulative CE count from peer
 *
 * Processes ECN feedback to detect L4S support and update congestion state.
 */
void tquic_l4s_on_ack(struct tquic_l4s_ctx *ctx,
		      u64 ect0_count, u64 ect1_count, u64 ce_count)
{
	u64 delta_ce;
	u64 delta_ect1;
	u32 ce_fraction;

	if (!ctx)
		return;

	/*
	 * Calculate deltas from previous counts using signed arithmetic
	 * to correctly detect decreases from peer bugs or attacks.
	 */
	if (ce_count < ctx->stats.ce_recv ||
	    ect1_count < ctx->stats.ect1_recv) {
		/* Counts decreased -- ignore this feedback */
		tquic_dbg("l4s: ECN count decreased, ignoring feedback\n");
		return;
	}

	delta_ce = ce_count - ctx->stats.ce_recv;
	delta_ect1 = ect1_count - ctx->stats.ect1_recv;

	/* Update statistics */
	ctx->stats.ect0_recv = ect0_count;
	ctx->stats.ect1_recv = ect1_count;
	ctx->stats.ce_recv = ce_count;

	if (delta_ce > 0) {
		ctx->ce_count += delta_ce;
		ctx->stats.ce_responded += delta_ce;

		/* Calculate CE fraction for alpha update */
		if (delta_ect1 + delta_ce > 0) {
			ce_fraction = (u32)div64_u64(
				delta_ce * TQUIC_L4S_ALPHA_SCALE,
				delta_ect1 + delta_ce);
			tquic_l4s_update_alpha(ctx, ce_fraction);
		}
	}

	/* Run detection state machine */
	tquic_l4s_detect(ctx);
}
EXPORT_SYMBOL_GPL(tquic_l4s_on_ack);

/**
 * tquic_l4s_on_loss - Process packet loss event
 * @ctx: L4S context
 * @packets_lost: Number of packets detected as lost
 *
 * Packet loss suggests classic AQM or congestion without ECN marking.
 */
void tquic_l4s_on_loss(struct tquic_l4s_ctx *ctx, u32 packets_lost)
{
	if (!ctx || packets_lost == 0)
		return;

	ctx->loss_count += packets_lost;

	/* Run detection state machine */
	tquic_l4s_detect(ctx);
}
EXPORT_SYMBOL_GPL(tquic_l4s_on_loss);

/**
 * tquic_l4s_detect - Run L4S detection state machine
 * @ctx: L4S context
 *
 * Determines whether the path supports L4S based on observed ECN marks
 * and packet losses. L4S AQMs typically:
 * - Mark packets with CE frequently and at low queue depths
 * - Rarely drop packets
 *
 * Classic AQMs typically:
 * - Drop packets more frequently
 * - Mark CE less frequently or not at all
 */
void tquic_l4s_detect(struct tquic_l4s_ctx *ctx)
{
	if (!ctx || !ctx->enabled)
		return;

	switch (ctx->state) {
	case TQUIC_L4S_PROBING:
		/* Check if we've received enough CE marks to confirm L4S */
		if (ctx->ce_count >= TQUIC_L4S_CE_THRESHOLD) {
			ctx->state = TQUIC_L4S_ENABLED;
			ctx->capable = true;
			tquic_info("l4s: L4S detected on path\n");
			return;
		}

		/* Check if we've seen too many losses (classic AQM) */
		if (ctx->loss_count >= TQUIC_L4S_CLASSIC_THRESHOLD) {
			ctx->state = TQUIC_L4S_DISABLED;
			ctx->capable = false;
			tquic_info("l4s: classic AQM detected, disabling L4S\n");
			return;
		}

		/* Advance probe round if we've sent enough packets */
		if (ctx->stats.ect1_sent > 0 &&
		    ctx->stats.ect1_sent % TQUIC_L4S_PROBE_PACKETS == 0) {
			ctx->probe_round++;

			if (ctx->probe_round >= TQUIC_L4S_PROBE_ROUNDS) {
				/* Probing complete without conclusive results */
				if (ctx->ce_count > 0) {
					/* Some CE marks seen, assume L4S */
					ctx->state = TQUIC_L4S_ENABLED;
					ctx->capable = true;
				} else {
					/* No CE marks, fall back to classic */
					ctx->state = TQUIC_L4S_DISABLED;
					ctx->capable = false;
				}
			}
		}
		break;

	case TQUIC_L4S_ENABLED:
		/*
		 * Monitor for path changes - excessive loss suggests change.
		 * Use a window-based approach: only count losses since the
		 * last successful L4S period to avoid accumulation over time.
		 * Reset loss_count periodically after confirming L4S is stable.
		 */
		if (ctx->loss_count >= TQUIC_L4S_CLASSIC_THRESHOLD * 2) {
			/* Path may have changed, restart probing */
			ctx->state = TQUIC_L4S_PROBING;
			ctx->probe_round = 0;
			ctx->ce_count = 0;
			ctx->loss_count = 0;
			tquic_info("l4s: path change detected, reprobing L4S\n");
		} else if (ctx->ce_count > TQUIC_L4S_CE_THRESHOLD * 2) {
			/*
			 * Sufficient CE marks confirm L4S is still active.
			 * Reset counters to prevent accumulation-based
			 * false reprobing.
			 */
			ctx->ce_count = 0;
			ctx->loss_count = 0;
		}
		break;

	case TQUIC_L4S_DISABLED:
		/* Could add logic to periodically re-probe */
		break;

	case TQUIC_L4S_UNKNOWN:
	default:
		break;
	}
}
EXPORT_SYMBOL_GPL(tquic_l4s_detect);

/**
 * tquic_l4s_is_enabled - Check if L4S marking is enabled
 * @ctx: L4S context
 *
 * Return: true if L4S is enabled by user
 */
bool tquic_l4s_is_enabled(struct tquic_l4s_ctx *ctx)
{
	return ctx && ctx->enabled;
}
EXPORT_SYMBOL_GPL(tquic_l4s_is_enabled);

/**
 * tquic_l4s_is_capable - Check if path is L4S-capable
 * @ctx: L4S context
 *
 * Return: true if path has been detected as L4S-capable
 */
bool tquic_l4s_is_capable(struct tquic_l4s_ctx *ctx)
{
	return ctx && ctx->capable;
}
EXPORT_SYMBOL_GPL(tquic_l4s_is_capable);

/**
 * tquic_l4s_get_alpha - Get current CE fraction estimate
 * @ctx: L4S context
 *
 * Return: Alpha value scaled by 1024 (0 = no congestion, 1024 = 100%)
 */
u32 tquic_l4s_get_alpha(struct tquic_l4s_ctx *ctx)
{
	if (!ctx)
		return 0;

	return ctx->alpha;
}
EXPORT_SYMBOL_GPL(tquic_l4s_get_alpha);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TQUIC L4S Support");
MODULE_AUTHOR("Linux Foundation");
