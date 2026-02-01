// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Accurate ECN (AccECN) Feedback
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Processes QUIC's ECN feedback to provide accurate congestion signals.
 * QUIC ACK frames include cumulative ECN counts (ECT(0), ECT(1), CE),
 * enabling precise detection of congestion marking unlike TCP's binary
 * ECN-Echo mechanism.
 *
 * Features:
 * - ECN capability validation during connection setup
 * - Bleaching and mangling detection
 * - Delta calculation for per-ACK congestion response
 * - L4S support via ECT(1) codepoint selection
 */

#include <linux/kernel.h>
#include <linux/module.h>

#include "accecn.h"

/**
 * accecn_init - Initialize AccECN context
 * @ctx: Context to initialize
 */
void accecn_init(struct accecn_ctx *ctx)
{
	if (!ctx)
		return;

	memset(ctx, 0, sizeof(*ctx));
	ctx->state = ACCECN_UNKNOWN;
	ctx->send_ect0 = true;	/* Start with classic ECN */
	ctx->send_ect1 = false;
}
EXPORT_SYMBOL_GPL(accecn_init);

/**
 * accecn_reset - Reset AccECN context
 * @ctx: Context to reset
 *
 * Resets state while preserving capability detection result.
 */
void accecn_reset(struct accecn_ctx *ctx)
{
	enum accecn_state saved_state;

	if (!ctx)
		return;

	saved_state = ctx->state;
	memset(&ctx->local_counts, 0, sizeof(ctx->local_counts));
	memset(&ctx->peer_counts, 0, sizeof(ctx->peer_counts));
	memset(&ctx->prev_peer_counts, 0, sizeof(ctx->prev_peer_counts));
	ctx->validation_needed = 0;
	ctx->validated_ce = 0;

	/* Preserve capability state unless failed */
	if (saved_state == ACCECN_FAILED)
		ctx->state = ACCECN_FAILED;
}
EXPORT_SYMBOL_GPL(accecn_reset);

/**
 * accecn_get_send_ecn - Get ECN codepoint for outgoing packet
 * @ctx: AccECN context
 *
 * Returns the ECN codepoint to set in outgoing IP packets.
 * Uses ECT(1) if L4S is enabled and supported, otherwise ECT(0).
 *
 * Return: ECN codepoint (ACCECN_ECT0, ACCECN_ECT1, or ACCECN_NOT_ECT)
 */
u8 accecn_get_send_ecn(struct accecn_ctx *ctx)
{
	if (!ctx)
		return ACCECN_NOT_ECT;

	/* Don't mark if ECN failed validation */
	if (ctx->state == ACCECN_FAILED)
		return ACCECN_NOT_ECT;

	/* Use ECT(1) for L4S if enabled */
	if (ctx->send_ect1)
		return ACCECN_ECT1;

	/* Use ECT(0) for classic ECN */
	if (ctx->send_ect0)
		return ACCECN_ECT0;

	return ACCECN_NOT_ECT;
}
EXPORT_SYMBOL_GPL(accecn_get_send_ecn);

/**
 * accecn_on_packet_sent - Track ECN marking of sent packet
 * @ctx: AccECN context
 * @ecn: ECN codepoint used (from IP header)
 *
 * Updates local counters to track what we've sent for validation.
 */
void accecn_on_packet_sent(struct accecn_ctx *ctx, u8 ecn)
{
	if (!ctx)
		return;

	switch (ecn & 0x03) {
	case ACCECN_ECT0:
		ctx->local_counts.ect0++;
		break;
	case ACCECN_ECT1:
		ctx->local_counts.ect1++;
		break;
	case ACCECN_CE:
		/* We should never send CE-marked packets */
		ctx->local_counts.ce++;
		break;
	case ACCECN_NOT_ECT:
	default:
		break;
	}

	/* Track for validation during testing phase */
	if (ctx->state == ACCECN_TESTING)
		ctx->validation_needed++;
}
EXPORT_SYMBOL_GPL(accecn_on_packet_sent);

/**
 * accecn_on_ack_received - Process ECN feedback from ACK
 * @ctx: AccECN context
 * @ect0_count: Peer's cumulative ECT(0) count
 * @ect1_count: Peer's cumulative ECT(1) count
 * @ce_count: Peer's cumulative CE count
 * @acked_packets: Number of newly acknowledged packets
 * @deltas: Output structure for ECN count changes
 *
 * Processes the ECN counts from an ACK frame and calculates
 * the delta (change) since the last ACK. These deltas are used
 * by the congestion controller for proportional response.
 *
 * Return: 0 on success, negative error code on validation failure
 */
int accecn_on_ack_received(struct accecn_ctx *ctx,
			   u64 ect0_count, u64 ect1_count, u64 ce_count,
			   u64 acked_packets,
			   struct accecn_deltas *deltas)
{
	u64 total_delta;
	u64 reported_total;

	if (!ctx || !deltas)
		return -EINVAL;

	/* Calculate deltas from previous counts */
	deltas->delta_ect0 = ect0_count - ctx->peer_counts.ect0;
	deltas->delta_ect1 = ect1_count - ctx->peer_counts.ect1;
	deltas->delta_ce = ce_count - ctx->peer_counts.ce;
	deltas->newly_acked = acked_packets;

	/* Detect count decreases (shouldn't happen - cumulative) */
	if ((s64)deltas->delta_ect0 < 0 ||
	    (s64)deltas->delta_ect1 < 0 ||
	    (s64)deltas->delta_ce < 0) {
		pr_debug("accecn: ECN count decreased - possible attack or bug\n");
		/* Could be packet reordering, allow small decreases */
		if ((s64)deltas->delta_ect0 < -ACCECN_MAX_REORDER ||
		    (s64)deltas->delta_ect1 < -ACCECN_MAX_REORDER ||
		    (s64)deltas->delta_ce < -ACCECN_MAX_REORDER) {
			return -EINVAL;
		}
		/* Clamp to zero */
		deltas->delta_ect0 = max((s64)deltas->delta_ect0, 0LL);
		deltas->delta_ect1 = max((s64)deltas->delta_ect1, 0LL);
		deltas->delta_ce = max((s64)deltas->delta_ce, 0LL);
	}

	/* Validate ECN counts */
	total_delta = deltas->delta_ect0 + deltas->delta_ect1 + deltas->delta_ce;
	reported_total = ect0_count + ect1_count + ce_count;

	/* Check for bleaching (ECN stripped by middlebox) */
	if (ctx->state == ACCECN_TESTING || ctx->state == ACCECN_CAPABLE) {
		u64 sent_ecn = ctx->local_counts.ect0 + ctx->local_counts.ect1;

		/* If we sent ECN-marked packets but peer reports fewer */
		if (sent_ecn > 0 && reported_total == 0 && acked_packets > 0) {
			ctx->bleaching_detected = true;
			pr_debug("accecn: ECN bleaching detected\n");
		}

		/* If we sent ECT(0) but peer reports ECT(1) or vice versa */
		if (ctx->local_counts.ect0 > 0 && ect0_count == 0 &&
		    ect1_count > ctx->prev_peer_counts.ect1) {
			ctx->mangling_detected = true;
			pr_debug("accecn: ECN mangling detected (ECT0->ECT1)\n");
		}
	}

	/* Save current counts for next delta calculation */
	ctx->prev_peer_counts = ctx->peer_counts;
	ctx->peer_counts.ect0 = ect0_count;
	ctx->peer_counts.ect1 = ect1_count;
	ctx->peer_counts.ce = ce_count;

	/* Track validated CE marks */
	ctx->validated_ce += deltas->delta_ce;

	return 0;
}
EXPORT_SYMBOL_GPL(accecn_on_ack_received);

/**
 * accecn_validate - Validate ECN capability
 * @ctx: AccECN context
 *
 * Called after testing phase to determine if ECN works on this path.
 * Checks for bleaching, mangling, and correct reflection of marks.
 */
void accecn_validate(struct accecn_ctx *ctx)
{
	u64 sent_marked;
	u64 recv_marked;

	if (!ctx)
		return;

	if (ctx->state != ACCECN_TESTING)
		return;

	sent_marked = ctx->local_counts.ect0 + ctx->local_counts.ect1;
	recv_marked = ctx->peer_counts.ect0 + ctx->peer_counts.ect1 +
		      ctx->peer_counts.ce;

	/* Check validation criteria */
	if (ctx->bleaching_detected || ctx->mangling_detected) {
		/* ECN path broken - disable */
		ctx->state = ACCECN_FAILED;
		ctx->send_ect0 = false;
		ctx->send_ect1 = false;
		pr_debug("accecn: ECN validation failed\n");
		return;
	}

	/* Allow some tolerance for in-flight packets */
	if (sent_marked > 0 && recv_marked >= sent_marked / 2) {
		/* ECN working correctly */
		ctx->state = ACCECN_CAPABLE;
		pr_debug("accecn: ECN validated successfully\n");
	} else if (ctx->validation_needed > 10 && recv_marked == 0) {
		/* Sent enough packets but no ECN feedback */
		ctx->state = ACCECN_FAILED;
		ctx->send_ect0 = false;
		ctx->send_ect1 = false;
		pr_debug("accecn: ECN validation failed - no feedback\n");
	}
	/* Otherwise keep testing */
}
EXPORT_SYMBOL_GPL(accecn_validate);

/**
 * accecn_is_capable - Check if ECN is supported
 * @ctx: AccECN context
 *
 * Return: true if path supports ECN
 */
bool accecn_is_capable(struct accecn_ctx *ctx)
{
	if (!ctx)
		return false;

	return ctx->state == ACCECN_CAPABLE;
}
EXPORT_SYMBOL_GPL(accecn_is_capable);

/**
 * accecn_get_ce_count - Get total validated CE marks
 * @ctx: AccECN context
 *
 * Return: Cumulative CE mark count
 */
u64 accecn_get_ce_count(struct accecn_ctx *ctx)
{
	if (!ctx)
		return 0;

	return ctx->validated_ce;
}
EXPORT_SYMBOL_GPL(accecn_get_ce_count);

/**
 * accecn_bleaching_detected - Check if bleaching was detected
 * @ctx: AccECN context
 *
 * Return: true if ECN bleaching was detected
 */
bool accecn_bleaching_detected(struct accecn_ctx *ctx)
{
	if (!ctx)
		return false;

	return ctx->bleaching_detected;
}
EXPORT_SYMBOL_GPL(accecn_bleaching_detected);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TQUIC Accurate ECN Feedback");
MODULE_AUTHOR("Linux Foundation");
