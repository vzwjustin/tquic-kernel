/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: Accurate ECN (AccECN) Feedback
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Implementation of Accurate ECN feedback for QUIC per RFC 9000.
 * QUIC's native ACK frame includes ECN counts, providing more
 * accurate feedback than TCP's limited ECN-Echo mechanism.
 *
 * This module processes ECN feedback from ACKs and provides
 * congestion signals to the congestion controller.
 */

#ifndef _TQUIC_ACCECN_H
#define _TQUIC_ACCECN_H

#include <linux/types.h>

/* ECN field in IP header */
#define ACCECN_NOT_ECT		0x00
#define ACCECN_ECT1		0x01	/* ECN-Capable Transport(1) - L4S */
#define ACCECN_ECT0		0x02	/* ECN-Capable Transport(0) - Classic */
#define ACCECN_CE		0x03	/* Congestion Experienced */

/* AccECN validation thresholds */
#define ACCECN_MAX_REORDER	3	/* Max ECN count reorder tolerance */

/*
 * Core AccECN types (enum accecn_state, struct accecn_counts,
 * struct accecn_ctx) are defined in <net/tquic.h> because
 * struct tquic_path embeds accecn_ctx directly.  The guard
 * _TQUIC_ACCECN_CTX_DEFINED prevents double-definition.
 */
#include <net/tquic.h>

/**
 * struct accecn_deltas - ECN count changes since last ACK
 * @delta_ect0: Change in ECT(0) count
 * @delta_ect1: Change in ECT(1) count
 * @delta_ce: Change in CE count
 * @newly_acked: Newly acknowledged packets
 */
struct accecn_deltas {
	u64 delta_ect0;
	u64 delta_ect1;
	u64 delta_ce;
	u64 newly_acked;
};

/* Initialization */
void accecn_init(struct accecn_ctx *ctx);
void accecn_reset(struct accecn_ctx *ctx);

/* ECN marking for outgoing packets */
u8 accecn_get_send_ecn(struct accecn_ctx *ctx);
void accecn_on_packet_sent(struct accecn_ctx *ctx, u8 ecn);

/* Processing incoming ECN feedback */
int accecn_on_ack_received(struct accecn_ctx *ctx,
			   u64 ect0_count, u64 ect1_count, u64 ce_count,
			   u64 acked_packets,
			   struct accecn_deltas *deltas);

/* ECN validation */
void accecn_validate(struct accecn_ctx *ctx);
bool accecn_is_capable(struct accecn_ctx *ctx);

/* State queries */
u64 accecn_get_ce_count(struct accecn_ctx *ctx);
bool accecn_bleaching_detected(struct accecn_ctx *ctx);

#endif /* _TQUIC_ACCECN_H */
