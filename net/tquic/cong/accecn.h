/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: Accurate ECN (AccECN) Feedback
 *
 * Copyright (c) 2026 Linux Foundation
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

/**
 * enum accecn_state - ECN capability state
 * @ACCECN_UNKNOWN: ECN support not determined
 * @ACCECN_TESTING: Testing ECN capability
 * @ACCECN_CAPABLE: Path supports ECN
 * @ACCECN_FAILED: ECN validation failed, disabled
 */
enum accecn_state {
	ACCECN_UNKNOWN = 0,
	ACCECN_TESTING,
	ACCECN_CAPABLE,
	ACCECN_FAILED,
};

/**
 * struct accecn_counts - ECN packet counts (cumulative)
 * @ect0: Packets received with ECT(0)
 * @ect1: Packets received with ECT(1)
 * @ce: Packets received with CE (Congestion Experienced)
 */
struct accecn_counts {
	u64 ect0;
	u64 ect1;
	u64 ce;
};

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

/**
 * struct accecn_ctx - Per-connection AccECN context
 * @state: ECN capability state
 * @local_counts: Our sent ECN packet counts
 * @peer_counts: Peer's reported ECN counts
 * @prev_peer_counts: Previous peer counts for delta calculation
 * @validation_needed: Packets needing ECN validation
 * @validated_ce: CE marks that passed validation
 * @bleaching_detected: ECN bleaching was detected
 * @mangling_detected: ECN mangling was detected
 * @send_ect0: Send with ECT(0) (classic)
 * @send_ect1: Send with ECT(1) (L4S)
 */
struct accecn_ctx {
	enum accecn_state state;
	struct accecn_counts local_counts;
	struct accecn_counts peer_counts;
	struct accecn_counts prev_peer_counts;
	u64 validation_needed;
	u64 validated_ce;
	bool bleaching_detected;
	bool mangling_detected;
	bool send_ect0;
	bool send_ect1;
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
