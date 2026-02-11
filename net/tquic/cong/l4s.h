/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: L4S (Low Latency Low Loss Scalable) Support
 *
 * Copyright (c) 2026 Linux Foundation
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Implementation of L4S ECN marking and detection per RFC 9330/9331.
 */

#ifndef _TQUIC_L4S_H
#define _TQUIC_L4S_H

#include <linux/types.h>
#include <linux/skbuff.h>

/* ECN codepoints */
#define TQUIC_ECN_NOT_ECT	0x00
#define TQUIC_ECN_ECT1		0x01	/* L4S-capable traffic */
#define TQUIC_ECN_ECT0		0x02	/* Classic ECN */
#define TQUIC_ECN_CE		0x03	/* Congestion Experienced */

/*
 * L4S detection thresholds.
 *
 * CE threshold must be high enough that an attacker cannot easily forge
 * enough CE marks to force L4S mode. Require multiple CE marks across
 * multiple probe rounds.
 */
#define TQUIC_L4S_CE_THRESHOLD		10	/* CE marks to detect L4S AQM */
#define TQUIC_L4S_CLASSIC_THRESHOLD	5	/* Loss events to detect classic */

/**
 * enum tquic_l4s_state - L4S path state
 * @TQUIC_L4S_UNKNOWN: L4S support not yet determined
 * @TQUIC_L4S_PROBING: Probing for L4S support
 * @TQUIC_L4S_ENABLED: L4S AQM detected, using ECT(1)
 * @TQUIC_L4S_DISABLED: Classic AQM or no ECN, using ECT(0)
 */
enum tquic_l4s_state {
	TQUIC_L4S_UNKNOWN = 0,
	TQUIC_L4S_PROBING,
	TQUIC_L4S_ENABLED,
	TQUIC_L4S_DISABLED,
};

/**
 * struct tquic_l4s_stats - L4S statistics
 * @ect0_sent: Packets sent with ECT(0)
 * @ect1_sent: Packets sent with ECT(1)
 * @ect0_recv: Packets received with ECT(0)
 * @ect1_recv: Packets received with ECT(1)
 * @ce_recv: CE marks received
 * @ce_responded: CE marks we responded to
 */
struct tquic_l4s_stats {
	u64 ect0_sent;
	u64 ect1_sent;
	u64 ect0_recv;
	u64 ect1_recv;
	u64 ce_recv;
	u64 ce_responded;
};

/**
 * struct tquic_l4s_ctx - Per-path L4S context
 * @state: Current L4S detection state
 * @enabled: L4S marking enabled by user
 * @capable: Path appears L4S-capable
 * @ce_count: CE marks in current detection window
 * @loss_count: Losses in current detection window
 * @probe_round: Current probing round
 * @alpha: EWMA of CE fraction (scaled by 1024)
 * @stats: L4S statistics
 */
struct tquic_l4s_ctx {
	enum tquic_l4s_state state;
	bool enabled;
	bool capable;
	u32 ce_count;
	u32 loss_count;
	u32 probe_round;
	u32 alpha;
	struct tquic_l4s_stats stats;
};

/* Initialization and cleanup */
void tquic_l4s_init(struct tquic_l4s_ctx *ctx);
void tquic_l4s_enable(struct tquic_l4s_ctx *ctx, bool enable);

/* Packet marking */
u8 tquic_l4s_get_ecn_codepoint(struct tquic_l4s_ctx *ctx);
int tquic_l4s_mark_skb(struct tquic_l4s_ctx *ctx, struct sk_buff *skb);

/* ECN feedback processing */
void tquic_l4s_on_ack(struct tquic_l4s_ctx *ctx,
		      u64 ect0_count, u64 ect1_count, u64 ce_count);
void tquic_l4s_on_loss(struct tquic_l4s_ctx *ctx, u32 packets_lost);

/* State queries */
bool tquic_l4s_is_enabled(struct tquic_l4s_ctx *ctx);
bool tquic_l4s_is_capable(struct tquic_l4s_ctx *ctx);
u32 tquic_l4s_get_alpha(struct tquic_l4s_ctx *ctx);

/* Detection */
void tquic_l4s_detect(struct tquic_l4s_ctx *ctx);

#endif /* _TQUIC_L4S_H */
