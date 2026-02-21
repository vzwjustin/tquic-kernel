/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: L4S (Low Latency Low Loss Scalable) Support
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
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

/*
 * L4S context types (enum tquic_l4s_state, struct tquic_l4s_stats,
 * struct tquic_l4s_ctx) are defined in <net/tquic.h> because
 * struct tquic_path embeds tquic_l4s_ctx directly.  The guard
 * _TQUIC_L4S_CTX_DEFINED prevents double-definition when both
 * headers are included.
 */
#include <net/tquic.h>

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
