// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Frame Processing
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 *
 * Frame-level state machine handlers. For wire-format parsing see core/frame.c.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/rhashtable.h>
#include <linux/random.h>
#include <linux/hrtimer.h>
#include <linux/overflow.h>
#include <linux/unaligned.h>
#include <net/sock.h>
#include <net/udp.h>
#include <net/udp_tunnel.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/gro.h>
#include <crypto/aead.h>
#include <net/tquic.h>
#include <net/tquic_frame.h>

#include "../tquic_compat.h"
#include "../tquic_debug.h"
#include "../tquic_mib.h"
#include "../protocol.h"
#include "../cong/tquic_cong.h"
#include "../crypto/tls.h"
#include "../crypto/key_update.h"
#include "../crypto/zero_rtt.h"
#include "../crypto/header_protection.h"
#include "../tquic_stateless_reset.h"
#include "../tquic_token.h"
#include "../tquic_retry.h"
#include "../tquic_ack_frequency.h"
#include "../tquic_ratelimit.h"
#include "../tquic_sysctl.h"
#include "../rate_limit.h"
#include "../security_hardening.h"
#include "../tquic_cid.h"
#include "flow_control.h"
#include "quic_loss.h"
#include "quic_path.h"
#include "ack.h"
#include "stream.h"
#include "frame_process.h"
#include <net/tquic_pm.h>
#include "../bond/tquic_reorder.h"
#include "../bond/tquic_bonding.h"

#ifdef CONFIG_TQUIC_FEC
#include "../fec/fec.h"
#endif

/* QUIC encryption level / packet type identifiers (RFC 9000 §17.2) */
#define TQUIC_PKT_INITIAL 0x00
#define TQUIC_PKT_ZERO_RTT 0x01
#define TQUIC_PKT_HANDSHAKE 0x02

/* Maximum ACK ranges to prevent resource exhaustion from malicious frames */
#define TQUIC_MAX_ACK_RANGES 256

/*
 * Conservative per-packet byte estimate for Initial/Handshake ACKs.
 * These spaces carry CRYPTO frames only; using MTU would wildly inflate
 * the bytes_acked value fed to congestion control.  ~300 bytes is a
 * realistic CRYPTO frame size (TLS ClientHello/ServerHello fragments).
 */
#define TQUIC_CRYPTO_FRAME_BYTES_EST 300ULL

/*
 * M-001: Maximum per-STREAM frame allocation limit.
 * Prevents a single frame from allocating multi-MB skbs.
 * 64KB is reasonable for packet-sized data but prevents abuse.
 */
#define TQUIC_MAX_STREAM_FRAME_ALLOC (64 * 1024)

/* QUIC frame types (must match tquic_output.c) */
#define TQUIC_FRAME_PADDING 0x00
#define TQUIC_FRAME_PING 0x01
#define TQUIC_FRAME_ACK 0x02
#define TQUIC_FRAME_ACK_ECN 0x03
#define TQUIC_FRAME_RESET_STREAM 0x04
#define TQUIC_FRAME_STOP_SENDING 0x05
#define TQUIC_FRAME_CRYPTO 0x06
#define TQUIC_FRAME_NEW_TOKEN 0x07
#define TQUIC_FRAME_STREAM 0x08 /* 0x08-0x0f */
#define TQUIC_FRAME_MAX_DATA 0x10
#define TQUIC_FRAME_MAX_STREAM_DATA 0x11
#define TQUIC_FRAME_MAX_STREAMS_BIDI 0x12
#define TQUIC_FRAME_MAX_STREAMS_UNI 0x13
#define TQUIC_FRAME_DATA_BLOCKED 0x14
#define TQUIC_FRAME_STREAM_DATA_BLOCKED 0x15
#define TQUIC_FRAME_STREAMS_BLOCKED_BIDI 0x16
#define TQUIC_FRAME_STREAMS_BLOCKED_UNI 0x17
#define TQUIC_FRAME_NEW_CONNECTION_ID 0x18
#define TQUIC_FRAME_RETIRE_CONNECTION_ID 0x19
#define TQUIC_FRAME_PATH_CHALLENGE 0x1a
#define TQUIC_FRAME_PATH_RESPONSE 0x1b
#define TQUIC_FRAME_CONNECTION_CLOSE 0x1c
#define TQUIC_FRAME_CONNECTION_CLOSE_APP 0x1d
#define TQUIC_FRAME_HANDSHAKE_DONE 0x1e
#define TQUIC_FRAME_DATAGRAM 0x30 /* 0x30-0x31 */
/* ACK frequency frame types defined in core/ack_frequency.h */

/*
 * =============================================================================
 * Frame Demultiplexing
 * =============================================================================
 */

/*
 * Process PADDING frame
 *
 * RFC 9000 Section 19.1: A PADDING frame has no semantic value and
 * can be used to increase the size of a packet. Limit the scan
 * to prevent CPU exhaustion on very large encrypted payloads.
 *
 * SECURITY: Limit padding to typical MTU size (1500 bytes).
 * Attackers could send excessive padding to waste CPU cycles.
 * We use memchr() for efficient scanning instead of byte-by-byte loop.
 */
#define TQUIC_MAX_PADDING_BYTES 1500

static int tquic_process_padding_frame(struct tquic_rx_ctx *ctx)
{
	u32 start = ctx->offset;
	u32 limit = min_t(u32, ctx->len, start + TQUIC_MAX_PADDING_BYTES);

	tquic_dbg("process_padding: offset=%u remaining=%zu\n", start,
		  ctx->len - start);

	/*
	 * Optimization: Scan padding bytes efficiently.
	 * While memchr() can't directly find non-zero bytes,
	 * we use a simple loop which is well-optimized by
	 * modern compilers and CPUs.
	 */
	while (ctx->offset < limit && ctx->data[ctx->offset] == 0)
		ctx->offset++;

	/*
	 * If we hit the limit and there's still padding, reject as
	 * excessive. Legitimate QUIC packets are at most ~1500 bytes
	 * (PMTU), not more.
	 *
	 * BOUNDS SAFETY: ctx->data[ctx->offset] is only evaluated when
	 * ctx->offset < ctx->len is true (short-circuit &&).  Do NOT
	 * reorder or split this condition — the array access MUST be
	 * guarded by the bounds check on the same line.
	 */
	if (ctx->offset >= limit && ctx->offset < ctx->len &&
	    ctx->data[ctx->offset] == 0)
		return -EINVAL;

	return 0;
}

/*
 * Process PING frame
 */
static int tquic_process_ping_frame(struct tquic_rx_ctx *ctx)
{
	tquic_dbg("process_ping: pkt_num=%llu\n", ctx->pkt_num);

	ctx->offset++; /* Skip frame type */
	ctx->ack_eliciting = true;

	return 0;
}

/*
 * Process ACK frame (0x02) or ACK_ECN frame (0x03)
 *
 * ACK frame format (RFC 9000 Section 19.3):
 *   Largest Acknowledged (varint)
 *   ACK Delay (varint)
 *   ACK Range Count (varint)
 *   First ACK Range (varint)
 *   [ACK Ranges...]
 *
 * ACK_ECN frame adds (RFC 9000 Section 19.3.2):
 *   ECT(0) Count (varint)
 *   ECT(1) Count (varint)
 *   ECN-CE Count (varint)
 */
static int tquic_process_ack_frame(struct tquic_rx_ctx *ctx)
{
	u64 largest_ack, ack_delay, ack_range_count, first_ack_range;
	u64 ecn_ect0 = 0, ecn_ect1 = 0, ecn_ce = 0;
	u64 total_acked_pkts = 0;
	struct tquic_ack_frame ack_frame;
	bool has_ecn;
	u8 frame_type;
	int ret;
	u64 i;

	frame_type = ctx->data[ctx->offset];
	has_ecn = (frame_type == TQUIC_FRAME_ACK_ECN);
	ctx->offset++; /* Skip frame type */

	/* Largest Acknowledged */
	ret = tquic_decode_varint(ctx->data + ctx->offset,
				  ctx->len - ctx->offset, &largest_ack);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	/* ACK Delay */
	ret = tquic_decode_varint(ctx->data + ctx->offset,
				  ctx->len - ctx->offset, &ack_delay);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	/* ACK Range Count */
	ret = tquic_decode_varint(ctx->data + ctx->offset,
				  ctx->len - ctx->offset, &ack_range_count);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	/* First ACK Range */
	ret = tquic_decode_varint(ctx->data + ctx->offset,
				  ctx->len - ctx->offset, &first_ack_range);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	/* Reject excessive ACK ranges to prevent resource exhaustion */
	if (ack_range_count > TQUIC_MAX_ACK_RANGES)
		return -EINVAL;

	/*
	 * CF-630: Validate largest_ack >= first_ack_range.
	 * Per RFC 9000 Section 19.3.1, the smallest acknowledged in the
	 * first range is largest_ack - first_ack_range. An underflow here
	 * would produce a bogus packet number.
	 */
	if (first_ack_range > largest_ack)
		return -EINVAL;

	/* Populate ack_frame for loss detection use below */
	memset(&ack_frame, 0, sizeof(ack_frame));
	ack_frame.largest_acked = largest_ack;
	ack_frame.ack_delay = ack_delay;
	ack_frame.first_range = first_ack_range;
	ack_frame.range_count =
		min_t(u32, ack_range_count, TQUIC_MAX_ACK_RANGES);
	ack_frame.has_ecn = has_ecn;

	/*
	 * Process additional ACK ranges and build ack_frame for loss
	 * detection.
	 *
	 * Track smallest_acked to validate that gap and range values
	 * do not underflow the running packet number. Per RFC 9000
	 * Section 19.3.1, each gap skips gap+2 packet numbers, and
	 * each range covers range+1 packet numbers.
	 *
	 * Also accumulate total_acked_pkts across ALL ranges (not just
	 * the first) so congestion control receives correct byte counts.
	 */
	{
		u64 smallest_acked = largest_ack - first_ack_range;
		u64 cumulative_gap = first_ack_range;

		/* Total packets acknowledged = first range + additional */
		total_acked_pkts = first_ack_range + 1;

		for (i = 0; i < ack_range_count; i++) {
			u64 gap, range;

			ret = tquic_decode_varint(ctx->data + ctx->offset,
						  ctx->len - ctx->offset, &gap);
			if (ret < 0)
				return ret;
			ctx->offset += ret;

			ret = tquic_decode_varint(ctx->data + ctx->offset,
						  ctx->len - ctx->offset,
						  &range);
			if (ret < 0)
				return ret;
			ctx->offset += ret;

			/* Validate gap does not underflow */
			if (gap + 2 > smallest_acked)
				return -EPROTO;

			/* Check cumulative overflow before updating */
			if (cumulative_gap > U64_MAX - (gap + 2))
				return -EPROTO;
			cumulative_gap += gap + 2;

			smallest_acked -= gap + 2;

			/* Validate range does not underflow */
			if (range > smallest_acked)
				return -EPROTO;

			/* Check cumulative overflow before updating */
			if (cumulative_gap > U64_MAX - range)
				return -EPROTO;
			cumulative_gap += range;

			smallest_acked -= range;

			/* Save range for loss detection ack_frame */
			if (i < TQUIC_MAX_ACK_RANGES) {
				ack_frame.ranges[i].gap = gap;
				ack_frame.ranges[i].length = range;
			}

			/* Accumulate acked packets from this range */
			total_acked_pkts += range + 1;
		}

		/* Final validation: cumulative must not exceed largest_ack */
		if (cumulative_gap > largest_ack)
			return -EPROTO;
	}

	/*
	 * ECN counts (ACK_ECN frame only)
	 *
	 * Per RFC 9000 Section 19.3.2:
	 * - ECT(0) Count: packets received with ECT(0) codepoint
	 * - ECT(1) Count: packets received with ECT(1) codepoint
	 * - ECN-CE Count: packets received with ECN-CE codepoint
	 *
	 * Per RFC 9002 Section 7.1:
	 * "Each increase in the ECN-CE counter is a signal of congestion."
	 *
	 * Per CONTEXT.md: "ECN support: available but off by default"
	 */
	if (has_ecn) {
		/* ECT(0) Count */
		ret = tquic_decode_varint(ctx->data + ctx->offset,
					  ctx->len - ctx->offset, &ecn_ect0);
		if (ret < 0)
			return ret;
		ctx->offset += ret;

		/* ECT(1) Count */
		ret = tquic_decode_varint(ctx->data + ctx->offset,
					  ctx->len - ctx->offset, &ecn_ect1);
		if (ret < 0)
			return ret;
		ctx->offset += ret;

		/* ECN-CE Count */
		ret = tquic_decode_varint(ctx->data + ctx->offset,
					  ctx->len - ctx->offset, &ecn_ce);
		if (ret < 0)
			return ret;
		ctx->offset += ret;

		/*
		 * Update MIB counters for ECN frames received.
		 *
		 * RFC 9000 Section 13.4.2.1: ECN counts are cumulative.
		 * They MUST NOT decrease; a decrease indicates a peer
		 * bug or attack and is treated as PROTOCOL_VIOLATION.
		 * Only the delta since the last ACK_ECN is added to MIB
		 * counters to avoid double-counting.
		 *
		 * SECURITY: Also validate that deltas are reasonable to
		 * prevent integer overflow attacks or resource exhaustion.
		 */
		if (ctx->conn && ctx->conn->sk && ctx->path) {
			struct net *net = sock_net(ctx->conn->sk);
			struct tquic_path *p = ctx->path;
			u64 ect0_delta, ect1_delta, ce_delta;

			/* Validate counters don't decrease */
			if (ecn_ect0 < p->ecn_ect0_count_prev ||
			    ecn_ect1 < p->ecn_ect1_count_prev ||
			    ecn_ce < p->ecn_ce_count_prev) {
				tquic_dbg(
					"ECN counts decreased: ect0 %llu->%llu ect1 %llu->%llu ce %llu->%llu\n",
					p->ecn_ect0_count_prev, ecn_ect0,
					p->ecn_ect1_count_prev, ecn_ect1,
					p->ecn_ce_count_prev, ecn_ce);
				return -EPROTO;
			}

			/* Calculate deltas */
			ect0_delta = ecn_ect0 - p->ecn_ect0_count_prev;
			ect1_delta = ecn_ect1 - p->ecn_ect1_count_prev;
			ce_delta = ecn_ce - p->ecn_ce_count_prev;

			/*
			 * H-002: Validate delta reasonableness with path-aware limit.
			 * ECN counters should not increase by more than packets we
			 * could have sent. Use cwnd-based calculation: allow up to
			 * 10 congestion windows worth of packets to accommodate
			 * bursty traffic patterns while preventing abuse.
			 *
			 * Max reasonable delta = (cwnd * 10) / mtu
			 * This ensures the limit scales with path capacity.
			 */
			if (p->mtu > 0 && p->cc.cwnd > 0) {
				u64 max_reasonable_delta =
					(p->cc.cwnd * 10ULL) / p->mtu;

				if (ect0_delta > max_reasonable_delta ||
				    ect1_delta > max_reasonable_delta ||
				    ce_delta > max_reasonable_delta) {
					tquic_warn(
						"ECN delta exceeds path capacity: ect0=%llu ect1=%llu ce=%llu (max=%llu, cwnd=%u, mtu=%u)\n",
						ect0_delta, ect1_delta,
						ce_delta, max_reasonable_delta,
						p->cc.cwnd, p->mtu);
					return -EPROTO;
				}
			}

			TQUIC_INC_STATS(net, TQUIC_MIB_ECNACKSRX);
			if (ect0_delta > 0)
				TQUIC_ADD_STATS(net, TQUIC_MIB_ECNECT0RX,
						ect0_delta);
			if (ect1_delta > 0)
				TQUIC_ADD_STATS(net, TQUIC_MIB_ECNECT1RX,
						ect1_delta);
			if (ce_delta > 0) {
				u8 pn_space_idx;

				TQUIC_ADD_STATS(net, TQUIC_MIB_ECNCEMARKSRX,
						ce_delta);
				/*
				 * RFC 9002 Section 7.1: notify congestion
				 * control of the CE increase on this path.
				 */
				tquic_cong_on_ecn(p, ce_delta);

				/*
				 * RFC 9002 Section 7.1: An ECN-CE mark is an
				 * explicit congestion signal.  Mark the largest
				 * acknowledged packet as lost so the loss
				 * detection state machine accounts for CE-
				 * induced losses and triggers retransmission.
				 *
				 * Map encryption level to packet number space.
				 */
				switch (ctx->enc_level) {
				case TQUIC_PKT_INITIAL:
					pn_space_idx = TQUIC_PN_SPACE_INITIAL;
					break;
				case TQUIC_PKT_HANDSHAKE:
					pn_space_idx = TQUIC_PN_SPACE_HANDSHAKE;
					break;
				default:
					pn_space_idx = TQUIC_PN_SPACE_APPLICATION;
					break;
				}
				tquic_loss_mark_packet_lost(ctx->conn,
							   pn_space_idx,
							   largest_ack);
			}

			tquic_dbg(
				"ECN on path %u: ect0=%llu ect1=%llu ce=%llu\n",
				p->path_id, ecn_ect0, ecn_ect1, ecn_ce);

			p->ecn_ect0_count_prev = ecn_ect0;
			p->ecn_ect1_count_prev = ecn_ect1;
			p->ecn_ce_count_prev = ecn_ce;
		}
	}

	/*
	 * Update RTT estimate and notify congestion control.
	 *
	 * RFC 9002 Section 5.1: An RTT sample is generated using only
	 * the largest acknowledged packet in the received ACK frame.
	 * The RTT is measured from when the packet was sent (sent_time)
	 * to now, minus the peer's reported ack_delay.
	 */
	if (ctx->path && ctx->conn && ctx->conn->pn_spaces) {
		ktime_t now = ktime_get();
		ktime_t sent_time;
		unsigned long pn_flags;
		int pn_space_idx;
		int lookup_ret;
		/* C-5: use negotiated ack_delay_exponent per RFC 9000 Section 19.3 */
		u8 ade = ctx->conn->remote_params.ack_delay_exponent;
		u64 ack_delay_us;
		u64 rtt_us;
		struct tquic_pn_space *pns;

		/*
		 * Map encryption level to packet number space.
		 * Initial -> 0, Handshake -> 1, 0-RTT/1-RTT -> 2
		 */
		switch (ctx->enc_level) {
		case TQUIC_PKT_INITIAL:
			pn_space_idx = TQUIC_PN_SPACE_INITIAL;
			break;
		case TQUIC_PKT_HANDSHAKE:
			pn_space_idx = TQUIC_PN_SPACE_HANDSHAKE;
			break;
		default:
			pn_space_idx = TQUIC_PN_SPACE_APPLICATION;
			break;
		}

		pns = &ctx->conn->pn_spaces[pn_space_idx];

		/*
		 * Look up the sent_time of the largest acked packet.
		 * If we cannot find it (already removed or never
		 * tracked), skip the RTT sample entirely rather than
		 * feeding garbage into the estimator.
		 */
		spin_lock_irqsave(&pns->lock, pn_flags);
		lookup_ret = tquic_pn_space_get_sent_time(pns, largest_ack,
							  &sent_time);
		spin_unlock_irqrestore(&pns->lock, pn_flags);

		if (lookup_ret == 0) {
			u64 raw_rtt_us;

			rtt_us = ktime_us_delta(now, sent_time);
			raw_rtt_us = rtt_us;

			/*
			 * Clamp ade to RFC 9000 maximum of 20, then
			 * check for overflow before shifting.
			 */
			ade = min_t(u8, ade, 20);
			if (ack_delay > (16000000ULL >> ade))
				ack_delay_us = 16000000ULL;
			else
				ack_delay_us = ack_delay << ade;

			if (rtt_us > ack_delay_us)
				rtt_us -= ack_delay_us;

			/* Update MIB counter for RTT sample */
			if (ctx->conn->sk)
				TQUIC_INC_STATS(sock_net(ctx->conn->sk),
						TQUIC_MIB_RTTSAMPLES);

			/*
			 * Update path RTT state (smoothed_rtt, rttvar,
			 * min_rtt) from raw RTT and ack_delay.
			 * Per RFC 9002 Section 5.3: path-level RTT state
			 * is used by PTO calculation and schedulers.
			 */
			if (ctx->path)
				tquic_path_rtt_update(
					ctx->path,
					(u32)min_t(u64, raw_rtt_us, U32_MAX),
					(u32)min_t(u64, ack_delay_us, U32_MAX));

			/*
			 * Dispatch to loss detection for Application-level
			 * ACKs. This handles:
			 * - Per-packet acked bytes (incremental, not cumulative)
			 * - RFC 9002 loss detection (3-packet threshold)
			 * - Congestion control notification
			 * - PTO reset and timer updates
			 *
			 * For Initial/Handshake, use estimated bytes since
			 * those spaces have no tracked sent packets.
			 */
			if (pn_space_idx == TQUIC_PN_SPACE_APPLICATION) {
				/* ECN counts for loss detection */
				if (has_ecn) {
					ack_frame.ecn.ect0 = ecn_ect0;
					ack_frame.ecn.ect1 = ecn_ect1;
					ack_frame.ecn.ce = ecn_ce;
				}
				tquic_loss_detection_on_ack_received(
					ctx->conn, &ack_frame, pn_space_idx,
					ctx->path);
			} else {
				u64 bytes_acked;

				if (check_mul_overflow(
					    total_acked_pkts,
					    TQUIC_CRYPTO_FRAME_BYTES_EST,
					    &bytes_acked))
					return -EPROTO;

				tquic_cong_on_ack(ctx->path, bytes_acked,
						  rtt_us);
				ctx->path->stats.acked_bytes += bytes_acked;

				/*
				 * RFC 9002 Section A.7: Reset PTO count on
				 * any valid ACK. Initial/Handshake packets
				 * are always ack-eliciting (CRYPTO frames),
				 * so any ACK at these levels proves the peer
				 * is alive. Without this, pto_count stays
				 * elevated after handshake and kills the
				 * connection during data transfer.
				 */
				ctx->conn->pto_count = 0;
				tquic_set_loss_detection_timer(ctx->conn);

				/*
				 * Sync timer sent-list for Initial/Handshake
				 * spaces (quic_loss.c handles Application).
				 */
				if (ctx->conn->timer_state)
					tquic_timer_on_ack_processed(
						ctx->conn->timer_state,
						pn_space_idx,
						ack_frame.largest_acked);

				/*
				 * Update CC RTT for Initial/Handshake only.
				 * Application-space RTT is notified inside
				 * tquic_loss_detection_on_ack_received().
				 */
				tquic_cong_on_rtt(ctx->path, rtt_us);
			}

			/*
			 * ACK opened cwnd - resume sending any
			 * pending stream data that was blocked.
			 */
			tquic_output_flush(ctx->conn);

			/*
			 * Wake blocked userspace writers. ACK processing
			 * may have opened cwnd, allowing sendmsg() callers
			 * that were blocked on sk_stream_wait_memory() to
			 * proceed.
			 */
			if (ctx->conn->sk &&
			    sk_stream_wspace(ctx->conn->sk) > 0)
				ctx->conn->sk->sk_write_space(ctx->conn->sk);
		}

		/*
		 * ECN CE congestion response already dispatched in the
		 * MIB delta section above via tquic_cong_on_ecn().
		 */
	}

	/* Mark acknowledged packets - processed by CC above */

	return 0;
}

/*
 * Process CRYPTO frame
 */
static int tquic_process_crypto_frame(struct tquic_rx_ctx *ctx)
{
	u64 offset, length;
	int ret;

	ctx->offset++; /* Skip frame type */

	/* Offset */
	ret = tquic_decode_varint(ctx->data + ctx->offset,
				  ctx->len - ctx->offset, &offset);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	/* Length */
	ret = tquic_decode_varint(ctx->data + ctx->offset,
				  ctx->len - ctx->offset, &length);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	/*
	 * SECURITY: Validate CRYPTO frame length to prevent integer overflow.
	 * length is u64 from varint decode (up to 2^62-1). On 32-bit systems
	 * adding to size_t ctx->offset could overflow/wrap. Also reject
	 * frames larger than the packet itself as obviously malformed.
	 */
	{
		size_t end_offset;

		if (length > ctx->len ||
		    check_add_overflow(ctx->offset, (size_t)length,
				       &end_offset) ||
		    end_offset > ctx->len)
			return -EINVAL;
	}

	/*
	 * SECURITY: Enforce pre-handshake memory allocation limits before
	 * processing CRYPTO frames at Initial/Handshake level.
	 * This prevents CVE-2025-54939 (QUIC-LEAK) resource exhaustion from
	 * bogus Initial packets.
	 *
	 * tquic_pre_hs_alloc() atomically checks and increments the per-IP
	 * and global counters.  On success the allocation is accounted; the
	 * matching release happens in tquic_pre_hs_free() when processing
	 * fails, or in tquic_pre_hs_connection_complete() when the handshake
	 * succeeds.
	 */
	if (ctx->enc_level == TQUIC_PKT_INITIAL ||
	    ctx->enc_level == TQUIC_PKT_HANDSHAKE) {
		if (ctx->conn && ctx->path) {
			ret = tquic_pre_hs_alloc(&ctx->path->remote_addr,
						 (size_t)length);
			if (ret < 0) {
				tquic_dbg(
					"CRYPTO frame rejected: pre-HS memory limit\n");
				return ret;
			}
		}
	}

	/*
	 * Feed CRYPTO frame data into the inline TLS handshake state machine.
	 * The data is a TLS handshake message (ClientHello, ServerHello, etc.)
	 * carried in the CRYPTO frame payload.
	 *
	 * Per RFC 9001 Section 4: "CRYPTO frames can be sent at all encryption
	 * levels except 0-RTT."
	 */
	if (ctx->conn && ctx->conn->tsk && ctx->conn->tsk->inline_hs) {
		struct sock *sk = (struct sock *)ctx->conn->tsk;

		pr_debug("crypto_frame: offset=%llu length=%llu enc_level=%d "
			 "data[0..3]=%*phN\n",
			 offset, length, ctx->enc_level,
			 min_t(int, (int)length, 4), ctx->data + ctx->offset);

		/*
		 * SECURITY: Validate length fits in u32 before cast.
		 * CRYPTO frames carrying TLS messages should never exceed
		 * practical limits. Reject oversized frames.
		 */
		if (length > U32_MAX)
			return -EINVAL;
		ret = tquic_inline_hs_recv_crypto(sk, ctx->data + ctx->offset,
						  (u32)length, ctx->enc_level);
		pr_debug("crypto_frame: inline_hs_recv_crypto ret=%d\n", ret);
		if (ret < 0) {
			tquic_dbg("CRYPTO frame processing failed: %d\n", ret);
			ctx->offset += length;
			return ret;
		}

		/*
		 * Flush any queued crypto response (e.g. client Finished)
		 * immediately after the handshake state machine processes
		 * incoming CRYPTO data.
		 */
		if (ctx->conn)
			tquic_output_flush_crypto(ctx->conn);
	} else {
		pr_debug("crypto_frame: no inline_hs! conn=%p tsk=%p\n",
			 ctx->conn, ctx->conn ? ctx->conn->tsk : NULL);
	}

	ctx->offset += length;
	ctx->ack_eliciting = true;

	return 0;
}

/*
 * tquic_stream_recv_insert_sorted - Insert skb into recv_buf in offset order
 * @stream: Target stream
 * @new_skb: skb to insert (stream offset stored in cb[0..7])
 *
 * Maintains recv_buf sorted by stream offset so that recvmsg can
 * deliver contiguous data even when STREAM frames arrive out of order.
 * Walks backward from the tail, which is O(1) when frames arrive in
 * order (the common case).
 *
 * Returns 0 on success, -EEXIST if the range overlaps an existing skb.
 */
static int tquic_stream_recv_insert_sorted(struct tquic_stream *stream,
					   struct sk_buff *new_skb)
{
	u64 new_off = get_unaligned((u64 *)new_skb->cb);
	u64 new_end = new_off + new_skb->len;
	struct sk_buff *skb;
	unsigned long flags;

	spin_lock_irqsave(&stream->recv_buf.lock, flags);

	/* Walk from tail — in-order arrival hits the first branch immediately */
	skb_queue_reverse_walk(&stream->recv_buf, skb)
	{
		u64 off = get_unaligned((u64 *)skb->cb);
		u64 end = off + skb->len;

		if (new_off >= end) {
			/* new_skb belongs right after this one */
			__skb_queue_after(&stream->recv_buf, skb, new_skb);
			spin_unlock_irqrestore(&stream->recv_buf.lock, flags);
			return 0;
		}

		if (new_end > off && new_off < end) {
			/* Overlaps with existing data — duplicate */
			spin_unlock_irqrestore(&stream->recv_buf.lock, flags);
			return -EEXIST;
		}
		/* new_end <= off: new_skb is earlier, keep walking back */
	}

	/* Smallest offset seen so far — insert at head */
	__skb_queue_head(&stream->recv_buf, new_skb);
	spin_unlock_irqrestore(&stream->recv_buf.lock, flags);
	return 0;
}

/*
 * =============================================================================
 * Bonding Reorder Buffer — Stream Delivery Helpers
 * =============================================================================
 */

/*
 * tquic_stream_reorder_cb - Extended SKB cb for bonding reorder buffer.
 *
 * The first member overlaps struct tquic_reorder_cb so the reorder buffer
 * reads/writes seq, len, path_id, and arrival correctly.  The stream pointer
 * and fin flag live in the remaining cb[] space and are only set/read here.
 *
 * Layout in skb->cb (48 bytes total):
 *   base (tquic_reorder_cb): 24 bytes  [seq/len/path_id/arrival]
 *   stream pointer:           8 bytes
 *   fin flag:                 1 byte
 *   ─────────────────────────────────
 *   total:                   33 bytes  (< 48, verified by BUILD_BUG_ON)
 */
struct tquic_stream_reorder_cb {
	struct tquic_reorder_cb base; /* Must be first */
	struct tquic_stream *stream; /* Stream to deliver data to */
	bool fin; /* FIN bit carried by this frame */
};

#define TQUIC_STREAM_REORDER_CB(skb) \
	((struct tquic_stream_reorder_cb *)((skb)->cb))

/*
 * tquic_stream_reorder_deliver - Deliver a buffered stream skb in order.
 *
 * Called by tquic_reorder_drain() when a gap is filled, or by the gap-timeout
 * work when the reorder buffer decides to flush a stale packet.
 *
 * The extra stream reference taken in tquic_process_stream_frame() is released
 * here once the skb has been inserted (or dropped on duplicate).
 */
static void tquic_stream_reorder_deliver(void *conn_ctx, struct sk_buff *skb)
{
	struct tquic_connection *conn = conn_ctx;
	struct tquic_stream_reorder_cb *scb = TQUIC_STREAM_REORDER_CB(skb);
	struct tquic_stream *stream = scb->stream;

	BUILD_BUG_ON(sizeof(struct tquic_stream_reorder_cb) >
		     sizeof(((struct sk_buff *)0)->cb));

	if (WARN_ON_ONCE(!stream)) {
		kfree_skb(skb);
		return;
	}

	if (tquic_stream_recv_insert_sorted(stream, skb)) {
		/*
		 * Duplicate within the stream buffer.  The reorder buffer
		 * deduplicates by sequence number, so this should not happen
		 * in practice — but handle it gracefully.
		 */
		if (conn->sk)
			sk_mem_uncharge(conn->sk, skb->truesize);
		kfree_skb(skb);
	} else {
		wake_up_interruptible(&stream->wait);
		if (conn->sk)
			conn->sk->sk_data_ready(conn->sk);
	}

	tquic_stream_put(stream);
}

/*
 * Process STREAM frame
 */
static int tquic_process_stream_frame(struct tquic_rx_ctx *ctx)
{
	u8 frame_type = ctx->data[ctx->offset];
	u64 stream_id, offset = 0, length;
	bool has_offset, has_length, fin;
	struct tquic_stream *stream;
	struct sk_buff *data_skb;
	int ret;

	/* Parse frame type flags */
	has_offset = (frame_type & 0x04) != 0;
	has_length = (frame_type & 0x02) != 0;
	fin = (frame_type & 0x01) != 0;

	ctx->offset++; /* Skip frame type */

	/* Stream ID */
	ret = tquic_decode_varint(ctx->data + ctx->offset,
				  ctx->len - ctx->offset, &stream_id);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	/* Offset (optional) */
	if (has_offset) {
		ret = tquic_decode_varint(ctx->data + ctx->offset,
					  ctx->len - ctx->offset, &offset);
		if (ret < 0)
			return ret;
		ctx->offset += ret;
	}

	pr_debug(
		"tquic: process_stream: id=%llu offset=%llu fin=%d len=%s is_server=%d\n",
		stream_id, offset, fin, has_length ? "pending" : "rest",
		ctx->conn->is_server);

	/* Length (optional) */
	if (has_length) {
		ret = tquic_decode_varint(ctx->data + ctx->offset,
					  ctx->len - ctx->offset, &length);
		if (ret < 0)
			return ret;
		ctx->offset += ret;
	} else {
		/* Length extends to end of packet */
		length = ctx->len - ctx->offset;
		/*
		 * RFC 9000 Section 19.8: A STREAM frame with no Length field
		 * consumes all remaining bytes in the packet. No further
		 * frames can follow -- record this so the frame loop can
		 * reject any trailing data.
		 */
		ctx->saw_stream_no_length = true;
	}

	/*
	 * M-001: Enforce hard per-frame allocation limit before any stream
	 * lookup or creation. A single STREAM frame must not allocate more
	 * than TQUIC_MAX_STREAM_FRAME_ALLOC bytes, preventing DoS via large
	 * single-frame allocations regardless of socket buffer size.
	 * This check must precede tquic_stream_open_incoming() so a rejected
	 * frame never causes a stream object to be allocated unnecessarily.
	 */
	if (length >= TQUIC_MAX_STREAM_FRAME_ALLOC) {
		pr_debug(
			"tquic: stream %llu: frame too large (%llu >= %u), dropping\n",
			stream_id, length, TQUIC_MAX_STREAM_FRAME_ALLOC);
		return -EMSGSIZE;
	}

	if (ctx->offset + length > ctx->len)
		return -EINVAL;

	/*
	 * Lookup stream, creating it if this is the first frame for a
	 * remotely-initiated stream ID.
	 *
	 * When the stream manager is present, delegate to
	 * tquic_stream_get_or_create() which performs the RB-tree lookup
	 * and, if not found, calls tquic_stream_create_internal() under
	 * mgr->lock — handling concurrent creation races correctly.
	 *
	 * Fall back to the legacy spin_lock_bh + tquic_stream_open_incoming()
	 * path when no manager is attached.
	 */
	if (ctx->conn->stream_mgr) {
		stream = tquic_stream_get_or_create(ctx->conn->stream_mgr,
						    stream_id);
		if (!stream)
			return -ENOMEM;
	} else {
	stream = NULL;
	spin_lock_bh(&ctx->conn->lock);
	{
		struct rb_node *node = ctx->conn->streams.rb_node;

		while (node) {
			struct tquic_stream *s =
				rb_entry(node, struct tquic_stream, node);

			if (stream_id < s->id) {
				node = node->rb_left;
			} else if (stream_id > s->id) {
				node = node->rb_right;
			} else {
				if (tquic_stream_get(s))
					stream = s;
				break;
			}
		}
	}
	spin_unlock_bh(&ctx->conn->lock);

	if (!stream) {
		/*
		 * Stream not found. Create new incoming stream.
		 * tquic_stream_open_incoming() handles concurrent creation
		 * attempts internally by checking the tree under conn->lock.
		 */
		stream = tquic_stream_open_incoming(ctx->conn, stream_id);
		if (!stream)
			return -ENOMEM;

		/*
		 * Wake up any recvmsg() blocked waiting for a stream to
		 * appear.  On the server side, accept() returns the child
		 * socket before the client's first STREAM frame arrives,
		 * so recvmsg() may be sleeping on sk_sleep(sk).
		 */
		if (ctx->conn->sk)
			ctx->conn->sk->sk_data_ready(ctx->conn->sk);
	}
	} /* end else (no stream_mgr) */

	/*
	 * CF-231: Check receive buffer memory BEFORE allocating the skb.
	 * The `length` field comes from the peer (attacker-controlled)
	 * and drives the alloc_skb() size below.
	 *
	 * Use sk_rmem_schedule() which atomically checks and reserves
	 * buffer space, preventing races where multiple threads could
	 * exceed the buffer limit between check and allocation.
	 *
	 * Cap allocation to socket receive buffer size so a single
	 * frame cannot trigger an unreasonably large kmalloc.
	 */
	if (ctx->conn->sk) {
		struct sock *sk = ctx->conn->sk;

		/* Cap allocation to remaining buffer capacity */
		if (length > (u64)sk->sk_rcvbuf) {
			pr_debug(
				"tquic: stream %llu: dropped: len %llu > rcvbuf %d\n",
				stream_id, length, sk->sk_rcvbuf);
			ctx->offset += length;
			ctx->ack_eliciting = true;
			tquic_stream_put(stream);
			return 0;
		}
	}

	/*
	 * Validate BEFORE allocating/enqueuing to prevent SKB leaks.
	 * All checks that can return -EPROTO must happen before the
	 * skb is allocated and enqueued into stream->recv_buf.
	 */

	/*
	 * SECURITY: Validate stream offset + length against RFC 9000 limit.
	 * Per Section 4.5: "An endpoint MUST treat receipt of data at or
	 * beyond the final size as a connection error." The maximum stream
	 * offset is 2^62-1. Check for overflow before proceeding.
	 */
	if (offset > ((1ULL << 62) - 1) - length) {
		tquic_stream_put(stream);
		return -EPROTO;
	}

	if (fin) {
		u64 final_size = offset + length;

		/*
		 * CF-349: RFC 9000 Section 4.5 - Final size consistency.
		 * If we already know the final size, it must match.
		 * Also, data beyond the final size is a protocol error.
		 */
		if (stream->fin_received && stream->final_size != final_size) {
			tquic_stream_put(stream);
			return -EPROTO;
		}
	} else if (stream->fin_received) {
		/* Data beyond the known final size is an error */
		if (offset + length > stream->final_size) {
			tquic_stream_put(stream);
			return -EPROTO;
		}
	}

	/*
	 * RFC 9000 Section 4.1: Enforce receive flow control limits.
	 * Check both stream-level and connection-level limits before
	 * accepting the data.
	 */
	if (tquic_flow_check_recv_limits(stream, offset, length)) {
		pr_debug("tquic: stream %llu: flow control exceeded\n",
			 stream_id);
		tquic_stream_put(stream);
		return -EDQUOT;
	}

	/*
	 * Dedup check: skip data the application has already consumed.
	 * recv_consumed tracks how many bytes the application has read
	 * via recvmsg — anything below that is definitely duplicate.
	 *
	 * We do NOT use recv_offset (highest byte seen) here because
	 * that would reject gap-filling retransmissions: if frames
	 * arrive as [0,1000) then [2000,3000) then [1000,2000), the
	 * third frame fills a gap and must not be discarded.
	 *
	 * Overlap with buffered-but-unconsumed data is caught later by
	 * the sorted insertion helper.
	 *
	 * This MUST come after tquic_flow_check_recv_limits() so that
	 * flow control *limit violations* are still detected on the
	 * original offset+length, while flow control *accounting* below
	 * only charges genuinely new bytes.
	 */
	if (length > 0 && offset + length <= stream->recv_consumed) {
		/* Fully consumed — ACK but do not charge FC or alloc */
		pr_debug(
			"tquic: stream %llu: dup data off=%llu len=%llu consumed=%llu\n",
			stream_id, offset, length, stream->recv_consumed);
		ctx->offset += length;
		ctx->ack_eliciting = true;
		tquic_stream_put(stream);
		return 0;
	}

	if (offset < stream->recv_consumed) {
		/*
		 * Partial overlap with consumed data: trim the prefix
		 * that the application has already read.
		 */
		u64 trim = stream->recv_consumed - offset;

		pr_debug(
			"tquic: stream %llu: partial dup trim %llu bytes (off %llu->%llu)\n",
			stream_id, trim, offset, stream->recv_consumed);
		ctx->offset += trim;
		length -= trim;
		offset = stream->recv_consumed;
	}

	/* Copy data to stream receive buffer */
	data_skb = alloc_skb(length, GFP_ATOMIC);
	if (!data_skb) {
		tquic_stream_put(stream);
		return -ENOMEM;
	}

	skb_put_data(data_skb, ctx->data + ctx->offset, length);

	/* Store offset in skb->cb for reordering */
	put_unaligned(offset, (u64 *)data_skb->cb);

	/*
	 * Atomically reserve receive buffer space and charge it to the socket.
	 * sk_rmem_schedule() prevents races where multiple threads allocate
	 * simultaneously and exceed the buffer limit. If reservation fails,
	 * free the skb and silently drop (peer will retransmit).
	 */
	if (ctx->conn->sk) {
		if (!sk_rmem_schedule(ctx->conn->sk, data_skb, length)) {
			/*
			 * Buffer quota exceeded — drop the data so the peer
			 * will retransmit.  Do NOT set ack_eliciting: sending
			 * an ACK for a packet whose STREAM data we dropped
			 * would falsely confirm delivery (RFC 9000 §2.2).
			 * The offset is advanced so the frame loop continues
			 * parsing subsequent frames in this packet.
			 */
			pr_debug(
				"tquic: stream %llu: rmem_schedule failed, dropping\n",
				stream_id);
			kfree_skb(data_skb);
			ctx->offset += length;
			tquic_stream_put(stream);
			return 0;
		}
		skb_set_owner_r(data_skb, ctx->conn->sk);
	}

	/*
	 * Bonding reorder buffer path: when multi-path bonding is active,
	 * stream data passes through the RB-tree reorder buffer to compensate
	 * for inter-path latency spread (e.g. fiber ~20 ms, satellite ~600 ms).
	 * The stream byte offset serves as the per-stream sequence number.
	 * State metadata (recv_offset, flow control) is updated at receive time
	 * per RFC 9000 §2.2; ordered delivery to the application follows drain.
	 */
	if (ctx->conn->pm && ctx->conn->pm->bonding_ctx) {
		struct tquic_bonding_ctx *bc = ctx->conn->pm->bonding_ctx;
		struct tquic_reorder_buffer *rb = tquic_bonding_get_reorder(bc);

		if (rb) {
			struct tquic_stream_reorder_cb *scb =
				TQUIC_STREAM_REORDER_CB(data_skb);
			int r;

			/*
			 * Take an extra stream reference that the reorder buffer
			 * holds until delivery.  tquic_stream_reorder_deliver()
			 * releases it after handing the skb to the stream.
			 */
			if (!tquic_stream_get(stream))
				goto normal_insert;

			scb->stream = stream;
			scb->fin = fin;

			/* Register timeout-flush callback (idempotent write) */
			tquic_reorder_set_deliver(
				rb, tquic_stream_reorder_deliver, ctx->conn);

			r = tquic_reorder_insert(rb, data_skb, offset,
						 (u32)length,
						 (u8)ctx->path->path_id);
			if (r < 0) {
				/* Dup, too old, or buffer full — drop cleanly */
				if (ctx->conn->sk)
					sk_mem_uncharge(ctx->conn->sk,
							data_skb->truesize);
				kfree_skb(data_skb);
				tquic_stream_put(
					stream); /* release extra ref */
			} else {
				/* Flush any now-consecutive buffered packets */
				tquic_reorder_drain(
					rb, tquic_stream_reorder_deliver,
					ctx->conn);
			}

			/* RFC 9000 §2.2: update state at receive time */
			stream->recv_offset =
				max(stream->recv_offset, offset + length);
			if (fin && !stream->fin_received) {
				stream->fin_received = true;
				stream->final_size = offset + length;
			}
			tquic_flow_on_stream_data_recvd(stream, offset, length);

			ctx->offset += length;
			ctx->ack_eliciting = true;
			ctx->conn->stats.rx_bytes += length;
			tquic_stream_put(stream); /* release original ref */
			return 0;
		}
	}

normal_insert:
	/*
	 * If a stream manager is present, delegate to tquic_stream_recv_data
	 * which handles sorted insertion, flow control accounting, FIN
	 * state, and connection stats in one place.
	 * Fall back to the legacy path when stream_mgr is not available.
	 */
	if (ctx->conn->stream_mgr) {
		int rv = tquic_stream_recv_data(ctx->conn->stream_mgr,
						stream, offset, data_skb, fin);

		if (rv < 0) {
			if (ctx->conn->sk)
				sk_mem_uncharge(ctx->conn->sk,
						data_skb->truesize);
			kfree_skb(data_skb);
		}
		ctx->offset += length;
		ctx->ack_eliciting = true;
		tquic_stream_put(stream);
		return rv < 0 ? rv : 0;
	}

	/*
	 * Legacy path: Insert in offset-sorted order so recvmsg can
	 * deliver contiguous data even when frames arrive out of order.
	 */
	if (tquic_stream_recv_insert_sorted(stream, data_skb)) {
		/* Overlaps with already-buffered data — drop duplicate */
		if (ctx->conn->sk)
			sk_mem_uncharge(ctx->conn->sk, data_skb->truesize);
		kfree_skb(data_skb);
		ctx->offset += length;
		ctx->ack_eliciting = true;
		tquic_stream_put(stream);
		return 0;
	}
	pr_debug("tquic: stream %llu: enqueued %llu bytes at off=%llu\n",
		 stream_id, length, offset);

	/* Update recv_offset and final_size after successful enqueue */
	stream->recv_offset = max(stream->recv_offset, offset + length);

	if (fin && !stream->fin_received) {
		stream->fin_received = true;
		stream->final_size = offset + length;
	}

	/* Notify flow control of received data */
	tquic_flow_on_stream_data_recvd(stream, offset, length);

	ctx->offset += length;
	ctx->ack_eliciting = true;

	/* Update connection stats */
	ctx->conn->stats.rx_bytes += length;

	/* Wake up any readers blocked in tquic_recvmsg() */
	wake_up_interruptible(&stream->wait);

	/*
	 * P-003: Release the stream reference we acquired during RCU lookup.
	 * The stream data has been safely enqueued, so we no longer need
	 * to hold the reference.
	 */
	tquic_stream_put(stream);

	return 0;
}

/*
 * Process MAX_DATA frame
 */
static int tquic_process_max_data_frame(struct tquic_rx_ctx *ctx)
{
	u64 max_data;
	int ret;

	tquic_dbg("process_max_data: pkt_num=%llu\n", ctx->pkt_num);

	ctx->offset++; /* Skip frame type */

	ret = tquic_decode_varint(ctx->data + ctx->offset,
				  ctx->len - ctx->offset, &max_data);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	tquic_dbg("process_max_data: new limit=%llu\n", max_data);

	/* Update RFC 9000 Section 4 connection FC state */
	if (ctx->conn->fc)
		tquic_fc_handle_max_data(ctx->conn->fc, max_data);

	/*
	 * RFC 9000 Section 19.9: Update connection-level flow control via
	 * the exported stream API (only increases, per RFC 9000).
	 */
	if (ctx->conn->stream_mgr)
		tquic_stream_conn_update_max_data(ctx->conn->stream_mgr,
						  max_data);

	/* Update remote's max data limit (only increase, per RFC 9000) */
	spin_lock_bh(&ctx->conn->lock);
	if (max_data > ctx->conn->max_data_remote) {
		struct rb_node *node;

		ctx->conn->max_data_remote = max_data;

		/*
		 * Wake all streams that may be blocked in sendmsg
		 * waiting for connection-level flow control credit.
		 * sendmsg waits on stream->wait with a condition that
		 * re-checks tquic_stream_check_flow_control(), which
		 * includes connection-level limits.
		 */
		for (node = rb_first(&ctx->conn->streams); node;
		     node = rb_next(node)) {
			struct tquic_stream *s =
				rb_entry(node, struct tquic_stream, node);
			wake_up_interruptible(&s->wait);
		}

		spin_unlock_bh(&ctx->conn->lock);
		tquic_output_flush(ctx->conn);
	} else {
		spin_unlock_bh(&ctx->conn->lock);
	}

	ctx->ack_eliciting = true;

	return 0;
}

/*
 * Process MAX_STREAM_DATA frame
 */
static int tquic_process_max_stream_data_frame(struct tquic_rx_ctx *ctx)
{
	u64 stream_id, max_data;
	int ret;

	tquic_dbg("process_max_stream_data: pkt_num=%llu\n", ctx->pkt_num);

	ctx->offset++; /* Skip frame type */

	/* Stream ID */
	ret = tquic_decode_varint(ctx->data + ctx->offset,
				  ctx->len - ctx->offset, &stream_id);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	/* Max Data */
	ret = tquic_decode_varint(ctx->data + ctx->offset,
				  ctx->len - ctx->offset, &max_data);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	tquic_dbg("process_max_stream_data: stream=%llu limit=%llu\n",
		  stream_id, max_data);

	pr_debug("tquic: RX MAX_STREAM_DATA: stream=%llu limit=%llu\n",
		 stream_id, max_data);

	/*
	 * RFC 9000 Section 19.10: Update stream send-side flow control limit
	 * via the exported stream API (only increases, per RFC 9000).
	 */
	spin_lock_bh(&ctx->conn->lock);
	{
		struct tquic_stream *s =
			tquic_conn_stream_lookup(ctx->conn, stream_id);

		if (s) {
			/* Update RFC 9000 Section 4 stream FC state */
			if (s->fc)
				tquic_fc_handle_max_stream_data(s->fc, max_data);
			tquic_stream_update_max_data(s, max_data);
		}
	}
	spin_unlock_bh(&ctx->conn->lock);

	/*
	 * Stream-level flow control opened - resume sending any pending
	 * stream data that was blocked.  Without this, the server stalls
	 * after the client sends MAX_STREAM_DATA because nothing triggers
	 * tquic_output_flush() to drain the send buffer.
	 */
	tquic_output_flush(ctx->conn);

	ctx->ack_eliciting = true;

	return 0;
}

/*
 * Process RESET_STREAM frame (0x04)
 *
 * RFC 9000 Section 19.4: Peer abruptly terminates a stream.
 * Fields: Stream ID, Application Protocol Error Code, Final Size.
 */
static int tquic_process_reset_stream_frame(struct tquic_rx_ctx *ctx)
{
	u64 stream_id, error_code, final_size;
	int ret;

	ctx->offset++; /* Skip frame type */

	ret = tquic_decode_varint(ctx->data + ctx->offset,
				  ctx->len - ctx->offset, &stream_id);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	ret = tquic_decode_varint(ctx->data + ctx->offset,
				  ctx->len - ctx->offset, &error_code);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	ret = tquic_decode_varint(ctx->data + ctx->offset,
				  ctx->len - ctx->offset, &final_size);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	pr_debug("tquic: RESET_STREAM stream=%llu error=%llu final_size=%llu\n",
		 stream_id, error_code, final_size);

	/*
	 * RFC 9000 Section 19.4: Deliver RESET_STREAM via the exported
	 * stream API which manages state transitions, discards the recv
	 * buffer, and wakes blocked readers.
	 */
	if (ctx->conn->stream_mgr) {
		struct tquic_stream *s;

		spin_lock_bh(&ctx->conn->lock);
		s = tquic_conn_stream_lookup(ctx->conn, stream_id);
		spin_unlock_bh(&ctx->conn->lock);

		if (s) {
			/*
			 * RFC 9000 §4.5: Validate final_size consistency
			 * before delegating to tquic_stream_reset_recv.
			 */
			if (final_size < s->recv_offset ||
			    (s->fin_received &&
			     s->final_size != final_size))
				return -EPROTO;

			tquic_stream_reset_recv(ctx->conn->stream_mgr, s,
						error_code, final_size);
		}
	} else {
		/* Fallback: direct state update if stream_mgr unavailable */
		spin_lock_bh(&ctx->conn->lock);
		{
			struct rb_node *node = ctx->conn->streams.rb_node;

			while (node) {
				struct tquic_stream *s =
					rb_entry(node, struct tquic_stream,
						 node);

				if (stream_id < s->id) {
					node = node->rb_left;
				} else if (stream_id > s->id) {
					node = node->rb_right;
				} else {
					if (final_size < s->recv_offset ||
					    (s->fin_received &&
					     s->final_size != final_size)) {
						spin_unlock_bh(&ctx->conn->lock);
						return -EPROTO;
					}
					s->fin_received = true;
					s->final_size = final_size;
					s->state = TQUIC_STREAM_CLOSED;
					wake_up_interruptible(&s->wait);
					break;
				}
			}
		}
		spin_unlock_bh(&ctx->conn->lock);
	}

	ctx->ack_eliciting = true;
	return 0;
}

/*
 * Process STOP_SENDING frame (0x05)
 *
 * RFC 9000 Section 19.5: Peer requests we stop sending on a stream.
 * Fields: Stream ID, Application Protocol Error Code.
 */
static int tquic_process_stop_sending_frame(struct tquic_rx_ctx *ctx)
{
	u64 stream_id, error_code;
	int ret;

	ctx->offset++; /* Skip frame type */

	ret = tquic_decode_varint(ctx->data + ctx->offset,
				  ctx->len - ctx->offset, &stream_id);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	ret = tquic_decode_varint(ctx->data + ctx->offset,
				  ctx->len - ctx->offset, &error_code);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	pr_debug("tquic: STOP_SENDING stream=%llu error=%llu\n", stream_id,
		 error_code);

	/*
	 * RFC 9000 Section 19.5: Peer requests we stop sending on this stream.
	 * Use the exported stream API to shut down the write side cleanly
	 * (sets fin_sent, wakes blocked writers, triggers RESET_STREAM).
	 */
	if (ctx->conn->stream_mgr) {
		struct tquic_stream *s;

		spin_lock_bh(&ctx->conn->lock);
		s = tquic_conn_stream_lookup(ctx->conn, stream_id);
		spin_unlock_bh(&ctx->conn->lock);

		if (s)
			tquic_stream_shutdown_write(ctx->conn->stream_mgr, s);
	} else {
		/* Fallback: direct state update if stream_mgr unavailable */
		spin_lock_bh(&ctx->conn->lock);
		{
			struct rb_node *node = ctx->conn->streams.rb_node;

			while (node) {
				struct tquic_stream *s =
					rb_entry(node, struct tquic_stream,
						 node);

				if (stream_id < s->id) {
					node = node->rb_left;
				} else if (stream_id > s->id) {
					node = node->rb_right;
				} else {
					s->fin_sent = true;
					wake_up_interruptible(&s->wait);
					break;
				}
			}
		}
		spin_unlock_bh(&ctx->conn->lock);
	}

	ctx->ack_eliciting = true;
	return 0;
}

/*
 * Process MAX_STREAMS frame (0x12 bidi, 0x13 uni)
 *
 * RFC 9000 Section 19.11: Peer increases the maximum number of
 * streams we're allowed to open.
 */
static int tquic_process_max_streams_frame(struct tquic_rx_ctx *ctx, bool bidi)
{
	u64 max_streams;
	int ret;

	ctx->offset++; /* Skip frame type */

	ret = tquic_decode_varint(ctx->data + ctx->offset,
				  ctx->len - ctx->offset, &max_streams);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	tquic_dbg("process_max_streams: %s max=%llu\n", bidi ? "bidi" : "uni",
		  max_streams);

	/* Update RFC 9000 Section 4.6 stream count FC state */
	if (ctx->conn->fc)
		tquic_fc_handle_max_streams(ctx->conn->fc, max_streams, bidi);

	/* Only increase, per RFC 9000 */
	spin_lock_bh(&ctx->conn->lock);
	if (bidi) {
		if (max_streams > ctx->conn->max_streams_bidi)
			ctx->conn->max_streams_bidi = max_streams;
	} else {
		if (max_streams > ctx->conn->max_streams_uni)
			ctx->conn->max_streams_uni = max_streams;
	}
	spin_unlock_bh(&ctx->conn->lock);

	ctx->ack_eliciting = true;
	return 0;
}

/*
 * Process DATA_BLOCKED frame (0x14)
 *
 * RFC 9000 Section 19.12: Peer is blocked by connection-level flow control.
 * This is informational only.
 */
static int tquic_process_data_blocked_frame(struct tquic_rx_ctx *ctx)
{
	u64 limit;
	int ret;

	ctx->offset++; /* Skip frame type */

	ret = tquic_decode_varint(ctx->data + ctx->offset,
				  ctx->len - ctx->offset, &limit);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	pr_debug("tquic: DATA_BLOCKED at limit=%llu\n", limit);

	/*
	 * RFC 9000 Section 4.1: Peer is blocked by our receive window.
	 * Update FC state and trigger a MAX_DATA update so the peer
	 * can make progress.
	 */
	if (ctx->conn->fc) {
		tquic_fc_handle_data_blocked(ctx->conn->fc, limit);
		tquic_output_flush(ctx->conn);
	}

	ctx->ack_eliciting = true;
	return 0;
}

/*
 * Process STREAM_DATA_BLOCKED frame (0x15)
 *
 * RFC 9000 Section 19.13: Peer is blocked by stream-level flow control.
 */
static int tquic_process_stream_data_blocked_frame(struct tquic_rx_ctx *ctx)
{
	u64 stream_id, limit;
	int ret;

	ctx->offset++; /* Skip frame type */

	ret = tquic_decode_varint(ctx->data + ctx->offset,
				  ctx->len - ctx->offset, &stream_id);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	ret = tquic_decode_varint(ctx->data + ctx->offset,
				  ctx->len - ctx->offset, &limit);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	pr_debug("tquic: STREAM_DATA_BLOCKED stream=%llu limit=%llu\n",
		 stream_id, limit);

	/*
	 * RFC 9000 Section 4.2: Peer is blocked on stream-level FC.
	 * Update FC state and trigger MAX_STREAM_DATA so peer can
	 * make progress.
	 */
	spin_lock_bh(&ctx->conn->lock);
	{
		struct rb_node *node = ctx->conn->streams.rb_node;

		while (node) {
			struct tquic_stream *s =
				rb_entry(node, struct tquic_stream, node);

			if (stream_id < s->id) {
				node = node->rb_left;
			} else if (stream_id > s->id) {
				node = node->rb_right;
			} else {
				if (s->fc)
					tquic_fc_handle_stream_data_blocked(
						s->fc, limit);
				break;
			}
		}
	}
	spin_unlock_bh(&ctx->conn->lock);

	ctx->ack_eliciting = true;
	return 0;
}

/*
 * Process STREAMS_BLOCKED frame (0x16 bidi, 0x17 uni)
 *
 * RFC 9000 Section 19.14: Peer is blocked by MAX_STREAMS limit.
 */
static int tquic_process_streams_blocked_frame(struct tquic_rx_ctx *ctx,
					       bool bidi)
{
	u64 limit;
	int ret;

	ctx->offset++; /* Skip frame type */

	ret = tquic_decode_varint(ctx->data + ctx->offset,
				  ctx->len - ctx->offset, &limit);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	pr_debug("tquic: STREAMS_BLOCKED at limit=%llu\n", limit);

	/*
	 * RFC 9000 Section 4.6: Peer is blocked on MAX_STREAMS.
	 * Update FC state so autotune can consider increasing the limit.
	 */
	if (ctx->conn->fc)
		tquic_fc_handle_streams_blocked(ctx->conn->fc, limit, bidi);

	ctx->ack_eliciting = true;
	return 0;
}

/*
 * Process PATH_CHALLENGE frame
 */
static int tquic_process_path_challenge_frame(struct tquic_rx_ctx *ctx)
{
	u8 data[8];
	int ret;

	ctx->offset++; /* Skip frame type */

	if (ctx->offset + 8 > ctx->len)
		return -EINVAL;

	memcpy(data, ctx->data + ctx->offset, 8);
	ctx->offset += 8;

	/*
	 * RFC 9000 Section 8.2: Handle PATH_CHALLENGE via the exported
	 * connection-layer API which sends a PATH_RESPONSE in reply.
	 */
	ret = tquic_handle_path_challenge(ctx->conn, ctx->path, data);
	if (ret < 0 && ret != -ENOBUFS) {
		/* Log error but don't fail packet processing */
		tquic_dbg("PATH_CHALLENGE handling failed: %d\n", ret);
	}

	ctx->ack_eliciting = true;

	return 0;
}

/*
 * Process PATH_RESPONSE frame
 */
static int tquic_process_path_response_frame(struct tquic_rx_ctx *ctx)
{
	u8 data[8];
	int ret;

	tquic_dbg("process_path_response: pkt_num=%llu\n", ctx->pkt_num);

	ctx->offset++; /* Skip frame type */

	if (ctx->offset + 8 > ctx->len)
		return -EINVAL;

	memcpy(data, ctx->data + ctx->offset, 8);
	ctx->offset += 8;

	/*
	 * RFC 9000 Section 8.2.2: Verify the PATH_RESPONSE data matches
	 * the per-path challenge we sent (stored in path->validation).
	 * tquic_path_verify_response() does a constant-time compare of
	 * the 8-byte challenge token.  If the per-path check passes we
	 * mark the path validated directly; if it fails we still try the
	 * connection-layer pending-challenges list (tquic_handle_path_response)
	 * which handles challenges issued from the conn state machine.
	 */
	if (ctx->path && tquic_path_verify_response(ctx->path, data)) {
		ctx->path->validation.challenge_pending = false;
		tquic_path_on_validated(ctx->conn, ctx->path);
	}

	/*
	 * RFC 9000 Section 8.2: Handle PATH_RESPONSE via the exported
	 * connection-layer API which validates the pending challenge.
	 */
	ret = tquic_handle_path_response(ctx->conn, ctx->path, data);
	if (ret == 0) {
		/* Update MIB counter for successful path validation */
		if (ctx->conn && ctx->conn->sk)
			TQUIC_INC_STATS(sock_net(ctx->conn->sk),
					TQUIC_MIB_PATHVALIDATED);
	}

	ctx->ack_eliciting = true;

	return 0;
}

/*
 * Process NEW_CONNECTION_ID frame
 */
static int tquic_process_new_connection_id_frame(struct tquic_rx_ctx *ctx)
{
	u64 seq_num, retire_prior_to;
	u8 cid_len;
	u8 cid[TQUIC_MAX_CID_LEN];
	u8 reset_token[16];
	int ret;

	ctx->offset++; /* Skip frame type */

	/* Sequence Number */
	ret = tquic_decode_varint(ctx->data + ctx->offset,
				  ctx->len - ctx->offset, &seq_num);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	/* Retire Prior To */
	ret = tquic_decode_varint(ctx->data + ctx->offset,
				  ctx->len - ctx->offset, &retire_prior_to);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	/* Connection ID Length */
	if (ctx->offset >= ctx->len)
		return -EINVAL;
	cid_len = ctx->data[ctx->offset++];

	if (cid_len > TQUIC_MAX_CID_LEN)
		return -EINVAL;

	/* Connection ID */
	if (ctx->offset + cid_len > ctx->len)
		return -EINVAL;
	memcpy(cid, ctx->data + ctx->offset, cid_len);
	ctx->offset += cid_len;

	/* Stateless Reset Token */
	if (ctx->offset + 16 > ctx->len)
		return -EINVAL;
	memcpy(reset_token, ctx->data + ctx->offset, 16);
	ctx->offset += 16;

	/*
	 * SECURITY: Check CID security limits before processing.
	 * This prevents CVE-2024-22189 Retire CID stuffing attacks
	 * by rate-limiting NEW_CONNECTION_ID frames.
	 */
	if (ctx->conn && ctx->conn->cid_pool) {
		struct tquic_cid_pool *pool = ctx->conn->cid_pool;
		int sret;

		sret = tquic_cid_security_check_new_cid(&pool->security);
		if (sret < 0) {
			tquic_dbg(
				"NEW_CONNECTION_ID rejected by security check: %d\n",
				sret);
			return sret;
		}
	}

	/* Store new CID for future use */
	/* This would be added to a CID pool */

	/*
	 * CF-249: RFC 9000 Section 19.15 requires retiring CIDs with
	 * sequence numbers less than retire_prior_to. Validate
	 * retire_prior_to <= seq_num per RFC 9000 Section 19.15:
	 * "A value of retire_prior_to greater than seq_num is an
	 * error of type FRAME_ENCODING_ERROR."
	 */
	if (retire_prior_to > seq_num) {
		tquic_dbg(
			"NEW_CONNECTION_ID: retire_prior_to %llu > seq %llu\n",
			retire_prior_to, seq_num);
		return -EINVAL;
	}

	/*
	 * Retire CIDs with sequence numbers below retire_prior_to.
	 * Only retire newly-covered CIDs to prevent DoS from large
	 * retire_prior_to values (up to 2^62) causing kernel soft lockup.
	 * Also cap per-frame iteration as defense in depth.
	 */
	if (ctx->conn && retire_prior_to > 0) {
		u64 prev_retire = ctx->conn->cid_retire_prior_to;

		if (retire_prior_to > prev_retire) {
			u64 i;
			u64 count = 0;

			for (i = prev_retire; i < retire_prior_to; i++) {
				tquic_conn_retire_cid(ctx->conn, i, false);
				if (++count >= 256)
					break;
			}
			ctx->conn->cid_retire_prior_to = retire_prior_to;
		}
	}

	ctx->ack_eliciting = true;

	return 0;
}

/*
 * Process RETIRE_CONNECTION_ID frame
 */
static int tquic_process_retire_connection_id_frame(struct tquic_rx_ctx *ctx)
{
	u64 seq_num;
	int ret;

	tquic_dbg("process_retire_cid: pkt_num=%llu\n", ctx->pkt_num);

	ctx->offset++; /* Skip frame type */

	ret = tquic_decode_varint(ctx->data + ctx->offset,
				  ctx->len - ctx->offset, &seq_num);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	tquic_dbg("process_retire_cid: seq_num=%llu\n", seq_num);

	/* Remove CID from active set */
	/* This would update the CID pool */

	ctx->ack_eliciting = true;

	return 0;
}

/*
 * Process CONNECTION_CLOSE frame
 */
static int tquic_process_connection_close_frame(struct tquic_rx_ctx *ctx,
						bool app)
{
	u64 error_code, frame_type = 0, reason_len;
	int ret;

	ctx->offset++; /* Skip frame type */

	/* Error Code */
	ret = tquic_decode_varint(ctx->data + ctx->offset,
				  ctx->len - ctx->offset, &error_code);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	/* Frame Type (only for transport close) */
	if (!app) {
		ret = tquic_decode_varint(ctx->data + ctx->offset,
					  ctx->len - ctx->offset, &frame_type);
		if (ret < 0)
			return ret;
		ctx->offset += ret;
	}

	/* Reason Phrase Length */
	ret = tquic_decode_varint(ctx->data + ctx->offset,
				  ctx->len - ctx->offset, &reason_len);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	/*
	 * SECURITY: Validate reason phrase length to prevent integer overflow
	 * and resource abuse. reason_len is u64 from varint (up to 2^62-1).
	 * Cap to a sane maximum to prevent allocation/processing abuse.
	 * RFC 9000 does not specify a maximum, but reason phrases exceeding
	 * the packet size are always invalid.
	 */
	if (reason_len > ctx->len - ctx->offset)
		return -EINVAL;

	/* Enforce a reasonable maximum for the reason phrase */
	if (reason_len > 1024) {
		pr_warn_ratelimited(
			"tquic: CONNECTION_CLOSE reason phrase too long (%llu)\n",
			reason_len);
		return -EINVAL;
	}
	ctx->offset += (size_t)reason_len;

	pr_info_ratelimited(
		"tquic: received CONNECTION_CLOSE, error=%llu frame_type=%llu\n",
		error_code, frame_type);

	/*
	 * Transition to draining state via connection close handler.
	 * Use tquic_conn_handle_close() which properly validates state
	 * transitions rather than bypassing the state machine.
	 */
	tquic_conn_handle_close(ctx->conn, error_code, frame_type, NULL, app);

	/* Update MIB counters for connection close */
	if (ctx->conn && ctx->conn->sk) {
		TQUIC_DEC_STATS(sock_net(ctx->conn->sk), TQUIC_MIB_CURRESTAB);
		if (error_code == EQUIC_NO_ERROR)
			TQUIC_INC_STATS(sock_net(ctx->conn->sk),
					TQUIC_MIB_CONNCLOSED);
		else
			TQUIC_INC_STATS(sock_net(ctx->conn->sk),
					TQUIC_MIB_CONNRESET);

		/* Track specific EQUIC error */
		enum linux_tquic_mib_field mib_field =
			tquic_equic_to_mib(error_code);
		if (mib_field != TQUIC_MIB_NUM)
			TQUIC_INC_STATS(sock_net(ctx->conn->sk), mib_field);
	}

	return 0;
}

/*
 * Process HANDSHAKE_DONE frame
 */
static int tquic_process_handshake_done_frame(struct tquic_rx_ctx *ctx)
{
	ctx->offset++; /* Skip frame type */

	/*
	 * RFC 9000 Section 19.20: "A server MUST NOT send a
	 * HANDSHAKE_DONE frame." Therefore only clients process it.
	 * Servers receiving HANDSHAKE_DONE is a protocol violation.
	 */
	if (ctx->conn->is_server) {
		tquic_dbg(
			"server received HANDSHAKE_DONE - protocol violation\n");
		ctx->conn->error_code = EQUIC_PROTOCOL_VIOLATION;
		return -EPROTO;
	}

	/* Mark handshake as complete (client side) */
	if (ctx->conn->crypto_state)
		ctx->conn->handshake_confirmed = true;

	/*
	 * CF-096: Transition to CONNECTED atomically.
	 *
	 * Use WRITE_ONCE() for the state assignment and validate
	 * the transition under the lock.  Only CONNECTING ->
	 * CONNECTED is valid here (RFC 9000 Section 19.20).
	 * Reject the transition if the connection has already
	 * moved to a later state (e.g. CLOSING due to a
	 * concurrent error), which would be an invalid backward
	 * transition.
	 *
	 * Also notify the socket layer so poll/epoll waiters see
	 * the new state promptly.
	 */
	spin_lock_bh(&ctx->conn->lock);
	if (ctx->conn->state == TQUIC_CONN_CONNECTING) {
		WRITE_ONCE(ctx->conn->state, TQUIC_CONN_CONNECTED);
		ctx->conn->handshake_complete = true;
		ctx->conn->stats.established_time = ktime_get();
		if (ctx->conn->sk)
			ctx->conn->sk->sk_state_change(ctx->conn->sk);
	}
	spin_unlock_bh(&ctx->conn->lock);

	ctx->ack_eliciting = true;

	return 0;
}

/*
 * Process NEW_TOKEN frame (RFC 9000 Section 8.1.3-8.1.4)
 *
 * NEW_TOKEN frames provide address validation tokens to clients
 * for use in future connections. This allows skipping the address
 * validation handshake on subsequent connections from the same client.
 *
 * Frame format:
 *   Type (0x07): 1 byte
 *   Token Length: varint
 *   Token: Token Length bytes
 *
 * Per RFC 9000: "A client MUST NOT send a NEW_TOKEN frame."
 * Only servers send NEW_TOKEN frames after handshake completion.
 */
static int tquic_process_new_token(struct tquic_rx_ctx *ctx)
{
	u64 token_len;
	int ret;

	ctx->offset++; /* Skip frame type */

	/* Parse token length */
	ret = tquic_decode_varint(ctx->data + ctx->offset,
				  ctx->len - ctx->offset, &token_len);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	/* RFC 9000 Section 19.7: Token MUST NOT be empty */
	if (token_len == 0)
		return -EINVAL;

	/*
	 * RFC 9000 Section 19.7: "A client MUST NOT send a NEW_TOKEN
	 * frame." If we are a server receiving this, the peer (client)
	 * sent it -- that is a protocol violation.
	 */
	if (ctx->conn && ctx->conn->is_server)
		return -EPROTO;

	/* Validate token length */
	if (token_len > TQUIC_TOKEN_MAX_LEN) {
		tquic_dbg("NEW_TOKEN too large: %llu > %u\n", token_len,
			  TQUIC_TOKEN_MAX_LEN);
		return -EINVAL;
	}

	if (ctx->offset + token_len > ctx->len)
		return -EINVAL;

	/* Process the token - delegate to token module */
	ret = tquic_process_new_token_frame(ctx->conn, ctx->data + ctx->offset,
					    token_len);
	if (ret < 0) {
		tquic_dbg("NEW_TOKEN processing failed: %d\n", ret);
		/* Update MIB counter for invalid token */
		if (ctx->conn && ctx->conn->sk)
			TQUIC_INC_STATS(sock_net(ctx->conn->sk),
					TQUIC_MIB_TOKENSINVALID);
	} else {
		/* Update MIB counter for token received */
		if (ctx->conn && ctx->conn->sk)
			TQUIC_INC_STATS(sock_net(ctx->conn->sk),
					TQUIC_MIB_NEWTOKENSRX);
	}

	ctx->offset += token_len;
	ctx->ack_eliciting = true;

	tquic_dbg("received NEW_TOKEN, len=%llu\n", token_len);

	return 0;
}

/*
 * Process DATAGRAM frame (RFC 9221)
 *
 * DATAGRAM frames carry unreliable, unordered application data.
 * Unlike STREAM frames, there is no retransmission or ordering.
 *
 * Wire parsing is delegated to tquic_parse_datagram_frame() which
 * handles both the 0x30 (no length) and 0x31 (with length) variants,
 * validates all bounds, and returns a tquic_frame with the data
 * pointer and length filled in.
 */
static int tquic_process_datagram_frame(struct tquic_rx_ctx *ctx)
{
	struct tquic_frame frame = {};
	u64 length;
	struct sk_buff *dgram_skb;
	int consumed;

	/*
	 * tquic_parse_datagram_frame() parses the frame type, optional
	 * length varint, and records a pointer into the packet buffer.
	 * It returns the total number of bytes consumed (type + length
	 * varint + data).  Security bounds-checking is centralised there.
	 */
	consumed = tquic_parse_datagram_frame(ctx->data + ctx->offset,
					      ctx->len - ctx->offset, &frame);
	if (consumed < 0)
		return consumed;

	length = frame.datagram.length;

	/* Check if datagram support is enabled on this connection */
	if (!ctx->conn || !ctx->conn->datagram.enabled) {
		/* RFC 9221: If not negotiated, this is a protocol error */
		tquic_dbg("received DATAGRAM but not negotiated\n");
		return -EPROTO;
	}

	/* Validate against negotiated maximum size */
	if (length > ctx->conn->datagram.max_recv_size) {
		tquic_dbg("DATAGRAM too large: %llu > %llu\n", length,
			  ctx->conn->datagram.max_recv_size);
		return -EMSGSIZE;
	}

	/* Queue datagram for delivery to application */
	spin_lock(&ctx->conn->datagram.lock);

	/* Check queue limit to prevent memory exhaustion */
	if (ctx->conn->datagram.recv_queue_len >=
	    ctx->conn->datagram.recv_queue_max) {
		/* Drop datagram (unreliable, so this is acceptable) */
		ctx->conn->datagram.datagrams_dropped++;
		spin_unlock(&ctx->conn->datagram.lock);
		/* Update MIB counter for dropped datagram */
		if (ctx->conn->sk)
			TQUIC_INC_STATS(sock_net(ctx->conn->sk),
					TQUIC_MIB_DATAGRAMSDROPPED);
		tquic_dbg("DATAGRAM dropped, queue full\n");
		/* Continue processing - this is not a fatal error */
		ctx->offset += consumed;
		ctx->ack_eliciting = true;
		return 0;
	}

	/* Allocate SKB for datagram */
	dgram_skb = alloc_skb(length, GFP_ATOMIC);
	if (!dgram_skb) {
		ctx->conn->datagram.datagrams_dropped++;
		spin_unlock(&ctx->conn->datagram.lock);
		/* Update MIB counter for dropped datagram */
		if (ctx->conn->sk)
			TQUIC_INC_STATS(sock_net(ctx->conn->sk),
					TQUIC_MIB_DATAGRAMSDROPPED);
		ctx->offset += consumed;
		ctx->ack_eliciting = true;
		return 0; /* Not fatal, continue */
	}

	/* Copy datagram payload using pointer from parsed frame */
	skb_put_data(dgram_skb, frame.datagram.data, length);

	/* Store receive timestamp in SKB cb -- ensure it fits */
	BUILD_BUG_ON(sizeof(struct timespec64) > sizeof(dgram_skb->cb));
	ktime_get_ts64((struct timespec64 *)dgram_skb->cb);

	/* Queue to receive buffer */
	skb_queue_tail(&ctx->conn->datagram.recv_queue, dgram_skb);
	ctx->conn->datagram.recv_queue_len++;
	ctx->conn->datagram.datagrams_received++;

	spin_unlock(&ctx->conn->datagram.lock);

	/* Update MIB counter for datagram receive */
	if (ctx->conn->sk)
		TQUIC_INC_STATS(sock_net(ctx->conn->sk), TQUIC_MIB_DATAGRAMSRX);

	/*
	 * Wake up waiters on both the datagram-specific wait queue
	 * (for tquic_recv_datagram blocking) and the socket wait queue
	 * (for poll/epoll/select).
	 */
	wake_up_interruptible(&ctx->conn->datagram.wait);
	if (ctx->conn->sk)
		ctx->conn->sk->sk_data_ready(ctx->conn->sk);

	/*
	 * Advance by the total number of bytes consumed by the frame
	 * (type byte + optional length varint + data), as returned by
	 * tquic_parse_datagram_frame().
	 */
	ctx->offset += consumed;
	ctx->ack_eliciting = true;

	tquic_dbg("received DATAGRAM, len=%llu\n", length);

	return 0;
}

/*
 * Process ACK_FREQUENCY frame (draft-ietf-quic-ack-frequency)
 *
 * ACK_FREQUENCY Frame {
 *   Type (i) = 0xaf,
 *   Sequence Number (i),
 *   Ack-Eliciting Threshold (i),
 *   Request Max Ack Delay (i),
 *   Reorder Threshold (i),
 * }
 *
 * This frame allows the sender to request changes to the peer's ACK behavior.
 */
static int tquic_process_ack_frequency_frame(struct tquic_rx_ctx *ctx)
{
	struct tquic_ack_frequency_frame frame;
	int ret;
	u64 frame_type;

	tquic_dbg("process_ack_frequency: pkt_num=%llu\n", ctx->pkt_num);

	/* Parse frame type */
	ret = tquic_decode_varint(ctx->data + ctx->offset,
				  ctx->len - ctx->offset, &frame_type);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	/* Parse the frame fields */
	ret = tquic_parse_ack_frequency_frame(ctx->data + ctx->offset,
					      ctx->len - ctx->offset, &frame);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	/* Handle the frame */
	ret = tquic_conn_handle_ack_frequency_frame(ctx->conn, &frame);
	if (ret < 0) {
		tquic_dbg("process_ack_frequency: handle failed=%d\n", ret);
		return ret;
	}

	ctx->ack_eliciting = true;

	return 0;
}

/*
 * Process IMMEDIATE_ACK frame (draft-ietf-quic-ack-frequency)
 *
 * IMMEDIATE_ACK Frame {
 *   Type (i) = 0xac,
 * }
 *
 * This frame requests that the peer send an ACK immediately.
 */
static int tquic_process_immediate_ack_frame(struct tquic_rx_ctx *ctx)
{
	int ret;
	u64 frame_type;

	/* Parse and validate frame type */
	ret = tquic_decode_varint(ctx->data + ctx->offset,
				  ctx->len - ctx->offset, &frame_type);
	if (ret < 0)
		return ret;

	if (frame_type != TQUIC_FRAME_IMMEDIATE_ACK)
		return -EINVAL;

	ctx->offset += ret;

	/*
	 * SECURITY: Only process the first IMMEDIATE_ACK per packet
	 * to prevent flooding attacks that force excessive ACK generation.
	 */
	if (ctx->immediate_ack_seen) {
		tquic_dbg("duplicate IMMEDIATE_ACK in packet, ignoring\n");
		ctx->ack_eliciting = true;
		return 0;
	}
	ctx->immediate_ack_seen = true;

	/* Handle the frame */
	ret = tquic_conn_handle_immediate_ack_frame(ctx->conn);
	if (ret < 0)
		return ret;

	ctx->ack_eliciting = true;

	tquic_dbg("processed IMMEDIATE_ACK frame\n");

	return 0;
}

/*
 * =============================================================================
 * RFC 9369 Multipath Frame Processing
 * =============================================================================
 */

#ifdef CONFIG_TQUIC_MULTIPATH

#include "../multipath/mp_frame.h"
#include "../multipath/mp_ack.h"
#include "../multipath/path_abandon.h"

/**
 * tquic_is_mp_extended_frame - Check if this is an extended MP frame
 * @ctx: Receive context
 *
 * Extended multipath frames have multi-byte frame types that start with
 * specific prefixes. This function peeks at the frame type without consuming it.
 */
static bool tquic_is_mp_extended_frame(struct tquic_rx_ctx *ctx)
{
	u64 frame_type;
	int ret;

	ret = tquic_decode_varint(ctx->data + ctx->offset,
				  ctx->len - ctx->offset, &frame_type);
	if (ret < 0)
		return false;

	tquic_dbg("is_mp_extended_frame: type=0x%llx\n", frame_type);

	/*
	 * Check for extended multipath frame types.
	 * Only 0x15c0-0x15c3 are defined (PATH_ABANDON, PATH_STATUS,
	 * PATH_STATUS_BACKUP, PATH_STATUS_AVAILABLE).
	 */
	return (frame_type >= 0x15c0 && frame_type <= 0x15c3);
}

static int tquic_process_path_abandon_frame(struct tquic_rx_ctx *ctx);
static int tquic_process_path_status_frame(struct tquic_rx_ctx *ctx);

/**
 * tquic_process_mp_extended_frame - Process extended multipath frames
 * @ctx: Receive context
 *
 * Handles PATH_ABANDON (0x15c0) and PATH_STATUS (0x15c1).
 */
static int tquic_process_mp_extended_frame(struct tquic_rx_ctx *ctx)
{
	u64 frame_type;
	int ret;

	ret = tquic_decode_varint(ctx->data + ctx->offset,
				  ctx->len - ctx->offset, &frame_type);
	if (ret < 0)
		return ret;

	if (frame_type == TQUIC_MP_FRAME_PATH_ABANDON) {
		return tquic_process_path_abandon_frame(ctx);
	} else if (frame_type == TQUIC_MP_FRAME_PATH_STATUS) {
		return tquic_process_path_status_frame(ctx);
	}

	tquic_dbg("unknown extended MP frame type 0x%llx\n", frame_type);
	return -EINVAL;
}

/**
 * tquic_process_path_abandon_frame - Process PATH_ABANDON frame
 * @ctx: Receive context
 *
 * RFC 9369: PATH_ABANDON frame indicates peer is abandoning a path.
 */
static int tquic_process_path_abandon_frame(struct tquic_rx_ctx *ctx)
{
	struct tquic_mp_path_abandon frame;
	int ret;

	ret = tquic_mp_parse_path_abandon(ctx->data + ctx->offset,
					  ctx->len - ctx->offset, &frame);
	if (ret < 0)
		return ret;

	ctx->offset += ret;
	ctx->ack_eliciting = true;

	/* Handle the frame */
	ret = tquic_mp_handle_path_abandon(ctx->conn, &frame);
	if (ret < 0) {
		tquic_dbg("PATH_ABANDON handling failed: %d\n", ret);
		return ret;
	}

	tquic_dbg("processed PATH_ABANDON for path %llu\n", frame.path_id);
	return 0;
}

/**
 * tquic_process_mp_new_connection_id_frame - Process MP_NEW_CONNECTION_ID
 * @ctx: Receive context
 *
 * RFC 9369: MP_NEW_CONNECTION_ID issues path-specific CIDs.
 */
static int tquic_process_mp_new_connection_id_frame(struct tquic_rx_ctx *ctx)
{
	struct tquic_mp_new_connection_id frame;
	int ret;

	ret = tquic_mp_parse_new_connection_id(ctx->data + ctx->offset,
					       ctx->len - ctx->offset, &frame);
	if (ret < 0)
		return ret;

	ctx->offset += ret;
	ctx->ack_eliciting = true;

	/* Handle the frame */
	ret = tquic_mp_handle_new_connection_id(ctx->conn, &frame);
	if (ret < 0) {
		tquic_dbg("MP_NEW_CONNECTION_ID handling failed: %d\n", ret);
		return ret;
	}

	tquic_dbg("processed MP_NEW_CONNECTION_ID path=%llu seq=%llu\n",
		  frame.path_id, frame.seq_num);
	return 0;
}

/**
 * tquic_process_mp_retire_connection_id_frame - Process MP_RETIRE_CONNECTION_ID
 * @ctx: Receive context
 *
 * RFC 9369: MP_RETIRE_CONNECTION_ID retires path-specific CIDs.
 */
static int tquic_process_mp_retire_connection_id_frame(struct tquic_rx_ctx *ctx)
{
	struct tquic_mp_retire_connection_id frame;
	int ret;

	ret = tquic_mp_parse_retire_connection_id(
		ctx->data + ctx->offset, ctx->len - ctx->offset, &frame);
	if (ret < 0)
		return ret;

	ctx->offset += ret;
	ctx->ack_eliciting = true;

	/* Handle the frame */
	ret = tquic_mp_handle_retire_connection_id(ctx->conn, &frame);
	if (ret < 0) {
		tquic_dbg("MP_RETIRE_CONNECTION_ID handling failed: %d\n", ret);
		return ret;
	}

	tquic_dbg("processed MP_RETIRE_CONNECTION_ID path=%llu seq=%llu\n",
		  frame.path_id, frame.seq_num);
	return 0;
}

/**
 * tquic_process_mp_ack_frame - Process MP_ACK frame
 * @ctx: Receive context
 *
 * RFC 9369: MP_ACK provides per-path acknowledgments.
 */
static int tquic_process_mp_ack_frame(struct tquic_rx_ctx *ctx)
{
	struct tquic_mp_ack *frame;
	struct tquic_path *path;
	struct tquic_mp_path_ack_state *ack_state;
	u8 ack_delay_exponent = 3; /* Default */
	int ret;

	/* Allocate frame on heap to avoid stack overflow (>4KB struct) */
	frame = kmalloc(sizeof(*frame), GFP_ATOMIC);
	if (!frame)
		return -ENOMEM;

	ret = tquic_mp_parse_ack(ctx->data + ctx->offset,
				 ctx->len - ctx->offset, frame,
				 ack_delay_exponent);
	if (ret < 0)
		goto out_free;

	ctx->offset += ret;
	/* MP_ACK is NOT ack-eliciting (RFC 9000 Section 13.2) */

	/*
	 * Find the path for this ACK.
	 * Keep paths_lock held during tquic_mp_on_ack_received() to
	 * prevent the path from being freed while we access it.
	 * tquic_mp_on_ack_received() must not sleep.
	 */
	spin_lock_bh(&ctx->conn->paths_lock);
	list_for_each_entry(path, &ctx->conn->paths, list) {
		if (path->path_id == frame->path_id) {
			ack_state = path->mp_ack_state;
			if (ack_state) {
				ret = tquic_mp_on_ack_received(
					ack_state, TQUIC_PN_SPACE_APPLICATION,
					frame, ctx->conn);
				spin_unlock_bh(&ctx->conn->paths_lock);
				if (ret < 0) {
					tquic_dbg(
						"MP_ACK processing failed: %d\n",
						ret);
					goto out_free;
				}
				tquic_dbg(
					"processed MP_ACK path=%llu largest=%llu\n",
					frame->path_id, frame->largest_ack);
				kfree(frame);
				return 0;
			}
			break;
		}
	}
	spin_unlock_bh(&ctx->conn->paths_lock);

	tquic_dbg("MP_ACK for unknown/uninitialized path %llu\n",
		  frame->path_id);
	ret = 0;

out_free:
	kfree(frame);
	return ret;
}

/**
 * tquic_process_path_status_frame - Process PATH_STATUS frame
 * @ctx: Receive context
 *
 * RFC 9369: PATH_STATUS reports path availability and priority.
 */
static int tquic_process_path_status_frame(struct tquic_rx_ctx *ctx)
{
	struct tquic_mp_path_status frame;
	int ret;

	ret = tquic_mp_parse_path_status(ctx->data + ctx->offset,
					 ctx->len - ctx->offset, &frame);
	if (ret < 0)
		return ret;

	ctx->offset += ret;
	ctx->ack_eliciting = true;

	/* Handle the frame */
	ret = tquic_mp_handle_path_status(ctx->conn, &frame);
	if (ret < 0) {
		tquic_dbg("PATH_STATUS handling failed: %d\n", ret);
		return ret;
	}

	tquic_dbg("processed PATH_STATUS path=%llu status=%llu\n",
		  frame.path_id, frame.status);
	return 0;
}

#endif /* CONFIG_TQUIC_MULTIPATH */

#ifdef CONFIG_TQUIC_FEC
static bool tquic_is_fec_frame(struct tquic_rx_ctx *ctx)
{
	u64 fec_type;
	int r = tquic_decode_varint(ctx->data + ctx->offset,
				    ctx->len - ctx->offset, &fec_type);

	return r > 0 && (fec_type == TQUIC_FRAME_FEC_REPAIR ||
			 fec_type == TQUIC_FRAME_FEC_SOURCE_INFO);
}

static int tquic_process_fec_frame(struct tquic_rx_ctx *ctx)
{
	struct tquic_connection *conn = ctx->conn;
	u64 fec_type;
	int fec_vlen;

	fec_vlen = tquic_decode_varint(ctx->data + ctx->offset,
				       ctx->len - ctx->offset, &fec_type);
	if (fec_vlen < 0)
		return -EPROTO;
	ctx->offset += fec_vlen;

	if (!conn->fec_state)
		return 0; /* FEC not initialised, skip frame */

	ctx->ack_eliciting = true;

	if (fec_type == TQUIC_FRAME_FEC_REPAIR) {
		struct tquic_fec_repair_frame rf;
		ssize_t n;

		n = tquic_fec_decode_repair_frame(ctx->data + ctx->offset,
						  ctx->len - ctx->offset, &rf);
		if (n < 0)
			return (int)n;
		ctx->offset += (size_t)n;
		return tquic_fec_receive_repair(conn->fec_state, &rf);
	} else {
		struct tquic_fec_source_info_frame sf;
		ssize_t n;

		n = tquic_fec_decode_source_info_frame(ctx->data + ctx->offset,
						       ctx->len - ctx->offset,
						       &sf);
		if (n < 0)
			return (int)n;
		ctx->offset += (size_t)n;
		return tquic_fec_receive_source(conn->fec_state, sf.block_id,
						sf.first_source_symbol_id,
						ctx->pkt_num, NULL, 0);
	}
}
#endif /* CONFIG_TQUIC_FEC */

/*
 * Demultiplex and process all frames in packet
 */
int tquic_process_frames(struct tquic_connection *conn, struct tquic_path *path,
			 u8 *payload, size_t len, int enc_level, u64 pkt_num)
{
	struct tquic_rx_ctx ctx = {};
	int ret = 0;
	u8 frame_type;
	size_t prev_offset;
	int frame_budget = 512; /* CF-610: limit frames per packet */
	bool is_0rtt = (enc_level == TQUIC_PKT_ZERO_RTT);
	bool is_1rtt = (enc_level == 3); /* Short header / Application */
	bool is_initial = (enc_level == TQUIC_PKT_INITIAL);
	bool is_handshake = (enc_level == TQUIC_PKT_HANDSHAKE);

	/*
	 * RFC 9000 Section 10.2: In DRAINING state, no frames should be
	 * processed. In CLOSING state, only CONNECTION_CLOSE is relevant
	 * (to determine if peer has also initiated close).
	 */
	if (READ_ONCE(conn->state) == TQUIC_CONN_DRAINING)
		return 0;

	ctx.conn = conn;
	ctx.path = path;
	ctx.data = payload;
	ctx.len = len;
	ctx.offset = 0;
	ctx.pkt_num = pkt_num;
	ctx.enc_level = enc_level;
	ctx.ack_eliciting = false;
	ctx.immediate_ack_seen = false;
	ctx.saw_stream_no_length = false;
	ctx.ack_frame_seen = false;
	ctx.key_phase_bit = 0;

	while (ctx.offset < ctx.len) {
		prev_offset = ctx.offset;

		if (is_initial)
			pr_debug(
				"process_frames: offset=%zu/%zu frame_type=0x%02x\n",
				ctx.offset, ctx.len, ctx.data[ctx.offset]);

		/* CF-610: Enforce per-packet frame processing budget */
		if (--frame_budget <= 0) {
			tquic_dbg("frame budget exhausted\n");
			return -EPROTO;
		}

		/*
		 * CF-012: A STREAM frame without a Length field consumes
		 * all remaining bytes in the packet (RFC 9000 Section
		 * 19.8).  Any trailing bytes after such a frame are
		 * malformed -- reject the packet to prevent data being
		 * silently queued from an invalid frame sequence.
		 */
		if (ctx.saw_stream_no_length) {
			tquic_dbg(
				"trailing data after length-less STREAM frame\n");
			return -EPROTO;
		}

		frame_type = ctx.data[ctx.offset];

		/*
		 * RFC 9000 Section 10.2.1: In CLOSING state, only
		 * CONNECTION_CLOSE frames are processed. All other
		 * frames are silently ignored.
		 */
		/* CLOSING is rare in steady-state 1-RTT data transfer. */
		if (unlikely(READ_ONCE(conn->state) == TQUIC_CONN_CLOSING)) {
			if (frame_type != TQUIC_FRAME_CONNECTION_CLOSE &&
			    frame_type != TQUIC_FRAME_CONNECTION_CLOSE_APP)
				return 0;
		}

		/*
		 * RFC 9000 Section 12.4, Table 3: Validate frame types
		 * against the current encryption level.
		 *
		 * - PADDING, PING, CONNECTION_CLOSE: all levels
		 * - ACK/ACK_ECN: all except 0-RTT
		 * - CRYPTO: Initial, Handshake, 1-RTT (not 0-RTT)
		 * - STREAM (0x08-0x0f): 0-RTT and 1-RTT only
		 * - HANDSHAKE_DONE (0x1e): 1-RTT only
		 * - NEW_TOKEN (0x07): 1-RTT only
		 * - Most other frames: 0-RTT and 1-RTT only
		 *
		 * Dispatch order: STREAM first (dominant in 1-RTT data
		 * transfer), then ACK (dominant in ACK-only packets), then
		 * rare control frames.  likely()/unlikely() guide branch
		 * prediction on modern CPUs.
		 */

		/* Handle frame based on type */
		if (likely((frame_type & 0xf8) == TQUIC_FRAME_STREAM)) {
			/* STREAM frames only in 0-RTT and 1-RTT */
			if (unlikely(is_initial || is_handshake)) {
				conn->error_code = EQUIC_FRAME_ENCODING;
				tquic_conn_close_with_error(
					conn, EQUIC_FRAME_ENCODING,
					"STREAM in Initial/Handshake");
				return -EPROTO;
			}
			ret = tquic_process_stream_frame(&ctx);
		} else if (likely(frame_type == TQUIC_FRAME_ACK ||
				  frame_type == TQUIC_FRAME_ACK_ECN)) {
			/* CF-283: Limit to one ACK frame per packet */
			if (ctx.ack_frame_seen)
				return -EPROTO;
			ctx.ack_frame_seen = true;
			/* ACK frames forbidden in 0-RTT packets */
			if (unlikely(is_0rtt)) {
				conn->error_code = EQUIC_FRAME_ENCODING;
				tquic_conn_close_with_error(
					conn, EQUIC_FRAME_ENCODING,
					"ACK in 0-RTT");
				return -EPROTO;
			}
			ret = tquic_process_ack_frame(&ctx);
		} else if (frame_type == TQUIC_FRAME_PADDING) {
			ret = tquic_process_padding_frame(&ctx);
		} else if (frame_type == TQUIC_FRAME_PING) {
			ret = tquic_process_ping_frame(&ctx);
		} else if (frame_type == TQUIC_FRAME_CRYPTO) {
			/* CRYPTO frames forbidden in 0-RTT */
			if (is_0rtt) {
				conn->error_code = EQUIC_FRAME_ENCODING;
				tquic_conn_close_with_error(
					conn, EQUIC_FRAME_ENCODING,
					"CRYPTO in 0-RTT");
				return -EPROTO;
			}
			ret = tquic_process_crypto_frame(&ctx);
		} else if (frame_type == TQUIC_FRAME_NEW_TOKEN) {
			/* NEW_TOKEN only in 1-RTT */
			if (!is_1rtt) {
				conn->error_code = EQUIC_FRAME_ENCODING;
				tquic_conn_close_with_error(
					conn, EQUIC_FRAME_ENCODING,
					"NEW_TOKEN not in 1-RTT");
				return -EPROTO;
			}
			ret = tquic_process_new_token(&ctx);
		} else if (frame_type == TQUIC_FRAME_MAX_DATA) {
			if (is_initial || is_handshake) {
				conn->error_code = EQUIC_FRAME_ENCODING;
				tquic_conn_close_with_error(
					conn, EQUIC_FRAME_ENCODING,
					"MAX_DATA in Initial/Handshake");
				return -EPROTO;
			}
			ret = tquic_process_max_data_frame(&ctx);
		} else if (frame_type == TQUIC_FRAME_MAX_STREAM_DATA) {
			if (is_initial || is_handshake) {
				conn->error_code = EQUIC_FRAME_ENCODING;
				tquic_conn_close_with_error(
					conn, EQUIC_FRAME_ENCODING,
					"MAX_STREAM_DATA in Initial/HS");
				return -EPROTO;
			}
			ret = tquic_process_max_stream_data_frame(&ctx);
		} else if (frame_type == TQUIC_FRAME_RESET_STREAM) {
			if (is_initial || is_handshake) {
				conn->error_code = EQUIC_FRAME_ENCODING;
				tquic_conn_close_with_error(
					conn, EQUIC_FRAME_ENCODING,
					"RESET_STREAM in Initial/HS");
				return -EPROTO;
			}
			ret = tquic_process_reset_stream_frame(&ctx);
		} else if (frame_type == TQUIC_FRAME_STOP_SENDING) {
			if (is_initial || is_handshake) {
				conn->error_code = EQUIC_FRAME_ENCODING;
				tquic_conn_close_with_error(
					conn, EQUIC_FRAME_ENCODING,
					"STOP_SENDING in Initial/HS");
				return -EPROTO;
			}
			ret = tquic_process_stop_sending_frame(&ctx);
		} else if (frame_type == TQUIC_FRAME_MAX_STREAMS_BIDI ||
			   frame_type == TQUIC_FRAME_MAX_STREAMS_UNI) {
			if (is_initial || is_handshake) {
				conn->error_code = EQUIC_FRAME_ENCODING;
				tquic_conn_close_with_error(
					conn, EQUIC_FRAME_ENCODING,
					"MAX_STREAMS in Initial/HS");
				return -EPROTO;
			}
			ret = tquic_process_max_streams_frame(
				&ctx,
				frame_type == TQUIC_FRAME_MAX_STREAMS_BIDI);
		} else if (frame_type == TQUIC_FRAME_DATA_BLOCKED) {
			if (is_initial || is_handshake) {
				conn->error_code = EQUIC_FRAME_ENCODING;
				tquic_conn_close_with_error(
					conn, EQUIC_FRAME_ENCODING,
					"DATA_BLOCKED in Initial/HS");
				return -EPROTO;
			}
			ret = tquic_process_data_blocked_frame(&ctx);
		} else if (frame_type == TQUIC_FRAME_STREAM_DATA_BLOCKED) {
			if (is_initial || is_handshake) {
				conn->error_code = EQUIC_FRAME_ENCODING;
				tquic_conn_close_with_error(
					conn, EQUIC_FRAME_ENCODING,
					"STREAM_DATA_BLOCKED in IH");
				return -EPROTO;
			}
			ret = tquic_process_stream_data_blocked_frame(&ctx);
		} else if (frame_type == TQUIC_FRAME_STREAMS_BLOCKED_BIDI ||
			   frame_type == TQUIC_FRAME_STREAMS_BLOCKED_UNI) {
			if (is_initial || is_handshake) {
				conn->error_code = EQUIC_FRAME_ENCODING;
				tquic_conn_close_with_error(
					conn, EQUIC_FRAME_ENCODING,
					"STREAMS_BLOCKED in I/HS");
				return -EPROTO;
			}
			ret = tquic_process_streams_blocked_frame(
				&ctx,
				frame_type == TQUIC_FRAME_STREAMS_BLOCKED_BIDI);
		} else if (frame_type == TQUIC_FRAME_PATH_CHALLENGE) {
			if (is_initial || is_handshake) {
				conn->error_code = EQUIC_FRAME_ENCODING;
				tquic_conn_close_with_error(
					conn, EQUIC_FRAME_ENCODING,
					"PATH_CHALLENGE in Initial/HS");
				return -EPROTO;
			}
			ret = tquic_process_path_challenge_frame(&ctx);
		} else if (frame_type == TQUIC_FRAME_PATH_RESPONSE) {
			if (is_initial || is_handshake) {
				conn->error_code = EQUIC_FRAME_ENCODING;
				tquic_conn_close_with_error(
					conn, EQUIC_FRAME_ENCODING,
					"PATH_RESPONSE in Initial/HS");
				return -EPROTO;
			}
			ret = tquic_process_path_response_frame(&ctx);
		} else if (frame_type == TQUIC_FRAME_NEW_CONNECTION_ID) {
			if (is_initial || is_handshake) {
				conn->error_code = EQUIC_FRAME_ENCODING;
				tquic_conn_close_with_error(
					conn, EQUIC_FRAME_ENCODING,
					"NEW_CID in Initial/HS");
				return -EPROTO;
			}
			ret = tquic_process_new_connection_id_frame(&ctx);
		} else if (frame_type == TQUIC_FRAME_RETIRE_CONNECTION_ID) {
			if (is_initial || is_handshake) {
				conn->error_code = EQUIC_FRAME_ENCODING;
				tquic_conn_close_with_error(
					conn, EQUIC_FRAME_ENCODING,
					"RETIRE_CID in Initial/HS");
				return -EPROTO;
			}
			ret = tquic_process_retire_connection_id_frame(&ctx);
		} else if (frame_type == TQUIC_FRAME_CONNECTION_CLOSE) {
			ret = tquic_process_connection_close_frame(&ctx, false);
		} else if (frame_type == TQUIC_FRAME_CONNECTION_CLOSE_APP) {
			ret = tquic_process_connection_close_frame(&ctx, true);
		} else if (frame_type == TQUIC_FRAME_HANDSHAKE_DONE) {
			/* HANDSHAKE_DONE only in 1-RTT */
			if (!is_1rtt) {
				conn->error_code = EQUIC_FRAME_ENCODING;
				tquic_conn_close_with_error(
					conn, EQUIC_FRAME_ENCODING,
					"HANDSHAKE_DONE not in 1-RTT");
				return -EPROTO;
			}
			ret = tquic_process_handshake_done_frame(&ctx);
		} else if ((frame_type & 0xfe) == TQUIC_FRAME_DATAGRAM) {
			if (is_initial || is_handshake) {
				conn->error_code = EQUIC_FRAME_ENCODING;
				tquic_conn_close_with_error(
					conn, EQUIC_FRAME_ENCODING,
					"DATAGRAM in Initial/HS");
				return -EPROTO;
			}
			ret = tquic_process_datagram_frame(&ctx);
		} else if (frame_type == TQUIC_FRAME_ACK_FREQUENCY) {
			/*
			 * ACK_FREQUENCY is only valid in 1-RTT packets
			 * per draft-ietf-quic-ack-frequency Section 3.
			 */
			if (!is_1rtt) {
				conn->error_code = EQUIC_FRAME_ENCODING;
				tquic_conn_close_with_error(
					conn, EQUIC_FRAME_ENCODING,
					"ACK_FREQUENCY not in 1-RTT");
				return -EPROTO;
			}
			ret = tquic_process_ack_frequency_frame(&ctx);
		} else if (frame_type == TQUIC_FRAME_IMMEDIATE_ACK) {
			/*
			 * IMMEDIATE_ACK is only valid in 1-RTT packets
			 * per draft-ietf-quic-ack-frequency Section 4.
			 */
			if (!is_1rtt) {
				conn->error_code = EQUIC_FRAME_ENCODING;
				tquic_conn_close_with_error(
					conn, EQUIC_FRAME_ENCODING,
					"IMMEDIATE_ACK not in 1-RTT");
				return -EPROTO;
			}
			ret = tquic_process_immediate_ack_frame(&ctx);
#ifdef CONFIG_TQUIC_MULTIPATH
		} else if (frame_type == 0x40) {
			/* MP_NEW_CONNECTION_ID - CF-281: 1-RTT only */
			if (!is_1rtt) {
				conn->error_code = EQUIC_FRAME_ENCODING;
				tquic_conn_close_with_error(
					conn, EQUIC_FRAME_ENCODING,
					"MP frame not in 1-RTT");
				return -EPROTO;
			}
			ret = tquic_process_mp_new_connection_id_frame(&ctx);
		} else if (frame_type == 0x41) {
			/* MP_RETIRE_CONNECTION_ID - CF-281: 1-RTT only */
			if (!is_1rtt) {
				conn->error_code = EQUIC_FRAME_ENCODING;
				tquic_conn_close_with_error(
					conn, EQUIC_FRAME_ENCODING,
					"MP frame not in 1-RTT");
				return -EPROTO;
			}
			ret = tquic_process_mp_retire_connection_id_frame(&ctx);
		} else if (frame_type == 0x42 || frame_type == 0x43) {
			/* MP_ACK or MP_ACK_ECN - CF-281: 1-RTT only */
			if (!is_1rtt) {
				conn->error_code = EQUIC_FRAME_ENCODING;
				tquic_conn_close_with_error(
					conn, EQUIC_FRAME_ENCODING,
					"MP frame not in 1-RTT");
				return -EPROTO;
			}
			ret = tquic_process_mp_ack_frame(&ctx);
		} else if (tquic_is_mp_extended_frame(&ctx)) {
			/* Extended multipath frames - CF-281: 1-RTT only */
			if (!is_1rtt) {
				conn->error_code = EQUIC_FRAME_ENCODING;
				tquic_conn_close_with_error(
					conn, EQUIC_FRAME_ENCODING,
					"MP frame not in 1-RTT");
				return -EPROTO;
			}
			ret = tquic_process_mp_extended_frame(&ctx);
#endif
#ifdef CONFIG_TQUIC_FEC
		} else if (tquic_is_fec_frame(&ctx)) {
			/* FEC frames only valid in 1-RTT (application level) */
			if (!is_1rtt) {
				conn->error_code = EQUIC_FRAME_ENCODING;
				tquic_conn_close_with_error(
					conn, EQUIC_FRAME_ENCODING,
					"FEC frame not in 1-RTT");
				return -EPROTO;
			}
			ret = tquic_process_fec_frame(&ctx);
#endif /* CONFIG_TQUIC_FEC */
		} else {
			/*
			 * Unknown frame type - RFC 9000 Section 12.4:
			 * "An endpoint MUST treat the receipt of a frame of
			 * unknown type as a connection error of type
			 * FRAME_ENCODING_ERROR."
			 *
			 * tquic_frame_type_name() provides a canonical name
			 * for any frame type byte, returning "UNKNOWN" for
			 * unrecognised values, enabling consistent diagnostics.
			 */
			tquic_dbg("unknown frame type 0x%02x (%s)\n",
				  frame_type,
				  tquic_frame_type_name(frame_type));
			conn->error_code = EQUIC_FRAME_ENCODING;
			tquic_conn_close_with_error(conn, EQUIC_FRAME_ENCODING,
						    "unknown frame type");
			return -EPROTO;
		}

		if (ret < 0) {
			if (is_initial)
				pr_debug("process_frames: handler ret=%d "
					 "for frame 0x%02x (%s) at offset=%zu\n",
					 ret, frame_type,
					 tquic_frame_type_name(frame_type),
					 prev_offset);
			break;
		}

		/*
		 * Consolidate ack-eliciting status using the canonical
		 * tquic_frame_is_ack_eliciting() predicate (RFC 9000
		 * Section 13.2).  Individual handlers may set
		 * ctx.ack_eliciting = true for their frame type;
		 * this OR-in ensures the flag is always set correctly
		 * even if a handler forgets to do so.
		 */
		if (tquic_frame_is_ack_eliciting(frame_type))
			ctx.ack_eliciting = true;

		/* Detect stuck parsing (no progress made) */
		if (ctx.offset == prev_offset) {
			if (is_initial)
				pr_debug("process_frames: stuck at offset=%zu "
					 "frame=0x%02x (%s)\n",
					 ctx.offset, frame_type,
					 tquic_frame_type_name(frame_type));
			return -EPROTO;
		}
	}

	/*
	 * RFC 9000 Section 13.2: Send ACK for ack-eliciting packets.
	 * RFC 9000 Section 13.2.1: An endpoint SHOULD use a delayed
	 * ACK strategy to reduce the number of ACK frames sent.
	 *
	 * Use the delayed ACK timer when available, otherwise send
	 * immediately for correctness.
	 */
	if (ctx.ack_eliciting && ret >= 0 && is_1rtt) {
		if (conn->timer_state) {
			tquic_timer_set_ack_delay(conn->timer_state);
		} else {
			struct tquic_path *ack_path;

			rcu_read_lock();
			ack_path = rcu_dereference(conn->active_path);
			if (ack_path)
				tquic_send_ack(conn, ack_path, pkt_num, 0, 0);
			rcu_read_unlock();
		}
	}

	return ret;
}
