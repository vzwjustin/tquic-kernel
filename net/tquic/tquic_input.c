// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Packet Reception Path
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Implements the QUIC packet reception path with multipath WAN bonding
 * support including UDP receive callbacks, header unprotection,
 * packet decryption, frame demultiplexing, and connection lookup.
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
#include <net/sock.h>
#include <net/udp.h>
#include <net/udp_tunnel.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/gro.h>
#include <crypto/aead.h>
#include <net/tquic.h>

#include "tquic_compat.h"
#include "tquic_debug.h"
#include "tquic_mib.h"
#include "cong/tquic_cong.h"
#include "crypto/key_update.h"
#include "crypto/zero_rtt.h"
#include "tquic_stateless_reset.h"
#include "tquic_token.h"
#include "tquic_retry.h"
#include "tquic_ack_frequency.h"
#include "tquic_ratelimit.h"
#include "rate_limit.h"

/* Per-packet RX decryption buffer slab cache (allocated in tquic_main.c) */
#define TQUIC_RX_BUF_SIZE	2048
extern struct kmem_cache *tquic_rx_buf_cache;

/* Maximum ACK ranges to prevent resource exhaustion from malicious frames */
#define TQUIC_MAX_ACK_RANGES		256

/* QUIC frame types (must match tquic_output.c) */
#define TQUIC_FRAME_PADDING		0x00
#define TQUIC_FRAME_PING		0x01
#define TQUIC_FRAME_ACK			0x02
#define TQUIC_FRAME_ACK_ECN		0x03
#define TQUIC_FRAME_RESET_STREAM	0x04
#define TQUIC_FRAME_STOP_SENDING	0x05
#define TQUIC_FRAME_CRYPTO		0x06
#define TQUIC_FRAME_NEW_TOKEN		0x07
#define TQUIC_FRAME_STREAM		0x08  /* 0x08-0x0f */
#define TQUIC_FRAME_MAX_DATA		0x10
#define TQUIC_FRAME_MAX_STREAM_DATA	0x11
#define TQUIC_FRAME_MAX_STREAMS_BIDI	0x12
#define TQUIC_FRAME_MAX_STREAMS_UNI	0x13
#define TQUIC_FRAME_DATA_BLOCKED	0x14
#define TQUIC_FRAME_STREAM_DATA_BLOCKED	0x15
#define TQUIC_FRAME_STREAMS_BLOCKED_BIDI 0x16
#define TQUIC_FRAME_STREAMS_BLOCKED_UNI	0x17
#define TQUIC_FRAME_NEW_CONNECTION_ID	0x18
#define TQUIC_FRAME_RETIRE_CONNECTION_ID 0x19
#define TQUIC_FRAME_PATH_CHALLENGE	0x1a
#define TQUIC_FRAME_PATH_RESPONSE	0x1b
#define TQUIC_FRAME_CONNECTION_CLOSE	0x1c
#define TQUIC_FRAME_CONNECTION_CLOSE_APP 0x1d
#define TQUIC_FRAME_HANDSHAKE_DONE	0x1e
#define TQUIC_FRAME_DATAGRAM		0x30  /* 0x30-0x31 */
/* ACK frequency frame types defined in core/ack_frequency.h */
/* Packet header constants */
#define TQUIC_HEADER_FORM_LONG		0x80
#define TQUIC_HEADER_FIXED_BIT		0x40
#define TQUIC_HEADER_SPIN_BIT		0x20
#define TQUIC_HEADER_KEY_PHASE		0x04

/* Long header packet types */
#define TQUIC_PKT_INITIAL		0x00
#define TQUIC_PKT_ZERO_RTT		0x01
#define TQUIC_PKT_HANDSHAKE		0x02
#define TQUIC_PKT_RETRY			0x03

/* Version constants */
#define TQUIC_VERSION_NEGOTIATION	0x00000000

/* Stateless reset */
#undef TQUIC_STATELESS_RESET_MIN_LEN
#define TQUIC_STATELESS_RESET_MIN_LEN	22  /* RFC 9000 Section 10.3 */
#define TQUIC_STATELESS_RESET_TOKEN_LEN	16

/* GRO configuration */
#define TQUIC_GRO_MAX_HOLD		10
#define TQUIC_GRO_FLUSH_TIMEOUT_US	1000

/* Forward declarations */
static int tquic_process_frames(struct tquic_connection *conn,
				struct tquic_path *path,
				u8 *payload, size_t len,
				int enc_level, u64 pkt_num);

/* From tquic_handshake.c - inline TLS handshake processing */
int tquic_inline_hs_recv_crypto(struct sock *sk, const u8 *data, u32 len,
				int enc_level);
/*
 * Per-path ECN tracking state for detecting CE count increases
 * Per RFC 9002 Section 7.1: Only respond to *increases* in CE count
 */
struct tquic_ecn_tracking {
	u64 ect0_count;		/* Previous ECT(0) count from peer */
	u64 ect1_count;		/* Previous ECT(1) count from peer */
	u64 ce_count;		/* Previous CE count from peer */
	bool validated;		/* ECN path validation complete */
};

/* Receive context for packet processing */
struct tquic_rx_ctx {
	struct tquic_connection *conn;
	struct tquic_path *path;
	struct sk_buff *skb;
	u8 *data;
	size_t len;
	size_t offset;
	u64 pkt_num;
	int enc_level;
	bool is_long_header;
	bool ack_eliciting;
	u8 key_phase_bit;  /* Key phase from short header (RFC 9001 Section 6) */
};

/* GRO state per socket */
struct tquic_gro_state {
	struct sk_buff_head hold_queue;
	spinlock_t lock;
	struct hrtimer flush_timer;
	int held_count;
	ktime_t first_hold_time;
};

/*
 * =============================================================================
 * Variable Length Integer Decoding (QUIC RFC 9000)
 * =============================================================================
 */

static inline int tquic_decode_varint(const u8 *buf, size_t buf_len, u64 *val)
{
	u8 prefix;
	int len;

	if (buf_len < 1)
		return -EINVAL;

	prefix = buf[0] >> 6;
	len = 1 << prefix;

	if (buf_len < len)
		return -EINVAL;

	switch (len) {
	case 1:
		*val = buf[0] & 0x3f;
		break;
	case 2:
		*val = ((u64)(buf[0] & 0x3f) << 8) | buf[1];
		break;
	case 4:
		*val = ((u64)(buf[0] & 0x3f) << 24) |
		       ((u64)buf[1] << 16) |
		       ((u64)buf[2] << 8) |
		       buf[3];
		break;
	case 8:
		*val = ((u64)(buf[0] & 0x3f) << 56) |
		       ((u64)buf[1] << 48) |
		       ((u64)buf[2] << 40) |
		       ((u64)buf[3] << 32) |
		       ((u64)buf[4] << 24) |
		       ((u64)buf[5] << 16) |
		       ((u64)buf[6] << 8) |
		       buf[7];
		break;
	}

	return len;
}

/*
 * =============================================================================
 * Connection Lookup by CID
 * =============================================================================
 */

/*
 * Look up connection by destination CID from packet
 */
static struct tquic_connection *tquic_lookup_by_dcid(const u8 *dcid, u8 dcid_len)
{
	struct tquic_cid cid;

	if (unlikely(dcid_len > TQUIC_MAX_CID_LEN))
		return NULL;

	cid.len = dcid_len;
	memcpy(cid.id, dcid, dcid_len);
	cid.seq_num = 0;
	cid.retire_prior_to = 0;

	/* Use the exported lookup function from core/connection.c */
	return tquic_conn_lookup_by_cid(&cid);
}

/*
 * Find path by source address
 */
static struct tquic_path *tquic_find_path_by_addr(struct tquic_connection *conn,
						  struct sockaddr_storage *addr)
{
	struct tquic_path *path;

	list_for_each_entry(path, &conn->paths, list) {
		if (memcmp(&path->remote_addr, addr, sizeof(*addr)) == 0)
			return path;
	}

	return NULL;
}

/*
 * Find path by local connection ID
 */
static struct tquic_path __maybe_unused *tquic_find_path_by_cid(struct tquic_connection *conn,
							       const u8 *cid, u8 cid_len)
{
	struct tquic_path *path;

	list_for_each_entry(path, &conn->paths, list) {
		if (path->local_cid.len == cid_len &&
		    memcmp(path->local_cid.id, cid, cid_len) == 0)
			return path;
	}

	return NULL;
}

/*
 * =============================================================================
 * Header Unprotection
 * =============================================================================
 */

/*
 * Remove header protection
 */
static int tquic_remove_header_protection(struct tquic_connection *conn,
					  u8 *header, int header_len,
					  u8 *payload, int payload_len,
					  bool is_long_header)
{
	/* Header protection removal is the inverse of application */
	/* For initial implementation, assume header protection is disabled */
	return 0;
}

/*
 * =============================================================================
 * Packet Decryption
 * =============================================================================
 */

/*
 * Decrypt packet payload
 */
static int tquic_decrypt_payload(struct tquic_connection *conn,
				 u8 *header, int header_len,
				 u8 *payload, int payload_len,
				 u64 pkt_num, int enc_level,
				 u8 *out, size_t *out_len)
{
	if (conn->crypto_state) {
		return tquic_decrypt_packet(conn->crypto_state,
					    header, header_len,
					    payload, payload_len,
					    pkt_num, out, out_len);
	}

	/* No crypto state - cannot process packet */
	return -ENOKEY;
}

/*
 * =============================================================================
 * Stateless Reset Detection
 * =============================================================================
 */

/*
 * Check if packet is a stateless reset
 *
 * Per RFC 9000 Section 10.3.1:
 * "An endpoint detects a potential stateless reset using the last
 * 16 bytes of the UDP datagram. An endpoint remembers all stateless
 * reset tokens associated with the connection IDs and remote addresses
 * for datagrams it has recently sent."
 */
static bool tquic_is_stateless_reset_internal(struct tquic_connection *conn,
				     const u8 *data, size_t len)
{
	/*
	 * Use the new detection API which checks against all tokens
	 * stored from NEW_CONNECTION_ID frames received from the peer.
	 */
	return tquic_stateless_reset_detect_conn(conn, data, len);
}

/*
 * Handle stateless reset
 */
static void tquic_handle_stateless_reset(struct tquic_connection *conn)
{
	tquic_info("received stateless reset for connection\n");

	spin_lock_bh(&conn->lock);
	conn->state = TQUIC_CONN_CLOSED;
	spin_unlock_bh(&conn->lock);

	/* Notify upper layer */
	if (conn->sk)
		conn->sk->sk_state_change(conn->sk);
}

/*
 * =============================================================================
 * Version Negotiation
 * =============================================================================
 */

/*
 * Check if packet is version negotiation
 */
static bool tquic_is_version_negotiation(const u8 *data, size_t len)
{
	u32 version;

	if (len < 7)  /* Minimum long header */
		return false;

	if (!(data[0] & TQUIC_HEADER_FORM_LONG))
		return false;

	version = (data[1] << 24) | (data[2] << 16) | (data[3] << 8) | data[4];

	return version == TQUIC_VERSION_NEGOTIATION;
}

/*
 * Process version negotiation packet
 */
static int tquic_process_version_negotiation(struct tquic_connection *conn,
					     const u8 *data, size_t len)
{
	u8 dcid_len, scid_len;
	const u8 *versions;
	size_t versions_len;
	int i;
	bool found = false;

	if (len < 7)
		return -EINVAL;

	/*
	 * SECURITY: Validate CID lengths before use as offsets.
	 * RFC 9000 limits CID to 20 bytes. Without this check, a crafted
	 * dcid_len of 255 would cause 6 + dcid_len to overflow u8 arithmetic.
	 * Use size_t arithmetic to prevent narrowing issues.
	 */
	dcid_len = data[5];
	if (dcid_len > TQUIC_MAX_CID_LEN)
		return -EINVAL;
	if (len < (size_t)6 + dcid_len + 1)
		return -EINVAL;

	scid_len = data[6 + dcid_len];
	if (scid_len > TQUIC_MAX_CID_LEN)
		return -EINVAL;
	if (len < (size_t)7 + dcid_len + scid_len)
		return -EINVAL;

	versions = data + 7 + dcid_len + scid_len;
	versions_len = len - 7 - dcid_len - scid_len;

	tquic_dbg("received version negotiation, offered versions:\n");

	/* Check each offered version */
	for (i = 0; i + 4 <= versions_len; i += 4) {
		u32 version = (versions[i] << 24) | (versions[i + 1] << 16) |
			      (versions[i + 2] << 8) | versions[i + 3];

		tquic_dbg("  version 0x%08x\n", version);

		if (version == TQUIC_VERSION_1 || version == TQUIC_VERSION_2)
			found = true;
	}

	if (!found) {
		tquic_warn("conn: no compatible version found (local supports v1/v2)\n");
		conn->state = TQUIC_CONN_CLOSED;
		return -EPROTONOSUPPORT;
	}

	/* Retry with a compatible version */
	/* This would trigger a new Initial packet with the selected version */

	return 0;
}

/*
 * Send version negotiation response (server side)
 */
static int __maybe_unused tquic_send_version_negotiation_internal(struct sock *sk,
					  const struct sockaddr *addr,
					  const u8 *dcid, u8 dcid_len,
					  const u8 *scid, u8 scid_len)
{
	struct sk_buff *skb;
	u8 *p;
	static const u32 supported_versions[] = {
		TQUIC_VERSION_1,
		TQUIC_VERSION_2,
	};
	int i;
	size_t pkt_len;

	pkt_len = 7 + dcid_len + scid_len + sizeof(supported_versions);

	skb = alloc_skb(pkt_len + MAX_HEADER, GFP_ATOMIC);
	if (!skb)
		return -ENOMEM;

	skb_reserve(skb, MAX_HEADER);
	p = skb_put(skb, pkt_len);

	/* First byte with random bits, long header form */
	get_random_bytes(p, 1);
	p[0] |= TQUIC_HEADER_FORM_LONG;
	p++;

	/* Version = 0 for version negotiation */
	memset(p, 0, 4);
	p += 4;

	/* DCID (echo back client's SCID) */
	*p++ = scid_len;
	memcpy(p, scid, scid_len);
	p += scid_len;

	/* SCID (echo back client's DCID) */
	*p++ = dcid_len;
	memcpy(p, dcid, dcid_len);
	p += dcid_len;

	/* Supported versions */
	for (i = 0; i < ARRAY_SIZE(supported_versions); i++) {
		*p++ = (supported_versions[i] >> 24) & 0xff;
		*p++ = (supported_versions[i] >> 16) & 0xff;
		*p++ = (supported_versions[i] >> 8) & 0xff;
		*p++ = supported_versions[i] & 0xff;
	}

	/* Send via UDP */
	/* This would use the socket's send path */
	kfree_skb(skb);

	return 0;
}

/*
 * =============================================================================
 * Frame Demultiplexing
 * =============================================================================
 */

/*
 * Process PADDING frame
 */
static int tquic_process_padding_frame(struct tquic_rx_ctx *ctx)
{
	/* Just skip padding bytes */
	while (ctx->offset < ctx->len && ctx->data[ctx->offset] == 0)
		ctx->offset++;

	return 0;
}

/*
 * Process PING frame
 */
static int tquic_process_ping_frame(struct tquic_rx_ctx *ctx)
{
	ctx->offset++;  /* Skip frame type */
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
	bool has_ecn;
	u8 frame_type;
	int ret;
	u64 i;

	frame_type = ctx->data[ctx->offset];
	has_ecn = (frame_type == TQUIC_FRAME_ACK_ECN);
	ctx->offset++;  /* Skip frame type */

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

	/* Process additional ACK ranges */
	for (i = 0; i < ack_range_count; i++) {
		u64 gap, range;

		ret = tquic_decode_varint(ctx->data + ctx->offset,
					  ctx->len - ctx->offset, &gap);
		if (ret < 0)
			return ret;
		ctx->offset += ret;

		ret = tquic_decode_varint(ctx->data + ctx->offset,
					  ctx->len - ctx->offset, &range);
		if (ret < 0)
			return ret;
		ctx->offset += ret;
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

		/* Update MIB counters for ECN frames received */
		if (ctx->conn && ctx->conn->sk) {
			struct net *net = sock_net(ctx->conn->sk);

			TQUIC_INC_STATS(net, TQUIC_MIB_ECNACKSRX);
			if (ecn_ect0 > 0)
				TQUIC_ADD_STATS(net, TQUIC_MIB_ECNECT0RX, ecn_ect0);
			if (ecn_ect1 > 0)
				TQUIC_ADD_STATS(net, TQUIC_MIB_ECNECT1RX, ecn_ect1);
			if (ecn_ce > 0)
				TQUIC_ADD_STATS(net, TQUIC_MIB_ECNCEMARKSRX, ecn_ce);
		}
	}

	/* Update RTT estimate and notify congestion control */
	if (ctx->path) {
		ktime_t now = ktime_get();
		/* Convert ack_delay to microseconds */
		u64 ack_delay_us = ack_delay * 8;  /* Default exponent = 3 */
		u64 rtt_us;

		/*
		 * RTT sample calculation (simplified).
		 * Full implementation would track sent_time per packet.
		 * Use path's last_activity as approximation for now.
		 */
		rtt_us = ktime_us_delta(now, ctx->path->last_activity);
		if (rtt_us > ack_delay_us)
			rtt_us -= ack_delay_us;

		/* Update MIB counter for RTT sample */
		if (ctx->conn && ctx->conn->sk)
			TQUIC_INC_STATS(sock_net(ctx->conn->sk), TQUIC_MIB_RTTSAMPLES);

		/*
		 * Calculate bytes acknowledged from first_ack_range.
		 * Simplified: use first_ack_range * 1200 (MTU) as estimate.
		 * Full implementation would use packet tracking.
		 */
		{
			u64 bytes_acked = (first_ack_range + 1) * 1200;

			/* Dispatch ACK event to congestion control */
			tquic_cong_on_ack(ctx->path, bytes_acked, rtt_us);

			/* Update RTT in CC algorithm */
			tquic_cong_on_rtt(ctx->path, rtt_us);
		}

		/*
		 * ECN CE handling
		 *
		 * Per RFC 9002 Section 7.1: "An increase in ECN-CE counters
		 * is a signal of congestion. The sender SHOULD reduce the
		 * congestion window using the approach described in..."
		 *
		 * Per CONTEXT.md: "Loss on one path reduces only that path's CWND"
		 * This applies to ECN as well - ECN on one path affects only
		 * that path.
		 */
		if (has_ecn && ecn_ce > 0) {
			/*
			 * Track previous ECN-CE count to detect increase.
			 * For now, treat any reported CE count as new marks.
			 * A full implementation would compare against
			 * previously reported values.
			 */
			tquic_cong_on_ecn(ctx->path, ecn_ce);

			tquic_dbg("ECN-CE on path %u: ce=%llu ect0=%llu ect1=%llu\n",
				 ctx->path->path_id, ecn_ce, ecn_ect0, ecn_ect1);
		}
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

	ctx->offset++;  /* Skip frame type */

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
	if (length > ctx->len || ctx->offset + (size_t)length > ctx->len)
		return -EINVAL;

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

		/*
		 * SECURITY: Validate length fits in u32 before cast.
		 * CRYPTO frames carrying TLS messages should never exceed
		 * practical limits. Reject oversized frames.
		 */
		if (length > U32_MAX)
			return -EINVAL;
		ret = tquic_inline_hs_recv_crypto(sk,
						  ctx->data + ctx->offset,
						  (u32)length,
						  ctx->enc_level);
		if (ret < 0) {
			tquic_dbg("CRYPTO frame processing failed: %d\n",
				 ret);
			ctx->offset += length;
			return ret;
		}
	} else {
		tquic_dbg("CRYPTO frame received but no inline handshake active\n");
	}

	ctx->offset += length;
	ctx->ack_eliciting = true;

	return 0;
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

	ctx->offset++;  /* Skip frame type */

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
	}

	if (length > 65535)
		return -EINVAL;

	if (ctx->offset + length > ctx->len)
		return -EINVAL;

	/* Find or create stream */
	stream = NULL;
	{
		struct rb_node *node = ctx->conn->streams.rb_node;
		while (node) {
			struct tquic_stream *s = rb_entry(node, struct tquic_stream, node);
			if (stream_id < s->id)
				node = node->rb_left;
			else if (stream_id > s->id)
				node = node->rb_right;
			else {
				stream = s;
				break;
			}
		}
	}

	if (!stream) {
		/* Create new stream for incoming data */
		stream = tquic_stream_open(ctx->conn, (stream_id & 0x02) == 0);
		if (!stream)
			return -ENOMEM;
		stream->id = stream_id;
	}

	/* Copy data to stream receive buffer */
	data_skb = alloc_skb(length, GFP_ATOMIC);
	if (!data_skb)
		return -ENOMEM;

	skb_put_data(data_skb, ctx->data + ctx->offset, length);

	/* Store offset in skb->cb for reordering */
	*(u64 *)data_skb->cb = offset;

	/*
	 * Charge receive buffer memory against the connection socket.
	 * If receive buffer is full, drop the skb and apply backpressure.
	 * Use sk_rmem_alloc_get() and skb_set_owner_r() for compatibility
	 * with kernels where sk_rmem_alloc changed from atomic_t to refcount_t.
	 */
	if (ctx->conn->sk) {
		struct sock *sk = ctx->conn->sk;
		int amt = data_skb->truesize;

		if (sk_rmem_alloc_get(sk) + amt > sk->sk_rcvbuf) {
			kfree_skb(data_skb);
			/* Don't treat as fatal - peer will retransmit */
			return 0;
		}
		skb_set_owner_r(data_skb, sk);
	}

	skb_queue_tail(&stream->recv_buf, data_skb);

	/*
	 * SECURITY: Validate stream offset + length against RFC 9000 limit.
	 * Per Section 4.5: "An endpoint MUST treat receipt of data at or
	 * beyond the final size as a connection error." The maximum stream
	 * offset is 2^62-1. Check for overflow before
	 * updating recv_offset.
	 */
	if (offset > ((1ULL << 62) - 1) - length) {
		/* Would exceed 2^62-1 - protocol error */
		return -EPROTO;
	}
	stream->recv_offset = max(stream->recv_offset, offset + length);

	if (fin)
		stream->fin_received = true;

	ctx->offset += length;
	ctx->ack_eliciting = true;

	/* Update connection stats */
	ctx->conn->stats.rx_bytes += length;

	return 0;
}

/*
 * Process MAX_DATA frame
 */
static int tquic_process_max_data_frame(struct tquic_rx_ctx *ctx)
{
	u64 max_data;
	int ret;

	ctx->offset++;  /* Skip frame type */

	ret = tquic_decode_varint(ctx->data + ctx->offset,
				  ctx->len - ctx->offset, &max_data);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	/* Update remote's max data limit */
	spin_lock(&ctx->conn->lock);
	ctx->conn->max_data_remote = max(ctx->conn->max_data_remote, max_data);
	spin_unlock(&ctx->conn->lock);

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

	ctx->offset++;  /* Skip frame type */

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

	/* Find stream and update limit */
	/* Simplified: lookup omitted */

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

	ctx->offset++;  /* Skip frame type */

	if (ctx->offset + 8 > ctx->len)
		return -EINVAL;

	memcpy(data, ctx->data + ctx->offset, 8);
	ctx->offset += 8;

	/* Handle challenge through path validation module */
	ret = tquic_path_handle_challenge(ctx->conn, ctx->path, data);
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

	ctx->offset++;  /* Skip frame type */

	if (ctx->offset + 8 > ctx->len)
		return -EINVAL;

	memcpy(data, ctx->data + ctx->offset, 8);
	ctx->offset += 8;

	/* Handle response through path validation module */
	ret = tquic_path_handle_response(ctx->conn, ctx->path, data);
	if (ret == 0) {
		/* Update MIB counter for successful path validation */
		if (ctx->conn && ctx->conn->sk)
			TQUIC_INC_STATS(sock_net(ctx->conn->sk), TQUIC_MIB_PATHVALIDATED);
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

	ctx->offset++;  /* Skip frame type */

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

	/* Store new CID for future use */
	/* This would be added to a CID pool */

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

	ctx->offset++;  /* Skip frame type */

	ret = tquic_decode_varint(ctx->data + ctx->offset,
				  ctx->len - ctx->offset, &seq_num);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	/* Remove CID from active set */
	/* This would update the CID pool */

	ctx->ack_eliciting = true;

	return 0;
}

/*
 * Process CONNECTION_CLOSE frame
 */
static int tquic_process_connection_close_frame(struct tquic_rx_ctx *ctx, bool app)
{
	u64 error_code, frame_type = 0, reason_len;
	int ret;

	ctx->offset++;  /* Skip frame type */

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
	 * SECURITY: Validate reason phrase length to prevent integer overflow.
	 * reason_len is u64 from varint (up to 2^62-1). Adding to size_t
	 * ctx->offset could overflow on 32-bit. First check against remaining
	 * bytes which is a safe size_t value.
	 */
	if (reason_len > ctx->len - ctx->offset)
		return -EINVAL;
	ctx->offset += (size_t)reason_len;

	pr_info_ratelimited("tquic: received CONNECTION_CLOSE, error=%llu frame_type=%llu\n",
			    error_code, frame_type);

	/* Transition to draining state */
	spin_lock(&ctx->conn->lock);
	ctx->conn->state = TQUIC_CONN_DRAINING;
	spin_unlock(&ctx->conn->lock);

	/* Update MIB counters for connection close */
	if (ctx->conn && ctx->conn->sk) {
		TQUIC_DEC_STATS(sock_net(ctx->conn->sk), TQUIC_MIB_CURRESTAB);
		if (error_code == EQUIC_NO_ERROR)
			TQUIC_INC_STATS(sock_net(ctx->conn->sk), TQUIC_MIB_CONNCLOSED);
		else
			TQUIC_INC_STATS(sock_net(ctx->conn->sk), TQUIC_MIB_CONNRESET);

		/* Track specific EQUIC error */
		enum linux_tquic_mib_field mib_field = tquic_equic_to_mib(error_code);
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
	ctx->offset++;  /* Skip frame type */

	/* Mark handshake as complete (client side) */
	if (ctx->conn->crypto_state) {
		/* Set handshake_complete flag */
	}

	spin_lock(&ctx->conn->lock);
	if (ctx->conn->state == TQUIC_CONN_CONNECTING)
		ctx->conn->state = TQUIC_CONN_CONNECTED;
	spin_unlock(&ctx->conn->lock);

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

	ctx->offset++;  /* Skip frame type */

	/* Parse token length */
	ret = tquic_decode_varint(ctx->data + ctx->offset,
				  ctx->len - ctx->offset, &token_len);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	/* Validate token length */
	if (token_len > TQUIC_TOKEN_MAX_LEN) {
		tquic_dbg("NEW_TOKEN too large: %llu > %u\n",
			 token_len, TQUIC_TOKEN_MAX_LEN);
		return -EINVAL;
	}

	if (ctx->offset + token_len > ctx->len)
		return -EINVAL;

	/* Process the token - delegate to token module */
	ret = tquic_process_new_token_frame(ctx->conn,
					    ctx->data + ctx->offset,
					    token_len);
	if (ret < 0) {
		tquic_dbg("NEW_TOKEN processing failed: %d\n", ret);
		/* Update MIB counter for invalid token */
		if (ctx->conn && ctx->conn->sk)
			TQUIC_INC_STATS(sock_net(ctx->conn->sk), TQUIC_MIB_TOKENSINVALID);
	} else {
		/* Update MIB counter for token received */
		if (ctx->conn && ctx->conn->sk)
			TQUIC_INC_STATS(sock_net(ctx->conn->sk), TQUIC_MIB_NEWTOKENSRX);
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
 * Frame format:
 *   Type (0x30 or 0x31): 1 byte
 *   [Length]: varint (only if Type & 0x01)
 *   Data: remaining bytes
 */
static int tquic_process_datagram_frame(struct tquic_rx_ctx *ctx)
{
	u8 frame_type = ctx->data[ctx->offset];
	bool has_length = (frame_type & 0x01) != 0;
	u64 length;
	struct sk_buff *dgram_skb;
	int ret;

	ctx->offset++;  /* Skip frame type */

	/* Parse length field if present (0x31), otherwise use remaining bytes */
	if (has_length) {
		ret = tquic_decode_varint(ctx->data + ctx->offset,
					  ctx->len - ctx->offset, &length);
		if (ret < 0)
			return ret;
		ctx->offset += ret;
	} else {
		/* Type 0x30: datagram extends to end of packet */
		length = ctx->len - ctx->offset;
	}

	/*
	 * SECURITY: Validate datagram length to prevent integer overflow.
	 * length is u64; compare against remaining bytes (safe size_t)
	 * to avoid overflow in ctx->offset + length on 32-bit.
	 */
	if (length > ctx->len - ctx->offset)
		return -EINVAL;

	/* Check if datagram support is enabled on this connection */
	if (!ctx->conn || !ctx->conn->datagram.enabled) {
		/* RFC 9221: If not negotiated, this is a protocol error */
		tquic_dbg("received DATAGRAM but not negotiated\n");
		return -EPROTO;
	}

	/* Validate against negotiated maximum size */
	if (length > ctx->conn->datagram.max_recv_size) {
		tquic_dbg("DATAGRAM too large: %llu > %llu\n",
			 length, ctx->conn->datagram.max_recv_size);
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
			TQUIC_INC_STATS(sock_net(ctx->conn->sk), TQUIC_MIB_DATAGRAMSDROPPED);
		tquic_dbg("DATAGRAM dropped, queue full\n");
		/* Continue processing - this is not a fatal error */
		ctx->offset += length;
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
			TQUIC_INC_STATS(sock_net(ctx->conn->sk), TQUIC_MIB_DATAGRAMSDROPPED);
		ctx->offset += length;
		ctx->ack_eliciting = true;
		return 0;  /* Not fatal, continue */
	}

	/* Copy datagram payload */
	skb_put_data(dgram_skb, ctx->data + ctx->offset, length);

	/* Store receive timestamp in SKB cb */
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

	ctx->offset += length;
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

	/* Parse frame type */
	ret = tquic_decode_varint(ctx->data + ctx->offset,
				  ctx->len - ctx->offset, &frame_type);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	/* Parse the frame fields */
	ret = tquic_parse_ack_frequency_frame(ctx->data + ctx->offset,
					      ctx->len - ctx->offset,
					      &frame);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	/* Handle the frame */
	ret = tquic_conn_handle_ack_frequency_frame(ctx->conn, &frame);
	if (ret < 0)
		return ret;

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

#include "multipath/mp_frame.h"
#include "multipath/mp_ack.h"
#include "multipath/path_abandon.h"

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

	/* Check for extended multipath frame types */
	return (frame_type >= 0x15c0 && frame_type <= 0x15cff);
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

	ret = tquic_mp_parse_retire_connection_id(ctx->data + ctx->offset,
						  ctx->len - ctx->offset, &frame);
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
	struct tquic_mp_ack frame;
	struct tquic_path *path;
	struct tquic_mp_path_ack_state *ack_state;
	u8 ack_delay_exponent = 3;  /* Default */
	int ret;

	ret = tquic_mp_parse_ack(ctx->data + ctx->offset,
				 ctx->len - ctx->offset,
				 &frame, ack_delay_exponent);
	if (ret < 0)
		return ret;

	ctx->offset += ret;
	/* MP_ACK is NOT ack-eliciting (RFC 9000 Section 13.2) */

	/* Find the path for this ACK */
	spin_lock(&ctx->conn->paths_lock);
	list_for_each_entry(path, &ctx->conn->paths, list) {
		if (path->path_id == frame.path_id) {
			ack_state = path->mp_ack_state;
			if (ack_state) {
				spin_unlock(&ctx->conn->paths_lock);
				ret = tquic_mp_on_ack_received(ack_state,
					TQUIC_PN_SPACE_APPLICATION,
					&frame, ctx->conn);
				if (ret < 0) {
					tquic_dbg("MP_ACK processing failed: %d\n", ret);
					return ret;
				}
				tquic_dbg("processed MP_ACK path=%llu largest=%llu\n",
					 frame.path_id, frame.largest_ack);
				return 0;
			}
			break;
		}
	}
	spin_unlock(&ctx->conn->paths_lock);

	tquic_dbg("MP_ACK for unknown/uninitialized path %llu\n",
		 frame.path_id);
	return 0;
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

/*
 * Demultiplex and process all frames in packet
 */
static int tquic_process_frames(struct tquic_connection *conn,
				struct tquic_path *path,
				u8 *payload, size_t len,
				int enc_level, u64 pkt_num)
{
	struct tquic_rx_ctx ctx;
	int ret = 0;
	u8 frame_type;
	size_t prev_offset;

	ctx.conn = conn;
	ctx.path = path;
	ctx.data = payload;
	ctx.len = len;
	ctx.offset = 0;
	ctx.pkt_num = pkt_num;
	ctx.enc_level = enc_level;
	ctx.ack_eliciting = false;

	while (ctx.offset < ctx.len) {
		prev_offset = ctx.offset;
		frame_type = ctx.data[ctx.offset];

		/* Handle frame based on type */
		if (frame_type == TQUIC_FRAME_PADDING) {
			ret = tquic_process_padding_frame(&ctx);
		} else if (frame_type == TQUIC_FRAME_PING) {
			ret = tquic_process_ping_frame(&ctx);
		} else if (frame_type == TQUIC_FRAME_ACK ||
			   frame_type == TQUIC_FRAME_ACK_ECN) {
			ret = tquic_process_ack_frame(&ctx);
		} else if (frame_type == TQUIC_FRAME_CRYPTO) {
			ret = tquic_process_crypto_frame(&ctx);
		} else if (frame_type == TQUIC_FRAME_NEW_TOKEN) {
			ret = tquic_process_new_token(&ctx);
		} else if ((frame_type & 0xf8) == TQUIC_FRAME_STREAM) {
			ret = tquic_process_stream_frame(&ctx);
		} else if (frame_type == TQUIC_FRAME_MAX_DATA) {
			ret = tquic_process_max_data_frame(&ctx);
		} else if (frame_type == TQUIC_FRAME_MAX_STREAM_DATA) {
			ret = tquic_process_max_stream_data_frame(&ctx);
		} else if (frame_type == TQUIC_FRAME_PATH_CHALLENGE) {
			ret = tquic_process_path_challenge_frame(&ctx);
		} else if (frame_type == TQUIC_FRAME_PATH_RESPONSE) {
			ret = tquic_process_path_response_frame(&ctx);
		} else if (frame_type == TQUIC_FRAME_NEW_CONNECTION_ID) {
			ret = tquic_process_new_connection_id_frame(&ctx);
		} else if (frame_type == TQUIC_FRAME_RETIRE_CONNECTION_ID) {
			ret = tquic_process_retire_connection_id_frame(&ctx);
		} else if (frame_type == TQUIC_FRAME_CONNECTION_CLOSE) {
			ret = tquic_process_connection_close_frame(&ctx, false);
		} else if (frame_type == TQUIC_FRAME_CONNECTION_CLOSE_APP) {
			ret = tquic_process_connection_close_frame(&ctx, true);
		} else if (frame_type == TQUIC_FRAME_HANDSHAKE_DONE) {
			ret = tquic_process_handshake_done_frame(&ctx);
		} else if ((frame_type & 0xfe) == TQUIC_FRAME_DATAGRAM) {
			ret = tquic_process_datagram_frame(&ctx);
		} else if (frame_type == TQUIC_FRAME_ACK_FREQUENCY) {
			ret = tquic_process_ack_frequency_frame(&ctx);
		} else if (frame_type == TQUIC_FRAME_IMMEDIATE_ACK) {
			ret = tquic_process_immediate_ack_frame(&ctx);
#ifdef CONFIG_TQUIC_MULTIPATH
		} else if (frame_type == 0x40) {
			/* MP_NEW_CONNECTION_ID (RFC 9369) */
			ret = tquic_process_mp_new_connection_id_frame(&ctx);
		} else if (frame_type == 0x41) {
			/* MP_RETIRE_CONNECTION_ID (RFC 9369) */
			ret = tquic_process_mp_retire_connection_id_frame(&ctx);
		} else if (frame_type == 0x42 || frame_type == 0x43) {
			/* MP_ACK or MP_ACK_ECN (RFC 9369) */
			ret = tquic_process_mp_ack_frame(&ctx);
		} else if (tquic_is_mp_extended_frame(&ctx)) {
			/* Extended multipath frames (PATH_ABANDON, PATH_STATUS) */
			ret = tquic_process_mp_extended_frame(&ctx);
#endif
		} else {
			/* Unknown frame type */
			tquic_dbg("unknown frame type 0x%02x\n", frame_type);
			ret = -EINVAL;
		}

		if (ret < 0)
			break;

		/* Detect stuck parsing (no progress made) */
		if (ctx.offset == prev_offset)
			return -EPROTO;
	}

	/* Send ACK if packet was ack-eliciting */
	if (ctx.ack_eliciting && ret >= 0) {
		/* Queue ACK to be sent */
		/* This would be handled by the ACK manager */
	}

	return ret;
}

/*
 * =============================================================================
 * Header Parsing
 * =============================================================================
 */

/*
 * Parse long header
 */
static int tquic_parse_long_header_internal(struct tquic_rx_ctx *ctx,
				   u8 *dcid, u8 *dcid_len,
				   u8 *scid, u8 *scid_len,
				   u32 *version, int *pkt_type)
{
	u8 *p = ctx->data;
	u8 first_byte;

	if (ctx->len < 7)
		return -EINVAL;

	first_byte = *p++;

	/* Version */
	*version = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
	p += 4;

	/* DCID Length + DCID */
	*dcid_len = *p++;
	if (*dcid_len > TQUIC_MAX_CID_LEN)
		return -EINVAL;
	if (p + *dcid_len > ctx->data + ctx->len)
		return -EINVAL;
	memcpy(dcid, p, *dcid_len);
	p += *dcid_len;

	/* SCID Length + SCID */
	if (p >= ctx->data + ctx->len)
		return -EINVAL;
	*scid_len = *p++;
	if (*scid_len > TQUIC_MAX_CID_LEN)
		return -EINVAL;
	if (p + *scid_len > ctx->data + ctx->len)
		return -EINVAL;
	memcpy(scid, p, *scid_len);
	p += *scid_len;

	/* Packet type from first byte */
	*pkt_type = (first_byte & 0x30) >> 4;

	ctx->offset = p - ctx->data;
	ctx->is_long_header = true;

	return 0;
}

/*
 * Parse short header
 */
static int tquic_parse_short_header_internal(struct tquic_rx_ctx *ctx,
				    u8 dcid_len,  /* Expected DCID length */
				    u8 *dcid,
				    bool *key_phase,
				    bool *spin_bit)
{
	u8 first_byte;

	if (ctx->len < 1 + dcid_len)
		return -EINVAL;

	first_byte = ctx->data[0];

	*spin_bit = (first_byte & TQUIC_HEADER_SPIN_BIT) != 0;
	*key_phase = (first_byte & TQUIC_HEADER_KEY_PHASE) != 0;

	/* Copy DCID */
	memcpy(dcid, ctx->data + 1, dcid_len);

	ctx->offset = 1 + dcid_len;
	ctx->is_long_header = false;

	return 0;
}

/*
 * Decode packet number
 */
static u64 tquic_decode_pkt_num(u8 *buf, int pkt_num_len, u64 largest_pn)
{
	u64 truncated_pn = 0;
	u64 expected_pn, pn_win, pn_hwin, pn_mask;
	u64 candidate_pn;
	int i;

	/* Read truncated packet number */
	for (i = 0; i < pkt_num_len; i++)
		truncated_pn = (truncated_pn << 8) | buf[i];

	/* Reconstruct full packet number */
	expected_pn = largest_pn + 1;
	pn_win = 1ULL << (pkt_num_len * 8);
	pn_hwin = pn_win / 2;
	pn_mask = pn_win - 1;

	candidate_pn = (expected_pn & ~pn_mask) | truncated_pn;

	if (candidate_pn + pn_hwin <= expected_pn &&
	    candidate_pn + pn_win < (1ULL << 62))
		candidate_pn += pn_win;
	else if (candidate_pn > expected_pn + pn_hwin &&
		 candidate_pn >= pn_win)
		candidate_pn -= pn_win;

	return candidate_pn;
}

/*
 * =============================================================================
 * GRO (Generic Receive Offload) Handling
 * =============================================================================
 */

/*
 * GRO flush timer callback
 */
static enum hrtimer_restart tquic_gro_flush_timer(struct hrtimer *timer)
{
	return HRTIMER_NORESTART;
}

/*
 * Initialize GRO state
 */
struct tquic_gro_state *tquic_gro_init(void)
{
	struct tquic_gro_state *gro;

	gro = kzalloc(sizeof(*gro), GFP_KERNEL);
	if (!gro)
		return NULL;

	skb_queue_head_init(&gro->hold_queue);
	spin_lock_init(&gro->lock);
	/* Use hrtimer_setup (new API) instead of hrtimer_init */
	hrtimer_setup(&gro->flush_timer, tquic_gro_flush_timer,
		      CLOCK_MONOTONIC, HRTIMER_MODE_REL);

	return gro;
}
EXPORT_SYMBOL_GPL(tquic_gro_init);

/*
 * Cleanup GRO state
 */
void tquic_gro_cleanup(struct tquic_gro_state *gro)
{
	if (!gro)
		return;

	hrtimer_cancel(&gro->flush_timer);
	skb_queue_purge(&gro->hold_queue);
	kfree(gro);
}
EXPORT_SYMBOL_GPL(tquic_gro_cleanup);

/*
 * Check if packets can be coalesced
 */
static bool tquic_gro_can_coalesce(struct sk_buff *skb1, struct sk_buff *skb2)
{
	/* For QUIC, we can coalesce packets from same connection */
	/* Check DCID matches */
	u8 *h1 = skb1->data;
	u8 *h2 = skb2->data;

	/* Both must be short headers or both long headers */
	if ((h1[0] & TQUIC_HEADER_FORM_LONG) != (h2[0] & TQUIC_HEADER_FORM_LONG))
		return false;

	/* For short headers, compare DCID */
	if (!(h1[0] & TQUIC_HEADER_FORM_LONG)) {
		/* Assume 8-byte CID for now */
		return memcmp(h1 + 1, h2 + 1, 8) == 0;
	}

	return false;
}

/*
 * Attempt to merge packets for GRO
 */
static struct sk_buff __maybe_unused *tquic_gro_receive_internal(struct tquic_gro_state *gro,
								struct sk_buff *skb)
{
	struct sk_buff *held;

	spin_lock(&gro->lock);

	/* Check if we can coalesce with held packets */
	skb_queue_walk(&gro->hold_queue, held) {
		if (tquic_gro_can_coalesce(held, skb)) {
			/* Coalesce into held packet */
			/* For QUIC, this is complex due to packet structure */
			/* Simple implementation just holds multiple packets */
		}
	}

	/* Add to hold queue */
	__skb_queue_tail(&gro->hold_queue, skb);
	gro->held_count++;

	if (gro->held_count == 1)
		gro->first_hold_time = ktime_get();

	/* Flush if queue is full */
	if (gro->held_count >= TQUIC_GRO_MAX_HOLD) {
		/* Would flush here */
	}

	spin_unlock(&gro->lock);

	return NULL;
}

/*
 * Flush GRO held packets
 */
int tquic_gro_flush(struct tquic_gro_state *gro,
		    void (*deliver)(struct sk_buff *))
{
	struct sk_buff *skb;
	int flushed = 0;

	spin_lock(&gro->lock);

	while ((skb = __skb_dequeue(&gro->hold_queue)) != NULL) {
		spin_unlock(&gro->lock);
		deliver(skb);
		flushed++;
		spin_lock(&gro->lock);
	}

	gro->held_count = 0;

	spin_unlock(&gro->lock);

	return flushed;
}
EXPORT_SYMBOL_GPL(tquic_gro_flush);

/*
 * =============================================================================
 * Main Receive Path
 * =============================================================================
 */

/*
 * Process a single QUIC packet
 */
static int tquic_process_packet(struct tquic_connection *conn,
				struct tquic_path *path,
				u8 *data, size_t len,
				struct sockaddr_storage *src_addr)
{
	struct tquic_rx_ctx ctx;
	u8 dcid[TQUIC_MAX_CID_LEN], scid[TQUIC_MAX_CID_LEN];
	u8 dcid_len, scid_len;
	u32 version;
	int pkt_type;
	int pkt_num_len;
	u64 pkt_num;
	u8 *payload;
	size_t payload_len, decrypted_len = 0;
	u8 *decrypted;
	bool decrypted_from_slab = false;
	int ret;

	ctx.data = data;
	ctx.len = len;
	ctx.offset = 0;

	/* Check header form */
	if (data[0] & TQUIC_HEADER_FORM_LONG) {
		/* Long header */
		ret = tquic_parse_long_header_internal(&ctx, dcid, &dcid_len,
					      scid, &scid_len,
					      &version, &pkt_type);
		if (unlikely(ret < 0))
			return ret;

		/* Handle version negotiation */
		if (unlikely(version == TQUIC_VERSION_NEGOTIATION)) {
			if (conn)
				return tquic_process_version_negotiation(conn, data, len);
			return 0;
		}

		/*
		 * Handle Retry packet (client-side, RFC 9000 Section 17.2.5)
		 *
		 * A Retry packet is sent by the server in response to an Initial
		 * packet to validate the client's address. The client must:
		 * 1. Verify the Retry Integrity Tag using original DCID
		 * 2. Extract the Retry Token
		 * 3. Store the new server-provided SCID
		 * 4. Retransmit Initial with the Retry Token
		 *
		 * Retry packets can only be received on clients during connection
		 * establishment (TQUIC_CONN_CONNECTING state).
		 */
		if (unlikely(pkt_type == TQUIC_PKT_RETRY)) {
			/* Need connection to process Retry */
			if (!conn)
				conn = tquic_lookup_by_dcid(dcid, dcid_len);

			if (conn) {
				/*
				 * Only process Retry in connecting state.
				 * Per RFC 9000: "A client MUST discard a Retry
				 * packet that contains a DCID field that is
				 * not equal to the SCID field of its Initial."
				 */
				if (conn->state == TQUIC_CONN_CONNECTING) {
					ret = tquic_retry_process(conn, data, len);
					if (ret == 0) {
						/* Update MIB counter */
						if (conn->sk)
							TQUIC_INC_STATS(sock_net(conn->sk),
									TQUIC_MIB_RETRYPACKETSRX);
						/*
						 * Retry processed successfully.
						 * Caller should retransmit Initial with token.
						 * Return special code to trigger retry.
						 */
						return -EAGAIN;
					}
				} else {
					/*
					 * Per RFC 9000 Section 17.2.5.2:
					 * "A client MUST discard a Retry packet
					 * if it has received and successfully
					 * processed a Retry packet for this
					 * connection."
					 */
					tquic_dbg("discarding Retry in state %d\n",
						 conn->state);
				}
			}
			return 0;  /* Discard Retry packet after processing */
		}

		/*
		 * Handle 0-RTT packets (RFC 9001 Section 4.6-4.7)
		 *
		 * 0-RTT packets are sent by clients using keys derived from
		 * a previous session's resumption_master_secret. They contain
		 * early application data and may arrive before or during the
		 * TLS handshake.
		 *
		 * Server processing:
		 * 1. Look up connection by DCID
		 * 2. Check if 0-RTT is enabled and not rejected
		 * 3. Decrypt using 0-RTT keys
		 * 4. Process frames (limited: no CRYPTO, ACK, etc.)
		 *
		 * Client processing (unlikely - server doesn't send 0-RTT):
		 * - Discard the packet
		 */
		if (pkt_type == TQUIC_PKT_ZERO_RTT) {
			if (!conn)
				conn = tquic_lookup_by_dcid(dcid, dcid_len);

			if (!conn) {
				tquic_dbg("0-RTT packet for unknown connection\n");
				return -ENOENT;
			}

			/* Server-side: check if we can accept 0-RTT */
			if (conn->role == TQUIC_ROLE_SERVER) {
				enum tquic_zero_rtt_state zrtt_state;
				zrtt_state = tquic_zero_rtt_get_state(conn);

				if (zrtt_state == TQUIC_0RTT_REJECTED) {
					/*
					 * 0-RTT already rejected - discard packet.
					 * Client will retransmit as 1-RTT.
					 */
					tquic_dbg("0-RTT rejected, discarding\n");
					return 0;
				}

				/*
				 * Accept 0-RTT if not yet decided.
				 * This initializes keys for decryption.
				 */
				if (zrtt_state == TQUIC_0RTT_NONE) {
					ret = tquic_zero_rtt_accept(conn);
					if (ret < 0) {
						/* Replay or other error - reject */
						tquic_zero_rtt_reject(conn);
						if (ret == -EEXIST && conn->sk)
							TQUIC_INC_STATS(sock_net(conn->sk),
									TQUIC_MIB_0RTTREPLAYS);
						tquic_dbg("0-RTT rejected: %d\n", ret);
						return 0;
					}
					if (conn->sk)
						TQUIC_INC_STATS(sock_net(conn->sk),
								TQUIC_MIB_0RTTACCEPTED);
				}
			} else {
				/* Client received 0-RTT packet - shouldn't happen */
				tquic_dbg("client received 0-RTT packet?\n");
				return -EPROTO;
			}

			/* Continue to decrypt and process as 0-RTT */
			/* Fall through to normal packet processing below */
		}

		/* Lookup connection by DCID if not provided */
		if (!conn)
			conn = tquic_lookup_by_dcid(dcid, dcid_len);

		if (!conn) {
			/* New connection - would handle Initial packet */
			tquic_dbg("no connection found for DCID\n");
			return -ENOENT;
		}

		/* Parse token for Initial packets */
		if (pkt_type == TQUIC_PKT_INITIAL) {
			u64 token_len;
			size_t remaining_len;

			ret = tquic_decode_varint(data + ctx.offset,
						  len - ctx.offset, &token_len);
			if (ret < 0)
				return ret;
			ctx.offset += ret;

			remaining_len = len - ctx.offset;
			if (token_len > remaining_len)
				return -EINVAL;

			ctx.offset += token_len;
		}

		/* Parse length field */
		{
			u64 pkt_len;
			ret = tquic_decode_varint(data + ctx.offset,
						  len - ctx.offset, &pkt_len);
			if (ret < 0)
				return ret;
			ctx.offset += ret;
		}

		/* Packet number length from first byte */
		pkt_num_len = (data[0] & 0x03) + 1;

	} else {
		/* Short header */
		bool key_phase, spin_bit;

		/* Need connection to know DCID length */
		if (!conn)
			return -ENOENT;

		ret = tquic_parse_short_header_internal(&ctx, conn->scid.len,
					       dcid, &key_phase, &spin_bit);
		if (ret < 0)
			return ret;

		pkt_type = -1;  /* Short header / 1-RTT */
		pkt_num_len = (data[0] & 0x03) + 1;

		/*
		 * Key phase handling (RFC 9001 Section 6)
		 *
		 * The key phase bit in short header packets indicates which
		 * key generation was used to encrypt the packet. A change
		 * indicates a key update by the peer.
		 *
		 * We handle this after header unprotection reveals the true
		 * key phase bit, and before decryption to use correct keys.
		 */
		ctx.key_phase_bit = key_phase ? 1 : 0;
	}

	/* Find path if not provided */
	if (!path && conn)
		path = tquic_find_path_by_addr(conn, src_addr);

	/* Remove header protection */
	ret = tquic_remove_header_protection(conn, data, ctx.offset,
					     data + ctx.offset,
					     len - ctx.offset,
					     ctx.is_long_header);
	if (unlikely(ret < 0))
		return ret;

	/* Decode packet number */
	pkt_num = tquic_decode_pkt_num(data + ctx.offset, pkt_num_len, 0);
	ctx.offset += pkt_num_len;

	/* Decrypt payload */
	payload = data + ctx.offset;
	payload_len = len - ctx.offset;

	/*
	 * Use the dedicated slab cache for decryption buffers when the
	 * payload fits (common case: all standard MTU packets).  Fall
	 * back to kmalloc for the rare jumbo/GSO case.
	 */
	if (likely(payload_len <= TQUIC_RX_BUF_SIZE)) {
		decrypted = kmem_cache_alloc(tquic_rx_buf_cache, GFP_ATOMIC);
		decrypted_from_slab = true;
	} else {
		decrypted = kmalloc(payload_len, GFP_ATOMIC);
	}
	if (unlikely(!decrypted))
		return -ENOMEM;

	/*
	 * Decrypt payload using appropriate keys:
	 * - 0-RTT packets use 0-RTT keys from session ticket
	 * - Other packets use normal crypto state keys
	 */
	if (unlikely(pkt_type == TQUIC_PKT_ZERO_RTT)) {
		/* Decrypt using 0-RTT keys */
		ret = tquic_zero_rtt_decrypt(conn, data, ctx.offset,
					     payload, payload_len,
					     pkt_num, decrypted, &decrypted_len);
		if (unlikely(ret < 0)) {
			if (decrypted_from_slab)
				kmem_cache_free(tquic_rx_buf_cache, decrypted);
			else
				kfree(decrypted);
			if (ret == -ENOKEY)
				tquic_dbg("0-RTT decryption failed, no keys\n");
			return ret;
		}
		/* Update 0-RTT stats */
		if (conn->sk)
			TQUIC_ADD_STATS(sock_net(conn->sk), TQUIC_MIB_0RTTBYTESRX,
					decrypted_len);
	} else {
		ret = tquic_decrypt_payload(conn, data, ctx.offset,
					    payload, payload_len,
					    pkt_num,
					    pkt_type >= 0 ? pkt_type : 3,
					    decrypted, &decrypted_len);
		if (unlikely(ret < 0)) {
			/*
			 * Key Update: Decryption failure for short headers might be
			 * due to key phase change. Try with old keys if available.
			 * Per RFC 9001 Section 6.3, packets in flight during key
			 * update may arrive encrypted with old keys.
			 */
			if (pkt_type < 0 && conn->crypto_state) {
				ret = tquic_try_decrypt_with_old_keys(conn,
								      data, ctx.offset,
								      payload, payload_len,
								      pkt_num,
								      decrypted, &decrypted_len);
			}
			if (ret < 0) {
				if (decrypted_from_slab)
					kmem_cache_free(tquic_rx_buf_cache,
							decrypted);
				else
					kfree(decrypted);
				return ret;
			}
		}
	}

	/*
	 * Key Update Detection (RFC 9001 Section 6)
	 *
	 * For short header packets (1-RTT), check if the key phase bit
	 * differs from our current key phase. A change indicates either:
	 * - Peer has initiated a key update (we need to respond)
	 * - Our previous key update has been acknowledged
	 */
	if (pkt_type < 0 && conn->crypto_state) {
		struct tquic_key_update_state *ku_state;
		ku_state = tquic_crypto_get_key_update_state(conn->crypto_state);
		if (ku_state) {
			u8 current_phase = tquic_key_update_get_phase(ku_state);
			if (ctx.key_phase_bit != current_phase) {
				int ku_ret = tquic_handle_key_phase_change(conn, ctx.key_phase_bit);
				if (ku_ret < 0)
					tquic_warn("key phase change %u->%u failed: %d\n",
						current_phase, ctx.key_phase_bit, ku_ret);
			}
			/* Track packet received for key update timing */
			tquic_key_update_on_packet_received(ku_state);
		}
	}

	/* Process frames */
	ret = tquic_process_frames(conn, path, decrypted, decrypted_len,
				   pkt_type >= 0 ? pkt_type : 3, pkt_num);

	if (decrypted_from_slab)
		kmem_cache_free(tquic_rx_buf_cache, decrypted);
	else
		kfree(decrypted);

	/* Update statistics */
	if (likely(ret >= 0)) {
		conn->stats.rx_packets++;
		if (likely(path)) {
			path->stats.rx_packets++;
			path->stats.rx_bytes += len;
			path->last_activity = ktime_get();
		}

		/* Update MIB counters for packet reception */
		if (conn->sk) {
			TQUIC_INC_STATS(sock_net(conn->sk), TQUIC_MIB_PACKETSRX);
			TQUIC_ADD_STATS(sock_net(conn->sk), TQUIC_MIB_BYTESRX, len);
		}

		/*
		 * RFC 9000 Section 10.1: "An endpoint restarts its idle
		 * timer when a packet from its peer is received and
		 * processed successfully."
		 */
		if (conn->timer_state)
			tquic_timer_reset_idle(conn->timer_state);
	}

	return ret;
}

/*
 * UDP receive callback - main entry point for received packets
 *
 * This is the primary entry point for all QUIC packets received via UDP.
 * It handles:
 * - Stateless reset detection (received from peer)
 * - Version negotiation processing
 * - Regular packet processing
 * - Stateless reset transmission (for unknown CIDs, per RFC 9000 Section 10.3)
 */
int tquic_udp_recv(struct sock *sk, struct sk_buff *skb)
{
	struct tquic_connection *conn = NULL;
	struct tquic_path *path = NULL;
	struct sockaddr_storage src_addr;
	struct sockaddr_storage local_addr;
	u8 *data;
	size_t len;
	int ret;

	if (unlikely(!skb))
		return -EINVAL;

	/* Extract source (remote) address */
	memset(&src_addr, 0, sizeof(src_addr));
	memset(&local_addr, 0, sizeof(local_addr));

	if (skb->protocol == htons(ETH_P_IP)) {
		struct sockaddr_in *sin_src = (struct sockaddr_in *)&src_addr;
		struct sockaddr_in *sin_local = (struct sockaddr_in *)&local_addr;

		sin_src->sin_family = AF_INET;
		sin_src->sin_addr.s_addr = ip_hdr(skb)->saddr;
		sin_src->sin_port = udp_hdr(skb)->source;

		/* Local address for stateless reset response */
		sin_local->sin_family = AF_INET;
		sin_local->sin_addr.s_addr = ip_hdr(skb)->daddr;
		sin_local->sin_port = udp_hdr(skb)->dest;
	} else if (skb->protocol == htons(ETH_P_IPV6)) {
		struct sockaddr_in6 *sin6_src = (struct sockaddr_in6 *)&src_addr;
		struct sockaddr_in6 *sin6_local = (struct sockaddr_in6 *)&local_addr;

		sin6_src->sin6_family = AF_INET6;
		sin6_src->sin6_addr = ipv6_hdr(skb)->saddr;
		sin6_src->sin6_port = udp_hdr(skb)->source;

		sin6_local->sin6_family = AF_INET6;
		sin6_local->sin6_addr = ipv6_hdr(skb)->daddr;
		sin6_local->sin6_port = udp_hdr(skb)->dest;
	}

	/* Get QUIC payload - UDP header already stripped by encap layer */
	data = skb->data;
	len = skb->len;

	if (unlikely(len < 1)) {
		kfree_skb(skb);
		return -EINVAL;
	}

	/*
	 * Rate limiting check for DDoS protection
	 *
	 * For Initial packets (new connection attempts), check against
	 * per-IP rate limits before allocating any connection state.
	 * This is the first line of defense against amplification attacks.
	 *
	 * We have two rate limiting subsystems:
	 * 1. rate_limit.h: Token bucket with global and per-IP limits
	 * 2. tquic_ratelimit.h: Advanced rate limiting with cookie validation
	 *
	 * Check order:
	 * 1. Global rate limit check (rate_limit.h)
	 * 2. Per-IP rate limit check (rate_limit.h)
	 * 3. Advanced checks with cookie support (tquic_ratelimit.h)
	 */
	if (len >= 7 && (data[0] & TQUIC_HEADER_FORM_LONG)) {
		/* Long header - check if this is an Initial packet */
		int pkt_type = (data[0] & 0x30) >> 4;

		if (pkt_type == TQUIC_PKT_INITIAL) {
			enum tquic_rl_action action;
			u8 dcid_len, scid_len;
			const u8 *token = NULL;
			size_t token_len = 0;
			size_t offset;

			/* Parse enough header to extract DCID */
			if (len >= 6) {
				dcid_len = data[5];

				/*
				 * SECURITY: Validate DCID length before use.
				 * RFC 9000 limits CID to 20 bytes. Without
				 * this check, offset = 6 + dcid_len could
				 * point past the packet buffer, causing
				 * out-of-bounds reads on data + 6.
				 */
				if (dcid_len > TQUIC_MAX_CID_LEN ||
				    6 + (size_t)dcid_len > len) {
					kfree_skb(skb);
					return -EINVAL;
				}
				offset = 6 + dcid_len;

				/*
				 * First check: Global and per-IP token bucket limits
				 * (rate_limit.h - lightweight fast path)
				 */
				if (!tquic_rate_limit_check_initial(sock_net(sk),
								    &src_addr,
								    data + 6,
								    dcid_len)) {
					/* Rate limited - silently drop */
					kfree_skb(skb);
					return -EBUSY;
				}

				if (offset < len) {
					scid_len = data[offset];
					if (scid_len > TQUIC_MAX_CID_LEN ||
					    offset + 1 + scid_len > len) {
						kfree_skb(skb);
						return -EINVAL;
					}
					offset += 1 + scid_len;

					/* Parse token length (varint) */
					if (offset < len) {
						u64 tlen;
						int vlen;
						vlen = tquic_decode_varint(data + offset,
									   len - offset, &tlen);
						if (vlen > 0 && offset + vlen + tlen <= len) {
							token = data + offset + vlen;
							token_len = tlen;
						}
					}
				}

				/*
				 * Second check: Advanced rate limiting with cookie
				 * support (tquic_ratelimit.h - attack mode handling)
				 */
				action = tquic_ratelimit_check_initial(
					sock_net(sk), &src_addr,
					data + 6, dcid_len,
					token, token_len);

				switch (action) {
				case TQUIC_RL_ACCEPT:
					/* Continue processing */
					break;

				case TQUIC_RL_RATE_LIMITED:
					/*
					 * Rate limited - silently drop
					 * No response to avoid amplification
					 */
					kfree_skb(skb);
					return -EBUSY;

				case TQUIC_RL_COOKIE_REQUIRED:
					/*
					 * Under attack - send Retry with cookie
					 * This validates the source address
					 */
					if (dcid_len > 0 && offset > 6 + dcid_len) {
						u8 cookie[64];
						size_t cookie_len = sizeof(cookie);
						int ret;

						ret = tquic_ratelimit_generate_cookie(
							sock_net(sk), &src_addr,
							data + 6, dcid_len,
							cookie, &cookie_len);
						if (ret == 0) {
							/* Send Retry packet with cookie as token */
							tquic_retry_send(sk, &src_addr,
									 TQUIC_VERSION_1,
									 data + 6, dcid_len,
									 data + 7 + dcid_len,
									 scid_len);
						}
					}
					kfree_skb(skb);
					return 0;

				case TQUIC_RL_BLACKLISTED:
					/* Blacklisted - silently drop */
					kfree_skb(skb);
					return -EACCES;
				}
			}
		}
	}

	/* Check for stateless reset (received from peer) */
	if (len < TQUIC_STATELESS_RESET_MIN_LEN)
		goto not_reset;

	if (data[0] & TQUIC_HEADER_FORM_LONG)
		goto not_reset;

	/* Try to find connection for reset check */
	if (len > 1) {
		u8 dcid_len = min_t(size_t, len - 1, TQUIC_MAX_CID_LEN);
		conn = tquic_lookup_by_dcid(data + 1, dcid_len);
	}

	if (conn && tquic_is_stateless_reset_internal(conn, data, len)) {
		tquic_handle_stateless_reset(conn);
		kfree_skb(skb);
		return 0;
	}

not_reset:
	/* Check for version negotiation */
	if (unlikely(tquic_is_version_negotiation(data, len))) {
		/* Need connection context */
		if (len > 6) {
			u8 dcid_len = data[5];

			/*
			 * SECURITY: Validate DCID length before use.
			 * A crafted dcid_len > 20 would cause data + 6
			 * to be passed with an oversized length to
			 * the connection lookup, potentially reading
			 * past the packet buffer.
			 */
			if (dcid_len <= TQUIC_MAX_CID_LEN &&
			    len > (size_t)6 + dcid_len)
				conn = tquic_lookup_by_dcid(data + 6, dcid_len);
		}

		if (conn) {
			ret = tquic_process_version_negotiation(conn, data, len);
		} else {
			ret = 0;  /* Ignore orphan version negotiation */
		}

		kfree_skb(skb);
		return ret;
	}

	/* Process the QUIC packet */
	ret = tquic_process_packet(conn, path, data, len, &src_addr);

	/*
	 * Per RFC 9000 Section 10.3:
	 * "An endpoint that receives packets that it cannot process sends
	 * a stateless reset in response."
	 *
	 * If we couldn't find a connection for a short header packet,
	 * we should send a stateless reset. However, we must NOT send
	 * a stateless reset in response to:
	 * - Long header packets (might be Initial packets for new connections)
	 * - Packets that could themselves be stateless resets
	 * - Packets too small to trigger without amplification
	 */
	if (ret == -ENOENT && !(data[0] & TQUIC_HEADER_FORM_LONG)) {
		/*
		 * Short header packet with unknown CID - send stateless reset
		 *
		 * We need to extract the DCID from the packet to generate
		 * the correct token. For short headers, DCID starts at byte 1.
		 */
		struct tquic_cid unknown_cid;
		const u8 *static_key;

		/*
		 * Don't send reset if this packet could itself be a reset
		 * (would cause infinite loop)
		 */
		if (len >= TQUIC_STATELESS_RESET_MIN_LEN) {
			/*
			 * Extract DCID - we don't know the length, but we
			 * can use up to TQUIC_DEFAULT_CID_LEN bytes
			 */
			unknown_cid.len = min_t(size_t,
						len - 1 - TQUIC_STATELESS_RESET_TOKEN_LEN,
						TQUIC_DEFAULT_CID_LEN);
			if (unknown_cid.len > 0) {
				memcpy(unknown_cid.id, data + 1, unknown_cid.len);
				unknown_cid.seq_num = 0;
				unknown_cid.retire_prior_to = 0;

				static_key = tquic_stateless_reset_get_static_key();
				if (static_key) {
					tquic_stateless_reset_send(sk,
								   &local_addr,
								   &src_addr,
								   &unknown_cid,
								   static_key,
								   len);
					tquic_dbg("sent stateless reset for unknown CID\n");
				}
			}
		}
	}

	kfree_skb(skb);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_udp_recv);

/*
 * Encapsulated receive callback for UDP tunnel
 */
static int tquic_encap_recv(struct sock *sk, struct sk_buff *skb)
{
	/* Remove UDP header and process */
	__skb_pull(skb, sizeof(struct udphdr));

	return tquic_udp_recv(sk, skb);
}

/*
 * Setup UDP encapsulation for a socket
 */
int tquic_setup_udp_encap(struct sock *sk)
{
	/* Set encapsulation callback */
	udp_sk(sk)->encap_type = 1;  /* Custom encapsulation */
	udp_sk(sk)->encap_rcv = tquic_encap_recv;

	/* Enable GRO */
	tquic_udp_tunnel_encap_enable(sk);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_setup_udp_encap);

/*
 * Remove UDP encapsulation from socket
 */
void tquic_clear_udp_encap(struct sock *sk)
{
	udp_sk(sk)->encap_type = 0;
	udp_sk(sk)->encap_rcv = NULL;
}
EXPORT_SYMBOL_GPL(tquic_clear_udp_encap);

/*
 * =============================================================================
 * Coalesced Packet Handling
 * =============================================================================
 */

/*
 * Process coalesced packets (multiple QUIC packets in single UDP datagram)
 */
int tquic_process_coalesced(struct tquic_connection *conn,
			    struct tquic_path *path,
			    u8 *data, size_t total_len,
			    struct sockaddr_storage *src_addr)
{
	size_t offset = 0;
	int packets = 0;
	int ret;

	while (offset < total_len) {
		size_t pkt_len;
		u8 first_byte = data[offset];

		if (first_byte & TQUIC_HEADER_FORM_LONG) {
			/* Long header - need to parse length field */
			size_t hdr_len;
			u8 dcid_len, scid_len;
			u64 pkt_len_val;

			if (offset + 7 > total_len)
				break;

			/* Skip version (4 bytes) */
			dcid_len = data[offset + 5];
			if (offset + 6 + dcid_len > total_len)
				break;

			/* Bounds check before reading scid_len */
			if (offset + 6 + dcid_len >= total_len)
				break;

			scid_len = data[offset + 6 + dcid_len];
			if (offset + 7 + dcid_len + scid_len > total_len)
				break;

			hdr_len = 7 + dcid_len + scid_len;

			/* Token for Initial packets */
			if (((first_byte & 0x30) >> 4) == TQUIC_PKT_INITIAL) {
				u64 token_len;
				int vlen = tquic_decode_varint(data + offset + hdr_len,
							       total_len - offset - hdr_len,
							       &token_len);
				if (vlen < 0)
					break;
				hdr_len += vlen + token_len;
			}

			/* Length field */
			{
				int vlen = tquic_decode_varint(data + offset + hdr_len,
							       total_len - offset - hdr_len,
							       &pkt_len_val);
				if (vlen < 0)
					break;
				hdr_len += vlen;
			}

			pkt_len = hdr_len + pkt_len_val;
		} else {
			/* Short header - extends to end of datagram */
			pkt_len = total_len - offset;
		}

		if (offset + pkt_len > total_len)
			pkt_len = total_len - offset;

		/* Process this packet */
		ret = tquic_process_packet(conn, path, data + offset, pkt_len, src_addr);
		if (ret < 0 && ret != -ENOENT)
			return ret;

		offset += pkt_len;
		packets++;
	}

	return packets;
}
EXPORT_SYMBOL_GPL(tquic_process_coalesced);

/*
 * =============================================================================
 * Module Registration
 * =============================================================================
 */

MODULE_DESCRIPTION("TQUIC Packet Reception Path");
MODULE_LICENSE("GPL");
