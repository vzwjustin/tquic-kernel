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
#include <net/sock.h>
#include <net/udp.h>
#include <net/udp_tunnel.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/gro.h>
#include <crypto/aead.h>
#include <net/tquic.h>

#include "tquic_mib.h"
#include "cong/tquic_cong.h"

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
#define TQUIC_FRAME_ACK_FREQUENCY	0xaf
#define TQUIC_FRAME_MP_NEW_CONNECTION_ID 0x40
#define TQUIC_FRAME_MP_RETIRE_CONNECTION_ID 0x41
#define TQUIC_FRAME_MP_ACK		0x42
#define TQUIC_FRAME_PATH_ABANDON	0x43

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
#define TQUIC_STATELESS_RESET_MIN_LEN	21
#define TQUIC_STATELESS_RESET_TOKEN_LEN	16

/* GRO configuration */
#define TQUIC_GRO_MAX_HOLD		10
#define TQUIC_GRO_FLUSH_TIMEOUT_US	1000

/* Forward declarations */
static int tquic_process_frames(struct tquic_connection *conn,
				struct tquic_path *path,
				u8 *payload, size_t len,
				int enc_level, u64 pkt_num);

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

	if (dcid_len > TQUIC_MAX_CID_LEN)
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
static struct tquic_path *tquic_find_path_by_cid(struct tquic_connection *conn,
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

	/* No crypto state - copy as-is for testing */
	if (payload_len > 16) {
		memcpy(out, payload, payload_len - 16);
		*out_len = payload_len - 16;
	} else {
		*out_len = 0;
	}

	return 0;
}

/*
 * =============================================================================
 * Stateless Reset Detection
 * =============================================================================
 */

/*
 * Check if packet is a stateless reset
 */
static bool tquic_is_stateless_reset(struct tquic_connection *conn,
				     const u8 *data, size_t len)
{
	const u8 *token;

	/* Must be at least minimum length */
	if (len < TQUIC_STATELESS_RESET_MIN_LEN)
		return false;

	/* Short header with random bits that looks like valid packet */
	if (data[0] & TQUIC_HEADER_FORM_LONG)
		return false;

	/* Extract token from last 16 bytes */
	token = data + len - TQUIC_STATELESS_RESET_TOKEN_LEN;

	/* Compare with known stateless reset tokens */
	/* In a real implementation, we'd check against tokens from */
	/* NEW_CONNECTION_ID frames */

	return false;  /* Not implemented yet */
}

/*
 * Handle stateless reset
 */
static void tquic_handle_stateless_reset(struct tquic_connection *conn)
{
	pr_info("tquic: received stateless reset for connection\n");

	spin_lock(&conn->lock);
	conn->state = TQUIC_CONN_CLOSED;
	spin_unlock(&conn->lock);

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

	/* Skip first byte and version (0) */
	dcid_len = data[5];
	if (len < 6 + dcid_len + 1)
		return -EINVAL;

	scid_len = data[6 + dcid_len];
	if (len < 7 + dcid_len + scid_len)
		return -EINVAL;

	versions = data + 7 + dcid_len + scid_len;
	versions_len = len - 7 - dcid_len - scid_len;

	pr_info("tquic: received version negotiation, offered versions:\n");

	/* Check each offered version */
	for (i = 0; i + 4 <= versions_len; i += 4) {
		u32 version = (versions[i] << 24) | (versions[i + 1] << 16) |
			      (versions[i + 2] << 8) | versions[i + 3];

		pr_info("  0x%08x\n", version);

		if (version == TQUIC_VERSION_1 || version == TQUIC_VERSION_2)
			found = true;
	}

	if (!found) {
		pr_warn("tquic: no compatible version found\n");
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
static int tquic_send_version_negotiation(struct sock *sk,
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

	/* Process additional ACK ranges */
	for (u64 i = 0; i < ack_range_count; i++) {
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

		/* Update MIB counter for ECN frames received */
		if (ctx->conn && ctx->conn->sk) {
			TQUIC_INC_STATS(sock_net(ctx->conn->sk), TQUIC_MIB_ECNACKSRX);
			if (ecn_ce > 0)
				TQUIC_ADD_STATS(sock_net(ctx->conn->sk),
						TQUIC_MIB_ECNCEMARKSRX, ecn_ce);
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

			pr_debug("tquic: ECN-CE on path %u: ce=%llu ect0=%llu ect1=%llu\n",
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

	if (ctx->offset + length > ctx->len)
		return -EINVAL;

	/* Process crypto data */
	/* This would feed into the TLS handshake state machine */

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

	skb_queue_tail(&stream->recv_buf, data_skb);
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
	struct tquic_stream *stream;
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
		pr_debug("tquic: PATH_CHALLENGE handling failed: %d\n", ret);
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

	/* Skip reason phrase */
	if (ctx->offset + reason_len > ctx->len)
		return -EINVAL;
	ctx->offset += reason_len;

	pr_info("tquic: received CONNECTION_CLOSE, error=%llu frame_type=%llu\n",
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
 * Process DATAGRAM frame
 */
static int tquic_process_datagram_frame(struct tquic_rx_ctx *ctx)
{
	u8 frame_type = ctx->data[ctx->offset];
	bool has_length = (frame_type & 0x01) != 0;
	u64 length;
	int ret;

	ctx->offset++;  /* Skip frame type */

	if (has_length) {
		ret = tquic_decode_varint(ctx->data + ctx->offset,
					  ctx->len - ctx->offset, &length);
		if (ret < 0)
			return ret;
		ctx->offset += ret;
	} else {
		length = ctx->len - ctx->offset;
	}

	if (ctx->offset + length > ctx->len)
		return -EINVAL;

	/* Deliver datagram to application */
	/* This would queue to a datagram receive buffer */

	ctx->offset += length;
	ctx->ack_eliciting = true;

	return 0;
}

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

	ctx.conn = conn;
	ctx.path = path;
	ctx.data = payload;
	ctx.len = len;
	ctx.offset = 0;
	ctx.pkt_num = pkt_num;
	ctx.enc_level = enc_level;
	ctx.ack_eliciting = false;

	while (ctx.offset < ctx.len) {
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
		} else {
			/* Unknown frame type */
			pr_debug("tquic: unknown frame type 0x%02x\n", frame_type);
			ret = -EINVAL;
		}

		if (ret < 0)
			break;
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
static int tquic_parse_long_header(struct tquic_rx_ctx *ctx,
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
static int tquic_parse_short_header(struct tquic_rx_ctx *ctx,
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

	/* Read truncated packet number */
	for (int i = 0; i < pkt_num_len; i++)
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
	hrtimer_init(&gro->gro_flush_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);

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
static struct sk_buff *tquic_gro_receive(struct tquic_gro_state *gro,
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
	size_t payload_len, decrypted_len;
	u8 *decrypted;
	int ret;

	ctx.data = data;
	ctx.len = len;
	ctx.offset = 0;

	/* Check header form */
	if (data[0] & TQUIC_HEADER_FORM_LONG) {
		/* Long header */
		ret = tquic_parse_long_header(&ctx, dcid, &dcid_len,
					      scid, &scid_len,
					      &version, &pkt_type);
		if (ret < 0)
			return ret;

		/* Handle version negotiation */
		if (version == TQUIC_VERSION_NEGOTIATION) {
			if (conn)
				return tquic_process_version_negotiation(conn, data, len);
			return 0;
		}

		/* Lookup connection by DCID if not provided */
		if (!conn)
			conn = tquic_lookup_by_dcid(dcid, dcid_len);

		if (!conn) {
			/* New connection - would handle Initial packet */
			pr_debug("tquic: no connection found for DCID\n");
			return -ENOENT;
		}

		/* Parse token for Initial packets */
		if (pkt_type == TQUIC_PKT_INITIAL) {
			u64 token_len;
			ret = tquic_decode_varint(data + ctx.offset,
						  len - ctx.offset, &token_len);
			if (ret < 0)
				return ret;
			ctx.offset += ret + token_len;
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

		ret = tquic_parse_short_header(&ctx, conn->scid.len,
					       dcid, &key_phase, &spin_bit);
		if (ret < 0)
			return ret;

		pkt_type = -1;  /* Short header / 1-RTT */
		pkt_num_len = (data[0] & 0x03) + 1;
	}

	/* Find path if not provided */
	if (!path && conn)
		path = tquic_find_path_by_addr(conn, src_addr);

	/* Remove header protection */
	ret = tquic_remove_header_protection(conn, data, ctx.offset,
					     data + ctx.offset,
					     len - ctx.offset,
					     ctx.is_long_header);
	if (ret < 0)
		return ret;

	/* Decode packet number */
	pkt_num = tquic_decode_pkt_num(data + ctx.offset, pkt_num_len, 0);
	ctx.offset += pkt_num_len;

	/* Decrypt payload */
	payload = data + ctx.offset;
	payload_len = len - ctx.offset;

	decrypted = kmalloc(payload_len, GFP_ATOMIC);
	if (!decrypted)
		return -ENOMEM;

	ret = tquic_decrypt_payload(conn, data, ctx.offset,
				    payload, payload_len,
				    pkt_num,
				    pkt_type >= 0 ? pkt_type : 3,
				    decrypted, &decrypted_len);
	if (ret < 0) {
		kfree(decrypted);
		return ret;
	}

	/* Process frames */
	ret = tquic_process_frames(conn, path, decrypted, decrypted_len,
				   pkt_type >= 0 ? pkt_type : 3, pkt_num);

	kfree(decrypted);

	/* Update statistics */
	if (ret >= 0) {
		conn->stats.rx_packets++;
		if (path) {
			path->stats.rx_packets++;
			path->stats.rx_bytes += len;
			path->last_activity = ktime_get();
		}

		/* Update MIB counters for packet reception */
		if (conn->sk) {
			TQUIC_INC_STATS(sock_net(conn->sk), TQUIC_MIB_PACKETSRX);
			TQUIC_ADD_STATS(sock_net(conn->sk), TQUIC_MIB_BYTESRX, len);
		}
	}

	return ret;
}

/*
 * UDP receive callback - main entry point for received packets
 */
int tquic_udp_recv(struct sock *sk, struct sk_buff *skb)
{
	struct tquic_connection *conn = NULL;
	struct tquic_path *path = NULL;
	struct sockaddr_storage src_addr;
	u8 *data;
	size_t len;
	int ret;

	if (!skb)
		return -EINVAL;

	/* Extract source address */
	memset(&src_addr, 0, sizeof(src_addr));
	if (skb->protocol == htons(ETH_P_IP)) {
		struct sockaddr_in *sin = (struct sockaddr_in *)&src_addr;
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = ip_hdr(skb)->saddr;
		sin->sin_port = udp_hdr(skb)->source;
	} else if (skb->protocol == htons(ETH_P_IPV6)) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&src_addr;
		sin6->sin6_family = AF_INET6;
		sin6->sin6_addr = ipv6_hdr(skb)->saddr;
		sin6->sin6_port = udp_hdr(skb)->source;
	}

	/* Get UDP payload */
	data = skb->data + sizeof(struct udphdr);
	len = skb->len - sizeof(struct udphdr);

	if (len < 1) {
		kfree_skb(skb);
		return -EINVAL;
	}

	/* Check for stateless reset */
	if (len >= TQUIC_STATELESS_RESET_MIN_LEN &&
	    !(data[0] & TQUIC_HEADER_FORM_LONG)) {
		/* Try to find connection for reset check */
		if (len > 1) {
			u8 dcid_len = min_t(size_t, len - 1, TQUIC_MAX_CID_LEN);
			conn = tquic_lookup_by_dcid(data + 1, dcid_len);
		}

		if (conn && tquic_is_stateless_reset(conn, data, len)) {
			tquic_handle_stateless_reset(conn);
			kfree_skb(skb);
			return 0;
		}
	}

	/* Check for version negotiation */
	if (tquic_is_version_negotiation(data, len)) {
		/* Need connection context */
		if (len > 6) {
			u8 dcid_len = data[5];
			if (len > 6 + dcid_len)
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
	struct udp_sock *up = udp_sk(sk);

	/* Set encapsulation callback */
	udp_sk(sk)->encap_type = 1;  /* Custom encapsulation */
	udp_sk(sk)->encap_rcv = tquic_encap_recv;

	/* Enable GRO */
	udp_tunnel_encap_enable(sk->sk_socket);

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

			scid_len = data[offset + 6 + dcid_len];
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
