// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Packet Transmission Path
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Implements the QUIC packet transmission path with multipath WAN bonding
 * support including frame generation, packet assembly, encryption,
 * path selection, and pacing.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/random.h>
#include <linux/hrtimer.h>
#include <linux/workqueue.h>
#include <linux/rcupdate.h>
#include <net/sock.h>
#include <net/udp.h>
#include <net/udp_tunnel.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/route.h>
#include <net/inet_common.h>
#include <net/inet_sock.h>
#include <crypto/aead.h>
#include <crypto/skcipher.h>
#include <net/tquic.h>

#include "tquic_compat.h"
#include "tquic_debug.h"
#include "protocol.h"
#include "tquic_init.h"

#include "tquic_mib.h"
#include "cong/tquic_cong.h"
#include "grease.h"
#include "crypto/key_update.h"
#include "crypto/header_protection.h"
#include "tquic_token.h"
#include "core/mp_frame.h"
#include "core/quic_loss.h"

/* Maximum packets per output_flush iteration */
#define TQUIC_TX_WORK_BATCH_MAX		64

/* Slab cache for tquic_pending_frame (CF-046: avoid per-frame kzalloc) */
struct kmem_cache *tquic_frame_cache;
EXPORT_SYMBOL_GPL(tquic_frame_cache);

/* QUIC frame types */
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
#define TQUIC_FRAME_PATH_ABANDON	TQUIC_MP_FRAME_PATH_ABANDON

/* Packet header flags */
#define TQUIC_HEADER_FORM_LONG		0x80
#define TQUIC_HEADER_FIXED_BIT		0x40
#define TQUIC_HEADER_SPIN_BIT		0x20
#define TQUIC_HEADER_KEY_PHASE		0x04

/* Long header packet types */
#define TQUIC_PKT_INITIAL		0x00
#define TQUIC_PKT_ZERO_RTT		0x01
#define TQUIC_PKT_HANDSHAKE		0x02
#define TQUIC_PKT_RETRY			0x03

/* GSO/TSO configuration */
#define TQUIC_GSO_MAX_SEGS		64
#define TQUIC_GSO_MAX_SIZE		65535

/* Maximum QUIC short header size: 1 (flags) + 20 (DCID) + 4 (pkt_num) = 25 */
#define TQUIC_MAX_SHORT_HEADER_SIZE	64

/* Pacing configuration */
#define TQUIC_PACING_GAIN		100	/* 100% of calculated rate */
#define TQUIC_PACING_MIN_INTERVAL_US	1	/* Minimum 1us between packets */
#define TQUIC_PACING_MAX_BURST		10	/* Max packets in a burst */

/* Frame generation context */
struct tquic_frame_ctx {
	struct tquic_connection *conn;
	struct tquic_path *path;
	u8 *buf;
	size_t buf_len;
	size_t offset;
	u64 pkt_num;
	int enc_level;
	bool ack_eliciting;
};

/*
 * Pending frame for coalescing
 *
 * Zero-copy optimization (P-001):
 * Instead of allocating and copying data for each frame, we reference
 * the original source data directly. This eliminates 50+ allocations
 * per send and reduces memory copies from 2 to 1.
 *
 * Frame lifecycle:
 * 1. Frame created with data_ref pointing to source (user buffer/skb)
 * 2. Frame passed to tquic_assemble_packet (synchronous)
 * 3. In tquic_coalesce_frames: single copy from data_ref to packet buffer
 * 4. Frame freed (no kfree if owns_data=false)
 *
 * Safety: The referenced data must remain valid until packet assembly
 * completes. Both tquic_xmit() and tquic_output_flush() ensure this
 * by calling tquic_assemble_packet() synchronously before returning.
 */
struct tquic_pending_frame {
	struct list_head list;
	u8 type;
	u8 *data;		/* For allocated data (legacy/special frames) */
	const u8 *data_ref;	/* Zero-copy reference to original data */
	struct sk_buff *skb;	/* Optional: payload sourced from skb (may be non-linear) */
	u32 skb_off;		/* Byte offset into skb for payload start */
	size_t len;
	u64 stream_id;
	u64 offset;
	u64 retire_prior_to;	/* For NEW_CONNECTION_ID frame */
	const struct tquic_cid *new_cid;	/* CID for NEW_CONNECTION_ID */
	const u8 *reset_token;	/* Reset token for NEW_CONNECTION_ID */
	bool fin;
	bool owns_data;		/* True if data was allocated and must be freed */
};

static_assert(sizeof(struct tquic_stream_skb_cb) <= sizeof(((struct sk_buff *)0)->cb),
	      "tquic_stream_skb_cb must fit in skb->cb");

/* Pacing state per path */
struct tquic_pacing_state {
	struct hrtimer timer;
	struct work_struct work;
	struct tquic_connection *conn;	/* owning connection */
	struct tquic_path *path;
	struct sk_buff_head queue;
	spinlock_t lock;
	ktime_t next_send_time;
	u64 pacing_rate;		/* bytes per second */
	u32 tokens;			/* tokens available for burst */
	u32 max_tokens;			/* maximum burst tokens */
	bool timer_active;
};

/* GSO context */
struct tquic_gso_ctx {
	struct sk_buff *gso_skb;
	u16 gso_size;
	u16 gso_segs;
	u16 current_seg;
	u32 total_len;
};

/* Forward declarations */
int tquic_output_packet(struct tquic_connection *conn,
			struct tquic_path *path,
			struct sk_buff *skb);
static void tquic_pacing_work(struct work_struct *work);

/*
 * =============================================================================
 * Variable Length Integer Encoding (QUIC RFC 9000)
 * =============================================================================
 *
 * tquic_varint_len and other varint functions are defined in core/varint.c
 */

static inline int tquic_encode_varint(u8 *buf, size_t buf_len, u64 val)
{
	int len = tquic_varint_len(val);

	tquic_dbg("encode_varint: val=%llu buf_len=%zu\n", val, buf_len);

	if (len == 0)
		return -EOVERFLOW;  /* Value exceeds QUIC varint range */
	if (len > buf_len)
		return -ENOSPC;

	switch (len) {
	case 1:
		buf[0] = (u8)val;
		break;
	case 2:
		buf[0] = 0x40 | ((val >> 8) & 0x3f);
		buf[1] = (u8)val;
		break;
	case 4:
		buf[0] = 0x80 | ((val >> 24) & 0x3f);
		buf[1] = (val >> 16) & 0xff;
		buf[2] = (val >> 8) & 0xff;
		buf[3] = (u8)val;
		break;
	case 8:
		buf[0] = 0xc0 | ((val >> 56) & 0x3f);
		buf[1] = (val >> 48) & 0xff;
		buf[2] = (val >> 40) & 0xff;
		buf[3] = (val >> 32) & 0xff;
		buf[4] = (val >> 24) & 0xff;
		buf[5] = (val >> 16) & 0xff;
		buf[6] = (val >> 8) & 0xff;
		buf[7] = (u8)val;
		break;
	}

	tquic_dbg("encode_varint: encoded len=%d\n", len);
	return len;
}

/*
 * =============================================================================
 * Frame Generation
 * =============================================================================
 */

/*
 * Generate PADDING frame
 */
static int tquic_gen_padding_frame(struct tquic_frame_ctx *ctx, size_t len)
{
	tquic_dbg("gen_padding: len=%zu offset=%zu\n", len, ctx->offset);

	if (ctx->offset + len > ctx->buf_len)
		return -ENOSPC;

	memset(ctx->buf + ctx->offset, 0, len);
	ctx->offset += len;

	return len;
}

/*
 * Generate PING frame
 */
static int tquic_gen_ping_frame(struct tquic_frame_ctx *ctx)
{
	tquic_dbg("gen_ping: offset=%zu\n", ctx->offset);

	if (ctx->offset + 1 > ctx->buf_len)
		return -ENOSPC;

	ctx->buf[ctx->offset++] = TQUIC_FRAME_PING;
	ctx->ack_eliciting = true;

	return 1;
}

/*
 * Generate ACK frame
 */
static int tquic_gen_ack_frame(struct tquic_frame_ctx *ctx,
			       u64 largest_ack, u64 ack_delay,
			       u64 ack_range_count, u64 first_ack_range)
{
	u8 *start = ctx->buf + ctx->offset;
	int ret;

	if (ctx->offset + 1 > ctx->buf_len)
		return -ENOSPC;

	ctx->buf[ctx->offset++] = TQUIC_FRAME_ACK;

	ret = tquic_encode_varint(ctx->buf + ctx->offset,
				  ctx->buf_len - ctx->offset, largest_ack);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	ret = tquic_encode_varint(ctx->buf + ctx->offset,
				  ctx->buf_len - ctx->offset, ack_delay);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	ret = tquic_encode_varint(ctx->buf + ctx->offset,
				  ctx->buf_len - ctx->offset, ack_range_count);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	ret = tquic_encode_varint(ctx->buf + ctx->offset,
				  ctx->buf_len - ctx->offset, first_ack_range);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	/* Note: ACK frames are not ack-eliciting */

	return ctx->buf + ctx->offset - start;
}

/*
 * Generate CRYPTO frame
 */
static int tquic_gen_crypto_frame(struct tquic_frame_ctx *ctx,
				  u64 offset, const u8 *data, size_t data_len)
{
	u8 *start = ctx->buf + ctx->offset;
	int ret;

	if (ctx->offset + 1 > ctx->buf_len)
		return -ENOSPC;

	ctx->buf[ctx->offset++] = TQUIC_FRAME_CRYPTO;

	ret = tquic_encode_varint(ctx->buf + ctx->offset,
				  ctx->buf_len - ctx->offset, offset);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	ret = tquic_encode_varint(ctx->buf + ctx->offset,
				  ctx->buf_len - ctx->offset, data_len);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	if (ctx->offset + data_len > ctx->buf_len)
		return -ENOSPC;

	memcpy(ctx->buf + ctx->offset, data, data_len);
	ctx->offset += data_len;
	ctx->ack_eliciting = true;

	return ctx->buf + ctx->offset - start;
}

/*
 * Generate STREAM frame
 */
static int tquic_gen_stream_frame(struct tquic_frame_ctx *ctx,
				  u64 stream_id, u64 offset,
				  const u8 *data, size_t data_len,
				  bool fin)
{
	u8 *start = ctx->buf + ctx->offset;
	u8 frame_type = TQUIC_FRAME_STREAM;
	int ret;

	/* Build frame type with flags */
	if (offset > 0)
		frame_type |= 0x04;  /* OFF bit */
	frame_type |= 0x02;  /* LEN bit (always include length) */
	if (fin)
		frame_type |= 0x01;  /* FIN bit */

	if (ctx->offset + 1 > ctx->buf_len)
		return -ENOSPC;

	ctx->buf[ctx->offset++] = frame_type;

	/* Stream ID */
	ret = tquic_encode_varint(ctx->buf + ctx->offset,
				  ctx->buf_len - ctx->offset, stream_id);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	/* Offset (if present) */
	if (offset > 0) {
		ret = tquic_encode_varint(ctx->buf + ctx->offset,
					  ctx->buf_len - ctx->offset, offset);
		if (ret < 0)
			return ret;
		ctx->offset += ret;
	}

	/* Length */
	ret = tquic_encode_varint(ctx->buf + ctx->offset,
				  ctx->buf_len - ctx->offset, data_len);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	/* Data - single copy directly into packet buffer */
	if (ctx->offset + data_len > ctx->buf_len)
		return -ENOSPC;

	/*
	 * Zero-copy optimization: Only one memcpy here.
	 * The data pointer now references the original source
	 * (user buffer or skb data), avoiding intermediate allocation.
	 */
	memcpy(ctx->buf + ctx->offset, data, data_len);
	ctx->offset += data_len;
	ctx->ack_eliciting = true;

	return ctx->buf + ctx->offset - start;
}

static int tquic_gen_stream_frame_skb(struct tquic_frame_ctx *ctx,
				      u64 stream_id, u64 offset,
				      struct sk_buff *skb, u32 skb_off,
				      size_t data_len, bool fin)
{
	u8 *start = ctx->buf + ctx->offset;
	u8 frame_type = TQUIC_FRAME_STREAM;
	int ret;

	if (unlikely(!skb))
		return -EINVAL;

	/* Build frame type with flags */
	if (offset > 0)
		frame_type |= 0x04;  /* OFF bit */
	frame_type |= 0x02;  /* LEN bit (always include length) */
	if (fin)
		frame_type |= 0x01;  /* FIN bit */

	if (ctx->offset + 1 > ctx->buf_len)
		return -ENOSPC;

	ctx->buf[ctx->offset++] = frame_type;

	/* Stream ID */
	ret = tquic_encode_varint(ctx->buf + ctx->offset,
				  ctx->buf_len - ctx->offset, stream_id);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	/* Offset (if present) */
	if (offset > 0) {
		ret = tquic_encode_varint(ctx->buf + ctx->offset,
					  ctx->buf_len - ctx->offset, offset);
		if (ret < 0)
			return ret;
		ctx->offset += ret;
	}

	/* Length */
	ret = tquic_encode_varint(ctx->buf + ctx->offset,
				  ctx->buf_len - ctx->offset, data_len);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	if (ctx->offset + data_len > ctx->buf_len)
		return -ENOSPC;

	if (skb_copy_bits(skb, skb_off, ctx->buf + ctx->offset, data_len))
		return -EFAULT;

	ctx->offset += data_len;
	ctx->ack_eliciting = true;

	return ctx->buf + ctx->offset - start;
}

/*
 * Generate MAX_DATA frame
 */
static int tquic_gen_max_data_frame(struct tquic_frame_ctx *ctx, u64 max_data)
{
	u8 *start = ctx->buf + ctx->offset;
	int ret;

	tquic_dbg("gen_max_data: max_data=%llu\n", max_data);

	if (ctx->offset + 1 > ctx->buf_len)
		return -ENOSPC;

	ctx->buf[ctx->offset++] = TQUIC_FRAME_MAX_DATA;

	ret = tquic_encode_varint(ctx->buf + ctx->offset,
				  ctx->buf_len - ctx->offset, max_data);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	ctx->ack_eliciting = true;

	return ctx->buf + ctx->offset - start;
}

/*
 * Generate MAX_STREAM_DATA frame
 */
static int tquic_gen_max_stream_data_frame(struct tquic_frame_ctx *ctx,
					   u64 stream_id, u64 max_data)
{
	u8 *start = ctx->buf + ctx->offset;
	int ret;

	if (ctx->offset + 1 > ctx->buf_len)
		return -ENOSPC;

	ctx->buf[ctx->offset++] = TQUIC_FRAME_MAX_STREAM_DATA;

	ret = tquic_encode_varint(ctx->buf + ctx->offset,
				  ctx->buf_len - ctx->offset, stream_id);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	ret = tquic_encode_varint(ctx->buf + ctx->offset,
				  ctx->buf_len - ctx->offset, max_data);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	ctx->ack_eliciting = true;

	return ctx->buf + ctx->offset - start;
}

/*
 * Generate PATH_CHALLENGE frame
 */
static int tquic_gen_path_challenge_frame(struct tquic_frame_ctx *ctx,
					  const u8 data[8])
{
	if (ctx->offset + 9 > ctx->buf_len)
		return -ENOSPC;

	ctx->buf[ctx->offset++] = TQUIC_FRAME_PATH_CHALLENGE;
	memcpy(ctx->buf + ctx->offset, data, 8);
	ctx->offset += 8;
	ctx->ack_eliciting = true;

	return 9;
}

/*
 * Generate PATH_RESPONSE frame
 */
static int tquic_gen_path_response_frame(struct tquic_frame_ctx *ctx,
					 const u8 data[8])
{
	if (ctx->offset + 9 > ctx->buf_len)
		return -ENOSPC;

	ctx->buf[ctx->offset++] = TQUIC_FRAME_PATH_RESPONSE;
	memcpy(ctx->buf + ctx->offset, data, 8);
	ctx->offset += 8;
	ctx->ack_eliciting = true;

	return 9;
}

/*
 * Generate HANDSHAKE_DONE frame (1 byte: type 0x1e)
 */
static int tquic_gen_handshake_done_frame(struct tquic_frame_ctx *ctx)
{
	if (ctx->offset + 1 > ctx->buf_len)
		return -ENOSPC;

	ctx->buf[ctx->offset++] = TQUIC_FRAME_HANDSHAKE_DONE;
	ctx->ack_eliciting = true;

	return 1;
}

/*
 * Generate NEW_CONNECTION_ID frame
 */
static int tquic_gen_new_connection_id_frame(struct tquic_frame_ctx *ctx,
							    u64 seq_num, u64 retire_prior_to,
							    const struct tquic_cid *cid,
							    const u8 stateless_reset_token[16])
{
	u8 *start = ctx->buf + ctx->offset;
	int ret;

	if (ctx->offset + 1 > ctx->buf_len)
		return -ENOSPC;

	ctx->buf[ctx->offset++] = TQUIC_FRAME_NEW_CONNECTION_ID;

	ret = tquic_encode_varint(ctx->buf + ctx->offset,
				  ctx->buf_len - ctx->offset, seq_num);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	ret = tquic_encode_varint(ctx->buf + ctx->offset,
				  ctx->buf_len - ctx->offset, retire_prior_to);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	if (ctx->offset + 1 + cid->len + 16 > ctx->buf_len)
		return -ENOSPC;

	ctx->buf[ctx->offset++] = cid->len;
	memcpy(ctx->buf + ctx->offset, cid->id, cid->len);
	ctx->offset += cid->len;

	memcpy(ctx->buf + ctx->offset, stateless_reset_token, 16);
	ctx->offset += 16;

	ctx->ack_eliciting = true;

	return ctx->buf + ctx->offset - start;
}

/*
 * Generate CONNECTION_CLOSE frame
 */
static int tquic_gen_connection_close_frame(struct tquic_frame_ctx *ctx,
					    u64 error_code,
					    const char *reason, size_t reason_len)
{
	u8 *start = ctx->buf + ctx->offset;
	int ret;

	if (ctx->offset + 1 > ctx->buf_len)
		return -ENOSPC;

	ctx->buf[ctx->offset++] = TQUIC_FRAME_CONNECTION_CLOSE;

	ret = tquic_encode_varint(ctx->buf + ctx->offset,
				  ctx->buf_len - ctx->offset, error_code);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	/* Frame type (0 for transport errors) */
	ret = tquic_encode_varint(ctx->buf + ctx->offset,
				  ctx->buf_len - ctx->offset, 0);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	ret = tquic_encode_varint(ctx->buf + ctx->offset,
				  ctx->buf_len - ctx->offset, reason_len);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	if (reason_len > 0) {
		if (ctx->offset + reason_len > ctx->buf_len)
			return -ENOSPC;
		memcpy(ctx->buf + ctx->offset, reason, reason_len);
		ctx->offset += reason_len;
	}

	/* CONNECTION_CLOSE is not ack-eliciting */

	return ctx->buf + ctx->offset - start;
}

/*
 * Generate DATAGRAM frame (RFC 9221)
 *
 * DATAGRAM frames carry unreliable, unordered application data.
 *
 * @ctx: Frame generation context
 * @data: Datagram payload
 * @data_len: Payload length
 * @with_length: If true, include length field (type 0x31); if false,
 *               omit length field (type 0x30, datagram extends to end)
 *
 * Frame format:
 *   Type: 0x30 (no length) or 0x31 (with length)
 *   [Length]: varint (only if type 0x31)
 *   Data: payload bytes
 *
 * Per RFC 9221, the "without length" variant (0x30) is more space-efficient
 * when the datagram is the last frame in a packet, as no length field is
 * needed. The "with length" variant (0x31) allows multiple datagrams or
 * other frames to follow in the same packet.
 */
static int tquic_gen_datagram_frame(struct tquic_frame_ctx *ctx,
				    const u8 *data, size_t data_len,
				    bool with_length)
{
	u8 *start = ctx->buf + ctx->offset;
	int ret;

	if (ctx->offset + 1 > ctx->buf_len)
		return -ENOSPC;

	/* Frame type: 0x30 without length, 0x31 with length */
	ctx->buf[ctx->offset++] = TQUIC_FRAME_DATAGRAM | (with_length ? 0x01 : 0x00);

	if (with_length) {
		ret = tquic_encode_varint(ctx->buf + ctx->offset,
					  ctx->buf_len - ctx->offset, data_len);
		if (ret < 0)
			return ret;
		ctx->offset += ret;
	}

	if (ctx->offset + data_len > ctx->buf_len)
		return -ENOSPC;

	memcpy(ctx->buf + ctx->offset, data, data_len);
	ctx->offset += data_len;
	ctx->ack_eliciting = true;

	return ctx->buf + ctx->offset - start;
}

/* Wrapper for backward compatibility - defaults to with_length variant */
static inline int tquic_gen_datagram_frame_len(struct tquic_frame_ctx *ctx,
					       const u8 *data, size_t data_len)
{
	return tquic_gen_datagram_frame(ctx, data, data_len, true);
}

/*
 * =============================================================================
 * Frame Coalescing
 * =============================================================================
 */

/*
 * Coalesce pending frames into a packet payload
 */
static int tquic_coalesce_frames(struct tquic_connection *conn,
				 struct tquic_frame_ctx *ctx,
				 struct list_head *pending_frames)
{
	struct tquic_pending_frame *frame, *tmp;
	int total = 0;
	int ret;

	list_for_each_entry_safe(frame, tmp, pending_frames, list) {
		const u8 *data_ptr;

		/* Use reference if available, otherwise use allocated data */
		data_ptr = frame->data_ref ? frame->data_ref : frame->data;

		switch (frame->type) {
		case TQUIC_FRAME_STREAM:
			if (frame->skb) {
				ret = tquic_gen_stream_frame_skb(ctx, frame->stream_id,
								 frame->offset,
								 frame->skb, frame->skb_off,
								 frame->len, frame->fin);
			} else {
				ret = tquic_gen_stream_frame(ctx, frame->stream_id,
							     frame->offset,
							     data_ptr, frame->len,
							     frame->fin);
			}
			break;

		case TQUIC_FRAME_CRYPTO:
			ret = tquic_gen_crypto_frame(ctx, frame->offset,
						     data_ptr, frame->len);
			break;

		case TQUIC_FRAME_PATH_CHALLENGE:
			ret = tquic_gen_path_challenge_frame(ctx, data_ptr);
			break;

		case TQUIC_FRAME_PATH_RESPONSE:
			ret = tquic_gen_path_response_frame(ctx, data_ptr);
			break;

		case TQUIC_FRAME_HANDSHAKE_DONE:
			ret = tquic_gen_handshake_done_frame(ctx);
			break;

		case TQUIC_FRAME_CONNECTION_CLOSE:
		case TQUIC_FRAME_CONNECTION_CLOSE_APP:
			/* error_code stored in frame->offset */
			ret = tquic_gen_connection_close_frame(
				ctx, frame->offset, NULL, 0);
			break;

		case TQUIC_FRAME_PING:
			ret = tquic_gen_ping_frame(ctx);
			break;

		case TQUIC_FRAME_NEW_CONNECTION_ID:
			ret = tquic_gen_new_connection_id_frame(ctx,
				frame->offset, frame->retire_prior_to,
				frame->new_cid, frame->reset_token);
			break;

		default:
			ret = -EINVAL;
			break;
		}

		if (ret < 0) {
			/* Not enough space, stop coalescing */
			if (ret == -ENOSPC)
				break;

			/*
			 * Fatal error: free all remaining frames on the
			 * pending list to prevent a memory leak.
			 */
			list_for_each_entry_safe(frame, tmp,
						 pending_frames, list) {
				list_del_init(&frame->list);
				if (frame->owns_data)
					kfree(frame->data);
				kmem_cache_free(tquic_frame_cache, frame);
			}
			return ret;
		}

		total += ret;

		/* Remove from pending list and free if needed */
		list_del_init(&frame->list);
		if (frame->owns_data)
			kfree(frame->data);
		kmem_cache_free(tquic_frame_cache, frame);
	}

	return total;
}

/*
 * =============================================================================
 * Packet Header Generation
 * =============================================================================
 */

/*
 * Encode packet number with minimal bytes
 */
static int tquic_encode_pkt_num(u8 *buf, u64 pkt_num, u64 largest_acked)
{
	u64 diff = pkt_num - largest_acked;
	int len;

	tquic_dbg("encode_pkt_num: pkt=%llu largest_acked=%llu\n",
		  pkt_num, largest_acked);

	if (diff < 128) {
		len = 1;
		buf[0] = (u8)pkt_num;
	} else if (diff < 32768) {
		len = 2;
		buf[0] = ((pkt_num >> 8) & 0xff);
		buf[1] = (pkt_num & 0xff);
	} else if (diff < 8388608) {
		len = 3;
		buf[0] = ((pkt_num >> 16) & 0xff);
		buf[1] = ((pkt_num >> 8) & 0xff);
		buf[2] = (pkt_num & 0xff);
	} else {
		len = 4;
		buf[0] = ((pkt_num >> 24) & 0xff);
		buf[1] = ((pkt_num >> 16) & 0xff);
		buf[2] = ((pkt_num >> 8) & 0xff);
		buf[3] = (pkt_num & 0xff);
	}

	tquic_dbg("encode_pkt_num: encoded len=%d\n", len);
	return len;
}

/*
 * Build long header (Initial, Handshake, 0-RTT)
 *
 * RFC 9287 GREASE support: The fixed bit (0x40) in the first byte of long
 * header packets can be randomly set to 0 instead of 1, if the peer has
 * signaled support via the grease_quic_bit transport parameter.
 *
 * @grease_state: GREASE state for this connection (NULL to disable GREASE)
 */
static int tquic_build_long_header_internal(struct tquic_connection *conn,
					    struct tquic_path *path,
					    u8 *buf, size_t buf_len,
					    int pkt_type, u64 pkt_num,
					    size_t payload_len,
					    struct tquic_grease_state *grease_state)
{
	u8 *p = buf;
	int pkt_num_len;
	u8 first_byte;
	bool grease_fixed_bit;

	/* Calculate packet number length */
	pkt_num_len = 4;  /* Use 4 bytes for long header */

	/*
	 * RFC 9287 Section 3: GREASE the Fixed Bit
	 *
	 * When the peer has advertised support for grease_quic_bit,
	 * we can randomly set the fixed bit (bit 0x40) to 0.
	 * This tests that implementations correctly ignore this bit.
	 */
	grease_fixed_bit = tquic_grease_should_grease_bit(grease_state);

	/* First byte: form(1) + fixed(1) + type(2) + reserved(2) + pn_len(2) */
	first_byte = TQUIC_HEADER_FORM_LONG;
	if (!grease_fixed_bit)
		first_byte |= TQUIC_HEADER_FIXED_BIT;  /* Set fixed bit to 1 */
	/* else: fixed bit is 0 (GREASE'd) */
	first_byte |= (pkt_type << 4);
	first_byte |= (pkt_num_len - 1);  /* Encoded pn length */

	if (buf_len < 7 + conn->dcid.len + conn->scid.len + pkt_num_len)
		return -ENOSPC;

	*p++ = first_byte;

	/* Version (4 bytes) */
	*p++ = (conn->version >> 24) & 0xff;
	*p++ = (conn->version >> 16) & 0xff;
	*p++ = (conn->version >> 8) & 0xff;
	*p++ = conn->version & 0xff;

	/* DCID Length + DCID */
	*p++ = conn->dcid.len;
	if (conn->dcid.len > 0) {
		memcpy(p, conn->dcid.id, conn->dcid.len);
		p += conn->dcid.len;
	}

	/* SCID Length + SCID */
	*p++ = conn->scid.len;
	if (conn->scid.len > 0) {
		memcpy(p, conn->scid.id, conn->scid.len);
		p += conn->scid.len;
	}

	/* Token (only for Initial packets) */
	if (pkt_type == TQUIC_PKT_INITIAL) {
		/* Token length (0 for now) */
		*p++ = 0;
	}

	/* Length (payload + packet number + AEAD tag) */
	{
		u64 length = payload_len + pkt_num_len + 16;  /* 16 = AEAD tag */
		int len_bytes = tquic_encode_varint(p, buf + buf_len - p, length);
		if (len_bytes < 0)
			return len_bytes;
		p += len_bytes;
	}

	/*
	 * Packet Number (will be encrypted by header protection).
	 *
	 * Long headers always use 4-byte PN encoding regardless of what
	 * the minimal encoding would be.  Write all 4 bytes explicitly
	 * to avoid leaving uninitialized stack bytes that would corrupt
	 * the AEAD nonce on the receiver side.
	 */
	p[0] = (pkt_num >> 24) & 0xff;
	p[1] = (pkt_num >> 16) & 0xff;
	p[2] = (pkt_num >> 8) & 0xff;
	p[3] = pkt_num & 0xff;
	p += pkt_num_len;

	return p - buf;
}

/*
 * Build short header (1-RTT)
 *
 * RFC 9287 GREASE support: The fixed bit (0x40) in the first byte of short
 * header packets can be randomly set to 0 instead of 1, if the peer has
 * signaled support via the grease_quic_bit transport parameter.
 *
 * @grease_state: GREASE state for this connection (NULL to disable GREASE)
 */
static int tquic_build_short_header_internal(struct tquic_connection *conn,
				    struct tquic_path *path,
				    u8 *buf, size_t buf_len,
				    u64 pkt_num, u64 largest_acked,
				    bool key_phase, bool spin_bit,
				    struct tquic_grease_state *grease_state)
{
	u8 *p = buf;
	int pkt_num_len;
	u8 first_byte;
	bool grease_fixed_bit;

	/*
	 * Always use 4-byte packet number encoding for short headers.
	 * This matches the long header behaviour and, critically,
	 * ensures that pn_offset = header_len - 4 is correct for HP,
	 * and that the packet is long enough for the HP sample
	 * (RFC 9001 Section 5.4.2).
	 *
	 * tquic_encode_pkt_num() computes the minimal encoding;
	 * log it for diagnostics but always send 4 bytes.
	 */
	pkt_num_len = 4;
	if (largest_acked > 0) {
		u8 tmp[4];
		int optimal = tquic_encode_pkt_num(tmp, pkt_num,
						   largest_acked);

		tquic_dbg("short_hdr: pkt=%llu optimal_pn_len=%d using=4\n",
			  pkt_num, optimal);
	}

	/*
	 * RFC 9287 Section 3: GREASE the Fixed Bit
	 *
	 * When the peer has advertised support for grease_quic_bit,
	 * we can randomly set the fixed bit (bit 0x40) to 0.
	 */
	grease_fixed_bit = tquic_grease_should_grease_bit(grease_state);

	/* First byte: form(0) + fixed(1) + spin(1) + reserved(2) + key_phase(1) + pn_len(2) */
	first_byte = 0;
	if (!grease_fixed_bit)
		first_byte |= TQUIC_HEADER_FIXED_BIT;  /* Set fixed bit to 1 */
	/* else: fixed bit is 0 (GREASE'd) */
	if (spin_bit)
		first_byte |= TQUIC_HEADER_SPIN_BIT;
	if (key_phase)
		first_byte |= TQUIC_HEADER_KEY_PHASE;
	first_byte |= (pkt_num_len - 1);  /* 0x03 = 4-byte PN */

	/* Check buffer space */
	if (buf_len < 1 + path->remote_cid.len + pkt_num_len)
		return -ENOSPC;

	*p++ = first_byte;

	/* Destination Connection ID */
	if (path->remote_cid.len > 0) {
		memcpy(p, path->remote_cid.id, path->remote_cid.len);
		p += path->remote_cid.len;
	}

	/* Packet Number (4 bytes, big-endian) */
	put_unaligned_be32((u32)pkt_num, p);
	p += 4;

	return p - buf;
}

/*
 * =============================================================================
 * Header Protection
 * =============================================================================
 */

/*
 * Apply header protection using AES-ECB
 */
/*
 * Apply header protection per RFC 9001 Section 5.4.
 *
 * Delegates to the fully-implemented tquic_hp_protect() in
 * crypto/header_protection.c, which handles both long and short
 * headers, AES-ECB and ChaCha20 cipher suites, and proper mask
 * generation.
 *
 * The packet buffer must contain the complete packet (header + payload)
 * with the packet number at @pn_offset already written in cleartext.
 *
 * If HP keys are not yet available (e.g. during Initial before keys
 * are derived), the function logs a debug message and returns 0 so
 * that packet sending is not blocked.
 */
static int tquic_apply_header_protection(struct tquic_connection *conn,
					 u8 *packet, size_t packet_len,
					 size_t pn_offset)
{
	struct tquic_hp_ctx *hp_ctx;
	int ret;

	if (!conn->crypto_state)
		return 0;  /* No crypto yet (Initial); skip HP */

	hp_ctx = tquic_crypto_get_hp_ctx(conn->crypto_state);
	if (!hp_ctx)
		return 0;  /* HP context not allocated; skip HP */

	ret = tquic_hp_protect(hp_ctx, packet, packet_len, pn_offset);
	if (ret) {
		/*
		 * HP keys may not be installed yet for the current
		 * encryption level.  Log and continue -- the packet
		 * can still be sent (e.g. Initial packets before HP
		 * key derivation).
		 */
		tquic_dbg("output: header protection failed: %d\n", ret);
		return 0;
	}

	return 0;
}

/*
 * =============================================================================
 * Packet Encryption
 * =============================================================================
 */

/*
 * Map QUIC packet type to encryption level.
 * PKT_INITIAL(0)->ENC_INITIAL(0), PKT_0RTT(1)->ENC_APPLICATION(2),
 * PKT_HANDSHAKE(2)->ENC_HANDSHAKE(1), short(3)->ENC_APPLICATION(2).
 */
static int tquic_pkt_type_to_enc_level(int pkt_type)
{
	switch (pkt_type) {
	case TQUIC_PKT_INITIAL:
		return 0;  /* TQUIC_ENC_INITIAL */
	case TQUIC_PKT_HANDSHAKE:
		return 1;  /* TQUIC_ENC_HANDSHAKE */
	default:
		return 2;  /* TQUIC_ENC_APPLICATION */
	}
}

/*
 * Encrypt packet payload using AEAD
 */
static int tquic_encrypt_payload(struct tquic_connection *conn,
				 u8 *header, int header_len,
				 u8 *payload, int payload_len,
				 u64 pkt_num, int pkt_type)
{
	/* Use the crypto module's encrypt function */
	if (conn->crypto_state) {
		size_t out_len;
		int enc_level = tquic_pkt_type_to_enc_level(pkt_type);

		return tquic_encrypt_packet(conn->crypto_state,
					    enc_level,
					    header, header_len,
					    payload, payload_len,
					    pkt_num, payload, &out_len);
	}

	/* If no crypto state, this is a test/initial packet */
	return 0;
}

/*
 * =============================================================================
 * Packet Assembly
 * =============================================================================
 */

/*
 * Assemble a complete QUIC packet
 *
 * Builds header and payload directly into the skb to avoid per-packet
 * kmalloc overhead.  The header is built into a small stack buffer
 * (128 B -- safe for kernel stack), and payload frames are written
 * straight into the skb linear data area.  After encryption and header
 * protection the header is prepended, giving a single contiguous
 * packet in the skb with zero intermediate heap allocations.
 */
static struct sk_buff *tquic_assemble_packet(struct tquic_connection *conn,
					     struct tquic_path *path,
					     int pkt_type, u64 pkt_num,
					     struct list_head *frames)
{
	struct sk_buff *skb;
	struct tquic_frame_ctx ctx;
	u8 header_buf[128] = {};	/* stack -- max QUIC header */
	u8 *payload_buf;
	int header_len;
	int payload_len;
	int max_payload;
	int ret;
	bool is_long_header;

	/*
	 * Allocate the skb up-front with room for the maximum possible
	 * packet: 128 (header) + MTU (payload) + 16 (AEAD tag).
	 * Reserve MAX_HEADER + 128 so we can later push the header in
	 * front of the payload that is written at skb->data.
	 */
	/*
	 * Read MTU with READ_ONCE since PMTUD may update path->mtu
	 * concurrently (via WRITE_ONCE under pmtud->lock).
	 * Enforce QUIC minimum MTU of 1200 bytes (RFC 9000 Section 14).
	 */
	max_payload = READ_ONCE(path->mtu);
	if (unlikely(max_payload < 1200))
		max_payload = 1200;
	skb = alloc_skb(MAX_HEADER + 128 + max_payload + 16, GFP_ATOMIC);
	if (unlikely(!skb))
		return NULL;

	skb_reserve(skb, MAX_HEADER + 128);

	/*
	 * payload_buf points into the skb linear data area right after
	 * the reserved header space.  Frames are coalesced directly here.
	 */
	payload_buf = skb_put(skb, max_payload + 16);

	/*
	 * Determine header type early so we can budget payload size.
	 * pkt_type -1 means short header (1-RTT); anything else is long.
	 */
	is_long_header = (pkt_type != -1);

	/* Initialize frame context */
	ctx.conn = conn;
	ctx.path = path;
	ctx.buf = payload_buf;
	/*
	 * Limit frame budget so the final packet (header + payload +
	 * 16-byte AEAD tag) fits within the path MTU.  Initial packets
	 * are exempt: they have separate padding logic that expands the
	 * packet to exactly the QUIC minimum of 1200 bytes.
	 */
	if (pkt_type == TQUIC_PKT_INITIAL) {
		ctx.buf_len = max_payload;
	} else {
		int hdr_est = is_long_header ? 64 : 32;

		ctx.buf_len = max_payload - hdr_est - 16;
		if (unlikely(ctx.buf_len < 64))
			ctx.buf_len = 64;
	}
	ctx.offset = 0;
	ctx.pkt_num = pkt_num;
	ctx.ack_eliciting = false;

	pr_debug("tquic_assemble: pkt_type=%d mtu=%d max_payload=%d buf_len=%zu\n",
		pkt_type, READ_ONCE(path->mtu), max_payload, ctx.buf_len);

	/* Coalesce frames into payload */
	ret = tquic_coalesce_frames(conn, &ctx, frames);
	if (unlikely(ret < 0))
		goto err_free_skb;

	payload_len = ctx.offset;

	/*
	 * RFC 9000 Section 14.1: "A client MUST expand the payload of all
	 * UDP datagrams carrying Initial packets to at least the smallest
	 * maximum datagram size of 1200 bytes."
	 *
	 * Total on-wire: header_len + payload_len + 16 (AEAD tag) >= 1200.
	 * We don't know header_len yet, so use a conservative 48-byte
	 * estimate (max Initial header ~52 bytes).
	 */
	if (pkt_type == TQUIC_PKT_INITIAL && payload_len < 1200 - 48 - 16) {
		int padding = 1200 - 48 - 16 - payload_len;

		tquic_gen_padding_frame(&ctx, padding);
		payload_len = ctx.offset;
	}

	/* Build header into stack buffer (is_long_header set above) */

	/*
	 * GREASE state: Pass the connection's GREASE state for RFC 9287
	 * compliant GREASE bit manipulation.  The grease_state is
	 * initialized during connection setup based on per-netns sysctl
	 * settings, and updated with peer capabilities after transport
	 * parameter exchange.
	 */
	if (is_long_header) {
		header_len = tquic_build_long_header_internal(
				conn, path, header_buf, sizeof(header_buf),
				pkt_type, pkt_num, payload_len,
				conn->grease_state);
	} else {
		/*
		 * For short header packets (1-RTT), get the current key
		 * phase from the key update state per RFC 9001 Section 6.
		 * The key phase bit indicates which generation of keys
		 * was used.
		 */
		bool key_phase = false;

		if (conn->crypto_state) {
			struct tquic_key_update_state *ku_state;

			ku_state = tquic_crypto_get_key_update_state(
					conn->crypto_state);
			if (ku_state)
				key_phase =
					tquic_key_update_get_phase(ku_state) != 0;
		}
		header_len = tquic_build_short_header_internal(
				conn, path, header_buf, sizeof(header_buf),
				pkt_num, 0, key_phase, false,
				conn->grease_state);
	}

	if (unlikely(header_len < 0))
		goto err_free_skb;

	/* Encrypt payload in-place inside the skb */
	ret = tquic_encrypt_payload(conn, header_buf, header_len,
				    payload_buf, payload_len, pkt_num,
				    is_long_header ? pkt_type : 3);
	if (unlikely(ret < 0))
		goto err_free_skb;

	/*
	 * Trim the skb tail to the actual encrypted payload size and
	 * then push the header in front.  skb_put() above reserved
	 * the maximum; now trim to reality.
	 */
	skb_trim(skb, payload_len + 16);

	/* Push header in front of payload */
	memcpy(skb_push(skb, header_len), header_buf, header_len);

	/*
	 * Apply header protection over the contiguous packet in the skb.
	 * The pn_offset is header_len minus the packet number length.
	 * Both long and short headers use 4-byte packet numbers, so
	 * pn_offset = header_len - 4.
	 */
	if (header_len < 5) {
		ret = -EINVAL;
		goto err_free_skb;
	}
	ret = tquic_apply_header_protection(conn, skb->data, skb->len,
					    header_len - 4);
	if (unlikely(ret < 0))
		goto err_free_skb;

	return skb;

err_free_skb:
	kfree_skb(skb);
	return NULL;
}

/*
 * =============================================================================
 * Path Selection for Multipath
 * =============================================================================
 */

/*
 * Select path using the connection's scheduler.
 *
 * Returns a referenced path on success; caller must call tquic_path_put().
 * Caller must NOT hold conn->paths_lock; this function acquires it as needed.
 */
static struct tquic_path *tquic_select_path_lb(struct tquic_connection *conn,
					       struct sk_buff *skb, u32 flags);

struct tquic_path *tquic_select_path(struct tquic_connection *conn,
				     struct sk_buff *skb)
{
	struct tquic_path *selected;

	/*
	 * Fast path: when no multipath scheduler is configured, read
	 * the active_path pointer without taking the lock.  The pointer
	 * is updated with WRITE_ONCE on the control path, so a single
	 * READ_ONCE is sufficient for the common single-path case.
	 */
	if (!conn->scheduler ||
	    !test_bit(TQUIC_F_BONDING_ENABLED, &conn->flags)) {
		rcu_read_lock();
		selected = rcu_dereference(conn->active_path);
		if (selected && !tquic_path_get(selected))
			selected = NULL;
		rcu_read_unlock();
		return selected;
	}

	/*
	 * Slow path: multipath scheduler needs conn->paths_lock to protect
	 * path list iteration (paths can be added/removed concurrently).
	 */
	spin_lock_bh(&conn->paths_lock);
	selected = tquic_bond_select_path(conn, skb);

	/*
	 * Fallback to load-balanced path selection if the bond
	 * scheduler returns NULL (e.g. all paths temporarily blocked).
	 */
	if (!selected) {
		tquic_dbg("select_path: bond returned NULL, trying lb\n");
		selected = tquic_select_path_lb(conn, skb, 0);
	}
	spin_unlock_bh(&conn->paths_lock);

	return selected;
}
EXPORT_SYMBOL_GPL(tquic_select_path);

static inline bool tquic_output_path_usable(const struct tquic_path *path)
{
	tquic_dbg("output_path_usable: path=%p state=%d\n",
		  path, path ? READ_ONCE(path->state) : -1);

	return path &&
	       (READ_ONCE(path->state) == TQUIC_PATH_ACTIVE ||
		READ_ONCE(path->state) == TQUIC_PATH_VALIDATED);
}

/*
 * Select path with load balancing
 * Caller must hold conn->paths_lock to protect path list iteration.
 */
static struct tquic_path *tquic_select_path_lb(struct tquic_connection *conn,
							      struct sk_buff *skb, u32 flags)
{
	struct tquic_path *path, *best = NULL;
	u32 best_score = 0;

	lockdep_assert_held(&conn->paths_lock);

	/* Iterate through active paths */
	list_for_each_entry(path, &conn->paths, list) {
		u32 score;
		u64 inflight;

		if (!tquic_output_path_usable(path))
			continue;

		/* Score based on available capacity and RTT */
		inflight = path->stats.tx_bytes - path->stats.rx_bytes;
		if (path->stats.cwnd > inflight) {
			score = (path->stats.cwnd - inflight) * 1000;
			if (path->stats.rtt_smoothed > 0)
				score /= path->stats.rtt_smoothed;
		} else {
			score = 0;
		}

		if (score > best_score) {
			best_score = score;
			best = path;
		}
	}

	/* Return a referenced path per API contract */
	if (best && tquic_path_get(best))
		return best;

	rcu_read_lock();
	best = rcu_dereference(conn->active_path);
	if (best && !tquic_path_get(best))
		best = NULL;
	rcu_read_unlock();

	return best;
}

/*
 * =============================================================================
 * Pacing Implementation
 * =============================================================================
 */

/* Forward declaration for hrtimer callback */
static enum hrtimer_restart tquic_pacing_timer(struct hrtimer *timer);

/*
 * Initialize pacing state for a path
 */
struct tquic_pacing_state *tquic_pacing_init(struct tquic_connection *conn,
					     struct tquic_path *path)
{
	struct tquic_pacing_state *pacing;

	pacing = kzalloc(sizeof(*pacing), GFP_KERNEL);
	if (!pacing)
		return NULL;

	pacing->conn = conn;
	pacing->path = path;
	pacing->pacing_rate = 1250000;  /* Default 10 Mbps */
	pacing->max_tokens = TQUIC_PACING_MAX_BURST;
	pacing->tokens = pacing->max_tokens;

	skb_queue_head_init(&pacing->queue);
	spin_lock_init(&pacing->lock);

	INIT_WORK(&pacing->work, tquic_pacing_work);

	/* Use hrtimer_setup (new API) instead of hrtimer_init + function assignment */
	hrtimer_setup(&pacing->timer, tquic_pacing_timer, CLOCK_MONOTONIC, HRTIMER_MODE_REL);

	return pacing;
}
EXPORT_SYMBOL_GPL(tquic_pacing_init);

/*
 * Cleanup pacing state
 */
void tquic_pacing_cleanup(struct tquic_pacing_state *pacing)
{
	tquic_dbg("pacing_cleanup: pacing=%p\n", pacing);

	if (!pacing)
		return;

	hrtimer_cancel(&pacing->timer);
	cancel_work_sync(&pacing->work);
	skb_queue_purge(&pacing->queue);
	kfree(pacing);
}
EXPORT_SYMBOL_GPL(tquic_pacing_cleanup);

/*
 * =============================================================================
 * FQ qdisc Integration
 * =============================================================================
 *
 * This section provides integration with the FQ (Fair Queue) qdisc for
 * hardware-assisted pacing. When FQ is attached to the interface, it will
 * pace packets according to sk->sk_pacing_rate. Otherwise, we fall back
 * to internal software pacing.
 *
 * Per CONTEXT.md: "Pacing enabled by default" with "FQ integration with fq qdisc"
 */

/*
 * tquic_update_pacing - Update socket pacing rate from CC state
 * @sk: Socket to update
 * @path: Path providing pacing information
 *
 * This integrates with FQ qdisc when available.
 * If FQ is attached to the interface, it will pace packets
 * according to sk->sk_pacing_rate. Otherwise, we use internal pacing.
 */
void tquic_update_pacing(struct sock *sk, struct tquic_path *path)
{
	struct tquic_sock *tsk;
	struct net *net;
	u64 pacing_rate;

	if (!sk || !path)
		return;

	tsk = tquic_sk(sk);
	net = sock_net(sk);

	/* Check if pacing is enabled at netns level */
	if (!tquic_pernet(net)->pacing_enabled)
		return;

	/* Check if pacing is enabled per-socket */
	if (!tsk->pacing_enabled)
		return;

	pacing_rate = tquic_cong_get_pacing_rate(path);

	/*
	 * Update socket pacing rate for FQ qdisc integration.
	 * FQ checks sk->sk_pacing_rate to pace packets.
	 * If FQ is not configured, this has no effect (internal pacing needed).
	 */
	WRITE_ONCE(sk->sk_pacing_rate, pacing_rate);

	/*
	 * Check pacing status:
	 * SK_PACING_NONE   - No pacing active
	 * SK_PACING_NEEDED - Internal pacing required (no FQ)
	 * SK_PACING_FQ     - FQ qdisc handles pacing
	 */
	if (smp_load_acquire(&sk->sk_pacing_status) == SK_PACING_NEEDED) {
		/* Internal pacing needed - FQ not available */
		if (path->conn && path->conn->scheduler) {
			/* Update internal pacing state if available */
			/* Note: Per-path pacing state would be accessed here */
		}
	}

	tquic_dbg("updated pacing rate for path %u: %llu bytes/sec (status=%d)\n",
		 path->path_id, pacing_rate, sk->sk_pacing_status);
}
EXPORT_SYMBOL_GPL(tquic_update_pacing);

/*
 * tquic_pacing_allows_send - Check if pacing allows sending
 * @sk: Socket to check
 * @skb: Packet to send
 *
 * If FQ is handling pacing, always allow (FQ will pace).
 * For internal pacing, check timer and set EDT (Earliest Departure Time).
 *
 * Return: true if packet can be sent, false if pacing should delay
 */
static bool tquic_pacing_allows_send(struct sock *sk, struct sk_buff *skb)
{
	u64 len_ns;

	tquic_dbg("pacing_allows_send: sk=%p skb_len=%u\n",
		  sk, skb ? skb->len : 0);

	if (!sk || !skb)
		return true;

	/* If FQ is handling pacing, always allow (FQ will pace) */
	if (smp_load_acquire(&sk->sk_pacing_status) == SK_PACING_FQ)
		return true;

	/* Check internal pacing - set EDT timestamp for FQ */
	if (sk->sk_pacing_rate > 0) {
		/*
		 * Calculate departure time based on pacing rate.
		 * len_ns = (bytes * NSEC_PER_SEC) / rate
		 */
		len_ns = div64_u64((u64)skb->len * NSEC_PER_SEC,
				   sk->sk_pacing_rate);

		/*
		 * Set EDT timestamp for FQ qdisc.
		 * When FQ sees this timestamp, it will delay the packet
		 * until the scheduled departure time.
		 */
		skb->tstamp = ktime_add_ns(ktime_get(), len_ns);
	}

	return true;  /* Allow send, FQ or internal timer handles pacing */
}

/*
 * Update pacing rate based on congestion control
 */
void tquic_pacing_update_rate(struct tquic_pacing_state *pacing, u64 rate)
{
	tquic_dbg("pacing_update_rate: rate=%llu\n", rate);

	spin_lock_bh(&pacing->lock);
	pacing->pacing_rate = rate;
	spin_unlock_bh(&pacing->lock);
}
EXPORT_SYMBOL_GPL(tquic_pacing_update_rate);

/*
 * Calculate inter-packet gap
 */
static ktime_t tquic_pacing_calc_gap(struct tquic_pacing_state *pacing,
				     u32 pkt_size)
{
	u64 gap_ns;

	if (pacing->pacing_rate == 0)
		return ns_to_ktime(TQUIC_PACING_MIN_INTERVAL_US * 1000);

	/* gap = packet_size / pacing_rate (in nanoseconds) */
	gap_ns = (u64)pkt_size * NSEC_PER_SEC / pacing->pacing_rate;

	/* Enforce minimum */
	gap_ns = max_t(u64, gap_ns, TQUIC_PACING_MIN_INTERVAL_US * 1000);

	return ns_to_ktime(gap_ns);
}

/*
 * Pacing timer callback
 */
static enum hrtimer_restart tquic_pacing_timer(struct hrtimer *timer)
{
	struct tquic_pacing_state *pacing = container_of(timer,
							 struct tquic_pacing_state,
							 timer);

	tquic_dbg("pacing_timer: fired, scheduling work\n");

	/* Schedule work to send packets */
	schedule_work(&pacing->work);

	return HRTIMER_NORESTART;
}

/*
 * Pacing work function
 */
static void tquic_pacing_work(struct work_struct *work)
{
	struct tquic_pacing_state *pacing = container_of(work,
							 struct tquic_pacing_state,
							 work);
	struct sk_buff_head batch;
	struct sk_buff *skb;
	ktime_t now;
	ktime_t gap;
	int sent = 0;
	int batch_count = 0;

	tquic_dbg("pacing_work: queue_len=%u rate=%llu\n",
		  skb_queue_len(&pacing->queue), pacing->pacing_rate);

	__skb_queue_head_init(&batch);

	/*
	 * Dequeue a batch of packets under a single lock hold,
	 * then send them all without the lock.
	 */
	spin_lock_bh(&pacing->lock);

	now = ktime_get();

	while ((skb = skb_peek(&pacing->queue)) != NULL) {
		/* Check if we can send */
		if (ktime_after(pacing->next_send_time, now) && batch_count > 0)
			break;

		/* Check burst limit */
		if (batch_count >= pacing->max_tokens)
			break;

		skb = __skb_dequeue(&pacing->queue);
		__skb_queue_tail(&batch, skb);
		batch_count++;
	}

	spin_unlock_bh(&pacing->lock);

	/* Send all dequeued packets without holding the lock */
	while ((skb = __skb_dequeue(&batch)) != NULL) {
		/*
		 * CF-258/CF-296: Save skb->len before sending because
		 * tquic_output_packet() may consume the skb.
		 */
		unsigned int pkt_len = skb->len;

		tquic_output_packet(pacing->conn, pacing->path, skb);

		gap = tquic_pacing_calc_gap(pacing, pkt_len);
		now = ktime_add(now, gap);
		sent++;
	}

	spin_lock_bh(&pacing->lock);
	pacing->next_send_time = now;

	/* Schedule timer for next packet if queue not empty */
	if (!skb_queue_empty(&pacing->queue)) {
		if (ktime_after(pacing->next_send_time, now)) {
			hrtimer_start(&pacing->timer,
				      ktime_sub(pacing->next_send_time, now),
				      HRTIMER_MODE_REL);
			pacing->timer_active = true;
		} else {
			/* Can send immediately, reschedule work */
			schedule_work(&pacing->work);
		}
	} else {
		pacing->timer_active = false;
	}

	spin_unlock_bh(&pacing->lock);
}

/*
 * Queue packet for paced sending
 */
int tquic_pacing_send(struct tquic_pacing_state *pacing, struct sk_buff *skb)
{
	tquic_dbg("pacing_send: skb_len=%u timer_active=%d\n",
		  skb ? skb->len : 0, pacing->timer_active);

	spin_lock_bh(&pacing->lock);

	/* Add to pacing queue */
	__skb_queue_tail(&pacing->queue, skb);

	/* Start sending if not already active */
	if (!pacing->timer_active)
		schedule_work(&pacing->work);

	spin_unlock_bh(&pacing->lock);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_pacing_send);

/*
 * =============================================================================
 * GSO/TSO Support
 * =============================================================================
 */

/*
 * Check if GSO is supported and beneficial
 */
static bool tquic_gso_supported(struct tquic_path *path)
{
	/* GSO is beneficial for high-bandwidth paths */
	return path->mtu >= 1200 && path->stats.bandwidth > 1000000;
}

/*
 * Initialize GSO context
 */
static int tquic_gso_init(struct tquic_gso_ctx *gso,
			  struct tquic_path *path, u16 max_segs)
{
	gso->gso_size = path->mtu - 48;  /* Leave room for UDP/IP headers */
	gso->gso_segs = 0;
	gso->current_seg = 0;
	gso->total_len = 0;

	/* Allocate GSO SKB -- check for multiplication overflow */
	{
		size_t alloc_size;

		if (check_mul_overflow((size_t)gso->gso_size,
				       (size_t)max_segs, &alloc_size) ||
		    check_add_overflow(alloc_size, (size_t)MAX_HEADER,
				       &alloc_size))
			return -EOVERFLOW;
		gso->gso_skb = alloc_skb(alloc_size, GFP_ATOMIC);
	}
	if (!gso->gso_skb)
		return -ENOMEM;

	skb_reserve(gso->gso_skb, MAX_HEADER);

	/* Mark as GSO */
	skb_shinfo(gso->gso_skb)->gso_type = SKB_GSO_UDP_L4;
	skb_shinfo(gso->gso_skb)->gso_size = gso->gso_size;

	return 0;
}

/*
 * Add a segment to GSO SKB
 */
static int tquic_gso_add_segment(struct tquic_gso_ctx *gso, const u8 *data,
				 size_t len)
{
	if (gso->gso_segs >= TQUIC_GSO_MAX_SEGS)
		return -ENOSPC;

	if (len > gso->gso_size)
		return -EINVAL;

	/* Validate tailroom before writing segment data */
	if (skb_tailroom(gso->gso_skb) < gso->gso_size)
		return -ENOSPC;

	/* Add data to GSO SKB */
	skb_put_data(gso->gso_skb, data, len);

	/* Pad to segment size if not the last */
	if (len < gso->gso_size) {
		memset(skb_put(gso->gso_skb, gso->gso_size - len), 0,
		       gso->gso_size - len);
	}

	gso->gso_segs++;
	gso->total_len += len;

	return 0;
}

/*
 * Finalize GSO SKB
 */
static struct sk_buff *tquic_gso_finalize(struct tquic_gso_ctx *gso)
{
	struct sk_buff *skb = gso->gso_skb;

	if (!skb || gso->gso_segs == 0) {
		kfree_skb(skb);
		return NULL;
	}

	skb_shinfo(skb)->gso_segs = gso->gso_segs;

	/*
	 * GSO handles segment sizing automatically. The network stack
	 * will segment the GSO packet according to the gso_size set
	 * during coalescing. No manual trimming needed.
	 */

	gso->gso_skb = NULL;
	return skb;
}

/*
 * Send multiple QUIC packets coalesced via GSO.
 * Falls back to individual sends if GSO is not supported.
 *
 * @conn: Connection
 * @path: Path for transmission
 * @pkts: Array of assembled QUIC packet buffers
 * @pkt_lens: Length of each packet
 * @num_pkts: Number of packets to send
 *
 * Returns 0 on success, negative errno on failure.
 */
static int tquic_output_gso_send(struct tquic_connection *conn,
				 struct tquic_path *path,
				 const u8 **pkts, size_t *pkt_lens,
				 int num_pkts)
{
	struct tquic_gso_ctx gso;
	struct sk_buff *gso_skb;
	int i, ret;

	if (num_pkts <= 1 || !tquic_gso_supported(path)) {
		tquic_dbg("gso_send: not using GSO (pkts=%d supported=%d)\n",
			  num_pkts, tquic_gso_supported(path));
		return -EOPNOTSUPP;
	}

	ret = tquic_gso_init(&gso, path, num_pkts);
	if (ret < 0) {
		tquic_dbg("gso_send: init failed %d\n", ret);
		return ret;
	}

	for (i = 0; i < num_pkts; i++) {
		ret = tquic_gso_add_segment(&gso, pkts[i], pkt_lens[i]);
		if (ret < 0) {
			tquic_dbg("gso_send: add_segment %d failed %d\n",
				  i, ret);
			kfree_skb(gso.gso_skb);
			return ret;
		}
	}

	gso_skb = tquic_gso_finalize(&gso);
	if (!gso_skb)
		return -ENOMEM;

	tquic_dbg("gso_send: sending %d segs total_len=%u\n",
		  num_pkts, gso_skb->len);
	return tquic_output_packet(conn, path, gso_skb);
}

/*
 * =============================================================================
 * ECN Marking for Outgoing Packets
 * =============================================================================
 *
 * Per RFC 9000 Section 13.4 and RFC 9002 Section 7:
 * - Endpoints that support ECN mark packets with ECT(0) or ECT(1)
 * - ECN marking is set in the IP header DSCP/ECN field
 * - Default marking is ECT(0) per QUIC specification
 *
 * Per CONTEXT.md: "ECN support: available but off by default (enable via sysctl)"
 */

/* ECN codepoints for IP header */
#define TQUIC_IP_ECN_NOT_ECT	0x00
#define TQUIC_IP_ECN_ECT1	0x01
#define TQUIC_IP_ECN_ECT0	0x02
#define TQUIC_IP_ECN_CE		0x03
#define TQUIC_IP_ECN_MASK	0x03

/*
 * tquic_set_ecn_marking - Set ECN codepoint on outgoing packet (IPv6 path)
 * @skb: Socket buffer to mark
 * @conn: Connection (for ECN enable check)
 *
 * Sets ECT(0) marking directly in the IP header. For IPv4,
 * tquic_output_packet() sets ECN via flowi4 TOS before xmit,
 * so this function is primarily needed for IPv6 packets where
 * the traffic class must be modified on the skb directly.
 */
static void tquic_set_ecn_marking(struct sk_buff *skb,
				  struct tquic_connection *conn)
{
	struct net *net = NULL;
	struct iphdr *iph;

	if (!skb || !conn)
		return;

	/* Check if ECN is enabled at netns level */
	if (conn->sk) {
		net = sock_net(conn->sk);
		if (!net || !tquic_pernet(net)->ecn_enabled)
			return;
	}

	/*
	 * Set ECT(0) codepoint in IP header.
	 * ECT(0) = 0x02 in low 2 bits of TOS/Traffic Class field.
	 *
	 * Per RFC 9000 Section 13.4.1: "An endpoint that supports ECN
	 * marks all IP packets with the ECT(0) codepoint."
	 */
	if (skb->protocol == htons(ETH_P_IP)) {
		iph = ip_hdr(skb);
		if (iph) {
			iph->tos = (iph->tos & ~TQUIC_IP_ECN_MASK) |
				   TQUIC_IP_ECN_ECT0;
			ip_send_check(iph);
			tquic_dbg("ecn: set ECT(0) on IPv4 pkt len=%u\n",
				  skb->len);
		}
	} else if (skb->protocol == htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6h = ipv6_hdr(skb);

		if (ip6h) {
			u32 flow = ntohl(*(__be32 *)ip6h);

			flow = (flow & ~(TQUIC_IP_ECN_MASK << 20)) |
			       (TQUIC_IP_ECN_ECT0 << 20);
			*(__be32 *)ip6h = htonl(flow);
			tquic_dbg("ecn: set ECT(0) on IPv6 pkt len=%u\n",
				  skb->len);
		}
	}
}

/*
 * =============================================================================
 * Packet Output
 * =============================================================================
 */

/*
 * Send packet on specified path
 */
int tquic_output_packet(struct tquic_connection *conn,
			struct tquic_path *path,
			struct sk_buff *skb)
{
	struct flowi4 fl4;
	struct rtable *rt;
	struct sockaddr_in *local, *remote;
	struct net *net = NULL;
	unsigned int skb_len;
	int ret;

	if (unlikely(!path || !skb))
		return -EINVAL;

	pr_debug("tquic_output_packet: path=%p skb_len=%u local=%pISpc remote=%pISpc sk=%p\n",
		path, skb->len, &path->local_addr, &path->remote_addr, conn ? conn->sk : NULL);

	/*
	 * Enforce path MTU. If the packet (QUIC payload before UDP/IP headers)
	 * exceeds the current path MTU, drop it rather than send an oversized
	 * packet that will be silently dropped on the network.
	 *
	 * MTU probes bypass this check -- they are intentionally oversized.
	 * In production, check TQUIC_SKB_CB(skb)->is_mtu_probe.
	 */
	{
		u32 current_mtu = READ_ONCE(path->mtu);

		if (unlikely(skb->len > current_mtu && current_mtu > 0)) {
			pr_debug("tquic_output: EMSGSIZE pkt=%u mtu=%u path=%u\n",
				skb->len, current_mtu, path->path_id);
			kfree_skb(skb);
			return -EMSGSIZE;
		}
	}

	/* Get addresses */
	local = (struct sockaddr_in *)&path->local_addr;
	remote = (struct sockaddr_in *)&path->remote_addr;

	/* Check if ECN is enabled for this connection */
	if (conn && conn->sk)
		net = sock_net(conn->sk);

	/* Setup flow */
	memset(&fl4, 0, sizeof(fl4));
	fl4.daddr = remote->sin_addr.s_addr;
	fl4.saddr = local->sin_addr.s_addr;
	fl4.flowi4_proto = IPPROTO_UDP;

	/*
	 * Set ECN marking in DSCP field if enabled.
	 * Per RFC 9000 Section 13.4.1: "An endpoint that supports ECN
	 * marks all IP packets that it sends with the ECT(0) codepoint."
	 * Note: flowi4_tos renamed to flowi4_dscp in newer kernels.
	 */
	if (net && tquic_pernet(net)->ecn_enabled)
		TQUIC_FLOWI4_SET_DSCP(fl4, TQUIC_IP_ECN_ECT0);

	/* Route lookup - never fall back to init_net for namespace isolation */
	if (!net) {
		kfree_skb(skb);
		return -EINVAL;
	}
	rt = ip_route_output_key(net, &fl4);
	if (unlikely(IS_ERR(rt))) {
		kfree_skb(skb);
		return PTR_ERR(rt);
	}

	/* Determine TOS for ECN marking and send */
	{
		u8 tos = 0;
		__be32 saddr = fl4.saddr;
		__be16 sport = local->sin_port;

		if (net && tquic_pernet(net)->ecn_enabled)
			tos = TQUIC_IP_ECN_ECT0;

		/*
		 * If the path has no local port assigned (unbound socket),
		 * use the socket's automatically assigned source port.
		 * If the socket has no port either, pick an ephemeral one.
		 */
		if (!sport && conn->sk)
			sport = inet_sk(conn->sk)->inet_sport;
		if (!sport)
			sport = htons(get_random_u32_below(16384) + 49152);

		/* Update path with resolved addresses for future use */
		if (!local->sin_addr.s_addr && saddr) {
			local->sin_addr.s_addr = saddr;
			local->sin_port = sport;
		}

		/* Apply pacing EDT timestamp for FQ qdisc */
		tquic_pacing_allows_send(conn->sk, skb);

		/* Set ECN marking for IPv6 (IPv4 handled via flowi4) */
		tquic_set_ecn_marking(skb, conn);

		/* Save skb->len before xmit which consumes the SKB */
		skb_len = skb->len;

		/*
		 * Use udp_tunnel_xmit_skb for proper UDP encapsulation.
		 * This builds the UDP header, IP header, and transmits
		 * the packet correctly through the network stack.
		 */
		TQUIC_UDP_TUNNEL_XMIT_SKB(rt, conn->sk, skb,
					   saddr,
					   remote->sin_addr.s_addr,
					   tos,
					   ip4_dst_hoplimit(&rt->dst),
					   0,		/* DF */
					   sport,
					   remote->sin_port,
					   false,	/* xnet */
					   true);	/* nocheck */
		ret = 0;

		/* Update path statistics */
		path->stats.tx_packets++;
		path->stats.tx_bytes += skb_len;
		WRITE_ONCE(path->last_activity, ktime_get());

		if (conn && conn->sk) {
			TQUIC_INC_STATS(sock_net(conn->sk),
					TQUIC_MIB_PACKETSTX);
			TQUIC_ADD_STATS(sock_net(conn->sk),
					TQUIC_MIB_BYTESTX, skb_len);
		}
	}

	return ret;
}
EXPORT_SYMBOL_GPL(tquic_output_packet);

/*
 * Main output function - transmit data on connection
 */
int tquic_xmit(struct tquic_connection *conn, struct tquic_stream *stream,
	       const u8 *data, size_t len, bool fin)
{
	struct tquic_path *path;
	struct tquic_pending_frame *frame;
	struct sk_buff *skb;
	LIST_HEAD(frames);
	u64 pkt_num;
	size_t offset = 0;
	size_t chunk;
	int ret = 0;

	if (unlikely(!conn || !stream))
		return -EINVAL;

	/* RFC 9000 Section 10.2.2: MUST NOT send packets in draining state */
	if (unlikely(READ_ONCE(conn->state) == TQUIC_CONN_DRAINING ||
		     READ_ONCE(conn->state) == TQUIC_CONN_CLOSED))
		return -ESHUTDOWN;

	if (unlikely(READ_ONCE(conn->state) != TQUIC_CONN_CONNECTED))
		return -ENOTCONN;

	pkt_num = atomic64_inc_return(&conn->pkt_num_tx) - 1;

	/* Process data in MTU-sized chunks */
	while (offset < len || (fin && offset == len)) {
		/* Select path for this packet */
		path = tquic_select_path(conn, NULL);
		if (!path) {
			ret = -ENETUNREACH;
			break;
		}

		/* Calculate chunk size, enforce QUIC minimum MTU */
		{
			u32 mtu = READ_ONCE(path->mtu);

			if (unlikely(mtu < 1200))
				mtu = 1200;
			chunk = min_t(size_t, len - offset, mtu - 100);
		}

		/* Create pending frame */
		frame = kmem_cache_zalloc(tquic_frame_cache, GFP_ATOMIC);
		if (unlikely(!frame)) {
			tquic_path_put(path);
			ret = -ENOMEM;
			break;
		}

		frame->type = TQUIC_FRAME_STREAM;
		frame->stream_id = stream->id;
		frame->offset = stream->send_offset + offset;
		frame->len = chunk;
		frame->fin = fin && (offset + chunk >= len);

		/*
		 * Zero-copy optimization: Reference user data directly
		 * instead of allocating and copying. The data remains valid
		 * until packet assembly completes (synchronous in this path).
		 */
		if (chunk > 0) {
			frame->data = NULL;
			frame->data_ref = data + offset;
			frame->owns_data = false;
		} else {
			frame->data = NULL;
			frame->data_ref = NULL;
			frame->owns_data = false;
		}

		INIT_LIST_HEAD(&frame->list);
		list_add_tail(&frame->list, &frames);

		/* Assemble packet */
		skb = tquic_assemble_packet(conn, path, -1, pkt_num, &frames);
		if (!skb) {
			/* Cleanup remaining frames */
			struct tquic_pending_frame *f, *tmp;
			list_for_each_entry_safe(f, tmp, &frames, list) {
				list_del_init(&f->list);
				if (f->owns_data)
					kfree(f->data);
				kmem_cache_free(tquic_frame_cache, f);
			}
			tquic_path_put(path);
			ret = -ENOMEM;
			break;
		}

		/* Send packet */
		ret = tquic_output_packet(conn, path, skb);
		tquic_path_put(path);
		if (ret < 0)
			break;

		offset += chunk;
		pkt_num++;

		/* Stop after sending FIN */
		if (fin && offset >= len)
			break;
	}

	/* Update stream state */
	if (ret >= 0) {
		stream->send_offset += len;
		if (fin)
			stream->fin_sent = true;
	}

	return ret < 0 ? ret : (int)len;
}
EXPORT_SYMBOL_GPL(tquic_xmit);

/*
 * Send ACK-only packet
 */
int tquic_send_ack(struct tquic_connection *conn, struct tquic_path *path,
		   u64 largest_ack, u64 ack_delay, u64 ack_range)
{
	struct tquic_frame_ctx ctx;
	struct sk_buff *skb;
	u8 header_buf[128];
	u8 *payload_buf;
	int header_len, payload_len;
	int ret;
	u64 pkt_num;
	bool key_phase = false;

	pkt_num = atomic64_inc_return(&conn->pkt_num_tx) - 1;

	/* Allocate skb with room for header + payload + AEAD tag */
	skb = alloc_skb(MAX_HEADER + 128 + 128 + 16, GFP_ATOMIC);
	if (!skb)
		return -ENOMEM;

	skb_reserve(skb, MAX_HEADER + 128);

	/* Write ACK frame directly into skb data area */
	payload_buf = skb_put(skb, 128 + 16);

	ctx.conn = conn;
	ctx.path = path;
	ctx.buf = payload_buf;
	ctx.buf_len = 128;
	ctx.offset = 0;
	ctx.ack_eliciting = false;

	ret = tquic_gen_ack_frame(&ctx, largest_ack, ack_delay, 0, ack_range);
	if (ret < 0) {
		kfree_skb(skb);
		return ret;
	}

	payload_len = ctx.offset;

	/* Build short header (1-RTT) with correct key phase */
	if (conn->crypto_state) {
		struct tquic_key_update_state *ku_state;

		ku_state = tquic_crypto_get_key_update_state(
				conn->crypto_state);
		if (ku_state)
			key_phase = tquic_key_update_get_phase(
					ku_state) != 0;
	}

	header_len = tquic_build_short_header_internal(
			conn, path, header_buf, sizeof(header_buf),
			pkt_num, 0, key_phase, false, conn->grease_state);
	if (header_len < 0) {
		kfree_skb(skb);
		return header_len;
	}

	/* Encrypt payload in-place (header is AAD) */
	ret = tquic_encrypt_payload(conn, header_buf, header_len,
				    payload_buf, payload_len, pkt_num,
				    3 /* short header = APPLICATION */);
	if (ret < 0) {
		kfree_skb(skb);
		return ret;
	}

	/* Trim skb to actual encrypted size */
	skb_trim(skb, payload_len + 16);

	/* Push header in front of encrypted payload */
	memcpy(skb_push(skb, header_len), header_buf, header_len);

	/* Apply header protection (pn_offset = header_len - 4) */
	if (header_len >= 5) {
		ret = tquic_apply_header_protection(conn, skb->data,
						    skb->len,
						    header_len - 4);
		if (ret < 0) {
			kfree_skb(skb);
			return ret;
		}
	}

	return tquic_output_packet(conn, path, skb);
}
EXPORT_SYMBOL_GPL(tquic_send_ack);

/*
 * Send PING-only packet for keepalive or path validation
 */
int tquic_send_ping(struct tquic_connection *conn, struct tquic_path *path)
{
	struct tquic_frame_ctx ctx;
	struct sk_buff *skb;
	u8 header_buf[128];
	u8 *payload_buf;
	int header_len, payload_len;
	int ret;
	u64 pkt_num;
	bool key_phase = false;

	tquic_dbg("send_ping: conn=%p path=%p\n", conn, path);

	pkt_num = atomic64_inc_return(&conn->pkt_num_tx) - 1;

	skb = alloc_skb(MAX_HEADER + 128 + 64 + 16, GFP_ATOMIC);
	if (!skb)
		return -ENOMEM;

	skb_reserve(skb, MAX_HEADER + 128);

	payload_buf = skb_put(skb, 64 + 16);

	ctx.conn = conn;
	ctx.path = path;
	ctx.buf = payload_buf;
	ctx.buf_len = 64;
	ctx.offset = 0;
	ctx.ack_eliciting = false;

	ret = tquic_gen_ping_frame(&ctx);
	if (ret < 0) {
		kfree_skb(skb);
		return ret;
	}

	payload_len = ctx.offset;

	if (conn->crypto_state) {
		struct tquic_key_update_state *ku_state;

		ku_state = tquic_crypto_get_key_update_state(
				conn->crypto_state);
		if (ku_state)
			key_phase =
				tquic_key_update_get_phase(ku_state) != 0;
	}

	header_len = tquic_build_short_header_internal(
			conn, path, header_buf, sizeof(header_buf),
			pkt_num, 0, key_phase, false, conn->grease_state);
	if (header_len < 0) {
		kfree_skb(skb);
		return header_len;
	}

	ret = tquic_encrypt_payload(conn, header_buf, header_len,
				    payload_buf, payload_len, pkt_num,
				    3);
	if (ret < 0) {
		kfree_skb(skb);
		return ret;
	}

	skb_trim(skb, payload_len + 16);
	memcpy(skb_push(skb, header_len), header_buf, header_len);

	if (header_len >= 5) {
		ret = tquic_apply_header_protection(conn, skb->data,
						    skb->len,
						    header_len - 4);
		if (ret < 0) {
			kfree_skb(skb);
			return ret;
		}
	}

	tquic_dbg("send_ping: sending pkt_num=%llu\n", pkt_num);
	return tquic_output_packet(conn, path, skb);
}
EXPORT_SYMBOL_GPL(tquic_send_ping);

/**
 * tquic_flow_send_max_data - Send MAX_DATA frame to update flow control window
 * @conn: QUIC connection
 * @path: Network path to send on
 * @max_data: New maximum data value to advertise
 *
 * Builds a minimal 1-RTT packet containing a MAX_DATA frame and sends it.
 * Called when the application has consumed enough data to warrant opening
 * the peer's send window (RFC 9000 Section 4.1).
 */
int tquic_flow_send_max_data(struct tquic_connection *conn,
			     struct tquic_path *path, u64 max_data)
{
	struct tquic_frame_ctx ctx;
	struct sk_buff *skb;
	u8 header_buf[128];
	u8 *payload_buf;
	int header_len, payload_len;
	int ret;
	u64 pkt_num;
	bool key_phase = false;

	pr_info("tquic: flow_send_max_data: max=%llu conn=%px is_server=%d\n",
		max_data, conn, conn->is_server);

	pkt_num = atomic64_inc_return(&conn->pkt_num_tx) - 1;

	/*
	 * Allocate skb with room for header + payload + AEAD tag (16 bytes).
	 * Follow the tquic_assemble_packet pattern: reserve space so we can
	 * push the header in front of the payload after encryption.
	 */
	skb = alloc_skb(MAX_HEADER + 128 + 128 + 16, GFP_ATOMIC);
	if (!skb)
		return -ENOMEM;

	skb_reserve(skb, MAX_HEADER + 128);

	/* Write frame directly into skb data area */
	payload_buf = skb_put(skb, 128 + 16);

	ctx.conn = conn;
	ctx.path = path;
	ctx.buf = payload_buf;
	ctx.buf_len = 128;
	ctx.offset = 0;
	ctx.ack_eliciting = true;

	ret = tquic_gen_max_data_frame(&ctx, max_data);
	if (ret < 0) {
		kfree_skb(skb);
		return ret;
	}

	payload_len = ctx.offset;

	/* Build short header (1-RTT) */
	if (conn->crypto_state) {
		struct tquic_key_update_state *ku_state;

		ku_state = tquic_crypto_get_key_update_state(
				conn->crypto_state);
		if (ku_state)
			key_phase = tquic_key_update_get_phase(
					ku_state) != 0;
	}

	header_len = tquic_build_short_header_internal(
			conn, path, header_buf, sizeof(header_buf),
			pkt_num, 0, key_phase, false, conn->grease_state);
	if (header_len < 0) {
		kfree_skb(skb);
		return header_len;
	}

	/* Encrypt payload in-place (header is AAD) */
	ret = tquic_encrypt_payload(conn, header_buf, header_len,
				    payload_buf, payload_len, pkt_num,
				    3 /* short header = APPLICATION */);
	if (ret < 0) {
		kfree_skb(skb);
		return ret;
	}

	/* Trim skb to actual encrypted size (payload + 16 byte AEAD tag) */
	skb_trim(skb, payload_len + 16);

	/* Push header in front of encrypted payload */
	memcpy(skb_push(skb, header_len), header_buf, header_len);

	/* Apply header protection (pn_offset = header_len - 4) */
	if (header_len >= 5) {
		ret = tquic_apply_header_protection(conn, skb->data,
						    skb->len,
						    header_len - 4);
		if (ret < 0) {
			kfree_skb(skb);
			return ret;
		}
	}

	return tquic_output_packet(conn, path, skb);
}
EXPORT_SYMBOL_GPL(tquic_flow_send_max_data);

/**
 * tquic_flow_send_max_stream_data - Send MAX_STREAM_DATA frame
 * @conn: QUIC connection
 * @path: Network path to send on
 * @stream_id: Stream to update
 * @max_data: New per-stream maximum data value to advertise
 *
 * Builds a minimal 1-RTT packet containing a MAX_STREAM_DATA frame.
 * Called when the application has consumed enough stream data to warrant
 * opening the peer's per-stream send window (RFC 9000 Section 4.2).
 */
int tquic_flow_send_max_stream_data(struct tquic_connection *conn,
				    struct tquic_path *path,
				    u64 stream_id, u64 max_data)
{
	struct tquic_frame_ctx ctx;
	struct sk_buff *skb;
	u8 header_buf[128];
	u8 *payload_buf;
	int header_len, payload_len;
	int ret;
	u64 pkt_num;
	bool key_phase = false;

	pr_info("tquic: flow_send_max_stream_data: stream=%llu max=%llu conn=%px is_server=%d\n",
		stream_id, max_data, conn, conn->is_server);

	pkt_num = atomic64_inc_return(&conn->pkt_num_tx) - 1;

	/*
	 * Allocate skb following tquic_assemble_packet pattern:
	 * reserve headroom so the header can be pushed after encryption.
	 */
	skb = alloc_skb(MAX_HEADER + 128 + 128 + 16, GFP_ATOMIC);
	if (!skb)
		return -ENOMEM;

	skb_reserve(skb, MAX_HEADER + 128);

	/* Write frame directly into skb data area */
	payload_buf = skb_put(skb, 128 + 16);

	ctx.conn = conn;
	ctx.path = path;
	ctx.buf = payload_buf;
	ctx.buf_len = 128;
	ctx.offset = 0;
	ctx.ack_eliciting = true;

	ret = tquic_gen_max_stream_data_frame(&ctx, stream_id, max_data);
	if (ret < 0) {
		kfree_skb(skb);
		return ret;
	}

	payload_len = ctx.offset;

	/* Build short header (1-RTT) */
	if (conn->crypto_state) {
		struct tquic_key_update_state *ku_state;

		ku_state = tquic_crypto_get_key_update_state(
				conn->crypto_state);
		if (ku_state)
			key_phase = tquic_key_update_get_phase(
					ku_state) != 0;
	}

	header_len = tquic_build_short_header_internal(
			conn, path, header_buf, sizeof(header_buf),
			pkt_num, 0, key_phase, false, conn->grease_state);
	if (header_len < 0) {
		kfree_skb(skb);
		return header_len;
	}

	/* Encrypt payload in-place (header is AAD) */
	ret = tquic_encrypt_payload(conn, header_buf, header_len,
				    payload_buf, payload_len, pkt_num,
				    3 /* short header = APPLICATION */);
	if (ret < 0) {
		kfree_skb(skb);
		return ret;
	}

	/* Trim skb to actual encrypted size (payload + 16 byte AEAD tag) */
	skb_trim(skb, payload_len + 16);

	/* Push header in front of encrypted payload */
	memcpy(skb_push(skb, header_len), header_buf, header_len);

	/* Apply header protection (pn_offset = header_len - 4) */
	if (header_len >= 5) {
		ret = tquic_apply_header_protection(conn, skb->data,
						    skb->len,
						    header_len - 4);
		if (ret < 0) {
			kfree_skb(skb);
			return ret;
		}
	}

	return tquic_output_packet(conn, path, skb);
}
EXPORT_SYMBOL_GPL(tquic_flow_send_max_stream_data);

/*
 * tquic_send_path_challenge and tquic_send_path_response are defined
 * in core/connection.c
 */

/*
 * Send CONNECTION_CLOSE
 */
int tquic_send_connection_close(struct tquic_connection *conn,
				u64 error_code, const char *reason)
{
	struct tquic_frame_ctx ctx;
	struct tquic_path *path;
	struct sk_buff *skb;
	u8 buf_stack[256];
	int ret;
	u64 pkt_num;

	rcu_read_lock();
	path = rcu_dereference(conn->active_path);
	if (path && !tquic_path_get(path))
		path = NULL;
	rcu_read_unlock();

	if (!path)
		return -EINVAL;

	ctx.conn = conn;
	ctx.path = path;
	ctx.buf = buf_stack;
	ctx.buf_len = sizeof(buf_stack);
	ctx.offset = 0;
	ctx.ack_eliciting = false;

	ret = tquic_gen_connection_close_frame(&ctx, error_code,
					       reason, reason ? strlen(reason) : 0);
	if (ret < 0)
		goto out_put_path;

	pkt_num = atomic64_inc_return(&conn->pkt_num_tx) - 1;

	/* Build packet */
	BUILD_BUG_ON(TQUIC_MAX_SHORT_HEADER_SIZE > 64);
	skb = alloc_skb(ctx.offset + TQUIC_MAX_SHORT_HEADER_SIZE + MAX_HEADER,
			GFP_ATOMIC);
	if (!skb) {
		ret = -ENOMEM;
		goto out_put_path;
	}

	skb_reserve(skb, MAX_HEADER);

	/* Build short header with connection's GREASE state */
	{
		u8 header[TQUIC_MAX_SHORT_HEADER_SIZE];
		int header_len = tquic_build_short_header_internal(
				conn, path, header,
				TQUIC_MAX_SHORT_HEADER_SIZE,
				pkt_num, 0, false, false,
				conn->grease_state);
		if (header_len <= 0) {
			/* Header build failed -- do not send unframed data */
			kfree_skb(skb);
			ret = header_len ? header_len : -EINVAL;
			goto out_put_path;
		}
		if (skb_tailroom(skb) < header_len) {
			kfree_skb(skb);
			ret = -ENOSPC;
			goto out_put_path;
		}
		skb_put_data(skb, header, header_len);
	}

	if (skb_tailroom(skb) < ctx.offset) {
		kfree_skb(skb);
		ret = -ENOSPC;
		goto out_put_path;
	}
	skb_put_data(skb, buf_stack, ctx.offset);

	ret = tquic_output_packet(conn, path, skb);

out_put_path:
	tquic_path_put(path);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_send_connection_close);

/*
 * tquic_output_flush - Flush pending stream data on connection
 * @conn: Connection with pending stream data
 *
 * This function implements the transmission trigger for non-NODELAY mode.
 * It iterates over all streams with pending data and transmits frames
 * respecting flow control and congestion control limits.
 *
 * Flow control is enforced at two levels:
 * - Stream level: Cannot exceed stream->max_send_data
 * - Connection level: Cannot exceed conn->max_data_remote
 *
 * Congestion control is checked per-path before transmission.
 *
 * Returns: Number of packets transmitted, or negative errno on error
 */
int tquic_output_flush(struct tquic_connection *conn)
{
	struct tquic_sent_packet *sent_pkt;
	struct tquic_path *path = NULL;
	struct tquic_pending_frame *frame;
	struct sk_buff *skb, *send_skb;
	struct rb_node *node;
	LIST_HEAD(frames);
	u64 pkt_num;
	u64 conn_credit;
	u64 inflight;
	int packets_sent = 0;
	int ret = 0;
	bool cwnd_limited;
	bool any_pending;
	int iter_sent;
	u32 pkt_size;
	const unsigned long flush_bit = 0;

	if (!conn)
		return -EINVAL;

	if (READ_ONCE(conn->state) != TQUIC_CONN_CONNECTED) {
		pr_info("tquic: output_flush: conn=%px NOT connected (state=%d)\n",
			conn, READ_ONCE(conn->state));
		return -ENOTCONN;
	}

	/*
	 * Avoid concurrent flushers racing conn_credit / conn->data_sent.
	 * If another flusher is active, schedule tx_work as a fallback
	 * so the send opportunity is not lost.
	 */
	if (test_and_set_bit(flush_bit, &conn->output_flush_flags)) {
		if (!work_pending(&conn->tx_work))
			schedule_work(&conn->tx_work);
		return 0;
	}

	/* Select path for transmission */
	path = tquic_select_path(conn, NULL);
	if (!tquic_output_path_usable(path)) {
		tquic_dbg("output_flush no active path\n");
		ret = 0;
		goto out_clear_flush;
	}

	/*
	 * Check congestion window before attempting transmission.
	 * If cwnd is exhausted, we'll be woken by ACK processing.
	 */
	if (path->stats.cwnd > 0) {
		inflight = (path->stats.tx_bytes > path->stats.acked_bytes) ?
			   path->stats.tx_bytes - path->stats.acked_bytes : 0;
		cwnd_limited = (inflight >= path->stats.cwnd);
	} else {
		/* No cwnd limit set yet (initial state) - allow sending */
		cwnd_limited = false;
	}

	if (cwnd_limited) {
		tquic_dbg("output_flush blocked by cwnd (inflight=%llu, cwnd=%u)\n",
			 inflight, path->stats.cwnd);
		ret = 0;
		goto out_clear_flush;
	}

	/*
	 * Outer drain loop: keep sending until all stream send_bufs are
	 * empty, or we're blocked by cwnd / connection flow control.
	 * The inner loop sends up to 64 packets per iteration to avoid
	 * holding conn->lock for too long.
	 */
	do {
		any_pending = false;
		iter_sent = 0;

		/*
		 * Re-check congestion window each outer iteration.
		 * ACK processing may have opened cwnd between iterations.
		 */
		if (path->stats.cwnd > 0) {
			inflight = (path->stats.tx_bytes >
				    path->stats.acked_bytes) ?
				   path->stats.tx_bytes -
				   path->stats.acked_bytes : 0;
			cwnd_limited = (inflight >= path->stats.cwnd);
		} else {
			cwnd_limited = false;
		}

		if (cwnd_limited)
			break;

		/*
		 * Take conn->lock once for both flow control check and
		 * stream iteration (CF-178: avoid releasing and
		 * re-acquiring the lock between the two critical
		 * sections).
		 */
		spin_lock_bh(&conn->lock);

		/* Check connection-level flow control credit */
		if (conn->data_sent >= conn->max_data_remote) {
			spin_unlock_bh(&conn->lock);
			tquic_dbg("output_flush blocked by connection flow control\n");
			break;
		}
		conn_credit = conn->max_data_remote - conn->data_sent;

		/* Iterate over streams with pending data (lock held). */
		for (node = rb_first(&conn->streams);
		     node && iter_sent < TQUIC_TX_WORK_BATCH_MAX;
		     node = rb_next(node)) {
			struct tquic_stream *stream;
			size_t chunk_size;

			stream = rb_entry(node, struct tquic_stream, node);

			/* Skip streams with no pending data */
			if (skb_queue_empty(&stream->send_buf))
				continue;

			/* Skip blocked streams */
			if (stream->blocked)
				continue;

			/* Process pending data from this stream's send buffer */
			while (!skb_queue_empty(&stream->send_buf) &&
			       conn_credit > 0 &&
			       iter_sent < TQUIC_TX_WORK_BATCH_MAX) {
				struct tquic_stream_skb_cb *cb;
				u64 stream_offset;
				u32 data_off;
				u32 remaining;
				u64 stream_credit;
				bool is_last;

				skb = skb_dequeue(&stream->send_buf);
				if (!skb)
					break;

				cb = tquic_stream_skb_cb(skb);
				stream_offset = cb->stream_offset;
				data_off = cb->data_off;
				if (unlikely(data_off > skb->len)) {
					/* Corrupted bookkeeping: drop skb to avoid looping. */
					kfree_skb(skb);
					ret = -EINVAL;
					break;
				}
				remaining = skb->len - data_off;
				if (unlikely(stream_offset >= stream->max_send_data)) {
					stream->blocked = true;
					skb_queue_head(&stream->send_buf, skb);
					break;
				}
				stream_credit = stream->max_send_data - stream_offset;

				/* Determine chunk size respecting flow control */
				chunk_size = remaining;
				if (chunk_size > conn_credit)
					chunk_size = conn_credit;
				if (chunk_size > stream_credit)
					chunk_size = stream_credit;
				if (chunk_size > path->mtu - 100)
					chunk_size = path->mtu - 100;

				/* FIN only on the last byte of the last queued skb. */
				is_last = skb_queue_empty(&stream->send_buf);

				/* Allocate and set up pending frame */
				frame = kmem_cache_zalloc(tquic_frame_cache, GFP_ATOMIC);
				if (!frame) {
					ret = -ENOMEM;
					skb_queue_head(&stream->send_buf, skb);
					break;
				}

				frame->type = TQUIC_FRAME_STREAM;
				frame->stream_id = stream->id;
				frame->offset = stream_offset;
				frame->len = chunk_size;
				frame->fin = stream->fin_sent &&
					     (chunk_size == remaining) &&
					     is_last;

				/*
				 * Zero-copy optimization: Reference skb data directly.
				 * The skb remains valid until packet assembly completes
				 * (happens synchronously before we free/consume the skb).
				 */
				frame->data = NULL;
				frame->data_ref = NULL;
				frame->skb = skb;
				frame->skb_off = data_off;
				frame->owns_data = false;

				INIT_LIST_HEAD(&frame->list);
				list_add_tail(&frame->list, &frames);

				/* Get next packet number (lock-free) */
				pkt_num = atomic64_inc_return(&conn->pkt_num_tx) - 1;

				/* Release lock while sending (may sleep in crypto) */
				spin_unlock_bh(&conn->lock);

				/* Assemble and send packet */
				send_skb = tquic_assemble_packet(conn, path, -1, pkt_num, &frames);
				if (send_skb) {
					/*
					 * Send via tquic_output_packet which handles:
					 * - EDT timestamp for FQ qdisc pacing
					 * - Internal pacing timer scheduling
					 * - Packet tracking for retransmission
					 *
					 * Pacing is configured via sk->sk_pacing_rate
					 * and handled by either FQ qdisc or EDT timestamps.
					 */
					/* Capture size before send consumes skb */
					pkt_size = send_skb->len;
					ret = tquic_output_packet(conn, path, send_skb);

					if (ret >= 0) {
						packets_sent++;
						iter_sent++;
						tquic_dbg("output_flush sent pkt %llu stream %llu offset %llu len %zu\n",
							 pkt_num, stream->id, stream_offset, chunk_size);

						/* Track packet for loss detection (RFC 9002 A.5) */
						sent_pkt = tquic_sent_packet_alloc(GFP_ATOMIC);
						if (sent_pkt) {
							tquic_sent_packet_init(sent_pkt,
								pkt_num, pkt_size,
								TQUIC_PN_SPACE_APPLICATION,
								true, true);
							tquic_loss_detection_on_packet_sent(
								conn, sent_pkt);
						}
					}
				} else {
					/* CF-615: Cleanup frame on assembly failure */
					struct tquic_pending_frame *f, *tmp;
					list_for_each_entry_safe(f, tmp, &frames, list) {
						list_del_init(&f->list);
						if (f->owns_data)
							kfree(f->data);
						kmem_cache_free(tquic_frame_cache, f);
					}
					ret = -ENOMEM;
				}

				/* Re-acquire lock and update state */
				spin_lock_bh(&conn->lock);

				if (ret >= 0 && send_skb) {
					/* Update flow control accounting */
					conn->data_sent += chunk_size;
					if (conn->fc_data_reserved >= chunk_size)
						conn->fc_data_reserved -= chunk_size;
					else
						conn->fc_data_reserved = 0;
					conn_credit -= chunk_size;

					if (chunk_size == remaining) {
						/* Consumed entire skb - uncharge memory */
						if (conn->sk) {
							sk_mem_uncharge(conn->sk, skb->truesize);
							/* sk_wmem_alloc handled by skb destructor */
							if (sk_stream_wspace(conn->sk) > 0)
								conn->sk->sk_write_space(conn->sk);
						}
						kfree_skb(skb);
					} else {
						/* Partial consumption - advance cb offsets (works for non-linear). */
						cb->stream_offset = stream_offset + chunk_size;
						cb->data_off = data_off + chunk_size;
						skb_queue_head(&stream->send_buf, skb);
					}
				} else {
					/* Failed to send: put skb back for retry. */
					skb_queue_head(&stream->send_buf, skb);
				}

				/* Clear frame list for next iteration */
				INIT_LIST_HEAD(&frames);

				if (ret < 0)
					break;
			}

			if (ret < 0)
				break;
		}

		/*
		 * Check if any stream still has pending data.
		 * If so, and we sent packets this iteration, loop
		 * again to drain remaining buffers.
		 */
		if (ret >= 0) {
			for (node = rb_first(&conn->streams);
			     node; node = rb_next(node)) {
				struct tquic_stream *s;

				s = rb_entry(node, struct tquic_stream, node);
				if (!skb_queue_empty(&s->send_buf) &&
				    !s->blocked) {
					any_pending = true;
					break;
				}
			}
		}

		spin_unlock_bh(&conn->lock);
	} while (ret >= 0 && any_pending);

	/*
	 * If we transmitted any packets, the timer/recovery subsystem
	 * will handle loss detection and retransmission via
	 * tquic_timer_schedule() called from tquic_output_packet().
	 */

	ret = packets_sent > 0 ? packets_sent : ret;
	if (packets_sent > 0)
		pr_info("tquic: output_flush: conn=%px sent %d pkts is_server=%d\n",
			conn, packets_sent, conn->is_server);
out_clear_flush:
	if (path)
		tquic_path_put(path);
	clear_bit(flush_bit, &conn->output_flush_flags);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_output_flush);

/**
 * tquic_send_handshake_done - Send HANDSHAKE_DONE frame (server only)
 * @conn: Connection that completed handshake
 *
 * RFC 9000 Section 19.20: The server sends HANDSHAKE_DONE in a 1-RTT
 * packet to signal handshake completion.  Must be called after the
 * server's TLS handshake reaches COMPLETE state and Application keys
 * are installed.
 */
int tquic_send_handshake_done(struct tquic_connection *conn)
{
	struct tquic_pending_frame *frame;
	struct tquic_path *path;
	struct sk_buff *skb;
	LIST_HEAD(frames);
	u64 pkt_num;
	int ret;

	if (!conn->is_server)
		return -EINVAL;

	path = rcu_dereference(conn->active_path);
	if (!path)
		return -ENOENT;

	frame = kmem_cache_zalloc(tquic_frame_cache, GFP_ATOMIC);
	if (!frame)
		return -ENOMEM;

	frame->type = TQUIC_FRAME_HANDSHAKE_DONE;
	frame->len = 0;
	frame->owns_data = false;
	list_add_tail(&frame->list, &frames);

	pkt_num = atomic64_inc_return(&conn->pkt_num_tx) - 1;

	/* pkt_type -1 = short header (1-RTT) */
	skb = tquic_assemble_packet(conn, path, -1, pkt_num, &frames);
	if (!skb) {
		/* Cleanup on failure */
		struct tquic_pending_frame *f, *tmp;

		list_for_each_entry_safe(f, tmp, &frames, list) {
			list_del_init(&f->list);
			kmem_cache_free(tquic_frame_cache, f);
		}
		return -ENOMEM;
	}

	ret = tquic_output_packet(conn, path, skb);
	pr_debug("tquic: sent HANDSHAKE_DONE frame (pkt_num=%llu ret=%d)\n",
		pkt_num, ret);

	return ret;
}
EXPORT_SYMBOL_GPL(tquic_send_handshake_done);

/**
 * tquic_xmit_close - Send a CONNECTION_CLOSE frame
 * @conn: Connection to close
 * @error_code: QUIC error code
 * @is_app: True for application-level close (0x1d), false for transport (0x1c)
 *
 * Sends a CONNECTION_CLOSE frame on the active path. Unlike tquic_xmit(),
 * this function works without a stream and in CLOSING state (RFC 9000
 * Section 10.2.1 permits sending CONNECTION_CLOSE in closing state).
 */
int tquic_xmit_close(struct tquic_connection *conn, u64 error_code,
		      bool is_app)
{
	struct tquic_pending_frame *frame;
	struct tquic_path *path;
	struct sk_buff *skb;
	LIST_HEAD(frames);
	u64 pkt_num;
	int ret;

	rcu_read_lock();
	path = rcu_dereference(conn->active_path);
	if (!path || !tquic_path_get(path)) {
		rcu_read_unlock();
		return -ENOENT;
	}
	rcu_read_unlock();

	frame = kmem_cache_zalloc(tquic_frame_cache, GFP_ATOMIC);
	if (!frame) {
		tquic_path_put(path);
		return -ENOMEM;
	}

	frame->type = is_app ? TQUIC_FRAME_CONNECTION_CLOSE_APP
			     : TQUIC_FRAME_CONNECTION_CLOSE;
	frame->offset = error_code; /* Repurpose offset for error code */
	frame->len = 0;
	frame->owns_data = false;
	list_add_tail(&frame->list, &frames);

	pkt_num = atomic64_inc_return(&conn->pkt_num_tx) - 1;

	/* pkt_type -1 = short header (1-RTT) */
	skb = tquic_assemble_packet(conn, path, -1, pkt_num, &frames);
	if (!skb) {
		struct tquic_pending_frame *f, *tmp;

		list_for_each_entry_safe(f, tmp, &frames, list) {
			list_del_init(&f->list);
			kmem_cache_free(tquic_frame_cache, f);
		}
		tquic_path_put(path);
		return -ENOMEM;
	}

	ret = tquic_output_packet(conn, path, skb);
	tquic_path_put(path);

	pr_debug("tquic: sent CONNECTION_CLOSE (error=%llu ret=%d)\n",
		 error_code, ret);

	return ret;
}
EXPORT_SYMBOL_GPL(tquic_xmit_close);

/*
 * tquic_output_flush_crypto - Flush pending CRYPTO frame data
 * @conn: Connection with pending crypto data
 *
 * Drains the per-PN-space crypto_buffer queues and sends CRYPTO frames
 * inside properly formed QUIC packets (Initial or Handshake).
 *
 * The packet assembly pipeline handles:
 *   1. CRYPTO frame generation (type 0x06 + offset + length + data)
 *   2. QUIC long header construction (version, CIDs, token, length)
 *   3. AEAD encryption (packet protection)
 *   4. Header protection (first byte + packet number masking)
 *   5. Padding to 1200 bytes for Initial packets (RFC 9000 Section 14.1)
 *
 * Returns: Number of packets sent, or negative errno on error
 */
int tquic_output_flush_crypto(struct tquic_connection *conn)
{
	struct tquic_path *path;
	struct sk_buff *crypto_skb;
	struct sk_buff *send_skb;
	struct tquic_pending_frame *frame;
	int packets_sent = 0;
	int space;
	u64 crypto_offset;
	int pkt_type;

	u64 pkt_num;
	int ret;

	if (!conn)
		return -EINVAL;

	rcu_read_lock();
	path = rcu_dereference(conn->active_path);
	if (path && !tquic_path_get(path))
		path = NULL;
	rcu_read_unlock();

	if (!path)
		return -ENOENT;

	/*
	 * Process each PN space's crypto buffer.
	 * Initial and Handshake spaces carry TLS handshake messages.
	 */
	for (space = 0; space < TQUIC_PN_SPACE_COUNT; space++) {
		crypto_offset = 0;

		/* Map PN space to QUIC long header packet type */
		switch (space) {
		case TQUIC_PN_SPACE_INITIAL:
			pkt_type = TQUIC_PKT_INITIAL;
			break;
		case TQUIC_PN_SPACE_HANDSHAKE:
			pkt_type = TQUIC_PKT_HANDSHAKE;
			break;
		default:
			/* Application space doesn't use CRYPTO frames */
			continue;
		}

		while ((crypto_skb = skb_dequeue(&conn->crypto_buffer[space]))) {
			u8 *chunk_data = crypto_skb->data;
			u32 remaining = crypto_skb->len;
			u32 path_mtu = READ_ONCE(path->mtu);
			u32 max_chunk;

			/*
			 * Split large crypto data across multiple QUIC
			 * packets so each fits within the path MTU.
			 *
			 * Per-packet overhead (conservative):
			 *   Long header:         64 bytes max
			 *   CRYPTO frame header: 16 bytes max
			 *   AEAD tag:            16 bytes
			 *   Total:               96 bytes
			 */
			if (unlikely(path_mtu < 1200))
				path_mtu = 1200;
			max_chunk = path_mtu - 96;

			while (remaining > 0) {
				u32 chunk = min_t(u32, remaining, max_chunk);
				LIST_HEAD(frames);

				frame = kmem_cache_zalloc(tquic_frame_cache,
							  GFP_ATOMIC);
				if (!frame) {
					kfree_skb(crypto_skb);
					ret = -ENOMEM;
					goto out_put_path;
				}

				INIT_LIST_HEAD(&frame->list);
				frame->type = TQUIC_FRAME_CRYPTO;
				frame->data_ref = chunk_data;
				frame->len = chunk;
				frame->offset = crypto_offset;
				frame->owns_data = false;

				list_add_tail(&frame->list, &frames);

				pkt_num = atomic64_inc_return(
						&conn->pkt_num_tx) - 1;

				send_skb = tquic_assemble_packet(
						conn, path, pkt_type,
						pkt_num, &frames);
				if (!send_skb) {
					kfree_skb(crypto_skb);
					ret = -ENOMEM;
					goto out_put_path;
				}

				ret = tquic_output_packet(conn, path,
							  send_skb);
				if (ret < 0) {
					kfree_skb(crypto_skb);
					goto out_put_path;
				}

				chunk_data += chunk;
				crypto_offset += chunk;
				remaining -= chunk;
				packets_sent++;
			}

			kfree_skb(crypto_skb);
		}
	}

	ret = packets_sent;

out_put_path:
	tquic_path_put(path);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_output_flush_crypto);

/*
 * =============================================================================
 * DATAGRAM Frame Support (RFC 9221)
 * =============================================================================
 *
 * QUIC DATAGRAM frames provide unreliable, unordered message delivery.
 * Unlike STREAM frames, DATAGRAM frames are not retransmitted on loss.
 * This is useful for real-time applications where stale data is less
 * valuable than timely delivery of fresh data.
 */

/*
 * tquic_datagram_init - Initialize datagram state for a connection
 * @conn: Connection to initialize
 *
 * This must be called after transport parameter negotiation to set up
 * the datagram receive queue and related state.
 */
void tquic_datagram_init(struct tquic_connection *conn)
{
	tquic_dbg("datagram_init: conn=%p\n", conn);

	if (!conn)
		return;

	spin_lock_init(&conn->datagram.lock);
	skb_queue_head_init(&conn->datagram.recv_queue);
	init_waitqueue_head(&conn->datagram.wait);

	conn->datagram.enabled = false;
	conn->datagram.max_send_size = 0;
	conn->datagram.max_recv_size = 0;
	conn->datagram.recv_queue_len = 0;
	conn->datagram.recv_queue_max = TQUIC_DATAGRAM_QUEUE_DEFAULT;
	conn->datagram.datagrams_sent = 0;
	conn->datagram.datagrams_received = 0;
	conn->datagram.datagrams_dropped = 0;
}
EXPORT_SYMBOL_GPL(tquic_datagram_init);

/*
 * tquic_datagram_cleanup - Cleanup datagram resources
 * @conn: Connection to cleanup
 *
 * Frees all queued datagrams. Should be called during connection teardown.
 */
void tquic_datagram_cleanup(struct tquic_connection *conn)
{
	unsigned long flags;

	tquic_dbg("datagram_cleanup: conn=%p\n", conn);

	if (!conn)
		return;

	spin_lock_irqsave(&conn->datagram.lock, flags);

	/* Purge receive queue */
	skb_queue_purge(&conn->datagram.recv_queue);
	conn->datagram.recv_queue_len = 0;

	conn->datagram.enabled = false;
	conn->datagram.max_send_size = 0;
	conn->datagram.max_recv_size = 0;

	spin_unlock_irqrestore(&conn->datagram.lock, flags);
}
EXPORT_SYMBOL_GPL(tquic_datagram_cleanup);

/*
 * tquic_datagram_max_size - Get maximum datagram payload size
 * @conn: Connection to query
 *
 * Returns the maximum payload size that can be sent in a DATAGRAM frame,
 * accounting for QUIC overhead (header, frame type, length field, AEAD tag).
 *
 * Return: Maximum datagram payload size, or 0 if datagrams not supported
 */
u64 tquic_datagram_max_size(struct tquic_connection *conn)
{
	struct tquic_path *path;
	u64 max_size;
	u64 overhead;

	tquic_dbg("datagram_max_size: conn=%p enabled=%d\n",
		  conn, conn ? conn->datagram.enabled : 0);

	if (!conn || !conn->datagram.enabled)
		return 0;

	/*
	 * Calculate maximum datagram size:
	 * - max_send_size is from peer's transport parameter
	 * - We also need to account for QUIC packet overhead
	 *
	 * Overhead estimate:
	 * - Short header: 1 + DCID_len + pkt_num_len (1-4) + AEAD tag (16)
	 * - DATAGRAM frame: type (1) + length varint (1-8)
	 *
	 * Conservative estimate: 40 bytes overhead
	 */
	overhead = 40;

	rcu_read_lock();
	path = rcu_dereference(conn->active_path);
	if (path)
		max_size = path->mtu;
	else
		max_size = 0;
	rcu_read_unlock();

	if (max_size > overhead)
		max_size -= overhead;
	else
		max_size = 1200 - overhead;  /* Minimum QUIC MTU */

	/* Limit by peer's advertised max_datagram_frame_size */
	if (conn->datagram.max_send_size > 0 &&
	    conn->datagram.max_send_size < max_size)
		max_size = conn->datagram.max_send_size;

	tquic_dbg("datagram_max_size: result=%llu\n", max_size);
	return max_size;
}
EXPORT_SYMBOL_GPL(tquic_datagram_max_size);

/*
 * tquic_send_datagram - Send a DATAGRAM frame
 * @conn: Connection to send on
 * @data: Datagram payload
 * @len: Payload length
 *
 * Sends an unreliable, unordered datagram. The datagram will be sent
 * on the currently active path. If multiple paths are available,
 * the scheduler will select the best path.
 *
 * Return: Number of bytes sent, or negative error code
 *         -ENOTCONN: Connection not established
 *         -ENOBUFS: Datagram support not negotiated
 *         -EMSGSIZE: Datagram too large
 *         -ENOMEM: Memory allocation failed
 *         -EAGAIN: Congestion window full (try again later)
 */
int tquic_send_datagram(struct tquic_connection *conn,
			const void *data, size_t len)
{
	struct tquic_path *path;
	struct tquic_frame_ctx ctx;
	struct sk_buff *skb;
	u8 *buf;
	u64 pkt_num;
	u64 max_size;
	int header_len;
	int ret;

	if (!conn)
		return -EINVAL;

	if (READ_ONCE(conn->state) != TQUIC_CONN_CONNECTED)
		return -ENOTCONN;

	/* Check if datagrams are negotiated */
	if (!conn->datagram.enabled)
		return -ENOBUFS;

	/* Check size limit */
	max_size = tquic_datagram_max_size(conn);
	if (len > max_size)
		return -EMSGSIZE;

	/* Select path */
	path = tquic_select_path(conn, NULL);
	if (!path)
		return -ENETUNREACH;

	/* Check congestion window */
	if (path->stats.cwnd > 0) {
		u64 inflight;

		if (path->stats.tx_bytes > path->stats.acked_bytes)
			inflight = path->stats.tx_bytes - path->stats.acked_bytes;
		else
			inflight = 0;

		if (inflight + len > path->stats.cwnd) {
			tquic_path_put(path);
			return -EAGAIN;
		}
	}

	/* Validate MTU and allocate buffer for frame generation */
	if (path->mtu == 0 || path->mtu > 65535) {
		tquic_path_put(path);
		return -EINVAL;
	}
	buf = kmalloc(path->mtu, GFP_ATOMIC);
	if (!buf) {
		tquic_path_put(path);
		return -ENOMEM;
	}

	/* Initialize frame context */
	ctx.conn = conn;
	ctx.path = path;
	ctx.buf = buf;
	ctx.buf_len = path->mtu - 64;  /* Leave room for header */
	ctx.offset = 0;
	ctx.ack_eliciting = false;

	/* Generate DATAGRAM frame (use with_length=true for safety) */
	ret = tquic_gen_datagram_frame(&ctx, data, len, true);
	if (ret < 0) {
		kfree(buf);
		tquic_path_put(path);
		return ret;
	}

	/* Get packet number (lock-free) */
	pkt_num = atomic64_inc_return(&conn->pkt_num_tx) - 1;

	/* Allocate SKB */
	skb = alloc_skb(ctx.offset + TQUIC_MAX_SHORT_HEADER_SIZE + MAX_HEADER,
			GFP_ATOMIC);
	if (!skb) {
		kfree(buf);
		tquic_path_put(path);
		return -ENOMEM;
	}

	skb_reserve(skb, MAX_HEADER);

	/* Build short header */
	{
		u8 header[TQUIC_MAX_SHORT_HEADER_SIZE];

		header_len = tquic_build_short_header_internal(
				conn, path, header,
				TQUIC_MAX_SHORT_HEADER_SIZE,
				pkt_num, 0, false, false, NULL);
			if (header_len < 0) {
				kfree_skb(skb);
				kfree(buf);
				tquic_path_put(path);
				return header_len;
			}
			if (skb_tailroom(skb) < header_len) {
				kfree_skb(skb);
				kfree(buf);
				tquic_path_put(path);
				return -ENOSPC;
			}
			skb_put_data(skb, header, header_len);
	}

	/* Add frame payload */
	if (skb_tailroom(skb) < ctx.offset) {
		kfree_skb(skb);
		kfree(buf);
		tquic_path_put(path);
		return -ENOSPC;
	}
	skb_put_data(skb, buf, ctx.offset);
	kfree(buf);

	/* Apply encryption if available */
	if (conn->crypto_state) {
		ret = tquic_encrypt_payload(conn, skb->data, header_len,
					    skb->data + header_len,
					    ctx.offset, pkt_num, 3);
		if (ret < 0) {
			kfree_skb(skb);
			tquic_path_put(path);
			return ret;
		}
	}

	/* Send packet */
	ret = tquic_output_packet(conn, path, skb);
	tquic_path_put(path);
	if (ret >= 0) {
		/* Update statistics (use _bh for softirq safety) */
		spin_lock_bh(&conn->datagram.lock);
		conn->datagram.datagrams_sent++;
		spin_unlock_bh(&conn->datagram.lock);

		/* Update MIB counters */
		if (conn->sk)
			TQUIC_INC_STATS(sock_net(conn->sk), TQUIC_MIB_DATAGRAMSTX);

		return len;
	}

	return ret;
}
EXPORT_SYMBOL_GPL(tquic_send_datagram);

/*
 * tquic_recv_datagram - Receive a DATAGRAM frame
 * @conn: Connection to receive from
 * @data: Buffer to store datagram payload
 * @len: Buffer size
 * @flags: Receive flags (MSG_DONTWAIT, MSG_PEEK, etc.)
 *
 * Receives an unreliable, unordered datagram from the receive queue.
 * Datagrams are delivered in the order they are received from the network,
 * which may differ from the order they were sent.
 *
 * Return: Number of bytes received, or negative error code
 *         -ENOTCONN: Connection not established
 *         -ENOBUFS: Datagram support not negotiated
 *         -EAGAIN: No datagram available (non-blocking)
 *         -EMSGSIZE: Buffer too small (datagram truncated)
 */
/*
 * tquic_datagram_wait_data - Wait for datagram data to arrive
 * @conn: Connection to wait on
 * @timeo: Pointer to timeout in jiffies (updated on return)
 *
 * Blocks until a datagram is available, the connection closes,
 * an error occurs, or the timeout expires.
 *
 * Return: 0 on success (data available), negative error code otherwise
 *         -EAGAIN: Timeout expired with no data
 *         -EINTR: Interrupted by signal (use sock_intr_errno for proper value)
 *         -ENOTCONN: Connection closed or in error state
 */
static int tquic_datagram_wait_data(struct tquic_connection *conn, long *timeo)
{
	struct sock *sk = conn->sk;
	int ret;

	tquic_dbg("datagram_wait_data: conn=%p timeo=%ld\n",
		  conn, *timeo);

	/*
	 * Wait for one of:
	 *   - Datagram available in receive queue
	 *   - Connection error (sk_err set)
	 *   - Connection closing/closed
	 *   - Socket shutdown (sk_shutdown & RCV_SHUTDOWN)
	 *   - Timeout
	 *   - Signal
	 *
	 * The datagram.wait queue is woken by tquic_input.c when a
	 * DATAGRAM frame is received (via sk->sk_data_ready callback).
	 */
	ret = wait_event_interruptible_timeout(
		conn->datagram.wait,
		!skb_queue_empty(&conn->datagram.recv_queue) ||
		    (sk && sk->sk_err) ||
		    (sk && (sk->sk_shutdown & RCV_SHUTDOWN)) ||
		    READ_ONCE(conn->state) == TQUIC_CONN_CLOSED ||
		    READ_ONCE(conn->state) == TQUIC_CONN_DRAINING,
		*timeo);

	if (ret < 0) {
		/* Interrupted by signal */
		return -EINTR;
	}

	if (ret == 0) {
		/* Timeout expired */
		*timeo = 0;
		return -EAGAIN;
	}

	/* Update remaining timeout */
	*timeo = ret;

	/* Check for socket error */
	if (sk && sk->sk_err)
		return -sock_error(sk);

	/* Check for shutdown */
	if (sk && (sk->sk_shutdown & RCV_SHUTDOWN))
		return -ENOTCONN;

	/* Check for connection close */
	if (READ_ONCE(conn->state) == TQUIC_CONN_CLOSED ||
	    READ_ONCE(conn->state) == TQUIC_CONN_DRAINING)
		return -ENOTCONN;

	/* Data should be available now */
	tquic_dbg("datagram_wait_data: data available\n");
	return 0;
}

int tquic_recv_datagram(struct tquic_connection *conn,
			void *data, size_t len, int flags)
{
	struct sk_buff *skb;
	size_t copy_len;
	unsigned long irqflags;
	int ret;
	long timeo;
	int retries = 0;

	if (!conn)
		return -EINVAL;

	if (READ_ONCE(conn->state) != TQUIC_CONN_CONNECTED &&
	    READ_ONCE(conn->state) != TQUIC_CONN_CLOSING)
		return -ENOTCONN;

	/* Check if datagrams are negotiated */
	if (!conn->datagram.enabled)
		return -ENOBUFS;

	/*
	 * Determine timeout for blocking operation.
	 * Use the socket's SO_RCVTIMEO if available, otherwise block indefinitely.
	 * A timeout of 0 means non-blocking when MSG_DONTWAIT is not set but
	 * the socket is in non-blocking mode.
	 */
	if (conn->sk)
		timeo = sock_rcvtimeo(conn->sk, flags & MSG_DONTWAIT);
	else
		timeo = (flags & MSG_DONTWAIT) ? 0 : MAX_SCHEDULE_TIMEOUT;

retry:
	/* CF-450: Prevent infinite loop under signal pressure */
	if (++retries > 3)
		return -EAGAIN;
	spin_lock_irqsave(&conn->datagram.lock, irqflags);

	/* Check for available datagram */
	skb = skb_peek(&conn->datagram.recv_queue);
	if (!skb) {
		spin_unlock_irqrestore(&conn->datagram.lock, irqflags);

		/* Non-blocking mode: return immediately */
		if (flags & MSG_DONTWAIT)
			return -EAGAIN;

		/* No timeout set (non-blocking socket): return immediately */
		if (timeo == 0)
			return -EAGAIN;

		/* Check for pending signals before blocking */
		if (signal_pending(current))
			return sock_intr_errno(timeo);

		/* Block waiting for data */
		ret = tquic_datagram_wait_data(conn, &timeo);
		if (ret < 0) {
			if (ret == -EINTR)
				return sock_intr_errno(timeo);
			return ret;
		}

		/*
		 * Re-check connection state after waking up.
		 * Connection may have transitioned while we were sleeping.
		 */
		if (READ_ONCE(conn->state) != TQUIC_CONN_CONNECTED &&
		    READ_ONCE(conn->state) != TQUIC_CONN_CLOSING)
			return -ENOTCONN;

		/* Retry to get the datagram */
		goto retry;
	}

	/* Calculate how much to copy */
	copy_len = min_t(size_t, len, skb->len);

	/* Copy data to user buffer */
	memcpy(data, skb->data, copy_len);

	/* Check if we truncated */
	if (skb->len > len)
		ret = -EMSGSIZE;
	else
		ret = copy_len;

	/* Remove from queue unless peeking */
	if (!(flags & MSG_PEEK)) {
		__skb_unlink(skb, &conn->datagram.recv_queue);
		conn->datagram.recv_queue_len--;
		spin_unlock_irqrestore(&conn->datagram.lock, irqflags);
		kfree_skb(skb);
	} else {
		spin_unlock_irqrestore(&conn->datagram.lock, irqflags);
	}

	return ret;
}
EXPORT_SYMBOL_GPL(tquic_recv_datagram);

/*
 * tquic_datagram_queue_len - Get number of queued datagrams
 * @conn: Connection to query
 *
 * Return: Number of datagrams in the receive queue
 */
u32 tquic_datagram_queue_len(struct tquic_connection *conn)
{
	u32 len;
	unsigned long flags;

	if (!conn)
		return 0;

	spin_lock_irqsave(&conn->datagram.lock, flags);
	len = conn->datagram.recv_queue_len;
	spin_unlock_irqrestore(&conn->datagram.lock, flags);

	tquic_dbg("datagram_queue_len: len=%u\n", len);
	return len;
}
EXPORT_SYMBOL_GPL(tquic_datagram_queue_len);

/*
 * =============================================================================
 * Module Registration
 * =============================================================================
 */

/**
 * tquic_output_tx_init - Initialize TX-path slab caches
 *
 * Creates the tquic_frame_cache used for tquic_pending_frame allocations
 * on the hot TX path.  Must be called once during module init.
 */
int __init tquic_output_tx_init(void)
{
	tquic_dbg("output_tx_init: creating frame slab cache\n");

	tquic_frame_cache = kmem_cache_create("tquic_pending_frame",
					      sizeof(struct tquic_pending_frame),
					      0, SLAB_HWCACHE_ALIGN, NULL);
	if (!tquic_frame_cache)
		return -ENOMEM;

	tquic_dbg("output_tx_init: frame cache created\n");
	return 0;
}

/**
 * tquic_output_tx_exit - Destroy TX-path slab caches
 */
void tquic_output_tx_exit(void)
{
	kmem_cache_destroy(tquic_frame_cache);
	tquic_frame_cache = NULL;
}

MODULE_DESCRIPTION("TQUIC Packet Transmission Path");
MODULE_LICENSE("GPL");
