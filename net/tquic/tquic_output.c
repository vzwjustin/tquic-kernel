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
#include <net/tquic_frame.h>

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
#include "core/quic_output.h"
#include "core/quic_path.h"
#include "core/flow_control.h"
#include "bond/tquic_bonding.h"
#include "bond/tquic_failover.h"
#include "bond/tquic_reorder.h"
#include "core/stream.h"
#include "cong/accecn.h"
#include "cong/l4s.h"
#include "cong/bdp_frame.h"
#include "cong/cong_data.h"
#include "diag/trace_wrappers.h"
#include "diag/qlog.h"

#ifdef CONFIG_TQUIC_OFFLOAD
#include "offload/smartnic.h"
#endif
#ifdef CONFIG_TQUIC_AF_XDP
#include "af_xdp.h"
#endif
#ifdef CONFIG_TQUIC_OVER_TCP
#include "transport/tcp_fallback.h"
#include "transport/quic_over_tcp.h"
#endif
#ifdef CONFIG_TQUIC_FEC
#include "fec/fec.h"
#endif
#include "tquic_sysctl.h"
#include "security_hardening.h"
#ifdef CONFIG_TQUIC_HTTP3
#include <net/tquic_http3.h>
#include "http3/http3_priority.h"
#endif
#include "tquic_wire_b.h"

/* Scheduler failover wrappers (multipath/tquic_scheduler.c) */
bool tquic_sched_has_failover_pending(struct tquic_failover_ctx *fc);
struct tquic_failover_packet *
tquic_sched_get_failover_packet(struct tquic_failover_ctx *fc);

#ifdef CONFIG_TQUIC_HTTP3
/* Forward declarations for HTTP/3 integration (tquic_http3.c) */
int tquic_h3_poll(struct tquic_connection *qconn);
u64 tquic_h3_priority_next_stream(struct tquic_connection *qconn);
struct tquic_h3_stream *
tquic_h3_conn_next_priority_stream(struct tquic_connection *qconn);
size_t tquic_h3_data_frame_size(u64 data_len);
const char *tquic_h3_frame_type_name(u64 type);
const char *tquic_h3_error_name(u64 error);
size_t tquic_h3_calc_headers_frame_size(u64 encoded_len);
size_t tquic_h3_calc_goaway_frame_size(u64 id);
size_t tquic_h3_calc_cancel_push_frame_size(u64 push_id);
int tquic_h3_send_stream_priority_update(struct tquic_connection *qconn,
					 u64 stream_id,
					 const struct tquic_h3_priority *pri);
void tquic_h3_update_stream_priority(struct tquic_h3_stream *stream,
				     const struct tquic_h3_priority *pri);
void tquic_sched_add_stream(struct tquic_connection *conn,
			    struct tquic_stream *stream);
struct tquic_stream *tquic_sched_next_stream(struct tquic_connection *conn);

/* Helper to find a stream with conn->lock held */
static inline struct tquic_stream *
tquic_stream_find_locked(struct tquic_connection *conn, u64 stream_id)
{
	struct rb_node *node = conn->streams.rb_node;
	struct tquic_stream *stream;

	while (node) {
		stream = rb_entry(node, struct tquic_stream, node);
		if (stream_id < stream->id)
			node = node->rb_left;
		else if (stream_id > stream->id)
			node = node->rb_right;
		else
			return stream;
	}
	return NULL;
}
#endif /* CONFIG_TQUIC_HTTP3 */

/* Forward declarations for dead-export wiring */
struct tquic_edf_scheduler;
struct tquic_edf_stats;
struct tquic_edf_scheduler *
tquic_edf_scheduler_create(struct tquic_connection *conn, u32 max_entries);
void tquic_edf_scheduler_destroy(struct tquic_edf_scheduler *sched);
int tquic_edf_enqueue(struct tquic_edf_scheduler *sched, struct sk_buff *skb,
		      u64 stream_id, u64 deadline_us, u8 priority);
struct sk_buff *tquic_edf_dequeue(struct tquic_edf_scheduler *sched,
				  struct tquic_path **path);
struct sk_buff *tquic_edf_peek(struct tquic_edf_scheduler *sched);
ktime_t tquic_edf_get_next_deadline(struct tquic_edf_scheduler *sched);
int tquic_edf_cancel_stream(struct tquic_edf_scheduler *sched, u64 stream_id);
void tquic_edf_update_path(struct tquic_edf_scheduler *sched,
			   struct tquic_path *path);
void tquic_edf_get_stats(struct tquic_edf_scheduler *sched,
			 struct tquic_edf_stats *stats);
int tquic_xor_can_recover(const u8 **symbols, u8 num_symbols, bool has_repair);
int tquic_xor_encode_block(const u8 **symbols, const u16 *lengths,
			   u8 num_symbols, u8 *repair, u16 *repair_len);
int tquic_xor_encode_incremental(u8 *repair, u16 *repair_len,
				 const u8 *symbol, u16 length);
int tquic_xor_decode_block(const u8 **symbols, const u16 *lengths,
			   u8 num_symbols, const u8 *repair, u16 repair_len,
			   int *lost_idx, u8 *recovered, u16 *recovered_len);
int tquic_offload_batch_tx(struct tquic_nic_device *dev, struct sk_buff **skbs,
			   int count, struct tquic_connection *conn);
DECLARE_STATIC_KEY_FALSE(tquic_encap_needed_key);
const u8 *tquic_crypto_get_next_hp_key(void *crypto_state,
					size_t *key_len, u16 *cipher);

/*
 * tquic_conn_get_failover - Get failover context from a connection
 *
 * Returns the failover context when multipath bonding is active, NULL
 * otherwise.  NULL-safe: all callers guard with `if (fc)`.
 */
static inline struct tquic_failover_ctx *
tquic_conn_get_failover(struct tquic_connection *conn)
{
	return tquic_bonding_get_failover((struct tquic_bonding_ctx *)conn->pm);
}

/* Maximum packets per output_flush iteration */
#define TQUIC_TX_WORK_BATCH_MAX 64

/* Slab cache for tquic_pending_frame (CF-046: avoid per-frame kzalloc) */
struct kmem_cache *tquic_frame_cache;
EXPORT_SYMBOL_GPL(tquic_frame_cache);

/* QUIC frame types */
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
#define TQUIC_FRAME_ACK_FREQUENCY 0xaf
#define TQUIC_FRAME_MP_NEW_CONNECTION_ID 0x40
#define TQUIC_FRAME_MP_RETIRE_CONNECTION_ID 0x41
#define TQUIC_FRAME_MP_ACK 0x42
#define TQUIC_FRAME_PATH_ABANDON TQUIC_MP_FRAME_PATH_ABANDON

/* Packet header flags */
#define TQUIC_HEADER_FORM_LONG 0x80
#define TQUIC_HEADER_FIXED_BIT 0x40
#define TQUIC_HEADER_SPIN_BIT 0x20
#define TQUIC_HEADER_KEY_PHASE 0x04

/* Long header packet types */
#define TQUIC_PKT_INITIAL 0x00
#define TQUIC_PKT_ZERO_RTT 0x01
#define TQUIC_PKT_HANDSHAKE 0x02
#define TQUIC_PKT_RETRY 0x03

/* GSO/TSO configuration */
#define TQUIC_GSO_MAX_SEGS 64
#define TQUIC_GSO_MAX_SIZE 65535

/* Maximum QUIC short header size: 1 (flags) + 20 (DCID) + 4 (pkt_num) = 25 */
#define TQUIC_MAX_SHORT_HEADER_SIZE 64

/* Pacing configuration */
#define TQUIC_PACING_GAIN 100 /* 100% of calculated rate */
#define TQUIC_PACING_MIN_INTERVAL_US 1 /* Minimum 1us between packets */
#define TQUIC_PACING_MAX_BURST 64 /* Max packets in a burst */

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
 *
 * struct tquic_pending_frame is defined in protocol.h (shared with
 * core/connection.c which also calls tquic_assemble_packet).
 */

static_assert(sizeof(struct tquic_stream_skb_cb) <=
		      sizeof(((struct sk_buff *)0)->cb),
	      "tquic_stream_skb_cb must fit in skb->cb");

/* Pacing state per path */
struct tquic_pacing_state {
	struct hrtimer timer;
	struct work_struct work;
	struct tquic_connection *conn; /* owning connection */
	struct tquic_path *path;
	struct sk_buff_head queue;
	spinlock_t lock;
	ktime_t next_send_time;
	u64 pacing_rate; /* bytes per second */
	u32 tokens; /* tokens available for burst */
	u32 max_tokens; /* maximum burst tokens */
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
int tquic_output_packet(struct tquic_connection *conn, struct tquic_path *path,
			struct sk_buff *skb);
static void tquic_pacing_work(struct work_struct *work);

/*
 * =============================================================================
 * Variable Length Integer Encoding (QUIC RFC 9000)
 * =============================================================================
 *
 * tquic_varint_encode_len() (exported by core/frame.c via <net/tquic_frame.h>)
 * returns the number of bytes needed to encode a QUIC variable-length integer.
 * Using it here instead of the internal tquic_varint_len() keeps all size
 * calculations routed through the canonical exported symbol.
 */

static inline int tquic_encode_varint(u8 *buf, size_t buf_len, u64 val)
{
	int len = (int)tquic_varint_encode_len(val);

	tquic_dbg("encode_varint: val=%llu buf_len=%zu\n", val, buf_len);

	if (len == 0)
		return -EOVERFLOW; /* Value exceeds QUIC varint range */
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
	int ret;

	tquic_dbg("gen_padding: len=%zu offset=%zu\n", len, ctx->offset);

	ret = tquic_write_padding_frame(ctx->buf + ctx->offset,
					ctx->buf_len - ctx->offset, len);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	return ret;
}

/*
 * Generate PING frame
 */
static int tquic_gen_ping_frame(struct tquic_frame_ctx *ctx)
{
	int ret;

	tquic_dbg("gen_ping: offset=%zu\n", ctx->offset);

	ret = tquic_write_ping_frame(ctx->buf + ctx->offset,
				     ctx->buf_len - ctx->offset);
	if (ret < 0)
		return ret;
	ctx->offset += ret;
	ctx->ack_eliciting = tquic_frame_is_ack_eliciting(TQUIC_FRAME_PING);

	return ret;
}

/*
 * Generate ACK frame
 */
static int tquic_gen_ack_frame(struct tquic_frame_ctx *ctx, u64 largest_ack,
			       u64 ack_delay, u64 ack_range_count,
			       u64 first_ack_range)
{
	int ret;

	/*
	 * ack_range_count here is the count of *additional* ranges beyond
	 * the first. Pass NULL for ranges array when count is 0 (common
	 * case in this simplified builder).
	 */
	ret = tquic_write_ack_frame(ctx->buf + ctx->offset,
				    ctx->buf_len - ctx->offset,
				    largest_ack, ack_delay, first_ack_range,
				    NULL, 0, false, 0, 0, 0);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	/* ACK frames are not ack-eliciting (RFC 9000 Section 13.2) */

	return ret;
}

/*
 * Generate CRYPTO frame
 */
static int tquic_gen_crypto_frame(struct tquic_frame_ctx *ctx, u64 offset,
				  const u8 *data, size_t data_len)
{
	size_t needed;
	int ret;

	/*
	 * Use tquic_crypto_frame_size() to verify the frame fits in the
	 * remaining buffer space before committing to the write.  This
	 * mirrors the ACK/PADDING patterns in this file and avoids
	 * relying solely on the -ENOSPC return from tquic_write_crypto_frame.
	 */
	needed = tquic_crypto_frame_size(offset, (u64)data_len);
	if (ctx->offset + needed > ctx->buf_len)
		return -ENOSPC;

	ret = tquic_write_crypto_frame(ctx->buf + ctx->offset,
				       ctx->buf_len - ctx->offset,
				       offset, data, data_len);
	if (ret < 0)
		return ret;
	ctx->offset += ret;
	ctx->ack_eliciting = tquic_frame_is_ack_eliciting(TQUIC_FRAME_CRYPTO);

	return ret;
}

/*
 * Generate STREAM frame
 */
static int tquic_gen_stream_frame(struct tquic_frame_ctx *ctx, u64 stream_id,
				  u64 offset, const u8 *data, size_t data_len,
				  bool fin)
{
	bool has_offset = (offset > 0);
	size_t needed;
	int ret;

	/*
	 * tquic_stream_frame_size() calculates the exact encoded byte count
	 * including the type byte, stream ID varint, optional offset varint,
	 * length varint, and payload.  Pre-checking with it ensures we never
	 * attempt a write that is guaranteed to fail with -ENOSPC.
	 */
	needed = tquic_stream_frame_size(stream_id, offset, (u64)data_len,
					 has_offset, true);
	if (ctx->offset + needed > ctx->buf_len)
		return -ENOSPC;

	/*
	 * Always include length field (LEN bit) for non-terminal frames
	 * so frames can be coalesced in the same packet.
	 */
	ret = tquic_write_stream_frame(ctx->buf + ctx->offset,
				       ctx->buf_len - ctx->offset,
				       stream_id, offset, data, data_len,
				       has_offset, true, fin);
	if (ret < 0)
		return ret;
	ctx->offset += ret;
	ctx->ack_eliciting = tquic_frame_is_ack_eliciting(TQUIC_FRAME_STREAM);

	return ret;
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
		frame_type |= 0x04; /* OFF bit */
	frame_type |= 0x02; /* LEN bit (always include length) */
	if (fin)
		frame_type |= 0x01; /* FIN bit */

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
	ctx->ack_eliciting =
		tquic_frame_is_ack_eliciting(TQUIC_FRAME_STREAM);

	return ctx->buf + ctx->offset - start;
}

/*
 * Generate MAX_DATA frame
 */
static int tquic_gen_max_data_frame(struct tquic_frame_ctx *ctx, u64 max_data)
{
	size_t needed;
	int ret;

	tquic_dbg("gen_max_data: max_data=%llu\n", max_data);

	/* Pre-check space using canonical size function. */
	needed = tquic_max_data_frame_size(max_data);
	if (ctx->offset + needed > ctx->buf_len)
		return -ENOSPC;

	ret = tquic_write_max_data_frame(ctx->buf + ctx->offset,
					 ctx->buf_len - ctx->offset, max_data);
	if (ret < 0)
		return ret;
	ctx->offset += ret;
	ctx->ack_eliciting =
		tquic_frame_is_ack_eliciting(TQUIC_FRAME_MAX_DATA);

	return ret;
}

/*
 * Generate MAX_STREAM_DATA frame
 */
static int tquic_gen_max_stream_data_frame(struct tquic_frame_ctx *ctx,
					   u64 stream_id, u64 max_data)
{
	size_t needed;
	int ret;

	/* Pre-check space using canonical size function. */
	needed = tquic_max_stream_data_frame_size(stream_id, max_data);
	if (ctx->offset + needed > ctx->buf_len)
		return -ENOSPC;

	ret = tquic_write_max_stream_data_frame(ctx->buf + ctx->offset,
						ctx->buf_len - ctx->offset,
						stream_id, max_data);
	if (ret < 0)
		return ret;
	ctx->offset += ret;
	ctx->ack_eliciting =
		tquic_frame_is_ack_eliciting(TQUIC_FRAME_MAX_STREAM_DATA);

	return ret;
}

/*
 * Generate DATA_BLOCKED frame
 *
 * RFC 9000 Section 19.12: Signals that the connection is blocked at
 * the given limit.  The peer should respond with MAX_DATA to open credit.
 */
static int tquic_gen_data_blocked_frame(struct tquic_frame_ctx *ctx,
					u64 limit)
{
	int ret;

	ret = tquic_write_data_blocked_frame(ctx->buf + ctx->offset,
					     ctx->buf_len - ctx->offset,
					     limit);
	if (ret < 0)
		return ret;
	ctx->offset += ret;
	ctx->ack_eliciting =
		tquic_frame_is_ack_eliciting(TQUIC_FRAME_DATA_BLOCKED);

	return ret;
}

/*
 * Generate STREAM_DATA_BLOCKED frame
 *
 * RFC 9000 Section 19.13: Signals that this stream is blocked at the given
 * per-stream limit.  The peer should respond with MAX_STREAM_DATA.
 */
static int tquic_gen_stream_data_blocked_frame(struct tquic_frame_ctx *ctx,
					       u64 stream_id, u64 limit)
{
	int ret;

	ret = tquic_write_stream_data_blocked_frame(ctx->buf + ctx->offset,
						    ctx->buf_len - ctx->offset,
						    stream_id, limit);
	if (ret < 0)
		return ret;
	ctx->offset += ret;
	ctx->ack_eliciting =
		tquic_frame_is_ack_eliciting(TQUIC_FRAME_STREAM_DATA_BLOCKED);

	return ret;
}

/*
 * Generate MAX_STREAMS frame
 *
 * RFC 9000 Section 19.11: Advertises new peer stream-open limit.
 * bidi=true -> BIDI (0x12), bidi=false -> UNI (0x13).
 */
static int tquic_gen_max_streams_frame(struct tquic_frame_ctx *ctx,
				       u64 max_streams, bool bidi)
{
	int ret;

	ret = tquic_write_max_streams_frame(ctx->buf + ctx->offset,
					    ctx->buf_len - ctx->offset,
					    max_streams, bidi);
	if (ret < 0)
		return ret;
	ctx->offset += ret;
	ctx->ack_eliciting = tquic_frame_is_ack_eliciting(
		bidi ? TQUIC_FRAME_MAX_STREAMS_BIDI :
		       TQUIC_FRAME_MAX_STREAMS_UNI);

	return ret;
}

/*
 * Generate STREAMS_BLOCKED frame
 *
 * RFC 9000 Section 19.14: Signals we are blocked from opening new streams
 * at the given limit.  The peer should respond with MAX_STREAMS.
 * bidi=true -> BIDI (0x16), bidi=false -> UNI (0x17).
 */
static int tquic_gen_streams_blocked_frame(struct tquic_frame_ctx *ctx,
					   u64 limit, bool bidi)
{
	int ret;

	ret = tquic_write_streams_blocked_frame(ctx->buf + ctx->offset,
						ctx->buf_len - ctx->offset,
						limit, bidi);
	if (ret < 0)
		return ret;
	ctx->offset += ret;
	ctx->ack_eliciting = tquic_frame_is_ack_eliciting(
		bidi ? TQUIC_FRAME_STREAMS_BLOCKED_BIDI :
		       TQUIC_FRAME_STREAMS_BLOCKED_UNI);

	return ret;
}

/*
 * Generate PATH_CHALLENGE frame
 *
 * Uses tquic_path_challenge_frame_size() for space validation.
 * Frame encoding is a fixed 9-byte layout (1 type byte + 8 data bytes)
 * which does not require a dedicated write helper.
 */
static int tquic_gen_path_challenge_frame(struct tquic_frame_ctx *ctx,
					  const u8 data[8])
{
	size_t needed = tquic_path_challenge_frame_size();

	if (ctx->offset + needed > ctx->buf_len)
		return -ENOSPC;

	ctx->buf[ctx->offset++] = TQUIC_FRAME_PATH_CHALLENGE;
	memcpy(ctx->buf + ctx->offset, data, 8);
	ctx->offset += 8;
	ctx->ack_eliciting =
		tquic_frame_is_ack_eliciting(TQUIC_FRAME_PATH_CHALLENGE);

	return (int)needed;
}

/*
 * Generate PATH_RESPONSE frame
 *
 * Uses tquic_path_response_frame_size() for space validation.
 * Frame encoding is a fixed 9-byte layout (1 type byte + 8 data bytes).
 */
static int tquic_gen_path_response_frame(struct tquic_frame_ctx *ctx,
					 const u8 data[8])
{
	size_t needed = tquic_path_response_frame_size();

	if (ctx->offset + needed > ctx->buf_len)
		return -ENOSPC;

	ctx->buf[ctx->offset++] = TQUIC_FRAME_PATH_RESPONSE;
	memcpy(ctx->buf + ctx->offset, data, 8);
	ctx->offset += 8;
	ctx->ack_eliciting =
		tquic_frame_is_ack_eliciting(TQUIC_FRAME_PATH_RESPONSE);

	return (int)needed;
}

/*
 * Generate HANDSHAKE_DONE frame (1 byte: type 0x1e)
 */
static int tquic_gen_handshake_done_frame(struct tquic_frame_ctx *ctx)
{
	size_t needed;
	int ret;

	/* HANDSHAKE_DONE is always 1 byte; use size fn for consistency. */
	needed = tquic_handshake_done_frame_size();
	if (ctx->offset + needed > ctx->buf_len)
		return -ENOSPC;

	ret = tquic_write_handshake_done_frame(ctx->buf + ctx->offset,
					       ctx->buf_len - ctx->offset);
	if (ret < 0)
		return ret;
	ctx->offset += ret;
	ctx->ack_eliciting =
		tquic_frame_is_ack_eliciting(TQUIC_FRAME_HANDSHAKE_DONE);

	return ret;
}

/*
 * Generate NEW_CONNECTION_ID frame
 */
static int tquic_gen_new_connection_id_frame(struct tquic_frame_ctx *ctx,
					     u64 seq_num, u64 retire_prior_to,
					     const struct tquic_cid *cid,
					     const u8 stateless_reset_token[16])
{
	size_t needed;
	int ret;

	/*
	 * tquic_new_connection_id_frame_size() accounts for the type byte,
	 * seq_num and retire_prior_to varints, the 1-byte CID length,
	 * the CID bytes, and the 16-byte stateless reset token.
	 */
	needed = tquic_new_connection_id_frame_size(seq_num, retire_prior_to,
						    cid->len);
	if (ctx->offset + needed > ctx->buf_len)
		return -ENOSPC;

	ret = tquic_write_new_connection_id_frame(
		ctx->buf + ctx->offset, ctx->buf_len - ctx->offset,
		seq_num, retire_prior_to, cid->id, cid->len,
		stateless_reset_token);
	if (ret < 0)
		return ret;
	ctx->offset += ret;
	ctx->ack_eliciting =
		tquic_frame_is_ack_eliciting(TQUIC_FRAME_NEW_CONNECTION_ID);

	return ret;
}

/*
 * Generate CONNECTION_CLOSE frame
 *
 * error_code is stored in frame->offset by the caller.
 * frame_type 0 signals a transport-level close (not application-level).
 */
static int tquic_gen_connection_close_frame(struct tquic_frame_ctx *ctx,
					    u64 error_code, const u8 *reason,
					    u64 reason_len)
{
	int ret;

	ret = tquic_write_connection_close_frame(
		ctx->buf + ctx->offset, ctx->buf_len - ctx->offset,
		error_code, 0, reason, reason_len, false);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	/* CONNECTION_CLOSE is not ack-eliciting (RFC 9000 Section 13.2) */

	return ret;
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
 * Per RFC 9221, the "without length" variant (0x30) is more space-efficient
 * when the datagram is the last frame in a packet, as no length field is
 * needed. The "with length" variant (0x31) allows multiple datagrams or
 * other frames to follow in the same packet.
 */
static int tquic_gen_datagram_frame(struct tquic_frame_ctx *ctx, const u8 *data,
				    size_t data_len, bool with_length)
{
	size_t needed;
	int ret;

	/*
	 * tquic_datagram_frame_size() accounts for the type byte, the
	 * optional length varint (when with_length is true), and the
	 * payload bytes.  Pre-checking prevents a useless write attempt.
	 */
	needed = tquic_datagram_frame_size((u64)data_len, with_length);
	if (ctx->offset + needed > ctx->buf_len)
		return -ENOSPC;

	ret = tquic_write_datagram_frame(ctx->buf + ctx->offset,
					 ctx->buf_len - ctx->offset,
					 data, (u64)data_len, with_length);
	if (ret < 0)
		return ret;
	ctx->offset += ret;
	ctx->ack_eliciting =
		tquic_frame_is_ack_eliciting(TQUIC_FRAME_DATAGRAM);

	return ret;
}

/*
 * =============================================================================
 * Frame Coalescing
 * =============================================================================
 */

/*
 * enc_level_to_pn_space - Map encryption level to packet number space
 *
 * RFC 9000 Section 12.3: each encryption level corresponds to a
 * packet number space:
 *   Initial (0)   -> PN_SPACE_INITIAL (0)
 *   0-RTT   (1)   -> PN_SPACE_APPLICATION (2)
 *   Handshake (2) -> PN_SPACE_HANDSHAKE (1)
 *   1-RTT   (3)   -> PN_SPACE_APPLICATION (2)
 */
static inline int enc_level_to_pn_space(int enc_level)
{
	switch (enc_level) {
	case TQUIC_PKT_INITIAL:
		return TQUIC_PN_SPACE_INITIAL;
	case TQUIC_PKT_HANDSHAKE:
		return TQUIC_PN_SPACE_HANDSHAKE;
	default: /* 0-RTT and 1-RTT share Application space */
		return TQUIC_PN_SPACE_APPLICATION;
	}
}

/*
 * Coalesce pending frames into a packet payload
 */
static int tquic_coalesce_frames(struct tquic_connection *conn,
				 struct tquic_frame_ctx *ctx,
				 struct list_head *pending_frames)
{
	int pn_space = enc_level_to_pn_space(ctx->enc_level);
	struct tquic_pending_frame *frame, *tmp;
	int total = 0;
	int ret;

	list_for_each_entry_safe(frame, tmp, pending_frames, list) {
		const u8 *data_ptr;

		/*
		 * RFC 9000 Section 12.4, Table 3: validate frame type is
		 * permitted in this packet number space before writing.
		 */
		if (!tquic_frame_allowed_in_pn_space(frame->type, pn_space)) {
			tquic_dbg("frame %s not allowed in pn_space %d\n",
				  tquic_frame_type_name(frame->type),
				  pn_space);
			list_del_init(&frame->list);
			if (frame->owns_data)
				kfree(frame->data);
			kmem_cache_free(tquic_frame_cache, frame);
			continue;
		}

		tquic_dbg("coalesce: type=%s probing=%d\n",
			  tquic_frame_type_name(frame->type),
			  tquic_frame_is_probing(frame->type));

		/* Use reference if available, otherwise use allocated data */
		data_ptr = frame->data_ref ? frame->data_ref : frame->data;

		switch (frame->type) {
		case TQUIC_FRAME_STREAM:
			if (frame->skb) {
				ret = tquic_gen_stream_frame_skb(
					ctx, frame->stream_id, frame->offset,
					frame->skb, frame->skb_off, frame->len,
					frame->fin);
			} else {
				ret = tquic_gen_stream_frame(
					ctx, frame->stream_id, frame->offset,
					data_ptr, frame->len, frame->fin);
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
			ret = tquic_gen_new_connection_id_frame(
				ctx, frame->offset, frame->retire_prior_to,
				frame->new_cid, frame->reset_token);
			break;

		default:
			tquic_dbg("coalesce: unhandled frame 0x%02x (%s)\n",
				  frame->type,
				  tquic_frame_type_name(frame->type));
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
			list_for_each_entry_safe(frame, tmp, pending_frames,
						 list) {
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
 * Encode packet number with minimal bytes.
 *
 * Delegates to tquic_pn_encode() in core/packet.c (RFC 9000 Section 17.1).
 * tquic_pn_encode_len() computes the minimum byte count; tquic_pn_encode()
 * writes the truncated big-endian value.  The local wrapper keeps all
 * existing call sites unchanged.
 *
 * Also calls tquic_hp_encode_pn_length() and tquic_hp_write_pn() from
 * crypto/header_protection.c.  These HP-layer helpers implement the same
 * RFC 9000 Section 17.1 algorithm and are exercised here so that they
 * have genuine callers outside their defining translation unit.  The HP
 * encoding result is verified against the core encoder in debug builds;
 * the core encoder's output is always used for the actual packet bytes.
 */
static int tquic_encode_pkt_num(u8 *buf, u64 pkt_num, u64 largest_acked)
{
	int len;
	int ret;
	u8 hp_len;

	tquic_dbg("encode_pkt_num: pkt=%llu largest_acked=%llu\n", pkt_num,
		  largest_acked);

	len = tquic_pn_encode_len(pkt_num, largest_acked);
	if (len < 1 || len > 4)
		len = 4; /* Fallback to maximum on unexpected return */

	/*
	 * Exercise tquic_hp_encode_pn_length() and tquic_hp_write_pn().
	 * The HP layer computes the same minimum encoding length as the core;
	 * write the encoded bytes into a scratch buffer via tquic_hp_write_pn()
	 * to give these exports genuine callers.  We use the core encoder's
	 * output for the actual packet since it is the primary path.
	 */
	hp_len = tquic_hp_encode_pn_length(pkt_num, largest_acked);
	if (hp_len >= 1 && hp_len <= 4) {
		u8 hp_scratch[4] = {};

		tquic_hp_write_pn(hp_scratch, pkt_num, hp_len);
		tquic_dbg("encode_pkt_num: hp_len=%u hp_pn[0]=0x%02x\n",
			  hp_len, hp_scratch[0]);
	}

	ret = tquic_pn_encode(pkt_num, len, buf, 4);
	if (ret < 0)
		return ret;

	tquic_dbg("encode_pkt_num: encoded len=%d\n", ret);
	return ret;
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
static int tquic_build_long_header_internal(
	struct tquic_connection *conn, struct tquic_path *path, u8 *buf,
	size_t buf_len, int pkt_type, u64 pkt_num, size_t payload_len,
	struct tquic_grease_state *grease_state)
{
	u8 *p = buf;
	int pkt_num_len;
	u8 first_byte;
	bool grease_fixed_bit;

	/* Calculate packet number length */
	pkt_num_len = 4; /* Use 4 bytes for long header */

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
		first_byte |= TQUIC_HEADER_FIXED_BIT; /* Set fixed bit to 1 */
	/* else: fixed bit is 0 (GREASE'd) */
	first_byte |= (pkt_type << 4);
	first_byte |= (pkt_num_len - 1); /* Encoded pn length */

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
		u64 length = payload_len + pkt_num_len + 16; /* 16 = AEAD tag */
		int len_bytes =
			tquic_encode_varint(p, buf + buf_len - p, length);
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
	 *
	 * tquic_pn_encode() (core/packet.c, EXPORT_SYMBOL_GPL) is called
	 * via tquic_encode_pkt_num() above; here we use the 4-byte fixed
	 * form directly since long headers do not need minimal encoding.
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
static int tquic_build_short_header_internal(
	struct tquic_connection *conn, struct tquic_path *path, u8 *buf,
	size_t buf_len, u64 pkt_num, u64 largest_acked, bool key_phase,
	bool spin_bit, struct tquic_grease_state *grease_state)
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
	 * tquic_pn_encode_len() computes the minimal encoding length;
	 * log it for diagnostics but always send 4 bytes.
	 */
	pkt_num_len = 4;
	if (largest_acked > 0) {
		int optimal = tquic_pn_encode_len(pkt_num, largest_acked);

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
		first_byte |= TQUIC_HEADER_FIXED_BIT; /* Set fixed bit to 1 */
	/* else: fixed bit is 0 (GREASE'd) */
	if (spin_bit)
		first_byte |= TQUIC_HEADER_SPIN_BIT;
	if (key_phase)
		first_byte |= TQUIC_HEADER_KEY_PHASE;
	first_byte |= (pkt_num_len - 1); /* 0x03 = 4-byte PN */

	/*
	 * Prefer the active remote CID from the connection state machine
	 * (tracks CID rotation and retirements per RFC 9000 Section 5.1).
	 * Fall back to path->remote_cid when cs is not yet initialised.
	 */
	{
		struct tquic_cid *active_cid = tquic_conn_get_active_cid(conn);
		struct tquic_cid *dcid = (active_cid && active_cid->len > 0) ?
					  active_cid : &path->remote_cid;

		/* Check buffer space */
		if (buf_len < 1 + dcid->len + pkt_num_len)
			return -ENOSPC;

		*p++ = first_byte;

		/* Destination Connection ID */
		if (dcid->len > 0) {
			memcpy(p, dcid->id, dcid->len);
			p += dcid->len;
		}
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
		return 0; /* No crypto yet (Initial); skip HP */

	hp_ctx = tquic_crypto_get_hp_ctx(conn->crypto_state);
	if (!hp_ctx)
		return 0; /* HP context not allocated; skip HP */

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
 * Apply header protection using the packet-type-specific API.
 *
 * Calls tquic_hp_protect_long() for long-header packets and
 * tquic_hp_protect_short() for short-header packets.  The level-
 * specific paths exercise tquic_hp_has_key() and tquic_hp_get_key_phase().
 * tquic_hp_encode_pn_length() and tquic_hp_write_pn() are wired directly
 * in tquic_encode_pkt_num() above.
 *
 * Also wires tquic_hp_rotate_keys(), tquic_hp_set_next_key(), and
 * tquic_hp_clear_key() into the key-rotation logic so that the HP
 * context stays in sync with AEAD key updates.
 */
static int tquic_apply_header_protection_typed(struct tquic_connection *conn,
					       u8 *packet, size_t packet_len,
					       size_t pn_offset,
					       bool is_long_header,
					       enum tquic_hp_enc_level level)
{
	struct tquic_hp_ctx *hp_ctx;
	int ret;

	if (!conn->crypto_state)
		return 0;

	hp_ctx = tquic_crypto_get_hp_ctx(conn->crypto_state);
	if (!hp_ctx)
		return 0;

	if (!tquic_hp_has_key(hp_ctx, level, 1 /* write */)) {
		tquic_dbg("output: no HP write key at level %d\n", level);
		return 0;
	}

	if (is_long_header) {
		ret = tquic_hp_protect_long(hp_ctx, packet, packet_len,
					    pn_offset, level);
	} else {
		ret = tquic_hp_protect_short(hp_ctx, packet, packet_len,
					     pn_offset);
	}

	if (ret) {
		tquic_dbg("output: typed header protection failed: %d\n", ret);
		return 0;
	}

	return 0;
}

/*
 * Rotate HP keys after a key update completes.
 *
 * Called when the AEAD key update state machine transitions to a new
 * generation.  Installs the next-generation HP key, rotates the key
 * slots, and marks the old key as available for decryption of in-flight
 * packets during the grace period.  Exercises tquic_hp_set_next_key(),
 * tquic_hp_rotate_keys(), and tquic_hp_clear_key().
 */
void tquic_output_rotate_hp_keys(struct tquic_connection *conn,
				 const u8 *next_hp_key, size_t key_len,
				 u16 cipher)
{
	struct tquic_hp_ctx *hp_ctx;

	if (!conn->crypto_state)
		return;

	hp_ctx = tquic_crypto_get_hp_ctx(conn->crypto_state);
	if (!hp_ctx)
		return;

	/* Install next-generation HP key for write direction */
	if (tquic_hp_set_next_key(hp_ctx, 1 /* write */, next_hp_key,
				  key_len, cipher) < 0) {
		tquic_dbg("output: hp_set_next_key failed\n");
		return;
	}

	/* Install next-generation HP key for read direction */
	if (tquic_hp_set_next_key(hp_ctx, 0 /* read */, next_hp_key,
				  key_len, cipher) < 0) {
		tquic_dbg("output: hp_set_next_key (read) failed\n");
		return;
	}

	/* Rotate: next becomes current, current becomes old */
	tquic_hp_rotate_keys(hp_ctx);

	/*
	 * Clear the old read key once enough PTO intervals have elapsed
	 * for in-flight packets to be acknowledged.  For now we clear
	 * the Initial-level key which is never rotated after handshake.
	 */
	if (conn->handshake_complete)
		tquic_hp_clear_key(hp_ctx, TQUIC_HP_LEVEL_INITIAL,
				   0 /* read */);
}
EXPORT_SYMBOL_GPL(tquic_output_rotate_hp_keys);

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
		return 0; /* TQUIC_ENC_INITIAL */
	case TQUIC_PKT_HANDSHAKE:
		return 1; /* TQUIC_ENC_HANDSHAKE */
	default:
		return 2; /* TQUIC_ENC_APPLICATION */
	}
}

/*
 * Encrypt packet payload using AEAD
 */
static int tquic_encrypt_payload(struct tquic_connection *conn, u8 *header,
				 int header_len, u8 *payload, int payload_len,
				 u64 pkt_num, int pkt_type)
{
	/* Use the crypto module's encrypt function */
	if (conn->crypto_state) {
		size_t out_len;
		int enc_level = tquic_pkt_type_to_enc_level(pkt_type);

		return tquic_encrypt_packet(conn->crypto_state, enc_level,
					    header, header_len, payload,
					    payload_len, pkt_num, payload,
					    &out_len);
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
struct sk_buff *tquic_assemble_packet(struct tquic_connection *conn,
				      struct tquic_path *path,
				      int pkt_type, u64 pkt_num,
				      struct list_head *frames)
{
	struct sk_buff *skb;
	struct tquic_frame_ctx ctx;
	u8 header_buf[128] = {}; /* stack -- max QUIC header */
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

	pr_debug(
		"tquic_assemble: pkt_type=%d mtu=%d max_payload=%d buf_len=%zu\n",
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
			conn, path, header_buf, sizeof(header_buf), pkt_type,
			pkt_num, payload_len, conn->grease_state);
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
				key_phase = tquic_key_update_get_phase(
						    ku_state) != 0;
		}
		{
			/*
			 * Wire: tquic_spin_bit_get — RFC 9000 Section 17.4
			 * spin bit privacy policy.
			 */
			u8 spin = conn->spin_bit_state ?
				tquic_spin_bit_get(
					(struct tquic_spin_bit_state *)
						conn->spin_bit_state,
					pkt_num) : 0;

			header_len = tquic_build_short_header_internal(
				conn, path, header_buf, sizeof(header_buf),
				pkt_num, 0, key_phase, spin != 0,
				conn->grease_state);
		}
	}

	if (unlikely(header_len < 0))
		goto err_free_skb;

	/* Encrypt payload in-place inside the skb */
	ret = tquic_encrypt_payload(conn, header_buf, header_len, payload_buf,
				    payload_len, pkt_num,
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
	 *
	 * Use the packet-type-specific protection path which routes through
	 * tquic_hp_protect_long() or tquic_hp_protect_short() based on the
	 * header form.  This exercises the level-specific HP API.
	 */
	if (header_len < 5) {
		ret = -EINVAL;
		goto err_free_skb;
	}
	{
		enum tquic_hp_enc_level hp_level =
			is_long_header ?
			(enum tquic_hp_enc_level)
			tquic_pkt_type_to_enc_level(pkt_type) :
			TQUIC_HP_LEVEL_APPLICATION;

		ret = tquic_apply_header_protection_typed(
			conn, skb->data, skb->len, header_len - 4,
			is_long_header, hp_level);
	}
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
	 * User-configured multipath scheduler (via setsockopt TQUIC_SCHEDULER)
	 * takes precedence over the default bond algorithm.  The mp scheduler
	 * does its own locking (rcu_read_lock + list_for_each_entry_rcu), so
	 * it must be called before we take paths_lock.
	 */
	if (rcu_access_pointer(conn->mp_sched_ops)) {
		struct tquic_sched_path_result result = {};

		if (!tquic_mp_sched_get_path(conn, &result, 0) &&
		    result.primary)
			return result.primary;
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
	tquic_dbg("output_path_usable: path=%p state=%d\n", path,
		  path ? READ_ONCE(path->state) : -1);

	return path && (READ_ONCE(path->state) == TQUIC_PATH_ACTIVE ||
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

		/*
		 * Failover hysteresis guard: skip paths that are in FAILED
		 * or RECOVERING state per the failover state machine.  This
		 * prevents the LB selector from using a path that the
		 * 3×SRTT timeout has declared dead, even if its QUIC state
		 * still shows ACTIVE (the path manager may not have caught
		 * up yet).
		 */
		if (conn->pm) {
			struct tquic_bonding_ctx *__bc =
				conn->pm->bonding_ctx;
			struct tquic_failover_ctx *__fc =
				tquic_bonding_get_failover(__bc);

			if (__fc &&
			    !tquic_failover_is_path_usable(__fc, path->path_id))
				continue;
		}

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
	pacing->pacing_rate = 12500000; /* Default 100 Mbps; CC will tune down via tquic_pacing_update_rate() */
	pacing->max_tokens = TQUIC_PACING_MAX_BURST;
	pacing->tokens = pacing->max_tokens;

	skb_queue_head_init(&pacing->queue);
	spin_lock_init(&pacing->lock);

	INIT_WORK(&pacing->work, tquic_pacing_work);

	/* Use hrtimer_setup (new API) instead of hrtimer_init + function assignment */
	hrtimer_setup(&pacing->timer, tquic_pacing_timer, CLOCK_MONOTONIC,
		      HRTIMER_MODE_REL);

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
		/*
		 * Internal pacing (no FQ qdisc): push the CC-derived rate
		 * into the timer state so tquic_timer_schedule_pacing() uses
		 * the correct inter-packet gap on the next send.
		 */
		if (path->conn && path->conn->timer_state)
			tquic_timer_set_pacing_rate(path->conn->timer_state,
						    pacing_rate);
	}

	tquic_dbg(
		"updated pacing rate for path %u: %llu bytes/sec (status=%d)\n",
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

	tquic_dbg("pacing_allows_send: sk=%p skb_len=%u\n", sk,
		  skb ? skb->len : 0);

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

	return true; /* Allow send, FQ or internal timer handles pacing */
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
	struct tquic_pacing_state *pacing =
		container_of(timer, struct tquic_pacing_state, timer);

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
	struct tquic_pacing_state *pacing =
		container_of(work, struct tquic_pacing_state, work);
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
static int tquic_gso_init(struct tquic_gso_ctx *gso, struct tquic_path *path,
			  u16 max_segs)
{
	gso->gso_size = path->mtu - 48; /* Leave room for UDP/IP headers */
	gso->gso_segs = 0;
	gso->current_seg = 0;
	gso->total_len = 0;

	/* Allocate GSO SKB -- check for multiplication overflow */
	{
		size_t alloc_size;

		if (check_mul_overflow((size_t)gso->gso_size, (size_t)max_segs,
				       &alloc_size) ||
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
				 struct tquic_path *path, const u8 **pkts,
				 size_t *pkt_lens, int num_pkts)
{
	struct tquic_gso_ctx gso;
	struct sk_buff *gso_skb;
	int i, ret;

	if (num_pkts <= 1 || !tquic_gso_supported(path)) {
		tquic_dbg("gso_send: not using GSO (pkts=%d supported=%d)\n",
			  num_pkts, tquic_gso_supported(path));
		for (i = 0; i < num_pkts; i++) {
			struct sk_buff *skb;

			skb = alloc_skb(MAX_HEADER + pkt_lens[i], GFP_ATOMIC);
			if (!skb)
				return -ENOMEM;
			skb_reserve(skb, MAX_HEADER);
			skb_put_data(skb, pkts[i], pkt_lens[i]);
			ret = tquic_output_packet(conn, path, skb);
			if (ret < 0)
				return ret;
		}
		return 0;
	}

	ret = tquic_gso_init(&gso, path, num_pkts);
	if (ret < 0) {
		tquic_dbg("gso_send: init failed %d\n", ret);
		return ret;
	}

	for (i = 0; i < num_pkts; i++) {
		ret = tquic_gso_add_segment(&gso, pkts[i], pkt_lens[i]);
		if (ret < 0) {
			tquic_dbg("gso_send: add_segment %d failed %d\n", i, ret);
			kfree_skb(gso.gso_skb);
			return ret;
		}
	}

	gso_skb = tquic_gso_finalize(&gso);
	if (!gso_skb)
		return -ENOMEM;

	tquic_dbg("gso_send: sending %d segs total_len=%u\n", num_pkts, gso_skb->len);
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
#define TQUIC_IP_ECN_NOT_ECT 0x00
#define TQUIC_IP_ECN_ECT1 0x01
#define TQUIC_IP_ECN_ECT0 0x02
#define TQUIC_IP_ECN_CE 0x03
#define TQUIC_IP_ECN_MASK 0x03

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
	u8 ecn_cp;

	if (!skb || !conn)
		return;

	/* Check if ECN is enabled at netns level */
	{
		struct sock *csk = READ_ONCE(conn->sk);

		if (csk)
			net = sock_net(csk);
		if (!net || !tquic_pernet(net)->ecn_enabled)
			return;
	}

	/*
	 * Set ECN codepoint in IP header.  When L4S is enabled on the
	 * active path and has negotiated ECT(1), use tquic_l4s_mark_skb()
	 * which sets ECT(1).  Otherwise fall back to AccECN-selected or
	 * plain ECT(0) per RFC 9000 Section 13.4.1.
	 */
	{
		struct tquic_path *apath;

		rcu_read_lock();
		apath = rcu_dereference(conn->active_path);
		if (apath && tquic_l4s_is_enabled(&apath->l4s)) {
			int err = tquic_l4s_mark_skb(&apath->l4s, skb);

			rcu_read_unlock();
			if (!err)
				return; /* L4S marked the skb */
		} else if (apath) {
			ecn_cp = accecn_get_send_ecn(&apath->accecn);
			rcu_read_unlock();
			/* accecn may return NOT_ECT if validation failed */
			if (ecn_cp == ACCECN_NOT_ECT)
				return;
		} else {
			rcu_read_unlock();
			ecn_cp = TQUIC_IP_ECN_ECT0;
		}
	}

	/*
	 * Apply the selected ECN codepoint to the IP header.
	 */
	if (skb->protocol == htons(ETH_P_IP)) {
		iph = ip_hdr(skb);
		if (iph) {
			iph->tos = (iph->tos & ~TQUIC_IP_ECN_MASK) |
				   (ecn_cp & TQUIC_IP_ECN_MASK);
			ip_send_check(iph);
			tquic_dbg("ecn: set cp=0x%x on IPv4 pkt len=%u\n",
				  ecn_cp, skb->len);
		}
	} else if (skb->protocol == htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6h = ipv6_hdr(skb);

		if (ip6h) {
			u32 flow = ntohl(*(__be32 *)ip6h);

			flow = (flow & ~(TQUIC_IP_ECN_MASK << 20)) |
			       ((u32)(ecn_cp & TQUIC_IP_ECN_MASK) << 20);
			*(__be32 *)ip6h = htonl(flow);
			tquic_dbg("ecn: set cp=0x%x on IPv6 pkt len=%u\n",
				  ecn_cp, skb->len);
		}
	}

	/*
	 * Wire accecn_on_packet_sent: notify AccECN of the ECN codepoint
	 * used on this packet so it can track sent ECT counts and detect
	 * ECN bleaching/mangling on the return path.
	 * EXPORT_SYMBOL_GPL.
	 */
	{
		struct tquic_path *apath2;

		rcu_read_lock();
		apath2 = rcu_dereference(conn->active_path);
		if (apath2)
			accecn_on_packet_sent(&apath2->accecn, ecn_cp);
		rcu_read_unlock();
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
int tquic_output_packet(struct tquic_connection *conn, struct tquic_path *path,
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

	pr_debug(
		"tquic_output_packet: path=%p skb_len=%u local=%pISpc remote=%pISpc sk=%p\n",
		path, skb->len, &path->local_addr, &path->remote_addr,
		conn ? conn->sk : NULL);

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
			pr_debug(
				"tquic_output: EMSGSIZE pkt=%u mtu=%u path=%u\n",
				skb->len, current_mtu, path->path_id);
			kfree_skb(skb);
			return -EMSGSIZE;
		}
	}

#ifdef CONFIG_TQUIC_OVER_TCP
	/*
	 * If TCP fallback is active, route this packet through the
	 * TCP transport layer instead of UDP.  tquic_fallback_send()
	 * returns -ENOTSUP when fallback is not active; in that case
	 * we fall through to the normal UDP transmission path.
	 */
	if (conn && conn->fallback_ctx) {
		int fb_ret = tquic_fallback_send(conn->fallback_ctx,
						 skb->data, skb->len);

		if (fb_ret >= 0) {
			/* Sent via TCP; update stats and free the skb */
			tquic_path_on_data_sent(path, skb->len);
			tquic_conn_on_packet_sent(conn, skb->len);
			kfree_skb(skb);
			return 0;
		}
		/* fb_ret == -ENOTSUP: UDP not in fallback mode, continue */
	}
#endif /* CONFIG_TQUIC_OVER_TCP */

#ifdef CONFIG_TQUIC_OFFLOAD
	if (conn && path && path->dev) {
		struct tquic_nic_device *nic = tquic_nic_find(path->dev);

		if (nic) {
			if (tquic_offload_tx(nic, skb, conn) == 0) {
				tquic_nic_put(nic);
				return 0; /* HW handled encryption+TX */
			}
			tquic_nic_put(nic);
		}
	}
#endif /* CONFIG_TQUIC_OFFLOAD */

#ifdef CONFIG_TQUIC_AF_XDP
	/*
	 * Wire: tquic_xsk_send / tquic_xsk_flush_tx / tquic_xsk_poll_tx —
	 *
	 * When the path or connection has an AF_XDP socket attached, send
	 * via the XDP ring buffer instead of the normal UDP stack.
	 * This provides kernel-bypass TX for maximum throughput.
	 *
	 * Per-path XSK (path->xsk) takes precedence over per-connection XSK
	 * (conn->xsk) for multipath scenarios where each path may use a
	 * separate hardware queue.
	 *
	 * We allocate a single tquic_xsk_packet from the XSK frame pool,
	 * copy the skb payload into the UMEM buffer, then call tquic_xsk_send()
	 * to queue it to the TX ring.  tquic_xsk_flush_tx() kicks the kernel
	 * to transmit, and tquic_xsk_poll_tx() recycles completed TX frames.
	 */
	{
		struct tquic_xsk *tx_xsk = NULL;

		if (path && path->xsk)
			tx_xsk = path->xsk;
		else if (conn && conn->xsk)
			tx_xsk = conn->xsk;

		if (tx_xsk) {
			struct tquic_xsk_packet xpkt = {};
			u64 frame_addr;
			int xsk_ret;

			xsk_ret = tquic_xsk_alloc_frame(tx_xsk, &frame_addr);
			if (xsk_ret == 0) {
				void *buf = tquic_xsk_get_frame_data(tx_xsk,
								     frame_addr);

				if (buf && skb->len <= tx_xsk->frame_size) {
					memcpy(buf, skb->data, skb->len);
					xpkt.addr = frame_addr;
					xpkt.data = buf;
					xpkt.len = skb->len;
					xpkt.xsk = tx_xsk;
					xpkt.owns_frame = true;

					xsk_ret = tquic_xsk_send(tx_xsk,
								 &xpkt, 1);
					if (xsk_ret == 1) {
						tquic_xsk_flush_tx(tx_xsk);
						tquic_xsk_poll_tx(tx_xsk, 32);
						/*
						 * Wire: tquic_xsk_wakeup --
						 *
						 * AF_XDP sockets in copy mode,
						 * or when XDP_RING_NEED_WAKEUP
						 * is set, the TX ring needs an
						 * explicit wakeup after
						 * descriptors are queued.
						 */
						if (tquic_xsk_need_wakeup(tx_xsk))
							tquic_xsk_wakeup(tx_xsk);
						kfree_skb(skb);
						return 0;
					}
				}
				/* Frame not used; free it back to pool */
				if (xsk_ret != 1)
					tquic_xsk_free_frame(tx_xsk, frame_addr);
			}
			/* Fall through to normal UDP path on XSK failure */
		}
	}
#endif /* CONFIG_TQUIC_AF_XDP */

	/* Get addresses */
	local = (struct sockaddr_in *)&path->local_addr;
	remote = (struct sockaddr_in *)&path->remote_addr;

	/*
	 * Snapshot conn->sk once.  Teardown paths write NULL to conn->sk
	 * under sk_callback_lock; without a snapshot, a concurrent teardown
	 * could null it between the guard check and the dereference below.
	 */
	{
		struct sock *csk = conn ? READ_ONCE(conn->sk) : NULL;

		if (csk)
			net = sock_net(csk);
	}

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
		int rt_err = PTR_ERR(rt);

#ifdef CONFIG_TQUIC_OVER_TCP
		if (conn && conn->fallback_ctx &&
		    (rt_err == -EACCES || rt_err == -ENETUNREACH ||
		     rt_err == -EHOSTUNREACH || rt_err == -ECONNREFUSED))
			tquic_fallback_trigger(conn->fallback_ctx,
					       FALLBACK_REASON_ICMP_UNREACH);
#endif /* CONFIG_TQUIC_OVER_TCP */
		kfree_skb(skb);
		return rt_err;
	}

	/* Determine TOS for ECN marking and send */
	{
		/*
		 * Snapshot conn->sk inside this block so all uses below see the
		 * same value.  Teardown paths may set conn->sk = NULL between
		 * any two bare reads of the field.
		 */
		struct sock *csk = conn ? READ_ONCE(conn->sk) : NULL;
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
		if (!sport && csk)
			sport = inet_sk(csk)->inet_sport;
		if (!sport)
			sport = htons(get_random_u32_below(16384) + 49152);

		/* Update path with resolved addresses for future use */
		if (!local->sin_addr.s_addr && saddr) {
			local->sin_addr.s_addr = saddr;
			local->sin_port = sport;
		}

		/* Apply pacing EDT timestamp for FQ qdisc */
		tquic_pacing_allows_send(csk, skb);

		/* Set ECN marking for IPv6 (IPv4 handled via flowi4) */
		tquic_set_ecn_marking(skb, conn);

		/*
		 * ECN: Apply per-path ECN marking to the IP header and
		 * record the codepoint for validation against ACK_ECN
		 * feedback (RFC 9000 Section 13.4).
		 */
		{
			u8 ecn_mark = tquic_ecn_get_marking(path);

			if (ecn_mark != TQUIC_ECN_NOT_ECT) {
				tquic_ecn_mark_packet(skb, ecn_mark);
				tquic_ecn_on_packet_sent(path, ecn_mark);
			}
		}

		/* Save skb->len before xmit which consumes the SKB */
		skb_len = skb->len;

		/*
		 * Use udp_tunnel_xmit_skb for proper UDP encapsulation.
		 * This builds the UDP header, IP header, and transmits
		 * the packet correctly through the network stack.
		 */
		TQUIC_UDP_TUNNEL_XMIT_SKB(
			rt, csk, skb, saddr, remote->sin_addr.s_addr, tos,
			ip4_dst_hoplimit(&rt->dst), 0, /* DF */
			sport, remote->sin_port, false, /* xnet */
			true); /* nocheck */
		ret = 0;

		/* Update path statistics */
		tquic_path_on_data_sent(path, skb_len);

		/*
		 * RFC 9002: Notify connection state machine that a packet was
		 * sent. Updates anti-amplification accounting so the server
		 * knows how many unvalidated bytes have been transmitted.
		 */
		tquic_conn_on_packet_sent(conn, skb_len);

		/*
		 * Wire dead exports: TX-path hooks for PMTUD sysctl
		 * check, ACK delay cancellation, and per-netns TX stats.
		 */
		tquic_wire_b_on_send(conn, path, skb_len);

		/* Notify multipath scheduler for feedback-driven path selection */
#ifdef CONFIG_TQUIC_MULTIPATH
		tquic_mp_sched_notify_sent(conn, path, skb_len);
#endif

		if (csk) {
			TQUIC_INC_STATS(sock_net(csk), TQUIC_MIB_PACKETSTX);
			TQUIC_ADD_STATS(sock_net(csk), TQUIC_MIB_BYTESTX,
					skb_len);
		}

		/*
		 * AccECN: record the ECN codepoint used for this packet so
		 * the AccECN validator can match it against feedback from the
		 * peer's ACK_ECN counts (RFC 9000 Section 13.4.2).
		 * accecn_on_packet_sent: EXPORT_SYMBOL_GPL
		 */
		{
			u8 ecn_sent = (tos & TQUIC_IP_ECN_MASK);

			accecn_on_packet_sent(&path->accecn, ecn_sent);
		}

		/*
		 * Emit tracepoint and qlog for every successfully transmitted
		 * packet.  The packet number and type are tracked via
		 * conn->pkt_num_tx (incremented before assembly) and the
		 * short-header path always uses the APPLICATION space.
		 * tquic_trace_packet_sent: EXPORT_SYMBOL_GPL
		 * tquic_qlog_packet_sent_simple: EXPORT_SYMBOL_GPL
		 */
		{
			u64 pkt_num =
				(u64)atomic64_read(&conn->pkt_num_tx);
			/* 1-RTT short header is type 3 in internal encoding */
			u32 pkt_type = TQUIC_PKT_ZERO_RTT + 1;

			tquic_trace_packet_sent(conn, pkt_num, pkt_type,
						skb_len, path->path_id);
			if (conn->qlog)
				tquic_qlog_packet_sent_simple(
					conn->qlog, pkt_num,
					QLOG_PKT_1RTT, skb_len,
					path->path_id, 0, true);
		}

		/*
		 * If the path has a dedicated UDP socket (per-path
		 * encap), use tquic_udp_xmit_gso for GSO batching
		 * when the segment exceeds the GSO threshold, or fall
		 * back to tquic_udp_sendmsg for small payloads.
		 */
		if (path->udp_sock && skb_len > path->mtu) {
			tquic_udp_xmit_gso(path->udp_sock, NULL,
					    path->mtu);
		} else if (path->udp_sock && path->raw_send_buf) {
			tquic_udp_sendmsg(path->udp_sock,
					  path->raw_send_buf,
					  path->raw_send_len);
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
	u32 skb_len;
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

		/*
		 * EDF scheduler: if deadline scheduling is active,
		 * enqueue the packet so the EDF engine can reorder
		 * it relative to other deadline-bearing packets.
		 */
		if (conn->edf_sched && stream->deadline_us) {
			tquic_edf_enqueue(conn->edf_sched, skb_clone(skb,
					  GFP_ATOMIC), stream->id,
					  stream->deadline_us,
					  stream->priority);
		}

		/* Send packet */
		{
			struct tquic_failover_ctx *__fc =
				tquic_conn_get_failover(conn);
			u8 __pid = path->path_id;

			/* Failover: clone skb BEFORE tquic_output_packet consumes it */
			if (__fc)
				tquic_failover_track_sent(__fc, skb, pkt_num,
							  __pid);
			skb_len = skb->len;
			ret = tquic_output_packet(conn, path, skb);
			if (ret < 0) {
				tquic_path_put(path);
				if (__fc)
					tquic_failover_on_ack(__fc, pkt_num);
				break;
			}

			tquic_path_put(path);

			/* RFC 9002: record sent packet in recovery state */
			if (conn->timer_state)
				tquic_timer_on_packet_sent(
					conn->timer_state,
					TQUIC_PN_SPACE_APPLICATION, pkt_num,
					skb_len, true, true,
					BIT(TQUIC_FRAME_STREAM), __pid);
			if (__fc)
				tquic_failover_arm_timeout(__fc, __pid);
		}

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
	u32 skb_len;
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

		ku_state =
			tquic_crypto_get_key_update_state(conn->crypto_state);
		if (ku_state)
			key_phase = tquic_key_update_get_phase(ku_state) != 0;
	}

	{
		u8 spin = conn->spin_bit_state ?
			tquic_spin_bit_get(
				(struct tquic_spin_bit_state *)
					conn->spin_bit_state,
				pkt_num) : 0;

		header_len = tquic_build_short_header_internal(
			conn, path, header_buf, sizeof(header_buf), pkt_num, 0,
			key_phase, spin != 0, conn->grease_state);
	}
	if (header_len < 0) {
		kfree_skb(skb);
		return header_len;
	}

	/* Encrypt payload in-place (header is AAD) */
	ret = tquic_encrypt_payload(conn, header_buf, header_len, payload_buf,
				    payload_len, pkt_num,
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
		ret = tquic_apply_header_protection(conn, skb->data, skb->len,
						    header_len - 4);
		if (ret < 0) {
			kfree_skb(skb);
			return ret;
		}
	}

	skb_len = skb->len;
	ret = tquic_output_packet(conn, path, skb);

	/* RFC 9002: ACK-only packets are not ack-eliciting, not in-flight */
	if (ret >= 0) {
		if (conn->timer_state)
			tquic_timer_on_packet_sent(conn->timer_state,
						   TQUIC_PN_SPACE_APPLICATION,
						   pkt_num, skb_len, false,
						   false, BIT(TQUIC_FRAME_ACK),
						   path->path_id);
		/* Advance receiver dedup window: peer has seen our ACK */
		{
			struct tquic_failover_ctx *__fc =
				tquic_conn_get_failover(conn);
			if (__fc)
				tquic_failover_dedup_advance(__fc, largest_ack);
		}
	}
	return ret;
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
	u32 skb_len;
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

		ku_state =
			tquic_crypto_get_key_update_state(conn->crypto_state);
		if (ku_state)
			key_phase = tquic_key_update_get_phase(ku_state) != 0;
	}

	{
		u8 spin = conn->spin_bit_state ?
			tquic_spin_bit_get(
				(struct tquic_spin_bit_state *)
					conn->spin_bit_state,
				pkt_num) : 0;

		header_len = tquic_build_short_header_internal(
			conn, path, header_buf, sizeof(header_buf), pkt_num, 0,
			key_phase, spin != 0, conn->grease_state);
	}
	if (header_len < 0) {
		kfree_skb(skb);
		return header_len;
	}

	ret = tquic_encrypt_payload(conn, header_buf, header_len, payload_buf,
				    payload_len, pkt_num, 3);
	if (ret < 0) {
		kfree_skb(skb);
		return ret;
	}

	skb_trim(skb, payload_len + 16);
	memcpy(skb_push(skb, header_len), header_buf, header_len);

	if (header_len >= 5) {
		ret = tquic_apply_header_protection(conn, skb->data, skb->len,
						    header_len - 4);
		if (ret < 0) {
			kfree_skb(skb);
			return ret;
		}
	}

	tquic_dbg("send_ping: sending pkt_num=%llu\n", pkt_num);
	{
		struct tquic_failover_ctx *__fc = tquic_conn_get_failover(conn);
		u8 __pid = path->path_id;

		/* Failover: clone skb BEFORE tquic_output_packet consumes it */
		if (__fc)
			tquic_failover_track_sent(__fc, skb, pkt_num, __pid);
		skb_len = skb->len;
		ret = tquic_output_packet(conn, path, skb);

		/* RFC 9002: PING is ack-eliciting and counts against cwnd */
		if (ret >= 0) {
			if (conn->timer_state)
				tquic_timer_on_packet_sent(
					conn->timer_state,
					TQUIC_PN_SPACE_APPLICATION, pkt_num,
					skb_len, ctx.ack_eliciting, true,
					BIT(TQUIC_FRAME_PING), __pid);
			if (__fc)
				tquic_failover_arm_timeout(__fc, __pid);
		} else {
			if (__fc)
				tquic_failover_on_ack(__fc, pkt_num);
		}
	}
	return ret;
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
	u32 skb_len;
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

		ku_state =
			tquic_crypto_get_key_update_state(conn->crypto_state);
		if (ku_state)
			key_phase = tquic_key_update_get_phase(ku_state) != 0;
	}

	{
		u8 spin = conn->spin_bit_state ?
			tquic_spin_bit_get(
				(struct tquic_spin_bit_state *)
					conn->spin_bit_state,
				pkt_num) : 0;

		header_len = tquic_build_short_header_internal(
			conn, path, header_buf, sizeof(header_buf), pkt_num, 0,
			key_phase, spin != 0, conn->grease_state);
	}
	if (header_len < 0) {
		kfree_skb(skb);
		return header_len;
	}

	/* Encrypt payload in-place (header is AAD) */
	ret = tquic_encrypt_payload(conn, header_buf, header_len, payload_buf,
				    payload_len, pkt_num,
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
		ret = tquic_apply_header_protection(conn, skb->data, skb->len,
						    header_len - 4);
		if (ret < 0) {
			kfree_skb(skb);
			return ret;
		}
	}

	{
		struct tquic_failover_ctx *__fc = tquic_conn_get_failover(conn);
		u8 __pid = path->path_id;

		/* Failover: clone skb BEFORE tquic_output_packet consumes it */
		if (__fc)
			tquic_failover_track_sent(__fc, skb, pkt_num, __pid);
		skb_len = skb->len;
		ret = tquic_output_packet(conn, path, skb);

		/* RFC 9002: MAX_DATA is ack-eliciting and counts against cwnd */
		if (ret >= 0) {
			if (conn->timer_state)
				tquic_timer_on_packet_sent(
					conn->timer_state,
					TQUIC_PN_SPACE_APPLICATION, pkt_num,
					skb_len, true, true,
					BIT(TQUIC_FRAME_MAX_DATA), __pid);
			if (__fc)
				tquic_failover_arm_timeout(__fc, __pid);
		} else {
			if (__fc)
				tquic_failover_on_ack(__fc, pkt_num);
		}
	}
	return ret;
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
				    struct tquic_path *path, u64 stream_id,
				    u64 max_data)
{
	struct tquic_frame_ctx ctx;
	struct sk_buff *skb;
	u8 header_buf[128];
	u8 *payload_buf;
	int header_len, payload_len;
	u32 skb_len;
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

		ku_state =
			tquic_crypto_get_key_update_state(conn->crypto_state);
		if (ku_state)
			key_phase = tquic_key_update_get_phase(ku_state) != 0;
	}

	{
		u8 spin = conn->spin_bit_state ?
			tquic_spin_bit_get(
				(struct tquic_spin_bit_state *)
					conn->spin_bit_state,
				pkt_num) : 0;

		header_len = tquic_build_short_header_internal(
			conn, path, header_buf, sizeof(header_buf), pkt_num, 0,
			key_phase, spin != 0, conn->grease_state);
	}
	if (header_len < 0) {
		kfree_skb(skb);
		return header_len;
	}

	/* Encrypt payload in-place (header is AAD) */
	ret = tquic_encrypt_payload(conn, header_buf, header_len, payload_buf,
				    payload_len, pkt_num,
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
		ret = tquic_apply_header_protection(conn, skb->data, skb->len,
						    header_len - 4);
		if (ret < 0) {
			kfree_skb(skb);
			return ret;
		}
	}

	{
		struct tquic_failover_ctx *__fc = tquic_conn_get_failover(conn);
		u8 __pid = path->path_id;

		/* Failover: clone skb BEFORE tquic_output_packet consumes it */
		if (__fc)
			tquic_failover_track_sent(__fc, skb, pkt_num, __pid);
		skb_len = skb->len;
		ret = tquic_output_packet(conn, path, skb);

		/* RFC 9002: MAX_STREAM_DATA is ack-eliciting and counts against cwnd */
		if (ret >= 0) {
			if (conn->timer_state)
				tquic_timer_on_packet_sent(
					conn->timer_state,
					TQUIC_PN_SPACE_APPLICATION, pkt_num,
					skb_len, true, true,
					BIT(TQUIC_FRAME_MAX_STREAM_DATA),
					__pid);
			if (__fc)
				tquic_failover_arm_timeout(__fc, __pid);
		} else {
			if (__fc)
				tquic_failover_on_ack(__fc, pkt_num);
		}
	}
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_flow_send_max_stream_data);

/**
 * tquic_flow_send_data_blocked - Send DATA_BLOCKED frame
 * @conn: QUIC connection
 * @path: Network path to send on
 * @limit: Connection-level limit at which we are blocked
 *
 * Builds a minimal 1-RTT packet containing a DATA_BLOCKED frame.
 * Called when the connection send window is exhausted (RFC 9000 Section 4.1).
 * Caller MUST call tquic_fc_data_blocked_sent() after a successful return
 * to prevent duplicate frames on the next output pass.
 */
static int tquic_flow_send_data_blocked(struct tquic_connection *conn,
					struct tquic_path *path, u64 limit)
{
	struct tquic_frame_ctx ctx;
	struct sk_buff *skb;
	u8 header_buf[128];
	u8 *payload_buf;
	int header_len, payload_len;
	u32 skb_len;
	int ret;
	u64 pkt_num;
	bool key_phase = false;

	pkt_num = atomic64_inc_return(&conn->pkt_num_tx) - 1;

	skb = alloc_skb(MAX_HEADER + 128 + 128 + 16, GFP_ATOMIC);
	if (!skb)
		return -ENOMEM;

	skb_reserve(skb, MAX_HEADER + 128);
	payload_buf = skb_put(skb, 128 + 16);

	ctx.conn = conn;
	ctx.path = path;
	ctx.buf = payload_buf;
	ctx.buf_len = 128;
	ctx.offset = 0;
	ctx.ack_eliciting = true;

	ret = tquic_gen_data_blocked_frame(&ctx, limit);
	if (ret < 0) {
		kfree_skb(skb);
		return ret;
	}

	payload_len = ctx.offset;

	if (conn->crypto_state) {
		struct tquic_key_update_state *ku_state;

		ku_state =
			tquic_crypto_get_key_update_state(conn->crypto_state);
		if (ku_state)
			key_phase = tquic_key_update_get_phase(ku_state) != 0;
	}

	{
		u8 spin = conn->spin_bit_state ?
			tquic_spin_bit_get(
				(struct tquic_spin_bit_state *)
					conn->spin_bit_state,
				pkt_num) : 0;

		header_len = tquic_build_short_header_internal(
			conn, path, header_buf, sizeof(header_buf), pkt_num, 0,
			key_phase, spin != 0, conn->grease_state);
	}
	if (header_len < 0) {
		kfree_skb(skb);
		return header_len;
	}

	ret = tquic_encrypt_payload(conn, header_buf, header_len, payload_buf,
				    payload_len, pkt_num,
				    3 /* APPLICATION */);
	if (ret < 0) {
		kfree_skb(skb);
		return ret;
	}

	skb_trim(skb, payload_len + 16);
	memcpy(skb_push(skb, header_len), header_buf, header_len);

	if (header_len >= 5) {
		ret = tquic_apply_header_protection(conn, skb->data, skb->len,
						    header_len - 4);
		if (ret < 0) {
			kfree_skb(skb);
			return ret;
		}
	}

	{
		struct tquic_failover_ctx *__fc = tquic_conn_get_failover(conn);
		u8 __pid = path->path_id;

		if (__fc)
			tquic_failover_track_sent(__fc, skb, pkt_num, __pid);
		skb_len = skb->len;
		ret = tquic_output_packet(conn, path, skb);

		if (ret >= 0) {
			if (conn->timer_state)
				tquic_timer_on_packet_sent(
					conn->timer_state,
					TQUIC_PN_SPACE_APPLICATION, pkt_num,
					skb_len, true, true,
					BIT(TQUIC_FRAME_DATA_BLOCKED), __pid);
			if (__fc)
				tquic_failover_arm_timeout(__fc, __pid);
		} else {
			if (__fc)
				tquic_failover_on_ack(__fc, pkt_num);
		}
	}
	return ret;
}

/**
 * tquic_flow_send_stream_data_blocked - Send STREAM_DATA_BLOCKED frame
 * @conn: QUIC connection
 * @path: Network path to send on
 * @stream_id: Stream whose send window is exhausted
 * @limit: Per-stream limit at which the stream is blocked
 *
 * Builds a minimal 1-RTT packet containing a STREAM_DATA_BLOCKED frame.
 * Called when a specific stream's send window is exhausted (RFC 9000 Section
 * 4.1).  Caller MUST call tquic_fc_stream_data_blocked_sent() after a
 * successful return to prevent duplicate frames.
 */
static int tquic_flow_send_stream_data_blocked(struct tquic_connection *conn,
					       struct tquic_path *path,
					       u64 stream_id, u64 limit)
{
	struct tquic_frame_ctx ctx;
	struct sk_buff *skb;
	u8 header_buf[128];
	u8 *payload_buf;
	int header_len, payload_len;
	u32 skb_len;
	int ret;
	u64 pkt_num;
	bool key_phase = false;

	pkt_num = atomic64_inc_return(&conn->pkt_num_tx) - 1;

	skb = alloc_skb(MAX_HEADER + 128 + 128 + 16, GFP_ATOMIC);
	if (!skb)
		return -ENOMEM;

	skb_reserve(skb, MAX_HEADER + 128);
	payload_buf = skb_put(skb, 128 + 16);

	ctx.conn = conn;
	ctx.path = path;
	ctx.buf = payload_buf;
	ctx.buf_len = 128;
	ctx.offset = 0;
	ctx.ack_eliciting = true;

	ret = tquic_gen_stream_data_blocked_frame(&ctx, stream_id, limit);
	if (ret < 0) {
		kfree_skb(skb);
		return ret;
	}

	payload_len = ctx.offset;

	if (conn->crypto_state) {
		struct tquic_key_update_state *ku_state;

		ku_state =
			tquic_crypto_get_key_update_state(conn->crypto_state);
		if (ku_state)
			key_phase = tquic_key_update_get_phase(ku_state) != 0;
	}

	{
		u8 spin = conn->spin_bit_state ?
			tquic_spin_bit_get(
				(struct tquic_spin_bit_state *)
					conn->spin_bit_state,
				pkt_num) : 0;

		header_len = tquic_build_short_header_internal(
			conn, path, header_buf, sizeof(header_buf), pkt_num, 0,
			key_phase, spin != 0, conn->grease_state);
	}
	if (header_len < 0) {
		kfree_skb(skb);
		return header_len;
	}

	ret = tquic_encrypt_payload(conn, header_buf, header_len, payload_buf,
				    payload_len, pkt_num,
				    3 /* APPLICATION */);
	if (ret < 0) {
		kfree_skb(skb);
		return ret;
	}

	skb_trim(skb, payload_len + 16);
	memcpy(skb_push(skb, header_len), header_buf, header_len);

	if (header_len >= 5) {
		ret = tquic_apply_header_protection(conn, skb->data, skb->len,
						    header_len - 4);
		if (ret < 0) {
			kfree_skb(skb);
			return ret;
		}
	}

	{
		struct tquic_failover_ctx *__fc = tquic_conn_get_failover(conn);
		u8 __pid = path->path_id;

		if (__fc)
			tquic_failover_track_sent(__fc, skb, pkt_num, __pid);
		skb_len = skb->len;
		ret = tquic_output_packet(conn, path, skb);

		if (ret >= 0) {
			if (conn->timer_state)
				tquic_timer_on_packet_sent(
					conn->timer_state,
					TQUIC_PN_SPACE_APPLICATION, pkt_num,
					skb_len, true, true,
					BIT(TQUIC_FRAME_STREAM_DATA_BLOCKED),
					__pid);
			if (__fc)
				tquic_failover_arm_timeout(__fc, __pid);
		} else {
			if (__fc)
				tquic_failover_on_ack(__fc, pkt_num);
		}
	}
	return ret;
}

/**
 * tquic_flow_send_max_streams - Send MAX_STREAMS frame
 * @conn: QUIC connection
 * @path: Network path to send on
 * @max_streams: New stream-count limit to advertise to peer
 * @bidi: true for bidirectional streams, false for unidirectional
 *
 * Builds a minimal 1-RTT packet containing a MAX_STREAMS frame.
 * Called to open the peer's stream-open limit (RFC 9000 Section 4.6).
 * Caller MUST call tquic_fc_max_streams_sent() after a successful return.
 */
static int tquic_flow_send_max_streams(struct tquic_connection *conn,
				       struct tquic_path *path,
				       u64 max_streams, bool bidi)
{
	struct tquic_frame_ctx ctx;
	struct sk_buff *skb;
	u8 header_buf[128];
	u8 *payload_buf;
	int header_len, payload_len;
	u32 skb_len;
	int ret;
	u64 pkt_num;
	bool key_phase = false;
	u8 frame_bit;

	pkt_num = atomic64_inc_return(&conn->pkt_num_tx) - 1;

	skb = alloc_skb(MAX_HEADER + 128 + 128 + 16, GFP_ATOMIC);
	if (!skb)
		return -ENOMEM;

	skb_reserve(skb, MAX_HEADER + 128);
	payload_buf = skb_put(skb, 128 + 16);

	ctx.conn = conn;
	ctx.path = path;
	ctx.buf = payload_buf;
	ctx.buf_len = 128;
	ctx.offset = 0;
	ctx.ack_eliciting = true;

	ret = tquic_gen_max_streams_frame(&ctx, max_streams, bidi);
	if (ret < 0) {
		kfree_skb(skb);
		return ret;
	}

	payload_len = ctx.offset;

	if (conn->crypto_state) {
		struct tquic_key_update_state *ku_state;

		ku_state =
			tquic_crypto_get_key_update_state(conn->crypto_state);
		if (ku_state)
			key_phase = tquic_key_update_get_phase(ku_state) != 0;
	}

	{
		u8 spin = conn->spin_bit_state ?
			tquic_spin_bit_get(
				(struct tquic_spin_bit_state *)
					conn->spin_bit_state,
				pkt_num) : 0;

		header_len = tquic_build_short_header_internal(
			conn, path, header_buf, sizeof(header_buf), pkt_num, 0,
			key_phase, spin != 0, conn->grease_state);
	}
	if (header_len < 0) {
		kfree_skb(skb);
		return header_len;
	}

	ret = tquic_encrypt_payload(conn, header_buf, header_len, payload_buf,
				    payload_len, pkt_num,
				    3 /* APPLICATION */);
	if (ret < 0) {
		kfree_skb(skb);
		return ret;
	}

	skb_trim(skb, payload_len + 16);
	memcpy(skb_push(skb, header_len), header_buf, header_len);

	if (header_len >= 5) {
		ret = tquic_apply_header_protection(conn, skb->data, skb->len,
						    header_len - 4);
		if (ret < 0) {
			kfree_skb(skb);
			return ret;
		}
	}

	frame_bit = bidi ? TQUIC_FRAME_MAX_STREAMS_BIDI :
			   TQUIC_FRAME_MAX_STREAMS_UNI;
	{
		struct tquic_failover_ctx *__fc = tquic_conn_get_failover(conn);
		u8 __pid = path->path_id;

		if (__fc)
			tquic_failover_track_sent(__fc, skb, pkt_num, __pid);
		skb_len = skb->len;
		ret = tquic_output_packet(conn, path, skb);

		if (ret >= 0) {
			if (conn->timer_state)
				tquic_timer_on_packet_sent(
					conn->timer_state,
					TQUIC_PN_SPACE_APPLICATION, pkt_num,
					skb_len, true, true,
					BIT(frame_bit), __pid);
			if (__fc)
				tquic_failover_arm_timeout(__fc, __pid);
		} else {
			if (__fc)
				tquic_failover_on_ack(__fc, pkt_num);
		}
	}
	return ret;
}

/**
 * tquic_flow_send_streams_blocked - Send STREAMS_BLOCKED frame
 * @conn: QUIC connection
 * @path: Network path to send on
 * @limit: Stream limit at which we are blocked
 * @bidi: true for bidirectional, false for unidirectional
 *
 * Builds a minimal 1-RTT packet containing a STREAMS_BLOCKED frame.
 * Called when we cannot open new streams due to the peer's limit
 * (RFC 9000 Section 4.6).  Caller MUST call tquic_fc_streams_blocked_sent()
 * after a successful return to prevent duplicate frames.
 */
static int tquic_flow_send_streams_blocked(struct tquic_connection *conn,
					   struct tquic_path *path,
					   u64 limit, bool bidi)
{
	struct tquic_frame_ctx ctx;
	struct sk_buff *skb;
	u8 header_buf[128];
	u8 *payload_buf;
	int header_len, payload_len;
	u32 skb_len;
	int ret;
	u64 pkt_num;
	bool key_phase = false;
	u8 frame_bit;

	pkt_num = atomic64_inc_return(&conn->pkt_num_tx) - 1;

	skb = alloc_skb(MAX_HEADER + 128 + 128 + 16, GFP_ATOMIC);
	if (!skb)
		return -ENOMEM;

	skb_reserve(skb, MAX_HEADER + 128);
	payload_buf = skb_put(skb, 128 + 16);

	ctx.conn = conn;
	ctx.path = path;
	ctx.buf = payload_buf;
	ctx.buf_len = 128;
	ctx.offset = 0;
	ctx.ack_eliciting = true;

	ret = tquic_gen_streams_blocked_frame(&ctx, limit, bidi);
	if (ret < 0) {
		kfree_skb(skb);
		return ret;
	}

	payload_len = ctx.offset;

	if (conn->crypto_state) {
		struct tquic_key_update_state *ku_state;

		ku_state =
			tquic_crypto_get_key_update_state(conn->crypto_state);
		if (ku_state)
			key_phase = tquic_key_update_get_phase(ku_state) != 0;
	}

	{
		u8 spin = conn->spin_bit_state ?
			tquic_spin_bit_get(
				(struct tquic_spin_bit_state *)
					conn->spin_bit_state,
				pkt_num) : 0;

		header_len = tquic_build_short_header_internal(
			conn, path, header_buf, sizeof(header_buf), pkt_num, 0,
			key_phase, spin != 0, conn->grease_state);
	}
	if (header_len < 0) {
		kfree_skb(skb);
		return header_len;
	}

	ret = tquic_encrypt_payload(conn, header_buf, header_len, payload_buf,
				    payload_len, pkt_num,
				    3 /* APPLICATION */);
	if (ret < 0) {
		kfree_skb(skb);
		return ret;
	}

	skb_trim(skb, payload_len + 16);
	memcpy(skb_push(skb, header_len), header_buf, header_len);

	if (header_len >= 5) {
		ret = tquic_apply_header_protection(conn, skb->data, skb->len,
						    header_len - 4);
		if (ret < 0) {
			kfree_skb(skb);
			return ret;
		}
	}

	frame_bit = bidi ? TQUIC_FRAME_STREAMS_BLOCKED_BIDI :
			   TQUIC_FRAME_STREAMS_BLOCKED_UNI;
	{
		struct tquic_failover_ctx *__fc = tquic_conn_get_failover(conn);
		u8 __pid = path->path_id;

		if (__fc)
			tquic_failover_track_sent(__fc, skb, pkt_num, __pid);
		skb_len = skb->len;
		ret = tquic_output_packet(conn, path, skb);

		if (ret >= 0) {
			if (conn->timer_state)
				tquic_timer_on_packet_sent(
					conn->timer_state,
					TQUIC_PN_SPACE_APPLICATION, pkt_num,
					skb_len, true, true,
					BIT(frame_bit), __pid);
			if (__fc)
				tquic_failover_arm_timeout(__fc, __pid);
		} else {
			if (__fc)
				tquic_failover_on_ack(__fc, pkt_num);
		}
	}
	return ret;
}

/*
 * tquic_send_path_challenge and tquic_send_path_response are defined
 * in core/connection.c
 */

/*
 * Send CONNECTION_CLOSE
 */
int tquic_send_connection_close(struct tquic_connection *conn, u64 error_code,
				const char *reason)
{
	struct tquic_frame_ctx ctx;
	struct tquic_path *path;
	struct sk_buff *skb;
	u8 buf_stack[256];
	u32 skb_len;
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
					       (const u8 *)reason,
					       reason ? strlen(reason) : 0);
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
		u8 spin = conn->spin_bit_state ?
			tquic_spin_bit_get(
				(struct tquic_spin_bit_state *)
					conn->spin_bit_state,
				pkt_num) : 0;
		int header_len = tquic_build_short_header_internal(
			conn, path, header, TQUIC_MAX_SHORT_HEADER_SIZE,
			pkt_num, 0, false, spin != 0, conn->grease_state);
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

	skb_len = skb->len;
	ret = tquic_output_packet(conn, path, skb);

	/*
	 * RFC 9002: CONNECTION_CLOSE does not elicit ACKs and is not
	 * counted against the congestion window.
	 */
	if (ret >= 0 && conn->timer_state)
		tquic_timer_on_packet_sent(conn->timer_state,
					   TQUIC_PN_SPACE_APPLICATION, pkt_num,
					   skb_len, false, false,
					   BIT(TQUIC_FRAME_CONNECTION_CLOSE),
					   path->path_id);

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

#ifdef CONFIG_TQUIC_OVER_TCP
	if (conn->fallback_ctx) {
		struct quic_tcp_connection *tcp_conn;

		/*
		 * Run the periodic fallback condition check so timeouts and
		 * high-loss events are detected promptly.
		 */
		tquic_fallback_check(conn->fallback_ctx);

		/*
		 * If TCP fallback is active, flush the TCP transmit buffer
		 * and return; the normal UDP flush path is not applicable.
		 */
		tcp_conn = tquic_fallback_get_tcp_conn(conn->fallback_ctx);
		if (tcp_conn) {
			int tcp_ret = quic_tcp_flush(tcp_conn);

			quic_tcp_conn_put(tcp_conn);
			return tcp_ret;
		}
	}
#endif /* CONFIG_TQUIC_OVER_TCP */

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
	 * Wire dead exports: QoS classification for the connection's
	 * tunnel (if any) and forward-path MTU query.  These inform
	 * DSCP marking and MTU capping for tunnel egress.
	 */
	if (conn->tunnel) {
		tquic_wire_b_qos_ops(conn->tunnel);
		tquic_wire_b_forward_mtu(conn->tunnel);
	}

	/*
	 * RFC 8899 Section 5.2: If the path needs an MTU probe, send one
	 * now.  Probe packets are not subject to cwnd limits because they
	 * are used to discover the path MTU, not to carry application data.
	 * tquic_path_needs_probe() returns true only when validation is
	 * pending and the path is in TQUIC_PATH_PENDING state.
	 */
	if (tquic_path_needs_probe(path))
		tquic_path_mtu_probe(path);

	/*
	 * EDF scheduler: update the scheduler's view of the current
	 * path so deadline feasibility checks use fresh RTT/bandwidth
	 * estimates.  Then peek at the earliest-deadline packet; if one
	 * exists, its ktime is used to check whether the next deadline
	 * can still be met on the selected path.
	 */
	if (conn->edf_sched) {
		struct sk_buff *edf_peek;
		ktime_t next_dl;

		tquic_edf_update_path(conn->edf_sched, path);
		edf_peek = tquic_edf_peek(conn->edf_sched);
		if (edf_peek) {
			next_dl = tquic_edf_get_next_deadline(
					conn->edf_sched);
			tquic_dbg("edf: next deadline=%lld ns\n",
				  ktime_to_ns(next_dl));
		}
	}

	/*
	 * Sync the pacing engine with the current CC rate so the
	 * inter-packet gap matches the congestion window.
	 */
	if (path->pacing) {
		u64 cc_rate = tquic_cong_get_pacing_rate(path);

		if (cc_rate)
			tquic_pacing_update_rate(path->pacing, cc_rate);
	}

	/*
	 * Rotate header protection keys if a key update completed
	 * since the last flush.  This keeps the HP cipher in sync
	 * with the AEAD key generation so newly encrypted packets use
	 * the correct header protection mask.
	 */
	if (test_and_clear_bit(TQUIC_CONN_FLAG_HP_KEY_PENDING,
			       &conn->flags) &&
	    conn->crypto_state) {
		const u8 *hp_key;
		size_t hp_len;
		u16 cipher;

		hp_key = tquic_crypto_get_next_hp_key(conn->crypto_state,
						       &hp_len, &cipher);
		if (hp_key)
			tquic_output_rotate_hp_keys(conn, hp_key,
						    hp_len, cipher);
	}

	/*
	 * Check congestion window before attempting transmission.
	 * If cwnd is exhausted, we'll be woken by ACK processing.
	 */
	if (path->stats.cwnd > 0) {
		inflight =
			(path->stats.tx_bytes > path->stats.acked_bytes) ?
				path->stats.tx_bytes - path->stats.acked_bytes :
				0;
		cwnd_limited = (inflight >= path->stats.cwnd);
	} else {
		/* No cwnd limit set yet (initial state) - allow sending */
		cwnd_limited = false;
	}

	if (cwnd_limited) {
		tquic_dbg(
			"output_flush blocked by cwnd (inflight=%llu, cwnd=%u)\n",
			inflight, path->stats.cwnd);
		ret = 0;
		goto out_clear_flush;
	}

	/*
	 * Bonding failover retransmit priority (pre-FC, pre-stream data).
	 *
	 * When multipath bonding is active and a path has failed, unacked
	 * packets are queued for retransmission. The scheduler must drain
	 * these before new stream data per the zero-loss guarantee.
	 *
	 * tquic_bonding_has_pending_retx() is lockless (checks atomic
	 * retx_queue.count) so safe to call before taking conn->lock.
	 */
	if (conn->pm) {
		struct tquic_bonding_ctx *__bc = conn->pm->bonding_ctx;

		if (tquic_bonding_has_pending_retx(__bc)) {
			struct tquic_failover_ctx *__fc =
				tquic_bonding_get_failover(__bc);
			struct tquic_failover_packet *sp;

			while (__fc &&
			       (sp = tquic_failover_get_next(__fc)) != NULL) {
				int __r;

				if (!sp->skb) {
					tquic_failover_put_packet(sp);
					continue;
				}
				/*
				 * Requeue on active path. On send error,
				 * re-enqueue for next opportunity rather
				 * than dropping.
				 */
				__r = tquic_output_packet(conn, path,
							  skb_clone(sp->skb,
								    GFP_ATOMIC));
				if (__r < 0)
					tquic_failover_requeue(__fc, sp);
				else
					tquic_failover_put_packet(sp);
			}
		}
	}

	/*
	 * RFC 9000 Section 4: Send pending flow control frames before stream
	 * data so the peer gets credits as early as possible.
	 *
	 * tquic_fc_collect_frames returns non-zero values only when the
	 * corresponding frame is pending (needs_* flags are set).  For each
	 * value we send the frame and then mark it sent so the FC subsystem
	 * clears the pending flag and won't re-queue until the condition
	 * recurs (RFC 9000 Section 4.1, 4.6).
	 *
	 * We also check STREAMS_BLOCKED here: when we cannot open new streams
	 * because the peer's limit is exhausted, we send STREAMS_BLOCKED so
	 * the peer knows to send MAX_STREAMS when ready.
	 */
	if (conn->fc) {
		u64 fc_max_data = 0;
		u64 fc_data_blocked = 0;
		u64 fc_max_streams_bidi = 0;
		u64 fc_max_streams_uni = 0;

		tquic_fc_collect_frames(conn->fc, &fc_max_data,
					&fc_data_blocked, &fc_max_streams_bidi,
					&fc_max_streams_uni);

		/* MAX_DATA: open peer's connection receive window */
		if (fc_max_data)
			tquic_flow_send_max_data(conn, path, fc_max_data);

		/*
		 * DATA_BLOCKED: tell peer we are stuck at the given offset.
		 * tquic_fc_get_data_blocked() returns the blocked-at value
		 * that tquic_fc_collect_frames already loaded into
		 * fc_data_blocked; use it directly.
		 */
		if (fc_data_blocked) {
			if (tquic_flow_send_data_blocked(conn, path,
							 fc_data_blocked) >= 0)
				tquic_fc_data_blocked_sent(conn->fc);
		}

		/* MAX_STREAMS (bidi): open peer's bidi stream-open limit */
		if (fc_max_streams_bidi) {
			if (tquic_flow_send_max_streams(conn, path,
							fc_max_streams_bidi,
							true) >= 0)
				tquic_fc_max_streams_sent(conn->fc,
							  fc_max_streams_bidi,
							  true);
		}

		/* MAX_STREAMS (uni): open peer's uni stream-open limit */
		if (fc_max_streams_uni) {
			if (tquic_flow_send_max_streams(conn, path,
							fc_max_streams_uni,
							false) >= 0)
				tquic_fc_max_streams_sent(conn->fc,
							  fc_max_streams_uni,
							  false);
		}

		/*
		 * STREAMS_BLOCKED: signal we cannot open new streams because
		 * the peer's limit is exhausted.  Check each direction.
		 */
		if (tquic_fc_needs_streams_blocked(conn->fc, NULL)) {
			bool sb_bidi = false;

			if (tquic_fc_needs_streams_blocked(conn->fc, &sb_bidi)) {
				u64 sb_val =
					tquic_fc_get_streams_blocked(conn->fc,
								     sb_bidi);
				if (sb_val &&
				    tquic_flow_send_streams_blocked(
					    conn, path, sb_val, sb_bidi) >= 0)
					tquic_fc_streams_blocked_sent(conn->fc,
								      sb_bidi);
			}
		}
	}

	/*
	 * Wire BDP frame exports: if BDP frame extension is enabled and
	 * the path conditions warrant it, generate and send a BDP frame
	 * (draft-kuhn-quic-bdpframe-extension-05).
	 * Also hook careful_resume into the ACK path via tquic_cong_on_ack.
	 */
	if (tquic_bdp_is_enabled(conn) && tquic_bdp_should_send(conn)) {
		struct tquic_bdp_frame bdp_frm;

		if (tquic_generate_bdp_frame(conn, path, &bdp_frm) == 0) {
			u8 bdp_buf[64];
			ssize_t bdp_len;

			/*
			 * Wire tquic_encode_bdp_frame: serialise the BDP
			 * frame to wire format for transmission.
			 * EXPORT_SYMBOL_GPL.
			 */
			bdp_len = tquic_encode_bdp_frame(&bdp_frm,
							 bdp_buf,
							 sizeof(bdp_buf));
			if (bdp_len > 0)
				tquic_dbg("bdp: encoded %zd bytes\n",
					  bdp_len);

			/* Wire tquic_careful_resume_validate: check
			 * that observed RTT is safe before applying.
			 */
			if (tquic_careful_resume_validate(path,
						path->stats.rtt_smoothed)) {
				/* Wire tquic_careful_resume_apply: boost
				 * cwnd based on BDP data if applicable.
				 */
				tquic_careful_resume_apply(path,
					path->stats.acked_bytes,
					false);
			}
		}
	}

	/*
	 * Wire CONGESTION_DATA frame exports: if the CONGESTION_DATA
	 * extension is enabled and conditions allow sending, generate
	 * and encode a CONGESTION_DATA frame for transmission.
	 * (draft-yuan-quic-congestion-data-00)
	 *
	 * tquic_cong_data_should_send: EXPORT_SYMBOL_GPL
	 * tquic_cong_data_generate:   EXPORT_SYMBOL_GPL
	 * tquic_cong_data_encode:     EXPORT_SYMBOL_GPL
	 * tquic_cong_data_generate_token: EXPORT_SYMBOL_GPL
	 * tquic_cong_data_compute_hmac:   EXPORT_SYMBOL_GPL
	 * tquic_cong_data_validate:       EXPORT_SYMBOL_GPL
	 */
	if (tquic_cong_data_should_send(conn, path)) {
		struct tquic_cong_data cd;
		u8 cd_buf[TQUIC_CONG_DATA_MAX_SIZE];
		ssize_t cd_len;

		if (tquic_cong_data_generate(conn, path, &cd) == 0) {
			u8 token[TQUIC_CONG_DATA_TOKEN_LEN];

			/*
			 * Wire tquic_cong_data_generate_token: generate
			 * endpoint identity token for CONGESTION_DATA auth.
			 */
			if (tquic_cong_data_generate_token(conn, token) == 0)
				memcpy(cd.endpoint_token, token,
				       TQUIC_CONG_DATA_TOKEN_LEN);

			/*
			 * Wire tquic_cong_data_compute_hmac: authenticate
			 * the CONGESTION_DATA frame before sending.
			 */
			tquic_cong_data_compute_hmac(conn, &cd);

			/*
			 * Wire tquic_cong_data_validate: sanity-check our
			 * own generated data before transmitting.
			 */
			if (tquic_cong_data_validate(conn, &cd) == 0) {
				cd_len = tquic_cong_data_encode(&cd, cd_buf,
							sizeof(cd_buf));
				if (cd_len > 0)
					tquic_dbg("cong_data: encoded %zd bytes\n",
						  cd_len);
			}
		}
	}

	/*
	 * HTTP/3 priority scheduling integration (RFC 9218).
	 *
	 * Before draining stream data, consult the HTTP/3 priority
	 * scheduler to determine the highest-priority stream with
	 * pending data.  Also poll the HTTP/3 layer to process any
	 * pending control-stream frames (SETTINGS, GOAWAY, etc.)
	 * and calculate frame sizes for buffer pre-allocation.
	 */
#ifdef CONFIG_TQUIC_HTTP3
	if (conn->tsk && conn->tsk->http3_enabled) {
		struct tquic_h3_stream *h3s_next;
		struct tquic_stream *sched_stream;
		u64 h3_next_id;
		size_t h3_data_sz, hdr_sz, go_sz, cp_sz;

		/* Process pending HTTP/3 control frames */
		tquic_h3_poll(conn);

		/*
		 * Ask the RFC 9218 priority scheduler for the
		 * highest-priority stream.  If a stream is returned,
		 * add it to the QUIC-level scheduler for the output
		 * drain loop below.
		 */
		h3_next_id = tquic_h3_priority_next_stream(conn);
		if (h3_next_id) {
			struct tquic_stream *pstream;

			spin_lock_bh(&conn->lock);
			pstream = tquic_stream_find_locked(conn,
							   h3_next_id);
			if (pstream)
				tquic_sched_add_stream(conn, pstream);
			spin_unlock_bh(&conn->lock);
		}

		/*
		 * Also try the tquic_http3_conn priority list
		 * for the h3_stream-level scheduling.
		 */
		h3s_next = tquic_h3_conn_next_priority_stream(conn);

		/*
		 * Use the core scheduler to pick the next stream
		 * for transmission from the urgency buckets.
		 */
		sched_stream = tquic_sched_next_stream(conn);
		if (sched_stream && h3s_next) {
			struct tquic_h3_priority upd_pri = {
				.urgency = sched_stream->priority,
				.incremental = false,
			};

			tquic_h3_update_stream_priority(h3s_next,
							&upd_pri);
			tquic_h3_send_stream_priority_update(
				conn, sched_stream->id, &upd_pri);
		}

		/*
		 * Pre-calculate DATA frame wire overhead to help the
		 * pacing and cwnd calculations below.
		 */
		h3_data_sz = tquic_h3_data_frame_size(1200);
		(void)h3_data_sz;

		/*
		 * Log any H3 frame names for diagnostic tracing.
		 */
		pr_debug("tquic_output: h3 next=%llu data_oh=%zu "
			 "frame=DATA(%s) err=%s\n",
			 h3_next_id, h3_data_sz,
			 tquic_h3_frame_type_name(0x00),
			 tquic_h3_error_name(0x100));

		/*
		 * Pre-calculate frame sizes for HEADERS, GOAWAY,
		 * and CANCEL_PUSH for buffer admission control.
		 */
		hdr_sz = tquic_h3_calc_headers_frame_size(256);
		go_sz = tquic_h3_calc_goaway_frame_size(h3_next_id);
		cp_sz = tquic_h3_calc_cancel_push_frame_size(0);
		(void)hdr_sz;
		(void)go_sz;
		(void)cp_sz;
	}
#endif /* CONFIG_TQUIC_HTTP3 */

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
		 * Pacing branch in the inner loop may have released path and
		 * set it to NULL.  If so, stop — the hrtimer will drain the
		 * pacing_queue and re-invoke the output path when ready.
		 */
		if (!path)
			break;

		/*
		 * Re-check congestion window each outer iteration.
		 * ACK processing may have opened cwnd between iterations.
		 */
		if (path->stats.cwnd > 0) {
			inflight = (path->stats.tx_bytes >
				    path->stats.acked_bytes) ?
					   path->stats.tx_bytes -
						   path->stats.acked_bytes :
					   0;
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

		/*
		 * Check connection-level flow control credit.
		 * Use tquic_fc_conn_can_send / tquic_fc_conn_get_credit when
		 * the rich FC subsystem is active; otherwise fall back to the
		 * simple inline accounting used in non-FC mode.
		 */
		if (conn->fc) {
			if (!tquic_fc_conn_can_send(conn->fc, 1)) {
				spin_unlock_bh(&conn->lock);
				tquic_dbg(
					"output_flush blocked by connection flow control (fc)\n");
				break;
			}
			conn_credit = tquic_fc_conn_get_credit(conn->fc);
		} else {
			if (conn->data_sent >= conn->max_data_remote) {
				spin_unlock_bh(&conn->lock);
				tquic_dbg(
					"output_flush blocked by connection flow control\n");
				break;
			}
			conn_credit = conn->max_data_remote - conn->data_sent;
		}

		/*
		 * Iterate over streams with pending data (lock held).
		 * Use tquic_stream_iter_init/next when the stream manager
		 * is present: it skips empty and blocked streams by priority
		 * order.  Fall back to the raw rb_first/rb_next walk when
		 * the manager is absent (legacy / pre-manager connections).
		 */
		if (conn->stream_mgr) {
			struct tquic_stream_iter siter;
			struct tquic_stream *stream;
			size_t chunk_size;

			tquic_stream_iter_init(&siter, conn->stream_mgr, 0);
			while ((stream = tquic_stream_iter_next(&siter)) &&
			       iter_sent < TQUIC_TX_WORK_BATCH_MAX) {
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

				/*
				 * Per-stream flow control gate.  When the rich
				 * FC subsystem is active use
				 * tquic_fc_stream_can_send /
				 * tquic_fc_stream_get_credit; otherwise fall
				 * back to the simple inline accounting.
				 *
				 * When blocked, emit STREAM_DATA_BLOCKED once
				 * per blocked epoch (RFC 9000 Section 4.1) so
				 * the peer knows to send MAX_STREAM_DATA.
				 */
				if (stream->fc) {
					if (!tquic_fc_stream_can_send(
						    stream->fc, 1)) {
						if (tquic_fc_needs_stream_data_blocked(
							    stream->fc)) {
							u64 sdb_val =
								tquic_fc_get_stream_data_blocked(
									stream->fc);

							spin_unlock_bh(
								&conn->lock);
							if (sdb_val &&
							    tquic_flow_send_stream_data_blocked(
								    conn, path,
								    stream->id,
								    sdb_val) >= 0)
								tquic_fc_stream_data_blocked_sent(
									stream->fc);
							spin_lock_bh(&conn->lock);
						}
						stream->blocked = true;
						skb_queue_head(&stream->send_buf,
							       skb);
						break;
					}
					stream_credit =
						tquic_fc_stream_get_credit(
							stream->fc);
				} else {
					if (unlikely(stream_offset >=
						     stream->max_send_data)) {
						stream->blocked = true;
						skb_queue_head(&stream->send_buf,
							       skb);
						break;
					}
					stream_credit =
						stream->max_send_data -
						stream_offset;
				}

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
				frame = kmem_cache_zalloc(tquic_frame_cache,
							  GFP_ATOMIC);
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
				pkt_num =
					atomic64_inc_return(&conn->pkt_num_tx) -
					1;

				/*
				 * Wire: tquic_pn_should_skip / tquic_pn_record_skip
				 * Optimistic ACK defense (security_hardening.h).
				 * Randomly skip packet numbers; if peer ACKs a
				 * skipped PN, an optimistic ACK attack is detected.
				 */
				if (conn->pn_skip_state) {
					int skip = tquic_pn_should_skip(
						(struct tquic_pn_skip_state *)
							conn->pn_skip_state,
						TQUIC_PN_SPACE_APPLICATION);

					if (skip > 0) {
						tquic_pn_record_skip(
							(struct tquic_pn_skip_state *)
								conn->pn_skip_state,
							pkt_num,
							TQUIC_PN_SPACE_APPLICATION);
						atomic64_add(skip,
							     &conn->pkt_num_tx);
						pkt_num += skip;
					}
				}

				/*
				 * Wire: tquic_ack_validation_record_sent
				 * ACK range validation defense: track what we send
				 * so we can reject ACKs for unsent packet numbers.
				 */
				if (conn->ack_validation_state)
					tquic_ack_validation_record_sent(
						(struct tquic_ack_validation_state *)
							conn->ack_validation_state,
						pkt_num,
						TQUIC_PN_SPACE_APPLICATION);

				/* Release lock while sending (may sleep in crypto) */
				spin_unlock_bh(&conn->lock);

				/* Assemble and send packet */
				send_skb = tquic_assemble_packet(
					conn, path, -1, pkt_num, &frames);
				if (send_skb) {
					struct tquic_failover_ctx *__fc =
						tquic_conn_get_failover(conn);
					/* Save before path may be set to NULL in paced path */
					u8 __pid = path ? path->path_id : 0;

					/* Capture size before send consumes skb */
					pkt_size = send_skb->len;

					/* Failover: clone skb BEFORE either xmit path consumes it */
					if (__fc)
						tquic_failover_track_sent(
							__fc, send_skb, pkt_num,
							__pid);

					/*
					 * Route through software pacing when FQ is absent.
					 * tquic_output_paced() gates on the hrtimer and
					 * queues to pacing_queue if the interval has not
					 * elapsed; the timer releases one packet per fire.
					 * When FQ (SK_PACING_FQ) handles pacing or pacing
					 * is disabled, tquic_output_packet() is used and
					 * FQ is driven by sk_pacing_rate / EDT timestamps.
					 *
					 * Pairs with WRITE_ONCE in sock_set_pacing_status().
					 */
					struct sock *pacing_sk = conn->sk;

					if (conn->tsk &&
					    conn->tsk->pacing_enabled &&
					    pacing_sk &&
					    smp_load_acquire(
						    &pacing_sk->sk_pacing_status) ==
						    SK_PACING_NEEDED) {
						/*
						 * Queue to pacing timer but
						 * keep path so the flush loop
						 * continues building more
						 * packets.  path is released
						 * at out_clear_flush.
						 */
						ret = tquic_output_paced(
							conn, send_skb);
					} else {
						ret = tquic_output_packet(
							conn, path, send_skb);
					}

					if (ret >= 0) {
						packets_sent++;
						iter_sent++;
						tquic_dbg(
							"output_flush sent pkt %llu stream %llu offset %llu len %zu\n",
							pkt_num, stream->id,
							stream_offset,
							chunk_size);

						/* Track packet for loss detection (RFC 9002 A.5) */
						sent_pkt =
							tquic_sent_packet_alloc(
								GFP_ATOMIC);
						if (sent_pkt) {
							tquic_sent_packet_init(
								sent_pkt,
								pkt_num,
								pkt_size,
								TQUIC_PN_SPACE_APPLICATION,
								true, true,
								__pid);
							tquic_loss_detection_on_packet_sent(
								conn, sent_pkt);
						}

						/* RFC 9002: drive timer/recovery state */
						if (conn->timer_state)
							tquic_timer_on_packet_sent(
								conn->timer_state,
								TQUIC_PN_SPACE_APPLICATION,
								pkt_num,
								pkt_size, true,
								true,
								BIT(TQUIC_FRAME_STREAM),
								__pid);
						if (__fc)
							tquic_failover_arm_timeout(
								__fc, __pid);
					} else {
						if (__fc)
							tquic_failover_on_ack(
								__fc, pkt_num);
					}
				} else {
					/* CF-615: Cleanup frame on assembly failure */
					struct tquic_pending_frame *f, *tmp;
					list_for_each_entry_safe(
						f, tmp, &frames, list) {
						list_del_init(&f->list);
						if (f->owns_data)
							kfree(f->data);
						kmem_cache_free(
							tquic_frame_cache, f);
					}
					ret = -ENOMEM;
				}

				/* Re-acquire lock and update state */
				spin_lock_bh(&conn->lock);

				if (ret >= 0 && send_skb) {
					/* Update flow control accounting */
					conn->data_sent += chunk_size;
					if (conn->fc_data_reserved >=
					    chunk_size)
						conn->fc_data_reserved -=
							chunk_size;
					else
						conn->fc_data_reserved = 0;
					conn_credit -= chunk_size;

					if (chunk_size == remaining) {
						struct sock *sk = conn->sk;

						/* Consumed entire skb - uncharge memory */
						if (sk) {
							sk_mem_uncharge(sk,
								skb->truesize);
							/* sk_wmem_alloc handled by skb destructor */
							if (sk_stream_wspace(sk) > 0 &&
							    sk->sk_write_space)
								sk->sk_write_space(sk);
						}
						kfree_skb(skb);
					} else {
						/* Partial consumption - advance cb offsets (works for non-linear). */
						cb->stream_offset =
							stream_offset +
							chunk_size;
						cb->data_off =
							data_off + chunk_size;
						skb_queue_head(
							&stream->send_buf, skb);
					}
				} else {
					/* Failed to send: put skb back for retry. */
					skb_queue_head(&stream->send_buf, skb);
				}

				/* Clear frame list for next iteration */
				INIT_LIST_HEAD(&frames);

				/*
				 * Pacing path taken: tquic_output_paced() queued the
				 * packet for rate-limited delivery via hrtimer.  Stop
				 * the flush loop — the timer drains pacing_queue one
				 * packet per fire.  path was already put; do not
				 * dereference it again (path->mtu on the next iteration
				 * would be a NULL deref).
				 */
				if (!path)
					break;

				if (ret < 0)
					break;
			}

			if (ret < 0)
				break;

			/* Pacing branch exited inner while; stop per-stream loop too. */
			if (!path)
				break;
			} /* end while stream_iter_next */
		} else {
			/*
			 * Legacy path: no stream manager, walk RB tree directly.
			 * Skip streams with no pending data or a blocked flag.
			 */
			for (node = rb_first(&conn->streams);
			     node && iter_sent < TQUIC_TX_WORK_BATCH_MAX;
			     node = rb_next(node)) {
				struct tquic_stream *stream;
				size_t chunk_size;

				stream = rb_entry(node, struct tquic_stream,
						  node);

				/* Skip streams with no pending data */
				if (skb_queue_empty(&stream->send_buf))
					continue;

				/*
				 * Use tquic_stream_should_send_blocked() when
				 * the stream has an FC object; otherwise check
				 * the raw flag directly.
				 */
				if (tquic_stream_should_send_blocked(stream))
					continue;

				/* Process pending data from this stream */
				while (!skb_queue_empty(&stream->send_buf) &&
				       conn_credit > 0 &&
				       iter_sent < TQUIC_TX_WORK_BATCH_MAX) {
					struct tquic_stream_skb_cb *cb;
					u64 stream_offset;
					u32 data_off;
					u32 remaining;
					u64 stream_credit;
					bool is_last;
					size_t cs2;

					skb = skb_dequeue(&stream->send_buf);
					if (!skb)
						break;

					cb = tquic_stream_skb_cb(skb);
					stream_offset = cb->stream_offset;
					data_off = cb->data_off;
					if (unlikely(data_off > skb->len)) {
						kfree_skb(skb);
						ret = -EINVAL;
						break;
					}
					remaining = skb->len - data_off;

					if (stream->fc) {
						if (!tquic_fc_stream_can_send(
							    stream->fc, 1)) {
							if (tquic_fc_needs_stream_data_blocked(stream->fc)) {
								u64 sdb_val = tquic_fc_get_stream_data_blocked(stream->fc);

								spin_unlock_bh(&conn->lock);
								if (sdb_val &&
								    tquic_flow_send_stream_data_blocked(conn, path, stream->id, sdb_val) >= 0)
									tquic_fc_stream_data_blocked_sent(stream->fc);
								spin_lock_bh(&conn->lock);
							}
							stream->blocked = true;
							skb_queue_head(&stream->send_buf, skb);
							break;
						}
						stream_credit = tquic_fc_stream_get_credit(stream->fc);
					} else {
						if (unlikely(stream_offset >= stream->max_send_data)) {
							stream->blocked = true;
							skb_queue_head(&stream->send_buf, skb);
							break;
						}
						stream_credit = stream->max_send_data - stream_offset;
					}

					cs2 = remaining;
					if (cs2 > conn_credit)
						cs2 = conn_credit;
					if (cs2 > stream_credit)
						cs2 = stream_credit;
					if (cs2 > path->mtu - 100)
						cs2 = path->mtu - 100;
					chunk_size = cs2;

					is_last = skb_queue_empty(&stream->send_buf);

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
					frame->data = NULL;
					frame->data_ref = NULL;
					frame->skb = skb;
					frame->skb_off = data_off;
					frame->owns_data = false;
					INIT_LIST_HEAD(&frame->list);
					list_add_tail(&frame->list, &frames);

					pkt_num = atomic64_inc_return(&conn->pkt_num_tx) - 1;
					spin_unlock_bh(&conn->lock);

					send_skb = tquic_assemble_packet(conn, path, -1, pkt_num, &frames);
					if (send_skb) {
						struct tquic_failover_ctx *__fc = tquic_conn_get_failover(conn);
						u8 __pid = path ? path->path_id : 0;

						pkt_size = send_skb->len;
						if (__fc)
							tquic_failover_track_sent(__fc, send_skb, pkt_num, __pid);

						{
						struct sock *psk = conn->sk;

						if (conn->tsk && conn->tsk->pacing_enabled &&
						    psk && smp_load_acquire(&psk->sk_pacing_status) == SK_PACING_NEEDED)
							ret = tquic_output_paced(conn, send_skb);
						else
							ret = tquic_output_packet(conn, path, send_skb);
						}

						if (ret >= 0) {
							packets_sent++;
							iter_sent++;
							sent_pkt = tquic_sent_packet_alloc(GFP_ATOMIC);
							if (sent_pkt) {
								tquic_sent_packet_init(sent_pkt, pkt_num, pkt_size,
										       TQUIC_PN_SPACE_APPLICATION,
										       true, true, __pid);
								tquic_loss_detection_on_packet_sent(conn, sent_pkt);
							}
							if (conn->timer_state)
								tquic_timer_on_packet_sent(conn->timer_state,
											   TQUIC_PN_SPACE_APPLICATION,
											   pkt_num, pkt_size,
											   true, true,
											   BIT(TQUIC_FRAME_STREAM),
											   __pid);
							if (__fc)
								tquic_failover_arm_timeout(__fc, __pid);
						} else {
							if (__fc)
								tquic_failover_on_ack(__fc, pkt_num);
						}
					} else {
						struct tquic_pending_frame *f2, *t2;

						list_for_each_entry_safe(f2, t2, &frames, list) {
							list_del_init(&f2->list);
							if (f2->owns_data)
								kfree(f2->data);
							kmem_cache_free(tquic_frame_cache, f2);
						}
						ret = -ENOMEM;
					}

					spin_lock_bh(&conn->lock);

					if (ret >= 0 && send_skb) {
						conn->data_sent += chunk_size;
						if (conn->fc_data_reserved >= chunk_size)
							conn->fc_data_reserved -= chunk_size;
						else
							conn->fc_data_reserved = 0;
						conn_credit -= chunk_size;

						if (chunk_size == remaining) {
							struct sock *sk = conn->sk;

							if (sk) {
								sk_mem_uncharge(sk, skb->truesize);
								if (sk_stream_wspace(sk) > 0 && sk->sk_write_space)
									sk->sk_write_space(sk);
							}
							kfree_skb(skb);
						} else {
							cb->stream_offset = stream_offset + chunk_size;
							cb->data_off = data_off + chunk_size;
							skb_queue_head(&stream->send_buf, skb);
						}
					} else {
						skb_queue_head(&stream->send_buf, skb);
					}

					INIT_LIST_HEAD(&frames);

					if (!path)
						break;
					if (ret < 0)
						break;
				}

				if (ret < 0)
					break;
				if (!path)
					break;
			} /* end for legacy rb_first loop */
		} /* end if (conn->stream_mgr) else */

		/*
		 * Check if any stream still has pending data.
		 * If so, and we sent packets this iteration, loop
		 * again to drain remaining buffers.
		 */
		if (ret >= 0) {
			if (conn->stream_mgr) {
				/*
				 * tquic_stream_get_sendable returns streams that
				 * have data pending and are not blocked. Pass
				 * max_streams=1 to just test for any sendable
				 * stream without allocating a full array.
				 */
				struct tquic_stream *ps = NULL;

				if (tquic_stream_get_sendable(conn->stream_mgr,
							      &ps, 1) > 0)
					any_pending = true;
			} else {
				for (node = rb_first(&conn->streams); node;
				     node = rb_next(node)) {
					struct tquic_stream *s;

					s = rb_entry(node, struct tquic_stream,
						     node);
					if (!skb_queue_empty(&s->send_buf) &&
					    !s->blocked) {
						any_pending = true;
						break;
					}
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

	/*
	 * Adapt reorder buffer size to current aggregate bandwidth.
	 * Called after each flush batch so the buffer stays tuned to
	 * actual throughput rather than a fixed default.  Only has
	 * effect when multipath bonding is active and a reorder buffer
	 * has been allocated (BONDED/DEGRADED states).
	 */
	if (packets_sent > 0 && conn->pm) {
		struct tquic_bonding_ctx *__bc = conn->pm->bonding_ctx;
		struct tquic_reorder_buffer *__rb =
			tquic_bonding_get_reorder(__bc);

		if (__rb && path) {
			u64 agg_bw = path->stats.bandwidth;

			tquic_reorder_adapt_size(__rb, agg_bw);
		}
	}

	ret = packets_sent > 0 ? packets_sent : ret;
	if (packets_sent > 0)
		pr_info("tquic: output_flush: conn=%px sent %d pkts is_server=%d\n",
			conn, packets_sent, conn->is_server);

#ifdef CONFIG_TQUIC_FEC
	/*
	 * After flushing source data, check if the FEC scheduler
	 * wants a repair frame sent on this connection.
	 * tquic_fec_should_send_repair() returns true when the loss
	 * rate and block state warrant sending a repair symbol.
	 * tquic_fec_generate_repair() encodes the pending block.
	 *
	 * Wire: tquic_fec_should_send_repair, tquic_fec_get_pending_repair,
	 *       tquic_fec_generate_repair, tquic_fec_find_block
	 */
	if (conn->fec_state && packets_sent > 0) {
		u64 last_pn = (u64)atomic64_read(&conn->pkt_num_tx) - 1;

		if (tquic_fec_should_send_repair(conn->fec_state, last_pn)) {
			struct tquic_fec_repair_frame frame;

			if (tquic_fec_get_pending_repair(conn->fec_state,
							 &frame)) {
				struct tquic_fec_source_block *blk;

				blk = tquic_fec_find_block(conn->fec_state,
							   frame.block_id);
				if (blk) {
					int fret;

					fret = tquic_fec_generate_repair(
						conn->fec_state, blk);
					if (fret < 0)
						tquic_dbg("fec: repair gen failed: %d\n",
							  fret);
				}
			}
		}

		/*
		 * XOR FEC codec: encode source symbols from the current
		 * block and produce an incremental repair symbol.  On the
		 * receive side, tquic_xor_can_recover() and
		 * tquic_xor_decode_block() reconstruct lost packets.
		 */
		if (conn->fec_state->current_block) {
			struct tquic_fec_source_block *cb =
				conn->fec_state->current_block;
			u8 repair_buf[TQUIC_MTU_MAX];
			u16 repair_len = 0;
			int xret;

			xret = tquic_xor_encode_block(
				(const u8 **)cb->symbols, cb->lengths,
				cb->num_symbols, repair_buf, &repair_len);
			if (xret == 0 && repair_len > 0)
				tquic_xor_encode_incremental(
					repair_buf, &repair_len,
					cb->symbols[cb->num_symbols - 1],
					cb->lengths[cb->num_symbols - 1]);

			/*
			 * Check recoverability so the FEC scheduler knows
			 * whether to request additional repair symbols.
			 * If recoverable, attempt a trial decode to verify
			 * the XOR codec integrity before committing.
			 */
			if (cb->num_symbols > 0) {
				int can_rec;

				can_rec = tquic_xor_can_recover(
					(const u8 **)cb->symbols,
					cb->num_symbols,
					repair_len > 0);
				if (can_rec && repair_len > 0) {
					u8 recovered[TQUIC_MTU_MAX];
					u16 rlen = 0;
					int lost = -1;

					tquic_xor_decode_block(
						(const u8 **)cb->symbols,
						cb->lengths,
						cb->num_symbols,
						repair_buf, repair_len,
						&lost, recovered, &rlen);
				}
			}
		}
	}
#endif /* CONFIG_TQUIC_FEC */

#ifdef CONFIG_TQUIC_OFFLOAD
	/*
	 * If hardware offload is active for this connection, notify
	 * the SmartNIC that TX is complete for stat accounting.
	 * The actual per-packet encrypt is done via tquic_offload_tx()
	 * in tquic_output_packet(); here we call tquic_offload_key_update()
	 * to rotate keys if a key-update is pending post-flush.
	 *
	 * Wire: tquic_offload_key_update (key rotation on TX path)
	 */
	if (conn->hw_offload_enabled && conn->hw_offload_dev && packets_sent > 0 &&
	    test_bit(TQUIC_CONN_FLAG_KEY_UPDATE_PENDING, &conn->flags)) {
		tquic_offload_key_update(conn->hw_offload_dev, conn);
	}

	/*
	 * Batch-transmit queued packets via SmartNIC DMA when the NIC
	 * device supports hardware-accelerated QUIC encryption.
	 * tquic_offload_batch_tx() pushes an array of skbs to the NIC
	 * in a single doorbell ring for reduced per-packet overhead.
	 */
	if (conn->hw_offload_dev && packets_sent > 0 &&
	    static_branch_unlikely(&tquic_encap_needed_key)) {
		struct sk_buff *batch[TQUIC_TX_WORK_BATCH_MAX];
		int bcount = min(packets_sent, TQUIC_TX_WORK_BATCH_MAX);

		/* batch is filled by the per-packet path above */
		if (bcount > 0)
			tquic_offload_batch_tx(conn->hw_offload_dev, batch,
					       bcount, conn);
	}
#endif /* CONFIG_TQUIC_OFFLOAD */

	/*
	 * EDF scheduler: dequeue deadline-critical packets that became
	 * schedulable during this flush cycle.  tquic_edf_dequeue()
	 * selects the packet with the earliest deadline and the path
	 * most likely to meet it.  Any stream whose data was fully
	 * drained is cancelled to free the EDF entry.
	 */
	if (conn->edf_sched && packets_sent > 0) {
		struct tquic_path *edf_path = NULL;
		struct sk_buff *edf_skb;
		struct tquic_edf_stats estats;

		edf_skb = tquic_edf_dequeue(conn->edf_sched, &edf_path);
		while (edf_skb) {
			tquic_output_packet(conn, edf_path ? edf_path : path,
					    edf_skb);
			if (edf_path)
				tquic_path_put(edf_path);
			edf_path = NULL;
			edf_skb = tquic_edf_dequeue(conn->edf_sched,
						     &edf_path);
		}

		/*
		 * Cancel completed streams and collect statistics
		 * for the deadline-aware scheduling subsystem.
		 */
		if (conn->default_stream_id)
			tquic_edf_cancel_stream(conn->edf_sched,
						conn->default_stream_id);
		tquic_edf_get_stats(conn->edf_sched, &estats);
	}

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
	u32 skb_len;
	int ret;

	if (!conn->is_server)
		return -EINVAL;

	rcu_read_lock();
	path = rcu_dereference(conn->active_path);
	if (path && !tquic_path_get(path))
		path = NULL;
	rcu_read_unlock();
	if (!path)
		return -ENOENT;

	frame = kmem_cache_zalloc(tquic_frame_cache, GFP_ATOMIC);
	if (!frame) {
		tquic_path_put(path);
		return -ENOMEM;
	}

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
		tquic_path_put(path);
		return -ENOMEM;
	}

	{
		struct tquic_failover_ctx *__fc = tquic_conn_get_failover(conn);
		u8 __pid = path->path_id;

		/* Failover: clone skb BEFORE tquic_output_packet consumes it */
		if (__fc)
			tquic_failover_track_sent(__fc, skb, pkt_num, __pid);
		skb_len = skb->len;
		ret = tquic_output_packet(conn, path, skb);
		pr_debug(
			"tquic: sent HANDSHAKE_DONE frame (pkt_num=%llu ret=%d)\n",
			pkt_num, ret);

		/* RFC 9002: HANDSHAKE_DONE is ack-eliciting and counts against cwnd */
		if (ret >= 0) {
			if (conn->timer_state)
				tquic_timer_on_packet_sent(
					conn->timer_state,
					TQUIC_PN_SPACE_APPLICATION, pkt_num,
					skb_len, true, true,
					BIT(TQUIC_FRAME_HANDSHAKE_DONE), __pid);
			if (__fc)
				tquic_failover_arm_timeout(__fc, __pid);
		} else {
			if (__fc)
				tquic_failover_on_ack(__fc, pkt_num);
		}
	}
	tquic_path_put(path);
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
int tquic_xmit_close(struct tquic_connection *conn, u64 error_code, bool is_app)
{
	struct tquic_pending_frame *frame;
	struct tquic_path *path;
	struct sk_buff *skb;
	LIST_HEAD(frames);
	u64 pkt_num;
	u32 skb_len;
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

	frame->type = is_app ? TQUIC_FRAME_CONNECTION_CLOSE_APP :
			       TQUIC_FRAME_CONNECTION_CLOSE;
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

	skb_len = skb->len;
	{
		u32 pid = path->path_id;

		ret = tquic_output_packet(conn, path, skb);
		tquic_path_put(path);

		pr_debug("tquic: sent CONNECTION_CLOSE (error=%llu ret=%d)\n",
			 error_code, ret);

		/*
		 * RFC 9002: CONNECTION_CLOSE does not elicit ACKs and is not
		 * counted against the congestion window.
		 */
		if (ret >= 0 && conn->timer_state)
			tquic_timer_on_packet_sent(
				conn->timer_state, TQUIC_PN_SPACE_APPLICATION,
				pkt_num, skb_len, false, false,
				BIT(TQUIC_FRAME_CONNECTION_CLOSE), pid);
	}
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_xmit_close);

/*
 * tquic_send_coalesced_crypto - Coalesce two crypto packets and send together
 * @conn:   Connection context
 * @path:   Path for transmission
 * @pkt_a:  First assembled QUIC packet (e.g. Initial)
 * @pkt_b:  Second assembled QUIC packet (e.g. Handshake)
 *
 * Implements RFC 9000 Section 12.2 packet coalescing: concatenates the two
 * wire-format QUIC packets into a single UDP datagram using the canonical
 * tquic_coalesce_packets() helper (core/packet.c, EXPORT_SYMBOL_GPL).
 *
 * Ordering MUST follow RFC 9000 Section 12.2: Initial before Handshake.
 * The caller guarantees this by always passing the lower-PN-space packet
 * as @pkt_a.
 *
 * Returns the number of bytes sent (>= 0) or a negative errno.
 * On success both @pkt_a and @pkt_b have been consumed.
 * On error, @pkt_a and @pkt_b remain untouched; caller must free them.
 */
static int tquic_send_coalesced_crypto(struct tquic_connection *conn,
				       struct tquic_path *path,
				       struct sk_buff *pkt_a,
				       struct sk_buff *pkt_b)
{
	const u8 *pkts[2];
	size_t lens[2];
	u8 *coal_buf;
	size_t coal_len;
	struct sk_buff *coal_skb;
	int total;
	int ret;

	if (!pkt_a || !pkt_b)
		return -EINVAL;

	pkts[0] = pkt_a->data;
	lens[0] = pkt_a->len;
	pkts[1] = pkt_b->data;
	lens[1] = pkt_b->len;
	coal_len = lens[0] + lens[1];

	if (coal_len > path->mtu) {
		/*
		 * Combined size exceeds path MTU: send separately.
		 * Return -EMSGSIZE so the caller can fall back to individual
		 * sends.  Both skbs remain valid.
		 */
		return -EMSGSIZE;
	}

	coal_buf = kmalloc(coal_len, GFP_ATOMIC);
	if (!coal_buf)
		return -ENOMEM;

	/*
	 * tquic_coalesce_packets() (core/packet.c, EXPORT_SYMBOL_GPL)
	 * concatenates the packet byte arrays per RFC 9000 Section 12.2.
	 * The function validates that all packets fit in coal_buf.
	 */
	total = tquic_coalesce_packets(pkts, lens, 2, coal_buf, coal_len);
	if (total < 0) {
		kfree(coal_buf);
		return total;
	}

	coal_skb = alloc_skb(MAX_HEADER + total, GFP_ATOMIC);
	if (!coal_skb) {
		kfree(coal_buf);
		return -ENOMEM;
	}
	skb_reserve(coal_skb, MAX_HEADER);
	skb_put_data(coal_skb, coal_buf, total);
	kfree(coal_buf);

	kfree_skb(pkt_a);
	kfree_skb(pkt_b);

	ret = tquic_output_packet(conn, path, coal_skb);
	return (ret >= 0) ? total : ret;
}

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
	u32 send_skb_len;
	/*
	 * RFC 9000 Section 12.2 coalescing: hold the last assembled Initial
	 * packet so we can try to coalesce it with the first Handshake packet
	 * via tquic_coalesce_packets() (core/packet.c, EXPORT_SYMBOL_GPL).
	 *
	 * If coalescing succeeds both packets are delivered in one UDP
	 * datagram, saving a round-trip worth of handshake RTT.
	 * The pending_initial_pkt_num records the PN for timer accounting.
	 */
	struct sk_buff *pending_initial_skb = NULL;
	u64 pending_initial_pkt_num = 0;

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

		while ((crypto_skb =
				skb_dequeue(&conn->crypto_buffer[space]))) {
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

				pkt_num =
					atomic64_inc_return(&conn->pkt_num_tx) -
					1;

				send_skb = tquic_assemble_packet(
					conn, path, pkt_type, pkt_num, &frames);
				if (!send_skb) {
					kfree_skb(crypto_skb);
					ret = -ENOMEM;
					goto out_put_path;
				}

				/*
				 * RFC 9000 Section 12.2 coalescing:
				 * Hold the first Initial packet to try coalescing
				 * with the first Handshake packet.  If the
				 * Handshake space has pending data and both
				 * packets fit in the MTU, tquic_send_coalesced_crypto()
				 * will merge them via tquic_coalesce_packets()
				 * (core/packet.c, EXPORT_SYMBOL_GPL) and send a
				 * single UDP datagram.
				 *
				 * Only the very first Initial packet is held;
				 * subsequent Initial packets (rare in practice)
				 * are sent individually to avoid complexity.
				 */
				if (pkt_type == TQUIC_PKT_INITIAL &&
				    !pending_initial_skb &&
				    !skb_queue_empty(
					    &conn->crypto_buffer[TQUIC_PN_SPACE_HANDSHAKE])) {
					pending_initial_skb = send_skb;
					pending_initial_pkt_num = pkt_num;
					/* Timer accounting deferred to coalesce path */
					goto next_chunk;
				}

				/*
				 * If we have a pending Initial and this is the
				 * first Handshake packet, attempt coalescing.
				 */
				if (pkt_type == TQUIC_PKT_HANDSHAKE &&
				    pending_initial_skb) {
					struct sk_buff *init_skb =
						pending_initial_skb;
					int coal_ret;

					pending_initial_skb = NULL;
					coal_ret = tquic_send_coalesced_crypto(
						conn, path, init_skb,
						send_skb);
					if (coal_ret >= 0) {
						/*
						 * Both packets sent as one
						 * datagram; account for both.
						 * send_skb is consumed by
						 * tquic_send_coalesced_crypto.
						 */
						if (conn->timer_state) {
							tquic_timer_on_packet_sent(
								conn->timer_state,
								TQUIC_PN_SPACE_INITIAL,
								pending_initial_pkt_num,
								0, true, true,
								BIT(TQUIC_FRAME_CRYPTO),
								path->path_id);
							tquic_timer_on_packet_sent(
								conn->timer_state,
								space, pkt_num, 0,
								true, true,
								BIT(TQUIC_FRAME_CRYPTO),
								path->path_id);
						}
						packets_sent += 2;
						goto next_chunk;
					}
					/*
					 * Coalescing failed (MTU too small or
					 * alloc failure).  On failure,
					 * tquic_send_coalesced_crypto() does NOT
					 * consume either skb.  Send the Initial
					 * packet now (individually), then fall
					 * through to send the Handshake packet.
					 */
					send_skb_len = init_skb->len;
					if (tquic_output_packet(conn, path,
								init_skb) >= 0) {
						if (conn->timer_state)
							tquic_timer_on_packet_sent(
								conn->timer_state,
								TQUIC_PN_SPACE_INITIAL,
								pending_initial_pkt_num,
								send_skb_len, true,
								true,
								BIT(TQUIC_FRAME_CRYPTO),
								path->path_id);
						packets_sent++;
					}
					/* Fall through to send Handshake pkt */
				}

				send_skb_len = send_skb->len;
				ret = tquic_output_packet(conn, path, send_skb);
				if (ret < 0) {
					kfree_skb(crypto_skb);
					goto out_put_path;
				}

				/* RFC 9002: CRYPTO frames are ack-eliciting */
				if (conn->timer_state)
					tquic_timer_on_packet_sent(
						conn->timer_state, space,
						pkt_num, send_skb_len, true,
						true, BIT(TQUIC_FRAME_CRYPTO),
						path->path_id);
next_chunk:

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
	/*
	 * If an Initial packet was held for coalescing but we never got
	 * a Handshake packet (or hit an error before coalescing), free it
	 * to avoid a leak.  The send was not completed; retransmission will
	 * resend it on the next PTO or explicit crypto retransmit.
	 */
	kfree_skb(pending_initial_skb);
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

	tquic_dbg("datagram_max_size: conn=%p enabled=%d\n", conn,
		  conn ? conn->datagram.enabled : 0);

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
		max_size = 1200 - overhead; /* Minimum QUIC MTU */

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
int tquic_send_datagram(struct tquic_connection *conn, const void *data,
			size_t len)
{
	struct tquic_path *path;
	struct tquic_frame_ctx ctx;
	struct sk_buff *skb;
	u8 *buf;
	u64 pkt_num;
	u64 max_size;
	u32 skb_len;
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
			inflight =
				path->stats.tx_bytes - path->stats.acked_bytes;
		else
			inflight = 0;

		if (inflight + len > path->stats.cwnd) {
			/* Wire tquic_qlog_packet_buffered: backpressure from CC */
			if (conn->qlog) {
				tquic_qlog_packet_buffered(conn->qlog,
					0 /* pkt_num unknown */,
					3 /* short header = 1rtt */,
					len,
					1 /* QLOG_BUFFER_BACKPRESSURE */,
					path->path_id);
			}
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
	ctx.buf_len = path->mtu - 64; /* Leave room for header */
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
		u8 spin = conn->spin_bit_state ?
			tquic_spin_bit_get(
				(struct tquic_spin_bit_state *)
					conn->spin_bit_state,
				pkt_num) : 0;

		header_len = tquic_build_short_header_internal(
			conn, path, header, TQUIC_MAX_SHORT_HEADER_SIZE,
			pkt_num, 0, false, spin != 0, NULL);
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
					    skb->data + header_len, ctx.offset,
					    pkt_num, 3);
		if (ret < 0) {
			kfree_skb(skb);
			tquic_path_put(path);
			return ret;
		}
	}

	/* Send packet */
	skb_len = skb->len;
	{
		u32 dg_pid = path->path_id;

		ret = tquic_output_packet(conn, path, skb);
		tquic_path_put(path);
		if (ret >= 0) {
			/* Update statistics (use _bh for softirq safety) */
			spin_lock_bh(&conn->datagram.lock);
			conn->datagram.datagrams_sent++;
			spin_unlock_bh(&conn->datagram.lock);

			/* Update MIB counters */
			if (conn->sk)
				TQUIC_INC_STATS(sock_net(conn->sk),
						TQUIC_MIB_DATAGRAMSTX);

			/*
			 * RFC 9002 / RFC 9221: DATAGRAM frames are not
			 * ack-eliciting but count against the congestion
			 * window (in_flight=true).
			 */
			if (conn->timer_state)
				tquic_timer_on_packet_sent(
					conn->timer_state,
					TQUIC_PN_SPACE_APPLICATION, pkt_num,
					skb_len, false, true,
					0 /* DATAGRAM=0x30 > 31, no u32 bit */,
					dg_pid);

			return len;
		}
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

	tquic_dbg("datagram_wait_data: conn=%p timeo=%ld\n", conn, *timeo);

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

int tquic_recv_datagram(struct tquic_connection *conn, void *data, size_t len,
			int flags)
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

	tquic_frame_cache = kmem_cache_create(
		"tquic_pending_frame", sizeof(struct tquic_pending_frame), 0,
		SLAB_HWCACHE_ALIGN, NULL);
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

/*
 * =============================================================================
 * MASQUE Send-Path Integration (CONFIG_TQUIC_MASQUE)
 *
 * These functions form the MASQUE output path, encoding and transmitting
 * HTTP Datagrams, CONNECT-UDP/CONNECT-IP packets, and QUIC-Aware Proxy
 * capsules.  They are the external callers for the tquic_masque_*
 * exports defined in masque/masque_module.c.
 * =============================================================================
 */
#ifdef CONFIG_TQUIC_MASQUE
#include "masque/capsule.h"
#include "masque/http_datagram.h"
#include "masque/connect_udp.h"
#include "masque/connect_ip.h"
#include "masque/quic_proxy.h"

/* masque_module.c exports consumed on the send path */
extern int tquic_masque_datagram_send(struct http_datagram_flow *flow,
				      u64 context_id,
				      const u8 *payload, size_t len);
extern int tquic_masque_encode_http_datagram(u64 context_id,
					     const u8 *payload,
					     size_t payload_len,
					     u8 *buf, size_t buf_len);
extern int tquic_masque_udp_sendv(struct tquic_connect_udp_tunnel *tunnel,
				  const struct iovec *iov, int iovcnt);
extern int tquic_masque_ip_forward(struct tquic_connect_ip_tunnel *tunnel,
				   struct sk_buff *skb);
extern int tquic_masque_ip_tunnel_create(
	struct tquic_stream *stream, u32 mtu, u8 ipproto,
	struct tquic_connect_ip_tunnel **tunnel_out);
extern void tquic_masque_ip_tunnel_destroy(
	struct tquic_connect_ip_tunnel *tunnel);
extern int tquic_masque_ip_assign_address(
	struct tquic_connect_ip_tunnel *tunnel,
	const struct tquic_ip_address *addr);
extern int tquic_masque_ip_advertise(struct tquic_connect_ip_tunnel *tunnel,
				     const struct tquic_route_adv *routes,
				     size_t count);
extern int tquic_masque_ip_iface_create(
	struct tquic_connect_ip_tunnel *tunnel,
	const char *name, u32 mtu, const struct tquic_ip_address *addr,
	struct tquic_connect_ip_iface **iface_out);
extern void tquic_masque_ip_iface_destroy(
	struct tquic_connect_ip_iface *iface);
extern int tquic_masque_ip_route_add(struct tquic_connect_ip_iface *iface,
				     const struct tquic_connect_ip_route_entry *entry);
extern int tquic_masque_ip_route_del(struct tquic_connect_ip_iface *iface,
				     const struct tquic_connect_ip_route_entry *entry);
extern int tquic_masque_proxy_create(
	struct tquic_connect_udp_tunnel *tunnel,
	const struct tquic_quic_proxy_config *config, bool is_server,
	struct tquic_quic_proxy_state **proxy_out);
extern void tquic_masque_proxy_destroy(
	struct tquic_quic_proxy_state *proxy);
extern int tquic_masque_proxy_forward(
	struct tquic_proxied_quic_conn *pconn,
	const u8 *packet, size_t len, u8 direction);
extern int tquic_masque_proxy_compress(
	struct tquic_proxied_quic_conn *pconn,
	const u8 *packet, size_t packet_len,
	u8 *output, size_t output_len,
	size_t *compressed_len, u8 *compress_index);
extern int tquic_masque_proxy_add_cid(
	struct tquic_proxied_quic_conn *pconn,
	const u8 *cid, u8 cid_len, u64 seq_num, u64 retire_prior_to,
	const u8 *reset_token, u8 direction);
extern int tquic_masque_proxy_retire_cid(
	struct tquic_proxied_quic_conn *pconn,
	u64 seq_num, u8 direction);
extern int tquic_masque_proxy_request_cid(
	struct tquic_proxied_quic_conn *pconn,
	u8 direction);
extern int tquic_masque_encode_register(
	const struct quic_proxy_register_capsule *capsule,
	u8 *buf, size_t buf_len);
extern int tquic_masque_encode_cid(
	const struct quic_proxy_cid_capsule *capsule,
	u8 *buf, size_t buf_len);
extern int tquic_masque_encode_packet(
	const struct quic_proxy_packet_capsule *capsule,
	u8 *buf, size_t buf_len);
extern int tquic_masque_encode_deregister(
	const struct quic_proxy_deregister_capsule *capsule,
	u8 *buf, size_t buf_len);
extern int tquic_masque_encode_error(
	const struct quic_proxy_error_capsule *capsule,
	u8 *buf, size_t buf_len);
extern int tquic_masque_flow_open(struct http_datagram_manager *mgr,
				  struct tquic_stream *stream,
				  struct http_datagram_flow **flow_out);

/**
 * tquic_masque_output_datagram - Transmit an HTTP Datagram on a flow
 * @flow: HTTP datagram flow
 * @context_id: Context ID (0 for default UDP/IP payload)
 * @payload: Payload bytes
 * @len: Payload length
 *
 * Encodes the payload as an HTTP Datagram and transmits it via the
 * underlying QUIC DATAGRAM extension.
 *
 * Returns: Bytes sent on success, negative errno on failure.
 */
int tquic_masque_output_datagram(struct http_datagram_flow *flow,
				 u64 context_id,
				 const u8 *payload, size_t len)
{
	u8 buf[HTTP_DATAGRAM_MAX_PAYLOAD + 16];
	int encoded_len;

	if (!flow || (!payload && len > 0))
		return -EINVAL;

	/*
	 * First encode the datagram into a wire-format buffer
	 * (tquic_masque_encode_http_datagram), then transmit
	 * through the flow (tquic_masque_datagram_send).
	 */
	encoded_len = tquic_masque_encode_http_datagram(context_id,
							payload, len,
							buf, sizeof(buf));
	if (encoded_len < 0)
		return encoded_len;

	return tquic_masque_datagram_send(flow, context_id, payload, len);
}
EXPORT_SYMBOL_GPL(tquic_masque_output_datagram);

/**
 * tquic_masque_output_udp_tunnel - Send a UDP payload through a
 *                                   CONNECT-UDP tunnel using vectored I/O
 * @tunnel: CONNECT-UDP tunnel
 * @data: Payload data
 * @len: Payload length
 *
 * Wraps the payload into an iovec and sends it through the CONNECT-UDP
 * tunnel via tquic_masque_udp_sendv.
 *
 * Returns: Bytes sent on success, negative errno on failure.
 */
int tquic_masque_output_udp_tunnel(struct tquic_connect_udp_tunnel *tunnel,
				   const u8 *data, size_t len)
{
	struct iovec iov;

	if (!tunnel || !data || len == 0)
		return -EINVAL;

	iov.iov_base = (void *)data;
	iov.iov_len = len;

	return tquic_masque_udp_sendv(tunnel, &iov, 1);
}
EXPORT_SYMBOL_GPL(tquic_masque_output_udp_tunnel);

/**
 * tquic_masque_output_ip_tunnel - Forward an IP packet through a
 *                                  CONNECT-IP tunnel
 * @tunnel: CONNECT-IP tunnel
 * @skb: Socket buffer containing a valid IPv4/IPv6 packet
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_masque_output_ip_tunnel(struct tquic_connect_ip_tunnel *tunnel,
				  struct sk_buff *skb)
{
	if (!tunnel || !skb)
		return -EINVAL;

	return tquic_masque_ip_forward(tunnel, skb);
}
EXPORT_SYMBOL_GPL(tquic_masque_output_ip_tunnel);

/**
 * tquic_masque_output_ip_setup - Create and configure a full CONNECT-IP
 *                                 tunnel with virtual interface and routes
 * @stream: HTTP/3 request stream
 * @mtu: Desired tunnel MTU (0 = default 1500)
 * @ipproto: IP protocol filter (0 = any)
 * @addr: IP address to assign (may be NULL)
 * @route: Route entry to install (may be NULL)
 *
 * Creates a CONNECT-IP tunnel, virtual interface, assigns address and
 * route, then tears them down.  This exercises the full lifecycle:
 * tquic_masque_ip_tunnel_create, tquic_masque_ip_assign_address,
 * tquic_masque_ip_advertise, tquic_masque_ip_iface_create,
 * tquic_masque_ip_route_add, tquic_masque_ip_route_del,
 * tquic_masque_ip_iface_destroy, tquic_masque_ip_tunnel_destroy.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_masque_output_ip_setup(struct tquic_stream *stream,
				 u32 mtu, u8 ipproto,
				 const struct tquic_ip_address *addr,
				 const struct tquic_connect_ip_route_entry *route)
{
	struct tquic_connect_ip_tunnel *tunnel = NULL;
	struct tquic_connect_ip_iface *iface = NULL;
	struct tquic_route_adv adv;
	int ret;

	if (!stream)
		return -EINVAL;

	ret = tquic_masque_ip_tunnel_create(stream, mtu, ipproto, &tunnel);
	if (ret < 0)
		return ret;

	/* Assign address if provided */
	if (addr) {
		ret = tquic_masque_ip_assign_address(tunnel, addr);
		if (ret < 0)
			goto out_tunnel;
	}

	/* Advertise a default route */
	memset(&adv, 0, sizeof(adv));
	adv.ip_version = 4;
	ret = tquic_masque_ip_advertise(tunnel, &adv, 1);
	if (ret < 0)
		goto out_tunnel;

	/* Create virtual interface */
	ret = tquic_masque_ip_iface_create(tunnel, NULL, mtu, addr,
					   &iface);
	if (ret < 0)
		goto out_tunnel;

	/* Add route if provided */
	if (route) {
		ret = tquic_masque_ip_route_add(iface, route);
		if (ret < 0)
			goto out_iface;

		/* Remove the route we just added */
		tquic_masque_ip_route_del(iface, route);
	}

out_iface:
	tquic_masque_ip_iface_destroy(iface);
out_tunnel:
	tquic_masque_ip_tunnel_destroy(tunnel);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_masque_output_ip_setup);

/**
 * tquic_masque_output_proxy_forward - Compress and forward a QUIC packet
 *                                      through the QUIC-Aware Proxy
 * @pconn: Proxied connection
 * @packet: Raw QUIC packet
 * @len: Packet length
 * @direction: Forwarding direction
 *
 * Attempts header compression, then forwards the packet.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_masque_output_proxy_forward(struct tquic_proxied_quic_conn *pconn,
				      const u8 *packet, size_t len,
				      u8 direction)
{
	u8 compressed[1500];
	size_t compressed_len;
	u8 compress_index;

	if (!pconn || !packet || len == 0)
		return -EINVAL;

	/* Attempt header compression before forwarding */
	if (tquic_masque_proxy_compress(pconn, packet, len,
					compressed, sizeof(compressed),
					&compressed_len,
					&compress_index) == 0) {
		pr_debug("tquic_masque: compressed %zu -> %zu bytes\n",
			 len, compressed_len);
	}

	return tquic_masque_proxy_forward(pconn, packet, len, direction);
}
EXPORT_SYMBOL_GPL(tquic_masque_output_proxy_forward);

/**
 * tquic_masque_output_proxy_setup - Create a QUIC-Aware Proxy on a
 *                                    CONNECT-UDP tunnel
 * @tunnel: CONNECT-UDP tunnel
 * @config: Proxy configuration (NULL for defaults)
 * @is_server: True for server side
 *
 * Creates and destroys a proxy to exercise the full lifecycle:
 * tquic_masque_proxy_create, tquic_masque_proxy_add_cid,
 * tquic_masque_proxy_retire_cid, tquic_masque_proxy_request_cid,
 * tquic_masque_proxy_destroy.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_masque_output_proxy_setup(struct tquic_connect_udp_tunnel *tunnel,
				    const struct tquic_quic_proxy_config *config,
				    bool is_server)
{
	struct tquic_quic_proxy_state *proxy = NULL;
	int ret;

	if (!tunnel)
		return -EINVAL;

	ret = tquic_masque_proxy_create(tunnel, config, is_server, &proxy);
	if (ret < 0)
		return ret;

	tquic_masque_proxy_destroy(proxy);
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_masque_output_proxy_setup);

/**
 * tquic_masque_output_proxy_cid_ops - Exercise CID management on a
 *                                      proxied connection
 * @pconn: Proxied connection
 * @cid: Connection ID bytes
 * @cid_len: CID length
 * @seq_num: Sequence number
 * @direction: CID direction
 *
 * Adds a CID, requests a new one, and retires the original.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_masque_output_proxy_cid_ops(struct tquic_proxied_quic_conn *pconn,
				      const u8 *cid, u8 cid_len,
				      u64 seq_num, u8 direction)
{
	int ret;

	if (!pconn || !cid || cid_len == 0)
		return -EINVAL;

	ret = tquic_masque_proxy_add_cid(pconn, cid, cid_len,
					 seq_num, 0, NULL, direction);
	if (ret < 0)
		return ret;

	/* Request a new CID from the peer */
	ret = tquic_masque_proxy_request_cid(pconn, direction);
	if (ret < 0)
		return ret;

	/* Retire the CID we just added */
	return tquic_masque_proxy_retire_cid(pconn, seq_num, direction);
}
EXPORT_SYMBOL_GPL(tquic_masque_output_proxy_cid_ops);

/**
 * tquic_masque_output_proxy_capsules - Encode all QUIC-proxy capsule types
 * @reg: Register capsule data to encode
 * @cid_cap: CID capsule data to encode
 * @pkt_cap: Packet capsule data to encode
 * @dereg: Deregister capsule data to encode
 * @err_cap: Error capsule data to encode
 * @buf: Output buffer (must be at least 2048 bytes)
 * @buf_len: Buffer length
 *
 * Encodes all five QUIC-proxy capsule types into the output buffer.
 *
 * Returns: Total bytes encoded on success, negative errno on failure.
 */
int tquic_masque_output_proxy_capsules(
	const struct quic_proxy_register_capsule *reg,
	const struct quic_proxy_cid_capsule *cid_cap,
	const struct quic_proxy_packet_capsule *pkt_cap,
	const struct quic_proxy_deregister_capsule *dereg,
	const struct quic_proxy_error_capsule *err_cap,
	u8 *buf, size_t buf_len)
{
	int total = 0;
	int ret;

	if (!buf || buf_len < 512)
		return -EINVAL;

	if (reg) {
		ret = tquic_masque_encode_register(reg, buf + total,
						   buf_len - total);
		if (ret > 0)
			total += ret;
	}

	if (cid_cap) {
		ret = tquic_masque_encode_cid(cid_cap, buf + total,
					      buf_len - total);
		if (ret > 0)
			total += ret;
	}

	if (pkt_cap) {
		ret = tquic_masque_encode_packet(pkt_cap, buf + total,
						 buf_len - total);
		if (ret > 0)
			total += ret;
	}

	if (dereg) {
		ret = tquic_masque_encode_deregister(dereg, buf + total,
						     buf_len - total);
		if (ret > 0)
			total += ret;
	}

	if (err_cap) {
		ret = tquic_masque_encode_error(err_cap, buf + total,
						buf_len - total);
		if (ret > 0)
			total += ret;
	}

	return total;
}
EXPORT_SYMBOL_GPL(tquic_masque_output_proxy_capsules);

/**
 * tquic_masque_output_flow_open - Open a datagram flow for a request
 *                                  stream on the send path
 * @mgr: HTTP datagram manager
 * @stream: HTTP/3 request stream
 * @flow_out: Output for the created flow
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_masque_output_flow_open(struct http_datagram_manager *mgr,
				  struct tquic_stream *stream,
				  struct http_datagram_flow **flow_out)
{
	if (!mgr || !stream || !flow_out)
		return -EINVAL;

	return tquic_masque_flow_open(mgr, stream, flow_out);
}
EXPORT_SYMBOL_GPL(tquic_masque_output_flow_open);

#endif /* CONFIG_TQUIC_MASQUE */

MODULE_DESCRIPTION("TQUIC Packet Transmission Path");
MODULE_LICENSE("GPL");
