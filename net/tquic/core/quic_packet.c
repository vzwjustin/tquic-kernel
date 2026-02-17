// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * TQUIC - True QUIC with WAN Bonding
 *
 * Packet processing implementation
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 */

#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/unaligned.h>
#include <linux/rcupdate.h>
#include <crypto/utils.h>
#include <net/tquic.h>
#include <net/tquic_frame.h>
#include "../diag/trace.h"
#include "../tquic_debug.h"
#include "tquic_crypto.h"
#include "ack.h"

/* TQUIC packet header forms */
#define TQUIC_HEADER_FORM_LONG	0x80
#define TQUIC_HEADER_FORM_SHORT	0x00
#define TQUIC_FIXED_BIT		0x40

/* Long header packet types */
#define TQUIC_LONG_TYPE_INITIAL		0x00
#define TQUIC_LONG_TYPE_0RTT		0x01
#define TQUIC_LONG_TYPE_HANDSHAKE	0x02
#define TQUIC_LONG_TYPE_RETRY		0x03

/* Crypto levels (mapping to PN spaces) - defined in tquic_crypto.h */

/* Packet types for SKB CB */
#define TQUIC_PACKET_1RTT		4

/* Varint prefix for 2-byte encoding */
#define TQUIC_VARINT_2BYTE_PREFIX	0x40

/* Packet size constants */
#define TQUIC_MAX_PACKET_SIZE		1350
#define TQUIC_MIN_PACKET_SIZE		1200
#define TQUIC_MAX_CONNECTION_ID_LEN	20
#define TQUIC_ACK_MAX_RANGES		256

/* Error codes */
#define TQUIC_ERROR_FLOW_CONTROL_ERROR	0x03

/* struct tquic_skb_cb and TQUIC_SKB_CB are defined in tquic_crypto.h */

/* Forward declarations for internal functions */
static void tquic_packet_process_retry(struct tquic_connection *conn,
				       struct sk_buff *skb);
static int tquic_frame_process_crypto(struct tquic_connection *conn,
				      const u8 *data, int len, u8 level);
static int tquic_frame_process_stream(struct tquic_connection *conn,
				      const u8 *data, int len);
static int tquic_frame_process_ack(struct tquic_connection *conn,
				   const u8 *data, int len, u8 level);
static int tquic_frame_process_new_cid(struct tquic_connection *conn,
				       const u8 *data, int len);

static struct tquic_path *tquic_packet_active_path_get(struct tquic_connection *conn)
{
	struct tquic_path *path;

	rcu_read_lock();
	path = rcu_dereference(conn->active_path);
	if (path && !tquic_path_get(path))
		path = NULL;
	rcu_read_unlock();

	return path;
}
static int tquic_frame_process_connection_close(struct tquic_connection *conn,
						const u8 *data, int len);

/*
 * Forward declarations for internal functions that need prototypes.
 * Most external functions are declared in <net/tquic.h>.
 */
int tquic_varint_decode(const u8 *data, size_t len, u64 *value);
int tquic_varint_encode(u64 value, u8 *buf, size_t len);
int tquic_varint_len(u64 value);
void tquic_ack_on_packet_received(struct tquic_connection *conn, u64 pn, u8 level);
int tquic_ack_frequency_process(struct tquic_connection *conn, const u8 *data, int len);
int tquic_immediate_ack_process(struct tquic_connection *conn);
void tquic_loss_detection_on_packet_sent(struct tquic_connection *conn,
					 struct tquic_sent_packet *pkt);
void tquic_loss_detection_on_ack_received(struct tquic_connection *conn,
					  struct tquic_ack_frame *ack,
					  u8 pn_space_idx);
/* tquic_crypto_* functions declared in tquic_crypto.h */
int tquic_flow_check_recv_limits(struct tquic_stream *stream, u64 offset, u64 len);
void tquic_stream_handle_reset(struct tquic_stream *stream, u64 error_code, u64 final_size);
void tquic_stream_handle_stop_sending(struct tquic_stream *stream, u64 error_code);

/*
 * quic_packet_deliver_stream_data - Internal helper to deliver raw data to stream
 *
 * This is a simplified internal function for frame processing. The full
 * tquic_stream_recv_data() in core/stream.c handles SKBs and stream manager
 * interactions for the complete implementation.
 */
static void quic_packet_deliver_stream_data(struct tquic_stream *stream, u64 offset,
					    const u8 *data, u64 len, bool fin);

/* Forward declarations for functions defined later in this file */
int tquic_frame_process_all(struct tquic_connection *conn, struct sk_buff *skb, u8 level);
int tquic_frame_process_one(struct tquic_connection *conn, const u8 *data, int len, u8 level);

/* Stream lookup/create functions - internal implementations */
static struct tquic_stream *tquic_stream_lookup_internal(struct tquic_connection *conn, u64 stream_id);
static struct tquic_stream *tquic_stream_create_internal(struct tquic_connection *conn, u64 stream_id);

/*
 * Connection state constants
 */
#define TQUIC_STATE_CONNECTING	1
#define TQUIC_STATE_CONNECTED	3
#define TQUIC_STATE_DRAINING	5

/*
 * Internal connection structure fields accessed via offsets
 * This provides compatibility with the internal tquic_connection layout
 */
struct tquic_internal_conn {
	/* Matches the beginning of tquic_connection for basic fields */
	enum tquic_conn_state state;
	enum tquic_conn_role role;
	u32 version;
	struct tquic_cid scid;
	struct tquic_cid dcid;
	/* ... additional fields follow in actual struct */
};

/* Helper to get connection fields - these access internal state */
static inline u32 tquic_conn_get_version(struct tquic_connection *conn)
{
	return conn->version;
}

static inline bool tquic_conn_is_server(struct tquic_connection *conn)
{
	return conn->role == TQUIC_ROLE_SERVER;
}

/*
 * Stream lookup/create helpers
 * Streams are stored in an rb_tree indexed by stream ID
 */
static struct tquic_stream *tquic_stream_lookup_internal(struct tquic_connection *conn,
							 u64 stream_id)
{
	struct rb_node *node;

	spin_lock_bh(&conn->lock);
	node = conn->streams.rb_node;
	while (node) {
		struct tquic_stream *stream = rb_entry(node, struct tquic_stream, node);

		if (stream_id < stream->id)
			node = node->rb_left;
		else if (stream_id > stream->id)
			node = node->rb_right;
		else {
			spin_unlock_bh(&conn->lock);
			return stream;
		}
	}
	spin_unlock_bh(&conn->lock);
	return NULL;
}

static struct tquic_stream *tquic_stream_create_internal(struct tquic_connection *conn,
							 u64 stream_id)
{
	struct tquic_stream *stream;
	struct rb_node **link, *parent = NULL;

	stream = kzalloc(sizeof(*stream), GFP_ATOMIC);
	if (!stream)
		return NULL;

	stream->id = stream_id;
	stream->conn = conn;
	stream->state = TQUIC_STREAM_OPEN;
	skb_queue_head_init(&stream->send_buf);
	skb_queue_head_init(&stream->recv_buf);
	init_waitqueue_head(&stream->wait);

	/* Insert into rb_tree */
	spin_lock_bh(&conn->lock);
	link = &conn->streams.rb_node;
	while (*link) {
		struct tquic_stream *s = rb_entry(*link, struct tquic_stream, node);
		parent = *link;
		if (stream_id < s->id)
			link = &(*link)->rb_left;
		else
			link = &(*link)->rb_right;
	}
	rb_link_node(&stream->node, parent, link);
	rb_insert_color(&stream->node, &conn->streams);
	spin_unlock_bh(&conn->lock);

	return stream;
}

/*
 * Connection close helper - wraps the actual tquic function
 */
static inline int tquic_conn_close_internal(struct tquic_connection *conn,
					    u64 error_code, const char *reason,
					    u32 reason_len, bool app_error)
{
	/* Use the appropriate close function based on error type */
	if (app_error)
		return tquic_conn_close_app(conn, error_code, reason);
	else
		return tquic_conn_close_with_error(conn, error_code, reason);
}

/*
 * Connection ID retirement helper
 */
static inline void tquic_conn_retire_cid_internal(struct tquic_connection *conn, u64 seq)
{
	/* Call with is_local=false since we're retiring peer's CID */
	tquic_conn_retire_cid(conn, seq, false);
}

/*
 * quic_packet_deliver_stream_data - Internal simplified stream data delivery
 *
 * This function delivers raw received data to a stream for the frame processor.
 * It handles FIN flag and wakes up any readers waiting on the stream.
 *
 * For full stream receive handling with flow control and reassembly,
 * use tquic_stream_recv_data() from core/stream.c which takes an SKB.
 */
static void quic_packet_deliver_stream_data(struct tquic_stream *stream, u64 offset,
					    const u8 *data, u64 len, bool fin)
{
	struct sk_buff *skb, *iter;
	unsigned long flags;

	if (!stream || !data || len == 0)
		return;

	/*
	 * SECURITY: alloc_skb() takes an unsigned int size parameter.
	 * len is u64 from the stream frame; if it exceeds a reasonable
	 * limit the cast would silently truncate, allocating a tiny
	 * buffer while skb_put_data copies len bytes -- heap overflow.
	 *
	 * Cap at 16KB (max_stream_data typical limit) rather than U32_MAX
	 * for defense in depth.  Individual QUIC packets are at most
	 * ~1500 bytes (PMTU), so anything larger is suspect.
	 */
	if (len > 16384)
		return;

	/* Dedup: data already consumed by application is duplicate */
	if (offset + len <= stream->recv_consumed)
		return;

	/* Trim consumed prefix */
	if (offset < stream->recv_consumed) {
		u64 trim = stream->recv_consumed - offset;

		data += trim;
		len -= trim;
		offset = stream->recv_consumed;
	}

	/* Allocate an skb to hold the data */
	skb = alloc_skb((unsigned int)len, GFP_ATOMIC);
	if (!skb)
		return;

	/* Copy data into the skb */
	skb_put_data(skb, data, len);

	/* Store offset for sorted insertion and contiguous delivery */
	put_unaligned(offset, (u64 *)skb->cb);

	/*
	 * Insert in offset-sorted order.  Walk from tail for O(1)
	 * in-order case.  Reject overlaps as duplicates.
	 */
	spin_lock_irqsave(&stream->recv_buf.lock, flags);

	skb_queue_reverse_walk(&stream->recv_buf, iter) {
		u64 iter_off = get_unaligned((u64 *)iter->cb);
		u64 iter_end = iter_off + iter->len;

		if (offset >= iter_end) {
			__skb_queue_after(&stream->recv_buf, iter, skb);
			goto inserted;
		}
		if (offset + len > iter_off && offset < iter_end) {
			/* Overlap — duplicate */
			spin_unlock_irqrestore(&stream->recv_buf.lock,
					       flags);
			kfree_skb(skb);
			return;
		}
	}

	__skb_queue_head(&stream->recv_buf, skb);

inserted:
	spin_unlock_irqrestore(&stream->recv_buf.lock, flags);

	/* Track highest byte offset seen */
	if (offset + len > stream->recv_offset)
		stream->recv_offset = offset + len;

	/* Update stream state */
	if (fin) {
		stream->fin_received = 1;
		stream->final_size = offset + len;
	}

	/* Wake up any waiting readers */
	wake_up_interruptible(&stream->wait);
}

/* Parse long header packet */
static int tquic_packet_parse_long(struct sk_buff *skb, u8 first_byte)
{
	struct tquic_skb_cb *cb = TQUIC_SKB_CB(skb);
	u8 *data = skb->data;
	int offset = 1;
	tquic_dbg("tquic_packet_parse_long: skb_len=%u first=0x%02x\n",
		  skb->len, first_byte);
	u32 version;
	u8 dcid_len, scid_len;
	u64 token_len = 0;
	u64 payload_len;

	if (skb->len < 7)
		return -EINVAL;

	/* Version (4 bytes) */
	version = ((u32)data[1] << 24) | ((u32)data[2] << 16) |
		  ((u32)data[3] << 8) | data[4];
	offset = 5;

	/* Destination Connection ID Length (1 byte) */
	dcid_len = data[offset++];
	if (dcid_len > TQUIC_MAX_CONNECTION_ID_LEN)
		return -EINVAL;

	if (skb->len < offset + dcid_len)
		return -EINVAL;

	cb->dcid_len = dcid_len;
	offset += dcid_len;

	/* Source Connection ID Length (1 byte) */
	if (skb->len < offset + 1)
		return -EINVAL;

	scid_len = data[offset++];
	if (scid_len > TQUIC_MAX_CONNECTION_ID_LEN)
		return -EINVAL;

	cb->scid_len = scid_len;
	if (skb->len < offset + scid_len)
		return -EINVAL;

	offset += scid_len;

	/* Packet type specific handling */
	cb->packet_type = (first_byte & 0x30) >> 4;

	switch (cb->packet_type) {
	case TQUIC_LONG_TYPE_INITIAL:
		/* Token Length (variable) */
		if (skb->len < offset + 1)
			return -EINVAL;

		{
			int varint_len = tquic_varint_decode(data + offset,
							     skb->len - offset,
							     &token_len);
			if (varint_len < 0)
				return varint_len;
			offset += varint_len;
		}

		/* Skip token */
		if (skb->len < offset + token_len)
			return -EINVAL;
		offset += token_len;
		break;

	case TQUIC_LONG_TYPE_0RTT:
	case TQUIC_LONG_TYPE_HANDSHAKE:
		/* No token field */
		break;

	case TQUIC_LONG_TYPE_RETRY:
		/* Retry packet has different format */
		cb->header_len = offset;
		return 0;

	default:
		return -EINVAL;
	}

	/* Payload Length (variable) */
	if (skb->len < offset + 1)
		return -EINVAL;

	{
		int varint_len = tquic_varint_decode(data + offset,
						     skb->len - offset,
						     &payload_len);
		if (varint_len < 0)
			return varint_len;
		offset += varint_len;
	}

	/*
	 * Validate payload length per RFC 9000 Section 12.2.
	 * The payload_len field indicates the length of the rest of the packet
	 * (packet number + encrypted payload + AEAD tag). It must not extend
	 * beyond the received packet data.
	 *
	 * Note: payload_len < remaining is allowed per RFC 9000 Section 12.2
	 * which permits coalesced packets. The peer may have combined multiple
	 * QUIC packets into a single UDP datagram.
	 */
	if (payload_len > skb->len - offset)
		return -EINVAL;

	/* Packet Number (1-4 bytes, encoded in pn_len after header unprotection) */
	cb->header_len = offset;

	return 0;
}

/* Parse short header packet */
static int tquic_packet_parse_short(struct sk_buff *skb, u8 first_byte,
				    u8 expected_dcid_len)
{
	struct tquic_skb_cb *cb = TQUIC_SKB_CB(skb);
	int offset = 1;

	cb->packet_type = TQUIC_PACKET_1RTT;
	cb->dcid_len = expected_dcid_len;
	cb->scid_len = 0;

	if (skb->len < 1 + expected_dcid_len)
		return -EINVAL;

	offset += expected_dcid_len;
	cb->header_len = offset;

	return 0;
}

/*
 * tquic_packet_get_length - Get the total length of a TQUIC packet in a buffer
 * @data: Pointer to the start of the TQUIC packet
 * @len: Total length of available data
 * @packet_len: Output parameter for the packet length
 *
 * Per RFC 9000 Section 12.2, multiple QUIC packets can be coalesced into a
 * single UDP datagram. This function determines the length of the first
 * packet so subsequent packets can be separated and processed.
 *
 * For long header packets, the length is determined by the Length field.
 * For short header packets, the entire remaining buffer is the packet.
 *
 * Returns 0 on success, negative error code on failure.
 */
static int tquic_packet_get_length(const u8 *data, int len, int *packet_len)
{
	int offset = 1;
	u8 first_byte;
	tquic_dbg("tquic_packet_get_length: len=%d\n", len);
	u8 dcid_len, scid_len;
	u8 packet_type;
	u64 token_len = 0;
	u64 payload_len;
	int varint_len;

	if (len < 1)
		return -EINVAL;

	first_byte = data[0];

	/* Validate fixed bit per RFC 9000 Section 17.2 */
	if (!(first_byte & TQUIC_FIXED_BIT))
		return -EINVAL;

	/* Short header packet consumes the entire remaining buffer */
	if (!(first_byte & TQUIC_HEADER_FORM_LONG)) {
		*packet_len = len;
		return 0;
	}

	/* Long header packet - parse to find Length field */
	if (len < 7)
		return -EINVAL;

	/* Skip version (4 bytes) */
	offset = 5;

	/* Destination Connection ID Length (1 byte) */
	dcid_len = data[offset++];
	if (dcid_len > TQUIC_MAX_CONNECTION_ID_LEN)
		return -EINVAL;

	if (len < offset + dcid_len + 1)
		return -EINVAL;
	offset += dcid_len;

	/* Source Connection ID Length (1 byte) */
	scid_len = data[offset++];
	if (scid_len > TQUIC_MAX_CONNECTION_ID_LEN)
		return -EINVAL;

	if (len < offset + scid_len)
		return -EINVAL;
	offset += scid_len;

	/* Packet type specific handling */
	packet_type = (first_byte & 0x30) >> 4;

	switch (packet_type) {
	case TQUIC_LONG_TYPE_INITIAL:
		/* Token Length (variable) */
		if (len < offset + 1)
			return -EINVAL;

		varint_len = tquic_varint_decode(data + offset, len - offset,
						 &token_len);
		if (varint_len < 0)
			return varint_len;
		offset += varint_len;

		/* Validate and skip token */
		if (token_len > len - offset)
			return -EINVAL;
		offset += token_len;
		break;

	case TQUIC_LONG_TYPE_0RTT:
	case TQUIC_LONG_TYPE_HANDSHAKE:
		/* No token field */
		break;

	case TQUIC_LONG_TYPE_RETRY:
		/*
		 * Retry packets don't have a Length field and cannot be
		 * coalesced with other packets per RFC 9000.
		 */
		*packet_len = len;
		return 0;

	default:
		return -EINVAL;
	}

	/* Payload Length (variable) */
	if (len < offset + 1)
		return -EINVAL;

	varint_len = tquic_varint_decode(data + offset, len - offset,
					 &payload_len);
	if (varint_len < 0)
		return varint_len;
	offset += varint_len;

	/*
	 * Validate payload length per RFC 9000 Section 12.2.
	 * The packet length is the header (up to and including Length field)
	 * plus the payload length value.
	 */
	if (payload_len > len - offset)
		return -EINVAL;

	/* Guard against u64 -> int truncation */
	if (payload_len > INT_MAX - offset)
		return -EINVAL;

	*packet_len = offset + payload_len;
	return 0;
}

int tquic_packet_parse(struct sk_buff *skb, struct tquic_packet *pkt)
{
	u8 first_byte;
	int err;

	tquic_dbg("tquic_packet_parse: skb_len=%u\n", skb->len);
	if (skb->len < 1)
		return -EINVAL;

	first_byte = skb->data[0];

	/* Check fixed bit */
	if (!(first_byte & TQUIC_FIXED_BIT))
		return -EINVAL;

	memset(TQUIC_SKB_CB(skb), 0, sizeof(struct tquic_skb_cb));

	if (first_byte & TQUIC_HEADER_FORM_LONG) {
		err = tquic_packet_parse_long(skb, first_byte);
	} else {
		/* For short header, use expected DCID length from packet */
		err = tquic_packet_parse_short(skb, first_byte, pkt->hdr.dcid_len);
	}

	return err;
}

/* Decode packet number from truncated form */
static u64 tquic_decode_pn(u64 largest_pn, u64 truncated_pn, u8 pn_len)
{
	u64 expected_pn = largest_pn + 1;
	u64 pn_win = 1ULL << (pn_len * 8);
	u64 pn_hwin = pn_win / 2;
	u64 pn_mask = pn_win - 1;
	u64 candidate_pn;

	candidate_pn = (expected_pn & ~pn_mask) | truncated_pn;

	if (candidate_pn <= expected_pn - pn_hwin && candidate_pn < (1ULL << 62) - pn_win)
		return candidate_pn + pn_win;

	if (candidate_pn > expected_pn + pn_hwin && candidate_pn >= pn_win)
		return candidate_pn - pn_win;

	return candidate_pn;
}

/* Extract truncated packet number */
static u64 tquic_extract_pn(const u8 *data, u8 pn_len)
{
	u64 pn = 0;
	int i;

	for (i = 0; i < pn_len; i++)
		pn = (pn << 8) | data[i];

	return pn;
}

/*
 * tquic_packet_process - Process a UDP datagram that may contain coalesced
 *                        TQUIC packets per RFC 9000 Section 12.2
 * @conn: TQUIC connection
 * @skb: Socket buffer containing the UDP datagram payload
 *
 * Per RFC 9000 Section 12.2, multiple QUIC packets at different encryption
 * levels can be coalesced into a single UDP datagram. This function:
 * 1. Determines the length of the first packet using tquic_packet_get_length()
 * 2. Processes the first packet
 * 3. If there's remaining data, recursively processes the next packet
 *
 * This is particularly important during the handshake when Initial and
 * Handshake packets are often coalesced together.
 */
int tquic_packet_process(struct tquic_connection *conn, struct sk_buff *skb)
{
	u8 first_byte;
	u8 pn_offset, pn_len;
	u64 truncated_pn, pn;
	u8 level;
	int err;
	int packet_len;
	struct sk_buff *next_skb;
	tquic_dbg("tquic_packet_process: skb_len=%u\n", skb->len);
	/*
	 * Max coalesced packet depth: one per encryption level
	 * (Initial, 0-RTT, Handshake, Application = 4).
	 * This bounds stack usage and prevents malicious datagrams
	 * from causing deep iteration.
	 */
	int depth = 0;
	const int max_depth = 4;

	while (skb) {

	if (depth++ >= max_depth) {
		kfree_skb(skb);
		return -EINVAL;
	}

	if (skb->len < 1) {
		kfree_skb(skb);
		return -EINVAL;
	}

	first_byte = skb->data[0];

	/*
	 * RFC 9000 Section 12.2: Coalesced Packets
	 * Determine the length of this packet. For long header packets,
	 * this allows us to separate coalesced packets. For short header
	 * packets, the entire remaining datagram is this packet.
	 */
	err = tquic_packet_get_length(skb->data, skb->len, &packet_len);
	if (err) {
		kfree_skb(skb);
		return err;
	}

	/*
	 * Validate packet_len is within bounds.
	 * This should not happen given tquic_packet_get_length validation,
	 * but defense in depth is important for network code.
	 */
	if (packet_len < 1 || packet_len > skb->len) {
		kfree_skb(skb);
		return -EINVAL;
	}

	/*
	 * If there's data remaining after this packet, we have coalesced
	 * packets. Create a new skb for the remaining data and queue it
	 * for processing after we finish with this packet.
	 */
	next_skb = NULL;
	if (packet_len < skb->len) {
		int remaining = skb->len - packet_len;

		/*
		 * Validate remaining data has at least a header byte
		 * to prevent processing empty/corrupt trailing data.
		 */
		if (remaining >= 1) {
			next_skb = alloc_skb(remaining + 64, GFP_ATOMIC);
			if (next_skb) {
				skb_reserve(next_skb, 64);
				skb_put_data(next_skb, skb->data + packet_len,
					     remaining);
			}
			/* If allocation fails, we just lose the coalesced packet(s) */
		}
		/* Trim this skb to just the first packet */
		skb_trim(skb, packet_len);
	}

	/* Determine encryption level */
	if (first_byte & TQUIC_HEADER_FORM_LONG) {
		u8 packet_type = (first_byte & 0x30) >> 4;

		switch (packet_type) {
		case TQUIC_LONG_TYPE_INITIAL:
			level = TQUIC_CRYPTO_INITIAL;
			break;
		case TQUIC_LONG_TYPE_0RTT:
			level = TQUIC_CRYPTO_EARLY_DATA;
			break;
		case TQUIC_LONG_TYPE_HANDSHAKE:
			level = TQUIC_CRYPTO_HANDSHAKE;
			break;
		case TQUIC_LONG_TYPE_RETRY:
			/* Handle retry packet specially */
			tquic_packet_process_retry(conn, skb);
			goto process_next;
		default:
			kfree_skb(skb);
			goto process_next;
		}
	} else {
		level = TQUIC_CRYPTO_APPLICATION;
	}

	/*
	 * Note: The original code accessed conn->crypto[level].keys_available
	 * and other internal fields. In tquic, the crypto state is managed
	 * differently through conn->crypto_state. For now, we proceed with
	 * processing assuming keys are available at the appropriate level.
	 */

	/* Remove header protection */
	err = tquic_crypto_unprotect_header(conn->crypto_state, skb,
					    &pn_offset, &pn_len);
	if (err) {
		kfree_skb(skb);
		goto process_next;
	}

	/* Decode packet number */
	truncated_pn = tquic_extract_pn(skb->data + pn_offset, pn_len);
	pn = tquic_decode_pn(atomic64_read(&conn->pkt_num_rx),
			     truncated_pn, pn_len);

	TQUIC_SKB_CB(skb)->pn = pn;
	TQUIC_SKB_CB(skb)->pn_len = pn_len;
	TQUIC_SKB_CB(skb)->header_len = pn_offset + pn_len;

	/* Decrypt packet */
	err = tquic_crypto_decrypt(conn->crypto_state, skb, pn);
	if (err) {
		kfree_skb(skb);
		goto process_next;
	}

	/* Update largest received packet number */
	if (pn > atomic64_read(&conn->pkt_num_rx))
		atomic64_set(&conn->pkt_num_rx, pn);

	/* Record ACK for this packet */
	tquic_ack_on_packet_received(conn, pn, level);

	/* Process frames */
	tquic_frame_process_all(conn, skb, level);

	/* Update statistics - use WRITE_ONCE to avoid KCSAN data races */
	WRITE_ONCE(conn->stats.rx_packets,
		   READ_ONCE(conn->stats.rx_packets) + 1);
	WRITE_ONCE(conn->stats.rx_bytes,
		   READ_ONCE(conn->stats.rx_bytes) + skb->len);

	kfree_skb(skb);

process_next:
	/* Continue with any remaining coalesced packets */
	skb = next_skb;

	} /* end while (skb) */

	return 0;
}

static void tquic_packet_process_retry(struct tquic_connection *conn,
				       struct sk_buff *skb)
{
	u8 *data = skb->data;
	int offset = 5;  /* Skip first byte and version */
	u8 dcid_len, scid_len;
	struct tquic_cid new_scid;

	if (READ_ONCE(conn->state) != TQUIC_CONN_CONNECTING) {
		kfree_skb(skb);
		return;
	}

	/*
	 * SECURITY: Validate DCID length before using it as an offset.
	 * RFC 9000 limits CID to 20 bytes. A crafted dcid_len of 255
	 * would advance offset past the buffer boundary.
	 */
	if (skb->len < offset + 1)
		goto drop;
	dcid_len = data[offset++];
	if (dcid_len > TQUIC_MAX_CONNECTION_ID_LEN)
		goto drop;
	if (skb->len < offset + dcid_len + 1)
		goto drop;
	offset += dcid_len;

	/* Parse SCID - this becomes our new DCID */
	scid_len = data[offset++];
	if (scid_len > TQUIC_MAX_CID_LEN)
		goto drop;
	if (skb->len < offset + scid_len)
		goto drop;

	new_scid.len = scid_len;
	memcpy(new_scid.id, data + offset, scid_len);
	offset += scid_len;

	/* The rest is the retry token (minus 16-byte integrity tag) */
	if (skb->len - offset < 16)
		goto drop;

	/*
	 * Store token for retry - in tquic, token storage is managed
	 * through conn->token_state or via socket options.
	 * For now, we would need to access the socket's token storage.
	 */

	/* Update DCID for next Initial packet */
	memcpy(&conn->dcid, &new_scid, sizeof(conn->dcid));

	/* Re-derive initial secrets with new DCID */
	tquic_crypto_derive_initial_secrets(conn, &conn->dcid);

	/* Resend Initial packet */
	schedule_work(&conn->tx_work);

drop:
	kfree_skb(skb);
}

int tquic_frame_process_all(struct tquic_connection *conn, struct sk_buff *skb,
			    u8 level)
{
	u8 *data = skb->data + TQUIC_SKB_CB(skb)->header_len;
	int len = skb->len - TQUIC_SKB_CB(skb)->header_len;
	int offset = 0;

	while (offset < len) {
		int frame_len;

		frame_len = tquic_frame_process_one(conn, data + offset,
						    len - offset, level);
		if (frame_len < 0)
			return frame_len;

		offset += frame_len;
	}

	return 0;
}

int tquic_frame_process_one(struct tquic_connection *conn, const u8 *data,
			    int len, u8 level)
{
	u8 frame_type;
	int offset = 0;
	u64 val1, val2, val3;
	int varint_len;

	if (len < 1)
		return -EINVAL;

	frame_type = data[offset++];

	switch (frame_type) {
	case TQUIC_FRAME_PADDING:
		/* Skip all padding bytes */
		while (offset < len && data[offset] == 0)
			offset++;
		return offset;

	case TQUIC_FRAME_PING:
		/* PING frame is just the type byte */
		return 1;

	case TQUIC_FRAME_ACK:
	case TQUIC_FRAME_ACK_ECN:
		return tquic_frame_process_ack(conn, data, len, level);

	case TQUIC_FRAME_RESET_STREAM:
		/* Stream ID */
		varint_len = tquic_varint_decode(data + offset, len - offset, &val1);
		if (varint_len < 0)

			return varint_len;
		offset += varint_len;

		/* Application Protocol Error Code */
		varint_len = tquic_varint_decode(data + offset, len - offset, &val2);
		if (varint_len < 0)

			return varint_len;
		offset += varint_len;

		/* Final Size */
		varint_len = tquic_varint_decode(data + offset, len - offset, &val3);
		if (varint_len < 0)

			return varint_len;
		offset += varint_len;

		{
			struct tquic_stream *stream = tquic_stream_lookup_internal(conn, val1);
			if (stream) {
				tquic_stream_handle_reset(stream, val2, val3);
			}
		}
		return offset;

	case TQUIC_FRAME_STOP_SENDING:
		/* Stream ID */
		varint_len = tquic_varint_decode(data + offset, len - offset, &val1);
		if (varint_len < 0)

			return varint_len;
		offset += varint_len;

		/* Application Protocol Error Code */
		varint_len = tquic_varint_decode(data + offset, len - offset, &val2);
		if (varint_len < 0)

			return varint_len;
		offset += varint_len;

		{
			struct tquic_stream *stream = tquic_stream_lookup_internal(conn, val1);
			if (stream) {
				tquic_stream_handle_stop_sending(stream, val2);
			}
		}
		return offset;

	case TQUIC_FRAME_CRYPTO:
		return tquic_frame_process_crypto(conn, data, len, level);

	case TQUIC_FRAME_NEW_TOKEN:
		/* Length */
		varint_len = tquic_varint_decode(data + offset, len - offset, &val1);
		if (varint_len < 0)

			return varint_len;
		offset += varint_len;

		/* SECURITY: Use subtraction to avoid int + u64 overflow */
		if (val1 > len - offset)
			return -EINVAL;

		/* Store token - handled via token_state in tquic */
		offset += val1;
		return offset;

	case TQUIC_FRAME_STREAM_BASE ... TQUIC_FRAME_STREAM_MAX:
		return tquic_frame_process_stream(conn, data, len);

	case TQUIC_FRAME_MAX_DATA:
		varint_len = tquic_varint_decode(data + offset, len - offset, &val1);
		if (varint_len < 0)
			return varint_len;
		offset += varint_len;

		if (val1 > READ_ONCE(conn->max_data_remote)) {
			WRITE_ONCE(conn->max_data_remote, val1);
			/* Trigger TX to send data blocked by connection FC */
			schedule_work(&conn->tx_work);
		}
		return offset;

	case TQUIC_FRAME_MAX_STREAM_DATA:
		/* Stream ID */
		varint_len = tquic_varint_decode(data + offset, len - offset, &val1);
		if (varint_len < 0)

			return varint_len;
		offset += varint_len;

		/* Maximum Stream Data */
		varint_len = tquic_varint_decode(data + offset, len - offset, &val2);
		if (varint_len < 0)

			return varint_len;
		offset += varint_len;

		{
			struct tquic_stream *stream = tquic_stream_lookup_internal(conn, val1);

			if (stream && val2 > stream->max_send_data) {
				stream->max_send_data = val2;
				stream->blocked = false;
				wake_up_interruptible(&stream->wait);
				schedule_work(&conn->tx_work);
			}
		}
		return offset;

	case TQUIC_FRAME_MAX_STREAMS_BIDI:
		varint_len = tquic_varint_decode(data + offset, len - offset, &val1);
		if (varint_len < 0)

			return varint_len;
		offset += varint_len;

		if (val1 > READ_ONCE(conn->max_streams_bidi))
			WRITE_ONCE(conn->max_streams_bidi, val1);
		return offset;

	case TQUIC_FRAME_MAX_STREAMS_UNI:
		varint_len = tquic_varint_decode(data + offset, len - offset, &val1);
		if (varint_len < 0)

			return varint_len;
		offset += varint_len;

		if (val1 > READ_ONCE(conn->max_streams_uni))
			WRITE_ONCE(conn->max_streams_uni, val1);
		return offset;

	case TQUIC_FRAME_DATA_BLOCKED:
	case TQUIC_FRAME_STREAM_DATA_BLOCKED:
	case TQUIC_FRAME_STREAMS_BLOCKED_BIDI:
	case TQUIC_FRAME_STREAMS_BLOCKED_UNI:
		/* These are informational, just parse and skip */
		varint_len = tquic_varint_decode(data + offset, len - offset, &val1);
		if (varint_len < 0)

			return varint_len;
		offset += varint_len;

		if (frame_type == TQUIC_FRAME_STREAM_DATA_BLOCKED) {
			varint_len = tquic_varint_decode(data + offset, len - offset, &val2);
			if (varint_len < 0)

				return varint_len;
			offset += varint_len;
		}
		return offset;

	case TQUIC_FRAME_NEW_CONNECTION_ID:
		return tquic_frame_process_new_cid(conn, data, len);

	case TQUIC_FRAME_RETIRE_CONNECTION_ID:
		varint_len = tquic_varint_decode(data + offset, len - offset, &val1);
		if (varint_len < 0)

			return varint_len;
		offset += varint_len;

		tquic_conn_retire_cid_internal(conn, val1);
		return offset;

	case TQUIC_FRAME_PATH_CHALLENGE:
		if (len < offset + 8)
			return -EINVAL;
		/* Echo back as PATH_RESPONSE per RFC 9000 Section 8.2.2 */
		{
			struct sk_buff *resp;
			u8 *p;

			/*
			 * Rate-limit PATH_CHALLENGE responses to prevent
			 * memory exhaustion from attacker-generated challenges.
			 * Cap the control frame queue at 64 entries.
			 */
			if (skb_queue_len(&conn->control_frames) >= 64) {
				net_warn_ratelimited("TQUIC: PATH_CHALLENGE rate limited\n");
				return offset + 8;
			}

			resp = alloc_skb(16, GFP_ATOMIC);
			if (!resp) {
				net_warn_ratelimited("TQUIC: failed to allocate PATH_RESPONSE\n");
				return -ENOMEM;
			}
			p = skb_put(resp, 9);
			p[0] = TQUIC_FRAME_PATH_RESPONSE;
			memcpy(p + 1, data + offset, 8);
			skb_queue_tail(&conn->control_frames, resp);
		}
		return offset + 8;

	case TQUIC_FRAME_PATH_RESPONSE:
		if (len < offset + 8)
			return -EINVAL;
		/* Validate path challenge response */
		{
			struct tquic_path *path = tquic_packet_active_path_get(conn);

			if (path && READ_ONCE(path->validation.challenge_pending)) {
				if (!crypto_memneq(data + offset,
						   path->validation.challenge_data, 8)) {
					WRITE_ONCE(path->state, TQUIC_PATH_VALIDATED);
					WRITE_ONCE(path->validation.challenge_pending, 0);
				}
			}
			if (path)
				tquic_path_put(path);
		}
		return offset + 8;

	case TQUIC_FRAME_CONNECTION_CLOSE:
	case TQUIC_FRAME_CONNECTION_CLOSE_APP:
		return tquic_frame_process_connection_close(conn, data, len);

	case TQUIC_FRAME_HANDSHAKE_DONE:
		if (conn->role == TQUIC_ROLE_CLIENT) {
			set_bit(TQUIC_CONN_FLAG_HANDSHAKE_DONE, &conn->flags);
			if (READ_ONCE(conn->state) == TQUIC_CONN_CONNECTING)
				tquic_conn_set_state(conn, TQUIC_CONN_CONNECTED,
						     TQUIC_REASON_NORMAL);
		}
		return 1;

	case TQUIC_FRAME_DATAGRAM:
	case TQUIC_FRAME_DATAGRAM_LEN:
		/*
		 * DATAGRAM frames (RFC 9221) - unreliable, unordered data.
		 */
		{
			u8 ftype = data[0];
			bool has_length = (ftype & 0x01) != 0;
			u64 datagram_len;
			int vlen;
			int off = 1;

			if (has_length) {
				/* Type 0x31: datagram length is explicit */
				vlen = tquic_varint_decode(data + off,
							   len - off,
							   &datagram_len);
				if (vlen < 0)
					return vlen;
				off += vlen;

				/*
				 * SECURITY: Use subtraction to avoid
				 * int + u64 overflow on 32-bit systems.
				 */
				if (datagram_len > len - off)
					return -EINVAL;

				off += datagram_len;
			} else {
				/* Type 0x30: datagram extends to end of packet */
				off = len;
			}

			return off;
		}

	default:
		/*
		 * Check for ACK_FREQUENCY frame (type 0xaf).
		 * This is a 2-byte varint frame type, so we need to check
		 * if we have a multi-byte frame type starting with 0x40.
		 */
		if (frame_type == 0x40 && len >= 2 && data[1] == 0xaf) {
			/*
			 * ACK_FREQUENCY frame (draft-ietf-quic-ack-frequency)
			 * Skip the 2-byte frame type and process the frame.
			 */
			int consumed = tquic_ack_frequency_process(conn,
								   data + 2,
								   len - 2);
			if (consumed < 0)
				return consumed;
			return consumed + 2;  /* Include frame type bytes */
		}

		/*
		 * Multipath extension frames (RFC 9369) are handled by
		 * the main input path in tquic_input.c, not here.
		 */

		/* Unknown frame type */
		return -EPROTO;
	}
}

static int tquic_frame_process_crypto(struct tquic_connection *conn,
				      const u8 *data, int len, u8 level)
{
	int offset = 1;  /* Skip frame type */
	u64 crypto_offset;
	u64 crypto_len;
	int varint_len;

	/* Offset */
	varint_len = tquic_varint_decode(data + offset, len - offset, &crypto_offset);
	if (varint_len < 0)
		return varint_len;
	offset += varint_len;

	/* Length */
	varint_len = tquic_varint_decode(data + offset, len - offset, &crypto_len);
	if (varint_len < 0)
		return varint_len;
	offset += varint_len;

	/* Bounds check using subtraction to avoid integer overflow */
	if (crypto_len > len - offset)
		return -EINVAL;

	/*
	 * Pass crypto data to TLS layer
	 * In tquic, this would go through conn->crypto_state
	 */

	offset += crypto_len;
	return offset;
}

static int tquic_frame_process_stream(struct tquic_connection *conn,
				      const u8 *data, int len)
{
	u8 frame_type = data[0];
	int offset = 1;
	u64 stream_id;
	u64 stream_offset = 0;
	u64 stream_len;
	bool has_offset = (frame_type & TQUIC_STREAM_FLAG_OFF) != 0;
	bool has_length = (frame_type & TQUIC_STREAM_FLAG_LEN) != 0;
	bool has_fin = (frame_type & TQUIC_STREAM_FLAG_FIN) != 0;
	int varint_len;
	struct tquic_stream *stream;

	/* Stream ID */
	varint_len = tquic_varint_decode(data + offset, len - offset, &stream_id);
	if (varint_len < 0)
		return varint_len;
	offset += varint_len;

	/* Offset (optional) */
	if (has_offset) {
		varint_len = tquic_varint_decode(data + offset, len - offset, &stream_offset);
		if (varint_len < 0)
			return varint_len;
		offset += varint_len;
	}

	/* Length (optional) */
	if (has_length) {
		varint_len = tquic_varint_decode(data + offset, len - offset, &stream_len);
		if (varint_len < 0)
			return varint_len;
		offset += varint_len;
	} else {
		stream_len = len - offset;
	}

	/* Bounds check using subtraction to avoid integer overflow */
	if (stream_len > len - offset)
		return -EINVAL;

	/* Find or create stream */
	stream = tquic_stream_lookup_internal(conn, stream_id);
	if (!stream) {
		/*
		 * RFC 9000 Section 4.6: A peer MUST NOT open more
		 * streams than the MAX_STREAMS limit allows.  Reject
		 * new peer-initiated streams that exceed our limit.
		 */
		bool is_bidi = !(stream_id & 0x2);
		bool is_peer = (stream_id & 0x1) != conn->is_server;

		if (is_peer) {
			u64 max = is_bidi ? conn->max_streams_bidi
					  : conn->max_streams_uni;
			u64 stream_num = stream_id >> 2;

			if (stream_num >= max) {
				pr_debug("tquic: peer exceeded MAX_STREAMS "
					 "(id=%llu max=%llu)\n",
					 stream_id, max);
				return -EPROTO;
			}
		}

		stream = tquic_stream_create_internal(conn, stream_id);
		if (!stream)
			return -ENOMEM;
	}

	/*
	 * RFC 9000 Section 4.1: Flow Control Validation
	 *
	 * A receiver MUST close the connection with a FLOW_CONTROL_ERROR
	 * error if the sender violates the advertised connection or stream
	 * data limits. Check both stream-level and connection-level limits
	 * before accepting the data.
	 */
	if (tquic_flow_check_recv_limits(stream, stream_offset, stream_len)) {
		/*
		 * Flow control violation detected. Close the connection
		 * with FLOW_CONTROL_ERROR (0x03) per RFC 9000.
		 */
		tquic_conn_close_internal(conn, TQUIC_ERROR_FLOW_CONTROL_ERROR,
					  "flow control limit exceeded", 29, false);
		return -EDQUOT;
	}

	/* Deliver data to stream */
	quic_packet_deliver_stream_data(stream, stream_offset, data + offset, stream_len, has_fin);

	return offset + stream_len;
}

static int tquic_frame_process_ack(struct tquic_connection *conn,
				   const u8 *data, int len, u8 level)
{
	struct tquic_ack_frame ack_frame;
	int offset = 1;  /* Skip frame type */
	u64 ack_range_count;
	int varint_len;
	int estimated_min_bytes;
	int i;

	memset(&ack_frame, 0, sizeof(ack_frame));

	/* Largest Acknowledged */
	varint_len = tquic_varint_decode(data + offset, len - offset,
					 &ack_frame.largest_acked);
	if (varint_len < 0)
		return varint_len;
	offset += varint_len;

	/* ACK Delay */
	varint_len = tquic_varint_decode(data + offset, len - offset,
					 &ack_frame.ack_delay);
	if (varint_len < 0)
		return varint_len;
	offset += varint_len;

	/* ACK Range Count - SECURITY: Validate before processing
	 *
	 * An untrusted ack_range_count from the network can cause:
	 * 1. DoS attacks by requesting extreme number of ranges
	 * 2. Buffer overruns if validation is skipped
	 * 3. Excessive memory usage or CPU time
	 *
	 * RFC 9000 doesn't specify a maximum, but we limit to
	 * TQUIC_MAX_ACK_RANGES which represents a reasonable upper
	 * bound for out-of-order packet tracking.
	 */
	varint_len = tquic_varint_decode(data + offset, len - offset,
					 &ack_range_count);
	if (varint_len < 0)
		return varint_len;
	offset += varint_len;

	/*
	 * SECURITY: Validate ack_range_count doesn't exceed array bounds.
	 * Each range requires 2 varints (gap + ack_range), and varints can
	 * be 1-8 bytes each. Maximum varint is 8 bytes, so worst case is
	 * 16 bytes per range. Check that buffer has sufficient data.
	 */
	if (ack_range_count > TQUIC_MAX_ACK_RANGES - 1)
		return -EINVAL;

	/* Estimate minimum buffer needed: 1st range + count*2 varints */
	estimated_min_bytes = (1 + ack_range_count * 2);
	if (len - offset < estimated_min_bytes)
		return -EINVAL;

	/* First ACK Range */
	varint_len = tquic_varint_decode(data + offset, len - offset,
					 &ack_frame.first_range);
	if (varint_len < 0)
		return varint_len;
	offset += varint_len;

	/* Additional ACK Ranges */
	ack_frame.range_count = (u32)ack_range_count;
	for (i = 0; i < ack_range_count; i++) {
		varint_len = tquic_varint_decode(data + offset,
						 len - offset,
						 &ack_frame.ranges[i].gap);
		if (varint_len < 0)
			return varint_len;
		offset += varint_len;

		varint_len = tquic_varint_decode(data + offset,
						 len - offset,
						 &ack_frame.ranges[i].length);
		if (varint_len < 0)
			return varint_len;
		offset += varint_len;
	}

	/* ECN counts (if ACK_ECN frame) */
	if (data[0] == TQUIC_FRAME_ACK_ECN) {
		ack_frame.has_ecn = true;

		varint_len = tquic_varint_decode(data + offset,
						 len - offset,
						 &ack_frame.ecn.ect0);
		if (varint_len < 0)
			return varint_len;
		offset += varint_len;

		varint_len = tquic_varint_decode(data + offset,
						 len - offset,
						 &ack_frame.ecn.ect1);
		if (varint_len < 0)
			return varint_len;
		offset += varint_len;

		varint_len = tquic_varint_decode(data + offset,
						 len - offset,
						 &ack_frame.ecn.ce);
		if (varint_len < 0)
			return varint_len;
		offset += varint_len;
	}

	/*
	 * Process ACK through loss detection and recovery.
	 * Only for Application pn_space since sent-packet tracking
	 * is currently only wired in tquic_output_flush (1-RTT).
	 * Initial/Handshake ACKs have no tracked sent packets, so
	 * calling loss detection would trigger a false PROTOCOL_VIOLATION
	 * (largest_acked > largest_sent when largest_sent == 0).
	 */
	if (level == TQUIC_PN_SPACE_APPLICATION)
		tquic_loss_detection_on_ack_received(conn, &ack_frame, level);

	return offset;
}

static int tquic_frame_process_new_cid(struct tquic_connection *conn,
				       const u8 *data, int len)
{
	int offset = 1;
	u64 seq, retire_prior_to;
	u8 cid_len;
	struct tquic_cid cid;
	u8 reset_token[16];
	int varint_len;

	if (!conn || !data || len <= 1)
		return -EINVAL;

	/* Sequence Number */
	varint_len = tquic_varint_decode(data + offset, len - offset, &seq);
	if (varint_len < 0)
		return varint_len;
	offset += varint_len;

	/* Retire Prior To */
	varint_len = tquic_varint_decode(data + offset, len - offset, &retire_prior_to);
	if (varint_len < 0)
		return varint_len;
	offset += varint_len;

	/* Length */
	if (offset >= len)
		return -EINVAL;
	cid_len = data[offset++];
	if (cid_len > TQUIC_MAX_CID_LEN)
		return -EINVAL;

	/* Connection ID - use subtraction to avoid integer overflow */
	if (cid_len > len - offset)
		return -EINVAL;
	cid.len = cid_len;
	memcpy(cid.id, data + offset, cid_len);
	offset += cid_len;

	/* Stateless Reset Token - use subtraction to avoid overflow */
	if (len < 16 || offset > len - 16)
		return -EINVAL;
	memcpy(reset_token, data + offset, 16);
	offset += 16;

	/* Note: retire_prior_to is parsed but not used by the current API */
	tquic_conn_add_remote_cid(conn, &cid, seq, reset_token);

	return offset;
}

static int tquic_frame_process_connection_close(struct tquic_connection *conn,
						const u8 *data, int len)
{
	int offset = 1;
	u64 error_code;
	u64 frame_type = 0;
	u64 reason_len;
	int varint_len;
	bool is_app_error = (data[0] == TQUIC_FRAME_CONNECTION_CLOSE_APP);

	/* Error Code */
	varint_len = tquic_varint_decode(data + offset, len - offset, &error_code);
	if (varint_len < 0)
		return varint_len;
	offset += varint_len;

	/* Frame Type (not present in APPLICATION_CLOSE) */
	if (!is_app_error) {
		varint_len = tquic_varint_decode(data + offset, len - offset, &frame_type);
		if (varint_len < 0)
			return varint_len;
		offset += varint_len;
	}

	/* Reason Phrase Length */
	varint_len = tquic_varint_decode(data + offset, len - offset, &reason_len);
	if (varint_len < 0)
		return varint_len;
	offset += varint_len;

	/* Bounds check using subtraction to avoid integer overflow */
	if (reason_len > len - offset)
		return -EINVAL;

	offset += reason_len;

	/* Enter draining state */
	if (READ_ONCE(conn->state) != TQUIC_CONN_DRAINING &&
	    READ_ONCE(conn->state) != TQUIC_CONN_CLOSED)
		tquic_conn_set_state(conn, TQUIC_CONN_DRAINING,
				     TQUIC_REASON_PEER_CLOSE);
	set_bit(TQUIC_CONN_FLAG_DRAINING, &conn->flags);

	return offset;
}

EXPORT_SYMBOL_GPL(tquic_packet_parse);
EXPORT_SYMBOL_GPL(tquic_packet_process);
EXPORT_SYMBOL_GPL(tquic_frame_process_all);
EXPORT_SYMBOL_GPL(tquic_frame_process_one);
