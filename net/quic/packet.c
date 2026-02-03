// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * QUIC - Quick UDP Internet Connections
 *
 * Packet processing implementation
 *
 * Copyright (c) 2024 Linux QUIC Authors
 */

#include <linux/slab.h>
#include <linux/skbuff.h>
#include <net/quic.h>

/* QUIC packet header forms */
#define QUIC_HEADER_FORM_LONG	0x80
#define QUIC_HEADER_FORM_SHORT	0x00
#define QUIC_FIXED_BIT		0x40

/* Long header packet types */
#define QUIC_LONG_TYPE_INITIAL		0x00
#define QUIC_LONG_TYPE_0RTT		0x01
#define QUIC_LONG_TYPE_HANDSHAKE	0x02
#define QUIC_LONG_TYPE_RETRY		0x03

/* QUIC packet control block for skb->cb */
struct quic_skb_cb {
	u64	pn;
	u32	header_len;
	u8	pn_len;
	u8	packet_type;
	u8	dcid_len;
	u8	scid_len;
};

#define QUIC_SKB_CB(skb) ((struct quic_skb_cb *)((skb)->cb))

/* Parse long header packet */
static int quic_packet_parse_long(struct sk_buff *skb, u8 first_byte)
{
	struct quic_skb_cb *cb = QUIC_SKB_CB(skb);
	u8 *data = skb->data;
	int offset = 1;
	u32 version;
	u8 dcid_len, scid_len;
	u64 token_len = 0;
	u64 payload_len;

	if (skb->len < 7)
		return -EINVAL;

	/* Version (4 bytes) */
	version = (data[1] << 24) | (data[2] << 16) | (data[3] << 8) | data[4];
	offset = 5;

	/* Destination Connection ID Length (1 byte) */
	dcid_len = data[offset++];
	if (dcid_len > QUIC_MAX_CONNECTION_ID_LEN)
		return -EINVAL;

	if (skb->len < offset + dcid_len)
		return -EINVAL;

	cb->dcid_len = dcid_len;
	offset += dcid_len;

	/* Source Connection ID Length (1 byte) */
	if (skb->len < offset + 1)
		return -EINVAL;

	scid_len = data[offset++];
	if (scid_len > QUIC_MAX_CONNECTION_ID_LEN)
		return -EINVAL;

	cb->scid_len = scid_len;
	if (skb->len < offset + scid_len)
		return -EINVAL;

	offset += scid_len;

	/* Packet type specific handling */
	cb->packet_type = (first_byte & 0x30) >> 4;

	switch (cb->packet_type) {
	case QUIC_LONG_TYPE_INITIAL:
		/* Token Length (variable) */
		if (skb->len < offset + 1)
			return -EINVAL;

		{
			int varint_len = quic_varint_decode(data + offset,
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

	case QUIC_LONG_TYPE_0RTT:
	case QUIC_LONG_TYPE_HANDSHAKE:
		/* No token field */
		break;

	case QUIC_LONG_TYPE_RETRY:
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
		int varint_len = quic_varint_decode(data + offset,
						    skb->len - offset,
						    &payload_len);
		if (varint_len < 0)
			return varint_len;
		offset += varint_len;
	}

	/* Packet Number (1-4 bytes, encoded in pn_len after header unprotection) */
	cb->header_len = offset;

	return 0;
}

/* Parse short header packet */
static int quic_packet_parse_short(struct sk_buff *skb, u8 first_byte,
				   u8 expected_dcid_len)
{
	struct quic_skb_cb *cb = QUIC_SKB_CB(skb);
	int offset = 1;

	cb->packet_type = QUIC_PACKET_1RTT;
	cb->dcid_len = expected_dcid_len;
	cb->scid_len = 0;

	if (skb->len < 1 + expected_dcid_len)
		return -EINVAL;

	offset += expected_dcid_len;
	cb->header_len = offset;

	return 0;
}

int quic_packet_parse(struct sk_buff *skb, struct quic_packet *pkt)
{
	u8 first_byte;
	int err;

	if (skb->len < 1)
		return -EINVAL;

	first_byte = skb->data[0];

	/* Check fixed bit */
	if (!(first_byte & QUIC_FIXED_BIT))
		return -EINVAL;

	memset(QUIC_SKB_CB(skb), 0, sizeof(struct quic_skb_cb));

	if (first_byte & QUIC_HEADER_FORM_LONG) {
		err = quic_packet_parse_long(skb, first_byte);
	} else {
		/* For short header, need to know expected DCID length */
		err = quic_packet_parse_short(skb, first_byte, 8);
	}

	return err;
}

/* Decode packet number from truncated form */
static u64 quic_decode_pn(u64 largest_pn, u64 truncated_pn, u8 pn_len)
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
static u64 quic_extract_pn(const u8 *data, u8 pn_len)
{
	u64 pn = 0;
	int i;

	for (i = 0; i < pn_len; i++)
		pn = (pn << 8) | data[i];

	return pn;
}

struct sk_buff *quic_packet_build(struct quic_connection *conn,
				  struct quic_pn_space *pn_space)
{
	struct sk_buff *skb;
	struct sk_buff *frame_skb;
	u8 *p;
	u8 first_byte;
	u64 pn;
	u8 pn_len;
	int pn_offset;
	int header_len;
	int max_payload;
	int payload_len = 0;

	skb = alloc_skb(QUIC_MAX_PACKET_SIZE + 128, GFP_ATOMIC);
	if (!skb)
		return NULL;

	skb_reserve(skb, 64);  /* Room for UDP/IP headers */

	pn = pn_space->next_pn++;

	/* Determine packet number encoding length */
	if (pn < 0x100)
		pn_len = 1;
	else if (pn < 0x10000)
		pn_len = 2;
	else if (pn < 0x1000000)
		pn_len = 3;
	else
		pn_len = 4;

	/* Build header based on crypto level */
	if (conn->crypto_level == QUIC_CRYPTO_INITIAL ||
	    conn->crypto_level == QUIC_CRYPTO_HANDSHAKE) {
		/* Long header */
		u8 packet_type;

		if (conn->crypto_level == QUIC_CRYPTO_INITIAL)
			packet_type = QUIC_LONG_TYPE_INITIAL;
		else
			packet_type = QUIC_LONG_TYPE_HANDSHAKE;

		first_byte = QUIC_HEADER_FORM_LONG | QUIC_FIXED_BIT |
			     (packet_type << 4) | (pn_len - 1);

		p = skb_put(skb, 1);
		*p = first_byte;

		/* Version */
		p = skb_put(skb, 4);
		p[0] = (conn->version >> 24) & 0xff;
		p[1] = (conn->version >> 16) & 0xff;
		p[2] = (conn->version >> 8) & 0xff;
		p[3] = conn->version & 0xff;

		/* DCID Length + DCID */
		p = skb_put(skb, 1);
		*p = conn->dcid.len;
		if (conn->dcid.len > 0) {
			p = skb_put(skb, conn->dcid.len);
			memcpy(p, conn->dcid.data, conn->dcid.len);
		}

		/* SCID Length + SCID */
		p = skb_put(skb, 1);
		*p = conn->scid.len;
		if (conn->scid.len > 0) {
			p = skb_put(skb, conn->scid.len);
			memcpy(p, conn->scid.data, conn->scid.len);
		}

		/* Token (only for Initial packets from client) */
		if (conn->crypto_level == QUIC_CRYPTO_INITIAL) {
			if (!conn->is_server && conn->qsk->token_len > 0) {
				p = skb_put(skb, quic_varint_len(conn->qsk->token_len));
				quic_varint_encode(conn->qsk->token_len, p);
				p = skb_put(skb, conn->qsk->token_len);
				memcpy(p, conn->qsk->token, conn->qsk->token_len);
			} else {
				p = skb_put(skb, 1);
				*p = 0;  /* Zero token length */
			}
		}

		/* Length field - 2-byte varint placeholder, updated after payload */
		p = skb_put(skb, 2);
		p[0] = QUIC_VARINT_2BYTE_PREFIX;
		p[1] = 0x00;

		pn_offset = skb->len;
		header_len = pn_offset + pn_len;
	} else {
		/* Short header (1-RTT) */
		first_byte = QUIC_FIXED_BIT | (conn->key_phase << 2) | (pn_len - 1);

		p = skb_put(skb, 1);
		*p = first_byte;

		/* DCID (no length prefix in short header) */
		if (conn->dcid.len > 0) {
			p = skb_put(skb, conn->dcid.len);
			memcpy(p, conn->dcid.data, conn->dcid.len);
		}

		pn_offset = skb->len;
		header_len = pn_offset + pn_len;
	}

	/* Packet number */
	p = skb_put(skb, pn_len);
	switch (pn_len) {
	case 1:
		p[0] = pn & 0xff;
		break;
	case 2:
		p[0] = (pn >> 8) & 0xff;
		p[1] = pn & 0xff;
		break;
	case 3:
		p[0] = (pn >> 16) & 0xff;
		p[1] = (pn >> 8) & 0xff;
		p[2] = pn & 0xff;
		break;
	case 4:
		p[0] = (pn >> 24) & 0xff;
		p[1] = (pn >> 16) & 0xff;
		p[2] = (pn >> 8) & 0xff;
		p[3] = pn & 0xff;
		break;
	}

	QUIC_SKB_CB(skb)->header_len = header_len;
	QUIC_SKB_CB(skb)->pn = pn;
	QUIC_SKB_CB(skb)->pn_len = pn_len;

	/* Add pending frames */
	max_payload = QUIC_MAX_PACKET_SIZE - header_len - 16;  /* 16 for AEAD tag */

	/* First add any ACK frames */
	if (quic_ack_should_send(conn, conn->crypto_level)) {
		int ack_len = quic_ack_create(conn, conn->crypto_level, skb);
		if (ack_len > 0)
			payload_len += ack_len;
	}

	/* Add crypto frames */
	while (!skb_queue_empty(&conn->crypto_buffer[conn->crypto_level]) &&
	       payload_len < max_payload) {
		frame_skb = skb_dequeue(&conn->crypto_buffer[conn->crypto_level]);
		if (!frame_skb)
			break;

		if (payload_len + frame_skb->len > max_payload) {
			skb_queue_head(&conn->crypto_buffer[conn->crypto_level], frame_skb);
			break;
		}

		p = skb_put(skb, frame_skb->len);
		skb_copy_bits(frame_skb, 0, p, frame_skb->len);
		payload_len += frame_skb->len;
		kfree_skb(frame_skb);
	}

	/* Add pending frames */
	while (!skb_queue_empty(&conn->pending_frames) &&
	       payload_len < max_payload) {
		frame_skb = skb_dequeue(&conn->pending_frames);
		if (!frame_skb)
			break;

		if (payload_len + frame_skb->len > max_payload) {
			skb_queue_head(&conn->pending_frames, frame_skb);
			break;
		}

		p = skb_put(skb, frame_skb->len);
		skb_copy_bits(frame_skb, 0, p, frame_skb->len);
		payload_len += frame_skb->len;
		kfree_skb(frame_skb);
	}

	/* Add PADDING if needed (Initial packets must be >= 1200 bytes) */
	if (conn->crypto_level == QUIC_CRYPTO_INITIAL) {
		int pad_len = QUIC_MIN_PACKET_SIZE - skb->len - 16;
		if (pad_len > 0) {
			p = skb_put(skb, pad_len);
			memset(p, 0, pad_len);  /* PADDING frames are 0x00 */
			payload_len += pad_len;
		}
	}

	/* Update length field for long headers */
	if (conn->crypto_level == QUIC_CRYPTO_INITIAL ||
	    conn->crypto_level == QUIC_CRYPTO_HANDSHAKE) {
		u64 length = pn_len + payload_len + 16;  /* PN + payload + tag */
		int len_offset = pn_offset - 2;

		skb->data[len_offset] = 0x40 | ((length >> 8) & 0x3f);
		skb->data[len_offset + 1] = length & 0xff;
	}

	/* Encrypt packet */
	if (quic_crypto_encrypt(&conn->crypto[conn->crypto_level], skb, pn) < 0) {
		kfree_skb(skb);
		return NULL;
	}

	/* Apply header protection */
	if (quic_crypto_protect_header(&conn->crypto[conn->crypto_level],
				       skb, pn_offset, pn_len) < 0) {
		kfree_skb(skb);
		return NULL;
	}

	/* Track sent packet for loss detection */
	{
		struct quic_sent_packet *sent;

		sent = kzalloc(sizeof(*sent), GFP_ATOMIC);
		if (!sent) {
			/*
			 * Cannot track packet for loss detection.
			 * Fail the send to maintain reliable delivery guarantees.
			 */
			kfree_skb(skb);
			return NULL;
		}
		sent->pn = pn;
		sent->sent_time = ktime_get();
		sent->size = skb->len;
		sent->ack_eliciting = payload_len > 0;
		sent->in_flight = 1;
		sent->pn_space = conn->crypto_level;
		INIT_LIST_HEAD(&sent->list);

		quic_loss_detection_on_packet_sent(conn, sent);
	}

	/* Update statistics */
	conn->stats.packets_sent++;
	conn->stats.bytes_sent += skb->len;

	return skb;
}

void quic_packet_process(struct quic_connection *conn, struct sk_buff *skb)
{
	struct quic_crypto_ctx *ctx;
	u8 first_byte;
	u8 pn_offset, pn_len;
	u64 truncated_pn, pn;
	u8 level;
	int err;

	if (skb->len < 1) {
		kfree_skb(skb);
		return;
	}

	first_byte = skb->data[0];

	/* Determine encryption level */
	if (first_byte & QUIC_HEADER_FORM_LONG) {
		u8 packet_type = (first_byte & 0x30) >> 4;

		switch (packet_type) {
		case QUIC_LONG_TYPE_INITIAL:
			level = QUIC_CRYPTO_INITIAL;
			break;
		case QUIC_LONG_TYPE_0RTT:
			level = QUIC_CRYPTO_EARLY_DATA;
			break;
		case QUIC_LONG_TYPE_HANDSHAKE:
			level = QUIC_CRYPTO_HANDSHAKE;
			break;
		case QUIC_LONG_TYPE_RETRY:
			/* Handle retry packet specially */
			quic_packet_process_retry(conn, skb);
			return;
		default:
			kfree_skb(skb);
			return;
		}
	} else {
		level = QUIC_CRYPTO_APPLICATION;
	}

	ctx = &conn->crypto[level];
	if (!ctx->keys_available) {
		/* Buffer packet for later processing */
		skb_queue_tail(&conn->pending_frames, skb);
		return;
	}

	/* Remove header protection */
	err = quic_crypto_unprotect_header(ctx, skb, &pn_offset, &pn_len);
	if (err) {
		kfree_skb(skb);
		return;
	}

	/* Decode packet number */
	truncated_pn = quic_extract_pn(skb->data + pn_offset, pn_len);
	pn = quic_decode_pn(conn->pn_spaces[level].largest_recv_pn,
			    truncated_pn, pn_len);

	QUIC_SKB_CB(skb)->pn = pn;
	QUIC_SKB_CB(skb)->pn_len = pn_len;
	QUIC_SKB_CB(skb)->header_len = pn_offset + pn_len;

	/* Decrypt packet */
	err = quic_crypto_decrypt(ctx, skb, pn);
	if (err) {
		kfree_skb(skb);
		return;
	}

	/* Update largest received packet number */
	if (pn > conn->pn_spaces[level].largest_recv_pn)
		conn->pn_spaces[level].largest_recv_pn = pn;

	/* Record ACK for this packet */
	quic_ack_on_packet_received(conn, pn, level);

	/* Process frames */
	quic_frame_process_all(conn, skb, level);

	/* Update statistics */
	conn->stats.packets_received++;
	conn->stats.bytes_received += skb->len;

	kfree_skb(skb);
}

static void quic_packet_process_retry(struct quic_connection *conn,
				      struct sk_buff *skb)
{
	u8 *data = skb->data;
	int offset = 5;  /* Skip first byte and version */
	u8 dcid_len, scid_len;
	struct quic_connection_id new_scid;

	if (conn->state != QUIC_STATE_CONNECTING) {
		kfree_skb(skb);
		return;
	}

	/* Parse DCID */
	dcid_len = data[offset++];
	offset += dcid_len;

	/* Parse SCID - this becomes our new DCID */
	scid_len = data[offset++];
	if (scid_len > QUIC_MAX_CONNECTION_ID_LEN) {
		kfree_skb(skb);
		return;
	}

	new_scid.len = scid_len;
	memcpy(new_scid.data, data + offset, scid_len);
	offset += scid_len;

	/* The rest is the retry token (minus 16-byte integrity tag) */
	if (skb->len - offset < 16) {
		kfree_skb(skb);
		return;
	}

	/* Store token for retry */
	{
		u32 token_len = skb->len - offset - 16;
		u8 *token = data + offset;

		kfree(conn->qsk->token);
		conn->qsk->token = kmemdup(token, token_len, GFP_ATOMIC);
		conn->qsk->token_len = token_len;
	}

	/* Update DCID for next Initial packet */
	memcpy(&conn->original_dcid, &conn->dcid, sizeof(conn->dcid));
	memcpy(&conn->dcid, &new_scid, sizeof(conn->dcid));

	/* Re-derive initial secrets with new DCID */
	quic_crypto_destroy(&conn->crypto[QUIC_CRYPTO_INITIAL]);
	quic_crypto_derive_initial_secrets(conn, &conn->dcid);

	/* Resend Initial packet */
	schedule_work(&conn->tx_work);

	kfree_skb(skb);
}

int quic_frame_process_all(struct quic_connection *conn, struct sk_buff *skb,
			   u8 level)
{
	u8 *data = skb->data + QUIC_SKB_CB(skb)->header_len;
	int len = skb->len - QUIC_SKB_CB(skb)->header_len;
	int offset = 0;

	while (offset < len) {
		u8 frame_type = data[offset];
		int frame_len;

		frame_len = quic_frame_process_one(conn, data + offset,
						   len - offset, level);
		if (frame_len < 0)
			return frame_len;

		offset += frame_len;
	}

	return 0;
}

int quic_frame_process_one(struct quic_connection *conn, const u8 *data,
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
	case QUIC_FRAME_PADDING:
		/* Skip all padding bytes */
		while (offset < len && data[offset] == 0)
			offset++;
		return offset;

	case QUIC_FRAME_PING:
		/* PING frame is just the type byte */
		return 1;

	case QUIC_FRAME_ACK:
	case QUIC_FRAME_ACK_ECN:
		return quic_frame_process_ack(conn, data, len, level);

	case QUIC_FRAME_RESET_STREAM:
		/* Stream ID */
		varint_len = quic_varint_decode(data + offset, len - offset, &val1);
		if (varint_len < 0) return varint_len;
		offset += varint_len;

		/* Application Protocol Error Code */
		varint_len = quic_varint_decode(data + offset, len - offset, &val2);
		if (varint_len < 0) return varint_len;
		offset += varint_len;

		/* Final Size */
		varint_len = quic_varint_decode(data + offset, len - offset, &val3);
		if (varint_len < 0) return varint_len;
		offset += varint_len;

		{
			struct quic_stream *stream = quic_stream_lookup(conn, val1);
			if (stream) {
				quic_stream_handle_reset(stream, val2, val3);
				refcount_dec(&stream->refcnt);
			}
		}
		return offset;

	case QUIC_FRAME_STOP_SENDING:
		/* Stream ID */
		varint_len = quic_varint_decode(data + offset, len - offset, &val1);
		if (varint_len < 0) return varint_len;
		offset += varint_len;

		/* Application Protocol Error Code */
		varint_len = quic_varint_decode(data + offset, len - offset, &val2);
		if (varint_len < 0) return varint_len;
		offset += varint_len;

		{
			struct quic_stream *stream = quic_stream_lookup(conn, val1);
			if (stream) {
				quic_stream_handle_stop_sending(stream, val2);
				refcount_dec(&stream->refcnt);
			}
		}
		return offset;

	case QUIC_FRAME_CRYPTO:
		return quic_frame_process_crypto(conn, data, len, level);

	case QUIC_FRAME_NEW_TOKEN:
		/* Length */
		varint_len = quic_varint_decode(data + offset, len - offset, &val1);
		if (varint_len < 0) return varint_len;
		offset += varint_len;

		if (offset + val1 > len)
			return -EINVAL;

		/* Store token */
		kfree(conn->qsk->token);
		conn->qsk->token = kmemdup(data + offset, val1, GFP_ATOMIC);
		conn->qsk->token_len = val1;
		offset += val1;
		return offset;

	case QUIC_FRAME_STREAM ... (QUIC_FRAME_STREAM | 0x07):
		return quic_frame_process_stream(conn, data, len);

	case QUIC_FRAME_MAX_DATA:
		varint_len = quic_varint_decode(data + offset, len - offset, &val1);
		if (varint_len < 0) return varint_len;
		offset += varint_len;

		if (val1 > conn->remote_fc.max_data)
			conn->remote_fc.max_data = val1;
		return offset;

	case QUIC_FRAME_MAX_STREAM_DATA:
		/* Stream ID */
		varint_len = quic_varint_decode(data + offset, len - offset, &val1);
		if (varint_len < 0) return varint_len;
		offset += varint_len;

		/* Maximum Stream Data */
		varint_len = quic_varint_decode(data + offset, len - offset, &val2);
		if (varint_len < 0) return varint_len;
		offset += varint_len;

		{
			struct quic_stream *stream = quic_stream_lookup(conn, val1);
			if (stream) {
				if (val2 > stream->send.max_stream_data)
					stream->send.max_stream_data = val2;
				refcount_dec(&stream->refcnt);
			}
		}
		return offset;

	case QUIC_FRAME_MAX_STREAMS_BIDI:
		varint_len = quic_varint_decode(data + offset, len - offset, &val1);
		if (varint_len < 0) return varint_len;
		offset += varint_len;

		if (val1 > conn->max_stream_id_bidi)
			conn->max_stream_id_bidi = val1;
		return offset;

	case QUIC_FRAME_MAX_STREAMS_UNI:
		varint_len = quic_varint_decode(data + offset, len - offset, &val1);
		if (varint_len < 0) return varint_len;
		offset += varint_len;

		if (val1 > conn->max_stream_id_uni)
			conn->max_stream_id_uni = val1;
		return offset;

	case QUIC_FRAME_DATA_BLOCKED:
	case QUIC_FRAME_STREAM_DATA_BLOCKED:
	case QUIC_FRAME_STREAMS_BLOCKED_BIDI:
	case QUIC_FRAME_STREAMS_BLOCKED_UNI:
		/* These are informational, just parse and skip */
		varint_len = quic_varint_decode(data + offset, len - offset, &val1);
		if (varint_len < 0) return varint_len;
		offset += varint_len;

		if (frame_type == QUIC_FRAME_STREAM_DATA_BLOCKED) {
			varint_len = quic_varint_decode(data + offset, len - offset, &val2);
			if (varint_len < 0) return varint_len;
			offset += varint_len;
		}
		return offset;

	case QUIC_FRAME_NEW_CONNECTION_ID:
		return quic_frame_process_new_cid(conn, data, len);

	case QUIC_FRAME_RETIRE_CONNECTION_ID:
		varint_len = quic_varint_decode(data + offset, len - offset, &val1);
		if (varint_len < 0) return varint_len;
		offset += varint_len;

		quic_conn_retire_cid(conn, val1);
		return offset;

	case QUIC_FRAME_PATH_CHALLENGE:
		if (len < offset + 8)
			return -EINVAL;
		/* Echo back as PATH_RESPONSE per RFC 9000 Section 8.2.2 */
		{
			struct sk_buff *resp = alloc_skb(16, GFP_ATOMIC);
			u8 *p;

			if (!resp) {
				net_warn_ratelimited("QUIC: failed to allocate PATH_RESPONSE\n");
				return -ENOMEM;
			}
			p = skb_put(resp, 9);
			p[0] = QUIC_FRAME_PATH_RESPONSE;
			memcpy(p + 1, data + offset, 8);
			skb_queue_tail(&conn->pending_frames, resp);
		}
		return offset + 8;

	case QUIC_FRAME_PATH_RESPONSE:
		if (len < offset + 8)
			return -EINVAL;
		/* Validate path challenge response */
		if (conn->active_path && conn->active_path->challenge_pending) {
			if (memcmp(data + offset, conn->active_path->challenge_data, 8) == 0) {
				conn->active_path->validated = 1;
				conn->active_path->challenge_pending = 0;
			}
		}
		return offset + 8;

	case QUIC_FRAME_CONNECTION_CLOSE:
	case QUIC_FRAME_CONNECTION_CLOSE_APP:
		return quic_frame_process_connection_close(conn, data, len);

	case QUIC_FRAME_HANDSHAKE_DONE:
		if (!conn->is_server) {
			conn->handshake_confirmed = 1;
			quic_conn_set_state(conn, QUIC_STATE_CONNECTED);
		}
		return 1;

	default:
		/* Unknown frame type */
		return -EPROTO;
	}
}

static int quic_frame_process_crypto(struct quic_connection *conn,
				     const u8 *data, int len, u8 level)
{
	int offset = 1;  /* Skip frame type */
	u64 crypto_offset;
	u64 crypto_len;
	int varint_len;

	/* Offset */
	varint_len = quic_varint_decode(data + offset, len - offset, &crypto_offset);
	if (varint_len < 0)
		return varint_len;
	offset += varint_len;

	/* Length */
	varint_len = quic_varint_decode(data + offset, len - offset, &crypto_len);
	if (varint_len < 0)
		return varint_len;
	offset += varint_len;

	if (offset + crypto_len > len)
		return -EINVAL;

	/* Pass crypto data to TLS layer (via userspace or kernel TLS) */
	{
		struct sk_buff *crypto_skb = alloc_skb(crypto_len + 16, GFP_ATOMIC);

		if (!crypto_skb) {
			net_warn_ratelimited("QUIC: failed to allocate crypto buffer\n");
			return -ENOMEM;
		}
		memcpy(skb_put(crypto_skb, crypto_len), data + offset, crypto_len);
		skb_queue_tail(&conn->crypto_buffer[level], crypto_skb);
	}

	offset += crypto_len;
	return offset;
}

static int quic_frame_process_stream(struct quic_connection *conn,
				     const u8 *data, int len)
{
	u8 frame_type = data[0];
	int offset = 1;
	u64 stream_id;
	u64 stream_offset = 0;
	u64 stream_len;
	bool has_offset = (frame_type & 0x04) != 0;
	bool has_length = (frame_type & 0x02) != 0;
	bool has_fin = (frame_type & 0x01) != 0;
	int varint_len;
	struct quic_stream *stream;

	/* Stream ID */
	varint_len = quic_varint_decode(data + offset, len - offset, &stream_id);
	if (varint_len < 0)
		return varint_len;
	offset += varint_len;

	/* Offset (optional) */
	if (has_offset) {
		varint_len = quic_varint_decode(data + offset, len - offset, &stream_offset);
		if (varint_len < 0)
			return varint_len;
		offset += varint_len;
	}

	/* Length (optional) */
	if (has_length) {
		varint_len = quic_varint_decode(data + offset, len - offset, &stream_len);
		if (varint_len < 0)
			return varint_len;
		offset += varint_len;
	} else {
		stream_len = len - offset;
	}

	if (offset + stream_len > len)
		return -EINVAL;

	/* Find or create stream */
	stream = quic_stream_lookup(conn, stream_id);
	if (!stream) {
		stream = quic_stream_create(conn, stream_id);
		if (!stream)
			return -ENOMEM;
	}

	/* Deliver data to stream */
	quic_stream_recv_data(stream, stream_offset, data + offset, stream_len, has_fin);

	refcount_dec(&stream->refcnt);

	return offset + stream_len;
}

static int quic_frame_process_ack(struct quic_connection *conn,
				  const u8 *data, int len, u8 level)
{
	struct quic_ack_info ack;
	int offset = 1;  /* Skip frame type */
	u64 ack_range_count;
	int varint_len;
	int i;

	memset(&ack, 0, sizeof(ack));

	/* Largest Acknowledged */
	varint_len = quic_varint_decode(data + offset, len - offset, &ack.largest_acked);
	if (varint_len < 0)
		return varint_len;
	offset += varint_len;

	/* ACK Delay */
	varint_len = quic_varint_decode(data + offset, len - offset, &ack.ack_delay);
	if (varint_len < 0)
		return varint_len;
	offset += varint_len;

	/* ACK Range Count */
	varint_len = quic_varint_decode(data + offset, len - offset, &ack_range_count);
	if (varint_len < 0)
		return varint_len;
	offset += varint_len;

	/* First ACK Range */
	varint_len = quic_varint_decode(data + offset, len - offset, &ack.ranges[0].ack_range);
	if (varint_len < 0)
		return varint_len;
	offset += varint_len;

	ack.ack_range_count = 1;

	/* Additional ACK Ranges */
	for (i = 0; i < ack_range_count && i < 255; i++) {
		varint_len = quic_varint_decode(data + offset, len - offset,
						&ack.ranges[i + 1].gap);
		if (varint_len < 0)
			return varint_len;
		offset += varint_len;

		varint_len = quic_varint_decode(data + offset, len - offset,
						&ack.ranges[i + 1].ack_range);
		if (varint_len < 0)
			return varint_len;
		offset += varint_len;

		ack.ack_range_count++;
	}

	/* ECN counts (if ACK_ECN frame) */
	if (data[0] == QUIC_FRAME_ACK_ECN) {
		varint_len = quic_varint_decode(data + offset, len - offset, &ack.ecn_ect0);
		if (varint_len < 0)
			return varint_len;
		offset += varint_len;

		varint_len = quic_varint_decode(data + offset, len - offset, &ack.ecn_ect1);
		if (varint_len < 0)
			return varint_len;
		offset += varint_len;

		varint_len = quic_varint_decode(data + offset, len - offset, &ack.ecn_ce);
		if (varint_len < 0)
			return varint_len;
		offset += varint_len;
	}

	/* Process ACK */
	quic_loss_detection_on_ack_received(conn, &ack, level);

	return offset;
}

static int quic_frame_process_new_cid(struct quic_connection *conn,
				      const u8 *data, int len)
{
	int offset = 1;
	u64 seq, retire_prior_to;
	u8 cid_len;
	struct quic_connection_id cid;
	u8 reset_token[16];
	int varint_len;

	/* Sequence Number */
	varint_len = quic_varint_decode(data + offset, len - offset, &seq);
	if (varint_len < 0)
		return varint_len;
	offset += varint_len;

	/* Retire Prior To */
	varint_len = quic_varint_decode(data + offset, len - offset, &retire_prior_to);
	if (varint_len < 0)
		return varint_len;
	offset += varint_len;

	/* Length */
	if (offset >= len)
		return -EINVAL;
	cid_len = data[offset++];
	if (cid_len > QUIC_MAX_CONNECTION_ID_LEN)
		return -EINVAL;

	/* Connection ID */
	if (offset + cid_len > len)
		return -EINVAL;
	cid.len = cid_len;
	memcpy(cid.data, data + offset, cid_len);
	offset += cid_len;

	/* Stateless Reset Token */
	if (offset + 16 > len)
		return -EINVAL;
	memcpy(reset_token, data + offset, 16);
	offset += 16;

	quic_conn_add_peer_cid(conn, &cid, seq, retire_prior_to, reset_token);

	return offset;
}

static int quic_frame_process_connection_close(struct quic_connection *conn,
					       const u8 *data, int len)
{
	int offset = 1;
	u64 error_code;
	u64 frame_type = 0;
	u64 reason_len;
	int varint_len;
	bool is_app_error = (data[0] == QUIC_FRAME_CONNECTION_CLOSE_APP);

	/* Error Code */
	varint_len = quic_varint_decode(data + offset, len - offset, &error_code);
	if (varint_len < 0)
		return varint_len;
	offset += varint_len;

	/* Frame Type (not present in APPLICATION_CLOSE) */
	if (!is_app_error) {
		varint_len = quic_varint_decode(data + offset, len - offset, &frame_type);
		if (varint_len < 0)
			return varint_len;
		offset += varint_len;
	}

	/* Reason Phrase Length */
	varint_len = quic_varint_decode(data + offset, len - offset, &reason_len);
	if (varint_len < 0)
		return varint_len;
	offset += varint_len;

	if (offset + reason_len > len)
		return -EINVAL;

	/* Store close info */
	conn->error_code = error_code;
	conn->frame_type = frame_type;
	conn->app_error = is_app_error ? 1 : 0;
	conn->close_received = 1;

	if (reason_len > 0) {
		char *phrase = kmemdup(data + offset, reason_len, GFP_ATOMIC);

		if (phrase) {
			kfree(conn->reason_phrase);
			conn->reason_phrase = phrase;
			conn->reason_len = reason_len;
		}
		/* On allocation failure, keep existing reason or none */
	}

	offset += reason_len;

	/* Enter draining state */
	quic_conn_set_state(conn, QUIC_STATE_DRAINING);

	return offset;
}
