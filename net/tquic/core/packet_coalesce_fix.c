// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * QUIC Packet Coalescing Fix for RFC 9000 Section 12.2
 *
 * This file contains the functions that need to be added/modified in packet.c
 * to properly support coalesced packets per RFC 9000 Section 12.2.
 *
 * RFC 9000 Section 12.2 requirements:
 * - Each coalesced packet must be complete and well-formed
 * - Length fields must accurately reflect packet boundaries
 * - Receiver must be able to separate coalesced packets
 */

/*
 * ADDITION 1: Add this function after quic_packet_parse_short()
 *
 * quic_packet_get_length - Get the total length of a QUIC packet in a buffer
 * @data: Pointer to the start of the QUIC packet
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
static int quic_packet_get_length(const u8 *data, int len, int *packet_len)
{
	int offset = 1;
	u8 first_byte;
	u8 dcid_len, scid_len;
	u8 packet_type;
	u64 token_len = 0;
	u64 payload_len;
	int varint_len;

	if (len < 1)
		return -EINVAL;

	first_byte = data[0];

	/* Validate fixed bit per RFC 9000 Section 17.2 */
	if (!(first_byte & QUIC_FIXED_BIT))
		return -EINVAL;

	/* Short header packet consumes the entire remaining buffer */
	if (!(first_byte & QUIC_HEADER_FORM_LONG)) {
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
	if (dcid_len > QUIC_MAX_CONNECTION_ID_LEN)
		return -EINVAL;

	if (len < offset + dcid_len + 1)
		return -EINVAL;
	offset += dcid_len;

	/* Source Connection ID Length (1 byte) */
	scid_len = data[offset++];
	if (scid_len > QUIC_MAX_CONNECTION_ID_LEN)
		return -EINVAL;

	if (len < offset + scid_len)
		return -EINVAL;
	offset += scid_len;

	/* Packet type specific handling */
	packet_type = (first_byte & 0x30) >> 4;

	switch (packet_type) {
	case QUIC_LONG_TYPE_INITIAL:
		/* Token Length (variable) */
		if (len < offset + 1)
			return -EINVAL;

		varint_len = quic_varint_decode(data + offset, len - offset,
						&token_len);
		if (varint_len < 0)
			return varint_len;
		offset += varint_len;

		/* Validate and skip token */
		if (token_len > len - offset)
			return -EINVAL;
		offset += token_len;
		break;

	case QUIC_LONG_TYPE_0RTT:
	case QUIC_LONG_TYPE_HANDSHAKE:
		/* No token field */
		break;

	case QUIC_LONG_TYPE_RETRY:
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

	varint_len = quic_varint_decode(data + offset, len - offset,
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

	*packet_len = offset + payload_len;
	return 0;
}

/*
 * MODIFICATION 2: Modify quic_packet_process() to handle coalesced packets
 *
 * Replace the existing quic_packet_process function with this version:
 */

/*
 * quic_packet_process_coalesced - Process a UDP datagram that may contain
 *                                  coalesced QUIC packets per RFC 9000 12.2
 * @conn: QUIC connection
 * @skb: Socket buffer containing the UDP datagram payload
 *
 * Per RFC 9000 Section 12.2, multiple QUIC packets at different encryption
 * levels can be coalesced into a single UDP datagram. This function:
 * 1. Determines the length of the first packet using quic_packet_get_length()
 * 2. Processes the first packet
 * 3. If there's remaining data, recursively processes the next packet
 *
 * This is particularly important during the handshake when Initial and
 * Handshake packets are often coalesced together.
 */
void quic_packet_process(struct quic_connection *conn, struct sk_buff *skb)
{
	struct quic_crypto_ctx *ctx;
	u8 first_byte;
	u8 pn_offset, pn_len;
	u64 truncated_pn, pn;
	u8 level;
	int err;
	int packet_len;
	struct sk_buff *next_skb;

	if (skb->len < 1) {
		kfree_skb(skb);
		return;
	}

	first_byte = skb->data[0];

	/*
	 * RFC 9000 Section 12.2: Coalesced Packets
	 * Determine the length of this packet. For long header packets,
	 * this allows us to separate coalesced packets. For short header
	 * packets, the entire remaining datagram is this packet.
	 */
	err = quic_packet_get_length(skb->data, skb->len, &packet_len);
	if (err) {
		kfree_skb(skb);
		return;
	}

	/*
	 * Validate packet_len is within bounds
	 * This should not happen given quic_packet_get_length validation,
	 * but defense in depth is important for network code.
	 */
	if (packet_len < 1 || packet_len > skb->len) {
		kfree_skb(skb);
		return;
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
				skb_put_data(next_skb, skb->data + packet_len, remaining);
			}
			/* If allocation fails, we just lose the coalesced packet(s) */
		}
		/* Trim this skb to just the first packet */
		skb_trim(skb, packet_len);
	}

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
			goto process_next;
		default:
			kfree_skb(skb);
			goto process_next;
		}
	} else {
		level = QUIC_CRYPTO_APPLICATION;
	}

	ctx = &conn->crypto[level];
	if (!ctx->keys_available) {
		/* Buffer packet for later processing */
		skb_queue_tail(&conn->pending_frames, skb);
		goto process_next;
	}

	/* Remove header protection */
	err = quic_crypto_unprotect_header(ctx, skb, &pn_offset, &pn_len);
	if (err) {
		kfree_skb(skb);
		goto process_next;
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
		goto process_next;
	}

	/* Update largest received packet number */
	if (pn > conn->pn_spaces[level].largest_recv_pn)
		conn->pn_spaces[level].largest_recv_pn = pn;

	/* Record ACK for this packet */
	quic_ack_on_packet_received(conn, pn, level);

	/* Process frames */
	quic_frame_process_all(conn, skb, level);

	/* Update statistics */
	atomic64_inc(&conn->stats.packets_received);
	atomic64_add(skb->len, &conn->stats.bytes_received);

	kfree_skb(skb);

process_next:
	/* Process any remaining coalesced packets */
	if (next_skb)
		quic_packet_process(conn, next_skb);
}

/*
 * MODIFICATION 3: Add validation to quic_packet_parse_long()
 *
 * After parsing the payload_len varint, add this validation:
 */
/*
 * Add after "offset += varint_len;" for payload_len parsing:
 *
 *	 * Validate payload length per RFC 9000 Section 12.2.
 *	 * The payload_len field indicates the length of the rest of the packet
 *	 * (packet number + encrypted payload + AEAD tag). It must not extend
 *	 * beyond the received packet data.
 *	 *
 *	 * Note: payload_len < remaining is allowed per RFC 9000 Section 12.2
 *	 * which permits coalesced packets. The peer may have combined multiple
 *	 * QUIC packets into a single UDP datagram.
 *	 *
 *	if (payload_len > skb->len - offset)
 *		return -EINVAL;
 */

/*
 * MODIFICATION 4: Add validation to quic_coalesce_packets() in output.c
 *
 * Before copying each packet, validate it is well-formed:
 */
/*
struct sk_buff *quic_coalesce_packets(struct sk_buff_head *packets)
{
	struct sk_buff *coalesced, *skb;
	u32 total_len = 0;
	u8 *p;
	int packet_len;

	if (skb_queue_empty(packets))
		return NULL;

	// First pass: validate all packets and calculate total length
	skb_queue_walk(packets, skb) {
		// Validate each packet is well-formed per RFC 9000 Section 12.2
		if (quic_packet_get_length(skb->data, skb->len, &packet_len) < 0)
			return NULL;

		if (packet_len != skb->len) {
			// Packet length doesn't match - malformed packet
			return NULL;
		}

		total_len += skb->len;
	}

	// Check against maximum packet size
	if (total_len > QUIC_MAX_PACKET_SIZE)
		return NULL;

	// Allocate coalesced skb
	coalesced = alloc_skb(QUIC_OUTPUT_SKB_HEADROOM + total_len + 16, GFP_ATOMIC);
	if (!coalesced)
		return NULL;

	skb_reserve(coalesced, QUIC_OUTPUT_SKB_HEADROOM);

	// Copy all packets
	while ((skb = __skb_dequeue(packets)) != NULL) {
		p = skb_put(coalesced, skb->len);
		skb_copy_bits(skb, 0, p, skb->len);
		kfree_skb(skb);
	}

	return coalesced;
}
*/
