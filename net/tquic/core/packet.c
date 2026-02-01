// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: WAN Bonding over QUIC - Packet Parsing and Construction
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * This file implements QUIC packet parsing and construction including:
 * - Long header packets (Initial, 0-RTT, Handshake, Retry)
 * - Short header packets (1-RTT)
 * - Variable-length packet number encoding/decoding
 * - Version negotiation packets
 * - Stateless reset handling
 * - Coalesced packet handling
 * - Packet validation
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/random.h>
#include <linux/crc32.h>
#include <linux/string.h>
#include <crypto/utils.h>
#include <net/tquic.h>
#include <net/tquic_frame.h>
#include <asm/unaligned.h>

/* QUIC packet type constants */
#define QUIC_PACKET_TYPE_INITIAL	0x00
#define QUIC_PACKET_TYPE_0RTT		0x01
#define QUIC_PACKET_TYPE_HANDSHAKE	0x02
#define QUIC_PACKET_TYPE_RETRY		0x03

/* Header form bits */
#define QUIC_HEADER_FORM_LONG		0x80
#define QUIC_HEADER_FORM_SHORT		0x00
#define QUIC_FIXED_BIT			0x40

/* Long header type mask */
#define QUIC_LONG_HEADER_TYPE_MASK	0x30
#define QUIC_LONG_HEADER_TYPE_SHIFT	4

/* Short header bits */
#define QUIC_SHORT_HEADER_SPIN_BIT	0x20
#define QUIC_SHORT_HEADER_RESERVED	0x18
#define QUIC_SHORT_HEADER_KEY_PHASE	0x04
#define QUIC_SHORT_HEADER_PN_LEN_MASK	0x03

/* Packet number length encoding */
#define QUIC_PN_LEN_1			0x00
#define QUIC_PN_LEN_2			0x01
#define QUIC_PN_LEN_3			0x02
#define QUIC_PN_LEN_4			0x03

/* Version constants */
#define QUIC_VERSION_NEGOTIATION	0x00000000
#define QUIC_VERSION_1			0x00000001
#define QUIC_VERSION_2			0x6b3343cf

/* Retry packet constants */
#define QUIC_RETRY_INTEGRITY_TAG_LEN	16

/* Stateless reset constants */
#define QUIC_STATELESS_RESET_TOKEN_LEN	16
#define QUIC_MIN_STATELESS_RESET_LEN	21

/* Maximum packet sizes */
#define QUIC_MAX_PACKET_SIZE		65527

/* Variable-length integer encoding thresholds */
#define QUIC_VARINT_1BYTE_MAX		63
#define QUIC_VARINT_2BYTE_MAX		16383
#define QUIC_VARINT_4BYTE_MAX		1073741823
#define QUIC_VARINT_8BYTE_MAX		4611686018427387903ULL

/* Variable-length integer prefix bits */
#define QUIC_VARINT_1BYTE_PREFIX	0x00
#define QUIC_VARINT_2BYTE_PREFIX	0x40
#define QUIC_VARINT_4BYTE_PREFIX	0x80
#define QUIC_VARINT_8BYTE_PREFIX	0xc0
#define QUIC_VARINT_PREFIX_MASK		0xc0

/*
 * Note: enum tquic_packet_type, struct tquic_packet_header, and
 * struct tquic_packet are defined in <net/tquic.h>
 */

/* Slab cache for packet structures */
static struct kmem_cache *tquic_packet_cache;

/*
 * Variable-length integer encoding/decoding
 *
 * QUIC uses variable-length integers throughout the protocol.
 * The encoding uses the two most significant bits to indicate length:
 *   00 = 1 byte  (6 bits of value)
 *   01 = 2 bytes (14 bits of value)
 *   10 = 4 bytes (30 bits of value)
 *   11 = 8 bytes (62 bits of value)
 */

/**
 * tquic_varint_decode - Decode a variable-length integer
 * @data: Pointer to data buffer
 * @len: Available length in buffer
 * @value: Output value
 *
 * Returns: Number of bytes consumed, or negative error
 */
int tquic_varint_decode(const u8 *data, size_t len, u64 *value)
{
	u8 prefix;
	int bytes;

	if (len < 1)
		return -EINVAL;

	prefix = data[0] & QUIC_VARINT_PREFIX_MASK;

	switch (prefix) {
	case QUIC_VARINT_1BYTE_PREFIX:
		bytes = 1;
		break;
	case QUIC_VARINT_2BYTE_PREFIX:
		bytes = 2;
		break;
	case QUIC_VARINT_4BYTE_PREFIX:
		bytes = 4;
		break;
	case QUIC_VARINT_8BYTE_PREFIX:
		bytes = 8;
		break;
	default:
		return -EINVAL;
	}

	if (len < bytes)
		return -EINVAL;

	switch (bytes) {
	case 1:
		*value = data[0] & 0x3f;
		break;
	case 2:
		*value = ((u64)(data[0] & 0x3f) << 8) | data[1];
		break;
	case 4:
		*value = ((u64)(data[0] & 0x3f) << 24) |
			 ((u64)data[1] << 16) |
			 ((u64)data[2] << 8) |
			 data[3];
		break;
	case 8:
		*value = ((u64)(data[0] & 0x3f) << 56) |
			 ((u64)data[1] << 48) |
			 ((u64)data[2] << 40) |
			 ((u64)data[3] << 32) |
			 ((u64)data[4] << 24) |
			 ((u64)data[5] << 16) |
			 ((u64)data[6] << 8) |
			 data[7];
		break;
	}

	return bytes;
}
EXPORT_SYMBOL_GPL(tquic_varint_decode);

/**
 * tquic_varint_encode - Encode a variable-length integer
 * @value: Value to encode
 * @data: Output buffer
 * @len: Available buffer length
 *
 * Returns: Number of bytes written, or negative error
 */
int tquic_varint_encode(u64 value, u8 *data, size_t len)
{
	if (value <= QUIC_VARINT_1BYTE_MAX) {
		if (len < 1)
			return -ENOSPC;
		data[0] = (u8)value;
		return 1;
	} else if (value <= QUIC_VARINT_2BYTE_MAX) {
		if (len < 2)
			return -ENOSPC;
		data[0] = QUIC_VARINT_2BYTE_PREFIX | ((value >> 8) & 0x3f);
		data[1] = value & 0xff;
		return 2;
	} else if (value <= QUIC_VARINT_4BYTE_MAX) {
		if (len < 4)
			return -ENOSPC;
		data[0] = QUIC_VARINT_4BYTE_PREFIX | ((value >> 24) & 0x3f);
		data[1] = (value >> 16) & 0xff;
		data[2] = (value >> 8) & 0xff;
		data[3] = value & 0xff;
		return 4;
	} else if (value <= QUIC_VARINT_8BYTE_MAX) {
		if (len < 8)
			return -ENOSPC;
		data[0] = QUIC_VARINT_8BYTE_PREFIX | ((value >> 56) & 0x3f);
		data[1] = (value >> 48) & 0xff;
		data[2] = (value >> 40) & 0xff;
		data[3] = (value >> 32) & 0xff;
		data[4] = (value >> 24) & 0xff;
		data[5] = (value >> 16) & 0xff;
		data[6] = (value >> 8) & 0xff;
		data[7] = value & 0xff;
		return 8;
	}

	return -EOVERFLOW;
}
EXPORT_SYMBOL_GPL(tquic_varint_encode);

/**
 * tquic_varint_len - Get encoding length for a value
 * @value: Value to encode
 *
 * Returns: Number of bytes needed to encode value
 */
int tquic_varint_len(u64 value)
{
	if (value <= QUIC_VARINT_1BYTE_MAX)
		return 1;
	else if (value <= QUIC_VARINT_2BYTE_MAX)
		return 2;
	else if (value <= QUIC_VARINT_4BYTE_MAX)
		return 4;
	else if (value <= QUIC_VARINT_8BYTE_MAX)
		return 8;
	return -EOVERFLOW;
}
EXPORT_SYMBOL_GPL(tquic_varint_len);

/*
 * Packet Number Encoding/Decoding
 *
 * Packet numbers are encoded using 1-4 bytes. The sender chooses
 * the encoding length based on the largest acknowledged packet number.
 * The receiver must decode using the largest received packet number.
 */

/**
 * tquic_pn_encode_len - Determine encoding length for packet number
 * @pn: Packet number to encode
 * @largest_acked: Largest acknowledged packet number
 *
 * Returns: Encoding length (1-4 bytes)
 */
int tquic_pn_encode_len(u64 pn, u64 largest_acked)
{
	u64 diff;
	u64 range;

	/*
	 * The number of bits must be large enough to represent the range
	 * between the packet number and the largest acknowledged number.
	 */
	if (largest_acked == U64_MAX)
		diff = pn;
	else
		diff = pn - largest_acked;

	/*
	 * Choose the smallest encoding that can represent twice the
	 * difference (to allow for packets in flight).
	 */
	range = diff * 2;

	if (range < (1ULL << 7))
		return 1;
	else if (range < (1ULL << 15))
		return 2;
	else if (range < (1ULL << 23))
		return 3;
	else
		return 4;
}
EXPORT_SYMBOL_GPL(tquic_pn_encode_len);

/**
 * tquic_pn_encode - Encode a packet number
 * @pn: Packet number to encode
 * @len: Encoding length (1-4)
 * @data: Output buffer
 * @buflen: Available buffer length
 *
 * Returns: Number of bytes written, or negative error
 */
int tquic_pn_encode(u64 pn, int len, u8 *data, size_t buflen)
{
	if (len < 1 || len > 4)
		return -EINVAL;

	if (buflen < len)
		return -ENOSPC;

	/* Encode only the low-order bytes */
	switch (len) {
	case 1:
		data[0] = pn & 0xff;
		break;
	case 2:
		data[0] = (pn >> 8) & 0xff;
		data[1] = pn & 0xff;
		break;
	case 3:
		data[0] = (pn >> 16) & 0xff;
		data[1] = (pn >> 8) & 0xff;
		data[2] = pn & 0xff;
		break;
	case 4:
		data[0] = (pn >> 24) & 0xff;
		data[1] = (pn >> 16) & 0xff;
		data[2] = (pn >> 8) & 0xff;
		data[3] = pn & 0xff;
		break;
	}

	return len;
}
EXPORT_SYMBOL_GPL(tquic_pn_encode);

/**
 * tquic_pn_decode - Decode a packet number
 * @data: Input buffer containing truncated packet number
 * @len: Length of truncated packet number (1-4)
 * @largest_pn: Largest packet number received so far
 *
 * Returns: Decoded full packet number
 *
 * The packet number is decoded by finding the value closest to
 * largest_pn + 1 that matches the truncated value.
 */
u64 tquic_pn_decode(const u8 *data, int len, u64 largest_pn)
{
	u64 truncated_pn = 0;
	u64 expected_pn;
	u64 pn_win;
	u64 pn_hwin;
	u64 pn_mask;
	u64 candidate_pn;

	if (len < 1 || len > 4)
		return 0;

	/* Read truncated packet number */
	switch (len) {
	case 1:
		truncated_pn = data[0];
		break;
	case 2:
		truncated_pn = ((u64)data[0] << 8) | data[1];
		break;
	case 3:
		truncated_pn = ((u64)data[0] << 16) |
			       ((u64)data[1] << 8) |
			       data[2];
		break;
	case 4:
		truncated_pn = ((u64)data[0] << 24) |
			       ((u64)data[1] << 16) |
			       ((u64)data[2] << 8) |
			       data[3];
		break;
	}

	/* Calculate expected packet number */
	expected_pn = largest_pn + 1;
	pn_win = 1ULL << (len * 8);
	pn_hwin = pn_win / 2;
	pn_mask = pn_win - 1;

	/*
	 * Find the candidate closest to the expected value.
	 * candidate_pn is formed by replacing the lower bits of expected_pn
	 * with the truncated value.
	 */
	candidate_pn = (expected_pn & ~pn_mask) | truncated_pn;

	/*
	 * Adjust if the candidate is too far from expected.
	 * This handles wrap-around cases.
	 */
	if (candidate_pn <= expected_pn - pn_hwin &&
	    candidate_pn < (1ULL << 62) - pn_win)
		return candidate_pn + pn_win;

	if (candidate_pn > expected_pn + pn_hwin &&
	    candidate_pn >= pn_win)
		return candidate_pn - pn_win;

	return candidate_pn;
}
EXPORT_SYMBOL_GPL(tquic_pn_decode);

/*
 * Long Header Packet Parsing
 *
 * Long header format:
 *   Header Form (1) = 1
 *   Fixed Bit (1) = 1
 *   Long Packet Type (2)
 *   Type-Specific Bits (4)
 *   Version (32)
 *   DCID Len (8)
 *   DCID (0-20)
 *   SCID Len (8)
 *   SCID (0-20)
 *   Type-specific fields...
 */

/**
 * tquic_parse_long_header - Parse a long header packet
 * @data: Packet data
 * @len: Packet length
 * @hdr: Output header structure
 * @largest_pn: Largest packet number for PN decoding
 *
 * Returns: Number of bytes consumed, or negative error
 */
int tquic_parse_long_header(const u8 *data, size_t len,
			    struct tquic_packet_header *hdr,
			    u64 largest_pn)
{
	size_t offset = 0;
	u8 first_byte;
	u8 pkt_type;
	u64 pn_tmp;
	int ret;

	if (len < 7)  /* Minimum: 1 + 4 + 1 + 0 + 1 + 0 */
		return -EINVAL;

	memset(hdr, 0, sizeof(*hdr));

	/* First byte */
	first_byte = data[offset++];

	/* Verify header form is long */
	if (!(first_byte & QUIC_HEADER_FORM_LONG))
		return -EINVAL;

	/* Verify fixed bit */
	if (!(first_byte & QUIC_FIXED_BIT))
		return -EPROTO;

	/* Extract packet type */
	pkt_type = (first_byte & QUIC_LONG_HEADER_TYPE_MASK) >>
		   QUIC_LONG_HEADER_TYPE_SHIFT;

	/* Version (4 bytes, big-endian) */
	hdr->version = get_unaligned_be32(&data[offset]);
	offset += 4;

	/* Handle version negotiation specially */
	if (hdr->version == QUIC_VERSION_NEGOTIATION) {
		hdr->type = TQUIC_PKT_VERSION_NEG;

		/* DCID length and DCID */
		if (offset >= len)
			return -EINVAL;
		hdr->dcid_len = data[offset++];
		if (hdr->dcid_len > TQUIC_MAX_CID_LEN)
			return -EINVAL;
		if (offset + hdr->dcid_len > len)
			return -EINVAL;
		memcpy(hdr->dcid, &data[offset], hdr->dcid_len);
		offset += hdr->dcid_len;

		/* SCID length and SCID */
		if (offset >= len)
			return -EINVAL;
		hdr->scid_len = data[offset++];
		if (hdr->scid_len > TQUIC_MAX_CID_LEN)
			return -EINVAL;
		if (offset + hdr->scid_len > len)
			return -EINVAL;
		memcpy(hdr->scid, &data[offset], hdr->scid_len);
		offset += hdr->scid_len;

		hdr->header_len = offset;
		hdr->payload_len = len - offset;
		return offset;
	}

	/* Map long header type to internal type */
	switch (pkt_type) {
	case QUIC_PACKET_TYPE_INITIAL:
		hdr->type = TQUIC_PKT_INITIAL;
		break;
	case QUIC_PACKET_TYPE_0RTT:
		hdr->type = TQUIC_PKT_0RTT;
		break;
	case QUIC_PACKET_TYPE_HANDSHAKE:
		hdr->type = TQUIC_PKT_HANDSHAKE;
		break;
	case QUIC_PACKET_TYPE_RETRY:
		hdr->type = TQUIC_PKT_RETRY;
		break;
	default:
		return -EINVAL;
	}

	/* DCID length and DCID */
	if (offset >= len)
		return -EINVAL;
	hdr->dcid_len = data[offset++];
	if (hdr->dcid_len > TQUIC_MAX_CID_LEN)
		return -EINVAL;
	if (offset + hdr->dcid_len > len)
		return -EINVAL;
	memcpy(hdr->dcid, &data[offset], hdr->dcid_len);
	offset += hdr->dcid_len;

	/* SCID length and SCID */
	if (offset >= len)
		return -EINVAL;
	hdr->scid_len = data[offset++];
	if (hdr->scid_len > TQUIC_MAX_CID_LEN)
		return -EINVAL;
	if (offset + hdr->scid_len > len)
		return -EINVAL;
	memcpy(hdr->scid, &data[offset], hdr->scid_len);
	offset += hdr->scid_len;

	/* Type-specific fields */
	if (hdr->type == TQUIC_PKT_RETRY) {
		/*
		 * Retry packets don't have packet number or length fields.
		 * The payload is the Retry Token followed by the Retry
		 * Integrity Tag.
		 */
		hdr->header_len = offset;
		hdr->payload_len = len - offset;
		if (hdr->payload_len < QUIC_RETRY_INTEGRITY_TAG_LEN)
			return -EINVAL;
		hdr->token = (u8 *)&data[offset];
		hdr->token_len = hdr->payload_len - QUIC_RETRY_INTEGRITY_TAG_LEN;
		return offset;
	}

	/* Token (Initial packets only) */
	if (hdr->type == TQUIC_PKT_INITIAL) {
		ret = tquic_varint_decode(&data[offset], len - offset,
					  &hdr->token_len);
		if (ret < 0)
			return ret;
		offset += ret;

		/*
		 * Validate token length to prevent memory exhaustion attacks.
		 * An attacker could send a varint encoding a huge token length
		 * to cause excessive memory allocation.
		 */
		if (hdr->token_len > TQUIC_MAX_TOKEN_LEN)
			return -EINVAL;

		if (hdr->token_len > 0) {
			if (offset + hdr->token_len > len)
				return -EINVAL;
			hdr->token = (u8 *)&data[offset];
			offset += hdr->token_len;
		}
	}

	/* Length field (varint) */
	ret = tquic_varint_decode(&data[offset], len - offset, &hdr->payload_len);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Verify we have enough data for payload */
	if (offset + hdr->payload_len > len)
		return -EINVAL;

	/* Packet number (1-4 bytes, encoded in first byte's low bits) */
	hdr->pn_len = (first_byte & 0x03) + 1;
	if (offset + hdr->pn_len > len)
		return -EINVAL;

	/*
	 * Note: In practice, the packet number is protected by header
	 * protection. Here we parse the unprotected form for simplicity.
	 * The caller must remove header protection before calling this.
	 */
	pn_tmp = tquic_pn_decode(&data[offset], hdr->pn_len, largest_pn);
	hdr->pn = pn_tmp;
	offset += hdr->pn_len;

	hdr->header_len = offset;
	/* Adjust payload_len to not include packet number */
	hdr->payload_len -= hdr->pn_len;

	return offset;
}
EXPORT_SYMBOL_GPL(tquic_parse_long_header);

/*
 * Short Header Packet Parsing
 *
 * Short header format:
 *   Header Form (1) = 0
 *   Fixed Bit (1) = 1
 *   Spin Bit (1)
 *   Reserved (2)
 *   Key Phase (1)
 *   Packet Number Length (2)
 *   Destination Connection ID (variable, known from context)
 *   Packet Number (1-4 bytes)
 *   Payload
 */

/**
 * tquic_parse_short_header - Parse a short header packet
 * @data: Packet data
 * @len: Packet length
 * @hdr: Output header structure
 * @dcid_len: Expected DCID length (from connection state)
 * @largest_pn: Largest packet number for PN decoding
 *
 * Returns: Number of bytes consumed, or negative error
 */
int tquic_parse_short_header(const u8 *data, size_t len,
			     struct tquic_packet_header *hdr,
			     u8 dcid_len, u64 largest_pn)
{
	size_t offset = 0;
	u8 first_byte;
	u64 pn_tmp;

	if (len < 1 + dcid_len + 1)  /* First byte + DCID + min PN */
		return -EINVAL;

	memset(hdr, 0, sizeof(*hdr));
	hdr->type = TQUIC_PKT_1RTT;

	/* First byte */
	first_byte = data[offset++];

	/* Verify header form is short */
	if (first_byte & QUIC_HEADER_FORM_LONG)
		return -EINVAL;

	/* Verify fixed bit */
	if (!(first_byte & QUIC_FIXED_BIT))
		return -EPROTO;

	/* Extract spin bit */
	hdr->spin_bit = (first_byte & QUIC_SHORT_HEADER_SPIN_BIT) ? 1 : 0;

	/* Extract key phase */
	hdr->key_phase = (first_byte & QUIC_SHORT_HEADER_KEY_PHASE) ? 1 : 0;

	/* Packet number length */
	hdr->pn_len = (first_byte & QUIC_SHORT_HEADER_PN_LEN_MASK) + 1;

	/* DCID (length known from connection context) */
	hdr->dcid_len = dcid_len;
	if (offset + dcid_len > len)
		return -EINVAL;
	memcpy(hdr->dcid, &data[offset], dcid_len);
	offset += dcid_len;

	/* Packet number */
	if (offset + hdr->pn_len > len)
		return -EINVAL;
	pn_tmp = tquic_pn_decode(&data[offset], hdr->pn_len, largest_pn);
	hdr->pn = pn_tmp;
	offset += hdr->pn_len;

	hdr->header_len = offset;
	hdr->payload_len = len - offset;

	return offset;
}
EXPORT_SYMBOL_GPL(tquic_parse_short_header);

/**
 * tquic_is_long_header - Check if packet has a long header
 * @data: Packet data
 * @len: Packet length
 *
 * Returns: true if long header, false if short header
 */
bool tquic_is_long_header(const u8 *data, size_t len)
{
	if (len < 1)
		return false;
	return (data[0] & QUIC_HEADER_FORM_LONG) != 0;
}
EXPORT_SYMBOL_GPL(tquic_is_long_header);

/**
 * tquic_get_packet_type - Determine packet type from first byte
 * @data: Packet data
 * @len: Packet length
 *
 * Returns: Packet type or negative error
 */
int tquic_get_packet_type(const u8 *data, size_t len)
{
	u8 first_byte;
	u32 version;

	if (len < 1)
		return -EINVAL;

	first_byte = data[0];

	if (!(first_byte & QUIC_HEADER_FORM_LONG)) {
		/* Short header is always 1-RTT */
		return TQUIC_PKT_1RTT;
	}

	/* Long header - need version to determine type */
	if (len < 5)
		return -EINVAL;

	version = get_unaligned_be32(&data[1]);

	if (version == QUIC_VERSION_NEGOTIATION)
		return TQUIC_PKT_VERSION_NEG;

	switch ((first_byte & QUIC_LONG_HEADER_TYPE_MASK) >>
		QUIC_LONG_HEADER_TYPE_SHIFT) {
	case QUIC_PACKET_TYPE_INITIAL:
		return TQUIC_PKT_INITIAL;
	case QUIC_PACKET_TYPE_0RTT:
		return TQUIC_PKT_0RTT;
	case QUIC_PACKET_TYPE_HANDSHAKE:
		return TQUIC_PKT_HANDSHAKE;
	case QUIC_PACKET_TYPE_RETRY:
		return TQUIC_PKT_RETRY;
	default:
		return -EINVAL;
	}
}
EXPORT_SYMBOL_GPL(tquic_get_packet_type);

/*
 * Version Negotiation Packet Handling
 *
 * Sent by server when it receives a client Initial with an
 * unsupported version. Contains list of supported versions.
 */

/**
 * tquic_build_version_negotiation - Build a version negotiation packet
 * @dcid: Destination CID (client's SCID)
 * @dcid_len: DCID length
 * @scid: Source CID (client's DCID)
 * @scid_len: SCID length
 * @versions: Array of supported versions
 * @num_versions: Number of supported versions
 * @buf: Output buffer
 * @buflen: Buffer length
 *
 * Returns: Packet length, or negative error
 */
int tquic_build_version_negotiation(const u8 *dcid, u8 dcid_len,
				    const u8 *scid, u8 scid_len,
				    const u32 *versions, int num_versions,
				    u8 *buf, size_t buflen)
{
	size_t offset = 0;
	int i;
	size_t needed;

	/* Calculate needed space */
	needed = 1 + 4 + 1 + dcid_len + 1 + scid_len + (4 * num_versions);
	if (buflen < needed)
		return -ENOSPC;

	/* First byte: set form bit, random other bits for unpredictability */
	buf[offset++] = QUIC_HEADER_FORM_LONG | (get_random_u8() & 0x7f);

	/* Version = 0 for version negotiation */
	put_unaligned_be32(0, &buf[offset]);
	offset += 4;

	/* DCID length and DCID */
	buf[offset++] = dcid_len;
	memcpy(&buf[offset], dcid, dcid_len);
	offset += dcid_len;

	/* SCID length and SCID */
	buf[offset++] = scid_len;
	memcpy(&buf[offset], scid, scid_len);
	offset += scid_len;

	/* Supported versions */
	for (i = 0; i < num_versions; i++) {
		put_unaligned_be32(versions[i], &buf[offset]);
		offset += 4;
	}

	return offset;
}
EXPORT_SYMBOL_GPL(tquic_build_version_negotiation);

/**
 * tquic_parse_version_negotiation - Parse a version negotiation packet
 * @data: Packet data (after header parsing)
 * @len: Data length
 * @versions: Output array for supported versions
 * @max_versions: Maximum versions to store
 * @num_versions: Output for actual number of versions
 *
 * Returns: 0 on success, negative error otherwise
 */
int tquic_parse_version_negotiation(const u8 *data, size_t len,
				    u32 *versions, int max_versions,
				    int *num_versions)
{
	int count = 0;
	size_t offset = 0;

	/* Each version is 4 bytes */
	if (len % 4 != 0)
		return -EINVAL;

	*num_versions = len / 4;

	while (offset + 4 <= len && count < max_versions) {
		versions[count++] = get_unaligned_be32(&data[offset]);
		offset += 4;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_parse_version_negotiation);

/*
 * Stateless Reset Handling
 *
 * Stateless resets allow a server to signal that it has lost state
 * for a connection. They look like short header packets but end
 * with a stateless reset token.
 */

/**
 * tquic_build_stateless_reset - Build a stateless reset packet
 * @token: Stateless reset token (16 bytes)
 * @buf: Output buffer
 * @buflen: Buffer length (should be unpredictable, min 21 bytes)
 *
 * Returns: Packet length, or negative error
 */
int tquic_build_stateless_reset(const u8 *token, u8 *buf, size_t buflen)
{
	size_t random_len;

	if (buflen < QUIC_MIN_STATELESS_RESET_LEN)
		return -ENOSPC;

	/*
	 * Stateless reset format:
	 * - First byte looks like short header (form bit = 0, fixed bit = 1)
	 * - Random bytes (unpredictable length)
	 * - Stateless Reset Token (16 bytes at end)
	 */

	/* Leave room for token at end */
	random_len = buflen - QUIC_STATELESS_RESET_TOKEN_LEN;

	/* Fill with random data */
	get_random_bytes(buf, random_len);

	/* First byte must look like short header */
	buf[0] = (buf[0] & ~QUIC_HEADER_FORM_LONG) | QUIC_FIXED_BIT;

	/* Append stateless reset token */
	memcpy(&buf[random_len], token, QUIC_STATELESS_RESET_TOKEN_LEN);

	return buflen;
}
EXPORT_SYMBOL_GPL(tquic_build_stateless_reset);

/**
 * tquic_is_stateless_reset - Check if packet is a stateless reset
 * @data: Packet data
 * @len: Packet length
 * @tokens: Array of known stateless reset tokens
 * @num_tokens: Number of tokens
 *
 * Returns: true if stateless reset detected
 */
bool tquic_is_stateless_reset(const u8 *data, size_t len,
			      const u8 (*tokens)[QUIC_STATELESS_RESET_TOKEN_LEN],
			      int num_tokens)
{
	const u8 *pkt_token;
	int i;

	if (len < QUIC_MIN_STATELESS_RESET_LEN)
		return false;

	/* Must look like short header */
	if (data[0] & QUIC_HEADER_FORM_LONG)
		return false;

	/* Token is at the end of the packet */
	pkt_token = &data[len - QUIC_STATELESS_RESET_TOKEN_LEN];

	/* Check against known tokens */
	for (i = 0; i < num_tokens; i++) {
		if (crypto_memneq(pkt_token, tokens[i],
				  QUIC_STATELESS_RESET_TOKEN_LEN) == 0)
			return true;
	}

	return false;
}
EXPORT_SYMBOL_GPL(tquic_is_stateless_reset);

/*
 * Retry Packet Handling
 *
 * Retry packets are sent by servers to validate client addresses
 * and provide tokens for resumption.
 */

/**
 * tquic_build_retry - Build a Retry packet
 * @version: QUIC version
 * @dcid: Destination CID
 * @dcid_len: DCID length
 * @scid: Source CID (new server CID)
 * @scid_len: SCID length
 * @odcid: Original DCID from client
 * @odcid_len: Original DCID length
 * @token: Retry token
 * @token_len: Token length
 * @buf: Output buffer
 * @buflen: Buffer length
 *
 * Returns: Packet length, or negative error
 *
 * Note: Caller must compute and append the Retry Integrity Tag
 */
int tquic_build_retry(u32 version, const u8 *dcid, u8 dcid_len,
		      const u8 *scid, u8 scid_len,
		      const u8 *odcid, u8 odcid_len,
		      const u8 *token, size_t token_len,
		      u8 *buf, size_t buflen)
{
	size_t offset = 0;
	size_t needed;

	/* Calculate needed space (excluding integrity tag) */
	needed = 1 + 4 + 1 + dcid_len + 1 + scid_len + token_len;
	if (buflen < needed + QUIC_RETRY_INTEGRITY_TAG_LEN)
		return -ENOSPC;

	/* First byte */
	buf[offset++] = QUIC_HEADER_FORM_LONG | QUIC_FIXED_BIT |
			(QUIC_PACKET_TYPE_RETRY << QUIC_LONG_HEADER_TYPE_SHIFT);

	/* Version */
	put_unaligned_be32(version, &buf[offset]);
	offset += 4;

	/* DCID length and DCID */
	buf[offset++] = dcid_len;
	memcpy(&buf[offset], dcid, dcid_len);
	offset += dcid_len;

	/* SCID length and SCID */
	buf[offset++] = scid_len;
	memcpy(&buf[offset], scid, scid_len);
	offset += scid_len;

	/* Retry Token */
	memcpy(&buf[offset], token, token_len);
	offset += token_len;

	/*
	 * Note: The Retry Integrity Tag must be computed using AEAD
	 * over the pseudo-packet (ODCID length || ODCID || Retry packet).
	 * The crypto module handles this.
	 */

	return offset;
}
EXPORT_SYMBOL_GPL(tquic_build_retry);

/*
 * Long Header Packet Construction
 */

/**
 * tquic_build_long_header - Build a long header packet
 * @type: Packet type (Initial, 0-RTT, Handshake)
 * @version: QUIC version
 * @dcid: Destination CID
 * @dcid_len: DCID length
 * @scid: Source CID
 * @scid_len: SCID length
 * @token: Token (Initial only, can be NULL)
 * @token_len: Token length
 * @pn: Packet number
 * @pn_len: Packet number length (1-4)
 * @payload: Payload data
 * @payload_len: Payload length
 * @buf: Output buffer
 * @buflen: Buffer length
 *
 * Returns: Packet length, or negative error
 */
int tquic_build_long_header(enum tquic_packet_type type, u32 version,
			    const u8 *dcid, u8 dcid_len,
			    const u8 *scid, u8 scid_len,
			    const u8 *token, size_t token_len,
			    u64 pn, int pn_len,
			    const u8 *payload, size_t payload_len,
			    u8 *buf, size_t buflen)
{
	size_t offset = 0;
	u8 first_byte;
	u8 pkt_type;
	int ret;
	int len_field_len;
	u64 length;

	if (pn_len < 1 || pn_len > 4)
		return -EINVAL;

	/* Map internal type to wire format */
	switch (type) {
	case TQUIC_PKT_INITIAL:
		pkt_type = QUIC_PACKET_TYPE_INITIAL;
		break;
	case TQUIC_PKT_0RTT:
		pkt_type = QUIC_PACKET_TYPE_0RTT;
		break;
	case TQUIC_PKT_HANDSHAKE:
		pkt_type = QUIC_PACKET_TYPE_HANDSHAKE;
		break;
	default:
		return -EINVAL;
	}

	/* Calculate length field value (pn_len + payload_len) */
	length = pn_len + payload_len;
	len_field_len = tquic_varint_len(length);
	if (len_field_len < 0)
		return len_field_len;

	/* Check buffer size */
	if (buflen < 1 + 4 + 1 + dcid_len + 1 + scid_len +
	    (type == TQUIC_PKT_INITIAL ? tquic_varint_len(token_len) + token_len : 0) +
	    len_field_len + pn_len + payload_len)
		return -ENOSPC;

	/* First byte */
	first_byte = QUIC_HEADER_FORM_LONG | QUIC_FIXED_BIT |
		     (pkt_type << QUIC_LONG_HEADER_TYPE_SHIFT) |
		     (pn_len - 1);
	buf[offset++] = first_byte;

	/* Version */
	put_unaligned_be32(version, &buf[offset]);
	offset += 4;

	/* DCID length and DCID */
	buf[offset++] = dcid_len;
	memcpy(&buf[offset], dcid, dcid_len);
	offset += dcid_len;

	/* SCID length and SCID */
	buf[offset++] = scid_len;
	memcpy(&buf[offset], scid, scid_len);
	offset += scid_len;

	/* Token (Initial only) */
	if (type == TQUIC_PKT_INITIAL) {
		ret = tquic_varint_encode(token_len, &buf[offset],
					  buflen - offset);
		if (ret < 0)
			return ret;
		offset += ret;

		if (token_len > 0) {
			memcpy(&buf[offset], token, token_len);
			offset += token_len;
		}
	}

	/* Length field */
	ret = tquic_varint_encode(length, &buf[offset], buflen - offset);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Packet number */
	ret = tquic_pn_encode(pn, pn_len, &buf[offset], buflen - offset);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Payload */
	memcpy(&buf[offset], payload, payload_len);
	offset += payload_len;

	return offset;
}
EXPORT_SYMBOL_GPL(tquic_build_long_header);

/*
 * Short Header Packet Construction
 */

/**
 * tquic_build_short_header - Build a short header packet
 * @dcid: Destination CID
 * @dcid_len: DCID length
 * @pn: Packet number
 * @pn_len: Packet number length (1-4)
 * @key_phase: Key phase bit
 * @spin_bit: Spin bit
 * @payload: Payload data
 * @payload_len: Payload length
 * @buf: Output buffer
 * @buflen: Buffer length
 *
 * Returns: Packet length, or negative error
 */
int tquic_build_short_header(const u8 *dcid, u8 dcid_len,
			     u64 pn, int pn_len,
			     u8 key_phase, u8 spin_bit,
			     const u8 *payload, size_t payload_len,
			     u8 *buf, size_t buflen)
{
	size_t offset = 0;
	u8 first_byte;
	int ret;

	if (pn_len < 1 || pn_len > 4)
		return -EINVAL;

	/* Check buffer size */
	if (buflen < 1 + dcid_len + pn_len + payload_len)
		return -ENOSPC;

	/* First byte */
	first_byte = QUIC_FIXED_BIT |
		     (spin_bit ? QUIC_SHORT_HEADER_SPIN_BIT : 0) |
		     (key_phase ? QUIC_SHORT_HEADER_KEY_PHASE : 0) |
		     (pn_len - 1);
	buf[offset++] = first_byte;

	/* DCID */
	memcpy(&buf[offset], dcid, dcid_len);
	offset += dcid_len;

	/* Packet number */
	ret = tquic_pn_encode(pn, pn_len, &buf[offset], buflen - offset);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Payload */
	memcpy(&buf[offset], payload, payload_len);
	offset += payload_len;

	return offset;
}
EXPORT_SYMBOL_GPL(tquic_build_short_header);

/*
 * Coalesced Packet Handling
 *
 * Multiple QUIC packets can be coalesced into a single UDP datagram.
 * All packets must have the same DCID. Long header packets include
 * their length, so they can be parsed individually.
 */

/**
 * tquic_split_coalesced - Split a coalesced packet into individual packets
 * @data: Coalesced packet data
 * @len: Total length
 * @packets: Output array of packet pointers
 * @lengths: Output array of packet lengths
 * @max_packets: Maximum packets to extract
 * @num_packets: Output for actual number of packets
 *
 * Returns: 0 on success, negative error otherwise
 */
int tquic_split_coalesced(const u8 *data, size_t len,
			  const u8 **packets, size_t *lengths,
			  int max_packets, int *num_packets)
{
	size_t offset = 0;
	int count = 0;
	u64 pkt_len;
	int ret;
	u8 dcid_len, scid_len;
	u64 token_len;
	size_t hdr_len;

	while (offset < len && count < max_packets) {
		packets[count] = &data[offset];

		if (!tquic_is_long_header(&data[offset], len - offset)) {
			/*
			 * Short header packet - must be the last packet.
			 * It consumes the rest of the datagram.
			 */
			lengths[count] = len - offset;
			count++;
			break;
		}

		/*
		 * Long header packet - we need to find its length.
		 * Parse enough of the header to get the Length field.
		 */
		if (offset + 5 > len)
			return -EINVAL;

		/* Skip to DCID length */
		hdr_len = 5;

		/* DCID */
		if (offset + hdr_len >= len)
			return -EINVAL;
		dcid_len = data[offset + hdr_len];
		if (dcid_len > TQUIC_MAX_CID_LEN)
			return -EINVAL;
		hdr_len += 1 + dcid_len;

		/* SCID */
		if (offset + hdr_len >= len)
			return -EINVAL;
		scid_len = data[offset + hdr_len];
		if (scid_len > TQUIC_MAX_CID_LEN)
			return -EINVAL;
		hdr_len += 1 + scid_len;

		/* Check for Initial packet (has token) */
		if ((data[offset] & QUIC_LONG_HEADER_TYPE_MASK) ==
		    (QUIC_PACKET_TYPE_INITIAL << QUIC_LONG_HEADER_TYPE_SHIFT)) {
			/* Token length (varint) */
			ret = tquic_varint_decode(&data[offset + hdr_len],
						  len - offset - hdr_len,
						  &token_len);
			if (ret < 0)
				return ret;
			/*
			 * Validate token length to prevent integer overflow
			 * and memory exhaustion attacks from malicious packets.
			 */
			if (token_len > TQUIC_MAX_TOKEN_LEN)
				return -EINVAL;
			hdr_len += ret + token_len;
		}

		/* Check for Retry packet (no length field) */
		if ((data[offset] & QUIC_LONG_HEADER_TYPE_MASK) ==
		    (QUIC_PACKET_TYPE_RETRY << QUIC_LONG_HEADER_TYPE_SHIFT)) {
			/* Retry packets consume rest of datagram */
			lengths[count] = len - offset;
			count++;
			break;
		}

		/* Length field */
		if (offset + hdr_len >= len)
			return -EINVAL;
		ret = tquic_varint_decode(&data[offset + hdr_len],
					  len - offset - hdr_len,
					  &pkt_len);
		if (ret < 0)
			return ret;
		hdr_len += ret;

		/* Total packet length */
		if (offset + hdr_len + pkt_len > len)
			return -EINVAL;

		lengths[count] = hdr_len + pkt_len;
		offset += lengths[count];
		count++;
	}

	*num_packets = count;
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_split_coalesced);

/**
 * tquic_coalesce_packets - Coalesce multiple packets into one datagram
 * @packets: Array of packet data
 * @lengths: Array of packet lengths
 * @num_packets: Number of packets
 * @buf: Output buffer
 * @buflen: Buffer length
 *
 * Returns: Total length, or negative error
 *
 * Note: Packets should be ordered: Initial, 0-RTT, Handshake, 1-RTT
 */
int tquic_coalesce_packets(const u8 **packets, const size_t *lengths,
			   int num_packets, u8 *buf, size_t buflen)
{
	size_t offset = 0;
	int i;

	for (i = 0; i < num_packets; i++) {
		if (offset + lengths[i] > buflen)
			return -ENOSPC;

		memcpy(&buf[offset], packets[i], lengths[i]);
		offset += lengths[i];
	}

	return offset;
}
EXPORT_SYMBOL_GPL(tquic_coalesce_packets);

/*
 * Packet Validation Functions
 */

/**
 * tquic_validate_packet - Validate basic packet structure
 * @data: Packet data
 * @len: Packet length
 *
 * Returns: 0 if valid, negative error otherwise
 */
int tquic_validate_packet(const u8 *data, size_t len)
{
	u8 first_byte;

	if (len < 1)
		return -EINVAL;

	first_byte = data[0];

	/* Check fixed bit (should be 1 for valid QUIC packets) */
	if (!(first_byte & QUIC_FIXED_BIT)) {
		/*
		 * Fixed bit is 0. This could be:
		 * - A stateless reset (valid)
		 * - A corrupted packet (invalid)
		 * We can't tell without more context, so allow it.
		 */
		return 0;
	}

	if (first_byte & QUIC_HEADER_FORM_LONG) {
		/* Long header - minimum size check */
		if (len < 7)
			return -EINVAL;
	} else {
		/* Short header - at least first byte + some DCID + PN */
		if (len < 2)
			return -EINVAL;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_validate_packet);

/**
 * tquic_validate_initial_packet - Validate an Initial packet
 * @data: Packet data
 * @len: Packet length
 * @is_client: true if validating client Initial
 *
 * Returns: 0 if valid, negative error otherwise
 */
int tquic_validate_initial_packet(const u8 *data, size_t len, bool is_client)
{
	struct tquic_packet_header hdr;
	int ret;

	/* Initial packets must be at least 1200 bytes when sent by client */
	if (is_client && len < TQUIC_MIN_INITIAL_PACKET_SIZE)
		return -EINVAL;

	/* Basic validation */
	ret = tquic_validate_packet(data, len);
	if (ret)
		return ret;

	/* Must be a long header */
	if (!tquic_is_long_header(data, len))
		return -EINVAL;

	/* Parse header (with dummy largest_pn) */
	ret = tquic_parse_long_header(data, len, &hdr, 0);
	if (ret < 0)
		return ret;

	/* Must be Initial type */
	if (hdr.type != TQUIC_PKT_INITIAL)
		return -EINVAL;

	/* Version must be valid (not negotiation) */
	if (hdr.version == QUIC_VERSION_NEGOTIATION)
		return -EINVAL;

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_validate_initial_packet);

/**
 * tquic_validate_version - Check if version is supported
 * @version: QUIC version to check
 *
 * Returns: true if supported
 */
bool tquic_validate_version(u32 version)
{
	switch (version) {
	case QUIC_VERSION_1:
	case QUIC_VERSION_2:
		return true;
	default:
		return false;
	}
}
EXPORT_SYMBOL_GPL(tquic_validate_version);

/**
 * tquic_get_version - Extract version from packet
 * @data: Packet data
 * @len: Packet length
 *
 * Returns: Version or 0 if short header/error
 */
u32 tquic_get_version(const u8 *data, size_t len)
{
	if (len < 5)
		return 0;

	if (!tquic_is_long_header(data, len))
		return 0;

	return get_unaligned_be32(&data[1]);
}
EXPORT_SYMBOL_GPL(tquic_get_version);

/*
 * Packet Structure Management
 */

/**
 * tquic_packet_alloc - Allocate a packet structure
 * @gfp: Memory allocation flags
 *
 * Returns: Allocated packet or NULL
 */
struct tquic_packet *tquic_packet_alloc(gfp_t gfp)
{
	struct tquic_packet *pkt;

	pkt = kmem_cache_zalloc(tquic_packet_cache, gfp);
	if (!pkt)
		return NULL;

	INIT_LIST_HEAD(&pkt->list);
	return pkt;
}
EXPORT_SYMBOL_GPL(tquic_packet_alloc);

/**
 * tquic_packet_free - Free a packet structure
 * @pkt: Packet to free
 */
void tquic_packet_free(struct tquic_packet *pkt)
{
	if (!pkt)
		return;

	/* Free raw buffer if allocated separately */
	if (pkt->raw && pkt->raw != pkt->payload)
		kfree(pkt->raw);

	kmem_cache_free(tquic_packet_cache, pkt);
}
EXPORT_SYMBOL_GPL(tquic_packet_free);

/**
 * tquic_packet_clone - Clone a packet structure
 * @pkt: Packet to clone
 * @gfp: Memory allocation flags
 *
 * Returns: Cloned packet or NULL
 */
struct tquic_packet *tquic_packet_clone(const struct tquic_packet *pkt, gfp_t gfp)
{
	struct tquic_packet *clone;

	clone = tquic_packet_alloc(gfp);
	if (!clone)
		return NULL;

	/* Copy header and metadata */
	memcpy(&clone->hdr, &pkt->hdr, sizeof(clone->hdr));
	clone->pn_space = pkt->pn_space;
	clone->ack_eliciting = pkt->ack_eliciting;
	clone->in_flight = pkt->in_flight;
	clone->path = pkt->path;

	/* Clone raw data if present */
	if (pkt->raw && pkt->raw_len > 0) {
		clone->raw = kmalloc(pkt->raw_len, gfp);
		if (!clone->raw) {
			tquic_packet_free(clone);
			return NULL;
		}
		memcpy(clone->raw, pkt->raw, pkt->raw_len);
		clone->raw_len = pkt->raw_len;

		/* Adjust payload pointer */
		if (pkt->payload >= pkt->raw &&
		    pkt->payload < pkt->raw + pkt->raw_len) {
			clone->payload = clone->raw +
					 (pkt->payload - pkt->raw);
			clone->payload_len = pkt->payload_len;
		}
	}

	return clone;
}
EXPORT_SYMBOL_GPL(tquic_packet_clone);

/**
 * tquic_packet_type_str - Get string name for packet type
 * @type: Packet type
 *
 * Returns: String name
 */
const char *tquic_packet_type_str(enum tquic_packet_type type)
{
	static const char * const names[] = {
		[TQUIC_PKT_INITIAL] = "Initial",
		[TQUIC_PKT_0RTT] = "0-RTT",
		[TQUIC_PKT_HANDSHAKE] = "Handshake",
		[TQUIC_PKT_RETRY] = "Retry",
		[TQUIC_PKT_1RTT] = "1-RTT",
		[TQUIC_PKT_VERSION_NEG] = "Version Negotiation",
		[TQUIC_PKT_STATELESS_RESET] = "Stateless Reset",
	};

	if (type < ARRAY_SIZE(names) && names[type])
		return names[type];
	return "Unknown";
}
EXPORT_SYMBOL_GPL(tquic_packet_type_str);

/**
 * tquic_packet_pn_space - Get packet number space for packet type
 * @type: Packet type
 *
 * Returns: Packet number space
 */
int tquic_packet_pn_space(enum tquic_packet_type type)
{
	switch (type) {
	case TQUIC_PKT_INITIAL:
		return TQUIC_PN_SPACE_INITIAL;
	case TQUIC_PKT_HANDSHAKE:
		return TQUIC_PN_SPACE_HANDSHAKE;
	case TQUIC_PKT_0RTT:
	case TQUIC_PKT_1RTT:
		return TQUIC_PN_SPACE_APPLICATION;
	default:
		return -EINVAL;
	}
}
EXPORT_SYMBOL_GPL(tquic_packet_pn_space);

/*
 * SKB Interface Functions
 */

/**
 * tquic_packet_from_skb - Parse packet from sk_buff
 * @skb: Socket buffer containing packet
 * @conn: Connection (for DCID length in short headers)
 * @largest_pn: Largest packet number for decoding
 * @gfp: Memory allocation flags
 *
 * Returns: Parsed packet or ERR_PTR on error
 */
struct tquic_packet *tquic_packet_from_skb(struct sk_buff *skb,
					   struct tquic_connection *conn,
					   u64 largest_pn, gfp_t gfp)
{
	struct tquic_packet *pkt;
	u8 dcid_len;
	int ret;

	if (!skb || !skb->len)
		return ERR_PTR(-EINVAL);

	pkt = tquic_packet_alloc(gfp);
	if (!pkt)
		return ERR_PTR(-ENOMEM);

	pkt->raw = skb->data;
	pkt->raw_len = skb->len;

	if (tquic_is_long_header(skb->data, skb->len)) {
		ret = tquic_parse_long_header(skb->data, skb->len,
					      &pkt->hdr, largest_pn);
	} else {
		/* For short headers, we need the expected DCID length */
		dcid_len = conn ? conn->scid.len : TQUIC_DEFAULT_CID_LEN;
		ret = tquic_parse_short_header(skb->data, skb->len,
					       &pkt->hdr, dcid_len, largest_pn);
	}

	if (ret < 0) {
		tquic_packet_free(pkt);
		return ERR_PTR(ret);
	}

	pkt->payload = pkt->raw + pkt->hdr.header_len;
	pkt->payload_len = pkt->hdr.payload_len;
	pkt->pn_space = tquic_packet_pn_space(pkt->hdr.type);

	return pkt;
}
EXPORT_SYMBOL_GPL(tquic_packet_from_skb);

/**
 * tquic_packet_to_skb - Convert packet to sk_buff for transmission
 * @pkt: Packet to convert
 * @gfp: Memory allocation flags
 *
 * Returns: Allocated sk_buff or NULL
 */
struct sk_buff *tquic_packet_to_skb(struct tquic_packet *pkt, gfp_t gfp)
{
	struct sk_buff *skb;

	if (!pkt || !pkt->raw || !pkt->raw_len)
		return NULL;

	skb = alloc_skb(pkt->raw_len + NET_SKB_PAD, gfp);
	if (!skb)
		return NULL;

	skb_reserve(skb, NET_SKB_PAD);
	skb_put_data(skb, pkt->raw, pkt->raw_len);

	return skb;
}
EXPORT_SYMBOL_GPL(tquic_packet_to_skb);

/*
 * Module Initialization
 */

/**
 * tquic_packet_init - Initialize packet subsystem
 *
 * Returns: 0 on success, negative error otherwise
 */
int __init tquic_packet_init(void)
{
	tquic_packet_cache = kmem_cache_create("tquic_packet",
					       sizeof(struct tquic_packet),
					       0, SLAB_HWCACHE_ALIGN, NULL);
	if (!tquic_packet_cache)
		return -ENOMEM;

	pr_info("tquic: packet subsystem initialized\n");
	return 0;
}

/**
 * tquic_packet_exit - Cleanup packet subsystem
 */
void __exit tquic_packet_exit(void)
{
	kmem_cache_destroy(tquic_packet_cache);
	pr_info("tquic: packet subsystem cleaned up\n");
}

MODULE_DESCRIPTION("TQUIC Packet Parsing and Construction");
MODULE_LICENSE("GPL");
