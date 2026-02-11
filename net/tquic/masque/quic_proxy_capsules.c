// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC MASQUE: QUIC-Aware Proxy Capsule Encoding/Decoding
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Implements encoding and decoding for QUIC-Aware Proxy capsules as
 * defined in draft-ietf-masque-quic-proxy.
 *
 * Capsule Types:
 *   QUIC_PROXY_REGISTER:   Register proxied QUIC connection
 *   QUIC_PROXY_CID:        Connection ID update
 *   QUIC_PROXY_PACKET:     Encapsulated QUIC packet
 *   QUIC_PROXY_DEREGISTER: Deregister proxied connection
 *   QUIC_PROXY_ERROR:      Error indication
 *
 * Wire Format:
 *   All capsules follow RFC 9297 Capsule Protocol format:
 *   Capsule Type (varint) || Capsule Length (varint) || Capsule Value
 *
 * References:
 *   draft-ietf-masque-quic-proxy - QUIC-Aware Proxying Using HTTP
 *   RFC 9297 - HTTP Datagrams and the Capsule Protocol
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <net/tquic.h>

#include "quic_proxy.h"
#include "capsule.h"

/*
 * =============================================================================
 * Varint Helpers (QUIC Variable-Length Integer Encoding)
 * =============================================================================
 */

/**
 * varint_encode - Encode value as QUIC varint
 * @buf: Output buffer
 * @len: Buffer length
 * @value: Value to encode
 *
 * Returns: Bytes written or negative error.
 */
static int varint_encode(u8 *buf, size_t len, u64 value)
{
	return capsule_varint_encode(value, buf, len);
}

/**
 * varint_decode - Decode QUIC varint from buffer
 * @buf: Input buffer
 * @len: Buffer length
 * @value: Output value
 *
 * Returns: Bytes consumed or negative error.
 */
static int varint_decode(const u8 *buf, size_t len, u64 *value)
{
	return capsule_varint_decode(buf, len, value);
}

/**
 * varint_size - Get encoded size of varint
 * @value: Value to encode
 *
 * Returns: 1, 2, 4, or 8 bytes.
 */
static inline int varint_size(u64 value)
{
	return capsule_varint_size(value);
}

/*
 * =============================================================================
 * QUIC_PROXY_REGISTER Capsule
 * =============================================================================
 *
 * Wire format:
 *   Capsule Type:   varint (CAPSULE_TYPE_QUIC_PROXY_REGISTER)
 *   Capsule Length: varint
 *   Capsule Value:
 *     Connection ID:     varint
 *     Target Host Len:   1 byte
 *     Target Host:       variable
 *     Target Port:       2 bytes (big-endian)
 *     Initial DCID Len:  1 byte
 *     Initial DCID:      variable
 *     Initial SCID Len:  1 byte
 *     Initial SCID:      variable
 *     Version:           4 bytes (big-endian)
 *     Flags:             1 byte
 */

/**
 * quic_proxy_encode_register - Encode QUIC_PROXY_REGISTER capsule
 * @capsule: Capsule data to encode
 * @buf: Output buffer
 * @buf_len: Buffer length
 *
 * Returns: Bytes written on success, negative errno on failure.
 */
int quic_proxy_encode_register(
	const struct quic_proxy_register_capsule *capsule,
	u8 *buf, size_t buf_len)
{
	size_t offset = 0;
	size_t payload_len;
	int ret;

	if (!capsule || !buf)
		return -EINVAL;

	/* Calculate payload length */
	payload_len = varint_size(capsule->conn_id) +
		      1 + capsule->target_host_len +
		      2 +
		      1 + capsule->initial_dcid_len +
		      1 + capsule->initial_scid_len +
		      4 + 1;

	/* Encode capsule type */
	ret = varint_encode(buf + offset, buf_len - offset,
			    CAPSULE_TYPE_QUIC_PROXY_REGISTER);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Encode capsule length */
	ret = varint_encode(buf + offset, buf_len - offset, payload_len);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Encode connection ID */
	ret = varint_encode(buf + offset, buf_len - offset, capsule->conn_id);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Bounds check for remaining payload */
	if (buf_len - offset < payload_len - varint_size(capsule->conn_id))
		return -ENOBUFS;

	/* Target host length */
	buf[offset++] = capsule->target_host_len;

	/* Target host */
	if (capsule->target_host_len > 0) {
		memcpy(buf + offset, capsule->target_host,
		       capsule->target_host_len);
		offset += capsule->target_host_len;
	}

	/* Target port (big-endian) */
	buf[offset++] = (capsule->target_port >> 8) & 0xFF;
	buf[offset++] = capsule->target_port & 0xFF;

	/* Initial DCID length */
	buf[offset++] = capsule->initial_dcid_len;

	/* Initial DCID */
	if (capsule->initial_dcid_len > 0) {
		memcpy(buf + offset, capsule->initial_dcid,
		       capsule->initial_dcid_len);
		offset += capsule->initial_dcid_len;
	}

	/* Initial SCID length */
	buf[offset++] = capsule->initial_scid_len;

	/* Initial SCID */
	if (capsule->initial_scid_len > 0) {
		memcpy(buf + offset, capsule->initial_scid,
		       capsule->initial_scid_len);
		offset += capsule->initial_scid_len;
	}

	/* Version (big-endian) */
	buf[offset++] = (capsule->version >> 24) & 0xFF;
	buf[offset++] = (capsule->version >> 16) & 0xFF;
	buf[offset++] = (capsule->version >> 8) & 0xFF;
	buf[offset++] = capsule->version & 0xFF;

	/* Flags */
	buf[offset++] = capsule->flags;

	return offset;
}
EXPORT_SYMBOL_GPL(quic_proxy_encode_register);

/**
 * quic_proxy_decode_register - Decode QUIC_PROXY_REGISTER capsule
 * @buf: Input buffer
 * @buf_len: Buffer length
 * @capsule: Output capsule structure
 *
 * Returns: Bytes consumed on success, negative errno on failure.
 */
int quic_proxy_decode_register(
	const u8 *buf, size_t buf_len,
	struct quic_proxy_register_capsule *capsule)
{
	size_t offset = 0;
	u64 capsule_type, capsule_len;
	int ret;

	if (!buf || !capsule)
		return -EINVAL;

	memset(capsule, 0, sizeof(*capsule));

	/* Decode capsule type */
	ret = varint_decode(buf + offset, buf_len - offset, &capsule_type);
	if (ret < 0)
		return ret;
	offset += ret;

	if (capsule_type != CAPSULE_TYPE_QUIC_PROXY_REGISTER)
		return -EINVAL;

	/* Decode capsule length */
	ret = varint_decode(buf + offset, buf_len - offset, &capsule_len);
	if (ret < 0)
		return ret;
	offset += ret;

	if (buf_len - offset < capsule_len)
		return -EAGAIN;

	/* Decode connection ID */
	ret = varint_decode(buf + offset, buf_len - offset, &capsule->conn_id);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Target host length */
	if (buf_len - offset < 1)
		return -EINVAL;
	capsule->target_host_len = buf[offset++];

	if (capsule->target_host_len > sizeof(capsule->target_host) - 1)
		return -EINVAL;

	/* Target host */
	if (buf_len - offset < capsule->target_host_len)
		return -EINVAL;
	if (capsule->target_host_len > 0) {
		memcpy(capsule->target_host, buf + offset,
		       capsule->target_host_len);
		capsule->target_host[capsule->target_host_len] = '\0';
		offset += capsule->target_host_len;
	}

	/* Target port */
	if (buf_len - offset < 2)
		return -EINVAL;
	capsule->target_port = ((u16)buf[offset] << 8) | buf[offset + 1];
	offset += 2;

	/* Initial DCID length */
	if (buf_len - offset < 1)
		return -EINVAL;
	capsule->initial_dcid_len = buf[offset++];

	if (capsule->initial_dcid_len > QUIC_PROXY_MAX_CID_LEN)
		return -EINVAL;

	/* Initial DCID */
	if (buf_len - offset < capsule->initial_dcid_len)
		return -EINVAL;
	if (capsule->initial_dcid_len > 0) {
		memcpy(capsule->initial_dcid, buf + offset,
		       capsule->initial_dcid_len);
		offset += capsule->initial_dcid_len;
	}

	/* Initial SCID length */
	if (buf_len - offset < 1)
		return -EINVAL;
	capsule->initial_scid_len = buf[offset++];

	if (capsule->initial_scid_len > QUIC_PROXY_MAX_CID_LEN)
		return -EINVAL;

	/* Initial SCID */
	if (buf_len - offset < capsule->initial_scid_len)
		return -EINVAL;
	if (capsule->initial_scid_len > 0) {
		memcpy(capsule->initial_scid, buf + offset,
		       capsule->initial_scid_len);
		offset += capsule->initial_scid_len;
	}

	/* Version */
	if (buf_len - offset < 4)
		return -EINVAL;
	capsule->version = ((u32)buf[offset] << 24) |
			   ((u32)buf[offset + 1] << 16) |
			   ((u32)buf[offset + 2] << 8) |
			   buf[offset + 3];
	offset += 4;

	/* Flags */
	if (buf_len - offset < 1)
		return -EINVAL;
	capsule->flags = buf[offset++];

	return offset;
}
EXPORT_SYMBOL_GPL(quic_proxy_decode_register);

/*
 * =============================================================================
 * QUIC_PROXY_CID Capsule
 * =============================================================================
 *
 * Wire format:
 *   Capsule Type:      varint (CAPSULE_TYPE_QUIC_PROXY_CID)
 *   Capsule Length:    varint
 *   Capsule Value:
 *     Connection ID:   varint
 *     Direction:       1 byte
 *     Action:          1 byte
 *     Sequence Number: varint
 *     Retire Prior To: varint
 *     CID Length:      1 byte
 *     CID:             variable
 *     [Reset Token:    16 bytes, if present]
 */

/**
 * quic_proxy_encode_cid - Encode QUIC_PROXY_CID capsule
 * @capsule: Capsule data to encode
 * @buf: Output buffer
 * @buf_len: Buffer length
 *
 * Returns: Bytes written on success, negative errno on failure.
 */
int quic_proxy_encode_cid(
	const struct quic_proxy_cid_capsule *capsule,
	u8 *buf, size_t buf_len)
{
	size_t offset = 0;
	size_t payload_len;
	int ret;

	if (!capsule || !buf)
		return -EINVAL;

	/* Calculate payload length */
	payload_len = varint_size(capsule->conn_id) +
		      1 + 1 +
		      varint_size(capsule->seq_num) +
		      varint_size(capsule->retire_prior_to) +
		      1 + capsule->cid_len +
		      (capsule->has_reset_token ? 16 : 0);

	/* Encode capsule type */
	ret = varint_encode(buf + offset, buf_len - offset,
			    CAPSULE_TYPE_QUIC_PROXY_CID);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Encode capsule length */
	ret = varint_encode(buf + offset, buf_len - offset, payload_len);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Encode connection ID */
	ret = varint_encode(buf + offset, buf_len - offset, capsule->conn_id);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Check remaining buffer */
	if (buf_len - offset < 2 + varint_size(capsule->seq_num) +
	    varint_size(capsule->retire_prior_to) + 1 + capsule->cid_len +
	    (capsule->has_reset_token ? 16 : 0))
		return -ENOBUFS;

	/* Direction */
	buf[offset++] = capsule->direction;

	/* Action */
	buf[offset++] = capsule->action;

	/* Sequence number */
	ret = varint_encode(buf + offset, buf_len - offset, capsule->seq_num);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Retire prior to */
	ret = varint_encode(buf + offset, buf_len - offset,
			    capsule->retire_prior_to);
	if (ret < 0)
		return ret;
	offset += ret;

	/* CID length */
	buf[offset++] = capsule->cid_len;

	/* CID */
	if (capsule->cid_len > 0) {
		memcpy(buf + offset, capsule->cid, capsule->cid_len);
		offset += capsule->cid_len;
	}

	/* Reset token (if present) */
	if (capsule->has_reset_token) {
		memcpy(buf + offset, capsule->reset_token, 16);
		offset += 16;
	}

	return offset;
}
EXPORT_SYMBOL_GPL(quic_proxy_encode_cid);

/**
 * quic_proxy_decode_cid - Decode QUIC_PROXY_CID capsule
 * @buf: Input buffer
 * @buf_len: Buffer length
 * @capsule: Output capsule structure
 *
 * Returns: Bytes consumed on success, negative errno on failure.
 */
int quic_proxy_decode_cid(
	const u8 *buf, size_t buf_len,
	struct quic_proxy_cid_capsule *capsule)
{
	size_t offset = 0;
	size_t capsule_start;
	u64 capsule_type, capsule_len;
	int ret;

	if (!buf || !capsule)
		return -EINVAL;

	memset(capsule, 0, sizeof(*capsule));

	/* Decode capsule type */
	ret = varint_decode(buf + offset, buf_len - offset, &capsule_type);
	if (ret < 0)
		return ret;
	offset += ret;

	if (capsule_type != CAPSULE_TYPE_QUIC_PROXY_CID)
		return -EINVAL;

	/* Decode capsule length */
	ret = varint_decode(buf + offset, buf_len - offset, &capsule_len);
	if (ret < 0)
		return ret;
	offset += ret;

	capsule_start = offset;

	if (buf_len - offset < capsule_len)
		return -EAGAIN;

	/* Decode connection ID */
	ret = varint_decode(buf + offset, buf_len - offset, &capsule->conn_id);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Direction */
	if (buf_len - offset < 2)
		return -EINVAL;
	capsule->direction = buf[offset++];
	capsule->action = buf[offset++];

	/* Sequence number */
	ret = varint_decode(buf + offset, buf_len - offset, &capsule->seq_num);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Retire prior to */
	ret = varint_decode(buf + offset, buf_len - offset,
			    &capsule->retire_prior_to);
	if (ret < 0)
		return ret;
	offset += ret;

	/* CID length */
	if (buf_len - offset < 1)
		return -EINVAL;
	capsule->cid_len = buf[offset++];

	if (capsule->cid_len > QUIC_PROXY_MAX_CID_LEN)
		return -EINVAL;

	/* CID */
	if (buf_len - offset < capsule->cid_len)
		return -EINVAL;
	if (capsule->cid_len > 0) {
		memcpy(capsule->cid, buf + offset, capsule->cid_len);
		offset += capsule->cid_len;
	}

	/* Check for reset token */
	if (offset - capsule_start < capsule_len) {
		size_t remaining = capsule_len - (offset - capsule_start);
		if (remaining >= 16) {
			memcpy(capsule->reset_token, buf + offset, 16);
			capsule->has_reset_token = true;
			offset += 16;
		}
	}

	return offset;
}
EXPORT_SYMBOL_GPL(quic_proxy_decode_cid);

/*
 * =============================================================================
 * QUIC_PROXY_PACKET Capsule
 * =============================================================================
 *
 * Wire format:
 *   Capsule Type:      varint (CAPSULE_TYPE_QUIC_PROXY_PACKET)
 *   Capsule Length:    varint
 *   Capsule Value:
 *     Connection ID:   varint
 *     Flags:           1 byte
 *       bit 0: direction (0=client->target, 1=target->client)
 *       bit 1: compressed
 *       bits 2-7: reserved
 *     [Compress Index: 1 byte, if compressed]
 *     Packet Length:   2 bytes (big-endian)
 *     Packet:          variable
 */

/**
 * quic_proxy_encode_packet - Encode QUIC_PROXY_PACKET capsule
 * @capsule: Capsule data to encode
 * @buf: Output buffer
 * @buf_len: Buffer length
 *
 * Returns: Bytes written on success, negative errno on failure.
 */
int quic_proxy_encode_packet(
	const struct quic_proxy_packet_capsule *capsule,
	u8 *buf, size_t buf_len)
{
	size_t offset = 0;
	size_t payload_len;
	u8 flags;
	int ret;

	if (!capsule || !buf || !capsule->packet)
		return -EINVAL;

	/* Calculate payload length */
	payload_len = varint_size(capsule->conn_id) +
		      1 +  /* flags */
		      (capsule->compressed ? 1 : 0) +  /* compress index */
		      2 + capsule->packet_len;

	/* Encode capsule type */
	ret = varint_encode(buf + offset, buf_len - offset,
			    CAPSULE_TYPE_QUIC_PROXY_PACKET);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Encode capsule length */
	ret = varint_encode(buf + offset, buf_len - offset, payload_len);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Encode connection ID */
	ret = varint_encode(buf + offset, buf_len - offset, capsule->conn_id);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Check remaining buffer */
	if (buf_len - offset < 1 + (capsule->compressed ? 1 : 0) +
	    2 + capsule->packet_len)
		return -ENOBUFS;

	/* Flags */
	flags = capsule->direction & 0x01;
	if (capsule->compressed)
		flags |= 0x02;
	buf[offset++] = flags;

	/* Compress index (if compressed) */
	if (capsule->compressed)
		buf[offset++] = capsule->compress_index;

	/* Packet length (big-endian) */
	buf[offset++] = (capsule->packet_len >> 8) & 0xFF;
	buf[offset++] = capsule->packet_len & 0xFF;

	/* Packet data */
	memcpy(buf + offset, capsule->packet, capsule->packet_len);
	offset += capsule->packet_len;

	return offset;
}
EXPORT_SYMBOL_GPL(quic_proxy_encode_packet);

/**
 * quic_proxy_decode_packet - Decode QUIC_PROXY_PACKET capsule
 * @buf: Input buffer
 * @buf_len: Buffer length
 * @capsule: Output capsule structure
 *
 * Note: capsule->packet points into buf, caller must not modify buf
 *       until done with capsule.
 *
 * Returns: Bytes consumed on success, negative errno on failure.
 */
int quic_proxy_decode_packet(
	const u8 *buf, size_t buf_len,
	struct quic_proxy_packet_capsule *capsule)
{
	size_t offset = 0;
	u64 capsule_type, capsule_len;
	u8 flags;
	int ret;

	if (!buf || !capsule)
		return -EINVAL;

	memset(capsule, 0, sizeof(*capsule));

	/* Decode capsule type */
	ret = varint_decode(buf + offset, buf_len - offset, &capsule_type);
	if (ret < 0)
		return ret;
	offset += ret;

	if (capsule_type != CAPSULE_TYPE_QUIC_PROXY_PACKET)
		return -EINVAL;

	/* Decode capsule length */
	ret = varint_decode(buf + offset, buf_len - offset, &capsule_len);
	if (ret < 0)
		return ret;
	offset += ret;

	if (buf_len - offset < capsule_len)
		return -EAGAIN;

	/* Decode connection ID */
	ret = varint_decode(buf + offset, buf_len - offset, &capsule->conn_id);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Flags */
	if (buf_len - offset < 1)
		return -EINVAL;
	flags = buf[offset++];
	capsule->direction = flags & 0x01;
	capsule->compressed = (flags & 0x02) != 0;

	/* Compress index (if compressed) */
	if (capsule->compressed) {
		if (buf_len - offset < 1)
			return -EINVAL;
		capsule->compress_index = buf[offset++];
	}

	/* Packet length */
	if (buf_len - offset < 2)
		return -EINVAL;
	capsule->packet_len = ((u16)buf[offset] << 8) | buf[offset + 1];
	offset += 2;

	/* Packet data */
	if (buf_len - offset < capsule->packet_len)
		return -EINVAL;
	capsule->packet = buf + offset;
	offset += capsule->packet_len;

	return offset;
}
EXPORT_SYMBOL_GPL(quic_proxy_decode_packet);

/*
 * =============================================================================
 * QUIC_PROXY_DEREGISTER Capsule
 * =============================================================================
 *
 * Wire format:
 *   Capsule Type:       varint (CAPSULE_TYPE_QUIC_PROXY_DEREGISTER)
 *   Capsule Length:     varint
 *   Capsule Value:
 *     Connection ID:    varint
 *     Reason:           1 byte
 *     Drain Timeout:    4 bytes (big-endian, milliseconds)
 */

/**
 * quic_proxy_encode_deregister - Encode QUIC_PROXY_DEREGISTER capsule
 * @capsule: Capsule data to encode
 * @buf: Output buffer
 * @buf_len: Buffer length
 *
 * Returns: Bytes written on success, negative errno on failure.
 */
int quic_proxy_encode_deregister(
	const struct quic_proxy_deregister_capsule *capsule,
	u8 *buf, size_t buf_len)
{
	size_t offset = 0;
	size_t payload_len;
	int ret;

	if (!capsule || !buf)
		return -EINVAL;

	/* Calculate payload length */
	payload_len = varint_size(capsule->conn_id) + 1 + 4;

	/* Encode capsule type */
	ret = varint_encode(buf + offset, buf_len - offset,
			    CAPSULE_TYPE_QUIC_PROXY_DEREGISTER);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Encode capsule length */
	ret = varint_encode(buf + offset, buf_len - offset, payload_len);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Encode connection ID */
	ret = varint_encode(buf + offset, buf_len - offset, capsule->conn_id);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Check remaining buffer */
	if (buf_len - offset < 5)
		return -ENOBUFS;

	/* Reason */
	buf[offset++] = capsule->reason;

	/* Drain timeout (big-endian) */
	buf[offset++] = (capsule->drain_timeout_ms >> 24) & 0xFF;
	buf[offset++] = (capsule->drain_timeout_ms >> 16) & 0xFF;
	buf[offset++] = (capsule->drain_timeout_ms >> 8) & 0xFF;
	buf[offset++] = capsule->drain_timeout_ms & 0xFF;

	return offset;
}
EXPORT_SYMBOL_GPL(quic_proxy_encode_deregister);

/**
 * quic_proxy_decode_deregister - Decode QUIC_PROXY_DEREGISTER capsule
 * @buf: Input buffer
 * @buf_len: Buffer length
 * @capsule: Output capsule structure
 *
 * Returns: Bytes consumed on success, negative errno on failure.
 */
int quic_proxy_decode_deregister(
	const u8 *buf, size_t buf_len,
	struct quic_proxy_deregister_capsule *capsule)
{
	size_t offset = 0;
	u64 capsule_type, capsule_len;
	int ret;

	if (!buf || !capsule)
		return -EINVAL;

	memset(capsule, 0, sizeof(*capsule));

	/* Decode capsule type */
	ret = varint_decode(buf + offset, buf_len - offset, &capsule_type);
	if (ret < 0)
		return ret;
	offset += ret;

	if (capsule_type != CAPSULE_TYPE_QUIC_PROXY_DEREGISTER)
		return -EINVAL;

	/* Decode capsule length */
	ret = varint_decode(buf + offset, buf_len - offset, &capsule_len);
	if (ret < 0)
		return ret;
	offset += ret;

	if (buf_len - offset < capsule_len)
		return -EAGAIN;

	/* Decode connection ID */
	ret = varint_decode(buf + offset, buf_len - offset, &capsule->conn_id);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Reason */
	if (buf_len - offset < 5)
		return -EINVAL;
	capsule->reason = buf[offset++];

	/* Drain timeout (big-endian) */
	capsule->drain_timeout_ms = ((u32)buf[offset] << 24) |
				    ((u32)buf[offset + 1] << 16) |
				    ((u32)buf[offset + 2] << 8) |
				    buf[offset + 3];
	offset += 4;

	return offset;
}
EXPORT_SYMBOL_GPL(quic_proxy_decode_deregister);

/*
 * =============================================================================
 * QUIC_PROXY_ERROR Capsule
 * =============================================================================
 *
 * Wire format:
 *   Capsule Type:       varint (CAPSULE_TYPE_QUIC_PROXY_ERROR)
 *   Capsule Length:     varint
 *   Capsule Value:
 *     Connection ID:    varint (0 for proxy-wide error)
 *     Error Code:       varint
 *     Error Msg Len:    2 bytes (big-endian)
 *     Error Message:    variable (UTF-8)
 */

/**
 * quic_proxy_encode_error - Encode QUIC_PROXY_ERROR capsule
 * @capsule: Capsule data to encode
 * @buf: Output buffer
 * @buf_len: Buffer length
 *
 * Returns: Bytes written on success, negative errno on failure.
 */
int quic_proxy_encode_error(
	const struct quic_proxy_error_capsule *capsule,
	u8 *buf, size_t buf_len)
{
	size_t offset = 0;
	size_t payload_len;
	int ret;

	if (!capsule || !buf)
		return -EINVAL;

	/* Calculate payload length */
	payload_len = varint_size(capsule->conn_id) +
		      varint_size(capsule->error_code) +
		      2 + capsule->error_len;

	/* Encode capsule type */
	ret = varint_encode(buf + offset, buf_len - offset,
			    CAPSULE_TYPE_QUIC_PROXY_ERROR);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Encode capsule length */
	ret = varint_encode(buf + offset, buf_len - offset, payload_len);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Encode connection ID */
	ret = varint_encode(buf + offset, buf_len - offset, capsule->conn_id);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Encode error code */
	ret = varint_encode(buf + offset, buf_len - offset, capsule->error_code);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Check remaining buffer */
	if (buf_len - offset < 2 + capsule->error_len)
		return -ENOBUFS;

	/* Error message length (big-endian) */
	buf[offset++] = (capsule->error_len >> 8) & 0xFF;
	buf[offset++] = capsule->error_len & 0xFF;

	/* Error message */
	if (capsule->error_len > 0) {
		memcpy(buf + offset, capsule->error_msg, capsule->error_len);
		offset += capsule->error_len;
	}

	return offset;
}
EXPORT_SYMBOL_GPL(quic_proxy_encode_error);

/**
 * quic_proxy_decode_error - Decode QUIC_PROXY_ERROR capsule
 * @buf: Input buffer
 * @buf_len: Buffer length
 * @capsule: Output capsule structure
 *
 * Returns: Bytes consumed on success, negative errno on failure.
 */
int quic_proxy_decode_error(
	const u8 *buf, size_t buf_len,
	struct quic_proxy_error_capsule *capsule)
{
	size_t offset = 0;
	u64 capsule_type, capsule_len;
	int ret;

	if (!buf || !capsule)
		return -EINVAL;

	memset(capsule, 0, sizeof(*capsule));

	/* Decode capsule type */
	ret = varint_decode(buf + offset, buf_len - offset, &capsule_type);
	if (ret < 0)
		return ret;
	offset += ret;

	if (capsule_type != CAPSULE_TYPE_QUIC_PROXY_ERROR)
		return -EINVAL;

	/* Decode capsule length */
	ret = varint_decode(buf + offset, buf_len - offset, &capsule_len);
	if (ret < 0)
		return ret;
	offset += ret;

	if (buf_len - offset < capsule_len)
		return -EAGAIN;

	/* Decode connection ID */
	ret = varint_decode(buf + offset, buf_len - offset, &capsule->conn_id);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Decode error code */
	ret = varint_decode(buf + offset, buf_len - offset, &capsule->error_code);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Error message length */
	if (buf_len - offset < 2)
		return -EINVAL;
	capsule->error_len = ((u16)buf[offset] << 8) | buf[offset + 1];
	offset += 2;

	if (capsule->error_len > sizeof(capsule->error_msg) - 1)
		return -EINVAL;

	/* Error message */
	if (buf_len - offset < capsule->error_len)
		return -EINVAL;
	if (capsule->error_len > 0) {
		memcpy(capsule->error_msg, buf + offset, capsule->error_len);
		capsule->error_msg[capsule->error_len] = '\0';
		offset += capsule->error_len;
	}

	return offset;
}
EXPORT_SYMBOL_GPL(quic_proxy_decode_error);

/*
 * =============================================================================
 * Capsule Dispatch
 * =============================================================================
 */

/**
 * quic_proxy_process_capsule - Process a received capsule
 * @proxy: QUIC proxy state
 * @buf: Capsule data
 * @buf_len: Buffer length
 *
 * Decodes and processes a QUIC-Aware Proxy capsule.
 *
 * Returns: Bytes consumed on success, negative errno on failure.
 */
int quic_proxy_process_capsule(
	struct tquic_quic_proxy_state *proxy,
	const u8 *buf, size_t buf_len)
{
	u64 capsule_type;
	int ret;

	if (!proxy || !buf || buf_len == 0)
		return -EINVAL;

	/* Peek at capsule type */
	ret = varint_decode(buf, buf_len, &capsule_type);
	if (ret < 0)
		return ret;

	switch (capsule_type) {
	case CAPSULE_TYPE_QUIC_PROXY_REGISTER: {
		struct quic_proxy_register_capsule reg;
		struct tquic_proxied_quic_conn *pconn;

		ret = quic_proxy_decode_register(buf, buf_len, &reg);
		if (ret < 0)
			return ret;

		/* Register the connection (server side) */
		if (proxy->is_server) {
			pconn = tquic_quic_proxy_register_conn(
				proxy,
				reg.target_host, reg.target_port,
				reg.initial_dcid, reg.initial_dcid_len,
				reg.initial_scid, reg.initial_scid_len,
				reg.version, reg.flags);

			if (IS_ERR(pconn)) {
				/* Send error capsule */
				return PTR_ERR(pconn);
			}

			proxied_conn_put(pconn);
		}

		return ret;
	}

	case CAPSULE_TYPE_QUIC_PROXY_CID: {
		struct quic_proxy_cid_capsule cid_cap;
		struct tquic_proxied_quic_conn *pconn;

		ret = quic_proxy_decode_cid(buf, buf_len, &cid_cap);
		if (ret < 0)
			return ret;

		/* Find connection and process CID update */
		pconn = tquic_quic_proxy_find_conn(proxy, cid_cap.conn_id);
		if (!pconn)
			return -ENOENT;

		ret = tquic_quic_proxy_cid_cooperation(pconn, &cid_cap);
		proxied_conn_put(pconn);

		if (ret < 0)
			return ret;

		return ret;
	}

	case CAPSULE_TYPE_QUIC_PROXY_PACKET: {
		struct quic_proxy_packet_capsule pkt_cap;

		ret = quic_proxy_decode_packet(buf, buf_len, &pkt_cap);
		if (ret < 0)
			return ret;

		/* Forward the packet */
		ret = tquic_quic_proxy_forward_packet_capsule(proxy, &pkt_cap);
		if (ret < 0)
			return ret;

		return ret;
	}

	case CAPSULE_TYPE_QUIC_PROXY_DEREGISTER: {
		struct quic_proxy_deregister_capsule dereg;
		struct tquic_proxied_quic_conn *pconn;

		ret = quic_proxy_decode_deregister(buf, buf_len, &dereg);
		if (ret < 0)
			return ret;

		/* Find and deregister connection */
		pconn = tquic_quic_proxy_find_conn(proxy, dereg.conn_id);
		if (!pconn)
			return ret;  /* Connection already gone, that's ok */

		tquic_quic_proxy_deregister_conn(pconn, dereg.reason,
						 dereg.drain_timeout_ms);
		proxied_conn_put(pconn);

		return ret;
	}

	case CAPSULE_TYPE_QUIC_PROXY_ERROR: {
		struct quic_proxy_error_capsule err;

		ret = quic_proxy_decode_error(buf, buf_len, &err);
		if (ret < 0)
			return ret;

		/* Log the error */
		pr_warn("quic-proxy: error conn=%llu code=%llu: %s\n",
			err.conn_id, err.error_code, err.error_msg);

		/* If conn_id is 0, this is a proxy-wide error */
		if (err.conn_id == 0) {
			proxy->stats.errors[QUIC_PROXY_ERR_INTERNAL]++;
		} else {
			struct tquic_proxied_quic_conn *pconn;

			pconn = tquic_quic_proxy_find_conn(proxy, err.conn_id);
			if (pconn) {
				pconn->state = QUIC_PROXY_CONN_ERROR;
				proxied_conn_put(pconn);
			}
		}

		return ret;
	}

	default:
		/* Unknown capsule type - skip it per RFC 9297 */
		pr_debug("quic-proxy: ignoring unknown capsule type 0x%llx\n",
			 capsule_type);
		return -ENOENT;
	}
}
EXPORT_SYMBOL_GPL(quic_proxy_process_capsule);

/*
 * =============================================================================
 * Capsule Handler Registration
 * =============================================================================
 */

/* Capsule handler for QUIC proxy capsules */
static int quic_proxy_capsule_handler(struct capsule *cap, void *context)
{
	struct tquic_quic_proxy_state *proxy = context;

	if (!proxy || !cap || !cap->value)
		return -EINVAL;

	return quic_proxy_process_capsule(proxy, cap->value, cap->length);
}

/**
 * quic_proxy_register_capsule_handlers - Register capsule handlers
 * @registry: Capsule registry
 * @proxy: QUIC proxy state
 *
 * Returns: 0 on success, negative errno on failure.
 */
int quic_proxy_register_capsule_handlers(
	struct capsule_registry *registry,
	struct tquic_quic_proxy_state *proxy)
{
	int ret;

	ret = capsule_register_handler(registry, CAPSULE_TYPE_QUIC_PROXY_REGISTER,
				       "QUIC_PROXY_REGISTER",
				       quic_proxy_capsule_handler, proxy);
	if (ret < 0 && ret != -EEXIST)
		return ret;

	ret = capsule_register_handler(registry, CAPSULE_TYPE_QUIC_PROXY_CID,
				       "QUIC_PROXY_CID",
				       quic_proxy_capsule_handler, proxy);
	if (ret < 0 && ret != -EEXIST)
		return ret;

	ret = capsule_register_handler(registry, CAPSULE_TYPE_QUIC_PROXY_PACKET,
				       "QUIC_PROXY_PACKET",
				       quic_proxy_capsule_handler, proxy);
	if (ret < 0 && ret != -EEXIST)
		return ret;

	ret = capsule_register_handler(registry, CAPSULE_TYPE_QUIC_PROXY_DEREGISTER,
				       "QUIC_PROXY_DEREGISTER",
				       quic_proxy_capsule_handler, proxy);
	if (ret < 0 && ret != -EEXIST)
		return ret;

	ret = capsule_register_handler(registry, CAPSULE_TYPE_QUIC_PROXY_ERROR,
				       "QUIC_PROXY_ERROR",
				       quic_proxy_capsule_handler, proxy);
	if (ret < 0 && ret != -EEXIST)
		return ret;

	return 0;
}
EXPORT_SYMBOL_GPL(quic_proxy_register_capsule_handlers);

/**
 * quic_proxy_unregister_capsule_handlers - Unregister capsule handlers
 * @registry: Capsule registry
 */
void quic_proxy_unregister_capsule_handlers(struct capsule_registry *registry)
{
	if (!registry)
		return;

	capsule_unregister_handler(registry, CAPSULE_TYPE_QUIC_PROXY_REGISTER);
	capsule_unregister_handler(registry, CAPSULE_TYPE_QUIC_PROXY_CID);
	capsule_unregister_handler(registry, CAPSULE_TYPE_QUIC_PROXY_PACKET);
	capsule_unregister_handler(registry, CAPSULE_TYPE_QUIC_PROXY_DEREGISTER);
	capsule_unregister_handler(registry, CAPSULE_TYPE_QUIC_PROXY_ERROR);
}
EXPORT_SYMBOL_GPL(quic_proxy_unregister_capsule_handlers);

MODULE_DESCRIPTION("TQUIC MASQUE QUIC-Aware Proxy Capsules");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Foundation");
