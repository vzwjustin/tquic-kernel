// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: WAN Bonding over QUIC - Transport Parameters
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Implementation of QUIC transport parameters encoding, decoding,
 * validation, and negotiation as defined in RFC 9000 Section 18.
 *
 * This includes a custom enable_multipath parameter for WAN bonding
 * support as defined in RFC 9369 (QUIC Multipath).
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/random.h>
#include <linux/bug.h>
#include <net/tquic.h>

#include "transport_params.h"
#include "../tquic_stateless_reset.h"

/*
 * Transport Parameter IDs as defined in RFC 9000 Section 18.2
 */
#define TP_ORIGINAL_DESTINATION_CONNECTION_ID	0x00
#define TP_MAX_IDLE_TIMEOUT			0x01
#define TP_STATELESS_RESET_TOKEN		0x02
#define TP_MAX_UDP_PAYLOAD_SIZE			0x03
#define TP_INITIAL_MAX_DATA			0x04
#define TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL	0x05
#define TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE	0x06
#define TP_INITIAL_MAX_STREAM_DATA_UNI		0x07
#define TP_INITIAL_MAX_STREAMS_BIDI		0x08
#define TP_INITIAL_MAX_STREAMS_UNI		0x09
#define TP_ACK_DELAY_EXPONENT			0x0a
#define TP_MAX_ACK_DELAY			0x0b
#define TP_DISABLE_ACTIVE_MIGRATION		0x0c
#define TP_PREFERRED_ADDRESS			0x0d
#define TP_ACTIVE_CONNECTION_ID_LIMIT		0x0e
#define TP_INITIAL_SOURCE_CONNECTION_ID		0x0f
#define TP_RETRY_SOURCE_CONNECTION_ID		0x10

/* Custom parameter for multipath/WAN bonding (RFC 9369) */
#define TP_ENABLE_MULTIPATH			0x0f739bbc1b666d05ULL

/* Multipath initial_max_path_id (draft-ietf-quic-multipath) */
#define TP_INITIAL_MAX_PATH_ID			0x0f739bbc1b666d06ULL

/* Version information (RFC 9368) */
#define TP_VERSION_INFORMATION			0x11

/* DATAGRAM frame support (RFC 9221) */
#define TP_MAX_DATAGRAM_FRAME_SIZE		0x20

/* GREASE (RFC 9287) */
#define TP_GREASE_QUIC_BIT			0x2ab2

/* ACK Frequency (draft-ietf-quic-ack-frequency) */
#define TP_MIN_ACK_DELAY			0xff04de1aULL

/* Stateless reset token length */
#define STATELESS_RESET_TOKEN_LEN	16

/* Preferred address structure sizes */
#define PREFERRED_ADDR_IPV4_LEN		(4 + 2)	/* IP + port */
#define PREFERRED_ADDR_IPV6_LEN		(16 + 2)

/* Default values as per RFC 9000 */
#define DEFAULT_MAX_IDLE_TIMEOUT		0	/* Disabled */
#define DEFAULT_MAX_UDP_PAYLOAD_SIZE		65527
#define DEFAULT_ACK_DELAY_EXPONENT		3
#define DEFAULT_MAX_ACK_DELAY			25	/* ms */
#define DEFAULT_ACTIVE_CONNECTION_ID_LIMIT	2

/* Limits */
#define MIN_MAX_UDP_PAYLOAD_SIZE		1200
#define MAX_ACK_DELAY_EXPONENT			20
#define MAX_MAX_ACK_DELAY			(1 << 14)  /* 16384 ms */
#define MAX_VARINT_VALUE			((1ULL << 62) - 1)

/*
 * Variable-length integer encoding/decoding (RFC 9000 Section 16)
 *
 * QUIC uses a variable-length integer encoding:
 * - 1 byte:  6-bit value (0-63), prefix 0b00
 * - 2 bytes: 14-bit value (0-16383), prefix 0b01
 * - 4 bytes: 30-bit value (0-1073741823), prefix 0b10
 * - 8 bytes: 62-bit value (0-4611686018427387903), prefix 0b11
 */

/**
 * tquic_varint_len - Get the encoded length of a variable-length integer
 * @value: The value to encode
 *
 * Return: Number of bytes needed to encode the value, or 0 if value is too large
 */
static size_t tp_varint_len(u64 value)
{
	if (value <= 63)
		return 1;
	if (value <= 16383)
		return 2;
	if (value <= 1073741823)
		return 4;
	if (value <= MAX_VARINT_VALUE)
		return 8;
	return 0;  /* Value too large */
}

/**
 * tquic_varint_encode - Encode a variable-length integer
 * @buf: Buffer to write to
 * @buflen: Available buffer space
 * @value: Value to encode
 *
 * Return: Number of bytes written, or negative error
 */
static ssize_t tp_varint_encode(u8 *buf, size_t buflen, u64 value)
{
	size_t len = tp_varint_len(value);

	if (len == 0)
		return -EOVERFLOW;
	if (buflen < len)
		return -ENOSPC;

	switch (len) {
	case 1:
		buf[0] = (u8)value;
		break;
	case 2:
		buf[0] = (u8)(0x40 | (value >> 8));
		buf[1] = (u8)value;
		break;
	case 4:
		buf[0] = (u8)(0x80 | (value >> 24));
		buf[1] = (u8)(value >> 16);
		buf[2] = (u8)(value >> 8);
		buf[3] = (u8)value;
		break;
	case 8:
		buf[0] = (u8)(0xc0 | (value >> 56));
		buf[1] = (u8)(value >> 48);
		buf[2] = (u8)(value >> 40);
		buf[3] = (u8)(value >> 32);
		buf[4] = (u8)(value >> 24);
		buf[5] = (u8)(value >> 16);
		buf[6] = (u8)(value >> 8);
		buf[7] = (u8)value;
		break;
	}

	return len;
}

/**
 * tquic_varint_decode - Decode a variable-length integer
 * @buf: Buffer to read from
 * @buflen: Available buffer space
 * @value: Output value
 *
 * Return: Number of bytes consumed, or negative error
 */
static ssize_t tp_varint_decode(const u8 *buf, size_t buflen, u64 *value)
{
	u8 prefix;
	size_t len;

	if (buflen < 1)
		return -EINVAL;

	prefix = buf[0] >> 6;
	len = 1 << prefix;

	if (buflen < len)
		return -EINVAL;

	switch (len) {
	case 1:
		*value = buf[0] & 0x3f;
		break;
	case 2:
		*value = ((u64)(buf[0] & 0x3f) << 8) | buf[1];
		break;
	case 4:
		*value = ((u64)(buf[0] & 0x3f) << 24) |
			 ((u64)buf[1] << 16) |
			 ((u64)buf[2] << 8) |
			 buf[3];
		break;
	case 8:
		*value = ((u64)(buf[0] & 0x3f) << 56) |
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

/**
 * tquic_tp_init - Initialize transport parameters with default values
 * @params: Transport parameters structure to initialize
 *
 * Sets all transport parameters to their default values as specified
 * in RFC 9000.
 */
void tquic_tp_init(struct tquic_transport_params *params)
{
	memset(params, 0, sizeof(*params));

	/* Set default values per RFC 9000 Section 18.2 */
	params->max_idle_timeout = DEFAULT_MAX_IDLE_TIMEOUT;
	params->max_udp_payload_size = DEFAULT_MAX_UDP_PAYLOAD_SIZE;
	params->initial_max_data = 0;
	params->initial_max_stream_data_bidi_local = 0;
	params->initial_max_stream_data_bidi_remote = 0;
	params->initial_max_stream_data_uni = 0;
	params->initial_max_streams_bidi = 0;
	params->initial_max_streams_uni = 0;
	params->ack_delay_exponent = DEFAULT_ACK_DELAY_EXPONENT;
	params->max_ack_delay = DEFAULT_MAX_ACK_DELAY;
	params->disable_active_migration = false;
	params->active_connection_id_limit = DEFAULT_ACTIVE_CONNECTION_ID_LIMIT;

	/* Multipath disabled by default */
	params->enable_multipath = false;

	/* DATAGRAM disabled by default (RFC 9221) */
	params->max_datagram_frame_size = 0;

	/* ACK Frequency - min_ack_delay not present by default */
	params->min_ack_delay = 0;
	params->min_ack_delay_present = false;
}
EXPORT_SYMBOL_GPL(tquic_tp_init);

/**
 * tquic_tp_set_defaults_client - Set recommended defaults for a client
 * @params: Transport parameters structure
 *
 * Sets transport parameters to recommended values for a client endpoint.
 */
void tquic_tp_set_defaults_client(struct tquic_transport_params *params)
{
	tquic_tp_init(params);

	params->max_idle_timeout = TQUIC_DEFAULT_IDLE_TIMEOUT;
	params->initial_max_data = TQUIC_DEFAULT_MAX_DATA;
	params->initial_max_stream_data_bidi_local = TQUIC_DEFAULT_MAX_STREAM_DATA;
	params->initial_max_stream_data_bidi_remote = TQUIC_DEFAULT_MAX_STREAM_DATA;
	params->initial_max_stream_data_uni = TQUIC_DEFAULT_MAX_STREAM_DATA;
	params->initial_max_streams_bidi = 100;
	params->initial_max_streams_uni = 100;
	params->active_connection_id_limit = TQUIC_MAX_PATHS;

	/* Enable multipath for WAN bonding by default on client */
	params->enable_multipath = true;

	/* Set initial_max_path_id for multipath (draft-ietf-quic-multipath) */
	params->initial_max_path_id = TQUIC_MAX_PATHS - 1;
	params->initial_max_path_id_present = true;

	/* Enable DATAGRAM support with reasonable default size */
	params->max_datagram_frame_size = 65535;

	/* Enable ACK frequency extension with default min_ack_delay of 25ms */
	params->min_ack_delay = 25000;  /* 25ms in microseconds */
	params->min_ack_delay_present = true;
}
EXPORT_SYMBOL_GPL(tquic_tp_set_defaults_client);

/**
 * tquic_tp_set_defaults_server - Set recommended defaults for a server
 * @params: Transport parameters structure
 *
 * Sets transport parameters to recommended values for a server endpoint.
 */
void tquic_tp_set_defaults_server(struct tquic_transport_params *params)
{
	tquic_tp_init(params);

	params->max_idle_timeout = TQUIC_DEFAULT_IDLE_TIMEOUT;
	params->initial_max_data = TQUIC_DEFAULT_MAX_DATA;
	params->initial_max_stream_data_bidi_local = TQUIC_DEFAULT_MAX_STREAM_DATA;
	params->initial_max_stream_data_bidi_remote = TQUIC_DEFAULT_MAX_STREAM_DATA;
	params->initial_max_stream_data_uni = TQUIC_DEFAULT_MAX_STREAM_DATA;
	params->initial_max_streams_bidi = 100;
	params->initial_max_streams_uni = 100;
	params->active_connection_id_limit = TQUIC_MAX_PATHS;

	/* Enable multipath for WAN bonding by default on server */
	params->enable_multipath = true;

	/* Set initial_max_path_id for multipath (draft-ietf-quic-multipath) */
	params->initial_max_path_id = TQUIC_MAX_PATHS - 1;
	params->initial_max_path_id_present = true;

	/* Enable DATAGRAM support with reasonable default size */
	params->max_datagram_frame_size = 65535;

	/* Enable ACK frequency extension with default min_ack_delay of 25ms */
	params->min_ack_delay = 25000;  /* 25ms in microseconds */
	params->min_ack_delay_present = true;
}
EXPORT_SYMBOL_GPL(tquic_tp_set_defaults_server);

/**
 * encode_connection_id - Encode a connection ID parameter
 * @buf: Output buffer
 * @buflen: Buffer length
 * @param_id: Parameter ID
 * @cid: Connection ID to encode
 *
 * Return: Bytes written or negative error
 */
static ssize_t encode_connection_id(u8 *buf, size_t buflen, u64 param_id,
				    const struct tquic_cid *cid)
{
	ssize_t ret;
	size_t offset = 0;

	/* Parameter ID */
	ret = tp_varint_encode(buf + offset, buflen - offset, param_id);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Length */
	ret = tp_varint_encode(buf + offset, buflen - offset, cid->len);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Value */
	if (buflen - offset < cid->len)
		return -ENOSPC;
	memcpy(buf + offset, cid->id, cid->len);
	offset += cid->len;

	return offset;
}

/**
 * encode_varint_param - Encode a variable-length integer parameter
 * @buf: Output buffer
 * @buflen: Buffer length
 * @param_id: Parameter ID
 * @value: Value to encode
 *
 * Return: Bytes written or negative error
 */
static ssize_t encode_varint_param(u8 *buf, size_t buflen, u64 param_id,
				   u64 value)
{
	ssize_t ret;
	size_t offset = 0;
	size_t value_len = tp_varint_len(value);

	/* Parameter ID */
	ret = tp_varint_encode(buf + offset, buflen - offset, param_id);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Length */
	ret = tp_varint_encode(buf + offset, buflen - offset, value_len);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Value */
	ret = tp_varint_encode(buf + offset, buflen - offset, value);
	if (ret < 0)
		return ret;
	offset += ret;

	return offset;
}

/**
 * encode_zero_length_param - Encode a parameter with no value
 * @buf: Output buffer
 * @buflen: Buffer length
 * @param_id: Parameter ID
 *
 * Return: Bytes written or negative error
 */
static ssize_t encode_zero_length_param(u8 *buf, size_t buflen, u64 param_id)
{
	ssize_t ret;
	size_t offset = 0;

	/* Parameter ID */
	ret = tp_varint_encode(buf + offset, buflen - offset, param_id);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Length (0) */
	ret = tp_varint_encode(buf + offset, buflen - offset, 0);
	if (ret < 0)
		return ret;
	offset += ret;

	return offset;
}

/**
 * encode_stateless_reset_token - Encode the stateless reset token
 * @buf: Output buffer
 * @buflen: Buffer length
 * @token: 16-byte token
 *
 * Return: Bytes written or negative error
 */
static ssize_t encode_stateless_reset_token(u8 *buf, size_t buflen,
					    const u8 *token)
{
	ssize_t ret;
	size_t offset = 0;

	/* Parameter ID */
	ret = tp_varint_encode(buf + offset, buflen - offset,
				  TP_STATELESS_RESET_TOKEN);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Length (always 16) */
	ret = tp_varint_encode(buf + offset, buflen - offset,
				  STATELESS_RESET_TOKEN_LEN);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Value */
	if (buflen - offset < STATELESS_RESET_TOKEN_LEN)
		return -ENOSPC;
	memcpy(buf + offset, token, STATELESS_RESET_TOKEN_LEN);
	offset += STATELESS_RESET_TOKEN_LEN;

	return offset;
}

/**
 * encode_preferred_address - Encode the preferred address parameter
 * @buf: Output buffer
 * @buflen: Buffer length
 * @pref: Preferred address structure
 *
 * Return: Bytes written or negative error
 */
static ssize_t encode_preferred_address(u8 *buf, size_t buflen,
					const struct tquic_preferred_address *pref)
{
	ssize_t ret;
	size_t offset = 0;
	size_t value_len;
	size_t value_offset;

	/* Calculate total length */
	value_len = 4 + 2 +	/* IPv4 address + port */
		    16 + 2 +	/* IPv6 address + port */
		    1 +		/* CID length */
		    pref->cid.len +
		    STATELESS_RESET_TOKEN_LEN;

	/* Parameter ID */
	ret = tp_varint_encode(buf + offset, buflen - offset,
				  TP_PREFERRED_ADDRESS);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Length */
	ret = tp_varint_encode(buf + offset, buflen - offset, value_len);
	if (ret < 0)
		return ret;
	offset += ret;

	if (buflen - offset < value_len)
		return -ENOSPC;

	value_offset = offset;

	/* IPv4 address (4 bytes) */
	memcpy(buf + offset, pref->ipv4_addr, 4);
	offset += 4;

	/* IPv4 port (2 bytes, network byte order) */
	buf[offset++] = (u8)(pref->ipv4_port >> 8);
	buf[offset++] = (u8)pref->ipv4_port;

	/* IPv6 address (16 bytes) */
	memcpy(buf + offset, pref->ipv6_addr, 16);
	offset += 16;

	/* IPv6 port (2 bytes, network byte order) */
	buf[offset++] = (u8)(pref->ipv6_port >> 8);
	buf[offset++] = (u8)pref->ipv6_port;

	/* Connection ID length (1 byte) */
	buf[offset++] = pref->cid.len;

	/* Connection ID */
	memcpy(buf + offset, pref->cid.id, pref->cid.len);
	offset += pref->cid.len;

	/* Stateless reset token (16 bytes) */
	memcpy(buf + offset, pref->stateless_reset_token, STATELESS_RESET_TOKEN_LEN);
	offset += STATELESS_RESET_TOKEN_LEN;

	return offset;
}

/**
 * tquic_tp_encode - Encode transport parameters
 * @params: Transport parameters to encode
 * @is_server: True if encoding for server, false for client
 * @buf: Output buffer
 * @buflen: Buffer length
 *
 * Encodes transport parameters into the wire format as specified in
 * RFC 9000 Section 18.
 *
 * Return: Number of bytes written, or negative error code
 */
ssize_t tquic_tp_encode(const struct tquic_transport_params *params,
			bool is_server, u8 *buf, size_t buflen)
{
	ssize_t ret;
	size_t offset = 0;

	/* original_destination_connection_id (server only) */
	if (is_server && params->original_dcid_present) {
		ret = encode_connection_id(buf + offset, buflen - offset,
					   TP_ORIGINAL_DESTINATION_CONNECTION_ID,
					   &params->original_dcid);
		if (ret < 0)
			return ret;
		offset += ret;
	}

	/* max_idle_timeout */
	if (params->max_idle_timeout > 0) {
		ret = encode_varint_param(buf + offset, buflen - offset,
					  TP_MAX_IDLE_TIMEOUT,
					  params->max_idle_timeout);
		if (ret < 0)
			return ret;
		offset += ret;
	}

	/* stateless_reset_token (server only) */
	if (is_server && params->stateless_reset_token_present) {
		ret = encode_stateless_reset_token(buf + offset, buflen - offset,
						   params->stateless_reset_token);
		if (ret < 0)
			return ret;
		offset += ret;
	}

	/* max_udp_payload_size */
	if (params->max_udp_payload_size != DEFAULT_MAX_UDP_PAYLOAD_SIZE) {
		ret = encode_varint_param(buf + offset, buflen - offset,
					  TP_MAX_UDP_PAYLOAD_SIZE,
					  params->max_udp_payload_size);
		if (ret < 0)
			return ret;
		offset += ret;
	}

	/* initial_max_data */
	if (params->initial_max_data > 0) {
		ret = encode_varint_param(buf + offset, buflen - offset,
					  TP_INITIAL_MAX_DATA,
					  params->initial_max_data);
		if (ret < 0)
			return ret;
		offset += ret;
	}

	/* initial_max_stream_data_bidi_local */
	if (params->initial_max_stream_data_bidi_local > 0) {
		ret = encode_varint_param(buf + offset, buflen - offset,
					  TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
					  params->initial_max_stream_data_bidi_local);
		if (ret < 0)
			return ret;
		offset += ret;
	}

	/* initial_max_stream_data_bidi_remote */
	if (params->initial_max_stream_data_bidi_remote > 0) {
		ret = encode_varint_param(buf + offset, buflen - offset,
					  TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
					  params->initial_max_stream_data_bidi_remote);
		if (ret < 0)
			return ret;
		offset += ret;
	}

	/* initial_max_stream_data_uni */
	if (params->initial_max_stream_data_uni > 0) {
		ret = encode_varint_param(buf + offset, buflen - offset,
					  TP_INITIAL_MAX_STREAM_DATA_UNI,
					  params->initial_max_stream_data_uni);
		if (ret < 0)
			return ret;
		offset += ret;
	}

	/* initial_max_streams_bidi */
	if (params->initial_max_streams_bidi > 0) {
		ret = encode_varint_param(buf + offset, buflen - offset,
					  TP_INITIAL_MAX_STREAMS_BIDI,
					  params->initial_max_streams_bidi);
		if (ret < 0)
			return ret;
		offset += ret;
	}

	/* initial_max_streams_uni */
	if (params->initial_max_streams_uni > 0) {
		ret = encode_varint_param(buf + offset, buflen - offset,
					  TP_INITIAL_MAX_STREAMS_UNI,
					  params->initial_max_streams_uni);
		if (ret < 0)
			return ret;
		offset += ret;
	}

	/* ack_delay_exponent (only if not default) */
	if (params->ack_delay_exponent != DEFAULT_ACK_DELAY_EXPONENT) {
		ret = encode_varint_param(buf + offset, buflen - offset,
					  TP_ACK_DELAY_EXPONENT,
					  params->ack_delay_exponent);
		if (ret < 0)
			return ret;
		offset += ret;
	}

	/* max_ack_delay (only if not default) */
	if (params->max_ack_delay != DEFAULT_MAX_ACK_DELAY) {
		ret = encode_varint_param(buf + offset, buflen - offset,
					  TP_MAX_ACK_DELAY,
					  params->max_ack_delay);
		if (ret < 0)
			return ret;
		offset += ret;
	}

	/* disable_active_migration */
	if (params->disable_active_migration) {
		ret = encode_zero_length_param(buf + offset, buflen - offset,
					       TP_DISABLE_ACTIVE_MIGRATION);
		if (ret < 0)
			return ret;
		offset += ret;
	}

	/* preferred_address (server only) */
	if (is_server && params->preferred_address_present) {
		ret = encode_preferred_address(buf + offset, buflen - offset,
					       &params->preferred_address);
		if (ret < 0)
			return ret;
		offset += ret;
	}

	/* active_connection_id_limit (only if not default) */
	if (params->active_connection_id_limit != DEFAULT_ACTIVE_CONNECTION_ID_LIMIT) {
		ret = encode_varint_param(buf + offset, buflen - offset,
					  TP_ACTIVE_CONNECTION_ID_LIMIT,
					  params->active_connection_id_limit);
		if (ret < 0)
			return ret;
		offset += ret;
	}

	/* initial_source_connection_id */
	if (params->initial_scid_present) {
		ret = encode_connection_id(buf + offset, buflen - offset,
					   TP_INITIAL_SOURCE_CONNECTION_ID,
					   &params->initial_scid);
		if (ret < 0)
			return ret;
		offset += ret;
	}

	/* retry_source_connection_id (server only, after Retry) */
	if (is_server && params->retry_scid_present) {
		ret = encode_connection_id(buf + offset, buflen - offset,
					   TP_RETRY_SOURCE_CONNECTION_ID,
					   &params->retry_scid);
		if (ret < 0)
			return ret;
		offset += ret;
	}

	/* enable_multipath (custom for WAN bonding) */
	if (params->enable_multipath) {
		ret = encode_varint_param(buf + offset, buflen - offset,
					  TP_ENABLE_MULTIPATH,
					  params->enable_multipath ? 1 : 0);
		if (ret < 0)
			return ret;
		offset += ret;
	}

	/* max_datagram_frame_size (RFC 9221) */
	if (params->max_datagram_frame_size > 0) {
		ret = encode_varint_param(buf + offset, buflen - offset,
					  TP_MAX_DATAGRAM_FRAME_SIZE,
					  params->max_datagram_frame_size);
		if (ret < 0)
			return ret;
		offset += ret;
	}

	/* grease_quic_bit (RFC 9287) - zero-length parameter */
	if (params->grease_quic_bit) {
		ret = encode_zero_length_param(buf + offset, buflen - offset,
					       TP_GREASE_QUIC_BIT);
		if (ret < 0)
			return ret;
		offset += ret;
	}

	/* min_ack_delay (draft-ietf-quic-ack-frequency) */
	if (params->min_ack_delay_present) {
		ret = encode_varint_param(buf + offset, buflen - offset,
					  TP_MIN_ACK_DELAY,
					  params->min_ack_delay);
		if (ret < 0)
			return ret;
		offset += ret;
	}

	/* initial_max_path_id (draft-ietf-quic-multipath) */
	if (params->initial_max_path_id_present) {
		ret = encode_varint_param(buf + offset, buflen - offset,
					  TP_INITIAL_MAX_PATH_ID,
					  params->initial_max_path_id);
		if (ret < 0)
			return ret;
		offset += ret;
	}

	/* version_information (RFC 9368) */
	if (params->version_info_present && params->version_info) {
		ssize_t vi_ret;
		size_t value_len;

		/* Calculate value length: chosen (4) + available (4 * count) */
		value_len = 4 + (4 * params->version_info->num_versions);

		/* Parameter ID */
		ret = tp_varint_encode(buf + offset, buflen - offset,
				       TP_VERSION_INFORMATION);
		if (ret < 0)
			return ret;
		offset += ret;

		/* Length */
		ret = tp_varint_encode(buf + offset, buflen - offset, value_len);
		if (ret < 0)
			return ret;
		offset += ret;

		/* Value: chosen version + available versions */
		vi_ret = tquic_encode_version_info(buf + offset, buflen - offset,
						   params->version_info->chosen_version,
						   params->version_info->available_versions,
						   params->version_info->num_versions);
		if (vi_ret < 0)
			return vi_ret;
		offset += vi_ret;
	}

	return offset;
}
EXPORT_SYMBOL_GPL(tquic_tp_encode);

/**
 * decode_connection_id - Decode a connection ID from parameter value
 * @buf: Input buffer (parameter value only)
 * @len: Length of parameter value
 * @cid: Output connection ID
 *
 * Return: 0 on success, negative error code on failure
 */
static int decode_connection_id(const u8 *buf, size_t len, struct tquic_cid *cid)
{
	if (len > TQUIC_MAX_CID_LEN)
		return -EINVAL;

	cid->len = len;
	memcpy(cid->id, buf, len);
	return 0;
}

/**
 * decode_preferred_address - Decode the preferred address parameter
 * @buf: Input buffer (parameter value only)
 * @len: Length of parameter value
 * @pref: Output preferred address structure
 *
 * Return: 0 on success, negative error code on failure
 */
static int decode_preferred_address(const u8 *buf, size_t len,
				    struct tquic_preferred_address *pref)
{
	size_t offset = 0;
	u8 cid_len;
	size_t min_len;

	/* Minimum length: IPv4(6) + IPv6(18) + CID len(1) + token(16) = 41 */
	min_len = 4 + 2 + 16 + 2 + 1 + STATELESS_RESET_TOKEN_LEN;
	if (len < min_len)
		return -EINVAL;

	/* IPv4 address */
	memcpy(pref->ipv4_addr, buf + offset, 4);
	offset += 4;

	/* IPv4 port */
	pref->ipv4_port = ((u16)buf[offset] << 8) | buf[offset + 1];
	offset += 2;

	/* IPv6 address */
	memcpy(pref->ipv6_addr, buf + offset, 16);
	offset += 16;

	/* IPv6 port */
	pref->ipv6_port = ((u16)buf[offset] << 8) | buf[offset + 1];
	offset += 2;

	/* Connection ID length */
	cid_len = buf[offset++];
	if (cid_len > TQUIC_MAX_CID_LEN)
		return -EINVAL;

	/* Check remaining length */
	if (len - offset < cid_len + STATELESS_RESET_TOKEN_LEN)
		return -EINVAL;

	/* Connection ID */
	pref->cid.len = cid_len;
	memcpy(pref->cid.id, buf + offset, cid_len);
	offset += cid_len;

	/* Stateless reset token */
	memcpy(pref->stateless_reset_token, buf + offset, STATELESS_RESET_TOKEN_LEN);

	return 0;
}

/**
 * tquic_tp_decode - Decode transport parameters
 * @buf: Input buffer containing encoded parameters
 * @buflen: Buffer length
 * @is_server: True if decoding parameters from server
 * @params: Output transport parameters structure
 *
 * Decodes transport parameters from the wire format. After decoding,
 * call tquic_tp_validate() to validate the parameters.
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_tp_decode(const u8 *buf, size_t buflen, bool is_server,
		    struct tquic_transport_params *params)
{
	size_t offset = 0;
	ssize_t ret;
	u64 param_id;
	u64 param_len;
	u64 value;

	/* Initialize with defaults */
	tquic_tp_init(params);

	while (offset < buflen) {
		/* Decode parameter ID */
		ret = tp_varint_decode(buf + offset, buflen - offset, &param_id);
		if (ret < 0)
			return ret;
		offset += ret;

		/* Decode parameter length */
		ret = tp_varint_decode(buf + offset, buflen - offset, &param_len);
		if (ret < 0)
			return ret;
		offset += ret;

		/* Check we have enough data */
		if (buflen - offset < param_len)
			return -EINVAL;

		/* Process parameter based on ID */
		switch (param_id) {
		case TP_ORIGINAL_DESTINATION_CONNECTION_ID:
			if (!is_server)
				return -EPROTO;  /* Client must not send this */
			ret = decode_connection_id(buf + offset, param_len,
						   &params->original_dcid);
			if (ret < 0)
				return ret;
			params->original_dcid_present = true;
			break;

		case TP_MAX_IDLE_TIMEOUT:
			ret = tp_varint_decode(buf + offset, param_len, &value);
			if (ret < 0 || (size_t)ret != param_len)
				return -EINVAL;
			params->max_idle_timeout = value;
			break;

		case TP_STATELESS_RESET_TOKEN:
			if (!is_server)
				return -EPROTO;  /* Client must not send this */
			if (param_len != STATELESS_RESET_TOKEN_LEN)
				return -EINVAL;
			memcpy(params->stateless_reset_token, buf + offset,
			       STATELESS_RESET_TOKEN_LEN);
			params->stateless_reset_token_present = true;
			break;

		case TP_MAX_UDP_PAYLOAD_SIZE:
			ret = tp_varint_decode(buf + offset, param_len, &value);
			if (ret < 0 || (size_t)ret != param_len)
				return -EINVAL;
			params->max_udp_payload_size = value;
			break;

		case TP_INITIAL_MAX_DATA:
			ret = tp_varint_decode(buf + offset, param_len, &value);
			if (ret < 0 || (size_t)ret != param_len)
				return -EINVAL;
			params->initial_max_data = value;
			break;

		case TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL:
			ret = tp_varint_decode(buf + offset, param_len, &value);
			if (ret < 0 || (size_t)ret != param_len)
				return -EINVAL;
			params->initial_max_stream_data_bidi_local = value;
			break;

		case TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE:
			ret = tp_varint_decode(buf + offset, param_len, &value);
			if (ret < 0 || (size_t)ret != param_len)
				return -EINVAL;
			params->initial_max_stream_data_bidi_remote = value;
			break;

		case TP_INITIAL_MAX_STREAM_DATA_UNI:
			ret = tp_varint_decode(buf + offset, param_len, &value);
			if (ret < 0 || (size_t)ret != param_len)
				return -EINVAL;
			params->initial_max_stream_data_uni = value;
			break;

		case TP_INITIAL_MAX_STREAMS_BIDI:
			ret = tp_varint_decode(buf + offset, param_len, &value);
			if (ret < 0 || (size_t)ret != param_len)
				return -EINVAL;
			params->initial_max_streams_bidi = value;
			break;

		case TP_INITIAL_MAX_STREAMS_UNI:
			ret = tp_varint_decode(buf + offset, param_len, &value);
			if (ret < 0 || (size_t)ret != param_len)
				return -EINVAL;
			params->initial_max_streams_uni = value;
			break;

		case TP_ACK_DELAY_EXPONENT:
			ret = tp_varint_decode(buf + offset, param_len, &value);
			if (ret < 0 || (size_t)ret != param_len)
				return -EINVAL;
			params->ack_delay_exponent = value;
			break;

		case TP_MAX_ACK_DELAY:
			ret = tp_varint_decode(buf + offset, param_len, &value);
			if (ret < 0 || (size_t)ret != param_len)
				return -EINVAL;
			params->max_ack_delay = value;
			break;

		case TP_DISABLE_ACTIVE_MIGRATION:
			if (param_len != 0)
				return -EINVAL;
			params->disable_active_migration = true;
			break;

		case TP_PREFERRED_ADDRESS:
			if (!is_server)
				return -EPROTO;  /* Client must not send this */
			ret = decode_preferred_address(buf + offset, param_len,
						       &params->preferred_address);
			if (ret < 0)
				return ret;
			params->preferred_address_present = true;
			break;

		case TP_ACTIVE_CONNECTION_ID_LIMIT:
			ret = tp_varint_decode(buf + offset, param_len, &value);
			if (ret < 0 || (size_t)ret != param_len)
				return -EINVAL;
			params->active_connection_id_limit = value;
			break;

		case TP_INITIAL_SOURCE_CONNECTION_ID:
			ret = decode_connection_id(buf + offset, param_len,
						   &params->initial_scid);
			if (ret < 0)
				return ret;
			params->initial_scid_present = true;
			break;

		case TP_RETRY_SOURCE_CONNECTION_ID:
			if (!is_server)
				return -EPROTO;  /* Client must not send this */
			ret = decode_connection_id(buf + offset, param_len,
						   &params->retry_scid);
			if (ret < 0)
				return ret;
			params->retry_scid_present = true;
			break;

		case TP_MAX_DATAGRAM_FRAME_SIZE:
			/* RFC 9221: max_datagram_frame_size */
			ret = tp_varint_decode(buf + offset, param_len, &value);
			if (ret < 0 || (size_t)ret != param_len)
				return -EINVAL;
			params->max_datagram_frame_size = value;
			break;

		case TP_GREASE_QUIC_BIT:
			/*
			 * RFC 9287: grease_quic_bit
			 * Zero-length parameter indicating willingness to
			 * receive packets with GREASE'd fixed bit.
			 */
			params->grease_quic_bit = true;
			break;

		case TP_VERSION_INFORMATION:
			/* Version information (RFC 9368) */
			if (param_len < 4)  /* At least chosen version */
				return -EINVAL;
			if (!params->version_info) {
				params->version_info = tquic_version_info_alloc(GFP_KERNEL);
				if (!params->version_info)
					return -ENOMEM;
			}
			ret = tquic_decode_version_info(buf + offset, param_len,
							params->version_info);
			if (ret < 0)
				return ret;
			params->version_info_present = true;
			break;

		default:
			/* Handle custom multipath parameter */
			if (param_id == TP_ENABLE_MULTIPATH) {
				if (param_len > 0) {
					ret = tp_varint_decode(buf + offset,
								  param_len, &value);
					if (ret < 0)
						return ret;
					params->enable_multipath = (value != 0);
				} else {
					/* Zero-length means enabled */
					params->enable_multipath = true;
				}
			} else if (param_id == TP_INITIAL_MAX_PATH_ID) {
				/* Multipath initial_max_path_id */
				ret = tp_varint_decode(buf + offset,
							  param_len, &value);
				if (ret < 0 || (size_t)ret != param_len)
					return -EINVAL;
				params->initial_max_path_id = value;
				params->initial_max_path_id_present = true;
			} else if (param_id == TP_MIN_ACK_DELAY) {
				/* ACK Frequency (draft-ietf-quic-ack-frequency) */
				ret = tp_varint_decode(buf + offset,
							  param_len, &value);
				if (ret < 0 || (size_t)ret != param_len)
					return -EINVAL;
				params->min_ack_delay = value;
				params->min_ack_delay_present = true;
			}
			/* Unknown parameters are ignored per RFC 9000 */
			break;
		}

		offset += param_len;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_tp_decode);

/**
 * tquic_tp_validate - Validate transport parameters
 * @params: Transport parameters to validate
 * @is_server: True if validating parameters from server
 *
 * Validates transport parameters according to RFC 9000 requirements.
 *
 * Return: 0 if valid, negative error code if invalid
 */
int tquic_tp_validate(const struct tquic_transport_params *params,
		      bool is_server)
{
	/* max_udp_payload_size must be >= 1200 */
	if (params->max_udp_payload_size < MIN_MAX_UDP_PAYLOAD_SIZE) {
		pr_debug("tquic: max_udp_payload_size too small: %llu\n",
			 params->max_udp_payload_size);
		return -EINVAL;
	}

	/* ack_delay_exponent must be <= 20 */
	if (params->ack_delay_exponent > MAX_ACK_DELAY_EXPONENT) {
		pr_debug("tquic: ack_delay_exponent too large: %u\n",
			 params->ack_delay_exponent);
		return -EINVAL;
	}

	/* max_ack_delay must be < 2^14 */
	if (params->max_ack_delay >= MAX_MAX_ACK_DELAY) {
		pr_debug("tquic: max_ack_delay too large: %u\n",
			 params->max_ack_delay);
		return -EINVAL;
	}

	/* active_connection_id_limit must be >= 2 */
	if (params->active_connection_id_limit < 2) {
		pr_debug("tquic: active_connection_id_limit too small: %llu\n",
			 params->active_connection_id_limit);
		return -EINVAL;
	}

	/* initial_max_streams values must be <= 2^60 */
	if (params->initial_max_streams_bidi > TQUIC_MAX_STREAM_COUNT_BIDI) {
		pr_debug("tquic: initial_max_streams_bidi too large\n");
		return -EINVAL;
	}

	if (params->initial_max_streams_uni > TQUIC_MAX_STREAM_COUNT_UNI) {
		pr_debug("tquic: initial_max_streams_uni too large\n");
		return -EINVAL;
	}

	/* Server must provide original_destination_connection_id */
	if (is_server && !params->original_dcid_present) {
		pr_debug("tquic: server missing original_destination_connection_id\n");
		return -EPROTO;
	}

	/* initial_source_connection_id should be present */
	if (!params->initial_scid_present) {
		pr_debug("tquic: missing initial_source_connection_id\n");
		return -EPROTO;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_tp_validate);

/**
 * tquic_tp_negotiate - Negotiate transport parameters between peers
 * @local: Local transport parameters
 * @remote: Remote peer's transport parameters
 * @result: Negotiated parameters result
 *
 * Performs transport parameter negotiation as specified in RFC 9000.
 * The result contains the effective values to use for the connection.
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_tp_negotiate(const struct tquic_transport_params *local,
		       const struct tquic_transport_params *remote,
		       struct tquic_negotiated_params *result)
{
	memset(result, 0, sizeof(*result));

	/*
	 * Idle timeout: use minimum of non-zero values
	 * If both are non-zero, use the minimum
	 * If one is zero, use the other
	 * If both are zero, idle timeout is disabled
	 */
	if (local->max_idle_timeout == 0)
		result->idle_timeout = remote->max_idle_timeout;
	else if (remote->max_idle_timeout == 0)
		result->idle_timeout = local->max_idle_timeout;
	else
		result->idle_timeout = min(local->max_idle_timeout,
					   remote->max_idle_timeout);

	/*
	 * Max UDP payload size: use minimum of both values
	 */
	result->max_udp_payload_size = min(local->max_udp_payload_size,
					   remote->max_udp_payload_size);

	/*
	 * Flow control limits from remote peer
	 * These are the limits the remote peer is imposing on us
	 */
	result->max_data_send = remote->initial_max_data;
	result->max_data_recv = local->initial_max_data;

	result->max_stream_data_bidi_local_send =
		remote->initial_max_stream_data_bidi_remote;
	result->max_stream_data_bidi_local_recv =
		local->initial_max_stream_data_bidi_local;

	result->max_stream_data_bidi_remote_send =
		remote->initial_max_stream_data_bidi_local;
	result->max_stream_data_bidi_remote_recv =
		local->initial_max_stream_data_bidi_remote;

	result->max_stream_data_uni_send = remote->initial_max_stream_data_uni;
	result->max_stream_data_uni_recv = local->initial_max_stream_data_uni;

	/*
	 * Stream limits
	 */
	result->max_streams_bidi_send = remote->initial_max_streams_bidi;
	result->max_streams_bidi_recv = local->initial_max_streams_bidi;
	result->max_streams_uni_send = remote->initial_max_streams_uni;
	result->max_streams_uni_recv = local->initial_max_streams_uni;

	/*
	 * ACK delay parameters - use remote's values for decoding their ACKs
	 */
	result->peer_ack_delay_exponent = remote->ack_delay_exponent;
	result->peer_max_ack_delay = remote->max_ack_delay;

	/*
	 * Migration: disabled if either peer disables it
	 */
	result->migration_disabled = local->disable_active_migration ||
				     remote->disable_active_migration;

	/*
	 * Active connection ID limit: use remote's limit for how many
	 * CIDs we can send them
	 */
	result->active_cid_limit = remote->active_connection_id_limit;

	/*
	 * Multipath: enabled only if both peers support it
	 */
	result->multipath_enabled = local->enable_multipath &&
				    remote->enable_multipath;

	/*
	 * Multipath path ID limits (draft-ietf-quic-multipath)
	 * If both peers advertise initial_max_path_id, use the minimum.
	 * If only one advertises it, use that value.
	 * If neither advertises it but multipath is enabled, use a default.
	 */
	if (result->multipath_enabled) {
		if (local->initial_max_path_id_present &&
		    remote->initial_max_path_id_present) {
			result->max_path_id = min(local->initial_max_path_id,
						  remote->initial_max_path_id);
		} else if (local->initial_max_path_id_present) {
			result->max_path_id = local->initial_max_path_id;
		} else if (remote->initial_max_path_id_present) {
			result->max_path_id = remote->initial_max_path_id;
		} else {
			/* Default: allow up to TQUIC_MAX_PATHS paths */
			result->max_path_id = TQUIC_MAX_PATHS - 1;
		}
	} else {
		result->max_path_id = 0;  /* Single path */
	}

	/*
	 * DATAGRAM support (RFC 9221):
	 * Enabled only if both peers advertise non-zero max_datagram_frame_size.
	 * The negotiated size is the minimum of both values.
	 */
	if (local->max_datagram_frame_size > 0 &&
	    remote->max_datagram_frame_size > 0) {
		result->datagram_enabled = true;
		result->max_datagram_frame_size = min(local->max_datagram_frame_size,
						      remote->max_datagram_frame_size);
	} else {
		result->datagram_enabled = false;
		result->max_datagram_frame_size = 0;
	}

	/*
	 * GREASE (RFC 9287):
	 * Store the peer's grease_quic_bit support for use in packet
	 * construction. We can only GREASE the fixed bit if the peer
	 * has advertised support.
	 */
	result->peer_grease_quic_bit = remote->grease_quic_bit;

	/* Copy preferred address if server provided one */
	if (remote->preferred_address_present) {
		result->preferred_address_present = true;
		memcpy(&result->preferred_address, &remote->preferred_address,
		       sizeof(result->preferred_address));
	}

	/* Store the remote's stateless reset token if present */
	if (remote->stateless_reset_token_present) {
		memcpy(result->peer_stateless_reset_token,
		       remote->stateless_reset_token,
		       STATELESS_RESET_TOKEN_LEN);
		result->peer_stateless_reset_token_present = true;
	}

	/*
	 * ACK Frequency (draft-ietf-quic-ack-frequency):
	 * Enabled only if both peers advertise min_ack_delay parameter.
	 * The peer's min_ack_delay is the minimum delay we MUST wait
	 * before requesting them to send an ACK.
	 */
	if (local->min_ack_delay_present && remote->min_ack_delay_present) {
		result->ack_frequency_enabled = true;
		result->peer_min_ack_delay = remote->min_ack_delay;
	} else {
		result->ack_frequency_enabled = false;
		result->peer_min_ack_delay = 0;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_tp_negotiate);

/* Forward declaration for preferred address handling */
int tquic_pref_addr_client_received(struct tquic_connection *conn,
				    const struct tquic_preferred_address *pref_addr);

/**
 * tquic_tp_apply - Apply negotiated parameters to a connection
 * @conn: Connection to apply parameters to
 * @negotiated: Negotiated parameters
 *
 * Applies the negotiated transport parameters to a connection's
 * internal state.
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_tp_apply(struct tquic_connection *conn,
		   const struct tquic_negotiated_params *negotiated)
{
	int ret;

	spin_lock(&conn->lock);

	/* Apply idle timeout */
	conn->idle_timeout = negotiated->idle_timeout;

	/* Apply flow control limits */
	conn->max_data_remote = negotiated->max_data_send;
	conn->max_data_local = negotiated->max_data_recv;

	/* Apply stream limits */
	conn->max_streams_bidi = negotiated->max_streams_bidi_send;
	conn->max_streams_uni = negotiated->max_streams_uni_send;

	/*
	 * Apply migration policy (RFC 9000 Section 9.1)
	 *
	 * If either endpoint advertised disable_active_migration, then
	 * active migration is disabled. However, per RFC 9000 Section 9.6,
	 * migration to a preferred_address is still permitted even when
	 * disable_active_migration is present.
	 */
	conn->migration_disabled = negotiated->migration_disabled;

	spin_unlock(&conn->lock);

	/*
	 * Handle preferred address (RFC 9000 Section 9.6)
	 *
	 * If the server provided a preferred_address in transport parameters,
	 * store it in the connection for potential migration after handshake.
	 * Only clients process preferred_address from servers.
	 *
	 * Per RFC 9000 Section 9.6: "A server MAY provide a preferred_address
	 * transport parameter, even when the disable_active_migration
	 * transport parameter is present."
	 */
	if (negotiated->preferred_address_present &&
	    conn->role == TQUIC_ROLE_CLIENT) {
		ret = tquic_pref_addr_client_received(conn,
						      &negotiated->preferred_address);
		if (ret < 0) {
			pr_debug("tquic: failed to store preferred address: %d\n",
				 ret);
			/* Non-fatal: connection continues without preferred addr */
		} else {
			pr_info("tquic: stored server's preferred address for migration\n");
		}
	}

	/*
	 * Apply DATAGRAM frame support (RFC 9221)
	 *
	 * If both peers advertised max_datagram_frame_size > 0, then
	 * datagram frames are enabled. The negotiated size is the
	 * minimum of both values.
	 *
	 * max_send_size: The maximum size WE can send (peer's advertised limit)
	 * max_recv_size: The maximum size WE will accept (our advertised limit)
	 *
	 * Use spin_lock_bh for softirq safety since this may be called from
	 * handshake completion which can happen in softirq context.
	 */
	spin_lock_bh(&conn->datagram.lock);
	if (negotiated->datagram_enabled) {
		conn->datagram.enabled = true;
		conn->datagram.max_send_size = negotiated->max_datagram_frame_size;
		conn->datagram.max_recv_size = negotiated->max_datagram_frame_size;
		pr_debug("tquic: DATAGRAM enabled, max_size=%llu\n",
			 negotiated->max_datagram_frame_size);
	} else {
		conn->datagram.enabled = false;
		conn->datagram.max_send_size = 0;
		conn->datagram.max_recv_size = 0;
	}
	spin_unlock_bh(&conn->datagram.lock);

	pr_debug("tquic: applied transport params - idle=%u max_data=%llu/%llu multipath=%d pref_addr=%d migration_disabled=%d datagram=%d\n",
		 negotiated->idle_timeout,
		 negotiated->max_data_send,
		 negotiated->max_data_recv,
		 negotiated->multipath_enabled,
		 negotiated->preferred_address_present,
		 negotiated->migration_disabled,
		 negotiated->datagram_enabled);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_tp_apply);

/**
 * tquic_tp_copy - Copy transport parameters
 * @dst: Destination
 * @src: Source
 */
void tquic_tp_copy(struct tquic_transport_params *dst,
		   const struct tquic_transport_params *src)
{
	memcpy(dst, src, sizeof(*dst));
}
EXPORT_SYMBOL_GPL(tquic_tp_copy);

/**
 * tquic_tp_generate_stateless_reset_token - Generate a stateless reset token
 * @conn: Connection
 * @cid: Connection ID to generate token for
 * @token: Output buffer (16 bytes)
 *
 * Generates a stateless reset token for a given connection ID.
 * The token is derived using the connection's secret and the CID.
 */
void tquic_tp_generate_stateless_reset_token(struct tquic_connection *conn,
					     const struct tquic_cid *cid,
					     u8 *token)
{
	const u8 *static_key;

	/*
	 * Generate stateless reset token using HMAC-SHA256 per RFC 9000
	 * Section 10.3.2: "An endpoint could generate a stateless reset
	 * token by using HMAC with a static key over the connection ID."
	 *
	 * We delegate to the proper implementation in tquic_stateless_reset.c
	 * which uses HMAC-SHA256 and the connection's static key.
	 */
	static_key = tquic_stateless_reset_get_static_key();
	if (static_key && cid) {
		tquic_stateless_reset_generate_token(cid, static_key, token);
	} else {
		/*
		 * Fallback: If no static key available (early in connection
		 * lifecycle), generate random bytes. This is less secure
		 * as tokens won't be deterministic, but is acceptable for
		 * initial CIDs which are replaced after handshake.
		 */
		get_random_bytes(token, STATELESS_RESET_TOKEN_LEN);
	}
}
EXPORT_SYMBOL_GPL(tquic_tp_generate_stateless_reset_token);

/**
 * tquic_tp_cmp_cid - Compare two connection IDs
 * @a: First connection ID
 * @b: Second connection ID
 *
 * Return: true if equal, false otherwise
 */
bool tquic_tp_cmp_cid(const struct tquic_cid *a, const struct tquic_cid *b)
{
	if (a->len != b->len)
		return false;
	return memcmp(a->id, b->id, a->len) == 0;
}
EXPORT_SYMBOL_GPL(tquic_tp_cmp_cid);

/**
 * tquic_tp_validate_cids - Validate connection IDs from transport parameters
 * @params: Received transport parameters
 * @expected_scid: Expected initial_source_connection_id
 * @original_dcid: Original destination_connection_id (for server validation)
 * @is_server: True if validating server's parameters
 *
 * Validates that the connection IDs in the transport parameters match
 * what was expected based on the handshake.
 *
 * Return: 0 if valid, negative error code if invalid
 */
int tquic_tp_validate_cids(const struct tquic_transport_params *params,
			   const struct tquic_cid *expected_scid,
			   const struct tquic_cid *original_dcid,
			   bool is_server)
{
	/* Verify initial_source_connection_id matches */
	if (!params->initial_scid_present) {
		pr_debug("tquic: missing initial_source_connection_id\n");
		return -EPROTO;
	}

	if (!tquic_tp_cmp_cid(&params->initial_scid, expected_scid)) {
		pr_debug("tquic: initial_source_connection_id mismatch\n");
		return -EPROTO;
	}

	/* Server must verify original_destination_connection_id */
	if (is_server && original_dcid) {
		if (!params->original_dcid_present) {
			pr_debug("tquic: missing original_destination_connection_id\n");
			return -EPROTO;
		}

		if (!tquic_tp_cmp_cid(&params->original_dcid, original_dcid)) {
			pr_debug("tquic: original_destination_connection_id mismatch\n");
			return -EPROTO;
		}
	}

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_tp_validate_cids);

/**
 * tquic_tp_encoded_size - Calculate the encoded size of transport parameters
 * @params: Transport parameters
 * @is_server: True if encoding for server
 *
 * Calculates the size needed to encode the transport parameters.
 * Useful for pre-allocating buffers.
 *
 * Return: Size in bytes needed for encoding
 */
size_t tquic_tp_encoded_size(const struct tquic_transport_params *params,
			     bool is_server)
{
	size_t size = 0;

	/* original_destination_connection_id */
	if (is_server && params->original_dcid_present)
		size += 2 + tp_varint_len(params->original_dcid.len) +
			params->original_dcid.len;

	/* max_idle_timeout */
	if (params->max_idle_timeout > 0)
		size += 2 + tp_varint_len(params->max_idle_timeout);

	/* stateless_reset_token */
	if (is_server && params->stateless_reset_token_present)
		size += 2 + 1 + STATELESS_RESET_TOKEN_LEN;

	/* max_udp_payload_size */
	if (params->max_udp_payload_size != DEFAULT_MAX_UDP_PAYLOAD_SIZE)
		size += 2 + tp_varint_len(params->max_udp_payload_size);

	/* initial_max_data */
	if (params->initial_max_data > 0)
		size += 2 + tp_varint_len(params->initial_max_data);

	/* initial_max_stream_data_bidi_local */
	if (params->initial_max_stream_data_bidi_local > 0)
		size += 2 + tp_varint_len(params->initial_max_stream_data_bidi_local);

	/* initial_max_stream_data_bidi_remote */
	if (params->initial_max_stream_data_bidi_remote > 0)
		size += 2 + tp_varint_len(params->initial_max_stream_data_bidi_remote);

	/* initial_max_stream_data_uni */
	if (params->initial_max_stream_data_uni > 0)
		size += 2 + tp_varint_len(params->initial_max_stream_data_uni);

	/* initial_max_streams_bidi */
	if (params->initial_max_streams_bidi > 0)
		size += 2 + tp_varint_len(params->initial_max_streams_bidi);

	/* initial_max_streams_uni */
	if (params->initial_max_streams_uni > 0)
		size += 2 + tp_varint_len(params->initial_max_streams_uni);

	/* ack_delay_exponent */
	if (params->ack_delay_exponent != DEFAULT_ACK_DELAY_EXPONENT)
		size += 2 + tp_varint_len(params->ack_delay_exponent);

	/* max_ack_delay */
	if (params->max_ack_delay != DEFAULT_MAX_ACK_DELAY)
		size += 2 + tp_varint_len(params->max_ack_delay);

	/* disable_active_migration */
	if (params->disable_active_migration)
		size += 2;

	/* preferred_address */
	if (is_server && params->preferred_address_present) {
		size += 2 + 1;  /* ID + length byte */
		size += 4 + 2;  /* IPv4 */
		size += 16 + 2; /* IPv6 */
		size += 1 + params->preferred_address.cid.len;
		size += STATELESS_RESET_TOKEN_LEN;
	}

	/* active_connection_id_limit */
	if (params->active_connection_id_limit != DEFAULT_ACTIVE_CONNECTION_ID_LIMIT)
		size += 2 + tp_varint_len(params->active_connection_id_limit);

	/* initial_source_connection_id */
	if (params->initial_scid_present)
		size += 2 + tp_varint_len(params->initial_scid.len) +
			params->initial_scid.len;

	/* retry_source_connection_id */
	if (is_server && params->retry_scid_present)
		size += 2 + tp_varint_len(params->retry_scid.len) +
			params->retry_scid.len;

	/* enable_multipath */
	if (params->enable_multipath)
		size += 10 + 1;  /* 8-byte ID + length + value */

	/* max_datagram_frame_size (RFC 9221) */
	if (params->max_datagram_frame_size > 0)
		size += 2 + tp_varint_len(params->max_datagram_frame_size);

	/* grease_quic_bit (RFC 9287) - 2-byte ID + 1-byte length (0) */
	if (params->grease_quic_bit)
		size += 4;  /* 0x2ab2 = 2-byte varint + 1-byte zero length */

	/* min_ack_delay (draft-ietf-quic-ack-frequency) */
	if (params->min_ack_delay_present) {
		size += tp_varint_len(TP_MIN_ACK_DELAY) +
			tp_varint_len(tp_varint_len(params->min_ack_delay)) +
			tp_varint_len(params->min_ack_delay);
	}

	return size;
}
EXPORT_SYMBOL_GPL(tquic_tp_encoded_size);

/**
 * tquic_tp_debug_print - Print transport parameters for debugging
 * @params: Transport parameters to print
 * @prefix: Prefix for log messages
 */
void tquic_tp_debug_print(const struct tquic_transport_params *params,
			  const char *prefix)
{
	pr_debug("%s: Transport Parameters:\n", prefix);
	pr_debug("%s:   max_idle_timeout: %llu ms\n", prefix,
		 params->max_idle_timeout);
	pr_debug("%s:   max_udp_payload_size: %llu\n", prefix,
		 params->max_udp_payload_size);
	pr_debug("%s:   initial_max_data: %llu\n", prefix,
		 params->initial_max_data);
	pr_debug("%s:   initial_max_stream_data_bidi_local: %llu\n", prefix,
		 params->initial_max_stream_data_bidi_local);
	pr_debug("%s:   initial_max_stream_data_bidi_remote: %llu\n", prefix,
		 params->initial_max_stream_data_bidi_remote);
	pr_debug("%s:   initial_max_stream_data_uni: %llu\n", prefix,
		 params->initial_max_stream_data_uni);
	pr_debug("%s:   initial_max_streams_bidi: %llu\n", prefix,
		 params->initial_max_streams_bidi);
	pr_debug("%s:   initial_max_streams_uni: %llu\n", prefix,
		 params->initial_max_streams_uni);
	pr_debug("%s:   ack_delay_exponent: %u\n", prefix,
		 params->ack_delay_exponent);
	pr_debug("%s:   max_ack_delay: %u ms\n", prefix,
		 params->max_ack_delay);
	pr_debug("%s:   disable_active_migration: %s\n", prefix,
		 params->disable_active_migration ? "yes" : "no");
	pr_debug("%s:   active_connection_id_limit: %llu\n", prefix,
		 params->active_connection_id_limit);
	pr_debug("%s:   enable_multipath: %s\n", prefix,
		 params->enable_multipath ? "yes" : "no");
	pr_debug("%s:   max_datagram_frame_size: %llu\n", prefix,
		 params->max_datagram_frame_size);
	pr_debug("%s:   grease_quic_bit: %s\n", prefix,
		 params->grease_quic_bit ? "yes" : "no");
	if (params->min_ack_delay_present)
		pr_debug("%s:   min_ack_delay: %llu us\n", prefix,
			 params->min_ack_delay);

	if (params->initial_scid_present)
		pr_debug("%s:   initial_source_cid: %*phN\n", prefix,
			 params->initial_scid.len, params->initial_scid.id);

	if (params->original_dcid_present)
		pr_debug("%s:   original_dest_cid: %*phN\n", prefix,
			 params->original_dcid.len, params->original_dcid.id);

	if (params->initial_max_path_id_present)
		pr_debug("%s:   initial_max_path_id: %llu\n", prefix,
			 params->initial_max_path_id);

	if (params->version_info_present && params->version_info) {
		size_t i;
		pr_debug("%s:   version_info.chosen: 0x%08x\n", prefix,
			 params->version_info->chosen_version);
		for (i = 0; i < params->version_info->num_versions; i++)
			pr_debug("%s:   version_info.available[%zu]: 0x%08x\n",
				 prefix, i, params->version_info->available_versions[i]);
	}
}
EXPORT_SYMBOL_GPL(tquic_tp_debug_print);

/*
 * =============================================================================
 * Version Information API (RFC 9368 - Compatible Version Negotiation)
 * =============================================================================
 */

/**
 * tquic_version_info_alloc - Allocate a version_info structure
 * @gfp: Memory allocation flags
 *
 * Return: Pointer to allocated structure, or NULL on failure
 */
struct tquic_version_info *tquic_version_info_alloc(gfp_t gfp)
{
	struct tquic_version_info *info;

	info = kzalloc(sizeof(*info), gfp);
	if (!info)
		return NULL;

	return info;
}
EXPORT_SYMBOL_GPL(tquic_version_info_alloc);

/**
 * tquic_version_info_free - Free a version_info structure
 * @info: Structure to free (may be NULL)
 */
void tquic_version_info_free(struct tquic_version_info *info)
{
	kfree(info);
}
EXPORT_SYMBOL_GPL(tquic_version_info_free);

/**
 * tquic_encode_version_info - Encode version_information transport parameter
 * @buf: Output buffer
 * @len: Buffer length
 * @chosen: The chosen QUIC version for the connection
 * @available: Array of available/supported versions
 * @count: Number of versions in the available array
 *
 * Return: Number of bytes written on success, negative error code on failure
 */
ssize_t tquic_encode_version_info(u8 *buf, size_t len,
				  u32 chosen, const u32 *available, size_t count)
{
	size_t offset = 0;
	size_t i;
	size_t needed;

	/* Validate: version 0 is not allowed */
	if (chosen == 0)
		return -EINVAL;

	for (i = 0; i < count; i++) {
		if (available[i] == 0)
			return -EINVAL;
	}

	/* Calculate needed space: chosen (4) + available (4 * count) */
	needed = 4 + (4 * count);
	if (len < needed)
		return -ENOSPC;

	/* Encode Chosen Version (4 bytes, big-endian) */
	buf[offset++] = (chosen >> 24) & 0xff;
	buf[offset++] = (chosen >> 16) & 0xff;
	buf[offset++] = (chosen >> 8) & 0xff;
	buf[offset++] = chosen & 0xff;

	/* Encode Available Versions (4 bytes each, big-endian) */
	for (i = 0; i < count; i++) {
		u32 v = available[i];
		buf[offset++] = (v >> 24) & 0xff;
		buf[offset++] = (v >> 16) & 0xff;
		buf[offset++] = (v >> 8) & 0xff;
		buf[offset++] = v & 0xff;
	}

	return offset;
}
EXPORT_SYMBOL_GPL(tquic_encode_version_info);

/**
 * tquic_decode_version_info - Decode version_information transport parameter
 * @buf: Input buffer containing the parameter value
 * @len: Length of the parameter value
 * @info: Output structure to populate
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_decode_version_info(const u8 *buf, size_t len,
			      struct tquic_version_info *info)
{
	size_t offset = 0;
	size_t num_available;
	size_t i;

	if (!buf || !info)
		return -EINVAL;

	/* Must have at least the Chosen Version (4 bytes) */
	if (len < 4)
		return -EINVAL;

	/* Decode Chosen Version */
	info->chosen_version = ((u32)buf[offset] << 24) |
			       ((u32)buf[offset + 1] << 16) |
			       ((u32)buf[offset + 2] << 8) |
			       buf[offset + 3];
	offset += 4;

	/* Version 0 is not allowed */
	if (info->chosen_version == 0)
		return -EPROTO;

	/* Remaining bytes are Available Versions (must be multiple of 4) */
	if ((len - offset) % 4 != 0)
		return -EINVAL;

	num_available = (len - offset) / 4;
	if (num_available > TQUIC_MAX_AVAILABLE_VERSIONS)
		num_available = TQUIC_MAX_AVAILABLE_VERSIONS;

	info->num_versions = num_available;

	for (i = 0; i < num_available; i++) {
		info->available_versions[i] = ((u32)buf[offset] << 24) |
					      ((u32)buf[offset + 1] << 16) |
					      ((u32)buf[offset + 2] << 8) |
					      buf[offset + 3];
		offset += 4;

		/* Version 0 is not allowed in available versions */
		if (info->available_versions[i] == 0)
			return -EPROTO;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_decode_version_info);

/**
 * tquic_validate_version_info - Validate version_information parameter
 * @info: Version information to validate
 * @connection_version: The version used on the connection
 * @is_client: True if validating a client's version_info
 *
 * Return: 0 if valid, negative error code if invalid
 */
int tquic_validate_version_info(const struct tquic_version_info *info,
				u32 connection_version, bool is_client)
{
	size_t i;
	bool chosen_in_available = false;

	if (!info)
		return -EINVAL;

	/* Chosen Version must not be 0 */
	if (info->chosen_version == 0)
		return -TQUIC_ERR_VERSION_NEGOTIATION;

	/* For clients: Chosen Version must match connection version */
	if (is_client && info->chosen_version != connection_version) {
		pr_debug("tquic: client version_info chosen (0x%08x) != connection (0x%08x)\n",
			 info->chosen_version, connection_version);
		return -TQUIC_ERR_VERSION_NEGOTIATION;
	}

	/* Validate Available Versions */
	for (i = 0; i < info->num_versions; i++) {
		if (info->available_versions[i] == 0)
			return -TQUIC_ERR_VERSION_NEGOTIATION;

		if (info->available_versions[i] == info->chosen_version)
			chosen_in_available = true;
	}

	/* Chosen Version should appear in Available Versions */
	if (info->num_versions > 0 && !chosen_in_available) {
		pr_warn("tquic: version_info chosen not in available list\n");
		/* This is a SHOULD, not a MUST, so just warn */
	}

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_validate_version_info);

/**
 * tquic_version_info_contains - Check if version is in available versions
 * @info: Version information structure
 * @version: Version to search for
 *
 * Return: true if version is found in available_versions, false otherwise
 */
bool tquic_version_info_contains(const struct tquic_version_info *info,
				 u32 version)
{
	size_t i;

	if (!info || version == 0)
		return false;

	for (i = 0; i < info->num_versions; i++) {
		if (info->available_versions[i] == version)
			return true;
	}

	return false;
}
EXPORT_SYMBOL_GPL(tquic_version_info_contains);

/**
 * tquic_tp_set_version_info - Set version_info in transport parameters
 * @params: Transport parameters structure
 * @chosen: Chosen version for the connection
 * @available: Array of available versions
 * @count: Number of available versions
 * @gfp: Memory allocation flags
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_tp_set_version_info(struct tquic_transport_params *params,
			      u32 chosen, const u32 *available, size_t count,
			      gfp_t gfp)
{
	if (!params)
		return -EINVAL;

	if (count > TQUIC_MAX_AVAILABLE_VERSIONS)
		return -EINVAL;

	/* Free existing version_info if present */
	if (params->version_info)
		tquic_version_info_free(params->version_info);

	params->version_info = tquic_version_info_alloc(gfp);
	if (!params->version_info)
		return -ENOMEM;

	params->version_info->chosen_version = chosen;
	params->version_info->num_versions = count;
	memcpy(params->version_info->available_versions, available,
	       count * sizeof(u32));

	params->version_info_present = true;

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_tp_set_version_info);

/**
 * tquic_tp_clear_version_info - Clear version_info from transport parameters
 * @params: Transport parameters structure
 */
void tquic_tp_clear_version_info(struct tquic_transport_params *params)
{
	if (!params)
		return;

	if (params->version_info) {
		tquic_version_info_free(params->version_info);
		params->version_info = NULL;
	}
	params->version_info_present = false;
}
EXPORT_SYMBOL_GPL(tquic_tp_clear_version_info);
