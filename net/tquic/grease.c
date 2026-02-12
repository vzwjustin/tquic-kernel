// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: GREASE Support Implementation (RFC 9287)
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Implementation of Generate Random Extensions And Sustain Extensibility
 * (GREASE) for QUIC protocol forward compatibility testing.
 *
 * This file provides:
 *   - GREASE transport parameter encoding/decoding
 *   - GREASE version generation for Version Negotiation
 *   - GREASE state management for connections
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <net/tquic.h>

#include "protocol.h"
#include "grease.h"
#include "tquic_debug.h"
#include "core/transport_params.h"

/*
 * =============================================================================
 * GREASE State Management
 * =============================================================================
 */

/**
 * tquic_grease_state_init - Initialize GREASE state for a connection
 * @state: GREASE state to initialize
 * @net: Network namespace for sysctl settings
 *
 * Return: 0 on success
 */
int tquic_grease_state_init(struct tquic_grease_state *state, struct net *net)
{
	if (!state)
		return -EINVAL;

	memset(state, 0, sizeof(*state));

	/* Check sysctl setting for this netns */
	state->grease_enabled = tquic_net_get_grease_enabled(net);

	/* If GREASE is enabled, we advertise grease_quic_bit support */
	state->local_grease_quic_bit = state->grease_enabled;

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_grease_state_init);

/**
 * tquic_grease_state_set_peer - Update GREASE state with peer's transport params
 * @state: GREASE state to update
 * @peer_grease_quic_bit: Whether peer advertised grease_quic_bit
 */
void tquic_grease_state_set_peer(struct tquic_grease_state *state,
				 bool peer_grease_quic_bit)
{
	if (state)
		state->peer_grease_quic_bit = peer_grease_quic_bit;
}
EXPORT_SYMBOL_GPL(tquic_grease_state_set_peer);

/*
 * =============================================================================
 * GREASE Transport Parameters Encoding
 * =============================================================================
 */

/*
 * Variable-length integer encoding helper (QUIC style)
 */
static int grease_varint_len(u64 val)
{
	if (val <= 63)
		return 1;
	if (val <= 16383)
		return 2;
	if (val <= 1073741823)
		return 4;
	return 8;
}

static int grease_varint_encode(u8 *buf, size_t buflen, u64 val)
{
	int len = grease_varint_len(val);

	if (len > buflen)
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

	return len;
}

/**
 * tquic_grease_encode_tp - Encode GREASE transport parameters
 * @state: GREASE state for the connection
 * @buf: Output buffer
 * @buflen: Buffer length
 *
 * Encodes the grease_quic_bit parameter (if enabled) and random GREASE
 * transport parameters for forward compatibility testing.
 *
 * Return: Number of bytes written, or negative error code
 */
ssize_t tquic_grease_encode_tp(struct tquic_grease_state *state,
			       u8 *buf, size_t buflen)
{
	size_t offset = 0;
	int ret;
	u8 grease_count;
	int i;

	if (!state || !state->grease_enabled)
		return 0;

	/*
	 * Encode grease_quic_bit transport parameter (0x2ab2)
	 * This is a zero-length parameter signaling support for GREASE'd packets
	 */
	if (state->local_grease_quic_bit) {
		/* Parameter ID (0x2ab2 = 10930, needs 2-byte varint) */
		ret = grease_varint_encode(buf + offset, buflen - offset,
					   TQUIC_TP_GREASE_QUIC_BIT);
		if (ret < 0)
			return ret;
		offset += ret;

		/* Length (0 - zero-length parameter) */
		ret = grease_varint_encode(buf + offset, buflen - offset, 0);
		if (ret < 0)
			return ret;
		offset += ret;

		tquic_dbg("encoded grease_quic_bit transport parameter\n");
	}

	/*
	 * Encode random GREASE transport parameters (31*N + 27 pattern)
	 * Per RFC 9000 Section 18.1, receivers MUST ignore these
	 */
	grease_count = tquic_grease_tp_count();
	state->grease_tp_count = 0;

	for (i = 0; i < grease_count && i < TQUIC_GREASE_TP_MAX_COUNT; i++) {
		u64 tp_id;
		u8 value_len;
		u8 value[TQUIC_GREASE_TP_MAX_LEN];

		/* Generate reserved transport parameter ID */
		tp_id = tquic_grease_generate_tp_id();

		/* Generate random value length and content */
		value_len = tquic_grease_tp_value_len();
		if (value_len > 0)
			tquic_grease_generate_tp_value(value, value_len);

		/* Check if we have enough space */
		if (offset + grease_varint_len(tp_id) +
		    grease_varint_len(value_len) + value_len > buflen)
			break;

		/* Encode parameter ID */
		ret = grease_varint_encode(buf + offset, buflen - offset, tp_id);
		if (ret < 0)
			return ret;
		offset += ret;

		/* Encode length */
		ret = grease_varint_encode(buf + offset, buflen - offset, value_len);
		if (ret < 0)
			return ret;
		offset += ret;

		/* Encode value (random data) */
		if (value_len > 0) {
			memcpy(buf + offset, value, value_len);
			offset += value_len;
		}

		/* Track the GREASE TP ID we sent */
		state->grease_tp_ids[state->grease_tp_count++] = tp_id;

		tquic_dbg("encoded GREASE transport param id=0x%llx len=%u\n",
			 tp_id, value_len);
	}

	return offset;
}
EXPORT_SYMBOL_GPL(tquic_grease_encode_tp);

/**
 * tquic_grease_encoded_tp_size - Calculate encoded size of GREASE transport params
 * @state: GREASE state
 *
 * Return: Maximum bytes needed for GREASE transport parameters
 */
size_t tquic_grease_encoded_tp_size(struct tquic_grease_state *state)
{
	size_t size = 0;

	if (!state || !state->grease_enabled)
		return 0;

	/* grease_quic_bit: 2-byte ID + 1-byte length (0) = ~3 bytes */
	if (state->local_grease_quic_bit)
		size += 4;

	/*
	 * Each GREASE TP: up to 8-byte ID + 2-byte length + 16-byte value
	 * Maximum: 3 TPs * 26 bytes = 78 bytes
	 */
	size += TQUIC_GREASE_TP_MAX_COUNT * (8 + 2 + TQUIC_GREASE_TP_MAX_LEN);

	return size;
}
EXPORT_SYMBOL_GPL(tquic_grease_encoded_tp_size);

/*
 * =============================================================================
 * GREASE Version Negotiation
 * =============================================================================
 */

/**
 * tquic_grease_add_versions - Add GREASE versions to Version Negotiation
 * @versions: Array to add versions to
 * @max_versions: Maximum versions the array can hold
 * @current_count: Current number of versions in array
 *
 * Randomly adds 1-2 GREASE versions to the Version Negotiation response.
 * These versions follow the 0x?a?a?a?a pattern per RFC 9000 Section 15.
 *
 * Return: New count of versions in array
 */
int tquic_grease_add_versions(u32 *versions, int max_versions, int current_count)
{
	u8 grease_version_cnt;
	int i;

	if (current_count >= max_versions)
		return current_count;

	/* Randomly add 1-2 GREASE versions */
	grease_version_cnt = tquic_grease_version_count();

	for (i = 0; i < grease_version_cnt && current_count < max_versions; i++) {
		versions[current_count] = tquic_grease_generate_version();
		tquic_dbg("added GREASE version 0x%08x to VN\n",
			 versions[current_count]);
		current_count++;
	}

	return current_count;
}
EXPORT_SYMBOL_GPL(tquic_grease_add_versions);

/*
 * =============================================================================
 * Per-netns GREASE Configuration
 * =============================================================================
 */

/**
 * tquic_net_get_grease_enabled - Check if GREASE is enabled for network namespace
 * @net: Network namespace to check
 *
 * Return: true if GREASE is enabled, false otherwise
 */
bool tquic_net_get_grease_enabled(struct net *net)
{
	struct tquic_net *tn;

	if (!net)
		return true;  /* Default enabled */

	tn = tquic_pernet(net);
	if (!tn)
		return true;  /* Default enabled */

	return tn->grease_enabled;
}
EXPORT_SYMBOL_GPL(tquic_net_get_grease_enabled);

/*
 * =============================================================================
 * Module Initialization
 * =============================================================================
 */

/**
 * tquic_grease_init - Initialize GREASE subsystem
 *
 * Return: 0 on success
 */
int __init tquic_grease_init(void)
{
	tquic_info("GREASE (RFC 9287) support initialized\n");
	return 0;
}

/**
 * tquic_grease_exit - Cleanup GREASE subsystem
 */
void tquic_grease_exit(void)
{
	tquic_dbg("GREASE support cleanup complete\n");
}
