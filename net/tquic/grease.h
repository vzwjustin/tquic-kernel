/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: GREASE Support (RFC 9287)
 *
 * Copyright (c) 2026 Linux Foundation
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Implementation of Generate Random Extensions And Sustain Extensibility
 * (GREASE) for QUIC protocol forward compatibility testing.
 *
 * RFC 9287: QUIC Greasing the QUIC Bit
 *   - Section 3: The GREASE Bit
 *   - Section 3.1: grease_quic_bit Transport Parameter (0x2ab2)
 *
 * RFC 9000 Section 18.1: Reserved Transport Parameter Values
 *   - Reserved parameter IDs: 31 * N + 27 (0x1f * N + 0x1b)
 *
 * RFC 9000 Section 15: Reserved Version Values
 *   - Reserved versions: 0x?a?a?a?a pattern
 */

#ifndef _TQUIC_GREASE_H
#define _TQUIC_GREASE_H

#include <linux/types.h>
#include <linux/random.h>

/* Forward declarations */
struct net;

/*
 * GREASE Transport Parameter ID (RFC 9287 Section 3.1)
 * Signals willingness to receive packets with GREASE'd fixed bit
 */
#define TQUIC_TP_GREASE_QUIC_BIT	0x2ab2

/*
 * Maximum GREASE transport parameters to include
 * We randomly include 0-3 GREASE parameters per connection
 */
#define TQUIC_GREASE_TP_MAX_COUNT	3

/*
 * Maximum length for GREASE transport parameter values
 * Random length 0-16 bytes
 */
#define TQUIC_GREASE_TP_MAX_LEN		16

/*
 * Number of GREASE versions to include in Version Negotiation
 * We include 1-2 GREASE versions randomly
 */
#define TQUIC_GREASE_VERSION_MAX_COUNT	2

/*
 * Probability of GREASE'ing the fixed bit (1 in N packets)
 * RFC 9287 recommends random selection, we use ~1 in 16
 */
#define TQUIC_GREASE_BIT_PROB		16

/**
 * struct tquic_grease_state - Per-connection GREASE state
 * @grease_enabled: GREASE is enabled for this connection
 * @peer_grease_quic_bit: Peer advertised grease_quic_bit support
 * @local_grease_quic_bit: We advertised grease_quic_bit support
 * @grease_tp_count: Number of GREASE transport parameters sent
 * @grease_tp_ids: IDs of GREASE transport parameters sent
 */
struct tquic_grease_state {
	bool grease_enabled;
	bool peer_grease_quic_bit;
	bool local_grease_quic_bit;
	u8 grease_tp_count;
	u64 grease_tp_ids[TQUIC_GREASE_TP_MAX_COUNT];
};

/**
 * tquic_grease_generate_tp_id - Generate a reserved transport parameter ID
 *
 * Reserved transport parameter IDs follow the pattern: 31 * N + 27
 * Per RFC 9000 Section 18.1, these MUST be ignored by receivers.
 *
 * Return: A reserved transport parameter ID
 */
static inline u64 tquic_grease_generate_tp_id(void)
{
	u32 n;

	get_random_bytes(&n, sizeof(n));
	/* Limit N to reasonable range to avoid huge varints */
	n = n % 1000;
	return (u64)31 * n + 27;
}

/**
 * tquic_grease_is_reserved_tp_id - Check if transport parameter ID is reserved
 * @tp_id: Transport parameter ID to check
 *
 * Return: true if this is a reserved GREASE transport parameter ID
 */
static inline bool tquic_grease_is_reserved_tp_id(u64 tp_id)
{
	/*
	 * Reserved IDs follow pattern: 31 * N + 27
	 * This means (tp_id - 27) must be divisible by 31
	 */
	if (tp_id < 27)
		return false;
	return ((tp_id - 27) % 31) == 0;
}

/**
 * tquic_grease_generate_version - Generate a reserved GREASE version
 *
 * Reserved versions follow the pattern: 0x?a?a?a?a
 * where ? is any 4-bit value. Per RFC 9000 Section 15.
 *
 * Return: A reserved GREASE version value
 */
static inline u32 tquic_grease_generate_version(void)
{
	u32 rand_val;
	u32 version;

	get_random_bytes(&rand_val, sizeof(rand_val));

	/*
	 * Build 0x?a?a?a?a pattern:
	 * Each nibble alternates between random and 0xa
	 */
	version = ((rand_val & 0x0f) << 28) |   /* First random nibble */
		  (0x0a << 24) |                 /* 0xa */
		  (((rand_val >> 4) & 0x0f) << 20) |  /* Second random nibble */
		  (0x0a << 16) |                 /* 0xa */
		  (((rand_val >> 8) & 0x0f) << 12) |  /* Third random nibble */
		  (0x0a << 8) |                  /* 0xa */
		  (((rand_val >> 12) & 0x0f) << 4) |  /* Fourth random nibble */
		  0x0a;                          /* 0xa */

	return version;
}

/**
 * tquic_grease_is_reserved_version - Check if version is reserved (GREASE)
 * @version: Version number to check
 *
 * Return: true if this follows the 0x?a?a?a?a GREASE pattern
 */
static inline bool tquic_grease_is_reserved_version(u32 version)
{
	/*
	 * Check the 0x?a?a?a?a pattern - every other nibble must be 0xa
	 */
	return ((version & 0x0f0f0f0f) == 0x0a0a0a0a);
}

/**
 * tquic_grease_should_grease_bit - Decide whether to GREASE the fixed bit
 * @state: GREASE state for the connection
 *
 * Only GREASE the fixed bit if:
 *   1. GREASE is enabled globally (sysctl)
 *   2. Peer has signaled support via grease_quic_bit transport parameter
 *   3. Random selection (approximately 1 in TQUIC_GREASE_BIT_PROB packets)
 *
 * Return: true if we should set fixed bit to 0, false to keep it as 1
 */
static inline bool tquic_grease_should_grease_bit(struct tquic_grease_state *state)
{
	u8 rand_byte;

	if (!state || !state->grease_enabled || !state->peer_grease_quic_bit)
		return false;

	get_random_bytes(&rand_byte, 1);
	return (rand_byte % TQUIC_GREASE_BIT_PROB) == 0;
}

/**
 * tquic_grease_generate_tp_value - Generate random data for GREASE TP value
 * @buf: Output buffer
 * @len: Length of random data to generate (0-16)
 */
static inline void tquic_grease_generate_tp_value(u8 *buf, u8 len)
{
	if (len > 0 && len <= TQUIC_GREASE_TP_MAX_LEN)
		get_random_bytes(buf, len);
}

/**
 * tquic_grease_tp_count - Decide how many GREASE transport parameters to send
 *
 * Return: Number of GREASE transport parameters (0-3)
 */
static inline u8 tquic_grease_tp_count(void)
{
	u8 rand_byte;

	get_random_bytes(&rand_byte, 1);
	/* Weighted distribution: ~50% send 0, ~30% send 1, ~15% send 2, ~5% send 3 */
	if (rand_byte < 128)
		return 0;
	if (rand_byte < 205)
		return 1;
	if (rand_byte < 243)
		return 2;
	return 3;
}

/**
 * tquic_grease_tp_value_len - Decide length of GREASE transport parameter value
 *
 * Return: Random length for GREASE transport parameter value (0-16)
 */
static inline u8 tquic_grease_tp_value_len(void)
{
	u8 rand_byte;

	get_random_bytes(&rand_byte, 1);
	/* Random length 0-16 */
	return rand_byte % (TQUIC_GREASE_TP_MAX_LEN + 1);
}

/**
 * tquic_grease_version_count - Decide how many GREASE versions to include
 *
 * Return: Number of GREASE versions (1-2)
 */
static inline u8 tquic_grease_version_count(void)
{
	u8 rand_byte;

	get_random_bytes(&rand_byte, 1);
	return (rand_byte & 1) + 1;  /* 1 or 2 */
}

/* Global sysctl accessor - implemented in tquic_sysctl.c */
int tquic_sysctl_get_grease_enabled(void);

/* Per-netns accessor - implemented in grease.c */
bool tquic_net_get_grease_enabled(struct net *net);

/*
 * GREASE state management - implemented in grease.c
 */
int tquic_grease_state_init(struct tquic_grease_state *state, struct net *net);
void tquic_grease_state_set_peer(struct tquic_grease_state *state,
				 bool peer_grease_quic_bit);

/*
 * GREASE transport parameters - implemented in grease.c
 */
ssize_t tquic_grease_encode_tp(struct tquic_grease_state *state,
			       u8 *buf, size_t buflen);
size_t tquic_grease_encoded_tp_size(struct tquic_grease_state *state);

/*
 * GREASE version negotiation - implemented in grease.c
 */
int tquic_grease_add_versions(u32 *versions, int max_versions, int current_count);

/*
 * Module init/exit - implemented in grease.c
 */
int __init tquic_grease_init(void);
void __exit tquic_grease_exit(void);

#endif /* _TQUIC_GREASE_H */
