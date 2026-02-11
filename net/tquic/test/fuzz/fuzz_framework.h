/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC Fuzzing Framework
 *
 * Copyright (c) 2026 Linux Foundation
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * This framework provides systematic fuzzing infrastructure for discovering
 * vulnerabilities in the TQUIC implementation. It supports:
 *
 * - Packet fuzzing (malformed headers, frames, lengths)
 * - State machine fuzzing (unexpected frame sequences)
 * - Transport parameter fuzzing
 * - Crypto fuzzing
 * - Connection ID fuzzing
 * - Flow control boundary fuzzing
 *
 * Integration:
 * - Can be used with kernel coverage (KCOV) for coverage-guided fuzzing
 * - Supports AFL/libFuzzer style mutation strategies
 * - Provides hooks for external fuzzers via debugfs
 */

#ifndef _TQUIC_FUZZ_H
#define _TQUIC_FUZZ_H

#include <linux/types.h>
#include <linux/random.h>
#include <linux/list.h>
#include <linux/spinlock.h>

/*
 * =============================================================================
 * Fuzzer Configuration
 * =============================================================================
 */

/* Fuzzing modes */
#define TQUIC_FUZZ_MODE_OFF		0
#define TQUIC_FUZZ_MODE_RANDOM		1	/* Random mutation */
#define TQUIC_FUZZ_MODE_GUIDED		2	/* Coverage-guided */
#define TQUIC_FUZZ_MODE_GRAMMAR		3	/* Grammar-based */
#define TQUIC_FUZZ_MODE_REPLAY		4	/* Replay corpus */

/* Fuzz targets */
#define TQUIC_FUZZ_TARGET_PACKET		BIT(0)
#define TQUIC_FUZZ_TARGET_FRAME			BIT(1)
#define TQUIC_FUZZ_TARGET_CRYPTO		BIT(2)
#define TQUIC_FUZZ_TARGET_PARAMS		BIT(3)
#define TQUIC_FUZZ_TARGET_TRANSPORT_PARAMS	TQUIC_FUZZ_TARGET_PARAMS
#define TQUIC_FUZZ_TARGET_CID			BIT(4)
#define TQUIC_FUZZ_TARGET_FLOW			BIT(5)
#define TQUIC_FUZZ_TARGET_STATE			BIT(6)
#define TQUIC_FUZZ_TARGET_SERVER		BIT(7)	/* Target server role */
#define TQUIC_FUZZ_TARGET_CLIENT		BIT(8)	/* Target client role */
#define TQUIC_FUZZ_TARGET_ALL			0xFFFFFFFF

/* Mutation strategies */
#define TQUIC_MUTATE_BIT_FLIP		BIT(0)
#define TQUIC_MUTATE_BYTE_FLIP		BIT(1)
#define TQUIC_MUTATE_ARITHMETIC		BIT(2)
#define TQUIC_MUTATE_INTERESTING	BIT(3)
#define TQUIC_MUTATE_HAVOC		BIT(4)
#define TQUIC_MUTATE_SPLICE		BIT(5)
#define TQUIC_MUTATE_INSERT		BIT(6)
#define TQUIC_MUTATE_DELETE		BIT(7)
#define TQUIC_MUTATE_ALL		0xFF

/* Interesting values for fuzzing */
static const u64 fuzz_interesting_u64[] = {
	0, 1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64,
	127, 128, 255, 256, 511, 512, 1023, 1024,
	0x7F, 0x7FF, 0x7FFF, 0x7FFFFFFF, 0x7FFFFFFFFFFFFFFFULL,
	0x80, 0x800, 0x8000, 0x80000000ULL, 0x8000000000000000ULL,
	0xFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFFULL,
	0x3FFF, 0x3FFFFFFF, 0x3FFFFFFFFFFFFFFFULL,  /* QUIC varints */
};

#define FUZZ_INTERESTING_U64_COUNT ARRAY_SIZE(fuzz_interesting_u64)

/*
 * =============================================================================
 * Fuzzer State
 * =============================================================================
 */

/**
 * struct tquic_fuzz_stats - Fuzzing statistics
 * @iterations:      Total fuzz iterations
 * @crashes:         Crash-inducing inputs found
 * @hangs:           Hang-inducing inputs found
 * @unique_crashes:  Unique crash signatures
 * @coverage_new:    New coverage paths found
 * @corpus_size:     Current corpus size
 * @execs_per_sec:   Executions per second
 */
struct tquic_fuzz_stats {
	atomic64_t iterations;
	atomic64_t crashes;
	atomic64_t hangs;
	atomic64_t unique_crashes;
	atomic64_t coverage_new;
	atomic64_t corpus_size;
	atomic64_t execs_per_sec;
};

/**
 * struct tquic_fuzz_input - Single fuzz input
 * @data:       Input data
 * @len:        Data length
 * @coverage:   Coverage bitmap hash
 * @is_crash:   Input causes crash
 * @is_hang:    Input causes hang
 * @list:       Corpus list linkage
 */
struct tquic_fuzz_input {
	u8 *data;
	size_t len;
	u32 coverage;
	bool is_crash;
	bool is_hang;
	struct list_head list;
};

/**
 * struct tquic_fuzz_state - Global fuzzer state
 * @mode:        Current fuzzing mode
 * @targets:     Active fuzz targets
 * @mutations:   Enabled mutation strategies
 * @corpus:      Input corpus list
 * @corpus_lock: Corpus list lock
 * @stats:       Fuzzing statistics
 * @seed:        Random seed
 * @running:     Fuzzer is running
 */
struct tquic_fuzz_state {
	u32 mode;
	u32 targets;
	u32 mutations;
	struct list_head corpus;
	spinlock_t corpus_lock;
	struct tquic_fuzz_stats stats;
	u64 seed;
	bool running;
};

/*
 * =============================================================================
 * Mutation Functions
 * =============================================================================
 */

/**
 * tquic_fuzz_mutate - Apply mutations to input buffer
 * @data: Buffer to mutate
 * @len: Buffer length
 * @max_len: Maximum allowed length
 * @strategies: Enabled mutation strategies
 *
 * Returns: New length after mutation
 */
size_t tquic_fuzz_mutate(u8 *data, size_t len, size_t max_len, u32 strategies);

/**
 * tquic_fuzz_bit_flip - Flip random bits
 * @data: Buffer
 * @len: Length
 * @count: Number of bits to flip
 */
void tquic_fuzz_bit_flip(u8 *data, size_t len, int count);

/**
 * tquic_fuzz_byte_flip - Flip random bytes
 * @data: Buffer
 * @len: Length
 * @count: Number of bytes to flip
 */
void tquic_fuzz_byte_flip(u8 *data, size_t len, int count);

/**
 * tquic_fuzz_arithmetic - Apply arithmetic mutations
 * @data: Buffer
 * @len: Length
 * @width: Width (1, 2, 4, or 8 bytes)
 */
void tquic_fuzz_arithmetic(u8 *data, size_t len, int width);

/**
 * tquic_fuzz_interesting - Replace with interesting values
 * @data: Buffer
 * @len: Length
 */
void tquic_fuzz_interesting(u8 *data, size_t len);

/**
 * tquic_fuzz_havoc - Apply random mutations (havoc mode)
 * @data: Buffer
 * @len: Length
 * @max_len: Maximum allowed length
 *
 * Returns: New length
 */
size_t tquic_fuzz_havoc(u8 *data, size_t len, size_t max_len);

/*
 * =============================================================================
 * Packet Fuzzing
 * =============================================================================
 */

/**
 * tquic_fuzz_packet - Generate fuzzed QUIC packet
 * @buf: Output buffer
 * @size: Buffer size
 * @template: Template packet (NULL for random)
 * @template_len: Template length
 *
 * Returns: Generated packet length
 */
size_t tquic_fuzz_packet(u8 *buf, size_t size,
			 const u8 *template, size_t template_len);

/**
 * tquic_fuzz_initial_packet - Generate fuzzed Initial packet
 * @buf: Output buffer
 * @size: Buffer size
 *
 * Returns: Packet length
 */
size_t tquic_fuzz_initial_packet(u8 *buf, size_t size);

/**
 * tquic_fuzz_handshake_packet - Generate fuzzed Handshake packet
 * @buf: Output buffer
 * @size: Buffer size
 *
 * Returns: Packet length
 */
size_t tquic_fuzz_handshake_packet(u8 *buf, size_t size);

/**
 * tquic_fuzz_short_header_packet - Generate fuzzed 1-RTT packet
 * @buf: Output buffer
 * @size: Buffer size
 *
 * Returns: Packet length
 */
size_t tquic_fuzz_short_header_packet(u8 *buf, size_t size);

/*
 * =============================================================================
 * Frame Fuzzing
 * =============================================================================
 */

/**
 * tquic_fuzz_frame - Generate fuzzed frame
 * @buf: Output buffer
 * @size: Buffer size
 * @frame_type: Frame type (or random if -1)
 *
 * Returns: Frame length
 */
size_t tquic_fuzz_frame(u8 *buf, size_t size, int frame_type);

/**
 * tquic_fuzz_ack_frame - Generate fuzzed ACK frame
 * @buf: Output buffer
 * @size: Buffer size
 *
 * Returns: Frame length
 */
size_t tquic_fuzz_ack_frame(u8 *buf, size_t size);

/**
 * tquic_fuzz_stream_frame - Generate fuzzed STREAM frame
 * @buf: Output buffer
 * @size: Buffer size
 *
 * Returns: Frame length
 */
size_t tquic_fuzz_stream_frame(u8 *buf, size_t size);

/**
 * tquic_fuzz_crypto_frame - Generate fuzzed CRYPTO frame
 * @buf: Output buffer
 * @size: Buffer size
 *
 * Returns: Frame length
 */
size_t tquic_fuzz_crypto_frame(u8 *buf, size_t size);

/*
 * =============================================================================
 * Transport Parameter Fuzzing
 * =============================================================================
 */

/**
 * tquic_fuzz_transport_params - Generate fuzzed transport parameters
 * @buf: Output buffer
 * @size: Buffer size
 *
 * Returns: Parameters length
 */
size_t tquic_fuzz_transport_params(u8 *buf, size_t size);

/*
 * =============================================================================
 * Varint Fuzzing
 * =============================================================================
 */

/**
 * tquic_fuzz_varint - Generate fuzzed QUIC varint
 * @buf: Output buffer
 * @size: Buffer size
 *
 * Returns: Varint encoded length (1, 2, 4, or 8)
 */
size_t tquic_fuzz_varint(u8 *buf, size_t size);

/**
 * tquic_fuzz_varint_invalid - Generate invalid varint
 * @buf: Output buffer
 * @size: Buffer size
 *
 * Returns: Bytes written
 */
size_t tquic_fuzz_varint_invalid(u8 *buf, size_t size);

/*
 * =============================================================================
 * Corpus Management
 * =============================================================================
 */

/**
 * tquic_fuzz_corpus_add - Add input to corpus
 * @state: Fuzzer state
 * @data: Input data
 * @len: Input length
 * @coverage: Coverage hash
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_fuzz_corpus_add(struct tquic_fuzz_state *state,
			  const u8 *data, size_t len, u32 coverage);

/**
 * tquic_fuzz_corpus_get - Get random input from corpus
 * @state: Fuzzer state
 * @buf: Output buffer
 * @size: Buffer size
 *
 * Returns: Input length, 0 if corpus empty
 */
size_t tquic_fuzz_corpus_get(struct tquic_fuzz_state *state,
			     u8 *buf, size_t size);

/**
 * tquic_fuzz_corpus_clear - Clear corpus
 * @state: Fuzzer state
 */
void tquic_fuzz_corpus_clear(struct tquic_fuzz_state *state);

/**
 * tquic_fuzz_corpus_load - Load corpus from storage
 * @state: Fuzzer state
 * @path: Corpus directory path
 *
 * Returns: Number of inputs loaded
 */
int tquic_fuzz_corpus_load(struct tquic_fuzz_state *state, const char *path);

/**
 * tquic_fuzz_corpus_save - Save corpus to storage
 * @state: Fuzzer state
 * @path: Corpus directory path
 *
 * Returns: Number of inputs saved
 */
int tquic_fuzz_corpus_save(struct tquic_fuzz_state *state, const char *path);

/*
 * =============================================================================
 * Execution Harness
 * =============================================================================
 */

/**
 * tquic_fuzz_run_once - Execute single fuzz iteration
 * @state: Fuzzer state
 * @input: Input data
 * @len: Input length
 *
 * Returns: 0 normal, 1 crash, 2 hang, negative errno
 */
int tquic_fuzz_run_once(struct tquic_fuzz_state *state,
			const u8 *input, size_t len);

/**
 * tquic_fuzz_start - Start fuzzing loop
 * @state: Fuzzer state
 * @iterations: Max iterations (0 = infinite)
 *
 * Returns: 0 on success
 */
int tquic_fuzz_start(struct tquic_fuzz_state *state, u64 iterations);

/**
 * tquic_fuzz_stop - Stop fuzzing
 * @state: Fuzzer state
 */
void tquic_fuzz_stop(struct tquic_fuzz_state *state);

/**
 * tquic_fuzz_reset_state - Reset fuzzing state for new run
 * @state: Fuzzer state to reset
 *
 * Cleans up and reinitializes the fuzzing connections.
 */
void tquic_fuzz_reset_state(struct tquic_fuzz_state *state);

/*
 * =============================================================================
 * Module Init/Exit
 * =============================================================================
 */

int tquic_fuzz_init(void);
void tquic_fuzz_exit(void);

/* Global fuzzer state (for debugfs interface) */
extern struct tquic_fuzz_state *tquic_fuzzer;

#endif /* _TQUIC_FUZZ_H */
