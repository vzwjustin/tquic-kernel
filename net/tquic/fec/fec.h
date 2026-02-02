/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC Forward Error Correction (FEC) Header
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Implementation of QUIC FEC extension based on draft-zheng-quic-fec-extension-01.
 * Forward Error Correction allows recovery of lost packets without retransmission,
 * reducing latency in lossy network conditions.
 *
 * Frame Types:
 *   - FEC_REPAIR (0xfc00): Contains repair symbols for packet recovery
 *   - FEC_SOURCE_INFO (0xfc01): Identifies source packets in FEC block
 *
 * FEC Schemes:
 *   - XOR: Simple single-packet recovery, low overhead
 *   - Reed-Solomon GF(2^8): Multiple packet recovery, moderate overhead
 *   - Reed-Solomon GF(2^16): High recovery capability, higher overhead
 */

#ifndef _TQUIC_FEC_H
#define _TQUIC_FEC_H

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/list.h>
#include <linux/ktime.h>

/* Forward declarations */
struct tquic_connection;
struct tquic_path;
struct sk_buff;

/*
 * =============================================================================
 * FEC Frame Types (draft-zheng-quic-fec-extension-01)
 * =============================================================================
 */

/* FEC frame type identifiers (reserved range 0xfc00-0xfcff) */
#define TQUIC_FRAME_FEC_REPAIR		0xfc00
#define TQUIC_FRAME_FEC_SOURCE_INFO	0xfc01

/*
 * =============================================================================
 * FEC Transport Parameters (draft-zheng-quic-fec-extension-01)
 * =============================================================================
 */

/* Transport parameter IDs for FEC negotiation */
#define TQUIC_TP_ENABLE_FEC		0xff0f000ULL	/* Enable FEC support */
#define TQUIC_TP_FEC_SCHEME		0xff0f001ULL	/* FEC scheme to use */
#define TQUIC_TP_MAX_SOURCE_SYMBOLS	0xff0f002ULL	/* Max symbols per block */

/* Default values */
#define TQUIC_FEC_DEFAULT_MAX_SOURCE_SYMBOLS	32
#define TQUIC_FEC_MIN_SOURCE_SYMBOLS		2
#define TQUIC_FEC_MAX_SOURCE_SYMBOLS		255

/* FEC source block size limits */
#define TQUIC_FEC_MIN_BLOCK_SIZE		2
#define TQUIC_FEC_MAX_BLOCK_SIZE		255
#define TQUIC_FEC_DEFAULT_BLOCK_SIZE		16

/* Maximum repair symbols per source block */
#define TQUIC_FEC_MAX_REPAIR_SYMBOLS		16

/* Maximum symbol (packet payload) size */
#define TQUIC_FEC_MAX_SYMBOL_SIZE		1500

/*
 * =============================================================================
 * FEC Schemes
 * =============================================================================
 */

/**
 * enum tquic_fec_scheme - Supported FEC coding schemes
 * @TQUIC_FEC_SCHEME_XOR: Simple XOR parity (single packet recovery)
 * @TQUIC_FEC_SCHEME_REED_SOLOMON_8: Reed-Solomon over GF(2^8)
 * @TQUIC_FEC_SCHEME_REED_SOLOMON_16: Reed-Solomon over GF(2^16)
 *
 * XOR is simple and has low computational overhead but can only recover
 * a single lost packet per source block.
 *
 * Reed-Solomon codes can recover up to N lost packets if N repair symbols
 * are generated, at the cost of higher computational complexity.
 */
enum tquic_fec_scheme {
	TQUIC_FEC_SCHEME_XOR		= 0,
	TQUIC_FEC_SCHEME_REED_SOLOMON_8	= 1,
	TQUIC_FEC_SCHEME_REED_SOLOMON_16 = 2,
	__TQUIC_FEC_SCHEME_MAX
};

/* String names for FEC schemes */
static inline const char *tquic_fec_scheme_name(enum tquic_fec_scheme scheme)
{
	switch (scheme) {
	case TQUIC_FEC_SCHEME_XOR:
		return "XOR";
	case TQUIC_FEC_SCHEME_REED_SOLOMON_8:
		return "RS-8";
	case TQUIC_FEC_SCHEME_REED_SOLOMON_16:
		return "RS-16";
	default:
		return "unknown";
	}
}

/*
 * =============================================================================
 * Source Block Structures
 * =============================================================================
 */

/**
 * struct tquic_fec_symbol - Single source or repair symbol
 * @list: List linkage in source block
 * @pkt_num: Packet number (for source symbols)
 * @symbol_id: Symbol ID within source block
 * @data: Symbol data (packet payload)
 * @length: Symbol length in bytes
 * @received: True if this symbol has been received
 * @is_repair: True if this is a repair symbol
 */
struct tquic_fec_symbol {
	struct list_head list;
	u64 pkt_num;
	u8 symbol_id;
	u8 *data;
	u16 length;
	bool received;
	bool is_repair;
};

/**
 * struct tquic_fec_source_block - Source block for FEC encoding/decoding
 * @block_id: Unique block identifier
 * @source_symbols: List of source symbols (tquic_fec_symbol)
 * @repair_symbols: List of repair symbols (tquic_fec_symbol)
 * @num_source: Number of source symbols
 * @num_repair: Number of repair symbols
 * @num_received: Number of source symbols received
 * @num_repair_received: Number of repair symbols received
 * @max_symbol_size: Maximum symbol size in this block
 * @first_pkt_num: First packet number in this block
 * @last_pkt_num: Last packet number in this block
 * @scheme: FEC scheme used for this block
 * @complete: All source symbols received (no recovery needed)
 * @recovered: Recovery has been attempted
 * @lock: Spinlock for source block access
 * @created: Timestamp when block was created
 * @list: List linkage for source block management
 */
struct tquic_fec_source_block {
	u32 block_id;
	struct list_head source_symbols;
	struct list_head repair_symbols;
	u8 num_source;
	u8 num_repair;
	u8 num_received;
	u8 num_repair_received;
	u16 max_symbol_size;
	u64 first_pkt_num;
	u64 last_pkt_num;
	enum tquic_fec_scheme scheme;
	bool complete;
	bool recovered;
	spinlock_t lock;
	ktime_t created;
	struct list_head list;
};

/*
 * =============================================================================
 * FEC Encoder State
 * =============================================================================
 */

/**
 * struct tquic_fec_encoder - Per-connection FEC encoder state
 * @enabled: FEC encoding is enabled
 * @scheme: FEC scheme in use
 * @block_size: Number of source symbols per block
 * @repair_count: Number of repair symbols to generate
 * @current_block: Current source block being filled
 * @current_block_id: Current block ID
 * @symbols_in_block: Symbols added to current block
 * @pending_blocks: Blocks ready for repair generation
 * @lock: Spinlock for encoder state
 * @stats: Encoding statistics
 */
struct tquic_fec_encoder {
	bool enabled;
	enum tquic_fec_scheme scheme;
	u8 block_size;
	u8 repair_count;
	struct tquic_fec_source_block *current_block;
	u32 current_block_id;
	u8 symbols_in_block;
	struct list_head pending_blocks;
	spinlock_t lock;

	/* Statistics */
	struct {
		u64 blocks_created;
		u64 symbols_encoded;
		u64 repair_symbols_sent;
		u64 bytes_overhead;
	} stats;
};

/*
 * =============================================================================
 * FEC Decoder State
 * =============================================================================
 */

/**
 * struct tquic_fec_decoder - Per-connection FEC decoder state
 * @enabled: FEC decoding is enabled
 * @scheme: FEC scheme in use
 * @active_blocks: List of source blocks being decoded
 * @num_active_blocks: Number of active blocks
 * @max_active_blocks: Maximum simultaneous blocks
 * @lock: Spinlock for decoder state
 * @stats: Decoding statistics
 */
struct tquic_fec_decoder {
	bool enabled;
	enum tquic_fec_scheme scheme;
	struct list_head active_blocks;
	u32 num_active_blocks;
	u32 max_active_blocks;
	spinlock_t lock;

	/* Statistics */
	struct {
		u64 blocks_received;
		u64 symbols_received;
		u64 repair_symbols_received;
		u64 recovery_attempts;
		u64 recovery_success;
		u64 recovery_failed;
		u64 packets_recovered;
	} stats;
};

/*
 * =============================================================================
 * FEC Scheduler State
 * =============================================================================
 */

/**
 * struct tquic_fec_scheduler - FEC repair symbol scheduling state
 * @target_fec_rate: Target ratio of repair symbols (percent)
 * @min_fec_rate: Minimum FEC rate
 * @max_fec_rate: Maximum FEC rate
 * @adaptive: Use adaptive FEC rate based on loss
 * @loss_window: Window for loss rate calculation (packets)
 * @loss_count: Recent loss count
 * @packet_count: Recent packet count
 * @current_loss_rate: Current calculated loss rate (permille)
 * @last_adjustment: Last rate adjustment time
 * @lock: Spinlock for scheduler state
 */
struct tquic_fec_scheduler {
	u8 target_fec_rate;
	u8 min_fec_rate;
	u8 max_fec_rate;
	bool adaptive;
	u32 loss_window;
	u32 loss_count;
	u32 packet_count;
	u32 current_loss_rate;
	ktime_t last_adjustment;
	spinlock_t lock;
};

/*
 * =============================================================================
 * Per-Connection FEC State
 * =============================================================================
 */

/**
 * struct tquic_fec_state - Complete FEC state for a connection
 * @encoder: Encoder state
 * @decoder: Decoder state
 * @scheduler: Scheduling state
 * @enabled: FEC is negotiated and enabled
 * @scheme: Negotiated FEC scheme
 * @max_source_symbols: Negotiated max source symbols
 * @peer_enabled: Peer supports FEC
 * @peer_scheme: Peer's preferred FEC scheme
 * @peer_max_source_symbols: Peer's max source symbols
 */
struct tquic_fec_state {
	struct tquic_fec_encoder encoder;
	struct tquic_fec_decoder decoder;
	struct tquic_fec_scheduler scheduler;

	bool enabled;
	enum tquic_fec_scheme scheme;
	u8 max_source_symbols;

	bool peer_enabled;
	enum tquic_fec_scheme peer_scheme;
	u8 peer_max_source_symbols;
};

/*
 * =============================================================================
 * FEC Frame Structures
 * =============================================================================
 */

/**
 * struct tquic_fec_repair_frame - FEC_REPAIR frame structure
 * @block_id: Source block identifier
 * @repair_symbol_id: Repair symbol index within block
 * @source_block_length: Number of source symbols in block
 * @encoding_symbol_id: Starting symbol ID for encoding
 * @repair_fec_payload_id: FEC payload identifier
 * @scheme: FEC scheme used
 * @repair_data: Repair symbol data
 * @repair_length: Length of repair data
 */
struct tquic_fec_repair_frame {
	u32 block_id;
	u8 repair_symbol_id;
	u8 source_block_length;
	u8 encoding_symbol_id;
	u32 repair_fec_payload_id;
	enum tquic_fec_scheme scheme;
	u8 *repair_data;
	u16 repair_length;
};

/**
 * struct tquic_fec_source_info_frame - FEC_SOURCE_INFO frame structure
 * @block_id: Source block identifier
 * @first_source_symbol_id: First source symbol in this packet
 * @num_source_symbols: Number of source symbols in this packet
 */
struct tquic_fec_source_info_frame {
	u32 block_id;
	u8 first_source_symbol_id;
	u8 num_source_symbols;
};

/*
 * =============================================================================
 * FEC Transport Parameters Structure
 * =============================================================================
 */

/**
 * struct tquic_fec_params - FEC transport parameters
 * @enable_fec: FEC is supported and enabled
 * @fec_scheme: Preferred FEC scheme
 * @max_source_symbols: Maximum source symbols per block
 */
struct tquic_fec_params {
	bool enable_fec;
	enum tquic_fec_scheme fec_scheme;
	u8 max_source_symbols;
};

/*
 * =============================================================================
 * FEC Encoder API (fec_encoder.c)
 * =============================================================================
 */

/**
 * tquic_fec_encoder_init - Initialize FEC encoder
 * @state: FEC state structure
 * @scheme: FEC scheme to use
 * @block_size: Source symbols per block
 * @repair_count: Repair symbols to generate
 *
 * Return: 0 on success, negative error on failure
 */
int tquic_fec_encoder_init(struct tquic_fec_state *state,
			   enum tquic_fec_scheme scheme,
			   u8 block_size, u8 repair_count);

/**
 * tquic_fec_encoder_destroy - Clean up FEC encoder
 * @state: FEC state structure
 */
void tquic_fec_encoder_destroy(struct tquic_fec_state *state);

/**
 * tquic_fec_add_source_symbol - Add packet to current source block
 * @state: FEC state
 * @pkt_num: Packet number
 * @data: Packet payload data
 * @length: Payload length
 *
 * Adds a packet as a source symbol to the current FEC block.
 * When the block is complete, repair symbols can be generated.
 *
 * Return: 0 on success, 1 if block is complete, negative error on failure
 */
int tquic_fec_add_source_symbol(struct tquic_fec_state *state,
				u64 pkt_num, const u8 *data, u16 length);

/**
 * tquic_fec_generate_repair - Generate repair symbols for current block
 * @state: FEC state
 * @block: Source block (or NULL for current)
 *
 * Generates repair symbols using the configured FEC scheme.
 * Called when a source block is complete.
 *
 * Return: Number of repair symbols generated, or negative error
 */
int tquic_fec_generate_repair(struct tquic_fec_state *state,
			      struct tquic_fec_source_block *block);

/**
 * tquic_fec_encode_repair_frame - Encode FEC_REPAIR frame to buffer
 * @state: FEC state
 * @block: Source block
 * @repair_id: Repair symbol index
 * @buf: Output buffer
 * @buflen: Buffer length
 *
 * Encodes a repair symbol as an FEC_REPAIR frame.
 *
 * Return: Bytes written, or negative error
 */
ssize_t tquic_fec_encode_repair_frame(struct tquic_fec_state *state,
				      struct tquic_fec_source_block *block,
				      u8 repair_id, u8 *buf, size_t buflen);

/**
 * tquic_fec_encode_source_info_frame - Encode FEC_SOURCE_INFO frame
 * @block_id: Source block ID
 * @symbol_id: First symbol ID
 * @num_symbols: Number of symbols
 * @buf: Output buffer
 * @buflen: Buffer length
 *
 * Return: Bytes written, or negative error
 */
ssize_t tquic_fec_encode_source_info_frame(u32 block_id, u8 symbol_id,
					   u8 num_symbols,
					   u8 *buf, size_t buflen);

/**
 * tquic_fec_get_pending_repair - Get next pending repair frame
 * @state: FEC state
 * @frame: Output frame structure
 *
 * Return: true if a repair frame is available, false otherwise
 */
bool tquic_fec_get_pending_repair(struct tquic_fec_state *state,
				  struct tquic_fec_repair_frame *frame);

/*
 * =============================================================================
 * FEC Decoder API (fec_decoder.c)
 * =============================================================================
 */

/**
 * tquic_fec_decoder_init - Initialize FEC decoder
 * @state: FEC state structure
 * @scheme: FEC scheme to use
 * @max_blocks: Maximum concurrent source blocks
 *
 * Return: 0 on success, negative error on failure
 */
int tquic_fec_decoder_init(struct tquic_fec_state *state,
			   enum tquic_fec_scheme scheme,
			   u32 max_blocks);

/**
 * tquic_fec_decoder_destroy - Clean up FEC decoder
 * @state: FEC state structure
 */
void tquic_fec_decoder_destroy(struct tquic_fec_state *state);

/**
 * tquic_fec_receive_source - Record received source packet
 * @state: FEC state
 * @block_id: Source block ID
 * @symbol_id: Symbol ID within block
 * @pkt_num: Packet number
 * @data: Packet payload
 * @length: Payload length
 *
 * Records a received source packet for potential FEC recovery.
 *
 * Return: 0 on success, negative error on failure
 */
int tquic_fec_receive_source(struct tquic_fec_state *state,
			     u32 block_id, u8 symbol_id, u64 pkt_num,
			     const u8 *data, u16 length);

/**
 * tquic_fec_receive_repair - Process received repair symbol
 * @state: FEC state
 * @frame: Decoded FEC_REPAIR frame
 *
 * Processes a received repair symbol and attempts recovery if possible.
 *
 * Return: Number of packets recovered, or negative error
 */
int tquic_fec_receive_repair(struct tquic_fec_state *state,
			     const struct tquic_fec_repair_frame *frame);

/**
 * tquic_fec_recover - Attempt packet recovery for a source block
 * @state: FEC state
 * @block: Source block to recover
 * @recovered: Output array for recovered packets (may be NULL)
 * @max_recovered: Maximum packets to recover
 *
 * Attempts to recover lost packets using available repair symbols.
 *
 * Return: Number of packets recovered, or negative error
 */
int tquic_fec_recover(struct tquic_fec_state *state,
		      struct tquic_fec_source_block *block,
		      struct sk_buff **recovered, int max_recovered);

/**
 * tquic_fec_decode_repair_frame - Decode FEC_REPAIR frame
 * @buf: Input buffer
 * @buflen: Buffer length
 * @frame: Output frame structure
 *
 * Return: Bytes consumed, or negative error
 */
ssize_t tquic_fec_decode_repair_frame(const u8 *buf, size_t buflen,
				      struct tquic_fec_repair_frame *frame);

/**
 * tquic_fec_decode_source_info_frame - Decode FEC_SOURCE_INFO frame
 * @buf: Input buffer
 * @buflen: Buffer length
 * @frame: Output frame structure
 *
 * Return: Bytes consumed, or negative error
 */
ssize_t tquic_fec_decode_source_info_frame(const u8 *buf, size_t buflen,
					   struct tquic_fec_source_info_frame *frame);

/**
 * tquic_fec_find_block - Find source block by ID
 * @state: FEC state
 * @block_id: Block ID to find
 *
 * Return: Source block or NULL if not found
 */
struct tquic_fec_source_block *tquic_fec_find_block(struct tquic_fec_state *state,
						    u32 block_id);

/**
 * tquic_fec_cleanup_old_blocks - Remove expired source blocks
 * @state: FEC state
 * @max_age_ms: Maximum block age in milliseconds
 */
void tquic_fec_cleanup_old_blocks(struct tquic_fec_state *state, u32 max_age_ms);

/*
 * =============================================================================
 * XOR FEC Scheme API (xor_fec.c)
 * =============================================================================
 */

/**
 * tquic_xor_encode - Generate XOR parity symbol
 * @symbols: Array of source symbol pointers
 * @lengths: Array of symbol lengths
 * @num_symbols: Number of source symbols
 * @repair: Output buffer for repair symbol
 * @repair_len: Output repair symbol length
 *
 * XOR all source symbols together to produce a single repair symbol.
 * Can recover exactly one lost packet per source block.
 *
 * Return: 0 on success, negative error on failure
 */
int tquic_xor_encode(const u8 **symbols, const u16 *lengths,
		     u8 num_symbols, u8 *repair, u16 *repair_len);

/**
 * tquic_xor_decode - Recover lost packet using XOR
 * @symbols: Array of source symbol pointers (NULL for lost)
 * @lengths: Array of symbol lengths
 * @num_symbols: Number of source symbols
 * @repair: Repair symbol
 * @repair_len: Repair symbol length
 * @recovered: Output buffer for recovered packet
 * @recovered_len: Output recovered packet length
 *
 * XOR all received symbols with repair symbol to recover the lost packet.
 * Only works when exactly one symbol is missing.
 *
 * Return: 0 on success, negative error on failure
 */
int tquic_xor_decode(const u8 **symbols, const u16 *lengths,
		     u8 num_symbols, const u8 *repair, u16 repair_len,
		     u8 *recovered, u16 *recovered_len);

/*
 * =============================================================================
 * Reed-Solomon FEC Scheme API (reed_solomon.c)
 * =============================================================================
 */

/**
 * tquic_rs_encode - Generate Reed-Solomon repair symbols
 * @symbols: Array of source symbol pointers
 * @lengths: Array of symbol lengths
 * @num_source: Number of source symbols
 * @num_repair: Number of repair symbols to generate
 * @repair: Array of output repair symbol buffers
 * @repair_lens: Array of output repair symbol lengths
 * @gf_bits: Galois field size (8 or 16)
 *
 * Generate Reed-Solomon parity symbols that can recover multiple losses.
 *
 * Return: 0 on success, negative error on failure
 */
int tquic_rs_encode(const u8 **symbols, const u16 *lengths,
		    u8 num_source, u8 num_repair,
		    u8 **repair, u16 *repair_lens, int gf_bits);

/**
 * tquic_rs_decode - Recover lost packets using Reed-Solomon
 * @symbols: Array of source symbol pointers (NULL for lost)
 * @lengths: Array of symbol lengths
 * @num_source: Number of source symbols
 * @repair: Array of repair symbols
 * @repair_lens: Array of repair symbol lengths
 * @num_repair: Number of repair symbols available
 * @erasure_pos: Positions of erased symbols
 * @num_erasures: Number of erasures
 * @recovered: Output array for recovered data
 * @recovered_lens: Output array for recovered lengths
 * @gf_bits: Galois field size (8 or 16)
 *
 * Use Berlekamp-Massey algorithm to decode and recover lost packets.
 *
 * Return: Number of packets recovered, or negative error
 */
int tquic_rs_decode(const u8 **symbols, const u16 *lengths,
		    u8 num_source, const u8 **repair, const u16 *repair_lens,
		    u8 num_repair, const u8 *erasure_pos, u8 num_erasures,
		    u8 **recovered, u16 *recovered_lens, int gf_bits);

/**
 * tquic_rs_init - Initialize Reed-Solomon tables
 *
 * Must be called before using RS encoding/decoding.
 *
 * Return: 0 on success, negative error on failure
 */
int tquic_rs_init(void);

/**
 * tquic_rs_exit - Clean up Reed-Solomon tables
 */
void tquic_rs_exit(void);

/*
 * =============================================================================
 * FEC Scheduler API (fec_scheduler.c)
 * =============================================================================
 */

/**
 * tquic_fec_scheduler_init - Initialize FEC scheduler
 * @state: FEC state
 * @initial_rate: Initial FEC rate (percent)
 * @adaptive: Enable adaptive rate adjustment
 *
 * Return: 0 on success, negative error on failure
 */
int tquic_fec_scheduler_init(struct tquic_fec_state *state,
			     u8 initial_rate, bool adaptive);

/**
 * tquic_fec_scheduler_destroy - Clean up FEC scheduler
 * @state: FEC state
 */
void tquic_fec_scheduler_destroy(struct tquic_fec_state *state);

/**
 * tquic_fec_should_send_repair - Decide if repair symbol should be sent
 * @state: FEC state
 * @pkt_num: Current packet number
 *
 * Decision logic for when to send repair symbols based on block
 * completion, loss rate, and FEC rate target.
 *
 * Return: true if repair should be sent
 */
bool tquic_fec_should_send_repair(struct tquic_fec_state *state, u64 pkt_num);

/**
 * tquic_fec_report_loss - Report packet loss to scheduler
 * @state: FEC state
 * @pkt_num: Lost packet number
 *
 * Updates loss statistics for adaptive FEC rate adjustment.
 */
void tquic_fec_report_loss(struct tquic_fec_state *state, u64 pkt_num);

/**
 * tquic_fec_report_ack - Report packet acknowledgment to scheduler
 * @state: FEC state
 * @pkt_num: Acknowledged packet number
 *
 * Updates delivery statistics for adaptive FEC rate adjustment.
 */
void tquic_fec_report_ack(struct tquic_fec_state *state, u64 pkt_num);

/**
 * tquic_fec_adjust_rate - Adjust FEC rate based on loss statistics
 * @state: FEC state
 *
 * Called periodically to adjust FEC rate based on observed loss.
 */
void tquic_fec_adjust_rate(struct tquic_fec_state *state);

/**
 * tquic_fec_get_current_rate - Get current FEC rate
 * @state: FEC state
 *
 * Return: Current FEC rate (percent)
 */
u8 tquic_fec_get_current_rate(struct tquic_fec_state *state);

/*
 * =============================================================================
 * FEC State Management API
 * =============================================================================
 */

/**
 * tquic_fec_init - Initialize complete FEC state
 * @state: FEC state to initialize
 *
 * Return: 0 on success, negative error on failure
 */
int tquic_fec_init(struct tquic_fec_state *state);

/**
 * tquic_fec_destroy - Destroy FEC state
 * @state: FEC state to destroy
 */
void tquic_fec_destroy(struct tquic_fec_state *state);

/**
 * tquic_fec_negotiate - Negotiate FEC parameters with peer
 * @state: FEC state
 * @local: Local FEC parameters
 * @peer: Peer's FEC parameters
 *
 * Return: 0 on success, negative error on failure
 */
int tquic_fec_negotiate(struct tquic_fec_state *state,
			const struct tquic_fec_params *local,
			const struct tquic_fec_params *peer);

/**
 * tquic_fec_enable - Enable FEC for connection
 * @state: FEC state
 * @scheme: FEC scheme to use
 * @block_size: Source block size
 *
 * Return: 0 on success, negative error on failure
 */
int tquic_fec_enable(struct tquic_fec_state *state,
		     enum tquic_fec_scheme scheme, u8 block_size);

/**
 * tquic_fec_disable - Disable FEC for connection
 * @state: FEC state
 */
void tquic_fec_disable(struct tquic_fec_state *state);

/*
 * =============================================================================
 * FEC Statistics
 * =============================================================================
 */

/**
 * struct tquic_fec_stats - FEC statistics
 * @blocks_encoded: Number of source blocks encoded
 * @symbols_encoded: Number of source symbols encoded
 * @repair_sent: Number of repair symbols sent
 * @blocks_received: Number of source blocks received
 * @symbols_received: Number of source symbols received
 * @repair_received: Number of repair symbols received
 * @recovery_attempts: Number of recovery attempts
 * @recovery_success: Number of successful recoveries
 * @recovery_failed: Number of failed recoveries
 * @packets_recovered: Total packets recovered
 * @current_fec_rate: Current FEC rate (percent)
 * @current_loss_rate: Current loss rate (permille)
 */
struct tquic_fec_stats {
	u64 blocks_encoded;
	u64 symbols_encoded;
	u64 repair_sent;
	u64 blocks_received;
	u64 symbols_received;
	u64 repair_received;
	u64 recovery_attempts;
	u64 recovery_success;
	u64 recovery_failed;
	u64 packets_recovered;
	u8 current_fec_rate;
	u32 current_loss_rate;
};

/**
 * tquic_fec_get_stats - Get FEC statistics
 * @state: FEC state
 * @stats: Output statistics structure
 */
void tquic_fec_get_stats(struct tquic_fec_state *state,
			 struct tquic_fec_stats *stats);

/*
 * =============================================================================
 * FEC Scheduler Additional API
 * =============================================================================
 */

/**
 * tquic_fec_set_rate_bounds - Set FEC rate bounds
 * @state: FEC state
 * @min_rate: Minimum FEC rate (percent)
 * @max_rate: Maximum FEC rate (percent)
 *
 * Return: 0 on success, negative error on failure
 */
int tquic_fec_set_rate_bounds(struct tquic_fec_state *state,
			      u8 min_rate, u8 max_rate);

/**
 * tquic_fec_get_loss_rate - Get current estimated loss rate
 * @state: FEC state
 *
 * Return: Current loss rate in permille (parts per thousand)
 */
u32 tquic_fec_get_loss_rate(struct tquic_fec_state *state);

/**
 * tquic_fec_scheduler_reset - Reset scheduler statistics
 * @state: FEC state
 */
void tquic_fec_scheduler_reset(struct tquic_fec_state *state);

/**
 * tquic_fec_compute_repair_count - Compute number of repair symbols
 * @state: FEC state
 * @block_size: Number of source symbols in block
 *
 * Return: Recommended number of repair symbols
 */
u8 tquic_fec_compute_repair_count(struct tquic_fec_state *state, u8 block_size);

/*
 * =============================================================================
 * FEC Module Init/Exit
 * =============================================================================
 */

/**
 * tquic_fec_module_init - Initialize FEC subsystem
 *
 * Return: 0 on success, negative error on failure
 */
int __init tquic_fec_module_init(void);

/**
 * tquic_fec_module_exit - Clean up FEC subsystem
 */
void __exit tquic_fec_module_exit(void);

#endif /* _TQUIC_FEC_H */
