// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC FEC Decoder
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Implementation of FEC decoding for QUIC based on draft-zheng-quic-fec-extension-01.
 * Handles receipt of source and repair symbols and packet recovery.
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/skbuff.h>

#include "fec.h"

/*
 * =============================================================================
 * Source Block Management
 * =============================================================================
 */

/**
 * decoder_alloc_block - Allocate a new source block for decoding
 * @block_id: Block identifier
 * @num_source: Expected number of source symbols
 * @scheme: FEC scheme
 *
 * Return: Allocated source block or NULL on failure
 */
static struct tquic_fec_source_block *decoder_alloc_block(u32 block_id,
							  u8 num_source,
							  enum tquic_fec_scheme scheme)
{
	struct tquic_fec_source_block *block;

	block = kzalloc(sizeof(*block), GFP_ATOMIC);
	if (!block)
		return NULL;

	block->block_id = block_id;
	block->num_source = num_source;
	block->scheme = scheme;
	block->created = ktime_get();

	INIT_LIST_HEAD(&block->source_symbols);
	INIT_LIST_HEAD(&block->repair_symbols);
	INIT_LIST_HEAD(&block->list);
	spin_lock_init(&block->lock);

	return block;
}

/**
 * decoder_free_symbol - Free a single FEC symbol
 * @symbol: Symbol to free
 */
static void decoder_free_symbol(struct tquic_fec_symbol *symbol)
{
	if (!symbol)
		return;

	kfree(symbol->data);
	kfree(symbol);
}

/**
 * decoder_free_block - Free a source block and all its symbols
 * @block: Block to free
 */
static void decoder_free_block(struct tquic_fec_source_block *block)
{
	struct tquic_fec_symbol *symbol, *tmp;

	if (!block)
		return;

	list_for_each_entry_safe(symbol, tmp, &block->source_symbols, list) {
		list_del(&symbol->list);
		decoder_free_symbol(symbol);
	}

	list_for_each_entry_safe(symbol, tmp, &block->repair_symbols, list) {
		list_del(&symbol->list);
		decoder_free_symbol(symbol);
	}

	kfree(block);
}

/**
 * decoder_alloc_symbol - Allocate a new FEC symbol
 * @pkt_num: Packet number
 * @symbol_id: Symbol ID
 * @data: Symbol data
 * @length: Data length
 * @is_repair: True for repair symbol
 *
 * Return: Allocated symbol or NULL on failure
 */
static struct tquic_fec_symbol *decoder_alloc_symbol(u64 pkt_num, u8 symbol_id,
						     const u8 *data, u16 length,
						     bool is_repair)
{
	struct tquic_fec_symbol *symbol;

	symbol = kzalloc(sizeof(*symbol), GFP_ATOMIC);
	if (!symbol)
		return NULL;

	symbol->data = kmalloc(length, GFP_ATOMIC);
	if (!symbol->data) {
		kfree(symbol);
		return NULL;
	}

	memcpy(symbol->data, data, length);
	symbol->pkt_num = pkt_num;
	symbol->symbol_id = symbol_id;
	symbol->length = length;
	symbol->received = true;
	symbol->is_repair = is_repair;
	INIT_LIST_HEAD(&symbol->list);

	return symbol;
}

/*
 * =============================================================================
 * FEC Decoder Implementation
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
			   u32 max_blocks)
{
	struct tquic_fec_decoder *dec;

	if (!state)
		return -EINVAL;

	if (scheme >= __TQUIC_FEC_SCHEME_MAX)
		return -EINVAL;

	dec = &state->decoder;

	spin_lock_init(&dec->lock);
	INIT_LIST_HEAD(&dec->active_blocks);

	dec->scheme = scheme;
	dec->num_active_blocks = 0;
	dec->max_active_blocks = max_blocks ? max_blocks : 16;
	dec->enabled = true;

	/* Reset statistics */
	memset(&dec->stats, 0, sizeof(dec->stats));

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_fec_decoder_init);

/**
 * tquic_fec_decoder_destroy - Clean up FEC decoder
 * @state: FEC state structure
 */
void tquic_fec_decoder_destroy(struct tquic_fec_state *state)
{
	struct tquic_fec_decoder *dec;
	struct tquic_fec_source_block *block, *tmp;

	if (!state)
		return;

	dec = &state->decoder;

	spin_lock_bh(&dec->lock);

	list_for_each_entry_safe(block, tmp, &dec->active_blocks, list) {
		list_del(&block->list);
		decoder_free_block(block);
	}

	dec->num_active_blocks = 0;
	dec->enabled = false;

	spin_unlock_bh(&dec->lock);
}
EXPORT_SYMBOL_GPL(tquic_fec_decoder_destroy);

/**
 * tquic_fec_find_block - Find source block by ID
 * @state: FEC state
 * @block_id: Block ID to find
 *
 * Return: Source block or NULL if not found
 */
struct tquic_fec_source_block *tquic_fec_find_block(struct tquic_fec_state *state,
						    u32 block_id)
{
	struct tquic_fec_decoder *dec;
	struct tquic_fec_source_block *block;

	if (!state)
		return NULL;

	dec = &state->decoder;

	list_for_each_entry(block, &dec->active_blocks, list) {
		if (block->block_id == block_id)
			return block;
	}

	return NULL;
}
EXPORT_SYMBOL_GPL(tquic_fec_find_block);

/**
 * tquic_fec_receive_source - Record received source packet
 * @state: FEC state
 * @block_id: Source block ID
 * @symbol_id: Symbol ID within block
 * @pkt_num: Packet number
 * @data: Packet payload
 * @length: Payload length
 *
 * Return: 0 on success, negative error on failure
 */
int tquic_fec_receive_source(struct tquic_fec_state *state,
			     u32 block_id, u8 symbol_id, u64 pkt_num,
			     const u8 *data, u16 length)
{
	struct tquic_fec_decoder *dec;
	struct tquic_fec_source_block *block;
	struct tquic_fec_symbol *symbol;
	bool found = false;
	int ret = 0;

	if (!state || !data || length == 0)
		return -EINVAL;

	dec = &state->decoder;

	spin_lock_bh(&dec->lock);

	if (!dec->enabled) {
		ret = -ENODEV;
		goto out;
	}

	/* Find or create block */
	block = tquic_fec_find_block(state, block_id);
	if (!block) {
		/* Create new block - we don't know num_source yet */
		if (dec->num_active_blocks >= dec->max_active_blocks) {
			ret = -ENOSPC;
			goto out;
		}

		block = decoder_alloc_block(block_id, 0, dec->scheme);
		if (!block) {
			ret = -ENOMEM;
			goto out;
		}

		list_add_tail(&block->list, &dec->active_blocks);
		dec->num_active_blocks++;
		dec->stats.blocks_received++;
	}

	spin_lock(&block->lock);

	/* Check for duplicate */
	list_for_each_entry(symbol, &block->source_symbols, list) {
		if (symbol->symbol_id == symbol_id) {
			found = true;
			break;
		}
	}

	if (!found) {
		/* Add new symbol */
		symbol = decoder_alloc_symbol(pkt_num, symbol_id, data, length, false);
		if (!symbol) {
			spin_unlock(&block->lock);
			ret = -ENOMEM;
			goto out;
		}

		list_add_tail(&symbol->list, &block->source_symbols);
		block->num_received++;

		if (length > block->max_symbol_size)
			block->max_symbol_size = length;

		if (block->first_pkt_num == 0)
			block->first_pkt_num = pkt_num;
		block->last_pkt_num = pkt_num;

		dec->stats.symbols_received++;

		/* Check if block is complete */
		if (block->num_source > 0 &&
		    block->num_received >= block->num_source) {
			block->complete = true;
		}
	}

	spin_unlock(&block->lock);

out:
	spin_unlock_bh(&dec->lock);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_fec_receive_source);

/**
 * attempt_xor_recovery - Try to recover lost packet using XOR
 * @block: Source block with loss
 *
 * Return: Number of packets recovered (0 or 1), or negative error
 */
static int attempt_xor_recovery(struct tquic_fec_source_block *block)
{
	struct tquic_fec_symbol *symbol, *repair = NULL;
	/*
	 * SECURITY FIX (CF-097): Move large arrays from stack to heap.
	 * Combined stack usage of symbols[] + lengths[] + recovered_data[]
	 * exceeded safe kernel stack limits (~4KB on some architectures).
	 */
	const u8 **symbols;
	u16 *lengths;
	u8 *recovered_data;
	u16 recovered_len = 0;
	int missing_idx = -1;
	int idx = 0;
	int i, ret;

	/* We need exactly one repair symbol for XOR */
	list_for_each_entry(symbol, &block->repair_symbols, list) {
		if (symbol->is_repair && symbol->received) {
			repair = symbol;
			break;
		}
	}

	if (!repair)
		return 0;  /* No repair symbol available */

	/* Allocate working arrays on the heap */
	symbols = kcalloc(block->num_source, sizeof(*symbols), GFP_ATOMIC);
	if (!symbols)
		return -ENOMEM;

	lengths = kcalloc(block->num_source, sizeof(*lengths), GFP_ATOMIC);
	if (!lengths) {
		kfree(symbols);
		return -ENOMEM;
	}

	recovered_data = kmalloc(TQUIC_FEC_MAX_SYMBOL_SIZE, GFP_ATOMIC);
	if (!recovered_data) {
		kfree(lengths);
		kfree(symbols);
		return -ENOMEM;
	}

	list_for_each_entry(symbol, &block->source_symbols, list) {
		if (symbol->symbol_id < block->num_source) {
			symbols[symbol->symbol_id] = symbol->data;
			lengths[symbol->symbol_id] = symbol->length;
		}
	}

	/* Count missing */
	for (i = 0; i < block->num_source; i++) {
		if (!symbols[i]) {
			if (missing_idx >= 0) {
				ret = 0;  /* More than one missing - XOR can't help */
				goto out_free;
			}
			missing_idx = i;
		}
	}

	if (missing_idx < 0) {
		ret = 0;  /* Nothing missing */
		goto out_free;
	}

	/* Perform XOR recovery */
	ret = tquic_xor_decode(symbols, lengths, block->num_source,
			       repair->data, repair->length,
			       recovered_data, &recovered_len);
	if (ret < 0)
		goto out_free;

	/* Create recovered symbol */
	symbol = decoder_alloc_symbol(0, missing_idx, recovered_data,
				      recovered_len, false);
	if (!symbol) {
		ret = -ENOMEM;
		goto out_free;
	}

	list_add_tail(&symbol->list, &block->source_symbols);
	block->num_received++;
	block->recovered = true;
	ret = 1;

out_free:
	kfree(recovered_data);
	kfree(lengths);
	kfree(symbols);
	return ret;
}

/**
 * attempt_rs_recovery - Try to recover lost packets using Reed-Solomon
 * @block: Source block with losses
 * @gf_bits: Galois field size (8 or 16)
 *
 * Return: Number of packets recovered, or negative error
 */
static int attempt_rs_recovery(struct tquic_fec_source_block *block, int gf_bits)
{
	struct tquic_fec_symbol *symbol;
	/*
	 * SECURITY FIX (CF-097): Move large arrays from stack to heap.
	 * Seven arrays totaling ~5.5KB exceeded safe kernel stack limits.
	 * Use a single allocation for all arrays to reduce overhead.
	 */
	const u8 **symbols;
	u16 *lengths;
	const u8 **repair_syms;
	u16 *repair_lens;
	u8 *erasure_pos;
	u8 **recovered;
	u16 *recovered_lens;
	void *work_buf;
	size_t alloc_size;
	int num_repair = 0;
	int num_erasures = 0;
	int i, ret;
	int recovered_count = 0;

	/*
	 * Single allocation for all working arrays:
	 *   symbols[num_source]       - const u8 * pointers
	 *   lengths[num_source]       - u16
	 *   repair_syms[MAX_REPAIR]   - const u8 * pointers
	 *   repair_lens[MAX_REPAIR]   - u16
	 *   erasure_pos[num_source]   - u8
	 *   recovered[num_source]     - u8 * pointers
	 *   recovered_lens[num_source]- u16
	 */
	alloc_size = block->num_source * sizeof(const u8 *) +
		     block->num_source * sizeof(u16) +
		     TQUIC_FEC_MAX_REPAIR_SYMBOLS * sizeof(const u8 *) +
		     TQUIC_FEC_MAX_REPAIR_SYMBOLS * sizeof(u16) +
		     block->num_source * sizeof(u8) +
		     block->num_source * sizeof(u8 *) +
		     block->num_source * sizeof(u16);

	work_buf = kzalloc(alloc_size, GFP_ATOMIC);
	if (!work_buf)
		return -ENOMEM;

	/* Partition the allocation into individual arrays */
	symbols = work_buf;
	lengths = (u16 *)&symbols[block->num_source];
	repair_syms = (const u8 **)&lengths[block->num_source];
	repair_lens = (u16 *)&repair_syms[TQUIC_FEC_MAX_REPAIR_SYMBOLS];
	erasure_pos = (u8 *)&repair_lens[TQUIC_FEC_MAX_REPAIR_SYMBOLS];
	recovered = (u8 **)&erasure_pos[block->num_source];
	recovered_lens = (u16 *)&recovered[block->num_source];

	/* Collect received source symbols */
	list_for_each_entry(symbol, &block->source_symbols, list) {
		if (symbol->symbol_id < block->num_source) {
			symbols[symbol->symbol_id] = symbol->data;
			lengths[symbol->symbol_id] = symbol->length;
		}
	}

	/* Find erasures */
	for (i = 0; i < block->num_source; i++) {
		if (!symbols[i]) {
			erasure_pos[num_erasures++] = i;
		}
	}

	if (num_erasures == 0) {
		kfree(work_buf);
		return 0;  /* Nothing to recover */
	}

	/* Collect repair symbols */
	list_for_each_entry(symbol, &block->repair_symbols, list) {
		if (symbol->is_repair && symbol->received &&
		    num_repair < TQUIC_FEC_MAX_REPAIR_SYMBOLS) {
			repair_syms[num_repair] = symbol->data;
			repair_lens[num_repair] = symbol->length;
			num_repair++;
		}
	}

	/* Need at least as many repair symbols as erasures */
	if (num_repair < num_erasures) {
		kfree(work_buf);
		return 0;  /* Not enough repair symbols */
	}

	/* Allocate recovery buffers */
	for (i = 0; i < num_erasures; i++) {
		recovered[i] = kmalloc(block->max_symbol_size, GFP_ATOMIC);
		if (!recovered[i]) {
			while (--i >= 0)
				kfree(recovered[i]);
			kfree(work_buf);
			return -ENOMEM;
		}
	}

	/* Perform RS decoding */
	ret = tquic_rs_decode(symbols, lengths, block->num_source,
			      repair_syms, repair_lens, num_repair,
			      erasure_pos, num_erasures,
			      recovered, recovered_lens, gf_bits);
	if (ret < 0) {
		for (i = 0; i < num_erasures; i++)
			kfree(recovered[i]);
		kfree(work_buf);
		return ret;
	}

	/* Create recovered symbols */
	for (i = 0; i < num_erasures; i++) {
		symbol = kzalloc(sizeof(*symbol), GFP_ATOMIC);
		if (!symbol) {
			kfree(recovered[i]);
			continue;
		}

		symbol->data = recovered[i];
		symbol->length = recovered_lens[i];
		symbol->symbol_id = erasure_pos[i];
		symbol->received = true;
		symbol->is_repair = false;
		INIT_LIST_HEAD(&symbol->list);

		list_add_tail(&symbol->list, &block->source_symbols);
		block->num_received++;
		recovered_count++;
	}

	if (recovered_count > 0)
		block->recovered = true;

	kfree(work_buf);
	return recovered_count;
}

/**
 * tquic_fec_receive_repair - Process received repair symbol
 * @state: FEC state
 * @frame: Decoded FEC_REPAIR frame
 *
 * Return: Number of packets recovered, or negative error
 */
int tquic_fec_receive_repair(struct tquic_fec_state *state,
			     const struct tquic_fec_repair_frame *frame)
{
	struct tquic_fec_decoder *dec;
	struct tquic_fec_source_block *block;
	struct tquic_fec_symbol *symbol;
	int recovered = 0;
	int ret = 0;

	if (!state || !frame || !frame->repair_data)
		return -EINVAL;

	dec = &state->decoder;

	spin_lock_bh(&dec->lock);

	if (!dec->enabled) {
		ret = -ENODEV;
		goto out;
	}

	/* Find or create block */
	block = tquic_fec_find_block(state, frame->block_id);
	if (!block) {
		if (dec->num_active_blocks >= dec->max_active_blocks) {
			ret = -ENOSPC;
			goto out;
		}

		block = decoder_alloc_block(frame->block_id,
					    frame->source_block_length,
					    frame->scheme);
		if (!block) {
			ret = -ENOMEM;
			goto out;
		}

		list_add_tail(&block->list, &dec->active_blocks);
		dec->num_active_blocks++;
		dec->stats.blocks_received++;
	}

	spin_lock(&block->lock);

	/* Update block info if we learned it */
	if (block->num_source == 0)
		block->num_source = frame->source_block_length;

	/* Add repair symbol */
	symbol = decoder_alloc_symbol(0, frame->repair_symbol_id,
				      frame->repair_data, frame->repair_length,
				      true);
	if (!symbol) {
		spin_unlock(&block->lock);
		ret = -ENOMEM;
		goto out;
	}

	list_add_tail(&symbol->list, &block->repair_symbols);
	block->num_repair_received++;
	dec->stats.repair_symbols_received++;

	/* Attempt recovery if we have losses */
	if (!block->complete && !block->recovered &&
	    block->num_source > 0 &&
	    block->num_received < block->num_source) {

		dec->stats.recovery_attempts++;

		switch (frame->scheme) {
		case TQUIC_FEC_SCHEME_XOR:
			recovered = attempt_xor_recovery(block);
			break;
		case TQUIC_FEC_SCHEME_REED_SOLOMON_8:
			recovered = attempt_rs_recovery(block, 8);
			break;
		case TQUIC_FEC_SCHEME_REED_SOLOMON_16:
			recovered = attempt_rs_recovery(block, 16);
			break;
		default:
			recovered = 0;
			break;
		}

		if (recovered > 0) {
			dec->stats.recovery_success++;
			dec->stats.packets_recovered += recovered;
		} else if (recovered == 0 && block->num_repair_received > 0) {
			/* Have repair but couldn't recover - not enough symbols yet */
		} else if (recovered < 0) {
			dec->stats.recovery_failed++;
		}
	}

	spin_unlock(&block->lock);
	ret = recovered;

out:
	spin_unlock_bh(&dec->lock);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_fec_receive_repair);

/**
 * tquic_fec_recover - Attempt packet recovery for a source block
 * @state: FEC state
 * @block: Source block to recover
 * @recovered: Output array for recovered packets (may be NULL)
 * @max_recovered: Maximum packets to recover
 *
 * Return: Number of packets recovered, or negative error
 */
int tquic_fec_recover(struct tquic_fec_state *state,
		      struct tquic_fec_source_block *block,
		      struct sk_buff **recovered, int max_recovered)
{
	struct tquic_fec_decoder *dec;
	int num_recovered = 0;

	if (!state || !block)
		return -EINVAL;

	dec = &state->decoder;

	spin_lock(&block->lock);

	if (block->complete || block->recovered) {
		spin_unlock(&block->lock);
		return 0;
	}

	/* Attempt recovery based on scheme */
	switch (block->scheme) {
	case TQUIC_FEC_SCHEME_XOR:
		num_recovered = attempt_xor_recovery(block);
		break;
	case TQUIC_FEC_SCHEME_REED_SOLOMON_8:
		num_recovered = attempt_rs_recovery(block, 8);
		break;
	case TQUIC_FEC_SCHEME_REED_SOLOMON_16:
		num_recovered = attempt_rs_recovery(block, 16);
		break;
	default:
		num_recovered = -EINVAL;
		break;
	}

	spin_unlock(&block->lock);

	return num_recovered;
}
EXPORT_SYMBOL_GPL(tquic_fec_recover);

/*
 * =============================================================================
 * Frame Decoding
 * =============================================================================
 */

/* Variable-length integer decoding helper */
static ssize_t decode_varint(const u8 *buf, size_t buflen, u64 *value)
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
 * tquic_fec_decode_repair_frame - Decode FEC_REPAIR frame
 * @buf: Input buffer (starts after frame type)
 * @buflen: Buffer length
 * @frame: Output frame structure
 *
 * Return: Bytes consumed, or negative error
 */
ssize_t tquic_fec_decode_repair_frame(const u8 *buf, size_t buflen,
				      struct tquic_fec_repair_frame *frame)
{
	ssize_t ret;
	size_t offset = 0;
	u64 value;

	if (!buf || !frame)
		return -EINVAL;

	memset(frame, 0, sizeof(*frame));

	/* Block ID */
	ret = decode_varint(buf + offset, buflen - offset, &value);
	if (ret < 0)
		return ret;
	frame->block_id = (u32)value;
	offset += ret;

	/* Repair Symbol ID (1 byte) */
	if (buflen - offset < 1)
		return -EINVAL;
	frame->repair_symbol_id = buf[offset++];

	/* Source Block Length (1 byte) */
	if (buflen - offset < 1)
		return -EINVAL;
	frame->source_block_length = buf[offset++];

	/* FEC Scheme (1 byte) */
	if (buflen - offset < 1)
		return -EINVAL;
	frame->scheme = (enum tquic_fec_scheme)buf[offset++];

	/* Repair Length */
	ret = decode_varint(buf + offset, buflen - offset, &value);
	if (ret < 0)
		return ret;
	frame->repair_length = (u16)value;
	offset += ret;

	/* Repair Data - just point to it in buffer */
	if (buflen - offset < frame->repair_length)
		return -EINVAL;
	frame->repair_data = (u8 *)(buf + offset);
	offset += frame->repair_length;

	return offset;
}
EXPORT_SYMBOL_GPL(tquic_fec_decode_repair_frame);

/**
 * tquic_fec_decode_source_info_frame - Decode FEC_SOURCE_INFO frame
 * @buf: Input buffer (starts after frame type)
 * @buflen: Buffer length
 * @frame: Output frame structure
 *
 * Return: Bytes consumed, or negative error
 */
ssize_t tquic_fec_decode_source_info_frame(const u8 *buf, size_t buflen,
					   struct tquic_fec_source_info_frame *frame)
{
	ssize_t ret;
	size_t offset = 0;
	u64 value;

	if (!buf || !frame)
		return -EINVAL;

	memset(frame, 0, sizeof(*frame));

	/* Block ID */
	ret = decode_varint(buf + offset, buflen - offset, &value);
	if (ret < 0)
		return ret;
	frame->block_id = (u32)value;
	offset += ret;

	/* First Symbol ID (1 byte) */
	if (buflen - offset < 2)
		return -EINVAL;
	frame->first_source_symbol_id = buf[offset++];

	/* Num Source Symbols (1 byte) */
	frame->num_source_symbols = buf[offset++];

	return offset;
}
EXPORT_SYMBOL_GPL(tquic_fec_decode_source_info_frame);

/**
 * tquic_fec_cleanup_old_blocks - Remove expired source blocks
 * @state: FEC state
 * @max_age_ms: Maximum block age in milliseconds
 */
void tquic_fec_cleanup_old_blocks(struct tquic_fec_state *state, u32 max_age_ms)
{
	struct tquic_fec_decoder *dec;
	struct tquic_fec_source_block *block, *tmp;
	ktime_t now = ktime_get();
	ktime_t max_age = ms_to_ktime(max_age_ms);

	if (!state)
		return;

	dec = &state->decoder;

	spin_lock_bh(&dec->lock);

	list_for_each_entry_safe(block, tmp, &dec->active_blocks, list) {
		if (ktime_sub(now, block->created) > max_age) {
			list_del(&block->list);
			dec->num_active_blocks--;
			decoder_free_block(block);
		}
	}

	spin_unlock_bh(&dec->lock);
}
EXPORT_SYMBOL_GPL(tquic_fec_cleanup_old_blocks);
