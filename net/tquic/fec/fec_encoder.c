// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC FEC Encoder
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Implementation of FEC encoding for QUIC based on draft-zheng-quic-fec-extension-01.
 * Supports XOR and Reed-Solomon coding schemes.
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/spinlock.h>

#include "fec.h"

/* Slab cache for FEC symbols to avoid per-packet GFP_ATOMIC allocations */
static struct kmem_cache *fec_symbol_cache __read_mostly;

void __init tquic_fec_encoder_cache_init(void)
{
	fec_symbol_cache = kmem_cache_create("tquic_fec_symbol",
					     sizeof(struct tquic_fec_symbol),
					     0, SLAB_HWCACHE_ALIGN, NULL);
}

void tquic_fec_encoder_cache_destroy(void)
{
	kmem_cache_destroy(fec_symbol_cache);
}

/*
 * =============================================================================
 * Source Block Management
 * =============================================================================
 */

/**
 * alloc_source_block - Allocate a new source block
 * @block_id: Block identifier
 * @num_source: Expected number of source symbols
 * @scheme: FEC scheme
 *
 * Return: Allocated source block or NULL on failure
 */
static struct tquic_fec_source_block *alloc_source_block(u32 block_id,
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
 * free_symbol - Free a single FEC symbol
 * @symbol: Symbol to free
 */
static void free_symbol(struct tquic_fec_symbol *symbol)
{
	if (!symbol)
		return;

	kfree(symbol->data);
	if (fec_symbol_cache)
		kmem_cache_free(fec_symbol_cache, symbol);
	else
		kfree(symbol);
}

/**
 * free_source_block - Free a source block and all its symbols
 * @block: Block to free
 */
static void free_source_block(struct tquic_fec_source_block *block)
{
	struct tquic_fec_symbol *symbol, *tmp;

	if (!block)
		return;

	/* Free source symbols */
	list_for_each_entry_safe(symbol, tmp, &block->source_symbols, list) {
		list_del_init(&symbol->list);
		free_symbol(symbol);
	}

	/* Free repair symbols */
	list_for_each_entry_safe(symbol, tmp, &block->repair_symbols, list) {
		list_del_init(&symbol->list);
		free_symbol(symbol);
	}

	kfree(block);
}

/**
 * alloc_symbol - Allocate a new FEC symbol
 * @pkt_num: Packet number
 * @symbol_id: Symbol ID
 * @data: Symbol data
 * @length: Data length
 * @is_repair: True for repair symbol
 *
 * Return: Allocated symbol or NULL on failure
 */
static struct tquic_fec_symbol *alloc_symbol(u64 pkt_num, u8 symbol_id,
					     const u8 *data, u16 length,
					     bool is_repair)
{
	struct tquic_fec_symbol *symbol;

	if (fec_symbol_cache)
		symbol = kmem_cache_zalloc(fec_symbol_cache, GFP_ATOMIC);
	else
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
 * FEC Encoder Implementation
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
			   u8 block_size, u8 repair_count)
{
	struct tquic_fec_encoder *enc;

	if (!state)
		return -EINVAL;

	if (block_size < TQUIC_FEC_MIN_SOURCE_SYMBOLS ||
	    block_size > TQUIC_FEC_MAX_SOURCE_SYMBOLS)
		return -EINVAL;

	if (scheme >= __TQUIC_FEC_SCHEME_MAX)
		return -EINVAL;

	/* XOR can only generate one repair symbol */
	if (scheme == TQUIC_FEC_SCHEME_XOR && repair_count > 1)
		repair_count = 1;

	enc = &state->encoder;

	spin_lock_init(&enc->lock);
	INIT_LIST_HEAD(&enc->pending_blocks);

	enc->scheme = scheme;
	enc->block_size = block_size;
	enc->repair_count = repair_count;
	enc->current_block = NULL;
	enc->current_block_id = 0;
	enc->symbols_in_block = 0;
	enc->enabled = true;

	/* Reset statistics */
	memset(&enc->stats, 0, sizeof(enc->stats));

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_fec_encoder_init);

/**
 * tquic_fec_encoder_destroy - Clean up FEC encoder
 * @state: FEC state structure
 */
void tquic_fec_encoder_destroy(struct tquic_fec_state *state)
{
	struct tquic_fec_encoder *enc;
	struct tquic_fec_source_block *block, *tmp;

	if (!state)
		return;

	enc = &state->encoder;

	spin_lock_bh(&enc->lock);

	/* Free current block */
	if (enc->current_block) {
		free_source_block(enc->current_block);
		enc->current_block = NULL;
	}

	/* Free pending blocks */
	list_for_each_entry_safe(block, tmp, &enc->pending_blocks, list) {
		list_del_init(&block->list);
		free_source_block(block);
	}

	enc->enabled = false;

	spin_unlock_bh(&enc->lock);
}
EXPORT_SYMBOL_GPL(tquic_fec_encoder_destroy);

/**
 * tquic_fec_add_source_symbol - Add packet to current source block
 * @state: FEC state
 * @pkt_num: Packet number
 * @data: Packet payload data
 * @length: Payload length
 *
 * Return: 0 on success, 1 if block is complete, negative error on failure
 */
int tquic_fec_add_source_symbol(struct tquic_fec_state *state,
				u64 pkt_num, const u8 *data, u16 length)
{
	struct tquic_fec_encoder *enc;
	struct tquic_fec_source_block *block;
	struct tquic_fec_symbol *symbol;
	int ret = 0;

	if (!state || !data || length == 0)
		return -EINVAL;

	if (length > TQUIC_FEC_MAX_SYMBOL_SIZE)
		return -EMSGSIZE;

	enc = &state->encoder;

	spin_lock_bh(&enc->lock);

	if (!enc->enabled) {
		ret = -ENODEV;
		goto out;
	}

	/* Create new block if needed */
	if (!enc->current_block) {
		block = alloc_source_block(enc->current_block_id++,
					   enc->block_size, enc->scheme);
		if (!block) {
			ret = -ENOMEM;
			goto out;
		}
		enc->current_block = block;
		enc->symbols_in_block = 0;
		block->first_pkt_num = pkt_num;
	}

	block = enc->current_block;

	/* Allocate and add symbol */
	symbol = alloc_symbol(pkt_num, enc->symbols_in_block, data, length, false);
	if (!symbol) {
		ret = -ENOMEM;
		goto out;
	}

	/*
	 * No need for block->lock here: the block is enc->current_block
	 * and we hold enc->lock, so no concurrent access is possible.
	 */
	list_add_tail(&symbol->list, &block->source_symbols);
	block->num_received++;
	block->last_pkt_num = pkt_num;

	if (length > block->max_symbol_size)
		block->max_symbol_size = length;

	enc->symbols_in_block++;
	enc->stats.symbols_encoded++;

	/* Check if block is complete */
	if (enc->symbols_in_block >= enc->block_size) {
		/* Move to pending list for repair generation */
		list_add_tail(&block->list, &enc->pending_blocks);
		enc->current_block = NULL;
		enc->stats.blocks_created++;
		ret = 1;  /* Block complete */
	}

out:
	spin_unlock_bh(&enc->lock);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_fec_add_source_symbol);

/**
 * generate_xor_repair - Generate XOR repair symbol
 * @block: Source block
 *
 * Return: Repair symbol or NULL on failure
 */
static struct tquic_fec_symbol *generate_xor_repair(struct tquic_fec_source_block *block)
{
	struct tquic_fec_symbol *symbol, *repair = NULL;
	const u8 **symbols;
	u16 *lengths;
	u8 *repair_data;
	u16 repair_len = 0;
	int idx = 0;
	int ret;

	/*
	 * Allocate work buffers dynamically to avoid ~4KB stack usage
	 * (symbols array + lengths array + repair_data combined exceed
	 * safe kernel stack limits on deeply nested paths).
	 */
	symbols = kmalloc_array(TQUIC_FEC_MAX_SOURCE_SYMBOLS,
				sizeof(*symbols), GFP_ATOMIC);
	lengths = kmalloc_array(TQUIC_FEC_MAX_SOURCE_SYMBOLS,
				sizeof(*lengths), GFP_ATOMIC);
	repair_data = kmalloc(TQUIC_FEC_MAX_SYMBOL_SIZE, GFP_ATOMIC);
	if (!symbols || !lengths || !repair_data)
		goto out_free;

	/* Collect source symbols */
	list_for_each_entry(symbol, &block->source_symbols, list) {
		if (idx >= block->num_source)
			break;
		symbols[idx] = symbol->data;
		lengths[idx] = symbol->length;
		idx++;
	}

	/* Generate XOR parity */
	ret = tquic_xor_encode(symbols, lengths, idx, repair_data, &repair_len);
	if (ret < 0)
		goto out_free;

	/* Allocate repair symbol */
	repair = alloc_symbol(0, 0, repair_data, repair_len, true);

out_free:
	kfree(repair_data);
	kfree(lengths);
	kfree(symbols);
	return repair;
}

/**
 * generate_rs_repair - Generate Reed-Solomon repair symbols
 * @block: Source block
 * @num_repair: Number of repair symbols to generate
 * @gf_bits: Galois field size (8 or 16)
 *
 * Return: Number of repair symbols generated, or negative error
 */
static int generate_rs_repair(struct tquic_fec_source_block *block,
			      u8 num_repair, int gf_bits)
{
	struct tquic_fec_symbol *symbol;
	const u8 *symbols[TQUIC_FEC_MAX_SOURCE_SYMBOLS];
	u16 lengths[TQUIC_FEC_MAX_SOURCE_SYMBOLS];
	u8 *repair_bufs[TQUIC_FEC_MAX_REPAIR_SYMBOLS];
	u16 repair_lens[TQUIC_FEC_MAX_REPAIR_SYMBOLS];
	int idx = 0;
	int i, ret;
	struct tquic_fec_symbol *repair_sym;

	/* Limit repair symbols */
	if (num_repair > TQUIC_FEC_MAX_REPAIR_SYMBOLS)
		num_repair = TQUIC_FEC_MAX_REPAIR_SYMBOLS;

	/* Collect source symbols */
	list_for_each_entry(symbol, &block->source_symbols, list) {
		if (idx >= block->num_source)
			break;
		symbols[idx] = symbol->data;
		lengths[idx] = symbol->length;
		idx++;
	}

	/* Allocate repair buffers */
	for (i = 0; i < num_repair; i++) {
		repair_bufs[i] = kmalloc(block->max_symbol_size, GFP_ATOMIC);
		if (!repair_bufs[i]) {
			while (--i >= 0)
				kfree(repair_bufs[i]);
			return -ENOMEM;
		}
	}

	/* Generate RS repair symbols */
	ret = tquic_rs_encode(symbols, lengths, idx, num_repair,
			      repair_bufs, repair_lens, gf_bits);
	if (ret < 0) {
		for (i = 0; i < num_repair; i++)
			kfree(repair_bufs[i]);
		return ret;
	}

	/* Create repair symbol structures */
	for (i = 0; i < num_repair; i++) {
		repair_sym = kzalloc(sizeof(*repair_sym), GFP_ATOMIC);
		if (!repair_sym) {
			/*
			 * MEMORY LEAK FIX: On allocation failure, we must:
			 * 1. Free all remaining unattached repair_bufs
			 * 2. Remove and free already-created repair_sym structs
			 * 3. Return error (not partial success)
			 */
			struct tquic_fec_symbol *tmp;
			int j;

			/* Free remaining unattached repair buffers */
			for (j = i; j < num_repair; j++)
				kfree(repair_bufs[j]);

			/* Remove and free already-added repair symbols */
			list_for_each_entry_safe(repair_sym, tmp,
						 &block->repair_symbols,
						 list) {
				list_del_init(&repair_sym->list);
				kfree(repair_sym->data);
				kfree(repair_sym);
			}
			block->num_repair = 0;

			return -ENOMEM;
		}

		repair_sym->data = repair_bufs[i];
		repair_sym->length = repair_lens[i];
		repair_sym->symbol_id = i;
		repair_sym->is_repair = true;
		repair_sym->received = true;
		INIT_LIST_HEAD(&repair_sym->list);

		list_add_tail(&repair_sym->list, &block->repair_symbols);
		block->num_repair++;
	}

	return block->num_repair;
}

/**
 * tquic_fec_generate_repair - Generate repair symbols for current block
 * @state: FEC state
 * @block: Source block (or NULL for current)
 *
 * Return: Number of repair symbols generated, or negative error
 */
int tquic_fec_generate_repair(struct tquic_fec_state *state,
			      struct tquic_fec_source_block *block)
{
	struct tquic_fec_encoder *enc;
	struct tquic_fec_symbol *repair;
	int ret = 0;

	if (!state)
		return -EINVAL;

	enc = &state->encoder;

	spin_lock_bh(&enc->lock);

	if (!enc->enabled) {
		ret = -ENODEV;
		goto out;
	}

	/* Use provided block or get from pending list */
	if (!block) {
		if (list_empty(&enc->pending_blocks)) {
			ret = 0;
			goto out;
		}
		block = list_first_entry(&enc->pending_blocks,
					 struct tquic_fec_source_block, list);
	}

	/*
	 * No need for block->lock here: the block is from enc->pending_blocks
	 * and we hold enc->lock, so no concurrent access is possible.
	 */

	/* Generate repair symbols based on scheme */
	switch (enc->scheme) {
	case TQUIC_FEC_SCHEME_XOR:
		repair = generate_xor_repair(block);
		if (repair) {
			list_add_tail(&repair->list, &block->repair_symbols);
			block->num_repair = 1;
			ret = 1;
		} else {
			ret = -ENOMEM;
		}
		break;

	case TQUIC_FEC_SCHEME_REED_SOLOMON_8:
		ret = generate_rs_repair(block, enc->repair_count, 8);
		break;

	case TQUIC_FEC_SCHEME_REED_SOLOMON_16:
		ret = generate_rs_repair(block, enc->repair_count, 16);
		break;

	default:
		ret = -EINVAL;
		break;
	}

	if (ret > 0)
		enc->stats.repair_symbols_sent += ret;

out:
	spin_unlock_bh(&enc->lock);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_fec_generate_repair);

/*
 * =============================================================================
 * Frame Encoding
 * =============================================================================
 */

/* Variable-length integer encoding helper */
static ssize_t encode_varint(u8 *buf, size_t buflen, u64 value)
{
	size_t len;

	if (value <= 63) {
		len = 1;
	} else if (value <= 16383) {
		len = 2;
	} else if (value <= 1073741823) {
		len = 4;
	} else {
		len = 8;
	}

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
 * tquic_fec_encode_repair_frame - Encode FEC_REPAIR frame to buffer
 * @state: FEC state
 * @block: Source block
 * @repair_id: Repair symbol index
 * @buf: Output buffer
 * @buflen: Buffer length
 *
 * FEC_REPAIR Frame Format:
 *   Frame Type (varint)     = 0xfc00
 *   Block ID (varint)       = Source block identifier
 *   Repair Symbol ID (8)    = Index of repair symbol
 *   Source Block Len (8)    = Number of source symbols
 *   FEC Scheme (8)          = Encoding scheme used
 *   Repair Length (varint)  = Length of repair data
 *   Repair Data (...)       = Repair symbol payload
 *
 * Return: Bytes written, or negative error
 */
ssize_t tquic_fec_encode_repair_frame(struct tquic_fec_state *state,
				      struct tquic_fec_source_block *block,
				      u8 repair_id, u8 *buf, size_t buflen)
{
	struct tquic_fec_symbol *repair = NULL;
	struct tquic_fec_symbol *sym;
	ssize_t ret;
	size_t offset = 0;
	int idx = 0;

	if (!state || !block || !buf)
		return -EINVAL;

	/* Find the repair symbol */
	spin_lock_bh(&block->lock);
	list_for_each_entry(sym, &block->repair_symbols, list) {
		if (idx == repair_id) {
			repair = sym;
			break;
		}
		idx++;
	}

	if (!repair) {
		spin_unlock_bh(&block->lock);
		return -ENOENT;
	}

	/* Frame type */
	ret = encode_varint(buf + offset, buflen - offset, TQUIC_FRAME_FEC_REPAIR);
	if (ret < 0) {
		spin_unlock_bh(&block->lock);
		return ret;
	}
	offset += ret;

	/* Block ID */
	ret = encode_varint(buf + offset, buflen - offset, block->block_id);
	if (ret < 0) {
		spin_unlock_bh(&block->lock);
		return ret;
	}
	offset += ret;

	/* Repair Symbol ID (1 byte) */
	if (buflen - offset < 1) {
		spin_unlock_bh(&block->lock);
		return -ENOSPC;
	}
	buf[offset++] = repair_id;

	/* Source Block Length (1 byte) */
	if (buflen - offset < 1) {
		spin_unlock_bh(&block->lock);
		return -ENOSPC;
	}
	buf[offset++] = block->num_source;

	/* FEC Scheme (1 byte) */
	if (buflen - offset < 1) {
		spin_unlock_bh(&block->lock);
		return -ENOSPC;
	}
	buf[offset++] = (u8)block->scheme;

	/* Repair Length */
	ret = encode_varint(buf + offset, buflen - offset, repair->length);
	if (ret < 0) {
		spin_unlock_bh(&block->lock);
		return ret;
	}
	offset += ret;

	/* Repair Data */
	if (buflen - offset < repair->length) {
		spin_unlock_bh(&block->lock);
		return -ENOSPC;
	}
	memcpy(buf + offset, repair->data, repair->length);
	offset += repair->length;

	spin_unlock_bh(&block->lock);

	return offset;
}
EXPORT_SYMBOL_GPL(tquic_fec_encode_repair_frame);

/**
 * tquic_fec_encode_source_info_frame - Encode FEC_SOURCE_INFO frame
 * @block_id: Source block ID
 * @symbol_id: First symbol ID
 * @num_symbols: Number of symbols
 * @buf: Output buffer
 * @buflen: Buffer length
 *
 * FEC_SOURCE_INFO Frame Format:
 *   Frame Type (varint)       = 0xfc01
 *   Block ID (varint)         = Source block identifier
 *   First Symbol ID (8)       = First source symbol in packet
 *   Num Symbols (8)           = Number of source symbols
 *
 * Return: Bytes written, or negative error
 */
ssize_t tquic_fec_encode_source_info_frame(u32 block_id, u8 symbol_id,
					   u8 num_symbols,
					   u8 *buf, size_t buflen)
{
	ssize_t ret;
	size_t offset = 0;

	if (!buf)
		return -EINVAL;

	/* Frame type */
	ret = encode_varint(buf + offset, buflen - offset, TQUIC_FRAME_FEC_SOURCE_INFO);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Block ID */
	ret = encode_varint(buf + offset, buflen - offset, block_id);
	if (ret < 0)
		return ret;
	offset += ret;

	/* First Symbol ID */
	if (buflen - offset < 2)
		return -ENOSPC;
	buf[offset++] = symbol_id;

	/* Number of symbols */
	buf[offset++] = num_symbols;

	return offset;
}
EXPORT_SYMBOL_GPL(tquic_fec_encode_source_info_frame);

/**
 * tquic_fec_get_pending_repair - Get next pending repair frame
 * @state: FEC state
 * @frame: Output frame structure
 *
 * Return: true if a repair frame is available, false otherwise
 */
bool tquic_fec_get_pending_repair(struct tquic_fec_state *state,
				  struct tquic_fec_repair_frame *frame)
{
	struct tquic_fec_encoder *enc;
	struct tquic_fec_source_block *block;
	struct tquic_fec_symbol *repair;
	bool found = false;

	if (!state || !frame)
		return false;

	enc = &state->encoder;

	spin_lock_bh(&enc->lock);

	if (list_empty(&enc->pending_blocks))
		goto out;

	/* Get first pending block */
	block = list_first_entry(&enc->pending_blocks,
				 struct tquic_fec_source_block, list);

	/*
	 * No need for block->lock: the block is on enc->pending_blocks
	 * and we hold enc->lock, so no concurrent access is possible.
	 */

	/* Get first unsent repair symbol */
	list_for_each_entry(repair, &block->repair_symbols, list) {
		if (repair->received) {
			/* Mark as sent */
			repair->received = false;

			/* Fill frame structure */
			frame->block_id = block->block_id;
			frame->repair_symbol_id = repair->symbol_id;
			frame->source_block_length = block->num_source;
			frame->scheme = block->scheme;
			frame->repair_data = repair->data;
			frame->repair_length = repair->length;

			found = true;
			break;
		}
	}

	/* Check if all repair symbols sent */
	if (found) {
		bool all_sent = true;

		list_for_each_entry(repair, &block->repair_symbols, list) {
			if (repair->received) {
				all_sent = false;
				break;
			}
		}

		/* Remove block from pending if all sent */
		if (all_sent)
			list_del_init(&block->list);
	}

out:
	spin_unlock_bh(&enc->lock);
	return found;
}
EXPORT_SYMBOL_GPL(tquic_fec_get_pending_repair);
