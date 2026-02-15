// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC XOR FEC Scheme
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Simple XOR-based Forward Error Correction for QUIC.
 * Can recover exactly one lost packet per source block.
 *
 * XOR FEC is computationally efficient but limited to single packet loss
 * recovery. It works by XORing all source symbols together to produce a
 * single repair symbol. When one source symbol is lost, it can be recovered
 * by XORing all received symbols with the repair symbol.
 *
 * Algorithm:
 *   Encode: R = S[0] ^ S[1] ^ S[2] ^ ... ^ S[n-1]
 *   Decode: S[i] = R ^ S[0] ^ ... ^ S[i-1] ^ S[i+1] ^ ... ^ S[n-1]
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>

#include "fec.h"

/**
 * tquic_xor_encode - Generate XOR parity symbol
 * @symbols: Array of source symbol pointers
 * @lengths: Array of symbol lengths
 * @num_symbols: Number of source symbols
 * @repair: Output buffer for repair symbol (must be at least max(lengths) bytes)
 * @repair_len: Output repair symbol length
 *
 * XOR all source symbols together to produce a single repair symbol.
 * The repair symbol length will be the maximum of all source symbol lengths.
 * Shorter symbols are zero-padded for XOR computation.
 *
 * Return: 0 on success, negative error on failure
 */
int tquic_xor_encode(const u8 **symbols, const u16 *lengths,
		     u8 num_symbols, u8 *repair, u16 *repair_len)
{
	u16 max_len = 0;
	int i, j;

	if (!symbols || !lengths || !repair || !repair_len)
		return -EINVAL;

	if (num_symbols < 1)
		return -EINVAL;

	/* Find maximum symbol length */
	for (i = 0; i < num_symbols; i++) {
		if (!symbols[i])
			return -EINVAL;
		if (lengths[i] > max_len)
			max_len = lengths[i];
	}

	if (max_len == 0)
		return -EINVAL;

	if (max_len > TQUIC_FEC_MAX_SYMBOL_SIZE)
		return -EMSGSIZE;

	/* Initialize repair symbol with zeros */
	memset(repair, 0, max_len);

	/* XOR all source symbols */
	for (i = 0; i < num_symbols; i++) {
		const u8 *sym = symbols[i];
		u16 len = lengths[i];

		/* XOR byte by byte */
		for (j = 0; j < len; j++)
			repair[j] ^= sym[j];

		/* Remaining bytes stay as zeros (implicit zero padding) */
	}

	*repair_len = max_len;
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_xor_encode);

/**
 * tquic_xor_decode - Recover lost packet using XOR
 * @symbols: Array of source symbol pointers (NULL for lost symbol)
 * @lengths: Array of symbol lengths (0 for lost symbol)
 * @num_symbols: Number of source symbols
 * @repair: Repair symbol
 * @repair_len: Repair symbol length
 * @recovered: Output buffer for recovered packet
 * @recovered_len: Output recovered packet length
 *
 * XOR all received symbols with repair symbol to recover the lost packet.
 * This function expects exactly one NULL entry in the symbols array,
 * indicating the lost packet position.
 *
 * Algorithm:
 *   If R = S[0] ^ S[1] ^ ... ^ S[n-1]
 *   And S[i] is lost, then:
 *   S[i] = R ^ S[0] ^ ... ^ S[i-1] ^ S[i+1] ^ ... ^ S[n-1]
 *
 * Return: 0 on success, negative error on failure
 *   -EINVAL: Invalid parameters
 *   -ENOENT: No lost symbol found (nothing to recover)
 *   -E2BIG: More than one symbol lost (XOR cannot recover)
 */
int tquic_xor_decode(const u8 **symbols, const u16 *lengths,
		     u8 num_symbols, const u8 *repair, u16 repair_len,
		     u8 *recovered, u16 *recovered_len)
{
	int lost_idx = -1;
	int num_lost = 0;
	int i, j;

	if (!symbols || !lengths || !repair || !recovered || !recovered_len)
		return -EINVAL;

	if (num_symbols < 2)
		return -EINVAL;

	if (repair_len == 0 || repair_len > TQUIC_FEC_MAX_SYMBOL_SIZE)
		return -EINVAL;

	/* Find the lost symbol(s) */
	for (i = 0; i < num_symbols; i++) {
		if (!symbols[i]) {
			lost_idx = i;
			num_lost++;
		}
	}

	/* XOR can only recover exactly one lost symbol */
	if (num_lost == 0)
		return -ENOENT;  /* Nothing to recover */

	if (num_lost > 1)
		return -E2BIG;  /* Too many losses for XOR */

	/*
	 * Recovery: XOR the repair symbol with all received symbols
	 *
	 * If R = S[0] ^ S[1] ^ ... ^ S[n-1]
	 * Then: S[lost] = R ^ S[0] ^ ... ^ S[lost-1] ^ S[lost+1] ^ ... ^ S[n-1]
	 */

	/* Start with repair symbol */
	memcpy(recovered, repair, repair_len);

	/* XOR with all received symbols */
	for (i = 0; i < num_symbols; i++) {
		if (i == lost_idx)
			continue;

		const u8 *sym = symbols[i];
		u16 len = lengths[i];

		for (j = 0; j < len && j < repair_len; j++)
			recovered[j] ^= sym[j];
	}

	/*
	 * The recovered length is the repair length minus any trailing zeros.
	 * However, we can't reliably detect the original length this way,
	 * so we return the full repair length. The caller should use
	 * additional framing information to determine actual packet length.
	 */
	*recovered_len = repair_len;

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_xor_decode);

/**
 * tquic_xor_encode_incremental - Incrementally update XOR parity
 * @repair: Current repair symbol (updated in place)
 * @repair_len: Current repair length (updated)
 * @symbol: New source symbol to add
 * @length: New symbol length
 *
 * Add a new source symbol to the XOR parity without storing all symbols.
 * Useful for streaming encoding where symbols arrive over time.
 *
 * Return: 0 on success, negative error on failure
 */
int tquic_xor_encode_incremental(u8 *repair, u16 *repair_len,
				 const u8 *symbol, u16 length)
{
	int i;

	if (!repair || !repair_len || !symbol)
		return -EINVAL;

	if (length > TQUIC_FEC_MAX_SYMBOL_SIZE)
		return -EMSGSIZE;

	/* Extend repair if needed */
	if (length > *repair_len) {
		/* Zero-fill the extension */
		memset(repair + *repair_len, 0, length - *repair_len);
		*repair_len = length;
	}

	/* XOR with new symbol */
	for (i = 0; i < length; i++)
		repair[i] ^= symbol[i];

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_xor_encode_incremental);

/**
 * tquic_xor_can_recover - Check if XOR recovery is possible
 * @symbols: Array of source symbol pointers (NULL for lost)
 * @num_symbols: Number of source symbols
 * @has_repair: True if repair symbol is available
 *
 * Return: Number of recoverable packets (0 or 1), or -1 if invalid
 */
int tquic_xor_can_recover(const u8 **symbols, u8 num_symbols, bool has_repair)
{
	int num_lost = 0;
	int i;

	if (!symbols || num_symbols < 1)
		return -1;

	if (!has_repair)
		return 0;

	for (i = 0; i < num_symbols; i++) {
		if (!symbols[i])
			num_lost++;
	}

	/* XOR can recover exactly 1 lost symbol */
	return (num_lost == 1) ? 1 : 0;
}
EXPORT_SYMBOL_GPL(tquic_xor_can_recover);

/**
 * tquic_xor_encode_block - Encode a complete block
 * @symbols: Array of source symbol pointers
 * @lengths: Array of symbol lengths
 * @num_symbols: Number of source symbols
 * @repair: Output repair symbol
 * @repair_len: Output repair length
 *
 * Convenience wrapper for encoding a complete source block.
 *
 * Return: 0 on success, negative error on failure
 */
int tquic_xor_encode_block(const u8 **symbols, const u16 *lengths,
			   u8 num_symbols, u8 *repair, u16 *repair_len)
{
	return tquic_xor_encode(symbols, lengths, num_symbols, repair, repair_len);
}
EXPORT_SYMBOL_GPL(tquic_xor_encode_block);

/**
 * tquic_xor_decode_block - Decode and recover from a block
 * @symbols: Array of source symbol pointers (NULL for lost)
 * @lengths: Array of symbol lengths
 * @num_symbols: Number of source symbols
 * @repair: Repair symbol
 * @repair_len: Repair symbol length
 * @lost_idx: Index of lost symbol (output if unknown, input if known)
 * @recovered: Output buffer for recovered data
 * @recovered_len: Output length
 *
 * Return: 0 on success, negative error on failure
 */
int tquic_xor_decode_block(const u8 **symbols, const u16 *lengths,
			   u8 num_symbols, const u8 *repair, u16 repair_len,
			   int *lost_idx, u8 *recovered, u16 *recovered_len)
{
	int found_idx = -1;
	int num_lost = 0;
	int i;

	if (!symbols || !lengths || !repair || !recovered || !recovered_len)
		return -EINVAL;

	/* Find lost symbol if not provided */
	if (lost_idx && *lost_idx >= 0 && *lost_idx < num_symbols) {
		found_idx = *lost_idx;
		num_lost = 1;
	} else {
		for (i = 0; i < num_symbols; i++) {
			if (!symbols[i]) {
				found_idx = i;
				num_lost++;
			}
		}
	}

	if (num_lost == 0)
		return -ENOENT;

	if (num_lost > 1)
		return -E2BIG;

	if (lost_idx)
		*lost_idx = found_idx;

	return tquic_xor_decode(symbols, lengths, num_symbols,
				repair, repair_len, recovered, recovered_len);
}
EXPORT_SYMBOL_GPL(tquic_xor_decode_block);
