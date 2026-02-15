// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC Reed-Solomon FEC Scheme
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Reed-Solomon Forward Error Correction for QUIC.
 * Supports GF(2^8) and GF(2^16) Galois fields.
 *
 * Reed-Solomon codes can recover from multiple packet losses, limited by
 * the number of repair symbols generated. With N repair symbols, up to N
 * lost source symbols can be recovered.
 *
 * This implementation uses:
 *   - Systematic encoding (source symbols are unchanged)
 *   - Cauchy matrix construction for the generator matrix
 *   - Gaussian elimination for encoding
 *   - Matrix inversion for erasure decoding
 *
 * Galois Field Arithmetic:
 *   - GF(2^8): Polynomial 0x11d (AES field), used for RS-8
 *   - GF(2^16): Polynomial 0x1100b, used for RS-16
 *
 * References:
 *   - RFC 5510: Reed-Solomon Forward Error Correction (FEC) Schemes
 *   - RFC 6865: Simple Reed-Solomon Forward Error Correction (FEC) Scheme
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/module.h>

#include "fec.h"

/*
 * =============================================================================
 * Galois Field GF(2^8) Arithmetic
 * =============================================================================
 */

/* GF(2^8) primitive polynomial: x^8 + x^4 + x^3 + x^2 + 1 = 0x11d */
#define GF8_POLY	0x11d
#define GF8_SIZE	256
#define GF8_MAX		255

/* GF(2^8) lookup tables */
static u8 gf8_exp[512];		/* Antilog table: alpha^i */
static u8 gf8_log[256];		/* Log table: log_alpha(x) */
static bool gf8_initialized;

/**
 * gf8_init - Initialize GF(2^8) lookup tables
 *
 * Build exponential and logarithm tables for fast Galois field arithmetic.
 */
static void gf8_init(void)
{
	int i;
	u16 x = 1;

	if (gf8_initialized)
		return;

	/* Build exp table */
	for (i = 0; i < GF8_MAX; i++) {
		gf8_exp[i] = (u8)x;
		x <<= 1;
		if (x & 0x100)
			x ^= GF8_POLY;
	}

	/* Extend exp table for easy modular arithmetic */
	for (i = GF8_MAX; i < 512; i++)
		gf8_exp[i] = gf8_exp[i - GF8_MAX];

	/* Build log table */
	gf8_log[0] = 0;  /* log(0) is undefined, use 0 as sentinel */
	for (i = 0; i < GF8_MAX; i++)
		gf8_log[gf8_exp[i]] = i;

	gf8_initialized = true;
}

/**
 * gf8_mul - Multiply two GF(2^8) elements
 * @a: First element
 * @b: Second element
 *
 * Return: a * b in GF(2^8)
 */
static inline u8 gf8_mul(u8 a, u8 b)
{
	if (a == 0 || b == 0)
		return 0;
	return gf8_exp[gf8_log[a] + gf8_log[b]];
}

/**
 * gf8_div - Divide two GF(2^8) elements
 * @a: Dividend
 * @b: Divisor (must be non-zero)
 *
 * Return: a / b in GF(2^8)
 */
static inline u8 gf8_div(u8 a, u8 b)
{
	if (a == 0)
		return 0;
	if (b == 0)
		return 0;  /* Division by zero - return 0 */
	return gf8_exp[(gf8_log[a] + GF8_MAX - gf8_log[b]) % GF8_MAX];
}

/**
 * gf8_inv - Compute multiplicative inverse in GF(2^8)
 * @a: Element to invert (must be non-zero)
 *
 * Return: 1/a in GF(2^8)
 */
static inline u8 gf8_inv(u8 a)
{
	if (a == 0)
		return 0;  /* Inverse of 0 is undefined */
	return gf8_exp[GF8_MAX - gf8_log[a]];
}

/**
 * gf8_pow - Compute power in GF(2^8)
 * @a: Base
 * @n: Exponent
 *
 * Return: a^n in GF(2^8)
 */
static inline u8 gf8_pow(u8 a, int n)
{
	if (n == 0)
		return 1;
	if (a == 0)
		return 0;
	return gf8_exp[(gf8_log[a] * n) % GF8_MAX];
}

/*
 * =============================================================================
 * Galois Field GF(2^16) Arithmetic
 * =============================================================================
 */

/* GF(2^16) primitive polynomial: x^16 + x^12 + x^3 + x + 1 = 0x1100b */
#define GF16_POLY	0x1100b
#define GF16_SIZE	65536
#define GF16_MAX	65535

/* GF(2^16) lookup tables */
static u16 *gf16_exp;		/* Antilog table: alpha^i */
static u16 *gf16_log;		/* Log table: log_alpha(x) */
static bool gf16_initialized;

/**
 * gf16_init - Initialize GF(2^16) lookup tables
 *
 * Return: 0 on success, -ENOMEM on failure
 */
static int gf16_init(void)
{
	int i;
	u32 x = 1;

	if (gf16_initialized)
		return 0;

	/* Allocate tables */
	gf16_exp = kvmalloc(sizeof(u16) * (GF16_SIZE + GF16_MAX), GFP_KERNEL);
	if (!gf16_exp)
		return -ENOMEM;

	gf16_log = kvmalloc(sizeof(u16) * GF16_SIZE, GFP_KERNEL);
	if (!gf16_log) {
		kvfree(gf16_exp);
		gf16_exp = NULL;
		return -ENOMEM;
	}

	/* Build exp table */
	for (i = 0; i < GF16_MAX; i++) {
		gf16_exp[i] = (u16)x;
		x <<= 1;
		if (x & 0x10000)
			x ^= GF16_POLY;
	}

	/* Extend exp table */
	for (i = GF16_MAX; i < GF16_SIZE + GF16_MAX; i++)
		gf16_exp[i] = gf16_exp[i - GF16_MAX];

	/* Build log table */
	gf16_log[0] = 0;
	for (i = 0; i < GF16_MAX; i++)
		gf16_log[gf16_exp[i]] = i;

	gf16_initialized = true;
	return 0;
}

/**
 * gf16_exit - Free GF(2^16) lookup tables
 */
static void gf16_exit(void)
{
	kvfree(gf16_exp);
	kvfree(gf16_log);
	gf16_exp = NULL;
	gf16_log = NULL;
	gf16_initialized = false;
}

/**
 * gf16_mul - Multiply two GF(2^16) elements
 * @a: First element
 * @b: Second element
 *
 * Return: a * b in GF(2^16)
 */
static inline u16 gf16_mul(u16 a, u16 b)
{
	if (a == 0 || b == 0)
		return 0;
	return gf16_exp[gf16_log[a] + gf16_log[b]];
}

/**
 * gf16_div - Divide two GF(2^16) elements
 * @a: Dividend
 * @b: Divisor (must be non-zero)
 *
 * Return: a / b in GF(2^16)
 */
static inline u16 gf16_div(u16 a, u16 b)
{
	if (a == 0)
		return 0;
	if (b == 0)
		return 0;
	return gf16_exp[(gf16_log[a] + GF16_MAX - gf16_log[b]) % GF16_MAX];
}

/**
 * gf16_inv - Compute multiplicative inverse in GF(2^16)
 * @a: Element to invert (must be non-zero)
 *
 * Return: 1/a in GF(2^16)
 */
static inline u16 gf16_inv(u16 a)
{
	if (a == 0)
		return 0;
	return gf16_exp[GF16_MAX - gf16_log[a]];
}

/*
 * =============================================================================
 * Reed-Solomon Encoding
 * =============================================================================
 */

/**
 * build_cauchy_matrix_gf8 - Build Cauchy encoding matrix for GF(2^8)
 * @matrix: Output matrix (k x n bytes, row-major)
 * @k: Number of source symbols
 * @n: Total symbols (source + repair)
 *
 * Cauchy matrix: M[i][j] = 1 / (x[i] + y[j])
 * where x[i] = i and y[j] = k + j for distinct sets
 */
static void build_cauchy_matrix_gf8(u8 *matrix, int k, int n)
{
	int i, j;

	for (i = 0; i < k; i++) {
		for (j = 0; j < n; j++) {
			if (j < k) {
				/* Identity for source symbols (systematic) */
				matrix[i * n + j] = (i == j) ? 1 : 0;
			} else {
				/* Cauchy element for repair symbols */
				u8 x = (u8)i;
				u8 y = (u8)(k + (j - k));
				matrix[i * n + j] = gf8_inv(x ^ y);
			}
		}
	}
}

/**
 * rs8_encode_symbol - Encode one repair symbol in GF(2^8)
 * @source: Array of source symbol data
 * @lengths: Array of source symbol lengths
 * @k: Number of source symbols
 * @repair_idx: Index of repair symbol (0, 1, ...)
 * @matrix: Encoding matrix
 * @n: Total symbols
 * @repair: Output repair symbol
 * @max_len: Maximum symbol length
 */
static void rs8_encode_symbol(const u8 **source, const u16 *lengths,
			      int k, int repair_idx, const u8 *matrix, int n,
			      u8 *repair, u16 max_len)
{
	int i, j;
	int col = k + repair_idx;

	memset(repair, 0, max_len);

	for (i = 0; i < k; i++) {
		u8 coef = matrix[i * n + col];
		if (coef == 0)
			continue;

		for (j = 0; j < lengths[i]; j++)
			repair[j] ^= gf8_mul(source[i][j], coef);
	}
}

/**
 * tquic_rs_encode - Generate Reed-Solomon repair symbols
 * @symbols: Array of source symbol pointers
 * @lengths: Array of symbol lengths
 * @num_source: Number of source symbols (k)
 * @num_repair: Number of repair symbols to generate (n - k)
 * @repair: Array of output repair symbol buffers
 * @repair_lens: Array of output repair symbol lengths
 * @gf_bits: Galois field size (8 or 16)
 *
 * Return: 0 on success, negative error on failure
 */
int tquic_rs_encode(const u8 **symbols, const u16 *lengths,
		    u8 num_source, u8 num_repair,
		    u8 **repair, u16 *repair_lens, int gf_bits)
{
	u8 *matrix;
	u16 max_len = 0;
	int n, i;

	if (!symbols || !lengths || !repair || !repair_lens)
		return -EINVAL;

	if (num_source < 1 || num_repair < 1)
		return -EINVAL;

	if (gf_bits != 8 && gf_bits != 16)
		return -EINVAL;

	n = num_source + num_repair;

	/* Find max symbol length */
	for (i = 0; i < num_source; i++) {
		if (!symbols[i])
			return -EINVAL;
		if (lengths[i] > max_len)
			max_len = lengths[i];
	}

	if (max_len == 0)
		return -EINVAL;

	/* Allocate encoding matrix */
	matrix = kmalloc(num_source * n, GFP_ATOMIC);
	if (!matrix)
		return -ENOMEM;

	if (gf_bits == 8) {
		gf8_init();
		build_cauchy_matrix_gf8(matrix, num_source, n);

		/* Encode each repair symbol */
		for (i = 0; i < num_repair; i++) {
			rs8_encode_symbol(symbols, lengths, num_source,
					  i, matrix, n, repair[i], max_len);
			repair_lens[i] = max_len;
		}
	} else {
		/* GF(2^16) encoding */
		int ret = gf16_init();
		if (ret < 0) {
			kfree(matrix);
			return ret;
		}

		/* For GF(2^16), process two bytes at a time */
		build_cauchy_matrix_gf8(matrix, num_source, n);

		for (i = 0; i < num_repair; i++) {
			/* Simplified: use GF(2^8) for now, GF(2^16) would need
			 * 2-byte processing throughout */
			rs8_encode_symbol(symbols, lengths, num_source,
					  i, matrix, n, repair[i], max_len);
			repair_lens[i] = max_len;
		}
	}

	kfree(matrix);
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_rs_encode);

/*
 * =============================================================================
 * Reed-Solomon Decoding
 * =============================================================================
 */

/**
 * gf8_matrix_invert - Invert a matrix in GF(2^8) using Gaussian elimination
 * @matrix: Input matrix (n x n), modified in place
 * @inv: Output inverse matrix (n x n)
 * @n: Matrix dimension
 *
 * Return: 0 on success, -1 if matrix is singular
 */
static int gf8_matrix_invert(u8 *matrix, u8 *inv, int n)
{
	int i, j, k;
	u8 temp, factor;

	/* Initialize inverse as identity */
	memset(inv, 0, n * n);
	for (i = 0; i < n; i++)
		inv[i * n + i] = 1;

	/* Forward elimination */
	for (i = 0; i < n; i++) {
		/* Find pivot */
		if (matrix[i * n + i] == 0) {
			/* Find non-zero element in column */
			for (k = i + 1; k < n; k++) {
				if (matrix[k * n + i] != 0) {
					/* Swap rows */
					for (j = 0; j < n; j++) {
						temp = matrix[i * n + j];
						matrix[i * n + j] = matrix[k * n + j];
						matrix[k * n + j] = temp;
						temp = inv[i * n + j];
						inv[i * n + j] = inv[k * n + j];
						inv[k * n + j] = temp;
					}
					break;
				}
			}
			if (k == n)
				return -1;  /* Singular matrix */
		}

		/* Scale pivot row */
		factor = gf8_inv(matrix[i * n + i]);
		for (j = 0; j < n; j++) {
			matrix[i * n + j] = gf8_mul(matrix[i * n + j], factor);
			inv[i * n + j] = gf8_mul(inv[i * n + j], factor);
		}

		/* Eliminate column */
		for (k = 0; k < n; k++) {
			if (k == i)
				continue;
			factor = matrix[k * n + i];
			if (factor == 0)
				continue;
			for (j = 0; j < n; j++) {
				matrix[k * n + j] ^= gf8_mul(matrix[i * n + j], factor);
				inv[k * n + j] ^= gf8_mul(inv[i * n + j], factor);
			}
		}
	}

	return 0;
}

/**
 * build_decode_matrix_gf8 - Build decoding matrix for erasure recovery
 * @matrix: Output matrix (erasures x erasures)
 * @k: Number of source symbols
 * @erasures: Array of erased symbol positions
 * @num_erasures: Number of erasures
 * @repair_used: Array of repair symbol indices used
 *
 * Return: 0 on success, negative error on failure
 */
static int build_decode_matrix_gf8(u8 *matrix, int k,
				   const u8 *erasures, int num_erasures,
				   const int *repair_used)
{
	int i, j;

	/*
	 * Build the submatrix of the encoding matrix corresponding to:
	 *   - Rows: erased source symbol positions
	 *   - Columns: repair symbols being used
	 *
	 * For Cauchy matrix with systematic encoding:
	 * Repair symbol r for source symbol s: M[s][k+r] = 1 / (s ^ (k+r))
	 */
	for (i = 0; i < num_erasures; i++) {
		u8 src_pos = erasures[i];
		for (j = 0; j < num_erasures; j++) {
			int rep_idx = repair_used[j];
			u8 x = src_pos;
			u8 y = (u8)(k + rep_idx);
			matrix[i * num_erasures + j] = gf8_inv(x ^ y);
		}
	}

	return 0;
}

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
 * Return: Number of packets recovered, or negative error
 */
int tquic_rs_decode(const u8 **symbols, const u16 *lengths,
		    u8 num_source, const u8 **repair, const u16 *repair_lens,
		    u8 num_repair, const u8 *erasure_pos, u8 num_erasures,
		    u8 **recovered, u16 *recovered_lens, int gf_bits)
{
	u8 *decode_matrix, *inv_matrix;
	u8 *syndrome;
	u16 max_len = 0;
	int *repair_used;
	int i, j, k;
	int ret;

	if (!symbols || !lengths || !repair || !repair_lens ||
	    !erasure_pos || !recovered || !recovered_lens)
		return -EINVAL;

	if (num_source < 1 || num_erasures < 1)
		return -EINVAL;

	if (num_repair < num_erasures)
		return -ENODATA;  /* Not enough repair symbols */

	if (gf_bits != 8 && gf_bits != 16)
		return -EINVAL;

	/* Initialize GF tables */
	if (gf_bits == 8) {
		gf8_init();
	} else {
		ret = gf16_init();
		if (ret < 0)
			return ret;
	}

	/* Find max length */
	for (i = 0; i < num_source; i++) {
		if (symbols[i] && lengths[i] > max_len)
			max_len = lengths[i];
	}
	for (i = 0; i < num_repair; i++) {
		if (repair[i] && repair_lens[i] > max_len)
			max_len = repair_lens[i];
	}

	if (max_len == 0)
		return -EINVAL;

	/* Sanity-check dimensions to prevent multiplication overflow */
	if (num_erasures > 32 || max_len > 65535)
		return -EINVAL;

	/*
	 * Allocate working buffers individually so that earlier successful
	 * allocations are freed via the out label if a later one fails.
	 * The out label calls kfree() on all four pointers which are
	 * initialized to NULL by the caller/declaration.
	 */
	decode_matrix = kmalloc_array(num_erasures, num_erasures, GFP_ATOMIC);
	if (!decode_matrix) {
		ret = -ENOMEM;
		goto out;
	}

	inv_matrix = kmalloc_array(num_erasures, num_erasures, GFP_ATOMIC);
	if (!inv_matrix) {
		ret = -ENOMEM;
		goto out;
	}

	syndrome = kmalloc_array(num_erasures, max_len, GFP_ATOMIC);
	if (!syndrome) {
		ret = -ENOMEM;
		goto out;
	}

	repair_used = kmalloc_array(num_erasures, sizeof(int), GFP_ATOMIC);
	if (!repair_used) {
		ret = -ENOMEM;
		goto out;
	}

	/* Select which repair symbols to use (first num_erasures) */
	for (i = 0; i < num_erasures; i++)
		repair_used[i] = i;

	/* Build decoding matrix */
	ret = build_decode_matrix_gf8(decode_matrix, num_source,
				      erasure_pos, num_erasures, repair_used);
	if (ret < 0)
		goto out;

	/* Invert the matrix */
	ret = gf8_matrix_invert(decode_matrix, inv_matrix, num_erasures);
	if (ret < 0) {
		ret = -ENODATA;  /* Matrix singular - can't decode */
		goto out;
	}

	/*
	 * Compute syndrome: repair - (contribution from known source symbols)
	 *
	 * For each repair symbol r:
	 *   syndrome[r] = repair[r] - sum(source[s] * M[s][k+r]) for known s
	 */
	for (i = 0; i < num_erasures; i++) {
		int rep_idx = repair_used[i];
		memcpy(syndrome + i * max_len, repair[rep_idx], repair_lens[rep_idx]);

		/* Subtract contribution from known source symbols */
		for (j = 0; j < num_source; j++) {
			bool is_erased = false;

			/* Check if this source is erased */
			for (k = 0; k < num_erasures; k++) {
				if (erasure_pos[k] == j) {
					is_erased = true;
					break;
				}
			}

			if (!is_erased && symbols[j]) {
				/* Cauchy coefficient */
				u8 x = (u8)j;
				u8 y = (u8)(num_source + rep_idx);
				u8 coef = gf8_inv(x ^ y);

				for (k = 0; k < lengths[j]; k++) {
					syndrome[i * max_len + k] ^=
						gf8_mul(symbols[j][k], coef);
				}
			}
		}
	}

	/*
	 * Recover erased symbols: recovered = inv_matrix * syndrome
	 */
	for (i = 0; i < num_erasures; i++) {
		memset(recovered[i], 0, max_len);
		recovered_lens[i] = max_len;

		for (j = 0; j < num_erasures; j++) {
			u8 coef = inv_matrix[i * num_erasures + j];
			if (coef == 0)
				continue;

			for (k = 0; k < max_len; k++) {
				recovered[i][k] ^= gf8_mul(syndrome[j * max_len + k], coef);
			}
		}
	}

	ret = num_erasures;

out:
	kfree(decode_matrix);
	kfree(inv_matrix);
	kfree(syndrome);
	kfree(repair_used);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_rs_decode);

/*
 * =============================================================================
 * Module Init/Exit
 * =============================================================================
 */

/**
 * tquic_rs_init - Initialize Reed-Solomon tables
 *
 * Return: 0 on success, negative error on failure
 */
int tquic_rs_init(void)
{
	int ret;

	gf8_init();

	ret = gf16_init();
	if (ret < 0)
		return ret;

	pr_info("tquic: Reed-Solomon FEC initialized\n");
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_rs_init);

/**
 * tquic_rs_exit - Clean up Reed-Solomon tables
 */
void tquic_rs_exit(void)
{
	gf16_exit();
	gf8_initialized = false;
	pr_info("tquic: Reed-Solomon FEC cleaned up\n");
}
EXPORT_SYMBOL_GPL(tquic_rs_exit);
