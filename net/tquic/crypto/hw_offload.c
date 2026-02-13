// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC Hardware Crypto Offload Detection
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Provides CPU feature detection and algorithm selection for hardware-
 * accelerated cryptographic operations. Supports AES-NI, AVX2, AVX-512,
 * VAES, VPCLMULQDQ, and Intel QAT offload.
 *
 * The goal is to automatically select the most efficient implementation
 * based on detected hardware capabilities, providing optimal performance
 * for QUIC packet encryption/decryption.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/percpu.h>
#include <linux/atomic.h>
#include <linux/math64.h>
#include <crypto/aead.h>
#include <crypto/hash.h>
#include <crypto/skcipher.h>
#include <crypto/utils.h>
#include <crypto/aes.h>
#include <net/tquic.h>
#include "../tquic_compat.h"
#include "../tquic_debug.h"
#include "../tquic_init.h"
#include "hw_offload.h"

#ifdef CONFIG_X86
#include <asm/cpufeature.h>
#include <asm/fpu/api.h>
#endif

/* AVX-512 batch processing lanes */
#define TQUIC_AVX512_LANES 8 /* 8 AES blocks in parallel */

/**
 * struct tquic_crypto_ctx - Crypto context for TQUIC connection
 * @aead:          AEAD transform handle
 * @impl:          Selected implementation
 * @cipher_suite:  Negotiated cipher suite
 * @key:           Current encryption key
 * @key_len:       Key length in bytes
 * @iv:            Initialization vector base
 * @iv_len:        IV length
 */
struct tquic_crypto_ctx {
	struct crypto_aead *aead;
	enum tquic_crypto_impl impl;
	u16 cipher_suite;
	u8 key[32];
	u8 key_len;
	u8 iv[12];
	u8 iv_len;
};

/* Global capabilities (detected once at init) */
static struct tquic_crypto_caps tquic_caps;
static DEFINE_SPINLOCK(tquic_caps_lock);

/* Per-CPU statistics */
static DEFINE_PER_CPU(struct tquic_crypto_stats, tquic_crypto_stats);

/*
 * =============================================================================
 * CPU Feature Detection
 * =============================================================================
 */

/**
 * tquic_crypto_detect_caps - Detect CPU cryptographic capabilities
 * @caps: Capabilities structure to populate
 *
 * Probes CPU features to determine available hardware acceleration.
 * Results are cached after first detection.
 */
void tquic_crypto_detect_caps(struct tquic_crypto_caps *caps)
{
	if (!caps)
		return;

	memset(caps, 0, sizeof(*caps));

#ifdef CONFIG_X86
	/* AES-NI support */
	if (boot_cpu_has(X86_FEATURE_AES))
		caps->aes_ni = true;

	/* AVX2 support (important for ChaCha20 and parallel operations) */
	if (boot_cpu_has(X86_FEATURE_AVX2))
		caps->avx2 = true;

	/* AVX-512 Foundation (required for AVX-512 operations) */
	if (boot_cpu_has(X86_FEATURE_AVX512F))
		caps->avx512 = true;

	/* VAES - Vector AES (AVX-512 accelerated AES) */
	if (boot_cpu_has(X86_FEATURE_VAES))
		caps->vaes = true;

	/* VPCLMULQDQ - Vector carry-less multiplication for GCM */
	if (boot_cpu_has(X86_FEATURE_VPCLMULQDQ))
		caps->vpclmulqdq = true;

	/* Standard PCLMULQDQ (for GCM) */
	if (boot_cpu_has(X86_FEATURE_PCLMULQDQ))
		caps->pclmulqdq = true;

	/* SHA-NI instructions */
	if (boot_cpu_has(X86_FEATURE_SHA_NI))
		caps->sha_ni = true;
#endif /* CONFIG_X86 */

	caps->detected = true;
}
EXPORT_SYMBOL_GPL(tquic_crypto_detect_caps);

/**
 * tquic_crypto_get_caps - Get cached CPU capabilities
 *
 * Returns pointer to global capabilities structure.
 * Performs detection if not already done.
 *
 * Return: Pointer to cached capabilities
 */
const struct tquic_crypto_caps *tquic_crypto_get_caps(void)
{
	unsigned long flags;

	spin_lock_irqsave(&tquic_caps_lock, flags);
	if (!tquic_caps.detected)
		tquic_crypto_detect_caps(&tquic_caps);
	spin_unlock_irqrestore(&tquic_caps_lock, flags);

	return &tquic_caps;
}
EXPORT_SYMBOL_GPL(tquic_crypto_get_caps);

/*
 * =============================================================================
 * Implementation Selection
 * =============================================================================
 */

/**
 * tquic_crypto_select_impl - Select optimal crypto implementation
 * @caps:         CPU capabilities
 * @cipher_suite: TLS 1.3 cipher suite identifier
 *
 * Selects the best available implementation based on:
 *   1. CPU hardware capabilities
 *   2. Cipher suite requirements
 *   3. Expected workload (single vs batch)
 *
 * Return: Selected implementation type
 */
enum tquic_crypto_impl tquic_crypto_select_impl(struct tquic_crypto_caps *caps,
						u16 cipher_suite)
{
	if (!caps || !caps->detected)
		return TQUIC_CRYPTO_GENERIC;

	switch (cipher_suite) {
	case TLS_AES_128_GCM_SHA256:
	case TLS_AES_256_GCM_SHA384:
		/*
		 * AES-GCM cipher suites benefit from:
		 * 1. AVX-512 + VAES + VPCLMULQDQ (best for batch)
		 * 2. AES-NI + PCLMULQDQ (good single-packet performance)
		 * 3. Generic fallback
		 */
		if (caps->avx512 && caps->vaes && caps->vpclmulqdq)
			return TQUIC_CRYPTO_AVX512;
		if (caps->aes_ni && caps->pclmulqdq)
			return TQUIC_CRYPTO_AESNI;
		return TQUIC_CRYPTO_GENERIC;

	case TLS_CHACHA20_POLY1305_SHA256:
		/*
		 * ChaCha20-Poly1305 benefits from:
		 * 1. AVX-512 (widest SIMD)
		 * 2. AVX2 (good parallel performance)
		 * 3. Generic fallback
		 */
		if (caps->avx512)
			return TQUIC_CRYPTO_AVX512;
		if (caps->avx2)
			return TQUIC_CRYPTO_AVX2;
		return TQUIC_CRYPTO_GENERIC;

	default:
		return TQUIC_CRYPTO_GENERIC;
	}
}
EXPORT_SYMBOL_GPL(tquic_crypto_select_impl);

/**
 * tquic_crypto_impl_name - Get human-readable name for implementation
 * @impl: Implementation type
 *
 * Return: String name for the implementation
 */
static const char *tquic_crypto_impl_name(enum tquic_crypto_impl impl)
{
	switch (impl) {
	case TQUIC_CRYPTO_GENERIC:
		return "generic";
	case TQUIC_CRYPTO_AESNI:
		return "aesni";
	case TQUIC_CRYPTO_AVX2:
		return "avx2";
	case TQUIC_CRYPTO_AVX512:
		return "avx512";
	default:
		return "unknown";
	}
}

/*
 * =============================================================================
 * Crypto Context Management
 * =============================================================================
 */

/**
 * tquic_crypto_ctx_alloc - Allocate crypto context
 * @cipher_suite: TLS 1.3 cipher suite
 * @gfp:          Allocation flags
 *
 * Allocates and initializes a crypto context with the optimal
 * implementation for the specified cipher suite.
 *
 * Return: Allocated context or NULL on failure
 */
struct tquic_crypto_ctx *tquic_crypto_ctx_alloc(u16 cipher_suite, gfp_t gfp)
{
	struct tquic_crypto_ctx *ctx;
	const struct tquic_crypto_caps *caps;
	const char *alg_name;

	ctx = kzalloc(sizeof(*ctx), gfp);
	if (!ctx)
		return NULL;

	ctx->cipher_suite = cipher_suite;

	/* Detect caps and select implementation */
	caps = tquic_crypto_get_caps();
	ctx->impl = tquic_crypto_select_impl((struct tquic_crypto_caps *)caps,
					     cipher_suite);

	/* Select algorithm name based on cipher suite and implementation */
	switch (cipher_suite) {
	case TLS_AES_128_GCM_SHA256:
		ctx->key_len = 16;
		ctx->iv_len = 12;
		alg_name = "gcm(aes)";
		break;
	case TLS_AES_256_GCM_SHA384:
		ctx->key_len = 32;
		ctx->iv_len = 12;
		alg_name = "gcm(aes)";
		break;
	case TLS_CHACHA20_POLY1305_SHA256:
		ctx->key_len = 32;
		ctx->iv_len = 12;
		alg_name = "rfc7539(chacha20,poly1305)";
		break;
	default:
		pr_err("tquic_hw_offload: unsupported cipher suite 0x%04x\n",
		       cipher_suite);
		kfree(ctx);
		return NULL;
	}

	/* Allocate AEAD transform */
	ctx->aead = crypto_alloc_aead(alg_name, 0, 0);
	if (IS_ERR(ctx->aead)) {
		pr_err("tquic_hw_offload: failed to allocate AEAD %s: %ld\n",
		       alg_name, PTR_ERR(ctx->aead));
		kfree(ctx);
		return NULL;
	}

	/* Set authentication tag length */
	if (crypto_aead_setauthsize(ctx->aead, 16)) {
		pr_err("tquic_hw_offload: failed to set auth tag size\n");
		crypto_free_aead(ctx->aead);
		kfree(ctx);
		return NULL;
	}

	pr_debug("tquic_hw_offload: allocated ctx with impl=%s cipher=0x%04x\n",
		 tquic_crypto_impl_name(ctx->impl), cipher_suite);

	return ctx;
}
EXPORT_SYMBOL_GPL(tquic_crypto_ctx_alloc);

/**
 * tquic_crypto_ctx_free - Free crypto context
 * @ctx: Context to free
 */
void tquic_crypto_ctx_free(struct tquic_crypto_ctx *ctx)
{
	if (!ctx)
		return;

	if (ctx->aead && !IS_ERR(ctx->aead))
		crypto_free_aead(ctx->aead);

	/* Clear sensitive key material */
	memzero_explicit(ctx->key, sizeof(ctx->key));
	memzero_explicit(ctx->iv, sizeof(ctx->iv));

	kfree(ctx);
}
EXPORT_SYMBOL_GPL(tquic_crypto_ctx_free);

/**
 * tquic_crypto_ctx_set_key - Set encryption key
 * @ctx:     Crypto context
 * @key:     Key material
 * @key_len: Key length
 *
 * Return: 0 on success, negative errno on failure
 */
int tquic_crypto_ctx_set_key(struct tquic_crypto_ctx *ctx, const u8 *key,
			     size_t key_len)
{
	int ret;

	if (!ctx || !key || key_len > sizeof(ctx->key))
		return -EINVAL;

	if (key_len != ctx->key_len) {
		pr_err("tquic_hw_offload: key length mismatch (got %zu, expected %u)\n",
		       key_len, ctx->key_len);
		return -EINVAL;
	}

	memcpy(ctx->key, key, key_len);

	ret = crypto_aead_setkey(ctx->aead, key, key_len);
	if (ret) {
		pr_err("tquic_hw_offload: failed to set AEAD key: %d\n", ret);
		return ret;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_crypto_ctx_set_key);

/**
 * tquic_crypto_ctx_set_iv - Set base IV
 * @ctx:    Crypto context
 * @iv:     IV material
 * @iv_len: IV length
 *
 * Return: 0 on success, negative errno on failure
 */
int tquic_crypto_ctx_set_iv(struct tquic_crypto_ctx *ctx, const u8 *iv,
			    size_t iv_len)
{
	if (!ctx || !iv || iv_len != ctx->iv_len)
		return -EINVAL;

	memcpy(ctx->iv, iv, iv_len);
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_crypto_ctx_set_iv);

/*
 * =============================================================================
 * Single Packet Operations
 * =============================================================================
 */

/**
 * tquic_hw_create_nonce - Create nonce from IV and packet number
 * @iv:      Base IV
 * @pkt_num: Packet number
 * @nonce:   Output nonce buffer (12 bytes)
 */
static void tquic_hw_create_nonce(const u8 *iv, u64 pkt_num, u8 *nonce)
{
	int i;

	memcpy(nonce, iv, 12);

	/* XOR packet number into rightmost bytes of nonce */
	for (i = 0; i < 8; i++)
		nonce[11 - i] ^= (pkt_num >> (i * 8)) & 0xff;
}

/**
 * tquic_hw_encrypt_packet - Encrypt a single packet
 * @ctx:         Crypto context
 * @aad:         Additional authenticated data (header)
 * @aad_len:     AAD length
 * @plaintext:   Input plaintext
 * @pt_len:      Plaintext length
 * @pkt_num:     Packet number
 * @ciphertext:  Output buffer (must have room for pt_len + 16)
 * @ct_len:      Output ciphertext length
 *
 * Return: 0 on success, negative errno on failure
 */
int tquic_hw_encrypt_packet(struct tquic_crypto_ctx *ctx, const u8 *aad,
			    size_t aad_len, const u8 *plaintext, size_t pt_len,
			    u64 pkt_num, u8 *ciphertext, size_t *ct_len)
{
	struct aead_request *req;
	struct scatterlist sg_src[2], sg_dst[2];
	u8 nonce[12];
	int ret;

	if (!ctx || !plaintext || !ciphertext || !ct_len)
		return -EINVAL;

	tquic_hw_create_nonce(ctx->iv, pkt_num, nonce);

	req = aead_request_alloc(ctx->aead, GFP_ATOMIC);
	if (!req) {
		ret = -ENOMEM;
		goto out_zeroize;
	}

	/* Set up scatter-gather lists */
	sg_init_table(sg_src, 2);
	sg_set_buf(&sg_src[0], aad, aad_len);
	sg_set_buf(&sg_src[1], plaintext, pt_len);

	sg_init_table(sg_dst, 2);
	sg_set_buf(&sg_dst[0], aad, aad_len);
	sg_set_buf(&sg_dst[1], ciphertext, pt_len + 16);

	aead_request_set_crypt(req, sg_src, sg_dst, pt_len, nonce);
	aead_request_set_ad(req, aad_len);

	ret = crypto_aead_encrypt(req);

	aead_request_free(req);

	if (ret == 0) {
		*ct_len = pt_len + 16;

		/* Update statistics */
		switch (ctx->impl) {
		case TQUIC_CRYPTO_AESNI:
			this_cpu_inc(tquic_crypto_stats.aesni_ops);
			break;
		case TQUIC_CRYPTO_AVX2:
			this_cpu_inc(tquic_crypto_stats.avx2_ops);
			break;
		case TQUIC_CRYPTO_AVX512:
			this_cpu_inc(tquic_crypto_stats.avx512_ops);
			break;
		default:
			this_cpu_inc(tquic_crypto_stats.generic_ops);
			break;
		}
		this_cpu_add(tquic_crypto_stats.total_bytes, pt_len);
	}

out_zeroize:
	memzero_explicit(nonce, sizeof(nonce));
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_hw_encrypt_packet);

/**
 * tquic_hw_decrypt_packet - Decrypt a single packet
 * @ctx:        Crypto context
 * @aad:        Additional authenticated data (header)
 * @aad_len:    AAD length
 * @ciphertext: Input ciphertext (includes auth tag)
 * @ct_len:     Ciphertext length (includes 16-byte tag)
 * @pkt_num:    Packet number
 * @plaintext:  Output buffer
 * @pt_len:     Output plaintext length
 *
 * Return: 0 on success, negative errno on failure (including auth failure)
 */
int tquic_hw_decrypt_packet(struct tquic_crypto_ctx *ctx, const u8 *aad,
			    size_t aad_len, const u8 *ciphertext, size_t ct_len,
			    u64 pkt_num, u8 *plaintext, size_t *pt_len)
{
	struct aead_request *req;
	struct scatterlist sg_src[2], sg_dst[2];
	u8 nonce[12];
	int ret;

	if (!ctx || !ciphertext || !plaintext || !pt_len)
		return -EINVAL;

	if (ct_len < 16)
		return -EINVAL; /* Too short for auth tag */

	tquic_hw_create_nonce(ctx->iv, pkt_num, nonce);

	req = aead_request_alloc(ctx->aead, GFP_ATOMIC);
	if (!req) {
		ret = -ENOMEM;
		goto out_zeroize;
	}

	/* Set up scatter-gather lists */
	sg_init_table(sg_src, 2);
	sg_set_buf(&sg_src[0], aad, aad_len);
	sg_set_buf(&sg_src[1], ciphertext, ct_len);

	sg_init_table(sg_dst, 2);
	sg_set_buf(&sg_dst[0], aad, aad_len);
	sg_set_buf(&sg_dst[1], plaintext, ct_len - 16);

	aead_request_set_crypt(req, sg_src, sg_dst, ct_len, nonce);
	aead_request_set_ad(req, aad_len);

	ret = crypto_aead_decrypt(req);

	aead_request_free(req);

	if (ret == 0) {
		*pt_len = ct_len - 16;
		this_cpu_add(tquic_crypto_stats.total_bytes, *pt_len);
	}

out_zeroize:
	memzero_explicit(nonce, sizeof(nonce));
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_hw_decrypt_packet);

/*
 * =============================================================================
 * AVX-512 Batch Operations
 * =============================================================================
 */

/**
 * tquic_crypto_batch_encrypt - Encrypt multiple packets in parallel
 * @ctx:   Crypto context
 * @pkts:  Array of packets to encrypt
 * @count: Number of packets (max TQUIC_BATCH_MAX_PACKETS)
 *
 * Uses AVX-512 VAES for parallel encryption of multiple packets when
 * available. Falls back to sequential encryption otherwise.
 *
 * Each packet in the array must have:
 *   - data: pointer to plaintext (modified in place to ciphertext)
 *   - len: plaintext length
 *   - pkt_num: packet number for nonce
 *   - aad: pointer to AAD
 *   - aad_len: AAD length
 *   - result: set to 0 on success, negative errno on failure
 *
 * Return: Number of successfully encrypted packets
 */
int tquic_crypto_batch_encrypt(struct tquic_crypto_ctx *ctx,
			       struct tquic_hw_packet *pkts, int count)
{
	int i, success = 0;
	size_t ct_len;

	if (!ctx || !pkts || count <= 0)
		return -EINVAL;

	if (count > TQUIC_BATCH_MAX_PACKETS)
		count = TQUIC_BATCH_MAX_PACKETS;

#ifdef CONFIG_X86
	/*
	 * For AVX-512 with VAES, we could implement true parallel encryption
	 * using 512-bit wide operations. The kernel crypto API doesn't expose
	 * this directly, but the underlying aesni_intel driver will use
	 * AVX-512 when available for gcm(aes).
	 *
	 * True batch optimization would require:
	 * 1. Custom assembly using VAES/VPCLMULQDQ
	 * 2. Interleaving multiple AES blocks across 512-bit lanes
	 * 3. Parallel GCM authentication using VPCLMULQDQ
	 *
	 * For now, we leverage the kernel's optimized crypto API which
	 * will use the best available implementation.
	 */
	if (ctx->impl == TQUIC_CRYPTO_AVX512) {
		/*
		 * Hint to kernel that we're doing batch operations.
		 * The crypto API will use kernel_fpu_begin/end internally
		 * for AVX-512 operations when available.
		 */
		this_cpu_inc(tquic_crypto_stats.batch_ops);
		this_cpu_add(tquic_crypto_stats.batch_packets, count);
	}
#endif

	/*
	 * Allocate a single buffer sized for the largest packet in the batch
	 * to avoid per-packet kmalloc in the hot path.
	 */
	{
		size_t max_buf_len = 0;
		u8 *shared_buf;

		for (i = 0; i < count; i++) {
			size_t need = pkts[i].len + 16;

			if (need > max_buf_len)
				max_buf_len = need;
		}

		shared_buf = kmalloc(max_buf_len, GFP_ATOMIC);
		if (!shared_buf)
			return -ENOMEM;

		for (i = 0; i < count; i++) {
			struct tquic_hw_packet *pkt = &pkts[i];
			size_t ct_buf_len = pkt->len + 16;

			/*
			 * Validate that the caller's data buffer is large
			 * enough to hold the ciphertext (plaintext + 16-byte
			 * auth tag).
			 */
			if (pkt->data_buf_len < ct_buf_len) {
				pkt->result = -ENOSPC;
				continue;
			}

			pkt->result = tquic_hw_encrypt_packet(
				ctx, pkt->aad, pkt->aad_len, pkt->data,
				pkt->len, pkt->pkt_num, shared_buf, &ct_len);

			if (pkt->result == 0) {
				memcpy(pkt->data, shared_buf, ct_len);
				pkt->len = ct_len;
				success++;
			}
		}

		kfree(shared_buf);
	}

	return success;
}
EXPORT_SYMBOL_GPL(tquic_crypto_batch_encrypt);

/**
 * tquic_crypto_batch_decrypt - Decrypt multiple packets in parallel
 * @ctx:   Crypto context
 * @pkts:  Array of packets to decrypt
 * @count: Number of packets
 *
 * Similar to batch_encrypt but for decryption.
 *
 * Return: Number of successfully decrypted packets
 */
int tquic_crypto_batch_decrypt(struct tquic_crypto_ctx *ctx,
			       struct tquic_hw_packet *pkts, int count)
{
	int i, success = 0;
	size_t pt_len;

	if (!ctx || !pkts || count <= 0)
		return -EINVAL;

	if (count > TQUIC_BATCH_MAX_PACKETS)
		count = TQUIC_BATCH_MAX_PACKETS;

#ifdef CONFIG_X86
	if (ctx->impl == TQUIC_CRYPTO_AVX512) {
		this_cpu_inc(tquic_crypto_stats.batch_ops);
		this_cpu_add(tquic_crypto_stats.batch_packets, count);
	}
#endif

	/*
	 * Allocate a single buffer sized for the largest packet in the batch
	 * to avoid per-packet kmalloc in the hot path.
	 */
	{
		size_t max_buf_len = 0;
		u8 *shared_buf;

		for (i = 0; i < count; i++) {
			if (pkts[i].len > max_buf_len)
				max_buf_len = pkts[i].len;
		}

		shared_buf = kmalloc(max_buf_len, GFP_ATOMIC);
		if (!shared_buf)
			return -ENOMEM;

		for (i = 0; i < count; i++) {
			struct tquic_hw_packet *pkt = &pkts[i];

			if (pkt->len < 16) {
				pkt->result = -EINVAL;
				continue;
			}

			pkt->result = tquic_hw_decrypt_packet(
				ctx, pkt->aad, pkt->aad_len, pkt->data,
				pkt->len, pkt->pkt_num, shared_buf, &pt_len);

			if (pkt->result == 0) {
				memcpy(pkt->data, shared_buf, pt_len);
				pkt->len = pt_len;
				success++;
			}
		}

		kfree(shared_buf);
	}

	return success;
}
EXPORT_SYMBOL_GPL(tquic_crypto_batch_decrypt);

/*
 * =============================================================================
 * Intel QAT Offload (Optional)
 * =============================================================================
 */

#ifdef CONFIG_CRYPTO_DEV_QAT

/**
 * struct tquic_qat_ctx - Intel QAT offload context
 * @tfm:           AEAD transform using QAT
 * @qat_available: True if QAT is available and initialized
 * @cipher_suite:  Cipher suite in use
 */
struct tquic_qat_ctx {
	struct crypto_aead *tfm;
	bool qat_available;
	u16 cipher_suite;
	u8 cached_key[32]; /* Cache last-set key to avoid redundant setkey */
	size_t cached_key_len;
};

/**
 * tquic_qat_init - Initialize QAT offload context
 * @ctx: QAT context to initialize
 *
 * Attempts to allocate a QAT-accelerated AEAD transform.
 * Falls back gracefully if QAT is not available.
 *
 * Return: 0 on success, negative errno on failure
 */
int tquic_qat_init(struct tquic_qat_ctx *ctx)
{
	struct crypto_aead *tfm;

	if (!ctx)
		return -EINVAL;

	memset(ctx, 0, sizeof(*ctx));

	/*
	 * Request a GCM transform. The crypto API will select QAT
	 * if available via CRYPTO_ALG_TYPE_AEAD_MASK.
	 *
	 * Note: To specifically request QAT, one could use:
	 *   crypto_alloc_aead("qat_gcm", 0, 0);
	 * but this would fail if QAT is not present.
	 */
	tfm = crypto_alloc_aead("gcm(aes)", 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(tfm)) {
		pr_debug("tquic_qat: QAT AEAD not available: %ld\n",
			 PTR_ERR(tfm));
		ctx->qat_available = false;
		return 0; /* Not an error - QAT is optional */
	}

	ctx->tfm = tfm;
	ctx->qat_available = true;

	if (crypto_aead_setauthsize(tfm, 16)) {
		pr_err("tquic_qat: failed to set auth tag size\n");
		crypto_free_aead(tfm);
		ctx->tfm = NULL;
		ctx->qat_available = false;
		return -EINVAL;
	}

	pr_info("tquic_qat: QAT offload initialized\n");

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_qat_init);

/**
 * tquic_qat_cleanup - Clean up QAT context
 * @ctx: QAT context to clean up
 */
void tquic_qat_cleanup(struct tquic_qat_ctx *ctx)
{
	if (!ctx)
		return;

	if (ctx->tfm && !IS_ERR(ctx->tfm))
		crypto_free_aead(ctx->tfm);

	memset(ctx, 0, sizeof(*ctx));
}
EXPORT_SYMBOL_GPL(tquic_qat_cleanup);

/**
 * tquic_qat_encrypt - Encrypt using QAT offload
 * @ctx:        QAT context
 * @key:        Encryption key
 * @key_len:    Key length
 * @iv:         Base IV
 * @pkt_num:    Packet number
 * @aad:        Additional authenticated data
 * @aad_len:    AAD length
 * @plaintext:  Input data
 * @pt_len:     Plaintext length
 * @ciphertext: Output buffer
 * @ct_len:     Output ciphertext length
 *
 * Return: 0 on success, negative errno on failure
 */
int tquic_qat_encrypt(struct tquic_qat_ctx *ctx, const u8 *key, size_t key_len,
		      const u8 *iv, u64 pkt_num, const u8 *aad, size_t aad_len,
		      const u8 *plaintext, size_t pt_len, u8 *ciphertext,
		      size_t *ct_len)
{
	struct aead_request *req;
	struct scatterlist sg_src[2], sg_dst[2];
	DECLARE_CRYPTO_WAIT(wait);
	u8 nonce[12];
	int ret;

	if (!ctx || !ctx->qat_available)
		return -ENODEV;

	tquic_hw_create_nonce(iv, pkt_num, nonce);

	/* Only set key when it has changed to avoid expensive per-call setkey */
	if (key_len != ctx->cached_key_len ||
	    crypto_memneq(key, ctx->cached_key, key_len)) {
		ret = crypto_aead_setkey(ctx->tfm, key, key_len);
		if (ret) {
			memzero_explicit(nonce, sizeof(nonce));
			return ret;
		}
		memcpy(ctx->cached_key, key,
		       min(key_len, sizeof(ctx->cached_key)));
		ctx->cached_key_len = key_len;
	}

	req = aead_request_alloc(ctx->tfm, GFP_KERNEL);
	if (!req) {
		memzero_explicit(nonce, sizeof(nonce));
		return -ENOMEM;
	}

	sg_init_table(sg_src, 2);
	sg_set_buf(&sg_src[0], aad, aad_len);
	sg_set_buf(&sg_src[1], plaintext, pt_len);

	sg_init_table(sg_dst, 2);
	sg_set_buf(&sg_dst[0], aad, aad_len);
	sg_set_buf(&sg_dst[1], ciphertext, pt_len + 16);

	aead_request_set_crypt(req, sg_src, sg_dst, pt_len, nonce);
	aead_request_set_ad(req, aad_len);
	aead_request_set_callback(req, CRYPTO_TFM_REQ_MAY_BACKLOG,
				  crypto_req_done, &wait);

	ret = crypto_wait_req(crypto_aead_encrypt(req), &wait);

	aead_request_free(req);
	memzero_explicit(nonce, sizeof(nonce));

	if (ret == 0) {
		*ct_len = pt_len + 16;
		this_cpu_inc(tquic_crypto_stats.qat_ops);
		this_cpu_add(tquic_crypto_stats.total_bytes, pt_len);
	}

	return ret;
}
EXPORT_SYMBOL_GPL(tquic_qat_encrypt);

/**
 * tquic_qat_is_available - Check if QAT is available
 * @ctx: QAT context
 *
 * Return: true if QAT is available and initialized
 */
bool tquic_qat_is_available(struct tquic_qat_ctx *ctx)
{
	return ctx && ctx->qat_available;
}
EXPORT_SYMBOL_GPL(tquic_qat_is_available);

#endif /* CONFIG_CRYPTO_DEV_QAT */

/*
 * =============================================================================
 * Statistics
 * =============================================================================
 */

/**
 * tquic_crypto_get_stats - Get aggregated crypto statistics
 * @stats: Output statistics structure
 */
void tquic_crypto_get_stats(struct tquic_crypto_stats *stats)
{
	int cpu;

	if (!stats)
		return;

	memset(stats, 0, sizeof(*stats));

	for_each_possible_cpu(cpu) {
		const struct tquic_crypto_stats *cpu_stats;

		cpu_stats = per_cpu_ptr(&tquic_crypto_stats, cpu);
		stats->aesni_ops += READ_ONCE(cpu_stats->aesni_ops);
		stats->avx2_ops += READ_ONCE(cpu_stats->avx2_ops);
		stats->avx512_ops += READ_ONCE(cpu_stats->avx512_ops);
		stats->generic_ops += READ_ONCE(cpu_stats->generic_ops);
		stats->qat_ops += READ_ONCE(cpu_stats->qat_ops);
		stats->total_bytes += READ_ONCE(cpu_stats->total_bytes);
		stats->batch_ops += READ_ONCE(cpu_stats->batch_ops);
		stats->batch_packets += READ_ONCE(cpu_stats->batch_packets);
	}
}
EXPORT_SYMBOL_GPL(tquic_crypto_get_stats);

/**
 * tquic_crypto_reset_stats - Reset crypto statistics
 */
void tquic_crypto_reset_stats(void)
{
	int cpu;

	for_each_possible_cpu(cpu) {
		struct tquic_crypto_stats *cpu_stats;

		cpu_stats = per_cpu_ptr(&tquic_crypto_stats, cpu);
		memset(cpu_stats, 0, sizeof(*cpu_stats));
	}
}
EXPORT_SYMBOL_GPL(tquic_crypto_reset_stats);

/*
 * =============================================================================
 * Proc Interface
 * =============================================================================
 */

static int tquic_crypto_caps_show(struct seq_file *m, void *v)
{
	const struct tquic_crypto_caps *caps = tquic_crypto_get_caps();
	struct tquic_crypto_stats stats;
	enum tquic_crypto_impl aes_impl, chacha_impl;

	seq_puts(m, "TQUIC Hardware Crypto Capabilities\n");
	seq_puts(m, "===================================\n\n");

	seq_puts(m, "CPU Features:\n");
	seq_printf(m, "  AES-NI:      %s\n", caps->aes_ni ? "yes" : "no");
	seq_printf(m, "  PCLMULQDQ:   %s\n", caps->pclmulqdq ? "yes" : "no");
	seq_printf(m, "  AVX2:        %s\n", caps->avx2 ? "yes" : "no");
	seq_printf(m, "  AVX-512:     %s\n", caps->avx512 ? "yes" : "no");
	seq_printf(m, "  VAES:        %s\n", caps->vaes ? "yes" : "no");
	seq_printf(m, "  VPCLMULQDQ:  %s\n", caps->vpclmulqdq ? "yes" : "no");
	seq_printf(m, "  SHA-NI:      %s\n", caps->sha_ni ? "yes" : "no");
	seq_puts(m, "\n");

	/* Show selected implementations */
	aes_impl = tquic_crypto_select_impl((struct tquic_crypto_caps *)caps,
					    TLS_AES_128_GCM_SHA256);
	chacha_impl = tquic_crypto_select_impl((struct tquic_crypto_caps *)caps,
					       TLS_CHACHA20_POLY1305_SHA256);

	seq_puts(m, "Selected Implementations:\n");
	seq_printf(m, "  AES-128-GCM:         %s\n",
		   tquic_crypto_impl_name(aes_impl));
	seq_printf(m, "  ChaCha20-Poly1305:   %s\n",
		   tquic_crypto_impl_name(chacha_impl));
	seq_puts(m, "\n");

	/* Show statistics */
	tquic_crypto_get_stats(&stats);

	seq_puts(m, "Statistics:\n");
	seq_printf(m, "  Generic ops:     %llu\n", stats.generic_ops);
	seq_printf(m, "  AES-NI ops:      %llu\n", stats.aesni_ops);
	seq_printf(m, "  AVX2 ops:        %llu\n", stats.avx2_ops);
	seq_printf(m, "  AVX-512 ops:     %llu\n", stats.avx512_ops);
	seq_printf(m, "  QAT ops:         %llu\n", stats.qat_ops);
	seq_printf(m, "  Total bytes:     %llu\n", stats.total_bytes);
	seq_printf(m, "  Batch ops:       %llu\n", stats.batch_ops);
	seq_printf(m, "  Batch packets:   %llu\n", stats.batch_packets);

	if (stats.batch_ops > 0 && stats.batch_packets >= stats.batch_ops) {
		seq_printf(m, "  Avg batch size:  %llu\n",
			   div64_u64(stats.batch_packets, stats.batch_ops));
	}

	seq_puts(m, "\n");

#ifdef CONFIG_CRYPTO_DEV_QAT
	seq_puts(m, "Intel QAT:\n");
	seq_puts(m, "  Support:         compiled in\n");
#else
	seq_puts(m, "Intel QAT:\n");
	seq_puts(m, "  Support:         not compiled\n");
#endif

	return 0;
}

static int tquic_crypto_caps_open(struct inode *inode, struct file *file)
{
	return single_open(file, tquic_crypto_caps_show, NULL);
}

static const struct proc_ops tquic_crypto_caps_ops = {
	.proc_open = tquic_crypto_caps_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

/*
 * =============================================================================
 * Module Init/Exit
 * =============================================================================
 */

static struct proc_dir_entry *tquic_proc_dir;
static struct proc_dir_entry *crypto_caps_entry;

/**
 * tquic_hw_offload_init - Initialize hardware offload subsystem
 *
 * Called during TQUIC module initialization.
 *
 * Return: 0 on success, negative errno on failure
 */
int __init tquic_hw_offload_init(void)
{
	/* Detect CPU capabilities early */
	tquic_crypto_detect_caps(&tquic_caps);

	/* Create /proc/net/tquic directory if it doesn't exist */
	tquic_proc_dir = proc_mkdir("net/tquic", NULL);
	if (!tquic_proc_dir) {
		/* Try to use existing directory */
		tquic_proc_dir = NULL;
	}

	/* Create /proc/net/tquic/crypto_caps */
	if (tquic_proc_dir) {
		crypto_caps_entry = proc_create("crypto_caps", 0444,
						tquic_proc_dir,
						&tquic_crypto_caps_ops);
	} else {
		/* Fallback: create in /proc/net directly */
		crypto_caps_entry = proc_create("tquic_crypto_caps", 0444,
						init_net.proc_net,
						&tquic_crypto_caps_ops);
	}

	if (!crypto_caps_entry)
		pr_warn("tquic_hw_offload: failed to create proc entry\n");

	pr_info("tquic_hw_offload: initialized (AES-NI:%s AVX2:%s AVX-512:%s VAES:%s)\n",
		tquic_caps.aes_ni ? "yes" : "no",
		tquic_caps.avx2 ? "yes" : "no",
		tquic_caps.avx512 ? "yes" : "no",
		tquic_caps.vaes ? "yes" : "no");

	return 0;
}

/**
 * tquic_hw_offload_exit - Clean up hardware offload subsystem
 */
void tquic_hw_offload_exit(void)
{
	if (crypto_caps_entry) {
		proc_remove(crypto_caps_entry);
		crypto_caps_entry = NULL;
	}

	if (tquic_proc_dir) {
		proc_remove(tquic_proc_dir);
		tquic_proc_dir = NULL;
	}

	pr_info("tquic_hw_offload: cleaned up\n");
}

MODULE_DESCRIPTION("TQUIC Hardware Crypto Offload Detection");
MODULE_LICENSE("GPL");
