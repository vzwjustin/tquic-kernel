/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC Hardware Crypto Offload Detection
 *
 * Copyright (c) 2026 Linux Foundation
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Header for CPU feature detection and algorithm selection for
 * hardware-accelerated cryptographic operations in TQUIC.
 */

#ifndef _TQUIC_HW_OFFLOAD_H
#define _TQUIC_HW_OFFLOAD_H

#include <linux/types.h>
#include <crypto/aead.h>

/* Cipher suite constants (TLS 1.3) */
#define TLS_AES_128_GCM_SHA256		0x1301
#define TLS_AES_256_GCM_SHA384		0x1302
#define TLS_CHACHA20_POLY1305_SHA256	0x1303

/* Batch processing limits */
#define TQUIC_BATCH_MAX_PACKETS		16

/**
 * struct tquic_crypto_caps - CPU cryptographic capabilities
 * @aes_ni:        AES-NI instruction support
 * @avx2:          AVX2 support (for ChaCha20 acceleration)
 * @avx512:        AVX-512 support (for batch processing)
 * @vaes:          Vector AES support (AVX-512 AES)
 * @vpclmulqdq:    Vector PCLMULQDQ for parallel GCM
 * @pclmulqdq:     Standard PCLMULQDQ support
 * @sha_ni:        SHA-NI instructions
 * @detected:      True if detection has been performed
 *
 * Populated by tquic_crypto_detect_caps() to indicate available
 * hardware acceleration features.
 */
struct tquic_crypto_caps {
	bool aes_ni;
	bool avx2;
	bool avx512;
	bool vaes;
	bool vpclmulqdq;
	bool pclmulqdq;
	bool sha_ni;
	bool detected;
};

/**
 * enum tquic_crypto_impl - Crypto implementation selection
 * @TQUIC_CRYPTO_GENERIC:   Software fallback implementation
 * @TQUIC_CRYPTO_AESNI:     AES-NI accelerated (single block)
 * @TQUIC_CRYPTO_AVX2:      AVX2 accelerated (ChaCha20, parallel ops)
 * @TQUIC_CRYPTO_AVX512:    AVX-512 accelerated (batch processing)
 *
 * Selected by tquic_crypto_select_impl() based on capabilities
 * and cipher suite.
 */
enum tquic_crypto_impl {
	TQUIC_CRYPTO_GENERIC = 0,
	TQUIC_CRYPTO_AESNI,
	TQUIC_CRYPTO_AVX2,
	TQUIC_CRYPTO_AVX512,
};

/**
 * struct tquic_crypto_stats - Crypto operation statistics
 * @aesni_ops:     Operations using AES-NI
 * @avx2_ops:      Operations using AVX2
 * @avx512_ops:    Operations using AVX-512
 * @generic_ops:   Operations using generic fallback
 * @qat_ops:       Operations using Intel QAT
 * @total_bytes:   Total bytes encrypted/decrypted
 * @batch_ops:     Batch encryption operations
 * @batch_packets: Total packets in batch operations
 *
 * Aggregated statistics from all CPUs. Use tquic_crypto_get_stats()
 * to populate this structure.
 */
struct tquic_crypto_stats {
	u64 aesni_ops;
	u64 avx2_ops;
	u64 avx512_ops;
	u64 generic_ops;
	u64 qat_ops;
	u64 total_bytes;
	u64 batch_ops;
	u64 batch_packets;
};

/* Forward declaration */
struct tquic_crypto_ctx;

/*
 * CPU Feature Detection
 */

/**
 * tquic_crypto_detect_caps - Detect CPU cryptographic capabilities
 * @caps: Capabilities structure to populate
 *
 * Probes CPU features to determine available hardware acceleration.
 * Safe to call multiple times; results are cached internally.
 */
void tquic_crypto_detect_caps(struct tquic_crypto_caps *caps);

/**
 * tquic_crypto_get_caps - Get cached CPU capabilities
 *
 * Returns pointer to global capabilities structure. Thread-safe.
 * Performs detection if not already done.
 *
 * Return: Pointer to cached capabilities (never NULL)
 */
const struct tquic_crypto_caps *tquic_crypto_get_caps(void);

/*
 * Implementation Selection
 */

/**
 * tquic_crypto_select_impl - Select optimal crypto implementation
 * @caps:         CPU capabilities (from tquic_crypto_get_caps())
 * @cipher_suite: TLS 1.3 cipher suite identifier
 *
 * Selects the best available implementation based on hardware
 * capabilities and cipher suite requirements.
 *
 * Return: Selected implementation type
 */
enum tquic_crypto_impl tquic_crypto_select_impl(struct tquic_crypto_caps *caps,
						u16 cipher_suite);

/*
 * Crypto Context Management
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
struct tquic_crypto_ctx *tquic_crypto_ctx_alloc(u16 cipher_suite, gfp_t gfp);

/**
 * tquic_crypto_ctx_free - Free crypto context
 * @ctx: Context to free (may be NULL)
 *
 * Frees the crypto context and securely erases key material.
 */
void tquic_crypto_ctx_free(struct tquic_crypto_ctx *ctx);

/**
 * tquic_crypto_ctx_set_key - Set encryption key
 * @ctx:     Crypto context
 * @key:     Key material
 * @key_len: Key length (must match cipher suite requirements)
 *
 * Return: 0 on success, negative errno on failure
 */
int tquic_crypto_ctx_set_key(struct tquic_crypto_ctx *ctx,
			     const u8 *key, size_t key_len);

/**
 * tquic_crypto_ctx_set_iv - Set base IV
 * @ctx:    Crypto context
 * @iv:     IV material
 * @iv_len: IV length (must be 12 for QUIC)
 *
 * Return: 0 on success, negative errno on failure
 */
int tquic_crypto_ctx_set_iv(struct tquic_crypto_ctx *ctx,
			    const u8 *iv, size_t iv_len);

/*
 * Single Packet Operations
 */

/**
 * tquic_hw_encrypt_packet - Encrypt a single packet
 * @ctx:         Crypto context
 * @aad:         Additional authenticated data (header)
 * @aad_len:     AAD length
 * @plaintext:   Input plaintext
 * @pt_len:      Plaintext length
 * @pkt_num:     Packet number (used for nonce construction)
 * @ciphertext:  Output buffer (must have room for pt_len + 16)
 * @ct_len:      Output ciphertext length
 *
 * Encrypts a QUIC packet using AEAD. The packet number is XORed
 * with the base IV to create the nonce per RFC 9001.
 *
 * Return: 0 on success, negative errno on failure
 */
int tquic_hw_encrypt_packet(struct tquic_crypto_ctx *ctx,
			    const u8 *aad, size_t aad_len,
			    const u8 *plaintext, size_t pt_len,
			    u64 pkt_num,
			    u8 *ciphertext, size_t *ct_len);

/**
 * tquic_hw_decrypt_packet - Decrypt a single packet
 * @ctx:        Crypto context
 * @aad:        Additional authenticated data (header)
 * @aad_len:    AAD length
 * @ciphertext: Input ciphertext (includes 16-byte auth tag)
 * @ct_len:     Ciphertext length
 * @pkt_num:    Packet number
 * @plaintext:  Output buffer
 * @pt_len:     Output plaintext length
 *
 * Decrypts a QUIC packet and verifies the authentication tag.
 *
 * Return: 0 on success, -EBADMSG on auth failure, other negative errno
 */
int tquic_hw_decrypt_packet(struct tquic_crypto_ctx *ctx,
			    const u8 *aad, size_t aad_len,
			    const u8 *ciphertext, size_t ct_len,
			    u64 pkt_num,
			    u8 *plaintext, size_t *pt_len);

/*
 * Batch Operations (AVX-512 optimized)
 */

/**
 * struct tquic_hw_packet - Packet for batch crypto operations
 * @data:     Packet data (input/output)
 * @len:      Data length (updated after operation)
 * @pkt_num:  Packet number for nonce
 * @aad:      Additional authenticated data
 * @aad_len:  AAD length
 * @result:   Operation result (0 = success)
 *
 * Note: This is distinct from struct tquic_packet in net/tquic.h which
 * represents parsed QUIC packets. This struct is for batch crypto operations.
 */
struct tquic_hw_packet {
	u8 *data;
	size_t len;
	u64 pkt_num;
	u8 *aad;
	size_t aad_len;
	int result;
};

/**
 * tquic_crypto_batch_encrypt - Encrypt multiple packets in parallel
 * @ctx:   Crypto context
 * @pkts:  Array of packets to encrypt
 * @count: Number of packets (max TQUIC_BATCH_MAX_PACKETS)
 *
 * Uses AVX-512 for parallel encryption when available. Each packet's
 * data buffer is modified in place. Check each packet's result field
 * for individual success/failure.
 *
 * Return: Number of successfully encrypted packets
 */
int tquic_crypto_batch_encrypt(struct tquic_crypto_ctx *ctx,
			       struct tquic_hw_packet *pkts, int count);

/**
 * tquic_crypto_batch_decrypt - Decrypt multiple packets in parallel
 * @ctx:   Crypto context
 * @pkts:  Array of packets to decrypt
 * @count: Number of packets
 *
 * Parallel decryption counterpart to batch_encrypt.
 *
 * Return: Number of successfully decrypted packets
 */
int tquic_crypto_batch_decrypt(struct tquic_crypto_ctx *ctx,
			       struct tquic_hw_packet *pkts, int count);

/*
 * Intel QAT Offload (Optional)
 */

#ifdef CONFIG_CRYPTO_DEV_QAT

/**
 * struct tquic_qat_ctx - Intel QAT offload context
 * @tfm:           AEAD transform using QAT
 * @qat_available: True if QAT is available and initialized
 * @cipher_suite:  Cipher suite in use
 *
 * QAT provides hardware crypto acceleration that can offload
 * encryption/decryption from the CPU entirely.
 */
struct tquic_qat_ctx {
	struct crypto_aead *tfm;
	bool qat_available;
	u16 cipher_suite;
};

/**
 * tquic_qat_init - Initialize QAT offload context
 * @ctx: QAT context to initialize
 *
 * Attempts to allocate a QAT-accelerated AEAD transform.
 * Falls back gracefully if QAT is not available.
 *
 * Return: 0 on success (QAT may still be unavailable), negative errno on error
 */
int tquic_qat_init(struct tquic_qat_ctx *ctx);

/**
 * tquic_qat_cleanup - Clean up QAT context
 * @ctx: QAT context to clean up
 */
void tquic_qat_cleanup(struct tquic_qat_ctx *ctx);

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
 * Uses QAT hardware for encryption. Requires QAT to be initialized
 * and available.
 *
 * Return: 0 on success, -ENODEV if QAT unavailable, other negative errno
 */
int tquic_qat_encrypt(struct tquic_qat_ctx *ctx,
		      const u8 *key, size_t key_len,
		      const u8 *iv, u64 pkt_num,
		      const u8 *aad, size_t aad_len,
		      const u8 *plaintext, size_t pt_len,
		      u8 *ciphertext, size_t *ct_len);

/**
 * tquic_qat_is_available - Check if QAT is available
 * @ctx: QAT context
 *
 * Return: true if QAT is available and initialized
 */
bool tquic_qat_is_available(struct tquic_qat_ctx *ctx);

#else /* !CONFIG_CRYPTO_DEV_QAT */

/* No-op implementations when QAT is not compiled */
struct tquic_qat_ctx {
	bool qat_available;
};

static inline int tquic_qat_init(struct tquic_qat_ctx *ctx)
{
	if (ctx)
		ctx->qat_available = false;
	return 0;
}

static inline void tquic_qat_cleanup(struct tquic_qat_ctx *ctx) { }

static inline int tquic_qat_encrypt(struct tquic_qat_ctx *ctx,
				    const u8 *key, size_t key_len,
				    const u8 *iv, u64 pkt_num,
				    const u8 *aad, size_t aad_len,
				    const u8 *plaintext, size_t pt_len,
				    u8 *ciphertext, size_t *ct_len)
{
	return -ENODEV;
}

static inline bool tquic_qat_is_available(struct tquic_qat_ctx *ctx)
{
	return false;
}

#endif /* CONFIG_CRYPTO_DEV_QAT */

/*
 * Statistics
 */

/**
 * tquic_crypto_get_stats - Get aggregated crypto statistics
 * @stats: Output statistics structure
 *
 * Aggregates per-CPU statistics into the output structure.
 */
void tquic_crypto_get_stats(struct tquic_crypto_stats *stats);

/**
 * tquic_crypto_reset_stats - Reset crypto statistics
 *
 * Resets all per-CPU statistics to zero.
 */
void tquic_crypto_reset_stats(void);

/*
 * Module Init/Exit
 */

/**
 * tquic_hw_offload_init - Initialize hardware offload subsystem
 *
 * Detects CPU capabilities, creates proc entries.
 * Called during TQUIC module initialization.
 *
 * Return: 0 on success, negative errno on failure
 */
int __init tquic_hw_offload_init(void);

/**
 * tquic_hw_offload_exit - Clean up hardware offload subsystem
 *
 * Removes proc entries and frees resources.
 */
void __exit tquic_hw_offload_exit(void);

#endif /* _TQUIC_HW_OFFLOAD_H */
