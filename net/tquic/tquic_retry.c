// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Retry Packet Mechanism
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Implements Retry packet generation and token validation per RFC 9000
 * Section 8.1 and RFC 9001 Section 5.8.
 *
 * Address Validation via Retry (RFC 9000 Section 8.1):
 *   - Server sends Retry packet to validate client address
 *   - Client must include Retry Token in subsequent Initial
 *   - Server validates token before allocating connection state
 *
 * Retry Integrity Tag (RFC 9001 Section 5.8):
 *   - Computed using AES-128-GCM with fixed key and nonce
 *   - Prevents off-path attackers from injecting Retry packets
 *
 * Token Format:
 *   - Encrypted with server-side secret (AES-128-GCM)
 *   - Contains: ODCID, client IP, timestamp
 *   - Configurable lifetime via sysctl
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/random.h>
#include <linux/time.h>
#include <linux/net.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <crypto/aead.h>
#include <crypto/aes.h>
#include <crypto/utils.h>
#include <net/sock.h>
#include <net/udp.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/tquic.h>

#include "tquic_retry.h"
#include "tquic_mib.h"
#include "tquic_debug.h"

/*
 * =============================================================================
 * Retry Integrity Key and Nonce (RFC 9001 Section 5.8)
 * =============================================================================
 *
 * These are fixed values specified in RFC 9001 for computing the Retry
 * Integrity Tag. They are public values - the security comes from the
 * tag preventing modification, not from secrecy.
 */

/* QUIC v1 Retry integrity key: 0xbe0c690b9f66575a1d766b54e368c84e */
const u8 tquic_retry_integrity_key_v1[16] = {
	0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
	0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e
};
EXPORT_SYMBOL_GPL(tquic_retry_integrity_key_v1);

/* QUIC v1 Retry integrity nonce: 0x461599d35d632bf2239825bb */
const u8 tquic_retry_integrity_nonce_v1[12] = {
	0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2,
	0x23, 0x98, 0x25, 0xbb
};
EXPORT_SYMBOL_GPL(tquic_retry_integrity_nonce_v1);

/* QUIC v2 Retry integrity key (draft-ietf-quic-v2) */
const u8 tquic_retry_integrity_key_v2[16] = {
	0x8f, 0xb4, 0xb0, 0x1b, 0x56, 0xac, 0x48, 0xe2,
	0x60, 0xfb, 0xcb, 0xce, 0xad, 0x7c, 0xcc, 0x92
};
EXPORT_SYMBOL_GPL(tquic_retry_integrity_key_v2);

/* QUIC v2 Retry integrity nonce (draft-ietf-quic-v2) */
const u8 tquic_retry_integrity_nonce_v2[12] = {
	0xd8, 0x69, 0x69, 0xbc, 0x2d, 0x7c, 0x6d, 0x99,
	0x90, 0xef, 0xb0, 0x4a
};
EXPORT_SYMBOL_GPL(tquic_retry_integrity_nonce_v2);

/* Long header packet type for Retry */
#define TQUIC_PKT_TYPE_RETRY	0x03

/* Header constants */
#define TQUIC_HEADER_FORM_LONG	0x80
#define TQUIC_HEADER_FIXED_BIT	0x40

/*
 * Global Retry state (per-namespace in future)
 */
static struct tquic_retry_state *tquic_global_retry_state;
static DEFINE_MUTEX(tquic_retry_mutex);

/*
 * Cached AEAD ciphers for Retry Integrity Tag computation.
 *
 * The retry integrity key is fixed per RFC version, so a single cached
 * instance per version is correct.  Protected by integrity_aead_lock.
 */
static DEFINE_MUTEX(integrity_aead_lock);
static struct crypto_aead *integrity_aead_v1;
static struct crypto_aead *integrity_aead_v2;

/* Sysctl-controlled values */
static int tquic_retry_required;	/* 0 = disabled, 1 = enabled */
static int tquic_retry_token_lifetime = TQUIC_RETRY_TOKEN_LIFETIME_DEFAULT;

/*
 * Rate limiting for Retry packet generation.
 * Prevents CPU exhaustion from attackers sending many Initial packets.
 */
#define TQUIC_RETRY_RATE_LIMIT_TOKENS		200
#define TQUIC_RETRY_RATE_LIMIT_REFILL_MS	1000
#define TQUIC_RETRY_RATE_LIMIT_REFILL_AMOUNT	50

static DEFINE_SPINLOCK(tquic_retry_rate_lock);
static u32 tquic_retry_rate_tokens = TQUIC_RETRY_RATE_LIMIT_TOKENS;
static ktime_t tquic_retry_rate_last;

static bool tquic_retry_rate_limit(void)
{
	ktime_t now;
	s64 elapsed_ms;
	u32 refill;

	spin_lock(&tquic_retry_rate_lock);

	now = ktime_get();
	elapsed_ms = ktime_ms_delta(now, tquic_retry_rate_last);

	if (elapsed_ms >= TQUIC_RETRY_RATE_LIMIT_REFILL_MS) {
		refill = (elapsed_ms / TQUIC_RETRY_RATE_LIMIT_REFILL_MS) *
			 TQUIC_RETRY_RATE_LIMIT_REFILL_AMOUNT;
		tquic_retry_rate_tokens = min_t(u32,
						tquic_retry_rate_tokens + refill,
						TQUIC_RETRY_RATE_LIMIT_TOKENS);
		tquic_retry_rate_last = now;
	}

	if (tquic_retry_rate_tokens == 0) {
		spin_unlock(&tquic_retry_rate_lock);
		return false;
	}

	tquic_retry_rate_tokens--;
	spin_unlock(&tquic_retry_rate_lock);
	return true;
}

/*
 * =============================================================================
 * Retry Integrity Tag Computation
 * =============================================================================
 */

/**
 * tquic_retry_get_key_nonce - Get key and nonce for version
 * @version: QUIC version
 * @key: Output: 16-byte key
 * @nonce: Output: 12-byte nonce
 *
 * Returns: 0 on success, -EINVAL for unsupported version
 */
static int tquic_retry_get_key_nonce(u32 version, const u8 **key,
				     const u8 **nonce)
{
	switch (version) {
	case TQUIC_VERSION_1:
		*key = tquic_retry_integrity_key_v1;
		*nonce = tquic_retry_integrity_nonce_v1;
		return 0;
	case TQUIC_VERSION_2:
		*key = tquic_retry_integrity_key_v2;
		*nonce = tquic_retry_integrity_nonce_v2;
		return 0;
	default:
		/* Reject unrecognized versions instead of silently using v1 */
		return -EPROTONOSUPPORT;
	}
}

/*
 * Get or lazily allocate the cached AEAD cipher for a given QUIC version.
 *
 * The retry integrity key is fixed per RFC version, so a single cached
 * instance per version is correct.  Caller must hold integrity_aead_lock.
 */
static struct crypto_aead *tquic_retry_get_integrity_aead(u32 version)
{
	struct crypto_aead **cached;
	const u8 *key;
	const u8 *nonce;
	struct crypto_aead *aead;
	int ret;

	ret = tquic_retry_get_key_nonce(version, &key, &nonce);
	if (ret)
		return ERR_PTR(ret);

	if (version == TQUIC_VERSION_1)
		cached = &integrity_aead_v1;
	else
		cached = &integrity_aead_v2;

	if (*cached)
		return *cached;

	aead = crypto_alloc_aead("gcm(aes)", 0, 0);
	if (IS_ERR(aead)) {
		tquic_err("retry: failed to allocate integrity AEAD\n");
		return aead;
	}

	ret = crypto_aead_setkey(aead, key, 16);
	if (ret) {
		tquic_err("retry: failed to set integrity AEAD key: %d\n", ret);
		crypto_free_aead(aead);
		return ERR_PTR(ret);
	}

	ret = crypto_aead_setauthsize(aead, TQUIC_RETRY_INTEGRITY_TAG_LEN);
	if (ret) {
		tquic_err("retry: failed to set auth tag size: %d\n", ret);
		crypto_free_aead(aead);
		return ERR_PTR(ret);
	}

	*cached = aead;
	return aead;
}

/**
 * tquic_retry_compute_integrity_tag - Compute Retry Integrity Tag
 *
 * RFC 9001 Section 5.8:
 *   The Retry Integrity Tag is computed as the output of AEAD_AES_128_GCM
 *   with the following inputs:
 *   - Key: retry_key (version-specific)
 *   - Nonce: retry_nonce (version-specific)
 *   - Plaintext: empty
 *   - AAD: Retry Pseudo-Packet
 *
 * The Retry Pseudo-Packet is:
 *   ODCID Length (1 byte) || ODCID || Retry packet without tag
 */
int tquic_retry_compute_integrity_tag(u32 version,
				      const u8 *odcid, u8 odcid_len,
				      const u8 *retry_packet, size_t retry_len,
				      u8 *tag)
{
	struct crypto_aead *aead;
	struct aead_request *req = NULL;
	struct scatterlist sg_out;
	u8 *pseudo_packet = NULL;
	u8 *combined = NULL;
	size_t pseudo_len, combined_len;
	const u8 *key, *nonce;
	int ret;

	if (!odcid || !retry_packet || !tag)
		return -EINVAL;

	if (odcid_len > TQUIC_MAX_CID_LEN)
		return -EINVAL;

	/* Get version-specific nonce */
	ret = tquic_retry_get_key_nonce(version, &key, &nonce);
	if (ret)
		return ret;

	/*
	 * SECURITY: Limit retry packet size to prevent memory exhaustion DoS.
	 * Use typical MTU (1500) minus IP/UDP headers (~60 bytes) as upper bound.
	 * This prevents attackers from forcing large allocations via Initial packets.
	 */
	if (retry_len > 1440)
		return -EINVAL;

	/* Get or lazily allocate the cached AEAD cipher for this version */
	mutex_lock(&integrity_aead_lock);
	aead = tquic_retry_get_integrity_aead(version);
	if (IS_ERR(aead)) {
		ret = PTR_ERR(aead);
		mutex_unlock(&integrity_aead_lock);
		return ret;
	}

	/* Build Retry Pseudo-Packet as AAD */
	pseudo_len = 1 + odcid_len + retry_len;
	pseudo_packet = kmalloc(pseudo_len, GFP_KERNEL);
	if (!pseudo_packet) {
		ret = -ENOMEM;
		goto out_unlock;
	}

	pseudo_packet[0] = odcid_len;
	memcpy(pseudo_packet + 1, odcid, odcid_len);
	memcpy(pseudo_packet + 1 + odcid_len, retry_packet, retry_len);

	/* Allocate request */
	req = aead_request_alloc(aead, GFP_KERNEL);
	if (!req) {
		ret = -ENOMEM;
		goto out_free_pseudo;
	}

	/*
	 * AEAD encrypt with empty plaintext:
	 * - Input: AAD (pseudo_packet) with zero-length plaintext
	 * - Output: 16-byte authentication tag
	 *
	 * The combined buffer holds AAD followed by space for the tag.
	 * The scatterlist covers the entire buffer; aead_request_set_ad
	 * tells the cipher how many leading bytes are AAD.
	 */
	combined_len = pseudo_len + TQUIC_RETRY_INTEGRITY_TAG_LEN;
	combined = kzalloc(combined_len, GFP_KERNEL);
	if (!combined) {
		ret = -ENOMEM;
		goto out_free_req;
	}

	memcpy(combined, pseudo_packet, pseudo_len);

	sg_init_one(&sg_out, combined, combined_len);
	aead_request_set_crypt(req, &sg_out, &sg_out, 0, (u8 *)nonce);
	aead_request_set_ad(req, pseudo_len);

	ret = crypto_aead_encrypt(req);
	if (ret == 0)
		memcpy(tag, combined + pseudo_len,
		       TQUIC_RETRY_INTEGRITY_TAG_LEN);
	else
		tquic_dbg("retry:AEAD encrypt failed: %d\n", ret);

	kfree(combined);
out_free_req:
	aead_request_free(req);
out_free_pseudo:
	kfree(pseudo_packet);
out_unlock:
	mutex_unlock(&integrity_aead_lock);

	return ret;
}
EXPORT_SYMBOL_GPL(tquic_retry_compute_integrity_tag);

/**
 * tquic_retry_verify_integrity_tag - Verify Retry Integrity Tag
 */
bool tquic_retry_verify_integrity_tag(u32 version,
				      const u8 *odcid, u8 odcid_len,
				      const u8 *retry_packet, size_t retry_len)
{
	u8 computed_tag[TQUIC_RETRY_INTEGRITY_TAG_LEN];
	const u8 *received_tag;
	size_t packet_without_tag_len;
	int ret;

	if (retry_len < TQUIC_RETRY_INTEGRITY_TAG_LEN)
		return false;

	/* Tag is last 16 bytes */
	packet_without_tag_len = retry_len - TQUIC_RETRY_INTEGRITY_TAG_LEN;
	received_tag = retry_packet + packet_without_tag_len;

	/* Compute expected tag */
	ret = tquic_retry_compute_integrity_tag(version, odcid, odcid_len,
						retry_packet,
						packet_without_tag_len,
						computed_tag);
	if (ret)
		return false;

	/* Constant-time comparison */
	return crypto_memneq(computed_tag, received_tag,
			     TQUIC_RETRY_INTEGRITY_TAG_LEN) == 0;
}
EXPORT_SYMBOL_GPL(tquic_retry_verify_integrity_tag);

/*
 * =============================================================================
 * Retry Token Creation and Validation
 * =============================================================================
 */

/**
 * tquic_retry_token_create - Create encrypted Retry Token
 */
int tquic_retry_token_create(struct tquic_retry_state *state,
			     const u8 *odcid, u8 odcid_len,
			     const struct sockaddr_storage *client_addr,
			     u8 *token, size_t *token_len)
{
	struct tquic_retry_token_plaintext pt;
	struct aead_request *req = NULL;
	struct scatterlist sg;
	u8 *encrypted = NULL;
	size_t pt_len, enc_len;
	u8 nonce[12];
	u8 local_key[16];
	unsigned long flags;
	int ret;

	if (!state || !odcid || !client_addr || !token || !token_len)
		return -EINVAL;

	if (odcid_len > TQUIC_MAX_CID_LEN)
		return -EINVAL;

	if (*token_len < TQUIC_RETRY_TOKEN_MIN_LEN)
		return -ENOSPC;

	/* Build plaintext structure */
	memset(&pt, 0, sizeof(pt));
	pt.version = TQUIC_RETRY_TOKEN_VERSION;
	pt.odcid_len = odcid_len;
	memcpy(pt.odcid, odcid, odcid_len);
	pt.addr_family = client_addr->ss_family;

	if (client_addr->ss_family == AF_INET) {
		const struct sockaddr_in *sin;

		sin = (const struct sockaddr_in *)client_addr;
		pt.client_addr.v4 = sin->sin_addr.s_addr;
		pt.client_port = sin->sin_port;
	} else if (client_addr->ss_family == AF_INET6) {
		const struct sockaddr_in6 *sin6;

		sin6 = (const struct sockaddr_in6 *)client_addr;
		pt.client_addr.v6 = sin6->sin6_addr;
		pt.client_port = sin6->sin6_port;
	} else {
		return -EAFNOSUPPORT;
	}

	pt.timestamp = ktime_get_real_seconds();
	get_random_bytes(pt.random, sizeof(pt.random));

	/* Calculate sizes */
	pt_len = sizeof(pt);
	enc_len = pt_len + 16;  /* plaintext + AEAD tag */

	/* Check output buffer can hold nonce + encrypted data */
	if (*token_len < 12 + enc_len)
		return -ENOSPC;

	encrypted = kmalloc(enc_len, GFP_KERNEL);
	if (!encrypted)
		return -ENOMEM;

	/* Generate random nonce */
	get_random_bytes(nonce, sizeof(nonce));

	/* Copy key under spinlock */
	spin_lock_irqsave(&state->lock, flags);
	memcpy(local_key, state->token_key, sizeof(local_key));
	spin_unlock_irqrestore(&state->lock, flags);

	/*
	 * Pick an AEAD instance from the pool based on current CPU.
	 * Each slot has its own mutex, allowing parallel token
	 * operations from different CPUs.
	 */
	{
		int cpu;
		u32 slot;

		cpu = get_cpu();
		slot = cpu % state->pool_size;
		put_cpu();

		mutex_lock(&state->pool_locks[slot]);

		if (!state->aead_pool[slot]) {
			mutex_unlock(&state->pool_locks[slot]);
			memzero_explicit(local_key, sizeof(local_key));
			kfree(encrypted);
			return -EINVAL;
		}

		ret = crypto_aead_setkey(state->aead_pool[slot],
					 local_key, 16);
		memzero_explicit(local_key, sizeof(local_key));
		if (ret) {
			mutex_unlock(&state->pool_locks[slot]);
			kfree(encrypted);
			return ret;
		}

		req = aead_request_alloc(state->aead_pool[slot], GFP_KERNEL);
		if (!req) {
			mutex_unlock(&state->pool_locks[slot]);
			kfree(encrypted);
			return -ENOMEM;
		}

		/* Copy plaintext to output, then encrypt in place */
		memcpy(encrypted, &pt, pt_len);

		sg_init_one(&sg, encrypted, enc_len);
		aead_request_set_crypt(req, &sg, &sg, pt_len, nonce);
		aead_request_set_ad(req, 0);

		ret = crypto_aead_encrypt(req);

		aead_request_free(req);
		mutex_unlock(&state->pool_locks[slot]);
	}

	if (ret) {
		kfree(encrypted);
		return ret;
	}

	/* Token format: nonce (12) || encrypted data + tag */
	memcpy(token, nonce, 12);
	memcpy(token + 12, encrypted, enc_len);
	*token_len = 12 + enc_len;

	kfree(encrypted);

	/* Wipe sensitive plaintext from stack */
	memzero_explicit(&pt, sizeof(pt));

	tquic_dbg("retry:created token, len=%zu\n", *token_len);
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_retry_token_create);

/**
 * tquic_retry_token_validate - Validate and decode Retry Token
 */
int tquic_retry_token_validate(struct tquic_retry_state *state,
			       const u8 *token, size_t token_len,
			       const struct sockaddr_storage *client_addr,
			       u8 *odcid, u8 *odcid_len)
{
	struct tquic_retry_token_plaintext pt;
	struct aead_request *req = NULL;
	struct scatterlist sg;
	u8 *decrypted = NULL;
	u8 nonce[12];
	u8 local_key[16];
	size_t enc_len, pt_len;
	u64 now, age;
	unsigned long flags;
	int ret;

	if (!state || !token || !client_addr || !odcid || !odcid_len)
		return -EINVAL;

	/* Minimum size: nonce (12) + min plaintext + tag (16) */
	if (token_len < 12 + sizeof(pt) + 16)
		return -EINVAL;

	/* Extract nonce */
	memcpy(nonce, token, 12);
	enc_len = token_len - 12;
	pt_len = enc_len - 16;  /* Remove AEAD tag */

	decrypted = kmalloc(enc_len, GFP_KERNEL);
	if (!decrypted)
		return -ENOMEM;

	memcpy(decrypted, token + 12, enc_len);

	/* Copy key under spinlock */
	spin_lock_irqsave(&state->lock, flags);
	memcpy(local_key, state->token_key, sizeof(local_key));
	spin_unlock_irqrestore(&state->lock, flags);

	/*
	 * Pick an AEAD instance from the pool based on current CPU.
	 * Each slot has its own mutex, allowing parallel token
	 * validation from different CPUs.
	 */
	{
		int cpu;
		u32 slot;

		cpu = get_cpu();
		slot = cpu % state->pool_size;
		put_cpu();

		mutex_lock(&state->pool_locks[slot]);

		if (!state->aead_pool[slot]) {
			mutex_unlock(&state->pool_locks[slot]);
			memzero_explicit(local_key, sizeof(local_key));
			kfree(decrypted);
			return -EINVAL;
		}

		ret = crypto_aead_setkey(state->aead_pool[slot],
					 local_key, 16);
		memzero_explicit(local_key, sizeof(local_key));
		if (ret) {
			mutex_unlock(&state->pool_locks[slot]);
			kfree(decrypted);
			return ret;
		}

		req = aead_request_alloc(state->aead_pool[slot], GFP_KERNEL);
		if (!req) {
			mutex_unlock(&state->pool_locks[slot]);
			kfree(decrypted);
			return -ENOMEM;
		}

		sg_init_one(&sg, decrypted, enc_len);
		aead_request_set_crypt(req, &sg, &sg, enc_len, nonce);
		aead_request_set_ad(req, 0);

		ret = crypto_aead_decrypt(req);

		aead_request_free(req);
		mutex_unlock(&state->pool_locks[slot]);
	}

	if (ret) {
		tquic_dbg("retry:token decryption failed: %d\n", ret);
		kfree(decrypted);
		return -EACCES;  /* Authentication failed */
	}

	/* Parse plaintext */
	if (pt_len < sizeof(pt)) {
		kfree(decrypted);
		return -EINVAL;
	}

	memcpy(&pt, decrypted, sizeof(pt));
	memzero_explicit(decrypted, enc_len);
	kfree(decrypted);

	/* Validate version */
	if (pt.version != TQUIC_RETRY_TOKEN_VERSION) {
		tquic_dbg("retry:invalid token version: %u\n", pt.version);
		return -EINVAL;
	}

	/* Validate ODCID length */
	if (pt.odcid_len > TQUIC_MAX_CID_LEN) {
		tquic_dbg("retry:invalid ODCID length: %u\n", pt.odcid_len);
		return -EINVAL;
	}

	/* Validate client address */
	if (pt.addr_family != client_addr->ss_family) {
		tquic_dbg("retry:address family mismatch\n");
		return -EACCES;
	}

	if (client_addr->ss_family == AF_INET) {
		const struct sockaddr_in *sin;

		sin = (const struct sockaddr_in *)client_addr;
		if (crypto_memneq(&pt.client_addr.v4, &sin->sin_addr.s_addr,
				  sizeof(pt.client_addr.v4)) ||
		    crypto_memneq(&pt.client_port, &sin->sin_port,
				  sizeof(pt.client_port))) {
			tquic_dbg("retry:IPv4 address mismatch\n");
			return -EACCES;
		}
	} else if (client_addr->ss_family == AF_INET6) {
		const struct sockaddr_in6 *sin6;

		sin6 = (const struct sockaddr_in6 *)client_addr;
		if (crypto_memneq(&pt.client_addr.v6, &sin6->sin6_addr,
				  sizeof(struct in6_addr)) ||
		    crypto_memneq(&pt.client_port, &sin6->sin6_port,
				  sizeof(pt.client_port))) {
			tquic_dbg("retry:IPv6 address mismatch\n");
			return -EACCES;
		}
	}

	/* Validate timestamp -- reject future tokens beyond small skew */
	now = ktime_get_real_seconds();
	if (pt.timestamp > now + 5) {
		tquic_dbg("retry:token from future\n");
		return -EINVAL;
	}

	if (pt.timestamp <= now) {
		age = now - pt.timestamp;
		if (age > state->token_lifetime) {
			tquic_dbg("retry:token expired (age=%llu, max=%u)\n",
				 age, state->token_lifetime);
			return -ETIMEDOUT;
		}
	}

	/* Output ODCID */
	memcpy(odcid, pt.odcid, pt.odcid_len);
	*odcid_len = pt.odcid_len;

	tquic_dbg("retry:token validated successfully\n");
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_retry_token_validate);

/*
 * =============================================================================
 * Retry Packet Building and Parsing
 * =============================================================================
 */

/**
 * tquic_retry_build_packet - Build a complete Retry packet
 */
int tquic_retry_build_packet(u8 *buf, size_t buf_len,
			     u32 version,
			     const u8 *dcid, u8 dcid_len,
			     const u8 *scid, u8 scid_len,
			     const u8 *odcid, u8 odcid_len,
			     const u8 *token, size_t token_len)
{
	u8 *p = buf;
	size_t hdr_len;
	int ret;

	if (!buf || !dcid || !scid || !odcid || !token)
		return -EINVAL;

	if (dcid_len > TQUIC_MAX_CID_LEN || scid_len > TQUIC_MAX_CID_LEN ||
	    odcid_len > TQUIC_MAX_CID_LEN)
		return -EINVAL;

	/*
	 * Retry packet format (RFC 9000 Section 17.2.5):
	 *   Header Form (1) = 1 (long header)
	 *   Fixed Bit (1) = 1
	 *   Long Packet Type (2) = 3 (Retry)
	 *   Unused (4)
	 *   Version (32)
	 *   DCID Len (8)
	 *   DCID (0-20)
	 *   SCID Len (8)
	 *   SCID (0-20)
	 *   Retry Token (variable)
	 *   Retry Integrity Tag (128)
	 */

	/* Calculate header length (without tag) */
	hdr_len = 1 + 4 + 1 + dcid_len + 1 + scid_len + token_len;

	if (buf_len < hdr_len + TQUIC_RETRY_INTEGRITY_TAG_LEN)
		return -ENOSPC;

	/* First byte: long header | fixed bit | Retry type | unused */
	*p++ = TQUIC_HEADER_FORM_LONG | TQUIC_HEADER_FIXED_BIT |
	       (TQUIC_PKT_TYPE_RETRY << 4);

	/* Version */
	*p++ = (version >> 24) & 0xff;
	*p++ = (version >> 16) & 0xff;
	*p++ = (version >> 8) & 0xff;
	*p++ = version & 0xff;

	/* DCID Length and DCID */
	*p++ = dcid_len;
	if (dcid_len > 0) {
		memcpy(p, dcid, dcid_len);
		p += dcid_len;
	}

	/* SCID Length and SCID */
	*p++ = scid_len;
	if (scid_len > 0) {
		memcpy(p, scid, scid_len);
		p += scid_len;
	}

	/* Retry Token */
	memcpy(p, token, token_len);
	p += token_len;

	/* Compute and append Retry Integrity Tag */
	ret = tquic_retry_compute_integrity_tag(version, odcid, odcid_len,
						buf, p - buf,
						p);
	if (ret)
		return ret;

	p += TQUIC_RETRY_INTEGRITY_TAG_LEN;

	return p - buf;
}
EXPORT_SYMBOL_GPL(tquic_retry_build_packet);

/**
 * tquic_retry_parse - Parse a Retry packet
 */
int tquic_retry_parse(const u8 *packet, size_t packet_len,
		      u32 *version,
		      u8 *dcid, u8 *dcid_len,
		      u8 *scid, u8 *scid_len,
		      const u8 **token, size_t *token_len,
		      const u8 **tag)
{
	const u8 *p = packet;
	u8 first_byte;
	size_t min_len;

	if (!packet || packet_len < 7)
		return -EINVAL;

	/* Check header form and packet type */
	first_byte = *p++;

	if (!(first_byte & TQUIC_HEADER_FORM_LONG))
		return -EINVAL;  /* Not a long header */

	if (((first_byte >> 4) & 0x03) != TQUIC_PKT_TYPE_RETRY)
		return -EINVAL;  /* Not a Retry packet */

	/* Version */
	*version = ((u32)p[0] << 24) | ((u32)p[1] << 16) |
		   ((u32)p[2] << 8) | p[3];
	p += 4;

	/* DCID Length */
	*dcid_len = *p++;
	if (*dcid_len > TQUIC_MAX_CID_LEN)
		return -EINVAL;

	/* Minimum length check */
	min_len = 1 + 4 + 1 + *dcid_len + 1;  /* So far */
	if (packet_len < min_len)
		return -EINVAL;

	/* DCID */
	if (*dcid_len > 0) {
		memcpy(dcid, p, *dcid_len);
		p += *dcid_len;
	}

	/* SCID Length */
	if (p >= packet + packet_len)
		return -EINVAL;
	*scid_len = *p++;
	if (*scid_len > TQUIC_MAX_CID_LEN)
		return -EINVAL;

	min_len += 1 + *scid_len + TQUIC_RETRY_INTEGRITY_TAG_LEN;
	if (packet_len < min_len)
		return -EINVAL;

	/* SCID */
	if (*scid_len > 0) {
		memcpy(scid, p, *scid_len);
		p += *scid_len;
	}

	/* Token: everything between SCID and tag */
	*token = p;
	*token_len = packet_len - (p - packet) - TQUIC_RETRY_INTEGRITY_TAG_LEN;

	/* Tag: last 16 bytes */
	*tag = packet + packet_len - TQUIC_RETRY_INTEGRITY_TAG_LEN;

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_retry_parse);

/*
 * =============================================================================
 * Retry Packet Sending (Server-side)
 * =============================================================================
 */

/**
 * tquic_retry_send - Send a Retry packet to client
 */
int tquic_retry_send(struct sock *sk,
		     const struct sockaddr_storage *src_addr,
		     u32 version,
		     const u8 *dcid, u8 dcid_len,
		     const u8 *scid, u8 scid_len)
{
	struct sk_buff *skb;
	u8 *pkt_buf;
	u8 token[TQUIC_RETRY_TOKEN_MAX_LEN];
	size_t token_len = sizeof(token);
	u8 new_scid[TQUIC_MAX_CID_LEN];
	u8 new_scid_len = 8;  /* Default CID length */
	int pkt_len;
	int ret;

	if (!sk || !src_addr || !dcid || !scid)
		return -EINVAL;

	if (!tquic_global_retry_state)
		return -ENODEV;

	/* Rate limit Retry generation to prevent CPU exhaustion */
	if (!tquic_retry_rate_limit()) {
		tquic_dbg("retry:rate limited\n");
		return -EAGAIN;
	}

	/* Generate new server CID for the Retry */
	get_random_bytes(new_scid, new_scid_len);

	/* Create token encoding ODCID (= client's DCID) and client address */
	ret = tquic_retry_token_create(tquic_global_retry_state,
				       dcid, dcid_len,  /* ODCID */
				       src_addr,
				       token, &token_len);
	if (ret) {
		tquic_dbg("retry:failed to create token: %d\n", ret);
		return ret;
	}

	/* Allocate packet buffer */
	pkt_buf = kmalloc(1500, GFP_ATOMIC);
	if (!pkt_buf)
		return -ENOMEM;

	/*
	 * Build Retry packet:
	 *   DCID = client's SCID (so client recognizes it)
	 *   SCID = new server CID
	 *   ODCID = client's DCID (encoded in integrity tag computation)
	 */
	pkt_len = tquic_retry_build_packet(pkt_buf, 1500,
					   version,
					   scid, scid_len,     /* Our DCID = their SCID */
					   new_scid, new_scid_len,  /* Our new SCID */
					   dcid, dcid_len,     /* ODCID = their DCID */
					   token, token_len);
	if (pkt_len < 0) {
		kfree(pkt_buf);
		return pkt_len;
	}

	/* Allocate SKB */
	skb = alloc_skb(pkt_len + MAX_HEADER + sizeof(struct udphdr),
			GFP_ATOMIC);
	if (!skb) {
		kfree(pkt_buf);
		return -ENOMEM;
	}

	skb_reserve(skb, MAX_HEADER + sizeof(struct udphdr));
	skb_put_data(skb, pkt_buf, pkt_len);
	kfree(pkt_buf);

	/*
	 * Send via UDP
	 *
	 * For proper sending, we need to:
	 * 1. Add UDP header
	 * 2. Route to destination
	 * 3. Call ip_local_out
	 *
	 * For now, use a simplified path that works with the socket's
	 * existing UDP infrastructure.
	 */
	{
		struct msghdr msg;
		struct kvec iov;
		int sent;

		memset(&msg, 0, sizeof(msg));
		msg.msg_name = (void *)src_addr;
		msg.msg_namelen = (src_addr->ss_family == AF_INET) ?
			sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);

		iov.iov_base = skb->data;
		iov.iov_len = skb->len;

		/* Use kernel_sendmsg for actual transmission */
		if (sk->sk_socket) {
			sent = kernel_sendmsg(sk->sk_socket, &msg, &iov, 1,
					      skb->len);
			ret = (sent >= 0) ? 0 : sent;
		} else {
			ret = -ENOTCONN;
		}
	}

	kfree_skb(skb);

	if (ret == 0) {
		/* Update MIB counter */
		if (sk)
			TQUIC_INC_STATS(sock_net(sk), TQUIC_MIB_RETRYPACKETSTX);
		tquic_dbg("retry:sent Retry packet, token_len=%zu\n",
			 token_len);
	}

	return ret;
}
EXPORT_SYMBOL_GPL(tquic_retry_send);

/*
 * =============================================================================
 * Client-side Retry Processing
 * =============================================================================
 */

/**
 * tquic_retry_process - Process received Retry packet (client-side)
 */
int tquic_retry_process(struct tquic_connection *conn,
			const u8 *packet, size_t packet_len)
{
	u32 version;
	u8 dcid[TQUIC_MAX_CID_LEN], scid[TQUIC_MAX_CID_LEN];
	u8 dcid_len, scid_len;
	const u8 *token, *tag;
	size_t token_len;
	int ret;

	if (!conn || !packet)
		return -EINVAL;

	/*
	 * RFC 9000 Section 17.2.5.2: "A client MUST accept and process
	 * at most one Retry packet for each connection attempt."
	 */
	if (conn->retry_received)
		return -EALREADY;

	/* Parse Retry packet */
	ret = tquic_retry_parse(packet, packet_len,
				&version,
				dcid, &dcid_len,
				scid, &scid_len,
				&token, &token_len,
				&tag);
	if (ret) {
		tquic_dbg("retry:failed to parse Retry packet: %d\n", ret);
		return ret;
	}

	/* Verify integrity tag using our original DCID */
	if (!tquic_retry_verify_integrity_tag(version,
					      conn->dcid.id, conn->dcid.len,
					      packet, packet_len)) {
		tquic_dbg("retry:integrity tag verification failed\n");
		/* Update MIB counter for invalid Retry */
		if (conn->sk)
			TQUIC_INC_STATS(sock_net(conn->sk), TQUIC_MIB_RETRYERRORS);
		return -EACCES;
	}

	/* Verify DCID matches our SCID */
	if (dcid_len != conn->scid.len ||
	    memcmp(dcid, conn->scid.id, dcid_len) != 0) {
		tquic_dbg("retry:DCID mismatch\n");
		return -EINVAL;
	}

	/*
	 * Update connection state for retry:
	 * - Save original DCID (needed for transport parameter validation)
	 * - Update DCID to server's new SCID
	 * - Store token for inclusion in next Initial
	 */
	spin_lock_bh(&conn->lock);

	/*
	 * Save the original DCID before overwriting. This is required
	 * by RFC 9000 Section 7.3 for transport parameter validation:
	 * the server's original_destination_connection_id transport
	 * parameter must match the ODCID.
	 */
	conn->original_dcid.len = conn->dcid.len;
	memcpy(conn->original_dcid.id, conn->dcid.id, conn->dcid.len);

	/* Update DCID to server's new SCID */
	conn->dcid.len = scid_len;
	memcpy(conn->dcid.id, scid, scid_len);

	/*
	 * Store the retry token for inclusion in the next Initial packet.
	 * The token_len has already been validated by tquic_retry_parse
	 * and is bounded by the packet size.
	 */
	if (token_len <= sizeof(conn->retry_token)) {
		memcpy(conn->retry_token, token, token_len);
		conn->retry_token_len = token_len;
	}

	/* Mark that we have received a Retry */
	conn->retry_received = true;

	spin_unlock_bh(&conn->lock);

	/* Update MIB counter for processed Retry */
	if (conn->sk)
		TQUIC_INC_STATS(sock_net(conn->sk), TQUIC_MIB_RETRYPACKETSRX);

	tquic_dbg("retry:processed Retry, new DCID len=%u, token_len=%zu\n",
		 scid_len, token_len);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_retry_process);

/*
 * =============================================================================
 * Retry State Management
 * =============================================================================
 */

/**
 * tquic_retry_state_alloc - Allocate and initialize Retry state
 */
struct tquic_retry_state *tquic_retry_state_alloc(void)
{
	struct tquic_retry_state *state;
	struct crypto_aead *aead;
	int i;

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return NULL;

	spin_lock_init(&state->lock);
	state->pool_size = TQUIC_RETRY_AEAD_POOL_SIZE;
	state->token_lifetime = tquic_retry_token_lifetime;

	/* Generate random token encryption key */
	get_random_bytes(state->token_key, sizeof(state->token_key));
	state->token_key_id = 0;

	/* Allocate AEAD cipher pool for parallel token operations */
	for (i = 0; i < state->pool_size; i++) {
		mutex_init(&state->pool_locks[i]);

		aead = crypto_alloc_aead("gcm(aes)", 0, 0);
		if (IS_ERR(aead)) {
			tquic_err("retry:failed to allocate token AEAD[%d]\n",
				  i);
			goto err_free_pool;
		}

		if (crypto_aead_setauthsize(aead, 16)) {
			crypto_free_aead(aead);
			goto err_free_pool;
		}

		state->aead_pool[i] = aead;
	}

	tquic_dbg("retry:allocated state with %u second token lifetime, pool=%u\n",
		 state->token_lifetime, state->pool_size);

	return state;

err_free_pool:
	while (--i >= 0) {
		if (state->aead_pool[i])
			crypto_free_aead(state->aead_pool[i]);
	}
	kfree(state);
	return NULL;
}
EXPORT_SYMBOL_GPL(tquic_retry_state_alloc);

/**
 * tquic_retry_state_free - Free Retry state
 */
void tquic_retry_state_free(struct tquic_retry_state *state)
{
	int i;

	if (!state)
		return;

	for (i = 0; i < state->pool_size; i++) {
		if (state->aead_pool[i] && !IS_ERR(state->aead_pool[i]))
			crypto_free_aead(state->aead_pool[i]);
	}

	/* Clear sensitive key material */
	memzero_explicit(state->token_key, sizeof(state->token_key));

	kfree(state);
}
EXPORT_SYMBOL_GPL(tquic_retry_state_free);

/**
 * tquic_retry_rotate_key - Rotate token encryption key
 */
int tquic_retry_rotate_key(struct tquic_retry_state *state)
{
	unsigned long flags;
	u32 new_key_id;

	if (!state)
		return -EINVAL;

	spin_lock_irqsave(&state->lock, flags);

	/* Generate new key */
	get_random_bytes(state->token_key, sizeof(state->token_key));
	state->token_key_id++;
	new_key_id = state->token_key_id;

	spin_unlock_irqrestore(&state->lock, flags);

	tquic_info("retry:rotated token key, new id=%u\n", new_key_id);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_retry_rotate_key);

/*
 * =============================================================================
 * Sysctl Interface
 * =============================================================================
 */

/**
 * tquic_retry_is_required - Check if Retry is required
 */
bool tquic_retry_is_required(struct net *net)
{
	/* For now, use global setting */
	/* Future: per-netns via net->tquic.retry_required */
	return tquic_retry_required != 0;
}
EXPORT_SYMBOL_GPL(tquic_retry_is_required);

/**
 * tquic_retry_get_token_lifetime - Get token lifetime
 */
u32 tquic_retry_get_token_lifetime(struct net *net)
{
	/* For now, use global setting */
	return tquic_retry_token_lifetime;
}
EXPORT_SYMBOL_GPL(tquic_retry_get_token_lifetime);

/*
 * =============================================================================
 * Module Init/Exit
 * =============================================================================
 */

int __init tquic_retry_init(void)
{
	/* Initialize rate limiter timestamp */
	tquic_retry_rate_last = ktime_get();

	mutex_lock(&tquic_retry_mutex);

	tquic_global_retry_state = tquic_retry_state_alloc();
	if (!tquic_global_retry_state) {
		mutex_unlock(&tquic_retry_mutex);
		tquic_err("retry: failed to allocate global state\n");
		return -ENOMEM;
	}

	mutex_unlock(&tquic_retry_mutex);

	tquic_info("retry subsystem initialized\n");
	return 0;
}

void tquic_retry_exit(void)
{
	mutex_lock(&tquic_retry_mutex);

	tquic_retry_state_free(tquic_global_retry_state);
	tquic_global_retry_state = NULL;

	mutex_unlock(&tquic_retry_mutex);

	/* Free cached integrity AEAD ciphers */
	mutex_lock(&integrity_aead_lock);
	if (integrity_aead_v1) {
		crypto_free_aead(integrity_aead_v1);
		integrity_aead_v1 = NULL;
	}
	if (integrity_aead_v2) {
		crypto_free_aead(integrity_aead_v2);
		integrity_aead_v2 = NULL;
	}
	mutex_unlock(&integrity_aead_lock);

	tquic_info("retry subsystem exited\n");
}

MODULE_DESCRIPTION("TQUIC Retry Packet Mechanism (RFC 9000 Section 8.1)");
MODULE_LICENSE("GPL");
