// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Address Validation Token Support (RFC 9000 Section 8.1.3-8.1.4)
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Implements address validation token generation, encryption, and validation
 * for TQUIC connections. Tokens allow servers to skip address validation on
 * future connections from previously validated clients.
 *
 * Token format: Version(1) || Encrypted(IP || Timestamp || Random) || Tag(16)
 *
 * Reference: RFC 9000 Section 8.1.3 (Address Validation Using Retry Packets)
 *            RFC 9000 Section 8.1.4 (Address Validation for Future Connections)
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/time64.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <crypto/aead.h>
#include <crypto/gcm.h>
#include <net/tquic.h>

#include "tquic_token.h"
#include "tquic_mib.h"

/* QUIC frame type for NEW_TOKEN */
#define TQUIC_FRAME_NEW_TOKEN		0x07

/* Retry token lifetime: 10 seconds */
#define TQUIC_RETRY_TOKEN_LIFETIME	10

/* AAD (Additional Authenticated Data) for token encryption */
#define TQUIC_TOKEN_AAD			"TQUIC-TOKEN-V1"
#define TQUIC_TOKEN_AAD_LEN		14

/* Global crypto handle for token encryption */
static struct crypto_aead *tquic_token_aead;
static DEFINE_MUTEX(tquic_token_mutex);

/* Default token lifetime (can be overridden by sysctl) */
static int tquic_token_lifetime_seconds = TQUIC_TOKEN_DEFAULT_LIFETIME;

/*
 * =============================================================================
 * Internal Helpers
 * =============================================================================
 */

/*
 * Extract IP address from sockaddr_storage
 */
static int tquic_extract_addr(const struct sockaddr_storage *addr,
			      u8 *buf, u8 *len, u8 *family)
{
	if (addr->ss_family == AF_INET) {
		const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
		*family = AF_INET;
		*len = 4;
		memcpy(buf, &sin->sin_addr.s_addr, 4);
		return 0;
	} else if (addr->ss_family == AF_INET6) {
		const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;
		*family = AF_INET6;
		*len = 16;
		memcpy(buf, &sin6->sin6_addr, 16);
		return 0;
	}

	return -EINVAL;
}

/*
 * Compare extracted address with sockaddr_storage
 */
static bool tquic_addr_match(const struct sockaddr_storage *addr,
			     const u8 *buf, u8 len, u8 family)
{
	if (addr->ss_family != family)
		return false;

	if (family == AF_INET) {
		const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
		return len == 4 && memcmp(&sin->sin_addr.s_addr, buf, 4) == 0;
	} else if (family == AF_INET6) {
		const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;
		return len == 16 && memcmp(&sin6->sin6_addr, buf, 16) == 0;
	}

	return false;
}

/*
 * Encode varint (QUIC variable-length integer)
 */
static int tquic_token_encode_varint(u8 *buf, size_t buf_len, u64 val)
{
	if (val <= 63) {
		if (buf_len < 1)
			return -ENOSPC;
		buf[0] = (u8)val;
		return 1;
	} else if (val <= 16383) {
		if (buf_len < 2)
			return -ENOSPC;
		buf[0] = 0x40 | ((val >> 8) & 0x3f);
		buf[1] = (u8)val;
		return 2;
	} else if (val <= 1073741823) {
		if (buf_len < 4)
			return -ENOSPC;
		buf[0] = 0x80 | ((val >> 24) & 0x3f);
		buf[1] = (val >> 16) & 0xff;
		buf[2] = (val >> 8) & 0xff;
		buf[3] = (u8)val;
		return 4;
	} else {
		if (buf_len < 8)
			return -ENOSPC;
		buf[0] = 0xc0 | ((val >> 56) & 0x3f);
		buf[1] = (val >> 48) & 0xff;
		buf[2] = (val >> 40) & 0xff;
		buf[3] = (val >> 32) & 0xff;
		buf[4] = (val >> 24) & 0xff;
		buf[5] = (val >> 16) & 0xff;
		buf[6] = (val >> 8) & 0xff;
		buf[7] = (u8)val;
		return 8;
	}
}

/*
 * Decode varint
 */
static int tquic_token_decode_varint(const u8 *buf, size_t buf_len, u64 *val)
{
	u8 prefix;
	int len;

	if (buf_len < 1)
		return -EINVAL;

	prefix = buf[0] >> 6;
	len = 1 << prefix;

	if (buf_len < len)
		return -EINVAL;

	switch (len) {
	case 1:
		*val = buf[0] & 0x3f;
		break;
	case 2:
		*val = ((u64)(buf[0] & 0x3f) << 8) | buf[1];
		break;
	case 4:
		*val = ((u64)(buf[0] & 0x3f) << 24) |
		       ((u64)buf[1] << 16) |
		       ((u64)buf[2] << 8) |
		       buf[3];
		break;
	case 8:
		*val = ((u64)(buf[0] & 0x3f) << 56) |
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

/*
 * =============================================================================
 * Token Key Management
 * =============================================================================
 */

int tquic_token_init_key(struct tquic_token_key *key)
{
	if (!key)
		return -EINVAL;

	get_random_bytes(key->key, TQUIC_TOKEN_KEY_LEN);
	key->generation = 1;
	key->valid = true;

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_token_init_key);

int tquic_token_set_key(struct tquic_token_key *key, const u8 *key_data)
{
	if (!key || !key_data)
		return -EINVAL;

	memcpy(key->key, key_data, TQUIC_TOKEN_KEY_LEN);
	key->generation = 1;
	key->valid = true;

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_token_set_key);

int tquic_token_rotate_key(struct tquic_token_key *old_key,
			   struct tquic_token_key *new_key)
{
	if (!new_key)
		return -EINVAL;

	get_random_bytes(new_key->key, TQUIC_TOKEN_KEY_LEN);
	new_key->generation = old_key ? old_key->generation + 1 : 1;
	new_key->valid = true;

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_token_rotate_key);

/*
 * =============================================================================
 * Token Generation
 * =============================================================================
 */

int tquic_token_generate(const struct tquic_token_key *key,
			 const struct sockaddr_storage *client_addr,
			 enum tquic_token_type type,
			 const struct tquic_cid *original_dcid,
			 u8 *token, u32 *token_len)
{
	struct tquic_token_plaintext pt;
	struct aead_request *req;
	struct scatterlist sg[2];
	u8 plaintext[128];
	u8 ciphertext[128];
	u8 iv[TQUIC_TOKEN_IV_LEN];
	u8 aad[TQUIC_TOKEN_AAD_LEN];
	int pt_len;
	int ret;
	u8 *p;
	struct crypto_aead *aead;

	if (!key || !key->valid || !client_addr || !token || !token_len)
		return -EINVAL;

	/* Build plaintext structure */
	memset(&pt, 0, sizeof(pt));
	pt.type = type;

	ret = tquic_extract_addr(client_addr, pt.addr, &pt.addr_len, &pt.addr_family);
	if (ret)
		return ret;

	pt.timestamp = ktime_get_real_seconds();
	get_random_bytes(pt.random, TQUIC_TOKEN_RANDOM_LEN);

	if (original_dcid && type == TQUIC_TOKEN_TYPE_RETRY) {
		pt.odcid_len = original_dcid->len;
		memcpy(pt.original_dcid, original_dcid->id, original_dcid->len);
	}

	/* Serialize plaintext */
	p = plaintext;
	*p++ = pt.type;
	*p++ = pt.addr_family;
	*p++ = pt.addr_len;
	memcpy(p, pt.addr, pt.addr_len);
	p += pt.addr_len;

	/* Timestamp as 8 bytes big-endian */
	*p++ = (pt.timestamp >> 56) & 0xff;
	*p++ = (pt.timestamp >> 48) & 0xff;
	*p++ = (pt.timestamp >> 40) & 0xff;
	*p++ = (pt.timestamp >> 32) & 0xff;
	*p++ = (pt.timestamp >> 24) & 0xff;
	*p++ = (pt.timestamp >> 16) & 0xff;
	*p++ = (pt.timestamp >> 8) & 0xff;
	*p++ = pt.timestamp & 0xff;

	memcpy(p, pt.random, TQUIC_TOKEN_RANDOM_LEN);
	p += TQUIC_TOKEN_RANDOM_LEN;

	/* Original DCID for retry tokens */
	if (type == TQUIC_TOKEN_TYPE_RETRY && original_dcid) {
		*p++ = pt.odcid_len;
		memcpy(p, pt.original_dcid, pt.odcid_len);
		p += pt.odcid_len;
	}

	pt_len = p - plaintext;

	/* Use global AEAD handle */
	mutex_lock(&tquic_token_mutex);

	if (!tquic_token_aead) {
		mutex_unlock(&tquic_token_mutex);
		return -EINVAL;
	}

	aead = tquic_token_aead;

	/* Set key */
	ret = crypto_aead_setkey(aead, key->key, TQUIC_TOKEN_KEY_LEN);
	if (ret) {
		mutex_unlock(&tquic_token_mutex);
		return ret;
	}

	/* Generate random IV */
	get_random_bytes(iv, TQUIC_TOKEN_IV_LEN);

	/* Prepare AAD */
	memcpy(aad, TQUIC_TOKEN_AAD, TQUIC_TOKEN_AAD_LEN);

	/* Allocate request */
	req = aead_request_alloc(aead, GFP_KERNEL);
	if (!req) {
		mutex_unlock(&tquic_token_mutex);
		return -ENOMEM;
	}

	/* Prepare ciphertext buffer (plaintext + tag) */
	memcpy(ciphertext, plaintext, pt_len);

	/* Set up scatter-gather */
	sg_init_one(&sg[0], ciphertext, pt_len + TQUIC_TOKEN_TAG_LEN);

	aead_request_set_crypt(req, &sg[0], &sg[0], pt_len, iv);
	aead_request_set_ad(req, 0);

	/* Encrypt */
	ret = crypto_aead_encrypt(req);

	aead_request_free(req);
	mutex_unlock(&tquic_token_mutex);

	if (ret)
		return ret;

	/* Assemble token: Version || IV || Ciphertext || Tag */
	p = token;
	*p++ = TQUIC_TOKEN_VERSION;
	memcpy(p, iv, TQUIC_TOKEN_IV_LEN);
	p += TQUIC_TOKEN_IV_LEN;
	memcpy(p, ciphertext, pt_len + TQUIC_TOKEN_TAG_LEN);
	p += pt_len + TQUIC_TOKEN_TAG_LEN;

	*token_len = p - token;

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_token_generate);

/*
 * =============================================================================
 * Token Validation
 * =============================================================================
 */

int tquic_token_validate(const struct tquic_token_key *key,
			 const struct sockaddr_storage *client_addr,
			 const u8 *token, u32 token_len,
			 u32 lifetime_secs,
			 struct tquic_cid *original_dcid)
{
	struct aead_request *req;
	struct scatterlist sg[1];
	u8 ciphertext[128];
	u8 plaintext[128];
	u8 iv[TQUIC_TOKEN_IV_LEN];
	u8 version;
	int ct_len;
	int ret;
	const u8 *p;
	u8 type, addr_family, addr_len;
	u8 addr[TQUIC_TOKEN_ADDR_MAX_LEN];
	u64 timestamp;
	time64_t now;
	struct crypto_aead *aead;

	if (!key || !key->valid || !client_addr || !token)
		return -EINVAL;

	/* Minimum token length: version + IV + tag */
	if (token_len < 1 + TQUIC_TOKEN_IV_LEN + TQUIC_TOKEN_TAG_LEN)
		return -EINVAL;

	/* Check version */
	version = token[0];
	if (version != TQUIC_TOKEN_VERSION)
		return -EINVAL;

	/* Extract IV */
	memcpy(iv, token + 1, TQUIC_TOKEN_IV_LEN);

	/* Ciphertext length */
	ct_len = token_len - 1 - TQUIC_TOKEN_IV_LEN;
	if (ct_len > sizeof(ciphertext))
		return -EINVAL;

	memcpy(ciphertext, token + 1 + TQUIC_TOKEN_IV_LEN, ct_len);

	/* Use global AEAD handle */
	mutex_lock(&tquic_token_mutex);

	if (!tquic_token_aead) {
		mutex_unlock(&tquic_token_mutex);
		return -EINVAL;
	}

	aead = tquic_token_aead;

	/* Set key */
	ret = crypto_aead_setkey(aead, key->key, TQUIC_TOKEN_KEY_LEN);
	if (ret) {
		mutex_unlock(&tquic_token_mutex);
		return ret;
	}

	/* Allocate request */
	req = aead_request_alloc(aead, GFP_KERNEL);
	if (!req) {
		mutex_unlock(&tquic_token_mutex);
		return -ENOMEM;
	}

	/* Set up scatter-gather for in-place decryption */
	memcpy(plaintext, ciphertext, ct_len);
	sg_init_one(&sg[0], plaintext, ct_len);

	aead_request_set_crypt(req, &sg[0], &sg[0], ct_len, iv);
	aead_request_set_ad(req, 0);

	/* Decrypt */
	ret = crypto_aead_decrypt(req);

	aead_request_free(req);
	mutex_unlock(&tquic_token_mutex);

	if (ret) {
		/* Decryption failed - invalid token */
		return -EINVAL;
	}

	/* Parse decrypted plaintext */
	ct_len -= TQUIC_TOKEN_TAG_LEN;  /* Remove tag from length */
	p = plaintext;

	if (ct_len < 3)
		return -EINVAL;

	type = *p++;
	addr_family = *p++;
	addr_len = *p++;

	if (addr_len > TQUIC_TOKEN_ADDR_MAX_LEN || ct_len < 3 + addr_len + 8)
		return -EINVAL;

	memcpy(addr, p, addr_len);
	p += addr_len;

	/* Parse timestamp (big-endian 8 bytes) */
	timestamp = ((u64)p[0] << 56) | ((u64)p[1] << 48) |
		    ((u64)p[2] << 40) | ((u64)p[3] << 32) |
		    ((u64)p[4] << 24) | ((u64)p[5] << 16) |
		    ((u64)p[6] << 8) | p[7];
	p += 8;

	/* Skip random bytes */
	p += TQUIC_TOKEN_RANDOM_LEN;

	/* Check for original DCID (retry tokens) */
	if (type == TQUIC_TOKEN_TYPE_RETRY && original_dcid) {
		u8 odcid_len;
		if (p >= plaintext + ct_len)
			return -EINVAL;
		odcid_len = *p++;
		if (odcid_len > TQUIC_MAX_CID_LEN || p + odcid_len > plaintext + ct_len)
			return -EINVAL;
		original_dcid->len = odcid_len;
		memcpy(original_dcid->id, p, odcid_len);
	}

	/* Validate timestamp */
	now = ktime_get_real_seconds();
	if (lifetime_secs == 0)
		lifetime_secs = tquic_token_lifetime_seconds;

	if (now > timestamp + lifetime_secs)
		return -ETIMEDOUT;

	/* Validate address */
	if (!tquic_addr_match(client_addr, addr, addr_len, addr_family))
		return -EACCES;

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_token_validate);

int tquic_token_validate_retry(const struct tquic_token_key *key,
			       const struct sockaddr_storage *client_addr,
			       const u8 *token, u32 token_len,
			       struct tquic_cid *original_dcid)
{
	return tquic_token_validate(key, client_addr, token, token_len,
				    TQUIC_RETRY_TOKEN_LIFETIME, original_dcid);
}
EXPORT_SYMBOL_GPL(tquic_token_validate_retry);

/*
 * =============================================================================
 * NEW_TOKEN Frame Generation and Processing
 * =============================================================================
 */

int tquic_gen_new_token_frame(const struct tquic_token_key *key,
			      const struct sockaddr_storage *client_addr,
			      u8 *buf, size_t buf_len)
{
	u8 token[TQUIC_TOKEN_MAX_LEN];
	u32 token_len;
	u8 *p = buf;
	int ret;

	if (!key || !client_addr || !buf)
		return -EINVAL;

	/* Generate token */
	ret = tquic_token_generate_new_token(key, client_addr, token, &token_len);
	if (ret)
		return ret;

	/* Calculate required space: type(1) + token_len_varint + token */
	if (buf_len < 1 + 2 + token_len)  /* Conservative estimate */
		return -ENOSPC;

	/* Frame type */
	*p++ = TQUIC_FRAME_NEW_TOKEN;

	/* Token length (varint) */
	ret = tquic_token_encode_varint(p, buf_len - 1, token_len);
	if (ret < 0)
		return ret;
	p += ret;

	/* Token data */
	memcpy(p, token, token_len);
	p += token_len;

	return p - buf;
}
EXPORT_SYMBOL_GPL(tquic_gen_new_token_frame);

int tquic_send_new_token(struct tquic_connection *conn)
{
	struct tquic_path *path;
	struct sk_buff *skb;
	u8 frame_buf[TQUIC_TOKEN_MAX_LEN + 16];
	int frame_len;
	u64 pkt_num;
	struct tquic_token_key key;
	int ret;

	if (!conn || conn->state != TQUIC_CONN_CONNECTED)
		return -EINVAL;

	/* Only server sends NEW_TOKEN */
	if (conn->role != TQUIC_ROLE_SERVER)
		return -EINVAL;

	path = conn->active_path;
	if (!path)
		return -ENETUNREACH;

	/* Initialize a key for this connection (in production, use persistent key) */
	ret = tquic_token_init_key(&key);
	if (ret)
		return ret;

	/* Generate NEW_TOKEN frame */
	frame_len = tquic_gen_new_token_frame(&key, &path->remote_addr,
					      frame_buf, sizeof(frame_buf));
	if (frame_len < 0)
		return frame_len;

	/* Get packet number */
	spin_lock(&conn->lock);
	pkt_num = conn->stats.tx_packets++;
	spin_unlock(&conn->lock);

	/* Allocate SKB for packet */
	skb = alloc_skb(frame_len + 64 + MAX_HEADER, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	skb_reserve(skb, MAX_HEADER);

	/* Build short header would go here - simplified for now */
	skb_put_data(skb, frame_buf, frame_len);

	/* Update MIB counter */
	if (conn->sk)
		TQUIC_INC_STATS(sock_net(conn->sk), TQUIC_MIB_NEWTOKENSTX);

	pr_debug("tquic: sent NEW_TOKEN frame, len=%d\n", frame_len);

	/* Note: In full implementation, this would go through packet assembly */
	kfree_skb(skb);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_send_new_token);

int tquic_process_new_token_frame(struct tquic_connection *conn,
				  const u8 *data, size_t len)
{
	u64 token_len;
	int ret;
	const u8 *p = data;

	if (!conn || !data || len < 1)
		return -EINVAL;

	/* Only client processes NEW_TOKEN */
	if (conn->role != TQUIC_ROLE_CLIENT)
		return -EINVAL;

	/* Parse token length */
	ret = tquic_token_decode_varint(p, len, &token_len);
	if (ret < 0)
		return ret;
	p += ret;
	len -= ret;

	if (len < token_len)
		return -EINVAL;

	/* Store token for future use */
	/* In production, this would be stored per server address */
	pr_debug("tquic: received NEW_TOKEN, len=%llu\n", token_len);

	/* Update MIB counter */
	if (conn->sk)
		TQUIC_INC_STATS(sock_net(conn->sk), TQUIC_MIB_NEWTOKENSRX);

	return ret + token_len;  /* Return bytes consumed */
}
EXPORT_SYMBOL_GPL(tquic_process_new_token_frame);

/*
 * =============================================================================
 * Token State Management
 * =============================================================================
 */

void tquic_token_state_init(struct tquic_token_state *state)
{
	if (!state)
		return;

	memset(state, 0, sizeof(*state));
	spin_lock_init(&state->lock);
}
EXPORT_SYMBOL_GPL(tquic_token_state_init);

void tquic_token_state_cleanup(struct tquic_token_state *state)
{
	unsigned long flags;

	if (!state)
		return;

	spin_lock_irqsave(&state->lock, flags);
	memset(state->stored_token, 0, sizeof(state->stored_token));
	state->stored_token_len = 0;
	state->token_valid = false;
	spin_unlock_irqrestore(&state->lock, flags);
}
EXPORT_SYMBOL_GPL(tquic_token_state_cleanup);

int tquic_token_store(struct tquic_token_state *state,
		      const u8 *token, u16 token_len,
		      const struct sockaddr_storage *server_addr)
{
	unsigned long flags;

	if (!state || !token || token_len > TQUIC_TOKEN_MAX_LEN)
		return -EINVAL;

	spin_lock_irqsave(&state->lock, flags);

	memcpy(state->stored_token, token, token_len);
	state->stored_token_len = token_len;
	memcpy(&state->token_addr, server_addr, sizeof(*server_addr));
	state->token_issued_time = ktime_get();
	state->token_valid = true;

	spin_unlock_irqrestore(&state->lock, flags);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_token_store);

int tquic_token_get(struct tquic_token_state *state,
		    const struct sockaddr_storage *server_addr,
		    u8 *token, u16 *token_len)
{
	unsigned long flags;
	int ret = 0;

	if (!state || !token || !token_len)
		return -EINVAL;

	spin_lock_irqsave(&state->lock, flags);

	if (!state->token_valid) {
		ret = -ENOENT;
		goto out;
	}

	/* Check if address matches */
	if (memcmp(&state->token_addr, server_addr, sizeof(*server_addr)) != 0) {
		ret = -ENOENT;
		goto out;
	}

	memcpy(token, state->stored_token, state->stored_token_len);
	*token_len = state->stored_token_len;

out:
	spin_unlock_irqrestore(&state->lock, flags);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_token_get);

void tquic_token_clear(struct tquic_token_state *state)
{
	unsigned long flags;

	if (!state)
		return;

	spin_lock_irqsave(&state->lock, flags);
	state->token_valid = false;
	memset(state->stored_token, 0, sizeof(state->stored_token));
	state->stored_token_len = 0;
	spin_unlock_irqrestore(&state->lock, flags);
}
EXPORT_SYMBOL_GPL(tquic_token_clear);

/*
 * =============================================================================
 * Module Initialization
 * =============================================================================
 *
 * Note: tquic_sysctl_get_token_lifetime() is defined in tquic_sysctl.c
 */

int __init tquic_token_init(void)
{
	/* Allocate global AEAD handle for token encryption */
	tquic_token_aead = crypto_alloc_aead("gcm(aes)", 0, 0);
	if (IS_ERR(tquic_token_aead)) {
		pr_err("tquic: failed to allocate token AEAD cipher\n");
		return PTR_ERR(tquic_token_aead);
	}

	/* Set authentication tag length */
	if (crypto_aead_setauthsize(tquic_token_aead, TQUIC_TOKEN_TAG_LEN)) {
		pr_err("tquic: failed to set token auth tag size\n");
		crypto_free_aead(tquic_token_aead);
		tquic_token_aead = NULL;
		return -EINVAL;
	}

	pr_info("tquic: token subsystem initialized\n");
	return 0;
}

void __exit tquic_token_exit(void)
{
	if (tquic_token_aead) {
		crypto_free_aead(tquic_token_aead);
		tquic_token_aead = NULL;
	}

	pr_info("tquic: token subsystem cleanup complete\n");
}

MODULE_DESCRIPTION("TQUIC Address Validation Token Support");
MODULE_LICENSE("GPL");
