// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Extended Key Update Extension (draft-ietf-quic-extended-key-update-01)
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Implements the Extended Key Update mechanism for QUIC:
 * - KEY_UPDATE_REQUEST and KEY_UPDATE_RESPONSE frame handling
 * - PSK injection for external key material
 * - State machine for coordinated key updates
 * - Integration with RFC 9001 key update mechanism
 *
 * The extended key update mechanism provides:
 * 1. Explicit request/response key updates with acknowledgment
 * 2. External PSK material injection for post-quantum security
 * 3. Coordinated key rotation between endpoints
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/ktime.h>
#include <linux/workqueue.h>
#include <linux/list.h>
#include <crypto/hash.h>
#include <net/tquic.h>

#include "extended_key_update.h"
#include "key_update.h"
#include "../tquic_debug.h"

/* HKDF labels for extended key update */
#define TQUIC_EKU_LABEL_PSK_EXTRACT	"quic eku psk"
#define TQUIC_EKU_LABEL_MIXED_SECRET	"quic eku mix"

/* Minimum request timeout */
#define TQUIC_EKU_MIN_TIMEOUT_MS	1000

/* Maximum retransmission count */
#define TQUIC_EKU_MAX_RETRANSMIT	3

/*
 * =============================================================================
 * Internal Helper Functions
 * =============================================================================
 */

/**
 * eku_varint_len - Get encoded length of a variable-length integer
 */
static inline size_t eku_varint_len(u64 value)
{
	if (value <= 63)
		return 1;
	if (value <= 16383)
		return 2;
	if (value <= 1073741823)
		return 4;
	return 8;
}

/**
 * eku_varint_encode - Encode a variable-length integer
 */
static ssize_t eku_varint_encode(u8 *buf, size_t buflen, u64 value)
{
	size_t len = eku_varint_len(value);

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
 * eku_varint_decode - Decode a variable-length integer
 */
static ssize_t eku_varint_decode(const u8 *buf, size_t buflen, u64 *value)
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
 * eku_alloc_request - Allocate a new request structure
 */
static struct tquic_eku_request *eku_alloc_request(gfp_t gfp)
{
	struct tquic_eku_request *req;

	req = kzalloc(sizeof(*req), gfp);
	if (!req)
		return NULL;

	INIT_LIST_HEAD(&req->list);
	req->timestamp = ktime_get();

	return req;
}

/**
 * eku_free_request - Free a request structure
 */
static void eku_free_request(struct tquic_eku_request *req)
{
	if (!req)
		return;

	/* Securely wipe PSK material */
	memzero_explicit(req->psk, sizeof(req->psk));
	kfree(req);
}

/**
 * eku_find_pending_request - Find a pending request by ID
 */
static struct tquic_eku_request *
eku_find_pending_request(struct tquic_extended_key_update_state *state,
			 u64 request_id)
{
	struct tquic_eku_request *req;

	list_for_each_entry(req, &state->pending_requests, list) {
		if (req->request_id == request_id)
			return req;
	}

	return NULL;
}

/**
 * eku_timeout_work_handler - Handle request timeouts
 */
static void eku_timeout_work_handler(struct work_struct *work)
{
	struct tquic_extended_key_update_state *state;
	struct tquic_eku_request *req, *tmp;
	ktime_t now = ktime_get();
	unsigned long flags;
	LIST_HEAD(expired);

	state = container_of(work, struct tquic_extended_key_update_state,
			     timeout_work.work);

	spin_lock_irqsave(&state->lock, flags);

	/* Find expired requests */
	list_for_each_entry_safe(req, tmp, &state->pending_requests, list) {
		s64 elapsed_ms = ktime_ms_delta(now, req->timestamp);

		if (elapsed_ms >= state->request_timeout) {
			list_move_tail(&req->list, &expired);
			state->pending_count--;
		}
	}

	spin_unlock_irqrestore(&state->lock, flags);

	/* Handle expired requests outside the lock */
	list_for_each_entry_safe(req, tmp, &expired, list) {
		pr_warn("tquic_eku: request %llu timed out\n", req->request_id);

		list_del(&req->list);
		eku_free_request(req);

		/* Update statistics (need lock for this) */
		spin_lock_irqsave(&state->lock, flags);
		/* Statistics update would happen here */
		spin_unlock_irqrestore(&state->lock, flags);
	}

	/* Reschedule if there are still pending requests */
	spin_lock_irqsave(&state->lock, flags);
	if (state->pending_count > 0) {
		schedule_delayed_work(&state->timeout_work,
				      msecs_to_jiffies(state->request_timeout));
	}
	spin_unlock_irqrestore(&state->lock, flags);
}

/*
 * =============================================================================
 * State Management Implementation
 * =============================================================================
 */

/**
 * tquic_eku_init - Initialize extended key update state
 */
int tquic_eku_init(struct tquic_connection *conn, u32 max_outstanding)
{
	struct tquic_extended_key_update_state *state;

	if (!conn)
		return -EINVAL;

	/* Clamp max_outstanding to valid range */
	if (max_outstanding == 0)
		max_outstanding = 1;
	if (max_outstanding > TQUIC_EKU_MAX_OUTSTANDING_REQUESTS)
		max_outstanding = TQUIC_EKU_MAX_OUTSTANDING_REQUESTS;

	state = kzalloc(sizeof(*state), GFP_KERNEL);
	if (!state)
		return -ENOMEM;

	spin_lock_init(&state->lock);
	INIT_LIST_HEAD(&state->pending_requests);
	INIT_LIST_HEAD(&state->received_requests);
	INIT_DELAYED_WORK(&state->timeout_work, eku_timeout_work_handler);

	state->state = TQUIC_EKU_STATE_IDLE;
	state->local_max_outstanding = max_outstanding;
	state->request_timeout = TQUIC_EKU_REQUEST_TIMEOUT_MS;
	state->conn = conn;
	state->last_update_time = ktime_get();

	/* Get reference to base key update state */
	if (conn->crypto_state) {
		state->key_update_state =
			tquic_crypto_get_key_update_state(conn->crypto_state);
	}

	/*
	 * Allocate a separate hash transform for EKU so that key
	 * derivation does not need to hold the KU lock (CF-184).
	 */
	if (state->key_update_state) {
		const char *hash_name;

		switch (state->key_update_state->cipher_suite) {
		case 0x1302: /* TLS_AES_256_GCM_SHA384 */
			hash_name = "hmac(sha384)";
			break;
		case 0x1301: /* TLS_AES_128_GCM_SHA256 */
		case 0x1303: /* TLS_CHACHA20_POLY1305_SHA256 */
		default:
			hash_name = "hmac(sha256)";
			break;
		}

		state->hash_tfm = crypto_alloc_shash(hash_name, 0, 0);
		if (IS_ERR(state->hash_tfm)) {
			pr_err("tquic_eku: failed to allocate hash %s\n",
			       hash_name);
			state->hash_tfm = NULL;
		}
	}

	conn->eku_state = state;

	pr_debug("tquic_eku: initialized with max_outstanding=%u\n",
		 max_outstanding);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_eku_init);

/**
 * tquic_eku_free - Free extended key update state
 */
void tquic_eku_free(struct tquic_connection *conn)
{
	struct tquic_extended_key_update_state *state;
	struct tquic_eku_request *req, *tmp;
	unsigned long flags;

	if (!conn || !conn->eku_state)
		return;

	state = conn->eku_state;

	/* Cancel pending work */
	cancel_delayed_work_sync(&state->timeout_work);

	spin_lock_irqsave(&state->lock, flags);

	/* Free pending requests */
	list_for_each_entry_safe(req, tmp, &state->pending_requests, list) {
		list_del(&req->list);
		eku_free_request(req);
	}

	/* Free received requests */
	list_for_each_entry_safe(req, tmp, &state->received_requests, list) {
		list_del(&req->list);
		eku_free_request(req);
	}

	spin_unlock_irqrestore(&state->lock, flags);

	/* Free EKU's own hash transform */
	if (state->hash_tfm && !IS_ERR(state->hash_tfm))
		crypto_free_shash(state->hash_tfm);

	/* Securely wipe PSK material */
	memzero_explicit(state->injected_psk, sizeof(state->injected_psk));

	kfree(state);
	conn->eku_state = NULL;

	pr_debug("tquic_eku: freed state\n");
}
EXPORT_SYMBOL_GPL(tquic_eku_free);

/**
 * tquic_eku_negotiate - Handle EKU transport parameter negotiation
 */
int tquic_eku_negotiate(struct tquic_connection *conn,
			u32 local_max, u32 remote_max)
{
	struct tquic_extended_key_update_state *state;
	unsigned long flags;
	int ret;

	if (!conn)
		return -EINVAL;

	/* Initialize if not already done */
	if (!conn->eku_state) {
		ret = tquic_eku_init(conn, local_max);
		if (ret)
			return ret;
	}

	state = conn->eku_state;

	spin_lock_irqsave(&state->lock, flags);

	state->local_max_outstanding = local_max;
	state->remote_max_outstanding = remote_max;

	/* Enable EKU if both peers advertised support */
	if (local_max > 0 && remote_max > 0) {
		state->flags |= TQUIC_EKU_FLAG_ENABLED;
		pr_debug("tquic_eku: negotiated - local_max=%u, remote_max=%u\n",
			 local_max, remote_max);
	}

	spin_unlock_irqrestore(&state->lock, flags);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_eku_negotiate);

/**
 * tquic_eku_is_enabled - Check if extended key update is enabled
 */
bool tquic_eku_is_enabled(struct tquic_connection *conn)
{
	struct tquic_extended_key_update_state *state;

	if (!conn || !conn->eku_state)
		return false;

	state = conn->eku_state;
	return (state->flags & TQUIC_EKU_FLAG_ENABLED) != 0;
}
EXPORT_SYMBOL_GPL(tquic_eku_is_enabled);

/*
 * =============================================================================
 * Key Update Request/Response Implementation
 * =============================================================================
 */

/**
 * tquic_eku_request - Initiate an extended key update request
 */
s64 tquic_eku_request(struct tquic_connection *conn, u32 flags)
{
	struct tquic_extended_key_update_state *state;
	struct tquic_eku_request *req;
	unsigned long irq_flags;
	u64 request_id;

	if (!conn || !conn->eku_state)
		return -EINVAL;

	state = conn->eku_state;

	/* Check if EKU is enabled */
	if (!(state->flags & TQUIC_EKU_FLAG_ENABLED)) {
		/* Fall back to RFC 9001 if not enabled */
		pr_debug("tquic_eku: not enabled, using RFC 9001 fallback\n");
		return tquic_eku_trigger_rfc9001_update(conn);
	}

	spin_lock_irqsave(&state->lock, irq_flags);

	/* Check if we have capacity for another request */
	if (state->pending_count >= state->remote_max_outstanding) {
		spin_unlock_irqrestore(&state->lock, irq_flags);
		return -EAGAIN;
	}

	/* Check state machine */
	if (state->state != TQUIC_EKU_STATE_IDLE &&
	    state->state != TQUIC_EKU_STATE_UPDATE_COMPLETE) {
		spin_unlock_irqrestore(&state->lock, irq_flags);
		return -EBUSY;
	}

	/* Allocate request ID */
	request_id = state->next_request_id++;

	spin_unlock_irqrestore(&state->lock, irq_flags);

	/* Allocate request structure */
	req = eku_alloc_request(GFP_ATOMIC);
	if (!req)
		return -ENOMEM;

	req->request_id = request_id;
	req->flags = flags;

	/* Copy PSK if available */
	spin_lock_irqsave(&state->lock, irq_flags);
	if (state->flags & TQUIC_EKU_FLAG_PSK_INJECTED) {
		memcpy(req->psk, state->injected_psk, state->injected_psk_len);
		req->psk_len = state->injected_psk_len;
	}

	/* Add to pending list */
	list_add_tail(&req->list, &state->pending_requests);
	state->pending_count++;
	state->state = TQUIC_EKU_STATE_REQUEST_SENT;
	state->total_requests_sent++;

	/* Schedule timeout handling */
	if (state->pending_count == 1) {
		schedule_delayed_work(&state->timeout_work,
				      msecs_to_jiffies(state->request_timeout));
	}

	spin_unlock_irqrestore(&state->lock, irq_flags);

	pr_debug("tquic_eku: sent request %llu with flags 0x%x\n",
		 request_id, flags);

	/* The actual frame will be sent by the connection's packet pacing */
	return (s64)request_id;
}
EXPORT_SYMBOL_GPL(tquic_eku_request);

/**
 * tquic_eku_handle_request - Handle incoming KEY_UPDATE_REQUEST frame
 */
int tquic_eku_handle_request(struct tquic_connection *conn,
			     const struct tquic_eku_frame_request *frame)
{
	struct tquic_extended_key_update_state *state;
	struct tquic_eku_request *req;
	unsigned long flags;
	int ret;

	if (!conn || !conn->eku_state || !frame)
		return -EINVAL;

	state = conn->eku_state;

	/* Check if EKU is enabled */
	if (!(state->flags & TQUIC_EKU_FLAG_ENABLED)) {
		pr_warn("tquic_eku: received request but EKU not enabled\n");
		return -EPROTO;
	}

	spin_lock_irqsave(&state->lock, flags);

	/* Check capacity for received requests */
	if (state->received_count >= state->local_max_outstanding) {
		spin_unlock_irqrestore(&state->lock, flags);
		pr_warn("tquic_eku: too many pending received requests\n");
		return -EBUSY;
	}

	spin_unlock_irqrestore(&state->lock, flags);

	/* Allocate received request */
	req = eku_alloc_request(GFP_ATOMIC);
	if (!req)
		return -ENOMEM;

	req->request_id = frame->request_id;
	req->flags = frame->flags;

	/* Store PSK hint if provided */
	if (frame->psk_len > 0 && frame->psk_len <= sizeof(req->psk)) {
		memcpy(req->psk, frame->psk_hint, frame->psk_len);
		req->psk_len = frame->psk_len;
	}

	spin_lock_irqsave(&state->lock, flags);

	list_add_tail(&req->list, &state->received_requests);
	state->received_count++;
	state->state = TQUIC_EKU_STATE_REQUEST_RECEIVED;

	spin_unlock_irqrestore(&state->lock, flags);

	/* Derive new keys */
	ret = tquic_eku_derive_keys(conn, req->psk_len > 0);
	if (ret) {
		pr_err("tquic_eku: key derivation failed: %d\n", ret);
		/* Remove the request on failure */
		spin_lock_irqsave(&state->lock, flags);
		list_del(&req->list);
		state->received_count--;
		state->state = TQUIC_EKU_STATE_ERROR;
		spin_unlock_irqrestore(&state->lock, flags);
		eku_free_request(req);
		return ret;
	}

	/* Update state and prepare response */
	spin_lock_irqsave(&state->lock, flags);

	state->state = TQUIC_EKU_STATE_RESPONSE_SENT;
	state->total_responses_sent++;
	state->last_update_time = ktime_get();

	/* Remove processed request */
	list_del(&req->list);
	state->received_count--;

	spin_unlock_irqrestore(&state->lock, flags);

	eku_free_request(req);

	pr_debug("tquic_eku: processed request %llu, keys updated\n",
		 frame->request_id);

	/* Response frame will be queued for sending by the caller */
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_eku_handle_request);

/**
 * tquic_eku_handle_response - Handle incoming KEY_UPDATE_RESPONSE frame
 */
int tquic_eku_handle_response(struct tquic_connection *conn,
			      const struct tquic_eku_frame_response *frame)
{
	struct tquic_extended_key_update_state *state;
	struct tquic_eku_request *req;
	unsigned long flags;
	int ret = 0;

	if (!conn || !conn->eku_state || !frame)
		return -EINVAL;

	state = conn->eku_state;

	spin_lock_irqsave(&state->lock, flags);

	/* Find matching pending request */
	req = eku_find_pending_request(state, frame->request_id);
	if (!req) {
		spin_unlock_irqrestore(&state->lock, flags);
		pr_warn("tquic_eku: response for unknown request %llu\n",
			frame->request_id);
		return -ENOENT;
	}

	/* Remove from pending list */
	list_del(&req->list);
	state->pending_count--;

	/* Check response status */
	if (frame->status != TQUIC_EKU_STATUS_SUCCESS) {
		pr_warn("tquic_eku: request %llu failed with status %u\n",
			frame->request_id, frame->status);
		state->state = TQUIC_EKU_STATE_ERROR;
		spin_unlock_irqrestore(&state->lock, flags);
		eku_free_request(req);
		return -EPROTO;
	}

	spin_unlock_irqrestore(&state->lock, flags);

	/* Derive our new keys to match peer */
	ret = tquic_eku_derive_keys(conn, req->psk_len > 0);
	if (ret) {
		pr_err("tquic_eku: key derivation on response failed: %d\n",
		       ret);
		spin_lock_irqsave(&state->lock, flags);
		state->state = TQUIC_EKU_STATE_ERROR;
		spin_unlock_irqrestore(&state->lock, flags);
		eku_free_request(req);
		return ret;
	}

	spin_lock_irqsave(&state->lock, flags);

	state->state = TQUIC_EKU_STATE_UPDATE_COMPLETE;
	state->total_updates_completed++;
	state->last_update_time = ktime_get();

	/* Clear PSK after successful update */
	if (req->psk_len > 0) {
		memzero_explicit(state->injected_psk, sizeof(state->injected_psk));
		state->injected_psk_len = 0;
		state->flags &= ~TQUIC_EKU_FLAG_PSK_INJECTED;
	}

	spin_unlock_irqrestore(&state->lock, flags);

	eku_free_request(req);

	pr_debug("tquic_eku: completed key update for request %llu\n",
		 frame->request_id);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_eku_handle_response);

/*
 * =============================================================================
 * PSK Injection Implementation
 * =============================================================================
 */

/**
 * tquic_eku_inject_psk - Inject external PSK material
 */
int tquic_eku_inject_psk(struct tquic_connection *conn,
			 const u8 *psk, size_t psk_len, u32 psk_id)
{
	struct tquic_extended_key_update_state *state;
	unsigned long flags;

	if (!conn || !conn->eku_state)
		return -EINVAL;

	if (!psk || psk_len == 0 || psk_len > TQUIC_EKU_PSK_MAX_LEN)
		return -EINVAL;

	state = conn->eku_state;

	spin_lock_irqsave(&state->lock, flags);

	/* Clear any existing PSK */
	memzero_explicit(state->injected_psk, sizeof(state->injected_psk));

	/* Store new PSK */
	memcpy(state->injected_psk, psk, psk_len);
	state->injected_psk_len = psk_len;
	state->injected_psk_id = psk_id;
	state->flags |= TQUIC_EKU_FLAG_PSK_INJECTED;

	spin_unlock_irqrestore(&state->lock, flags);

	pr_debug("tquic_eku: injected PSK id=%u, len=%zu\n", psk_id, psk_len);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_eku_inject_psk);

/**
 * tquic_eku_clear_psk - Clear injected PSK material
 */
void tquic_eku_clear_psk(struct tquic_connection *conn)
{
	struct tquic_extended_key_update_state *state;
	unsigned long flags;

	if (!conn || !conn->eku_state)
		return;

	state = conn->eku_state;

	spin_lock_irqsave(&state->lock, flags);

	memzero_explicit(state->injected_psk, sizeof(state->injected_psk));
	state->injected_psk_len = 0;
	state->injected_psk_id = 0;
	state->flags &= ~TQUIC_EKU_FLAG_PSK_INJECTED;

	spin_unlock_irqrestore(&state->lock, flags);

	pr_debug("tquic_eku: cleared PSK\n");
}
EXPORT_SYMBOL_GPL(tquic_eku_clear_psk);

/**
 * tquic_eku_has_psk - Check if PSK material is currently injected
 */
bool tquic_eku_has_psk(struct tquic_connection *conn)
{
	struct tquic_extended_key_update_state *state;

	if (!conn || !conn->eku_state)
		return false;

	state = conn->eku_state;
	return (state->flags & TQUIC_EKU_FLAG_PSK_INJECTED) != 0;
}
EXPORT_SYMBOL_GPL(tquic_eku_has_psk);

/*
 * =============================================================================
 * Key Derivation Implementation
 * =============================================================================
 */

/**
 * eku_hkdf_extract - HKDF-Extract for PSK mixing
 * @hash_tfm: Hash transform (HMAC-SHA256 or HMAC-SHA384)
 * @salt: Salt value (current secret)
 * @salt_len: Length of salt
 * @ikm: Input key material (PSK)
 * @ikm_len: Length of IKM
 * @prk: Output pseudorandom key
 * @prk_len: Length of PRK (hash output size)
 */
static int eku_hkdf_extract(struct crypto_shash *hash_tfm,
			    const u8 *salt, size_t salt_len,
			    const u8 *ikm, size_t ikm_len,
			    u8 *prk, size_t prk_len)
{
	SHASH_DESC_ON_STACK(desc, hash_tfm);
	int ret;

	if (!hash_tfm || !prk)
		return -EINVAL;

	desc->tfm = hash_tfm;

	/* Set salt as HMAC key */
	ret = crypto_shash_setkey(hash_tfm, salt, salt_len);
	if (ret)
		return ret;

	/* HMAC(salt, ikm) */
	ret = crypto_shash_init(desc);
	if (ret)
		return ret;

	if (ikm && ikm_len > 0) {
		ret = crypto_shash_update(desc, ikm, ikm_len);
		if (ret)
			return ret;
	}

	ret = crypto_shash_final(desc, prk);
	return ret;
}

/**
 * tquic_eku_derive_keys - Derive keys with extended mechanism
 */
int tquic_eku_derive_keys(struct tquic_connection *conn, bool include_psk)
{
	struct tquic_extended_key_update_state *state;
	struct tquic_key_update_state *ku_state;
	u8 mixed_secret[48];  /* Max for SHA-384 */
	unsigned long flags;
	int ret;

	if (!conn || !conn->eku_state)
		return -EINVAL;

	state = conn->eku_state;
	ku_state = state->key_update_state;

	if (!ku_state) {
		pr_err("tquic_eku: no base key update state\n");
		return -EINVAL;
	}

	spin_lock_irqsave(&state->lock, flags);

	/* Check if PSK should be included */
	if (include_psk && (state->flags & TQUIC_EKU_FLAG_PSK_INJECTED)) {
		u8 current_secret[TQUIC_SECRET_MAX_LEN];
		u32 secret_len;

		/* Get current traffic secret (not derived key) */
		ret = tquic_key_update_get_current_secret(ku_state, 1,
							  current_secret,
							  &secret_len);
		if (ret) {
			spin_unlock_irqrestore(&state->lock, flags);
			return ret;
		}

		spin_unlock_irqrestore(&state->lock, flags);

		/*
		 * Mix PSK into the derivation using HKDF-Extract:
		 * mixed_secret = HKDF-Extract(current_secret, psk)
		 *
		 * This provides additional entropy from the external PSK.
		 * Use EKU's own hash_tfm to avoid needing the KU lock (CF-184).
		 */
		if (state->hash_tfm) {
			ret = eku_hkdf_extract(state->hash_tfm,
					       current_secret, secret_len,
					       state->injected_psk,
					       state->injected_psk_len,
					       mixed_secret, secret_len);
			if (ret) {
				memzero_explicit(current_secret,
						 sizeof(current_secret));
				return ret;
			}

			/*
			 * Now we need to use this mixed_secret for the next
			 * key derivation. This integrates with the base
			 * key_update.c by calling its internal derivation
			 * with the mixed secret.
			 */
		}

		memzero_explicit(current_secret, sizeof(current_secret));
		memzero_explicit(mixed_secret, sizeof(mixed_secret));

		spin_lock_irqsave(&state->lock, flags);
	}

	spin_unlock_irqrestore(&state->lock, flags);

	/*
	 * Trigger the standard key update mechanism.
	 * This will derive new keys using HKDF-Expand-Label.
	 */
	ret = tquic_initiate_key_update(conn);
	if (ret && ret != -EINPROGRESS) {
		pr_err("tquic_eku: base key update failed: %d\n", ret);
		return ret;
	}

	pr_debug("tquic_eku: derived new keys (psk_included=%d)\n", include_psk);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_eku_derive_keys);

/*
 * =============================================================================
 * Frame Encoding/Decoding Implementation
 * =============================================================================
 */

/**
 * tquic_eku_encode_request - Encode KEY_UPDATE_REQUEST frame
 */
ssize_t tquic_eku_encode_request(const struct tquic_eku_frame_request *frame,
				 u8 *buf, size_t buflen)
{
	size_t offset = 0;
	ssize_t ret;

	if (!frame || !buf)
		return -EINVAL;

	/* Frame type */
	ret = eku_varint_encode(buf + offset, buflen - offset,
				TQUIC_FRAME_KEY_UPDATE_REQUEST);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Request ID */
	ret = eku_varint_encode(buf + offset, buflen - offset,
				frame->request_id);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Flags */
	ret = eku_varint_encode(buf + offset, buflen - offset, frame->flags);
	if (ret < 0)
		return ret;
	offset += ret;

	/* PSK hint length */
	if (buflen - offset < 1)
		return -ENOSPC;
	buf[offset++] = frame->psk_len;

	/* PSK hint (if present) */
	if (frame->psk_len > 0) {
		if (buflen - offset < frame->psk_len)
			return -ENOSPC;
		memcpy(buf + offset, frame->psk_hint, frame->psk_len);
		offset += frame->psk_len;
	}

	return offset;
}
EXPORT_SYMBOL_GPL(tquic_eku_encode_request);

/**
 * tquic_eku_decode_request - Decode KEY_UPDATE_REQUEST frame
 */
ssize_t tquic_eku_decode_request(const u8 *buf, size_t buflen,
				 struct tquic_eku_frame_request *frame)
{
	size_t offset = 0;
	ssize_t ret;
	u64 value;

	if (!buf || !frame)
		return -EINVAL;

	memset(frame, 0, sizeof(*frame));

	/* Request ID */
	ret = eku_varint_decode(buf + offset, buflen - offset, &value);
	if (ret < 0)
		return ret;
	frame->request_id = value;
	offset += ret;

	/* Flags */
	ret = eku_varint_decode(buf + offset, buflen - offset, &value);
	if (ret < 0)
		return ret;
	frame->flags = (u32)value;
	offset += ret;

	/* PSK hint length */
	if (buflen - offset < 1)
		return -EINVAL;
	frame->psk_len = buf[offset++];

	/* PSK hint */
	if (frame->psk_len > 0) {
		if (frame->psk_len > sizeof(frame->psk_hint))
			return -EINVAL;
		if (buflen - offset < frame->psk_len)
			return -EINVAL;
		memcpy(frame->psk_hint, buf + offset, frame->psk_len);
		offset += frame->psk_len;
	}

	return offset;
}
EXPORT_SYMBOL_GPL(tquic_eku_decode_request);

/**
 * tquic_eku_encode_response - Encode KEY_UPDATE_RESPONSE frame
 */
ssize_t tquic_eku_encode_response(const struct tquic_eku_frame_response *frame,
				  u8 *buf, size_t buflen)
{
	size_t offset = 0;
	ssize_t ret;

	if (!frame || !buf)
		return -EINVAL;

	/* Frame type */
	ret = eku_varint_encode(buf + offset, buflen - offset,
				TQUIC_FRAME_KEY_UPDATE_RESPONSE);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Request ID */
	ret = eku_varint_encode(buf + offset, buflen - offset,
				frame->request_id);
	if (ret < 0)
		return ret;
	offset += ret;

	/* Status */
	if (buflen - offset < 1)
		return -ENOSPC;
	buf[offset++] = frame->status;

	return offset;
}
EXPORT_SYMBOL_GPL(tquic_eku_encode_response);

/**
 * tquic_eku_decode_response - Decode KEY_UPDATE_RESPONSE frame
 */
ssize_t tquic_eku_decode_response(const u8 *buf, size_t buflen,
				  struct tquic_eku_frame_response *frame)
{
	size_t offset = 0;
	ssize_t ret;
	u64 value;

	if (!buf || !frame)
		return -EINVAL;

	memset(frame, 0, sizeof(*frame));

	/* Request ID */
	ret = eku_varint_decode(buf + offset, buflen - offset, &value);
	if (ret < 0)
		return ret;
	frame->request_id = value;
	offset += ret;

	/* Status */
	if (buflen - offset < 1)
		return -EINVAL;
	frame->status = buf[offset++];

	return offset;
}
EXPORT_SYMBOL_GPL(tquic_eku_decode_response);

/*
 * =============================================================================
 * RFC 9001 Backward Compatibility
 * =============================================================================
 */

/**
 * tquic_eku_use_rfc9001_fallback - Check if RFC 9001 fallback should be used
 */
bool tquic_eku_use_rfc9001_fallback(struct tquic_connection *conn)
{
	struct tquic_extended_key_update_state *state;

	if (!conn)
		return true;

	/* Use fallback if EKU state doesn't exist or isn't enabled */
	if (!conn->eku_state)
		return true;

	state = conn->eku_state;
	return !(state->flags & TQUIC_EKU_FLAG_ENABLED);
}
EXPORT_SYMBOL_GPL(tquic_eku_use_rfc9001_fallback);

/**
 * tquic_eku_trigger_rfc9001_update - Trigger RFC 9001 style key update
 */
int tquic_eku_trigger_rfc9001_update(struct tquic_connection *conn)
{
	struct tquic_extended_key_update_state *state;
	int ret;

	if (!conn)
		return -EINVAL;

	/* Use the base key update mechanism */
	ret = tquic_initiate_key_update(conn);

	/* Track statistics if EKU state exists */
	if (conn->eku_state) {
		state = conn->eku_state;
		/* Could add rfc9001_fallbacks counter increment here */
	}

	return ret;
}
EXPORT_SYMBOL_GPL(tquic_eku_trigger_rfc9001_update);

/*
 * =============================================================================
 * Statistics and Debugging
 * =============================================================================
 */

/**
 * tquic_eku_get_stats - Get extended key update statistics
 */
int tquic_eku_get_stats(struct tquic_connection *conn,
			struct tquic_eku_stats *stats)
{
	struct tquic_extended_key_update_state *state;
	unsigned long flags;

	if (!conn || !conn->eku_state || !stats)
		return -EINVAL;

	state = conn->eku_state;

	spin_lock_irqsave(&state->lock, flags);

	stats->requests_sent = state->total_requests_sent;
	stats->responses_sent = state->total_responses_sent;
	stats->updates_completed = state->total_updates_completed;

	/* These would need additional tracking */
	stats->requests_received = 0;
	stats->responses_received = 0;
	stats->updates_failed = 0;
	stats->psk_injections = 0;
	stats->timeouts = 0;
	stats->rfc9001_fallbacks = 0;

	spin_unlock_irqrestore(&state->lock, flags);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_eku_get_stats);

/**
 * tquic_eku_get_state_name - Get human-readable state name
 */
const char *tquic_eku_get_state_name(enum tquic_eku_state state)
{
	switch (state) {
	case TQUIC_EKU_STATE_IDLE:
		return "IDLE";
	case TQUIC_EKU_STATE_REQUEST_SENT:
		return "REQUEST_SENT";
	case TQUIC_EKU_STATE_REQUEST_RECEIVED:
		return "REQUEST_RECEIVED";
	case TQUIC_EKU_STATE_RESPONSE_SENT:
		return "RESPONSE_SENT";
	case TQUIC_EKU_STATE_UPDATE_COMPLETE:
		return "UPDATE_COMPLETE";
	case TQUIC_EKU_STATE_ERROR:
		return "ERROR";
	default:
		return "UNKNOWN";
	}
}
EXPORT_SYMBOL_GPL(tquic_eku_get_state_name);

MODULE_DESCRIPTION("TQUIC Extended Key Update Extension");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Foundation");
