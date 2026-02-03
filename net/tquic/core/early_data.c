// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * QUIC - Quick UDP Internet Connections
 *
 * 0-RTT Early Data Support (RFC 9001 Section 4.6)
 *
 * This file implements 0-RTT (Zero Round Trip Time) early data support
 * for QUIC, allowing clients to send application data before the
 * handshake completes when resuming a connection with a valid session ticket.
 *
 * Key features:
 * - Session ticket storage and retrieval
 * - 0-RTT key derivation from resumption secret
 * - 0-RTT packet building and sending
 * - 0-RTT packet reception and decryption
 * - 0-RTT rejection handling (re-send as 1-RTT)
 * - Anti-replay protection (timestamps, nonces)
 *
 * Copyright (c) 2024 Linux QUIC Authors
 */

#include <linux/slab.h>
#include <linux/random.h>
#include <crypto/aead.h>
#include <crypto/hash.h>
#include <net/quic.h>

/* HKDF labels for 0-RTT key derivation (RFC 9001 Section 5.1) */
static const char quic_early_traffic_label[] = "c e traffic";
static const char quic_key_label[] = "quic key";
static const char quic_iv_label[] = "quic iv";
static const char quic_hp_label[] = "quic hp";

/* 0-RTT packet type in long header (RFC 9000 Section 17.2.3) */
#define QUIC_LONG_TYPE_0RTT		0x01

/*
 * Maximum 0-RTT data that can be sent (RFC 9001 Section 4.6.1)
 * Default limit if not specified in session ticket
 */
#define QUIC_DEFAULT_MAX_EARLY_DATA	16384

/*
 * Frame types NOT allowed in 0-RTT packets (RFC 9001 Section 4.6.3):
 * - ACK frames
 * - CRYPTO frames
 * - HANDSHAKE_DONE frames
 * - NEW_TOKEN frames
 * - PATH_RESPONSE frames
 * - RETIRE_CONNECTION_ID frames
 */
#define QUIC_0RTT_FORBIDDEN_ACK			0x01
#define QUIC_0RTT_FORBIDDEN_CRYPTO		0x02
#define QUIC_0RTT_FORBIDDEN_NEW_TOKEN		0x04
#define QUIC_0RTT_FORBIDDEN_PATH_RESPONSE	0x08
#define QUIC_0RTT_FORBIDDEN_RETIRE_CID		0x10
#define QUIC_0RTT_FORBIDDEN_HANDSHAKE_DONE	0x20

/*
 * Anti-replay window configuration
 * Per RFC 9001 Section 8, servers MUST implement anti-replay protection
 */
#define ANTI_REPLAY_WINDOW_MS		10000	/* 10 second window */
#define ANTI_REPLAY_HASH_BITS		8
#define ANTI_REPLAY_HASH_SIZE		(1 << ANTI_REPLAY_HASH_BITS)

struct quic_anti_replay {
	spinlock_t		lock;
	ktime_t			window_start;
	struct hlist_head	hash[ANTI_REPLAY_HASH_SIZE];
	u32			count;
};

struct quic_anti_replay_entry {
	struct hlist_node	node;
	u64			ticket_hash;
	ktime_t			time;
};

static struct quic_anti_replay anti_replay_state;

/*
 * quic_anti_replay_init - Initialize anti-replay protection
 */
void quic_anti_replay_init(void)
{
	int i;

	spin_lock_init(&anti_replay_state.lock);
	anti_replay_state.window_start = ktime_get();
	anti_replay_state.count = 0;

	for (i = 0; i < ANTI_REPLAY_HASH_SIZE; i++)
		INIT_HLIST_HEAD(&anti_replay_state.hash[i]);
}
EXPORT_SYMBOL(quic_anti_replay_init);

/*
 * quic_anti_replay_cleanup - Clean up anti-replay state
 */
void quic_anti_replay_cleanup(void)
{
	struct quic_anti_replay_entry *entry;
	struct hlist_node *tmp;
	unsigned long flags;
	int i;

	spin_lock_irqsave(&anti_replay_state.lock, flags);

	for (i = 0; i < ANTI_REPLAY_HASH_SIZE; i++) {
		hlist_for_each_entry_safe(entry, tmp,
					  &anti_replay_state.hash[i], node) {
			hlist_del(&entry->node);
			kfree(entry);
		}
	}
	anti_replay_state.count = 0;

	spin_unlock_irqrestore(&anti_replay_state.lock, flags);
}
EXPORT_SYMBOL(quic_anti_replay_cleanup);

/*
 * Hash a ticket for anti-replay lookup
 */
static u64 quic_ticket_hash(const u8 *ticket, u32 len)
{
	u64 hash = 0xcbf29ce484222325ULL;  /* FNV-1a offset basis */
	u32 i;

	for (i = 0; i < len; i++) {
		hash ^= ticket[i];
		hash *= 0x100000001b3ULL;  /* FNV-1a prime */
	}

	return hash;
}

/*
 * quic_anti_replay_check - Check if ticket has been seen before
 * @ticket: Session ticket data
 * @ticket_len: Length of session ticket
 *
 * Returns true if this is a replay (ticket already seen), false otherwise.
 * On success (not a replay), records the ticket.
 *
 * Per RFC 9001 Section 8:
 * "Servers SHOULD provide a mechanism to limit the time over which
 * a 0-RTT secret might be reused."
 */
bool quic_anti_replay_check(const u8 *ticket, u32 ticket_len)
{
	struct quic_anti_replay_entry *entry, *new_entry;
	struct hlist_node *tmp;
	ktime_t now = ktime_get();
	ktime_t window_threshold;
	u64 hash;
	u32 bucket;
	unsigned long flags;
	bool replay = false;
	int i;

	if (!ticket || ticket_len == 0)
		return true;  /* Invalid ticket is treated as replay */

	hash = quic_ticket_hash(ticket, ticket_len);
	bucket = hash & (ANTI_REPLAY_HASH_SIZE - 1);

	spin_lock_irqsave(&anti_replay_state.lock, flags);

	/* Clean up expired entries */
	window_threshold = ktime_sub_ms(now, ANTI_REPLAY_WINDOW_MS);

	if (ktime_before(anti_replay_state.window_start, window_threshold)) {
		/* Slide the window forward, remove old entries */
		for (i = 0; i < ANTI_REPLAY_HASH_SIZE; i++) {
			hlist_for_each_entry_safe(entry, tmp,
						  &anti_replay_state.hash[i],
						  node) {
				if (ktime_before(entry->time, window_threshold)) {
					hlist_del(&entry->node);
					kfree(entry);
					anti_replay_state.count--;
				}
			}
		}
		anti_replay_state.window_start = now;
	}

	/* Check for replay */
	hlist_for_each_entry(entry, &anti_replay_state.hash[bucket], node) {
		if (entry->ticket_hash == hash) {
			replay = true;
			goto out;
		}
	}

	/* Not a replay - record this ticket */
	new_entry = kmalloc(sizeof(*new_entry), GFP_ATOMIC);
	if (new_entry) {
		new_entry->ticket_hash = hash;
		new_entry->time = now;
		hlist_add_head(&new_entry->node,
			       &anti_replay_state.hash[bucket]);
		anti_replay_state.count++;
	}
	/* On allocation failure, allow the request but log warning */
	else {
		pr_warn_ratelimited("QUIC: anti-replay entry alloc failed\n");
	}

out:
	spin_unlock_irqrestore(&anti_replay_state.lock, flags);

	if (replay)
		pr_debug("QUIC: 0-RTT replay detected, rejecting\n");

	return replay;
}
EXPORT_SYMBOL(quic_anti_replay_check);

/*
 * quic_early_data_derive_keys - Derive 0-RTT keys from resumption secret
 * @conn: QUIC connection
 * @ticket: Session ticket containing resumption secret
 *
 * Derives the client_early_traffic_secret and then the traffic keys
 * per RFC 9001 Section 5.1:
 *
 *   client_early_traffic_secret = HKDF-Expand-Label(
 *       Resumption Secret,
 *       "c e traffic",
 *       ClientHello,
 *       Hash.length)
 *
 * Returns 0 on success, negative error code on failure.
 */
int quic_early_data_derive_keys(struct quic_connection *conn,
				const struct quic_session_ticket *ticket)
{
	struct quic_crypto_ctx *ctx;
	struct crypto_shash *hash;
	SHASH_DESC_ON_STACK(desc, hash);
	u8 early_secret[64];
	u8 info[256];
	size_t info_len;
	const char *hash_name;
	u32 hash_len;
	int err;

	if (!conn || !ticket || ticket->resumption_secret_len == 0)
		return -EINVAL;

	ctx = &conn->crypto[QUIC_CRYPTO_EARLY_DATA];

	/* Initialize crypto context based on cipher from ticket */
	err = quic_crypto_init(ctx, ticket->cipher_type);
	if (err)
		return err;

	/* Determine hash algorithm from cipher suite */
	switch (ticket->cipher_type) {
	case QUIC_CIPHER_AES_128_GCM_SHA256:
	case QUIC_CIPHER_CHACHA20_POLY1305_SHA256:
		hash_name = "hmac(sha256)";
		hash_len = 32;
		break;
	case QUIC_CIPHER_AES_256_GCM_SHA384:
		hash_name = "hmac(sha384)";
		hash_len = 48;
		break;
	default:
		quic_crypto_destroy(ctx);
		return -EINVAL;
	}

	/* Allocate hash for HKDF */
	hash = crypto_alloc_shash(hash_name, 0, 0);
	if (IS_ERR(hash)) {
		quic_crypto_destroy(ctx);
		return PTR_ERR(hash);
	}

	desc->tfm = hash;

	/*
	 * Build HKDF-Expand-Label info for client_early_traffic_secret
	 * HkdfLabel struct:
	 *   uint16 length
	 *   opaque label<7..255> = "tls13 " + Label
	 *   opaque context<0..255> = ClientHello hash (simplified to empty)
	 */
	info[0] = (hash_len >> 8) & 0xff;
	info[1] = hash_len & 0xff;
	info[2] = 6 + sizeof(quic_early_traffic_label) - 1;
	memcpy(&info[3], "tls13 ", 6);
	memcpy(&info[9], quic_early_traffic_label,
	       sizeof(quic_early_traffic_label) - 1);
	info_len = 9 + sizeof(quic_early_traffic_label) - 1;
	info[info_len++] = 0;  /* Empty context */

	/* Set key from resumption secret */
	err = crypto_shash_setkey(hash, ticket->resumption_secret,
				  ticket->resumption_secret_len);
	if (err)
		goto out_free_hash;

	/* Derive client_early_traffic_secret */
	err = crypto_shash_digest(desc, info, info_len, early_secret);
	if (err)
		goto out_free_hash;

	/* Store the secret */
	memcpy(ctx->tx.secret, early_secret, hash_len);
	ctx->tx.secret_len = hash_len;

	/* Derive traffic key from early secret */
	info[0] = (ctx->tx.key_len >> 8) & 0xff;
	info[1] = ctx->tx.key_len & 0xff;
	info[2] = 6 + sizeof(quic_key_label) - 1;
	memcpy(&info[3], "tls13 ", 6);
	memcpy(&info[9], quic_key_label, sizeof(quic_key_label) - 1);
	info_len = 9 + sizeof(quic_key_label) - 1;
	info[info_len++] = 0;

	err = crypto_shash_setkey(hash, early_secret, hash_len);
	if (err)
		goto out_free_hash;

	err = crypto_shash_digest(desc, info, info_len, ctx->tx.key);
	if (err)
		goto out_free_hash;

	/* Derive IV from early secret */
	info[0] = (ctx->tx.iv_len >> 8) & 0xff;
	info[1] = ctx->tx.iv_len & 0xff;
	info[2] = 6 + sizeof(quic_iv_label) - 1;
	memcpy(&info[3], "tls13 ", 6);
	memcpy(&info[9], quic_iv_label, sizeof(quic_iv_label) - 1);
	info_len = 9 + sizeof(quic_iv_label) - 1;
	info[info_len++] = 0;

	err = crypto_shash_digest(desc, info, info_len, ctx->tx.iv);
	if (err)
		goto out_free_hash;

	/* Derive HP key from early secret */
	info[0] = (ctx->tx.hp_key_len >> 8) & 0xff;
	info[1] = ctx->tx.hp_key_len & 0xff;
	info[2] = 6 + sizeof(quic_hp_label) - 1;
	memcpy(&info[3], "tls13 ", 6);
	memcpy(&info[9], quic_hp_label, sizeof(quic_hp_label) - 1);
	info_len = 9 + sizeof(quic_hp_label) - 1;
	info[info_len++] = 0;

	err = crypto_shash_digest(desc, info, info_len, ctx->tx.hp_key);
	if (err)
		goto out_free_hash;

	/* Set keys on crypto transforms */
	err = crypto_aead_setkey(ctx->tx_aead, ctx->tx.key, ctx->tx.key_len);
	if (err)
		goto out_free_hash;

	err = crypto_aead_setauthsize(ctx->tx_aead, 16);
	if (err)
		goto out_free_hash;

	err = crypto_cipher_setkey(ctx->tx_hp, ctx->tx.hp_key,
				   ctx->tx.hp_key_len);
	if (err)
		goto out_free_hash;

	/* Mark keys as available */
	ctx->keys_available = 1;

	/* Copy RX keys for server-side decryption */
	memcpy(&ctx->rx, &ctx->tx, sizeof(ctx->rx));

	if (ctx->rx_aead) {
		err = crypto_aead_setkey(ctx->rx_aead, ctx->rx.key,
					 ctx->rx.key_len);
		if (err)
			goto out_free_hash;

		err = crypto_aead_setauthsize(ctx->rx_aead, 16);
		if (err)
			goto out_free_hash;
	}

	if (ctx->rx_hp) {
		err = crypto_cipher_setkey(ctx->rx_hp, ctx->rx.hp_key,
					   ctx->rx.hp_key_len);
		if (err)
			goto out_free_hash;
	}

	pr_debug("QUIC: 0-RTT keys derived successfully\n");

out_free_hash:
	memzero_explicit(early_secret, sizeof(early_secret));
	crypto_free_shash(hash);
	return err;
}
EXPORT_SYMBOL(quic_early_data_derive_keys);

/*
 * quic_early_data_frame_allowed - Check if frame type is allowed in 0-RTT
 * @frame_type: QUIC frame type
 *
 * Returns true if the frame type can be sent in 0-RTT packets.
 * Per RFC 9001 Section 4.6.3, certain frames are forbidden.
 */
bool quic_early_data_frame_allowed(u8 frame_type)
{
	switch (frame_type) {
	case QUIC_FRAME_ACK:
	case QUIC_FRAME_ACK_ECN:
	case QUIC_FRAME_CRYPTO:
	case QUIC_FRAME_NEW_TOKEN:
	case QUIC_FRAME_PATH_RESPONSE:
	case QUIC_FRAME_RETIRE_CONNECTION_ID:
	case QUIC_FRAME_HANDSHAKE_DONE:
		return false;
	default:
		return true;
	}
}
EXPORT_SYMBOL(quic_early_data_frame_allowed);

/*
 * quic_early_data_build_packet - Build a 0-RTT packet
 * @conn: QUIC connection
 * @pn_space: Packet number space for 0-RTT
 *
 * Builds a 0-RTT Long Header packet per RFC 9000 Section 17.2.3:
 *
 *   0-RTT Packet {
 *     Header Form (1) = 1,
 *     Fixed Bit (1) = 1,
 *     Long Packet Type (2) = 1,
 *     Reserved Bits (2),
 *     Packet Number Length (2),
 *     Version (32),
 *     Destination Connection ID Length (8),
 *     Destination Connection ID (0..160),
 *     Source Connection ID Length (8),
 *     Source Connection ID (0..160),
 *     Length (i),
 *     Packet Number (8..32),
 *     Packet Payload (..),
 *   }
 *
 * Returns the built skb or NULL on failure.
 */
struct sk_buff *quic_early_data_build_packet(struct quic_connection *conn,
					     struct quic_pn_space *pn_space)
{
	struct quic_crypto_ctx *ctx;
	struct sk_buff *skb, *frame_skb;
	u8 *p;
	u8 first_byte;
	u64 pn;
	u8 pn_len;
	int pn_offset;
	int header_len;
	int max_payload;
	int payload_len = 0;

	if (!conn || !conn->early_data_enabled)
		return NULL;

	ctx = &conn->crypto[QUIC_CRYPTO_EARLY_DATA];
	if (!ctx->keys_available)
		return NULL;

	/* Check if we've exceeded early data limit */
	if (conn->early_data_sent >= conn->max_early_data)
		return NULL;

	skb = alloc_skb(QUIC_MAX_PACKET_SIZE + 128, GFP_ATOMIC);
	if (!skb)
		return NULL;

	skb_reserve(skb, 64);  /* Room for UDP/IP headers */

	pn = pn_space->next_pn++;

	/* Determine packet number encoding length */
	if (pn < 0x100)
		pn_len = 1;
	else if (pn < 0x10000)
		pn_len = 2;
	else if (pn < 0x1000000)
		pn_len = 3;
	else
		pn_len = 4;

	/* Build 0-RTT Long Header */
	first_byte = 0x80 | 0x40 | (QUIC_LONG_TYPE_0RTT << 4) | (pn_len - 1);

	p = skb_put(skb, 1);
	*p = first_byte;

	/* Version */
	p = skb_put(skb, 4);
	p[0] = (conn->version >> 24) & 0xff;
	p[1] = (conn->version >> 16) & 0xff;
	p[2] = (conn->version >> 8) & 0xff;
	p[3] = conn->version & 0xff;

	/* DCID Length + DCID */
	p = skb_put(skb, 1);
	*p = conn->dcid.len;
	if (conn->dcid.len > 0) {
		p = skb_put(skb, conn->dcid.len);
		memcpy(p, conn->dcid.data, conn->dcid.len);
	}

	/* SCID Length + SCID */
	p = skb_put(skb, 1);
	*p = conn->scid.len;
	if (conn->scid.len > 0) {
		p = skb_put(skb, conn->scid.len);
		memcpy(p, conn->scid.data, conn->scid.len);
	}

	/* Length field - 2-byte varint placeholder */
	p = skb_put(skb, 2);
	p[0] = 0x40;  /* 2-byte varint prefix */
	p[1] = 0x00;

	pn_offset = skb->len;
	header_len = pn_offset + pn_len;

	/* Packet number */
	p = skb_put(skb, pn_len);
	switch (pn_len) {
	case 1:
		p[0] = pn & 0xff;
		break;
	case 2:
		p[0] = (pn >> 8) & 0xff;
		p[1] = pn & 0xff;
		break;
	case 3:
		p[0] = (pn >> 16) & 0xff;
		p[1] = (pn >> 8) & 0xff;
		p[2] = pn & 0xff;
		break;
	case 4:
		p[0] = (pn >> 24) & 0xff;
		p[1] = (pn >> 16) & 0xff;
		p[2] = (pn >> 8) & 0xff;
		p[3] = pn & 0xff;
		break;
	}

	QUIC_SKB_CB(skb)->header_len = header_len;
	QUIC_SKB_CB(skb)->pn = pn;
	QUIC_SKB_CB(skb)->pn_len = pn_len;

	/* Add frames from early data buffer (only allowed frame types) */
	max_payload = QUIC_MAX_PACKET_SIZE - header_len - 16;

	while (!skb_queue_empty(&conn->early_data_buffer) &&
	       payload_len < max_payload) {
		u8 frame_type;

		frame_skb = skb_dequeue(&conn->early_data_buffer);
		if (!frame_skb)
			break;

		/* Validate frame type is allowed in 0-RTT */
		frame_type = frame_skb->data[0];
		if (!quic_early_data_frame_allowed(frame_type)) {
			/* Re-queue forbidden frame for 1-RTT */
			skb_queue_head(&conn->pending_frames, frame_skb);
			continue;
		}

		if (payload_len + frame_skb->len > max_payload) {
			skb_queue_head(&conn->early_data_buffer, frame_skb);
			break;
		}

		p = skb_put(skb, frame_skb->len);
		skb_copy_bits(frame_skb, 0, p, frame_skb->len);
		payload_len += frame_skb->len;

		/* Track early data sent */
		conn->early_data_sent += frame_skb->len;

		kfree_skb(frame_skb);
	}

	if (payload_len == 0) {
		/* No frames to send */
		kfree_skb(skb);
		return NULL;
	}

	/* Update length field */
	{
		u64 length = pn_len + payload_len + 16;  /* PN + payload + tag */
		int len_offset;

		if (pn_offset < 2) {
			kfree_skb(skb);
			return NULL;
		}
		len_offset = pn_offset - 2;

		skb->data[len_offset] = 0x40 | ((length >> 8) & 0x3f);
		skb->data[len_offset + 1] = length & 0xff;
	}

	/* Encrypt packet */
	if (quic_crypto_encrypt(ctx, skb, pn) < 0) {
		kfree_skb(skb);
		return NULL;
	}

	/* Apply header protection */
	if (quic_crypto_protect_header(ctx, skb, pn_offset, pn_len) < 0) {
		kfree_skb(skb);
		return NULL;
	}

	/* Track sent packet */
	{
		struct quic_sent_packet *sent;

		sent = kzalloc(sizeof(*sent), GFP_ATOMIC);
		if (!sent) {
			kfree_skb(skb);
			return NULL;
		}
		sent->pn = pn;
		sent->sent_time = ktime_get();
		sent->size = skb->len;
		sent->ack_eliciting = 1;
		sent->in_flight = 1;
		sent->pn_space = QUIC_CRYPTO_EARLY_DATA;
		INIT_LIST_HEAD(&sent->list);

		quic_loss_detection_on_packet_sent(conn, sent);
	}

	atomic64_inc(&conn->stats.packets_sent);
	atomic64_add(skb->len, &conn->stats.bytes_sent);

	pr_debug("QUIC: Built 0-RTT packet, pn=%llu, len=%d\n", pn, skb->len);

	return skb;
}
EXPORT_SYMBOL(quic_early_data_build_packet);

/*
 * quic_early_data_process_packet - Process received 0-RTT packet
 * @conn: QUIC connection
 * @skb: Received 0-RTT packet
 *
 * Decrypts and processes a 0-RTT packet from the client.
 * The server must have 0-RTT keys available from the session ticket.
 *
 * Returns 0 on success, negative error code on failure.
 */
int quic_early_data_process_packet(struct quic_connection *conn,
				   struct sk_buff *skb)
{
	struct quic_crypto_ctx *ctx;
	u8 pn_offset, pn_len;
	u64 truncated_pn, pn;
	int err;

	if (!conn || !skb)
		return -EINVAL;

	/* Server must have 0-RTT keys */
	ctx = &conn->crypto[QUIC_CRYPTO_EARLY_DATA];
	if (!ctx->keys_available) {
		pr_debug("QUIC: 0-RTT keys not available, rejecting\n");
		conn->early_data_rejected = 1;
		return -ENOKEY;
	}

	/* Remove header protection */
	err = quic_crypto_unprotect_header(ctx, skb, &pn_offset, &pn_len);
	if (err) {
		pr_debug("QUIC: Failed to unprotect 0-RTT header\n");
		return err;
	}

	/* Decode packet number */
	truncated_pn = 0;
	for (int i = 0; i < pn_len; i++)
		truncated_pn = (truncated_pn << 8) | skb->data[pn_offset + i];

	/* Reconstruct full packet number */
	{
		u64 expected_pn = conn->pn_spaces[QUIC_CRYPTO_EARLY_DATA].largest_recv_pn + 1;
		u64 pn_win = 1ULL << (pn_len * 8);
		u64 pn_hwin = pn_win / 2;
		u64 pn_mask = pn_win - 1;
		u64 candidate_pn;

		candidate_pn = (expected_pn & ~pn_mask) | truncated_pn;

		if (candidate_pn <= expected_pn - pn_hwin &&
		    candidate_pn < (1ULL << 62) - pn_win)
			pn = candidate_pn + pn_win;
		else if (candidate_pn > expected_pn + pn_hwin &&
			 candidate_pn >= pn_win)
			pn = candidate_pn - pn_win;
		else
			pn = candidate_pn;
	}

	QUIC_SKB_CB(skb)->pn = pn;
	QUIC_SKB_CB(skb)->pn_len = pn_len;
	QUIC_SKB_CB(skb)->header_len = pn_offset + pn_len;

	/* Decrypt packet */
	err = quic_crypto_decrypt(ctx, skb, pn);
	if (err) {
		pr_debug("QUIC: Failed to decrypt 0-RTT packet\n");
		conn->early_data_rejected = 1;
		return err;
	}

	/* Update largest received packet number */
	if (pn > conn->pn_spaces[QUIC_CRYPTO_EARLY_DATA].largest_recv_pn)
		conn->pn_spaces[QUIC_CRYPTO_EARLY_DATA].largest_recv_pn = pn;

	/* Mark 0-RTT as accepted */
	conn->early_data_accepted = 1;

	/* Process frames (note: no ACK recording for 0-RTT at Initial level) */
	quic_frame_process_all(conn, skb, QUIC_CRYPTO_EARLY_DATA);

	atomic64_inc(&conn->stats.packets_received);
	atomic64_add(skb->len, &conn->stats.bytes_received);

	pr_debug("QUIC: Processed 0-RTT packet, pn=%llu\n", pn);

	return 0;
}
EXPORT_SYMBOL(quic_early_data_process_packet);

/*
 * quic_early_data_reject - Handle 0-RTT rejection
 * @conn: QUIC connection
 *
 * Called when the server rejects 0-RTT data. All 0-RTT data must be
 * retransmitted as 1-RTT data after the handshake completes.
 *
 * Per RFC 9001 Section 4.6.2:
 * "A client that attempts 0-RTT might also need to retransmit the
 * data once the handshake is complete."
 */
void quic_early_data_reject(struct quic_connection *conn)
{
	struct sk_buff *skb;

	if (!conn)
		return;

	conn->early_data_rejected = 1;
	conn->early_data_accepted = 0;

	pr_info("QUIC: 0-RTT rejected, will retransmit as 1-RTT\n");

	/* Move all early data frames to pending frames for 1-RTT */
	while ((skb = skb_dequeue(&conn->early_data_buffer)) != NULL) {
		if (quic_conn_queue_frame(conn, skb)) {
			/* Queue full, drop remaining frames */
			kfree_skb(skb);
			skb_queue_purge(&conn->early_data_buffer);
			break;
		}
	}

	/* Clear 0-RTT crypto context */
	quic_crypto_destroy(&conn->crypto[QUIC_CRYPTO_EARLY_DATA]);
}
EXPORT_SYMBOL(quic_early_data_reject);

/*
 * quic_early_data_accept - Handle 0-RTT acceptance
 * @conn: QUIC connection
 *
 * Called when the server accepts 0-RTT data. The client can stop
 * buffering 0-RTT data for potential retransmission.
 */
void quic_early_data_accept(struct quic_connection *conn)
{
	if (!conn)
		return;

	conn->early_data_accepted = 1;
	conn->early_data_rejected = 0;

	pr_debug("QUIC: 0-RTT accepted by server\n");
}
EXPORT_SYMBOL(quic_early_data_accept);

/*
 * quic_early_data_init - Initialize 0-RTT state for connection
 * @conn: QUIC connection
 * @ticket: Session ticket for 0-RTT (NULL for server)
 *
 * Sets up the connection for 0-RTT operation.
 *
 * Returns 0 on success, negative error code on failure.
 */
int quic_early_data_init(struct quic_connection *conn,
			 const struct quic_session_ticket *ticket)
{
	int err;

	if (!conn)
		return -EINVAL;

	skb_queue_head_init(&conn->early_data_buffer);
	conn->early_data_enabled = 0;
	conn->early_data_accepted = 0;
	conn->early_data_rejected = 0;
	conn->early_data_sent = 0;

	/* Client with session ticket: derive 0-RTT keys */
	if (!conn->is_server && ticket && ticket->resumption_secret_len > 0) {
		conn->max_early_data = ticket->max_early_data;
		if (conn->max_early_data == 0)
			conn->max_early_data = QUIC_DEFAULT_MAX_EARLY_DATA;

		err = quic_early_data_derive_keys(conn, ticket);
		if (err) {
			pr_debug("QUIC: Failed to derive 0-RTT keys: %d\n", err);
			return err;
		}

		conn->early_data_enabled = 1;
		conn->pn_spaces[QUIC_CRYPTO_EARLY_DATA].keys_available = 1;

		pr_debug("QUIC: 0-RTT initialized, max_early_data=%u\n",
			 conn->max_early_data);
	}

	return 0;
}
EXPORT_SYMBOL(quic_early_data_init);

/*
 * quic_early_data_cleanup - Clean up 0-RTT state
 * @conn: QUIC connection
 */
void quic_early_data_cleanup(struct quic_connection *conn)
{
	if (!conn)
		return;

	skb_queue_purge(&conn->early_data_buffer);
	quic_crypto_destroy(&conn->crypto[QUIC_CRYPTO_EARLY_DATA]);

	conn->early_data_enabled = 0;
}
EXPORT_SYMBOL(quic_early_data_cleanup);

/*
 * quic_session_ticket_store - Store a session ticket for future 0-RTT
 * @qsk: QUIC socket
 * @ticket: Session ticket from NEW_SESSION_TICKET
 *
 * Called when receiving NEW_SESSION_TICKET from server.
 * Stores the ticket for future connection resumption with 0-RTT.
 *
 * Returns 0 on success, negative error code on failure.
 */
int quic_session_ticket_store(struct quic_sock *qsk,
			      const struct quic_session_ticket *ticket)
{
	struct quic_session_ticket *new_ticket;

	if (!qsk || !ticket || ticket->ticket_len == 0)
		return -EINVAL;

	if (ticket->ticket_len > QUIC_MAX_SESSION_TICKET_LEN)
		return -EINVAL;

	new_ticket = kmalloc(sizeof(*new_ticket), GFP_KERNEL);
	if (!new_ticket)
		return -ENOMEM;

	memcpy(new_ticket, ticket, sizeof(*new_ticket));

	/* Free old ticket if exists */
	kfree(qsk->session_ticket_data);
	qsk->session_ticket_data = new_ticket;

	/* Also update raw ticket pointer for backward compatibility */
	kfree(qsk->session_ticket);
	qsk->session_ticket = kmemdup(ticket->ticket, ticket->ticket_len,
				      GFP_KERNEL);
	qsk->session_ticket_len = ticket->ticket_len;

	pr_debug("QUIC: Session ticket stored, len=%u, max_early_data=%u\n",
		 ticket->ticket_len, ticket->max_early_data);

	return 0;
}
EXPORT_SYMBOL(quic_session_ticket_store);

/*
 * quic_session_ticket_retrieve - Retrieve stored session ticket
 * @qsk: QUIC socket
 *
 * Returns the stored session ticket or NULL if none exists.
 */
struct quic_session_ticket *quic_session_ticket_retrieve(struct quic_sock *qsk)
{
	if (!qsk)
		return NULL;

	return qsk->session_ticket_data;
}
EXPORT_SYMBOL(quic_session_ticket_retrieve);

/*
 * quic_session_ticket_valid - Check if session ticket is still valid
 * @ticket: Session ticket to check
 *
 * Returns true if ticket is valid for 0-RTT, false otherwise.
 */
bool quic_session_ticket_valid(const struct quic_session_ticket *ticket)
{
	ktime_t now;
	u64 age_ms;

	if (!ticket || ticket->ticket_len == 0)
		return false;

	if (ticket->resumption_secret_len == 0)
		return false;

	/* Check ticket lifetime */
	now = ktime_get();
	age_ms = ktime_to_ms(now) - ticket->issued_time;

	if (age_ms > ticket->lifetime)
		return false;

	return true;
}
EXPORT_SYMBOL(quic_session_ticket_valid);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux QUIC Authors");
MODULE_DESCRIPTION("QUIC 0-RTT Early Data Support");
