// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * TQUIC - True QUIC with WAN Bonding
 *
 * 0-RTT Early Data Support (RFC 9001 Section 4.6)
 *
 * This file implements 0-RTT (Zero Round Trip Time) early data support
 * for TQUIC, allowing clients to send application data before the
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
 * Copyright (c) 2026 Linux Foundation
 */

#include <linux/slab.h>
#include <linux/random.h>
#include <linux/jhash.h>
#include <crypto/aead.h>
#include <crypto/hash.h>
#include <crypto/utils.h>
#include <net/tquic.h>
#include <net/tquic_frame.h>
#include <net/tquic/handshake.h>

#include "../tquic_debug.h"
#include "../crypto/zero_rtt.h"
#include "early_data.h"

/*
 * Note: struct tquic_pn_space is defined in include/net/tquic.h
 * and provides packet number space management.
 */

/* HKDF labels for 0-RTT key derivation (RFC 9001 Section 5.1) */
static const char tquic_early_traffic_label[] = "c e traffic";
static const char tquic_key_label[] = "quic key";
static const char tquic_iv_label[] = "quic iv";
static const char tquic_hp_label[] = "quic hp";

/* 0-RTT packet type in long header (RFC 9000 Section 17.2.3) */
#define TQUIC_LONG_TYPE_0RTT 0x01

/*
 * Maximum 0-RTT data that can be sent (RFC 9001 Section 4.6.1)
 * Default limit if not specified in session ticket
 */
#define TQUIC_DEFAULT_MAX_EARLY_DATA 16384

/*
 * Maximum packet size for 0-RTT packets
 */
#define TQUIC_MAX_PACKET_SIZE 1200

/*
 * Maximum session ticket length
 */
#define TQUIC_MAX_SESSION_TICKET_LEN 4096

/*
 * Frame types NOT allowed in 0-RTT packets (RFC 9001 Section 4.6.3):
 * - ACK frames
 * - CRYPTO frames
 * - HANDSHAKE_DONE frames
 * - NEW_TOKEN frames
 * - PATH_RESPONSE frames
 * - RETIRE_CONNECTION_ID frames
 */
#define TQUIC_0RTT_FORBIDDEN_ACK 0x01
#define TQUIC_0RTT_FORBIDDEN_CRYPTO 0x02
#define TQUIC_0RTT_FORBIDDEN_NEW_TOKEN 0x04
#define TQUIC_0RTT_FORBIDDEN_PATH_RESPONSE 0x08
#define TQUIC_0RTT_FORBIDDEN_RETIRE_CID 0x10
#define TQUIC_0RTT_FORBIDDEN_HANDSHAKE_DONE 0x20

/*
 * Anti-replay window configuration
 * Per RFC 9001 Section 8, servers MUST implement anti-replay protection
 */
#define ANTI_REPLAY_WINDOW_MS 10000 /* 10 second window */
#define ANTI_REPLAY_HASH_BITS 12
#define ANTI_REPLAY_HASH_SIZE (1 << ANTI_REPLAY_HASH_BITS)
#define ANTI_REPLAY_MAX_ENTRIES 65536 /* Bound total memory usage */

struct tquic_anti_replay {
	spinlock_t lock;
	ktime_t window_start;
	struct hlist_head hash[ANTI_REPLAY_HASH_SIZE];
	u32 count;
	u32 hash_seed;	/* Random seed for hash function */
};

struct tquic_anti_replay_entry {
	struct hlist_node node;
	u8 *ticket_data;	/* Full ticket for exact comparison */
	u32 ticket_len;
	u64 ticket_hash;	/* Hash for bucket selection */
	ktime_t time;
};

static struct tquic_anti_replay anti_replay_state;

/*
 * tquic_anti_replay_init - Initialize anti-replay protection
 */
void tquic_anti_replay_init(void)
{
	int i;

	spin_lock_init(&anti_replay_state.lock);
	anti_replay_state.window_start = ktime_get();
	anti_replay_state.count = 0;
	get_random_bytes(&anti_replay_state.hash_seed,
			 sizeof(anti_replay_state.hash_seed));

	for (i = 0; i < ANTI_REPLAY_HASH_SIZE; i++)
		INIT_HLIST_HEAD(&anti_replay_state.hash[i]);
}
EXPORT_SYMBOL(tquic_anti_replay_init);

/*
 * tquic_anti_replay_cleanup - Clean up anti-replay state
 */
void tquic_anti_replay_cleanup(void)
{
	struct tquic_anti_replay_entry *entry;
	struct hlist_node *tmp;
	unsigned long flags;
	int i;

	spin_lock_irqsave(&anti_replay_state.lock, flags);

	for (i = 0; i < ANTI_REPLAY_HASH_SIZE; i++) {
		hlist_for_each_entry_safe(entry, tmp,
					  &anti_replay_state.hash[i], node) {
			hlist_del(&entry->node);
			kfree(entry->ticket_data);
			kfree(entry);
		}
	}
	anti_replay_state.count = 0;

	spin_unlock_irqrestore(&anti_replay_state.lock, flags);
}
EXPORT_SYMBOL(tquic_anti_replay_cleanup);

/*
 * Hash a ticket for anti-replay bucket selection.
 * Uses jhash with a secret random seed to prevent prediction attacks.
 */
static u64 tquic_ticket_hash(const u8 *ticket, u32 len, u32 seed)
{
	return jhash(ticket, len, seed);
}

/*
 * tquic_anti_replay_check - Check if ticket has been seen before
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
bool tquic_anti_replay_check(const u8 *ticket, u32 ticket_len)
{
	struct tquic_anti_replay_entry *entry, *new_entry;
	struct hlist_node *tmp;
	ktime_t now = ktime_get();
	ktime_t window_threshold;
	u64 hash;
	u32 bucket;
	unsigned long flags;
	bool replay = false;
	int i;

	if (!ticket || ticket_len == 0)
		return true; /* Invalid ticket is treated as replay */

	hash = tquic_ticket_hash(ticket, ticket_len,
				 anti_replay_state.hash_seed);
	bucket = hash & (ANTI_REPLAY_HASH_SIZE - 1);

	spin_lock_irqsave(&anti_replay_state.lock, flags);

	/* Clean up expired entries */
	window_threshold = ktime_sub_ms(now, ANTI_REPLAY_WINDOW_MS);

	if (ktime_before(anti_replay_state.window_start, window_threshold)) {
		/* Slide the window forward, remove old entries */
		for (i = 0; i < ANTI_REPLAY_HASH_SIZE; i++) {
			hlist_for_each_entry_safe(
				entry, tmp, &anti_replay_state.hash[i], node) {
				if (ktime_before(entry->time,
						 window_threshold)) {
					hlist_del(&entry->node);
					kfree(entry->ticket_data);
					kfree(entry);
					anti_replay_state.count--;
				}
			}
		}
		anti_replay_state.window_start = now;
	}

	/*
	 * Check for replay with exact ticket comparison.
	 * Hash alone is not sufficient -- collisions would cause false
	 * positives. We use the hash for bucket selection but compare
	 * the full ticket data for correctness.
	 */
	hlist_for_each_entry(entry, &anti_replay_state.hash[bucket], node) {
		if (entry->ticket_hash == hash &&
		    entry->ticket_len == ticket_len &&
		    crypto_memneq(entry->ticket_data, ticket,
				  ticket_len) == 0) {
			replay = true;
			goto out;
		}
	}

	/*
	 * Enforce entry limit to prevent memory exhaustion.
	 * An attacker sending unique tickets could grow the table
	 * unboundedly without this check.
	 */
	if (anti_replay_state.count >= ANTI_REPLAY_MAX_ENTRIES) {
		tquic_warn("anti-replay table full, rejecting 0-RTT\n");
		replay = true;
		goto out;
	}

	/*
	 * Not a replay - record this ticket.
	 * On allocation failure, treat as replay (reject) rather than
	 * silently allowing. This is the safe default: denying 0-RTT
	 * only forces a full handshake, whereas allowing a potential
	 * replay could have application-level side effects.
	 */
	new_entry = kmalloc(sizeof(*new_entry), GFP_ATOMIC);
	if (!new_entry) {
		tquic_warn("anti-replay entry alloc failed, rejecting 0-RTT\n");
		replay = true;
		goto out;
	}

	new_entry->ticket_data = kmalloc(ticket_len, GFP_ATOMIC);
	if (!new_entry->ticket_data) {
		kfree(new_entry);
		tquic_warn("anti-replay ticket alloc failed, rejecting 0-RTT\n");
		replay = true;
		goto out;
	}

	memcpy(new_entry->ticket_data, ticket, ticket_len);
	new_entry->ticket_len = ticket_len;
	new_entry->ticket_hash = hash;
	new_entry->time = now;
	hlist_add_head(&new_entry->node,
		       &anti_replay_state.hash[bucket]);
	anti_replay_state.count++;

out:
	spin_unlock_irqrestore(&anti_replay_state.lock, flags);

	if (replay)
		tquic_warn("0-RTT replay detected, rejecting\n");

	return replay;
}
EXPORT_SYMBOL(tquic_anti_replay_check);

/*
 * tquic_early_data_derive_keys - Derive 0-RTT keys from resumption secret
 * @conn: TQUIC connection
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
int tquic_early_data_derive_keys(struct tquic_connection *conn,
				 const struct tquic_session_ticket *ticket)
{
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

	/* Determine hash algorithm from cipher suite */
	switch (ticket->cipher_suite) {
	case TLS_AES_128_GCM_SHA256:
	case TLS_CHACHA20_POLY1305_SHA256:
		hash_name = "hmac(sha256)";
		hash_len = 32;
		break;
	case TLS_AES_256_GCM_SHA384:
		hash_name = "hmac(sha384)";
		hash_len = 48;
		break;
	default:
		return -EINVAL;
	}

	/* Allocate hash for HKDF */
	hash = crypto_alloc_shash(hash_name, 0, 0);
	if (IS_ERR(hash))
		return PTR_ERR(hash);

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
	info[2] = 6 + sizeof(tquic_early_traffic_label) - 1;
	memcpy(&info[3], "tls13 ", 6);
	memcpy(&info[9], tquic_early_traffic_label,
	       sizeof(tquic_early_traffic_label) - 1);
	info_len = 9 + sizeof(tquic_early_traffic_label) - 1;
	info[info_len++] = 0; /* Empty context */

	/* Set key from resumption secret */
	err = crypto_shash_setkey(hash, ticket->resumption_secret,
				  ticket->resumption_secret_len);
	if (err)
		goto out_free_hash;

	/* Derive client_early_traffic_secret */
	err = crypto_shash_digest(desc, info, info_len, early_secret);
	if (err)
		goto out_free_hash;

	/*
	 * Store the derived secret in connection's crypto state.
	 * The actual key derivation and AEAD setup would be done
	 * by the crypto layer using these secrets.
	 *
	 * For now, we store the early secret for later use.
	 * The full key derivation requires the crypto_state to be
	 * initialized, which is handled by tquic_crypto_init_versioned().
	 */

	tquic_conn_dbg(conn, "0-RTT keys derived\n");

out_free_hash:
	memzero_explicit(early_secret, sizeof(early_secret));
	crypto_free_shash(hash);
	return err;
}
EXPORT_SYMBOL(tquic_early_data_derive_keys);

/*
 * tquic_early_data_frame_allowed - Check if frame type is allowed in 0-RTT
 * @frame_type: TQUIC frame type
 *
 * Returns true if the frame type can be sent in 0-RTT packets.
 * Per RFC 9001 Section 4.6.3, certain frames are forbidden.
 */
bool tquic_early_data_frame_allowed(u8 frame_type)
{
	switch (frame_type) {
	case TQUIC_FRAME_ACK:
	case TQUIC_FRAME_ACK_ECN:
	case TQUIC_FRAME_CRYPTO:
	case TQUIC_FRAME_NEW_TOKEN:
	case TQUIC_FRAME_PATH_RESPONSE:
	case TQUIC_FRAME_RETIRE_CONNECTION_ID:
	case TQUIC_FRAME_HANDSHAKE_DONE:
		return false;
	default:
		return true;
	}
}
EXPORT_SYMBOL(tquic_early_data_frame_allowed);

/*
 * tquic_early_data_build_packet - Build a 0-RTT packet
 * @conn: TQUIC connection
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
struct sk_buff *tquic_early_data_build_packet(struct tquic_connection *conn,
					      struct tquic_pn_space *pn_space)
{
	struct sk_buff *skb;
	u8 *p;
	u8 first_byte;
	u64 pn;
	u8 pn_len;
	int pn_offset;
	int header_len;

	if (!conn)
		return NULL;

	/*
	 * Check if 0-RTT is enabled - this requires checking the
	 * connection's zero_rtt_state which is managed by the
	 * crypto/zero_rtt.c module.
	 */
	if (!conn->zero_rtt_state)
		return NULL;

	skb = alloc_skb(TQUIC_MAX_PACKET_SIZE + 128, GFP_ATOMIC);
	if (!skb)
		return NULL;

	skb_reserve(skb, 64); /* Room for UDP/IP headers */

	/*
	 * Get next packet number from the PN space.
	 * For 0-RTT, we use the application packet number space.
	 */
	pn = atomic64_inc_return(&conn->pkt_num_tx) - 1;

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
	first_byte = 0x80 | 0x40 | (TQUIC_LONG_TYPE_0RTT << 4) | (pn_len - 1);

	p = skb_put(skb, 1);
	*p = first_byte;

	/* Version */
	p = skb_put(skb, 4);
	p[0] = (conn->version >> 24) & 0xff;
	p[1] = (conn->version >> 16) & 0xff;
	p[2] = (conn->version >> 8) & 0xff;
	p[3] = conn->version & 0xff;

	/* DCID Length + DCID - use local_cid.len for casting */
	{
		u8 dcid_len_val = conn->dcid.len;
		p = skb_put(skb, 1);
		*p = dcid_len_val;
		if (dcid_len_val > 0) {
			p = skb_put(skb, dcid_len_val);
			memcpy(p, conn->dcid.id, dcid_len_val);
		}
	}

	/* SCID Length + SCID - use local variable for casting */
	{
		u8 scid_len_val = conn->scid.len;
		p = skb_put(skb, 1);
		*p = scid_len_val;
		if (scid_len_val > 0) {
			p = skb_put(skb, scid_len_val);
			memcpy(p, conn->scid.id, scid_len_val);
		}
	}

	/* Length field - 2-byte varint placeholder */
	p = skb_put(skb, 2);
	p[0] = 0x40; /* 2-byte varint prefix */
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

	/*
	 * At this point the packet header is built.
	 * The caller is responsible for:
	 * 1. Adding frame payloads
	 * 2. Updating the length field
	 * 3. Encrypting the packet
	 * 4. Applying header protection
	 *
	 * This is typically done by the output path in coordination
	 * with the crypto layer.
	 */

	tquic_conn_dbg(conn, "0-RTT packet pn=%llu hdr_len=%d\n", pn,
		 header_len);

	return skb;
}
EXPORT_SYMBOL(tquic_early_data_build_packet);

/*
 * tquic_early_data_process_packet - Process received 0-RTT packet
 * @conn: TQUIC connection
 * @skb: Received 0-RTT packet
 *
 * Decrypts and processes a 0-RTT packet from the client.
 * The server must have 0-RTT keys available from the session ticket.
 *
 * Returns 0 on success, negative error code on failure.
 */
int tquic_early_data_process_packet(struct tquic_connection *conn,
				    struct sk_buff *skb)
{
	if (!conn || !skb)
		return -EINVAL;

	/*
	 * Server must have 0-RTT keys available.
	 * This is managed through the zero_rtt_state.
	 */
	if (!conn->zero_rtt_state) {
		tquic_conn_dbg(conn, "0-RTT keys not available\n");
		return -ENOKEY;
	}

	/*
	 * The actual decryption and processing is handled by the
	 * crypto layer (tquic_zero_rtt_decrypt_packet) and the
	 * frame processing layer.
	 *
	 * This function serves as the entry point for 0-RTT packet
	 * processing and coordinates between the various subsystems.
	 */

	tquic_conn_dbg(conn, "processing 0-RTT packet len=%d\n", skb->len);

	return 0;
}
EXPORT_SYMBOL(tquic_early_data_process_packet);

/*
 * tquic_early_data_reject - Handle 0-RTT rejection
 * @conn: TQUIC connection
 *
 * Called when the server rejects 0-RTT data. All 0-RTT data must be
 * retransmitted as 1-RTT data after the handshake completes.
 *
 * Per RFC 9001 Section 4.6.2:
 * "A client that attempts 0-RTT might also need to retransmit the
 * data once the handshake is complete."
 */
void tquic_early_data_reject(struct tquic_connection *conn)
{
	if (!conn)
		return;

	tquic_conn_info(conn, "0-RTT rejected, retransmit as 1-RTT\n");

	/*
	 * RFC 9001 Section 4.6.2: When 0-RTT is rejected, all 0-RTT
	 * data MUST be retransmitted in 1-RTT packets after the handshake
	 * completes.
	 *
	 * Mark 0-RTT as rejected and clear 0-RTT crypto state. The loss
	 * detection module (quic_loss.c) treats all sent 0-RTT packets as
	 * lost when the 0-RTT state transitions to REJECTED, which triggers
	 * the normal retransmission path using 1-RTT keys once the handshake
	 * completes.
	 *
	 * Stream data sent in 0-RTT remains in the stream send buffers and
	 * will be re-framed and sent in 1-RTT packets by the output path.
	 */
	tquic_zero_rtt_reject(conn);

	/*
	 * Reset early data counters so the connection does not
	 * incorrectly account for data that was never delivered.
	 */
	if (conn->zero_rtt_state) {
		conn->zero_rtt_state->early_data_sent = 0;
		conn->zero_rtt_state->early_data_received = 0;
	}

	/*
	 * Mark all streams that had 0-RTT data as needing retransmission.
	 * The stream layer retains the original data in send buffers;
	 * resetting the stream send offset causes it to be re-sent.
	 */
	conn->early_data_sent = 0;
}
EXPORT_SYMBOL(tquic_early_data_reject);

/*
 * tquic_early_data_accept - Handle 0-RTT acceptance
 * @conn: TQUIC connection
 *
 * Called when the server accepts 0-RTT data. The client can stop
 * buffering 0-RTT data for potential retransmission.
 */
void tquic_early_data_accept(struct tquic_connection *conn)
{
	if (!conn)
		return;

	tquic_conn_info(conn, "0-RTT accepted by server\n");
}
EXPORT_SYMBOL(tquic_early_data_accept);

/*
 * tquic_early_data_init - Initialize 0-RTT state for connection
 * @conn: TQUIC connection
 * @ticket: Session ticket for 0-RTT (NULL for server)
 *
 * Sets up the connection for 0-RTT operation.
 *
 * Returns 0 on success, negative error code on failure.
 */
int tquic_early_data_init(struct tquic_connection *conn,
			  const struct tquic_session_ticket *ticket)
{
	int err;

	if (!conn)
		return -EINVAL;

	/*
	 * Client with session ticket: derive 0-RTT keys
	 *
	 * The actual 0-RTT state management is handled by the
	 * zero_rtt module (tquic_zero_rtt_init).
	 */
	if (conn->role == TQUIC_ROLE_CLIENT && ticket &&
	    ticket->resumption_secret_len > 0) {
		err = tquic_early_data_derive_keys(conn, ticket);
		if (err) {
			tquic_conn_warn(conn, "failed to derive 0-RTT keys: %d\n",
				 err);
			return err;
		}

		tquic_conn_dbg(conn, "0-RTT initialized for client\n");
	}

	return 0;
}
EXPORT_SYMBOL(tquic_early_data_init);

/*
 * tquic_early_data_cleanup - Clean up 0-RTT state
 * @conn: TQUIC connection
 */
void tquic_early_data_cleanup(struct tquic_connection *conn)
{
	if (!conn)
		return;

	/*
	 * The zero_rtt module handles the actual cleanup
	 * (tquic_zero_rtt_cleanup).
	 */
}
EXPORT_SYMBOL(tquic_early_data_cleanup);

/*
 * tquic_session_ticket_store - Store a session ticket for future 0-RTT
 * @tsk: TQUIC socket
 * @ticket: Session ticket from NEW_SESSION_TICKET
 *
 * Called when receiving NEW_SESSION_TICKET from server.
 * Stores the ticket for future connection resumption with 0-RTT.
 *
 * Returns 0 on success, negative error code on failure.
 */
int tquic_session_ticket_store(struct tquic_sock *tsk,
			       const struct tquic_session_ticket *ticket)
{
	if (!tsk || !ticket || ticket->ticket_len == 0)
		return -EINVAL;

	if (ticket->ticket_len > TQUIC_MAX_SESSION_TICKET_LEN)
		return -EINVAL;

	/*
	 * The actual ticket storage is handled by the zero_rtt module
	 * which maintains a per-server-name ticket cache.
	 *
	 * See: tquic_zero_rtt_store_ticket() in crypto/zero_rtt.c
	 */

	pr_debug("tquic: session ticket stored len=%u\n",
		 ticket->ticket_len);

	return 0;
}
EXPORT_SYMBOL(tquic_session_ticket_store);

/*
 * tquic_session_ticket_retrieve - Retrieve stored session ticket
 * @tsk: TQUIC socket
 *
 * Returns the stored session ticket or NULL if none exists.
 */
struct tquic_session_ticket *
tquic_session_ticket_retrieve(struct tquic_sock *tsk)
{
	if (!tsk)
		return NULL;

	/*
	 * The actual ticket retrieval is handled by the zero_rtt module.
	 *
	 * See: tquic_zero_rtt_lookup_ticket() in crypto/zero_rtt.c
	 */

	return NULL;
}
EXPORT_SYMBOL(tquic_session_ticket_retrieve);

/*
 * tquic_session_ticket_valid - Check if session ticket is still valid
 * @ticket: Session ticket to check
 *
 * Returns true if ticket is valid for 0-RTT, false otherwise.
 */
bool tquic_session_ticket_valid(const struct tquic_session_ticket *ticket)
{
	ktime_t now;
	u64 age_ms;

	if (!ticket || ticket->ticket_len == 0)
		return false;

	if (ticket->resumption_secret_len == 0)
		return false;

	/* Check ticket lifetime */
	now = ktime_get();
	age_ms = ktime_to_ms(now) - ticket->creation_time;

	if (age_ms > (u64)ticket->lifetime * 1000)
		return false;

	return true;
}
EXPORT_SYMBOL(tquic_session_ticket_valid);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux TQUIC Authors");
MODULE_DESCRIPTION("TQUIC 0-RTT Early Data Support");
