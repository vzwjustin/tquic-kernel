/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: 0-RTT Early Data Support (RFC 9001 Sections 4.6-4.7)
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * This header provides the API for TLS 1.3 0-RTT early data in QUIC:
 * - Session ticket storage and retrieval
 * - 0-RTT key derivation from resumption_master_secret
 * - Early data transmission before handshake completion
 * - Server accept/reject via early_data_indication
 * - Anti-replay protection using bloom filter with TTL
 *
 * Security considerations (RFC 9001 Section 9.2):
 * - 0-RTT data is not forward-secret until handshake completes
 * - 0-RTT data may be replayed; applications must handle this
 * - Server anti-replay is implemented via bloom filter
 */

#ifndef _TQUIC_ZERO_RTT_H
#define _TQUIC_ZERO_RTT_H

#include <linux/types.h>
#include <linux/ktime.h>
#include <linux/spinlock.h>
#include <linux/rbtree.h>
#include <linux/list.h>
#include <net/tquic.h>

/* Forward declarations */
struct tquic_connection;
struct tquic_path;
struct crypto_shash;
struct crypto_aead;

/*
 * =============================================================================
 * Constants
 * =============================================================================
 */

/* Session ticket constants */
#define TQUIC_SESSION_TICKET_VERSION		1
#define TQUIC_SESSION_TICKET_MAX_LEN		2048
#define TQUIC_SESSION_TICKET_TAG_LEN		16
#define TQUIC_SESSION_TICKET_NONCE_LEN		12
#define TQUIC_SESSION_TICKET_KEY_LEN		32

/* 0-RTT key constants */
#define TQUIC_ZERO_RTT_SECRET_MAX_LEN		48
#define TQUIC_ZERO_RTT_KEY_MAX_LEN		32
#define TQUIC_ZERO_RTT_IV_MAX_LEN		12

/* Default configuration */
#define TQUIC_ZERO_RTT_DEFAULT_MAX_AGE		604800	/* 7 days in seconds */
#define TQUIC_ZERO_RTT_DEFAULT_ENABLED		1

/* Anti-replay bloom filter parameters */
#define TQUIC_REPLAY_BLOOM_BITS			(1 << 16)	/* 64K bits */
#define TQUIC_REPLAY_BLOOM_HASHES		4		/* 4 hash functions */
#define TQUIC_REPLAY_TTL_SECONDS		3600		/* 1 hour */

/* ALPN maximum length */
#define TQUIC_ALPN_MAX_LEN			255

/*
 * =============================================================================
 * 0-RTT State
 * =============================================================================
 */

/**
 * enum tquic_zero_rtt_state - 0-RTT connection state
 * @TQUIC_0RTT_NONE: No 0-RTT attempt
 * @TQUIC_0RTT_ATTEMPTING: Client is attempting 0-RTT
 * @TQUIC_0RTT_ACCEPTED: Server accepted 0-RTT
 * @TQUIC_0RTT_REJECTED: Server rejected 0-RTT
 *
 * State transitions:
 *   Client: NONE -> ATTEMPTING -> ACCEPTED/REJECTED
 *   Server: NONE -> ACCEPTED/REJECTED (after evaluating early_data_indication)
 */
enum tquic_zero_rtt_state {
	TQUIC_0RTT_NONE = 0,
	TQUIC_0RTT_ATTEMPTING,
	TQUIC_0RTT_ACCEPTED,
	TQUIC_0RTT_REJECTED,
};

/*
 * =============================================================================
 * Session Ticket Format
 * =============================================================================
 *
 * Format: Version(1) || Encrypted(PSK || MaxAge || ALPN || TP) || Tag(16)
 *
 * Encrypted payload contains:
 *   - PSK (Pre-Shared Key): 32 or 48 bytes depending on cipher
 *   - MaxAge: 4 bytes (ticket lifetime in seconds)
 *   - ALPN: Length-prefixed string
 *   - Transport Parameters: QUIC transport parameters blob
 *
 * The ticket is encrypted using AES-256-GCM with a server-side ticket key.
 */

/**
 * struct tquic_session_ticket_plaintext - Decrypted session ticket content
 * @psk: Pre-shared key (resumption_master_secret)
 * @psk_len: Length of PSK (32 or 48)
 * @max_age: Ticket lifetime in seconds
 * @creation_time: Ticket creation timestamp
 * @cipher_suite: Negotiated TLS 1.3 cipher suite
 * @alpn: Application-Layer Protocol Negotiation string
 * @alpn_len: Length of ALPN
 * @transport_params: Serialized QUIC transport parameters
 * @transport_params_len: Length of transport parameters
 */
struct tquic_session_ticket_plaintext {
	u8 psk[TQUIC_ZERO_RTT_SECRET_MAX_LEN];
	u32 psk_len;
	u32 max_age;
	u64 creation_time;
	u16 cipher_suite;
	char alpn[TQUIC_ALPN_MAX_LEN + 1];
	u8 alpn_len;
	u8 transport_params[512];
	u32 transport_params_len;
};

/**
 * struct tquic_session_ticket - Stored session ticket
 * @node: RB-tree node for lookup by server name
 * @list: List node for LRU eviction
 * @server_name: Server hostname (SNI)
 * @server_name_len: Length of server name
 * @ticket: Encrypted ticket data
 * @ticket_len: Length of encrypted ticket
 * @plaintext: Decrypted ticket content
 * @refcount: Reference counter
 */
struct tquic_session_ticket {
	struct rb_node node;
	struct list_head list;
	char server_name[256];
	u8 server_name_len;
	u8 *ticket;
	u32 ticket_len;
	struct tquic_session_ticket_plaintext plaintext;
	refcount_t refcount;
};

/**
 * struct tquic_ticket_store - Session ticket storage
 * @lock: Protects ticket tree and list
 * @tickets: RB-tree indexed by server name
 * @lru_list: LRU list for eviction
 * @count: Number of stored tickets
 * @max_count: Maximum tickets to store
 */
struct tquic_ticket_store {
	spinlock_t lock;
	struct rb_root tickets;
	struct list_head lru_list;
	u32 count;
	u32 max_count;
};

/*
 * =============================================================================
 * 0-RTT Keys
 * =============================================================================
 */

/**
 * struct tquic_zero_rtt_keys - 0-RTT encryption keys
 * @secret: early_traffic_secret from HKDF
 * @key: AEAD key derived from secret
 * @iv: AEAD IV derived from secret
 * @hp_key: Header protection key
 * @secret_len: Length of secret
 * @key_len: Length of AEAD key
 * @iv_len: Length of IV
 * @valid: Keys are valid and usable
 */
struct tquic_zero_rtt_keys {
	u8 secret[TQUIC_ZERO_RTT_SECRET_MAX_LEN];
	u8 key[TQUIC_ZERO_RTT_KEY_MAX_LEN];
	u8 iv[TQUIC_ZERO_RTT_IV_MAX_LEN];
	u8 hp_key[TQUIC_ZERO_RTT_KEY_MAX_LEN];
	u32 secret_len;
	u32 key_len;
	u32 iv_len;
	bool valid;
};

/**
 * struct tquic_zero_rtt_state_s - Per-connection 0-RTT state
 * @state: Current 0-RTT state (ATTEMPTING, ACCEPTED, REJECTED)
 * @keys: 0-RTT encryption keys
 * @ticket: Session ticket being used (client) or issued (server)
 * @early_data_max: Maximum early data size negotiated
 * @early_data_sent: Bytes of early data sent
 * @early_data_received: Bytes of early data received
 * @cipher_suite: Cipher suite for 0-RTT (must match resumption)
 * @largest_sent_pn: Largest packet number sent (for nonce reuse prevention)
 * @largest_recv_pn: Largest packet number received (for replay protection)
 * @pn_initialized: True once first packet sent/received (for initial state)
 */
struct tquic_zero_rtt_state_s {
	enum tquic_zero_rtt_state state;
	struct tquic_zero_rtt_keys keys;
	struct tquic_session_ticket *ticket;
	u64 early_data_max;
	u64 early_data_sent;
	u64 early_data_received;
	u16 cipher_suite;
	/* Packet number tracking for nonce reuse and replay protection */
	u64 largest_sent_pn;
	u64 largest_recv_pn;
	bool pn_initialized;
};

/*
 * =============================================================================
 * Anti-Replay Protection
 * =============================================================================
 *
 * Per RFC 9001 Section 9.2, servers MUST implement anti-replay.
 * We use a time-bucketed bloom filter approach:
 * - Hash(ticket) is inserted into bloom filter on first use
 * - TTL-based bucket rotation clears old entries
 * - Lookup before use rejects replays within TTL window
 */

/**
 * struct tquic_replay_filter - Anti-replay bloom filter
 * @lock: Protects filter state
 * @bits: Bloom filter bit array
 * @current_bucket: Current time bucket index
 * @last_rotation: Time of last bucket rotation
 * @ttl_seconds: TTL for entries
 */
struct tquic_replay_filter {
	spinlock_t lock;
	unsigned long bits[TQUIC_REPLAY_BLOOM_BITS / BITS_PER_LONG];
	u32 current_bucket;
	ktime_t last_rotation;
	u32 ttl_seconds;
};

/*
 * =============================================================================
 * Configuration
 * =============================================================================
 */

/**
 * struct tquic_zero_rtt_config - 0-RTT global configuration
 * @enabled: 0-RTT feature enabled
 * @max_age_seconds: Maximum session ticket age
 * @early_data_max: Maximum early data size
 * @anti_replay_enabled: Anti-replay protection enabled
 * @store: Session ticket store
 * @replay_filter: Anti-replay filter (server-side)
 */
struct tquic_zero_rtt_config {
	bool enabled;
	u32 max_age_seconds;
	u64 early_data_max;
	bool anti_replay_enabled;
	struct tquic_ticket_store store;
	struct tquic_replay_filter replay_filter;
};

/*
 * =============================================================================
 * Session Ticket API
 * =============================================================================
 */

/**
 * tquic_zero_rtt_store_ticket - Store session ticket after successful handshake
 * @server_name: Server hostname (SNI)
 * @server_name_len: Length of server name
 * @ticket: Encrypted ticket from NEW_SESSION_TICKET
 * @ticket_len: Length of ticket
 * @plaintext: Decrypted ticket content
 *
 * Called by client after receiving NEW_SESSION_TICKET message.
 * Stores ticket for future 0-RTT attempts.
 *
 * Returns: 0 on success, negative error on failure
 */
int tquic_zero_rtt_store_ticket(const char *server_name, u8 server_name_len,
				const u8 *ticket, u32 ticket_len,
				const struct tquic_session_ticket_plaintext *plaintext);

/**
 * tquic_zero_rtt_lookup_ticket - Look up session ticket for server
 * @server_name: Server hostname (SNI)
 * @server_name_len: Length of server name
 *
 * Returns: Session ticket or NULL if not found/expired
 *          Caller must call tquic_zero_rtt_put_ticket() when done
 */
struct tquic_session_ticket *tquic_zero_rtt_lookup_ticket(
	const char *server_name, u8 server_name_len);

/**
 * tquic_zero_rtt_put_ticket - Release reference to session ticket
 * @ticket: Ticket to release
 */
void tquic_zero_rtt_put_ticket(struct tquic_session_ticket *ticket);

/**
 * tquic_zero_rtt_remove_ticket - Remove ticket for server
 * @server_name: Server hostname
 * @server_name_len: Length of server name
 *
 * Called when 0-RTT is rejected to remove stale ticket.
 */
void tquic_zero_rtt_remove_ticket(const char *server_name, u8 server_name_len);

/*
 * =============================================================================
 * 0-RTT Key Derivation
 * =============================================================================
 */

/**
 * tquic_zero_rtt_derive_keys - Derive 0-RTT keys from PSK
 * @keys: Output key structure
 * @psk: Pre-shared key (resumption_master_secret)
 * @psk_len: Length of PSK
 * @cipher_suite: TLS 1.3 cipher suite
 *
 * Derives 0-RTT keys using:
 *   early_secret = HKDF-Extract(0, PSK)
 *   client_early_traffic_secret = Derive-Secret(early_secret, "c e traffic", ClientHello)
 *   0-RTT keys = HKDF-Expand-Label(client_early_traffic_secret, "quic 0-rtt", "", key_len)
 *
 * Returns: 0 on success, negative error on failure
 */
int tquic_zero_rtt_derive_keys(struct tquic_zero_rtt_keys *keys,
			       const u8 *psk, u32 psk_len,
			       u16 cipher_suite);

/**
 * tquic_zero_rtt_derive_secret - Derive client_early_traffic_secret
 * @out: Output buffer for secret
 * @out_len: Expected output length
 * @psk: Pre-shared key
 * @psk_len: Length of PSK
 * @client_hello_hash: Hash of ClientHello (for transcript)
 * @hash_len: Length of hash
 * @cipher_suite: TLS 1.3 cipher suite
 *
 * Returns: 0 on success, negative error on failure
 */
int tquic_zero_rtt_derive_secret(u8 *out, u32 out_len,
				 const u8 *psk, u32 psk_len,
				 const u8 *client_hello_hash, u32 hash_len,
				 u16 cipher_suite);

/*
 * =============================================================================
 * 0-RTT Connection Operations
 * =============================================================================
 */

/**
 * tquic_zero_rtt_init - Initialize 0-RTT state for connection
 * @conn: TQUIC connection
 *
 * Called during connection creation to initialize 0-RTT state.
 *
 * Returns: 0 on success, negative error on failure
 */
int tquic_zero_rtt_init(struct tquic_connection *conn);

/**
 * tquic_zero_rtt_cleanup - Clean up 0-RTT state
 * @conn: TQUIC connection
 *
 * Called during connection destruction.
 */
void tquic_zero_rtt_cleanup(struct tquic_connection *conn);

/**
 * tquic_zero_rtt_attempt - Attempt 0-RTT on cached ticket
 * @conn: TQUIC connection
 * @server_name: Server hostname (SNI)
 * @server_name_len: Length of server name
 *
 * Called by client during connection setup to attempt 0-RTT.
 * If a valid ticket exists, derives 0-RTT keys and sets state to ATTEMPTING.
 *
 * Returns: 0 on success (0-RTT possible), -ENOENT if no ticket,
 *          negative error on failure
 */
int tquic_zero_rtt_attempt(struct tquic_connection *conn,
			   const char *server_name, u8 server_name_len);

/**
 * tquic_zero_rtt_accept - Server accepts 0-RTT early data
 * @conn: TQUIC connection
 *
 * Called by server to accept 0-RTT. Validates ticket, checks anti-replay,
 * derives keys, and sets state to ACCEPTED.
 *
 * Returns: 0 on success, negative error on rejection
 */
int tquic_zero_rtt_accept(struct tquic_connection *conn);

/**
 * tquic_zero_rtt_reject - Server rejects 0-RTT early data
 * @conn: TQUIC connection
 *
 * Called by server to reject 0-RTT. Sets state to REJECTED.
 * Client will retransmit early data as 1-RTT.
 */
void tquic_zero_rtt_reject(struct tquic_connection *conn);

/**
 * tquic_zero_rtt_confirmed - 0-RTT acceptance confirmed
 * @conn: TQUIC connection
 *
 * Called when client receives confirmation that 0-RTT was accepted
 * (via early_data_indication in EncryptedExtensions).
 */
void tquic_zero_rtt_confirmed(struct tquic_connection *conn);

/*
 * =============================================================================
 * 0-RTT Packet Operations
 * =============================================================================
 */

/**
 * tquic_zero_rtt_can_send - Check if 0-RTT data can be sent
 * @conn: TQUIC connection
 *
 * Returns: true if 0-RTT is ATTEMPTING or ACCEPTED and quota available
 */
bool tquic_zero_rtt_can_send(struct tquic_connection *conn);

/**
 * tquic_zero_rtt_encrypt - Encrypt data for 0-RTT packet
 * @conn: TQUIC connection
 * @header: Packet header (for AAD)
 * @header_len: Header length
 * @payload: Plaintext payload
 * @payload_len: Payload length
 * @pkt_num: Packet number
 * @out: Output buffer
 * @out_len: Output length
 *
 * Returns: 0 on success, negative error on failure
 */
int tquic_zero_rtt_encrypt(struct tquic_connection *conn,
			   const u8 *header, size_t header_len,
			   const u8 *payload, size_t payload_len,
			   u64 pkt_num, u8 *out, size_t *out_len);

/**
 * tquic_zero_rtt_decrypt - Decrypt 0-RTT packet
 * @conn: TQUIC connection
 * @header: Packet header (for AAD)
 * @header_len: Header length
 * @payload: Ciphertext payload
 * @payload_len: Payload length (including auth tag)
 * @pkt_num: Packet number
 * @out: Output buffer
 * @out_len: Output length
 *
 * Returns: 0 on success, negative error on failure
 */
int tquic_zero_rtt_decrypt(struct tquic_connection *conn,
			   const u8 *header, size_t header_len,
			   u8 *payload, size_t payload_len,
			   u64 pkt_num, u8 *out, size_t *out_len);

/*
 * =============================================================================
 * Anti-Replay Protection
 * =============================================================================
 */

/**
 * tquic_replay_filter_init - Initialize anti-replay filter
 * @filter: Filter to initialize
 * @ttl_seconds: TTL for entries
 *
 * Returns: 0 on success
 */
int tquic_replay_filter_init(struct tquic_replay_filter *filter,
			     u32 ttl_seconds);

/**
 * tquic_replay_filter_cleanup - Clean up anti-replay filter
 * @filter: Filter to clean up
 */
void tquic_replay_filter_cleanup(struct tquic_replay_filter *filter);

/**
 * tquic_replay_filter_check - Check and insert ticket for replay
 * @filter: Anti-replay filter
 * @ticket: Ticket data
 * @ticket_len: Ticket length
 *
 * Returns: 0 if ticket is new (not a replay), -EEXIST if replay detected
 */
int tquic_replay_filter_check(struct tquic_replay_filter *filter,
			      const u8 *ticket, u32 ticket_len);

/*
 * =============================================================================
 * Session Ticket Encoding/Decoding
 * =============================================================================
 */

/**
 * tquic_session_ticket_encode - Encode and encrypt session ticket
 * @plaintext: Ticket content to encode
 * @ticket_key: Server-side encryption key
 * @key_len: Key length
 * @out: Output buffer
 * @out_len: Input: buffer size, Output: encoded length
 *
 * Returns: 0 on success, negative error on failure
 */
int tquic_session_ticket_encode(const struct tquic_session_ticket_plaintext *plaintext,
				const u8 *ticket_key, u32 key_len,
				u8 *out, u32 *out_len);

/**
 * tquic_session_ticket_decode - Decrypt and decode session ticket
 * @ticket: Encrypted ticket data
 * @ticket_len: Ticket length
 * @ticket_key: Server-side encryption key
 * @key_len: Key length
 * @out: Output plaintext structure
 *
 * Returns: 0 on success, negative error on failure
 */
int tquic_session_ticket_decode(const u8 *ticket, u32 ticket_len,
				const u8 *ticket_key, u32 key_len,
				struct tquic_session_ticket_plaintext *out);

/*
 * =============================================================================
 * State Query
 * =============================================================================
 */

/**
 * tquic_zero_rtt_get_state - Get current 0-RTT state
 * @conn: TQUIC connection
 *
 * Returns: Current 0-RTT state
 */
enum tquic_zero_rtt_state tquic_zero_rtt_get_state(struct tquic_connection *conn);

/**
 * tquic_zero_rtt_state_name - Get string name for 0-RTT state
 * @state: 0-RTT state
 *
 * Returns: Human-readable state name
 */
const char *tquic_zero_rtt_state_name(enum tquic_zero_rtt_state state);

/*
 * =============================================================================
 * Module Initialization
 * =============================================================================
 */

/**
 * tquic_zero_rtt_module_init - Initialize 0-RTT subsystem
 *
 * Called during module load.
 *
 * Returns: 0 on success, negative error on failure
 */
int __init tquic_zero_rtt_module_init(void);

/**
 * tquic_zero_rtt_module_exit - Clean up 0-RTT subsystem
 *
 * Called during module unload.
 */
void __exit tquic_zero_rtt_module_exit(void);

/*
 * =============================================================================
 * Sysctl Accessors
 * =============================================================================
 */

/**
 * tquic_sysctl_get_zero_rtt_enabled - Get 0-RTT enabled status
 *
 * Returns: non-zero if 0-RTT is enabled, 0 if disabled
 */
int tquic_sysctl_get_zero_rtt_enabled(void);

/**
 * tquic_sysctl_get_zero_rtt_max_age - Get maximum ticket age
 *
 * Returns: Maximum ticket age in seconds
 */
int tquic_sysctl_get_zero_rtt_max_age(void);

#endif /* _TQUIC_ZERO_RTT_H */
