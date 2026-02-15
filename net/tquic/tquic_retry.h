/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: Retry Packet Mechanism
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Implements Retry packet generation and validation per RFC 9000 Section 8.1.
 * The Retry mechanism allows servers to validate client addresses before
 * allocating connection state, mitigating amplification attacks.
 *
 * Retry packet format (RFC 9000 Section 17.2.5):
 *   - Long Header with type = Retry (0x03)
 *   - No packet number
 *   - Contains Retry Token (server-generated)
 *   - 16-byte Retry Integrity Tag (AEAD protected)
 *
 * Integrity tag computation (RFC 9001 Section 5.8):
 *   - Uses AES-128-GCM with fixed key and nonce
 *   - AAD = Retry Pseudo-Packet (Original DCID + Retry packet without tag)
 */

#ifndef _NET_TQUIC_RETRY_H
#define _NET_TQUIC_RETRY_H

#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/skbuff.h>
#include <net/sock.h>
#include <net/tquic.h>

/*
 * Retry Integrity Tag constants (RFC 9001 Section 5.8)
 *
 * These are the fixed key and nonce used for computing the Retry
 * Integrity Tag. They are defined in the QUIC-TLS specification and
 * are the same for all QUIC v1 implementations.
 */
#define TQUIC_RETRY_INTEGRITY_TAG_LEN	16

/* QUIC v1 Retry key (RFC 9001 Section 5.8) */
extern const u8 tquic_retry_integrity_key_v1[16];

/* QUIC v1 Retry nonce (RFC 9001 Section 5.8) */
extern const u8 tquic_retry_integrity_nonce_v1[12];

/* QUIC v2 Retry key (draft-ietf-quic-v2) */
extern const u8 tquic_retry_integrity_key_v2[16];

/* QUIC v2 Retry nonce (draft-ietf-quic-v2) */
extern const u8 tquic_retry_integrity_nonce_v2[12];

/*
 * Retry Token constants
 */
#define TQUIC_RETRY_TOKEN_MAX_LEN	256
#define TQUIC_RETRY_TOKEN_MIN_LEN	32
#define TQUIC_RETRY_TOKEN_VERSION	0x01

/* Token lifetime in seconds (configurable via sysctl) */
#define TQUIC_RETRY_TOKEN_LIFETIME_DEFAULT	120

/*
 * Retry Token structure (encrypted format)
 *
 * The token encodes:
 *   - Version (1 byte)
 *   - Original Destination CID (variable, 1 + ODCID_len bytes)
 *   - Client IP address (variable, 4 or 16 bytes)
 *   - Client port (2 bytes)
 *   - Timestamp (8 bytes)
 *   - Random padding (variable)
 *   - AEAD tag (16 bytes)
 *
 * The token is encrypted using AES-128-GCM with a server-side secret.
 */
struct tquic_retry_token_plaintext {
	u8 version;
	u8 odcid_len;
	u8 odcid[TQUIC_MAX_CID_LEN];
	sa_family_t addr_family;
	union {
		__be32 v4;
		struct in6_addr v6;
	} client_addr;
	__be16 client_port;
	u64 timestamp;		/* ktime_get_real_seconds() */
	u8 random[8];		/* Random padding for uniqueness */
};

/* Number of AEAD cipher instances in the token crypto pool */
#define TQUIC_RETRY_AEAD_POOL_SIZE	8

/**
 * struct tquic_retry_state - Server-side Retry state
 * @enabled: Whether Retry is required for new connections
 * @token_key: Secret key for token encryption (32 bytes)
 * @token_key_id: Key identifier for key rotation
 * @token_lifetime: Token validity period in seconds
 * @aead_pool: Pool of AEAD ciphers for parallel token operations
 * @pool_locks: Per-slot mutexes for the AEAD pool
 * @pool_size: Number of AEAD instances in the pool
 * @lock: Protects key material
 */
struct tquic_retry_state {
	bool enabled;
	u8 token_key[32];
	u32 token_key_id;
	u32 token_lifetime;
	struct crypto_aead *aead_pool[TQUIC_RETRY_AEAD_POOL_SIZE];
	struct mutex pool_locks[TQUIC_RETRY_AEAD_POOL_SIZE];
	u32 pool_size;
	spinlock_t lock;		/* Protects key material */
};

/*
 * =============================================================================
 * Retry Packet Generation (Server-side)
 * =============================================================================
 */

/**
 * tquic_retry_send - Send a Retry packet to client
 * @sk: Server socket
 * @src_addr: Client source address
 * @version: QUIC version from client Initial
 * @dcid: Destination CID from client Initial (will become ODCID)
 * @dcid_len: Length of DCID
 * @scid: Source CID from client Initial
 * @scid_len: Length of SCID
 *
 * Generates and sends a Retry packet to the client. The Retry packet
 * includes a token that encodes the original DCID, client address,
 * and timestamp. The client must include this token in subsequent
 * Initial packets.
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_retry_send(struct sock *sk,
		     const struct sockaddr_storage *src_addr,
		     u32 version,
		     const u8 *dcid, u8 dcid_len,
		     const u8 *scid, u8 scid_len);

/**
 * tquic_retry_build_packet - Build a Retry packet
 * @buf: Output buffer
 * @buf_len: Buffer size
 * @version: QUIC version
 * @dcid: Destination CID (for Retry = client's SCID)
 * @dcid_len: DCID length
 * @scid: Source CID (new server-generated CID)
 * @scid_len: SCID length
 * @odcid: Original DCID (from client's Initial)
 * @odcid_len: ODCID length
 * @token: Retry Token
 * @token_len: Token length
 *
 * Builds a complete Retry packet including the Retry Integrity Tag.
 *
 * Returns: Packet length on success, negative errno on failure
 */
int tquic_retry_build_packet(u8 *buf, size_t buf_len,
			     u32 version,
			     const u8 *dcid, u8 dcid_len,
			     const u8 *scid, u8 scid_len,
			     const u8 *odcid, u8 odcid_len,
			     const u8 *token, size_t token_len);

/*
 * =============================================================================
 * Retry Token Management
 * =============================================================================
 */

/**
 * tquic_retry_token_create - Create a Retry Token
 * @state: Retry state with encryption key
 * @odcid: Original Destination CID
 * @odcid_len: ODCID length
 * @client_addr: Client address
 * @token: Output buffer for token
 * @token_len: In: buffer size, Out: token length
 *
 * Creates an encrypted token encoding the ODCID, client address, and
 * timestamp. The token is encrypted with AES-128-GCM.
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_retry_token_create(struct tquic_retry_state *state,
			     const u8 *odcid, u8 odcid_len,
			     const struct sockaddr_storage *client_addr,
			     u8 *token, size_t *token_len);

/**
 * tquic_retry_token_validate - Validate a Retry Token from Initial packet
 * @state: Retry state with decryption key
 * @token: Token from client's Initial packet
 * @token_len: Token length
 * @client_addr: Client address (must match encoded address)
 * @odcid: Output: Original DCID encoded in token
 * @odcid_len: Output: ODCID length
 *
 * Decrypts and validates the token. Checks:
 *   - Decryption succeeds (authentication)
 *   - Client address matches encoded address
 *   - Timestamp is within validity period
 *
 * Returns: 0 on success, negative errno on failure
 *   -EINVAL: Invalid token format
 *   -EACCES: Client address mismatch
 *   -ETIMEDOUT: Token expired
 */
int tquic_retry_token_validate(struct tquic_retry_state *state,
			       const u8 *token, size_t token_len,
			       const struct sockaddr_storage *client_addr,
			       u8 *odcid, u8 *odcid_len);

/*
 * =============================================================================
 * Retry Integrity Tag
 * =============================================================================
 */

/**
 * tquic_retry_compute_integrity_tag - Compute Retry Integrity Tag
 * @version: QUIC version (determines key/nonce)
 * @odcid: Original Destination CID
 * @odcid_len: ODCID length
 * @retry_packet: Retry packet without tag
 * @retry_len: Retry packet length
 * @tag: Output buffer for 16-byte tag
 *
 * Computes the Retry Integrity Tag per RFC 9001 Section 5.8.
 * The pseudo-packet used as AAD is: ODCID_len + ODCID + Retry packet.
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_retry_compute_integrity_tag(u32 version,
				      const u8 *odcid, u8 odcid_len,
				      const u8 *retry_packet, size_t retry_len,
				      u8 *tag);

/**
 * tquic_retry_verify_integrity_tag - Verify Retry Integrity Tag
 * @version: QUIC version
 * @odcid: Original Destination CID
 * @odcid_len: ODCID length
 * @retry_packet: Complete Retry packet including tag
 * @retry_len: Total packet length including tag
 *
 * Verifies the Retry Integrity Tag. Used by client to validate
 * Retry packets before processing.
 *
 * Returns: true if tag is valid, false otherwise
 */
bool tquic_retry_verify_integrity_tag(u32 version,
				      const u8 *odcid, u8 odcid_len,
				      const u8 *retry_packet, size_t retry_len);

/*
 * =============================================================================
 * Client-side Retry Processing
 * =============================================================================
 */

/**
 * tquic_retry_process - Process a received Retry packet (client-side)
 * @conn: Connection that received the Retry
 * @packet: Retry packet data
 * @packet_len: Packet length
 *
 * Called by the client when a Retry packet is received. Validates
 * the integrity tag, extracts the token, and prepares the connection
 * to retry with the new parameters.
 *
 * Returns: 0 on success (should retry with token), negative errno on failure
 */
int tquic_retry_process(struct tquic_connection *conn,
			const u8 *packet, size_t packet_len);

/**
 * tquic_retry_parse - Parse a Retry packet
 * @packet: Packet data
 * @packet_len: Packet length
 * @version: Output: QUIC version
 * @dcid: Output: Destination CID
 * @dcid_len: Output: DCID length
 * @scid: Output: Source CID (new server CID)
 * @scid_len: Output: SCID length
 * @token: Output: Pointer to token start
 * @token_len: Output: Token length
 * @tag: Output: Pointer to integrity tag
 *
 * Parses a Retry packet and extracts all fields.
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_retry_parse(const u8 *packet, size_t packet_len,
		      u32 *version,
		      u8 *dcid, u8 *dcid_len,
		      u8 *scid, u8 *scid_len,
		      const u8 **token, size_t *token_len,
		      const u8 **tag);

/*
 * =============================================================================
 * Server Retry State Management
 * =============================================================================
 */

/**
 * tquic_retry_state_alloc - Allocate Retry state
 *
 * Allocates and initializes server-side Retry state including
 * generating a random token encryption key.
 *
 * Returns: Allocated state or NULL on failure
 */
struct tquic_retry_state *tquic_retry_state_alloc(void);

/**
 * tquic_retry_state_free - Free Retry state
 * @state: State to free
 */
void tquic_retry_state_free(struct tquic_retry_state *state);

/**
 * tquic_retry_rotate_key - Rotate token encryption key
 * @state: Retry state
 *
 * Generates a new token encryption key. Old tokens remain valid
 * until they expire naturally.
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_retry_rotate_key(struct tquic_retry_state *state);

/*
 * =============================================================================
 * Sysctl Interface
 * =============================================================================
 */

/**
 * tquic_retry_is_required - Check if Retry is required for new connections
 * @net: Network namespace
 *
 * Returns: true if Retry is required, false otherwise
 */
bool tquic_retry_is_required(struct net *net);

/**
 * tquic_retry_get_token_lifetime - Get token validity period
 * @net: Network namespace
 *
 * Returns: Token lifetime in seconds
 */
u32 tquic_retry_get_token_lifetime(struct net *net);

/*
 * =============================================================================
 * Module Init/Exit
 * =============================================================================
 */

int __init tquic_retry_init(void);
void tquic_retry_exit(void);

#endif /* _NET_TQUIC_RETRY_H */
