/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: Address Validation Token Support (RFC 9000 Section 8.1.3-8.1.4)
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * This header provides address validation token generation, encryption,
 * and validation for TQUIC connections. Tokens allow servers to skip
 * address validation on future connections from validated clients.
 *
 * Token format: Version(1) || Encrypted(IP || Timestamp || Random) || Tag(16)
 *
 * Reference: RFC 9000 Section 8.1.3 (Address Validation Using Retry Packets)
 *            RFC 9000 Section 8.1.4 (Address Validation for Future Connections)
 */

#ifndef _NET_TQUIC_TOKEN_H
#define _NET_TQUIC_TOKEN_H

#include <linux/types.h>
#include <linux/time64.h>
#include <net/tquic.h>

/* Token constants */
#define TQUIC_TOKEN_VERSION		0x01
#define TQUIC_TOKEN_KEY_LEN		32	/* AES-256-GCM key */
#define TQUIC_TOKEN_IV_LEN		12	/* GCM nonce */
#define TQUIC_TOKEN_TAG_LEN		16	/* GCM auth tag */
#define TQUIC_TOKEN_RANDOM_LEN		8	/* Server-chosen random data */
#define TQUIC_TOKEN_MAX_LEN		128	/* Maximum token length */
#define TQUIC_TOKEN_ADDR_MAX_LEN	16	/* IPv6 address length */

/* Default token lifetime: 24 hours (86400 seconds) */
#define TQUIC_TOKEN_DEFAULT_LIFETIME	86400

/* Token types */
enum tquic_token_type {
	TQUIC_TOKEN_TYPE_RETRY = 0,	/* Retry token (short-lived) */
	TQUIC_TOKEN_TYPE_NEW_TOKEN,	/* NEW_TOKEN token (long-lived) */
};

/**
 * struct tquic_token_key - Server token encryption key
 * @key: AES-256-GCM encryption key
 * @generation: Key generation number (for rotation)
 * @valid: Key is valid for use
 *
 * The server maintains one or more token keys for encrypting
 * address validation tokens. Key rotation is supported by
 * keeping the previous generation during transition.
 */
struct tquic_token_key {
	u8 key[TQUIC_TOKEN_KEY_LEN];
	u32 generation;
	bool valid;
};

/**
 * struct tquic_token_state - Per-connection token state
 * @stored_token: Token received from server (client) or issued (server)
 * @stored_token_len: Length of stored token
 * @token_addr: Address associated with stored token
 * @token_issued_time: When token was issued
 * @token_valid: Token is available for use
 * @lock: Spinlock protecting token state
 *
 * Client-side: Stores tokens received via NEW_TOKEN frames for use
 * in future connection attempts to the same server.
 *
 * Server-side: Tracks tokens issued to this client for validation.
 */
struct tquic_token_state {
	u8 stored_token[TQUIC_TOKEN_MAX_LEN];
	u16 stored_token_len;
	struct sockaddr_storage token_addr;
	ktime_t token_issued_time;
	bool token_valid;
	spinlock_t lock;
};

/**
 * struct tquic_token_plaintext - Token plaintext structure
 * @type: Token type (retry or new_token)
 * @addr_family: Address family (AF_INET or AF_INET6)
 * @addr: Client IP address (4 or 16 bytes)
 * @addr_len: Length of address
 * @timestamp: Token creation timestamp (seconds since epoch)
 * @random: Server-chosen random data
 * @original_dcid: Original DCID (for retry tokens only)
 * @odcid_len: Length of original DCID
 *
 * This structure is encrypted to form the token.
 */
struct tquic_token_plaintext {
	u8 type;
	u8 addr_family;
	u8 addr[TQUIC_TOKEN_ADDR_MAX_LEN];
	u8 addr_len;
	u64 timestamp;
	u8 random[TQUIC_TOKEN_RANDOM_LEN];
	u8 original_dcid[TQUIC_MAX_CID_LEN];
	u8 odcid_len;
};

/*
 * =============================================================================
 * Token Key Management
 * =============================================================================
 */

/**
 * tquic_token_init_key - Initialize server token encryption key
 * @key: Key structure to initialize
 *
 * Generates a random AES-256-GCM key for token encryption.
 * Should be called during server initialization.
 *
 * Return: 0 on success, -errno on failure
 */
int tquic_token_init_key(struct tquic_token_key *key);

/**
 * tquic_token_set_key - Set token encryption key from external source
 * @key: Key structure to set
 * @key_data: 32-byte key material
 *
 * Allows setting the token key from configuration or key management.
 *
 * Return: 0 on success, -EINVAL if key_data is invalid
 */
int tquic_token_set_key(struct tquic_token_key *key, const u8 *key_data);

/**
 * tquic_token_rotate_key - Rotate token encryption key
 * @old_key: Previous key (kept for validation of existing tokens)
 * @new_key: New key to generate
 *
 * Generates a new key while preserving the old key for validating
 * tokens issued before the rotation.
 *
 * Return: 0 on success, -errno on failure
 */
int tquic_token_rotate_key(struct tquic_token_key *old_key,
			   struct tquic_token_key *new_key);

/*
 * =============================================================================
 * Token Generation (Server-side)
 * =============================================================================
 */

/**
 * tquic_token_generate - Generate an address validation token
 * @key: Server's token encryption key
 * @client_addr: Client's IP address
 * @type: Token type (TQUIC_TOKEN_TYPE_NEW_TOKEN or TQUIC_TOKEN_TYPE_RETRY)
 * @original_dcid: Original DCID (for retry tokens, NULL otherwise)
 * @token: Output buffer for encrypted token
 * @token_len: Output token length
 *
 * Generates an encrypted token encoding the client address and timestamp.
 * For NEW_TOKEN frames, the token can be used for future connections.
 * For Retry packets, includes the original DCID.
 *
 * Return: 0 on success, -errno on failure
 */
int tquic_token_generate(const struct tquic_token_key *key,
			 const struct sockaddr_storage *client_addr,
			 enum tquic_token_type type,
			 const struct tquic_cid *original_dcid,
			 u8 *token, u32 *token_len);

/**
 * tquic_token_generate_retry - Generate a retry token
 * @key: Server's token encryption key
 * @client_addr: Client's IP address
 * @original_dcid: Original DCID from Initial packet
 * @token: Output buffer for encrypted token
 * @token_len: Output token length
 *
 * Convenience wrapper for generating retry tokens.
 *
 * Return: 0 on success, -errno on failure
 */
static inline int tquic_token_generate_retry(const struct tquic_token_key *key,
					     const struct sockaddr_storage *client_addr,
					     const struct tquic_cid *original_dcid,
					     u8 *token, u32 *token_len)
{
	return tquic_token_generate(key, client_addr, TQUIC_TOKEN_TYPE_RETRY,
				    original_dcid, token, token_len);
}

/**
 * tquic_token_generate_new_token - Generate a NEW_TOKEN token
 * @key: Server's token encryption key
 * @client_addr: Client's IP address
 * @token: Output buffer for encrypted token
 * @token_len: Output token length
 *
 * Convenience wrapper for generating NEW_TOKEN tokens.
 *
 * Return: 0 on success, -errno on failure
 */
static inline int tquic_token_generate_new_token(const struct tquic_token_key *key,
						 const struct sockaddr_storage *client_addr,
						 u8 *token, u32 *token_len)
{
	return tquic_token_generate(key, client_addr, TQUIC_TOKEN_TYPE_NEW_TOKEN,
				    NULL, token, token_len);
}

/*
 * =============================================================================
 * Token Validation (Server-side)
 * =============================================================================
 */

/**
 * tquic_token_validate - Validate an address validation token
 * @key: Server's token encryption key
 * @client_addr: Client's current IP address
 * @token: Token received from client
 * @token_len: Token length
 * @lifetime_secs: Maximum token age in seconds (0 for default)
 * @original_dcid: Output original DCID (for retry tokens, may be NULL)
 *
 * Decrypts and validates the token. Checks:
 * - Token decrypts successfully with server's key
 * - Token is not expired (timestamp + lifetime > now)
 * - Client address matches token's embedded address
 *
 * Return: 0 if valid, -EINVAL if invalid, -ETIMEDOUT if expired,
 *         -EACCES if address mismatch
 */
int tquic_token_validate(const struct tquic_token_key *key,
			 const struct sockaddr_storage *client_addr,
			 const u8 *token, u32 token_len,
			 u32 lifetime_secs,
			 struct tquic_cid *original_dcid);

/**
 * tquic_token_validate_retry - Validate a retry token
 * @key: Server's token encryption key
 * @client_addr: Client's current IP address
 * @token: Token received from client
 * @token_len: Token length
 * @original_dcid: Output original DCID
 *
 * Validates a retry token with short lifetime (e.g., 10 seconds).
 *
 * Return: 0 if valid, -errno on failure
 */
int tquic_token_validate_retry(const struct tquic_token_key *key,
			       const struct sockaddr_storage *client_addr,
			       const u8 *token, u32 token_len,
			       struct tquic_cid *original_dcid);

/*
 * =============================================================================
 * NEW_TOKEN Frame (Server-side)
 * =============================================================================
 */

/**
 * tquic_send_new_token - Send NEW_TOKEN frame to client
 * @conn: Connection to send on
 *
 * Generates a token for the client's address and sends it via
 * a NEW_TOKEN frame. Called after handshake completion.
 *
 * Return: 0 on success, -errno on failure
 */
int tquic_send_new_token(struct tquic_connection *conn);

/**
 * tquic_gen_new_token_frame - Generate NEW_TOKEN frame bytes
 * @key: Server's token encryption key
 * @client_addr: Client's IP address
 * @buf: Output buffer
 * @buf_len: Buffer size
 *
 * Generates the NEW_TOKEN frame including type byte and token.
 *
 * Return: Frame length on success, -errno on failure
 */
int tquic_gen_new_token_frame(const struct tquic_token_key *key,
			      const struct sockaddr_storage *client_addr,
			      u8 *buf, size_t buf_len);

/*
 * =============================================================================
 * Token Storage (Client-side)
 * =============================================================================
 */

/**
 * tquic_token_state_init - Initialize token state for connection
 * @state: Token state structure
 *
 * Initializes the token state structure for a new connection.
 */
void tquic_token_state_init(struct tquic_token_state *state);

/**
 * tquic_token_state_cleanup - Cleanup token state
 * @state: Token state structure
 *
 * Clears sensitive token data.
 */
void tquic_token_state_cleanup(struct tquic_token_state *state);

/**
 * tquic_token_store - Store a received token
 * @state: Token state structure
 * @token: Token received via NEW_TOKEN frame
 * @token_len: Token length
 * @server_addr: Server address this token is valid for
 *
 * Stores a token received from the server for future use.
 * Overwrites any previously stored token.
 *
 * Return: 0 on success, -EINVAL if token too large
 */
int tquic_token_store(struct tquic_token_state *state,
		      const u8 *token, u16 token_len,
		      const struct sockaddr_storage *server_addr);

/**
 * tquic_token_get - Get stored token for reconnection
 * @state: Token state structure
 * @server_addr: Server address to match
 * @token: Output buffer for token
 * @token_len: Output token length
 *
 * Retrieves a stored token for use in Initial packet.
 *
 * Return: 0 if token available, -ENOENT if no matching token
 */
int tquic_token_get(struct tquic_token_state *state,
		    const struct sockaddr_storage *server_addr,
		    u8 *token, u16 *token_len);

/**
 * tquic_token_clear - Clear stored token
 * @state: Token state structure
 *
 * Removes any stored token (e.g., on validation failure).
 */
void tquic_token_clear(struct tquic_token_state *state);

/*
 * =============================================================================
 * Frame Processing
 * =============================================================================
 */

/**
 * tquic_process_new_token_frame - Process received NEW_TOKEN frame
 * @conn: Connection receiving the frame
 * @data: Frame data (starting after type byte)
 * @len: Data length
 *
 * Called when client receives NEW_TOKEN frame from server.
 * Stores the token for future connection attempts.
 *
 * Return: Number of bytes consumed, or -errno on error
 */
int tquic_process_new_token_frame(struct tquic_connection *conn,
				  const u8 *data, size_t len);

/*
 * =============================================================================
 * Module Initialization
 * =============================================================================
 */

/**
 * tquic_token_init - Initialize token subsystem
 *
 * Called during module initialization to set up crypto resources.
 *
 * Return: 0 on success, -errno on failure
 */
int __init tquic_token_init(void);

/**
 * tquic_token_exit - Cleanup token subsystem
 *
 * Called during module unload.
 */
void __exit tquic_token_exit(void);

/*
 * =============================================================================
 * Sysctl Accessors
 * =============================================================================
 */

/**
 * tquic_sysctl_get_token_lifetime - Get configured token lifetime
 *
 * Returns the token lifetime from sysctl (default 86400 seconds).
 */
int tquic_sysctl_get_token_lifetime(void);

#endif /* _NET_TQUIC_TOKEN_H */
