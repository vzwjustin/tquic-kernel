/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: Stateless Reset Packet Support
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Implements stateless reset per RFC 9000 Section 10.3.
 *
 * Stateless reset allows an endpoint that has lost state (e.g., after
 * a crash) to signal to its peer that the connection is unusable. The
 * reset packet looks like a regular short header packet to avoid
 * amplification attacks but contains a stateless reset token in the
 * last 16 bytes that the peer can recognize.
 *
 * Key properties:
 * - Minimum 21 bytes (1 byte header + 4 random + 16 token)
 * - Must look like a short header packet (first bit = 0)
 * - Token is deterministically generated from CID and static secret
 * - Peer detects reset by matching token from NEW_CONNECTION_ID frames
 */

#ifndef _NET_TQUIC_STATELESS_RESET_H
#define _NET_TQUIC_STATELESS_RESET_H

#include <linux/types.h>
#include <linux/skbuff.h>
#include <net/tquic.h>

/*
 * Stateless reset constants (RFC 9000 Section 10.3)
 */
#define TQUIC_STATELESS_RESET_MIN_LEN		21
#define TQUIC_STATELESS_RESET_TOKEN_LEN		16
#define TQUIC_STATELESS_RESET_RANDOM_MIN	4
#define TQUIC_STATELESS_RESET_MAX_LEN		1200

/*
 * Static secret length for token generation
 * Used with HMAC-SHA256 to derive tokens deterministically
 */
#define TQUIC_STATELESS_RESET_SECRET_LEN	32

/**
 * struct tquic_stateless_reset_ctx - Context for stateless reset operations
 * @static_key: Static secret used to generate tokens deterministically
 * @enabled: Whether stateless reset transmission is enabled
 * @rate_limit_tokens: Rate limiting tokens available
 * @rate_limit_last: Last rate limit refill time
 * @lock: Protects rate limiting state
 *
 * The static key should be randomly generated at module load and kept
 * constant across restarts if tokens need to be recognized after recovery.
 * For maximum security, regenerate on each restart (tokens won't be
 * recognized, but that's acceptable for stateless reset).
 */
struct tquic_stateless_reset_ctx {
	u8 static_key[TQUIC_STATELESS_RESET_SECRET_LEN];
	bool enabled;
	u32 rate_limit_tokens;
	ktime_t rate_limit_last;
	spinlock_t lock;
};

/*
 * =============================================================================
 * Token Generation API
 * =============================================================================
 *
 * Stateless reset tokens are generated deterministically from the CID and
 * a static secret per RFC 9000 Section 10.3.2. This allows the server to
 * regenerate the same token after losing state.
 */

/**
 * tquic_stateless_reset_generate_token - Generate a stateless reset token
 * @cid: Connection ID to generate token for
 * @static_key: Static secret key (TQUIC_STATELESS_RESET_SECRET_LEN bytes)
 * @token: Output buffer for token (TQUIC_STATELESS_RESET_TOKEN_LEN bytes)
 *
 * Generates a deterministic stateless reset token using HMAC-SHA256
 * truncated to 128 bits. The token is included in NEW_CONNECTION_ID
 * frames sent to the peer.
 *
 * Per RFC 9000 Section 10.3.2:
 * "An endpoint that has multiple CIDs, or that changes CID, needs to
 * be able to generate a valid token for any of those CIDs."
 */
void tquic_stateless_reset_generate_token(const struct tquic_cid *cid,
					  const u8 *static_key,
					  u8 *token);

/**
 * tquic_stateless_reset_verify_token - Verify a stateless reset token
 * @cid: Connection ID the token was generated for
 * @static_key: Static secret key
 * @token: Token to verify (TQUIC_STATELESS_RESET_TOKEN_LEN bytes)
 *
 * Returns: true if token matches, false otherwise
 */
bool tquic_stateless_reset_verify_token(const struct tquic_cid *cid,
					const u8 *static_key,
					const u8 *token);

/*
 * =============================================================================
 * Packet Construction and Transmission API
 * =============================================================================
 */

/**
 * tquic_stateless_reset_build - Build a stateless reset packet
 * @buf: Output buffer for the packet
 * @buf_len: Size of output buffer (must be >= TQUIC_STATELESS_RESET_MIN_LEN)
 * @token: Stateless reset token (16 bytes)
 * @incoming_pkt_len: Length of packet that triggered the reset
 *
 * Constructs a stateless reset packet per RFC 9000 Section 10.3.
 * The packet format is:
 *   - First byte: Short header form (bit 0 = 0), fixed bit set, random bits
 *   - Random bytes: At least 4 bytes, unpredictable content
 *   - Token: Last 16 bytes contain the stateless reset token
 *
 * Per RFC 9000: "A stateless reset is not appropriate for signaling
 * error conditions. An endpoint that wishes to communicate a fatal
 * connection error MUST use a CONNECTION_CLOSE frame."
 *
 * Returns: Length of packet written, or negative error code
 *          -EINVAL if buffer too small
 *          -ENOSPC if incoming_pkt_len constraint cannot be satisfied
 */
int tquic_stateless_reset_build(u8 *buf, size_t buf_len,
				const u8 *token, size_t incoming_pkt_len);

/**
 * tquic_stateless_reset_send - Send a stateless reset packet
 * @sk: UDP socket to send from (or NULL to create temporary)
 * @local_addr: Local address to send from
 * @remote_addr: Remote address to send to
 * @cid: Connection ID that was in the received packet
 * @static_key: Static secret for token generation
 * @incoming_pkt_len: Length of packet that triggered the reset
 *
 * Constructs and transmits a stateless reset packet to the specified
 * remote address. Uses rate limiting to prevent amplification.
 *
 * Per RFC 9000 Section 10.3:
 * "Stateless reset packets are not sent when receiving a packet
 * that could be a stateless reset."
 *
 * Returns: 0 on success, negative error code on failure
 *          -EAGAIN if rate limited
 *          -EINVAL if parameters invalid
 *          -ENOMEM if memory allocation failed
 */
int tquic_stateless_reset_send(struct sock *sk,
			       const struct sockaddr_storage *local_addr,
			       const struct sockaddr_storage *remote_addr,
			       const struct tquic_cid *cid,
			       const u8 *static_key,
			       size_t incoming_pkt_len);

/*
 * =============================================================================
 * Detection API
 * =============================================================================
 *
 * Peers detect stateless reset by matching the last 16 bytes against
 * tokens received in NEW_CONNECTION_ID frames.
 */

/**
 * tquic_stateless_reset_detect - Check if packet is a stateless reset
 * @data: Packet data
 * @len: Packet length
 * @tokens: Array of known stateless reset tokens
 * @num_tokens: Number of tokens in array
 *
 * Checks if a received packet is a stateless reset by:
 * 1. Verifying minimum length (21 bytes)
 * 2. Verifying short header form (first bit = 0)
 * 3. Matching last 16 bytes against known tokens
 *
 * Per RFC 9000 Section 10.3.1:
 * "An endpoint MUST NOT check for any stateless reset tokens
 * associated with connection IDs it has not used."
 *
 * Returns: true if packet matches a known reset token, false otherwise
 */
bool tquic_stateless_reset_detect(const u8 *data, size_t len,
				  const u8 (*tokens)[TQUIC_STATELESS_RESET_TOKEN_LEN],
				  int num_tokens);

/**
 * tquic_stateless_reset_detect_conn - Check if packet is reset for connection
 * @conn: Connection to check against
 * @data: Packet data
 * @len: Packet length
 *
 * Checks received packet against all stateless reset tokens known
 * for the connection (from NEW_CONNECTION_ID frames received from peer).
 *
 * Returns: true if packet is a stateless reset for this connection
 */
bool tquic_stateless_reset_detect_conn(struct tquic_connection *conn,
				       const u8 *data, size_t len);

/*
 * =============================================================================
 * Token Storage API (for peer tokens from NEW_CONNECTION_ID)
 * =============================================================================
 */

/**
 * tquic_stateless_reset_add_peer_token - Store peer's reset token
 * @conn: Connection
 * @cid: Connection ID the token is associated with
 * @token: Reset token from NEW_CONNECTION_ID frame
 *
 * Stores a stateless reset token received from the peer in a
 * NEW_CONNECTION_ID frame. This token will be used to detect
 * stateless resets from the peer.
 *
 * Returns: 0 on success, negative error on failure
 */
int tquic_stateless_reset_add_peer_token(struct tquic_connection *conn,
					 const struct tquic_cid *cid,
					 const u8 *token);

/**
 * tquic_stateless_reset_remove_peer_token - Remove peer's reset token
 * @conn: Connection
 * @cid: Connection ID whose token to remove
 *
 * Removes a stored peer token when the CID is retired.
 */
void tquic_stateless_reset_remove_peer_token(struct tquic_connection *conn,
					     const struct tquic_cid *cid);

/*
 * =============================================================================
 * Context Management API
 * =============================================================================
 */

/**
 * tquic_stateless_reset_ctx_init - Initialize stateless reset context
 * @ctx: Context to initialize
 *
 * Initializes the stateless reset context with a random static key.
 * The key is generated cryptographically and should not be disclosed.
 *
 * Returns: 0 on success, negative error on failure
 */
int tquic_stateless_reset_ctx_init(struct tquic_stateless_reset_ctx *ctx);

/**
 * tquic_stateless_reset_ctx_destroy - Destroy stateless reset context
 * @ctx: Context to destroy
 *
 * Securely wipes the static key and releases resources.
 */
void tquic_stateless_reset_ctx_destroy(struct tquic_stateless_reset_ctx *ctx);

/**
 * tquic_stateless_reset_set_enabled - Enable/disable stateless reset
 * @ctx: Context
 * @enabled: true to enable, false to disable
 *
 * When disabled, stateless reset packets will not be sent in response
 * to packets with unknown CIDs.
 */
void tquic_stateless_reset_set_enabled(struct tquic_stateless_reset_ctx *ctx,
				       bool enabled);

/**
 * tquic_stateless_reset_is_enabled - Check if stateless reset is enabled
 * @ctx: Context
 *
 * Returns: true if stateless reset transmission is enabled
 */
bool tquic_stateless_reset_is_enabled(struct tquic_stateless_reset_ctx *ctx);

/*
 * =============================================================================
 * Module Initialization
 * =============================================================================
 */

/**
 * tquic_stateless_reset_init - Initialize stateless reset subsystem
 *
 * Initializes global state for stateless reset operations.
 * Called during module initialization.
 *
 * Returns: 0 on success, negative error on failure
 */
int __init tquic_stateless_reset_init(void);

/**
 * tquic_stateless_reset_exit - Cleanup stateless reset subsystem
 *
 * Releases resources used by stateless reset subsystem.
 * Called during module exit.
 */
void __exit tquic_stateless_reset_exit(void);

/*
 * =============================================================================
 * Sysctl Integration
 * =============================================================================
 */

/**
 * tquic_sysctl_get_stateless_reset_enabled - Get sysctl enabled state
 *
 * Returns: true if stateless reset is enabled via sysctl
 */
bool tquic_sysctl_get_stateless_reset_enabled(void);

/*
 * =============================================================================
 * Global Context Access
 * =============================================================================
 */

/**
 * tquic_stateless_reset_get_static_key - Get the global static key
 *
 * Returns the static key used for deterministic token generation.
 * Used by CID management when generating tokens for NEW_CONNECTION_ID.
 *
 * Returns: Pointer to static key (TQUIC_STATELESS_RESET_SECRET_LEN bytes),
 *          or NULL if not initialized
 */
const u8 *tquic_stateless_reset_get_static_key(void);

#endif /* _NET_TQUIC_STATELESS_RESET_H */
