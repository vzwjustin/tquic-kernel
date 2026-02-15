/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: QUIC Address Discovery Extension
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Implementation of draft-ietf-quic-address-discovery which enables endpoints
 * to learn their external address as observed by the peer. This is useful for
 * NAT rebinding detection and helps in scenarios where endpoints need to
 * discover their public address.
 *
 * Key features:
 * - OBSERVED_ADDRESS frame (type 0x9f00) to report peer's observed address
 * - Transport parameter negotiation for address discovery support
 * - Sequence number tracking to prevent replay attacks
 * - Rate limiting to prevent amplification attacks
 * - IPv4 and IPv6 support
 */

#ifndef _TQUIC_ADDRESS_DISCOVERY_H
#define _TQUIC_ADDRESS_DISCOVERY_H

#include <linux/types.h>
#include <linux/timer.h>
#include <linux/spinlock.h>
#include <linux/inet.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <net/tquic.h>

/*
 * Frame type for OBSERVED_ADDRESS (draft-ietf-quic-address-discovery)
 *
 * This is a provisional type code from the experimental range.
 * The actual code may change when the draft becomes an RFC.
 */
#define TQUIC_FRAME_OBSERVED_ADDRESS		0x9f00

/*
 * Transport parameter IDs for address discovery negotiation
 *
 * enable_address_discovery (0x9f01):
 *   A zero-length parameter indicating the endpoint supports sending
 *   OBSERVED_ADDRESS frames.
 *
 * observed_address_token_key (0x9f02):
 *   Optional key for authenticating observed addresses (future use).
 */
#define TQUIC_TP_ENABLE_ADDRESS_DISCOVERY	0x9f01ULL
#define TQUIC_TP_OBSERVED_ADDRESS_TOKEN_KEY	0x9f02ULL

/*
 * Address discovery configuration constants
 */
#define TQUIC_ADDR_DISC_MAX_RATE_MS		1000	/* Min ms between sends */
#define TQUIC_ADDR_DISC_MAX_SEQ_GAP		16	/* Max acceptable seq gap */
#define TQUIC_ADDR_DISC_SEQ_WINDOW_SIZE		64	/* Anti-replay window size */
#define TQUIC_ADDR_DISC_MAX_PENDING		8	/* Max pending observations */

/*
 * IP version identifiers for OBSERVED_ADDRESS frame
 */
#define TQUIC_ADDR_DISC_IPV4			4
#define TQUIC_ADDR_DISC_IPV6			6

/**
 * struct tquic_observed_address - Observed address information
 * @seq: Sequence number for ordering and replay prevention
 * @ip_version: IP version (4 for IPv4, 6 for IPv6)
 * @addr: Observed IP address
 * @port: Observed port number
 * @timestamp: When this observation was made (ktime)
 * @list: Linkage for pending observations list
 *
 * This structure represents a single observed address report.
 * The sequence number increases monotonically and is used to:
 * 1. Order observations (newer has higher seq)
 * 2. Detect replay attacks (duplicates are rejected)
 * 3. Handle out-of-order delivery (within window)
 */
struct tquic_observed_address {
	u64 seq;
	u8 ip_version;
	union {
		__be32 v4;
		struct in6_addr v6;
	} addr;
	__be16 port;
	ktime_t timestamp;
	struct list_head list;
};

/**
 * struct tquic_addr_discovery_config - Configuration for address discovery
 * @enabled: Whether address discovery is enabled
 * @report_on_change: Report when observed address changes
 * @report_periodically: Report periodically even without change
 * @report_interval_ms: Interval for periodic reports (if enabled)
 * @max_rate_ms: Minimum interval between frame sends
 */
struct tquic_addr_discovery_config {
	bool enabled;
	bool report_on_change;
	bool report_periodically;
	u32 report_interval_ms;
	u32 max_rate_ms;
};

/**
 * struct tquic_addr_discovery_state - Per-connection address discovery state
 * @lock: Protects all fields in this structure
 * @config: Configuration parameters
 *
 * Local observation state (addresses we observe for the peer):
 * @local_send_seq: Next sequence number to use when sending
 * @last_send_time: Timestamp of last OBSERVED_ADDRESS sent
 * @current_observed: Currently observed peer address
 * @current_observed_valid: Whether current_observed is valid
 *
 * Remote observation state (addresses the peer observes for us):
 * @remote_recv_seq: Highest sequence number received from peer
 * @recv_seq_bitmap: Bitmap for anti-replay window
 * @pending_observations: List of received observations pending processing
 * @pending_count: Number of pending observations
 * @reported_addr: Most recently reported address (what peer sees us as)
 * @reported_addr_valid: Whether reported_addr is valid
 *
 * NAT rebinding detection:
 * @addr_change_count: Number of detected address changes
 * @last_addr_change: Timestamp of last address change
 * @nat_rebind_detected: NAT rebinding event was detected
 *
 * Statistics:
 * @frames_sent: Number of OBSERVED_ADDRESS frames sent
 * @frames_received: Number of OBSERVED_ADDRESS frames received
 * @frames_rejected: Frames rejected (replay, invalid, etc.)
 */
struct tquic_addr_discovery_state {
	spinlock_t lock;
	struct tquic_addr_discovery_config config;

	/* Local observation state - what we observe about peer */
	u64 local_send_seq;
	ktime_t last_send_time;
	struct tquic_observed_address current_observed;
	bool current_observed_valid;

	/* Remote observation state - what peer observes about us */
	u64 remote_recv_seq;
	u64 recv_seq_bitmap;
	struct list_head pending_observations;
	u8 pending_count;
	struct tquic_observed_address reported_addr;
	bool reported_addr_valid;

	/* NAT rebinding detection */
	u32 addr_change_count;
	ktime_t last_addr_change;
	bool nat_rebind_detected;

	/* Statistics */
	u64 frames_sent;
	u64 frames_received;
	u64 frames_rejected;
};

/**
 * struct tquic_frame_observed_address - Parsed OBSERVED_ADDRESS frame
 * @seq: Sequence number
 * @ip_version: 4 for IPv4, 6 for IPv6
 * @addr_v4: IPv4 address (if ip_version == 4)
 * @addr_v6: IPv6 address (if ip_version == 6)
 * @port: Port number in network byte order
 *
 * Wire format (draft-ietf-quic-address-discovery):
 *   Type (0x9f00)
 *   Sequence Number (varint)
 *   IP Version (1 byte: 4 or 6)
 *   IP Address (4 or 16 bytes depending on version)
 *   Port (2 bytes, network byte order)
 */
struct tquic_frame_observed_address {
	u64 seq;
	u8 ip_version;
	union {
		__be32 v4;
		struct in6_addr v6;
	} addr;
	__be16 port;
};

/*
 * Address Discovery State Management API
 */

/**
 * tquic_addr_discovery_init - Initialize address discovery state
 * @state: State structure to initialize
 *
 * Initializes the address discovery state with default configuration.
 * Must be called before any other address discovery functions.
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_addr_discovery_init(struct tquic_addr_discovery_state *state);

/**
 * tquic_addr_discovery_cleanup - Clean up address discovery state
 * @state: State structure to clean up
 *
 * Frees any allocated resources associated with the state.
 * The state structure itself is not freed (caller's responsibility).
 */
void tquic_addr_discovery_cleanup(struct tquic_addr_discovery_state *state);

/**
 * tquic_addr_discovery_set_config - Update configuration
 * @state: State structure
 * @config: New configuration to apply
 *
 * Updates the configuration while the state is active.
 * Takes effect immediately for subsequent operations.
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_addr_discovery_set_config(struct tquic_addr_discovery_state *state,
				    const struct tquic_addr_discovery_config *config);

/*
 * Frame Encoding/Decoding API
 */

/**
 * tquic_encode_observed_address - Encode OBSERVED_ADDRESS frame
 * @buf: Output buffer
 * @buflen: Buffer size
 * @frame: Frame data to encode
 *
 * Encodes an OBSERVED_ADDRESS frame into the wire format.
 *
 * Return: Number of bytes written on success, negative error code on failure
 *   -ENOSPC: Buffer too small
 *   -EINVAL: Invalid frame data (bad IP version, etc.)
 */
ssize_t tquic_encode_observed_address(u8 *buf, size_t buflen,
				      const struct tquic_frame_observed_address *frame);

/**
 * tquic_decode_observed_address - Decode OBSERVED_ADDRESS frame
 * @buf: Input buffer (starting after frame type)
 * @buflen: Buffer size
 * @frame: Output frame structure
 *
 * Decodes an OBSERVED_ADDRESS frame from wire format.
 * The caller must have already consumed the frame type byte.
 *
 * Return: Number of bytes consumed on success, negative error code on failure
 *   -EINVAL: Malformed frame
 *   -EPROTO: Protocol error (invalid IP version, etc.)
 */
ssize_t tquic_decode_observed_address(const u8 *buf, size_t buflen,
				      struct tquic_frame_observed_address *frame);

/**
 * tquic_observed_address_frame_size - Calculate encoded frame size
 * @frame: Frame to calculate size for
 *
 * Return: Size in bytes needed to encode the frame, or 0 on error
 */
size_t tquic_observed_address_frame_size(const struct tquic_frame_observed_address *frame);

/*
 * Frame Processing API
 */

/**
 * tquic_handle_observed_address - Process received OBSERVED_ADDRESS frame
 * @conn: Connection that received the frame
 * @state: Address discovery state
 * @frame: Decoded frame
 *
 * Processes an incoming OBSERVED_ADDRESS frame:
 * 1. Validates sequence number (anti-replay)
 * 2. Updates reported address if sequence is newer
 * 3. Triggers NAT rebinding detection if address changed
 *
 * Return: 0 on success, negative error code on failure
 *   -EINVAL: Invalid frame data
 *   -EALREADY: Duplicate frame (replay detected)
 *   -ERANGE: Sequence number out of acceptable range
 */
int tquic_handle_observed_address(struct tquic_connection *conn,
				  struct tquic_addr_discovery_state *state,
				  const struct tquic_frame_observed_address *frame);

/**
 * tquic_send_observed_address - Send OBSERVED_ADDRESS to peer
 * @conn: Connection to send on
 * @state: Address discovery state
 * @addr: Socket address of observed peer address
 *
 * Sends an OBSERVED_ADDRESS frame to inform the peer of their
 * observed address. Subject to rate limiting.
 *
 * Return: 0 on success, negative error code on failure
 *   -EAGAIN: Rate limited, try again later
 *   -EINVAL: Invalid address
 *   -ENOMEM: Memory allocation failed
 */
int tquic_send_observed_address(struct tquic_connection *conn,
				struct tquic_addr_discovery_state *state,
				const struct sockaddr_storage *addr);

/**
 * tquic_update_observed_address - Update current observation
 * @state: Address discovery state
 * @addr: New observed address
 * @changed: Output flag indicating if address changed
 *
 * Updates the currently observed address for the peer. If the address
 * changed, sets *changed to true. Does not send any frame.
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_update_observed_address(struct tquic_addr_discovery_state *state,
				  const struct sockaddr_storage *addr,
				  bool *changed);

/*
 * NAT Rebinding Detection API
 */

/**
 * tquic_detect_nat_rebinding - Check for NAT rebinding
 * @conn: Connection to check
 * @state: Address discovery state
 * @from_addr: Address the packet was received from
 *
 * Compares the incoming packet's source address against the expected
 * peer address. If they differ, this may indicate NAT rebinding.
 *
 * Return: true if NAT rebinding detected, false otherwise
 */
bool tquic_detect_nat_rebinding(struct tquic_connection *conn,
				struct tquic_addr_discovery_state *state,
				const struct sockaddr_storage *from_addr);

/**
 * tquic_addr_discovery_get_reported - Get the reported address
 * @state: Address discovery state
 * @addr: Output address storage
 *
 * Retrieves the most recently reported address (what the peer sees us as).
 * Returns -ENODATA if no address has been reported yet.
 *
 * Return: 0 on success, negative error code on failure
 */
int tquic_addr_discovery_get_reported(struct tquic_addr_discovery_state *state,
				      struct sockaddr_storage *addr);

/**
 * tquic_addr_discovery_nat_rebind_detected - Check if NAT rebind detected
 * @state: Address discovery state
 *
 * Return: true if NAT rebinding was detected since last check
 */
bool tquic_addr_discovery_nat_rebind_detected(struct tquic_addr_discovery_state *state);

/**
 * tquic_addr_discovery_clear_nat_rebind - Clear NAT rebind flag
 * @state: Address discovery state
 *
 * Clears the NAT rebind detection flag after handling.
 */
void tquic_addr_discovery_clear_nat_rebind(struct tquic_addr_discovery_state *state);

/*
 * Transport Parameter Helpers
 */

/**
 * tquic_addr_discovery_tp_enabled - Check if peer supports address discovery
 * @params: Negotiated transport parameters
 *
 * Return: true if peer advertised enable_address_discovery
 */
bool tquic_addr_discovery_tp_enabled(const struct tquic_negotiated_params *params);

/*
 * Utility Functions
 */

/**
 * tquic_sockaddr_to_observed - Convert sockaddr to observed_address
 * @addr: Source socket address
 * @observed: Output observed address structure
 *
 * Return: 0 on success, -EAFNOSUPPORT for unsupported address family
 */
int tquic_sockaddr_to_observed(const struct sockaddr_storage *addr,
			       struct tquic_observed_address *observed);

/**
 * tquic_observed_to_sockaddr - Convert observed_address to sockaddr
 * @observed: Source observed address
 * @addr: Output socket address
 *
 * Return: 0 on success, negative error on failure
 */
int tquic_observed_to_sockaddr(const struct tquic_observed_address *observed,
			       struct sockaddr_storage *addr);

/**
 * tquic_observed_address_equal - Compare two observed addresses
 * @a: First address
 * @b: Second address
 *
 * Compares IP version, address, and port. Does not compare sequence numbers.
 *
 * Return: true if addresses are equal, false otherwise
 */
bool tquic_observed_address_equal(const struct tquic_observed_address *a,
				  const struct tquic_observed_address *b);

/*
 * Statistics Accessors
 */

/**
 * tquic_addr_discovery_get_stats - Get address discovery statistics
 * @state: Address discovery state
 * @frames_sent: Output for frames sent count
 * @frames_received: Output for frames received count
 * @frames_rejected: Output for frames rejected count
 * @addr_changes: Output for address change count
 */
void tquic_addr_discovery_get_stats(struct tquic_addr_discovery_state *state,
				    u64 *frames_sent, u64 *frames_received,
				    u64 *frames_rejected, u32 *addr_changes);

#endif /* _TQUIC_ADDRESS_DISCOVERY_H */
