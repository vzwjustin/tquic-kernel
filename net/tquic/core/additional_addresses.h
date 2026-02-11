/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: Additional Addresses Transport Parameter Extension
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Implements draft-piraux-quic-additional-addresses extension
 *
 * The additional_addresses transport parameter allows endpoints to advertise
 * multiple addresses they can be reached at, beyond the standard
 * preferred_address parameter. This enables more flexible connection
 * migration and multipath scenarios.
 *
 * Wire Format (per additional address entry):
 *   IP Version (1 byte): 4 for IPv4, 6 for IPv6
 *   Address (4 or 16 bytes): IP address
 *   Port (2 bytes): UDP port (big-endian)
 *   CID Length (1 byte): Connection ID length
 *   Connection ID (variable): CID for this address
 *   Stateless Reset Token (16 bytes): Reset token for this CID
 *
 * The transport parameter contains a sequence of such entries.
 */

#ifndef _TQUIC_ADDITIONAL_ADDRESSES_H
#define _TQUIC_ADDITIONAL_ADDRESSES_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <net/tquic.h>
#include "transport_params.h"

/*
 * Transport parameter ID for additional_addresses
 * (draft-piraux-quic-additional-addresses)
 *
 * Using 0xff04de06 as a provisional ID in the experimental range.
 * This will be updated when the draft is assigned an official ID.
 */
#define TQUIC_TP_ADDITIONAL_ADDRESSES	0xff04de06

/*
 * Maximum number of additional addresses that can be advertised.
 * This limit helps prevent resource exhaustion and keeps the transport
 * parameter size reasonable.
 */
#define TQUIC_MAX_ADDITIONAL_ADDRESSES	8

/*
 * IP version identifiers used in wire format
 */
#define TQUIC_ADDR_IP_VERSION_4		4
#define TQUIC_ADDR_IP_VERSION_6		6

/*
 * Minimum encoded size for an additional address entry:
 *   IPv4: 1 (version) + 4 (addr) + 2 (port) + 1 (cid_len) + 0 (cid) + 16 (token) = 24
 *   IPv6: 1 (version) + 16 (addr) + 2 (port) + 1 (cid_len) + 0 (cid) + 16 (token) = 36
 */
#define TQUIC_ADDITIONAL_ADDR_MIN_IPV4	24
#define TQUIC_ADDITIONAL_ADDR_MIN_IPV6	36

/*
 * Maximum encoded size for an additional address entry:
 *   IPv4: 24 + 20 (max CID) = 44
 *   IPv6: 36 + 20 (max CID) = 56
 */
#define TQUIC_ADDITIONAL_ADDR_MAX_IPV4	44
#define TQUIC_ADDITIONAL_ADDR_MAX_IPV6	56

/**
 * struct tquic_additional_address - Single additional address entry
 * @list: List node for linked list of addresses
 * @ip_version: IP version (4 or 6)
 * @addr: Socket address (IPv4 or IPv6)
 * @cid: Connection ID for this address
 * @stateless_reset_token: Stateless reset token for this CID
 * @validated: Whether this address has been validated via PATH_CHALLENGE
 * @active: Whether this address is currently usable
 * @priority: Priority for address selection (lower = preferred)
 * @rtt_estimate: Estimated RTT to this address (0 if unknown)
 * @last_used: Timestamp of last packet sent to this address
 *
 * Represents a single additional address advertised by the peer or
 * configured locally for advertisement.
 */
struct tquic_additional_address {
	struct list_head list;

	/* Wire format fields */
	u8 ip_version;
	struct sockaddr_storage addr;
	struct tquic_cid cid;
	u8 stateless_reset_token[TQUIC_STATELESS_RESET_TOKEN_LEN];

	/* Runtime state */
	bool validated;
	bool active;
	u8 priority;
	u32 rtt_estimate;
	ktime_t last_used;
};

/**
 * struct tquic_additional_addresses - List of additional addresses
 * @addresses: Linked list of additional address entries
 * @count: Number of entries in the list
 * @max_count: Maximum allowed entries (default: TQUIC_MAX_ADDITIONAL_ADDRESSES)
 * @lock: Spinlock protecting the list
 * @seq_num_base: Base sequence number for CIDs (usually 2, after preferred_address)
 *
 * Container for managing multiple additional addresses. Used both for
 * local addresses to advertise and remote addresses received from peer.
 */
struct tquic_additional_addresses {
	struct list_head addresses;
	u8 count;
	u8 max_count;
	spinlock_t lock;
	u64 seq_num_base;
};

/**
 * enum tquic_addr_select_policy - Address selection policy
 * @TQUIC_ADDR_SELECT_BEST_RTT: Select address with lowest RTT
 * @TQUIC_ADDR_SELECT_SAME_FAMILY: Prefer same address family as current path
 * @TQUIC_ADDR_SELECT_PRIORITY: Select by priority (lowest first)
 * @TQUIC_ADDR_SELECT_ROUND_ROBIN: Rotate through available addresses
 * @TQUIC_ADDR_SELECT_RANDOM: Random selection
 */
enum tquic_addr_select_policy {
	TQUIC_ADDR_SELECT_BEST_RTT = 0,
	TQUIC_ADDR_SELECT_SAME_FAMILY,
	TQUIC_ADDR_SELECT_PRIORITY,
	TQUIC_ADDR_SELECT_ROUND_ROBIN,
	TQUIC_ADDR_SELECT_RANDOM,
};

/*
 * =============================================================================
 * INITIALIZATION AND CLEANUP
 * =============================================================================
 */

/**
 * tquic_additional_addr_init - Initialize an additional addresses list
 * @addrs: Additional addresses structure to initialize
 *
 * Initializes the list, lock, and sets defaults.
 */
void tquic_additional_addr_init(struct tquic_additional_addresses *addrs);

/**
 * tquic_additional_addr_cleanup - Clean up additional addresses list
 * @addrs: Additional addresses structure to clean up
 *
 * Frees all address entries and resets the structure.
 */
void tquic_additional_addr_cleanup(struct tquic_additional_addresses *addrs);

/*
 * =============================================================================
 * ADDRESS MANAGEMENT
 * =============================================================================
 */

/**
 * tquic_additional_addr_add - Add an address to the list
 * @addrs: Additional addresses list
 * @ip_version: IP version (4 or 6)
 * @addr: Socket address to add
 * @cid: Connection ID for this address
 * @reset_token: Stateless reset token (16 bytes, may be NULL)
 *
 * Adds a new address entry to the list. If reset_token is NULL,
 * a random token will be generated.
 *
 * Return: 0 on success, negative errno on failure
 *         -ENOSPC: List is full
 *         -EEXIST: Address already in list
 *         -EINVAL: Invalid parameters
 *         -ENOMEM: Memory allocation failed
 */
int tquic_additional_addr_add(struct tquic_additional_addresses *addrs,
			      u8 ip_version,
			      const struct sockaddr_storage *addr,
			      const struct tquic_cid *cid,
			      const u8 *reset_token);

/**
 * tquic_additional_addr_add_ipv4 - Add an IPv4 address (convenience)
 * @addrs: Additional addresses list
 * @addr: IPv4 address
 * @cid: Connection ID
 * @reset_token: Reset token (may be NULL)
 *
 * Return: 0 on success, negative errno on failure
 */
int tquic_additional_addr_add_ipv4(struct tquic_additional_addresses *addrs,
				   const struct sockaddr_in *addr,
				   const struct tquic_cid *cid,
				   const u8 *reset_token);

/**
 * tquic_additional_addr_add_ipv6 - Add an IPv6 address (convenience)
 * @addrs: Additional addresses list
 * @addr: IPv6 address
 * @cid: Connection ID
 * @reset_token: Reset token (may be NULL)
 *
 * Return: 0 on success, negative errno on failure
 */
int tquic_additional_addr_add_ipv6(struct tquic_additional_addresses *addrs,
				   const struct sockaddr_in6 *addr,
				   const struct tquic_cid *cid,
				   const u8 *reset_token);

/**
 * tquic_additional_addr_remove - Remove an address from the list
 * @addrs: Additional addresses list
 * @addr: Socket address to remove
 *
 * Removes the address entry matching the given address.
 *
 * Return: 0 on success, -ENOENT if not found
 */
int tquic_additional_addr_remove(struct tquic_additional_addresses *addrs,
				 const struct sockaddr_storage *addr);

/**
 * tquic_additional_addr_remove_by_cid - Remove address by connection ID
 * @addrs: Additional addresses list
 * @cid: Connection ID to remove
 *
 * Return: 0 on success, -ENOENT if not found
 */
int tquic_additional_addr_remove_by_cid(struct tquic_additional_addresses *addrs,
					const struct tquic_cid *cid);

/**
 * tquic_additional_addr_find - Find an address entry
 * @addrs: Additional addresses list
 * @addr: Socket address to find
 *
 * Caller must hold addrs->lock or be in RCU read section.
 *
 * Return: Address entry if found, NULL otherwise
 */
struct tquic_additional_address *tquic_additional_addr_find(
	struct tquic_additional_addresses *addrs,
	const struct sockaddr_storage *addr);

/**
 * tquic_additional_addr_find_by_cid - Find address by connection ID
 * @addrs: Additional addresses list
 * @cid: Connection ID to find
 *
 * Return: Address entry if found, NULL otherwise
 */
struct tquic_additional_address *tquic_additional_addr_find_by_cid(
	struct tquic_additional_addresses *addrs,
	const struct tquic_cid *cid);

/*
 * =============================================================================
 * ENCODING AND DECODING
 * =============================================================================
 */

/**
 * tquic_additional_addr_encode - Encode addresses for transport parameter
 * @addrs: Additional addresses list to encode
 * @buf: Output buffer
 * @buflen: Buffer length
 *
 * Encodes all addresses in the list to wire format for the
 * additional_addresses transport parameter.
 *
 * Return: Bytes written on success, negative errno on failure
 *         -ENOSPC: Buffer too small
 *         -EINVAL: Invalid parameters
 */
ssize_t tquic_additional_addr_encode(const struct tquic_additional_addresses *addrs,
				     u8 *buf, size_t buflen);

/**
 * tquic_additional_addr_encoded_size - Calculate encoded size
 * @addrs: Additional addresses list
 *
 * Return: Number of bytes needed to encode all addresses
 */
size_t tquic_additional_addr_encoded_size(
	const struct tquic_additional_addresses *addrs);

/**
 * tquic_additional_addr_decode - Decode transport parameter
 * @buf: Input buffer containing encoded addresses
 * @len: Length of input data
 * @addrs: Output additional addresses structure (must be initialized)
 *
 * Decodes the additional_addresses transport parameter value.
 *
 * Return: 0 on success, negative errno on failure
 *         -EINVAL: Malformed data
 *         -ENOMEM: Memory allocation failed
 *         -ENOSPC: Too many addresses (exceeds max_count)
 */
int tquic_additional_addr_decode(const u8 *buf, size_t len,
				 struct tquic_additional_addresses *addrs);

/*
 * =============================================================================
 * ADDRESS SELECTION AND VALIDATION
 * =============================================================================
 */

/**
 * tquic_additional_addr_select - Select best address for migration
 * @addrs: Additional addresses list
 * @policy: Selection policy
 * @current_family: Current path's address family (for SAME_FAMILY policy)
 *
 * Selects the best additional address for migration based on the policy.
 * Caller must hold addrs->lock or be in RCU read section.
 *
 * Return: Selected address entry, or NULL if none available
 */
struct tquic_additional_address *tquic_additional_addr_select(
	struct tquic_additional_addresses *addrs,
	enum tquic_addr_select_policy policy,
	sa_family_t current_family);

/**
 * tquic_additional_addr_validate - Mark address as validated
 * @addr_entry: Address entry to mark validated
 *
 * Called after successful PATH_CHALLENGE/PATH_RESPONSE exchange.
 */
void tquic_additional_addr_validate(struct tquic_additional_address *addr_entry);

/**
 * tquic_additional_addr_invalidate - Mark address as invalid
 * @addr_entry: Address entry to invalidate
 *
 * Called when path validation fails or address becomes unreachable.
 */
void tquic_additional_addr_invalidate(struct tquic_additional_address *addr_entry);

/**
 * tquic_additional_addr_update_rtt - Update RTT estimate for address
 * @addr_entry: Address entry
 * @rtt_us: Measured RTT in microseconds
 */
void tquic_additional_addr_update_rtt(struct tquic_additional_address *addr_entry,
				      u32 rtt_us);

/**
 * tquic_additional_addr_set_priority - Set priority for an address
 * @addr_entry: Address entry
 * @priority: New priority (0 = highest)
 */
void tquic_additional_addr_set_priority(struct tquic_additional_address *addr_entry,
					u8 priority);

/*
 * =============================================================================
 * ADDRESS VALIDATION HELPERS
 * =============================================================================
 */

/**
 * tquic_additional_addr_is_valid_ipv4 - Validate IPv4 address for migration
 * @addr: IPv4 address to validate
 *
 * Checks that the address is not:
 *   - Unspecified (0.0.0.0)
 *   - Loopback (127.x.x.x)
 *   - Multicast
 *   - Broadcast
 *
 * Return: true if valid for migration
 */
bool tquic_additional_addr_is_valid_ipv4(const struct sockaddr_in *addr);

/**
 * tquic_additional_addr_is_valid_ipv6 - Validate IPv6 address for migration
 * @addr: IPv6 address to validate
 *
 * Checks that the address is not:
 *   - Unspecified (::)
 *   - Loopback (::1)
 *   - Link-local (fe80::)
 *   - Multicast
 *
 * Return: true if valid for migration
 */
bool tquic_additional_addr_is_valid_ipv6(const struct sockaddr_in6 *addr);

/**
 * tquic_additional_addr_is_valid - Validate address for migration
 * @addr: Socket address to validate
 *
 * Return: true if valid for migration
 */
bool tquic_additional_addr_is_valid(const struct sockaddr_storage *addr);

/*
 * =============================================================================
 * CONNECTION INTEGRATION
 * =============================================================================
 */

/**
 * tquic_additional_addr_conn_init - Initialize additional addresses for connection
 * @conn: Connection to initialize
 *
 * Allocates and initializes the additional addresses state for both
 * local and remote addresses on a connection.
 *
 * Return: 0 on success, negative errno on failure
 */
int tquic_additional_addr_conn_init(struct tquic_connection *conn);

/**
 * tquic_additional_addr_conn_cleanup - Clean up additional addresses
 * @conn: Connection to clean up
 */
void tquic_additional_addr_conn_cleanup(struct tquic_connection *conn);

/**
 * tquic_additional_addr_on_tp_received - Handle received transport parameter
 * @conn: Connection
 * @buf: Encoded parameter data
 * @len: Length of data
 *
 * Called when the additional_addresses transport parameter is received
 * from the peer during handshake.
 *
 * Return: 0 on success, negative errno on failure
 */
int tquic_additional_addr_on_tp_received(struct tquic_connection *conn,
					 const u8 *buf, size_t len);

/**
 * tquic_additional_addr_generate_tp - Generate transport parameter for sending
 * @conn: Connection
 * @buf: Output buffer
 * @buflen: Buffer length
 *
 * Generates the additional_addresses transport parameter value to send
 * to the peer.
 *
 * Return: Bytes written on success, negative errno on failure
 */
ssize_t tquic_additional_addr_generate_tp(struct tquic_connection *conn,
					  u8 *buf, size_t buflen);

/*
 * =============================================================================
 * SYSCTL AND CONFIGURATION
 * =============================================================================
 */

/**
 * tquic_additional_addr_enabled - Check if additional addresses is enabled
 * @net: Network namespace
 *
 * Return: true if additional addresses extension is enabled
 */
bool tquic_additional_addr_enabled(struct net *net);

/**
 * tquic_additional_addr_get_max_count - Get max additional addresses limit
 * @net: Network namespace
 *
 * Return: Maximum number of additional addresses to advertise/accept
 */
u8 tquic_additional_addr_get_max_count(struct net *net);

/*
 * =============================================================================
 * MODULE INITIALIZATION
 * =============================================================================
 */

/**
 * tquic_additional_addr_module_init - Initialize additional addresses subsystem
 *
 * Return: 0 on success, negative errno on failure
 */
int __init tquic_additional_addr_module_init(void);

/**
 * tquic_additional_addr_module_exit - Clean up additional addresses subsystem
 */
void __exit tquic_additional_addr_module_exit(void);

#endif /* _TQUIC_ADDITIONAL_ADDRESSES_H */
