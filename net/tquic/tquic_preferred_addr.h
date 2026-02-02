/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: Preferred Address Transport Parameter and Migration
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Implements RFC 9000 Section 9.6: Server's Preferred Address
 *
 * The server MAY advertise a preferred address in transport parameters.
 * Format: IPv4(4) || IPv4Port(2) || IPv6(16) || IPv6Port(2) ||
 *         CID Length(1) || CID || Stateless Reset Token(16)
 *
 * Clients MAY migrate to this address after handshake completion.
 */

#ifndef _TQUIC_PREFERRED_ADDR_H
#define _TQUIC_PREFERRED_ADDR_H

#include <linux/types.h>
#include <linux/socket.h>
#include <net/tquic.h>
#include "core/transport_params.h"

/*
 * Transport parameter ID for preferred_address (RFC 9000 Section 18.2)
 */
#define TQUIC_TP_PREFERRED_ADDRESS	0x0d

/*
 * Preferred address constants
 */
#define TQUIC_PREF_ADDR_MIN_LEN		41	/* IPv4(6) + IPv6(18) + CID len(1) + token(16) */
#define TQUIC_PREF_ADDR_MAX_LEN		61	/* Above + max CID(20) */

/*
 * Preferred address migration states
 */
enum tquic_pref_addr_state {
	TQUIC_PREF_ADDR_NONE = 0,	/* No preferred address */
	TQUIC_PREF_ADDR_AVAILABLE,	/* Received from server, not migrated */
	TQUIC_PREF_ADDR_VALIDATING,	/* Migration validation in progress */
	TQUIC_PREF_ADDR_MIGRATED,	/* Successfully migrated */
	TQUIC_PREF_ADDR_FAILED,		/* Migration failed */
	TQUIC_PREF_ADDR_DISABLED,	/* Migration disabled by policy */
};

/*
 * Preferred address configuration for server
 */
struct tquic_pref_addr_config {
	/* IPv4 address and port (0 if not available) */
	struct sockaddr_in	ipv4_addr;
	bool			ipv4_valid;

	/* IPv6 address and port (zeroes if not available) */
	struct sockaddr_in6	ipv6_addr;
	bool			ipv6_valid;

	/* CID and token for preferred address path */
	struct tquic_cid	cid;
	u8			reset_token[TQUIC_STATELESS_RESET_TOKEN_LEN];
};

/*
 * Client-side preferred address migration state
 */
struct tquic_pref_addr_migration {
	enum tquic_pref_addr_state state;

	/* Decoded preferred address from server */
	struct tquic_pref_addr_config server_addr;

	/* Selected address family for migration */
	sa_family_t		selected_family;

	/* Migration path (created for validation) */
	struct tquic_path	*migration_path;

	/* Validation state */
	u8			challenge_data[8];
	ktime_t			validation_started;
	u8			retry_count;

	/* Statistics */
	u64			migration_attempts;
	u64			migration_successes;
	u64			validation_failures;
};

/*
 * =============================================================================
 * SERVER-SIDE API: Preferred Address Generation
 * =============================================================================
 */

/**
 * tquic_pref_addr_server_init - Initialize preferred address config for server
 * @config: Configuration structure to initialize
 *
 * Initializes the server's preferred address configuration.
 * Call before setting addresses.
 */
void tquic_pref_addr_server_init(struct tquic_pref_addr_config *config);

/**
 * tquic_pref_addr_server_set_ipv4 - Set IPv4 preferred address
 * @config: Configuration structure
 * @addr: IPv4 address and port
 *
 * Sets the IPv4 address to advertise as preferred.
 * Server must be ready to receive on this address.
 *
 * Return: 0 on success, negative errno on failure
 */
int tquic_pref_addr_server_set_ipv4(struct tquic_pref_addr_config *config,
				    const struct sockaddr_in *addr);

/**
 * tquic_pref_addr_server_set_ipv6 - Set IPv6 preferred address
 * @config: Configuration structure
 * @addr: IPv6 address and port
 *
 * Sets the IPv6 address to advertise as preferred.
 * Server must be ready to receive on this address.
 *
 * Return: 0 on success, negative errno on failure
 */
int tquic_pref_addr_server_set_ipv6(struct tquic_pref_addr_config *config,
				    const struct sockaddr_in6 *addr);

/**
 * tquic_pref_addr_server_set_cid - Set CID for preferred address
 * @config: Configuration structure
 * @cid: Connection ID for preferred address path
 * @reset_token: Stateless reset token for this CID
 *
 * Sets the connection ID and reset token to use for the preferred
 * address path. The CID must be unique for this connection.
 *
 * Return: 0 on success, negative errno on failure
 */
int tquic_pref_addr_server_set_cid(struct tquic_pref_addr_config *config,
				   const struct tquic_cid *cid,
				   const u8 *reset_token);

/**
 * tquic_pref_addr_server_generate - Generate preferred_address for transport params
 * @conn: Connection
 * @config: Configuration with addresses to advertise
 * @params: Transport parameters to populate
 *
 * Populates the preferred_address field in transport parameters
 * for server-side encoding.
 *
 * Return: 0 on success, negative errno on failure
 */
int tquic_pref_addr_server_generate(struct tquic_connection *conn,
				    const struct tquic_pref_addr_config *config,
				    struct tquic_transport_params *params);

/**
 * tquic_pref_addr_server_encode - Encode preferred_address parameter
 * @pref_addr: Preferred address structure to encode
 * @buf: Output buffer
 * @buflen: Buffer length
 *
 * Encodes the preferred_address structure to wire format.
 *
 * Return: Bytes written, or negative errno on failure
 */
ssize_t tquic_pref_addr_server_encode(const struct tquic_preferred_address *pref_addr,
				      u8 *buf, size_t buflen);

/*
 * =============================================================================
 * CLIENT-SIDE API: Preferred Address Migration
 * =============================================================================
 */

/**
 * tquic_pref_addr_client_init - Initialize client migration state
 * @conn: Connection
 *
 * Initializes the client's preferred address migration state.
 * Called during connection setup.
 *
 * Return: 0 on success, negative errno on failure
 */
int tquic_pref_addr_client_init(struct tquic_connection *conn);

/**
 * tquic_pref_addr_client_cleanup - Clean up client migration state
 * @conn: Connection
 *
 * Releases resources allocated for preferred address migration.
 */
void tquic_pref_addr_client_cleanup(struct tquic_connection *conn);

/**
 * tquic_pref_addr_client_decode - Decode preferred_address from server
 * @buf: Encoded parameter data
 * @len: Length of data
 * @pref_addr: Output preferred address structure
 *
 * Decodes the preferred_address transport parameter received from server.
 *
 * Return: 0 on success, negative errno on failure
 */
int tquic_pref_addr_client_decode(const u8 *buf, size_t len,
				  struct tquic_preferred_address *pref_addr);

/**
 * tquic_pref_addr_client_received - Handle preferred_address from server
 * @conn: Connection
 * @pref_addr: Decoded preferred address from transport parameters
 *
 * Called when transport parameters are received with a preferred_address.
 * Stores the address for potential migration.
 *
 * Return: 0 on success, negative errno on failure
 */
int tquic_pref_addr_client_received(struct tquic_connection *conn,
				    const struct tquic_preferred_address *pref_addr);

/**
 * tquic_pref_addr_client_can_migrate - Check if migration is possible
 * @conn: Connection
 *
 * Checks whether the client can migrate to the server's preferred address.
 * Factors: handshake complete, address available, migration not disabled.
 *
 * Return: true if migration is possible
 */
bool tquic_pref_addr_client_can_migrate(struct tquic_connection *conn);

/**
 * tquic_pref_addr_client_select_address - Select address family for migration
 * @conn: Connection
 * @family: OUT - Selected address family (AF_INET or AF_INET6)
 *
 * Selects which address to migrate to based on client's network capability.
 * Prefers the same family as the current connection if available.
 *
 * Return: 0 on success, -ENOENT if no suitable address
 */
int tquic_pref_addr_client_select_address(struct tquic_connection *conn,
					  sa_family_t *family);

/**
 * tquic_pref_addr_client_start_migration - Start migration to preferred address
 * @conn: Connection
 *
 * Initiates migration to the server's preferred address.
 * Creates a new path and begins path validation (PATH_CHALLENGE).
 *
 * Return: 0 on success, negative errno on failure
 */
int tquic_pref_addr_client_start_migration(struct tquic_connection *conn);

/**
 * tquic_pref_addr_client_on_validated - Handle successful path validation
 * @conn: Connection
 * @path: Validated path
 *
 * Called when PATH_RESPONSE is received for the migration path.
 * Completes the migration and switches traffic to the new path.
 *
 * Return: 0 on success, negative errno on failure
 */
int tquic_pref_addr_client_on_validated(struct tquic_connection *conn,
					struct tquic_path *path);

/**
 * tquic_pref_addr_client_on_failed - Handle failed migration
 * @conn: Connection
 * @error: Error code
 *
 * Called when migration validation fails. Cleans up state
 * and keeps using the original path.
 */
void tquic_pref_addr_client_on_failed(struct tquic_connection *conn, int error);

/**
 * tquic_pref_addr_client_abort - Abort in-progress migration
 * @conn: Connection
 *
 * Aborts an in-progress migration to preferred address.
 * Traffic continues on the original path.
 */
void tquic_pref_addr_client_abort(struct tquic_connection *conn);

/**
 * tquic_pref_addr_client_get_state - Get current migration state
 * @conn: Connection
 *
 * Return: Current preferred address migration state
 */
enum tquic_pref_addr_state tquic_pref_addr_client_get_state(
	struct tquic_connection *conn);

/*
 * =============================================================================
 * SYSCTL ACCESSORS
 * =============================================================================
 */

/**
 * tquic_pref_addr_enabled - Check if preferred address is enabled (server)
 * @net: Network namespace
 *
 * Return: true if server should advertise preferred address
 */
bool tquic_pref_addr_enabled(struct net *net);

/**
 * tquic_pref_addr_auto_migrate - Check if auto-migration is enabled (client)
 * @net: Network namespace
 *
 * Return: true if client should automatically migrate to preferred address
 */
bool tquic_pref_addr_auto_migrate(struct net *net);

/*
 * =============================================================================
 * PATH MANAGER INTEGRATION
 * =============================================================================
 */

/**
 * tquic_pref_addr_create_path - Create path for preferred address
 * @conn: Connection
 * @remote_addr: Preferred address to connect to
 * @cid: Connection ID for this path
 * @reset_token: Stateless reset token
 *
 * Creates and initializes a path for the preferred address.
 * The path is not yet validated.
 *
 * Return: New path, or ERR_PTR on failure
 */
struct tquic_path *tquic_pref_addr_create_path(struct tquic_connection *conn,
					       const struct sockaddr_storage *remote_addr,
					       const struct tquic_cid *cid,
					       const u8 *reset_token);

/**
 * tquic_pref_addr_validate_path - Start validation for preferred address path
 * @conn: Connection
 * @path: Path to validate
 *
 * Initiates PATH_CHALLENGE on the preferred address path.
 *
 * Return: 0 on success, negative errno on failure
 */
int tquic_pref_addr_validate_path(struct tquic_connection *conn,
				  struct tquic_path *path);

/*
 * =============================================================================
 * MODULE INITIALIZATION
 * =============================================================================
 */

/**
 * tquic_pref_addr_init - Initialize preferred address subsystem
 *
 * Return: 0 on success, negative errno on failure
 */
int __init tquic_pref_addr_init(void);

/**
 * tquic_pref_addr_exit - Clean up preferred address subsystem
 */
void __exit tquic_pref_addr_exit(void);

#endif /* _TQUIC_PREFERRED_ADDR_H */
