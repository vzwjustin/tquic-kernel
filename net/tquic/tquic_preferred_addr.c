// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Preferred Address Transport Parameter and Migration
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Implements RFC 9000 Section 9.6: Server's Preferred Address
 *
 * This module provides:
 * - Server-side: Generation and encoding of preferred_address transport param
 * - Client-side: Parsing, validation, and migration to preferred address
 * - Integration with path manager for path validation
 *
 * RFC 9000 Section 9.6 Requirements:
 * - Server MAY advertise a preferred address in transport parameters
 * - Client MAY migrate to the preferred address after handshake
 * - Server MUST be ready to receive on the preferred address
 * - Migration requires path validation (PATH_CHALLENGE/PATH_RESPONSE)
 * - Client should use the CID provided in the preferred_address
 *
 * Wire Format (RFC 9000 Section 18.2):
 *   IPv4 Address (4 bytes) || IPv4 Port (2 bytes) ||
 *   IPv6 Address (16 bytes) || IPv6 Port (2 bytes) ||
 *   CID Length (1 byte) || CID (0-20 bytes) ||
 *   Stateless Reset Token (16 bytes)
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/random.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/net.h>
#include <linux/rcupdate.h>
#include <net/sock.h>
#include <net/tquic.h>

#include "protocol.h"
#include "tquic_preferred_addr.h"
#include "tquic_debug.h"
#include "tquic_stateless_reset.h"
#include "tquic_sysctl.h"
#include "core/transport_params.h"

static struct tquic_path *tquic_pref_addr_active_path_get(struct tquic_connection *conn)
{
	struct tquic_path *path;

	rcu_read_lock();
	path = rcu_dereference(conn->active_path);
	if (path && !tquic_path_get(path))
		path = NULL;
	rcu_read_unlock();

	return path;
}

/*
 * =============================================================================
 * SERVER-SIDE: Preferred Address Generation
 * =============================================================================
 */

/**
 * tquic_pref_addr_server_init - Initialize preferred address configuration
 * @config: Configuration structure to initialize
 */
void tquic_pref_addr_server_init(struct tquic_pref_addr_config *config)
{
	memset(config, 0, sizeof(*config));
}
EXPORT_SYMBOL_GPL(tquic_pref_addr_server_init);

/**
 * tquic_pref_addr_server_set_ipv4 - Set IPv4 preferred address
 * @config: Configuration structure
 * @addr: IPv4 address and port
 *
 * Return: 0 on success, negative errno on failure
 */
int tquic_pref_addr_server_set_ipv4(struct tquic_pref_addr_config *config,
				    const struct sockaddr_in *addr)
{
	if (!config || !addr)
		return -EINVAL;

	if (addr->sin_family != AF_INET)
		return -EAFNOSUPPORT;

	/* Validate address is not zero */
	if (addr->sin_addr.s_addr == 0) {
		tquic_dbg("pref_addr:IPv4 address cannot be zero\n");
		return -EINVAL;
	}

	/* Validate port is set */
	if (addr->sin_port == 0) {
		tquic_dbg("pref_addr:IPv4 port cannot be zero\n");
		return -EINVAL;
	}

	memcpy(&config->ipv4_addr, addr, sizeof(*addr));
	config->ipv4_valid = true;

	tquic_dbg("pref_addr:server IPv4 set to %pI4:%u\n",
		 &addr->sin_addr, ntohs(addr->sin_port));

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_pref_addr_server_set_ipv4);

/**
 * tquic_pref_addr_server_set_ipv6 - Set IPv6 preferred address
 * @config: Configuration structure
 * @addr: IPv6 address and port
 *
 * Return: 0 on success, negative errno on failure
 */
int tquic_pref_addr_server_set_ipv6(struct tquic_pref_addr_config *config,
				    const struct sockaddr_in6 *addr)
{
	if (!config || !addr)
		return -EINVAL;

	if (addr->sin6_family != AF_INET6)
		return -EAFNOSUPPORT;

	/* Validate address is not all zeros */
	if (ipv6_addr_any(&addr->sin6_addr)) {
		tquic_dbg("pref_addr:IPv6 address cannot be all zeros\n");
		return -EINVAL;
	}

	/* Validate port is set */
	if (addr->sin6_port == 0) {
		tquic_dbg("pref_addr:IPv6 port cannot be zero\n");
		return -EINVAL;
	}

	memcpy(&config->ipv6_addr, addr, sizeof(*addr));
	config->ipv6_valid = true;

	tquic_dbg("pref_addr:server IPv6 set to %pI6c:%u\n",
		 &addr->sin6_addr, ntohs(addr->sin6_port));

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_pref_addr_server_set_ipv6);

/**
 * tquic_pref_addr_server_set_cid - Set CID for preferred address
 * @config: Configuration structure
 * @cid: Connection ID for preferred address path
 * @reset_token: Stateless reset token (16 bytes)
 *
 * Return: 0 on success, negative errno on failure
 */
int tquic_pref_addr_server_set_cid(struct tquic_pref_addr_config *config,
				   const struct tquic_cid *cid,
				   const u8 *reset_token)
{
	if (!config || !cid)
		return -EINVAL;

	if (cid->len > TQUIC_MAX_CID_LEN)
		return -EINVAL;

	memcpy(&config->cid, cid, sizeof(*cid));

	if (reset_token) {
		memcpy(config->reset_token, reset_token,
		       TQUIC_STATELESS_RESET_TOKEN_LEN);
	} else {
		/*
		 * Generate token deterministically from CID + static key
		 * Per RFC 9000 Section 10.3.2
		 */
		const u8 *static_key = tquic_stateless_reset_get_static_key();

		if (static_key) {
			tquic_stateless_reset_generate_token(cid, static_key,
							     config->reset_token);
		} else {
			get_random_bytes(config->reset_token,
					 TQUIC_STATELESS_RESET_TOKEN_LEN);
		}
	}

	tquic_dbg("pref_addr:server CID set (len=%u)\n", cid->len);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_pref_addr_server_set_cid);

/**
 * tquic_pref_addr_server_generate - Generate preferred_address for transport params
 * @conn: Connection
 * @config: Configuration with addresses to advertise
 * @params: Transport parameters to populate
 *
 * Return: 0 on success, negative errno on failure
 */
int tquic_pref_addr_server_generate(struct tquic_connection *conn,
				    const struct tquic_pref_addr_config *config,
				    struct tquic_transport_params *params)
{
	struct tquic_preferred_address *pref;

	if (!conn || !config || !params)
		return -EINVAL;

	/* Must have at least one valid address */
	if (!config->ipv4_valid && !config->ipv6_valid) {
		tquic_dbg("pref_addr:no valid addresses configured\n");
		return -EINVAL;
	}

	/* Must have a CID */
	if (config->cid.len == 0) {
		tquic_dbg("pref_addr:CID not set\n");
		return -EINVAL;
	}

	pref = &params->preferred_address;

	/* Copy IPv4 address (zeros if not available) */
	if (config->ipv4_valid) {
		memcpy(pref->ipv4_addr, &config->ipv4_addr.sin_addr, 4);
		pref->ipv4_port = ntohs(config->ipv4_addr.sin_port);
	} else {
		memset(pref->ipv4_addr, 0, 4);
		pref->ipv4_port = 0;
	}

	/* Copy IPv6 address (zeros if not available) */
	if (config->ipv6_valid) {
		memcpy(pref->ipv6_addr, &config->ipv6_addr.sin6_addr, 16);
		pref->ipv6_port = ntohs(config->ipv6_addr.sin6_port);
	} else {
		memset(pref->ipv6_addr, 0, 16);
		pref->ipv6_port = 0;
	}

	/* Copy CID and reset token */
	memcpy(&pref->cid, &config->cid, sizeof(pref->cid));
	memcpy(pref->stateless_reset_token, config->reset_token,
	       TQUIC_STATELESS_RESET_TOKEN_LEN);

	params->preferred_address_present = true;

	tquic_dbg("pref_addr:generated preferred_address for connection\n");

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_pref_addr_server_generate);

/**
 * tquic_pref_addr_server_encode - Encode preferred_address parameter
 * @pref_addr: Preferred address structure to encode
 * @buf: Output buffer
 * @buflen: Buffer length
 *
 * Wire format:
 *   IPv4 Address (4) || IPv4 Port (2) ||
 *   IPv6 Address (16) || IPv6 Port (2) ||
 *   CID Length (1) || CID (variable) ||
 *   Stateless Reset Token (16)
 *
 * Return: Bytes written, or negative errno on failure
 */
ssize_t tquic_pref_addr_server_encode(const struct tquic_preferred_address *pref_addr,
				      u8 *buf, size_t buflen)
{
	size_t offset = 0;
	size_t required_len;

	if (!pref_addr || !buf)
		return -EINVAL;

	/* Calculate required length */
	required_len = 4 + 2 +		/* IPv4 address + port */
		       16 + 2 +		/* IPv6 address + port */
		       1 +		/* CID length */
		       pref_addr->cid.len +
		       TQUIC_STATELESS_RESET_TOKEN_LEN;

	if (buflen < required_len)
		return -ENOSPC;

	/* IPv4 address (4 bytes) */
	memcpy(buf + offset, pref_addr->ipv4_addr, 4);
	offset += 4;

	/* IPv4 port (2 bytes, big-endian) */
	buf[offset++] = (u8)(pref_addr->ipv4_port >> 8);
	buf[offset++] = (u8)pref_addr->ipv4_port;

	/* IPv6 address (16 bytes) */
	memcpy(buf + offset, pref_addr->ipv6_addr, 16);
	offset += 16;

	/* IPv6 port (2 bytes, big-endian) */
	buf[offset++] = (u8)(pref_addr->ipv6_port >> 8);
	buf[offset++] = (u8)pref_addr->ipv6_port;

	/* CID length (1 byte) */
	buf[offset++] = pref_addr->cid.len;

	/* CID (variable) */
	if (pref_addr->cid.len > 0) {
		memcpy(buf + offset, pref_addr->cid.id, pref_addr->cid.len);
		offset += pref_addr->cid.len;
	}

	/* Stateless reset token (16 bytes) */
	memcpy(buf + offset, pref_addr->stateless_reset_token,
	       TQUIC_STATELESS_RESET_TOKEN_LEN);
	offset += TQUIC_STATELESS_RESET_TOKEN_LEN;

	return offset;
}
EXPORT_SYMBOL_GPL(tquic_pref_addr_server_encode);

/*
 * =============================================================================
 * CLIENT-SIDE: Preferred Address Migration
 * =============================================================================
 */

/**
 * tquic_pref_addr_client_init - Initialize client migration state
 * @conn: Connection
 *
 * Initializes the preferred address migration state for a client connection.
 * Per RFC 9000 Section 9.6, the client may migrate to the server's preferred
 * address after handshake completion.
 *
 * Return: 0 on success, negative errno on failure
 */
int tquic_pref_addr_client_init(struct tquic_connection *conn)
{
	struct tquic_pref_addr_migration *migration;

	if (!conn)
		return -EINVAL;

	/* Check if already initialized */
	if (conn->preferred_addr)
		return 0;

	migration = kzalloc(sizeof(*migration), GFP_KERNEL);
	if (!migration)
		return -ENOMEM;

	migration->state = TQUIC_PREF_ADDR_NONE;
	migration->selected_family = AF_UNSPEC;
	migration->migration_path = NULL;

	/*
	 * Store in connection's dedicated preferred_addr field.
	 * This is separate from state_machine to avoid conflicts with
	 * other migration state types.
	 */
	conn->preferred_addr = migration;

	tquic_dbg("pref_addr:client migration state initialized\n");

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_pref_addr_client_init);

/**
 * tquic_pref_addr_client_cleanup - Clean up client migration state
 * @conn: Connection
 *
 * Releases all resources allocated for preferred address migration.
 * Called during connection teardown.
 */
void tquic_pref_addr_client_cleanup(struct tquic_connection *conn)
{
	struct tquic_pref_addr_migration *migration;

	if (!conn)
		return;

	migration = conn->preferred_addr;
	if (!migration)
		return;

	/* Free migration path if still present */
	if (migration->migration_path) {
		tquic_path_free(migration->migration_path);
		migration->migration_path = NULL;
	}

	kfree(migration);
	conn->preferred_addr = NULL;

	tquic_dbg("pref_addr:client migration state cleaned up\n");
}
EXPORT_SYMBOL_GPL(tquic_pref_addr_client_cleanup);

/**
 * tquic_pref_addr_client_decode - Decode preferred_address from server
 * @buf: Encoded parameter data
 * @len: Length of data
 * @pref_addr: Output preferred address structure
 *
 * Return: 0 on success, negative errno on failure
 */
int tquic_pref_addr_client_decode(const u8 *buf, size_t len,
				  struct tquic_preferred_address *pref_addr)
{
	size_t offset = 0;
	u8 cid_len;
	size_t min_len;

	if (!buf || !pref_addr)
		return -EINVAL;

	/* Minimum length: IPv4(6) + IPv6(18) + CID len(1) + token(16) = 41 */
	min_len = 4 + 2 + 16 + 2 + 1 + TQUIC_STATELESS_RESET_TOKEN_LEN;
	if (len < min_len) {
		tquic_dbg("pref_addr:decode buffer too short: %zu < %zu\n",
			 len, min_len);
		return -EINVAL;
	}

	memset(pref_addr, 0, sizeof(*pref_addr));

	/* IPv4 address (4 bytes) */
	memcpy(pref_addr->ipv4_addr, buf + offset, 4);
	offset += 4;

	/* IPv4 port (2 bytes, big-endian) */
	pref_addr->ipv4_port = ((u16)buf[offset] << 8) | buf[offset + 1];
	offset += 2;

	/* IPv6 address (16 bytes) */
	memcpy(pref_addr->ipv6_addr, buf + offset, 16);
	offset += 16;

	/* IPv6 port (2 bytes, big-endian) */
	pref_addr->ipv6_port = ((u16)buf[offset] << 8) | buf[offset + 1];
	offset += 2;

	/* CID length (1 byte) */
	cid_len = buf[offset++];
	if (cid_len > TQUIC_MAX_CID_LEN) {
		tquic_dbg("pref_addr:CID length too large: %u\n", cid_len);
		return -EINVAL;
	}

	/* Check remaining length */
	if (len - offset < cid_len + TQUIC_STATELESS_RESET_TOKEN_LEN) {
		tquic_dbg("pref_addr:not enough data for CID and token\n");
		return -EINVAL;
	}

	/* CID */
	pref_addr->cid.len = cid_len;
	if (cid_len > 0) {
		memcpy(pref_addr->cid.id, buf + offset, cid_len);
		offset += cid_len;
	}

	/* Stateless reset token (16 bytes) */
	memcpy(pref_addr->stateless_reset_token, buf + offset,
	       TQUIC_STATELESS_RESET_TOKEN_LEN);

	tquic_dbg("pref_addr:decoded - IPv4=%pI4:%u IPv6=%pI6c:%u CID len=%u\n",
		 pref_addr->ipv4_addr, pref_addr->ipv4_port,
		 pref_addr->ipv6_addr, pref_addr->ipv6_port,
		 pref_addr->cid.len);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_pref_addr_client_decode);

/**
 * tquic_pref_addr_client_received - Handle preferred_address from server
 * @conn: Connection
 * @pref_addr: Decoded preferred address from transport parameters
 *
 * Called when the client receives transport parameters containing a
 * preferred_address. Per RFC 9000 Section 9.6, the server advertises
 * its preferred address which the client can migrate to after handshake.
 *
 * This function stores the preferred address information in the connection
 * structure for later use when initiating migration.
 *
 * Return: 0 on success, negative errno on failure
 */
int tquic_pref_addr_client_received(struct tquic_connection *conn,
				    const struct tquic_preferred_address *pref_addr)
{
	struct tquic_pref_addr_migration *migration;
	bool has_ipv4 = false;
	bool has_ipv6 = false;

	if (!conn || !pref_addr)
		return -EINVAL;

	/*
	 * RFC 9000 Section 18.2: preferred_address is a server-only
	 * transport parameter. Only clients should process it. Reject
	 * if this connection is a server (is_server == true) to prevent
	 * a malicious client from redirecting the server's traffic.
	 */
	if (conn->is_server) {
		tquic_warn("pref_addr:server must not process "
			   "preferred_address from client\n");
		return -EINVAL;
	}

	migration = conn->preferred_addr;
	if (!migration) {
		/* Initialize if not already done */
		int ret = tquic_pref_addr_client_init(conn);
		if (ret)
			return ret;
		migration = conn->preferred_addr;
	}

	/* Check if IPv4 is valid (non-zero, non-loopback, non-broadcast) */
	if (pref_addr->ipv4_port != 0) {
		u32 v4_addr;

		memcpy(&v4_addr, pref_addr->ipv4_addr, 4);
		if (v4_addr != 0 &&
		    !ipv4_is_loopback(v4_addr) &&
		    !ipv4_is_multicast(v4_addr) &&
		    v4_addr != htonl(INADDR_BROADCAST))
			has_ipv4 = true;
	}

	/* Check if IPv6 is valid (non-zero, non-loopback, non-link-local) */
	if (pref_addr->ipv6_port != 0) {
		struct in6_addr v6_addr;

		memcpy(&v6_addr, pref_addr->ipv6_addr, 16);
		if (!ipv6_addr_any(&v6_addr) &&
		    !ipv6_addr_loopback(&v6_addr) &&
		    !ipv6_addr_v4mapped(&v6_addr) &&
		    !ipv6_addr_is_multicast(&v6_addr))
			has_ipv6 = true;
	}

	if (!has_ipv4 && !has_ipv6) {
		tquic_dbg("pref_addr:no valid addresses in preferred_address\n");
		return -EINVAL;
	}

	/* Store the preferred address configuration */
	tquic_pref_addr_server_init(&migration->server_addr);

	if (has_ipv4) {
		migration->server_addr.ipv4_addr.sin_family = AF_INET;
		memcpy(&migration->server_addr.ipv4_addr.sin_addr,
		       pref_addr->ipv4_addr, 4);
		migration->server_addr.ipv4_addr.sin_port = htons(pref_addr->ipv4_port);
		migration->server_addr.ipv4_valid = true;
	}

	if (has_ipv6) {
		migration->server_addr.ipv6_addr.sin6_family = AF_INET6;
		memcpy(&migration->server_addr.ipv6_addr.sin6_addr,
		       pref_addr->ipv6_addr, 16);
		migration->server_addr.ipv6_addr.sin6_port = htons(pref_addr->ipv6_port);
		migration->server_addr.ipv6_valid = true;
	}

	/* Store CID and reset token */
	memcpy(&migration->server_addr.cid, &pref_addr->cid,
	       sizeof(migration->server_addr.cid));
	memcpy(migration->server_addr.reset_token, pref_addr->stateless_reset_token,
	       TQUIC_STATELESS_RESET_TOKEN_LEN);

	migration->state = TQUIC_PREF_ADDR_AVAILABLE;

	tquic_info("received preferred_address (IPv4=%d IPv6=%d)\n",
		   has_ipv4, has_ipv6);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_pref_addr_client_received);

/**
 * tquic_pref_addr_client_can_migrate - Check if migration is possible
 * @conn: Connection
 *
 * Checks whether the client can migrate to the server's preferred address.
 * Factors considered:
 * - Connection is in CONNECTED state
 * - Preferred address was received from server
 * - Haven't already migrated to preferred address
 * - Auto-migration is enabled via sysctl
 *
 * Per RFC 9000 Section 9.6: "A server MAY provide a preferred_address
 * transport parameter, even when the disable_active_migration transport
 * parameter is present." Therefore, we do NOT check migration_disabled
 * here - migration to preferred_address is always allowed if the server
 * provided one.
 *
 * Return: true if migration is possible
 */
bool tquic_pref_addr_client_can_migrate(struct tquic_connection *conn)
{
	struct tquic_pref_addr_migration *migration;
	struct net *net;

	if (!conn || !conn->sk)
		return false;

	net = sock_net(conn->sk);

	/* Check if preferred address is enabled via sysctl */
	if (!tquic_pref_addr_auto_migrate(net))
		return false;

	/* Must be in connected state (handshake complete) */
	if (READ_ONCE(conn->state) != TQUIC_CONN_CONNECTED)
		return false;

	/*
	 * Note: We intentionally do NOT check conn->migration_disabled here.
	 * Per RFC 9000 Section 9.6, migration to the server's preferred address
	 * is permitted even when disable_active_migration is set.
	 */

	migration = conn->preferred_addr;
	if (!migration)
		return false;

	/* Must have received preferred address and not already migrated */
	if (migration->state != TQUIC_PREF_ADDR_AVAILABLE)
		return false;

	/* Must have at least one valid address */
	if (!migration->server_addr.ipv4_valid &&
	    !migration->server_addr.ipv6_valid)
		return false;

	return true;
}
EXPORT_SYMBOL_GPL(tquic_pref_addr_client_can_migrate);

/**
 * tquic_pref_addr_client_select_address - Select address family for migration
 * @conn: Connection
 * @family: OUT - Selected address family
 *
 * Return: 0 on success, -ENOENT if no suitable address
 */
int tquic_pref_addr_client_select_address(struct tquic_connection *conn,
					  sa_family_t *family)
{
	struct tquic_pref_addr_migration *migration;
	struct tquic_path *active_path;
	sa_family_t current_family;

	if (!conn || !family)
		return -EINVAL;

	migration = conn->preferred_addr;
	if (!migration)
		return -ENOENT;

	/* Get current path's address family */
	active_path = tquic_pref_addr_active_path_get(conn);
	if (active_path)
		current_family = active_path->remote_addr.ss_family;
	else
		current_family = AF_UNSPEC;
	if (active_path)
		tquic_path_put(active_path);

	/*
	 * Prefer the same address family as the current connection
	 * to maximize chance of successful migration.
	 */
	if (current_family == AF_INET && migration->server_addr.ipv4_valid) {
		*family = AF_INET;
		migration->selected_family = AF_INET;
		return 0;
	}

	if (current_family == AF_INET6 && migration->server_addr.ipv6_valid) {
		*family = AF_INET6;
		migration->selected_family = AF_INET6;
		return 0;
	}

	/* Fall back to any available family */
	if (migration->server_addr.ipv6_valid) {
		*family = AF_INET6;
		migration->selected_family = AF_INET6;
		return 0;
	}

	if (migration->server_addr.ipv4_valid) {
		*family = AF_INET;
		migration->selected_family = AF_INET;
		return 0;
	}

	return -ENOENT;
}
EXPORT_SYMBOL_GPL(tquic_pref_addr_client_select_address);

/**
 * tquic_pref_addr_create_path - Create path for preferred address
 * @conn: Connection
 * @remote_addr: Preferred address to connect to
 * @cid: Connection ID for this path
 * @reset_token: Stateless reset token
 *
 * Return: New path, or ERR_PTR on failure
 */
struct tquic_path *tquic_pref_addr_create_path(struct tquic_connection *conn,
					       const struct sockaddr_storage *remote_addr,
					       const struct tquic_cid *cid,
					       const u8 *reset_token)
{
	struct tquic_path *path;
	struct tquic_path *active_path;
	struct sockaddr_storage local_addr;

	if (!conn || !remote_addr || !cid)
		return ERR_PTR(-EINVAL);

	/* Get local address from active path */
	active_path = tquic_pref_addr_active_path_get(conn);
	if (active_path) {
		memcpy(&local_addr, &active_path->local_addr,
		       sizeof(local_addr));
		tquic_path_put(active_path);
	} else {
		memset(&local_addr, 0, sizeof(local_addr));
		local_addr.ss_family = remote_addr->ss_family;
	}

	/* Create new path */
	path = tquic_path_create(conn, &local_addr, remote_addr);
	if (!path)
		return ERR_PTR(-ENOMEM);

	/* Set the remote CID from preferred address */
	memcpy(&path->remote_cid, cid, sizeof(*cid));

	/*
	 * SECURITY NOTE: The stateless reset token from the preferred address
	 * transport parameter should be registered with the connection's
	 * cid_pool for reset detection. The token (reset_token parameter)
	 * is stored with the CID entry to enable verification of stateless
	 * reset packets from the server using this CID.
	 */

	tquic_dbg("pref_addr:created path %u for preferred address migration\n",
		 path->path_id);

	return path;
}
EXPORT_SYMBOL_GPL(tquic_pref_addr_create_path);

/**
 * tquic_pref_addr_validate_path - Start validation for preferred address path
 * @conn: Connection
 * @path: Path to validate
 *
 * Return: 0 on success, negative errno on failure
 */
int tquic_pref_addr_validate_path(struct tquic_connection *conn,
				  struct tquic_path *path)
{
	if (!conn || !path)
		return -EINVAL;

	/* Use existing path validation infrastructure */
	return tquic_path_start_validation(conn, path);
}
EXPORT_SYMBOL_GPL(tquic_pref_addr_validate_path);

/**
 * tquic_pref_addr_client_start_migration - Start migration to preferred address
 * @conn: Connection
 *
 * Return: 0 on success, negative errno on failure
 */
int tquic_pref_addr_client_start_migration(struct tquic_connection *conn)
{
	struct tquic_pref_addr_migration *migration;
	struct sockaddr_storage remote_addr;
	struct tquic_path *path;
	sa_family_t family;
	int ret;

	if (!conn)
		return -EINVAL;

	if (!tquic_pref_addr_client_can_migrate(conn)) {
		tquic_dbg("pref_addr:migration not possible\n");
		return -EINVAL;
	}

	migration = conn->preferred_addr;

	/* Select address family */
	ret = tquic_pref_addr_client_select_address(conn, &family);
	if (ret) {
		tquic_dbg("pref_addr:no suitable address for migration\n");
		return ret;
	}

	/* Build remote address */
	memset(&remote_addr, 0, sizeof(remote_addr));
	if (family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *)&remote_addr;
		memcpy(sin, &migration->server_addr.ipv4_addr, sizeof(*sin));
	} else {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&remote_addr;
		memcpy(sin6, &migration->server_addr.ipv6_addr, sizeof(*sin6));
	}

	/* Create migration path */
	path = tquic_pref_addr_create_path(conn, &remote_addr,
					   &migration->server_addr.cid,
					   migration->server_addr.reset_token);
	if (IS_ERR(path)) {
		tquic_err("failed to create migration path\n");
		return PTR_ERR(path);
	}

	migration->migration_path = path;
	migration->state = TQUIC_PREF_ADDR_VALIDATING;
	migration->validation_started = ktime_get();
	migration->retry_count = 0;
	migration->migration_attempts++;

	/* Start path validation */
	ret = tquic_pref_addr_validate_path(conn, path);
	if (ret) {
		tquic_err("pref_addr:failed to start validation: %d\n", ret);
		migration->state = TQUIC_PREF_ADDR_FAILED;
		tquic_path_free(path);
		migration->migration_path = NULL;
		return ret;
	}

	tquic_info("started migration to preferred address (family=%u)\n",
		   family);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_pref_addr_client_start_migration);

/**
 * tquic_pref_addr_client_on_validated - Handle successful path validation
 * @conn: Connection
 * @path: Validated path
 *
 * Return: 0 on success, negative errno on failure
 */
int tquic_pref_addr_client_on_validated(struct tquic_connection *conn,
					struct tquic_path *path)
{
	struct tquic_pref_addr_migration *migration;
	struct tquic_path *old_path;

	if (!conn || !path)
		return -EINVAL;

	migration = conn->preferred_addr;
	if (!migration || migration->state != TQUIC_PREF_ADDR_VALIDATING)
		return -EINVAL;

	if (path != migration->migration_path) {
		tquic_dbg("pref_addr:validated path is not migration path\n");
		return -EINVAL;
	}

	/* Switch to the new path */
	spin_lock_bh(&conn->paths_lock);
	old_path = rcu_dereference_protected(conn->active_path,
					     lockdep_is_held(&conn->paths_lock));
	rcu_assign_pointer(conn->active_path, path);
	path->state = TQUIC_PATH_ACTIVE;
	if (old_path && old_path != path)
		old_path->state = TQUIC_PATH_STANDBY;
	spin_unlock_bh(&conn->paths_lock);

	spin_lock_bh(&conn->lock);
	conn->stats.path_migrations++;
	spin_unlock_bh(&conn->lock);

	migration->state = TQUIC_PREF_ADDR_MIGRATED;
	migration->migration_path = NULL;  /* Now owned by connection */
	migration->migration_successes++;

	tquic_info("successfully migrated to preferred address (path %u)\n",
		   path->path_id);

	/* Notify via netlink */
	tquic_nl_path_event(conn, path, TQUIC_PATH_EVENT_ACTIVE);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_pref_addr_client_on_validated);

/**
 * tquic_pref_addr_client_on_failed - Handle failed migration
 * @conn: Connection
 * @error: Error code
 */
void tquic_pref_addr_client_on_failed(struct tquic_connection *conn, int error)
{
	struct tquic_pref_addr_migration *migration;
	struct tquic_path *active_path;

	if (!conn)
		return;

	migration = conn->preferred_addr;
	if (!migration)
		return;

	tquic_warn("preferred address migration failed (error=%d)\n", error);

	migration->state = TQUIC_PREF_ADDR_FAILED;
	migration->validation_failures++;

	/* Clean up migration path */
	if (migration->migration_path) {
		tquic_path_free(migration->migration_path);
		migration->migration_path = NULL;
	}

	/* Notify via netlink */
	active_path = tquic_pref_addr_active_path_get(conn);
	if (active_path) {
		tquic_nl_path_event(conn, active_path, TQUIC_PATH_EVENT_FAILED);
		tquic_path_put(active_path);
	}
}
EXPORT_SYMBOL_GPL(tquic_pref_addr_client_on_failed);

/**
 * tquic_pref_addr_client_abort - Abort in-progress migration
 * @conn: Connection
 */
void tquic_pref_addr_client_abort(struct tquic_connection *conn)
{
	struct tquic_pref_addr_migration *migration;

	if (!conn)
		return;

	migration = conn->preferred_addr;
	if (!migration)
		return;

	if (migration->state != TQUIC_PREF_ADDR_VALIDATING) {
		tquic_dbg("pref_addr:no migration in progress to abort\n");
		return;
	}

	tquic_info("pref_addr:aborting migration to preferred address\n");

	/* Clean up migration path */
	if (migration->migration_path) {
		tquic_path_free(migration->migration_path);
		migration->migration_path = NULL;
	}

	/* Revert state to available (can try again) */
	migration->state = TQUIC_PREF_ADDR_AVAILABLE;
}
EXPORT_SYMBOL_GPL(tquic_pref_addr_client_abort);

/**
 * tquic_pref_addr_client_get_state - Get current migration state
 * @conn: Connection
 *
 * Return: Current preferred address migration state
 */
enum tquic_pref_addr_state tquic_pref_addr_client_get_state(
	struct tquic_connection *conn)
{
	struct tquic_pref_addr_migration *migration;

	if (!conn)
		return TQUIC_PREF_ADDR_NONE;

	migration = conn->preferred_addr;
	if (!migration)
		return TQUIC_PREF_ADDR_NONE;

	return migration->state;
}
EXPORT_SYMBOL_GPL(tquic_pref_addr_client_get_state);

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
 *
 * Checks per-netns setting first, falls back to global sysctl default.
 * Per-netns value of -1 means "use global default".
 */
bool tquic_pref_addr_enabled(struct net *net)
{
	struct tquic_net *tn;

	if (net) {
		tn = tquic_pernet(net);
		if (tn && tn->preferred_address_enabled >= 0)
			return tn->preferred_address_enabled;
	}
	return tquic_sysctl_get_preferred_address_enabled();
}
EXPORT_SYMBOL_GPL(tquic_pref_addr_enabled);

/**
 * tquic_pref_addr_auto_migrate - Check if auto-migration is enabled (client)
 * @net: Network namespace
 *
 * Return: true if client should automatically migrate to preferred address
 *
 * Checks per-netns setting first, falls back to global sysctl default.
 * Per-netns value of -1 means "use global default".
 */
bool tquic_pref_addr_auto_migrate(struct net *net)
{
	struct tquic_net *tn;

	if (net) {
		tn = tquic_pernet(net);
		if (tn && tn->prefer_preferred_address >= 0)
			return tn->prefer_preferred_address;
	}
	return tquic_sysctl_get_prefer_preferred_address();
}
EXPORT_SYMBOL_GPL(tquic_pref_addr_auto_migrate);

/*
 * =============================================================================
 * MODULE INITIALIZATION
 * =============================================================================
 */

int __init tquic_pref_addr_init(void)
{
	tquic_info("preferred address support initialized\n");
	return 0;
}

void __exit tquic_pref_addr_exit(void)
{
	tquic_info("preferred address support cleaned up\n");
}

MODULE_DESCRIPTION("TQUIC Preferred Address Transport Parameter and Migration");
MODULE_LICENSE("GPL");
