/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC MASQUE: QUIC-Aware Proxy Protocol (draft-ietf-masque-quic-proxy)
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * This header defines the QUIC-Aware Proxy extension for MASQUE, enabling
 * optimized proxying of QUIC connections through HTTP/3 proxies. Unlike
 * standard CONNECT-UDP, QUIC-Aware Proxy provides:
 *
 *   - Connection ID cooperation between hops
 *   - Header compression for proxied QUIC packets
 *   - Reduced latency through packet-level proxying
 *   - End-to-end QUIC semantics preservation
 *
 * Protocol Overview:
 *   1. Client registers proxied QUIC connection with proxy
 *   2. Proxy and client coordinate connection IDs
 *   3. QUIC packets are forwarded with optional header compression
 *   4. Multiple QUIC connections can share a single tunnel
 *
 * Capsule Types (draft-ietf-masque-quic-proxy):
 *   QUIC_PROXY_REGISTER:   Register new proxied connection
 *   QUIC_PROXY_CID:        Connection ID update
 *   QUIC_PROXY_PACKET:     Encapsulated QUIC packet
 *   QUIC_PROXY_DEREGISTER: Deregister proxied connection
 *
 * References:
 *   draft-ietf-masque-quic-proxy - QUIC-Aware Proxying Using HTTP
 *   RFC 9298 - Proxying UDP in HTTP (CONNECT-UDP)
 *   RFC 9297 - HTTP Datagrams and the Capsule Protocol
 *   RFC 9000 - QUIC: A UDP-Based Multiplexed and Secure Transport
 */

#ifndef _TQUIC_MASQUE_QUIC_PROXY_H
#define _TQUIC_MASQUE_QUIC_PROXY_H

#include <linux/types.h>
#include <linux/list.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <linux/refcount.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <net/tquic.h>

/* Forward declarations */
struct tquic_connection;
struct tquic_stream;
struct tquic_connect_udp_tunnel;

/*
 * =============================================================================
 * CAPSULE TYPE DEFINITIONS (draft-ietf-masque-quic-proxy)
 * =============================================================================
 */

/*
 * QUIC-Aware Proxy Capsule Types
 *
 * These capsule types are sent on the CONNECT-UDP request stream to
 * coordinate QUIC connection proxying.
 */
#define CAPSULE_TYPE_QUIC_PROXY_REGISTER	0x4143	/* Register connection */
#define CAPSULE_TYPE_QUIC_PROXY_CID		0x4144	/* CID update */
#define CAPSULE_TYPE_QUIC_PROXY_PACKET		0x4145	/* Encapsulated packet */
#define CAPSULE_TYPE_QUIC_PROXY_DEREGISTER	0x4146	/* Deregister connection */
#define CAPSULE_TYPE_QUIC_PROXY_ERROR		0x4147	/* Error indication */
#define CAPSULE_TYPE_QUIC_PROXY_ACK		0x4148	/* Acknowledgment */

/* Extended capsule types for advanced features */
#define CAPSULE_TYPE_QUIC_PROXY_MTU		0x4149	/* MTU discovery */
#define CAPSULE_TYPE_QUIC_PROXY_KEEPALIVE	0x414A	/* Keepalive */
#define CAPSULE_TYPE_QUIC_PROXY_STATS		0x414B	/* Statistics report */

/*
 * =============================================================================
 * CONSTANTS
 * =============================================================================
 */

/* Maximum connection ID length per RFC 9000 */
#define QUIC_PROXY_MAX_CID_LEN			20

/* Maximum number of connection IDs per direction */
#define QUIC_PROXY_MAX_CIDS_PER_CONN		8

/* Maximum proxied connections per tunnel */
#define QUIC_PROXY_MAX_CONNECTIONS		64

/* Connection ID hash table size (power of 2) */
#define QUIC_PROXY_CID_HASH_BITS		8

/* Default timeout for CID cooperation (milliseconds) */
#define QUIC_PROXY_CID_TIMEOUT_MS		30000

/* Header compression context window size */
#define QUIC_PROXY_COMPRESS_WINDOW_SIZE		16

/* Maximum compressed header size */
#define QUIC_PROXY_MAX_COMPRESSED_HEADER	32

/* Error codes */
#define QUIC_PROXY_ERR_SUCCESS			0
#define QUIC_PROXY_ERR_INVALID_CID		1
#define QUIC_PROXY_ERR_CID_CONFLICT		2
#define QUIC_PROXY_ERR_CONN_NOT_FOUND		3
#define QUIC_PROXY_ERR_RESOURCE_LIMIT		4
#define QUIC_PROXY_ERR_INTERNAL			5
#define QUIC_PROXY_ERR_INVALID_PACKET		6
#define QUIC_PROXY_ERR_COMPRESSION		7

/* Packet forwarding modes */
#define QUIC_PROXY_MODE_PASSTHROUGH		0	/* Forward as-is */
#define QUIC_PROXY_MODE_HEADER_COMPRESS		1	/* Compress headers */
#define QUIC_PROXY_MODE_CID_REWRITE		2	/* Rewrite CIDs */

/* CID ownership flags */
#define QUIC_PROXY_CID_OWNER_CLIENT		0x01
#define QUIC_PROXY_CID_OWNER_TARGET		0x02
#define QUIC_PROXY_CID_OWNER_PROXY		0x04

/*
 * =============================================================================
 * CONNECTION ID STRUCTURES
 * =============================================================================
 */

/**
 * struct quic_proxy_cid - Connection ID entry
 * @cid: Connection ID bytes
 * @len: Connection ID length (1-20 bytes)
 * @seq_num: Sequence number for this CID
 * @retire_prior_to: CIDs with lower sequence numbers should be retired
 * @stateless_reset_token: Stateless reset token (if provided)
 * @has_reset_token: Whether reset token is present
 * @owner: CID ownership flags
 * @refcnt: Reference count
 * @hash_node: Hash table linkage
 * @list_node: List linkage within connection
 * @created_at: Creation timestamp
 *
 * Represents a single connection ID used in proxied QUIC connections.
 * Multiple CIDs can be associated with a single proxied connection.
 */
struct quic_proxy_cid {
	u8 cid[QUIC_PROXY_MAX_CID_LEN];
	u8 len;
	u64 seq_num;
	u64 retire_prior_to;
	u8 stateless_reset_token[16];
	bool has_reset_token;
	u8 owner;
	refcount_t refcnt;
	struct hlist_node hash_node;
	struct list_head list_node;
	ktime_t created_at;
};

/**
 * struct quic_proxy_cid_pair - Matched CID pair for forwarding
 * @client_cid: CID used on client-proxy path
 * @target_cid: CID used on proxy-target path
 * @proxy_cid: Proxy-generated CID (if CID rewriting enabled)
 * @active: Whether this pair is active
 *
 * Links connection IDs between the two hops of the proxied connection.
 */
struct quic_proxy_cid_pair {
	struct quic_proxy_cid *client_cid;
	struct quic_proxy_cid *target_cid;
	struct quic_proxy_cid *proxy_cid;
	bool active;
};

/**
 * struct quic_proxy_cid_cooperation - CID cooperation state
 * @client_cids: CIDs provided by client
 * @target_cids: CIDs provided by target
 * @proxy_cids: CIDs generated by proxy
 * @pairs: Active CID pairs
 * @num_pairs: Number of active pairs
 * @next_seq_num: Next sequence number to assign
 * @pending_request: Pending CID request (if any)
 * @lock: Protects cooperation state
 *
 * Manages the coordination of connection IDs between client, proxy,
 * and target for a single proxied QUIC connection.
 */
struct quic_proxy_cid_cooperation {
	struct list_head client_cids;
	struct list_head target_cids;
	struct list_head proxy_cids;
	struct quic_proxy_cid_pair pairs[QUIC_PROXY_MAX_CIDS_PER_CONN];
	int num_pairs;
	u64 next_seq_num;
	bool pending_request;
	spinlock_t lock;
};

/*
 * =============================================================================
 * HEADER COMPRESSION STRUCTURES
 * =============================================================================
 */

/**
 * struct quic_proxy_compress_entry - Compression dictionary entry
 * @dcid: Destination CID
 * @dcid_len: DCID length
 * @scid: Source CID (if present)
 * @scid_len: SCID length
 * @version: QUIC version
 * @index: Entry index in dictionary
 * @used: Entry usage count
 *
 * Stores header fields for compression/decompression.
 */
struct quic_proxy_compress_entry {
	u8 dcid[QUIC_PROXY_MAX_CID_LEN];
	u8 dcid_len;
	u8 scid[QUIC_PROXY_MAX_CID_LEN];
	u8 scid_len;
	u32 version;
	u8 index;
	u32 used;
};

/**
 * struct quic_proxy_compress_ctx - Header compression context
 * @entries: Compression dictionary entries
 * @num_entries: Number of active entries
 * @next_index: Next entry index to use
 * @enabled: Compression enabled flag
 * @tx_compressed: Packets sent with compression
 * @tx_uncompressed: Packets sent without compression
 * @rx_compressed: Packets received with compression
 * @rx_decompression_errors: Decompression failures
 * @lock: Context lock
 *
 * Maintains compression state for header compression optimization.
 */
struct quic_proxy_compress_ctx {
	struct quic_proxy_compress_entry entries[QUIC_PROXY_COMPRESS_WINDOW_SIZE];
	int num_entries;
	u8 next_index;
	bool enabled;
	u64 tx_compressed;
	u64 tx_uncompressed;
	u64 rx_compressed;
	u64 rx_decompression_errors;
	spinlock_t lock;
};

/*
 * =============================================================================
 * PROXIED CONNECTION STRUCTURES
 * =============================================================================
 */

/**
 * enum quic_proxy_conn_state - Proxied connection state
 * @QUIC_PROXY_CONN_IDLE: Initial state
 * @QUIC_PROXY_CONN_REGISTERING: Registration in progress
 * @QUIC_PROXY_CONN_ACTIVE: Actively forwarding packets
 * @QUIC_PROXY_CONN_DRAINING: Connection draining
 * @QUIC_PROXY_CONN_CLOSED: Connection closed
 * @QUIC_PROXY_CONN_ERROR: Error state
 */
enum quic_proxy_conn_state {
	QUIC_PROXY_CONN_IDLE = 0,
	QUIC_PROXY_CONN_REGISTERING,
	QUIC_PROXY_CONN_ACTIVE,
	QUIC_PROXY_CONN_DRAINING,
	QUIC_PROXY_CONN_CLOSED,
	QUIC_PROXY_CONN_ERROR,
};

/**
 * struct tquic_proxied_quic_conn - State for a proxied QUIC connection
 * @conn_id: Unique identifier for this proxied connection
 * @state: Current connection state
 *
 * Endpoint information:
 * @target_host: Target hostname or IP
 * @target_port: Target UDP port
 *
 * Connection ID management:
 * @cid_coop: CID cooperation state
 * @dcid_hash_node: Hash node for DCID lookup
 *
 * Header compression:
 * @compress_ctx: Compression context (if enabled)
 *
 * Forwarding mode:
 * @mode: Packet forwarding mode
 *
 * Statistics:
 * @tx_packets: Packets forwarded client->target
 * @rx_packets: Packets forwarded target->client
 * @tx_bytes: Bytes forwarded client->target
 * @rx_bytes: Bytes forwarded target->client
 * @cid_updates: Number of CID updates
 * @compression_savings: Bytes saved by compression
 *
 * Timing:
 * @created_at: Connection creation time
 * @last_activity: Last packet forwarded
 *
 * Linkage:
 * @list: List linkage in proxy state
 * @proxy: Parent proxy state
 * @refcnt: Reference count
 */
struct tquic_proxied_quic_conn {
	u64 conn_id;
	enum quic_proxy_conn_state state;

	/* Target endpoint */
	char target_host[256];
	u16 target_port;

	/* Connection ID management */
	struct quic_proxy_cid_cooperation cid_coop;
	struct hlist_node dcid_hash_node;

	/* Header compression */
	struct quic_proxy_compress_ctx compress_ctx;

	/* Forwarding mode */
	u8 mode;

	/* Statistics */
	u64 tx_packets;
	u64 rx_packets;
	u64 tx_bytes;
	u64 rx_bytes;
	u64 cid_updates;
	u64 compression_savings;

	/* Timing */
	ktime_t created_at;
	ktime_t last_activity;

	/* Linkage */
	struct list_head list;
	struct tquic_quic_proxy_state *proxy;
	refcount_t refcnt;
};

/*
 * =============================================================================
 * PROXY CONFIGURATION
 * =============================================================================
 */

/**
 * struct tquic_quic_proxy_config - QUIC proxy configuration
 * @max_connections: Maximum proxied connections
 * @cid_cooperation_enabled: Enable CID cooperation
 * @header_compression_enabled: Enable header compression
 * @cid_rewriting_enabled: Enable proxy CID rewriting
 * @cid_timeout_ms: CID request timeout
 * @idle_timeout_ms: Idle connection timeout
 * @stats_interval_ms: Statistics report interval (0 = disabled)
 * @allowed_versions: Bitmask of allowed QUIC versions
 * @require_auth: Require client authentication
 *
 * Configuration for QUIC-aware proxy behavior.
 */
struct tquic_quic_proxy_config {
	u32 max_connections;
	bool cid_cooperation_enabled;
	bool header_compression_enabled;
	bool cid_rewriting_enabled;
	u32 cid_timeout_ms;
	u32 idle_timeout_ms;
	u32 stats_interval_ms;
	u32 allowed_versions;
	bool require_auth;
};

/* Default configuration values */
#define QUIC_PROXY_DEFAULT_MAX_CONNECTIONS	64
#define QUIC_PROXY_DEFAULT_CID_TIMEOUT_MS	30000
#define QUIC_PROXY_DEFAULT_IDLE_TIMEOUT_MS	120000

/**
 * struct tquic_quic_proxy_stats - Proxy-wide statistics
 * @active_connections: Currently active proxied connections
 * @total_connections: Total connections handled
 * @total_packets_fwd: Total packets forwarded
 * @total_bytes_fwd: Total bytes forwarded
 * @cid_operations: CID cooperation operations
 * @compression_ops: Header compression operations
 * @errors: Error count by type
 */
struct tquic_quic_proxy_stats {
	u32 active_connections;
	u64 total_connections;
	u64 total_packets_fwd;
	u64 total_bytes_fwd;
	u64 cid_operations;
	u64 compression_ops;
	u64 errors[8];
};

/*
 * =============================================================================
 * PROXY STATE
 * =============================================================================
 */

/**
 * struct tquic_quic_proxy_state - Main QUIC proxy state
 * @tunnel: Underlying CONNECT-UDP tunnel
 * @conn: QUIC connection (client-proxy)
 * @stream: HTTP/3 request stream
 *
 * Configuration:
 * @config: Proxy configuration
 *
 * Connection management:
 * @connections: List of proxied connections
 * @num_connections: Current connection count
 * @next_conn_id: Next connection ID to assign
 * @cid_hash: Hash table for CID lookup
 *
 * Statistics:
 * @stats: Proxy statistics
 *
 * Timing:
 * @created_at: Proxy creation time
 * @idle_timer: Idle timeout timer
 * @stats_timer: Statistics timer
 *
 * Work queue:
 * @forward_work: Packet forwarding work
 *
 * Synchronization:
 * @lock: Protects proxy state
 * @refcnt: Reference count
 *
 * State:
 * @active: Proxy is active
 * @is_server: Server (proxy) side vs client side
 */
struct tquic_quic_proxy_state {
	struct tquic_connect_udp_tunnel *tunnel;
	struct tquic_connection *conn;
	struct tquic_stream *stream;

	/* Configuration */
	struct tquic_quic_proxy_config config;

	/* Connection management */
	struct list_head connections;
	u32 num_connections;
	u64 next_conn_id;
	DECLARE_HASHTABLE(cid_hash, QUIC_PROXY_CID_HASH_BITS);

	/* Statistics */
	struct tquic_quic_proxy_stats stats;

	/* Timing */
	ktime_t created_at;
	struct timer_list idle_timer;
	struct timer_list stats_timer;

	/* Work queue */
	struct work_struct forward_work;

	/* Synchronization */
	spinlock_t lock;
	refcount_t refcnt;

	/* State */
	bool active;
	bool is_server;
	bool authenticated;	/* Set by auth handler before registering conns */
};

/*
 * =============================================================================
 * CAPSULE STRUCTURES
 * =============================================================================
 */

/**
 * struct quic_proxy_register_capsule - QUIC_PROXY_REGISTER capsule
 * @conn_id: Connection identifier
 * @target_host_len: Target hostname length
 * @target_host: Target hostname or IP
 * @target_port: Target UDP port
 * @initial_dcid_len: Initial DCID length
 * @initial_dcid: Initial destination connection ID
 * @initial_scid_len: Initial SCID length
 * @initial_scid: Initial source connection ID
 * @version: QUIC version
 * @flags: Registration flags
 *
 * Sent by client to register a new proxied QUIC connection.
 */
struct quic_proxy_register_capsule {
	u64 conn_id;
	u8 target_host_len;
	char target_host[256];
	u16 target_port;
	u8 initial_dcid_len;
	u8 initial_dcid[QUIC_PROXY_MAX_CID_LEN];
	u8 initial_scid_len;
	u8 initial_scid[QUIC_PROXY_MAX_CID_LEN];
	u32 version;
	u8 flags;
};

/* Registration flags */
#define QUIC_PROXY_REG_FLAG_CID_COOP		0x01	/* Request CID cooperation */
#define QUIC_PROXY_REG_FLAG_COMPRESS		0x02	/* Request compression */
#define QUIC_PROXY_REG_FLAG_CID_REWRITE		0x04	/* Allow CID rewriting */

/**
 * struct quic_proxy_cid_capsule - QUIC_PROXY_CID capsule
 * @conn_id: Connection identifier
 * @direction: CID direction (client->target or target->client)
 * @action: CID action (add, retire, etc.)
 * @seq_num: CID sequence number
 * @retire_prior_to: Retire CIDs with lower sequence
 * @cid_len: Connection ID length
 * @cid: Connection ID bytes
 * @reset_token: Stateless reset token (16 bytes if present)
 * @has_reset_token: Whether reset token is present
 *
 * Updates connection ID state for a proxied connection.
 */
struct quic_proxy_cid_capsule {
	u64 conn_id;
	u8 direction;
	u8 action;
	u64 seq_num;
	u64 retire_prior_to;
	u8 cid_len;
	u8 cid[QUIC_PROXY_MAX_CID_LEN];
	u8 reset_token[16];
	bool has_reset_token;
};

/* CID directions */
#define QUIC_PROXY_CID_DIR_CLIENT_TARGET	0	/* Client to target */
#define QUIC_PROXY_CID_DIR_TARGET_CLIENT	1	/* Target to client */

/* CID actions */
#define QUIC_PROXY_CID_ACTION_ADD		0	/* Add new CID */
#define QUIC_PROXY_CID_ACTION_RETIRE		1	/* Retire CID */
#define QUIC_PROXY_CID_ACTION_REQUEST		2	/* Request new CID */
#define QUIC_PROXY_CID_ACTION_ACK		3	/* Acknowledge CID */

/**
 * struct quic_proxy_packet_capsule - QUIC_PROXY_PACKET capsule
 * @conn_id: Connection identifier
 * @direction: Packet direction
 * @compressed: Header is compressed
 * @compress_index: Compression dictionary index (if compressed)
 * @packet_len: QUIC packet length
 * @packet: QUIC packet data
 *
 * Encapsulates a QUIC packet for forwarding.
 */
struct quic_proxy_packet_capsule {
	u64 conn_id;
	u8 direction;
	bool compressed;
	u8 compress_index;
	u16 packet_len;
	u8 *packet;
};

/**
 * struct quic_proxy_deregister_capsule - QUIC_PROXY_DEREGISTER capsule
 * @conn_id: Connection identifier
 * @reason: Deregistration reason code
 * @drain_timeout_ms: Draining period (0 = immediate)
 *
 * Deregisters a proxied QUIC connection.
 */
struct quic_proxy_deregister_capsule {
	u64 conn_id;
	u8 reason;
	u32 drain_timeout_ms;
};

/* Deregistration reasons */
#define QUIC_PROXY_DEREG_NORMAL			0	/* Normal closure */
#define QUIC_PROXY_DEREG_ERROR			1	/* Error occurred */
#define QUIC_PROXY_DEREG_TIMEOUT		2	/* Idle timeout */
#define QUIC_PROXY_DEREG_MIGRATION		3	/* Connection migrated */

/**
 * struct quic_proxy_error_capsule - QUIC_PROXY_ERROR capsule
 * @conn_id: Connection identifier (0 for proxy-wide)
 * @error_code: Error code
 * @error_len: Error message length
 * @error_msg: Human-readable error message
 *
 * Reports an error condition.
 */
struct quic_proxy_error_capsule {
	u64 conn_id;
	u64 error_code;
	u16 error_len;
	char error_msg[256];
};

/*
 * =============================================================================
 * PROXY LIFECYCLE API
 * =============================================================================
 */

/**
 * tquic_quic_proxy_init - Initialize QUIC proxy state
 * @tunnel: Underlying CONNECT-UDP tunnel
 * @config: Proxy configuration (NULL for defaults)
 * @is_server: True if this is the proxy (server) side
 *
 * Creates and initializes a QUIC-aware proxy state. The proxy can be
 * created on either the client or server side of the tunnel.
 *
 * Returns: Proxy state on success, ERR_PTR on failure.
 */
struct tquic_quic_proxy_state *tquic_quic_proxy_init(
	struct tquic_connect_udp_tunnel *tunnel,
	const struct tquic_quic_proxy_config *config,
	bool is_server);

/**
 * tquic_quic_proxy_destroy - Destroy QUIC proxy state
 * @proxy: Proxy state to destroy
 *
 * Tears down all proxied connections and releases resources.
 */
void tquic_quic_proxy_destroy(struct tquic_quic_proxy_state *proxy);

/**
 * tquic_quic_proxy_get - Increment proxy reference count
 * @proxy: Proxy to reference
 */
void tquic_quic_proxy_get(struct tquic_quic_proxy_state *proxy);

/**
 * tquic_quic_proxy_put - Decrement proxy reference count
 * @proxy: Proxy to dereference
 */
void tquic_quic_proxy_put(struct tquic_quic_proxy_state *proxy);

/*
 * =============================================================================
 * CONNECTION REGISTRATION API
 * =============================================================================
 */

/**
 * tquic_quic_proxy_register_conn - Register a proxied QUIC connection
 * @proxy: Proxy state
 * @target_host: Target hostname or IP
 * @target_port: Target UDP port
 * @initial_dcid: Initial destination CID
 * @dcid_len: DCID length
 * @initial_scid: Initial source CID (may be NULL)
 * @scid_len: SCID length
 * @version: QUIC version
 * @flags: Registration flags
 *
 * Registers a new proxied QUIC connection. The proxy will begin
 * forwarding packets for this connection.
 *
 * Returns: Proxied connection on success, ERR_PTR on failure.
 */
struct tquic_proxied_quic_conn *tquic_quic_proxy_register_conn(
	struct tquic_quic_proxy_state *proxy,
	const char *target_host,
	u16 target_port,
	const u8 *initial_dcid,
	u8 dcid_len,
	const u8 *initial_scid,
	u8 scid_len,
	u32 version,
	u8 flags);

/**
 * tquic_quic_proxy_deregister_conn - Deregister a proxied connection
 * @pconn: Proxied connection
 * @reason: Deregistration reason
 * @drain_ms: Draining period in milliseconds
 *
 * Initiates deregistration of a proxied connection. If drain_ms > 0,
 * the connection enters draining state before being removed.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_quic_proxy_deregister_conn(
	struct tquic_proxied_quic_conn *pconn,
	u8 reason,
	u32 drain_ms);

/**
 * tquic_quic_proxy_find_conn - Find proxied connection by ID
 * @proxy: Proxy state
 * @conn_id: Connection identifier
 *
 * Returns: Proxied connection (refcount incremented) or NULL.
 */
struct tquic_proxied_quic_conn *tquic_quic_proxy_find_conn(
	struct tquic_quic_proxy_state *proxy,
	u64 conn_id);

/**
 * tquic_quic_proxy_find_conn_by_cid - Find proxied connection by DCID
 * @proxy: Proxy state
 * @dcid: Destination connection ID
 * @dcid_len: DCID length
 *
 * Returns: Proxied connection (refcount incremented) or NULL.
 */
struct tquic_proxied_quic_conn *tquic_quic_proxy_find_conn_by_cid(
	struct tquic_quic_proxy_state *proxy,
	const u8 *dcid,
	u8 dcid_len);

/*
 * =============================================================================
 * PACKET FORWARDING API
 * =============================================================================
 */

/**
 * tquic_quic_proxy_forward_packet - Forward a QUIC packet
 * @pconn: Proxied connection
 * @packet: QUIC packet data
 * @len: Packet length
 * @direction: Forwarding direction
 *
 * Forwards a QUIC packet through the proxy. The packet may be
 * modified (header compression, CID rewriting) based on configuration.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_quic_proxy_forward_packet(
	struct tquic_proxied_quic_conn *pconn,
	const u8 *packet,
	size_t len,
	u8 direction);

/**
 * tquic_quic_proxy_forward_packet_capsule - Forward packet via capsule
 * @proxy: Proxy state
 * @capsule: Packet capsule
 *
 * Processes a received QUIC_PROXY_PACKET capsule and forwards
 * the contained QUIC packet.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_quic_proxy_forward_packet_capsule(
	struct tquic_quic_proxy_state *proxy,
	const struct quic_proxy_packet_capsule *capsule);

/*
 * =============================================================================
 * CID COOPERATION API
 * =============================================================================
 */

/**
 * tquic_quic_proxy_cid_cooperation - Process CID cooperation
 * @pconn: Proxied connection
 * @capsule: CID capsule
 *
 * Handles CID coordination between client, proxy, and target.
 * Updates the connection's CID state based on the capsule.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_quic_proxy_cid_cooperation(
	struct tquic_proxied_quic_conn *pconn,
	const struct quic_proxy_cid_capsule *capsule);

/**
 * tquic_quic_proxy_add_cid - Add a connection ID
 * @pconn: Proxied connection
 * @cid: Connection ID bytes
 * @cid_len: CID length
 * @seq_num: Sequence number
 * @retire_prior_to: Retire prior CIDs
 * @reset_token: Stateless reset token (may be NULL)
 * @direction: CID direction
 *
 * Adds a new connection ID to the proxied connection.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_quic_proxy_add_cid(
	struct tquic_proxied_quic_conn *pconn,
	const u8 *cid,
	u8 cid_len,
	u64 seq_num,
	u64 retire_prior_to,
	const u8 *reset_token,
	u8 direction);

/**
 * tquic_quic_proxy_retire_cid - Retire a connection ID
 * @pconn: Proxied connection
 * @seq_num: Sequence number to retire
 * @direction: CID direction
 *
 * Retires a connection ID by sequence number.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_quic_proxy_retire_cid(
	struct tquic_proxied_quic_conn *pconn,
	u64 seq_num,
	u8 direction);

/**
 * tquic_quic_proxy_request_cid - Request a new connection ID
 * @pconn: Proxied connection
 * @direction: CID direction
 *
 * Requests a new connection ID from the peer.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_quic_proxy_request_cid(
	struct tquic_proxied_quic_conn *pconn,
	u8 direction);

/*
 * =============================================================================
 * HEADER COMPRESSION API
 * =============================================================================
 */

/**
 * tquic_quic_proxy_header_compress - Compress QUIC header
 * @pconn: Proxied connection
 * @packet: Input packet
 * @packet_len: Input packet length
 * @output: Output buffer
 * @output_len: Output buffer size
 * @compressed_len: Output compressed length
 * @compress_index: Output compression index used
 *
 * Compresses the QUIC packet header using the connection's
 * compression context.
 *
 * Returns: 0 on success (check compressed_len), negative errno on failure.
 */
int tquic_quic_proxy_header_compress(
	struct tquic_proxied_quic_conn *pconn,
	const u8 *packet,
	size_t packet_len,
	u8 *output,
	size_t output_len,
	size_t *compressed_len,
	u8 *compress_index);

/**
 * tquic_quic_proxy_header_decompress - Decompress QUIC header
 * @pconn: Proxied connection
 * @compressed: Compressed header data
 * @compressed_len: Compressed data length
 * @compress_index: Compression index
 * @payload: Remaining packet payload
 * @payload_len: Payload length
 * @output: Output buffer
 * @output_len: Output buffer size
 * @packet_len: Output decompressed packet length
 *
 * Decompresses a QUIC packet header using the connection's
 * compression context.
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_quic_proxy_header_decompress(
	struct tquic_proxied_quic_conn *pconn,
	const u8 *compressed,
	size_t compressed_len,
	u8 compress_index,
	const u8 *payload,
	size_t payload_len,
	u8 *output,
	size_t output_len,
	size_t *packet_len);

/*
 * =============================================================================
 * CAPSULE ENCODING/DECODING API
 * =============================================================================
 */

/* Declared in quic_proxy_capsules.c */
int quic_proxy_encode_register(
	const struct quic_proxy_register_capsule *capsule,
	u8 *buf, size_t buf_len);

int quic_proxy_decode_register(
	const u8 *buf, size_t buf_len,
	struct quic_proxy_register_capsule *capsule);

int quic_proxy_encode_cid(
	const struct quic_proxy_cid_capsule *capsule,
	u8 *buf, size_t buf_len);

int quic_proxy_decode_cid(
	const u8 *buf, size_t buf_len,
	struct quic_proxy_cid_capsule *capsule);

int quic_proxy_encode_packet(
	const struct quic_proxy_packet_capsule *capsule,
	u8 *buf, size_t buf_len);

int quic_proxy_decode_packet(
	const u8 *buf, size_t buf_len,
	struct quic_proxy_packet_capsule *capsule);

int quic_proxy_encode_deregister(
	const struct quic_proxy_deregister_capsule *capsule,
	u8 *buf, size_t buf_len);

int quic_proxy_decode_deregister(
	const u8 *buf, size_t buf_len,
	struct quic_proxy_deregister_capsule *capsule);

int quic_proxy_encode_error(
	const struct quic_proxy_error_capsule *capsule,
	u8 *buf, size_t buf_len);

int quic_proxy_decode_error(
	const u8 *buf, size_t buf_len,
	struct quic_proxy_error_capsule *capsule);

/*
 * =============================================================================
 * STATISTICS AND DEBUGGING
 * =============================================================================
 */

/**
 * tquic_quic_proxy_get_stats - Get proxy statistics
 * @proxy: Proxy state
 * @stats: Output statistics
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_quic_proxy_get_stats(
	struct tquic_quic_proxy_state *proxy,
	struct tquic_quic_proxy_stats *stats);

/**
 * tquic_quic_proxy_get_conn_stats - Get per-connection statistics
 * @pconn: Proxied connection
 * @tx_packets: Output TX packets
 * @rx_packets: Output RX packets
 * @tx_bytes: Output TX bytes
 * @rx_bytes: Output RX bytes
 *
 * Returns: 0 on success, negative errno on failure.
 */
int tquic_quic_proxy_get_conn_stats(
	struct tquic_proxied_quic_conn *pconn,
	u64 *tx_packets, u64 *rx_packets,
	u64 *tx_bytes, u64 *rx_bytes);

/*
 * =============================================================================
 * MODULE INITIALIZATION
 * =============================================================================
 */

int __init tquic_quic_proxy_init_module(void);
void __exit tquic_quic_proxy_exit_module(void);

#endif /* _TQUIC_MASQUE_QUIC_PROXY_H */
