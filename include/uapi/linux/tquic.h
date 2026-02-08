/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * TQUIC: WAN Bonding over QUIC - User API
 *
 * Copyright (c) 2026 Linux Foundation
 */

#ifndef _UAPI_LINUX_TQUIC_H
#define _UAPI_LINUX_TQUIC_H

#include <linux/types.h>
#include <linux/socket.h>
#include <linux/in.h>

/*
 * Protocol number for TQUIC sockets is defined in <linux/in.h> as IPPROTO_TQUIC.
 *
 * In this tree, TQUIC uses a classic 8-bit IP protocol number (253).
 */

/* Socket options at SOL_TQUIC level */
#define SOL_TQUIC	288

/* TQUIC socket options */
#define TQUIC_NODELAY		1   /* Disable Nagle algorithm */
#define TQUIC_MAXSEG		2   /* Maximum segment size */
#define TQUIC_CORK		3   /* Cork data before sending */
#define TQUIC_KEEPIDLE		4   /* Idle time before keepalive */
#define TQUIC_KEEPINTVL		5   /* Keepalive interval */
#define TQUIC_KEEPCNT		6   /* Keepalive probe count */
#define TQUIC_INFO		7   /* Connection info (read-only) */
#define TQUIC_CONGESTION	8   /* Congestion control algorithm */
#define TQUIC_SCHEDULER		9   /* Path scheduler algorithm */

/*
 * SO_TQUIC_SCHEDULER - Set scheduler name before connect()
 *
 * Used with setsockopt(SOL_TQUIC, SO_TQUIC_SCHEDULER, name, len).
 * The value is a null-terminated string naming the scheduler.
 *
 * Per CONTEXT.md: Scheduler is locked at connection establishment
 * and cannot be changed mid-connection. Setting after connect()
 * returns -EISCONN.
 *
 * Available schedulers can be queried via /proc/net/tquic/schedulers.
 */
#define SO_TQUIC_SCHEDULER	TQUIC_SCHEDULER

/*
 * SO_TQUIC_CONGESTION - Set congestion control algorithm before connect()
 *
 * Used with setsockopt(SOL_TQUIC, SO_TQUIC_CONGESTION, name, len).
 * The value is a null-terminated string naming the CC algorithm.
 *
 * Per CONTEXT.md: Each path can use different CC algorithms.
 * This sockopt sets the preferred CC for the connection; individual
 * paths may use different algorithms based on RTT-based auto-selection:
 *   - High-RTT paths (>= bbr_rtt_threshold_ms) auto-select BBR
 *   - Other paths use this preference or the per-netns default
 *
 * Available algorithms: cubic (default), bbr, reno
 * Set "auto" to enable automatic selection per path.
 */
#define SO_TQUIC_CONGESTION	TQUIC_CONGESTION

/*
 * SO_TQUIC_PACING - Enable/disable pacing for socket
 *
 * Used with setsockopt(SOL_TQUIC, SO_TQUIC_PACING, &val, sizeof(val)).
 * The value is an int: 1 = enable pacing, 0 = disable pacing.
 *
 * Pacing is enabled by default per CONTEXT.md. When enabled, TQUIC
 * integrates with FQ qdisc for hardware pacing when available, or
 * uses internal software pacing otherwise.
 */
#define TQUIC_PACING		10  /* Enable/disable pacing for socket */
#define SO_TQUIC_PACING		TQUIC_PACING

#define TQUIC_IDLE_TIMEOUT	11  /* Idle timeout in ms */
#define TQUIC_MAX_DATA		12  /* Maximum data per connection */
#define TQUIC_MAX_STREAM_DATA	13  /* Maximum data per stream */
#define TQUIC_MAX_STREAMS_BIDI	14  /* Maximum bidirectional streams */
#define TQUIC_MAX_STREAMS_UNI	15  /* Maximum unidirectional streams */
#define TQUIC_ACK_DELAY		16  /* Maximum ACK delay in ms */
#define TQUIC_MIGRATION		17  /* Enable/disable connection migration */
#define TQUIC_MULTIPATH		18  /* Enable/disable multipath */
#define TQUIC_PATH_STATUS	19  /* Path status (bonding) */
#define TQUIC_ACTIVE_PATH	20  /* Set active path (bonding) */
#define TQUIC_ZEROCOPY		21  /* Enable zero-copy send */
#define TQUIC_PSK_IDENTITY	22  /* PSK identity for authentication */

/*
 * SO_TQUIC_ZEROCOPY - Enable/disable zero-copy I/O
 *
 * Used with setsockopt(SOL_TQUIC, SO_TQUIC_ZEROCOPY, &val, sizeof(val)).
 * The value is an int: 1 = enable zero-copy, 0 = disable zero-copy.
 *
 * When enabled:
 *   - sendmsg() with MSG_ZEROCOPY maps user pages directly into skbs
 *     without copying, completion notification via error queue
 *   - sendfile() uses page references instead of copying
 *   - splice() provides zero-copy data transfer to/from pipes
 *
 * Zero-copy completion notification:
 *   - SO_EE_ORIGIN_ZEROCOPY messages on socket error queue
 *   - ee_data/ee_info contain the notification ID range
 *   - ee_code & SO_EE_CODE_ZEROCOPY_COPIED indicates copy fallback
 *
 * Requirements:
 *   - For best performance, NIC should support scatter-gather (NETIF_F_SG)
 *   - Without SG, fallback to copy with completion notification
 */
#define SO_TQUIC_ZEROCOPY	TQUIC_ZEROCOPY

/*
 * SO_TQUIC_PSK_IDENTITY - Set PSK identity for connection
 *
 * Used with setsockopt(SOL_TQUIC, SO_TQUIC_PSK_IDENTITY, identity, len).
 * The value is a null-terminated string identifying the PSK (up to 64 bytes).
 *
 * For server sockets: Configures PSK database entry (identity -> PSK mapping)
 * For client sockets: Sets PSK identity to send in ClientHello
 *
 * Identity length must be 1-64 bytes.
 */
#define SO_TQUIC_PSK_IDENTITY	TQUIC_PSK_IDENTITY

/* Maximum PSK identity length */
#define TQUIC_MAX_PSK_IDENTITY_LEN	64

/*
 * Certificate Verification Socket Options
 *
 * These options control TLS certificate chain validation behavior.
 * Must be set before connect() for client sockets.
 */

/* Certificate verification mode */
#define TQUIC_CERT_VERIFY_MODE		30
#define SO_TQUIC_CERT_VERIFY_MODE	TQUIC_CERT_VERIFY_MODE

/* Expected hostname for SNI/certificate matching */
#define TQUIC_EXPECTED_HOSTNAME		31
#define SO_TQUIC_EXPECTED_HOSTNAME	TQUIC_EXPECTED_HOSTNAME

/* Allow self-signed certificates (DANGEROUS - testing only) */
#define TQUIC_ALLOW_SELF_SIGNED		32
#define SO_TQUIC_ALLOW_SELF_SIGNED	TQUIC_ALLOW_SELF_SIGNED

/**
 * Certificate verification modes for TQUIC_CERT_VERIFY_MODE
 *
 * @TQUIC_VERIFY_NONE: No certificate verification (INSECURE)
 *                     Only use for testing in controlled environments
 * @TQUIC_VERIFY_OPTIONAL: Verify if certificate present, allow missing
 *                         Useful for opportunistic encryption
 * @TQUIC_VERIFY_REQUIRED: Full verification required (default)
 *                         Recommended for production use
 */
#define TQUIC_VERIFY_NONE		0
#define TQUIC_VERIFY_OPTIONAL		1
#define TQUIC_VERIFY_REQUIRED		2

/* Maximum expected hostname length */
#define TQUIC_MAX_HOSTNAME_LEN		255

/**
 * struct tquic_cert_verify_args - Certificate verification configuration
 * @verify_mode: Verification mode (TQUIC_VERIFY_*)
 * @allow_self_signed: Allow self-signed certs (0 = no, 1 = yes)
 * @verify_hostname: Verify hostname matches cert (0 = no, 1 = yes)
 * @reserved: Reserved, must be 0
 *
 * Used with getsockopt(TQUIC_CERT_VERIFY_MODE) to query current settings.
 * Individual fields can be set via separate setsockopt calls.
 */
struct tquic_cert_verify_args {
	__u8	verify_mode;
	__u8	allow_self_signed;
	__u8	verify_hostname;
	__u8	reserved;
};

/* WAN Bonding specific socket options */
#define TQUIC_BOND_MODE		50  /* Bonding mode */
#define TQUIC_BOND_ADD_PATH	51  /* Add a path to bond */
#define TQUIC_BOND_DEL_PATH	52  /* Remove a path from bond */
#define TQUIC_BOND_PATH_PRIO	53  /* Set path priority */
#define TQUIC_BOND_PATH_WEIGHT	54  /* Set path weight */
#define TQUIC_BOND_FAILOVER	55  /* Failover configuration */
#define TQUIC_BOND_PRIMARY	56  /* Set primary path */
#define TQUIC_BOND_STATS	57  /* Get bonding statistics */
#define TQUIC_BOND_REORDER_WIN	58  /* Reorder window size */
#define TQUIC_BOND_AGGR_MODE	59  /* Aggregation mode */

/* Stream-level options (via ancillary data) */
#define TQUIC_STREAM_ID		100
#define TQUIC_STREAM_PRIORITY	101
#define TQUIC_STREAM_RESET	102
#define TQUIC_STREAM_FIN	103

/* Bonding modes */
#define TQUIC_BOND_MODE_NONE		0  /* Single path only */
#define TQUIC_BOND_MODE_FAILOVER	1  /* Active-backup failover */
#define TQUIC_BOND_MODE_ROUNDROBIN	2  /* Round-robin scheduling */
#define TQUIC_BOND_MODE_WEIGHTED	3  /* Weighted scheduling */
#define TQUIC_BOND_MODE_MINRTT		4  /* Minimum RTT selection */
#define TQUIC_BOND_MODE_REDUNDANT	5  /* Send on all paths */
#define TQUIC_BOND_MODE_AGGREGATE	6  /* True bandwidth aggregation */
#define TQUIC_BOND_MODE_BLEST		7  /* BLEST scheduler */
#define TQUIC_BOND_MODE_ECF		8  /* Earliest completion first */

/* Aggregation modes for true bonding */
#define TQUIC_AGGR_PACKET	0  /* Packet-level striping */
#define TQUIC_AGGR_STREAM	1  /* Stream-level distribution */
#define TQUIC_AGGR_HYBRID	2  /* Adaptive hybrid */

/* Path states (visible to userspace) */
#define TQUIC_PATH_STATE_UNUSED		0
#define TQUIC_PATH_STATE_PENDING	1
#define TQUIC_PATH_STATE_ACTIVE		2
#define TQUIC_PATH_STATE_STANDBY	3
#define TQUIC_PATH_STATE_FAILED		4

/* Failover settings */
#define TQUIC_FAILOVER_IMMEDIATE	0  /* Immediate failover */
#define TQUIC_FAILOVER_DEFERRED		1  /* Wait for confirmation */
#define TQUIC_FAILOVER_MANUAL		2  /* Manual failover only */

/* Maximum values */
#define TQUIC_MAX_PATHS_USER		16
#define TQUIC_MAX_CONG_NAME		16
#define TQUIC_MAX_SCHED_NAME		16

/**
 * struct tquic_info - Connection information
 * @state: Connection state
 * @version: QUIC version
 * @rtt: Smoothed RTT in microseconds
 * @rtt_var: RTT variance in microseconds
 * @cwnd: Congestion window
 * @bytes_sent: Total bytes sent
 * @bytes_received: Total bytes received
 * @packets_sent: Total packets sent
 * @packets_received: Total packets received
 * @packets_lost: Total packets lost
 * @streams_active: Number of active streams
 * @paths_active: Number of active paths (bonding)
 * @idle_timeout: Idle timeout in ms
 */
struct tquic_info {
	__u8	state;
	__u8	paths_active;
	__u16	streams_active;
	__u32	version;
	__u32	rtt;
	__u32	rtt_var;
	__u32	cwnd;
	__u32	idle_timeout;
	__u64	bytes_sent;
	__u64	bytes_received;
	__u64	packets_sent;
	__u64	packets_received;
	__u64	packets_lost;
};

/**
 * struct tquic_path_info - Path information for WAN bonding
 * @path_id: Path identifier
 * @state: Path state
 * @priority: Path priority (0 = highest)
 * @weight: Weight for weighted scheduling
 * @mtu: Path MTU
 * @rtt: Smoothed RTT in microseconds
 * @rtt_var: RTT variance
 * @bandwidth: Estimated bandwidth in bytes/sec
 * @cwnd: Congestion window
 * @bytes_sent: Bytes sent on this path
 * @bytes_received: Bytes received on this path
 * @packets_lost: Packets lost on this path
 * @local_addr: Local address
 * @remote_addr: Remote address
 */
struct tquic_path_info {
	__u32	path_id;
	__u8	state;
	__u8	priority;
	__u8	weight;
	__u8	reserved;
	__u32	mtu;
	__u32	rtt;
	__u32	rtt_var;
	__u64	bandwidth;
	__u32	cwnd;
	__u32	reserved2;
	__u64	bytes_sent;
	__u64	bytes_received;
	__u64	packets_lost;
	struct sockaddr_storage local_addr;
	struct sockaddr_storage remote_addr;
};

/**
 * struct tquic_bond_config - Bonding configuration
 * @mode: Bonding mode
 * @aggr_mode: Aggregation mode
 * @failover_mode: Failover behavior
 * @reorder_window: Reorder buffer size in packets
 * @probe_interval: Path probe interval in ms
 * @failover_timeout: Failover detection timeout in ms
 */
struct tquic_bond_config {
	__u8	mode;
	__u8	aggr_mode;
	__u8	failover_mode;
	__u8	reserved;
	__u32	reorder_window;
	__u32	probe_interval;
	__u32	failover_timeout;
};

/**
 * struct tquic_add_path - Add path request
 * @local_addr: Local address for the path
 * @remote_addr: Remote address for the path
 * @priority: Initial priority (0 = highest)
 * @weight: Initial weight for weighted scheduling
 * @flags: Path flags
 */
struct tquic_add_path {
	struct sockaddr_storage local_addr;
	struct sockaddr_storage remote_addr;
	__u8	priority;
	__u8	weight;
	__u16	flags;
	__u32	reserved;
};

/* Path flags */
#define TQUIC_PATH_FLAG_BACKUP		(1 << 0)  /* Backup path only */
#define TQUIC_PATH_FLAG_NOVALIDATE	(1 << 1)  /* Skip validation */
#define TQUIC_PATH_FLAG_PREFERRED	(1 << 2)  /* Preferred path */

/**
 * struct tquic_path_weight_args - Arguments for TQUIC_BOND_PATH_WEIGHT sockopt
 * @path_id: Path identifier (0-7)
 * @weight: Weight value (50-1000, or 0 to clear override)
 * @reserved: Reserved, must be 0
 *
 * Used with setsockopt(TQUIC_BOND_PATH_WEIGHT) to set user-defined
 * path weight for bonding traffic distribution.
 *
 * Weight values:
 *   0: Clear user override, return to automatic derivation
 *   50-1000: User-defined weight (50 = 5%, 1000 = 100%)
 *
 * The minimum weight of 50 (5%) prevents path starvation.
 */
struct tquic_path_weight_args {
	__u8	path_id;
	__u8	reserved[3];
	__u32	weight;
};

/**
 * struct tquic_bond_stats - Bonding statistics
 * @total_paths: Total paths ever added
 * @active_paths: Currently active paths
 * @failed_paths: Paths that have failed
 * @migrations: Number of path migrations
 * @failovers: Number of failover events
 * @reorder_events: Packets reordered
 * @bytes_aggregated: Bytes sent via aggregation
 */
struct tquic_bond_stats {
	__u32	total_paths;
	__u32	active_paths;
	__u32	failed_paths;
	__u32	standby_paths;
	__u64	migrations;
	__u64	failovers;
	__u64	reorder_events;
	__u64	bytes_aggregated;
};

/* Netlink interface */
#define TQUIC_GENL_NAME		"TQUIC"
#define TQUIC_GENL_VERSION	1

/* Netlink commands */
enum {
	TQUIC_CMD_UNSPEC,
	TQUIC_CMD_GET_CONN,	/* Get connection info */
	TQUIC_CMD_SET_CONN,	/* Modify connection */
	TQUIC_CMD_GET_PATH,	/* Get path info */
	TQUIC_CMD_ADD_PATH,	/* Add bonding path */
	TQUIC_CMD_DEL_PATH,	/* Remove bonding path */
	TQUIC_CMD_SET_PATH,	/* Modify path */
	TQUIC_CMD_GET_STATS,	/* Get statistics */
	TQUIC_CMD_SET_BOND,	/* Configure bonding */
	TQUIC_CMD_MIGRATE,	/* Trigger migration */
	TQUIC_CMD_NEW_CONN,	/* New connection notification */
	TQUIC_CMD_DEL_CONN,	/* Connection closed notification */
	TQUIC_CMD_PATH_EVENT,	/* Path state change notification */
	__TQUIC_CMD_MAX,
};
#define TQUIC_CMD_MAX (__TQUIC_CMD_MAX - 1)

/* Netlink attributes */
enum {
	TQUIC_ATTR_UNSPEC,
	TQUIC_ATTR_CONN_ID,	/* Connection identifier */
	TQUIC_ATTR_PATH_ID,	/* Path identifier */
	TQUIC_ATTR_LOCAL_ADDR,	/* Local address */
	TQUIC_ATTR_REMOTE_ADDR,	/* Remote address */
	TQUIC_ATTR_STATE,	/* State */
	TQUIC_ATTR_PRIORITY,	/* Priority */
	TQUIC_ATTR_WEIGHT,	/* Weight */
	TQUIC_ATTR_RTT,		/* RTT in microseconds */
	TQUIC_ATTR_BANDWIDTH,	/* Bandwidth in bytes/sec */
	TQUIC_ATTR_CWND,	/* Congestion window */
	TQUIC_ATTR_BYTES_SENT,	/* Bytes sent */
	TQUIC_ATTR_BYTES_RECV,	/* Bytes received */
	TQUIC_ATTR_PACKETS_LOST,/* Packets lost */
	TQUIC_ATTR_BOND_MODE,	/* Bonding mode */
	TQUIC_ATTR_BOND_CONFIG,	/* Full bond config */
	TQUIC_ATTR_PATH_INFO,	/* Full path info */
	TQUIC_ATTR_CONN_INFO,	/* Full connection info */
	TQUIC_ATTR_BOND_STATS,	/* Bonding statistics */
	TQUIC_ATTR_FLAGS,	/* Flags */
	TQUIC_ATTR_EVENT,	/* Event type */
	TQUIC_ATTR_PAD,
	__TQUIC_ATTR_MAX,
};
#define TQUIC_ATTR_MAX (__TQUIC_ATTR_MAX - 1)

/* Path events (for netlink notifications) */
enum tquic_path_event {
	TQUIC_PATH_EVENT_ADD,
	TQUIC_PATH_EVENT_REMOVE,
	TQUIC_PATH_EVENT_ACTIVE,
	TQUIC_PATH_EVENT_STANDBY,
	TQUIC_PATH_EVENT_FAILED,
	TQUIC_PATH_EVENT_RECOVERED,
	TQUIC_PATH_EVENT_MIGRATE,
};

/* Multicast groups */
enum tquic_nl_groups {
	TQUIC_NL_GRP_NONE,
	TQUIC_NL_GRP_CONN,	/* Connection events */
	TQUIC_NL_GRP_PATH,	/* Path events */
	__TQUIC_NL_GRP_MAX,
};
#define TQUIC_NL_GRP_MAX (__TQUIC_NL_GRP_MAX - 1)

/*
 * QUIC-native error codes (EQUIC*)
 *
 * These map to RFC 9000 QUIC Transport Error Codes.
 * They are returned via errno and provide QUIC-specific
 * error semantics rather than TCP-like mappings.
 *
 * Base value starts at 500 to avoid collision with standard errno.
 */
#define EQUIC_BASE			500

/* Transport errors (RFC 9000 Section 20.1) */
#define EQUIC_NO_ERROR			(EQUIC_BASE + 0x00)  /* 0x00 */
#define EQUIC_INTERNAL_ERROR		(EQUIC_BASE + 0x01)  /* 0x01 */
#define EQUIC_CONNECTION_REFUSED	(EQUIC_BASE + 0x02)  /* 0x02 */
#define EQUIC_FLOW_CONTROL		(EQUIC_BASE + 0x03)  /* 0x03 */
#define EQUIC_STREAM_LIMIT		(EQUIC_BASE + 0x04)  /* 0x04 */
#define EQUIC_STREAM_STATE		(EQUIC_BASE + 0x05)  /* 0x05 */
#define EQUIC_FINAL_SIZE		(EQUIC_BASE + 0x06)  /* 0x06 */
#define EQUIC_FRAME_ENCODING		(EQUIC_BASE + 0x07)  /* 0x07 */
#define EQUIC_TRANSPORT_PARAM		(EQUIC_BASE + 0x08)  /* 0x08 */
#define EQUIC_CONNECTION_ID_LIMIT	(EQUIC_BASE + 0x09)  /* 0x09 */
#define EQUIC_PROTOCOL_VIOLATION	(EQUIC_BASE + 0x0a)  /* 0x0a */
#define EQUIC_INVALID_TOKEN		(EQUIC_BASE + 0x0b)  /* 0x0b */
#define EQUIC_APPLICATION_ERROR		(EQUIC_BASE + 0x0c)  /* 0x0c */
#define EQUIC_CRYPTO_BUFFER		(EQUIC_BASE + 0x0d)  /* 0x0d */
#define EQUIC_KEY_UPDATE		(EQUIC_BASE + 0x0e)  /* 0x0e */
#define EQUIC_AEAD_LIMIT		(EQUIC_BASE + 0x0f)  /* 0x0f */
#define EQUIC_NO_VIABLE_PATH		(EQUIC_BASE + 0x10)  /* 0x10 */

/* Crypto errors (0x100 + TLS alert) */
#define EQUIC_CRYPTO_BASE		(EQUIC_BASE + 0x100)
#define EQUIC_HANDSHAKE_FAILED		(EQUIC_CRYPTO_BASE + 0x00)  /* Generic handshake failure */
#define EQUIC_CERT_EXPIRED		(EQUIC_CRYPTO_BASE + 0x2d)  /* Certificate expired (alert 45) */
#define EQUIC_CERT_REVOKED		(EQUIC_CRYPTO_BASE + 0x2c)  /* Certificate revoked (alert 44) */
#define EQUIC_UNKNOWN_CA		(EQUIC_CRYPTO_BASE + 0x30)  /* Unknown CA (alert 48) */
#define EQUIC_HANDSHAKE_TIMEOUT		(EQUIC_CRYPTO_BASE + 0xff)  /* Handshake timeout */

/* Connection timeout (fixed per CONTEXT.md) */
#define TQUIC_HANDSHAKE_TIMEOUT_MS	30000  /* Fixed 30 second timeout */

/*
 * Connection Migration Socket Options
 *
 * Note: Full migration implementation in Phase 4 (Path Manager).
 * Migration is implemented in-kernel; these sockopts are part of the userspace
 * API.
 */
#define TQUIC_MIGRATE           70  /* Trigger explicit migration to new address */
#define TQUIC_MIGRATE_STATUS    71  /* Get migration status (read-only) */
#define TQUIC_MIGRATION_ENABLED 72  /* Enable/disable automatic migration */

/**
 * struct tquic_migrate_args - Arguments for TQUIC_MIGRATE sockopt
 * @local_addr: New local address to migrate to
 * @flags: Migration flags
 * @reserved: Reserved, must be 0
 *
 * Used with setsockopt(TQUIC_MIGRATE) to trigger explicit migration.
 */
struct tquic_migrate_args {
	struct sockaddr_storage local_addr;
	__u32 flags;
	__u32 reserved;
};

/* Migration flags */
#define TQUIC_MIGRATE_FLAG_PROBE_ONLY  (1 << 0)  /* Only probe, don't switch */
#define TQUIC_MIGRATE_FLAG_FORCE       (1 << 1)  /* Force even if current path ok */

/**
 * enum tquic_migrate_status - Migration state
 */
enum tquic_migrate_status {
	TQUIC_MIGRATE_NONE = 0,      /* No migration in progress */
	TQUIC_MIGRATE_PROBING,       /* PATH_CHALLENGE sent, awaiting response */
	TQUIC_MIGRATE_VALIDATED,     /* New path validated, migration complete */
	TQUIC_MIGRATE_FAILED,        /* Migration failed (timeout, etc.) */
};

/**
 * struct tquic_migrate_info - Migration status information
 * @status: Current migration status
 * @old_path_id: Previous path ID
 * @new_path_id: New path ID (if migrating)
 * @probe_rtt: RTT of PATH_CHALLENGE/RESPONSE (us)
 * @error_code: Error code if failed
 * @reserved: Reserved for alignment
 * @old_local: Previous local address
 * @new_local: New local address
 * @remote: Remote address
 *
 * Used with getsockopt(TQUIC_MIGRATE_STATUS) to poll migration status.
 */
struct tquic_migrate_info {
	__u32 status;
	__u32 old_path_id;
	__u32 new_path_id;
	__u32 probe_rtt;
	__u32 error_code;
	__u32 reserved;
	struct sockaddr_storage old_local;
	struct sockaddr_storage new_local;
	struct sockaddr_storage remote;
};

/*
 * Connection ID limits
 */
#define TQUIC_CID_POOL_MIN          2   /* Minimum CIDs to maintain */
#define TQUIC_CID_POOL_DEFAULT      8   /* Default CID pool size */
#define TQUIC_ACTIVE_CID_LIMIT      8   /* Max active CIDs (transport param) */

/*
 * TQUIC Stream ioctls
 *
 * Use ioctl on connection socket to create stream file descriptors.
 * Stream fds are first-class file descriptors supporting poll/epoll/select.
 *
 * Note: TQUIC uses a streams-only I/O model. sendmsg/recvmsg work on
 * stream sockets, not the connection socket. The connection socket is
 * used for control (connect, listen, accept, stream creation).
 */

/* ioctl magic number for TQUIC */
#define TQUIC_IOC_MAGIC		'Q'

/**
 * struct tquic_stream_args - Arguments for TQUIC_NEW_STREAM ioctl
 * @stream_id: OUT - Assigned stream ID after successful creation
 * @flags: IN - Stream type flags (TQUIC_STREAM_BIDI or TQUIC_STREAM_UNIDI)
 * @reserved: Reserved for future use, must be 0
 *
 * On success, the ioctl returns the new stream's file descriptor.
 * The stream_id field is populated with the assigned QUIC stream ID.
 */
struct tquic_stream_args {
	__u64 stream_id;	/* OUT: assigned stream ID */
	__u32 flags;		/* IN: TQUIC_STREAM_BIDI or TQUIC_STREAM_UNIDI */
	__u32 reserved;		/* Must be 0 */
};

/* Create new stream, returns fd on success */
#define TQUIC_NEW_STREAM	_IOWR(TQUIC_IOC_MAGIC, 1, struct tquic_stream_args)

/* Stream type flags */
#define TQUIC_STREAM_BIDI	0x00	/* Bidirectional stream (default) */
#define TQUIC_STREAM_UNIDI	0x01	/* Unidirectional stream (send-only) */

/* Stream limit sockopt (read-only) */
#define TQUIC_STREAMS_AVAILABLE	60	/* Get number of streams that can be opened */

/*
 * DATAGRAM Frame Support (RFC 9221)
 *
 * QUIC DATAGRAM frames provide unreliable, unordered message delivery
 * over a QUIC connection. Unlike streams, datagrams are not retransmitted
 * on loss and have no ordering guarantees.
 *
 * Use cases:
 *   - Real-time applications (VoIP, gaming, live video)
 *   - Unreliable messaging on top of QUIC
 *   - Tunneling protocols that handle their own reliability
 */

/* Socket option to enable/query DATAGRAM support */
#define TQUIC_SO_DATAGRAM		80	/* Enable DATAGRAM frame support */
#define TQUIC_SO_MAX_DATAGRAM_SIZE	81	/* Get max datagram size (read-only) */
#define TQUIC_SO_DATAGRAM_QUEUE_LEN	82	/* Get/set datagram queue length */
#define TQUIC_SO_DATAGRAM_STATS		83	/* Get datagram statistics (read-only) */
#define TQUIC_SO_DATAGRAM_RCVBUF	84	/* Get/set datagram receive buffer size */

/**
 * struct tquic_datagram_info - DATAGRAM frame ancillary data
 * @dgram_id: Application-provided datagram identifier (for tracking)
 * @flags: Datagram flags (reserved for future use)
 *
 * This structure is passed via cmsg with sendmsg/recvmsg to
 * distinguish datagram messages from stream data.
 *
 * Usage:
 *   - sendmsg: Use TQUIC_CMSG_DATAGRAM with this struct
 *   - recvmsg: Receive this struct via cmsg when reading datagrams
 */
struct tquic_datagram_info {
	__u64 dgram_id;		/* Application datagram identifier */
	__u32 flags;		/* Reserved, must be 0 */
	__u32 reserved;		/* Reserved for alignment */
};

/* cmsg type for DATAGRAM frames */
#define TQUIC_CMSG_DATAGRAM	200	/* Ancillary data indicates DATAGRAM */

/* Datagram flags (for future use) */
#define TQUIC_DGRAM_FLAG_NONE		0x00

/* Default and limits for datagram queue */
#define TQUIC_DATAGRAM_QUEUE_DEFAULT	256
#define TQUIC_DATAGRAM_QUEUE_MAX	4096

/* Maximum datagram frame size (excluding QUIC header overhead) */
#define TQUIC_MAX_DATAGRAM_SIZE		65527

/**
 * struct tquic_datagram_stats - DATAGRAM frame statistics
 * @datagrams_sent: Total datagrams sent successfully
 * @datagrams_received: Total datagrams received and delivered to application
 * @datagrams_dropped: Datagrams dropped due to queue full or allocation failure
 * @recv_queue_len: Current number of datagrams in receive queue
 * @recv_queue_max: Maximum receive queue depth
 * @max_send_size: Maximum datagram size we can send (peer's limit)
 * @max_recv_size: Maximum datagram size we accept (our limit)
 *
 * Used with getsockopt(TQUIC_SO_DATAGRAM_STATS) to query datagram statistics.
 */
struct tquic_datagram_stats {
	__u64 datagrams_sent;		/* Datagrams sent */
	__u64 datagrams_received;	/* Datagrams received */
	__u64 datagrams_dropped;	/* Datagrams dropped (queue full/alloc fail) */
	__u32 recv_queue_len;		/* Current queue depth */
	__u32 recv_queue_max;		/* Maximum queue depth */
	__u64 max_send_size;		/* Max size we can send */
	__u64 max_recv_size;		/* Max size we accept */
};

/*
 * HTTP/3 Support (RFC 9114)
 *
 * When HTTP/3 mode is enabled, QUIC streams follow HTTP/3 semantics:
 *   - Bidirectional streams: Request/response pairs
 *   - Unidirectional streams: Control, Push, QPACK streams
 *
 * Stream type mapping:
 *   - Client-initiated bidi (0, 4, 8, ...): Request streams
 *   - Server-initiated uni: Control (0x00), Push (0x01), QPACK (0x02, 0x03)
 *
 * Frame types are enforced per stream:
 *   - Control stream: SETTINGS, GOAWAY, MAX_PUSH_ID only
 *   - Request stream: HEADERS, DATA, PUSH_PROMISE only
 */

/* Socket option to enable HTTP/3 mode */
#define TQUIC_SO_HTTP3_ENABLE			90	/* Enable HTTP/3 semantics */
#define TQUIC_SO_HTTP3_SETTINGS			91	/* Set HTTP/3 settings */
#define TQUIC_SO_HTTP3_MAX_TABLE_CAPACITY	92	/* QPACK max table capacity */
#define TQUIC_SO_HTTP3_MAX_FIELD_SECTION_SIZE	93	/* Max header field section size */
#define TQUIC_SO_HTTP3_BLOCKED_STREAMS		94	/* QPACK blocked streams */
#define TQUIC_SO_HTTP3_SERVER_PUSH		95	/* Enable server push */
#define TQUIC_SO_HTTP3_STREAM_INFO		96	/* Get stream info (read-only) */

/* Aliases for backward compatibility */
#define TQUIC_SO_HTTP3_QPACK_MAX_CAP	TQUIC_SO_HTTP3_MAX_TABLE_CAPACITY
#define TQUIC_SO_HTTP3_MAX_FIELD_SIZE	TQUIC_SO_HTTP3_MAX_FIELD_SECTION_SIZE
#define TQUIC_SO_HTTP3_QPACK_BLOCKED	TQUIC_SO_HTTP3_BLOCKED_STREAMS

/* HTTP/3 default values */
#define TQUIC_HTTP3_DEFAULT_TABLE_CAPACITY	4096
#define TQUIC_HTTP3_DEFAULT_FIELD_SECTION_SIZE	16384
#define TQUIC_HTTP3_DEFAULT_BLOCKED_STREAMS	100

/* HTTP/3 maximum values */
#define TQUIC_HTTP3_MAX_TABLE_CAPACITY_MAX	65536
#define TQUIC_HTTP3_MAX_BLOCKED_STREAMS_MAX	1000

/**
 * struct tquic_http3_settings - HTTP/3 SETTINGS parameters
 * @max_table_capacity: Maximum QPACK dynamic table capacity (bytes)
 * @max_field_section_size: Maximum compressed header field section size (bytes)
 * @max_blocked_streams: Maximum blocked QPACK streams
 * @enable_push: Enable server push (0 = disabled, 1 = enabled)
 * @reserved: Reserved for alignment
 *
 * Used with setsockopt(TQUIC_SO_HTTP3_SETTINGS) to configure HTTP/3 params.
 * Must be set before connect() or handshake completion.
 *
 * Defaults:
 *   max_table_capacity: 4096 bytes
 *   max_field_section_size: 16384 bytes
 *   max_blocked_streams: 100
 *   enable_push: 0 (disabled)
 */
struct tquic_http3_settings {
	__u32 max_table_capacity;
	__u32 max_field_section_size;
	__u32 max_blocked_streams;
	__u32 enable_push;
	__u32 reserved;
	__u32 reserved2;
};

/*
 * HTTP/3 Error Codes (RFC 9114 Section 8.1)
 *
 * These error codes are used in CONNECTION_CLOSE frames and
 * RESET_STREAM/STOP_SENDING frames for HTTP/3 connections.
 */
#define TQUIC_H3_NO_ERROR			0x100
#define TQUIC_H3_GENERAL_PROTOCOL_ERROR		0x101
#define TQUIC_H3_INTERNAL_ERROR			0x102
#define TQUIC_H3_STREAM_CREATION_ERROR		0x103
#define TQUIC_H3_CLOSED_CRITICAL_STREAM		0x104
#define TQUIC_H3_FRAME_UNEXPECTED		0x105
#define TQUIC_H3_FRAME_ERROR			0x106
#define TQUIC_H3_EXCESSIVE_LOAD			0x107
#define TQUIC_H3_ID_ERROR			0x108
#define TQUIC_H3_SETTINGS_ERROR			0x109
#define TQUIC_H3_MISSING_SETTINGS		0x10a
#define TQUIC_H3_REQUEST_REJECTED		0x10b
#define TQUIC_H3_REQUEST_CANCELLED		0x10c
#define TQUIC_H3_REQUEST_INCOMPLETE		0x10d
#define TQUIC_H3_MESSAGE_ERROR			0x10e
#define TQUIC_H3_CONNECT_ERROR			0x10f
#define TQUIC_H3_VERSION_FALLBACK		0x110

/*
 * HTTP/3 Stream Types (RFC 9114 Section 6.2)
 *
 * Unidirectional streams in HTTP/3 start with a stream type byte.
 * These constants define the standard stream types.
 */
#define TQUIC_H3_STREAM_TYPE_CONTROL		0x00
#define TQUIC_H3_STREAM_TYPE_PUSH		0x01
#define TQUIC_H3_STREAM_TYPE_QPACK_ENCODER	0x02
#define TQUIC_H3_STREAM_TYPE_QPACK_DECODER	0x03

/*
 * HTTP/3 Frame Types (RFC 9114 Section 7.2)
 */
#define TQUIC_H3_FRAME_DATA			0x00
#define TQUIC_H3_FRAME_HEADERS			0x01
#define TQUIC_H3_FRAME_CANCEL_PUSH		0x03
#define TQUIC_H3_FRAME_SETTINGS			0x04
#define TQUIC_H3_FRAME_PUSH_PROMISE		0x05
#define TQUIC_H3_FRAME_GOAWAY			0x07
#define TQUIC_H3_FRAME_MAX_PUSH_ID		0x0d

/**
 * struct tquic_http3_stream_info - HTTP/3 stream information
 * @stream_id: QUIC stream ID (input: stream to query)
 * @type: HTTP/3 stream type (H3_STREAM_TYPE_* for unidirectional streams)
 * @state: Request state machine state (TQUIC_H3_REQUEST_*)
 * @is_request_stream: True if this is a request stream
 * @headers_received: True if HEADERS frame has been received
 * @data_offset: Current data offset
 * @content_length: Expected content length (-1 if unknown)
 * @bytes_sent: Bytes sent on this stream
 * @bytes_received: Bytes received on this stream
 *
 * Used with getsockopt(TQUIC_SO_HTTP3_STREAM_INFO) to query HTTP/3 stream state.
 * Set stream_id before calling getsockopt to query a specific stream.
 */
struct tquic_http3_stream_info {
	__u64 stream_id;
	__u32 type;
	__u32 state;
	__u32 is_request_stream;
	__u32 headers_received;
	__u64 data_offset;
	__s64 content_length;
	__u64 bytes_sent;
	__u64 bytes_received;
};

/* HTTP/3 request states (for tquic_http3_stream_info.request_state) */
#define TQUIC_H3_REQUEST_IDLE			0
#define TQUIC_H3_REQUEST_HEADERS_RECEIVED	1
#define TQUIC_H3_REQUEST_DATA			2
#define TQUIC_H3_REQUEST_TRAILERS		3
#define TQUIC_H3_REQUEST_COMPLETE		4
#define TQUIC_H3_REQUEST_ERROR			5

/*
 * =============================================================================
 * io_uring Integration Socket Options
 * =============================================================================
 *
 * These options configure io_uring behavior for TQUIC sockets.
 * io_uring provides high-performance async I/O with minimal syscall overhead.
 */

/* io_uring socket options at SOL_TQUIC level */
#define TQUIC_URING_SQPOLL		200	/* Enable/disable SQPOLL mode */
#define TQUIC_URING_CQE_BATCH		201	/* Set CQE batching threshold */
#define TQUIC_URING_BUF_RING		202	/* Configure buffer ring */

/*
 * SO_TQUIC_URING_SQPOLL - Enable/disable submission queue polling
 *
 * Used with setsockopt(SOL_TQUIC, TQUIC_URING_SQPOLL, &val, sizeof(val)).
 * The value is an int: 1 = enable SQPOLL mode, 0 = disable.
 *
 * When SQPOLL is enabled:
 *   - A kernel thread polls the submission queue for new work
 *   - Applications can submit I/O without syscalls
 *   - Provides lowest possible latency for high-frequency I/O
 *   - Uses more CPU (kernel thread is always running)
 *
 * Note: The io_uring instance must be set up with IORING_SETUP_SQPOLL
 * for this to have any effect.
 */
#define SO_TQUIC_URING_SQPOLL		TQUIC_URING_SQPOLL

/*
 * SO_TQUIC_URING_CQE_BATCH - Set completion queue entry batching threshold
 *
 * Used with setsockopt(SOL_TQUIC, TQUIC_URING_CQE_BATCH, &val, sizeof(val)).
 * The value is an int: batch_size (0-256), where 0 = no batching.
 *
 * When batching is enabled:
 *   - Completions are accumulated until threshold is reached
 *   - Reduces overhead of per-completion CQ updates
 *   - May increase latency for individual operations
 *   - Useful for high-throughput scenarios
 *
 * Default is 0 (no batching, immediate completion).
 */
#define SO_TQUIC_URING_CQE_BATCH	TQUIC_URING_CQE_BATCH

/*
 * SO_TQUIC_URING_BUF_RING - Configure registered buffer ring
 *
 * Used with setsockopt(SOL_TQUIC, TQUIC_URING_BUF_RING, &args, sizeof(args)).
 * The args is a struct tquic_uring_buf_ring_args.
 *
 * Buffer rings provide pre-registered buffers for zero-copy I/O:
 *   - Eliminates buffer allocation overhead in the fast path
 *   - Enables efficient multishot receive operations
 *   - Buffers are automatically recycled after use
 *   - Significantly reduces latency variance
 */
#define SO_TQUIC_URING_BUF_RING		TQUIC_URING_BUF_RING

/**
 * struct tquic_uring_buf_ring_args - Buffer ring configuration
 * @bgid: Buffer group ID (unique identifier for this ring)
 * @flags: Configuration flags (CREATE, DESTROY)
 * @buf_size: Size of each buffer in the ring (bytes)
 * @buf_count: Number of buffers in the ring (power of 2 recommended)
 * @reserved: Reserved for future use, must be 0
 *
 * Used with setsockopt(TQUIC_URING_BUF_RING) to create or destroy
 * a registered buffer ring for zero-copy receive operations.
 *
 * To create a buffer ring:
 *   args.flags = TQUIC_URING_BUF_RING_CREATE;
 *   args.bgid = unique_group_id;
 *   args.buf_size = 4096;  // or larger for jumbo frames
 *   args.buf_count = 256;
 *
 * To destroy a buffer ring:
 *   args.flags = TQUIC_URING_BUF_RING_DESTROY;
 *   args.bgid = group_id_to_destroy;
 */
#ifndef TQUIC_URING_BUF_RING_ARGS_DEFINED
#define TQUIC_URING_BUF_RING_ARGS_DEFINED
struct tquic_uring_buf_ring_args {
	__u16	bgid;		/* Buffer group ID */
	__u16	flags;		/* TQUIC_URING_BUF_RING_* flags */
	__u32	buf_size;	/* Size of each buffer */
	__u32	buf_count;	/* Number of buffers */
	__u32	reserved;	/* Must be 0 */
};
#endif

/* Buffer ring flags */
#define TQUIC_URING_BUF_RING_CREATE	(1 << 0)	/* Create new ring */
#define TQUIC_URING_BUF_RING_DESTROY	(1 << 1)	/* Destroy existing ring */

/**
 * struct tquic_uring_stats - io_uring statistics for TQUIC socket
 * @sends: Total send operations completed
 * @recvs: Total receive operations completed
 * @completions: Total completion queue entries generated
 * @multishot_recvs: Multishot receive operations
 * @zc_sends: Zero-copy send operations
 * @retries: Operations that needed retry
 * @overflow_events: CQE overflow events (dropped completions)
 *
 * Used with getsockopt to retrieve io_uring performance statistics.
 */
#ifndef TQUIC_URING_STATS_DEFINED
#define TQUIC_URING_STATS_DEFINED
struct tquic_uring_stats {
	__u64	sends;
	__u64	recvs;
	__u64	completions;
	__u64	multishot_recvs;
	__u64	zc_sends;
	__u64	retries;
	__u64	overflow_events;
};
#endif

/* Get io_uring statistics (read-only) */
#define TQUIC_URING_STATS		203
#define SO_TQUIC_URING_STATS		TQUIC_URING_STATS

/* io_uring buffer ring limits */
#define TQUIC_URING_MAX_BUF_RINGS	16	/* Max buffer rings per connection */
#define TQUIC_URING_MAX_BUFS_PER_RING	32768	/* Max buffers per ring */
#define TQUIC_URING_MIN_BUF_SIZE	64	/* Minimum buffer size */
#define TQUIC_URING_MAX_BUF_SIZE	(1 << 20)  /* Maximum buffer size (1MB) */

/*
 * =============================================================================
 * AF_XDP Integration Socket Options
 * =============================================================================
 *
 * These options configure AF_XDP (XDP sockets) for kernel-bypass packet I/O.
 * AF_XDP provides 10x+ packet rate improvements by bypassing the networking stack.
 */

/* AF_XDP socket options at SOL_TQUIC level */
#define TQUIC_XDP_MODE		210	/* Set XDP mode (TQUIC_XDP_*) */
#define TQUIC_XDP_STATS		211	/* Get XDP statistics (read-only) */

#define SO_TQUIC_XDP_MODE	TQUIC_XDP_MODE
#define SO_TQUIC_XDP_STATS	TQUIC_XDP_STATS

/*
 * XDP operating modes
 *
 * @TQUIC_XDP_OFF: XDP disabled, use regular UDP socket (default)
 * @TQUIC_XDP_COPY: XDP copy mode - works with all drivers
 * @TQUIC_XDP_ZEROCOPY: XDP zero-copy mode - requires driver support
 */
#define TQUIC_XDP_OFF		0	/* XDP disabled */
#define TQUIC_XDP_COPY		1	/* XDP copy mode */
#define TQUIC_XDP_ZEROCOPY	2	/* XDP zero-copy mode */

/*
 * XDP configuration flags
 */
#define TQUIC_XDP_FLAG_NEED_WAKEUP	(1 << 0)  /* Use need_wakeup mechanism */
#define TQUIC_XDP_FLAG_SHARED_UMEM	(1 << 1)  /* Share UMEM across paths */
#define TQUIC_XDP_FLAG_DRV_MODE		(1 << 2)  /* Force driver XDP mode */

/**
 * struct tquic_xdp_config - AF_XDP configuration
 * @mode: Operating mode (TQUIC_XDP_OFF, TQUIC_XDP_COPY, TQUIC_XDP_ZEROCOPY)
 * @queue_id: NIC queue to bind AF_XDP socket to
 * @frame_size: UMEM frame size in bytes (0 = default 4096)
 * @num_frames: Number of frames in UMEM (0 = default 4096)
 * @flags: Configuration flags (TQUIC_XDP_FLAG_*)
 * @ifname: Network interface name
 *
 * Used with setsockopt(SOL_TQUIC, TQUIC_XDP_MODE, &config, sizeof(config))
 * to enable and configure AF_XDP for the TQUIC socket.
 *
 * Example:
 *   struct tquic_xdp_config config = {
 *       .mode = TQUIC_XDP_ZEROCOPY,
 *       .queue_id = 0,
 *       .frame_size = 4096,
 *       .num_frames = 4096,
 *       .flags = TQUIC_XDP_FLAG_NEED_WAKEUP,
 *   };
 *   strncpy(config.ifname, "eth0", IFNAMSIZ);
 *   setsockopt(fd, SOL_TQUIC, TQUIC_XDP_MODE, &config, sizeof(config));
 *
 * To disable XDP:
 *   config.mode = TQUIC_XDP_OFF;
 *   setsockopt(fd, SOL_TQUIC, TQUIC_XDP_MODE, &config, sizeof(config));
 */
struct tquic_xdp_config {
	__u32	mode;		/* TQUIC_XDP_OFF/COPY/ZEROCOPY */
	__u32	queue_id;	/* NIC queue to bind */
	__u32	frame_size;	/* Frame size (0 = default 4096) */
	__u32	num_frames;	/* Number of frames (0 = default 4096) */
	__u32	flags;		/* TQUIC_XDP_FLAG_* */
	char	ifname[16];	/* Interface name (IFNAMSIZ) */
};

/**
 * struct tquic_xdp_stats - AF_XDP statistics
 * @rx_packets: Packets received via XDP
 * @rx_bytes: Bytes received via XDP
 * @rx_drops: Receive drops (fill ring empty, etc.)
 * @tx_packets: Packets transmitted via XDP
 * @tx_bytes: Bytes transmitted via XDP
 * @tx_drops: Transmit drops (TX ring full, etc.)
 * @fill_ring_empty: Times fill ring ran empty
 * @completion_ring_full: Times completion ring was full
 * @invalid_descs: Invalid descriptors encountered
 * @xdp_redirect_ok: Successful XDP redirects
 * @xdp_redirect_fail: Failed XDP redirects
 *
 * Used with getsockopt(SOL_TQUIC, TQUIC_XDP_STATS) to retrieve statistics.
 */
struct tquic_xdp_stats {
	__u64	rx_packets;
	__u64	rx_bytes;
	__u64	rx_drops;
	__u64	tx_packets;
	__u64	tx_bytes;
	__u64	tx_drops;
	__u64	fill_ring_empty;
	__u64	completion_ring_full;
	__u64	invalid_descs;
	__u64	xdp_redirect_ok;
	__u64	xdp_redirect_fail;
};

/* AF_XDP defaults */
#define TQUIC_XDP_DEFAULT_FRAME_SIZE	4096
#define TQUIC_XDP_DEFAULT_NUM_FRAMES	4096
#define TQUIC_XDP_DEFAULT_RING_SIZE	2048

/* AF_XDP limits */
#define TQUIC_XDP_MIN_FRAME_SIZE	2048
#define TQUIC_XDP_MAX_FRAME_SIZE	16384
#define TQUIC_XDP_MIN_NUM_FRAMES	256
#define TQUIC_XDP_MAX_NUM_FRAMES	65536

/* QUIC ports for XDP packet filtering */
#define TQUIC_XDP_PORT_443		443
#define TQUIC_XDP_PORT_4433		4433
#define TQUIC_XDP_PORT_8443		8443

/*
 * =============================================================================
 * Qlog Tracing (draft-ietf-quic-qlog-main-schema)
 * =============================================================================
 *
 * Qlog provides structured event logging for QUIC protocol debugging
 * and analysis. Events are captured in a ring buffer and can be
 * relayed to userspace via netlink.
 *
 * Include <uapi/linux/tquic_qlog.h> for detailed qlog API.
 */

/* Qlog socket options (see tquic_qlog.h for details) */
#define TQUIC_QLOG_ENABLE		250
#define SO_TQUIC_QLOG_ENABLE		TQUIC_QLOG_ENABLE

#define TQUIC_QLOG_STATS		251
#define SO_TQUIC_QLOG_STATS		TQUIC_QLOG_STATS

#define TQUIC_QLOG_FILTER		252
#define SO_TQUIC_QLOG_FILTER		TQUIC_QLOG_FILTER

#endif /* _UAPI_LINUX_TQUIC_H */
