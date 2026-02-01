/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: WAN Bonding over QUIC
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * This header provides the main TQUIC API for kernel consumers
 * and socket interface definitions.
 */

#ifndef _NET_TQUIC_H
#define _NET_TQUIC_H

#include <linux/types.h>
#include <linux/socket.h>
#include <linux/skbuff.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <linux/rhashtable.h>
#include <linux/refcount.h>
#include <net/sock.h>
#include <net/inet_connection_sock.h>
#include <uapi/linux/tquic.h>

/* Protocol version numbers */
#define TQUIC_VERSION_1		0x00000001
#define TQUIC_VERSION_2		0x6b3343cf  /* QUIC v2 */
#define TQUIC_VERSION_CURRENT	TQUIC_VERSION_1

/* Connection ID constraints */
#define TQUIC_MAX_CID_LEN	20
#define TQUIC_MIN_CID_LEN	0
#define TQUIC_DEFAULT_CID_LEN	8

/* Packet number spaces */
#define TQUIC_PN_SPACE_INITIAL	0
#define TQUIC_PN_SPACE_HANDSHAKE	1
#define TQUIC_PN_SPACE_APPLICATION	2
#define TQUIC_PN_SPACE_COUNT	3

/* Stream limits */
#define TQUIC_MAX_STREAMS_BIDI	(1ULL << 60)
#define TQUIC_MAX_STREAMS_UNI	(1ULL << 60)

/* Flow control defaults */
#define TQUIC_DEFAULT_MAX_DATA		(1 << 20)   /* 1 MB */
#define TQUIC_DEFAULT_MAX_STREAM_DATA	(1 << 18)   /* 256 KB */

/* Timing constants (in ms) */
#define TQUIC_DEFAULT_IDLE_TIMEOUT	30000
#define TQUIC_MIN_RTT			1
#define TQUIC_DEFAULT_RTT		100
#define TQUIC_MAX_ACK_DELAY		25

/* Path limits for WAN bonding */
#define TQUIC_MAX_PATHS		16
#define TQUIC_MIN_PATHS		1
#define TQUIC_DEFAULT_PATHS	4

struct tquic_sock;
struct tquic_connection;
struct tquic_stream;
struct tquic_path;
struct tquic_frame;
struct tquic_packet;
struct tquic_coupled_state;
struct tquic_client;

/**
 * enum tquic_conn_state - Connection state machine states
 * @TQUIC_CONN_IDLE: Initial state, no connection
 * @TQUIC_CONN_CONNECTING: Client initiating connection
 * @TQUIC_CONN_CONNECTED: Connection established
 * @TQUIC_CONN_CLOSING: Connection being closed gracefully
 * @TQUIC_CONN_DRAINING: Draining period before close
 * @TQUIC_CONN_CLOSED: Connection fully closed
 */
enum tquic_conn_state {
	TQUIC_CONN_IDLE = 0,
	TQUIC_CONN_CONNECTING,
	TQUIC_CONN_CONNECTED,
	TQUIC_CONN_CLOSING,
	TQUIC_CONN_DRAINING,
	TQUIC_CONN_CLOSED,
};

/**
 * enum tquic_conn_role - Connection role (client vs server)
 * @TQUIC_ROLE_CLIENT: Client-initiated connection
 * @TQUIC_ROLE_SERVER: Server-side accepted connection
 */
enum tquic_conn_role {
	TQUIC_ROLE_CLIENT = 0,
	TQUIC_ROLE_SERVER,
};

/**
 * enum tquic_stream_state - Stream state machine
 */
enum tquic_stream_state {
	TQUIC_STREAM_IDLE = 0,
	TQUIC_STREAM_OPEN,
	TQUIC_STREAM_SEND,
	TQUIC_STREAM_RECV,
	TQUIC_STREAM_SIZE_KNOWN,
	TQUIC_STREAM_DATA_SENT,
	TQUIC_STREAM_DATA_RECVD,
	TQUIC_STREAM_RESET_SENT,
	TQUIC_STREAM_RESET_RECVD,
	TQUIC_STREAM_CLOSED,
};

/**
 * enum tquic_path_state - Path state for WAN bonding
 * @TQUIC_PATH_UNUSED: Path slot not in use
 * @TQUIC_PATH_PENDING: Path validation in progress
 * @TQUIC_PATH_VALIDATED: Validation passed but not active
 * @TQUIC_PATH_ACTIVE: Path validated and usable
 * @TQUIC_PATH_STANDBY: Path usable but not preferred
 * @TQUIC_PATH_UNAVAILABLE: Interface down, state preserved for recovery
 * @TQUIC_PATH_FAILED: Path has failed, may recover
 * @TQUIC_PATH_CLOSED: Path permanently closed
 */
enum tquic_path_state {
	TQUIC_PATH_UNUSED = 0,
	TQUIC_PATH_PENDING,		/* Awaiting validation */
	TQUIC_PATH_VALIDATED,		/* Validation passed */
	TQUIC_PATH_ACTIVE,		/* In use for data */
	TQUIC_PATH_STANDBY,		/* Backup path */
	TQUIC_PATH_UNAVAILABLE,		/* Interface down, state preserved */
	TQUIC_PATH_FAILED,		/* Validation failed or errors */
	TQUIC_PATH_CLOSED,		/* Removal in progress */
};

/**
 * struct tquic_cid - Connection ID
 * @len: Length of the connection ID (0-20)
 * @id: The connection ID bytes
 * @seq_num: Sequence number for this CID
 * @retire_prior_to: Retire CIDs before this sequence
 * @node: Hash table linkage
 */
struct tquic_cid {
	u8 len;
	u8 id[TQUIC_MAX_CID_LEN];
	u64 seq_num;
	u64 retire_prior_to;
	struct rhash_head node;
};

/**
 * struct tquic_path_stats - Per-path statistics
 * @tx_packets: Packets transmitted
 * @tx_bytes: Bytes transmitted
 * @rx_packets: Packets received
 * @rx_bytes: Bytes received
 * @lost_packets: Detected lost packets
 * @rtt_min: Minimum observed RTT (us)
 * @rtt_smoothed: Smoothed RTT (us)
 * @rtt_variance: RTT variance (us)
 * @bandwidth: Estimated bandwidth (bytes/s)
 * @cwnd: Current congestion window
 */
struct tquic_path_stats {
	u64 tx_packets;
	u64 tx_bytes;
	u64 rx_packets;
	u64 rx_bytes;
	u64 lost_packets;
	u32 rtt_min;
	u32 rtt_smoothed;
	u32 rtt_variance;
	u64 bandwidth;
	u32 cwnd;
};

/* Maximum pending PATH_RESPONSE frames per path to prevent memory exhaustion */
#define TQUIC_MAX_PENDING_RESPONSES 256

/**
 * struct tquic_path - A network path for WAN bonding
 * @conn: Parent connection (back-pointer for safe access)
 * @state: Current path state
 * @saved_state: State before UNAVAILABLE (for recovery)
 * @path_id: Unique identifier for this path
 * @local_addr: Local address for this path
 * @remote_addr: Remote address for this path
 * @local_cid: Local connection ID for this path
 * @remote_cid: Remote connection ID for this path
 * @stats: Path statistics
 * @cong: Congestion control state (algorithm-specific)
 * @cong_ops: Congestion control algorithm operations
 * @mtu: Path MTU
 * @priority: Path priority (lower = preferred)
 * @weight: Weight for weighted schedulers
 * @dev: Network device for this path
 * @last_activity: Timestamp of last activity
 * @validation_timer: Path validation timer
 * @probe_count: Number of outstanding probes
 * @challenge_data: PATH_CHALLENGE data (legacy field, replaced by validation)
 * @list: Connection's path list linkage
 * @validation: Validation state (RFC 9000 PATH_CHALLENGE/RESPONSE)
 * @response: Response queue (prevent memory exhaustion)
 * @rcu_head: RCU callback head for deferred freeing
 */
struct tquic_path {
	struct tquic_connection *conn;
	enum tquic_path_state state;
	enum tquic_path_state saved_state;	/* State before unavailable */
	u32 path_id;

	struct sockaddr_storage local_addr;
	struct sockaddr_storage remote_addr;

	struct tquic_cid local_cid;
	struct tquic_cid remote_cid;

	struct tquic_path_stats stats;
	void *cong;  /* Congestion control state */
	struct tquic_cong_ops *cong_ops;  /* Current CC algorithm ops */

	u32 mtu;
	u8 priority;
	u8 weight;

	struct net_device *dev;		/* Interface for this path */
	ktime_t last_activity;
	struct timer_list validation_timer;
	u8 probe_count;
	u8 challenge_data[8];  /* Legacy - use validation.challenge_data instead */

	struct list_head list;

	/* Validation state */
	struct {
		u8 challenge_data[8];         /* Sent challenge */
		ktime_t challenge_sent;       /* When challenge was sent */
		bool challenge_pending;       /* Awaiting response */
		u8 retries;                   /* Retry count */
		struct timer_list timer;      /* Retransmission timer */
	} validation;

	/* Response queue (prevent memory exhaustion - RFC 9000 Section 8.2) */
	struct {
		struct sk_buff_head queue;    /* Pending PATH_RESPONSE frames */
		atomic_t count;               /* Current queue depth */
	} response;

	struct rcu_head rcu_head;	/* RCU callback for kfree_rcu */
};

/**
 * struct tquic_stream - A QUIC stream
 * @id: Stream identifier
 * @state: Current stream state
 * @conn: Parent connection
 * @send_buf: Send buffer
 * @recv_buf: Receive buffer
 * @send_offset: Current send offset
 * @recv_offset: Current receive offset
 * @max_send_data: Maximum data allowed to send
 * @max_recv_data: Maximum data allowed to receive
 * @priority: Stream priority
 * @blocked: Stream is flow-control blocked
 * @fin_sent: FIN has been sent
 * @fin_received: FIN has been received
 * @node: Connection's stream tree linkage
 * @wait: Wait queue for blocking operations
 * @ext: Extended stream state (priority, reassembly, etc.)
 */
struct tquic_stream {
	u64 id;
	enum tquic_stream_state state;
	struct tquic_connection *conn;

	struct sk_buff_head send_buf;
	struct sk_buff_head recv_buf;

	u64 send_offset;
	u64 recv_offset;
	u64 max_send_data;
	u64 max_recv_data;

	u8 priority;
	bool blocked;
	bool fin_sent;
	bool fin_received;

	struct rb_node node;
	wait_queue_head_t wait;

	void *ext;  /* Extended stream state for reassembly and priority */
};

/**
 * struct tquic_conn_stats - Connection-level statistics
 */
struct tquic_conn_stats {
	u64 tx_packets;
	u64 tx_bytes;
	u64 rx_packets;
	u64 rx_bytes;
	u64 lost_packets;
	u64 retransmissions;
	u64 path_migrations;
	u64 streams_opened;
	u64 streams_closed;
	ktime_t established_time;
};

/**
 * struct tquic_connection - A TQUIC connection
 * @state: Current connection state
 * @version: Negotiated QUIC version
 * @scid: Source (local) connection ID
 * @dcid: Destination (remote) connection ID
 * @paths: List of network paths
 * @active_path: Currently active primary path
 * @num_paths: Number of paths
 * @streams: RB-tree of streams
 * @next_stream_id_bidi: Next bidirectional stream ID
 * @next_stream_id_uni: Next unidirectional stream ID
 * @max_streams_bidi: Maximum bidirectional streams
 * @max_streams_uni: Maximum unidirectional streams
 * @max_data_local: Local max data limit
 * @max_data_remote: Remote max data limit
 * @data_sent: Total data sent
 * @data_received: Total data received
 * @stats: Connection statistics
 * @idle_timeout: Idle timeout in ms
 * @timer_state: Unified timer and recovery state (idle, ack, loss, PTO)
 * @crypto_state: TLS/crypto state
 * @scheduler: Packet scheduler
 * @state_machine: Connection state machine (extended state)
 * @cid_pool: Connection ID pool (tquic_cid.c)
 * @pm: Path manager state
 * @token: Connection token for netlink identification
 * @lock: Connection lock
 * @refcnt: Reference counter
 * @sk: Associated socket
 * @node: Global connection hash linkage
 */
struct tquic_connection {
	enum tquic_conn_state state;
	enum tquic_conn_role role;
	u32 version;

	struct tquic_cid scid;
	struct tquic_cid dcid;

	/* Multi-path support for WAN bonding */
	struct list_head paths;
	spinlock_t paths_lock;		/* Protects paths list */
	struct tquic_path *active_path;
	u8 num_paths;
	u8 max_paths;			/* Maximum paths allowed */

	/* Stream management */
	struct rb_root streams;
	u64 next_stream_id_bidi;
	u64 next_stream_id_uni;
	u64 max_streams_bidi;
	u64 max_streams_uni;

	/* Flow control */
	u64 max_data_local;
	u64 max_data_remote;
	u64 data_sent;
	u64 data_received;

	struct tquic_conn_stats stats;

	/* Timers - managed via timer_state for unified timer/recovery handling */
	u32 idle_timeout;
	struct tquic_timer_state *timer_state;

	/* Crypto */
	void *crypto_state;

	/* Scheduler */
	void *scheduler;

	/* Connection state machine (extended state) */
	void *state_machine;

	/* Connection ID pool (tquic_cid.c) */
	void *cid_pool;

	/* Path manager state */
	struct tquic_pm_state *pm;

	/* Coupled CC state (NULL when coupling disabled) */
	struct tquic_coupled_state *coupled_cc;

	/* Server-side client binding (NULL for client connections) */
	struct tquic_client *client;

	/* Connection token for netlink identification */
	u32 token;

	/* DATAGRAM frame support (RFC 9221) */
	struct {
		bool enabled;			/* True if datagrams negotiated */
		u64 max_send_size;		/* Max datagram size we can send */
		u64 max_recv_size;		/* Max datagram size we accept */
		struct sk_buff_head recv_queue;	/* Received datagram queue */
		spinlock_t lock;		/* Protects datagram state */
		u32 recv_queue_len;		/* Current queue length */
		u32 recv_queue_max;		/* Maximum queue length */
		u64 datagrams_sent;		/* Statistics: sent count */
		u64 datagrams_received;		/* Statistics: recv count */
		u64 datagrams_dropped;		/* Statistics: dropped count */
	} datagram;

	/*
	 * GREASE (RFC 9287) state
	 *
	 * GREASE (Generate Random Extensions And Sustain Extensibility)
	 * helps ensure forward compatibility by randomly including
	 * reserved values that receivers must ignore.
	 */
	struct {
		bool enabled;			/* GREASE enabled for this conn */
		bool peer_grease_quic_bit;	/* Peer advertised grease_quic_bit */
		bool local_grease_quic_bit;	/* We advertised grease_quic_bit */
	} grease;

	spinlock_t lock;
	refcount_t refcnt;
	struct sock *sk;
	struct rhash_head node;
};

/* Forward declaration for handshake state */
struct tquic_handshake_state;

/**
 * struct tquic_sock - TQUIC socket structure
 * @inet: Inet connection socket base
 * @conn: Associated TQUIC connection
 * @bind_addr: Bound local address
 * @connect_addr: Connected remote address
 * @accept_queue: Queue of incoming connections (listener)
 * @accept_list: Linkage for being queued on listener (child socket)
 * @accept_queue_len: Length of accept queue
 * @max_accept_queue: Maximum accept queue length
 * @default_stream: Default stream for simple operations
 * @handshake_state: TLS handshake state (during connection)
 * @flags: Socket flags (TQUIC_F_*)
 * @nodelay: Disable Nagle algorithm (TQUIC_NODELAY option)
 */
struct tquic_sock {
	struct inet_connection_sock inet;
	struct tquic_connection *conn;

	struct sockaddr_storage bind_addr;
	struct sockaddr_storage connect_addr;

	struct list_head accept_queue;	/* Listener: queue of pending children */
	struct list_head accept_list;	/* Child: linkage in listener's queue */
	struct hlist_node listener_node; /* Listener hash table linkage */
	u32 accept_queue_len;
	u32 max_accept_queue;

	struct tquic_stream *default_stream;

	/* Handshake state (NULL when not in handshake) */
	struct tquic_handshake_state *handshake_state;

	/* Socket flags (TQUIC_F_*) - see net/tquic/protocol.h */
	u32 flags;

	/* Socket options */
	bool nodelay;		/* TQUIC_NODELAY: disable Nagle, send immediately */
	bool pacing_enabled;	/* SO_TQUIC_PACING: enable pacing (default true) */

	/*
	 * Scheduler preference (set via SO_TQUIC_SCHEDULER before connect)
	 *
	 * Per CONTEXT.md: "Scheduler locked at connection establishment,
	 * cannot change mid-connection". This field stores the user's
	 * preference until connection is established.
	 *
	 * If empty, the per-netns default is used.
	 */
	char requested_scheduler[TQUIC_MAX_SCHED_NAME];

	/*
	 * Congestion control preference (set via SO_TQUIC_CONGESTION before connect)
	 *
	 * Per CONTEXT.md: Different paths can use different CC algorithms.
	 * This field stores the user's preference until connection is established.
	 * Individual paths may auto-select BBR based on RTT threshold.
	 *
	 * If empty, the per-netns default is used.
	 * If "auto", RTT-based auto-selection is enabled.
	 */
	char requested_congestion[TQUIC_MAX_CONG_NAME];

	/*
	 * PSK identity for authentication (set via SO_TQUIC_PSK_IDENTITY)
	 *
	 * For client: Identity to send in ClientHello
	 * For server: Not used (server uses tquic_client_register)
	 */
	char psk_identity[64];
	u8 psk_identity_len;

	/*
	 * DATAGRAM frame support (RFC 9221)
	 *
	 * When enabled, sendmsg/recvmsg can transfer unreliable datagrams
	 * using cmsg with TQUIC_CMSG_DATAGRAM type.
	 */
	bool datagram_enabled;		/* SO_TQUIC_DATAGRAM enabled */
	u32 datagram_queue_max;		/* Max receive queue length */
};

static inline struct tquic_sock *tquic_sk(struct sock *sk)
{
	return (struct tquic_sock *)sk;
}

/* Bonding operations */
struct tquic_bond_ops {
	const char *name;

	int (*add_path)(struct tquic_connection *conn,
			struct sockaddr *local,
			struct sockaddr *remote);
	int (*remove_path)(struct tquic_connection *conn, u32 path_id);
	int (*set_path_priority)(struct tquic_connection *conn,
				 u32 path_id, u8 priority);
	int (*get_path_info)(struct tquic_connection *conn,
			     u32 path_id, struct tquic_path_info *info);

	struct tquic_path *(*select_path)(struct tquic_connection *conn,
					  struct sk_buff *skb);
	void (*path_event)(struct tquic_connection *conn,
			   struct tquic_path *path, int event);
};

/* Scheduler operations */
struct tquic_sched_ops {
	const char *name;
	struct module *owner;

	void *(*init)(struct tquic_connection *conn);
	void (*release)(void *sched_data);

	struct tquic_path *(*select)(void *sched_data,
				     struct tquic_connection *conn,
				     struct sk_buff *skb);
	void (*feedback)(void *sched_data,
			 struct tquic_path *path,
			 struct sk_buff *skb,
			 bool success);

	struct list_head list;
};

/* Congestion control operations */
struct tquic_cong_ops {
	const char *name;
	struct module *owner;
	u32 key;

	void *(*init)(struct tquic_path *path);
	void (*release)(void *cong_data);

	void (*on_packet_sent)(void *cong_data, u64 bytes, ktime_t sent_time);
	void (*on_ack)(void *cong_data, u64 bytes_acked, u64 rtt_us);
	void (*on_loss)(void *cong_data, u64 bytes_lost);
	void (*on_rtt_update)(void *cong_data, u64 rtt_us);
	void (*on_ecn)(void *cong_data, u64 ecn_ce_count);  /* ECN CE handler */

	u64 (*get_cwnd)(void *cong_data);
	u64 (*get_pacing_rate)(void *cong_data);
	bool (*can_send)(void *cong_data, u64 bytes);

	struct list_head list;
};

/* Core API functions */
int tquic_connect(struct sock *sk, struct sockaddr *addr, int addr_len);
int tquic_accept(struct sock *sk, struct sock **newsk, int flags, bool kern);
int tquic_sendmsg(struct sock *sk, struct msghdr *msg, size_t len);
int tquic_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int flags);
int tquic_close(struct sock *sk, long timeout);
__poll_t tquic_poll(struct file *file, struct socket *sock, poll_table *wait);

/* Connection management */
struct tquic_connection *tquic_conn_create(struct sock *sk, gfp_t gfp);
void tquic_conn_destroy(struct tquic_connection *conn);
int tquic_conn_add_path(struct tquic_connection *conn,
			struct sockaddr *local, struct sockaddr *remote);
int tquic_conn_remove_path(struct tquic_connection *conn, u32 path_id);
struct tquic_path *tquic_conn_get_path(struct tquic_connection *conn, u32 path_id);
void tquic_conn_migrate(struct tquic_connection *conn, struct tquic_path *new_path);
struct tquic_connection *tquic_conn_lookup_by_token(struct net *net, u32 token);
void tquic_conn_flush_paths(struct tquic_connection *conn);

/* RCU-safe path operations (dynamic add/remove) */
int tquic_conn_add_path_safe(struct tquic_connection *conn,
			      struct sockaddr *local,
			      struct sockaddr *remote);
int tquic_conn_remove_path_safe(struct tquic_connection *conn,
				 u32 path_id);
struct tquic_path *tquic_conn_get_path_locked(struct tquic_connection *conn,
					       u32 path_id);

/* Path manager connection lifecycle */
int tquic_pm_conn_init(struct tquic_connection *conn);
void tquic_pm_conn_release(struct tquic_connection *conn);

/* Path validation (PATH_CHALLENGE/RESPONSE) - net/tquic/pm/path_validation.c */
int tquic_path_start_validation(struct tquic_connection *conn,
				 struct tquic_path *path);
int tquic_path_handle_challenge(struct tquic_connection *conn,
				 struct tquic_path *path,
				 const u8 *data);
int tquic_path_handle_response(struct tquic_connection *conn,
				struct tquic_path *path,
				const u8 *data);
void tquic_path_validation_timeout(struct timer_list *t);
int tquic_path_send_challenge(struct tquic_connection *conn,
			       struct tquic_path *path);

/*
 * Connection State Machine API
 */

/* Connection ID management */
struct tquic_cid_entry *tquic_conn_add_local_cid(struct tquic_connection *conn);
int tquic_conn_add_remote_cid(struct tquic_connection *conn,
			      const struct tquic_cid *cid, u64 seq,
			      const u8 *reset_token);
int tquic_conn_retire_cid(struct tquic_connection *conn, u64 seq, bool is_local);
struct tquic_cid *tquic_conn_get_active_cid(struct tquic_connection *conn);

/* Stateless reset */
void tquic_generate_stateless_reset_token(const struct tquic_cid *cid,
					  const u8 *static_key, u8 *token);
bool tquic_verify_stateless_reset(struct tquic_connection *conn,
				  const u8 *data, size_t len);
int tquic_send_stateless_reset(struct tquic_connection *conn);

/* Version negotiation */
bool tquic_version_is_supported(u32 version);
u32 tquic_version_select(const u32 *offered, int num_offered);
int tquic_send_version_negotiation(struct tquic_connection *conn,
				   const struct tquic_cid *dcid,
				   const struct tquic_cid *scid);
int tquic_handle_version_negotiation(struct tquic_connection *conn,
				     const u32 *versions, int num_versions);

/* Retry token handling */
int tquic_generate_retry_token(struct tquic_connection *conn,
			       const struct tquic_cid *original_dcid,
			       const struct sockaddr *client_addr,
			       u8 *token, u32 *token_len);
int tquic_validate_retry_token(struct tquic_connection *conn,
			       const u8 *token, u32 token_len,
			       const struct sockaddr *client_addr,
			       struct tquic_cid *original_dcid);
int tquic_send_retry(struct tquic_connection *conn,
		     const struct tquic_cid *original_dcid,
		     const struct sockaddr *client_addr);

/* Address validation (PATH_CHALLENGE/PATH_RESPONSE) */
int tquic_send_path_challenge(struct tquic_connection *conn,
			      struct tquic_path *path);
int tquic_send_path_response(struct tquic_connection *conn,
			     struct tquic_path *path, const u8 *data);
int tquic_handle_path_challenge(struct tquic_connection *conn,
				struct tquic_path *path, const u8 *data);
int tquic_handle_path_response(struct tquic_connection *conn,
			       struct tquic_path *path, const u8 *data);

/* Connection migration */
int tquic_conn_migrate_to_path(struct tquic_connection *conn,
			       struct tquic_path *new_path);
int tquic_conn_handle_migration(struct tquic_connection *conn,
				struct tquic_path *path,
				const struct sockaddr *remote_addr);

/* 0-RTT handling */
int tquic_conn_enable_0rtt(struct tquic_connection *conn);
int tquic_conn_send_0rtt(struct tquic_connection *conn,
			 const void *data, size_t len);
void tquic_conn_0rtt_accepted(struct tquic_connection *conn);
void tquic_conn_0rtt_rejected(struct tquic_connection *conn);

/* Handshake packet processing */
int tquic_conn_process_handshake(struct tquic_connection *conn,
				 struct sk_buff *skb);

/* Connection close */
int tquic_conn_close_with_error(struct tquic_connection *conn,
				u64 error_code, const char *reason);
int tquic_conn_close_app(struct tquic_connection *conn,
			 u64 error_code, const char *reason);
int tquic_conn_handle_close(struct tquic_connection *conn,
			    u64 error_code, u64 frame_type,
			    const char *reason, bool is_app);
int tquic_conn_shutdown(struct tquic_connection *conn);

/* Client/Server connection establishment */
int tquic_conn_client_connect(struct tquic_connection *conn,
			      const struct sockaddr *server_addr);
int tquic_conn_client_restart(struct tquic_connection *conn);
int tquic_conn_server_accept(struct tquic_connection *conn,
			     struct sk_buff *initial_pkt);

/* Anti-amplification */
bool tquic_conn_can_send(struct tquic_connection *conn, size_t bytes);
void tquic_conn_on_packet_sent(struct tquic_connection *conn, size_t bytes);
void tquic_conn_on_packet_received(struct tquic_connection *conn, size_t bytes);

/* Connection lookup */
struct tquic_connection *tquic_conn_lookup_by_cid(const struct tquic_cid *cid);

/* State machine cleanup */
void tquic_conn_state_cleanup(struct tquic_connection *conn);

/* Stream management */
struct tquic_stream *tquic_stream_open(struct tquic_connection *conn, bool bidi);
void tquic_stream_close(struct tquic_stream *stream);
int tquic_stream_send(struct tquic_stream *stream, const void *data, size_t len, bool fin);
int tquic_stream_recv(struct tquic_stream *stream, void *data, size_t len);
void tquic_stream_reset(struct tquic_stream *stream, u64 error_code);

/* Path management for WAN bonding */
int tquic_path_probe(struct tquic_connection *conn, struct tquic_path *path);
void tquic_path_validate(struct tquic_connection *conn, struct tquic_path *path);
void tquic_path_update_stats(struct tquic_path *path, struct sk_buff *skb, bool success);
int tquic_path_set_weight(struct tquic_path *path, u8 weight);

/* Bonding state machine (Phase 05) */
int tquic_bond_set_path_weight(struct tquic_connection *conn, u8 path_id, u32 weight);
u32 tquic_bond_get_path_weight(struct tquic_connection *conn, u8 path_id);

/* Packet transmission (tquic_output.c) */
struct tquic_pacing_state;
struct tquic_path *tquic_select_path(struct tquic_connection *conn,
				     struct sk_buff *skb);

/*
 * GRO/GSO Offload Support (tquic_offload.c)
 *
 * Generic Receive Offload (GRO) aggregates multiple incoming QUIC packets
 * into larger buffers for efficient processing. This is the receive-side
 * counterpart to GSO (Generic Segmentation Offload) on transmit.
 */

/* GRO receive callback for UDP tunnel sockets */
struct sk_buff *tquic_gro_receive(struct list_head *head, struct sk_buff *skb,
				  struct udphdr *uh, struct sock *sk);
struct sk_buff *tquic_gro_receive_udp(struct sock *sk, struct list_head *head,
				      struct sk_buff *skb);

/* GRO complete callback */
int tquic_gro_complete(struct sk_buff *skb, int nhoff);
int tquic_gro_complete_udp(struct sock *sk, struct sk_buff *skb, int nhoff);

/* GRO setup/teardown per socket */
int tquic_setup_gro(struct sock *sk);
void tquic_clear_gro(struct sock *sk);

/* GRO statistics */
void tquic_gro_stats_show(struct seq_file *seq);
void tquic_gro_get_stats(u64 *coalesced, u64 *flushes, u64 *avg_aggregation);

/* Offload initialization */
int __init tquic_offload_init(void);
void __exit tquic_offload_exit(void);

/*
 * DATAGRAM Frame Support (RFC 9221)
 *
 * QUIC DATAGRAM frames provide unreliable, unordered message delivery.
 * Datagrams are not retransmitted on loss and have no flow control.
 */

/**
 * tquic_send_datagram - Send a DATAGRAM frame
 * @conn: Connection to send on
 * @data: Datagram payload
 * @len: Payload length
 *
 * Sends an unreliable datagram on the connection. The datagram will be
 * sent on the next packet, subject to congestion control. Unlike stream
 * data, datagrams are not retransmitted if lost.
 *
 * Returns: 0 on success, -EMSGSIZE if len exceeds max_datagram_frame_size,
 *          -ENOTCONN if connection not established, -EOPNOTSUPP if
 *          datagrams not negotiated, other negative errno on error.
 */
int tquic_send_datagram(struct tquic_connection *conn,
			const void *data, size_t len);

/**
 * tquic_recv_datagram - Receive a DATAGRAM frame
 * @conn: Connection to receive from
 * @data: Buffer for datagram payload
 * @len: Buffer size
 * @flags: Receive flags (MSG_DONTWAIT, MSG_PEEK, etc.)
 *
 * Receives the next available datagram from the receive queue.
 * Datagrams are delivered in the order they were received but
 * may arrive out of order relative to when they were sent.
 *
 * Returns: Number of bytes received, -EAGAIN if no datagram available
 *          and MSG_DONTWAIT set, -EOPNOTSUPP if datagrams not negotiated,
 *          other negative errno on error.
 */
int tquic_recv_datagram(struct tquic_connection *conn,
			void *data, size_t len, int flags);

/**
 * tquic_datagram_max_size - Get maximum datagram payload size
 * @conn: Connection
 *
 * Returns the maximum size of datagram payloads that can be sent
 * on this connection, as negotiated via transport parameters.
 *
 * Returns: Maximum payload size, or 0 if datagrams not supported.
 */
u64 tquic_datagram_max_size(struct tquic_connection *conn);

/**
 * tquic_datagram_init - Initialize datagram support for connection
 * @conn: Connection
 *
 * Called after transport parameter negotiation to initialize
 * datagram receive queue and state.
 */
void tquic_datagram_init(struct tquic_connection *conn);

/**
 * tquic_datagram_cleanup - Cleanup datagram state
 * @conn: Connection
 *
 * Called during connection teardown to free datagram resources.
 */
void tquic_datagram_cleanup(struct tquic_connection *conn);

/**
 * tquic_datagram_queue_len - Get number of queued datagrams
 * @conn: Connection to query
 *
 * Returns the number of datagrams currently in the receive queue.
 */
u32 tquic_datagram_queue_len(struct tquic_connection *conn);

int tquic_xmit(struct tquic_connection *conn, struct tquic_stream *stream,
	       const u8 *data, size_t len, bool fin);
int tquic_send_ack(struct tquic_connection *conn, struct tquic_path *path,
		   u64 largest_ack, u64 ack_delay, u64 ack_range);
int tquic_send_connection_close(struct tquic_connection *conn,
				u64 error_code, const char *reason);
int tquic_output_flush(struct tquic_connection *conn);

/* Pacing */
struct tquic_pacing_state *tquic_pacing_init(struct tquic_path *path);
void tquic_pacing_cleanup(struct tquic_pacing_state *pacing);
void tquic_pacing_update_rate(struct tquic_pacing_state *pacing, u64 rate);
int tquic_pacing_send(struct tquic_pacing_state *pacing, struct sk_buff *skb);

/* Packet reception (tquic_input.c) */
struct tquic_gro_state;
int tquic_udp_recv(struct sock *sk, struct sk_buff *skb);
int tquic_setup_udp_encap(struct sock *sk);
void tquic_clear_udp_encap(struct sock *sk);
int tquic_process_coalesced(struct tquic_connection *conn,
			    struct tquic_path *path,
			    u8 *data, size_t total_len,
			    struct sockaddr_storage *src_addr);

/* GRO handling */
struct tquic_gro_state *tquic_gro_init(void);
void tquic_gro_cleanup(struct tquic_gro_state *gro);
int tquic_gro_flush(struct tquic_gro_state *gro,
		    void (*deliver)(struct sk_buff *));

/* Encryption/decryption (crypto/tls.c) */
struct tquic_crypto_state;
struct tquic_crypto_state *tquic_crypto_init(const struct tquic_cid *dcid,
					     bool is_server);
void tquic_crypto_cleanup(struct tquic_crypto_state *crypto);
int tquic_encrypt_packet(struct tquic_crypto_state *crypto,
			 u8 *header, size_t header_len,
			 u8 *payload, size_t payload_len,
			 u64 pkt_num, u8 *out, size_t *out_len);
int tquic_decrypt_packet(struct tquic_crypto_state *crypto,
			 const u8 *header, size_t header_len,
			 u8 *payload, size_t payload_len,
			 u64 pkt_num, u8 *out, size_t *out_len);
bool tquic_crypto_handshake_complete(struct tquic_crypto_state *crypto);

/* Scheduler registration */
int tquic_register_scheduler(struct tquic_sched_ops *ops);
void tquic_unregister_scheduler(struct tquic_sched_ops *ops);

/* Congestion control registration */
int tquic_register_cong(struct tquic_cong_ops *ops);
void tquic_unregister_cong(struct tquic_cong_ops *ops);

/* Module initialization */
int __init tquic_init(void);
void __exit tquic_exit(void);

/* Netlink interface */
int __init tquic_netlink_init(void);
void __exit tquic_netlink_exit(void);

/* Sysctl interface */
int __init tquic_sysctl_init(void);
void __exit tquic_sysctl_exit(void);

/* Protocol handler registration */
int __init tquic_proto_init(void);
void __exit tquic_proto_exit(void);

/* Socket registration */
int __init tquic_socket_init(void);
void __exit tquic_socket_exit(void);

/* Diagnostics (ss tool integration) */
int __init tquic_diag_init(void);
void __exit tquic_diag_exit(void);

/* MIB statistics (net/tquic/tquic_mib.c) */
struct seq_file;
bool tquic_mib_alloc(struct net *net);
void tquic_mib_free(struct net *net);
void tquic_mib_seq_show(struct seq_file *seq);
int __init tquic_mib_init(struct net *net);
void __exit tquic_mib_exit(struct net *net);

/* Proc interface (net/tquic/tquic_proc.c) */
struct tquic_error_ring;
int __init tquic_proc_init(struct net *net);
void __exit tquic_proc_exit(struct net *net);
void tquic_log_error(struct net *net, struct tquic_connection *conn,
		     u32 error_code, const char *msg);
const char *tquic_error_name(u32 error_code);

/*
 * Per-Network Namespace API
 *
 * These functions provide access to per-netns sysctl values.
 * They should be used instead of the global sysctl accessors
 * when network namespace context is available.
 */
int tquic_net_get_enabled(struct net *net);
int tquic_net_get_bond_mode(struct net *net);
int tquic_net_get_max_paths(struct net *net);
int tquic_net_get_reorder_window(struct net *net);
int tquic_net_get_probe_interval(struct net *net);
int tquic_net_get_failover_timeout(struct net *net);
int tquic_net_get_idle_timeout(struct net *net);
int tquic_net_get_initial_rtt(struct net *net);
int tquic_net_get_initial_cwnd(struct net *net);
int tquic_net_get_debug_level(struct net *net);

/* Per-netns statistics update */
void tquic_net_update_tx_stats(struct net *net, u64 bytes);
void tquic_net_update_rx_stats(struct net *net, u64 bytes);

/* Netlink path event notification */
int tquic_nl_path_event(struct tquic_connection *conn,
			struct tquic_path *path,
			enum tquic_path_event event);

/*
 * Packet Types and Structures
 */

/* QUIC packet types */
enum tquic_packet_type {
	TQUIC_PKT_INITIAL = 0,
	TQUIC_PKT_0RTT,
	TQUIC_PKT_HANDSHAKE,
	TQUIC_PKT_RETRY,
	TQUIC_PKT_1RTT,
	TQUIC_PKT_VERSION_NEG,
	TQUIC_PKT_STATELESS_RESET,
};

/* Stateless reset token length */
#define TQUIC_STATELESS_RESET_TOKEN_LEN	16

/* Minimum initial packet size */
#define TQUIC_MIN_INITIAL_PACKET_SIZE	1200

/**
 * struct tquic_packet_header - Parsed packet header
 * @type: Packet type
 * @version: QUIC version (0 for short header)
 * @dcid: Destination connection ID
 * @dcid_len: Length of destination CID
 * @scid: Source connection ID (long header only)
 * @scid_len: Length of source CID
 * @pn: Decoded packet number
 * @pn_len: Packet number length in bytes
 * @token: Token (Initial packets only)
 * @token_len: Token length
 * @payload_len: Payload length
 * @header_len: Total header length
 * @key_phase: Key phase bit (short header)
 * @spin_bit: Spin bit (short header)
 */
struct tquic_packet_header {
	enum tquic_packet_type type;
	u32 version;

	u8 dcid[TQUIC_MAX_CID_LEN];
	u8 dcid_len;

	u8 scid[TQUIC_MAX_CID_LEN];
	u8 scid_len;

	u64 pn;
	u8 pn_len;

	u8 *token;
	u64 token_len;

	u64 payload_len;
	size_t header_len;

	u8 key_phase;
	u8 spin_bit;
};

/**
 * struct tquic_packet - Complete packet structure
 * @hdr: Parsed header
 * @payload: Pointer to payload data
 * @payload_len: Length of payload
 * @raw: Raw packet data
 * @raw_len: Total raw packet length
 * @path: Path this packet arrived on / will be sent on
 * @pn_space: Packet number space
 * @ack_eliciting: Whether packet is ACK-eliciting
 * @in_flight: Whether packet counts as in-flight
 * @sent_time: Time packet was sent
 * @list: List linkage for packet queues
 */
struct tquic_packet {
	struct tquic_packet_header hdr;

	u8 *payload;
	size_t payload_len;

	u8 *raw;
	size_t raw_len;

	struct tquic_path *path;
	u8 pn_space;

	bool ack_eliciting;
	bool in_flight;

	ktime_t sent_time;
	struct list_head list;
};

/*
 * Packet Parsing and Construction Functions
 */

/* Variable-length integer encoding/decoding */
int tquic_varint_decode(const u8 *data, size_t len, u64 *value);
int tquic_varint_encode(u64 value, u8 *data, size_t len);
int tquic_varint_len(u64 value);

/* Packet number encoding/decoding */
int tquic_pn_encode_len(u64 pn, u64 largest_acked);
int tquic_pn_encode(u64 pn, int len, u8 *data, size_t buflen);
u64 tquic_pn_decode(const u8 *data, int len, u64 largest_pn);

/* Header parsing */
int tquic_parse_long_header(const u8 *data, size_t len,
			    struct tquic_packet_header *hdr,
			    u64 largest_pn);
int tquic_parse_short_header(const u8 *data, size_t len,
			     struct tquic_packet_header *hdr,
			     u8 dcid_len, u64 largest_pn);
bool tquic_is_long_header(const u8 *data, size_t len);
int tquic_get_packet_type(const u8 *data, size_t len);

/* Version negotiation */
int tquic_build_version_negotiation(const u8 *dcid, u8 dcid_len,
				    const u8 *scid, u8 scid_len,
				    const u32 *versions, int num_versions,
				    u8 *buf, size_t buflen);
int tquic_parse_version_negotiation(const u8 *data, size_t len,
				    u32 *versions, int max_versions,
				    int *num_versions);

/* Stateless reset */
int tquic_build_stateless_reset(const u8 *token, u8 *buf, size_t buflen);
bool tquic_is_stateless_reset(const u8 *data, size_t len,
			      const u8 (*tokens)[TQUIC_STATELESS_RESET_TOKEN_LEN],
			      int num_tokens);

/* Retry packets */
int tquic_build_retry(u32 version, const u8 *dcid, u8 dcid_len,
		      const u8 *scid, u8 scid_len,
		      const u8 *odcid, u8 odcid_len,
		      const u8 *token, size_t token_len,
		      u8 *buf, size_t buflen);

/* Packet construction */
int tquic_build_long_header(enum tquic_packet_type type, u32 version,
			    const u8 *dcid, u8 dcid_len,
			    const u8 *scid, u8 scid_len,
			    const u8 *token, size_t token_len,
			    u64 pn, int pn_len,
			    const u8 *payload, size_t payload_len,
			    u8 *buf, size_t buflen);
int tquic_build_short_header(const u8 *dcid, u8 dcid_len,
			     u64 pn, int pn_len,
			     u8 key_phase, u8 spin_bit,
			     const u8 *payload, size_t payload_len,
			     u8 *buf, size_t buflen);

/* Coalesced packet handling */
int tquic_split_coalesced(const u8 *data, size_t len,
			  const u8 **packets, size_t *lengths,
			  int max_packets, int *num_packets);
int tquic_coalesce_packets(const u8 **packets, const size_t *lengths,
			   int num_packets, u8 *buf, size_t buflen);

/* Packet validation */
int tquic_validate_packet(const u8 *data, size_t len);
int tquic_validate_initial_packet(const u8 *data, size_t len, bool is_client);
bool tquic_validate_version(u32 version);
u32 tquic_get_version(const u8 *data, size_t len);

/* Packet structure management */
struct tquic_packet *tquic_packet_alloc(gfp_t gfp);
void tquic_packet_free(struct tquic_packet *pkt);
struct tquic_packet *tquic_packet_clone(const struct tquic_packet *pkt, gfp_t gfp);
const char *tquic_packet_type_str(enum tquic_packet_type type);
int tquic_packet_pn_space(enum tquic_packet_type type);

/* SKB interface */
struct tquic_packet *tquic_packet_from_skb(struct sk_buff *skb,
					   struct tquic_connection *conn,
					   u64 largest_pn, gfp_t gfp);
struct sk_buff *tquic_packet_to_skb(struct tquic_packet *pkt, gfp_t gfp);

/* Packet subsystem initialization */
int __init tquic_packet_init(void);
void __exit tquic_packet_exit(void);

/*
 * Connection ID Management
 */

/* CID management constants */
#define TQUIC_RESET_TOKEN_LEN		16
#define TQUIC_CID_POOL_MIN		4
#define TQUIC_CID_POOL_MAX		16

/* Forward declarations for CID management */
struct tquic_cid_manager;
struct tquic_cid_entry;
struct tquic_new_cid_frame;
struct tquic_retire_cid_frame;

/* CID generation and validation */
int tquic_cid_generate(struct tquic_cid *cid, u8 len);
int tquic_cid_generate_reset_token(const struct tquic_cid *cid, u8 *token);
bool tquic_cid_validate_reset_token(const struct tquic_cid *cid,
				    const u8 *token);

/* CID comparison and utilities */
int tquic_cid_cmp(const struct tquic_cid *a, const struct tquic_cid *b);
void tquic_cid_copy(struct tquic_cid *dst, const struct tquic_cid *src);
bool tquic_cid_is_zero(const struct tquic_cid *cid);

/* CID-to-connection lookup */
struct tquic_connection *tquic_cid_lookup(const struct tquic_cid *cid);
struct tquic_cid_entry *tquic_cid_lookup_entry(const struct tquic_cid *cid);

/* CID manager lifecycle */
struct tquic_cid_manager *tquic_cid_manager_create(
	struct tquic_connection *conn, u8 cid_len);
void tquic_cid_manager_destroy(struct tquic_cid_manager *mgr);

/* CID pool management */
int tquic_cid_pool_replenish(struct tquic_cid_manager *mgr);
struct tquic_cid_entry *tquic_cid_get_unused_local(struct tquic_cid_manager *mgr);

/* NEW_CONNECTION_ID frame handling */
int tquic_cid_build_new_cid_frame(struct tquic_cid_manager *mgr,
				  struct tquic_new_cid_frame *frame);
int tquic_cid_handle_new_cid(struct tquic_cid_manager *mgr,
			     u64 seq_num, u64 retire_prior_to,
			     const struct tquic_cid *cid,
			     const u8 *reset_token);

/* RETIRE_CONNECTION_ID frame handling */
int tquic_cid_build_retire_frame(struct tquic_cid_manager *mgr,
				 struct tquic_retire_cid_frame *frame);
int tquic_cid_handle_retire(struct tquic_cid_manager *mgr, u64 seq_num);
void tquic_cid_complete_retire(struct tquic_cid_manager *mgr, u64 seq_num);

/* CID rotation */
void tquic_cid_enable_rotation(struct tquic_cid_manager *mgr);
void tquic_cid_disable_rotation(struct tquic_cid_manager *mgr);
int tquic_cid_rotate_now(struct tquic_cid_manager *mgr);
void tquic_cid_on_packet_sent(struct tquic_cid_manager *mgr);

/* Per-path CID assignment for multipath */
int tquic_cid_assign_to_path(struct tquic_cid_manager *mgr,
			     struct tquic_path *path);
void tquic_cid_release_from_path(struct tquic_cid_manager *mgr,
				 struct tquic_path *path);
const struct tquic_cid *tquic_cid_get_for_path(struct tquic_cid_manager *mgr,
					       u32 path_id);

/* Preferred address CID handling */
int tquic_cid_set_preferred_addr(struct tquic_cid_manager *mgr,
				 const struct tquic_cid *cid,
				 const u8 *reset_token);
int tquic_cid_handle_preferred_addr(struct tquic_cid_manager *mgr,
				    const struct tquic_cid *cid,
				    const u8 *reset_token);

/* Active CID accessors */
const struct tquic_cid *tquic_cid_get_active_local(struct tquic_cid_manager *mgr);
const struct tquic_cid *tquic_cid_get_active_remote(struct tquic_cid_manager *mgr);
int tquic_cid_set_active_remote(struct tquic_cid_manager *mgr,
				const struct tquic_cid *cid);

/* Stateless reset handling */
int tquic_cid_get_reset_token(struct tquic_cid_manager *mgr,
			      const struct tquic_cid *cid,
			      u8 *token);
bool tquic_cid_check_stateless_reset(struct tquic_cid_manager *mgr,
				     const u8 *token);

/* Statistics */
void tquic_cid_get_stats(struct tquic_cid_manager *mgr,
			 u32 *local_count, u32 *remote_count,
			 u64 *local_seq);

/* CID subsystem initialization */
int __init tquic_cid_init(void);
void __exit tquic_cid_exit(void);

/* Bonding helper (used by path manager) */
void tquic_bond_path_failed(struct tquic_connection *conn,
			    struct tquic_path *path);
void tquic_bond_interface_down(struct tquic_connection *conn,
				struct net_device *dev);
void tquic_bond_path_recovered(struct tquic_connection *conn,
			       struct tquic_path *path);

struct tquic_bond_state *tquic_bond_init(struct tquic_connection *conn);
void tquic_bond_cleanup(struct tquic_bond_state *bond);
int tquic_bond_set_mode(struct tquic_connection *conn, u8 mode);
struct tquic_path *tquic_bond_select_path(struct tquic_connection *conn,
					  struct sk_buff *skb);

/*
 * UDP Tunnel Integration for WAN Bonding
 */

/* Forward declaration for UDP socket state */
struct tquic_udp_sock;

/* UDP socket lifecycle */
void tquic_udp_sock_put(struct tquic_udp_sock *us);

/* UDP socket connection */
int tquic_udp_connect(struct tquic_udp_sock *us,
		      struct sockaddr_storage *remote);

/* Receive path - deliver packets to connection */
int tquic_udp_deliver_to_conn(struct tquic_connection *conn,
			      struct tquic_path *path,
			      struct sk_buff *skb);

/* Transmit path */
int tquic_udp_xmit(struct tquic_udp_sock *us, struct sk_buff *skb);
int tquic_udp_xmit_gso(struct tquic_udp_sock *us, struct sk_buff *skb,
		       unsigned int gso_size);
int tquic_udp_sendmsg(struct tquic_udp_sock *us, const void *data, size_t len);

/* Checksum offload control */
int tquic_udp_set_csum_offload(struct tquic_udp_sock *us, bool enable);

/* Per-path UDP socket management for WAN bonding */
int tquic_udp_create_path_socket(struct tquic_connection *conn,
				 struct tquic_path *path);
void tquic_udp_destroy_path_socket(struct tquic_path *path);
int tquic_udp_xmit_on_path(struct tquic_connection *conn,
			   struct tquic_path *path,
			   struct sk_buff *skb);

/* inet_connection_sock integration */
int tquic_udp_icsk_bind(struct sock *sk, struct sockaddr *uaddr, int addr_len);

/* Module initialization */
int __init tquic_udp_init(void);
void __exit tquic_udp_exit(void);

/*
 * Timer and Recovery System
 */

/* Forward declarations for timer state */
struct tquic_timer_state;
struct tquic_recovery_state;
struct tquic_sent_packet;
struct tquic_pn_space;

/* Timer state lifecycle */
struct tquic_timer_state *tquic_timer_state_alloc(struct tquic_connection *conn);
void tquic_timer_state_free(struct tquic_timer_state *ts);

/* Idle timeout management */
void tquic_timer_set_idle(struct tquic_timer_state *ts);
void tquic_timer_reset_idle(struct tquic_timer_state *ts);

/* ACK delay timer management */
void tquic_timer_set_ack_delay(struct tquic_timer_state *ts);
void tquic_timer_cancel_ack_delay(struct tquic_timer_state *ts);

/* Loss detection timer */
void tquic_timer_update_loss_timer(struct tquic_timer_state *ts);

/* Probe timeout (PTO) timer */
void tquic_timer_update_pto(struct tquic_timer_state *ts);

/* Connection draining */
void tquic_timer_start_drain(struct tquic_timer_state *ts);

/* Keep-alive timer */
void tquic_timer_set_keepalive(struct tquic_timer_state *ts, u32 interval_ms);
void tquic_timer_reset_keepalive(struct tquic_timer_state *ts);

/* Packet pacing (BBR support) */
void tquic_timer_schedule_pacing(struct tquic_timer_state *ts, u32 bytes_to_send);
void tquic_timer_set_pacing_rate(struct tquic_timer_state *ts, u64 rate);
bool tquic_timer_can_send_paced(struct tquic_timer_state *ts);

/* Path validation timers */
void tquic_timer_start_path_validation(struct tquic_connection *conn,
				       struct tquic_path *path);
void tquic_timer_path_validated(struct tquic_connection *conn,
				struct tquic_path *path);

/* Packet tracking for recovery */
int tquic_timer_on_packet_sent(struct tquic_timer_state *ts, int pn_space,
			       u64 pkt_num, u32 bytes, bool ack_eliciting,
			       bool in_flight, u32 frames);
int tquic_timer_on_ack_received(struct tquic_timer_state *ts, int pn_space,
				u64 largest_acked, u64 ack_delay_us,
				u64 *ack_ranges, int num_ranges);

/* Retransmission handling */
int tquic_timer_get_lost_packets(struct tquic_timer_state *ts, int pn_space,
				 struct list_head *lost_list, int max_count);
void tquic_timer_mark_retransmitted(struct tquic_timer_state *ts, int pn_space,
				    u64 old_pkt_num, u64 new_pkt_num);

/* Statistics */
void tquic_timer_get_rtt_stats(struct tquic_timer_state *ts,
			       u64 *smoothed, u64 *variance,
			       u64 *min, u64 *latest);
void tquic_timer_get_recovery_stats(struct tquic_timer_state *ts,
				    u64 *bytes_in_flight, u64 *cwnd,
				    u64 *ssthresh, u32 *pto_count);

/* Timer subsystem initialization */
int __init tquic_timer_init(void);
void __exit tquic_timer_exit(void);

/*
 * =============================================================================
 * Path MTU Discovery (DPLPMTUD) - RFC 8899
 * =============================================================================
 */

/* PMTUD state machine states */
enum tquic_pmtud_state {
	TQUIC_PMTUD_DISABLED = 0,
	TQUIC_PMTUD_BASE,
	TQUIC_PMTUD_SEARCHING,
	TQUIC_PMTUD_SEARCH_COMPLETE,
	TQUIC_PMTUD_ERROR,
};

/* PMTUD constants */
#define TQUIC_PMTUD_BASE_MTU		1200	/* QUIC minimum MTU */
#define TQUIC_PMTUD_MAX_MTU_DEFAULT	1500	/* Ethernet MTU */
#define TQUIC_PMTUD_MAX_MTU_JUMBO	9000	/* Jumbo frames */

/* PMTUD path lifecycle */
int tquic_pmtud_init_path(struct tquic_path *path);
void tquic_pmtud_release_path(struct tquic_path *path);

/* PMTUD control */
int tquic_pmtud_start(struct tquic_path *path);
void tquic_pmtud_stop(struct tquic_path *path);

/* PMTUD probe events */
void tquic_pmtud_on_probe_ack(struct tquic_path *path, u64 pkt_num,
			      u32 probed_size);
void tquic_pmtud_on_probe_lost(struct tquic_path *path, u64 pkt_num);

/* Black hole detection */
void tquic_pmtud_on_packet_loss(struct tquic_path *path, u32 pkt_size);
void tquic_pmtud_on_ack(struct tquic_path *path, u32 pkt_size);

/* MTU accessors */
u32 tquic_pmtud_get_mtu(struct tquic_path *path);
int tquic_pmtud_set_max_mtu(struct tquic_path *path, u32 max_mtu);

/* Sysctl accessors */
int tquic_pmtud_sysctl_enabled(void);
int tquic_pmtud_sysctl_probe_interval(void);

/* PMTUD subsystem initialization */
int __init tquic_pmtud_init(void);
void __exit tquic_pmtud_exit(void);

/*
 * =============================================================================
 * Coupled Multipath Congestion Control API
 * =============================================================================
 *
 * These functions provide control over the coupled CC algorithms
 * (OLIA/LIA/BALIA) which are critical for fair and efficient WAN bonding.
 */

/**
 * enum tquic_coupled_algo - Coupled congestion control algorithm selection
 * @TQUIC_COUPLED_NONE: No coupled CC (per-path independent CC)
 * @TQUIC_COUPLED_LIA: Linked Increases Algorithm - basic coupled CC
 * @TQUIC_COUPLED_OLIA: Opportunistic LIA (RFC 6356) - recommended default
 * @TQUIC_COUPLED_BALIA: Balanced Linked Adaptation - adaptive coupling
 */
enum tquic_coupled_algo {
	TQUIC_COUPLED_NONE = -1,
	TQUIC_COUPLED_LIA = 0,
	TQUIC_COUPLED_OLIA,
	TQUIC_COUPLED_BALIA,
};

/**
 * struct tquic_coupled_stats - Coupled CC statistics
 * @total_cwnd: Aggregate cwnd across all paths (bytes)
 * @total_bw: Aggregate bandwidth estimate (bytes/s)
 * @best_rtt: Best (minimum) RTT among all paths (us)
 * @max_rtt: Worst (maximum) RTT among all paths (us)
 * @num_subflows: Number of active subflows/paths
 * @sbd_detected: True if shared bottleneck detected
 * @sbd_correlation: SBD correlation value (0-1000, higher = more correlated)
 * @global_alpha: Current coupled alpha value (scaled)
 * @pooling_benefit: Measured resource pooling benefit
 */
struct tquic_coupled_stats {
	u64 total_cwnd;
	u64 total_bw;
	u32 best_rtt;
	u32 max_rtt;
	u32 num_subflows;
	bool sbd_detected;
	u32 sbd_correlation;
	u64 global_alpha;
	u64 pooling_benefit;
};

/**
 * struct tquic_subflow_stats - Per-subflow statistics for coupled CC
 * @path_id: Path identifier
 * @cwnd: Current congestion window
 * @ssthresh: Slow start threshold
 * @rtt_us: Smoothed RTT
 * @rtt_min: Minimum RTT observed
 * @delivered: Total bytes delivered
 * @lost: Total bytes lost
 * @in_flight: Bytes currently in flight
 * @in_slow_start: True if in slow start phase
 * @alpha: Per-subflow alpha value
 */
struct tquic_subflow_stats {
	u32 path_id;
	u64 cwnd;
	u64 ssthresh;
	u32 rtt_us;
	u32 rtt_min;
	u64 delivered;
	u64 lost;
	u64 in_flight;
	bool in_slow_start;
	u64 alpha;
};

/* Set/get the coupled CC algorithm for a connection */
int tquic_coupled_set_algo(struct tquic_connection *conn,
			   enum tquic_coupled_algo algo);
int tquic_coupled_get_algo(struct tquic_connection *conn);

/*
 * Coupled CC coordination API (net/tquic/cong/tquic_cong.c)
 *
 * These functions manage the coupled CC layer which coordinates
 * CWND across multiple paths for fairness at shared bottlenecks.
 */

/**
 * tquic_cong_enable_coupling - Enable coupled CC for a connection
 * @conn: Connection to enable coupling on
 * @algo: Coupled algorithm (OLIA, LIA, or BALIA)
 *
 * Per CONTEXT.md: "Coupled CC is opt-in via sysctl/sockopt (per-path CC by default)"
 * Per RESEARCH.md: "OLIA as default" when coupled CC is enabled.
 *
 * Return: 0 on success, -errno on failure
 */
int tquic_cong_enable_coupling(struct tquic_connection *conn,
			       enum tquic_coupled_algo algo);

/**
 * tquic_cong_disable_coupling - Disable coupled CC for a connection
 * @conn: Connection to disable coupling on
 *
 * Reverts to per-path independent CC. Each path continues using
 * its assigned CC algorithm without coupled coordination.
 */
void tquic_cong_disable_coupling(struct tquic_connection *conn);

/**
 * tquic_cong_is_coupling_enabled - Check if coupled CC is enabled
 * @conn: Connection to check
 *
 * Return: true if coupled CC is active, false otherwise
 */
bool tquic_cong_is_coupling_enabled(struct tquic_connection *conn);

/* Get coupled CC statistics */
int tquic_coupled_get_stats(struct tquic_connection *conn,
			    struct tquic_coupled_stats *stats);

/* Get per-subflow statistics */
int tquic_coupled_get_subflow_stats(struct tquic_connection *conn,
				    u32 path_id,
				    struct tquic_subflow_stats *stats);

/* Enable/disable CUBIC integration in coupled CC */
int tquic_coupled_set_cubic(struct tquic_connection *conn, bool enable);

/* Enable/disable BBR integration in coupled CC */
int tquic_coupled_set_bbr(struct tquic_connection *conn, bool enable);

/* Enable/disable shared bottleneck detection */
int tquic_coupled_set_sbd(struct tquic_connection *conn, bool enable);

/* Force recalculation of global alpha */
int tquic_coupled_force_alpha_update(struct tquic_connection *conn);


/*
 * IPv6 Support for WAN Bonding
 */

#if IS_ENABLED(CONFIG_IPV6)

#include <linux/ipv6.h>
#include <linux/in6.h>
#include <net/ipv6.h>

/**
 * struct tquic6_sock - IPv6 TQUIC socket structure
 * @tquic: Base TQUIC socket
 * @inet6: IPv6 specific info
 */
struct tquic6_sock {
	struct tquic_sock	tquic;
	struct ipv6_pinfo	inet6;
};

static inline struct ipv6_pinfo *tquic6_inet6_sk(struct sock *sk)
{
	return &((struct tquic6_sock *)sk)->inet6;
}

/* IPv6 initialization */
int __init tquic6_init(void);
void __exit tquic6_exit(void);

/* IPv6 address discovery for bonding */
int tquic_v6_discover_addresses(struct tquic_connection *conn,
				struct sockaddr_storage *addrs,
				int max_addrs);

/* IPv6 path management */
int tquic_v6_add_path(struct tquic_connection *conn,
		      struct sockaddr_in6 *local,
		      struct sockaddr_in6 *remote);

/**
 * struct tquic_happy_eyeballs_config - Happy Eyeballs configuration
 * @resolution_delay_ms: Delay before IPv4 fallback attempt (RFC 8305)
 * @connection_timeout_ms: Total connection timeout
 * @prefer_ipv6: Whether to prefer IPv6 connections
 * @allow_fallback: Whether to allow IPv4 fallback
 *
 * Happy Eyeballs (RFC 8305) provides fast fallback from IPv6 to IPv4
 * when IPv6 connectivity is broken or slow.
 */
struct tquic_happy_eyeballs_config {
	unsigned int resolution_delay_ms;
	unsigned int connection_timeout_ms;
	bool prefer_ipv6;
	bool allow_fallback;
};

/* Happy Eyeballs defaults per RFC 8305 */
#define TQUIC_HE_RESOLUTION_DELAY_MS	50
#define TQUIC_HE_CONNECTION_TIMEOUT_MS	30000

/* IPv6 flow label utilities */
static inline __be32 tquic_v6_make_flowlabel(struct sock *sk,
					     struct tquic_path *path)
{
	u32 hash;

	if (!path || path->remote_addr.ss_family != AF_INET6)
		return 0;

	/* Generate based on path addresses for consistent routing */
	hash = jhash(&path->local_addr, sizeof(struct sockaddr_in6), 0);
	hash = jhash(&path->remote_addr, sizeof(struct sockaddr_in6), hash);

	return cpu_to_be32(hash & IPV6_FLOWLABEL_MASK);
}

/* Check if path is IPv6 */
static inline bool tquic_path_is_ipv6(const struct tquic_path *path)
{
	return path->remote_addr.ss_family == AF_INET6;
}

/* Check if path uses IPv4-mapped IPv6 address (dual-stack) */
static inline bool tquic_path_is_v4mapped(const struct tquic_path *path)
{
	if (path->remote_addr.ss_family == AF_INET6) {
		const struct sockaddr_in6 *sin6;
		sin6 = (const struct sockaddr_in6 *)&path->remote_addr;
		return ipv6_addr_v4mapped(&sin6->sin6_addr);
	}
	return false;
}

/* Get effective address family for routing decisions */
static inline sa_family_t tquic_path_effective_family(const struct tquic_path *path)
{
	if (tquic_path_is_v4mapped(path))
		return AF_INET;
	return path->remote_addr.ss_family;
}

/* IPv6 extension header overhead calculation */
static inline unsigned int tquic_v6_ext_hdr_overhead(struct sock *sk)
{
	struct ipv6_pinfo *np = tquic6_inet6_sk(sk);
	struct ipv6_txoptions *opt;
	unsigned int len = 0;

	rcu_read_lock();
	opt = rcu_dereference(np->opt);
	if (opt)
		len = opt->opt_flen + opt->opt_nflen;
	rcu_read_unlock();

	return len;
}

/* IPv6 path MTU calculation */
static inline u32 tquic_v6_path_mtu(struct sock *sk, u32 dst_mtu)
{
	u32 overhead = sizeof(struct ipv6hdr) + sizeof(struct udphdr);

	if (sk)
		overhead += tquic_v6_ext_hdr_overhead(sk);

	if (dst_mtu <= overhead)
		return 1200;  /* QUIC minimum */

	return dst_mtu - overhead;
}

/* Bonding path recovery notification */
void tquic_bond_path_recovered(struct tquic_connection *conn,
			       struct tquic_path *path);

#else /* !CONFIG_IPV6 */

/* Stubs when IPv6 is not enabled */
static inline int tquic6_init(void) { return 0; }
static inline void tquic6_exit(void) { }

static inline int tquic_v6_discover_addresses(struct tquic_connection *conn,
					      struct sockaddr_storage *addrs,
					      int max_addrs)
{
	return 0;
}

static inline bool tquic_path_is_ipv6(const struct tquic_path *path)
{
	return false;
}

static inline bool tquic_path_is_v4mapped(const struct tquic_path *path)
{
	return false;
}

static inline sa_family_t tquic_path_effective_family(const struct tquic_path *path)
{
	return path->remote_addr.ss_family;
}

#endif /* CONFIG_IPV6 */

/*
 * =============================================================================
 * TCP-over-QUIC Tunnel Termination (VPS Endpoint)
 * =============================================================================
 *
 * These functions implement VPS-side tunnel termination for TCP-over-QUIC.
 * The VPS receives encapsulated TCP from routers and forwards to internet.
 */

/* Forward declarations for tunnel types */
struct tquic_tunnel;
struct tquic_client;

/* Tunnel lifecycle */
struct tquic_tunnel *tquic_tunnel_create(struct tquic_client *client,
					 struct tquic_stream *stream,
					 const u8 *header_data,
					 size_t header_len);
struct tquic_tunnel *tquic_tunnel_create_tproxy(struct tquic_client *client,
						struct tquic_stream *stream,
						const u8 *header_data,
						size_t header_len);
void tquic_tunnel_close(struct tquic_tunnel *tunnel);
void tquic_tunnel_established(struct tquic_tunnel *tunnel);

/* ICMP passthrough */
int tquic_tunnel_icmp_forward(struct tquic_tunnel *tunnel,
			      struct sk_buff *skb, int direction);
int tquic_tunnel_handle_icmp_error(struct tquic_tunnel *tunnel,
				   u8 type, u8 code, u32 info);

/* Tunnel accessor functions */
u8 tquic_tunnel_get_traffic_class(struct tquic_tunnel *tunnel);
__be16 tquic_tunnel_get_dest_port(struct tquic_tunnel *tunnel);
int tquic_tunnel_get_dest_addr(struct tquic_tunnel *tunnel,
			       struct sockaddr_storage *addr);
int tquic_tunnel_get_stats(struct tquic_tunnel *tunnel,
			   u64 *bytes_tx, u64 *bytes_rx,
			   u64 *packets_tx, u64 *packets_rx);
bool tquic_tunnel_is_tproxy(struct tquic_tunnel *tunnel);

/* Tunnel subsystem init/exit */
int __init tquic_tunnel_init(void);
void __exit tquic_tunnel_exit(void);

/*
 * =============================================================================
 * QoS Traffic Classification
 * =============================================================================
 *
 * Traffic classification for tc HTB scheduling and DSCP marking.
 */

/* Traffic class constants */
#define TQUIC_TC_REALTIME	0
#define TQUIC_TC_INTERACTIVE	1
#define TQUIC_TC_BULK		2
#define TQUIC_TC_BACKGROUND	3

/* QoS classification */
int tquic_qos_classify(void *tunnel_ptr, u8 router_hint);
void tquic_qos_mark_skb(struct sk_buff *skb, void *tunnel_ptr);
u8 tquic_qos_get_dscp(u8 traffic_class);
u32 tquic_qos_get_priority(u8 traffic_class);

/* QoS statistics */
void tquic_qos_update_stats(u8 traffic_class, u64 bytes);
void tquic_qos_get_stats(u8 traffic_class, u64 *packets, u64 *bytes, u64 *drops);

/* QoS subsystem init/exit */
int __init tquic_qos_init(void);
void __exit tquic_qos_exit(void);

/*
 * =============================================================================
 * Zero-Copy Splice Forwarding
 * =============================================================================
 *
 * Data forwarding between QUIC streams and TCP sockets using splice.
 */

/* Forwarding directions */
#define TQUIC_FORWARD_TX	0	/* QUIC stream -> TCP socket */
#define TQUIC_FORWARD_RX	1	/* TCP socket -> QUIC stream */

/* Zero-copy splice forwarding */
ssize_t tquic_forward_splice(struct tquic_tunnel *tunnel, int direction);

/* Hairpin traffic detection and routing */
struct tquic_client *tquic_forward_check_hairpin(struct tquic_tunnel *tunnel);
ssize_t tquic_forward_hairpin(struct tquic_tunnel *tunnel,
			      struct tquic_client *peer);

/* Client registration for hairpin detection */
int tquic_forward_register_client(struct tquic_client *client,
				  const struct sockaddr_storage *addr);
void tquic_forward_unregister_client(struct tquic_client *client);

/* NAT setup verification */
int tquic_forward_setup_nat(struct net_device *dev);

/* MTU handling */
u32 tquic_forward_get_mtu(struct tquic_tunnel *tunnel);
int tquic_forward_signal_mtu(struct tquic_tunnel *tunnel, u32 new_mtu);

/* TCP callback setup */
int tquic_forward_setup_tcp_callbacks(struct tquic_tunnel *tunnel);

/* GRO/GSO verification */
int tquic_forward_check_gro_gso(struct net_device *dev);

/* Forwarding subsystem init/exit */
int __init tquic_forward_init(void);
void __exit tquic_forward_exit(void);

/*
 * =============================================================================
 * Zero-Copy I/O Support
 * =============================================================================
 *
 * High-performance I/O paths using zero-copy techniques:
 *   - MSG_ZEROCOPY for sendmsg with completion notification
 *   - sendfile/sendpage support via page references
 *   - splice support for zero-copy pipe transfer
 *   - Direct page placement for receive path
 *
 * Reference: TCP zerocopy implementation (net/ipv4/tcp.c)
 */

/* MSG_ZEROCOPY support for sendmsg */
int tquic_sendmsg_zerocopy(struct sock *sk, struct msghdr *msg, size_t len,
			   struct tquic_stream *stream);
int tquic_check_zerocopy_flag(struct sock *sk, struct msghdr *msg, int flags);

/* sendfile/sendpage support */
ssize_t tquic_sendpage(struct socket *sock, struct page *page,
		       int offset, size_t size, int flags);

/* splice support */
ssize_t tquic_splice_read(struct socket *sock, loff_t *ppos,
			  struct pipe_inode_info *pipe, size_t len,
			  unsigned int flags);

/* Receive-side optimization */
size_t tquic_recvmsg_peek_size(struct sock *sk, struct tquic_stream *stream);
struct page *tquic_rx_page_pool_alloc(struct tquic_connection *conn);
struct sk_buff *tquic_rx_build_skb_from_page(struct tquic_connection *conn,
					     struct page *page,
					     unsigned int offset,
					     unsigned int len);

/* Socket option support */
int tquic_set_zerocopy(struct sock *sk, int val);
int tquic_get_zerocopy(struct sock *sk);

/* Completion notification */
void tquic_zc_complete(struct sock *sk, u32 id);
void tquic_zc_abort(struct sock *sk, u32 id, int err);

/* Zerocopy state management */
int tquic_zc_state_alloc(struct tquic_connection *conn);
void tquic_zc_state_free(struct tquic_connection *conn);

/* SKB zerocopy helpers */
int tquic_skb_zerocopy_setup(struct sk_buff *skb, struct page *page,
			     unsigned int offset, unsigned int len);
int tquic_skb_orphan_frags_rx(struct sk_buff *skb, gfp_t gfp);

#endif /* _NET_TQUIC_H */
