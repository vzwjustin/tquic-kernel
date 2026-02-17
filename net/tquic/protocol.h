/* SPDX-License-Identifier: GPL-2.0 */
/*
 * TQUIC Internal Definitions
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * This header provides internal socket structure definitions and
 * locking documentation for the TQUIC subsystem. It follows the
 * pattern established by net/mptcp/protocol.h.
 *
 * LOCKING:
 * ========
 * Lock hierarchy (acquire in this order, never reverse):
 *
 *   1. sk->sk_lock.slock (socket lock)
 *        |
 *        +-- 2. conn->lock (connection state lock)
 *                  |
 *                  +-- 3. path->state_lock (per-path state)
 *                            |
 *                            +-- 4. cc->lock (congestion control)
 *                                      |
 *                                      +-- 5. stream->lock (per-stream)
 *
 * Socket lock (sk->sk_lock):
 *   - Standard socket lock, use lock_sock()/release_sock()
 *   - Required for most socket operations
 *   - Can sleep (process context only)
 *
 * Connection lock (conn->lock):
 *   - Spinlock (bh_lock variant for softirq safety)
 *   - Protects: state transitions, path list, global seqnums
 *   - Use spin_lock_bh(&conn->lock)
 *
 * Path state lock (path->state_lock):
 *   - Per-path spinlock
 *   - Protects: path state, RTT samples, congestion state
 *   - Never hold multiple path locks simultaneously
 *
 * Congestion control lock (cc->lock):
 *   - Per-path CC spinlock
 *   - Protects: cwnd, ssthresh, pacing rate
 *
 * Stream lock (stream->lock):
 *   - Per-stream spinlock
 *   - Protects: stream state, flow control, buffers
 *   - Never hold multiple stream locks simultaneously
 *
 * Reference counting:
 *   - conn: refcount_t, use tquic_conn_get/put
 *   - path: refcount_t, use tquic_path_get/put
 *   - stream: refcount_t, RCU for lookup
 *
 * Error paths:
 *   - Use goto cleanup pattern
 *   - Release locks in reverse order
 *   - Drop references before returning
 */

#ifndef _NET_TQUIC_PROTOCOL_H
#define _NET_TQUIC_PROTOCOL_H

#include <linux/spinlock.h>
#include <linux/lockdep.h>
#include <linux/snmp.h>
#include <net/inet_connection_sock.h>
#include <net/netns/generic.h>
#include <net/tquic.h>

/* Forward declarations */
struct tquic_connection;
struct tquic_mib;
struct tquic_error_ring;

/*
 * Per-network namespace TQUIC data (for out-of-tree module builds)
 *
 * This structure is accessed via netns_generic mechanism since we cannot
 * modify struct net or struct netns_mib for out-of-tree modules.
 */
/* Scheduler/CC name limits for per-netns storage */
#define TQUIC_NET_SCHED_NAME_MAX 16
#define TQUIC_NET_CC_NAME_MAX 16

struct tquic_net {
	/* Sysctl parameters */
	int enabled;
	int bond_mode;
	int max_paths;
	int reorder_window;
	int probe_interval;
	int failover_timeout;
	int idle_timeout;
	int initial_rtt;
	int initial_cwnd;
	int debug_level;

	/* Scheduler/CC per-netns configuration */
	struct tquic_sched_ops __rcu *default_scheduler;
	char sched_name[TQUIC_NET_SCHED_NAME_MAX];
	struct tquic_cong_ops __rcu *default_cong;
	char cc_name[TQUIC_NET_CC_NAME_MAX];

	/* BBR auto-selection threshold (ms) */
	u32 bbr_rtt_threshold_ms;

	/* Feature flags */
	bool coupled_enabled;
	bool ecn_enabled;
	int ecn_beta;
	bool pacing_enabled;
	int path_degrade_threshold;
	bool grease_enabled;
	int preferred_address_enabled; /* -1 = use global, 0/1 = disabled/enabled */
	int prefer_preferred_address; /* -1 = use global, 0/1 = disabled/enabled */
	int additional_addresses_enabled; /* -1 = use global, 0/1 = disabled/enabled */
	int additional_addresses_max; /* Max addresses (0 = use global) */

	/* Per-netns MIB statistics (out-of-tree replacement for net->mib) */
	struct tquic_mib __percpu *mib;

	/* Proc entries */
	struct proc_dir_entry *proc_net_tquic;

	/* Error ring buffer for /proc/net/tquic_errors */
	struct tquic_error_ring *error_ring;

	/* Sysctl header */
	struct ctl_table_header *sysctl_header;

	/* Connection tracking for this namespace */
	struct list_head connections;
	spinlock_t conn_lock;
	atomic_t conn_count;

	/* Statistics */
	atomic64_t total_tx_bytes;
	atomic64_t total_rx_bytes;
	atomic64_t total_connections;
};

/* Network namespace ID (defined in tquic_proto.c) */
extern unsigned int tquic_net_id;

/* Access per-netns data */
static inline struct tquic_net *tquic_pernet(const struct net *net)
{
	return net_generic(net, tquic_net_id);
}
struct tquic_path;
struct tquic_stream;
struct tquic_path_manager;

/*
 * TQUIC connection states
 * Note: These mirror the enum in include/net/tquic.h for consistency
 */
enum tquic_conn_state_internal {
	TQUIC_CONN_STATE_IDLE = 0,
	TQUIC_CONN_STATE_CONNECTING,
	TQUIC_CONN_STATE_HANDSHAKE,
	TQUIC_CONN_STATE_CONNECTED,
	TQUIC_CONN_STATE_CLOSING,
	TQUIC_CONN_STATE_DRAINING,
	TQUIC_CONN_STATE_CLOSED,
};

/*
 * TQUIC socket structure
 *
 * IMPORTANT: inet_connection_sock MUST be the first member.
 * This enables casting between struct sock and tquic_sock via
 * the standard inet_csk() and then container_of patterns.
 *
 * The public definition in include/net/tquic.h is the canonical
 * source. This header provides internal documentation and any
 * internal-only extensions.
 */

/*
 * tquic_sk - Convert struct sock to tquic_sock
 * @sk: socket to convert
 *
 * This macro is already defined in include/net/tquic.h.
 * Re-declaring here for documentation purposes.
 *
 * Usage:
 *   struct tquic_sock *tsk = tquic_sk(sk);
 *
 * Note: tquic_sk is already defined in include/net/tquic.h, so we don't
 * redefine it here. This comment is kept for documentation.
 */

/*
 * IPv6 TQUIC socket structure
 * Used for AF_INET6 sockets
 *
 * Note: This is already defined in include/net/tquic.h (struct tquic6_sock).
 * The tquic_ipv6.c file has its own inline definition which should be
 * migrated to use this header in future cleanup.
 */

/*
 * tquic_inet6_sk - Get IPv6 pinfo from TQUIC socket
 * @sk: socket to get IPv6 info from
 *
 * For IPv6 sockets, retrieves the ipv6_pinfo structure.
 * The socket must be an AF_INET6 socket.
 */
#if IS_ENABLED(CONFIG_IPV6)
static inline struct ipv6_pinfo *tquic_inet6_sk(const struct sock *sk)
{
	return &((struct tquic6_sock *)sk)->inet6;
}
#endif

/*
 * Socket flags
 */
#define TQUIC_F_MULTIPATH_ENABLED BIT(0)
#define TQUIC_F_BONDING_ENABLED BIT(1)
#define TQUIC_F_SERVER_MODE BIT(2)
#define TQUIC_F_HANDSHAKE_DONE BIT(3)
#define TQUIC_F_CLOSING BIT(4)
#define TQUIC_F_ZERO_RTT_ENABLED BIT(7) /* 0-RTT early data enabled */
#define TQUIC_F_ZERO_RTT_ACCEPTED BIT(8) /* 0-RTT accepted by server */
#define TQUIC_F_HAS_SESSION_TICKET BIT(9) /* Valid session ticket for 0-RTT */
#define TQUIC_F_SERVER_HANDSHAKE_STARTED \
	BIT(10) /* Server handshake initiated */
#define TQUIC_F_PM_DISABLED BIT(11) /* Path manager init failed */

/*
 * =============================================================================
 * INLINE LOCK DOCUMENTATION
 * =============================================================================
 *
 * This section provides detailed inline documentation for each lock field
 * in the TQUIC data structures. These comments should be treated as the
 * authoritative reference for lock semantics and ordering.
 *
 * The structures are defined in include/net/tquic.h but their locking
 * semantics are documented here for maintainability.
 */

/*
 * struct tquic_connection lock fields:
 * ------------------------------------
 *
 * conn->lock (spinlock_t):
 *
 *   Main connection state lock. This is a spinlock using BH variants
 *   for softirq safety.
 *
 *   Protects:
 *     - state transitions (conn->state)
 *     - Path list modifications (conn->paths, conn->active_path)
 *     - Connection ID changes (conn->scid, conn->dcid)
 *     - Global sequence numbers
 *     - Stream tree modifications (conn->streams)
 *     - Flow control state (conn->max_data_*, conn->data_*)
 *
 *   Lock ordering: sk->sk_lock > conn->lock
 *   Context: softirq-safe, use spin_lock_bh()/spin_unlock_bh()
 *   Nesting: conn->lock > path->state_lock > stream->lock
 *
 *   Never hold while sleeping. Never hold multiple conn->locks.
 *   Use tquic_conn_lock()/tquic_conn_unlock() helpers.
 *
 * conn->refcnt (refcount_t):
 *
 *   Reference counter for connection lifecycle.
 *   Use tquic_conn_get()/tquic_conn_put() helpers.
 *   Connection is freed when refcount drops to zero.
 */

/*
 * struct tquic_path lock fields (per path->state_lock):
 * -----------------------------------------------------
 *
 * path->state_lock (spinlock_t):
 *
 *   Per-path spinlock for path-specific state protection.
 *
 *   Protects:
 *     - Path state transitions (path->state)
 *     - RTT samples and statistics (path->stats.rtt_*)
 *     - Path MTU (path->mtu)
 *     - Priority and weight (path->priority, path->weight)
 *     - Probe state (path->probe_count, path->challenge_data)
 *
 *   Lock ordering: conn->lock > path->state_lock
 *   Context: softirq-safe (may be called from timer/softirq)
 *
 *   Never hold multiple path locks simultaneously.
 *   When updating multiple paths, acquire conn->lock instead.
 */

/*
 * struct tquic_stream lock fields:
 * --------------------------------
 *
 * stream->lock (spinlock_t - if present):
 *
 *   Per-stream spinlock for stream-specific state.
 *   Note: Stream locking strategy may use conn->lock instead
 *   for simplicity in initial implementation.
 *
 *   Protects:
 *     - Stream state transitions (stream->state)
 *     - Send/receive offsets (stream->send_offset, stream->recv_offset)
 *     - Flow control limits (stream->max_send_data, stream->max_recv_data)
 *     - Buffer access (stream->send_buf, stream->recv_buf) - with care
 *     - FIN state (stream->fin_sent, stream->fin_received)
 *
 *   Lock ordering: conn->lock > path->state_lock > stream->lock
 *
 *   Buffer queues (sk_buff_head) have their own internal locks for
 *   queue operations. Stream lock protects metadata and state, not
 *   individual buffer operations.
 *
 *   Never hold multiple stream locks simultaneously.
 *   For operations spanning streams, acquire conn->lock instead.
 */

/*
 * struct tquic_sock lock notes:
 * -----------------------------
 *
 * The socket lock (sk->sk_lock) is the top-level lock.
 * Access via lock_sock(sk)/release_sock(sk) for process context,
 * or bh_lock_sock()/bh_unlock_sock() for softirq context.
 *
 * tquic_sock fields protected by socket lock:
 *   - conn (pointer to connection)
 *   - bind_addr, connect_addr
 *   - accept_queue (list operations)
 *   - accept_queue_len
 *   - default_stream
 *   - nodelay and other socket options
 *
 * The accept_queue may use sk_lock.slock for softirq-safe access
 * when checking queue state from incoming packet handling.
 */

/*
 * Connection lock helpers
 *
 * These provide softirq-safe locking for connection state.
 * Always use these instead of raw spinlock operations.
 */
static inline void tquic_conn_lock(struct tquic_connection *conn)
{
	spin_lock_bh(&conn->lock);
}

static inline void tquic_conn_unlock(struct tquic_connection *conn)
{
	spin_unlock_bh(&conn->lock);
}

/*
 * Socket owned by user check
 *
 * Returns true if the socket lock is held by the user (process context).
 * Used to defer operations that cannot be done in softirq context.
 */
static inline bool tquic_sk_owned_by_user(const struct sock *sk)
{
	return sock_owned_by_user(sk);
}

/*
 * Socket data lock helpers
 *
 * For protecting socket data that may be accessed from both
 * process context and softirq context.
 */
#define tquic_data_lock(sk) spin_lock_bh(&(sk)->sk_lock.slock)
#define tquic_data_unlock(sk) spin_unlock_bh(&(sk)->sk_lock.slock)

/*
 * Debug helpers
 */
#ifdef CONFIG_DEBUG_NET
static inline void tquic_sk_owned_by_me(const struct tquic_sock *tsk)
{
	sock_owned_by_me((const struct sock *)tsk);
}
#else
static inline void tquic_sk_owned_by_me(const struct tquic_sock *tsk)
{
}
#endif

/*
 * Lockdep class keys for TQUIC socket locks
 *
 * These are used to distinguish lock instances so lockdep can properly
 * validate locking patterns between different socket types (IPv4 vs IPv6)
 * and different lock levels (socket lock vs connection lock).
 *
 * Keys are indexed: [0] = IPv4, [1] = IPv6
 */
extern struct lock_class_key tquic_slock_keys[2];
extern struct lock_class_key tquic_lock_keys[2];

/*
 * Connection lock class keys
 * Separate from socket locks for proper nesting validation
 */
extern struct lock_class_key tquic_conn_lock_key;
extern struct lock_class_key tquic_path_lock_key;
extern struct lock_class_key tquic_stream_lock_key;

/*
 * Global connection table and memory caches (tquic_main.c)
 *
 * Connection hashtable for fast lookup by CID or 4-tuple.
 * SLAB caches for frequently allocated objects.
 */
extern struct rhashtable tquic_conn_table;
extern const struct rhashtable_params tquic_conn_params;
extern struct kmem_cache *tquic_conn_cache;
extern struct kmem_cache *tquic_stream_cache;
extern struct kmem_cache *tquic_path_cache;
extern struct kmem_cache *tquic_rx_buf_cache;

/*
 * Stream reference counting (tquic_stream.c)
 */
bool tquic_stream_get(struct tquic_stream *stream);
void tquic_stream_put(struct tquic_stream *stream);

/*
 * Handshake functions (tquic_handshake.c)
 *
 * These functions implement TLS 1.3 handshake via net/handshake
 * delegation to the tlshd userspace daemon.
 */
int tquic_start_handshake(struct sock *sk);
int tquic_wait_for_handshake(struct sock *sk, u32 timeout_ms);
void tquic_handshake_cleanup(struct sock *sk);
void tquic_handshake_done(void *data, int status, key_serial_t peerid);
bool tquic_handshake_in_progress(struct sock *sk);

/*
 * 0-RTT Early Data functions (tquic_handshake.c)
 *
 * These functions implement TLS 1.3 0-RTT early data support
 * per RFC 9001 Sections 4.6-4.7.
 */
int tquic_attempt_zero_rtt(struct sock *sk, const char *server_name,
			   u8 server_name_len);
void tquic_handle_zero_rtt_response(struct sock *sk, bool accepted);
int tquic_store_session_ticket(struct sock *sk, const char *server_name,
			       u8 server_name_len, const u8 *ticket_data,
			       u32 ticket_len, const u8 *psk, u32 psk_len,
			       u16 cipher_suite, u32 max_age);

/*
 * =============================================================================
 * UDP LISTENER REGISTRATION
 * =============================================================================
 *
 * These functions register/unregister listening sockets for incoming
 * QUIC connections. The listener table is used by the UDP receive path
 * to demultiplex incoming Initial packets to the correct listener.
 */

/* Listener registration (tquic_udp.c) */
int tquic_register_listener(struct sock *sk);
void tquic_unregister_listener(struct sock *sk);

/* Listener lookup (tquic_udp.c) */
struct sock *tquic_lookup_listener(const struct sockaddr_storage *local_addr);
struct sock *
tquic_lookup_listener_net(struct net *net,
			  const struct sockaddr_storage *local_addr);

/* Listener flag for tquic_sock.flags */
#define TQUIC_F_LISTENER_REGISTERED BIT(5)

/*
 * =============================================================================
 * SERVER HANDSHAKE
 * =============================================================================
 *
 * Server-side handshake functions for accepting incoming connections.
 */

/* Server handshake (tquic_handshake.c) */
int tquic_server_handshake(struct sock *listener_sk,
			   struct sk_buff *initial_pkt,
			   struct sockaddr_storage *client_addr);

/* Server PSK callback for TLS layer (tquic_handshake.c) */
int tquic_server_psk_callback(struct sock *sk, const char *identity,
			      size_t identity_len, u8 *psk);

/* Server PSK handshake with rate limiting (tquic_handshake.c) */
int tquic_server_hello_psk(struct sock *sk, struct sk_buff *initial_pkt,
			   struct sockaddr_storage *client_addr);

/* Crypto state installation after handshake (tquic_handshake.c) */
void tquic_install_crypto_state(struct sock *sk);

/*
 * =============================================================================
 * SERVER MULTI-TENANT CLIENT MANAGEMENT
 * =============================================================================
 *
 * These functions manage per-client (router) state for multi-tenant VPS.
 */

/* Forward declaration */
struct tquic_client;

/* Client lookup by PSK identity (tquic_server.c) */
struct tquic_client *tquic_client_lookup_by_psk(const char *identity,
						size_t identity_len);

/* Reference counting (tquic_server.c) */
bool tquic_client_get(struct tquic_client *client);
void tquic_client_release(struct tquic_client *client);

/* Rate limit check (tquic_server.c) */
bool tquic_client_rate_limit_check(struct tquic_client *client);

/* Client registration (tquic_server.c) */
int tquic_client_register(const char *identity, size_t identity_len,
			  const u8 *psk);
int tquic_client_unregister(const char *identity, size_t identity_len);

/* Connection-client binding (tquic_server.c) */
int tquic_server_bind_client(struct tquic_connection *conn,
			     struct tquic_client *client);
void tquic_server_unbind_client(struct tquic_connection *conn);
u32 tquic_server_conn_session_ttl(struct tquic_connection *conn,
				  u32 default_ttl_ms);

/* PSK retrieval (tquic_server.c) */
int tquic_server_get_client_psk(const char *identity, size_t identity_len,
				u8 *psk);
int tquic_client_copy_psk(const struct tquic_client *client, u8 *psk);

/* Server accept (tquic_server.c) */
int tquic_server_accept(struct sock *sk, struct sk_buff *skb,
			struct sockaddr_storage *client_addr);

/* Process Initial packet for new server connection (tquic_input.c) */
int tquic_process_initial_for_server(struct tquic_connection *conn,
				     struct sk_buff *skb,
				     struct sockaddr_storage *src_addr);

/* Server subsystem init/exit (tquic_server.c) */
int __init tquic_server_init(void);
void tquic_server_exit(void);

/* Security hardening init/exit (security_hardening.c) */
int __init tquic_security_hardening_init(void);
void tquic_security_hardening_exit(void);

/* Persistent congestion sysctl init/exit (cong/persistent_cong.c) */
int __init tquic_persistent_cong_module_init(void);
void tquic_persistent_cong_module_exit(void);

/*
 * =============================================================================
 * CONNECTION ID POOL MANAGEMENT
 * =============================================================================
 *
 * CID pool maintains connection IDs per RFC 9000 Section 5.1.
 * Each connection maintains a pool of local CIDs for rotation and migration.
 */

/* Forward declaration */
struct tquic_cid_pool;

/* CID constants */
#define TQUIC_DEFAULT_CID_LEN 8
#define TQUIC_STATELESS_RESET_TOKEN_LEN 16

/* CID pool functions (tquic_cid.c) */
int tquic_cid_pool_init(struct tquic_connection *conn);
void tquic_cid_pool_destroy(struct tquic_connection *conn);
int tquic_cid_issue(struct tquic_connection *conn, struct tquic_cid *cid);
int tquic_cid_retire(struct tquic_connection *conn, u64 seq_num);
struct tquic_connection *tquic_cid_lookup(const struct tquic_cid *cid);
struct tquic_connection *tquic_cid_rht_lookup(const struct tquic_cid *cid);
int tquic_cid_get_for_migration(struct tquic_connection *conn,
				struct tquic_cid *cid);
int tquic_cid_add_remote(struct tquic_connection *conn,
			 const struct tquic_cid *cid, u64 seq_num,
			 u64 retire_prior_to, const u8 *reset_token);

/* CID frame transmission (tquic_cid.c) */
void tquic_send_new_connection_id(struct tquic_connection *conn,
				  const struct tquic_cid *cid,
				  const u8 *reset_token);
void tquic_send_retire_connection_id(struct tquic_connection *conn,
				     u64 seq_num);

/* CID rotation (tquic_cid.c) */
bool tquic_cid_check_rotation(struct tquic_connection *conn);
int tquic_cid_rotate(struct tquic_connection *conn);
void tquic_cid_set_rotation_enabled(struct tquic_connection *conn,
				    bool enabled);
void tquic_cid_update_active_limit(struct tquic_connection *conn, u8 limit);

/* CID sequence number tracking (tquic_cid.c) */
u64 tquic_cid_get_next_seq(struct tquic_connection *conn);
u64 tquic_cid_get_retire_prior_to(struct tquic_connection *conn);
void tquic_cid_handle_peer_retire_prior_to(struct tquic_connection *conn,
					   u64 retire_prior_to);

/* CID path integration (core/cid.c - CID manager interface) */
int tquic_cidmgr_assign_to_path(struct tquic_cid_manager *mgr,
				struct tquic_path *path);
void tquic_cidmgr_release_from_path(struct tquic_cid_manager *mgr,
				    struct tquic_path *path);
int tquic_cid_get_path_cid(struct tquic_connection *conn,
			   struct tquic_path *path, struct tquic_cid *cid);
void tquic_cid_retire_remote(struct tquic_connection *conn, u64 seq_num);

/* CID table init/exit */
int __init tquic_cid_table_init(void);
void tquic_cid_table_exit(void);

/* Connection state machine init/exit (core/connection.c) */
int __init tquic_connection_init(void);
void tquic_connection_exit(void);

/*
 * =============================================================================
 * CONNECTION MIGRATION
 * =============================================================================
 *
 * Connection migration API per RFC 9000 Section 9.
 * Implementation in tquic_migration.c.
 */

/* Migration flag for tquic_sock.flags */
#define TQUIC_F_MIGRATION_ENABLED BIT(6)

/* Migration functions (tquic_migration.c) */
int tquic_migrate_auto(struct tquic_connection *conn, struct tquic_path *path,
		       struct sockaddr_storage *new_addr);
int tquic_migrate_explicit(struct tquic_connection *conn,
			   struct sockaddr_storage *new_local, u32 flags);
int tquic_migration_get_status(struct tquic_connection *conn,
			       struct tquic_migrate_info *info);
void tquic_migration_cleanup(struct tquic_connection *conn);

/* Path management functions (tquic_migration.c) */
struct tquic_path *tquic_path_find_by_addr(struct tquic_connection *conn,
					   const struct sockaddr_storage *addr);
struct tquic_path *tquic_path_create(struct tquic_connection *conn,
				     const struct sockaddr_storage *local,
				     const struct sockaddr_storage *remote);
void tquic_path_free(struct tquic_path *path);
int tquic_migration_send_path_challenge(struct tquic_connection *conn,
					struct tquic_path *path);
void tquic_migration_path_event(struct tquic_connection *conn,
				struct tquic_path *path, int event);

/* Path event types for migration */
#define TQUIC_PATH_EVENT_MIGRATE_START 1
#define TQUIC_PATH_EVENT_MIGRATE_FAILED 2
#define TQUIC_PATH_EVENT_MIGRATE_STANDBY 3

/*
 * =============================================================================
 * SERVER-SIDE MIGRATION AND SESSION TTL
 * =============================================================================
 *
 * These functions implement VPS-side connection migration support.
 */

/* Server-side migration handling (tquic_migration.c) */
int tquic_server_handle_migration(struct tquic_connection *conn,
				  struct tquic_path *path,
				  const struct sockaddr_storage *new_remote);

/* Session TTL for router reconnects (tquic_migration.c) */
int tquic_server_start_session_ttl(struct tquic_connection *conn);
int tquic_server_session_resume(struct tquic_connection *conn,
				struct tquic_path *path);

/* Packet queuing during path unavailability (tquic_migration.c) */
int tquic_server_queue_packet(struct tquic_connection *conn,
			      struct sk_buff *skb);

/* Path recovery check (tquic_migration.c) */
void tquic_server_check_path_recovery(struct tquic_connection *conn);

/*
 * =============================================================================
 * STREAM SOCKET MANAGEMENT
 * =============================================================================
 *
 * Stream sockets are created via ioctl(TQUIC_NEW_STREAM) on the connection
 * socket. Each stream is a first-class file descriptor that can be used with
 * poll/epoll/select.
 *
 * Stream ID encoding (RFC 9000 Section 2.1):
 *   - Bits 0-1 encode type: 0=client-initiated bidi, 1=server-initiated bidi,
 *                           2=client-initiated uni, 3=server-initiated uni
 *   - Client-initiated: even numbers (bidi: 0,4,8..., uni: 2,6,10...)
 *   - Server-initiated: odd numbers (bidi: 1,5,9..., uni: 3,7,11...)
 *
 * Locking:
 *   Stream operations acquire conn->lock when modifying stream lists.
 *   Per-stream state is protected by the stream's own spinlock when present.
 *   Buffer queues (sk_buff_head) have internal locking for queue ops.
 */

/**
 * struct tquic_stream_sock - Stream socket state
 * @stream: Associated QUIC stream
 * @conn: Parent connection
 * @parent_sk: Connection socket
 * @wait: Wait queue for blocking operations
 *
 * Stored in socket->sk_user_data to link stream fd to tquic_stream.
 */
struct tquic_stream_sock {
	struct tquic_stream *stream;
	struct tquic_connection *conn;
	struct sock *parent_sk;
	wait_queue_head_t wait;
};

/*
 * Stream management functions (tquic_stream.c)
 */

/**
 * tquic_stream_socket_create - Create a new stream socket
 * @conn: Parent connection
 * @parent_sk: Connection socket (for network namespace, etc.)
 * @flags: Stream type flags (TQUIC_STREAM_BIDI or TQUIC_STREAM_UNIDI)
 * @stream_id: OUT - Assigned stream ID
 *
 * Creates a new stream on the connection and returns a file descriptor
 * for the stream socket. The stream fd is first-class and supports
 * poll/epoll/select.
 *
 * Returns: File descriptor on success, negative errno on failure
 *   -ENOTCONN: Connection not established
 *   -EAGAIN: Would block and O_NONBLOCK set (stream limit)
 *   -EINTR: Interrupted while waiting for stream credit
 *   -EINVAL: Invalid flags
 *   -ENOMEM: Memory allocation failed
 */
int tquic_stream_socket_create(struct tquic_connection *conn,
			       struct sock *parent_sk, u32 flags,
			       u64 *stream_id);

/**
 * tquic_stream_wake - Wake up waiters on stream socket
 * @stream: Stream with incoming data or state change
 *
 * Called from packet input path when data arrives on a stream
 * or stream state changes. Wakes up processes blocked in
 * recvmsg() or poll() on the stream socket.
 */
void tquic_stream_wake(struct tquic_stream *stream);

/**
 * tquic_wait_for_stream_credit - Wait until stream can be opened
 * @conn: Connection
 * @is_bidi: True for bidirectional, false for unidirectional
 * @nonblock: True if O_NONBLOCK set on socket
 *
 * Per CONTEXT.md: ioctl blocks until peer grants more streams via
 * MAX_STREAMS frame. If stream credit is available, returns immediately.
 *
 * Returns: 0 when stream can be opened, negative errno on failure
 *   -EAGAIN: Would block and nonblock=true
 *   -EINTR: Interrupted by signal
 *   -ENOTCONN: Connection closed while waiting
 */
int tquic_wait_for_stream_credit(struct tquic_connection *conn, bool is_bidi,
				 bool nonblock);

/*
 * =============================================================================
 * FUNCTIONS EXPORTED ACROSS TRANSLATION UNITS
 * =============================================================================
 *
 * Prototypes for functions defined in one .c file but called from others.
 */

/* Forward declarations for types used below */
struct tquic_additional_address;

/* Anti-amplification check (tquic_migration.c) */
bool tquic_path_anti_amplification_check(struct tquic_path *path, u64 bytes);

/* Additional address migration (tquic_migration.c) */
int tquic_migrate_to_additional_address(
	struct tquic_connection *conn,
	struct tquic_additional_address *addr_entry);

/* Inline handshake crypto processing (tquic_handshake.c) */
int tquic_inline_hs_recv_crypto(struct sock *sk, const u8 *data, u32 len,
				int enc_level);

/* Pacing integration (tquic_output.c) */
void tquic_update_pacing(struct sock *sk, struct tquic_path *path);

/* Timer update (tquic_timer.c) */
void tquic_timer_update(struct tquic_connection *conn);

/* Transport parameter helpers (core/quic_connection.c) */
int tquic_transport_param_parse(struct tquic_connection *conn, const u8 *data,
				size_t len);
int tquic_transport_param_apply(struct tquic_connection *conn);
int tquic_transport_param_encode(struct tquic_connection *conn, u8 *buf,
				 size_t buf_len, size_t *written);
int tquic_transport_param_validate(struct tquic_connection *conn);

/* Coalesced packet processing (core/packet_coalesce_fix.c) */
void tquic_packet_process_coalesced(struct tquic_connection *conn,
				    struct sk_buff *skb);
#endif /* _NET_TQUIC_PROTOCOL_H */
