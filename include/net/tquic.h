/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: WAN Bonding over QUIC
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * This header provides the main TQUIC API for kernel consumers
 * and socket interface definitions.
 */

#ifndef _NET_TQUIC_H
#define _NET_TQUIC_H

#include <linux/types.h>
#include <linux/socket.h>
#include <linux/skbuff.h>
#include <linux/version.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <net/tquic/crypto/cert_verify.h>
#include <linux/rhashtable.h>
#include <linux/refcount.h>
#include <linux/udp.h>
#include <net/sock.h>
#include <net/inet_connection_sock.h>
#include <uapi/linux/tquic.h>

/*
 * IPPROTO_TQUIC - Transport QUIC with multipath
 *
 * For out-of-tree builds, the system's linux/in.h doesn't include
 * IPPROTO_TQUIC. Define it here if not already defined.
 *
 * NOTE:
 * TQUIC is wired to a classic 8-bit IP protocol number in this tree.
 */
#ifndef IPPROTO_TQUIC
#define IPPROTO_TQUIC 253
#endif

/* Protocol version numbers */
#define TQUIC_VERSION_1 0x00000001
#define TQUIC_VERSION_2 0x6b3343cf /* QUIC v2 (RFC 9369) */
#define TQUIC_VERSION_CURRENT TQUIC_VERSION_1

/* QUIC version helper macros */
#define TQUIC_IS_VERSION_1(v) ((v) == TQUIC_VERSION_1)
#define TQUIC_IS_VERSION_2(v) ((v) == TQUIC_VERSION_2)
#define TQUIC_IS_SUPPORTED_VERSION(v) \
	(TQUIC_IS_VERSION_1(v) || TQUIC_IS_VERSION_2(v))

/* Version preference sysctl accessors (tquic_sysctl.c) */
u32 tquic_sysctl_get_preferred_version(void);
bool tquic_sysctl_prefer_v2(void);

/* Connection ID constraints */
#define TQUIC_MAX_CID_LEN 20
#define TQUIC_MIN_CID_LEN 0
#define TQUIC_DEFAULT_CID_LEN 8

/* Packet number spaces */
#define TQUIC_PN_SPACE_INITIAL 0
#define TQUIC_PN_SPACE_HANDSHAKE 1
#define TQUIC_PN_SPACE_APPLICATION 2
#define TQUIC_PN_SPACE_COUNT 3

/* Timer types (mirrors QUIC_TIMER_* from include/net/quic.h) */
#define TQUIC_TIMER_LOSS 0
#define TQUIC_TIMER_ACK 1
#define TQUIC_TIMER_IDLE 2
#define TQUIC_TIMER_HANDSHAKE 3
#define TQUIC_TIMER_PATH_PROBE 4
#define TQUIC_TIMER_PACING 5
#define TQUIC_TIMER_KEY_DISCARD 6
#define TQUIC_TIMER_KEY_UPDATE 7 /* Key update timeout (3 * PTO) */
#define TQUIC_TIMER_MAX 8

/* Crypto level indices */
#define TQUIC_CRYPTO_INITIAL 0
#define TQUIC_CRYPTO_HANDSHAKE 1
#define TQUIC_CRYPTO_APPLICATION 2
#define TQUIC_CRYPTO_EARLY_DATA 3
#define TQUIC_CRYPTO_MAX 4

/*
 * Stream limits - practical defaults for DoS prevention.
 * RFC 9000 allows up to 2^60 but that is an absolute maximum, not a
 * sensible default.  These can be raised via sysctl or transport
 * parameter negotiation.
 */
#define TQUIC_MAX_STREAM_COUNT_BIDI 256
#define TQUIC_MAX_STREAM_COUNT_UNI 256

/* Flow control defaults */
#define TQUIC_DEFAULT_MAX_DATA (1 << 20) /* 1 MB */
#define TQUIC_DEFAULT_MAX_STREAM_DATA (1 << 18) /* 256 KB */

/* Timing constants (in ms) */
#define TQUIC_DEFAULT_IDLE_TIMEOUT 30000
#define TQUIC_MIN_RTT 1
#define TQUIC_DEFAULT_RTT 100
#define TQUIC_MAX_ACK_DELAY 25

/* Path limits for WAN bonding */
#define TQUIC_MAX_PATHS 16
#define TQUIC_MIN_PATHS 1
#define TQUIC_DEFAULT_PATHS 4

/* Maximum number of available versions in version_info */
#define TQUIC_MAX_AVAILABLE_VERSIONS 16

/* Stateless reset token length (also defined later but needed for struct) */
#ifndef TQUIC_STATELESS_RESET_TOKEN_LEN
#define TQUIC_STATELESS_RESET_TOKEN_LEN 16
#endif

/* Scheduler/CC name limits */
#define TQUIC_SCHED_NAME_MAX 16
#define TQUIC_CC_NAME_MAX 16

struct tquic_sock;
struct tquic_connection;
struct tquic_stream;
struct tquic_stream_manager;
struct tquic_fc_stream_state;
struct tquic_path;
struct tquic_frame;
struct tquic_packet;
struct tquic_xsk;
struct tquic_udp_sock;

/**
 * struct tquic_rtt_state - RTT measurement state (RFC 9002 Section 5)
 * @latest_rtt: Most recent RTT sample
 * @smoothed_rtt: Smoothed RTT (SRTT)
 * @rtt_var: RTT variance
 * @min_rtt: Minimum RTT observed
 * @max_ack_delay: Maximum ACK delay from peer
 * @first_rtt_sample: Time of first RTT sample
 * @samples: Number of RTT samples taken
 */
#define TQUIC_RTT_STATE_DEFINED
struct tquic_rtt_state {
	u64 latest_rtt;
	u64 smoothed_rtt;
	u64 rtt_var;
	u64 min_rtt;
	u64 max_ack_delay;
	ktime_t first_rtt_sample;
	u32 samples;
};
struct tquic_coupled_state;
struct tquic_client;
struct tquic_persistent_cong_info;
struct tquic_bond_state;
struct tquic_grease_state;
struct tquic_addr_discovery_state;
struct tquic_negotiated_params;
struct tquic_cid_manager;
struct tquic_mp_sched_ops;

/* State machine magic numbers for type discrimination */
#define TQUIC_SM_MAGIC_CONN_STATE 0x434F4E53 /* "CONS" */
#define TQUIC_SM_MAGIC_MIGRATION 0x4D494752 /* "MIGR" */
#define TQUIC_SM_MAGIC_SESSION 0x53455353 /* "SESS" */

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
 * enum tquic_state_reason - Connection state transition reasons
 * @TQUIC_REASON_NORMAL: Normal state progression
 * @TQUIC_REASON_TIMEOUT: Timer-driven transition
 * @TQUIC_REASON_ERROR: Internal/protocol error transition
 * @TQUIC_REASON_PEER_CLOSE: Peer initiated close/drain
 * @TQUIC_REASON_APPLICATION: Application initiated transition
 */
enum tquic_state_reason {
	TQUIC_REASON_NORMAL,
	TQUIC_REASON_TIMEOUT,
	TQUIC_REASON_ERROR,
	TQUIC_REASON_PEER_CLOSE,
	TQUIC_REASON_APPLICATION,
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
	TQUIC_PATH_PENDING, /* Awaiting validation */
	TQUIC_PATH_VALIDATED, /* Validation passed */
	TQUIC_PATH_ACTIVE, /* In use for data */
	TQUIC_PATH_STANDBY, /* Backup path */
	TQUIC_PATH_UNAVAILABLE, /* Interface down, state preserved */
	TQUIC_PATH_FAILED, /* Validation failed or errors */
	TQUIC_PATH_CLOSED, /* Removal in progress */
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

/*
 * ECN codepoint values from IP header (RFC 3168)
 * These are the 2-bit values in the IP TOS/Traffic Class field
 */
#define TQUIC_ECN_NOT_ECT 0x00 /* Not ECN-Capable Transport */
#define TQUIC_ECN_ECT_1 0x01 /* ECN Capable Transport(1) */
#define TQUIC_ECN_ECT_0 0x02 /* ECN Capable Transport(0) */
#define TQUIC_ECN_CE 0x03 /* Congestion Experienced */

/**
 * struct tquic_ecn_state - Per-path ECN state (RFC 9000 Section 13.4)
 * @ect0_sent: Packets sent with ECT(0) marking
 * @ect1_sent: Packets sent with ECT(1) marking
 * @ect0_acked: ECT(0) count from peer's ACK_ECN frames
 * @ect1_acked: ECT(1) count from peer's ACK_ECN frames
 * @ce_acked: CE count from peer's ACK_ECN frames
 * @ecn_capable: Path validated for ECN
 * @ecn_validated: Validation complete
 * @ecn_failed: Validation failed
 * @ecn_testing: In validation mode
 * @ecn_marking: Current ECN marking for outgoing packets
 *
 * ECN is validated independently per path because network paths may
 * have different ECN handling characteristics.
 */
struct tquic_ecn_state {
	/* Counters for packets sent with ECN marking */
	u64 ect0_sent;
	u64 ect1_sent;

	/* Counters from peer's ACK_ECN frames */
	u64 ect0_acked;
	u64 ect1_acked;
	u64 ce_acked;

	/* ECN state flags */
	u8 ecn_capable : 1; /* Path validated for ECN */
	u8 ecn_validated : 1; /* Validation complete */
	u8 ecn_failed : 1; /* Validation failed */
	u8 ecn_testing : 1; /* In validation mode */

	/* Current ECN marking to use for outgoing packets */
	u8 ecn_marking;
};

/**
 * struct tquic_path_stats - Per-path statistics
 * @tx_packets: Packets transmitted (legacy, use packets_sent)
 * @tx_bytes: Bytes transmitted (legacy, use bytes_sent)
 * @rx_packets: Packets received
 * @rx_bytes: Bytes received
 * @acked_bytes: Bytes acknowledged
 * @lost_packets: Detected lost packets (legacy, use packets_lost)
 * @rtt_min: Minimum observed RTT (us)
 * @rtt_smoothed: Smoothed RTT (us)
 * @rtt_variance: RTT variance (us)
 * @bandwidth: Estimated bandwidth (bytes/s)
 * @cwnd: Current congestion window
 * @packets_sent: Atomic counter of packets sent on this path
 * @bytes_sent: Atomic counter of bytes sent on this path
 * @packets_acked: Atomic counter of packets acknowledged
 * @packets_lost: Atomic counter of packets lost
 * @packets_retrans: Atomic counter of packets retransmitted
 *
 * This struct tracks per-path statistics for the multipath scheduler.
 * Fields accessed from multiple contexts use atomic64_t for lock-free access.
 */
struct tquic_path_stats {
	/* Legacy counters (non-atomic) */
	u64 tx_packets;
	u64 tx_bytes;
	u64 rx_packets;
	u64 rx_bytes;
	u64 acked_bytes;
	u64 lost_packets;
	u32 rtt_min;
	u32 rtt_smoothed;
	u32 rtt_variance;
	u64 bandwidth;
	u32 cwnd;

	/*
	 * Atomic counters for scheduler and loss detection.
	 * These are updated from softirq context (packet TX/RX)
	 * and read from process context (stats queries).
	 */
	atomic64_t packets_sent; /* Packets sent on this path */
	atomic64_t bytes_sent; /* Bytes sent on this path */
	atomic64_t packets_acked; /* Packets acknowledged */
	atomic64_t packets_lost; /* Packets declared lost (atomic) */
	atomic64_t packets_retrans; /* Packets retransmitted */
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
	refcount_t refcnt; /* Reference count */
	struct tquic_connection *conn;
	enum tquic_path_state state;
	enum tquic_path_state saved_state; /* State before unavailable */
	u32 path_id;

	struct sockaddr_storage local_addr;
	struct sockaddr_storage remote_addr;

	struct tquic_cid local_cid;
	struct tquic_cid remote_cid;

	struct tquic_path_stats stats;

	/*
	 * ECN state for this path (RFC 9000 Section 13.4)
	 *
	 * ECN is validated independently per path because network
	 * paths may have different ECN handling characteristics.
	 */
	struct tquic_ecn_state ecn;

	/*
	 * Previous ECN counts from peer's ACK_ECN frames, used to
	 * compute deltas per RFC 9000 Section 13.4.2.1.
	 * Cumulative counters must only increase; a decrease is a
	 * PROTOCOL_VIOLATION.  MIB stats use only the delta.
	 */
	u64 ecn_ect0_count_prev;
	u64 ecn_ect1_count_prev;
	u64 ecn_ce_count_prev;

	void *cong; /* Congestion control state */
	struct tquic_cong_ops *cong_ops; /* Current CC algorithm ops */

	/* Per-path UDP encapsulation socket (owned by the path). */
	struct tquic_udp_sock *udp_sock;

	/* RTT measurement state (for loss detection) - embedded struct */
	struct tquic_rtt_state rtt;

	/*
	 * Scheduler-accessible congestion control info (RFC 9002)
	 *
	 * This embedded struct provides congestion control state that
	 * schedulers and loss detection need to access. It mirrors key
	 * values from the per-path congestion controller (path->cong).
	 *
	 * RTT variables follow RFC 9002 Section 5 naming:
	 * - smoothed_rtt: Exponentially weighted moving average of RTT
	 * - rtt_var: Mean deviation of RTT samples
	 * - min_rtt: Minimum RTT observed over a period
	 * - latest_rtt: Most recent RTT sample
	 *
	 * Congestion variables follow RFC 9002 Section 7:
	 * - cwnd: Congestion window in bytes
	 * - bytes_in_flight: Sum of bytes in unacknowledged packets
	 * - ssthresh: Slow start threshold
	 * - in_slow_start: Whether in slow start phase
	 * - in_recovery: Whether in recovery phase
	 */
	struct {
		/* RTT measurement (RFC 9002 Section 5) */
		u64 smoothed_rtt_us; /* Smoothed RTT in microseconds */
		u64 rtt_var_us; /* RTT variance in microseconds */
		u64 min_rtt_us; /* Minimum RTT observed */
		u64 last_rtt_us; /* Previous RTT sample */

		/* Congestion window (RFC 9002 Section 7) */
		u32 cwnd; /* Congestion window (bytes) */
		u32 bytes_in_flight; /* Bytes currently in flight */
		u32 ssthresh; /* Slow start threshold */
		u32 mss; /* Maximum segment size (1200 default) */

		/* Loss tracking */
		u64 delivered; /* Total bytes delivered */
		u64 lost; /* Total bytes lost */
		u32 loss_rate; /* Loss rate (0-1000 = 0-100%) */
		u64 bandwidth; /* Estimated bandwidth (bytes/sec) */

		/* Recovery state */
		bool in_slow_start; /* In slow start phase */
		bool in_recovery; /* In loss recovery */
		u64 recovery_start; /* Packet number at recovery start */

		/* PTO state (RFC 9002 Section 6.2) */
		u32 pto_count; /* PTO backoff counter */
	} cc;

	/* Path degradation tracking (consecutive losses in a round) */
	struct {
		spinlock_t lock;
		u32 consecutive_losses;
		u64 round_start_tx;
		u64 last_loss_tx;
	} loss_tracker;

	u32 mtu;
	u32 flags; /* Path flags (TQUIC_PATH_FLAG_*) */
	u8 priority;
	u8 weight;
	bool schedulable; /* Can be selected by scheduler */
	int ifindex; /* Network interface index */

	struct net_device *dev; /* Interface for this path */
	ktime_t last_activity;
	struct timer_list validation_timer;
	u8 probe_count;
	u8 challenge_data[8]; /* Legacy - use validation.challenge_data instead */

	struct list_head list; /* Connection path list */
	struct list_head pm_list; /* Path manager path list */

	/* Validation state */
	struct {
		u8 challenge_data[8]; /* Sent challenge */
		ktime_t challenge_sent; /* When challenge was sent */
		bool challenge_pending; /* Awaiting response */
		u8 retries; /* Retry count */
		struct timer_list timer; /* Retransmission timer */
	} validation;

	/*
	 * Anti-amplification state (RFC 9000 Section 8.1)
	 *
	 * Before a path is validated, an endpoint MUST NOT send more than
	 * three times the amount of data received from that address.
	 * This prevents the endpoint from being used as an amplifier.
	 *
	 * Counters use atomic64_t because they are read in
	 * tquic_path_anti_amplification_check() and written in
	 * tquic_path_anti_amplification_sent/received() potentially
	 * from different contexts (softirq vs process) without a
	 * shared lock.
	 */
	struct {
		atomic64_t
			bytes_received; /* Bytes received on unvalidated path */
		atomic64_t bytes_sent; /* Bytes sent on unvalidated path */
		bool active; /* Anti-amplification limits in effect */
	} anti_amplification;

	/*
	 * PATH_CHALLENGE response rate limiting.
	 *
	 * Limits the number of PATH_RESPONSE frames sent per RTT to
	 * prevent resource exhaustion from excessive PATH_CHALLENGE
	 * frames.  The counter resets each RTT interval.
	 */
	struct {
		u32 challenge_count; /* Challenges responded to in window */
		ktime_t window_start; /* Start of current rate limit window */
#define TQUIC_MAX_CHALLENGE_RESPONSES_PER_RTT 4
	} challenge_rate;

	/* Response queue (prevent memory exhaustion - RFC 9000 Section 8.2) */
	struct {
		struct sk_buff_head queue; /* Pending PATH_RESPONSE frames */
		atomic_t count; /* Current queue depth */
	} response;

	/* Multipath extension state (draft-ietf-quic-multipath) */
	void *mp_ack_state; /* Per-path ACK tracking */
	void *abandon_state; /* Path abandonment state */
	u64 status_seq_num; /* Path status sequence number */
	bool is_backup; /* Path is in standby/backup mode */
	bool is_preferred_addr; /* Path to server's preferred address */

	/*
	 * PMTUD (Path MTU Discovery) state - RFC 8899 DPLPMTUD
	 *
	 * Manages per-path MTU probing using PING+PADDING frames.
	 * Allocated by tquic_pmtud_init_path(), freed by tquic_pmtud_release_path().
	 */
	void *pmtud_state; /* struct tquic_pmtud_state_info * */

	/*
	 * NAT Keepalive state - RFC 9308 Section 3.5
	 *
	 * Manages per-path NAT binding keepalive using minimal PING frames.
	 * Allocated by tquic_nat_keepalive_init(), freed by tquic_nat_keepalive_cleanup().
	 */
	void *nat_keepalive_state; /* struct tquic_nat_keepalive_state * */

	/*
	 * NAT Lifecycle state - Advanced NAT management
	 *
	 * Provides advanced NAT lifecycle management including:
	 * - NAT binding timeout detection and prediction
	 * - NAT type detection (Full Cone, Restricted, Symmetric, CGNAT)
	 * - Adaptive keepalive interval adjustment
	 * - Cascaded NAT topology detection
	 * - STUN-like probing for NAT characteristic detection
	 *
	 * Allocated by tquic_nat_lifecycle_init(), freed by tquic_nat_lifecycle_cleanup().
	 * Works in conjunction with nat_keepalive_state for optimal NAT handling.
	 */
	void *nat_lifecycle_state; /* struct tquic_nat_lifecycle_state * */

	/*
	 * Careful Resume state (BDP frame extension)
	 *
	 * Per-path state for Careful Resume algorithm. Allocated by
	 * tquic_careful_resume_init(), freed by release_cr_state().
	 * NULL when Careful Resume is not active on this path.
	 */
	void *cr_state; /* struct careful_resume_state * */

	/* AF_XDP socket for kernel-bypass packet I/O on this path */
	struct tquic_xsk *xsk;

	struct rcu_head rcu_head; /* RCU callback for kfree_rcu */
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
	refcount_t refcount;

	struct sk_buff_head send_buf;
	struct sk_buff_head recv_buf;

	u64 send_offset;
	u64 recv_offset;
	u64 recv_consumed; /* Bytes consumed by application (for FC) */
	u64 max_send_data;
	u64 max_recv_data;
	struct tquic_fc_stream_state *fc;

	u8 priority;
	bool blocked;
	bool fin_sent;
	bool fin_received;
	u64 final_size; /* Final size from FIN (RFC 9000 §4.5) */

	struct rb_node node;
	wait_queue_head_t wait;

	void *ext; /* Extended stream state for reassembly and priority */
};

/*
 * skb->cb layout for skbs enqueued on stream->send_buf.
 *
 * The send path may partially consume an SKB while leaving it queued; for
 * non-linear (zerocopy) SKBs we cannot use skb_pull() reliably. Track the
 * byte offset within the SKB separately.
 */
struct tquic_stream_skb_cb {
	u64 stream_offset; /* Stream offset for skb data[0] */
	u32 data_off; /* Bytes already consumed from this skb */
};

static inline struct tquic_stream_skb_cb *
tquic_stream_skb_cb(struct sk_buff *skb)
{
	return (struct tquic_stream_skb_cb *)skb->cb;
}

/**
 * struct tquic_conn_stats - Connection-level statistics
 *
 * This struct tracks connection-wide statistics for monitoring and
 * diagnostics. Fields used from multiple contexts (softirq, process)
 * are atomic64_t for lock-free access.
 *
 * RFC 9002 loss detection statistics are tracked here for connection-wide
 * aggregation. Per-path RTT and loss stats are in struct tquic_path_stats.
 */
struct tquic_conn_stats {
	/* Basic packet/byte counters */
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
	atomic64_t handshake_time_us; /* Handshake completion time */

	/*
	 * Atomic counters for lock-free access from multiple contexts.
	 * These are used by loss detection (quic_loss.c) and scheduler
	 * (tquic_scheduler.c) code paths.
	 */

	/* RFC 9002 Loss Detection statistics */
	atomic64_t packets_lost; /* Total packets declared lost */
	atomic64_t packets_retransmitted; /* Packets retransmitted */
	atomic64_t clone_failures; /* SKB clone failures during retx */

	/* RTT statistics (aggregated from active path) */
	atomic64_t min_rtt_us; /* Minimum RTT observed (microseconds) */
	atomic64_t smoothed_rtt_us; /* Smoothed RTT (microseconds) */
	atomic64_t rtt_variance_us; /* RTT variance (microseconds) */
	atomic64_t latest_rtt_us; /* Most recent RTT sample */

	/* Scheduler statistics */
	atomic64_t total_packets; /* Total packets scheduled */
	atomic64_t total_bytes; /* Total bytes scheduled */
	atomic64_t sched_decisions; /* Number of scheduler invocations */
	atomic64_t path_switches; /* Times scheduler switched paths */
	atomic64_t reinjections; /* Packets reinjected on alternate path */

	/*
	 * QUIC-over-TCP statistics (transport/quic_over_tcp.c)
	 * These are only used when QUIC runs over TCP for firewall traversal.
	 */
	atomic64_t packets_rx; /* TCP: packets received */
	atomic64_t packets_tx; /* TCP: packets transmitted */
	atomic64_t bytes_rx; /* TCP: bytes received */
	atomic64_t bytes_tx; /* TCP: bytes transmitted */
	atomic64_t coalesce_count; /* TCP: packets coalesced */
	atomic64_t tcp_segments_rx; /* TCP: segments received */
	atomic64_t tcp_segments_tx; /* TCP: segments transmitted */
	atomic64_t framing_errors; /* TCP: framing errors */
	atomic64_t flow_control_pauses; /* TCP: flow control pauses */
	atomic64_t keepalives_sent; /* TCP: keepalives sent */
	atomic64_t keepalives_recv; /* TCP: keepalives received */

	/* Additional counters for packet processing */
	atomic64_t packets_received; /* Input packets processed */
	atomic64_t bytes_received; /* Input bytes processed */
};

/**
 * struct tquic_flow_control - Connection flow control state
 */
struct tquic_flow_control {
	u64 max_data;
	u64 max_data_next;
	u64 data_sent;
	u64 data_received;
	u64 max_streams_bidi;
	u64 max_streams_uni;
	u64 streams_opened_bidi;
	u64 streams_opened_uni;
	u8 blocked;
	u64 blocked_at;
};

/**
 * struct tquic_config - Connection configuration
 */
struct tquic_config {
	u32 version; /* QUIC version to use */
	u32 max_idle_timeout_ms;
	u32 handshake_timeout_ms; /* Handshake timeout */
	u64 initial_max_data;
	u64 initial_max_stream_data_bidi_local;
	u64 initial_max_stream_data_bidi_remote;
	u64 initial_max_stream_data_uni;
	u64 initial_max_streams_bidi;
	u64 initial_max_streams_uni;
	u8 ack_delay_exponent;
	u32 max_ack_delay_ms;
	bool disable_active_migration;
	u64 max_connection_ids;
	u64 max_datagram_size;
};

/**
 * struct tquic_preferred_address - Preferred address for migration (RFC 9000 9.6)
 */
#ifndef TQUIC_PREFERRED_ADDRESS_DEFINED
#define TQUIC_PREFERRED_ADDRESS_DEFINED
struct tquic_preferred_address {
	u8 ipv4_addr[4];
	u16 ipv4_port;
	u8 ipv6_addr[16];
	u16 ipv6_port;
	struct tquic_cid cid;
	u8 stateless_reset_token[16];
};
#endif /* TQUIC_PREFERRED_ADDRESS_DEFINED */

/**
 * struct tquic_version_info - Version Information transport parameter (RFC 9368)
 * @chosen_version: The QUIC version selected for the connection
 * @available_versions: Array of versions the endpoint supports
 * @num_versions: Number of entries in available_versions array
 */
#ifndef TQUIC_VERSION_INFO_DEFINED
#define TQUIC_VERSION_INFO_DEFINED
struct tquic_version_info {
	u32 chosen_version;
	u32 available_versions[TQUIC_MAX_AVAILABLE_VERSIONS];
	size_t num_versions;
};
#endif /* TQUIC_VERSION_INFO_DEFINED */

/**
 * struct tquic_transport_params - Transport parameters (RFC 9000 Section 18)
 *
 * Full transport parameters structure for QUIC with all RFC extensions.
 * This includes all standard RFC 9000 parameters plus multipath (RFC 9369),
 * datagram (RFC 9221), version negotiation (RFC 9368), and draft extensions.
 */
#ifndef TQUIC_TRANSPORT_PARAMS_DEFINED
#define TQUIC_TRANSPORT_PARAMS_DEFINED
struct tquic_transport_params {
	/* Connection IDs */
	struct tquic_cid original_dcid;
	bool original_dcid_present;

	struct tquic_cid initial_scid;
	bool initial_scid_present;

	struct tquic_cid retry_scid;
	bool retry_scid_present;

	/* Timing parameters */
	u64 max_idle_timeout; /* milliseconds, 0 = disabled */
	u8 ack_delay_exponent; /* default 3, max 20 */
	u32 max_ack_delay; /* milliseconds, default 25, max 2^14 */

	/* Stateless reset token (server only) */
	u8 stateless_reset_token[TQUIC_STATELESS_RESET_TOKEN_LEN];
	bool stateless_reset_token_present;

	/* Size limits */
	u64 max_udp_payload_size; /* minimum 1200, default 65527 */

	/* Connection-level flow control */
	u64 initial_max_data;

	/* Stream-level flow control */
	u64 initial_max_stream_data_bidi_local;
	u64 initial_max_stream_data_bidi_remote;
	u64 initial_max_stream_data_uni;

	/* Stream limits */
	u64 initial_max_streams_bidi; /* max 2^60 */
	u64 initial_max_streams_uni; /* max 2^60 */

	/* Migration */
	bool disable_active_migration;

	/* Preferred address (server only) */
	struct tquic_preferred_address preferred_address;
	bool preferred_address_present;

	/* Connection ID management */
	u64 active_connection_id_limit; /* minimum 2 */

	/* Multipath extension for WAN bonding (RFC 9369) */
	bool enable_multipath;

	/* RFC 9369 Multipath transport parameters */
	u64 initial_max_paths; /* Maximum concurrent paths (0x0f01) */

	/* draft-ietf-quic-multipath initial_max_path_id */
	u64 initial_max_path_id; /* Maximum Path ID (0x0f02) */
	bool initial_max_path_id_present;

	/* DATAGRAM frame support (RFC 9221) */
	u64 max_datagram_frame_size; /* 0 = disabled, >0 = max size */

	/* GREASE support (RFC 9287) */
	bool grease_quic_bit; /* Willing to receive GREASE'd packets */

	/* ACK Frequency (draft-ietf-quic-ack-frequency) */
	u64 min_ack_delay; /* Minimum ACK delay in microseconds (0x0e) */
	bool min_ack_delay_present; /* Whether min_ack_delay was advertised */

	/* Version Information (RFC 9368 - Compatible Version Negotiation) */
	struct tquic_version_info
		*version_info; /* Version information parameter */
	bool version_info_present; /* Whether version_info was advertised */

	/* Receive Timestamps (draft-smith-quic-receive-ts-03) */
	u64 max_receive_timestamps_per_ack; /* Max timestamps in ACK (0xff0a002) */
	bool max_receive_timestamps_per_ack_present;
	u8 receive_timestamps_exponent; /* Timestamp delta exponent (0xff0a003) */
	bool receive_timestamps_exponent_present;

	/* Address Discovery (draft-ietf-quic-address-discovery) */
	bool enable_address_discovery; /* Supports OBSERVED_ADDRESS frames (0x9f01) */

	/* Reliable Stream Reset (draft-ietf-quic-reliable-stream-reset-07) */
	bool reliable_stream_reset; /* Supports RESET_STREAM_AT frame (0x17cd) */

	/* Extended Key Update (draft-ietf-quic-extended-key-update-01) */
	u64 extended_key_update; /* Max outstanding requests (0 = disabled) */
	bool extended_key_update_present;

	/* Additional Addresses (draft-piraux-quic-additional-addresses) */
	void *additional_addresses; /* Pointer to tquic_additional_addresses */
	bool additional_addresses_present;

	/* BDP Frame Extension (draft-kuhn-quic-bdpframe-extension-05) */
	bool enable_bdp_frame; /* Supports BDP Frame extension */

	/* Deadline-Aware Multipath Scheduling (draft-tjohn-quic-multipath-dmtp-01) */
	bool enable_deadline_aware; /* Enable deadline-aware scheduling (0x0f10) */
	bool enable_deadline_aware_present;
	u32 deadline_granularity; /* Time granularity in microseconds (0x0f11) */
	bool deadline_granularity_present;
	u32 max_deadline_streams; /* Max streams with deadlines (0x0f12) */
	bool max_deadline_streams_present;
	u8 deadline_miss_policy; /* Policy for missed deadlines (0x0f13) */
	bool deadline_miss_policy_present;

	/* Forward Error Correction (draft-zheng-quic-fec-extension-01) */
	bool enable_fec; /* FEC is supported (0xff0f000) */
	bool enable_fec_present; /* Whether FEC was advertised */
	u8 fec_scheme; /* Preferred FEC scheme (0xff0f001) */
	bool fec_scheme_present;
	u8 max_source_symbols; /* Max source symbols per block (0xff0f002) */
	bool max_source_symbols_present;

	/* Congestion Control Data Exchange (draft-yuan-quic-congestion-data-00) */
	bool enable_cong_data; /* CC data exchange supported (0xff0cd002) */
	bool enable_cong_data_present; /* Whether enable_cong_data was advertised */

	/* One-Way Delay Measurement (draft-huitema-quic-1wd) */
	u64 enable_one_way_delay; /* Timestamp resolution in us (0xff02de1a) */
	bool enable_one_way_delay_present;
};
#endif /* TQUIC_TRANSPORT_PARAMS_DEFINED */

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
 * @data_received: Total data received (wire-level)
 * @data_consumed: Total data consumed by application (for window updates)
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

	/* True if this is a server-side connection */
	bool is_server;

	struct tquic_cid scid;
	struct tquic_cid dcid;

	/* Original Destination Connection ID (for transport param validation) */
	struct tquic_cid original_dcid;

	/*
	 * Retry state (RFC 9000 Section 8.1)
	 *
	 * When a client receives a Retry packet, the token from that
	 * packet must be included in the subsequent Initial packet.
	 * The ODCID is stored in original_dcid above.
	 */
	u8 retry_token[256]; /* Token from Retry packet */
	size_t retry_token_len; /* Length of retry token */
	bool retry_received; /* True after Retry processing */

	/*
	 * RFC 9000 Section 7.2: Client updates DCID to server's SCID
	 * from the first Initial packet received.  Set after update.
	 */
	bool dcid_updated;

	/* Transport parameters (RFC 9000 Section 18) */
	struct tquic_transport_params local_params;
	struct tquic_transport_params remote_params;

	/*
	 * Flow control state (authoritative)
	 *
	 * These are the canonical flow control structures.  The legacy
	 * per-field counters (max_data_local, max_data_remote, data_sent,
	 * data_received) below are DEPRECATED and should not be used in
	 * new code -- use local_fc / remote_fc or the tquic_fc_state
	 * pointed to by conn->fc instead.
	 */
	struct tquic_flow_control local_fc;
	struct tquic_flow_control remote_fc;

	/* Multi-path support for WAN bonding */
	struct list_head paths;
	spinlock_t paths_lock; /* Protects paths list */
	struct tquic_path *active_path;
	u8 num_paths;
	u8 active_paths; /* Number of active/usable paths */
	u8 max_paths; /* Maximum paths allowed */
	u64 aggregate_cwnd; /* Sum of cwnd across all paths */

	/*
	 * Migration control (RFC 9000 Section 9)
	 *
	 * If either endpoint advertises disable_active_migration transport
	 * parameter, active migration MUST NOT be performed. However,
	 * migration to preferred_address is still allowed per RFC 9000 9.6.
	 */
	bool migration_disabled; /* True if active migration is disabled */

	/* Stream management */
	struct rb_root streams;
	spinlock_t streams_lock; /* Protects stream tree */
	u64 next_stream_id_bidi;
	u64 next_stream_id_uni;
	u64 max_streams_bidi;
	u64 max_streams_uni;
	u64 max_stream_id_bidi; /* Maximum stream ID for bidi streams */
	u64 max_stream_id_uni; /* Maximum stream ID for uni streams */

	/*
	 * Stream manager for the exported stream API (stream.c).
	 * This provides the tquic_stream_manager_create/destroy lifecycle
	 * and backs tquic_stream_reset_recv, tquic_stream_update_max_data,
	 * tquic_stream_conn_update_max_data, tquic_stream_shutdown_write,
	 * and the other exported stream operations.
	 */
	struct tquic_stream_manager *stream_mgr;

	/*
	 * Per-type stream counters for HTTP/3 unidirectional streams.
	 * Indexed by H3_STREAM_TYPE_* (0-3). Avoids O(n) scans
	 * in tquic_stream_count_by_type().
	 */
#define TQUIC_H3_STREAM_TYPE_MAX 4
	int h3_uni_stream_count[TQUIC_H3_STREAM_TYPE_MAX];

	/* Connection ID management */
	struct list_head dcid_list; /* List of destination CIDs */
	struct list_head scid_list; /* List of source CIDs */

	/*
	 * Legacy flow control fields -- DEPRECATED.
	 * Use conn->local_fc / conn->remote_fc or conn->fc instead.
	 * Kept for existing callers that have not yet been migrated.
	 */
	u64 max_data_local;
	u64 max_data_remote;
	u64 data_sent;
	u64 data_received;
	u64 data_consumed; /* App-read bytes (for window updates) */
	/*
	 * Connection-level flow control reservation for queued (not yet sent)
	 * STREAM data. This is used to provide backpressure in send paths without
	 * abusing conn->data_sent (which is incremented on actual send).
	 *
	 * Protected by conn->lock.
	 */
	u64 fc_data_reserved;

	/* Serialize tquic_output_flush() instances (bit 0). */
	unsigned long output_flush_flags;

	/*
	 * Packet number tracking for application packet space.
	 * Must be atomic: TX paths (tquic_xmit, tquic_send_ack,
	 * tquic_send_connection_close, tquic_output_flush) are NOT
	 * always serialized by conn->lock, so concurrent callers
	 * need atomic increments for unique, monotonic packet numbers.
	 */
	atomic64_t pkt_num_tx; /* Next TX packet number */
	atomic64_t pkt_num_rx; /* Highest RX packet number seen */

	/* Extended flow control state (tquic_fc_state from flow_control.c) */
	struct tquic_fc_state *fc;

	struct tquic_conn_stats stats;

	/* Timers - managed via timer_state for unified timer/recovery handling */
	u32 idle_timeout;
	struct tquic_timer_state *timer_state;
	struct timer_list timers[TQUIC_TIMER_MAX]; /* Per-type timers */

	/* Crypto */
	void *crypto_state;
	void *crypto[TQUIC_CRYPTO_MAX]; /* Per-level crypto state */
	u8 crypto_level; /* Current crypto level (TQUIC_CRYPTO_*) */

	/* Handshake state */
	bool handshake_complete;
	bool draining; /* Connection is draining */

	/*
	 * RFC 9002 Loss Detection and Congestion Control State
	 *
	 * These connection-level variables implement the loss detection
	 * algorithm from RFC 9002 Appendix A.3-A.4.
	 *
	 * Loss detection uses a single timer (loss_detection_timer) whose
	 * expiration triggers either time-based loss detection or PTO.
	 *
	 * The packet_threshold and time_threshold control when packets
	 * are declared lost based on gaps in acknowledgments.
	 */

	/* RFC 9002 Section 6.2: Probe Timeout (PTO) */
	u32 pto_count; /* PTO exponential backoff counter */

	/* RFC 9002 Appendix A.3: Loss Detection Timer */
	ktime_t loss_detection_timer; /* Timer deadline (0 = not set) */
	ktime_t time_of_last_ack_eliciting; /* When last ack-eliciting pkt sent */

	/*
	 * RFC 9002 Section 6.1.1: Packet Threshold
	 *
	 * kPacketThreshold: Maximum reordering in packets before declaring
	 * packet loss. The RECOMMENDED value is 3.
	 */
	u32 packet_threshold;

	/*
	 * RFC 9002 Section 6.1.2: Time Threshold
	 *
	 * kTimeThreshold: Maximum reordering in time before declaring loss.
	 * The RECOMMENDED time threshold is 9/8 of max(smoothed_rtt, latest_rtt).
	 * We store the numerator here (9); the denominator is implicitly 8.
	 */
	u32 time_threshold;

	/*
	 * Handshake confirmed state (RFC 9002 Appendix A.3)
	 *
	 * For servers: Set when HANDSHAKE_DONE is sent.
	 * For clients: Set when HANDSHAKE_DONE is received.
	 *
	 * When handshake_confirmed is false, anti-deadlock mechanisms
	 * ensure the connection can make progress even without RTT samples.
	 */
	bool handshake_confirmed;

	/* Packet number spaces */
	struct tquic_pn_space *pn_spaces; /* Array of PN spaces */

	/* Connection error state */
	u64 error_code; /* QUIC error code for close */
	bool app_error; /* True if application error */
	char *reason; /* Error reason string (deprecated) */
	u32 reason_len; /* Length of reason string (deprecated) */
	char *reason_phrase; /* Error reason phrase */

	/* CID management */
	u64 next_scid_seq; /* Next SCID sequence number */
	u64 retire_dcid_prior_to; /* Retire DCIDs prior to this seq */

	/* Socket reference */
	struct tquic_sock *tsk; /* Associated TQUIC socket */

	/* Scheduler */
	void *scheduler; /* Bonding scheduler state (struct tquic_bond_state *) */
	void *sched_priv; /* Non-bond per-connection scheduler/congestion private data */
	struct tquic_mp_sched_ops __rcu
		*mp_sched_ops; /* Multipath scheduler ops */

	/* Connection state machine (extended state) */
	void *state_machine;

	/* Connection ID pool (tquic_cid.c) */
	void *cid_pool;
	u64 cid_retire_prior_to; /* Last retire_prior_to from peer */

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
		bool enabled; /* True if datagrams negotiated */
		u64 max_send_size; /* Max datagram size we can send */
		u64 max_recv_size; /* Max datagram size we accept */
		struct sk_buff_head recv_queue; /* Received datagram queue */
		spinlock_t lock; /* Protects datagram state */
		u32 recv_queue_len; /* Current queue length */
		u32 recv_queue_max; /* Maximum queue length */
		u64 datagrams_sent; /* Statistics: sent count */
		u64 datagrams_received; /* Statistics: recv count */
		u64 datagrams_dropped; /* Statistics: dropped count */
		wait_queue_head_t wait; /* Wait queue for blocking recv */
	} datagram;

	/*
	 * GREASE (RFC 9287) state
	 *
	 * GREASE (Generate Random Extensions And Sustain Extensibility)
	 * helps ensure forward compatibility by randomly including
	 * reserved values that receivers must ignore.
	 *
	 * This pointer is allocated during connection setup if GREASE is
	 * enabled (per-netns sysctl). It is passed to header building
	 * functions to enable GREASE bit manipulation.
	 */
	struct tquic_grease_state *grease_state;

	/*
	 * Address validation token state (RFC 9000 Section 8.1.3-8.1.4)
	 *
	 * Tokens allow servers to skip address validation on future
	 * connections from validated clients. Clients store tokens
	 * received via NEW_TOKEN frames for future use.
	 */
	void *token_state; /* struct tquic_token_state * */

	/*
	 * 0-RTT early data state (RFC 9001 Section 4.6-4.7)
	 *
	 * Manages 0-RTT key derivation, early data transmission,
	 * and server accept/reject handling. NULL when 0-RTT not in use.
	 */
	void *zero_rtt_state; /* struct tquic_zero_rtt_state_s * */

	/* 0-RTT early data tracking fields */
	bool early_data_enabled; /* 0-RTT is enabled for this connection */
	bool early_data_accepted; /* Server accepted early data */
	bool early_data_rejected; /* Server rejected early data */
	u64 max_early_data; /* Max early data size */
	u64 early_data_sent; /* Early data bytes sent */

	/*
	 * Preferred Address state (RFC 9000 Section 9.6)
	 *
	 * Server advertises a preferred address in transport parameters.
	 * Client stores this address and can migrate to it after handshake.
	 * This enables server-directed migration for load balancing/failover.
	 *
	 * The preferred_addr pointer holds client-side migration state
	 * (struct tquic_pref_addr_migration *) which includes:
	 * - IPv4 and IPv6 preferred addresses from server
	 * - Connection ID for preferred address path
	 * - Stateless reset token for the CID
	 * - Migration state machine
	 *
	 * For server-side, this holds the config being advertised
	 * (struct tquic_pref_addr_config *).
	 */
	void *preferred_addr; /* struct tquic_pref_addr_migration/config * */

	/*
	 * Additional Addresses state (draft-piraux-quic-additional-addresses)
	 *
	 * The additional_addresses transport parameter allows endpoints to
	 * advertise multiple addresses for connection migration beyond the
	 * single preferred_address. This enables flexible migration scenarios
	 * for multipath and mobile connections.
	 *
	 * additional_local_addrs: Local addresses to advertise to peer
	 * additional_remote_addrs: Remote addresses received from peer
	 *
	 * Both are struct tquic_additional_addresses *.
	 */
	void *additional_local_addrs; /* Local addresses to advertise */
	void *additional_remote_addrs; /* Remote addresses from peer */

	/*
	 * HTTP/3 Priority state (RFC 9218)
	 *
	 * Manages RFC 9218 Extensible Priorities for HTTP/3 streams.
	 * Contains urgency buckets (0-7) for priority-based scheduling
	 * and stream-to-priority mapping via RB-tree.
	 *
	 * This is allocated by http3_priority_state_init() when HTTP/3
	 * layer is established on this QUIC connection.
	 */
	void *priority_state; /* struct http3_priority_state * */

	/*
	 * ACK Frequency state (RFC 9002 Appendix A.7, draft-ietf-quic-ack-frequency)
	 *
	 * Manages ACK frequency negotiation and dynamic adjustment including:
	 *   - min_ack_delay transport parameter (0xff04de1a)
	 *   - ACK_FREQUENCY frame (0xaf) generation and handling
	 *   - IMMEDIATE_ACK frame (0x1f) generation and handling
	 *   - Dynamic ACK frequency adjustment based on:
	 *     - Congestion control state (recovery, exit recovery)
	 *     - RTT characteristics (low/high RTT paths)
	 *     - Bandwidth estimates (high bandwidth paths)
	 *     - Packet reordering detection
	 *     - Application hints (latency-sensitive, throughput-focused)
	 *     - ECN congestion signals
	 *
	 * Allocated by tquic_ack_freq_conn_init() during connection setup.
	 * Freed by tquic_ack_freq_conn_cleanup() during connection teardown.
	 */
	void *ack_freq_state; /* struct tquic_ack_frequency_state * */

	/*
	 * Zero-copy I/O state (MSG_ZEROCOPY support)
	 *
	 * Tracks pending zero-copy sends, manages page pinning,
	 * and handles completion notifications via SO_EE_CODE_ZEROCOPY_COPIED.
	 * Allocated by tquic_zc_state_alloc(), freed by tquic_zc_state_free().
	 */
	void *zc_state; /* struct tquic_zc_state * */

	/*
	 * Extended Key Update state (RFC 9369 Key Update extension)
	 *
	 * Manages extended key update negotiations and tracking for
	 * enhanced cryptographic agility.
	 */
	void *eku_state; /* struct tquic_eku_state * */

	/*
	 * io_uring integration context
	 *
	 * Manages buffer rings for recv, completion queue entries,
	 * and async I/O operations for high-performance I/O paths.
	 * Allocated by tquic_uring_ctx_alloc(), freed by tquic_uring_ctx_free().
	 */
	void *uring_ctx; /* struct tquic_uring_ctx * */

	/*
	 * Connection-level flags (atomic bit operations)
	 *
	 * Uses set_bit/clear_bit/test_bit for lock-free flag manipulation.
	 * See TQUIC_CONN_FLAG_* definitions below.
	 */
	unsigned long flags;

	/*
	 * Transmit tasklet for deferred/batched transmission
	 *
	 * Used for immediate transmission of time-sensitive frames
	 * like PATH_RESPONSE without holding connection locks.
	 * Scheduled via tasklet_hi_schedule() for high-priority processing.
	 */
	struct tasklet_struct tx_tasklet;

	/*
	 * Control frame queue (RESET_STREAM, STOP_SENDING, etc.)
	 *
	 * Frames queued here are transmitted in the next packet.
	 * Protected by connection lock.
	 */
	struct sk_buff_head control_frames;

	/*
	 * Frame queues for various purposes
	 */
	struct sk_buff_head pacing_queue; /* Pacing-delayed frames */
	struct sk_buff_head early_data_buffer; /* 0-RTT early data buffer */
	struct sk_buff_head
		crypto_buffer[TQUIC_PN_SPACE_COUNT]; /* Per-space crypto buffers */

	/*
	 * Work structs for deferred processing
	 */
	struct work_struct tx_work;
	struct work_struct close_work; /* Connection close processing */

	/*
	 * Reliable Stream Reset (draft-ietf-quic-reliable-stream-reset-07)
	 *
	 * True when both endpoints have negotiated support for
	 * RESET_STREAM_AT frames via the reliable_stream_reset
	 * transport parameter (0x17cd).
	 */
	bool reliable_reset_enabled;

	/*
	 * Address Discovery state (draft-ietf-quic-address-discovery)
	 *
	 * Manages OBSERVED_ADDRESS frame generation and processing,
	 * NAT rebinding detection, and address change notifications.
	 * Allocated by tquic_pm_init_address_discovery() after
	 * transport parameter negotiation confirms mutual support.
	 */
	struct tquic_addr_discovery_state *addr_discovery_state;

	/*
	 * Negotiated transport parameters
	 *
	 * Result of transport parameter negotiation between endpoints.
	 * Contains the effective values for flow control, stream limits,
	 * and extension support after applying negotiation rules.
	 * Allocated separately to avoid header dependency on transport_params.h
	 */
	struct tquic_negotiated_params *negotiated_params;

	/*
	 * BDP Frame Extension state (draft-kuhn-quic-bdpframe-extension-05)
	 *
	 * Manages BDP (Bandwidth-Delay Product) frame generation, reception,
	 * validation, and Careful Resume algorithm for safe congestion control
	 * state restoration across connection resumption.
	 *
	 * Allocated by tquic_bdp_init() after transport parameter negotiation
	 * confirms mutual support. Freed by tquic_bdp_release().
	 */
	void *bdp_state; /* struct tquic_bdp_state * */

	/*
	 * Congestion Control Data Exchange state (draft-yuan-quic-congestion-data-00)
	 *
	 * Manages CONGESTION_DATA frame generation, reception, validation,
	 * and Careful Resume for congestion control state restoration during
	 * connection resumption. Supports 0-RTT integration for faster startup.
	 *
	 * Allocated by tquic_cong_data_init() after transport parameter negotiation
	 * confirms mutual support. Freed by tquic_cong_data_release().
	 */
	void *cong_data_state; /* struct tquic_cong_data_state * */

	/* AF_XDP socket for kernel-bypass packet I/O */
	struct tquic_xsk *xsk;

#ifdef CONFIG_TQUIC_FEC
	struct tquic_fec_state *fec_state; /* FEC encoder/decoder; NULL if disabled */
#endif
#ifdef CONFIG_TQUIC_QUIC_LB
	struct tquic_lb_config *lb_config; /* QUIC-LB config; NULL if unused */
#endif
#ifdef CONFIG_TQUIC_OVER_TCP
	struct tquic_fallback_ctx *fallback_ctx; /* TCP fallback; NULL if unused */
#endif

	struct tquic_pacing_state *pacing; /* Pacing state; NULL if disabled */
	struct tquic_gro_state *gro; /* GRO aggregation; NULL if disabled */

	spinlock_t lock;
	refcount_t refcnt;
	struct sock *sk;
	struct rhash_head node;
	struct list_head pm_node; /* Path manager connection list linkage */
};

/*
 * Connection flag bits for tquic_connection.flags
 *
 * Use set_bit(), clear_bit(), test_bit() for atomic access.
 * These flags enable lock-free signaling between different contexts
 * (e.g., softirq, process context, tasklet).
 */
#define TQUIC_CONN_FLAG_PATH_RESPONSE_PENDING \
	0 /* PATH_RESPONSE needs sending */
#define TQUIC_CONN_FLAG_ACK_PENDING 1 /* ACK frame needs sending */
#define TQUIC_CONN_FLAG_HANDSHAKE_DONE 2 /* Handshake completed */
#define TQUIC_CONN_FLAG_DRAINING 3 /* Connection draining */
#define TQUIC_CONN_FLAG_IMMEDIATE_ACK 4 /* Send ACK immediately */
#define TQUIC_CONN_FLAG_KEY_UPDATE_PENDING 5 /* Key update in progress */
#define TQUIC_CONN_FLAG_TASKLET_SCHED 6 /* TX tasklet is scheduled */

/* Backwards compatibility alias */
#define TQUIC_PATH_RESPONSE_PENDING TQUIC_CONN_FLAG_PATH_RESPONSE_PENDING

/* Forward declaration for handshake state */
struct tquic_handshake_state;

/**
 * struct tquic_bond_state - WAN bonding state per connection
 * @mode: Bonding mode (active-backup, round-robin, etc.)
 * @aggr_mode: Aggregation mode
 * @failover_mode: Failover mode
 * @reorder_queue: Reorder buffer for out-of-order packets
 * @reorder_next_seq: Next expected sequence number
 * @reorder_window: Size of reorder window
 * @stats: Bonding statistics
 * @rr_counter: Round-robin counter
 * @primary_path: Primary path for active-backup mode
 * @failover_pending: Failover operation in progress
 * @conn: Reference to parent connection
 */
struct tquic_bond_state {
	u8 mode;
	u8 aggr_mode;
	u8 failover_mode;

	struct sk_buff_head reorder_queue;
	u64 reorder_next_seq;
	u32 reorder_window;
	spinlock_t reorder_lock;

	struct tquic_bond_stats stats;

	atomic_t rr_counter;
	struct tquic_path *primary_path;

	bool failover_pending;
	ktime_t failover_start;
	struct tquic_path *failover_from;

	struct work_struct failover_work;
	struct delayed_work probe_work;

	struct tquic_connection *conn;
};

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
	struct socket *udp_sock; /* UDP encapsulation socket */

	struct sockaddr_storage bind_addr;
	struct sockaddr_storage connect_addr;

	struct list_head accept_queue; /* Listener: queue of pending children */
	struct list_head accept_list; /* Child: linkage in listener's queue */
	struct hlist_node listener_node; /* Listener hash table linkage */
	atomic_t accept_queue_len;
	u32 max_accept_queue;

	/* Listener: deferred packet processing (encap_rcv runs in softirq) */
	struct sk_buff_head listener_queue;
	struct work_struct listener_work;

	/*
	 * Socket-owned reference to the default stream.
	 *
	 * This pointer may be accessed concurrently (e.g. data delivery from
	 * softirq context). Always use tquic_sock_default_stream_get() (or
	 * tquic_sock_default_stream_get_or_open()) to acquire a transient ref
	 * before dereferencing. The socket holds its own ref while the pointer
	 * is installed, so it cannot dangle.
	 */
	struct tquic_stream *default_stream;

	/* Handshake state (NULL when not in handshake) */
	struct tquic_handshake_state *handshake_state;

	/* Inline TLS 1.3 handshake context (NULL when using tlshd) */
	struct tquic_handshake *inline_hs;

	/* Socket flags (TQUIC_F_*) - see net/tquic/protocol.h */
	u32 flags;

	/* Socket options */
	bool nodelay; /* TQUIC_NODELAY: disable Nagle, send immediately */
	bool pacing_enabled; /* SO_TQUIC_PACING: enable pacing (default true) */

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
	 * Server name for SNI and 0-RTT ticket lookup (set via connect)
	 *
	 * For client: Server hostname used for TLS SNI and 0-RTT session
	 *             ticket lookup. Set during connect() from sockaddr.
	 * For server: Not used.
	 */
	char server_name[256];
	u8 server_name_len;

	/*
	 * DATAGRAM frame support (RFC 9221)
	 *
	 * When enabled, sendmsg/recvmsg can transfer unreliable datagrams
	 * using cmsg with TQUIC_CMSG_DATAGRAM type.
	 */
	bool datagram_enabled; /* SO_TQUIC_DATAGRAM enabled */
	u32 datagram_queue_max; /* Max receive queue length */

	/*
	 * HTTP/3 support (RFC 9114)
	 *
	 * When enabled, the QUIC connection operates in HTTP/3 mode with
	 * proper stream type mapping, control streams, and QPACK support.
	 */
	bool http3_enabled; /* SO_TQUIC_HTTP3_ENABLE enabled */
	struct {
		u32 max_table_capacity; /* QPACK max table capacity */
		u32 max_field_section_size; /* Max header section size */
		u32 max_blocked_streams; /* QPACK blocked streams */
		bool server_push_enabled; /* Server push support */
	} http3_settings;
	void *h3_conn; /* h3_connection pointer when active */

	/*
	 * Certificate verification settings
	 *
	 * Controls TLS certificate chain validation behavior.
	 * Settings must be configured before connect().
	 */
	struct {
		u8 verify_mode; /* TQUIC_VERIFY_* mode */
		bool verify_hostname; /* Check hostname matches cert */
		bool allow_self_signed; /* Allow self-signed certs (testing) */
		char expected_hostname[256]; /* Override hostname for matching */
		u8 expected_hostname_len;
	} cert_verify;

	/*
	 * Server certificate and private key (DER-encoded)
	 *
	 * Set via SO_TQUIC_CERTIFICATE / SO_TQUIC_PRIVATE_KEY sockopts
	 * before listen(). Inherited by child sockets on accept.
	 */
	u8 *cert_der;
	u32 cert_der_len;
	u8 *key_der;
	u32 key_der_len;

	/* Connection configuration (using full tquic_config struct) */
	struct tquic_config config;

	/* Event wait queue */
	wait_queue_head_t event_wait;
};

static inline struct tquic_sock *tquic_sk(const struct sock *sk)
{
	return (struct tquic_sock *)sk;
}

/* Bonding operations */
struct tquic_bond_ops {
	const char *name;

	int (*add_path)(struct tquic_connection *conn, struct sockaddr *local,
			struct sockaddr *remote);
	int (*remove_path)(struct tquic_connection *conn, u32 path_id);
	int (*set_path_priority)(struct tquic_connection *conn, u32 path_id,
				 u8 priority);
	int (*get_path_info)(struct tquic_connection *conn, u32 path_id,
			     struct tquic_path_info *info);

	struct tquic_path *(*select_path)(struct tquic_connection *conn,
					  struct sk_buff *skb);
	void (*path_event)(struct tquic_connection *conn,
			   struct tquic_path *path, int event);
};

/* Scheduler operations (simple interface) */
struct tquic_sched_ops {
	const char *name;
	struct module *owner;

	void *(*init)(struct tquic_connection *conn);
	void (*release)(void *sched_data);

	struct tquic_path *(*select)(void *sched_data,
				     struct tquic_connection *conn,
				     struct sk_buff *skb);
	void (*feedback)(void *sched_data, struct tquic_path *path,
			 struct sk_buff *skb, bool success);

	struct list_head list;
};

/**
 * struct tquic_sched_path_result - Path selection result for multipath schedulers
 * @primary: Primary path for packet transmission
 * @backup: Backup path for failover (optional, may be NULL)
 * @flags: Flags affecting transmission (TQUIC_SCHED_F_*)
 */
struct tquic_sched_path_result {
	struct tquic_path *primary;
	struct tquic_path *backup;
	u32 flags;
};

/* Scheduler result flags */
#define TQUIC_SCHED_F_REDUNDANT BIT(0) /* Send on multiple paths */

/**
 * struct tquic_mp_sched_ops - Multipath scheduler operations
 *
 * Extended scheduler interface for multipath QUIC with path event callbacks.
 * This is the preferred interface for advanced multipath schedulers that need
 * feedback from ACK/loss events to make path selection decisions.
 */
struct tquic_mp_sched_ops {
	char name[TQUIC_SCHED_NAME_MAX];
	struct module *owner;
	struct list_head list;

	/* Required: select path for next packet */
	int (*get_path)(struct tquic_connection *conn,
			struct tquic_sched_path_result *result, u32 flags);

	/* Optional lifecycle hooks */
	int (*init)(struct tquic_connection *conn);
	void (*release)(struct tquic_connection *conn);

	/* Optional path events */
	void (*path_added)(struct tquic_connection *conn,
			   struct tquic_path *path);
	void (*path_removed)(struct tquic_connection *conn,
			     struct tquic_path *path);

	/* Optional feedback hooks */
	void (*packet_sent)(struct tquic_connection *conn,
			    struct tquic_path *path, u32 sent_bytes);
	void (*ack_received)(struct tquic_connection *conn,
			     struct tquic_path *path, u64 acked_bytes);
	void (*loss_detected)(struct tquic_connection *conn,
			      struct tquic_path *path, u64 lost_bytes);
} ____cacheline_aligned_in_smp;

/* Multipath scheduler registration API */
int tquic_mp_register_scheduler(struct tquic_mp_sched_ops *sched);
void tquic_mp_unregister_scheduler(struct tquic_mp_sched_ops *sched);
struct tquic_mp_sched_ops *tquic_mp_sched_find(const char *name);

/* Multipath scheduler per-connection lifecycle API */
int tquic_mp_sched_init_conn(struct tquic_connection *conn, const char *name);
void tquic_mp_sched_release_conn(struct tquic_connection *conn);
int tquic_mp_sched_get_path(struct tquic_connection *conn,
			    struct tquic_sched_path_result *result, u32 flags);

/* Multipath scheduler notification API */
void tquic_mp_sched_notify_sent(struct tquic_connection *conn,
				struct tquic_path *path, u32 sent_bytes);
void tquic_mp_sched_notify_ack(struct tquic_connection *conn,
			       struct tquic_path *path, u64 acked_bytes);
void tquic_mp_sched_notify_loss(struct tquic_connection *conn,
				struct tquic_path *path, u64 lost_bytes);

/*
 * Path events: Base events defined in <uapi/linux/tquic.h>
 * Additional internal-only events for scheduler callbacks:
 */
#define TQUIC_PATH_EVENT_RTT_UPDATE 100 /* Path RTT estimate updated */
#define TQUIC_PATH_EVENT_CWND_UPDATE 101 /* Path congestion window changed */

/* Scheduler parameter IDs for set_param callback */
#define TQUIC_SCHED_PARAM_MODE 0
#define TQUIC_SCHED_PARAM_MIN_PATHS 1

/* Scheduler context passed to select_path callback */
struct tquic_sched_ctx {
	struct sk_buff *skb; /* Packet to schedule */
	u64 stream_id; /* Stream ID (if stream data) */
	u32 len; /* Payload length */
	u8 frame_type; /* Primary frame type */
	bool ack_eliciting; /* Is this an ack-eliciting packet */
	bool retransmission; /* Is this a retransmission */
};

/**
 * struct tquic_sched_stats - Scheduler statistics for get_stats callback
 * @total_sent_bytes: Total bytes sent across all paths
 * @total_sent_packets: Total packets sent across all paths
 * @total_acked_bytes: Total bytes acknowledged
 * @total_lost_packets: Total packets detected as lost
 * @path_switches: Number of times scheduler switched paths
 * @scheduler_invocations: Number of times scheduler was called
 */
struct tquic_sched_stats {
	u64 total_sent_bytes;
	u64 total_sent_packets;
	u64 total_acked_bytes;
	u64 total_lost_packets;
	u64 path_switches;
	u64 scheduler_invocations;
};

/* Maximum private data size for BPF schedulers */
#define TQUIC_SCHED_PRIV_SIZE 256

/* Forward declaration for path manager */
struct tquic_pm_state;

/**
 * struct tquic_scheduler - BPF struct_ops scheduler state
 * @ops: Pointer to scheduler operations (BPF or built-in)
 * @pm: Path manager state (provides path list access)
 * @conn: Parent connection
 * @rr_counter: Round-robin counter for default scheduling
 * @priv_data: Private data area for BPF scheduler state
 * @total_sent_bytes: Statistics: total bytes sent
 * @total_sent_packets: Statistics: total packets sent
 * @total_acked_bytes: Statistics: total bytes acknowledged
 * @total_lost_packets: Statistics: total packets lost
 * @path_switches: Statistics: number of path switches
 * @scheduler_invocations: Statistics: number of invocations
 * @lock: Spinlock for scheduler state protection
 */
struct tquic_scheduler {
	struct tquic_scheduler_ops *ops;
	struct tquic_pm_state *pm;
	struct tquic_connection *conn;

	/* Default scheduler state */
	u32 rr_counter;

	/* BPF private data area */
	u8 priv_data[TQUIC_SCHED_PRIV_SIZE];

	/* Statistics (updated by callbacks) */
	u64 total_sent_bytes;
	u64 total_sent_packets;
	u64 total_acked_bytes;
	u64 total_lost_packets;
	u64 path_switches;
	u64 scheduler_invocations;

	spinlock_t lock;
};

/**
 * struct tquic_scheduler_ops - BPF struct_ops scheduler interface
 *
 * This structure defines the interface for BPF-implemented schedulers.
 * It is more comprehensive than tquic_sched_ops, providing fine-grained
 * event callbacks for BPF programs to track state and make decisions.
 */
struct tquic_scheduler_ops {
	const char *name;
	struct module *owner;

	/* Lifecycle callbacks */
	int (*init)(struct tquic_scheduler *sched);
	void (*release)(struct tquic_scheduler *sched);

	/* Path selection (required) */
	struct tquic_path *(*select_path)(struct tquic_scheduler *sched,
					  struct tquic_sched_ctx *ctx);

	/* Event callbacks (all optional) */
	void (*on_packet_sent)(struct tquic_scheduler *sched,
			       struct tquic_path *path, u32 bytes);
	void (*on_packet_acked)(struct tquic_scheduler *sched,
				struct tquic_path *path, u32 bytes,
				ktime_t rtt);
	void (*on_packet_lost)(struct tquic_scheduler *sched,
			       struct tquic_path *path, u32 bytes);
	void (*on_path_change)(struct tquic_scheduler *sched,
			       struct tquic_path *path,
			       enum tquic_path_event event);

	/* Parameter and statistics */
	int (*set_param)(struct tquic_scheduler *sched, int param, u64 value);
	void (*get_stats)(struct tquic_scheduler *sched, void *stats,
			  size_t len);

	struct list_head list;
};

/* Scheduler registration for BPF struct_ops */
int tquic_scheduler_register(struct tquic_scheduler_ops *ops);
void tquic_scheduler_unregister(struct tquic_scheduler_ops *ops);

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
	void (*on_ecn)(void *cong_data, u64 ecn_ce_count); /* ECN CE handler */

	/*
	 * Persistent congestion handler (RFC 9002 Section 7.6)
	 *
	 * Called when persistent congestion is detected. The algorithm
	 * should reset cwnd to minimum (2 * max_datagram_size) and
	 * reset any algorithm-specific state as needed.
	 */
	void (*on_persistent_congestion)(
		void *cong_data, struct tquic_persistent_cong_info *info);

	u64 (*get_cwnd)(void *cong_data);
	u64 (*get_pacing_rate)(void *cong_data);
	bool (*can_send)(void *cong_data, u64 bytes);

	struct list_head list;
};

/* Socket address type compatibility */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 19, 0)
typedef struct sockaddr_unsized tquic_sockaddr_t;
#else
typedef struct sockaddr tquic_sockaddr_t;
#endif

/* Core API functions */
int tquic_connect(struct sock *sk, tquic_sockaddr_t *addr, int addr_len);
int tquic_accept(struct sock *sk, struct sock **newsk, int flags, bool kern);
int tquic_sendmsg(struct sock *sk, struct msghdr *msg, size_t len);
int tquic_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int flags,
		  int *addr_len);
void tquic_close(struct sock *sk, long timeout);
__poll_t tquic_poll(struct file *file, struct socket *sock, poll_table *wait);

/* Connection management */
struct tquic_connection *tquic_conn_create(struct tquic_sock *tsk,
					   bool is_server);
void tquic_conn_destroy(struct tquic_connection *conn);
int tquic_conn_add_path(struct tquic_connection *conn, struct sockaddr *local,
			struct sockaddr *remote);
int tquic_conn_remove_path(struct tquic_connection *conn, u32 path_id);
struct tquic_path *tquic_conn_get_path(struct tquic_connection *conn,
				       u32 path_id);
void tquic_conn_migrate(struct tquic_connection *conn,
			struct tquic_path *new_path);
struct tquic_connection *tquic_conn_lookup_by_token(struct net *net, u32 token);
void tquic_conn_flush_paths(struct tquic_connection *conn);

/* RCU-safe path operations (dynamic add/remove) */
int tquic_conn_add_path_safe(struct tquic_connection *conn,
			     struct sockaddr *local, struct sockaddr *remote);
int tquic_conn_remove_path_safe(struct tquic_connection *conn, u32 path_id);
struct tquic_path *tquic_conn_get_path_locked(struct tquic_connection *conn,
					      u32 path_id);

/* Path manager connection lifecycle */
int tquic_pm_conn_init(struct tquic_connection *conn);
void tquic_pm_conn_release(struct tquic_connection *conn);

/* Loss detection initialization */
int tquic_loss_detection_init(struct tquic_connection *conn);
void tquic_loss_detection_cleanup(struct tquic_connection *conn);

/* Scheduler initialization */
int tquic_sched_init(struct tquic_connection *conn);
void tquic_sched_cleanup(struct tquic_connection *conn);

/* Path validation (PATH_CHALLENGE/RESPONSE) - net/tquic/pm/path_validation.c */
int tquic_path_start_validation(struct tquic_connection *conn,
				struct tquic_path *path);
int tquic_path_handle_challenge(struct tquic_connection *conn,
				struct tquic_path *path, const u8 *data);
int tquic_path_handle_response(struct tquic_connection *conn,
			       struct tquic_path *path, const u8 *data);
void tquic_path_validation_timeout(struct timer_list *t);
void tquic_path_validation_expired(struct timer_list *t);
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
int tquic_conn_retire_cid(struct tquic_connection *conn, u64 seq,
			  bool is_local);
struct tquic_cid *tquic_conn_get_active_cid(struct tquic_connection *conn);

/* CID manager operations for additional_addresses */
int tquic_cid_register_remote(struct tquic_cid_manager *mgr,
			      const struct tquic_cid *cid, u64 seq_num,
			      const u8 *reset_token);
int tquic_cid_register_local(struct tquic_cid_manager *mgr,
			     const struct tquic_cid *cid);

/* Stateless reset */
void tquic_generate_stateless_reset_token(const struct tquic_cid *cid,
					  const u8 *static_key, u8 *token);
bool tquic_verify_stateless_reset(struct tquic_connection *conn, const u8 *data,
				  size_t len);
int tquic_send_stateless_reset(struct tquic_connection *conn);

/* Version negotiation (RFC 9000, RFC 9368, RFC 9369) */
bool tquic_version_is_supported(u32 version);
u32 tquic_version_select(const u32 *offered, int num_offered);
int tquic_get_preferred_versions(u32 *versions);
u32 tquic_version_select_for_initial(void);
int tquic_send_version_negotiation(struct tquic_connection *conn,
				   const struct tquic_cid *dcid,
				   const struct tquic_cid *scid);
int tquic_handle_version_negotiation(struct tquic_connection *conn,
				     const u32 *versions, int num_versions);

/* Retry token handling */
int tquic_generate_retry_token(struct tquic_connection *conn,
			       const struct tquic_cid *original_dcid,
			       const struct sockaddr *client_addr, u8 *token,
			       u32 *token_len);
int tquic_validate_retry_token(struct tquic_connection *conn, const u8 *token,
			       u32 token_len,
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
int tquic_conn_send_0rtt(struct tquic_connection *conn, const void *data,
			 size_t len);
void tquic_conn_0rtt_accepted(struct tquic_connection *conn);
void tquic_conn_0rtt_rejected(struct tquic_connection *conn);

/* Handshake packet processing */
int tquic_conn_process_handshake(struct tquic_connection *conn,
				 struct sk_buff *skb);

/* Connection close */
int tquic_conn_set_state(struct tquic_connection *conn,
			 enum tquic_conn_state new_state,
			 enum tquic_state_reason reason);
int tquic_conn_close_with_error(struct tquic_connection *conn, u64 error_code,
				const char *reason);
int tquic_conn_close_app(struct tquic_connection *conn, u64 error_code,
			 const char *reason);
void tquic_conn_enter_closed(struct tquic_connection *conn);
int tquic_conn_handle_close(struct tquic_connection *conn, u64 error_code,
			    u64 frame_type, const char *reason, bool is_app);
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
struct tquic_connection *tquic_state_cid_lookup(const struct tquic_cid *cid);

/**
 * tquic_conn_get - Acquire a reference on a connection
 * @conn: Connection to reference
 *
 * Increments the connection's reference count. Use this when storing
 * a pointer to a connection that needs to remain valid.
 *
 * Returns: true if reference was acquired, false if connection is being destroyed
 */
static inline bool tquic_conn_get(struct tquic_connection *conn)
{
	return refcount_inc_not_zero(&conn->refcnt);
}

static inline struct tquic_connection *
tquic_sock_conn_get(struct tquic_sock *tsk)
{
	struct sock *sk = (struct sock *)tsk;
	struct tquic_connection *conn;

	/*
	 * tsk->conn can be cleared concurrently during teardown. Protect the
	 * pointer + ref acquisition with sk_callback_lock so readers can safely
	 * take a reference without racing a final tquic_conn_put().
	 */
	read_lock_bh(&sk->sk_callback_lock);
	conn = tsk->conn;
	if (conn && !tquic_conn_get(conn))
		conn = NULL;
	read_unlock_bh(&sk->sk_callback_lock);

	return conn;
}

/**
 * tquic_conn_put - Release a reference on a connection
 * @conn: Connection to release
 *
 * Decrements the connection's reference count. When the count reaches
 * zero, the connection will be destroyed.
 *
 * Note: This function returns whether the final reference was dropped,
 * but callers should not rely on this for destruction - the destruction
 * is handled internally.
 */
static inline void tquic_conn_put(struct tquic_connection *conn)
{
	if (refcount_dec_and_test(&conn->refcnt))
		tquic_conn_destroy(conn);
}

/**
 * tquic_path_get - Acquire a reference on a path
 * @path: Path to reference
 *
 * Returns: true if reference was acquired, false if path is being destroyed
 */
static inline bool tquic_path_get(struct tquic_path *path)
{
	return refcount_inc_not_zero(&path->refcnt);
}

/**
 * tquic_path_put - Release a reference on a path
 * @path: Path to release
 *
 * Decrements the path's reference count. When the count reaches zero,
 * the path is freed.
 */
void tquic_path_free(struct tquic_path *path);
static inline void tquic_path_put(struct tquic_path *path)
{
	if (refcount_dec_and_test(&path->refcnt))
		tquic_path_free(path);
}

/* Path data accounting (anti-amplification + statistics) */
void tquic_path_on_data_sent(struct tquic_path *path, u32 bytes);
void tquic_path_on_data_received(struct tquic_path *path, u32 bytes);

/* State machine cleanup */
void tquic_conn_state_cleanup(struct tquic_connection *conn);

/* Stream management */
struct tquic_stream *tquic_stream_open(struct tquic_connection *conn,
				       bool bidi);
struct tquic_stream *tquic_stream_open_incoming(struct tquic_connection *conn,
						u64 stream_id);
struct tquic_stream *tquic_conn_stream_lookup(struct tquic_connection *conn,
					      u64 stream_id);
bool tquic_stream_get(struct tquic_stream *stream);
void tquic_stream_put(struct tquic_stream *stream);
void tquic_stream_close(struct tquic_stream *stream);
void tquic_stream_destroy(struct tquic_stream_manager *mgr,
			  struct tquic_stream *stream);
int tquic_stream_send(struct tquic_stream *stream, const void *data, size_t len,
		      bool fin);
int tquic_stream_recv(struct tquic_stream *stream, void *data, size_t len);
void tquic_stream_reset(struct tquic_stream *stream, u64 error_code);

static inline struct tquic_stream *
tquic_sock_default_stream_get(struct tquic_sock *tsk)
{
	struct sock *sk = (struct sock *)tsk;
	struct tquic_stream *stream;

	read_lock_bh(&sk->sk_callback_lock);
	stream = tsk->default_stream;
	if (stream && !tquic_stream_get(stream))
		stream = NULL;
	read_unlock_bh(&sk->sk_callback_lock);

	return stream;
}

static inline struct tquic_stream *
tquic_sock_default_stream_get_or_open(struct tquic_sock *tsk,
				      struct tquic_connection *conn)
{
	struct sock *sk = (struct sock *)tsk;
	struct tquic_stream *stream, *new_stream;
	bool installed = false;

	stream = tquic_sock_default_stream_get(tsk);
	if (stream)
		return stream;

	new_stream = tquic_stream_open(conn, true);
	if (!new_stream)
		return NULL;

	write_lock_bh(&sk->sk_callback_lock);
	if (!tsk->default_stream) {
		/*
		 * Take the socket-owned reference before publishing the
		 * pointer, so any reader that sees it can always get a ref.
		 */
		if (!tquic_stream_get(new_stream)) {
			write_unlock_bh(&sk->sk_callback_lock);
			tquic_stream_close(new_stream);
			return NULL;
		}
		tsk->default_stream = new_stream;
		installed = true;

		/* Return a transient reference to the caller. */
		stream = new_stream;
		if (!tquic_stream_get(stream))
			stream = NULL;
	} else {
		stream = tsk->default_stream;
		if (stream && !tquic_stream_get(stream))
			stream = NULL;
	}
	write_unlock_bh(&sk->sk_callback_lock);

	/* Lost the race: close the extra stream we created. */
	if (!installed)
		tquic_stream_close(new_stream);

	return stream;
}

static inline void tquic_sock_default_stream_clear(struct tquic_sock *tsk)
{
	struct sock *sk = (struct sock *)tsk;
	struct tquic_stream *old;

	write_lock_bh(&sk->sk_callback_lock);
	old = tsk->default_stream;
	tsk->default_stream = NULL;
	write_unlock_bh(&sk->sk_callback_lock);

	if (old)
		tquic_stream_put(old);
}

/* Path management for WAN bonding */
struct tquic_path *tquic_path_create(struct tquic_connection *conn,
				     const struct sockaddr_storage *local,
				     const struct sockaddr_storage *remote);
int tquic_path_probe(struct tquic_connection *conn, struct tquic_path *path);
void tquic_path_validate(struct tquic_connection *conn,
			 struct tquic_path *path);
int tquic_path_validate_start(struct tquic_path *path);
int tquic_path_challenge(struct tquic_path *path);
void tquic_path_destroy(struct tquic_path *path);
void tquic_path_update_stats(struct tquic_path *path, struct sk_buff *skb,
			     bool success);
int tquic_path_set_weight(struct tquic_path *path, u8 weight);

/*
 * ECN (Explicit Congestion Notification) Support - RFC 9000 Section 13.4
 *
 * ECN allows routers to signal congestion without dropping packets by
 * marking the ECN field in the IP header. QUIC validates ECN capability
 * per-path and uses feedback from ACK_ECN frames.
 */
struct tquic_ack_frame; /* Forward declaration */

void tquic_ecn_init(struct tquic_path *path);
u8 tquic_ecn_get_marking(const struct tquic_path *path);
void tquic_ecn_on_packet_sent(struct tquic_path *path, u8 ecn_marking);
int tquic_ecn_validate_ack(struct tquic_path *path,
			   struct tquic_ack_frame *ack);
void tquic_ecn_process_ce(struct tquic_connection *conn,
			  struct tquic_path *path, u64 ce_count);
int tquic_ecn_mark_packet(struct sk_buff *skb, u8 ecn_marking);
u8 tquic_ecn_read_marking(struct sk_buff *skb);
void tquic_ecn_disable(struct tquic_path *path);
bool tquic_ecn_is_capable(struct tquic_path *path);

/* Bonding state machine (Phase 05) */
int tquic_bond_set_path_weight(struct tquic_connection *conn, u32 path_id,
			       u32 weight);
u32 tquic_bond_get_path_weight(struct tquic_connection *conn, u32 path_id);

/* Packet transmission (tquic_output.c) */
struct tquic_pacing_state;
/* Returns a referenced path; caller must release with tquic_path_put(). */
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
void tquic_offload_exit(void);

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
int tquic_send_datagram(struct tquic_connection *conn, const void *data,
			size_t len);

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
int tquic_recv_datagram(struct tquic_connection *conn, void *data, size_t len,
			int flags);

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
int tquic_xmit_close(struct tquic_connection *conn, u64 error_code,
		     bool is_app);
int tquic_send_ack(struct tquic_connection *conn, struct tquic_path *path,
		   u64 largest_ack, u64 ack_delay, u64 ack_range);
int tquic_send_ping(struct tquic_connection *conn, struct tquic_path *path);
int tquic_flow_send_max_data(struct tquic_connection *conn,
			     struct tquic_path *path, u64 max_data);
int tquic_flow_send_max_stream_data(struct tquic_connection *conn,
				    struct tquic_path *path, u64 stream_id,
				    u64 max_data);
int tquic_send_connection_close(struct tquic_connection *conn, u64 error_code,
				const char *reason);
int tquic_output_flush(struct tquic_connection *conn);
int tquic_output_flush_crypto(struct tquic_connection *conn);
int tquic_send_handshake_done(struct tquic_connection *conn);
int tquic_output_packet(struct tquic_connection *conn, struct tquic_path *path,
			struct sk_buff *skb);

/* Pacing */
struct tquic_pacing_state *tquic_pacing_init(struct tquic_connection *conn,
					     struct tquic_path *path);
void tquic_pacing_cleanup(struct tquic_pacing_state *pacing);
void tquic_pacing_update_rate(struct tquic_pacing_state *pacing, u64 rate);
int tquic_pacing_send(struct tquic_pacing_state *pacing, struct sk_buff *skb);

/* Packet reception (tquic_input.c) */
struct tquic_gro_state;
int tquic_udp_recv(struct sock *sk, struct sk_buff *skb);
int tquic_setup_udp_encap(struct sock *sk);
void tquic_clear_udp_encap(struct sock *sk);
int tquic_udp_encap_init(
	struct tquic_sock *tsk); /* Initialize UDP encap for sock */
int tquic_process_coalesced(struct tquic_connection *conn,
			    struct tquic_path *path, u8 *data, size_t total_len,
			    struct sockaddr_storage *src_addr);

/* GRO handling */
struct tquic_gro_state *tquic_gro_init(struct tquic_connection *conn,
				       void (*deliver)(struct sk_buff *));
void tquic_gro_cleanup(struct tquic_gro_state *gro);
int tquic_gro_flush(struct tquic_gro_state *gro,
		    void (*deliver)(struct sk_buff *));

/* Encryption/decryption (crypto/tls.c) */
struct tquic_crypto_state;

/*
 * Version-aware crypto initialization (RFC 9369 QUIC v2 support)
 *
 * tquic_crypto_init_versioned() initializes crypto state using the appropriate
 * HKDF labels and initial salt based on the QUIC version:
 *   - TQUIC_VERSION_1 (0x00000001): RFC 9001 - "quic key/iv/hp"
 *   - TQUIC_VERSION_2 (0x6b3343cf): RFC 9369 - "quicv2 key/iv/hp"
 *
 * tquic_crypto_init() is the legacy wrapper that defaults to QUIC v1.
 */
struct tquic_crypto_state *
tquic_crypto_init_versioned(const struct tquic_cid *dcid, bool is_server,
			    u32 version);
struct tquic_crypto_state *tquic_crypto_init(const struct tquic_cid *dcid,
					     bool is_server);
void tquic_crypto_cleanup(struct tquic_crypto_state *crypto);
void tquic_crypto_destroy(void *crypto); /* Destroy per-level crypto */
int tquic_crypto_derive_initial_secrets(struct tquic_connection *conn,
					const struct tquic_cid *dcid);

/* Version management for crypto state */
u32 tquic_crypto_get_version(struct tquic_crypto_state *crypto);
void tquic_crypto_set_version(struct tquic_crypto_state *crypto, u32 version);

/* Packet encryption/decryption - enc_level selects which key set to use */
int tquic_encrypt_packet(struct tquic_crypto_state *crypto, int enc_level,
			 u8 *header, size_t header_len, u8 *payload,
			 size_t payload_len, u64 pkt_num, u8 *out,
			 size_t *out_len);
int tquic_decrypt_packet(struct tquic_crypto_state *crypto, int enc_level,
			 const u8 *header, size_t header_len, u8 *payload,
			 size_t payload_len, u64 pkt_num, u8 *out,
			 size_t *out_len);
bool tquic_crypto_handshake_complete(struct tquic_crypto_state *crypto);

/*
 * Certificate Verification (crypto/cert_verify.c)
 *
 * Provides X.509 certificate chain validation for TQUIC TLS 1.3.
 * Uses kernel keyring infrastructure for trust anchor lookup.
 */
#ifdef CONFIG_TQUIC_CERT_VERIFY
struct tquic_cert_verify_ctx;
struct tquic_handshake;

/* Context management */
struct tquic_cert_verify_ctx *tquic_cert_verify_ctx_alloc(gfp_t gfp);
void tquic_cert_verify_ctx_free(struct tquic_cert_verify_ctx *ctx);

/* Configuration */
int tquic_cert_verify_set_hostname(struct tquic_cert_verify_ctx *ctx,
				   const char *hostname, u32 len);
int tquic_cert_verify_set_mode(struct tquic_cert_verify_ctx *ctx,
			       enum tquic_cert_verify_mode mode);
int tquic_cert_verify_set_keyring(struct tquic_cert_verify_ctx *ctx,
				  struct key *keyring);

/* Chain verification */
int tquic_verify_cert_chain(struct tquic_cert_verify_ctx *ctx,
			    const u8 *cert_chain, size_t chain_len);
int tquic_verify_hostname(const struct tquic_x509_cert *cert,
			  const char *expected, u32 expected_len);
const char *tquic_cert_verify_get_error(struct tquic_cert_verify_ctx *ctx);

/* Handshake integration */
int tquic_hs_verify_server_cert(struct tquic_handshake *hs,
				struct tquic_connection *conn);
int tquic_hs_verify_client_cert(struct tquic_handshake *hs,
				struct tquic_connection *conn);

/* Certificate chain access from handshake */
u8 *tquic_hs_get_peer_cert(struct tquic_handshake *hs, u32 *len);
u8 *tquic_hs_get_peer_cert_chain(struct tquic_handshake *hs, u32 *len);
const char *tquic_hs_get_sni(struct tquic_handshake *hs, u32 *len);
bool tquic_hs_is_psk_mode(struct tquic_handshake *hs);

/* Module init/exit */
int __init tquic_cert_verify_init(void);
void tquic_cert_verify_exit(void);

#endif /* CONFIG_TQUIC_CERT_VERIFY */

/* Scheduler registration and operations */
int tquic_register_scheduler(struct tquic_sched_ops *ops);
void tquic_unregister_scheduler(struct tquic_sched_ops *ops);
int tquic_sched_register(struct tquic_sched_ops *ops);
void tquic_sched_unregister(struct tquic_sched_ops *ops);
struct tquic_sched_ops *tquic_sched_find(const char *name);
int tquic_sched_set_default(const char *name);
void *tquic_sched_init_conn(struct tquic_connection *conn,
			    struct tquic_sched_ops *ops);
void tquic_sched_release_conn(struct tquic_sched_ops *ops, void *state);
const char *tquic_sched_get_default(struct net *net);
struct tquic_sched_ops *tquic_sched_default(void);

/* Congestion control registration */
int tquic_register_cong(struct tquic_cong_ops *ops);
void tquic_unregister_cong(struct tquic_cong_ops *ops);

/* Module initialization */
int __ref tquic_init(void);
void __exit tquic_exit(void);

/* Netlink interface */
int __init tquic_netlink_init(void);
void __exit tquic_netlink_exit(void);

/* Sysctl interface (registered per network namespace) */
int tquic_sysctl_init(struct net *net);
void tquic_sysctl_exit(struct net *net);

/* Protocol handler registration */
int __init tquic_proto_init(void);
void tquic_proto_exit(void);

/* Socket operations (tquic_socket.c) */
int tquic_init_sock(struct sock *sk);
void tquic_destroy_sock(struct sock *sk);
/*
 * sockptr_t was introduced in 5.9; on older kernels, the compat wrapper
 * in tquic_proto.c bridges the old char __user * interface.  Hide this
 * declaration from pre-5.9 kernels where sockptr_t is not yet defined
 * at the point this header is parsed.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
int tquic_sock_setsockopt(struct socket *sock, int level, int optname,
			  sockptr_t optval, unsigned int optlen);
#endif
int tquic_sock_getsockopt(struct socket *sock, int level, int optname,
			  char __user *optval, int __user *optlen);
int tquic_sock_bind(struct socket *sock, tquic_sockaddr_t *uaddr, int addr_len);
int tquic_connect_socket(struct socket *sock, tquic_sockaddr_t *uaddr,
			 int addr_len, int flags);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 7, 0)
int tquic_accept_socket(struct socket *sock, struct socket *newsock,
			struct proto_accept_arg *arg);
#else
int tquic_accept_socket(struct socket *sock, struct socket *newsock, int flags,
			bool kern);
#endif
int tquic_sock_getname(struct socket *sock, struct sockaddr *addr, int peer);
__poll_t tquic_poll_socket(struct file *file, struct socket *sock,
			   struct poll_table_struct *wait);
int tquic_sock_listen(struct socket *sock, int backlog);
int tquic_sock_shutdown(struct socket *sock, int how);
int tquic_sock_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg);
int tquic_sendmsg_socket(struct socket *sock, struct msghdr *msg, size_t len);
int tquic_recvmsg_socket(struct socket *sock, struct msghdr *msg, size_t len,
			 int flags);
ssize_t tquic_splice_read_socket(struct socket *sock, loff_t *ppos,
				 struct pipe_inode_info *pipe, size_t len,
				 unsigned int flags);

/* Diagnostics (ss tool integration) */
int __init tquic_diag_init(void);
void tquic_diag_exit(void);

/* MIB statistics (net/tquic/tquic_mib.c) */
struct seq_file;
void tquic_mib_seq_show(struct seq_file *seq);
int __init tquic_mib_init(struct net *net);
void __exit tquic_mib_exit(struct net *net);

/* Proc interface (net/tquic/tquic_proc.c) */
struct tquic_error_ring;
int tquic_proc_init(struct net *net);
void tquic_proc_exit(struct net *net);
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
int tquic_nl_path_event(struct tquic_connection *conn, struct tquic_path *path,
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
#define TQUIC_STATELESS_RESET_TOKEN_LEN 16

/* Minimum initial packet size */
#define TQUIC_MIN_INITIAL_PACKET_SIZE 1200

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
			    struct tquic_packet_header *hdr, u64 largest_pn);
int tquic_parse_short_header(const u8 *data, size_t len,
			     struct tquic_packet_header *hdr, u8 dcid_len,
			     u64 largest_pn);
bool tquic_is_long_header(const u8 *data, size_t len);
int tquic_get_packet_type(const u8 *data, size_t len);

/* Version negotiation */
int tquic_build_version_negotiation(const u8 *dcid, u8 dcid_len, const u8 *scid,
				    u8 scid_len, const u32 *versions,
				    int num_versions, u8 *buf, size_t buflen);
int tquic_parse_version_negotiation(const u8 *data, size_t len, u32 *versions,
				    int max_versions, int *num_versions);

/* Stateless reset */
int tquic_build_stateless_reset(const u8 *token, u8 *buf, size_t buflen);
bool tquic_is_stateless_reset(
	const u8 *data, size_t len,
	const u8 (*tokens)[TQUIC_STATELESS_RESET_TOKEN_LEN], int num_tokens);

/* Retry packets */
int tquic_build_retry(u32 version, const u8 *dcid, u8 dcid_len, const u8 *scid,
		      u8 scid_len, const u8 *odcid, u8 odcid_len,
		      const u8 *token, size_t token_len, u8 *buf,
		      size_t buflen);

/* Packet construction */
int tquic_build_long_header(enum tquic_packet_type type, u32 version,
			    const u8 *dcid, u8 dcid_len, const u8 *scid,
			    u8 scid_len, const u8 *token, size_t token_len,
			    u64 pn, int pn_len, const u8 *payload,
			    size_t payload_len, u8 *buf, size_t buflen);
int tquic_build_short_header(const u8 *dcid, u8 dcid_len, u64 pn, int pn_len,
			     u8 key_phase, u8 spin_bit, const u8 *payload,
			     size_t payload_len, u8 *buf, size_t buflen);

/* Coalesced packet handling */
int tquic_split_coalesced(const u8 *data, size_t len, const u8 **packets,
			  size_t *lengths, int max_packets, int *num_packets);
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
struct tquic_packet *tquic_packet_clone(const struct tquic_packet *pkt,
					gfp_t gfp);
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

/* Packet building and processing */
struct sk_buff *tquic_packet_build(struct tquic_connection *conn, int pn_space);
int tquic_packet_process(struct tquic_connection *conn, struct sk_buff *skb);
int tquic_packet_parse(struct sk_buff *skb, struct tquic_packet *pkt);
int tquic_frame_process_all(struct tquic_connection *conn, struct sk_buff *skb,
			    u8 level);
int tquic_frame_process_one(struct tquic_connection *conn, const u8 *data,
			    int len, u8 level);
int tquic_udp_send(struct tquic_sock *tsk, struct sk_buff *skb,
		   struct tquic_path *path);

/*
 * Connection ID Management
 */

/* CID management constants */
#define TQUIC_RESET_TOKEN_LEN 16
#ifndef TQUIC_CID_POOL_MIN
#define TQUIC_CID_POOL_MIN 4
#endif
#define TQUIC_CID_POOL_MAX 16

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
struct tquic_cid_manager *
tquic_cid_manager_create(struct tquic_connection *conn, u8 cid_len);
void tquic_cid_manager_destroy(struct tquic_cid_manager *mgr);

/* CID pool management */
int tquic_cid_pool_replenish(struct tquic_cid_manager *mgr);
struct tquic_cid_entry *
tquic_cid_get_unused_local(struct tquic_cid_manager *mgr);

/* NEW_CONNECTION_ID frame handling */
int tquic_cid_build_new_cid_frame(struct tquic_cid_manager *mgr,
				  struct tquic_new_cid_frame *frame);
int tquic_cid_handle_new_cid(struct tquic_cid_manager *mgr, u64 seq_num,
			     u64 retire_prior_to, const struct tquic_cid *cid,
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

/* Per-path CID assignment for multipath (CID manager interface) */
int tquic_cidmgr_assign_to_path(struct tquic_cid_manager *mgr,
				struct tquic_path *path);
void tquic_cidmgr_release_from_path(struct tquic_cid_manager *mgr,
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
const struct tquic_cid *
tquic_cid_get_active_local(struct tquic_cid_manager *mgr);
const struct tquic_cid *
tquic_cid_get_active_remote(struct tquic_cid_manager *mgr);
int tquic_cid_set_active_remote(struct tquic_cid_manager *mgr,
				const struct tquic_cid *cid);

/* Stateless reset handling */
int tquic_cid_get_reset_token(struct tquic_cid_manager *mgr,
			      const struct tquic_cid *cid, u8 *token);
bool tquic_cid_check_stateless_reset(struct tquic_cid_manager *mgr,
				     const u8 *token);

/* Statistics */
void tquic_cid_get_stats(struct tquic_cid_manager *mgr, u32 *local_count,
			 u32 *remote_count, u64 *local_seq);

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
int tquic_bond_get_stats(struct tquic_connection *conn,
			 struct tquic_bond_stats *stats);

/*
 * UDP Tunnel Integration for WAN Bonding
 */

/* Listener registration and lookup */
int tquic_register_listener(struct sock *sk);
void tquic_unregister_listener(struct sock *sk);
struct sock *tquic_lookup_listener(const struct sockaddr_storage *local_addr);
struct sock *
tquic_lookup_listener_net(struct net *net,
			  const struct sockaddr_storage *local_addr);

/* UDP socket lifecycle */
void tquic_udp_sock_put(struct tquic_udp_sock *us);

/* UDP socket connection */
int tquic_udp_connect(struct tquic_udp_sock *us,
		      struct sockaddr_storage *remote);

/* Receive path - deliver packets to connection */
int tquic_udp_deliver_to_conn(struct tquic_connection *conn,
			      struct tquic_path *path, struct sk_buff *skb);

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
			   struct tquic_path *path, struct sk_buff *skb);

/* inet_connection_sock integration */
int tquic_udp_icsk_bind(struct sock *sk, struct sockaddr *uaddr, int addr_len);

/* Module initialization */
int __init tquic_udp_init(void);
void tquic_udp_exit(void);

/*
 * Timer and Recovery System
 */

/* Forward declarations for timer state */
struct tquic_timer_state;
struct tquic_recovery_state;

/**
 * enum tquic_pkt_state - State of a sent packet in the loss detection machine
 * @TQUIC_PKT_OUTSTANDING: Sent, awaiting ACK
 * @TQUIC_PKT_ACKED:       Acknowledged by the peer
 * @TQUIC_PKT_LOST:        Declared lost by loss detection
 * @TQUIC_PKT_RETRANSMITTED: Retransmission has been scheduled
 *
 * Used by the timer/recovery path (tquic_timer.c) to track per-packet
 * state across the full loss-detection and retransmission lifecycle.
 */
enum tquic_pkt_state {
	TQUIC_PKT_OUTSTANDING, /* Awaiting ACK */
	TQUIC_PKT_ACKED, /* ACKed by peer */
	TQUIC_PKT_LOST, /* Declared lost */
	TQUIC_PKT_RETRANSMITTED, /* Retransmission scheduled */
};

/*
 * Packet metadata flags for struct tquic_sent_packet::flags.
 * Used by ack.c to track per-packet properties without a bool-per-field.
 */
#define TQUIC_PKT_FLAG_ACK_ELICITING BIT(0)
#define TQUIC_PKT_FLAG_IN_FLIGHT BIT(1)
#define TQUIC_PKT_FLAG_HAS_CRYPTO BIT(2)
#define TQUIC_PKT_FLAG_RETRANSMITTABLE BIT(3)
#define TQUIC_PKT_FLAG_PATH_CHALLENGE BIT(4)
#define TQUIC_PKT_FLAG_PATH_RESPONSE BIT(5)
#define TQUIC_PKT_FLAG_MTU_PROBE BIT(6)
#define TQUIC_PKT_FLAG_ECN_CE BIT(7)

/**
 * struct tquic_sent_packet - Canonical metadata for a sent QUIC packet
 *
 * This is the single authoritative definition shared by all compilation
 * units that track sent packets (tquic_timer.c, quic_loss.c, quic_output.c,
 * quic_connection.c, ack.c).  Having one definition in the shared header
 * eliminates undefined behaviour from passing pointers across translation
 * units that previously each had a local, incompatible copy.
 *
 * Field notes:
 *   @node:          RB-tree node; packet number ordering within a PN space.
 *   @list:          List linkage for time-ordered traversal and lost/acked
 *                   staging lists.
 *   @stream_data:   Per-packet list of stream data ranges, used by ack.c to
 *                   retransmit stream payload on loss.
 *   @pn:            QUIC packet number (unique within @pn_space).
 *   @sent_time:     ktime_t when the packet was handed to the network layer.
 *   @sent_bytes:    On-wire size of the packet in bytes.
 *   @size:          Alias for @sent_bytes kept for API compatibility with
 *                   callers that use the shorter name.
 *   @pn_space:      Packet number space index (Initial/Handshake/Application).
 *   @path_id:       Multipath path identifier this packet was sent on.
 *   @state:         Loss-detection state machine value (tquic_timer.c path).
 *   @ack_eliciting: True when the peer must send an ACK for this packet.
 *   @in_flight:     True when the packet counts against the congestion window.
 *   @retransmitted: True once a retransmission has been scheduled (quic_loss.c
 *                   / quic_output.c path, mutually exclusive with @state).
 *   @flags:         Bitmask of TQUIC_PKT_FLAG_* values (ack.c path).
 *   @frames:        Bitmask of QUIC frame types carried in the packet.
 *   @largest_acked: Largest ACK number piggybacked in this packet (ack.c).
 *   @retrans_of:    Packet number this is a retransmission of, or 0.
 *   @skb:           Socket buffer clone kept for potential retransmission.
 */
struct tquic_sent_packet {
	/* Tree / list linkage */
	struct rb_node node;
	struct list_head list;
	struct list_head stream_data; /* ack.c: stream ranges in pkt */

	/* Identification */
	u64 pn; /* QUIC packet number */
	u8 pn_space; /* PN space (Initial/HS/App) */
	u32 path_id; /* Multipath path identifier */

	/* Timing */
	ktime_t sent_time; /* Time of transmission */

	/* Size — both names in active use across the codebase */
	u32 sent_bytes; /* On-wire byte count */
	u32 size; /* Alias for sent_bytes */

	/* Loss-detection state (tquic_timer.c uses state enum; quic_loss.c /
	 * quic_output.c use the retransmitted bool; they track the same packet
	 * through non-overlapping code paths) */
	enum tquic_pkt_state state;
	bool ack_eliciting; /* Peer must ACK */
	bool in_flight; /* Counts vs congestion window */
	bool retransmitted; /* Retransmission scheduled */

	/* Flag bitmask (ack.c path, TQUIC_PKT_FLAG_* above) */
	u32 flags;

	/* Frame / retransmit metadata */
	u32 frames; /* Frame type bitmask */
	u64 largest_acked; /* Largest ACK in this packet */
	u64 retrans_of; /* Original pkt_num, or 0 */

	/* Payload for retransmission */
	struct sk_buff *skb;
};

/**
 * struct tquic_pn_space - Packet number space state
 *
 * QUIC has 3 packet number spaces: Initial, Handshake, Application.
 * Each space has independent packet numbering and ACK tracking.
 */
#ifndef TQUIC_PN_SPACE_DEFINED
#define TQUIC_PN_SPACE_DEFINED
struct tquic_pn_space {
	u64 largest_acked; /* Largest ACKed packet number */
	u64 largest_sent; /* Largest sent packet number */
	u64 next_pn; /* Next packet number to use */
	u64 largest_recv_pn; /* Largest received packet number */
	ktime_t loss_time; /* Time-based loss detection */
	ktime_t last_ack_time; /* Last ACK sent time */
	u32 ack_eliciting_in_flight; /* ACK-eliciting packets in flight */

	struct rb_root sent_packets; /* RB-tree of sent packets */
	struct list_head sent_list; /* Time-ordered list of sent packets */
	struct list_head lost_packets; /* Packets detected as lost */

	u64 *pending_acks; /* Packet numbers to ACK */
	u32 pending_ack_count; /* Number of pending ACKs */
	u32 pending_ack_capacity; /* Capacity of pending_acks array */

	struct {
		u64 largest_pn;
		u64 ranges[64]; /* ACK ranges */
		u32 num_ranges;
	} recv_ack_info; /* Received packet tracking for ACKs */
	u8 keys_available : 1; /* Crypto keys available */
	u8 keys_discarded : 1; /* Keys have been discarded */

	spinlock_t lock; /* Per-space lock */
};
#endif /* TQUIC_PN_SPACE_DEFINED */

/* RTT measurement and loss detection */
u32 tquic_rtt_pto(struct tquic_rtt_state *rtt);
int tquic_pn_space_get_sent_time(struct tquic_pn_space *pn_space, u64 pkt_num,
				 ktime_t *sent_time);

/* Crypto state management */
void tquic_crypto_destroy(void *crypto);

/* Timer state lifecycle */
struct tquic_timer_state *
tquic_timer_state_alloc(struct tquic_connection *conn);
void tquic_timer_state_free(struct tquic_timer_state *ts);
void tquic_timer_cancel_work(struct tquic_timer_state *ts);

/* Generic timer set function (from quic_timer.c) */
void tquic_timer_set(struct tquic_connection *conn, u8 timer_type,
		     ktime_t when);
void tquic_timer_cancel(struct tquic_connection *conn, u8 timer_type);

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
void tquic_timer_schedule_pacing(struct tquic_timer_state *ts,
				 u32 bytes_to_send);
void tquic_timer_set_pacing_rate(struct tquic_timer_state *ts, u64 rate);
bool tquic_timer_can_send_paced(struct tquic_timer_state *ts);

/* Path validation timers */
void tquic_timer_start_path_validation(struct tquic_connection *conn,
				       struct tquic_path *path);
void tquic_timer_path_validated(struct tquic_connection *conn,
				struct tquic_path *path);

/* Migration/session helpers (tquic_migration.c) */
int tquic_migration_get_status(struct tquic_connection *conn,
			       struct tquic_migrate_info *info);
void tquic_migration_cleanup(struct tquic_connection *conn);
void tquic_session_cleanup(struct tquic_connection *conn);

/* Packet tracking for recovery */
int tquic_timer_on_packet_sent(struct tquic_timer_state *ts, int pn_space,
			       u64 pkt_num, u32 bytes, bool ack_eliciting,
			       bool in_flight, u32 frames, u32 path_id);

/* ACK synchronization — call after core/quic_loss.c processes an ACK */
void tquic_timer_on_ack_processed(struct tquic_timer_state *ts, int pn_space,
				  u64 largest_acked);

/* RTT propagation — call after tquic_rtt_update() to feed PTO calculation */
void tquic_timer_update_rtt(struct tquic_timer_state *ts, u64 smoothed_rtt,
			    u64 rtt_variance, u64 latest_rtt);

/* Timer subsystem initialization */
int __init tquic_timer_init(void);
void tquic_timer_exit(void);

/*
 * =============================================================================
 * Path MTU Discovery (DPLPMTUD) - RFC 8899
 * =============================================================================
 */

/* PMTUD state machine states - defined in tquic_pmtud.h */

/* PMTUD constants */
#define TQUIC_PMTUD_BASE_MTU 1200 /* QUIC minimum MTU */
#define TQUIC_PMTUD_MAX_MTU_DEFAULT 1500 /* Ethernet MTU */
#define TQUIC_PMTUD_MAX_MTU_JUMBO 9000 /* Jumbo frames */

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
void tquic_pmtud_exit(void);

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
int tquic_coupled_get_subflow_stats(struct tquic_connection *conn, u32 path_id,
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
	struct tquic_sock tquic;
	struct ipv6_pinfo inet6;
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
				struct sockaddr_storage *addrs, int max_addrs);

/* IPv6 path management */
int tquic_v6_add_path(struct tquic_connection *conn, struct sockaddr_in6 *local,
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
#define TQUIC_HE_RESOLUTION_DELAY_MS 50
#define TQUIC_HE_CONNECTION_TIMEOUT_MS 30000

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
static inline sa_family_t
tquic_path_effective_family(const struct tquic_path *path)
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
		return 1200; /* QUIC minimum */

	return dst_mtu - overhead;
}

/* Bonding path recovery notification */
void tquic_bond_path_recovered(struct tquic_connection *conn,
			       struct tquic_path *path);

#else /* !CONFIG_IPV6 */

/* Stubs when IPv6 is not enabled */
static inline int tquic6_init(void)
{
	return 0;
}
static inline void tquic6_exit(void)
{
}

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

static inline sa_family_t
tquic_path_effective_family(const struct tquic_path *path)
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
int tquic_tunnel_icmp_forward(struct tquic_tunnel *tunnel, struct sk_buff *skb,
			      int direction);
int tquic_tunnel_handle_icmp_error(struct tquic_tunnel *tunnel, u8 type,
				   u8 code, u32 info);

/* Tunnel accessor functions */
u8 tquic_tunnel_get_traffic_class(struct tquic_tunnel *tunnel);
__be16 tquic_tunnel_get_dest_port(struct tquic_tunnel *tunnel);
int tquic_tunnel_get_dest_addr(struct tquic_tunnel *tunnel,
			       struct sockaddr_storage *addr);
int tquic_tunnel_get_stats(struct tquic_tunnel *tunnel, u64 *bytes_tx,
			   u64 *bytes_rx, u64 *packets_tx, u64 *packets_rx);
bool tquic_tunnel_is_tproxy(struct tquic_tunnel *tunnel);
void tquic_tunnel_schedule_forward(struct tquic_tunnel *tunnel);

/* Tunnel subsystem init/exit */
int __init tquic_tunnel_init(void);
void tquic_tunnel_exit(void);

/*
 * =============================================================================
 * QoS Traffic Classification
 * =============================================================================
 *
 * Traffic classification for tc HTB scheduling and DSCP marking.
 */

/* Traffic class constants */
#define TQUIC_TC_REALTIME 0
#define TQUIC_TC_INTERACTIVE 1
#define TQUIC_TC_BULK 2
#define TQUIC_TC_BACKGROUND 3

/* QoS classification */
int tquic_qos_classify(void *tunnel_ptr, u8 router_hint);
void tquic_qos_mark_skb(struct sk_buff *skb, void *tunnel_ptr);
u8 tquic_qos_get_dscp(u8 traffic_class);
u32 tquic_qos_get_priority(u8 traffic_class);

/* QoS statistics */
void tquic_qos_update_stats(u8 traffic_class, u64 bytes);
void tquic_qos_get_stats(u8 traffic_class, u64 *packets, u64 *bytes,
			 u64 *drops);

/* QoS subsystem init/exit */
int __init tquic_qos_init(void);
void tquic_qos_exit(void);

/*
 * =============================================================================
 * Zero-Copy Splice Forwarding
 * =============================================================================
 *
 * Data forwarding between QUIC streams and TCP sockets using splice.
 */

/* Forwarding directions */
#define TQUIC_FORWARD_TX 0 /* QUIC stream -> TCP socket */
#define TQUIC_FORWARD_RX 1 /* TCP socket -> QUIC stream */

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
void tquic_forward_teardown_tcp_callbacks(struct tquic_tunnel *tunnel);

/* GRO/GSO verification */
int tquic_forward_check_gro_gso(struct net_device *dev);

/* Forwarding subsystem init/exit */
int __init tquic_forward_init(void);
void tquic_forward_exit(void);

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
ssize_t tquic_sendpage(struct socket *sock, struct page *page, int offset,
		       size_t size, int flags);

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
