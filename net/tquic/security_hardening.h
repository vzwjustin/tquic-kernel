/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: Security Hardening Definitions
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * This header provides security hardening definitions for protecting
 * against known QUIC vulnerabilities and attacks:
 *
 * - CVE-2025-54939 (QUIC-LEAK): Pre-handshake memory exhaustion attack
 * - CVE-2024-22189: Retire CID stuffing attack
 * - Optimistic ACK attack: Packet number skipping defense
 * - ACK range validation: Prevent invalid ACK processing
 * - Spin bit privacy: Prevent latency fingerprinting
 */

#ifndef _TQUIC_SECURITY_HARDENING_H
#define _TQUIC_SECURITY_HARDENING_H

#include <linux/types.h>
#include <linux/rhashtable.h>
#include <linux/spinlock.h>
#include <linux/ktime.h>
#include <linux/atomic.h>

/*
 * =============================================================================
 * CVE-2025-54939: QUIC-LEAK Defense
 * =============================================================================
 *
 * The QUIC-LEAK attack exploits the fact that servers must allocate state
 * for Initial packets before the handshake completes (and client address
 * is validated). An attacker can exhaust server memory by sending many
 * Initial packets with spoofed source IPs.
 *
 * Defense:
 * - Limit total pre-handshake memory allocation
 * - Per-source-IP memory budget before handshake completion
 * - Limit Initial packet state allocation count
 */

/* Default pre-handshake memory limits */
#define TQUIC_PRE_HS_MEMORY_LIMIT_DEFAULT	(64 * 1024 * 1024)  /* 64 MB total */
#define TQUIC_PRE_HS_MEMORY_LIMIT_MIN		(1 * 1024 * 1024)   /* 1 MB min */
#define TQUIC_PRE_HS_MEMORY_LIMIT_MAX		(512 * 1024 * 1024) /* 512 MB max */

/* Per-IP pre-handshake memory budget */
#define TQUIC_PRE_HS_PER_IP_BUDGET_DEFAULT	(1 * 1024 * 1024)   /* 1 MB per IP */
#define TQUIC_PRE_HS_PER_IP_BUDGET_MIN		(64 * 1024)         /* 64 KB min */
#define TQUIC_PRE_HS_PER_IP_BUDGET_MAX		(16 * 1024 * 1024)  /* 16 MB max */

/* Maximum pre-handshake connections per IP */
#define TQUIC_PRE_HS_MAX_CONNS_PER_IP		16

/* Hash table size for per-IP tracking */
#define TQUIC_PRE_HS_IP_TABLE_SIZE		4096

/**
 * struct tquic_pre_hs_ip_entry - Per-IP pre-handshake state
 * @ip_hash: Hash key (IPv4 addr or IPv6 prefix)
 * @addr: Full address for verification
 * @memory_used: Memory allocated for this IP
 * @conn_count: Number of pre-handshake connections
 * @first_seen: Time of first connection attempt
 * @node: Hash table linkage
 * @rcu_head: RCU callback for deferred freeing
 */
struct tquic_pre_hs_ip_entry {
	u32 ip_hash;
	union {
		__be32 v4;
		struct in6_addr v6;
	} addr;
	bool is_v6;
	atomic64_t memory_used;
	atomic_t conn_count;
	ktime_t first_seen;
	struct rhash_head node;
	struct rcu_head rcu_head;
};

/**
 * struct tquic_pre_hs_state - Global pre-handshake memory tracking
 * @total_memory: Total pre-handshake memory used
 * @memory_limit: Maximum allowed pre-handshake memory
 * @per_ip_budget: Per-IP memory budget
 * @ip_table: Per-IP tracking hash table
 * @lock: Protects ip_table modifications
 */
struct tquic_pre_hs_state {
	atomic64_t total_memory;
	u64 memory_limit;
	u64 per_ip_budget;
	struct rhashtable ip_table;
	spinlock_t lock;
};

/* Pre-handshake state management */
int tquic_pre_hs_init(void);
void tquic_pre_hs_exit(void);

/* Memory accounting functions */
int tquic_pre_hs_alloc(const struct sockaddr_storage *addr, size_t size);
void tquic_pre_hs_free(const struct sockaddr_storage *addr, size_t size);
void tquic_pre_hs_connection_complete(const struct sockaddr_storage *addr);

/* Check if pre-handshake allocation is allowed */
bool tquic_pre_hs_can_allocate(const struct sockaddr_storage *addr, size_t size);

/*
 * =============================================================================
 * CVE-2024-22189: Retire CID Stuffing Attack Defense
 * =============================================================================
 *
 * An attacker can send a large number of NEW_CONNECTION_ID frames with high
 * retire_prior_to values, causing the victim to queue many RETIRE_CONNECTION_ID
 * frames. This can exhaust memory or CPU processing pending frames.
 *
 * Defense:
 * - Limit maximum queued RETIRE_CONNECTION_ID frames per connection
 * - Rate limit NEW_CONNECTION_ID frame processing
 * - Close connection with PROTOCOL_VIOLATION if limit exceeded
 */

/* Maximum queued RETIRE_CONNECTION_ID frames per connection */
#define TQUIC_MAX_QUEUED_RETIRE_CID		256

/* Rate limit for NEW_CONNECTION_ID processing (per second) */
#define TQUIC_NEW_CID_RATE_LIMIT		100

/* Minimum interval between NEW_CONNECTION_ID frames (ms) */
#define TQUIC_NEW_CID_MIN_INTERVAL_MS		10

/**
 * struct tquic_cid_security - CID security state per connection
 * @queued_retire_frames: Number of queued RETIRE_CONNECTION_ID frames
 * @new_cid_count: NEW_CONNECTION_ID frames received this second
 * @new_cid_window_start: Start of rate limit window
 * @last_new_cid_time: Time of last NEW_CONNECTION_ID frame
 * @lock: Protects this structure
 */
struct tquic_cid_security {
	atomic_t queued_retire_frames;
	u32 new_cid_count;
	ktime_t new_cid_window_start;
	ktime_t last_new_cid_time;
	spinlock_t lock;
};

/* CID security functions */
int tquic_cid_security_init(struct tquic_cid_security *sec);
void tquic_cid_security_destroy(struct tquic_cid_security *sec);

/* Check if NEW_CONNECTION_ID can be processed */
int tquic_cid_security_check_new_cid(struct tquic_cid_security *sec);

/* Track RETIRE_CONNECTION_ID frame queuing */
int tquic_cid_security_queue_retire(struct tquic_cid_security *sec);
void tquic_cid_security_dequeue_retire(struct tquic_cid_security *sec);

/*
 * =============================================================================
 * Optimistic ACK Attack Defense: Packet Number Skipping
 * =============================================================================
 *
 * An attacker can send ACKs for packets before receiving them (optimistic
 * ACKs) to inflate congestion window and cause excessive retransmissions.
 *
 * Defense:
 * - Randomly skip packet numbers occasionally
 * - If peer ACKs a skipped packet number, it's proof of optimistic ACKing
 * - Close connection on detection
 *
 * The skip rate is configurable via sysctl. Default is 1/128 (0.78%).
 */

/* Packet number skip rate (1 in N packets) */
#define TQUIC_PN_SKIP_RATE_DEFAULT		128
#define TQUIC_PN_SKIP_RATE_MIN			8
#define TQUIC_PN_SKIP_RATE_MAX			65536

/* Maximum skip amount (random 1-255) */
#define TQUIC_PN_SKIP_MIN			1
#define TQUIC_PN_SKIP_MAX			255

/* Maximum tracked skipped PNs (circular buffer) */
#define TQUIC_MAX_SKIPPED_PNS			64

/**
 * struct tquic_pn_skip_entry - Skipped packet number entry
 * @pn: The skipped packet number
 * @pn_space: Packet number space
 * @skip_time: When the skip was recorded
 */
struct tquic_pn_skip_entry {
	u64 pn;
	u8 pn_space;
	ktime_t skip_time;
};

/**
 * struct tquic_pn_skip_state - Packet number skipping state per connection
 * @skipped_pns: Circular buffer of skipped packet numbers
 * @head: Head index for circular buffer
 * @count: Number of entries in buffer
 * @skip_rate: Current skip rate (1 in N)
 * @next_skip_threshold: Random threshold for next skip
 * @packets_since_skip: Packets sent since last skip
 * @lock: Protects this structure
 */
struct tquic_pn_skip_state {
	struct tquic_pn_skip_entry skipped_pns[TQUIC_MAX_SKIPPED_PNS];
	u16 head;
	u16 count;
	u32 skip_rate;
	u32 next_skip_threshold;
	u32 packets_since_skip;
	spinlock_t lock;
};

/* PN skip state management */
int tquic_pn_skip_init(struct tquic_pn_skip_state *state, u32 skip_rate);
void tquic_pn_skip_destroy(struct tquic_pn_skip_state *state);

/* Check if should skip and get skip amount */
int tquic_pn_should_skip(struct tquic_pn_skip_state *state, u8 pn_space);

/* Record a skipped packet number */
void tquic_pn_record_skip(struct tquic_pn_skip_state *state, u64 pn, u8 pn_space);

/* Validate ACK - returns true if ACK references a skipped PN (attack detected) */
bool tquic_pn_check_optimistic_ack(struct tquic_pn_skip_state *state,
				   u64 acked_pn, u8 pn_space);

/*
 * =============================================================================
 * ACK Range Validation
 * =============================================================================
 *
 * Validate that ACK frames only acknowledge packet numbers that were actually
 * sent. An attacker could send ACKs for packets not yet sent to confuse
 * loss detection and congestion control.
 *
 * Defense:
 * - Track largest sent packet number per packet number space
 * - Validate ACK.largest_acknowledged <= largest_sent
 * - Close connection with PROTOCOL_VIOLATION on invalid ACK
 */

/**
 * struct tquic_ack_validation_state - ACK validation state per connection
 * @largest_sent_pn: Largest sent packet number per space
 * @lock: Protects this structure
 */
struct tquic_ack_validation_state {
	u64 largest_sent_pn[TQUIC_PN_SPACE_COUNT];
	spinlock_t lock;
};

/* Validation state initialization requires PN space count from main header */
#define TQUIC_PN_SPACE_COUNT	3

/* ACK validation functions */
int tquic_ack_validation_init(struct tquic_ack_validation_state *state);
void tquic_ack_validation_destroy(struct tquic_ack_validation_state *state);

/* Record sent packet number */
void tquic_ack_validation_record_sent(struct tquic_ack_validation_state *state,
				      u64 pn, u8 pn_space);

/* Validate ACK - returns 0 if valid, -EPROTO if invalid */
int tquic_ack_validation_check(struct tquic_ack_validation_state *state,
			       u64 largest_acked, u8 pn_space);

/*
 * =============================================================================
 * Spin Bit Privacy Controls
 * =============================================================================
 *
 * The spin bit (RFC 9000 Section 17.4) enables passive RTT measurement by
 * network observers. This can be used for:
 * - Traffic analysis and fingerprinting
 * - Inferring connection quality
 * - Identifying specific connections
 *
 * Defense:
 * - Configurable spin bit policy
 * - Probabilistic disabling (send random value instead of spin)
 * - Default: 12.5% random values
 */

/* Spin bit policy values */
#define TQUIC_SPIN_BIT_ALWAYS		0	/* Always set spin bit correctly */
#define TQUIC_SPIN_BIT_NEVER		1	/* Never set spin bit (always random) */
#define TQUIC_SPIN_BIT_PROBABILISTIC	2	/* Probabilistic disabling */

/* Default probabilistic disable rate (1 in 8 = 12.5%) */
#define TQUIC_SPIN_BIT_DISABLE_RATE_DEFAULT	8

/**
 * struct tquic_spin_bit_state - Spin bit privacy state per connection
 * @policy: Current spin bit policy
 * @disable_rate: Probabilistic disable rate (1 in N)
 * @current_spin: Current spin bit value
 * @packet_count: Packets sent (for tracking spin transitions)
 * @last_largest_pn: Last largest packet number seen (for spin calculation)
 */
struct tquic_spin_bit_state {
	u8 policy;
	u8 disable_rate;
	u8 current_spin;
	u64 packet_count;
	u64 last_largest_pn;
};

/* Spin bit state management */
void tquic_spin_bit_init(struct tquic_spin_bit_state *state, u8 policy,
			 u8 disable_rate);

/* Get spin bit value for outgoing packet */
u8 tquic_spin_bit_get(struct tquic_spin_bit_state *state, u64 pn);

/* Update spin bit based on received packet */
void tquic_spin_bit_update(struct tquic_spin_bit_state *state, u8 received_spin,
			   u64 received_pn);

/*
 * =============================================================================
 * Integration Guide
 * =============================================================================
 *
 * Pre-Handshake Memory Defense (CVE-2025-54939):
 *   Call from tquic_input.c when processing Initial packets:
 *     1. tquic_pre_hs_can_allocate() before allocating connection state
 *     2. tquic_pre_hs_alloc() after allocating state
 *     3. tquic_pre_hs_connection_complete() when handshake completes
 *     4. tquic_pre_hs_free() if connection fails before handshake
 *
 * CID Stuffing Defense (CVE-2024-22189):
 *   Integrated in tquic_cid.c:
 *     1. tquic_cid_security_check_new_cid() in tquic_cid_add_remote()
 *     2. tquic_cid_security_queue_retire() in tquic_send_retire_connection_id()
 *
 * Packet Number Skipping (Optimistic ACK Defense):
 *   Call from tquic_output.c when sending packets:
 *     1. Allocate state: tquic_pn_skip_init() in connection setup
 *     2. When assigning PN: tquic_pn_should_skip() to check if skip needed
 *     3. If skipping: tquic_pn_record_skip() to record the skipped PN
 *     4. When processing ACK: tquic_pn_check_optimistic_ack() for each acked PN
 *
 * ACK Validation:
 *   Call from tquic_input.c when processing ACK frames:
 *     1. tquic_ack_validation_record_sent() when sending packet
 *     2. tquic_ack_validation_check() when receiving ACK frame
 *
 * Spin Bit Privacy:
 *   Call from tquic_output.c when building short header:
 *     1. tquic_spin_bit_init() in connection setup
 *     2. tquic_spin_bit_get() to get spin bit value for outgoing packet
 *     3. tquic_spin_bit_update() when receiving packet
 */

/*
 * =============================================================================
 * Sysctl Variables
 * =============================================================================
 */

/* Sysctl accessors */
u64 tquic_sysctl_get_pre_handshake_memory_limit(void);
u64 tquic_sysctl_get_pre_handshake_per_ip_budget(void);
u32 tquic_sysctl_get_pn_skip_rate(void);
u8 tquic_sysctl_get_spin_bit_policy(void);

/*
 * =============================================================================
 * Security Event Reporting
 * =============================================================================
 */

/* Security event types */
enum tquic_security_event {
	TQUIC_SEC_EVENT_PRE_HS_LIMIT = 1,	/* Pre-handshake memory limit */
	TQUIC_SEC_EVENT_RETIRE_CID_FLOOD,	/* Retire CID stuffing detected */
	TQUIC_SEC_EVENT_NEW_CID_RATE_LIMIT,	/* NEW_CONNECTION_ID rate limit */
	TQUIC_SEC_EVENT_OPTIMISTIC_ACK,		/* Optimistic ACK detected */
	TQUIC_SEC_EVENT_INVALID_ACK,		/* ACK for unsent packet */
};

/* Report security event (logs and updates MIB counters) */
void tquic_security_event(enum tquic_security_event event,
			  const struct sockaddr_storage *addr,
			  const char *details);

#endif /* _TQUIC_SECURITY_HARDENING_H */
