/* SPDX-License-Identifier: GPL-2.0 */
/*
 * TQUIC Seamless Failover for WAN Bonding
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Implements seamless failover with zero application-visible packet loss
 * when a path fails. All unacknowledged packets on the failed path are
 * requeued for retransmission on remaining paths.
 *
 * Key guarantees:
 *   - Unacked packets from failed path are requeued to remaining paths
 *   - Retransmit queue has priority over new data
 *   - Connection survives complete path failure with zero app-visible loss
 *   - Path failure declared after 3x SRTT without ACK
 *   - Receiver deduplication handles potential duplicates from failover
 */

#ifndef _NET_TQUIC_FAILOVER_H
#define _NET_TQUIC_FAILOVER_H

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/rhashtable.h>
#include <linux/list.h>
#include <linux/ktime.h>
#include <linux/skbuff.h>
#include <linux/workqueue.h>

#ifndef TQUIC_MAX_PATHS
#define TQUIC_MAX_PATHS		16
#endif

/* Forward declarations */
struct tquic_path;
struct tquic_bonding_ctx;
struct tquic_connection;

/*
 * Path failure detection constants
 *
 * Path is declared failed after 3x SRTT without receiving an ACK.
 * This balances prompt failover with avoiding false positives.
 */
#define TQUIC_FAILOVER_TIMEOUT_MULT	3	/* 3x SRTT */
#define TQUIC_FAILOVER_MIN_TIMEOUT_MS	100	/* Minimum 100ms */
#define TQUIC_FAILOVER_MAX_TIMEOUT_MS	15000	/* Maximum 15 seconds */
#define TQUIC_FAILOVER_DEFAULT_SRTT_US	100000	/* Default 100ms SRTT */

/*
 * Hysteresis constants for path flap prevention
 *
 * Prevent rapid oscillation between active and failed states under
 * unstable network conditions. A path must exhibit N consecutive
 * failures before being marked failed, and N consecutive successes
 * before being restored. Additionally, a minimum stabilization
 * period must elapse before a failed path can be re-enabled.
 */
#define TQUIC_HYST_FAIL_THRESHOLD	3	/* Consecutive failures to fail */
#define TQUIC_HYST_RECOVER_THRESHOLD	5	/* Consecutive successes to restore */
#define TQUIC_HYST_MIN_STABLE_MS	2000	/* Minimum 2s stability period */
#define TQUIC_HYST_RTT_STABLE_MULT	2	/* Or 2x SRTT, whichever larger */
#define TQUIC_HYST_MAX_STABLE_MS	30000	/* Cap stabilization at 30s */

/*
 * Retransmit queue limits
 */
#define TQUIC_FAILOVER_MAX_QUEUED	1024	/* Max packets in retransmit queue */
#define TQUIC_FAILOVER_MAX_QUEUE_BYTES	(4 * 1024 * 1024) /* 4MB max */

/*
 * Receiver deduplication bitmap constants
 *
 * Bitmap tracks recently received packet numbers to detect duplicates
 * that may occur during failover retransmission.
 */
#define TQUIC_DEDUP_WINDOW_SIZE		2048	/* Track 2048 packet numbers */
#define TQUIC_DEDUP_BITMAP_LONGS	(TQUIC_DEDUP_WINDOW_SIZE / BITS_PER_LONG)

/*
 * Sent packet tracking structure
 *
 * Tracks sent packets for failover requeuing on path failure.
 * Stored in rhashtable for O(1) lookup on ACK/NACK.
 *
 * Lifecycle:
 *   1. Created when packet sent, added to rhashtable
 *   2. Removed and freed when ACK received
 *   3. On path failure: requeued to retransmit queue, removed from table
 *   4. After retransmission: re-added with new send time
 */
struct tquic_sent_packet {
	/* Hash table linkage */
	struct rhash_head	hash_node;

	/* Packet identification */
	u64			packet_number;	/* QUIC packet number (hash key) */
	u64			send_time;	/* Time packet was sent (us) */
	u8			path_id;	/* Path packet was sent on */

	/* Packet data for retransmission */
	struct sk_buff		*skb;		/* Packet data (clone) */
	u32			len;		/* Packet length */

	/* Retransmission state */
	u8			retx_count;	/* Number of retransmissions */
	bool			in_retx_queue;	/* Currently in retransmit queue */

	/* Retransmit queue linkage */
	struct list_head	retx_list;

	/* RCU callback for deferred free */
	struct rcu_head		rcu;
};

/*
 * rhashtable params for sent packet tracking
 */
extern const struct rhashtable_params tquic_sent_packet_params;

/*
 * Retransmit queue structure
 *
 * Priority queue of packets to retransmit after failover.
 * Retransmit queue is checked before new data queue.
 */
struct tquic_retx_queue {
	struct list_head	queue;		/* List of tquic_sent_packet */
	spinlock_t		lock;
	u32			count;		/* Number of packets queued */
	size_t			bytes;		/* Total bytes queued */
};

/* Forward declaration */
struct tquic_failover_ctx;

/*
 * Path hysteresis state
 *
 * Tracks whether a path is considered healthy, degraded (experiencing
 * intermittent failures), or failed. Transitions require sustained
 * consecutive events to prevent flapping.
 */
enum tquic_path_hyst_state {
	TQUIC_PATH_HYST_HEALTHY = 0,	/* Path operating normally */
	TQUIC_PATH_HYST_DEGRADED,	/* Failures seen, not yet failed */
	TQUIC_PATH_HYST_FAILED,		/* Confirmed failed */
	TQUIC_PATH_HYST_RECOVERING,	/* Failed, receiving ACKs again */
};

/*
 * Path timeout tracking
 *
 * Per-path state for failure detection with hysteresis to prevent
 * flapping under unstable network conditions.
 */
struct tquic_path_timeout {
	u64			last_ack_time;	/* Last ACK received (us) */
	u64			srtt_us;	/* Smoothed RTT for this path */
	u32			timeout_ms;	/* Calculated timeout */
	bool			timeout_armed;	/* Timeout timer active */
	struct delayed_work	timeout_work;	/* Timeout work */
	struct tquic_failover_ctx *fc;		/* Parent context */
	u8			path_id;	/* Path identifier */

	/* Hysteresis state for flap prevention */
	enum tquic_path_hyst_state hyst_state;	/* Current hysteresis state */
	u32			consec_failures;/* Consecutive timeout failures */
	u32			consec_successes;/* Consecutive ACK successes */
	u64			last_state_change_us; /* Timestamp of last transition */
	u64			fail_time_us;	/* When path entered FAILED state */
};

/*
 * Receiver-side deduplication state
 *
 * Bitmap to detect duplicate packets that may arrive after failover
 * when the same packet is retransmitted on a different path.
 */
struct tquic_dedup_state {
	/* Sliding window bitmap */
	unsigned long		bitmap[TQUIC_DEDUP_BITMAP_LONGS];
	u64			window_base;	/* Lowest tracked packet number */

	/* Statistics */
	u64			duplicates_detected;

	spinlock_t		lock;
};

/*
 * Failover context structure
 *
 * Per-connection failover state machine and retransmit queue.
 *
 * LOCKING:
 *   sent_packets_lock protects rhashtable operations
 *   retx_queue.lock protects retransmit queue
 *   dedup.lock protects receiver bitmap
 *   Lock order when both are needed:
 *     sent_packets_lock -> retx_queue.lock
 */
struct tquic_failover_ctx {
	/* Sent packet tracking (for ACK lookup and failover requeue) */
	struct rhashtable	sent_packets;	/* pkt_num -> tquic_sent_packet */
	spinlock_t		sent_packets_lock;
	u32			sent_count;	/* Number of tracked packets */

	/* Retransmit queue (priority over new data) */
	struct tquic_retx_queue	retx_queue;

	/* Per-path timeout tracking */
	struct tquic_path_timeout path_timeouts[TQUIC_MAX_PATHS];

	/* Receiver deduplication */
	struct tquic_dedup_state dedup;

	/* Workqueue for timeout handling */
	struct workqueue_struct	*wq;

	/* Statistics (atomic for lockless access from multiple contexts) */
	struct {
		atomic64_t	packets_tracked;	/* Total packets tracked */
		atomic64_t	packets_acked;		/* Packets ACKed normally */
		atomic64_t	packets_requeued;	/* Packets requeued on failure */
		atomic64_t	packets_retransmitted;	/* Packets retransmitted */
		atomic64_t	path_failures;		/* Path failure events */
		atomic64_t	failover_time_ns;	/* Total failover time */
		atomic64_t	rhashtable_errors;	/* rhashtable walk errors */
		atomic64_t	hash_insert_errors;	/* Hash table insertion errors */
		atomic64_t	flaps_suppressed;	/* Transitions blocked by hysteresis */
		atomic64_t	path_recoveries;	/* Paths restored from FAILED */
	} stats;

	/* Back pointer */
	struct tquic_bonding_ctx *bonding;

	/*
	 * Destruction guard: set to 1 at the start of tquic_failover_destroy()
	 * before cancelling delayed works.  Timeout work items that were
	 * already running (and re-queued themselves) check this flag and
	 * return immediately, preventing them from accessing the rhashtable
	 * after rhashtable_destroy() has been called.
	 */
	atomic_t		destroyed;
};

/*
 * ============================================================================
 * Lifecycle API
 * ============================================================================
 */

/**
 * tquic_failover_init - Initialize failover context
 * @bonding: Parent bonding context
 * @wq: Workqueue for timeout handling
 * @gfp: Memory allocation flags
 *
 * Returns allocated and initialized failover context, or NULL on failure.
 */
struct tquic_failover_ctx *tquic_failover_init(struct tquic_bonding_ctx *bonding,
					       struct workqueue_struct *wq,
					       gfp_t gfp);

/**
 * tquic_failover_destroy - Destroy failover context
 * @fc: Failover context to destroy
 *
 * Frees all tracked packets and the context itself.
 */
void tquic_failover_destroy(struct tquic_failover_ctx *fc);

/*
 * ============================================================================
 * Sent Packet Tracking API
 * ============================================================================
 */

/**
 * tquic_failover_track_sent - Track a sent packet for potential failover
 * @fc: Failover context
 * @skb: Packet that was sent (will be cloned)
 * @packet_number: QUIC packet number
 * @path_id: Path the packet was sent on
 *
 * Call after sending each packet. Clones the skb for potential retransmission.
 *
 * Returns: 0 on success, negative error code on failure
 */
int tquic_failover_track_sent(struct tquic_failover_ctx *fc,
			      struct sk_buff *skb, u64 packet_number,
			      u8 path_id);

/**
 * tquic_failover_on_ack - Handle ACK for a sent packet
 * @fc: Failover context
 * @packet_number: QUIC packet number that was ACKed
 *
 * Removes packet from tracking. Call when ACK frame is processed.
 *
 * Returns: 0 if packet was found and removed, -ENOENT if not tracked
 */
int tquic_failover_on_ack(struct tquic_failover_ctx *fc, u64 packet_number);

/**
 * tquic_failover_on_ack_range - Handle ACK range for multiple packets
 * @fc: Failover context
 * @first: First packet number in range (inclusive)
 * @last: Last packet number in range (inclusive)
 *
 * Efficiently handles ACK frames that acknowledge multiple packets.
 *
 * Returns: Number of packets acknowledged
 */
int tquic_failover_on_ack_range(struct tquic_failover_ctx *fc,
				u64 first, u64 last);

/*
 * ============================================================================
 * Path Failure API
 * ============================================================================
 */

/**
 * tquic_failover_on_path_failed - Handle path failure
 * @fc: Failover context
 * @path_id: ID of the failed path
 *
 * Moves all unacked packets from the failed path to the retransmit queue.
 * Call when path failure is detected (timeout or explicit failure).
 *
 * Returns: Number of packets requeued
 */
int tquic_failover_on_path_failed(struct tquic_failover_ctx *fc, u8 path_id);

/**
 * tquic_failover_update_path_ack - Update path ACK timestamp
 * @fc: Failover context
 * @path_id: Path that received the ACK
 * @srtt_us: Current smoothed RTT for the path
 *
 * Call when any ACK is received on a path. Updates timeout calculation.
 */
void tquic_failover_update_path_ack(struct tquic_failover_ctx *fc,
				    u8 path_id, u64 srtt_us);

/**
 * tquic_failover_arm_timeout - Arm path failure timeout
 * @fc: Failover context
 * @path_id: Path to arm timeout for
 *
 * Call after sending on a path. Arms the 3x SRTT timeout.
 */
void tquic_failover_arm_timeout(struct tquic_failover_ctx *fc, u8 path_id);

/**
 * tquic_failover_path_hyst_state - Get hysteresis state name for a path
 * @fc: Failover context
 * @path_id: Path identifier
 *
 * Returns string name of the current hysteresis state for debugging.
 */
const char *tquic_failover_path_hyst_state(struct tquic_failover_ctx *fc,
					   u8 path_id);

/**
 * tquic_failover_is_path_usable - Check if path is usable for sending
 * @fc: Failover context
 * @path_id: Path identifier
 *
 * A path is usable if its hysteresis state is HEALTHY. Paths in DEGRADED
 * state are still usable but are being monitored. Paths in FAILED or
 * RECOVERING states are not usable.
 *
 * Returns: true if path can be used for sending
 */
bool tquic_failover_is_path_usable(struct tquic_failover_ctx *fc,
				   u8 path_id);

/*
 * ============================================================================
 * Retransmit Queue API
 * ============================================================================
 */

/**
 * tquic_failover_requeue - Add packet to retransmit queue
 * @fc: Failover context
 * @sp: Sent packet to requeue
 *
 * Adds packet to front of retransmit queue (priority).
 *
 * Returns: 0 on success, -ENOBUFS if queue full
 */
int tquic_failover_requeue(struct tquic_failover_ctx *fc,
			   struct tquic_sent_packet *sp);

/**
 * tquic_failover_has_pending - Check if retransmit queue has packets
 * @fc: Failover context
 *
 * Returns: true if there are packets waiting for retransmission
 */
bool tquic_failover_has_pending(struct tquic_failover_ctx *fc);

/**
 * tquic_failover_get_next - Get next packet to retransmit
 * @fc: Failover context
 *
 * Returns packet from retransmit queue, or NULL if empty.
 * Caller must handle the returned packet (retransmit or free).
 *
 * Returns: tquic_sent_packet pointer, or NULL
 */
struct tquic_sent_packet *tquic_failover_get_next(struct tquic_failover_ctx *fc);

/**
 * tquic_failover_retx_count - Get number of packets in retransmit queue
 * @fc: Failover context
 *
 * Returns: Number of packets pending retransmission
 */
static inline u32 tquic_failover_retx_count(struct tquic_failover_ctx *fc)
{
	if (!fc)
		return 0;
	return READ_ONCE(fc->retx_queue.count);
}

/*
 * ============================================================================
 * Receiver Deduplication API
 * ============================================================================
 */

/**
 * tquic_failover_dedup_check - Check if packet is duplicate
 * @fc: Failover context
 * @packet_number: Incoming packet number
 *
 * Checks if packet has already been received. If not, marks it as received.
 * Call on packet reception before processing.
 *
 * Returns: true if duplicate, false if first time seeing this packet
 */
bool tquic_failover_dedup_check(struct tquic_failover_ctx *fc, u64 packet_number);

/**
 * tquic_failover_dedup_advance - Advance deduplication window
 * @fc: Failover context
 * @ack_number: Largest acknowledged packet number
 *
 * Call after sending ACK to advance window base and free old state.
 */
void tquic_failover_dedup_advance(struct tquic_failover_ctx *fc, u64 ack_number);

/*
 * ============================================================================
 * Statistics API
 * ============================================================================
 */

/**
 * struct tquic_failover_stats - Failover statistics snapshot
 */
struct tquic_failover_stats {
	u64	packets_tracked;
	u64	packets_acked;
	u64	packets_requeued;
	u64	packets_retransmitted;
	u64	path_failures;
	u64	duplicates_detected;
	u64	flaps_suppressed;
	u64	path_recoveries;
	u32	current_tracked;
	u32	current_retx_queue;
};

/**
 * tquic_failover_get_stats - Get failover statistics
 * @fc: Failover context
 * @stats: Output statistics structure
 */
void tquic_failover_get_stats(struct tquic_failover_ctx *fc,
			      struct tquic_failover_stats *stats);

#endif /* _NET_TQUIC_FAILOVER_H */
