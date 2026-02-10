/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC NAPI Polling Support
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * This header provides NAPI (New API) polling mode support for TQUIC.
 * NAPI reduces interrupt overhead by polling for packets in softirq
 * context, providing better performance at high packet rates.
 *
 * Features:
 *   - Per-socket NAPI polling for receive path
 *   - Busy polling support (sk_busy_loop) for ultra-low latency
 *   - SO_BUSY_POLL socket option integration
 *   - Per-CPU NAPI instances for multi-queue NICs
 *   - Adaptive interrupt coalescing
 *   - Statistics via /proc/net/tquic_napi
 */

#ifndef _NET_TQUIC_NAPI_H
#define _NET_TQUIC_NAPI_H

#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/percpu.h>
#include <net/busy_poll.h>

#include "tquic_compat.h"

struct tquic_sock;
struct tquic_connection;
struct tquic_path;

/*
 * NAPI configuration defaults
 */
#define TQUIC_NAPI_DEFAULT_WEIGHT	64	/* Default NAPI poll weight */
#define TQUIC_NAPI_MIN_WEIGHT		1	/* Minimum poll weight */
#define TQUIC_NAPI_MAX_WEIGHT		256	/* Maximum poll weight */
#define TQUIC_NAPI_RX_QUEUE_LEN		4096	/* Max queued RX packets */

/* Busy polling configuration */
#define TQUIC_BUSY_POLL_DEFAULT_US	50	/* Default busy poll timeout (us) */
#define TQUIC_BUSY_POLL_MIN_US		1	/* Minimum busy poll timeout */
#define TQUIC_BUSY_POLL_MAX_US		1000	/* Maximum busy poll timeout */
#define TQUIC_BUSY_POLL_BUDGET		8	/* Packets per busy poll iteration */

/* Adaptive coalescing parameters */
#define TQUIC_NAPI_COALESCE_LOW_RATE	1000	/* Low packet rate threshold (pps) */
#define TQUIC_NAPI_COALESCE_HIGH_RATE	100000	/* High packet rate threshold (pps) */
#define TQUIC_NAPI_COALESCE_MIN_US	10	/* Minimum coalesce delay (us) */
#define TQUIC_NAPI_COALESCE_MAX_US	250	/* Maximum coalesce delay (us) */

/**
 * enum tquic_napi_state - NAPI instance state
 * @TQUIC_NAPI_STATE_DISABLED: NAPI not enabled
 * @TQUIC_NAPI_STATE_ENABLED: NAPI enabled and running
 * @TQUIC_NAPI_STATE_SCHEDULED: NAPI scheduled to run
 * @TQUIC_NAPI_STATE_BUSY_POLL: Currently in busy poll mode
 */
enum tquic_napi_state {
	TQUIC_NAPI_STATE_DISABLED = 0,
	TQUIC_NAPI_STATE_ENABLED,
	TQUIC_NAPI_STATE_SCHEDULED,
	TQUIC_NAPI_STATE_BUSY_POLL,
};

/**
 * struct tquic_napi_stats - NAPI statistics
 * @packets_polled: Total packets processed via NAPI
 * @poll_cycles: Number of NAPI poll invocations
 * @poll_empty: Polls that found no packets
 * @busy_poll_packets: Packets processed via busy polling
 * @busy_poll_cycles: Number of busy poll iterations
 * @rx_queue_full: Times RX queue was full
 * @coalesce_events: Interrupt coalescing adjustments
 * @avg_batch_size: Running average of packets per poll
 */
struct tquic_napi_stats {
	u64 packets_polled;
	u64 poll_cycles;
	u64 poll_empty;
	u64 busy_poll_packets;
	u64 busy_poll_cycles;
	u64 rx_queue_full;
	u64 coalesce_events;
	u32 avg_batch_size;
};

/* Magic value to identify tquic_napi in sk_user_data */
#define TQUIC_NAPI_MAGIC	0x54514E41	/* "TQNA" */

/**
 * struct tquic_napi - NAPI structure for TQUIC
 * @magic: Magic value for type identification (TQUIC_NAPI_MAGIC)
 * @napi: Kernel NAPI structure
 * @sk: Associated TQUIC socket
 * @conn: Associated connection (for quick access)
 * @rx_queue: Receive packet queue
 * @rx_queue_len: Current queue length
 * @weight: NAPI poll weight (max packets per poll)
 * @state: Current NAPI state
 * @enabled: True if NAPI is enabled
 * @busy_poll_enabled: True if busy polling is enabled
 * @busy_poll_timeout_us: Busy poll timeout in microseconds
 * @stats: NAPI statistics
 * @coalesce: Adaptive coalescing state
 * @lock: Spinlock for queue protection
 * @cpu: Preferred CPU for this NAPI instance
 * @list: Linkage in global NAPI list
 */
struct tquic_napi {
	u32 magic;
	struct napi_struct napi;
	struct tquic_sock *sk;
	struct tquic_connection *conn;

	/* Hot path: receive queue (accessed on every packet) */
	struct sk_buff_head rx_queue;
	atomic_t rx_queue_len;
	spinlock_t lock;

	/* Configuration */
	int weight;
	enum tquic_napi_state state;
	bool enabled;
	bool busy_poll_enabled;
	u32 busy_poll_timeout_us;

	/* Cold path: statistics and coalescing on separate cacheline */
	struct tquic_napi_stats stats ____cacheline_aligned_in_smp;

	/* Adaptive interrupt coalescing */
	struct {
		u32 current_delay_us;	/* Current coalesce delay */
		u64 last_rx_packets;	/* Packets at last adjustment */
		ktime_t last_adjust;	/* Time of last adjustment */
		bool enabled;		/* Adaptive coalescing enabled */
	} coalesce;

	int cpu;
	struct list_head list;
};

/**
 * struct tquic_napi_percpu - Per-CPU NAPI instances for multi-queue NICs
 * @napi: Per-CPU NAPI structures
 * @num_queues: Number of active queues
 * @active_cpus: Bitmask of CPUs with active NAPI
 * @conn: Parent connection
 * @stats_sum: Aggregated statistics across all CPUs
 * @lock: Lock for per-CPU coordination
 */
struct tquic_napi_percpu {
	struct tquic_napi __percpu *napi;
	int num_queues;
	cpumask_t active_cpus;
	struct tquic_connection *conn;
	struct tquic_napi_stats stats_sum;
	spinlock_t lock;
};

/*
 * =============================================================================
 * NAPI Lifecycle Functions
 * =============================================================================
 */

/**
 * tquic_napi_init - Initialize NAPI for a TQUIC socket
 * @sk: TQUIC socket
 * @weight: NAPI poll weight (0 for default)
 *
 * Initializes NAPI polling for the socket. This must be called
 * after socket creation but before any receive operations.
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_napi_init(struct tquic_sock *sk, int weight);

/**
 * tquic_napi_cleanup - Clean up NAPI for a TQUIC socket
 * @sk: TQUIC socket
 *
 * Disables and removes NAPI polling. Must be called before socket
 * destruction. Safe to call even if NAPI was not initialized.
 */
void tquic_napi_cleanup(struct tquic_sock *sk);

/**
 * tquic_napi_enable - Enable NAPI polling
 * @sk: TQUIC socket
 *
 * Enables NAPI polling for the socket. The socket must have been
 * previously initialized with tquic_napi_init().
 */
void tquic_napi_enable(struct tquic_sock *sk);

/**
 * tquic_napi_disable - Disable NAPI polling
 * @sk: TQUIC socket
 *
 * Temporarily disables NAPI polling without removing it.
 * Can be re-enabled with tquic_napi_enable().
 */
void tquic_napi_disable(struct tquic_sock *sk);

/**
 * tquic_napi_schedule - Schedule NAPI poll
 * @tn: TQUIC NAPI structure
 *
 * Schedules a NAPI poll to run in softirq context.
 * Safe to call from any context.
 */
void tquic_napi_schedule(struct tquic_napi *tn);

/*
 * =============================================================================
 * Busy Polling Support
 * =============================================================================
 */

/**
 * tquic_busy_poll_init - Initialize busy polling for a socket
 * @sk: TQUIC socket
 *
 * Sets up busy polling support. This enables SO_BUSY_POLL socket
 * option and sk_busy_loop() integration for ultra-low latency.
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_busy_poll_init(struct tquic_sock *sk);

/**
 * tquic_busy_poll - Perform busy polling iteration
 * @sk: TQUIC socket
 * @budget: Maximum packets to process
 *
 * Polls for and processes packets without sleeping. This is called
 * from sk_busy_loop() when the application is waiting for data.
 *
 * Returns: true if more work is available, false otherwise
 */
bool tquic_busy_poll(struct tquic_sock *sk, unsigned long budget);

/**
 * tquic_busy_poll_set_timeout - Set busy poll timeout
 * @sk: TQUIC socket
 * @timeout_us: Timeout in microseconds
 *
 * Sets the busy polling timeout for the socket. This controls how
 * long the application will busy-poll before blocking.
 *
 * Returns: 0 on success, -EINVAL for invalid timeout
 */
int tquic_busy_poll_set_timeout(struct tquic_sock *sk, u32 timeout_us);

/**
 * tquic_busy_poll_get_timeout - Get busy poll timeout
 * @sk: TQUIC socket
 *
 * Returns: Current busy poll timeout in microseconds
 */
u32 tquic_busy_poll_get_timeout(struct tquic_sock *sk);

/*
 * =============================================================================
 * Per-CPU NAPI for Multi-Queue NICs
 * =============================================================================
 */

/**
 * tquic_napi_percpu_init - Initialize per-CPU NAPI instances
 * @conn: TQUIC connection
 * @num_queues: Number of hardware queues to use (0 for auto)
 *
 * Initializes per-CPU NAPI instances for multi-queue NICs. This
 * allows parallel packet processing across multiple CPUs.
 *
 * Returns: Allocated percpu NAPI structure, or ERR_PTR on failure
 */
struct tquic_napi_percpu *tquic_napi_percpu_init(struct tquic_connection *conn,
						  int num_queues);

/**
 * tquic_napi_percpu_cleanup - Clean up per-CPU NAPI instances
 * @percpu: Per-CPU NAPI structure
 *
 * Disables and frees all per-CPU NAPI instances.
 */
void tquic_napi_percpu_cleanup(struct tquic_napi_percpu *percpu);

/**
 * tquic_napi_percpu_get - Get NAPI instance for current CPU
 * @percpu: Per-CPU NAPI structure
 *
 * Returns the NAPI instance for the current CPU. Must be called
 * with preemption disabled or from softirq context.
 *
 * Returns: NAPI instance for current CPU
 */
struct tquic_napi *tquic_napi_percpu_get(struct tquic_napi_percpu *percpu);

/*
 * =============================================================================
 * Receive Path Integration
 * =============================================================================
 */

/**
 * tquic_napi_rx_queue - Queue a packet for NAPI processing
 * @tn: TQUIC NAPI structure
 * @skb: Packet to queue
 *
 * Queues a received packet for NAPI processing. If NAPI is not
 * scheduled, it will be scheduled to run.
 *
 * Returns: 0 on success, -ENOBUFS if queue is full
 */
int tquic_napi_rx_queue(struct tquic_napi *tn, struct sk_buff *skb);

/**
 * tquic_napi_rx_deliver - Deliver packet directly (bypass queue)
 * @tn: TQUIC NAPI structure
 * @skb: Packet to deliver
 *
 * Delivers a packet directly to the connection without queuing.
 * This is used when NAPI is processing packets synchronously.
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_napi_rx_deliver(struct tquic_napi *tn, struct sk_buff *skb);

/*
 * =============================================================================
 * Adaptive Interrupt Coalescing
 * =============================================================================
 */

/**
 * tquic_napi_coalesce_enable - Enable adaptive interrupt coalescing
 * @tn: TQUIC NAPI structure
 *
 * Enables adaptive interrupt coalescing which automatically adjusts
 * the coalescing delay based on packet rate.
 */
void tquic_napi_coalesce_enable(struct tquic_napi *tn);

/**
 * tquic_napi_coalesce_disable - Disable adaptive interrupt coalescing
 * @tn: TQUIC NAPI structure
 *
 * Disables adaptive interrupt coalescing and reverts to default
 * coalescing settings.
 */
void tquic_napi_coalesce_disable(struct tquic_napi *tn);

/**
 * tquic_napi_coalesce_adjust - Adjust coalescing based on traffic
 * @tn: TQUIC NAPI structure
 *
 * Called periodically to adjust the coalescing delay based on
 * observed packet rates. Higher rates get shorter delays.
 */
void tquic_napi_coalesce_adjust(struct tquic_napi *tn);

/*
 * =============================================================================
 * Statistics and Debugging
 * =============================================================================
 */

/**
 * tquic_napi_get_stats - Get NAPI statistics
 * @tn: TQUIC NAPI structure
 * @stats: Output statistics structure
 *
 * Copies current statistics to the provided structure.
 */
void tquic_napi_get_stats(struct tquic_napi *tn, struct tquic_napi_stats *stats);

/**
 * tquic_napi_reset_stats - Reset NAPI statistics
 * @tn: TQUIC NAPI structure
 *
 * Resets all statistics counters to zero.
 */
void tquic_napi_reset_stats(struct tquic_napi *tn);

/**
 * tquic_napi_proc_show - Show NAPI stats in proc file
 * @seq: Seq file for output
 *
 * Called from /proc/net/tquic_napi to display statistics.
 */
void tquic_napi_proc_show(struct seq_file *seq);

/*
 * =============================================================================
 * Socket Option Support
 * =============================================================================
 */

/**
 * tquic_napi_setsockopt - Handle NAPI-related socket options
 * @sk: Socket
 * @level: Option level
 * @optname: Option name
 * @optval: Option value
 * @optlen: Option value length
 *
 * Handles SO_BUSY_POLL and TQUIC-specific NAPI socket options.
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_napi_setsockopt(struct sock *sk, int level, int optname,
			  sockptr_t optval, unsigned int optlen);

/**
 * tquic_napi_getsockopt - Get NAPI-related socket options
 * @sk: Socket
 * @level: Option level
 * @optname: Option name
 * @optval: Output buffer
 * @optlen: Buffer length (in/out)
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_napi_getsockopt(struct sock *sk, int level, int optname,
			  char __user *optval, int __user *optlen);

/*
 * =============================================================================
 * Module Initialization
 * =============================================================================
 */

/**
 * tquic_napi_subsys_init - Initialize NAPI subsystem
 *
 * Called during module initialization to set up global NAPI state.
 *
 * Returns: 0 on success, negative errno on failure
 */
int __init tquic_napi_subsys_init(void);

/**
 * tquic_napi_subsys_exit - Clean up NAPI subsystem
 *
 * Called during module exit to clean up global NAPI state.
 */
void __exit tquic_napi_subsys_exit(void);

/*
 * =============================================================================
 * Inline Helper Functions
 * =============================================================================
 */

/**
 * tquic_napi_from_sk - Safely retrieve TQUIC NAPI from socket
 * @sk: Socket with potential NAPI in sk_user_data
 *
 * Returns: tquic_napi pointer if valid, NULL otherwise
 */
static inline struct tquic_napi *tquic_napi_from_sk(struct sock *sk)
{
	struct tquic_napi *tn;

	if (!sk)
		return NULL;

	tn = sk->sk_user_data;
	if (!tn || tn->magic != TQUIC_NAPI_MAGIC)
		return NULL;

	return tn;
}

/**
 * tquic_napi_is_enabled - Check if NAPI is enabled
 * @tn: TQUIC NAPI structure
 *
 * Returns: true if NAPI is enabled, false otherwise
 */
static inline bool tquic_napi_is_enabled(struct tquic_napi *tn)
{
	return tn && tn->enabled;
}

/**
 * tquic_napi_is_busy_polling - Check if busy polling is active
 * @tn: TQUIC NAPI structure
 *
 * Returns: true if currently busy polling, false otherwise
 */
static inline bool tquic_napi_is_busy_polling(struct tquic_napi *tn)
{
	return tn && tn->state == TQUIC_NAPI_STATE_BUSY_POLL;
}

/**
 * tquic_napi_rx_queue_len - Get current receive queue length
 * @tn: TQUIC NAPI structure
 *
 * Returns: Number of packets in the receive queue
 */
static inline int tquic_napi_rx_queue_len(struct tquic_napi *tn)
{
	return tn ? atomic_read(&tn->rx_queue_len) : 0;
}

/**
 * tquic_napi_rx_queue_full - Check if receive queue is full
 * @tn: TQUIC NAPI structure
 *
 * Returns: true if queue is at capacity, false otherwise
 */
static inline bool tquic_napi_rx_queue_full(struct tquic_napi *tn)
{
	return tn && atomic_read(&tn->rx_queue_len) >= TQUIC_NAPI_RX_QUEUE_LEN;
}

/**
 * tquic_can_busy_poll - Check if busy polling is available
 * @sk: TQUIC socket
 *
 * Returns: true if busy polling can be used, false otherwise
 */
static inline bool tquic_can_busy_poll(struct tquic_sock *sk)
{
#ifdef CONFIG_NET_RX_BUSY_POLL
	return sk && READ_ONCE(((struct sock *)sk)->sk_ll_usec) > 0;
#else
	return false;
#endif
}

#endif /* _NET_TQUIC_NAPI_H */
