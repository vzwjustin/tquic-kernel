// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC NAPI Polling Support
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * This file implements NAPI (New API) polling mode for TQUIC.
 * NAPI reduces interrupt overhead by polling for packets in softirq
 * context, providing better performance at high packet rates.
 *
 * Key features:
 *   - Per-socket NAPI polling for receive path
 *   - Busy polling support (sk_busy_loop) for ultra-low latency
 *   - Per-CPU NAPI instances for multi-queue NICs
 *   - Adaptive interrupt coalescing
 *   - Integration with socket receive path
 *   - Statistics via /proc/net/tquic_napi
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/percpu.h>
#include <linux/cpu.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <net/sock.h>
#include <net/busy_poll.h>
#include <net/tquic.h>

#include "napi.h"
#include "tquic_debug.h"
#include "protocol.h"
#include "tquic_compat.h"

/*
 * =============================================================================
 * Global NAPI State
 * =============================================================================
 */

/* Global list of active NAPI instances for statistics */
static LIST_HEAD(tquic_napi_list);
static DEFINE_SPINLOCK(tquic_napi_list_lock);

/* Virtual net_device for NAPI registration */
static struct net_device *tquic_napi_dev;

/* Per-CPU statistics for scalable stat updates */
struct tquic_napi_pcpu_stats {
	u64 total_packets;
	u64 total_polls;
	u64 busy_poll_packets;
};

DEFINE_PER_CPU(struct tquic_napi_pcpu_stats, tquic_napi_pcpu_stats);

/**
 * tquic_napi_aggregate_pcpu_stats - Sum per-CPU stats into output struct
 * @out_packets: output total packets
 * @out_polls: output total polls
 * @out_busy: output busy poll packets
 */
static void tquic_napi_aggregate_pcpu_stats(u64 *out_packets, u64 *out_polls,
					    u64 *out_busy)
{
	int cpu;
	u64 packets = 0, polls = 0, busy = 0;

	for_each_possible_cpu(cpu) {
		struct tquic_napi_pcpu_stats *s;

		s = per_cpu_ptr(&tquic_napi_pcpu_stats, cpu);
		packets += s->total_packets;
		polls += s->total_polls;
		busy += s->busy_poll_packets;
	}

	*out_packets = packets;
	*out_polls = polls;
	*out_busy = busy;
}

/* Proc file availability flag - set when /proc/net/tquic_napi unavailable */
static bool tquic_napi_proc_disabled;

/*
 * =============================================================================
 * Forward Declarations
 * =============================================================================
 */

static int tquic_napi_poll(struct napi_struct *napi, int budget);
static void tquic_process_rx_packet(struct tquic_sock *sk, struct sk_buff *skb);

/*
 * =============================================================================
 * NAPI Lifecycle Functions
 * =============================================================================
 */

/**
 * tquic_napi_init - Initialize NAPI for a TQUIC socket
 * @sk: TQUIC socket
 * @weight: NAPI poll weight (0 for default)
 */
int tquic_napi_init(struct tquic_sock *sk, int weight)
{
	struct tquic_napi *tn;
	int actual_weight;

	if (!sk)
		return -EINVAL;

	/* Validate weight */
	if (weight < 0)
		weight = TQUIC_NAPI_DEFAULT_WEIGHT;
	else if (weight > TQUIC_NAPI_MAX_WEIGHT)
		weight = TQUIC_NAPI_MAX_WEIGHT;
	else if (weight < TQUIC_NAPI_MIN_WEIGHT && weight != 0)
		weight = TQUIC_NAPI_MIN_WEIGHT;

	actual_weight = weight ? weight : TQUIC_NAPI_DEFAULT_WEIGHT;

	/* Allocate NAPI structure */
	tn = kzalloc(sizeof(*tn), GFP_KERNEL);
	if (!tn)
		return -ENOMEM;

	/* Initialize fields */
	tn->magic = TQUIC_NAPI_MAGIC;
	tn->sk = sk;
	tn->conn = sk->conn;
	tn->weight = actual_weight;
	tn->state = TQUIC_NAPI_STATE_DISABLED;
	tn->enabled = false;
	tn->busy_poll_enabled = false;
	tn->busy_poll_timeout_us = TQUIC_BUSY_POLL_DEFAULT_US;
	tn->cpu = smp_processor_id();

	/* Initialize receive queue */
	skb_queue_head_init(&tn->rx_queue);
	atomic_set(&tn->rx_queue_len, 0);

	spin_lock_init(&tn->lock);
	INIT_LIST_HEAD(&tn->list);

	/* Initialize coalescing */
	tn->coalesce.current_delay_us = TQUIC_NAPI_COALESCE_MIN_US;
	tn->coalesce.last_adjust = ktime_get();
	tn->coalesce.enabled = false;

	/* Initialize NAPI structure */
	netif_napi_add_weight(tquic_napi_dev, &tn->napi, tquic_napi_poll, actual_weight);

	/*
	 * Store NAPI context in socket's user data field.
	 * This allows retrieval via sk_user_data in the poll callback.
	 */
	((struct sock *)sk)->sk_user_data = tn;

	/* Add to global list */
	spin_lock(&tquic_napi_list_lock);
	list_add_tail(&tn->list, &tquic_napi_list);
	spin_unlock(&tquic_napi_list_lock);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_napi_init);

/**
 * tquic_napi_cleanup - Clean up NAPI for a TQUIC socket
 * @sk: TQUIC socket
 */
void tquic_napi_cleanup(struct tquic_sock *sk)
{
	struct tquic_napi *tn;
	struct sk_buff *skb;

	if (!sk)
		return;

	tn = tquic_napi_from_sk((struct sock *)sk);
	if (!tn)
		return;

	/* Remove from global list */
	spin_lock(&tquic_napi_list_lock);
	list_del(&tn->list);
	spin_unlock(&tquic_napi_list_lock);

	/* Disable and delete NAPI */
	if (tn->enabled) {
		napi_disable(&tn->napi);
		tn->enabled = false;
	}
	netif_napi_del(&tn->napi);

	/* Flush receive queue */
	while ((skb = __skb_dequeue(&tn->rx_queue)) != NULL)
		kfree_skb(skb);

	/* Clear socket reference */
	((struct sock *)sk)->sk_user_data = NULL;

	kfree(tn);
}
EXPORT_SYMBOL_GPL(tquic_napi_cleanup);

/**
 * tquic_napi_enable - Enable NAPI polling
 * @sk: TQUIC socket
 */
void tquic_napi_enable(struct tquic_sock *sk)
{
	struct tquic_napi *tn;

	if (!sk)
		return;

	tn = tquic_napi_from_sk((struct sock *)sk);
	if (!tn || tn->enabled)
		return;

	napi_enable(&tn->napi);
	tn->enabled = true;
	tn->state = TQUIC_NAPI_STATE_ENABLED;
}
EXPORT_SYMBOL_GPL(tquic_napi_enable);

/**
 * tquic_napi_disable - Disable NAPI polling
 * @sk: TQUIC socket
 */
void tquic_napi_disable(struct tquic_sock *sk)
{
	struct tquic_napi *tn;

	if (!sk)
		return;

	tn = tquic_napi_from_sk((struct sock *)sk);
	if (!tn || !tn->enabled)
		return;

	napi_disable(&tn->napi);
	tn->enabled = false;
	tn->state = TQUIC_NAPI_STATE_DISABLED;
}
EXPORT_SYMBOL_GPL(tquic_napi_disable);

/**
 * tquic_napi_schedule - Schedule NAPI poll
 * @tn: TQUIC NAPI structure
 */
void tquic_napi_schedule(struct tquic_napi *tn)
{
	if (!tn || !tn->enabled)
		return;

	if (napi_schedule_prep(&tn->napi)) {
		tn->state = TQUIC_NAPI_STATE_SCHEDULED;
		__napi_schedule(&tn->napi);
	}
}
EXPORT_SYMBOL_GPL(tquic_napi_schedule);

/*
 * =============================================================================
 * NAPI Poll Function
 * =============================================================================
 */

/**
 * tquic_napi_poll - Main NAPI poll callback
 * @napi: NAPI structure
 * @budget: Maximum packets to process
 *
 * This is the main NAPI poll function called from softirq context.
 * It processes packets from the receive queue up to the budget limit.
 *
 * Returns: Number of packets processed
 */
static int tquic_napi_poll(struct napi_struct *napi, int budget)
{
	struct tquic_napi *tn = container_of(napi, struct tquic_napi, napi);
	int work_done = 0;
	struct sk_buff *skb;
	ktime_t start_time;
	unsigned long flags;
	struct sk_buff_head local_queue;
	int spliced;

	start_time = ktime_get();
	tn->stats.poll_cycles++;
	this_cpu_inc(tquic_napi_pcpu_stats.total_polls);

	/*
	 * Batch dequeue: take the lock once, splice the entire queue
	 * to a local list, release the lock, then process all skbs.
	 * This reduces lock contention vs per-skb lock/unlock.
	 */
	__skb_queue_head_init(&local_queue);

	spin_lock_irqsave(&tn->lock, flags);
	skb_queue_splice_init(&tn->rx_queue, &local_queue);
	spliced = atomic_xchg(&tn->rx_queue_len, 0);
	spin_unlock_irqrestore(&tn->lock, flags);

	/* Process up to budget packets from the local queue */
	while (likely(work_done < budget)) {
		skb = __skb_dequeue(&local_queue);

		if (unlikely(!skb))
			break;

		/* Process the received packet */
		tquic_process_rx_packet(tn->sk, skb);
		work_done++;
	}

	/* Re-queue any unprocessed skbs back to the rx_queue */
	if (!skb_queue_empty(&local_queue)) {
		int remaining = skb_queue_len(&local_queue);

		spin_lock_irqsave(&tn->lock, flags);
		skb_queue_splice(&local_queue, &tn->rx_queue);
		atomic_add(remaining, &tn->rx_queue_len);
		spin_unlock_irqrestore(&tn->lock, flags);
	}

	/* Update statistics */
	tn->stats.packets_polled += work_done;
	this_cpu_add(tquic_napi_pcpu_stats.total_packets, work_done);

	if (work_done == 0)
		tn->stats.poll_empty++;

	/* Update running average batch size */
	if (tn->stats.poll_cycles > 0) {
		tn->stats.avg_batch_size = (tn->stats.avg_batch_size * 7 +
					    work_done) / 8;
	}

	/* Adaptive coalescing adjustment */
	if (tn->coalesce.enabled)
		tquic_napi_coalesce_adjust(tn);

	/* If we processed fewer than budget packets, we're done */
	if (work_done < budget) {
		napi_complete_done(napi, work_done);
		tn->state = TQUIC_NAPI_STATE_ENABLED;
	}

	return work_done;
}

/**
 * tquic_process_rx_packet - Process a received packet
 * @sk: TQUIC socket
 * @skb: Received packet
 *
 * Processes a single received packet. This function is called from
 * both NAPI poll and busy poll contexts.
 */
static void tquic_process_rx_packet(struct tquic_sock *sk, struct sk_buff *skb)
{
	struct tquic_connection *conn;

	if (!sk || !skb) {
		kfree_skb(skb);
		return;
	}

	conn = sk->conn;
	if (!conn) {
		kfree_skb(skb);
		return;
	}

	/*
	 * Deliver packet to the TQUIC input path.
	 * This calls into tquic_input.c for packet processing.
	 */
	tquic_udp_recv((struct sock *)sk, skb);
}

/*
 * =============================================================================
 * Busy Polling Support
 * =============================================================================
 */

/**
 * tquic_busy_poll_init - Initialize busy polling for a socket
 * @sk: TQUIC socket
 */
int tquic_busy_poll_init(struct tquic_sock *sk)
{
	struct tquic_napi *tn;

	if (!sk)
		return -EINVAL;

	tn = tquic_napi_from_sk((struct sock *)sk);
	if (!tn)
		return -ENOENT;

	tn->busy_poll_enabled = true;
	tn->busy_poll_timeout_us = TQUIC_BUSY_POLL_DEFAULT_US;

#ifdef CONFIG_NET_RX_BUSY_POLL
	/* Set socket busy poll timeout */
	WRITE_ONCE(((struct sock *)sk)->sk_ll_usec, tn->busy_poll_timeout_us);
#endif

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_busy_poll_init);

/**
 * tquic_busy_poll - Perform busy polling iteration
 * @sk: TQUIC socket
 * @budget: Maximum packets to process
 *
 * Returns: true if more work is available, false otherwise
 */
bool tquic_busy_poll(struct tquic_sock *sk, unsigned long budget)
{
	struct tquic_napi *tn;
	struct sk_buff *skb;
	struct sk_buff_head local_queue;
	unsigned long work_done = 0;
	unsigned long flags;

	if (!sk)
		return false;

	tn = tquic_napi_from_sk((struct sock *)sk);
	if (!tn || !tn->enabled || !tn->busy_poll_enabled)
		return false;

	/* Set busy poll state */
	tn->state = TQUIC_NAPI_STATE_BUSY_POLL;
	tn->stats.busy_poll_cycles++;

	/*
	 * Batch-splice: take the lock once, move the entire queue to a
	 * local list, then process without holding the lock (CF-023).
	 */
	__skb_queue_head_init(&local_queue);

	spin_lock_irqsave(&tn->lock, flags);
	skb_queue_splice_init(&tn->rx_queue, &local_queue);
	atomic_set(&tn->rx_queue_len, 0);
	spin_unlock_irqrestore(&tn->lock, flags);

	/* Process packets up to budget from the local queue */
	while (work_done < budget) {
		skb = __skb_dequeue(&local_queue);
		if (!skb)
			break;

		tquic_process_rx_packet(tn->sk, skb);
		work_done++;
	}

	/* Re-queue any unprocessed skbs back to the rx_queue */
	if (!skb_queue_empty(&local_queue)) {
		int remaining = skb_queue_len(&local_queue);

		spin_lock_irqsave(&tn->lock, flags);
		skb_queue_splice(&local_queue, &tn->rx_queue);
		atomic_add(remaining, &tn->rx_queue_len);
		spin_unlock_irqrestore(&tn->lock, flags);
	}

	/* Update statistics */
	tn->stats.busy_poll_packets += work_done;
	this_cpu_add(tquic_napi_pcpu_stats.busy_poll_packets, work_done);

	/* Restore state */
	tn->state = TQUIC_NAPI_STATE_ENABLED;

	/* Return true if there are more packets */
	return atomic_read(&tn->rx_queue_len) > 0;
}
EXPORT_SYMBOL_GPL(tquic_busy_poll);

/**
 * tquic_busy_poll_set_timeout - Set busy poll timeout
 * @sk: TQUIC socket
 * @timeout_us: Timeout in microseconds
 */
int tquic_busy_poll_set_timeout(struct tquic_sock *sk, u32 timeout_us)
{
	struct tquic_napi *tn;

	if (!sk)
		return -EINVAL;

	if (timeout_us < TQUIC_BUSY_POLL_MIN_US ||
	    timeout_us > TQUIC_BUSY_POLL_MAX_US)
		return -EINVAL;

	tn = tquic_napi_from_sk((struct sock *)sk);
	if (!tn)
		return -ENOENT;

	tn->busy_poll_timeout_us = timeout_us;

#ifdef CONFIG_NET_RX_BUSY_POLL
	WRITE_ONCE(((struct sock *)sk)->sk_ll_usec, timeout_us);
#endif

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_busy_poll_set_timeout);

/**
 * tquic_busy_poll_get_timeout - Get busy poll timeout
 * @sk: TQUIC socket
 */
u32 tquic_busy_poll_get_timeout(struct tquic_sock *sk)
{
	struct tquic_napi *tn;

	if (!sk)
		return 0;

	tn = tquic_napi_from_sk((struct sock *)sk);
	if (!tn)
		return 0;

	return tn->busy_poll_timeout_us;
}
EXPORT_SYMBOL_GPL(tquic_busy_poll_get_timeout);

/*
 * =============================================================================
 * Per-CPU NAPI for Multi-Queue NICs
 * =============================================================================
 */

/**
 * tquic_napi_percpu_init - Initialize per-CPU NAPI instances
 * @conn: TQUIC connection
 * @num_queues: Number of hardware queues to use (0 for auto)
 */
struct tquic_napi_percpu *tquic_napi_percpu_init(struct tquic_connection *conn,
						  int num_queues)
{
	struct tquic_napi_percpu *percpu;
	struct tquic_napi *tn;
	int cpu, active = 0;

	if (!conn)
		return ERR_PTR(-EINVAL);

	/* Determine number of queues to use */
	if (num_queues <= 0)
		num_queues = num_online_cpus();

	/* Allocate main structure */
	percpu = kzalloc(sizeof(*percpu), GFP_KERNEL);
	if (!percpu)
		return ERR_PTR(-ENOMEM);

	/* Allocate per-CPU NAPI structures */
	percpu->napi = alloc_percpu(struct tquic_napi);
	if (!percpu->napi) {
		kfree(percpu);
		return ERR_PTR(-ENOMEM);
	}

	percpu->conn = conn;
	percpu->num_queues = min_t(int, num_queues, num_online_cpus());
	cpumask_clear(&percpu->active_cpus);
	spin_lock_init(&percpu->lock);

	/* Initialize NAPI on each CPU up to num_queues */
	for_each_online_cpu(cpu) {
		if (active >= percpu->num_queues)
			break;

		tn = per_cpu_ptr(percpu->napi, cpu);

		/* Initialize per-CPU NAPI */
		tn->magic = TQUIC_NAPI_MAGIC;
		tn->conn = conn;
		tn->weight = TQUIC_NAPI_DEFAULT_WEIGHT;
		tn->state = TQUIC_NAPI_STATE_DISABLED;
		tn->enabled = false;
		tn->cpu = cpu;

		skb_queue_head_init(&tn->rx_queue);
		atomic_set(&tn->rx_queue_len, 0);
		spin_lock_init(&tn->lock);
		INIT_LIST_HEAD(&tn->list);

		netif_napi_add_weight(tquic_napi_dev, &tn->napi,
				      tquic_napi_poll, TQUIC_NAPI_DEFAULT_WEIGHT);

		cpumask_set_cpu(cpu, &percpu->active_cpus);
		active++;
	}

	return percpu;
}
EXPORT_SYMBOL_GPL(tquic_napi_percpu_init);

/**
 * tquic_napi_percpu_cleanup - Clean up per-CPU NAPI instances
 * @percpu: Per-CPU NAPI structure
 */
void tquic_napi_percpu_cleanup(struct tquic_napi_percpu *percpu)
{
	struct tquic_napi *tn;
	struct sk_buff *skb;
	int cpu;

	if (!percpu)
		return;

	/* Clean up NAPI on each active CPU */
	for_each_cpu(cpu, &percpu->active_cpus) {
		tn = per_cpu_ptr(percpu->napi, cpu);

		if (tn->enabled) {
			napi_disable(&tn->napi);
			tn->enabled = false;
		}
		netif_napi_del(&tn->napi);

		/* Flush queue */
		while ((skb = __skb_dequeue(&tn->rx_queue)) != NULL)
			kfree_skb(skb);
	}

	free_percpu(percpu->napi);
	kfree(percpu);
}
EXPORT_SYMBOL_GPL(tquic_napi_percpu_cleanup);

/**
 * tquic_napi_percpu_get - Get NAPI instance for current CPU
 * @percpu: Per-CPU NAPI structure
 */
struct tquic_napi *tquic_napi_percpu_get(struct tquic_napi_percpu *percpu)
{
	struct tquic_napi *tn;
	int cpu;

	if (!percpu)
		return NULL;

	/*
	 * Disable preemption to get a stable CPU ID and ensure the
	 * returned per-CPU pointer remains valid for the caller.
	 * Caller must call put_cpu() or equivalent when done.
	 */
	cpu = get_cpu();

	/* Check if this CPU is active */
	if (!cpumask_test_cpu(cpu, &percpu->active_cpus)) {
		/* Fall back to first active CPU */
		cpu = cpumask_first(&percpu->active_cpus);
		if (cpu >= nr_cpu_ids) {
			put_cpu();
			return NULL;
		}
	}

	tn = per_cpu_ptr(percpu->napi, cpu);
	put_cpu();

	return tn;
}
EXPORT_SYMBOL_GPL(tquic_napi_percpu_get);

/*
 * =============================================================================
 * Receive Path Integration
 * =============================================================================
 */

/**
 * tquic_napi_rx_queue - Queue a packet for NAPI processing
 * @tn: TQUIC NAPI structure
 * @skb: Packet to queue
 */
int tquic_napi_rx_queue(struct tquic_napi *tn, struct sk_buff *skb)
{
	unsigned long flags;

	if (unlikely(!tn || !skb))
		return -EINVAL;

	/* Check queue capacity - rarely full under normal operation */
	if (unlikely(atomic_read(&tn->rx_queue_len) >= TQUIC_NAPI_RX_QUEUE_LEN)) {
		tn->stats.rx_queue_full++;
		return -ENOBUFS;
	}

	/* Add to queue */
	spin_lock_irqsave(&tn->lock, flags);
	__skb_queue_tail(&tn->rx_queue, skb);
	atomic_inc(&tn->rx_queue_len);
	spin_unlock_irqrestore(&tn->lock, flags);

	/* Schedule NAPI if not already scheduled */
	tquic_napi_schedule(tn);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_napi_rx_queue);

/**
 * tquic_napi_rx_deliver - Deliver packet directly (bypass queue)
 * @tn: TQUIC NAPI structure
 * @skb: Packet to deliver
 */
int tquic_napi_rx_deliver(struct tquic_napi *tn, struct sk_buff *skb)
{
	if (!tn || !skb)
		return -EINVAL;

	if (!tn->sk) {
		kfree_skb(skb);
		return -ENOENT;
	}

	tquic_process_rx_packet(tn->sk, skb);
	tn->stats.packets_polled++;

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_napi_rx_deliver);

/*
 * =============================================================================
 * Adaptive Interrupt Coalescing
 * =============================================================================
 */

/**
 * tquic_napi_coalesce_enable - Enable adaptive interrupt coalescing
 * @tn: TQUIC NAPI structure
 */
void tquic_napi_coalesce_enable(struct tquic_napi *tn)
{
	if (!tn)
		return;

	tn->coalesce.enabled = true;
	tn->coalesce.current_delay_us = TQUIC_NAPI_COALESCE_MIN_US;
	tn->coalesce.last_rx_packets = tn->stats.packets_polled;
	tn->coalesce.last_adjust = ktime_get();
}
EXPORT_SYMBOL_GPL(tquic_napi_coalesce_enable);

/**
 * tquic_napi_coalesce_disable - Disable adaptive interrupt coalescing
 * @tn: TQUIC NAPI structure
 */
void tquic_napi_coalesce_disable(struct tquic_napi *tn)
{
	if (!tn)
		return;

	tn->coalesce.enabled = false;
	tn->coalesce.current_delay_us = TQUIC_NAPI_COALESCE_MIN_US;
}
EXPORT_SYMBOL_GPL(tquic_napi_coalesce_disable);

/**
 * tquic_napi_coalesce_adjust - Adjust coalescing based on traffic
 * @tn: TQUIC NAPI structure
 */
void tquic_napi_coalesce_adjust(struct tquic_napi *tn)
{
	ktime_t now;
	s64 elapsed_us;
	u64 packets_delta;
	u64 packet_rate;
	u32 new_delay;

	if (!tn || !tn->coalesce.enabled)
		return;

	now = ktime_get();
	elapsed_us = ktime_to_us(ktime_sub(now, tn->coalesce.last_adjust));

	/* Only adjust every 100ms */
	if (elapsed_us < 100000)
		return;

	/* Calculate packet rate (packets per second) */
	packets_delta = tn->stats.packets_polled - tn->coalesce.last_rx_packets;
	packet_rate = div64_u64(packets_delta * 1000000, elapsed_us);

	/* Determine new coalescing delay based on rate */
	if (packet_rate < TQUIC_NAPI_COALESCE_LOW_RATE) {
		/* Low rate: use minimum delay for low latency */
		new_delay = TQUIC_NAPI_COALESCE_MIN_US;
	} else if (packet_rate > TQUIC_NAPI_COALESCE_HIGH_RATE) {
		/* High rate: use maximum delay to batch more packets */
		new_delay = TQUIC_NAPI_COALESCE_MAX_US;
	} else {
		/* Scale linearly between min and max */
		u32 range = TQUIC_NAPI_COALESCE_MAX_US - TQUIC_NAPI_COALESCE_MIN_US;
		u64 rate_range = TQUIC_NAPI_COALESCE_HIGH_RATE - TQUIC_NAPI_COALESCE_LOW_RATE;
		u64 rate_delta = packet_rate - TQUIC_NAPI_COALESCE_LOW_RATE;

		new_delay = TQUIC_NAPI_COALESCE_MIN_US +
			    (u32)div64_u64(rate_delta * range, rate_range);
	}

	/* Apply hysteresis to avoid oscillation */
	if (abs((int)new_delay - (int)tn->coalesce.current_delay_us) > 10) {
		tn->coalesce.current_delay_us = new_delay;
		tn->stats.coalesce_events++;
	}

	/* Update tracking */
	tn->coalesce.last_rx_packets = tn->stats.packets_polled;
	tn->coalesce.last_adjust = now;
}
EXPORT_SYMBOL_GPL(tquic_napi_coalesce_adjust);

/*
 * =============================================================================
 * Statistics and Debugging
 * =============================================================================
 */

/**
 * tquic_napi_get_stats - Get NAPI statistics
 * @tn: TQUIC NAPI structure
 * @stats: Output statistics structure
 */
void tquic_napi_get_stats(struct tquic_napi *tn, struct tquic_napi_stats *stats)
{
	if (!tn || !stats)
		return;

	memcpy(stats, &tn->stats, sizeof(*stats));
}
EXPORT_SYMBOL_GPL(tquic_napi_get_stats);

/**
 * tquic_napi_reset_stats - Reset NAPI statistics
 * @tn: TQUIC NAPI structure
 */
void tquic_napi_reset_stats(struct tquic_napi *tn)
{
	if (!tn)
		return;

	memset(&tn->stats, 0, sizeof(tn->stats));
}
EXPORT_SYMBOL_GPL(tquic_napi_reset_stats);

/**
 * tquic_napi_proc_show - Show NAPI stats in proc file
 * @seq: Seq file for output
 */
void tquic_napi_proc_show(struct seq_file *seq)
{
	struct tquic_napi *tn;
	u64 total_packets, total_polls, busy_packets;

	/* Use per-CPU aggregation as the single source of truth (CF-217) */
	tquic_napi_aggregate_pcpu_stats(&total_packets, &total_polls,
					&busy_packets);

	seq_puts(seq, "TquicNapi:\n");
	seq_printf(seq, "  TotalPacketsPolled: %llu\n", total_packets);
	seq_printf(seq, "  TotalPollCycles: %llu\n", total_polls);
	seq_printf(seq, "  BusyPollPackets: %llu\n", busy_packets);
	seq_printf(seq, "  AvgPacketsPerPoll: %llu\n",
		   total_polls ? div64_u64(total_packets, total_polls) : 0);

	seq_puts(seq, "\nPerSocket:\n");
	seq_puts(seq, "  cpu  enabled  polled  busy_poll  empty  queue_full  batch_avg\n");

	spin_lock(&tquic_napi_list_lock);
	list_for_each_entry(tn, &tquic_napi_list, list) {
		seq_printf(seq, "  %3d  %7s  %6llu  %9llu  %5llu  %10llu  %9u\n",
			   tn->cpu,
			   tn->enabled ? "yes" : "no",
			   tn->stats.packets_polled,
			   tn->stats.busy_poll_packets,
			   tn->stats.poll_empty,
			   tn->stats.rx_queue_full,
			   tn->stats.avg_batch_size);
	}
	spin_unlock(&tquic_napi_list_lock);
}
EXPORT_SYMBOL_GPL(tquic_napi_proc_show);

/*
 * =============================================================================
 * Socket Option Support
 * =============================================================================
 */

/**
 * tquic_napi_setsockopt - Handle NAPI-related socket options
 */
int tquic_napi_setsockopt(struct sock *sk, int level, int optname,
			  sockptr_t optval, unsigned int optlen)
{
	struct tquic_sock *tsk = tquic_sk(sk);
	struct tquic_napi *tn;
	int val;

	if (!tsk)
		return -ENOENT;

	tn = tquic_napi_from_sk(sk);
	if (!tn)
		return -ENOENT;

	if (optlen < sizeof(int))
		return -EINVAL;

	if (copy_from_sockptr(&val, optval, sizeof(val)))
		return -EFAULT;

	switch (optname) {
	case SO_BUSY_POLL:
#ifdef CONFIG_NET_RX_BUSY_POLL
		if (val < 0)
			return -EINVAL;
		if (val > 0 && val < TQUIC_BUSY_POLL_MIN_US)
			val = TQUIC_BUSY_POLL_MIN_US;
		if (val > TQUIC_BUSY_POLL_MAX_US)
			val = TQUIC_BUSY_POLL_MAX_US;

		WRITE_ONCE(sk->sk_ll_usec, val);
		tn->busy_poll_timeout_us = val;
		tn->busy_poll_enabled = (val > 0);
		return 0;
#else
		return -EOPNOTSUPP;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
	case SO_BUSY_POLL_BUDGET:
#ifdef CONFIG_NET_RX_BUSY_POLL
		if (val < 1 || val > NAPI_POLL_WEIGHT)
			return -EINVAL;
		WRITE_ONCE(sk->sk_busy_poll_budget, val);
		return 0;
#else
		return -EOPNOTSUPP;
#endif
#endif /* >= 5.11 */

	default:
		return -ENOPROTOOPT;
	}
}
EXPORT_SYMBOL_GPL(tquic_napi_setsockopt);

/**
 * tquic_napi_getsockopt - Get NAPI-related socket options
 */
int tquic_napi_getsockopt(struct sock *sk, int level, int optname,
			  char __user *optval, int __user *optlen)
{
	struct tquic_napi *tn;
	int val, len;

	if (get_user(len, optlen))
		return -EFAULT;

	if (len < sizeof(int))
		return -EINVAL;

	tn = tquic_napi_from_sk(sk);
	if (!tn)
		return -ENOENT;

	switch (optname) {
	case SO_BUSY_POLL:
#ifdef CONFIG_NET_RX_BUSY_POLL
		val = READ_ONCE(sk->sk_ll_usec);
		break;
#else
		return -EOPNOTSUPP;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 11, 0)
	case SO_BUSY_POLL_BUDGET:
#ifdef CONFIG_NET_RX_BUSY_POLL
		val = READ_ONCE(sk->sk_busy_poll_budget);
		break;
#else
		return -EOPNOTSUPP;
#endif
#endif /* >= 5.11 */

	default:
		return -ENOPROTOOPT;
	}

	len = sizeof(int);
	if (put_user(len, optlen))
		return -EFAULT;

	if (copy_to_user(optval, &val, len))
		return -EFAULT;

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_napi_getsockopt);

/*
 * =============================================================================
 * Proc File for /proc/net/tquic_napi
 * =============================================================================
 */

static int tquic_napi_proc_seq_show(struct seq_file *seq, void *v)
{
	tquic_napi_proc_show(seq);
	return 0;
}

static int tquic_napi_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, tquic_napi_proc_seq_show, NULL);
}

static const struct proc_ops tquic_napi_proc_ops = {
	.proc_open	= tquic_napi_proc_open,
	.proc_read	= seq_read,
	.proc_lseek	= seq_lseek,
	.proc_release	= single_release,
};

/*
 * =============================================================================
 * Module Initialization
 * =============================================================================
 */

/**
 * tquic_napi_subsys_init - Initialize NAPI subsystem
 */
int __init tquic_napi_subsys_init(void)
{
	struct proc_dir_entry *pde;

	/* Create dummy net device for NAPI attachment */
	tquic_napi_dev = alloc_netdev_dummy(0);
	if (!tquic_napi_dev) {
		tquic_err("napi:failed to allocate net device\n");
		return -ENOMEM;
	}

	/* Create proc file */
	pde = proc_create("tquic_napi", 0444, init_net.proc_net,
			  &tquic_napi_proc_ops);
	if (!pde) {
		tquic_warn("napi:failed to create /proc/net/tquic_napi\n");
		tquic_napi_proc_disabled = true;
		/*
		 * Non-fatal - continue without proc file. NAPI statistics
		 * will not be available via /proc but polling still works.
		 */
		pr_notice("tquic_napi: statistics unavailable via /proc\n");
	} else {
		tquic_napi_proc_disabled = false;
	}

	tquic_info("NAPIsubsystem initialized\n");

	return 0;
}

/**
 * tquic_napi_subsys_exit - Clean up NAPI subsystem
 */
void __exit tquic_napi_subsys_exit(void)
{
	/* Remove proc file only if it was created */
	if (!tquic_napi_proc_disabled)
		remove_proc_entry("tquic_napi", init_net.proc_net);

	/* Free dummy net device (not registered, so just free it) */
	if (tquic_napi_dev) {
		free_netdev(tquic_napi_dev);
		tquic_napi_dev = NULL;
	}

	tquic_info("NAPIsubsystem exited\n");
}

MODULE_DESCRIPTION("TQUIC NAPI Polling Support");
MODULE_AUTHOR("Linux Foundation");
MODULE_LICENSE("GPL");
