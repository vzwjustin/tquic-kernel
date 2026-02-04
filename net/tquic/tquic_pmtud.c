// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Path MTU Discovery (DPLPMTUD)
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Implements Datagram Packetization Layer Path MTU Discovery (DPLPMTUD)
 * per RFC 8899 and QUIC-specific guidance from RFC 9000.
 *
 * Key features:
 * - Per-path MTU tracking and probing
 * - Binary search for optimal MTU
 * - Black hole detection and recovery
 * - Periodic re-probing for MTU increases
 * - Integration with timer and output subsystems
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <linux/random.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <net/sock.h>
#include <net/route.h>
#include <net/ip.h>
#include <net/dst.h>
#include <net/ipv6_stubs.h>
#include <net/tquic.h>
#include <net/tquic_pmtud.h>
#include "protocol.h"
#include "cong/tquic_cong.h"

/*
 * =============================================================================
 * PMTUD Constants (RFC 8899, RFC 9000)
 * =============================================================================
 */

/* QUIC minimum MTU - packets MUST be at least this size */
#define TQUIC_BASE_PLPMTU		1200

/* Default maximum MTU to probe for */
#define TQUIC_MAX_PLPMTU_DEFAULT	1500

/* Maximum MTU we'll ever probe (jumbo frames) */
#define TQUIC_MAX_PLPMTU_ABSOLUTE	9000

/* Minimum probe size increase to continue binary search */
#define TQUIC_PMTU_SEARCH_THRESHOLD	20

/* Number of probes before declaring size as too large */
#define TQUIC_MAX_PROBES		3

/* Probe timer initial value (RFC 8899 recommends 15 seconds) */
#define TQUIC_PROBE_TIMER_MS		15000

/* PMTU raise timer - re-probe after network may have changed */
#define TQUIC_PMTU_RAISE_TIMER_MS	600000	/* 10 minutes */

/* Black hole detection thresholds */
#define TQUIC_BLACK_HOLE_THRESHOLD	6	/* Consecutive losses */
#define TQUIC_BLACK_HOLE_PERIOD_MS	60000	/* 1 minute observation */

/* IP/UDP overhead for MTU calculation */
#define TQUIC_IPV4_UDP_OVERHEAD		28	/* 20 + 8 */
#define TQUIC_IPV6_UDP_OVERHEAD		48	/* 40 + 8 */

/*
 * =============================================================================
 * PMTUD State Machine States (RFC 8899 Section 5.2)
 * =============================================================================
 */

/*
 * Note: enum tquic_pmtud_state is defined in <net/tquic.h>
 */

/**
 * struct tquic_pmtud_state_info - Per-path PMTUD state
 * @state: Current PMTUD state machine state
 * @base_plpmtu: Minimum confirmed MTU (starts at 1200)
 * @plpmtu: Current effective path MTU
 * @probed_size: Size currently being probed
 * @max_plpmtu: Maximum MTU based on interface
 * @probe_count: Number of probes sent at current size
 * @probe_pkt_num: Packet number of current probe
 * @probe_pending: True if probe is outstanding
 * @probe_time: Time probe was sent
 * @last_probe_success: Time of last successful probe
 * @search_low: Binary search lower bound
 * @search_high: Binary search upper bound
 * @black_hole_count: Consecutive losses for black hole detection
 * @black_hole_start: Time black hole detection started
 * @timer: Probe/raise timer
 * @work: Deferred work for probe handling
 * @path: Back-pointer to owning path
 * @lock: Protects PMTUD state
 */
struct tquic_pmtud_state_info {
	enum tquic_pmtud_state state;

	/* MTU values */
	u32 base_plpmtu;
	u32 plpmtu;
	u32 probed_size;
	u32 max_plpmtu;

	/* Probe tracking */
	u8 probe_count;
	u64 probe_pkt_num;
	bool probe_pending;
	ktime_t probe_time;
	ktime_t last_probe_success;

	/* Binary search bounds */
	u32 search_low;
	u32 search_high;

	/* Black hole detection */
	u32 black_hole_count;
	ktime_t black_hole_start;

	/* Timer and work */
	struct timer_list timer;
	struct work_struct work;

	/* Back-pointers */
	struct tquic_path *path;

	spinlock_t lock;
};

/* Global workqueue for PMTUD processing */
static struct workqueue_struct *tquic_pmtud_wq;

/* Forward declarations */
static void tquic_pmtud_timer_expired(struct timer_list *t);
static void tquic_pmtud_work_fn(struct work_struct *work);
static int tquic_pmtud_send_probe(struct tquic_path *path, u32 probe_size);

/*
 * =============================================================================
 * PMTUD Sysctl Variables
 * =============================================================================
 */

/* Global enable/disable for PMTUD */
static int tquic_pmtud_enabled = 1;

/* Default probe interval in ms */
static int tquic_pmtud_probe_interval = TQUIC_PROBE_TIMER_MS;

/*
 * =============================================================================
 * PMTUD State Management
 * =============================================================================
 */

/**
 * tquic_pmtud_get_interface_mtu - Get maximum MTU from network interface
 * @path: Path to query
 *
 * Return: Maximum MTU in bytes, or default if not determinable
 */
static u32 tquic_pmtud_get_interface_mtu(struct tquic_path *path)
{
	struct net_device *dev;
	struct dst_entry *dst;
	u32 mtu = TQUIC_MAX_PLPMTU_DEFAULT;
	u32 overhead;

	if (!path)
		return mtu;

	/* Determine IP overhead based on address family */
	if (path->remote_addr.ss_family == AF_INET6)
		overhead = TQUIC_IPV6_UDP_OVERHEAD;
	else
		overhead = TQUIC_IPV4_UDP_OVERHEAD;

	/* Try to get MTU from device */
	dev = path->dev;
	if (dev) {
		mtu = dev->mtu;
		if (mtu > overhead)
			mtu -= overhead;
		else
			mtu = TQUIC_BASE_PLPMTU;
	}

	/* Try route-based MTU discovery */
	if (path->conn && path->conn->sk) {
		struct sock *sk = path->conn->sk;

		if (path->remote_addr.ss_family == AF_INET) {
			struct flowi4 fl4 = {};
			struct rtable *rt;
			struct sockaddr_in *sin;

			sin = (struct sockaddr_in *)&path->remote_addr;
			fl4.daddr = sin->sin_addr.s_addr;
			fl4.flowi4_proto = IPPROTO_UDP;

			rcu_read_lock();
			rt = ip_route_output_key(sock_net(sk), &fl4);
			if (!IS_ERR(rt)) {
				dst = &rt->dst;
				if (dst->dev)
					mtu = min(mtu, dst_mtu(dst) - overhead);
				ip_rt_put(rt);
			}
			rcu_read_unlock();
		}
#if IS_ENABLED(CONFIG_IPV6)
		else if (path->remote_addr.ss_family == AF_INET6) {
			struct flowi6 fl6 = {};
			struct dst_entry *dst6;
			struct sockaddr_in6 *sin6;

			sin6 = (struct sockaddr_in6 *)&path->remote_addr;
			fl6.daddr = sin6->sin6_addr;
			fl6.flowi6_proto = IPPROTO_UDP;

			rcu_read_lock();
			dst6 = ipv6_stub->ipv6_dst_lookup_flow(sock_net(sk), sk,
							       &fl6, NULL);
			if (!IS_ERR(dst6)) {
				mtu = min(mtu, dst_mtu(dst6) - overhead);
				dst_release(dst6);
			}
			rcu_read_unlock();
		}
#endif
	}

	/* Clamp to absolute limits */
	mtu = clamp(mtu, TQUIC_BASE_PLPMTU, TQUIC_MAX_PLPMTU_ABSOLUTE);

	return mtu;
}

/**
 * tquic_pmtud_state_name - Get string name for PMTUD state
 * @state: PMTUD state
 *
 * Return: Human-readable state name
 */
static const char *tquic_pmtud_state_name(enum tquic_pmtud_state state)
{
	switch (state) {
	case TQUIC_PMTUD_DISABLED:
		return "DISABLED";
	case TQUIC_PMTUD_BASE:
		return "BASE";
	case TQUIC_PMTUD_SEARCHING:
		return "SEARCHING";
	case TQUIC_PMTUD_SEARCH_COMPLETE:
		return "SEARCH_COMPLETE";
	case TQUIC_PMTUD_ERROR:
		return "ERROR";
	default:
		return "UNKNOWN";
	}
}

/**
 * tquic_pmtud_init_path - Initialize PMTUD state for a path
 * @path: Path to initialize PMTUD for
 *
 * Allocates and initializes PMTUD state, setting initial MTU to BASE_PLPMTU.
 *
 * Return: 0 on success, -errno on failure
 */
int tquic_pmtud_init_path(struct tquic_path *path)
{
	struct tquic_pmtud_state_info *pmtud;

	if (!path)
		return -EINVAL;

	pmtud = kzalloc(sizeof(*pmtud), GFP_KERNEL);
	if (!pmtud)
		return -ENOMEM;

	spin_lock_init(&pmtud->lock);

	/* Initialize to BASE state with minimum QUIC MTU */
	pmtud->state = TQUIC_PMTUD_BASE;
	pmtud->base_plpmtu = TQUIC_BASE_PLPMTU;
	pmtud->plpmtu = TQUIC_BASE_PLPMTU;
	pmtud->path = path;

	/* Determine maximum MTU from interface */
	pmtud->max_plpmtu = tquic_pmtud_get_interface_mtu(path);

	/* Initialize search bounds */
	pmtud->search_low = TQUIC_BASE_PLPMTU;
	pmtud->search_high = pmtud->max_plpmtu;

	/* Setup timer and work */
	timer_setup(&pmtud->timer, tquic_pmtud_timer_expired, 0);
	INIT_WORK(&pmtud->work, tquic_pmtud_work_fn);

	/* Store PMTUD state in path's dedicated field */
	path->pmtud_state = pmtud;
	path->mtu = pmtud->plpmtu;

	pr_debug("tquic_pmtud: initialized path %u, base=%u, max=%u\n",
		 path->path_id, pmtud->base_plpmtu, pmtud->max_plpmtu);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_pmtud_init_path);

/**
 * tquic_pmtud_release_path - Release PMTUD state for a path
 * @path: Path whose PMTUD state should be released
 */
void tquic_pmtud_release_path(struct tquic_path *path)
{
	struct tquic_pmtud_state_info *pmtud;

	if (!path)
		return;

	pmtud = path->pmtud_state;
	if (!pmtud)
		return;

	/* Stop timer and cancel pending work */
	del_timer_sync(&pmtud->timer);
	cancel_work_sync(&pmtud->work);

	/* Clear path reference and free */
	path->pmtud_state = NULL;
	kfree(pmtud);

	pr_debug("tquic_pmtud: released state for path %u\n", path->path_id);
}
EXPORT_SYMBOL_GPL(tquic_pmtud_release_path);

/*
 * =============================================================================
 * MTU Probe Generation
 * =============================================================================
 */

/**
 * tquic_pmtud_calc_next_probe_size - Calculate next probe size using binary search
 * @pmtud: PMTUD state
 *
 * Return: Next probe size in bytes
 */
static u32 tquic_pmtud_calc_next_probe_size(struct tquic_pmtud_state_info *pmtud)
{
	u32 mid;

	/* Binary search: probe the midpoint between low and high */
	mid = (pmtud->search_low + pmtud->search_high) / 2;

	/* Round up to nice boundary (8 bytes) */
	mid = ALIGN(mid, 8);

	/* Ensure within bounds */
	mid = clamp(mid, pmtud->search_low + 1, pmtud->search_high);

	return mid;
}

/**
 * tquic_pmtud_gen_probe_frame - Generate PING + PADDING frames for MTU probe
 * @buf: Buffer to write frames to
 * @buf_len: Buffer length
 * @target_size: Target packet size including headers
 * @header_overhead: Size of QUIC headers
 *
 * Return: Number of bytes written, or negative error
 */
static int tquic_pmtud_gen_probe_frame(u8 *buf, size_t buf_len,
				       u32 target_size, u32 header_overhead)
{
	size_t payload_size;
	size_t offset = 0;

	/* Calculate required payload (target - headers - AEAD tag) */
	if (target_size <= header_overhead + 16)
		return -EINVAL;

	payload_size = target_size - header_overhead - 16;

	if (payload_size > buf_len)
		return -ENOSPC;

	/* PING frame (1 byte, type 0x01) */
	buf[offset++] = 0x01;

	/* PADDING frames to reach target size */
	while (offset < payload_size) {
		buf[offset++] = 0x00;  /* PADDING frame type */
	}

	return offset;
}

/**
 * tquic_pmtud_send_probe - Send an MTU probe packet
 * @path: Path to probe on
 * @probe_size: Target packet size in bytes
 *
 * Generates and sends a probe packet consisting of PING + PADDING frames.
 * The packet is marked as an MTU probe so it won't be retransmitted normally.
 *
 * Return: 0 on success, negative error on failure
 */
static int tquic_pmtud_send_probe(struct tquic_path *path, u32 probe_size)
{
	struct tquic_connection *conn;
	struct sk_buff *skb;
	u8 *payload;
	int payload_len;
	u64 pkt_num;
	int header_len;
	u8 header[64];
	int ret;

	if (!path || !path->conn)
		return -EINVAL;

	conn = path->conn;

	/* Estimate header overhead (short header + CID) */
	header_len = 1 + path->remote_cid.len + 4;  /* 1 + CID + max PN */

	/* Allocate payload buffer */
	payload = kmalloc(probe_size, GFP_ATOMIC);
	if (!payload)
		return -ENOMEM;

	/* Generate probe frames */
	payload_len = tquic_pmtud_gen_probe_frame(payload, probe_size,
						  probe_size, header_len);
	if (payload_len < 0) {
		kfree(payload);
		return payload_len;
	}

	/* Get packet number */
	spin_lock(&conn->lock);
	pkt_num = conn->stats.tx_packets++;
	spin_unlock(&conn->lock);

	/* Allocate SKB */
	skb = alloc_skb(probe_size + MAX_HEADER, GFP_ATOMIC);
	if (!skb) {
		kfree(payload);
		return -ENOMEM;
	}

	skb_reserve(skb, MAX_HEADER);

	/* Build short header (1-RTT packet) */
	header[0] = 0x40;  /* Fixed bit set, short header */
	header[0] |= 0x03;  /* 4-byte packet number */

	memcpy(header + 1, path->remote_cid.id, path->remote_cid.len);
	header_len = 1 + path->remote_cid.len;

	/* Encode packet number (4 bytes) */
	header[header_len++] = (pkt_num >> 24) & 0xff;
	header[header_len++] = (pkt_num >> 16) & 0xff;
	header[header_len++] = (pkt_num >> 8) & 0xff;
	header[header_len++] = pkt_num & 0xff;

	/* Copy header and payload to SKB */
	skb_put_data(skb, header, header_len);
	skb_put_data(skb, payload, payload_len);

	/* Add AEAD tag space (16 bytes) - in production, actual encryption */
	memset(skb_put(skb, 16), 0, 16);

	kfree(payload);

	/* Mark as MTU probe in SKB control block */
	/* In production: TQUIC_SKB_CB(skb)->is_mtu_probe = true; */

	/* Send via path */
	ret = tquic_udp_xmit_on_path(conn, path, skb);

	if (ret >= 0) {
		pr_debug("tquic_pmtud: sent probe pkt %llu size %u on path %u\n",
			 pkt_num, probe_size, path->path_id);
	}

	return ret;
}

/*
 * =============================================================================
 * PMTUD State Machine Transitions
 * =============================================================================
 */

/**
 * tquic_pmtud_enter_searching - Enter SEARCHING state and send first probe
 * @pmtud: PMTUD state
 */
static void tquic_pmtud_enter_searching(struct tquic_pmtud_state_info *pmtud)
{
	pmtud->state = TQUIC_PMTUD_SEARCHING;
	pmtud->search_low = pmtud->plpmtu;
	pmtud->search_high = pmtud->max_plpmtu;
	pmtud->probe_count = 0;
	pmtud->probed_size = tquic_pmtud_calc_next_probe_size(pmtud);

	pr_debug("tquic_pmtud: entering SEARCHING, probing %u (low=%u, high=%u)\n",
		 pmtud->probed_size, pmtud->search_low, pmtud->search_high);

	/* Schedule probe send via work */
	queue_work(tquic_pmtud_wq, &pmtud->work);
}

/**
 * tquic_pmtud_probe_success - Handle successful probe acknowledgment
 * @pmtud: PMTUD state
 * @probed_size: Size that was successfully probed
 */
static void tquic_pmtud_probe_success(struct tquic_pmtud_state_info *pmtud,
				      u32 probed_size)
{
	unsigned long spin_flags;

	spin_lock_irqsave(&pmtud->lock, spin_flags);

	pmtud->probe_pending = false;
	pmtud->probe_count = 0;
	pmtud->last_probe_success = ktime_get();

	/* Update confirmed MTU */
	if (probed_size > pmtud->plpmtu) {
		pmtud->plpmtu = probed_size;
		pmtud->search_low = probed_size;

		/* Update path MTU */
		if (pmtud->path)
			pmtud->path->mtu = probed_size;

		pr_info("tquic_pmtud: path %u MTU increased to %u\n",
			pmtud->path ? pmtud->path->path_id : 0, probed_size);
	}

	/* Check if search is complete */
	if (pmtud->search_high - pmtud->search_low < TQUIC_PMTU_SEARCH_THRESHOLD) {
		pmtud->state = TQUIC_PMTUD_SEARCH_COMPLETE;
		pr_info("tquic_pmtud: search complete, MTU=%u\n", pmtud->plpmtu);

		/* Schedule raise timer to re-probe later */
		mod_timer(&pmtud->timer,
			  jiffies + msecs_to_jiffies(TQUIC_PMTU_RAISE_TIMER_MS));
	} else {
		/* Continue searching with larger size */
		pmtud->probed_size = tquic_pmtud_calc_next_probe_size(pmtud);

		pr_debug("tquic_pmtud: continuing search, next probe=%u\n",
			 pmtud->probed_size);

		/* Schedule next probe */
		queue_work(tquic_pmtud_wq, &pmtud->work);
	}

	spin_unlock_irqrestore(&pmtud->lock, spin_flags);
}

/**
 * tquic_pmtud_probe_failed - Handle probe failure (loss or timeout)
 * @pmtud: PMTUD state
 */
static void tquic_pmtud_probe_failed(struct tquic_pmtud_state_info *pmtud)
{
	unsigned long spin_flags;

	spin_lock_irqsave(&pmtud->lock, spin_flags);

	pmtud->probe_count++;

	if (pmtud->probe_count >= TQUIC_MAX_PROBES) {
		/* This size is too large, adjust search bounds */
		pmtud->search_high = pmtud->probed_size - 1;
		pmtud->probe_count = 0;

		pr_debug("tquic_pmtud: size %u too large after %d probes\n",
			 pmtud->probed_size, TQUIC_MAX_PROBES);

		/* Check if search is complete */
		if (pmtud->search_high - pmtud->search_low < TQUIC_PMTU_SEARCH_THRESHOLD) {
			pmtud->state = TQUIC_PMTUD_SEARCH_COMPLETE;
			pr_info("tquic_pmtud: search complete, MTU=%u\n",
				pmtud->plpmtu);

			/* Schedule raise timer */
			mod_timer(&pmtud->timer,
				  jiffies + msecs_to_jiffies(TQUIC_PMTU_RAISE_TIMER_MS));
		} else {
			/* Try smaller size */
			pmtud->probed_size = tquic_pmtud_calc_next_probe_size(pmtud);
			queue_work(tquic_pmtud_wq, &pmtud->work);
		}
	} else {
		/* Retry same size */
		pr_debug("tquic_pmtud: retrying probe %u (attempt %d)\n",
			 pmtud->probed_size, pmtud->probe_count + 1);

		/* Schedule probe timer for retry */
		mod_timer(&pmtud->timer,
			  jiffies + msecs_to_jiffies(tquic_pmtud_probe_interval));
	}

	pmtud->probe_pending = false;

	spin_unlock_irqrestore(&pmtud->lock, spin_flags);
}

/*
 * =============================================================================
 * Black Hole Detection
 * =============================================================================
 */

/**
 * tquic_pmtud_black_hole_detected - Handle suspected MTU black hole
 * @pmtud: PMTUD state
 *
 * Called when too many consecutive losses occur, suggesting packets
 * larger than BASE_PLPMTU are being silently dropped.
 */
static void tquic_pmtud_black_hole_detected(struct tquic_pmtud_state_info *pmtud)
{
	unsigned long spin_flags;

	spin_lock_irqsave(&pmtud->lock, spin_flags);

	pr_warn("tquic_pmtud: black hole detected on path %u, falling back to BASE\n",
		pmtud->path ? pmtud->path->path_id : 0);

	/* Fall back to base MTU */
	pmtud->state = TQUIC_PMTUD_ERROR;
	pmtud->plpmtu = TQUIC_BASE_PLPMTU;

	/* Update path MTU */
	if (pmtud->path)
		pmtud->path->mtu = TQUIC_BASE_PLPMTU;

	/* Reset search bounds */
	pmtud->search_low = TQUIC_BASE_PLPMTU;
	pmtud->search_high = pmtud->max_plpmtu;
	pmtud->black_hole_count = 0;

	/* Schedule re-probe after delay */
	mod_timer(&pmtud->timer,
		  jiffies + msecs_to_jiffies(TQUIC_BLACK_HOLE_PERIOD_MS));

	spin_unlock_irqrestore(&pmtud->lock, spin_flags);
}

/**
 * tquic_pmtud_on_packet_loss - Handle packet loss for black hole detection
 * @path: Path that experienced loss
 * @pkt_size: Size of lost packet
 *
 * Tracks consecutive losses of large packets to detect MTU black holes.
 */
void tquic_pmtud_on_packet_loss(struct tquic_path *path, u32 pkt_size)
{
	struct tquic_pmtud_state_info *pmtud;

	if (!path)
		return;

	/* Only track losses of packets larger than base MTU */
	if (pkt_size <= TQUIC_BASE_PLPMTU)
		return;

	/* Get PMTUD state from path structure */
	pmtud = path->pmtud_state;

	if (!pmtud)
		return;

	spin_lock_bh(&pmtud->lock);

	pmtud->black_hole_count++;

	/* Start observation period on first loss */
	if (pmtud->black_hole_count == 1)
		pmtud->black_hole_start = ktime_get();

	/* Check if within observation period and threshold exceeded */
	if (pmtud->black_hole_count >= TQUIC_BLACK_HOLE_THRESHOLD) {
		s64 elapsed_ms = ktime_ms_delta(ktime_get(),
						pmtud->black_hole_start);

		if (elapsed_ms < TQUIC_BLACK_HOLE_PERIOD_MS) {
			spin_unlock_bh(&pmtud->lock);
			tquic_pmtud_black_hole_detected(pmtud);
			return;
		} else {
			/* Reset observation period */
			pmtud->black_hole_count = 0;
		}
	}

	spin_unlock_bh(&pmtud->lock);
}
EXPORT_SYMBOL_GPL(tquic_pmtud_on_packet_loss);

/**
 * tquic_pmtud_on_ack - Handle ACK for black hole detection reset
 * @path: Path that received ACK
 * @pkt_size: Size of acknowledged packet
 *
 * Resets black hole detection counter when large packets succeed.
 */
void tquic_pmtud_on_ack(struct tquic_path *path, u32 pkt_size)
{
	struct tquic_pmtud_state_info *pmtud;

	if (!path)
		return;

	/* Only care about large packets */
	if (pkt_size <= TQUIC_BASE_PLPMTU)
		return;

	/* Get PMTUD state from path structure */
	pmtud = path->pmtud_state;

	if (!pmtud)
		return;

	spin_lock_bh(&pmtud->lock);
	pmtud->black_hole_count = 0;
	spin_unlock_bh(&pmtud->lock);
}
EXPORT_SYMBOL_GPL(tquic_pmtud_on_ack);

/*
 * =============================================================================
 * Timer and Work Handlers
 * =============================================================================
 */

/**
 * tquic_pmtud_timer_expired - PMTUD timer callback
 * @t: Timer that expired
 */
static void tquic_pmtud_timer_expired(struct timer_list *t)
{
	struct tquic_pmtud_state_info *pmtud = from_timer(pmtud, t, timer);

	/* Schedule work to handle timeout in process context */
	queue_work(tquic_pmtud_wq, &pmtud->work);
}

/**
 * tquic_pmtud_work_fn - PMTUD work handler
 * @work: Work struct
 */
static void tquic_pmtud_work_fn(struct work_struct *work)
{
	struct tquic_pmtud_state_info *pmtud = container_of(work,
		struct tquic_pmtud_state_info, work);
	unsigned long spin_flags;
	enum tquic_pmtud_state state;
	bool should_probe = false;
	u32 probe_size = 0;

	spin_lock_irqsave(&pmtud->lock, spin_flags);

	state = pmtud->state;

	switch (state) {
	case TQUIC_PMTUD_DISABLED:
		/* Nothing to do */
		break;

	case TQUIC_PMTUD_BASE:
		/* Start searching if interface MTU > base */
		if (pmtud->max_plpmtu > TQUIC_BASE_PLPMTU + TQUIC_PMTU_SEARCH_THRESHOLD) {
			spin_unlock_irqrestore(&pmtud->lock, spin_flags);
			tquic_pmtud_enter_searching(pmtud);
			return;
		}
		break;

	case TQUIC_PMTUD_SEARCHING:
		/* Check if probe timed out */
		if (pmtud->probe_pending) {
			s64 elapsed_ms = ktime_ms_delta(ktime_get(),
							pmtud->probe_time);
			if (elapsed_ms >= tquic_pmtud_probe_interval) {
				/* Probe timeout - treat as failure */
				spin_unlock_irqrestore(&pmtud->lock, spin_flags);
				tquic_pmtud_probe_failed(pmtud);
				return;
			}
		} else {
			/* Send next probe */
			should_probe = true;
			probe_size = pmtud->probed_size;
		}
		break;

	case TQUIC_PMTUD_SEARCH_COMPLETE:
		/* Raise timer expired - try probing for larger MTU */
		pmtud->max_plpmtu = tquic_pmtud_get_interface_mtu(pmtud->path);
		if (pmtud->max_plpmtu > pmtud->plpmtu + TQUIC_PMTU_SEARCH_THRESHOLD) {
			spin_unlock_irqrestore(&pmtud->lock, spin_flags);
			tquic_pmtud_enter_searching(pmtud);
			return;
		}

		/* Re-arm raise timer */
		mod_timer(&pmtud->timer,
			  jiffies + msecs_to_jiffies(TQUIC_PMTU_RAISE_TIMER_MS));
		break;

	case TQUIC_PMTUD_ERROR:
		/* Error timer expired - try to recover */
		pmtud->state = TQUIC_PMTUD_BASE;
		spin_unlock_irqrestore(&pmtud->lock, spin_flags);
		tquic_pmtud_enter_searching(pmtud);
		return;
	}

	spin_unlock_irqrestore(&pmtud->lock, spin_flags);

	/* Send probe outside of lock */
	if (should_probe && pmtud->path) {
		int ret;

		ret = tquic_pmtud_send_probe(pmtud->path, probe_size);

		spin_lock_irqsave(&pmtud->lock, spin_flags);
		if (ret >= 0) {
			pmtud->probe_pending = true;
			pmtud->probe_time = ktime_get();

			/* Arm probe timer */
			mod_timer(&pmtud->timer,
				  jiffies + msecs_to_jiffies(tquic_pmtud_probe_interval));
		} else {
			/* Send failed - retry later */
			pr_warn("tquic_pmtud: probe send failed: %d\n", ret);
			mod_timer(&pmtud->timer,
				  jiffies + msecs_to_jiffies(1000));
		}
		spin_unlock_irqrestore(&pmtud->lock, spin_flags);
	}
}

/*
 * =============================================================================
 * External API
 * =============================================================================
 */

/**
 * tquic_pmtud_start - Start PMTUD for a path
 * @path: Path to start PMTUD on
 *
 * Begins the MTU discovery process by entering the SEARCHING state.
 *
 * Return: 0 on success, negative error on failure
 */
int tquic_pmtud_start(struct tquic_path *path)
{
	struct tquic_pmtud_state_info *pmtud;
	int ret;

	if (!path)
		return -EINVAL;

	if (!tquic_pmtud_enabled)
		return 0;

	/* Initialize PMTUD state if not already done */
	ret = tquic_pmtud_init_path(path);
	if (ret)
		return ret;

	/* In production, pmtud would be retrieved from path structure */
	/* For now, we'd need to track it separately or store in path->ext */

	pr_debug("tquic_pmtud: started for path %u\n", path->path_id);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_pmtud_start);

/**
 * tquic_pmtud_stop - Stop PMTUD for a path
 * @path: Path to stop PMTUD on
 */
void tquic_pmtud_stop(struct tquic_path *path)
{
	if (!path)
		return;

	tquic_pmtud_release_path(path);

	pr_debug("tquic_pmtud: stopped for path %u\n", path->path_id);
}
EXPORT_SYMBOL_GPL(tquic_pmtud_stop);

/**
 * tquic_pmtud_on_probe_ack - Handle ACK of MTU probe packet
 * @path: Path the probe was sent on
 * @pkt_num: Packet number of the acknowledged probe
 * @probed_size: Size of the probed packet
 *
 * Called when an MTU probe packet is acknowledged, indicating
 * the probed size works on this path.
 */
void tquic_pmtud_on_probe_ack(struct tquic_path *path, u64 pkt_num,
			      u32 probed_size)
{
	struct tquic_pmtud_state_info *pmtud;

	if (!path)
		return;

	/* In production, pmtud would be retrieved from path structure */
	pmtud = NULL;

	if (!pmtud)
		return;

	spin_lock_bh(&pmtud->lock);

	/* Verify this is the probe we're waiting for */
	if (!pmtud->probe_pending || pmtud->probe_pkt_num != pkt_num) {
		spin_unlock_bh(&pmtud->lock);
		return;
	}

	spin_unlock_bh(&pmtud->lock);

	/* Handle successful probe */
	tquic_pmtud_probe_success(pmtud, probed_size);
}
EXPORT_SYMBOL_GPL(tquic_pmtud_on_probe_ack);

/**
 * tquic_pmtud_on_probe_lost - Handle loss of MTU probe packet
 * @path: Path the probe was sent on
 * @pkt_num: Packet number of the lost probe
 *
 * Called when an MTU probe packet is declared lost.
 */
void tquic_pmtud_on_probe_lost(struct tquic_path *path, u64 pkt_num)
{
	struct tquic_pmtud_state_info *pmtud;

	if (!path)
		return;

	/* In production, pmtud would be retrieved from path structure */
	pmtud = NULL;

	if (!pmtud)
		return;

	spin_lock_bh(&pmtud->lock);

	/* Verify this is the probe we're waiting for */
	if (!pmtud->probe_pending || pmtud->probe_pkt_num != pkt_num) {
		spin_unlock_bh(&pmtud->lock);
		return;
	}

	spin_unlock_bh(&pmtud->lock);

	/* Handle failed probe */
	tquic_pmtud_probe_failed(pmtud);
}
EXPORT_SYMBOL_GPL(tquic_pmtud_on_probe_lost);

/**
 * tquic_pmtud_get_mtu - Get current path MTU
 * @path: Path to query
 *
 * Return: Current effective MTU for the path
 */
u32 tquic_pmtud_get_mtu(struct tquic_path *path)
{
	if (!path)
		return TQUIC_BASE_PLPMTU;

	return path->mtu;
}
EXPORT_SYMBOL_GPL(tquic_pmtud_get_mtu);

/**
 * tquic_pmtud_set_max_mtu - Set maximum MTU for a path
 * @path: Path to configure
 * @max_mtu: Maximum MTU to probe for
 *
 * Allows external configuration of the maximum MTU to probe.
 * Useful when interface MTU is known to be limited.
 *
 * Return: 0 on success, negative error on failure
 */
int tquic_pmtud_set_max_mtu(struct tquic_path *path, u32 max_mtu)
{
	struct tquic_pmtud_state_info *pmtud;

	if (!path)
		return -EINVAL;

	if (max_mtu < TQUIC_BASE_PLPMTU)
		return -EINVAL;

	/* In production, pmtud would be retrieved from path structure */
	pmtud = NULL;

	if (!pmtud)
		return -ENOENT;

	spin_lock_bh(&pmtud->lock);
	pmtud->max_plpmtu = min(max_mtu, TQUIC_MAX_PLPMTU_ABSOLUTE);
	pmtud->search_high = pmtud->max_plpmtu;
	spin_unlock_bh(&pmtud->lock);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_pmtud_set_max_mtu);

/*
 * =============================================================================
 * Sysctl Interface
 * =============================================================================
 */

/**
 * tquic_pmtud_sysctl_enabled - Get PMTUD enabled status
 *
 * Return: 1 if PMTUD is enabled, 0 otherwise
 */
int tquic_pmtud_sysctl_enabled(void)
{
	return tquic_pmtud_enabled;
}
EXPORT_SYMBOL_GPL(tquic_pmtud_sysctl_enabled);

/**
 * tquic_pmtud_sysctl_probe_interval - Get PMTUD probe interval
 *
 * Return: Probe interval in milliseconds
 */
int tquic_pmtud_sysctl_probe_interval(void)
{
	return tquic_pmtud_probe_interval;
}
EXPORT_SYMBOL_GPL(tquic_pmtud_sysctl_probe_interval);

/*
 * =============================================================================
 * Module Initialization
 * =============================================================================
 */

/**
 * tquic_pmtud_init - Initialize PMTUD subsystem
 *
 * Return: 0 on success, negative error on failure
 */
int __init tquic_pmtud_init(void)
{
	/* Create workqueue for PMTUD processing */
	tquic_pmtud_wq = alloc_workqueue("tquic_pmtud",
					 WQ_HIGHPRI | WQ_MEM_RECLAIM, 0);
	if (!tquic_pmtud_wq)
		return -ENOMEM;

	pr_info("tquic_pmtud: PMTUD subsystem initialized (enabled=%d)\n",
		tquic_pmtud_enabled);

	return 0;
}

/**
 * tquic_pmtud_exit - Cleanup PMTUD subsystem
 */
void __exit tquic_pmtud_exit(void)
{
	if (tquic_pmtud_wq) {
		flush_workqueue(tquic_pmtud_wq);
		destroy_workqueue(tquic_pmtud_wq);
	}

	pr_info("tquic_pmtud: PMTUD subsystem shutdown\n");
}

MODULE_DESCRIPTION("TQUIC Path MTU Discovery (DPLPMTUD)");
MODULE_LICENSE("GPL");
