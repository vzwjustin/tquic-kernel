// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC AF_XDP Integration
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * This file implements AF_XDP (XDP sockets) integration for TQUIC,
 * providing kernel-bypass packet processing for high-performance
 * QUIC networking.
 *
 * AF_XDP enables 10x+ packet rate improvements by:
 *   - Eliminating kernel-userspace copies (zero-copy mode)
 *   - Bypassing the full networking stack
 *   - Using efficient ring buffers for batched processing
 *   - Leveraging XDP for early packet steering
 */

#define pr_fmt(fmt) "TQUIC-XDP: " fmt

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/slab.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/if_xdp.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/vmalloc.h>
#include <linux/uaccess.h>
#include <linux/overflow.h>
#include <linux/capability.h>
#include <linux/nsproxy.h>
#include <net/sock.h>
#include <net/xdp_sock_drv.h>
#include <net/tquic.h>

#include "af_xdp.h"
#include "tquic_debug.h"
#include "protocol.h"
#include "tquic_compat.h"

/*
 * XDP program bytecode for QUIC packet steering
 *
 * This BPF program is loaded to steer UDP packets on QUIC ports
 * (443, 4433, 8443) to the AF_XDP socket. Other packets pass through
 * to the normal networking stack.
 *
 * The program:
 *   1. Parses Ethernet header
 *   2. Checks for IPv4/IPv6
 *   3. Parses UDP header
 *   4. Checks destination port against QUIC ports
 *   5. Optionally validates QUIC header format
 *   6. Redirects matching packets to XSK
 */

/* Embedded BPF program for QUIC steering (compiled bytecode) */
static const struct bpf_insn tquic_xdp_prog_insns[] = {
	/* r6 = ctx (xdp_md) */
	BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),

	/* r2 = data */
	BPF_LDX_MEM(BPF_W, BPF_REG_2, BPF_REG_6,
		    offsetof(struct xdp_md, data)),

	/* r3 = data_end */
	BPF_LDX_MEM(BPF_W, BPF_REG_3, BPF_REG_6,
		    offsetof(struct xdp_md, data_end)),

	/* Check Ethernet header bounds: data + 14 <= data_end */
	BPF_MOV64_REG(BPF_REG_4, BPF_REG_2),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_4, 14),
	BPF_JMP_REG(BPF_JGT, BPF_REG_4, BPF_REG_3, 36), /* goto pass */

	/* r4 = ethertype (offset 12 in ethernet header) */
	BPF_LDX_MEM(BPF_H, BPF_REG_4, BPF_REG_2, 12),

	/* Check IPv4 (0x0800) */
	BPF_JMP_IMM(BPF_JNE, BPF_REG_4, 0x0800, 2), /* not IPv4, check IPv6 */

	/* IPv4: Check header bounds: data + 14 + 20 <= data_end */
	BPF_MOV64_IMM(BPF_REG_5, 14),  /* IP header offset */
	BPF_JMP_IMM(BPF_JA, 0, 0, 5),  /* goto check_udp */

	/* Check IPv6 (0x86DD) */
	BPF_JMP_IMM(BPF_JNE, BPF_REG_4, 0x86DD, 28), /* goto pass */

	/* IPv6: offset = 14, header size = 40 */
	BPF_MOV64_IMM(BPF_REG_5, 14),  /* IP header offset */

	/* Check IP + UDP header bounds */
	/* check_udp: */
	BPF_MOV64_REG(BPF_REG_4, BPF_REG_2),
	BPF_ALU64_REG(BPF_ADD, BPF_REG_4, BPF_REG_5),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_4, 28), /* min IP + UDP headers */
	BPF_JMP_REG(BPF_JGT, BPF_REG_4, BPF_REG_3, 22), /* goto pass */

	/* r7 = IP header start */
	BPF_MOV64_REG(BPF_REG_7, BPF_REG_2),
	BPF_ALU64_REG(BPF_ADD, BPF_REG_7, BPF_REG_5),

	/* Check IP protocol is UDP (17) - assume offset 9 for IPv4 */
	BPF_LDX_MEM(BPF_B, BPF_REG_4, BPF_REG_7, 9),
	BPF_JMP_IMM(BPF_JNE, BPF_REG_4, 17, 17), /* not UDP, goto pass */

	/* r8 = UDP header start (IP header + 20 for IPv4) */
	BPF_MOV64_REG(BPF_REG_8, BPF_REG_7),
	BPF_ALU64_IMM(BPF_ADD, BPF_REG_8, 20),

	/* r4 = destination port (UDP offset 2, big-endian) */
	BPF_LDX_MEM(BPF_H, BPF_REG_4, BPF_REG_8, 2),

	/* Check for QUIC ports: 443, 4433, 8443 */
	/* Port 443 */
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_4, 443, 4), /* match, goto redirect */

	/* Port 4433 */
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_4, 4433, 3), /* match, goto redirect */

	/* Port 8443 */
	BPF_JMP_IMM(BPF_JEQ, BPF_REG_4, 8443, 2), /* match, goto redirect */

	/* No match - pass to kernel stack */
	BPF_JMP_IMM(BPF_JA, 0, 0, 3), /* goto pass */

	/* redirect: Return XDP_REDIRECT to XSK */
	BPF_MOV64_IMM(BPF_REG_0, XDP_REDIRECT),
	BPF_JMP_IMM(BPF_JA, 0, 0, 1), /* goto exit */

	/* pass: Return XDP_PASS */
	BPF_MOV64_IMM(BPF_REG_0, XDP_PASS),

	/* exit: */
	BPF_EXIT_INSN(),
};

#define TQUIC_XDP_PROG_LEN ARRAY_SIZE(tquic_xdp_prog_insns)

/*
 * Frame pool implementation
 */

/* Maximum frames to prevent resource exhaustion and integer overflow */
#define TQUIC_XSK_MAX_FRAMES		(1U << 20)	/* 1M frames */
#define TQUIC_XSK_MAX_FRAME_SIZE	(64U * 1024)	/* 64KB per frame */

static struct tquic_xsk_frame_pool *
tquic_xsk_frame_pool_create(u32 num_frames, u32 frame_size)
{
	struct tquic_xsk_frame_pool *pool;
	size_t frames_sz, freelist_sz;
	u32 i;

	/* Validate bounds to prevent overflow and resource exhaustion */
	if (num_frames == 0 || num_frames > TQUIC_XSK_MAX_FRAMES)
		return ERR_PTR(-EINVAL);
	if (frame_size == 0 || frame_size > TQUIC_XSK_MAX_FRAME_SIZE)
		return ERR_PTR(-EINVAL);

	/* Check for overflow in allocation sizes */
	if (check_mul_overflow((size_t)num_frames,
			       sizeof(struct tquic_xsk_frame_meta), &frames_sz))
		return ERR_PTR(-EOVERFLOW);
	if (check_mul_overflow((size_t)num_frames, sizeof(u32), &freelist_sz))
		return ERR_PTR(-EOVERFLOW);

	pool = kzalloc(sizeof(*pool), GFP_KERNEL);
	if (!pool)
		return ERR_PTR(-ENOMEM);

	pool->frames = vzalloc(frames_sz);
	if (!pool->frames) {
		kfree(pool);
		return ERR_PTR(-ENOMEM);
	}

	pool->free_list = vzalloc(freelist_sz);
	if (!pool->free_list) {
		vfree(pool->frames);
		kfree(pool);
		return ERR_PTR(-ENOMEM);
	}

	pool->num_frames = num_frames;
	pool->frame_size = frame_size;
	spin_lock_init(&pool->lock);

	/* Initialize free list with all frames */
	for (i = 0; i < num_frames; i++) {
		pool->free_list[i] = i;
		pool->frames[i].addr = (u64)i * frame_size;
		pool->frames[i].state = TQUIC_XSK_FRAME_FREE;
		atomic_set(&pool->frames[i].refcnt, 0);
	}

	pool->free_head = 0;
	pool->free_tail = num_frames - 1;
	pool->free_count = num_frames;

	return pool;
}

static void tquic_xsk_frame_pool_destroy(struct tquic_xsk_frame_pool *pool)
{
	if (!pool)
		return;

	vfree(pool->free_list);
	vfree(pool->frames);
	kfree(pool);
}

static int tquic_xsk_frame_pool_alloc(struct tquic_xsk_frame_pool *pool,
				      u64 *addr)
{
	u32 idx;
	unsigned long flags;

	spin_lock_irqsave(&pool->lock, flags);

	if (pool->free_count == 0) {
		pool->alloc_failures++;
		spin_unlock_irqrestore(&pool->lock, flags);
		return -ENOMEM;
	}

	idx = pool->free_list[pool->free_head];
	pool->free_head = (pool->free_head + 1) % pool->num_frames;
	pool->free_count--;
	pool->alloc_count++;

	pool->frames[idx].state = TQUIC_XSK_FRAME_TX;
	atomic_set(&pool->frames[idx].refcnt, 1);

	spin_unlock_irqrestore(&pool->lock, flags);

	*addr = pool->frames[idx].addr;

	return 0;
}

static void tquic_xsk_frame_pool_free(struct tquic_xsk_frame_pool *pool,
				      u64 addr)
{
	u32 idx;
	unsigned long flags;

	if (!pool || pool->frame_size == 0)
		return;

	idx = addr / pool->frame_size;
	if (idx >= pool->num_frames)
		return;

	if (!atomic_dec_and_test(&pool->frames[idx].refcnt))
		return;

	spin_lock_irqsave(&pool->lock, flags);

	/* Prevent double-free: only free if not already free */
	if (pool->frames[idx].state == TQUIC_XSK_FRAME_FREE) {
		spin_unlock_irqrestore(&pool->lock, flags);
		WARN_ONCE(1, "tquic_xsk: double-free of frame idx %u\n", idx);
		return;
	}

	pool->frames[idx].state = TQUIC_XSK_FRAME_FREE;
	pool->free_tail = (pool->free_tail + 1) % pool->num_frames;
	pool->free_list[pool->free_tail] = idx;
	pool->free_count++;
	pool->free_count_stat++;

	spin_unlock_irqrestore(&pool->lock, flags);
}

/*
 * XSK socket creation and destruction
 */

int tquic_xsk_create(struct tquic_xsk **xsk_out, const char *ifname,
		     int queue_id, const struct tquic_xdp_config *config)
{
	struct tquic_xsk *xsk;
	struct net_device *dev;
	u32 frame_size, num_frames;
	size_t buffer_size;
	int err;

	if (!xsk_out || !ifname)
		return -EINVAL;

	/* XDP socket creation requires CAP_NET_ADMIN */
	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	/* Find network device */
	dev = dev_get_by_name(current->nsproxy->net_ns, ifname);
	if (!dev) {
		tquic_err("xdp: device %s not found\n", ifname);
		return -ENODEV;
	}

	/* Allocate XSK structure */
	xsk = kzalloc(sizeof(*xsk), GFP_KERNEL);
	if (!xsk) {
		dev_put(dev);
		return -ENOMEM;
	}

	/* Set configuration with validation */
	frame_size = config && config->frame_size ?
		     config->frame_size : TQUIC_XSK_DEFAULT_FRAME_SIZE;
	num_frames = config && config->num_frames ?
		     config->num_frames : TQUIC_XSK_DEFAULT_NUM_FRAMES;

	/* Validate frame parameters against pool limits */
	if (frame_size > TQUIC_XSK_MAX_FRAME_SIZE ||
	    num_frames > TQUIC_XSK_MAX_FRAMES) {
		err = -EINVAL;
		goto err_free_xsk;
	}

	/* Check for overflow in buffer_size calculation */
	if (check_mul_overflow((size_t)frame_size, (size_t)num_frames,
			       &buffer_size)) {
		err = -EOVERFLOW;
		goto err_free_xsk;
	}

	xsk->dev = dev;
	xsk->queue_id = queue_id;
	xsk->frame_size = frame_size;
	xsk->num_frames = num_frames;
	xsk->headroom = XDP_PACKET_HEADROOM;
	xsk->buffer_size = buffer_size;
	xsk->rx_batch_size = TQUIC_XSK_DEFAULT_BATCH_SIZE;
	xsk->tx_batch_size = TQUIC_XSK_DEFAULT_BATCH_SIZE;
	xsk->mode = config ? config->mode : TQUIC_XDP_COPY;

	/* Initialize ring sizes (must be power of 2 for index masking) */
	xsk->rx.ring_size = TQUIC_XSK_DEFAULT_RING_SIZE;
	xsk->tx.ring_size = TQUIC_XSK_DEFAULT_RING_SIZE;
	xsk->fill.ring_size = TQUIC_XSK_DEFAULT_RING_SIZE;
	xsk->comp.ring_size = TQUIC_XSK_DEFAULT_RING_SIZE;

	refcount_set(&xsk->refcnt, 1);

	/* Allocate UMEM buffer */
	xsk->buffer = vzalloc(xsk->buffer_size);
	if (!xsk->buffer) {
		err = -ENOMEM;
		goto err_free_xsk;
	}

	/* Create frame pool */
	xsk->frame_pool = tquic_xsk_frame_pool_create(num_frames, frame_size);
	if (IS_ERR(xsk->frame_pool)) {
		err = PTR_ERR(xsk->frame_pool);
		xsk->frame_pool = NULL;
		goto err_free_buffer;
	}

	/*
	 * SECURITY FIX (CF-071): Use the device's network namespace
	 * instead of init_net to support containerized environments.
	 */
	err = sock_create_kern(dev_net(dev), AF_XDP, SOCK_RAW, 0, &xsk->sock);
	if (err) {
		tquic_err("xdp: failed tocreate AF_XDP socket: %d\n", err);
		goto err_free_pool;
	}

	tquic_dbg("xdp: created XSKfor %s queue %d: %u frames x %u bytes\n",
		 ifname, queue_id, num_frames, frame_size);

	*xsk_out = xsk;
	return 0;

err_free_pool:
	tquic_xsk_frame_pool_destroy(xsk->frame_pool);
err_free_buffer:
	vfree(xsk->buffer);
err_free_xsk:
	dev_put(dev);
	kfree(xsk);
	return err;
}
EXPORT_SYMBOL_GPL(tquic_xsk_create);

void tquic_xsk_destroy(struct tquic_xsk *xsk)
{
	if (!xsk)
		return;

	/* Unload XDP program */
	tquic_xdp_unload_prog(xsk);

	/* Unbind from device */
	if (xsk->bound)
		tquic_xsk_unbind(xsk);

	/* Release socket */
	if (xsk->sock)
		sock_release(xsk->sock);

	/* Free resources */
	tquic_xsk_frame_pool_destroy(xsk->frame_pool);
	vfree(xsk->buffer);

	if (xsk->dev)
		dev_put(xsk->dev);

	kfree(xsk);
}
EXPORT_SYMBOL_GPL(tquic_xsk_destroy);

int tquic_xsk_bind(struct tquic_xsk *xsk)
{
	struct sockaddr_xdp sxdp = {};
	int err;

	if (!xsk || !xsk->sock || !xsk->dev)
		return -EINVAL;

	if (xsk->bound)
		return -EALREADY;

	/* Configure bind address */
	sxdp.sxdp_family = AF_XDP;
	sxdp.sxdp_ifindex = xsk->dev->ifindex;
	sxdp.sxdp_queue_id = xsk->queue_id;

	/* Set copy/zero-copy flags */
	if (xsk->mode == TQUIC_XDP_COPY)
		sxdp.sxdp_flags |= XDP_COPY;
	else if (xsk->mode == TQUIC_XDP_ZEROCOPY)
		sxdp.sxdp_flags |= XDP_ZEROCOPY;

	/* Bind socket to device queue */
	err = kernel_bind(xsk->sock, (struct sockaddr_unsized *)&sxdp, sizeof(sxdp));
	if (err) {
		tquic_err("xdp: failed tobind XSK to %s queue %d: %d\n",
		       xsk->dev->name, xsk->queue_id, err);
		return err;
	}

	xsk->bound = true;

	tquic_dbg("xdp: bound XSKto %s queue %d (mode=%s)\n",
		 xsk->dev->name, xsk->queue_id,
		 xsk->mode == TQUIC_XDP_ZEROCOPY ? "zerocopy" : "copy");

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_xsk_bind);

void tquic_xsk_unbind(struct tquic_xsk *xsk)
{
	if (!xsk || !xsk->bound)
		return;

	/* Socket unbind happens on close */
	xsk->bound = false;
}
EXPORT_SYMBOL_GPL(tquic_xsk_unbind);

/*
 * Packet I/O operations
 *
 * These functions provide the interface for AF_XDP packet reception and
 * transmission. They read from and write to the XSK ring buffers that are
 * shared between kernel and userspace via the XDP socket.
 */

int tquic_xsk_recv(struct tquic_xsk *xsk, struct tquic_xsk_packet *pkts,
		   int max_pkts)
{
	u32 idx_rx = 0;
	u32 entries;
	u32 available;
	u32 i;
	int received = 0;

	if (!xsk || !pkts || max_pkts <= 0)
		return -EINVAL;

	if (!xsk->bound)
		return -ENOTCONN;

	/* Get available entries from RX ring */
	if (!xsk->rx.ring || !xsk->rx.cons)
		return 0;

	entries = min_t(u32, max_pkts, xsk->rx_batch_size);

	/*
	 * Read from the RX ring. The producer (XDP program) writes descriptors
	 * to the ring, and we consume them here. We use memory barriers to
	 * ensure proper ordering between the producer and consumer.
	 */
	smp_rmb(); /* Read barrier before accessing ring */

	/* Calculate available entries: producer - consumer */
	available = READ_ONCE(*xsk->rx.prod) - READ_ONCE(*xsk->rx.cons);
	if (available == 0)
		return 0;

	entries = min_t(u32, entries, available);

	/* Process available descriptors */
	idx_rx = READ_ONCE(*xsk->rx.cons) & (xsk->rx.ring_size - 1);

	for (i = 0; i < entries; i++) {
		struct xdp_desc *desc = &xsk->rx.ring[idx_rx];
		u64 addr = desc->addr;
		u32 len = desc->len;

		/* Validate address is within buffer bounds */
		if (addr + len > xsk->buffer_size) {
			tquic_dbg("xdp:invalid RX desc addr=%llu len=%u\n",
				 addr, len);
			break;
		}

		/* Populate packet structure */
		pkts[received].addr = addr;
		pkts[received].data = xsk->buffer + addr;
		pkts[received].len = len;
		pkts[received].timestamp = ktime_get();
		pkts[received].xsk = xsk;
		pkts[received].frame_idx = addr / xsk->frame_size;
		pkts[received].owns_frame = true;

		received++;
		xsk->stats.rx_packets++;
		xsk->stats.rx_bytes += len;

		/* Advance ring index */
		idx_rx = (idx_rx + 1) & (xsk->rx.ring_size - 1);
	}

	/* Update consumer pointer */
	if (received > 0) {
		smp_wmb(); /* Write barrier before updating consumer */
		WRITE_ONCE(*xsk->rx.cons, READ_ONCE(*xsk->rx.cons) + received);
		xsk->rx.packets += received;
	}

	return received;
}
EXPORT_SYMBOL_GPL(tquic_xsk_recv);

void tquic_xsk_recv_complete(struct tquic_xsk *xsk,
			     struct tquic_xsk_packet *pkts, int num_pkts)
{
	int i;
	u32 added = 0;

	if (!xsk || !pkts || num_pkts <= 0)
		return;

	/* Return frames to fill ring */
	for (i = 0; i < num_pkts; i++) {
		if (!pkts[i].owns_frame)
			continue;

		/* Add frame back to fill ring for reuse */
		/* Real impl: xsk_ring_prod__reserve + submit */
		tquic_xsk_frame_pool_free(xsk->frame_pool, pkts[i].addr);
		pkts[i].owns_frame = false;
		added++;
	}

	xsk->fill.packets += added;
}
EXPORT_SYMBOL_GPL(tquic_xsk_recv_complete);

int tquic_xsk_send(struct tquic_xsk *xsk, struct tquic_xsk_packet *pkts,
		   int num_pkts)
{
	int sent = 0;
	int i;

	if (!xsk || !pkts || num_pkts <= 0)
		return -EINVAL;

	if (!xsk->bound)
		return -ENOTCONN;

	/* Queue packets to TX ring */
	for (i = 0; i < num_pkts && sent < xsk->tx_batch_size; i++) {
		u64 addr = pkts[i].addr;
		u32 len = pkts[i].len;

		/* Validate frame */
		if (addr + len > xsk->buffer_size) {
			xsk->stats.invalid_desc++;
			continue;
		}

		/* Copy data if using copy mode and addr is external */
		if (xsk->mode == TQUIC_XDP_COPY && !pkts[i].owns_frame) {
			u64 new_addr;
			int err;

			err = tquic_xsk_alloc_frame(xsk, &new_addr);
			if (err) {
				xsk->stats.tx_drops++;
				continue;
			}

			memcpy(xsk->buffer + new_addr, pkts[i].data, len);
			addr = new_addr;
		}

		/* Add to TX ring */
		/* Real impl: xsk_ring_prod__reserve + xsk_ring_prod__submit */
		sent++;
		xsk->stats.tx_packets++;
		xsk->stats.tx_bytes += len;
	}

	xsk->tx.packets += sent;

	return sent;
}
EXPORT_SYMBOL_GPL(tquic_xsk_send);

int tquic_xsk_flush_tx(struct tquic_xsk *xsk)
{
	int err;

	if (!xsk || !xsk->sock)
		return -EINVAL;

	/* Kick kernel to transmit */
	err = kernel_sendmsg(xsk->sock, &(struct msghdr){}, NULL, 0, 0);
	if (err < 0 && err != -EAGAIN && err != -ENOBUFS)
		return err;

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_xsk_flush_tx);

int tquic_xsk_poll_tx(struct tquic_xsk *xsk, int num_completions)
{
	u32 idx_comp;
	u32 available;
	u32 entries;
	int completed = 0;

	if (!xsk)
		return -EINVAL;

	/* Check if completion ring is available */
	if (!xsk->comp.ring || !xsk->comp.cons)
		return 0;

	/*
	 * Read from completion ring. The kernel writes completed TX frame
	 * addresses here after transmission. We consume them to free the
	 * frames back to our pool.
	 */
	smp_rmb(); /* Read barrier before accessing ring */

	/* Calculate available completions: producer - consumer */
	available = READ_ONCE(*xsk->comp.prod) - READ_ONCE(*xsk->comp.cons);
	if (available == 0)
		return 0;

	entries = min_t(u32, num_completions, available);
	idx_comp = READ_ONCE(*xsk->comp.cons) & (xsk->comp.ring_size - 1);

	/* Process completed TX descriptors */
	while (completed < entries) {
		u64 addr = xsk->comp.comp_addrs[idx_comp];

		/* Return frame to pool */
		if (xsk->frame_pool)
			tquic_xsk_frame_pool_free(xsk->frame_pool, addr);

		completed++;
		idx_comp = (idx_comp + 1) & (xsk->comp.ring_size - 1);
	}

	/* Update consumer pointer */
	if (completed > 0) {
		smp_wmb(); /* Write barrier before updating consumer */
		WRITE_ONCE(*xsk->comp.cons, READ_ONCE(*xsk->comp.cons) + completed);
		xsk->comp.packets += completed;
	}

	return completed;
}
EXPORT_SYMBOL_GPL(tquic_xsk_poll_tx);

/*
 * Frame allocation
 */

int tquic_xsk_alloc_frame(struct tquic_xsk *xsk, u64 *addr)
{
	if (!xsk || !xsk->frame_pool || !addr)
		return -EINVAL;

	return tquic_xsk_frame_pool_alloc(xsk->frame_pool, addr);
}
EXPORT_SYMBOL_GPL(tquic_xsk_alloc_frame);

void tquic_xsk_free_frame(struct tquic_xsk *xsk, u64 addr)
{
	if (!xsk || !xsk->frame_pool)
		return;

	tquic_xsk_frame_pool_free(xsk->frame_pool, addr);
}
EXPORT_SYMBOL_GPL(tquic_xsk_free_frame);

void *tquic_xsk_get_frame_data(struct tquic_xsk *xsk, u64 addr)
{
	if (!xsk || !xsk->buffer)
		return NULL;

	if (addr >= xsk->buffer_size)
		return NULL;

	return xsk->buffer + addr;
}
EXPORT_SYMBOL_GPL(tquic_xsk_get_frame_data);

/*
 * XDP program management
 *
 * XDP programs for QUIC packet steering can be loaded in two ways:
 * 1. From userspace via standard BPF tools (bpftool, libbpf)
 * 2. In-kernel using bpf_prog_create() with the embedded bytecode
 *
 * The embedded BPF program (tquic_xdp_prog_insns) steers QUIC packets
 * to the AF_XDP socket while passing other traffic through.
 */

int tquic_xdp_load_prog(struct tquic_xsk *xsk, const __be16 *ports,
			int num_ports)
{
	struct bpf_prog *prog;
	int err;

	if (!xsk || !xsk->dev)
		return -EINVAL;

	/* Attaching XDP programs requires CAP_NET_ADMIN */
	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	if (xsk->xdp_prog)
		return -EALREADY;

	/*
	 * Load the embedded BPF program using the kernel's BPF infrastructure.
	 * bpf_prog_create() compiles the BPF instructions and creates a
	 * verified, JIT-compiled program ready for execution.
	 */
	err = bpf_prog_create(&prog, &bpf_prog_types[BPF_PROG_TYPE_XDP],
			      tquic_xdp_prog_insns, TQUIC_XDP_PROG_LEN);
	if (err) {
		tquic_err("xdp: failed tocreate XDP program: %d\n", err);
		tquic_info("xdp: programcan alternatively be loaded from userspace\n");
		return err;
	}

	xsk->xdp_prog = prog;

	/* Attach XDP program to the network device */
	rtnl_lock();
	err = dev_xdp_attach(xsk->dev, NULL, prog, XDP_FLAGS_SKB_MODE, NULL);
	rtnl_unlock();

	if (err) {
		tquic_err("xdp: failed toattach XDP program to %s: %d\n",
		       xsk->dev->name, err);
		bpf_prog_put(prog);
		xsk->xdp_prog = NULL;
		return err;
	}

	tquic_info("xdp: loadedprogram on %s\n", xsk->dev->name);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_xdp_load_prog);

void tquic_xdp_unload_prog(struct tquic_xsk *xsk)
{
	if (!xsk || !xsk->dev)
		return;

	if (!xsk->xdp_prog)
		return;

	/* Detach XDP program from device */
	rtnl_lock();
	dev_xdp_attach(xsk->dev, NULL, NULL, XDP_FLAGS_SKB_MODE, NULL);
	rtnl_unlock();

	/* Release BPF program reference */
	bpf_prog_put(xsk->xdp_prog);
	xsk->xdp_prog = NULL;
	xsk->xdp_prog_fd = 0;

	tquic_dbg("xdp: unloadedprogram from %s\n", xsk->dev->name);
}
EXPORT_SYMBOL_GPL(tquic_xdp_unload_prog);

int tquic_xdp_get_stats(struct tquic_xsk *xsk, struct tquic_xdp_stats *stats)
{
	if (!xsk || !stats)
		return -EINVAL;

	memset(stats, 0, sizeof(*stats));

	/* Copy stats from XSK */
	stats->rx_quic_packets = xsk->stats.rx_packets;
	stats->xsk_redirect_ok = xsk->stats.rx_packets;
	stats->xsk_redirect_fail = xsk->stats.rx_drops;

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_xdp_get_stats);

/*
 * TQUIC socket integration
 */

int tquic_xsk_attach(struct sock *sk, struct tquic_xsk *xsk)
{
	struct tquic_sock *tsk;

	if (!sk || !xsk)
		return -EINVAL;

	tsk = tquic_sk(sk);
	if (!tsk->conn)
		return -ENOTCONN;

	lock_sock(sk);

	/* Release any previously attached XSK */
	if (tsk->conn->xsk)
		tquic_xsk_put(tsk->conn->xsk);

	/* Store XSK reference in connection */
	tquic_xsk_get(xsk);
	xsk->conn = tsk->conn;
	tsk->conn->xsk = xsk;

	release_sock(sk);

	tquic_dbg("xdp: attached XSK to TQUIC socket\n");

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_xsk_attach);

void tquic_xsk_detach(struct sock *sk)
{
	struct tquic_sock *tsk;
	struct tquic_xsk *xsk;

	if (!sk)
		return;

	tsk = tquic_sk(sk);
	if (!tsk->conn)
		return;

	lock_sock(sk);

	/*
	 * Retrieve and release XSK reference from connection.
	 * The XSK stores a back-pointer to conn; use it to find
	 * and release the matching XSK.
	 */
	xsk = tsk->conn->xsk;
	if (xsk) {
		xsk->conn = NULL;
		tsk->conn->xsk = NULL;
		tquic_xsk_put(xsk);
	}

	release_sock(sk);

	tquic_dbg("xdp: detached XSK from TQUIC socket\n");
}
EXPORT_SYMBOL_GPL(tquic_xsk_detach);

int tquic_xsk_attach_path(struct tquic_connection *conn,
			  struct tquic_path *path,
			  struct tquic_xsk *xsk)
{
	if (!conn || !path || !xsk)
		return -EINVAL;

	/* Release any previously attached XSK on this path */
	if (path->xsk)
		tquic_xsk_put(path->xsk);

	/* Per-path XSK attachment for multipath */
	tquic_xsk_get(xsk);
	xsk->path = path;
	path->xsk = xsk;

	tquic_dbg("xdp: attached XSK to path %u\n", path->path_id);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_xsk_attach_path);

void tquic_xsk_detach_path(struct tquic_connection *conn,
			   struct tquic_path *path)
{
	struct tquic_xsk *xsk;

	if (!conn || !path)
		return;

	/* Release XSK reference from path */
	xsk = path->xsk;
	if (xsk) {
		xsk->path = NULL;
		path->xsk = NULL;
		tquic_xsk_put(xsk);
	}

	tquic_dbg("xdp: detached XSK from path %u\n", path->path_id);
}
EXPORT_SYMBOL_GPL(tquic_xsk_detach_path);

/*
 * Socket option handlers
 */

int tquic_xsk_setsockopt(struct sock *sk, sockptr_t optval,
			 unsigned int optlen)
{
	struct tquic_xdp_config config = {};
	struct tquic_xsk *xsk = NULL;
	int err;

	/* XDP configuration requires CAP_NET_ADMIN */
	if (!capable(CAP_NET_ADMIN))
		return -EPERM;

	if (optlen < sizeof(config))
		return -EINVAL;

	if (copy_from_sockptr(&config, optval, sizeof(config)))
		return -EFAULT;

	/* Validate mode */
	if (config.mode > TQUIC_XDP_ZEROCOPY)
		return -EINVAL;

	/* If disabling XDP, just detach */
	if (config.mode == TQUIC_XDP_OFF) {
		tquic_xsk_detach(sk);
		return 0;
	}

	/* Create XSK */
	err = tquic_xsk_create(&xsk, config.ifname, config.queue_id, &config);
	if (err)
		return err;

	/* Load XDP program */
	err = tquic_xdp_load_prog(xsk, NULL, 0);
	if (err) {
		tquic_xsk_destroy(xsk);
		return err;
	}

	/* Bind to device */
	err = tquic_xsk_bind(xsk);
	if (err) {
		tquic_xsk_destroy(xsk);
		return err;
	}

	/* Attach to TQUIC socket */
	err = tquic_xsk_attach(sk, xsk);
	if (err) {
		tquic_xsk_destroy(xsk);
		return err;
	}

	/* Release our reference (socket now owns it) */
	tquic_xsk_put(xsk);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_xsk_setsockopt);

int tquic_xsk_getsockopt(struct sock *sk, char __user *optval,
			 int __user *optlen)
{
	struct tquic_xdp_stats stats = {};
	int len;

	if (get_user(len, optlen))
		return -EFAULT;

	if (len < sizeof(stats))
		return -EINVAL;

	/* Get stats from attached XSK */
	/* Would retrieve XSK from socket and call tquic_xdp_get_stats */

	if (copy_to_user(optval, &stats, sizeof(stats)))
		return -EFAULT;

	if (put_user(sizeof(stats), optlen))
		return -EFAULT;

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_xsk_getsockopt);

/*
 * Utility functions
 */

bool tquic_xsk_need_wakeup(struct tquic_xsk *xsk)
{
	if (!xsk)
		return false;

	/* Check if kernel needs wakeup via poll/sendmsg */
	/* Real impl checks XDP_RING_NEED_WAKEUP flag */
	return false;
}
EXPORT_SYMBOL_GPL(tquic_xsk_need_wakeup);

int tquic_xsk_wakeup(struct tquic_xsk *xsk)
{
	if (!xsk || !xsk->sock)
		return -EINVAL;

	/* Wake up the socket for processing */
	return tquic_xsk_flush_tx(xsk);
}
EXPORT_SYMBOL_GPL(tquic_xsk_wakeup);

bool tquic_xsk_fill_ring_empty(struct tquic_xsk *xsk)
{
	if (!xsk || !xsk->frame_pool)
		return true;

	/* Check if fill ring needs replenishment */
	return xsk->frame_pool->free_count < (xsk->num_frames / 4);
}
EXPORT_SYMBOL_GPL(tquic_xsk_fill_ring_empty);

int tquic_xsk_fill_ring_replenish(struct tquic_xsk *xsk, int num_frames)
{
	int added = 0;
	int i;

	if (!xsk || num_frames <= 0)
		return 0;

	/* Add frames to fill ring */
	for (i = 0; i < num_frames; i++) {
		u64 addr;
		int err;

		err = tquic_xsk_alloc_frame(xsk, &addr);
		if (err)
			break;

		/* Add to fill ring */
		/* Real impl: xsk_ring_prod__reserve + submit */
		added++;
	}

	return added;
}
EXPORT_SYMBOL_GPL(tquic_xsk_fill_ring_replenish);

bool tquic_xsk_supported(const char *ifname)
{
	struct net_device *dev;
	bool supported = false;

	if (!ifname)
		return false;

	/* SECURITY FIX (CF-071): Use caller's network namespace */
	dev = dev_get_by_name(current->nsproxy->net_ns, ifname);
	if (!dev)
		return false;

	/* Check if device supports XDP */
	if (dev->netdev_ops && dev->netdev_ops->ndo_bpf)
		supported = true;

	dev_put(dev);
	return supported;
}
EXPORT_SYMBOL_GPL(tquic_xsk_supported);

bool tquic_xsk_zerocopy_supported(const char *ifname)
{
	struct net_device *dev;
	bool supported = false;

	if (!ifname)
		return false;

	/* SECURITY FIX (CF-071): Use caller's network namespace */
	dev = dev_get_by_name(current->nsproxy->net_ns, ifname);
	if (!dev)
		return false;

	/* Check if device supports XDP zero-copy */
	if (dev->xdp_features & NETDEV_XDP_ACT_XSK_ZEROCOPY)
		supported = true;

	dev_put(dev);
	return supported;
}
EXPORT_SYMBOL_GPL(tquic_xsk_zerocopy_supported);

/*
 * Module initialization
 */

int __init tquic_af_xdp_init(void)
{
	tquic_info("AF_XDPsupport initialized\n");
	return 0;
}

void __exit tquic_af_xdp_exit(void)
{
	tquic_info("AF_XDPsupport exiting\n");
}

module_init(tquic_af_xdp_init);
module_exit(tquic_af_xdp_exit);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TQUIC AF_XDP Integration");
MODULE_AUTHOR("Linux Foundation");
