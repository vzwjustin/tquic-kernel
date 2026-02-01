/* SPDX-License-Identifier: GPL-2.0 */
/*
 * TQUIC: Zero-Copy I/O Support Header
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Internal definitions for TQUIC zero-copy I/O support.
 */

#ifndef _TQUIC_ZEROCOPY_H
#define _TQUIC_ZEROCOPY_H

#include <linux/types.h>
#include <linux/socket.h>
#include <linux/skbuff.h>
#include <linux/splice.h>
#include <net/sock.h>
#include <net/tquic.h>

/*
 * Zerocopy Configuration
 */

/* Maximum outstanding zerocopy buffers per connection */
#define TQUIC_ZC_MAX_OUTSTANDING	256

/* Minimum data size to use zerocopy (avoid overhead for small sends) */
#define TQUIC_ZC_MIN_SIZE		PAGE_SIZE

/* Maximum pages per single zerocopy operation */
#define TQUIC_ZC_MAX_PAGES		16

/*
 * Zerocopy Entry State
 */

/* Zerocopy entry states */
enum tquic_zc_state {
	TQUIC_ZC_PENDING = 0,	/* Queued for transmission */
	TQUIC_ZC_IN_FLIGHT,	/* Transmitted, awaiting ACK */
	TQUIC_ZC_COMPLETED,	/* ACKed, ready for notification */
	TQUIC_ZC_NOTIFIED,	/* Userspace notified */
};

/*
 * Forward Declarations
 */

struct tquic_connection;
struct tquic_stream;
struct tquic_zc_state;
struct tquic_zc_entry;

/*
 * Zerocopy State Management
 */

/* Allocate/free zerocopy state for connection */
int tquic_zc_state_alloc(struct tquic_connection *conn);
void tquic_zc_state_free(struct tquic_connection *conn);

/*
 * MSG_ZEROCOPY Support
 */

/* Handle MSG_ZEROCOPY in sendmsg */
int tquic_sendmsg_zerocopy(struct sock *sk, struct msghdr *msg, size_t len,
			   struct tquic_stream *stream);

/* Validate MSG_ZEROCOPY requirements */
int tquic_check_zerocopy_flag(struct sock *sk, struct msghdr *msg, int flags);

/*
 * sendpage/sendfile Support
 */

/* sendfile() support via .sendpage */
ssize_t tquic_sendpage(struct socket *sock, struct page *page,
		       int offset, size_t size, int flags);

/*
 * Splice Support
 */

/* splice_read() support for zero-copy pipe transfer */
ssize_t tquic_splice_read(struct socket *sock, loff_t *ppos,
			  struct pipe_inode_info *pipe, size_t len,
			  unsigned int flags);

/*
 * Receive-Side Zero-Copy
 */

/* Peek at available data size (for MSG_TRUNC optimization) */
size_t tquic_recvmsg_peek_size(struct sock *sk, struct tquic_stream *stream);

/* Page pool for direct receive placement */
struct page *tquic_rx_page_pool_alloc(struct tquic_connection *conn);

/* Build skb using pre-allocated page (zero-copy receive) */
struct sk_buff *tquic_rx_build_skb_from_page(struct tquic_connection *conn,
					     struct page *page,
					     unsigned int offset,
					     unsigned int len);

/*
 * Socket Options
 */

/* SO_ZEROCOPY support */
int tquic_set_zerocopy(struct sock *sk, int val);
int tquic_get_zerocopy(struct sock *sk);

/*
 * Completion Notification
 */

/* Notify zerocopy completion via error queue */
void tquic_zc_complete(struct sock *sk, u32 id);
void tquic_zc_abort(struct sock *sk, u32 id, int err);

/*
 * SKB Zerocopy Helpers
 */

/* Setup skb for zerocopy transmission */
int tquic_skb_zerocopy_setup(struct sk_buff *skb, struct page *page,
			     unsigned int offset, unsigned int len);

/* Handle page references for received zerocopy skb */
int tquic_skb_orphan_frags_rx(struct sk_buff *skb, gfp_t gfp);

/*
 * Integration Helpers
 */

/**
 * tquic_supports_zerocopy - Check if zerocopy is supported
 * @sk: Socket to check
 *
 * Returns true if zerocopy is supported and beneficial.
 */
static inline bool tquic_supports_zerocopy(struct sock *sk)
{
	if (!sk)
		return false;

	/*
	 * Zerocopy is supported if:
	 * 1. SO_ZEROCOPY is enabled on socket
	 * 2. Device supports scatter-gather (for best performance)
	 *
	 * Without SG, we can still do zerocopy with copy fallback
	 * and completion notification.
	 */
	return sock_flag(sk, SOCK_ZEROCOPY);
}

/**
 * tquic_zerocopy_sg_ok - Check if SG is available for zerocopy
 * @sk: Socket to check
 *
 * Returns true if scatter-gather is available for true zerocopy.
 */
static inline bool tquic_zerocopy_sg_ok(struct sock *sk)
{
	return sk && (sk->sk_route_caps & NETIF_F_SG);
}

/**
 * tquic_zerocopy_size_ok - Check if size is suitable for zerocopy
 * @size: Data size
 *
 * Returns true if size is large enough to benefit from zerocopy.
 * Small messages have more overhead than copying.
 */
static inline bool tquic_zerocopy_size_ok(size_t size)
{
	return size >= TQUIC_ZC_MIN_SIZE;
}

/**
 * tquic_can_use_zerocopy - Full zerocopy eligibility check
 * @sk: Socket
 * @size: Data size
 * @flags: Message flags
 *
 * Returns true if zerocopy should be used for this send operation.
 */
static inline bool tquic_can_use_zerocopy(struct sock *sk, size_t size, int flags)
{
	if (!(flags & MSG_ZEROCOPY))
		return false;

	if (!tquic_supports_zerocopy(sk))
		return false;

	/* Allow small sizes if explicitly requested, but log warning */
	if (!tquic_zerocopy_size_ok(size))
		pr_debug("tquic: zerocopy for small size %zu (may have overhead)\n",
			 size);

	return true;
}

/*
 * Stream-Level Zerocopy Tracking
 */

/**
 * struct tquic_stream_zc_info - Per-stream zerocopy tracking
 * @zc_enabled: Zerocopy enabled for this stream
 * @pending_zc: Number of pending zerocopy operations
 * @completed_zc: Number of completed operations awaiting notification
 *
 * Tracks zerocopy state per-stream for proper ordering and
 * completion notification.
 */
struct tquic_stream_zc_info {
	bool		zc_enabled;
	atomic_t	pending_zc;
	atomic_t	completed_zc;
};

/* Initialize stream zerocopy info */
static inline void tquic_stream_zc_init(struct tquic_stream_zc_info *info)
{
	info->zc_enabled = false;
	atomic_set(&info->pending_zc, 0);
	atomic_set(&info->completed_zc, 0);
}

/* Check if stream has pending zerocopy operations */
static inline bool tquic_stream_zc_pending(struct tquic_stream_zc_info *info)
{
	return atomic_read(&info->pending_zc) > 0;
}

#endif /* _TQUIC_ZEROCOPY_H */
