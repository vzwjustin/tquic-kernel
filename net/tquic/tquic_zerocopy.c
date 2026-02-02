// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Zero-Copy I/O Support
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Implements high-performance zero-copy I/O paths for TQUIC:
 *   - sendfile/splice support via page references
 *   - MSG_ZEROCOPY for sendmsg with completion notification
 *   - Receive-side direct page placement
 *   - Integration with QUIC stream framing
 *
 * Reference: TCP zerocopy implementation (net/ipv4/tcp.c)
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/socket.h>
#include <linux/file.h>
#include <linux/splice.h>
#include <linux/pipe_fs_i.h>
#include <linux/highmem.h>
#include <linux/pagemap.h>
#include <linux/uio.h>
#include <linux/errqueue.h>
#include <net/sock.h>
#include <net/tquic.h>

#include "protocol.h"

/*
 * =============================================================================
 * Zero-Copy Tracking State
 * =============================================================================
 */

/* Maximum outstanding zerocopy buffers per connection */
#define TQUIC_ZC_MAX_OUTSTANDING	256

/* Zerocopy buffer tracking entry */
struct tquic_zc_entry {
	struct list_head	list;
	u32			id;		/* Notification ID */
	struct ubuf_info	*uarg;		/* User buffer info */
	struct page		**pages;	/* Page references */
	unsigned int		nr_pages;	/* Number of pages */
	u64			stream_id;	/* Associated stream */
	u64			offset;		/* Stream offset */
	size_t			len;		/* Data length */
	atomic_t		refcnt;		/* Reference count */
	bool			completed;	/* Transmission complete */
};

/* Zerocopy state for connection */
struct tquic_zc_state {
	spinlock_t		lock;
	struct list_head	pending;	/* Pending zerocopy entries */
	struct list_head	completed;	/* Completed entries awaiting notification */
	u32			next_id;	/* Next notification ID */
	u32			outstanding;	/* Outstanding zerocopy count */
	wait_queue_head_t	wait;		/* Wait for completion */
	bool			enabled;	/* Zerocopy enabled */
};

/*
 * =============================================================================
 * Zerocopy State Management
 * =============================================================================
 */

/**
 * tquic_zc_state_alloc - Allocate zerocopy state for connection
 * @conn: Connection to add zerocopy state to
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_zc_state_alloc(struct tquic_connection *conn)
{
	struct tquic_zc_state *zc;

	if (!conn)
		return -EINVAL;

	zc = kzalloc(sizeof(*zc), GFP_KERNEL);
	if (!zc)
		return -ENOMEM;

	spin_lock_init(&zc->lock);
	INIT_LIST_HEAD(&zc->pending);
	INIT_LIST_HEAD(&zc->completed);
	init_waitqueue_head(&zc->wait);
	zc->next_id = 0;
	zc->outstanding = 0;
	zc->enabled = false;

	/* Store state in connection's dedicated field */
	conn->zc_state = zc;

	pr_debug("tquic: zero-copy state allocated\n");
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_zc_state_alloc);

/**
 * tquic_zc_state_free - Free zerocopy state
 * @conn: Connection
 */
void tquic_zc_state_free(struct tquic_connection *conn)
{
	struct tquic_zc_state *zc;
	struct tquic_zc_entry *entry, *tmp;

	if (!conn)
		return;

	zc = conn->zc_state;
	if (!zc)
		return;

	spin_lock_bh(&zc->lock);

	/* Free all pending entries */
	list_for_each_entry_safe(entry, tmp, &zc->pending, list) {
		list_del(&entry->list);
		tquic_zc_entry_free(entry);
	}

	/* Free all completed entries */
	list_for_each_entry_safe(entry, tmp, &zc->completed, list) {
		list_del(&entry->list);
		tquic_zc_entry_free(entry);
	}

	spin_unlock_bh(&zc->lock);

	kfree(zc);
	conn->zc_state = NULL;

	pr_debug("tquic: zero-copy state freed\n");
}
EXPORT_SYMBOL_GPL(tquic_zc_state_free);

/*
 * =============================================================================
 * Zero-Copy Entry Management
 * =============================================================================
 */

static struct tquic_zc_entry *tquic_zc_entry_alloc(gfp_t gfp)
{
	struct tquic_zc_entry *entry;

	entry = kzalloc(sizeof(*entry), gfp);
	if (!entry)
		return NULL;

	INIT_LIST_HEAD(&entry->list);
	atomic_set(&entry->refcnt, 1);
	entry->completed = false;

	return entry;
}

static void tquic_zc_entry_free(struct tquic_zc_entry *entry)
{
	unsigned int i;

	if (!entry)
		return;

	/* Release page references */
	if (entry->pages) {
		for (i = 0; i < entry->nr_pages; i++) {
			if (entry->pages[i])
				put_page(entry->pages[i]);
		}
		kfree(entry->pages);
	}

	/* Release user buffer info */
	if (entry->uarg)
		net_zcopy_put(entry->uarg);

	kfree(entry);
}

static void tquic_zc_entry_get(struct tquic_zc_entry *entry)
{
	atomic_inc(&entry->refcnt);
}

static void tquic_zc_entry_put(struct tquic_zc_entry *entry)
{
	if (atomic_dec_and_test(&entry->refcnt))
		tquic_zc_entry_free(entry);
}

/*
 * =============================================================================
 * MSG_ZEROCOPY Support for sendmsg
 * =============================================================================
 */

/**
 * tquic_zerocopy_callback - Callback when zerocopy transmission completes
 * @sk: Socket
 * @uarg: User buffer argument
 * @success: Whether transmission succeeded
 *
 * Called from skb destructor when zerocopy pages can be released.
 * Sends notification to userspace via error queue.
 */
/**
 * tquic_zerocopy_complete - Zerocopy completion callback
 * @skb: Socket buffer being completed
 * @uarg: Zerocopy buffer info
 * @success: True if zero-copy was successful
 *
 * Called when zerocopy transmission completes. Uses the standard
 * msg_zerocopy_ubuf_ops for completion notification.
 */
static void tquic_zerocopy_complete(struct sk_buff *skb,
				    struct ubuf_info *uarg,
				    bool success)
{
	/* Use the standard zerocopy ops for completion */
	if (uarg && uarg->ops && uarg->ops->complete)
		uarg->ops->complete(skb, uarg, success);
}

/**
 * tquic_sendmsg_zerocopy - Handle MSG_ZEROCOPY flag in sendmsg
 * @sk: Socket
 * @msg: Message header
 * @len: Data length
 * @stream: Target stream
 *
 * Uses skb_zerocopy_iter_stream() to map user pages directly into
 * skbs without copying. Completion notification via error queue.
 *
 * Returns: Number of bytes queued on success, negative errno on failure
 */
int tquic_sendmsg_zerocopy(struct sock *sk, struct msghdr *msg, size_t len,
			   struct tquic_stream *stream)
{
	struct tquic_sock *tsk = tquic_sk(sk);
	struct tquic_connection *conn = tsk->conn;
	struct ubuf_info *uarg = NULL;
	struct sk_buff *skb = NULL;
	size_t copied = 0;
	int err;

	if (!conn || conn->state != TQUIC_CONN_CONNECTED)
		return -ENOTCONN;

	if (!stream)
		return -EINVAL;

	/* Check if zerocopy is enabled on socket */
	if (!sock_flag(sk, SOCK_ZEROCOPY))
		return -EOPNOTSUPP;

	/* Get or allocate user buffer info for zerocopy tracking */
	if (msg->msg_ubuf) {
		/* Reuse existing ubuf from message */
		uarg = msg->msg_ubuf;
	} else {
		/* Allocate new zerocopy tracking structure */
		skb = skb_peek_tail(&stream->send_buf);
		uarg = msg_zerocopy_realloc(sk, len, skb ? skb_zcopy(skb) : NULL);
		if (!uarg) {
			err = -ENOBUFS;
			goto out_err;
		}
	}

	/* Process data in chunks, mapping pages directly */
	while (copied < len) {
		size_t chunk = min_t(size_t, len - copied, 1200);
		struct sk_buff *new_skb;

		/* Allocate skb for this chunk */
		new_skb = alloc_skb(0, GFP_KERNEL);
		if (!new_skb) {
			err = -ENOMEM;
			goto out_err;
		}

		new_skb->sk = sk;

		/* Check if scatter-gather is supported */
		if (sk->sk_route_caps & NETIF_F_SG) {
			/*
			 * Use zerocopy path - map user pages directly
			 * into skb frags without copying data.
			 */
			err = skb_zerocopy_iter_stream(sk, new_skb, msg, chunk,
						       uarg);
			if (err < 0) {
				kfree_skb(new_skb);
				if (err == -EMSGSIZE || err == -EEXIST) {
					/* Try with a new skb */
					continue;
				}
				goto out_err;
			}

			/* Mark skb for zerocopy notification */
			skb_shinfo(new_skb)->flags |= SKBFL_ZEROCOPY_FRAG;
		} else {
			/*
			 * Fallback to copy path if SG not supported.
			 * Mark as zerocopy but actually copy data.
			 */
			u8 *data = skb_put(new_skb, chunk);

			if (copy_from_iter(data, chunk, &msg->msg_iter) != chunk) {
				kfree_skb(new_skb);
				err = -EFAULT;
				goto out_err;
			}

			/* Still notify completion even though we copied */
			if (uarg) {
				skb_zcopy_set(new_skb, uarg, NULL);
				uarg_to_msgzc(uarg)->zerocopy = 0;
			}
		}

		/* Queue the skb to stream send buffer */
		skb_queue_tail(&stream->send_buf, new_skb);
		copied += chunk;
		conn->stats.tx_bytes += chunk;
	}

	/* Trigger transmission */
	if (tsk->nodelay || stream->send_offset == 0)
		tquic_output_flush(conn);

	return copied;

out_err:
	if (uarg && !msg->msg_ubuf)
		net_zcopy_put(uarg);
	return err;
}
EXPORT_SYMBOL_GPL(tquic_sendmsg_zerocopy);

/**
 * tquic_check_zerocopy_flag - Check and validate MSG_ZEROCOPY flag
 * @sk: Socket
 * @msg: Message header
 * @flags: Message flags
 *
 * Validates zerocopy requirements and socket state.
 *
 * Returns: 0 if zerocopy can proceed, negative errno otherwise
 */
int tquic_check_zerocopy_flag(struct sock *sk, struct msghdr *msg, int flags)
{
	if (!(flags & MSG_ZEROCOPY))
		return -EOPNOTSUPP;

	/* Check SO_ZEROCOPY is enabled */
	if (!sock_flag(sk, SOCK_ZEROCOPY))
		return -EOPNOTSUPP;

	/* Check for scatter-gather support (preferred but not required) */
	if (!(sk->sk_route_caps & NETIF_F_SG)) {
		/* Will fallback to copy with notification */
		pr_debug("tquic: zerocopy fallback to copy (no SG support)\n");
	}

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_check_zerocopy_flag);

/*
 * =============================================================================
 * sendpage/sendfile Support
 * =============================================================================
 */

/**
 * tquic_sendpage - sendfile() support for TQUIC sockets
 * @sock: Socket
 * @page: Page to send
 * @offset: Offset within page
 * @size: Number of bytes to send
 * @flags: Send flags
 *
 * Implements .sendpage for sendfile() support. Uses page references
 * instead of copying data, integrating with QUIC stream framing.
 *
 * Returns: Number of bytes sent on success, negative errno on failure
 */
ssize_t tquic_sendpage(struct socket *sock, struct page *page,
		       int offset, size_t size, int flags)
{
	struct sock *sk = sock->sk;
	struct tquic_sock *tsk;
	struct tquic_connection *conn;
	struct tquic_stream *stream;
	struct sk_buff *skb;
	int err;

	if (!sk)
		return -ENOTCONN;

	tsk = tquic_sk(sk);
	conn = tsk->conn;

	if (!conn || conn->state != TQUIC_CONN_CONNECTED)
		return -ENOTCONN;

	/* Use default stream */
	stream = tsk->default_stream;
	if (!stream) {
		stream = tquic_stream_open(conn, true);
		if (!stream)
			return -ENOMEM;
		tsk->default_stream = stream;
	}

	/* Validate size and offset */
	if (offset < 0 || size > PAGE_SIZE - offset)
		return -EINVAL;

	/* Allocate skb without data buffer - we'll use page frags */
	skb = alloc_skb(0, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	skb->sk = sk;

	/* Check for scatter-gather support */
	if (sk->sk_route_caps & NETIF_F_SG) {
		/*
		 * Zero-copy path: add page as fragment.
		 * Use skb_fill_page_desc to add page reference.
		 */
		get_page(page);
		skb_fill_page_desc(skb, 0, page, offset, size);
		skb->len += size;
		skb->data_len += size;
		skb->truesize += size;

		/* Mark for zerocopy completion */
		skb_shinfo(skb)->flags |= SKBFL_ZEROCOPY_FRAG;
	} else {
		/*
		 * Copy path: map page and copy data.
		 * Required when hardware doesn't support SG.
		 */
		u8 *data;
		void *vaddr;

		/* Need to allocate actual data space */
		kfree_skb(skb);
		skb = alloc_skb(size, GFP_KERNEL);
		if (!skb)
			return -ENOMEM;

		skb->sk = sk;
		data = skb_put(skb, size);

		/* Map page and copy */
		vaddr = kmap_local_page(page);
		memcpy(data, vaddr + offset, size);
		kunmap_local(vaddr);
	}

	/* Queue to stream send buffer */
	skb_queue_tail(&stream->send_buf, skb);
	conn->stats.tx_bytes += size;

	/* Trigger transmission */
	if (tsk->nodelay)
		tquic_output_flush(conn);

	return size;
}
EXPORT_SYMBOL_GPL(tquic_sendpage);

/*
 * =============================================================================
 * Splice Support
 * =============================================================================
 */

/* Splice state for TQUIC */
struct tquic_splice_state {
	struct tquic_connection	*conn;
	struct tquic_stream	*stream;
	struct pipe_inode_info	*pipe;
	size_t			len;
	unsigned int		flags;
};

/**
 * tquic_splice_data_recv - Callback for splice data reception
 * @desc: Read descriptor containing splice state
 * @skb: SKB containing data
 * @offset: Offset into skb data
 * @len: Length of data available
 *
 * Called during splice_read to transfer data from stream to pipe.
 */
static int tquic_splice_data_recv(read_descriptor_t *desc,
				  struct sk_buff *skb,
				  unsigned int offset,
				  size_t len)
{
	struct tquic_splice_state *tss = desc->arg.data;
	struct splice_pipe_desc spd = {
		.pages = NULL,
		.partial = NULL,
		.nr_pages_max = MAX_SKB_FRAGS,
		.ops = &nosteal_pipe_buf_ops,
		.spd_release = NULL,
	};
	struct page *pages[MAX_SKB_FRAGS];
	struct partial_page partial[MAX_SKB_FRAGS];
	int nr_pages = 0;
	size_t splice_len;
	int ret;

	/* Limit to requested length */
	splice_len = min(len, desc->count);
	if (splice_len == 0)
		return 0;

	spd.pages = pages;
	spd.partial = partial;

	/*
	 * For linear data in skb head, we need to find/allocate a page.
	 * For paged data (frags), we can reference pages directly.
	 */
	if (skb_headlen(skb) > offset) {
		/* Data in linear region */
		size_t head_len = min(splice_len, skb_headlen(skb) - offset);
		struct page *page;
		unsigned int pg_off;

		page = virt_to_page(skb->data + offset);
		pg_off = ((unsigned long)(skb->data + offset)) & ~PAGE_MASK;

		pages[nr_pages] = page;
		partial[nr_pages].offset = pg_off;
		partial[nr_pages].len = head_len;
		partial[nr_pages].private = 0;

		get_page(page);
		nr_pages++;
		splice_len = head_len;  /* May be less than requested */
	} else {
		/* Data in page frags */
		int frag_idx;
		size_t frag_offset;
		skb_frag_t *frag;

		/* Find the right frag */
		frag_offset = offset - skb_headlen(skb);
		for (frag_idx = 0; frag_idx < skb_shinfo(skb)->nr_frags; frag_idx++) {
			frag = &skb_shinfo(skb)->frags[frag_idx];
			if (frag_offset < skb_frag_size(frag))
				break;
			frag_offset -= skb_frag_size(frag);
		}

		if (frag_idx < skb_shinfo(skb)->nr_frags) {
			frag = &skb_shinfo(skb)->frags[frag_idx];
			splice_len = min(splice_len,
					 (size_t)(skb_frag_size(frag) - frag_offset));

			pages[nr_pages] = skb_frag_page(frag);
			partial[nr_pages].offset = skb_frag_off(frag) + frag_offset;
			partial[nr_pages].len = splice_len;
			partial[nr_pages].private = 0;

			get_page(pages[nr_pages]);
			nr_pages++;
		}
	}

	if (nr_pages == 0)
		return 0;

	spd.nr_pages = nr_pages;

	/* Splice pages into pipe */
	ret = splice_to_pipe(tss->pipe, &spd);
	if (ret > 0)
		desc->count -= ret;

	return ret;
}

/**
 * __tquic_splice_read - Internal splice read helper
 * @sk: Socket
 * @tss: Splice state
 *
 * Returns: Number of bytes spliced or negative errno
 */
static int __tquic_splice_read(struct sock *sk, struct tquic_splice_state *tss)
{
	struct tquic_sock *tsk = tquic_sk(sk);
	struct tquic_stream *stream = tss->stream;
	read_descriptor_t rd_desc = {
		.arg.data = tss,
		.count = tss->len,
	};
	struct sk_buff *skb;
	int ret = 0;
	size_t spliced = 0;

	/* Process available skbs in receive buffer */
	while ((skb = skb_peek(&stream->recv_buf)) != NULL && rd_desc.count > 0) {
		int used;

		used = tquic_splice_data_recv(&rd_desc, skb, 0, skb->len);
		if (used <= 0) {
			if (used < 0)
				ret = used;
			break;
		}

		spliced += used;

		/* Consume from skb */
		if (used >= skb->len) {
			skb_unlink(skb, &stream->recv_buf);
			kfree_skb(skb);
		} else {
			/* Partial read - pull data */
			skb_pull(skb, used);
		}
	}

	return spliced > 0 ? spliced : ret;
}

/**
 * tquic_splice_read - splice data from TQUIC stream to pipe
 * @sock: Socket
 * @ppos: Position (not used, must be NULL)
 * @pipe: Pipe to splice to
 * @len: Number of bytes to splice
 * @flags: Splice flags
 *
 * Implements .splice_read in proto_ops for zero-copy data transfer
 * from QUIC stream receive buffer to a pipe (for use with sendfile/splice).
 *
 * Returns: Number of bytes spliced on success, negative errno on failure
 */
ssize_t tquic_splice_read(struct socket *sock, loff_t *ppos,
			  struct pipe_inode_info *pipe, size_t len,
			  unsigned int flags)
{
	struct sock *sk = sock->sk;
	struct tquic_sock *tsk;
	struct tquic_connection *conn;
	struct tquic_stream *stream;
	struct tquic_splice_state tss;
	long timeo;
	ssize_t spliced = 0;
	int ret;

	if (!sk)
		return -ENOTCONN;

	tsk = tquic_sk(sk);
	conn = tsk->conn;

	if (!conn || conn->state != TQUIC_CONN_CONNECTED)
		return -ENOTCONN;

	/* Use default stream for simple API */
	stream = tsk->default_stream;
	if (!stream)
		return 0;  /* No data available */

	/* Initialize splice state */
	tss.conn = conn;
	tss.stream = stream;
	tss.pipe = pipe;
	tss.len = len;
	tss.flags = flags;

	lock_sock(sk);

	/* Get receive timeout */
	timeo = sock_rcvtimeo(sk, sock->file->f_flags & O_NONBLOCK);

	while (tss.len) {
		ret = __tquic_splice_read(sk, &tss);
		if (ret < 0)
			break;
		else if (!ret) {
			/* No data spliced */
			if (spliced)
				break;

			/* Check for EOF/stream closed */
			if (stream->fin_received)
				break;
			if (stream->state == TQUIC_STREAM_CLOSED ||
			    stream->state == TQUIC_STREAM_RESET_RECVD) {
				ret = -ECONNRESET;
				break;
			}

			/* Non-blocking mode */
			if (flags & SPLICE_F_NONBLOCK) {
				ret = -EAGAIN;
				break;
			}

			/* Wait for data with timeout */
			if (!timeo) {
				ret = -EAGAIN;
				break;
			}

			/* Check for pending signal */
			if (signal_pending(current)) {
				ret = sock_intr_errno(timeo);
				break;
			}

			/* Wait for more data */
			release_sock(sk);

			ret = wait_event_interruptible_timeout(
				stream->wait,
				!skb_queue_empty(&stream->recv_buf) ||
				stream->fin_received ||
				stream->state == TQUIC_STREAM_CLOSED,
				timeo);

			lock_sock(sk);

			if (ret < 0) {
				ret = sock_intr_errno(timeo);
				break;
			}
			if (ret == 0) {
				ret = -EAGAIN;
				break;
			}
			continue;
		}

		/* Data spliced successfully */
		tss.len -= ret;
		spliced += ret;
	}

	release_sock(sk);

	if (spliced > 0)
		return spliced;
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_splice_read);

/*
 * =============================================================================
 * Receive-Side Zero-Copy Optimization
 * =============================================================================
 */

/**
 * tquic_recvmsg_peek_size - Peek at available data size (MSG_TRUNC)
 * @sk: Socket
 * @stream: Stream to check
 *
 * Used with MSG_TRUNC to efficiently check how much data is available
 * without copying. Helps userspace allocate optimal buffer sizes.
 *
 * Returns: Number of bytes available in receive buffer
 */
size_t tquic_recvmsg_peek_size(struct sock *sk, struct tquic_stream *stream)
{
	struct sk_buff *skb;
	size_t total = 0;

	if (!stream)
		return 0;

	skb_queue_walk(&stream->recv_buf, skb) {
		total += skb->len;
	}

	return total;
}
EXPORT_SYMBOL_GPL(tquic_recvmsg_peek_size);

/**
 * tquic_rx_page_pool_alloc - Allocate page for direct receive placement
 * @conn: Connection
 *
 * Allocates a page from the receive page pool for direct DMA placement.
 * This avoids an extra copy when receiving data.
 *
 * Returns: Allocated page or NULL
 */
struct page *tquic_rx_page_pool_alloc(struct tquic_connection *conn)
{
	struct page *page;

	/*
	 * For high-performance receive, we would use a page pool here.
	 * For now, just allocate a regular page.
	 */
	page = alloc_page(GFP_ATOMIC | __GFP_COMP);
	if (!page)
		return NULL;

	return page;
}
EXPORT_SYMBOL_GPL(tquic_rx_page_pool_alloc);

/**
 * tquic_rx_build_skb_from_page - Build skb using pre-allocated page
 * @conn: Connection
 * @page: Pre-allocated page with data
 * @offset: Data offset in page
 * @len: Data length
 *
 * Creates an skb referencing the page directly (zero-copy).
 *
 * Returns: SKB on success, NULL on failure
 */
struct sk_buff *tquic_rx_build_skb_from_page(struct tquic_connection *conn,
					     struct page *page,
					     unsigned int offset,
					     unsigned int len)
{
	struct sk_buff *skb;

	if (!page || offset + len > PAGE_SIZE)
		return NULL;

	/* Allocate skb header only */
	skb = alloc_skb(0, GFP_ATOMIC);
	if (!skb)
		return NULL;

	/* Add page as fragment - zero copy */
	skb_fill_page_desc(skb, 0, page, offset, len);
	skb->len = len;
	skb->data_len = len;
	skb->truesize += len;

	/* Keep page reference (already held) */

	return skb;
}
EXPORT_SYMBOL_GPL(tquic_rx_build_skb_from_page);

/*
 * =============================================================================
 * Socket Option Support
 * =============================================================================
 */

/**
 * tquic_set_zerocopy - Handle SO_ZEROCOPY socket option
 * @sk: Socket
 * @val: Option value (0 = disable, 1 = enable)
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_set_zerocopy(struct sock *sk, int val)
{
	if (val < 0 || val > 1)
		return -EINVAL;

	if (val) {
		/*
		 * Enable zerocopy. Check if the socket supports it.
		 * Scatter-gather is preferred but not strictly required
		 * (we can fallback to copy with notification).
		 */
		sock_set_flag(sk, SOCK_ZEROCOPY);
		pr_debug("tquic: zerocopy enabled on socket\n");
	} else {
		sock_reset_flag(sk, SOCK_ZEROCOPY);
		pr_debug("tquic: zerocopy disabled on socket\n");
	}

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_set_zerocopy);

/**
 * tquic_get_zerocopy - Get SO_ZEROCOPY socket option value
 * @sk: Socket
 *
 * Returns: 1 if zerocopy enabled, 0 otherwise
 */
int tquic_get_zerocopy(struct sock *sk)
{
	return sock_flag(sk, SOCK_ZEROCOPY) ? 1 : 0;
}
EXPORT_SYMBOL_GPL(tquic_get_zerocopy);

/*
 * =============================================================================
 * Zerocopy Completion Notification
 * =============================================================================
 */

/**
 * tquic_zc_complete - Mark zerocopy buffer transmission as complete
 * @sk: Socket
 * @id: Notification ID
 *
 * Called when all packets containing zerocopy data have been transmitted.
 * Triggers notification to userspace via error queue.
 */
void tquic_zc_complete(struct sock *sk, u32 id)
{
	struct sk_buff *skb;
	struct sock_exterr_skb *serr;
	unsigned long flags;
	struct sk_buff_head *q;

	/* Build error queue notification skb */
	skb = alloc_skb(0, GFP_ATOMIC);
	if (!skb)
		return;

	skb->sk = sk;

	serr = SKB_EXT_ERR(skb);
	memset(serr, 0, sizeof(*serr));
	serr->ee.ee_errno = 0;
	serr->ee.ee_origin = SO_EE_ORIGIN_ZEROCOPY;
	serr->ee.ee_data = id;  /* High watermark */
	serr->ee.ee_info = id;  /* Low watermark */
	/* ee_code = 0 means zerocopy succeeded (no copy fallback) */

	/* Queue to socket error queue */
	q = &sk->sk_error_queue;
	spin_lock_irqsave(&q->lock, flags);
	__skb_queue_tail(q, skb);
	spin_unlock_irqrestore(&q->lock, flags);

	/* Wake up waiters on error queue */
	sk_error_report(sk);
}
EXPORT_SYMBOL_GPL(tquic_zc_complete);

/**
 * tquic_zc_abort - Abort zerocopy due to error
 * @sk: Socket
 * @id: Notification ID
 * @err: Error code
 *
 * Called when zerocopy transmission fails. Notifies userspace.
 */
void tquic_zc_abort(struct sock *sk, u32 id, int err)
{
	struct sk_buff *skb;
	struct sock_exterr_skb *serr;
	unsigned long flags;
	struct sk_buff_head *q;

	skb = alloc_skb(0, GFP_ATOMIC);
	if (!skb)
		return;

	skb->sk = sk;

	serr = SKB_EXT_ERR(skb);
	memset(serr, 0, sizeof(*serr));
	serr->ee.ee_errno = err;
	serr->ee.ee_origin = SO_EE_ORIGIN_ZEROCOPY;
	serr->ee.ee_data = id;
	serr->ee.ee_info = id;
	serr->ee.ee_code |= SO_EE_CODE_ZEROCOPY_COPIED;

	q = &sk->sk_error_queue;
	spin_lock_irqsave(&q->lock, flags);
	__skb_queue_tail(q, skb);
	spin_unlock_irqrestore(&q->lock, flags);

	sk_error_report(sk);
}
EXPORT_SYMBOL_GPL(tquic_zc_abort);

/*
 * =============================================================================
 * SKB Zerocopy Fragment Handling
 * =============================================================================
 */

/**
 * tquic_skb_zerocopy_setup - Setup skb for zerocopy transmission
 * @skb: SKB to configure
 * @page: Page to reference
 * @offset: Offset in page
 * @len: Length of data
 *
 * Configures an skb for zerocopy by adding page as fragment and
 * setting appropriate flags for completion notification.
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_skb_zerocopy_setup(struct sk_buff *skb, struct page *page,
			     unsigned int offset, unsigned int len)
{
	int i;

	if (!skb || !page)
		return -EINVAL;

	if (offset + len > PAGE_SIZE)
		return -EINVAL;

	/* Check if we can add more frags */
	i = skb_shinfo(skb)->nr_frags;
	if (i >= MAX_SKB_FRAGS)
		return -EMSGSIZE;

	/* Add page as fragment */
	get_page(page);
	skb_fill_page_desc(skb, i, page, offset, len);

	skb->len += len;
	skb->data_len += len;
	skb->truesize += PAGE_SIZE;

	/* Set zerocopy flag for completion callback */
	skb_shinfo(skb)->flags |= SKBFL_ZEROCOPY_FRAG;

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_skb_zerocopy_setup);

/**
 * tquic_skb_orphan_frags_rx - Handle page reference for received zerocopy skb
 * @skb: SKB to process
 * @gfp: Allocation flags
 *
 * Ensures page references are properly handled for received zerocopy skbs.
 * May need to copy data if pages cannot be safely shared.
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_skb_orphan_frags_rx(struct sk_buff *skb, gfp_t gfp)
{
	/*
	 * For received skbs with zerocopy pages, we may need to
	 * handle orphaning to avoid page lifetime issues.
	 *
	 * The kernel's skb_orphan_frags_rx() handles this.
	 */
	return skb_orphan_frags_rx(skb, gfp);
}
EXPORT_SYMBOL_GPL(tquic_skb_orphan_frags_rx);

/*
 * =============================================================================
 * Module Information
 * =============================================================================
 */

MODULE_DESCRIPTION("TQUIC Zero-Copy I/O Support");
MODULE_LICENSE("GPL");
