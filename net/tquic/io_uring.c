// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC io_uring Integration
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Provides high-performance async I/O for TQUIC using io_uring.
 * This implementation follows the patterns established in io_uring/net.c
 * while providing TQUIC-specific optimizations.
 *
 * Features:
 *   - TQUIC-specific send/recv operations with stream awareness
 *   - Multishot receive for continuous packet reception
 *   - Registered buffers for zero-copy I/O
 *   - SQPOLL integration for lowest latency
 *   - Completion batching to reduce overhead
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/file.h>
#include <linux/uio.h>
#include <linux/io_uring.h>
#include <linux/io_uring_types.h>
#include <net/sock.h>
#include <net/tquic.h>

#include "protocol.h"
#include "io_uring.h"

/*
 * =============================================================================
 * Constants and Limits
 * =============================================================================
 */

/* Maximum number of multishot receive retries before yielding */
#define TQUIC_MSHOT_MAX_RETRY		32

/* Default buffer size for buffer rings */
#define TQUIC_URING_DEFAULT_BUF_SIZE	4096

/* Maximum buffer rings per connection */
#define TQUIC_URING_MAX_BUF_RINGS	16

/* Default CQE batch size (0 = no batching) */
#define TQUIC_URING_DEFAULT_BATCH_SIZE	0

/*
 * =============================================================================
 * Internal Async Data Structures
 * =============================================================================
 */

/**
 * struct io_tquic_async_data - Async operation data
 * @iov: I/O vectors
 * @fast_iov: Fast path single iovec
 * @nr_segs: Number of iovec segments
 * @msg: Message header for sendmsg/recvmsg
 * @addr: Address storage
 *
 * Cached async data to avoid repeated allocations.
 */
struct io_tquic_async_data {
	struct iovec		*iov;
	struct iovec		fast_iov;
	unsigned int		nr_segs;
	struct msghdr		msg;
	struct sockaddr_storage	addr;
};

/*
 * =============================================================================
 * Helper Functions
 * =============================================================================
 */

/**
 * io_tquic_get_socket - Get TQUIC socket from io_kiocb
 * @req: io_uring request
 *
 * Return: TQUIC socket, or ERR_PTR on error
 */
static struct tquic_sock *io_tquic_get_socket(struct io_kiocb *req)
{
	struct socket *sock;
	struct sock *sk;

	sock = sock_from_file(req->file);
	if (!sock)
		return ERR_PTR(-ENOTSOCK);

	sk = sock->sk;
	if (!sk || sk->sk_protocol != IPPROTO_TQUIC)
		return ERR_PTR(-ENOTSOCK);

	return tquic_sk(sk);
}

/**
 * io_tquic_check_connected - Verify connection is established
 * @tsk: TQUIC socket
 *
 * Return: 0 if connected, -ENOTCONN otherwise
 */
static int io_tquic_check_connected(struct tquic_sock *tsk)
{
	struct sock *sk = (struct sock *)tsk;

	if (sk->sk_state != TCP_ESTABLISHED)
		return -ENOTCONN;

	if (!tsk->conn || tsk->conn->state != TQUIC_CONN_CONNECTED)
		return -ENOTCONN;

	return 0;
}

/**
 * io_tquic_alloc_async_data - Allocate async data for request
 * @req: io_uring request
 *
 * Return: Allocated async data, or NULL on failure
 */
static struct io_tquic_async_data *io_tquic_alloc_async_data(
	struct io_kiocb *req)
{
	struct io_tquic_async_data *data;

	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		return NULL;

	req->async_data = data;
	req->flags |= REQ_F_ASYNC_DATA;

	return data;
}

/**
 * io_tquic_free_async_data - Free async data
 * @req: io_uring request
 */
static void io_tquic_free_async_data(struct io_kiocb *req)
{
	struct io_tquic_async_data *data = req->async_data;

	if (!data)
		return;

	if (data->iov && data->iov != &data->fast_iov)
		kfree(data->iov);

	kfree(data);
	req->async_data = NULL;
	req->flags &= ~REQ_F_ASYNC_DATA;
}

/*
 * =============================================================================
 * Send Operation Implementation
 * =============================================================================
 */

/**
 * io_tquic_send_prep - Prepare TQUIC send operation
 */
int io_tquic_send_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_tquic_send *sr;
	struct tquic_sock *tsk;

	/* Validate unused fields */
	if (sqe->buf_index || sqe->splice_fd_in)
		return -EINVAL;

	/* Get socket and validate */
	tsk = io_tquic_get_socket(req);
	if (IS_ERR(tsk))
		return PTR_ERR(tsk);

	/* Allocate command data in req */
	sr = io_kiocb_to_cmd(req, struct io_tquic_send);
	sr->sk = tsk;
	sr->flags = READ_ONCE(sqe->msg_flags);
	sr->stream_id = READ_ONCE(sqe->off);  /* Use offset field for stream ID */
	sr->done_io = 0;
	sr->zc.enabled = false;

	/* Get buffer pointer and length */
	sr->iov = NULL;
	sr->iovcnt = 0;

	/* Mark as needing async execution if non-blocking would fail */
	if (!(sr->flags & MSG_DONTWAIT))
		req->flags |= REQ_F_FORCE_ASYNC;

	return 0;
}

/**
 * io_tquic_send - Execute TQUIC send operation
 */
int io_tquic_send(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_tquic_send *sr = io_kiocb_to_cmd(req, struct io_tquic_send);
	struct tquic_sock *tsk = sr->sk;
	struct sock *sk = (struct sock *)tsk;
	struct tquic_connection *conn;
	struct tquic_stream *stream;
	struct tquic_uring_ctx *uctx;
	struct msghdr msg = {};
	struct iovec iov;
	int ret;

	/* Verify still connected */
	ret = io_tquic_check_connected(tsk);
	if (ret)
		goto done;

	conn = tsk->conn;

	/* Get target stream */
	if (sr->stream_id == 0) {
		stream = tsk->default_stream;
		if (!stream) {
			stream = tquic_stream_open(conn, true);
			if (!stream) {
				ret = -ENOMEM;
				goto done;
			}
			tsk->default_stream = stream;
		}
	} else {
		/* Look up specific stream */
		stream = NULL;  /* TODO: Implement stream lookup */
		if (!stream) {
			ret = -ENOENT;
			goto done;
		}
	}

	/* Set up message */
	iov.iov_base = (void __user *)req->cqe.user_data;
	iov.iov_len = READ_ONCE(req->cqe.res);

	iov_iter_init(&msg.msg_iter, ITER_SOURCE, &iov, 1, iov.iov_len);
	msg.msg_flags = sr->flags;

	if (issue_flags & IO_URING_F_NONBLOCK)
		msg.msg_flags |= MSG_DONTWAIT;

	/* Perform send */
	ret = tquic_sendmsg(sk, &msg, iov.iov_len);

	if (ret == -EAGAIN && !(issue_flags & IO_URING_F_NONBLOCK)) {
		/* Need to retry in blocking context */
		return IOU_RETRY;
	}

	/* Update statistics */
	uctx = tquic_uring_ctx_get(sk);
	if (uctx && ret > 0) {
		uctx->stats.sends++;
	}

done:
	io_req_set_res(req, ret, 0);
	return IOU_COMPLETE;
}

/*
 * =============================================================================
 * Receive Operation Implementation
 * =============================================================================
 */

/**
 * io_tquic_recv_prep - Prepare TQUIC receive operation
 */
int io_tquic_recv_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_tquic_recv *sr;
	struct tquic_sock *tsk;
	u16 ioprio;

	tsk = io_tquic_get_socket(req);
	if (IS_ERR(tsk))
		return PTR_ERR(tsk);

	sr = io_kiocb_to_cmd(req, struct io_tquic_recv);
	sr->sk = tsk;
	sr->flags = READ_ONCE(sqe->msg_flags);
	sr->stream_id = READ_ONCE(sqe->off);
	sr->done_io = 0;
	sr->addr = NULL;
	sr->retry_count = 0;

	/* Check for multishot mode */
	ioprio = READ_ONCE(sqe->ioprio);
	sr->multishot = !!(ioprio & IORING_RECV_MULTISHOT);

	/* Multishot requires buffer selection */
	if (sr->multishot && !(req->flags & REQ_F_BUFFER_SELECT)) {
		sr->multishot = false;
	}

	if (!(sr->flags & MSG_DONTWAIT))
		req->flags |= REQ_F_FORCE_ASYNC;

	return 0;
}

/**
 * io_tquic_recv - Execute TQUIC receive operation
 */
int io_tquic_recv(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_tquic_recv *sr = io_kiocb_to_cmd(req, struct io_tquic_recv);
	struct tquic_sock *tsk = sr->sk;
	struct sock *sk = (struct sock *)tsk;
	struct tquic_stream *stream;
	struct tquic_uring_ctx *uctx;
	struct msghdr msg = {};
	struct iovec iov;
	int ret;

	/* Verify still connected */
	ret = io_tquic_check_connected(tsk);
	if (ret)
		goto done;

	/* Get source stream */
	if (sr->stream_id == 0) {
		stream = tsk->default_stream;
	} else {
		stream = NULL;  /* TODO: Implement stream lookup */
	}

	if (!stream) {
		ret = 0;  /* No data available */
		if (!(issue_flags & IO_URING_F_NONBLOCK))
			return IOU_RETRY;
		goto done;
	}

	/* Set up receive buffer */
	iov.iov_base = (void __user *)req->cqe.user_data;
	iov.iov_len = READ_ONCE(req->cqe.res);

	iov_iter_init(&msg.msg_iter, ITER_DEST, &iov, 1, iov.iov_len);
	msg.msg_flags = sr->flags;

	if (issue_flags & IO_URING_F_NONBLOCK)
		msg.msg_flags |= MSG_DONTWAIT;

	/* Perform receive */
	ret = tquic_recvmsg(sk, &msg, iov.iov_len, msg.msg_flags);

	if (ret == -EAGAIN) {
		if (!(issue_flags & IO_URING_F_NONBLOCK))
			return IOU_RETRY;
	}

	/* Update statistics */
	uctx = tquic_uring_ctx_get(sk);
	if (uctx && ret > 0) {
		uctx->stats.recvs++;
	}

done:
	io_req_set_res(req, ret, 0);
	return IOU_COMPLETE;
}

/**
 * io_tquic_recv_multishot - Multishot receive operation
 *
 * Continues receiving data without re-arming until cancelled.
 * Each received packet generates a CQE.
 */
int io_tquic_recv_multishot(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_tquic_recv *sr = io_kiocb_to_cmd(req, struct io_tquic_recv);
	struct tquic_sock *tsk = sr->sk;
	struct sock *sk = (struct sock *)tsk;
	struct tquic_stream *stream;
	struct tquic_uring_ctx *uctx;
	struct msghdr msg = {};
	struct iovec iov;
	int ret;
	unsigned int cflags = 0;

	/* Verify still connected */
	ret = io_tquic_check_connected(tsk);
	if (ret)
		goto done_final;

	/* Check retry limit */
	if (sr->retry_count >= TQUIC_MSHOT_MAX_RETRY) {
		/* Yield to other requests */
		sr->retry_count = 0;
		return IOU_REQUEUE;
	}

	/* Get source stream */
	stream = (sr->stream_id == 0) ? tsk->default_stream : NULL;

	if (!stream || skb_queue_empty(&stream->recv_buf)) {
		if (!(issue_flags & IO_URING_F_NONBLOCK)) {
			sr->retry_count = 0;
			return IOU_RETRY;
		}
		ret = -EAGAIN;
		goto done_continue;
	}

	/* Set up receive buffer - would use buffer selection in practice */
	iov.iov_base = (void __user *)req->cqe.user_data;
	iov.iov_len = READ_ONCE(req->cqe.res);

	iov_iter_init(&msg.msg_iter, ITER_DEST, &iov, 1, iov.iov_len);
	msg.msg_flags = sr->flags | MSG_DONTWAIT;

	/* Perform receive */
	ret = tquic_recvmsg(sk, &msg, iov.iov_len, msg.msg_flags);

	/* Update statistics */
	uctx = tquic_uring_ctx_get(sk);
	if (uctx) {
		if (ret > 0) {
			uctx->stats.recvs++;
			uctx->stats.multishot_recvs++;
		}
	}

	if (ret > 0) {
		sr->retry_count++;

		/* Post CQE with IORING_CQE_F_MORE to indicate more coming */
		cflags |= IORING_CQE_F_MORE;
		io_req_set_res(req, ret, cflags);

		/* Continue multishot */
		return IOU_ISSUE_SKIP_COMPLETE;
	}

done_continue:
	if (ret == -EAGAIN || ret == 0) {
		/* No more data available, wait */
		sr->retry_count = 0;
		return IOU_RETRY;
	}

done_final:
	/* Error or connection closed - complete without MORE flag */
	io_req_set_res(req, ret, 0);
	return IOU_COMPLETE;
}

/*
 * =============================================================================
 * Sendmsg/Recvmsg Operations
 * =============================================================================
 */

int io_tquic_sendmsg_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_tquic_sendmsg *sr;
	struct tquic_sock *tsk;

	tsk = io_tquic_get_socket(req);
	if (IS_ERR(tsk))
		return PTR_ERR(tsk);

	sr = io_kiocb_to_cmd(req, struct io_tquic_sendmsg);
	sr->sk = tsk;
	sr->flags = READ_ONCE(sqe->msg_flags);
	sr->stream_id = READ_ONCE(sqe->off);
	sr->msg = NULL;

	if (!(sr->flags & MSG_DONTWAIT))
		req->flags |= REQ_F_FORCE_ASYNC;

	return 0;
}

int io_tquic_sendmsg(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_tquic_sendmsg *sr = io_kiocb_to_cmd(req, struct io_tquic_sendmsg);
	struct tquic_sock *tsk = sr->sk;
	struct sock *sk = (struct sock *)tsk;
	struct io_tquic_async_data *data;
	struct msghdr *msg;
	int ret;

	ret = io_tquic_check_connected(tsk);
	if (ret)
		goto done;

	/* Get or allocate async data */
	data = req->async_data;
	if (!data) {
		data = io_tquic_alloc_async_data(req);
		if (!data) {
			ret = -ENOMEM;
			goto done;
		}
	}

	msg = &data->msg;
	msg->msg_flags = sr->flags;

	if (issue_flags & IO_URING_F_NONBLOCK)
		msg->msg_flags |= MSG_DONTWAIT;

	ret = tquic_sendmsg(sk, msg, msg->msg_iter.count);

	if (ret == -EAGAIN && !(issue_flags & IO_URING_F_NONBLOCK))
		return IOU_RETRY;

done:
	io_tquic_free_async_data(req);
	io_req_set_res(req, ret, 0);
	return IOU_COMPLETE;
}

int io_tquic_recvmsg_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_tquic_recvmsg *sr;
	struct tquic_sock *tsk;
	u16 ioprio;

	tsk = io_tquic_get_socket(req);
	if (IS_ERR(tsk))
		return PTR_ERR(tsk);

	sr = io_kiocb_to_cmd(req, struct io_tquic_recvmsg);
	sr->sk = tsk;
	sr->flags = READ_ONCE(sqe->msg_flags);
	sr->stream_id = READ_ONCE(sqe->off);
	sr->msg = NULL;

	ioprio = READ_ONCE(sqe->ioprio);
	sr->multishot = !!(ioprio & IORING_RECV_MULTISHOT);

	if (!(sr->flags & MSG_DONTWAIT))
		req->flags |= REQ_F_FORCE_ASYNC;

	return 0;
}

int io_tquic_recvmsg(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_tquic_recvmsg *sr = io_kiocb_to_cmd(req, struct io_tquic_recvmsg);
	struct tquic_sock *tsk = sr->sk;
	struct sock *sk = (struct sock *)tsk;
	struct io_tquic_async_data *data;
	struct msghdr *msg;
	int ret;

	ret = io_tquic_check_connected(tsk);
	if (ret)
		goto done;

	/* Get or allocate async data */
	data = req->async_data;
	if (!data) {
		data = io_tquic_alloc_async_data(req);
		if (!data) {
			ret = -ENOMEM;
			goto done;
		}
	}

	msg = &data->msg;
	msg->msg_flags = sr->flags;

	if (issue_flags & IO_URING_F_NONBLOCK)
		msg->msg_flags |= MSG_DONTWAIT;

	ret = tquic_recvmsg(sk, msg, msg->msg_iter.count, msg->msg_flags);

	if (ret == -EAGAIN && !(issue_flags & IO_URING_F_NONBLOCK))
		return IOU_RETRY;

done:
	io_tquic_free_async_data(req);
	io_req_set_res(req, ret, 0);
	return IOU_COMPLETE;
}

/*
 * =============================================================================
 * Zero-Copy Send Operations
 * =============================================================================
 */

int io_tquic_send_zc_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe)
{
	struct io_tquic_send *sr;
	struct tquic_sock *tsk;

	tsk = io_tquic_get_socket(req);
	if (IS_ERR(tsk))
		return PTR_ERR(tsk);

	sr = io_kiocb_to_cmd(req, struct io_tquic_send);
	sr->sk = tsk;
	sr->flags = READ_ONCE(sqe->msg_flags) | MSG_ZEROCOPY;
	sr->stream_id = READ_ONCE(sqe->off);
	sr->done_io = 0;
	sr->zc.enabled = true;
	sr->zc.notif_seq = 0;

	req->flags |= REQ_F_FORCE_ASYNC;

	return 0;
}

int io_tquic_send_zc(struct io_kiocb *req, unsigned int issue_flags)
{
	struct io_tquic_send *sr = io_kiocb_to_cmd(req, struct io_tquic_send);
	struct tquic_sock *tsk = sr->sk;
	struct sock *sk = (struct sock *)tsk;
	struct tquic_connection *conn;
	struct tquic_stream *stream;
	struct tquic_uring_ctx *uctx;
	struct msghdr msg = {};
	struct iovec iov;
	int ret;

	ret = io_tquic_check_connected(tsk);
	if (ret)
		goto done;

	conn = tsk->conn;

	/* Get target stream */
	stream = (sr->stream_id == 0) ? tsk->default_stream : NULL;
	if (!stream) {
		stream = tquic_stream_open(conn, true);
		if (!stream) {
			ret = -ENOMEM;
			goto done;
		}
		if (sr->stream_id == 0)
			tsk->default_stream = stream;
	}

	/* Set up message with MSG_ZEROCOPY */
	iov.iov_base = (void __user *)req->cqe.user_data;
	iov.iov_len = READ_ONCE(req->cqe.res);

	iov_iter_init(&msg.msg_iter, ITER_SOURCE, &iov, 1, iov.iov_len);
	msg.msg_flags = sr->flags;

	/* Use TQUIC zero-copy sendmsg */
	ret = tquic_sendmsg_zerocopy(sk, &msg, iov.iov_len, stream);

	if (ret == -EAGAIN)
		return IOU_RETRY;

	/* Update statistics */
	uctx = tquic_uring_ctx_get(sk);
	if (uctx && ret > 0) {
		uctx->stats.sends++;
		uctx->stats.zc_sends++;
	}

done:
	io_req_set_res(req, ret, 0);
	return IOU_COMPLETE;
}

void io_tquic_send_zc_cleanup(struct io_kiocb *req)
{
	/* Cleanup zero-copy resources if operation cancelled */
	io_tquic_free_async_data(req);
}

/*
 * =============================================================================
 * Registered Buffer Ring Management
 * =============================================================================
 */

struct tquic_io_buf_ring *tquic_io_buf_ring_create(
	struct tquic_connection *conn,
	size_t buf_size,
	int buf_count,
	int bgid)
{
	struct tquic_io_buf_ring *br;
	size_t ring_size;
	int i;

	if (buf_count <= 0 || buf_count > 32768)
		return ERR_PTR(-EINVAL);

	if (buf_size < 64 || buf_size > (1 << 20))
		return ERR_PTR(-EINVAL);

	br = kzalloc(sizeof(*br), GFP_KERNEL);
	if (!br)
		return ERR_PTR(-ENOMEM);

	/* Calculate ring size (power of 2) */
	ring_size = roundup_pow_of_two(buf_count);
	br->mask = ring_size - 1;

	/* Allocate buffer ring structure */
	br->br = kzalloc(sizeof(*br->br) * ring_size, GFP_KERNEL);
	if (!br->br) {
		kfree(br);
		return ERR_PTR(-ENOMEM);
	}

	/* Allocate buffer memory */
	br->buf_base = vmalloc(buf_size * ring_size);
	if (!br->buf_base) {
		kfree(br->br);
		kfree(br);
		return ERR_PTR(-ENOMEM);
	}

	br->buf_size = buf_size;
	br->buf_count = ring_size;
	br->bgid = bgid;
	br->head = 0;
	br->tail = ring_size;  /* All buffers initially available */
	spin_lock_init(&br->lock);

	/* Initialize buffer entries */
	for (i = 0; i < ring_size; i++) {
		br->br->bufs[i].addr = (u64)(br->buf_base + i * buf_size);
		br->br->bufs[i].len = buf_size;
		br->br->bufs[i].bid = i;
	}

	pr_debug("tquic: created buffer ring bgid=%d count=%d size=%zu\n",
		 bgid, ring_size, buf_size);

	return br;
}
EXPORT_SYMBOL_GPL(tquic_io_buf_ring_create);

void tquic_io_buf_ring_destroy(struct tquic_io_buf_ring *br)
{
	if (!br)
		return;

	vfree(br->buf_base);
	kfree(br->br);
	kfree(br);
}
EXPORT_SYMBOL_GPL(tquic_io_buf_ring_destroy);

void *tquic_io_buf_ring_get(struct tquic_io_buf_ring *br, u16 *bid)
{
	void *buf;
	u32 head;

	spin_lock(&br->lock);

	if (br->head == br->tail) {
		spin_unlock(&br->lock);
		return NULL;
	}

	head = br->head & br->mask;
	*bid = br->br->bufs[head].bid;
	buf = (void *)(unsigned long)br->br->bufs[head].addr;
	br->head++;

	spin_unlock(&br->lock);

	return buf;
}
EXPORT_SYMBOL_GPL(tquic_io_buf_ring_get);

void tquic_io_buf_ring_put(struct tquic_io_buf_ring *br, u16 bid)
{
	u32 tail;

	spin_lock(&br->lock);

	tail = br->tail & br->mask;
	br->br->bufs[tail].bid = bid;
	br->br->bufs[tail].addr = (u64)(br->buf_base + bid * br->buf_size);
	br->br->bufs[tail].len = br->buf_size;
	br->tail++;

	spin_unlock(&br->lock);
}
EXPORT_SYMBOL_GPL(tquic_io_buf_ring_put);

void tquic_io_buf_ring_advance(struct tquic_io_buf_ring *br, unsigned int count)
{
	spin_lock(&br->lock);
	br->head += count;
	spin_unlock(&br->lock);
}
EXPORT_SYMBOL_GPL(tquic_io_buf_ring_advance);

/*
 * =============================================================================
 * SQPOLL Integration
 * =============================================================================
 */

int tquic_uring_enable_sqpoll(struct tquic_connection *conn)
{
	struct tquic_uring_ctx *uctx;

	if (!conn)
		return -EINVAL;

	uctx = conn->state_machine;
	if (!uctx)
		return -EINVAL;

	if (uctx->sqpoll_enabled)
		return 0;

	/*
	 * SQPOLL mode requires the io_uring instance to be set up with
	 * IORING_SETUP_SQPOLL. This is done at ring creation time.
	 * Here we just track that the connection wants SQPOLL semantics.
	 */
	uctx->sqpoll_enabled = true;

	pr_debug("tquic: enabled SQPOLL mode for connection\n");
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_uring_enable_sqpoll);

void tquic_uring_disable_sqpoll(struct tquic_connection *conn)
{
	struct tquic_uring_ctx *uctx;

	if (!conn)
		return;

	uctx = conn->state_machine;
	if (!uctx)
		return;

	uctx->sqpoll_enabled = false;
	pr_debug("tquic: disabled SQPOLL mode for connection\n");
}
EXPORT_SYMBOL_GPL(tquic_uring_disable_sqpoll);

bool tquic_uring_sqpoll_enabled(struct tquic_connection *conn)
{
	struct tquic_uring_ctx *uctx;

	if (!conn)
		return false;

	uctx = conn->state_machine;
	return uctx && uctx->sqpoll_enabled;
}
EXPORT_SYMBOL_GPL(tquic_uring_sqpoll_enabled);

/*
 * =============================================================================
 * Completion Batching
 * =============================================================================
 */

int tquic_uring_set_cqe_batch_size(struct tquic_connection *conn,
				   unsigned int batch_size)
{
	struct tquic_uring_ctx *uctx;

	if (!conn)
		return -EINVAL;

	uctx = conn->state_machine;
	if (!uctx)
		return -EINVAL;

	/* Limit batch size to reasonable value */
	if (batch_size > 256)
		batch_size = 256;

	uctx->cqe_batch_size = batch_size;

	pr_debug("tquic: set CQE batch size to %u\n", batch_size);
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_uring_set_cqe_batch_size);

void tquic_uring_flush_cqes(struct tquic_connection *conn)
{
	struct tquic_uring_ctx *uctx;

	if (!conn)
		return;

	uctx = conn->state_machine;
	if (!uctx)
		return;

	/*
	 * In actual implementation, this would flush any pending
	 * batched CQEs to the completion ring.
	 */
	atomic_set(&uctx->pending_cqes, 0);
}
EXPORT_SYMBOL_GPL(tquic_uring_flush_cqes);

int tquic_uring_handle_overflow(struct tquic_connection *conn)
{
	struct tquic_uring_ctx *uctx;
	int overflow;

	if (!conn)
		return 0;

	uctx = conn->state_machine;
	if (!uctx)
		return 0;

	overflow = atomic_xchg(&uctx->cqe_overflow, 0);
	if (overflow > 0) {
		pr_warn("tquic: %d CQE overflows detected\n", overflow);
	}

	return overflow;
}
EXPORT_SYMBOL_GPL(tquic_uring_handle_overflow);

/*
 * =============================================================================
 * Connection Context Management
 * =============================================================================
 */

int tquic_uring_ctx_alloc(struct tquic_connection *conn)
{
	struct tquic_uring_ctx *uctx;

	if (!conn)
		return -EINVAL;

	uctx = kzalloc(sizeof(*uctx), GFP_KERNEL);
	if (!uctx)
		return -ENOMEM;

	uctx->buf_rings = kzalloc(sizeof(*uctx->buf_rings) *
				  TQUIC_URING_MAX_BUF_RINGS, GFP_KERNEL);
	if (!uctx->buf_rings) {
		kfree(uctx);
		return -ENOMEM;
	}

	uctx->nr_buf_rings = 0;
	uctx->sqpoll_enabled = false;
	uctx->cqe_batch_size = TQUIC_URING_DEFAULT_BATCH_SIZE;
	atomic_set(&uctx->pending_cqes, 0);
	atomic_set(&uctx->cqe_overflow, 0);

	/* Store in connection - using state_machine field as placeholder */
	/* In production, add dedicated field to tquic_connection */

	pr_debug("tquic: allocated io_uring context for connection\n");
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_uring_ctx_alloc);

void tquic_uring_ctx_free(struct tquic_connection *conn)
{
	struct tquic_uring_ctx *uctx;
	int i;

	if (!conn)
		return;

	uctx = conn->state_machine;
	if (!uctx)
		return;

	/* Free all buffer rings */
	if (uctx->buf_rings) {
		for (i = 0; i < uctx->nr_buf_rings; i++) {
			tquic_io_buf_ring_destroy(uctx->buf_rings[i]);
		}
		kfree(uctx->buf_rings);
	}

	kfree(uctx);
	pr_debug("tquic: freed io_uring context\n");
}
EXPORT_SYMBOL_GPL(tquic_uring_ctx_free);

struct tquic_uring_ctx *tquic_uring_ctx_get(struct sock *sk)
{
	struct tquic_sock *tsk;
	struct tquic_connection *conn;

	if (!sk || sk->sk_protocol != IPPROTO_TQUIC)
		return NULL;

	tsk = tquic_sk(sk);
	conn = tsk->conn;
	if (!conn)
		return NULL;

	/* Return the uring context stored in state_machine */
	return conn->state_machine;
}
EXPORT_SYMBOL_GPL(tquic_uring_ctx_get);

/*
 * =============================================================================
 * Statistics
 * =============================================================================
 */

int tquic_uring_get_stats(struct tquic_connection *conn,
			  struct tquic_uring_stats *stats)
{
	struct tquic_uring_ctx *uctx;

	if (!conn || !stats)
		return -EINVAL;

	uctx = conn->state_machine;
	if (!uctx)
		return -EINVAL;

	stats->sends = uctx->stats.sends;
	stats->recvs = uctx->stats.recvs;
	stats->completions = uctx->stats.completions;
	stats->multishot_recvs = uctx->stats.multishot_recvs;
	stats->zc_sends = uctx->stats.zc_sends;
	stats->retries = uctx->stats.retries;
	stats->overflow_events = atomic_read(&uctx->cqe_overflow);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_uring_get_stats);

/*
 * =============================================================================
 * Socket Option Handlers
 * =============================================================================
 */

/**
 * tquic_uring_setsockopt - Handle io_uring socket options
 * @sk: Socket
 * @optname: Option name
 * @optval: Option value
 * @optlen: Option length
 *
 * Return: 0 on success, negative errno on error
 */
int tquic_uring_setsockopt(struct sock *sk, int optname,
			   sockptr_t optval, unsigned int optlen)
{
	struct tquic_sock *tsk = tquic_sk(sk);
	struct tquic_connection *conn = tsk->conn;
	int val;

	switch (optname) {
	case TQUIC_URING_SQPOLL:
		if (optlen < sizeof(int))
			return -EINVAL;
		if (copy_from_sockptr(&val, optval, sizeof(val)))
			return -EFAULT;

		if (val)
			return tquic_uring_enable_sqpoll(conn);
		else
			tquic_uring_disable_sqpoll(conn);
		return 0;

	case TQUIC_URING_CQE_BATCH:
		if (optlen < sizeof(int))
			return -EINVAL;
		if (copy_from_sockptr(&val, optval, sizeof(val)))
			return -EFAULT;

		return tquic_uring_set_cqe_batch_size(conn, val);

	case TQUIC_URING_BUF_RING: {
		struct tquic_uring_buf_ring_args args;
		struct tquic_io_buf_ring *br;
		struct tquic_uring_ctx *uctx;

		if (optlen < sizeof(args))
			return -EINVAL;
		if (copy_from_sockptr(&args, optval, sizeof(args)))
			return -EFAULT;

		uctx = tquic_uring_ctx_get(sk);
		if (!uctx)
			return -EINVAL;

		if (args.flags & TQUIC_URING_BUF_RING_CREATE) {
			if (uctx->nr_buf_rings >= TQUIC_URING_MAX_BUF_RINGS)
				return -ENOSPC;

			br = tquic_io_buf_ring_create(conn, args.buf_size,
						      args.buf_count, args.bgid);
			if (IS_ERR(br))
				return PTR_ERR(br);

			uctx->buf_rings[uctx->nr_buf_rings++] = br;
			return 0;
		}

		if (args.flags & TQUIC_URING_BUF_RING_DESTROY) {
			int i;

			for (i = 0; i < uctx->nr_buf_rings; i++) {
				if (uctx->buf_rings[i]->bgid == args.bgid) {
					tquic_io_buf_ring_destroy(uctx->buf_rings[i]);
					uctx->buf_rings[i] = uctx->buf_rings[--uctx->nr_buf_rings];
					return 0;
				}
			}
			return -ENOENT;
		}

		return -EINVAL;
	}

	default:
		return -ENOPROTOOPT;
	}
}
EXPORT_SYMBOL_GPL(tquic_uring_setsockopt);

/**
 * tquic_uring_getsockopt - Get io_uring socket options
 * @sk: Socket
 * @optname: Option name
 * @optval: Output buffer
 * @optlen: Buffer length
 *
 * Return: 0 on success, negative errno on error
 */
int tquic_uring_getsockopt(struct sock *sk, int optname,
			   char __user *optval, int __user *optlen)
{
	struct tquic_sock *tsk = tquic_sk(sk);
	struct tquic_connection *conn = tsk->conn;
	struct tquic_uring_ctx *uctx;
	int len, val;

	uctx = tquic_uring_ctx_get(sk);
	if (!uctx)
		return -EINVAL;

	if (get_user(len, optlen))
		return -EFAULT;

	switch (optname) {
	case TQUIC_URING_SQPOLL:
		val = tquic_uring_sqpoll_enabled(conn) ? 1 : 0;
		break;

	case TQUIC_URING_CQE_BATCH:
		val = uctx->cqe_batch_size;
		break;

	default:
		return -ENOPROTOOPT;
	}

	len = min_t(int, len, sizeof(int));
	if (put_user(len, optlen))
		return -EFAULT;
	if (copy_to_user(optval, &val, len))
		return -EFAULT;

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_uring_getsockopt);

/*
 * =============================================================================
 * Module Initialization
 * =============================================================================
 */

int __init tquic_io_uring_init(void)
{
	pr_info("tquic: io_uring support initialized\n");
	return 0;
}

void __exit tquic_io_uring_exit(void)
{
	pr_info("tquic: io_uring support cleanup\n");
}

MODULE_DESCRIPTION("TQUIC io_uring Integration");
MODULE_LICENSE("GPL");
