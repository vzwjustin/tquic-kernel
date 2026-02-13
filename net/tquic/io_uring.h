/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: io_uring Integration Declarations
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 */

#ifndef _TQUIC_IO_URING_H
#define _TQUIC_IO_URING_H

#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>
#include <linux/uio.h>
#include <linux/sockptr.h>
#include <uapi/linux/tquic.h>

struct io_kiocb;
struct io_uring_sqe;
struct tquic_connection;
struct tquic_sock;
struct sock;
struct msghdr;
struct io_uring_buf_ring;

/*
 * =============================================================================
 * Internal struct definitions for io_uring command data
 * =============================================================================
 */

/**
 * struct io_tquic_send - Send command data embedded in io_kiocb
 */
struct io_tquic_send {
	struct tquic_sock	*sk;
	u32			flags;
	u64			stream_id;
	int			done_io;
	struct iovec		*iov;
	unsigned int		iovcnt;
	struct {
		bool		enabled;
		u32		notif_seq;
	} zc;
};

/**
 * struct io_tquic_recv - Receive command data embedded in io_kiocb
 */
struct io_tquic_recv {
	struct tquic_sock	*sk;
	u32			flags;
	u64			stream_id;
	int			done_io;
	void			*addr;
	unsigned int		retry_count;
	struct iovec		*iov;
	unsigned int		iovcnt;
	bool			multishot;
};

/**
 * struct io_tquic_sendmsg - Sendmsg command data embedded in io_kiocb
 */
struct io_tquic_sendmsg {
	struct tquic_sock	*sk;
	u32			flags;
	u64			stream_id;
	struct msghdr		*msg;
};

/**
 * struct io_tquic_recvmsg - Recvmsg command data embedded in io_kiocb
 */
struct io_tquic_recvmsg {
	struct tquic_sock	*sk;
	u32			flags;
	u64			stream_id;
	struct msghdr		*msg;
	bool			multishot;
};

/**
 * struct tquic_io_buf_ring - Registered buffer ring for zero-copy I/O
 */
struct tquic_io_buf_ring {
	struct io_uring_buf_ring *br;
	void			*buf_base;
	size_t			buf_size;
	u32			buf_count;
	u32			mask;
	int			bgid;
	u32			head;
	u32			tail;
	spinlock_t		lock;
};

/**
 * struct tquic_uring_ctx - Per-connection io_uring context
 */
struct tquic_uring_ctx {
	struct tquic_io_buf_ring **buf_rings;
	int			nr_buf_rings;
	bool			sqpoll_enabled;
	unsigned int		cqe_batch_size;
	atomic_t		pending_cqes;
	atomic_t		cqe_overflow;
	struct tquic_uring_stats stats;
};

/*
 * =============================================================================
 * Function declarations
 * =============================================================================
 */

/* io_uring send operations */
int io_tquic_send_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
int io_tquic_send(struct io_kiocb *req, unsigned int issue_flags);

/* io_uring receive operations */
int io_tquic_recv_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
int io_tquic_recv(struct io_kiocb *req, unsigned int issue_flags);
int io_tquic_recv_multishot(struct io_kiocb *req, unsigned int issue_flags);

/* io_uring sendmsg/recvmsg */
int io_tquic_sendmsg_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
int io_tquic_sendmsg(struct io_kiocb *req, unsigned int issue_flags);
int io_tquic_recvmsg_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
int io_tquic_recvmsg(struct io_kiocb *req, unsigned int issue_flags);

/* io_uring zero-copy send */
int io_tquic_send_zc_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);
int io_tquic_send_zc(struct io_kiocb *req, unsigned int issue_flags);
void io_tquic_send_zc_cleanup(struct io_kiocb *req);

/* Buffer ring operations */
struct tquic_io_buf_ring *tquic_io_buf_ring_create(
	struct tquic_connection *conn, size_t buf_size,
	int buf_count, int bgid);
void tquic_io_buf_ring_destroy(struct tquic_io_buf_ring *br);
void *tquic_io_buf_ring_get(struct tquic_io_buf_ring *br, u16 *bid);
void tquic_io_buf_ring_put(struct tquic_io_buf_ring *br, u16 bid);
void tquic_io_buf_ring_advance(struct tquic_io_buf_ring *br,
			       unsigned int count);

/* Connection context management */
int tquic_uring_ctx_alloc(struct tquic_connection *conn);
void tquic_uring_ctx_free(struct tquic_connection *conn);
struct tquic_uring_ctx *tquic_uring_ctx_get(struct sock *sk);

/* SQ poll mode */
int tquic_uring_enable_sqpoll(struct tquic_connection *conn);
void tquic_uring_disable_sqpoll(struct tquic_connection *conn);
bool tquic_uring_sqpoll_enabled(struct tquic_connection *conn);
int tquic_uring_set_cqe_batch_size(struct tquic_connection *conn,
				   unsigned int batch_size);

/* Completion batching */
void tquic_uring_flush_cqes(struct tquic_connection *conn);
int tquic_uring_handle_overflow(struct tquic_connection *conn);

/* Statistics */
int tquic_uring_get_stats(struct tquic_connection *conn,
			  struct tquic_uring_stats *stats);

/* Socket options */
int tquic_uring_setsockopt(struct sock *sk, int optname,
			   sockptr_t optval, unsigned int optlen);
int tquic_uring_getsockopt(struct sock *sk, int optname,
			   char __user *optval, int __user *optlen);

/* Module init/exit */
int __init tquic_io_uring_init(void);
void tquic_io_uring_exit(void);

#endif /* _TQUIC_IO_URING_H */
