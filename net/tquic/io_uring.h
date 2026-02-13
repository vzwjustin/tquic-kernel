/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: io_uring Integration Declarations
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 */

#ifndef _TQUIC_IO_URING_H
#define _TQUIC_IO_URING_H

struct io_kiocb;
struct io_uring_sqe;
struct tquic_connection;
struct tquic_io_buf_ring;

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
void tquic_io_buf_ring_destroy(struct tquic_io_buf_ring *br);
void *tquic_io_buf_ring_get(struct tquic_io_buf_ring *br, u16 *bid);
void tquic_io_buf_ring_put(struct tquic_io_buf_ring *br, u16 bid);
void tquic_io_buf_ring_advance(struct tquic_io_buf_ring *br,
			       unsigned int count);

/* SQ poll mode */
int tquic_uring_enable_sqpoll(struct tquic_connection *conn);
void tquic_uring_disable_sqpoll(struct tquic_connection *conn);
bool tquic_uring_sqpoll_enabled(struct tquic_connection *conn);
int tquic_uring_set_cqe_batch_size(struct tquic_connection *conn,
				   unsigned int batch_size);

#endif /* _TQUIC_IO_URING_H */
