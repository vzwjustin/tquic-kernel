/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC io_uring Integration
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Provides high-performance async I/O for TQUIC using io_uring.
 * Features:
 *   - TQUIC-specific send/recv operations
 *   - Multishot receive for continuous packet reception
 *   - Registered buffers for zero-copy I/O
 *   - SQPOLL integration for lowest latency
 *   - Completion batching
 */

#ifndef _NET_TQUIC_IO_URING_H
#define _NET_TQUIC_IO_URING_H

#include <linux/types.h>
#include <linux/socket.h>
#include <linux/io_uring_types.h>
#include <net/tquic.h>

#ifdef CONFIG_TQUIC_IO_URING

struct io_kiocb;
struct io_uring_sqe;
struct tquic_sock;
struct tquic_connection;
struct tquic_stream;

/*
 * =============================================================================
 * TQUIC io_uring Operation Structures
 * =============================================================================
 */

/**
 * struct io_tquic_send - TQUIC send operation context
 * @sk: TQUIC socket
 * @iov: I/O vectors for data
 * @iovcnt: Number of I/O vectors
 * @flags: Send flags (MSG_DONTWAIT, MSG_ZEROCOPY, etc.)
 * @stream_id: Target stream ID (0 for default stream)
 * @done_io: Bytes sent so far (for partial completions)
 * @zc: Zero-copy state
 *
 * Used for IORING_OP_TQUIC_SEND operations.
 */
struct io_tquic_send {
	struct tquic_sock	*sk;
	struct iovec		*iov;
	int			iovcnt;
	int			flags;
	u64			stream_id;
	unsigned int		done_io;
	struct {
		bool		enabled;
		u32		notif_seq;
	} zc;
};

/**
 * struct io_tquic_recv - TQUIC receive operation context
 * @sk: TQUIC socket
 * @iov: I/O vectors for receive buffer
 * @iovcnt: Number of I/O vectors
 * @flags: Receive flags
 * @addr: Optional remote address storage
 * @stream_id: Source stream ID (0 for any stream)
 * @done_io: Bytes received so far
 * @multishot: Multishot mode enabled
 * @retry_count: Number of multishot retries
 *
 * Used for IORING_OP_TQUIC_RECV operations.
 */
struct io_tquic_recv {
	struct tquic_sock	*sk;
	struct iovec		*iov;
	int			iovcnt;
	int			flags;
	struct sockaddr_storage	*addr;
	u64			stream_id;
	unsigned int		done_io;
	bool			multishot;
	unsigned int		retry_count;
};

/**
 * struct io_tquic_sendmsg - TQUIC sendmsg operation context
 * @sk: TQUIC socket
 * @msg: Message header
 * @flags: Send flags
 * @stream_id: Target stream ID
 *
 * Used for IORING_OP_TQUIC_SENDMSG operations.
 */
struct io_tquic_sendmsg {
	struct tquic_sock	*sk;
	struct msghdr		*msg;
	int			flags;
	u64			stream_id;
};

/**
 * struct io_tquic_recvmsg - TQUIC recvmsg operation context
 * @sk: TQUIC socket
 * @msg: Message header
 * @flags: Receive flags
 * @stream_id: Source stream ID filter
 * @multishot: Multishot mode enabled
 *
 * Used for IORING_OP_TQUIC_RECVMSG operations.
 */
struct io_tquic_recvmsg {
	struct tquic_sock	*sk;
	struct msghdr		*msg;
	int			flags;
	u64			stream_id;
	bool			multishot;
};

/*
 * =============================================================================
 * Registered Buffer Pool
 * =============================================================================
 */

/**
 * struct tquic_io_buf_ring - Pre-registered buffer pool for zero-copy
 * @br: io_uring buffer ring
 * @buf_base: Base address of buffer memory
 * @buf_size: Size of each buffer
 * @buf_count: Number of buffers in the ring
 * @bgid: Buffer group ID for io_uring
 * @mask: Ring index mask
 * @head: Current head position (consumed by kernel)
 * @tail: Current tail position (produced by userspace)
 * @lock: Spinlock for concurrent access
 *
 * Provides pre-registered buffers for zero-copy receive operations.
 * Buffers are registered with io_uring and can be selected during
 * receive operations to avoid allocation overhead.
 */
struct tquic_io_buf_ring {
	struct io_uring_buf_ring	*br;
	void				*buf_base;
	size_t				buf_size;
	int				buf_count;
	int				bgid;
	u32				mask;
	u32				head;
	u32				tail;
	spinlock_t			lock;
};

/**
 * struct tquic_uring_ctx - Per-connection io_uring context
 * @buf_rings: Array of buffer rings for this connection
 * @nr_buf_rings: Number of buffer rings
 * @sqpoll_enabled: SQPOLL mode enabled
 * @cqe_batch_size: Completion batching threshold
 * @pending_cqes: Count of pending completions
 * @cqe_overflow: Count of overflow events
 * @stats: io_uring statistics for this connection
 *
 * Maintains io_uring-specific state per TQUIC connection.
 */
struct tquic_uring_ctx {
	struct tquic_io_buf_ring	**buf_rings;
	int				nr_buf_rings;
	bool				sqpoll_enabled;
	unsigned int			cqe_batch_size;
	atomic_t			pending_cqes;
	atomic_t			cqe_overflow;
	struct {
		u64			sends;
		u64			recvs;
		u64			completions;
		u64			multishot_recvs;
		u64			zc_sends;
		u64			retries;
	} stats;
};

/*
 * =============================================================================
 * io_uring Operation Handlers
 * =============================================================================
 */

/**
 * io_tquic_send_prep - Prepare TQUIC send operation
 * @req: io_uring request
 * @sqe: Submission queue entry
 *
 * Validates and prepares a TQUIC send operation from the SQE.
 *
 * Return: 0 on success, negative errno on error
 */
int io_tquic_send_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/**
 * io_tquic_send - Execute TQUIC send operation
 * @req: io_uring request
 * @issue_flags: Operation flags (IO_URING_F_*)
 *
 * Performs the actual send operation on a TQUIC socket.
 *
 * Return: IOU_COMPLETE on completion, IOU_RETRY if needs retry
 */
int io_tquic_send(struct io_kiocb *req, unsigned int issue_flags);

/**
 * io_tquic_recv_prep - Prepare TQUIC receive operation
 * @req: io_uring request
 * @sqe: Submission queue entry
 *
 * Validates and prepares a TQUIC receive operation from the SQE.
 *
 * Return: 0 on success, negative errno on error
 */
int io_tquic_recv_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/**
 * io_tquic_recv - Execute TQUIC receive operation
 * @req: io_uring request
 * @issue_flags: Operation flags
 *
 * Performs receive operation on a TQUIC socket.
 *
 * Return: IOU_COMPLETE on completion, IOU_RETRY if needs retry
 */
int io_tquic_recv(struct io_kiocb *req, unsigned int issue_flags);

/**
 * io_tquic_recv_multishot - Multishot receive operation
 * @req: io_uring request
 * @issue_flags: Operation flags
 *
 * Performs continuous receive operations without re-arming.
 * Each received packet generates a CQE, and the operation
 * continues until explicitly cancelled.
 *
 * Return: IOU_COMPLETE on final completion, IOU_RETRY to continue
 */
int io_tquic_recv_multishot(struct io_kiocb *req, unsigned int issue_flags);

/**
 * io_tquic_sendmsg_prep - Prepare TQUIC sendmsg operation
 * @req: io_uring request
 * @sqe: Submission queue entry
 *
 * Return: 0 on success, negative errno on error
 */
int io_tquic_sendmsg_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/**
 * io_tquic_sendmsg - Execute TQUIC sendmsg operation
 * @req: io_uring request
 * @issue_flags: Operation flags
 *
 * Return: IOU_COMPLETE on completion, IOU_RETRY if needs retry
 */
int io_tquic_sendmsg(struct io_kiocb *req, unsigned int issue_flags);

/**
 * io_tquic_recvmsg_prep - Prepare TQUIC recvmsg operation
 * @req: io_uring request
 * @sqe: Submission queue entry
 *
 * Return: 0 on success, negative errno on error
 */
int io_tquic_recvmsg_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/**
 * io_tquic_recvmsg - Execute TQUIC recvmsg operation
 * @req: io_uring request
 * @issue_flags: Operation flags
 *
 * Return: IOU_COMPLETE on completion, IOU_RETRY if needs retry
 */
int io_tquic_recvmsg(struct io_kiocb *req, unsigned int issue_flags);

/*
 * =============================================================================
 * Zero-Copy Send Support
 * =============================================================================
 */

/**
 * io_tquic_send_zc_prep - Prepare zero-copy send operation
 * @req: io_uring request
 * @sqe: Submission queue entry
 *
 * Return: 0 on success, negative errno on error
 */
int io_tquic_send_zc_prep(struct io_kiocb *req, const struct io_uring_sqe *sqe);

/**
 * io_tquic_send_zc - Execute zero-copy send operation
 * @req: io_uring request
 * @issue_flags: Operation flags
 *
 * Performs zero-copy send using registered buffers or user pages.
 * Completion notification is delivered via a separate CQE with
 * IORING_CQE_F_NOTIF flag.
 *
 * Return: IOU_COMPLETE on completion, IOU_RETRY if needs retry
 */
int io_tquic_send_zc(struct io_kiocb *req, unsigned int issue_flags);

/**
 * io_tquic_send_zc_cleanup - Cleanup zero-copy send resources
 * @req: io_uring request
 *
 * Called when a zero-copy send operation fails or is cancelled.
 */
void io_tquic_send_zc_cleanup(struct io_kiocb *req);

/*
 * =============================================================================
 * Registered Buffer Management
 * =============================================================================
 */

/**
 * tquic_io_buf_ring_create - Create a registered buffer ring
 * @conn: TQUIC connection
 * @buf_size: Size of each buffer
 * @buf_count: Number of buffers
 * @bgid: Buffer group ID
 *
 * Allocates and registers a buffer ring with io_uring for
 * zero-copy receive operations.
 *
 * Return: Buffer ring on success, ERR_PTR on error
 */
struct tquic_io_buf_ring *tquic_io_buf_ring_create(
	struct tquic_connection *conn,
	size_t buf_size,
	int buf_count,
	int bgid);

/**
 * tquic_io_buf_ring_destroy - Destroy a registered buffer ring
 * @br: Buffer ring to destroy
 *
 * Unregisters and frees the buffer ring and all associated buffers.
 */
void tquic_io_buf_ring_destroy(struct tquic_io_buf_ring *br);

/**
 * tquic_io_buf_ring_get - Get a buffer from the ring
 * @br: Buffer ring
 * @bid: Output buffer ID
 *
 * Returns the next available buffer from the ring.
 *
 * Return: Buffer address on success, NULL if ring empty
 */
void *tquic_io_buf_ring_get(struct tquic_io_buf_ring *br, u16 *bid);

/**
 * tquic_io_buf_ring_put - Return a buffer to the ring
 * @br: Buffer ring
 * @bid: Buffer ID to return
 *
 * Makes a buffer available for reuse after processing.
 */
void tquic_io_buf_ring_put(struct tquic_io_buf_ring *br, u16 bid);

/**
 * tquic_io_buf_ring_advance - Advance ring head
 * @br: Buffer ring
 * @count: Number of buffers to advance
 *
 * Called after consuming buffers to update the ring head.
 */
void tquic_io_buf_ring_advance(struct tquic_io_buf_ring *br, unsigned int count);

/*
 * =============================================================================
 * SQPOLL Integration
 * =============================================================================
 */

/**
 * tquic_uring_enable_sqpoll - Enable SQPOLL mode for connection
 * @conn: TQUIC connection
 *
 * Enables kernel-side submission queue polling for lowest latency.
 * When enabled, a kernel thread polls the SQ, eliminating the need
 * for system calls to submit I/O.
 *
 * Return: 0 on success, negative errno on error
 */
int tquic_uring_enable_sqpoll(struct tquic_connection *conn);

/**
 * tquic_uring_disable_sqpoll - Disable SQPOLL mode
 * @conn: TQUIC connection
 *
 * Disables kernel-side polling, returning to normal syscall submission.
 */
void tquic_uring_disable_sqpoll(struct tquic_connection *conn);

/**
 * tquic_uring_sqpoll_enabled - Check if SQPOLL is enabled
 * @conn: TQUIC connection
 *
 * Return: true if SQPOLL mode is active
 */
bool tquic_uring_sqpoll_enabled(struct tquic_connection *conn);

/*
 * =============================================================================
 * Completion Batching
 * =============================================================================
 */

/**
 * tquic_uring_set_cqe_batch_size - Set completion batching threshold
 * @conn: TQUIC connection
 * @batch_size: Number of completions to batch (0 = disable)
 *
 * When batching is enabled, completions are accumulated until
 * the threshold is reached, reducing completion overhead.
 *
 * Return: 0 on success, negative errno on error
 */
int tquic_uring_set_cqe_batch_size(struct tquic_connection *conn,
				   unsigned int batch_size);

/**
 * tquic_uring_flush_cqes - Force flush pending completions
 * @conn: TQUIC connection
 *
 * Flushes any batched completions to the CQ immediately.
 */
void tquic_uring_flush_cqes(struct tquic_connection *conn);

/**
 * tquic_uring_handle_overflow - Handle CQE overflow
 * @conn: TQUIC connection
 *
 * Called when the CQ overflows. Handles overflow recovery
 * and notifies userspace of dropped completions.
 *
 * Return: Number of overflowed CQEs
 */
int tquic_uring_handle_overflow(struct tquic_connection *conn);

/*
 * =============================================================================
 * Connection Context Management
 * =============================================================================
 */

/**
 * tquic_uring_ctx_alloc - Allocate io_uring context for connection
 * @conn: TQUIC connection
 *
 * Creates and initializes the io_uring context for a connection.
 *
 * Return: 0 on success, negative errno on error
 */
int tquic_uring_ctx_alloc(struct tquic_connection *conn);

/**
 * tquic_uring_ctx_free - Free io_uring context
 * @conn: TQUIC connection
 *
 * Releases all io_uring resources for the connection.
 */
void tquic_uring_ctx_free(struct tquic_connection *conn);

/**
 * tquic_uring_ctx_get - Get io_uring context from socket
 * @sk: Socket
 *
 * Return: io_uring context, or NULL if not initialized
 */
struct tquic_uring_ctx *tquic_uring_ctx_get(struct sock *sk);

/*
 * =============================================================================
 * Socket Option Support
 * =============================================================================
 */

/* TQUIC io_uring socket option */
#define TQUIC_URING_SQPOLL	200	/* Enable/disable SQPOLL mode */
#define TQUIC_URING_CQE_BATCH	201	/* Set CQE batching threshold */
#define TQUIC_URING_BUF_RING	202	/* Configure buffer ring */

/**
 * struct tquic_uring_buf_ring_args - Buffer ring configuration
 * @bgid: Buffer group ID
 * @buf_size: Size of each buffer
 * @buf_count: Number of buffers
 * @flags: Configuration flags
 */
struct tquic_uring_buf_ring_args {
	__u16	bgid;
	__u16	flags;
	__u32	buf_size;
	__u32	buf_count;
	__u32	reserved;
};

/* Buffer ring flags */
#define TQUIC_URING_BUF_RING_CREATE	(1 << 0)	/* Create new ring */
#define TQUIC_URING_BUF_RING_DESTROY	(1 << 1)	/* Destroy existing ring */

/*
 * =============================================================================
 * Statistics and Debugging
 * =============================================================================
 */

/**
 * struct tquic_uring_stats - io_uring statistics
 * @sends: Total send operations
 * @recvs: Total receive operations
 * @completions: Total completions
 * @multishot_recvs: Multishot receive operations
 * @zc_sends: Zero-copy send operations
 * @retries: Operation retries
 * @overflow_events: CQE overflow events
 */
struct tquic_uring_stats {
	__u64	sends;
	__u64	recvs;
	__u64	completions;
	__u64	multishot_recvs;
	__u64	zc_sends;
	__u64	retries;
	__u64	overflow_events;
};

/**
 * tquic_uring_get_stats - Get io_uring statistics
 * @conn: TQUIC connection
 * @stats: Output statistics structure
 *
 * Return: 0 on success, negative errno on error
 */
int tquic_uring_get_stats(struct tquic_connection *conn,
			  struct tquic_uring_stats *stats);

/*
 * =============================================================================
 * Module Init/Exit
 * =============================================================================
 */

/**
 * tquic_io_uring_init - Initialize io_uring support
 *
 * Called during TQUIC module initialization.
 *
 * Return: 0 on success, negative errno on error
 */
int __init tquic_io_uring_init(void);

/**
 * tquic_io_uring_exit - Cleanup io_uring support
 *
 * Called during TQUIC module unload.
 */
void __exit tquic_io_uring_exit(void);

#endif /* CONFIG_TQUIC_IO_URING */

#endif /* _NET_TQUIC_IO_URING_H */
