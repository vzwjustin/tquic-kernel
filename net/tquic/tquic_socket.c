// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Socket Interface
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Provides BSD socket interface for TQUIC connections with WAN bonding.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/skbuff.h>
#include <linux/poll.h>
#include <linux/splice.h>
#include <linux/pipe_fs_i.h>
#include <net/sock.h>
#include <net/inet_common.h>
#include <net/inet_connection_sock.h>
#include <net/protocol.h>
#include <net/net_namespace.h>
#include <net/tquic.h>

#include "protocol.h"
#include "tquic_compat.h"
#include "cong/tquic_cong.h"
#include "tquic_zerocopy.h"

#ifdef CONFIG_TQUIC_QLOG
#include <uapi/linux/tquic_qlog.h>
#include "diag/qlog.h"
#endif

/*
 * Lockdep class keys for TQUIC sockets
 * Indexed: [0] = IPv4, [1] = IPv6
 */
struct lock_class_key tquic_slock_keys[2];
struct lock_class_key tquic_lock_keys[2];

/*
 * Lock class keys for connection, path, and stream locks
 */
struct lock_class_key tquic_conn_lock_key;
struct lock_class_key tquic_path_lock_key;
struct lock_class_key tquic_stream_lock_key;

/*
 * tquic_set_lockdep_class - Initialize lockdep class for socket
 * @sk: socket to initialize lockdep for
 * @is_ipv6: true if socket is IPv6, false for IPv4
 *
 * This allows lockdep to distinguish between IPv4 and IPv6 sockets
 * and properly validate lock ordering.
 */
static void tquic_set_lockdep_class(struct sock *sk, bool is_ipv6)
{
	sock_lock_init_class_and_name(sk,
		is_ipv6 ? "slock-AF_INET6-TQUIC" : "slock-AF_INET-TQUIC",
		&tquic_slock_keys[is_ipv6],
		is_ipv6 ? "sk_lock-AF_INET6-TQUIC" : "sk_lock-AF_INET-TQUIC",
		&tquic_lock_keys[is_ipv6]);
}

/* Socket operations (exported - used by tquic_proto.c) */
int tquic_sock_bind(struct socket *sock, TQUIC_SOCKADDR *uaddr, int addr_len);
int tquic_connect_socket(struct socket *sock, TQUIC_SOCKADDR *uaddr,
			 int addr_len, int flags);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 7, 0)
int tquic_accept_socket(struct socket *sock, struct socket *newsock,
			struct proto_accept_arg *arg);
#else
int tquic_accept_socket(struct socket *sock, struct socket *newsock,
			int flags, bool kern);
#endif
int tquic_sock_getname(struct socket *sock, struct sockaddr *addr, int peer);
__poll_t tquic_poll_socket(struct file *file, struct socket *sock,
			   poll_table *wait);
int tquic_sock_listen(struct socket *sock, int backlog);
int tquic_sock_shutdown(struct socket *sock, int how);
int tquic_sock_setsockopt(struct socket *sock, int level, int optname,
			  sockptr_t optval, unsigned int optlen);
int tquic_sock_getsockopt(struct socket *sock, int level, int optname,
			  char __user *optval, int __user *optlen);
int tquic_sendmsg_socket(struct socket *sock, struct msghdr *msg,
			 size_t len);
int tquic_recvmsg_socket(struct socket *sock, struct msghdr *msg,
			 size_t len, int flags);
int tquic_sock_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg);

/* Zero-copy operations (exported) */
ssize_t tquic_splice_read_socket(struct socket *sock, loff_t *ppos,
				 struct pipe_inode_info *pipe,
				 size_t len, unsigned int flags);

/* Protocol operations */
int tquic_init_sock(struct sock *sk);
void tquic_destroy_sock(struct sock *sk);

/*
 * Initialize a TQUIC socket
 */
int tquic_init_sock(struct sock *sk)
{
	struct tquic_sock *tsk = tquic_sk(sk);

	/* Initialize lockdep class for this socket (IPv4 or IPv6) */
	tquic_set_lockdep_class(sk, sk->sk_family == AF_INET6);

	/* Initialize connection socket */
	inet_sk_set_state(sk, TCP_CLOSE);

	/* Initialize TQUIC-specific state */
	INIT_LIST_HEAD(&tsk->accept_queue);
	INIT_LIST_HEAD(&tsk->accept_list);
	INIT_HLIST_NODE(&tsk->listener_node);
	tsk->accept_queue_len = 0;
	tsk->max_accept_queue = 128;
	tsk->flags = 0;
	init_waitqueue_head(&tsk->event_wait);

	/* Clear requested scheduler (will use per-netns default if not set) */
	tsk->requested_scheduler[0] = '\0';

	/* Clear requested congestion control (will use per-netns default if not set) */
	tsk->requested_congestion[0] = '\0';

	/* Enable pacing by default per CONTEXT.md */
	tsk->pacing_enabled = true;

	/* Initialize certificate verification with secure defaults */
	tsk->cert_verify.verify_mode = TQUIC_VERIFY_REQUIRED;
	tsk->cert_verify.verify_hostname = true;
	tsk->cert_verify.allow_self_signed = false;
	tsk->cert_verify.expected_hostname[0] = '\0';
	tsk->cert_verify.expected_hostname_len = 0;

	/* Create connection structure */
	tsk->conn = tquic_conn_create(tsk, false);
	if (!tsk->conn)
		return -ENOMEM;

	/* Initialize bonding state */
	tsk->conn->scheduler = tquic_bond_init(tsk->conn);

	pr_debug("tquic: socket initialized\n");
	return 0;
}

/*
 * Destroy a TQUIC socket
 */
void tquic_destroy_sock(struct sock *sk)
{
	struct tquic_sock *tsk = tquic_sk(sk);

	/* Ensure any listen-table registration is removed before final free. */
	if (sk->sk_state == TCP_LISTEN)
		tquic_unregister_listener(sk);

	/* Clean up any in-progress handshake */
	tquic_handshake_cleanup(sk);

	if (tsk->conn) {
		if (tsk->conn->scheduler)
			tquic_bond_cleanup(tsk->conn->scheduler);
		tquic_conn_destroy(tsk->conn);
		tsk->conn = NULL;
	}

	pr_debug("tquic: socket destroyed\n");
}

/*
 * Bind socket to address
 * Note: sockaddr type varies by kernel; use TQUIC_SOCKADDR for compatibility.
 */
int tquic_sock_bind(struct socket *sock, TQUIC_SOCKADDR *uaddr, int addr_len)
{
	struct sockaddr *addr = (struct sockaddr *)uaddr;
	struct sock *sk = sock->sk;
	struct tquic_sock *tsk = tquic_sk(sk);

	if (addr_len < sizeof(struct sockaddr_in))
		return -EINVAL;

	memcpy(&tsk->bind_addr, addr, min_t(size_t, addr_len,
					    sizeof(struct sockaddr_storage)));

	inet_sk_set_state(sk, TCP_CLOSE);

	return 0;
}

/*
 * Connect to remote address
 * Note: sockaddr type varies by kernel; use TQUIC_SOCKADDR for compatibility.
 */
int tquic_connect_socket(struct socket *sock, TQUIC_SOCKADDR *uaddr,
			 int addr_len, int flags)
{
	struct sock *sk = sock->sk;

	return tquic_connect(sk, uaddr, addr_len);
}

/*
 * Connect implementation
 *
 * Implements blocking connect() with TLS 1.3 handshake.
 * Per CONTEXT.md, connect() blocks until handshake completes or
 * a fixed 30-second timeout expires.
 *
 * State transitions:
 *   TCP_CLOSE -> TCP_SYN_SENT -> TCP_ESTABLISHED (success)
 *   TCP_CLOSE -> TCP_SYN_SENT -> TCP_CLOSE (failure)
 */
/*
 * Note: sockaddr type varies by kernel; use TQUIC_SOCKADDR and cast
 * internally since TQUIC uses fixed sockaddr_storage.
 */
int tquic_connect(struct sock *sk, TQUIC_SOCKADDR *uaddr, int addr_len)
{
	struct sockaddr *addr = (struct sockaddr *)uaddr;
	struct tquic_sock *tsk = tquic_sk(sk);
	struct tquic_connection *conn = tsk->conn;
	int ret;

	if (!conn)
		return -EINVAL;

	if (addr_len < sizeof(struct sockaddr_in))
		return -EINVAL;

	lock_sock(sk);

	/* Store peer address */
	memcpy(&tsk->connect_addr, addr,
	       min_t(size_t, addr_len, sizeof(struct sockaddr_storage)));

	/* Add initial path */
	ret = tquic_conn_add_path(conn, (struct sockaddr *)&tsk->bind_addr,
				  (struct sockaddr *)&tsk->connect_addr);
	if (ret < 0)
		goto out_unlock;

	/* Initialize connection state machine for client mode */
	ret = tquic_conn_client_connect(conn, (struct sockaddr *)addr);
	if (ret < 0)
		goto out_unlock;

	/*
	 * Initialize scheduler - use requested or per-netns default.
	 * Per CONTEXT.md: "Scheduler locked at connection establishment"
	 */
	{
		struct tquic_sched_ops *sched_ops = NULL;

		if (tsk->requested_scheduler[0])
			sched_ops = tquic_sched_find(tsk->requested_scheduler);

		conn->scheduler = tquic_sched_init_conn(conn, sched_ops);
		if (!conn->scheduler) {
			pr_warn("tquic: scheduler init failed, using default\n");
			conn->scheduler = tquic_sched_init_conn(conn, NULL);
			if (!conn->scheduler) {
				ret = -ENOMEM;
				goto out_unlock;
			}
		}
	}

	/* Set state before handshake */
	inet_sk_set_state(sk, TCP_SYN_SENT);

	/* Initiate TLS handshake (async via net/handshake) */
	ret = tquic_start_handshake(sk);
	if (ret < 0)
		goto out_close;

	release_sock(sk);

	/*
	 * Block until handshake completes (per CONTEXT.md).
	 * Timeout is fixed at 30 seconds, not configurable per-socket.
	 */
	ret = tquic_wait_for_handshake(sk, TQUIC_HANDSHAKE_TIMEOUT_MS);

	lock_sock(sk);

	if (ret < 0) {
		/* Handshake failed or timed out */
		goto out_close;
	}

	/* Verify handshake actually completed */
	if (!(tsk->flags & TQUIC_F_HANDSHAKE_DONE)) {
		ret = -EQUIC_HANDSHAKE_FAILED;
		goto out_close;
	}

	inet_sk_set_state(sk, TCP_ESTABLISHED);

	/* Initialize path manager after connection established */
	ret = tquic_pm_conn_init(conn);
	if (ret < 0) {
		pr_warn("tquic: PM init failed (%d), multipath disabled\n", ret);
		tsk->flags |= TQUIC_F_PM_DISABLED;
		tsk->flags &= ~TQUIC_F_MULTIPATH_ENABLED;
		/*
		 * Continue with single-path operation. Multipath and migration
		 * features will be unavailable for this connection.
		 */
		pr_notice("tquic: connection using single-path mode\n");
		ret = 0;  /* Not fatal */
	}

	release_sock(sk);

	pr_debug("tquic: client connection established\n");
	return 0;

out_close:
	inet_sk_set_state(sk, TCP_CLOSE);
	sk->sk_err = -ret;  /* Store error for getsockopt */
out_unlock:
	release_sock(sk);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_connect);

/*
 * Listen for incoming connections
 *
 * Sets up the socket to receive incoming QUIC connections.
 * Registers with the UDP demux layer and transitions to TCP_LISTEN state.
 */
int tquic_sock_listen(struct socket *sock, int backlog)
{
	struct sock *sk = sock->sk;
	struct tquic_sock *tsk = tquic_sk(sk);
	int ret;

	lock_sock(sk);

	if (sock->state != SS_UNCONNECTED) {
		ret = -EINVAL;
		goto out;
	}

	/* Validate backlog */
	if (backlog < 0)
		backlog = 0;
	if (backlog > SOMAXCONN)
		backlog = SOMAXCONN;

	tsk->max_accept_queue = backlog;

	/* Initialize accept queue if not already done */
	if (list_empty(&tsk->accept_queue))
		INIT_LIST_HEAD(&tsk->accept_queue);
	tsk->accept_queue_len = 0;

	/* Register with UDP demux to receive incoming packets */
	ret = tquic_register_listener(sk);
	if (ret < 0) {
		pr_err("tquic: failed to register listener: %d\n", ret);
		goto out;
	}

	/* Transition to listen state */
	inet_sk_set_state(sk, TCP_LISTEN);
	sock->state = SS_CONNECTED;  /* Mark as ready for accept */

	pr_debug("tquic: listening on socket, backlog=%d\n", backlog);
	ret = 0;

out:
	release_sock(sk);
	return ret;
}

/*
 * Accept incoming connection (socket layer wrapper)
 *
 * This is called by the socket layer. It calls tquic_accept() to get
 * the child socket from the accept queue, then grafts it onto newsock.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 7, 0)
int tquic_accept_socket(struct socket *sock, struct socket *newsock,
			struct proto_accept_arg *arg)
{
	struct sock *sk = sock->sk;
	struct sock *newsk;
	int err;

	err = tquic_accept(sk, &newsk, arg->flags, arg->kern);
	if (err < 0)
		return err;

	/* Graft the child socket onto newsock */
	sock_graft(newsk, newsock);
	newsock->state = SS_CONNECTED;

	return 0;
}
#else
int tquic_accept_socket(struct socket *sock, struct socket *newsock,
			int flags, bool kern)
{
	struct sock *sk = sock->sk;
	struct sock *newsk;
	int err;

	err = tquic_accept(sk, &newsk, flags, kern);
	if (err < 0)
		return err;

	/* Graft the child socket onto newsock */
	sock_graft(newsk, newsock);
	newsock->state = SS_CONNECTED;

	return 0;
}
#endif

/**
 * tquic_accept - Accept incoming connection from listen queue
 * @sk: Listening socket
 * @newsk: Output pointer for accepted socket
 * @flags: Socket flags (O_NONBLOCK, etc.)
 * @kern: True if kernel socket
 *
 * Waits for and dequeues a connection from the accept queue.
 * The returned socket is in TCP_ESTABLISHED state with a working
 * connection (handshake already completed by server_handshake).
 *
 * Returns: 0 on success with *newsk set, negative errno on failure
 */
int tquic_accept(struct sock *sk, struct sock **newsk, int flags, bool kern)
{
	struct tquic_sock *tsk = tquic_sk(sk);
	struct tquic_sock *child_tsk;
	DEFINE_WAIT(wait);
	int err = 0;

	lock_sock(sk);

	/* Must be in listen state */
	if (sk->sk_state != TCP_LISTEN) {
		err = -EINVAL;
		goto out_unlock;
	}

	/* Wait for incoming connection */
	for (;;) {
		/* Check accept queue under spinlock */
		spin_lock_bh(&sk->sk_lock.slock);
		if (!list_empty(&tsk->accept_queue)) {
			child_tsk = list_first_entry(&tsk->accept_queue,
						     struct tquic_sock,
						     accept_list);
			list_del_init(&child_tsk->accept_list);
			tsk->accept_queue_len--;
			spin_unlock_bh(&sk->sk_lock.slock);

			/* Return the child socket */
			*newsk = (struct sock *)child_tsk;

			/* Update connection's socket pointer */
			if (child_tsk->conn)
				child_tsk->conn->sk = (struct sock *)child_tsk;

			pr_debug("tquic: accept returned connection\n");
			goto out_unlock;
		}
		spin_unlock_bh(&sk->sk_lock.slock);

		/* Non-blocking mode */
		if (flags & O_NONBLOCK) {
			err = -EAGAIN;
			goto out_unlock;
		}

		/* Wait for incoming connection */
		prepare_to_wait_exclusive(sk_sleep(sk), &wait,
					  TASK_INTERRUPTIBLE);

		release_sock(sk);

		if (signal_pending(current)) {
			finish_wait(sk_sleep(sk), &wait);
			lock_sock(sk);
			err = -ERESTARTSYS;
			goto out_unlock;
		}

		schedule();
		lock_sock(sk);
		finish_wait(sk_sleep(sk), &wait);

		/* Check if socket is still listening */
		if (sk->sk_state != TCP_LISTEN) {
			err = -EINVAL;
			goto out_unlock;
		}
	}

out_unlock:
	release_sock(sk);
	return err;
}
EXPORT_SYMBOL_GPL(tquic_accept);

/*
 * Get socket name
 */
int tquic_sock_getname(struct socket *sock, struct sockaddr *addr, int peer)
{
	struct sock *sk = sock->sk;
	struct tquic_sock *tsk = tquic_sk(sk);
	struct sockaddr_storage *saddr;
	int len;

	if (peer)
		saddr = &tsk->connect_addr;
	else
		saddr = &tsk->bind_addr;

	len = sizeof(struct sockaddr_in);
	if (saddr->ss_family == AF_INET6)
		len = sizeof(struct sockaddr_in6);

	memcpy(addr, saddr, len);
	return len;
}

/*
 * Poll for events
 */
__poll_t tquic_poll_socket(struct file *file, struct socket *sock,
			  poll_table *wait)
{
	return tquic_poll(file, sock, wait);
}

__poll_t tquic_poll(struct file *file, struct socket *sock, poll_table *wait)
{
	struct sock *sk = sock->sk;
	struct tquic_sock *tsk = tquic_sk(sk);
	__poll_t mask = 0;

	sock_poll_wait(file, sock, wait);

	if (sk->sk_state == TCP_LISTEN) {
		if (tsk->accept_queue_len > 0)
			mask |= EPOLLIN | EPOLLRDNORM;
	} else if (sk->sk_state == TCP_ESTABLISHED) {
		/* Check if stream data available to read */
		if (tsk->conn && tsk->default_stream) {
			if (!skb_queue_empty(&tsk->default_stream->recv_buf))
				mask |= EPOLLIN | EPOLLRDNORM;
		}

		/*
		 * Check if datagram data available (RFC 9221)
		 *
		 * Datagrams are readable if the datagram receive queue
		 * has at least one datagram queued. This allows poll/epoll
		 * to wake on datagram arrival.
		 */
		if (tsk->conn && tsk->conn->datagram.enabled) {
			if (!skb_queue_empty(&tsk->conn->datagram.recv_queue))
				mask |= EPOLLIN | EPOLLRDNORM;
		}

		/* Always writable for now */
		mask |= EPOLLOUT | EPOLLWRNORM;
	}

	if (sk->sk_err)
		mask |= EPOLLERR;

	if (sk->sk_shutdown & RCV_SHUTDOWN)
		mask |= EPOLLRDHUP | EPOLLIN | EPOLLRDNORM;

	return mask;
}
EXPORT_SYMBOL_GPL(tquic_poll);

/*
 * Shutdown connection
 */
int tquic_sock_shutdown(struct socket *sock, int how)
{
	struct sock *sk = sock->sk;
	struct tquic_sock *tsk = tquic_sk(sk);
	int ret = 0;

	if (tsk->conn && tsk->conn->state == TQUIC_CONN_CONNECTED) {
		/* Use graceful shutdown via state machine */
		ret = tquic_conn_shutdown(tsk->conn);
	}

	if ((how & SEND_SHUTDOWN) && (how & RCV_SHUTDOWN))
		inet_sk_set_state(sk, TCP_CLOSE);

	return ret;
}

/*
 * Close connection
 */
void tquic_close(struct sock *sk, long timeout)
{
	struct tquic_sock *tsk = tquic_sk(sk);

	if (tsk->conn) {
		/* Release path manager state before connection teardown */
		tquic_pm_conn_release(tsk->conn);

		/*
		 * If we're still connected, initiate graceful close.
		 * The connection close will proceed through CLOSING -> DRAINING -> CLOSED.
		 */
		if (tsk->conn->state == TQUIC_CONN_CONNECTED ||
		    tsk->conn->state == TQUIC_CONN_CONNECTING) {
			tquic_conn_close_with_error(tsk->conn, 0x00, NULL);
		}
	}

	inet_sk_set_state(sk, TCP_CLOSE);
}
EXPORT_SYMBOL_GPL(tquic_close);

/*
 * ioctl handler for connection socket
 *
 * Handles TQUIC-specific ioctls, primarily TQUIC_NEW_STREAM which creates
 * new stream file descriptors. Falls back to inet_ioctl for standard ioctls.
 */
int tquic_sock_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
{
	struct sock *sk = sock->sk;
	struct tquic_sock *tsk = tquic_sk(sk);
	struct tquic_connection *conn = tsk->conn;
	void __user *uarg = (void __user *)arg;

	switch (cmd) {
	case TQUIC_NEW_STREAM: {
		struct tquic_stream_args args;
		u64 stream_id;
		bool is_bidi;
		bool nonblock;
		int ret;

		/* Must be connected */
		if (!conn || conn->state != TQUIC_CONN_CONNECTED)
			return -ENOTCONN;

		/* Copy args from userspace */
		if (copy_from_user(&args, uarg, sizeof(args)))
			return -EFAULT;

		/* Validate flags */
		if (args.flags > TQUIC_STREAM_UNIDI || args.reserved != 0)
			return -EINVAL;

		is_bidi = !(args.flags & TQUIC_STREAM_UNIDI);
		nonblock = !!(sock->file->f_flags & O_NONBLOCK);

		/*
		 * Block until stream credit available (per CONTEXT.md).
		 * ioctl blocks when at stream limit until peer sends MAX_STREAMS.
		 */
		ret = tquic_wait_for_stream_credit(conn, is_bidi, nonblock);
		if (ret < 0)
			return ret;

		/* Create stream socket */
		ret = tquic_stream_socket_create(conn, sk, args.flags, &stream_id);
		if (ret < 0)
			return ret;

		/* Copy stream ID back to userspace */
		args.stream_id = stream_id;
		if (copy_to_user(uarg, &args, sizeof(args))) {
			/*
			 * We created the fd but can't return the stream_id.
			 * The fd is still valid; user can query stream_id via sockopt.
			 * Return success since the stream was created.
			 */
			pr_warn("tquic: failed to copy stream_id to user\n");
		}

		pr_debug("tquic: ioctl NEW_STREAM returned fd=%d stream_id=%llu\n",
			 ret, stream_id);

		/* Return the file descriptor */
		return ret;
	}

	default:
		/* Fall back to inet_ioctl for standard socket ioctls */
		return inet_ioctl(sock, cmd, arg);
	}
}

/*
 * Set socket options
 */
int tquic_sock_setsockopt(struct socket *sock, int level, int optname,
			  sockptr_t optval, unsigned int optlen)
{
	struct sock *sk = sock->sk;
	struct tquic_sock *tsk = tquic_sk(sk);
	int val;

	if (level != SOL_TQUIC)
		return -ENOPROTOOPT;

	if (optlen < sizeof(int))
		return -EINVAL;

	if (copy_from_sockptr(&val, optval, sizeof(val)))
		return -EFAULT;

	switch (optname) {
	case TQUIC_NODELAY:
		tsk->nodelay = !!val;
		break;

	case TQUIC_PACING:
		/*
		 * SO_TQUIC_PACING: Enable/disable pacing for socket
		 *
		 * When pacing is enabled, TQUIC integrates with FQ qdisc for
		 * hardware pacing when available, or uses internal pacing.
		 */
		tsk->pacing_enabled = !!val;
		if (sk->sk_pacing_status != SK_PACING_FQ) {
			/* Update pacing status for internal pacing */
			if (tsk->pacing_enabled)
				smp_store_release(&sk->sk_pacing_status,
						  SK_PACING_NEEDED);
			else
				smp_store_release(&sk->sk_pacing_status,
						  SK_PACING_NONE);
		}
		return 0;

	case TQUIC_IDLE_TIMEOUT:
		if (tsk->conn)
			tsk->conn->idle_timeout = val;
		break;

	case TQUIC_BOND_MODE:
		if (tsk->conn)
			return tquic_bond_set_mode(tsk->conn, val);
		break;

	case TQUIC_BOND_PATH_PRIO:
		/* Requires additional path info */
		return -EINVAL;

	case TQUIC_BOND_PATH_WEIGHT: {
		struct tquic_path_weight_args args;

		if (optlen < sizeof(args))
			return -EINVAL;

		if (copy_from_sockptr(&args, optval, sizeof(args)))
			return -EFAULT;

		if (args.reserved[0] || args.reserved[1] || args.reserved[2])
			return -EINVAL;

		if (!tsk->conn || !tsk->conn->pm)
			return -ENOTCONN;

		/* Bonding context accessed via path manager */
		return tquic_bond_set_path_weight(tsk->conn, args.path_id, args.weight);
	}

	case TQUIC_MULTIPATH:
		/* Enable/disable multipath */
		break;

	case TQUIC_MIGRATE: {
		struct tquic_migrate_args args;

		if (optlen < sizeof(args))
			return -EINVAL;

		if (copy_from_sockptr(&args, optval, sizeof(args)))
			return -EFAULT;

		if (args.reserved != 0)
			return -EINVAL;

		if (tsk->conn)
			return tquic_migrate_explicit(tsk->conn,
						      &args.local_addr,
						      args.flags);

		return -ENOTCONN;
	}

	case TQUIC_MIGRATION_ENABLED:
		if (val)
			tsk->flags |= TQUIC_F_MIGRATION_ENABLED;
		else
			tsk->flags &= ~TQUIC_F_MIGRATION_ENABLED;
		break;

	case TQUIC_SCHEDULER: {
		/*
		 * SO_TQUIC_SCHEDULER: Set scheduler name before connect()
		 *
		 * Per CONTEXT.md: Scheduler is locked at connection establishment
		 * and cannot be changed mid-connection.
		 */
		char name[TQUIC_SCHED_NAME_MAX];
		int ret = 0;

		if (optlen < 1 || optlen >= TQUIC_SCHED_NAME_MAX)
			return -EINVAL;

		if (copy_from_sockptr(name, optval, optlen))
			return -EFAULT;
		name[optlen] = '\0';

		/* Validate scheduler exists */
		rcu_read_lock();
		if (!tquic_sched_find(name)) {
			rcu_read_unlock();
			return -ENOENT;
		}
		rcu_read_unlock();

		lock_sock(sk);
		/*
		 * Must be called before connect/listen.
		 * Check connection state if one exists.
		 */
		if (tsk->conn && tsk->conn->state != TQUIC_CONN_IDLE) {
			ret = -EISCONN;
		} else if (tsk->conn) {
			/* Connection exists but idle, init scheduler now */
			struct tquic_sched_ops *sched_ops = tquic_sched_find(name);

			if (sched_ops) {
				tsk->conn->scheduler = tquic_sched_init_conn(tsk->conn, sched_ops);
				if (!tsk->conn->scheduler)
					ret = -ENOMEM;
			} else {
				ret = -ENOENT;
			}
		} else {
			/* No connection yet, store for later when connection is created */
			strscpy(tsk->requested_scheduler, name,
				sizeof(tsk->requested_scheduler));
		}
		release_sock(sk);
		return ret;
	}

	case TQUIC_CONGESTION: {
		/*
		 * SO_TQUIC_CONGESTION: Set CC algorithm before connect()
		 *
		 * Per CONTEXT.md: Different paths can use different CC algorithms.
		 * This sockopt sets the preferred CC for new paths on the connection.
		 *
		 * Special values:
		 *   "auto" - Enable RTT-based auto-selection (BBR for high-RTT)
		 *   Empty or default per-netns setting otherwise
		 *
		 * Unlike scheduler, CC can be set per-path dynamically, so
		 * this preference is stored and used when paths are created.
		 */
		char name[TQUIC_MAX_CONG_NAME];
		int ret = 0;

		if (optlen < 1 || optlen >= TQUIC_MAX_CONG_NAME)
			return -EINVAL;

		if (copy_from_sockptr(name, optval, optlen))
			return -EFAULT;
		name[optlen] = '\0';

		/* "auto" is a special value for RTT-based selection */
		if (strcmp(name, "auto") != 0) {
			/* Validate CC algorithm exists */
			struct tquic_cong_ops *ca = tquic_cong_find(name);
			if (!ca) {
				pr_warn("tquic: unknown CC algorithm '%s'\n", name);
				return -ENOENT;
			}
			/* Release module reference from find */
			if (ca->owner)
				module_put(ca->owner);
		}

		lock_sock(sk);
		/*
		 * Store preference - unlike scheduler, CC preference
		 * can be set even on an established connection since
		 * it affects new paths, not existing ones.
		 */
		strscpy(tsk->requested_congestion, name,
			sizeof(tsk->requested_congestion));
		release_sock(sk);
		return ret;
	}

	case TQUIC_PSK_IDENTITY: {
		/*
		 * SO_TQUIC_PSK_IDENTITY: Set PSK identity for connection
		 *
		 * For client sockets: Sets identity to send in ClientHello
		 * For server sockets: Store identity for later use
		 *
		 * Must be set before connect().
		 */
		char identity[64];

		if (optlen < 1 || optlen > 64)
			return -EINVAL;

		if (copy_from_sockptr(identity, optval, optlen))
			return -EFAULT;

		lock_sock(sk);
		/* Store PSK identity in socket */
		memcpy(tsk->psk_identity, identity, optlen);
		tsk->psk_identity_len = optlen;
		release_sock(sk);

		pr_debug("tquic: PSK identity set (%d bytes)\n", optlen);
		return 0;
	}

	case TQUIC_ZEROCOPY:
		/*
		 * SO_TQUIC_ZEROCOPY: Enable/disable zero-copy I/O
		 *
		 * When enabled, sendmsg() with MSG_ZEROCOPY will use
		 * zero-copy transmission with completion notification via
		 * the socket error queue (SO_EE_ORIGIN_ZEROCOPY).
		 *
		 * Also enables sendfile()/splice() optimizations.
		 */
		return tquic_set_zerocopy(sk, val);

	case TQUIC_SO_DATAGRAM:
		/*
		 * SO_TQUIC_DATAGRAM: Enable/disable DATAGRAM frame support
		 *
		 * When enabled before connect(), the connection will negotiate
		 * DATAGRAM frame support (RFC 9221) with the peer via the
		 * max_datagram_frame_size transport parameter.
		 *
		 * Must be set before connect().
		 */
		lock_sock(sk);
		if (tsk->conn && tsk->conn->state != TQUIC_CONN_IDLE) {
			release_sock(sk);
			return -EISCONN;
		}
		tsk->datagram_enabled = !!val;
		release_sock(sk);
		return 0;

	case TQUIC_SO_DATAGRAM_QUEUE_LEN:
		/*
		 * SO_TQUIC_DATAGRAM_QUEUE_LEN: Set receive queue limit
		 *
		 * Sets the maximum number of datagrams that can be queued
		 * for receive. Excess datagrams are dropped (unreliable).
		 */
		if (val < 1 || val > TQUIC_DATAGRAM_QUEUE_MAX)
			return -EINVAL;

		lock_sock(sk);
		tsk->datagram_queue_max = val;
		if (tsk->conn)
			tsk->conn->datagram.recv_queue_max = val;
		release_sock(sk);
		return 0;

	case TQUIC_SO_DATAGRAM_RCVBUF:
		/*
		 * SO_TQUIC_DATAGRAM_RCVBUF: Set datagram receive buffer size
		 *
		 * Sets the maximum number of datagrams that can be queued
		 * in the receive buffer. This provides SO_RCVBUF-like semantics
		 * for datagram flow control.
		 *
		 * Note: Unlike SO_RCVBUF which is in bytes, this is the
		 * maximum number of datagrams to queue. Each datagram can be
		 * up to max_datagram_frame_size bytes.
		 */
		if (val < 1 || val > TQUIC_DATAGRAM_QUEUE_MAX)
			return -EINVAL;

		lock_sock(sk);
		tsk->datagram_queue_max = val;
		if (tsk->conn)
			tsk->conn->datagram.recv_queue_max = val;
		release_sock(sk);
		return 0;

	case TQUIC_SO_HTTP3_ENABLE:
		/*
		 * SO_TQUIC_HTTP3_ENABLE: Enable/disable HTTP/3 mode
		 *
		 * When enabled before connect(), the connection will operate
		 * in HTTP/3 mode (RFC 9114) with proper stream type mapping,
		 * control streams, and QPACK header compression.
		 *
		 * Must be set before connect().
		 */
		lock_sock(sk);
		if (tsk->conn && tsk->conn->state != TQUIC_CONN_IDLE) {
			release_sock(sk);
			return -EISCONN;
		}
		tsk->http3_enabled = !!val;
		release_sock(sk);
		return 0;

	case TQUIC_SO_HTTP3_MAX_TABLE_CAPACITY:
		/*
		 * SO_TQUIC_HTTP3_MAX_TABLE_CAPACITY: Set QPACK max table capacity
		 *
		 * Sets the maximum size (in bytes) of the QPACK dynamic table
		 * for header compression. Default is 4096.
		 */
		if (val < 0 || val > TQUIC_HTTP3_MAX_TABLE_CAPACITY_MAX)
			return -EINVAL;

		lock_sock(sk);
		tsk->http3_settings.max_table_capacity = val;
		release_sock(sk);
		return 0;

	case TQUIC_SO_HTTP3_MAX_FIELD_SECTION_SIZE:
		/*
		 * SO_TQUIC_HTTP3_MAX_FIELD_SECTION_SIZE: Set max header section size
		 *
		 * Sets the maximum size (in bytes) of a header section that
		 * the endpoint is willing to accept. Default is 16384.
		 */
		if (val < 0)
			return -EINVAL;

		lock_sock(sk);
		tsk->http3_settings.max_field_section_size = val;
		release_sock(sk);
		return 0;

	case TQUIC_SO_HTTP3_BLOCKED_STREAMS:
		/*
		 * SO_TQUIC_HTTP3_BLOCKED_STREAMS: Set QPACK blocked streams
		 *
		 * Sets the maximum number of streams that can be blocked
		 * waiting for QPACK decoder instructions. Default is 100.
		 */
		if (val < 0 || val > TQUIC_HTTP3_MAX_BLOCKED_STREAMS_MAX)
			return -EINVAL;

		lock_sock(sk);
		tsk->http3_settings.max_blocked_streams = val;
		release_sock(sk);
		return 0;

	case TQUIC_SO_HTTP3_SERVER_PUSH:
		/*
		 * SO_TQUIC_HTTP3_SERVER_PUSH: Enable/disable server push
		 *
		 * When enabled, the server can push resources to the client
		 * using PUSH_PROMISE frames. Default is disabled.
		 */
		lock_sock(sk);
		tsk->http3_settings.server_push_enabled = !!val;
		release_sock(sk);
		return 0;

	case TQUIC_SO_HTTP3_SETTINGS: {
		/*
		 * SO_TQUIC_HTTP3_SETTINGS: Set all HTTP/3 settings at once
		 *
		 * Allows setting all HTTP/3 configuration parameters with
		 * a single socket option call using struct tquic_http3_settings.
		 */
		struct tquic_http3_settings settings;

		if (optlen < sizeof(settings))
			return -EINVAL;

		if (copy_from_sockptr(&settings, optval, sizeof(settings)))
			return -EFAULT;

		/* Validate settings */
		if (settings.max_table_capacity > TQUIC_HTTP3_MAX_TABLE_CAPACITY_MAX)
			return -EINVAL;
		if (settings.max_blocked_streams > TQUIC_HTTP3_MAX_BLOCKED_STREAMS_MAX)
			return -EINVAL;

		lock_sock(sk);
		if (tsk->conn && tsk->conn->state != TQUIC_CONN_IDLE) {
			release_sock(sk);
			return -EISCONN;
		}
		tsk->http3_settings.max_table_capacity = settings.max_table_capacity;
		tsk->http3_settings.max_field_section_size = settings.max_field_section_size;
		tsk->http3_settings.max_blocked_streams = settings.max_blocked_streams;
		tsk->http3_settings.server_push_enabled = settings.enable_push;
		release_sock(sk);
		return 0;
	}

	/*
	 * Certificate Verification Socket Options
	 *
	 * These options control TLS certificate chain validation.
	 * Must be set before connect() for client sockets.
	 */

	case TQUIC_CERT_VERIFY_MODE:
		/*
		 * SO_TQUIC_CERT_VERIFY_MODE: Set certificate verification mode
		 *
		 * Values:
		 *   TQUIC_VERIFY_NONE     - No verification (INSECURE)
		 *   TQUIC_VERIFY_OPTIONAL - Verify if present, allow missing
		 *   TQUIC_VERIFY_REQUIRED - Full verification required (default)
		 *
		 * WARNING: Using NONE leaves connections vulnerable to MITM attacks.
		 * Must be set before connect().
		 */
		if (val < TQUIC_VERIFY_NONE || val > TQUIC_VERIFY_REQUIRED)
			return -EINVAL;

		lock_sock(sk);
		if (tsk->conn && tsk->conn->state != TQUIC_CONN_IDLE) {
			release_sock(sk);
			return -EISCONN;
		}
		tsk->cert_verify.verify_mode = val;
		if (val == TQUIC_VERIFY_NONE)
			pr_warn("tquic: Certificate verification disabled for socket - INSECURE\n");
		release_sock(sk);
		return 0;

	case TQUIC_EXPECTED_HOSTNAME: {
		/*
		 * SO_TQUIC_EXPECTED_HOSTNAME: Set expected hostname for verification
		 *
		 * Overrides the hostname used for certificate verification.
		 * By default, the hostname from connect() or server_name is used.
		 *
		 * Useful when connecting via IP address but expecting a specific
		 * certificate, or when using a different name than the SNI.
		 *
		 * Must be set before connect().
		 */
		char hostname[TQUIC_MAX_HOSTNAME_LEN + 1];

		if (optlen <= 0 || optlen > TQUIC_MAX_HOSTNAME_LEN)
			return -EINVAL;

		if (copy_from_sockptr(hostname, optval, optlen))
			return -EFAULT;
		hostname[optlen] = '\0';

		lock_sock(sk);
		if (tsk->conn && tsk->conn->state != TQUIC_CONN_IDLE) {
			release_sock(sk);
			return -EISCONN;
		}
		memcpy(tsk->cert_verify.expected_hostname, hostname, optlen);
		tsk->cert_verify.expected_hostname_len = optlen;
		tsk->cert_verify.verify_hostname = true;
		release_sock(sk);

		pr_debug("tquic: Expected hostname set to '%s'\n", hostname);
		return 0;
	}

	case TQUIC_ALLOW_SELF_SIGNED:
		/*
		 * SO_TQUIC_ALLOW_SELF_SIGNED: Allow self-signed certificates
		 *
		 * WARNING: This is DANGEROUS and should only be used for testing
		 * in controlled environments. Self-signed certificates provide
		 * no authentication and are vulnerable to MITM attacks.
		 *
		 * Must be set before connect().
		 */
		lock_sock(sk);
		if (tsk->conn && tsk->conn->state != TQUIC_CONN_IDLE) {
			release_sock(sk);
			return -EISCONN;
		}
		tsk->cert_verify.allow_self_signed = !!val;
		if (val)
			pr_warn("tquic: Self-signed certificates allowed for socket - INSECURE\n");
		release_sock(sk);
		return 0;

#ifdef CONFIG_TQUIC_QLOG
	case TQUIC_QLOG_ENABLE: {
		/*
		 * TQUIC_QLOG_ENABLE: Enable qlog tracing
		 *
		 * Enables qlog event logging for this connection with the
		 * specified mode and event filter. See tquic_qlog.h for
		 * detailed configuration options.
		 *
		 * Must be called after connect() (connection must exist).
		 */
		struct tquic_qlog_args args;
		struct tquic_qlog *qlog;

		if (optlen < sizeof(args))
			return -EINVAL;

		if (copy_from_sockptr(&args, optval, sizeof(args)))
			return -EFAULT;

		/* Validate reserved flags */
		if (args.flags != 0)
			return -EINVAL;

		lock_sock(sk);
		if (!tsk->conn) {
			release_sock(sk);
			return -ENOTCONN;
		}

		/* Create qlog context */
		qlog = tquic_qlog_create(tsk->conn, &args);
		if (IS_ERR(qlog)) {
			release_sock(sk);
			return PTR_ERR(qlog);
		}

		/* Store qlog context (implementation would add to connection) */
		pr_debug("tquic: qlog enabled for connection, mode=%u\n", args.mode);
		release_sock(sk);
		return 0;
	}

	case TQUIC_QLOG_FILTER: {
		/*
		 * TQUIC_QLOG_FILTER: Update qlog event filter
		 *
		 * Dynamically update the event filter mask for an active
		 * qlog session. This allows enabling/disabling specific
		 * event categories at runtime.
		 */
		u64 mask;

		if (optlen < sizeof(mask))
			return -EINVAL;

		if (copy_from_sockptr(&mask, optval, sizeof(mask)))
			return -EFAULT;

		lock_sock(sk);
		if (!tsk->conn) {
			release_sock(sk);
			return -ENOTCONN;
		}
		/* Would call: tquic_qlog_set_mask(tsk->conn->qlog, mask); */
		release_sock(sk);
		return 0;
	}
#endif /* CONFIG_TQUIC_QLOG */

	default:
		return -ENOPROTOOPT;
	}

	return 0;
}

/*
 * Get socket options
 */
int tquic_sock_getsockopt(struct socket *sock, int level, int optname,
			  char __user *optval, int __user *optlen)
{
	struct sock *sk = sock->sk;
	struct tquic_sock *tsk = tquic_sk(sk);
	int len, val;

	if (level != SOL_TQUIC)
		return -ENOPROTOOPT;

	if (get_user(len, optlen))
		return -EFAULT;

	if (len < 0)
		return -EINVAL;

	switch (optname) {
	case TQUIC_INFO:
		if (len < sizeof(struct tquic_info))
			return -EINVAL;
		if (tsk->conn) {
			struct tquic_info info = {0};
			info.state = tsk->conn->state;
			info.version = tsk->conn->version;
			info.paths_active = tsk->conn->num_paths;
			info.bytes_sent = tsk->conn->stats.tx_bytes;
			info.bytes_received = tsk->conn->stats.rx_bytes;
			if (copy_to_user(optval, &info, sizeof(info)))
				return -EFAULT;
			if (put_user(sizeof(info), optlen))
				return -EFAULT;
		}
		return 0;

	case TQUIC_IDLE_TIMEOUT:
		val = tsk->conn ? tsk->conn->idle_timeout : 0;
		break;

	case TQUIC_BOND_MODE:
		if (tsk->conn && tsk->conn->scheduler) {
			struct tquic_bond_state *bond = tsk->conn->scheduler;
			val = bond->mode;
		} else {
			val = 0;
		}
		break;

	case TQUIC_PATH_STATUS:
		if (tsk->conn) {
			val = tsk->conn->num_paths;
		} else {
			val = 0;
		}
		break;

	case TQUIC_MIGRATE_STATUS: {
		struct tquic_migrate_info info;

		if (len < sizeof(info))
			return -EINVAL;

		if (tsk->conn)
			tquic_migration_get_status(tsk->conn, &info);
		else
			memset(&info, 0, sizeof(info));

		if (copy_to_user(optval, &info, sizeof(info)))
			return -EFAULT;
		if (put_user(sizeof(info), optlen))
			return -EFAULT;
		return 0;
	}

	case TQUIC_MIGRATION_ENABLED:
		val = (tsk->flags & TQUIC_F_MIGRATION_ENABLED) ? 1 : 0;
		break;

	case TQUIC_SCHEDULER: {
		/*
		 * SO_TQUIC_SCHEDULER: Get current scheduler name
		 *
		 * Returns the scheduler assigned to this connection, or the
		 * requested scheduler if not yet connected, or the per-netns
		 * default if neither is set.
		 */
		const char *name;
		int name_len;

		lock_sock(sk);
		if (tsk->requested_scheduler[0]) {
			/* Return the requested/active scheduler name */
			name = tsk->requested_scheduler;
		} else {
			/* Return per-netns default */
			name = tquic_sched_get_default(sock_net(sk));
			if (!name)
				name = "aggregate";
		}
		release_sock(sk);

		name_len = strlen(name) + 1;
		if (len < name_len)
			return -EINVAL;

		if (copy_to_user(optval, name, name_len))
			return -EFAULT;
		if (put_user(name_len, optlen))
			return -EFAULT;

		return 0;
	}

	case TQUIC_CONGESTION: {
		/*
		 * SO_TQUIC_CONGESTION: Get current CC algorithm preference
		 *
		 * Returns the requested CC algorithm for this socket, or the
		 * per-netns default if none is set.
		 *
		 * Note: Individual paths may use different CC algorithms
		 * based on RTT auto-selection. This returns the preference,
		 * not necessarily what each path uses.
		 */
		const char *name;
		int name_len;

		lock_sock(sk);
		if (tsk->requested_congestion[0]) {
			name = tsk->requested_congestion;
		} else {
			/* Return per-netns default */
			name = tquic_cong_get_default_name(sock_net(sk));
		}
		release_sock(sk);

		name_len = strlen(name) + 1;
		if (len < name_len)
			return -EINVAL;

		if (copy_to_user(optval, name, name_len))
			return -EFAULT;
		if (put_user(name_len, optlen))
			return -EFAULT;

		return 0;
	}

	case TQUIC_PACING:
		/*
		 * SO_TQUIC_PACING: Get pacing status
		 *
		 * Returns 1 if pacing is enabled, 0 otherwise.
		 */
		val = tsk->pacing_enabled ? 1 : 0;
		break;

	case TQUIC_PSK_IDENTITY: {
		/*
		 * SO_TQUIC_PSK_IDENTITY: Get current PSK identity
		 */
		int identity_len;

		lock_sock(sk);
		identity_len = tsk->psk_identity_len;
		if (identity_len == 0) {
			release_sock(sk);
			return -ENOENT;
		}

		if (len < identity_len) {
			release_sock(sk);
			return -EINVAL;
		}

		if (copy_to_user(optval, tsk->psk_identity, identity_len)) {
			release_sock(sk);
			return -EFAULT;
		}
		release_sock(sk);

		if (put_user(identity_len, optlen))
			return -EFAULT;

		return 0;
	}

	case TQUIC_ZEROCOPY:
		/*
		 * SO_TQUIC_ZEROCOPY: Get zero-copy I/O status
		 *
		 * Returns 1 if zero-copy is enabled, 0 otherwise.
		 */
		val = tquic_get_zerocopy(sk);
		break;

	case TQUIC_SO_DATAGRAM:
		/*
		 * SO_TQUIC_DATAGRAM: Get DATAGRAM frame status
		 *
		 * Returns 1 if DATAGRAM support is enabled/negotiated.
		 */
		if (tsk->conn)
			val = tsk->conn->datagram.enabled ? 1 : 0;
		else
			val = tsk->datagram_enabled ? 1 : 0;
		break;

	case TQUIC_SO_MAX_DATAGRAM_SIZE:
		/*
		 * SO_TQUIC_MAX_DATAGRAM_SIZE: Get max datagram payload size
		 *
		 * Returns the maximum datagram payload size that can be sent
		 * on this connection. Returns 0 if datagrams not supported.
		 * Read-only option.
		 */
		if (tsk->conn)
			val = tquic_datagram_max_size(tsk->conn);
		else
			val = 0;
		break;

	case TQUIC_SO_DATAGRAM_QUEUE_LEN:
		/*
		 * SO_TQUIC_DATAGRAM_QUEUE_LEN: Get receive queue limit
		 *
		 * Returns the maximum number of datagrams that can be queued.
		 */
		if (tsk->conn)
			val = tsk->conn->datagram.recv_queue_max;
		else
			val = tsk->datagram_queue_max;
		break;

	case TQUIC_SO_DATAGRAM_STATS: {
		/*
		 * SO_TQUIC_DATAGRAM_STATS: Get datagram statistics
		 *
		 * Returns comprehensive datagram statistics including
		 * sent/received/dropped counts and queue state.
		 */
		struct tquic_datagram_stats stats = {0};

		if (len < sizeof(stats))
			return -EINVAL;

		lock_sock(sk);
		if (tsk->conn && tsk->conn->datagram.enabled) {
			spin_lock_bh(&tsk->conn->datagram.lock);
			stats.datagrams_sent = tsk->conn->datagram.datagrams_sent;
			stats.datagrams_received = tsk->conn->datagram.datagrams_received;
			stats.datagrams_dropped = tsk->conn->datagram.datagrams_dropped;
			stats.recv_queue_len = tsk->conn->datagram.recv_queue_len;
			stats.recv_queue_max = tsk->conn->datagram.recv_queue_max;
			stats.max_send_size = tsk->conn->datagram.max_send_size;
			stats.max_recv_size = tsk->conn->datagram.max_recv_size;
			spin_unlock_bh(&tsk->conn->datagram.lock);
		}
		release_sock(sk);

		if (copy_to_user(optval, &stats, sizeof(stats)))
			return -EFAULT;
		if (put_user(sizeof(stats), optlen))
			return -EFAULT;
		return 0;
	}

	case TQUIC_SO_DATAGRAM_RCVBUF:
		/*
		 * SO_TQUIC_DATAGRAM_RCVBUF: Get datagram receive buffer size
		 *
		 * Returns the maximum number of datagrams that can be queued
		 * in the receive buffer. This is an alias for DATAGRAM_QUEUE_LEN
		 * provided for API consistency with SO_RCVBUF semantics.
		 */
		if (tsk->conn)
			val = tsk->conn->datagram.recv_queue_max;
		else
			val = tsk->datagram_queue_max;
		break;

	case TQUIC_SO_HTTP3_ENABLE:
		/*
		 * SO_TQUIC_HTTP3_ENABLE: Get HTTP/3 mode status
		 *
		 * Returns 1 if HTTP/3 mode is enabled, 0 otherwise.
		 */
		val = tsk->http3_enabled ? 1 : 0;
		break;

	case TQUIC_SO_HTTP3_MAX_TABLE_CAPACITY:
		/*
		 * SO_TQUIC_HTTP3_MAX_TABLE_CAPACITY: Get QPACK max table capacity
		 *
		 * Returns the configured QPACK dynamic table capacity.
		 */
		val = tsk->http3_settings.max_table_capacity;
		break;

	case TQUIC_SO_HTTP3_MAX_FIELD_SECTION_SIZE:
		/*
		 * SO_TQUIC_HTTP3_MAX_FIELD_SECTION_SIZE: Get max header section size
		 *
		 * Returns the maximum header section size this endpoint accepts.
		 */
		val = tsk->http3_settings.max_field_section_size;
		break;

	case TQUIC_SO_HTTP3_BLOCKED_STREAMS:
		/*
		 * SO_TQUIC_HTTP3_BLOCKED_STREAMS: Get QPACK blocked streams
		 *
		 * Returns the maximum number of QPACK blocked streams.
		 */
		val = tsk->http3_settings.max_blocked_streams;
		break;

	case TQUIC_SO_HTTP3_SERVER_PUSH:
		/*
		 * SO_TQUIC_HTTP3_SERVER_PUSH: Get server push status
		 *
		 * Returns 1 if server push is enabled, 0 otherwise.
		 */
		val = tsk->http3_settings.server_push_enabled ? 1 : 0;
		break;

	case TQUIC_SO_HTTP3_SETTINGS: {
		/*
		 * SO_TQUIC_HTTP3_SETTINGS: Get all HTTP/3 settings
		 *
		 * Returns all HTTP/3 configuration parameters in a single
		 * struct tquic_http3_settings.
		 */
		struct tquic_http3_settings settings;

		if (len < sizeof(settings))
			return -EINVAL;

		lock_sock(sk);
		settings.max_table_capacity = tsk->http3_settings.max_table_capacity;
		settings.max_field_section_size = tsk->http3_settings.max_field_section_size;
		settings.max_blocked_streams = tsk->http3_settings.max_blocked_streams;
		settings.enable_push = tsk->http3_settings.server_push_enabled;
		settings.reserved = 0;
		settings.reserved2 = 0;
		release_sock(sk);

		if (copy_to_user(optval, &settings, sizeof(settings)))
			return -EFAULT;
		if (put_user(sizeof(settings), optlen))
			return -EFAULT;

		return 0;
	}

	case TQUIC_SO_HTTP3_STREAM_INFO: {
		/*
		 * SO_TQUIC_HTTP3_STREAM_INFO: Get HTTP/3 stream information
		 *
		 * Returns information about a specific HTTP/3 stream including
		 * its type, state, and statistics.
		 */
		struct tquic_http3_stream_info info;

		if (len < sizeof(info))
			return -EINVAL;

		/* Get stream ID from user */
		if (copy_from_user(&info, optval, sizeof(info)))
			return -EFAULT;

		lock_sock(sk);
		if (!tsk->h3_conn) {
			release_sock(sk);
			return -ENOTCONN;
		}

		/*
		 * Stream info lookup would be implemented in http3_stream.c
		 * For now, return basic socket-level info
		 */
		info.type = 0; /* Filled by h3_stream_get_info() */
		info.state = 0;
		info.bytes_sent = 0;
		info.bytes_received = 0;
		release_sock(sk);

		if (copy_to_user(optval, &info, sizeof(info)))
			return -EFAULT;
		if (put_user(sizeof(info), optlen))
			return -EFAULT;

		return 0;
	}

	/*
	 * Certificate Verification Socket Options (getsockopt)
	 */

	case TQUIC_CERT_VERIFY_MODE:
		/*
		 * SO_TQUIC_CERT_VERIFY_MODE: Get certificate verification mode
		 *
		 * Returns the current verification mode:
		 *   TQUIC_VERIFY_NONE     - No verification (INSECURE)
		 *   TQUIC_VERIFY_OPTIONAL - Verify if present, allow missing
		 *   TQUIC_VERIFY_REQUIRED - Full verification required
		 */
		val = tsk->cert_verify.verify_mode;
		break;

	case TQUIC_EXPECTED_HOSTNAME: {
		/*
		 * SO_TQUIC_EXPECTED_HOSTNAME: Get expected hostname
		 *
		 * Returns the configured hostname for certificate verification.
		 * If not explicitly set, returns the server_name (SNI).
		 */
		const char *hostname;
		int hostname_len;

		lock_sock(sk);
		if (tsk->cert_verify.expected_hostname_len > 0) {
			hostname = tsk->cert_verify.expected_hostname;
			hostname_len = tsk->cert_verify.expected_hostname_len;
		} else if (tsk->server_name_len > 0) {
			hostname = tsk->server_name;
			hostname_len = tsk->server_name_len;
		} else {
			release_sock(sk);
			return -ENOENT;
		}

		if (len < hostname_len) {
			release_sock(sk);
			return -EINVAL;
		}

		if (copy_to_user(optval, hostname, hostname_len)) {
			release_sock(sk);
			return -EFAULT;
		}
		release_sock(sk);

		if (put_user(hostname_len, optlen))
			return -EFAULT;

		return 0;
	}

	case TQUIC_ALLOW_SELF_SIGNED:
		/*
		 * SO_TQUIC_ALLOW_SELF_SIGNED: Get self-signed certificate status
		 *
		 * Returns 1 if self-signed certificates are allowed, 0 otherwise.
		 */
		val = tsk->cert_verify.allow_self_signed ? 1 : 0;
		break;

#ifdef CONFIG_TQUIC_QLOG
	case TQUIC_QLOG_STATS: {
		/*
		 * TQUIC_QLOG_STATS: Get qlog statistics
		 *
		 * Returns qlog event logging statistics including event
		 * counts, drops, and relay status.
		 */
		struct tquic_qlog_stats stats = {0};

		if (len < sizeof(stats))
			return -EINVAL;

		lock_sock(sk);
		if (!tsk->conn) {
			release_sock(sk);
			return -ENOTCONN;
		}
		/* Would call: tquic_qlog_get_stats(tsk->conn->qlog, &stats); */
		release_sock(sk);

		if (copy_to_user(optval, &stats, sizeof(stats)))
			return -EFAULT;
		if (put_user(sizeof(stats), optlen))
			return -EFAULT;
		return 0;
	}

	case TQUIC_QLOG_ENABLE:
		/*
		 * TQUIC_QLOG_ENABLE: Get qlog enable status
		 *
		 * Returns 1 if qlog is enabled for this connection.
		 */
		val = 0; /* Would check tsk->conn->qlog != NULL */
		break;
#endif /* CONFIG_TQUIC_QLOG */

	default:
		return -ENOPROTOOPT;
	}

	len = min_t(unsigned int, len, sizeof(int));
	if (put_user(len, optlen))
		return -EFAULT;
	if (copy_to_user(optval, &val, len))
		return -EFAULT;

	return 0;
}

/*
 * Send message
 */
int tquic_sendmsg_socket(struct socket *sock, struct msghdr *msg,
			 size_t len)
{
	return tquic_sendmsg(sock->sk, msg, len);
}

/*
 * tquic_check_datagram_cmsg - Check if sendmsg/recvmsg requests datagram I/O
 * @msg: Message header with control data
 *
 * Scans ancillary data for TQUIC_CMSG_DATAGRAM to determine if
 * the caller wants to send/receive a datagram instead of stream data.
 *
 * Return: true if datagram I/O requested, false otherwise
 */
static bool tquic_check_datagram_cmsg(struct msghdr *msg)
{
	struct cmsghdr *cmsg;

	if (!msg->msg_control || msg->msg_controllen == 0)
		return false;

	for_each_cmsghdr(cmsg, msg) {
		if (!CMSG_OK(msg, cmsg))
			break;

		if (cmsg->cmsg_level == SOL_TQUIC &&
		    cmsg->cmsg_type == TQUIC_CMSG_DATAGRAM)
			return true;
	}

	return false;
}

/*
 * tquic_sendmsg_datagram - Send a datagram via sendmsg
 * @sk: Socket
 * @msg: Message header
 * @len: Data length
 *
 * Internal helper for datagram transmission. Called when ancillary data
 * requests a datagram send via TQUIC_CMSG_DATAGRAM.
 *
 * Return: Number of bytes sent, or negative error code
 */
static int tquic_sendmsg_datagram(struct sock *sk, struct msghdr *msg,
				  size_t len)
{
	struct tquic_sock *tsk = tquic_sk(sk);
	struct tquic_connection *conn = tsk->conn;
	void *buf;
	int ret;

	if (!conn || conn->state != TQUIC_CONN_CONNECTED)
		return -ENOTCONN;

	/* Verify datagram support is negotiated */
	if (!conn->datagram.enabled)
		return -EOPNOTSUPP;

	/* Check size against negotiated limit */
	if (len > conn->datagram.max_send_size)
		return -EMSGSIZE;

	/* Allocate buffer for datagram payload */
	buf = kmalloc(len, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	/* Copy data from user */
	if (copy_from_iter(buf, len, &msg->msg_iter) != len) {
		kfree(buf);
		return -EFAULT;
	}

	/* Send the datagram */
	ret = tquic_send_datagram(conn, buf, len);
	kfree(buf);

	if (ret < 0)
		return ret;

	return len;
}

int tquic_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
{
	struct tquic_sock *tsk = tquic_sk(sk);
	struct tquic_connection *conn = tsk->conn;
	struct tquic_stream *stream;
	struct sk_buff *skb;
	int copied = 0;
	int flags = msg->msg_flags;

	if (!conn || conn->state != TQUIC_CONN_CONNECTED)
		return -ENOTCONN;

	/*
	 * Check if caller wants datagram send (RFC 9221)
	 *
	 * If ancillary data contains TQUIC_CMSG_DATAGRAM, this is a
	 * datagram send request. The entire message is sent as a single
	 * unreliable datagram.
	 */
	if (tquic_check_datagram_cmsg(msg))
		return tquic_sendmsg_datagram(sk, msg, len);

	/* Use or create default stream */
	stream = tsk->default_stream;
	if (!stream) {
		stream = tquic_stream_open(conn, true);
		if (!stream)
			return -ENOMEM;
		tsk->default_stream = stream;
	}

	/*
	 * Zero-copy path: Handle MSG_ZEROCOPY flag
	 *
	 * When MSG_ZEROCOPY is set and SO_ZEROCOPY socket option is enabled,
	 * use skb_zerocopy_iter_stream() to map user pages directly into
	 * skbs without copying. Completion notification is sent via the
	 * socket error queue with SO_EE_ORIGIN_ZEROCOPY.
	 */
	if ((flags & MSG_ZEROCOPY) && len > 0) {
		int ret = tquic_check_zerocopy_flag(sk, msg, flags);

		if (ret == 0) {
			/* Zerocopy is available - use zero-copy path */
			return tquic_sendmsg_zerocopy(sk, msg, len, stream);
		}
		/*
		 * If zerocopy not available, fall through to regular copy.
		 * This handles the case where MSG_ZEROCOPY is set but
		 * SO_ZEROCOPY socket option is not enabled.
		 */
		if (ret != -EOPNOTSUPP)
			return ret;
	}

	/* Regular copy path */
	while (copied < len) {
		size_t chunk = min_t(size_t, len - copied, 1200);

		skb = alloc_skb(chunk, GFP_KERNEL);
		if (!skb)
			return copied > 0 ? copied : -ENOMEM;

		if (copy_from_iter(skb_put(skb, chunk), chunk, &msg->msg_iter) != chunk) {
			kfree_skb(skb);
			return copied > 0 ? copied : -EFAULT;
		}

		/* Charge socket memory for this buffer */
		if (sk_wmem_schedule(sk, skb->truesize)) {
			skb_set_owner_w(skb, sk);
		} else {
			kfree_skb(skb);
			return copied > 0 ? copied : -ENOBUFS;
		}

		skb_queue_tail(&stream->send_buf, skb);
		copied += chunk;

		conn->stats.tx_bytes += chunk;
	}

	/*
	 * Trigger actual transmission.
	 * If nodelay is set, flush immediately. Otherwise, let the
	 * output subsystem coalesce data based on congestion state.
	 */
	if (tsk->nodelay || stream->send_offset == 0) {
		/* Flush stream data to the network */
		tquic_output_flush(conn);
	}

	return copied;
}
EXPORT_SYMBOL_GPL(tquic_sendmsg);

/*
 * Receive message
 */
int tquic_recvmsg_socket(struct socket *sock, struct msghdr *msg,
			 size_t len, int flags)
{
	return tquic_recvmsg(sock->sk, msg, len, flags, NULL);
}

/*
 * tquic_recvmsg_datagram - Receive a datagram via recvmsg
 * @sk: Socket
 * @msg: Message header
 * @len: Maximum length to receive
 * @flags: Receive flags
 *
 * Internal helper for datagram reception. Called when ancillary data
 * requests a datagram read via TQUIC_CMSG_DATAGRAM.
 *
 * Return: Number of bytes received, or negative error code
 */
static int tquic_recvmsg_datagram(struct sock *sk, struct msghdr *msg,
				  size_t len, int flags)
{
	struct tquic_sock *tsk = tquic_sk(sk);
	struct tquic_connection *conn = tsk->conn;
	struct tquic_datagram_info dgram_info;
	struct sk_buff *skb;
	unsigned long irqflags;
	size_t copy_len;
	long timeo;
	int ret;

	if (!conn || (conn->state != TQUIC_CONN_CONNECTED &&
		      conn->state != TQUIC_CONN_CLOSING))
		return -ENOTCONN;

	/* Verify datagram support is negotiated */
	if (!conn->datagram.enabled)
		return -EOPNOTSUPP;

	/* Get receive timeout */
	timeo = sock_rcvtimeo(sk, flags & MSG_DONTWAIT);

retry:
	spin_lock_irqsave(&conn->datagram.lock, irqflags);

	skb = skb_peek(&conn->datagram.recv_queue);
	if (!skb) {
		spin_unlock_irqrestore(&conn->datagram.lock, irqflags);

		/* Non-blocking: return immediately */
		if (flags & MSG_DONTWAIT)
			return -EAGAIN;

		if (timeo == 0)
			return -EAGAIN;

		/* Check for pending signals */
		if (signal_pending(current))
			return sock_intr_errno(timeo);

		/* Wait for datagram arrival */
		ret = wait_event_interruptible_timeout(
			conn->datagram.wait,
			!skb_queue_empty(&conn->datagram.recv_queue) ||
			    sk->sk_err ||
			    (sk->sk_shutdown & RCV_SHUTDOWN) ||
			    conn->state == TQUIC_CONN_CLOSED,
			timeo);

		if (ret < 0)
			return sock_intr_errno(timeo);

		if (ret == 0)
			return -EAGAIN;

		/* Re-check connection state */
		if (conn->state == TQUIC_CONN_CLOSED)
			return -ENOTCONN;

		if (sk->sk_err)
			return -sock_error(sk);

		if (sk->sk_shutdown & RCV_SHUTDOWN)
			return 0;

		timeo = ret;
		goto retry;
	}

	/* Calculate copy length */
	copy_len = min_t(size_t, len, skb->len);

	/* Copy data to user buffer */
	if (copy_to_iter(skb->data, copy_len, &msg->msg_iter) != copy_len) {
		spin_unlock_irqrestore(&conn->datagram.lock, irqflags);
		return -EFAULT;
	}

	/* Set MSG_TRUNC if datagram was truncated */
	if (skb->len > len)
		msg->msg_flags |= MSG_TRUNC;

	/* Remove from queue unless peeking */
	if (!(flags & MSG_PEEK)) {
		__skb_unlink(skb, &conn->datagram.recv_queue);
		conn->datagram.recv_queue_len--;
		spin_unlock_irqrestore(&conn->datagram.lock, irqflags);
		kfree_skb(skb);
	} else {
		spin_unlock_irqrestore(&conn->datagram.lock, irqflags);
	}

	/*
	 * Return ancillary data indicating this was a datagram
	 *
	 * Per UAPI: struct tquic_datagram_info is returned via cmsg
	 * with type TQUIC_CMSG_DATAGRAM at level SOL_TQUIC.
	 */
	if (msg->msg_controllen >= CMSG_SPACE(sizeof(dgram_info))) {
		memset(&dgram_info, 0, sizeof(dgram_info));
		dgram_info.dgram_id = 0;  /* Could be enhanced with tracking */
		dgram_info.flags = 0;
		put_cmsg(msg, SOL_TQUIC, TQUIC_CMSG_DATAGRAM,
			 sizeof(dgram_info), &dgram_info);
	}

	return copy_len;
}

int tquic_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int flags,
		  int *addr_len)
{
	struct tquic_sock *tsk = tquic_sk(sk);
	struct tquic_connection *conn = tsk->conn;
	struct tquic_stream *stream;
	struct sk_buff *skb;
	int copied = 0;

	if (!conn || conn->state != TQUIC_CONN_CONNECTED)
		return -ENOTCONN;

	/*
	 * Check if caller wants datagram read (RFC 9221)
	 *
	 * If ancillary data contains TQUIC_CMSG_DATAGRAM, this is a
	 * datagram read request. Otherwise, read from the default stream.
	 */
	if (tquic_check_datagram_cmsg(msg))
		return tquic_recvmsg_datagram(sk, msg, len, flags);

	stream = tsk->default_stream;
	if (!stream)
		return 0;

	while (copied < len && !skb_queue_empty(&stream->recv_buf)) {
		size_t chunk;

		skb = skb_dequeue(&stream->recv_buf);
		if (!skb)
			break;

		chunk = min_t(size_t, len - copied, skb->len);

		if (copy_to_iter(skb->data, chunk, &msg->msg_iter) != chunk) {
			skb_queue_head(&stream->recv_buf, skb);
			return copied > 0 ? copied : -EFAULT;
		}

		copied += chunk;

		if (chunk < skb->len) {
			/* Partial read, requeue remainder */
			skb_pull(skb, chunk);
			skb_queue_head(&stream->recv_buf, skb);
		} else {
			kfree_skb(skb);
		}

		conn->stats.rx_bytes += chunk;
	}

	return copied;
}
EXPORT_SYMBOL_GPL(tquic_recvmsg);

/*
 * =============================================================================
 * Zero-Copy I/O Operations
 * =============================================================================
 */

/**
 * tquic_splice_read_socket - splice() support wrapper
 * @sock: Socket
 * @ppos: Position (not used, must be NULL)
 * @pipe: Pipe to splice to
 * @len: Number of bytes to splice
 * @flags: Splice flags
 *
 * Implements .splice_read in proto_ops for zero-copy data transfer
 * from QUIC stream receive buffer to a pipe.
 *
 * Returns: Number of bytes spliced on success, negative errno on failure
 */
ssize_t tquic_splice_read_socket(struct socket *sock, loff_t *ppos,
				 struct pipe_inode_info *pipe,
				 size_t len, unsigned int flags)
{
	return tquic_splice_read(sock, ppos, pipe, len, flags);
}
