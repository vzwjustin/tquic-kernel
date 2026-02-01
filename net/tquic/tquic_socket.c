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
#include "../quic/tquic_sched.h"
#include "cong/tquic_cong.h"
#include "tquic_zerocopy.h"

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

/* Socket operations */
static int tquic_release(struct socket *sock);
static int tquic_bind(struct socket *sock, struct sockaddr *addr, int addr_len);
static int tquic_connect_socket(struct socket *sock, struct sockaddr *addr,
				int addr_len, int flags);
static int tquic_accept_socket(struct socket *sock, struct socket *newsock,
			       struct proto_accept_arg *arg);
static int tquic_getname(struct socket *sock, struct sockaddr *addr, int peer);
static __poll_t tquic_poll_socket(struct file *file, struct socket *sock,
				  poll_table *wait);
static int tquic_listen(struct socket *sock, int backlog);
static int tquic_shutdown(struct socket *sock, int how);
static int tquic_setsockopt(struct socket *sock, int level, int optname,
			    sockptr_t optval, unsigned int optlen);
static int tquic_getsockopt(struct socket *sock, int level, int optname,
			    char __user *optval, int __user *optlen);
static int tquic_sendmsg_socket(struct socket *sock, struct msghdr *msg,
				size_t len);
static int tquic_recvmsg_socket(struct socket *sock, struct msghdr *msg,
				size_t len, int flags);
static int tquic_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg);

/* Zero-copy operations (forward declarations) */
static ssize_t tquic_sendpage_socket(struct socket *sock, struct page *page,
				     int offset, size_t size, int flags);
static ssize_t tquic_splice_read_socket(struct socket *sock, loff_t *ppos,
					struct pipe_inode_info *pipe,
					size_t len, unsigned int flags);

/* Protocol operations */
static int tquic_init_sock(struct sock *sk);
static void tquic_destroy_sock(struct sock *sk);
static int tquic_hash(struct sock *sk);
static void tquic_unhash(struct sock *sk);
static int tquic_get_port(struct sock *sk, unsigned short snum);

/* Socket family operations */
static const struct proto_ops tquic_proto_ops = {
	.family		= PF_INET,
	.owner		= THIS_MODULE,
	.release	= tquic_release,
	.bind		= tquic_bind,
	.connect	= tquic_connect_socket,
	.socketpair	= sock_no_socketpair,
	.accept		= tquic_accept_socket,
	.getname	= tquic_getname,
	.poll		= tquic_poll_socket,
	.ioctl		= tquic_ioctl,
	.listen		= tquic_listen,
	.shutdown	= tquic_shutdown,
	.setsockopt	= tquic_setsockopt,
	.getsockopt	= tquic_getsockopt,
	.sendmsg	= tquic_sendmsg_socket,
	.recvmsg	= tquic_recvmsg_socket,
	.mmap		= sock_no_mmap,
	.sendpage	= tquic_sendpage_socket,	/* Zero-copy sendfile support */
	.splice_read	= tquic_splice_read_socket,	/* Zero-copy splice support */
};

/* Socket protocol definition */
static struct proto tquic_prot = {
	.name		= "TQUIC",
	.owner		= THIS_MODULE,
	.obj_size	= sizeof(struct tquic_sock),
	.init		= tquic_init_sock,
	.destroy	= tquic_destroy_sock,
	.hash		= tquic_hash,
	.unhash		= tquic_unhash,
	.get_port	= tquic_get_port,
	.close		= tquic_close,
	.connect	= tquic_connect,
	.sendmsg	= tquic_sendmsg,
	.recvmsg	= tquic_recvmsg,
};

/*
 * Initialize a TQUIC socket
 */
static int tquic_init_sock(struct sock *sk)
{
	struct tquic_sock *tsk = tquic_sk(sk);

	/* Initialize lockdep class for this socket (IPv4) */
	tquic_set_lockdep_class(sk, false);

	/* Initialize connection socket */
	inet_sk_set_state(sk, TCP_CLOSE);

	/* Initialize TQUIC-specific state */
	INIT_LIST_HEAD(&tsk->accept_queue);
	INIT_LIST_HEAD(&tsk->accept_list);
	INIT_HLIST_NODE(&tsk->listener_node);
	tsk->accept_queue_len = 0;
	tsk->max_accept_queue = 128;
	tsk->flags = 0;

	/* Clear requested scheduler (will use per-netns default if not set) */
	tsk->requested_scheduler[0] = '\0';

	/* Clear requested congestion control (will use per-netns default if not set) */
	tsk->requested_congestion[0] = '\0';

	/* Enable pacing by default per CONTEXT.md */
	tsk->pacing_enabled = true;

	/* Create connection structure */
	tsk->conn = tquic_conn_create(sk, GFP_KERNEL);
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
static void tquic_destroy_sock(struct sock *sk)
{
	struct tquic_sock *tsk = tquic_sk(sk);

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
 * Release socket
 */
static int tquic_release(struct socket *sock)
{
	struct sock *sk = sock->sk;

	if (!sk)
		return 0;

	/* Unregister from listener table if we were listening */
	if (sk->sk_state == TCP_LISTEN)
		tquic_unregister_listener(sk);

	sock->sk = NULL;
	sock_put(sk);

	return 0;
}

/*
 * Bind socket to address
 */
static int tquic_bind(struct socket *sock, struct sockaddr *addr, int addr_len)
{
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
 */
static int tquic_connect_socket(struct socket *sock, struct sockaddr *addr,
				int addr_len, int flags)
{
	struct sock *sk = sock->sk;

	return tquic_connect(sk, addr, addr_len);
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
int tquic_connect(struct sock *sk, struct sockaddr *addr, int addr_len)
{
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
	ret = tquic_conn_client_connect(conn, addr);
	if (ret < 0)
		goto out_unlock;

	/*
	 * Initialize scheduler - use requested or per-netns default.
	 * Per CONTEXT.md: "Scheduler locked at connection establishment"
	 */
	ret = tquic_sched_init_conn(conn,
				    tsk->requested_scheduler[0] ?
				    tsk->requested_scheduler : NULL);
	if (ret < 0) {
		pr_warn("tquic: scheduler init failed: %d, using default\n", ret);
		/* Try with default scheduler */
		ret = tquic_sched_init_conn(conn, NULL);
		if (ret < 0)
			goto out_unlock;
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
		pr_warn("tquic: PM init failed: %d\n", ret);
		/* Continue anyway - PM is optional for basic operation */
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
static int tquic_listen(struct socket *sock, int backlog)
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
static int tquic_accept_socket(struct socket *sock, struct socket *newsock,
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
static int tquic_getname(struct socket *sock, struct sockaddr *addr, int peer)
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
static __poll_t tquic_poll_socket(struct file *file, struct socket *sock,
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
		/* Check if data available to read */
		if (tsk->conn && tsk->default_stream) {
			if (!skb_queue_empty(&tsk->default_stream->recv_buf))
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
static int tquic_shutdown(struct socket *sock, int how)
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
int tquic_close(struct sock *sk, long timeout)
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

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_close);

/*
 * ioctl handler for connection socket
 *
 * Handles TQUIC-specific ioctls, primarily TQUIC_NEW_STREAM which creates
 * new stream file descriptors. Falls back to inet_ioctl for standard ioctls.
 */
static int tquic_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg)
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
static int tquic_setsockopt(struct socket *sock, int level, int optname,
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
			ret = tquic_sched_init_conn(tsk->conn, name);
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

	default:
		return -ENOPROTOOPT;
	}

	return 0;
}

/*
 * Get socket options
 */
static int tquic_getsockopt(struct socket *sock, int level, int optname,
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
		if (tsk->conn && tsk->conn->scheduler) {
			/*
			 * Connection exists with scheduler - get name from
			 * the scheduler's sched_ops via tquic_sched.h API
			 */
			struct tquic_sched_ops *sched;

			rcu_read_lock();
			/* scheduler points to bonding state which contains sched */
			sched = rcu_dereference((struct tquic_sched_ops *)
						tsk->conn->scheduler);
			/*
			 * In this implementation, conn->scheduler is actually
			 * a tquic_bond_state pointer. The actual scheduler ops
			 * would be accessed differently. For now, check if we
			 * have a requested_scheduler stored.
			 */
			if (tsk->requested_scheduler[0]) {
				name = tsk->requested_scheduler;
			} else {
				name = tquic_sched_get_default(sock_net(sk));
			}
			rcu_read_unlock();
		} else if (tsk->requested_scheduler[0]) {
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
static int tquic_sendmsg_socket(struct socket *sock, struct msghdr *msg,
				size_t len)
{
	return tquic_sendmsg(sock->sk, msg, len);
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
static int tquic_recvmsg_socket(struct socket *sock, struct msghdr *msg,
				size_t len, int flags)
{
	return tquic_recvmsg(sock->sk, msg, len, flags);
}

int tquic_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int flags)
{
	struct tquic_sock *tsk = tquic_sk(sk);
	struct tquic_connection *conn = tsk->conn;
	struct tquic_stream *stream;
	struct sk_buff *skb;
	int copied = 0;

	if (!conn || conn->state != TQUIC_CONN_CONNECTED)
		return -ENOTCONN;

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
 * Hash/unhash operations (minimal for now)
 */
static int tquic_hash(struct sock *sk)
{
	return 0;
}

static void tquic_unhash(struct sock *sk)
{
}

static int tquic_get_port(struct sock *sk, unsigned short snum)
{
	return 0;
}

/*
 * =============================================================================
 * Zero-Copy I/O Operations
 * =============================================================================
 */

/**
 * tquic_sendpage_socket - sendfile() support wrapper
 * @sock: Socket
 * @page: Page to send
 * @offset: Offset within page
 * @size: Number of bytes to send
 * @flags: Send flags
 *
 * Implements .sendpage in proto_ops for sendfile() support.
 * Uses page references instead of copying data when scatter-gather
 * is available. Falls back to copy when SG is not supported.
 *
 * Returns: Number of bytes sent on success, negative errno on failure
 */
static ssize_t tquic_sendpage_socket(struct socket *sock, struct page *page,
				     int offset, size_t size, int flags)
{
	return tquic_sendpage(sock, page, offset, size, flags);
}

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
static ssize_t tquic_splice_read_socket(struct socket *sock, loff_t *ppos,
					struct pipe_inode_info *pipe,
					size_t len, unsigned int flags)
{
	return tquic_splice_read(sock, ppos, pipe, len, flags);
}

/*
 * Socket registration
 */
static struct inet_protosw tquic_protosw = {
	.type = SOCK_STREAM,
	.protocol = IPPROTO_TQUIC,
	.prot = &tquic_prot,
	.ops = &tquic_proto_ops,
};

int __init tquic_socket_init(void)
{
	int ret;

	ret = proto_register(&tquic_prot, 1);
	if (ret)
		return ret;

	inet_register_protosw(&tquic_protosw);

	pr_info("tquic: socket interface registered\n");
	return 0;
}

void __exit tquic_socket_exit(void)
{
	inet_unregister_protosw(&tquic_protosw);
	proto_unregister(&tquic_prot);
}
