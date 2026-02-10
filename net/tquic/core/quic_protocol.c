// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * TQUIC - Transport QUIC with WAN Bonding
 *
 * Linux kernel TQUIC protocol implementation
 *
 * Copyright (c) 2026 Linux Foundation
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <linux/version.h>
#include <asm/ioctls.h>
#include <net/sock.h>
#include <net/inet_common.h>
#include <net/inet_hashtables.h>
#include <net/protocol.h>
#include <net/udp.h>
#include <net/tquic.h>
#include <net/tquic/handshake.h>
#include "../tquic_compat.h"
#include "../tquic_debug.h"

static struct kmem_cache __maybe_unused *tquic_sock_cachep __read_mostly;
static struct kmem_cache __maybe_unused *tquic_conn_cachep __read_mostly;
static struct kmem_cache __maybe_unused *tquic_stream_cachep __read_mostly;

/* Sysctl variables - sysctl_mem has been long[] since before 5.4 */
long sysctl_tquic_mem[3] __read_mostly;
int sysctl_tquic_wmem[3] __read_mostly = { 4096, 16384, 4194304 };
int sysctl_tquic_rmem[3] __read_mostly = { 4096, 131072, 6291456 };

/*
 * Configurable connection defaults (via module parameters)
 * These can be overridden per-socket via setsockopt.
 */
static unsigned int tquic_default_idle_timeout_ms __read_mostly = 30000;
static unsigned int tquic_default_handshake_timeout_ms __read_mostly = 10000;
static unsigned int tquic_default_max_data __read_mostly = 1048576;		/* 1 MB */
static unsigned int tquic_default_max_stream_data __read_mostly = 65536;	/* 64 KB */
static unsigned int tquic_default_max_streams __read_mostly = 100;
static unsigned int tquic_default_initial_rtt_ms __read_mostly = 333;

module_param(tquic_default_idle_timeout_ms, uint, 0644);
MODULE_PARM_DESC(tquic_default_idle_timeout_ms, "Default idle timeout in milliseconds");
module_param(tquic_default_handshake_timeout_ms, uint, 0644);
MODULE_PARM_DESC(tquic_default_handshake_timeout_ms, "Default handshake timeout in milliseconds");
module_param(tquic_default_max_data, uint, 0644);
MODULE_PARM_DESC(tquic_default_max_data, "Default initial max data limit");
module_param(tquic_default_max_stream_data, uint, 0644);
MODULE_PARM_DESC(tquic_default_max_stream_data, "Default initial max stream data limit");
module_param(tquic_default_max_streams, uint, 0644);
MODULE_PARM_DESC(tquic_default_max_streams, "Default initial max streams");
module_param(tquic_default_initial_rtt_ms, uint, 0644);
MODULE_PARM_DESC(tquic_default_initial_rtt_ms,
	"Default initial RTT in ms, 1-60000 (default 333)");

/*
 * Module parameter validation bounds
 */
#define TQUIC_IDLE_TIMEOUT_MIN_MS	1
#define TQUIC_IDLE_TIMEOUT_MAX_MS	600000
#define TQUIC_IDLE_TIMEOUT_DEFAULT_MS	30000

#define TQUIC_HS_TIMEOUT_MIN_MS		1
#define TQUIC_HS_TIMEOUT_MAX_MS		120000
#define TQUIC_HS_TIMEOUT_DEFAULT_MS	10000

#define TQUIC_MAX_DATA_MIN		1024
#define TQUIC_MAX_DATA_MAX		16777216
#define TQUIC_MAX_DATA_DEFAULT		1048576

#define TQUIC_MAX_STREAM_DATA_MIN	1024
#define TQUIC_MAX_STREAM_DATA_MAX	16777216
#define TQUIC_MAX_STREAM_DATA_DEFAULT	65536

#define TQUIC_MAX_STREAMS_MIN		1
#define TQUIC_MAX_STREAMS_MAX		65535
#define TQUIC_MAX_STREAMS_DEFAULT	100

#define TQUIC_INITIAL_RTT_MIN_MS	1
#define TQUIC_INITIAL_RTT_MAX_MS	60000
#define TQUIC_INITIAL_RTT_DEFAULT_MS	333

static inline unsigned int tquic_get_validated_idle_timeout(void)
{
	unsigned int val = READ_ONCE(tquic_default_idle_timeout_ms);

	if (val < TQUIC_IDLE_TIMEOUT_MIN_MS || val > TQUIC_IDLE_TIMEOUT_MAX_MS) {
		tquic_warn("idle_timeout_ms %u out of range, using %u\n",
			     val, TQUIC_IDLE_TIMEOUT_DEFAULT_MS);
		return TQUIC_IDLE_TIMEOUT_DEFAULT_MS;
	}
	return val;
}

static inline unsigned int tquic_get_validated_handshake_timeout(void)
{
	unsigned int val = READ_ONCE(tquic_default_handshake_timeout_ms);

	if (val < TQUIC_HS_TIMEOUT_MIN_MS || val > TQUIC_HS_TIMEOUT_MAX_MS) {
		tquic_warn("handshake_timeout_ms %u out of range, using %u\n",
			     val, TQUIC_HS_TIMEOUT_DEFAULT_MS);
		return TQUIC_HS_TIMEOUT_DEFAULT_MS;
	}
	return val;
}

static inline unsigned int tquic_get_validated_max_data(void)
{
	unsigned int val = READ_ONCE(tquic_default_max_data);

	if (val < TQUIC_MAX_DATA_MIN || val > TQUIC_MAX_DATA_MAX) {
		tquic_warn("max_data %u out of range, using %u\n",
			     val, TQUIC_MAX_DATA_DEFAULT);
		return TQUIC_MAX_DATA_DEFAULT;
	}
	return val;
}

static inline unsigned int tquic_get_validated_max_stream_data(void)
{
	unsigned int val = READ_ONCE(tquic_default_max_stream_data);

	if (val < TQUIC_MAX_STREAM_DATA_MIN || val > TQUIC_MAX_STREAM_DATA_MAX) {
		tquic_warn("max_stream_data %u out of range, using %u\n",
			     val, TQUIC_MAX_STREAM_DATA_DEFAULT);
		return TQUIC_MAX_STREAM_DATA_DEFAULT;
	}
	return val;
}

static inline unsigned int tquic_get_validated_max_streams(void)
{
	unsigned int val = READ_ONCE(tquic_default_max_streams);

	if (val < TQUIC_MAX_STREAMS_MIN || val > TQUIC_MAX_STREAMS_MAX) {
		tquic_warn("max_streams %u out of range, using %u\n",
			     val, TQUIC_MAX_STREAMS_DEFAULT);
		return TQUIC_MAX_STREAMS_DEFAULT;
	}
	return val;
}

static inline unsigned int tquic_get_validated_initial_rtt(void)
{
	unsigned int val = READ_ONCE(tquic_default_initial_rtt_ms);

	if (val < TQUIC_INITIAL_RTT_MIN_MS || val > TQUIC_INITIAL_RTT_MAX_MS) {
		tquic_warn("initial_rtt_ms %u out of range, using %u\n",
			     val, TQUIC_INITIAL_RTT_DEFAULT_MS);
		return TQUIC_INITIAL_RTT_DEFAULT_MS;
	}
	return val;
}

static atomic_long_t tquic_memory_allocated;
static struct percpu_counter tquic_sockets_allocated;
static unsigned long tquic_memory_pressure_val;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
/* Kernel 6.4+ uses percpu unsigned int for orphan_count */
static DEFINE_PER_CPU(unsigned int, tquic_orphan_count_percpu) __maybe_unused;
#else
static struct percpu_counter __maybe_unused tquic_orphan_count_percpu;
#endif

/*
 * Guard against double initialization on module reload or multiple init calls.
 * These flags track which subsystems have been successfully initialized to
 * ensure proper cleanup and prevent resource leaks (e.g., calling proto_register
 * twice causes kernel warnings, double percpu_counter_init leaks memory).
 */
static bool tquic_proto_registered __read_mostly;
static bool __maybe_unused tquic_percpu_initialized __read_mostly;

/* Forward declarations for proto_ops callbacks */
static int tquic_stream_release(struct socket *sock);
static int tquic_stream_bind(struct socket *sock, TQUIC_SOCKADDR *addr,
			     int addr_len);
static int tquic_stream_connect(struct socket *sock, TQUIC_SOCKADDR *addr,
				int addr_len, int flags);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 7, 0)
static int tquic_stream_accept(struct socket *sock, struct socket *newsock,
			       struct proto_accept_arg *arg);
#else
static int tquic_stream_accept(struct socket *sock, struct socket *newsock,
			       int flags, bool kern);
#endif
static int tquic_stream_getname(struct socket *sock, struct sockaddr *addr,
				int peer);
static __poll_t tquic_stream_poll(struct file *file, struct socket *sock,
				  poll_table *wait);
static int tquic_stream_ioctl(struct socket *sock, unsigned int cmd,
			      unsigned long arg);
static int tquic_stream_listen(struct socket *sock, int backlog);
static int tquic_stream_shutdown(struct socket *sock, int how);
static int tquic_stream_setsockopt(struct socket *sock, int level, int optname,
				   sockptr_t optval, unsigned int optlen);
static int tquic_stream_getsockopt(struct socket *sock, int level, int optname,
				   char __user *optval, int __user *optlen);
static int tquic_stream_sendmsg(struct socket *sock, struct msghdr *msg,
				size_t len);
static int tquic_stream_recvmsg(struct socket *sock, struct msghdr *msg,
				size_t len, int flags);

/* Forward declarations for proto callbacks */
static void tquic_proto_close(struct sock *sk, long timeout);
static int tquic_proto_pre_connect(struct sock *sk, TQUIC_SOCKADDR *addr,
				   int addr_len);
static int tquic_proto_connect(struct sock *sk, TQUIC_SOCKADDR *addr,
			       int addr_len);
static int tquic_proto_disconnect(struct sock *sk, int flags);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 7, 0)
static struct sock *tquic_proto_accept(struct sock *sk,
				       struct proto_accept_arg *arg);
#else
static struct sock *tquic_proto_accept(struct sock *sk,
				       int flags, int *err, bool kern);
#endif
static int tquic_proto_ioctl(struct sock *sk, int cmd, int *karg);
static int tquic_proto_init_sock(struct sock *sk);
static void tquic_proto_destroy_sock(struct sock *sk);
static void tquic_proto_shutdown(struct sock *sk, int how);
static int tquic_proto_setsockopt(struct sock *sk, int level, int optname,
				  sockptr_t optval, unsigned int optlen);
static int tquic_proto_getsockopt(struct sock *sk, int level, int optname,
				  char __user *optval, int __user *optlen);
static int tquic_proto_sendmsg(struct sock *sk, struct msghdr *msg, size_t len);
static int tquic_proto_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
			       int flags, int *addr_len);
static int tquic_proto_bind(struct sock *sk, TQUIC_SOCKADDR *addr,
			    int addr_len);
static int tquic_proto_backlog_rcv(struct sock *sk, struct sk_buff *skb);
static void tquic_proto_release_cb(struct sock *sk);
static int tquic_proto_hash(struct sock *sk);
static void tquic_proto_unhash(struct sock *sk);
static int tquic_proto_get_port(struct sock *sk, unsigned short snum);

/* Compat wrapper for proto.setsockopt on kernels < 5.9 (no sockptr_t) */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
static int tquic_proto_setsockopt_compat(struct sock *sk, int level,
					 int optname, char __user *optval,
					 unsigned int optlen)
{
	return tquic_proto_setsockopt(sk, level, optname,
				      USER_SOCKPTR(optval), optlen);
}
#endif

/* Compat wrapper for proto.recvmsg on kernels < 5.19 (6-arg signature) */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 19, 0)
TQUIC_DEFINE_RECVMSG_WRAPPER(tquic_proto_recvmsg_compat, tquic_proto_recvmsg)
#endif

/*
 * Compat wrapper for proto.ioctl on kernels < 6.4.
 * Before 6.4, proto.ioctl signature is:
 *   int (*)(struct sock *, int cmd, unsigned long arg)
 * From 6.4+, it changed to:
 *   int (*)(struct sock *, int cmd, int *karg)
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
static int tquic_proto_ioctl_compat(struct sock *sk, int cmd, unsigned long arg)
{
	int karg;
	int err;

	err = tquic_proto_ioctl(sk, cmd, &karg);
	if (!err && put_user(karg, (int __user *)arg))
		return -EFAULT;
	return err;
}
#endif

/* TQUIC protocol identifier */
static struct proto tquic_prot = {
	.name			= "TQUIC",
	.owner			= THIS_MODULE,
	.close			= tquic_proto_close,
	.pre_connect		= tquic_proto_pre_connect,
	.connect		= tquic_proto_connect,
	.disconnect		= tquic_proto_disconnect,
	.accept			= tquic_proto_accept,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
	.ioctl			= tquic_proto_ioctl,
#else
	.ioctl			= tquic_proto_ioctl_compat,
#endif
	.init			= tquic_proto_init_sock,
	.destroy		= tquic_proto_destroy_sock,
	.shutdown		= tquic_proto_shutdown,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
	.setsockopt		= tquic_proto_setsockopt,
#else
	.setsockopt		= tquic_proto_setsockopt_compat,
#endif
	.getsockopt		= tquic_proto_getsockopt,
	.sendmsg		= tquic_proto_sendmsg,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 19, 0)
	.recvmsg		= tquic_proto_recvmsg,
#else
	.recvmsg		= tquic_proto_recvmsg_compat,
#endif
	.bind			= tquic_proto_bind,
	.backlog_rcv		= tquic_proto_backlog_rcv,
	.release_cb		= tquic_proto_release_cb,
	.hash			= tquic_proto_hash,
	.unhash			= tquic_proto_unhash,
	.get_port		= tquic_proto_get_port,
	.memory_allocated	= &tquic_memory_allocated,
	.sysctl_mem		= sysctl_tquic_mem,
	.sysctl_wmem		= sysctl_tquic_wmem,
	.sysctl_rmem		= sysctl_tquic_rmem,
	.sockets_allocated	= &tquic_sockets_allocated,
	/* orphan_count removed in kernel 6.12+ */
	.memory_pressure	= &tquic_memory_pressure_val,
	.obj_size		= sizeof(struct tquic_sock),
	.slab_flags		= SLAB_TYPESAFE_BY_RCU,
	.no_autobind		= true,
};

#if IS_ENABLED(CONFIG_IPV6)
static struct proto tquicv6_prot = {
	.name			= "TQUICv6",
	.owner			= THIS_MODULE,
	.close			= tquic_proto_close,
	.pre_connect		= tquic_proto_pre_connect,
	.connect		= tquic_proto_connect,
	.disconnect		= tquic_proto_disconnect,
	.accept			= tquic_proto_accept,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
	.ioctl			= tquic_proto_ioctl,
#else
	.ioctl			= tquic_proto_ioctl_compat,
#endif
	.init			= tquic_proto_init_sock,
	.destroy		= tquic_proto_destroy_sock,
	.shutdown		= tquic_proto_shutdown,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
	.setsockopt		= tquic_proto_setsockopt,
#else
	.setsockopt		= tquic_proto_setsockopt_compat,
#endif
	.getsockopt		= tquic_proto_getsockopt,
	.sendmsg		= tquic_proto_sendmsg,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 19, 0)
	.recvmsg		= tquic_proto_recvmsg,
#else
	.recvmsg		= tquic_proto_recvmsg_compat,
#endif
	.bind			= tquic_proto_bind,
	.backlog_rcv		= tquic_proto_backlog_rcv,
	.release_cb		= tquic_proto_release_cb,
	.hash			= tquic_proto_hash,
	.unhash			= tquic_proto_unhash,
	.get_port		= tquic_proto_get_port,
	.memory_allocated	= &tquic_memory_allocated,
	.sysctl_mem		= sysctl_tquic_mem,
	.sysctl_wmem		= sysctl_tquic_wmem,
	.sysctl_rmem		= sysctl_tquic_rmem,
	.sockets_allocated	= &tquic_sockets_allocated,
	/* orphan_count removed in kernel 6.12+ */
	.memory_pressure	= &tquic_memory_pressure_val,
	.obj_size		= sizeof(struct tquic_sock),
	.slab_flags		= SLAB_TYPESAFE_BY_RCU,
	.no_autobind		= true,
};
#endif

static void tquic_proto_close(struct sock *sk, long timeout)
{
	struct tquic_sock *tsk = tquic_sk(sk);
	struct tquic_connection *conn = tsk->conn;

	lock_sock(sk);

	if (conn && conn->state != TQUIC_CONN_CLOSED) {
		tquic_conn_close_with_error(conn, EQUIC_NO_ERROR, NULL);
		conn->state = TQUIC_CONN_CLOSING;
		/* Set timer for draining period */
		if (conn->active_path && conn->timer_state) {
			/* 3 * smoothed_rtt draining period per RFC 9000 */
		}
	}

	sk->sk_shutdown = SHUTDOWN_MASK;
	sk_common_release(sk);
	release_sock(sk);
}

static int tquic_proto_pre_connect(struct sock *sk, TQUIC_SOCKADDR *uaddr,
				   int addr_len)
{
	struct sockaddr *addr = (struct sockaddr *)uaddr;
	if (addr->sa_family != AF_INET && addr->sa_family != AF_INET6)
		return -EAFNOSUPPORT;

	return 0;
}

static int tquic_proto_connect(struct sock *sk, TQUIC_SOCKADDR *uaddr,
			       int addr_len)
{
	struct sockaddr *addr = (struct sockaddr *)uaddr;
	struct tquic_sock *tsk = tquic_sk(sk);
	struct tquic_connection *conn;
	int err;

	lock_sock(sk);

	if (tsk->conn) {
		err = -EISCONN;
		goto out;
	}

	conn = tquic_conn_create(tsk, false);
	if (!conn) {
		err = -ENOMEM;
		goto out;
	}

	err = tquic_conn_client_connect(conn, addr);
	if (err) {
		tquic_conn_destroy(conn);
		tsk->conn = NULL;
		goto out;
	}

	tsk->conn = conn;
	sk->sk_state = TCP_SYN_SENT;
	err = 0;

out:
	release_sock(sk);
	return err;
}

static int tquic_proto_disconnect(struct sock *sk, int flags)
{
	struct tquic_sock *tsk = tquic_sk(sk);
	struct tquic_connection *conn = tsk->conn;

	if (conn) {
		tquic_conn_close_with_error(conn, EQUIC_NO_ERROR, NULL);
		tquic_conn_destroy(conn);
		tsk->conn = NULL;
	}

	sk->sk_state = TCP_CLOSE;
	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 7, 0)
static struct sock *tquic_proto_accept(struct sock *sk,
				       struct proto_accept_arg *arg)
{
	struct tquic_sock *tsk = tquic_sk(sk);
	struct tquic_sock *newtsk;
	struct sock *newsk;
	DEFINE_WAIT(wait);

	lock_sock(sk);

	if (sk->sk_state != TCP_LISTEN) {
		arg->err = -EINVAL;
		release_sock(sk);
		return NULL;
	}

	while (list_empty(&tsk->accept_queue)) {
		if (arg->flags & O_NONBLOCK) {
			arg->err = -EAGAIN;
			release_sock(sk);
			return NULL;
		}

		prepare_to_wait_exclusive(sk_sleep(sk), &wait,
					  TASK_INTERRUPTIBLE);
		release_sock(sk);

		if (signal_pending(current)) {
			finish_wait(sk_sleep(sk), &wait);
			arg->err = -ERESTARTSYS;
			return NULL;
		}

		schedule();
		lock_sock(sk);
		finish_wait(sk_sleep(sk), &wait);
	}

	newsk = sk_alloc(sock_net(sk), sk->sk_family, GFP_KERNEL,
#if IS_ENABLED(CONFIG_IPV6)
			 sk->sk_family == AF_INET6 ? &tquicv6_prot :
#endif
			 &tquic_prot, false);
	if (!newsk) {
		arg->err = -ENOMEM;
		release_sock(sk);
		return NULL;
	}

	sock_init_data(NULL, newsk);
	newtsk = tquic_sk(newsk);

	newsk->sk_state = TCP_ESTABLISHED;
	arg->err = 0;

	release_sock(sk);
	return newsk;
}
#else
static struct sock *tquic_proto_accept(struct sock *sk,
				       int flags, int *err, bool kern)
{
	struct tquic_sock *tsk = tquic_sk(sk);
	struct tquic_sock *newtsk;
	struct sock *newsk;
	DEFINE_WAIT(wait);

	lock_sock(sk);

	if (sk->sk_state != TCP_LISTEN) {
		*err = -EINVAL;
		release_sock(sk);
		return NULL;
	}

	while (list_empty(&tsk->accept_queue)) {
		if (flags & O_NONBLOCK) {
			*err = -EAGAIN;
			release_sock(sk);
			return NULL;
		}

		prepare_to_wait_exclusive(sk_sleep(sk), &wait,
					  TASK_INTERRUPTIBLE);
		release_sock(sk);

		if (signal_pending(current)) {
			finish_wait(sk_sleep(sk), &wait);
			*err = -ERESTARTSYS;
			return NULL;
		}

		schedule();
		lock_sock(sk);
		finish_wait(sk_sleep(sk), &wait);
	}

	newsk = sk_alloc(sock_net(sk), sk->sk_family, GFP_KERNEL,
#if IS_ENABLED(CONFIG_IPV6)
			 sk->sk_family == AF_INET6 ? &tquicv6_prot :
#endif
			 &tquic_prot, false);
	if (!newsk) {
		*err = -ENOMEM;
		release_sock(sk);
		return NULL;
	}

	sock_init_data(NULL, newsk);
	newtsk = tquic_sk(newsk);

	newsk->sk_state = TCP_ESTABLISHED;
	*err = 0;

	release_sock(sk);
	return newsk;
}
#endif

static int tquic_proto_ioctl(struct sock *sk, int cmd, int *karg)
{
	struct tquic_sock *tsk = tquic_sk(sk);
	struct tquic_connection *conn = tsk->conn;

	switch (cmd) {
	case SIOCOUTQ:
		if (conn && conn->active_path)
			*karg = conn->active_path->cc.bytes_in_flight;
		else
			*karg = 0;
		return 0;

	case SIOCINQ:
		*karg = sk_rmem_alloc_get(sk);
		return 0;

	default:
		return -ENOIOCTLCMD;
	}
}

static int tquic_proto_init_sock(struct sock *sk)
{
	struct tquic_sock *tsk = tquic_sk(sk);

	tsk->conn = NULL;

	/* Initialize default socket state */
	memset(&tsk->bind_addr, 0, sizeof(tsk->bind_addr));
	memset(&tsk->connect_addr, 0, sizeof(tsk->connect_addr));

	INIT_LIST_HEAD(&tsk->accept_queue);
	INIT_LIST_HEAD(&tsk->accept_list);
	tsk->accept_queue_len = 0;
	tsk->max_accept_queue = 0;

	tsk->default_stream = NULL;
	tsk->handshake_state = NULL;
	tsk->flags = 0;

	/* Socket options */
	tsk->nodelay = false;
	tsk->pacing_enabled = true;  /* Default enabled per CONTEXT.md */

	/* Clear scheduler/congestion preferences */
	memset(tsk->requested_scheduler, 0, sizeof(tsk->requested_scheduler));
	memset(tsk->requested_congestion, 0, sizeof(tsk->requested_congestion));

	/* Clear PSK identity */
	memset(tsk->psk_identity, 0, sizeof(tsk->psk_identity));
	tsk->psk_identity_len = 0;

	/* Clear server name */
	memset(tsk->server_name, 0, sizeof(tsk->server_name));
	tsk->server_name_len = 0;

	/* Datagram support (disabled by default) */
	tsk->datagram_enabled = false;
	tsk->datagram_queue_max = TQUIC_DATAGRAM_QUEUE_DEFAULT;

	/* HTTP/3 support (disabled by default) */
	tsk->http3_enabled = false;
	tsk->http3_settings.max_table_capacity = TQUIC_HTTP3_DEFAULT_TABLE_CAPACITY;
	tsk->http3_settings.max_field_section_size = TQUIC_HTTP3_DEFAULT_FIELD_SECTION_SIZE;
	tsk->http3_settings.max_blocked_streams = TQUIC_HTTP3_DEFAULT_BLOCKED_STREAMS;
	tsk->http3_settings.server_push_enabled = false;
	tsk->h3_conn = NULL;

	/* Certificate verification (strict by default) */
	tsk->cert_verify.verify_mode = TQUIC_VERIFY_REQUIRED;
	tsk->cert_verify.verify_hostname = true;
	tsk->cert_verify.allow_self_signed = false;
	memset(tsk->cert_verify.expected_hostname, 0,
	       sizeof(tsk->cert_verify.expected_hostname));
	tsk->cert_verify.expected_hostname_len = 0;

	return 0;
}

static void tquic_proto_destroy_sock(struct sock *sk)
{
	struct tquic_sock *tsk = tquic_sk(sk);

	if (tsk->conn) {
		tquic_conn_destroy(tsk->conn);
		tsk->conn = NULL;
	}

	/* Clean up any remaining accept queue entries */
	/* (would need to close child connections) */
}

static void tquic_proto_shutdown(struct sock *sk, int how)
{
	struct tquic_sock *tsk = tquic_sk(sk);
	struct tquic_connection *conn = tsk->conn;

	if (!conn)
		return;

	if ((how & SEND_SHUTDOWN) && conn->state == TQUIC_CONN_CONNECTED) {
		tquic_conn_close_with_error(conn, EQUIC_NO_ERROR, NULL);
	}
}

static int tquic_proto_setsockopt(struct sock *sk, int level, int optname,
				  sockptr_t optval, unsigned int optlen)
{
	struct tquic_sock *tsk = tquic_sk(sk);
	int val, err = 0;

	if (level != SOL_TQUIC)
		return -ENOPROTOOPT;

	lock_sock(sk);

	switch (optname) {
	case TQUIC_NODELAY:
		if (optlen != sizeof(int)) {
			err = -EINVAL;
			break;
		}
		if (copy_from_sockptr(&val, optval, sizeof(val))) {
			err = -EFAULT;
			break;
		}
		tsk->nodelay = !!val;
		break;

	case TQUIC_CONGESTION:
		if (optlen > TQUIC_CC_NAME_MAX) {
			err = -EINVAL;
			break;
		}
		if (tsk->conn) {
			/* Cannot change CC after connection established */
			err = -EISCONN;
			break;
		}
		if (copy_from_sockptr(tsk->requested_congestion, optval, optlen)) {
			err = -EFAULT;
			break;
		}
		tsk->requested_congestion[optlen < TQUIC_CC_NAME_MAX ? optlen : TQUIC_CC_NAME_MAX - 1] = '\0';
		break;

	case TQUIC_SCHEDULER:
		if (optlen > TQUIC_SCHED_NAME_MAX) {
			err = -EINVAL;
			break;
		}
		if (tsk->conn) {
			/* Cannot change scheduler after connection established */
			err = -EISCONN;
			break;
		}
		if (copy_from_sockptr(tsk->requested_scheduler, optval, optlen)) {
			err = -EFAULT;
			break;
		}
		tsk->requested_scheduler[optlen < TQUIC_SCHED_NAME_MAX ? optlen : TQUIC_SCHED_NAME_MAX - 1] = '\0';
		break;

	case TQUIC_PACING:
		if (optlen != sizeof(int)) {
			err = -EINVAL;
			break;
		}
		if (copy_from_sockptr(&val, optval, sizeof(val))) {
			err = -EFAULT;
			break;
		}
		tsk->pacing_enabled = !!val;
		break;

	case TQUIC_IDLE_TIMEOUT:
		if (optlen != sizeof(int)) {
			err = -EINVAL;
			break;
		}
		if (copy_from_sockptr(&val, optval, sizeof(val))) {
			err = -EFAULT;
			break;
		}
		if (tsk->conn)
			tsk->conn->idle_timeout = val;
		break;

	case TQUIC_SO_DATAGRAM:
		if (optlen != sizeof(int)) {
			err = -EINVAL;
			break;
		}
		if (copy_from_sockptr(&val, optval, sizeof(val))) {
			err = -EFAULT;
			break;
		}
		tsk->datagram_enabled = !!val;
		break;

	case TQUIC_SO_HTTP3_ENABLE:
		if (optlen != sizeof(int)) {
			err = -EINVAL;
			break;
		}
		if (copy_from_sockptr(&val, optval, sizeof(val))) {
			err = -EFAULT;
			break;
		}
		if (tsk->conn) {
			/* Cannot enable HTTP/3 after connection established */
			err = -EISCONN;
			break;
		}
		tsk->http3_enabled = !!val;
		break;

	case TQUIC_CERT_VERIFY_MODE:
		if (optlen != sizeof(int)) {
			err = -EINVAL;
			break;
		}
		if (tsk->conn) {
			err = -EISCONN;
			break;
		}
		if (copy_from_sockptr(&val, optval, sizeof(val))) {
			err = -EFAULT;
			break;
		}
		if (val < TQUIC_VERIFY_NONE || val > TQUIC_VERIFY_REQUIRED) {
			err = -EINVAL;
			break;
		}
		tsk->cert_verify.verify_mode = val;
		break;

	case TQUIC_ALLOW_SELF_SIGNED:
		if (optlen != sizeof(int)) {
			err = -EINVAL;
			break;
		}
		if (tsk->conn) {
			err = -EISCONN;
			break;
		}
		if (copy_from_sockptr(&val, optval, sizeof(val))) {
			err = -EFAULT;
			break;
		}
		tsk->cert_verify.allow_self_signed = !!val;
		break;

	case TQUIC_PSK_IDENTITY:
		if (optlen > TQUIC_MAX_PSK_IDENTITY_LEN) {
			err = -EINVAL;
			break;
		}
		if (copy_from_sockptr(tsk->psk_identity, optval, optlen)) {
			err = -EFAULT;
			break;
		}
		tsk->psk_identity_len = optlen;
		break;

	default:
		err = -ENOPROTOOPT;
	}

	release_sock(sk);
	return err;
}

static int tquic_proto_getsockopt(struct sock *sk, int level, int optname,
				  char __user *optval, int __user *optlen)
{
	struct tquic_sock *tsk = tquic_sk(sk);
	int len, val, err = 0;

	if (level != SOL_TQUIC)
		return -ENOPROTOOPT;

	if (get_user(len, optlen))
		return -EFAULT;

	lock_sock(sk);

	switch (optname) {
	case TQUIC_NODELAY:
		val = tsk->nodelay;
		if (put_user(sizeof(int), optlen)) {
			err = -EFAULT;
			break;
		}
		if (copy_to_user(optval, &val, sizeof(int)))
			err = -EFAULT;
		break;

	case TQUIC_INFO:
		if (len < sizeof(struct tquic_info)) {
			err = -EINVAL;
			break;
		}
		if (tsk->conn) {
			struct tquic_info info = {
				.state = tsk->conn->state,
				.paths_active = tsk->conn->num_paths,
				.version = tsk->conn->version,
				.idle_timeout = tsk->conn->idle_timeout,
			};

			if (tsk->conn->active_path) {
				info.rtt = tsk->conn->active_path->cc.smoothed_rtt_us;
				info.rtt_var = tsk->conn->active_path->cc.rtt_var_us;
				info.cwnd = tsk->conn->active_path->cc.cwnd;
			}

			info.bytes_sent = tsk->conn->stats.tx_bytes;
			info.bytes_received = tsk->conn->stats.rx_bytes;
			info.packets_sent = tsk->conn->stats.tx_packets;
			info.packets_received = tsk->conn->stats.rx_packets;
			info.packets_lost = tsk->conn->stats.lost_packets;

			if (copy_to_user(optval, &info, sizeof(info))) {
				err = -EFAULT;
				break;
			}
			if (put_user(sizeof(info), optlen)) {
				err = -EFAULT;
				break;
			}
		} else {
			err = -ENOTCONN;
		}
		break;

	case TQUIC_PACING:
		val = tsk->pacing_enabled;
		if (put_user(sizeof(int), optlen)) {
			err = -EFAULT;
			break;
		}
		if (copy_to_user(optval, &val, sizeof(int)))
			err = -EFAULT;
		break;

	default:
		err = -ENOPROTOOPT;
	}

	release_sock(sk);
	return err;
}

static int tquic_proto_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
{
	struct tquic_sock *tsk = tquic_sk(sk);
	struct tquic_connection *conn = tsk->conn;

	if (!conn || conn->state != TQUIC_CONN_CONNECTED)
		return -ENOTCONN;

	/* Use tquic_sendmsg from tquic.h */
	return tquic_sendmsg(sk, msg, len);
}

static int tquic_proto_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
			       int flags, int *addr_len)
{
	struct tquic_sock *tsk = tquic_sk(sk);
	struct tquic_connection *conn = tsk->conn;

	if (!conn)
		return -ENOTCONN;

	/* Use tquic_recvmsg from tquic.h */
	return tquic_recvmsg(sk, msg, len, flags, addr_len);
}

static int tquic_proto_bind(struct sock *sk, TQUIC_SOCKADDR *uaddr,
			    int addr_len)
{
	struct sockaddr *addr = (struct sockaddr *)uaddr;
	struct tquic_sock *tsk = tquic_sk(sk);

	/* Store bind address */
	if (addr_len > sizeof(tsk->bind_addr))
		return -EINVAL;

	memcpy(&tsk->bind_addr, addr, addr_len);

	/* Set up UDP encapsulation for QUIC */
	return tquic_setup_udp_encap(sk);
}

static int tquic_proto_backlog_rcv(struct sock *sk, struct sk_buff *skb)
{
	struct tquic_sock *tsk = tquic_sk(sk);

	if (tsk->conn)
		return tquic_udp_recv(sk, skb);
	else
		kfree_skb(skb);

	return 0;
}

static void tquic_proto_release_cb(struct sock *sk)
{
	struct tquic_sock *tsk = tquic_sk(sk);
	struct tquic_connection *conn = tsk->conn;

	if (conn && conn->timer_state) {
		/* Update timers after socket unlock */
	}
}

static int tquic_proto_hash(struct sock *sk)
{
	/* TQUIC uses connection IDs for demuxing, not port hash */
	return 0;
}

static void tquic_proto_unhash(struct sock *sk)
{
	struct tquic_sock *tsk = tquic_sk(sk);
	struct tquic_connection *conn = tsk->conn;

	if (conn) {
		/* Remove connection from CID hash table */
	}
}

static int tquic_proto_get_port(struct sock *sk, unsigned short snum)
{
	/* Port allocation handled by UDP encapsulation socket */
	return 0;
}

/* Compat wrapper for proto_ops.setsockopt on kernels < 5.9 (no sockptr_t) */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
static int tquic_stream_setsockopt_compat(struct socket *sock, int level,
					  int optname, char __user *optval,
					  unsigned int optlen)
{
	return tquic_stream_setsockopt(sock, level, optname,
				       USER_SOCKPTR(optval), optlen);
}
#endif

static const struct proto_ops tquic_stream_ops = {
	.family		= PF_INET,
	.owner		= THIS_MODULE,
	.release	= tquic_stream_release,
	.bind		= tquic_stream_bind,
	.connect	= tquic_stream_connect,
	.socketpair	= sock_no_socketpair,
	.accept		= tquic_stream_accept,
	.getname	= tquic_stream_getname,
	.poll		= tquic_stream_poll,
	.ioctl		= tquic_stream_ioctl,
	.listen		= tquic_stream_listen,
	.shutdown	= tquic_stream_shutdown,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 9, 0)
	.setsockopt	= tquic_stream_setsockopt,
#else
	.setsockopt	= tquic_stream_setsockopt_compat,
#endif
	.getsockopt	= tquic_stream_getsockopt,
	.sendmsg	= tquic_stream_sendmsg,
	.recvmsg	= tquic_stream_recvmsg,
	.mmap		= sock_no_mmap,
};

static int tquic_stream_release(struct socket *sock)
{
	struct sock *sk = sock->sk;

	if (!sk)
		return 0;

	sock->sk = NULL;
	sock_put(sk);
	return 0;
}

static int tquic_stream_bind(struct socket *sock, TQUIC_SOCKADDR *addr,
			     int addr_len)
{
	struct sock *sk = sock->sk;
	return tquic_proto_bind(sk, addr, addr_len);
}

static int tquic_stream_connect(struct socket *sock, TQUIC_SOCKADDR *addr,
				int addr_len, int flags)
{
	struct sock *sk = sock->sk;
	int err;

	err = tquic_connect(sk, addr, addr_len);
	if (err)
		return err;

	/* Wait for handshake to complete if blocking */
	if (!(flags & O_NONBLOCK)) {
		struct tquic_sock *tsk = tquic_sk(sk);
		DEFINE_WAIT(wait);

		while (tsk->conn && tsk->conn->state == TQUIC_CONN_CONNECTING) {
			prepare_to_wait(sk_sleep(sk), &wait, TASK_INTERRUPTIBLE);

			if (signal_pending(current)) {
				finish_wait(sk_sleep(sk), &wait);
				return -ERESTARTSYS;
			}

			release_sock(sk);
			schedule();
			lock_sock(sk);
			finish_wait(sk_sleep(sk), &wait);
		}

		if (!tsk->conn || tsk->conn->state != TQUIC_CONN_CONNECTED)
			return -ECONNREFUSED;
	}

	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 7, 0)
static int tquic_stream_accept(struct socket *sock, struct socket *newsock,
			       struct proto_accept_arg *arg)
{
	struct sock *newsk;
	int err;
	int flags = arg ? arg->flags : 0;
	bool kern = arg ? arg->kern : false;

	err = tquic_accept(sock->sk, &newsk, flags, kern);
	if (err)
		return err;

	newsock->sk = newsk;
	newsock->ops = sock->ops;
	sock_graft(newsk, newsock);

	return 0;
}
#else
static int tquic_stream_accept(struct socket *sock, struct socket *newsock,
			       int flags, bool kern)
{
	struct sock *newsk;
	int err;

	err = tquic_accept(sock->sk, &newsk, flags, kern);
	if (err)
		return err;

	newsock->sk = newsk;
	newsock->ops = sock->ops;
	sock_graft(newsk, newsock);

	return 0;
}
#endif

static int tquic_stream_getname(struct socket *sock, struct sockaddr *addr,
				int peer)
{
	struct sock *sk = sock->sk;
	struct tquic_sock *tsk = tquic_sk(sk);
	struct tquic_connection *conn = tsk->conn;
	struct sockaddr_storage *saddr;

	if (!conn)
		return -ENOTCONN;

	if (peer)
		saddr = &conn->active_path->remote_addr;
	else
		saddr = &conn->active_path->local_addr;

	memcpy(addr, saddr, sizeof(*saddr));

	if (addr->sa_family == AF_INET)
		return sizeof(struct sockaddr_in);
	else
		return sizeof(struct sockaddr_in6);
}

static __poll_t tquic_stream_poll(struct file *file, struct socket *sock,
				  poll_table *wait)
{
	struct sock *sk = sock->sk;
	struct tquic_sock *tsk = tquic_sk(sk);
	struct tquic_connection *conn = tsk->conn;
	__poll_t mask = 0;

	sock_poll_wait(file, sock, wait);

	if (sk->sk_state == TCP_LISTEN)
		return !list_empty(&tsk->accept_queue) ? EPOLLIN | EPOLLRDNORM : 0;

	if (sk->sk_err)
		mask |= EPOLLERR;

	if (sk->sk_shutdown == SHUTDOWN_MASK || !conn)
		mask |= EPOLLHUP;

	if (sk->sk_shutdown & RCV_SHUTDOWN)
		mask |= EPOLLRDHUP;

	if (conn) {
		if (conn->state == TQUIC_CONN_CONNECTED) {
			if (sk_rmem_alloc_get(sk) > 0)
				mask |= EPOLLIN | EPOLLRDNORM;

			/* Check if we can send */
			if (tquic_conn_can_send(conn, 1))
				mask |= EPOLLOUT | EPOLLWRNORM;
		}
	}

	return mask;
}

static int tquic_stream_ioctl(struct socket *sock, unsigned int cmd,
			      unsigned long arg)
{
	struct sock *sk = sock->sk;
	int karg;
	int err;

	err = tquic_proto_ioctl(sk, cmd, &karg);
	if (!err && put_user(karg, (int __user *)arg))
		return -EFAULT;

	return err;
}

static int tquic_stream_listen(struct socket *sock, int backlog)
{
	struct sock *sk = sock->sk;
	struct tquic_sock *tsk = tquic_sk(sk);
	int err;

	lock_sock(sk);

	if (sk->sk_state != TCP_CLOSE) {
		err = -EINVAL;
		goto out;
	}

	err = tquic_setup_udp_encap(sk);
	if (err)
		goto out;

	sk->sk_max_ack_backlog = backlog;
	tsk->max_accept_queue = backlog;
	sk->sk_state = TCP_LISTEN;
	err = 0;

out:
	release_sock(sk);
	return err;
}

static int tquic_stream_shutdown(struct socket *sock, int how)
{
	struct sock *sk = sock->sk;
	tquic_proto_shutdown(sk, how);
	return 0;
}

static int tquic_stream_setsockopt(struct socket *sock, int level, int optname,
				   sockptr_t optval, unsigned int optlen)
{
	struct sock *sk = sock->sk;
	return tquic_proto_setsockopt(sk, level, optname, optval, optlen);
}

static int tquic_stream_getsockopt(struct socket *sock, int level, int optname,
				   char __user *optval, int __user *optlen)
{
	struct sock *sk = sock->sk;
	return tquic_proto_getsockopt(sk, level, optname, optval, optlen);
}

static int tquic_stream_sendmsg(struct socket *sock, struct msghdr *msg,
				size_t len)
{
	struct sock *sk = sock->sk;
	return tquic_sendmsg(sk, msg, len);
}

static int tquic_stream_recvmsg(struct socket *sock, struct msghdr *msg,
				size_t len, int flags)
{
	struct sock *sk = sock->sk;
	int addr_len = 0;
	return tquic_recvmsg(sk, msg, len, flags, &addr_len);
}

static int tquic_create(struct net *net, struct socket *sock, int protocol,
			int kern)
{
	struct sock *sk;
	int err;

	if (sock->type != SOCK_STREAM && sock->type != SOCK_DGRAM)
		return -ESOCKTNOSUPPORT;

	sock->state = SS_UNCONNECTED;
	sock->ops = &tquic_stream_ops;

	sk = sk_alloc(net, PF_INET, GFP_KERNEL, &tquic_prot, kern);
	if (!sk)
		return -ENOMEM;

	sock_init_data(sock, sk);

	err = tquic_proto_init_sock(sk);
	if (err) {
		sk_common_release(sk);
		return err;
	}

	return 0;
}

static const struct net_proto_family tquic_family_ops = {
	.family	= PF_INET,
	.create	= tquic_create,
	.owner	= THIS_MODULE,
};

static int __init __maybe_unused tquic_proto_register_all(void)
{
	int err;

	/* Guard against double registration */
	if (tquic_proto_registered) {
		tquic_warn("protocol already registered, skipping\n");
		return 0;
	}

	err = proto_register(&tquic_prot, 1);
	if (err)
		return err;

#if IS_ENABLED(CONFIG_IPV6)
	err = proto_register(&tquicv6_prot, 1);
	if (err) {
		proto_unregister(&tquic_prot);
		return err;
	}
#endif

	tquic_proto_registered = true;
	return 0;
}

static void __maybe_unused tquic_proto_unregister_all(void)
{
	if (!tquic_proto_registered)
		return;

#if IS_ENABLED(CONFIG_IPV6)
	proto_unregister(&tquicv6_prot);
#endif
	proto_unregister(&tquic_prot);
	tquic_proto_registered = false;
}

/*
 * Module init/exit for in-tree builds only.
 * For out-of-tree builds, tquic_main.c handles module init/exit.
 */
#ifndef TQUIC_OUT_OF_TREE
static int __init tquic_init(void)
{
	int err;

	BUILD_BUG_ON(sizeof(struct tquic_sock) > PAGE_SIZE);

	tquic_sock_cachep = kmem_cache_create("tquic_sock",
					      sizeof(struct tquic_sock), 0,
					      SLAB_HWCACHE_ALIGN, NULL);
	if (!tquic_sock_cachep)
		return -ENOMEM;

	tquic_conn_cachep = kmem_cache_create("tquic_conn",
					      sizeof(struct tquic_connection), 0,
					      SLAB_HWCACHE_ALIGN, NULL);
	if (!tquic_conn_cachep) {
		err = -ENOMEM;
		goto out_sock_cache;
	}

	tquic_stream_cachep = kmem_cache_create("tquic_stream",
						sizeof(struct tquic_stream), 0,
						SLAB_HWCACHE_ALIGN, NULL);
	if (!tquic_stream_cachep) {
		err = -ENOMEM;
		goto out_conn_cache;
	}

	/* Guard against double percpu_counter initialization */
	if (tquic_percpu_initialized) {
		tquic_warn("percpu counters already initialized\n");
	} else {
		err = percpu_counter_init(&tquic_sockets_allocated, 0, GFP_KERNEL);
		if (err)
			goto out_stream_cache;

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
		/* Only pre-6.4 uses percpu_counter for orphan count */
		err = percpu_counter_init(&tquic_orphan_count_percpu, 0, GFP_KERNEL);
		if (err)
			goto out_sockets_counter;
#endif
		tquic_percpu_initialized = true;
	}

	err = tquic_proto_register_all();
	if (err)
		goto out_orphan_counter;

	err = tquic_offload_init();
	if (err)
		goto out_proto;

	/* Initialize TQUIC bonding subsystem */
	err = tquic_bonding_init_module();
	if (err)
		goto out_offload;

	/* Initialize TQUIC path manager */
	err = tquic_path_init_module();
	if (err)
		goto out_bonding;

	/* Initialize TQUIC scheduler framework */
	err = tquic_scheduler_init();
	if (err)
		goto out_path;

	/* Initialize individual schedulers */
	err = tquic_sched_minrtt_init();
	if (err)
		goto out_sched;

	err = tquic_sched_aggregate_init();
	if (err)
		goto out_minrtt;

	err = tquic_sched_weighted_init();
	if (err)
		goto out_aggregate;

	err = tquic_sched_blest_init();
	if (err)
		goto out_weighted;

	err = tquic_sched_ecf_init();
	if (err)
		goto out_blest;

	/* Initialize coupled congestion control */
	err = coupled_cc_init_module();
	if (err)
		goto out_ecf;

	tquic_info("kernel implementation initialized\n");
	return 0;

out_ecf:
	tquic_sched_ecf_exit();
out_blest:
	tquic_sched_blest_exit();
out_weighted:
	tquic_sched_weighted_exit();
out_aggregate:
	tquic_sched_aggregate_exit();
out_minrtt:
	tquic_sched_minrtt_exit();
out_sched:
	tquic_scheduler_exit();
out_path:
	tquic_path_exit_module();
out_bonding:
	tquic_bonding_exit_module();
out_offload:
	tquic_offload_exit();
out_proto:
	tquic_proto_unregister_all();
out_orphan_counter:
	if (!tquic_percpu_initialized)
		goto out_stream_cache;
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
	percpu_counter_destroy(&tquic_orphan_count_percpu);
#endif
out_sockets_counter:
	percpu_counter_destroy(&tquic_sockets_allocated);
	tquic_percpu_initialized = false;
out_stream_cache:
	kmem_cache_destroy(tquic_stream_cachep);
out_conn_cache:
	kmem_cache_destroy(tquic_conn_cachep);
out_sock_cache:
	kmem_cache_destroy(tquic_sock_cachep);
	return err;
}

static void __exit tquic_exit(void)
{
	/* Cleanup TQUIC subsystems in reverse order */
	coupled_cc_exit_module();
	tquic_sched_ecf_exit();
	tquic_sched_blest_exit();
	tquic_sched_weighted_exit();
	tquic_sched_aggregate_exit();
	tquic_sched_minrtt_exit();
	tquic_scheduler_exit();
	tquic_path_exit_module();
	tquic_bonding_exit_module();

	tquic_offload_exit();
	tquic_proto_unregister_all();

	if (tquic_percpu_initialized) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
		percpu_counter_destroy(&tquic_orphan_count_percpu);
#endif
		percpu_counter_destroy(&tquic_sockets_allocated);
		tquic_percpu_initialized = false;
	}

	kmem_cache_destroy(tquic_stream_cachep);
	kmem_cache_destroy(tquic_conn_cachep);
	kmem_cache_destroy(tquic_sock_cachep);

	tquic_info("kernel implementation unloaded\n");
}

module_init(tquic_init);
module_exit(tquic_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Foundation");
MODULE_DESCRIPTION("TQUIC transport protocol with WAN bonding");
MODULE_VERSION("1.0");
#endif /* !TQUIC_OUT_OF_TREE */
