// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * QUIC - Quick UDP Internet Connections
 *
 * Linux kernel QUIC protocol implementation
 *
 * Copyright (c) 2024 Linux QUIC Authors
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/skbuff.h>
#include <linux/slab.h>
#include <linux/random.h>
#include <net/sock.h>
#include <net/inet_common.h>
#include <net/inet_hashtables.h>
#include <net/protocol.h>
#include <net/udp.h>
#include <net/quic.h>

static struct kmem_cache *quic_sock_cachep __read_mostly;
static struct kmem_cache *quic_conn_cachep __read_mostly;
static struct kmem_cache *quic_stream_cachep __read_mostly;

/* Sysctl variables */
int sysctl_quic_mem[3] __read_mostly;
int sysctl_quic_wmem[3] __read_mostly = { 4096, 16384, 4194304 };
int sysctl_quic_rmem[3] __read_mostly = { 4096, 131072, 6291456 };

static atomic_long_t quic_memory_allocated;
static struct percpu_counter quic_sockets_allocated;
static struct percpu_counter quic_orphan_count;

static int quic_memory_pressure;

/* QUIC protocol identifier */
static struct proto quic_prot = {
	.name			= "QUIC",
	.owner			= THIS_MODULE,
	.close			= quic_close,
	.pre_connect		= quic_pre_connect,
	.connect		= quic_connect,
	.disconnect		= quic_disconnect,
	.accept			= quic_accept,
	.ioctl			= quic_ioctl,
	.init			= quic_init_sock,
	.destroy		= quic_destroy_sock,
	.shutdown		= quic_shutdown,
	.setsockopt		= quic_setsockopt,
	.getsockopt		= quic_getsockopt,
	.sendmsg		= quic_sendmsg,
	.recvmsg		= quic_recvmsg,
	.bind			= quic_bind,
	.backlog_rcv		= quic_backlog_rcv,
	.release_cb		= quic_release_cb,
	.hash			= quic_hash,
	.unhash			= quic_unhash,
	.get_port		= quic_get_port,
	.memory_allocated	= &quic_memory_allocated,
	.sysctl_mem		= sysctl_quic_mem,
	.sysctl_wmem		= sysctl_quic_wmem,
	.sysctl_rmem		= sysctl_quic_rmem,
	.sockets_allocated	= &quic_sockets_allocated,
	.orphan_count		= &quic_orphan_count,
	.memory_pressure	= &quic_memory_pressure,
	.obj_size		= sizeof(struct quic_sock),
	.slab_flags		= SLAB_TYPESAFE_BY_RCU,
	.no_autobind		= true,
};

#if IS_ENABLED(CONFIG_IPV6)
static struct proto quicv6_prot = {
	.name			= "QUICv6",
	.owner			= THIS_MODULE,
	.close			= quic_close,
	.pre_connect		= quic_pre_connect,
	.connect		= quic_connect,
	.disconnect		= quic_disconnect,
	.accept			= quic_accept,
	.ioctl			= quic_ioctl,
	.init			= quic_init_sock,
	.destroy		= quic_destroy_sock,
	.shutdown		= quic_shutdown,
	.setsockopt		= quic_setsockopt,
	.getsockopt		= quic_getsockopt,
	.sendmsg		= quic_sendmsg,
	.recvmsg		= quic_recvmsg,
	.bind			= quic_bind,
	.backlog_rcv		= quic_backlog_rcv,
	.release_cb		= quic_release_cb,
	.hash			= quic_hash,
	.unhash			= quic_unhash,
	.get_port		= quic_get_port,
	.memory_allocated	= &quic_memory_allocated,
	.sysctl_mem		= sysctl_quic_mem,
	.sysctl_wmem		= sysctl_quic_wmem,
	.sysctl_rmem		= sysctl_quic_rmem,
	.sockets_allocated	= &quic_sockets_allocated,
	.orphan_count		= &quic_orphan_count,
	.memory_pressure	= &quic_memory_pressure,
	.obj_size		= sizeof(struct quic_sock),
	.slab_flags		= SLAB_TYPESAFE_BY_RCU,
	.no_autobind		= true,
};
#endif

void quic_close(struct sock *sk, long timeout)
{
	struct quic_sock *qsk = quic_sk(sk);
	struct quic_connection *conn = qsk->conn;

	lock_sock(sk);

	if (conn && conn->state != QUIC_STATE_CLOSED) {
		quic_conn_close(conn, QUIC_ERROR_NO_ERROR, NULL, 0, true);
		conn->state = QUIC_STATE_CLOSING;
		quic_timer_set(conn, QUIC_TIMER_IDLE,
			       ktime_add_ms(ktime_get(), 3 * conn->active_path->rtt.smoothed_rtt));
	}

	sk->sk_shutdown = SHUTDOWN_MASK;
	sk_common_release(sk);
	release_sock(sk);
}

int quic_pre_connect(struct sock *sk, struct sockaddr *addr, int addr_len)
{
	if (addr->sa_family != AF_INET && addr->sa_family != AF_INET6)
		return -EAFNOSUPPORT;

	return 0;
}

int quic_connect(struct sock *sk, struct sockaddr *addr, int addr_len)
{
	struct quic_sock *qsk = quic_sk(sk);
	struct quic_connection *conn;
	int err;

	lock_sock(sk);

	if (qsk->conn) {
		err = -EISCONN;
		goto out;
	}

	conn = quic_conn_create(qsk, false);
	if (!conn) {
		err = -ENOMEM;
		goto out;
	}

	err = quic_conn_connect(conn, addr, addr_len);
	if (err) {
		quic_conn_destroy(conn);
		qsk->conn = NULL;
		goto out;
	}

	qsk->conn = conn;
	sk->sk_state = TCP_SYN_SENT;
	err = 0;

out:
	release_sock(sk);
	return err;
}

int quic_disconnect(struct sock *sk, int flags)
{
	struct quic_sock *qsk = quic_sk(sk);
	struct quic_connection *conn = qsk->conn;

	if (conn) {
		quic_conn_close(conn, QUIC_ERROR_NO_ERROR, NULL, 0, true);
		quic_conn_destroy(conn);
		qsk->conn = NULL;
	}

	sk->sk_state = TCP_CLOSE;
	return 0;
}

struct sock *quic_accept(struct sock *sk, struct proto_accept_arg *arg)
{
	struct quic_sock *qsk = quic_sk(sk);
	struct quic_sock *newqsk;
	struct sock *newsk;
	DEFINE_WAIT(wait);

	lock_sock(sk);

	if (sk->sk_state != TCP_LISTEN) {
		arg->err = -EINVAL;
		release_sock(sk);
		return NULL;
	}

	while (skb_queue_empty(&qsk->event_queue)) {
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

	newsk = sk_alloc(sock_net(sk), sk->sk_family, GFP_KERNEL, &quic_prot, false);
	if (!newsk) {
		arg->err = -ENOMEM;
		release_sock(sk);
		return NULL;
	}

	sock_init_data(NULL, newsk);
	newqsk = quic_sk(newsk);

	newsk->sk_state = TCP_ESTABLISHED;
	arg->err = 0;

	release_sock(sk);
	return newsk;
}

int quic_ioctl(struct sock *sk, int cmd, int *karg)
{
	struct quic_sock *qsk = quic_sk(sk);
	struct quic_connection *conn = qsk->conn;

	switch (cmd) {
	case SIOCOUTQ:
		if (conn)
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

int quic_init_sock(struct sock *sk)
{
	struct quic_sock *qsk = quic_sk(sk);

	qsk->conn = NULL;
	qsk->udp_sock = NULL;

	/* Initialize default configuration */
	qsk->config.version = QUIC_VERSION_1;
	qsk->config.max_idle_timeout_ms = 30000;
	qsk->config.handshake_timeout_ms = 10000;
	qsk->config.initial_max_data = 1048576;
	qsk->config.initial_max_stream_data_bidi_local = 65536;
	qsk->config.initial_max_stream_data_bidi_remote = 65536;
	qsk->config.initial_max_stream_data_uni = 65536;
	qsk->config.initial_max_streams_bidi = 100;
	qsk->config.initial_max_streams_uni = 100;
	qsk->config.ack_delay_exponent = 3;
	qsk->config.max_ack_delay_ms = 25;
	qsk->config.initial_rtt_ms = 333;
	qsk->config.max_connection_ids = 8;

	qsk->alpn = NULL;
	qsk->alpn_len = 0;
	qsk->session_ticket = NULL;
	qsk->session_ticket_len = 0;
	qsk->token = NULL;
	qsk->token_len = 0;

	skb_queue_head_init(&qsk->event_queue);
	init_waitqueue_head(&qsk->event_wait);
	INIT_LIST_HEAD(&qsk->pending_streams);
	spin_lock_init(&qsk->pending_lock);

	qsk->events_enabled = 0;
	qsk->datagram_enabled = 0;
	qsk->zero_rtt_enabled = 0;

	return 0;
}

void quic_destroy_sock(struct sock *sk)
{
	struct quic_sock *qsk = quic_sk(sk);

	if (qsk->conn) {
		quic_conn_destroy(qsk->conn);
		qsk->conn = NULL;
	}

	if (qsk->udp_sock) {
		sock_release(qsk->udp_sock);
		qsk->udp_sock = NULL;
	}

	kfree(qsk->alpn);
	kfree(qsk->session_ticket);
	kfree(qsk->token);

	skb_queue_purge(&qsk->event_queue);
}

int quic_shutdown(struct sock *sk, int how)
{
	struct quic_sock *qsk = quic_sk(sk);
	struct quic_connection *conn = qsk->conn;

	if (!conn)
		return -ENOTCONN;

	if ((how & SEND_SHUTDOWN) && conn->state == QUIC_STATE_CONNECTED) {
		quic_conn_close(conn, QUIC_ERROR_NO_ERROR, NULL, 0, true);
	}

	return 0;
}

int quic_setsockopt(struct sock *sk, int level, int optname,
		    sockptr_t optval, unsigned int optlen)
{
	struct quic_sock *qsk = quic_sk(sk);
	int val, err = 0;

	if (level != SOL_QUIC)
		return -ENOPROTOOPT;

	lock_sock(sk);

	switch (optname) {
	case QUIC_SOCKOPT_EVENT:
		if (optlen != sizeof(int)) {
			err = -EINVAL;
			break;
		}
		if (copy_from_sockptr(&val, optval, sizeof(val))) {
			err = -EFAULT;
			break;
		}
		qsk->events_enabled = !!val;
		break;

	case QUIC_SOCKOPT_ALPN:
		if (optlen > QUIC_MAX_ALPN_LEN) {
			err = -EINVAL;
			break;
		}
		kfree(qsk->alpn);
		qsk->alpn = kmalloc(optlen, GFP_KERNEL);
		if (!qsk->alpn) {
			err = -ENOMEM;
			break;
		}
		if (copy_from_sockptr(qsk->alpn, optval, optlen)) {
			kfree(qsk->alpn);
			qsk->alpn = NULL;
			err = -EFAULT;
			break;
		}
		qsk->alpn_len = optlen;
		break;

	case QUIC_SOCKOPT_TRANSPORT_PARAM:
		if (optlen != sizeof(struct quic_transport_params)) {
			err = -EINVAL;
			break;
		}
		if (qsk->conn) {
			if (copy_from_sockptr(&qsk->conn->local_params, optval, optlen))
				err = -EFAULT;
		} else {
			err = -ENOTCONN;
		}
		break;

	case QUIC_SOCKOPT_CONFIG:
		if (optlen != sizeof(struct quic_config)) {
			err = -EINVAL;
			break;
		}
		if (copy_from_sockptr(&qsk->config, optval, optlen))
			err = -EFAULT;
		break;

	case QUIC_SOCKOPT_TOKEN:
		if (optlen > QUIC_MAX_TOKEN_LEN) {
			err = -EINVAL;
			break;
		}
		kfree(qsk->token);
		qsk->token = kmalloc(optlen, GFP_KERNEL);
		if (!qsk->token) {
			err = -ENOMEM;
			break;
		}
		if (copy_from_sockptr(qsk->token, optval, optlen)) {
			kfree(qsk->token);
			qsk->token = NULL;
			err = -EFAULT;
			break;
		}
		qsk->token_len = optlen;
		break;

	case QUIC_SOCKOPT_CONGESTION:
		if (optlen != sizeof(int)) {
			err = -EINVAL;
			break;
		}
		if (copy_from_sockptr(&val, optval, sizeof(val))) {
			err = -EFAULT;
			break;
		}
		if (qsk->conn && qsk->conn->active_path) {
			if (val >= 0 && val <= QUIC_CC_BBR2)
				qsk->conn->active_path->cc.algo = val;
			else
				err = -EINVAL;
		} else {
			err = -ENOTCONN;
		}
		break;

	case QUIC_SOCKOPT_CRYPTO_SECRET:
		if (optlen != sizeof(struct quic_crypto_info)) {
			err = -EINVAL;
			break;
		}
		if (qsk->conn) {
			struct quic_crypto_info info;
			if (copy_from_sockptr(&info, optval, optlen)) {
				err = -EFAULT;
				break;
			}
			err = quic_crypto_set_secret(qsk->conn, &info);
		} else {
			err = -ENOTCONN;
		}
		break;

	default:
		err = -ENOPROTOOPT;
	}

	release_sock(sk);
	return err;
}

int quic_getsockopt(struct sock *sk, int level, int optname,
		    char __user *optval, int __user *optlen)
{
	struct quic_sock *qsk = quic_sk(sk);
	int len, val, err = 0;

	if (level != SOL_QUIC)
		return -ENOPROTOOPT;

	if (get_user(len, optlen))
		return -EFAULT;

	lock_sock(sk);

	switch (optname) {
	case QUIC_SOCKOPT_EVENT:
		val = qsk->events_enabled;
		if (put_user(sizeof(int), optlen)) {
			err = -EFAULT;
			break;
		}
		if (copy_to_user(optval, &val, sizeof(int)))
			err = -EFAULT;
		break;

	case QUIC_SOCKOPT_TRANSPORT_PARAM:
		if (len < sizeof(struct quic_transport_params)) {
			err = -EINVAL;
			break;
		}
		if (qsk->conn) {
			if (put_user(sizeof(struct quic_transport_params), optlen)) {
				err = -EFAULT;
				break;
			}
			if (copy_to_user(optval, &qsk->conn->remote_params,
					 sizeof(struct quic_transport_params)))
				err = -EFAULT;
		} else {
			err = -ENOTCONN;
		}
		break;

	case QUIC_SOCKOPT_CONFIG:
		if (len < sizeof(struct quic_config)) {
			err = -EINVAL;
			break;
		}
		if (put_user(sizeof(struct quic_config), optlen)) {
			err = -EFAULT;
			break;
		}
		if (copy_to_user(optval, &qsk->config, sizeof(struct quic_config)))
			err = -EFAULT;
		break;

	default:
		err = -ENOPROTOOPT;
	}

	release_sock(sk);
	return err;
}

int quic_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
{
	struct quic_sock *qsk = quic_sk(sk);
	struct quic_connection *conn = qsk->conn;
	struct quic_stream *stream = NULL;
	struct quic_stream_info sinfo;
	struct cmsghdr *cmsg;
	u64 stream_id = 0;
	u32 flags = 0;
	int err;

	if (!conn || conn->state != QUIC_STATE_CONNECTED)
		return -ENOTCONN;

	/* Parse control message for stream info */
	for_each_cmsghdr(cmsg, msg) {
		if (!CMSG_OK(msg, cmsg))
			return -EINVAL;

		if (cmsg->cmsg_level != SOL_QUIC)
			continue;

		if (cmsg->cmsg_type == QUIC_CMSG_STREAM_INFO) {
			if (cmsg->cmsg_len < CMSG_LEN(sizeof(sinfo)))
				return -EINVAL;
			memcpy(&sinfo, CMSG_DATA(cmsg), sizeof(sinfo));
			stream_id = sinfo.stream_id;
			flags = sinfo.stream_flags;
		}
	}

	/* Find or create stream */
	if (flags & QUIC_STREAM_FLAG_NEW) {
		stream_id = quic_stream_next_id(conn, flags & QUIC_STREAM_FLAG_UNI);
		stream = quic_stream_create(conn, stream_id);
		if (!stream)
			return -ENOMEM;
	} else {
		stream = quic_stream_lookup(conn, stream_id);
		if (!stream)
			return -ENOENT;
	}

	err = quic_stream_send(stream, msg, len);

	if (flags & QUIC_STREAM_FLAG_FIN)
		stream->fin_sent = 1;

	return err;
}

int quic_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
		 int flags, int *addr_len)
{
	struct quic_sock *qsk = quic_sk(sk);
	struct quic_connection *conn = qsk->conn;
	struct quic_stream_info sinfo;
	struct quic_stream *stream;
	int copied = 0;
	int err;
	DEFINE_WAIT(wait);

	if (!conn)
		return -ENOTCONN;

	lock_sock(sk);

	/* Find a stream with available data */
	spin_lock(&conn->streams_lock);
	stream = rb_entry_safe(rb_first(&conn->streams), struct quic_stream, node);
	while (stream) {
		if (stream->recv.pending > 0)
			break;
		stream = rb_entry_safe(rb_next(&stream->node), struct quic_stream, node);
	}
	spin_unlock(&conn->streams_lock);

	if (!stream) {
		if (flags & MSG_DONTWAIT) {
			err = -EAGAIN;
			goto out;
		}

		/* Wait for data */
		prepare_to_wait(sk_sleep(sk), &wait, TASK_INTERRUPTIBLE);
		release_sock(sk);

		if (signal_pending(current)) {
			finish_wait(sk_sleep(sk), &wait);
			return -ERESTARTSYS;
		}

		schedule();
		lock_sock(sk);
		finish_wait(sk_sleep(sk), &wait);

		/* Retry finding stream */
		spin_lock(&conn->streams_lock);
		stream = rb_entry_safe(rb_first(&conn->streams), struct quic_stream, node);
		while (stream) {
			if (stream->recv.pending > 0)
				break;
			stream = rb_entry_safe(rb_next(&stream->node), struct quic_stream, node);
		}
		spin_unlock(&conn->streams_lock);

		if (!stream) {
			err = -EAGAIN;
			goto out;
		}
	}

	copied = quic_stream_recv(stream, msg, len);
	if (copied < 0) {
		err = copied;
		goto out;
	}

	/* Add stream info to cmsg */
	memset(&sinfo, 0, sizeof(sinfo));
	sinfo.stream_id = stream->id;
	if (stream->fin_received)
		sinfo.stream_flags |= QUIC_STREAM_FLAG_FIN;

	put_cmsg(msg, SOL_QUIC, QUIC_CMSG_STREAM_INFO, sizeof(sinfo), &sinfo);

	err = copied;

out:
	release_sock(sk);
	return err;
}

int quic_bind(struct sock *sk, struct sockaddr *addr, int addr_len)
{
	struct quic_sock *qsk = quic_sk(sk);
	int err;

	err = quic_udp_encap_init(qsk);
	if (err)
		return err;

	return kernel_bind(qsk->udp_sock, addr, addr_len);
}

int quic_backlog_rcv(struct sock *sk, struct sk_buff *skb)
{
	struct quic_sock *qsk = quic_sk(sk);

	if (qsk->conn)
		quic_packet_process(qsk->conn, skb);
	else
		kfree_skb(skb);

	return 0;
}

void quic_release_cb(struct sock *sk)
{
	struct quic_sock *qsk = quic_sk(sk);
	struct quic_connection *conn = qsk->conn;

	if (conn)
		quic_timer_update(conn);
}

void quic_hash(struct sock *sk)
{
	/* QUIC uses connection IDs for demuxing, not port hash */
}

void quic_unhash(struct sock *sk)
{
	struct quic_sock *qsk = quic_sk(sk);
	struct quic_connection *conn = qsk->conn;
	struct quic_cid_entry *entry, *tmp;

	if (conn) {
		list_for_each_entry_safe(entry, tmp, &conn->scid_list, list) {
			quic_cid_hash_del(entry);
		}
	}
}

int quic_get_port(struct sock *sk, unsigned short snum)
{
	/* Port allocation handled by UDP encapsulation socket */
	return 0;
}

int quic_crypto_set_secret(struct quic_connection *conn,
			   struct quic_crypto_info *info)
{
	struct quic_crypto_ctx *ctx;
	u8 level;

	if (info->version != 1)
		return -EINVAL;

	switch (info->cipher_type) {
	case QUIC_CIPHER_AES_128_GCM_SHA256:
	case QUIC_CIPHER_AES_256_GCM_SHA384:
	case QUIC_CIPHER_CHACHA20_POLY1305_SHA256:
		break;
	default:
		return -EINVAL;
	}

	level = conn->crypto_level;
	if (level >= QUIC_CRYPTO_MAX)
		return -EINVAL;

	ctx = &conn->crypto[level];

	memcpy(ctx->tx.key, info->tx_key, info->key_len);
	memcpy(ctx->rx.key, info->rx_key, info->key_len);
	memcpy(ctx->tx.iv, info->tx_iv, info->iv_len);
	memcpy(ctx->rx.iv, info->rx_iv, info->iv_len);
	memcpy(ctx->tx.hp_key, info->tx_hp_key, info->hp_key_len);
	memcpy(ctx->rx.hp_key, info->rx_hp_key, info->hp_key_len);

	ctx->tx.key_len = info->key_len;
	ctx->rx.key_len = info->key_len;
	ctx->tx.iv_len = info->iv_len;
	ctx->rx.iv_len = info->iv_len;
	ctx->tx.hp_key_len = info->hp_key_len;
	ctx->rx.hp_key_len = info->hp_key_len;

	ctx->cipher_type = info->cipher_type;
	ctx->keys_available = 1;

	return quic_crypto_init(ctx, info->cipher_type);
}

static const struct proto_ops quic_stream_ops = {
	.family		= PF_QUIC,
	.owner		= THIS_MODULE,
	.release	= quic_stream_release,
	.bind		= quic_stream_bind,
	.connect	= quic_stream_connect,
	.socketpair	= sock_no_socketpair,
	.accept		= quic_stream_accept,
	.getname	= quic_stream_getname,
	.poll		= quic_stream_poll,
	.ioctl		= quic_stream_ioctl,
	.listen		= quic_stream_listen,
	.shutdown	= quic_stream_shutdown,
	.setsockopt	= quic_stream_setsockopt,
	.getsockopt	= quic_stream_getsockopt,
	.sendmsg	= quic_stream_sendmsg,
	.recvmsg	= quic_stream_recvmsg,
	.mmap		= sock_no_mmap,
};

static int quic_stream_release(struct socket *sock)
{
	struct sock *sk = sock->sk;

	if (!sk)
		return 0;

	sock->sk = NULL;
	sock_put(sk);
	return 0;
}

static int quic_stream_bind(struct socket *sock, struct sockaddr *addr,
			    int addr_len)
{
	struct sock *sk = sock->sk;
	return quic_bind(sk, addr, addr_len);
}

static int quic_stream_connect(struct socket *sock, struct sockaddr *addr,
			       int addr_len, int flags)
{
	struct sock *sk = sock->sk;
	int err;

	err = quic_connect(sk, addr, addr_len);
	if (err)
		return err;

	/* Wait for handshake to complete if blocking */
	if (!(flags & O_NONBLOCK)) {
		struct quic_sock *qsk = quic_sk(sk);
		DEFINE_WAIT(wait);

		while (qsk->conn && qsk->conn->state == QUIC_STATE_CONNECTING) {
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

		if (!qsk->conn || qsk->conn->state != QUIC_STATE_CONNECTED)
			return -ECONNREFUSED;
	}

	return 0;
}

static int quic_stream_accept(struct socket *sock, struct socket *newsock,
			      int flags, bool kern)
{
	struct proto_accept_arg arg = {
		.flags = flags,
	};
	struct sock *sk = sock->sk;
	struct sock *newsk;

	newsk = quic_accept(sk, &arg);
	if (!newsk)
		return arg.err;

	newsock->sk = newsk;
	newsock->ops = sock->ops;
	sock_graft(newsk, newsock);

	return 0;
}

static int quic_stream_getname(struct socket *sock, struct sockaddr *addr,
			       int peer)
{
	struct sock *sk = sock->sk;
	struct quic_sock *qsk = quic_sk(sk);
	struct quic_connection *conn = qsk->conn;
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

static __poll_t quic_stream_poll(struct file *file, struct socket *sock,
				 poll_table *wait)
{
	struct sock *sk = sock->sk;
	struct quic_sock *qsk = quic_sk(sk);
	struct quic_connection *conn = qsk->conn;
	__poll_t mask = 0;

	sock_poll_wait(file, sock, wait);

	if (sk->sk_state == TCP_LISTEN)
		return !skb_queue_empty(&qsk->event_queue) ? EPOLLIN | EPOLLRDNORM : 0;

	if (sk->sk_err)
		mask |= EPOLLERR;

	if (sk->sk_shutdown == SHUTDOWN_MASK || !conn)
		mask |= EPOLLHUP;

	if (sk->sk_shutdown & RCV_SHUTDOWN)
		mask |= EPOLLRDHUP;

	if (conn) {
		if (conn->state == QUIC_STATE_CONNECTED) {
			if (sk_rmem_alloc_get(sk) > 0)
				mask |= EPOLLIN | EPOLLRDNORM;

			if (quic_flow_control_can_send(conn, 1))
				mask |= EPOLLOUT | EPOLLWRNORM;
		}
	}

	return mask;
}

static int quic_stream_ioctl(struct socket *sock, unsigned int cmd,
			     unsigned long arg)
{
	struct sock *sk = sock->sk;
	int karg;
	int err;

	err = quic_ioctl(sk, cmd, &karg);
	if (!err && put_user(karg, (int __user *)arg))
		return -EFAULT;

	return err;
}

static int quic_stream_listen(struct socket *sock, int backlog)
{
	struct sock *sk = sock->sk;
	struct quic_sock *qsk = quic_sk(sk);
	int err;

	lock_sock(sk);

	if (sk->sk_state != TCP_CLOSE) {
		err = -EINVAL;
		goto out;
	}

	if (!qsk->udp_sock) {
		err = quic_udp_encap_init(qsk);
		if (err)
			goto out;
	}

	sk->sk_max_ack_backlog = backlog;
	sk->sk_state = TCP_LISTEN;
	err = 0;

out:
	release_sock(sk);
	return err;
}

static int quic_stream_shutdown(struct socket *sock, int how)
{
	struct sock *sk = sock->sk;
	return quic_shutdown(sk, how);
}

static int quic_stream_setsockopt(struct socket *sock, int level, int optname,
				  sockptr_t optval, unsigned int optlen)
{
	struct sock *sk = sock->sk;
	return quic_setsockopt(sk, level, optname, optval, optlen);
}

static int quic_stream_getsockopt(struct socket *sock, int level, int optname,
				  char __user *optval, int __user *optlen)
{
	struct sock *sk = sock->sk;
	return quic_getsockopt(sk, level, optname, optval, optlen);
}

static int quic_stream_sendmsg(struct socket *sock, struct msghdr *msg,
			       size_t len)
{
	struct sock *sk = sock->sk;
	return quic_sendmsg(sk, msg, len);
}

static int quic_stream_recvmsg(struct socket *sock, struct msghdr *msg,
			       size_t len, int flags)
{
	struct sock *sk = sock->sk;
	int addr_len = 0;
	return quic_recvmsg(sk, msg, len, flags, &addr_len);
}

static int quic_create(struct net *net, struct socket *sock, int protocol,
		       int kern)
{
	struct sock *sk;
	int err;

	if (sock->type != SOCK_STREAM && sock->type != SOCK_DGRAM)
		return -ESOCKTNOSUPPORT;

	sock->state = SS_UNCONNECTED;
	sock->ops = &quic_stream_ops;

	sk = sk_alloc(net, PF_QUIC, GFP_KERNEL, &quic_prot, kern);
	if (!sk)
		return -ENOMEM;

	sock_init_data(sock, sk);

	err = quic_init_sock(sk);
	if (err) {
		sk_common_release(sk);
		return err;
	}

	return 0;
}

static const struct net_proto_family quic_family_ops = {
	.family	= PF_QUIC,
	.create	= quic_create,
	.owner	= THIS_MODULE,
};

static int __init quic_proto_register(void)
{
	int err;

	err = proto_register(&quic_prot, 1);
	if (err)
		return err;

#if IS_ENABLED(CONFIG_IPV6)
	err = proto_register(&quicv6_prot, 1);
	if (err) {
		proto_unregister(&quic_prot);
		return err;
	}
#endif

	err = sock_register(&quic_family_ops);
	if (err) {
#if IS_ENABLED(CONFIG_IPV6)
		proto_unregister(&quicv6_prot);
#endif
		proto_unregister(&quic_prot);
		return err;
	}

	return 0;
}

static void quic_proto_unregister(void)
{
	sock_unregister(PF_QUIC);
#if IS_ENABLED(CONFIG_IPV6)
	proto_unregister(&quicv6_prot);
#endif
	proto_unregister(&quic_prot);
}

static int __init quic_init(void)
{
	int err;

	BUILD_BUG_ON(sizeof(struct quic_sock) > PAGE_SIZE);

	quic_sock_cachep = kmem_cache_create("quic_sock",
					     sizeof(struct quic_sock), 0,
					     SLAB_HWCACHE_ALIGN, NULL);
	if (!quic_sock_cachep)
		return -ENOMEM;

	quic_conn_cachep = kmem_cache_create("quic_conn",
					     sizeof(struct quic_connection), 0,
					     SLAB_HWCACHE_ALIGN, NULL);
	if (!quic_conn_cachep) {
		err = -ENOMEM;
		goto out_sock_cache;
	}

	quic_stream_cachep = kmem_cache_create("quic_stream",
					       sizeof(struct quic_stream), 0,
					       SLAB_HWCACHE_ALIGN, NULL);
	if (!quic_stream_cachep) {
		err = -ENOMEM;
		goto out_conn_cache;
	}

	err = percpu_counter_init(&quic_sockets_allocated, 0, GFP_KERNEL);
	if (err)
		goto out_stream_cache;

	err = percpu_counter_init(&quic_orphan_count, 0, GFP_KERNEL);
	if (err)
		goto out_sockets_counter;

	err = quic_cid_hash_init();
	if (err)
		goto out_orphan_counter;

	err = quic_proto_register();
	if (err)
		goto out_cid_hash;

	err = quic_offload_init();
	if (err)
		goto out_proto;

	pr_info("QUIC: kernel implementation initialized\n");
	return 0;

out_proto:
	quic_proto_unregister();
out_cid_hash:
	quic_cid_hash_cleanup();
out_orphan_counter:
	percpu_counter_destroy(&quic_orphan_count);
out_sockets_counter:
	percpu_counter_destroy(&quic_sockets_allocated);
out_stream_cache:
	kmem_cache_destroy(quic_stream_cachep);
out_conn_cache:
	kmem_cache_destroy(quic_conn_cachep);
out_sock_cache:
	kmem_cache_destroy(quic_sock_cachep);
	return err;
}

static void __exit quic_exit(void)
{
	quic_offload_exit();
	quic_proto_unregister();
	quic_cid_hash_cleanup();

	percpu_counter_destroy(&quic_orphan_count);
	percpu_counter_destroy(&quic_sockets_allocated);

	kmem_cache_destroy(quic_stream_cachep);
	kmem_cache_destroy(quic_conn_cachep);
	kmem_cache_destroy(quic_sock_cachep);

	pr_info("QUIC: kernel implementation unloaded\n");
}

module_init(quic_init);
module_exit(quic_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux QUIC Authors");
MODULE_DESCRIPTION("QUIC transport protocol");
MODULE_VERSION("1.0");
