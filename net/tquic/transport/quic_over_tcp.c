// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: QUIC over TCP Transport Implementation
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Implements QUIC packet transport over TCP for environments where
 * UDP is unavailable or unreliable.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/workqueue.h>
#include <linux/kthread.h>
#include <net/sock.h>
#include <net/tcp.h>

#include "quic_over_tcp.h"
#include "../protocol.h"

/*
 * =============================================================================
 * Global State
 * =============================================================================
 */

static struct workqueue_struct *quic_tcp_wq;
static bool quic_tcp_initialized;

/* Global statistics */
static struct {
	atomic64_t connections;
	atomic64_t listeners;
	atomic64_t total_packets_rx;
	atomic64_t total_packets_tx;
} quic_tcp_global_stats;

/*
 * =============================================================================
 * Buffer Management
 * =============================================================================
 */

static int rx_buf_init(struct quic_tcp_rx_buffer *buf, size_t size)
{
	buf->data = kvmalloc(size, GFP_KERNEL);
	if (!buf->data)
		return -ENOMEM;

	buf->size = size;
	buf->head = 0;
	buf->tail = 0;
	spin_lock_init(&buf->lock);

	return 0;
}

static void rx_buf_free(struct quic_tcp_rx_buffer *buf)
{
	kvfree(buf->data);
	buf->data = NULL;
}

static size_t rx_buf_used(struct quic_tcp_rx_buffer *buf)
{
	return buf->tail - buf->head;
}

static size_t rx_buf_free_space(struct quic_tcp_rx_buffer *buf)
{
	return buf->size - rx_buf_used(buf);
}

static int rx_buf_write(struct quic_tcp_rx_buffer *buf,
			const void *data, size_t len)
{
	size_t free_space;

	spin_lock(&buf->lock);

	/* Compact buffer if needed */
	if (buf->head > 0 && buf->tail + len > buf->size) {
		size_t used = rx_buf_used(buf);
		memmove(buf->data, buf->data + buf->head, used);
		buf->head = 0;
		buf->tail = used;
	}

	free_space = rx_buf_free_space(buf);
	if (len > free_space) {
		spin_unlock(&buf->lock);
		return -ENOSPC;
	}

	memcpy(buf->data + buf->tail, data, len);
	buf->tail += len;

	spin_unlock(&buf->lock);
	return len;
}

static int rx_buf_read(struct quic_tcp_rx_buffer *buf,
		       void *data, size_t len)
{
	size_t avail;

	spin_lock(&buf->lock);

	avail = rx_buf_used(buf);
	if (len > avail)
		len = avail;

	if (len > 0) {
		memcpy(data, buf->data + buf->head, len);
		buf->head += len;
	}

	spin_unlock(&buf->lock);
	return len;
}

static int rx_buf_peek(struct quic_tcp_rx_buffer *buf,
		       void *data, size_t len)
{
	size_t avail;

	spin_lock(&buf->lock);

	avail = rx_buf_used(buf);
	if (len > avail)
		len = avail;

	if (len > 0)
		memcpy(data, buf->data + buf->head, len);

	spin_unlock(&buf->lock);
	return len;
}

static void rx_buf_consume(struct quic_tcp_rx_buffer *buf, size_t len)
{
	spin_lock(&buf->lock);
	buf->head += min(len, rx_buf_used(buf));
	spin_unlock(&buf->lock);
}

/* TX buffer functions */
static int tx_buf_init(struct quic_tcp_tx_buffer *buf, size_t size)
{
	buf->data = kvmalloc(size, GFP_KERNEL);
	if (!buf->data)
		return -ENOMEM;

	buf->size = size;
	buf->len = 0;
	buf->packets = 0;
	spin_lock_init(&buf->lock);

	return 0;
}

static void tx_buf_free(struct quic_tcp_tx_buffer *buf)
{
	kvfree(buf->data);
	buf->data = NULL;
}

/*
 * =============================================================================
 * TCP Socket Operations
 * =============================================================================
 */

static void quic_tcp_data_ready(struct sock *sk)
{
	struct quic_tcp_connection *conn = sk->sk_user_data;

	if (conn)
		queue_work(quic_tcp_wq, &conn->rx_work);
}

/* Separate callback for listener sockets to avoid type confusion */
static void quic_tcp_listener_data_ready(struct sock *sk)
{
	struct quic_tcp_listener *listener = sk->sk_user_data;

	if (listener && listener->running)
		queue_work(quic_tcp_wq, &listener->accept_work);
}

static void quic_tcp_write_space(struct sock *sk)
{
	struct quic_tcp_connection *conn = sk->sk_user_data;

	if (conn)
		queue_work(quic_tcp_wq, &conn->tx_work);
}

static void quic_tcp_state_change(struct sock *sk)
{
	struct quic_tcp_connection *conn = sk->sk_user_data;

	if (!conn)
		return;

	switch (sk->sk_state) {
	case TCP_ESTABLISHED:
		conn->state = QUIC_TCP_STATE_CONNECTED;
		pr_debug("quic_tcp: connection established\n");
		break;

	case TCP_CLOSE:
	case TCP_CLOSE_WAIT:
		conn->state = QUIC_TCP_STATE_CLOSED;
		queue_work(quic_tcp_wq, &conn->close_work);
		break;
	}
}

static void setup_tcp_callbacks(struct quic_tcp_connection *conn)
{
	struct sock *sk = conn->tcp_sk->sk;

	write_lock_bh(&sk->sk_callback_lock);
	sk->sk_user_data = conn;
	sk->sk_data_ready = quic_tcp_data_ready;
	sk->sk_write_space = quic_tcp_write_space;
	sk->sk_state_change = quic_tcp_state_change;
	write_unlock_bh(&sk->sk_callback_lock);
}

/*
 * =============================================================================
 * Receive Processing
 * =============================================================================
 */

static void quic_tcp_rx_work(struct work_struct *work)
{
	struct quic_tcp_connection *conn =
		container_of(work, struct quic_tcp_connection, rx_work);
	struct msghdr msg = { .msg_flags = MSG_DONTWAIT };
	struct kvec iov;
	u8 tmp_buf[4096];
	int ret;

	if (conn->state != QUIC_TCP_STATE_CONNECTED)
		return;

	/* Read data from TCP socket */
	iov.iov_base = tmp_buf;
	iov.iov_len = sizeof(tmp_buf);

	while ((ret = kernel_recvmsg(conn->tcp_sk, &msg, &iov, 1,
				     sizeof(tmp_buf), MSG_DONTWAIT)) > 0) {
		/* Add to RX buffer */
		if (rx_buf_write(&conn->rx_buf, tmp_buf, ret) < 0) {
			pr_warn("quic_tcp: RX buffer full\n");
			break;
		}

		atomic64_inc(&conn->stats.tcp_segments_rx);
	}

	/* Process complete QUIC packets from buffer */
	while (rx_buf_used(&conn->rx_buf) >= QUIC_TCP_LENGTH_FIELD_SIZE) {
		__be16 len_be;
		u16 pkt_len;
		u8 *pkt_buf;

		/* Peek at length field */
		if (rx_buf_peek(&conn->rx_buf, &len_be, sizeof(len_be)) < 2)
			break;

		pkt_len = ntohs(len_be);

		/* Validate length */
		if (pkt_len < QUIC_TCP_MIN_PACKET_SIZE ||
		    pkt_len > QUIC_TCP_MAX_PACKET_SIZE) {
			pr_warn("quic_tcp: invalid packet length %u\n", pkt_len);
			atomic64_inc(&conn->stats.framing_errors);
			/* Skip length field and try to resync */
			rx_buf_consume(&conn->rx_buf, sizeof(len_be));
			continue;
		}

		/* Check if full packet available */
		if (rx_buf_used(&conn->rx_buf) < sizeof(len_be) + pkt_len)
			break;

		/* Consume length field */
		rx_buf_consume(&conn->rx_buf, sizeof(len_be));

		/* Read packet */
		pkt_buf = kmalloc(pkt_len, GFP_KERNEL);
		if (!pkt_buf)
			break;

		if (rx_buf_read(&conn->rx_buf, pkt_buf, pkt_len) < pkt_len) {
			kfree(pkt_buf);
			break;
		}

		/* Deliver to QUIC */
		if (conn->quic_conn) {
			/* Would call QUIC packet input here */
			pr_debug("quic_tcp: received %u byte QUIC packet\n", pkt_len);
		}

		atomic64_inc(&conn->stats.packets_rx);
		atomic64_add(pkt_len, &conn->stats.bytes_rx);
		atomic64_inc(&quic_tcp_global_stats.total_packets_rx);

		kfree(pkt_buf);
	}
}

/*
 * =============================================================================
 * Transmit Processing
 * =============================================================================
 */

static int do_tcp_send(struct quic_tcp_connection *conn,
		       const void *data, size_t len)
{
	struct msghdr msg = { .msg_flags = MSG_DONTWAIT };
	struct kvec iov = { .iov_base = (void *)data, .iov_len = len };
	int ret;

	ret = kernel_sendmsg(conn->tcp_sk, &msg, &iov, 1, len);
	if (ret > 0)
		atomic64_inc(&conn->stats.tcp_segments_tx);

	return ret;
}

static void quic_tcp_tx_work(struct work_struct *work)
{
	struct quic_tcp_connection *conn =
		container_of(work, struct quic_tcp_connection, tx_work);

	/* Flush any pending coalesced packets */
	quic_tcp_flush(conn);
}

int quic_tcp_send(struct quic_tcp_connection *conn,
		  const void *data, size_t len)
{
	struct quic_tcp_tx_buffer *tx = &conn->tx_buf;
	__be16 len_be;
	int ret;

	if (!conn || conn->state != QUIC_TCP_STATE_CONNECTED)
		return -ENOTCONN;

	if (len < QUIC_TCP_MIN_PACKET_SIZE || len > QUIC_TCP_MAX_PACKET_SIZE)
		return -EINVAL;

	spin_lock(&tx->lock);

	/* Check if we should flush first */
	if (tx->len + sizeof(len_be) + len > tx->size ||
	    tx->packets >= QUIC_TCP_MAX_COALESCE) {
		spin_unlock(&tx->lock);
		quic_tcp_flush(conn);
		spin_lock(&tx->lock);
	}

	/* Record first packet time for coalesce timeout */
	if (tx->packets == 0)
		tx->timestamp = ktime_get();

	/* Add framed packet to buffer */
	len_be = htons(len);
	memcpy(tx->data + tx->len, &len_be, sizeof(len_be));
	tx->len += sizeof(len_be);
	memcpy(tx->data + tx->len, data, len);
	tx->len += len;
	tx->packets++;

	atomic64_inc(&conn->stats.packets_tx);
	atomic64_add(len, &conn->stats.bytes_tx);
	atomic64_inc(&quic_tcp_global_stats.total_packets_tx);

	spin_unlock(&tx->lock);

	/* Immediate flush if only one packet (no coalescing) */
	if (tx->packets == 1) {
		ret = quic_tcp_flush(conn);
		if (ret < 0)
			return ret;
	}

	return len;
}
EXPORT_SYMBOL_GPL(quic_tcp_send);

int quic_tcp_flush(struct quic_tcp_connection *conn)
{
	struct quic_tcp_tx_buffer *tx = &conn->tx_buf;
	int ret = 0;

	if (!conn || conn->state != QUIC_TCP_STATE_CONNECTED)
		return -ENOTCONN;

	spin_lock(&tx->lock);

	if (tx->len > 0) {
		ret = do_tcp_send(conn, tx->data, tx->len);

		if (tx->packets > 1)
			atomic64_inc(&conn->stats.coalesce_count);

		tx->len = 0;
		tx->packets = 0;
	}

	spin_unlock(&tx->lock);

	return ret;
}
EXPORT_SYMBOL_GPL(quic_tcp_flush);

int quic_tcp_recv(struct quic_tcp_connection *conn, void *buf, size_t size)
{
	/* Packets are delivered asynchronously via rx_work */
	return -EWOULDBLOCK;
}
EXPORT_SYMBOL_GPL(quic_tcp_recv);

/*
 * =============================================================================
 * Connection Management
 * =============================================================================
 */

static void quic_tcp_close_work(struct work_struct *work)
{
	struct quic_tcp_connection *conn =
		container_of(work, struct quic_tcp_connection, close_work);

	pr_debug("quic_tcp: connection closed\n");

	/* Notify QUIC connection */
	if (conn->quic_conn) {
		/* Would notify QUIC of transport failure */
	}
}

struct quic_tcp_connection *quic_tcp_connect(struct sockaddr *addr,
					     int addrlen,
					     struct tquic_connection *quic_conn)
{
	struct quic_tcp_connection *conn;
	int ret;

	if (!quic_tcp_initialized)
		return ERR_PTR(-ENODEV);

	conn = kzalloc(sizeof(*conn), GFP_KERNEL);
	if (!conn)
		return ERR_PTR(-ENOMEM);

	/* Initialize buffers */
	ret = rx_buf_init(&conn->rx_buf, QUIC_TCP_RX_BUF_SIZE);
	if (ret)
		goto err_free_conn;

	ret = tx_buf_init(&conn->tx_buf, QUIC_TCP_TX_BUF_SIZE);
	if (ret)
		goto err_free_rx;

	/* Create TCP socket */
	ret = sock_create_kern(&init_net,
			       addr->sa_family,
			       SOCK_STREAM,
			       IPPROTO_TCP,
			       &conn->tcp_sk);
	if (ret)
		goto err_free_tx;

	/* Initialize state */
	conn->quic_conn = quic_conn;
	conn->state = QUIC_TCP_STATE_CONNECTING;
	spin_lock_init(&conn->lock);
	atomic_set(&conn->refcount, 1);
	INIT_WORK(&conn->rx_work, quic_tcp_rx_work);
	INIT_WORK(&conn->tx_work, quic_tcp_tx_work);
	INIT_WORK(&conn->close_work, quic_tcp_close_work);

	/* Set socket options */
	{
		int one = 1;
		kernel_setsockopt(conn->tcp_sk, IPPROTO_TCP, TCP_NODELAY,
				  (char *)&one, sizeof(one));
	}

	/* Setup callbacks before connect */
	setup_tcp_callbacks(conn);

	/* Connect */
	ret = kernel_connect(conn->tcp_sk, addr, addrlen, O_NONBLOCK);
	if (ret && ret != -EINPROGRESS)
		goto err_free_sock;

	atomic64_inc(&quic_tcp_global_stats.connections);
	pr_info("quic_tcp: connecting...\n");

	return conn;

err_free_sock:
	sock_release(conn->tcp_sk);
err_free_tx:
	tx_buf_free(&conn->tx_buf);
err_free_rx:
	rx_buf_free(&conn->rx_buf);
err_free_conn:
	kfree(conn);
	return ERR_PTR(ret);
}
EXPORT_SYMBOL_GPL(quic_tcp_connect);

void quic_tcp_close(struct quic_tcp_connection *conn)
{
	if (!conn)
		return;

	conn->state = QUIC_TCP_STATE_CLOSING;

	/* Cancel pending work */
	cancel_work_sync(&conn->rx_work);
	cancel_work_sync(&conn->tx_work);

	/* Flush pending data */
	quic_tcp_flush(conn);

	/* Close TCP socket */
	if (conn->tcp_sk) {
		kernel_sock_shutdown(conn->tcp_sk, SHUT_RDWR);
		sock_release(conn->tcp_sk);
		conn->tcp_sk = NULL;
	}

	/* Free buffers */
	rx_buf_free(&conn->rx_buf);
	tx_buf_free(&conn->tx_buf);

	conn->state = QUIC_TCP_STATE_CLOSED;

	kfree(conn);
}
EXPORT_SYMBOL_GPL(quic_tcp_close);

/*
 * =============================================================================
 * Listener Management
 * =============================================================================
 */

static void quic_tcp_accept_work(struct work_struct *work)
{
	struct quic_tcp_listener *listener =
		container_of(work, struct quic_tcp_listener, accept_work);
	struct socket *newsock;
	struct quic_tcp_connection *conn;
	int ret;

	while (listener->running) {
		ret = kernel_accept(listener->tcp_sk, &newsock, O_NONBLOCK);
		if (ret == -EAGAIN || ret == -EWOULDBLOCK) {
			/* No pending connections, wait to be woken up */
			break;
		}
		if (ret < 0)
			break;

		/* Create connection for accepted socket */
		conn = kzalloc(sizeof(*conn), GFP_KERNEL);
		if (!conn) {
			sock_release(newsock);
			continue;
		}

		ret = rx_buf_init(&conn->rx_buf, QUIC_TCP_RX_BUF_SIZE);
		if (ret) {
			sock_release(newsock);
			kfree(conn);
			continue;
		}

		ret = tx_buf_init(&conn->tx_buf, QUIC_TCP_TX_BUF_SIZE);
		if (ret) {
			rx_buf_free(&conn->rx_buf);
			sock_release(newsock);
			kfree(conn);
			continue;
		}

		conn->tcp_sk = newsock;
		conn->state = QUIC_TCP_STATE_CONNECTED;
		spin_lock_init(&conn->lock);
		atomic_set(&conn->refcount, 1);
		INIT_WORK(&conn->rx_work, quic_tcp_rx_work);
		INIT_WORK(&conn->tx_work, quic_tcp_tx_work);
		INIT_WORK(&conn->close_work, quic_tcp_close_work);

		setup_tcp_callbacks(conn);

		/* Add to listener's connection list */
		spin_lock(&listener->conn_lock);
		list_add_tail(&conn->list, &listener->connections);
		spin_unlock(&listener->conn_lock);

		atomic64_inc(&quic_tcp_global_stats.connections);
		pr_info("quic_tcp: accepted connection\n");
	}
}

struct quic_tcp_listener *quic_tcp_listen(u16 port)
{
	struct quic_tcp_listener *listener;
	struct sockaddr_in6 addr;
	int ret, one = 1;

	if (!quic_tcp_initialized)
		return ERR_PTR(-ENODEV);

	listener = kzalloc(sizeof(*listener), GFP_KERNEL);
	if (!listener)
		return ERR_PTR(-ENOMEM);

	/* Create listening socket */
	ret = sock_create_kern(&init_net, AF_INET6, SOCK_STREAM,
			       IPPROTO_TCP, &listener->tcp_sk);
	if (ret)
		goto err_free;

	/* Set socket options */
	kernel_setsockopt(listener->tcp_sk, SOL_SOCKET, SO_REUSEADDR,
			  (char *)&one, sizeof(one));
	kernel_setsockopt(listener->tcp_sk, IPPROTO_IPV6, IPV6_V6ONLY,
			  (char *)&one, sizeof(one));

	/* Bind */
	memset(&addr, 0, sizeof(addr));
	addr.sin6_family = AF_INET6;
	addr.sin6_port = htons(port);
	addr.sin6_addr = in6addr_any;

	ret = kernel_bind(listener->tcp_sk, (struct sockaddr *)&addr,
			  sizeof(addr));
	if (ret)
		goto err_sock;

	/* Listen */
	ret = kernel_listen(listener->tcp_sk, 128);
	if (ret)
		goto err_sock;

	/* Initialize state */
	listener->port = port;
	listener->running = true;
	INIT_LIST_HEAD(&listener->connections);
	spin_lock_init(&listener->conn_lock);
	INIT_WORK(&listener->accept_work, quic_tcp_accept_work);

	/* Setup data_ready callback for accept - use listener-specific callback */
	{
		struct sock *sk = listener->tcp_sk->sk;
		write_lock_bh(&sk->sk_callback_lock);
		sk->sk_user_data = listener;
		sk->sk_data_ready = quic_tcp_listener_data_ready;
		write_unlock_bh(&sk->sk_callback_lock);
	}

	atomic64_inc(&quic_tcp_global_stats.listeners);
	pr_info("quic_tcp: listening on port %u\n", port);

	return listener;

err_sock:
	sock_release(listener->tcp_sk);
err_free:
	kfree(listener);
	return ERR_PTR(ret);
}
EXPORT_SYMBOL_GPL(quic_tcp_listen);

void quic_tcp_stop_listen(struct quic_tcp_listener *listener)
{
	struct quic_tcp_connection *conn, *tmp;

	if (!listener)
		return;

	listener->running = false;
	cancel_work_sync(&listener->accept_work);

	/* Close all accepted connections */
	spin_lock(&listener->conn_lock);
	list_for_each_entry_safe(conn, tmp, &listener->connections, list) {
		list_del(&conn->list);
		spin_unlock(&listener->conn_lock);
		quic_tcp_close(conn);
		spin_lock(&listener->conn_lock);
	}
	spin_unlock(&listener->conn_lock);

	/* Close listening socket */
	if (listener->tcp_sk) {
		sock_release(listener->tcp_sk);
		listener->tcp_sk = NULL;
	}

	pr_info("quic_tcp: stopped listening on port %u\n", listener->port);
	kfree(listener);
}
EXPORT_SYMBOL_GPL(quic_tcp_stop_listen);

/*
 * =============================================================================
 * Module Init/Exit
 * =============================================================================
 */

int tquic_over_tcp_init(void)
{
	if (quic_tcp_initialized)
		return 0;

	quic_tcp_wq = alloc_workqueue("quic_tcp", WQ_HIGHPRI | WQ_UNBOUND, 0);
	if (!quic_tcp_wq)
		return -ENOMEM;

	quic_tcp_initialized = true;
	pr_info("quic_tcp: QUIC-over-TCP transport initialized\n");

	return 0;
}

void tquic_over_tcp_exit(void)
{
	if (!quic_tcp_initialized)
		return;

	if (quic_tcp_wq) {
		destroy_workqueue(quic_tcp_wq);
		quic_tcp_wq = NULL;
	}

	quic_tcp_initialized = false;
	pr_info("quic_tcp: QUIC-over-TCP transport shutdown\n");
}

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TQUIC over TCP Transport");
MODULE_AUTHOR("Linux Foundation");
