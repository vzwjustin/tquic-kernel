// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Socket Interface
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
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
#include <linux/workqueue.h>
#include <net/sock.h>
#include <net/inet_common.h>
#include <net/inet_connection_sock.h>
#include <net/protocol.h>
#include <net/net_namespace.h>
#include <net/ip.h>
#include <net/udp.h>
#include <net/udp_tunnel.h>
#include <net/tquic.h>
#include <net/tquic/handshake.h>

#include "protocol.h"
#include "tquic_compat.h"
#include "tquic_debug.h"
#include "cong/tquic_cong.h"
#include "tquic_zerocopy.h"
#include "core/flow_control.h"

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
	tquic_dbg("tquic_set_lockdep_class: sk=%p is_ipv6=%d\n", sk, is_ipv6);
	sock_lock_init_class_and_name(
		sk, is_ipv6 ? "slock-AF_INET6-TQUIC" : "slock-AF_INET-TQUIC",
		&tquic_slock_keys[is_ipv6],
		is_ipv6 ? "sk_lock-AF_INET6-TQUIC" : "sk_lock-AF_INET-TQUIC",
		&tquic_lock_keys[is_ipv6]);
}

/* Socket operations (exported - used by tquic_proto.c) */
int tquic_sock_bind(struct socket *sock, tquic_sockaddr_t *uaddr, int addr_len);
int tquic_connect_socket(struct socket *sock, tquic_sockaddr_t *uaddr,
			 int addr_len, int flags);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 7, 0)
int tquic_accept_socket(struct socket *sock, struct socket *newsock,
			struct proto_accept_arg *arg);
#else
int tquic_accept_socket(struct socket *sock, struct socket *newsock, int flags,
			bool kern);
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
int tquic_sendmsg_socket(struct socket *sock, struct msghdr *msg, size_t len);
int tquic_recvmsg_socket(struct socket *sock, struct msghdr *msg, size_t len,
			 int flags);
int tquic_sock_ioctl(struct socket *sock, unsigned int cmd, unsigned long arg);

/* Zero-copy operations (exported) */
ssize_t tquic_splice_read_socket(struct socket *sock, loff_t *ppos,
				 struct pipe_inode_info *pipe, size_t len,
				 unsigned int flags);

/* Protocol operations */
int tquic_init_sock(struct sock *sk);
void tquic_destroy_sock(struct sock *sk);

/* Forward declaration: work handler shared by listen and connect paths */
static void tquic_listener_work_handler(struct work_struct *work);

/*
 * Initialize a TQUIC socket
 */
int tquic_init_sock(struct sock *sk)
{
	struct tquic_sock *tsk = tquic_sk(sk);
	struct tquic_connection *conn;

	/* Initialize lockdep class for this socket (IPv4 or IPv6) */
	tquic_set_lockdep_class(sk, sk->sk_family == AF_INET6);

	/* Initialize connection socket */
	inet_sk_set_state(sk, TCP_CLOSE);

	/* Initialize TQUIC-specific state */
	INIT_LIST_HEAD(&tsk->accept_queue);
	INIT_LIST_HEAD(&tsk->accept_list);
	INIT_HLIST_NODE(&tsk->listener_node);
	atomic_set(&tsk->accept_queue_len, 0);
	tsk->max_accept_queue = 128;
	tsk->flags = 0;
	init_waitqueue_head(&tsk->event_wait);
	tsk->default_stream = NULL;

	/*
	 * Pre-initialise listener_queue and listener_work so that
	 * cancel_work_sync() is always safe to call, even on a socket that has
	 * never been through listen() or connect().  Both paths re-initialise
	 * these fields before use; doing it here avoids WARN_ON(!work->func)
	 * inside __flush_work when cancel_work_sync() is invoked on a socket
	 * that never reached the UDP-tunnel setup step.
	 */
	skb_queue_head_init(&tsk->listener_queue);
	INIT_WORK(&tsk->listener_work, tquic_listener_work_handler);

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

	/* Default QUIC version and transport parameters (RFC 9000) */
	tsk->config.version = TQUIC_VERSION_1;
	tsk->config.max_idle_timeout_ms = 30000;
	tsk->config.handshake_timeout_ms = 10000;
	tsk->config.initial_max_data = 1048576;
	tsk->config.initial_max_stream_data_bidi_local = 262144;
	tsk->config.initial_max_stream_data_bidi_remote = 262144;
	tsk->config.initial_max_stream_data_uni = 262144;
	tsk->config.initial_max_streams_bidi = 100;
	tsk->config.initial_max_streams_uni = 100;
	tsk->config.ack_delay_exponent = 3;
	tsk->config.max_ack_delay_ms = 25;
	tsk->config.max_connection_ids = 8;
	tsk->config.max_datagram_size = 1200;

	/* Create connection structure */
	conn = tquic_conn_create(tsk, false);
	if (!conn)
		return -ENOMEM;

	/* Initialize bonding state */
	conn->scheduler = tquic_bond_init(conn);
	if (conn->scheduler)
		set_bit(TQUIC_F_BONDING_ENABLED, &conn->flags);

	/* Publish the connection pointer for concurrent readers. */
	write_lock_bh(&sk->sk_callback_lock);
	tsk->conn = conn;
	write_unlock_bh(&sk->sk_callback_lock);

	tquic_dbg("socket initialized\n");
	return 0;
}

/*
 * Destroy a TQUIC socket
 */
void tquic_destroy_sock(struct sock *sk)
{
	struct tquic_sock *tsk = tquic_sk(sk);
	struct tquic_connection *conn;
	struct tquic_stream *dstream;

	/* Ensure any listen-table registration is removed before final free. */
	if (tsk->flags & TQUIC_F_LISTENER_REGISTERED)
		tquic_unregister_listener(sk);

	/* Release the listener UDP tunnel socket and drain packet queue */
	if (tsk->udp_sock) {
		cancel_work_sync(&tsk->listener_work);
		skb_queue_purge(&tsk->listener_queue);
		udp_tunnel_sock_release(tsk->udp_sock);
		tsk->udp_sock = NULL;
	}

	/* Clean up any in-progress handshake */
	tquic_handshake_cleanup(sk);

	/* Free server certificate and key material */
	kfree(tsk->cert_der);
	tsk->cert_der = NULL;
	tsk->cert_der_len = 0;
	kfree_sensitive(tsk->key_der);
	tsk->key_der = NULL;
	tsk->key_der_len = 0;

	/* Detach conn pointer under sk_callback_lock to synchronize with readers. */
	write_lock_bh(&sk->sk_callback_lock);
	conn = tsk->conn;
	dstream = tsk->default_stream;
	tsk->conn = NULL;
	tsk->default_stream = NULL;
	write_unlock_bh(&sk->sk_callback_lock);

	if (dstream)
		tquic_stream_put(dstream);
	if (conn) {
		if (conn->scheduler &&
		    test_bit(TQUIC_F_BONDING_ENABLED, &conn->flags)) {
			tquic_bond_cleanup(conn->scheduler);
			conn->scheduler = NULL;
			clear_bit(TQUIC_F_BONDING_ENABLED, &conn->flags);
		}
		tquic_conn_put(conn);
	}

	tquic_dbg("socket destroyed\n");
}

/*
 * Bind socket to address
 * Note: sockaddr type varies by kernel; use tquic_sockaddr_t for compatibility.
 */
int tquic_sock_bind(struct socket *sock, tquic_sockaddr_t *uaddr, int addr_len)
{
	struct sockaddr *addr = (struct sockaddr *)uaddr;
	struct sock *sk = sock->sk;
	struct tquic_sock *tsk = tquic_sk(sk);

	tquic_dbg("tquic_sock_bind: family=%d addr_len=%d\n",
		  addr->sa_family, addr_len);

	if (addr->sa_family == AF_INET) {
		if (addr_len < sizeof(struct sockaddr_in))
			return -EINVAL;
	} else if (addr->sa_family == AF_INET6) {
		if (addr_len < sizeof(struct sockaddr_in6))
			return -EINVAL;
	} else {
		return -EAFNOSUPPORT;
	}

	/*
	 * CF-074: Hold socket lock to prevent races with concurrent
	 * tquic_connect() which reads bind_addr under lock_sock().
	 */
	lock_sock(sk);
	if (sk->sk_state != TCP_CLOSE ||
	    (tsk->flags & TQUIC_F_LISTENER_REGISTERED)) {
		release_sock(sk);
		return -EINVAL;
	}

	memcpy(&tsk->bind_addr, addr,
	       min_t(size_t, addr_len, sizeof(struct sockaddr_storage)));

	inet_sk_set_state(sk, TCP_CLOSE);

	release_sock(sk);

	tquic_dbg("tquic_sock_bind: ret=0\n");
	return 0;
}

/*
 * Connect to remote address
 * Note: sockaddr type varies by kernel; use tquic_sockaddr_t for compatibility.
 */
int tquic_connect_socket(struct socket *sock, tquic_sockaddr_t *uaddr,
			 int addr_len, int flags)
{
	struct sock *sk = sock->sk;

	return tquic_connect(sk, uaddr, addr_len);
}

/*
 * Client-side encap_rcv - receives server responses in softirq
 * and defers processing to a workqueue for process context.
 *
 * The QUIC socket pointer is stored in sk->sk_user_data of the
 * UDP tunnel socket at connect() time.
 */
static int tquic_client_encap_recv(struct sock *sk, struct sk_buff *skb)
{
	struct sock *quic_sk;
	struct tquic_sock *tsk;

	tquic_dbg("tquic_client_encap_recv: sk=%p skb_len=%u\n", sk, skb->len);

	quic_sk = READ_ONCE(sk->sk_user_data);
	if (!quic_sk) {
		kfree_skb(skb);
		return 0;
	}
	tsk = tquic_sk(quic_sk);

	/* Strip UDP header to expose QUIC payload */
	if (!pskb_may_pull(skb, sizeof(struct udphdr))) {
		kfree_skb(skb);
		return 0;
	}
	__skb_pull(skb, sizeof(struct udphdr));

	/* Queue for deferred processing in process context */
	skb_queue_tail(&tsk->listener_queue, skb);
	schedule_work(&tsk->listener_work);

	return 0;
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
 * Note: sockaddr type varies by kernel; use tquic_sockaddr_t and cast
 * internally since TQUIC uses fixed sockaddr_storage.
 */
int tquic_connect(struct sock *sk, tquic_sockaddr_t *uaddr, int addr_len)
{
	struct sockaddr *addr = (struct sockaddr *)uaddr;
	struct tquic_sock *tsk = tquic_sk(sk);
	struct tquic_connection *conn;
	int ret;

	if (addr->sa_family == AF_INET) {
		if (addr_len < sizeof(struct sockaddr_in))
			return -EINVAL;
	} else if (addr->sa_family == AF_INET6) {
		if (addr_len < sizeof(struct sockaddr_in6))
			return -EINVAL;
	} else {
		return -EAFNOSUPPORT;
	}

	/*
	 * CF-085: Take a connection reference that is synchronized against
	 * concurrent teardown via sk_callback_lock.
	 */
	conn = tquic_sock_conn_get(tsk);
	if (!conn)
		return -EINVAL;

	lock_sock(sk);

	/* Set socket reference for PM and path management */
	conn->sk = sk;

	/* Store peer address */
	memcpy(&tsk->connect_addr, addr,
	       min_t(size_t, addr_len, sizeof(struct sockaddr_storage)));

	/*
	 * Create a client-side UDP socket for receiving server responses.
	 * The server sends packets to our source port, which needs a real
	 * UDP socket with an encap_rcv handler to receive them.
	 */
	if (!tsk->udp_sock && addr->sa_family == AF_INET) {
		struct socket *usock;
		struct sockaddr_in udp_addr;
		struct sockaddr_in bound;

		ret = sock_create_kern(sock_net(sk), AF_INET,
				       SOCK_DGRAM, IPPROTO_UDP, &usock);
		if (ret < 0)
			goto out_unlock;

		/* Bind to ephemeral port on INADDR_ANY */
		memset(&udp_addr, 0, sizeof(udp_addr));
		udp_addr.sin_family = AF_INET;
		ret = kernel_bind(usock,
				  (struct sockaddr_unsized *)&udp_addr,
				  sizeof(udp_addr));
		if (ret < 0) {
			sock_release(usock);
			goto out_unlock;
		}

		/* Get assigned ephemeral port */
		memset(&bound, 0, sizeof(bound));
		ret = kernel_getsockname(usock, (struct sockaddr *)&bound);
		if (ret < 0) {
			sock_release(usock);
			goto out_unlock;
		}

		/* Update bind address so the path gets the correct port */
		((struct sockaddr_in *)&tsk->bind_addr)->sin_family = AF_INET;
		((struct sockaddr_in *)&tsk->bind_addr)->sin_port =
			bound.sin_port;

		/*
		 * Initialize deferred packet processing.  cancel_work_sync
		 * drains any work item left over from a previous failed
		 * connect attempt before reinitialising the work_struct —
		 * calling INIT_WORK on a pending item corrupts workqueue state.
		 */
		cancel_work_sync(&tsk->listener_work);
		skb_queue_purge(&tsk->listener_queue);
		skb_queue_head_init(&tsk->listener_queue);
		INIT_WORK(&tsk->listener_work, tquic_listener_work_handler);

		/* Register encap_rcv handler */
		WRITE_ONCE(usock->sk->sk_user_data, sk);
		udp_sk(usock->sk)->encap_type = 1;
		udp_sk(usock->sk)->encap_rcv = tquic_client_encap_recv;
		udp_encap_enable();
		tsk->udp_sock = usock;

		pr_debug("tquic: client IPv4 UDP socket on port %u\n",
			 ntohs(bound.sin_port));
	} else if (!tsk->udp_sock && addr->sa_family == AF_INET6) {
		struct socket *usock;
		struct sockaddr_in6 udp_addr6;
		struct sockaddr_in6 bound6;

		ret = sock_create_kern(sock_net(sk), AF_INET6,
				       SOCK_DGRAM, IPPROTO_UDP, &usock);
		if (ret < 0)
			goto out_unlock;

		/* Bind to ephemeral port on in6addr_any */
		memset(&udp_addr6, 0, sizeof(udp_addr6));
		udp_addr6.sin6_family = AF_INET6;
		udp_addr6.sin6_addr = in6addr_any;
		ret = kernel_bind(usock,
				  (struct sockaddr_unsized *)&udp_addr6,
				  sizeof(udp_addr6));
		if (ret < 0) {
			sock_release(usock);
			goto out_unlock;
		}

		/* Get assigned ephemeral port */
		memset(&bound6, 0, sizeof(bound6));
		ret = kernel_getsockname(usock, (struct sockaddr *)&bound6);
		if (ret < 0) {
			sock_release(usock);
			goto out_unlock;
		}

		/* Update bind address so the path gets the correct port */
		((struct sockaddr_in6 *)&tsk->bind_addr)->sin6_family = AF_INET6;
		((struct sockaddr_in6 *)&tsk->bind_addr)->sin6_port =
			bound6.sin6_port;

		/*
		 * Initialize deferred packet processing.  Drain any work item
		 * left over from a previous failed connect attempt before
		 * reinitialising the work_struct — calling INIT_WORK on a
		 * pending item corrupts workqueue state (mirrors IPv4 path).
		 */
		cancel_work_sync(&tsk->listener_work);
		skb_queue_purge(&tsk->listener_queue);
		skb_queue_head_init(&tsk->listener_queue);
		INIT_WORK(&tsk->listener_work, tquic_listener_work_handler);

		/* Register encap_rcv handler */
		WRITE_ONCE(usock->sk->sk_user_data, sk);
		udp_sk(usock->sk)->encap_type = 1;
		udp_sk(usock->sk)->encap_rcv = tquic_client_encap_recv;
		udp_encap_enable();
		tsk->udp_sock = usock;

		pr_debug("tquic: client IPv6 UDP socket on port %u\n",
			 ntohs(bound6.sin6_port));
	}

	/* Add initial path */
	ret = tquic_conn_add_path(conn, (struct sockaddr *)&tsk->bind_addr,
				  (struct sockaddr *)&tsk->connect_addr);
	if (ret < 0)
		goto out_unlock;

	/* Initialize connection state machine for client mode */
	ret = tquic_conn_client_connect(conn, (struct sockaddr *)addr);
	if (ret < 0)
		goto out_unlock;

	/* Bonding scheduler is initialized at socket creation. */

	/* Set state before handshake */
	inet_sk_set_state(sk, TCP_SYN_SENT);

	/*
	 * Allocate and set up the timer state for the connection.
	 * This includes the PTO timer for Initial packet retransmission.
	 */
	if (!conn->timer_state) {
		conn->timer_state = tquic_timer_state_alloc(conn);
		if (!conn->timer_state) {
			ret = -ENOMEM;
			goto out_close;
		}
	}

	/* Initiate TLS handshake (async via net/handshake) */
	ret = tquic_start_handshake(sk);
	if (ret < 0 && ret != -EALREADY && ret != -EISCONN)
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

	/* Start idle timeout now that the connection is established. */
	if (conn->timer_state)
		tquic_timer_set_idle(conn->timer_state);

	/* Initialize path manager after connection established */
	ret = tquic_pm_conn_init(conn);
	if (ret < 0) {
		tquic_warn("PM init failed (%d), multipath disabled\n", ret);
		tsk->flags |= TQUIC_F_PM_DISABLED;
		tsk->flags &= ~TQUIC_F_MULTIPATH_ENABLED;
		/*
		 * Continue with single-path operation. Multipath and migration
		 * features will be unavailable for this connection.
		 */
		pr_notice("tquic: connection using single-path mode\n");
		ret = 0; /* Not fatal */
	}

	release_sock(sk);

	/* CF-085: Drop the connection reference taken at function entry */
	tquic_conn_put(conn);

	tquic_dbg("client connection established\n");
	return 0;

out_close:
	inet_sk_set_state(sk, TCP_CLOSE);
	/*
	 * CF-241: sk_err uses positive errno values per kernel convention.
	 * ret is already negative (e.g., -ECONNREFUSED), so negate it.
	 */
	WRITE_ONCE(sk->sk_err, -ret);
out_unlock:
	release_sock(sk);
	/* CF-085: Drop the connection reference taken at function entry */
	tquic_conn_put(conn);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_connect);

/*
 * Listener deferred packet processing
 *
 * The UDP encap_rcv callback runs in softirq (NET_RX) context where
 * GFP_KERNEL allocations are forbidden. Since tquic_server_handshake()
 * creates connections with GFP_KERNEL, we must defer Initial packet
 * processing to a workqueue running in process context.
 */
static void tquic_listener_work_handler(struct work_struct *work)
{
	struct tquic_sock *tsk = container_of(work, struct tquic_sock,
					      listener_work);
	struct sock *sk = (struct sock *)tsk;
	struct sk_buff *skb;

	tquic_dbg("tquic_listener_work_handler: processing queued packets\n");

	while ((skb = skb_dequeue(&tsk->listener_queue)) != NULL) {
		/*
		 * Process the packet in process context where GFP_KERNEL
		 * allocations are safe. tquic_udp_recv() handles Initial
		 * packet routing to tquic_server_accept().
		 */
		tquic_udp_recv(sk, skb);
	}
}

/*
 * Listener encap_rcv - receives UDP packets in softirq and defers processing
 *
 * This is registered as the encap_rcv callback on the listener's UDP tunnel
 * socket. It queues received packets and schedules the work handler.
 */
static int tquic_listener_encap_recv(struct sock *sk, struct sk_buff *skb)
{
	struct tquic_sock *tsk;
	struct sock *listener_sk;
	struct sockaddr_storage local_addr;

	tquic_dbg("tquic_listener_encap_recv: sk=%p skb_len=%u\n",
		  sk, skb->len);

	/*
	 * Look up the TQUIC listener socket for this local address.
	 * The sk parameter here is the UDP tunnel socket, not the TQUIC socket.
	 */
	memset(&local_addr, 0, sizeof(local_addr));
	if (skb->protocol == htons(ETH_P_IP)) {
		struct sockaddr_in *sin = (struct sockaddr_in *)&local_addr;

		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = ip_hdr(skb)->daddr;
		sin->sin_port = udp_hdr(skb)->dest;
	}
#if IS_ENABLED(CONFIG_IPV6)
	else if (skb->protocol == htons(ETH_P_IPV6)) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&local_addr;

		sin6->sin6_family = AF_INET6;
		sin6->sin6_addr = ipv6_hdr(skb)->daddr;
		sin6->sin6_port = udp_hdr(skb)->dest;
	}
#endif
	else {
		kfree_skb(skb);
		return 0;
	}

	listener_sk = tquic_lookup_listener_net(sock_net(sk), &local_addr);
	if (!listener_sk) {
		kfree_skb(skb);
		return 0;
	}

	tsk = tquic_sk(listener_sk);

	/*
	 * Pull past the UDP header to expose the QUIC payload.
	 * The encap_rcv callback receives the SKB with skb->data
	 * still at the UDP header.  Downstream tquic_udp_recv()
	 * expects skb->data at the start of the QUIC packet.
	 * ip_hdr()/udp_hdr() still work after pull since they
	 * use the network_header/transport_header offsets.
	 */
	if (!pskb_may_pull(skb, sizeof(struct udphdr))) {
		kfree_skb(skb);
		sock_put(listener_sk);
		return 0;
	}
	__skb_pull(skb, sizeof(struct udphdr));

	/* Queue the packet for deferred processing in process context */
	skb_queue_tail(&tsk->listener_queue, skb);
	schedule_work(&tsk->listener_work);

	sock_put(listener_sk);
	return 0;
}

/*
 * Listen for incoming connections
 *
 * Sets up the socket to receive incoming QUIC connections.
 * Creates a UDP tunnel socket, registers with the UDP demux layer,
 * and transitions to TCP_LISTEN state.
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
	atomic_set(&tsk->accept_queue_len, 0);

	/* Initialize deferred packet processing */
	skb_queue_head_init(&tsk->listener_queue);
	INIT_WORK(&tsk->listener_work, tquic_listener_work_handler);

	/* Register with UDP demux to receive incoming packets */
	ret = tquic_register_listener(sk);
	if (ret < 0) {
		tquic_err("failed to register listener: %d\n", ret);
		goto out;
	}

	/*
	 * Create a UDP tunnel socket on the bind address/port.
	 *
	 * QUIC runs over UDP, so we need an actual kernel UDP socket
	 * listening on the bound port to receive incoming UDP packets.
	 * The encap_rcv callback queues packets for deferred processing
	 * in process context, where tquic_server_handshake() can safely
	 * allocate memory with GFP_KERNEL.
	 *
	 * We create the socket manually (instead of udp_sock_create4)
	 * so we can set SO_REUSEADDR before binding - this prevents
	 * EADDRINUSE from orphaned sockets left by crashed connections.
	 */
	if (!tsk->udp_sock) {
		struct socket *usock;

		if (tsk->bind_addr.ss_family == AF_INET) {
			struct sockaddr_in udp_addr;
			struct sockaddr_in *sin =
				(struct sockaddr_in *)&tsk->bind_addr;

			ret = sock_create_kern(sock_net(sk), AF_INET,
					       SOCK_DGRAM, IPPROTO_UDP,
					       &usock);
			if (ret < 0)
				goto listen_sock_err;

			sock_set_reuseaddr(usock->sk);
			sock_set_reuseport(usock->sk);

			udp_addr.sin_family = AF_INET;
			udp_addr.sin_addr = sin->sin_addr;
			udp_addr.sin_port = sin->sin_port;
			ret = kernel_bind(usock,
					  (struct sockaddr_unsized *)&udp_addr,
					  sizeof(udp_addr));
			if (ret < 0) {
				kernel_sock_shutdown(usock, SHUT_RDWR);
				sock_release(usock);
				goto listen_sock_err;
			}
		}
#if IS_ENABLED(CONFIG_IPV6)
		else if (tsk->bind_addr.ss_family == AF_INET6) {
			struct sockaddr_in6 udp_addr6;
			struct sockaddr_in6 *sin6 =
				(struct sockaddr_in6 *)&tsk->bind_addr;

			ret = sock_create_kern(sock_net(sk), AF_INET6,
					       SOCK_DGRAM, IPPROTO_UDP,
					       &usock);
			if (ret < 0)
				goto listen_sock_err;

			sock_set_reuseaddr(usock->sk);
			sock_set_reuseport(usock->sk);

			memset(&udp_addr6, 0, sizeof(udp_addr6));
			udp_addr6.sin6_family = AF_INET6;
			udp_addr6.sin6_addr = sin6->sin6_addr;
			udp_addr6.sin6_port = sin6->sin6_port;
			ret = kernel_bind(usock,
					  (struct sockaddr_unsized *)&udp_addr6,
					  sizeof(udp_addr6));
			if (ret < 0) {
				kernel_sock_shutdown(usock, SHUT_RDWR);
				sock_release(usock);
				goto listen_sock_err;
			}
		}
#endif
		else {
			ret = -EAFNOSUPPORT;
			goto listen_sock_err;
		}

		goto listen_sock_ok;

listen_sock_err:
		tquic_err("failed to create listener UDP socket: %d\n",
			  ret);
		tquic_unregister_listener(sk);
		goto out;

listen_sock_ok:

		/*
		 * Register the listener-specific encap_rcv handler that
		 * defers processing to a workqueue for process context.
		 */
		udp_sk(usock->sk)->encap_type = 1;
		udp_sk(usock->sk)->encap_rcv = tquic_listener_encap_recv;
		udp_encap_enable();
		tsk->udp_sock = usock;

		pr_warn("tquic: listener UDP socket created on port %u\n",
			ntohs(((struct sockaddr_in *)&tsk->bind_addr)->sin_port));
	}

	/* Transition to listen state */
	inet_sk_set_state(sk, TCP_LISTEN);
	sock->state = SS_CONNECTED; /* Mark as ready for accept */

	tquic_dbg("listening on socket, backlog=%d\n", backlog);
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
int tquic_accept_socket(struct socket *sock, struct socket *newsock, int flags,
			bool kern)
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
		/*
		 * CF-169: lock_sock() is already held, which provides
		 * serialization on the accept queue.  The inner
		 * spin_lock_bh(&sk->sk_lock.slock) was redundant and
		 * could deadlock since lock_sock() acquires the same lock.
		 */
		if (!list_empty(&tsk->accept_queue)) {
			child_tsk = list_first_entry(&tsk->accept_queue,
						     struct tquic_sock,
						     accept_list);
			list_del_init(&child_tsk->accept_list);
			atomic_dec(&tsk->accept_queue_len);

			/* Return the child socket */
			*newsk = (struct sock *)child_tsk;

			/*
			 * Update connection's socket pointer.
			 * For server-side connections, conn->sk still points
			 * to the listener (with a sock_hold taken in
			 * tquic_server_handshake).  Release that reference
			 * before switching to the child socket.
			 */
			if (child_tsk->conn) {
				struct sock *old_sk = child_tsk->conn->sk;

				child_tsk->conn->sk = (struct sock *)child_tsk;
				if (old_sk && old_sk != (struct sock *)child_tsk)
					sock_put(old_sk);
			}

			tquic_dbg("accept returned connection\n");
			goto out_unlock;
		}

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

	tquic_dbg("tquic_sock_getname: peer=%d\n", peer);

	lock_sock(sk);

	if (peer)
		saddr = &tsk->connect_addr;
	else
		saddr = &tsk->bind_addr;

	len = sizeof(struct sockaddr_in);
	if (saddr->ss_family == AF_INET6)
		len = sizeof(struct sockaddr_in6);

	memcpy(addr, saddr, len);

	release_sock(sk);

	tquic_dbg("tquic_sock_getname: ret=%d\n", len);
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
	struct tquic_connection *conn = NULL;
	struct tquic_stream *stream;
	__poll_t mask = 0;

	tquic_dbg("tquic_poll: sk_state=%d\n", sk->sk_state);

	sock_poll_wait(file, sock, wait);
	stream = NULL;

	lock_sock(sk);

	if (sk->sk_state == TCP_LISTEN) {
		if (atomic_read(&tsk->accept_queue_len) > 0)
			mask |= EPOLLIN | EPOLLRDNORM;
	} else if (sk->sk_state == TCP_ESTABLISHED) {
		conn = tquic_sock_conn_get(tsk);
		stream = tquic_sock_default_stream_get(tsk);

		/* Check if stream data available to read */
		if (conn && stream) {
			if (!skb_queue_empty(&stream->recv_buf))
				mask |= EPOLLIN | EPOLLRDNORM;
		}

		/*
		 * Check if datagram data available (RFC 9221)
		 *
		 * Datagrams are readable if the datagram receive queue
		 * has at least one datagram queued. This allows poll/epoll
		 * to wake on datagram arrival.
		 */
		if (conn && conn->datagram.enabled) {
			if (!skb_queue_empty(&conn->datagram.recv_queue))
				mask |= EPOLLIN | EPOLLRDNORM;
		}

		/* Always writable for now */
		mask |= EPOLLOUT | EPOLLWRNORM;
	}

	if (sk->sk_err)
		mask |= EPOLLERR;

	if (sk->sk_shutdown & RCV_SHUTDOWN)
		mask |= EPOLLRDHUP | EPOLLIN | EPOLLRDNORM;

	release_sock(sk);
	if (stream)
		tquic_stream_put(stream);
	if (conn)
		tquic_conn_put(conn);

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
	struct tquic_connection *conn = NULL;
	int ret = 0;

	tquic_dbg("tquic_sock_shutdown: how=%d\n", how);

	lock_sock(sk);

	conn = tquic_sock_conn_get(tsk);
	if (conn && READ_ONCE(conn->state) == TQUIC_CONN_CONNECTED) {
		/* Use graceful shutdown via state machine */
		ret = tquic_conn_shutdown(conn);
	}

	if ((how & SEND_SHUTDOWN) && (how & RCV_SHUTDOWN))
		inet_sk_set_state(sk, TCP_CLOSE);

	release_sock(sk);
	if (conn)
		tquic_conn_put(conn);
	tquic_dbg("tquic_sock_shutdown: ret=%d\n", ret);
	return ret;
}

/*
 * Close connection
 */
void tquic_close(struct sock *sk, long timeout)
{
	struct tquic_sock *tsk = tquic_sk(sk);
	struct tquic_connection *conn;

	tquic_dbg("tquic_close: sk=%p timeout=%ld\n", sk, timeout);

	lock_sock(sk);

	conn = tquic_sock_conn_get(tsk);
	if (conn) {
		/* Release path manager state before connection teardown */
		tquic_pm_conn_release(conn);

		/*
		 * If we're still connected, initiate graceful close.
		 *
		 * First, flush any pending stream data and send FIN on the
		 * default stream so the peer knows data transfer is complete.
		 * Then send CONNECTION_CLOSE for the connection.
		 */
		if (READ_ONCE(conn->state) == TQUIC_CONN_CONNECTED ||
		    READ_ONCE(conn->state) == TQUIC_CONN_CONNECTING) {
			struct tquic_stream *stream;

			stream = tquic_sock_default_stream_get(tsk);
			if (stream) {
				/* Flush pending send buffer data */
				tquic_output_flush(conn);

				/* Send FIN if not already sent */
				if (!stream->fin_sent)
					tquic_xmit(conn, stream, NULL, 0, true);
				tquic_stream_put(stream);
			}
			tquic_conn_close_with_error(conn, 0x00, NULL);
		}
	}

	inet_sk_set_state(sk, TCP_CLOSE);

	release_sock(sk);
	if (conn)
		tquic_conn_put(conn);
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
	struct tquic_sock *tsk;
	struct tquic_connection *conn;
	void __user *uarg = (void __user *)arg;
	int ret = 0;

	lock_sock(sk);
	tsk = tquic_sk(sk);
	conn = tquic_sock_conn_get(tsk);
	release_sock(sk);

	switch (cmd) {
	case TQUIC_NEW_STREAM: {
		struct tquic_stream_args args;
		u64 stream_id;
		bool is_bidi;
		bool nonblock;
		int ret;

		/* Must be connected */
		if (!conn || READ_ONCE(conn->state) != TQUIC_CONN_CONNECTED) {
			ret = -ENOTCONN;
			goto out;
		}

		/* Copy args from userspace */
		if (copy_from_user(&args, uarg, sizeof(args))) {
			ret = -EFAULT;
			goto out;
		}

		/*
		 * CF-083: Validate reserved field is zeroed and flags
		 * contain no unknown bits.  Reject any request that
		 * sets reserved fields -- this ensures forward
		 * compatibility when new fields are added.
		 */
		if (args.reserved != 0) {
			ret = -EINVAL;
			goto out;
		}

		if (args.flags & ~((__u32)TQUIC_STREAM_UNIDI)) {
			ret = -EINVAL;
			goto out;
		}

		is_bidi = !(args.flags & TQUIC_STREAM_UNIDI);
		nonblock = !!(sock->file->f_flags & O_NONBLOCK);

		/*
		 * Block until stream credit available (per CONTEXT.md).
		 * ioctl blocks when at stream limit until peer sends MAX_STREAMS.
		 */
		ret = tquic_wait_for_stream_credit(conn, is_bidi, nonblock);
		if (ret < 0)
			goto out;

		/* Create stream socket */
		ret = tquic_stream_socket_create(conn, sk, args.flags,
						 &stream_id);
		if (ret < 0)
			goto out;

		/*
		 * CF-083: Zero reserved field before copying back to
		 * userspace to prevent any kernel info leak.
		 */
		args.stream_id = stream_id;
		args.reserved = 0;
		if (copy_to_user(uarg, &args, sizeof(args))) {
			/*
			 * We created the fd but can't return the stream_id.
			 * The fd is still valid; user can query stream_id via sockopt.
			 * Return success since the stream was created.
			 */
			tquic_warn("failed to copy stream_id to user\n");
		}

		tquic_dbg("ioctl NEW_STREAM returned fd=%d stream_id=%llu\n",
			  ret, stream_id);

		/* Return the file descriptor */
		goto out;
	}

	default:
		/* Fall back to inet_ioctl for standard socket ioctls */
		if (conn)
			tquic_conn_put(conn);
		return inet_ioctl(sock, cmd, arg);
	}

out:
	if (conn)
		tquic_conn_put(conn);
	return ret;
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

	/*
	 * Variable-length options (PSK identity, etc.) handle their
	 * own optlen validation below.  For all other (integer) options,
	 * require exactly sizeof(int).
	 */
	switch (optname) {
	case TQUIC_PSK_IDENTITY:
	case TQUIC_EXPECTED_HOSTNAME:
	case TQUIC_CERT_DATA:
	case TQUIC_KEY_DATA:
		/* Variable-length, validated in their case blocks */
		break;
	default:
		if (optlen != sizeof(int))
			return -EINVAL;
		break;
	}

	if (optlen >= sizeof(int)) {
		if (copy_from_sockptr(&val, optval, sizeof(val)))
			return -EFAULT;
	}

	switch (optname) {
	case TQUIC_NODELAY:
		WRITE_ONCE(tsk->nodelay, !!val);
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
		/*
		 * RFC 9000 Section 10.1: idle_timeout in milliseconds.
		 * Cap at 600000ms (10 minutes) to prevent unreasonable values.
		 * A value of 0 disables the idle timeout.
		 */
		if (val > 600000)
			return -ERANGE;
		{
			struct tquic_connection *conn;

			conn = tquic_sock_conn_get(tsk);
			if (!conn)
				return -ENOTCONN;
			lock_sock(sk);
			WRITE_ONCE(conn->idle_timeout, val);
			release_sock(sk);
			tquic_conn_put(conn);
		}
		break;

	case TQUIC_KEEPIDLE:
		/*
		 * Set keepalive interval (in seconds, like TCP_KEEPIDLE).
		 * A value of 0 disables keepalive PING transmission.
		 * Caps at 3600s (1 hour) per RFC 9000 §10.1 guidance.
		 */
		if (val < 0 || val > 3600)
			return -ERANGE;
		{
			struct tquic_connection *conn;

			conn = tquic_sock_conn_get(tsk);
			if (!conn)
				return -ENOTCONN;
			if (conn->timer_state)
				tquic_timer_set_keepalive(conn->timer_state,
							  (u32)val * 1000);
			tquic_conn_put(conn);
		}
		break;

	case TQUIC_BOND_MODE: {
		struct tquic_connection *conn;
		int ret = -ENOTCONN;

		conn = tquic_sock_conn_get(tsk);
		if (!conn)
			return -ENOTCONN;
		lock_sock(sk);
		ret = tquic_bond_set_mode(conn, val);
		release_sock(sk);
		tquic_conn_put(conn);
		return ret;
	}

	case TQUIC_BOND_PATH_PRIO:
		/* Requires additional path info */
		return -EINVAL;

	case TQUIC_BOND_PATH_WEIGHT: {
		struct tquic_connection *conn;
		struct tquic_path_weight_args args;
		int ret;

		if (optlen < sizeof(args))
			return -EINVAL;

		if (copy_from_sockptr(&args, optval, sizeof(args)))
			return -EFAULT;

		if (args.reserved[0] || args.reserved[1] || args.reserved[2])
			return -EINVAL;

		conn = tquic_sock_conn_get(tsk);
		if (!conn)
			return -ENOTCONN;
		lock_sock(sk);
		if (!conn->pm) {
			release_sock(sk);
			tquic_conn_put(conn);
			return -ENOTCONN;
		}

		/* Bonding context accessed via path manager */
		ret = tquic_bond_set_path_weight(conn, args.path_id, args.weight);
		release_sock(sk);
		tquic_conn_put(conn);
		return ret;
	}

	case TQUIC_MULTIPATH:
		/* Enable/disable multipath */
		break;

	case TQUIC_MIGRATE: {
		struct tquic_connection *conn;
		struct tquic_migrate_args args;
		sa_family_t family;
		int ret;

		if (optlen < sizeof(args))
			return -EINVAL;

		if (copy_from_sockptr(&args, optval, sizeof(args)))
			return -EFAULT;

		if (args.reserved != 0)
			return -EINVAL;

		/*
		 * CF-208: Validate the address family and basic
		 * structure before passing to migration code.
		 * Without this, a malformed sockaddr could cause
		 * undefined behavior in the path lookup code.
		 */
		family = args.local_addr.ss_family;
		if (family != AF_INET && family != AF_INET6)
			return -EAFNOSUPPORT;

		if (family == AF_INET) {
			struct sockaddr_in *sin =
				(struct sockaddr_in *)&args.local_addr;
			if (sin->sin_addr.s_addr == INADDR_ANY)
				return -EINVAL;
		} else {
			struct sockaddr_in6 *sin6 =
				(struct sockaddr_in6 *)&args.local_addr;
			if (ipv6_addr_any(&sin6->sin6_addr))
				return -EINVAL;
		}

		/* CF-208: Validate known flags only */
		if (args.flags &
		    ~(TQUIC_MIGRATE_FLAG_PROBE_ONLY | TQUIC_MIGRATE_FLAG_FORCE))
			return -EINVAL;

		conn = tquic_sock_conn_get(tsk);
		if (!conn)
			return -ENOTCONN;
		lock_sock(sk);
		ret = tquic_migrate_explicit(conn, &args.local_addr, args.flags);
		release_sock(sk);
		tquic_conn_put(conn);
		return ret;
	}

	case TQUIC_MIGRATION_ENABLED:
		lock_sock(sk);
		if (val)
			tsk->flags |= TQUIC_F_MIGRATION_ENABLED;
		else
			tsk->flags &= ~TQUIC_F_MIGRATION_ENABLED;
		release_sock(sk);
		break;

	case TQUIC_SCHEDULER: {
		/*
		 * SO_TQUIC_SCHEDULER: Set scheduler name before connect()
		 *
		 * Per CONTEXT.md: Scheduler is locked at connection establishment
		 * and cannot be changed mid-connection.
		 */
		char name[TQUIC_SCHED_NAME_MAX];
		struct tquic_sched_ops *sched_ops;
		struct tquic_connection *conn;
		int ret = 0;

		if (optlen < 1 || optlen >= TQUIC_SCHED_NAME_MAX)
			return -EINVAL;

		if (copy_from_sockptr(name, optval, optlen))
			return -EFAULT;
		name[optlen] = '\0';

		/* Validate scheduler exists and drop temporary module ref */
		sched_ops = tquic_sched_find(name);
		if (!sched_ops)
			return -ENOENT;
		module_put(sched_ops->owner);

		conn = tquic_sock_conn_get(tsk);
		lock_sock(sk);
		/*
		 * Must be called before connect/listen.
		 * Check connection state if one exists.
		 */
		if (conn && READ_ONCE(conn->state) != TQUIC_CONN_IDLE) {
			ret = -EISCONN;
		} else {
			/*
			 * Store the requested scheduler name. If a connection
			 * already exists (IDLE state), it will be applied when
			 * the scheduler is next evaluated. Otherwise, it is
			 * saved for when the connection is created.
			 */
			strscpy(tsk->requested_scheduler, name,
				sizeof(tsk->requested_scheduler));
		}
		release_sock(sk);
		if (conn)
			tquic_conn_put(conn);
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
				tquic_warn("unknown CC algorithm '%s'\n", name);
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
		 *
		 * CF-042: Requires CAP_NET_ADMIN - key material is
		 * security-sensitive.
		 */
		char identity[64];

		if (!ns_capable(sock_net(sk)->user_ns, CAP_NET_ADMIN))
			return -EPERM;

		if (optlen < 1 || optlen > 64)
			return -EINVAL;

		if (copy_from_sockptr(identity, optval, optlen))
			return -EFAULT;

		lock_sock(sk);
		/* Store PSK identity in socket */
		memcpy(tsk->psk_identity, identity, optlen);
		tsk->psk_identity_len = optlen;
		release_sock(sk);

		tquic_dbg("PSK identity set (%d bytes)\n", optlen);
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
		{
			struct tquic_connection *conn;

			conn = tquic_sock_conn_get(tsk);
			lock_sock(sk);
			if (conn && READ_ONCE(conn->state) != TQUIC_CONN_IDLE) {
				release_sock(sk);
				if (conn)
					tquic_conn_put(conn);
				return -EISCONN;
			}
			tsk->datagram_enabled = !!val;
			release_sock(sk);
			if (conn)
				tquic_conn_put(conn);
		}
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

		{
			struct tquic_connection *conn;

			conn = tquic_sock_conn_get(tsk);
			lock_sock(sk);
			tsk->datagram_queue_max = val;
			if (conn)
				WRITE_ONCE(conn->datagram.recv_queue_max, val);
			release_sock(sk);
			if (conn)
				tquic_conn_put(conn);
		}
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

		{
			struct tquic_connection *conn;

			conn = tquic_sock_conn_get(tsk);
			lock_sock(sk);
			tsk->datagram_queue_max = val;
			if (conn)
				WRITE_ONCE(conn->datagram.recv_queue_max, val);
			release_sock(sk);
			if (conn)
				tquic_conn_put(conn);
		}
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
		{
			struct tquic_connection *conn;

			conn = tquic_sock_conn_get(tsk);
			lock_sock(sk);
			if (conn && READ_ONCE(conn->state) != TQUIC_CONN_IDLE) {
				release_sock(sk);
				if (conn)
					tquic_conn_put(conn);
				return -EISCONN;
			}
			tsk->http3_enabled = !!val;
			release_sock(sk);
			if (conn)
				tquic_conn_put(conn);
		}
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
		if (settings.max_table_capacity >
		    TQUIC_HTTP3_MAX_TABLE_CAPACITY_MAX)
			return -EINVAL;
		if (settings.max_blocked_streams >
		    TQUIC_HTTP3_MAX_BLOCKED_STREAMS_MAX)
			return -EINVAL;

		{
			struct tquic_connection *conn;

			conn = tquic_sock_conn_get(tsk);
			lock_sock(sk);
			if (conn && READ_ONCE(conn->state) != TQUIC_CONN_IDLE) {
				release_sock(sk);
				if (conn)
					tquic_conn_put(conn);
				return -EISCONN;
			}
		tsk->http3_settings.max_table_capacity =
			settings.max_table_capacity;
		tsk->http3_settings.max_field_section_size =
			settings.max_field_section_size;
		tsk->http3_settings.max_blocked_streams =
			settings.max_blocked_streams;
		tsk->http3_settings.server_push_enabled = settings.enable_push;
			release_sock(sk);
			if (conn)
				tquic_conn_put(conn);
		}
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
		 *
		 * CF-042: Requires CAP_NET_ADMIN - controls TLS verification.
		 */
		if (!ns_capable(sock_net(sk)->user_ns, CAP_NET_ADMIN))
			return -EPERM;

		if (val < TQUIC_VERIFY_NONE || val > TQUIC_VERIFY_REQUIRED)
			return -EINVAL;

		{
			struct tquic_connection *conn;

			conn = tquic_sock_conn_get(tsk);
			lock_sock(sk);
			if (conn && READ_ONCE(conn->state) != TQUIC_CONN_IDLE) {
				release_sock(sk);
				if (conn)
					tquic_conn_put(conn);
				return -EISCONN;
			}
			tsk->cert_verify.verify_mode = val;
			if (val == TQUIC_VERIFY_NONE)
				tquic_warn(
					"Certificate verification disabled for socket - INSECURE\n");
			release_sock(sk);
			if (conn)
				tquic_conn_put(conn);
		}
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
		 *
		 * CF-042: Requires CAP_NET_ADMIN - controls TLS verification.
		 */
		char hostname[TQUIC_MAX_HOSTNAME_LEN + 1];

		if (!ns_capable(sock_net(sk)->user_ns, CAP_NET_ADMIN))
			return -EPERM;

		if (optlen <= 0 || optlen > TQUIC_MAX_HOSTNAME_LEN)
			return -EINVAL;

		if (copy_from_sockptr(hostname, optval, optlen))
			return -EFAULT;
		hostname[optlen] = '\0';

		{
			struct tquic_connection *conn;

			conn = tquic_sock_conn_get(tsk);
			lock_sock(sk);
			if (conn && READ_ONCE(conn->state) != TQUIC_CONN_IDLE) {
				release_sock(sk);
				if (conn)
					tquic_conn_put(conn);
				return -EISCONN;
			}
			memcpy(tsk->cert_verify.expected_hostname, hostname, optlen);
			tsk->cert_verify.expected_hostname_len = optlen;
			tsk->cert_verify.verify_hostname = true;
			release_sock(sk);
			if (conn)
				tquic_conn_put(conn);
		}

		tquic_dbg("Expected hostname set to '%s'\n", hostname);
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
		 *
		 * CF-042: Requires CAP_NET_ADMIN - weakens TLS security.
		 */
		if (!ns_capable(sock_net(sk)->user_ns, CAP_NET_ADMIN))
			return -EPERM;

		{
			struct tquic_connection *conn;

			conn = tquic_sock_conn_get(tsk);
			lock_sock(sk);
			if (conn && READ_ONCE(conn->state) != TQUIC_CONN_IDLE) {
				release_sock(sk);
				if (conn)
					tquic_conn_put(conn);
				return -EISCONN;
			}
			tsk->cert_verify.allow_self_signed = !!val;
			if (val)
				tquic_warn(
					"Self-signed certificates allowed for socket - INSECURE\n");
			release_sock(sk);
			if (conn)
				tquic_conn_put(conn);
		}
		return 0;

	case TQUIC_CERT_DATA: {
		/*
		 * SO_TQUIC_CERT_DATA: Set DER-encoded X.509 certificate
		 *
		 * Server sockets must set this before listen()/accept().
		 * The certificate is passed to the TLS handshake context
		 * for sending in the Certificate message.
		 */
		u8 *cert;

		if (optlen <= 0 || optlen > TQUIC_MAX_CERT_DER_SIZE)
			return -EINVAL;

		cert = kmalloc(optlen, GFP_KERNEL);
		if (!cert)
			return -ENOMEM;

		if (copy_from_sockptr(cert, optval, optlen)) {
			kfree(cert);
			return -EFAULT;
		}

		lock_sock(sk);
		kfree(tsk->cert_der);
		tsk->cert_der = cert;
		tsk->cert_der_len = optlen;
		/* Also install into handshake context if it exists */
		if (tsk->inline_hs)
			tquic_hs_set_certificate(tsk->inline_hs, cert, optlen);
		release_sock(sk);
		return 0;
	}

	case TQUIC_KEY_DATA: {
		/*
		 * SO_TQUIC_KEY_DATA: Set DER-encoded private key (PKCS#8)
		 *
		 * Server sockets must set this before listen()/accept().
		 * The key is used for signing the CertificateVerify message.
		 */
		u8 *key;

		if (optlen <= 0 || optlen > TQUIC_MAX_KEY_DER_SIZE)
			return -EINVAL;

		key = kmalloc(optlen, GFP_KERNEL);
		if (!key)
			return -ENOMEM;

		if (copy_from_sockptr(key, optval, optlen)) {
			kfree_sensitive(key);
			return -EFAULT;
		}

		lock_sock(sk);
		kfree_sensitive(tsk->key_der);
		tsk->key_der = key;
		tsk->key_der_len = optlen;
		/* Also install into handshake context if it exists */
		if (tsk->inline_hs)
			tquic_hs_set_private_key(tsk->inline_hs, key, optlen);
		release_sock(sk);
		return 0;
	}

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
		 *
		 * CF-042: Requires CAP_NET_ADMIN - exposes connection
		 * internals and can affect performance.
		 */
		struct tquic_qlog_args args;

		if (!ns_capable(sock_net(sk)->user_ns, CAP_NET_ADMIN))
			return -EPERM;
		struct tquic_qlog *qlog;
		struct tquic_connection *conn;

		if (optlen < sizeof(args))
			return -EINVAL;

		if (copy_from_sockptr(&args, optval, sizeof(args)))
			return -EFAULT;

		/* Validate reserved flags */
		if (args.flags != 0)
			return -EINVAL;

		conn = tquic_sock_conn_get(tsk);
		if (!conn)
			return -ENOTCONN;

		lock_sock(sk);
		/* Create qlog context */
		qlog = tquic_qlog_create(conn, &args);
		if (IS_ERR(qlog)) {
			release_sock(sk);
			tquic_conn_put(conn);
			return PTR_ERR(qlog);
		}

		/* Store qlog context (implementation would add to connection) */
		tquic_dbg("qlog enabled for connection, mode=%u\n", args.mode);
		release_sock(sk);
		tquic_conn_put(conn);
		return 0;
	}

	case TQUIC_QLOG_FILTER: {
		/*
		 * TQUIC_QLOG_FILTER: Update qlog event filter
		 *
		 * Dynamically update the event filter mask for an active
		 * qlog session. This allows enabling/disabling specific
		 * event categories at runtime.
		 *
		 * CF-042: Requires CAP_NET_ADMIN - controls diagnostic
		 * tracing.
		 */
		u64 mask;

		if (!ns_capable(sock_net(sk)->user_ns, CAP_NET_ADMIN))
			return -EPERM;

		if (optlen < sizeof(mask))
			return -EINVAL;

		if (copy_from_sockptr(&mask, optval, sizeof(mask)))
			return -EFAULT;

		{
			struct tquic_connection *conn;

			conn = tquic_sock_conn_get(tsk);
			if (!conn)
				return -ENOTCONN;

		lock_sock(sk);
		tquic_qlog_set_mask(conn->qlog, mask);
		release_sock(sk);
			tquic_conn_put(conn);
		}
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
	case TQUIC_INFO: {
		struct tquic_connection *conn;
		struct tquic_info info = { 0 };

		if (len < sizeof(struct tquic_info))
			return -EINVAL;

		conn = tquic_sock_conn_get(tsk);
		if (conn) {
			spin_lock_bh(&conn->lock);
			info.state = READ_ONCE(conn->state);
			info.version = conn->version;
			info.paths_active = conn->num_paths;
			info.bytes_sent = conn->stats.tx_bytes;
			info.bytes_received = conn->stats.rx_bytes;
			spin_unlock_bh(&conn->lock);
			tquic_conn_put(conn);
		}

		if (copy_to_user(optval, &info, sizeof(info)))
			return -EFAULT;
		if (put_user(sizeof(info), optlen))
			return -EFAULT;
		return 0;
	}

	case TQUIC_IDLE_TIMEOUT:
		{
			struct tquic_connection *conn;

			conn = tquic_sock_conn_get(tsk);
			val = conn ? READ_ONCE(conn->idle_timeout) : 0;
			if (conn)
				tquic_conn_put(conn);
		}
		break;

	case TQUIC_BOND_MODE:
		{
			struct tquic_connection *conn;

			conn = tquic_sock_conn_get(tsk);
			if (conn && conn->scheduler &&
			    test_bit(TQUIC_F_BONDING_ENABLED, &conn->flags)) {
				struct tquic_bond_state *bond = conn->scheduler;

				val = bond->mode;
			} else {
				val = 0;
			}
			if (conn)
				tquic_conn_put(conn);
		}
		break;

	case TQUIC_PATH_STATUS:
		{
			struct tquic_connection *conn;

			conn = tquic_sock_conn_get(tsk);
			val = conn ? conn->num_paths : 0;
			if (conn)
				tquic_conn_put(conn);
		}
		break;

	case TQUIC_MIGRATE_STATUS: {
		struct tquic_connection *conn;
		struct tquic_migrate_info info;

		if (len < sizeof(info))
			return -EINVAL;

		conn = tquic_sock_conn_get(tsk);
		if (conn) {
			lock_sock(sk);
			tquic_migration_get_status(conn, &info);
			release_sock(sk);
			tquic_conn_put(conn);
		} else {
			memset(&info, 0, sizeof(info));
		}

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

		/*
		 * CF-190: Validate identity_len is within buffer bounds
		 * in addition to the user-supplied length check.
		 */
		if (identity_len > TQUIC_MAX_PSK_IDENTITY_LEN) {
			release_sock(sk);
			return -EINVAL;
		}

		if (identity_len > len) {
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
		{
			struct tquic_connection *conn;

			conn = tquic_sock_conn_get(tsk);
			if (conn) {
				val = conn->datagram.enabled ? 1 : 0;
				tquic_conn_put(conn);
			} else {
				val = tsk->datagram_enabled ? 1 : 0;
			}
		}
		break;

	case TQUIC_SO_MAX_DATAGRAM_SIZE:
		/*
		 * SO_TQUIC_MAX_DATAGRAM_SIZE: Get max datagram payload size
		 *
		 * Returns the maximum datagram payload size that can be sent
		 * on this connection. Returns 0 if datagrams not supported.
		 * Read-only option.
		 */
		{
			struct tquic_connection *conn;

			conn = tquic_sock_conn_get(tsk);
			val = conn ? tquic_datagram_max_size(conn) : 0;
			if (conn)
				tquic_conn_put(conn);
		}
		break;

	case TQUIC_SO_DATAGRAM_QUEUE_LEN:
		/*
		 * SO_TQUIC_DATAGRAM_QUEUE_LEN: Get receive queue limit
		 *
		 * Returns the maximum number of datagrams that can be queued.
		 */
		{
			struct tquic_connection *conn;

			conn = tquic_sock_conn_get(tsk);
			val = conn ? conn->datagram.recv_queue_max :
				     tsk->datagram_queue_max;
			if (conn)
				tquic_conn_put(conn);
		}
		break;

	case TQUIC_SO_DATAGRAM_STATS: {
		struct tquic_connection *conn;
		/*
		 * SO_TQUIC_DATAGRAM_STATS: Get datagram statistics
		 *
		 * Returns comprehensive datagram statistics including
		 * sent/received/dropped counts and queue state.
		 */
		struct tquic_datagram_stats stats = { 0 };

		if (len < sizeof(stats))
			return -EINVAL;

		conn = tquic_sock_conn_get(tsk);
		lock_sock(sk);
		if (conn && conn->datagram.enabled) {
			spin_lock_bh(&conn->datagram.lock);
			stats.datagrams_sent =
				conn->datagram.datagrams_sent;
			stats.datagrams_received =
				conn->datagram.datagrams_received;
			stats.datagrams_dropped =
				conn->datagram.datagrams_dropped;
			stats.recv_queue_len =
				conn->datagram.recv_queue_len;
			stats.recv_queue_max =
				conn->datagram.recv_queue_max;
			stats.max_send_size = conn->datagram.max_send_size;
			stats.max_recv_size = conn->datagram.max_recv_size;
			spin_unlock_bh(&conn->datagram.lock);
		}
		release_sock(sk);
		if (conn)
			tquic_conn_put(conn);

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
		{
			struct tquic_connection *conn;

			conn = tquic_sock_conn_get(tsk);
			val = conn ? conn->datagram.recv_queue_max :
				     tsk->datagram_queue_max;
			if (conn)
				tquic_conn_put(conn);
		}
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
		settings.max_table_capacity =
			tsk->http3_settings.max_table_capacity;
		settings.max_field_section_size =
			tsk->http3_settings.max_field_section_size;
		settings.max_blocked_streams =
			tsk->http3_settings.max_blocked_streams;
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
		struct tquic_connection *conn;
		/*
		 * TQUIC_QLOG_STATS: Get qlog statistics
		 *
		 * Returns qlog event logging statistics including event
		 * counts, drops, and relay status.
		 */
		struct tquic_qlog_stats stats = { 0 };

		if (len < sizeof(stats))
			return -EINVAL;

		conn = tquic_sock_conn_get(tsk);
		if (!conn)
			return -ENOTCONN;
		lock_sock(sk);
		if (conn->qlog) {
			spin_lock_bh(&conn->qlog->lock);
			stats = conn->qlog->stats;
			spin_unlock_bh(&conn->qlog->lock);
		}
		release_sock(sk);
		tquic_conn_put(conn);

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
		val = 0; /* Would check connection qlog != NULL */
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
int tquic_sendmsg_socket(struct socket *sock, struct msghdr *msg, size_t len)
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

	tquic_dbg("tquic_check_datagram_cmsg: controllen=%zu\n",
		  msg->msg_controllen);

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
static int tquic_sendmsg_datagram(struct tquic_connection *conn,
				  struct msghdr *msg, size_t len)
{
	void *buf;
	int ret;

	if (!conn || READ_ONCE(conn->state) != TQUIC_CONN_CONNECTED)
		return -ENOTCONN;

	/* Verify datagram support is negotiated */
	if (!conn->datagram.enabled)
		return -EOPNOTSUPP;

	/* Check size against negotiated limit */
	if (len > conn->datagram.max_send_size)
		return -EMSGSIZE;

	/* CF-350: Cap allocation to prevent excessive kernel memory usage */
	if (len > 65535)
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

static size_t tquic_sendmsg_check_flow_control(struct tquic_connection *conn,
					       struct tquic_stream *stream,
					       size_t len)
{
	size_t allowed = len;
	u64 stream_limit, conn_limit;

	spin_lock_bh(&conn->lock);

	/* Stream-level flow control */
	if (stream->send_offset >= stream->max_send_data) {
		stream->blocked = true;
		spin_unlock_bh(&conn->lock);
		pr_info_ratelimited("tquic: sendmsg FC BLOCKED: stream %llu send_off=%llu max_send=%llu\n",
			stream->id, stream->send_offset, stream->max_send_data);
		return 0;
	}
	stream_limit = stream->max_send_data - stream->send_offset;
	if (allowed > stream_limit)
		allowed = stream_limit;

	/* Connection-level flow control (sent + reserved queued data) */
	if (conn->data_sent + conn->fc_data_reserved >= conn->max_data_remote) {
		spin_unlock_bh(&conn->lock);
		pr_info_ratelimited("tquic: sendmsg FC BLOCKED: conn data_sent=%llu reserved=%llu max_remote=%llu\n",
			conn->data_sent, conn->fc_data_reserved, conn->max_data_remote);
		return 0;
	}
	conn_limit = conn->max_data_remote -
		     (conn->data_sent + conn->fc_data_reserved);
	if (allowed > conn_limit)
		allowed = conn_limit;

	spin_unlock_bh(&conn->lock);
	return allowed;
}

int tquic_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
{
	struct tquic_sock *tsk = tquic_sk(sk);
	struct tquic_connection *conn;
	struct tquic_stream *stream;
	struct sk_buff *skb;
	int copied = 0;
	int flags = msg->msg_flags;
	bool nonblock;
	size_t allowed;

	tquic_dbg("tquic_sendmsg: sk=%p len=%zu flags=0x%x\n", sk, len, flags);

	conn = tquic_sock_conn_get(tsk);
	if (!conn)
		return -ENOTCONN;
	stream = NULL;

	if (READ_ONCE(conn->state) != TQUIC_CONN_CONNECTED) {
		tquic_conn_put(conn);
		return -ENOTCONN;
	}

	nonblock = (flags & MSG_DONTWAIT) ||
		   (sk->sk_socket && sk->sk_socket->file &&
		    (sk->sk_socket->file->f_flags & O_NONBLOCK));

	/*
	 * Check if caller wants datagram send (RFC 9221)
	 *
	 * If ancillary data contains TQUIC_CMSG_DATAGRAM, this is a
	 * datagram send request. The entire message is sent as a single
	 * unreliable datagram.
	 */
	if (tquic_check_datagram_cmsg(msg))
		goto out_datagram;

	/* Use or create default stream */
	stream = tquic_sock_default_stream_get_or_open(tsk, conn);
	if (!stream) {
		bool no_stream_credit = false;

		spin_lock_bh(&conn->lock);
		no_stream_credit =
			(conn->next_stream_id_bidi / 4 >= conn->max_streams_bidi);
		spin_unlock_bh(&conn->lock);

		copied = no_stream_credit ? -EAGAIN : -ENOMEM;
		goto out_put;
	}

	if (len == 0)
		goto out_put;

	/* Check flow control before copying/mapping data (shared by copy + zerocopy). */
	allowed = tquic_sendmsg_check_flow_control(conn, stream, len);
	if (allowed == 0) {
		if (nonblock) {
			copied = -EAGAIN;
			goto out_put;
		}

		/*
		 * Block waiting for flow control credit.
		 * MAX_STREAM_DATA or MAX_DATA from peer will wake us.
		 */
		if (wait_event_interruptible(
			    stream->wait,
			    tquic_sendmsg_check_flow_control(conn, stream,
							     len) > 0 ||
				    stream->state == TQUIC_STREAM_CLOSED ||
				    READ_ONCE(conn->state) !=
					    TQUIC_CONN_CONNECTED)) {
			copied = -EINTR;
			goto out_put;
		}

		/* Re-check state after waking */
		if (stream->state == TQUIC_STREAM_CLOSED) {
			copied = -EPIPE;
			goto out_put;
		}
		if (READ_ONCE(conn->state) != TQUIC_CONN_CONNECTED) {
			copied = -ENOTCONN;
			goto out_put;
		}

		allowed = tquic_sendmsg_check_flow_control(conn, stream, len);
		if (allowed == 0) {
			copied = -EAGAIN;
			goto out_put;
		}
	}

	if (len > allowed)
		len = allowed;

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
			copied = tquic_sendmsg_zerocopy(sk, msg, len, stream);
			goto out_put;
		}
		/*
		 * If zerocopy not available, fall through to regular copy.
		 * This handles the case where MSG_ZEROCOPY is set but
		 * SO_ZEROCOPY socket option is not enabled.
		 */
		if (ret != -EOPNOTSUPP) {
			copied = ret;
			goto out_put;
		}
	}

	/* Regular copy path */
	while (copied < len) {
		size_t chunk = min_t(size_t, len - copied, 1200);

		skb = alloc_skb(chunk, GFP_KERNEL);
		if (!skb) {
			if (copied == 0)
				copied = -ENOMEM;
			goto out_put;
		}

		if (copy_from_iter(skb_put(skb, chunk), chunk,
				   &msg->msg_iter) != chunk) {
			kfree_skb(skb);
			if (copied == 0)
				copied = -EFAULT;
			goto out_put;
		}

		/*
		 * Charge socket memory for this buffer.
		 *
		 * If the write memory budget is exhausted (too much data queued
		 * but not yet transmitted), flush pending data first and retry.
		 * This prevents silent partial writes that the application
		 * might not handle, and provides proper backpressure.
		 */
		if (!sk_wmem_schedule(sk, skb->truesize)) {
			/*
			 * Flush pending output - transmitting queued data
			 * frees skbs and releases sk_wmem_alloc, making
			 * room for new data.
			 */
			tquic_output_flush(conn);

			/* Retry after flush */
			if (!sk_wmem_schedule(sk, skb->truesize)) {
				kfree_skb(skb);
				if (copied == 0)
					copied = -ENOBUFS;
				goto out_put;
			}
		}
		skb_set_owner_w(skb, sk);

			/* Initialize skb->cb stream offset for output_flush and reserve FC. */
			spin_lock_bh(&conn->lock);
			tquic_stream_skb_cb(skb)->stream_offset = stream->send_offset;
			tquic_stream_skb_cb(skb)->data_off = 0;
			stream->send_offset += chunk;
			conn->fc_data_reserved += chunk;
			conn->stats.tx_bytes += chunk;

		/*
		 * CF-179: Queue under lock to prevent reordering.
		 * If we unlocked before queuing, another thread could grab the next
		 * offset and queue its packet first, violating stream order.
		 */
		skb_queue_tail(&stream->send_buf, skb);
		spin_unlock_bh(&conn->lock);

		copied += chunk;
	}

	/*
	 * Trigger actual transmission after queuing data.
	 *
	 * The previous check used stream->send_offset == 0, but send_offset is
	 * incremented during queuing, so the flush path was never reached for
	 * normal sends. Flush whenever bytes were queued to ensure progress.
	 */
	if (copied > 0)
		tquic_output_flush(conn);

out_put:
	if (stream)
		tquic_stream_put(stream);
	tquic_conn_put(conn);
	tquic_dbg("tquic_sendmsg: ret=%d\n", copied);
	return copied;

out_datagram:
	copied = tquic_sendmsg_datagram(conn, msg, len);
	goto out_put;
}
EXPORT_SYMBOL_GPL(tquic_sendmsg);

/*
 * Receive message
 */
int tquic_recvmsg_socket(struct socket *sock, struct msghdr *msg, size_t len,
			 int flags)
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
	struct tquic_connection *conn;
	struct tquic_datagram_info dgram_info;
	struct sk_buff *skb;
	unsigned long irqflags;
	size_t copy_len;
	long timeo;
	int ret;

	conn = tquic_sock_conn_get(tsk);
	if (!conn)
		return -ENOTCONN;
	if (READ_ONCE(conn->state) != TQUIC_CONN_CONNECTED &&
	    READ_ONCE(conn->state) != TQUIC_CONN_CLOSING) {
		ret = -ENOTCONN;
		goto out_put;
	}

	/* Verify datagram support is negotiated */
	if (!conn->datagram.enabled) {
		ret = -EOPNOTSUPP;
		goto out_put;
	}

	/* Get receive timeout */
	timeo = sock_rcvtimeo(sk, flags & MSG_DONTWAIT);

retry:
	spin_lock_irqsave(&conn->datagram.lock, irqflags);

	skb = skb_peek(&conn->datagram.recv_queue);
	if (!skb) {
		spin_unlock_irqrestore(&conn->datagram.lock, irqflags);

		/* Non-blocking: return immediately */
		if (flags & MSG_DONTWAIT) {
			ret = -EAGAIN;
			goto out_put;
		}

		if (timeo == 0) {
			ret = -EAGAIN;
			goto out_put;
		}

		/* Check for pending signals */
		if (signal_pending(current)) {
			ret = sock_intr_errno(timeo);
			goto out_put;
		}

		/* Wait for datagram arrival */
		ret = wait_event_interruptible_timeout(
			conn->datagram.wait,
			!skb_queue_empty(&conn->datagram.recv_queue) ||
				sk->sk_err ||
				(sk->sk_shutdown & RCV_SHUTDOWN) ||
				READ_ONCE(conn->state) == TQUIC_CONN_CLOSED,
			timeo);

		if (ret < 0) {
			ret = sock_intr_errno(timeo);
			goto out_put;
		}

		if (ret == 0) {
			ret = -EAGAIN;
			goto out_put;
		}

		/* Re-check connection state */
		if (READ_ONCE(conn->state) == TQUIC_CONN_CLOSED) {
			ret = -ENOTCONN;
			goto out_put;
		}

		if (sk->sk_err) {
			ret = -sock_error(sk);
			goto out_put;
		}

		if (sk->sk_shutdown & RCV_SHUTDOWN) {
			ret = 0;
			goto out_put;
		}

		timeo = ret;
		goto retry;
	}

	/* Calculate copy length */
	copy_len = min_t(size_t, len, skb->len);

	/* Copy data to user buffer */
	if (copy_to_iter(skb->data, copy_len, &msg->msg_iter) != copy_len) {
		spin_unlock_irqrestore(&conn->datagram.lock, irqflags);
		ret = -EFAULT;
		goto out_put;
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
		dgram_info.dgram_id = 0; /* Could be enhanced with tracking */
		dgram_info.flags = 0;
		put_cmsg(msg, SOL_TQUIC, TQUIC_CMSG_DATAGRAM,
			 sizeof(dgram_info), &dgram_info);
	}

	tquic_conn_put(conn);
	return copy_len;

out_put:
	tquic_conn_put(conn);
	return ret;
}

int tquic_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, int flags,
		  int *addr_len)
{
	struct tquic_sock *tsk = tquic_sk(sk);
	struct tquic_connection *conn;
	struct tquic_stream *stream;
	struct sk_buff *skb;
	int copied = 0;
	bool nonblock;

	conn = tquic_sock_conn_get(tsk);
	if (!conn)
		return -ENOTCONN;

	if (READ_ONCE(conn->state) != TQUIC_CONN_CONNECTED) {
		tquic_conn_put(conn);
		return -ENOTCONN;
	}

	nonblock = (flags & MSG_DONTWAIT) ||
		   (sk->sk_socket && sk->sk_socket->file &&
		    (sk->sk_socket->file->f_flags & O_NONBLOCK));

	/*
	 * Check if caller wants datagram read (RFC 9221)
	 *
	 * If ancillary data contains TQUIC_CMSG_DATAGRAM, this is a
	 * datagram read request. Otherwise, read from the default stream.
	 */
	if (tquic_check_datagram_cmsg(msg)) {
		copied = tquic_recvmsg_datagram(sk, msg, len, flags);
		tquic_conn_put(conn);
		return copied;
	}

	stream = tquic_sock_default_stream_get(tsk);
	if (!stream) {
		/*
		 * No default stream yet.  On the server side the first
		 * peer-initiated bidirectional stream (created by
		 * tquic_process_stream_frame) lives in the connection's
		 * stream tree but was never installed as default_stream
		 * because the STREAM frame may arrive before accept()
		 * switches conn->sk to the child socket.
		 *
		 * Walk the tree and adopt the first bidirectional stream
		 * as the default so that recv() works on accepted sockets.
		 */
		pr_info("tquic: recvmsg: no default_stream, walking tree conn=%px sk=%px\n",
			conn, sk);
		spin_lock_bh(&conn->lock);
		{
			struct rb_node *node;
			int count = 0;

			for (node = rb_first(&conn->streams); node;
			     node = rb_next(node)) {
				struct tquic_stream *s;

				s = rb_entry(node, struct tquic_stream, node);
				pr_info("tquic: recvmsg: tree stream id=%llu refs=%d recv_buf_len=%d\n",
					s->id, refcount_read(&s->refcount),
					skb_queue_len(&s->recv_buf));
				count++;
				if ((s->id & 0x02) == 0 &&
				    tquic_stream_get(s)) {
					stream = s;
					break;
				}
			}
			if (!count)
				pr_info("tquic: recvmsg: stream tree EMPTY conn=%px\n", conn);
		}
		spin_unlock_bh(&conn->lock);

		if (stream) {
			/* Install as default_stream for future calls */
			write_lock_bh(&sk->sk_callback_lock);
			if (!tsk->default_stream) {
				tquic_stream_get(stream);
				tsk->default_stream = stream;
			}
			write_unlock_bh(&sk->sk_callback_lock);
		}
	}

	if (!stream && !nonblock) {
		/*
		 * No stream exists yet.  On the server side this means the
		 * client's first STREAM frame hasn't arrived.  Block until
		 * tquic_process_stream_frame() creates one (and calls
		 * sk->sk_data_ready), the connection closes, or SO_RCVTIMEO
		 * expires.
		 */
		long timeo = sock_rcvtimeo(sk, 0);
		DEFINE_WAIT_FUNC(wait, woken_wake_function);

		add_wait_queue(sk_sleep(sk), &wait);
		while (!stream) {
			if (READ_ONCE(conn->state) == TQUIC_CONN_CLOSED)
				break;
			if (signal_pending(current))
				break;

			timeo = wait_woken(&wait, TASK_INTERRUPTIBLE, timeo);
			if (!timeo)
				break;

			/* Re-walk stream tree after wakeup */
			spin_lock_bh(&conn->lock);
			{
				struct rb_node *node;

				for (node = rb_first(&conn->streams); node;
				     node = rb_next(node)) {
					struct tquic_stream *s;

					s = rb_entry(node, struct tquic_stream,
						     node);
					if ((s->id & 0x02) == 0 &&
					    tquic_stream_get(s)) {
						stream = s;
						break;
					}
				}
			}
			spin_unlock_bh(&conn->lock);
		}
		remove_wait_queue(sk_sleep(sk), &wait);

		if (stream) {
			/* Install as default_stream for future calls */
			write_lock_bh(&sk->sk_callback_lock);
			if (!tsk->default_stream) {
				tquic_stream_get(stream);
				tsk->default_stream = stream;
			}
			write_unlock_bh(&sk->sk_callback_lock);
		}
	}
	if (!stream) {
		tquic_conn_put(conn);
		return nonblock ? -EAGAIN : -ENOTCONN;
	}

	lock_sock(sk);

	/*
	 * Wait for data if the stream buffer is empty.
	 *
	 * For blocking sockets, sleep until data arrives, the stream
	 * receives FIN, or the connection is fully CLOSED.
	 *
	 * Allow reads during CLOSING and DRAINING states — data that
	 * was in transit can still arrive and should be delivered to the
	 * application.  Only stop when the connection is CLOSED (no
	 * more data possible) or when FIN is received on the stream.
	 */
	while (skb_queue_empty(&stream->recv_buf)) {
		if (stream->fin_received) {
			/* Peer sent FIN — EOF */
			copied = 0;
			goto out_release;
		}
		if (READ_ONCE(conn->state) == TQUIC_CONN_CLOSED) {
			copied = 0;
			goto out_release;
		}
		if (nonblock) {
			copied = -EAGAIN;
			goto out_release;
		}

		release_sock(sk);
		if (wait_event_interruptible(stream->wait,
				!skb_queue_empty(&stream->recv_buf) ||
				stream->fin_received ||
				READ_ONCE(conn->state) ==
					TQUIC_CONN_CLOSED)) {
			lock_sock(sk);
			copied = -EINTR;
			goto out_release;
		}
		lock_sock(sk);
	}

	while (copied < len && !skb_queue_empty(&stream->recv_buf)) {
		size_t chunk;

		skb = skb_dequeue(&stream->recv_buf);
		if (!skb)
			break;

		chunk = min_t(size_t, len - copied, skb->len);

		if (copy_to_iter(skb->data, chunk, &msg->msg_iter) != chunk) {
			skb_queue_head(&stream->recv_buf, skb);
			copied = copied > 0 ? copied : -EFAULT;
			goto out_release;
		}

		copied += chunk;

		if (chunk < skb->len) {
			/* Partial read, requeue remainder */
			skb_pull(skb, chunk);
			skb_queue_head(&stream->recv_buf, skb);
		} else {
			sk_mem_uncharge(sk, skb->truesize);
			kfree_skb(skb);
		}

		conn->stats.rx_bytes += chunk;
	}

	/*
	 * Update flow control after application consumes data.
	 *
	 * RFC 9000 Section 4.1-4.2: Send MAX_DATA (connection-level) and
	 * MAX_STREAM_DATA (stream-level) when the application has consumed
	 * enough data to warrant opening the peer's send window.  We use
	 * the half-window threshold: update when consumed > window / 2.
	 */
	if (copied > 0) {
		struct tquic_path *upd_path;

		/*
		 * Track consumption and update flow control windows.
		 *
		 * NOTE: conn->data_received is already incremented in
		 * tquic_flow_control_on_data_recvd() when STREAM frames
		 * arrive on the wire.  Do NOT increment it again here;
		 * that was the double-counting bug.
		 *
		 * Instead, track application-level consumption so that
		 * MAX_DATA / MAX_STREAM_DATA window updates are driven
		 * by consumed (app-read) bytes per RFC 9000 Section 4.2.
		 */
		if (conn->fc && stream->fc) {
			/*
			 * Preferred path: use the proper flow control
			 * subsystem which tracks data_consumed separately
			 * and computes correct window updates.
			 */
			tquic_fc_on_stream_consumed(conn->fc, stream->fc,
						    (u64)copied);

			/* Send pending MAX_DATA if the fc layer flagged it */
			if (tquic_fc_needs_max_data(conn->fc)) {
				u64 new_conn_max;

				new_conn_max = tquic_fc_get_max_data(conn->fc);
				rcu_read_lock();
				upd_path = rcu_dereference(conn->active_path);
				if (upd_path)
					tquic_flow_send_max_data(conn, upd_path,
								 new_conn_max);
				rcu_read_unlock();
				tquic_fc_max_data_sent(conn->fc, new_conn_max);
			}

			/* Send pending MAX_STREAM_DATA */
			if (tquic_fc_needs_max_stream_data(stream->fc)) {
				u64 new_stream_max;

				new_stream_max =
					tquic_fc_get_max_stream_data(stream->fc);
				rcu_read_lock();
				upd_path = rcu_dereference(conn->active_path);
				if (upd_path)
					tquic_flow_send_max_stream_data(
						conn, upd_path, stream->id,
						new_stream_max);
				rcu_read_unlock();
				tquic_fc_max_stream_data_sent(stream->fc,
							      new_stream_max);
			}
		} else {
			/*
			 * Legacy fallback: conn->fc not yet initialised.
			 * Use conn->data_consumed for window calculations.
			 */
			u64 consumed, threshold;
			bool send_conn_update = false;
			bool send_stream_update = false;
			u64 new_conn_max = 0;
			u64 new_stream_max = 0;

			spin_lock_bh(&conn->lock);

			conn->data_consumed += copied;
			consumed = conn->data_consumed;
			threshold = conn->max_data_local / 2;
			if (consumed > threshold &&
			    conn->max_data_local > 0) {
				new_conn_max = consumed +
					       conn->max_data_local;
				conn->max_data_local = new_conn_max;
				send_conn_update = true;
			}

			stream->recv_consumed += copied;
			consumed = stream->recv_consumed;
			threshold = stream->max_recv_data / 2;
			if (consumed > threshold &&
			    stream->max_recv_data > 0) {
				new_stream_max = consumed +
						 stream->max_recv_data;
				stream->max_recv_data = new_stream_max;
				send_stream_update = true;
			}

			spin_unlock_bh(&conn->lock);

			rcu_read_lock();
			upd_path = rcu_dereference(conn->active_path);
			if (upd_path) {
				if (send_conn_update)
					tquic_flow_send_max_data(
						conn, upd_path,
						new_conn_max);
				if (send_stream_update)
					tquic_flow_send_max_stream_data(
						conn, upd_path, stream->id,
						new_stream_max);
			}
			rcu_read_unlock();
		}
	}

out_release:
	release_sock(sk);
	tquic_stream_put(stream);
	tquic_conn_put(conn);

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
				 struct pipe_inode_info *pipe, size_t len,
				 unsigned int flags)
{
	return tquic_splice_read(sock, ppos, pipe, len, flags);
}
