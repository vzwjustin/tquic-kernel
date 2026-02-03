// SPDX-License-Identifier: GPL-2.0-or-later
/* QUIC Kernel Implementation
 *
 * QUIC socket interface implementation
 *
 * Copyright (c) 2024 Linux QUIC Authors
 */

#define pr_fmt(fmt) "QUIC: " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/slab.h>
#include <linux/file.h>
#include <linux/sched/signal.h>
#include <linux/random.h>
#include <asm/ioctls.h>
#include <net/sock.h>
#include <net/inet_common.h>
#include <net/inet_sock.h>
#include <net/udp.h>
#include <net/udp_tunnel.h>
#include <net/protocol.h>
#include <net/tcp_states.h>
#if IS_ENABLED(CONFIG_IPV6)
#include <net/ipv6.h>
#include <net/transp_v6.h>
#include <net/addrconf.h>
#endif

/* QUIC socket option level */
#define SOL_QUIC		288

/* QUIC socket options */
#define QUIC_SOCKOPT_CONNECTION_ID	1
#define QUIC_SOCKOPT_STREAM_OPEN	2
#define QUIC_SOCKOPT_STREAM_CLOSE	3
#define QUIC_SOCKOPT_MAX_STREAMS	4
#define QUIC_SOCKOPT_IDLE_TIMEOUT	5
#define QUIC_SOCKOPT_MAX_DATA		6
#define QUIC_SOCKOPT_ALPN		7
#define QUIC_SOCKOPT_KEY		8
#define QUIC_SOCKOPT_HANDSHAKE_COMPLETE	9
#define QUIC_SOCKOPT_SNI		10	/* Server Name Indication */
#define QUIC_SOCKOPT_ALPN_SELECTED	11	/* Negotiated ALPN (read-only) */
#define QUIC_SOCKOPT_STREAM_PRIORITY	12

/* QUIC socket flags */
#define QUIC_F_HANDSHAKE_COMPLETE	BIT(0)
#define QUIC_F_CONNECTED		BIT(1)
#define QUIC_F_LISTENING		BIT(2)
#define QUIC_F_CLOSING			BIT(3)

/* Maximum connection ID length (RFC 9000) */
#define QUIC_MAX_CID_LEN		20

/* Maximum ALPN length */
#define QUIC_MAX_ALPN_LEN		255

/* Default values */
#define QUIC_DEFAULT_MAX_STREAMS_BIDI	100
#define QUIC_DEFAULT_MAX_STREAMS_UNI	100
#define QUIC_DEFAULT_IDLE_TIMEOUT	30000	/* 30 seconds in ms */
#define QUIC_DEFAULT_MAX_DATA		(1 << 20)  /* 1 MB */

/* Forward declarations */
struct quic_connection;
struct quic_stream;

/* External function declarations */
extern int quic_conn_close(struct quic_connection *conn, u64 error_code,
			   const char *reason, u32 reason_len, bool app_error);

/* QUIC error codes for CONNECTION_CLOSE (RFC 9000 Section 20) */
#define QUIC_ERROR_NO_ERROR		0x00

/* Stream entry for stream table */
struct quic_stream_entry {
	struct hlist_node	node;
	u64			stream_id;
	struct quic_stream	*stream;
};

/* Stream table */
struct quic_stream_table {
	struct hlist_head	*buckets;
	unsigned int		size;
	unsigned int		count;
	spinlock_t		lock;
};

/* Connection ID structure */
struct quic_connection_id {
	u8			len;
	u8			data[QUIC_MAX_CID_LEN];
};

/* Maximum SNI length (RFC 6066) */
#define QUIC_MAX_SNI_LEN		255

/* QUIC socket options structure */
struct quic_sock_options {
	u64			max_streams_bidi;
	u64			max_streams_uni;
	u64			max_data;
	u64			max_stream_data_bidi_local;
	u64			max_stream_data_bidi_remote;
	u64			max_stream_data_uni;
	u32			idle_timeout;	/* in milliseconds */
	char			alpn[QUIC_MAX_ALPN_LEN];
	u8			alpn_len;
	/*
	 * Negotiated ALPN - set after successful handshake.
	 * Contains the single selected protocol (length-prefixed format).
	 */
	char			alpn_selected[QUIC_MAX_ALPN_LEN];
	u8			alpn_selected_len;
	/*
	 * SNI - Server Name Indication (RFC 6066, RFC 9001)
	 * Null-terminated hostname for TLS server_name extension.
	 */
	char			server_name[QUIC_MAX_SNI_LEN + 1];
	u8			server_name_len;
};

/* Accept queue entry */
struct quic_accept_entry {
	struct list_head	node;
	struct sock		*sk;
};

/* QUIC socket structure for IPv4 */
struct quic_sock {
	/* inet_sock must be the first member */
	struct inet_sock	inet;

	/* Connection pointer */
	struct quic_connection	*conn;

	/* Stream management */
	struct quic_stream_table streams;
	u64			next_stream_id_bidi;
	u64			next_stream_id_uni;

	/* Accept queue for listening sockets */
	struct list_head	accept_queue;
	spinlock_t		accept_lock;
	u32			accept_queue_len;
	u32			accept_queue_max;

	/* Connection IDs */
	struct quic_connection_id local_cid;
	struct quic_connection_id remote_cid;

	/* Underlying UDP socket */
	struct socket		*udp_sock;

	/* Socket options */
	struct quic_sock_options options;

	/* Socket state flags */
	unsigned long		flags;

	/* Send/receive flow control */
	u64			tx_offset;
	u64			tx_max_data;
	u64			rx_offset;
	u64			rx_max_data;

	/* Encryption keys (set externally) */
	u8			*tx_key;
	u8			*rx_key;
	u16			key_len;

	/* Receive queue */
	struct sk_buff_head	receive_queue;
	spinlock_t		rx_lock;

	/* Work for async processing */
	struct work_struct	work;

	/* Statistics */
	u64			bytes_sent;
	u64			bytes_received;
	u64			packets_sent;
	u64			packets_received;
};

/* IPv6 QUIC socket structure */
#if IS_ENABLED(CONFIG_IPV6)
struct quic6_sock {
	struct quic_sock	quic;
	struct ipv6_pinfo	inet6;
};
#endif

/* Ancillary data structure for stream ID */
struct quic_stream_info {
	u64			stream_id;
	u32			flags;
};

/* Socket allocation counter */
static struct percpu_counter quic_sockets_allocated ____cacheline_aligned_in_smp;

/*
 * Helper macros
 */
static inline struct quic_sock *quic_sk(const struct sock *sk)
{
	return (struct quic_sock *)sk;
}

static inline struct sock *quic_to_sock(struct quic_sock *qsk)
{
	return (struct sock *)qsk;
}

static inline bool quic_is_established(const struct quic_sock *qsk)
{
	return test_bit(QUIC_F_CONNECTED, &qsk->flags) &&
	       test_bit(QUIC_F_HANDSHAKE_COMPLETE, &qsk->flags);
}

#if IS_ENABLED(CONFIG_IPV6)
static inline struct ipv6_pinfo *quic_inet6_sk(const struct sock *sk)
{
	struct quic6_sock *qsk6 = container_of(quic_sk(sk), struct quic6_sock, quic);
	return &qsk6->inet6;
}
#endif

/*
 * QUIC Variable-Length Integer Encoding (RFC 9000 Section 16)
 *
 * Encodes an integer using QUIC's variable-length encoding scheme:
 *   - 1 byte:  values 0-63 (6-bit, prefix 00)
 *   - 2 bytes: values 64-16383 (14-bit, prefix 01)
 *   - 4 bytes: values 16384-1073741823 (30-bit, prefix 10)
 *   - 8 bytes: values 1073741824-4611686018427387903 (62-bit, prefix 11)
 *
 * Returns the number of bytes written.
 */
static inline int quic_encode_varint(u8 *p, u64 value)
{
	if (value <= QUIC_VARINT_1BYTE_MAX) {
		*p = (u8)value;
		return 1;
	} else if (value <= QUIC_VARINT_2BYTE_MAX) {
		*p++ = QUIC_VARINT_2BYTE_PREFIX | (u8)(value >> 8);
		*p = (u8)(value & 0xff);
		return 2;
	} else if (value <= QUIC_VARINT_4BYTE_MAX) {
		*p++ = QUIC_VARINT_4BYTE_PREFIX | (u8)(value >> 24);
		*p++ = (u8)(value >> 16);
		*p++ = (u8)(value >> 8);
		*p = (u8)(value & 0xff);
		return 4;
	} else {
		*p++ = QUIC_VARINT_8BYTE_PREFIX | (u8)(value >> 56);
		*p++ = (u8)(value >> 48);
		*p++ = (u8)(value >> 40);
		*p++ = (u8)(value >> 32);
		*p++ = (u8)(value >> 24);
		*p++ = (u8)(value >> 16);
		*p++ = (u8)(value >> 8);
		*p = (u8)(value & 0xff);
		return 8;
	}
}

/*
 * Stream table operations
 */
static int quic_stream_table_init(struct quic_stream_table *table, unsigned int size)
{
	table->buckets = kcalloc(size, sizeof(struct hlist_head), GFP_KERNEL);
	if (!table->buckets)
		return -ENOMEM;

	table->size = size;
	table->count = 0;
	spin_lock_init(&table->lock);
	return 0;
}

static void quic_stream_table_destroy(struct quic_stream_table *table)
{
	struct quic_stream_entry *entry;
	struct hlist_node *tmp;
	unsigned int i;

	if (!table->buckets)
		return;

	spin_lock_bh(&table->lock);
	for (i = 0; i < table->size; i++) {
		hlist_for_each_entry_safe(entry, tmp, &table->buckets[i], node) {
			hlist_del(&entry->node);
			kfree(entry);
		}
	}
	spin_unlock_bh(&table->lock);

	kfree(table->buckets);
	table->buckets = NULL;
	table->size = 0;
	table->count = 0;
}

static unsigned int quic_stream_hash(u64 stream_id, unsigned int size)
{
	return (unsigned int)(stream_id % size);
}

/*
 * Look up a stream by ID in the stream table.
 *
 * Must be called with rcu_read_lock() held.
 */
static struct quic_stream_entry *quic_stream_lookup(struct quic_stream_table *table,
						    u64 stream_id)
{
	struct quic_stream_entry *entry;
	unsigned int bucket;

	bucket = quic_stream_hash(stream_id, table->size);

	hlist_for_each_entry_rcu(entry, &table->buckets[bucket], node) {
		if (entry->stream_id == stream_id)
			return entry;
	}
	return NULL;
}

static int quic_stream_insert(struct quic_stream_table *table, u64 stream_id,
			      struct quic_stream *stream)
{
	struct quic_stream_entry *entry;
	unsigned int bucket;

	entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
	if (!entry)
		return -ENOMEM;

	entry->stream_id = stream_id;
	entry->stream = stream;

	bucket = quic_stream_hash(stream_id, table->size);

	spin_lock_bh(&table->lock);
	hlist_add_head_rcu(&entry->node, &table->buckets[bucket]);
	table->count++;
	spin_unlock_bh(&table->lock);

	return 0;
}

static int quic_stream_remove(struct quic_stream_table *table, u64 stream_id)
{
	struct quic_stream_entry *entry;
	unsigned int bucket;

	bucket = quic_stream_hash(stream_id, table->size);

	spin_lock_bh(&table->lock);
	hlist_for_each_entry(entry, &table->buckets[bucket], node) {
		if (entry->stream_id == stream_id) {
			hlist_del_rcu(&entry->node);
			table->count--;
			spin_unlock_bh(&table->lock);
			kfree_rcu(entry, node);
			return 0;
		}
	}
	spin_unlock_bh(&table->lock);

	return -ENOENT;
}

/*
 * Connection ID operations
 */
static void quic_generate_cid(struct quic_connection_id *cid, u8 len)
{
	if (len > QUIC_MAX_CID_LEN)
		len = QUIC_MAX_CID_LEN;

	cid->len = len;
	get_random_bytes(cid->data, len);
}

static bool quic_cid_match(const struct quic_connection_id *a,
			   const struct quic_connection_id *b)
{
	if (a->len != b->len)
		return false;
	return memcmp(a->data, b->data, a->len) == 0;
}

/*
 * UDP socket management
 */
static void quic_udp_encap_rcv(struct sock *sk, struct sk_buff *skb);

static int quic_create_udp_sock(struct sock *sk)
{
	struct quic_sock *qsk = quic_sk(sk);
	struct socket *sock;
	struct udp_tunnel_sock_cfg cfg = {};
	int err;
	int family = sk->sk_family;

	err = sock_create_kern(sock_net(sk), family, SOCK_DGRAM, IPPROTO_UDP, &sock);
	if (err < 0) {
		pr_debug("Failed to create UDP socket: %d\n", err);
		return err;
	}

	/* Bind to the same address as QUIC socket */
	if (family == AF_INET) {
		struct sockaddr_in addr = {
			.sin_family = AF_INET,
			.sin_port = inet_sk(sk)->inet_sport,
			.sin_addr.s_addr = inet_sk(sk)->inet_saddr,
		};
		err = kernel_bind(sock, (struct sockaddr *)&addr, sizeof(addr));
	}
#if IS_ENABLED(CONFIG_IPV6)
	else if (family == AF_INET6) {
		struct sockaddr_in6 addr = {
			.sin6_family = AF_INET6,
			.sin6_port = inet_sk(sk)->inet_sport,
		};
		addr.sin6_addr = sk->sk_v6_rcv_saddr;
		err = kernel_bind(sock, (struct sockaddr *)&addr, sizeof(addr));
	}
#endif

	if (err < 0) {
		sock_release(sock);
		pr_debug("Failed to bind UDP socket: %d\n", err);
		return err;
	}

	/* Configure UDP encapsulation */
	cfg.sk_user_data = sk;
	cfg.encap_type = UDP_ENCAP_QUIC;
	cfg.encap_rcv = (udp_tunnel_encap_rcv_t)quic_udp_encap_rcv;
	cfg.encap_destroy = NULL;

	setup_udp_tunnel_sock(sock_net(sk), sock, &cfg);

	qsk->udp_sock = sock;

	pr_debug("Created UDP socket for QUIC: family=%d\n", family);
	return 0;
}

static void quic_release_udp_sock(struct sock *sk)
{
	struct quic_sock *qsk = quic_sk(sk);

	if (qsk->udp_sock) {
		/* Remove encapsulation */
		udp_tunnel_sock_release(qsk->udp_sock);
		qsk->udp_sock = NULL;
	}
}

/*
 * Socket initialization and destruction
 */
static void quic_sk_init_options(struct quic_sock *qsk)
{
	qsk->options.max_streams_bidi = QUIC_DEFAULT_MAX_STREAMS_BIDI;
	qsk->options.max_streams_uni = QUIC_DEFAULT_MAX_STREAMS_UNI;
	qsk->options.max_data = QUIC_DEFAULT_MAX_DATA;
	qsk->options.max_stream_data_bidi_local = QUIC_DEFAULT_MAX_DATA;
	qsk->options.max_stream_data_bidi_remote = QUIC_DEFAULT_MAX_DATA;
	qsk->options.max_stream_data_uni = QUIC_DEFAULT_MAX_DATA;
	qsk->options.idle_timeout = QUIC_DEFAULT_IDLE_TIMEOUT;
	qsk->options.alpn_len = 0;
	qsk->options.alpn_selected_len = 0;
	qsk->options.server_name[0] = '\0';
	qsk->options.server_name_len = 0;
}

static int quic_sk_init(struct sock *sk)
{
	struct quic_sock *qsk = quic_sk(sk);
	int err;

	pr_debug("Initializing QUIC socket %p\n", sk);

	/* Initialize connection state */
	qsk->conn = NULL;
	qsk->flags = 0;

	/* Initialize stream table */
	err = quic_stream_table_init(&qsk->streams, 64);
	if (err)
		return err;

	qsk->next_stream_id_bidi = 0;
	qsk->next_stream_id_uni = 2;  /* Client-initiated unidirectional: 2, 6, 10, ... */

	/* Initialize accept queue */
	INIT_LIST_HEAD(&qsk->accept_queue);
	spin_lock_init(&qsk->accept_lock);
	qsk->accept_queue_len = 0;
	qsk->accept_queue_max = SOMAXCONN;

	/* Initialize connection IDs */
	memset(&qsk->local_cid, 0, sizeof(qsk->local_cid));
	memset(&qsk->remote_cid, 0, sizeof(qsk->remote_cid));
	quic_generate_cid(&qsk->local_cid, 8);

	/* Initialize UDP socket pointer */
	qsk->udp_sock = NULL;

	/* Initialize options */
	quic_sk_init_options(qsk);

	/* Initialize flow control */
	qsk->tx_offset = 0;
	qsk->tx_max_data = QUIC_DEFAULT_MAX_DATA;
	qsk->rx_offset = 0;
	qsk->rx_max_data = QUIC_DEFAULT_MAX_DATA;

	/* Initialize keys */
	qsk->tx_key = NULL;
	qsk->rx_key = NULL;
	qsk->key_len = 0;

	/* Initialize receive queue */
	skb_queue_head_init(&qsk->receive_queue);
	spin_lock_init(&qsk->rx_lock);

	/* Initialize statistics */
	qsk->bytes_sent = 0;
	qsk->bytes_received = 0;
	qsk->packets_sent = 0;
	qsk->packets_received = 0;

	percpu_counter_inc(&quic_sockets_allocated);

	return 0;
}

static void quic_sk_destruct(struct sock *sk)
{
	struct quic_sock *qsk = quic_sk(sk);

	pr_debug("Destructing QUIC socket %p\n", sk);

	/* Free keys */
	kfree(qsk->tx_key);
	kfree(qsk->rx_key);
	qsk->tx_key = NULL;
	qsk->rx_key = NULL;

	/* Free receive queue */
	skb_queue_purge(&qsk->receive_queue);

	/* Destroy stream table */
	quic_stream_table_destroy(&qsk->streams);

	/* Clean up accept queue */
	spin_lock_bh(&qsk->accept_lock);
	while (!list_empty(&qsk->accept_queue)) {
		struct quic_accept_entry *entry;

		entry = list_first_entry(&qsk->accept_queue,
					 struct quic_accept_entry, node);
		list_del(&entry->node);
		if (entry->sk)
			sock_put(entry->sk);
		kfree(entry);
	}
	spin_unlock_bh(&qsk->accept_lock);

	percpu_counter_dec(&quic_sockets_allocated);

	inet_sock_destruct(sk);
}

struct sock *quic_sk_alloc(struct net *net, struct socket *sock, int protocol,
			   gfp_t gfp, int family)
{
	struct proto *prot;
	struct sock *sk;

	/* Select the appropriate protocol based on address family */
	if (family == AF_INET) {
		extern struct proto quic_prot;
		prot = &quic_prot;
	}
#if IS_ENABLED(CONFIG_IPV6)
	else if (family == AF_INET6) {
		extern struct proto quicv6_prot;
		prot = &quicv6_prot;
	}
#endif
	else {
		return ERR_PTR(-EAFNOSUPPORT);
	}

	sk = sk_alloc(net, family, gfp, prot, 1);
	if (!sk)
		return ERR_PTR(-ENOBUFS);

	sock_init_data(sock, sk);

	sk->sk_protocol = IPPROTO_UDP;  /* QUIC runs over UDP */
	sk->sk_destruct = quic_sk_destruct;

#if IS_ENABLED(CONFIG_IPV6)
	if (family == AF_INET6) {
		struct quic6_sock *qsk6 = container_of(quic_sk(sk),
						       struct quic6_sock, quic);
		inet_sk(sk)->pinet6 = &qsk6->inet6;
	}
#endif

	return sk;
}

void quic_sk_free(struct sock *sk)
{
	struct quic_sock *qsk = quic_sk(sk);

	pr_debug("Freeing QUIC socket %p\n", sk);

	/* Release UDP socket */
	quic_release_udp_sock(sk);

	/* Clear connection */
	qsk->conn = NULL;

	sock_put(sk);
}

/*
 * Event notification
 */
void quic_sk_wake_up(struct sock *sk, int event)
{
	struct socket_wq *wq;

	rcu_read_lock();
	wq = rcu_dereference(sk->sk_wq);
	if (skwq_has_sleeper(wq))
		wake_up_interruptible_sync_poll(&wq->wait,
			EPOLLIN | EPOLLRDNORM | EPOLLOUT | EPOLLWRNORM);

	sk_wake_async(sk, event, POLL_IN);
	rcu_read_unlock();
}

void quic_data_ready(struct sock *sk)
{
	struct quic_sock *qsk = quic_sk(sk);

	if (!sock_flag(sk, SOCK_DEAD)) {
		sk->sk_data_ready(sk);

		/* Update receive statistics */
		qsk->packets_received++;
	}
}

void quic_write_space(struct sock *sk)
{
	if (!sock_flag(sk, SOCK_DEAD)) {
		sk->sk_write_space(sk);
	}
}

/*
 * UDP encapsulation receive handler
 */
static void quic_udp_encap_rcv(struct sock *sk, struct sk_buff *skb)
{
	struct quic_sock *qsk;
	struct sock *quic_sk_ptr;

	quic_sk_ptr = (struct sock *)sk->sk_user_data;
	if (!quic_sk_ptr) {
		kfree_skb(skb);
		return;
	}

	qsk = quic_sk(quic_sk_ptr);

	/* Queue the packet for processing */
	spin_lock_bh(&qsk->rx_lock);
	skb_queue_tail(&qsk->receive_queue, skb);
	qsk->bytes_received += skb->len;
	spin_unlock_bh(&qsk->rx_lock);

	/* Notify the socket */
	quic_data_ready(quic_sk_ptr);
}

/*
 * Socket options implementation
 */
static int quic_setsockopt_cid(struct quic_sock *qsk, sockptr_t optval,
			       unsigned int optlen)
{
	struct quic_connection_id cid;

	if (optlen < sizeof(u8) || optlen > sizeof(cid))
		return -EINVAL;

	if (copy_from_sockptr(&cid.len, optval, sizeof(u8)))
		return -EFAULT;

	if (cid.len > QUIC_MAX_CID_LEN)
		return -EINVAL;

	if (optlen < sizeof(u8) + cid.len)
		return -EINVAL;

	if (copy_from_sockptr(&cid, optval, sizeof(u8) + cid.len))
		return -EFAULT;

	memcpy(&qsk->local_cid, &cid, sizeof(cid));
	return 0;
}

static int quic_getsockopt_cid(struct quic_sock *qsk, char __user *optval,
			       int __user *optlen)
{
	int len;

	if (get_user(len, optlen))
		return -EFAULT;

	len = min_t(int, len, sizeof(u8) + qsk->local_cid.len);

	if (put_user(len, optlen))
		return -EFAULT;

	if (copy_to_user(optval, &qsk->local_cid, len))
		return -EFAULT;

	return 0;
}

static int quic_setsockopt_stream_open(struct quic_sock *qsk, sockptr_t optval,
				       unsigned int optlen)
{
	struct sock *sk = quic_to_sock(qsk);
	u64 stream_id;
	u32 stream_type;
	int err;

	if (optlen < sizeof(u32))
		return -EINVAL;

	if (copy_from_sockptr(&stream_type, optval, sizeof(u32)))
		return -EFAULT;

	/* Allocate stream ID based on type */
	/* Client-initiated: even (bidi=0,4,8..., uni=2,6,10...)
	 * Server-initiated: odd (bidi=1,5,9..., uni=3,7,11...)
	 */
	lock_sock(sk);

	if (stream_type == 0) {
		/* Bidirectional stream */
		stream_id = qsk->next_stream_id_bidi;
		qsk->next_stream_id_bidi += 4;

		if (qsk->next_stream_id_bidi / 4 > qsk->options.max_streams_bidi) {
			release_sock(sk);
			return -EAGAIN;  /* Stream limit reached */
		}
	} else {
		/* Unidirectional stream */
		stream_id = qsk->next_stream_id_uni;
		qsk->next_stream_id_uni += 4;

		if (qsk->next_stream_id_uni / 4 > qsk->options.max_streams_uni) {
			release_sock(sk);
			return -EAGAIN;  /* Stream limit reached */
		}
	}

	/* Insert into stream table */
	err = quic_stream_insert(&qsk->streams, stream_id, NULL);
	if (err) {
		release_sock(sk);
		return err;
	}

	release_sock(sk);

	/* Return stream ID to user if space provided */
	if (optlen >= sizeof(u64)) {
		if (copy_to_user((void __user *)optval + sizeof(u32),
				 &stream_id, sizeof(u64)))
			return -EFAULT;
	}

	return 0;
}

static int quic_setsockopt_stream_close(struct quic_sock *qsk, sockptr_t optval,
					unsigned int optlen)
{
	struct sock *sk = quic_to_sock(qsk);
	u64 stream_id;
	int err;

	if (optlen < sizeof(u64))
		return -EINVAL;

	if (copy_from_sockptr(&stream_id, optval, sizeof(u64)))
		return -EFAULT;

	lock_sock(sk);
	err = quic_stream_remove(&qsk->streams, stream_id);
	release_sock(sk);

	return err;
}

static int quic_setsockopt_max_streams(struct quic_sock *qsk, sockptr_t optval,
				       unsigned int optlen)
{
	u64 max_streams[2];  /* [0] = bidi, [1] = uni */

	if (optlen < sizeof(max_streams))
		return -EINVAL;

	if (copy_from_sockptr(max_streams, optval, sizeof(max_streams)))
		return -EFAULT;

	qsk->options.max_streams_bidi = max_streams[0];
	qsk->options.max_streams_uni = max_streams[1];

	return 0;
}

static int quic_getsockopt_max_streams(struct quic_sock *qsk, char __user *optval,
				       int __user *optlen)
{
	u64 max_streams[2];
	int len;

	if (get_user(len, optlen))
		return -EFAULT;

	max_streams[0] = qsk->options.max_streams_bidi;
	max_streams[1] = qsk->options.max_streams_uni;

	len = min_t(int, len, sizeof(max_streams));

	if (put_user(len, optlen))
		return -EFAULT;

	if (copy_to_user(optval, max_streams, len))
		return -EFAULT;

	return 0;
}

static int quic_setsockopt_idle_timeout(struct quic_sock *qsk, sockptr_t optval,
					unsigned int optlen)
{
	u32 timeout;

	if (optlen < sizeof(u32))
		return -EINVAL;

	if (copy_from_sockptr(&timeout, optval, sizeof(u32)))
		return -EFAULT;

	qsk->options.idle_timeout = timeout;
	return 0;
}

static int quic_getsockopt_idle_timeout(struct quic_sock *qsk, char __user *optval,
					int __user *optlen)
{
	int len;

	if (get_user(len, optlen))
		return -EFAULT;

	len = min_t(int, len, sizeof(u32));

	if (put_user(len, optlen))
		return -EFAULT;

	if (copy_to_user(optval, &qsk->options.idle_timeout, len))
		return -EFAULT;

	return 0;
}

static int quic_setsockopt_max_data(struct quic_sock *qsk, sockptr_t optval,
				    unsigned int optlen)
{
	u64 max_data;

	if (optlen < sizeof(u64))
		return -EINVAL;

	if (copy_from_sockptr(&max_data, optval, sizeof(u64)))
		return -EFAULT;

	qsk->options.max_data = max_data;
	qsk->rx_max_data = max_data;
	return 0;
}

static int quic_getsockopt_max_data(struct quic_sock *qsk, char __user *optval,
				    int __user *optlen)
{
	int len;

	if (get_user(len, optlen))
		return -EFAULT;

	len = min_t(int, len, sizeof(u64));

	if (put_user(len, optlen))
		return -EFAULT;

	if (copy_to_user(optval, &qsk->options.max_data, len))
		return -EFAULT;

	return 0;
}

static int quic_setsockopt_alpn(struct quic_sock *qsk, sockptr_t optval,
				unsigned int optlen)
{
	if (optlen > QUIC_MAX_ALPN_LEN)
		return -EINVAL;

	if (copy_from_sockptr(qsk->options.alpn, optval, optlen))
		return -EFAULT;

	qsk->options.alpn_len = optlen;
	return 0;
}

static int quic_getsockopt_alpn(struct quic_sock *qsk, char __user *optval,
				int __user *optlen)
{
	int len;

	if (get_user(len, optlen))
		return -EFAULT;

	len = min_t(int, len, qsk->options.alpn_len);

	if (put_user(len, optlen))
		return -EFAULT;

	if (copy_to_user(optval, qsk->options.alpn, len))
		return -EFAULT;

	return 0;
}

/*
 * SNI - Server Name Indication (RFC 6066, RFC 9001)
 *
 * Set the server hostname for TLS ClientHello server_name extension.
 * Client: set before connect() to specify target hostname.
 * Server: read after accept() to get client's requested hostname.
 *
 * The hostname must be a valid DNS name (not IP address) per RFC 6066.
 * Maximum length is 255 bytes.
 */
static int quic_setsockopt_sni(struct quic_sock *qsk, sockptr_t optval,
			       unsigned int optlen)
{
	if (optlen > QUIC_MAX_SNI_LEN)
		return -EINVAL;

	if (optlen == 0) {
		/* Clear SNI */
		qsk->options.server_name[0] = '\0';
		qsk->options.server_name_len = 0;
		return 0;
	}

	if (copy_from_sockptr(qsk->options.server_name, optval, optlen))
		return -EFAULT;

	/* Ensure null-termination */
	qsk->options.server_name[optlen] = '\0';
	qsk->options.server_name_len = optlen;
	return 0;
}

static int quic_getsockopt_sni(struct quic_sock *qsk, char __user *optval,
			       int __user *optlen)
{
	int len;

	if (get_user(len, optlen))
		return -EFAULT;

	len = min_t(int, len, qsk->options.server_name_len);

	if (put_user(len, optlen))
		return -EFAULT;

	if (len > 0 && copy_to_user(optval, qsk->options.server_name, len))
		return -EFAULT;

	return 0;
}

/*
 * ALPN Selected - Negotiated Application Protocol (RFC 7301)
 *
 * Get the negotiated ALPN after successful handshake.
 * This is a read-only option; setting returns -EOPNOTSUPP.
 * Returns empty (len=0) if handshake not complete or no ALPN negotiated.
 */
static int quic_getsockopt_alpn_selected(struct quic_sock *qsk,
					 char __user *optval,
					 int __user *optlen)
{
	int len;

	if (get_user(len, optlen))
		return -EFAULT;

	len = min_t(int, len, qsk->options.alpn_selected_len);

	if (put_user(len, optlen))
		return -EFAULT;

	if (len > 0 && copy_to_user(optval, qsk->options.alpn_selected, len))
		return -EFAULT;

	return 0;
}

/*
 * quic_set_alpn_selected - Set the negotiated ALPN after handshake
 * @qsk: QUIC socket
 * @alpn: selected ALPN protocol (length-prefixed format)
 * @len: length of ALPN data
 *
 * Called internally by TLS handshake processing when server selects ALPN.
 * Returns 0 on success, -EINVAL if len exceeds maximum.
 */
int quic_set_alpn_selected(struct quic_sock *qsk, const char *alpn, u8 len)
{
	if (len > QUIC_MAX_ALPN_LEN)
		return -EINVAL;

	memcpy(qsk->options.alpn_selected, alpn, len);
	qsk->options.alpn_selected_len = len;
	return 0;
}
EXPORT_SYMBOL_GPL(quic_set_alpn_selected);

/*
 * quic_set_server_name - Set the SNI hostname from ClientHello
 * @qsk: QUIC socket
 * @name: server name string (null-terminated)
 * @len: length of server name (not including null terminator)
 *
 * Called internally by TLS handshake processing on server when
 * parsing ClientHello server_name extension.
 * Returns 0 on success, -EINVAL if len exceeds maximum.
 */
int quic_set_server_name(struct quic_sock *qsk, const char *name, u8 len)
{
	if (len > QUIC_MAX_SNI_LEN)
		return -EINVAL;

	memcpy(qsk->options.server_name, name, len);
	qsk->options.server_name[len] = '\0';
	qsk->options.server_name_len = len;
	return 0;
}
EXPORT_SYMBOL_GPL(quic_set_server_name);

/*
 * quic_get_server_name - Get the SNI hostname configured on socket
 * @qsk: QUIC socket
 *
 * Returns pointer to server name string, or NULL if not set.
 */
const char *quic_get_server_name(const struct quic_sock *qsk)
{
	if (qsk->options.server_name_len == 0)
		return NULL;
	return qsk->options.server_name;
}
EXPORT_SYMBOL_GPL(quic_get_server_name);

/*
 * quic_get_alpn - Get the offered ALPN list configured on socket
 * @qsk: QUIC socket
 * @len: output parameter for ALPN length
 *
 * Returns pointer to ALPN data (length-prefixed format), or NULL if not set.
 */
const char *quic_get_alpn(const struct quic_sock *qsk, u8 *len)
{
	if (qsk->options.alpn_len == 0) {
		if (len)
			*len = 0;
		return NULL;
	}
	if (len)
		*len = qsk->options.alpn_len;
	return qsk->options.alpn;
}
EXPORT_SYMBOL_GPL(quic_get_alpn);

static int quic_setsockopt_key(struct quic_sock *qsk, sockptr_t optval,
			       unsigned int optlen)
{
	struct {
		u8 direction;  /* 0 = TX, 1 = RX */
		u8 key_len;
		u8 key[];
	} __packed *key_data;
	u8 *new_key;

	if (optlen < 2)
		return -EINVAL;

	key_data = kmalloc(optlen, GFP_KERNEL);
	if (!key_data)
		return -ENOMEM;

	if (copy_from_sockptr(key_data, optval, optlen)) {
		kfree(key_data);
		return -EFAULT;
	}

	if (key_data->key_len > optlen - 2) {
		kfree(key_data);
		return -EINVAL;
	}

	new_key = kmemdup(key_data->key, key_data->key_len, GFP_KERNEL);
	if (!new_key) {
		kfree(key_data);
		return -ENOMEM;
	}

	if (key_data->direction == 0) {
		kfree(qsk->tx_key);
		qsk->tx_key = new_key;
	} else {
		kfree(qsk->rx_key);
		qsk->rx_key = new_key;
	}
	qsk->key_len = key_data->key_len;

	kfree(key_data);
	return 0;
}

static int quic_setsockopt_handshake_complete(struct quic_sock *qsk,
					      sockptr_t optval,
					      unsigned int optlen)
{
	int val;

	if (optlen < sizeof(int))
		return -EINVAL;

	if (copy_from_sockptr(&val, optval, sizeof(int)))
		return -EFAULT;

	if (val)
		set_bit(QUIC_F_HANDSHAKE_COMPLETE, &qsk->flags);
	else
		clear_bit(QUIC_F_HANDSHAKE_COMPLETE, &qsk->flags);

	return 0;
}

/*
 * Set stream priority (RFC 9218)
 *
 * Allows applications to specify urgency (0-7) and incremental flag
 * for stream scheduling. Lower urgency values indicate higher priority.
 */
static int quic_setsockopt_stream_priority(struct quic_sock *qsk,
					   sockptr_t optval,
					   unsigned int optlen)
{
	struct quic_stream_priority prio;
	struct quic_connection *conn = qsk->conn;
	struct quic_stream *stream;
	int err;

	if (optlen < sizeof(prio))
		return -EINVAL;

	if (copy_from_sockptr(&prio, optval, sizeof(prio)))
		return -EFAULT;

	/* Validate urgency range */
	if (prio.urgency > QUIC_PRIORITY_URGENCY_MAX)
		return -EINVAL;

	if (!conn)
		return -ENOTCONN;

	/* Find the stream */
	stream = quic_stream_lookup(conn, prio.stream_id);
	if (!stream)
		return -ENOENT;

	/* Set the priority */
	err = quic_stream_set_priority(stream, prio.urgency,
				       prio.incremental != 0);

	/* Release lookup reference */
	refcount_dec(&stream->refcnt);

	return err;
}

/*
 * Get stream priority (RFC 9218)
 */
static int quic_getsockopt_stream_priority(struct quic_sock *qsk,
					   char __user *optval,
					   int __user *optlen)
{
	struct quic_stream_priority prio;
	struct quic_connection *conn = qsk->conn;
	struct quic_stream *stream;
	int len;
	u8 urgency;
	bool incremental;

	if (get_user(len, optlen))
		return -EFAULT;

	if (len < sizeof(prio.stream_id))
		return -EINVAL;

	/* Get stream_id from user to know which stream to query */
	if (copy_from_user(&prio.stream_id, optval, sizeof(prio.stream_id)))
		return -EFAULT;

	if (!conn)
		return -ENOTCONN;

	/* Find the stream */
	stream = quic_stream_lookup(conn, prio.stream_id);
	if (!stream)
		return -ENOENT;

	/* Get the priority */
	quic_stream_get_priority(stream, &urgency, &incremental);

	/* Release lookup reference */
	refcount_dec(&stream->refcnt);

	/* Fill in response */
	memset(&prio, 0, sizeof(prio));
	prio.stream_id = stream->id;
	prio.urgency = urgency;
	prio.incremental = incremental ? 1 : 0;

	len = min_t(int, len, sizeof(prio));
	if (put_user(len, optlen))
		return -EFAULT;

	if (copy_to_user(optval, &prio, len))
		return -EFAULT;

	return 0;
}

int quic_setsockopt(struct sock *sk, int level, int optname,
		    sockptr_t optval, unsigned int optlen)
{
	struct quic_sock *qsk = quic_sk(sk);
	int err = 0;

	if (level == SOL_SOCKET)
		return sock_setsockopt(sk->sk_socket, level, optname,
				       optval, optlen);

	if (level != SOL_QUIC)
		return -ENOPROTOOPT;

	lock_sock(sk);

	switch (optname) {
	case QUIC_SOCKOPT_CONNECTION_ID:
		err = quic_setsockopt_cid(qsk, optval, optlen);
		break;

	case QUIC_SOCKOPT_STREAM_OPEN:
		err = quic_setsockopt_stream_open(qsk, optval, optlen);
		break;

	case QUIC_SOCKOPT_STREAM_CLOSE:
		err = quic_setsockopt_stream_close(qsk, optval, optlen);
		break;

	case QUIC_SOCKOPT_MAX_STREAMS:
		err = quic_setsockopt_max_streams(qsk, optval, optlen);
		break;

	case QUIC_SOCKOPT_IDLE_TIMEOUT:
		err = quic_setsockopt_idle_timeout(qsk, optval, optlen);
		break;

	case QUIC_SOCKOPT_MAX_DATA:
		err = quic_setsockopt_max_data(qsk, optval, optlen);
		break;

	case QUIC_SOCKOPT_ALPN:
		err = quic_setsockopt_alpn(qsk, optval, optlen);
		break;

	case QUIC_SOCKOPT_KEY:
		err = quic_setsockopt_key(qsk, optval, optlen);
		break;

	case QUIC_SOCKOPT_HANDSHAKE_COMPLETE:
		err = quic_setsockopt_handshake_complete(qsk, optval, optlen);
		break;

	case QUIC_SOCKOPT_STREAM_PRIORITY:
		err = quic_setsockopt_stream_priority(qsk, optval, optlen);
		break;

	case QUIC_SOCKOPT_SNI:
		err = quic_setsockopt_sni(qsk, optval, optlen);
		break;

	case QUIC_SOCKOPT_ALPN_SELECTED:
		/* Read-only option */
		err = -EOPNOTSUPP;
		break;

	default:
		err = -ENOPROTOOPT;
		break;
	}

	release_sock(sk);
	return err;
}

int quic_getsockopt(struct sock *sk, int level, int optname,
		    char __user *optval, int __user *optlen)
{
	struct quic_sock *qsk = quic_sk(sk);
	int err = 0;

	if (level == SOL_SOCKET)
		return sock_getsockopt(sk->sk_socket, level, optname,
				       optval, optlen);

	if (level != SOL_QUIC)
		return -ENOPROTOOPT;

	lock_sock(sk);

	switch (optname) {
	case QUIC_SOCKOPT_CONNECTION_ID:
		err = quic_getsockopt_cid(qsk, optval, optlen);
		break;

	case QUIC_SOCKOPT_MAX_STREAMS:
		err = quic_getsockopt_max_streams(qsk, optval, optlen);
		break;

	case QUIC_SOCKOPT_IDLE_TIMEOUT:
		err = quic_getsockopt_idle_timeout(qsk, optval, optlen);
		break;

	case QUIC_SOCKOPT_MAX_DATA:
		err = quic_getsockopt_max_data(qsk, optval, optlen);
		break;

	case QUIC_SOCKOPT_ALPN:
		err = quic_getsockopt_alpn(qsk, optval, optlen);
		break;

	case QUIC_SOCKOPT_STREAM_PRIORITY:
		err = quic_getsockopt_stream_priority(qsk, optval, optlen);
		break;

	case QUIC_SOCKOPT_SNI:
		err = quic_getsockopt_sni(qsk, optval, optlen);
		break;

	case QUIC_SOCKOPT_ALPN_SELECTED:
		err = quic_getsockopt_alpn_selected(qsk, optval, optlen);
		break;

	default:
		err = -ENOPROTOOPT;
		break;
	}

	release_sock(sk);
	return err;
}

/*
 * Send path implementation
 */
static int quic_sendmsg_stream(struct sock *sk, struct msghdr *msg,
			       u64 stream_id, size_t len)
{
	struct quic_sock *qsk = quic_sk(sk);
	struct quic_stream_entry *entry;
	size_t sent = 0;
	int err;

	/* Verify stream exists */
	rcu_read_lock();
	entry = quic_stream_lookup(&qsk->streams, stream_id);
	if (!entry) {
		rcu_read_unlock();
		return -ENOENT;
	}
	rcu_read_unlock();

	/*
	 * Check flow control.
	 * Use subtraction form to avoid integer overflow when tx_offset + len
	 * would exceed U64_MAX with large values.
	 */
	if (len > qsk->tx_max_data - qsk->tx_offset) {
		/* Flow control blocking */
		if (msg->msg_flags & MSG_DONTWAIT)
			return -EAGAIN;

		/* Wait for flow control credit */
		err = wait_event_interruptible(sk->sk_wq->wait,
			len <= qsk->tx_max_data - qsk->tx_offset ||
			sk->sk_err);
		if (err)
			return err;
		if (sk->sk_err)
			return -sk->sk_err;
	}

	/* Send data via UDP socket */
	if (qsk->udp_sock) {
		struct msghdr udp_msg = {};
		struct kvec iov;
		u8 *pkt_buf;
		u8 *user_data;
		size_t to_send = min(len, (size_t)sk->sk_sndbuf);
		size_t pkt_len;
		size_t header_len;
		size_t frame_overhead;
		u8 *p;
		u64 pn;

		/*
		 * Calculate packet size:
		 * - Short header: 1 byte flags + DCID + 1-4 byte PN
		 * - STREAM frame: 1 byte type + varint stream_id + varint offset +
		 *                 varint length + data
		 * - AEAD tag: 16 bytes
		 */
		header_len = 1 + qsk->remote_cid.len + 2;  /* Conservative PN length */
		frame_overhead = 1 + 8 + 8 + 2;  /* Type + stream_id + offset + length (max varint) */
		pkt_len = header_len + frame_overhead + to_send + 16;  /* +16 for AEAD tag */

		pkt_buf = kmalloc(pkt_len, GFP_KERNEL);
		if (!pkt_buf)
			return -ENOMEM;

		user_data = kmalloc(to_send, GFP_KERNEL);
		if (!user_data) {
			kfree(pkt_buf);
			return -ENOMEM;
		}

		if (!copy_from_iter_full(user_data, to_send, &msg->msg_iter)) {
			kfree(user_data);
			kfree(pkt_buf);
			return -EFAULT;
		}

		/*
		 * Build QUIC short header packet (RFC 9000 Section 17.3)
		 *
		 * Short Header {
		 *   Header Form (1) = 0,
		 *   Fixed Bit (1) = 1,
		 *   Spin Bit (1),
		 *   Reserved Bits (2),
		 *   Key Phase (1),
		 *   Packet Number Length (2),
		 *   Destination Connection ID (0..160),
		 *   Packet Number (8..32),
		 * }
		 */
		p = pkt_buf;
		pn = qsk->packets_sent;  /* Use packet counter as PN */

		/* First byte: form=0, fixed=1, spin=0, reserved=00, kp=0, pn_len=01 (2 bytes) */
		*p++ = 0x40 | 0x01;  /* Short header, fixed bit, 2-byte PN */

		/* Destination Connection ID */
		if (qsk->remote_cid.len > 0) {
			memcpy(p, qsk->remote_cid.data, qsk->remote_cid.len);
			p += qsk->remote_cid.len;
		}

		/* Packet Number (2 bytes) */
		*p++ = (pn >> 8) & 0xff;
		*p++ = pn & 0xff;

		header_len = p - pkt_buf;

		/*
		 * Build STREAM frame (RFC 9000 Section 19.8)
		 *
		 * STREAM Frame {
		 *   Type (i) = 0x08..0x0f,
		 *   Stream ID (i),
		 *   [Offset (i)],
		 *   [Length (i)],
		 *   Stream Data (..),
		 * }
		 */
		/* Frame type: 0x08 base + 0x04 (OFF) + 0x02 (LEN) = 0x0E */
		*p++ = 0x08 | 0x04 | 0x02;

		/* Stream ID (varint - RFC 9000 Section 16) */
		p += quic_encode_varint(p, stream_id);

		/* Offset (varint - RFC 9000 Section 16) */
		p += quic_encode_varint(p, qsk->tx_offset);

		/* Length (varint - RFC 9000 Section 16) */
		p += quic_encode_varint(p, to_send);

		/* Stream data */
		memcpy(p, user_data, to_send);
		p += to_send;

		pkt_len = p - pkt_buf;

		/*
		 * Encryption: Apply AEAD packet protection (RFC 9001 Section 5)
		 *
		 * For production: Use quic_packet_encrypt() or similar.
		 * This requires properly negotiated keys from TLS handshake.
		 */
		if (qsk->conn && qsk->conn->handshake_complete) {
			/* Use connection's crypto context for encryption */
			struct quic_crypto_ctx *crypto =
				&qsk->conn->crypto[QUIC_CRYPTO_APPLICATION];

			if (crypto->keys_available) {
				err = quic_crypto_encrypt(crypto, pkt_buf, pkt_len,
							  header_len, pn);
				if (err < 0) {
					kfree(user_data);
					kfree(pkt_buf);
					return err;
				}
				pkt_len += 16;  /* AEAD tag */

				/* Apply header protection */
				err = quic_crypto_hp_mask(crypto,
							  pkt_buf + header_len + 4,
							  pkt_buf);
				if (err < 0) {
					kfree(user_data);
					kfree(pkt_buf);
					return err;
				}
			} else {
				/*
				 * Keys not available - cannot send application data
				 * unencrypted. Return error to caller.
				 */
				kfree(user_data);
				kfree(pkt_buf);
				return -EAGAIN;
			}
		} else {
			/*
			 * Handshake not complete - cannot send application data
			 * yet. Caller should wait for connection establishment.
			 */
			kfree(user_data);
			kfree(pkt_buf);
			return -ENOTCONN;
		}

		kfree(user_data);

		iov.iov_base = pkt_buf;
		iov.iov_len = pkt_len;

		err = kernel_sendmsg(qsk->udp_sock, &udp_msg, &iov, 1, pkt_len);
		if (err < 0) {
			kfree(pkt_buf);
			return err;
		}

		sent = to_send;  /* Application data sent (not wire bytes) */
		qsk->tx_offset += sent;
		qsk->bytes_sent += pkt_len;
		qsk->packets_sent++;

		kfree(pkt_buf);
	} else {
		/* No UDP socket yet - queue data */
		return -ENOTCONN;
	}

	return sent;
}

int quic_sendmsg(struct sock *sk, struct msghdr *msg, size_t len)
{
	struct quic_sock *qsk = quic_sk(sk);
	struct quic_stream_info *info = NULL;
	struct cmsghdr *cmsg;
	u64 stream_id = 0;
	size_t copied = 0;
	int err = 0;
	long timeo;

	/* Parse ancillary data for stream ID */
	for_each_cmsghdr(cmsg, msg) {
		if (cmsg->cmsg_level != SOL_QUIC)
			continue;

		if (cmsg->cmsg_type == QUIC_SOCKOPT_STREAM_OPEN &&
		    cmsg->cmsg_len >= CMSG_LEN(sizeof(struct quic_stream_info))) {
			info = CMSG_DATA(cmsg);
			stream_id = info->stream_id;
			break;
		}
	}

	/* If no stream specified, use default (stream 0 for bidi) */
	if (!info) {
		bool stream_exists;

		stream_id = 0;

		/* Ensure stream 0 exists - need RCU lock for lookup */
		rcu_read_lock();
		stream_exists = (quic_stream_lookup(&qsk->streams, 0) != NULL);
		rcu_read_unlock();

		if (!stream_exists) {
			err = quic_stream_insert(&qsk->streams, 0, NULL);
			if (err)
				return err;
		}
	}

	lock_sock(sk);

	timeo = sock_sndtimeo(sk, msg->msg_flags & MSG_DONTWAIT);

	/* Check socket state */
	if (sk->sk_state == TCP_LISTEN) {
		err = -ENOTCONN;
		goto out;
	}

	if (!quic_is_established(qsk) && !(msg->msg_flags & MSG_DONTWAIT)) {
		/* Wait for handshake completion */
		err = sk_stream_wait_connect(sk, &timeo);
		if (err)
			goto out;
	}

	/* Check for errors */
	if (sk->sk_err) {
		err = -sk->sk_err;
		goto out;
	}

	if (sk->sk_shutdown & SEND_SHUTDOWN) {
		err = -EPIPE;
		goto out;
	}

	/* Send data */
	while (copied < len) {
		size_t chunk = min(len - copied, (size_t)PAGE_SIZE);

		err = quic_sendmsg_stream(sk, msg, stream_id, chunk);
		if (err < 0) {
			if (copied > 0)
				break;  /* Return what we've sent */
			goto out;
		}

		copied += err;

		/* Handle MSG_MORE - batch sends */
		if ((msg->msg_flags & MSG_MORE) && copied < len)
			continue;
	}

	err = copied;

out:
	release_sock(sk);
	return err;
}

/*
 * Receive path implementation
 */
static int quic_recvmsg_stream(struct sock *sk, struct msghdr *msg,
			       size_t len, int flags, u64 *stream_id_out)
{
	struct quic_sock *qsk = quic_sk(sk);
	struct sk_buff *skb;
	int copied = 0;
	int err;

	spin_lock_bh(&qsk->rx_lock);

	skb = skb_peek(&qsk->receive_queue);
	if (!skb) {
		spin_unlock_bh(&qsk->rx_lock);
		return -EAGAIN;
	}

	if (!(flags & MSG_PEEK))
		__skb_unlink(skb, &qsk->receive_queue);

	spin_unlock_bh(&qsk->rx_lock);

	/*
	 * Parse QUIC packet header and extract stream ID from STREAM frame
	 *
	 * QUIC Short Header (RFC 9000 Section 17.3):
	 *   First byte: Form(1) | Fixed(1) | Spin(1) | Reserved(2) | KeyPhase(1) | PN_Len(2)
	 *   DCID: 0-20 bytes (length known from connection)
	 *   Packet Number: 1-4 bytes (length from first byte)
	 *
	 * After decryption, parse STREAM frame (RFC 9000 Section 19.8):
	 *   Type: 0x08-0x0F (bits indicate OFF/LEN/FIN)
	 *   Stream ID: varint
	 *   [Offset]: varint (if OFF bit set)
	 *   [Length]: varint (if LEN bit set)
	 *   Data: remaining bytes or Length bytes
	 */
	if (stream_id_out) {
		u8 *data = skb->data;
		size_t data_len = skb->len;
		size_t offset = 0;
		u8 first_byte;
		u8 pn_len;
		u64 stream_id = 0;

		*stream_id_out = 0;  /* Default */

		if (data_len < 2)
			goto copy_data;

		first_byte = data[0];

		/* Check if short header (form bit = 0) */
		if (!(first_byte & 0x80)) {
			/* Short header packet */
			pn_len = (first_byte & 0x03) + 1;

			/* Skip DCID (use local CID length as expected DCID len) */
			offset = 1 + qsk->local_cid.len + pn_len;

			if (offset >= data_len)
				goto copy_data;

			/*
			 * Decrypt packet if connection has keys.
			 * For now, assume data after header is already decrypted
			 * (e.g., by receive processing before queueing).
			 */

			/* Parse frames - look for STREAM frame (0x08-0x0F) */
			while (offset < data_len) {
				u8 frame_type = data[offset];

				/* Check for STREAM frame type (0x08-0x0F) */
				if ((frame_type & 0xF8) == 0x08) {
					bool has_offset = frame_type & 0x04;
					bool has_length = frame_type & 0x02;
					u8 varint_len;

					offset++;

					/* Parse Stream ID (varint) */
					if (offset >= data_len)
						break;

					/* Decode varint for stream ID */
					if ((data[offset] & 0xC0) == 0x00) {
						stream_id = data[offset] & 0x3F;
						offset++;
					} else if ((data[offset] & 0xC0) == 0x40) {
						if (offset + 1 >= data_len)
							break;
						stream_id = ((data[offset] & 0x3F) << 8) |
							     data[offset + 1];
						offset += 2;
					} else if ((data[offset] & 0xC0) == 0x80) {
						if (offset + 3 >= data_len)
							break;
						stream_id = ((u64)(data[offset] & 0x3F) << 24) |
							     ((u64)data[offset + 1] << 16) |
							     ((u64)data[offset + 2] << 8) |
							     data[offset + 3];
						offset += 4;
					} else {
						/* 8-byte varint */
						if (offset + 7 >= data_len)
							break;
						offset += 8;
					}

					/*
					 * Skip Offset field if present (RFC 9000 Section 19.8)
					 * The OFF bit indicates presence of Offset field.
					 */
					if (has_offset && offset < data_len) {
						varint_len = 1 << ((data[offset] & 0xC0) >> 6);
						if (offset + varint_len > data_len)
							break;
						offset += varint_len;
					}

					/*
					 * Skip Length field if present (RFC 9000 Section 19.8)
					 * The LEN bit indicates presence of Length field.
					 */
					if (has_length && offset < data_len) {
						varint_len = 1 << ((data[offset] & 0xC0) >> 6);
						if (offset + varint_len > data_len)
							break;
						offset += varint_len;
					}

					*stream_id_out = stream_id;
					break;  /* Found stream ID */
				}

				/* Skip other frame types */
				if (frame_type == 0x00) {
					/* PADDING - skip single byte */
					offset++;
				} else if (frame_type == 0x01) {
					/* PING - skip single byte */
					offset++;
				} else {
					/* Unknown frame - cannot continue parsing */
					break;
				}
			}
		} else {
			/* Long header - would need version-specific parsing */
			/* For Initial packets, stream 0 is implicit crypto stream */
			*stream_id_out = 0;
		}
	}

copy_data:
	/* Copy data to user */
	copied = min_t(size_t, len, skb->len);

	if (!(flags & MSG_TRUNC)) {
		err = skb_copy_datagram_msg(skb, 0, msg, copied);
		if (err < 0) {
			if (!(flags & MSG_PEEK)) {
				/* Re-queue the skb */
				spin_lock_bh(&qsk->rx_lock);
				skb_queue_head(&qsk->receive_queue, skb);
				spin_unlock_bh(&qsk->rx_lock);
			}
			return err;
		}
	}

	/* Update flow control */
	qsk->rx_offset += copied;

	if (!(flags & MSG_PEEK)) {
		consume_skb(skb);
	}

	return copied;
}

int quic_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
		 int flags, int *addr_len)
{
	struct quic_sock *qsk = quic_sk(sk);
	struct quic_stream_info stream_info = {};
	int copied = 0;
	int err = 0;
	long timeo;

	if (flags & MSG_ERRQUEUE)
		return inet_recv_error(sk, msg, len, addr_len);

	lock_sock(sk);

	if (sk->sk_state == TCP_LISTEN) {
		err = -ENOTCONN;
		goto out;
	}

	timeo = sock_rcvtimeo(sk, flags & MSG_DONTWAIT);

	while (copied < len) {
		u64 stream_id;
		int chunk;

		/* Try to receive data */
		chunk = quic_recvmsg_stream(sk, msg, len - copied, flags,
					    &stream_id);
		if (chunk > 0) {
			copied += chunk;
			stream_info.stream_id = stream_id;

			if (flags & MSG_PEEK)
				break;
			continue;
		}

		if (chunk == -EAGAIN) {
			/* No data available */
			if (copied > 0)
				break;  /* Return what we have */

			if (sk->sk_err) {
				err = -sk->sk_err;
				goto out;
			}

			if (sk->sk_shutdown & RCV_SHUTDOWN) {
				/* EOF */
				break;
			}

			if (sk->sk_state == TCP_CLOSE) {
				err = -ENOTCONN;
				goto out;
			}

			if (!timeo) {
				err = -EAGAIN;
				goto out;
			}

			if (signal_pending(current)) {
				err = sock_intr_errno(timeo);
				goto out;
			}

			/* Wait for data */
			err = sk_wait_data(sk, &timeo, NULL);
			if (err < 0)
				goto out;
			continue;
		}

		/* Error occurred */
		if (copied > 0)
			break;
		err = chunk;
		goto out;
	}

	/* Return stream ID in ancillary data */
	if (copied > 0) {
		put_cmsg(msg, SOL_QUIC, QUIC_SOCKOPT_STREAM_OPEN,
			 sizeof(stream_info), &stream_info);
	}

	err = copied;

out:
	release_sock(sk);
	return err;
}

/*
 * Stream accept/connect operations
 */
struct sock *quic_stream_accept(struct sock *sk, int flags, int *err, bool kern)
{
	struct quic_sock *qsk = quic_sk(sk);
	struct quic_accept_entry *entry;
	struct sock *new_sk = NULL;
	long timeo;
	DEFINE_WAIT(wait);

	lock_sock(sk);

	if (sk->sk_state != TCP_LISTEN) {
		*err = -EINVAL;
		goto out;
	}

	timeo = sock_rcvtimeo(sk, flags & O_NONBLOCK);

	while (1) {
		spin_lock_bh(&qsk->accept_lock);

		if (!list_empty(&qsk->accept_queue)) {
			entry = list_first_entry(&qsk->accept_queue,
						 struct quic_accept_entry, node);
			list_del(&entry->node);
			qsk->accept_queue_len--;
			new_sk = entry->sk;
			kfree(entry);
			spin_unlock_bh(&qsk->accept_lock);
			break;
		}

		spin_unlock_bh(&qsk->accept_lock);

		if (!timeo) {
			*err = -EAGAIN;
			goto out;
		}

		if (signal_pending(current)) {
			*err = sock_intr_errno(timeo);
			goto out;
		}

		prepare_to_wait_exclusive(sk_sleep(sk), &wait,
					  TASK_INTERRUPTIBLE);
		release_sock(sk);
		timeo = schedule_timeout(timeo);
		lock_sock(sk);
		finish_wait(sk_sleep(sk), &wait);

		if (sk->sk_state != TCP_LISTEN) {
			*err = -EINVAL;
			goto out;
		}
	}

	*err = 0;

out:
	release_sock(sk);
	return new_sk;
}

int quic_stream_connect(struct sock *sk, struct sockaddr *uaddr, int addr_len,
			int flags)
{
	struct quic_sock *qsk = quic_sk(sk);
	struct sockaddr_in *sin = (struct sockaddr_in *)uaddr;
	int err;

	if (addr_len < sizeof(struct sockaddr_in))
		return -EINVAL;

	if (sin->sin_family != AF_INET && sin->sin_family != AF_INET6)
		return -EAFNOSUPPORT;

	lock_sock(sk);

	if (sk->sk_state != TCP_CLOSE) {
		err = -EISCONN;
		goto out;
	}

	/* Store destination address */
	inet_sk(sk)->inet_daddr = sin->sin_addr.s_addr;
	inet_sk(sk)->inet_dport = sin->sin_port;

#if IS_ENABLED(CONFIG_IPV6)
	if (sin->sin_family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)uaddr;
		sk->sk_v6_daddr = sin6->sin6_addr;
	}
#endif

	/* Create UDP socket if not already created */
	if (!qsk->udp_sock) {
		err = quic_create_udp_sock(sk);
		if (err)
			goto out;
	}

	/* Connect the underlying UDP socket */
	err = kernel_connect(qsk->udp_sock, uaddr, addr_len, flags);
	if (err && err != -EINPROGRESS)
		goto out;

	/* Mark as connected */
	set_bit(QUIC_F_CONNECTED, &qsk->flags);
	sk->sk_state = TCP_ESTABLISHED;

	err = 0;

out:
	release_sock(sk);
	return err;
}

/*
 * Socket operations
 */
static int quic_init_sock(struct sock *sk)
{
	return quic_sk_init(sk);
}

static void quic_destroy_sock(struct sock *sk)
{
	struct quic_sock *qsk = quic_sk(sk);

	pr_debug("Destroying QUIC socket %p\n", sk);

	/* Release UDP socket */
	quic_release_udp_sock(sk);

	/* Mark as closing */
	set_bit(QUIC_F_CLOSING, &qsk->flags);
}

static void quic_close(struct sock *sk, long timeout)
{
	pr_debug("Closing QUIC socket %p, timeout=%ld\n", sk, timeout);

	lock_sock(sk);

	sk->sk_shutdown = SHUTDOWN_MASK;

	/* Clean up connection */
	quic_destroy_sock(sk);

	sk->sk_state = TCP_CLOSE;

	release_sock(sk);

	sock_orphan(sk);
	sock_put(sk);
}

static int quic_disconnect(struct sock *sk, int flags)
{
	struct quic_sock *qsk = quic_sk(sk);

	lock_sock(sk);

	/* Release UDP socket */
	quic_release_udp_sock(sk);

	/* Reset state */
	clear_bit(QUIC_F_CONNECTED, &qsk->flags);
	clear_bit(QUIC_F_HANDSHAKE_COMPLETE, &qsk->flags);
	sk->sk_state = TCP_CLOSE;

	/* Clear addresses */
	inet_sk(sk)->inet_daddr = 0;
	inet_sk(sk)->inet_dport = 0;

	release_sock(sk);

	return 0;
}

static int quic_ioctl(struct sock *sk, int cmd, int *karg)
{
	struct quic_sock *qsk = quic_sk(sk);

	switch (cmd) {
	case SIOCINQ:
		lock_sock(sk);
		*karg = skb_queue_len(&qsk->receive_queue);
		release_sock(sk);
		break;

	case SIOCOUTQ:
		lock_sock(sk);
		*karg = sk->sk_wmem_queued;
		release_sock(sk);
		break;

	default:
		return -ENOIOCTLCMD;
	}

	return 0;
}

static int quic_hash(struct sock *sk)
{
	/* QUIC sockets don't go into the hash tables directly */
	return 0;
}

static void quic_unhash(struct sock *sk)
{
	/* Nothing to do */
}

static int quic_get_port(struct sock *sk, unsigned short snum)
{
	struct quic_sock *qsk = quic_sk(sk);

	/* If we have a UDP socket, delegate to it */
	if (qsk->udp_sock) {
		struct sock *usk = qsk->udp_sock->sk;
		return inet_csk_get_port(usk, snum);
	}

	/* Otherwise, just accept the port */
	inet_sk(sk)->inet_num = snum;
	return 0;
}

static void quic_shutdown(struct sock *sk, int how)
{
	struct quic_sock *qsk = quic_sk(sk);

	pr_debug("Shutdown QUIC socket %p, how=%d\n", sk, how);

	/*
	 * Per QUIC semantics, shutdown should trigger CONNECTION_CLOSE.
	 * SEND_SHUTDOWN: We stop sending and initiate connection close.
	 * RCV_SHUTDOWN: We stop processing received data.
	 */
	if (how & SEND_SHUTDOWN) {
		sk->sk_shutdown |= SEND_SHUTDOWN;

		/* Initiate QUIC connection close if we have a connection */
		if (qsk->conn) {
			quic_conn_close(qsk->conn, QUIC_ERROR_NO_ERROR,
					"socket shutdown", 15, false);
		}
	}

	if (how & RCV_SHUTDOWN)
		sk->sk_shutdown |= RCV_SHUTDOWN;
}

static __poll_t quic_poll(struct file *file, struct socket *sock,
			  poll_table *wait)
{
	struct sock *sk = sock->sk;
	struct quic_sock *qsk = quic_sk(sk);
	__poll_t mask = 0;

	sock_poll_wait(file, sock, wait);

	if (sk->sk_state == TCP_LISTEN) {
		/* Check accept queue */
		spin_lock_bh(&qsk->accept_lock);
		if (!list_empty(&qsk->accept_queue))
			mask |= EPOLLIN | EPOLLRDNORM;
		spin_unlock_bh(&qsk->accept_lock);
		return mask;
	}

	/* Check for errors */
	if (sk->sk_err)
		mask |= EPOLLERR;

	/* Check for read availability */
	if (!skb_queue_empty(&qsk->receive_queue))
		mask |= EPOLLIN | EPOLLRDNORM;

	/* Check for write availability */
	if (sk_stream_is_writeable(sk))
		mask |= EPOLLOUT | EPOLLWRNORM;

	/* Check for hangup */
	if (sk->sk_shutdown == SHUTDOWN_MASK)
		mask |= EPOLLHUP;

	if (sk->sk_shutdown & RCV_SHUTDOWN)
		mask |= EPOLLIN | EPOLLRDNORM | EPOLLRDHUP;

	return mask;
}

/*
 * Socket bind operation
 */
static int quic_bind(struct socket *sock, struct sockaddr *uaddr, int addr_len)
{
	struct sock *sk = sock->sk;
	struct quic_sock *qsk = quic_sk(sk);
	int err;

	lock_sock(sk);

	/* Create UDP socket */
	if (!qsk->udp_sock) {
		/* Store local address first */
		if (sk->sk_family == AF_INET) {
			struct sockaddr_in *sin = (struct sockaddr_in *)uaddr;
			inet_sk(sk)->inet_saddr = sin->sin_addr.s_addr;
			inet_sk(sk)->inet_rcv_saddr = sin->sin_addr.s_addr;
			inet_sk(sk)->inet_sport = sin->sin_port;
		}
#if IS_ENABLED(CONFIG_IPV6)
		else if (sk->sk_family == AF_INET6) {
			struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)uaddr;
			sk->sk_v6_rcv_saddr = sin6->sin6_addr;
			inet_sk(sk)->inet_sport = sin6->sin6_port;
		}
#endif

		err = quic_create_udp_sock(sk);
		if (err) {
			release_sock(sk);
			return err;
		}
	}

	/* Bind the underlying UDP socket */
	err = kernel_bind(qsk->udp_sock, uaddr, addr_len);
	if (err) {
		release_sock(sk);
		return err;
	}

	/* Update local address from UDP socket */
	if (sk->sk_family == AF_INET) {
		inet_sk(sk)->inet_sport = inet_sk(qsk->udp_sock->sk)->inet_sport;
		inet_sk(sk)->inet_saddr = inet_sk(qsk->udp_sock->sk)->inet_saddr;
		inet_sk(sk)->inet_rcv_saddr = inet_sk(qsk->udp_sock->sk)->inet_rcv_saddr;
	}
#if IS_ENABLED(CONFIG_IPV6)
	else if (sk->sk_family == AF_INET6) {
		inet_sk(sk)->inet_sport = inet_sk(qsk->udp_sock->sk)->inet_sport;
		sk->sk_v6_rcv_saddr = qsk->udp_sock->sk->sk_v6_rcv_saddr;
	}
#endif

	release_sock(sk);
	return 0;
}

/*
 * Socket listen operation
 */
static int quic_listen(struct socket *sock, int backlog)
{
	struct sock *sk = sock->sk;
	struct quic_sock *qsk = quic_sk(sk);
	int err = 0;

	lock_sock(sk);

	if (sock->state != SS_UNCONNECTED) {
		err = -EINVAL;
		goto out;
	}

	/* Create UDP socket if not already created */
	if (!qsk->udp_sock) {
		err = quic_create_udp_sock(sk);
		if (err)
			goto out;
	}

	sk->sk_state = TCP_LISTEN;
	sk->sk_max_ack_backlog = backlog;
	qsk->accept_queue_max = backlog;

	set_bit(QUIC_F_LISTENING, &qsk->flags);

out:
	release_sock(sk);
	return err;
}

/*
 * Socket accept operation
 */
static int quic_accept(struct socket *sock, struct socket *newsock,
		       struct proto_accept_arg *arg)
{
	struct sock *sk = sock->sk;
	struct sock *newsk;
	int err;

	newsk = quic_stream_accept(sk, arg->flags, &err, arg->kern);
	if (!newsk)
		return err;

	lock_sock(newsk);
	sock_graft(newsk, newsock);
	newsock->state = SS_CONNECTED;
	release_sock(newsk);

	return 0;
}

/*
 * Socket connect operation (wrapper)
 */
static int quic_connect(struct socket *sock, struct sockaddr *uaddr,
			int addr_len, int flags)
{
	return quic_stream_connect(sock->sk, uaddr, addr_len, flags);
}

/*
 * Protocol definitions
 */
struct proto quic_prot = {
	.name			= "QUIC",
	.owner			= THIS_MODULE,
	.init			= quic_init_sock,
	.destroy		= quic_destroy_sock,
	.close			= quic_close,
	.disconnect		= quic_disconnect,
	.shutdown		= quic_shutdown,
	.sendmsg		= quic_sendmsg,
	.recvmsg		= quic_recvmsg,
	.setsockopt		= quic_setsockopt,
	.getsockopt		= quic_getsockopt,
	.ioctl			= quic_ioctl,
	.hash			= quic_hash,
	.unhash			= quic_unhash,
	.get_port		= quic_get_port,
	.sockets_allocated	= &quic_sockets_allocated,
	.obj_size		= sizeof(struct quic_sock),
	.no_autobind		= true,
};
EXPORT_SYMBOL_GPL(quic_prot);

#if IS_ENABLED(CONFIG_IPV6)
struct proto quicv6_prot = {
	.name			= "QUICv6",
	.owner			= THIS_MODULE,
	.init			= quic_init_sock,
	.destroy		= quic_destroy_sock,
	.close			= quic_close,
	.disconnect		= quic_disconnect,
	.shutdown		= quic_shutdown,
	.sendmsg		= quic_sendmsg,
	.recvmsg		= quic_recvmsg,
	.setsockopt		= quic_setsockopt,
	.getsockopt		= quic_getsockopt,
	.ioctl			= quic_ioctl,
	.hash			= quic_hash,
	.unhash			= quic_unhash,
	.get_port		= quic_get_port,
	.sockets_allocated	= &quic_sockets_allocated,
	.obj_size		= sizeof(struct quic6_sock),
	.no_autobind		= true,
};
EXPORT_SYMBOL_GPL(quicv6_prot);
#endif

/*
 * Socket-level proto_ops wrappers
 *
 * These wrappers properly call QUIC-specific handlers instead of delegating
 * to generic inet_* functions which have TCP-specific assumptions.
 */

/*
 * quic_release_sock - Release a QUIC socket
 *
 * This is the proto_ops release handler that properly cleans up QUIC state.
 * Unlike inet_release which is designed for TCP/UDP, we need QUIC-specific
 * cleanup for connection state, streams, and the underlying UDP socket.
 */
static int quic_release_sock(struct socket *sock)
{
	struct sock *sk = sock->sk;

	if (!sk)
		return 0;

	/* Let the proto close handler do QUIC-specific cleanup */
	if (sk->sk_prot->close) {
		long timeout = 0;

		if (sock_flag(sk, SOCK_LINGER) &&
		    !(current->flags & PF_EXITING))
			timeout = sk->sk_lingertime;

		sk->sk_prot->close(sk, timeout);
	}

	sock->sk = NULL;
	return 0;
}

/*
 * quic_sock_shutdown - Shutdown a QUIC socket
 *
 * QUIC shutdown semantics differ from TCP:
 * - SEND_SHUTDOWN triggers CONNECTION_CLOSE frame
 * - RCV_SHUTDOWN stops processing incoming data
 * - Both are needed for full bidirectional close
 *
 * Unlike inet_shutdown which has TCP state machine dependencies,
 * we directly invoke QUIC-specific shutdown logic.
 */
static int quic_sock_shutdown(struct socket *sock, int how)
{
	struct sock *sk = sock->sk;
	int err = 0;

	/* Validate shutdown flags */
	how++;  /* maps 0->1, 1->2, 2->3 per POSIX shutdown() semantics */
	if ((how & ~SHUTDOWN_MASK) || !how)
		return -EINVAL;

	lock_sock(sk);

	/* Update socket state for connection management */
	if (sock->state == SS_CONNECTING)
		sock->state = SS_DISCONNECTING;

	/* Check for already closed socket */
	if (sk->sk_state == TCP_CLOSE) {
		err = -ENOTCONN;
		/* Still update shutdown flags to wake up waiters */
	}

	/* Set shutdown flags */
	WRITE_ONCE(sk->sk_shutdown, sk->sk_shutdown | how);

	/* Call QUIC-specific shutdown handler */
	if (sk->sk_prot->shutdown)
		sk->sk_prot->shutdown(sk, how);

	/* Wake up any processes waiting in poll */
	sk->sk_state_change(sk);

	release_sock(sk);
	return err;
}

/*
 * quic_sock_sendmsg - Send message on QUIC socket
 *
 * This wrapper directly calls the QUIC sendmsg handler instead of going
 * through inet_sendmsg. This ensures:
 * - No TCP/UDP-specific INDIRECT_CALL optimizations that slow QUIC
 * - Proper handling of QUIC stream semantics
 * - Correct ancillary message processing for stream IDs
 */
static int quic_sock_sendmsg(struct socket *sock, struct msghdr *msg,
			     size_t size)
{
	struct sock *sk = sock->sk;

	/* Basic socket state validation */
	if (unlikely(inet_send_prepare(sk)))
		return -EAGAIN;

	return quic_sendmsg(sk, msg, size);
}

/*
 * quic_sock_recvmsg - Receive message from QUIC socket
 *
 * This wrapper directly calls the QUIC recvmsg handler. This ensures:
 * - Proper QUIC stream reassembly
 * - Correct handling of stream FIN
 * - Stream ID information in ancillary data
 */
static int quic_sock_recvmsg(struct socket *sock, struct msghdr *msg,
			     size_t size, int flags)
{
	struct sock *sk = sock->sk;
	int addr_len = 0;
	int err;

	/*
	 * Note: RPS flow recording is handled by the kernel's UDP layer
	 * which underlies our QUIC implementation.
	 */

	err = quic_recvmsg(sk, msg, size, flags, &addr_len);
	if (err >= 0)
		msg->msg_namelen = addr_len;

	return err;
}

/*
 * Proto operations for socket interface
 *
 * Note: We use QUIC-specific handlers for operations that have different
 * semantics from TCP/UDP:
 * - release: quic_release_sock (proper QUIC state cleanup)
 * - shutdown: quic_sock_shutdown (triggers CONNECTION_CLOSE)
 * - sendmsg: quic_sock_sendmsg (QUIC stream semantics)
 * - recvmsg: quic_sock_recvmsg (QUIC stream reassembly)
 *
 * Operations that correctly delegate are:
 * - setsockopt/getsockopt: sock_common_* correctly calls sk->sk_prot handlers
 * - getname: inet_getname works for QUIC (same address semantics)
 * - ioctl: inet_ioctl handles standard socket ioctls
 * - socketpair: sock_no_socketpair (QUIC doesn't support socketpair)
 * - mmap: sock_no_mmap (QUIC doesn't support mmap)
 */
static const struct proto_ops quic_stream_ops = {
	.family		= PF_INET,
	.owner		= THIS_MODULE,
	.release	= quic_release_sock,
	.bind		= quic_bind,
	.connect	= quic_connect,
	.socketpair	= sock_no_socketpair,
	.accept		= quic_accept,
	.getname	= inet_getname,
	.poll		= quic_poll,
	.ioctl		= inet_ioctl,
	.listen		= quic_listen,
	.shutdown	= quic_sock_shutdown,
	.setsockopt	= sock_common_setsockopt,
	.getsockopt	= sock_common_getsockopt,
	.sendmsg	= quic_sock_sendmsg,
	.recvmsg	= quic_sock_recvmsg,
	.mmap		= sock_no_mmap,
};

#if IS_ENABLED(CONFIG_IPV6)
static const struct proto_ops quic6_stream_ops = {
	.family		= PF_INET6,
	.owner		= THIS_MODULE,
	.release	= quic_release_sock,
	.bind		= quic_bind,
	.connect	= quic_connect,
	.socketpair	= sock_no_socketpair,
	.accept		= quic_accept,
	.getname	= inet6_getname,
	.poll		= quic_poll,
	.ioctl		= inet6_ioctl,
	.listen		= quic_listen,
	.shutdown	= quic_sock_shutdown,
	.setsockopt	= sock_common_setsockopt,
	.getsockopt	= sock_common_getsockopt,
	.sendmsg	= quic_sock_sendmsg,
	.recvmsg	= quic_sock_recvmsg,
	.mmap		= sock_no_mmap,
};
#endif

/*
 * Socket creation
 */
static int quic_create(struct net *net, struct socket *sock, int protocol,
		       int kern)
{
	struct sock *sk;
	int err;

	if (sock->type != SOCK_STREAM && sock->type != SOCK_DGRAM)
		return -ESOCKTNOSUPPORT;

	sock->state = SS_UNCONNECTED;
	sock->ops = &quic_stream_ops;

	sk = quic_sk_alloc(net, sock, protocol, GFP_KERNEL, AF_INET);
	if (IS_ERR(sk))
		return PTR_ERR(sk);

	err = quic_sk_init(sk);
	if (err) {
		sk_common_release(sk);
		return err;
	}

	return 0;
}

#if IS_ENABLED(CONFIG_IPV6)
static int quic6_create(struct net *net, struct socket *sock, int protocol,
			int kern)
{
	struct sock *sk;
	int err;

	if (sock->type != SOCK_STREAM && sock->type != SOCK_DGRAM)
		return -ESOCKTNOSUPPORT;

	sock->state = SS_UNCONNECTED;
	sock->ops = &quic6_stream_ops;

	sk = quic_sk_alloc(net, sock, protocol, GFP_KERNEL, AF_INET6);
	if (IS_ERR(sk))
		return PTR_ERR(sk);

	err = quic_sk_init(sk);
	if (err) {
		sk_common_release(sk);
		return err;
	}

	return 0;
}
#endif

/*
 * Module initialization
 */
static struct inet_protosw quic_protosw = {
	.type		= SOCK_STREAM,
	.protocol	= IPPROTO_UDP,  /* QUIC runs over UDP */
	.prot		= &quic_prot,
	.ops		= &quic_stream_ops,
	.flags		= INET_PROTOSW_ICSK,
};

#if IS_ENABLED(CONFIG_IPV6)
static struct inet_protosw quicv6_protosw = {
	.type		= SOCK_STREAM,
	.protocol	= IPPROTO_UDP,
	.prot		= &quicv6_prot,
	.ops		= &quic6_stream_ops,
	.flags		= INET_PROTOSW_ICSK,
};
#endif

int __init quic_socket_init(void)
{
	int err;

	err = percpu_counter_init(&quic_sockets_allocated, 0, GFP_KERNEL);
	if (err)
		return err;

	err = proto_register(&quic_prot, 1);
	if (err) {
		percpu_counter_destroy(&quic_sockets_allocated);
		return err;
	}

#if IS_ENABLED(CONFIG_IPV6)
	err = proto_register(&quicv6_prot, 1);
	if (err) {
		proto_unregister(&quic_prot);
		percpu_counter_destroy(&quic_sockets_allocated);
		return err;
	}
#endif

	inet_register_protosw(&quic_protosw);

#if IS_ENABLED(CONFIG_IPV6)
	inet6_register_protosw(&quicv6_protosw);
#endif

	pr_info("QUIC socket layer initialized\n");
	return 0;
}

void __exit quic_socket_exit(void)
{
#if IS_ENABLED(CONFIG_IPV6)
	inet6_unregister_protosw(&quicv6_protosw);
	proto_unregister(&quicv6_prot);
#endif

	inet_unregister_protosw(&quic_protosw);
	proto_unregister(&quic_prot);

	percpu_counter_destroy(&quic_sockets_allocated);

	pr_info("QUIC socket layer exited\n");
}

/* Export symbols for other QUIC modules */
EXPORT_SYMBOL_GPL(quic_sk_alloc);
EXPORT_SYMBOL_GPL(quic_sk_free);
EXPORT_SYMBOL_GPL(quic_sk_wake_up);
EXPORT_SYMBOL_GPL(quic_data_ready);
EXPORT_SYMBOL_GPL(quic_write_space);
EXPORT_SYMBOL_GPL(quic_sendmsg);
EXPORT_SYMBOL_GPL(quic_recvmsg);
EXPORT_SYMBOL_GPL(quic_setsockopt);
EXPORT_SYMBOL_GPL(quic_getsockopt);
EXPORT_SYMBOL_GPL(quic_stream_accept);
EXPORT_SYMBOL_GPL(quic_stream_connect);
EXPORT_SYMBOL_GPL(quic_socket_init);
EXPORT_SYMBOL_GPL(quic_socket_exit);

MODULE_DESCRIPTION("QUIC Socket Interface");
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux QUIC Authors");
