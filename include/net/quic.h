/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * QUIC - Quick UDP Internet Connections
 *
 * Linux kernel QUIC implementation based on RFC 9000, RFC 9001, RFC 9002
 *
 * Copyright (c) 2024 Linux QUIC Authors
 */

#ifndef _NET_QUIC_H
#define _NET_QUIC_H

#include <linux/types.h>
#include <linux/socket.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/rbtree.h>
#include <linux/list.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <linux/crypto.h>
#include <net/sock.h>
#include <net/inet_sock.h>
#include <net/inet_connection_sock.h>
#include <net/udp.h>
#include <crypto/aead.h>
#include <crypto/hash.h>
#include <uapi/linux/quic.h>

/* Forward declarations */
struct quic_sock;
struct quic_connection;
struct quic_stream;
struct quic_packet;
struct quic_frame;
struct quic_crypto_ctx;
struct quic_pn_space;
struct quic_path;

/* QUIC packet number space indices */
#define QUIC_PN_SPACE_INITIAL		0
#define QUIC_PN_SPACE_HANDSHAKE		1
#define QUIC_PN_SPACE_APPLICATION	2
#define QUIC_PN_SPACE_MAX		3

/* QUIC timer types */
#define QUIC_TIMER_LOSS		0
#define QUIC_TIMER_ACK		1
#define QUIC_TIMER_IDLE		2
#define QUIC_TIMER_HANDSHAKE	3
#define QUIC_TIMER_PATH_PROBE	4
#define QUIC_TIMER_MAX		5

/*
 * QUIC Variable-Length Integer encoding (RFC 9000 Section 16)
 * The two most significant bits encode the length:
 * 00 = 1 byte  (6-bit value, 0-63)
 * 01 = 2 bytes (14-bit value, 0-16383)
 * 10 = 4 bytes (30-bit value, 0-1073741823)
 * 11 = 8 bytes (62-bit value, 0-4611686018427387903)
 */
#define QUIC_VARINT_1BYTE_PREFIX	0x00
#define QUIC_VARINT_2BYTE_PREFIX	0x40
#define QUIC_VARINT_4BYTE_PREFIX	0x80
#define QUIC_VARINT_8BYTE_PREFIX	0xc0
#define QUIC_VARINT_PREFIX_MASK		0xc0

/* QUIC Variable-Length Integer maximum values */
#define QUIC_VARINT_1BYTE_MAX		63ULL
#define QUIC_VARINT_2BYTE_MAX		16383ULL
#define QUIC_VARINT_4BYTE_MAX		1073741823ULL
#define QUIC_VARINT_8BYTE_MAX		4611686018427387903ULL

/* QUIC packet header constants */
#define QUIC_HEADER_FORM_BIT		0x80	/* Long header if set */
#define QUIC_FIXED_BIT			0x40	/* Must be 1 */

/* QUIC stream frame flags (RFC 9000 Section 19.8) */
#define QUIC_STREAM_FRAME_FIN_BIT	0x01
#define QUIC_STREAM_FRAME_LEN_BIT	0x02
#define QUIC_STREAM_FRAME_OFF_BIT	0x04

/* ACK range structure */
struct quic_ack_range {
	u64	gap;
	u64	ack_range;
};

/* Sent packet tracking */
struct quic_sent_packet {
	struct list_head	list;
	u64			pn;
	ktime_t			sent_time;
	u32			size;
	u32			ack_eliciting:1;
	u32			in_flight:1;
	u32			retransmitted:1;
	u32			has_crypto:1;
	u8			pn_space;
	struct sk_buff		*skb;
};

/* ACK info for received packets */
struct quic_ack_info {
	u64			largest_acked;
	u64			ack_delay;
	u64			ecn_ce;
	u64			ecn_ect0;
	u64			ecn_ect1;
	u32			ack_range_count;
	struct quic_ack_range	ranges[256];
};

/* Packet number space */
struct quic_pn_space {
	spinlock_t		lock;
	u64			next_pn;
	u64			largest_acked_pn;
	u64			largest_recv_pn;
	u64			loss_time;
	ktime_t			last_ack_time;
	u32			ack_eliciting_in_flight;
	struct list_head	sent_packets;
	struct list_head	lost_packets;
	struct quic_ack_info	recv_ack_info;
	u8			keys_available:1;
	u8			keys_discarded:1;
};

/* QUIC crypto secret */
struct quic_crypto_secret {
	u8	secret[64];
	u8	key[32];
	u8	iv[12];
	u8	hp_key[32];
	u32	secret_len;
	u32	key_len;
	u32	iv_len;
	u32	hp_key_len;
};

/* QUIC crypto context */
struct quic_crypto_ctx {
	struct crypto_aead	*tx_aead;
	struct crypto_aead	*rx_aead;
	struct crypto_cipher	*tx_hp;
	struct crypto_cipher	*rx_hp;
	struct crypto_shash	*hash;
	struct quic_crypto_secret tx;
	struct quic_crypto_secret rx;
	u16			cipher_type;
	u8			key_phase:1;
	u8			keys_available:1;
};

/* QUIC congestion control state */
struct quic_cc_state {
	u64		cwnd;
	u64		ssthresh;
	u64		bytes_in_flight;
	u64		congestion_window;
	u64		pacing_rate;
	u64		last_sent_time;
	ktime_t		congestion_recovery_start;
	u32		pto_count;
	u32		loss_burst_count;
	u8		in_slow_start:1;
	u8		in_recovery:1;
	u8		app_limited:1;
	enum quic_cc_algo algo;
	/* BBR specific */
	u64		bbr_bw;
	u64		bbr_min_rtt;
	u32		bbr_cycle_index;
	u8		bbr_mode;
	/* CUBIC specific */
	u64		cubic_k;
	u64		cubic_origin_point;
	ktime_t		cubic_epoch_start;
};

/* QUIC RTT measurement */
struct quic_rtt {
	u32		latest_rtt;
	u32		min_rtt;
	u32		smoothed_rtt;
	u32		rttvar;
	ktime_t		first_rtt_sample;
	u8		has_sample:1;
};

/* QUIC flow control - connection level */
struct quic_flow_control {
	u64		max_data;
	u64		data_sent;
	u64		data_received;
	u64		max_data_next;
	u64		max_streams_bidi;
	u64		max_streams_uni;
	u64		streams_opened_bidi;
	u64		streams_opened_uni;
	u64		blocked_at;
	u8		blocked:1;
};

/* QUIC path structure */
struct quic_path {
	struct list_head	list;
	struct sockaddr_storage	local_addr;
	struct sockaddr_storage	remote_addr;
	struct quic_cc_state	cc;
	struct quic_rtt		rtt;
	u32			mtu;
	u32			amplification_limit;
	u64			bytes_sent;
	u64			bytes_recv;
	u8			validated:1;
	u8			active:1;
	u8			challenge_pending:1;
	u8			challenge_data[8];
	ktime_t			validation_start;
};

/* QUIC stream receive buffer */
struct quic_stream_recv_buf {
	struct rb_root		data_tree;
	spinlock_t		lock;
	u64			offset;
	u64			highest_offset;
	u64			final_size;
	u32			pending;
	u8			fin_received:1;
	u8			reset_received:1;
};

/* QUIC stream send buffer */
struct quic_stream_send_buf {
	struct list_head	pending;
	spinlock_t		lock;
	u64			offset;
	u64			acked_offset;
	u64			max_stream_data;
	u32			pending_bytes;
	u8			fin_sent:1;
	u8			reset_sent:1;
};

/* QUIC stream */
struct quic_stream {
	struct rb_node		node;
	struct list_head	list;
	u64			id;
	enum quic_stream_state	state;
	struct quic_stream_recv_buf recv;
	struct quic_stream_send_buf send;
	u64			error_code;
	u64			max_stream_data_local;
	u64			max_stream_data_remote;
	wait_queue_head_t	wait;
	struct quic_connection	*conn;
	refcount_t		refcnt;
	u8			fin_sent:1;
	u8			fin_received:1;
	u8			reset_sent:1;
	u8			reset_received:1;
	u8			stop_sending_sent:1;
	u8			stop_sending_received:1;
};

/* QUIC received data chunk */
struct quic_recv_chunk {
	struct rb_node	node;
	u64		offset;
	u32		len;
	u8		data[];
};

/* QUIC connection ID entry */
struct quic_cid_entry {
	struct list_head	list;
	struct hlist_node	hash_node;
	struct quic_connection_id cid;
	u8			stateless_reset_token[16];
	u64			sequence_number;
	u64			retire_prior_to;
	u8			used:1;
};

/* QUIC connection */
struct quic_connection {
	struct quic_sock		*qsk;
	spinlock_t			lock;
	enum quic_state			state;
	u32				version;

	/* Connection IDs */
	struct quic_connection_id	scid;
	struct quic_connection_id	dcid;
	struct quic_connection_id	original_dcid;
	struct list_head		scid_list;
	struct list_head		dcid_list;
	u64				next_scid_seq;
	u64				next_dcid_seq;
	u64				retire_dcid_prior_to;

	/* Packet number spaces */
	struct quic_pn_space		pn_spaces[QUIC_PN_SPACE_MAX];

	/* Crypto contexts for each encryption level */
	struct quic_crypto_ctx		crypto[QUIC_CRYPTO_MAX];
	u8				crypto_level;

	/* Streams */
	struct rb_root			streams;
	spinlock_t			streams_lock;
	u64				next_stream_id_bidi;
	u64				next_stream_id_uni;
	u64				max_stream_id_bidi;
	u64				max_stream_id_uni;
	u64				streams_count_bidi;
	u64				streams_count_uni;

	/* Flow control */
	struct quic_flow_control	local_fc;
	struct quic_flow_control	remote_fc;

	/* Paths */
	struct list_head		paths;
	struct quic_path		*active_path;
	u32				num_paths;

	/* Transport parameters */
	struct quic_transport_params	local_params;
	struct quic_transport_params	remote_params;

	/* Timers */
	struct timer_list		timers[QUIC_TIMER_MAX];
	ktime_t				timer_deadlines[QUIC_TIMER_MAX];

	/* Work queues */
	struct work_struct		tx_work;
	struct work_struct		rx_work;
	struct work_struct		close_work;

	/* Loss detection */
	u32				pto_count;
	ktime_t				loss_detection_timer;
	ktime_t				time_of_last_ack_eliciting;
	u64				time_threshold;
	u64				packet_threshold;

	/* Pending frames */
	struct sk_buff_head		pending_frames;
	struct sk_buff_head		crypto_buffer[QUIC_CRYPTO_MAX];

	/* Close info */
	u64				error_code;
	u64				frame_type;
	char				*reason_phrase;
	u32				reason_len;
	u8				app_error:1;
	u8				close_received:1;
	u8				close_sent:1;

	/* Connection state flags */
	u8				handshake_complete:1;
	u8				handshake_confirmed:1;
	u8				key_phase:1;
	u8				is_server:1;
	u8				draining:1;
	u8				migration_disabled:1;

	/* Statistics */
	struct quic_stats		stats;

	/* Reference counting */
	refcount_t			refcnt;
};

/* QUIC socket */
struct quic_sock {
	struct inet_sock		inet;
	struct quic_connection		*conn;
	struct socket			*udp_sock;

	/* Configuration */
	struct quic_config		config;

	/* ALPN */
	char				*alpn;
	u32				alpn_len;

	/* Session ticket for 0-RTT */
	u8				*session_ticket;
	u32				session_ticket_len;

	/* Token from server */
	u8				*token;
	u32				token_len;

	/* Event queue */
	struct sk_buff_head		event_queue;
	wait_queue_head_t		event_wait;

	/* Socket options */
	u8				events_enabled:1;
	u8				datagram_enabled:1;
	u8				zero_rtt_enabled:1;

	/* Pending operations */
	struct list_head		pending_streams;
	spinlock_t			pending_lock;
};

static inline struct quic_sock *quic_sk(struct sock *sk)
{
	return (struct quic_sock *)sk;
}

static inline struct sock *quic_sock_sk(struct quic_sock *qsk)
{
	return (struct sock *)qsk;
}

/* Protocol operations */
extern struct proto quic_prot;
extern struct proto quicv6_prot;
extern const struct proto_ops quic_stream_ops;
extern const struct proto_ops quicv6_stream_ops;
extern const struct proto_ops quic_dgram_ops;
extern const struct proto_ops quicv6_dgram_ops;

/* Connection management */
struct quic_connection *quic_conn_create(struct quic_sock *qsk, bool is_server);
void quic_conn_destroy(struct quic_connection *conn);
int quic_conn_connect(struct quic_connection *conn,
		      struct sockaddr *addr, int addr_len);
int quic_conn_accept(struct quic_connection *conn);
int quic_conn_close(struct quic_connection *conn, u64 error_code,
		    const char *reason, u32 reason_len, bool app_error);
void quic_conn_set_state(struct quic_connection *conn, enum quic_state state);
struct quic_connection *quic_conn_lookup(struct quic_connection_id *cid);

/* Stream management */
struct quic_stream *quic_stream_create(struct quic_connection *conn, u64 id);
void quic_stream_destroy(struct quic_stream *stream);
struct quic_stream *quic_stream_lookup(struct quic_connection *conn, u64 id);
int quic_stream_send(struct quic_stream *stream, struct msghdr *msg, size_t len);
int quic_stream_recv(struct quic_stream *stream, struct msghdr *msg, size_t len);
int quic_stream_reset(struct quic_stream *stream, u64 error_code);
int quic_stream_stop_sending(struct quic_stream *stream, u64 error_code);
u64 quic_stream_next_id(struct quic_connection *conn, bool unidirectional);
bool quic_stream_is_local(struct quic_connection *conn, u64 stream_id);
bool quic_stream_is_bidi(u64 stream_id);

/* Packet processing */
int quic_packet_parse(struct sk_buff *skb, struct quic_packet *pkt);
struct sk_buff *quic_packet_build(struct quic_connection *conn,
				  struct quic_pn_space *pn_space);
int quic_packet_encrypt(struct quic_connection *conn, struct sk_buff *skb,
			u8 level);
int quic_packet_decrypt(struct quic_connection *conn, struct sk_buff *skb,
			u8 level);
void quic_packet_process(struct quic_connection *conn, struct sk_buff *skb);

/* Frame handling */
int quic_frame_parse(struct quic_connection *conn, struct sk_buff *skb,
		     struct quic_frame *frame);
struct sk_buff *quic_frame_build(struct quic_connection *conn, u8 type,
				 void *data);
int quic_frame_process(struct quic_connection *conn, struct quic_frame *frame);

/* Crypto operations */
int quic_crypto_init(struct quic_crypto_ctx *ctx, u16 cipher_type);
void quic_crypto_destroy(struct quic_crypto_ctx *ctx);
int quic_crypto_derive_initial_secrets(struct quic_connection *conn,
				       struct quic_connection_id *cid);
int quic_crypto_derive_secrets(struct quic_crypto_ctx *ctx,
			       const u8 *secret, u32 secret_len);
int quic_crypto_encrypt(struct quic_crypto_ctx *ctx, struct sk_buff *skb,
			u64 pn);
int quic_crypto_decrypt(struct quic_crypto_ctx *ctx, struct sk_buff *skb,
			u64 pn);
int quic_crypto_hp_mask(struct quic_crypto_ctx *ctx, const u8 *sample,
			u8 *mask);
int quic_crypto_update_keys(struct quic_connection *conn);

/* Congestion control */
void quic_cc_init(struct quic_cc_state *cc, enum quic_cc_algo algo);
void quic_cc_on_packet_sent(struct quic_cc_state *cc, u32 bytes);
void quic_cc_on_ack(struct quic_cc_state *cc, u64 acked_bytes,
		    struct quic_rtt *rtt);
void quic_cc_on_loss(struct quic_cc_state *cc, u64 lost_bytes);
void quic_cc_on_congestion_event(struct quic_cc_state *cc);
u64 quic_cc_pacing_delay(struct quic_cc_state *cc, u32 bytes);
bool quic_cc_can_send(struct quic_cc_state *cc, u32 bytes);

/* Flow control */
bool quic_flow_control_can_send(struct quic_connection *conn, u64 bytes);
void quic_flow_control_on_data_sent(struct quic_connection *conn, u64 bytes);
void quic_flow_control_on_data_recvd(struct quic_connection *conn, u64 bytes);
void quic_flow_control_update_max_data(struct quic_connection *conn);
bool quic_stream_flow_control_can_send(struct quic_stream *stream, u64 bytes);
void quic_stream_flow_control_on_data_sent(struct quic_stream *stream,
					   u64 bytes);

/* Loss detection */
void quic_loss_detection_init(struct quic_connection *conn);
void quic_loss_detection_on_packet_sent(struct quic_connection *conn,
					struct quic_sent_packet *pkt);
void quic_loss_detection_on_ack_received(struct quic_connection *conn,
					 struct quic_ack_info *ack, u8 pn_space);
void quic_loss_detection_set_timer(struct quic_connection *conn);
void quic_loss_detection_on_timeout(struct quic_connection *conn);
void quic_loss_detection_detect_lost(struct quic_connection *conn, u8 pn_space);

/* Path management */
int __init quic_path_init(void);
void quic_path_exit(void);
struct quic_path *quic_path_create(struct quic_connection *conn,
				   struct sockaddr *local,
				   struct sockaddr *remote);
void quic_path_destroy(struct quic_path *path);
int quic_path_validate(struct quic_path *path);
void quic_path_on_validated(struct quic_path *path);
int quic_path_challenge(struct quic_path *path);
int quic_path_migrate(struct quic_connection *conn, struct quic_path *path);
bool quic_path_verify_response(struct quic_path *path, const u8 *data);
void quic_path_mtu_discovery_start(struct quic_path *path);
int quic_path_mtu_probe(struct quic_path *path);
void quic_path_mtu_probe_acked(struct quic_path *path, u32 probe_size);
void quic_path_mtu_probe_lost(struct quic_path *path, u32 probe_size);
void quic_path_rtt_update(struct quic_path *path, u32 latest_rtt_us,
			  u32 ack_delay_us);
u32 quic_path_pto(struct quic_path *path);
void quic_path_on_data_sent(struct quic_path *path, u32 bytes);
void quic_path_on_data_received(struct quic_path *path, u32 bytes);
bool quic_path_can_send(struct quic_path *path, u32 bytes);
struct quic_path *quic_path_find(struct quic_connection *conn,
				 struct sockaddr *remote);
int quic_path_get_info(struct quic_path *path, struct quic_path_info *info);
void quic_path_on_probe_timeout(struct quic_path *path);
bool quic_path_needs_probe(struct quic_path *path);

/* ACK handling */
int quic_ack_create(struct quic_connection *conn, u8 pn_space,
		    struct sk_buff *skb);
void quic_ack_on_packet_received(struct quic_connection *conn, u64 pn,
				 u8 pn_space);
bool quic_ack_should_send(struct quic_connection *conn, u8 pn_space);

/* RTT measurement */
void quic_rtt_update(struct quic_rtt *rtt, u32 latest_rtt, u32 ack_delay);
u32 quic_rtt_pto(struct quic_rtt *rtt);

/* Timer operations */
void quic_timer_init(struct quic_connection *conn);
void quic_timer_set(struct quic_connection *conn, u8 timer_type, ktime_t when);
void quic_timer_cancel(struct quic_connection *conn, u8 timer_type);
void quic_timer_cancel_all(struct quic_connection *conn);
void quic_timer_update(struct quic_connection *conn);
void quic_timer_reset_idle(struct quic_connection *conn);
u64 quic_timer_next_timeout_us(struct quic_connection *conn);
bool quic_timer_pending(struct quic_connection *conn, u8 timer_type);
void quic_timer_on_packet_sent(struct quic_connection *conn, bool ack_eliciting);
void quic_timer_on_ack_received(struct quic_connection *conn);
void quic_timer_on_pto_timeout(struct quic_connection *conn);
void quic_timer_start_handshake(struct quic_connection *conn, u64 timeout_ms);
void quic_timer_stop_handshake(struct quic_connection *conn);
void quic_timer_start_path_validation(struct quic_connection *conn, u64 timeout_ms);
void quic_timer_get_state(struct quic_connection *conn, u8 timer_type,
			  ktime_t *deadline, bool *armed);

/* Socket operations */
int quic_socket_create(struct net *net, struct socket *sock, int protocol,
		       int kern);
int quic_socket_bind(struct socket *sock, struct sockaddr *addr, int addr_len);
int quic_socket_connect(struct socket *sock, struct sockaddr *addr,
			int addr_len, int flags);
int quic_socket_listen(struct socket *sock, int backlog);
int quic_socket_accept(struct socket *sock, struct socket *newsock, int flags,
		       bool kern);
int quic_socket_sendmsg(struct socket *sock, struct msghdr *msg, size_t len);
int quic_socket_recvmsg(struct socket *sock, struct msghdr *msg, size_t len,
			int flags);
int quic_socket_close(struct socket *sock, long timeout);
int quic_socket_shutdown(struct socket *sock, int how);
int quic_socket_setsockopt(struct socket *sock, int level, int optname,
			   sockptr_t optval, unsigned int optlen);
int quic_socket_getsockopt(struct socket *sock, int level, int optname,
			   char __user *optval, int __user *optlen);
__poll_t quic_socket_poll(struct file *file, struct socket *sock,
			  poll_table *wait);

/* UDP encapsulation */
int quic_udp_encap_init(struct quic_sock *qsk);
void quic_udp_encap_destroy(struct quic_sock *qsk);
int quic_udp_send(struct quic_sock *qsk, struct sk_buff *skb,
		  struct sockaddr *dest);
int quic_udp_recv(struct sock *sk, struct sk_buff *skb);

/* CID hash table operations */
int quic_cid_hash_init(void);
void quic_cid_hash_cleanup(void);
int quic_cid_hash_add(struct quic_cid_entry *entry);
void quic_cid_hash_del(struct quic_cid_entry *entry);
struct quic_cid_entry *quic_cid_hash_lookup(struct quic_connection_id *cid);

/* Initialization */
int __init quic_init(void);
void __exit quic_exit(void);
int __init quic_proto_init(void);
void __exit quic_proto_exit(void);
int __init quic_offload_init(void);
void __exit quic_offload_exit(void);

/* Hardware offload interface */
struct quic_offload_ops {
	int (*encrypt)(struct sk_buff *skb, struct quic_crypto_ctx *ctx);
	int (*decrypt)(struct sk_buff *skb, struct quic_crypto_ctx *ctx);
	int (*gso_segment)(struct sk_buff *skb, netdev_features_t features);
	struct sk_buff *(*gro_receive)(struct list_head *head,
				       struct sk_buff *skb);
	int (*gro_complete)(struct sk_buff *skb, int nhoff);
};

extern const struct quic_offload_ops *quic_offload;

/* Debug and tracing */
#ifdef CONFIG_QUIC_DEBUG
#define quic_dbg(fmt, ...) \
	pr_debug("QUIC: " fmt, ##__VA_ARGS__)
#else
#define quic_dbg(fmt, ...) do { } while (0)
#endif

/* Sysctl interface */
extern int sysctl_quic_mem[3];
extern int sysctl_quic_wmem[3];
extern int sysctl_quic_rmem[3];

#endif /* _NET_QUIC_H */
