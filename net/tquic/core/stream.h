/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: Stream Layer Internal Definitions
 *
 * Copyright (c) 2026 Linux Foundation
 */

#ifndef _TQUIC_CORE_STREAM_H
#define _TQUIC_CORE_STREAM_H

#include <linux/types.h>
#include <linux/rbtree.h>
#include <linux/list.h>
#include <linux/skbuff.h>
#include <net/tquic.h>

/* Stream ID bit layout */
#define STREAM_ID_INITIATOR_BIT		0x01
#define STREAM_ID_DIRECTION_BIT		0x02
#define STREAM_ID_MASK			0x03

/* Stream types */
#define STREAM_TYPE_CLIENT_BIDI		0x00
#define STREAM_TYPE_SERVER_BIDI		0x01
#define STREAM_TYPE_CLIENT_UNI		0x02
#define STREAM_TYPE_SERVER_UNI		0x03

/* Stream memory limits */
#define TQUIC_STREAM_SNDBUF_DEFAULT	(256 * 1024)
#define TQUIC_STREAM_RCVBUF_DEFAULT	(256 * 1024)
#define TQUIC_STREAM_SNDBUF_MAX		(16 * 1024 * 1024)
#define TQUIC_STREAM_RCVBUF_MAX		(16 * 1024 * 1024)

/* Priority levels */
#define TQUIC_STREAM_PRIO_URGENT	0
#define TQUIC_STREAM_PRIO_HIGH		64
#define TQUIC_STREAM_PRIO_NORMAL	128
#define TQUIC_STREAM_PRIO_LOW		192
#define TQUIC_STREAM_PRIO_BULK		255

/* Maximum reassembly gaps */
#define TQUIC_MAX_GAPS			64

/* Forward declarations */
struct tquic_stream_manager;
struct tquic_stream_ext;
struct tquic_stream_gap;
struct tquic_recv_chunk;
struct tquic_stream_iter;

/**
 * struct tquic_stream_gap - Gap in received data
 */
struct tquic_stream_gap {
	u64 offset;
	u64 length;
	struct list_head list;
};

/**
 * struct tquic_recv_chunk - Received data chunk for reassembly
 */
struct tquic_recv_chunk {
	u64 offset;
	u32 length;
	void *data;
	struct sk_buff *skb;
	struct rb_node node;
	bool fin;
};

/**
 * struct tquic_stream_ext - Extended stream state
 */
struct tquic_stream_ext {
	/* Priority and dependency */
	u8 priority;
	u64 dependency;
	u16 weight;
	bool exclusive;

	/* Flow control */
	bool send_blocked;
	bool recv_blocked;
	u32 sndbuf_limit;
	u32 rcvbuf_limit;
	u32 sndbuf_used;
	u32 rcvbuf_used;

	/* Reassembly */
	struct list_head gaps;
	u32 num_gaps;
	struct rb_root recv_chunks;
	u64 recv_next;
	u64 recv_max;
	s64 final_size;

	/* Error state */
	u64 error_code;
	bool rst_received;
	bool rst_sent;
	bool stop_sending_received;
	bool stop_sending_sent;

	/* Queues */
	struct sk_buff_head pending_frames;
	struct sk_buff_head retransmit_queue;

	/* Dependency tree */
	struct list_head dep_children;
	struct list_head dep_node;

	/* Zero-copy */
	atomic_t zerocopy_refs;
	struct pipe_inode_info *splice_pipe;

	/* Statistics */
	struct {
		u64 bytes_sent;
		u64 bytes_received;
		u64 frames_sent;
		u64 frames_received;
		u64 retransmissions;
		ktime_t created;
		ktime_t first_byte_sent;
		ktime_t first_byte_received;
		ktime_t last_activity;
	} stats;

	/* Deadline-aware scheduling (draft-tjohn-quic-multipath-dmtp-01) */
	struct {
		bool enabled;		/* Deadline scheduling enabled for stream */
		ktime_t deadline;	/* Current stream deadline (absolute) */
		u64 relative_deadline_us;  /* Relative deadline from app */
		u8 priority;		/* Deadline priority level (0=critical) */
		u8 miss_policy;		/* Policy when deadline missed */
		u64 deadline_offset;	/* Data offset deadline applies to */
		u64 deadline_length;	/* Data length deadline covers */
		u32 slack_us;		/* Allowed slack time */
		u64 deadlines_met;	/* Statistics: deadlines met */
		u64 deadlines_missed;	/* Statistics: deadlines missed */
		u64 avg_delivery_us;	/* Average delivery time */
	} deadline;
};

/**
 * struct tquic_stream_manager - Stream management for a connection
 */
struct tquic_stream_manager {
	struct rb_root streams;
	u32 stream_count;

	/* Stream counters */
	u32 bidi_local;
	u32 bidi_remote;
	u32 uni_local;
	u32 uni_remote;

	/* Limits */
	u64 max_bidi_local;
	u64 max_bidi_remote;
	u64 max_uni_local;
	u64 max_uni_remote;

	/* Next IDs */
	u64 next_bidi_local;
	u64 next_uni_local;
	u64 next_bidi_remote;
	u64 next_uni_remote;

	struct tquic_connection *conn;
	spinlock_t lock;

	/* Scheduling */
	struct list_head send_list;
	struct list_head blocked_list;

	/* Memory pools */
	struct kmem_cache *stream_cache;
	struct kmem_cache *ext_cache;
	struct kmem_cache *gap_cache;
	struct kmem_cache *chunk_cache;

	/* Role */
	bool is_server;

	/* Connection flow control */
	bool data_blocked;
	u64 max_data_local;
	u64 max_data_remote;
	u64 data_sent;
	u64 data_received;
};

/**
 * struct tquic_stream_iter - Stream iteration state
 */
struct tquic_stream_iter {
	struct tquic_stream_manager *mgr;
	struct rb_node *node;
	u8 min_priority;
};

/* Stream ID helpers */
static inline bool tquic_stream_id_is_client(u64 stream_id)
{
	return (stream_id & STREAM_ID_INITIATOR_BIT) == 0;
}

static inline bool tquic_stream_id_is_server(u64 stream_id)
{
	return (stream_id & STREAM_ID_INITIATOR_BIT) != 0;
}

static inline bool tquic_stream_id_is_bidi(u64 stream_id)
{
	return (stream_id & STREAM_ID_DIRECTION_BIT) == 0;
}

static inline bool tquic_stream_id_is_uni(u64 stream_id)
{
	return (stream_id & STREAM_ID_DIRECTION_BIT) != 0;
}

static inline int tquic_stream_id_type(u64 stream_id)
{
	return stream_id & STREAM_ID_MASK;
}

/* Stream manager API */
struct tquic_stream_manager *tquic_stream_manager_create(
	struct tquic_connection *conn, bool is_server);
void tquic_stream_manager_destroy(struct tquic_stream_manager *mgr);

/* Stream lookup */
struct tquic_stream *tquic_stream_lookup(struct tquic_stream_manager *mgr,
					 u64 stream_id);

/* Stream creation */
struct tquic_stream *tquic_stream_create(struct tquic_stream_manager *mgr,
					 bool bidi);
struct tquic_stream *tquic_stream_get_or_create(
	struct tquic_stream_manager *mgr, u64 stream_id);
void tquic_stream_destroy(struct tquic_stream_manager *mgr,
			  struct tquic_stream *stream);

/* Data transfer */
ssize_t tquic_stream_write(struct tquic_stream_manager *mgr,
			   struct tquic_stream *stream,
			   struct iov_iter *from, size_t len, bool fin);
ssize_t tquic_stream_write_zerocopy(struct tquic_stream_manager *mgr,
				    struct tquic_stream *stream,
				    struct page **pages, int nr_pages,
				    size_t offset, size_t len, bool fin);
ssize_t tquic_stream_read(struct tquic_stream_manager *mgr,
			  struct tquic_stream *stream,
			  struct iov_iter *to, size_t len);
int tquic_stream_recv_data(struct tquic_stream_manager *mgr,
			   struct tquic_stream *stream,
			   u64 offset, struct sk_buff *skb, bool fin);

/* Shutdown and reset */
int tquic_stream_shutdown_write(struct tquic_stream_manager *mgr,
				struct tquic_stream *stream);
int tquic_stream_shutdown_read(struct tquic_stream_manager *mgr,
			       struct tquic_stream *stream,
			       u64 error_code);
int tquic_stream_reset_send(struct tquic_stream_manager *mgr,
			    struct tquic_stream *stream,
			    u64 error_code);
int tquic_stream_reset_recv(struct tquic_stream_manager *mgr,
			    struct tquic_stream *stream,
			    u64 error_code, u64 final_size);

/* Priority and dependency */
int tquic_stream_set_priority(struct tquic_stream *stream, u8 priority);
int tquic_stream_set_dependency(struct tquic_stream_manager *mgr,
				struct tquic_stream *stream,
				u64 dependency, u16 weight, bool exclusive);

/* Flow control */
int tquic_stream_update_max_data(struct tquic_stream *stream, u64 max_data);
int tquic_stream_conn_update_max_data(struct tquic_stream_manager *mgr,
				      u64 max_data);
bool tquic_stream_should_send_blocked(struct tquic_stream *stream);
u64 tquic_stream_advertise_max_data(struct tquic_stream *stream);

/* Iteration */
void tquic_stream_iter_init(struct tquic_stream_iter *iter,
			    struct tquic_stream_manager *mgr,
			    u8 min_priority);
struct tquic_stream *tquic_stream_iter_next(struct tquic_stream_iter *iter);
int tquic_stream_for_each(struct tquic_stream_manager *mgr,
			  int (*cb)(struct tquic_stream *stream, void *ctx),
			  void *ctx);
int tquic_stream_get_sendable(struct tquic_stream_manager *mgr,
			      struct tquic_stream **streams,
			      int max_streams);

/* Splice/sendfile */
ssize_t tquic_stream_splice_read(struct tquic_stream_manager *mgr,
				 struct tquic_stream *stream,
				 struct pipe_inode_info *pipe,
				 size_t len, unsigned int flags);
ssize_t tquic_stream_sendfile(struct tquic_stream_manager *mgr,
			      struct tquic_stream *stream,
			      struct file *file, loff_t *offset,
			      size_t count);

/* Blocking operations */
int tquic_stream_wait_for_space(struct tquic_stream *stream, long *timeo);
int tquic_stream_wait_for_data(struct tquic_stream *stream, long *timeo);

/* Memory management */
void tquic_stream_memory_pressure(struct tquic_stream_manager *mgr);
void tquic_stream_get_buffer_usage(struct tquic_stream_manager *mgr,
				   u64 *send_bytes, u64 *recv_bytes);

/* Debugging */
void tquic_stream_dump(struct tquic_stream *stream);
void tquic_stream_manager_dump(struct tquic_stream_manager *mgr);

#endif /* _TQUIC_CORE_STREAM_H */
