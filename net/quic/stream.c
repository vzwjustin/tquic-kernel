// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * QUIC - Quick UDP Internet Connections
 *
 * Stream multiplexing implementation
 *
 * Copyright (c) 2024 Linux QUIC Authors
 */

#include <linux/slab.h>
#include <linux/uio.h>
#include <net/quic.h>

static struct kmem_cache *quic_stream_cache __read_mostly;
static struct kmem_cache *quic_recv_chunk_cache __read_mostly;

static struct quic_stream *quic_stream_alloc(void)
{
	struct quic_stream *stream;

	stream = kmem_cache_zalloc(quic_stream_cache, GFP_KERNEL);
	if (!stream)
		return NULL;

	RB_CLEAR_NODE(&stream->node);
	INIT_LIST_HEAD(&stream->list);
	init_waitqueue_head(&stream->wait);
	refcount_set(&stream->refcnt, 1);

	return stream;
}

static void quic_stream_recv_buf_init(struct quic_stream_recv_buf *recv)
{
	recv->data_tree = RB_ROOT;
	spin_lock_init(&recv->lock);
	recv->offset = 0;
	recv->highest_offset = 0;
	recv->final_size = QUIC_MAX_DATA;
	recv->pending = 0;
	recv->fin_received = 0;
	recv->reset_received = 0;
}

static void quic_stream_send_buf_init(struct quic_stream_send_buf *send)
{
	INIT_LIST_HEAD(&send->pending);
	spin_lock_init(&send->lock);
	send->offset = 0;
	send->acked_offset = 0;
	send->max_stream_data = 0;
	send->pending_bytes = 0;
	send->fin_sent = 0;
	send->reset_sent = 0;
}

static void quic_stream_recv_buf_destroy(struct quic_stream_recv_buf *recv)
{
	struct rb_node *node;
	struct quic_recv_chunk *chunk;

	spin_lock(&recv->lock);
	node = rb_first(&recv->data_tree);
	while (node) {
		chunk = rb_entry(node, struct quic_recv_chunk, node);
		node = rb_next(node);
		rb_erase(&chunk->node, &recv->data_tree);
		kmem_cache_free(quic_recv_chunk_cache, chunk);
	}
	spin_unlock(&recv->lock);
}

static void quic_stream_send_buf_destroy(struct quic_stream_send_buf *send)
{
	struct sk_buff *skb, *tmp;

	spin_lock(&send->lock);
	list_for_each_entry_safe(skb, tmp, &send->pending, list) {
		list_del(&skb->list);
		kfree_skb(skb);
	}
	spin_unlock(&send->lock);
}

struct quic_stream *quic_stream_create(struct quic_connection *conn, u64 id)
{
	struct quic_stream *stream;
	struct rb_node **link, *parent = NULL;
	struct quic_stream *entry;
	bool is_local;

	stream = quic_stream_alloc();
	if (!stream)
		return NULL;

	stream->id = id;
	stream->conn = conn;
	stream->state = QUIC_STREAM_STATE_IDLE;

	quic_stream_recv_buf_init(&stream->recv);
	quic_stream_send_buf_init(&stream->send);

	/* Set initial flow control limits */
	is_local = quic_stream_is_local(conn, id);
	if (quic_stream_is_bidi(id)) {
		if (is_local) {
			stream->send.max_stream_data =
				conn->remote_params.initial_max_stream_data_bidi_remote;
			stream->max_stream_data_local =
				conn->local_params.initial_max_stream_data_bidi_local;
		} else {
			stream->send.max_stream_data =
				conn->remote_params.initial_max_stream_data_bidi_local;
			stream->max_stream_data_local =
				conn->local_params.initial_max_stream_data_bidi_remote;
		}
	} else {
		if (is_local) {
			stream->send.max_stream_data =
				conn->remote_params.initial_max_stream_data_uni;
			stream->max_stream_data_local = 0;  /* Can't receive on local uni */
		} else {
			stream->send.max_stream_data = 0;  /* Can't send on remote uni */
			stream->max_stream_data_local =
				conn->local_params.initial_max_stream_data_uni;
		}
	}
	stream->max_stream_data_remote = stream->send.max_stream_data;

	/* Insert into streams tree */
	spin_lock(&conn->streams_lock);
	link = &conn->streams.rb_node;
	while (*link) {
		parent = *link;
		entry = rb_entry(parent, struct quic_stream, node);

		if (id < entry->id)
			link = &parent->rb_left;
		else if (id > entry->id)
			link = &parent->rb_right;
		else {
			/* Stream already exists */
			spin_unlock(&conn->streams_lock);
			quic_stream_destroy(stream);
			return NULL;
		}
	}
	rb_link_node(&stream->node, parent, link);
	rb_insert_color(&stream->node, &conn->streams);

	/* Update stream counts */
	if (quic_stream_is_bidi(id))
		conn->streams_count_bidi++;
	else
		conn->streams_count_uni++;

	spin_unlock(&conn->streams_lock);

	stream->state = QUIC_STREAM_STATE_OPEN;
	conn->stats.streams_opened++;

	return stream;
}

void quic_stream_destroy(struct quic_stream *stream)
{
	if (!stream)
		return;

	if (!refcount_dec_and_test(&stream->refcnt))
		return;

	quic_stream_recv_buf_destroy(&stream->recv);
	quic_stream_send_buf_destroy(&stream->send);

	if (stream->conn) {
		spin_lock(&stream->conn->streams_lock);
		if (!RB_EMPTY_NODE(&stream->node))
			rb_erase(&stream->node, &stream->conn->streams);
		spin_unlock(&stream->conn->streams_lock);
		stream->conn->stats.streams_closed++;
	}

	kmem_cache_free(quic_stream_cache, stream);
}

struct quic_stream *quic_stream_lookup(struct quic_connection *conn, u64 id)
{
	struct rb_node *node;
	struct quic_stream *stream;

	spin_lock(&conn->streams_lock);
	node = conn->streams.rb_node;
	while (node) {
		stream = rb_entry(node, struct quic_stream, node);

		if (id < stream->id)
			node = node->rb_left;
		else if (id > stream->id)
			node = node->rb_right;
		else {
			refcount_inc(&stream->refcnt);
			spin_unlock(&conn->streams_lock);
			return stream;
		}
	}
	spin_unlock(&conn->streams_lock);

	return NULL;
}

u64 quic_stream_next_id(struct quic_connection *conn, bool unidirectional)
{
	u64 id;

	spin_lock(&conn->streams_lock);
	if (unidirectional) {
		id = conn->next_stream_id_uni;
		conn->next_stream_id_uni += 4;
	} else {
		id = conn->next_stream_id_bidi;
		conn->next_stream_id_bidi += 4;
	}
	spin_unlock(&conn->streams_lock);

	return id;
}

bool quic_stream_is_local(struct quic_connection *conn, u64 stream_id)
{
	bool initiator_is_client = (stream_id & 0x01) == 0;
	return conn->is_server != initiator_is_client;
}

bool quic_stream_is_bidi(u64 stream_id)
{
	return (stream_id & 0x02) == 0;
}

static int quic_stream_send_data(struct quic_stream *stream,
				 const u8 *data, size_t len, bool fin)
{
	struct quic_connection *conn = stream->conn;
	struct quic_stream_send_buf *send = &stream->send;
	size_t max_chunk = QUIC_MAX_PACKET_SIZE - 100;  /* Leave room for headers */
	size_t offset = 0;

	while (offset < len) {
		size_t chunk_len = min(len - offset, max_chunk);
		struct sk_buff *skb;
		u8 frame_type;
		u8 *p;

		/* Check flow control */
		if (!quic_stream_flow_control_can_send(stream, chunk_len)) {
			/* Block until we have credits */
			if (offset == 0)
				return -EAGAIN;
			break;
		}

		skb = alloc_skb(chunk_len + 32, GFP_KERNEL);
		if (!skb)
			return -ENOMEM;

		/* Build STREAM frame */
		frame_type = QUIC_FRAME_STREAM | 0x02;  /* OFF bit */
		if (chunk_len < len - offset || !fin)
			frame_type |= 0x02;  /* LEN bit */
		if (offset + chunk_len >= len && fin)
			frame_type |= 0x01;  /* FIN bit */

		p = skb_put(skb, 1);
		*p = frame_type;

		/* Stream ID (variable length encoding) */
		p = skb_put(skb, quic_varint_len(stream->id));
		quic_varint_encode(stream->id, p);

		/* Offset (variable length encoding) */
		p = skb_put(skb, quic_varint_len(send->offset + offset));
		quic_varint_encode(send->offset + offset, p);

		/* Length if LEN bit set */
		if (frame_type & 0x02) {
			p = skb_put(skb, quic_varint_len(chunk_len));
			quic_varint_encode(chunk_len, p);
		}

		/* Data */
		p = skb_put(skb, chunk_len);
		memcpy(p, data + offset, chunk_len);

		/* Queue the frame */
		spin_lock(&send->lock);
		list_add_tail(&skb->list, &send->pending);
		send->pending_bytes += chunk_len;
		spin_unlock(&send->lock);

		quic_stream_flow_control_on_data_sent(stream, chunk_len);
		quic_flow_control_on_data_sent(conn, chunk_len);

		offset += chunk_len;
	}

	send->offset += offset;

	if (fin && offset >= len)
		stream->fin_sent = 1;

	/* Trigger TX */
	schedule_work(&conn->tx_work);

	return offset;
}

int quic_stream_send(struct quic_stream *stream, struct msghdr *msg, size_t len)
{
	u8 *buf;
	size_t copied;
	int err;

	if (stream->state == QUIC_STREAM_STATE_CLOSED ||
	    stream->state == QUIC_STREAM_STATE_RESET_SENT)
		return -EPIPE;

	if (!quic_stream_is_local(stream->conn, stream->id) &&
	    !quic_stream_is_bidi(stream->id))
		return -EINVAL;  /* Can't send on remote-initiated uni stream */

	buf = kmalloc(len, GFP_KERNEL);
	if (!buf)
		return -ENOMEM;

	copied = copy_from_iter(buf, len, &msg->msg_iter);
	if (copied != len) {
		kfree(buf);
		return -EFAULT;
	}

	err = quic_stream_send_data(stream, buf, len, false);

	kfree(buf);
	return err;
}

static int quic_stream_recv_data_insert(struct quic_stream_recv_buf *recv,
					u64 offset, const u8 *data, u32 len)
{
	struct quic_recv_chunk *chunk, *existing;
	struct rb_node **link, *parent = NULL;

	/* Allocate chunk */
	chunk = kmem_cache_alloc(quic_recv_chunk_cache, GFP_ATOMIC);
	if (!chunk)
		return -ENOMEM;

	/* Note: For real implementation, need variable-size allocation */
	chunk->offset = offset;
	chunk->len = min_t(u32, len, 1024);
	memcpy(chunk->data, data, chunk->len);

	spin_lock(&recv->lock);

	/* Find insertion point */
	link = &recv->data_tree.rb_node;
	while (*link) {
		parent = *link;
		existing = rb_entry(parent, struct quic_recv_chunk, node);

		if (offset < existing->offset) {
			link = &parent->rb_left;
		} else if (offset > existing->offset) {
			link = &parent->rb_right;
		} else {
			/* Duplicate data at same offset - skip */
			spin_unlock(&recv->lock);
			kmem_cache_free(quic_recv_chunk_cache, chunk);
			return 0;
		}
	}

	rb_link_node(&chunk->node, parent, link);
	rb_insert_color(&chunk->node, &recv->data_tree);

	if (offset + len > recv->highest_offset)
		recv->highest_offset = offset + len;

	recv->pending += chunk->len;

	spin_unlock(&recv->lock);

	return 0;
}

int quic_stream_recv_data(struct quic_stream *stream, u64 offset,
			  const u8 *data, u32 len, bool fin)
{
	struct quic_stream_recv_buf *recv = &stream->recv;
	int err;

	if (stream->state == QUIC_STREAM_STATE_RESET_RECVD)
		return -ECONNRESET;

	/* Check for final size violation */
	if (recv->fin_received) {
		if (offset + len > recv->final_size)
			return -EPROTO;
	}

	if (fin) {
		recv->final_size = offset + len;
		recv->fin_received = 1;
		stream->fin_received = 1;
	}

	err = quic_stream_recv_data_insert(recv, offset, data, len);
	if (err)
		return err;

	quic_flow_control_on_data_recvd(stream->conn, len);

	/* Wake up any waiting readers */
	wake_up(&stream->wait);

	return 0;
}

int quic_stream_recv(struct quic_stream *stream, struct msghdr *msg, size_t len)
{
	struct quic_stream_recv_buf *recv = &stream->recv;
	struct quic_recv_chunk *chunk;
	struct rb_node *node;
	size_t copied = 0;
	size_t to_copy;

	if (stream->state == QUIC_STREAM_STATE_RESET_RECVD)
		return -ECONNRESET;

	spin_lock(&recv->lock);

	/* Read contiguous data starting from current offset */
	node = rb_first(&recv->data_tree);
	while (node && copied < len) {
		chunk = rb_entry(node, struct quic_recv_chunk, node);

		/* Check if this chunk is contiguous with what we've read */
		if (chunk->offset > recv->offset)
			break;

		/* Calculate how much to copy from this chunk */
		if (chunk->offset + chunk->len <= recv->offset) {
			/* Already read this chunk, remove it */
			node = rb_next(node);
			rb_erase(&chunk->node, &recv->data_tree);
			kmem_cache_free(quic_recv_chunk_cache, chunk);
			continue;
		}

		u64 skip = recv->offset - chunk->offset;
		to_copy = min_t(size_t, chunk->len - skip, len - copied);

		spin_unlock(&recv->lock);

		if (copy_to_iter(chunk->data + skip, to_copy, &msg->msg_iter) != to_copy) {
			spin_lock(&recv->lock);
			break;
		}

		spin_lock(&recv->lock);

		copied += to_copy;
		recv->offset += to_copy;
		recv->pending -= to_copy;

		/* Remove chunk if fully consumed */
		if (skip + to_copy >= chunk->len) {
			node = rb_next(node);
			rb_erase(&chunk->node, &recv->data_tree);
			kmem_cache_free(quic_recv_chunk_cache, chunk);
		} else {
			node = rb_next(node);
		}
	}

	spin_unlock(&recv->lock);

	return copied > 0 ? copied : -EAGAIN;
}

int quic_stream_reset(struct quic_stream *stream, u64 error_code)
{
	struct quic_connection *conn = stream->conn;
	struct sk_buff *skb;
	u8 *p;

	if (stream->reset_sent)
		return 0;

	stream->error_code = error_code;
	stream->reset_sent = 1;
	stream->state = QUIC_STREAM_STATE_RESET_SENT;

	/* Build RESET_STREAM frame */
	skb = alloc_skb(32, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	p = skb_put(skb, 1);
	*p = QUIC_FRAME_RESET_STREAM;

	p = skb_put(skb, quic_varint_len(stream->id));
	quic_varint_encode(stream->id, p);

	p = skb_put(skb, quic_varint_len(error_code));
	quic_varint_encode(error_code, p);

	p = skb_put(skb, quic_varint_len(stream->send.offset));
	quic_varint_encode(stream->send.offset, p);

	skb_queue_tail(&conn->pending_frames, skb);
	schedule_work(&conn->tx_work);

	wake_up(&stream->wait);

	return 0;
}

int quic_stream_stop_sending(struct quic_stream *stream, u64 error_code)
{
	struct quic_connection *conn = stream->conn;
	struct sk_buff *skb;
	u8 *p;

	if (stream->stop_sending_sent)
		return 0;

	stream->stop_sending_sent = 1;

	/* Build STOP_SENDING frame */
	skb = alloc_skb(24, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	p = skb_put(skb, 1);
	*p = QUIC_FRAME_STOP_SENDING;

	p = skb_put(skb, quic_varint_len(stream->id));
	quic_varint_encode(stream->id, p);

	p = skb_put(skb, quic_varint_len(error_code));
	quic_varint_encode(error_code, p);

	skb_queue_tail(&conn->pending_frames, skb);
	schedule_work(&conn->tx_work);

	return 0;
}

/* Process RESET_STREAM frame */
int quic_stream_handle_reset(struct quic_stream *stream, u64 error_code,
			     u64 final_size)
{
	struct quic_stream_recv_buf *recv = &stream->recv;

	if (stream->reset_received)
		return 0;

	/* Check final size consistency */
	if (recv->fin_received && final_size != recv->final_size)
		return -EPROTO;

	stream->error_code = error_code;
	stream->reset_received = 1;
	stream->state = QUIC_STREAM_STATE_RESET_RECVD;
	recv->reset_received = 1;
	recv->final_size = final_size;

	/* Discard any buffered data */
	quic_stream_recv_buf_destroy(recv);

	wake_up(&stream->wait);

	return 0;
}

/* Process STOP_SENDING frame */
int quic_stream_handle_stop_sending(struct quic_stream *stream, u64 error_code)
{
	if (stream->stop_sending_received)
		return 0;

	stream->stop_sending_received = 1;

	/* Respond with RESET_STREAM */
	return quic_stream_reset(stream, error_code);
}

/* Variable-length integer encoding helpers */
int quic_varint_len(u64 val)
{
	if (val <= 63)
		return 1;
	if (val <= 16383)
		return 2;
	if (val <= 1073741823)
		return 4;
	return 8;
}

void quic_varint_encode(u64 val, u8 *buf)
{
	if (val <= 63) {
		buf[0] = val;
	} else if (val <= 16383) {
		buf[0] = 0x40 | (val >> 8);
		buf[1] = val & 0xff;
	} else if (val <= 1073741823) {
		buf[0] = 0x80 | (val >> 24);
		buf[1] = (val >> 16) & 0xff;
		buf[2] = (val >> 8) & 0xff;
		buf[3] = val & 0xff;
	} else {
		buf[0] = 0xc0 | (val >> 56);
		buf[1] = (val >> 48) & 0xff;
		buf[2] = (val >> 40) & 0xff;
		buf[3] = (val >> 32) & 0xff;
		buf[4] = (val >> 24) & 0xff;
		buf[5] = (val >> 16) & 0xff;
		buf[6] = (val >> 8) & 0xff;
		buf[7] = val & 0xff;
	}
}

int quic_varint_decode(const u8 *buf, size_t len, u64 *val)
{
	u8 prefix;
	int varint_len;

	if (len < 1)
		return -EINVAL;

	prefix = buf[0] >> 6;
	varint_len = 1 << prefix;

	if (len < varint_len)
		return -EINVAL;

	switch (varint_len) {
	case 1:
		*val = buf[0] & 0x3f;
		break;
	case 2:
		*val = ((u64)(buf[0] & 0x3f) << 8) | buf[1];
		break;
	case 4:
		*val = ((u64)(buf[0] & 0x3f) << 24) |
		       ((u64)buf[1] << 16) |
		       ((u64)buf[2] << 8) |
		       buf[3];
		break;
	case 8:
		*val = ((u64)(buf[0] & 0x3f) << 56) |
		       ((u64)buf[1] << 48) |
		       ((u64)buf[2] << 40) |
		       ((u64)buf[3] << 32) |
		       ((u64)buf[4] << 24) |
		       ((u64)buf[5] << 16) |
		       ((u64)buf[6] << 8) |
		       buf[7];
		break;
	}

	return varint_len;
}

int __init quic_stream_init(void)
{
	quic_stream_cache = kmem_cache_create("quic_stream",
					      sizeof(struct quic_stream), 0,
					      SLAB_HWCACHE_ALIGN, NULL);
	if (!quic_stream_cache)
		return -ENOMEM;

	quic_recv_chunk_cache = kmem_cache_create("quic_recv_chunk",
						  sizeof(struct quic_recv_chunk) + 1024, 0,
						  SLAB_HWCACHE_ALIGN, NULL);
	if (!quic_recv_chunk_cache) {
		kmem_cache_destroy(quic_stream_cache);
		return -ENOMEM;
	}

	return 0;
}

void quic_stream_exit(void)
{
	kmem_cache_destroy(quic_recv_chunk_cache);
	kmem_cache_destroy(quic_stream_cache);
}
