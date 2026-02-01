// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Packet Reordering Buffer for WAN Bonding
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Handles packet reordering when using multiple paths with different
 * latencies in WAN bonding scenarios.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/rbtree.h>
#include <linux/timer.h>
#include <linux/spinlock.h>
#include <net/tquic.h>

/* Reorder buffer configuration */
#define TQUIC_REORDER_DEFAULT_SIZE	256
#define TQUIC_REORDER_MAX_SIZE		4096
#define TQUIC_REORDER_TIMEOUT_MS	100

/* Per-packet metadata stored in skb->cb */
struct tquic_reorder_cb {
	u64 pkt_num;		/* Packet number */
	u32 path_id;		/* Path packet arrived on */
	ktime_t arrival;	/* Arrival timestamp */
};

#define TQUIC_REORDER_CB(skb) ((struct tquic_reorder_cb *)(skb)->cb)

/* Reorder buffer entry */
struct tquic_reorder_entry {
	struct rb_node node;
	struct sk_buff *skb;
	u64 pkt_num;
};

/* Reorder buffer state */
struct tquic_reorder_buf {
	struct rb_root entries;		/* RB-tree of buffered packets */
	struct sk_buff_head overflow;	/* Overflow queue */
	spinlock_t lock;

	u64 next_expected;		/* Next expected packet number */
	u64 highest_received;		/* Highest received packet number */

	u32 max_size;			/* Maximum buffer size */
	u32 current_size;		/* Current number of entries */
	u32 window;			/* Reorder window size */

	/* Statistics */
	u64 in_order_packets;		/* Packets delivered in order */
	u64 reordered_packets;		/* Packets that needed buffering */
	u64 dropped_packets;		/* Packets dropped due to overflow */
	u64 timeout_deliveries;		/* Packets delivered due to timeout */
	u64 gap_deliveries;		/* Packets delivered due to gap */

	/* Timeout handling */
	struct timer_list timeout_timer;
	struct work_struct deliver_work;
	struct tquic_connection *conn;
};

/*
 * Allocate reorder buffer
 */
struct tquic_reorder_buf *tquic_reorder_alloc(struct tquic_connection *conn,
					      u32 window_size)
{
	struct tquic_reorder_buf *buf;

	buf = kzalloc(sizeof(*buf), GFP_KERNEL);
	if (!buf)
		return NULL;

	buf->entries = RB_ROOT;
	skb_queue_head_init(&buf->overflow);
	spin_lock_init(&buf->lock);

	buf->max_size = TQUIC_REORDER_DEFAULT_SIZE;
	buf->window = window_size ?: 64;
	buf->next_expected = 0;
	buf->conn = conn;

	timer_setup(&buf->timeout_timer, NULL, 0);

	pr_debug("tquic_reorder: allocated buffer with window %u\n", buf->window);

	return buf;
}
EXPORT_SYMBOL_GPL(tquic_reorder_alloc);

/*
 * Free reorder buffer
 */
void tquic_reorder_free(struct tquic_reorder_buf *buf)
{
	struct rb_node *node;

	if (!buf)
		return;

	del_timer_sync(&buf->timeout_timer);

	/* Free all buffered packets */
	spin_lock_bh(&buf->lock);
	while ((node = rb_first(&buf->entries))) {
		struct tquic_reorder_entry *entry;

		entry = rb_entry(node, struct tquic_reorder_entry, node);
		rb_erase(node, &buf->entries);
		kfree_skb(entry->skb);
		kfree(entry);
	}
	skb_queue_purge(&buf->overflow);
	spin_unlock_bh(&buf->lock);

	kfree(buf);
}
EXPORT_SYMBOL_GPL(tquic_reorder_free);

/*
 * Insert packet into reorder buffer
 */
static int reorder_insert(struct tquic_reorder_buf *buf, struct sk_buff *skb,
			  u64 pkt_num)
{
	struct tquic_reorder_entry *entry, *existing;
	struct rb_node **link, *parent = NULL;

	/* Check for duplicates and find insertion point */
	link = &buf->entries.rb_node;
	while (*link) {
		parent = *link;
		existing = rb_entry(parent, struct tquic_reorder_entry, node);

		if (pkt_num < existing->pkt_num) {
			link = &parent->rb_left;
		} else if (pkt_num > existing->pkt_num) {
			link = &parent->rb_right;
		} else {
			/* Duplicate packet */
			return -EEXIST;
		}
	}

	/* Allocate new entry */
	entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
	if (!entry) {
		buf->dropped_packets++;
		return -ENOMEM;
	}

	entry->skb = skb;
	entry->pkt_num = pkt_num;

	rb_link_node(&entry->node, parent, link);
	rb_insert_color(&entry->node, &buf->entries);
	buf->current_size++;

	return 0;
}

/*
 * Deliver consecutive packets starting from next_expected
 */
static int reorder_deliver(struct tquic_reorder_buf *buf,
			   struct sk_buff_head *delivered)
{
	struct rb_node *node;
	int count = 0;

	while ((node = rb_first(&buf->entries))) {
		struct tquic_reorder_entry *entry;

		entry = rb_entry(node, struct tquic_reorder_entry, node);

		/* Stop if packet is not the next expected */
		if (entry->pkt_num != buf->next_expected)
			break;

		/* Remove from tree */
		rb_erase(node, &buf->entries);
		buf->current_size--;

		/* Add to delivery queue */
		__skb_queue_tail(delivered, entry->skb);
		buf->next_expected++;
		buf->in_order_packets++;
		count++;

		kfree(entry);
	}

	return count;
}

/*
 * Force delivery up to a certain packet number (for gap handling)
 */
static int reorder_force_deliver(struct tquic_reorder_buf *buf,
				 u64 up_to_pkt_num,
				 struct sk_buff_head *delivered)
{
	struct rb_node *node, *next;
	int count = 0;

	for (node = rb_first(&buf->entries); node; node = next) {
		struct tquic_reorder_entry *entry;

		next = rb_next(node);
		entry = rb_entry(node, struct tquic_reorder_entry, node);

		if (entry->pkt_num > up_to_pkt_num)
			break;

		rb_erase(node, &buf->entries);
		buf->current_size--;

		__skb_queue_tail(delivered, entry->skb);
		count++;

		kfree(entry);
	}

	if (count > 0) {
		buf->next_expected = up_to_pkt_num + 1;
		buf->gap_deliveries += count;
	}

	return count;
}

/*
 * Process incoming packet
 *
 * Returns:
 *   Positive: Number of packets delivered (including this one if in-order)
 *   0: Packet buffered (out of order)
 *   Negative: Error
 */
int tquic_reorder_receive(struct tquic_reorder_buf *buf, struct sk_buff *skb,
			  u64 pkt_num, struct sk_buff_head *delivered)
{
	int ret;
	int deliver_count = 0;

	spin_lock_bh(&buf->lock);

	/* Update highest received */
	if (pkt_num > buf->highest_received)
		buf->highest_received = pkt_num;

	/* Check if packet is too old */
	if (pkt_num < buf->next_expected) {
		/* Old packet, already delivered */
		spin_unlock_bh(&buf->lock);
		kfree_skb(skb);
		return 0;
	}

	/* Store metadata in skb */
	TQUIC_REORDER_CB(skb)->pkt_num = pkt_num;
	TQUIC_REORDER_CB(skb)->arrival = ktime_get();

	/* Check if packet is in order */
	if (pkt_num == buf->next_expected) {
		/* Deliver immediately */
		__skb_queue_tail(delivered, skb);
		buf->next_expected++;
		buf->in_order_packets++;
		deliver_count = 1;

		/* Try to deliver any buffered consecutive packets */
		deliver_count += reorder_deliver(buf, delivered);
	} else {
		/* Out of order - buffer it */
		if (buf->current_size >= buf->max_size) {
			/* Buffer full, try to make room */
			if (pkt_num > buf->next_expected + buf->window) {
				/* Large gap - force deliver old packets */
				reorder_force_deliver(buf,
						      pkt_num - buf->window,
						      delivered);
			}
		}

		if (buf->current_size >= buf->max_size) {
			/* Still full, drop packet */
			spin_unlock_bh(&buf->lock);
			buf->dropped_packets++;
			kfree_skb(skb);
			return -ENOSPC;
		}

		ret = reorder_insert(buf, skb, pkt_num);
		if (ret < 0) {
			spin_unlock_bh(&buf->lock);
			if (ret == -EEXIST) {
				kfree_skb(skb);
				return 0;  /* Duplicate */
			}
			kfree_skb(skb);
			return ret;
		}

		buf->reordered_packets++;

		/* Check if we should force delivery due to large gap */
		if (pkt_num > buf->next_expected + buf->window) {
			deliver_count = reorder_force_deliver(buf,
							     pkt_num - buf->window / 2,
							     delivered);
		}
	}

	spin_unlock_bh(&buf->lock);
	return deliver_count;
}
EXPORT_SYMBOL_GPL(tquic_reorder_receive);

/*
 * Flush buffer (timeout or explicit request)
 */
int tquic_reorder_flush(struct tquic_reorder_buf *buf,
			struct sk_buff_head *delivered)
{
	struct rb_node *node, *next;
	int count = 0;

	spin_lock_bh(&buf->lock);

	for (node = rb_first(&buf->entries); node; node = next) {
		struct tquic_reorder_entry *entry;

		next = rb_next(node);
		entry = rb_entry(node, struct tquic_reorder_entry, node);

		rb_erase(node, &buf->entries);
		buf->current_size--;

		__skb_queue_tail(delivered, entry->skb);
		count++;

		kfree(entry);
	}

	buf->timeout_deliveries += count;

	/* Update next expected to highest we've seen + 1 */
	if (count > 0)
		buf->next_expected = buf->highest_received + 1;

	spin_unlock_bh(&buf->lock);

	return count;
}
EXPORT_SYMBOL_GPL(tquic_reorder_flush);

/*
 * Get reorder buffer statistics
 */
void tquic_reorder_get_stats(struct tquic_reorder_buf *buf,
			     u64 *in_order, u64 *reordered,
			     u64 *dropped, u64 *timeout,
			     u32 *buffered)
{
	spin_lock_bh(&buf->lock);

	if (in_order)
		*in_order = buf->in_order_packets;
	if (reordered)
		*reordered = buf->reordered_packets;
	if (dropped)
		*dropped = buf->dropped_packets;
	if (timeout)
		*timeout = buf->timeout_deliveries;
	if (buffered)
		*buffered = buf->current_size;

	spin_unlock_bh(&buf->lock);
}
EXPORT_SYMBOL_GPL(tquic_reorder_get_stats);

/*
 * Set reorder window size
 */
void tquic_reorder_set_window(struct tquic_reorder_buf *buf, u32 window)
{
	spin_lock_bh(&buf->lock);
	buf->window = min(window, (u32)TQUIC_REORDER_MAX_SIZE);
	spin_unlock_bh(&buf->lock);
}
EXPORT_SYMBOL_GPL(tquic_reorder_set_window);

/*
 * Check if reorder buffer has pending packets
 */
bool tquic_reorder_has_pending(struct tquic_reorder_buf *buf)
{
	bool has_pending;

	spin_lock_bh(&buf->lock);
	has_pending = buf->current_size > 0;
	spin_unlock_bh(&buf->lock);

	return has_pending;
}
EXPORT_SYMBOL_GPL(tquic_reorder_has_pending);

/*
 * Get expected packet gap (for flow control)
 */
u64 tquic_reorder_get_gap(struct tquic_reorder_buf *buf)
{
	u64 gap;

	spin_lock_bh(&buf->lock);
	gap = buf->highest_received - buf->next_expected;
	spin_unlock_bh(&buf->lock);

	return gap;
}
EXPORT_SYMBOL_GPL(tquic_reorder_get_gap);

MODULE_DESCRIPTION("TQUIC Packet Reordering Buffer");
MODULE_LICENSE("GPL");
