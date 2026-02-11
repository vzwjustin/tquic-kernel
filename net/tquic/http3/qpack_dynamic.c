// SPDX-License-Identifier: GPL-2.0-only
/*
 * QPACK Dynamic Table Management - RFC 9204
 *
 * Copyright (c) 2026 Linux Foundation
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * The dynamic table is a FIFO table that maintains recently used
 * header field entries. It supports insertion, duplication, and
 * eviction of entries based on table capacity.
 *
 * Entry size calculation per RFC 9204 Section 3.2.1:
 *   size = len(name) + len(value) + 32
 *
 * Indexing:
 *   - Absolute Index: Sequential insertion number (starts at 0)
 *   - Relative Index: Counted backwards from current base
 *   - Post-Base Index: Counted forwards from current base
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/module.h>

#include "qpack.h"

/* Entry size overhead per RFC 9204 Section 3.2.1 */
#define QPACK_ENTRY_OVERHEAD	32

/**
 * entry_size - Calculate dynamic table entry size
 * @name_len: Length of header name
 * @value_len: Length of header value
 *
 * Returns: Total entry size including overhead
 */
static inline u32 entry_size(u16 name_len, u16 value_len)
{
	return name_len + value_len + QPACK_ENTRY_OVERHEAD;
}

/**
 * qpack_dynamic_entry_alloc - Allocate a dynamic table entry
 * @name: Header field name
 * @name_len: Length of name
 * @value: Header field value
 * @value_len: Length of value
 *
 * Returns: Allocated entry or NULL on failure
 */
static struct qpack_dynamic_entry *qpack_dynamic_entry_alloc(
	const char *name, u16 name_len,
	const char *value, u16 value_len)
{
	struct qpack_dynamic_entry *entry;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return NULL;

	entry->name = kmalloc(name_len, GFP_KERNEL);
	if (!entry->name) {
		kfree(entry);
		return NULL;
	}
	memcpy(entry->name, name, name_len);
	entry->name_len = name_len;

	entry->value = kmalloc(value_len, GFP_KERNEL);
	if (!entry->value) {
		kfree(entry->name);
		kfree(entry);
		return NULL;
	}
	if (value_len > 0)
		memcpy(entry->value, value, value_len);
	entry->value_len = value_len;

	entry->size = entry_size(name_len, value_len);
	refcount_set(&entry->refcnt, 1);
	INIT_LIST_HEAD(&entry->list);

	return entry;
}

/**
 * qpack_dynamic_entry_free - Free a dynamic table entry
 * @entry: Entry to free
 */
static void qpack_dynamic_entry_free(struct qpack_dynamic_entry *entry)
{
	if (!entry)
		return;

	kfree(entry->name);
	kfree(entry->value);
	kfree(entry);
}

/**
 * qpack_dynamic_entry_get - Increment entry reference count
 * @entry: Entry to reference
 */
static inline void qpack_dynamic_entry_get(struct qpack_dynamic_entry *entry)
{
	refcount_inc(&entry->refcnt);
}

/**
 * qpack_dynamic_entry_put - Decrement entry reference count
 * @entry: Entry to dereference
 *
 * Frees entry when reference count reaches zero.
 */
static inline void qpack_dynamic_entry_put(struct qpack_dynamic_entry *entry)
{
	if (refcount_dec_and_test(&entry->refcnt))
		qpack_dynamic_entry_free(entry);
}

/**
 * evict_entries - Evict oldest entries to make room
 * @table: Dynamic table
 * @required_space: Space needed for new entry
 *
 * Returns: 0 on success, -ENOSPC if cannot make enough room
 *
 * Entries are evicted from the end of the list (oldest first).
 * Only entries that have been acknowledged can be evicted.
 */
static int evict_entries(struct qpack_dynamic_table *table, u64 required_space)
{
	struct qpack_dynamic_entry *entry, *tmp;
	u64 available;

	/* Calculate space available after eviction */
	available = table->capacity - table->size;
	if (available >= required_space)
		return 0;

	/* Evict oldest entries until we have enough space */
	list_for_each_entry_safe_reverse(entry, tmp, &table->entries, list) {
		/* Only evict acknowledged entries */
		if (entry->absolute_index >= table->acked_insert_count)
			continue;

		/* Don't evict entries still referenced */
		if (refcount_read(&entry->refcnt) > 1)
			continue;

		table->size -= entry->size;
		table->num_entries--;
		list_del(&entry->list);
		qpack_dynamic_entry_put(entry);

		available = table->capacity - table->size;
		if (available >= required_space)
			return 0;
	}

	/* Could not make enough room */
	return -ENOSPC;
}

/**
 * qpack_dynamic_table_init - Initialize dynamic table
 * @table: Table to initialize
 * @capacity: Maximum table capacity in bytes
 *
 * Returns: 0 on success, negative error code on failure
 */
int qpack_dynamic_table_init(struct qpack_dynamic_table *table, u64 capacity)
{
	if (!table)
		return -EINVAL;

	INIT_LIST_HEAD(&table->entries);
	table->capacity = capacity;
	table->size = 0;
	table->max_entries = capacity / QPACK_ENTRY_OVERHEAD;
	table->num_entries = 0;
	table->insert_count = 0;
	table->acked_insert_count = 0;
	spin_lock_init(&table->lock);

	return 0;
}
EXPORT_SYMBOL_GPL(qpack_dynamic_table_init);

/**
 * qpack_dynamic_table_destroy - Release dynamic table resources
 * @table: Table to destroy
 */
void qpack_dynamic_table_destroy(struct qpack_dynamic_table *table)
{
	struct qpack_dynamic_entry *entry, *tmp;
	unsigned long flags;

	if (!table)
		return;

	spin_lock_irqsave(&table->lock, flags);
	list_for_each_entry_safe(entry, tmp, &table->entries, list) {
		list_del(&entry->list);
		qpack_dynamic_entry_put(entry);
	}
	table->size = 0;
	table->num_entries = 0;
	spin_unlock_irqrestore(&table->lock, flags);
}
EXPORT_SYMBOL_GPL(qpack_dynamic_table_destroy);

/**
 * qpack_dynamic_table_set_capacity - Set dynamic table capacity
 * @table: Dynamic table
 * @capacity: New capacity in bytes
 *
 * Returns: 0 on success, negative error code on failure
 *
 * Reducing capacity may trigger eviction of entries.
 */
int qpack_dynamic_table_set_capacity(struct qpack_dynamic_table *table,
				     u64 capacity)
{
	unsigned long flags;
	int ret = 0;

	if (!table)
		return -EINVAL;

	spin_lock_irqsave(&table->lock, flags);

	if (capacity < table->capacity) {
		/* Need to evict entries if new capacity is smaller */
		while (table->size > capacity) {
			struct qpack_dynamic_entry *entry;

			if (list_empty(&table->entries)) {
				ret = -ENOSPC;
				goto out;
			}

			/* Evict oldest entry */
			entry = list_last_entry(&table->entries,
						struct qpack_dynamic_entry, list);

			/* Cannot evict unacknowledged entries */
			if (entry->absolute_index >= table->acked_insert_count) {
				ret = -EBUSY;
				goto out;
			}

			table->size -= entry->size;
			table->num_entries--;
			list_del(&entry->list);
			qpack_dynamic_entry_put(entry);
		}
	}

	table->capacity = capacity;
	table->max_entries = capacity / QPACK_ENTRY_OVERHEAD;

out:
	spin_unlock_irqrestore(&table->lock, flags);
	return ret;
}
EXPORT_SYMBOL_GPL(qpack_dynamic_table_set_capacity);

/**
 * qpack_dynamic_table_insert - Insert entry into dynamic table
 * @table: Dynamic table
 * @name: Header field name
 * @name_len: Length of name
 * @value: Header field value
 * @value_len: Length of value
 *
 * Returns: 0 on success, negative error code on failure
 *
 * New entries are added to the front of the list.
 */
int qpack_dynamic_table_insert(struct qpack_dynamic_table *table,
			       const char *name, u16 name_len,
			       const char *value, u16 value_len)
{
	struct qpack_dynamic_entry *entry;
	unsigned long flags;
	u32 size;
	int ret;

	if (!table || !name)
		return -EINVAL;

	size = entry_size(name_len, value_len);
	if (size > table->capacity)
		return -ENOSPC;

	/* Allocate entry before taking lock */
	entry = qpack_dynamic_entry_alloc(name, name_len, value, value_len);
	if (!entry)
		return -ENOMEM;

	spin_lock_irqsave(&table->lock, flags);

	/* Evict entries if needed */
	ret = evict_entries(table, size);
	if (ret) {
		spin_unlock_irqrestore(&table->lock, flags);
		qpack_dynamic_entry_free(entry);
		return ret;
	}

	/* Assign absolute index */
	entry->absolute_index = table->insert_count++;

	/* Add to front of list */
	list_add(&entry->list, &table->entries);
	table->size += size;
	table->num_entries++;

	spin_unlock_irqrestore(&table->lock, flags);
	return 0;
}
EXPORT_SYMBOL_GPL(qpack_dynamic_table_insert);

/**
 * qpack_dynamic_table_duplicate - Duplicate entry in dynamic table
 * @table: Dynamic table
 * @index: Absolute index of entry to duplicate
 *
 * Returns: 0 on success, negative error code on failure
 *
 * Creates a copy of an existing entry at the front of the table.
 * This is useful for preventing eviction of frequently used entries.
 */
int qpack_dynamic_table_duplicate(struct qpack_dynamic_table *table,
				  u64 index)
{
	struct qpack_dynamic_entry *source, *entry;
	unsigned long flags;
	int ret;

	if (!table)
		return -EINVAL;

	/*
	 * Hold the lock across the entire lookup-allocate-evict-insert
	 * sequence to prevent a TOCTOU race where another thread modifies
	 * the table between lookup and insertion.  All allocations use
	 * GFP_ATOMIC since we are under a spinlock.
	 */
	spin_lock_irqsave(&table->lock, flags);

	/* Find source entry */
	source = qpack_dynamic_table_get(table, index);
	if (!source) {
		spin_unlock_irqrestore(&table->lock, flags);
		return -ENOENT;
	}

	/* Allocate the duplicate entry under the lock (GFP_ATOMIC) */
	entry = kzalloc(sizeof(*entry), GFP_ATOMIC);
	if (!entry) {
		spin_unlock_irqrestore(&table->lock, flags);
		return -ENOMEM;
	}

	entry->name = kmalloc(source->name_len, GFP_ATOMIC);
	entry->value = kmalloc(source->value_len, GFP_ATOMIC);
	if (!entry->name || !entry->value) {
		spin_unlock_irqrestore(&table->lock, flags);
		kfree(entry->name);
		kfree(entry->value);
		kfree(entry);
		return -ENOMEM;
	}

	memcpy(entry->name, source->name, source->name_len);
	entry->name_len = source->name_len;
	memcpy(entry->value, source->value, source->value_len);
	entry->value_len = source->value_len;
	entry->size = source->size;
	refcount_set(&entry->refcnt, 1);
	INIT_LIST_HEAD(&entry->list);

	/* Evict entries if needed */
	ret = evict_entries(table, entry->size);
	if (ret) {
		spin_unlock_irqrestore(&table->lock, flags);
		kfree(entry->name);
		kfree(entry->value);
		kfree(entry);
		return ret;
	}

	/* Assign absolute index */
	entry->absolute_index = table->insert_count++;

	/* Add to front of list */
	list_add(&entry->list, &table->entries);
	table->size += entry->size;
	table->num_entries++;

	spin_unlock_irqrestore(&table->lock, flags);
	return 0;
}
EXPORT_SYMBOL_GPL(qpack_dynamic_table_duplicate);

/**
 * qpack_dynamic_table_get - Get entry by absolute index
 * @table: Dynamic table
 * @absolute_index: Absolute index of entry
 *
 * Returns: Entry pointer or NULL if not found
 *
 * Note: Must be called with table->lock held or RCU read lock.
 */
struct qpack_dynamic_entry *qpack_dynamic_table_get(
	struct qpack_dynamic_table *table, u64 absolute_index)
{
	struct qpack_dynamic_entry *entry;

	if (!table)
		return NULL;

	list_for_each_entry(entry, &table->entries, list) {
		if (entry->absolute_index == absolute_index)
			return entry;
	}

	return NULL;
}
EXPORT_SYMBOL_GPL(qpack_dynamic_table_get);

/**
 * qpack_dynamic_table_get_relative - Get entry by relative index
 * @table: Dynamic table
 * @relative_index: Relative index from base
 * @base: Base value for relative addressing
 *
 * Returns: Entry pointer or NULL if not found
 *
 * Relative index addressing: absolute = base - relative - 1
 */
struct qpack_dynamic_entry *qpack_dynamic_table_get_relative(
	struct qpack_dynamic_table *table, u64 relative_index, u64 base)
{
	u64 absolute_index;

	if (!table || relative_index >= base)
		return NULL;

	absolute_index = base - relative_index - 1;
	return qpack_dynamic_table_get(table, absolute_index);
}
EXPORT_SYMBOL_GPL(qpack_dynamic_table_get_relative);

/**
 * qpack_dynamic_table_get_post_base - Get entry by post-base index
 * @table: Dynamic table
 * @post_base_index: Post-base index
 * @base: Base value for addressing
 *
 * Returns: Entry pointer or NULL if not found
 *
 * Post-base index addressing: absolute = base + post_base_index
 */
struct qpack_dynamic_entry *qpack_dynamic_table_get_post_base(
	struct qpack_dynamic_table *table, u64 post_base_index, u64 base)
{
	u64 absolute_index;

	if (!table)
		return NULL;

	absolute_index = base + post_base_index;
	return qpack_dynamic_table_get(table, absolute_index);
}
EXPORT_SYMBOL_GPL(qpack_dynamic_table_get_post_base);

/**
 * qpack_dynamic_table_find_name - Find entry by name only
 * @table: Dynamic table
 * @name: Header field name
 * @name_len: Length of name
 *
 * Returns: Absolute index of first match, or -1 if not found
 *
 * Searches for entry with matching name (value may differ).
 */
s64 qpack_dynamic_table_find_name(struct qpack_dynamic_table *table,
				  const char *name, u16 name_len)
{
	struct qpack_dynamic_entry *entry;
	unsigned long flags;
	s64 result = -1;

	if (!table || !name || name_len == 0)
		return -1;

	spin_lock_irqsave(&table->lock, flags);
	list_for_each_entry(entry, &table->entries, list) {
		if (entry->name_len == name_len &&
		    memcmp(entry->name, name, name_len) == 0) {
			result = entry->absolute_index;
			break;
		}
	}
	spin_unlock_irqrestore(&table->lock, flags);

	return result;
}
EXPORT_SYMBOL_GPL(qpack_dynamic_table_find_name);

/**
 * qpack_dynamic_table_find - Find entry by name and value
 * @table: Dynamic table
 * @name: Header field name
 * @name_len: Length of name
 * @value: Header field value
 * @value_len: Length of value
 *
 * Returns: Absolute index of matching entry, or -1 if not found
 */
s64 qpack_dynamic_table_find(struct qpack_dynamic_table *table,
			     const char *name, u16 name_len,
			     const char *value, u16 value_len)
{
	struct qpack_dynamic_entry *entry;
	unsigned long flags;
	s64 result = -1;

	if (!table || !name || name_len == 0)
		return -1;

	spin_lock_irqsave(&table->lock, flags);
	list_for_each_entry(entry, &table->entries, list) {
		/* Check name match */
		if (entry->name_len != name_len ||
		    memcmp(entry->name, name, name_len) != 0)
			continue;

		/* Check value match */
		if (entry->value_len == value_len) {
			if (value_len == 0) {
				result = entry->absolute_index;
				break;
			}
			if (value && memcmp(entry->value, value, value_len) == 0) {
				result = entry->absolute_index;
				break;
			}
		}
	}
	spin_unlock_irqrestore(&table->lock, flags);

	return result;
}
EXPORT_SYMBOL_GPL(qpack_dynamic_table_find);

/**
 * qpack_dynamic_table_acknowledge - Acknowledge insertions
 * @table: Dynamic table
 * @insert_count: Insert count to acknowledge up to
 *
 * Updates the acked_insert_count, enabling eviction of acknowledged entries.
 */
void qpack_dynamic_table_acknowledge(struct qpack_dynamic_table *table,
				     u64 insert_count)
{
	unsigned long flags;

	if (!table)
		return;

	spin_lock_irqsave(&table->lock, flags);
	if (insert_count > table->acked_insert_count)
		table->acked_insert_count = insert_count;
	spin_unlock_irqrestore(&table->lock, flags);
}
EXPORT_SYMBOL_GPL(qpack_dynamic_table_acknowledge);

MODULE_DESCRIPTION("QPACK Dynamic Table for HTTP/3");
MODULE_LICENSE("GPL");
