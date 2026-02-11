// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Additional Addresses Transport Parameter Extension
 *
 * Copyright (c) 2026 Linux Foundation
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Implements draft-piraux-quic-additional-addresses extension
 *
 * This extension allows QUIC endpoints to advertise multiple addresses
 * they can be reached at, enabling flexible connection migration and
 * multipath scenarios beyond the single preferred_address parameter.
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/random.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <net/sock.h>
#include <net/tquic.h>

#include "additional_addresses.h"
#include "varint.h"
#include "transport_params.h"
#include "../protocol.h"
#include "../tquic_stateless_reset.h"
#include "../tquic_cid.h"

/*
 * =============================================================================
 * SYSCTL ACCESSOR DECLARATIONS
 * =============================================================================
 */
extern int tquic_sysctl_get_additional_addresses_enabled(void);
extern int tquic_sysctl_get_additional_addresses_max(void);

/*
 * =============================================================================
 * HELPER FUNCTIONS
 * =============================================================================
 */

/**
 * sockaddr_storage_equal - Compare two socket addresses
 */
static bool sockaddr_storage_equal(const struct sockaddr_storage *a,
				   const struct sockaddr_storage *b)
{
	if (a->ss_family != b->ss_family)
		return false;

	if (a->ss_family == AF_INET) {
		const struct sockaddr_in *a4 = (const struct sockaddr_in *)a;
		const struct sockaddr_in *b4 = (const struct sockaddr_in *)b;
		return a4->sin_addr.s_addr == b4->sin_addr.s_addr &&
		       a4->sin_port == b4->sin_port;
	}

#if IS_ENABLED(CONFIG_IPV6)
	if (a->ss_family == AF_INET6) {
		const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)a;
		const struct sockaddr_in6 *b6 = (const struct sockaddr_in6 *)b;
		return ipv6_addr_equal(&a6->sin6_addr, &b6->sin6_addr) &&
		       a6->sin6_port == b6->sin6_port;
	}
#endif

	return false;
}

/**
 * cid_equal - Compare two connection IDs
 */
static bool cid_equal(const struct tquic_cid *a, const struct tquic_cid *b)
{
	if (a->len != b->len)
		return false;
	if (a->len == 0)
		return true;
	return memcmp(a->id, b->id, a->len) == 0;
}

/*
 * =============================================================================
 * INITIALIZATION AND CLEANUP
 * =============================================================================
 */

/**
 * tquic_additional_addr_init - Initialize an additional addresses list
 */
void tquic_additional_addr_init(struct tquic_additional_addresses *addrs)
{
	if (!addrs)
		return;

	INIT_LIST_HEAD(&addrs->addresses);
	addrs->count = 0;
	addrs->max_count = TQUIC_MAX_ADDITIONAL_ADDRESSES;
	spin_lock_init(&addrs->lock);
	addrs->seq_num_base = 2;  /* 0=initial, 1=preferred_address */
}
EXPORT_SYMBOL_GPL(tquic_additional_addr_init);

/**
 * tquic_additional_addr_cleanup - Clean up additional addresses list
 */
void tquic_additional_addr_cleanup(struct tquic_additional_addresses *addrs)
{
	struct tquic_additional_address *entry, *tmp;

	if (!addrs)
		return;

	spin_lock_bh(&addrs->lock);
	list_for_each_entry_safe(entry, tmp, &addrs->addresses, list) {
		list_del(&entry->list);
		kfree(entry);
	}
	addrs->count = 0;
	spin_unlock_bh(&addrs->lock);
}
EXPORT_SYMBOL_GPL(tquic_additional_addr_cleanup);

/*
 * =============================================================================
 * ADDRESS MANAGEMENT
 * =============================================================================
 */

/**
 * tquic_additional_addr_add - Add an address to the list
 */
int tquic_additional_addr_add(struct tquic_additional_addresses *addrs,
			      u8 ip_version,
			      const struct sockaddr_storage *addr,
			      const struct tquic_cid *cid,
			      const u8 *reset_token)
{
	struct tquic_additional_address *entry;
	struct tquic_additional_address *existing;

	if (!addrs || !addr || !cid)
		return -EINVAL;

	/* Validate IP version */
	if (ip_version != TQUIC_ADDR_IP_VERSION_4 &&
	    ip_version != TQUIC_ADDR_IP_VERSION_6)
		return -EINVAL;

	/* Validate address family matches IP version */
	if ((ip_version == TQUIC_ADDR_IP_VERSION_4 && addr->ss_family != AF_INET) ||
	    (ip_version == TQUIC_ADDR_IP_VERSION_6 && addr->ss_family != AF_INET6))
		return -EINVAL;

	/* Validate CID length */
	if (cid->len > TQUIC_MAX_CID_LEN)
		return -EINVAL;

	/* Validate address is suitable for migration */
	if (!tquic_additional_addr_is_valid(addr)) {
		pr_debug("tquic_additional_addr: invalid address rejected\n");
		return -EINVAL;
	}

	/*
	 * CF-330: Pre-allocate the entry before taking the lock so we can
	 * use GFP_KERNEL, then do the duplicate check and insert atomically
	 * under the lock to eliminate the TOCTOU race.
	 */
	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;

	/* Initialize entry before taking the lock */
	INIT_LIST_HEAD(&entry->list);
	entry->ip_version = ip_version;
	memcpy(&entry->addr, addr,
	       ip_version == TQUIC_ADDR_IP_VERSION_4 ?
	       sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
	memcpy(&entry->cid, cid, sizeof(*cid));

	/* Copy or generate reset token */
	if (reset_token) {
		memcpy(entry->stateless_reset_token, reset_token,
		       TQUIC_STATELESS_RESET_TOKEN_LEN);
	} else {
		get_random_bytes(entry->stateless_reset_token,
				 TQUIC_STATELESS_RESET_TOKEN_LEN);
	}

	entry->validated = false;
	entry->active = true;
	entry->rtt_estimate = 0;
	entry->last_used = ktime_get();

	spin_lock_bh(&addrs->lock);

	/* Check capacity */
	if (addrs->count >= addrs->max_count) {
		spin_unlock_bh(&addrs->lock);
		kfree(entry);
		pr_debug("tquic_additional_addr: list full (max=%u)\n",
			 addrs->max_count);
		return -ENOSPC;
	}

	/* Check for duplicate address */
	list_for_each_entry(existing, &addrs->addresses, list) {
		if (sockaddr_storage_equal(&existing->addr, addr)) {
			spin_unlock_bh(&addrs->lock);
			kfree(entry);
			pr_debug("tquic_additional_addr: duplicate address\n");
			return -EEXIST;
		}
	}

	entry->priority = addrs->count;  /* Lower indices = higher priority */
	list_add_tail(&entry->list, &addrs->addresses);
	addrs->count++;
	spin_unlock_bh(&addrs->lock);

	pr_debug("tquic_additional_addr: added address (IPv%u, count=%u)\n",
		 ip_version, addrs->count);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_additional_addr_add);

/**
 * tquic_additional_addr_add_ipv4 - Add an IPv4 address (convenience)
 */
int tquic_additional_addr_add_ipv4(struct tquic_additional_addresses *addrs,
				   const struct sockaddr_in *addr,
				   const struct tquic_cid *cid,
				   const u8 *reset_token)
{
	struct sockaddr_storage ss;

	if (!addr)
		return -EINVAL;

	memset(&ss, 0, sizeof(ss));
	memcpy(&ss, addr, sizeof(*addr));

	return tquic_additional_addr_add(addrs, TQUIC_ADDR_IP_VERSION_4,
					 &ss, cid, reset_token);
}
EXPORT_SYMBOL_GPL(tquic_additional_addr_add_ipv4);

/**
 * tquic_additional_addr_add_ipv6 - Add an IPv6 address (convenience)
 */
int tquic_additional_addr_add_ipv6(struct tquic_additional_addresses *addrs,
				   const struct sockaddr_in6 *addr,
				   const struct tquic_cid *cid,
				   const u8 *reset_token)
{
	struct sockaddr_storage ss;

	if (!addr)
		return -EINVAL;

	memset(&ss, 0, sizeof(ss));
	memcpy(&ss, addr, sizeof(*addr));

	return tquic_additional_addr_add(addrs, TQUIC_ADDR_IP_VERSION_6,
					 &ss, cid, reset_token);
}
EXPORT_SYMBOL_GPL(tquic_additional_addr_add_ipv6);

/**
 * tquic_additional_addr_remove - Remove an address from the list
 */
int tquic_additional_addr_remove(struct tquic_additional_addresses *addrs,
				 const struct sockaddr_storage *addr)
{
	struct tquic_additional_address *entry, *tmp;
	bool found = false;

	if (!addrs || !addr)
		return -EINVAL;

	spin_lock_bh(&addrs->lock);
	list_for_each_entry_safe(entry, tmp, &addrs->addresses, list) {
		if (sockaddr_storage_equal(&entry->addr, addr)) {
			list_del(&entry->list);
			addrs->count--;
			found = true;
			break;
		}
	}
	spin_unlock_bh(&addrs->lock);

	if (!found)
		return -ENOENT;

	kfree(entry);
	pr_debug("tquic_additional_addr: removed address (count=%u)\n",
		 addrs->count);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_additional_addr_remove);

/**
 * tquic_additional_addr_remove_by_cid - Remove address by connection ID
 */
int tquic_additional_addr_remove_by_cid(struct tquic_additional_addresses *addrs,
					const struct tquic_cid *cid)
{
	struct tquic_additional_address *entry, *tmp;
	bool found = false;

	if (!addrs || !cid)
		return -EINVAL;

	spin_lock_bh(&addrs->lock);
	list_for_each_entry_safe(entry, tmp, &addrs->addresses, list) {
		if (cid_equal(&entry->cid, cid)) {
			list_del(&entry->list);
			addrs->count--;
			found = true;
			break;
		}
	}
	spin_unlock_bh(&addrs->lock);

	if (!found)
		return -ENOENT;

	kfree(entry);
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_additional_addr_remove_by_cid);

/**
 * tquic_additional_addr_find - Find an address entry
 */
struct tquic_additional_address *tquic_additional_addr_find(
	struct tquic_additional_addresses *addrs,
	const struct sockaddr_storage *addr)
{
	struct tquic_additional_address *entry;

	if (!addrs || !addr)
		return NULL;

	list_for_each_entry(entry, &addrs->addresses, list) {
		if (sockaddr_storage_equal(&entry->addr, addr))
			return entry;
	}

	return NULL;
}
EXPORT_SYMBOL_GPL(tquic_additional_addr_find);

/**
 * tquic_additional_addr_find_by_cid - Find address by connection ID
 */
struct tquic_additional_address *tquic_additional_addr_find_by_cid(
	struct tquic_additional_addresses *addrs,
	const struct tquic_cid *cid)
{
	struct tquic_additional_address *entry;

	if (!addrs || !cid)
		return NULL;

	list_for_each_entry(entry, &addrs->addresses, list) {
		if (cid_equal(&entry->cid, cid))
			return entry;
	}

	return NULL;
}
EXPORT_SYMBOL_GPL(tquic_additional_addr_find_by_cid);

/*
 * =============================================================================
 * ENCODING AND DECODING
 * =============================================================================
 */

/**
 * encode_single_address - Encode a single address entry
 */
static ssize_t encode_single_address(const struct tquic_additional_address *entry,
				     u8 *buf, size_t buflen)
{
	size_t offset = 0;
	size_t required;

	if (!entry || !buf)
		return -EINVAL;

	/* Calculate required size */
	required = 1 +	/* IP version */
		   (entry->ip_version == TQUIC_ADDR_IP_VERSION_4 ? 4 : 16) +
		   2 +	/* Port */
		   1 +	/* CID length */
		   entry->cid.len +
		   TQUIC_STATELESS_RESET_TOKEN_LEN;

	if (buflen < required)
		return -ENOSPC;

	/* IP version (1 byte) */
	buf[offset++] = entry->ip_version;

	/* Address */
	if (entry->ip_version == TQUIC_ADDR_IP_VERSION_4) {
		const struct sockaddr_in *sin =
			(const struct sockaddr_in *)&entry->addr;
		memcpy(buf + offset, &sin->sin_addr, 4);
		offset += 4;
		/* Port (big-endian) */
		buf[offset++] = (ntohs(sin->sin_port) >> 8) & 0xff;
		buf[offset++] = ntohs(sin->sin_port) & 0xff;
	} else {
		const struct sockaddr_in6 *sin6 =
			(const struct sockaddr_in6 *)&entry->addr;
		memcpy(buf + offset, &sin6->sin6_addr, 16);
		offset += 16;
		/* Port (big-endian) */
		buf[offset++] = (ntohs(sin6->sin6_port) >> 8) & 0xff;
		buf[offset++] = ntohs(sin6->sin6_port) & 0xff;
	}

	/* CID length (1 byte) */
	buf[offset++] = entry->cid.len;

	/* CID */
	if (entry->cid.len > 0) {
		memcpy(buf + offset, entry->cid.id, entry->cid.len);
		offset += entry->cid.len;
	}

	/* Stateless reset token (16 bytes) */
	memcpy(buf + offset, entry->stateless_reset_token,
	       TQUIC_STATELESS_RESET_TOKEN_LEN);
	offset += TQUIC_STATELESS_RESET_TOKEN_LEN;

	return offset;
}

/**
 * tquic_additional_addr_encode - Encode addresses for transport parameter
 */
ssize_t tquic_additional_addr_encode(const struct tquic_additional_addresses *addrs,
				     u8 *buf, size_t buflen)
{
	struct tquic_additional_address *entry;
	size_t offset = 0;
	ssize_t written;

	if (!addrs || !buf)
		return -EINVAL;

	if (addrs->count == 0)
		return 0;

	list_for_each_entry(entry, &addrs->addresses, list) {
		/* Only encode active addresses */
		if (!entry->active)
			continue;

		written = encode_single_address(entry, buf + offset,
						buflen - offset);
		if (written < 0)
			return written;

		offset += written;
	}

	return offset;
}
EXPORT_SYMBOL_GPL(tquic_additional_addr_encode);

/**
 * tquic_additional_addr_encoded_size - Calculate encoded size
 */
size_t tquic_additional_addr_encoded_size(
	const struct tquic_additional_addresses *addrs)
{
	struct tquic_additional_address *entry;
	size_t size = 0;

	if (!addrs)
		return 0;

	list_for_each_entry(entry, &addrs->addresses, list) {
		if (!entry->active)
			continue;

		size += 1;  /* IP version */
		size += (entry->ip_version == TQUIC_ADDR_IP_VERSION_4) ? 4 : 16;
		size += 2;  /* Port */
		size += 1;  /* CID length */
		size += entry->cid.len;
		size += TQUIC_STATELESS_RESET_TOKEN_LEN;
	}

	return size;
}
EXPORT_SYMBOL_GPL(tquic_additional_addr_encoded_size);

/**
 * decode_single_address - Decode a single address entry
 */
static int decode_single_address(const u8 *buf, size_t len,
				 struct tquic_additional_address *entry,
				 size_t *consumed)
{
	size_t offset = 0;
	u8 ip_version;
	u8 cid_len;
	size_t min_len;

	if (!buf || !entry || !consumed || len < 1)
		return -EINVAL;

	/* IP version */
	ip_version = buf[offset++];
	if (ip_version != TQUIC_ADDR_IP_VERSION_4 &&
	    ip_version != TQUIC_ADDR_IP_VERSION_6) {
		pr_debug("tquic_additional_addr: invalid IP version %u\n",
			 ip_version);
		return -EINVAL;
	}

	/* Minimum length check */
	min_len = (ip_version == TQUIC_ADDR_IP_VERSION_4) ?
		  TQUIC_ADDITIONAL_ADDR_MIN_IPV4 :
		  TQUIC_ADDITIONAL_ADDR_MIN_IPV6;
	if (len < min_len) {
		pr_debug("tquic_additional_addr: buffer too short for IPv%u\n",
			 ip_version);
		return -EINVAL;
	}

	entry->ip_version = ip_version;

	/* Address and port */
	if (ip_version == TQUIC_ADDR_IP_VERSION_4) {
		struct sockaddr_in *sin = (struct sockaddr_in *)&entry->addr;
		sin->sin_family = AF_INET;
		memcpy(&sin->sin_addr, buf + offset, 4);
		offset += 4;
		sin->sin_port = htons(((u16)buf[offset] << 8) | buf[offset + 1]);
		offset += 2;
	} else {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&entry->addr;
		sin6->sin6_family = AF_INET6;
		memcpy(&sin6->sin6_addr, buf + offset, 16);
		offset += 16;
		sin6->sin6_port = htons(((u16)buf[offset] << 8) | buf[offset + 1]);
		offset += 2;
	}

	/* CID length */
	cid_len = buf[offset++];
	if (cid_len > TQUIC_MAX_CID_LEN) {
		pr_debug("tquic_additional_addr: CID too long: %u\n", cid_len);
		return -EINVAL;
	}

	/* Check remaining length */
	if (len - offset < cid_len + TQUIC_STATELESS_RESET_TOKEN_LEN) {
		pr_debug("tquic_additional_addr: not enough data for CID+token\n");
		return -EINVAL;
	}

	/* CID */
	entry->cid.len = cid_len;
	if (cid_len > 0) {
		memcpy(entry->cid.id, buf + offset, cid_len);
		offset += cid_len;
	}

	/* Stateless reset token */
	memcpy(entry->stateless_reset_token, buf + offset,
	       TQUIC_STATELESS_RESET_TOKEN_LEN);
	offset += TQUIC_STATELESS_RESET_TOKEN_LEN;

	/* Initialize runtime state */
	entry->validated = false;
	entry->active = true;
	entry->priority = 0;
	entry->rtt_estimate = 0;
	entry->last_used = ktime_get();

	*consumed = offset;
	return 0;
}

/**
 * tquic_additional_addr_decode - Decode transport parameter
 */
int tquic_additional_addr_decode(const u8 *buf, size_t len,
				 struct tquic_additional_addresses *addrs)
{
	size_t offset = 0;
	int ret;
	u8 priority = 0;

	if (!buf || !addrs)
		return -EINVAL;

	/* Empty parameter is valid (no additional addresses) */
	if (len == 0)
		return 0;

	while (offset < len) {
		struct tquic_additional_address *entry;
		size_t consumed;

		/* Check capacity */
		if (addrs->count >= addrs->max_count) {
			pr_warn("tquic_additional_addr: too many addresses, truncating\n");
			break;
		}

		entry = kzalloc(sizeof(*entry), GFP_KERNEL);
		if (!entry)
			return -ENOMEM;

		INIT_LIST_HEAD(&entry->list);

		ret = decode_single_address(buf + offset, len - offset,
					    entry, &consumed);
		if (ret < 0) {
			kfree(entry);
			return ret;
		}

		/* Validate address */
		if (!tquic_additional_addr_is_valid(&entry->addr)) {
			pr_debug("tquic_additional_addr: decoded invalid address, skipping\n");
			kfree(entry);
			offset += consumed;
			continue;
		}

		entry->priority = priority++;

		/* Add to list */
		spin_lock_bh(&addrs->lock);
		list_add_tail(&entry->list, &addrs->addresses);
		addrs->count++;
		spin_unlock_bh(&addrs->lock);

		offset += consumed;
	}

	pr_debug("tquic_additional_addr: decoded %u addresses\n", addrs->count);
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_additional_addr_decode);

/*
 * =============================================================================
 * ADDRESS SELECTION AND VALIDATION
 * =============================================================================
 */

/**
 * tquic_additional_addr_select - Select best address for migration
 */
struct tquic_additional_address *tquic_additional_addr_select(
	struct tquic_additional_addresses *addrs,
	enum tquic_addr_select_policy policy,
	sa_family_t current_family)
{
	struct tquic_additional_address *entry, *best = NULL;
	u32 best_rtt = U32_MAX;
	u8 best_priority = U8_MAX;
	static u8 rr_index;

	if (!addrs || addrs->count == 0)
		return NULL;

	switch (policy) {
	case TQUIC_ADDR_SELECT_BEST_RTT:
		list_for_each_entry(entry, &addrs->addresses, list) {
			if (!entry->active || !entry->validated)
				continue;
			if (entry->rtt_estimate > 0 &&
			    entry->rtt_estimate < best_rtt) {
				best_rtt = entry->rtt_estimate;
				best = entry;
			}
		}
		/* Fall back to first validated if no RTT data */
		if (!best) {
			list_for_each_entry(entry, &addrs->addresses, list) {
				if (entry->active && entry->validated) {
					best = entry;
					break;
				}
			}
		}
		break;

	case TQUIC_ADDR_SELECT_SAME_FAMILY:
		/* First try same family */
		list_for_each_entry(entry, &addrs->addresses, list) {
			if (!entry->active)
				continue;
			if (entry->addr.ss_family == current_family) {
				best = entry;
				break;
			}
		}
		/* Fall back to any active address */
		if (!best) {
			list_for_each_entry(entry, &addrs->addresses, list) {
				if (entry->active) {
					best = entry;
					break;
				}
			}
		}
		break;

	case TQUIC_ADDR_SELECT_PRIORITY:
		list_for_each_entry(entry, &addrs->addresses, list) {
			if (!entry->active)
				continue;
			if (entry->priority < best_priority) {
				best_priority = entry->priority;
				best = entry;
			}
		}
		break;

	case TQUIC_ADDR_SELECT_ROUND_ROBIN:
		{
			u8 index = 0;
			u8 target = rr_index % addrs->count;

			list_for_each_entry(entry, &addrs->addresses, list) {
				if (!entry->active)
					continue;
				if (index == target) {
					best = entry;
					rr_index++;
					break;
				}
				index++;
			}
			/* Wrap around if needed */
			if (!best && addrs->count > 0) {
				rr_index = 0;
				list_for_each_entry(entry, &addrs->addresses, list) {
					if (entry->active) {
						best = entry;
						rr_index++;
						break;
					}
				}
			}
		}
		break;

	case TQUIC_ADDR_SELECT_RANDOM:
		{
			u8 target = get_random_u32() % addrs->count;
			u8 index = 0;

			list_for_each_entry(entry, &addrs->addresses, list) {
				if (!entry->active)
					continue;
				if (index == target) {
					best = entry;
					break;
				}
				index++;
			}
		}
		break;

	default:
		/* Default to priority-based selection */
		list_for_each_entry(entry, &addrs->addresses, list) {
			if (entry->active) {
				best = entry;
				break;
			}
		}
		break;
	}

	return best;
}
EXPORT_SYMBOL_GPL(tquic_additional_addr_select);

/**
 * tquic_additional_addr_validate - Mark address as validated
 */
void tquic_additional_addr_validate(struct tquic_additional_address *addr_entry)
{
	if (!addr_entry)
		return;

	addr_entry->validated = true;
	addr_entry->last_used = ktime_get();

	pr_debug("tquic_additional_addr: address validated\n");
}
EXPORT_SYMBOL_GPL(tquic_additional_addr_validate);

/**
 * tquic_additional_addr_invalidate - Mark address as invalid
 */
void tquic_additional_addr_invalidate(struct tquic_additional_address *addr_entry)
{
	if (!addr_entry)
		return;

	addr_entry->validated = false;
	addr_entry->active = false;

	pr_debug("tquic_additional_addr: address invalidated\n");
}
EXPORT_SYMBOL_GPL(tquic_additional_addr_invalidate);

/**
 * tquic_additional_addr_update_rtt - Update RTT estimate for address
 */
void tquic_additional_addr_update_rtt(struct tquic_additional_address *addr_entry,
				      u32 rtt_us)
{
	if (!addr_entry)
		return;

	/* Simple exponential smoothing */
	if (addr_entry->rtt_estimate == 0)
		addr_entry->rtt_estimate = rtt_us;
	else
		addr_entry->rtt_estimate =
			(addr_entry->rtt_estimate * 7 + rtt_us) / 8;
}
EXPORT_SYMBOL_GPL(tquic_additional_addr_update_rtt);

/**
 * tquic_additional_addr_set_priority - Set priority for an address
 */
void tquic_additional_addr_set_priority(struct tquic_additional_address *addr_entry,
					u8 priority)
{
	if (!addr_entry)
		return;

	addr_entry->priority = priority;
}
EXPORT_SYMBOL_GPL(tquic_additional_addr_set_priority);

/*
 * =============================================================================
 * ADDRESS VALIDATION HELPERS
 * =============================================================================
 */

/**
 * tquic_additional_addr_is_valid_ipv4 - Validate IPv4 address for migration
 */
bool tquic_additional_addr_is_valid_ipv4(const struct sockaddr_in *addr)
{
	__be32 ip;

	if (!addr || addr->sin_family != AF_INET)
		return false;

	ip = addr->sin_addr.s_addr;

	/* Unspecified (0.0.0.0) */
	if (ip == 0)
		return false;

	/* Loopback (127.0.0.0/8) */
	if ((ntohl(ip) >> 24) == 127)
		return false;

	/* Port must be non-zero */
	if (addr->sin_port == 0)
		return false;

	/* Multicast (224.0.0.0/4) */
	if ((ntohl(ip) >> 28) == 14)
		return false;

	/* Broadcast (255.255.255.255) */
	if (ip == htonl(INADDR_BROADCAST))
		return false;

	return true;
}
EXPORT_SYMBOL_GPL(tquic_additional_addr_is_valid_ipv4);

/**
 * tquic_additional_addr_is_valid_ipv6 - Validate IPv6 address for migration
 */
bool tquic_additional_addr_is_valid_ipv6(const struct sockaddr_in6 *addr)
{
	if (!addr || addr->sin6_family != AF_INET6)
		return false;

	/* Unspecified (::) */
	if (ipv6_addr_any(&addr->sin6_addr))
		return false;

	/* Loopback (::1) */
	if (ipv6_addr_loopback(&addr->sin6_addr))
		return false;

	/* Port must be non-zero */
	if (addr->sin6_port == 0)
		return false;

	/* Multicast */
	if (ipv6_addr_is_multicast(&addr->sin6_addr))
		return false;

	/* Link-local (fe80::/10) - typically not useful for WAN migration */
	if (ipv6_addr_type(&addr->sin6_addr) & IPV6_ADDR_LINKLOCAL)
		return false;

	return true;
}
EXPORT_SYMBOL_GPL(tquic_additional_addr_is_valid_ipv6);

/**
 * tquic_additional_addr_is_valid - Validate address for migration
 */
bool tquic_additional_addr_is_valid(const struct sockaddr_storage *addr)
{
	if (!addr)
		return false;

	if (addr->ss_family == AF_INET)
		return tquic_additional_addr_is_valid_ipv4(
			(const struct sockaddr_in *)addr);

#if IS_ENABLED(CONFIG_IPV6)
	if (addr->ss_family == AF_INET6)
		return tquic_additional_addr_is_valid_ipv6(
			(const struct sockaddr_in6 *)addr);
#endif

	return false;
}
EXPORT_SYMBOL_GPL(tquic_additional_addr_is_valid);

/*
 * =============================================================================
 * CONNECTION INTEGRATION
 * =============================================================================
 */

/**
 * tquic_additional_addr_conn_init - Initialize additional addresses for connection
 */
int tquic_additional_addr_conn_init(struct tquic_connection *conn)
{
	struct tquic_additional_addresses *local_addrs;
	struct tquic_additional_addresses *remote_addrs;

	if (!conn)
		return -EINVAL;

	/* Already initialized? */
	if (conn->additional_local_addrs)
		return 0;

	/* Allocate local addresses list */
	local_addrs = kzalloc(sizeof(*local_addrs), GFP_KERNEL);
	if (!local_addrs)
		return -ENOMEM;

	tquic_additional_addr_init(local_addrs);

	/* Allocate remote addresses list */
	remote_addrs = kzalloc(sizeof(*remote_addrs), GFP_KERNEL);
	if (!remote_addrs) {
		kfree(local_addrs);
		return -ENOMEM;
	}

	tquic_additional_addr_init(remote_addrs);

	conn->additional_local_addrs = local_addrs;
	conn->additional_remote_addrs = remote_addrs;

	pr_debug("tquic_additional_addr: initialized for connection\n");

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_additional_addr_conn_init);

/**
 * tquic_additional_addr_conn_cleanup - Clean up additional addresses
 */
void tquic_additional_addr_conn_cleanup(struct tquic_connection *conn)
{
	if (!conn)
		return;

	if (conn->additional_local_addrs) {
		tquic_additional_addr_cleanup(conn->additional_local_addrs);
		kfree(conn->additional_local_addrs);
		conn->additional_local_addrs = NULL;
	}

	if (conn->additional_remote_addrs) {
		tquic_additional_addr_cleanup(conn->additional_remote_addrs);
		kfree(conn->additional_remote_addrs);
		conn->additional_remote_addrs = NULL;
	}
}
EXPORT_SYMBOL_GPL(tquic_additional_addr_conn_cleanup);

/**
 * tquic_additional_addr_on_tp_received - Handle received transport parameter
 */
int tquic_additional_addr_on_tp_received(struct tquic_connection *conn,
					 const u8 *buf, size_t len)
{
	struct tquic_additional_addresses *remote_addrs;
	struct tquic_additional_address *entry;
	int ret;

	if (!conn || !buf)
		return -EINVAL;

	/* Initialize if needed */
	if (!conn->additional_remote_addrs) {
		ret = tquic_additional_addr_conn_init(conn);
		if (ret < 0)
			return ret;
	}

	remote_addrs = conn->additional_remote_addrs;

	/* Clear existing remote addresses */
	tquic_additional_addr_cleanup(remote_addrs);
	tquic_additional_addr_init(remote_addrs);

	/* Decode the parameter */
	ret = tquic_additional_addr_decode(buf, len, remote_addrs);
	if (ret < 0) {
		pr_warn("tquic_additional_addr: failed to decode parameter: %d\n",
			ret);
		return ret;
	}

	/*
	 * Register CIDs and reset tokens with the CID pool.
	 * This is critical for proper stateless reset detection.
	 * Use tquic_cid_add_remote() which works with struct tquic_connection
	 * and internally handles the cid_pool (struct tquic_cid_pool *).
	 */
	if (conn->cid_pool) {
		u64 seq_num = remote_addrs->seq_num_base;

		spin_lock_bh(&remote_addrs->lock);
		list_for_each_entry(entry, &remote_addrs->addresses, list) {
			ret = tquic_cid_add_remote(conn,
						   &entry->cid,
						   seq_num++,
						   0, /* retire_prior_to */
						   entry->stateless_reset_token);
			if (ret < 0) {
				pr_warn("tquic_additional_addr: failed to register CID: %d\n",
					ret);
				/* Continue despite error */
			}
		}
		spin_unlock_bh(&remote_addrs->lock);
	}

	pr_info("tquic_additional_addr: received %u additional addresses from peer\n",
		remote_addrs->count);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_additional_addr_on_tp_received);

/**
 * tquic_additional_addr_generate_tp - Generate transport parameter for sending
 */
ssize_t tquic_additional_addr_generate_tp(struct tquic_connection *conn,
					  u8 *buf, size_t buflen)
{
	struct tquic_additional_addresses *local_addrs;

	if (!conn || !buf)
		return -EINVAL;

	local_addrs = conn->additional_local_addrs;
	if (!local_addrs || local_addrs->count == 0)
		return 0;

	return tquic_additional_addr_encode(local_addrs, buf, buflen);
}
EXPORT_SYMBOL_GPL(tquic_additional_addr_generate_tp);

/*
 * =============================================================================
 * SYSCTL AND CONFIGURATION
 * =============================================================================
 */

/**
 * tquic_additional_addr_enabled - Check if additional addresses is enabled
 */
bool tquic_additional_addr_enabled(struct net *net)
{
	struct tquic_net *tn;

	if (net) {
		tn = tquic_pernet(net);
		if (tn && tn->additional_addresses_enabled >= 0)
			return tn->additional_addresses_enabled;
	}

	return tquic_sysctl_get_additional_addresses_enabled();
}
EXPORT_SYMBOL_GPL(tquic_additional_addr_enabled);

/**
 * tquic_additional_addr_get_max_count - Get max additional addresses limit
 */
u8 tquic_additional_addr_get_max_count(struct net *net)
{
	struct tquic_net *tn;

	if (net) {
		tn = tquic_pernet(net);
		if (tn && tn->additional_addresses_max > 0)
			return tn->additional_addresses_max;
	}

	return tquic_sysctl_get_additional_addresses_max();
}
EXPORT_SYMBOL_GPL(tquic_additional_addr_get_max_count);

/*
 * =============================================================================
 * MODULE INITIALIZATION
 * =============================================================================
 */

int __init tquic_additional_addr_module_init(void)
{
	pr_info("tquic_additional_addr: additional addresses extension initialized\n");
	return 0;
}

void __exit tquic_additional_addr_module_exit(void)
{
	pr_info("tquic_additional_addr: additional addresses extension cleaned up\n");
}

MODULE_DESCRIPTION("TQUIC Additional Addresses Transport Parameter Extension");
MODULE_LICENSE("GPL");
