// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC SmartNIC/FPGA Offload Implementation
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Provides hardware offload support for QUIC packet processing on SmartNICs
 * and FPGAs. This reduces CPU overhead and latency by moving packet
 * encryption/decryption, header parsing, and flow steering to hardware.
 *
 * Architecture:
 * - Device registration creates tquic_nic_device for each SmartNIC
 * - Connections can be associated with a device for offload
 * - TX path: encrypt packets in hardware before transmission
 * - RX path: decrypt packets in hardware, steer to correct CPU
 * - Key management syncs TLS keys with hardware key tables
 * - CID table enables hardware-based connection lookup
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/netdevice.h>
#include <linux/rhashtable.h>
#include <linux/jhash.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/workqueue.h>
#include <net/tquic.h>

#include "smartnic.h"
#include "../protocol.h"

/*
 * =============================================================================
 * Global State
 * =============================================================================
 */

/* List of registered SmartNIC devices */
static LIST_HEAD(tquic_nic_devices);
static DEFINE_SPINLOCK(tquic_nic_lock);

/* Workqueue for async offload operations */
static struct workqueue_struct *offload_wq;

/* Module initialized flag */
static bool smartnic_initialized;

/* Debug level (0=off, 1=errors, 2=info, 3=debug) */
static int debug_level = 1;
module_param(debug_level, int, 0644);
MODULE_PARM_DESC(debug_level, "SmartNIC offload debug level (0-3)");

/* Enable/disable offload globally */
static bool offload_enabled = true;
module_param(offload_enabled, bool, 0644);
MODULE_PARM_DESC(offload_enabled, "Enable SmartNIC QUIC offload");

#define NIC_DBG(level, fmt, ...) \
	do { \
		if (debug_level >= (level)) \
			pr_debug("tquic_nic: " fmt, ##__VA_ARGS__); \
	} while (0)

#define NIC_ERR(fmt, ...) pr_err("tquic_nic: " fmt, ##__VA_ARGS__)
#define NIC_INFO(fmt, ...) pr_info("tquic_nic: " fmt, ##__VA_ARGS__)

/*
 * =============================================================================
 * Packet Number Extraction
 * =============================================================================
 */

/**
 * tquic_skb_get_packet_number - Extract packet number from QUIC header
 * @skb: Socket buffer containing QUIC packet
 * @dcid_len: Length of Destination Connection ID (from connection state)
 *
 * Parses the QUIC short header to extract the packet number.
 * Returns 0 if extraction fails (caller should use fallback).
 */
static u64 tquic_skb_get_packet_number(struct sk_buff *skb, u8 dcid_len)
{
	unsigned char *data;
	u8 first_byte;
	int pn_len;
	u64 pn = 0;
	int offset;

	if (!skb || skb->len < 2)
		return 0;

	data = skb->data;
	first_byte = data[0];

	/* Check if short header (bit 7 = 0 for short header) */
	if (first_byte & 0x80) {
		/* Long header - packet number position varies */
		return 0;  /* Let caller use fallback */
	}

	/* Short header: PN length encoded in bits 0-1 */
	pn_len = (first_byte & 0x03) + 1;

	/* Skip DCID using actual connection ID length */
	offset = 1 + dcid_len;  /* 1 byte header + DCID */

	if (skb->len < offset + pn_len)
		return 0;

	/* Extract packet number (big-endian) */
	switch (pn_len) {
	case 1:
		pn = data[offset];
		break;
	case 2:
		pn = (data[offset] << 8) | data[offset + 1];
		break;
	case 4:
		pn = ((u32)data[offset] << 24) |
		     ((u32)data[offset + 1] << 16) |
		     ((u32)data[offset + 2] << 8) |
		     data[offset + 3];
		break;
	default:
		return 0;
	}

	return pn;
}

/*
 * =============================================================================
 * Device Registration
 * =============================================================================
 */

/**
 * tquic_nic_register - Register SmartNIC for QUIC offload
 */
struct tquic_nic_device *tquic_nic_register(struct net_device *netdev,
					    const struct tquic_nic_ops *ops,
					    u32 caps, void *priv)
{
	struct tquic_nic_device *dev;
	int ret;

	if (!netdev || !ops) {
		NIC_ERR("invalid registration params\n");
		return ERR_PTR(-EINVAL);
	}

	if (!smartnic_initialized) {
		NIC_ERR("module not initialized\n");
		return ERR_PTR(-ENODEV);
	}

	/* Check for required operations */
	if (caps & TQUIC_NIC_CAP_CRYPTO) {
		if (!ops->add_key || !ops->del_key) {
			NIC_ERR("crypto offload requires key ops\n");
			return ERR_PTR(-EINVAL);
		}
		if (!ops->encrypt || !ops->decrypt) {
			NIC_ERR("crypto offload requires encrypt/decrypt ops\n");
			return ERR_PTR(-EINVAL);
		}
	}

	if (caps & TQUIC_NIC_CAP_CID_LOOKUP) {
		if (!ops->add_cid || !ops->del_cid) {
			NIC_ERR("CID lookup requires CID ops\n");
			return ERR_PTR(-EINVAL);
		}
	}

	/* Check if already registered */
	spin_lock(&tquic_nic_lock);
	list_for_each_entry(dev, &tquic_nic_devices, list) {
		if (dev->netdev == netdev) {
			spin_unlock(&tquic_nic_lock);
			NIC_ERR("device %s already registered\n", netdev->name);
			return ERR_PTR(-EEXIST);
		}
	}
	spin_unlock(&tquic_nic_lock);

	/* Allocate device structure */
	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return ERR_PTR(-ENOMEM);

	dev->netdev = netdev;
	dev->ops = ops;
	dev->caps = caps;
	dev->priv = priv;
	spin_lock_init(&dev->lock);

	/* Set defaults */
	dev->ciphers = TQUIC_NIC_CIPHER_AES_128_GCM |
		       TQUIC_NIC_CIPHER_AES_256_GCM;
	dev->max_cids = 65536;
	dev->max_keys = 16384;
	dev->max_batch = 64;

	/* Initialize device */
	if (ops->init) {
		ret = ops->init(dev);
		if (ret) {
			NIC_ERR("device init failed: %d\n", ret);
			kfree(dev);
			return ERR_PTR(ret);
		}
	}

	/* Add to device list */
	spin_lock(&tquic_nic_lock);
	list_add_tail(&dev->list, &tquic_nic_devices);
	spin_unlock(&tquic_nic_lock);

	NIC_INFO("registered device %s (caps=0x%x)\n", netdev->name, caps);

	return dev;
}
EXPORT_SYMBOL_GPL(tquic_nic_register);

/**
 * tquic_nic_unregister - Unregister SmartNIC
 */
void tquic_nic_unregister(struct tquic_nic_device *dev)
{
	if (!dev)
		return;

	/* Remove from device list */
	spin_lock(&tquic_nic_lock);
	list_del(&dev->list);
	spin_unlock(&tquic_nic_lock);

	/* Cleanup device */
	if (dev->ops->cleanup)
		dev->ops->cleanup(dev);

	NIC_INFO("unregistered device %s\n", dev->netdev->name);

	kfree(dev);
}
EXPORT_SYMBOL_GPL(tquic_nic_unregister);

/**
 * tquic_nic_find - Find SmartNIC device by netdev
 */
struct tquic_nic_device *tquic_nic_find(struct net_device *netdev)
{
	struct tquic_nic_device *dev;

	if (!netdev)
		return NULL;

	spin_lock(&tquic_nic_lock);
	list_for_each_entry(dev, &tquic_nic_devices, list) {
		if (dev->netdev == netdev) {
			spin_unlock(&tquic_nic_lock);
			return dev;
		}
	}
	spin_unlock(&tquic_nic_lock);

	return NULL;
}
EXPORT_SYMBOL_GPL(tquic_nic_find);

/*
 * =============================================================================
 * Key Management
 * =============================================================================
 */

/**
 * tquic_offload_key_install - Install connection keys for offload
 */
int tquic_offload_key_install(struct tquic_nic_device *dev,
			      struct tquic_connection *conn)
{
	struct tquic_nic_key key;
	int ret;

	if (!dev || !conn)
		return -EINVAL;

	if (!tquic_nic_has_capability(dev, TQUIC_NIC_CAP_CRYPTO))
		return -EOPNOTSUPP;

	if (!dev->ops->add_key)
		return -EOPNOTSUPP;

	/* Extract key from connection's crypto state */
	memset(&key, 0, sizeof(key));

	/* Get write key (for TX encryption) */
	if (conn->crypto_state && conn->crypto_state->tx_secret) {
		memcpy(key.key, conn->crypto_state->tx_secret,
		       min_t(size_t, conn->crypto_state->key_len, sizeof(key.key)));
		key.key_len = conn->crypto_state->key_len;
		key.cipher_suite = conn->crypto_state->cipher_suite;
		atomic_set(&key.refcount, 1);

		spin_lock(&dev->lock);
		ret = dev->ops->add_key(dev, &key);
		spin_unlock(&dev->lock);

		if (ret < 0) {
			NIC_ERR("failed to add TX key: %d\n", ret);
			return ret;
		}

		conn->hw_tx_key_id = ret;
		atomic64_inc(&dev->stats.key_updates);
		NIC_DBG(2, "installed TX key %d for conn\n", ret);
	}

	/* Get read key (for RX decryption) - reset key struct first */
	if (conn->crypto_state && conn->crypto_state->rx_secret) {
		memset(&key, 0, sizeof(key));
		memcpy(key.key, conn->crypto_state->rx_secret,
		       min_t(size_t, conn->crypto_state->key_len, sizeof(key.key)));
		key.key_len = conn->crypto_state->key_len;
		key.cipher_suite = conn->crypto_state->cipher_suite;
		atomic_set(&key.refcount, 1);

		spin_lock(&dev->lock);
		ret = dev->ops->add_key(dev, &key);
		spin_unlock(&dev->lock);

		if (ret < 0) {
			NIC_ERR("failed to add RX key: %d\n", ret);
			return ret;
		}

		conn->hw_rx_key_id = ret;
		atomic64_inc(&dev->stats.key_updates);
		NIC_DBG(2, "installed RX key %d for conn\n", ret);
	}

	conn->hw_offload_enabled = true;
	conn->hw_offload_dev = dev;

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_offload_key_install);

/**
 * tquic_offload_key_update - Update connection keys (key rotation)
 */
int tquic_offload_key_update(struct tquic_nic_device *dev,
			     struct tquic_connection *conn)
{
	struct tquic_nic_key key;
	int ret;

	if (!dev || !conn)
		return -EINVAL;

	if (!tquic_nic_has_capability(dev, TQUIC_NIC_CAP_CRYPTO))
		return -EOPNOTSUPP;

	if (!dev->ops->update_key)
		return tquic_offload_key_install(dev, conn);

	/* Update TX key */
	if (conn->crypto_state && conn->crypto_state->tx_secret &&
	    conn->hw_tx_key_id != 0) {
		memset(&key, 0, sizeof(key));
		memcpy(key.key, conn->crypto_state->tx_secret,
		       min_t(size_t, conn->crypto_state->key_len, sizeof(key.key)));
		key.key_len = conn->crypto_state->key_len;
		key.cipher_suite = conn->crypto_state->cipher_suite;

		spin_lock(&dev->lock);
		ret = dev->ops->update_key(dev, conn->hw_tx_key_id, &key);
		spin_unlock(&dev->lock);

		if (ret < 0) {
			NIC_ERR("failed to update TX key: %d\n", ret);
			return ret;
		}

		atomic64_inc(&dev->stats.key_updates);
	}

	/* Update RX key */
	if (conn->crypto_state && conn->crypto_state->rx_secret &&
	    conn->hw_rx_key_id != 0) {
		memset(&key, 0, sizeof(key));
		memcpy(key.key, conn->crypto_state->rx_secret,
		       min_t(size_t, conn->crypto_state->key_len, sizeof(key.key)));
		key.key_len = conn->crypto_state->key_len;

		spin_lock(&dev->lock);
		ret = dev->ops->update_key(dev, conn->hw_rx_key_id, &key);
		spin_unlock(&dev->lock);

		if (ret < 0) {
			NIC_ERR("failed to update RX key: %d\n", ret);
			return ret;
		}

		atomic64_inc(&dev->stats.key_updates);
	}

	NIC_DBG(2, "updated keys for conn\n");
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_offload_key_update);

/*
 * =============================================================================
 * Connection ID Management
 * =============================================================================
 */

/**
 * tquic_offload_cid_add - Add connection ID for offload
 */
int tquic_offload_cid_add(struct tquic_nic_device *dev,
			  struct tquic_connection *conn,
			  const u8 *cid, u8 cid_len)
{
	struct tquic_nic_cid_entry entry;
	int ret;

	if (!dev || !conn || !cid || cid_len == 0)
		return -EINVAL;

	if (!tquic_nic_has_capability(dev, TQUIC_NIC_CAP_CID_LOOKUP))
		return -EOPNOTSUPP;

	if (!dev->ops->add_cid)
		return -EOPNOTSUPP;

	memset(&entry, 0, sizeof(entry));
	memcpy(entry.cid, cid, min_t(size_t, cid_len, sizeof(entry.cid)));
	entry.cid_len = cid_len;
	entry.conn_id = conn->conn_id;
	entry.key_id = conn->hw_rx_key_id;
	entry.queue_id = conn->cpu_affinity % dev->netdev->real_num_rx_queues;

	spin_lock(&dev->lock);
	ret = dev->ops->add_cid(dev, &entry);
	spin_unlock(&dev->lock);

	if (ret < 0) {
		NIC_ERR("failed to add CID: %d\n", ret);
		return ret;
	}

	/* Configure flow steering if supported */
	if (tquic_nic_has_capability(dev, TQUIC_NIC_CAP_FLOW_STEER) &&
	    dev->ops->set_flow_steer) {
		spin_lock(&dev->lock);
		ret = dev->ops->set_flow_steer(dev, cid, cid_len, entry.queue_id);
		spin_unlock(&dev->lock);

		if (ret == 0)
			atomic64_inc(&dev->stats.flow_steer_ok);
	}

	NIC_DBG(2, "added CID for conn (queue=%d)\n", entry.queue_id);
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_offload_cid_add);

/**
 * tquic_offload_cid_del - Remove connection ID from offload
 */
int tquic_offload_cid_del(struct tquic_nic_device *dev,
			  const u8 *cid, u8 cid_len)
{
	int ret;

	if (!dev || !cid || cid_len == 0)
		return -EINVAL;

	if (!tquic_nic_has_capability(dev, TQUIC_NIC_CAP_CID_LOOKUP))
		return -EOPNOTSUPP;

	if (!dev->ops->del_cid)
		return -EOPNOTSUPP;

	spin_lock(&dev->lock);
	ret = dev->ops->del_cid(dev, cid, cid_len);
	spin_unlock(&dev->lock);

	if (ret < 0) {
		NIC_ERR("failed to delete CID: %d\n", ret);
		return ret;
	}

	NIC_DBG(2, "deleted CID\n");
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_offload_cid_del);

/*
 * =============================================================================
 * Packet Processing
 * =============================================================================
 */

/**
 * tquic_offload_rx - Process received packet with offload
 */
int tquic_offload_rx(struct tquic_nic_device *dev, struct sk_buff *skb,
		     struct tquic_connection *conn)
{
	u64 pn;
	int ret;

	if (!offload_enabled)
		return 1;  /* Fallback to software */

	if (!dev || !skb || !conn)
		return -EINVAL;

	if (!conn->hw_offload_enabled || conn->hw_offload_dev != dev) {
		atomic64_inc(&dev->stats.fallback_sw);
		return 1;  /* Fallback to software */
	}

	if (!tquic_nic_has_capability(dev, TQUIC_NIC_CAP_AEAD_DECRYPT)) {
		atomic64_inc(&dev->stats.fallback_sw);
		return 1;
	}

	/* Extract packet number from QUIC header using connection's DCID length */
	pn = tquic_skb_get_packet_number(skb, conn->dcid_len);
	if (pn == 0) {
		/* Fallback if we can't extract PN from header */
		pn = conn->rx_pn_next;
	}

	spin_lock(&dev->lock);
	ret = dev->ops->decrypt(dev, skb, conn->hw_rx_key_id, pn);
	spin_unlock(&dev->lock);

	if (ret < 0) {
		atomic64_inc(&dev->stats.decrypt_fail);
		atomic64_inc(&dev->stats.fallback_sw);
		NIC_DBG(1, "HW decrypt failed: %d, falling back\n", ret);
		return 1;  /* Fallback to software */
	}

	atomic64_inc(&dev->stats.decrypt_success);
	atomic64_inc(&dev->stats.rx_offloaded);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_offload_rx);

/**
 * tquic_offload_tx - Transmit packet with offload
 */
int tquic_offload_tx(struct tquic_nic_device *dev, struct sk_buff *skb,
		     struct tquic_connection *conn)
{
	u64 pn;
	int ret;

	if (!offload_enabled)
		return -EOPNOTSUPP;

	if (!dev || !skb || !conn)
		return -EINVAL;

	if (!conn->hw_offload_enabled || conn->hw_offload_dev != dev)
		return -EOPNOTSUPP;

	if (!tquic_nic_has_capability(dev, TQUIC_NIC_CAP_AEAD_ENCRYPT))
		return -EOPNOTSUPP;

	/* Get packet number for encryption */
	pn = conn->tx_pn_next;

	spin_lock(&dev->lock);
	ret = dev->ops->encrypt(dev, skb, conn->hw_tx_key_id, pn);
	spin_unlock(&dev->lock);

	if (ret < 0) {
		atomic64_inc(&dev->stats.encrypt_fail);
		NIC_DBG(1, "HW encrypt failed: %d\n", ret);
		return ret;
	}

	atomic64_inc(&dev->stats.encrypt_success);
	atomic64_inc(&dev->stats.tx_offloaded);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_offload_tx);

/*
 * =============================================================================
 * Batch Processing
 * =============================================================================
 */

/**
 * tquic_offload_batch_rx - Batch process received packets
 */
int tquic_offload_batch_rx(struct tquic_nic_device *dev,
			   struct sk_buff **skbs, int count,
			   struct tquic_connection *conn)
{
	u64 *pns;
	int ret, i;

	if (!offload_enabled || !dev || !skbs || count <= 0 || !conn)
		return -EINVAL;

	if (!conn->hw_offload_enabled)
		return -EOPNOTSUPP;

	if (!tquic_nic_has_capability(dev, TQUIC_NIC_CAP_BATCH_PROCESS) ||
	    !dev->ops->batch_decrypt)
		return -EOPNOTSUPP;

	/* Allocate packet number array */
	pns = kmalloc_array(count, sizeof(u64), GFP_ATOMIC);
	if (!pns)
		return -ENOMEM;

	/* Extract packet numbers from QUIC headers using connection's DCID length */
	for (i = 0; i < count; i++) {
		pns[i] = tquic_skb_get_packet_number(skbs[i], conn->dcid_len);
		if (pns[i] == 0)
			pns[i] = conn->rx_pn_next + i;  /* Fallback */
	}

	spin_lock(&dev->lock);
	ret = dev->ops->batch_decrypt(dev, skbs, count,
				      conn->hw_rx_key_id, pns);
	spin_unlock(&dev->lock);

	kfree(pns);

	if (ret > 0) {
		atomic64_add(ret, &dev->stats.decrypt_success);
		atomic64_add(ret, &dev->stats.rx_offloaded);
		atomic64_inc(&dev->stats.batch_ops);
	}
	if (ret < count)
		atomic64_add(count - ret, &dev->stats.decrypt_fail);

	return ret;
}
EXPORT_SYMBOL_GPL(tquic_offload_batch_rx);

/**
 * tquic_offload_batch_tx - Batch process transmit packets
 */
int tquic_offload_batch_tx(struct tquic_nic_device *dev,
			   struct sk_buff **skbs, int count,
			   struct tquic_connection *conn)
{
	u64 *pns;
	int ret, i;

	if (!offload_enabled || !dev || !skbs || count <= 0 || !conn)
		return -EINVAL;

	if (!conn->hw_offload_enabled)
		return -EOPNOTSUPP;

	if (!tquic_nic_has_capability(dev, TQUIC_NIC_CAP_BATCH_PROCESS) ||
	    !dev->ops->batch_encrypt)
		return -EOPNOTSUPP;

	/* Allocate packet number array */
	pns = kmalloc_array(count, sizeof(u64), GFP_ATOMIC);
	if (!pns)
		return -ENOMEM;

	/* Assign packet numbers */
	for (i = 0; i < count; i++)
		pns[i] = conn->tx_pn_next++;

	spin_lock(&dev->lock);
	ret = dev->ops->batch_encrypt(dev, skbs, count,
				      conn->hw_tx_key_id, pns);
	spin_unlock(&dev->lock);

	kfree(pns);

	if (ret > 0) {
		atomic64_add(ret, &dev->stats.encrypt_success);
		atomic64_add(ret, &dev->stats.tx_offloaded);
		atomic64_inc(&dev->stats.batch_ops);
	}
	if (ret < count)
		atomic64_add(count - ret, &dev->stats.encrypt_fail);

	return ret;
}
EXPORT_SYMBOL_GPL(tquic_offload_batch_tx);

/*
 * =============================================================================
 * Proc Filesystem Interface
 * =============================================================================
 */

static int tquic_nic_stats_show(struct seq_file *m, void *v)
{
	struct tquic_nic_device *dev;

	seq_puts(m, "TQUIC SmartNIC Offload Statistics\n");
	seq_puts(m, "==================================\n\n");

	spin_lock(&tquic_nic_lock);
	list_for_each_entry(dev, &tquic_nic_devices, list) {
		seq_printf(m, "Device: %s\n", dev->netdev->name);
		seq_printf(m, "  Capabilities: 0x%x\n", dev->caps);
		seq_printf(m, "  RX Offloaded:     %llu\n",
			   atomic64_read(&dev->stats.rx_offloaded));
		seq_printf(m, "  TX Offloaded:     %llu\n",
			   atomic64_read(&dev->stats.tx_offloaded));
		seq_printf(m, "  Decrypt Success:  %llu\n",
			   atomic64_read(&dev->stats.decrypt_success));
		seq_printf(m, "  Decrypt Fail:     %llu\n",
			   atomic64_read(&dev->stats.decrypt_fail));
		seq_printf(m, "  Encrypt Success:  %llu\n",
			   atomic64_read(&dev->stats.encrypt_success));
		seq_printf(m, "  Encrypt Fail:     %llu\n",
			   atomic64_read(&dev->stats.encrypt_fail));
		seq_printf(m, "  CID Lookup Hit:   %llu\n",
			   atomic64_read(&dev->stats.cid_lookup_hit));
		seq_printf(m, "  CID Lookup Miss:  %llu\n",
			   atomic64_read(&dev->stats.cid_lookup_miss));
		seq_printf(m, "  Flow Steer OK:    %llu\n",
			   atomic64_read(&dev->stats.flow_steer_ok));
		seq_printf(m, "  Fallback SW:      %llu\n",
			   atomic64_read(&dev->stats.fallback_sw));
		seq_printf(m, "  Key Updates:      %llu\n",
			   atomic64_read(&dev->stats.key_updates));
		seq_printf(m, "  Batch Operations: %llu\n",
			   atomic64_read(&dev->stats.batch_ops));
		seq_puts(m, "\n");
	}
	spin_unlock(&tquic_nic_lock);

	if (list_empty(&tquic_nic_devices))
		seq_puts(m, "No SmartNIC devices registered\n");

	return 0;
}

static int tquic_nic_stats_open(struct inode *inode, struct file *file)
{
	return single_open(file, tquic_nic_stats_show, NULL);
}

static const struct proc_ops tquic_nic_stats_ops = {
	.proc_open = tquic_nic_stats_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
};

/*
 * =============================================================================
 * Module Init/Exit
 * =============================================================================
 */

int tquic_smartnic_init(void)
{
	struct proc_dir_entry *proc_entry;

	if (smartnic_initialized)
		return 0;

	/* Create workqueue for async operations */
	offload_wq = alloc_workqueue("tquic_offload", WQ_HIGHPRI | WQ_UNBOUND, 0);
	if (!offload_wq) {
		NIC_ERR("failed to create workqueue\n");
		return -ENOMEM;
	}

	/* Create proc entry for statistics */
	proc_entry = proc_create("tquic_smartnic", 0444, NULL,
				 &tquic_nic_stats_ops);
	if (!proc_entry)
		NIC_INFO("failed to create proc entry (non-fatal)\n");

	smartnic_initialized = true;
	NIC_INFO("SmartNIC offload subsystem initialized\n");

	return 0;
}

void tquic_smartnic_exit(void)
{
	struct tquic_nic_device *dev, *tmp;

	if (!smartnic_initialized)
		return;

	/* Remove proc entry */
	remove_proc_entry("tquic_smartnic", NULL);

	/* Unregister all devices */
	spin_lock(&tquic_nic_lock);
	list_for_each_entry_safe(dev, tmp, &tquic_nic_devices, list) {
		list_del(&dev->list);
		if (dev->ops->cleanup)
			dev->ops->cleanup(dev);
		kfree(dev);
	}
	spin_unlock(&tquic_nic_lock);

	/* Destroy workqueue */
	if (offload_wq) {
		destroy_workqueue(offload_wq);
		offload_wq = NULL;
	}

	smartnic_initialized = false;
	NIC_INFO("SmartNIC offload subsystem shutdown\n");
}

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("TQUIC SmartNIC/FPGA Offload Support");
MODULE_AUTHOR("Linux Foundation");
