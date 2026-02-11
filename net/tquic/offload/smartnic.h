/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC SmartNIC/FPGA Offload Interface
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * This header defines the interface for offloading QUIC packet processing
 * to SmartNICs and FPGAs. Supported operations include:
 * - Header parsing and validation
 * - Packet number decoding
 * - AEAD encryption/decryption
 * - Connection ID lookup
 * - Flow steering
 *
 * SmartNIC offload reduces CPU overhead and latency by moving
 * computationally intensive QUIC operations to dedicated hardware.
 */

#ifndef _TQUIC_SMARTNIC_H
#define _TQUIC_SMARTNIC_H

#include <linux/types.h>
#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/list.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <linux/atomic.h>
#include <linux/refcount.h>

/*
 * =============================================================================
 * Feature Capabilities
 * =============================================================================
 */

/* SmartNIC capability flags */
#define TQUIC_NIC_CAP_HEADER_PARSE	BIT(0)	/* Header parsing */
#define TQUIC_NIC_CAP_PN_DECODE		BIT(1)	/* Packet number decoding */
#define TQUIC_NIC_CAP_AEAD_ENCRYPT	BIT(2)	/* AEAD encryption */
#define TQUIC_NIC_CAP_AEAD_DECRYPT	BIT(3)	/* AEAD decryption */
#define TQUIC_NIC_CAP_CID_LOOKUP	BIT(4)	/* Connection ID lookup */
#define TQUIC_NIC_CAP_FLOW_STEER	BIT(5)	/* Flow steering to queues */
#define TQUIC_NIC_CAP_RETX_ACCEL	BIT(6)	/* Retransmission acceleration */
#define TQUIC_NIC_CAP_CONG_FEEDBACK	BIT(7)	/* Congestion feedback */
#define TQUIC_NIC_CAP_BATCH_PROCESS	BIT(8)	/* Batch packet processing */
#define TQUIC_NIC_CAP_ZERO_COPY		BIT(9)	/* Zero-copy transfers */
#define TQUIC_NIC_CAP_TSO		BIT(10)	/* Transmit segmentation offload */
#define TQUIC_NIC_CAP_LRO		BIT(11)	/* Large receive offload */
#define TQUIC_NIC_CAP_TIMESTAMP		BIT(12)	/* Hardware timestamps */

/* Combined capability sets */
#define TQUIC_NIC_CAP_CRYPTO \
	(TQUIC_NIC_CAP_AEAD_ENCRYPT | TQUIC_NIC_CAP_AEAD_DECRYPT)

#define TQUIC_NIC_CAP_FULL_OFFLOAD \
	(TQUIC_NIC_CAP_HEADER_PARSE | TQUIC_NIC_CAP_PN_DECODE | \
	 TQUIC_NIC_CAP_CRYPTO | TQUIC_NIC_CAP_CID_LOOKUP | \
	 TQUIC_NIC_CAP_FLOW_STEER)

/* Supported cipher suites for offload */
#define TQUIC_NIC_CIPHER_AES_128_GCM	BIT(0)
#define TQUIC_NIC_CIPHER_AES_256_GCM	BIT(1)
#define TQUIC_NIC_CIPHER_CHACHA20_POLY	BIT(2)

/*
 * =============================================================================
 * Offload State Structures
 * =============================================================================
 */

/**
 * struct tquic_nic_key - Encryption key for hardware offload
 * @key:          Key material
 * @key_len:      Key length in bytes
 * @iv:           Initialization vector / nonce base
 * @iv_len:       IV length
 * @cipher_suite: TLS cipher suite identifier
 * @hw_key_id:    Hardware key table index
 * @refcount:     Reference count
 */
struct tquic_nic_key {
	u8 key[32];
	u8 key_len;
	u8 iv[12];
	u8 iv_len;
	u16 cipher_suite;
	u32 hw_key_id;
	atomic_t refcount;
};

/**
 * struct tquic_nic_cid_entry - Connection ID table entry
 * @cid:          Connection ID bytes
 * @cid_len:      Connection ID length
 * @conn_id:      Internal connection identifier
 * @key_id:       Associated key table index
 * @queue_id:     Target RX queue for flow steering
 * @flags:        Entry flags
 */
struct tquic_nic_cid_entry {
	u8 cid[20];
	u8 cid_len;
	u32 conn_id;
	u32 key_id;
	u16 queue_id;
	u16 flags;
};

/**
 * struct tquic_nic_stats - Per-device offload statistics
 * @rx_offloaded:       Packets received with offload
 * @tx_offloaded:       Packets transmitted with offload
 * @decrypt_success:    Successful decryptions
 * @decrypt_fail:       Failed decryptions
 * @encrypt_success:    Successful encryptions
 * @encrypt_fail:       Failed encryptions
 * @cid_lookup_hit:     CID lookup hits
 * @cid_lookup_miss:    CID lookup misses
 * @flow_steer_ok:      Successful flow steering
 * @fallback_sw:        Packets falling back to software
 * @key_updates:        Key update operations
 * @batch_ops:          Batch processing operations
 */
struct tquic_nic_stats {
	atomic64_t rx_offloaded;
	atomic64_t tx_offloaded;
	atomic64_t decrypt_success;
	atomic64_t decrypt_fail;
	atomic64_t encrypt_success;
	atomic64_t encrypt_fail;
	atomic64_t cid_lookup_hit;
	atomic64_t cid_lookup_miss;
	atomic64_t flow_steer_ok;
	atomic64_t fallback_sw;
	atomic64_t key_updates;
	atomic64_t batch_ops;
};

/**
 * struct tquic_nic_device - SmartNIC device state
 * @list:            List linkage for registered devices
 * @netdev:          Associated network device
 * @ops:             Device operations
 * @caps:            Device capabilities
 * @ciphers:         Supported cipher suites
 * @max_cids:        Maximum CID table entries
 * @max_keys:        Maximum key table entries
 * @max_batch:       Maximum batch size
 * @stats:           Device statistics
 * @lock:            Device lock
 * @priv:            Driver private data
 */
struct tquic_nic_device {
	struct list_head list;
	struct net_device *netdev;
	const struct tquic_nic_ops *ops;
	u32 caps;
	u32 ciphers;
	u32 max_cids;
	u32 max_keys;
	u32 max_batch;
	struct tquic_nic_stats stats;
	spinlock_t lock;
	refcount_t refcnt;	/* SECURITY FIX (CF-084): reference counting */
	bool dead;		/* Set during unregister to prevent new ops */
	bool registered;	/* SECURITY FIX (C-004): track registration */
	struct completion unregister_done; /* Wait for refs to drain */
	void *priv;
};

/*
 * =============================================================================
 * Offload Operations Interface
 * =============================================================================
 */

/**
 * struct tquic_nic_ops - SmartNIC device operations
 *
 * These operations are implemented by SmartNIC/FPGA drivers to provide
 * hardware-accelerated QUIC packet processing.
 */
struct tquic_nic_ops {
	/**
	 * @init: Initialize device for QUIC offload
	 * @dev: SmartNIC device
	 *
	 * Called when QUIC offload is enabled on the device.
	 * Returns: 0 on success, negative errno on failure
	 */
	int (*init)(struct tquic_nic_device *dev);

	/**
	 * @cleanup: Cleanup device offload state
	 * @dev: SmartNIC device
	 *
	 * Called when QUIC offload is disabled.
	 */
	void (*cleanup)(struct tquic_nic_device *dev);

	/**
	 * @add_key: Add encryption key to hardware
	 * @dev: SmartNIC device
	 * @key: Key structure
	 *
	 * Programs a key into the hardware key table.
	 * Returns: Hardware key ID on success, negative errno on failure
	 */
	int (*add_key)(struct tquic_nic_device *dev,
		       struct tquic_nic_key *key);

	/**
	 * @del_key: Remove encryption key from hardware
	 * @dev: SmartNIC device
	 * @hw_key_id: Hardware key ID
	 *
	 * Removes a key from the hardware key table.
	 * Returns: 0 on success, negative errno on failure
	 */
	int (*del_key)(struct tquic_nic_device *dev, u32 hw_key_id);

	/**
	 * @update_key: Update encryption key (key rotation)
	 * @dev: SmartNIC device
	 * @hw_key_id: Hardware key ID
	 * @key: New key material
	 *
	 * Returns: 0 on success, negative errno on failure
	 */
	int (*update_key)(struct tquic_nic_device *dev, u32 hw_key_id,
			  struct tquic_nic_key *key);

	/**
	 * @add_cid: Add connection ID to lookup table
	 * @dev: SmartNIC device
	 * @entry: CID entry
	 *
	 * Programs a CID entry for hardware lookup and flow steering.
	 * Returns: 0 on success, negative errno on failure
	 */
	int (*add_cid)(struct tquic_nic_device *dev,
		       struct tquic_nic_cid_entry *entry);

	/**
	 * @del_cid: Remove connection ID from lookup table
	 * @dev: SmartNIC device
	 * @cid: Connection ID bytes
	 * @cid_len: Connection ID length
	 *
	 * Returns: 0 on success, negative errno on failure
	 */
	int (*del_cid)(struct tquic_nic_device *dev,
		       const u8 *cid, u8 cid_len);

	/**
	 * @encrypt: Hardware encrypt packet
	 * @dev: SmartNIC device
	 * @skb: Packet to encrypt (payload modified in place)
	 * @hw_key_id: Hardware key ID
	 * @pn: Packet number for nonce
	 *
	 * Returns: 0 on success, negative errno on failure
	 */
	int (*encrypt)(struct tquic_nic_device *dev, struct sk_buff *skb,
		       u32 hw_key_id, u64 pn);

	/**
	 * @decrypt: Hardware decrypt packet
	 * @dev: SmartNIC device
	 * @skb: Packet to decrypt (payload modified in place)
	 * @hw_key_id: Hardware key ID
	 * @pn: Packet number for nonce
	 *
	 * Returns: 0 on success, negative errno on failure
	 */
	int (*decrypt)(struct tquic_nic_device *dev, struct sk_buff *skb,
		       u32 hw_key_id, u64 pn);

	/**
	 * @batch_encrypt: Batch encrypt multiple packets
	 * @dev: SmartNIC device
	 * @skbs: Array of packets
	 * @count: Number of packets
	 * @hw_key_id: Hardware key ID
	 * @pns: Array of packet numbers
	 *
	 * Returns: Number of successfully encrypted packets
	 */
	int (*batch_encrypt)(struct tquic_nic_device *dev,
			     struct sk_buff **skbs, int count,
			     u32 hw_key_id, u64 *pns);

	/**
	 * @batch_decrypt: Batch decrypt multiple packets
	 * @dev: SmartNIC device
	 * @skbs: Array of packets
	 * @count: Number of packets
	 * @hw_key_id: Hardware key ID
	 * @pns: Array of packet numbers
	 *
	 * Returns: Number of successfully decrypted packets
	 */
	int (*batch_decrypt)(struct tquic_nic_device *dev,
			     struct sk_buff **skbs, int count,
			     u32 hw_key_id, u64 *pns);

	/**
	 * @set_flow_steer: Configure flow steering rule
	 * @dev: SmartNIC device
	 * @cid: Connection ID
	 * @cid_len: CID length
	 * @queue_id: Target RX queue
	 *
	 * Returns: 0 on success, negative errno on failure
	 */
	int (*set_flow_steer)(struct tquic_nic_device *dev,
			      const u8 *cid, u8 cid_len, u16 queue_id);

	/**
	 * @get_stats: Get device statistics
	 * @dev: SmartNIC device
	 * @stats: Statistics output
	 */
	void (*get_stats)(struct tquic_nic_device *dev,
			  struct tquic_nic_stats *stats);

	/**
	 * @reset_stats: Reset device statistics
	 * @dev: SmartNIC device
	 */
	void (*reset_stats)(struct tquic_nic_device *dev);
};

/*
 * =============================================================================
 * Offload Request Structures (for async operations)
 * =============================================================================
 */

/**
 * enum tquic_nic_req_type - Offload request types
 */
enum tquic_nic_req_type {
	TQUIC_NIC_REQ_ENCRYPT,
	TQUIC_NIC_REQ_DECRYPT,
	TQUIC_NIC_REQ_ADD_KEY,
	TQUIC_NIC_REQ_DEL_KEY,
	TQUIC_NIC_REQ_ADD_CID,
	TQUIC_NIC_REQ_DEL_CID,
};

/**
 * struct tquic_nic_request - Async offload request
 * @type:         Request type
 * @dev:          Target device
 * @skb:          Packet (for encrypt/decrypt)
 * @key:          Key data (for key ops)
 * @cid_entry:    CID entry (for CID ops)
 * @hw_key_id:    Hardware key ID
 * @pn:           Packet number
 * @callback:     Completion callback
 * @callback_data: Callback data
 * @result:       Operation result
 * @list:         Request queue linkage
 */
struct tquic_nic_request {
	enum tquic_nic_req_type type;
	struct tquic_nic_device *dev;
	struct sk_buff *skb;
	struct tquic_nic_key *key;
	struct tquic_nic_cid_entry *cid_entry;
	u32 hw_key_id;
	u64 pn;
	void (*callback)(struct tquic_nic_request *req, int result);
	void *callback_data;
	int result;
	struct list_head list;
};

/*
 * =============================================================================
 * Registration and Lookup API
 * =============================================================================
 */

/**
 * tquic_nic_register - Register SmartNIC for QUIC offload
 * @netdev: Network device
 * @ops: Device operations
 * @caps: Device capabilities
 * @priv: Driver private data
 *
 * Returns: Pointer to tquic_nic_device on success, ERR_PTR on failure
 */
struct tquic_nic_device *tquic_nic_register(struct net_device *netdev,
					    const struct tquic_nic_ops *ops,
					    u32 caps, void *priv);

/**
 * tquic_nic_unregister - Unregister SmartNIC
 * @dev: SmartNIC device
 */
void tquic_nic_unregister(struct tquic_nic_device *dev);

/**
 * tquic_nic_find - Find SmartNIC device by netdev
 * @netdev: Network device
 *
 * Returns: tquic_nic_device or NULL if not found
 */
struct tquic_nic_device *tquic_nic_find(struct net_device *netdev);

/**
 * tquic_nic_has_capability - Check if device has capability
 * @dev: SmartNIC device
 * @cap: Capability flag
 *
 * Returns: true if device has capability
 */
static inline bool tquic_nic_has_capability(struct tquic_nic_device *dev,
					    u32 cap)
{
	return dev && (dev->caps & cap);
}

/*
 * =============================================================================
 * High-Level Offload API
 * =============================================================================
 */

/**
 * tquic_offload_rx - Process received packet with offload
 * @dev: SmartNIC device
 * @skb: Received packet
 * @conn: Connection (for key lookup)
 *
 * Returns: 0 if offload handled, >0 if software fallback needed,
 *          negative errno on error
 */
int tquic_offload_rx(struct tquic_nic_device *dev, struct sk_buff *skb,
		     struct tquic_connection *conn);

/**
 * tquic_offload_tx - Transmit packet with offload
 * @dev: SmartNIC device
 * @skb: Packet to transmit
 * @conn: Connection (for key lookup)
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_offload_tx(struct tquic_nic_device *dev, struct sk_buff *skb,
		     struct tquic_connection *conn);

/**
 * tquic_offload_key_install - Install connection keys for offload
 * @dev: SmartNIC device
 * @conn: Connection with keys to install
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_offload_key_install(struct tquic_nic_device *dev,
			      struct tquic_connection *conn);

/**
 * tquic_offload_key_update - Update connection keys (key rotation)
 * @dev: SmartNIC device
 * @conn: Connection with new keys
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_offload_key_update(struct tquic_nic_device *dev,
			     struct tquic_connection *conn);

/**
 * tquic_offload_cid_add - Add connection ID for offload
 * @dev: SmartNIC device
 * @conn: Connection
 * @cid: Connection ID
 * @cid_len: CID length
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_offload_cid_add(struct tquic_nic_device *dev,
			  struct tquic_connection *conn,
			  const u8 *cid, u8 cid_len);

/**
 * tquic_offload_cid_del - Remove connection ID from offload
 * @dev: SmartNIC device
 * @cid: Connection ID
 * @cid_len: CID length
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_offload_cid_del(struct tquic_nic_device *dev,
			  const u8 *cid, u8 cid_len);

/*
 * =============================================================================
 * Module Init/Exit
 * =============================================================================
 */

int tquic_smartnic_init(void);
void tquic_smartnic_exit(void);

#endif /* _TQUIC_SMARTNIC_H */
