// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * QUIC - Quick UDP Internet Connections
 *
 * Hardware offload support for QUIC protocol
 * - GSO (Generic Segmentation Offload)
 * - GRO (Generic Receive Offload)
 * - Crypto offload hooks for NIC-based encryption/decryption
 * - UDP encapsulation handling
 *
 * Copyright (c) 2024 Linux QUIC Authors
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/socket.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/indirect_call_wrapper.h>
#include <net/gro.h>
#include <net/gso.h>
#include <net/protocol.h>
#include <net/udp.h>
#include <net/udp_tunnel.h>
#include <net/inet_common.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/checksum.h>
#include <net/tquic.h>
#include <net/ip6_checksum.h>
#include <crypto/aead.h>
#include "tquic_compat.h"
#include "tquic_cid.h"

/* QUIC GSO type flag for skb_shared_info */
#define SKB_GSO_QUIC	SKB_GSO_UDP_L4

/*
 * QUIC offload operations structure
 * Used for optional hardware crypto offload hooks
 */
struct tquic_offload_ops {
	int (*encrypt)(struct sk_buff *skb, void *ctx);
	int (*decrypt)(struct sk_buff *skb, void *ctx);
	struct sk_buff *(*gso_segment)(struct sk_buff *skb, netdev_features_t features);
	struct sk_buff *(*gro_receive)(struct list_head *head, struct sk_buff *skb);
	int (*gro_complete)(struct sk_buff *skb, int nhoff);
};

/*
 * Backlog receive handler for deferred packet processing
 */
static inline int tquic_backlog_rcv(struct sock *sk, struct sk_buff *skb)
{
	/* Process packet from backlog - pass to socket receive queue */
	return sock_queue_rcv_skb(sk, skb);
}

/* QUIC header constants */
#define QUIC_HEADER_FORM_LONG	0x80
#define QUIC_HEADER_FORM_SHORT	0x00
#define QUIC_FIXED_BIT		0x40
#define QUIC_LONG_TYPE_MASK	0x30
#define QUIC_SHORT_KEY_PHASE	0x04
#define QUIC_SHORT_PN_LEN_MASK	0x03

/* QUIC packet types in long header */
#define QUIC_PKT_INITIAL	0x00
#define QUIC_PKT_0RTT		0x10
#define QUIC_PKT_HANDSHAKE	0x20
#define QUIC_PKT_RETRY		0x30

/* Local aliases for QUIC constants (map to TQUIC_* from header) */
#define QUIC_MAX_CONNECTION_ID_LEN	TQUIC_MAX_CID_LEN
#define QUIC_CRYPTO_INITIAL		TQUIC_CRYPTO_INITIAL
#define QUIC_CRYPTO_HANDSHAKE		TQUIC_CRYPTO_HANDSHAKE
#define QUIC_CRYPTO_APPLICATION		TQUIC_CRYPTO_APPLICATION
#define QUIC_CRYPTO_EARLY_DATA		1  /* Between INITIAL and HANDSHAKE */

/* Maximum number of segments in a GSO batch */
#define QUIC_GSO_MAX_SEGS	64

/* GRO flow aggregation limits */
#define QUIC_GRO_MAX_CNT	64
#define TQUIC_GRO_MAX_SIZE	65535

/* QUIC offload control block in skb->cb */
struct tquic_offload_cb {
	u64	pn;			/* Packet number */
	u32	header_len;		/* Header length including PN */
	u32	payload_len;		/* Payload length */
	u16	gso_size;		/* GSO segment size */
	u8	pn_len;			/* Packet number length */
	u8	dcid_len;		/* Destination CID length */
	u8	scid_len;		/* Source CID length (long header) */
	u8	crypto_level;		/* Encryption level */
	u8	key_phase:1;		/* Key phase bit (short header) */
	u8	is_long_header:1;	/* Long or short header */
	u8	hw_offload:1;		/* Hardware crypto offload enabled */
	u8	needs_encrypt:1;	/* Needs software encryption */
	u8	needs_decrypt:1;	/* Needs software decryption */
};

#define TQUIC_OFFLOAD_CB(skb) ((struct tquic_offload_cb *)((skb)->cb))

/* Crypto context for hardware offload operations */
struct tquic_crypto_ctx {
	void	*key;		/* Encryption key reference */
	void	*iv;		/* Initialization vector */
	u8	level;		/* Crypto level (TQUIC_CRYPTO_*) */
	u8	key_phase;	/* Key phase for rotation */
	u16	tag_len;	/* AEAD tag length */
};

/* Crypto offload context stored in skb extension */
struct tquic_crypto_offload {
	u64	pn;
	u32	header_len;
	u8	level;
	u8	direction;	/* 0 = TX, 1 = RX */
	u8	key_phase;
	u8	reserved;
};

/* Static key for QUIC encapsulation detection */
DEFINE_STATIC_KEY_FALSE(tquic_encap_needed_key);
EXPORT_SYMBOL(tquic_encap_needed_key);

/* Forward declarations - local static versions for offload layer */
static struct sk_buff *tquic_gso_segment(struct sk_buff *skb,
					netdev_features_t features);
static struct sk_buff *tquic_offload_gro_receive(struct list_head *head,
						struct sk_buff *skb);
static int tquic_offload_gro_complete(struct sk_buff *skb, int nhoff);

/* Parse QUIC packet header for offload processing */
static int tquic_parse_header(struct sk_buff *skb, struct tquic_offload_cb *cb)
{
	u8 *data = skb->data;
	u8 first_byte;
	int offset = 0;
	u32 version;

	if (skb->len < 1)
		return -EINVAL;

	first_byte = data[0];

	/* Check fixed bit */
	if (!(first_byte & QUIC_FIXED_BIT))
		return -EINVAL;

	memset(cb, 0, sizeof(*cb));

	if (first_byte & QUIC_HEADER_FORM_LONG) {
		/* Long header packet */
		cb->is_long_header = 1;

		if (skb->len < 6)
			return -EINVAL;

		/* Version field */
		version = (data[1] << 24) | (data[2] << 16) |
			  (data[3] << 8) | data[4];
		offset = 5;

		/* DCID length */
		cb->dcid_len = data[offset++];
		if (cb->dcid_len > QUIC_MAX_CONNECTION_ID_LEN)
			return -EINVAL;

		if (skb->len < offset + cb->dcid_len + 1)
			return -EINVAL;

		offset += cb->dcid_len;

		/* SCID length */
		cb->scid_len = data[offset++];
		if (cb->scid_len > QUIC_MAX_CONNECTION_ID_LEN)
			return -EINVAL;

		if (skb->len < offset + cb->scid_len)
			return -EINVAL;

		offset += cb->scid_len;

		/* Determine crypto level from packet type */
		switch (first_byte & QUIC_LONG_TYPE_MASK) {
		case QUIC_PKT_INITIAL:
			cb->crypto_level = QUIC_CRYPTO_INITIAL;
			/* Skip token length and token for Initial packets */
			if (skb->len > offset) {
				u64 token_len = 0;
				int varint_len;
				/* Simple varint decode for token length */
				if ((data[offset] & 0xc0) == 0) {
					token_len = data[offset];
					varint_len = 1;
				} else if ((data[offset] & 0xc0) == 0x40) {
					if (skb->len < offset + 2)
						return -EINVAL;
					token_len = ((data[offset] & 0x3f) << 8) |
						    data[offset + 1];
					varint_len = 2;
				} else {
					/* 4 or 8 byte varint - unlikely for token length */
					return -EINVAL;
				}
				offset += varint_len + token_len;
			}
			break;
		case QUIC_PKT_0RTT:
			cb->crypto_level = QUIC_CRYPTO_EARLY_DATA;
			break;
		case QUIC_PKT_HANDSHAKE:
			cb->crypto_level = QUIC_CRYPTO_HANDSHAKE;
			break;
		case QUIC_PKT_RETRY:
			/* Retry packets don't have PN or encryption */
			cb->header_len = offset;
			return 0;
		default:
			return -EINVAL;
		}

		/* Skip length field (varint) */
		if (skb->len > offset) {
			if ((data[offset] & 0xc0) == 0) {
				offset += 1;
			} else if ((data[offset] & 0xc0) == 0x40) {
				offset += 2;
			} else if ((data[offset] & 0xc0) == 0x80) {
				offset += 4;
			} else {
				offset += 8;
			}
		}

		/* PN length from first byte (low 2 bits after unprotection) */
		cb->pn_len = (first_byte & 0x03) + 1;
	} else {
		/* Short header packet (1-RTT) */
		cb->is_long_header = 0;
		cb->crypto_level = QUIC_CRYPTO_APPLICATION;
		cb->key_phase = (first_byte & QUIC_SHORT_KEY_PHASE) ? 1 : 0;

		/* DCID follows first byte (length must be known from context) */
		cb->dcid_len = 8;  /* Default CID length */
		offset = 1 + cb->dcid_len;

		cb->pn_len = (first_byte & QUIC_SHORT_PN_LEN_MASK) + 1;
	}

	cb->header_len = offset + cb->pn_len;

	if (skb->len < cb->header_len)
		return -EINVAL;

	cb->payload_len = skb->len - cb->header_len;

	return 0;
}

/*
 * QUIC GSO Segmentation
 *
 * Segments large QUIC packets while preserving header integrity.
 * Each segment needs its own packet number and potentially its own
 * encryption, so we handle this at the UDP level.
 */
static struct sk_buff *tquic_gso_inner_segment(struct sk_buff *skb,
					      netdev_features_t features,
					      bool is_ipv6)
{
	struct tquic_offload_cb *cb = TQUIC_OFFLOAD_CB(skb);
	unsigned int mss = skb_shinfo(skb)->gso_size;
	struct sk_buff *segs, *seg;
	struct udphdr *uh;
	unsigned int header_len;
	unsigned int payload_offset;
	unsigned int sum_truesize = 0;
	struct sock *sk = skb->sk;
	bool copy_dtor;
	__sum16 check;
	__be16 newlen;
	u64 pn;
	int err;

	if (skb->len <= sizeof(struct udphdr) + mss)
		return ERR_PTR(-EINVAL);

	/* Parse the QUIC header to understand structure */
	err = tquic_parse_header(skb, cb);
	if (err)
		return ERR_PTR(err);

	header_len = sizeof(struct udphdr) + cb->header_len;
	payload_offset = header_len;

	/* Validate checksum setup */
	if (unlikely(skb_checksum_start(skb) != skb_transport_header(skb)))
		return ERR_PTR(-EINVAL);

	/* Don't segment if we can hardware offload */
	if (skb_gso_ok(skb, features | NETIF_F_GSO_ROBUST)) {
		skb_shinfo(skb)->gso_segs = DIV_ROUND_UP(skb->len - header_len,
							 mss);
		return NULL;
	}

	/* Pull UDP header for segmentation */
	uh = udp_hdr(skb);
	skb_pull(skb, sizeof(struct udphdr));

	/* Handle socket reference for segments */
	copy_dtor = skb->destructor == sock_wfree;
	if (copy_dtor) {
		skb->destructor = NULL;
		skb->sk = NULL;
	}

	/* Perform the actual segmentation */
	segs = skb_segment(skb, features);
	if (IS_ERR_OR_NULL(segs)) {
		if (copy_dtor) {
			skb->destructor = sock_wfree;
			skb->sk = sk;
		}
		return segs;
	}

	/* Process each segment */
	pn = cb->pn;
	seg = segs;

	/* Preserve timestamp flags for first segment */
	skb_shinfo(seg)->tskey = skb_shinfo(skb)->tskey;
	skb_shinfo(seg)->tx_flags |=
		(skb_shinfo(skb)->tx_flags & SKBTX_ANY_TSTAMP);

	/* Calculate checksum adjustment */
	newlen = htons(sizeof(struct udphdr) + mss);
	check = csum16_add(csum16_sub(uh->check, uh->len), newlen);

	do {
		u8 *tquic_hdr;
		int i;

		if (copy_dtor) {
			seg->destructor = sock_wfree;
			seg->sk = sk;
			sum_truesize += seg->truesize;
		}

		/* Push back UDP header */
		__skb_push(seg, sizeof(struct udphdr));
		skb_reset_transport_header(seg);

		/* Get QUIC header location */
		tquic_hdr = seg->data + sizeof(struct udphdr);

		/* Update packet number in QUIC header for each segment */
		if (cb->pn_len > 0 && seg != segs) {
			u8 *pn_ptr = tquic_hdr + cb->header_len - cb->pn_len;

			/* Increment packet number */
			pn++;

			/* Encode packet number (big-endian) */
			for (i = cb->pn_len - 1; i >= 0; i--) {
				pn_ptr[i] = pn & 0xff;
				pn >>= 8;
			}
		}

		if (!seg->next)
			break;

		/* Update UDP header for intermediate segments */
		uh = udp_hdr(seg);
		uh->len = newlen;
		uh->check = check;

		if (seg->ip_summed == CHECKSUM_PARTIAL)
			gso_reset_checksum(seg, ~check);
		else
			uh->check = gso_make_checksum(seg, ~check) ? :
				    CSUM_MANGLED_0;

		seg = seg->next;
	} while (seg);

	/* Handle last segment with potentially different size */
	newlen = htons(skb_tail_pointer(seg) - skb_transport_header(seg) +
		       seg->data_len);
	check = csum16_add(csum16_sub(uh->check, uh->len), newlen);

	uh = udp_hdr(seg);
	uh->len = newlen;
	uh->check = check;

	if (seg->ip_summed == CHECKSUM_PARTIAL)
		gso_reset_checksum(seg, ~check);
	else
		uh->check = gso_make_checksum(seg, ~check) ? : CSUM_MANGLED_0;

	/* Fix checksum state on original skb */
	if (skb->ip_summed == CHECKSUM_NONE)
		skb->ip_summed = CHECKSUM_UNNECESSARY;

	/* Update socket accounting */
	if (copy_dtor) {
		int delta = sum_truesize - skb->truesize;

		if (likely(delta >= 0))
			refcount_add(delta, &sk->sk_wmem_alloc);
		else
			WARN_ON_ONCE(refcount_sub_and_test(-delta,
							   &sk->sk_wmem_alloc));
	}

	return segs;
}

/* Main GSO segment callback for QUIC */
static struct sk_buff *tquic_gso_segment(struct sk_buff *skb,
					netdev_features_t features)
{
	struct sk_buff *segs = ERR_PTR(-EINVAL);
	struct udphdr *uh;
	bool is_ipv6 = false;

	/* Check protocol type */
	if (skb->protocol == htons(ETH_P_IPV6))
		is_ipv6 = true;
	else if (skb->protocol != htons(ETH_P_IP))
		goto out;

	/* Verify GSO type */
	if (!(skb_shinfo(skb)->gso_type & (SKB_GSO_UDP_L4 | SKB_GSO_QUIC)))
		goto out;

	/* Pull UDP header */
	if (!pskb_may_pull(skb, sizeof(struct udphdr)))
		goto out;

	uh = udp_hdr(skb);

	/* Verify this looks like a QUIC packet */
	if (skb->len < sizeof(struct udphdr) + 1)
		goto out;

	/* Perform QUIC-aware segmentation */
	segs = tquic_gso_inner_segment(skb, features, is_ipv6);

out:
	return segs;
}

/*
 * QUIC GRO (Generic Receive Offload)
 *
 * Aggregates multiple QUIC packets for more efficient processing.
 * We can only aggregate packets from the same QUIC connection (same CID)
 * and with consecutive packet numbers.
 */

/* Check if two QUIC packets can be aggregated */
static bool tquic_gro_same_flow(struct sk_buff *skb1, struct sk_buff *skb2)
{
	struct tquic_offload_cb cb1, cb2;
	u8 *data1, *data2;
	u8 cid_len;

	if (tquic_parse_header(skb1, &cb1) || tquic_parse_header(skb2, &cb2))
		return false;

	/* Both must be same header type */
	if (cb1.is_long_header != cb2.is_long_header)
		return false;

	/* Same crypto level */
	if (cb1.crypto_level != cb2.crypto_level)
		return false;

	/* Compare DCIDs */
	if (cb1.dcid_len != cb2.dcid_len)
		return false;

	cid_len = cb1.dcid_len;
	if (cid_len > 0) {
		if (cb1.is_long_header) {
			data1 = skb1->data + 6;  /* After fixed header + version + dcid_len */
			data2 = skb2->data + 6;
		} else {
			data1 = skb1->data + 1;  /* After first byte */
			data2 = skb2->data + 1;
		}

		if (memcmp(data1, data2, cid_len) != 0)
			return false;
	}

	return true;
}

/* GRO receive callback for QUIC packets */
static struct sk_buff *tquic_offload_gro_receive(struct list_head *head,
					struct sk_buff *skb)
{
	struct sk_buff *pp = NULL;
	struct sk_buff *p;
	struct tquic_offload_cb *cb;
	unsigned int tquic_len;
	int flush = 1;

	/* Basic validation */
	if (skb->len < 1)
		goto out;

	cb = TQUIC_OFFLOAD_CB(skb);
	if (tquic_parse_header(skb, cb))
		goto out;

	/* QUIC packet length for GRO */
	tquic_len = skb_gro_len(skb);

	/* Check if we can do L4 aggregation */
	if (skb->encapsulation)
		goto out;

	flush = 0;

	/* Look for matching flows */
	list_for_each_entry(p, head, list) {
		if (!NAPI_GRO_CB(p)->same_flow)
			continue;

		/* Verify same QUIC connection */
		if (!tquic_gro_same_flow(p, skb)) {
			NAPI_GRO_CB(p)->same_flow = 0;
			continue;
		}

		/* Check for overflow conditions */
		if (NAPI_GRO_CB(p)->count >= QUIC_GRO_MAX_CNT) {
			pp = p;
			break;
		}

		/* Check total size doesn't exceed limits */
		if (p->len + tquic_len > TQUIC_GRO_MAX_SIZE) {
			pp = p;
			break;
		}

		/* Merge the packets */
		if (skb_gro_receive(p, skb)) {
			pp = p;
			break;
		}

		/* Mark that we successfully merged */
		return pp;
	}

out:
	skb_gro_flush_final(skb, pp, flush);
	return pp;
}

/* GRO complete callback for QUIC */
static int tquic_offload_gro_complete(struct sk_buff *skb, int nhoff)
{
	struct udphdr *uh = (struct udphdr *)(skb->data + nhoff);
	__be16 newlen = htons(skb->len - nhoff);

	/* Update UDP length field */
	uh->len = newlen;

	/* Setup for hardware checksum */
	skb->csum_start = (unsigned char *)uh - skb->head;
	skb->csum_offset = offsetof(struct udphdr, check);
	skb->ip_summed = CHECKSUM_PARTIAL;

	/* Set GSO info */
	skb_shinfo(skb)->gso_segs = NAPI_GRO_CB(skb)->count;
	skb_shinfo(skb)->gso_type |= SKB_GSO_UDP_L4;

	if (skb->encapsulation)
		skb->inner_transport_header = skb->transport_header;

	return 0;
}

/*
 * Crypto Offload Support
 *
 * These functions provide hooks for NIC-based QUIC encryption/decryption.
 * Hardware that supports QUIC crypto offload can use these to bypass
 * software encryption.
 */

/*
 * tquic_crypto_offload_available - Check if hardware crypto offload is available
 * @dev: Network device to check
 * @crypto_level: QUIC crypto level (Initial, Handshake, or Application)
 *
 * Checks whether the specified network device supports QUIC hardware crypto
 * offload for the given encryption level. Currently no NICs support QUIC-
 * specific crypto offload, so this always returns false after basic validation.
 *
 * Future implementation should:
 * 1. Define a NETIF_F_QUIC_CRYPTO capability flag in netdev_features.h
 * 2. Check: if (!(dev->features & NETIF_F_QUIC_CRYPTO)) return false;
 * 3. Return true when hardware is verified to support QUIC crypto offload
 * 4. Consider vendor-specific capability checks for early-adopter NICs
 *
 * Returns: true if hardware offload is available, false otherwise
 */
static bool tquic_crypto_offload_available(struct net_device *dev,
					  u8 crypto_level)
{
	/* Check device capabilities */
	if (!dev)
		return false;

	/* Basic hardware checksum capability is a prerequisite */
	if (!(dev->features & NETIF_F_HW_CSUM))
		return false;

	/* Only application data level is typically offloaded */
	if (crypto_level != QUIC_CRYPTO_APPLICATION)
		return false;

	/*
	 * Hardware crypto offload for QUIC requires NIC support for
	 * QUIC-specific AEAD operations. When hardware implements
	 * NETIF_F_QUIC_CRYPTO, this function should check that flag
	 * and return true for supported offload configurations.
	 */
	return false;
}

/* Prepare skb for hardware crypto offload (TX path) */
int tquic_crypto_offload_encrypt(struct sk_buff *skb,
				struct tquic_crypto_ctx *ctx,
				u64 pn)
{
	struct tquic_offload_cb *cb = TQUIC_OFFLOAD_CB(skb);
	struct net_device *dev = skb->dev;

	if (!tquic_crypto_offload_available(dev, cb->crypto_level)) {
		cb->hw_offload = 0;
		cb->needs_encrypt = 1;
		return -EOPNOTSUPP;
	}

	/* Mark for hardware encryption */
	cb->hw_offload = 1;
	cb->needs_encrypt = 0;
	cb->pn = pn;

	/* Store crypto context info in skb for hardware */
	skb->encapsulation = 1;

	return 0;
}
EXPORT_SYMBOL(tquic_crypto_offload_encrypt);

/* Check and handle hardware crypto on RX path */
int tquic_crypto_offload_decrypt(struct sk_buff *skb,
				struct tquic_crypto_ctx *ctx,
				u64 *pn)
{
	struct tquic_offload_cb *cb = TQUIC_OFFLOAD_CB(skb);

	/* Check if hardware already decrypted */
	if (cb->hw_offload && !cb->needs_decrypt) {
		/* Hardware handled decryption */
		if (pn)
			*pn = cb->pn;
		return 0;
	}

	/* Fall back to software decryption */
	cb->needs_decrypt = 1;
	return -EOPNOTSUPP;
}
EXPORT_SYMBOL(tquic_crypto_offload_decrypt);

/*
 * UDP Encapsulation Support
 *
 * QUIC runs over UDP. The main UDP encapsulation functions are defined in
 * tquic_udp.c which provides the complete UDP tunnel integration for TQUIC.
 *
 * This file only provides the offload-layer specific helpers used by the
 * GRO/GSO callbacks defined below.
 */

/* QUIC offload operations structure */
static const struct tquic_offload_ops tquic_offload_ops = {
	.encrypt	= NULL,  /* Use software by default */
	.decrypt	= NULL,  /* Use software by default */
	.gso_segment	= tquic_gso_segment,
	.gro_receive	= tquic_offload_gro_receive,
	.gro_complete	= tquic_offload_gro_complete,
};

const struct tquic_offload_ops *tquic_offload = &tquic_offload_ops;
EXPORT_SYMBOL(tquic_offload);

/* IPv4 QUIC GRO receive wrapper */
static struct sk_buff *quic4_gro_receive(struct list_head *head,
					 struct sk_buff *skb)
{
	struct udphdr *uh;
	struct sk_buff *pp = NULL;

	uh = udp_gro_udphdr(skb);
	if (unlikely(!uh))
		goto flush;

	/* Verify this could be QUIC */
	if (skb_gro_len(skb) < sizeof(struct udphdr) + 1)
		goto flush;

	/* Validate UDP checksum */
	if (NAPI_GRO_CB(skb)->flush)
		goto skip;

	if (skb_gro_checksum_validate_zero_check(skb, IPPROTO_UDP, uh->check,
						 inet_gro_compute_pseudo))
		goto flush;
	else if (uh->check)
		tquic_gro_checksum_try_convert(skb, IPPROTO_UDP,
					       inet_gro_compute_pseudo);

skip:
	/* Pull UDP header */
	skb_gro_pull(skb, sizeof(struct udphdr));
	skb_gro_postpull_rcsum(skb, uh, sizeof(struct udphdr));

	/* Call QUIC GRO */
	pp = tquic_offload_gro_receive(head, skb);

	return pp;

flush:
	NAPI_GRO_CB(skb)->flush = 1;
	return NULL;
}

/* IPv4 QUIC GRO complete wrapper */
static int quic4_gro_complete(struct sk_buff *skb, int nhoff)
{
	const struct iphdr *iph = (struct iphdr *)(skb->data +
			TQUIC_GRO_NETWORK_OFFSET(skb));
	struct udphdr *uh = (struct udphdr *)(skb->data + nhoff);

	/* Update UDP checksum with final length */
	if (uh->check)
		uh->check = ~udp_v4_check(skb->len - nhoff, iph->saddr,
					  iph->daddr, 0);

	return tquic_offload_gro_complete(skb, nhoff);
}

#if IS_ENABLED(CONFIG_IPV6)
/* IPv6 QUIC GRO receive wrapper */
static struct sk_buff *quic6_gro_receive(struct list_head *head,
					 struct sk_buff *skb)
{
	struct udphdr *uh;
	struct sk_buff *pp = NULL;

	uh = udp_gro_udphdr(skb);
	if (unlikely(!uh))
		goto flush;

	/* Verify this could be QUIC */
	if (skb_gro_len(skb) < sizeof(struct udphdr) + 1)
		goto flush;

	/* Validate UDP checksum */
	if (NAPI_GRO_CB(skb)->flush)
		goto skip;

	if (skb_gro_checksum_validate_zero_check(skb, IPPROTO_UDP, uh->check,
						 ip6_gro_compute_pseudo))
		goto flush;
	else if (uh->check)
		tquic_gro_checksum_try_convert(skb, IPPROTO_UDP,
					       ip6_gro_compute_pseudo);

skip:
	/* Pull UDP header */
	skb_gro_pull(skb, sizeof(struct udphdr));
	skb_gro_postpull_rcsum(skb, uh, sizeof(struct udphdr));

	/* Call QUIC GRO */
	pp = tquic_offload_gro_receive(head, skb);

	return pp;

flush:
	NAPI_GRO_CB(skb)->flush = 1;
	return NULL;
}

/* IPv6 QUIC GRO complete wrapper */
static int quic6_gro_complete(struct sk_buff *skb, int nhoff)
{
	const struct ipv6hdr *ipv6h = (struct ipv6hdr *)(skb->data +
			TQUIC_GRO_NETWORK_OFFSET(skb));
	struct udphdr *uh = (struct udphdr *)(skb->data + nhoff);

	/* Update UDP checksum with final length */
	if (uh->check)
		uh->check = ~udp_v6_check(skb->len - nhoff, &ipv6h->saddr,
					  &ipv6h->daddr, 0);

	return tquic_offload_gro_complete(skb, nhoff);
}
#endif /* CONFIG_IPV6 */

/* GSO segment handler for IPv4 */
static struct sk_buff *quic4_gso_segment(struct sk_buff *skb,
					 netdev_features_t features)
{
	return tquic_gso_segment(skb, features);
}

#if IS_ENABLED(CONFIG_IPV6)
/* GSO segment handler for IPv6 */
static struct sk_buff *quic6_gso_segment(struct sk_buff *skb,
					 netdev_features_t features)
{
	return tquic_gso_segment(skb, features);
}
#endif

/* Net offload structure for QUIC over IPv4 */
static struct net_offload quic4_offload __read_mostly = {
	.callbacks = {
		.gso_segment	= quic4_gso_segment,
		.gro_receive	= quic4_gro_receive,
		.gro_complete	= quic4_gro_complete,
	},
};

#if IS_ENABLED(CONFIG_IPV6)
/* Net offload structure for QUIC over IPv6 */
static struct net_offload quic6_offload __read_mostly = {
	.callbacks = {
		.gso_segment	= quic6_gso_segment,
		.gro_receive	= quic6_gro_receive,
		.gro_complete	= quic6_gro_complete,
	},
};
#endif

/*
 * Module initialization is handled by tquic_offload.c which provides the
 * tquic_offload_init() and tquic_offload_exit() functions for the complete
 * GRO/GSO offload implementation.
 */

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux QUIC Authors");
MODULE_DESCRIPTION("QUIC Hardware Offload Support");
