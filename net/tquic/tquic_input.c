// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: Packet Reception Path
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Implements the QUIC packet reception path with multipath WAN bonding
 * support including UDP receive callbacks, header unprotection,
 * packet decryption, frame demultiplexing, and connection lookup.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/rhashtable.h>
#include <linux/random.h>
#include <linux/hrtimer.h>
#include <linux/overflow.h>
#include <linux/unaligned.h>
#include <net/sock.h>
#include <net/udp.h>
#include <net/udp_tunnel.h>
#include <net/ip.h>
#include <net/ipv6.h>
#include <net/gro.h>
#include <crypto/aead.h>
#include <net/tquic.h>
#include <net/tquic_frame.h>

#include "tquic_compat.h"
#include "tquic_debug.h"
#include "tquic_mib.h"
#include "protocol.h"
#include "cong/tquic_cong.h"
#include "crypto/key_update.h"
#include "crypto/zero_rtt.h"
#include "crypto/header_protection.h"
#include "tquic_stateless_reset.h"
#include "tquic_token.h"
#include "tquic_retry.h"
#include "tquic_ack_frequency.h"
#include "tquic_ratelimit.h"
#include "rate_limit.h"
#include "security_hardening.h"
#include "tquic_cid.h"
#include "core/flow_control.h"

/* Per-packet RX decryption buffer slab cache (allocated in tquic_main.c) */
#define TQUIC_RX_BUF_SIZE	2048

/* Maximum ACK ranges to prevent resource exhaustion from malicious frames */
#define TQUIC_MAX_ACK_RANGES		256

/*
 * M-001: Maximum per-STREAM frame allocation limit.
 * Prevents a single frame from allocating multi-MB skbs.
 * 64KB is reasonable for packet-sized data but prevents abuse.
 */
#define TQUIC_MAX_STREAM_FRAME_ALLOC	(64 * 1024)

/* QUIC frame types (must match tquic_output.c) */
#define TQUIC_FRAME_PADDING		0x00
#define TQUIC_FRAME_PING		0x01
#define TQUIC_FRAME_ACK			0x02
#define TQUIC_FRAME_ACK_ECN		0x03
#define TQUIC_FRAME_RESET_STREAM	0x04
#define TQUIC_FRAME_STOP_SENDING	0x05
#define TQUIC_FRAME_CRYPTO		0x06
#define TQUIC_FRAME_NEW_TOKEN		0x07
#define TQUIC_FRAME_STREAM		0x08  /* 0x08-0x0f */
#define TQUIC_FRAME_MAX_DATA		0x10
#define TQUIC_FRAME_MAX_STREAM_DATA	0x11
#define TQUIC_FRAME_MAX_STREAMS_BIDI	0x12
#define TQUIC_FRAME_MAX_STREAMS_UNI	0x13
#define TQUIC_FRAME_DATA_BLOCKED	0x14
#define TQUIC_FRAME_STREAM_DATA_BLOCKED	0x15
#define TQUIC_FRAME_STREAMS_BLOCKED_BIDI 0x16
#define TQUIC_FRAME_STREAMS_BLOCKED_UNI	0x17
#define TQUIC_FRAME_NEW_CONNECTION_ID	0x18
#define TQUIC_FRAME_RETIRE_CONNECTION_ID 0x19
#define TQUIC_FRAME_PATH_CHALLENGE	0x1a
#define TQUIC_FRAME_PATH_RESPONSE	0x1b
#define TQUIC_FRAME_CONNECTION_CLOSE	0x1c
#define TQUIC_FRAME_CONNECTION_CLOSE_APP 0x1d
#define TQUIC_FRAME_HANDSHAKE_DONE	0x1e
#define TQUIC_FRAME_DATAGRAM		0x30  /* 0x30-0x31 */
/* ACK frequency frame types defined in core/ack_frequency.h */
/* Packet header constants */
#define TQUIC_HEADER_FORM_LONG		0x80
#define TQUIC_HEADER_FIXED_BIT		0x40
#define TQUIC_HEADER_SPIN_BIT		0x20
#define TQUIC_HEADER_KEY_PHASE		0x04

/* Long header packet types */
#define TQUIC_PKT_INITIAL		0x00
#define TQUIC_PKT_ZERO_RTT		0x01
#define TQUIC_PKT_HANDSHAKE		0x02
#define TQUIC_PKT_RETRY			0x03

/* Version constants */
#define TQUIC_VERSION_NEGOTIATION	0x00000000

/* Stateless reset */
#undef TQUIC_STATELESS_RESET_MIN_LEN
#define TQUIC_STATELESS_RESET_MIN_LEN	22  /* RFC 9000 Section 10.3 */
#define TQUIC_STATELESS_RESET_TOKEN_LEN	16

/* GRO configuration */
#define TQUIC_GRO_MAX_HOLD		10
#define TQUIC_GRO_FLUSH_TIMEOUT_US	1000

/* Maximum token length for coalesced packet parsing */
#define TQUIC_COALESCED_MAX_TOKEN_LEN	512

/*
 * CF-176: QUIC v2 packet type constants (RFC 9369 Section 5.4).
 * v2 swaps the Initial and Retry type codes vs v1.
 */
#ifndef QUIC_V2_PACKET_TYPE_INITIAL
#define QUIC_V2_PACKET_TYPE_INITIAL	0x01
#endif
#ifndef QUIC_VERSION_2
#define QUIC_VERSION_2			0x6b3343cf
#endif

/*
 * CF-075: Maximum number of QUIC packets in a single UDP datagram.
 * RFC 9000 Section 12.2 allows coalescing, but a practical upper bound
 * prevents CPU exhaustion from malicious datagrams with many tiny packets.
 */
#define TQUIC_MAX_COALESCED_PACKETS	16

/* Forward declarations */
static int tquic_process_frames(struct tquic_connection *conn,
				struct tquic_path *path,
				u8 *payload, size_t len,
				int enc_level, u64 pkt_num);

/*
 * Per-path ECN tracking state for detecting CE count increases
 * Per RFC 9002 Section 7.1: Only respond to *increases* in CE count
 */
struct tquic_ecn_tracking {
	u64 ect0_count;		/* Previous ECT(0) count from peer */
	u64 ect1_count;		/* Previous ECT(1) count from peer */
	u64 ce_count;		/* Previous CE count from peer */
	bool validated;		/* ECN path validation complete */
};

/* Receive context for packet processing */
struct tquic_rx_ctx {
	struct tquic_connection *conn;
	struct tquic_path *path;
	struct sk_buff *skb;
	u8 *data;
	size_t len;
	size_t offset;
	u64 pkt_num;
	int enc_level;
	bool is_long_header;
	bool ack_eliciting;
	bool immediate_ack_seen;  /* Only process first IMMEDIATE_ACK per pkt */
	bool ack_frame_seen;      /* CF-283: Only process first ACK per pkt */
	bool saw_stream_no_length; /* A STREAM frame without Length was seen */
	u8 key_phase_bit;  /* Key phase from short header (RFC 9001 Section 6) */
};

/* GRO state per socket */
struct tquic_gro_state {
	struct sk_buff_head hold_queue;
	spinlock_t lock;
	struct hrtimer flush_timer;
	int held_count;
	ktime_t first_hold_time;
};

/*
 * =============================================================================
 * Variable Length Integer Decoding (QUIC RFC 9000)
 * =============================================================================
 */

static inline int tquic_decode_varint(const u8 *buf, size_t buf_len, u64 *val)
{
	u8 prefix;
	int len;

	if (buf_len < 1)
		return -EINVAL;

	prefix = buf[0] >> 6;
	len = 1 << prefix;

	if (buf_len < len)
		return -EINVAL;

	switch (len) {
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

	return len;
}

/*
 * =============================================================================
 * Connection Lookup by CID
 * =============================================================================
 */

/*
 * Look up connection by destination CID from packet
 */
static struct tquic_connection *tquic_lookup_by_dcid(const u8 *dcid, u8 dcid_len)
{
	struct tquic_cid cid;

	if (unlikely(dcid_len > TQUIC_MAX_CID_LEN))
		return NULL;

	cid.len = dcid_len;
	memcpy(cid.id, dcid, dcid_len);
	cid.seq_num = 0;
	cid.retire_prior_to = 0;

	/* Use the exported lookup function from core/connection.c */
	return tquic_conn_lookup_by_cid(&cid);
}

/*
 * Find path by source address
 *
 * Caller must NOT hold paths_lock. This function acquires it internally.
 * Caller must hold rcu_read_lock() to prevent the returned path from being
 * freed via kfree_rcu() after we release the spinlock.
 */
/*
 * Compare two socket addresses by family, address, and port only.
 * Using memcmp on the full sockaddr_storage is incorrect because
 * padding bytes may differ between otherwise-identical addresses.
 */
static bool tquic_sockaddr_equal(const struct sockaddr_storage *a,
				 const struct sockaddr_storage *b)
{
	if (a->ss_family != b->ss_family)
		return false;

	switch (a->ss_family) {
	case AF_INET: {
		const struct sockaddr_in *a4 = (const struct sockaddr_in *)a;
		const struct sockaddr_in *b4 = (const struct sockaddr_in *)b;

		return a4->sin_port == b4->sin_port &&
		       a4->sin_addr.s_addr == b4->sin_addr.s_addr;
	}
	case AF_INET6: {
		const struct sockaddr_in6 *a6 = (const struct sockaddr_in6 *)a;
		const struct sockaddr_in6 *b6 = (const struct sockaddr_in6 *)b;

		return a6->sin6_port == b6->sin6_port &&
		       ipv6_addr_equal(&a6->sin6_addr, &b6->sin6_addr);
	}
	default:
		return false;
	}
}

/**
 * tquic_find_path_by_addr - Find path by remote address
 * @conn: Connection
 * @addr: Remote address to match
 *
 * Returns path with incremented reference count. Caller MUST call
 * tquic_path_put() when done with the path to avoid leaking references.
 * Caller must hold rcu_read_lock().
 *
 * Return: Path pointer with reference, or NULL if not found
 */
static struct tquic_path *tquic_find_path_by_addr(struct tquic_connection *conn,
						  struct sockaddr_storage *addr)
{
	struct tquic_path *path;
	struct tquic_path *found = NULL;

	/*
	 * CF-179: Fast-path -- check the connection's active_path first
	 * without taking the lock.  Most packets arrive on the active
	 * path, so this avoids the spinlock overhead on the hot path.
	 * The caller holds rcu_read_lock(), so use rcu_dereference()
	 * for proper RCU annotation.
	 * SECURITY: Take a reference to prevent use-after-free if path
	 * is removed concurrently. Caller must call tquic_path_put().
	 * C-001 FIX: Use refcount_inc_not_zero() directly to avoid
	 * TOCTOU race between rcu_dereference() and reference acquisition.
	 */
	RCU_LOCKDEP_WARN(!rcu_read_lock_held(),
			 "tquic_find_path_by_addr: caller must hold rcu_read_lock");
	path = rcu_dereference(conn->active_path);
	if (path && tquic_sockaddr_equal(&path->remote_addr, addr)) {
		if (refcount_inc_not_zero(&path->refcnt))
			return path;
		goto slow_path;
	}

slow_path:

	/*
	 * P-002: Use RCU for lock-free path list traversal.
	 * The paths list is modified using list_add_rcu() and list_del_rcu(),
	 * and paths are freed via kfree_rcu(), so RCU protection ensures
	 * safe access during traversal.
	 */
	/*
	 * Slow path: walk the full paths list under the caller's
	 * rcu_read_lock().  No additional rcu_read_lock/unlock needed
	 * since the caller already holds it (see RCU_LOCKDEP_WARN above).
	 */
	list_for_each_entry_rcu(path, &conn->paths, list) {
		if (tquic_sockaddr_equal(&path->remote_addr, addr)) {
			if (tquic_path_get(path))
				found = path;
			break;
		}
	}

	return found;
}

/*
 * Find path by local connection ID
 *
 * Caller must NOT hold paths_lock. This function acquires it internally.
 */
static struct tquic_path __maybe_unused *tquic_find_path_by_cid(struct tquic_connection *conn,
							       const u8 *cid, u8 cid_len)
{
	struct tquic_path *path;
	struct tquic_path *found = NULL;

	/*
	 * P-002: Use RCU for lock-free path list traversal.
	 * Note: This function doesn't take a reference on the path,
	 * so caller must hold appropriate lock or be in RCU critical section.
	 */
	rcu_read_lock();
	list_for_each_entry_rcu(path, &conn->paths, list) {
		if (path->local_cid.len == cid_len &&
		    memcmp(path->local_cid.id, cid, cid_len) == 0) {
			/*
			 * Take reference to prevent path from being freed
			 * after we release RCU read lock.
			 */
			if (tquic_path_get(path))
				found = path;
			break;
		}
	}
	rcu_read_unlock();

	return found;
}

/*
 * =============================================================================
 * Header Unprotection
 * =============================================================================
 */

/*
 * Remove header protection
 *
 * Delegates to tquic_hp_unprotect() from crypto/header_protection.c when
 * the connection has an HP context initialised. When crypto state is not
 * yet available (e.g. first Initial packet before keys are derived), HP
 * removal is a no-op because the Initial keys are derived from the DCID
 * and the caller handles that separately.
 */
static int tquic_remove_header_protection(struct tquic_connection *conn,
					  u8 *header, int header_len,
					  u8 *payload, int payload_len,
					  bool is_long_header,
					  u8 *out_pn_len,
					  u8 *out_key_phase)
{
	struct tquic_hp_ctx *hp;
	u8 pn_len = 0;
	u8 key_phase = 0;
	size_t total_len;
	int ret;

	if (!conn || !conn->crypto_state)
		return 0;

	/*
	 * The crypto module exposes an HP context through the opaque
	 * crypto_state.  If no HP keys have been installed yet (e.g.
	 * during Initial packet processing before key derivation),
	 * crypto_state will not carry an HP context and we skip removal.
	 */
	hp = tquic_crypto_get_hp_ctx(conn->crypto_state);
	if (!hp)
		return 0;

	total_len = (size_t)header_len + (size_t)payload_len;
	ret = tquic_hp_unprotect(hp, header, total_len,
				 (size_t)header_len, &pn_len, &key_phase);
	if (ret < 0) {
		tquic_dbg("header protection removal failed: %d\n", ret);
		return ret;
	}

	/*
	 * CF-099: Return the pn_len and key_phase recovered by
	 * tquic_hp_unprotect() so the caller uses values from
	 * the unprotected header rather than the protected one.
	 */
	if (out_pn_len)
		*out_pn_len = pn_len;
	if (out_key_phase)
		*out_key_phase = key_phase;

	return 0;
}

/*
 * =============================================================================
 * Packet Decryption
 * =============================================================================
 */

/*
 * Decrypt packet payload
 */
static int tquic_decrypt_payload(struct tquic_connection *conn,
				 u8 *header, int header_len,
				 u8 *payload, int payload_len,
				 u64 pkt_num, int enc_level,
				 u8 *out, size_t *out_len)
{
	if (conn->crypto_state) {
		return tquic_decrypt_packet(conn->crypto_state,
					    header, header_len,
					    payload, payload_len,
					    pkt_num, out, out_len);
	}

	/* No crypto state - cannot process packet */
	return -ENOKEY;
}

/*
 * =============================================================================
 * Stateless Reset Detection
 * =============================================================================
 */

/*
 * Check if packet is a stateless reset
 *
 * Per RFC 9000 Section 10.3.1:
 * "An endpoint detects a potential stateless reset using the last
 * 16 bytes of the UDP datagram. An endpoint remembers all stateless
 * reset tokens associated with the connection IDs and remote addresses
 * for datagrams it has recently sent."
 */
static bool tquic_is_stateless_reset_internal(struct tquic_connection *conn,
				     const u8 *data, size_t len)
{
	/*
	 * Use the new detection API which checks against all tokens
	 * stored from NEW_CONNECTION_ID frames received from the peer.
	 */
	return tquic_stateless_reset_detect_conn(conn, data, len);
}

/*
 * Handle stateless reset
 */
static void tquic_handle_stateless_reset(struct tquic_connection *conn)
{
	tquic_info("received stateless reset for connection\n");

	/*
	 * Use the proper state machine transition instead of directly
	 * setting conn->state.  tquic_conn_close_with_error() validates
	 * the transition, stores the error code, and notifies upper
	 * layers through the standard close path.
	 */
	tquic_conn_close_with_error(conn, EQUIC_NO_ERROR, "stateless reset");
}

/*
 * =============================================================================
 * Version Negotiation
 * =============================================================================
 */

/*
 * Check if packet is version negotiation
 */
static bool tquic_is_version_negotiation(const u8 *data, size_t len)
{
	u32 version;

	if (len < 7)  /* Minimum long header */
		return false;

	if (!(data[0] & TQUIC_HEADER_FORM_LONG))
		return false;

	/* CF-157: cast to u32 before shift to avoid signed overflow */
	version = ((u32)data[1] << 24) | ((u32)data[2] << 16) |
		  ((u32)data[3] << 8) | (u32)data[4];

	return version == TQUIC_VERSION_NEGOTIATION;
}

/*
 * Process version negotiation packet
 */
static int tquic_process_version_negotiation(struct tquic_connection *conn,
					     const u8 *data, size_t len)
{
	u8 dcid_len, scid_len;
	const u8 *versions;
	size_t versions_len;
	int i;
	bool found = false;

	if (len < 7)
		return -EINVAL;

	/*
	 * SECURITY: Validate CID lengths before use as offsets.
	 * RFC 9000 limits CID to 20 bytes. Without this check, a crafted
	 * dcid_len of 255 would cause 6 + dcid_len to overflow u8 arithmetic.
	 * Use size_t arithmetic to prevent narrowing issues.
	 */
	dcid_len = data[5];
	if (dcid_len > TQUIC_MAX_CID_LEN)
		return -EINVAL;
	if (len < (size_t)6 + dcid_len + 1)
		return -EINVAL;

	scid_len = data[6 + dcid_len];
	if (scid_len > TQUIC_MAX_CID_LEN)
		return -EINVAL;
	if (len < (size_t)7 + dcid_len + scid_len)
		return -EINVAL;

	versions = data + 7 + dcid_len + scid_len;
	versions_len = len - 7 - dcid_len - scid_len;

	tquic_dbg("received version negotiation, %zu bytes of versions\n",
		  versions_len);

	/* Check each offered version (cap log output to prevent flooding) */
	for (i = 0; i + 4 <= versions_len; i += 4) {
		/* CF-157: cast to u32 before shift to avoid signed overflow */
		u32 version = ((u32)versions[i] << 24) |
			      ((u32)versions[i + 1] << 16) |
			      ((u32)versions[i + 2] << 8) |
			      (u32)versions[i + 3];

		/*
		 * RFC 9000 Section 6.1: A client MUST discard a VN packet
		 * that lists the QUIC version the client selected.
		 */
		if (version == conn->version) {
			tquic_dbg("VN lists our current version 0x%08x, discarding\n",
				  conn->version);
			return 0;
		}

		if (version == TQUIC_VERSION_1 || version == TQUIC_VERSION_2)
			found = true;
	}

	if (!found) {
		tquic_warn("conn: no compatible version found (local supports v1/v2)\n");
		tquic_conn_close_with_error(conn, EQUIC_NO_ERROR,
					    "no compatible version");
		return -EPROTONOSUPPORT;
	}

	/* Retry with a compatible version */
	/* This would trigger a new Initial packet with the selected version */

	return 0;
}

/*
 * tquic_send_vn_from_listener - Send Version Negotiation from listening socket
 * @listener: Listening socket
 * @skb: Received Initial packet
 * @client_addr: Client source address
 * @local_addr: Local address packet was received on
 *
 * Sends a Version Negotiation packet in response to an Initial packet
 * with an unsupported version (RFC 9000 Section 6).
 *
 * Returns: 0 on success, negative errno on failure
 */
static int tquic_send_vn_from_listener(struct sock *listener,
				       struct sk_buff *skb,
				       struct sockaddr_storage *client_addr,
				       struct sockaddr_storage *local_addr)
{
	const u8 *data = skb->data;
	size_t len = skb->len;
	u8 dcid_len, scid_len;
	const u8 *dcid, *scid;
	struct sk_buff *vn_skb;
	u8 *p;
	static const u32 supported_versions[] = {
		TQUIC_VERSION_1,
		TQUIC_VERSION_2,
	};
	size_t vn_len;
	int i, ret;

	/* Extract connection IDs from Initial packet (RFC 9000 Section 17.2) */
	if (len < 7) /* Min: 1 byte header + 4 bytes version + 1 dcid_len + 1 scid_len */
		return -EINVAL;

	dcid_len = data[5];
	if (len < 6 + dcid_len + 1)
		return -EINVAL;

	dcid = &data[6];
	scid_len = data[6 + dcid_len];

	if (len < 7 + dcid_len + scid_len)
		return -EINVAL;

	scid = &data[7 + dcid_len];

	/* Build Version Negotiation packet */
	vn_len = 1 + 4 + 1 + scid_len + 1 + dcid_len + sizeof(supported_versions);
	vn_skb = alloc_skb(vn_len + MAX_HEADER, GFP_ATOMIC);
	if (!vn_skb)
		return -ENOMEM;

	skb_reserve(vn_skb, MAX_HEADER);
	p = skb_put(vn_skb, vn_len);

	/* First byte: long header form with random bits */
	get_random_bytes(p, 1);
	p[0] |= TQUIC_HEADER_FORM_LONG;
	p++;

	/* Version = 0 for Version Negotiation */
	put_unaligned_be32(0, p);
	p += 4;

	/* DCID = client's SCID */
	*p++ = scid_len;
	memcpy(p, scid, scid_len);
	p += scid_len;

	/* SCID = client's DCID */
	*p++ = dcid_len;
	memcpy(p, dcid, dcid_len);
	p += dcid_len;

	/* Supported versions list */
	for (i = 0; i < ARRAY_SIZE(supported_versions); i++) {
		put_unaligned_be32(supported_versions[i], p);
		p += 4;
	}

	/* Send VN packet to client using UDP */
	{
		struct msghdr msg = {};
		struct kvec iov;

		/* Set destination address */
		msg.msg_name = client_addr;
		msg.msg_namelen = (client_addr->ss_family == AF_INET) ?
				  sizeof(struct sockaddr_in) :
				  sizeof(struct sockaddr_in6);

		/* Set data buffer */
		iov.iov_base = vn_skb->data;
		iov.iov_len = vn_skb->len;

		/* Send through kernel UDP */
		ret = kernel_sendmsg(listener->sk_socket, &msg, &iov, 1, vn_skb->len);
		kfree_skb(vn_skb);

		if (ret < 0) {
			tquic_dbg("failed to send version negotiation: %d\n", ret);
			return ret;
		}

		tquic_dbg("sent version negotiation (v1, v2) to client\n");
	}

	return 0;
}

/*
 * Send version negotiation response (server side) - UNUSED
 */
static int __maybe_unused tquic_send_version_negotiation_internal(struct sock *sk,
					  const struct sockaddr *addr,
					  const u8 *dcid, u8 dcid_len,
					  const u8 *scid, u8 scid_len)
{
	struct sk_buff *skb;
	u8 *p;
	static const u32 supported_versions[] = {
		TQUIC_VERSION_1,
		TQUIC_VERSION_2,
	};
	int i;
	size_t pkt_len;

	pkt_len = 7 + dcid_len + scid_len + sizeof(supported_versions);

	skb = alloc_skb(pkt_len + MAX_HEADER, GFP_ATOMIC);
	if (!skb)
		return -ENOMEM;

	skb_reserve(skb, MAX_HEADER);
	p = skb_put(skb, pkt_len);

	/* First byte with random bits, long header form */
	get_random_bytes(p, 1);
	p[0] |= TQUIC_HEADER_FORM_LONG;
	p++;

	/* Version = 0 for version negotiation */
	memset(p, 0, 4);
	p += 4;

	/* DCID (echo back client's SCID) */
	*p++ = scid_len;
	memcpy(p, scid, scid_len);
	p += scid_len;

	/* SCID (echo back client's DCID) */
	*p++ = dcid_len;
	memcpy(p, dcid, dcid_len);
	p += dcid_len;

	/* Supported versions */
	for (i = 0; i < ARRAY_SIZE(supported_versions); i++) {
		*p++ = (supported_versions[i] >> 24) & 0xff;
		*p++ = (supported_versions[i] >> 16) & 0xff;
		*p++ = (supported_versions[i] >> 8) & 0xff;
		*p++ = supported_versions[i] & 0xff;
	}

	/* Send via UDP */
	/* This would use the socket's send path */
	kfree_skb(skb);

	return 0;
}

/*
 * =============================================================================
 * Frame Demultiplexing
 * =============================================================================
 */

/*
 * Process PADDING frame
 *
 * RFC 9000 Section 19.1: A PADDING frame has no semantic value and
 * can be used to increase the size of a packet. Limit the scan
 * to prevent CPU exhaustion on very large encrypted payloads.
 *
 * SECURITY: Limit padding to typical MTU size (1500 bytes).
 * Attackers could send excessive padding to waste CPU cycles.
 * We use memchr() for efficient scanning instead of byte-by-byte loop.
 */
#define TQUIC_MAX_PADDING_BYTES	1500

static int tquic_process_padding_frame(struct tquic_rx_ctx *ctx)
{
	u32 start = ctx->offset;
	u32 limit = min_t(u32, ctx->len, start + TQUIC_MAX_PADDING_BYTES);

	/*
	 * Optimization: Scan padding bytes efficiently.
	 * While memchr() can't directly find non-zero bytes,
	 * we use a simple loop which is well-optimized by
	 * modern compilers and CPUs.
	 */
	while (ctx->offset < limit && ctx->data[ctx->offset] == 0)
		ctx->offset++;

	/*
	 * If we hit the limit and there's still padding, reject as
	 * excessive. Legitimate QUIC packets are at most ~1500 bytes
	 * (PMTU), not more.
	 */
	if (ctx->offset >= limit && ctx->offset < ctx->len &&
	    ctx->data[ctx->offset] == 0)
		return -EINVAL;

	return 0;
}

/*
 * Process PING frame
 */
static int tquic_process_ping_frame(struct tquic_rx_ctx *ctx)
{
	ctx->offset++;  /* Skip frame type */
	ctx->ack_eliciting = true;

	return 0;
}

/*
 * Process ACK frame (0x02) or ACK_ECN frame (0x03)
 *
 * ACK frame format (RFC 9000 Section 19.3):
 *   Largest Acknowledged (varint)
 *   ACK Delay (varint)
 *   ACK Range Count (varint)
 *   First ACK Range (varint)
 *   [ACK Ranges...]
 *
 * ACK_ECN frame adds (RFC 9000 Section 19.3.2):
 *   ECT(0) Count (varint)
 *   ECT(1) Count (varint)
 *   ECN-CE Count (varint)
 */
static int tquic_process_ack_frame(struct tquic_rx_ctx *ctx)
{
	u64 largest_ack, ack_delay, ack_range_count, first_ack_range;
	u64 ecn_ect0 = 0, ecn_ect1 = 0, ecn_ce = 0;
	bool has_ecn;
	u8 frame_type;
	int ret;
	u64 i;

	frame_type = ctx->data[ctx->offset];
	has_ecn = (frame_type == TQUIC_FRAME_ACK_ECN);
	ctx->offset++;  /* Skip frame type */

	/* Largest Acknowledged */
	ret = tquic_decode_varint(ctx->data + ctx->offset,
				  ctx->len - ctx->offset, &largest_ack);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	/* ACK Delay */
	ret = tquic_decode_varint(ctx->data + ctx->offset,
				  ctx->len - ctx->offset, &ack_delay);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	/* ACK Range Count */
	ret = tquic_decode_varint(ctx->data + ctx->offset,
				  ctx->len - ctx->offset, &ack_range_count);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	/* First ACK Range */
	ret = tquic_decode_varint(ctx->data + ctx->offset,
				  ctx->len - ctx->offset, &first_ack_range);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	/* Reject excessive ACK ranges to prevent resource exhaustion */
	if (ack_range_count > TQUIC_MAX_ACK_RANGES)
		return -EINVAL;

	/*
	 * CF-630: Validate largest_ack >= first_ack_range.
	 * Per RFC 9000 Section 19.3.1, the smallest acknowledged in the
	 * first range is largest_ack - first_ack_range. An underflow here
	 * would produce a bogus packet number.
	 */
	if (first_ack_range > largest_ack)
		return -EINVAL;

	/*
	 * Process additional ACK ranges.
	 *
	 * Track smallest_acked to validate that gap and range values
	 * do not underflow the running packet number. Per RFC 9000
	 * Section 19.3.1, each gap skips gap+2 packet numbers, and
	 * each range covers range+1 packet numbers.
	 *
	 * We must validate both individual and cumulative underflows:
	 * - Individual: each gap/range must not exceed remaining space
	 * - Cumulative: total must not wrap around to produce invalid pn
	 */
	{
		u64 smallest_acked = largest_ack - first_ack_range;
		u64 cumulative_gap = first_ack_range;

		for (i = 0; i < ack_range_count; i++) {
			u64 gap, range;

			ret = tquic_decode_varint(ctx->data + ctx->offset,
						  ctx->len - ctx->offset,
						  &gap);
			if (ret < 0)
				return ret;
			ctx->offset += ret;

			ret = tquic_decode_varint(ctx->data + ctx->offset,
						  ctx->len - ctx->offset,
						  &range);
			if (ret < 0)
				return ret;
			ctx->offset += ret;

			/* Validate gap does not underflow */
			if (gap + 2 > smallest_acked)
				return -EPROTO;

			/* Check cumulative overflow before updating */
			if (cumulative_gap > U64_MAX - (gap + 2))
				return -EPROTO;
			cumulative_gap += gap + 2;

			smallest_acked -= gap + 2;

			/* Validate range does not underflow */
			if (range > smallest_acked)
				return -EPROTO;

			/* Check cumulative overflow before updating */
			if (cumulative_gap > U64_MAX - range)
				return -EPROTO;
			cumulative_gap += range;

			smallest_acked -= range;
		}

		/* Final validation: cumulative must not exceed largest_ack */
		if (cumulative_gap > largest_ack)
			return -EPROTO;
	}

	/*
	 * ECN counts (ACK_ECN frame only)
	 *
	 * Per RFC 9000 Section 19.3.2:
	 * - ECT(0) Count: packets received with ECT(0) codepoint
	 * - ECT(1) Count: packets received with ECT(1) codepoint
	 * - ECN-CE Count: packets received with ECN-CE codepoint
	 *
	 * Per RFC 9002 Section 7.1:
	 * "Each increase in the ECN-CE counter is a signal of congestion."
	 *
	 * Per CONTEXT.md: "ECN support: available but off by default"
	 */
	if (has_ecn) {
		/* ECT(0) Count */
		ret = tquic_decode_varint(ctx->data + ctx->offset,
					  ctx->len - ctx->offset, &ecn_ect0);
		if (ret < 0)
			return ret;
		ctx->offset += ret;

		/* ECT(1) Count */
		ret = tquic_decode_varint(ctx->data + ctx->offset,
					  ctx->len - ctx->offset, &ecn_ect1);
		if (ret < 0)
			return ret;
		ctx->offset += ret;

		/* ECN-CE Count */
		ret = tquic_decode_varint(ctx->data + ctx->offset,
					  ctx->len - ctx->offset, &ecn_ce);
		if (ret < 0)
			return ret;
		ctx->offset += ret;

		/*
		 * Update MIB counters for ECN frames received.
		 *
		 * RFC 9000 Section 13.4.2.1: ECN counts are cumulative.
		 * They MUST NOT decrease; a decrease indicates a peer
		 * bug or attack and is treated as PROTOCOL_VIOLATION.
		 * Only the delta since the last ACK_ECN is added to MIB
		 * counters to avoid double-counting.
		 *
		 * SECURITY: Also validate that deltas are reasonable to
		 * prevent integer overflow attacks or resource exhaustion.
		 */
		if (ctx->conn && ctx->conn->sk && ctx->path) {
			struct net *net = sock_net(ctx->conn->sk);
			struct tquic_path *p = ctx->path;
			u64 ect0_delta, ect1_delta, ce_delta;

			/* Validate counters don't decrease */
			if (ecn_ect0 < p->ecn_ect0_count_prev ||
			    ecn_ect1 < p->ecn_ect1_count_prev ||
			    ecn_ce < p->ecn_ce_count_prev) {
				tquic_dbg("ECN counts decreased: ect0 %llu->%llu ect1 %llu->%llu ce %llu->%llu\n",
					 p->ecn_ect0_count_prev, ecn_ect0,
					 p->ecn_ect1_count_prev, ecn_ect1,
					 p->ecn_ce_count_prev, ecn_ce);
				return -EPROTO;
			}

			/* Calculate deltas */
			ect0_delta = ecn_ect0 - p->ecn_ect0_count_prev;
			ect1_delta = ecn_ect1 - p->ecn_ect1_count_prev;
			ce_delta = ecn_ce - p->ecn_ce_count_prev;

			/*
			 * H-002: Validate delta reasonableness with path-aware limit.
			 * ECN counters should not increase by more than packets we
			 * could have sent. Use cwnd-based calculation: allow up to
			 * 10 congestion windows worth of packets to accommodate
			 * bursty traffic patterns while preventing abuse.
			 *
			 * Max reasonable delta = (cwnd * 10) / mtu
			 * This ensures the limit scales with path capacity.
			 */
			if (p->mtu > 0) {
				u64 max_reasonable_delta = (p->cc.cwnd * 10ULL) / p->mtu;

				if (ect0_delta > max_reasonable_delta ||
				    ect1_delta > max_reasonable_delta ||
				    ce_delta > max_reasonable_delta) {
					tquic_warn("ECN delta exceeds path capacity: ect0=%llu ect1=%llu ce=%llu (max=%llu, cwnd=%u, mtu=%u)\n",
						  ect0_delta, ect1_delta, ce_delta,
						  max_reasonable_delta, p->cc.cwnd, p->mtu);
					return -EPROTO;
				}
			}

			TQUIC_INC_STATS(net, TQUIC_MIB_ECNACKSRX);
			if (ect0_delta > 0)
				TQUIC_ADD_STATS(net, TQUIC_MIB_ECNECT0RX,
						ect0_delta);
			if (ect1_delta > 0)
				TQUIC_ADD_STATS(net, TQUIC_MIB_ECNECT1RX,
						ect1_delta);
			if (ce_delta > 0) {
				TQUIC_ADD_STATS(net, TQUIC_MIB_ECNCEMARKSRX,
						ce_delta);
				/*
				 * RFC 9002 Section 7.1: notify congestion
				 * control of the CE increase on this path.
				 */
				tquic_cong_on_ecn(p, ce_delta);
			}

			tquic_dbg("ECN on path %u: ect0=%llu ect1=%llu ce=%llu\n",
				 p->path_id, ecn_ect0, ecn_ect1, ecn_ce);

			p->ecn_ect0_count_prev = ecn_ect0;
			p->ecn_ect1_count_prev = ecn_ect1;
			p->ecn_ce_count_prev = ecn_ce;
		}
	}

	/*
	 * Update RTT estimate and notify congestion control.
	 *
	 * RFC 9002 Section 5.1: An RTT sample is generated using only
	 * the largest acknowledged packet in the received ACK frame.
	 * The RTT is measured from when the packet was sent (sent_time)
	 * to now, minus the peer's reported ack_delay.
	 */
	if (ctx->path && ctx->conn && ctx->conn->pn_spaces) {
		ktime_t now = ktime_get();
		ktime_t sent_time;
		unsigned long pn_flags;
		int pn_space_idx;
		int lookup_ret;
		/* C-5: use negotiated ack_delay_exponent per RFC 9000 Section 19.3 */
		u8 ade = ctx->conn->remote_params.ack_delay_exponent;
		u64 ack_delay_us;
		u64 rtt_us;
		struct tquic_pn_space *pns;

		/*
		 * Map encryption level to packet number space.
		 * Initial -> 0, Handshake -> 1, 0-RTT/1-RTT -> 2
		 */
		switch (ctx->enc_level) {
		case TQUIC_PKT_INITIAL:
			pn_space_idx = TQUIC_PN_SPACE_INITIAL;
			break;
		case TQUIC_PKT_HANDSHAKE:
			pn_space_idx = TQUIC_PN_SPACE_HANDSHAKE;
			break;
		default:
			pn_space_idx = TQUIC_PN_SPACE_APPLICATION;
			break;
		}

		pns = &ctx->conn->pn_spaces[pn_space_idx];

		/*
		 * Look up the sent_time of the largest acked packet.
		 * If we cannot find it (already removed or never
		 * tracked), skip the RTT sample entirely rather than
		 * feeding garbage into the estimator.
		 */
		spin_lock_irqsave(&pns->lock, pn_flags);
		lookup_ret = tquic_pn_space_get_sent_time(pns, largest_ack,
							  &sent_time);
		spin_unlock_irqrestore(&pns->lock, pn_flags);

		if (lookup_ret == 0) {
			rtt_us = ktime_us_delta(now, sent_time);

			/*
			 * Clamp ade to RFC 9000 maximum of 20, then
			 * check for overflow before shifting.
			 */
			ade = min_t(u8, ade, 20);
			if (ack_delay > (16000000ULL >> ade))
				ack_delay_us = 16000000ULL;
			else
				ack_delay_us = ack_delay << ade;

			if (rtt_us > ack_delay_us)
				rtt_us -= ack_delay_us;

			/* Update MIB counter for RTT sample */
			if (ctx->conn->sk)
				TQUIC_INC_STATS(sock_net(ctx->conn->sk),
						TQUIC_MIB_RTTSAMPLES);

			/*
			 * Calculate bytes acknowledged from first_ack_range.
			 *
			 * H-1: use actual path MTU instead of hardcoded 1200.
			 * CF-073: Use safe arithmetic to prevent overflow.
			 * C-002 FIX: Reject frame on overflow instead of using
			 * fallback values that could manipulate congestion control.
			 */
			{
				u64 acked_pkts, bytes_acked;
				u64 mtu = (ctx->path->mtu > 0) ?
					ctx->path->mtu : 1200;

				if (check_add_overflow(first_ack_range,
						       (u64)1, &acked_pkts))
					return -EPROTO;
				if (check_mul_overflow(acked_pkts, mtu,
						       &bytes_acked))
					return -EPROTO;

				/* Dispatch ACK event to congestion control */
				tquic_cong_on_ack(ctx->path, bytes_acked,
						  rtt_us);

				/* Update RTT in CC algorithm */
				tquic_cong_on_rtt(ctx->path, rtt_us);
			}
		}

		/*
		 * ECN CE congestion response already dispatched in the
		 * MIB delta section above via tquic_cong_on_ecn().
		 */
	}

	/* Mark acknowledged packets - processed by CC above */

	return 0;
}

/*
 * Process CRYPTO frame
 */
static int tquic_process_crypto_frame(struct tquic_rx_ctx *ctx)
{
	u64 offset, length;
	int ret;

	ctx->offset++;  /* Skip frame type */

	/* Offset */
	ret = tquic_decode_varint(ctx->data + ctx->offset,
				  ctx->len - ctx->offset, &offset);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	/* Length */
	ret = tquic_decode_varint(ctx->data + ctx->offset,
				  ctx->len - ctx->offset, &length);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	/*
	 * SECURITY: Validate CRYPTO frame length to prevent integer overflow.
	 * length is u64 from varint decode (up to 2^62-1). On 32-bit systems
	 * adding to size_t ctx->offset could overflow/wrap. Also reject
	 * frames larger than the packet itself as obviously malformed.
	 */
	{
		size_t end_offset;

		if (length > ctx->len ||
		    check_add_overflow(ctx->offset, (size_t)length, &end_offset) ||
		    end_offset > ctx->len)
			return -EINVAL;
	}

	/*
	 * SECURITY: Check pre-handshake memory allocation limits before
	 * processing CRYPTO frames at Initial/Handshake level.
	 * This prevents resource exhaustion from bogus Initial packets.
	 */
	if (ctx->enc_level == TQUIC_PKT_INITIAL ||
	    ctx->enc_level == TQUIC_PKT_HANDSHAKE) {
		if (ctx->conn && ctx->path &&
		    !tquic_pre_hs_can_allocate(&ctx->path->remote_addr,
					       (size_t)length)) {
			tquic_dbg("CRYPTO frame rejected: pre-HS memory limit\n");
			return -ENOMEM;
		}
	}

	/*
	 * Feed CRYPTO frame data into the inline TLS handshake state machine.
	 * The data is a TLS handshake message (ClientHello, ServerHello, etc.)
	 * carried in the CRYPTO frame payload.
	 *
	 * Per RFC 9001 Section 4: "CRYPTO frames can be sent at all encryption
	 * levels except 0-RTT."
	 */
	if (ctx->conn && ctx->conn->tsk && ctx->conn->tsk->inline_hs) {
		struct sock *sk = (struct sock *)ctx->conn->tsk;

		/*
		 * SECURITY: Validate length fits in u32 before cast.
		 * CRYPTO frames carrying TLS messages should never exceed
		 * practical limits. Reject oversized frames.
		 */
		if (length > U32_MAX)
			return -EINVAL;
		ret = tquic_inline_hs_recv_crypto(sk,
						  ctx->data + ctx->offset,
						  (u32)length,
						  ctx->enc_level);
		if (ret < 0) {
			tquic_dbg("CRYPTO frame processing failed: %d\n",
				 ret);
			ctx->offset += length;
			return ret;
		}
	} else {
		tquic_dbg("CRYPTO frame received but no inline handshake active\n");
	}

	ctx->offset += length;
	ctx->ack_eliciting = true;

	return 0;
}

/*
 * Process STREAM frame
 */
static int tquic_process_stream_frame(struct tquic_rx_ctx *ctx)
{
	u8 frame_type = ctx->data[ctx->offset];
	u64 stream_id, offset = 0, length;
	bool has_offset, has_length, fin;
	struct tquic_stream *stream;
	struct sk_buff *data_skb;
	int ret;

	/* Parse frame type flags */
	has_offset = (frame_type & 0x04) != 0;
	has_length = (frame_type & 0x02) != 0;
	fin = (frame_type & 0x01) != 0;

	ctx->offset++;  /* Skip frame type */

	/* Stream ID */
	ret = tquic_decode_varint(ctx->data + ctx->offset,
				  ctx->len - ctx->offset, &stream_id);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	/* Offset (optional) */
	if (has_offset) {
		ret = tquic_decode_varint(ctx->data + ctx->offset,
					  ctx->len - ctx->offset, &offset);
		if (ret < 0)
			return ret;
		ctx->offset += ret;
	}

	/* Length (optional) */
	if (has_length) {
		ret = tquic_decode_varint(ctx->data + ctx->offset,
					  ctx->len - ctx->offset, &length);
		if (ret < 0)
			return ret;
		ctx->offset += ret;
	} else {
		/* Length extends to end of packet */
		length = ctx->len - ctx->offset;
		/*
		 * RFC 9000 Section 19.8: A STREAM frame with no Length field
		 * consumes all remaining bytes in the packet. No further
		 * frames can follow -- record this so the frame loop can
		 * reject any trailing data.
		 */
		ctx->saw_stream_no_length = true;
	}

	if (length > 65535)
		return -EINVAL;

	if (ctx->offset + length > ctx->len)
		return -EINVAL;

	/*
	 * Lookup stream under conn->lock (stream tree lock per protocol.h),
	 * then take a reference before dropping the lock so the stream remains
	 * valid for processing.
	 */
	stream = NULL;
	spin_lock_bh(&ctx->conn->lock);
	{
		struct rb_node *node = ctx->conn->streams.rb_node;

		while (node) {
			struct tquic_stream *s = rb_entry(node,
							  struct tquic_stream, node);

			if (stream_id < s->id) {
				node = node->rb_left;
			} else if (stream_id > s->id) {
				node = node->rb_right;
			} else {
				if (tquic_stream_get(s))
					stream = s;
				break;
			}
		}
	}
	spin_unlock_bh(&ctx->conn->lock);

	if (!stream) {
		/*
		 * Stream not found. Create new incoming stream.
		 * tquic_stream_open_incoming() handles concurrent creation
		 * attempts internally by checking the tree under conn->lock.
		 */
		stream = tquic_stream_open_incoming(ctx->conn, stream_id);
		if (!stream)
			return -ENOMEM;
	}

	/*
	 * M-001: Enforce hard per-frame allocation limit FIRST.
	 * A single STREAM frame must not allocate more than 64KB,
	 * regardless of socket buffer size. This prevents DoS via
	 * large single-frame allocations.
	 */
	if (length > TQUIC_MAX_STREAM_FRAME_ALLOC) {
		tquic_stream_put(stream);
		return -EMSGSIZE;
	}

	/*
	 * CF-231: Check receive buffer memory BEFORE allocating the skb.
	 * The `length` field comes from the peer (attacker-controlled)
	 * and drives the alloc_skb() size below.
	 *
	 * Use sk_rmem_schedule() which atomically checks and reserves
	 * buffer space, preventing races where multiple threads could
	 * exceed the buffer limit between check and allocation.
	 *
	 * Cap allocation to socket receive buffer size so a single
	 * frame cannot trigger an unreasonably large kmalloc.
	 */
	if (ctx->conn->sk) {
		struct sock *sk = ctx->conn->sk;

		/* Cap allocation to remaining buffer capacity */
		if (length > (u64)sk->sk_rcvbuf) {
			ctx->offset += length;
			ctx->ack_eliciting = true;
			tquic_stream_put(stream);
			return 0;
		}
	}

	/*
	 * Validate BEFORE allocating/enqueuing to prevent SKB leaks.
	 * All checks that can return -EPROTO must happen before the
	 * skb is allocated and enqueued into stream->recv_buf.
	 */

	/*
	 * SECURITY: Validate stream offset + length against RFC 9000 limit.
	 * Per Section 4.5: "An endpoint MUST treat receipt of data at or
	 * beyond the final size as a connection error." The maximum stream
	 * offset is 2^62-1. Check for overflow before proceeding.
	 */
	if (offset > ((1ULL << 62) - 1) - length) {
		tquic_stream_put(stream);
		return -EPROTO;
	}

	if (fin) {
		u64 final_size = offset + length;

		/*
		 * CF-349: RFC 9000 Section 4.5 - Final size consistency.
		 * If we already know the final size, it must match.
		 * Also, data beyond the final size is a protocol error.
		 */
		if (stream->fin_received && stream->final_size != final_size) {
			tquic_stream_put(stream);
			return -EPROTO;
		}
	} else if (stream->fin_received) {
		/* Data beyond the known final size is an error */
		if (offset + length > stream->final_size) {
			tquic_stream_put(stream);
			return -EPROTO;
		}
	}

	/*
	 * RFC 9000 Section 4.1: Enforce receive flow control limits.
	 * Check both stream-level and connection-level limits before
	 * accepting the data.
	 */
	if (tquic_flow_check_recv_limits(stream, offset, length)) {
		tquic_stream_put(stream);
		return -EDQUOT;
	}

	/* Copy data to stream receive buffer */
	data_skb = alloc_skb(length, GFP_ATOMIC);
	if (!data_skb) {
		tquic_stream_put(stream);
		return -ENOMEM;
	}

	skb_put_data(data_skb, ctx->data + ctx->offset, length);

	/* Store offset in skb->cb for reordering */
	put_unaligned(offset, (u64 *)data_skb->cb);

	/*
	 * Atomically reserve receive buffer space and charge it to the socket.
	 * sk_rmem_schedule() prevents races where multiple threads allocate
	 * simultaneously and exceed the buffer limit. If reservation fails,
	 * free the skb and silently drop (peer will retransmit).
	 */
	if (ctx->conn->sk) {
		if (!sk_rmem_schedule(ctx->conn->sk, data_skb, length)) {
			/* Buffer full - drop packet, peer will retransmit */
			kfree_skb(data_skb);
			ctx->offset += length;
			ctx->ack_eliciting = true;
			tquic_stream_put(stream);
			return 0;
		}
		skb_set_owner_r(data_skb, ctx->conn->sk);
	}

	skb_queue_tail(&stream->recv_buf, data_skb);

	/* Update recv_offset and final_size after successful enqueue */
	stream->recv_offset = max(stream->recv_offset, offset + length);

	if (fin && !stream->fin_received) {
		stream->fin_received = true;
		stream->final_size = offset + length;
	}

	/* Notify flow control of received data */
	tquic_flow_on_stream_data_recvd(stream, offset, length);

	ctx->offset += length;
	ctx->ack_eliciting = true;

	/* Update connection stats */
	ctx->conn->stats.rx_bytes += length;

	/*
	 * P-003: Release the stream reference we acquired during RCU lookup.
	 * The stream data has been safely enqueued, so we no longer need
	 * to hold the reference.
	 */
	tquic_stream_put(stream);

	return 0;
}

/*
 * Process MAX_DATA frame
 */
static int tquic_process_max_data_frame(struct tquic_rx_ctx *ctx)
{
	u64 max_data;
	int ret;

	ctx->offset++;  /* Skip frame type */

	ret = tquic_decode_varint(ctx->data + ctx->offset,
				  ctx->len - ctx->offset, &max_data);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	/* Update remote's max data limit */
	spin_lock_bh(&ctx->conn->lock);
	ctx->conn->max_data_remote = max(ctx->conn->max_data_remote, max_data);
	spin_unlock_bh(&ctx->conn->lock);

	ctx->ack_eliciting = true;

	return 0;
}

/*
 * Process MAX_STREAM_DATA frame
 */
static int tquic_process_max_stream_data_frame(struct tquic_rx_ctx *ctx)
{
	u64 stream_id, max_data;
	int ret;

	ctx->offset++;  /* Skip frame type */

	/* Stream ID */
	ret = tquic_decode_varint(ctx->data + ctx->offset,
				  ctx->len - ctx->offset, &stream_id);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	/* Max Data */
	ret = tquic_decode_varint(ctx->data + ctx->offset,
				  ctx->len - ctx->offset, &max_data);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	/* Find stream and update limit */
	/* Simplified: lookup omitted */

	ctx->ack_eliciting = true;

	return 0;
}

/*
 * Process PATH_CHALLENGE frame
 */
static int tquic_process_path_challenge_frame(struct tquic_rx_ctx *ctx)
{
	u8 data[8];
	int ret;

	ctx->offset++;  /* Skip frame type */

	if (ctx->offset + 8 > ctx->len)
		return -EINVAL;

	memcpy(data, ctx->data + ctx->offset, 8);
	ctx->offset += 8;

	/* Handle challenge through path validation module */
	ret = tquic_path_handle_challenge(ctx->conn, ctx->path, data);
	if (ret < 0 && ret != -ENOBUFS) {
		/* Log error but don't fail packet processing */
		tquic_dbg("PATH_CHALLENGE handling failed: %d\n", ret);
	}

	ctx->ack_eliciting = true;

	return 0;
}

/*
 * Process PATH_RESPONSE frame
 */
static int tquic_process_path_response_frame(struct tquic_rx_ctx *ctx)
{
	u8 data[8];
	int ret;

	ctx->offset++;  /* Skip frame type */

	if (ctx->offset + 8 > ctx->len)
		return -EINVAL;

	memcpy(data, ctx->data + ctx->offset, 8);
	ctx->offset += 8;

	/* Handle response through path validation module */
	ret = tquic_path_handle_response(ctx->conn, ctx->path, data);
	if (ret == 0) {
		/* Update MIB counter for successful path validation */
		if (ctx->conn && ctx->conn->sk)
			TQUIC_INC_STATS(sock_net(ctx->conn->sk), TQUIC_MIB_PATHVALIDATED);
	}

	ctx->ack_eliciting = true;

	return 0;
}

/*
 * Process NEW_CONNECTION_ID frame
 */
static int tquic_process_new_connection_id_frame(struct tquic_rx_ctx *ctx)
{
	u64 seq_num, retire_prior_to;
	u8 cid_len;
	u8 cid[TQUIC_MAX_CID_LEN];
	u8 reset_token[16];
	int ret;

	ctx->offset++;  /* Skip frame type */

	/* Sequence Number */
	ret = tquic_decode_varint(ctx->data + ctx->offset,
				  ctx->len - ctx->offset, &seq_num);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	/* Retire Prior To */
	ret = tquic_decode_varint(ctx->data + ctx->offset,
				  ctx->len - ctx->offset, &retire_prior_to);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	/* Connection ID Length */
	if (ctx->offset >= ctx->len)
		return -EINVAL;
	cid_len = ctx->data[ctx->offset++];

	if (cid_len > TQUIC_MAX_CID_LEN)
		return -EINVAL;

	/* Connection ID */
	if (ctx->offset + cid_len > ctx->len)
		return -EINVAL;
	memcpy(cid, ctx->data + ctx->offset, cid_len);
	ctx->offset += cid_len;

	/* Stateless Reset Token */
	if (ctx->offset + 16 > ctx->len)
		return -EINVAL;
	memcpy(reset_token, ctx->data + ctx->offset, 16);
	ctx->offset += 16;

	/*
	 * SECURITY: Check CID security limits before processing.
	 * This prevents CVE-2024-22189 Retire CID stuffing attacks
	 * by rate-limiting NEW_CONNECTION_ID frames.
	 */
	if (ctx->conn && ctx->conn->cid_pool) {
		struct tquic_cid_pool *pool = ctx->conn->cid_pool;
		int sret;

		sret = tquic_cid_security_check_new_cid(&pool->security);
		if (sret < 0) {
			tquic_dbg("NEW_CONNECTION_ID rejected by security check: %d\n",
				 sret);
			return sret;
		}
	}

	/* Store new CID for future use */
	/* This would be added to a CID pool */

	/*
	 * CF-249: RFC 9000 Section 19.15 requires retiring CIDs with
	 * sequence numbers less than retire_prior_to. Validate
	 * retire_prior_to <= seq_num per RFC 9000 Section 19.15:
	 * "A value of retire_prior_to greater than seq_num is an
	 * error of type FRAME_ENCODING_ERROR."
	 */
	if (retire_prior_to > seq_num) {
		tquic_dbg("NEW_CONNECTION_ID: retire_prior_to %llu > seq %llu\n",
			  retire_prior_to, seq_num);
		return -EINVAL;
	}

	/*
	 * Retire CIDs with sequence numbers below retire_prior_to.
	 * Only retire newly-covered CIDs to prevent DoS from large
	 * retire_prior_to values (up to 2^62) causing kernel soft lockup.
	 * Also cap per-frame iteration as defense in depth.
	 */
	if (ctx->conn && retire_prior_to > 0) {
		u64 prev_retire = ctx->conn->cid_retire_prior_to;

		if (retire_prior_to > prev_retire) {
			u64 i;
			u64 count = 0;

			for (i = prev_retire; i < retire_prior_to; i++) {
				tquic_conn_retire_cid(ctx->conn, i, false);
				if (++count >= 256)
					break;
			}
			ctx->conn->cid_retire_prior_to = retire_prior_to;
		}
	}

	ctx->ack_eliciting = true;

	return 0;
}

/*
 * Process RETIRE_CONNECTION_ID frame
 */
static int tquic_process_retire_connection_id_frame(struct tquic_rx_ctx *ctx)
{
	u64 seq_num;
	int ret;

	ctx->offset++;  /* Skip frame type */

	ret = tquic_decode_varint(ctx->data + ctx->offset,
				  ctx->len - ctx->offset, &seq_num);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	/* Remove CID from active set */
	/* This would update the CID pool */

	ctx->ack_eliciting = true;

	return 0;
}

/*
 * Process CONNECTION_CLOSE frame
 */
static int tquic_process_connection_close_frame(struct tquic_rx_ctx *ctx, bool app)
{
	u64 error_code, frame_type = 0, reason_len;
	int ret;

	ctx->offset++;  /* Skip frame type */

	/* Error Code */
	ret = tquic_decode_varint(ctx->data + ctx->offset,
				  ctx->len - ctx->offset, &error_code);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	/* Frame Type (only for transport close) */
	if (!app) {
		ret = tquic_decode_varint(ctx->data + ctx->offset,
					  ctx->len - ctx->offset, &frame_type);
		if (ret < 0)
			return ret;
		ctx->offset += ret;
	}

	/* Reason Phrase Length */
	ret = tquic_decode_varint(ctx->data + ctx->offset,
				  ctx->len - ctx->offset, &reason_len);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	/*
	 * SECURITY: Validate reason phrase length to prevent integer overflow
	 * and resource abuse. reason_len is u64 from varint (up to 2^62-1).
	 * Cap to a sane maximum to prevent allocation/processing abuse.
	 * RFC 9000 does not specify a maximum, but reason phrases exceeding
	 * the packet size are always invalid.
	 */
	if (reason_len > ctx->len - ctx->offset)
		return -EINVAL;

	/* Enforce a reasonable maximum for the reason phrase */
	if (reason_len > 1024) {
		pr_warn_ratelimited("tquic: CONNECTION_CLOSE reason phrase too long (%llu)\n",
				    reason_len);
		return -EINVAL;
	}
	ctx->offset += (size_t)reason_len;

	pr_info_ratelimited("tquic: received CONNECTION_CLOSE, error=%llu frame_type=%llu\n",
			    error_code, frame_type);

	/*
	 * Transition to draining state via connection close handler.
	 * Use tquic_conn_handle_close() which properly validates state
	 * transitions rather than bypassing the state machine.
	 */
	tquic_conn_handle_close(ctx->conn, error_code, frame_type,
				NULL, app);

	/* Update MIB counters for connection close */
	if (ctx->conn && ctx->conn->sk) {
		TQUIC_DEC_STATS(sock_net(ctx->conn->sk), TQUIC_MIB_CURRESTAB);
		if (error_code == EQUIC_NO_ERROR)
			TQUIC_INC_STATS(sock_net(ctx->conn->sk), TQUIC_MIB_CONNCLOSED);
		else
			TQUIC_INC_STATS(sock_net(ctx->conn->sk), TQUIC_MIB_CONNRESET);

		/* Track specific EQUIC error */
		enum linux_tquic_mib_field mib_field = tquic_equic_to_mib(error_code);
		if (mib_field != TQUIC_MIB_NUM)
			TQUIC_INC_STATS(sock_net(ctx->conn->sk), mib_field);
	}

	return 0;
}

/*
 * Process HANDSHAKE_DONE frame
 */
static int tquic_process_handshake_done_frame(struct tquic_rx_ctx *ctx)
{
	ctx->offset++;  /* Skip frame type */

	/*
	 * RFC 9000 Section 19.20: "A server MUST NOT send a
	 * HANDSHAKE_DONE frame." Therefore only clients process it.
	 * Servers receiving HANDSHAKE_DONE is a protocol violation.
	 */
	if (ctx->conn->is_server) {
		tquic_dbg("server received HANDSHAKE_DONE - protocol violation\n");
		ctx->conn->error_code = EQUIC_PROTOCOL_VIOLATION;
		return -EPROTO;
	}

	/* Mark handshake as complete (client side) */
	if (ctx->conn->crypto_state)
		ctx->conn->handshake_confirmed = true;

	/*
	 * CF-096: Transition to CONNECTED atomically.
	 *
	 * Use WRITE_ONCE() for the state assignment and validate
	 * the transition under the lock.  Only CONNECTING ->
	 * CONNECTED is valid here (RFC 9000 Section 19.20).
	 * Reject the transition if the connection has already
	 * moved to a later state (e.g. CLOSING due to a
	 * concurrent error), which would be an invalid backward
	 * transition.
	 *
	 * Also notify the socket layer so poll/epoll waiters see
	 * the new state promptly.
	 */
	spin_lock_bh(&ctx->conn->lock);
	if (ctx->conn->state == TQUIC_CONN_CONNECTING) {
		WRITE_ONCE(ctx->conn->state, TQUIC_CONN_CONNECTED);
		ctx->conn->handshake_complete = true;
		ctx->conn->stats.established_time = ktime_get();
		if (ctx->conn->sk)
			ctx->conn->sk->sk_state_change(ctx->conn->sk);
	}
	spin_unlock_bh(&ctx->conn->lock);

	ctx->ack_eliciting = true;

	return 0;
}

/*
 * Process NEW_TOKEN frame (RFC 9000 Section 8.1.3-8.1.4)
 *
 * NEW_TOKEN frames provide address validation tokens to clients
 * for use in future connections. This allows skipping the address
 * validation handshake on subsequent connections from the same client.
 *
 * Frame format:
 *   Type (0x07): 1 byte
 *   Token Length: varint
 *   Token: Token Length bytes
 *
 * Per RFC 9000: "A client MUST NOT send a NEW_TOKEN frame."
 * Only servers send NEW_TOKEN frames after handshake completion.
 */
static int tquic_process_new_token(struct tquic_rx_ctx *ctx)
{
	u64 token_len;
	int ret;

	ctx->offset++;  /* Skip frame type */

	/* Parse token length */
	ret = tquic_decode_varint(ctx->data + ctx->offset,
				  ctx->len - ctx->offset, &token_len);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	/* RFC 9000 Section 19.7: Token MUST NOT be empty */
	if (token_len == 0)
		return -EINVAL;

	/*
	 * RFC 9000 Section 19.7: "A client MUST NOT send a NEW_TOKEN
	 * frame." If we are a server receiving this, the peer (client)
	 * sent it -- that is a protocol violation.
	 */
	if (ctx->conn && ctx->conn->is_server)
		return -EPROTO;

	/* Validate token length */
	if (token_len > TQUIC_TOKEN_MAX_LEN) {
		tquic_dbg("NEW_TOKEN too large: %llu > %u\n",
			 token_len, TQUIC_TOKEN_MAX_LEN);
		return -EINVAL;
	}

	if (ctx->offset + token_len > ctx->len)
		return -EINVAL;

	/* Process the token - delegate to token module */
	ret = tquic_process_new_token_frame(ctx->conn,
					    ctx->data + ctx->offset,
					    token_len);
	if (ret < 0) {
		tquic_dbg("NEW_TOKEN processing failed: %d\n", ret);
		/* Update MIB counter for invalid token */
		if (ctx->conn && ctx->conn->sk)
			TQUIC_INC_STATS(sock_net(ctx->conn->sk), TQUIC_MIB_TOKENSINVALID);
	} else {
		/* Update MIB counter for token received */
		if (ctx->conn && ctx->conn->sk)
			TQUIC_INC_STATS(sock_net(ctx->conn->sk), TQUIC_MIB_NEWTOKENSRX);
	}

	ctx->offset += token_len;
	ctx->ack_eliciting = true;

	tquic_dbg("received NEW_TOKEN, len=%llu\n", token_len);

	return 0;
}

/*
 * Process DATAGRAM frame (RFC 9221)
 *
 * DATAGRAM frames carry unreliable, unordered application data.
 * Unlike STREAM frames, there is no retransmission or ordering.
 *
 * Frame format:
 *   Type (0x30 or 0x31): 1 byte
 *   [Length]: varint (only if Type & 0x01)
 *   Data: remaining bytes
 */
static int tquic_process_datagram_frame(struct tquic_rx_ctx *ctx)
{
	u8 frame_type = ctx->data[ctx->offset];
	bool has_length = (frame_type & 0x01) != 0;
	u64 length;
	struct sk_buff *dgram_skb;
	int ret;

	ctx->offset++;  /* Skip frame type */

	/* Parse length field if present (0x31), otherwise use remaining bytes */
	if (has_length) {
		ret = tquic_decode_varint(ctx->data + ctx->offset,
					  ctx->len - ctx->offset, &length);
		if (ret < 0)
			return ret;
		ctx->offset += ret;
	} else {
		/* Type 0x30: datagram extends to end of packet */
		length = ctx->len - ctx->offset;
	}

	/*
	 * SECURITY: Validate datagram length to prevent integer overflow.
	 * length is u64; compare against remaining bytes (safe size_t)
	 * to avoid overflow in ctx->offset + length on 32-bit.
	 */
	if (length > ctx->len - ctx->offset)
		return -EINVAL;

	/* Check if datagram support is enabled on this connection */
	if (!ctx->conn || !ctx->conn->datagram.enabled) {
		/* RFC 9221: If not negotiated, this is a protocol error */
		tquic_dbg("received DATAGRAM but not negotiated\n");
		return -EPROTO;
	}

	/* Validate against negotiated maximum size */
	if (length > ctx->conn->datagram.max_recv_size) {
		tquic_dbg("DATAGRAM too large: %llu > %llu\n",
			 length, ctx->conn->datagram.max_recv_size);
		return -EMSGSIZE;
	}

	/* Queue datagram for delivery to application */
	spin_lock(&ctx->conn->datagram.lock);

	/* Check queue limit to prevent memory exhaustion */
	if (ctx->conn->datagram.recv_queue_len >=
	    ctx->conn->datagram.recv_queue_max) {
		/* Drop datagram (unreliable, so this is acceptable) */
		ctx->conn->datagram.datagrams_dropped++;
		spin_unlock(&ctx->conn->datagram.lock);
		/* Update MIB counter for dropped datagram */
		if (ctx->conn->sk)
			TQUIC_INC_STATS(sock_net(ctx->conn->sk), TQUIC_MIB_DATAGRAMSDROPPED);
		tquic_dbg("DATAGRAM dropped, queue full\n");
		/* Continue processing - this is not a fatal error */
		ctx->offset += length;
		ctx->ack_eliciting = true;
		return 0;
	}

	/* Allocate SKB for datagram */
	dgram_skb = alloc_skb(length, GFP_ATOMIC);
	if (!dgram_skb) {
		ctx->conn->datagram.datagrams_dropped++;
		spin_unlock(&ctx->conn->datagram.lock);
		/* Update MIB counter for dropped datagram */
		if (ctx->conn->sk)
			TQUIC_INC_STATS(sock_net(ctx->conn->sk), TQUIC_MIB_DATAGRAMSDROPPED);
		ctx->offset += length;
		ctx->ack_eliciting = true;
		return 0;  /* Not fatal, continue */
	}

	/* Copy datagram payload */
	skb_put_data(dgram_skb, ctx->data + ctx->offset, length);

	/* Store receive timestamp in SKB cb -- ensure it fits */
	BUILD_BUG_ON(sizeof(struct timespec64) > sizeof(dgram_skb->cb));
	ktime_get_ts64((struct timespec64 *)dgram_skb->cb);

	/* Queue to receive buffer */
	skb_queue_tail(&ctx->conn->datagram.recv_queue, dgram_skb);
	ctx->conn->datagram.recv_queue_len++;
	ctx->conn->datagram.datagrams_received++;

	spin_unlock(&ctx->conn->datagram.lock);

	/* Update MIB counter for datagram receive */
	if (ctx->conn->sk)
		TQUIC_INC_STATS(sock_net(ctx->conn->sk), TQUIC_MIB_DATAGRAMSRX);

	/*
	 * Wake up waiters on both the datagram-specific wait queue
	 * (for tquic_recv_datagram blocking) and the socket wait queue
	 * (for poll/epoll/select).
	 */
	wake_up_interruptible(&ctx->conn->datagram.wait);
	if (ctx->conn->sk)
		ctx->conn->sk->sk_data_ready(ctx->conn->sk);

	ctx->offset += length;
	ctx->ack_eliciting = true;

	tquic_dbg("received DATAGRAM, len=%llu\n", length);

	return 0;
}

/*
 * Process ACK_FREQUENCY frame (draft-ietf-quic-ack-frequency)
 *
 * ACK_FREQUENCY Frame {
 *   Type (i) = 0xaf,
 *   Sequence Number (i),
 *   Ack-Eliciting Threshold (i),
 *   Request Max Ack Delay (i),
 *   Reorder Threshold (i),
 * }
 *
 * This frame allows the sender to request changes to the peer's ACK behavior.
 */
static int tquic_process_ack_frequency_frame(struct tquic_rx_ctx *ctx)
{
	struct tquic_ack_frequency_frame frame;
	int ret;
	u64 frame_type;

	/* Parse frame type */
	ret = tquic_decode_varint(ctx->data + ctx->offset,
				  ctx->len - ctx->offset, &frame_type);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	/* Parse the frame fields */
	ret = tquic_parse_ack_frequency_frame(ctx->data + ctx->offset,
					      ctx->len - ctx->offset,
					      &frame);
	if (ret < 0)
		return ret;
	ctx->offset += ret;

	/* Handle the frame */
	ret = tquic_conn_handle_ack_frequency_frame(ctx->conn, &frame);
	if (ret < 0)
		return ret;

	ctx->ack_eliciting = true;

	return 0;
}

/*
 * Process IMMEDIATE_ACK frame (draft-ietf-quic-ack-frequency)
 *
 * IMMEDIATE_ACK Frame {
 *   Type (i) = 0xac,
 * }
 *
 * This frame requests that the peer send an ACK immediately.
 */
static int tquic_process_immediate_ack_frame(struct tquic_rx_ctx *ctx)
{
	int ret;
	u64 frame_type;

	/* Parse and validate frame type */
	ret = tquic_decode_varint(ctx->data + ctx->offset,
				  ctx->len - ctx->offset, &frame_type);
	if (ret < 0)
		return ret;

	if (frame_type != TQUIC_FRAME_IMMEDIATE_ACK)
		return -EINVAL;

	ctx->offset += ret;

	/*
	 * SECURITY: Only process the first IMMEDIATE_ACK per packet
	 * to prevent flooding attacks that force excessive ACK generation.
	 */
	if (ctx->immediate_ack_seen) {
		tquic_dbg("duplicate IMMEDIATE_ACK in packet, ignoring\n");
		ctx->ack_eliciting = true;
		return 0;
	}
	ctx->immediate_ack_seen = true;

	/* Handle the frame */
	ret = tquic_conn_handle_immediate_ack_frame(ctx->conn);
	if (ret < 0)
		return ret;

	ctx->ack_eliciting = true;

	tquic_dbg("processed IMMEDIATE_ACK frame\n");

	return 0;
}

/*
 * =============================================================================
 * RFC 9369 Multipath Frame Processing
 * =============================================================================
 */

#ifdef CONFIG_TQUIC_MULTIPATH

#include "multipath/mp_frame.h"
#include "multipath/mp_ack.h"
#include "multipath/path_abandon.h"

/**
 * tquic_is_mp_extended_frame - Check if this is an extended MP frame
 * @ctx: Receive context
 *
 * Extended multipath frames have multi-byte frame types that start with
 * specific prefixes. This function peeks at the frame type without consuming it.
 */
static bool tquic_is_mp_extended_frame(struct tquic_rx_ctx *ctx)
{
	u64 frame_type;
	int ret;

	ret = tquic_decode_varint(ctx->data + ctx->offset,
				  ctx->len - ctx->offset, &frame_type);
	if (ret < 0)
		return false;

	/*
	 * Check for extended multipath frame types.
	 * Only 0x15c0-0x15c3 are defined (PATH_ABANDON, PATH_STATUS,
	 * PATH_STATUS_BACKUP, PATH_STATUS_AVAILABLE).
	 */
	return (frame_type >= 0x15c0 && frame_type <= 0x15c3);
}

static int tquic_process_path_abandon_frame(struct tquic_rx_ctx *ctx);
static int tquic_process_path_status_frame(struct tquic_rx_ctx *ctx);

/**
 * tquic_process_mp_extended_frame - Process extended multipath frames
 * @ctx: Receive context
 *
 * Handles PATH_ABANDON (0x15c0) and PATH_STATUS (0x15c1).
 */
static int tquic_process_mp_extended_frame(struct tquic_rx_ctx *ctx)
{
	u64 frame_type;
	int ret;

	ret = tquic_decode_varint(ctx->data + ctx->offset,
				  ctx->len - ctx->offset, &frame_type);
	if (ret < 0)
		return ret;

	if (frame_type == TQUIC_MP_FRAME_PATH_ABANDON) {
		return tquic_process_path_abandon_frame(ctx);
	} else if (frame_type == TQUIC_MP_FRAME_PATH_STATUS) {
		return tquic_process_path_status_frame(ctx);
	}

	tquic_dbg("unknown extended MP frame type 0x%llx\n", frame_type);
	return -EINVAL;
}

/**
 * tquic_process_path_abandon_frame - Process PATH_ABANDON frame
 * @ctx: Receive context
 *
 * RFC 9369: PATH_ABANDON frame indicates peer is abandoning a path.
 */
static int tquic_process_path_abandon_frame(struct tquic_rx_ctx *ctx)
{
	struct tquic_mp_path_abandon frame;
	int ret;

	ret = tquic_mp_parse_path_abandon(ctx->data + ctx->offset,
					  ctx->len - ctx->offset, &frame);
	if (ret < 0)
		return ret;

	ctx->offset += ret;
	ctx->ack_eliciting = true;

	/* Handle the frame */
	ret = tquic_mp_handle_path_abandon(ctx->conn, &frame);
	if (ret < 0) {
		tquic_dbg("PATH_ABANDON handling failed: %d\n", ret);
		return ret;
	}

	tquic_dbg("processed PATH_ABANDON for path %llu\n", frame.path_id);
	return 0;
}

/**
 * tquic_process_mp_new_connection_id_frame - Process MP_NEW_CONNECTION_ID
 * @ctx: Receive context
 *
 * RFC 9369: MP_NEW_CONNECTION_ID issues path-specific CIDs.
 */
static int tquic_process_mp_new_connection_id_frame(struct tquic_rx_ctx *ctx)
{
	struct tquic_mp_new_connection_id frame;
	int ret;

	ret = tquic_mp_parse_new_connection_id(ctx->data + ctx->offset,
					       ctx->len - ctx->offset, &frame);
	if (ret < 0)
		return ret;

	ctx->offset += ret;
	ctx->ack_eliciting = true;

	/* Handle the frame */
	ret = tquic_mp_handle_new_connection_id(ctx->conn, &frame);
	if (ret < 0) {
		tquic_dbg("MP_NEW_CONNECTION_ID handling failed: %d\n", ret);
		return ret;
	}

	tquic_dbg("processed MP_NEW_CONNECTION_ID path=%llu seq=%llu\n",
		 frame.path_id, frame.seq_num);
	return 0;
}

/**
 * tquic_process_mp_retire_connection_id_frame - Process MP_RETIRE_CONNECTION_ID
 * @ctx: Receive context
 *
 * RFC 9369: MP_RETIRE_CONNECTION_ID retires path-specific CIDs.
 */
static int tquic_process_mp_retire_connection_id_frame(struct tquic_rx_ctx *ctx)
{
	struct tquic_mp_retire_connection_id frame;
	int ret;

	ret = tquic_mp_parse_retire_connection_id(ctx->data + ctx->offset,
						  ctx->len - ctx->offset, &frame);
	if (ret < 0)
		return ret;

	ctx->offset += ret;
	ctx->ack_eliciting = true;

	/* Handle the frame */
	ret = tquic_mp_handle_retire_connection_id(ctx->conn, &frame);
	if (ret < 0) {
		tquic_dbg("MP_RETIRE_CONNECTION_ID handling failed: %d\n", ret);
		return ret;
	}

	tquic_dbg("processed MP_RETIRE_CONNECTION_ID path=%llu seq=%llu\n",
		 frame.path_id, frame.seq_num);
	return 0;
}

/**
 * tquic_process_mp_ack_frame - Process MP_ACK frame
 * @ctx: Receive context
 *
 * RFC 9369: MP_ACK provides per-path acknowledgments.
 */
static int tquic_process_mp_ack_frame(struct tquic_rx_ctx *ctx)
{
	struct tquic_mp_ack *frame;
	struct tquic_path *path;
	struct tquic_mp_path_ack_state *ack_state;
	u8 ack_delay_exponent = 3;  /* Default */
	int ret;

	/* Allocate frame on heap to avoid stack overflow (>4KB struct) */
	frame = kmalloc(sizeof(*frame), GFP_ATOMIC);
	if (!frame)
		return -ENOMEM;

	ret = tquic_mp_parse_ack(ctx->data + ctx->offset,
				 ctx->len - ctx->offset,
				 frame, ack_delay_exponent);
	if (ret < 0)
		goto out_free;

	ctx->offset += ret;
	/* MP_ACK is NOT ack-eliciting (RFC 9000 Section 13.2) */

	/*
	 * Find the path for this ACK.
	 * Keep paths_lock held during tquic_mp_on_ack_received() to
	 * prevent the path from being freed while we access it.
	 * tquic_mp_on_ack_received() must not sleep.
	 */
	spin_lock_bh(&ctx->conn->paths_lock);
	list_for_each_entry(path, &ctx->conn->paths, list) {
		if (path->path_id == frame->path_id) {
			ack_state = path->mp_ack_state;
			if (ack_state) {
				ret = tquic_mp_on_ack_received(ack_state,
					TQUIC_PN_SPACE_APPLICATION,
					frame, ctx->conn);
				spin_unlock_bh(&ctx->conn->paths_lock);
				if (ret < 0) {
					tquic_dbg("MP_ACK processing failed: %d\n", ret);
					goto out_free;
				}
				tquic_dbg("processed MP_ACK path=%llu largest=%llu\n",
					 frame->path_id, frame->largest_ack);
				kfree(frame);
				return 0;
			}
			break;
		}
	}
	spin_unlock_bh(&ctx->conn->paths_lock);

	tquic_dbg("MP_ACK for unknown/uninitialized path %llu\n",
		 frame->path_id);
	ret = 0;

out_free:
	kfree(frame);
	return ret;
}

/**
 * tquic_process_path_status_frame - Process PATH_STATUS frame
 * @ctx: Receive context
 *
 * RFC 9369: PATH_STATUS reports path availability and priority.
 */
static int tquic_process_path_status_frame(struct tquic_rx_ctx *ctx)
{
	struct tquic_mp_path_status frame;
	int ret;

	ret = tquic_mp_parse_path_status(ctx->data + ctx->offset,
					 ctx->len - ctx->offset, &frame);
	if (ret < 0)
		return ret;

	ctx->offset += ret;
	ctx->ack_eliciting = true;

	/* Handle the frame */
	ret = tquic_mp_handle_path_status(ctx->conn, &frame);
	if (ret < 0) {
		tquic_dbg("PATH_STATUS handling failed: %d\n", ret);
		return ret;
	}

	tquic_dbg("processed PATH_STATUS path=%llu status=%llu\n",
		 frame.path_id, frame.status);
	return 0;
}

#endif /* CONFIG_TQUIC_MULTIPATH */

/*
 * Demultiplex and process all frames in packet
 */
static int tquic_process_frames(struct tquic_connection *conn,
				struct tquic_path *path,
				u8 *payload, size_t len,
				int enc_level, u64 pkt_num)
{
	struct tquic_rx_ctx ctx;
	int ret = 0;
	u8 frame_type;
	size_t prev_offset;
	int frame_budget = 512;  /* CF-610: limit frames per packet */
	bool is_0rtt = (enc_level == TQUIC_PKT_ZERO_RTT);
	bool is_1rtt = (enc_level == 3);	/* Short header / Application */
	bool is_initial = (enc_level == TQUIC_PKT_INITIAL);
	bool is_handshake = (enc_level == TQUIC_PKT_HANDSHAKE);

	/*
	 * RFC 9000 Section 10.2: In DRAINING state, no frames should be
	 * processed. In CLOSING state, only CONNECTION_CLOSE is relevant
	 * (to determine if peer has also initiated close).
	 */
	if (READ_ONCE(conn->state) == TQUIC_CONN_DRAINING)
		return 0;

	ctx.conn = conn;
	ctx.path = path;
	ctx.data = payload;
	ctx.len = len;
	ctx.offset = 0;
	ctx.pkt_num = pkt_num;
	ctx.enc_level = enc_level;
	ctx.ack_eliciting = false;
	ctx.immediate_ack_seen = false;
	ctx.saw_stream_no_length = false;

	while (ctx.offset < ctx.len) {
		prev_offset = ctx.offset;

		/* CF-610: Enforce per-packet frame processing budget */
		if (--frame_budget <= 0) {
			tquic_dbg("frame budget exhausted\n");
			return -EPROTO;
		}

		/*
		 * CF-012: A STREAM frame without a Length field consumes
		 * all remaining bytes in the packet (RFC 9000 Section
		 * 19.8).  Any trailing bytes after such a frame are
		 * malformed -- reject the packet to prevent data being
		 * silently queued from an invalid frame sequence.
		 */
		if (ctx.saw_stream_no_length) {
			tquic_dbg("trailing data after length-less STREAM frame\n");
			return -EPROTO;
		}

		frame_type = ctx.data[ctx.offset];

		/*
		 * RFC 9000 Section 10.2.1: In CLOSING state, only
		 * CONNECTION_CLOSE frames are processed. All other
		 * frames are silently ignored.
		 */
		if (READ_ONCE(conn->state) == TQUIC_CONN_CLOSING) {
			if (frame_type != TQUIC_FRAME_CONNECTION_CLOSE &&
			    frame_type != TQUIC_FRAME_CONNECTION_CLOSE_APP)
				return 0;
		}

		/*
		 * RFC 9000 Section 12.4, Table 3: Validate frame types
		 * against the current encryption level.
		 *
		 * - PADDING, PING, CONNECTION_CLOSE: all levels
		 * - ACK/ACK_ECN: all except 0-RTT
		 * - CRYPTO: Initial, Handshake, 1-RTT (not 0-RTT)
		 * - STREAM (0x08-0x0f): 0-RTT and 1-RTT only
		 * - HANDSHAKE_DONE (0x1e): 1-RTT only
		 * - NEW_TOKEN (0x07): 1-RTT only
		 * - Most other frames: 0-RTT and 1-RTT only
		 */

		/* Handle frame based on type */
		if (frame_type == TQUIC_FRAME_PADDING) {
			ret = tquic_process_padding_frame(&ctx);
		} else if (frame_type == TQUIC_FRAME_PING) {
			ret = tquic_process_ping_frame(&ctx);
		} else if (frame_type == TQUIC_FRAME_ACK ||
			   frame_type == TQUIC_FRAME_ACK_ECN) {
			/* CF-283: Limit to one ACK frame per packet */
			if (ctx.ack_frame_seen)
				return -EPROTO;
			ctx.ack_frame_seen = true;
			/* ACK frames forbidden in 0-RTT packets */
			if (is_0rtt) {
				conn->error_code = EQUIC_FRAME_ENCODING;
				tquic_conn_close_with_error(conn,
					EQUIC_FRAME_ENCODING,
					"ACK in 0-RTT");
				return -EPROTO;
			}
			ret = tquic_process_ack_frame(&ctx);
		} else if (frame_type == TQUIC_FRAME_CRYPTO) {
			/* CRYPTO frames forbidden in 0-RTT */
			if (is_0rtt) {
				conn->error_code = EQUIC_FRAME_ENCODING;
				tquic_conn_close_with_error(conn,
					EQUIC_FRAME_ENCODING,
					"CRYPTO in 0-RTT");
				return -EPROTO;
			}
			ret = tquic_process_crypto_frame(&ctx);
		} else if (frame_type == TQUIC_FRAME_NEW_TOKEN) {
			/* NEW_TOKEN only in 1-RTT */
			if (!is_1rtt) {
				conn->error_code = EQUIC_FRAME_ENCODING;
				tquic_conn_close_with_error(conn,
					EQUIC_FRAME_ENCODING,
					"NEW_TOKEN not in 1-RTT");
				return -EPROTO;
			}
			ret = tquic_process_new_token(&ctx);
		} else if ((frame_type & 0xf8) == TQUIC_FRAME_STREAM) {
			/* STREAM frames only in 0-RTT and 1-RTT */
			if (is_initial || is_handshake) {
				conn->error_code = EQUIC_FRAME_ENCODING;
				tquic_conn_close_with_error(conn,
					EQUIC_FRAME_ENCODING,
					"STREAM in Initial/Handshake");
				return -EPROTO;
			}
			ret = tquic_process_stream_frame(&ctx);
		} else if (frame_type == TQUIC_FRAME_MAX_DATA) {
			if (is_initial || is_handshake) {
				conn->error_code = EQUIC_FRAME_ENCODING;
				tquic_conn_close_with_error(conn,
					EQUIC_FRAME_ENCODING,
					"MAX_DATA in Initial/Handshake");
				return -EPROTO;
			}
			ret = tquic_process_max_data_frame(&ctx);
		} else if (frame_type == TQUIC_FRAME_MAX_STREAM_DATA) {
			if (is_initial || is_handshake) {
				conn->error_code = EQUIC_FRAME_ENCODING;
				tquic_conn_close_with_error(conn,
					EQUIC_FRAME_ENCODING,
					"MAX_STREAM_DATA in Initial/HS");
				return -EPROTO;
			}
			ret = tquic_process_max_stream_data_frame(&ctx);
		} else if (frame_type == TQUIC_FRAME_PATH_CHALLENGE) {
			if (is_initial || is_handshake) {
				conn->error_code = EQUIC_FRAME_ENCODING;
				tquic_conn_close_with_error(conn,
					EQUIC_FRAME_ENCODING,
					"PATH_CHALLENGE in Initial/HS");
				return -EPROTO;
			}
			ret = tquic_process_path_challenge_frame(&ctx);
		} else if (frame_type == TQUIC_FRAME_PATH_RESPONSE) {
			if (is_initial || is_handshake) {
				conn->error_code = EQUIC_FRAME_ENCODING;
				tquic_conn_close_with_error(conn,
					EQUIC_FRAME_ENCODING,
					"PATH_RESPONSE in Initial/HS");
				return -EPROTO;
			}
			ret = tquic_process_path_response_frame(&ctx);
		} else if (frame_type == TQUIC_FRAME_NEW_CONNECTION_ID) {
			if (is_initial || is_handshake) {
				conn->error_code = EQUIC_FRAME_ENCODING;
				tquic_conn_close_with_error(conn,
					EQUIC_FRAME_ENCODING,
					"NEW_CID in Initial/HS");
				return -EPROTO;
			}
			ret = tquic_process_new_connection_id_frame(&ctx);
		} else if (frame_type == TQUIC_FRAME_RETIRE_CONNECTION_ID) {
			if (is_initial || is_handshake) {
				conn->error_code = EQUIC_FRAME_ENCODING;
				tquic_conn_close_with_error(conn,
					EQUIC_FRAME_ENCODING,
					"RETIRE_CID in Initial/HS");
				return -EPROTO;
			}
			ret = tquic_process_retire_connection_id_frame(&ctx);
		} else if (frame_type == TQUIC_FRAME_CONNECTION_CLOSE) {
			ret = tquic_process_connection_close_frame(&ctx, false);
		} else if (frame_type == TQUIC_FRAME_CONNECTION_CLOSE_APP) {
			ret = tquic_process_connection_close_frame(&ctx, true);
		} else if (frame_type == TQUIC_FRAME_HANDSHAKE_DONE) {
			/* HANDSHAKE_DONE only in 1-RTT */
			if (!is_1rtt) {
				conn->error_code = EQUIC_FRAME_ENCODING;
				tquic_conn_close_with_error(conn,
					EQUIC_FRAME_ENCODING,
					"HANDSHAKE_DONE not in 1-RTT");
				return -EPROTO;
			}
			ret = tquic_process_handshake_done_frame(&ctx);
		} else if ((frame_type & 0xfe) == TQUIC_FRAME_DATAGRAM) {
			if (is_initial || is_handshake) {
				conn->error_code = EQUIC_FRAME_ENCODING;
				tquic_conn_close_with_error(conn,
					EQUIC_FRAME_ENCODING,
					"DATAGRAM in Initial/HS");
				return -EPROTO;
			}
			ret = tquic_process_datagram_frame(&ctx);
		} else if (frame_type == TQUIC_FRAME_ACK_FREQUENCY) {
			/*
			 * ACK_FREQUENCY is only valid in 1-RTT packets
			 * per draft-ietf-quic-ack-frequency Section 3.
			 */
			if (!is_1rtt) {
				conn->error_code = EQUIC_FRAME_ENCODING;
				tquic_conn_close_with_error(conn,
					EQUIC_FRAME_ENCODING,
					"ACK_FREQUENCY not in 1-RTT");
				return -EPROTO;
			}
			ret = tquic_process_ack_frequency_frame(&ctx);
		} else if (frame_type == TQUIC_FRAME_IMMEDIATE_ACK) {
			/*
			 * IMMEDIATE_ACK is only valid in 1-RTT packets
			 * per draft-ietf-quic-ack-frequency Section 4.
			 */
			if (!is_1rtt) {
				conn->error_code = EQUIC_FRAME_ENCODING;
				tquic_conn_close_with_error(conn,
					EQUIC_FRAME_ENCODING,
					"IMMEDIATE_ACK not in 1-RTT");
				return -EPROTO;
			}
			ret = tquic_process_immediate_ack_frame(&ctx);
#ifdef CONFIG_TQUIC_MULTIPATH
		} else if (frame_type == 0x40) {
			/* MP_NEW_CONNECTION_ID - CF-281: 1-RTT only */
			if (!is_1rtt) {
				conn->error_code = EQUIC_FRAME_ENCODING;
				tquic_conn_close_with_error(conn,
					EQUIC_FRAME_ENCODING,
					"MP frame not in 1-RTT");
				return -EPROTO;
			}
			ret = tquic_process_mp_new_connection_id_frame(&ctx);
		} else if (frame_type == 0x41) {
			/* MP_RETIRE_CONNECTION_ID - CF-281: 1-RTT only */
			if (!is_1rtt) {
				conn->error_code = EQUIC_FRAME_ENCODING;
				tquic_conn_close_with_error(conn,
					EQUIC_FRAME_ENCODING,
					"MP frame not in 1-RTT");
				return -EPROTO;
			}
			ret = tquic_process_mp_retire_connection_id_frame(&ctx);
		} else if (frame_type == 0x42 || frame_type == 0x43) {
			/* MP_ACK or MP_ACK_ECN - CF-281: 1-RTT only */
			if (!is_1rtt) {
				conn->error_code = EQUIC_FRAME_ENCODING;
				tquic_conn_close_with_error(conn,
					EQUIC_FRAME_ENCODING,
					"MP frame not in 1-RTT");
				return -EPROTO;
			}
			ret = tquic_process_mp_ack_frame(&ctx);
		} else if (tquic_is_mp_extended_frame(&ctx)) {
			/* Extended multipath frames - CF-281: 1-RTT only */
			if (!is_1rtt) {
				conn->error_code = EQUIC_FRAME_ENCODING;
				tquic_conn_close_with_error(conn,
					EQUIC_FRAME_ENCODING,
					"MP frame not in 1-RTT");
				return -EPROTO;
			}
			ret = tquic_process_mp_extended_frame(&ctx);
#endif
		} else {
			/*
			 * Unknown frame type - RFC 9000 Section 12.4:
			 * "An endpoint MUST treat the receipt of a frame of
			 * unknown type as a connection error of type
			 * FRAME_ENCODING_ERROR."
			 */
			tquic_dbg("unknown frame type 0x%02x\n", frame_type);
			conn->error_code = EQUIC_FRAME_ENCODING;
			tquic_conn_close_with_error(conn, EQUIC_FRAME_ENCODING,
						    "unknown frame type");
			return -EPROTO;
		}

		if (ret < 0)
			break;

		/* Detect stuck parsing (no progress made) */
		if (ctx.offset == prev_offset)
			return -EPROTO;
	}

	/* Send ACK if packet was ack-eliciting */
	if (ctx.ack_eliciting && ret >= 0) {
		/* Queue ACK to be sent */
		/* This would be handled by the ACK manager */
	}

	return ret;
}

/*
 * =============================================================================
 * Header Parsing
 * =============================================================================
 */

/*
 * Parse long header
 */
static int tquic_parse_long_header_internal(struct tquic_rx_ctx *ctx,
				   u8 *dcid, u8 *dcid_len,
				   u8 *scid, u8 *scid_len,
				   u32 *version, int *pkt_type)
{
	u8 *p = ctx->data;
	u8 first_byte;

	if (ctx->len < 7)
		return -EINVAL;

	first_byte = *p++;

	/*
	 * Version - cast each byte to u32 before shifting to avoid
	 * signed integer overflow UB when p[0] >= 0x80 (u8 promotes
	 * to int, and int << 24 overflows for values >= 128).
	 */
	*version = ((u32)p[0] << 24) | ((u32)p[1] << 16) |
		   ((u32)p[2] << 8) | (u32)p[3];
	p += 4;

	/* DCID Length + DCID */
	*dcid_len = *p++;
	if (*dcid_len > TQUIC_MAX_CID_LEN)
		return -EINVAL;
	if (p + *dcid_len > ctx->data + ctx->len)
		return -EINVAL;
	memcpy(dcid, p, *dcid_len);
	p += *dcid_len;

	/* SCID Length + SCID */
	if (p >= ctx->data + ctx->len)
		return -EINVAL;
	*scid_len = *p++;
	if (*scid_len > TQUIC_MAX_CID_LEN)
		return -EINVAL;
	if (p + *scid_len > ctx->data + ctx->len)
		return -EINVAL;
	memcpy(scid, p, *scid_len);
	p += *scid_len;

	/* Packet type from first byte */
	*pkt_type = (first_byte & 0x30) >> 4;

	ctx->offset = p - ctx->data;
	ctx->is_long_header = true;

	return 0;
}

/*
 * Parse short header
 */
static int tquic_parse_short_header_internal(struct tquic_rx_ctx *ctx,
				    u8 dcid_len,  /* Expected DCID length */
				    u8 *dcid,
				    bool *key_phase,
				    bool *spin_bit)
{
	u8 first_byte;

	if (ctx->len < 1 + dcid_len)
		return -EINVAL;

	first_byte = ctx->data[0];

	*spin_bit = (first_byte & TQUIC_HEADER_SPIN_BIT) != 0;
	*key_phase = (first_byte & TQUIC_HEADER_KEY_PHASE) != 0;

	/* Copy DCID */
	memcpy(dcid, ctx->data + 1, dcid_len);

	ctx->offset = 1 + dcid_len;
	ctx->is_long_header = false;

	return 0;
}

/*
 * Decode packet number
 */
static u64 tquic_decode_pkt_num(u8 *buf, int pkt_num_len, u64 largest_pn)
{
	u64 truncated_pn = 0;
	u64 expected_pn, pn_win, pn_hwin, pn_mask;
	u64 candidate_pn;
	int i;

	/* Read truncated packet number */
	for (i = 0; i < pkt_num_len; i++)
		truncated_pn = (truncated_pn << 8) | buf[i];

	/* Reconstruct full packet number */
	expected_pn = largest_pn + 1;
	pn_win = 1ULL << (pkt_num_len * 8);
	pn_hwin = pn_win / 2;
	pn_mask = pn_win - 1;

	candidate_pn = (expected_pn & ~pn_mask) | truncated_pn;

	if (candidate_pn + pn_hwin <= expected_pn &&
	    candidate_pn + pn_win < (1ULL << 62))
		candidate_pn += pn_win;
	else if (candidate_pn > expected_pn + pn_hwin &&
		 candidate_pn >= pn_win)
		candidate_pn -= pn_win;

	return candidate_pn;
}

/*
 * =============================================================================
 * GRO (Generic Receive Offload) Handling
 * =============================================================================
 */

/*
 * GRO flush timer callback
 */
static enum hrtimer_restart tquic_gro_flush_timer(struct hrtimer *timer)
{
	return HRTIMER_NORESTART;
}

/*
 * Initialize GRO state
 */
struct tquic_gro_state *tquic_gro_init(void)
{
	struct tquic_gro_state *gro;

	gro = kzalloc(sizeof(*gro), GFP_KERNEL);
	if (!gro)
		return NULL;

	skb_queue_head_init(&gro->hold_queue);
	spin_lock_init(&gro->lock);
	/* Use hrtimer_setup (new API) instead of hrtimer_init */
	hrtimer_setup(&gro->flush_timer, tquic_gro_flush_timer,
		      CLOCK_MONOTONIC, HRTIMER_MODE_REL);

	return gro;
}
EXPORT_SYMBOL_GPL(tquic_gro_init);

/*
 * Cleanup GRO state
 */
void tquic_gro_cleanup(struct tquic_gro_state *gro)
{
	if (!gro)
		return;

	hrtimer_cancel(&gro->flush_timer);
	skb_queue_purge(&gro->hold_queue);
	kfree(gro);
}
EXPORT_SYMBOL_GPL(tquic_gro_cleanup);

/*
 * Check if packets can be coalesced
 *
 * @dcid_len: Actual DCID length from the connection state.  Must not
 *            exceed TQUIC_MAX_CID_LEN (20).
 */
static bool tquic_gro_can_coalesce(struct sk_buff *skb1, struct sk_buff *skb2,
				    u8 dcid_len)
{
	/* For QUIC, we can coalesce packets from same connection */
	/* Check DCID matches */
	u8 *h1 = skb1->data;
	u8 *h2 = skb2->data;

	/* Both must be short headers or both long headers */
	if ((h1[0] & TQUIC_HEADER_FORM_LONG) != (h2[0] & TQUIC_HEADER_FORM_LONG))
		return false;

	/* For short headers, compare DCID using actual CID length */
	if (!(h1[0] & TQUIC_HEADER_FORM_LONG)) {
		/*
		 * CF-191: Use the actual DCID length from connection
		 * state instead of a hardcoded 8-byte comparison.
		 * Validate both skbs are long enough for the comparison.
		 */
		if (dcid_len > TQUIC_MAX_CID_LEN)
			return false;
		if (skb1->len < 1 + dcid_len || skb2->len < 1 + dcid_len)
			return false;
		return memcmp(h1 + 1, h2 + 1, dcid_len) == 0;
	}

	return false;
}

/*
 * Attempt to merge packets for GRO
 *
 * @dcid_len: Actual DCID length from the connection state so that
 *            coalesce comparisons use the correct CID size.
 */
static struct sk_buff __maybe_unused *tquic_gro_receive_internal(struct tquic_gro_state *gro,
								struct sk_buff *skb,
								u8 dcid_len)
{
	struct sk_buff *held;

	spin_lock(&gro->lock);

	/* Check if we can coalesce with held packets */
	skb_queue_walk(&gro->hold_queue, held) {
		if (tquic_gro_can_coalesce(held, skb, dcid_len)) {
			/* Coalesce into held packet */
			/* For QUIC, this is complex due to packet structure */
			/* Simple implementation just holds multiple packets */
		}
	}

	/* Add to hold queue */
	__skb_queue_tail(&gro->hold_queue, skb);
	gro->held_count++;

	if (gro->held_count == 1)
		gro->first_hold_time = ktime_get();

	/* Flush if queue is full */
	if (gro->held_count >= TQUIC_GRO_MAX_HOLD) {
		/* Would flush here */
	}

	spin_unlock(&gro->lock);

	return NULL;
}

/*
 * Flush GRO held packets
 */
int tquic_gro_flush(struct tquic_gro_state *gro,
		    void (*deliver)(struct sk_buff *))
{
	struct sk_buff *skb;
	int flushed = 0;

	spin_lock(&gro->lock);

	while ((skb = __skb_dequeue(&gro->hold_queue)) != NULL) {
		spin_unlock(&gro->lock);
		deliver(skb);
		flushed++;
		spin_lock(&gro->lock);
	}

	/*
	 * CF-192: Re-validate held_count from the actual queue length
	 * after the unlock-relock loop.  While we dropped the lock to
	 * call deliver(), new skbs may have been enqueued by another
	 * CPU.  Using the true queue length keeps held_count consistent
	 * instead of blindly setting it to 0.
	 */
	gro->held_count = skb_queue_len(&gro->hold_queue);

	spin_unlock(&gro->lock);

	return flushed;
}
EXPORT_SYMBOL_GPL(tquic_gro_flush);

/*
 * =============================================================================
 * Main Receive Path
 * =============================================================================
 */

/*
 * Process a single QUIC packet
 */
static int tquic_process_packet(struct tquic_connection *conn,
				struct tquic_path *path,
				u8 *data, size_t len,
				struct sockaddr_storage *src_addr)
{
	struct tquic_rx_ctx ctx;
	u8 dcid[TQUIC_MAX_CID_LEN], scid[TQUIC_MAX_CID_LEN];
	u8 dcid_len, scid_len;
	u32 version;
	int pkt_type;
	int pkt_num_len = 0;
	u64 pkt_num;
	u8 *payload;
	size_t payload_len, decrypted_len = 0;
	u8 *decrypted;
	bool decrypted_from_slab = false;
	bool path_looked_up = false;  /* C-001 FIX: Track if we own path ref */
	int pn_space_idx = TQUIC_PN_SPACE_APPLICATION;
	u64 largest_pn = 0;
	int ret;

	ctx.data = data;
	ctx.len = len;
	ctx.offset = 0;

	/* Check header form */
	if (data[0] & TQUIC_HEADER_FORM_LONG) {
		/* Long header */
		ret = tquic_parse_long_header_internal(&ctx, dcid, &dcid_len,
					      scid, &scid_len,
					      &version, &pkt_type);
		if (unlikely(ret < 0))
			return ret;

		/* Handle version negotiation */
		if (unlikely(version == TQUIC_VERSION_NEGOTIATION)) {
			if (conn)
				return tquic_process_version_negotiation(conn, data, len);
			return 0;
		}

		/*
		 * Handle Retry packet (client-side, RFC 9000 Section 17.2.5)
		 *
		 * A Retry packet is sent by the server in response to an Initial
		 * packet to validate the client's address. The client must:
		 * 1. Verify the Retry Integrity Tag using original DCID
		 * 2. Extract the Retry Token
		 * 3. Store the new server-provided SCID
		 * 4. Retransmit Initial with the Retry Token
		 *
		 * Retry packets can only be received on clients during connection
		 * establishment (TQUIC_CONN_CONNECTING state).
		 */
		if (unlikely(pkt_type == TQUIC_PKT_RETRY)) {
			/* Need connection to process Retry */
			if (!conn)
				conn = tquic_lookup_by_dcid(dcid, dcid_len);

			if (conn) {
				/*
				 * Only process Retry in connecting state.
				 * Per RFC 9000: "A client MUST discard a Retry
				 * packet that contains a DCID field that is
				 * not equal to the SCID field of its Initial."
				 */
				if (READ_ONCE(conn->state) == TQUIC_CONN_CONNECTING) {
					ret = tquic_retry_process(conn, data, len);
					if (ret == 0) {
						/* Update MIB counter */
						if (conn->sk)
							TQUIC_INC_STATS(sock_net(conn->sk),
									TQUIC_MIB_RETRYPACKETSRX);
						/*
						 * Retry processed successfully.
						 * Caller should retransmit Initial with token.
						 * Return special code to trigger retry.
						 */
						return -EAGAIN;
					}
				} else {
					/*
					 * Per RFC 9000 Section 17.2.5.2:
					 * "A client MUST discard a Retry packet
					 * if it has received and successfully
					 * processed a Retry packet for this
					 * connection."
					 */
					tquic_dbg("discarding Retry in state %d\n",
						 READ_ONCE(conn->state));
				}
			}
			return 0;  /* Discard Retry packet after processing */
		}

		/*
		 * Handle 0-RTT packets (RFC 9001 Section 4.6-4.7)
		 *
		 * 0-RTT packets are sent by clients using keys derived from
		 * a previous session's resumption_master_secret. They contain
		 * early application data and may arrive before or during the
		 * TLS handshake.
		 *
		 * Server processing:
		 * 1. Look up connection by DCID
		 * 2. Check if 0-RTT is enabled and not rejected
		 * 3. Decrypt using 0-RTT keys
		 * 4. Process frames (limited: no CRYPTO, ACK, etc.)
		 *
		 * Client processing (unlikely - server doesn't send 0-RTT):
		 * - Discard the packet
		 */
		if (pkt_type == TQUIC_PKT_ZERO_RTT) {
			if (!conn)
				conn = tquic_lookup_by_dcid(dcid, dcid_len);

			if (!conn) {
				tquic_dbg("0-RTT packet for unknown connection\n");
				return -ENOENT;
			}

			/* Server-side: check if we can accept 0-RTT */
			if (conn->role == TQUIC_ROLE_SERVER) {
				enum tquic_zero_rtt_state zrtt_state;
				zrtt_state = tquic_zero_rtt_get_state(conn);

				if (zrtt_state == TQUIC_0RTT_REJECTED) {
					/*
					 * 0-RTT already rejected - discard packet.
					 * Client will retransmit as 1-RTT.
					 */
					tquic_dbg("0-RTT rejected, discarding\n");
					return 0;
				}

				/*
				 * Accept 0-RTT if not yet decided.
				 * This initializes keys for decryption.
				 */
				if (zrtt_state == TQUIC_0RTT_NONE) {
					ret = tquic_zero_rtt_accept(conn);
					if (ret < 0) {
						/* Replay or other error - reject */
						tquic_zero_rtt_reject(conn);
						if (ret == -EEXIST && conn->sk)
							TQUIC_INC_STATS(sock_net(conn->sk),
									TQUIC_MIB_0RTTREPLAYS);
						tquic_dbg("0-RTT rejected: %d\n", ret);
						return 0;
					}
					if (conn->sk)
						TQUIC_INC_STATS(sock_net(conn->sk),
								TQUIC_MIB_0RTTACCEPTED);
				}
			} else {
				/* Client received 0-RTT packet - shouldn't happen */
				tquic_dbg("client received 0-RTT packet?\n");
				return -EPROTO;
			}

			/* Continue to decrypt and process as 0-RTT */
			/* Fall through to normal packet processing below */
		}

		/* Lookup connection by DCID if not provided */
		if (!conn)
			conn = tquic_lookup_by_dcid(dcid, dcid_len);

		if (!conn) {
			/* New connection - would handle Initial packet */
			tquic_dbg("no connection found for DCID\n");
			return -ENOENT;
		}

		/* Parse token for Initial packets */
		if (pkt_type == TQUIC_PKT_INITIAL) {
			u64 token_len;
			size_t remaining_len;

			ret = tquic_decode_varint(data + ctx.offset,
						  len - ctx.offset, &token_len);
			if (ret < 0)
				return ret;
			ctx.offset += ret;

			if (token_len > TQUIC_MAX_TOKEN_LEN)
				return -EINVAL;

			remaining_len = len - ctx.offset;
			if (token_len > remaining_len)
				return -EINVAL;

			ctx.offset += token_len;
		}

		/* Parse length field */
		{
			u64 pkt_len;
			ret = tquic_decode_varint(data + ctx.offset,
						  len - ctx.offset, &pkt_len);
			if (ret < 0)
				return ret;
			ctx.offset += ret;
		}

		/*
		 * CF-076: Do NOT extract pkt_num_len here -- the low
		 * 2 bits of the first byte are still masked by header
		 * protection.  Extraction is deferred until after
		 * tquic_remove_header_protection().
		 */

	} else {
		/* Short header */
		bool key_phase_tmp, spin_bit;

		/* Need connection to know DCID length */
		if (!conn)
			return -ENOENT;

		ret = tquic_parse_short_header_internal(&ctx, conn->scid.len,
					       dcid, &key_phase_tmp,
					       &spin_bit);
		if (ret < 0)
			return ret;

		pkt_type = -1;  /* Short header / 1-RTT */

		/*
		 * CF-076/CF-099: Do NOT extract pkt_num_len or
		 * key_phase from the protected header.  Both the
		 * low 2 bits (PN length) and bit 0x04 (key phase)
		 * are masked by header protection.  Correct values
		 * are obtained after tquic_remove_header_protection().
		 */
	}

	/*
	 * Find path if not provided.
	 *
	 * CF-045: Hold rcu_read_lock() across path lookup and the
	 * subsequent use of the path pointer.  Paths are freed via
	 * kfree_rcu(), so the RCU read-side critical section prevents
	 * use-after-free if another CPU removes this path while we
	 * are processing the packet.
	 *
	 * C-001 FIX: tquic_find_path_by_addr() now takes a reference
	 * via refcount_inc_not_zero(). We must release this reference
	 * before returning. Track ownership with path_looked_up flag.
	 */
	rcu_read_lock();
	if (!path && conn) {
		path = tquic_find_path_by_addr(conn, src_addr);
		if (path)
			path_looked_up = true;
	}

	/* Remove header protection */
	{
		u8 hp_pn_len = 0, hp_key_phase = 0;

		ret = tquic_remove_header_protection(conn, data, ctx.offset,
						     data + ctx.offset,
						     len - ctx.offset,
						     ctx.is_long_header,
						     &hp_pn_len,
						     &hp_key_phase);
		if (unlikely(ret < 0)) {
			if (path_looked_up)
				tquic_path_put(path);
			rcu_read_unlock();
			return ret;
		}

		/*
		 * CF-076: Extract pkt_num_len from the NOW-unprotected
		 * first byte.  Header protection has been removed, so
		 * the low 2 bits of data[0] reflect the true PN length.
		 */
		if (hp_pn_len > 0) {
			/* Prefer the value returned by HP removal */
			pkt_num_len = hp_pn_len;
		} else {
			/*
			 * HP context was not available (e.g. Initial
			 * before key derivation).  First byte is already
			 * in the clear; read the PN length directly.
			 */
			pkt_num_len = (data[0] & 0x03) + 1;
		}

		/*
		 * CF-099: Re-read key_phase from the unprotected
		 * header for short-header (1-RTT) packets.
		 */
		if (!ctx.is_long_header) {
			if (hp_pn_len > 0)
				ctx.key_phase_bit = hp_key_phase;
			else
				ctx.key_phase_bit =
					(data[0] & TQUIC_HEADER_KEY_PHASE) ?
					1 : 0;
		}
	}

	/* Validate pkt_num_len is within protocol bounds (1..4) */
	if (pkt_num_len < 1 || pkt_num_len > 4) {
		if (path_looked_up)
			tquic_path_put(path);
		rcu_read_unlock();
		return -EINVAL;
	}

	if (ctx.offset + pkt_num_len > len) {
		if (path_looked_up)
			tquic_path_put(path);
		rcu_read_unlock();
		return -EINVAL;
	}

	/*
	 * CF-110: Decode packet number using the largest received PN
	 * for this PN space, not 0.  The reconstruction algorithm
	 * (RFC 9000 Appendix A) requires the largest successfully
	 * processed PN to correctly unwrap truncated packet numbers.
	 */
	if (pkt_type == TQUIC_PKT_INITIAL)
		pn_space_idx = TQUIC_PN_SPACE_INITIAL;
	else if (pkt_type == TQUIC_PKT_HANDSHAKE)
		pn_space_idx = TQUIC_PN_SPACE_HANDSHAKE;
	else
		pn_space_idx = TQUIC_PN_SPACE_APPLICATION;

	if (conn && conn->pn_spaces)
		largest_pn = READ_ONCE(
			conn->pn_spaces[pn_space_idx].largest_recv_pn);

	pkt_num = tquic_decode_pkt_num(data + ctx.offset,
				       pkt_num_len, largest_pn);
	ctx.offset += pkt_num_len;

	/* Decrypt payload */
	payload = data + ctx.offset;
	payload_len = len - ctx.offset;

	/*
	 * CF-055: Use the dedicated slab cache for decryption buffers when
	 * the payload fits (common case: all standard MTU packets).  Fall
	 * back to kmalloc for the rare jumbo/GSO case.
	 *
	 * The slab objects are exactly TQUIC_RX_BUF_SIZE bytes.  Validate
	 * that payload_len (which comes from the network and is therefore
	 * untrusted) does not exceed the slab object size before we hand
	 * the buffer to the decryption routine.  For oversized payloads
	 * use kmalloc so the buffer is always large enough.
	 */
	if (likely(payload_len > 0 && payload_len <= TQUIC_RX_BUF_SIZE)) {
		decrypted = kmem_cache_alloc(tquic_rx_buf_cache, GFP_ATOMIC);
		decrypted_from_slab = true;
	} else if (payload_len > 0) {
		decrypted = kmalloc(payload_len, GFP_ATOMIC);
	} else {
		if (path_looked_up)
			tquic_path_put(path);
		rcu_read_unlock();
		return -EINVAL;
	}
	if (unlikely(!decrypted)) {
		if (path_looked_up)
			tquic_path_put(path);
		rcu_read_unlock();
		return -ENOMEM;
	}

	/*
	 * Decrypt payload using appropriate keys:
	 * - 0-RTT packets use 0-RTT keys from session ticket
	 * - Other packets use normal crypto state keys
	 */
	if (unlikely(pkt_type == TQUIC_PKT_ZERO_RTT)) {
		/* Decrypt using 0-RTT keys */
		ret = tquic_zero_rtt_decrypt(conn, data, ctx.offset,
					     payload, payload_len,
					     pkt_num, decrypted, &decrypted_len);
		if (unlikely(ret < 0)) {
			if (decrypted_from_slab)
				kmem_cache_free(tquic_rx_buf_cache, decrypted);
			else
				kfree(decrypted);
			if (ret == -ENOKEY)
				tquic_dbg("0-RTT decryption failed, no keys\n");
			if (path_looked_up)
				tquic_path_put(path);
			rcu_read_unlock();
			return ret;
		}
		/* Update 0-RTT stats */
		if (conn->sk)
			TQUIC_ADD_STATS(sock_net(conn->sk), TQUIC_MIB_0RTTBYTESRX,
					decrypted_len);
	} else {
		ret = tquic_decrypt_payload(conn, data, ctx.offset,
					    payload, payload_len,
					    pkt_num,
					    pkt_type >= 0 ? pkt_type : 3,
					    decrypted, &decrypted_len);
		if (unlikely(ret < 0)) {
			/*
			 * Key Update: Decryption failure for short headers might be
			 * due to key phase change. Try with old keys if available.
			 * Per RFC 9001 Section 6.3, packets in flight during key
			 * update may arrive encrypted with old keys.
			 */
			if (pkt_type < 0 && conn->crypto_state) {
				ret = tquic_try_decrypt_with_old_keys(conn,
								      data, ctx.offset,
								      payload, payload_len,
								      pkt_num,
								      decrypted, &decrypted_len);
			}
			if (ret < 0) {
				if (decrypted_from_slab)
					kmem_cache_free(tquic_rx_buf_cache,
							decrypted);
				else
					kfree(decrypted);
				if (path_looked_up)
					tquic_path_put(path);
				rcu_read_unlock();
				return ret;
			}
		}
	}

	/*
	 * CF-055: Post-decrypt safety check.  Ensure the decryption
	 * routine did not produce more output than the buffer can hold.
	 * For the slab path the ceiling is TQUIC_RX_BUF_SIZE; for the
	 * kmalloc path it is the original payload_len.
	 */
	{
		size_t buf_cap = decrypted_from_slab ?
				 TQUIC_RX_BUF_SIZE : payload_len;
		if (unlikely(decrypted_len > buf_cap)) {
			tquic_warn("decrypted_len %zu exceeds buffer %zu\n",
				   decrypted_len, buf_cap);
			if (decrypted_from_slab)
				kmem_cache_free(tquic_rx_buf_cache, decrypted);
			else
				kfree(decrypted);
			if (path_looked_up)
				tquic_path_put(path);
			rcu_read_unlock();
			return -EOVERFLOW;
		}
	}

	/*
	 * Decryption succeeded -- now safe to update the largest received
	 * packet number for this PN space. This must happen after decryption
	 * to prevent attackers from corrupting the reconstruction window
	 * with forged packets (RFC 9000 Appendix A).
	 */
	if (conn && conn->pn_spaces && pkt_num > largest_pn)
		WRITE_ONCE(conn->pn_spaces[pn_space_idx].largest_recv_pn,
			   pkt_num);

	/*
	 * Key Update Detection (RFC 9001 Section 6)
	 *
	 * For short header packets (1-RTT), check if the key phase bit
	 * differs from our current key phase. A change indicates either:
	 * - Peer has initiated a key update (we need to respond)
	 * - Our previous key update has been acknowledged
	 */
	if (pkt_type < 0 && conn->crypto_state) {
		struct tquic_key_update_state *ku_state;
		ku_state = tquic_crypto_get_key_update_state(conn->crypto_state);
		if (ku_state) {
			u8 current_phase = tquic_key_update_get_phase(ku_state);
			if (ctx.key_phase_bit != current_phase) {
				int ku_ret = tquic_handle_key_phase_change(conn, ctx.key_phase_bit);
				if (ku_ret < 0)
					tquic_warn("key phase change %u->%u failed: %d\n",
						current_phase, ctx.key_phase_bit, ku_ret);
			}
			/* Track packet received for key update timing */
			tquic_key_update_on_packet_received(ku_state);
		}
	}

	/* Process frames */
	ret = tquic_process_frames(conn, path, decrypted, decrypted_len,
				   pkt_type >= 0 ? pkt_type : 3, pkt_num);

	if (decrypted_from_slab)
		kmem_cache_free(tquic_rx_buf_cache, decrypted);
	else
		kfree(decrypted);

	/* Update statistics */
	if (likely(ret >= 0)) {
		conn->stats.rx_packets++;
		if (likely(path)) {
			path->stats.rx_packets++;
			path->stats.rx_bytes += len;
			WRITE_ONCE(path->last_activity, ktime_get());
		}

		/* Update MIB counters for packet reception */
		if (conn->sk) {
			TQUIC_INC_STATS(sock_net(conn->sk), TQUIC_MIB_PACKETSRX);
			TQUIC_ADD_STATS(sock_net(conn->sk), TQUIC_MIB_BYTESRX, len);
		}

		/*
		 * RFC 9000 Section 10.1: "An endpoint restarts its idle
		 * timer when a packet from its peer is received and
		 * processed successfully."
		 */
		if (conn->timer_state)
			tquic_timer_reset_idle(conn->timer_state);
	}

	/* C-001 FIX: Release path reference if we looked it up */
	if (path_looked_up)
		tquic_path_put(path);

	rcu_read_unlock();
	return ret;
}

/*
 * UDP receive callback - main entry point for received packets
 *
 * This is the primary entry point for all QUIC packets received via UDP.
 * It handles:
 * - Stateless reset detection (received from peer)
 * - Version negotiation processing
 * - Regular packet processing
 * - Stateless reset transmission (for unknown CIDs, per RFC 9000 Section 10.3)
 */
int tquic_udp_recv(struct sock *sk, struct sk_buff *skb)
{
	struct tquic_connection *conn = NULL;
	struct tquic_path *path = NULL;
	struct sockaddr_storage src_addr;
	struct sockaddr_storage local_addr;
	u8 *data;
	size_t len;
	int ret;

	if (unlikely(!skb))
		return -EINVAL;

	/* Extract source (remote) address */
	memset(&src_addr, 0, sizeof(src_addr));
	memset(&local_addr, 0, sizeof(local_addr));

	if (skb->protocol == htons(ETH_P_IP)) {
		struct sockaddr_in *sin_src = (struct sockaddr_in *)&src_addr;
		struct sockaddr_in *sin_local = (struct sockaddr_in *)&local_addr;

		sin_src->sin_family = AF_INET;
		sin_src->sin_addr.s_addr = ip_hdr(skb)->saddr;
		sin_src->sin_port = udp_hdr(skb)->source;

		/* Local address for stateless reset response */
		sin_local->sin_family = AF_INET;
		sin_local->sin_addr.s_addr = ip_hdr(skb)->daddr;
		sin_local->sin_port = udp_hdr(skb)->dest;
	} else if (skb->protocol == htons(ETH_P_IPV6)) {
		struct sockaddr_in6 *sin6_src = (struct sockaddr_in6 *)&src_addr;
		struct sockaddr_in6 *sin6_local = (struct sockaddr_in6 *)&local_addr;

		sin6_src->sin6_family = AF_INET6;
		sin6_src->sin6_addr = ipv6_hdr(skb)->saddr;
		sin6_src->sin6_port = udp_hdr(skb)->source;

		sin6_local->sin6_family = AF_INET6;
		sin6_local->sin6_addr = ipv6_hdr(skb)->daddr;
		sin6_local->sin6_port = udp_hdr(skb)->dest;
	}

	/*
	 * Ensure the skb data is contiguous before parsing.
	 *
	 * GRO or other aggregation may produce non-linear skbs where
	 * skb->data only covers the first fragment.  All downstream
	 * parsing and decryption use direct pointer arithmetic on
	 * skb->data, so we must linearize first.
	 */
	if (skb_is_nonlinear(skb)) {
		if (skb_linearize(skb)) {
			kfree_skb(skb);
			return -ENOMEM;
		}
	}

	/* Get QUIC payload - UDP header already stripped by encap layer */
	data = skb->data;
	len = skb->len;

	pr_warn("tquic_udp_recv: proto=0x%04x len=%zu data[0]=0x%02x sk=%p\n",
		ntohs(skb->protocol), len, len > 0 ? data[0] : 0, sk);

	if (unlikely(len < 1)) {
		kfree_skb(skb);
		return -EINVAL;
	}

	/*
	 * Rate limiting check for DDoS protection
	 *
	 * For Initial packets (new connection attempts), check against
	 * per-IP rate limits before allocating any connection state.
	 * This is the first line of defense against amplification attacks.
	 *
	 * We have two rate limiting subsystems:
	 * 1. rate_limit.h: Token bucket with global and per-IP limits
	 * 2. tquic_ratelimit.h: Advanced rate limiting with cookie validation
	 *
	 * Check order:
	 * 1. Global rate limit check (rate_limit.h)
	 * 2. Per-IP rate limit check (rate_limit.h)
	 * 3. Advanced checks with cookie support (tquic_ratelimit.h)
	 */
	if (len >= 7 && (data[0] & TQUIC_HEADER_FORM_LONG)) {
		/* Long header - check if this is an Initial packet */
		int pkt_type = (data[0] & 0x30) >> 4;

		if (pkt_type == TQUIC_PKT_INITIAL) {
			enum tquic_rl_action action;
			u8 dcid_len, scid_len;
			const u8 *token = NULL;
			size_t token_len = 0;
			size_t offset;

			pr_warn("tquic_udp_recv: Initial pkt detected, len=%zu\n",
				len);

			/* Parse enough header to extract DCID */
			if (len >= 6) {
				dcid_len = data[5];

				/*
				 * SECURITY: Validate DCID length before use.
				 * RFC 9000 limits CID to 20 bytes. Without
				 * this check, offset = 6 + dcid_len could
				 * point past the packet buffer, causing
				 * out-of-bounds reads on data + 6.
				 */
				if (dcid_len > TQUIC_MAX_CID_LEN ||
				    6 + (size_t)dcid_len > len) {
					pr_warn("tquic_udp_recv: DCID len invalid (%u)\n",
						dcid_len);
					kfree_skb(skb);
					return -EINVAL;
				}
				offset = 6 + dcid_len;

				/*
				 * First check: Global and per-IP token bucket limits
				 * (rate_limit.h - lightweight fast path)
				 */
				if (!tquic_rate_limit_check_initial(sock_net(sk),
								    &src_addr,
								    data + 6,
								    dcid_len)) {
					/* Rate limited - silently drop */
					pr_warn("tquic_udp_recv: rate limited (token bucket)\n");
					kfree_skb(skb);
					return -EBUSY;
				}

				if (offset < len) {
					scid_len = data[offset];
					if (scid_len > TQUIC_MAX_CID_LEN ||
					    offset + 1 + scid_len > len) {
						kfree_skb(skb);
						return -EINVAL;
					}
					offset += 1 + scid_len;

					/* Parse token length (varint) */
					if (offset < len) {
						u64 tlen;
						int vlen;

						vlen = tquic_decode_varint(data + offset,
									   len - offset, &tlen);
						/*
						 * SECURITY: Validate tlen to prevent
						 * u64 wrap in offset + vlen + tlen.
						 * Use safe subtraction instead.
						 */
						if (vlen > 0 &&
						    tlen <= TQUIC_MAX_TOKEN_LEN &&
						    (size_t)vlen <= len - offset &&
						    tlen <= len - offset - vlen) {
							token = data + offset + vlen;
							token_len = tlen;
						}
					}
				}

				/*
				 * Second check: Advanced rate limiting with cookie
				 * support (tquic_ratelimit.h - attack mode handling)
				 */
				action = tquic_ratelimit_check_initial(
					sock_net(sk), &src_addr,
					data + 6, dcid_len,
					token, token_len);

				pr_warn("tquic_udp_recv: ratelimit action=%d\n",
					action);

				switch (action) {
				case TQUIC_RL_ACCEPT:
					/* Continue processing */
					break;

				case TQUIC_RL_RATE_LIMITED:
					/*
					 * Rate limited - silently drop
					 * No response to avoid amplification
					 */
					kfree_skb(skb);
					return -EBUSY;

				case TQUIC_RL_COOKIE_REQUIRED:
					/*
					 * Under attack - send Retry with cookie
					 * This validates the source address
					 */
					if (dcid_len > 0 && offset > 6 + dcid_len) {
						u8 cookie[64];
						size_t cookie_len = sizeof(cookie);
						u32 pkt_version;
						int ret;

						/* Preserve the client's QUIC version from Initial. */
						pkt_version = get_unaligned_be32(data + 1);

						ret = tquic_ratelimit_generate_cookie(
							sock_net(sk), &src_addr,
							data + 6, dcid_len,
							cookie, &cookie_len);
						if (ret == 0) {
							/* Send Retry packet with cookie as token */
							tquic_retry_send_with_token(sk, &src_addr,
										    pkt_version,
										    data + 6, dcid_len,
										    data + 7 + dcid_len,
										    scid_len,
										    cookie,
										    cookie_len);
						}
					}
					kfree_skb(skb);
					return 0;

				case TQUIC_RL_BLACKLISTED:
					/* Blacklisted - silently drop */
					kfree_skb(skb);
					return -EACCES;
				}
			}
		}
	}

	/* Check for stateless reset (received from peer) */
	if (len < TQUIC_STATELESS_RESET_MIN_LEN)
		goto not_reset;

	if (data[0] & TQUIC_HEADER_FORM_LONG)
		goto not_reset;

	/* Try to find connection for reset check */
	if (len > 1) {
		u8 dcid_len = min_t(size_t, len - 1, TQUIC_MAX_CID_LEN);
		conn = tquic_lookup_by_dcid(data + 1, dcid_len);
	}

	if (conn && tquic_is_stateless_reset_internal(conn, data, len)) {
		tquic_handle_stateless_reset(conn);
		kfree_skb(skb);
		return 0;
	}

not_reset:
	/* Check for version negotiation */
	if (unlikely(tquic_is_version_negotiation(data, len))) {
		/* Need connection context */
		if (len > 6) {
			u8 dcid_len = data[5];

			/*
			 * SECURITY: Validate DCID length before use.
			 * A crafted dcid_len > 20 would cause data + 6
			 * to be passed with an oversized length to
			 * the connection lookup, potentially reading
			 * past the packet buffer.
			 */
			if (dcid_len <= TQUIC_MAX_CID_LEN &&
			    len > (size_t)6 + dcid_len)
				conn = tquic_lookup_by_dcid(data + 6, dcid_len);
		}

		if (conn) {
			ret = tquic_process_version_negotiation(conn, data, len);
		} else {
			ret = 0;  /* Ignore orphan version negotiation */
		}

		kfree_skb(skb);
		return ret;
	}

	/*
	 * Handle Initial packets for new connections on listening sockets.
	 *
	 * Per RFC 9000 Section 7.2, servers must accept Initial packets
	 * even when no connection exists. Check if this is an Initial packet
	 * for a new connection and route to server accept path.
	 */
	if (!conn && (data[0] & TQUIC_HEADER_FORM_LONG)) {
		/* Extract packet type from long header */
		u8 pkt_type = (data[0] & 0x30) >> 4;

		pr_warn("tquic_udp_recv: long header, pkt_type=%u, data[0]=0x%02x\n",
			pkt_type, data[0]);

		/* Initial packet type == 0 */
		if (pkt_type == 0) {
			struct sock *listener;
			u32 pkt_version;

			/* Lookup listener socket for this address/port in this netns */
			listener = tquic_lookup_listener_net(sock_net(sk),
							     &local_addr);
			pr_warn("tquic_udp_recv: Initial pkt, listener lookup: %s (local_addr family=%d)\n",
				listener ? "FOUND" : "NOT FOUND",
				local_addr.ss_family);
			if (listener) {
				/*
				 * Extract version from long header (bytes 1-4).
				 * RFC 9000 Section 17.2: Long Header Packet Format
				 */
				if (len < 5) {
					tquic_dbg("Initial packet too short for version\n");
					sock_put(listener);
					kfree_skb(skb);
					return -EINVAL;
				}

				pkt_version = get_unaligned_be32(data + 1);

				/*
				 * Check if version is supported (RFC 9000 Section 6).
				 * Send Version Negotiation if client uses unsupported version.
				 */
				if (pkt_version != TQUIC_VERSION_1 &&
				    pkt_version != TQUIC_VERSION_2 &&
				    pkt_version != TQUIC_VERSION_NEGOTIATION) {
					tquic_dbg("unsupported version 0x%08x, sending VN\n",
						  pkt_version);

					/*
					 * Send Version Negotiation packet (RFC 9000 Section 6).
					 * VN packet lists versions we support (v1 and v2).
					 * This is sent from the listener socket context.
					 */
					ret = tquic_send_vn_from_listener(listener, skb,
									  &src_addr,
									  &local_addr);
					sock_put(listener);
					kfree_skb(skb);
					return ret;
				}

				/*
				 * Version is supported - route to server accept path.
				 * tquic_server_accept() will create a new connection,
				 * perform Retry validation if needed, and initiate
				 * the handshake.
				 */
				ret = tquic_server_accept(listener, skb, &src_addr);

				/*
				 * Server accept consumes the skb on success or
				 * failure, so we return here without freeing it.
				 */
				sock_put(listener);
				return ret;
			}

			/*
			 * No listener found for this port. Fall through to
			 * normal processing which will return -ENOENT and
			 * avoid sending stateless reset for long headers.
			 */
		}
	}

	/* Process the QUIC packet */
	pr_warn("tquic_udp_recv: no Initial match, calling process_packet (conn=%p data[0]=0x%02x len=%zu)\n",
		conn, data[0], len);
	ret = tquic_process_packet(conn, path, data, len, &src_addr);

	/*
	 * Per RFC 9000 Section 10.3:
	 * "An endpoint that receives packets that it cannot process sends
	 * a stateless reset in response."
	 *
	 * If we couldn't find a connection for a short header packet,
	 * we should send a stateless reset. However, we must NOT send
	 * a stateless reset in response to:
	 * - Long header packets (might be Initial packets for new connections)
	 * - Packets that could themselves be stateless resets
	 * - Packets too small to trigger without amplification
	 */
	if (ret == -ENOENT && !(data[0] & TQUIC_HEADER_FORM_LONG) &&
	    len > TQUIC_STATELESS_RESET_MIN_LEN + TQUIC_DEFAULT_CID_LEN) {
		pr_warn("tquic_udp_recv: would send stateless reset (data[0]=0x%02x len=%zu ret=%d)\n",
			data[0], len, ret);
	}
	if (0 && ret == -ENOENT && !(data[0] & TQUIC_HEADER_FORM_LONG) &&
	    /*
	     * CF-299: Do NOT send stateless resets during handshake
	     * (before authentication). A stateless reset is only valid
	     * for short-header packets to established connections.
	     * If we have no connection context, verify the packet is
	     * large enough to not be an amplification vector.
	     * RFC 9000 Section 10.3: "An endpoint MUST NOT generate a
	     * stateless reset that is smaller than the minimum size."
	     */
	    len > TQUIC_STATELESS_RESET_MIN_LEN + TQUIC_DEFAULT_CID_LEN) {
		/*
		 * Short header packet with unknown CID - send stateless reset
		 *
		 * We need to extract the DCID from the packet to generate
		 * the correct token. For short headers, DCID starts at byte 1.
		 */
		struct tquic_cid unknown_cid;
		const u8 *static_key;

		/*
		 * Don't send reset if this packet could itself be a reset
		 * (would cause infinite loop)
		 */
		if (len >= TQUIC_STATELESS_RESET_MIN_LEN) {
			/*
			 * Extract DCID - we don't know the length, but we
			 * can use up to TQUIC_DEFAULT_CID_LEN bytes
			 */
			unknown_cid.len = min_t(size_t,
						len - 1 - TQUIC_STATELESS_RESET_TOKEN_LEN,
						TQUIC_DEFAULT_CID_LEN);
			if (unknown_cid.len > 0) {
				memcpy(unknown_cid.id, data + 1, unknown_cid.len);
				unknown_cid.seq_num = 0;
				unknown_cid.retire_prior_to = 0;

				static_key = tquic_stateless_reset_get_static_key();
				if (static_key) {
					tquic_stateless_reset_send(sk,
								   &local_addr,
								   &src_addr,
								   &unknown_cid,
								   static_key,
								   len);
					tquic_dbg("sent stateless reset for unknown CID\n");
				}
			}
		}
	}

	kfree_skb(skb);
	return ret;
}
EXPORT_SYMBOL_GPL(tquic_udp_recv);

/*
 * Encapsulated receive callback for UDP tunnel
 */
static int tquic_encap_recv(struct sock *sk, struct sk_buff *skb)
{
	/*
	 * CF-625: The UDP layer already pulled past the UDP header before
	 * calling encap_rcv, so skb->data already points at the QUIC
	 * payload. Do NOT strip the UDP header again.
	 */
	return tquic_udp_recv(sk, skb);
}

/*
 * Setup UDP encapsulation for a socket
 */
int tquic_setup_udp_encap(struct sock *sk)
{
	/* Set encapsulation callback */
	udp_sk(sk)->encap_type = 1;  /* Custom encapsulation */
	udp_sk(sk)->encap_rcv = tquic_encap_recv;

	/* Enable GRO */
	tquic_udp_tunnel_encap_enable(sk);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_setup_udp_encap);

/*
 * Remove UDP encapsulation from socket
 */
void tquic_clear_udp_encap(struct sock *sk)
{
	udp_sk(sk)->encap_type = 0;
	udp_sk(sk)->encap_rcv = NULL;
}
EXPORT_SYMBOL_GPL(tquic_clear_udp_encap);

/*
 * =============================================================================
 * Coalesced Packet Handling
 * =============================================================================
 */

/*
 * Process coalesced packets (multiple QUIC packets in single UDP datagram)
 */
int tquic_process_coalesced(struct tquic_connection *conn,
			    struct tquic_path *path,
			    u8 *data, size_t total_len,
			    struct sockaddr_storage *src_addr)
{
	size_t offset = 0;
	int packets = 0;
	int ret;

	while (offset < total_len) {
		size_t pkt_len;
		u8 first_byte = data[offset];

		/*
		 * CF-075: Limit coalesced packets per UDP datagram
		 * to prevent CPU exhaustion from crafted datagrams.
		 */
		if (packets >= TQUIC_MAX_COALESCED_PACKETS) {
			tquic_dbg("coalesced packet limit reached (%d)\n",
				  TQUIC_MAX_COALESCED_PACKETS);
			break;
		}

		if (first_byte & TQUIC_HEADER_FORM_LONG) {
			/* Long header - need to parse length field */
			size_t hdr_len;
			u8 dcid_len, scid_len;
			u64 pkt_len_val;
			u32 pkt_version;
			bool is_initial;

			if (offset + 7 > total_len)
				break;

			/*
			 * CF-176: Read the version field (bytes 1-4)
			 * for version-aware packet type detection.
			 * QUIC v2 (RFC 9369) uses different type bits.
			 */
			pkt_version = get_unaligned_be32(data + offset + 1);
			dcid_len = data[offset + 5];

			/*
			 * SECURITY: Validate CID length per RFC 9000.
			 * Matches validation in tquic_parse_long_header().
			 */
			if (dcid_len > TQUIC_MAX_CID_LEN)
				break;

			if (offset + 6 + dcid_len > total_len)
				break;

			/* Bounds check before reading scid_len */
			if (offset + 6 + dcid_len >= total_len)
				break;

			scid_len = data[offset + 6 + dcid_len];
			if (scid_len > TQUIC_MAX_CID_LEN)
				break;

			if (offset + 7 + dcid_len + scid_len > total_len)
				break;

			hdr_len = 7 + dcid_len + scid_len;

			/*
			 * CF-176: Version-aware Initial packet detection.
			 * v1 wire type 0 = Initial, v2 wire type 1 = Initial.
			 */
			{
				u8 wire_type = (first_byte & 0x30) >> 4;

				if (pkt_version == QUIC_VERSION_2)
					is_initial = (wire_type == QUIC_V2_PACKET_TYPE_INITIAL);
				else
					is_initial = (wire_type == TQUIC_PKT_INITIAL);
			}
			if (is_initial) {
				u64 token_len;
				size_t token_addition;
				int vlen = tquic_decode_varint(
						data + offset + hdr_len,
						total_len - offset - hdr_len,
						&token_len);
				if (vlen < 0)
					break;

				/*
				 * SECURITY: Validate token_len against
				 * reasonable max and use check_add_overflow
				 * to prevent integer overflow in hdr_len.
				 */
				if (token_len >
				    TQUIC_COALESCED_MAX_TOKEN_LEN)
					break;
				if (check_add_overflow((size_t)vlen,
						       (size_t)token_len,
						       &token_addition))
					break;
				if (check_add_overflow(hdr_len,
						       token_addition,
						       &hdr_len))
					break;
				if (offset + hdr_len > total_len)
					break;
			}

			/* Length field */
			{
				int vlen = tquic_decode_varint(
						data + offset + hdr_len,
						total_len - offset - hdr_len,
						&pkt_len_val);
				if (vlen < 0)
					break;
				hdr_len += vlen;
			}

			/*
			 * SECURITY: Use check_add_overflow to prevent
			 * integer overflow in pkt_len computation.
			 */
			if (check_add_overflow(hdr_len, (size_t)pkt_len_val,
					       &pkt_len))
				break;
		} else {
			/* Short header - extends to end of datagram */
			pkt_len = total_len - offset;
		}

		/*
		 * CF-441: Reject coalesced packet when claimed length
		 * exceeds remaining data instead of silently truncating.
		 */
		if (offset + pkt_len > total_len)
			break;

		/*
		 * CF-631: Ensure forward progress.  A zero-length packet
		 * would cause an infinite loop.
		 */
		if (pkt_len == 0)
			break;

		/* Process this packet */
		ret = tquic_process_packet(conn, path, data + offset, pkt_len, src_addr);
		if (ret < 0 && ret != -ENOENT)
			return ret;

		offset += pkt_len;
		packets++;
	}

	return packets;
}
EXPORT_SYMBOL_GPL(tquic_process_coalesced);

/*
 * =============================================================================
 * Module Registration
 * =============================================================================
 */

MODULE_DESCRIPTION("TQUIC Packet Reception Path");
MODULE_LICENSE("GPL");
