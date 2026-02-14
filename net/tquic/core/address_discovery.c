// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: QUIC Address Discovery Extension Implementation
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Implementation of draft-ietf-quic-address-discovery.
 *
 * This extension enables endpoints to:
 * 1. Inform peers about their observed source address
 * 2. Learn their own external address as seen by peers
 * 3. Detect NAT rebinding events
 *
 * Security considerations:
 * - Sequence numbers prevent replay attacks
 * - Rate limiting prevents amplification attacks
 * - Address validation before acting on reported addresses
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/jiffies.h>
#include <linux/random.h>
#include <net/tquic.h>

#include "address_discovery.h"
#include "varint.h"
#include "transport_params.h"

/*
 * Default configuration values
 */
#define DEFAULT_RATE_LIMIT_MS		1000
#define DEFAULT_REPORT_INTERVAL_MS	5000
#define ANTI_REPLAY_WINDOW_BITS		64

/*
 * =============================================================================
 * Frame Transmission Helper
 * =============================================================================
 */

/**
 * tquic_queue_frame - Queue a frame for transmission
 * @conn: Connection to queue the frame on
 * @data: Frame data buffer
 * @len: Length of frame data
 * @frame_type: Type of the frame being queued (unused, frame type is in data)
 *
 * Allocates an sk_buff for the frame and queues it on the connection's
 * control frame queue for transmission with the next packet.
 *
 * Return: 0 on success, negative error code on failure
 */
static int tquic_queue_frame(struct tquic_connection *conn,
			     const u8 *data, size_t len, u64 frame_type)
{
	struct sk_buff *skb;

	(void)frame_type;  /* Frame type is encoded in data */

	if (!conn || !data || len == 0)
		return -EINVAL;

	/* Allocate sk_buff for the frame */
	skb = alloc_skb(len + 32, GFP_ATOMIC);
	if (!skb)
		return -ENOMEM;

	/* Reserve headroom for potential header additions */
	skb_reserve(skb, 16);

	/* Copy frame data (includes encoded frame type) */
	skb_put_data(skb, data, len);

	/* Queue for transmission */
	spin_lock_bh(&conn->lock);
	skb_queue_tail(&conn->control_frames, skb);
	spin_unlock_bh(&conn->lock);

	/* Trigger transmission (schedule tx_work if needed) */
	if (!work_pending(&conn->tx_work))
		schedule_work(&conn->tx_work);

	return 0;
}

/*
 * =============================================================================
 * State Management
 * =============================================================================
 */

/**
 * tquic_addr_discovery_init - Initialize address discovery state
 * @state: State structure to initialize
 */
int tquic_addr_discovery_init(struct tquic_addr_discovery_state *state)
{
	if (!state)
		return -EINVAL;

	memset(state, 0, sizeof(*state));
	spin_lock_init(&state->lock);

	/* Default configuration */
	state->config.enabled = false;  /* Must be negotiated */
	state->config.report_on_change = true;
	state->config.report_periodically = false;
	state->config.report_interval_ms = DEFAULT_REPORT_INTERVAL_MS;
	state->config.max_rate_ms = DEFAULT_RATE_LIMIT_MS;

	/* Initialize sequence numbers */
	state->local_send_seq = 0;
	state->remote_recv_seq = 0;
	state->recv_seq_bitmap = 0;

	/* Initialize timestamps */
	state->last_send_time = ktime_set(0, 0);
	state->last_addr_change = ktime_set(0, 0);

	/* Initialize observation lists */
	INIT_LIST_HEAD(&state->pending_observations);
	state->pending_count = 0;

	/* No addresses observed yet */
	state->current_observed_valid = false;
	state->reported_addr_valid = false;
	state->nat_rebind_detected = false;

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_addr_discovery_init);

/**
 * tquic_addr_discovery_cleanup - Clean up address discovery state
 * @state: State structure to clean up
 */
void tquic_addr_discovery_cleanup(struct tquic_addr_discovery_state *state)
{
	struct tquic_observed_address *obs, *tmp;
	unsigned long flags;

	if (!state)
		return;

	spin_lock_irqsave(&state->lock, flags);

	/* Free pending observations */
	list_for_each_entry_safe(obs, tmp, &state->pending_observations, list) {
		list_del_init(&obs->list);
		kfree(obs);
	}
	state->pending_count = 0;

	spin_unlock_irqrestore(&state->lock, flags);
}
EXPORT_SYMBOL_GPL(tquic_addr_discovery_cleanup);

/**
 * tquic_addr_discovery_set_config - Update configuration
 */
int tquic_addr_discovery_set_config(struct tquic_addr_discovery_state *state,
				    const struct tquic_addr_discovery_config *config)
{
	unsigned long flags;

	if (!state || !config)
		return -EINVAL;

	/* Validate rate limit (minimum 100ms to prevent abuse) */
	if (config->max_rate_ms < 100)
		return -EINVAL;

	spin_lock_irqsave(&state->lock, flags);
	memcpy(&state->config, config, sizeof(state->config));
	spin_unlock_irqrestore(&state->lock, flags);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_addr_discovery_set_config);

/*
 * =============================================================================
 * Frame Encoding
 * =============================================================================
 */

/**
 * tquic_observed_address_frame_size - Calculate encoded frame size
 */
size_t tquic_observed_address_frame_size(const struct tquic_frame_observed_address *frame)
{
	size_t size = 0;

	if (!frame)
		return 0;

	/* Frame type (0x9f00 = 2-byte varint) */
	size += tquic_varint_size(TQUIC_FRAME_OBSERVED_ADDRESS);

	/* Sequence number (varint) */
	size += tquic_varint_size(frame->seq);

	/* IP version (1 byte) */
	size += 1;

	/* IP address */
	if (frame->ip_version == TQUIC_ADDR_DISC_IPV4) {
		size += 4;  /* IPv4 address */
	} else if (frame->ip_version == TQUIC_ADDR_DISC_IPV6) {
		size += 16;  /* IPv6 address */
	} else {
		return 0;  /* Invalid IP version */
	}

	/* Port (2 bytes) */
	size += 2;

	return size;
}
EXPORT_SYMBOL_GPL(tquic_observed_address_frame_size);

/**
 * tquic_encode_observed_address - Encode OBSERVED_ADDRESS frame
 */
ssize_t tquic_encode_observed_address(u8 *buf, size_t buflen,
				      const struct tquic_frame_observed_address *frame)
{
	size_t offset = 0;
	int ret;
	size_t needed;

	if (!buf || !frame)
		return -EINVAL;

	/* Validate IP version */
	if (frame->ip_version != TQUIC_ADDR_DISC_IPV4 &&
	    frame->ip_version != TQUIC_ADDR_DISC_IPV6)
		return -EINVAL;

	/* Check buffer size */
	needed = tquic_observed_address_frame_size(frame);
	if (needed == 0 || buflen < needed)
		return -ENOSPC;

	/* Frame type (0x9f00) */
	ret = tquic_varint_encode(TQUIC_FRAME_OBSERVED_ADDRESS, buf + offset,
				  buflen - offset);
	if (ret <= 0)
		return -ENOSPC;
	offset += ret;

	/* Sequence number */
	ret = tquic_varint_encode(frame->seq, buf + offset, buflen - offset);
	if (ret <= 0)
		return -ENOSPC;
	offset += ret;

	/* IP version */
	buf[offset++] = frame->ip_version;

	/* IP address */
	if (frame->ip_version == TQUIC_ADDR_DISC_IPV4) {
		memcpy(buf + offset, &frame->addr.v4, 4);
		offset += 4;
	} else {
		memcpy(buf + offset, &frame->addr.v6, 16);
		offset += 16;
	}

	/* Port (network byte order) */
	buf[offset++] = (u8)(ntohs(frame->port) >> 8);
	buf[offset++] = (u8)ntohs(frame->port);

	return offset;
}
EXPORT_SYMBOL_GPL(tquic_encode_observed_address);

/*
 * =============================================================================
 * Frame Decoding
 * =============================================================================
 */

/**
 * tquic_decode_observed_address - Decode OBSERVED_ADDRESS frame
 */
ssize_t tquic_decode_observed_address(const u8 *buf, size_t buflen,
				      struct tquic_frame_observed_address *frame)
{
	size_t offset = 0;
	int ret;
	u64 value;

	if (!buf || !frame)
		return -EINVAL;

	memset(frame, 0, sizeof(*frame));

	/* Minimum size: seq (1) + version (1) + addr (4) + port (2) = 8 */
	if (buflen < 8)
		return -EINVAL;

	/* Decode sequence number */
	ret = tquic_varint_decode(buf + offset, buflen - offset, &value);
	if (ret < 0)
		return ret;
	frame->seq = value;
	offset += ret;

	/* Check remaining bytes */
	if (buflen - offset < 1)
		return -EINVAL;

	/* Decode IP version */
	frame->ip_version = buf[offset++];

	/* Validate IP version and decode address */
	if (frame->ip_version == TQUIC_ADDR_DISC_IPV4) {
		if (buflen - offset < 4 + 2)  /* 4 addr + 2 port */
			return -EINVAL;
		memcpy(&frame->addr.v4, buf + offset, 4);
		offset += 4;
	} else if (frame->ip_version == TQUIC_ADDR_DISC_IPV6) {
		if (buflen - offset < 16 + 2)  /* 16 addr + 2 port */
			return -EINVAL;
		memcpy(&frame->addr.v6, buf + offset, 16);
		offset += 16;
	} else {
		pr_debug("tquic: OBSERVED_ADDRESS invalid IP version: %u\n",
			 frame->ip_version);
		return -EPROTO;
	}

	/* Decode port (network byte order in frame, store as network order) */
	frame->port = htons(((u16)buf[offset] << 8) | buf[offset + 1]);
	offset += 2;

	return offset;
}
EXPORT_SYMBOL_GPL(tquic_decode_observed_address);

/*
 * =============================================================================
 * Anti-Replay Window Management
 * =============================================================================
 */

/**
 * check_and_update_replay_window - Check sequence and update anti-replay window
 * @state: Address discovery state
 * @seq: Incoming sequence number
 *
 * Implements sliding window anti-replay protection similar to IPsec.
 * The window tracks the highest seen sequence and a bitmap of recent sequences.
 *
 * Return: true if sequence is acceptable, false if replay detected
 */
static bool check_and_update_replay_window(struct tquic_addr_discovery_state *state,
					   u64 seq)
{
	u64 diff;

	/* First sequence - initialize window */
	if (state->remote_recv_seq == 0 && state->recv_seq_bitmap == 0) {
		state->remote_recv_seq = seq;
		state->recv_seq_bitmap = 1;
		return true;
	}

	/* Check if sequence is ahead of window */
	if (seq > state->remote_recv_seq) {
		diff = seq - state->remote_recv_seq;

		/* Shift window */
		if (diff >= ANTI_REPLAY_WINDOW_BITS) {
			/* Far ahead - reset window */
			state->recv_seq_bitmap = 1;
		} else {
			/* Shift and set new bit */
			state->recv_seq_bitmap <<= diff;
			state->recv_seq_bitmap |= 1;
		}
		state->remote_recv_seq = seq;
		return true;
	}

	/* Check if sequence is within window */
	diff = state->remote_recv_seq - seq;
	if (diff >= ANTI_REPLAY_WINDOW_BITS) {
		/* Too old - outside window */
		return false;
	}

	/* Check if already seen */
	if (state->recv_seq_bitmap & (1ULL << diff)) {
		/* Duplicate */
		return false;
	}

	/* Mark as seen */
	state->recv_seq_bitmap |= (1ULL << diff);
	return true;
}

/*
 * =============================================================================
 * Frame Processing
 * =============================================================================
 */

/**
 * tquic_handle_observed_address - Process received OBSERVED_ADDRESS frame
 */
int tquic_handle_observed_address(struct tquic_connection *conn,
				  struct tquic_addr_discovery_state *state,
				  const struct tquic_frame_observed_address *frame)
{
	struct tquic_observed_address new_addr;
	bool addr_changed = false;
	unsigned long flags;

	if (!state || !frame)
		return -EINVAL;

	spin_lock_irqsave(&state->lock, flags);

	/* Check if address discovery is enabled */
	if (!state->config.enabled) {
		spin_unlock_irqrestore(&state->lock, flags);
		pr_debug("tquic: OBSERVED_ADDRESS received but feature disabled\n");
		return -EPROTO;
	}

	/* Anti-replay check */
	if (!check_and_update_replay_window(state, frame->seq)) {
		state->frames_rejected++;
		spin_unlock_irqrestore(&state->lock, flags);
		pr_debug("tquic: OBSERVED_ADDRESS replay detected (seq=%llu)\n",
			 frame->seq);
		return -EALREADY;
	}

	state->frames_received++;

	/* Convert frame to observed_address struct */
	new_addr.seq = frame->seq;
	new_addr.ip_version = frame->ip_version;
	new_addr.port = frame->port;
	new_addr.timestamp = ktime_get();
	if (frame->ip_version == TQUIC_ADDR_DISC_IPV4) {
		new_addr.addr.v4 = frame->addr.v4;
	} else {
		memcpy(&new_addr.addr.v6, &frame->addr.v6, sizeof(struct in6_addr));
	}

	/* Check if address changed from previous report */
	if (state->reported_addr_valid) {
		if (!tquic_observed_address_equal(&state->reported_addr, &new_addr)) {
			addr_changed = true;
			state->addr_change_count++;
			state->last_addr_change = ktime_get();
			state->nat_rebind_detected = true;

			pr_info("tquic: observed address changed (changes=%u)\n",
				state->addr_change_count);
		}
	} else {
		/* First report */
		addr_changed = true;
	}

	/* Update reported address (only if newer sequence) */
	if (frame->seq >= state->reported_addr.seq || !state->reported_addr_valid) {
		memcpy(&state->reported_addr, &new_addr, sizeof(new_addr));
		state->reported_addr_valid = true;
	}

	spin_unlock_irqrestore(&state->lock, flags);

	/* Log the observation */
	if (frame->ip_version == TQUIC_ADDR_DISC_IPV4) {
		pr_debug("tquic: observed address IPv4 %pI4:%u (seq=%llu)\n",
			 &frame->addr.v4, ntohs(frame->port), frame->seq);
	} else {
		pr_debug("tquic: observed address IPv6 %pI6c:%u (seq=%llu)\n",
			 &frame->addr.v6, ntohs(frame->port), frame->seq);
	}

	/* Notify path manager if address changed */
	if (addr_changed && conn) {
		/* Could trigger path validation or migration here */
	}

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_handle_observed_address);

/**
 * tquic_send_observed_address - Send OBSERVED_ADDRESS to peer
 */
int tquic_send_observed_address(struct tquic_connection *conn,
				struct tquic_addr_discovery_state *state,
				const struct sockaddr_storage *addr)
{
	struct tquic_frame_observed_address frame;
	u8 buf[64];  /* Max frame size: type(2) + seq(8) + ver(1) + addr(16) + port(2) = 29 */
	ssize_t frame_len;
	ktime_t now;
	s64 elapsed_ms;
	unsigned long flags;
	int ret = 0;

	if (!conn || !state || !addr)
		return -EINVAL;

	spin_lock_irqsave(&state->lock, flags);

	/* Check if enabled */
	if (!state->config.enabled) {
		spin_unlock_irqrestore(&state->lock, flags);
		return -ENOENT;
	}

	/* Rate limiting */
	now = ktime_get();
	elapsed_ms = ktime_ms_delta(now, state->last_send_time);
	if (elapsed_ms < state->config.max_rate_ms && state->frames_sent > 0) {
		spin_unlock_irqrestore(&state->lock, flags);
		return -EAGAIN;
	}

	/* Build frame */
	frame.seq = state->local_send_seq++;

	if (addr->ss_family == AF_INET) {
		const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
		frame.ip_version = TQUIC_ADDR_DISC_IPV4;
		frame.addr.v4 = sin->sin_addr.s_addr;
		frame.port = sin->sin_port;
	} else if (addr->ss_family == AF_INET6) {
		const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;
		frame.ip_version = TQUIC_ADDR_DISC_IPV6;
		memcpy(&frame.addr.v6, &sin6->sin6_addr, sizeof(struct in6_addr));
		frame.port = sin6->sin6_port;
	} else {
		spin_unlock_irqrestore(&state->lock, flags);
		return -EAFNOSUPPORT;
	}

	/* Encode frame */
	frame_len = tquic_encode_observed_address(buf, sizeof(buf), &frame);
	if (frame_len < 0) {
		state->local_send_seq--;  /* Rollback sequence */
		spin_unlock_irqrestore(&state->lock, flags);
		return frame_len;
	}

	/* Update state before release */
	state->last_send_time = now;
	state->frames_sent++;

	spin_unlock_irqrestore(&state->lock, flags);

	/* Queue frame for transmission */
	ret = tquic_queue_frame(conn, buf, frame_len, TQUIC_FRAME_OBSERVED_ADDRESS);
	if (ret < 0) {
		pr_debug("tquic: failed to queue OBSERVED_ADDRESS frame: %d\n", ret);
		return ret;
	}

	pr_debug("tquic: sent OBSERVED_ADDRESS (seq=%llu)\n", frame.seq);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_send_observed_address);

/**
 * tquic_update_observed_address - Update current observation without sending
 */
int tquic_update_observed_address(struct tquic_addr_discovery_state *state,
				  const struct sockaddr_storage *addr,
				  bool *changed)
{
	struct tquic_observed_address new_obs;
	unsigned long flags;
	int ret;

	if (!state || !addr)
		return -EINVAL;

	/* Convert sockaddr to observed_address */
	ret = tquic_sockaddr_to_observed(addr, &new_obs);
	if (ret < 0)
		return ret;

	spin_lock_irqsave(&state->lock, flags);

	/* Check if changed */
	if (changed) {
		if (state->current_observed_valid) {
			*changed = !tquic_observed_address_equal(&state->current_observed,
								 &new_obs);
		} else {
			*changed = true;
		}
	}

	/* Update observation (preserve timestamp) */
	new_obs.timestamp = ktime_get();
	memcpy(&state->current_observed, &new_obs, sizeof(new_obs));
	state->current_observed_valid = true;

	spin_unlock_irqrestore(&state->lock, flags);

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_update_observed_address);

/*
 * =============================================================================
 * NAT Rebinding Detection
 * =============================================================================
 */

/**
 * tquic_detect_nat_rebinding - Check for NAT rebinding
 */
bool tquic_detect_nat_rebinding(struct tquic_connection *conn,
				struct tquic_addr_discovery_state *state,
				const struct sockaddr_storage *from_addr)
{
	struct tquic_path *active_path;
	bool rebind_detected = false;

	if (!conn || !state || !from_addr)
		return false;

	/*
	 * Compare incoming address against the expected peer address.
	 * If they differ, this indicates the peer's address has changed,
	 * potentially due to NAT rebinding.
	 */
	rcu_read_lock();
	active_path = rcu_dereference(conn->active_path);
	if (active_path) {
		const struct sockaddr_storage *expected = &active_path->remote_addr;

		if (from_addr->ss_family == expected->ss_family) {
			if (from_addr->ss_family == AF_INET) {
				const struct sockaddr_in *from4 =
					(const struct sockaddr_in *)from_addr;
				const struct sockaddr_in *exp4 =
					(const struct sockaddr_in *)expected;

				if (from4->sin_addr.s_addr != exp4->sin_addr.s_addr ||
				    from4->sin_port != exp4->sin_port) {
					rebind_detected = true;
				}
			} else if (from_addr->ss_family == AF_INET6) {
				const struct sockaddr_in6 *from6 =
					(const struct sockaddr_in6 *)from_addr;
				const struct sockaddr_in6 *exp6 =
					(const struct sockaddr_in6 *)expected;

				if (!ipv6_addr_equal(&from6->sin6_addr, &exp6->sin6_addr) ||
				    from6->sin6_port != exp6->sin6_port) {
					rebind_detected = true;
				}
			}
		} else {
			/* Address family changed - definitely rebinding */
			rebind_detected = true;
		}
	}
	rcu_read_unlock();

	if (rebind_detected) {
		unsigned long flags;

		spin_lock_irqsave(&state->lock, flags);
		state->nat_rebind_detected = true;
		state->addr_change_count++;
		state->last_addr_change = ktime_get();
		spin_unlock_irqrestore(&state->lock, flags);

		pr_info("tquic: NAT rebinding detected\n");
	}

	return rebind_detected;
}
EXPORT_SYMBOL_GPL(tquic_detect_nat_rebinding);

/**
 * tquic_addr_discovery_get_reported - Get the reported address
 */
int tquic_addr_discovery_get_reported(struct tquic_addr_discovery_state *state,
				      struct sockaddr_storage *addr)
{
	unsigned long flags;
	int ret;

	if (!state || !addr)
		return -EINVAL;

	spin_lock_irqsave(&state->lock, flags);

	if (!state->reported_addr_valid) {
		spin_unlock_irqrestore(&state->lock, flags);
		return -ENODATA;
	}

	ret = tquic_observed_to_sockaddr(&state->reported_addr, addr);

	spin_unlock_irqrestore(&state->lock, flags);

	return ret;
}
EXPORT_SYMBOL_GPL(tquic_addr_discovery_get_reported);

/**
 * tquic_addr_discovery_nat_rebind_detected - Check if NAT rebind detected
 */
bool tquic_addr_discovery_nat_rebind_detected(struct tquic_addr_discovery_state *state)
{
	bool detected;
	unsigned long flags;

	if (!state)
		return false;

	spin_lock_irqsave(&state->lock, flags);
	detected = state->nat_rebind_detected;
	spin_unlock_irqrestore(&state->lock, flags);

	return detected;
}
EXPORT_SYMBOL_GPL(tquic_addr_discovery_nat_rebind_detected);

/**
 * tquic_addr_discovery_clear_nat_rebind - Clear NAT rebind flag
 */
void tquic_addr_discovery_clear_nat_rebind(struct tquic_addr_discovery_state *state)
{
	unsigned long flags;

	if (!state)
		return;

	spin_lock_irqsave(&state->lock, flags);
	state->nat_rebind_detected = false;
	spin_unlock_irqrestore(&state->lock, flags);
}
EXPORT_SYMBOL_GPL(tquic_addr_discovery_clear_nat_rebind);

/*
 * =============================================================================
 * Utility Functions
 * =============================================================================
 */

/**
 * tquic_sockaddr_to_observed - Convert sockaddr to observed_address
 */
int tquic_sockaddr_to_observed(const struct sockaddr_storage *addr,
			       struct tquic_observed_address *observed)
{
	if (!addr || !observed)
		return -EINVAL;

	memset(observed, 0, sizeof(*observed));
	observed->timestamp = ktime_get();

	if (addr->ss_family == AF_INET) {
		const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
		observed->ip_version = TQUIC_ADDR_DISC_IPV4;
		observed->addr.v4 = sin->sin_addr.s_addr;
		observed->port = sin->sin_port;
	} else if (addr->ss_family == AF_INET6) {
		const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;
		observed->ip_version = TQUIC_ADDR_DISC_IPV6;
		memcpy(&observed->addr.v6, &sin6->sin6_addr, sizeof(struct in6_addr));
		observed->port = sin6->sin6_port;
	} else {
		return -EAFNOSUPPORT;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_sockaddr_to_observed);

/**
 * tquic_observed_to_sockaddr - Convert observed_address to sockaddr
 */
int tquic_observed_to_sockaddr(const struct tquic_observed_address *observed,
			       struct sockaddr_storage *addr)
{
	if (!observed || !addr)
		return -EINVAL;

	memset(addr, 0, sizeof(*addr));

	if (observed->ip_version == TQUIC_ADDR_DISC_IPV4) {
		struct sockaddr_in *sin = (struct sockaddr_in *)addr;
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = observed->addr.v4;
		sin->sin_port = observed->port;
	} else if (observed->ip_version == TQUIC_ADDR_DISC_IPV6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)addr;
		sin6->sin6_family = AF_INET6;
		memcpy(&sin6->sin6_addr, &observed->addr.v6, sizeof(struct in6_addr));
		sin6->sin6_port = observed->port;
	} else {
		return -EAFNOSUPPORT;
	}

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_observed_to_sockaddr);

/**
 * tquic_observed_address_equal - Compare two observed addresses
 */
bool tquic_observed_address_equal(const struct tquic_observed_address *a,
				  const struct tquic_observed_address *b)
{
	if (!a || !b)
		return false;

	if (a->ip_version != b->ip_version)
		return false;

	if (a->port != b->port)
		return false;

	if (a->ip_version == TQUIC_ADDR_DISC_IPV4) {
		return a->addr.v4 == b->addr.v4;
	} else if (a->ip_version == TQUIC_ADDR_DISC_IPV6) {
		return ipv6_addr_equal(&a->addr.v6, &b->addr.v6);
	}

	return false;
}
EXPORT_SYMBOL_GPL(tquic_observed_address_equal);

/**
 * tquic_addr_discovery_get_stats - Get address discovery statistics
 */
void tquic_addr_discovery_get_stats(struct tquic_addr_discovery_state *state,
				    u64 *frames_sent, u64 *frames_received,
				    u64 *frames_rejected, u32 *addr_changes)
{
	unsigned long flags;

	if (!state)
		return;

	spin_lock_irqsave(&state->lock, flags);

	if (frames_sent)
		*frames_sent = state->frames_sent;
	if (frames_received)
		*frames_received = state->frames_received;
	if (frames_rejected)
		*frames_rejected = state->frames_rejected;
	if (addr_changes)
		*addr_changes = state->addr_change_count;

	spin_unlock_irqrestore(&state->lock, flags);
}
EXPORT_SYMBOL_GPL(tquic_addr_discovery_get_stats);

/*
 * =============================================================================
 * Transport Parameter Support
 * =============================================================================
 */

/**
 * tquic_addr_discovery_tp_enabled - Check if peer supports address discovery
 */
bool tquic_addr_discovery_tp_enabled(const struct tquic_negotiated_params *params)
{
	if (!params)
		return false;

	return params->address_discovery_enabled;
}
EXPORT_SYMBOL_GPL(tquic_addr_discovery_tp_enabled);

MODULE_DESCRIPTION("TQUIC QUIC Address Discovery Extension");
MODULE_LICENSE("GPL");
