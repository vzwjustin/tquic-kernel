/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: Frame Processing Interface
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 *
 * Declarations for frame-level state machine handlers.
 * For wire-format parsing see core/frame.c.
 */

#ifndef TQUIC_FRAME_PROCESS_H
#define TQUIC_FRAME_PROCESS_H

#include <linux/types.h>
#include <linux/skbuff.h>
#include <net/tquic.h>

/*
 * QUIC variable-length integer decoder (RFC 9000 Section 16).
 *
 * Decodes a QUIC variable-length integer from @buf of length @buf_len
 * into @val.  Returns the number of bytes consumed on success, or a
 * negative errno on failure (-EINVAL if @buf_len is too short).
 *
 * Placed here so both tquic_input.c and core/frame_process.c share a
 * single definition without a separate translation unit.
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

/* Receive context for per-packet frame processing */
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

/*
 * Demultiplex and dispatch all QUIC frames in a decrypted packet payload.
 *
 * @conn:      Connection state
 * @path:      Receiving path
 * @payload:   Decrypted packet payload
 * @len:       Payload length in bytes
 * @enc_level: Encryption level (TQUIC_PKT_INITIAL / HANDSHAKE / 0-RTT / 1-RTT)
 * @pkt_num:   Reconstructed packet number
 *
 * Returns 0 on success or a negative errno.  On protocol errors the
 * appropriate QUIC error code is set on @conn before returning.
 */
int tquic_process_frames(struct tquic_connection *conn,
			 struct tquic_path *path,
			 u8 *payload, size_t len,
			 int enc_level, u64 pkt_num);

#endif /* TQUIC_FRAME_PROCESS_H */
