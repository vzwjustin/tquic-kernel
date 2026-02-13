/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: QLOG v2 Format Declarations
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 */

#ifndef _TQUIC_QLOG_V2_H
#define _TQUIC_QLOG_V2_H

struct tquic_qlog;
struct tquic_sent_packet;
struct tquic_cc_state;

int qlog_v2_emit_packet_sent(struct tquic_qlog *qlog,
			     struct tquic_sent_packet *pkt);
int qlog_v2_emit_packet_received(struct tquic_qlog *qlog,
				 const u8 *data, u32 len, u64 pn);
int qlog_v2_emit_metrics_updated(struct tquic_qlog *qlog,
				 struct tquic_cc_state *cc);
int qlog_v2_emit_bbr_state(struct tquic_qlog *qlog,
			   struct tquic_cc_state *cc);
int qlog_v2_emit_path_assigned(struct tquic_qlog *qlog,
			       u64 stream_id, u32 path_id);
int qlog_v2_emit_path_updated(struct tquic_qlog *qlog,
			      u32 path_id, const char *event);
int qlog_v2_emit_frame(u64 frame_type, const void *data, size_t data_len,
		       char *buf, size_t buf_len);
int qlog_v2_init(void);
void qlog_v2_exit(void);

#endif /* _TQUIC_QLOG_V2_H */
