/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: QLOG v2 Format Declarations
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 */

#ifndef _TQUIC_QLOG_V2_H
#define _TQUIC_QLOG_V2_H

struct tquic_qlog;
struct qlog_v2_packet_header;
struct qlog_v2_metrics;
struct qlog_v2_path_info;

int qlog_v2_emit_packet_sent(struct tquic_qlog *qlog,
			     const struct qlog_v2_packet_header *hdr,
			     u32 path_id, bool is_coalesced,
			     const void *frames, u32 frame_count,
			     char *buf, size_t size);
int qlog_v2_emit_packet_received(struct tquic_qlog *qlog,
				 const struct qlog_v2_packet_header *hdr,
				 u32 path_id, u8 ecn,
				 char *buf, size_t size);
int qlog_v2_emit_metrics_updated(struct tquic_qlog *qlog,
				 const struct qlog_v2_metrics *m,
				 char *buf, size_t size);
int qlog_v2_emit_bbr_state(struct tquic_qlog *qlog,
			   const struct qlog_v2_metrics *m,
			   char *buf, size_t size);
int qlog_v2_emit_path_assigned(struct tquic_qlog *qlog,
			       const struct qlog_v2_path_info *path,
			       char *buf, size_t size);
int qlog_v2_emit_path_updated(struct tquic_qlog *qlog,
			      u32 path_id, u32 old_state, u32 new_state,
			      char *buf, size_t size);
int qlog_v2_emit_frame(u64 frame_type, const void *data, size_t data_len,
		       char *buf, size_t buf_len);
int qlog_v2_init(void);
void qlog_v2_exit(void);

#endif /* _TQUIC_QLOG_V2_H */
