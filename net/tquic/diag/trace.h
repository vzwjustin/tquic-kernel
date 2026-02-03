/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * QUIC Tracepoint Header
 *
 * Include this header in QUIC source files to use tracepoints.
 * The tracepoint functions (trace_quic_*) will be available after inclusion.
 *
 * Example usage:
 *   #include "trace.h"
 *
 *   trace_quic_packet_recv(conn_id, pkt_num, len, pn_space);
 *
 * Enable tracing at runtime:
 *   echo 1 > /sys/kernel/debug/tracing/events/quic/enable
 *   cat /sys/kernel/debug/tracing/trace_pipe
 *
 * Copyright (c) 2024 Linux QUIC Authors
 */

#ifndef _QUIC_TRACE_H
#define _QUIC_TRACE_H

#include <uapi/linux/quic.h>

/*
 * Define the path where trace headers are located.
 * This is needed for TRACE_INCLUDE_PATH to resolve correctly.
 */
#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH ../../include/trace/events

/*
 * Define the trace include file.
 */
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE quic

#include <trace/events/quic.h>

/*
 * Helper function to extract connection ID as u64 for tracing.
 * Uses the first 8 bytes of the connection ID for identification.
 */
static inline u64 quic_trace_conn_id(const struct quic_connection_id *cid)
{
	u64 id = 0;
	int i;
	int len = cid->len > 8 ? 8 : cid->len;

	for (i = 0; i < len; i++)
		id = (id << 8) | cid->data[i];

	return id;
}

#endif /* _QUIC_TRACE_H */
