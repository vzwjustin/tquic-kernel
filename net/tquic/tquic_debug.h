/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC Debug Infrastructure
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Provides debugfs interface and debug macros for TQUIC subsystem.
 *
 * Debugfs entries (/sys/kernel/debug/tquic/):
 *   connections  - All active connections with detailed state
 *   paths        - Per-path state and metrics for all connections
 *   handshake    - Handshake state for active/recent connections
 *   debug_level  - Read/write debug verbosity (0=off, 1=error, 2=warn, 3=info, 4=debug)
 *
 * Debug logging macros:
 *   tquic_dbg()  - Debug messages (level >= 4)
 *   tquic_info() - Informational (level >= 3)
 *   tquic_warn() - Warnings (level >= 2)
 *   tquic_err()  - Errors (level >= 1)
 */

#ifndef _NET_TQUIC_DEBUG_H
#define _NET_TQUIC_DEBUG_H

#include <linux/debugfs.h>
#include <net/tquic.h>

/* Debug levels */
#define TQUIC_DBG_OFF	0
#define TQUIC_DBG_ERR	1
#define TQUIC_DBG_WARN	2
#define TQUIC_DBG_INFO	3
#define TQUIC_DBG_DEBUG	4

/* Global debug level (set via debugfs or sysctl) */
extern int tquic_debug_level;

/*
 * Debug logging macros with level check
 *
 * These use pr_debug/pr_info/pr_warn/pr_err but guard on the
 * global debug level to avoid unnecessary formatting overhead.
 * The tquic: prefix is added for dmesg filtering.
 */
#define tquic_dbg(fmt, ...)						\
	do {								\
		if (tquic_debug_level >= TQUIC_DBG_DEBUG)		\
			pr_debug("tquic: " fmt, ##__VA_ARGS__);		\
	} while (0)

#define tquic_info(fmt, ...)						\
	do {								\
		if (tquic_debug_level >= TQUIC_DBG_INFO)		\
			pr_info("tquic: " fmt, ##__VA_ARGS__);		\
	} while (0)

#define tquic_warn(fmt, ...)						\
	do {								\
		if (tquic_debug_level >= TQUIC_DBG_WARN)		\
			pr_warn("tquic: " fmt, ##__VA_ARGS__);		\
	} while (0)

#define tquic_err(fmt, ...)						\
	do {								\
		if (tquic_debug_level >= TQUIC_DBG_ERR)			\
			pr_err("tquic: " fmt, ##__VA_ARGS__);		\
	} while (0)

/*
 * Connection-scoped debug macros (include SCID prefix)
 */
#define tquic_conn_dbg(conn, fmt, ...)					\
	do {								\
		if (tquic_debug_level >= TQUIC_DBG_DEBUG && (conn))	\
			pr_debug("tquic: [%*phN] " fmt,		\
				 (conn)->scid.len, (conn)->scid.id,	\
				 ##__VA_ARGS__);			\
	} while (0)

#define tquic_conn_info(conn, fmt, ...)					\
	do {								\
		if (tquic_debug_level >= TQUIC_DBG_INFO && (conn))	\
			pr_info("tquic: [%*phN] " fmt,			\
				(conn)->scid.len, (conn)->scid.id,	\
				##__VA_ARGS__);				\
	} while (0)

#define tquic_conn_warn(conn, fmt, ...)					\
	do {								\
		if (tquic_debug_level >= TQUIC_DBG_WARN && (conn))	\
			pr_warn("tquic: [%*phN] " fmt,			\
				(conn)->scid.len, (conn)->scid.id,	\
				##__VA_ARGS__);				\
	} while (0)

#define tquic_conn_err(conn, fmt, ...)					\
	do {								\
		if (tquic_debug_level >= TQUIC_DBG_ERR && (conn))	\
			pr_err("tquic: [%*phN] " fmt,			\
			       (conn)->scid.len, (conn)->scid.id,	\
			       ##__VA_ARGS__);				\
	} while (0)

/* Tracepoint helper declarations (diag/tracepoints.c) */
void tquic_trace_handshake_start(struct tquic_connection *conn,
				 bool is_server, bool has_session_ticket,
				 u32 verify_mode);
void tquic_trace_handshake_complete(struct tquic_connection *conn,
				    int status, u64 duration_us);
void tquic_trace_failover(struct tquic_connection *conn,
			  u32 failed_path_id, u32 new_path_id,
			  u32 reason, u64 rtt_us);
void tquic_trace_bond_state(struct tquic_connection *conn,
			    u32 bond_mode, u32 active_paths,
			    u64 total_bandwidth);
void tquic_trace_frame_debug(struct tquic_connection *conn,
			     u32 frame_type, u32 length,
			     u32 path_id, bool is_send);

/* Debugfs init/exit */
#ifdef CONFIG_TQUIC_DEBUGFS
int tquic_debug_init(void);
void tquic_debug_exit(void);
#else
static inline int tquic_debug_init(void) { return 0; }
static inline void tquic_debug_exit(void) {}
#endif

#endif /* _NET_TQUIC_DEBUG_H */
