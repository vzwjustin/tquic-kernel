/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * TQUIC inet_diag interface
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Netlink attributes and structures for ss tool integration.
 * Used by inet_diag handler to provide TQUIC connection diagnostics.
 */

#ifndef _UAPI_LINUX_TQUIC_DIAG_H
#define _UAPI_LINUX_TQUIC_DIAG_H

#include <linux/types.h>

/*
 * Netlink attributes for TQUIC inet_diag
 *
 * These attributes are used by the ss tool to display extended
 * TQUIC connection information. Connection IDs are shown in full
 * hex format for packet capture correlation.
 */
enum {
	TQUIC_DIAG_ATTR_UNSPEC,
	TQUIC_DIAG_ATTR_INFO,		/* struct tquic_info */
	TQUIC_DIAG_ATTR_SCID,		/* Source CID (variable length) */
	TQUIC_DIAG_ATTR_DCID,		/* Dest CID (variable length) */
	TQUIC_DIAG_ATTR_VERSION,	/* QUIC version __u32 */
	TQUIC_DIAG_ATTR_PATHS,		/* Nested: per-path info */
	TQUIC_DIAG_ATTR_STREAMS,	/* Stream count __u32 */

	__TQUIC_DIAG_ATTR_MAX,
};

#define TQUIC_DIAG_ATTR_MAX (__TQUIC_DIAG_ATTR_MAX - 1)

/*
 * Per-path nested attributes
 *
 * Each path within a TQUIC connection has its own statistics
 * and state information. These are nested under TQUIC_DIAG_ATTR_PATHS.
 */
enum {
	TQUIC_DIAG_PATH_UNSPEC,
	TQUIC_DIAG_PATH_ID,		/* __u32 path_id */
	TQUIC_DIAG_PATH_STATE,		/* __u8 enum tquic_path_state */
	TQUIC_DIAG_PATH_RTT,		/* __u32 smoothed RTT (us) */
	TQUIC_DIAG_PATH_CWND,		/* __u32 cwnd (bytes) */
	TQUIC_DIAG_PATH_TX_BYTES,	/* __u64 bytes transmitted */
	TQUIC_DIAG_PATH_RX_BYTES,	/* __u64 bytes received */
	TQUIC_DIAG_PATH_LOST,		/* __u64 lost packets */

	__TQUIC_DIAG_PATH_MAX,
};

#define TQUIC_DIAG_PATH_MAX (__TQUIC_DIAG_PATH_MAX - 1)

/*
 * struct tquic_info - Basic info structure for ss output
 *
 * This structure provides the primary connection information
 * displayed by the ss tool. It is returned via TQUIC_DIAG_ATTR_INFO.
 *
 * Note: struct tquic_info is defined in <uapi/linux/tquic.h>
 * This comment remains for documentation purposes.
 */

/*
 * Path state values for TQUIC_DIAG_PATH_STATE
 *
 * These mirror enum tquic_path_state from include/net/tquic.h
 */
enum tquic_diag_path_state {
	TQUIC_DIAG_PATH_UNUSED = 0,
	TQUIC_DIAG_PATH_PENDING,
	TQUIC_DIAG_PATH_ACTIVE,
	TQUIC_DIAG_PATH_STANDBY,
	TQUIC_DIAG_PATH_FAILED,
	TQUIC_DIAG_PATH_CLOSED,
};

/*
 * Connection state values
 *
 * These mirror enum tquic_conn_state from include/net/tquic.h
 * State names shown in ss output use hybrid format:
 *   QUIC state (TCP equivalent)
 * For example: "CONNECTED (ESTABLISHED)"
 */
enum tquic_diag_conn_state {
	TQUIC_DIAG_CONN_IDLE = 0,	/* IDLE (CLOSED) */
	TQUIC_DIAG_CONN_CONNECTING,	/* CONNECTING (SYN_SENT) */
	TQUIC_DIAG_CONN_CONNECTED,	/* CONNECTED (ESTABLISHED) */
	TQUIC_DIAG_CONN_CLOSING,	/* CLOSING (FIN_WAIT1) */
	TQUIC_DIAG_CONN_DRAINING,	/* DRAINING (TIME_WAIT) */
	TQUIC_DIAG_CONN_CLOSED,		/* CLOSED (CLOSED) */
};

#endif /* _UAPI_LINUX_TQUIC_DIAG_H */
