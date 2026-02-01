/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC MIB Statistics Counters
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * This header defines MIB (Management Information Base) counters
 * for TQUIC protocol statistics. Follows the MPTCP MIB pattern
 * (net/mptcp/mib.h) for consistency.
 *
 * Counter categories:
 * - Handshake counters: Track TLS handshake success/failure
 * - Packet counters: Track packets and bytes TX/RX
 * - Connection lifecycle: Track active connections
 * - Path health: Track RTT, loss, migrations (for WAN bonding)
 * - Stream counters: Track stream opens/closes
 * - Per-EQUIC error counters: Track specific QUIC transport errors
 */

#ifndef _NET_TQUIC_MIB_H
#define _NET_TQUIC_MIB_H

#include <linux/snmp.h>
#include <net/snmp.h>
#include <uapi/linux/tquic.h>

/**
 * enum linux_tquic_mib_field - TQUIC MIB counter indices
 *
 * These values index into the per-CPU MIB counter array.
 * Order must match tquic_snmp_list[] in tquic_mib.c.
 */
enum linux_tquic_mib_field {
	TQUIC_MIB_NUM = 0,

	/* Handshake counters */
	TQUIC_MIB_HANDSHAKESCOMPLETE,    /* Successful handshakes */
	TQUIC_MIB_HANDSHAKESFAILED,      /* Failed handshakes */
	TQUIC_MIB_HANDSHAKESTIMEOUT,     /* Handshake timeouts */

	/* Packet counters */
	TQUIC_MIB_PACKETSRX,             /* Packets received */
	TQUIC_MIB_PACKETSTX,             /* Packets transmitted */
	TQUIC_MIB_BYTESRX,               /* Bytes received */
	TQUIC_MIB_BYTESTX,               /* Bytes transmitted */
	TQUIC_MIB_RETRANSMISSIONS,       /* Retransmitted packets */

	/* Connection lifecycle */
	TQUIC_MIB_CURRESTAB,             /* Currently established connections */
	TQUIC_MIB_CONNTIMEDOUT,          /* Connection timeouts */
	TQUIC_MIB_CONNCLOSED,            /* Connections closed gracefully */
	TQUIC_MIB_CONNRESET,             /* Connection resets */

	/* Path health (for WAN bonding) */
	TQUIC_MIB_PATHMIGRATIONS,        /* Path migrations */
	TQUIC_MIB_PATHFAILURES,          /* Path failures */
	TQUIC_MIB_PATHVALIDATED,         /* Paths successfully validated */
	TQUIC_MIB_RTTSAMPLES,            /* RTT measurements taken */
	TQUIC_MIB_LOSSEVENTS,            /* Loss detection events */

	/* Stream counters */
	TQUIC_MIB_STREAMSOPENED,         /* Streams opened */
	TQUIC_MIB_STREAMSCLOSED,         /* Streams closed */
	TQUIC_MIB_STREAMBLOCKED,         /* Stream limit blocked */

	/* DATAGRAM frame counters (RFC 9221) */
	TQUIC_MIB_DATAGRAMSRX,           /* DATAGRAM frames received */
	TQUIC_MIB_DATAGRAMSTX,           /* DATAGRAM frames transmitted */
	TQUIC_MIB_DATAGRAMSDROPPED,      /* DATAGRAM frames dropped (queue full) */

	/* ECN counters - per CONTEXT.md: "ECN support: available but off by default" */
	TQUIC_MIB_ECNACKSRX,             /* ACK_ECN frames received */
	TQUIC_MIB_ECNACKSTX,             /* ACK_ECN frames transmitted */
	TQUIC_MIB_ECNCEMARKSRX,          /* ECN CE marks received (congestion signals) */
	TQUIC_MIB_ECNECT0RX,             /* ECT(0) marks received */
	TQUIC_MIB_ECNECT1RX,             /* ECT(1) marks received */

	/* GRO (Generic Receive Offload) counters */
	TQUIC_MIB_GROPACKETS,            /* Packets processed by GRO */
	TQUIC_MIB_GROCOALESCED,          /* Packets coalesced via GRO */
	TQUIC_MIB_GROFLUSHES,            /* GRO flush events */
	TQUIC_MIB_GSOPACKETS,            /* Packets processed by GSO */
	TQUIC_MIB_GSOSEGMENTS,           /* Segments created by GSO */

	/*
	 * Per-EQUIC error counters (EQUIC_BASE=500)
	 * Maps to RFC 9000 QUIC Transport Error Codes
	 */
	TQUIC_MIB_EQUIC_NO_ERROR,           /* 0x00 NO_ERROR */
	TQUIC_MIB_EQUIC_INTERNAL_ERROR,     /* 0x01 INTERNAL_ERROR */
	TQUIC_MIB_EQUIC_CONNECTION_REFUSED, /* 0x02 CONNECTION_REFUSED */
	TQUIC_MIB_EQUIC_FLOW_CONTROL,       /* 0x03 FLOW_CONTROL_ERROR */
	TQUIC_MIB_EQUIC_STREAM_LIMIT,       /* 0x04 STREAM_LIMIT_ERROR */
	TQUIC_MIB_EQUIC_STREAM_STATE,       /* 0x05 STREAM_STATE_ERROR */
	TQUIC_MIB_EQUIC_FINAL_SIZE,         /* 0x06 FINAL_SIZE_ERROR */
	TQUIC_MIB_EQUIC_FRAME_ENCODING,     /* 0x07 FRAME_ENCODING_ERROR */
	TQUIC_MIB_EQUIC_TRANSPORT_PARAM,    /* 0x08 TRANSPORT_PARAMETER_ERROR */
	TQUIC_MIB_EQUIC_CONNECTION_ID_LIMIT,/* 0x09 CONNECTION_ID_LIMIT_ERROR */
	TQUIC_MIB_EQUIC_PROTOCOL_VIOLATION, /* 0x0a PROTOCOL_VIOLATION */
	TQUIC_MIB_EQUIC_INVALID_TOKEN,      /* 0x0b INVALID_TOKEN */
	TQUIC_MIB_EQUIC_APPLICATION_ERROR,  /* 0x0c APPLICATION_ERROR */
	TQUIC_MIB_EQUIC_CRYPTO_BUFFER,      /* 0x0d CRYPTO_BUFFER_EXCEEDED */
	TQUIC_MIB_EQUIC_KEY_UPDATE,         /* 0x0e KEY_UPDATE_ERROR */
	TQUIC_MIB_EQUIC_AEAD_LIMIT,         /* 0x0f AEAD_LIMIT_REACHED */
	TQUIC_MIB_EQUIC_NO_VIABLE_PATH,     /* 0x10 NO_VIABLE_PATH */

	__TQUIC_MIB_MAX
};

#define LINUX_MIB_TQUIC_MAX	__TQUIC_MIB_MAX

/**
 * struct tquic_mib - Per-CPU TQUIC statistics counters
 * @mibs: Array of counter values indexed by linux_tquic_mib_field
 */
struct tquic_mib {
	unsigned long mibs[LINUX_MIB_TQUIC_MAX];
};

/*
 * Counter manipulation macros
 *
 * These follow the SNMP_*_STATS pattern used throughout the kernel.
 * The net->mib.tquic_statistics pointer must be initialized before use.
 */

/**
 * TQUIC_INC_STATS - Increment a TQUIC MIB counter
 * @net: Network namespace
 * @field: Counter to increment (TQUIC_MIB_* enum value)
 */
#define TQUIC_INC_STATS(net, field)					\
	do {								\
		if (likely((net)->mib.tquic_statistics))		\
			SNMP_INC_STATS((net)->mib.tquic_statistics, field); \
	} while (0)

/**
 * __TQUIC_INC_STATS - Increment without preemption disable (IRQ-safe context)
 * @net: Network namespace
 * @field: Counter to increment
 */
#define __TQUIC_INC_STATS(net, field)					\
	do {								\
		if (likely((net)->mib.tquic_statistics))		\
			__SNMP_INC_STATS((net)->mib.tquic_statistics, field); \
	} while (0)

/**
 * TQUIC_DEC_STATS - Decrement a TQUIC MIB counter
 * @net: Network namespace
 * @field: Counter to decrement
 */
#define TQUIC_DEC_STATS(net, field)					\
	do {								\
		if (likely((net)->mib.tquic_statistics))		\
			SNMP_DEC_STATS((net)->mib.tquic_statistics, field); \
	} while (0)

/**
 * TQUIC_ADD_STATS - Add value to a TQUIC MIB counter
 * @net: Network namespace
 * @field: Counter to add to
 * @val: Value to add
 *
 * Use for byte counters where multiple bytes are counted at once.
 */
#define TQUIC_ADD_STATS(net, field, val)				\
	do {								\
		if (likely((net)->mib.tquic_statistics))		\
			SNMP_ADD_STATS((net)->mib.tquic_statistics, field, val); \
	} while (0)

/**
 * tquic_equic_to_mib - Map EQUIC error code to MIB counter field
 * @error_code: EQUIC error code (EQUIC_* from uapi/linux/tquic.h)
 *
 * Returns: Corresponding MIB field, or TQUIC_MIB_NUM if invalid/unknown
 *
 * Example:
 *   enum linux_tquic_mib_field mib_field = tquic_equic_to_mib(EQUIC_FLOW_CONTROL);
 *   if (mib_field != TQUIC_MIB_NUM)
 *       TQUIC_INC_STATS(net, mib_field);
 */
static inline enum linux_tquic_mib_field tquic_equic_to_mib(u32 error_code)
{
	u32 offset;

	/* Check if in valid EQUIC range (0x00 to 0x10) */
	if (error_code < EQUIC_BASE)
		return TQUIC_MIB_NUM;

	offset = error_code - EQUIC_BASE;

	/* EQUIC errors 0x00-0x10 map to MIB counters */
	if (offset <= 0x10)
		return TQUIC_MIB_EQUIC_NO_ERROR + offset;

	return TQUIC_MIB_NUM;  /* Invalid/unknown error code */
}

#endif /* _NET_TQUIC_MIB_H */
