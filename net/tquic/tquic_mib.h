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
 * - 0-RTT counters: Track early data attempts, acceptance, rejection
 * - Per-EQUIC error counters: Track specific QUIC transport errors
 */

#ifndef _NET_TQUIC_MIB_H
#define _NET_TQUIC_MIB_H

#include <linux/snmp.h>
#include <net/snmp.h>
#include <uapi/linux/tquic.h>

/*
 * For out-of-tree module builds, we access MIB via our per-netns
 * structure instead of net->mib.tquic_statistics.
 *
 * Include protocol.h to get tquic_net and tquic_pernet() definitions.
 */
#include "protocol.h"

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

	/* Stateless reset counters (RFC 9000 Section 10.3) */
	TQUIC_MIB_STATELESSRESETSTX,     /* Stateless reset packets sent */
	TQUIC_MIB_STATELESSRESETSRX,     /* Stateless reset packets received */
	TQUIC_MIB_STATELESSRESETSERR,    /* Stateless reset errors */

	/* Path health (for WAN bonding) */
	TQUIC_MIB_PATHMIGRATIONS,        /* Path migrations */
	TQUIC_MIB_PATHFAILURES,          /* Path failures */
	TQUIC_MIB_PATHVALIDATED,         /* Paths successfully validated */
	TQUIC_MIB_RTTSAMPLES,            /* RTT measurements taken */
	TQUIC_MIB_LOSSEVENTS,            /* Loss detection events */
	TQUIC_MIB_PERSISTENTCONGESTION,  /* Persistent congestion events (RFC 9002) */

	/* Stream counters */
	TQUIC_MIB_STREAMSOPENED,         /* Streams opened */
	TQUIC_MIB_STREAMSCLOSED,         /* Streams closed */
	TQUIC_MIB_STREAMBLOCKED,         /* Stream limit blocked */

	/* DATAGRAM frame counters (RFC 9221) */
	TQUIC_MIB_DATAGRAMSRX,           /* DATAGRAM frames received */
	TQUIC_MIB_DATAGRAMSTX,           /* DATAGRAM frames transmitted */
	TQUIC_MIB_DATAGRAMSDROPPED,      /* DATAGRAM frames dropped (queue full) */

	/* Address validation token counters (RFC 9000 Section 8.1.3-8.1.4) */
	TQUIC_MIB_NEWTOKENSRX,           /* NEW_TOKEN frames received */
	TQUIC_MIB_NEWTOKENSTX,           /* NEW_TOKEN frames transmitted */
	TQUIC_MIB_TOKENSVALID,           /* Tokens validated successfully */
	TQUIC_MIB_TOKENSEXPIRED,         /* Tokens rejected (expired) */
	TQUIC_MIB_TOKENSINVALID,         /* Tokens rejected (invalid) */

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

	/* Retry packet counters (RFC 9000 Section 8.1) */
	TQUIC_MIB_RETRYPACKETSTX,        /* Retry packets sent (server) */
	TQUIC_MIB_RETRYPACKETSRX,        /* Retry packets received (client) */
	TQUIC_MIB_RETRYERRORS,           /* Retry integrity tag verification failures */

	/* 0-RTT Early Data counters (RFC 9001 Section 4.6-4.7) */
	TQUIC_MIB_0RTTATTEMPTED,         /* 0-RTT attempts by client */
	TQUIC_MIB_0RTTACCEPTED,          /* 0-RTT accepted by server */
	TQUIC_MIB_0RTTREJECTED,          /* 0-RTT rejected by server */
	TQUIC_MIB_0RTTBYTESTX,           /* Bytes sent in 0-RTT packets */
	TQUIC_MIB_0RTTBYTESRX,           /* Bytes received in 0-RTT packets */
	TQUIC_MIB_0RTTREPLAYS,           /* 0-RTT replay attempts detected */

	/* Rate limiting counters (DDoS protection) */
	TQUIC_MIB_RATELIMIT_CHECKED,         /* Connection attempts checked */
	TQUIC_MIB_RATELIMIT_ACCEPTED,        /* Connections accepted */
	TQUIC_MIB_RATELIMIT_DROPPED,         /* Connections rate limited */
	TQUIC_MIB_RATELIMIT_COOKIES,         /* Cookie validations required */
	TQUIC_MIB_RATELIMIT_BLACKLISTED,     /* Connections from blacklisted IPs */
	TQUIC_MIB_RATELIMIT_ATTACK_MODE,     /* Times attack mode was triggered */

	/* Security event counters */
	TQUIC_MIB_SEC_PRE_HS_LIMIT,          /* Pre-handshake memory limit exceeded */
	TQUIC_MIB_SEC_RETIRE_CID_FLOOD,      /* RETIRE_CONNECTION_ID stuffing detected */
	TQUIC_MIB_SEC_NEW_CID_RATE_LIMIT,    /* NEW_CONNECTION_ID rate limit exceeded */
	TQUIC_MIB_SEC_OPTIMISTIC_ACK,        /* Optimistic ACK attack detected */
	TQUIC_MIB_SEC_INVALID_ACK,           /* ACK for unsent packet detected */

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
 *
 * For out-of-tree builds, accesses MIB via tquic_pernet(net)->mib
 * instead of net->mib.tquic_statistics.
 */
#define TQUIC_INC_STATS(net, field)					\
	do {								\
		struct tquic_net *__tn = tquic_pernet(net);		\
		if (likely(__tn && __tn->mib))				\
			SNMP_INC_STATS(__tn->mib, field);		\
	} while (0)

/**
 * __TQUIC_INC_STATS - Increment without preemption disable (IRQ-safe context)
 * @net: Network namespace
 * @field: Counter to increment
 */
#define __TQUIC_INC_STATS(net, field)					\
	do {								\
		struct tquic_net *__tn = tquic_pernet(net);		\
		if (likely(__tn && __tn->mib))				\
			__SNMP_INC_STATS(__tn->mib, field);		\
	} while (0)

/**
 * TQUIC_DEC_STATS - Decrement a TQUIC MIB counter
 * @net: Network namespace
 * @field: Counter to decrement
 */
#define TQUIC_DEC_STATS(net, field)					\
	do {								\
		struct tquic_net *__tn = tquic_pernet(net);		\
		if (likely(__tn && __tn->mib))				\
			SNMP_DEC_STATS(__tn->mib, field);		\
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
		struct tquic_net *__tn = tquic_pernet(net);		\
		if (likely(__tn && __tn->mib))				\
			SNMP_ADD_STATS(__tn->mib, field, val);		\
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

/*
 * MIB function declarations
 */

/* Allocate MIB counters for network namespace */
bool tquic_mib_alloc(struct net *net);

/* Free MIB counters for network namespace */
void tquic_mib_free(struct net *net);

/* Output MIB counters to seq_file (explicit net for out-of-tree compatibility) */
void tquic_mib_seq_show_net(struct seq_file *seq, struct net *net);

/* Output MIB counters to seq_file (wrapper for in-tree compatibility) */
void tquic_mib_seq_show(struct seq_file *seq);

/* GRO statistics output */
void tquic_gro_stats_show(struct seq_file *seq);

#endif /* _NET_TQUIC_MIB_H */
