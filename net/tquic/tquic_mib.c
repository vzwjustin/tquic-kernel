// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC MIB Statistics Implementation
 *
 * Copyright (c) 2026 Justin Adams <spotty118@gmail.com>
 * Kernel implementation by Justin Adams <spotty118@gmail.com>
 *
 * Implements per-CPU counter management and /proc/net/tquic_stat output.
 * Follows the MPTCP MIB pattern (net/mptcp/mib.c).
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/seq_file.h>
#include <linux/percpu.h>
#include <net/net_namespace.h>
#include <net/snmp.h>
#include <net/tquic.h>

#include "protocol.h"
#include "tquic_debug.h"
#include "tquic_mib.h"

/*
 * SNMP MIB name list for /proc/net/tquic_stat output
 *
 * These names appear in the TquicExt output format.
 * Order must match enum linux_tquic_mib_field in tquic_mib.h.
 */
static const struct snmp_mib tquic_snmp_list[] = {
	/* Handshake counters */
	SNMP_MIB_ITEM("HandshakesComplete", TQUIC_MIB_HANDSHAKESCOMPLETE),
	SNMP_MIB_ITEM("HandshakesFailed", TQUIC_MIB_HANDSHAKESFAILED),
	SNMP_MIB_ITEM("HandshakesTimeout", TQUIC_MIB_HANDSHAKESTIMEOUT),

	/* Packet counters */
	SNMP_MIB_ITEM("PacketsRx", TQUIC_MIB_PACKETSRX),
	SNMP_MIB_ITEM("PacketsTx", TQUIC_MIB_PACKETSTX),
	SNMP_MIB_ITEM("BytesRx", TQUIC_MIB_BYTESRX),
	SNMP_MIB_ITEM("BytesTx", TQUIC_MIB_BYTESTX),
	SNMP_MIB_ITEM("Retransmissions", TQUIC_MIB_RETRANSMISSIONS),

	/* Connection lifecycle */
	SNMP_MIB_ITEM("CurrEstab", TQUIC_MIB_CURRESTAB),
	SNMP_MIB_ITEM("ConnTimedOut", TQUIC_MIB_CONNTIMEDOUT),
	SNMP_MIB_ITEM("ConnClosed", TQUIC_MIB_CONNCLOSED),
	SNMP_MIB_ITEM("ConnReset", TQUIC_MIB_CONNRESET),

	/* Path health counters */
	SNMP_MIB_ITEM("PathMigrations", TQUIC_MIB_PATHMIGRATIONS),
	SNMP_MIB_ITEM("PathFailures", TQUIC_MIB_PATHFAILURES),
	SNMP_MIB_ITEM("PathValidated", TQUIC_MIB_PATHVALIDATED),
	SNMP_MIB_ITEM("RttSamples", TQUIC_MIB_RTTSAMPLES),
	SNMP_MIB_ITEM("LossEvents", TQUIC_MIB_LOSSEVENTS),
	SNMP_MIB_ITEM("PersistentCongestion", TQUIC_MIB_PERSISTENTCONGESTION),

	/* Stream counters */
	SNMP_MIB_ITEM("StreamsOpened", TQUIC_MIB_STREAMSOPENED),
	SNMP_MIB_ITEM("StreamsClosed", TQUIC_MIB_STREAMSCLOSED),
	SNMP_MIB_ITEM("StreamBlocked", TQUIC_MIB_STREAMBLOCKED),

	/* DATAGRAM frame counters (RFC 9221) */
	SNMP_MIB_ITEM("DatagramsRx", TQUIC_MIB_DATAGRAMSRX),
	SNMP_MIB_ITEM("DatagramsTx", TQUIC_MIB_DATAGRAMSTX),
	SNMP_MIB_ITEM("DatagramsDropped", TQUIC_MIB_DATAGRAMSDROPPED),

	/* Address validation token counters (RFC 9000 Section 8.1.3-8.1.4) */
	SNMP_MIB_ITEM("NewTokensRx", TQUIC_MIB_NEWTOKENSRX),
	SNMP_MIB_ITEM("NewTokensTx", TQUIC_MIB_NEWTOKENSTX),
	SNMP_MIB_ITEM("TokensValid", TQUIC_MIB_TOKENSVALID),
	SNMP_MIB_ITEM("TokensExpired", TQUIC_MIB_TOKENSEXPIRED),
	SNMP_MIB_ITEM("TokensInvalid", TQUIC_MIB_TOKENSINVALID),

	/* ECN counters */
	SNMP_MIB_ITEM("EcnAcksRx", TQUIC_MIB_ECNACKSRX),
	SNMP_MIB_ITEM("EcnAcksTx", TQUIC_MIB_ECNACKSTX),
	SNMP_MIB_ITEM("EcnCeMarksRx", TQUIC_MIB_ECNCEMARKSRX),
	SNMP_MIB_ITEM("EcnEct0Rx", TQUIC_MIB_ECNECT0RX),
	SNMP_MIB_ITEM("EcnEct1Rx", TQUIC_MIB_ECNECT1RX),

	/* GRO/GSO counters */
	SNMP_MIB_ITEM("GroPackets", TQUIC_MIB_GROPACKETS),
	SNMP_MIB_ITEM("GroCoalesced", TQUIC_MIB_GROCOALESCED),
	SNMP_MIB_ITEM("GroFlushes", TQUIC_MIB_GROFLUSHES),
	SNMP_MIB_ITEM("GsoPackets", TQUIC_MIB_GSOPACKETS),
	SNMP_MIB_ITEM("GsoSegments", TQUIC_MIB_GSOSEGMENTS),

	/* Per-EQUIC error counters */
	SNMP_MIB_ITEM("EquicNoError", TQUIC_MIB_EQUIC_NO_ERROR),
	SNMP_MIB_ITEM("EquicInternalError", TQUIC_MIB_EQUIC_INTERNAL_ERROR),
	SNMP_MIB_ITEM("EquicConnectionRefused", TQUIC_MIB_EQUIC_CONNECTION_REFUSED),
	SNMP_MIB_ITEM("EquicFlowControl", TQUIC_MIB_EQUIC_FLOW_CONTROL),
	SNMP_MIB_ITEM("EquicStreamLimit", TQUIC_MIB_EQUIC_STREAM_LIMIT),
	SNMP_MIB_ITEM("EquicStreamState", TQUIC_MIB_EQUIC_STREAM_STATE),
	SNMP_MIB_ITEM("EquicFinalSize", TQUIC_MIB_EQUIC_FINAL_SIZE),
	SNMP_MIB_ITEM("EquicFrameEncoding", TQUIC_MIB_EQUIC_FRAME_ENCODING),
	SNMP_MIB_ITEM("EquicTransportParam", TQUIC_MIB_EQUIC_TRANSPORT_PARAM),
	SNMP_MIB_ITEM("EquicConnectionIdLimit", TQUIC_MIB_EQUIC_CONNECTION_ID_LIMIT),
	SNMP_MIB_ITEM("EquicProtocolViolation", TQUIC_MIB_EQUIC_PROTOCOL_VIOLATION),
	SNMP_MIB_ITEM("EquicInvalidToken", TQUIC_MIB_EQUIC_INVALID_TOKEN),
	SNMP_MIB_ITEM("EquicApplicationError", TQUIC_MIB_EQUIC_APPLICATION_ERROR),
	SNMP_MIB_ITEM("EquicCryptoBuffer", TQUIC_MIB_EQUIC_CRYPTO_BUFFER),
	SNMP_MIB_ITEM("EquicKeyUpdate", TQUIC_MIB_EQUIC_KEY_UPDATE),
	SNMP_MIB_ITEM("EquicAeadLimit", TQUIC_MIB_EQUIC_AEAD_LIMIT),
	SNMP_MIB_ITEM("EquicNoViablePath", TQUIC_MIB_EQUIC_NO_VIABLE_PATH),
	/* Kernel 6.12+: No sentinel needed - use ARRAY_SIZE() for iteration */
};

/**
 * tquic_mib_alloc - Allocate per-CPU MIB counters for a network namespace
 * @net: Network namespace to allocate counters for
 *
 * Note: For out-of-tree builds, MIB is allocated in tquic_pernet via tquic_proto.c.
 * This function is kept for compatibility but allocation happens at pernet init.
 *
 * Returns: true on success (or already allocated), false on allocation failure
 */
bool tquic_mib_alloc(struct net *net)
{
	struct tquic_net *tn = tquic_pernet(net);

	/* MIB already allocated in pernet init */
	return tn && tn->mib != NULL;
}

/**
 * tquic_mib_free - Free per-CPU MIB counters for a network namespace
 * @net: Network namespace to free counters for
 *
 * Note: For out-of-tree builds, MIB is freed in tquic_pernet via tquic_proto.c.
 * This function is kept for compatibility.
 */
void tquic_mib_free(struct net *net)
{
	/* MIB freed in pernet exit */
}

/**
 * tquic_mib_seq_show_net - Output MIB counters in TquicExt format
 * @seq: Sequence file to write to
 * @net: Network namespace (explicit parameter for out-of-tree compatibility)
 *
 * Outputs counters in the same format as /proc/net/netstat TcpExt.
 * First line contains counter names, second line contains values.
 *
 * Example output:
 *   TquicExt: HandshakesComplete HandshakesFailed ...
 *   TquicExt: 1234 56 ...
 */
void tquic_mib_seq_show_net(struct seq_file *seq, struct net *net)
{
	unsigned long sum[ARRAY_SIZE(tquic_snmp_list)];
	const int cnt = ARRAY_SIZE(tquic_snmp_list);
	struct tquic_net *tn;
	int i, cpu;

	if (!net)
		return;

	tn = tquic_pernet(net);

	/* Output header line with counter names */
	seq_puts(seq, "\nTquicExt:");
	for (i = 0; i < cnt; i++)
		seq_printf(seq, " %s", tquic_snmp_list[i].name);

	/* Output value line */
	seq_puts(seq, "\nTquicExt:");

	/* Aggregate per-CPU counters */
	memset(sum, 0, sizeof(sum));
	if (tn && tn->mib) {
		for_each_possible_cpu(cpu) {
			struct tquic_mib *mib = per_cpu_ptr(tn->mib, cpu);
			for (i = 0; i < cnt; i++)
				sum[i] += mib->mibs[tquic_snmp_list[i].entry];
		}
	}

	for (i = 0; i < cnt; i++)
		seq_printf(seq, " %lu", sum[i]);

	seq_putc(seq, '\n');
}
EXPORT_SYMBOL_GPL(tquic_mib_seq_show_net);

/**
 * tquic_mib_seq_show - Output MIB counters (wrapper for in-tree compatibility)
 * @seq: Sequence file to write to
 *
 * This wrapper exists for in-tree build compatibility where seq_file_net
 * can be used directly.
 */
void tquic_mib_seq_show(struct seq_file *seq)
{
	/* For out-of-tree, caller should use tquic_mib_seq_show_net directly */
	tquic_mib_seq_show_net(seq, NULL);
}
EXPORT_SYMBOL_GPL(tquic_mib_seq_show);

/**
 * tquic_mib_init - Initialize MIB subsystem for a network namespace
 * @net: Network namespace
 *
 * Called from pernet_operations init. Currently a no-op as
 * counters are allocated lazily on first socket creation.
 *
 * Returns: 0 on success
 */
int tquic_mib_init(struct net *net)
{
	/* Counters are allocated lazily via tquic_mib_alloc() */
	return 0;
}

/**
 * tquic_mib_exit - Cleanup MIB subsystem for a network namespace
 * @net: Network namespace
 *
 * Called from pernet_operations exit to free any allocated counters.
 */
void tquic_mib_exit(struct net *net)
{
	tquic_mib_free(net);
}

MODULE_DESCRIPTION("TQUIC MIB Statistics");
MODULE_LICENSE("GPL");
