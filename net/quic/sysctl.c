// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * QUIC sysctl interface
 *
 * Runtime configuration via /proc/sys/net/quic/
 *
 * Copyright (c) 2024 Linux QUIC Authors
 */

#include <linux/module.h>
#include <linux/sysctl.h>
#include <linux/init.h>
#include <net/quic.h>

/*
 * QUIC sysctl variables
 *
 * These provide runtime-tunable parameters for the QUIC implementation.
 * Values can be modified via /proc/sys/net/quic/ or sysctl(8).
 */

/* Maximum number of concurrent connections (global limit) */
static int sysctl_quic_max_connections __read_mostly = 65536;
static int sysctl_quic_max_connections_min = 1;
static int sysctl_quic_max_connections_max = 1048576;

/* Default idle timeout in milliseconds */
static unsigned int sysctl_quic_default_timeout_ms __read_mostly = 30000;
static int sysctl_quic_timeout_min = 1000;		/* 1 second minimum */
static int sysctl_quic_timeout_max = 600000;		/* 10 minutes maximum */

/* Maximum streams per connection */
static int sysctl_quic_max_streams __read_mostly = 100;
static int sysctl_quic_max_streams_min = 1;
static int sysctl_quic_max_streams_max = 65536;

/*
 * Default congestion control algorithm
 * 0 = Reno, 1 = CUBIC, 2 = BBR, 3 = BBR2
 */
static int sysctl_quic_congestion_control __read_mostly;
static int sysctl_quic_cc_min;
static int sysctl_quic_cc_max = 3;	/* QUIC_CC_BBR2 */

/* Initial RTT estimate in milliseconds */
static unsigned int sysctl_quic_initial_rtt_ms __read_mostly = 333;
static int sysctl_quic_rtt_min = 1;
static int sysctl_quic_rtt_max = 10000;

/* Maximum datagram frame size (0 = disabled) */
static unsigned int sysctl_quic_max_datagram_size __read_mostly;
static int sysctl_quic_datagram_min;
static int sysctl_quic_datagram_max = 65535;

/* ACK delay exponent (RFC 9000 default: 3) */
static int sysctl_quic_ack_delay_exponent __read_mostly = 3;
static int sysctl_quic_ack_delay_exp_min;
static int sysctl_quic_ack_delay_exp_max = 20;

/* Maximum ACK delay in milliseconds (RFC 9000 default: 25) */
static unsigned int sysctl_quic_max_ack_delay_ms __read_mostly = 25;
static int sysctl_quic_max_ack_delay_min = 1;
static int sysctl_quic_max_ack_delay_max = 16384;

/* Enable active migration (RFC 9000 Section 9) */
static int sysctl_quic_migration_enabled __read_mostly = 1;

/* Maximum connection ID length (RFC 9000: 1-20) */
static int sysctl_quic_max_cid_len __read_mostly = 20;
static int sysctl_quic_cid_len_min = 1;
static int sysctl_quic_cid_len_max = 20;

/* Number of connection IDs to maintain (RFC 9000 active_connection_id_limit) */
static int sysctl_quic_active_cid_limit __read_mostly = 2;
static int sysctl_quic_cid_limit_min = 2;
static int sysctl_quic_cid_limit_max = 8;

/* Maximum UDP payload size (RFC 9000 max_udp_payload_size) */
static unsigned int sysctl_quic_max_udp_payload __read_mostly = 1200;
static int sysctl_quic_udp_payload_min = 1200;	/* RFC minimum */
static int sysctl_quic_udp_payload_max = 65527;	/* Max UDP payload */

/* Enable QUIC spin bit for RTT measurement (RFC 9000 Section 17.4) */
static int sysctl_quic_spin_bit_enabled __read_mostly = 1;

/* Enable packet pacing */
static int sysctl_quic_pacing_enabled __read_mostly = 1;

/* Handshake timeout in milliseconds */
static unsigned int sysctl_quic_handshake_timeout_ms __read_mostly = 10000;
static int sysctl_quic_hs_timeout_min = 1000;
static int sysctl_quic_hs_timeout_max = 120000;

/* Memory limits (uses existing sysctl_quic_mem from protocol.c) */
extern int sysctl_quic_mem[3];
extern int sysctl_quic_wmem[3];
extern int sysctl_quic_rmem[3];

static struct ctl_table_header *quic_sysctl_header;

/*
 * QUIC sysctl table
 *
 * All parameters are exposed under /proc/sys/net/quic/
 */
static struct ctl_table quic_sysctl_table[] = {
	{
		.procname	= "max_connections",
		.data		= &sysctl_quic_max_connections,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &sysctl_quic_max_connections_min,
		.extra2		= &sysctl_quic_max_connections_max,
	},
	{
		.procname	= "default_timeout_ms",
		.data		= &sysctl_quic_default_timeout_ms,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &sysctl_quic_timeout_min,
		.extra2		= &sysctl_quic_timeout_max,
	},
	{
		.procname	= "max_streams_per_conn",
		.data		= &sysctl_quic_max_streams,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &sysctl_quic_max_streams_min,
		.extra2		= &sysctl_quic_max_streams_max,
	},
	{
		.procname	= "congestion_control",
		.data		= &sysctl_quic_congestion_control,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &sysctl_quic_cc_min,
		.extra2		= &sysctl_quic_cc_max,
	},
	{
		.procname	= "initial_rtt_ms",
		.data		= &sysctl_quic_initial_rtt_ms,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &sysctl_quic_rtt_min,
		.extra2		= &sysctl_quic_rtt_max,
	},
	{
		.procname	= "max_datagram_size",
		.data		= &sysctl_quic_max_datagram_size,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &sysctl_quic_datagram_min,
		.extra2		= &sysctl_quic_datagram_max,
	},
	{
		.procname	= "ack_delay_exponent",
		.data		= &sysctl_quic_ack_delay_exponent,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &sysctl_quic_ack_delay_exp_min,
		.extra2		= &sysctl_quic_ack_delay_exp_max,
	},
	{
		.procname	= "max_ack_delay_ms",
		.data		= &sysctl_quic_max_ack_delay_ms,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &sysctl_quic_max_ack_delay_min,
		.extra2		= &sysctl_quic_max_ack_delay_max,
	},
	{
		.procname	= "migration_enabled",
		.data		= &sysctl_quic_migration_enabled,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
	{
		.procname	= "max_cid_length",
		.data		= &sysctl_quic_max_cid_len,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &sysctl_quic_cid_len_min,
		.extra2		= &sysctl_quic_cid_len_max,
	},
	{
		.procname	= "active_cid_limit",
		.data		= &sysctl_quic_active_cid_limit,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &sysctl_quic_cid_limit_min,
		.extra2		= &sysctl_quic_cid_limit_max,
	},
	{
		.procname	= "max_udp_payload",
		.data		= &sysctl_quic_max_udp_payload,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &sysctl_quic_udp_payload_min,
		.extra2		= &sysctl_quic_udp_payload_max,
	},
	{
		.procname	= "spin_bit_enabled",
		.data		= &sysctl_quic_spin_bit_enabled,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
	{
		.procname	= "pacing_enabled",
		.data		= &sysctl_quic_pacing_enabled,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= SYSCTL_ZERO,
		.extra2		= SYSCTL_ONE,
	},
	{
		.procname	= "handshake_timeout_ms",
		.data		= &sysctl_quic_handshake_timeout_ms,
		.maxlen		= sizeof(unsigned int),
		.mode		= 0644,
		.proc_handler	= proc_dointvec_minmax,
		.extra1		= &sysctl_quic_hs_timeout_min,
		.extra2		= &sysctl_quic_hs_timeout_max,
	},
	{
		.procname	= "mem",
		.data		= &sysctl_quic_mem,
		.maxlen		= sizeof(sysctl_quic_mem),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "wmem",
		.data		= &sysctl_quic_wmem,
		.maxlen		= sizeof(sysctl_quic_wmem),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
	{
		.procname	= "rmem",
		.data		= &sysctl_quic_rmem,
		.maxlen		= sizeof(sysctl_quic_rmem),
		.mode		= 0644,
		.proc_handler	= proc_dointvec,
	},
};

/*
 * Accessor functions for sysctl values
 *
 * These functions provide safe access to sysctl values from other
 * parts of the QUIC implementation.
 */
int quic_sysctl_max_connections(void)
{
	return READ_ONCE(sysctl_quic_max_connections);
}
EXPORT_SYMBOL_GPL(quic_sysctl_max_connections);

unsigned int quic_sysctl_default_timeout_ms(void)
{
	return READ_ONCE(sysctl_quic_default_timeout_ms);
}
EXPORT_SYMBOL_GPL(quic_sysctl_default_timeout_ms);

int quic_sysctl_max_streams(void)
{
	return READ_ONCE(sysctl_quic_max_streams);
}
EXPORT_SYMBOL_GPL(quic_sysctl_max_streams);

int quic_sysctl_congestion_control(void)
{
	return READ_ONCE(sysctl_quic_congestion_control);
}
EXPORT_SYMBOL_GPL(quic_sysctl_congestion_control);

unsigned int quic_sysctl_initial_rtt_ms(void)
{
	return READ_ONCE(sysctl_quic_initial_rtt_ms);
}
EXPORT_SYMBOL_GPL(quic_sysctl_initial_rtt_ms);

unsigned int quic_sysctl_max_datagram_size(void)
{
	return READ_ONCE(sysctl_quic_max_datagram_size);
}
EXPORT_SYMBOL_GPL(quic_sysctl_max_datagram_size);

int quic_sysctl_ack_delay_exponent(void)
{
	return READ_ONCE(sysctl_quic_ack_delay_exponent);
}
EXPORT_SYMBOL_GPL(quic_sysctl_ack_delay_exponent);

unsigned int quic_sysctl_max_ack_delay_ms(void)
{
	return READ_ONCE(sysctl_quic_max_ack_delay_ms);
}
EXPORT_SYMBOL_GPL(quic_sysctl_max_ack_delay_ms);

bool quic_sysctl_migration_enabled(void)
{
	return READ_ONCE(sysctl_quic_migration_enabled);
}
EXPORT_SYMBOL_GPL(quic_sysctl_migration_enabled);

int quic_sysctl_max_cid_length(void)
{
	return READ_ONCE(sysctl_quic_max_cid_len);
}
EXPORT_SYMBOL_GPL(quic_sysctl_max_cid_length);

int quic_sysctl_active_cid_limit(void)
{
	return READ_ONCE(sysctl_quic_active_cid_limit);
}
EXPORT_SYMBOL_GPL(quic_sysctl_active_cid_limit);

unsigned int quic_sysctl_max_udp_payload(void)
{
	return READ_ONCE(sysctl_quic_max_udp_payload);
}
EXPORT_SYMBOL_GPL(quic_sysctl_max_udp_payload);

bool quic_sysctl_spin_bit_enabled(void)
{
	return READ_ONCE(sysctl_quic_spin_bit_enabled);
}
EXPORT_SYMBOL_GPL(quic_sysctl_spin_bit_enabled);

bool quic_sysctl_pacing_enabled(void)
{
	return READ_ONCE(sysctl_quic_pacing_enabled);
}
EXPORT_SYMBOL_GPL(quic_sysctl_pacing_enabled);

unsigned int quic_sysctl_handshake_timeout_ms(void)
{
	return READ_ONCE(sysctl_quic_handshake_timeout_ms);
}
EXPORT_SYMBOL_GPL(quic_sysctl_handshake_timeout_ms);

/**
 * quic_sysctl_register - Register QUIC sysctl entries
 *
 * Creates /proc/sys/net/quic/ directory with all QUIC parameters.
 * Must be called during module initialization.
 *
 * Returns 0 on success, negative error code on failure.
 */
int __init quic_sysctl_register(void)
{
	quic_sysctl_header = register_net_sysctl(&init_net, "net/quic",
						 quic_sysctl_table);
	if (!quic_sysctl_header) {
		pr_err("QUIC: failed to register sysctl table\n");
		return -ENOMEM;
	}

	pr_info("QUIC: sysctl interface registered at /proc/sys/net/quic\n");
	return 0;
}

/**
 * quic_sysctl_unregister - Unregister QUIC sysctl entries
 *
 * Removes /proc/sys/net/quic/ directory and all entries.
 * Must be called during module cleanup.
 */
void quic_sysctl_unregister(void)
{
	if (quic_sysctl_header) {
		unregister_net_sysctl_table(quic_sysctl_header);
		quic_sysctl_header = NULL;
	}
}
