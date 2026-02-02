/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: UDP to TCP Fallback Mechanism
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Public API for the automatic UDP-to-TCP fallback mechanism.
 */

#ifndef _TQUIC_TCP_FALLBACK_H
#define _TQUIC_TCP_FALLBACK_H

#include <linux/types.h>
#include <linux/ktime.h>

struct tquic_connection;
struct tquic_fallback_ctx;
struct quic_tcp_connection;

/*
 * =============================================================================
 * Fallback Reason Codes
 * =============================================================================
 */

/**
 * enum tquic_fallback_reason - Reasons for triggering TCP fallback
 * @FALLBACK_REASON_NONE: No fallback (normal UDP operation)
 * @FALLBACK_REASON_TIMEOUT: UDP connection attempt timed out
 * @FALLBACK_REASON_ICMP_UNREACH: ICMP port unreachable received
 * @FALLBACK_REASON_ICMP_PROHIBITED: ICMP admin prohibited received
 * @FALLBACK_REASON_LOSS: High packet loss rate detected
 * @FALLBACK_REASON_MANUAL: Manually triggered by application
 * @FALLBACK_REASON_MTU: MTU issues preventing UDP operation
 */
enum tquic_fallback_reason {
	FALLBACK_REASON_NONE = 0,
	FALLBACK_REASON_TIMEOUT,
	FALLBACK_REASON_ICMP_UNREACH,
	FALLBACK_REASON_ICMP_PROHIBITED,
	FALLBACK_REASON_LOSS,
	FALLBACK_REASON_MANUAL,
	FALLBACK_REASON_MTU,
};

/*
 * =============================================================================
 * Context Management
 * =============================================================================
 */

/**
 * tquic_fallback_ctx_create - Create fallback context for connection
 * @conn: QUIC connection
 *
 * Creates a new fallback context to track the fallback state for a
 * QUIC connection. Should be called when a connection is created.
 *
 * Returns: Fallback context or NULL on failure
 */
struct tquic_fallback_ctx *tquic_fallback_ctx_create(struct tquic_connection *conn);

/**
 * tquic_fallback_ctx_destroy - Destroy fallback context
 * @ctx: Fallback context
 *
 * Cleans up the fallback context, including any TCP connections
 * created during fallback. Should be called when the connection is closed.
 */
void tquic_fallback_ctx_destroy(struct tquic_fallback_ctx *ctx);

/*
 * =============================================================================
 * Fallback State
 * =============================================================================
 */

/**
 * tquic_fallback_is_active - Check if fallback to TCP is active
 * @ctx: Fallback context
 *
 * Returns: true if currently using TCP fallback transport
 */
bool tquic_fallback_is_active(struct tquic_fallback_ctx *ctx);

/**
 * tquic_fallback_get_tcp_conn - Get TCP connection if in fallback mode
 * @ctx: Fallback context
 *
 * Returns: TCP connection pointer or NULL if not in fallback mode
 */
struct quic_tcp_connection *tquic_fallback_get_tcp_conn(struct tquic_fallback_ctx *ctx);

/*
 * =============================================================================
 * Fallback Control
 * =============================================================================
 */

/**
 * tquic_fallback_trigger - Manually trigger fallback to TCP
 * @ctx: Fallback context
 * @reason: Reason for fallback
 *
 * Explicitly triggers fallback from UDP to TCP transport. This can be
 * called by the application or automatically by detection mechanisms.
 *
 * Returns: 0 on success, negative errno on failure
 *          -EALREADY if already in TCP fallback mode
 *          -ENOTSUP if fallback is disabled via sysctl
 */
int tquic_fallback_trigger(struct tquic_fallback_ctx *ctx,
			   enum tquic_fallback_reason reason);

/**
 * tquic_fallback_check - Check fallback conditions
 * @ctx: Fallback context
 *
 * Called periodically to check if fallback conditions are met
 * (timeout, high loss, etc.) and trigger fallback if needed.
 */
void tquic_fallback_check(struct tquic_fallback_ctx *ctx);

/*
 * =============================================================================
 * Event Handlers
 * =============================================================================
 */

/**
 * tquic_fallback_on_icmp - Handle ICMP error
 * @ctx: Fallback context
 * @type: ICMP type
 * @code: ICMP code
 *
 * Called when an ICMP error is received that may indicate UDP is blocked.
 *
 * Returns: true if fallback should be triggered
 */
bool tquic_fallback_on_icmp(struct tquic_fallback_ctx *ctx, int type, int code);

/**
 * tquic_fallback_update_loss - Update loss statistics
 * @ctx: Fallback context
 * @loss_pct: Current loss percentage (0-100)
 *
 * Called periodically with loss statistics. If loss exceeds the
 * configured threshold, fallback may be triggered.
 */
void tquic_fallback_update_loss(struct tquic_fallback_ctx *ctx, u8 loss_pct);

/*
 * =============================================================================
 * Data Transmission
 * =============================================================================
 */

/**
 * tquic_fallback_send - Send packet via appropriate transport
 * @ctx: Fallback context
 * @data: Packet data
 * @len: Packet length
 *
 * Sends a packet via TCP if in fallback mode, otherwise returns an
 * error indicating that the normal UDP path should be used.
 *
 * Returns: Bytes sent if using TCP fallback
 *          -ENOTSUP if using UDP (caller should use normal path)
 *          Negative errno on error
 */
int tquic_fallback_send(struct tquic_fallback_ctx *ctx,
			const void *data, size_t len);

/*
 * =============================================================================
 * Module Init/Exit
 * =============================================================================
 */

/**
 * tquic_fallback_init - Initialize fallback subsystem
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_fallback_init(void);

/**
 * tquic_fallback_exit - Cleanup fallback subsystem
 */
void tquic_fallback_exit(void);

#endif /* _TQUIC_TCP_FALLBACK_H */
