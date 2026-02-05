/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * TQUIC: Kernel API Compatibility Layer
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * Provides compatibility macros and wrappers for kernel APIs that changed
 * between kernel versions. Include this header in any TQUIC source file
 * that uses timer, socket, or other APIs that vary by kernel version.
 *
 * Kernel 6.12+ compatibility:
 * - Timer API: from_timer() -> timer_container_of()
 * - Timer API: del_timer() -> timer_delete()
 * - Timer API: del_timer_sync() -> timer_delete_sync()
 * - Timer API: hrtimer_init() -> hrtimer_setup()
 * - Socket API: struct sockaddr -> struct sockaddr_unsized in callbacks
 * - Flow routing: flowi4_tos -> flowi4_dscp
 */

#ifndef _TQUIC_COMPAT_H
#define _TQUIC_COMPAT_H

#include <linux/timer.h>
#include <linux/hrtimer.h>
#include <linux/version.h>

/*
 * Timer API compatibility for kernel 6.12+
 *
 * The timer callback mechanism changed:
 * - Old: void callback(unsigned long data)
 * - New: void callback(struct timer_list *t)
 *
 * The from_timer() macro was replaced with timer_container_of() in 6.12.
 */
#ifndef from_timer
#ifdef timer_container_of
#define from_timer(var, callback_timer, timer_fieldname) \
	timer_container_of(var, callback_timer, timer_fieldname)
#else
#define from_timer(var, callback_timer, timer_fieldname) \
	container_of(callback_timer, typeof(*var), timer_fieldname)
#endif
#endif

/*
 * del_timer() was renamed to timer_delete() in newer kernels
 */
#ifndef del_timer
#define del_timer(t) timer_delete(t)
#endif

/*
 * del_timer_sync() was renamed to timer_delete_sync() in newer kernels
 * (This is also handled via Makefile -D flag, but define here as backup)
 */
#ifndef del_timer_sync
#define del_timer_sync(t) timer_delete_sync(t)
#endif

/*
 * hrtimer_setup() is not available on older kernels.
 */
#ifndef hrtimer_setup
#define hrtimer_setup(timer, fn, clock_id, mode)                 \
	do {                                                     \
		hrtimer_init((timer), (clock_id), (mode));       \
		(timer)->function = (fn);                        \
	} while (0)
#endif

/*
 * flowi4_dscp replaced flowi4_tos on newer kernels.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 19, 0)
#define TQUIC_FLOWI4_SET_DSCP(fl4, dscp) ((fl4).flowi4_dscp = (dscp))
#else
#define TQUIC_FLOWI4_SET_DSCP(fl4, dscp) ((fl4).flowi4_tos = (dscp))
#endif

/*
 * Zerocopy helpers gained devmem/binding parameters in newer kernels.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 19, 0)
#define TQUIC_MSG_ZEROCOPY_REALLOC(sk, size, uarg) \
	msg_zerocopy_realloc(sk, size, uarg, false)
#define TQUIC_SKB_ZEROCOPY_ITER_STREAM(sk, skb, msg, len, uarg) \
	skb_zerocopy_iter_stream(sk, skb, msg, len, uarg, NULL)
#else
#define TQUIC_MSG_ZEROCOPY_REALLOC(sk, size, uarg) \
	msg_zerocopy_realloc(sk, size, uarg)
#define TQUIC_SKB_ZEROCOPY_ITER_STREAM(sk, skb, msg, len, uarg) \
	skb_zerocopy_iter_stream(sk, skb, msg, len, uarg)
#endif

/*
 * udp_tunnel_xmit_skb() gained an ipcb_flags parameter in newer kernels.
 * Keep a wrapper to handle both signatures.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 19, 0)
#define TQUIC_UDP_TUNNEL_XMIT_SKB(rt, sk, skb, saddr, daddr, tos, ttl, df, sport, dport, xnet, nocheck) \
	udp_tunnel_xmit_skb(rt, sk, skb, saddr, daddr, tos, ttl, df, sport, dport, xnet, nocheck, 0)
#define TQUIC_UDP_TUNNEL6_XMIT_SKB(dst, sk, skb, dev, saddr, daddr, prio, ttl, label, sport, dport, nocheck) \
	udp_tunnel6_xmit_skb(dst, sk, skb, dev, saddr, daddr, prio, ttl, label, sport, dport, nocheck, 0)
#else
#define TQUIC_UDP_TUNNEL_XMIT_SKB(rt, sk, skb, saddr, daddr, tos, ttl, df, sport, dport, xnet, nocheck) \
	udp_tunnel_xmit_skb(rt, sk, skb, saddr, daddr, tos, ttl, df, sport, dport, xnet, nocheck)
#define TQUIC_UDP_TUNNEL6_XMIT_SKB(dst, sk, skb, dev, saddr, daddr, prio, ttl, label, sport, dport, nocheck) \
	udp_tunnel6_xmit_skb(dst, sk, skb, dev, saddr, daddr, prio, ttl, label, sport, dport, nocheck)
#endif

#endif /* _TQUIC_COMPAT_H */
