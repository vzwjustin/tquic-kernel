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
 * Supported kernel range: 5.4+
 *
 * Kernel 5.4 - 5.5 compatibility:
 * - proc_ops: use struct file_operations instead of struct proc_ops
 *
 * Kernel 5.4 - 5.8 compatibility:
 * - sockptr_t: polyfill for kernels before 5.9
 * - SYSCTL_ZERO/ONE/TWO: define missing sysctl limit constants
 *
 * Kernel 5.4 - 5.16 compatibility:
 * - pde_data: renamed from PDE_DATA in 5.17
 *
 * Kernel 5.4 - 6.0 compatibility:
 * - netif_napi_add_weight: introduced in 6.1 (weight param removed
 *   from netif_napi_add)
 *
 * Kernel 5.4 - 6.1 compatibility:
 * - get_random_u32_below: introduced in 6.2, replaces prandom_u32_max
 *
 * Kernel 5.4 - 6.5 compatibility:
 * - register_net_sysctl_sz: fall back to register_net_sysctl
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
#include <linux/sysctl.h>
#include <linux/proc_fs.h>

/* ========================================================================
 * Kernel 5.4 - 5.5: proc_ops was introduced in 5.6
 * On older kernels, proc entries use struct file_operations directly.
 * ======================================================================== */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 6, 0)
#define proc_ops			file_operations
#define proc_open			open
#define proc_read			read
#define proc_write			write
#define proc_lseek			llseek
#define proc_release			release
#define proc_poll			poll
#define proc_ioctl			unlocked_ioctl
#define proc_mmap			mmap
#endif /* < 5.6 */

/* ========================================================================
 * Kernel 5.4 - 5.8: sockptr_t was introduced in 5.9
 * Provide a minimal polyfill so setsockopt/getsockopt handlers compile.
 * ======================================================================== */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
#include <linux/uaccess.h>

typedef struct {
	union {
		void		*kernel;
		void __user	*user;
	};
	bool	is_kernel;
} sockptr_t;

static inline sockptr_t USER_SOCKPTR(void __user *p)
{
	return (sockptr_t) { .user = p, .is_kernel = false };
}

static inline sockptr_t KERNEL_SOCKPTR(void *p)
{
	return (sockptr_t) { .kernel = p, .is_kernel = true };
}

static inline int copy_from_sockptr(void *dst, sockptr_t src, size_t size)
{
	if (src.is_kernel) {
		memcpy(dst, src.kernel, size);
		return 0;
	}
	return copy_from_user(dst, src.user, size);
}

static inline int copy_from_sockptr_offset(void *dst, sockptr_t src,
					   size_t offset, size_t size)
{
	if (src.is_kernel) {
		memcpy(dst, src.kernel + offset, size);
		return 0;
	}
	return copy_from_user(dst, src.user + offset, size);
}

static inline bool sockptr_is_null(sockptr_t sp)
{
	if (sp.is_kernel)
		return !sp.kernel;
	return !sp.user;
}
#endif /* < 5.9 */

/* ========================================================================
 * Kernel 5.4 - 5.7: SYSCTL_ZERO / SYSCTL_ONE / SYSCTL_TWO
 * These sysctl boundary constants were added in 5.8.
 * ======================================================================== */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
static const int tquic_sysctl_zero;
static const int tquic_sysctl_one = 1;
static const int tquic_sysctl_two = 2;

#ifndef SYSCTL_ZERO
#define SYSCTL_ZERO	((void *)&tquic_sysctl_zero)
#endif
#ifndef SYSCTL_ONE
#define SYSCTL_ONE	((void *)&tquic_sysctl_one)
#endif
#ifndef SYSCTL_TWO
#define SYSCTL_TWO	((void *)&tquic_sysctl_two)
#endif
#endif /* < 5.8 */

/* ========================================================================
 * Kernel 5.4 - 6.5: register_net_sysctl_sz()
 * This variant with an explicit table-size parameter was added in 6.6.
 * Fall back to register_net_sysctl() and ignore the size argument.
 * ======================================================================== */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 6, 0)
#define register_net_sysctl_sz(net, path, table, table_size) \
	register_net_sysctl(net, path, table)
#endif /* < 6.6 */

/* ========================================================================
 * Kernel 5.4 - 5.16: pde_data() was introduced in 5.17
 * Older kernels provide the PDE_DATA() macro instead.
 * ======================================================================== */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 17, 0)
#define pde_data(inode) PDE_DATA(inode)
#endif /* < 5.17 */

/* ========================================================================
 * Kernel 5.4 - 6.0: netif_napi_add_weight()
 * In 6.1, the weight parameter was removed from netif_napi_add() and a
 * separate netif_napi_add_weight() was introduced for callers that need
 * a non-default weight. On pre-6.1 kernels, map it to the 4-arg form.
 * ======================================================================== */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
#define netif_napi_add_weight(dev, napi, poll, weight) \
	netif_napi_add(dev, napi, poll, weight)
#endif /* < 6.1 */

/* ========================================================================
 * Kernel 5.4 - 6.1: get_random_u32_below()
 * Introduced in 6.2 as a cleaner replacement for prandom_u32_max().
 * On pre-6.2, fall back to prandom_u32_max() which is available 5.4+.
 * ======================================================================== */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 2, 0)
#define get_random_u32_below(ceil) prandom_u32_max(ceil)
#endif /* < 6.2 */

/*
 * Timer API compatibility
 *
 * In kernel 6.12, the timer API was renamed:
 *   del_timer()      -> timer_delete()
 *   del_timer_sync() -> timer_delete_sync()
 *   from_timer()     -> timer_container_of()
 *
 * Provide both directions:
 *   - On pre-6.12: map new names (timer_delete*) to old names (del_timer*)
 *   - On 6.12+:    map old names (del_timer*) to new names (timer_delete*)
 */

/* Pre-6.12: provide the new-style timer_delete* API via old del_timer* */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 12, 0)
#ifndef timer_delete
#define timer_delete(t) del_timer(t)
#endif
#ifndef timer_delete_sync
#define timer_delete_sync(t) del_timer_sync(t)
#endif
#endif /* < 6.12 */

/* 6.12+: provide old del_timer* names via new timer_delete* */
#ifndef del_timer
#define del_timer(t) timer_delete(t)
#endif
#ifndef del_timer_sync
#define del_timer_sync(t) timer_delete_sync(t)
#endif

/* from_timer() was replaced with timer_container_of() in 6.12 */
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
 * hrtimer_setup() replaced hrtimer_init() in 6.12.
 * On 6.12+, hrtimer_setup() is native and hrtimer_init() no longer exists.
 * Only define the compat macro on pre-6.12 kernels.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 12, 0)
#define hrtimer_setup(timer, fn, clock_id, mode)                 \
	do {                                                     \
		hrtimer_init((timer), (clock_id), (mode));       \
		(timer)->function = (fn);                        \
	} while (0)
#endif /* < 6.12 */

/*
 * sockaddr_unsized was introduced in 6.19 for kernel_bind/kernel_connect.
 * On older kernels, these functions take struct sockaddr *.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 19, 0)
#define sockaddr_unsized sockaddr
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
 * Zerocopy helpers gained devmem/binding parameters in 6.12+.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
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
 * udp_tunnel_xmit_skb() gained an ipcb_flags parameter in 6.12+.
 * Always pass 0 for ipcb_flags on kernels that have the 13-arg version.
 * For kernels older than 6.12, the 12-arg version is used.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
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
