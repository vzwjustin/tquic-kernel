/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * TQUIC compatibility shim for <net/gro.h>
 *
 * Kernel 6.2+ split GRO helpers out of <linux/netdevice.h> into <net/gro.h>.
 * On older kernels the symbols (struct napi_gro_cb, NAPI_GRO_CB, etc.) still
 * live in <linux/netdevice.h>, so including a second copy causes redefinition
 * errors.
 *
 * Strategy:
 *   >= 6.2  - forward to the real kernel header via #include_next
 *   <  6.2  - everything is already in <linux/netdevice.h>; nothing to add
 */

#ifndef _NET_GRO_H
#define _NET_GRO_H

#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0)
/*
 * The kernel ships its own <net/gro.h>.  Because the project's include/
 * directory appears first on the -I search path, we must use #include_next
 * to reach the real kernel header.
 */
#include_next <net/gro.h>
#else
/*
 * Pre-6.2: struct napi_gro_cb, NAPI_GRO_CB, skb_gro_*, and friends are
 * provided by <linux/netdevice.h> which every networking file already
 * includes.  Nothing extra is needed here.
 */
#include <linux/netdevice.h>
#endif

#endif /* _NET_GRO_H */
