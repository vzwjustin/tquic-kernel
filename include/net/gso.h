/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * TQUIC compatibility shim for <net/gso.h>
 *
 * Kernel 6.2+ split GSO helpers out of <linux/skbuff.h> into <net/gso.h>.
 * On older kernels the symbols (struct skb_gso_cb, SKB_GSO_CB, etc.) still
 * live in <linux/skbuff.h>, so including a second copy causes redefinition
 * errors.
 *
 * Strategy:
 *   >= 6.2  - forward to the real kernel header via #include_next
 *   <  6.2  - everything is already in <linux/skbuff.h>; nothing to add
 */

#ifndef _NET_GSO_H
#define _NET_GSO_H

#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 2, 0)
/*
 * The kernel ships its own <net/gso.h>.  Because the project's include/
 * directory appears first on the -I search path, we must use #include_next
 * to reach the real kernel header.
 */
#include_next <net/gso.h>
#else
/*
 * Pre-6.2: struct skb_gso_cb, SKB_GSO_CB, skb_gso_segment, etc. are
 * provided by <linux/skbuff.h> which every networking file already
 * includes.  Nothing extra is needed here.
 */
#include <linux/skbuff.h>
#endif

#endif /* _NET_GSO_H */
