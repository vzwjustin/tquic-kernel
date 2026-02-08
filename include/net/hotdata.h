/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * TQUIC compatibility shim for <net/hotdata.h>
 *
 * Kernel 6.9+ introduced <net/hotdata.h> (struct net_hotdata for fast-path
 * networking data).  On older kernels this header does not exist and the
 * fields live elsewhere (e.g. gro_normal_batch in netdevice globals).
 *
 * Strategy:
 *   >= 6.9  - forward to the real kernel header via #include_next
 *   <  6.9  - provide a minimal stub so that gro.h compiles
 */

#ifndef _NET_HOTDATA_H
#define _NET_HOTDATA_H

#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 9, 0)
#include_next <net/hotdata.h>
#else
/*
 * Pre-6.9: net_hotdata does not exist.  The gro.h shim redirects to
 * <linux/netdevice.h> on pre-6.2 anyway, so this header is only reached
 * if something explicitly includes it on 6.2-6.8, which the tquic code
 * does not do.  Provide an empty placeholder.
 */
#endif

#endif /* _NET_HOTDATA_H */
