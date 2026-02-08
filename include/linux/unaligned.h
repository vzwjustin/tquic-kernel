/* SPDX-License-Identifier: GPL-2.0 */
/*
 * TQUIC compatibility shim for <linux/unaligned.h>
 *
 * Kernel 6.12+ moved unaligned access helpers from <asm/unaligned.h> to
 * <linux/unaligned.h>.  On older kernels, including a project-local copy
 * of the new header causes redefinition errors (get_unaligned_le16, etc.
 * are already defined via <asm/unaligned.h>).
 *
 * Strategy:
 *   >= 6.12 - forward to the real kernel header via #include_next
 *   <  6.12 - redirect to <asm/unaligned.h> which has all the helpers
 */

#ifndef __LINUX_UNALIGNED_H
#define __LINUX_UNALIGNED_H

#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
#include_next <linux/unaligned.h>
#else
#include <asm/unaligned.h>
#endif

#endif /* __LINUX_UNALIGNED_H */
