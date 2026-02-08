/* SPDX-License-Identifier: GPL-2.0 */
/*
 * TQUIC compatibility shim for <vdso/unaligned.h>
 *
 * On >= 6.12, the kernel provides this natively.
 * On <  6.12, it does not exist; <asm/unaligned.h> handles everything.
 */

#ifndef __VDSO_UNALIGNED_H
#define __VDSO_UNALIGNED_H

#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
#include_next <vdso/unaligned.h>
#else
/*
 * Pre-6.12: __get_unaligned_t / __put_unaligned_t are provided by
 * <asm/unaligned.h> via architecture-specific paths.  Nothing to add.
 */
#endif

#endif /* __VDSO_UNALIGNED_H */
