/* SPDX-License-Identifier: GPL-2.0 */
/*
 * TQUIC compatibility shim for <linux/unaligned/packed_struct.h>
 *
 * On >= 6.12, the kernel's own <linux/unaligned.h> pulls in its own copy.
 * On <  6.12, <asm/unaligned.h> provides everything needed.
 * This file exists only to prevent build errors if something still
 * references the path directly.
 */

#ifndef _LINUX_UNALIGNED_PACKED_STRUCT_H
#define _LINUX_UNALIGNED_PACKED_STRUCT_H

#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 12, 0)
#include_next <linux/unaligned/packed_struct.h>
#else
#include <asm/unaligned.h>
#endif

#endif /* _LINUX_UNALIGNED_PACKED_STRUCT_H */
