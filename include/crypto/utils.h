/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Cryptographic utilities - compat wrapper for out-of-tree builds
 *
 * On kernels >= 6.4, crypto_memneq/crypto_xor were moved from
 * crypto/algapi.h to crypto/utils.h.  This local header ensures
 * #include <crypto/utils.h> works on all kernel versions 5.4+.
 *
 * On < 6.4: crypto_memneq lives in crypto/algapi.h (included
 *   transitively by most crypto headers). Don't redefine it.
 * On >= 6.4: crypto_memneq was moved to crypto/utils.h but our
 *   local header shadows the kernel's. Provide the definition.
 */
#ifndef _TQUIC_CRYPTO_UTILS_COMPAT_H
#define _TQUIC_CRYPTO_UTILS_COMPAT_H

#include <linux/version.h>
#include <linux/types.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
/*
 * On >= 6.4, crypto/algapi.h no longer provides crypto_memneq.
 * The kernel's crypto/utils.h does, but our local copy shadows it.
 * Provide the declarations ourselves.
 */
noinline unsigned long __crypto_memneq(const void *a, const void *b,
				       size_t size);

static inline int crypto_memneq(const void *a, const void *b, size_t size)
{
	return __crypto_memneq(a, b, size) != 0UL ? 1 : 0;
}
#endif /* >= 6.4 */

/*
 * On < 6.4, crypto_memneq is provided by crypto/algapi.h which
 * is included transitively. Nothing needed here.
 */

#endif	/* _TQUIC_CRYPTO_UTILS_COMPAT_H */
