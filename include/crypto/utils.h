/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Cryptographic utilities
 *
 * Copyright (c) 2023 Herbert Xu <herbert@gondor.apana.org.au>
 *
 * Compat: On kernels < 6.4 where crypto/utils.h doesn't exist natively,
 * crypto_memneq/crypto_xor live in crypto/algapi.h. Redirect there.
 */
#ifndef _CRYPTO_UTILS_H
#define _CRYPTO_UTILS_H

#include <linux/version.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 4, 0)
/* crypto_memneq, crypto_xor, etc. are in crypto/algapi.h on older kernels */
#include_next <crypto/algapi.h>
#else
/* On 6.4+, the kernel has a native crypto/utils.h — use it */
#include_next <crypto/utils.h>
#endif

#endif	/* _CRYPTO_UTILS_H */
