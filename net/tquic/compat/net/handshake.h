/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef _NET_HANDSHAKE_H
#define _NET_HANDSHAKE_H
/*
 * Compat shim: <net/handshake.h> (generic netlink TLS handshake service)
 * was introduced in kernel 6.7.
 *
 * This file is only reached when the kernel does not provide its own
 * <net/handshake.h>.  Provide minimal type stubs so TQUIC compiles.
 */
#include <linux/types.h>
#include <linux/key.h>
#include <linux/net.h>

enum {
	TLS_NO_KEYRING = 0,
	TLS_NO_PEERID = 0,
	TLS_NO_CERT = 0,
	TLS_NO_PRIVKEY = 0,
};

typedef void	(*tls_done_func_t)(void *data, int status,
				   key_serial_t peerid);

struct tls_handshake_args {
	struct socket		*ta_sock;
	tls_done_func_t		ta_done;
	void			*ta_data;
	const char		*ta_peername;
	unsigned int		ta_timeout_ms;
	key_serial_t		ta_keyring;
	key_serial_t		ta_my_cert;
	key_serial_t		ta_my_privkey;
	unsigned int		ta_num_peerids;
	key_serial_t		ta_my_peerids[5];
};

static inline int tls_client_hello_x509(struct tls_handshake_args *args,
					gfp_t flags)
{
	return -EAGAIN;
}

static inline int tls_client_hello_psk(struct tls_handshake_args *args,
				       gfp_t flags)
{
	return -EAGAIN;
}

static inline int tls_server_hello_x509(struct tls_handshake_args *args,
					gfp_t flags)
{
	return -EAGAIN;
}

static inline int tls_server_hello_psk(struct tls_handshake_args *args,
				       gfp_t flags)
{
	return -EAGAIN;
}

static inline bool tls_handshake_cancel(struct sock *sk)
{
	return false;
}

static inline void tls_handshake_close(struct socket *sock)
{
}

#endif /* _NET_HANDSHAKE_H */
