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
 * Kernel 5.4 - 6.7 compatibility:
 * - alloc_netdev_dummy: introduced in 6.8, polyfill via alloc_netdev
 *
 * Kernel 6.12+ compatibility:
 * - Timer API: from_timer() -> timer_container_of()
 * - Timer API: del_timer() -> timer_delete()
 * - Timer API: del_timer_sync() -> timer_delete_sync()
 *
 * Kernel 6.13+ compatibility:
 * - udp_tunnel_xmit_skb/udp_tunnel6_xmit_skb gained ipcb_flags param
 *
 * Kernel 6.15+ compatibility:
 * - Timer API: hrtimer_init() -> hrtimer_setup()
 *
 * Kernel 6.19+ compatibility:
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

/*
 * tquic_kernel_setsockopt - set socket option from kernel space.
 * On < 5.9, sock->ops->setsockopt() takes char __user *, not sockptr_t.
 * Use kernel_setsockopt() which existed on these older kernels.
 * On >= 5.9, kernel_setsockopt() was removed; use sockptr_t interface.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
static inline int tquic_kernel_setsockopt(struct socket *sock, int level,
					  int optname, void *optval,
					  unsigned int optlen)
{
	return kernel_setsockopt(sock, level, optname,
				 (char __user *)optval, optlen);
}
#else
static inline int tquic_kernel_setsockopt(struct socket *sock, int level,
					  int optname, void *optval,
					  unsigned int optlen)
{
	return sock->ops->setsockopt(sock, level, optname,
				     KERNEL_SOCKPTR(optval), optlen);
}
#endif

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
 * hrtimer_setup() replaced hrtimer_init() in 6.15.
 * On 6.15+, hrtimer_setup() is native and hrtimer_init() no longer exists.
 * Only define the compat macro on pre-6.15 kernels.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 15, 0)
#define hrtimer_setup(timer, fn, clock_id, mode)                 \
	do {                                                     \
		hrtimer_init((timer), (clock_id), (mode));       \
		(timer)->function = (fn);                        \
	} while (0)
#endif /* < 6.15 */

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
 * Zerocopy helpers: msg_zerocopy_realloc and skb_zerocopy_iter_stream
 * require kernel >= 6.7 due to ubuf_info struct split and API changes.
 * These macros are only used by tquic_zerocopy.c which is itself guarded
 * at >= 6.7, so they are only defined for that version range.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 7, 0)
#define TQUIC_MSG_ZEROCOPY_REALLOC(sk, size, uarg) \
	msg_zerocopy_realloc(sk, size, uarg)
#define TQUIC_SKB_ZEROCOPY_ITER_STREAM(sk, skb, msg, len, uarg) \
	skb_zerocopy_iter_stream(sk, skb, msg, len, uarg)
#endif

/*
 * udp_tunnel_xmit_skb() gained an ipcb_flags parameter in 6.13+.
 * Always pass 0 for ipcb_flags on kernels that have the 13-arg version.
 * For kernels older than 6.13, the 12-arg version is used.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 13, 0)
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

/* ========================================================================
 * Kernel < 6.11: ctl_table became const in sysctl handlers in 6.11
 * On older kernels, handler functions take non-const struct ctl_table *.
 * ======================================================================== */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 11, 0)
#define TQUIC_CTL_TABLE const struct ctl_table
#else
#define TQUIC_CTL_TABLE struct ctl_table
#endif /* 6.11 ctl_table const */

/* ========================================================================
 * Kernel < 6.7: proto_accept_arg struct was introduced in 6.7
 * Provide a polyfill for older kernels.
 * ======================================================================== */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 7, 0)
struct proto_accept_arg {
	int flags;
	int err;
	bool kern;
};
#endif /* < 6.7 */

/* ========================================================================
 * Kernel < 6.4: per_cpu_fw_alloc field in struct proto
 * ======================================================================== */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
#define TQUIC_PROTO_PER_CPU_FW_ALLOC(var) .per_cpu_fw_alloc = (var),
#else
#define TQUIC_PROTO_PER_CPU_FW_ALLOC(var)
#endif

/* ========================================================================
 * Kernel < 6.4: ipv6_pinfo_offset field in struct proto
 * ======================================================================== */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 4, 0)
#define TQUIC_PROTO_IPV6_PINFO_OFFSET(type, member) \
	.ipv6_pinfo_offset = offsetof(type, member),
#else
#define TQUIC_PROTO_IPV6_PINFO_OFFSET(type, member)
#endif

/* ========================================================================
 * sysctl_mem type: has been long[] since before 5.4
 * ======================================================================== */
#define TQUIC_SYSCTL_MEM_TYPE long

/* ========================================================================
 * proto.hash return type: has been int since before 5.4
 * ======================================================================== */
#define TQUIC_PROTO_HASH_RET int
#define TQUIC_PROTO_HASH_RETURN return 0

/* ========================================================================
 * Kernel < 5.19: proto.recvmsg had 6 args (extra noblock param)
 * Provide a wrapper macro to adapt the new 5-arg signature.
 * ======================================================================== */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 19, 0)
#define TQUIC_DEFINE_RECVMSG_WRAPPER(name, inner)			\
	static int name(struct sock *sk, struct msghdr *msg, size_t len,\
			int noblock, int flags, int *addr_len)		\
	{								\
		if (noblock)						\
			flags |= MSG_DONTWAIT;				\
		return inner(sk, msg, len, flags, addr_len);		\
	}
#endif /* < 5.19 */

/* ========================================================================
 * Genetlink API compatibility for tquic_netlink.c
 * ======================================================================== */
#include <net/genetlink.h>

/* GENL_MCAST_CAP_NET_ADMIN: added in ~6.10 along with the .flags field
 * in struct genl_multicast_group. On older kernels neither the macro nor
 * the struct field exist, so we must omit the entire field initializer.
 */
#ifdef GENL_MCAST_CAP_NET_ADMIN
#define TQUIC_GENL_MCAST_FLAGS(val) .flags = (val),
#else
#define TQUIC_GENL_MCAST_FLAGS(val)
#endif

/* GENL_REQ_ATTR_CHECK: added in ~5.16. Returns true (error) if the
 * required attribute is missing, and sets extack message automatically.
 * On older kernels, fall back to a simple NULL check on info->attrs[].
 */
#ifndef GENL_REQ_ATTR_CHECK
#define GENL_REQ_ATTR_CHECK(info, attr)			\
	({						\
		 !((info)->attrs[attr]);			\
	})
#endif

/* genl_info_dump(): added in 6.4 to retrieve genl_info from dump cb.
 * On older kernels, attrs must be obtained differently:
 *   5.10 - 6.3: genl_dumpit_info(cb)->attrs
 *   < 5.10:     re-parse from cb->nlh
 * Compat handled inline in tquic_netlink.c rather than here because
 * struct genl_dumpit_info layout and availability vary widely.
 */

/* resv_start_op: added in 5.16 to struct genl_family.
 * On older kernels this field does not exist, so we must guard the
 * designated initializer.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 16, 0)
#define TQUIC_GENL_RESV_START_OP(val) .resv_start_op = (val),
#else
#define TQUIC_GENL_RESV_START_OP(val)
#endif

/* ========================================================================
 * GRO / GSO / Offload compatibility
 * ======================================================================== */

#include <linux/netdevice.h>

/*
 * napi_gro_cb.is_flist: added in 5.11 for frag_list GRO.
 * On older kernels this field does not exist; stub it out.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
#define TQUIC_NAPI_GRO_CB_SET_IS_FLIST(skb, val) do { } while (0)
#else
#define TQUIC_NAPI_GRO_CB_SET_IS_FLIST(skb, val) \
	(NAPI_GRO_CB(skb)->is_flist = (val))
#endif

/*
 * SKB_GSO_FRAGLIST: added in 5.6. On older kernels, frag_list GSO
 * is not available; define it to 0 so bitwise tests always fail and
 * the code gracefully falls through to other paths.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 6, 0)
#ifndef SKB_GSO_FRAGLIST
#define SKB_GSO_FRAGLIST	0
#endif
#endif

/*
 * skb_segment_list(): added in 5.6. On older kernels it does not exist.
 * Guard callers with TQUIC_HAS_SKB_SEGMENT_LIST.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
#define TQUIC_HAS_SKB_SEGMENT_LIST 1
#else
#define TQUIC_HAS_SKB_SEGMENT_LIST 0
#endif

/*
 * __udp_gso_segment(): gained a third bool is_ipv6 parameter in 5.6.
 * On 5.4 it takes only (skb, features).
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 6, 0)
#define TQUIC_UDP_GSO_SEGMENT(skb, features, is_ipv6) \
	__udp_gso_segment(skb, features)
#else
#define TQUIC_UDP_GSO_SEGMENT(skb, features, is_ipv6) \
	__udp_gso_segment(skb, features, is_ipv6)
#endif

/*
 * napi_gro_cb.network_offsets[]: added in 6.5 (commit that introduced
 * per-encapsulation network offsets). Before 6.5, fall back to computing
 * it from skb network header (network_offset singular existed briefly
 * but is not available on all pre-6.5 kernels).
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 5, 0)
#define TQUIC_GRO_NETWORK_OFFSET(skb) \
	NAPI_GRO_CB(skb)->network_offsets[(skb)->encapsulation]
#else
#define TQUIC_GRO_NETWORK_OFFSET(skb) \
	(skb_network_header(skb) - skb_mac_header(skb))
#endif

/*
 * skb_gro_receive_network_offset(): added in 6.5 along with network_offsets.
 * Provide a compat definition for older kernels.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 5, 0)
static inline int tquic_skb_gro_receive_network_offset(const struct sk_buff *skb)
{
	return skb_network_offset(skb);
}
#define skb_gro_receive_network_offset(skb) \
	tquic_skb_gro_receive_network_offset(skb)
#endif

/*
 * skb_gro_checksum_try_convert(): on 5.4 this may not be available
 * as a standalone function. Provide a no-op compat for pre-5.5.
 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 5, 0)
#define tquic_gro_checksum_try_convert(skb, proto, compute_pseudo) \
	do { } while (0)
#else
#define tquic_gro_checksum_try_convert(skb, proto, compute_pseudo) \
	skb_gro_checksum_try_convert(skb, proto, compute_pseudo)
#endif

/*
 * udp_tunnel_encap_enable(): changed from struct socket * to struct sock *
 * in kernel 6.7. On pre-6.7, use udp_encap_enable() which takes no args.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 7, 0)
#define tquic_udp_tunnel_encap_enable(sk) udp_tunnel_encap_enable(sk)
#else
#define tquic_udp_tunnel_encap_enable(sk)		\
	do {						\
		udp_encap_enable();			\
	} while (0)
#endif

/*
 * skb_gro_receive_list(): added in 5.6 with frag_list GRO support.
 * On older kernels, frag_list GRO is not available.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
#define TQUIC_HAS_GRO_RECEIVE_LIST 1
#else
#define TQUIC_HAS_GRO_RECEIVE_LIST 0
#endif

/* ========================================================================
 * Kernel < 6.8: alloc_netdev_dummy() was introduced in 6.8
 * Provide a compat wrapper using alloc_netdev() with a minimal setup
 * function, which works on all kernels 5.4+.
 * ======================================================================== */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 8, 0)
static inline void tquic_compat_dummy_setup(struct net_device *dev)
{
	/* Minimal setup - matches what alloc_netdev_dummy does */
}

static inline struct net_device *alloc_netdev_dummy(int sizeof_priv)
{
	return alloc_netdev(sizeof_priv, "tquic%d", NET_NAME_ENUM,
			    tquic_compat_dummy_setup);
}
#endif /* < 6.8 */

/* ========================================================================
 * Kernel < 6.2: skb_frag_fill_page_desc() was introduced in 6.2
 * On older kernels, populate the frag fields individually using helpers
 * that have been available since well before 5.4.
 * ======================================================================== */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 2, 0)
static inline void skb_frag_fill_page_desc(skb_frag_t *frag,
					    struct page *page,
					    int off, int size)
{
	__skb_frag_set_page(frag, page);
	skb_frag_off_set(frag, off);
	skb_frag_size_set(frag, size);
}
#endif /* < 6.2 */

/* ========================================================================
 * Kernel < 6.2: get_random_u8() was introduced in 6.2
 * Fall back to get_random_u32() truncated to u8.
 * ======================================================================== */
#if LINUX_VERSION_CODE < KERNEL_VERSION(6, 1, 0)
static inline u8 get_random_u8(void)
{
	return (u8)get_random_u32();
}
#endif /* < 6.1 */

/* ========================================================================
 * Kernel < 6.12: GENL_MCAST_CAP_NET_ADMIN was introduced in 6.12
 * On older kernels, multicast group flags field doesn't exist or doesn't
 * support this flag; define as 0 (no capability check).
 * ======================================================================== */
#ifndef GENL_MCAST_CAP_NET_ADMIN
#define GENL_MCAST_CAP_NET_ADMIN 0
#endif

/* ========================================================================
 * Kernel < 5.15: cancel_work() was introduced in 5.15.
 * On older kernels, fall back to cancel_work_sync() which has been
 * available since long before 5.4.
 * ======================================================================== */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 15, 0)
#define cancel_work(work)	cancel_work_sync(work)
#endif

/* ========================================================================
 * Kernel < 5.10: register_netdevice_notifier_net() not available
 * Fall back to global register_netdevice_notifier().
 * ======================================================================== */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 10, 0)
static inline int
tquic_register_netdevice_notifier_net(struct net *net,
				      struct notifier_block *nb)
{
	return register_netdevice_notifier(nb);
}
static inline int
tquic_unregister_netdevice_notifier_net(struct net *net,
					struct notifier_block *nb)
{
	return unregister_netdevice_notifier(nb);
}
#else
#define tquic_register_netdevice_notifier_net(net, nb) \
	register_netdevice_notifier_net(net, nb)
#define tquic_unregister_netdevice_notifier_net(net, nb) \
	unregister_netdevice_notifier_net(net, nb)
#endif

/* ========================================================================
 * Kernel < 5.13: proc_dou8vec_minmax() was introduced in 5.13
 * Provide a compat implementation using proc_dointvec_minmax with a
 * temporary int variable to handle the u8 <-> int size mismatch.
 * Use a prefixed name to avoid conflict with the local sysctl.h header
 * which declares (but doesn't define) proc_dou8vec_minmax on < 5.13.
 * ======================================================================== */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 13, 0)
static inline int tquic_proc_dou8vec_minmax(struct ctl_table *table, int write,
					    void __user *buffer, size_t *lenp,
					    loff_t *ppos)
{
	struct ctl_table tmp;
	unsigned int val;
	int ret;

	tmp = *table;
	tmp.maxlen = sizeof(val);
	tmp.data = &val;

	val = *(u8 *)table->data;
	ret = proc_dointvec_minmax(&tmp, write, buffer, lenp, ppos);
	if (!ret && write)
		*(u8 *)table->data = val;

	return ret;
}
#define proc_dou8vec_minmax tquic_proc_dou8vec_minmax
#endif

/* ========================================================================
 * UDP GRO enable: API changed multiple times
 * - 6.7+: set_bit(UDP_FLAGS_GRO_ENABLED, &udp_sk(sk)->udp_flags)
 * - 5.15-6.6: udp_sk(sk)->gro_enabled = 1
 * - < 5.15: no direct GRO enable (use setsockopt)
 * ======================================================================== */
#include <net/udp.h>
static inline void tquic_udp_enable_gro(struct sock *sk)
{
	/*
	 * UDP GRO enable API history:
	 * - 6.4+: set_bit(UDP_FLAGS_GRO_ENABLED, &udp_sk->udp_flags)
	 *   (gro_enabled merged into udp_flags bitfield)
	 * - < 6.4: no reliable direct-set method across all versions;
	 *   the kernel enables GRO via udp_sock_set_gro() or setsockopt
	 *   internally. For out-of-tree, just skip — GRO is a performance
	 *   optimization, not a correctness requirement.
	 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 7, 0)
	set_bit(UDP_FLAGS_GRO_ENABLED, &udp_sk(sk)->udp_flags);
#endif
}

#endif /* _TQUIC_COMPAT_H */
