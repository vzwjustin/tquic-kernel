// SPDX-License-Identifier: GPL-2.0-only
/*
 * TQUIC: UDP Tunnel Integration for WAN Bonding
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * This module provides UDP tunnel infrastructure for TQUIC connections,
 * enabling multi-path WAN bonding with per-path UDP socket management,
 * GRO/GSO support, and checksum offloading.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/socket.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/net.h>
#include <linux/inetdevice.h>
#include <linux/workqueue.h>
#include <linux/hashtable.h>
#include <net/sock.h>
#include <net/udp.h>
#include <net/udp_tunnel.h>
#include <net/inet_common.h>
#include <net/inet_connection_sock.h>
#include <net/ip.h>
#include <net/route.h>
#include <net/dst_cache.h>
#include <net/checksum.h>
#include <net/gso.h>
#include <net/gro.h>
#if IS_ENABLED(CONFIG_IPV6)
#include <net/ipv6.h>
#include <net/ipv6_stubs.h>
#include <net/ip6_route.h>
#include <net/ip6_checksum.h>
#endif
#include <net/tquic.h>

#include "tquic_compat.h"
#include "tquic_debug.h"
#include "protocol.h"

/* UDP tunnel encapsulation type for TQUIC */
#define UDP_ENCAP_TQUIC		10

/* Default QUIC port */
#define TQUIC_DEFAULT_PORT	443

/* Minimum headroom required for UDP encapsulation */
#define TQUIC_UDP_MIN_HEADROOM	(sizeof(struct iphdr) + sizeof(struct udphdr) + 32)
#define TQUIC_UDP6_MIN_HEADROOM	(sizeof(struct ipv6hdr) + sizeof(struct udphdr) + 32)

/* GSO segment size for UDP */
#define TQUIC_UDP_GSO_SIZE	1200

/* Maximum sockets per connection (for multi-path) */
#define TQUIC_MAX_UDP_SOCKETS	TQUIC_MAX_PATHS

/* Port allocation range */
#define TQUIC_PORT_MIN		49152
#define TQUIC_PORT_MAX		65535

/* Socket hash table */
static DEFINE_HASHTABLE(tquic_udp_sock_hash, 8);
static DEFINE_SPINLOCK(tquic_udp_hash_lock);

/*
 * Listener hash table for demuxing incoming connections
 * Key: local address + port
 * Value: tquic_sock in TCP_LISTEN state
 *
 * This is separate from the UDP socket hash above, which tracks
 * per-path UDP sockets. This tracks TQUIC listening sockets.
 */
static DEFINE_SPINLOCK(tquic_listener_lock);
static struct hlist_head tquic_listeners[256];

/**
 * struct tquic_udp_sock - Per-path UDP socket state
 * @sock: Kernel socket structure
 * @path: Associated path (NULL for listening socket)
 * @conn: Associated connection
 * @family: Address family (AF_INET or AF_INET6)
 * @local_addr: Local address for this socket
 * @remote_addr: Remote address (if connected)
 * @local_port: Local UDP port
 * @remote_port: Remote UDP port
 * @dst_cache: Route cache for fast path
 * @refcnt: Reference counter
 * @work: Cleanup work structure
 * @hash_node: Hash table linkage
 * @flags: Socket flags
 * @gso_enabled: GSO is enabled
 * @gro_enabled: GRO is enabled
 * @csum_offload: Checksum offload is enabled
 * @stats: Per-socket statistics
 */
struct tquic_udp_sock {
	struct socket *sock;
	struct tquic_path *path;
	struct tquic_connection *conn;

	sa_family_t family;
	union {
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} local_addr;
	union {
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} remote_addr;

	__be16 local_port;
	__be16 remote_port;

	struct dst_cache dst_cache;
	refcount_t refcnt;
	struct work_struct cleanup_work;
	struct hlist_node hash_node;

	unsigned long flags;
#define TQUIC_UDSOCK_F_CONNECTED	0
#define TQUIC_UDSOCK_F_LISTENING	1
#define TQUIC_UDSOCK_F_CLOSING		2

	bool gso_enabled;
	bool gro_enabled;
	bool csum_offload;

	/* Statistics */
	struct {
		u64 tx_packets;
		u64 tx_bytes;
		u64 rx_packets;
		u64 rx_bytes;
		u64 tx_errors;
		u64 rx_errors;
		u64 gso_segments;
		u64 gro_packets;
		u64 gro_merged;		/* Packets successfully merged via GRO */
	} stats;
};

/**
 * struct tquic_udp_port_alloc - Port allocation state
 * @lock: Protects port allocation
 * @next_port: Next port to try
 * @bitmap: Bitmap of allocated ports
 */
struct tquic_udp_port_alloc {
	spinlock_t lock;
	u16 next_port;
	DECLARE_BITMAP(bitmap, TQUIC_PORT_MAX - TQUIC_PORT_MIN + 1);
};

static struct tquic_udp_port_alloc port_alloc = {
	.lock = __SPIN_LOCK_UNLOCKED(port_alloc.lock),
	.next_port = TQUIC_PORT_MIN,
};

/* Forward declarations */
static int tquic_udp_encap_recv(struct sock *sk, struct sk_buff *skb);
static void tquic_udp_encap_destroy(struct sock *sk);
static struct sk_buff *tquic_udp_gro_receive(struct sock *sk,
					     struct list_head *head,
					     struct sk_buff *skb);
static int tquic_udp_gro_complete(struct sock *sk, struct sk_buff *skb,
				  int nhoff);
static void tquic_udp_sock_cleanup_work(struct work_struct *work);

/*
 * Port number management
 */

/**
 * tquic_udp_alloc_port - Allocate an ephemeral port
 * @net: Network namespace
 *
 * Returns: Allocated port in network byte order, or 0 on failure
 */
static __be16 tquic_udp_alloc_port(struct net *net)
{
	u16 port;
	int attempts = TQUIC_PORT_MAX - TQUIC_PORT_MIN + 1;

	spin_lock_bh(&port_alloc.lock);

	while (attempts--) {
		port = port_alloc.next_port;

		/* Increment with wrap */
		if (++port_alloc.next_port > TQUIC_PORT_MAX)
			port_alloc.next_port = TQUIC_PORT_MIN;

		/* Check if already in use */
		if (!test_and_set_bit(port - TQUIC_PORT_MIN, port_alloc.bitmap)) {
			spin_unlock_bh(&port_alloc.lock);
			return htons(port);
		}
	}

	spin_unlock_bh(&port_alloc.lock);
	return 0;
}

/**
 * tquic_udp_free_port - Release an allocated port
 * @port: Port to release (network byte order)
 */
static void tquic_udp_free_port(__be16 port)
{
	u16 p = ntohs(port);

	if (p < TQUIC_PORT_MIN || p > TQUIC_PORT_MAX)
		return;

	spin_lock_bh(&port_alloc.lock);
	clear_bit(p - TQUIC_PORT_MIN, port_alloc.bitmap);
	spin_unlock_bh(&port_alloc.lock);
}

/**
 * tquic_udp_reserve_port - Reserve a specific port
 * @port: Port to reserve (network byte order)
 *
 * Returns: 0 on success, -EADDRINUSE if already in use
 */
static int tquic_udp_reserve_port(__be16 port)
{
	u16 p = ntohs(port);
	int ret = 0;

	if (p < TQUIC_PORT_MIN || p > TQUIC_PORT_MAX)
		return -EINVAL;

	spin_lock_bh(&port_alloc.lock);
	if (test_and_set_bit(p - TQUIC_PORT_MIN, port_alloc.bitmap))
		ret = -EADDRINUSE;
	spin_unlock_bh(&port_alloc.lock);

	return ret;
}

/*
 * =============================================================================
 * TQUIC Listener Registration
 * =============================================================================
 *
 * These functions manage the listener hash table for demuxing incoming
 * QUIC Initial packets to the correct listening socket.
 */

/**
 * tquic_listener_hash_port - Compute hash for listener lookup by port only
 * @port: Port number in network byte order
 *
 * Hash by port only to allow finding both specific-address and wildcard
 * listeners in the same bucket. Address matching is done during iteration.
 *
 * This follows the pattern of TCP's inet_lhashfn() which hashes by port,
 * allowing efficient lookup of listeners bound to different addresses
 * on the same port.
 */
static inline u32 tquic_listener_hash_port(__be16 port)
{
	return jhash_1word((__force u32)port, 0) & 0xff;
}

/**
 * tquic_listener_hash - Compute hash for listener lookup
 * @addr: Local address to hash
 *
 * Extracts port from address and hashes by port only.
 * This ensures listeners on the same port but different addresses
 * (including wildcard) end up in the same hash bucket.
 */
static inline u32 tquic_listener_hash(const struct sockaddr_storage *addr)
{
	__be16 port = 0;

	if (addr->ss_family == AF_INET) {
		const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
		port = sin->sin_port;
	} else if (addr->ss_family == AF_INET6) {
		const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;
		port = sin6->sin6_port;
	}

	return tquic_listener_hash_port(port);
}

/**
 * tquic_register_listener - Register socket to receive incoming connections
 * @sk: Socket transitioning to TCP_LISTEN state
 *
 * Adds the socket to the listener hash table for packet demuxing.
 * Called by listen() before transitioning to TCP_LISTEN state.
 *
 * Returns: 0 on success, negative errno on failure
 */
int tquic_register_listener(struct sock *sk)
{
	struct tquic_sock *tsk = tquic_sk(sk);
	u32 hash;

	if (tsk->flags & TQUIC_F_LISTENER_REGISTERED)
		return 0;  /* Already registered */

	hash = tquic_listener_hash(&tsk->bind_addr);

	spin_lock_bh(&tquic_listener_lock);
	hlist_add_head_rcu(&tsk->listener_node, &tquic_listeners[hash]);
	tsk->flags |= TQUIC_F_LISTENER_REGISTERED;
	spin_unlock_bh(&tquic_listener_lock);

	tquic_dbg("listener registered, hash=%u\n", hash);
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_register_listener);

/**
 * tquic_unregister_listener - Remove socket from listener table
 * @sk: Socket to unregister
 *
 * Removes the socket from the listener hash table.
 * Called by release() and when transitioning away from TCP_LISTEN.
 */
void tquic_unregister_listener(struct sock *sk)
{
	struct tquic_sock *tsk = tquic_sk(sk);

	if (!(tsk->flags & TQUIC_F_LISTENER_REGISTERED))
		return;

	spin_lock_bh(&tquic_listener_lock);
	hlist_del_init_rcu(&tsk->listener_node);
	tsk->flags &= ~TQUIC_F_LISTENER_REGISTERED;
	spin_unlock_bh(&tquic_listener_lock);

	/* Ensure RCU readers have completed */
	synchronize_rcu();

	tquic_dbg("listener unregistered\n");
}
EXPORT_SYMBOL_GPL(tquic_unregister_listener);

/*
 * Helper: Check if an IPv4 address is wildcard (INADDR_ANY)
 */
static inline bool tquic_ipv4_is_wildcard(__be32 addr)
{
	return addr == htonl(INADDR_ANY);
}

#if IS_ENABLED(CONFIG_IPV6)
/*
 * Helper: Check if an IPv6 address is wildcard (in6addr_any)
 */
static inline bool tquic_ipv6_is_wildcard(const struct in6_addr *addr)
{
	return ipv6_addr_any(addr);
}

/*
 * Helper: Check if IPv6 address is IPv4-mapped (::ffff:x.x.x.x)
 */
static inline bool tquic_ipv6_is_v4mapped(const struct in6_addr *addr)
{
	return ipv6_addr_v4mapped(addr);
}

/*
 * Helper: Extract IPv4 address from IPv4-mapped IPv6 address
 */
static inline __be32 tquic_ipv6_get_v4mapped(const struct in6_addr *addr)
{
	return addr->s6_addr32[3];
}
#endif

/*
 * tquic_listener_addr_match - Compare addresses for listener matching
 * @bind_addr: Listener's bound address
 * @local_addr: Incoming packet's destination address
 *
 * Returns match score:
 *   0 = no match
 *   1 = wildcard match (listener bound to INADDR_ANY/in6addr_any)
 *   2 = exact address match
 *   3 = IPv4-mapped match (IPv6 wildcard listener matching IPv4)
 *
 * Higher score = more specific match.
 */
static int tquic_listener_addr_match(const struct sockaddr_storage *bind_addr,
				     const struct sockaddr_storage *local_addr)
{
	/* Handle IPv4 addresses */
	if (bind_addr->ss_family == AF_INET &&
	    local_addr->ss_family == AF_INET) {
		const struct sockaddr_in *bind_sin =
			(const struct sockaddr_in *)bind_addr;
		const struct sockaddr_in *local_sin =
			(const struct sockaddr_in *)local_addr;

		/* Port must match */
		if (bind_sin->sin_port != local_sin->sin_port)
			return 0;

		/* Exact address match */
		if (bind_sin->sin_addr.s_addr == local_sin->sin_addr.s_addr)
			return 2;

		/* Wildcard match (INADDR_ANY) */
		if (tquic_ipv4_is_wildcard(bind_sin->sin_addr.s_addr))
			return 1;

		return 0;
	}

#if IS_ENABLED(CONFIG_IPV6)
	/* Handle IPv6 addresses */
	if (bind_addr->ss_family == AF_INET6 &&
	    local_addr->ss_family == AF_INET6) {
		const struct sockaddr_in6 *bind_sin6 =
			(const struct sockaddr_in6 *)bind_addr;
		const struct sockaddr_in6 *local_sin6 =
			(const struct sockaddr_in6 *)local_addr;

		/* Port must match */
		if (bind_sin6->sin6_port != local_sin6->sin6_port)
			return 0;

		/* Exact address match */
		if (ipv6_addr_equal(&bind_sin6->sin6_addr,
				    &local_sin6->sin6_addr))
			return 2;

		/* Wildcard match (in6addr_any) */
		if (tquic_ipv6_is_wildcard(&bind_sin6->sin6_addr))
			return 1;

		return 0;
	}

	/*
	 * Handle cross-family matching:
	 * IPv6 wildcard listener can accept IPv4 connections
	 * (dual-stack socket behavior)
	 */
	if (bind_addr->ss_family == AF_INET6 &&
	    local_addr->ss_family == AF_INET) {
		const struct sockaddr_in6 *bind_sin6 =
			(const struct sockaddr_in6 *)bind_addr;
		const struct sockaddr_in *local_sin =
			(const struct sockaddr_in *)local_addr;

		/* Port must match (network byte order) */
		if (bind_sin6->sin6_port != local_sin->sin_port)
			return 0;

		/* IPv6 wildcard matches any IPv4 address */
		if (tquic_ipv6_is_wildcard(&bind_sin6->sin6_addr))
			return 1;

		/*
		 * IPv4-mapped IPv6 address match:
		 * Listener bound to ::ffff:a.b.c.d matches IPv4 a.b.c.d
		 */
		if (tquic_ipv6_is_v4mapped(&bind_sin6->sin6_addr)) {
			__be32 mapped_addr = tquic_ipv6_get_v4mapped(
				&bind_sin6->sin6_addr);

			/* Exact mapped address match */
			if (mapped_addr == local_sin->sin_addr.s_addr)
				return 2;

			/* Wildcard mapped address (::ffff:0.0.0.0) */
			if (tquic_ipv4_is_wildcard(mapped_addr))
				return 1;
		}

		return 0;
	}

	/*
	 * Handle IPv4 listener matching IPv4-mapped IPv6 address
	 * (incoming packet has IPv6 header but IPv4-mapped destination)
	 */
	if (bind_addr->ss_family == AF_INET &&
	    local_addr->ss_family == AF_INET6) {
		const struct sockaddr_in *bind_sin =
			(const struct sockaddr_in *)bind_addr;
		const struct sockaddr_in6 *local_sin6 =
			(const struct sockaddr_in6 *)local_addr;
		__be32 v4addr;

		/* Only match if the IPv6 address is IPv4-mapped */
		if (!tquic_ipv6_is_v4mapped(&local_sin6->sin6_addr))
			return 0;

		/* Port must match */
		if (bind_sin->sin_port != local_sin6->sin6_port)
			return 0;

		/* Extract the IPv4 address from the mapped address */
		v4addr = tquic_ipv6_get_v4mapped(&local_sin6->sin6_addr);

		/* Exact address match */
		if (bind_sin->sin_addr.s_addr == v4addr)
			return 2;

		/* Wildcard match */
		if (tquic_ipv4_is_wildcard(bind_sin->sin_addr.s_addr))
			return 1;

		return 0;
	}
#endif

	return 0;
}

/**
 * tquic_listener_compute_score - Compute match score for a listener
 * @tsk: TQUIC socket to evaluate
 * @local_addr: Incoming packet's destination address
 * @net: Network namespace to match
 *
 * Computes a score indicating how well this listener matches the
 * incoming packet's destination address. Higher scores indicate
 * more specific matches.
 *
 * Score breakdown:
 *   -1 = No match (wrong port, wrong address family, wrong netns)
 *    1 = Wildcard address match (INADDR_ANY or in6addr_any)
 *    2 = Exact address match
 *    3 = Exact match + bound to specific device
 *    4 = Exact match + bound device + same CPU (NUMA locality)
 *
 * This mirrors TCP's compute_score() in inet_hashtables.c
 *
 * Returns: Match score, or -1 if no match
 */
static int tquic_listener_compute_score(struct tquic_sock *tsk,
					const struct sockaddr_storage *local_addr,
					struct net *net)
{
	struct sock *sk = (struct sock *)tsk;
	int score;
	int addr_score;

	/* Must be in listening state */
	if (sk->sk_state != TCP_LISTEN)
		return -1;

	/* Network namespace must match */
	if (net && !net_eq(sock_net(sk), net))
		return -1;

	/* Get address match score (0 = no match, 1 = wildcard, 2 = exact) */
	addr_score = tquic_listener_addr_match(&tsk->bind_addr, local_addr);
	if (addr_score == 0)
		return -1;

	/* Base score from address match */
	score = addr_score;

	/*
	 * Bonus for bound device (like TCP):
	 * Listeners bound to a specific interface are preferred over
	 * listeners bound to all interfaces.
	 */
	if (sk->sk_bound_dev_if) {
		/*
		 * Note: For full device matching we would need the incoming
		 * interface index. For now, just give a small bonus for
		 * being bound to a specific device.
		 */
		score++;
	}

	/*
	 * Bonus for CPU locality (like TCP):
	 * If the listener's preferred incoming CPU matches the current
	 * CPU, give a small performance bonus.
	 */
	if (READ_ONCE(sk->sk_incoming_cpu) == raw_smp_processor_id())
		score++;

	return score;
}

/**
 * tquic_lookup_listener_in_bucket - Search a single hash bucket for listeners
 * @bucket: Hash bucket to search
 * @local_addr: Incoming packet's destination address
 * @net: Network namespace (may be NULL to skip netns check)
 * @best_sk: Current best match (input/output)
 * @best_score: Current best score (input/output)
 *
 * Iterates through all listeners in the bucket and updates best_sk/best_score
 * if a better match is found.
 *
 * Returns: true if an exact match was found (can stop searching)
 */
static bool tquic_lookup_listener_in_bucket(struct hlist_head *bucket,
					    const struct sockaddr_storage *local_addr,
					    struct net *net,
					    struct sock **best_sk,
					    int *best_score)
{
	struct tquic_sock *tsk;
	int score;

	hlist_for_each_entry_rcu(tsk, bucket, listener_node) {
		score = tquic_listener_compute_score(tsk, local_addr, net);

		if (score > *best_score) {
			*best_score = score;
			*best_sk = (struct sock *)tsk;

			/*
			 * Exact address match with good score - this is optimal.
			 * Score of 2 means exact address match, 3+ means exact
			 * with additional bonuses. No need to continue searching.
			 */
			if (score >= 2)
				return true;
		}
	}

	return false;
}

/**
 * tquic_lookup_listener - Find listener for incoming packet
 * @local_addr: Local address from incoming UDP packet (destination addr+port)
 *
 * Searches the listener hash table for a socket listening on the
 * specified local address. Returns the most specific match:
 *   - Exact address match preferred over wildcard
 *   - IPv4-mapped addresses handled for dual-stack support
 *   - Device-bound listeners preferred over unbound
 *
 * The lookup algorithm (following TCP's __inet_lookup_listener pattern):
 *   1. Hash by port to find the bucket
 *   2. Iterate all listeners in bucket, computing match score for each
 *   3. Return highest-scoring listener (most specific match)
 *
 * For servers with multiple interfaces or IP addresses, this ensures
 * packets are delivered to the correct listener:
 *   - Listener on 192.168.1.1:443 gets packets for that IP
 *   - Listener on 0.0.0.0:443 gets packets for any other IP on port 443
 *   - If both exist, specific IP listener wins
 *
 * Thread safety: Caller must hold RCU read lock.
 *
 * Returns: Matching listener socket, or NULL if not found
 */
struct sock *tquic_lookup_listener(const struct sockaddr_storage *local_addr)
{
	struct sock *best_sk = NULL;
	int best_score = 0;
	u32 hash;

	/*
	 * Hash by port only - this puts all listeners on the same port
	 * into the same bucket, regardless of their bound address.
	 * This is crucial for matching both specific-address and wildcard
	 * listeners efficiently.
	 */
	hash = tquic_listener_hash(local_addr);

	/*
	 * Search the bucket for the best matching listener.
	 * Unlike TCP which does separate lookups for specific address and
	 * INADDR_ANY buckets, we use a single bucket keyed by port only
	 * and score each listener based on address match specificity.
	 */
	tquic_lookup_listener_in_bucket(&tquic_listeners[hash], local_addr,
					NULL, &best_sk, &best_score);

	return best_sk;
}
EXPORT_SYMBOL_GPL(tquic_lookup_listener);

/**
 * tquic_lookup_listener_net - Find listener for incoming packet with netns
 * @net: Network namespace to search in
 * @local_addr: Local address from incoming UDP packet
 *
 * Like tquic_lookup_listener() but also matches network namespace.
 * Use this when you have the network namespace from the incoming socket.
 *
 * Returns: Matching listener socket, or NULL if not found
 */
struct sock *tquic_lookup_listener_net(struct net *net,
				       const struct sockaddr_storage *local_addr)
{
	struct sock *best_sk = NULL;
	int best_score = 0;
	u32 hash;

	if (!net)
		return tquic_lookup_listener(local_addr);

	hash = tquic_listener_hash(local_addr);

	tquic_lookup_listener_in_bucket(&tquic_listeners[hash], local_addr,
					net, &best_sk, &best_score);

	return best_sk;
}
EXPORT_SYMBOL_GPL(tquic_lookup_listener_net);

/*
 * Socket hash table operations
 */

static inline u32 tquic_udp_sock_hash_key(__be16 port)
{
	return jhash_1word((__force u32)port, 0);
}

static void tquic_udp_sock_hash_add(struct tquic_udp_sock *us)
{
	u32 key = tquic_udp_sock_hash_key(us->local_port);

	spin_lock_bh(&tquic_udp_hash_lock);
	hash_add(tquic_udp_sock_hash, &us->hash_node, key);
	spin_unlock_bh(&tquic_udp_hash_lock);
}

static void tquic_udp_sock_hash_remove(struct tquic_udp_sock *us)
{
	spin_lock_bh(&tquic_udp_hash_lock);
	hash_del(&us->hash_node);
	spin_unlock_bh(&tquic_udp_hash_lock);
}

static struct tquic_udp_sock __maybe_unused *tquic_udp_sock_lookup(__be16 port)
{
	struct tquic_udp_sock *us;
	u32 key = tquic_udp_sock_hash_key(port);

	spin_lock_bh(&tquic_udp_hash_lock);
	hash_for_each_possible(tquic_udp_sock_hash, us, hash_node, key) {
		if (us->local_port == port) {
			if (!refcount_inc_not_zero(&us->refcnt)) {
				spin_unlock_bh(&tquic_udp_hash_lock);
				return NULL;
			}
			spin_unlock_bh(&tquic_udp_hash_lock);
			return us;
		}
	}
	spin_unlock_bh(&tquic_udp_hash_lock);

	return NULL;
}

/*
 * Socket creation and configuration
 */

/**
 * tquic_udp_sock_create4 - Create an IPv4 UDP socket
 * @net: Network namespace
 * @local_addr: Local address
 * @local_port: Local port (0 for auto-allocation)
 * @us: UDP socket structure to populate
 *
 * Returns: 0 on success, negative error code on failure
 */
static int tquic_udp_sock_create4(struct net *net,
				  struct in_addr *local_addr,
				  __be16 local_port,
				  struct tquic_udp_sock *us)
{
	struct udp_port_cfg cfg = {
		.family = AF_INET,
		.local_ip = *local_addr,
		.local_udp_port = local_port,
		.use_udp_checksums = true,
	};
	struct udp_tunnel_sock_cfg tunnel_cfg = {
		.sk_user_data = us,
		.encap_type = UDP_ENCAP_TQUIC,
		.encap_rcv = tquic_udp_encap_recv,
		.encap_destroy = tquic_udp_encap_destroy,
		.gro_receive = tquic_udp_gro_receive,
		.gro_complete = tquic_udp_gro_complete,
	};
	int err;

	/* Allocate port if not specified */
	if (!local_port) {
		local_port = tquic_udp_alloc_port(net);
		if (!local_port)
			return -EADDRINUSE;
		cfg.local_udp_port = local_port;
	} else {
		err = tquic_udp_reserve_port(local_port);
		if (err)
			return err;
	}

	err = udp_sock_create4(net, &cfg, &us->sock);
	if (err) {
		tquic_udp_free_port(local_port);
		return err;
	}

	/* Configure for tunnel operation */
	setup_udp_tunnel_sock(net, us->sock, &tunnel_cfg);

	us->family = AF_INET;
	us->local_port = local_port;
	us->local_addr.sin.sin_family = AF_INET;
	us->local_addr.sin.sin_addr = *local_addr;
	us->local_addr.sin.sin_port = local_port;

	/* Enable checksum offload if supported */
	us->csum_offload = true;
	us->sock->sk->sk_no_check_tx = 0;

	/* Initialize dst cache */
	err = dst_cache_init(&us->dst_cache, GFP_KERNEL);
	if (err) {
		udp_tunnel_sock_release(us->sock);
		tquic_udp_free_port(local_port);
		return err;
	}

	us->gso_enabled = true;
	us->gro_enabled = true;

	return 0;
}

#if IS_ENABLED(CONFIG_IPV6)
/**
 * tquic_udp_sock_create6 - Create an IPv6 UDP socket
 * @net: Network namespace
 * @local_addr: Local address
 * @local_port: Local port (0 for auto-allocation)
 * @us: UDP socket structure to populate
 *
 * Returns: 0 on success, negative error code on failure
 */
static int tquic_udp_sock_create6(struct net *net,
				  struct in6_addr *local_addr,
				  __be16 local_port,
				  struct tquic_udp_sock *us)
{
	struct udp_port_cfg cfg = {
		.family = AF_INET6,
		.local_ip6 = *local_addr,
		.local_udp_port = local_port,
		.use_udp6_tx_checksums = true,
		.use_udp6_rx_checksums = true,
	};
	struct udp_tunnel_sock_cfg tunnel_cfg = {
		.sk_user_data = us,
		.encap_type = UDP_ENCAP_TQUIC,
		.encap_rcv = tquic_udp_encap_recv,
		.encap_destroy = tquic_udp_encap_destroy,
		.gro_receive = tquic_udp_gro_receive,
		.gro_complete = tquic_udp_gro_complete,
	};
	int err;

	/* Allocate port if not specified */
	if (!local_port) {
		local_port = tquic_udp_alloc_port(net);
		if (!local_port)
			return -EADDRINUSE;
		cfg.local_udp_port = local_port;
	} else {
		err = tquic_udp_reserve_port(local_port);
		if (err)
			return err;
	}

	err = udp_sock_create6(net, &cfg, &us->sock);
	if (err) {
		tquic_udp_free_port(local_port);
		return err;
	}

	/* Configure for tunnel operation */
	setup_udp_tunnel_sock(net, us->sock, &tunnel_cfg);

	us->family = AF_INET6;
	us->local_port = local_port;
	us->local_addr.sin6.sin6_family = AF_INET6;
	us->local_addr.sin6.sin6_addr = *local_addr;
	us->local_addr.sin6.sin6_port = local_port;

	/* Enable checksum offload */
	us->csum_offload = true;

	/* Initialize dst cache */
	err = dst_cache_init(&us->dst_cache, GFP_KERNEL);
	if (err) {
		udp_tunnel_sock_release(us->sock);
		tquic_udp_free_port(local_port);
		return err;
	}

	us->gso_enabled = true;
	us->gro_enabled = true;

	return 0;
}
#endif

/**
 * tquic_udp_sock_alloc - Allocate a new UDP socket structure
 *
 * Returns: Allocated structure or NULL on failure
 */
static struct tquic_udp_sock *tquic_udp_sock_alloc(void)
{
	struct tquic_udp_sock *us;

	us = kzalloc(sizeof(*us), GFP_KERNEL);
	if (!us)
		return NULL;

	refcount_set(&us->refcnt, 1);
	INIT_HLIST_NODE(&us->hash_node);
	INIT_WORK(&us->cleanup_work, tquic_udp_sock_cleanup_work);

	return us;
}

/**
 * tquic_udp_sock_cleanup_work - Deferred socket cleanup
 * @work: Work structure
 */
static void tquic_udp_sock_cleanup_work(struct work_struct *work)
{
	struct tquic_udp_sock *us = container_of(work, struct tquic_udp_sock,
						 cleanup_work);

	if (us->sock) {
		dst_cache_destroy(&us->dst_cache);
		udp_tunnel_sock_release(us->sock);
	}

	tquic_udp_free_port(us->local_port);
	kfree(us);
}

/**
 * tquic_udp_sock_put - Release reference to UDP socket
 * @us: UDP socket
 */
void tquic_udp_sock_put(struct tquic_udp_sock *us)
{
	if (!us)
		return;

	if (refcount_dec_and_test(&us->refcnt)) {
		tquic_udp_sock_hash_remove(us);

		/* Schedule cleanup in process context */
		schedule_work(&us->cleanup_work);
	}
}
EXPORT_SYMBOL_GPL(tquic_udp_sock_put);

/**
 * tquic_udp_sock_hold - Take reference to UDP socket
 * @us: UDP socket
 */
static inline void tquic_udp_sock_hold(struct tquic_udp_sock *us)
{
	if (us)
		refcount_inc(&us->refcnt);
}

/*
 * Socket connection for path binding
 */

/**
 * tquic_udp_connect - Connect UDP socket to remote address
 * @us: UDP socket
 * @remote: Remote address
 *
 * Returns: 0 on success, negative error code on failure
 */
int tquic_udp_connect(struct tquic_udp_sock *us,
		      struct sockaddr_storage *remote)
{
	int err;

	if (test_bit(TQUIC_UDSOCK_F_CONNECTED, &us->flags))
		return -EISCONN;

	if (us->family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *)remote;

		err = kernel_connect(us->sock, (struct sockaddr_unsized *)sin,
				     sizeof(*sin), 0);
		if (err)
			return err;

		us->remote_addr.sin = *sin;
		us->remote_port = sin->sin_port;
	}
#if IS_ENABLED(CONFIG_IPV6)
	else if (us->family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)remote;

		err = kernel_connect(us->sock, (struct sockaddr_unsized *)sin6,
				     sizeof(*sin6), 0);
		if (err)
			return err;

		us->remote_addr.sin6 = *sin6;
		us->remote_port = sin6->sin6_port;
	}
#endif
	else {
		return -EAFNOSUPPORT;
	}

	set_bit(TQUIC_UDSOCK_F_CONNECTED, &us->flags);

	/* Clear dst cache on connect */
	dst_cache_reset(&us->dst_cache);

	tquic_dbg("udp:socket connected to remote\n");
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_udp_connect);

/*
 * Receive path
 */

/**
 * tquic_udp_encap_recv - Receive callback for encapsulated packets
 * @sk: Socket that received the packet
 * @skb: Received socket buffer
 *
 * Returns: 0 on success (skb consumed), >0 if skb should be resubmitted,
 *          <0 on error
 */
static int tquic_udp_encap_recv(struct sock *sk, struct sk_buff *skb)
{
	struct tquic_udp_sock *us;
	struct tquic_connection *conn;
	struct tquic_path *path;
	struct udphdr *uh;
	int ret;

	/* Get our socket context */
	us = rcu_dereference_sk_user_data(sk);
	if (!us) {
		tquic_dbg("udp:no socket context\n");
		goto drop;
	}

	conn = us->conn;
	path = us->path;

	/* Skip UDP header - already pulled by UDP layer */
	if (!pskb_may_pull(skb, sizeof(struct udphdr)))
		goto drop;

	uh = udp_hdr(skb);

	/* Validate packet length */
	if (skb->len < sizeof(struct udphdr))
		goto drop;

	/* Pull UDP header */
	__skb_pull(skb, sizeof(struct udphdr));
	skb_reset_transport_header(skb);

	/* Update statistics */
	us->stats.rx_packets++;
	us->stats.rx_bytes += skb->len;

	/* Update path statistics if we have a path */
	if (path) {
		path->stats.rx_packets++;
		path->stats.rx_bytes += skb->len;
		path->last_activity = ktime_get();
	}

	/* If this is a listening socket, find/create connection */
	if (test_bit(TQUIC_UDSOCK_F_LISTENING, &us->flags)) {
		/*
		 * Lookup connection by QUIC connection ID.
		 * Extract DCID from packet header and lookup in CID table.
		 */
		struct tquic_cid dcid;
		struct tquic_connection *lookup_conn;

		if (skb->len >= 1) {
			if (skb->data[0] & 0x80) {
				/* Long header: version(4) + dcid_len(1) + dcid */
				if (skb->len >= 6) {
					u8 dcid_len = skb->data[5];
					if (dcid_len <= TQUIC_MAX_CID_LEN &&
					    skb->len >= 6 + dcid_len) {
						dcid.len = dcid_len;
						memcpy(dcid.id, skb->data + 6,
						       dcid_len);
						lookup_conn = tquic_conn_lookup_by_cid(&dcid);
						if (lookup_conn)
							conn = lookup_conn;
					}
				}
			} else {
				/* Short header: dcid at byte 1 */
				if (skb->len >= 1 + TQUIC_DEFAULT_CID_LEN) {
					dcid.len = TQUIC_DEFAULT_CID_LEN;
					memcpy(dcid.id, skb->data + 1,
					       TQUIC_DEFAULT_CID_LEN);
					lookup_conn = tquic_conn_lookup_by_cid(&dcid);
					if (lookup_conn)
						conn = lookup_conn;
				}
			}
		}
	}

	/* Deliver to connection */
	if (conn) {
		ret = tquic_udp_deliver_to_conn(conn, path, skb);
		if (ret == 0)
			return 0;
	}

	/* Fall through to drop if delivery failed */
drop:
	if (us)
		us->stats.rx_errors++;
	kfree_skb(skb);
	return 0;
}

/**
 * tquic_udp_deliver_to_conn - Deliver received packet to connection
 * @conn: Target connection
 * @path: Path packet was received on
 * @skb: Packet to deliver
 *
 * Returns: 0 on success, negative error on failure
 */
int tquic_udp_deliver_to_conn(struct tquic_connection *conn,
			      struct tquic_path *path,
			      struct sk_buff *skb)
{
	struct tquic_sock *tsk;

	if (!conn || !conn->sk)
		return -ENOTCONN;

	tsk = tquic_sk(conn->sk);

	/* Update connection statistics */
	conn->stats.rx_packets++;
	conn->stats.rx_bytes += skb->len;

	/*
	 * Process QUIC packet:
	 * 1. Parse QUIC header
	 * 2. Decrypt payload (if not Initial packet)
	 * 3. Handle frames (ACK, STREAM, PATH_CHALLENGE, etc.)
	 * 4. Deliver stream data to application
	 */
	if (skb->len >= 1) {
		u8 *data = skb->data;
		size_t len = skb->len;

		/* Check packet type */
		if (data[0] & 0x80) {
			/* Long header packet - handle during handshake */
			if (conn->state == TQUIC_CONN_CONNECTING ||
			    conn->state == TQUIC_CONN_IDLE) {
				/* Process handshake packet */
				tquic_conn_process_handshake(conn, skb);
				return 0;
			}
		} else {
			/* Short header (1-RTT) packet */
			if (conn->state == TQUIC_CONN_CONNECTED) {
				/*
				 * For connected state, process via coalesced
				 * packet handler which handles decryption
				 * and frame processing.
				 */
				struct sockaddr_storage src_addr;
				memset(&src_addr, 0, sizeof(src_addr));
				if (path) {
					memcpy(&src_addr, &path->remote_addr,
					       sizeof(src_addr));
				}

				tquic_process_coalesced(conn, path, data, len,
							&src_addr);
				kfree_skb(skb);
				return 0;
			}
		}
	}

	/* Fallback: queue to default stream for basic functionality */
	if (tsk->default_stream) {
		skb_queue_tail(&tsk->default_stream->recv_buf, skb);
		conn->sk->sk_data_ready(conn->sk);
		return 0;
	}

	kfree_skb(skb);
	return 0;
}
EXPORT_SYMBOL_GPL(tquic_udp_deliver_to_conn);

/**
 * tquic_udp_encap_destroy - Callback when encap socket is destroyed
 * @sk: Socket being destroyed
 */
static void tquic_udp_encap_destroy(struct sock *sk)
{
	struct tquic_udp_sock *us;

	rcu_read_lock();
	us = rcu_dereference_sk_user_data(sk);
	if (us) {
		set_bit(TQUIC_UDSOCK_F_CLOSING, &us->flags);
		tquic_udp_sock_put(us);
	}
	rcu_read_unlock();
}

/*
 * GRO (Generic Receive Offload) support
 */

/**
 * tquic_udp_gro_receive - GRO receive callback
 * @sk: Socket
 * @head: List of held packets
 * @skb: New packet to potentially aggregate
 *
 * Uses the TQUIC GRO offload module for packet coalescing. QUIC packets
 * from the same connection (same DCID) can be aggregated using frag_list
 * to reduce per-packet processing overhead.
 *
 * Returns: Packet to flush, or NULL
 */
static struct sk_buff *tquic_udp_gro_receive(struct sock *sk,
					     struct list_head *head,
					     struct sk_buff *skb)
{
	struct tquic_udp_sock *us;
	struct udphdr *uh;

	us = rcu_dereference_sk_user_data(sk);
	if (!us || !us->gro_enabled) {
		NAPI_GRO_CB(skb)->flush = 1;
		return NULL;
	}

	/* Update socket-level GRO statistics */
	us->stats.gro_packets++;

	/* Get UDP header for the TQUIC GRO receive */
	uh = udp_hdr(skb);

	/* Use TQUIC-specific GRO receive for packet aggregation */
	return tquic_gro_receive_udp(sk, head, skb);
}

/**
 * tquic_udp_gro_complete - GRO complete callback
 * @sk: Socket
 * @skb: Completed packet
 * @nhoff: Network header offset
 *
 * Finalizes GRO aggregation for TQUIC packets. Sets up GSO information
 * so the aggregated packet can be properly handled by the stack.
 *
 * Returns: 0 on success
 */
static int tquic_udp_gro_complete(struct sock *sk, struct sk_buff *skb,
				  int nhoff)
{
	struct tquic_udp_sock *us;

	us = rcu_dereference_sk_user_data(sk);
	if (us)
		us->stats.gro_merged++;

	/* Use TQUIC-specific GRO complete */
	return tquic_gro_complete_udp(sk, skb, nhoff);
}

/*
 * Transmit path
 */

/**
 * tquic_udp_xmit_skb4 - Transmit packet over IPv4
 * @us: UDP socket
 * @skb: Packet to transmit
 *
 * Returns: 0 on success, negative error on failure
 */
static int tquic_udp_xmit_skb4(struct tquic_udp_sock *us, struct sk_buff *skb)
{
	struct sock *sk = us->sock->sk;
	struct net *net = sock_net(sk);
	struct rtable *rt;
	struct flowi4 fl4;
	__be32 saddr, daddr;
	unsigned int skb_len;
	int err;

	/* Get addresses */
	saddr = us->local_addr.sin.sin_addr.s_addr;
	daddr = us->remote_addr.sin.sin_addr.s_addr;

	/* Try dst cache first */
	rt = dst_cache_get_ip4(&us->dst_cache, &saddr);
	if (!rt) {
		memset(&fl4, 0, sizeof(fl4));
		fl4.flowi4_oif = 0;
		fl4.flowi4_proto = IPPROTO_UDP;
		fl4.daddr = daddr;
		fl4.saddr = saddr;
		fl4.fl4_sport = us->local_port;
		fl4.fl4_dport = us->remote_port;

		rt = ip_route_output_key(net, &fl4);
		if (IS_ERR(rt)) {
			err = PTR_ERR(rt);
			goto err_free;
		}

		dst_cache_set_ip4(&us->dst_cache, &rt->dst, saddr);
	}

	/* Save skb->len before xmit which consumes the SKB */
	skb_len = skb->len;

	/* Use udp_tunnel_xmit_skb for proper encapsulation */
	TQUIC_UDP_TUNNEL_XMIT_SKB(rt, sk, skb,
				  saddr, daddr,
				  0,			/* TOS */
				  ip4_dst_hoplimit(&rt->dst),
				  0,			/* DF */
				  us->local_port,
				  us->remote_port,
				  false,		/* xnet */
				  !us->csum_offload);	/* nocheck */

	/* SKB is consumed after xmit -- do not access it */
	us->stats.tx_packets++;
	us->stats.tx_bytes += skb_len;

	return 0;

err_free:
	us->stats.tx_errors++;
	kfree_skb(skb);
	return err;
}

#if IS_ENABLED(CONFIG_IPV6)
/**
 * tquic_udp_xmit_skb6 - Transmit packet over IPv6
 * @us: UDP socket
 * @skb: Packet to transmit
 *
 * Returns: 0 on success, negative error on failure
 */
static int tquic_udp_xmit_skb6(struct tquic_udp_sock *us, struct sk_buff *skb)
{
	struct sock *sk = us->sock->sk;
	struct net *net = sock_net(sk);
	struct dst_entry *dst;
	struct flowi6 fl6;
	unsigned int skb_len;
	int err;

	/* Try dst cache first */
	dst = dst_cache_get_ip6(&us->dst_cache, &us->local_addr.sin6.sin6_addr);
	if (!dst) {
		memset(&fl6, 0, sizeof(fl6));
		fl6.flowi6_proto = IPPROTO_UDP;
		fl6.daddr = us->remote_addr.sin6.sin6_addr;
		fl6.saddr = us->local_addr.sin6.sin6_addr;
		fl6.fl6_sport = us->local_port;
		fl6.fl6_dport = us->remote_port;

		dst = ipv6_stub->ipv6_dst_lookup_flow(net, sk, &fl6, NULL);
		if (IS_ERR(dst)) {
			err = PTR_ERR(dst);
			goto err_free;
		}

		dst_cache_set_ip6(&us->dst_cache, dst, &fl6.saddr);
	}

	/* Save skb->len before xmit which consumes the SKB */
	skb_len = skb->len;

	TQUIC_UDP_TUNNEL6_XMIT_SKB(dst, sk, skb,
				  NULL,		/* dev */
				  &us->local_addr.sin6.sin6_addr,
				  &us->remote_addr.sin6.sin6_addr,
				  0,			/* prio */
				  ip6_dst_hoplimit(dst),
				  0,			/* label */
				  us->local_port,
				  us->remote_port,
				  !us->csum_offload);	/* nocheck */

	/* SKB is consumed after xmit -- do not access it */
	us->stats.tx_packets++;
	us->stats.tx_bytes += skb_len;

	return 0;

err_free:
	us->stats.tx_errors++;
	kfree_skb(skb);
	return err;
}
#endif

/**
 * tquic_udp_xmit - Transmit a packet
 * @us: UDP socket
 * @skb: Packet to transmit
 *
 * Returns: 0 on success, negative error on failure
 */
int tquic_udp_xmit(struct tquic_udp_sock *us, struct sk_buff *skb)
{
	int headroom;
	int ret;

	if (!us || !us->sock || !skb)
		return -EINVAL;

	if (!test_bit(TQUIC_UDSOCK_F_CONNECTED, &us->flags))
		return -ENOTCONN;

	/* Ensure sufficient headroom */
	headroom = (us->family == AF_INET) ? TQUIC_UDP_MIN_HEADROOM
					   : TQUIC_UDP6_MIN_HEADROOM;
	if (skb_headroom(skb) < headroom) {
		int err = pskb_expand_head(skb, headroom - skb_headroom(skb),
					   0, GFP_ATOMIC);
		if (err) {
			us->stats.tx_errors++;
			kfree_skb(skb);
			return err;
		}
	}

	local_bh_disable();

	if (us->family == AF_INET) {
		ret = tquic_udp_xmit_skb4(us, skb);
		local_bh_enable();
		return ret;
	}
#if IS_ENABLED(CONFIG_IPV6)
	else if (us->family == AF_INET6) {
		ret = tquic_udp_xmit_skb6(us, skb);
		local_bh_enable();
		return ret;
	}
#endif

	local_bh_enable();

	us->stats.tx_errors++;
	kfree_skb(skb);
	return -EAFNOSUPPORT;
}
EXPORT_SYMBOL_GPL(tquic_udp_xmit);

/**
 * tquic_udp_xmit_gso - Transmit with GSO
 * @us: UDP socket
 * @skb: Packet to transmit
 * @gso_size: GSO segment size
 *
 * Returns: 0 on success, negative error on failure
 */
int tquic_udp_xmit_gso(struct tquic_udp_sock *us, struct sk_buff *skb,
		       unsigned int gso_size)
{
	struct sock *sk;

	if (!us || !us->sock || !skb)
		return -EINVAL;

	if (!us->gso_enabled || skb->len <= gso_size)
		return tquic_udp_xmit(us, skb);

	sk = us->sock->sk;

	/* Set up GSO */
	skb_shinfo(skb)->gso_size = gso_size;
	skb_shinfo(skb)->gso_type = SKB_GSO_UDP_TUNNEL;
	skb_shinfo(skb)->gso_segs = DIV_ROUND_UP(skb->len, gso_size);

	us->stats.gso_segments += skb_shinfo(skb)->gso_segs;

	return tquic_udp_xmit(us, skb);
}
EXPORT_SYMBOL_GPL(tquic_udp_xmit_gso);

/**
 * tquic_udp_sendmsg - Send data using kernel_sendmsg
 * @us: UDP socket
 * @data: Data to send
 * @len: Length of data
 *
 * This is an alternative to xmit_skb for simpler send operations.
 *
 * Returns: Bytes sent on success, negative error on failure
 */
int tquic_udp_sendmsg(struct tquic_udp_sock *us, const void *data, size_t len)
{
	struct msghdr msg = {};
	struct kvec iov;
	int ret;

	if (!us || !us->sock)
		return -EINVAL;

	if (!test_bit(TQUIC_UDSOCK_F_CONNECTED, &us->flags))
		return -ENOTCONN;

	iov.iov_base = (void *)data;
	iov.iov_len = len;

	ret = kernel_sendmsg(us->sock, &msg, &iov, 1, len);
	if (ret > 0) {
		us->stats.tx_packets++;
		us->stats.tx_bytes += ret;
	} else {
		us->stats.tx_errors++;
	}

	return ret;
}
EXPORT_SYMBOL_GPL(tquic_udp_sendmsg);

/*
 * Checksum offload support
 */

/**
 * tquic_udp_set_csum_offload - Enable/disable checksum offload
 * @us: UDP socket
 * @enable: Enable or disable
 *
 * Returns: 0 on success
 */
int tquic_udp_set_csum_offload(struct tquic_udp_sock *us, bool enable)
{
	struct sock *sk;

	if (!us || !us->sock)
		return -EINVAL;

	sk = us->sock->sk;
	us->csum_offload = enable;

	if (us->family == AF_INET) {
		sk->sk_no_check_tx = !enable;
	}
#if IS_ENABLED(CONFIG_IPV6)
	else if (us->family == AF_INET6) {
		udp_set_no_check6_tx(sk, !enable);
		udp_set_no_check6_rx(sk, !enable);
	}
#endif

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_udp_set_csum_offload);

/*
 * Per-path UDP socket management for WAN bonding
 */

/**
 * tquic_udp_create_path_socket - Create UDP socket for a path
 * @conn: TQUIC connection
 * @path: Path to create socket for
 *
 * Returns: 0 on success, negative error on failure
 */
int tquic_udp_create_path_socket(struct tquic_connection *conn,
				 struct tquic_path *path)
{
	struct tquic_udp_sock *us;
	struct net *net = sock_net(conn->sk);
	int err;

	if (!conn || !path)
		return -EINVAL;

	us = tquic_udp_sock_alloc();
	if (!us)
		return -ENOMEM;

	us->conn = conn;
	us->path = path;

	/* Create socket based on address family */
	if (path->local_addr.ss_family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *)&path->local_addr;

		err = tquic_udp_sock_create4(net, &sin->sin_addr,
					     sin->sin_port, us);
	}
#if IS_ENABLED(CONFIG_IPV6)
	else if (path->local_addr.ss_family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&path->local_addr;

		err = tquic_udp_sock_create6(net, &sin6->sin6_addr,
					     sin6->sin6_port, us);
	}
#endif
	else {
		err = -EAFNOSUPPORT;
	}

	if (err) {
		kfree(us);
		return err;
	}

	/* Connect to remote */
	err = tquic_udp_connect(us, &path->remote_addr);
	if (err) {
		tquic_udp_sock_put(us);
		return err;
	}

	/* Add to hash table */
	tquic_udp_sock_hash_add(us);

	/* Store in path structure
	 * Note: The path->cong field is used here; ideally we'd add
	 * a dedicated udp_sock field to tquic_path structure
	 */
	path->cong = us;

	tquic_dbg("udp:created socket for path %u (port %u)\n",
		 path->path_id, ntohs(us->local_port));

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_udp_create_path_socket);

/**
 * tquic_udp_destroy_path_socket - Destroy UDP socket for a path
 * @path: Path to destroy socket for
 */
void tquic_udp_destroy_path_socket(struct tquic_path *path)
{
	struct tquic_udp_sock *us;

	if (!path)
		return;

	us = path->cong;
	if (us) {
		path->cong = NULL;
		tquic_udp_sock_put(us);
	}
}
EXPORT_SYMBOL_GPL(tquic_udp_destroy_path_socket);

/**
 * tquic_udp_xmit_on_path - Transmit packet on specific path
 * @conn: TQUIC connection
 * @path: Path to transmit on
 * @skb: Packet to transmit
 *
 * Returns: 0 on success, negative error on failure
 */
int tquic_udp_xmit_on_path(struct tquic_connection *conn,
			   struct tquic_path *path,
			   struct sk_buff *skb)
{
	struct tquic_udp_sock *us;
	int err;

	if (!conn || !path || !skb)
		return -EINVAL;

	us = path->cong;
	if (!us) {
		/* Create socket on demand */
		err = tquic_udp_create_path_socket(conn, path);
		if (err) {
			kfree_skb(skb);
			return err;
		}
		us = path->cong;
	}

	/* Update path statistics */
	path->stats.tx_packets++;
	path->stats.tx_bytes += skb->len;
	path->last_activity = ktime_get();

	/* Update connection statistics */
	conn->stats.tx_packets++;
	conn->stats.tx_bytes += skb->len;

	return tquic_udp_xmit(us, skb);
}
EXPORT_SYMBOL_GPL(tquic_udp_xmit_on_path);

int tquic_udp_encap_init(struct tquic_sock *tsk)
{
	struct tquic_connection *conn;
	struct tquic_path *path;
	int err;

	if (!tsk)
		return -EINVAL;

	conn = tsk->conn;
	if (!conn || !conn->active_path)
		return -EINVAL;

	path = conn->active_path;

	/* Seed local address from bound socket if path hasn't been set yet. */
	if (path->local_addr.ss_family == 0 &&
	    tsk->bind_addr.ss_family != 0)
		path->local_addr = tsk->bind_addr;

	/* Seed remote address from connect info if not yet set. */
	if (path->remote_addr.ss_family == 0 &&
	    tsk->connect_addr.ss_family != 0)
		path->remote_addr = tsk->connect_addr;

	/* Create per-path UDP socket if missing. */
	if (!path->cong) {
		err = tquic_udp_create_path_socket(conn, path);
		if (err)
			return err;
	}

	/*
	 * Expose the underlying socket for legacy paths that expect
	 * tsk->udp_sock to be populated.
	 */
	if (!tsk->udp_sock && path->cong)
		tsk->udp_sock = ((struct tquic_udp_sock *)path->cong)->sock;

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_udp_encap_init);

int tquic_udp_send(struct tquic_sock *tsk, struct sk_buff *skb,
		   struct tquic_path *path)
{
	struct tquic_connection *conn;

	if (!tsk || !skb) {
		kfree_skb(skb);
		return -EINVAL;
	}

	conn = tsk->conn;
	if (!conn) {
		kfree_skb(skb);
		return -EINVAL;
	}

	if (!path)
		path = conn->active_path;
	if (!path) {
		kfree_skb(skb);
		return -EINVAL;
	}

	return tquic_udp_xmit_on_path(conn, path, skb);
}
EXPORT_SYMBOL_GPL(tquic_udp_send);

/*
 * Integration with inet_connection_sock
 */

/**
 * tquic_udp_icsk_bind - Bind TQUIC socket via UDP
 * @sk: Socket to bind
 * @uaddr: Address to bind to
 * @addr_len: Address length
 *
 * Returns: 0 on success, negative error on failure
 */
int tquic_udp_icsk_bind(struct sock *sk, struct sockaddr *uaddr, int addr_len)
{
	struct tquic_sock *tsk = tquic_sk(sk);
	struct tquic_udp_sock *us;
	struct net *net = sock_net(sk);
	int err;

	if (addr_len < sizeof(struct sockaddr_in))
		return -EINVAL;

	us = tquic_udp_sock_alloc();
	if (!us)
		return -ENOMEM;

	us->conn = tsk->conn;

	if (uaddr->sa_family == AF_INET) {
		struct sockaddr_in *sin = (struct sockaddr_in *)uaddr;

		err = tquic_udp_sock_create4(net, &sin->sin_addr,
					     sin->sin_port, us);
		if (err) {
			kfree(us);
			return err;
		}

		/* Copy to socket structure */
		inet_sk(sk)->inet_saddr = sin->sin_addr.s_addr;
		inet_sk(sk)->inet_sport = us->local_port;
	}
#if IS_ENABLED(CONFIG_IPV6)
	else if (uaddr->sa_family == AF_INET6) {
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)uaddr;

		err = tquic_udp_sock_create6(net, &sin6->sin6_addr,
					     sin6->sin6_port, us);
		if (err) {
			kfree(us);
			return err;
		}

		sk->sk_v6_rcv_saddr = sin6->sin6_addr;
		inet_sk(sk)->inet_sport = us->local_port;
	}
#endif
	else {
		kfree(us);
		return -EAFNOSUPPORT;
	}

	set_bit(TQUIC_UDSOCK_F_LISTENING, &us->flags);

	/* Store in connection for later use */
	tquic_udp_sock_hash_add(us);

	/* Copy bind address */
	memcpy(&tsk->bind_addr, uaddr, addr_len);

	tquic_dbg("udp:bound to port %u\n", ntohs(us->local_port));

	return 0;
}
EXPORT_SYMBOL_GPL(tquic_udp_icsk_bind);

/*
 * Module initialization
 */

/**
 * tquic_udp_init - Initialize UDP tunnel subsystem
 *
 * Returns: 0 on success, negative error on failure
 */
int __init tquic_udp_init(void)
{
	int i;

	hash_init(tquic_udp_sock_hash);
	bitmap_zero(port_alloc.bitmap, TQUIC_PORT_MAX - TQUIC_PORT_MIN + 1);

	/* Initialize listener hash table */
	for (i = 0; i < ARRAY_SIZE(tquic_listeners); i++)
		INIT_HLIST_HEAD(&tquic_listeners[i]);

	tquic_info("udp:UDP tunnel subsystem initialized\n");
	return 0;
}

/**
 * tquic_udp_exit - Cleanup UDP tunnel subsystem
 */
void __exit tquic_udp_exit(void)
{
	struct tquic_udp_sock *us;
	struct hlist_node *tmp;
	int bkt;

	/* Release all sockets */
	spin_lock_bh(&tquic_udp_hash_lock);
	hash_for_each_safe(tquic_udp_sock_hash, bkt, tmp, us, hash_node) {
		hash_del(&us->hash_node);
		if (us->sock) {
			dst_cache_destroy(&us->dst_cache);
			udp_tunnel_sock_release(us->sock);
		}
		tquic_udp_free_port(us->local_port);
		kfree(us);
	}
	spin_unlock_bh(&tquic_udp_hash_lock);

	tquic_info("udp:UDP tunnel subsystem cleaned up\n");
}

MODULE_DESCRIPTION("TQUIC UDP Tunnel Integration");
MODULE_LICENSE("GPL");
