/* SPDX-License-Identifier: GPL-2.0 */
/*
 * TQUIC AF_XDP Integration
 *
 * Copyright (c) 2026 Linux Foundation
 *
 * This header provides AF_XDP (XDP sockets) integration for TQUIC,
 * enabling kernel-bypass packet processing for 10x+ packet rates.
 *
 * AF_XDP allows TQUIC to send and receive QUIC packets directly
 * from userspace memory regions (UMEM), bypassing the normal
 * kernel networking stack for maximum performance.
 *
 * Features:
 *   - Zero-copy packet reception via XDP redirect
 *   - Zero-copy packet transmission via XSK TX ring
 *   - UMEM management with reference counting
 *   - Copy mode fallback for compatibility
 *   - Automatic fallback to regular sockets if XDP not supported
 *
 * Usage:
 *   1. Enable via TQUIC_XDP_MODE socket option
 *   2. XDP program steers QUIC packets to AF_XDP socket
 *   3. TQUIC processes packets directly from UMEM
 */

#ifndef _NET_TQUIC_AF_XDP_H
#define _NET_TQUIC_AF_XDP_H

#include <linux/types.h>
#include <linux/if_xdp.h>
#include <linux/bpf.h>
#include <linux/netdevice.h>
#include <net/xdp_sock_drv.h>

struct tquic_connection;
struct tquic_path;
struct tquic_packet;
struct sock;

/*
 * XDP mode configuration
 */
enum tquic_xdp_mode {
	TQUIC_XDP_OFF = 0,	/* XDP disabled, use regular UDP socket */
	TQUIC_XDP_COPY,		/* XDP copy mode (driver compatibility) */
	TQUIC_XDP_ZEROCOPY,	/* XDP zero-copy mode (best performance) */
};

/*
 * UMEM frame state for reference counting
 */
enum tquic_xsk_frame_state {
	TQUIC_XSK_FRAME_FREE = 0,	/* Frame available for allocation */
	TQUIC_XSK_FRAME_FILL,		/* Frame in fill ring (RX pending) */
	TQUIC_XSK_FRAME_RX,		/* Frame received, being processed */
	TQUIC_XSK_FRAME_TX,		/* Frame queued for transmission */
	TQUIC_XSK_FRAME_COMP,		/* Frame in completion ring */
};

/*
 * Per-frame metadata for UMEM management
 */
struct tquic_xsk_frame_meta {
	atomic_t refcnt;		/* Reference count */
	enum tquic_xsk_frame_state state;
	u64 addr;			/* Frame address in UMEM */
	u32 len;			/* Actual data length */
	ktime_t timestamp;		/* Receive/send timestamp */
	struct tquic_path *path;	/* Associated path */
};

/*
 * Frame pool for efficient allocation
 */
struct tquic_xsk_frame_pool {
	struct tquic_xsk_frame_meta *frames;	/* Frame metadata array */
	u32 num_frames;				/* Total frames in pool */
	u32 frame_size;				/* Size of each frame */

	/* Free list management */
	spinlock_t lock;
	u32 *free_list;				/* Free frame indices */
	u32 free_head;				/* Head of free list */
	u32 free_tail;				/* Tail of free list */
	u32 free_count;				/* Number of free frames */

	/* Statistics */
	u64 alloc_count;
	u64 free_count_stat;
	u64 alloc_failures;
};

/*
 * XSK ring wrapper with TQUIC-specific state
 */
struct tquic_xsk_ring {
	/* Kernel XSK ring (shared with driver) */
	union {
		struct xsk_ring_prod *prod;	/* Producer ring (fill/tx) */
		struct xsk_ring_cons *cons;	/* Consumer ring (rx/comp) */
	};

	/* Ring state */
	u32 cached_prod;		/* Cached producer index */
	u32 cached_cons;		/* Cached consumer index */
	u32 size;			/* Ring size (power of 2) */
	u32 mask;			/* Ring mask (size - 1) */

	/* Statistics */
	u64 packets;			/* Packets processed */
	u64 bytes;			/* Bytes processed */
	u64 drops;			/* Dropped due to full ring */
};

/*
 * AF_XDP socket state for TQUIC
 *
 * This structure wraps the kernel XSK socket and provides
 * TQUIC-specific packet processing capabilities.
 */
struct tquic_xsk {
	/* Kernel XSK socket */
	struct socket *sock;		/* AF_XDP socket */
	struct net_device *dev;		/* Network device */
	u32 queue_id;			/* NIC queue bound to */

	/* UMEM (user memory region) */
	struct xdp_umem *umem;		/* UMEM descriptor */
	void *buffer;			/* UMEM buffer base address */
	size_t buffer_size;		/* Total UMEM size */
	u32 frame_size;			/* Size per frame */
	u32 num_frames;			/* Total frames */
	u32 headroom;			/* Headroom per frame */

	/* Ring buffers */
	struct tquic_xsk_ring fill;	/* Fill ring (provide RX buffers) */
	struct tquic_xsk_ring comp;	/* Completion ring (TX done) */
	struct tquic_xsk_ring tx;	/* TX ring (send packets) */
	struct tquic_xsk_ring rx;	/* RX ring (receive packets) */

	/* Frame pool for UMEM management */
	struct tquic_xsk_frame_pool *frame_pool;

	/* Mode configuration */
	enum tquic_xdp_mode mode;	/* Copy vs zero-copy */
	bool bound;			/* Socket bound to device */

	/* BPF program */
	struct bpf_prog *xdp_prog;	/* Loaded XDP program */
	int xdp_prog_fd;		/* Program FD for cleanup */

	/* Back-reference */
	struct tquic_connection *conn;	/* Parent connection */
	struct tquic_path *path;	/* Associated path */

	/* Batch processing state */
	u32 rx_batch_size;		/* RX batch size */
	u32 tx_batch_size;		/* TX batch size */

	/* Statistics */
	struct {
		u64 rx_packets;
		u64 rx_bytes;
		u64 rx_drops;
		u64 tx_packets;
		u64 tx_bytes;
		u64 tx_drops;
		u64 fill_empty;		/* Fill ring ran empty */
		u64 comp_full;		/* Completion ring full */
		u64 invalid_desc;	/* Invalid descriptors */
	} stats;

	/* Reference counting and lifecycle */
	refcount_t refcnt;
	struct rcu_head rcu;
};

/*
 * TQUIC packet descriptor for XSK I/O
 *
 * This structure is used to pass packets between TQUIC and XSK.
 * It provides a unified interface regardless of copy/zero-copy mode.
 */
struct tquic_xsk_packet {
	/* Packet data */
	void *data;			/* Pointer to packet data */
	u32 len;			/* Packet length */
	u64 addr;			/* UMEM address (zero-copy) */

	/* Metadata */
	ktime_t timestamp;		/* Receive timestamp */
	struct sockaddr_storage src;	/* Source address */
	struct sockaddr_storage dst;	/* Destination address */

	/* XSK state (for completion tracking) */
	struct tquic_xsk *xsk;		/* XSK this packet belongs to */
	u32 frame_idx;			/* Frame index in pool */
	bool owns_frame;		/* True if we need to free frame */
};

/*
 * XDP program context for QUIC packet steering
 *
 * This structure defines the BPF map keys used by the XDP program
 * to steer QUIC packets to the correct AF_XDP socket.
 */
struct tquic_xdp_key {
	__be32 local_ip;		/* Local IP (or 0 for any) */
	__be32 remote_ip;		/* Remote IP (or 0 for any) */
	__be16 local_port;		/* Local UDP port */
	__be16 remote_port;		/* Remote UDP port (or 0 for any) */
};

/*
 * XDP program statistics
 */
struct tquic_xdp_stats {
	u64 rx_quic_packets;		/* QUIC packets steered to XSK */
	u64 rx_other_packets;		/* Non-QUIC packets passed */
	u64 rx_invalid;			/* Invalid/malformed packets */
	u64 xsk_redirect_ok;		/* Successful XSK redirects */
	u64 xsk_redirect_fail;		/* Failed XSK redirects */
};

/*
 * Socket option value for TQUIC_XDP_MODE
 */
struct tquic_xdp_config {
	__u32 mode;			/* enum tquic_xdp_mode */
	__u32 queue_id;			/* NIC queue to bind */
	__u32 frame_size;		/* Frame size (0 = default 4096) */
	__u32 num_frames;		/* Number of frames (0 = default) */
	__u32 flags;			/* Configuration flags */
	char ifname[IFNAMSIZ];		/* Interface name */
};

/* Configuration flags */
#define TQUIC_XDP_FLAG_NEED_WAKEUP	BIT(0)	/* Use need_wakeup mechanism */
#define TQUIC_XDP_FLAG_SHARED_UMEM	BIT(1)	/* Share UMEM across paths */
#define TQUIC_XDP_FLAG_DRV_MODE		BIT(2)	/* Force driver mode (not SKB) */

/* Default values */
#define TQUIC_XSK_DEFAULT_FRAME_SIZE	4096
#define TQUIC_XSK_DEFAULT_NUM_FRAMES	4096
#define TQUIC_XSK_DEFAULT_RING_SIZE	2048
#define TQUIC_XSK_DEFAULT_BATCH_SIZE	32
#define TQUIC_XSK_MAX_BATCH_SIZE	64

/* QUIC port numbers for XDP filtering */
#define TQUIC_XDP_PORT_443		443
#define TQUIC_XDP_PORT_4433		4433
#define TQUIC_XDP_PORT_8443		8443

/* Socket option (add to SOL_TQUIC options) */
#define TQUIC_XDP_MODE		200	/* Set XDP mode */
#define SO_TQUIC_XDP_MODE	TQUIC_XDP_MODE
#define TQUIC_XDP_STATS		201	/* Get XDP statistics (read-only) */
#define SO_TQUIC_XDP_STATS	TQUIC_XDP_STATS

/*
 * XSK socket lifecycle management
 */

/**
 * tquic_xsk_create - Create and configure AF_XDP socket for TQUIC
 * @xsk: Pointer to store created XSK handle
 * @ifname: Network interface name
 * @queue_id: NIC queue to bind
 * @config: Configuration parameters (may be NULL for defaults)
 *
 * Creates an AF_XDP socket, allocates UMEM, and sets up ring buffers.
 * The socket is not bound until tquic_xsk_bind() is called.
 *
 * Return: 0 on success, negative errno on failure
 */
int tquic_xsk_create(struct tquic_xsk **xsk, const char *ifname,
		     int queue_id, const struct tquic_xdp_config *config);

/**
 * tquic_xsk_destroy - Destroy AF_XDP socket and free resources
 * @xsk: XSK handle to destroy
 *
 * Unloads XDP program, releases UMEM, and frees all resources.
 * Safe to call on NULL or already-destroyed XSK.
 */
void tquic_xsk_destroy(struct tquic_xsk *xsk);

/**
 * tquic_xsk_bind - Bind XSK to network device and queue
 * @xsk: XSK handle
 *
 * Binds the AF_XDP socket to the configured device and queue.
 * Must be called after tquic_xsk_create() and before I/O operations.
 *
 * Return: 0 on success, negative errno on failure
 */
int tquic_xsk_bind(struct tquic_xsk *xsk);

/**
 * tquic_xsk_unbind - Unbind XSK from network device
 * @xsk: XSK handle
 *
 * Unbinds the AF_XDP socket. Pending packets are dropped.
 */
void tquic_xsk_unbind(struct tquic_xsk *xsk);

/*
 * Packet I/O operations
 */

/**
 * tquic_xsk_recv - Receive packets from AF_XDP socket
 * @xsk: XSK handle
 * @pkts: Array to store received packets
 * @max_pkts: Maximum packets to receive
 *
 * Receives up to max_pkts packets from the XSK RX ring.
 * In zero-copy mode, packets reference UMEM directly.
 * Caller must call tquic_xsk_recv_complete() when done processing.
 *
 * Return: Number of packets received, or negative errno on error
 */
int tquic_xsk_recv(struct tquic_xsk *xsk, struct tquic_xsk_packet *pkts,
		   int max_pkts);

/**
 * tquic_xsk_recv_complete - Complete receive processing
 * @xsk: XSK handle
 * @pkts: Array of packets (from tquic_xsk_recv)
 * @num_pkts: Number of packets
 *
 * Releases received packet frames back to the fill ring.
 * Must be called after processing packets from tquic_xsk_recv().
 */
void tquic_xsk_recv_complete(struct tquic_xsk *xsk,
			     struct tquic_xsk_packet *pkts, int num_pkts);

/**
 * tquic_xsk_send - Send packets via AF_XDP socket
 * @xsk: XSK handle
 * @pkts: Array of packets to send
 * @num_pkts: Number of packets
 *
 * Queues packets for transmission via the XSK TX ring.
 * In zero-copy mode, packets must reference UMEM frames.
 *
 * Return: Number of packets queued, or negative errno on error
 */
int tquic_xsk_send(struct tquic_xsk *xsk, struct tquic_xsk_packet *pkts,
		   int num_pkts);

/**
 * tquic_xsk_flush_tx - Flush pending TX packets
 * @xsk: XSK handle
 *
 * Kicks the kernel to transmit queued packets.
 * Should be called after tquic_xsk_send() for optimal batching.
 *
 * Return: 0 on success, negative errno on error
 */
int tquic_xsk_flush_tx(struct tquic_xsk *xsk);

/**
 * tquic_xsk_poll_tx - Poll for TX completions
 * @xsk: XSK handle
 * @num_completions: Number of completions to process
 *
 * Processes TX completion ring and releases frames.
 *
 * Return: Number of completions processed
 */
int tquic_xsk_poll_tx(struct tquic_xsk *xsk, int num_completions);

/*
 * UMEM frame allocation
 */

/**
 * tquic_xsk_alloc_frame - Allocate a frame from UMEM
 * @xsk: XSK handle
 * @addr: Pointer to store allocated address
 *
 * Allocates a frame for transmission or internal use.
 *
 * Return: 0 on success, -ENOMEM if no frames available
 */
int tquic_xsk_alloc_frame(struct tquic_xsk *xsk, u64 *addr);

/**
 * tquic_xsk_free_frame - Free a frame back to UMEM
 * @xsk: XSK handle
 * @addr: Frame address to free
 */
void tquic_xsk_free_frame(struct tquic_xsk *xsk, u64 addr);

/**
 * tquic_xsk_get_frame_data - Get data pointer for frame
 * @xsk: XSK handle
 * @addr: Frame address
 *
 * Return: Pointer to frame data, or NULL on error
 */
void *tquic_xsk_get_frame_data(struct tquic_xsk *xsk, u64 addr);

/*
 * XDP program management
 */

/**
 * tquic_xdp_load_prog - Load XDP program for QUIC steering
 * @xsk: XSK handle
 * @ports: Array of UDP ports to intercept (NULL for defaults)
 * @num_ports: Number of ports in array
 *
 * Loads and attaches the TQUIC XDP program to the network device.
 * The program steers QUIC packets to the AF_XDP socket.
 *
 * Return: 0 on success, negative errno on failure
 */
int tquic_xdp_load_prog(struct tquic_xsk *xsk, const __be16 *ports,
			int num_ports);

/**
 * tquic_xdp_unload_prog - Unload XDP program
 * @xsk: XSK handle
 *
 * Detaches and unloads the XDP program from the network device.
 */
void tquic_xdp_unload_prog(struct tquic_xsk *xsk);

/**
 * tquic_xdp_get_stats - Get XDP program statistics
 * @xsk: XSK handle
 * @stats: Buffer for statistics
 *
 * Return: 0 on success, negative errno on failure
 */
int tquic_xdp_get_stats(struct tquic_xsk *xsk, struct tquic_xdp_stats *stats);

/*
 * TQUIC socket integration
 */

/**
 * tquic_xsk_attach - Attach XSK to TQUIC socket
 * @sk: TQUIC socket
 * @xsk: XSK handle
 *
 * Integrates the AF_XDP socket with the TQUIC socket for
 * kernel-bypass packet processing.
 *
 * Return: 0 on success, negative errno on failure
 */
int tquic_xsk_attach(struct sock *sk, struct tquic_xsk *xsk);

/**
 * tquic_xsk_detach - Detach XSK from TQUIC socket
 * @sk: TQUIC socket
 *
 * Removes AF_XDP integration and falls back to regular UDP socket.
 */
void tquic_xsk_detach(struct sock *sk);

/**
 * tquic_xsk_attach_path - Attach XSK to specific path
 * @conn: TQUIC connection
 * @path: Path to attach XSK to
 * @xsk: XSK handle
 *
 * For multipath TQUIC, allows per-path XSK configuration.
 *
 * Return: 0 on success, negative errno on failure
 */
int tquic_xsk_attach_path(struct tquic_connection *conn,
			  struct tquic_path *path,
			  struct tquic_xsk *xsk);

/**
 * tquic_xsk_detach_path - Detach XSK from path
 * @conn: TQUIC connection
 * @path: Path to detach XSK from
 */
void tquic_xsk_detach_path(struct tquic_connection *conn,
			   struct tquic_path *path);

/*
 * Socket option handlers
 */

/**
 * tquic_xsk_setsockopt - Handle TQUIC_XDP_MODE socket option
 * @sk: TQUIC socket
 * @optval: Option value (struct tquic_xdp_config)
 * @optlen: Option length
 *
 * Return: 0 on success, negative errno on failure
 */
int tquic_xsk_setsockopt(struct sock *sk, sockptr_t optval,
			 unsigned int optlen);

/**
 * tquic_xsk_getsockopt - Get XDP statistics
 * @sk: TQUIC socket
 * @optval: Buffer for statistics
 * @optlen: Buffer length
 *
 * Return: 0 on success, negative errno on failure
 */
int tquic_xsk_getsockopt(struct sock *sk, char __user *optval,
			 int __user *optlen);

/*
 * Utility functions
 */

/**
 * tquic_xsk_need_wakeup - Check if XSK needs wakeup
 * @xsk: XSK handle
 *
 * Return: true if poll() or sendmsg() needed to kick processing
 */
bool tquic_xsk_need_wakeup(struct tquic_xsk *xsk);

/**
 * tquic_xsk_wakeup - Wake up XSK for processing
 * @xsk: XSK handle
 *
 * Return: 0 on success, negative errno on failure
 */
int tquic_xsk_wakeup(struct tquic_xsk *xsk);

/**
 * tquic_xsk_fill_ring_empty - Check if fill ring is empty
 * @xsk: XSK handle
 *
 * Return: true if fill ring needs more buffers
 */
bool tquic_xsk_fill_ring_empty(struct tquic_xsk *xsk);

/**
 * tquic_xsk_fill_ring_replenish - Replenish fill ring
 * @xsk: XSK handle
 * @num_frames: Number of frames to add
 *
 * Adds frames to the fill ring for RX.
 *
 * Return: Number of frames added
 */
int tquic_xsk_fill_ring_replenish(struct tquic_xsk *xsk, int num_frames);

/**
 * tquic_xsk_supported - Check if XDP is supported on interface
 * @ifname: Network interface name
 *
 * Return: true if interface supports AF_XDP
 */
bool tquic_xsk_supported(const char *ifname);

/**
 * tquic_xsk_zerocopy_supported - Check if zero-copy is supported
 * @ifname: Network interface name
 *
 * Return: true if interface supports zero-copy AF_XDP
 */
bool tquic_xsk_zerocopy_supported(const char *ifname);

/*
 * Reference counting helpers
 */

static inline void tquic_xsk_get(struct tquic_xsk *xsk)
{
	refcount_inc(&xsk->refcnt);
}

static inline void tquic_xsk_put(struct tquic_xsk *xsk)
{
	if (refcount_dec_and_test(&xsk->refcnt))
		tquic_xsk_destroy(xsk);
}

/*
 * Module initialization
 */

int __init tquic_af_xdp_init(void);
void __exit tquic_af_xdp_exit(void);

#endif /* _NET_TQUIC_AF_XDP_H */
