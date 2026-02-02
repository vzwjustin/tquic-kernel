.. SPDX-License-Identifier: GPL-2.0

======================
TQUIC Kernel API Guide
======================

Introduction
============

TQUIC is a high-performance QUIC protocol implementation in the Linux kernel.
This document describes the programming interfaces available to kernel modules
and userspace applications.

Overview
--------

TQUIC provides:

- Full RFC 9000/9001/9002 compliance
- HTTP/3 support (RFC 9114)
- Multipath QUIC for WAN bonding
- BPF extensibility for custom schedulers
- Comprehensive observability via tracepoints and qlog

Socket Interface
================

Creating QUIC Sockets
---------------------

QUIC sockets use the ``AF_INET``/``AF_INET6`` address family with
``SOCK_DGRAM`` socket type and ``IPPROTO_QUIC`` protocol::

    int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_QUIC);
    if (fd < 0) {
        perror("socket");
        exit(1);
    }

Socket Options
--------------

TQUIC provides numerous socket options at the ``SOL_TQUIC`` level:

Connection Configuration
~~~~~~~~~~~~~~~~~~~~~~~~

``TQUIC_SOCKOPT_ALPN``
    Set/get ALPN protocols. Example::

        const char *alpn = "h3";
        setsockopt(fd, SOL_TQUIC, TQUIC_SOCKOPT_ALPN, alpn, strlen(alpn));

``TQUIC_SOCKOPT_MAX_IDLE_TIMEOUT``
    Maximum idle timeout in milliseconds (default: 30000)::

        uint32_t timeout = 60000;
        setsockopt(fd, SOL_TQUIC, TQUIC_SOCKOPT_MAX_IDLE_TIMEOUT,
                   &timeout, sizeof(timeout));

``TQUIC_SOCKOPT_INITIAL_MAX_DATA``
    Initial connection flow control limit (default: 1MB)

``TQUIC_SOCKOPT_INITIAL_MAX_STREAM_DATA_BIDI``
    Initial stream flow control for bidirectional streams

``TQUIC_SOCKOPT_INITIAL_MAX_STREAMS_BIDI``
    Maximum concurrent bidirectional streams

Multipath Configuration
~~~~~~~~~~~~~~~~~~~~~~~

``TQUIC_SOCKOPT_MULTIPATH_ENABLE``
    Enable/disable multipath (default: disabled)::

        int enable = 1;
        setsockopt(fd, SOL_TQUIC, TQUIC_SOCKOPT_MULTIPATH_ENABLE,
                   &enable, sizeof(enable));

``TQUIC_SOCKOPT_SCHEDULER``
    Set multipath scheduler (minrtt, roundrobin, weighted, blest, ecf)::

        const char *sched = "minrtt";
        setsockopt(fd, SOL_TQUIC, TQUIC_SOCKOPT_SCHEDULER,
                   sched, strlen(sched));

``TQUIC_SOCKOPT_ADD_PATH``
    Add a new path for multipath::

        struct sockaddr_in local_addr;
        // ... fill local_addr ...
        setsockopt(fd, SOL_TQUIC, TQUIC_SOCKOPT_ADD_PATH,
                   &local_addr, sizeof(local_addr));

Congestion Control
~~~~~~~~~~~~~~~~~~

``TQUIC_SOCKOPT_CONGESTION``
    Set congestion control algorithm::

        const char *cc = "bbr";  // cubic, bbr, bbr2, bbr3, prague, copa
        setsockopt(fd, SOL_TQUIC, TQUIC_SOCKOPT_CONGESTION,
                   cc, strlen(cc));

Observability
~~~~~~~~~~~~~

``TQUIC_QLOG_ENABLE``
    Enable qlog tracing::

        struct tquic_qlog_args args = {
            .mode = TQUIC_QLOG_MODE_NETLINK,
            .event_mask = QLOG_MASK_ALL,
            .severity = TQUIC_QLOG_SEV_BASE,
        };
        setsockopt(fd, SOL_TQUIC, TQUIC_QLOG_ENABLE,
                   &args, sizeof(args));

Stream Operations
=================

Opening Streams
---------------

Streams are created implicitly when sending data::

    struct tquic_stream_info info;
    info.stream_id = 0;  // Client-initiated bidirectional
    info.flags = 0;

    setsockopt(fd, SOL_TQUIC, TQUIC_SOCKOPT_STREAM_OPEN,
               &info, sizeof(info));

Sending Data
------------

Use ``sendmsg()`` with the stream ID in ancillary data::

    struct msghdr msg = {0};
    struct iovec iov = {
        .iov_base = data,
        .iov_len = len,
    };
    char cmsg_buf[CMSG_SPACE(sizeof(uint64_t))];
    struct cmsghdr *cmsg;

    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf;
    msg.msg_controllen = sizeof(cmsg_buf);

    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_TQUIC;
    cmsg->cmsg_type = TQUIC_STREAM_ID;
    cmsg->cmsg_len = CMSG_LEN(sizeof(uint64_t));
    *(uint64_t *)CMSG_DATA(cmsg) = stream_id;

    sendmsg(fd, &msg, 0);

Receiving Data
--------------

Use ``recvmsg()`` to receive data with stream metadata::

    struct msghdr msg = {0};
    struct iovec iov = {
        .iov_base = buffer,
        .iov_len = sizeof(buffer),
    };
    char cmsg_buf[CMSG_SPACE(sizeof(struct tquic_stream_info))];

    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = cmsg_buf;
    msg.msg_controllen = sizeof(cmsg_buf);

    ssize_t n = recvmsg(fd, &msg, 0);

    for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
         cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        if (cmsg->cmsg_level == SOL_TQUIC &&
            cmsg->cmsg_type == TQUIC_STREAM_INFO) {
            struct tquic_stream_info *info =
                (struct tquic_stream_info *)CMSG_DATA(cmsg);
            printf("Stream %llu: %zd bytes\n", info->stream_id, n);
        }
    }

BPF Scheduler Interface
=======================

TQUIC supports custom multipath schedulers via BPF struct_ops.

Scheduler Structure
-------------------

::

    struct tquic_scheduler_ops {
        char name[16];

        /* Initialize scheduler state */
        int (*init)(struct tquic_scheduler *sched);

        /* Release scheduler resources */
        void (*release)(struct tquic_scheduler *sched);

        /* Select path for next packet */
        struct tquic_path *(*select_path)(struct tquic_scheduler *sched,
                                          struct tquic_sched_ctx *ctx);

        /* Callbacks for events */
        void (*on_packet_sent)(struct tquic_scheduler *sched,
                               struct tquic_path *path, u32 bytes);
        void (*on_packet_acked)(struct tquic_scheduler *sched,
                                struct tquic_path *path,
                                u32 bytes, ktime_t rtt);
        void (*on_packet_lost)(struct tquic_scheduler *sched,
                               struct tquic_path *path, u32 bytes);
        void (*on_path_change)(struct tquic_scheduler *sched,
                               struct tquic_path *path,
                               enum tquic_path_event event);
    };

Example BPF Scheduler
---------------------

::

    #include <linux/bpf.h>
    #include <bpf/bpf_helpers.h>
    #include <bpf/bpf_tracing.h>

    SEC("struct_ops")
    struct tquic_path *BPF_PROG(my_select_path,
                                struct tquic_scheduler *sched,
                                struct tquic_sched_ctx *ctx)
    {
        struct tquic_path *best = NULL;
        u64 min_rtt = ~0ULL;

        /* Find path with minimum RTT */
        for_each_path(sched, path) {
            u64 rtt = bpf_tquic_path_get_srtt_us(path);
            if (rtt < min_rtt && bpf_tquic_path_can_send(path, ctx->bytes)) {
                min_rtt = rtt;
                best = path;
            }
        }

        return best;
    }

    SEC(".struct_ops")
    struct tquic_scheduler_ops my_scheduler = {
        .name = "my_minrtt",
        .select_path = (void *)my_select_path,
    };

Available BPF kfuncs
--------------------

Path Information
~~~~~~~~~~~~~~~~

- ``bpf_tquic_get_primary_path(sched)`` - Get primary path
- ``bpf_tquic_get_backup_path(sched)`` - Get backup path
- ``bpf_tquic_get_path_count(sched)`` - Get total path count
- ``bpf_tquic_get_active_path_count(sched)`` - Get active path count
- ``bpf_tquic_path_next(sched, path)`` - Iterate to next path

Path Metrics
~~~~~~~~~~~~

- ``bpf_tquic_path_is_usable(path)`` - Check if path is usable
- ``bpf_tquic_path_is_active(path)`` - Check if path is active
- ``bpf_tquic_path_get_srtt_us(path)`` - Get smoothed RTT (microseconds)
- ``bpf_tquic_path_get_min_rtt_us(path)`` - Get minimum RTT
- ``bpf_tquic_path_get_bandwidth(path)`` - Get estimated bandwidth
- ``bpf_tquic_path_get_cwnd(path)`` - Get congestion window
- ``bpf_tquic_path_get_bytes_in_flight(path)`` - Get bytes in flight
- ``bpf_tquic_path_get_loss_rate(path)`` - Get loss rate (per 10000)
- ``bpf_tquic_path_can_send(path, bytes)`` - Check if can send bytes

Observability
=============

Tracepoints
-----------

TQUIC provides comprehensive tracepoints for eBPF observability:

Connection Tracepoints
~~~~~~~~~~~~~~~~~~~~~~

- ``tquic:connection_new`` - New connection attempt
- ``tquic:connection_established`` - Connection established
- ``tquic:connection_closed`` - Connection closed

Packet Tracepoints
~~~~~~~~~~~~~~~~~~

- ``tquic:packet_sent`` - Packet transmitted
- ``tquic:packet_received`` - Packet received
- ``tquic:packet_dropped`` - Packet dropped
- ``tquic:packet_lost`` - Packet declared lost

Stream Tracepoints
~~~~~~~~~~~~~~~~~~

- ``tquic:stream_opened`` - Stream opened
- ``tquic:stream_closed`` - Stream closed
- ``tquic:stream_data`` - Stream data transfer

Congestion Control Tracepoints
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

- ``tquic:cc_state_changed`` - CC state transition
- ``tquic:cc_metrics_updated`` - CC metrics update

Multipath Tracepoints
~~~~~~~~~~~~~~~~~~~~~

- ``tquic:path_created`` - New path created
- ``tquic:path_validated`` - Path validated
- ``tquic:path_closed`` - Path closed
- ``tquic:scheduler_decision`` - Scheduler path selection
- ``tquic:migration`` - Connection migration

Example bpftrace
~~~~~~~~~~~~~~~~

::

    #!/usr/bin/env bpftrace

    tracepoint:tquic:packet_sent
    {
        @bytes[args->path_id] = sum(args->size);
        @pkts[args->path_id] = count();
    }

    tracepoint:tquic:cc_metrics_updated
    {
        printf("conn=%llu cwnd=%llu rtt=%lluus\n",
               args->conn_id, args->cwnd, args->smoothed_rtt);
    }

    END
    {
        print(@bytes);
        print(@pkts);
    }

Qlog
----

TQUIC implements qlog (draft-ietf-quic-qlog-quic-events-14) for
structured event logging.

Enabling Qlog
~~~~~~~~~~~~~

Via socket option::

    struct tquic_qlog_args args = {
        .mode = TQUIC_QLOG_MODE_NETLINK,
        .event_mask = QLOG_MASK_ALL,
        .severity = TQUIC_QLOG_SEV_BASE,
    };
    setsockopt(fd, SOL_TQUIC, TQUIC_QLOG_ENABLE, &args, sizeof(args));

Via sysctl::

    sysctl -w net.tquic.qlog_enable=1
    sysctl -w net.tquic.qlog_mask=0xffffffff

Receiving Qlog Events
~~~~~~~~~~~~~~~~~~~~~

Events are delivered via netlink multicast group ``qlog``::

    struct nl_sock *sk = nl_socket_alloc();
    genl_connect(sk);
    int family = genl_ctrl_resolve(sk, "tquic");
    nl_socket_add_membership(sk, nl_get_multicast_id(sk, "tquic", "qlog"));

    while (1) {
        nl_recvmsgs_default(sk);
        // Process events in callback
    }

Performance Tuning
==================

Sysctl Parameters
-----------------

::

    # Maximum connections per listener
    net.tquic.max_connections = 100000

    # Default congestion control
    net.tquic.default_congestion = bbr

    # Enable multipath by default
    net.tquic.multipath_default = 1

    # Enable ECN
    net.tquic.ecn_enable = 1

    # GSO/GRO offload
    net.tquic.gso_enable = 1
    net.tquic.gro_enable = 1

Zero-Copy I/O
-------------

Enable zero-copy transmission::

    int enable = 1;
    setsockopt(fd, SOL_TQUIC, TQUIC_SOCKOPT_ZEROCOPY, &enable, sizeof(enable));

    // Use MSG_ZEROCOPY flag with sendmsg()
    sendmsg(fd, &msg, MSG_ZEROCOPY);

    // Check for completion notifications
    recvmsg(fd, &msg, MSG_ERRQUEUE);

AF_XDP Integration
------------------

For highest performance, TQUIC can use AF_XDP for packet I/O::

    int enable = 1;
    setsockopt(fd, SOL_TQUIC, TQUIC_SOCKOPT_AF_XDP, &enable, sizeof(enable));

Hardware Offload
----------------

Check and enable SmartNIC offload::

    struct tquic_offload_info info;
    socklen_t len = sizeof(info);
    getsockopt(fd, SOL_TQUIC, TQUIC_SOCKOPT_OFFLOAD_INFO, &info, &len);

    if (info.caps & TQUIC_OFFLOAD_CAP_CRYPTO) {
        int caps = TQUIC_OFFLOAD_CRYPTO;
        setsockopt(fd, SOL_TQUIC, TQUIC_SOCKOPT_OFFLOAD_ENABLE,
                   &caps, sizeof(caps));
    }

Benchmarking
============

TQUIC includes built-in benchmarking tools accessible via procfs:

Running Benchmarks
------------------

::

    # Throughput benchmark (10 seconds)
    echo "throughput 10" > /proc/tquic_bench

    # Latency benchmark (1000 iterations)
    echo "latency 1000" > /proc/tquic_bench

    # Crypto benchmark
    echo "crypto 10" > /proc/tquic_bench

    # Multipath benchmark (4 paths, 10 seconds)
    echo "multipath 4 10" > /proc/tquic_bench

Viewing Results
---------------

::

    cat /proc/tquic_bench_results

Results are output in JSON format for easy parsing.

Error Codes
===========

TQUIC defines specific error codes in addition to standard errno values:

Transport Errors (RFC 9000)
---------------------------

- ``TQUIC_ERR_NO_ERROR`` (0x00) - No error
- ``TQUIC_ERR_INTERNAL_ERROR`` (0x01) - Internal error
- ``TQUIC_ERR_CONNECTION_REFUSED`` (0x02) - Connection refused
- ``TQUIC_ERR_FLOW_CONTROL_ERROR`` (0x03) - Flow control violation
- ``TQUIC_ERR_STREAM_LIMIT_ERROR`` (0x04) - Stream limit exceeded
- ``TQUIC_ERR_STREAM_STATE_ERROR`` (0x05) - Invalid stream state
- ``TQUIC_ERR_FINAL_SIZE_ERROR`` (0x06) - Final size mismatch
- ``TQUIC_ERR_FRAME_ENCODING_ERROR`` (0x07) - Frame encoding error
- ``TQUIC_ERR_TRANSPORT_PARAMETER_ERROR`` (0x08) - Invalid parameter
- ``TQUIC_ERR_PROTOCOL_VIOLATION`` (0x0a) - Protocol violation
- ``TQUIC_ERR_CRYPTO_ERROR`` (0x1xx) - TLS alert

Version History
===============

TQUIC supports:

- QUIC v1 (RFC 9000) - ``0x00000001``
- QUIC v2 (RFC 9369) - ``0x6b3343cf``
- Compatible version negotiation (RFC 9368)

See Also
========

- :doc:`tquic-sysctl` - Sysctl parameters
- :doc:`tquic-multipath` - Multipath configuration
- :doc:`tquic-security` - Security considerations

References
==========

- RFC 9000: QUIC Transport Protocol
- RFC 9001: Using TLS to Secure QUIC
- RFC 9002: QUIC Loss Detection and Congestion Control
- RFC 9114: HTTP/3
- RFC 9369: QUIC Version 2
- draft-ietf-quic-multipath: Multipath Extension for QUIC
