.. SPDX-License-Identifier: GPL-2.0

==========================================
TQUIC - Multipath QUIC WAN Bonding
==========================================

Overview
========

TQUIC is a Linux kernel implementation of multipath QUIC designed for WAN
bandwidth aggregation. It allows home routers and enterprise gateways to
bond multiple internet connections (fiber, cable, 4G, 5G) into a single
high-throughput, resilient pipe.

TQUIC operates at the transport layer, implementing the QUIC protocol
(RFC 9000) with multipath extensions from the IETF draft-ietf-quic-multipath.
Unlike userspace solutions, TQUIC runs in the kernel data path, achieving
near-line-rate forwarding with zero-copy packet handling.

Architecture
============

TQUIC follows a client-server model::

    Home Router (Client)          VPS Aggregation Endpoint (Server)
    ┌──────────────────┐          ┌─────────────────────────────┐
    │  Application     │          │  tquicd daemon              │
    │  (TCP/UDP)       │          │  - Config management        │
    │       ↕          │          │  - Prometheus metrics       │
    │  TQUIC kernel    │═══WAN1══▶│  - Web dashboard            │
    │  module          │═══WAN2══▶│                             │
    │  - Bonding       │═══WAN3══▶│  TQUIC kernel module        │
    │  - Scheduling    │          │  - Multi-tenant server      │
    │  - CC per-path   │          │  - TCP tunnel termination   │
    │  - Path manager  │          │  - QoS classification       │
    └──────────────────┘          └─────────────────────────────┘

The TQUIC kernel module (``tquic.ko``) implements:

- **Protocol core**: QUIC framing, handshake (via net/handshake TLS 1.3),
  stream multiplexing, and flow control per RFC 9000/9001/9002.
- **Path manager**: Automatic discovery of WAN interfaces using FIB lookup,
  or manual configuration via userspace daemon.
- **Scheduler framework**: Pluggable packet scheduling (minrtt, aggregate,
  weighted, BLEST, ECF) with runtime selection.
- **Congestion control**: Per-path CC (Cubic, BBR) with optional coupled
  CC coordination (OLIA/BALIA) for shared bottleneck fairness.
- **Bonding core**: Bandwidth aggregation with adaptive reorder buffer
  (handles up to 600ms latency spread), seamless failover.

Kernel Configuration
====================

Enable TQUIC in menuconfig under::

    Networking support →
      Networking options →
        [M] TQUIC multipath QUIC protocol (CONFIG_TQUIC)
          [*] TQUIC IPv6 support (CONFIG_TQUIC_IPV6)
          [*] TQUIC multipath extension (CONFIG_TQUIC_MULTIPATH)
          [*] TQUIC WAN bonding core (CONFIG_TQUIC_WAN_BONDING)
          [*] TQUIC netfilter integration (CONFIG_TQUIC_NETFILTER)
          <M> TQUIC Cubic congestion control (CONFIG_TQUIC_CONG_CUBIC)
          <M> TQUIC BBR congestion control (CONFIG_TQUIC_CONG_BBR)

Build the module::

    make M=net/tquic
    make M=net/tquic W=1   # With extra warnings

Load the module::

    modprobe tquic
    modprobe tquic_nf       # Optional: netfilter integration

Socket API
==========

TQUIC uses ``IPPROTO_TQUIC`` (263) with ``SOCK_STREAM`` sockets::

    /* Client connection */
    fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TQUIC);
    connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));

    /* Open a QUIC stream within the connection */
    stream_fd = ioctl(fd, TQUIC_NEW_STREAM, 0);
    write(stream_fd, data, len);
    read(stream_fd, buf, sizeof(buf));

    /* Server */
    srv = socket(AF_INET, SOCK_STREAM, IPPROTO_TQUIC);
    bind(srv, (struct sockaddr *)&addr, sizeof(addr));
    listen(srv, backlog);
    client = accept(srv, NULL, NULL);

See ``Documentation/networking/tquic-api.rst`` for full socket option reference.

Socket Options
--------------

.. list-table::
   :widths: 35 15 50
   :header-rows: 1

   * - Option
     - Level
     - Description
   * - ``SO_TQUIC_SCHEDULER``
     - ``SOL_TQUIC``
     - Select scheduler: "minrtt", "aggregate", "weighted", "blest", "ecf"
   * - ``SO_TQUIC_CONGESTION``
     - ``SOL_TQUIC``
     - Select CC: "cubic", "bbr", "copa", "westwood", "auto"
   * - ``TQUIC_NEW_STREAM``
     - ioctl
     - Create a new QUIC stream within the connection
   * - ``TQUIC_MIGRATE``
     - ``SOL_TQUIC``
     - Initiate connection ID migration

Path Management
===============

TQUIC supports two path management modes, selectable per-namespace via
``net.tquic.path_manager``:

Kernel PM (default)
-------------------

The kernel automatically discovers WAN interfaces by checking for default
routes via ``fib_lookup()``. When a new interface with a default route
appears, TQUIC adds it as a path and initiates PATH_CHALLENGE/PATH_RESPONSE
validation per RFC 9000 Section 8.2.

The kernel PM filters out:

- Loopback interfaces (no internet connectivity)
- Bridge ports and bonding slaves (already aggregated)
- OVS internal ports (overlay networking)
- Interfaces without a default route

Userspace PM
------------

For more control, a userspace daemon can manage paths via generic netlink::

    # Using ip-tquic tool
    ip tquic path add conn_id 12345 dev eth0 \
        local 192.168.1.1:0 remote 203.0.113.1:4433
    ip tquic path del path_id 2

The userspace PM receives netlink events for PATH_UP, PATH_DOWN, and
PATH_CHANGE, allowing custom policies for path selection.

Schedulers
==========

Select the default scheduler system-wide::

    sysctl net.tquic.scheduler=aggregate

Or per-connection::

    ip tquic scheduler set minrtt conn_id 12345

.. list-table::
   :widths: 20 80
   :header-rows: 1

   * - Scheduler
     - Description
   * - ``minrtt``
     - Sends packets on the lowest-latency path. Best for latency-sensitive
       traffic. Uses a configurable tolerance band to avoid oscillation.
   * - ``aggregate`` (default)
     - Distributes packets across all paths proportional to capacity
       (cwnd/RTT). Maximizes combined throughput for bulk transfers.
   * - ``weighted``
     - Respects user-defined path weights with a 5% minimum floor.
       Uses Deficit Round Robin (DRR) for fairness within weights.
   * - ``blest``
     - BLEST (BLocking ESTimation-based) scheduler. Avoids HOL blocking
       by estimating when slow paths would block faster ones.
   * - ``ecf``
     - Earliest Completion First. Estimates completion time per path and
       sends on whichever path delivers data first.

Congestion Control
==================

TQUIC implements per-path congestion control. Each path maintains an
independent cwnd, ssthresh, and pacing rate. Loss on one path does not
affect other paths' CWND.

Select CC per-connection::

    sysctl net.tquic.congestion=bbr
    # or
    ip tquic scheduler set aggregate conn_id 12345

BBR Auto-Selection
------------------

Setting ``SO_TQUIC_CONGESTION`` to ``"auto"`` enables automatic per-path
CC selection: paths with RTT > 100ms use BBR (better for high-latency WAN),
while LAN-like paths use Cubic.

Coupled Congestion Control
--------------------------

For multipath scenarios sharing a bottleneck (e.g., two DSL lines on the
same DSLAM), coupled CC (OLIA or BALIA) coordinates cwnd reductions across
paths to prevent excessive bandwidth consumption at shared bottlenecks.

Enable via::

    sysctl net.tquic.coupled_cc=olia   # or balia

Sysctl Parameters
=================

All parameters are per-network-namespace (container-safe)::

    /proc/sys/net/tquic/

.. list-table::
   :widths: 35 15 50
   :header-rows: 1

   * - Parameter
     - Default
     - Description
   * - ``enabled``
     - 1
     - Enable/disable TQUIC globally
   * - ``scheduler``
     - aggregate
     - Default scheduler for new connections
   * - ``congestion``
     - cubic
     - Default CC algorithm
   * - ``max_paths``
     - 8
     - Maximum paths per connection
   * - ``probe_interval``
     - 1000ms
     - Interval between path probes
   * - ``failover_timeout``
     - 3000ms
     - Time before declaring path failure (3x SRTT)
   * - ``idle_timeout``
     - 30000ms
     - Connection idle timeout
   * - ``initial_rtt``
     - 100ms
     - Initial RTT estimate before first measurement
   * - ``reorder_window``
     - 64
     - Reorder buffer window (packets)
   * - ``ecn_enabled``
     - 0
     - Enable ECN (explicit congestion notification)

Diagnostics
===========

Connection Listing (ss)
-----------------------

TQUIC integrates with the ``ss`` tool via ``inet_diag``::

    $ ss -t -A tquic
    State   Recv-Q  Send-Q  Local Address:Port  Peer Address:Port
    ESTAB   0       0       192.168.1.1:54321   203.0.113.1:4433

    $ ss -ti -A tquic
    ... (extended info: paths, RTT, scheduler, streams)

Proc Interface
--------------

::

    /proc/net/tquic/connections   # All TQUIC connections
    /proc/net/tquic/paths         # Per-path statistics
    /proc/net/tquic/stats         # Aggregate MIB counters

MIB Counters
------------

TQUIC exposes 37 MIB counters via ``/proc/net/snmp``::

    TquicHandshakesAttempted    Total handshake attempts
    TquicHandshakesCompleted    Successful handshakes
    TquicPacketsTx              Packets sent
    TquicPacketsRx              Packets received
    TquicPacketsLost            Packets declared lost
    TquicPathsAdded             Paths added
    TquicPathsRemoved           Paths removed
    TquicPathsFailed            Path failures
    TquicStreamsOpened          QUIC streams opened
    TquicBytesTx                Total bytes sent
    TquicBytesRx                Total bytes received

Management Tool (ip-tquic)
--------------------------

The ``ip-tquic`` tool provides ``ip``-compatible management::

    # Show all connections and their paths
    ip tquic show

    # Per-path statistics
    ip tquic stats

    # Live event monitoring
    ip tquic monitor

    # Scheduler management
    ip tquic scheduler get
    ip tquic scheduler set aggregate

VPS Aggregation Endpoint
========================

The server-side component consists of:

**Kernel module** (``tquic.ko``): Handles QUIC connection acceptance, TCP
tunnel termination via zero-copy splice, QoS classification, and per-client
rate limiting.

**tquicd daemon**: Userspace configuration and monitoring daemon.

Configuration (``/etc/tquic.d/*.conf``)::

    [global]
    listen_port = 443
    metrics_port = 9100       # Prometheus endpoint
    dashboard_port = 8080     # Web dashboard (localhost)
    session_ttl = 120         # Seconds to hold session on reconnect

    [client.router1]
    psk = <base64-encoded-pre-shared-key>
    port_range = 10000-10999   # NAT port range for this client
    bandwidth_limit = 500mbit

Deploy on Ubuntu/Debian::

    sudo apt install tquicd    # Installs module + daemon
    # postinst automatically:
    # - Loads tquic.ko
    # - Configures kernel parameters
    # - Sets up nftables TPROXY rules
    # - Starts tquicd.service

Security Considerations
=======================

- All TQUIC connections use TLS 1.3 (RFC 9001). No plaintext connections.
- Path validation (PATH_CHALLENGE/RESPONSE) prevents source address spoofing.
- Connection ID rotation limits linkability between paths.
- The VPS endpoint uses PSK authentication; rotate keys regularly.
- TQUIC respects network namespace isolation for multi-tenant deployments.
- The ``tquic_nf`` module integrates with netfilter for stateful firewalling.

RFC Compliance
==============

TQUIC implements:

- **RFC 9000**: QUIC Transport Protocol
- **RFC 9001**: Using TLS to Secure QUIC
- **RFC 9002**: QUIC Loss Detection and Congestion Control
- **RFC 9114**: HTTP/3 (optional, ``CONFIG_TQUIC_HTTP3``)
- **RFC 9221**: QUIC Datagram Extension
- **draft-ietf-quic-multipath**: Multipath QUIC Extension

References
==========

- :doc:`tquic-api` - Kernel programming API reference
- ``net/tquic/`` - Kernel source code
- ``tools/tquic/`` - Userspace tools (ip-tquic, tquicd)
- https://datatracker.ietf.org/doc/draft-ietf-quic-multipath/
