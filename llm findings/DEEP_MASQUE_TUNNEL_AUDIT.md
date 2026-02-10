# EXTREME DEEP SECURITY AUDIT: MASQUE Proxy, Tunnel, and Exfiltration Prevention Subsystems

**Auditor:** Claude Opus 4.6 (Kernel Security Reviewer)
**Date:** 2026-02-09
**Scope:** MASQUE proxy (CONNECT-UDP, CONNECT-IP, QUIC-Aware Proxy), TCP-over-QUIC tunneling, Capsule protocol, HTTP Datagrams, and QUIC exfiltration mitigation
**Classification:** CRITICAL -- Multiple remotely exploitable vulnerabilities identified

---

## Executive Summary

This audit covers the highest-risk network-facing subsystems of the TQUIC kernel module. These components process untrusted data from remote clients and make outbound connections on behalf of those clients, making them prime targets for Server-Side Request Forgery (SSRF), memory corruption, privilege escalation, and resource exhaustion attacks.

**Findings by Severity:**
- CRITICAL: 5
- HIGH: 7
- MEDIUM: 6
- LOW: 4

---

## CRITICAL FINDINGS

### CRITICAL-01: Complete SSRF in CONNECT-UDP -- No Address Validation

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/masque/connect_udp.c`
**Lines:** 500-543

**Description:** The `resolve_target()` function parses the client-supplied target address but performs absolutely zero validation on the resolved IP address. A remote attacker connected via QUIC can use the CONNECT-UDP proxy to send UDP packets to any IP address reachable from the kernel, including loopback (127.0.0.1), link-local (169.254.x.x including AWS/GCP/Azure metadata at 169.254.169.254), all RFC1918 private ranges, and multicast addresses.

**Code:**
```c
static int resolve_target(struct tquic_connect_udp_tunnel *tunnel)
{
    struct tquic_connect_udp_target *target = &tunnel->target;
    struct sockaddr_in *sin;
    struct sockaddr_in6 *sin6;
    int ret;

    if (target->resolved)
        return 0;

    /* Try IPv4 first */
    sin = (struct sockaddr_in *)&target->addr;
    ret = in4_pton(target->host, strlen(target->host),
                   (u8 *)&sin->sin_addr.s_addr, -1, NULL);
    if (ret == 1) {
        sin->sin_family = AF_INET;
        sin->sin_port = htons(target->port);
        target->resolved = true;
        return 0;   /* <-- NO VALIDATION WHATSOEVER */
    }
    /* ... IPv6 path similarly unvalidated ... */
}
```

**Exploitation Scenario:**
1. Attacker establishes a QUIC connection to the proxy
2. Sends a CONNECT-UDP request with target_host="169.254.169.254" and target_port=80
3. The proxy creates a UDP socket and forwards packets to the cloud metadata service
4. Attacker can retrieve IAM credentials, instance metadata, service account tokens
5. On AWS, this yields full account compromise via IMDSv1 (UDP is unusual but the socket creation succeeds)
6. Alternatively, target_host="127.0.0.1" allows scanning and attacking any local service

**Impact:** Full SSRF -- remote attacker can reach any IP the kernel can reach, including cloud metadata endpoints, internal services, and loopback interfaces. This is a network-level compromise vector.

**Recommendation:** Add address validation after `in4_pton`/`in6_pton` succeeds. Block at minimum: `ipv4_is_loopback()`, `ipv4_is_multicast()`, `ipv4_is_lbcast()`, `ipv4_is_zeronet()`, `ipv4_is_private_10()`, `ipv4_is_private_172()`, `ipv4_is_private_192()`, link-local (169.254.0.0/16), and the IPv6 equivalents. Provide a configurable allowlist/denylist for deployment flexibility.

---

### CRITICAL-02: Hardcoded init_net Namespace Bypass in Socket Creation

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/masque/connect_udp.c`
**Line:** 459

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_tunnel.c`
**Line:** 332

**Description:** Both the CONNECT-UDP proxy and the TCP-over-QUIC tunnel create kernel sockets using the hardcoded `&init_net` network namespace instead of the namespace of the requesting process or connection. This completely defeats container network isolation.

**Code (connect_udp.c:459):**
```c
ret = sock_create_kern(&init_net, family, SOCK_DGRAM, IPPROTO_UDP, &sock);
```

**Code (tquic_tunnel.c:332):**
```c
err = sock_create_kern(&init_net, family, SOCK_STREAM, IPPROTO_TCP, &sock);
```

**Exploitation Scenario:**
1. A containerized workload uses TQUIC MASQUE proxy
2. The container has a restricted network namespace with limited connectivity
3. The TQUIC module creates sockets in `init_net` (the host namespace)
4. The container can now reach any address accessible from the host, bypassing all network namespace isolation, network policies, and firewall rules
5. In Kubernetes environments, this allows pod-to-pod communication that violates NetworkPolicy, access to the node network, and access to the Kubernetes API server

**Impact:** Complete network namespace isolation bypass. Containers can escape their network restrictions and access the host network. This is a container escape vulnerability.

**Recommendation:** Store a reference to the correct network namespace (`struct net *`) at connection establishment time (via `sock_net(sk)` from the original QUIC socket) and use that namespace for all subsequent socket creation.

---

### CRITICAL-03: Unbounded Memory Allocation from Attacker-Controlled Capsule Length

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/masque/capsule.c`
**Lines:** 241-257 (capsule_alloc) and 427-430 (parser feed)

**Description:** The capsule parser allocates memory based on the `header.length` field which is a varint decoded directly from network data. This is a `u64` value that can be up to 2^62. The `CAPSULE_MAX_PAYLOAD_SIZE` constant (65535) is defined but never checked in the allocation path. An attacker can send a capsule header with a multi-gigabyte length value, causing the kernel to attempt a massive allocation.

**Code (capsule.c:427-430, in capsule_parser_feed):**
```c
/* Header complete, allocate capsule */
parser->cur_capsule = capsule_alloc(
    parser->header.type,
    parser->header.length,  /* <-- attacker-controlled u64 */
    GFP_ATOMIC);
```

**Code (capsule.c:241-257, capsule_alloc):**
```c
struct capsule *capsule_alloc(u64 type, size_t payload_len, gfp_t gfp)
{
    struct capsule *cap;
    /* ... allocate cap ... */
    cap->type = type;
    cap->length = payload_len;

    if (payload_len > 0) {
        cap->value = kmalloc(payload_len, gfp);  /* <-- NO UPPER BOUND CHECK */
        if (!cap->value) {
```

**Exploitation Scenario:**
1. Attacker sends a capsule with type=0x00 and length=0x3FFFFFFFFFFFFFFF (max QUIC varint = ~4.6 exabytes)
2. `capsule_alloc()` calls `kmalloc(4611686018427387903, GFP_ATOMIC)`
3. With GFP_ATOMIC, this will fail immediately for huge sizes, returning ENOMEM
4. However, for sizes in the range of tens of megabytes to a few gigabytes, `kmalloc` may succeed or trigger the OOM killer
5. Repeated requests with length values around available memory can exhaust kernel memory
6. Even when allocations fail, the rapid ENOMEM returns from GFP_ATOMIC create a tight failure loop that wastes CPU

**Impact:** Remote denial-of-service via kernel memory exhaustion. Attacker can trigger OOM killer, killing arbitrary processes on the system.

**Recommendation:** Validate `parser->header.length <= CAPSULE_MAX_PAYLOAD_SIZE` immediately after header decode succeeds, before calling `capsule_alloc()`. Additionally, add the same check inside `capsule_alloc()` as defense-in-depth.

---

### CRITICAL-04: No Address Validation in CONNECT-IP Packet Injection

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/masque/connect_ip.c`
**Lines:** 1029-1071 (connect_ip_validate_ip_header) and 2047-2084 (tquic_connect_ip_inject_packet)

**Description:** The CONNECT-IP tunnel validates IP header structure (version, IHL, length) but never checks the destination or source addresses of forwarded packets. The `tquic_connect_ip_inject_packet()` function calls `netif_rx()` to inject arbitrary IP packets directly into the kernel network stack. An attacker can forge packets with any source/destination address, effectively gaining raw IP socket capability through the proxy.

**Code (connect_ip.c:2047-2084):**
```c
int tquic_connect_ip_inject_packet(struct tquic_connect_ip_tunnel *tunnel,
                                   struct sk_buff *skb)
{
    unsigned char *data;
    u8 ip_version;

    /* ... basic NULL/length checks ... */

    data = skb->data;
    ip_version = (data[0] >> 4) & 0x0f;

    skb->dev = NULL;  /* No device association */
    skb_reset_mac_header(skb);
    skb_reset_network_header(skb);

    if (ip_version == 4) {
        skb->protocol = htons(ETH_P_IP);
        ret = netif_rx(skb);  /* <-- Inject arbitrary packet into kernel */
    }
    /* ... IPv6 path similar ... */
}
```

**Code (connect_ip.c:1029-1071, connect_ip_validate_ip_header):**
```c
static int connect_ip_validate_ip_header(struct sk_buff *skb, u8 *version)
{
    /* Only checks: version, IHL >= 5, length consistency */
    /* NO check on source address, destination address */
    /* NO check on protocol field */
    /* NO check for RFC1918, loopback, multicast, link-local */
}
```

**Exploitation Scenario:**
1. Attacker establishes CONNECT-IP tunnel
2. Sends an IP packet with dst=127.0.0.1 and a TCP SYN to port 22 (SSH)
3. Packet is injected via `netif_rx()` into the kernel network stack
4. Kernel processes it as a locally-received packet, delivering to localhost services
5. Attacker can also spoof source addresses, enabling reflection attacks from the kernel
6. With `skb->dev = NULL`, the packet bypasses all netfilter INPUT rules tied to specific interfaces

**Impact:** Remote attacker gains the ability to inject arbitrary IP packets into the kernel network stack. This enables SSRF to any local service, IP spoofing for reflection/amplification attacks, and netfilter bypass.

**Recommendation:** Add source and destination address validation in `connect_ip_validate_ip_header()` or a new function called before `netif_rx()`. Block loopback, multicast, broadcast, link-local, RFC1918, and IPv4-mapped-IPv6 addresses. Set `skb->dev` to the tunnel's virtual network device so netfilter rules apply correctly.

---

### CRITICAL-05: Authentication Bypass in QUIC-Aware Proxy

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/masque/quic_proxy.c`
**Line:** 524

**Description:** The QUIC-Aware Proxy initialization sets `require_auth = false` by default, and no authentication check is performed in the connection registration path. Any client that can establish a QUIC connection can register proxied connections and use CID cooperation to route traffic through the proxy.

**Code (quic_proxy.c:524):**
```c
proxy->config.require_auth = false;
```

**Exploitation Scenario:**
1. Attacker connects to a server running the QUIC-Aware Proxy
2. Sends a QUIC_PROXY_REGISTER capsule with arbitrary target address
3. No authentication is required -- the default allows any client
4. Proxy registers the connection and begins forwarding packets
5. Combined with the lack of target address validation, this creates an open relay

**Impact:** Unauthenticated proxy access allows any network client to relay traffic through the server. This enables use as an open proxy for attacks, circumventing IP-based access controls.

**Recommendation:** Set `require_auth = true` by default. Implement mandatory authentication (PSK, certificate, or token-based) in `tquic_quic_proxy_register_conn()` before processing any registration.

---

## HIGH SEVERITY FINDINGS

### HIGH-01: Function Pointer Stored in skb->cb Without Validation

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/security/quic_exfil.c`
**Lines:** 71-75 (read), 271 (write), 1090-1094 (read), 1310 (write)

**Description:** The exfiltration protection code stores function pointers in `skb->cb` (the control buffer) and later retrieves and calls them without any validation. The `skb->cb` field is 48 bytes and is used by multiple layers of the networking stack. If any other code modifies `skb->cb` between the store and the load, the function pointer could be corrupted, leading to arbitrary code execution.

**Code (quic_exfil.c:270-271, storing):**
```c
/* Store send function in skb->cb */
*(unsigned long *)skb->cb = (unsigned long)send_fn;
```

**Code (quic_exfil.c:71-75, loading and calling):**
```c
if (skb->cb[0]) {
    void (*send_fn)(struct sk_buff *) =
        (void (*)(struct sk_buff *))
        (*(unsigned long *)skb->cb);
    send_fn(skb);  /* <-- calling unvalidated function pointer */
}
```

**Exploitation Scenario:**
1. An skb is queued for delayed transmission with a function pointer stored in `skb->cb`
2. A netfilter hook, traffic classifier, or another TQUIC subsystem processes the skb while it is queued
3. That code overwrites `skb->cb` with its own control data
4. When the timer fires, the corrupted value is cast to a function pointer and called
5. If an attacker can influence the value written to `skb->cb` (e.g., via packet header manipulation that affects classification), this becomes arbitrary code execution in kernel context

**Impact:** Potential arbitrary kernel code execution if `skb->cb` is corrupted by another networking layer. The check `if (skb->cb[0])` only verifies the first byte is non-zero, not that the pointer is valid.

**Recommendation:** Use a unique magic value alongside the function pointer to validate integrity before calling. Better yet, do not store function pointers in `skb->cb` -- instead use a dedicated hash table keyed by skb pointer or use `skb->destructor` with a wrapper. At minimum, add a bounds check that the function pointer falls within kernel text section (`__is_kernel_text()`).

---

### HIGH-02: Integer Overflow in iovec Total Length Calculation

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/masque/connect_udp.c`
**Lines:** 1029-1030

**Description:** The `tquic_connect_udp_sendv()` function sums `iov_len` values from a caller-provided iovec array into a `size_t` without checking for integer overflow. If the sum wraps around, a small buffer is allocated but large memcpy operations follow.

**Code (connect_udp.c:1028-1041):**
```c
/* Calculate total length */
for (i = 0; i < iovcnt; i++)
    total_len += iov[i].iov_len;  /* <-- can overflow on 32-bit */

if (total_len > TQUIC_CONNECT_UDP_MAX_PAYLOAD)
    return -EMSGSIZE;

/* Allocate and copy to contiguous buffer */
buf = kmalloc(total_len, GFP_KERNEL);  /* small due to overflow */
if (!buf)
    return -ENOMEM;

for (i = 0; i < iovcnt; i++) {
    memcpy(buf + offset, iov[i].iov_base, iov[i].iov_len);  /* heap overflow */
    offset += iov[i].iov_len;
}
```

**Exploitation Scenario:**
On a 32-bit kernel (or if `size_t` is 32 bits), two iov entries with `iov_len = 0x80000001` each would sum to `total_len = 0x00000002`. The EMSGSIZE check passes, 2 bytes are allocated, then two 2GB memcpy operations overwrite the heap.

**Impact:** Heap buffer overflow leading to kernel memory corruption and potential code execution. The severity depends on whether this code path is reachable from userspace on 32-bit architectures.

**Recommendation:** Use `check_add_overflow()` or manually check for overflow: `if (total_len + iov[i].iov_len < total_len) return -EOVERFLOW;` within the accumulation loop.

---

### HIGH-03: Incomplete SSRF Protection in TCP-over-QUIC Tunnel

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_tunnel.c`
**Lines:** 164-169 (IPv4), 202-206 (IPv6)

**Description:** The tunnel header parser blocks loopback, multicast, broadcast, and zeronet for IPv4, plus loopback, multicast, and link-local for IPv6. However, it fails to block RFC1918 private addresses (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16), the cloud metadata address (169.254.169.254), and IPv4-mapped IPv6 addresses (::ffff:127.0.0.1).

**Code (tquic_tunnel.c:164-169):**
```c
if (ipv4_is_loopback(addr4) ||
    ipv4_is_multicast(addr4) ||
    ipv4_is_lbcast(addr4) ||
    ipv4_is_zeronet(addr4)) {
    return -EACCES;
}
/* MISSING: ipv4_is_private_10, ipv4_is_private_172, ipv4_is_private_192 */
/* MISSING: link-local (169.254.0.0/16) including cloud metadata */
```

**Exploitation Scenario:**
1. Attacker sends a tunnel header with destination 10.0.0.5:3306 (internal MySQL)
2. The address passes all four checks (not loopback, not multicast, not broadcast, not zeronet)
3. The proxy creates a TCP connection to the internal MySQL server
4. Attacker can now interact with the database through the tunnel
5. Similarly, 169.254.169.254:80 passes all checks, allowing cloud metadata access

**Impact:** SSRF to internal RFC1918 services and cloud metadata endpoints. While less severe than CRITICAL-01 (some addresses are blocked), this still allows attacking most internal infrastructure.

**Recommendation:** Add checks for all private ranges. Use `ipv4_is_private_10()`, `ipv4_is_private_172()`, `ipv4_is_private_192()` (or the unified `ipv4_is_private()` if available in the kernel version). Add link-local check. For IPv6, add check for IPv4-mapped addresses: `ipv6_addr_v4mapped()` and then validate the embedded IPv4 address.

---

### HIGH-04: Weak CID Hash Function Enables Hash Flooding

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/masque/quic_proxy.c`
**Lines:** 145-154

**Description:** The CID hash table uses a trivially predictable hash function (`hash = hash * 31 + byte`). An attacker can compute CID values that all hash to the same bucket, degrading the hash table to a linked list and causing O(n) lookup time.

**Code (quic_proxy.c:145-154):**
```c
static inline u32 cid_hash_key(const u8 *cid, u8 len)
{
    u32 hash = 0;
    int i;

    for (i = 0; i < len; i++)
        hash = (hash * 31) + cid[i];

    return hash;
}
```

**Exploitation Scenario:**
1. Attacker registers many proxied connections with crafted CIDs that all collide in the hash table
2. Each subsequent lookup degrades to O(n) list traversal
3. With 10,000 colliding CIDs, each packet forwarding operation scans 10,000 entries
4. At high packet rates, this consumes all available CPU and causes denial of service

**Impact:** Algorithmic complexity denial-of-service. A remote attacker can make every CID lookup O(n), exhausting server CPU.

**Recommendation:** Use `jhash()` or `siphash()` with a per-proxy random key initialized at proxy creation time. SipHash is specifically designed to be resistant to hash-flooding attacks.

---

### HIGH-05: Race Condition in Idle Timer Connection Processing

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/masque/quic_proxy.c`
**Lines:** 419-424

**Description:** The idle timer callback collects connections to remove into a local list while holding `proxy->lock`, then releases the lock and processes removals outside the lock. Between the unlock and the deregistration call, another thread could concurrently access or modify the same connection.

**Code (quic_proxy.c:417-424):**
```c
spin_unlock_bh(&proxy->lock);

/* Process removals outside lock */
list_for_each_entry_safe(pconn, tmp, &to_remove, list) {
    list_del(&pconn->list);
    tquic_quic_proxy_deregister_conn(pconn, QUIC_PROXY_DEREG_TIMEOUT, 0);
    proxied_conn_put(pconn);  /* <-- pconn may already be freed by concurrent path */
}
```

**Exploitation Scenario:**
1. The idle timer fires and moves a connection to `to_remove` list
2. The lock is released
3. Concurrently, a packet arrives for that connection and is dispatched through the CID hash table
4. The packet processing thread accesses `pconn` fields
5. The idle timer thread calls `proxied_conn_put()` which may free `pconn`
6. The packet processing thread dereferences freed memory (use-after-free)

**Impact:** Use-after-free in kernel context, potentially exploitable for privilege escalation.

**Recommendation:** Hold a reference count on each connection while it is in the `to_remove` list (which appears to be partially done via `proxied_conn_put`). Ensure CID hash removal happens atomically with the list removal under the proxy lock, so no new lookups can find the connection after it is selected for removal.

---

### HIGH-06: const-Correctness Violation in Proxy Packet Decode

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/masque/quic_proxy_capsules.c`
**Line:** 686

**Description:** The packet decoder stores a pointer into the input buffer as a mutable `u8 *`, discarding the `const` qualifier. If the caller frees or reuses the input buffer, the capsule structure holds a dangling pointer. The caller may also inadvertently modify protocol data through this non-const pointer.

**Code (quic_proxy_capsules.c:686):**
```c
capsule->packet = (u8 *)(buf + offset);  /* discards const from buf */
```

**Impact:** Use-after-free if the input buffer is freed before the capsule's packet pointer is used. Data corruption if the caller modifies data through the cast-away const pointer. This is a latent bug that becomes exploitable depending on the lifetime management of the input buffer.

**Recommendation:** Either copy the packet data into a separately allocated buffer, or declare `capsule->packet` as `const u8 *` and ensure all consumers respect const correctness.

---

### HIGH-07: TPROXY Capability Check Logic Inversion

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/tquic_tunnel.c`
**Lines:** 363-383

**Description:** The TPROXY code path first attempts to set `IP_TRANSPARENT` via `setsockopt`, and only after it fails does it check `capable(CAP_NET_ADMIN)`. The logic is inverted: if the process has `CAP_NET_ADMIN` but `setsockopt` fails for another reason (e.g., kernel config), the socket is released and an error is returned. If the process does NOT have `CAP_NET_ADMIN`, the code silently falls back to non-TPROXY mode. This means an unprivileged process can request TPROXY and get a degraded-but-working tunnel, while a privileged process gets an error.

**Code (tquic_tunnel.c:363-383):**
```c
if (is_tproxy) {
    val = 1;
    err = tquic_kernel_setsockopt(sock, SOL_IP, IP_TRANSPARENT,
                                  &val, sizeof(val));
    if (err < 0) {
        if (capable(CAP_NET_ADMIN)) {
            /* Has caps but setsockopt failed -> error */
            tquic_err("IP_TRANSPARENT failed despite CAP_NET_ADMIN: %d\n", err);
            sock_release(sock);
            return err;
        }
        /* No caps -> silent fallback to non-TPROXY */
        tquic_info("IP_TRANSPARENT requires CAP_NET_ADMIN, using normal mode\n");
        tunnel->is_tproxy = false;
    }
}
```

**Impact:** Unprivileged users can request TPROXY mode and get a working (non-TPROXY) tunnel without any error, potentially bypassing intended access controls. The capability check should happen before the setsockopt attempt.

**Recommendation:** Check `capable(CAP_NET_ADMIN)` first. If the caller lacks the capability, return `-EPERM` immediately rather than silently degrading.

---

## MEDIUM SEVERITY FINDINGS

### MEDIUM-01: Request ID Truncation from u64 to int

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/masque/connect_ip.c`
**Line:** 931

**Description:** The function `tquic_connect_ip_request_address()` returns the request_id as `(int)request_id`, truncating the u64 value. For request IDs > INT_MAX, this returns a negative value that the caller will interpret as an error code.

**Code (connect_ip.c:931):**
```c
return (int)request_id;
```

**Impact:** After ~2 billion requests, the function will return negative values that callers interpret as errno codes, causing spurious failures. Request ID 0xFFFFFFFF would be truncated to -1 (EPERM), 0xFFFFFFF2 would be -14 (EFAULT), etc.

**Recommendation:** Change the return type to `s64` or return 0 for success and pass the request_id through an output pointer parameter.

---

### MEDIUM-02: Constant-Time CID Validation Leaks Length via Branch

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/security/quic_exfil.c`
**Lines:** 379-405

**Description:** The function `tquic_ct_validate_cid()` is documented as constant-time but contains a data-dependent branch on line 394 (`cid_len > expected_len ? cid_len : expected_len`). The ternary operator compiles to a conditional branch on most architectures, leaking whether the CID length matches the expected length through timing.

**Code (quic_exfil.c:394):**
```c
/* Use the larger length to ensure constant-time */
max_len = cid_len > expected_len ? cid_len : expected_len;
```

**Impact:** Timing side-channel that reveals whether a connection ID has the expected length. While CID length alone may have limited value, it degrades the security guarantee that this function claims to provide.

**Recommendation:** Use `max_len = cid_len | expected_len;` (works if lengths are small enough) or use a branchless max: `max_len = cid_len ^ ((cid_len ^ expected_len) & -(cid_len < expected_len));`.

---

### MEDIUM-03: No Flow Count Limit in HTTP Datagram Manager

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/masque/http_datagram.c`

**Description:** The HTTP Datagram manager tracks `num_flows` as a `u32` but never enforces a maximum. An attacker can create an unbounded number of flows, each consuming memory from the kmem_cache.

**Impact:** Memory exhaustion via flow allocation. Each flow consumes `sizeof(struct http_datagram_flow)` from the slab cache.

**Recommendation:** Add a configurable `max_flows` limit to the manager and reject new flow creation when the limit is reached.

---

### MEDIUM-04: Decoy Traffic Uses Easily Fingerprinted All-Zero Padding

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/security/quic_exfil.c`

**Description:** The traffic shaper generates decoy packets using QUIC PADDING frames, which are all-zero bytes. A network observer can trivially distinguish decoy traffic from real traffic by checking if the decrypted payload is all zeros, completely negating the traffic analysis protection.

**Impact:** The entire decoy traffic subsystem provides a false sense of security. An observer on the network path can identify and strip decoy packets, restoring the original traffic pattern.

**Recommendation:** Fill decoy packets with cryptographically random data, or better yet, use the same encryption layer as real packets so decoy traffic is indistinguishable at the wire level.

---

### MEDIUM-05: Missing skb->dev Assignment in Packet Injection

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/masque/connect_ip.c`
**Line:** 2064

**Description:** `tquic_connect_ip_inject_packet()` sets `skb->dev = NULL` before calling `netif_rx()`. This means the injected packet has no associated network device, which bypasses netfilter rules that match on input interface (`-i` flag in iptables). It also means conntrack cannot properly track the connection's originating interface.

**Code (connect_ip.c:2064):**
```c
skb->dev = NULL;  /* Would be set to virtual interface */
```

**Impact:** Netfilter bypass for interface-based rules. Security-critical firewall rules that filter based on input interface will not match packets injected through this path.

**Recommendation:** Set `skb->dev` to the tunnel's virtual network device (`iface->net_device` from the tunnel's interface structure).

---

### MEDIUM-06: Gaussian Random Approximation Produces Biased Distribution

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/security/quic_exfil.c`
**Lines:** 1058-1074

**Description:** The `gaussian_random()` function uses a poor approximation of the Box-Muller transform. Instead of proper Box-Muller (which requires log and trigonometric functions), it sums two uniform random values modulo 1000 and subtracts 1000. This produces a triangular distribution, not Gaussian. The `(u32)max_t(s64, 0, ...)` clamp further truncates the distribution at zero, creating a half-triangular distribution.

**Impact:** The jitter distribution is predictable and distinguishable from true Gaussian jitter. An attacker performing traffic analysis can detect the characteristic triangular distribution and partially reconstruct timing patterns.

**Recommendation:** If Gaussian jitter is required, use a proper implementation. For kernel context where floating-point is unavailable, consider using the Ziggurat method with integer arithmetic, or use a larger sum of uniform random variables for better CLT approximation (sum of 12 uniform randoms is a common choice).

---

## LOW SEVERITY FINDINGS

### LOW-01: Missing Error Check for init_net Reference

**Files:** Multiple (connect_udp.c, tquic_tunnel.c)

**Description:** The code uses `&init_net` directly without checking if it is still valid. While `init_net` is a global that exists for the kernel lifetime, this pattern makes it impossible to later add proper namespace support without auditing every callsite.

**Recommendation:** Store the network namespace reference at module load time and add a helper function that returns the appropriate namespace.

---

### LOW-02: Duplicate MODULE_DESCRIPTION in quic_exfil.c

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/security/quic_exfil.c`
**Lines:** 1684 and 1763

**Description:** The MODULE_DESCRIPTION, MODULE_LICENSE, and MODULE_AUTHOR macros are duplicated at lines 1684-1686 and 1763-1765. While not a security issue, duplicate module metadata can cause build warnings with some kernel configurations.

---

### LOW-03: Context Set Level Does Not Check init Return Values

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/security/quic_exfil.c`
**Lines:** 1457-1464

**Description:** `tquic_exfil_ctx_set_level()` destroys and reinitializes the shaper, spin randomizer, and jitter subsystems but does not check the return values of the `_init()` calls. If initialization fails, the context is left in a partially initialized state.

**Code (quic_exfil.c:1457-1464):**
```c
tquic_traffic_shaper_destroy(&ctx->shaper);
tquic_traffic_shaper_init(&ctx->shaper, level);  /* return value ignored */

tquic_spin_randomizer_destroy(&ctx->spin_rand);
tquic_spin_randomizer_init(&ctx->spin_rand, level);  /* return value ignored */
```

**Recommendation:** Check return values and either revert to the previous level or mark the context as failed.

---

### LOW-04: Workqueue Not Validated Before Use

**File:** `/Users/justinadams/Downloads/tquic-kernel/net/tquic/security/quic_exfil.c`
**Lines:** 279-281

**Description:** `tquic_timing_normalize_send()` checks `if (exfil_wq)` before queuing work, but silently drops the packet if the workqueue is NULL (not initialized or destroyed). The packet is queued to `delay_queue` but never sent.

**Impact:** If module init fails partially, packets may be silently dropped (queued but never sent, leaking memory via the skb).

**Recommendation:** If `exfil_wq` is NULL, either send the packet immediately (bypassing timing normalization) or return an error so the caller can handle it.

---

## Summary Table

| ID | Severity | Component | Issue |
|---|---|---|---|
| CRITICAL-01 | CRITICAL | connect_udp.c | Complete SSRF -- no address validation |
| CRITICAL-02 | CRITICAL | connect_udp.c, tquic_tunnel.c | Hardcoded init_net namespace bypass |
| CRITICAL-03 | CRITICAL | capsule.c | Unbounded allocation from attacker length |
| CRITICAL-04 | CRITICAL | connect_ip.c | No address validation in packet injection |
| CRITICAL-05 | CRITICAL | quic_proxy.c | Authentication bypass (require_auth=false) |
| HIGH-01 | HIGH | quic_exfil.c | Unvalidated function pointer in skb->cb |
| HIGH-02 | HIGH | connect_udp.c | Integer overflow in iovec total_len |
| HIGH-03 | HIGH | tquic_tunnel.c | Incomplete SSRF protection (missing RFC1918) |
| HIGH-04 | HIGH | quic_proxy.c | Weak hash function enables hash flooding |
| HIGH-05 | HIGH | quic_proxy.c | Race condition in idle timer processing |
| HIGH-06 | HIGH | quic_proxy_capsules.c | const-correctness violation / dangling pointer |
| HIGH-07 | HIGH | tquic_tunnel.c | TPROXY capability check logic inversion |
| MEDIUM-01 | MEDIUM | connect_ip.c | u64 to int truncation of request ID |
| MEDIUM-02 | MEDIUM | quic_exfil.c | Timing leak in "constant-time" CID validation |
| MEDIUM-03 | MEDIUM | http_datagram.c | No flow count limit (resource exhaustion) |
| MEDIUM-04 | MEDIUM | quic_exfil.c | Decoy traffic trivially fingerprinted |
| MEDIUM-05 | MEDIUM | connect_ip.c | Missing skb->dev bypasses netfilter |
| MEDIUM-06 | MEDIUM | quic_exfil.c | Biased jitter distribution |
| LOW-01 | LOW | Multiple | init_net reference pattern |
| LOW-02 | LOW | quic_exfil.c | Duplicate MODULE_DESCRIPTION |
| LOW-03 | LOW | quic_exfil.c | Unchecked init return values in set_level |
| LOW-04 | LOW | quic_exfil.c | Silent packet drop if workqueue NULL |

---

## Prioritized Remediation Order

1. **CRITICAL-01 and CRITICAL-04**: Address validation for SSRF. These are the most immediately exploitable and have the broadest impact. Implement a shared `tquic_validate_target_address()` helper used by all proxy types.

2. **CRITICAL-03**: Capsule payload size limit. Single-line fix with maximum impact on resource exhaustion attacks.

3. **CRITICAL-02**: Namespace isolation. Requires architectural change to thread the correct `struct net *` through the call chain.

4. **CRITICAL-05**: Authentication default. Change default to `require_auth = true`.

5. **HIGH-01**: Function pointer validation in skb->cb. Replace with a safer pattern.

6. **HIGH-03**: Complete the SSRF protection in tquic_tunnel.c with RFC1918 checks.

7. **HIGH-04**: Replace hash function with SipHash.

8. **HIGH-02, HIGH-05, HIGH-06, HIGH-07**: Fix remaining high severity issues.

9. **MEDIUM and LOW**: Address in subsequent passes.

---

*End of audit report. All file paths are absolute. All line numbers verified against source as of 2026-02-09.*
