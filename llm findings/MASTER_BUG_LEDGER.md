# Master Bug Ledger (Consolidated)

## Inputs
- REPORT_A_JSON (Codex): 136 FindingCards
- REPORT_B_JSON (Opus/Claude): 671 FindingCards
- REPORT_C_JSON (Gemini): 437 FindingCards

Total consolidated findings: **645**

## A) Prioritized List

| Rank | CID | Priority | Severity | Confidence | Sources | Title |
|---:|---|---:|---|---|---|---|
| 1 | CF-001 | 10.00 | S0 | high | A,B,C | Adaptive Scheduler cwnd_avail Underflow |
| 2 | CF-002 | 10.00 | S0 | high | A,B,C | Buffer Overflow in ClientHello Extension Building |
| 3 | CF-003 | 10.00 | S0 | high | A,B,C | Client Certificate Verification Uses Server Logic |
| 4 | CF-004 | 10.00 | S0 | high | A,B,C | Connection Destroy Calls Sleeping Function Under Spinlock |
| 5 | CF-005 | 10.00 | S0 | high | A,B,C | Fragile Hardcoded Offset for Key Update State Access |
| 6 | CF-006 | 10.00 | S0 | high | A,B,C | HTTP/3 Stream Lookup: Use-After-Free |
| 7 | CF-007 | 10.00 | S0 | high | A,B,C | OCSP Stapling Response Accepted Without Any Verification |
| 8 | CF-008 | 10.00 | S0 | high | A,B,C | Path Metrics Netlink: Unbounded Allocation from Attacker-Influenced Value |
| 9 | CF-009 | 10.00 | S0 | high | A,B,C | QPACK Dynamic Table Duplicate: Use-After-Free via Lock Drop |
| 10 | CF-010 | 10.00 | S0 | high | A,B,C | Self-Signed Certificate Comparison Uses Non-Constant-Time memcmp in One Path |
| 11 | CF-011 | 10.00 | S0 | high | A,B,C | Stack Buffer Overflow in HKDF-Expand-Label |
| 12 | CF-012 | 10.00 | S0 | high | A,B,C | Stream Data Queued Before Validation Check |
| 13 | CF-013 | 10.00 | S0 | high | B,C | `tquic_close()` Does Not Hold `lock_sock()` During Connection Teardown |
| 14 | CF-014 | 10.00 | S0 | high | B,C | `tquic_hs_process_certificate` -- integer underflow in `certs_len` tracking |
| 15 | CF-015 | 10.00 | S0 | high | B,C | `tquic_hs_process_new_session_ticket` -- nonce overflow into session ticket |
| 16 | CF-016 | 10.00 | S0 | high | B,C | `tquic_hs_process_server_hello` -- missing bounds check before compression byte read |
| 17 | CF-017 | 10.00 | S0 | high | B,C | `tquic_shutdown()` Missing `lock_sock()` -- Race on Connection State |
| 18 | CF-018 | 10.00 | S0 | high | B,C | `tquic_varint_len()` Returns 0 for Invalid Values Without Error Propagation |
| 19 | CF-019 | 10.00 | S0 | high | B,C | Adaptive Feedback Uses Path After list_for_each_entry Exit |
| 20 | CF-020 | 10.00 | S0 | high | B,C | ASN.1 Time Parsing Does Not Validate Character Ranges |
| 21 | CF-021 | 10.00 | S0 | high | B,C | Authentication Bypass in QUIC-Aware Proxy |
| 22 | CF-022 | 10.00 | S0 | high | B,C | BLEST Inconsistent Locking -- 3 of 6 Callbacks Lack Lock |
| 23 | CF-023 | 10.00 | S0 | high | A,B | Busy-poll per-packet lock/unlock |
| 24 | CF-024 | 10.00 | S0 | high | B,C | Capsule Buffer Size Addition Overflow |
| 25 | CF-025 | 10.00 | S0 | high | B,C | Complete SSRF in CONNECT-UDP -- No Address Validation |
| 26 | CF-026 | 10.00 | S0 | high | B,C | ECF Scheduler Declares Lock But Never Uses It |
| 27 | CF-027 | 10.00 | S0 | high | B,C | ECN CE Count Processing Does Not Track Deltas |
| 28 | CF-028 | 10.00 | S0 | high | B,C | GSO Segment Accumulation Can Overflow SKB Tailroom |
| 29 | CF-029 | 10.00 | S0 | high | B,C | GSO SKB Allocation Multiplication Overflow |
| 30 | CF-030 | 10.00 | S0 | high | B,C | Handshake Packet Parsing with Unvalidated Offsets |
| 31 | CF-031 | 10.00 | S0 | high | B,C | Hard-Fail Revocation Mode Does Not Actually Fail |
| 32 | CF-032 | 10.00 | S0 | high | B,C | Hardcoded init_net Namespace Bypass in Socket Creation |
| 33 | CF-033 | 10.00 | S0 | high | B,C | Install Secrets Accesses State Without Lock After Unlock |
| 34 | CF-034 | 10.00 | S0 | high | B,C | Integer overflow in `tquic_hs_build_ch_extensions` PSK identity length calculations |
| 35 | CF-035 | 10.00 | S0 | high | B,C | Load Balancer Plaintext Mode Exposes Server ID |
| 36 | CF-036 | 10.00 | S0 | high | B,C | Missing RFC 1918 / Private Network Filtering in IPv4 SSRF Checks |
| 37 | CF-037 | 10.00 | S0 | high | B,C | Missing SKB Tailroom Check in Coalesced Packet Output |
| 38 | CF-038 | 10.00 | S0 | high | B,C | Nested Lock Hierarchy Violation in Timer Code |
| 39 | CF-039 | 10.00 | S0 | high | B,C | Netfilter Hooks Registered Only in init_net |
| 40 | CF-040 | 10.00 | S0 | high | B,C | No Address Validation in CONNECT-IP Packet Injection |
| 41 | CF-041 | 10.00 | S0 | high | B,C | No Privilege Check for TQUIC Socket Creation |
| 42 | CF-042 | 10.00 | S0 | high | B,C | No Privilege Checks for Security-Sensitive Socket Options |
| 43 | CF-043 | 10.00 | S0 | high | B,C | No security_socket_* Hook Invocations |
| 44 | CF-044 | 10.00 | S0 | high | B,C | PADDING Frame Infinite Skip Without Bound on Encrypted Payload |
| 45 | CF-045 | 10.00 | S0 | high | B,C | Path Pointer Use After Lock Release |
| 46 | CF-046 | 10.00 | S0 | high | A,B | Per-frame kzalloc + kmalloc in TX path |
| 47 | CF-047 | 10.00 | S0 | high | B,C | Per-Packet crypto_aead_setkey on Shared AEAD Handle -- Race Condition |
| 48 | CF-048 | 10.00 | S0 | high | B,C | Priority PRIORITY_UPDATE Parsing Off-by-Two in Loop Bound |
| 49 | CF-049 | 10.00 | S0 | high | B,C | QPACK Decoder Stack Buffer Overflow via Large Headers |
| 50 | CF-050 | 10.00 | S0 | high | B,C | quic_packet.c Stream Frame - Uncapped Stream Creation |
| 51 | CF-051 | 10.00 | S0 | high | B,C | Race Condition Between `tquic_destroy_sock()` and Poll/Sendmsg/Recvmsg |
| 52 | CF-052 | 10.00 | S0 | high | B,C | Retry Token Address Validation Uses Non-Constant-Time Comparison |
| 53 | CF-053 | 10.00 | S0 | high | B,C | Retry Token Validation -- Plaintext Buffer Overread |
| 54 | CF-054 | 10.00 | S0 | high | B,C | Server Accept CID Parsing Missing Bounds Checks -- Buffer Over-Read |
| 55 | CF-055 | 10.00 | S0 | high | B,C | Slab Cache Decryption Buffer May Be Too Small for Payload |
| 56 | CF-056 | 10.00 | S0 | high | B,C | Sleep-in-Atomic Context |
| 57 | CF-057 | 10.00 | S0 | high | B,C | SSRF via IPv4-Mapped IPv6 Addresses Bypasses Address Filtering |
| 58 | CF-058 | 10.00 | S0 | high | B,C | Stack buffer overflow in `tquic_hs_hkdf_expand_label` -- unbounded label/context write to 512-byte stack buffer |
| 59 | CF-059 | 10.00 | S0 | high | B,C | Stateless Reset Bypasses State Machine |
| 60 | CF-060 | 10.00 | S0 | high | B,C | Stream Data Delivery Uses u64 Length with u32 alloc_skb |
| 61 | CF-061 | 10.00 | S0 | high | B,C | tquic_conn_server_accept() -- err_free leaks registered CIDs, work items, timers, crypto state |
| 62 | CF-062 | 10.00 | S0 | high | B,C | tquic_conn_server_accept() -- overrides actual error code with -EINVAL |
| 63 | CF-063 | 10.00 | S0 | high | B,C | tquic_send_connection_close() -- SKB leak and unencrypted packet on header failure |
| 64 | CF-064 | 10.00 | S0 | high | B,C | tquic_stream_sendmsg Writes to Stream Without Connection Refcount on Stream |
| 65 | CF-065 | 10.00 | S0 | high | B,C | Transcript Buffer Reallocation Doubling Overflow |
| 66 | CF-066 | 10.00 | S0 | high | B,C | Tunnel Uses init_net -- Namespace Escape |
| 67 | CF-067 | 10.00 | S0 | high | B,C | Unbounded Memory Allocation from Attacker-Controlled Capsule Length |
| 68 | CF-068 | 10.00 | S0 | high | A,B | Use-After-Free in Path Lookup |
| 69 | CF-069 | 10.00 | S0 | high | B,C | Version Negotiation Packet Overflow -- Unsanitized CID Lengths in tquic_send_version_negotiation |
| 70 | CF-070 | 10.00 | S0 | high | B,C | WebTransport Close Capsule Large Stack Allocation |
| 71 | CF-071 | 10.00 | S0 | high | B | AF_XDP Socket and Device Lookup Use init_net |
| 72 | CF-072 | 10.00 | S0 | high | B | conn->sk Accessed Without Lock After Stateless Reset |
| 73 | CF-073 | 10.00 | S0 | high | B | Integer Overflow in bytes_acked Calculation |
| 74 | CF-074 | 10.00 | S0 | high | B | Missing Lock in `tquic_sock_bind()` -- Race with `tquic_connect()` |
| 75 | CF-075 | 10.00 | S0 | high | B | Missing Upper Bound on Coalesced Packet Count |
| 76 | CF-076 | 10.00 | S0 | high | B | Packet Number Length Extracted Before Header Unprotection |
| 77 | CF-077 | 10.00 | S0 | high | B | QUIC-over-TCP Client and Server Sockets Use init_net |
| 78 | CF-078 | 10.00 | S0 | high | B | Refcount Underflow in Netlink Path Creation |
| 79 | CF-079 | 10.00 | S0 | high | B | Stale skb->len Read After ip_local_out |
| 80 | CF-080 | 10.00 | S0 | high | B | State Machine Type Confusion via `conn->state_machine` Void Pointer |
| 81 | CF-081 | 10.00 | S0 | high | B | Stream Lookup Returns Pointer Without Refcount -- Use-After-Free |
| 82 | CF-082 | 10.00 | S0 | high | B | TOCTOU Race in Failover Hysteresis |
| 83 | CF-083 | 10.00 | S0 | high | B | TQUIC_NEW_STREAM Missing Reserved Field Zeroing Check |
| 84 | CF-084 | 10.00 | S0 | high | B | UAF-P1-01: - SmartNIC tquic_nic_find() returns pointer without reference |
| 85 | CF-085 | 10.00 | S0 | high | B | Use-After-Free in Connect |
| 86 | CF-086 | 10.00 | S0 | high | B | Wrong Network Namespace in ip_local_out |
| 87 | CF-087 | 7.00 | S0 | medium | C | (actual): `tquic_hs_process_server_hello` -- missing check before cipher suite read |
| 88 | CF-088 | 7.00 | S0 | medium | C | (Revised): tquic_process_packet Does Not Validate pkt_num_len Against Remaining Data (tquic_input.c, lines 2528-2529, 2572-2574) |
| 89 | CF-089 | 7.00 | S0 | medium | B | ACK Range Failover Can Iterate Over Unbounded Packet Number Range |
| 90 | CF-090 | 7.00 | S0 | medium | C | AF_XDP Socket and Device Lookup Use init_net (Container Escape) |
| 91 | CF-091 | 7.00 | S0 | medium | B | Attacker-Controlled Allocation Sizes |
| 92 | CF-092 | 7.00 | S0 | medium | A | CID demux/lookup appears non-functional: the RX path uses one table, while connection creation populates different tables |
| 93 | CF-093 | 7.00 | S0 | medium | C | Client Certificate Verification Uses Server Logic (EKU Bypass) |
| 94 | CF-094 | 7.00 | S0 | medium | C | conn->sk Accessed Without Lock After Stateless Reset (tquic_input.c, lines 397-407) |
| 95 | CF-095 | 7.00 | S0 | medium | B | Connection State Transition Not Fully Atomic |
| 96 | CF-096 | 7.00 | S0 | medium | C | Connection State Transition Not Fully Atomic |
| 97 | CF-097 | 7.00 | S0 | medium | B | Excessive Stack Usage in RS Recovery |
| 98 | CF-098 | 7.00 | S0 | medium | A | Global connection hashtable (`tquic_conn_table`) is initialized and removed-from, but never inserted-into |
| 99 | CF-099 | 7.00 | S0 | medium | A | Header protection outputs are ignored; packet-number length + key phase are derived from protected header |
| 100 | CF-100 | 7.00 | S0 | medium | B | Huffman Decoder O(n*256) Algorithmic Complexity DoS |
| 101 | CF-101 | 7.00 | S0 | medium | B | Integer Overflow in Coupled CC Increase Calculation |
| 102 | CF-102 | 7.00 | S0 | medium | B | IPv4/IPv6 Address Discovery Enumerates Host Interfaces |
| 103 | CF-103 | 7.00 | S0 | medium | C | IPv4/IPv6 Address Discovery Enumerates Host Interfaces (Container Escape / Info Leak) |
| 104 | CF-104 | 7.00 | S0 | medium | B | List Iterator Invalidation in BPM Netdev Notifier |
| 105 | CF-105 | 7.00 | S0 | medium | C | List Iterator Invalidation in BPM Netdev Notifier (Drop-Relock Pattern) |
| 106 | CF-106 | 7.00 | S0 | medium | B | MASQUE CONNECT-UDP Proxy Creates Sockets in init_net |
| 107 | CF-107 | 7.00 | S0 | medium | C | MASQUE CONNECT-UDP Proxy Creates Sockets in init_net (Container Escape) |
| 108 | CF-108 | 7.00 | S0 | medium | B | Missing Bounds Check Before Frame Type Read |
| 109 | CF-109 | 7.00 | S0 | medium | C | Packet Number Length Extracted Before Header Unprotection (tquic_input.c, lines 2529, 2545 vs 2565) |
| 110 | CF-110 | 7.00 | S0 | medium | A | Packet number reconstruction always uses `largest_pn = 0` |
| 111 | CF-111 | 7.00 | S0 | medium | B | Potential Integer Overflow in CRYPTO Frame on 32-bit |
| 112 | CF-112 | 7.00 | S0 | medium | B | QPACK Dynamic Table Duplicate TOCTOU Race |
| 113 | CF-113 | 7.00 | S0 | medium | A | QUIC-Exfil mitigation code uses `skb->cb` as a function-pointer slot and gates on `skb->cb[0]` |
| 114 | CF-114 | 7.00 | S0 | medium | C | QUIC-over-TCP Client and Server Sockets Use init_net (Container Escape) |
| 115 | CF-115 | 7.00 | S0 | medium | B | Rate Calculation Integer Overflow |
| 116 | CF-116 | 7.00 | S0 | medium | C | Rate Calculation Integer Overflow (`count * 1000`) |
| 117 | CF-117 | 7.00 | S0 | medium | B | Reason Length Underflow on 32-bit |
| 118 | CF-118 | 7.00 | S0 | medium | B | Redundant Scheduler Deduplication Uses Only 8-bit Sequence Hash -- Trivial Collision |
| 119 | CF-119 | 7.00 | S0 | medium | A | Reference counting/RCU lifetime is not actually enforced; direct `tquic_conn_destroy()` calls can free live connections |
| 120 | CF-120 | 7.00 | S0 | medium | A | rhashtable/RCU lifetime issues (use-after-free risk) in CID tables |
| 121 | CF-121 | 7.00 | S0 | medium | A | RX parsing/decryption assumes contiguous skb data (non-linear skb / GRO risk) |
| 122 | CF-122 | 7.00 | S0 | medium | B | Same Overflow in OLIA Increase Path |
| 123 | CF-123 | 7.00 | S0 | medium | C | Stale skb->len Read After ip_local_out (tquic_output.c, lines 1730-1736) |
| 124 | CF-124 | 7.00 | S0 | medium | C | TOCTOU Race in Failover Hysteresis (Atomic Read-Modify-Write) |
| 125 | CF-125 | 7.00 | S0 | medium | B | Tunnel Socket Creation Uses init_net |
| 126 | CF-126 | 7.00 | S0 | medium | C | Tunnel Socket Creation Uses init_net (Container Escape) |
| 127 | CF-127 | 7.00 | S0 | medium | B | UAF-P2-01: - SKB accessed after udp_tunnel_xmit_skb |
| 128 | CF-128 | 7.00 | S0 | medium | B | UAF-P3-01: - retransmit_work_fn accesses ts->conn without connection reference |
| 129 | CF-129 | 7.00 | S0 | medium | B | UAF-P3-02: - path_work_fn accesses ts->conn without reference |
| 130 | CF-130 | 7.00 | S0 | medium | B | Use-After-Free in `tquic_migrate_auto()` -- RCU-Protected Path Used After RCU Unlock |
| 131 | CF-131 | 7.00 | S0 | medium | B | Use-After-Free in `tquic_migrate_explicit()` -- Path Used Without Reference |
| 132 | CF-132 | 7.00 | S0 | medium | B | Use-After-Free in Algorithm Name Return |
| 133 | CF-133 | 7.00 | S0 | medium | C | Use-After-Free in Path Lookup (tquic_input.c, lines 245-261) |
| 134 | CF-134 | 7.00 | S0 | medium | A | Widespread allocator mismatches (kmem_cache vs kzalloc/kfree) for core objects (conn/path/stream) |
| 135 | CF-135 | 7.00 | S0 | medium | C | Wrong Network Namespace in ip_local_out (tquic_output.c, line 1730) |
| 136 | CF-136 | 7.00 | S1 | high | A,B,C | `ext->final_size = -1` Uses Signed Overflow |
| 137 | CF-137 | 7.00 | S1 | high | A,B,C | Constant-Time CID Validation Has Branching on Lengths |
| 138 | CF-138 | 7.00 | S1 | high | A,B,C | Custom ASN.1 Parser - High Attack Surface |
| 139 | CF-139 | 7.00 | S1 | high | A,B,C | Function Pointer Stored in skb->cb Without Validation |
| 140 | CF-140 | 7.00 | S1 | high | A,B,C | HTTP/3 Request: TOCTOU Between State Check and Send |
| 141 | CF-141 | 7.00 | S1 | high | A,B,C | HTTP/3 Settings Frame Length Truncation |
| 142 | CF-142 | 7.00 | S1 | high | A,B,C | Load Balancer Encryption Key Not Zeroized on Destroy |
| 143 | CF-143 | 7.00 | S1 | high | A,B,C | No CAP_NET_ADMIN Check for Tunnel Creation |
| 144 | CF-144 | 7.00 | S1 | high | A,B,C | Path Metrics Netlink: Missing CAP_NET_ADMIN Permission Check |
| 145 | CF-145 | 7.00 | S1 | high | A,B,C | Per-Call crypto_aead_setkey in Encrypt/Decrypt Hot Path |
| 146 | CF-146 | 7.00 | S1 | high | A,B,C | Per-Call crypto_alloc_aead in 0-RTT Encrypt/Decrypt |
| 147 | CF-147 | 7.00 | S1 | high | A,B,C | QPACK Decoder: Unbounded Blocked Stream Memory Exhaustion |
| 148 | CF-148 | 7.00 | S1 | high | A,B,C | QPACK Encoder: Insert Count Increment Overflow |
| 149 | CF-149 | 7.00 | S1 | high | A,B,C | Race Condition in Key Update Secret Installation |
| 150 | CF-150 | 7.00 | S1 | high | A,B,C | RSA-PSS Hash Algorithm Hardcoded to SHA-256 |
| 151 | CF-151 | 7.00 | S1 | high | A,B,C | Secrets not zeroized on error paths in key derivation functions |
| 152 | CF-152 | 7.00 | S1 | high | A,B,C | Stream State Machine Allows Unexpected Transitions from OPEN |
| 153 | CF-153 | 7.00 | S1 | high | A,B,C | Timing Normalization Can Block in Packet Processing Path |
| 154 | CF-154 | 7.00 | S1 | high | A,B,C | Unbounded Connection Creation via Netlink |
| 155 | CF-155 | 7.00 | S1 | high | A,B,C | WebTransport Context Destroy: Lock Drop During Iteration |
| 156 | CF-156 | 7.00 | S1 | high | A,B,C | WebTransport: Unbounded Capsule Buffer Growth |
| 157 | CF-157 | 7.00 | S1 | high | B,C | `quic_offload.c` Version Field Shift Without Cast |
| 158 | CF-158 | 7.00 | S1 | high | B,C | `tquic_cid_pool_destroy()` Removes from rhashtable Under BH spinlock |
| 159 | CF-159 | 7.00 | S1 | high | B,C | `tquic_conn_retire_cid()` Does Not Remove CID from Lookup Hash Table |
| 160 | CF-160 | 7.00 | S1 | high | B,C | `tquic_hs_build_ch_extensions` -- ALPN extension length written as 2-byte but can overflow u16 |
| 161 | CF-161 | 7.00 | S1 | high | B,C | `tquic_hs_cleanup` -- potential double-free of session ticket |
| 162 | CF-162 | 7.00 | S1 | high | B,C | `tquic_hs_generate_client_hello` -- output buffer `buf` not validated for minimum size |
| 163 | CF-163 | 7.00 | S1 | high | B,C | `tquic_hs_hkdf_expand_label` -- `context_len` truncated to u8 |
| 164 | CF-164 | 7.00 | S1 | high | B,C | `tquic_hs_process_encrypted_extensions` -- ALPN validation insufficient |
| 165 | CF-165 | 7.00 | S1 | high | B,C | `tquic_hs_process_new_session_ticket` -- memory leak of old ticket data on re-entry |
| 166 | CF-166 | 7.00 | S1 | high | B,C | `tquic_hs_process_server_hello` -- session ID comparison not fully bounds-safe |
| 167 | CF-167 | 7.00 | S1 | high | B,C | `tquic_hs_setup_psk` -- integer overflow in ticket age calculation |
| 168 | CF-168 | 7.00 | S1 | high | B,C | `tquic_recvmsg()` Same Issue as HIGH-07 |
| 169 | CF-169 | 7.00 | S1 | high | B,C | accept() Uses spin_lock_bh on sk_lock.slock While lock_sock() Is Held |
| 170 | CF-170 | 7.00 | S1 | high | B,C | Anti-Amplification Integer Overflow |
| 171 | CF-171 | 7.00 | S1 | high | B,C | atomic_sub on sk_rmem_alloc Incompatible with refcount_t |
| 172 | CF-172 | 7.00 | S1 | high | B,C | BBRv2 Inflight Calculation Truncation |
| 173 | CF-173 | 7.00 | S1 | high | B,C | Bloom Filter Has High False Positive Rate at Scale |
| 174 | CF-174 | 7.00 | S1 | high | B,C | Bonding State Machine Drop-Relock Without Re-validation |
| 175 | CF-175 | 7.00 | S1 | high | B,C | CID Lookup Returns Connection Without Reference Count |
| 176 | CF-176 | 7.00 | S1 | high | B,C | Coalesced Packet Splitting Assumes v1 Packet Type Encoding |
| 177 | CF-177 | 7.00 | S1 | high | A,B | conn->lock held during path selection on every TX packet |
| 178 | CF-178 | 7.00 | S1 | high | A,B | conn->lock released and reacquired during output flush stream iteration |
| 179 | CF-179 | 7.00 | S1 | high | A,B | conn->paths_lock in RX path for every packet |
| 180 | CF-180 | 7.00 | S1 | high | A,B | CONNECTION_CLOSE uses kmalloc for small buffer |
| 181 | CF-181 | 7.00 | S1 | high | B,C | const-Correctness Violation in Proxy Packet Decode |
| 182 | CF-182 | 7.00 | S1 | high | B,C | copy_from_user with User-Controlled Size in Socket Options |
| 183 | CF-183 | 7.00 | S1 | high | B,C | ECN Counter Values Passed Directly to TQUIC_ADD_STATS Without Overflow Check |
| 184 | CF-184 | 7.00 | S1 | high | B,C | EKU Derives Keys Using KU hash_tfm Without KU Lock |
| 185 | CF-185 | 7.00 | S1 | high | B,C | EKU Semantic Mismatch: get_current_keys Returns Key, Not Secret |
| 186 | CF-186 | 7.00 | S1 | high | B,C | FEC decoder recovery -- partial recovery leaks on kzalloc failure |
| 187 | CF-187 | 7.00 | S1 | high | B,C | FEC encoder repair symbol generation -- partial resource leak on kzalloc failure |
| 188 | CF-188 | 7.00 | S1 | high | B,C | FEC Repair Count Computation: `block_size * target_fec_rate` Truncation |
| 189 | CF-189 | 7.00 | S1 | high | B,C | FEC Scheduler Loss Rate Overflow |
| 190 | CF-190 | 7.00 | S1 | high | B,C | getsockopt PSK Identity - Missing Length Validation |
| 191 | CF-191 | 7.00 | S1 | high | B,C | GRO Coalesce Uses Hardcoded 8-byte CID Comparison |
| 192 | CF-192 | 7.00 | S1 | high | B,C | GRO Flush Unlock-Relock Loop Without Re-validation |
| 193 | CF-193 | 7.00 | S1 | high | B,C | h3_control_recv_frame Does Not Parse Frame Payloads |
| 194 | CF-194 | 7.00 | S1 | high | A,B | HIGH: atomic64_inc_return for packet number on every TX |
| 195 | CF-195 | 7.00 | S1 | high | A,B | HIGH: GRO stats use global atomic64 on every packet |
| 196 | CF-196 | 7.00 | S1 | high | A,B | HIGH: Kernel address stored as u64 in buffer ring entries |
| 197 | CF-197 | 7.00 | S1 | high | A,B | HIGH: kmalloc(path->mtu) per datagram send |
| 198 | CF-198 | 7.00 | S1 | high | B,C | http3_stream.c Uses spin_lock Without _bh |
| 199 | CF-199 | 7.00 | S1 | high | B,C | Incomplete SSRF Protection in TCP-over-QUIC Tunnel |
| 200 | CF-200 | 7.00 | S1 | high | A,B | Infinite retry loop on EMSGSIZE/EEXIST |
| 201 | CF-201 | 7.00 | S1 | high | B,C | Integer Overflow in iovec Total Length Calculation |
| 202 | CF-202 | 7.00 | S1 | high | A,B | io_uring buffer ring spinlock per get/put operation |
| 203 | CF-203 | 7.00 | S1 | high | B,C | Load Balancer Has No Privilege Checks |
| 204 | CF-204 | 7.00 | S1 | high | B,C | MASQUE Proxy Has No Access Control |
| 205 | CF-205 | 7.00 | S1 | high | B,C | memset Instead of memzero_explicit for Old Key Material |
| 206 | CF-206 | 7.00 | S1 | high | B,C | Missing kfree_sensitive for key material in crypto/handshake.c extensions buffer |
| 207 | CF-207 | 7.00 | S1 | high | B,C | Missing Validation of `first_ack_range` Against `largest_ack` |
| 208 | CF-208 | 7.00 | S1 | high | B,C | Missing Validation of `TQUIC_MIGRATE` sockopt Address |
| 209 | CF-209 | 7.00 | S1 | high | B,C | Netfilter Short Header DCID Parsing Uses Arbitrary Length |
| 210 | CF-210 | 7.00 | S1 | high | B,C | Packet Forwarding Has No Privilege Checks |
| 211 | CF-211 | 7.00 | S1 | high | B,C | payload_len Subtraction Underflow in Long Header Parsing |
| 212 | CF-212 | 7.00 | S1 | high | B,C | Prague Congestion Control: `ecn_ce_count * mss` Overflow |
| 213 | CF-213 | 7.00 | S1 | high | B,C | Procfs trusted_cas Writable Without Privilege Check |
| 214 | CF-214 | 7.00 | S1 | high | B,C | PTO Duration Exponential Shift Overflow |
| 215 | CF-215 | 7.00 | S1 | high | B,C | qlog TOCTOU Race Between Length Check and copy_to_user |
| 216 | CF-216 | 7.00 | S1 | high | B,C | Race Condition in Idle Timer Connection Processing |
| 217 | CF-217 | 7.00 | S1 | high | A,B | Redundant triple-counting of statistics |
| 218 | CF-218 | 7.00 | S1 | high | B,C | reed_solomon.c -- four-allocation group without individual NULL checks |
| 219 | CF-219 | 7.00 | S1 | high | B,C | Retry Integrity Tag Uses Wrong Key/Nonce for QUIC v2 |
| 220 | CF-220 | 7.00 | S1 | high | B,C | Retry Packet Stack Buffer Overflow |
| 221 | CF-221 | 7.00 | S1 | high | B,C | Retry Packet Version Encoding Is Hardcoded for v1 |
| 222 | CF-222 | 7.00 | S1 | high | B,C | Retry Token AEAD Key Set Under Non-IRQ-Safe Spinlock |
| 223 | CF-223 | 7.00 | S1 | high | B,C | Return Pointer to Stack/Lock-Protected Data in tquic_conn_get_active_cid |
| 224 | CF-224 | 7.00 | S1 | high | B,C | RSA Signature Algorithm Hardcoded to SHA-256 Regardless of Certificate |
| 225 | CF-225 | 7.00 | S1 | high | B,C | Security Hardening Pre-HS Atomic TOCTOU |
| 226 | CF-226 | 7.00 | S1 | high | B,C | Session Ticket Decode Missing Bounds Check on PSK Copy |
| 227 | CF-227 | 7.00 | S1 | high | B,C | smartnic.c Uses spin_lock Without _bh |
| 228 | CF-228 | 7.00 | S1 | high | A,B | struct tquic_napi mixes hot and cold fields |
| 229 | CF-229 | 7.00 | S1 | high | B,C | Ticket Store Free-After-Remove Race Condition |
| 230 | CF-230 | 7.00 | S1 | high | B,C | TPROXY Capability Check Logic Inversion |
| 231 | CF-231 | 7.00 | S1 | high | B,C | tquic_process_stream_frame Allocates skb Based on Attacker-Controlled length |
| 232 | CF-232 | 7.00 | S1 | high | B,C | tquic_stream_count_by_type O(n) Scan for Critical Stream Enforcement |
| 233 | CF-233 | 7.00 | S1 | high | B,C | tquic_stream_recv_data Potential Integer Overflow in Flow Control Check |
| 234 | CF-234 | 7.00 | S1 | high | B,C | tquic_stream_send_allowed Missing Underflow Check |
| 235 | CF-235 | 7.00 | S1 | high | B,C | tquic_stream_sendfile Reads Only Into First Page |
| 236 | CF-236 | 7.00 | S1 | high | B,C | tquic_stream_socket_create Double-Free on fd Failure |
| 237 | CF-237 | 7.00 | S1 | high | B,C | tquic_zerocopy_sendmsg -- uarg leak on partial send |
| 238 | CF-238 | 7.00 | S1 | high | B,C | Version Negotiation Packet Missing Randomized First Byte |
| 239 | CF-239 | 7.00 | S1 | high | B,C | Weak CID Hash Function Enables Hash Flooding |
| 240 | CF-240 | 7.00 | S1 | high | B,C | Zero-RTT Session Ticket Deserialization Trusts Length Fields |
| 241 | CF-241 | 7.00 | S1 | high | B | `tquic_connect()` Stores Error in `sk->sk_err` as Positive Value Wrongly |
| 242 | CF-242 | 7.00 | S1 | high | B | ACK Frame bytes_acked Calculation Can Overflow |
| 243 | CF-243 | 7.00 | S1 | high | B | ACK Range Processing Without Semantic Validation |
| 244 | CF-244 | 7.00 | S1 | high | B | Connection Close Reason Phrase Skipped Without Content Validation |
| 245 | CF-245 | 7.00 | S1 | high | B | Data Race in Server Migration Check |
| 246 | CF-246 | 7.00 | S1 | high | B | Internal Round-Robin Scheduler Missing Bounds Check |
| 247 | CF-247 | 7.00 | S1 | high | B | Multipath Frame Processing Lacks Encryption Level Validation |
| 248 | CF-248 | 7.00 | S1 | high | B | Race Condition on path->last_activity |
| 249 | CF-249 | 7.00 | S1 | high | B | Retire Prior To Not Validated Against Sequence Number |
| 250 | CF-250 | 7.00 | S1 | high | B | Route Lookup Fallback to init_net |
| 251 | CF-251 | 7.00 | S1 | high | B | tquic_output_packet Passes NULL conn to ip_local_out |
| 252 | CF-252 | 7.00 | S1 | high | B | Type Shadowing Creates Memory Corruption Risk |
| 253 | CF-253 | 7.00 | S1 | high | B | UAF-P1-02: - tquic_diag.c accesses conn->sk without reference |
| 254 | CF-254 | 7.00 | S1 | high | B | UAF-P3-03: - Tunnel close races with connect_work and forward_work |
| 255 | CF-255 | 7.00 | S1 | high | B | UAF-P3-04: - Path validation timer callback accesses path after potential free |
| 256 | CF-256 | 7.00 | S1 | high | B | UAF-P6-01: - SmartNIC ops dereference after device could be freed |
| 257 | CF-257 | 7.00 | S1 | high | B | Unlocked Connection Access in IOCTL |
| 258 | CF-258 | 4.90 | S1 | medium | C | (Revised): tquic_pacing_work Accesses skb->len After tquic_output_packet (tquic_output.c, lines 1413-1418) |
| 259 | CF-259 | 4.90 | S1 | medium | B | 0-RTT Keys Derived With Empty Transcript |
| 260 | CF-260 | 4.90 | S1 | medium | C | 0-RTT Keys Derived With Empty Transcript (Not ClientHello Hash) |
| 261 | CF-261 | 4.90 | S1 | medium | A | `setsockopt(SOL_TQUIC, ...)` forces `optlen >= sizeof(int)` even for string/binary options |
| 262 | CF-262 | 4.90 | S1 | medium | B | `tquic_nl_cmd_path_remove()` Double Put on Path |
| 263 | CF-263 | 4.90 | S1 | medium | C | ACK Frame bytes_acked Calculation Can Overflow (tquic_input.c, lines 736-738) |
| 264 | CF-264 | 4.90 | S1 | medium | B | Aggregate Scheduler Unfair Minimum Weight Floor |
| 265 | CF-265 | 4.90 | S1 | medium | B | Bonding State Machine Missing Lock on State Transition Checks |
| 266 | CF-266 | 4.90 | S1 | medium | B | BPM Path Manager Falls Back to init_net |
| 267 | CF-267 | 4.90 | S1 | medium | B | CPU-5: All hash tables use `jhash` with a **fixed seed of 0**. |
| 268 | CF-268 | 4.90 | S1 | medium | B | Double `tquic_nl_path_put()` in `tquic_path_remove_and_free()` Assumes refcnt==2 |
| 269 | CF-269 | 4.90 | S1 | medium | B | Expensive Operation in Loss Path |
| 270 | CF-270 | 4.90 | S1 | medium | B | Failover Retransmit Queue Can Exceed Memory Limits |
| 271 | CF-271 | 4.90 | S1 | medium | B | FEC Scheme ID Not Validated From Wire |
| 272 | CF-272 | 4.90 | S1 | medium | B | Global Congestion Data Cache Without Namespace Isolation |
| 273 | CF-273 | 4.90 | S1 | medium | B | h3_request_send_headers State Check TOCTOU |
| 274 | CF-274 | 4.90 | S1 | medium | B | h3_stream_lookup_by_push_id Linear Scan Under Lock |
| 275 | CF-275 | 4.90 | S1 | medium | A | HIGH: Multiple ktime_get() calls per packet |
| 276 | CF-276 | 4.90 | S1 | medium | B | Hysteresis Counters Use Non-Atomic READ_ONCE/WRITE_ONCE Without Lock |
| 277 | CF-277 | 4.90 | S1 | medium | B | Large Stack Allocation in XOR Recovery |
| 278 | CF-278 | 4.90 | S1 | medium | B | Memory Exhaustion via Unbounded QPACK Header Lists |
| 279 | CF-279 | 4.90 | S1 | medium | B | Migration State Stores Raw Path Pointers Without Reference Counting |
| 280 | CF-280 | 4.90 | S1 | medium | B | Missing Address Family Validation in `tquic_path_create()` |
| 281 | CF-281 | 4.90 | S1 | medium | C | Multipath Frame Processing Lacks Encryption Level Validation (tquic_input.c, lines 2027-2038) |
| 282 | CF-282 | 4.90 | S1 | medium | B | Multiple ktime_get() calls per packet |
| 283 | CF-283 | 4.90 | S1 | medium | B | No ACK Frame Frequency Limit Per Packet |
| 284 | CF-284 | 4.90 | S1 | medium | B | Path Manager Uses init_net Instead of Per-Connection Net Namespace |
| 285 | CF-285 | 4.90 | S1 | medium | B | Path Validation Timeout Accesses Path State Without Lock After Unlock |
| 286 | CF-286 | 4.90 | S1 | medium | B | qpack_encoder known_received_count Overflow via Insert Count Increment |
| 287 | CF-287 | 4.90 | S1 | medium | B | Repair Frame Field Truncation Without Validation |
| 288 | CF-288 | 4.90 | S1 | medium | B | Same Stack Issue in Encoder |
| 289 | CF-289 | 4.90 | S1 | medium | B | sched/scheduler.c rr_select TOCTOU on num_paths |
| 290 | CF-290 | 4.90 | S1 | medium | B | sched/scheduler.c wrr_select Stale total_weight |
| 291 | CF-291 | 4.90 | S1 | medium | B | Stale Path Pointer Returned After rcu_read_unlock |
| 292 | CF-292 | 4.90 | S1 | medium | B | Stateless Reset Falls Back to init_net |
| 293 | CF-293 | 4.90 | S1 | medium | B | TOCTOU in Round-Robin Path Count vs Selection |
| 294 | CF-294 | 4.90 | S1 | medium | B | TOCTOU Race in Bonding State Transition |
| 295 | CF-295 | 4.90 | S1 | medium | B | TQUIC_MAX_PATHS Mismatch |
| 296 | CF-296 | 4.90 | S1 | medium | C | tquic_output_packet Passes NULL conn to ip_local_out (tquic_output.c, line 1413) |
| 297 | CF-297 | 4.90 | S1 | medium | B | tquic_stream_check_flow_control TOCTOU with sendmsg |
| 298 | CF-298 | 4.90 | S1 | medium | B | tquic_stream_ext Uses GFP_ATOMIC for Large Allocation |
| 299 | CF-299 | 4.90 | S1 | medium | B | tquic_udp_recv Processes Stateless Reset Before Authenticating Packet |
| 300 | CF-300 | 4.90 | S1 | medium | C | tquic_udp_recv Processes Stateless Reset Before Authenticating Packet (tquic_input.c, lines 2916-2932) |
| 301 | CF-301 | 4.90 | S1 | medium | B | UAF-P1-03: - conn->sk dereference in congestion control without locking |
| 302 | CF-302 | 4.90 | S1 | medium | B | UAF-P4-01: - tquic_zc_entry uses atomic_t instead of refcount_t |
| 303 | CF-303 | 4.90 | S1 | medium | B | UAF-P4-02: - Paths lack reference counting entirely |
| 304 | CF-304 | 4.90 | S1 | medium | A | Unit tests model packet-number length as readable from the first byte without HP removal |
| 305 | CF-305 | 4.90 | S1 | medium | B | Unprotected Global Loss Tracker Array |
| 306 | CF-306 | 4.90 | S1 | medium | B | Unvalidated `addr_len` Passed to `memcpy` in `tquic_connect()` |
| 307 | CF-307 | 4.90 | S1 | medium | B | Weight Accumulation Without Overflow Check |
| 308 | CF-308 | 4.90 | S1 | medium | B | Weighted Scheduler Has No Lock Protection |
| 309 | CF-309 | 4.00 | S2 | high | A,B,C | Bloom Filter False Negatives Allow Replay |
| 310 | CF-310 | 4.00 | S2 | high | A,B,C | Decoy Packet Size Calculation Can Underflow |
| 311 | CF-311 | 4.00 | S2 | high | A,B,C | EKU Request ID Increment Outside Lock |
| 312 | CF-312 | 4.00 | S2 | high | A,B,C | HP Key Rotation Swaps Old Keys Without Zeroization |
| 313 | CF-313 | 4.00 | S2 | high | A,B,C | HTTP/3 Connection: O(n) Push Entry Counting |
| 314 | CF-314 | 4.00 | S2 | high | A,B,C | HTTP/3 Frame Parsing: 16MB Maximum Frame Payload |
| 315 | CF-315 | 4.00 | S2 | high | A,B,C | HTTP/3 Settings Parser: TOCTOU on Settings Count |
| 316 | CF-316 | 4.00 | S2 | high | A,B,C | Missing Bounds Check on tbs Pointer in Signature Parse |
| 317 | CF-317 | 4.00 | S2 | high | A,B,C | Path Metrics Subscription: Timer/Connection Lifetime Race |
| 318 | CF-318 | 4.00 | S2 | high | A,B,C | Path Score Computation Can Overflow in Migration Target Selection |
| 319 | CF-319 | 4.00 | S2 | high | A,B,C | Per-Call crypto_alloc_shash in Stateless Reset Token Generation |
| 320 | CF-320 | 4.00 | S2 | high | A,B,C | QAT Encrypt Sets Key on Every Call |
| 321 | CF-321 | 4.00 | S2 | high | A,B,C | Qlog Ring Buffer: Not Truly Lock-Free |
| 322 | CF-322 | 4.00 | S2 | high | A,B,C | Qlog: JSON Strings Not Escaped |
| 323 | CF-323 | 4.00 | S2 | high | A,B,C | QPACK Encoder/Decoder: Excessive Stack Usage |
| 324 | CF-324 | 4.00 | S2 | high | A,B,C | QPACK Huffman Decoder: O(n*256) Complexity |
| 325 | CF-325 | 4.00 | S2 | high | A,B,C | QPACK Integer Decode: Shift Overflow |
| 326 | CF-326 | 4.00 | S2 | high | A,B,C | Time Parsing Does Not Validate Digit Characters |
| 327 | CF-327 | 4.00 | S2 | high | A,B,C | Transcript Buffer Not Zeroized Before Free |
| 328 | CF-328 | 4.00 | S2 | high | A,B,C | Tunnel Port Allocation Unsigned Underflow |
| 329 | CF-329 | 4.00 | S2 | high | A,B,C | WebTransport: TOCTOU in Datagram Queue Push |
| 330 | CF-330 | 4.00 | S2 | high | B,C | `additional_addr_add()` Has TOCTOU Between Duplicate Check and Insert |
| 331 | CF-331 | 4.00 | S2 | high | B,C | `bbrv3.c` CE Ratio Potential Division by Zero |
| 332 | CF-332 | 4.00 | S2 | high | B,C | `hs_varint_encode` -- no bounds check on output buffer |
| 333 | CF-333 | 4.00 | S2 | high | B,C | `http3_frame.c` Settings Frame Parser: No Bounds on `count` |
| 334 | CF-334 | 4.00 | S2 | high | B,C | `kmem_cache_create()` Per Stream Manager Risks Name Collision |
| 335 | CF-335 | 4.00 | S2 | high | B,C | `ring_index()` Uses Unbounded While Loop |
| 336 | CF-336 | 4.00 | S2 | high | B,C | `tquic_accept()` Holding `sk_lock.slock` Improperly |
| 337 | CF-337 | 4.00 | S2 | high | B,C | `tquic_cong.c` ECN Byte Calculation Overflow |
| 338 | CF-338 | 4.00 | S2 | high | B,C | `tquic_fc_conn_data_sent()` Race Between Check and Update |
| 339 | CF-339 | 4.00 | S2 | high | B,C | `tquic_hs_derive_early_secrets` -- `memzero_explicit` called before error check |
| 340 | CF-340 | 4.00 | S2 | high | B,C | `tquic_hs_generate_client_hello` -- `hkdf_label` stack buffer on sensitive crypto path |
| 341 | CF-341 | 4.00 | S2 | high | B,C | `tquic_hs_process_certificate_verify` -- `content[200]` stack buffer could overflow with large hash |
| 342 | CF-342 | 4.00 | S2 | high | B,C | `tquic_hs_process_certificate` -- unbounded certificate allocation |
| 343 | CF-343 | 4.00 | S2 | high | B,C | `tquic_hs_process_server_hello` -- `static const` inside function body |
| 344 | CF-344 | 4.00 | S2 | high | B,C | `tquic_migrate_validate_all_additional()` Lock Drop/Reacquire Pattern |
| 345 | CF-345 | 4.00 | S2 | high | B,C | `tquic_nl_cmd_path_dump()` Incorrect Cast of `cb->ctx` |
| 346 | CF-346 | 4.00 | S2 | high | B,C | `tquic_path_compute_score()` Integer Overflow in Score Calculation |
| 347 | CF-347 | 4.00 | S2 | high | B,C | `tquic_path_is_degraded()` Division by Zero Possible |
| 348 | CF-348 | 4.00 | S2 | high | B,C | `tquic_proc.c` Buffer Overflow in Hex CID Formatting |
| 349 | CF-349 | 4.00 | S2 | high | B,C | `tquic_process_stream_frame()` Does Not Check Final Size Consistency |
| 350 | CF-350 | 4.00 | S2 | high | B,C | `tquic_sendmsg_datagram()` Allocates Kernel Buffer Sized by User-Controlled `len` |
| 351 | CF-351 | 4.00 | S2 | high | B,C | `tquic_sock_setsockopt()` Reads `int` for Some Options But Accepts `optlen >= sizeof(int)` Without Capping |
| 352 | CF-352 | 4.00 | S2 | high | B,C | `transport_params.c` Memcpy with `count * sizeof(u32)` Without Overflow Check |
| 353 | CF-353 | 4.00 | S2 | high | B,C | ACK Frame Range Count Uses u64 Loop Variable Against size_t max_ranges |
| 354 | CF-354 | 4.00 | S2 | high | B,C | Anti-Replay Hash Table Cleanup Iterates All Buckets Under spinlock |
| 355 | CF-355 | 4.00 | S2 | high | A,B | atomic_inc/dec for rx_queue_len on every enqueue/dequeue |
| 356 | CF-356 | 4.00 | S2 | high | B,C | Benchmark write() Handler - Stack Buffer for User Input |
| 357 | CF-357 | 4.00 | S2 | high | B,C | Bloom Filter Seeds Never Rotated |
| 358 | CF-358 | 4.00 | S2 | high | B,C | BPM Path Manager Uses Workqueue Without Connection Lifetime Guard |
| 359 | CF-359 | 4.00 | S2 | high | B,C | cert_verify.c - kmalloc(count + 1) Integer Overflow |
| 360 | CF-360 | 4.00 | S2 | high | B,C | cert_verify.c parse_san_extension -- error code not propagated |
| 361 | CF-361 | 4.00 | S2 | high | B,C | Certificate Chain Parsing Does Not Verify Issuer-Subject Linkage Before Trust Check |
| 362 | CF-362 | 4.00 | S2 | high | B,C | CID Sequence Number Rollback on rhashtable Insert Failure |
| 363 | CF-363 | 4.00 | S2 | high | A,B | conn->streams_lock for RB-tree walk on every STREAM frame |
| 364 | CF-364 | 4.00 | S2 | high | B,C | connect_ip.c Datagram Buffer Allocation from Attacker Data |
| 365 | CF-365 | 4.00 | S2 | high | B,C | connect_udp.c URL Encoding Can Exceed Buffer |
| 366 | CF-366 | 4.00 | S2 | high | B,C | Connection State Not Checked in tquic_conn_handle_close |
| 367 | CF-367 | 4.00 | S2 | high | B,C | Coupled Congestion Control Division by Zero |
| 368 | CF-368 | 4.00 | S2 | high | B,C | Decoy Traffic Uses Easily Fingerprinted All-Zero Padding |
| 369 | CF-369 | 4.00 | S2 | high | B,C | Diag/Tracepoints Initialize in init_net |
| 370 | CF-370 | 4.00 | S2 | high | B,C | Error Ring Uses Atomics Under Spinlock Unnecessarily |
| 371 | CF-371 | 4.00 | S2 | high | B,C | Exfil Context set_level Destroys and Reinitializes Without Lock |
| 372 | CF-372 | 4.00 | S2 | high | A,B | FEC encoder allocates per-symbol in GFP_ATOMIC |
| 373 | CF-373 | 4.00 | S2 | high | A,B | FEC encoder double lock nesting |
| 374 | CF-374 | 4.00 | S2 | high | B,C | FEC Encoder Triple-Nested Locking |
| 375 | CF-375 | 4.00 | S2 | high | B,C | Gaussian Random Approximation Produces Biased Distribution |
| 376 | CF-376 | 4.00 | S2 | high | B,C | h3_stream_recv_data frame_hdr Buffer Partial Read |
| 377 | CF-377 | 4.00 | S2 | high | B,C | h3_stream_recv_headers Does Not Validate payload_len Against H3_MAX_FRAME_PAYLOAD_SIZE |
| 378 | CF-378 | 4.00 | S2 | high | B,C | Hardcoded 8-Byte CID in Short Header Unprotect |
| 379 | CF-379 | 4.00 | S2 | high | B,C | HMAC Transform Allocated Per-Token in `tquic_stateless_reset_generate_token()` |
| 380 | CF-380 | 4.00 | S2 | high | B,C | Hostname Wildcard Matching Allows Wildcards in Non-Leftmost Position |
| 381 | CF-381 | 4.00 | S2 | high | B,C | http3_priority.c snprintf Priority Field Truncation |
| 382 | CF-382 | 4.00 | S2 | high | B,C | Interop Framework - Same Pattern |
| 383 | CF-383 | 4.00 | S2 | high | B,C | Key Material Not Zeroized on All Error Paths in tquic_zero_rtt_derive_keys |
| 384 | CF-384 | 4.00 | S2 | high | B,C | kmem_cache Names Not Unique Per Connection |
| 385 | CF-385 | 4.00 | S2 | high | B,C | Load Balancer Feistel Network Half-Length Overlap |
| 386 | CF-386 | 4.00 | S2 | high | B,C | Load Balancer Nonce Counter Wraps Without Re-keying |
| 387 | CF-387 | 4.00 | S2 | high | A,B | MEDIUM: BBRv3 uses ktime_get_ns() for every bandwidth sample |
| 388 | CF-388 | 4.00 | S2 | high | A,B | MEDIUM: kzalloc per io_uring async request |
| 389 | CF-389 | 4.00 | S2 | high | A,B | MEDIUM: Per-chunk skb allocation in zerocopy path |
| 390 | CF-390 | 4.00 | S2 | high | A,B | MEDIUM: Zerocopy sendmsg chunks at 1200 bytes |
| 391 | CF-391 | 4.00 | S2 | high | A,B | MIB counter updates on every packet in RX/TX paths |
| 392 | CF-392 | 4.00 | S2 | high | B,C | Missing Bounds Check on tquic_hyst_state_names Array Access |
| 393 | CF-393 | 4.00 | S2 | high | B,C | Missing skb->dev Assignment in Packet Injection |
| 394 | CF-394 | 4.00 | S2 | high | A,B | Multiple atomic operations in NAPI enqueue path |
| 395 | CF-395 | 4.00 | S2 | high | B,C | NAT Keepalive Config Pointer Not Protected Against Concurrent Free |
| 396 | CF-396 | 4.00 | S2 | high | B,C | Netlink Path Dump Reads conn_id on Every Iteration |
| 397 | CF-397 | 4.00 | S2 | high | B,C | Netlink PM Commands Missing CAP_NET_ADMIN Checks |
| 398 | CF-398 | 4.00 | S2 | high | B,C | No Flow Count Limit in HTTP Datagram Manager |
| 399 | CF-399 | 4.00 | S2 | high | B,C | No Token Replay Protection Beyond Timestamp |
| 400 | CF-400 | 4.00 | S2 | high | A,B | Pacing work function drops and reacquires lock per packet |
| 401 | CF-401 | 4.00 | S2 | high | B,C | Packet Number Decode Returns 0 on Invalid Input |
| 402 | CF-402 | 4.00 | S2 | high | B,C | Path Length Constraint Check Off-By-One |
| 403 | CF-403 | 4.00 | S2 | high | B,C | Path Manager netdev_event Shadows Variable 'i' |
| 404 | CF-404 | 4.00 | S2 | high | B,C | Per-Call skcipher_request Allocation in HP Mask Hot Path |
| 405 | CF-405 | 4.00 | S2 | high | B,C | Per-Packet kmalloc in Batch Encrypt/Decrypt |
| 406 | CF-406 | 4.00 | S2 | high | A,B | Per-path stats updated from both RX and TX |
| 407 | CF-407 | 4.00 | S2 | high | B,C | poll() Accesses Connection/Stream Without Any Lock |
| 408 | CF-408 | 4.00 | S2 | high | B,C | Proc Entries Hardcoded to init_net.proc_net |
| 409 | CF-409 | 4.00 | S2 | high | B,C | PSK Identity Logged with `tquic_dbg()` -- Sensitive Data in Kernel Logs |
| 410 | CF-410 | 4.00 | S2 | high | B,C | rcu_dereference Outside Explicit RCU Section |
| 411 | CF-411 | 4.00 | S2 | high | B,C | Request ID Truncation from u64 to int |
| 412 | CF-412 | 4.00 | S2 | high | B,C | Retry Token Address Validation Uses Weak Hash |
| 413 | CF-413 | 4.00 | S2 | high | B,C | SAN DNS Names Not Validated for Embedded NUL Characters |
| 414 | CF-414 | 4.00 | S2 | high | B,C | Scheduler Change Race Between State Check and Modification |
| 415 | CF-415 | 4.00 | S2 | high | B,C | Security Hardening MIB Stats Always Go to init_net |
| 416 | CF-416 | 4.00 | S2 | high | B,C | Signed/Unsigned Mismatch in Scheduler Queue Delay |
| 417 | CF-417 | 4.00 | S2 | high | A,B | SmartNIC offload takes dev->lock for every key operation |
| 418 | CF-418 | 4.00 | S2 | high | B,C | smartnic.c - kmalloc_array with Attacker-Influenced Count |
| 419 | CF-419 | 4.00 | S2 | high | B,C | snprintf Return Value Not Checked in qlog.c |
| 420 | CF-420 | 4.00 | S2 | high | B,C | Stateless Reset Static Key Accessible via `tquic_stateless_reset_get_static_key()` Export |
| 421 | CF-421 | 4.00 | S2 | high | B,C | Sysctl and Proc Entries Registered in init_net Only |
| 422 | CF-422 | 4.00 | S2 | high | B,C | Sysctl Permissions Are Overly Permissive |
| 423 | CF-423 | 4.00 | S2 | high | B,C | Sysctl Variables Lack Range Validation |
| 424 | CF-424 | 4.00 | S2 | high | B,C | Token Hash Comparison Not Constant-Time |
| 425 | CF-425 | 4.00 | S2 | high | B,C | Token Key Rotation Does Not Zeroize Old Key |
| 426 | CF-426 | 4.00 | S2 | high | B,C | tquic_cid_pool_init -- timer initialized but not cancelled on later failure |
| 427 | CF-427 | 4.00 | S2 | high | B,C | tquic_conn_create -- loss_detection_init failure doesn't clean up timers |
| 428 | CF-428 | 4.00 | S2 | high | B,C | tquic_fc_reserve_credit Does Not Actually Reserve |
| 429 | CF-429 | 4.00 | S2 | high | B,C | tquic_handshake.c tquic_start_handshake -- hs freed with memzero_explicit but no kfree_sensitive |
| 430 | CF-430 | 4.00 | S2 | high | B,C | tquic_output_flush -- spin_unlock_bh after acquiring spin_lock_bh, but lock dropped mid-loop |
| 431 | CF-431 | 4.00 | S2 | high | B,C | tquic_retry.c -- integrity_aead_lock held across AEAD operations |
| 432 | CF-432 | 4.00 | S2 | high | B,C | tquic_stream_memory_pressure Frees Without ext Cleanup |
| 433 | CF-433 | 4.00 | S2 | high | B,C | tquic_stream_trigger_output Inflight Underflow |
| 434 | CF-434 | 4.00 | S2 | high | B,C | tquic_stream_write Holds mgr->lock for Entire Copy Loop |
| 435 | CF-435 | 4.00 | S2 | high | B,C | Unbounded Pending Path Challenges |
| 436 | CF-436 | 4.00 | S2 | high | B,C | Version Negotiation Packet Not Authenticated |
| 437 | CF-437 | 4.00 | S2 | high | B,C | WebTransport Session Refcount Not Checked After Accept |
| 438 | CF-438 | 4.00 | S2 | high | A,B | Zerocopy entry refcount uses atomic_t |
| 439 | CF-439 | 4.00 | S2 | high | B | AMP-1: The anti-amplification check uses `atomic64` operations for `bytes_received` and `bytes_sent`, but the check-then-add pattern is not atomic as a whole: |
| 440 | CF-440 | 4.00 | S2 | high | B | asn1_get_length Does Not Handle Length 0x84+ |
| 441 | CF-441 | 4.00 | S2 | high | B | Coalesced Packet Processing Silently Truncates on Overflow |
| 442 | CF-442 | 4.00 | S2 | high | B | conn->data_sent Underflow on Error Path |
| 443 | CF-443 | 4.00 | S2 | high | B | CPU-2: FEC decoder block search is a linear list walk. |
| 444 | CF-444 | 4.00 | S2 | high | B | EDF Scheduler edf_select_path Called Without Lock |
| 445 | CF-445 | 4.00 | S2 | high | B | ktime_get_ts64 Written to skb->cb May Exceed cb Size |
| 446 | CF-446 | 4.00 | S2 | high | B | MP Frame Type Range Check Too Broad |
| 447 | CF-447 | 4.00 | S2 | high | B | tquic_fc_stream_can_send Missing Overflow Check |
| 448 | CF-448 | 4.00 | S2 | high | B | TQUIC_IDLE_TIMEOUT Missing Range Validation |
| 449 | CF-449 | 4.00 | S2 | high | B | TQUIC_PSK_IDENTITY Off-by-One Potential |
| 450 | CF-450 | 4.00 | S2 | high | B | tquic_recv_datagram Can Loop Forever Under Signal Pressure |
| 451 | CF-451 | 4.00 | S2 | high | B | TQUIC_SCHEDULER Race on tquic_sched_find |
| 452 | CF-452 | 4.00 | S2 | high | B | UAF-P5-02: - Path list uses RCU but active_path does not |
| 453 | CF-453 | 4.00 | S2 | high | B | Version Negotiation Versions Logged Without Rate Limiting |
| 454 | CF-454 | 2.80 | S1 | low | B | CROSS-1: The systematic use of `jhash` with seed 0 across 15+ call sites creates a coordinated attack vector. An attacker who can determine CID values and IP addresses can craft inputs that degrade: |
| 455 | CF-455 | 2.80 | S2 | medium | B | 0-RTT Encrypt Allocates AEAD Per-Packet |
| 456 | CF-456 | 2.80 | S2 | medium | C | 0-RTT Encrypt Allocates AEAD Per-Packet (Performance / Side Channel) |
| 457 | CF-457 | 2.80 | S2 | medium | B | All MP Scheduler init() Functions Silently Fail on OOM |
| 458 | CF-458 | 2.80 | S2 | medium | B | Alpha Precision Loss in Coupled CC |
| 459 | CF-459 | 2.80 | S2 | medium | B | AMP-2: The `tquic_path_handle_challenge` function in `pm/path_validation.c:249` does not check anti-amplification limits before queuing the PATH_RESPONSE. Per RFC 9000 Section 8.1, data sent on unvali |
| 460 | CF-460 | 2.80 | S2 | medium | B | AMP-3: The MASQUE CONNECT-UDP tunnel implementation in `masque/connect_udp.c` creates UDP sockets to forward proxied traffic. There is **no visible limit on the number of tunnels per connection or per |
| 461 | CF-461 | 2.80 | S2 | medium | B | Anti-Amplification Check Has TOCTOU Race |
| 462 | CF-462 | 2.80 | S2 | medium | C | asn1_get_length Does Not Handle Length 0x84+ (4+ byte lengths) |
| 463 | CF-463 | 2.80 | S2 | medium | C | Coalesced Packet Processing Silently Truncates on Overflow (tquic_input.c, lines 3172-3173) |
| 464 | CF-464 | 2.80 | S2 | medium | B | Deadline Scheduler in_flight Underflow |
| 465 | CF-465 | 2.80 | S2 | medium | B | Division Safety in Congestion Data Validation |
| 466 | CF-466 | 2.80 | S2 | medium | B | Duplicate ECF Path State Allocation Race |
| 467 | CF-467 | 2.80 | S2 | medium | B | ECN State Tracking Per-Round Limitation |
| 468 | CF-468 | 2.80 | S2 | medium | B | h3_parse_settings_frame u64 to Pointer Cast |
| 469 | CF-469 | 2.80 | S2 | medium | B | h3_parser_advance Missing Bounds Check |
| 470 | CF-470 | 2.80 | S2 | medium | B | HMAC Stack Buffer Size |
| 471 | CF-471 | 2.80 | S2 | medium | B | In-Flight Calculation Signed Arithmetic |
| 472 | CF-472 | 2.80 | S2 | medium | C | ktime_get_ts64 Written to skb->cb May Exceed cb Size (tquic_input.c, line 1471) |
| 473 | CF-473 | 2.80 | S2 | medium | B | Lock Ordering Between Encoder and Scheduler |
| 474 | CF-474 | 2.80 | S2 | medium | B | Loss Rate Cast Overflow |
| 475 | CF-475 | 2.80 | S2 | medium | B | MEM-1: `tquic_handshake.c` lines 605 and 1136 allocate skbs based on computed handshake message lengths (`ch_len`, `resp_len`). While these are internally computed (not directly from network), a malfo |
| 476 | CF-476 | 2.80 | S2 | medium | B | Nested Locking in Repair Reception |
| 477 | CF-477 | 2.80 | S2 | medium | B | Path Creation Uses static atomic_t for path_id -- Not Per-Connection |
| 478 | CF-478 | 2.80 | S2 | medium | B | Path Manager discover_addresses Holds rtnl_lock While Accessing inet6_dev |
| 479 | CF-479 | 2.80 | S2 | medium | B | Priority State No Limit on stream_count |
| 480 | CF-480 | 2.80 | S2 | medium | B | Push Entry Count O(n) Iteration |
| 481 | CF-481 | 2.80 | S2 | medium | B | Reorder Buffer Sequence in skb->cb Alignment |
| 482 | CF-482 | 2.80 | S2 | medium | B | sched/scheduler.c Debug Logging Leaks Kernel Pointers |
| 483 | CF-483 | 2.80 | S2 | medium | B | sched/scheduler.c ECF Loss Rate Division by Zero |
| 484 | CF-484 | 2.80 | S2 | medium | B | Sort Modifies Caller's Lost Packets Array |
| 485 | CF-485 | 2.80 | S2 | medium | B | STATE-1: The transition to "attack mode" (TQUIC_RL_COOKIE_REQUIRED) appears to be reactive -- it triggers when rate limits are exceeded. During the ramp-up period before attack mode activates, an atta |
| 486 | CF-486 | 2.80 | S2 | medium | C | tquic_gro_flush Drops and Re-acquires Lock Per Packet (tquic_input.c, lines 2303-2310) |
| 487 | CF-487 | 2.80 | S2 | medium | B | tquic_main.c init/exit -- conditional cleanup mismatch for NAPI/io_uring |
| 488 | CF-488 | 2.80 | S2 | medium | C | tquic_main.c init/exit -- conditional cleanup mismatch for NAPI/io_uring |
| 489 | CF-489 | 2.80 | S2 | medium | C | tquic_recv_datagram Can Loop Forever Under Signal Pressure (tquic_output.c, lines 2706-2743) |
| 490 | CF-490 | 2.80 | S2 | medium | B | Triplicated Varint Encode/Decode Implementations |
| 491 | CF-491 | 2.80 | S2 | medium | B | UAF-ADD-01: - tquic_tunnel_close does not cancel forward_work for tproxy tunnels |
| 492 | CF-492 | 2.80 | S2 | medium | B | UAF-P3-05: - GRO flush_timer can fire after kfree |
| 493 | CF-493 | 2.80 | S2 | medium | B | UAF-P4-03: - Double destruction path for connections |
| 494 | CF-494 | 2.80 | S2 | medium | B | UAF-P5-01: - Correct RCU usage in tquic_nf.c |
| 495 | CF-495 | 2.80 | S2 | medium | B | UAF-P6-02: - tquic_zerocopy_complete callback chain |
| 496 | CF-496 | 2.80 | S2 | medium | C | Version Negotiation Versions Logged Without Rate Limiting (tquic_input.c, lines 473-477) |
| 497 | CF-497 | 2.80 | S2 | medium | B | WebTransport Datagram Queue Double-Checked Locking Anti-Pattern |
| 498 | CF-498 | 2.80 | S2 | medium | B | Weighted Scheduler Weight Not Validated |
| 499 | CF-499 | 2.80 | S2 | medium | B | XDP Uses capable |
| 500 | CF-500 | 2.80 | S2 | medium | C | XDP Uses capable() Instead of ns_capable() |
| 501 | CF-501 | 1.00 | S3 | high | A,B,C | Batch Crypto Allocates Per-Packet Temporary Buffer |
| 502 | CF-502 | 1.00 | S3 | high | A,B,C | Certificate Chain Length Limit Checked Late |
| 503 | CF-503 | 1.00 | S3 | high | A,B,C | Duplicate MODULE_DESCRIPTION in quic_exfil.c |
| 504 | CF-504 | 1.00 | S3 | high | A,B,C | Duplicate Static Functions: h3_varint_encode/decode |
| 505 | CF-505 | 1.00 | S3 | high | A,B,C | HTTP/3 Priority: push_buckets Not Initialized |
| 506 | CF-506 | 1.00 | S3 | high | A,B,C | Key Update Timeout Revert Could Race With Concurrent Update |
| 507 | CF-507 | 1.00 | S3 | high | A,B,C | Load Balancer Stack Buffers for Feistel Not Zeroized on Error |
| 508 | CF-508 | 1.00 | S3 | high | A,B,C | Module Parameters Expose Security Configuration |
| 509 | CF-509 | 1.00 | S3 | high | A,B,C | Netlink Events Do Not Include Timestamp |
| 510 | CF-510 | 1.00 | S3 | high | A,B,C | Netlink Family Exported as EXPORT_SYMBOL_GPL |
| 511 | CF-511 | 1.00 | S3 | high | A,B,C | Per-CPU Stats Not Protected Against Torn Reads on 32-bit |
| 512 | CF-512 | 1.00 | S3 | high | A,B,C | Procfs trusted_cas File Writable Without Capability Check |
| 513 | CF-513 | 1.00 | S3 | high | A,B,C | Qlog: Lock Drop Around copy_to_user |
| 514 | CF-514 | 1.00 | S3 | high | A,B,C | Unused HKDF-Expand Output in Extended Key Update |
| 515 | CF-515 | 1.00 | S3 | high | A,B,C | Volatile Qualifiers in Constant-Time Functions May Be Insufficient |
| 516 | CF-516 | 1.00 | S3 | high | B,C | `established_time` Set Twice in Connection State Machine |
| 517 | CF-517 | 1.00 | S3 | high | B,C | `sk->sk_err = -ret` Stores Negative Error Code |
| 518 | CF-518 | 1.00 | S3 | high | B,C | `tquic_cid_compare()` Marked `__maybe_unused` |
| 519 | CF-519 | 1.00 | S3 | high | B,C | `tquic_cid_retire()` Sends RETIRE_CONNECTION_ID After Retirement |
| 520 | CF-520 | 1.00 | S3 | high | B,C | `tquic_debug.c` CID Hex Loop Bound |
| 521 | CF-521 | 1.00 | S3 | high | B,C | `tquic_hs_cleanup` -- does not zeroize exporter_secret and resumption_secret |
| 522 | CF-522 | 1.00 | S3 | high | B,C | `tquic_hs_generate_client_hello` -- client random not checked for all-zero |
| 523 | CF-523 | 1.00 | S3 | high | B,C | `tquic_hs_get_handshake_secrets` and `tquic_hs_get_app_secrets` -- no output buffer size validation |
| 524 | CF-524 | 1.00 | S3 | high | B,C | `tquic_hs_process_certificate_verify` hardcodes "server CertificateVerify" string |
| 525 | CF-525 | 1.00 | S3 | high | B,C | `tquic_hs_process_new_session_ticket` -- ignores extensions |
| 526 | CF-526 | 1.00 | S3 | high | B,C | `tquic_server_check_path_recovery()` Uses `goto restart` Pattern |
| 527 | CF-527 | 1.00 | S3 | high | B,C | `tquic_store_session_ticket()` Does Not Store ALPN or Transport Parameters |
| 528 | CF-528 | 1.00 | S3 | high | B,C | `tquic_sysctl_prefer_v2()` Function Not Declared in Visible Header |
| 529 | CF-529 | 1.00 | S3 | high | A,B | AF_XDP frame pool uses spinlock for every frame alloc/free |
| 530 | CF-530 | 1.00 | S3 | high | B,C | bench/benchmark.c -- kvmalloc used correctly with kvfree |
| 531 | CF-531 | 1.00 | S3 | high | A,B | Benchmark Code: Userspace, Not Kernel |
| 532 | CF-532 | 1.00 | S3 | high | B,C | CID Table Initialization Not Thread-Safe |
| 533 | CF-533 | 1.00 | S3 | high | B,C | close_work Repurposes drain_work for Retransmit Scheduling |
| 534 | CF-534 | 1.00 | S3 | high | B,C | Consistent use of kfree_sensitive for key material -- GOOD |
| 535 | CF-535 | 1.00 | S3 | high | B,C | Constant-Time Comparison Used for Integrity Tags |
| 536 | CF-536 | 1.00 | S3 | high | B,C | Context Set Level Does Not Check init Return Values |
| 537 | CF-537 | 1.00 | S3 | high | B,C | CRYPTO_TFM_REQ_MAY_BACKLOG in Atomic Context |
| 538 | CF-538 | 1.00 | S3 | high | B,C | crypto_wait_req May Sleep in Encrypt/Decrypt Hot Path |
| 539 | CF-539 | 1.00 | S3 | high | B,C | Empty Hash Computed Without Algorithm Validation |
| 540 | CF-540 | 1.00 | S3 | high | B,C | h3_varint_len Defined Multiple Times as Static |
| 541 | CF-541 | 1.00 | S3 | high | B,C | HMAC Output Not Zeroized on Fallback Path |
| 542 | CF-542 | 1.00 | S3 | high | B,C | Inconsistent Error Return From verify_chain |
| 543 | CF-543 | 1.00 | S3 | high | B,C | io_uring.c getsockopt Same len Validation Pattern |
| 544 | CF-544 | 1.00 | S3 | high | B,C | Lock Drop/Re-acquire Pattern in Key Derivation |
| 545 | CF-545 | 1.00 | S3 | high | A,B | LOW: pacing_calc_gap uses division |
| 546 | CF-546 | 1.00 | S3 | high | A,B | LOW: Prague RTT scaling division on every ACK |
| 547 | CF-547 | 1.00 | S3 | high | B,C | memzero_explicit Used Correctly for Key Material |
| 548 | CF-548 | 1.00 | S3 | high | A,B | Minimal tracepoint overhead |
| 549 | CF-549 | 1.00 | S3 | high | B,C | Missing Error Check for init_net Reference |
| 550 | CF-550 | 1.00 | S3 | high | B,C | Missing lockdep Annotations |
| 551 | CF-551 | 1.00 | S3 | high | B,C | Multipath Nonce Construction -- Potential Nonce Reuse Across Paths |
| 552 | CF-552 | 1.00 | S3 | high | B,C | Multiple Redundant Varint Implementations |
| 553 | CF-553 | 1.00 | S3 | high | B,C | Netlink Operations All Require GENL_ADMIN_PERM |
| 554 | CF-554 | 1.00 | S3 | high | B,C | nla_put Operations in Netlink Properly Handle Failure |
| 555 | CF-555 | 1.00 | S3 | high | B,C | parse_basic_constraints Hardcoded BOOLEAN Length |
| 556 | CF-556 | 1.00 | S3 | high | B,C | Path Validation Response Queue Uses Two Tracking Mechanisms |
| 557 | CF-557 | 1.00 | S3 | high | B,C | quic_exfil.c Decoy Packet Size Controlled by MTU |
| 558 | CF-558 | 1.00 | S3 | high | B,C | Redundant Lock in tquic_bonding_get_state |
| 559 | CF-559 | 1.00 | S3 | high | B,C | Retry Integrity Tag Computed with Potentially-Failing AEAD |
| 560 | CF-560 | 1.00 | S3 | high | B,C | SAN Parsing Capacity Limit Check Could Be Tighter |
| 561 | CF-561 | 1.00 | S3 | high | B,C | Scheduler Lock Uses spin_lock Without _bh |
| 562 | CF-562 | 1.00 | S3 | high | B,C | server_ticket_key Is Static Global Without Rotation |
| 563 | CF-563 | 1.00 | S3 | high | B,C | Slab Cache Names Are Not Module-Prefixed |
| 564 | CF-564 | 1.00 | S3 | high | B,C | Stream ID Right-Shift Comparison |
| 565 | CF-565 | 1.00 | S3 | high | B,C | tquic_conn_destroy -- thorough cleanup |
| 566 | CF-566 | 1.00 | S3 | high | B,C | tquic_ipv6.c MTU Info getsockopt |
| 567 | CF-567 | 1.00 | S3 | high | B,C | tquic_main.c init -- correct cascading cleanup |
| 568 | CF-568 | 1.00 | S3 | high | B,C | tquic_output_flush Holds conn->lock While Calling GFP_ATOMIC Allocation |
| 569 | CF-569 | 1.00 | S3 | high | B,C | tquic_pacing_cleanup -- correct ordering |
| 570 | CF-570 | 1.00 | S3 | high | B,C | tquic_retry_rate_limit Potential Token Bucket Underflow |
| 571 | CF-571 | 1.00 | S3 | high | B,C | tquic_stream_manager_destroy Does Not Free Extended State for All Streams |
| 572 | CF-572 | 1.00 | S3 | high | B,C | tquic_timer_state_alloc -- cleanup loop is correct |
| 573 | CF-573 | 1.00 | S3 | high | B,C | tquic_timer_state_free -- thorough and correct |
| 574 | CF-574 | 1.00 | S3 | high | B,C | Version Negotiation First Byte Missing Fixed Bit Randomization |
| 575 | CF-575 | 1.00 | S3 | high | B,C | Version Negotiation Packet Size Not Validated Against 256-Byte Buffer |
| 576 | CF-576 | 1.00 | S3 | high | B,C | Version Negotiation Response - dcid/scid_len Not Capped |
| 577 | CF-577 | 1.00 | S3 | high | B,C | Workqueue Not Validated Before Use |
| 578 | CF-578 | 1.00 | S3 | high | A,B | XOR FEC encoding is efficient |
| 579 | CF-579 | 1.00 | S3 | high | B | `bench_latency.c` Allocation Without Overflow Check |
| 580 | CF-580 | 1.00 | S3 | high | B | CPU-3: CID pool active count enumeration. |
| 581 | CF-581 | 1.00 | S3 | high | B | spin_lock |
| 582 | CF-582 | 1.00 | S3 | high | B | tquic_build_short_header_internal Writes pkt_num to buf+64 Scratch Space |
| 583 | CF-583 | 1.00 | S3 | high | B | tquic_gso_init Integer Overflow in Allocation Size |
| 584 | CF-584 | 1.00 | S3 | high | B | UAF-ADD-02: - CID pool rotation_work vs pool destruction race window |
| 585 | CF-585 | 0.70 | S3 | medium | B | `bench_common.c` Variance Calculation |
| 586 | CF-586 | 0.70 | S3 | medium | C | `bench_common.c` Variance Calculation (Userspace Code) |
| 587 | CF-587 | 0.70 | S3 | medium | C | `bench_latency.c` Allocation Without Overflow Check (Userspace Code) |
| 588 | CF-588 | 0.70 | S3 | medium | B | `tquic_accept()` Nested Locking Pattern |
| 589 | CF-589 | 0.70 | S3 | medium | B | `tquic_sock_listen()` Redundant `INIT_LIST_HEAD` Check |
| 590 | CF-590 | 0.70 | S3 | medium | B | `tquic_stateless_reset_detect()` Iterates All Tokens Non-Constant-Time |
| 591 | CF-591 | 0.70 | S3 | medium | B | Aggregate Scheduler Long Spinlock Hold |
| 592 | CF-592 | 0.70 | S3 | medium | C | Benchmark Code: Userspace, Not Kernel |
| 593 | CF-593 | 0.70 | S3 | medium | B | BPM Path Metrics min_rtt Initialized to UINT_MAX |
| 594 | CF-594 | 0.70 | S3 | medium | B | C99 Variable Declaration in Loop |
| 595 | CF-595 | 0.70 | S3 | medium | B | Constant-Time Comparison |
| 596 | CF-596 | 0.70 | S3 | medium | B | Coupled CC Alpha Smoothing May Suppress Rapid Changes |
| 597 | CF-597 | 0.70 | S3 | medium | C | Coupled CC Alpha Smoothing May Suppress Rapid Changes |
| 598 | CF-598 | 0.70 | S3 | medium | B | CPU-6: The QPACK decoder accepts a `max_table_capacity` parameter from the peer via SETTINGS. While the sysctl caps the local maximum at 1MB, the actual limit used should be `min(peer_requested, local |
| 599 | CF-599 | 0.70 | S3 | medium | B | CROSS-2: Consider using the `tquic_rx_buf_cache` slab cache pattern (already used at `tquic_input.c:2586`) more broadly for hot-path allocations to reduce GFP_ATOMIC pressure. |
| 600 | CF-600 | 0.70 | S3 | medium | B | Debug Logging of Packet Contents |
| 601 | CF-601 | 0.70 | S3 | medium | B | Failover Sent Packet Count Can Go Negative |
| 602 | CF-602 | 0.70 | S3 | medium | B | INFO-1: Several `pr_debug`/`tquic_dbg` calls include connection state information. While these are compile-time optional, in debug builds they could leak timing information about connection state to a |
| 603 | CF-603 | 0.70 | S3 | medium | B | MEM-3: The NF connection tracking limit (65536) has no per-source-IP limit at the netfilter layer. While the TQUIC protocol layer has per-IP limits, the NF `tquic_nf_conn_alloc` at line 497 only check |
| 604 | CF-604 | 0.70 | S3 | medium | B | MEM-4: While stream count is limited, each stream allocates both `send_buf` and `recv_buf` skb queues. An attacker opening `max_streams_bidi` streams and sending minimal data to each creates per-strea |
| 605 | CF-605 | 0.70 | S3 | medium | B | Missing Documentation on Lock Ordering |
| 606 | CF-606 | 0.70 | S3 | medium | B | Multicast Group Only Requires CAP_NET_ADMIN |
| 607 | CF-607 | 0.70 | S3 | medium | B | Multiple Scheduler Registration Systems Coexist |
| 608 | CF-608 | 0.70 | S3 | medium | B | Multiple Varint Implementations |
| 609 | CF-609 | 0.70 | S3 | medium | B | Netlink Attribute Policy Does Not Use Strict Validation for Binary Addresses |
| 610 | CF-610 | 0.70 | S3 | medium | B | No Per-Connection Frame Processing Budget |
| 611 | CF-611 | 0.70 | S3 | medium | B | Path Validation Timer del_timer vs del_timer_sync |
| 612 | CF-612 | 0.70 | S3 | medium | B | Priority Extension Allocation Race |
| 613 | CF-613 | 0.70 | S3 | medium | B | PROTO-1: The retire loop at `tquic_cid.c:667-674` iterates the entire remote CID list for each NEW_CONNECTION_ID frame, marking CIDs as retired. While bounded by `active_connection_id_limit`, repeated |
| 614 | CF-614 | 0.70 | S3 | medium | B | Repair Data Pointer Lifetime |
| 615 | CF-615 | 0.70 | S3 | medium | C | send_skb Variable Used After Potential NULL |
| 616 | CF-616 | 0.70 | S3 | medium | B | Sensitive Key Cleanup |
| 617 | CF-617 | 0.70 | S3 | medium | B | settings seen_mask Limited to 64 Settings |
| 618 | CF-618 | 0.70 | S3 | medium | C | spin_lock (Not spin_lock_bh) Used in tquic_process_max_data_frame (tquic_input.c, lines 1015-1017) |
| 619 | CF-619 | 0.70 | S3 | medium | B | STATE-2: An attacker could open connections, complete the handshake (consuming 1 connection per client rate token), then keep them alive by sending a PING frame every 29 seconds. With default 100 conn |
| 620 | CF-620 | 0.70 | S3 | medium | B | STATE-3: No visible limit on the number of paths per connection. If an attacker can trigger path creation (via connection migration or multipath signaling), each new path creates timers and state. |
| 621 | CF-621 | 0.70 | S3 | medium | B | Stateless Reset Token Comparison Timing |
| 622 | CF-622 | 0.70 | S3 | medium | B | Stream Creation Not Bounded in Input Path |
| 623 | CF-623 | 0.70 | S3 | medium | B | timer_setup with NULL Callback |
| 624 | CF-624 | 0.70 | S3 | medium | C | tquic_build_short_header_internal Writes pkt_num to buf+64 Scratch Space (tquic_output.c, line 818) |
| 625 | CF-625 | 0.70 | S3 | medium | C | tquic_encap_recv Double UDP Header Strip |
| 626 | CF-626 | 0.70 | S3 | medium | B | tquic_encode_varint Does Not Validate val Range |
| 627 | CF-627 | 0.70 | S3 | medium | C | tquic_encode_varint Does Not Validate val Range (tquic_output.c, lines 164-198) |
| 628 | CF-628 | 0.70 | S3 | medium | C | tquic_gso_init Integer Overflow in Allocation Size (tquic_output.c, line 1489) |
| 629 | CF-629 | 0.70 | S3 | medium | B | tquic_process_ack_frame Does Not Validate largest_ack vs first_ack_range |
| 630 | CF-630 | 0.70 | S3 | medium | C | tquic_process_ack_frame Does Not Validate largest_ack vs first_ack_range (tquic_input.c, lines 601-660) |
| 631 | CF-631 | 0.70 | S3 | medium | B | tquic_process_coalesced Missing Infinite Loop Guard |
| 632 | CF-632 | 0.70 | S3 | medium | C | tquic_process_coalesced Missing Infinite Loop Guard (tquic_input.c, lines 3079-3182) |
| 633 | CF-633 | 0.70 | S3 | medium | B | tquic_sched_release Frees ext Under Lock but kfree Can Sleep |
| 634 | CF-634 | 0.70 | S3 | medium | B | tquic_stream_alloc Uses GFP_KERNEL in Potentially Atomic Context |
| 635 | CF-635 | 0.70 | S3 | medium | B | tquic_stream_release Missing Error Return |
| 636 | CF-636 | 0.70 | S3 | medium | B | tquic_stream_set_priority Missing Lock Protection |
| 637 | CF-637 | 0.70 | S3 | medium | B | Weighted DRR Iterates Over Empty Slots |
| 638 | CF-638 | 0.40 | S3 | low | C | ACK Frequency Frame Type Inconsistency |
| 639 | CF-639 | 0.40 | S3 | low | C | copy_from_sockptr in setsockopt Always Uses sizeof(type) |
| 640 | CF-640 | 0.40 | S3 | low | B | Diagnostic Counter Wraps |
| 641 | CF-641 | 0.40 | S3 | low | B | Error Codes Leak Processing State |
| 642 | CF-642 | 0.40 | S3 | low | C | IMMEDIATE_ACK Frame Type Similar Issue |
| 643 | CF-643 | 0.40 | S3 | low | C | Inconsistent Congestion State Layouts |
| 644 | CF-644 | 0.40 | S3 | low | C | Multiple Varint Implementations (Code Duplication Risk) |
| 645 | CF-645 | 0.40 | S3 | low | C | Three Parallel Scheduler Frameworks |

## B) Missing Evidence Checklist

### CF-001 - Adaptive Scheduler cwnd_avail Underflow
- [ ] Capture exact line range(s) where the fault manifests.

### CF-002 - Buffer Overflow in ClientHello Extension Building
- [ ] Capture exact line range(s) where the fault manifests.

### CF-003 - Client Certificate Verification Uses Server Logic
- [ ] No major evidence gaps detected.

### CF-004 - Connection Destroy Calls Sleeping Function Under Spinlock
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-005 - Fragile Hardcoded Offset for Key Update State Access
- [ ] Capture exact line range(s) where the fault manifests.

### CF-006 - HTTP/3 Stream Lookup: Use-After-Free
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-007 - OCSP Stapling Response Accepted Without Any Verification
- [ ] Capture exact line range(s) where the fault manifests.

### CF-008 - Path Metrics Netlink: Unbounded Allocation from Attacker-Influenced Value
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-009 - QPACK Dynamic Table Duplicate: Use-After-Free via Lock Drop
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-010 - Self-Signed Certificate Comparison Uses Non-Constant-Time memcmp in One Path
- [ ] No major evidence gaps detected.

### CF-011 - Stack Buffer Overflow in HKDF-Expand-Label
- [ ] Include a minimal code snippet proving the issue.

### CF-012 - Stream Data Queued Before Validation Check
- [ ] No major evidence gaps detected.

### CF-013 - `tquic_close()` Does Not Hold `lock_sock()` During Connection Teardown
- [ ] Capture exact line range(s) where the fault manifests.

### CF-014 - `tquic_hs_process_certificate` -- integer underflow in `certs_len` tracking
- [ ] No major evidence gaps detected.

### CF-015 - `tquic_hs_process_new_session_ticket` -- nonce overflow into session ticket
- [ ] No major evidence gaps detected.

### CF-016 - `tquic_hs_process_server_hello` -- missing bounds check before compression byte read
- [ ] Capture exact line range(s) where the fault manifests.

### CF-017 - `tquic_shutdown()` Missing `lock_sock()` -- Race on Connection State
- [ ] Capture exact line range(s) where the fault manifests.

### CF-018 - `tquic_varint_len()` Returns 0 for Invalid Values Without Error Propagation
- [ ] Capture exact line range(s) where the fault manifests.

### CF-019 - Adaptive Feedback Uses Path After list_for_each_entry Exit
- [ ] Capture exact line range(s) where the fault manifests.

### CF-020 - ASN.1 Time Parsing Does Not Validate Character Ranges
- [ ] Capture exact line range(s) where the fault manifests.

### CF-021 - Authentication Bypass in QUIC-Aware Proxy
- [ ] Capture exact line range(s) where the fault manifests.

### CF-022 - BLEST Inconsistent Locking -- 3 of 6 Callbacks Lack Lock
- [ ] Capture exact line range(s) where the fault manifests.

### CF-023 - Busy-poll per-packet lock/unlock
- [ ] No major evidence gaps detected.

### CF-024 - Capsule Buffer Size Addition Overflow
- [ ] No major evidence gaps detected.

### CF-025 - Complete SSRF in CONNECT-UDP -- No Address Validation
- [ ] Capture exact line range(s) where the fault manifests.

### CF-026 - ECF Scheduler Declares Lock But Never Uses It
- [ ] Capture exact line range(s) where the fault manifests.

### CF-027 - ECN CE Count Processing Does Not Track Deltas
- [ ] Capture exact line range(s) where the fault manifests.

### CF-028 - GSO Segment Accumulation Can Overflow SKB Tailroom
- [ ] No major evidence gaps detected.

### CF-029 - GSO SKB Allocation Multiplication Overflow
- [ ] No major evidence gaps detected.

### CF-030 - Handshake Packet Parsing with Unvalidated Offsets
- [ ] No major evidence gaps detected.

### CF-031 - Hard-Fail Revocation Mode Does Not Actually Fail
- [ ] Capture exact line range(s) where the fault manifests.

### CF-032 - Hardcoded init_net Namespace Bypass in Socket Creation
- [ ] Capture exact line range(s) where the fault manifests.

### CF-033 - Install Secrets Accesses State Without Lock After Unlock
- [ ] No major evidence gaps detected.

### CF-034 - Integer overflow in `tquic_hs_build_ch_extensions` PSK identity length calculations
- [ ] No major evidence gaps detected.

### CF-035 - Load Balancer Plaintext Mode Exposes Server ID
- [ ] Capture exact line range(s) where the fault manifests.

### CF-036 - Missing RFC 1918 / Private Network Filtering in IPv4 SSRF Checks
- [ ] Capture exact line range(s) where the fault manifests.

### CF-037 - Missing SKB Tailroom Check in Coalesced Packet Output
- [ ] No major evidence gaps detected.

### CF-038 - Nested Lock Hierarchy Violation in Timer Code
- [ ] No major evidence gaps detected.

### CF-039 - Netfilter Hooks Registered Only in init_net
- [ ] Capture exact line range(s) where the fault manifests.

### CF-040 - No Address Validation in CONNECT-IP Packet Injection
- [ ] Capture exact line range(s) where the fault manifests.

### CF-041 - No Privilege Check for TQUIC Socket Creation
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-042 - No Privilege Checks for Security-Sensitive Socket Options
- [ ] Include a minimal code snippet proving the issue.

### CF-043 - No security_socket_* Hook Invocations
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-044 - PADDING Frame Infinite Skip Without Bound on Encrypted Payload
- [ ] No major evidence gaps detected.

### CF-045 - Path Pointer Use After Lock Release
- [ ] No major evidence gaps detected.

### CF-046 - Per-frame kzalloc + kmalloc in TX path
- [ ] No major evidence gaps detected.

### CF-047 - Per-Packet crypto_aead_setkey on Shared AEAD Handle -- Race Condition
- [ ] No major evidence gaps detected.

### CF-048 - Priority PRIORITY_UPDATE Parsing Off-by-Two in Loop Bound
- [ ] No major evidence gaps detected.

### CF-049 - QPACK Decoder Stack Buffer Overflow via Large Headers
- [ ] Capture exact line range(s) where the fault manifests.

### CF-050 - quic_packet.c Stream Frame - Uncapped Stream Creation
- [ ] No major evidence gaps detected.

### CF-051 - Race Condition Between `tquic_destroy_sock()` and Poll/Sendmsg/Recvmsg
- [ ] No major evidence gaps detected.

### CF-052 - Retry Token Address Validation Uses Non-Constant-Time Comparison
- [ ] Capture exact line range(s) where the fault manifests.

### CF-053 - Retry Token Validation -- Plaintext Buffer Overread
- [ ] No major evidence gaps detected.

### CF-054 - Server Accept CID Parsing Missing Bounds Checks -- Buffer Over-Read
- [ ] No major evidence gaps detected.

### CF-055 - Slab Cache Decryption Buffer May Be Too Small for Payload
- [ ] No major evidence gaps detected.

### CF-056 - Sleep-in-Atomic Context
- [ ] No major evidence gaps detected.

### CF-057 - SSRF via IPv4-Mapped IPv6 Addresses Bypasses Address Filtering
- [ ] Capture exact line range(s) where the fault manifests.

### CF-058 - Stack buffer overflow in `tquic_hs_hkdf_expand_label` -- unbounded label/context write to 512-byte stack buffer
- [ ] No major evidence gaps detected.

### CF-059 - Stateless Reset Bypasses State Machine
- [ ] No major evidence gaps detected.

### CF-060 - Stream Data Delivery Uses u64 Length with u32 alloc_skb
- [ ] No major evidence gaps detected.

### CF-061 - tquic_conn_server_accept() -- err_free leaks registered CIDs, work items, timers, crypto state
- [ ] No major evidence gaps detected.

### CF-062 - tquic_conn_server_accept() -- overrides actual error code with -EINVAL
- [ ] Capture exact line range(s) where the fault manifests.

### CF-063 - tquic_send_connection_close() -- SKB leak and unencrypted packet on header failure
- [ ] Capture exact line range(s) where the fault manifests.

### CF-064 - tquic_stream_sendmsg Writes to Stream Without Connection Refcount on Stream
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-065 - Transcript Buffer Reallocation Doubling Overflow
- [ ] No major evidence gaps detected.

### CF-066 - Tunnel Uses init_net -- Namespace Escape
- [ ] Capture exact line range(s) where the fault manifests.

### CF-067 - Unbounded Memory Allocation from Attacker-Controlled Capsule Length
- [ ] Capture exact line range(s) where the fault manifests.

### CF-068 - Use-After-Free in Path Lookup
- [ ] No major evidence gaps detected.

### CF-069 - Version Negotiation Packet Overflow -- Unsanitized CID Lengths in tquic_send_version_negotiation
- [ ] No major evidence gaps detected.

### CF-070 - WebTransport Close Capsule Large Stack Allocation
- [ ] Capture exact line range(s) where the fault manifests.

### CF-071 - AF_XDP Socket and Device Lookup Use init_net
- [ ] Get independent confirmation from a second report/source.

### CF-072 - conn->sk Accessed Without Lock After Stateless Reset
- [ ] Get independent confirmation from a second report/source.

### CF-073 - Integer Overflow in bytes_acked Calculation
- [ ] Get independent confirmation from a second report/source.

### CF-074 - Missing Lock in `tquic_sock_bind()` -- Race with `tquic_connect()`
- [ ] Get independent confirmation from a second report/source.

### CF-075 - Missing Upper Bound on Coalesced Packet Count
- [ ] Get independent confirmation from a second report/source.

### CF-076 - Packet Number Length Extracted Before Header Unprotection
- [ ] Get independent confirmation from a second report/source.

### CF-077 - QUIC-over-TCP Client and Server Sockets Use init_net
- [ ] Get independent confirmation from a second report/source.

### CF-078 - Refcount Underflow in Netlink Path Creation
- [ ] Get independent confirmation from a second report/source.

### CF-079 - Stale skb->len Read After ip_local_out
- [ ] Get independent confirmation from a second report/source.

### CF-080 - State Machine Type Confusion via `conn->state_machine` Void Pointer
- [ ] Get independent confirmation from a second report/source.

### CF-081 - Stream Lookup Returns Pointer Without Refcount -- Use-After-Free
- [ ] Get independent confirmation from a second report/source.

### CF-082 - TOCTOU Race in Failover Hysteresis
- [ ] Get independent confirmation from a second report/source.

### CF-083 - TQUIC_NEW_STREAM Missing Reserved Field Zeroing Check
- [ ] Get independent confirmation from a second report/source.

### CF-084 - UAF-P1-01: - SmartNIC tquic_nic_find() returns pointer without reference
- [ ] Get independent confirmation from a second report/source.

### CF-085 - Use-After-Free in Connect
- [ ] Get independent confirmation from a second report/source.

### CF-086 - Wrong Network Namespace in ip_local_out
- [ ] Get independent confirmation from a second report/source.

### CF-087 - (actual): `tquic_hs_process_server_hello` -- missing check before cipher suite read
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-088 - (Revised): tquic_process_packet Does Not Validate pkt_num_len Against Remaining Data (tquic_input.c, lines 2528-2529, 2572-2574)
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-089 - ACK Range Failover Can Iterate Over Unbounded Packet Number Range
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-090 - AF_XDP Socket and Device Lookup Use init_net (Container Escape)
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-091 - Attacker-Controlled Allocation Sizes
- [ ] Pinpoint at least one concrete source file path.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-092 - CID demux/lookup appears non-functional: the RX path uses one table, while connection creation populates different tables
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-093 - Client Certificate Verification Uses Server Logic (EKU Bypass)
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-094 - conn->sk Accessed Without Lock After Stateless Reset (tquic_input.c, lines 397-407)
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-095 - Connection State Transition Not Fully Atomic
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-096 - Connection State Transition Not Fully Atomic
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-097 - Excessive Stack Usage in RS Recovery
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-098 - Global connection hashtable (`tquic_conn_table`) is initialized and removed-from, but never inserted-into
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-099 - Header protection outputs are ignored; packet-number length + key phase are derived from protected header
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-100 - Huffman Decoder O(n*256) Algorithmic Complexity DoS
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-101 - Integer Overflow in Coupled CC Increase Calculation
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-102 - IPv4/IPv6 Address Discovery Enumerates Host Interfaces
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-103 - IPv4/IPv6 Address Discovery Enumerates Host Interfaces (Container Escape / Info Leak)
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-104 - List Iterator Invalidation in BPM Netdev Notifier
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-105 - List Iterator Invalidation in BPM Netdev Notifier (Drop-Relock Pattern)
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-106 - MASQUE CONNECT-UDP Proxy Creates Sockets in init_net
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-107 - MASQUE CONNECT-UDP Proxy Creates Sockets in init_net (Container Escape)
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-108 - Missing Bounds Check Before Frame Type Read
- [ ] Pinpoint at least one concrete source file path.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-109 - Packet Number Length Extracted Before Header Unprotection (tquic_input.c, lines 2529, 2545 vs 2565)
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-110 - Packet number reconstruction always uses `largest_pn = 0`
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-111 - Potential Integer Overflow in CRYPTO Frame on 32-bit
- [ ] Pinpoint at least one concrete source file path.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-112 - QPACK Dynamic Table Duplicate TOCTOU Race
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-113 - QUIC-Exfil mitigation code uses `skb->cb` as a function-pointer slot and gates on `skb->cb[0]`
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-114 - QUIC-over-TCP Client and Server Sockets Use init_net (Container Escape)
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-115 - Rate Calculation Integer Overflow
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-116 - Rate Calculation Integer Overflow (`count * 1000`)
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-117 - Reason Length Underflow on 32-bit
- [ ] Pinpoint at least one concrete source file path.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-118 - Redundant Scheduler Deduplication Uses Only 8-bit Sequence Hash -- Trivial Collision
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-119 - Reference counting/RCU lifetime is not actually enforced; direct `tquic_conn_destroy()` calls can free live connections
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-120 - rhashtable/RCU lifetime issues (use-after-free risk) in CID tables
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-121 - RX parsing/decryption assumes contiguous skb data (non-linear skb / GRO risk)
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-122 - Same Overflow in OLIA Increase Path
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-123 - Stale skb->len Read After ip_local_out (tquic_output.c, lines 1730-1736)
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-124 - TOCTOU Race in Failover Hysteresis (Atomic Read-Modify-Write)
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-125 - Tunnel Socket Creation Uses init_net
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-126 - Tunnel Socket Creation Uses init_net (Container Escape)
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-127 - UAF-P2-01: - SKB accessed after udp_tunnel_xmit_skb
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-128 - UAF-P3-01: - retransmit_work_fn accesses ts->conn without connection reference
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-129 - UAF-P3-02: - path_work_fn accesses ts->conn without reference
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-130 - Use-After-Free in `tquic_migrate_auto()` -- RCU-Protected Path Used After RCU Unlock
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-131 - Use-After-Free in `tquic_migrate_explicit()` -- Path Used Without Reference
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-132 - Use-After-Free in Algorithm Name Return
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-133 - Use-After-Free in Path Lookup (tquic_input.c, lines 245-261)
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-134 - Widespread allocator mismatches (kmem_cache vs kzalloc/kfree) for core objects (conn/path/stream)
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-135 - Wrong Network Namespace in ip_local_out (tquic_output.c, line 1730)
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-136 - `ext->final_size = -1` Uses Signed Overflow
- [ ] Capture exact line range(s) where the fault manifests.

### CF-137 - Constant-Time CID Validation Has Branching on Lengths
- [ ] No major evidence gaps detected.

### CF-138 - Custom ASN.1 Parser - High Attack Surface
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-139 - Function Pointer Stored in skb->cb Without Validation
- [ ] No major evidence gaps detected.

### CF-140 - HTTP/3 Request: TOCTOU Between State Check and Send
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-141 - HTTP/3 Settings Frame Length Truncation
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-142 - Load Balancer Encryption Key Not Zeroized on Destroy
- [ ] Capture exact line range(s) where the fault manifests.

### CF-143 - No CAP_NET_ADMIN Check for Tunnel Creation
- [ ] Capture exact line range(s) where the fault manifests.

### CF-144 - Path Metrics Netlink: Missing CAP_NET_ADMIN Permission Check
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-145 - Per-Call crypto_aead_setkey in Encrypt/Decrypt Hot Path
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-146 - Per-Call crypto_alloc_aead in 0-RTT Encrypt/Decrypt
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-147 - QPACK Decoder: Unbounded Blocked Stream Memory Exhaustion
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-148 - QPACK Encoder: Insert Count Increment Overflow
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-149 - Race Condition in Key Update Secret Installation
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-150 - RSA-PSS Hash Algorithm Hardcoded to SHA-256
- [ ] Capture exact line range(s) where the fault manifests.

### CF-151 - Secrets not zeroized on error paths in key derivation functions
- [ ] No major evidence gaps detected.

### CF-152 - Stream State Machine Allows Unexpected Transitions from OPEN
- [ ] Capture exact line range(s) where the fault manifests.

### CF-153 - Timing Normalization Can Block in Packet Processing Path
- [ ] Capture exact line range(s) where the fault manifests.

### CF-154 - Unbounded Connection Creation via Netlink
- [ ] Capture exact line range(s) where the fault manifests.

### CF-155 - WebTransport Context Destroy: Lock Drop During Iteration
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-156 - WebTransport: Unbounded Capsule Buffer Growth
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-157 - `quic_offload.c` Version Field Shift Without Cast
- [ ] No major evidence gaps detected.

### CF-158 - `tquic_cid_pool_destroy()` Removes from rhashtable Under BH spinlock
- [ ] Capture exact line range(s) where the fault manifests.

### CF-159 - `tquic_conn_retire_cid()` Does Not Remove CID from Lookup Hash Table
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-160 - `tquic_hs_build_ch_extensions` -- ALPN extension length written as 2-byte but can overflow u16
- [ ] No major evidence gaps detected.

### CF-161 - `tquic_hs_cleanup` -- potential double-free of session ticket
- [ ] Capture exact line range(s) where the fault manifests.

### CF-162 - `tquic_hs_generate_client_hello` -- output buffer `buf` not validated for minimum size
- [ ] Include a minimal code snippet proving the issue.

### CF-163 - `tquic_hs_hkdf_expand_label` -- `context_len` truncated to u8
- [ ] No major evidence gaps detected.

### CF-164 - `tquic_hs_process_encrypted_extensions` -- ALPN validation insufficient
- [ ] Capture exact line range(s) where the fault manifests.

### CF-165 - `tquic_hs_process_new_session_ticket` -- memory leak of old ticket data on re-entry
- [ ] No major evidence gaps detected.

### CF-166 - `tquic_hs_process_server_hello` -- session ID comparison not fully bounds-safe
- [ ] No major evidence gaps detected.

### CF-167 - `tquic_hs_setup_psk` -- integer overflow in ticket age calculation
- [ ] Capture exact line range(s) where the fault manifests.

### CF-168 - `tquic_recvmsg()` Same Issue as HIGH-07
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-169 - accept() Uses spin_lock_bh on sk_lock.slock While lock_sock() Is Held
- [ ] No major evidence gaps detected.

### CF-170 - Anti-Amplification Integer Overflow
- [ ] Capture exact line range(s) where the fault manifests.

### CF-171 - atomic_sub on sk_rmem_alloc Incompatible with refcount_t
- [ ] Capture exact line range(s) where the fault manifests.

### CF-172 - BBRv2 Inflight Calculation Truncation
- [ ] Capture exact line range(s) where the fault manifests.

### CF-173 - Bloom Filter Has High False Positive Rate at Scale
- [ ] No major evidence gaps detected.

### CF-174 - Bonding State Machine Drop-Relock Without Re-validation
- [ ] No major evidence gaps detected.

### CF-175 - CID Lookup Returns Connection Without Reference Count
- [ ] Capture exact line range(s) where the fault manifests.

### CF-176 - Coalesced Packet Splitting Assumes v1 Packet Type Encoding
- [ ] Capture exact line range(s) where the fault manifests.

### CF-177 - conn->lock held during path selection on every TX packet
- [ ] No major evidence gaps detected.

### CF-178 - conn->lock released and reacquired during output flush stream iteration
- [ ] No major evidence gaps detected.

### CF-179 - conn->paths_lock in RX path for every packet
- [ ] No major evidence gaps detected.

### CF-180 - CONNECTION_CLOSE uses kmalloc for small buffer
- [ ] No major evidence gaps detected.

### CF-181 - const-Correctness Violation in Proxy Packet Decode
- [ ] Capture exact line range(s) where the fault manifests.

### CF-182 - copy_from_user with User-Controlled Size in Socket Options
- [ ] Capture exact line range(s) where the fault manifests.

### CF-183 - ECN Counter Values Passed Directly to TQUIC_ADD_STATS Without Overflow Check
- [ ] No major evidence gaps detected.

### CF-184 - EKU Derives Keys Using KU hash_tfm Without KU Lock
- [ ] No major evidence gaps detected.

### CF-185 - EKU Semantic Mismatch: get_current_keys Returns Key, Not Secret
- [ ] Capture exact line range(s) where the fault manifests.

### CF-186 - FEC decoder recovery -- partial recovery leaks on kzalloc failure
- [ ] Capture exact line range(s) where the fault manifests.

### CF-187 - FEC encoder repair symbol generation -- partial resource leak on kzalloc failure
- [ ] Capture exact line range(s) where the fault manifests.

### CF-188 - FEC Repair Count Computation: `block_size * target_fec_rate` Truncation
- [ ] Capture exact line range(s) where the fault manifests.

### CF-189 - FEC Scheduler Loss Rate Overflow
- [ ] Capture exact line range(s) where the fault manifests.

### CF-190 - getsockopt PSK Identity - Missing Length Validation
- [ ] No major evidence gaps detected.

### CF-191 - GRO Coalesce Uses Hardcoded 8-byte CID Comparison
- [ ] No major evidence gaps detected.

### CF-192 - GRO Flush Unlock-Relock Loop Without Re-validation
- [ ] No major evidence gaps detected.

### CF-193 - h3_control_recv_frame Does Not Parse Frame Payloads
- [ ] Capture exact line range(s) where the fault manifests.

### CF-194 - HIGH: atomic64_inc_return for packet number on every TX
- [ ] No major evidence gaps detected.

### CF-195 - HIGH: GRO stats use global atomic64 on every packet
- [ ] No major evidence gaps detected.

### CF-196 - HIGH: Kernel address stored as u64 in buffer ring entries
- [ ] No major evidence gaps detected.

### CF-197 - HIGH: kmalloc(path->mtu) per datagram send
- [ ] No major evidence gaps detected.

### CF-198 - http3_stream.c Uses spin_lock Without _bh
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-199 - Incomplete SSRF Protection in TCP-over-QUIC Tunnel
- [ ] Capture exact line range(s) where the fault manifests.

### CF-200 - Infinite retry loop on EMSGSIZE/EEXIST
- [ ] No major evidence gaps detected.

### CF-201 - Integer Overflow in iovec Total Length Calculation
- [ ] Capture exact line range(s) where the fault manifests.

### CF-202 - io_uring buffer ring spinlock per get/put operation
- [ ] No major evidence gaps detected.

### CF-203 - Load Balancer Has No Privilege Checks
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-204 - MASQUE Proxy Has No Access Control
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-205 - memset Instead of memzero_explicit for Old Key Material
- [ ] No major evidence gaps detected.

### CF-206 - Missing kfree_sensitive for key material in crypto/handshake.c extensions buffer
- [ ] No major evidence gaps detected.

### CF-207 - Missing Validation of `first_ack_range` Against `largest_ack`
- [ ] Include a minimal code snippet proving the issue.

### CF-208 - Missing Validation of `TQUIC_MIGRATE` sockopt Address
- [ ] Capture exact line range(s) where the fault manifests.

### CF-209 - Netfilter Short Header DCID Parsing Uses Arbitrary Length
- [ ] Capture exact line range(s) where the fault manifests.

### CF-210 - Packet Forwarding Has No Privilege Checks
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-211 - payload_len Subtraction Underflow in Long Header Parsing
- [ ] No major evidence gaps detected.

### CF-212 - Prague Congestion Control: `ecn_ce_count * mss` Overflow
- [ ] Capture exact line range(s) where the fault manifests.

### CF-213 - Procfs trusted_cas Writable Without Privilege Check
- [ ] No major evidence gaps detected.

### CF-214 - PTO Duration Exponential Shift Overflow
- [ ] Capture exact line range(s) where the fault manifests.

### CF-215 - qlog TOCTOU Race Between Length Check and copy_to_user
- [ ] Capture exact line range(s) where the fault manifests.

### CF-216 - Race Condition in Idle Timer Connection Processing
- [ ] Capture exact line range(s) where the fault manifests.

### CF-217 - Redundant triple-counting of statistics
- [ ] No major evidence gaps detected.

### CF-218 - reed_solomon.c -- four-allocation group without individual NULL checks
- [ ] No major evidence gaps detected.

### CF-219 - Retry Integrity Tag Uses Wrong Key/Nonce for QUIC v2
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-220 - Retry Packet Stack Buffer Overflow
- [ ] No major evidence gaps detected.

### CF-221 - Retry Packet Version Encoding Is Hardcoded for v1
- [ ] Capture exact line range(s) where the fault manifests.

### CF-222 - Retry Token AEAD Key Set Under Non-IRQ-Safe Spinlock
- [ ] Capture exact line range(s) where the fault manifests.

### CF-223 - Return Pointer to Stack/Lock-Protected Data in tquic_conn_get_active_cid
- [ ] Capture exact line range(s) where the fault manifests.

### CF-224 - RSA Signature Algorithm Hardcoded to SHA-256 Regardless of Certificate
- [ ] Capture exact line range(s) where the fault manifests.

### CF-225 - Security Hardening Pre-HS Atomic TOCTOU
- [ ] No major evidence gaps detected.

### CF-226 - Session Ticket Decode Missing Bounds Check on PSK Copy
- [ ] No major evidence gaps detected.

### CF-227 - smartnic.c Uses spin_lock Without _bh
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-228 - struct tquic_napi mixes hot and cold fields
- [ ] Include a minimal code snippet proving the issue.

### CF-229 - Ticket Store Free-After-Remove Race Condition
- [ ] Capture exact line range(s) where the fault manifests.

### CF-230 - TPROXY Capability Check Logic Inversion
- [ ] Capture exact line range(s) where the fault manifests.

### CF-231 - tquic_process_stream_frame Allocates skb Based on Attacker-Controlled length
- [ ] No major evidence gaps detected.

### CF-232 - tquic_stream_count_by_type O(n) Scan for Critical Stream Enforcement
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-233 - tquic_stream_recv_data Potential Integer Overflow in Flow Control Check
- [ ] No major evidence gaps detected.

### CF-234 - tquic_stream_send_allowed Missing Underflow Check
- [ ] Capture exact line range(s) where the fault manifests.

### CF-235 - tquic_stream_sendfile Reads Only Into First Page
- [ ] Capture exact line range(s) where the fault manifests.

### CF-236 - tquic_stream_socket_create Double-Free on fd Failure
- [ ] No major evidence gaps detected.

### CF-237 - tquic_zerocopy_sendmsg -- uarg leak on partial send
- [ ] No major evidence gaps detected.

### CF-238 - Version Negotiation Packet Missing Randomized First Byte
- [ ] Capture exact line range(s) where the fault manifests.

### CF-239 - Weak CID Hash Function Enables Hash Flooding
- [ ] Capture exact line range(s) where the fault manifests.

### CF-240 - Zero-RTT Session Ticket Deserialization Trusts Length Fields
- [ ] No major evidence gaps detected.

### CF-241 - `tquic_connect()` Stores Error in `sk->sk_err` as Positive Value Wrongly
- [ ] Get independent confirmation from a second report/source.

### CF-242 - ACK Frame bytes_acked Calculation Can Overflow
- [ ] Get independent confirmation from a second report/source.

### CF-243 - ACK Range Processing Without Semantic Validation
- [ ] Get independent confirmation from a second report/source.

### CF-244 - Connection Close Reason Phrase Skipped Without Content Validation
- [ ] Get independent confirmation from a second report/source.

### CF-245 - Data Race in Server Migration Check
- [ ] Get independent confirmation from a second report/source.

### CF-246 - Internal Round-Robin Scheduler Missing Bounds Check
- [ ] Get independent confirmation from a second report/source.

### CF-247 - Multipath Frame Processing Lacks Encryption Level Validation
- [ ] Get independent confirmation from a second report/source.

### CF-248 - Race Condition on path->last_activity
- [ ] Get independent confirmation from a second report/source.

### CF-249 - Retire Prior To Not Validated Against Sequence Number
- [ ] Get independent confirmation from a second report/source.

### CF-250 - Route Lookup Fallback to init_net
- [ ] Get independent confirmation from a second report/source.

### CF-251 - tquic_output_packet Passes NULL conn to ip_local_out
- [ ] Get independent confirmation from a second report/source.

### CF-252 - Type Shadowing Creates Memory Corruption Risk
- [ ] Get independent confirmation from a second report/source.

### CF-253 - UAF-P1-02: - tquic_diag.c accesses conn->sk without reference
- [ ] Get independent confirmation from a second report/source.

### CF-254 - UAF-P3-03: - Tunnel close races with connect_work and forward_work
- [ ] Get independent confirmation from a second report/source.

### CF-255 - UAF-P3-04: - Path validation timer callback accesses path after potential free
- [ ] Get independent confirmation from a second report/source.

### CF-256 - UAF-P6-01: - SmartNIC ops dereference after device could be freed
- [ ] Get independent confirmation from a second report/source.

### CF-257 - Unlocked Connection Access in IOCTL
- [ ] Get independent confirmation from a second report/source.

### CF-258 - (Revised): tquic_pacing_work Accesses skb->len After tquic_output_packet (tquic_output.c, lines 1413-1418)
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-259 - 0-RTT Keys Derived With Empty Transcript
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-260 - 0-RTT Keys Derived With Empty Transcript (Not ClientHello Hash)
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-261 - `setsockopt(SOL_TQUIC, ...)` forces `optlen >= sizeof(int)` even for string/binary options
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-262 - `tquic_nl_cmd_path_remove()` Double Put on Path
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-263 - ACK Frame bytes_acked Calculation Can Overflow (tquic_input.c, lines 736-738)
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-264 - Aggregate Scheduler Unfair Minimum Weight Floor
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-265 - Bonding State Machine Missing Lock on State Transition Checks
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-266 - BPM Path Manager Falls Back to init_net
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-267 - CPU-5: All hash tables use `jhash` with a **fixed seed of 0**.
- [ ] Pinpoint at least one concrete source file path.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-268 - Double `tquic_nl_path_put()` in `tquic_path_remove_and_free()` Assumes refcnt==2
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-269 - Expensive Operation in Loss Path
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-270 - Failover Retransmit Queue Can Exceed Memory Limits
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-271 - FEC Scheme ID Not Validated From Wire
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-272 - Global Congestion Data Cache Without Namespace Isolation
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-273 - h3_request_send_headers State Check TOCTOU
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-274 - h3_stream_lookup_by_push_id Linear Scan Under Lock
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-275 - HIGH: Multiple ktime_get() calls per packet
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-276 - Hysteresis Counters Use Non-Atomic READ_ONCE/WRITE_ONCE Without Lock
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-277 - Large Stack Allocation in XOR Recovery
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-278 - Memory Exhaustion via Unbounded QPACK Header Lists
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-279 - Migration State Stores Raw Path Pointers Without Reference Counting
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-280 - Missing Address Family Validation in `tquic_path_create()`
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-281 - Multipath Frame Processing Lacks Encryption Level Validation (tquic_input.c, lines 2027-2038)
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-282 - Multiple ktime_get() calls per packet
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-283 - No ACK Frame Frequency Limit Per Packet
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-284 - Path Manager Uses init_net Instead of Per-Connection Net Namespace
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-285 - Path Validation Timeout Accesses Path State Without Lock After Unlock
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-286 - qpack_encoder known_received_count Overflow via Insert Count Increment
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-287 - Repair Frame Field Truncation Without Validation
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-288 - Same Stack Issue in Encoder
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-289 - sched/scheduler.c rr_select TOCTOU on num_paths
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-290 - sched/scheduler.c wrr_select Stale total_weight
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-291 - Stale Path Pointer Returned After rcu_read_unlock
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-292 - Stateless Reset Falls Back to init_net
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-293 - TOCTOU in Round-Robin Path Count vs Selection
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-294 - TOCTOU Race in Bonding State Transition
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-295 - TQUIC_MAX_PATHS Mismatch
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-296 - tquic_output_packet Passes NULL conn to ip_local_out (tquic_output.c, line 1413)
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-297 - tquic_stream_check_flow_control TOCTOU with sendmsg
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-298 - tquic_stream_ext Uses GFP_ATOMIC for Large Allocation
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-299 - tquic_udp_recv Processes Stateless Reset Before Authenticating Packet
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-300 - tquic_udp_recv Processes Stateless Reset Before Authenticating Packet (tquic_input.c, lines 2916-2932)
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-301 - UAF-P1-03: - conn->sk dereference in congestion control without locking
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-302 - UAF-P4-01: - tquic_zc_entry uses atomic_t instead of refcount_t
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-303 - UAF-P4-02: - Paths lack reference counting entirely
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-304 - Unit tests model packet-number length as readable from the first byte without HP removal
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-305 - Unprotected Global Loss Tracker Array
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-306 - Unvalidated `addr_len` Passed to `memcpy` in `tquic_connect()`
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-307 - Weight Accumulation Without Overflow Check
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-308 - Weighted Scheduler Has No Lock Protection
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-309 - Bloom Filter False Negatives Allow Replay
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-310 - Decoy Packet Size Calculation Can Underflow
- [ ] Capture exact line range(s) where the fault manifests.

### CF-311 - EKU Request ID Increment Outside Lock
- [ ] Include a minimal code snippet proving the issue.

### CF-312 - HP Key Rotation Swaps Old Keys Without Zeroization
- [ ] Capture exact line range(s) where the fault manifests.

### CF-313 - HTTP/3 Connection: O(n) Push Entry Counting
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-314 - HTTP/3 Frame Parsing: 16MB Maximum Frame Payload
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-315 - HTTP/3 Settings Parser: TOCTOU on Settings Count
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-316 - Missing Bounds Check on tbs Pointer in Signature Parse
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-317 - Path Metrics Subscription: Timer/Connection Lifetime Race
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-318 - Path Score Computation Can Overflow in Migration Target Selection
- [ ] Capture exact line range(s) where the fault manifests.

### CF-319 - Per-Call crypto_alloc_shash in Stateless Reset Token Generation
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-320 - QAT Encrypt Sets Key on Every Call
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-321 - Qlog Ring Buffer: Not Truly Lock-Free
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-322 - Qlog: JSON Strings Not Escaped
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-323 - QPACK Encoder/Decoder: Excessive Stack Usage
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-324 - QPACK Huffman Decoder: O(n*256) Complexity
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-325 - QPACK Integer Decode: Shift Overflow
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-326 - Time Parsing Does Not Validate Digit Characters
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-327 - Transcript Buffer Not Zeroized Before Free
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-328 - Tunnel Port Allocation Unsigned Underflow
- [ ] Capture exact line range(s) where the fault manifests.

### CF-329 - WebTransport: TOCTOU in Datagram Queue Push
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-330 - `additional_addr_add()` Has TOCTOU Between Duplicate Check and Insert
- [ ] Include a minimal code snippet proving the issue.

### CF-331 - `bbrv3.c` CE Ratio Potential Division by Zero
- [ ] Capture exact line range(s) where the fault manifests.

### CF-332 - `hs_varint_encode` -- no bounds check on output buffer
- [ ] Capture exact line range(s) where the fault manifests.

### CF-333 - `http3_frame.c` Settings Frame Parser: No Bounds on `count`
- [ ] Capture exact line range(s) where the fault manifests.

### CF-334 - `kmem_cache_create()` Per Stream Manager Risks Name Collision
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-335 - `ring_index()` Uses Unbounded While Loop
- [ ] Capture exact line range(s) where the fault manifests.

### CF-336 - `tquic_accept()` Holding `sk_lock.slock` Improperly
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-337 - `tquic_cong.c` ECN Byte Calculation Overflow
- [ ] Capture exact line range(s) where the fault manifests.

### CF-338 - `tquic_fc_conn_data_sent()` Race Between Check and Update
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-339 - `tquic_hs_derive_early_secrets` -- `memzero_explicit` called before error check
- [ ] Capture exact line range(s) where the fault manifests.

### CF-340 - `tquic_hs_generate_client_hello` -- `hkdf_label` stack buffer on sensitive crypto path
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-341 - `tquic_hs_process_certificate_verify` -- `content[200]` stack buffer could overflow with large hash
- [ ] Capture exact line range(s) where the fault manifests.

### CF-342 - `tquic_hs_process_certificate` -- unbounded certificate allocation
- [ ] Capture exact line range(s) where the fault manifests.

### CF-343 - `tquic_hs_process_server_hello` -- `static const` inside function body
- [ ] Capture exact line range(s) where the fault manifests.

### CF-344 - `tquic_migrate_validate_all_additional()` Lock Drop/Reacquire Pattern
- [ ] Capture exact line range(s) where the fault manifests.

### CF-345 - `tquic_nl_cmd_path_dump()` Incorrect Cast of `cb->ctx`
- [ ] Capture exact line range(s) where the fault manifests.

### CF-346 - `tquic_path_compute_score()` Integer Overflow in Score Calculation
- [ ] Capture exact line range(s) where the fault manifests.

### CF-347 - `tquic_path_is_degraded()` Division by Zero Possible
- [ ] Capture exact line range(s) where the fault manifests.

### CF-348 - `tquic_proc.c` Buffer Overflow in Hex CID Formatting
- [ ] No major evidence gaps detected.

### CF-349 - `tquic_process_stream_frame()` Does Not Check Final Size Consistency
- [ ] Capture exact line range(s) where the fault manifests.

### CF-350 - `tquic_sendmsg_datagram()` Allocates Kernel Buffer Sized by User-Controlled `len`
- [ ] Capture exact line range(s) where the fault manifests.

### CF-351 - `tquic_sock_setsockopt()` Reads `int` for Some Options But Accepts `optlen >= sizeof(int)` Without Capping
- [ ] No major evidence gaps detected.

### CF-352 - `transport_params.c` Memcpy with `count * sizeof(u32)` Without Overflow Check
- [ ] No major evidence gaps detected.

### CF-353 - ACK Frame Range Count Uses u64 Loop Variable Against size_t max_ranges
- [ ] No major evidence gaps detected.

### CF-354 - Anti-Replay Hash Table Cleanup Iterates All Buckets Under spinlock
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-355 - atomic_inc/dec for rx_queue_len on every enqueue/dequeue
- [ ] Include a minimal code snippet proving the issue.

### CF-356 - Benchmark write() Handler - Stack Buffer for User Input
- [ ] Capture exact line range(s) where the fault manifests.

### CF-357 - Bloom Filter Seeds Never Rotated
- [ ] Capture exact line range(s) where the fault manifests.

### CF-358 - BPM Path Manager Uses Workqueue Without Connection Lifetime Guard
- [ ] Capture exact line range(s) where the fault manifests.

### CF-359 - cert_verify.c - kmalloc(count + 1) Integer Overflow
- [ ] Capture exact line range(s) where the fault manifests.

### CF-360 - cert_verify.c parse_san_extension -- error code not propagated
- [ ] Capture exact line range(s) where the fault manifests.

### CF-361 - Certificate Chain Parsing Does Not Verify Issuer-Subject Linkage Before Trust Check
- [ ] No major evidence gaps detected.

### CF-362 - CID Sequence Number Rollback on rhashtable Insert Failure
- [ ] No major evidence gaps detected.

### CF-363 - conn->streams_lock for RB-tree walk on every STREAM frame
- [ ] No major evidence gaps detected.

### CF-364 - connect_ip.c Datagram Buffer Allocation from Attacker Data
- [ ] Capture exact line range(s) where the fault manifests.

### CF-365 - connect_udp.c URL Encoding Can Exceed Buffer
- [ ] Capture exact line range(s) where the fault manifests.

### CF-366 - Connection State Not Checked in tquic_conn_handle_close
- [ ] Capture exact line range(s) where the fault manifests.

### CF-367 - Coupled Congestion Control Division by Zero
- [ ] No major evidence gaps detected.

### CF-368 - Decoy Traffic Uses Easily Fingerprinted All-Zero Padding
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-369 - Diag/Tracepoints Initialize in init_net
- [ ] Capture exact line range(s) where the fault manifests.

### CF-370 - Error Ring Uses Atomics Under Spinlock Unnecessarily
- [ ] No major evidence gaps detected.

### CF-371 - Exfil Context set_level Destroys and Reinitializes Without Lock
- [ ] Capture exact line range(s) where the fault manifests.

### CF-372 - FEC encoder allocates per-symbol in GFP_ATOMIC
- [ ] No major evidence gaps detected.

### CF-373 - FEC encoder double lock nesting
- [ ] No major evidence gaps detected.

### CF-374 - FEC Encoder Triple-Nested Locking
- [ ] No major evidence gaps detected.

### CF-375 - Gaussian Random Approximation Produces Biased Distribution
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-376 - h3_stream_recv_data frame_hdr Buffer Partial Read
- [ ] Capture exact line range(s) where the fault manifests.

### CF-377 - h3_stream_recv_headers Does Not Validate payload_len Against H3_MAX_FRAME_PAYLOAD_SIZE
- [ ] Capture exact line range(s) where the fault manifests.

### CF-378 - Hardcoded 8-Byte CID in Short Header Unprotect
- [ ] Capture exact line range(s) where the fault manifests.

### CF-379 - HMAC Transform Allocated Per-Token in `tquic_stateless_reset_generate_token()`
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-380 - Hostname Wildcard Matching Allows Wildcards in Non-Leftmost Position
- [ ] Capture exact line range(s) where the fault manifests.

### CF-381 - http3_priority.c snprintf Priority Field Truncation
- [ ] Capture exact line range(s) where the fault manifests.

### CF-382 - Interop Framework - Same Pattern
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-383 - Key Material Not Zeroized on All Error Paths in tquic_zero_rtt_derive_keys
- [ ] No major evidence gaps detected.

### CF-384 - kmem_cache Names Not Unique Per Connection
- [ ] Capture exact line range(s) where the fault manifests.

### CF-385 - Load Balancer Feistel Network Half-Length Overlap
- [ ] Capture exact line range(s) where the fault manifests.

### CF-386 - Load Balancer Nonce Counter Wraps Without Re-keying
- [ ] Capture exact line range(s) where the fault manifests.

### CF-387 - MEDIUM: BBRv3 uses ktime_get_ns() for every bandwidth sample
- [ ] No major evidence gaps detected.

### CF-388 - MEDIUM: kzalloc per io_uring async request
- [ ] No major evidence gaps detected.

### CF-389 - MEDIUM: Per-chunk skb allocation in zerocopy path
- [ ] No major evidence gaps detected.

### CF-390 - MEDIUM: Zerocopy sendmsg chunks at 1200 bytes
- [ ] No major evidence gaps detected.

### CF-391 - MIB counter updates on every packet in RX/TX paths
- [ ] Pinpoint at least one concrete source file path.

### CF-392 - Missing Bounds Check on tquic_hyst_state_names Array Access
- [ ] Capture exact line range(s) where the fault manifests.

### CF-393 - Missing skb->dev Assignment in Packet Injection
- [ ] Capture exact line range(s) where the fault manifests.

### CF-394 - Multiple atomic operations in NAPI enqueue path
- [ ] Include a minimal code snippet proving the issue.

### CF-395 - NAT Keepalive Config Pointer Not Protected Against Concurrent Free
- [ ] Capture exact line range(s) where the fault manifests.

### CF-396 - Netlink Path Dump Reads conn_id on Every Iteration
- [ ] Capture exact line range(s) where the fault manifests.

### CF-397 - Netlink PM Commands Missing CAP_NET_ADMIN Checks
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-398 - No Flow Count Limit in HTTP Datagram Manager
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-399 - No Token Replay Protection Beyond Timestamp
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-400 - Pacing work function drops and reacquires lock per packet
- [ ] No major evidence gaps detected.

### CF-401 - Packet Number Decode Returns 0 on Invalid Input
- [ ] Capture exact line range(s) where the fault manifests.

### CF-402 - Path Length Constraint Check Off-By-One
- [ ] Capture exact line range(s) where the fault manifests.

### CF-403 - Path Manager netdev_event Shadows Variable 'i'
- [ ] Capture exact line range(s) where the fault manifests.

### CF-404 - Per-Call skcipher_request Allocation in HP Mask Hot Path
- [ ] No major evidence gaps detected.

### CF-405 - Per-Packet kmalloc in Batch Encrypt/Decrypt
- [ ] No major evidence gaps detected.

### CF-406 - Per-path stats updated from both RX and TX
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-407 - poll() Accesses Connection/Stream Without Any Lock
- [ ] Capture exact line range(s) where the fault manifests.

### CF-408 - Proc Entries Hardcoded to init_net.proc_net
- [ ] Capture exact line range(s) where the fault manifests.

### CF-409 - PSK Identity Logged with `tquic_dbg()` -- Sensitive Data in Kernel Logs
- [ ] No major evidence gaps detected.

### CF-410 - rcu_dereference Outside Explicit RCU Section
- [ ] No major evidence gaps detected.

### CF-411 - Request ID Truncation from u64 to int
- [ ] Capture exact line range(s) where the fault manifests.

### CF-412 - Retry Token Address Validation Uses Weak Hash
- [ ] Capture exact line range(s) where the fault manifests.

### CF-413 - SAN DNS Names Not Validated for Embedded NUL Characters
- [ ] Capture exact line range(s) where the fault manifests.

### CF-414 - Scheduler Change Race Between State Check and Modification
- [ ] Capture exact line range(s) where the fault manifests.

### CF-415 - Security Hardening MIB Stats Always Go to init_net
- [ ] Capture exact line range(s) where the fault manifests.

### CF-416 - Signed/Unsigned Mismatch in Scheduler Queue Delay
- [ ] Capture exact line range(s) where the fault manifests.

### CF-417 - SmartNIC offload takes dev->lock for every key operation
- [ ] No major evidence gaps detected.

### CF-418 - smartnic.c - kmalloc_array with Attacker-Influenced Count
- [ ] Capture exact line range(s) where the fault manifests.

### CF-419 - snprintf Return Value Not Checked in qlog.c
- [ ] Capture exact line range(s) where the fault manifests.

### CF-420 - Stateless Reset Static Key Accessible via `tquic_stateless_reset_get_static_key()` Export
- [ ] Capture exact line range(s) where the fault manifests.

### CF-421 - Sysctl and Proc Entries Registered in init_net Only
- [ ] No major evidence gaps detected.

### CF-422 - Sysctl Permissions Are Overly Permissive
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-423 - Sysctl Variables Lack Range Validation
- [ ] Capture exact line range(s) where the fault manifests.

### CF-424 - Token Hash Comparison Not Constant-Time
- [ ] Capture exact line range(s) where the fault manifests.

### CF-425 - Token Key Rotation Does Not Zeroize Old Key
- [ ] Capture exact line range(s) where the fault manifests.

### CF-426 - tquic_cid_pool_init -- timer initialized but not cancelled on later failure
- [ ] Capture exact line range(s) where the fault manifests.

### CF-427 - tquic_conn_create -- loss_detection_init failure doesn't clean up timers
- [ ] No major evidence gaps detected.

### CF-428 - tquic_fc_reserve_credit Does Not Actually Reserve
- [ ] Capture exact line range(s) where the fault manifests.

### CF-429 - tquic_handshake.c tquic_start_handshake -- hs freed with memzero_explicit but no kfree_sensitive
- [ ] Capture exact line range(s) where the fault manifests.

### CF-430 - tquic_output_flush -- spin_unlock_bh after acquiring spin_lock_bh, but lock dropped mid-loop
- [ ] Capture exact line range(s) where the fault manifests.

### CF-431 - tquic_retry.c -- integrity_aead_lock held across AEAD operations
- [ ] Capture exact line range(s) where the fault manifests.

### CF-432 - tquic_stream_memory_pressure Frees Without ext Cleanup
- [ ] Capture exact line range(s) where the fault manifests.

### CF-433 - tquic_stream_trigger_output Inflight Underflow
- [ ] Capture exact line range(s) where the fault manifests.

### CF-434 - tquic_stream_write Holds mgr->lock for Entire Copy Loop
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-435 - Unbounded Pending Path Challenges
- [ ] Capture exact line range(s) where the fault manifests.

### CF-436 - Version Negotiation Packet Not Authenticated
- [ ] Capture exact line range(s) where the fault manifests.

### CF-437 - WebTransport Session Refcount Not Checked After Accept
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-438 - Zerocopy entry refcount uses atomic_t
- [ ] No major evidence gaps detected.

### CF-439 - AMP-1: The anti-amplification check uses `atomic64` operations for `bytes_received` and `bytes_sent`, but the check-then-add pattern is not atomic as a whole:
- [ ] Get independent confirmation from a second report/source.

### CF-440 - asn1_get_length Does Not Handle Length 0x84+
- [ ] Get independent confirmation from a second report/source.

### CF-441 - Coalesced Packet Processing Silently Truncates on Overflow
- [ ] Get independent confirmation from a second report/source.

### CF-442 - conn->data_sent Underflow on Error Path
- [ ] Get independent confirmation from a second report/source.

### CF-443 - CPU-2: FEC decoder block search is a linear list walk.
- [ ] Get independent confirmation from a second report/source.

### CF-444 - EDF Scheduler edf_select_path Called Without Lock
- [ ] Get independent confirmation from a second report/source.

### CF-445 - ktime_get_ts64 Written to skb->cb May Exceed cb Size
- [ ] Get independent confirmation from a second report/source.

### CF-446 - MP Frame Type Range Check Too Broad
- [ ] Get independent confirmation from a second report/source.

### CF-447 - tquic_fc_stream_can_send Missing Overflow Check
- [ ] Get independent confirmation from a second report/source.

### CF-448 - TQUIC_IDLE_TIMEOUT Missing Range Validation
- [ ] Get independent confirmation from a second report/source.

### CF-449 - TQUIC_PSK_IDENTITY Off-by-One Potential
- [ ] Get independent confirmation from a second report/source.

### CF-450 - tquic_recv_datagram Can Loop Forever Under Signal Pressure
- [ ] Get independent confirmation from a second report/source.

### CF-451 - TQUIC_SCHEDULER Race on tquic_sched_find
- [ ] Get independent confirmation from a second report/source.

### CF-452 - UAF-P5-02: - Path list uses RCU but active_path does not
- [ ] Get independent confirmation from a second report/source.

### CF-453 - Version Negotiation Versions Logged Without Rate Limiting
- [ ] Get independent confirmation from a second report/source.

### CF-454 - CROSS-1: The systematic use of `jhash` with seed 0 across 15+ call sites creates a coordinated attack vector. An attacker who can determine CID values and IP addresses can craft inputs that degrade:
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-455 - 0-RTT Encrypt Allocates AEAD Per-Packet
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-456 - 0-RTT Encrypt Allocates AEAD Per-Packet (Performance / Side Channel)
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-457 - All MP Scheduler init() Functions Silently Fail on OOM
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-458 - Alpha Precision Loss in Coupled CC
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-459 - AMP-2: The `tquic_path_handle_challenge` function in `pm/path_validation.c:249` does not check anti-amplification limits before queuing the PATH_RESPONSE. Per RFC 9000 Section 8.1, data sent on unvali
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-460 - AMP-3: The MASQUE CONNECT-UDP tunnel implementation in `masque/connect_udp.c` creates UDP sockets to forward proxied traffic. There is **no visible limit on the number of tunnels per connection or per
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-461 - Anti-Amplification Check Has TOCTOU Race
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-462 - asn1_get_length Does Not Handle Length 0x84+ (4+ byte lengths)
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-463 - Coalesced Packet Processing Silently Truncates on Overflow (tquic_input.c, lines 3172-3173)
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-464 - Deadline Scheduler in_flight Underflow
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-465 - Division Safety in Congestion Data Validation
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-466 - Duplicate ECF Path State Allocation Race
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-467 - ECN State Tracking Per-Round Limitation
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-468 - h3_parse_settings_frame u64 to Pointer Cast
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-469 - h3_parser_advance Missing Bounds Check
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-470 - HMAC Stack Buffer Size
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-471 - In-Flight Calculation Signed Arithmetic
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-472 - ktime_get_ts64 Written to skb->cb May Exceed cb Size (tquic_input.c, line 1471)
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-473 - Lock Ordering Between Encoder and Scheduler
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-474 - Loss Rate Cast Overflow
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-475 - MEM-1: `tquic_handshake.c` lines 605 and 1136 allocate skbs based on computed handshake message lengths (`ch_len`, `resp_len`). While these are internally computed (not directly from network), a malfo
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-476 - Nested Locking in Repair Reception
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-477 - Path Creation Uses static atomic_t for path_id -- Not Per-Connection
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-478 - Path Manager discover_addresses Holds rtnl_lock While Accessing inet6_dev
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-479 - Priority State No Limit on stream_count
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-480 - Push Entry Count O(n) Iteration
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-481 - Reorder Buffer Sequence in skb->cb Alignment
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-482 - sched/scheduler.c Debug Logging Leaks Kernel Pointers
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-483 - sched/scheduler.c ECF Loss Rate Division by Zero
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-484 - Sort Modifies Caller's Lost Packets Array
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-485 - STATE-1: The transition to "attack mode" (TQUIC_RL_COOKIE_REQUIRED) appears to be reactive -- it triggers when rate limits are exceeded. During the ramp-up period before attack mode activates, an atta
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-486 - tquic_gro_flush Drops and Re-acquires Lock Per Packet (tquic_input.c, lines 2303-2310)
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-487 - tquic_main.c init/exit -- conditional cleanup mismatch for NAPI/io_uring
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-488 - tquic_main.c init/exit -- conditional cleanup mismatch for NAPI/io_uring
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-489 - tquic_recv_datagram Can Loop Forever Under Signal Pressure (tquic_output.c, lines 2706-2743)
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-490 - Triplicated Varint Encode/Decode Implementations
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-491 - UAF-ADD-01: - tquic_tunnel_close does not cancel forward_work for tproxy tunnels
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-492 - UAF-P3-05: - GRO flush_timer can fire after kfree
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-493 - UAF-P4-03: - Double destruction path for connections
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-494 - UAF-P5-01: - Correct RCU usage in tquic_nf.c
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-495 - UAF-P6-02: - tquic_zerocopy_complete callback chain
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-496 - Version Negotiation Versions Logged Without Rate Limiting (tquic_input.c, lines 473-477)
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-497 - WebTransport Datagram Queue Double-Checked Locking Anti-Pattern
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-498 - Weighted Scheduler Weight Not Validated
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-499 - XDP Uses capable
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-500 - XDP Uses capable() Instead of ns_capable()
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-501 - Batch Crypto Allocates Per-Packet Temporary Buffer
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-502 - Certificate Chain Length Limit Checked Late
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-503 - Duplicate MODULE_DESCRIPTION in quic_exfil.c
- [ ] No major evidence gaps detected.

### CF-504 - Duplicate Static Functions: h3_varint_encode/decode
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-505 - HTTP/3 Priority: push_buckets Not Initialized
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-506 - Key Update Timeout Revert Could Race With Concurrent Update
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-507 - Load Balancer Stack Buffers for Feistel Not Zeroized on Error
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-508 - Module Parameters Expose Security Configuration
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-509 - Netlink Events Do Not Include Timestamp
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-510 - Netlink Family Exported as EXPORT_SYMBOL_GPL
- [ ] Capture exact line range(s) where the fault manifests.

### CF-511 - Per-CPU Stats Not Protected Against Torn Reads on 32-bit
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-512 - Procfs trusted_cas File Writable Without Capability Check
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-513 - Qlog: Lock Drop Around copy_to_user
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-514 - Unused HKDF-Expand Output in Extended Key Update
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-515 - Volatile Qualifiers in Constant-Time Functions May Be Insufficient
- [ ] Capture exact line range(s) where the fault manifests.

### CF-516 - `established_time` Set Twice in Connection State Machine
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-517 - `sk->sk_err = -ret` Stores Negative Error Code
- [ ] Capture exact line range(s) where the fault manifests.

### CF-518 - `tquic_cid_compare()` Marked `__maybe_unused`
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-519 - `tquic_cid_retire()` Sends RETIRE_CONNECTION_ID After Retirement
- [ ] Include a minimal code snippet proving the issue.

### CF-520 - `tquic_debug.c` CID Hex Loop Bound
- [ ] Capture exact line range(s) where the fault manifests.

### CF-521 - `tquic_hs_cleanup` -- does not zeroize exporter_secret and resumption_secret
- [ ] Capture exact line range(s) where the fault manifests.

### CF-522 - `tquic_hs_generate_client_hello` -- client random not checked for all-zero
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-523 - `tquic_hs_get_handshake_secrets` and `tquic_hs_get_app_secrets` -- no output buffer size validation
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-524 - `tquic_hs_process_certificate_verify` hardcodes "server CertificateVerify" string
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-525 - `tquic_hs_process_new_session_ticket` -- ignores extensions
- [ ] No major evidence gaps detected.

### CF-526 - `tquic_server_check_path_recovery()` Uses `goto restart` Pattern
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-527 - `tquic_store_session_ticket()` Does Not Store ALPN or Transport Parameters
- [ ] Capture exact line range(s) where the fault manifests.

### CF-528 - `tquic_sysctl_prefer_v2()` Function Not Declared in Visible Header
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-529 - AF_XDP frame pool uses spinlock for every frame alloc/free
- [ ] Include a minimal code snippet proving the issue.

### CF-530 - bench/benchmark.c -- kvmalloc used correctly with kvfree
- [ ] Include a minimal code snippet proving the issue.

### CF-531 - Benchmark Code: Userspace, Not Kernel
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-532 - CID Table Initialization Not Thread-Safe
- [ ] Capture exact line range(s) where the fault manifests.

### CF-533 - close_work Repurposes drain_work for Retransmit Scheduling
- [ ] Capture exact line range(s) where the fault manifests.

### CF-534 - Consistent use of kfree_sensitive for key material -- GOOD
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-535 - Constant-Time Comparison Used for Integrity Tags
- [ ] Capture exact line range(s) where the fault manifests.

### CF-536 - Context Set Level Does Not Check init Return Values
- [ ] Capture exact line range(s) where the fault manifests.

### CF-537 - CRYPTO_TFM_REQ_MAY_BACKLOG in Atomic Context
- [ ] Capture exact line range(s) where the fault manifests.

### CF-538 - crypto_wait_req May Sleep in Encrypt/Decrypt Hot Path
- [ ] No major evidence gaps detected.

### CF-539 - Empty Hash Computed Without Algorithm Validation
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-540 - h3_varint_len Defined Multiple Times as Static
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-541 - HMAC Output Not Zeroized on Fallback Path
- [ ] Capture exact line range(s) where the fault manifests.

### CF-542 - Inconsistent Error Return From verify_chain
- [ ] Include a minimal code snippet proving the issue.

### CF-543 - io_uring.c getsockopt Same len Validation Pattern
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-544 - Lock Drop/Re-acquire Pattern in Key Derivation
- [ ] Capture exact line range(s) where the fault manifests.

### CF-545 - LOW: pacing_calc_gap uses division
- [ ] No major evidence gaps detected.

### CF-546 - LOW: Prague RTT scaling division on every ACK
- [ ] No major evidence gaps detected.

### CF-547 - memzero_explicit Used Correctly for Key Material
- [ ] Pinpoint at least one concrete source file path.
- [ ] Include a minimal code snippet proving the issue.

### CF-548 - Minimal tracepoint overhead
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-549 - Missing Error Check for init_net Reference
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-550 - Missing lockdep Annotations
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.

### CF-551 - Multipath Nonce Construction -- Potential Nonce Reuse Across Paths
- [ ] No major evidence gaps detected.

### CF-552 - Multiple Redundant Varint Implementations
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-553 - Netlink Operations All Require GENL_ADMIN_PERM
- [ ] No major evidence gaps detected.

### CF-554 - nla_put Operations in Netlink Properly Handle Failure
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-555 - parse_basic_constraints Hardcoded BOOLEAN Length
- [ ] Capture exact line range(s) where the fault manifests.

### CF-556 - Path Validation Response Queue Uses Two Tracking Mechanisms
- [ ] Capture exact line range(s) where the fault manifests.

### CF-557 - quic_exfil.c Decoy Packet Size Controlled by MTU
- [ ] Capture exact line range(s) where the fault manifests.

### CF-558 - Redundant Lock in tquic_bonding_get_state
- [ ] No major evidence gaps detected.

### CF-559 - Retry Integrity Tag Computed with Potentially-Failing AEAD
- [ ] Capture exact line range(s) where the fault manifests.

### CF-560 - SAN Parsing Capacity Limit Check Could Be Tighter
- [ ] Capture exact line range(s) where the fault manifests.

### CF-561 - Scheduler Lock Uses spin_lock Without _bh
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-562 - server_ticket_key Is Static Global Without Rotation
- [ ] Capture exact line range(s) where the fault manifests.

### CF-563 - Slab Cache Names Are Not Module-Prefixed
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-564 - Stream ID Right-Shift Comparison
- [ ] No major evidence gaps detected.

### CF-565 - tquic_conn_destroy -- thorough cleanup
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-566 - tquic_ipv6.c MTU Info getsockopt
- [ ] No major evidence gaps detected.

### CF-567 - tquic_main.c init -- correct cascading cleanup
- [ ] Include a minimal code snippet proving the issue.

### CF-568 - tquic_output_flush Holds conn->lock While Calling GFP_ATOMIC Allocation
- [ ] Include a minimal code snippet proving the issue.

### CF-569 - tquic_pacing_cleanup -- correct ordering
- [ ] Capture exact line range(s) where the fault manifests.

### CF-570 - tquic_retry_rate_limit Potential Token Bucket Underflow
- [ ] Capture exact line range(s) where the fault manifests.

### CF-571 - tquic_stream_manager_destroy Does Not Free Extended State for All Streams
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-572 - tquic_timer_state_alloc -- cleanup loop is correct
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-573 - tquic_timer_state_free -- thorough and correct
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-574 - Version Negotiation First Byte Missing Fixed Bit Randomization
- [ ] No major evidence gaps detected.

### CF-575 - Version Negotiation Packet Size Not Validated Against 256-Byte Buffer
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-576 - Version Negotiation Response - dcid/scid_len Not Capped
- [ ] Capture exact line range(s) where the fault manifests.

### CF-577 - Workqueue Not Validated Before Use
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-578 - XOR FEC encoding is efficient
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.

### CF-579 - `bench_latency.c` Allocation Without Overflow Check
- [ ] Get independent confirmation from a second report/source.

### CF-580 - CPU-3: CID pool active count enumeration.
- [ ] Get independent confirmation from a second report/source.

### CF-581 - spin_lock
- [ ] Get independent confirmation from a second report/source.

### CF-582 - tquic_build_short_header_internal Writes pkt_num to buf+64 Scratch Space
- [ ] Get independent confirmation from a second report/source.

### CF-583 - tquic_gso_init Integer Overflow in Allocation Size
- [ ] Get independent confirmation from a second report/source.

### CF-584 - UAF-ADD-02: - CID pool rotation_work vs pool destruction race window
- [ ] Get independent confirmation from a second report/source.

### CF-585 - `bench_common.c` Variance Calculation
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-586 - `bench_common.c` Variance Calculation (Userspace Code)
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-587 - `bench_latency.c` Allocation Without Overflow Check (Userspace Code)
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-588 - `tquic_accept()` Nested Locking Pattern
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-589 - `tquic_sock_listen()` Redundant `INIT_LIST_HEAD` Check
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-590 - `tquic_stateless_reset_detect()` Iterates All Tokens Non-Constant-Time
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-591 - Aggregate Scheduler Long Spinlock Hold
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-592 - Benchmark Code: Userspace, Not Kernel
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-593 - BPM Path Metrics min_rtt Initialized to UINT_MAX
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-594 - C99 Variable Declaration in Loop
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-595 - Constant-Time Comparison
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-596 - Coupled CC Alpha Smoothing May Suppress Rapid Changes
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-597 - Coupled CC Alpha Smoothing May Suppress Rapid Changes
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-598 - CPU-6: The QPACK decoder accepts a `max_table_capacity` parameter from the peer via SETTINGS. While the sysctl caps the local maximum at 1MB, the actual limit used should be `min(peer_requested, local
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-599 - CROSS-2: Consider using the `tquic_rx_buf_cache` slab cache pattern (already used at `tquic_input.c:2586`) more broadly for hot-path allocations to reduce GFP_ATOMIC pressure.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-600 - Debug Logging of Packet Contents
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-601 - Failover Sent Packet Count Can Go Negative
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-602 - INFO-1: Several `pr_debug`/`tquic_dbg` calls include connection state information. While these are compile-time optional, in debug builds they could leak timing information about connection state to a
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-603 - MEM-3: The NF connection tracking limit (65536) has no per-source-IP limit at the netfilter layer. While the TQUIC protocol layer has per-IP limits, the NF `tquic_nf_conn_alloc` at line 497 only check
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-604 - MEM-4: While stream count is limited, each stream allocates both `send_buf` and `recv_buf` skb queues. An attacker opening `max_streams_bidi` streams and sending minimal data to each creates per-strea
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-605 - Missing Documentation on Lock Ordering
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-606 - Multicast Group Only Requires CAP_NET_ADMIN
- [ ] Pinpoint at least one concrete source file path.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-607 - Multiple Scheduler Registration Systems Coexist
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-608 - Multiple Varint Implementations
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-609 - Netlink Attribute Policy Does Not Use Strict Validation for Binary Addresses
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-610 - No Per-Connection Frame Processing Budget
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-611 - Path Validation Timer del_timer vs del_timer_sync
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-612 - Priority Extension Allocation Race
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-613 - PROTO-1: The retire loop at `tquic_cid.c:667-674` iterates the entire remote CID list for each NEW_CONNECTION_ID frame, marking CIDs as retired. While bounded by `active_connection_id_limit`, repeated
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-614 - Repair Data Pointer Lifetime
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-615 - send_skb Variable Used After Potential NULL
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-616 - Sensitive Key Cleanup
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-617 - settings seen_mask Limited to 64 Settings
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-618 - spin_lock (Not spin_lock_bh) Used in tquic_process_max_data_frame (tquic_input.c, lines 1015-1017)
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-619 - STATE-2: An attacker could open connections, complete the handshake (consuming 1 connection per client rate token), then keep them alive by sending a PING frame every 29 seconds. With default 100 conn
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-620 - STATE-3: No visible limit on the number of paths per connection. If an attacker can trigger path creation (via connection migration or multipath signaling), each new path creates timers and state.
- [ ] Pinpoint at least one concrete source file path.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-621 - Stateless Reset Token Comparison Timing
- [ ] Pinpoint at least one concrete source file path.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-622 - Stream Creation Not Bounded in Input Path
- [ ] Pinpoint at least one concrete source file path.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-623 - timer_setup with NULL Callback
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-624 - tquic_build_short_header_internal Writes pkt_num to buf+64 Scratch Space (tquic_output.c, line 818)
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-625 - tquic_encap_recv Double UDP Header Strip
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-626 - tquic_encode_varint Does Not Validate val Range
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-627 - tquic_encode_varint Does Not Validate val Range (tquic_output.c, lines 164-198)
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-628 - tquic_gso_init Integer Overflow in Allocation Size (tquic_output.c, line 1489)
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-629 - tquic_process_ack_frame Does Not Validate largest_ack vs first_ack_range
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-630 - tquic_process_ack_frame Does Not Validate largest_ack vs first_ack_range (tquic_input.c, lines 601-660)
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-631 - tquic_process_coalesced Missing Infinite Loop Guard
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-632 - tquic_process_coalesced Missing Infinite Loop Guard (tquic_input.c, lines 3079-3182)
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-633 - tquic_sched_release Frees ext Under Lock but kfree Can Sleep
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-634 - tquic_stream_alloc Uses GFP_KERNEL in Potentially Atomic Context
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-635 - tquic_stream_release Missing Error Return
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-636 - tquic_stream_set_priority Missing Lock Protection
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-637 - Weighted DRR Iterates Over Empty Slots
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-638 - ACK Frequency Frame Type Inconsistency
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-639 - copy_from_sockptr in setsockopt Always Uses sizeof(type)
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-640 - Diagnostic Counter Wraps
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-641 - Error Codes Leak Processing State
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-642 - IMMEDIATE_ACK Frame Type Similar Issue
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-643 - Inconsistent Congestion State Layouts
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-644 - Multiple Varint Implementations (Code Duplication Risk)
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

### CF-645 - Three Parallel Scheduler Frameworks
- [ ] Pinpoint at least one concrete source file path.
- [ ] Capture exact line range(s) where the fault manifests.
- [ ] Include a minimal code snippet proving the issue.
- [ ] Get independent confirmation from a second report/source.
- [ ] Add minimal repro steps with expected vs actual behavior.

## C) Fix Plan (Risk-Minimizing Order)

1. **Stabilize memory-safety and security-critical parser paths first**
   - Address 119 S0/S1 memory+security findings to reduce crash/exploit risk before behavior tuning.
2. **Fix protocol-state and packet processing correctness**
   - Triage 119 high-priority correctness/concurrency findings once safety rails are in place.
3. **Resolve residual high-priority architecture issues**
   - Handle remaining 19 high-priority items and remove temporary mitigations.
4. **Backfill evidence gaps + tests before closeout**
   - For single-source or low-evidence clusters, require line-level proof and a regression test to close.

## Notes
- Severity reconciliation keeps the highest severity; weakly evidenced cases are explicitly flagged in `conflicts`.
- Confidence is high only with multi-source agreement or strong single-source evidence.

