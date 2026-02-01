# TQUIC Kernel Implementation - Comprehensive Gap Analysis

**Date:** 2026-02-01
**Methodology:** Online research of IETF RFCs/drafts + deep codebase scan

---

## Executive Summary

Based on comprehensive research of current IETF QUIC specifications and comparison with the TQUIC kernel implementation, **18 major gaps** have been identified across 8 categories. The implementation is strong in core QUIC v1, multipath basics, and ECN, but lacks several advanced features required for full production readiness.

---

## 1. QUIC Version 2 (RFC 9369)

### Current Status: PARTIAL

| Requirement | Status | Notes |
|-------------|--------|-------|
| Version constant `0x6b3343cf` | DONE | `include/net/tquic.h:27` |
| v2 Retry integrity keys | DONE | `tquic_retry.c:68-75` |
| v2 Initial salt | **MISSING** | Need `0x0dede3def700a6db819381be6e269dcbf9bd2ed9` |
| v2 HKDF labels | **MISSING** | Need `"quicv2 key"`, `"quicv2 iv"`, `"quicv2 hp"`, `"quicv2 ku"` |
| v2 Packet type encodings | **MISSING** | v2 uses different long header packet type bits |
| `version_information` TP (0x11) | **MISSING** | Required for RFC 9368 compatible version negotiation |

### Files to Create/Modify
- `crypto/tls.c` - Add v2 salt and version-aware label selection
- `core/packet.c` - Add version-aware packet type encoding/decoding
- `core/transport_params.c` - Add version_information (0x11) transport parameter

---

## 2. Multipath QUIC (draft-ietf-quic-multipath-17)

### Current Status: MOSTLY COMPLETE

| Requirement | Status | Notes |
|-------------|--------|-------|
| PATH_ABANDON frame (0x15c0) | DONE | Full implementation |
| PATH_STATUS frame (0x15c08) | DONE | Full implementation |
| MP_ACK frame (0x42/0x43) | DONE | Per-path ACK state |
| MP_NEW_CONNECTION_ID (0x40) | DONE | Path-specific CID issuance |
| MP_RETIRE_CONNECTION_ID (0x41) | DONE | Path-specific CID retirement |
| `enable_multipath` TP | DONE | `0x0f739bbc1b666d05ULL` |
| `initial_max_path_id` TP | **MISSING** | Needed to negotiate max path count |
| Per-path packet number spaces | PARTIAL | Has per-level PN spaces, needs full per-path |
| Path ID in AEAD nonce | **NEEDS VERIFICATION** | Required for multipath security |

### Files to Create/Modify
- `core/transport_params.c` - Add `initial_max_path_id` transport parameter
- `crypto/aead.c` - Verify path ID included in nonce calculation

---

## 3. QUIC Load Balancing (draft-ietf-quic-load-balancers-21)

### Current Status: NOT IMPLEMENTED

| Requirement | Status | Notes |
|-------------|--------|-------|
| Server ID encoding in CIDs | **MISSING** | Need plaintext/obfuscated/encrypted modes |
| Config rotation (3-bit codepoint) | **MISSING** | First octet structure for LB routing |
| Retry Service (shared state) | **MISSING** | AES-GCM token encryption |
| Retry Service (no shared state) | **MISSING** | Stateless token validation |
| QUIC-LB protocol (0xF1000000) | **MISSING** | Config distribution protocol |

### Files to Create
```
net/tquic/lb/
├── quic_lb.h           # QUIC-LB definitions
├── quic_lb.c           # Server ID encoding/decoding
├── cid_routing.c       # CID-based routing logic
├── retry_service.c     # Retry offload service
└── lb_config.c         # Configuration management
```

---

## 4. ECN / L4S / AccECN

### Current Status: ECN DONE, L4S MISSING

| Requirement | Status | Notes |
|-------------|--------|-------|
| ECN validation | DONE | `core/ack.c:1592-1653` |
| ECN feedback in ACKs | DONE | Both ACK_ECN and MP_ACK_ECN |
| Per-path ECN state | DONE | `tquic_input.c:113` |
| ECN congestion response | DONE | `cong/tquic_cong.c:1071-1159` |
| L4S (ECT(1) marking) | **MISSING** | RFC 9330/9331 |
| AccECN (accurate feedback) | **MISSING** | draft-seemann-quic-accurate-ack-ecn |
| Prague congestion control | **MISSING** | L4S-compatible CC |

### Files to Create
```
net/tquic/cong/
├── prague.c            # Prague CC for L4S
└── l4s.c               # L4S marking/detection
net/tquic/core/
└── accecn.c            # Accurate ECN feedback
```

---

## 5. WebTransport (draft-ietf-webtrans-http3-14)

### Current Status: NOT IMPLEMENTED

| Requirement | Status | Notes |
|-------------|--------|-------|
| Extended CONNECT (`:protocol=webtransport`) | **MISSING** | RFC 9220 |
| WT_STREAM frame (0x41) | **MISSING** | Bidirectional streams |
| Unidirectional stream type (0x54) | **MISSING** | WebTransport uni streams |
| WT_MAX_DATA capsule (0x190B4D3D) | **MISSING** | Session flow control |
| WT_MAX_STREAMS capsules | **MISSING** | Stream limits |
| WT_CLOSE_SESSION (0x2843) | **MISSING** | Session termination |
| Session ID management | **MISSING** | CONNECT stream ID |

### Files to Create
```
net/tquic/webtrans/
├── webtrans.h          # WebTransport definitions
├── webtrans.c          # Session management
├── wt_stream.c         # Stream handling
├── wt_capsule.c        # Capsule encoding/decoding
└── wt_flow.c           # Flow control capsules
```

---

## 6. MASQUE (RFC 9297, 9298, 9484)

### Current Status: NOT IMPLEMENTED

| Requirement | Status | Notes |
|-------------|--------|-------|
| HTTP Datagrams (RFC 9297) | PARTIAL | DATAGRAM frames exist |
| CONNECT-UDP (RFC 9298) | **MISSING** | UDP proxying |
| CONNECT-IP (RFC 9484) | **MISSING** | IP proxying |
| Capsule Protocol | **MISSING** | Type-Length-Value encoding |
| QUIC-aware proxy | **MISSING** | draft-ietf-masque-quic-proxy |

### Files to Create
```
net/tquic/masque/
├── masque.h            # MASQUE definitions
├── capsule.c           # Capsule protocol
├── connect_udp.c       # CONNECT-UDP tunneling
├── connect_ip.c        # CONNECT-IP tunneling
└── quic_proxy.c        # QUIC-aware proxying
```

---

## 7. Performance Optimizations

### Current Status: PARTIAL

| Optimization | Status | Notes |
|--------------|--------|-------|
| UDP GSO | DONE | `gso.c` |
| UDP GRO | DONE | `gro.c` |
| Zero-copy TX/RX | DONE | `zerocopy.c` |
| AF_XDP | DONE | `af_xdp.c` |
| io_uring | DONE | `io_uring.c` |
| NAPI polling | DONE | `napi.c` |
| Hardware crypto offload | **MISSING** | AES-NI/VAES detection |
| SmartNIC offload | **MISSING** | FPGA/NIC header processing |
| BBRv2 | **MISSING** | Only BBRv1 implemented |
| Pacing within GSO | **MISSING** | Kernel FQ integration |

### Files to Create/Modify
- `cong/bbrv2.c` - BBR version 2
- `crypto/hw_offload.c` - Hardware crypto detection/offload
- `accel/smartnic.c` - SmartNIC integration

---

## 8. Additional Missing Features

### HTTP/3 Enhancements
| Feature | Status |
|---------|--------|
| QPACK dynamic table | PARTIAL |
| Server Push | **MISSING** |
| Priority (RFC 9218) | **MISSING** |
| Extended CONNECT | **MISSING** |

### Security Features
| Feature | Status |
|---------|--------|
| Stateless reset token rotation | **MISSING** |
| Connection ID linkability prevention | PARTIAL |
| Anti-amplification strict enforcement | **NEEDS VERIFICATION** |

### Diagnostic Features
| Feature | Status |
|---------|--------|
| QUIC trace logging (qlog) | **MISSING** |
| Detailed connection statistics export | PARTIAL |
| Path-specific metrics export | **MISSING** |

---

## Implementation Priority Matrix

### P0 - Required for Production (Weeks 1-4)

| Feature | Effort | Impact |
|---------|--------|--------|
| QUIC v2 initial salt + labels | Low | High - interop |
| QUIC v2 packet type encodings | Medium | High - interop |
| `version_information` TP | Medium | High - security |
| `initial_max_path_id` TP | Low | Medium - multipath |
| Path ID in AEAD nonce verification | Low | Critical - security |

### P1 - Important for Enterprise (Weeks 5-8)

| Feature | Effort | Impact |
|---------|--------|--------|
| QUIC-LB server ID encoding | High | High - scalability |
| L4S support | Medium | Medium - latency |
| BBRv2 | Medium | Medium - performance |
| Hardware crypto offload | Medium | High - performance |

### P2 - Advanced Features (Weeks 9-16)

| Feature | Effort | Impact |
|---------|--------|--------|
| WebTransport | High | Medium - features |
| MASQUE | High | Medium - features |
| QUIC-aware proxy | High | Low - niche |
| SmartNIC offload | Very High | High - performance |

---

## Estimated Lines of Code

| Category | New Files | Estimated LOC |
|----------|-----------|---------------|
| QUIC v2 completion | 0 (modifications) | ~500 |
| Multipath gaps | 1 | ~200 |
| QUIC-LB | 5 | ~3,000 |
| L4S/AccECN | 3 | ~1,500 |
| WebTransport | 5 | ~4,000 |
| MASQUE | 5 | ~5,000 |
| Performance gaps | 3 | ~2,000 |
| **Total** | **22** | **~16,200** |

---

## Recommended Next Steps

1. **Immediate (This Week)**
   - Add QUIC v2 initial salt and HKDF labels
   - Add `version_information` transport parameter
   - Verify path ID in AEAD nonce calculation

2. **Short Term (Next 2 Weeks)**
   - Add QUIC v2 packet type encoding
   - Add `initial_max_path_id` transport parameter
   - Implement BBRv2 congestion control

3. **Medium Term (Next Month)**
   - Implement QUIC-LB server ID encoding
   - Add L4S support
   - Add hardware crypto offload detection

4. **Long Term (Next Quarter)**
   - Implement WebTransport
   - Implement MASQUE
   - Add SmartNIC offload support

---

## Sources

- RFC 9369 - QUIC Version 2
- RFC 9368 - Compatible Version Negotiation for QUIC
- draft-ietf-quic-multipath-17 - Multipath QUIC
- draft-ietf-quic-load-balancers-21 - QUIC-LB
- RFC 9330/9331 - L4S Architecture and ECN Protocol
- draft-ietf-webtrans-http3-14 - WebTransport over HTTP/3
- RFC 9297/9298/9484 - MASQUE protocols
- lxin/quic - Linux kernel QUIC reference
- MsQuic - Microsoft kernel QUIC reference
