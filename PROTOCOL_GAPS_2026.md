# TQUIC Kernel Module - QUIC Protocol Gaps Analysis (2026)

**Date:** 2026-02-02
**Methodology:** IETF RFC/Draft research + comprehensive codebase analysis

---

## Executive Summary

Based on analysis of the latest IETF QUIC specifications (as of February 2026) and comparison with the TQUIC kernel implementation, **12 major protocol gaps** have been identified. The implementation is strong in core features, but lacks several emerging extensions that are critical for optimal performance, debugging, and interoperability.

### Current Implementation Status (VERIFIED)

| Category | Status |
|----------|--------|
| RFC 9000 (QUIC v1) | COMPLETE |
| RFC 9001 (QUIC-TLS) | COMPLETE |
| RFC 9002 (Loss Detection) | COMPLETE |
| RFC 9114 (HTTP/3) | COMPLETE |
| RFC 9204 (QPACK) | COMPLETE |
| RFC 9221 (DATAGRAM) | COMPLETE |
| RFC 9287 (GREASE) | COMPLETE |
| RFC 9368 (Compatible Version Negotiation) | COMPLETE |
| RFC 9369 (QUIC v2 + Multipath) | COMPLETE |
| WebTransport | COMPLETE |
| MASQUE (RFC 9297/9298/9484) | COMPLETE |
| QUIC-LB | COMPLETE |
| ACK Frequency | COMPLETE |
| L4S/Prague/AccECN | COMPLETE |
| BBRv2 | COMPLETE |

---

## Protocol Gaps Requiring Implementation

### Gap 1: RESET_STREAM_AT Frame (Reliable Stream Reset)
**Draft:** [draft-ietf-quic-reliable-stream-reset-07](https://datatracker.ietf.org/doc/draft-ietf-quic-reliable-stream-reset/)
**Status:** Standards Track (WGLC completed)
**Priority:** HIGH

#### Description
Allows resetting a stream while guaranteeing delivery of data up to a specified byte offset. Essential for WebTransport session ID delivery and partial content scenarios.

#### New Frame Type
```
RESET_STREAM_AT (0x24):
  Stream ID (i)
  Application Protocol Error Code (i)
  Final Size (i)
  Reliable Size (i)
```

#### Transport Parameter
- `reliable_stream_reset` (0x17cd): Indicates support for the extension

#### Implementation Requirements
- New frame type `TQUIC_FRAME_RESET_STREAM_AT` (0x24)
- Modify stream state machine to support partial delivery guarantee
- Buffer management for reliable portion retransmission
- Negotiation via transport parameter

#### Files to Create/Modify
```
net/tquic/core/stream.c          - Stream state machine updates
net/tquic/core/frame.c           - RESET_STREAM_AT encoding/decoding
net/tquic/core/transport_params.c - reliable_stream_reset parameter
```

#### Estimated LOC: ~800

---

### Gap 2: Receive Timestamps Extension
**Draft:** [draft-smith-quic-receive-ts-03](https://datatracker.ietf.org/doc/draft-smith-quic-receive-ts/)
**Status:** Adopted by QUIC WG (July 2025)
**Priority:** HIGH

#### Description
Enables reporting packet receive timestamps in ACK frames for improved RTT estimation, bandwidth measurement, and congestion control accuracy. Critical for real-time applications.

#### New Frame Type
```
ACK_RECEIVE_TIMESTAMPS (0x40-0x41 range, TBD):
  Largest Acknowledged (i)
  ACK Delay (i)
  ACK Range Count (i)
  First ACK Range (i)
  ACK Ranges (...)
  Timestamp Section Count (i)
  Timestamp Sections:
    Gap (i)
    Timestamp Delta Count (i)
    Timestamp Deltas (i...)
```

#### Transport Parameters
- `max_receive_timestamps_per_ack` (0xff0a002): Maximum timestamps per ACK
- `receive_timestamps_exponent` (0xff0a003): Timestamp precision exponent

#### Implementation Requirements
- Per-packet receive timestamp recording with microsecond precision
- ACK frame extension with timestamp sections
- Timestamp basis calculation and delta encoding
- Session-wide timestamp basis management

#### Files to Create
```
net/tquic/core/receive_timestamps.h  - Data structures and API
net/tquic/core/receive_timestamps.c  - Timestamp recording and encoding
net/tquic/core/ack.c                 - Modify ACK generation
net/tquic/cong/                      - Integrate with congestion control
```

#### Estimated LOC: ~1,200

---

### Gap 3: Address Discovery Extension
**Draft:** [draft-ietf-quic-address-discovery-00](https://datatracker.ietf.org/doc/draft-ietf-quic-address-discovery/)
**Status:** Adopted by QUIC WG
**Priority:** MEDIUM-HIGH

#### Description
Allows endpoints to discover their external IP address and port. Critical for NAT traversal, connection migration planning, and peer-to-peer scenarios.

#### New Frame Type
```
OBSERVED_ADDRESS (0x9f00, provisional):
  Sequence Number (i)
  IP Version (8)
  IP Address (32 or 128 bits)
  Port (16)
```

#### Transport Parameters
- `observed_address` (TBD): Offer to send OBSERVED_ADDRESS frames
- `request_observed_address` (TBD): Request to receive observations

#### Implementation Requirements
- Track remote endpoint address changes per path
- Generate OBSERVED_ADDRESS frames on address observation
- Detect NAT rebinding events
- Rate limit frame generation to prevent amplification

#### Files to Create
```
net/tquic/core/address_discovery.h  - Definitions
net/tquic/core/address_discovery.c  - OBSERVED_ADDRESS handling
net/tquic/pm/path_manager.c         - Integration with path management
```

#### Estimated LOC: ~700

---

### Gap 4: BDP Frame Extension (Bandwidth-Delay Product)
**Draft:** [draft-kuhn-quic-bdpframe-extension-05](https://datatracker.ietf.org/doc/draft-kuhn-quic-bdpframe-extension/)
**Status:** Individual Draft
**Priority:** MEDIUM

#### Description
Enables exchange of path characteristics (BDP, RTT, cwnd) between endpoints for faster connection resumption on high-BDP paths. Particularly valuable for satellite and long-distance links.

#### New Frame Type
```
BDP_FRAME (0x1f, provisional):
  BDP (i)                    - Bandwidth-delay product in bytes
  Saved CWND (i)             - Preserved congestion window
  Saved RTT (i)              - Preserved minimum RTT (microseconds)
  Lifetime (i)               - Validity period (seconds)
  Endpoint Token (variable)  - Session identifier
  Hash (16 bytes)            - Authentication
```

#### Transport Parameters
- `enable_bdp_frame` (TBD): Enable BDP frame exchange

#### Implementation Requirements
- Secure BDP frame generation with HMAC authentication
- 0-RTT BDP restoration with careful validation
- Integration with congestion control for "Careful Resume"
- Rate limiting and anti-abuse measures

#### Files to Create
```
net/tquic/cong/bdp_frame.h      - BDP frame definitions
net/tquic/cong/bdp_frame.c      - Frame handling and validation
net/tquic/cong/careful_resume.c - Careful Resume integration
```

#### Estimated LOC: ~900

---

### Gap 5: Extended Key Update
**Draft:** [draft-ietf-quic-extended-key-update-01](https://datatracker.ietf.org/doc/draft-ietf-quic-extended-key-update/)
**Status:** Adopted by QUIC WG (July 2025)
**Priority:** MEDIUM-HIGH

#### Description
Replaces the QUIC Key Update mechanism with an extended version based on TLS Extended Key Update. Provides additional security for long-lived connections and enables external PSK injection.

#### Key Changes from RFC 9001 Key Update
- New key update request/response handshake
- Support for external PSK injection during connection
- Bidirectional key update coordination
- Enhanced replay protection

#### New Frame Types (TBD)
```
KEY_UPDATE_REQUEST
KEY_UPDATE_RESPONSE
```

#### Implementation Requirements
- Extended key update state machine
- PSK injection API for external key material
- Coordination with existing key_update.c
- Backwards compatibility with RFC 9001 key update

#### Files to Create/Modify
```
net/tquic/crypto/extended_key_update.h  - Extended key update definitions
net/tquic/crypto/extended_key_update.c  - Implementation
net/tquic/crypto/key_update.c           - Integration/fallback
```

#### Estimated LOC: ~1,000

---

### Gap 6: Forward Error Correction (FEC) Extension
**Draft:** [draft-zheng-quic-fec-extension-01](https://datatracker.ietf.org/doc/draft-zheng-quic-fec-extension/)
**Status:** Individual Draft (Expires March 2026)
**Priority:** MEDIUM

#### Description
Adds Forward Error Correction to QUIC, allowing receivers to recover lost packets without retransmission. Critical for low-latency scenarios (gaming, video conferencing) and lossy networks.

#### New Frame Types
```
FEC_REPAIR (0xfc00, provisional):
  FEC Scheme ID (i)
  Source Block Number (i)
  Repair Symbol Index (i)
  Repair Symbol Data (variable)

FEC_SOURCE_SYMBOL_INFO:
  Source Block Number (i)
  Source Symbol Count (i)
  Symbol Size (i)
```

#### Transport Parameters
- `enable_fec` (TBD): Enable FEC support
- `fec_scheme` (TBD): Supported FEC schemes (Reed-Solomon, XOR, etc.)
- `max_source_symbols` (TBD): Maximum source symbols per block

#### Implementation Requirements
- FEC encoder/decoder (Reed-Solomon recommended)
- Source block management and symbol tracking
- Repair symbol generation and scheduling
- Integration with loss detection to avoid redundant FEC + retransmit

#### Files to Create
```
net/tquic/fec/
├── fec.h               - FEC definitions and API
├── fec_encoder.c       - Encoding logic
├── fec_decoder.c       - Decoding logic
├── fec_scheduler.c     - Repair symbol scheduling
├── reed_solomon.c      - Reed-Solomon implementation
└── xor_fec.c           - Simple XOR FEC (optional)
```

#### Estimated LOC: ~2,500

---

### Gap 7: Deadline-Aware Multipath Scheduling
**Draft:** [draft-tjohn-quic-multipath-dmtp-01](https://www.ietf.org/archive/id/draft-tjohn-quic-multipath-dmtp-01.html)
**Status:** Individual Draft (August 2025)
**Priority:** MEDIUM

#### Description
Extends multipath QUIC with deadline-aware stream scheduling. Packets are scheduled across paths to meet application-specified deadlines, optimal for real-time media.

#### New Transport Parameters
- `enable_deadline_aware` (TBD): Enable deadline-aware scheduling
- `deadline_granularity` (TBD): Deadline precision in microseconds

#### New Frame Extensions
```
STREAM (extended):
  + Deadline (i, optional) - Delivery deadline in microseconds from now

STREAM_DEADLINE:
  Stream ID (i)
  Deadline (i)
```

#### Implementation Requirements
- Per-stream deadline tracking
- Deadline-aware path selection algorithm
- Integration with existing multipath scheduler (ECF, BLEST)
- Deadline miss statistics and handling

#### Files to Create/Modify
```
net/tquic/sched/deadline_aware.c  - Deadline-aware scheduler
net/tquic/core/stream.h           - Add deadline field
net/tquic/multipath/mp_sched.c    - Scheduler integration
```

#### Estimated LOC: ~800

---

### Gap 8: Connection Rate Limiting
**Standard:** Best practice / QUIC applicability guidance
**Priority:** HIGH (Security)

#### Description
Currently missing per-namespace and global connection accept rate limiting to prevent DoS attacks and resource exhaustion.

#### Implementation Requirements
- Per-netns connection accept rate limiter (token bucket)
- Global connection rate limiter
- Configurable via sysctl
- Integration with initial packet processing

#### Files to Create
```
net/tquic/rate_limit.h     - Rate limiter definitions
net/tquic/rate_limit.c     - Token bucket implementation
net/tquic/tquic_sysctl.c   - Add sysctl parameters
net/tquic/tquic_input.c    - Integration point
```

#### Sysctl Parameters
```
net.tquic.max_connections_per_second = 10000
net.tquic.max_connections_burst = 1000
net.tquic.per_ip_rate_limit = 100
```

#### Estimated LOC: ~500

---

### Gap 9: Additional Addresses Extension
**Draft:** [draft-piraux-quic-additional-addresses-00](https://www.rfc-editor.org/rfc/internet-drafts/draft-piraux-quic-additional-addresses-00.xml)
**Priority:** MEDIUM

#### Description
Allows servers to advertise multiple addresses beyond preferred_address. Clients can migrate to any advertised address, improving reliability and load distribution.

#### Transport Parameter
```
additional_addresses (TBD):
  Count (i)
  Addresses:
    IP Version (8)
    IP Address (32 or 128)
    Port (16)
    CID (variable)
    Stateless Reset Token (16)
```

#### Implementation Requirements
- Extended preferred_address handling
- Multi-address advertisement from server
- Client address selection logic
- Path validation for each additional address

#### Files to Modify
```
net/tquic/core/transport_params.c  - Additional addresses encoding
net/tquic/pm/path_manager.c        - Address selection
net/tquic/tquic_migration.c        - Migration to additional addresses
```

#### Estimated LOC: ~600

---

### Gap 10: NAT Keepalive Optimization
**Reference:** RFC 9308 (Applicability) Section 3.5
**Priority:** LOW-MEDIUM

#### Description
Implement optimized NAT keepalive using minimal PING frames with configurable intervals based on detected NAT binding timeout.

#### Implementation Requirements
- NAT binding timeout detection/estimation
- Adaptive PING interval selection
- Path-specific keepalive timers
- Statistics for keepalive overhead

#### Files to Modify
```
net/tquic/pm/path_manager.c   - Keepalive timer management
net/tquic/tquic_timer.c       - Timer integration
net/tquic/tquic_sysctl.c      - Configurable intervals
```

#### Estimated LOC: ~300

---

### Gap 11: QUIC-Aware Proxy Protocol
**Draft:** [draft-ietf-masque-quic-proxy](https://datatracker.ietf.org/doc/draft-ietf-masque-quic-proxy/)
**Priority:** LOW

#### Description
Extends MASQUE for QUIC-aware proxying where the proxy can inspect and optimize QUIC connections while maintaining end-to-end encryption of application data.

#### Implementation Requirements (Complex)
- Connection ID cooperation between client-proxy-server
- Split connection state management
- Header compression across proxy hops
- Integration with existing MASQUE implementation

#### Files to Create
```
net/tquic/masque/quic_proxy.h  - QUIC proxy definitions
net/tquic/masque/quic_proxy.c  - Proxy implementation
```

#### Estimated LOC: ~2,000

---

### Gap 12: qlog Events for Diagnostics
**Draft:** [draft-ietf-quic-qlog-quic-events-12](https://datatracker.ietf.org/doc/draft-ietf-quic-qlog-quic-events/)
**Status:** WG Draft (October 2025)
**Priority:** MEDIUM

#### Description
Comprehensive logging format for QUIC debugging and performance analysis. The current qlog implementation needs updates to match the latest draft specification.

#### Required Event Updates (partial list)
```
transport:packet_sent
transport:packet_received
transport:packet_dropped
transport:packet_buffered
recovery:metrics_updated
recovery:congestion_state_updated
connectivity:connection_started
connectivity:connection_closed
connectivity:path_updated
security:key_updated
security:key_discarded
```

#### Implementation Requirements
- Update existing qlog.c to latest draft
- Add missing event types
- Structured JSON/NDJSON output
- Integration with tracing subsystem

#### Files to Modify
```
net/tquic/diag/qlog.c           - Update event definitions
net/tquic/diag/qlog.h           - Update structures
include/uapi/linux/tquic_qlog.h - Update UAPI
```

#### Estimated LOC: ~600

---

## Implementation Priority Matrix

### P0 - Critical (Implement First)

| Gap | Feature | Effort | Impact |
|-----|---------|--------|--------|
| 1 | RESET_STREAM_AT | Medium | High - WebTransport reliability |
| 2 | Receive Timestamps | Medium | High - RTT/bandwidth accuracy |
| 8 | Connection Rate Limiting | Low | Critical - Security |

### P1 - Important (Next Sprint)

| Gap | Feature | Effort | Impact |
|-----|---------|--------|--------|
| 3 | Address Discovery | Medium | High - NAT traversal |
| 5 | Extended Key Update | Medium | Medium - Long connections |
| 12 | qlog Updates | Low | Medium - Debugging |

### P2 - Enhancement (Future)

| Gap | Feature | Effort | Impact |
|-----|---------|--------|--------|
| 4 | BDP Frame | Medium | Medium - High-BDP paths |
| 6 | FEC Extension | High | High - Lossy networks |
| 7 | Deadline Multipath | Medium | Medium - Real-time |
| 9 | Additional Addresses | Low | Medium - Reliability |
| 10 | NAT Keepalive | Low | Low - Efficiency |
| 11 | QUIC-Aware Proxy | High | Low - Niche |

---

## Estimated Total Implementation Effort

| Priority | Gaps | Estimated LOC | Estimated Time |
|----------|------|---------------|----------------|
| P0 | 3 | ~2,500 | 2-3 weeks |
| P1 | 3 | ~2,300 | 2-3 weeks |
| P2 | 6 | ~7,100 | 6-8 weeks |
| **Total** | **12** | **~11,900** | **10-14 weeks** |

---

## Recommended Implementation Order

1. **Week 1-2: Connection Rate Limiting**
   - Security-critical, low effort
   - Immediate production benefit

2. **Week 2-3: RESET_STREAM_AT**
   - WebTransport dependency
   - Approaching RFC status

3. **Week 3-5: Receive Timestamps**
   - High impact on congestion control accuracy
   - Recently adopted by WG

4. **Week 5-6: Address Discovery**
   - NAT traversal improvement
   - Multipath optimization

5. **Week 6-7: qlog Updates**
   - Debugging and monitoring
   - Lower risk, high value

6. **Week 7-9: Extended Key Update**
   - Long-lived connection security
   - TLS 1.3 alignment

7. **Week 9-12: BDP Frame + FEC (if time permits)**
   - Performance optimizations
   - Specialized use cases

---

## Sources

- [draft-ietf-quic-reliable-stream-reset-07](https://datatracker.ietf.org/doc/draft-ietf-quic-reliable-stream-reset/)
- [draft-smith-quic-receive-ts-03](https://datatracker.ietf.org/doc/draft-smith-quic-receive-ts/)
- [draft-ietf-quic-address-discovery-00](https://datatracker.ietf.org/doc/draft-ietf-quic-address-discovery/)
- [draft-kuhn-quic-bdpframe-extension-05](https://datatracker.ietf.org/doc/draft-kuhn-quic-bdpframe-extension/)
- [draft-ietf-quic-extended-key-update-01](https://datatracker.ietf.org/doc/draft-ietf-quic-extended-key-update/)
- [draft-zheng-quic-fec-extension-01](https://datatracker.ietf.org/doc/draft-zheng-quic-fec-extension/)
- [draft-ietf-quic-qlog-quic-events-12](https://datatracker.ietf.org/doc/draft-ietf-quic-qlog-quic-events/)
- [RFC 9368 - Compatible Version Negotiation](https://datatracker.ietf.org/doc/html/rfc9368)
- [RFC 9308 - QUIC Applicability](https://www.rfc-editor.org/rfc/rfc9308.html)
- [IETF QUIC Working Group](https://quicwg.org/)
