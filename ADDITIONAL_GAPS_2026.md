# TQUIC Kernel Module - Additional Protocol Gaps Report

**Date:** 2026-02-02
**Methodology:** Web research (IETF drafts, CVEs, implementation best practices) + comprehensive codebase analysis

---

## Executive Summary

This document captures 15 additional QUIC protocol gaps discovered through research that were **NOT** in the original PROTOCOL_GAPS_2026.md. These fall into three categories:

1. **Security Vulnerability Mitigations** (7 gaps) - Critical CVEs and attack vectors from 2025-2026
2. **Emerging Protocol Extensions** (5 gaps) - New IETF drafts and proposals
3. **Implementation Best Practices** (3 gaps) - Performance and reliability optimizations

---

## Implementation Status

### ✅ IMPLEMENTED in This Commit

| Gap | Feature | Status |
|-----|---------|--------|
| A1 | QUIC-LEAK Defense (CVE-2025-54939) | ✅ Complete |
| A2 | Retire CID Stuffing Attack (CVE-2024-22189) | ✅ Complete |
| A3 | PATH_CHALLENGE Flooding Protection | ✅ Verified existing |
| A5 | Optimistic ACK Attack Protection | ✅ Complete |
| A6 | ACK Range Validation | ✅ Complete |
| A9 | Congestion Data Exchange | ✅ Complete |
| A11 | One-Way Delay Measurement | ✅ Complete |
| A13 | Spin Bit Privacy Controls | ✅ Complete |

### 🔶 Partially Implemented / Needs Verification

| Gap | Feature | Status |
|-----|---------|--------|
| A7 | Cipher NULL Check Audit | 🔶 Needs audit |
| A14 | Multipath draft-17 Verification | 🔶 Needs verification |
| A15 | Certificate Pinning Audit | 🔶 Needs audit |

### ⏳ Future Work

| Gap | Feature | Priority |
|-----|---------|----------|
| A4 | QUIC-Exfil Mitigation | P1 - High |
| A8 | NAT Lifecycle Optimization | P2 - Medium |
| A10 | BBRv3 Updates | P2 - Medium |
| A12 | QUIC Over Reliable Transport | P3 - Low |

---

## Security Gaps Implemented

### A1: QUIC-LEAK Defense (CVE-2025-54939)
**Location:** `security_hardening.c`, `security_hardening.h`

Pre-handshake memory exhaustion attack defense:
- Per-IP memory budgets before handshake completion
- Global pre-handshake memory limit (configurable via sysctl)
- Automatic cleanup when handshake completes

### A2: Retire CID Stuffing Attack (CVE-2024-22189)
**Location:** `security_hardening.c`, `tquic_cid.c`

Memory exhaustion via RETIRE_CONNECTION_ID frame flooding:
- Maximum 256 queued RETIRE_CID frames per connection
- Rate limiting for NEW_CONNECTION_ID processing (100/sec)
- Connection closed with PROTOCOL_VIOLATION if exceeded

### A5: Optimistic ACK Attack Protection
**Location:** `security_hardening.c`

Detection of attackers ACKing packets that were never sent:
- Packet number skipping (1-255 random gaps)
- Configurable skip rate via sysctl (default 1/128)
- Detection when skipped PNs are ACKed

### A6: ACK Range Validation
**Location:** `security_hardening.c`

Validation that ACK ranges only reference sent packets:
- Track largest_sent_pn per packet number space
- Validate ACK.largest_acknowledged <= largest_sent
- Connection closed on invalid ACK

### A13: Spin Bit Privacy Controls
**Location:** `security_hardening.c`

Privacy controls for the latency spin bit:
- Policy: always (0), never (1), probabilistic (2)
- Default 12.5% random when probabilistic
- Configurable via sysctl

---

## Protocol Extensions Implemented

### A9: Congestion Data Exchange (draft-yuan-quic-congestion-data-00)
**Location:** `cong/cong_data.c`, `cong/cong_data.h`

Share congestion state between endpoints:
- CONGESTION_DATA frame with BWE, RTT, loss rate
- 0-RTT integration for faster startup
- Privacy controls (FULL, PARTIAL, MINIMAL, DISABLED)
- Careful Resume validation

### A11: One-Way Delay Measurement (draft-huitema-quic-1wd)
**Location:** `core/one_way_delay.c`, `core/one_way_delay.h`

Measure directional delays on asymmetric paths:
- ACK_1WD (0x1a02) and ACK_1WD_ECN (0x1a03) frames
- Clock skew estimation
- OWD-aware multipath scheduler
- Critical for satellite/cellular links

---

## Sysctl Parameters Added

```
# Security Hardening
net.tquic.pre_handshake_memory_limit = 67108864  # 64 MB
net.tquic.pn_skip_rate = 128                      # 1/128 packets
net.tquic.spin_bit_policy = 2                     # probabilistic

# Rate Limiting
net.tquic.rate_limit_enabled = 1
net.tquic.max_connections_per_second = 10000
net.tquic.max_connections_burst = 1000
net.tquic.per_ip_rate_limit = 100
```

---

## Sources

### CVE References
- [CVE-2025-54939 (QUIC-LEAK)](https://www.imperva.com/blog/quic-leak-cve-2025-54939/)
- [CVE-2024-22189 (Retire CID Stuffing)](https://github.com/quic-go/quic-go/security/advisories/GHSA-c33x-xqrf-c478)
- [CVE-2025-4820/4821 (Cloudflare ACK Attacks)](https://blog.cloudflare.com/defending-quic-from-acknowledgement-based-ddos-attacks/)

### IETF Drafts
- [draft-yuan-quic-congestion-data-00](https://datatracker.ietf.org/doc/draft-yuan-quic-congestion-data/)
- [draft-huitema-quic-1wd-00](https://datatracker.ietf.org/doc/draft-huitema-quic-1wd/)
- [draft-ietf-quic-multipath-17](https://datatracker.ietf.org/doc/draft-ietf-quic-multipath/)

### Research Papers
- [QUIC-Exfil: ASIA CCS 2025](https://arxiv.org/html/2505.05292v1)
- [Spin Bit Privacy Analysis](https://arxiv.org/abs/2310.02599)
