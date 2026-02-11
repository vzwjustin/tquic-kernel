# Roadmap

## Completed

- Full QUIC v1/v2 protocol implementation (RFC 9000, 9001, 9002, 9369)
- HTTP/3 + QPACK (RFC 9114, 9204)
- Multipath QUIC with 7 schedulers and 10 congestion control algorithms
- DATAGRAM extension (RFC 9221), WebTransport, MASQUE
- QUIC-LB load balancing, FEC, GREASE
- 11 rounds of security audit fixes (deadlocks, UAFs, races, overflows, DoS)
- 78 KUnit test suites across 35 test files
- GRO/GSO, zero-copy, AF_XDP, io_uring performance paths

## Short-Term

- **Kernel version porting** - Validate and fix API compatibility across 6.x kernels
- **Out-of-tree build hardening** - Streamline module build for non-development kernels
- **Test coverage** - Expand KUnit tests for edge cases and error paths

## Medium-Term

- **Userspace CLI** for netlink configuration and diagnostics
- **Sample path manager** and example bonding profiles
- **Interop validation** against quiche, msquic, ngtcp2, picoquic

## Long-Term

- Split patches by subsystem for upstream review
- Align APIs with in-tree QUIC changes (if any)
- Reduce delta against mainline
