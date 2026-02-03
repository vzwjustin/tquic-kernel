# CLAUDE.md - TQUIC Kernel Project

## Project Overview

TQUIC (True QUIC) is a kernel-level QUIC implementation for Linux, providing multipath WAN bonding capabilities. The core implementation is in `net/quic/`.

## Key Directories

```
net/quic/           # TQUIC implementation (main codebase)
├── ack.c           # ACK frame processing
├── cong.c          # Congestion control
├── connection.c    # Connection management
├── crypto.c/h      # Cryptographic operations
├── flow.c          # Flow control
├── loss.c          # Loss detection (RFC 9002)
├── output.c        # Packet transmission
├── packet.c        # Packet parsing
├── path.c          # Path management
├── protocol.c      # Protocol state machine
├── socket.c        # Socket interface
├── stream.c        # Stream management
├── timer.c         # Timer handling
├── tquic_bonding.c/h   # Multipath bonding
├── tquic_failover.c/h  # Failover logic
├── tquic_netlink.c     # Netlink interface
└── sched_*.c       # Multipath schedulers (aggregate, blest, ecf, minrtt, weighted)

kernel/             # Core kernel (upstream Linux - avoid modifying)
lib/                # Kernel libraries (upstream Linux - avoid modifying)
include/            # Headers (modify only for QUIC additions in include/net/quic/)
```

## Coding Standards

This is Linux kernel code. Follow kernel coding style:

- Tab indentation (not spaces)
- 80 character line limit (flexible for readability)
- K&R brace style
- Run `scripts/checkpatch.pl --strict -f <file>` before committing
- Use kernel APIs (kmalloc, kfree, list_head, etc.)

## RFC References

The implementation follows these specifications:
- **RFC 9000**: QUIC Transport Protocol
- **RFC 9001**: Using TLS to Secure QUIC
- **RFC 9002**: QUIC Loss Detection and Congestion Control
- **RFC 9114**: HTTP/3
- **RFC 9221**: QUIC Datagram Extension
- **draft-ietf-quic-multipath**: Multipath QUIC

## Common Tasks

### Code Review
Use `/kernel-code-review` skill for comprehensive kernel-style review.

### Debugging
Use `/kernel-debug` skill for debugging techniques and tools.

### Patch Preparation
Use `/patch-prep` skill to prepare patches for submission.

## Build Commands

```bash
# Configure (enable QUIC)
make menuconfig  # Enable CONFIG_IP_QUIC under Networking

# Build module only
make M=net/quic

# Check for warnings
make M=net/quic W=1

# Static analysis
make M=net/quic C=1
```

## Testing

```bash
# Run KUnit tests (when available)
./tools/testing/kunit/kunit.py run --kunitconfig=net/quic/tests/.kunitconfig

# Load module for testing
insmod net/quic/quic.ko

# Check kernel logs
dmesg | grep -i quic
```

## Important Notes

1. **Don't modify upstream code**: Files outside `net/quic/` and `include/net/quic/` are from upstream Linux kernel. Avoid changes unless absolutely necessary.

2. **Memory safety is critical**: All allocations must be checked, all error paths must free resources, all locks must be released.

3. **Network data is untrusted**: Every field from packets must be validated before use.

4. **Reference counting**: Use proper refcounting for shared objects (connections, streams).

## Agents Available

- `security-reviewer` - Security audit for kernel code
- `performance-analyzer` - Performance bottleneck analysis
- `test-generator` - Generate KUnit/kselftest tests

## Skills Available

- `/kernel-code-review` - Review patches for style/safety
- `/kernel-debug` - Debugging techniques and tools
- `/rfc-lookup` - Quick RFC section references
- `/patch-prep` - Prepare patches for submission
- `/quic-protocol-check` - Protocol compliance (auto-invoked)
