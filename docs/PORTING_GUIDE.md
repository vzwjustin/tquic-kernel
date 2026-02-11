# TQUIC Porting Guide

This guide documents the kernel API changes and compatibility issues encountered when porting TQUIC to different Linux kernel versions. It is intended for developers working on TQUIC compatibility across kernel versions.

## Target Environment

- **Primary Target**: Debian 6.12 kernel (DietPi)
- **Development Kernel**: Linux 6.19-rc7 (upstream)
- **Transport**: UDP encapsulation (per RFC 9000)

## Kernel API Changes Summary

### 1. Timer API (Kernel 6.2+)

**Change**: `del_timer_sync()` renamed to `timer_delete_sync()`

**Files Affected**: Multiple files using `del_timer_sync()`

**Solution**: Add compatibility macro in Makefile:
```makefile
ccflags-y += -Ddel_timer_sync=timer_delete_sync
```

**Files with timer calls**:
- `tquic_main.c`
- `tquic_timer.c`
- `quic_timer.c`
- `tquic_migration.c`
- `pm/path_manager.c`
- `pm/nat_keepalive.c`
- `pm/nat_lifecycle.c`
- `sched/deadline_aware.c`
- `sched/reorder.c`
- `multipath/path_abandon.c`
- `bond/tquic_bpm.c`
- `transport/tcp_fallback.c`
- `transport/quic_over_tcp.c`
- `masque/quic_proxy.c`
- `masque/connect_udp.c`
- `diag/path_metrics.c`
- `core/cid.c`
- `core/ack.c`
- `core/ack_frequency.c`
- `core/quic_connection.c`

### 2. Socket Address API (Kernel 6.x)

**Change**: Socket callbacks (`bind`, `connect`) now use `struct sockaddr_unsized *` instead of `struct sockaddr *`

**Files Affected**:
- `tquic_socket.c` - Socket operations
- `tquic_proto.c` - Protocol definitions
- `tquic_udp.c` - UDP connect
- `include/net/tquic.h` - API declarations

**Solution**: Update function signatures:
```c
// Old
int tquic_connect(struct sock *sk, struct sockaddr *addr, int addr_len);

// New
int tquic_connect(struct sock *sk, struct sockaddr_unsized *uaddr, int addr_len);
```

Cast internally for code that uses `struct sockaddr`:
```c
struct sockaddr *addr = (struct sockaddr *)uaddr;
```

### 3. UDP Tunnel API (Kernel 6.x)

**Change**: `udp_tunnel_xmit_skb()` and `udp_tunnel6_xmit_skb()` signatures changed

**Files Affected**:
- `tquic_udp.c`

**Issue**: The number of parameters and their types have changed. Requires checking the specific kernel version's `net/udp_tunnel.h` header.

**Workaround Options**:
1. Create wrapper functions with version checks
2. Add `#if LINUX_VERSION_CODE >= KERNEL_VERSION(x,y,z)` guards
3. Use UDP socket sendmsg instead of tunnel helpers

### 4. Kernel Connect API

**Change**: `kernel_connect()` now uses `struct sockaddr_unsized *`

**Files Affected**:
- `tquic_udp.c`

**Solution**:
```c
// Old
kernel_connect(sock, (struct sockaddr *)sin, sizeof(*sin), 0);

// New
kernel_connect(sock, (struct sockaddr_unsized *)sin, sizeof(*sin), 0);
```

### 5. Protocol Number (IPPROTO_TQUIC)

**Issue**: `IPPROTO_TQUIC = 263` exceeds 8-bit range for `inet_add_protocol()`

**Context**: QUIC runs over UDP (RFC 9000), not as a raw IP protocol. The protocol number is used for socket identification, not raw IP protocol handling.

**Solution**: Skip raw IP protocol handler registration since TQUIC uses UDP encapsulation:
```c
static int tquic_v4_add_protocol(void)
{
    /* TQUIC uses UDP encapsulation - no raw IP handler needed */
    pr_info("TQUIC uses UDP encapsulation\n");
    return 0;
}
```

## Optional Features (Kconfig)

These features are conditionally compiled and may require API porting for specific kernel versions:

### CONFIG_TQUIC_IO_URING
- **Reason**: io_uring symbols/structs mismatch with Debian 6.12 headers
- **Fix**: Port `net/tquic/io_uring.c` to 6.12 io_uring API or add compat guards

### CONFIG_TQUIC_NAPI
- **Reason**: `linux/napi.h` missing in Debian 6.12; NAPI hooks mismatch
- **Fix**: Refactor to use in-tree 6.12 NAPI APIs or add conditional paths

### CONFIG_TQUIC_AF_XDP
- **Reason**: Not enabled; dependency validation required
- **Fix**: Confirm AF_XDP deps, add Kconfig guards, implement 6.12 bindings

### CONFIG_TQUIC_OFFLOAD
- **Reason**: Not enabled; HW offload API compatibility needed
- **Fix**: Verify HW offload API compatibility with Debian 6.12

### CONFIG_TQUIC_OVER_TCP
- **Reason**: Not enabled; transport wiring needed
- **Fix**: Verify dependencies and transport wiring on Debian 6.12

## Build Configuration

### Makefile Compatibility Flags

Add these flags to `net/tquic/Makefile` and `net/tquic/Kbuild`:

```makefile
# Timer API compatibility: del_timer_sync renamed to timer_delete_sync in 6.2+
ccflags-y += -Ddel_timer_sync=timer_delete_sync

# Suppress development warnings (remove for production)
ccflags-y += -Wno-error=unused-function -Wno-error=unused-variable
ccflags-y += -Wno-error=missing-prototypes
```

### Type Alias for Path Manager

In `include/net/tquic_pm.h`:
```c
struct tquic_pm_state;
#define tquic_path_manager tquic_pm_state
```

## Testing Build

```bash
# In-tree build
cd /path/to/kernel-source
make M=net/tquic modules

# Out-of-tree build
cd /path/to/tquic-kernel/net/tquic
make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
```

## Common Build Errors

### "implicit declaration of function 'del_timer_sync'"
**Fix**: Add `-Ddel_timer_sync=timer_delete_sync` to ccflags

### "incompatible pointer type 'struct sockaddr *'"
**Fix**: Update function signatures to use `struct sockaddr_unsized *`

### "unsigned conversion from 'int' to 'unsigned char' changes value from '263'"
**Fix**: Skip `inet_add_protocol()` for TQUIC (uses UDP encapsulation)

### "too few arguments to function 'udp_tunnel_xmit_skb'"
**Fix**: Check kernel version's UDP tunnel API and update parameters

## Version-Specific Notes

### Kernel 6.2+
- Timer API: Use `timer_delete_sync()` instead of `del_timer_sync()`
- Socket API: `struct sockaddr_unsized *` in callbacks

### Kernel 6.12 (Debian)
- Timer API: `from_timer()` replaced with `timer_container_of()`
- Timer API: `del_timer()` renamed to `timer_delete()`
- Timer API: `hrtimer_init()` changed to `hrtimer_setup()` with callback param
- struct proto: `orphan_count` field removed
- inet_diag: `idiag_get_aux_size` field removed
- SNMP: `SNMP_MIB_SENTINEL` removed - use ARRAY_SIZE() instead
- Zerocopy: `msg_zerocopy_realloc()` adds `bool devmem` parameter
- Zerocopy: `skb_zerocopy_iter_stream()` adds `binding` parameter
- Crypto: `crypto_akcipher_verify()` removed - use `crypto_sig_verify()` from `<crypto/sig.h>`
- Crypto: Signature verification now uses synchronous `crypto_sig` API instead of async akcipher
- procfs: `single_open_net()` may be unavailable - use `single_open()` instead
- Stack: Kernel enforces 2048 byte frame limit - use dynamic allocation for large structures
- Some NAPI/io_uring APIs may differ from upstream
- Check header availability for optional features

### Kernel 6.19+ (Development)
- Latest APIs - primary development target

## Compatibility Header

Include `net/tquic/tquic_compat.h` in source files that use timer callbacks:

```c
#include "tquic_compat.h"  // For root-level files
#include "../tquic_compat.h"  // For files in subdirectories
```

This header provides compatibility macros for:
- `from_timer()` - maps to `timer_container_of()` on 6.12+
- `del_timer()` - maps to `timer_delete()` on 6.12+
- `del_timer_sync()` - maps to `timer_delete_sync()` on 6.12+
- May have additional changes not yet documented

## Contributing

When fixing compatibility issues:

1. Document the kernel version range affected
2. Add `#if LINUX_VERSION_CODE` guards if needed
3. Update this guide with the fix
4. Test on both target kernels

## References

- [RFC 9000](https://www.rfc-editor.org/rfc/rfc9000) - QUIC Transport Protocol
- [ROADMAP.md](ROADMAP.md) - Development roadmap
