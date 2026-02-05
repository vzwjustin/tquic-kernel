# TQUIC Porting Gaps (Debian 6.12 / DietPi)

This document lists what is still not enabled or not yet ported in the current
Debian 6.12-based TQUIC kernel build, and why.

See [docs/PORTING_GUIDE.md](docs/PORTING_GUIDE.md) for detailed porting instructions.

## Kernel API Compatibility (Fixed)

The following API changes have been addressed with compatibility layers:

- **Timer API**: `del_timer_sync()` → `timer_delete_sync()` (via Makefile `-D` flag)
- **Socket Address API**: `struct sockaddr *` → `struct sockaddr_unsized *` in callbacks
- **Path Manager Types**: `tquic_path_manager` aliased to `tquic_pm_state`
- **Protocol Registration**: IPPROTO_TQUIC (263) - UDP encapsulation used instead of raw IP

## Kernel API Compatibility (In Progress)

- **UDP Tunnel API**: `udp_tunnel_xmit_skb()` / `udp_tunnel6_xmit_skb()` signature changes
  - Status: Requires kernel version-specific parameter updates
  - Files: `tquic_udp.c`

## Disabled / Not Yet Ported

- `CONFIG_TQUIC_IO_URING`
  - Reason: io_uring symbols/structs mismatch with Debian 6.12 headers.
  - Needed: port `net/tquic/io_uring.c` to 6.12 io_uring API or add compat guards.

- `CONFIG_TQUIC_NAPI`
  - Reason: `linux/napi.h` missing in Debian 6.12 headers; NAPI hooks mismatch.
  - Needed: refactor to use in-tree 6.12 NAPI APIs or add conditional paths.

- `CONFIG_TQUIC_AF_XDP`
  - Reason: not enabled; dependency validation and API wiring required.
  - Needed: confirm AF_XDP deps, add Kconfig guards, and implement 6.12 bindings.

- `CONFIG_TQUIC_OFFLOAD`
  - Reason: not enabled; dependency validation and API wiring required.
  - Needed: confirm HW offload API compatibility with Debian 6.12.

- `CONFIG_TQUIC_OVER_TCP`
  - Reason: not enabled.
  - Needed: verify dependencies and transport wiring on Debian 6.12.

## Build Compatibility

The Makefile includes the following compatibility flags:

```makefile
# Timer API compatibility
ccflags-y += -Ddel_timer_sync=timer_delete_sync

# Suppress development warnings
ccflags-y += -Wno-error=unused-function -Wno-error=unused-variable
ccflags-y += -Wno-error=missing-prototypes
```

## Notes

- Out-of-tree stubs were removed on `main` per project direction.
- Core TQUIC and WAN bonding are enabled and load successfully as modules.
- TQUIC uses UDP encapsulation per RFC 9000, not raw IP protocol handlers.
