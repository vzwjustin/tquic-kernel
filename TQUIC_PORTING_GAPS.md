# TQUIC Porting Gaps (Debian 6.12 / DietPi)

This document lists what is still not enabled or not yet ported in the current
Debian 6.12-based TQUIC kernel build, and why.

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

## Notes

- Out-of-tree stubs were removed on `main` per project direction.
- Core TQUIC and WAN bonding are enabled and load successfully as modules.
