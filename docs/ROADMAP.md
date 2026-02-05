# Roadmap / Porting Gaps

This extends `TQUIC_PORTING_GAPS.md` with a short roadmap of remaining work
for Debian 6.12 / DietPi builds.

## Short‑Term (Porting)

- **IO_URING**
  - Port `net/tquic/io_uring.c` to 6.12 io_uring API
  - Enable `CONFIG_TQUIC_IO_URING`

- **NAPI**
  - Adapt NAPI usage to 6.12 headers and callbacks
  - Enable `CONFIG_TQUIC_NAPI`

- **AF_XDP**
  - Validate deps, wire XDP fast‑path
  - Enable `CONFIG_TQUIC_AF_XDP`

## Medium‑Term (Quality & UX)

- Add a minimal **userspace CLI** for netlink configuration
- Provide a **sample path manager** and example bonding profiles
- Improve **on‑device diagnostics** (counters, tracepoints)

## Long‑Term (Upstreaming)

- Split patches by subsystem for upstream review
- Align APIs with in‑tree QUIC changes
- Reduce delta against mainline
