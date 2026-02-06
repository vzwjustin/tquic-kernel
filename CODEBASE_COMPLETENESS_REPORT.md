# Codebase Completeness Scan (Stubs/TODOs/Incomplete Work)

Date: 2026-02-06

This repo is a full Linux kernel tree plus TQUIC additions. A naive global scan will always find lots of TODO/FIXME/XXX in upstream code, so this report splits:

- TQUIC-relevant scope: `net/quic/`, `net/tquic/`, `include/uapi/linux/tquic.h`, `include/net/netns/tquic.h`
- Upstream remainder: everything else

## Summary Metrics (ripgrep line matches)

### Whole repo (all directories)

- `TODO`: 2893
- `FIXME`: 2033
- `XXX`: 7494
- `HACK`: 154
- `STUB`: 298
- `#if 0`: 566

These are overwhelmingly in upstream kernel/drivers and are not actionable for TQUIC specifically.

### TQUIC scope

- `TODO`: 0
- `FIXME`: 0
- `HACK`: 0
- `STUB`: 0
- `#if 0`: 0
- `XXX`: 1 (bit-pattern comment, not a placeholder): `net/tquic/tquic_stateless_reset.c:237`
- `TBD`: 2 (IANA placeholder wording, not stub logic): `net/tquic/core/mp_frame.c:23`, `net/tquic/core/mp_frame.h:24`

## High Severity Findings (Build/Repo Wiring)

### 1) README/CLAUDE build path requires CONFIG_IP_QUIC + `make M=net/quic`

Wiring was made consistent with the documented build commands:

- `net/quic/Kconfig`: top-level symbol is `menuconfig IP_QUIC` and the submenu is scoped under `if IP_QUIC`.
- `net/Makefile`: `obj-$(CONFIG_IP_QUIC) += quic/` so `net/quic/` is the in-tree entry point.
- `net/quic/Makefile`: builds `quic.ko` (module object `quic.o`) from the existing implementation under `net/tquic/` (via `net/quic/tquic -> ../tquic` symlink).
- `net/tquic/Kconfig`: fixed an invalid dependency (`depends on TQUIC`) that would break Kconfig parsing; it now depends on `TQUIC_CORE`.
- Netns gating for TQUIC MIB/state follows `CONFIG_IP_QUIC`: `include/net/net_namespace.h`, `include/net/netns/mib.h`.

### 2) Sysctl path mismatch vs README

- `net/tquic/quic_sysctl.c`: log/comment strings now match the README path `/proc/sys/net/tquic/`.

## Medium Severity Findings (Real “Incomplete” Code Paths)

### 3) QUIC loss tracing used non-existent config and trace names

`net/tquic/core/quic_loss.c` referenced a dead config symbol and tracepoint macros that don’t exist.

Status: fixed

- It now includes `net/tquic/diag/trace.h` and uses the real `trace_quic_packet_acked`, `trace_quic_packet_lost`, `trace_quic_rtt_update` events from `include/trace/events/quic.h`.
- Removed the dead `CONFIG_TQUIC_TRACING` conditional and the local “stub macro” block.

### 4) Trace header selection logic was too tied to build mode

Status: fixed

- `net/tquic/diag/trace.h` now prefers real kernel trace events whenever `<trace/events/quic.h>` is available, and only falls back to no-op macros when it is not.

### 5) Deprecated standalone timer implementation

Status: fixed by removal

- Deleted `net/tquic/quic_timer.c` (unreferenced legacy file; it contained invalid trace calls).
- Updated the compatibility comment in `net/tquic/tquic_timer.c`.

## Notes (Not Incomplete)

- “Length placeholder” comments in frame/message encoding are normal patterns where the length is backfilled after the payload is constructed.
- `-EOPNOTSUPP` / `-ENOTSUPP` returns are generally used for “feature not negotiated/enabled in this configuration” (e.g., QAT offload, certain MASQUE/HTTP3 paths), not missing implementations.

## Reproduction Commands

Counts (whole repo):

```bash
for p in 'TODO' 'FIXME' 'XXX' 'HACK' 'STUB' '#if 0'; do
  echo -n "$p "
  rg -n -S "$p" . | wc -l
done
```

Counts (TQUIC scope):

```bash
rg -n -S 'TODO|FIXME|XXX|HACK|STUB|#if 0|TBD' \
  net/quic net/tquic include/uapi/linux/tquic.h include/net/netns/tquic.h
```
