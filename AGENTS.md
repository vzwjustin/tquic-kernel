# Agent Instructions (tquic-kernel)

This repository is a Linux kernel source tree with the experimental **TQUIC**
(kernel QUIC + WAN bonding / multipath) implementation.

These instructions are for AI/code agents making changes in this repo.

## Scope: Where To Work

Prefer changes in these areas:

- `/Users/justinadams/Downloads/tquic-kernel/net/tquic/` (main TQUIC module and subsystems)
- `/Users/justinadams/Downloads/tquic-kernel/net/quic/` (integration glue; note `net/quic/tquic` is a symlink)
- `/Users/justinadams/Downloads/tquic-kernel/include/net/tquic.h` and other TQUIC-specific headers
- `/Users/justinadams/Downloads/tquic-kernel/docs/` (project documentation)

Avoid modifying upstream kernel code outside TQUIC unless it is truly required.
If you must touch upstream areas, keep the diff minimal and justify why.

## Non-Negotiables

- **No stubs**: do not add placeholder implementations, TODO-only functions, or
  "return success" skeletons. Implement behavior fully or do not change it.
- **Treat network input as hostile**: all packet/user inputs require strict
  bounds checks, overflow-safe arithmetic, and clear error handling.
- **Memory safety**: check all allocations; free on all error paths; maintain
  correct refcounts; avoid UAF/double-free; zeroize key material where needed.
- **Concurrency correctness**: lock ordering, RCU rules, and atomicity matter.
  Do not introduce data races to "make it work".
- **Do not add or log secrets**: never commit credentials, IPs/hostnames tied
  to a private environment, private keys, tokens, or full `dmesg` dumps that may
  contain sensitive data. Redact before sharing.

## Coding Style (Kernel Rules)

- Follow Linux kernel coding style: tabs, K&R braces, keep lines ~80 columns.
- Prefer kernel helpers/APIs (`kmalloc`, `kfree`, `copy_*_user`, `READ_ONCE`, etc.).
- Run checkpatch on touched C/H files:

```bash
scripts/checkpatch.pl --no-tree --strict -f path/to/file.c
```

## Build: Fast Feedback Loops

This tree builds TQUIC as a kernel module (and optionally additional modules).

Typical module-only builds:

```bash
# Build the consolidated module
make M=net/tquic

# Include extra warnings
make M=net/tquic W=1

# Sparse/static checks (slower)
make M=net/tquic C=1
```

Configuration notes:

- TQUIC is gated by `CONFIG_IP_QUIC` and `CONFIG_TQUIC` (see `net/tquic/Kconfig`).

## Runtime Smoke Tests (On a Linux Test System)

After installing/booting a kernel that includes these changes:

```bash
modprobe tquic
lsmod | grep -i tquic
dmesg | grep -i tquic | head
```

Sysctl presence:

```bash
ls /proc/sys/net/tquic | head
```

Basic socket creation (example uses protocol 263 as configured by this tree):

```bash
python3 - <<'PY'
import socket
proto = 263  # See include/uapi/linux/in.h (IPPROTO_TQUIC)
for fam,name in [(socket.AF_INET,"AF_INET"), (socket.AF_INET6,"AF_INET6")]:
    s = socket.socket(fam, socket.SOCK_DGRAM, proto)
    print(f"{name} SOCK_DGRAM proto {proto} OK")
    s.close()
PY
```

If you cannot test on bare metal, use a VM/QEMU-based workflow. Do not require
root login over the network for basic validation; prefer console access or
key-based auth in a controlled test lab.

## Change Hygiene

- Keep diffs focused; avoid drive-by refactors in unrelated kernel subsystems.
- Add or update tests/docs when behavior changes (KUnit/kselftest where applicable).
- When changing protocol behavior, cite the RFC section in the commit message or
  code comment (short reference, no long quotes).
