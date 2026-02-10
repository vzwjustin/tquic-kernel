# TQUIC Kernel Audit (Codex)

Date: 2026-02-10

Scope:
- Repo: `/Users/justinadams/Downloads/tquic-kernel`
- Target host: `root@192.168.8.132` (Ubuntu test server)

## Executive Summary

The test server is **not running a kernel that actually contains the in-tree QUIC/TQUIC implementation**, despite the kernel release string containing `tquic` (`6.19.0-rc8-tquic+`). QUIC is not registered, and attempts to load an out-of-tree `tquic.ko` fail with unresolved symbols. This blocks functional verification and makes any “modules loaded” check misleading: the kernel/userspace state is inconsistent with the repo’s documented boot/verify flow.

Separately, the repo currently contains **two competing build/integration paths** (in-tree `net/quic` producing `quic.o`/`quic.ko` vs an out-of-tree-oriented `net/tquic` producing `tquic.ko`) plus build flags that are likely incorrect for in-tree use (e.g., `-DTQUIC_OUT_OF_TREE` in `net/quic/Makefile`). This increases the probability of building or installing the “wrong thing” and then debugging symptoms rather than causes.

## Host Snapshot (192.168.8.132)

Observed on 2026-02-10:
- `uname -r`: `6.19.0-rc8-tquic+`
- `/proc/net/protocols`: **no `QUIC` entry**
- `lsmod | grep -i -E 'quic|tquic'`: **no modules loaded**
- `dmesg` includes a failed out-of-tree module load:
  - `tquic: loading out-of-tree module taints kernel.`
  - `tquic: Unknown symbol setup_udp_tunnel_sock (err -2)`
  - `tquic: Unknown symbol udp_tunnel_xmit_skb (err -2)`
  - `tquic: Unknown symbol inet_diag_register (err -2)` (and related `inet_diag_*`)
  - `tquic: Unknown symbol curve25519_generate_public (err -2)` (and related `curve25519`)
- The kernel config is **not readable from the running kernel**:
  - `/proc/config.gz` absent (suggests `CONFIG_IKCONFIG_PROC` not enabled)
  - `/boot/config-6.19.0-rc8-tquic+` absent
  - `/boot/config-6.19.0-rc7-tquic` exists
- The installed module tree for the running kernel looks incomplete/non-standard:
  - `/lib/modules/6.19.0-rc8-tquic+/kernel/` contains `drivers/` and `lib/`, but no `net/` subtree.
  - `/lib/modules/6.19.0-rc8-tquic+/extra/tquic.ko` exists (out-of-tree module artifact).
- Repo checkout exists on host:
  - `/root/tquic-kernel` git head: `2d846414` (has `net/quic/` present)
  - `/root/tquic-kernel/.config` indicates `CONFIG_IP_QUIC=y` and many `CONFIG_TQUIC_*` set to `y`.

Interpretation:
- The running kernel image and its boot artifacts do **not** correspond to the `.config` in `/root/tquic-kernel` (or they were built but not installed/booted correctly).
- The system is currently in the failure mode: “custom kernel string + out-of-tree module insertion attempt + missing/incorrect exports => QUIC never registers.”

## Repo-Level Findings

### [P0] Build/Boot/Verify Mismatch (blocks functionality)

The repo documentation (`KERNEL_BOOT_GUIDE.md`, `QUICK_START.md`, `verify_tquic.sh`) assumes:
- A kernel version like `6.19.0-rc7-tquic`
- `CONFIG_IP_QUIC=y` (built-in)
- QUIC registered and visible via `/proc/net/protocols`

On the test server, QUIC is not registered and the kernel config is not inspectable at runtime, so the “verify” path cannot confirm correctness and the kernel is not functionally correct for TQUIC.

### [P1] Hardcoded Versioning in Install Script

`/Users/justinadams/Downloads/tquic-kernel/install_kernel.sh` hardcodes:
- `KERNEL_VERSION="6.19.0-rc7-tquic"`

But the host is booting `6.19.0-rc8-tquic+`. Hardcoding version strings makes it easy to install one kernel and boot another, or to have mismatched `/boot/*` and `/lib/modules/*` trees.

Recommendation:
- Derive the install target from `make -s kernelrelease` in the build tree, and install config/System.map for that exact value.

### [P1] Dual Integration Paths (in-tree `quic` vs out-of-tree `tquic`)

There are effectively two paths:
- In-tree style: `net/quic/Kconfig` defines `CONFIG_IP_QUIC` (tristate), and `net/quic/Makefile` builds `quic.o` from `net/tquic/**.o`.
- Out-of-tree style: `net/tquic/Makefile` builds `tquic.ko` based on `CONFIG_TQUIC` and related options.

This matters because:
- The out-of-tree module path will often fail unless it only uses exported symbols. The server failure (`Unknown symbol ... inet_diag_* / udp_tunnel_* / curve25519*`) is consistent with this.
- Operators will end up loading `tquic.ko` even though the intended integration is `CONFIG_IP_QUIC=y` in-tree.

Recommendation:
- Pick one supported path and make the other explicitly “dev-only” (or remove it).
- Rename/guard `TQUIC_OUT_OF_TREE` so the in-tree build does not define it.

### [P2] In-Tree Build Flag Looks Wrong

`/Users/justinadams/Downloads/tquic-kernel/net/quic/Makefile` adds:
- `-DTQUIC_OUT_OF_TREE`

If the same source is used for both in-tree and out-of-tree builds, this macro should be set only for the out-of-tree build. Defining it in the in-tree build path risks:
- Building code that expects module-style constraints (exports, init ordering, etc.)
- Accidentally taking compatibility branches that are inappropriate in-tree

### [P2] Warning Suppression in Build Flags

Both `net/quic/Makefile` and `net/tquic/Makefile` contain multiple `-Wno-error=...` suppressions.

In kernel work, warnings often correspond to real correctness issues (missing prototypes, unused static functions that indicate dead code, etc.). Suppressing them broadly makes regressions more likely.

Recommendation:
- Make warning suppression opt-in (e.g., behind a dev config), not the default.

### [P2] Socket Option Parsing: Global `int` Read Forces `optlen >= 4`

In `tquic_sock_setsockopt()` (`net/tquic/tquic_socket.c`), `optlen < sizeof(int)` is rejected and an `int val` is always read from `optval` before `switch (optname)`.

For string/binary options (e.g. `TQUIC_PSK_IDENTITY`, scheduler names), this:
- Forces a minimum option length of 4 bytes even when smaller is valid.
- Performs an unnecessary userspace read for every setsockopt call.

This is not a direct security bug, but it is an API correctness footgun and increases fragility of the userspace interface.

### [P2] Netlink Permissions Are Correctly Restricted

`net/tquic/tquic_netlink.c` uses:
- `GENL_ADMIN_PERM` on all genl ops
- multicast group flags `GENL_MCAST_CAP_NET_ADMIN`
- `TQUIC_NL_ATTR_SCHED_NAME` policy uses `NLA_NUL_STRING`

This is good baseline hardening for a privileged configuration plane.

## Risk Notes (Security/Correctness)

- Any workflow that depends on loading an out-of-tree `tquic.ko` is high-risk because it implicitly depends on kernel-private symbols being exported. The observed “Unknown symbol …” failures are typical of that approach.
- Disabling certificate verification is supported by socket options and is called out as insecure. Ensure default remains “required” and that docs/UX make unsafe modes hard to enable accidentally.
- Given the size/complexity of the protocol implementation (multipath, netlink, BPF/XDP, crypto), a true “security-grade” audit also needs concurrency review (locking/RCU), bounds review on all packet parsing paths, and fuzzing/integration tests. This report is focused on the immediate integration blockers + the highest-leverage interface concerns spotted quickly.

## Immediate Recommendations (to reach a verifiable “correct kernel” state)

1. Make the running kernel self-describing:
   - Enable `CONFIG_IKCONFIG=y` and `CONFIG_IKCONFIG_PROC=y` so `/proc/config.gz` exists.
2. Remove version hardcoding from install scripts:
   - Use `make -s kernelrelease` to compute install targets.
3. Ensure QUIC registers at boot:
   - After booting the intended kernel, `/proc/net/protocols` should contain `QUIC`.
4. Avoid out-of-tree module loading for core QUIC path:
   - Prefer `CONFIG_IP_QUIC=y` in-tree integration.
5. Align docs/scripts with reality:
   - Decide whether the project target is `6.19.0-rc7-tquic` or `6.19.0-rc8-tquic+` and update docs accordingly.

## For Merging With Claude’s Report

When you paste Claude’s audit, I’ll merge by:
- Deduplicating findings
- Reconciling any disagreements with evidence and clarifying which kernel/version/date each claim refers to
- Producing a single combined list of findings by severity (P0..P3) plus a single action plan

