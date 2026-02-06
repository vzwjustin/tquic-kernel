# TQUIC Smoke Test

This is a minimal sanity check for a Linux system with the TQUIC kernel module
installed.

## Run

As root:

```bash
tools/tquic/smoke/tquic-smoke.sh
```

If socket creation is suspected to crash/hang the kernel, you can run a partial
check that skips the socket probe:

```bash
TQUIC_SMOKE_NO_SOCKET=1 tools/tquic/smoke/tquic-smoke.sh
```

## What It Checks

- `modprobe tquic` succeeds
- `/proc/sys/net/tquic` exists
- A `SOCK_DGRAM` socket can be created with `IPPROTO_TQUIC` (253) on IPv4/IPv6
- Prints recent `dmesg` lines containing "tquic"

## If It Fails

See `docs/TROUBLESHOOTING.md`.
