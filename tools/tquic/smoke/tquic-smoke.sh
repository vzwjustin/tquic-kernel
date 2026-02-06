#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-only
set -euo pipefail

proto=253 # IPPROTO_TQUIC

if [[ "${EUID}" -ne 0 ]]; then
  echo "error: run as root (needed for modprobe + reading kernel logs)" >&2
  exit 1
fi

echo "[1/4] Loading module"
if ! modprobe -q tquic; then
  echo "error: modprobe tquic failed. Check dmesg for details." >&2
  exit 1
fi

echo "[2/4] Verifying sysctls"
if [[ ! -d /proc/sys/net/tquic ]]; then
  echo "error: /proc/sys/net/tquic missing (module didn't init sysctls?)" >&2
  exit 1
fi
ls /proc/sys/net/tquic >/dev/null

echo "[3/4] Creating sockets (IPv4 + IPv6)"
if [[ "${TQUIC_SMOKE_NO_SOCKET:-0}" = "1" ]]; then
  echo "skipped (set TQUIC_SMOKE_NO_SOCKET=0 to enable)"
else
python3 - <<PY
import socket
proto = ${proto}
for fam, name in [(socket.AF_INET, "AF_INET"), (socket.AF_INET6, "AF_INET6")]:
    s = socket.socket(fam, socket.SOCK_DGRAM, proto)
    s.close()
    print(f"{name} SOCK_DGRAM proto {proto} OK")
PY
fi

echo "[4/4] Recent kernel log lines"
if command -v dmesg >/dev/null 2>&1; then
  dmesg | grep -i tquic | tail -n 25 || true
fi

echo "OK"
