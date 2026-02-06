# Quick Start (DietPi, Debian 6.12 Kernel)

This guide covers a minimal, working path to build and load TQUIC on a DietPi
system running the Debian 6.12.x kernel.

## Prereqs

- DietPi system with root access
- Kernel source in `/usr/src/linux-6.12.63` (or similar)
- Toolchain and build deps installed (build-essential, bc, flex, bison, libssl-dev, libelf-dev, etc.)
- TQUIC source synced into the kernel tree

## Build + Install

From the DietPi box:

```bash
cd /usr/src/linux-6.12.63

# Configure (example: reuse existing config)
make olddefconfig

# Build kernel + modules
make -j"$(nproc)" bzImage modules

# Install modules + kernel
make modules_install
make install

# Update bootloader
update-grub
```

Reboot:

```bash
reboot
```

## Load Module

```bash
modprobe tquic
lsmod | grep -i tquic
```

Expected dmesg line (example):

```bash
dmesg | grep -i tquic | head -n 5
```

## Enable Auto‑Load on Boot

```bash
echo tquic > /etc/modules-load.d/tquic.conf
```

## Sanity Checks

```bash
# Sysctl presence
ls /proc/sys/net/tquic | head -n 10

# Socket smoke test
python3 - <<'PY'
import socket
for fam,name in [(socket.AF_INET,"AF_INET"),(socket.AF_INET6,"AF_INET6")]:
    s = socket.socket(fam, socket.SOCK_DGRAM, 253)  # IPPROTO_TQUIC
    print(f"{name} SOCK_DGRAM proto 253 OK")
    s.close()
PY
```

If the module loads and sysctls are present, the core TQUIC stack is working.

Alternatively, run the bundled smoke script from this repo (as root):

```bash
tools/tquic/smoke/tquic-smoke.sh
```
