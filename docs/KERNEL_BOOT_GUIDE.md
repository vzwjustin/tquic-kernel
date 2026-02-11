# TQUIC Kernel - Boot Guide

## Overview

Building and booting a custom Linux kernel with TQUIC built-in (not as a module).

---

## Build

```bash
cd /path/to/tquic-kernel

# Use provided config or configure manually
cp configs/router_minimal.config .config
make olddefconfig

# Build
make -j$(nproc)
```

### Outputs
1. **vmlinux** - Uncompressed kernel binary
2. **arch/x86/boot/bzImage** - Compressed bootable kernel
3. **System.map** - Kernel symbol table

---

## Installation

```bash
cd /path/to/tquic-kernel

# Install kernel, modules, and update bootloader
sudo make modules_install
sudo make install
sudo update-grub
```

Or manually:
```bash
sudo cp arch/x86/boot/bzImage /boot/vmlinuz-$(make kernelrelease)
sudo cp System.map /boot/System.map-$(make kernelrelease)
sudo cp .config /boot/config-$(make kernelrelease)
sudo update-initramfs -c -k $(make kernelrelease)
sudo update-grub
```

---

## Boot

### Select at GRUB Menu
1. Reboot: `sudo reboot`
2. Select "Advanced options" at GRUB menu
3. Choose the TQUIC kernel entry

### Set as Default
```bash
sudo nano /etc/default/grub
# Set GRUB_DEFAULT to the TQUIC kernel entry
sudo update-grub
sudo reboot
```

---

## Verification

```bash
# Check kernel version
uname -r

# Verify TQUIC is built-in
zcat /proc/config.gz | grep CONFIG_TQUIC
# Expected: CONFIG_TQUIC=y

# Check TQUIC in dmesg
dmesg | grep -i tquic

# Check protocol registration
cat /proc/net/protocols | grep TQUIC

# Verify sysctl interface
ls /proc/sys/net/tquic/
```

---

## Testing TQUIC Sockets

```python
import socket

# TQUIC uses IPPROTO_TQUIC = 253
# Both SOCK_STREAM and SOCK_DGRAM are supported

# IPv4 stream socket
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 253)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind(('0.0.0.0', 44333))
sock.listen(1)
print("QUIC IPv4 socket created and listening!")
sock.close()

# IPv6 datagram socket
sock6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM, 253)
sock6.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock6.bind(('::', 44334))
print("QUIC IPv6 datagram socket created!")
sock6.close()
```

---

## Rollback

If boot fails, select the previous working kernel from the GRUB menu, then:

```bash
sudo rm /boot/vmlinuz-<tquic-version>
sudo rm /boot/initrd.img-<tquic-version>
sudo rm /boot/System.map-<tquic-version>
sudo rm /boot/config-<tquic-version>
sudo update-grub
```

For headless systems, add `console=ttyS0,115200n8` to the kernel command line in GRUB for serial console access.

---

## Troubleshooting

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for common issues.
