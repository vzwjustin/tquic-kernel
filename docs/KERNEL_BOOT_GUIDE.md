# TQUIC Kernel - Boot Guide

## Overview

Building and booting a custom Linux kernel 6.19.0-rc7 with TQUIC built-in (not as modules).

---

## Build Status

### Configuration
- **TQUIC Mode**: Built-in (=y) - integrated into kernel binary
- **IPv6 Support**: Enabled
- **Kernel Version**: 6.19.0-rc7-tquic
- **Build Parallelization**: 4 cores

### Build Command
```bash
cd /root/tquic-kernel
make -j4
```

### Expected Outputs
1. **vmlinux** - Uncompressed kernel binary (~100MB)
2. **arch/x86/boot/bzImage** - Compressed bootable kernel (~10MB)
3. **System.map** - Kernel symbol table
4. **modules/** - Loadable kernel modules (optional extras)

---

## Installation Steps

### 1. Install Kernel Image
```bash
cd /root/tquic-kernel

# Copy kernel image
sudo cp arch/x86/boot/bzImage /boot/vmlinuz-6.19.0-rc7-tquic

# Copy System.map
sudo cp System.map /boot/System.map-6.19.0-rc7-tquic

# Copy kernel config
sudo cp .config /boot/config-6.19.0-rc7-tquic
```

### 2. Create initramfs
```bash
# Generate initial ramdisk
sudo update-initramfs -c -k 6.19.0-rc7-tquic

# Or using mkinitramfs
sudo mkinitramfs -o /boot/initrd.img-6.19.0-rc7-tquic 6.19.0-rc7-tquic
```

### 3. Update Bootloader (GRUB)
```bash
# Update GRUB configuration
sudo update-grub

# Or manually
sudo grub-mkconfig -o /boot/grub/grub.cfg
```

### 4. Verify GRUB Entry
```bash
# Check GRUB menu entries
grep "menuentry" /boot/grub/grub.cfg | grep 6.19.0-rc7-tquic
```

Expected output:
```
menuentry 'Ubuntu, with Linux 6.19.0-rc7-tquic' ...
```

---

## Boot Process

### Option 1: Reboot and Select Kernel
```bash
sudo reboot
```

At GRUB menu:
1. Select "Advanced options for Ubuntu"
2. Select "Ubuntu, with Linux 6.19.0-rc7-tquic"

### Option 2: Set as Default
```bash
# Edit GRUB default
sudo nano /etc/default/grub

# Set:
GRUB_DEFAULT="Advanced options for Ubuntu>Ubuntu, with Linux 6.19.0-rc7-tquic"

# Update GRUB
sudo update-grub

# Reboot
sudo reboot
```

---

## Verification After Boot

### 1. Check Kernel Version
```bash
uname -a
# Expected: Linux 6.19.0-rc7-tquic

uname -r
# Expected: 6.19.0-rc7-tquic
```

### 2. Verify TQUIC is Built-in
```bash
# Check if QUIC protocol is registered
cat /proc/net/protocols | grep QUIC

# Check kernel config
zcat /proc/config.gz | grep CONFIG_IP_QUIC
# Expected: CONFIG_IP_QUIC=y (not =m)

# Or from boot
cat /boot/config-$(uname -r) | grep CONFIG_IP_QUIC
```

### 3. Check TQUIC in dmesg
```bash
dmesg | grep -i tquic
dmesg | grep -i quic
```

Expected output (examples):
```
[    0.123456] TQUIC: Initializing QUIC protocol
[    0.123457] TQUIC: IPv6 support enabled
[    0.123458] TQUIC: Registered QUIC protocol family
```

### 4. Check Network Protocols
```bash
# List all protocols
cat /proc/net/protocols

# Should include QUIC entry
```

### 5. Verify Socket Support
```bash
# Check if QUIC sockets can be created
# (requires QUIC application)
```

---

## Rollback Plan

### If Boot Fails

1. **Use GRUB Recovery**:
   - At GRUB menu, select previous working kernel
   - System will boot with old kernel

2. **Remove Bad Kernel**:
```bash
# After booting old kernel
sudo rm /boot/vmlinuz-6.19.0-rc7-tquic
sudo rm /boot/initrd.img-6.19.0-rc7-tquic
sudo rm /boot/System.map-6.19.0-rc7-tquic
sudo rm /boot/config-6.19.0-rc7-tquic

# Update GRUB
sudo update-grub
```

3. **Serial Console Access** (if no display):
```bash
# Add to kernel command line in GRUB:
console=ttyS0,115200n8

# Connect via serial:
screen /dev/ttyS0 115200
```

---

## Troubleshooting

### Issue: Kernel Panic on Boot

**Check**:
1. initramfs created correctly
2. Correct root filesystem UUID
3. Required drivers built-in (not as modules)

**Solution**:
```bash
# Rebuild initramfs
sudo update-initramfs -u -k 6.19.0-rc7-tquic
```

### Issue: Missing Network Interface

**Check**:
```bash
# Ensure network drivers are built-in
cat /boot/config-6.19.0-rc7-tquic | grep -i "CONFIG_E1000\|CONFIG_RTL8169"
```

**Solution**: Rebuild kernel with network drivers as built-in (=y)

### Issue: TQUIC Not Available

**Check**:
```bash
cat /proc/config.gz | grep CONFIG_IP_QUIC
cat /boot/config-$(uname -r) | grep CONFIG_IP_QUIC
```

**Expected**: `CONFIG_IP_QUIC=y`

**If =m**: TQUIC was built as module, need to rebuild

---

## Performance Tuning

### After Successful Boot

```bash
# Set congestion control algorithm
sudo sysctl -w net.ipv4.tcp_congestion_control=bbr

# Enable TQUIC-specific settings
# (application-dependent)
```

---

## Testing TQUIC

### Create QUIC Socket (Python example)
```python
import socket

# TQUIC uses SOCK_STREAM with protocol number 262
try:
    # IPv4
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 262)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', 44333))
    sock.listen(1)
    print("QUIC IPv4 socket created and listening!")
    sock.close()

    # IPv6
    sock6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM, 262)
    sock6.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock6.bind(('::', 44334))
    sock6.listen(1)
    print("QUIC IPv6 socket created and listening!")
    sock6.close()
except Exception as e:
    print(f"Error: {e}")
```

### Check QUIC Protocol Number
```bash
# TQUIC uses SOCK_STREAM with protocol 262
cat /proc/net/protocols | grep TQUIC
```

---

## Complete Installation Script

```bash
#!/bin/bash
set -e

cd /root/tquic-kernel

# Install kernel
sudo cp arch/x86/boot/bzImage /boot/vmlinuz-6.19.0-rc7-tquic
sudo cp System.map /boot/System.map-6.19.0-rc7-tquic
sudo cp .config /boot/config-6.19.0-rc7-tquic

# Create initramfs
sudo update-initramfs -c -k 6.19.0-rc7-tquic

# Install modules (optional extras not built-in)
sudo make modules_install

# Update bootloader
sudo update-grub

echo "Kernel installed successfully!"
echo "Reboot and select: Ubuntu, with Linux 6.19.0-rc7-tquic"
```

---

## Quick Commands Reference

```bash
# Check build completion
ls -lh /root/tquic-kernel/vmlinux
ls -lh /root/tquic-kernel/arch/x86/boot/bzImage

# Install
cd /root/tquic-kernel && sudo make install

# After boot
uname -r                          # Check kernel version
cat /proc/net/protocols | grep QUIC  # Verify TQUIC
dmesg | grep -i tquic             # Check boot messages

# Rollback
sudo update-grub                  # Select old kernel
```

---

## Build Time Estimates

- **Small build (modules only)**: 5-10 minutes
- **Full kernel build**: 15-30 minutes (4 cores)
- **Full kernel + modules**: 20-40 minutes

Actual time depends on:
- CPU cores (4 in this system)
- Disk I/O speed
- Enabled kernel features

---

## Next Steps After Successful Boot

1. **Test QUIC Functionality**:
   - Use QUIC client/server applications
   - Test multipath bonding
   - Verify IPv6 support

2. **Performance Testing**:
   - iperf3 with QUIC
   - Latency measurements
   - Throughput tests

3. **Monitoring**:
   - Watch `/proc/net/protocols`
   - Monitor `dmesg` for errors
   - Check `/sys/kernel/debug/quic/` (if debugfs enabled)

---

## Important Notes

1. **Backup**: Current kernel remains bootable - can always rollback
2. **rc7**: This is a release candidate - expect potential bugs
3. **TQUIC**: Experimental WAN bonding feature - test thoroughly
4. **Support**: May not have long-term maintenance - kernel.org for updates

---

## Status

- ✅ Kernel configured (TQUIC=y)
- 🔄 Kernel building (in progress)
- ⏳ Installation (pending build completion)
- ⏳ Boot test (pending installation)

**Current step**: Waiting for kernel build to complete (~15-30 min)
