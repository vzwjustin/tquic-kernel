# TQUIC Kernel - Quick Start Guide

## Current Status

✅ **Kernel building** - Linux 6.19.0-rc7 with TQUIC built-in
⏳ **Progress**: ~1937+ lines compiled, network stack pending
📍 **Location**: Ubuntu server 192.168.8.133

---

## After Build Completes

### Step 1: Verify Build Success

```bash
ssh root@192.168.8.133
cd /root/tquic-kernel

# Check build artifacts
ls -lh vmlinux                    # Should be ~100MB
ls -lh arch/x86/boot/bzImage      # Should be ~10MB
ls -lh System.map                 # Symbol table

# Check for TQUIC compilation
grep "CC.*tquic" /tmp/kernel_build.log
```

### Step 2: Install Kernel

```bash
# Run the installation script
cd /root
sudo ./install_kernel.sh
```

**What it does:**
- ✅ Copies kernel to `/boot/vmlinuz-6.19.0-rc7-tquic`
- ✅ Copies System.map to `/boot/System.map-6.19.0-rc7-tquic`
- ✅ Installs modules to `/lib/modules/6.19.0-rc7-tquic/`
- ✅ Creates initramfs
- ✅ Updates GRUB bootloader

**Estimated time**: 2-3 minutes

### Step 3: Reboot

```bash
sudo reboot
```

**At GRUB menu:**
1. Press `ESC` or `Shift` during boot to show menu
2. Select **"Advanced options for Ubuntu"**
3. Select **"Ubuntu, with Linux 6.19.0-rc7-tquic"**

### Step 4: Verify TQUIC After Boot

```bash
# Run verification script
cd /root
./verify_tquic.sh
```

**Quick manual checks:**
```bash
# Check kernel version
uname -r
# Expected: 6.19.0-rc7-tquic

# Verify TQUIC is built-in
zcat /proc/config.gz | grep CONFIG_IP_QUIC
# Expected: CONFIG_IP_QUIC=y

# Check QUIC protocol registration
cat /proc/net/protocols | grep QUIC
# Expected: QUIC entry in the list

# Check boot messages
dmesg | grep -i tquic
# Expected: TQUIC initialization messages
```

---

## Troubleshooting

### Build Failed

**Check logs:**
```bash
tail -100 /tmp/kernel_build.log
```

**Look for errors:**
```bash
grep -i "error:" /tmp/kernel_build.log | tail -20
```

### Boot Failed / Kernel Panic

**Recovery:**
1. Reboot and select previous working kernel from GRUB
2. System will boot normally with old kernel
3. Check kernel logs:
```bash
journalctl -k -b -1  # Previous boot
```

### TQUIC Not Working After Boot

**Checks:**
```bash
# 1. Verify you booted the right kernel
uname -r  # Should show "tquic"

# 2. Check config
zcat /proc/config.gz | grep TQUIC

# 3. Check dmesg for errors
dmesg | grep -i tquic | grep -i error
```

---

## Files on Server

### Build Location
```
/root/tquic-kernel/                 # Kernel source
├── vmlinux                         # Uncompressed kernel
├── arch/x86/boot/bzImage          # Bootable kernel
├── System.map                      # Symbol table
└── .config                         # Build configuration
```

### Installation Scripts
```
/root/install_kernel.sh             # Install kernel to /boot
/root/verify_tquic.sh               # Verify after boot
```

### After Installation
```
/boot/vmlinuz-6.19.0-rc7-tquic     # Bootable kernel
/boot/initrd.img-6.19.0-rc7-tquic  # Initial ramdisk
/boot/System.map-6.19.0-rc7-tquic  # Symbols
/boot/config-6.19.0-rc7-tquic      # Config
/lib/modules/6.19.0-rc7-tquic/     # Modules
```

---

## Next Steps After Successful Boot

### 1. Basic Functionality Test
```bash
# Check all protocols
cat /proc/net/protocols

# Look for QUIC-specific files
ls -la /proc/net/quic* 2>/dev/null || echo "No QUIC proc files"

# Check sysctl parameters
sysctl -a | grep -i quic
```

### 2. Application Testing
```bash
# Test with QUIC applications
# (Requires QUIC client/server tools)
```

### 3. Performance Testing
```bash
# Multipath bonding tests
# Throughput measurements
# Latency tests
```

### 4. Make Default Boot Kernel (Optional)
```bash
sudo nano /etc/default/grub

# Add/modify:
GRUB_DEFAULT="Advanced options for Ubuntu>Ubuntu, with Linux 6.19.0-rc7-tquic"

# Update GRUB
sudo update-grub

# Reboot to verify
sudo reboot
```

---

## Important Notes

⚠️ **This is a release candidate kernel (rc7)**
- Expect potential bugs
- Not recommended for production servers
- Good for development and testing

✅ **Rollback is easy**
- Original kernel remains bootable
- Just select it from GRUB menu
- No risk to existing system

📝 **TQUIC is built-in**
- Not a loadable module
- Integrated into kernel binary
- Cannot be unloaded without reboot

---

## Support

### Documentation
- `/Users/justinadams/Downloads/tquic-kernel/BUILD_COMPLETE.md`
- `/Users/justinadams/Downloads/tquic-kernel/KERNEL_BOOT_GUIDE.md`
- `/Users/justinadams/Downloads/tquic-kernel/COMPILATION_SUCCESS.md`

### Quick Reference
```bash
# On server (192.168.8.133)
ssh root@192.168.8.133

# Build directory
cd /root/tquic-kernel

# Check build log
less /tmp/kernel_build.log

# After boot
./verify_tquic.sh
```

---

**Status**: Build in progress, installation scripts ready
**Next**: Wait for build to complete (~10-15 more minutes)
