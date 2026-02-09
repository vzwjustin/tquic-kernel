#!/bin/bash
#
# TQUIC Kernel Installation Script
# Installs Linux 6.19.0-rc7 with TQUIC built-in
#

set -e  # Exit on error

KERNEL_VERSION="6.19.0-rc7-tquic"
KERNEL_DIR="/root/tquic-kernel"

echo "======================================="
echo "TQUIC Kernel Installation"
echo "Version: $KERNEL_VERSION"
echo "======================================="
echo ""

# Check if build completed
if [ ! -f "$KERNEL_DIR/vmlinux" ]; then
    echo "ERROR: vmlinux not found. Build may not be complete."
    echo "Expected: $KERNEL_DIR/vmlinux"
    exit 1
fi

if [ ! -f "$KERNEL_DIR/arch/x86/boot/bzImage" ]; then
    echo "ERROR: bzImage not found. Build may not be complete."
    echo "Expected: $KERNEL_DIR/arch/x86/boot/bzImage"
    exit 1
fi

echo "✓ Build verification passed"
echo ""

# Show build artifacts
echo "Build artifacts:"
ls -lh "$KERNEL_DIR/vmlinux"
ls -lh "$KERNEL_DIR/arch/x86/boot/bzImage"
echo ""

# Backup existing files (if they exist)
if [ -f "/boot/vmlinuz-$KERNEL_VERSION" ]; then
    echo "Backing up existing kernel..."
    sudo cp "/boot/vmlinuz-$KERNEL_VERSION" "/boot/vmlinuz-$KERNEL_VERSION.backup"
fi

# Install kernel image
echo "Installing kernel image..."
sudo cp "$KERNEL_DIR/arch/x86/boot/bzImage" "/boot/vmlinuz-$KERNEL_VERSION"
echo "✓ Installed /boot/vmlinuz-$KERNEL_VERSION"

# Install System.map
echo "Installing System.map..."
sudo cp "$KERNEL_DIR/System.map" "/boot/System.map-$KERNEL_VERSION"
echo "✓ Installed /boot/System.map-$KERNEL_VERSION"

# Install kernel config
echo "Installing kernel config..."
sudo cp "$KERNEL_DIR/.config" "/boot/config-$KERNEL_VERSION"
echo "✓ Installed /boot/config-$KERNEL_VERSION"

# Install modules (optional - most are built-in)
echo ""
echo "Installing kernel modules..."
cd "$KERNEL_DIR"
sudo make modules_install INSTALL_MOD_PATH=/ > /tmp/modules_install.log 2>&1
echo "✓ Modules installed to /lib/modules/$KERNEL_VERSION"

# Create initramfs
echo ""
echo "Creating initramfs..."
if command -v update-initramfs &> /dev/null; then
    # Ubuntu/Debian
    sudo update-initramfs -c -k "$KERNEL_VERSION"
    echo "✓ Created initramfs using update-initramfs"
elif command -v mkinitramfs &> /dev/null; then
    # Alternative method
    sudo mkinitramfs -o "/boot/initrd.img-$KERNEL_VERSION" "$KERNEL_VERSION"
    echo "✓ Created initramfs using mkinitramfs"
else
    echo "WARNING: Could not find initramfs tool"
    echo "You may need to create initramfs manually"
fi

# Update bootloader
echo ""
echo "Updating GRUB bootloader..."
if command -v update-grub &> /dev/null; then
    sudo update-grub
    echo "✓ GRUB updated"
elif command -v grub-mkconfig &> /dev/null; then
    sudo grub-mkconfig -o /boot/grub/grub.cfg
    echo "✓ GRUB configuration regenerated"
else
    echo "WARNING: Could not update GRUB"
    echo "You may need to update bootloader manually"
fi

# Verify installation
echo ""
echo "======================================="
echo "Installation Summary"
echo "======================================="
echo ""
echo "Installed files:"
ls -lh /boot/vmlinuz-$KERNEL_VERSION
ls -lh /boot/System.map-$KERNEL_VERSION
ls -lh /boot/config-$KERNEL_VERSION
ls -lh /boot/initrd.img-$KERNEL_VERSION 2>/dev/null || echo "initrd.img-$KERNEL_VERSION: Not found (may need manual creation)"
echo ""

# Check GRUB entries
echo "GRUB menu entries:"
grep "menuentry" /boot/grub/grub.cfg | grep "$KERNEL_VERSION" | head -3
echo ""

# Final verification
echo "======================================="
echo "Installation Complete!"
echo "======================================="
echo ""
echo "Next steps:"
echo "1. Review the GRUB entries above"
echo "2. Reboot your system: sudo reboot"
echo "3. At GRUB menu, select:"
echo "   'Advanced options for Ubuntu' → 'Ubuntu, with Linux $KERNEL_VERSION'"
echo "4. After boot, verify with: uname -r"
echo "5. Check TQUIC: cat /proc/net/protocols | grep QUIC"
echo ""
echo "To set as default boot kernel:"
echo "  sudo nano /etc/default/grub"
echo "  Set: GRUB_DEFAULT=\"Advanced options for Ubuntu>Ubuntu, with Linux $KERNEL_VERSION\""
echo "  sudo update-grub"
echo ""
