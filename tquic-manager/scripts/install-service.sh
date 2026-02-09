#!/bin/bash

# TQUIC Manager - Systemd Service Installer

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SERVICE_FILE="$SCRIPT_DIR/tquic-manager.service"
SYSTEMD_DIR="/etc/systemd/system"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ This script must be run as root"
    echo "   Usage: sudo $0"
    exit 1
fi

echo "📦 Installing TQUIC Manager as systemd service..."

# Copy project to /opt
echo "   Copying files to /opt/tquic-manager..."
cp -r "$(dirname "$SCRIPT_DIR")" /opt/tquic-manager

# Install Python dependencies
echo "   Installing Python dependencies..."
cd /opt/tquic-manager/backend
pip3 install -r requirements.txt --quiet

# Copy service file
echo "   Installing systemd service..."
cp "$SERVICE_FILE" "$SYSTEMD_DIR/tquic-manager.service"

# Reload systemd
systemctl daemon-reload

echo ""
echo "✅ TQUIC Manager service installed!"
echo ""
echo "   Start:   sudo systemctl start tquic-manager"
echo "   Stop:    sudo systemctl stop tquic-manager"
echo "   Status:  sudo systemctl status tquic-manager"
echo "   Enable:  sudo systemctl enable tquic-manager (auto-start on boot)"
echo ""
