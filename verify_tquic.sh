#!/bin/bash
#
# TQUIC Kernel Verification Script
# Verify TQUIC is built-in and functional after boot
#

echo "======================================="
echo "TQUIC Kernel Verification"
echo "======================================="
echo ""

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

pass() {
    echo -e "${GREEN}✓${NC} $1"
}

fail() {
    echo -e "${RED}✗${NC} $1"
}

warn() {
    echo -e "${YELLOW}⚠${NC} $1"
}

# Test 1: Kernel version
echo "Test 1: Kernel Version"
KERNEL=$(uname -r)
echo "  Current kernel: $KERNEL"
if [[ "$KERNEL" == *"tquic"* ]]; then
    pass "TQUIC kernel detected"
else
    warn "Kernel name doesn't contain 'tquic' - may be wrong kernel"
fi
echo ""

# Test 2: Kernel version details
echo "Test 2: Kernel Details"
uname -a
echo ""

# Test 3: TQUIC config check
echo "Test 3: TQUIC Configuration"
if [ -f /proc/config.gz ]; then
    CONFIG=$(zcat /proc/config.gz | grep "CONFIG_IP_QUIC=")
    echo "  $CONFIG"
    if [[ "$CONFIG" == "CONFIG_IP_QUIC=y" ]]; then
        pass "TQUIC is built-in (=y)"
    elif [[ "$CONFIG" == "CONFIG_IP_QUIC=m" ]]; then
        warn "TQUIC is modular (=m), not built-in"
    else
        fail "TQUIC not found in kernel config"
    fi
elif [ -f "/boot/config-$(uname -r)" ]; then
    CONFIG=$(grep "CONFIG_IP_QUIC=" "/boot/config-$(uname -r)")
    echo "  $CONFIG"
    if [[ "$CONFIG" == "CONFIG_IP_QUIC=y" ]]; then
        pass "TQUIC is built-in (=y)"
    else
        warn "TQUIC config: $CONFIG"
    fi
else
    warn "Cannot find kernel config"
fi
echo ""

# Test 4: IPv6 support
echo "Test 4: TQUIC IPv6 Support"
if [ -f /proc/config.gz ]; then
    IPV6_CONFIG=$(zcat /proc/config.gz | grep "CONFIG_TQUIC_IPV6=")
    echo "  $IPV6_CONFIG"
    if [[ "$IPV6_CONFIG" == "CONFIG_TQUIC_IPV6=y" ]]; then
        pass "TQUIC IPv6 support enabled"
    else
        warn "TQUIC IPv6: $IPV6_CONFIG"
    fi
fi
echo ""

# Test 5: QUIC protocol registration
echo "Test 5: QUIC Protocol Registration"
if [ -f /proc/net/protocols ]; then
    QUIC_PROTO=$(cat /proc/net/protocols | grep -i QUIC)
    if [ -n "$QUIC_PROTO" ]; then
        pass "QUIC protocol registered"
        echo "  $QUIC_PROTO"
    else
        fail "QUIC protocol NOT registered in /proc/net/protocols"
    fi
else
    warn "/proc/net/protocols not found"
fi
echo ""

# Test 6: Kernel boot messages
echo "Test 6: TQUIC Boot Messages"
DMESG_TQUIC=$(dmesg | grep -i tquic | head -10)
if [ -n "$DMESG_TQUIC" ]; then
    pass "TQUIC messages found in dmesg"
    echo "$DMESG_TQUIC" | sed 's/^/  /'
else
    DMESG_QUIC=$(dmesg | grep -i quic | head -10)
    if [ -n "$DMESG_QUIC" ]; then
        pass "QUIC messages found in dmesg"
        echo "$DMESG_QUIC" | sed 's/^/  /'
    else
        warn "No TQUIC/QUIC messages in dmesg"
    fi
fi
echo ""

# Test 7: Loaded modules (should be minimal since built-in)
echo "Test 7: TQUIC Modules (should be minimal)"
TQUIC_MODULES=$(lsmod | grep -i tquic || echo "None")
if [[ "$TQUIC_MODULES" == "None" ]]; then
    pass "No TQUIC modules loaded (expected for built-in)"
else
    warn "TQUIC modules found (unexpected for built-in):"
    echo "$TQUIC_MODULES" | sed 's/^/  /'
fi
echo ""

# Test 8: Network interfaces
echo "Test 8: Network Interfaces"
ip link show | grep -E "^[0-9]+:" | sed 's/^/  /'
echo ""

# Test 9: Sysctl QUIC parameters (if any)
echo "Test 9: QUIC sysctl Parameters"
QUIC_SYSCTL=$(sysctl -a 2>/dev/null | grep -i quic | head -10 || echo "None found")
if [[ "$QUIC_SYSCTL" != "None found" ]]; then
    pass "QUIC sysctl parameters found"
    echo "$QUIC_SYSCTL" | sed 's/^/  /'
else
    warn "No QUIC sysctl parameters found"
fi
echo ""

# Test 10: Check for /sys/kernel/debug/quic (if debugfs mounted)
echo "Test 10: QUIC Debug Interface"
if [ -d /sys/kernel/debug/quic ]; then
    pass "QUIC debug interface available"
    ls -la /sys/kernel/debug/quic/ | sed 's/^/  /'
elif [ -d /sys/kernel/debug ]; then
    warn "Debugfs mounted but no /quic directory"
else
    warn "Debugfs not mounted (mount -t debugfs none /sys/kernel/debug)"
fi
echo ""

# Summary
echo "======================================="
echo "Verification Summary"
echo "======================================="
echo ""
echo "Kernel: $(uname -r)"
echo "TQUIC Status: Check results above"
echo ""
echo "Quick Tests:"
echo "  1. Check protocol: cat /proc/net/protocols | grep QUIC"
echo "  2. Check config: zcat /proc/config.gz | grep TQUIC"
echo "  3. Check messages: dmesg | grep -i tquic"
echo ""
echo "To test QUIC functionality:"
echo "  - Use QUIC client/server applications"
echo "  - Check multipath bonding features"
echo "  - Monitor /proc/net/quic/* (if available)"
echo ""
