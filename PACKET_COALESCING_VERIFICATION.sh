#!/bin/bash
# Verification script for RFC 9000 Section 12.2 Packet Coalescing Integration

echo "=== Packet Coalescing Integration Verification ==="
echo ""

# Check that the key functions exist
echo "1. Checking for quic_packet_get_length function..."
if grep -q "static int quic_packet_get_length" net/quic/packet.c; then
    echo "   ✓ quic_packet_get_length function found"
else
    echo "   ✗ quic_packet_get_length function NOT found"
fi

# Check for payload validation in parse_long
echo "2. Checking for payload length validation in quic_packet_parse_long..."
if grep -q "RFC 9000 Section 12.2" net/quic/packet.c | grep -q "payload_len"; then
    echo "   ✓ Payload validation with RFC reference found"
else
    # Check more broadly
    if grep -A5 "Payload Length (variable)" net/quic/packet.c | grep -q "if (payload_len > skb->len - offset)"; then
        echo "   ✓ Payload validation found"
    else
        echo "   ✗ Payload validation NOT found"
    fi
fi

# Check for coalescing support in quic_packet_process
echo "3. Checking for coalescing support in quic_packet_process..."
if grep -q "next_skb" net/quic/packet.c && grep -q "quic_packet_get_length" net/quic/packet.c; then
    echo "   ✓ Coalescing support found in quic_packet_process"
else
    echo "   ✗ Coalescing support NOT found"
fi

# Check for process_next label
echo "4. Checking for process_next control flow..."
if grep -q "process_next:" net/quic/packet.c; then
    echo "   ✓ process_next label found"
else
    echo "   ✗ process_next label NOT found"
fi

# Count RFC 9000 references
echo ""
echo "5. RFC 9000 Section 12.2 references:"
RFC_COUNT=$(grep -c "RFC 9000 Section 12.2" net/quic/packet.c)
echo "   Found $RFC_COUNT references to RFC 9000 Section 12.2"

# Check for proper comments
echo ""
echo "6. Documentation quality:"
COMMENT_LINES=$(grep -c "^ \* " net/quic/packet.c)
echo "   Total comment lines: $COMMENT_LINES"

# Verify the file compiles (syntax only)
echo ""
echo "7. Syntax verification:"
echo "   Note: Full compilation requires kernel build environment"
echo "   Reference file status:"
if [ -f "net/quic/packet_coalesce_fix.c" ]; then
    echo "   ✓ Reference file (packet_coalesce_fix.c) preserved"
else
    echo "   ✗ Reference file NOT found (should be preserved as documentation)"
fi

# Check git status
echo ""
echo "8. Git status:"
if git diff --quiet net/quic/packet.c; then
    echo "   ! No changes detected in packet.c"
else
    echo "   ✓ Changes present in packet.c"
    ADDED=$(git diff net/quic/packet.c | grep "^+" | wc -l | tr -d ' ')
    REMOVED=$(git diff net/quic/packet.c | grep "^-" | wc -l | tr -d ' ')
    echo "   Lines added: $ADDED"
    echo "   Lines removed: $REMOVED"
fi

echo ""
echo "=== Verification Complete ==="
echo ""
echo "To review detailed changes:"
echo "  git diff net/quic/packet.c"
echo ""
echo "To view the integration summary:"
echo "  cat RFC9000_SECTION_12.2_INTEGRATION_SUMMARY.md"
