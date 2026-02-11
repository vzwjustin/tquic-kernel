#!/bin/bash

# TQUIC Manager Startup Script

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BACKEND_DIR="$PROJECT_DIR/backend"
FRONTEND_DIR="$PROJECT_DIR/frontend"
RUNTIME_DIR="/run/tquic-manager"
if ! install -d -m 700 "$RUNTIME_DIR" 2>/dev/null; then
    RUNTIME_DIR="/tmp/tquic-manager-$UID"
    install -d -m 700 "$RUNTIME_DIR" || {
        echo "❌ Failed to create runtime directory: $RUNTIME_DIR"
        exit 1
    }
fi
PID_FILE="$RUNTIME_DIR/tquic-manager.pid"
LOG_FILE="$RUNTIME_DIR/tquic-manager.log"

echo "🚀 Starting TQUIC Manager..."

# Check if already running
if [ -f "$PID_FILE" ]; then
    PID=$(cat "$PID_FILE")
    if ! [[ "$PID" =~ ^[0-9]+$ ]]; then
        echo "⚠️  Invalid PID file content, removing stale PID file"
        rm -f "$PID_FILE"
    elif ps -p $PID > /dev/null 2>&1; then
        echo "⚠️  TQUIC Manager is already running (PID: $PID)"
        echo "   Access at: http://$(hostname -I | awk '{print $1}'):5000"
        exit 1
    else
        rm -f "$PID_FILE"
    fi
fi

# Reject symlink PID file to avoid clobbering arbitrary paths
if [ -L "$PID_FILE" ]; then
    echo "❌ Refusing to use symlinked PID file: $PID_FILE"
    exit 1
fi

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is not installed"
    exit 1
fi

# Check/Install dependencies
echo "📦 Checking dependencies..."
cd "$BACKEND_DIR"

if ! python3 -c "import flask" 2>/dev/null; then
    echo "Installing Flask..."
    pip3 install -r requirements.txt --quiet
fi

# Check for root privileges
if [ "$EUID" -ne 0 ]; then
    echo "⚠️  WARNING: Not running as root. sysctl modifications may fail."
    echo "   Consider running: sudo $0"
    echo ""
fi

# Start Flask server
echo "🔧 Starting Flask backend..."
cd "$BACKEND_DIR"

# Start in background and save PID
nohup python3 -u app.py > "$LOG_FILE" 2>&1 &
BACKEND_PID=$!

# Save PID
umask 077
echo $BACKEND_PID > "$PID_FILE"

# Wait a moment for server to start
sleep 2

# Check if still running
if ! ps -p $BACKEND_PID > /dev/null 2>&1; then
    echo "❌ Failed to start backend. Check logs:"
    echo "   tail -f $LOG_FILE"
    rm -f "$PID_FILE"
    exit 1
fi

# Get IP address
IP=$(hostname -I | awk '{print $1}')
if [ -z "$IP" ]; then
    IP="localhost"
fi

echo ""
echo "✅ TQUIC Manager started successfully!"
echo ""
echo "   🌐 Web Interface: http://$IP:5000"
echo "   📝 Logs: tail -f $LOG_FILE"
echo "   🛑 Stop: $SCRIPT_DIR/stop.sh"
echo ""
echo "   PID: $BACKEND_PID"
echo ""
