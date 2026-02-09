#!/bin/bash

# TQUIC Manager Stop Script

PID_FILE="/tmp/tquic-manager.pid"

echo "🛑 Stopping TQUIC Manager..."

# Check if PID file exists
if [ ! -f "$PID_FILE" ]; then
    echo "⚠️  TQUIC Manager is not running (no PID file found)"
    
    # Try to find and kill any running instances
    PIDS=$(pgrep -f "python3.*tquic-manager.*app.py")
    if [ -n "$PIDS" ]; then
        echo "   Found orphaned processes: $PIDS"
        echo "   Killing orphaned processes..."
        echo "$PIDS" | xargs kill
        echo "✅ Cleaned up orphaned processes"
    fi
    
    exit 0
fi

# Read PID
PID=$(cat "$PID_FILE")

# Check if process is running
if ! ps -p $PID > /dev/null 2>&1; then
    echo "⚠️  Process $PID is not running"
    rm -f "$PID_FILE"
    exit 0
fi

# Kill the process
kill $PID

# Wait for process to terminate
for i in {1..10}; do
    if ! ps -p $PID > /dev/null 2>&1; then
        echo "✅ TQUIC Manager stopped successfully"
        rm -f "$PID_FILE"
        exit 0
    fi
    sleep 1
done

# Force kill if still running
if ps -p $PID > /dev/null 2>&1; then
    echo "   Process didn't terminate gracefully, force killing..."
    kill -9 $PID
    sleep 1
fi

# Final check
if ! ps -p $PID > /dev/null 2>&1; then
    echo "✅ TQUIC Manager stopped (forced)"
    rm -f "$PID_FILE"
else
    echo "❌ Failed to stop TQUIC Manager"
    exit 1
fi
