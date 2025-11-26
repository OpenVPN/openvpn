#!/bin/bash
set -e

CLIENT_NAME=${CLIENT_NAME:-client}
LOG_FILE="/var/log/openvpn/${CLIENT_NAME}.log"

# Function to log routes
log_routes() {
    echo "=== Routes at $(date -Iseconds) ===" >> "$LOG_FILE"
    ip route show | grep -E "^(10\.|172\.|192\.168\.)" >> "$LOG_FILE" 2>/dev/null || echo "(no VPN routes)" >> "$LOG_FILE"
    echo "" >> "$LOG_FILE"
}

# Monitor route changes in background
monitor_routes() {
    while true; do
        ip monitor route 2>/dev/null | while read -r line; do
            echo "[$(date -Iseconds)] ROUTE CHANGE: $line" >> "$LOG_FILE"
        done
        sleep 1
    done
}

# Start route monitor
monitor_routes &

# Log initial routes
echo "=== Client $CLIENT_NAME starting ===" > "$LOG_FILE"
log_routes

# Start OpenVPN
exec /usr/local/sbin/openvpn --config /etc/openvpn/client.conf \
    --log-append "$LOG_FILE" \
    --verb 4

