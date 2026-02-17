#!/bin/bash
set -e

echo "Starting OpenVPN server..."

# Default push options (used on initial start)
export PUSH_OPTIONS='push "route 192.168.10.0 255.255.255.0"
push "route 192.168.20.0 255.255.255.0"
push "dhcp-option DNS 8.8.8.8"'

# Generate config from template
envsubst '${PUSH_OPTIONS}' < /etc/openvpn/server.conf.default > /etc/openvpn/server.conf
echo "Generated server config with default push options"

# Enable IP forwarding (ignore error in container)
echo 1 > /proc/sys/net/ipv4/ip_forward 2>/dev/null || true

# Start OpenVPN
exec /usr/local/sbin/openvpn --config /etc/openvpn/server.conf

