#!/bin/bash
set -e

CLIENT_NAME="${1:-client1}"
echo "Starting OpenVPN client: $CLIENT_NAME"

# Wait for server to be ready
sleep 3

# Start OpenVPN with client-specific cert/key
exec /usr/local/sbin/openvpn \
    --config /etc/openvpn/client.conf \
    --cert /etc/openvpn/keys/${CLIENT_NAME}.crt \
    --key /etc/openvpn/keys/${CLIENT_NAME}.key \
    --log /results/${CLIENT_NAME}.log



