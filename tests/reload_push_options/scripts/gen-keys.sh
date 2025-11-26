#!/bin/bash
# Generate test PKI for OpenVPN testing
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
KEYS_DIR="$SCRIPT_DIR/../keys"
mkdir -p "$KEYS_DIR"
cd "$KEYS_DIR"

# Generate CA
openssl genrsa -out ca.key 2048
openssl req -new -x509 -days 365 -key ca.key -out ca.crt \
    -subj "/CN=Test CA"

# Generate server cert
openssl genrsa -out server.key 2048
openssl req -new -key server.key -out server.csr \
    -subj "/CN=server"
openssl x509 -req -days 365 -in server.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out server.crt

# Generate client1 cert
openssl genrsa -out client1.key 2048
openssl req -new -key client1.key -out client1.csr \
    -subj "/CN=client1"
openssl x509 -req -days 365 -in client1.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out client1.crt

# Generate client2 cert
openssl genrsa -out client2.key 2048
openssl req -new -key client2.key -out client2.csr \
    -subj "/CN=client2"
openssl x509 -req -days 365 -in client2.csr -CA ca.crt -CAkey ca.key \
    -CAcreateserial -out client2.crt

# Generate DH params (2048 required by modern OpenSSL)
openssl dhparam -out dh.pem 2048

# Generate TLS auth key
openvpn --genkey secret ta.key 2>/dev/null || \
    dd if=/dev/urandom of=ta.key bs=256 count=1 2>/dev/null

# Cleanup CSRs
rm -f *.csr

echo "Keys generated in $KEYS_DIR"
ls -la "$KEYS_DIR"

