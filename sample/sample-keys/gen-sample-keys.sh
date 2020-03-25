#!/bin/sh
#
# Run this script to set up a test CA, and test key-certificate pair for a
# server, and various clients.
#
# Copyright (C) 2014 Steffan Karger <steffan@karger.me>
set -eu

command -v openssl >/dev/null 2>&1 || { echo >&2 "Unable to find openssl. Please make sure openssl is installed and in your path."; exit 1; }

if [ ! -f openssl.cnf ]
then
    echo "Please run this script from the sample directory"
    exit 1
fi

# Generate static key for tls-auth (or static key mode)
$(dirname ${0})/../../src/openvpn/openvpn --genkey tls-auth ta.key

# Create required directories and files
mkdir -p sample-ca
rm -f sample-ca/index.txt
touch sample-ca/index.txt
echo "01" > sample-ca/serial

# Generate CA key and cert
openssl req -new -newkey rsa:4096 -days 3650 -nodes -x509 \
    -extensions easyrsa_ca -keyout sample-ca/ca.key -out sample-ca/ca.crt \
    -subj "/C=KG/ST=NA/L=BISHKEK/O=OpenVPN-TEST/emailAddress=me@myhost.mydomain" \
    -config openssl.cnf

# Create server key and cert
openssl req -new -nodes -config openssl.cnf -extensions server \
    -keyout sample-ca/server.key -out sample-ca/server.csr \
    -subj "/C=KG/ST=NA/O=OpenVPN-TEST/CN=Test-Server/emailAddress=me@myhost.mydomain"
openssl ca -batch -config openssl.cnf -extensions server \
    -out sample-ca/server.crt -in sample-ca/server.csr

# Create client key and cert
openssl req -new -nodes -config openssl.cnf \
    -keyout sample-ca/client.key -out sample-ca/client.csr \
    -subj "/C=KG/ST=NA/O=OpenVPN-TEST/CN=Test-Client/emailAddress=me@myhost.mydomain"
openssl ca -batch -config openssl.cnf \
    -out sample-ca/client.crt -in sample-ca/client.csr

# Create password protected key file
openssl rsa -aes256 -passout pass:password \
    -in sample-ca/client.key -out sample-ca/client-pass.key

# Create pkcs#12 client bundle
openssl pkcs12 -export -nodes -password pass:password \
    -out sample-ca/client.p12 -inkey sample-ca/client.key \
    -in sample-ca/client.crt -certfile sample-ca/ca.crt

# Create a client cert, revoke it, generate CRL
openssl req -new -nodes -config openssl.cnf \
    -keyout sample-ca/client-revoked.key -out sample-ca/client-revoked.csr \
    -subj "/C=KG/ST=NA/O=OpenVPN-TEST/CN=client-revoked/emailAddress=me@myhost.mydomain"
openssl ca -batch -config openssl.cnf \
    -out sample-ca/client-revoked.crt -in sample-ca/client-revoked.csr
openssl ca -config openssl.cnf -revoke sample-ca/client-revoked.crt
openssl ca -config openssl.cnf -gencrl -out sample-ca/ca.crl

# Create DSA server and client cert (signed by 'regular' RSA CA)
openssl dsaparam -out sample-ca/dsaparams.pem 2048

openssl req -new -newkey dsa:sample-ca/dsaparams.pem -nodes -config openssl.cnf \
    -extensions server \
    -keyout sample-ca/server-dsa.key -out sample-ca/server-dsa.csr \
    -subj "/C=KG/ST=NA/O=OpenVPN-TEST/CN=Test-Server-DSA/emailAddress=me@myhost.mydomain"
openssl ca -batch -config openssl.cnf -extensions server \
    -out sample-ca/server-dsa.crt -in sample-ca/server-dsa.csr

openssl req -new -newkey dsa:sample-ca/dsaparams.pem -nodes -config openssl.cnf \
    -keyout sample-ca/client-dsa.key -out sample-ca/client-dsa.csr \
    -subj "/C=KG/ST=NA/O=OpenVPN-TEST/CN=Test-Client-DSA/emailAddress=me@myhost.mydomain"
openssl ca -batch -config openssl.cnf \
    -out sample-ca/client-dsa.crt -in sample-ca/client-dsa.csr

# Create EC server and client cert (signed by 'regular' RSA CA)
openssl ecparam -out sample-ca/secp256k1.pem -name secp256k1

openssl req -new -newkey ec:sample-ca/secp256k1.pem -nodes -config openssl.cnf \
    -extensions server \
    -keyout sample-ca/server-ec.key -out sample-ca/server-ec.csr \
    -subj "/C=KG/ST=NA/O=OpenVPN-TEST/CN=Test-Server-EC/emailAddress=me@myhost.mydomain"
openssl ca -batch -config openssl.cnf -extensions server \
    -out sample-ca/server-ec.crt -in sample-ca/server-ec.csr

openssl req -new -newkey ec:sample-ca/secp256k1.pem -nodes -config openssl.cnf \
    -keyout sample-ca/client-ec.key -out sample-ca/client-ec.csr \
    -subj "/C=KG/ST=NA/O=OpenVPN-TEST/CN=Test-Client-EC/emailAddress=me@myhost.mydomain"
openssl ca -batch -config openssl.cnf \
    -out sample-ca/client-ec.crt -in sample-ca/client-ec.csr

# Generate DH parameters
openssl dhparam -out dh2048.pem 2048

# Copy keys and certs to working directory
cp sample-ca/*.key .
cp sample-ca/*.crt .
cp sample-ca/*.p12 .
cp sample-ca/*.crl .
