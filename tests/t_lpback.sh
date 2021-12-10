#! /bin/sh
#
# t_lpback.sh - script to test OpenVPN's crypto loopback
# Copyright (C) 2005  Matthias Andree
# Copyright (C) 2014  Steffan Karger
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA.

set -eu
top_builddir="${top_builddir:-..}"
trap "rm -f key.$$ tc-server-key.$$ tc-client-key.$$ log.$$ ; trap 0 ; exit 77" 1 2 15
trap "rm -f key.$$ tc-server-key.$$ tc-client-key.$$ log.$$ ; exit 1" 0 3

# Get list of supported ciphers from openvpn --show-ciphers output
CIPHERS=$(${top_builddir}/src/openvpn/openvpn --show-ciphers | \
            sed -e '/The following/,/^$/d' -e s'/ .*//' -e '/^[[:space:]]*$/d')

# SK, 2014-06-04: currently the DES-EDE3-CFB1 implementation of OpenSSL is
# broken (see http://rt.openssl.org/Ticket/Display.html?id=2867), so exclude
# that cipher from this test.
# GD, 2014-07-06 so is DES-CFB1
# GD, 2014-07-06 do not test RC5-* either (fails on NetBSD w/o libcrypto_rc5)
CIPHERS=$(echo "$CIPHERS" | egrep -v '^(DES-EDE3-CFB1|DES-CFB1|RC5-)' )

e=0
if [ -z "$CIPHERS" ] ; then
    echo "'openvpn --show-ciphers' FAILED (empty list)"
    e=1
fi

# Also test cipher 'none'
CIPHERS=${CIPHERS}$(printf "\nnone")

"${top_builddir}/src/openvpn/openvpn" --genkey secret key.$$
set +e

for cipher in ${CIPHERS}
do
    printf "Testing cipher ${cipher}... "
    ( "${top_builddir}/src/openvpn/openvpn" --test-crypto --secret key.$$ --cipher ${cipher} ) >log.$$ 2>&1
    if [ $? != 0 ] ; then
        echo "FAILED"
        cat log.$$
        e=1
    else
        echo "OK"
    fi
done

printf "Testing tls-crypt-v2 server key generation... "
"${top_builddir}/src/openvpn/openvpn" \
    --genkey tls-crypt-v2-server tc-server-key.$$ >log.$$ 2>&1
if [ $? != 0 ] ; then
    echo "FAILED"
    cat log.$$
    e=1
else
    echo "OK"
fi

printf "Testing tls-crypt-v2 key generation (no metadata)... "
"${top_builddir}/src/openvpn/openvpn" --tls-crypt-v2 tc-server-key.$$ \
    --genkey tls-crypt-v2-client tc-client-key.$$ >log.$$ 2>&1
if [ $? != 0 ] ; then
    echo "FAILED"
    cat log.$$
    e=1
else
    echo "OK"
fi

# Generate max-length base64 metadata ('A' is 0b000000 in base64)
METADATA=""
i=0
while [ $i -lt 732 ]; do
    METADATA="${METADATA}A"
    i=$(expr $i + 1)
done
printf "Testing tls-crypt-v2 key generation (max length metadata)... "
"${top_builddir}/src/openvpn/openvpn" --tls-crypt-v2 tc-server-key.$$ \
    --genkey tls-crypt-v2-client tc-client-key.$$ "${METADATA}" \
    >log.$$ 2>&1
if [ $? != 0 ] ; then
    echo "FAILED"
    cat log.$$
    e=1
else
    echo "OK"
fi

rm key.$$ tc-server-key.$$ tc-client-key.$$ log.$$
trap 0
exit $e
