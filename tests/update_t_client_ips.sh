#!/bin/sh
#
# This --up script caches the IPs handed out by the test VPN server to a file
# for later use.

RC="$TOP_BUILDDIR/t_client_ips.rc"

grep EXPECT_IFCONFIG4_$TESTNUM= $RC > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "EXPECT_IFCONFIG4_$TESTNUM=$ifconfig_local" >> $RC
fi

grep EXPECT_IFCONFIG6_$TESTNUM= $RC > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "EXPECT_IFCONFIG6_$TESTNUM=$ifconfig_ipv6_local" >> $RC
fi
