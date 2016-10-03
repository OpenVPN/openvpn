#!/bin/sh
#
# This --up script caches the IPs handed out by the test VPN server to a file
# for later use.

echo "EXPECT_IFCONFIG4_$TESTNUM=$ifconfig_local" >> $TOP_BUILDDIR/t_client_ips.rc
echo "EXPECT_IFCONFIG6_$TESTNUM=$ifconfig_ipv6_local" >> $TOP_BUILDDIR/t_client_ips.rc
