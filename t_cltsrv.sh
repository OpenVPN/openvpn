#! /bin/sh
#
# t_cltsrv.sh - script to test OpenVPN's crypto loopback
# Copyright (C) 2005,2006  Matthias Andree
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

set -e
trap "rm -f log.$$ log.$$.signal ; trap 0 ; exit 77" 1 2 15
trap "rm -f log.$$ log.$$.signal ; exit 1" 0 3
addopts=
case `uname -s` in
    FreeBSD)
    # FreeBSD jails map the outgoing IP to the jail IP - we need to
    # allow the real IP unless we want the test to run forever.
    if test "`sysctl 2>/dev/null -n security.jail.jailed`" = 1 \
    || ps -ostate= -p $$ | grep -q J; then
	addopts="--float"
	if test "x`ifconfig | grep inet`" = x ; then
	    echo "###"
	    echo "### To run the test in a FreeBSD jail, you MUST add an IP alias for the jail's IP."
	    echo "###"
	    exit 1
	fi
    fi
    ;;
esac
echo "the following test will take about two minutes..." >&2
set +e
(
./openvpn --cd "${srcdir}" ${addopts} --down 'echo "srv:${signal}" >&3 ; : #' --tls-exit --ping-exit 180 --config sample-config-files/loopback-server &
./openvpn --cd "${srcdir}" ${addopts} --down 'echo "clt:${signal}" >&3 ; : #' --tls-exit --ping-exit 180 --config sample-config-files/loopback-client
) 3>log.$$.signal >log.$$ 2>&1
e1=$?
wait $!
e2=$?
grep -v ":inactive$" log.$$.signal >/dev/null && { cat log.$$.signal ; echo ; cat log.$$ ; exit 1 ; }

set -e

if [ $e1 != 0 ] || [ $e2 != 0 ] ; then
    cat log.$$
    exit 1
fi
rm log.$$ log.$$.signal
trap 0
