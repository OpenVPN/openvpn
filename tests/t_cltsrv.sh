#! /bin/sh
#
# t_cltsrv.sh - script to test OpenVPN's crypto loopback
# Copyright (C) 2005, 2006, 2008  Matthias Andree
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
srcdir="${srcdir:-.}"
top_srcdir="${top_srcdir:-..}"
top_builddir="${top_builddir:-..}"
openvpn="${openvpn:-${top_builddir}/src/openvpn/openvpn}"
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
	    exit 77
	fi
    fi
    ;;
esac

# make sure that the --down script is executable -- fail (rather than
# skip) test if it isn't.
downscript="../tests/t_cltsrv-down.sh"
root="${top_srcdir}/sample"
test -x "${root}/${downscript}" || chmod +x "${root}/${downscript}" || { echo >&2 "${root}/${downscript} is not executable, failing." ; exit 1 ; }
echo "The following test will take about two minutes." >&2
echo "If the addresses are in use, this test will retry up to two times." >&2

# go
success=0
for i in 1 2 3 ; do
  set +e
  (
  "${openvpn}" --script-security 2 --cd "${root}" ${addopts} --setenv role srv --down "${downscript}" --tls-exit --ping-exit 180 --config "sample-config-files/loopback-server" &
  "${openvpn}" --script-security 2 --cd "${top_srcdir}/sample" ${addopts} --setenv role clt --down "${downscript}" --tls-exit --ping-exit 180 --config "sample-config-files/loopback-client"
  ) 3>log.$$.signal >log.$$ 2>&1
  e1=$?
  wait $!
  e2=$?
  grep 'TCP/UDP: Socket bind failed on local address.*in use' log.$$ >/dev/null && {
    echo 'address in use, retrying in 150 s'
    sleep 150
    continue
  }
  grep -v ':inactive$' log.$$.signal >/dev/null && { cat log.$$.signal ; echo ; cat log.$$ ; exit 1 ; }
  success=1
  break
done

set -e

# exit code - defaults to 0, PASS
ec=0

if [ $success != 1 ] ; then
  # couldn't run test -- addresses in use, skip test
  cat log.$$
  ec=77
elif [ $e1 != 0 ] || [ $e2 != 0 ] ; then
  # failure -- fail test
  cat log.$$
  ec=1
fi

rm log.$$ log.$$.signal
trap 0
exit $ec
