#! /bin/sh
#
# t_cltsrv.sh - script to test OpenVPN's crypto loopback
# Copyright (C) 2005  Matthias Andree
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
echo "the following test will run about two minutes..." >&2
trap "rm -f log.$$ ; false" 1 2 3 15
set +e
(
./openvpn --cd "${srcdir}" --config sample-config-files/loopback-server &
./openvpn --cd "${srcdir}" --config sample-config-files/loopback-client
) >log.$$ 2>&1
e1=$?
wait $!
e2=$?
set -e

if [ $e1 != 0 ] || [ $e2 != 0 ] ; then
    cat log.$$
    exit 1
fi
rm log.$$
