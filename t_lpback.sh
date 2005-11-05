#! /bin/sh
#
# t_lpback.sh - script to test OpenVPN's crypto loopback
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
trap "rm -f key.$$ log.$$ ; trap 0 ; exit 77" 1 2 15
trap "rm -f key.$$ log.$$ ; exit 1" 0 3
./openvpn --genkey --secret key.$$
set +e
( ./openvpn --test-crypto --secret key.$$ ) >log.$$ 2>&1
e=$?
if [ $e != 0 ] ; then cat log.$$ ; fi
rm key.$$ log.$$
trap 0
exit $e
