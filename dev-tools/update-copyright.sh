#!/bin/sh
# update-copyright-sh - Simple tool to update the Copyright lines
#                       in all files checked into git
#
# Copyright (C) 2016-2022 OpenVPN Inc <sales@openvpn.net>
# Copyright (C) 2016-2022 David Sommerseth <davids@openvpn.net>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#

# Basic shell sanity
set -eu

# Simple argument control
if [ $# -ne 1 ]; then
    echo "Usage: $0 <New Copyright Year>"
    exit 1
fi

# Only update Copyright lines with these owners
# The 'or' operator is GNU sed specific, and must be \|
UPDATE_COPYRIGHT_LINES="@openvpn\.net\|@fox-it\.com\|@sophos.com\|@eurephia\.org\|@greenie\.muc\.de\|@rozman.si\|@unstable\.cc\|@rfc2549.org\|@karger\.me\|selva.nair@"
COPY_YEAR="$1"

cd "$(git rev-parse --show-toplevel)"
for file in $(git ls-files | grep -v vendor/);
do
    echo -n "Updating $file ..."
    # The first sed operation covers 20xx-20yy copyright lines,
    # The second sed operation changes 20xx -> 20xx-20yy
    sed -e "/$UPDATE_COPYRIGHT_LINES/s/\(Copyright (C) 20..-\)\(20..\)[[:blank:]]\+/\1$COPY_YEAR /" \
        -e "/$UPDATE_COPYRIGHT_LINES/s/\(Copyright (C) \)\(20..\)[[:blank:]]\+/\1\2-$COPY_YEAR /" \
        -i $file
    echo " Done"
done
echo
echo "** All files updated with $COPY_YEAR as the ending copyright year"
echo
exit 0
