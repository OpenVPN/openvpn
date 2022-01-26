#!/bin/sh
# lz4-rebaser.sh   - Does the LZ4 rebase process in an automated fashion
#
# Copyright (C) 2017-2022 David Sommerseth <davids@openvpn.net>
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
    echo "Usage: $0 <Path to upstream LZ4 source tree>"
    exit 1
fi

# Check that we have the files we need before starting the rebase
LZ4_C="$1/lib/lz4.c"
LZ4_H="$1/lib/lz4.h"
if [ ! -r "$LZ4_C" -o ! -r "$LZ4_H" ]; then
    echo "Could not locate $LZ4_H and/or $LZ4_C"
    exit 1
fi

# Extract the upstream LZ4 commit base
lz4_tag="$(git --git-dir $1/.git tag --contains HEAD)"
lz4_commit="$(git --git-dir $1/.git rev-parse --short=20 HEAD)"

# Do the rebase
srcroot="$(git rev-parse --show-toplevel)"
echo "* Copying upstream lz4.h to compat-lz4.h"
cp "$LZ4_H" "${srcroot}/src/compat/compat-lz4.h"

echo "* Porting upstream lz4.c to compat-lz4.c"
{
    cat <<EOF
/* This file has been backported by $0
 * from upstream lz4 commit $lz4_commit ($lz4_tag)
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#elif defined(_MSC_VER)
#include "config-msvc.h"
#endif

#ifdef NEED_COMPAT_LZ4
EOF
    sed 's/\"lz4\.h\"/\"compat-lz4.h"/' "$LZ4_C"
cat <<EOF
#endif /* NEED_COMPAT_LZ4 */
EOF
} > "${srcroot}/src/compat/compat-lz4.c"

echo "* Running 'git add'"
git add src/compat/compat-lz4.[ch]
