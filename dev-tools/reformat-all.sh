#!/bin/sh
# reformat-all.sh - Reformat all git files in the checked out
#                   git branch using uncrustify.
#
# Copyright (C) 2016-2021 - David Sommerseth <davids@openvpn.net>
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

tstamp="$(date +%Y%m%d-%H%M%S)"
files="$(pwd)/reformat-all_files-$tstamp.lst"
log="$(pwd)/reformat-all_log-$tstamp.txt"

srcroot="$(git rev-parse --show-toplevel)"
cfg="$srcroot/dev-tools/uncrustify.conf"
specialfiles="$srcroot/dev-tools/special-files.lst"

export gitfiles=0
export procfiles=0

# Go to the root of the source tree
cd "$srcroot"

{
    echo -n "** Starting $0: "
    date

    # Find all C source/header files
    git ls-files | grep -E ".*\.[ch](\.in$|$)" > "${files}.git"

    # Manage files which needs special treatment
    awk -F\# '{gsub("\n| ", "", $1); print $1}' "$specialfiles" > "${files}.sp"
    while read srcfile
    do
        res=$(grep "$srcfile" "${files}.sp" 2>/dev/null)
        if [ $? -ne 0 ]; then
            # If grep didn't find the file among special files,
            # process it normally
            echo "$srcfile" >> "$files"
        else
            mode=$(echo "$res" | cut -d:  -f1)
            case "$mode" in
                E)
                    echo "** INFO **  Excluding '$srcfile'"
                    ;;
                P)
                    echo "** INFO **  Pre-patching '$srcfile'"
                    patchfile="${srcroot}"/dev-tools/reformat-patches/before_$(echo "$srcfile" | tr "/" "_").patch
                    if [ -r "$patchfile" ]; then
                        git apply "$patchfile"
                        if [ $? -ne 0 ]; then
                            echo "** ERROR **  Failed to apply pre-patch file: $patchfile"
                            exit 2
                        fi
                    else
                        echo "** WARN ** Pre-patch file for $srcfile is missing: $patchfile"
                    fi
                    echo "$srcfile" >> "${files}.postpatch"
                    echo "$srcfile" >> "$files"
                    ;;
                *)
                    echo "** WARN ** Unknown mode '$mode' for file '$srcfile'"
                    ;;
            esac
        fi
    done < "${files}.git"
    rm -f "${files}.git" "${files}.sp"

    # Kick off uncrustify
    echo
    echo "** INFO ** Running: uncrustify -c $cfg --no-backup -l C -p debug.uncr -F $files"
    uncrustify -c "$cfg" --no-backup -l C -p debug.uncr -F "$files" 2>&1
    res=$?
    echo "** INFO ** Uncrustify completed (exit code $res)"
} | tee "${log}-1"  # Log needs to be closed here, to be processed in next block

{
    # Check the results
    gitfiles=$(wc -l "$files" | cut -d\  -f1)
    procfiles=$(grep "Parsing: " "${log}-1" | wc -l)
    echo
    echo "C source/header files checked into git: $gitfiles"
    echo "Files processed by uncrustify:          $procfiles"
    echo

    # Post-Patch files modified after we uncrustify have adjusted them
    if [ -r "${files}.postpatch" ]; then
        while read srcfile;
        do
            patchfile="${srcroot}"/dev-tools/reformat-patches/after_$(echo "$srcfile" | tr "/" "_").patch
            if [ -r "$patchfile" ]; then
                echo "** INFO **  Post-patching '$srcfile'"
                git apply "$patchfile"
                if [ $? -ne 0 ]; then
                    echo "** WARN ** Failed to apply $patchfile"
                fi
            else
                echo "** WARN ** Post-patch file for $srcfile is missing: $patchfile"
            fi
        done < "${files}.postpatch"
        rm -f "${files}.postpatch"
    fi
} | tee "${log}-2" # Log needs to be closed here, to be processed in next block

cat "${log}-1" "${log}-2" > "$log"

{
    ec=1
    echo
    if [ "$gitfiles" -eq "$procfiles" ]; then
        echo "Reformatting completed successfully"
        ec=0
    else
        last=$(tail -n1 "${log}-1")
        echo "** ERROR ** Reformating failed to process all files."
        echo "            uncrustify exit code: $res"
        echo "            Last log line: $last"
        echo
    fi
    rm -f "${log}-1" "${log}-2"
} | tee -a "$log"
rm -f "${files}"

exit $ec
