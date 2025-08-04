#!/bin/sh

# Copyright (c) 2015, David Martin
#               2022, Heiko Hund
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


# git pre-commit hook that runs an Uncrustify stylecheck.
# Features:
#  - abort commit when commit does not comply with the style guidelines
#  - create a patch of the proposed style changes
#
# More info on Uncrustify: http://uncrustify.sourceforge.net/

# This file was taken from a set of unofficial pre-commit hooks available
# at https://github.com/ddddavidmartin/Pre-commit-hooks and modified to
# fit the openvpn project's needs

# exit on error
set -e


# If called so, install this script as pre-commit hook
if [ "$1" = "install" ] ; then
    TARGET="$(git rev-parse --git-path hooks)/pre-commit"

    if [ -e "$TARGET" ] ; then
        printf "$TARGET file exists. Won't overwrite.\n"
        printf "Aborting installation.\n"
        exit 1
    fi

    read -p "Install as $TARGET? [y/N] " INPUT
    [ "$INPUT" = "y" ] || exit 0
    cp "$0" "$TARGET"
    chmod +x $TARGET
    exit 0
fi

# check whether the given file matches any of the set extensions
matches_extension() {
    local filename="$(basename -- "$1")"
    local extension=".${filename##*.}"
    local ext

    for ext in .c .h ; do [ "$ext" = "$extension" ] && return 0; done

    return 1
}

# necessary check for initial commit
if git rev-parse --verify HEAD >/dev/null 2>&1 ; then
    against=HEAD
else
    # Initial commit: diff against an empty tree object
    against=4b825dc642cb6eb9a060e54bf8d69288fbee4904
fi

UNCRUSTIFY=$(command -v uncrustify)
UNCRUST_CONFIG="$(git rev-parse --show-toplevel)/dev-tools/uncrustify.conf"

# make sure the config file and executable are correctly set
if [ ! -f "$UNCRUST_CONFIG" ] ; then
    printf "Error: uncrustify config file not found.\n"
    printf "Expected to find it at $UNCRUST_CONFIG.\n"
    printf "Aborting commit.\n"
    exit 1
fi

if [ -z "$UNCRUSTIFY" ] ; then
    printf "Error: uncrustify executable not found.\n"
    printf "Is it installed and in your \$PATH?\n"
    printf "Aborting commit.\n"
    exit 1
fi

# create a filename to store our generated patch
patch=$(mktemp /tmp/ovpn-fmt-XXXXXX)
tmpout=$(mktemp /tmp/uncrustify-XXXXXX)

# create one patch containing all changes to the files
# sed to remove quotes around the filename, if inserted by the system
# (done sometimes, if the filename contains special characters, like the quote itself)
git diff-index --cached --diff-filter=ACMR --name-only $against -- | \
sed -e 's/^"\(.*\)"$/\1/' | \
while read file
do
    # ignore file if we do check for file extensions and the file
    # does not match the extensions .c or .h
    if ! matches_extension "$file"; then
        continue;
    fi

    # escape special characters in the target filename:
    # phase 1 (characters escaped in the output diff):
    #     - '\': backslash needs to be escaped in the output diff
    #     - '"': quote needs to be escaped in the output diff if present inside
    #            of the filename, as it used to bracket the entire filename part
    # phase 2 (characters escaped in the match replacement):
    #     - '\': backslash needs to be escaped again for sed itself
    #            (i.e. double escaping after phase 1)
    #     - '&': would expand to matched string
    #     - '|': used as sed split char instead of '/'
    # printf %s particularly important if the filename contains the % character
    file_escaped_target=$(printf "%s" "$file" | sed -e 's/[\"]/\\&/g' -e 's/[\&|]/\\&/g')

    # uncrustify our sourcefile, create a patch with diff and append it to our $patch
    # The sed call is necessary to transform the patch from
    #    --- - timestamp
    #    +++ $tmpout timestamp
    # to both lines working on the same file and having a a/ and b/ prefix.
    # Else it can not be applied with 'git apply'.
    git show ":$file" | "$UNCRUSTIFY" -q -l C -c "$UNCRUST_CONFIG" -o "$tmpout"
    git show ":$file" | diff -u -- - "$tmpout" | \
        sed -e "1s|--- -|--- \"b/$file_escaped_target\"|" -e "2s|+++ $tmpout|+++ \"a/$file_escaped_target\"|" >> "$patch"
done

rm -f "$tmpout"

# if no patch has been generated all is ok, clean up the file stub and exit
if [ ! -s "$patch" ] ; then
    rm -f "$patch"
    exit 0
fi

# a patch has been created, notify the user and exit
printf "Formatting of some code does not follow the project guidelines.\n"

if [ $(wc -l < $patch) -gt 80 ] ; then
    printf "The file $patch contains the necessary fixes.\n"
else
    printf "Here's the patch that fixes the formatting:\n\n"
    cat $patch
fi

printf "\nYou can apply these changes with:\n git apply $patch\n"
printf "(from the root directory of the repository) and then commit again.\n"
printf "\nAborting commit.\n"

exit 1
