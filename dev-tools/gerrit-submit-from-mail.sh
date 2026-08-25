#!/bin/bash

# Assertions:
#  - there is a remote called "gerrit" that can be used to
#    pushed to gerrit. Create it with
#    git remote add gerrit ssh://<yourgerritusername>@gerrit.openvpn.net:29418/openvpn.git
# - the master branch does not contain pending commits, move them to branches
#
# Usage:
# - Pipe mail to this script on stdin
# - You can specify the target branch as the first argument to the script
#   if it is not master.

set -eu

TARGET_BRANCH=${1:-master}
SOURCE_DIR=$(dirname $(readlink -e "${BASH_SOURCE[0]}"))
TIMESTAMP=$(date +%Y%m%dT%H%M%S)

git -C $SOURCE_DIR checkout $TARGET_BRANCH
git -C $SOURCE_DIR checkout -B mail-submit-${TIMESTAMP}
git -C $SOURCE_DIR am

warnings=0
if git -C $SOURCE_DIR log -n1 --format=%an | grep -q "via Openvpn-devel"; then
    echo WARNING: Author contains \"via Openvpn-devel\"
    echo Try to get an actual email-adress from the submitter!
    warnings=$((warnings + 1))
fi

if ! git -C $SOURCE_DIR log -n1 --format=%b | grep -qi "signed-off-by:"; then
    echo WARNING: Signed-off-by: line missing
    echo Consider adding it.
    warnings=$((warnings + 1))
fi

if [ "$warnings" -gt 0 ]; then
    echo Please fix the $warnings warnings above before pushing.
    echo Push the changes with git -C $SOURCE_DIR push gerrit HEAD:refs/for/$TARGET_BRANCH
else
    echo git -C $SOURCE_DIR push gerrit HEAD:refs/for/$TARGET_BRANCH
fi
