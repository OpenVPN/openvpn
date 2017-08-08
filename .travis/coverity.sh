#!/bin/sh
set -eu

RUN_COVERITY="${RUN_COVERITY:-0}"

export COVERITY_SCAN_PROJECT_NAME="OpenVPN/openvpn"
export COVERITY_SCAN_BRANCH_PATTERN="release\/2.4"
export COVERITY_SCAN_NOTIFICATION_EMAIL="scan-reports@openvpn.net"
export COVERITY_SCAN_BUILD_COMMAND_PREPEND="autoreconf -vi && ./configure --enable-iproute2 && make clean"
export COVERITY_SCAN_BUILD_COMMAND="make"

if [ "${RUN_COVERITY}" = "1" ]; then
    # Ignore exit code, script exits with 1 if we're not on the right branch
    curl -s "https://scan.coverity.com/scripts/travisci_build_coverity_scan.sh" | bash || true
else
    echo "Skipping coverity scan because \$RUN_COVERITY != \"1\""
fi
