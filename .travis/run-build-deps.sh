#!/bin/sh
set -eux

if [ "${TRAVIS_OS_NAME}" = "windows" ]; then
    # for windows we need to print output since openssl build
    # might take more than 10 minutes, which causes build abort
    .travis/build-deps.sh
else
    .travis/build-deps.sh > build-deps.log 2>&1 || (cat build-deps.log && exit 1)
fi
