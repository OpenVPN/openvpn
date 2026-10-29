#!/usr/bin/env bash

set -eu

: ${CPPCHECK_VERBOSE:=false}
: ${CPPCHECK_CHECK_LEVEL:=normal}

if "${CPPCHECK_VERBOSE}"; then
    verbosity_arg="-v"
else
    verbosity_arg="-q"
fi

disable_arg=
if [ "${CPPCHECK_CHECK_LEVEL}" != exhaustive ]; then
    # suppress all the information that we should use exhaustive
    disable_arg="--disable=information"
fi

if [ $(uname) = "Darwin" ] || [ $(uname) = "FreeBSD" ]; then
    SCRIPT_DIR=$(dirname $(readlink -f "${BASH_SOURCE[0]}"))
    num_procs=$(sysctl -n hw.ncpu)
else
    SCRIPT_DIR=$(dirname $(readlink -e "${BASH_SOURCE[0]}"))
    num_procs=$(nproc)
fi
: ${SOURCE_DIR:=$SCRIPT_DIR/..}
: ${BUILD_DIR:=$PWD}
: ${INCLUDE_FLAGS:=}
CPPCHECK_DIR="${BUILD_DIR}/cppcheck_build_dir"
COMMON_ARGS="-j${num_procs} ${verbosity_arg} \
 -DMBEDTLS_SSL_PROTO_TLS1_3 \
 -I./include/ -I./tests/unit_tests/openvpn/ \
 -I./src/compat/ -I./src/openvpn/ -I./src/openvpnserv/ -I./src/plugins/auth-pam/ \
 -I${BUILD_DIR} -I${BUILD_DIR}/include/ \
 --enable=all ${disable_arg} \
 --library=${SCRIPT_DIR}/openvpn-cppcheck-library.cfg \
 --library=openssl.cfg \
 --suppress-xml=${SCRIPT_DIR}/cppcheck-suppressions.xml --inline-suppr \
 --cppcheck-build-dir=${CPPCHECK_DIR} \
 --check-level=${CPPCHECK_CHECK_LEVEL} --max-configs=10 \
 --error-exitcode=1"

set -x

mkdir -p "$CPPCHECK_DIR"
cd "${SOURCE_DIR}"
ret=0
cppcheck $COMMON_ARGS $INCLUDE_FLAGS \
    --platform=unix64 \
    --library=posix.cfg --library=bsd.cfg --library=gnu.cfg \
    -U_WIN32 \
    src/openvpn/ src/compat/ src/plugins/ sample/ \
    tests/unit_tests/example_test/ tests/unit_tests/openvpn/ \
    tests/unit_tests/plugins/ || ret=$?
cppcheck $COMMON_ARGS \
    --platform=win64 \
    --library=windows.cfg --library=${SCRIPT_DIR}/openvpn-cppcheck-windows.cfg \
    -D_WIN32 \
    -UTARGET_LINUX -UTARGET_FREEBSD -UTARGET_OPENBSD -UTARGET_NETBSD \
    -UTARGET_DARWIN -UTARGET_ANDROID -UTARGET_SOLARIS -UTARGET_DRAGONFLY \
    -UTARGET_AIX \
    -UOPENSSL_NO_EC \
    src/openvpn* src/compat/ \
    tests/unit_tests/example_test/ tests/unit_tests/openvpn* || ret=$?

exit $ret
