#!/bin/bash

set -eu

SCRIPT_DIR=$(dirname $(readlink -e "${BASH_SOURCE[0]}"))
: ${SOURCE_DIR:=$SCRIPT_DIR/..}
: ${BUILD_DIR:=$PWD}
: ${INCLUDE_FLAGS:=}
CPPCHECK_DIR="${BUILD_DIR}/cppcheck_build_dir"
COMMON_ARGS="-j$(nproc) -q \
 -DMBEDTLS_SSL_PROTO_TLS1_3 -DMBEDTLS_SSL_KEYING_MATERIAL_EXPORT \
 -I./include/ -I./tests/unit_tests/openvpn/ \
 -I./src/compat/ -I./src/openvpn/ -I./src/openvpnserv/ -I./src/plugins/auth-pam/ \
 -I${BUILD_DIR} -I${BUILD_DIR}/include/ \
 --enable=all \
 --library=${SCRIPT_DIR}/openvpn-cppcheck-library.cfg \
 --library=openssl.cfg \
 --suppressions-list=${SCRIPT_DIR}/cppcheck-suppression \
 --cppcheck-build-dir=${CPPCHECK_DIR} \
 --check-level=exhaustive --max-configs=10 \
 --error-exitcode=1"


set -x

mkdir -p "$CPPCHECK_DIR"
cd "${SOURCE_DIR}"
cppcheck $COMMON_ARGS $INCLUDE_FLAGS \
         --platform=unix64 \
         --library=posix.cfg --library=bsd.cfg --library=gnu.cfg \
         -U_WIN32 \
         src/openvpn/ src/compat/ src/plugins/ sample/ \
         tests/unit_tests/example_test/ tests/unit_tests/openvpn/ \
         tests/unit_tests/plugins/
cppcheck $COMMON_ARGS \
         --platform=win64 \
         --library=windows.cfg \
         -D_WIN32 \
         -UTARGET_LINUX -UTARGET_FREEBSD -UTARGET_OPENBSD -UTARGET_NETBSD \
         -UTARGET_DARWIN -UTARGET_ANDROID -UTARGET_SOLARIS -UTARGET_DRAGONFLY \
         -UTARGET_AIX \
         src/openvpn* src/compat/ \
         tests/unit_tests/example_test/ tests/unit_tests/openvpn*
