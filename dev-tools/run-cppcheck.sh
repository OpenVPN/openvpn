#!/bin/bash

set -eu

SCRIPT_DIR=$(dirname $(readlink -e "${BASH_SOURCE[0]}"))
: ${SOURCE_DIR:=$SCRIPT_DIR/..}
: ${BUILD_DIR:=$PWD}
: ${INCLUDE_FLAGS:=}
CPPCHECK_DIR="${BUILD_DIR}/cppcheck_build_dir"

set -x

mkdir -p "$CPPCHECK_DIR"
cd "${SOURCE_DIR}"
cppcheck -j$(nproc) \
	 -DHAVE_CONFIG_H -U_WIN32 \
         -DMBEDTLS_SSL_PROTO_TLS1_3 -DMBEDTLS_SSL_KEYING_MATERIAL_EXPORT \
	 -I./include/ -I./tests/unit_tests/openvpn/ \
	 -I./src/compat/ -I./src/openvpn/ -I./src/openvpnserv/ -I./src/plugins/auth-pam/ \
	 -I"${BUILD_DIR}" -I"${BUILD_DIR}/include/" $INCLUDE_FLAGS \
	 --enable=all \
	 --suppressions-list="${SCRIPT_DIR}/cppcheck-suppression" \
	 --cppcheck-build-dir="${CPPCHECK_DIR}" \
	 --check-level=exhaustive \
	 --error-exitcode=1 \
	 src/ tests/ sample/
