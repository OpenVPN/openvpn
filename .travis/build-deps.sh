#!/bin/sh
set -eux

# Set defaults
MBEDTLS_VERSION="${MBEDTLS_VERSION:-2.2.1}"
OPENSSL_VERSION="${OPENSSL_VERION:-1.0.2h}"
PREFIX="${PREFIX:-${HOME}/opt}"

download_mbedtls () {
    if [ ! -f "download-cache/mbedtls-${MBEDTLS_VERSION}-apache.tgz" ]; then
        wget -P download-cache/ \
            "https://tls.mbed.org/download/mbedtls-${MBEDTLS_VERSION}-apache.tgz"
    fi
}

build_mbedtls () {
    if [ "$(cat ${PREFIX}/.mbedtls-version)" != "${MBEDTLS_VERSION}" ]; then
        tar zxf download-cache/mbedtls-${MBEDTLS_VERSION}-apache.tgz
        (
            cd "mbedtls-${MBEDTLS_VERSION}"
            make
            make install DESTDIR="${PREFIX}"
        )
        echo "${MBEDTLS_VERSION}" > "${PREFIX}/.mbedtls-version"
    fi
}

download_openssl () {
    if [ ! -f "download-cache/openssl-${OPENSSL_VERSION}.tar.gz" ]; then
        wget -P download-cache/ \
            "https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz"
    fi
}

build_openssl_linux () {
    tar zxf "download-cache/openssl-${OPENSSL_VERSION}.tar.gz"
    (
        cd "openssl-${OPENSSL_VERSION}/"
        ./config shared --openssldir="${PREFIX}" -DPURIFY
        make all install_sw
    )
}

build_openssl_osx () {
    tar zxf "download-cache/openssl-${OPENSSL_VERSION}.tar.gz"
    (
        cd "openssl-${OPENSSL_VERSION}/"
        ./Configure darwin64-x86_64-cc shared \
            --openssldir="${PREFIX}" -DPURIFY
        make depend all install_sw
    )
}

build_openssl () {
    if [ "$(cat ${PREFIX}/.openssl-version)" != "${OPENSSL_VERSION}" ]; then
        if [ "${TRAVIS_OS_NAME}" = "osx" ]; then
            build_openssl_osx
        elif [ "${TRAVIS_OS_NAME}" = "linux" ]; then
            build_openssl_linux
        fi
        echo "${OPENSSL_VERSION}" > "${PREFIX}/.openssl-version"
    fi
}

# Enable ccache
if [ "${TRAVIS_OS_NAME}" != "osx" ]; then
    # ccache not available on osx, see:
    # https://github.com/travis-ci/travis-ci/issues/5567
    mkdir -p "${HOME}/bin"
    ln -s "$(which ccache)" "${HOME}/bin/${CC}"
    PATH="${HOME}/bin:${PATH}"
fi

# Download and build crypto lib
mkdir -p download-cache
if [ "${SSLLIB}" = "openssl" ]; then
    download_openssl
    build_openssl
elif [ "${SSLLIB}" = "mbedtls" ]; then
    download_mbedtls
    build_mbedtls
else
    echo "Invalid crypto lib: ${SSLLIB}"
    exit 1
fi
