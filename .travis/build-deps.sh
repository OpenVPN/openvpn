#!/bin/sh
set -eux

if [ "${TRAVIS_OS_NAME}" = "windows" ]; then
    choco install strawberryperl nasm
    choco install visualstudio2019buildtools --package-parameters "--includeRecommended --includeOptional"
    choco install visualstudio2019-workload-vctools
    cd ..
    git clone https://github.com/openvpn/openvpn-build.git
    cd openvpn-build
    PATH="/c/Strawberry/perl/bin:":$PATH MODE=DEPS msvc/build.bat
    exit 0
fi

# Set defaults
PREFIX="${PREFIX:-${HOME}/opt}"

download_tap_windows () {
    if [ ! -f "download-cache/tap-windows-${TAP_WINDOWS_VERSION}.zip" ]; then
       wget -P download-cache/ \
           "https://build.openvpn.net/downloads/releases/tap-windows-${TAP_WINDOWS_VERSION}.zip"
    fi
}

download_lzo () {
    if [ ! -f "download-cache/lzo-${LZO_VERSION}.tar.gz" ]; then
        wget -P download-cache/ \
            "https://www.oberhumer.com/opensource/lzo/download/lzo-${LZO_VERSION}.tar.gz"
    fi
}

build_lzo () {
    if [ "$(cat ${PREFIX}/.lzo-version)" != "${LZO_VERSION}" ]; then
        tar zxf download-cache/lzo-${LZO_VERSION}.tar.gz
        (
            cd "lzo-${LZO_VERSION}"

            ./configure --host=${CHOST} --program-prefix='' \
                --libdir=${PREFIX}/lib --prefix=${PREFIX} --build=x86_64-pc-linux-gnu
            make all install
        )
        echo "${LZO_VERSION}" > "${PREFIX}/.lzo-version"
    fi
}

download_pkcs11_helper () {
    if [ ! -f "pkcs11-helper-${PKCS11_HELPER_VERSION}.tar.gz" ]; then
        wget -P download-cache/ \
            "https://github.com/OpenSC/pkcs11-helper/archive/pkcs11-helper-${PKCS11_HELPER_VERSION}.tar.gz"
    fi
}

build_pkcs11_helper () {
    if [ "$(cat ${PREFIX}/.pkcs11_helper-version)" != "${PKCS11_HELPER_VERSION}" ]; then
        tar xf download-cache/pkcs11-helper-${PKCS11_HELPER_VERSION}.tar.gz
        (
            cd "pkcs11-helper-pkcs11-helper-${PKCS11_HELPER_VERSION}"

            autoreconf -iv

            ./configure --host=${CHOST} --program-prefix='' --libdir=${PREFIX}/lib \
                 --prefix=${PREFIX} --build=x86_64-pc-linux-gnu \
                 --disable-crypto-engine-gnutls \
                 --disable-crypto-engine-nss \
                 --disable-crypto-engine-polarssl \
                 --disable-crypto-engine-mbedtls
            make all install
         )
         echo "${PKCS11_HELPER_VERSION}" > "${PREFIX}/.pkcs11_helper-version"
    fi
}

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
        MAJOR=`echo $OPENSSL_VERSION | sed -e 's/\([0-9.]*\).*/\1/'`
        wget -P download-cache/ \
             "https://www.openssl.org/source/old/${MAJOR}/openssl-${OPENSSL_VERSION}.tar.gz"
    fi
}

build_openssl_linux () {
    (
        cd "openssl-${OPENSSL_VERSION}/"
        ./config shared --prefix="${PREFIX}" --openssldir="${PREFIX}" -DPURIFY
        make all install_sw
    )
}

build_openssl_osx () {
    (
        cd "openssl-${OPENSSL_VERSION}/"
        ./Configure darwin64-x86_64-cc shared \
            --prefix="${PREFIX}" --openssldir="${PREFIX}" -DPURIFY
        make depend all install_sw
    )
}

build_openssl_mingw () {
    (
        cd "openssl-${OPENSSL_VERSION}/"

        if [ "${CHOST}" = "i686-w64-mingw32" ]; then
            export TARGET=mingw
        elif [ "${CHOST}" = "x86_64-w64-mingw32" ]; then
            export TARGET=mingw64
        fi

        ./Configure --cross-compile-prefix=${CHOST}- shared \
           ${TARGET} no-capieng --prefix="${PREFIX}" --openssldir="${PREFIX}" -static-libgcc
        make install
    )
}

build_openssl () {
    if [ "$(cat ${PREFIX}/.openssl-version)" != "${OPENSSL_VERSION}" ]; then
        tar zxf "download-cache/openssl-${OPENSSL_VERSION}.tar.gz"
        if [ ! -z ${CHOST+x} ]; then
            build_openssl_mingw
        elif [ "${TRAVIS_OS_NAME}" = "osx" ]; then
            build_openssl_osx
        elif [ "${TRAVIS_OS_NAME}" = "linux" ]; then
            build_openssl_linux
        fi
        echo "${OPENSSL_VERSION}" > "${PREFIX}/.openssl-version"
    fi
}

# Download and build crypto lib
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

# Download and build dependencies for mingw cross build
# dependencies are the same as in regular windows installer build
if [ ! -z ${CHOST+x} ]; then
      download_tap_windows
      unzip download-cache/tap-windows-${TAP_WINDOWS_VERSION}.zip

      download_lzo
      build_lzo

      download_pkcs11_helper
      build_pkcs11_helper
fi
