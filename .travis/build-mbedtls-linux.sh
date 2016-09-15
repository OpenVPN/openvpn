#!/bin/sh

if [ ! -f download-cache/mbedtls-${MBEDTLS_VERSION}-apache.tgz ]; then
	wget -O download-cache/mbedtls-${MBEDTLS_VERSION}-apache.tgz https://tls.mbed.org/download/mbedtls-${MBEDTLS_VERSION}-apache.tgz;
fi

tar zxf download-cache/mbedtls-${MBEDTLS_VERSION}-apache.tgz
cd mbedtls-${MBEDTLS_VERSION} && make > build.log 2>&1 || (cat build.log && exit 1)
make install DESTDIR=$MBEDTLS_PREFIX && cd ..
