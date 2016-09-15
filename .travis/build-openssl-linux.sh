#!/bin/sh

if [ ! -f download-cache/openssl-${OPENSSL_VERSION}.tar.gz ]; then
	wget -O download-cache/openssl-${OPENSSL_VERSION}.tar.gz https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz;
fi

tar zxf download-cache/openssl-${OPENSSL_VERSION}.tar.gz
cd openssl-${OPENSSL_VERSION}/
./config shared --prefix=$OPENSSL_PREFIX -DPURIFY > build.log 2>&1 || (cat build.log && exit 1)
make > build.log 2>&1 || (cat build.log && exit 1)
make install_sw > build.log 2>&1 || (cat build.log && exit 1)
cd ..
