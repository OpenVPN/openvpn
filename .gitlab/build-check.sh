#!/bin/sh
set -eux

export LD_LIBRARY_PATH="${PREFIX}/lib:${LD_LIBRARY_PATH:-}"

autoreconf -vi

if [ -z ${CHOST+x} ]; then
	./configure --with-crypto-library="${SSLLIB}" ${EXTRA_CONFIG:-} || (cat config.log && exit 1)
	make -j$JOBS
	src/openvpn/openvpn --version || true
	ldd src/openvpn/openvpn
	make check
	${EXTRA_SCRIPT:-}
else
	export TAP_CFLAGS="-I${PWD}/tap-windows-${TAP_WINDOWS_VERSION}/include"
	export LZO_CFLAGS="-I${PREFIX}/include"
	export LZO_LIBS="-L${PREFIX}/lib -llzo2"
	export PKCS11_HELPER_LIBS="-L${PREFIX}/lib -lpkcs11-helper"
	export PKCS11_HELPER_CFLAGS="-I${PREFIX}/include"
	./configure --with-crypto-library="${SSLLIB}" --host=${CHOST} --build=x86_64-pc-linux-gnu --enable-pkcs11 --disable-plugins ${EXTRA_CONFIG:-} || (cat config.log && exit 1)
	make -j${JOBS}
fi
