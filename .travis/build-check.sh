#!/bin/sh
set -eux

if [ "${TRAVIS_OS_NAME}" = "windows" ]; then
	PATH="/c/Program Files (x86)/Microsoft Visual Studio/2019/BuildTools/MSBuild/Current/Bin/":$PATH
	MSBuild.exe openvpn.sln //p:Platform=x64 && exit 0
fi

autoreconf -vi

if [ -z ${CHOST+x} ]; then
	if [ "${TRAVIS_OS_NAME}" = "linux" ]; then
		export EXTRA_CONFIG="${EXTRA_CONFIG:-} --enable-werror"
	fi
	./configure --with-crypto-library="${SSLLIB}" ${EXTRA_CONFIG:-} || (cat config.log && exit 1)
	make LDFLAGS="-Wl,-rpath,${PREFIX}/lib" -j$JOBS
	src/openvpn/openvpn --version || true
	if [ "${TRAVIS_OS_NAME}" = "linux" ]; then
		ldd src/openvpn/openvpn;
	fi
	if [ "${TRAVIS_OS_NAME}" = "osx" ]; then otool -L src/openvpn/openvpn; fi
	make check
	${EXTRA_SCRIPT:-}
else
	export TAP_CFLAGS="-I${PWD}/tap-windows-${TAP_WINDOWS_VERSION}/include"
	export LZO_CFLAGS="-I${PREFIX}/include"
	export LZO_LIBS="-L${PREFIX}/lib -llzo2"
	export PKCS11_HELPER_LIBS="-L${PREFIX}/lib -lpkcs11-helper"
	export PKCS11_HELPER_CFLAGS="-I${PREFIX}/include"
	./configure --with-crypto-library="${SSLLIB}" --host=${CHOST} --build=x86_64-pc-linux-gnu --enable-pkcs11 --disable-plugins || (cat config.log && exit 1)
	make -j${JOBS}
fi
