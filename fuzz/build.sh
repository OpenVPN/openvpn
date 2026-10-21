#!/bin/bash -eu
# Copyright 2021 Google LLC
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

OPENVPN_ROOT=${SRC}/openvpn
FUZZ_DIR=${OPENVPN_ROOT}/fuzz
BASE=${OPENVPN_ROOT}/src/openvpn

apply_sed_changes() {
  sed -i 's/read(/fuzz_read(/g' ${BASE}/console_systemd.c
  sed -i 's/fgets(/fuzz_fgets(/g' ${BASE}/console_builtin.c
  sed -i 's/fgets(/fuzz_fgets(/g' ${BASE}/misc.c
  sed -i 's/#include "forward.h"/#include "fuzz_header.h"\n#include "forward.h"/g' ${BASE}/proxy.c
  sed -i 's/openvpn_select(/fuzz_select(/g' ${BASE}/proxy.c
  sed -i 's/openvpn_send(/fuzz_send(/g' ${BASE}/proxy.c
  sed -i 's/recv(/fuzz_recv(/g' ${BASE}/proxy.c
  sed -i 's/isatty/fuzz_isatty/g' ${BASE}/console_builtin.c

  sed -i 's/fopen/fuzz_fopen/g' ${BASE}/console_builtin.c
  sed -i 's/fclose/fuzz_fclose/g' ${BASE}/console_builtin.c

  sed -i 's/sendto/fuzz_sendto/g' ${BASE}/socket.h
  sed -i 's/#include "misc.h"/#include "misc.h"\nextern size_t fuzz_sendto(int sockfd, void *buf, size_t len, int flags, struct sockaddr *dest_addr, socklen_t addrlen);/g' ${BASE}/socket.h

  sed -i 's/fp = (flags/fp = stdout;\n\/\//g' ${BASE}/error.c

  sed -i 's/crypto_msg(M_FATAL/crypto_msg(M_WARN/g' ${BASE}/crypto_openssl.c
  sed -i 's/msg(M_FATAL, \"Cipher/return;msg(M_FATAL, \"Cipher/g' ${BASE}/crypto.c
  sed -i 's/msg(M_FATAL/msg(M_WARN/g' ${BASE}/crypto.c

  sed -i 's/= write/= fuzz_write/g' ${BASE}/packet_id.c
}

echo "" >> ${BASE}/openvpn.c
echo "#include \"fake_fuzz_header.h\"" >> ${BASE}/openvpn.c
echo "ssize_t fuzz_get_random_data(void *buf, size_t len) { return 0; }" >> ${BASE}/fake_fuzz_header.h
echo "int fuzz_success;" >> ${BASE}/fake_fuzz_header.h

# Apply hooking changes
apply_sed_changes

# Copy corpuses out
zip -r $OUT/fuzz_verify_cert_seed_corpus.zip $SRC/boringssl/fuzz/cert_corpus

# Build openvpn
autoreconf -ivf
./configure --disable-lz4 --with-crypto-library=openssl OPENSSL_LIBS="-L/usr/local/ssl/ -lssl -lcrypto" OPENSSL_CFLAGS="-I/usr/local/ssl/include/"
make -j$(nproc)

# Make openvpn object files into a library we can link fuzzers to
cd src/openvpn
rm openvpn.o
ar r libopenvpn.a *.o

# Compile our fuzz helper
$CXX $CXXFLAGS -g -c ${FUZZ_DIR}/fuzz_randomizer.cpp -o ${FUZZ_DIR}/fuzz_randomizer.o

# Compile the fuzzers
for fuzzname in dhcp misc base64 proxy buffer route packet_id mroute list verify_cert; do
    $CC -DHAVE_CONFIG_H -I. -I../.. -I../../include -I../../src/compat -I/usr/include/libnl3/ \
      -DPLUGIN_LIBDIR=\"/usr/local/lib/openvpn/plugins\" -std=c99 $CFLAGS \
      -c ${FUZZ_DIR}/fuzz_${fuzzname}.c -o ${FUZZ_DIR}/fuzz_${fuzzname}.o

    # Link with CXX
    $CXX ${CXXFLAGS} ${LIB_FUZZING_ENGINE} $FUZZ_DIR/fuzz_${fuzzname}.o -o $OUT/fuzz_${fuzzname} $FUZZ_DIR/fuzz_randomizer.o \
        libopenvpn.a ../../src/compat/.libs/libcompat.a /usr/lib/x86_64-linux-gnu/libnsl.a \
        /usr/lib/x86_64-linux-gnu/libresolv.a /usr/lib/x86_64-linux-gnu/liblzo2.a \
        -lssl -lcrypto -ldl -l:libnl-3.a -l:libnl-genl-3.a -lcap-ng -pthread
done
