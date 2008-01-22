F=pkcs11-helper-1.05
OPENSSL_DIR=`pwd`/openssl-0.9.7m

PKCS11_HELPER_DIR=`pwd`/pkcs11-helper
rm -rf $PKCS11_HELPER_DIR
mkdir $PKCS11_HELPER_DIR
tbz=$F.tar.bz2

rm -rf $F
tar xfj $tbz

cd $F
./configure \
	MAN2HTML=true \
	ac_cv_type_size_t=no \
	--disable-crypto-engine-gnutls \
        --disable-crypto-engine-nss \
        PKG_CONFIG=true \
        OPENSSL_CFLAGS="-I${OPENSSL_DIR}/include" \
        OPENSSL_LIBS="-L${OPENSSL_DIR}/out -lcrypto"

make
make install DESTDIR="${PKCS11_HELPER_DIR}"
