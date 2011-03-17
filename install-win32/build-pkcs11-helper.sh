F=pkcs11-helper-1.06-beta1
OPENSSL_DIR=`pwd`/openssl-0.9.8h

PKCS11_HELPER_DIR=`pwd`/pkcs11-helper
rm -rf $PKCS11_HELPER_DIR
mkdir $PKCS11_HELPER_DIR
tbz=$F.tar.bz2

rm -rf $F
tar xfj $tbz

cd $F
./configure \
	MAN2HTML=true \
	--disable-crypto-engine-gnutls \
        --disable-crypto-engine-nss \
        PKG_CONFIG=true \
        OPENSSL_CFLAGS="-I${OPENSSL_DIR}/include" \
        OPENSSL_LIBS="-L${OPENSSL_DIR}/out -leay32"

make
make install DESTDIR="${PKCS11_HELPER_DIR}"

# ./configure doesn't need this any more: ac_cv_type_size_t=no
