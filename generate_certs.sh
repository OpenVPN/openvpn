#!/usr/bin/env bash

# set PATH to find all binaries
PATH=$PATH:/sbin:/usr/sbin:/usr/local/bin:/usr/local/sbin
export TOPDIR=$(realpath $(dirname $0))
export PARMS="$@"

# Static defaults
LTHN_PREFIX=/home/lthn

# General usage help
usage() {
   echo 
   echo "To generate root CA with your own CA CN and password, and generate a VPN server certificate. Other options are optional if already having keys"
   echo $0 "--ca [--generate-ca] [--with-cn commonname] [--with-capass pass] [--generate-dh] [--generate_tls_auth]"
   echo
   echo "To generate root CA and server certificates using defaults"
   echo $0 "--defaults"
   echo
   exit
}

# Find command or report error. If env is already set, only test availability
# $1 - cmd
# $2 - env to get/set
# $3 - optional
findcmd() {
    local cmd="$1"
    local env="$2"
    eval "bin=\$$env"

    if [ -z "$bin" ]; then
        bin=$(PATH=$PATH:/usr/sbin which $cmd)
    fi

    if [ -z "$3" ]; then
      if [ -z "$bin" ]; then
        echo "Missing $cmd!"
      fi
    else
      if [ -z "$bin" ]; then
        echo "Not found $cmd"
      fi
    fi
    eval "$env=$bin"
}

defaults() {
    findcmd openvpn OPENVPN_BIN optional
    findcmd openssl OPENSSL_BIN
    findcmd sudo SUDO_BIN optional

}

summary() {
    echo
    if [ -z "$OPENSSL_BIN" ]; then
        echo "Missing openssl. Exiting."
        usage
        exit 1
    fi

    echo "Lethean VPN CA, Server Certificates, DH and TLS-Auth keys generated."
    echo "sudo bin:     $SUDO_BIN"
    echo "Openssl bin:  $OPENSSL_BIN"
    echo "Openvpn bin:  $OPENVPN_BIN"
    echo "Prefix:       $LTHN_PREFIX"
    echo "Conf dir:     $sysconf_dir"
    echo "CA dir:       $ca_dir"
    echo
}


# Specify configuration for root CA and how it is generated
generate_ca() {
    local prefix="$1"
    local cn="$2"
    echo "Generating CA $cn"
    cd $prefix || exit 2
    mkdir -p private certs csr newcerts || exit 2
    touch index.txt
    echo -n 00 >serial
    "${OPENSSL_BIN}" genrsa -aes256 -out private/ca.key.pem -passout pass:$cert_pass 4096
    chmod 400 private/ca.key.pem
    "${OPENSSL_BIN}" req -config $TOPDIR/openvpn/conf/ca.cfg -batch -subj "/CN=$cn" -passin pass:$cert_pass \
      -key private/ca.key.pem \
      -new -x509 -days 7300 -sha256 -extensions v3_ca \
      -out certs/ca.cert.pem
    if ! [ -f certs/ca.cert.pem ]; then
        echo "Error generating CA! See messages above."
        exit 2
    fi
}

# Specify how server keys are generated and signed with CA
generate_crt() {
    local name="$1"
    local cn="$2"
    echo "Generating crt (name=$name,cn=$cn)"
    "${OPENSSL_BIN}" genrsa -aes256 \
      -out private/$name.key.pem -passout pass:$cert_pass 4096
    chmod 400 private/$name.key.pem
    "${OPENSSL_BIN}" req -config $TOPDIR/openvpn/conf/ca.cfg -batch -subj "/CN=$cn" -passin "pass:$cert_pass" \
      -key private/$name.key.pem \
      -new -sha256 -out csr/$name.csr.pem
    "${OPENSSL_BIN}" ca -batch -config $TOPDIR/openvpn/conf/ca.cfg -subj "/CN=$cn" -passin "pass:$cert_pass" \
      -extensions server_cert -days 375 -notext -md sha256 \
      -in csr/$name.csr.pem \
      -out certs/$name.cert.pem
    (cat certs/ca.cert.pem certs/$name.cert.pem; openssl rsa -passin "pass:$cert_pass" -text <private/$name.key.pem) >certs/$name.all.pem
    (cat certs/$name.cert.pem; openssl rsa -passin "pass:$cert_pass" -text <private/$name.key.pem) >certs/$name.both.pem
    if ! [ -f certs/$name.cert.pem ]; then
        echo "Error generating cert $name! See messages above."
        exit 2
    fi
}

generate_env() {
    cat <<EOF
LTHN_PREFIX=$LTHN_PREFIX
OPENVPN_BIN=$OPENVPN_BIN
SUDO_BIN=$SUDO_BIN
OPENSSL_BIN=$OPENSSL_BIN

EOF
}

defaults

while [[ $# -gt 0 ]]; do
  key="$1"
  case $key in
    -h|--help)
        usage
    ;;
    --prefix)
        LTHN_PREFIX="$2"
        shift
        shift
    ;;
    --openssl-bin)
        OPENSSL_BIN="$2"
        shift
        shift
    ;;
    --sudo-bin)
        SUDO_BIN="$2"
        shift
        shift
    ;;
    --with-capass)
        cert_pass="$2"
        shift
        shift
    ;;
    --with-cn)
        cert_cn="$2"
        shift
        shift
    ;;
    --generate-ca)
        generate_ca=1
        shift
    ;;
    --generate-dh)
        generate_dh=1
        shift
    ;;
    --generate-tls-auth)
        generate_tls_auth=1
        shift
    ;;
    --ca)
        generate_ca=1
        cert_key_copy=1
        shift
    ;;
    --defaults)
        cert_pass="1234"
        cert_cn="Lethean VPN Server"
        generate_ca=1
        generate_dh=1
        generate_tls_auth=1
        cert_key_copy=1
        shift
    ;;
    *)
    echo "Unknown option $1"
    usage
    exit 1;
    ;;
esac
done

# Incomplete command message to user
if [ -z "$generate_ca" ]; then
    echo "You must select which parts to configure".
    $0 -h
    exit 1
fi

# Make directories for creation and moving generate keys
mkdir -p build/etc
mkdir -p etc/ca

# Where files will eventually live
sysconf_dir=${LTHN_PREFIX}/etc/
ca_dir=${LTHN_PREFIX}/etc/ca/

# Generate CA, sign server certificate and copy into desired folder
mkdir -p build
if [ -n "$generate_ca" ] && ! [ -f build/etc/ca/index.txt ]; then
    export cert_pass cert_cn
    if [ -z "$cert_pass" ] || [ -z "$cert_cn" ] ; then
        echo "You must specify --with-capass yourpassword --with_cn CN!"
        exit 2
    fi
    if [ "$cert_pass" = "1234" ]; then
    	echo "Generating with default password!"
    fi
    (
    rm -rf build/etc/ca
    mkdir -p build/etc/ca
    generate_ca build/etc/ca/ "$cert_cn"
    generate_crt openvpn "$cert_cn"
    )
fi

# Copy CA and signed certificates into desired folders
if [ -n "$cert_key_copy" ]; then
    if ! [ -f etc/ca/index.txt ]; then
        if [ -f ./build/etc/ca/index.txt ]; then
            cp -R build/etc/ca/* etc/ca/
        else
            echo "CA directory $LTHN_PREFIX/etc/ca/ not prepared! You should generate by configure or use your own CA!"
        fi
    fi
fi

# Generate and copy DH key to desired folder
if [ -n "$generate_dh" ]; then
    if ! [ -f build/etc/dhparam.pem ]; then 
        "$OPENSSL_BIN" dhparam -out build/etc/dhparam.pem 2048
        cp build/etc/dhparam.pem $LTHN_PREFIX/etc/
    fi
fi

# Generate and copy tls-auth key to desired folder
if [ -n "$generate_tls_auth" ]; then
    if ! [ -f build/etc/ca/ta.key ]; then 
      "$OPENVPN_BIN" --genkey secret build/etc/ta.key
      cp build/etc/ta.key $LTHN_PREFIX/etc/
    fi
fi

generate_env >env.mk
summary