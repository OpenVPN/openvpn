# -*- mode: sh -*-
# vi: set ft=sh :
#!/bin/bash

#
# - Expects the source to be located at "~/openvpn"
# - Must be run as root
# - Expects a t_client.rc to be present
#

cd ~vagrant/openvpn/tests

# Look for t_client.rc in the same locations t_client.sh does

srcdir="${srcdir:-.}"
top_builddir="${top_builddir:-..}"
if [ -r "${top_builddir}"/t_client.rc ] ; then
    . "${top_builddir}"/t_client.rc
elif [ -r "${srcdir}"/t_client.rc ] ; then
    . "${srcdir}"/t_client.rc
else
    echo "$0: cannot find 't_client.rc' in build dir ('${top_builddir}')" >&2
    echo "$0: or source directory ('${srcdir}'). SKIPPING TEST." >&2
    exit 77
fi

CA_CERT="${CA_CERT:-${top_srcdir}/sample/sample-keys/ca.crt}"
CLIENT_KEY="${CLIENT_KEY:-${top_srcdir}/sample/sample-keys/client.key}"
CLIENT_CERT="${CLIENT_CERT:-${top_srcdir}/sample/sample-keys/client.crt}"

VM_SERVER_KEY="${VM_SERVER_KEY:-${top_srcdir}/sample/sample-keys/server.key}"
VM_SERVER_CERT="${VM_SERVER_CERT:-${top_srcdir}/sample/sample-keys/server.crt}"
VM_SERVER_DH="${VM_SERVER_DH:-${top_srcdir}/sample/sample-keys//dh2048.pem}"


assert_var_set() {
  local varname="$1"
  local value=
  eval value=\$$varname

  if [ -n "${value}" ]; then
     echo " - $varname  := '${value}'"
  else
     echo "$varname not defined in 't_client.rc'. abort." >&2
     exit 77
  fi
}

assert_var_set CA_CERT
assert_var_set VM_SERVER_KEY
assert_var_set VM_SERVER_CERT
assert_var_set VM_SERVER_DH
assert_var_set VM_SERVER_NET
assert_var_set VM_SERVER_MASK
assert_var_set REMOTE_PORT


OPENVPN="${top_builddir}/src/openvpn/openvpn"

if [ ! -x "${OPENVPN}" ] ;  then
    echo "openvpn not found at '${OPENVPN}'" >&2
    exit 77
fi

SERVER="$VM_SERVER_NET $VM_SERVER_MASK"

# Bind to all adresses
LOCAL="0.0.0.0"

CMD="\"${OPENVPN}\" \
 --mode server \
 --dev tun \
 --tls-server \
 --dh \"${VM_SERVER_DH}\" \
 --ca \"${CA_CERT}\" \
 --cert \"${VM_SERVER_CERT}\" \
 --key \"${VM_SERVER_KEY}\" \
 --server ${SERVER} \
 --local  ${LOCAL} \
 --port   ${REMOTE_PORT} \
 --topology subnet \
 --comp-lzo \
 --management ${LOCAL} 7505 \
 --verb 3 \
"

echo $CMD
eval $CMD
