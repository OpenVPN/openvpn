#!/bin/sh

OPENSSL_CONF="${builddir}/openssl.cnf"
export OPENSSL_CONF

password='AT3S4PASSWD'

key="${builddir}/client.key"
pwdfile="${builddir}/passwd"

# create an engine key for us
sed 's/PRIVATE KEY/TEST ENGINE KEY/' < ${top_srcdir}/sample/sample-keys/client.key > ${key}
echo "$password" > $pwdfile

# our version of grep to output log.txt on failure in case it's an openssl
# error mismatch and the grep expression needs updating
loggrep() {
    egrep -q "$1" log.txt || { echo '---- begin log.txt ----'; cat log.txt; echo '--- end log.txt ---'; return 1; }
}

# note here we've induced a mismatch in the client key and the server
# cert which openvpn should report and die.  Check that it does.  Note
# also that this mismatch depends on openssl not openvpn, so it is
# somewhat fragile
${top_builddir}/src/openvpn/openvpn --cd ${top_srcdir}/sample --config sample-config-files/loopback-server --engine testengine --key ${key} --askpass $pwdfile > log.txt 2>&1

# first off check we died because of a key mismatch.  If this doesn't
# pass, suspect openssl of returning different messages and update the
# test accordingly
loggrep '(X509_check_private_key:key values mismatch|func\(128\):reason\(116\))' log.txt || { echo "Key mismatch not detected"; exit 1; }

# now look for the engine prints (these are under our control)
loggrep 'ENGINE: engine_init called' || { echo "Engine initialization not detected"; exit 1; }
loggrep 'ENGINE: engine_load_key called' || { echo "Key was not loaded from engine"; exit 1; }
loggrep "ENGINE: engine_load_key got password ${password}" || { echo "Key password was not retrieved by the engine"; exit 1; }
exit 0
