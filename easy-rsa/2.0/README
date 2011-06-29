EASY-RSA Version 2.0-rc1

This is a small RSA key management package, based on the openssl
command line tool, that can be found in the easy-rsa subdirectory
of the OpenVPN distribution.  While this tool is primary concerned
with key management for the SSL VPN application space, it can also
be used for building web certificates.

These are reference notes.  For step-by-step instructions, see the
HOWTO:

http://openvpn.net/howto.html

This package is based on the ./pkitool script.  Run ./pkitool
without arguments for a detailed help message (which is also pasted
below).

Release Notes for easy-rsa-2.0

* Most functionality has been consolidated into the pkitool
  script. For compatibility, all previous scripts from 1.0 such
  as build-key and build-key-server are provided as stubs
  which call pkitool to do the real work.

* pkitool has a --batch flag (enabled by default) which generates
  keys/certs without needing any interactive input.  pkitool
  can still generate certs/keys using interactive prompting by
  using the --interact flag.

* The inherit-inter script has been provided for creating
  a new PKI rooted on an intermediate certificate built within a
  higher-level PKI.  See comments in the inherit-inter script
  for more info.

* The openssl.cnf file has been modified.  pkitool will not
  work with the openssl.cnf file included with previous
  easy-rsa releases.

* The vars file has been modified -- the following extra
  variables have been added: EASY_RSA, CA_EXPIRE,
  KEY_EXPIRE.

* The make-crl and revoke-crt scripts have been removed and
  are replaced by the revoke-full script.

* The "Organizational Unit" X509 field can be set using
  the KEY_OU environmental variable before calling pkitool.

* This release only affects the Linux/Unix version of easy-rsa.
  The Windows version (written to use the Windows shell) is unchanged.

* Use the revoke-full script to revoke a certificate, and generate
  (or update) the crl.pem file in the keys directory (as set by the
  vars script).  Then use "crl-verify crl.pem" in your OpenVPN server
  config file, so that OpenVPN can reject any connections coming from
  clients which present a revoked certificate.  Usage for the script is:

    revoke-full <common-name>

  Note this this procedure is primarily designed to revoke client
  certificates. You could theoretically use this method to revoke
  server certificates as well, but then you would need to propagate
  the crl.pem file to all clients as well, and have them include
  "crl-verify crl.pem" in their configuration files.

* PKCS#11 support was added.

* For those interested in using this tool to generate web certificates,
  A variant of the easy-rsa package that allows the creation of multi-domain
  certificates with subjectAltName can be obtained from here:

  http://www.bisente.com/proyectos/easy-rsa-subjectaltname/

INSTALL easy-rsa

1. Edit vars.
2. Set KEY_CONFIG to point to the correct openssl-<version>.cnf
   file included in this distribution.
3. Set KEY_DIR to point to a directory which will
   contain all keys, certificates, etc.  This
   directory need not exist, and if it does,
   it will be deleted with rm -rf, so BE
   CAREFUL how you set KEY_DIR.
4. (Optional) Edit other fields in vars
   per your site data.  You may want to
   increase KEY_SIZE to 2048 if you are
   paranoid and don't mind slower key
   processing, but certainly 1024 is
   fine for testing purposes.  KEY_SIZE
   must be compatible across both peers
   participating in a secure SSL/TLS
   connection.
5. (Optional) If you intend to use PKCS#11,
   install openssl >= 0.9.7, install the 
   following components from www.opensc.org:
   - opensc >= 0.10.0
   - engine_pkcs11 >= 0.1.3
   Update the openssl.cnf to load the engine:
   - Uncomment pkcs11 under engine_section.
   - Validate path at dynamic_path under pkcs11_section.
6. . vars
7. ./clean-all
8. As you create certificates, keys, and
   certificate signing requests, understand that
   only .key files should be kept confidential.
   .crt and .csr files can be sent over insecure
   channels such as plaintext email.

IMPORTANT

To avoid a possible Man-in-the-Middle attack where an authorized
client tries to connect to another client by impersonating the
server, make sure to enforce some kind of server certificate
verification by clients.  There are currently four different ways
of accomplishing this, listed in the order of preference:

(1) Build your server certificates with specific key usage and
    extended key usage. The RFC3280 determine that the following
    attributes should be provided for TLS connections:

    Mode      Key usage	                         Extended key usage
    ---------------------------------------------------------------------------
    Client    digitalSignature	                 TLS Web Client Authentication
              keyAgreement
              digitalSignature, keyAgreement
	      
    Server    digitalSignature, keyEncipherment  TLS Web Server Authentication
              digitalSignature, keyAgreement

    Now add the following line to your client configuration:
      
    remote-cert-tls server

    This will block clients from connecting to any
    server which lacks the required extension designation
    in its certificate, even if the certificate has been
    signed by the CA which is cited in the OpenVPN configuration
    file (--ca directive).

(3) Use the --tls-remote directive on the client to
    accept/reject the server connection based on the common
    name of the server certificate.

(3) Use a --tls-verify script or plugin to accept/reject the
    server connection based on a custom test of the server
    certificate's embedded X509 subject details.

(4) Sign server certificates with one CA and client certificates
    with a different CA.  The client config "ca" directive should
    reference the server-signing CA while the server config "ca"
    directive should reference the client-signing CA.

NOTES

Show certificate fields:
  openssl x509 -in cert.crt -text

PKITOOL documentation

pkitool 2.0
Usage: pkitool [options...] [common-name]
Options:
  --batch    : batch mode (default)
  --keysize  : Set keysize
      size   : size (default=1024)
  --interact : interactive mode
  --server   : build server cert
  --initca   : build root CA
  --inter    : build intermediate CA
  --pass     : encrypt private key with password
  --csr      : only generate a CSR, do not sign
  --sign     : sign an existing CSR
  --pkcs12   : generate a combined PKCS#12 file
  --pkcs11   : generate certificate on PKCS#11 token
      lib    : PKCS#11 library
      slot   : PKCS#11 slot
      id     : PKCS#11 object id (hex string)
      label  : PKCS#11 object label
Standalone options:
  --pkcs11-slots   : list PKCS#11 slots
      lib    : PKCS#11 library
  --pkcs11-objects : list PKCS#11 token objects
      lib    : PKCS#11 library
      slot   : PKCS#11 slot
  --pkcs11-init    : initialize PKCS#11 token DANGEROUS!!!
      lib    : PKCS#11 library
      slot   : PKCS#11 slot
      label  : PKCS#11 token label
Notes:
  Please edit the vars script to reflect your configuration,
  then source it with "source ./vars".
  Next, to start with a fresh PKI configuration and to delete any
  previous certificates and keys, run "./clean-all".
  Finally, you can run this tool (pkitool) to build certificates/keys.
  In order to use PKCS#11 interface you must have opensc-0.10.0 or higher.
Generated files and corresponding OpenVPN directives:
(Files will be placed in the $KEY_DIR directory, defined in ./vars)
  ca.crt     -> root certificate (--ca)
  ca.key     -> root key, keep secure (not directly used by OpenVPN)
  .crt files -> client/server certificates (--cert)
  .key files -> private keys, keep secure (--key)
  .csr files -> certificate signing request (not directly used by OpenVPN)
  dh1024.pem or dh2048.pem -> Diffie Hellman parameters (--dh)
Examples:
  pkitool --initca          -> Build root certificate
  pkitool --initca --pass   -> Build root certificate with password-protected key
  pkitool --server server1  -> Build "server1" certificate/key
  pkitool client1           -> Build "client1" certificate/key
  pkitool --pass client2    -> Build password-protected "client2" certificate/key
  pkitool --pkcs12 client3  -> Build "client3" certificate/key in PKCS#12 format
  pkitool --csr client4     -> Build "client4" CSR to be signed by another CA
  pkitool --sign client4    -> Sign "client4" CSR
  pkitool --inter interca   -> Build an intermediate key-signing certificate/key
                               Also see ./inherit-inter script.
  pkitool --pkcs11 /usr/lib/pkcs11/lib1 0 010203 "client5 id" client5
                              -> Build "client5" certificate/key in PKCS#11 token
Typical usage for initial PKI setup.  Build myserver, client1, and client2 cert/keys.
Protect client2 key with a password.  Build DH parms.  Generated files in ./keys :
  [edit vars with your site-specific info]
  source ./vars
  ./clean-all
  ./build-dh     -> takes a long time, consider backgrounding
  ./pkitool --initca
  ./pkitool --server myserver
  ./pkitool client1
  ./pkitool --pass client2
Typical usage for adding client cert to existing PKI:
  source ./vars
  ./pkitool client-new
