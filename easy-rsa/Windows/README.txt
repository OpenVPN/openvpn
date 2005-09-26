Extract all zip'd files to the OpenVPN home directory,
including the openssl.cnf file from the top-level
"easy-rsa" directory.

First run init-config.bat

Next, edit vars.bat to adapt it to your environment, and
create the directory that will hold your key files.

To generate TLS keys:

Create new empty index and serial files (once only)
1. vars
2. clean-all

Build a CA key (once only)
1. vars
2. build-ca

Build a DH file (for server side, once only)
1. vars
2. build-dh

Build a private key/certficate for the openvpn server
1. vars
2. build-key-server <machine-name>

Build key files in PEM format (for each client machine)
1. vars
2. build-key <machine-name>
   (use <machine name> for specific name within script)

or

Build key files in PKCS #12 format (for each client machine)
1. vars
2. build-key-pkcs12 <machine-name>
   (use <machine name> for specific name within script)

To revoke a TLS certificate and generate a CRL file:
1. vars
2. revoke-full <machine-name>
3. verify last line of output confirms revokation
4. copy crl.pem to server directory and ensure config file uses "crl-verify <crl filename>"
