TLS Mode Options
````````````````

TLS mode is the most powerful crypto mode of OpenVPN in both security
and flexibility. TLS mode works by establishing control and data
channels which are multiplexed over a single TCP/UDP port. OpenVPN
initiates a TLS session over the control channel and uses it to exchange
cipher and HMAC keys to protect the data channel. TLS mode uses a robust
reliability layer over the UDP connection for all control channel
communication, while the data channel, over which encrypted tunnel data
passes, is forwarded without any mediation. The result is the best of
both worlds: a fast data channel that forwards over UDP with only the
overhead of encrypt, decrypt, and HMAC functions, and a control channel
that provides all of the security features of TLS, including
certificate-based authentication and Diffie Hellman forward secrecy.

To use TLS mode, each peer that runs OpenVPN should have its own local
certificate/key pair (``--cert`` and ``--key``), signed by the root
certificate which is specified in ``--ca``.

When two OpenVPN peers connect, each presents its local certificate to
the other. Each peer will then check that its partner peer presented a
certificate which was signed by the master root certificate as specified
in ``--ca``.

If that check on both peers succeeds, then the TLS negotiation will
succeed, both OpenVPN peers will exchange temporary session keys, and
the tunnel will begin passing data.

The OpenVPN project provides a set of scripts for managing RSA
certificates and keys: https://github.com/OpenVPN/easy-rsa

--askpass file
  Get certificate password from console or ``file`` before we daemonize.

  Valid syntaxes:
  ::

     askpass
     askpass file

  For the extremely security conscious, it is possible to protect your
  private key with a password. Of course this means that every time the
  OpenVPN daemon is started you must be there to type the password. The
  ``--askpass`` option allows you to start OpenVPN from the command line.
  It will query you for a password before it daemonizes. To protect a
  private key with a password you should omit the ``-nodes`` option when
  you use the ``openssl`` command line tool to manage certificates and
  private keys.

  If ``file`` is specified, read the password from the first line of
  ``file``. Keep in mind that storing your password in a file to a certain
  extent invalidates the extra security provided by using an encrypted
  key.

--ca file
  Certificate authority (CA) file in .pem format, also referred to as the
  *root* certificate. This file can have multiple certificates in .pem
  format, concatenated together. You can construct your own certificate
  authority certificate and private key by using a command such as:
  ::

     openssl req -nodes -new -x509 -keyout ca.key -out ca.crt

  Then edit your openssl.cnf file and edit the ``certificate`` variable to
  point to your new root certificate ``ca.crt``.

  For testing purposes only, the OpenVPN distribution includes a sample CA
  certificate (ca.crt). Of course you should never use the test
  certificates and test keys distributed with OpenVPN in a production
  environment, since by virtue of the fact that they are distributed with
  OpenVPN, they are totally insecure.

--capath dir
  Directory containing trusted certificates (CAs and CRLs). Not available
  with mbed TLS.

  CAs in the capath directory are expected to be named <hash>.<n>. CRLs
  are expected to be named <hash>.r<n>. See the ``-CApath`` option of
  ``openssl verify``, and the ``-hash`` option of ``openssl x509``,
  ``openssl crl`` and ``X509_LOOKUP_hash_dir()``\(3)
  for more information.

  Similar to the ``--crl-verify`` option, CRLs are not mandatory -
  OpenVPN will log the usual warning in the logs if the relevant CRL is
  missing, but the connection will be allowed.

--cert file
  Local peer's signed certificate in .pem format -- must be signed by a
  certificate authority whose certificate is in ``--ca file``. Each peer
  in an OpenVPN link running in TLS mode should have its own certificate
  and private key file. In addition, each certificate should have been
  signed by the key of a certificate authority whose public key resides in
  the ``--ca`` certificate authority file. You can easily make your own
  certificate authority (see above) or pay money to use a commercial
  service such as thawte.com (in which case you will be helping to finance
  the world's second space tourist :). To generate a certificate, you can
  use a command such as:
  ::

     openssl req -nodes -new -keyout mycert.key -out mycert.csr

  If your certificate authority private key lives on another machine, copy
  the certificate signing request (mycert.csr) to this other machine (this
  can be done over an insecure channel such as email). Now sign the
  certificate with a command such as:
  ::

     openssl ca -out mycert.crt -in mycert.csr

  Now copy the certificate (mycert.crt) back to the peer which initially
  generated the .csr file (this can be over a public medium). Note that
  the ``openssl ca`` command reads the location of the certificate
  authority key from its configuration file such as
  :code:`/usr/share/ssl/openssl.cnf` -- note also that for certificate
  authority functions, you must set up the files :code:`index.txt` (may be
  empty) and :code:`serial` (initialize to :code:`01`).

--crl-verify args
  Check peer certificate against a Certificate Revocation List.

  Valid syntax:
  ::

     crl-verify file/directory flag

  Examples:
  ::

     crl-verify crl-file.pem
     crl-verify /etc/openvpn/crls dir

  A CRL (certificate revocation list) is used when a particular key is
  compromised but when the overall PKI is still intact.

  Suppose you had a PKI consisting of a CA, root certificate, and a number
  of client certificates. Suppose a laptop computer containing a client
  key and certificate was stolen. By adding the stolen certificate to the
  CRL file, you could reject any connection which attempts to use it,
  while preserving the overall integrity of the PKI.

  The only time when it would be necessary to rebuild the entire PKI from
  scratch would be if the root certificate key itself was compromised.

  The option is not mandatory - if the relevant CRL is missing, OpenVPN
  will log a warning in the logs - e.g.
  ::

     VERIFY WARNING: depth=0, unable to get certificate CRL

  but the connection will be allowed.  If the optional :code:`dir` flag
  is specified, enable a different mode where the ``crl-verify`` is
  pointed at a directory containing files named as revoked serial numbers
  (the files may be empty, the contents are never read). If a client
  requests a connection, where the client certificate serial number
  (decimal string) is the name of a file present in the directory, it will
  be rejected.

  *Note:*
            As the crl file (or directory) is read every time a peer
            connects, if you are dropping root privileges with
            ``--user``, make sure that this user has sufficient
            privileges to read the file.


--dh file
  File containing Diffie Hellman parameters in .pem format (required for
  ``--tls-server`` only).

  Set ``file`` to :code:`none` to disable Diffie Hellman key exchange (and
  use ECDH only). Note that this requires peers to be using an SSL library
  that supports ECDH TLS cipher suites (e.g. OpenSSL 1.0.1+, or
  mbed TLS 2.0+).

  Use ``openssl dhparam -out dh2048.pem 2048`` to generate 2048-bit DH
  parameters. Diffie Hellman parameters may be considered public.

--ecdh-curve name
  Specify the curve to use for elliptic curve Diffie Hellman. Available
  curves can be listed with ``--show-curves``. The specified curve will
  only be used for ECDH TLS-ciphers.

  This option is not supported in mbed TLS builds of OpenVPN.

--extra-certs file
  Specify a ``file`` containing one or more PEM certs (concatenated
  together) that complete the local certificate chain.

  This option is useful for "split" CAs, where the CA for server certs is
  different than the CA for client certs. Putting certs in this file
  allows them to be used to complete the local certificate chain without
  trusting them to verify the peer-submitted certificate, as would be the
  case if the certs were placed in the ``ca`` file.

--hand-window n
  Handshake Window -- the TLS-based key exchange must finalize within
  ``n`` seconds of handshake initiation by any peer (default :code:`60`
  seconds). If the handshake fails we will attempt to reset our connection
  with our peer and try again. Even in the event of handshake failure we
  will still use our expiring key for up to ``--tran-window`` seconds to
  maintain continuity of transmission of tunnel data.

  The ``--hand-window`` parameter also controls the amount of time that
  the OpenVPN client repeats the pull request until it times out.

--key file
  Local peer's private key in .pem format. Use the private key which was
  generated when you built your peer's certificate (see ``--cert file``
  above).

--pkcs12 file
  Specify a PKCS #12 file containing local private key, local certificate,
  and root CA certificate. This option can be used instead of ``--ca``,
  ``--cert``, and ``--key``.  Not available with mbed TLS.

--remote-cert-eku oid
  Require that peer certificate was signed with an explicit *extended key
  usage*.

  This is a useful security option for clients, to ensure that the host
  they connect to is a designated server.

  The extended key usage should be encoded in *oid notation*, or *OpenSSL
  symbolic representation*.

--remote-cert-ku key-usage
  Require that peer certificate was signed with an explicit
  ``key-usage``.

  If present in the certificate, the :code:`keyUsage` value is validated by
  the TLS library during the TLS handshake. Specifying this option without
  arguments requires this extension to be present (so the TLS library will
  verify it).

  If ``key-usage`` is a list of usage bits, the :code:`keyUsage` field
  must have *at least* the same bits set as the bits in *one of* the values
  supplied in the ``key-usage`` list.

  The ``key-usage`` values in the list must be encoded in hex, e.g.
  ::

     remote-cert-ku a0

--remote-cert-tls type
  Require that peer certificate was signed with an explicit *key usage*
  and *extended key usage* based on RFC3280 TLS rules.

  Valid syntaxes:
  ::

     remote-cert-tls server
     remote-cert-tls client

  This is a useful security option for clients, to ensure that the host
  they connect to is a designated server. Or the other way around; for a
  server to verify that only hosts with a client certificate can connect.

  The ``--remote-cert-tls client`` option is equivalent to
  ::

     remote-cert-ku
     remote-cert-eku "TLS Web Client Authentication"

  The ``--remote-cert-tls server`` option is equivalent to
  ::

     remote-cert-ku
     remote-cert-eku "TLS Web Server Authentication"

  This is an important security precaution to protect against a
  man-in-the-middle attack where an authorized client attempts to connect
  to another client by impersonating the server. The attack is easily
  prevented by having clients verify the server certificate using any one
  of ``--remote-cert-tls``, ``--verify-x509-name``, ``--peer-fingerprint``
  or ``--tls-verify``.

--tls-auth args
  Add an additional layer of HMAC authentication on top of the TLS control
  channel to mitigate DoS attacks and attacks on the TLS stack.

  Valid syntaxes:
  ::

     tls-auth file
     tls-auth file 0
     tls-auth file 1

  In a nutshell, ``--tls-auth`` enables a kind of "HMAC firewall" on
  OpenVPN's TCP/UDP port, where TLS control channel packets bearing an
  incorrect HMAC signature can be dropped immediately without response.

  ``file`` (required) is a file in OpenVPN static key format which can be
  generated by ``--genkey``.

  Older versions (up to OpenVPN 2.3) supported a freeform passphrase file.
  This is no longer supported in newer versions (v2.4+).

  See the ``--secret`` option for more information on the optional
  ``direction`` parameter.

  ``--tls-auth`` is recommended when you are running OpenVPN in a mode
  where it is listening for packets from any IP address, such as when
  ``--remote`` is not specified, or ``--remote`` is specified with
  ``--float``.

  The rationale for this feature is as follows. TLS requires a
  multi-packet exchange before it is able to authenticate a peer. During
  this time before authentication, OpenVPN is allocating resources (memory
  and CPU) to this potential peer. The potential peer is also exposing
  many parts of OpenVPN and the OpenSSL library to the packets it is
  sending. Most successful network attacks today seek to either exploit
  bugs in programs (such as buffer overflow attacks) or force a program to
  consume so many resources that it becomes unusable. Of course the first
  line of defense is always to produce clean, well-audited code. OpenVPN
  has been written with buffer overflow attack prevention as a top
  priority. But as history has shown, many of the most widely used network
  applications have, from time to time, fallen to buffer overflow attacks.

  So as a second line of defense, OpenVPN offers this special layer of
  authentication on top of the TLS control channel so that every packet on
  the control channel is authenticated by an HMAC signature and a unique
  ID for replay protection. This signature will also help protect against
  DoS (Denial of Service) attacks. An important rule of thumb in reducing
  vulnerability to DoS attacks is to minimize the amount of resources a
  potential, but as yet unauthenticated, client is able to consume.

  ``--tls-auth`` does this by signing every TLS control channel packet
  with an HMAC signature, including packets which are sent before the TLS
  level has had a chance to authenticate the peer. The result is that
  packets without the correct signature can be dropped immediately upon
  reception, before they have a chance to consume additional system
  resources such as by initiating a TLS handshake. ``--tls-auth`` can be
  strengthened by adding the ``--replay-persist`` option which will keep
  OpenVPN's replay protection state in a file so that it is not lost
  across restarts.

  It should be emphasized that this feature is optional and that the key
  file used with ``--tls-auth`` gives a peer nothing more than the power
  to initiate a TLS handshake. It is not used to encrypt or authenticate
  any tunnel data.

  Use ``--tls-crypt`` instead if you want to use the key file to not only
  authenticate, but also encrypt the TLS control channel.

--tls-groups list
    A list of allowable groups/curves in order of preference.

    Set the allowed elliptic curves/groups for the TLS session.
    These groups are allowed to be used in signatures and key exchange.

    mbedTLS currently allows all known curves per default.

    OpenSSL 1.1+ restricts the list per default to
    ::

      "X25519:secp256r1:X448:secp521r1:secp384r1".

    If you use certificates that use non-standard curves, you
    might need to add them here. If you do not force the ecdh curve
    by using ``--ecdh-curve``, the groups for ecdh will also be picked
    from this list.

    OpenVPN maps the curve name `secp256r1` to `prime256v1` to allow
    specifying the same tls-groups option for mbedTLS and OpenSSL.

    Warning: this option not only affects elliptic curve certificates
    but also the key exchange in TLS 1.3 and using this option improperly
    will disable TLS 1.3.

--tls-cert-profile profile
  Set the allowed cryptographic algorithms for certificates according to
  ``profile``.

  The following profiles are supported:

  :code:`insecure`
      Identical for mbed TLS to `legacy`

  :code:`legacy` (default)
      SHA1 and newer, RSA 2048-bit+, any elliptic curve.

  :code:`preferred`
      SHA2 and newer, RSA 2048-bit+, any elliptic curve.

  :code:`suiteb`
      SHA256/SHA384, ECDSA with P-256 or P-384.

  This option is only fully supported for mbed TLS builds. OpenSSL builds
  use the following approximation:

  :code:`insecure`
      sets "security level 0"

  :code:`legacy` (default)
      sets "security level 1"

  :code:`preferred`
      sets "security level 2"

  :code:`suiteb`
      sets "security level 3" and ``--tls-cipher "SUITEB128"``.

  OpenVPN will migrate to 'preferred' as default in the future. Please
  ensure that your keys already comply.

*WARNING:* ``--tls-ciphers``, ``--tls-ciphersuites`` and ``tls-groups``
    These options are expert features, which - if used correctly - can
    improve the security of your VPN connection. But it is also easy to
    unwittingly use them to carefully align a gun with your foot, or just
    break your connection. Use with care!

--tls-cipher l
  A list ``l`` of allowable TLS ciphers delimited by a colon (":code:`:`").

  These setting can be used to ensure that certain cipher suites are used
  (or not used) for the TLS connection. OpenVPN uses TLS to secure the
  control channel, over which the keys that are used to protect the actual
  VPN traffic are exchanged.

  The supplied list of ciphers is (after potential OpenSSL/IANA name
  translation) simply supplied to the crypto library. Please see the
  OpenSSL and/or mbed TLS documentation for details on the cipher list
  interpretation.

  For OpenSSL, the ``--tls-cipher`` is used for TLS 1.2 and below.

  Use ``--show-tls`` to see a list of TLS ciphers supported by your crypto
  library.

  The default for ``--tls-cipher`` is to use mbed TLS's default cipher list
  when using mbed TLS or
  :code:`DEFAULT:!EXP:!LOW:!MEDIUM:!kDH:!kECDH:!DSS:!PSK:!SRP:!kRSA` when
  using OpenSSL.

--tls-ciphersuites l
  Same as ``--tls-cipher`` but for TLS 1.3 and up. mbed TLS has no
  TLS 1.3 support yet and only the ``--tls-cipher`` setting is used.

  The default for `--tls-ciphersuites` is to use the crypto library's
  default.

--tls-client
  Enable TLS and assume client role during TLS handshake.

--tls-crypt keyfile
  Encrypt and authenticate all control channel packets with the key from
  ``keyfile``. (See ``--tls-auth`` for more background.)

  Encrypting (and authenticating) control channel packets:

  * provides more privacy by hiding the certificate used for the TLS
    connection,

  * makes it harder to identify OpenVPN traffic as such,

  * provides "poor-man's" post-quantum security, against attackers who will
    never know the pre-shared key (i.e. no forward secrecy).

  In contrast to ``--tls-auth``, ``--tls-crypt`` does *not* require the
  user to set ``--key-direction``.

  **Security Considerations**

  All peers use the same ``--tls-crypt`` pre-shared group key to
  authenticate and encrypt control channel messages. To ensure that IV
  collisions remain unlikely, this key should not be used to encrypt more
  than 2^48 client-to-server or 2^48 server-to-client control channel
  messages. A typical initial negotiation is about 10 packets in each
  direction. Assuming both initial negotiation and renegotiations are at
  most 2^16 (65536) packets (to be conservative), and (re)negotiations
  happen each minute for each user (24/7), this limits the tls-crypt key
  lifetime to 8171 years divided by the number of users. So a setup with
  1000 users should rotate the key at least once each eight years. (And a
  setup with 8000 users each year.)

  If IV collisions were to occur, this could result in the security of
  ``--tls-crypt`` degrading to the same security as using ``--tls-auth``.
  That is, the control channel still benefits from the extra protection
  against active man-in-the-middle-attacks and DoS attacks, but may no
  longer offer extra privacy and post-quantum security on top of what TLS
  itself offers.

  For large setups or setups where clients are not trusted, consider using
  ``--tls-crypt-v2`` instead. That uses per-client unique keys, and
  thereby improves the bounds to 'rotate a client key at least once per
  8000 years'.

--tls-crypt-v2 keyfile

  Valid syntax::

     tls-crypt-v2 keyfile
     tls-crypt-v2 keyfile force-cookie
     tls-crypt-v2 keyfile allow-noncookie

  Use client-specific tls-crypt keys.

  For clients, ``keyfile`` is a client-specific tls-crypt key. Such a key
  can be generated using the :code:`--genkey tls-crypt-v2-client` option.

  For servers, ``keyfile`` is used to unwrap client-specific keys supplied
  by the client during connection setup. This key must be the same as the
  key used to generate the client-specific key (see :code:`--genkey
  tls-crypt-v2-client`).

  On servers, this option can be used together with the ``--tls-auth`` or
  ``--tls-crypt`` option. In that case, the server will detect whether the
  client is using client-specific keys, and automatically select the right
  mode.

  The optional parameters :code:`force-cookie` allows only tls-crypt-v2
  clients that support a cookie based stateless three way handshake that
  avoids replay attacks and state exhaustion on the server side (OpenVPN
  2.6 and later). The option :code:`allow-noncookie` explicitly allows
  older tls-crypt-v2 clients. The default is (currently)
  :code:`allow-noncookie`.

--tls-crypt-v2-verify cmd
  Run command ``cmd`` to verify the metadata of the client-specific
  tls-crypt-v2 key of a connecting client. This allows server
  administrators to reject client connections, before exposing the TLS
  stack (including the notoriously dangerous X.509 and ASN.1 stacks) to
  the connecting client.

  OpenVPN supplies the following environment variables to the command (and
  only these variables. The normal environment variables available for
  other scripts are NOT present):

  * :code:`script_type` is set to :code:`tls-crypt-v2-verify`

  * :code:`metadata_type` is set to :code:`0` if the metadata was user
    supplied, or :code:`1` if it's a 64-bit unix timestamp representing
    the key creation time.

  * :code:`metadata_file` contains the filename of a temporary file that
    contains the client metadata.

  The command can reject the connection by exiting with a non-zero exit
  code.

--tls-exit
  Exit on TLS negotiation failure. This option can be useful when you only
  want to make one attempt at connecting, e.g. in a test or monitoring script.
  (OpenVPN's own test suite uses it this way.)

--tls-server
  Enable TLS and assume server role during TLS handshake. Note that
  OpenVPN is designed as a peer-to-peer application. The designation of
  client or server is only for the purpose of negotiating the TLS control
  channel.

--tls-timeout n
  Packet retransmit timeout on TLS control channel if no acknowledgment
  from remote within ``n`` seconds (default :code:`2`). When OpenVPN sends
  a control packet to its peer, it will expect to receive an
  acknowledgement within ``n`` seconds or it will retransmit the packet,
  subject to a TCP-like exponential backoff algorithm. This parameter only
  applies to control channel packets. Data channel packets (which carry
  encrypted tunnel data) are never acknowledged, sequenced, or
  retransmitted by OpenVPN because the higher level network protocols
  running on top of the tunnel such as TCP expect this role to be left to
  them.

--tls-version-min args
  Sets the minimum TLS version we will accept from the peer (default in
  2.6.0 and later is "1.2").

  Valid syntax:
  ::

     tls-version-min version ['or-highest']

  Examples for version include :code:`1.0`, :code:`1.1`, or :code:`1.2`. If
  :code:`or-highest` is specified and version is not recognized, we will
  only accept the highest TLS version supported by the local SSL
  implementation.

--tls-version-max version
  Set the maximum TLS version we will use (default is the highest version
  supported). Examples for version include :code:`1.0`, :code:`1.1`, or
  :code:`1.2`.

--verify-hash args
  **DEPRECATED** Specify SHA1 or SHA256 fingerprint for level-1 cert.

  Valid syntax:
  ::

     verify-hash hash [algo]

  The level-1 cert is the CA (or intermediate cert) that signs the leaf
  certificate, and is one removed from the leaf certificate in the
  direction of the root. When accepting a connection from a peer, the
  level-1 cert fingerprint must match ``hash`` or certificate verification
  will fail. Hash is specified as XX:XX:... For example:
  ::

     AD:B0:95:D8:09:C8:36:45:12:A9:89:C8:90:09:CB:13:72:A6:AD:16

  The ``algo`` flag can be either :code:`SHA1` or :code:`SHA256`. If not
  provided, it defaults to :code:`SHA1`.

  This option can also be inlined
  ::

    <verify-hash>
    00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff
    11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00
    </verify-hash>

If the option is inlined, ``algo`` is always :code:`SHA256`.

--peer-fingerprint args
   Specify a SHA256 fingerprint or list of SHA256 fingerprints to verify
   the peer certificate against. The peer certificate must match one of the
   fingerprint or certificate verification will fail. The option can also
   be inlined

  Valid syntax:
  ::

    peer-fingerprint AD:B0:95:D8:09:...

  or inline:
  ::

    <peer-fingerprint>
    00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff
    11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00
    </peer-fingerprint>

  When the ``--peer-fingerprint`` option is used, specifying a CA with ``--ca`` or ``--capath`` is
  optional. This allows the he ``--peer-fingerprint`` to be used as alternative to a PKI with
  self-signed certificates for small setups. See the examples section for such a setup.

--verify-x509-name args
  Accept connections only if a host's X.509 name is equal to **name.** The
  remote host must also pass all other tests of verification.

  Valid syntax:
  ::

     verify-x509 name type

  Which X.509 name is compared to ``name`` depends on the setting of type.
  ``type`` can be :code:`subject` to match the complete subject DN
  (default), :code:`name` to match a subject RDN or :code:`name-prefix` to
  match a subject RDN prefix. Which RDN is verified as name depends on the
  ``--x509-username-field`` option. But it defaults to the common name
  (CN), e.g. a certificate with a subject DN
  ::

     C=KG, ST=NA, L=Bishkek, CN=Server-1

  would be matched by:
  ::

     verify-x509-name 'C=KG, ST=NA, L=Bishkek, CN=Server-1'
     verify-x509-name Server-1 name
     verify-x509-name Server- name-prefix

  The last example is useful if you want a client to only accept
  connections to :code:`Server-1`, :code:`Server-2`, etc.

  ``--verify-x509-name`` is a useful replacement for the ``--tls-verify``
  option to verify the remote host, because ``--verify-x509-name`` works
  in a ``--chroot`` environment without any dependencies.

  Using a name prefix is a useful alternative to managing a CRL
  (Certificate Revocation List) on the client, since it allows the client
  to refuse all certificates except for those associated with designated
  servers.

  *NOTE:*
      Test against a name prefix only when you are using OpenVPN
      with a custom CA certificate that is under your control. Never use
      this option with type :code:`name-prefix` when your client
      certificates are signed by a third party, such as a commercial
      web CA.

--x509-track attribute
  Save peer X509 **attribute** value in environment for use by plugins and
  management interface. Prepend a :code:`+` to ``attribute`` to save values
  from full cert chain. Otherwise the attribute will only be exported for
  the leaf cert (i.e. depth :code:`0` of the cert chain). Values will be
  encoded as :code:`X509_<depth>_<attribute>=<value>`. Multiple ``--x509-track``
  options can be defined to track multiple attributes.

  ``attribute`` can be any part of the X509 Subject field or any X509v3
  extension (RFC 3280). X509v3 extensions might not be supported when
  not using the default TLS backend library (OpenSSL). You can also
  request the ``SHA1`` and ``SHA256`` fingerprints of the cert,
  but that is always exported as :code:`tls_digest_{n}` and
  :code:`tls_digest_sha256_{n}` anyway.

  Note that by default **all** parts of the X509 Subject field are exported in
  the environment for the whole cert chain. If you use ``--x509-track`` at least
  once **only** the attributes specified by these options are exported.

  Examples::

    x509-track CN               # exports only X509_0_CN
    x509-track +CN              # exports X509_{n}_CN for chain
    x509-track basicConstraints # exports value of "X509v3 Basic Constraints"
    x509-track SHA256           # exports SHA256 fingerprint

--x509-username-field args
  Fields in the X.509 certificate subject to be used as the username
  (default :code:`CN`). If multiple fields are specified their values
  will be concatenated into the one username using :code:`_` symbol
  as a separator.

  Valid syntax:
  ::

     x509-username-field [ext:]fieldname [[ext:]fieldname...]

  Typically, this option is specified with **fieldname** arguments as
  either of the following:
  ::

     x509-username-field emailAddress
     x509-username-field ext:subjectAltName
     x509-username-field CN serialNumber

  The first example uses the value of the :code:`emailAddress` attribute
  in the certificate's Subject field as the username. The second example
  uses the :code:`ext:` prefix to signify that the X.509 extension
  ``fieldname`` :code:`subjectAltName` be searched for an rfc822Name
  (email) field to be used as the username. In cases where there are
  multiple email addresses in :code:`ext:fieldname`, the last occurrence
  is chosen. The last example uses the value of the :code:`CN` attribute
  in the Subject field, combined with the :code:`_` separator and the
  hexadecimal representation of the certificate's :code:`serialNumber`.

  When this option is used, the ``--verify-x509-name`` option will match
  against the chosen ``fieldname`` instead of the Common Name.

  Only the :code:`subjectAltName` and :code:`issuerAltName` X.509
  extensions and :code:`serialNumber` X.509 attribute are supported.

  **Please note:** This option has a feature which will convert an
  all-lowercase ``fieldname`` to uppercase characters, e.g.,
  :code:`ou` -> :code:`OU`. A mixed-case ``fieldname`` or one having the
  :code:`ext:` prefix will be left as-is. This automatic upcasing feature is
  deprecated and will be removed in a future release.

  Non-compliant symbols are being replaced with the :code:`_` symbol, same as
  the field separator, so concatenating multiple fields with such or :code:`_`
  symbols can potentially lead to username collisions.
