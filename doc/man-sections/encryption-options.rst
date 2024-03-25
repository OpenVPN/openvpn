Encryption Options
------------------

SSL Library information
```````````````````````

--show-ciphers
  (Standalone) Show all cipher algorithms to use with the ``--cipher``
  option.

--show-digests
  (Standalone) Show all message digest algorithms to use with the
  ``--auth`` option.

--show-tls
  (Standalone) Show all TLS ciphers supported by the crypto library.
  OpenVPN uses TLS to secure the control channel, over which the keys that
  are used to protect the actual VPN traffic are exchanged. The TLS
  ciphers will be sorted from highest preference (most secure) to lowest.

  Be aware that whether a cipher suite in this list can actually work
  depends on the specific setup of both peers (e.g. both peers must
  support the cipher, and an ECDSA cipher suite will not work if you are
  using an RSA certificate, etc.).

--show-engines
  (Standalone) Show currently available hardware-based crypto acceleration
  engines supported by the OpenSSL library.

--show-groups
  (Standalone) Show all available elliptic curves/groups to use with the
  ``--ecdh-curve`` and ``tls-groups`` options.

Generating key material
```````````````````````

--genkey args
  (Standalone) Generate a key to be used of the type keytype. if keyfile
  is left out or empty the key will be output on stdout. See the following
  sections for the different keytypes.

  Valid syntax:
  ::

     --genkey keytype keyfile

  Valid keytype arguments are:

  :code:`secret`                Standard OpenVPN shared secret keys

  :code:`tls-crypt`             Alias for :code:`secret`

  :code:`tls-auth`              Alias for :code:`secret`

  :code:`auth-token`            Key used for ``--auth-gen-token-key``

  :code:`tls-crypt-v2-server`   TLS Crypt v2 server key

  :code:`tls-crypt-v2-client`   TLS Crypt v2 client key


  Examples:
  ::

     $ openvpn --genkey secret shared.key
     $ openvpn --genkey tls-crypt shared.key
     $ openvpn --genkey tls-auth shared.key
     $ openvpn --genkey tls-crypt-v2-server v2crypt-server.key
     $ openvpn --tls-crypt-v2 v2crypt-server.key --genkey tls-crypt-v2-client v2crypt-client-1.key

  * Generating *Shared Secret Keys*
    Generate a shared secret, for use with the ``--secret``, ``--tls-auth``
    or ``--tls-crypt`` options.

    Syntax:
    ::

       $ openvpn --genkey secret|tls-crypt|tls-auth keyfile

    The key is saved in ``keyfile``. All three variants (``--secret``,
    ``tls-crypt`` and ``tls-auth``) generate the same type of key. The
    aliases are added for convenience.

    If using this for ``--secret``, this file must be shared with the peer
    over a pre-existing secure channel such as ``scp``\(1).

  * Generating *TLS Crypt v2 Server key*
    Generate a ``--tls-crypt-v2`` key to be used by an OpenVPN server.
    The key is stored in ``keyfile``.

    Syntax:
    ::

       --genkey tls-crypt-v2-server keyfile

  * Generating *TLS Crypt v2 Client key*
    Generate a --tls-crypt-v2 key to be used by OpenVPN clients.  The
    key is stored in ``keyfile``.

    Syntax
    ::

       --genkey tls-crypt-v2-client keyfile [metadata]

    If supplied, include the supplied ``metadata`` in the wrapped client
    key. This metadata must be supplied in base64-encoded form. The
    metadata must be at most 733 bytes long (980 characters in base64, though
    note that 980 base64 characters can encode more than 733 bytes).

    If no metadata is supplied, OpenVPN will use a 64-bit unix timestamp
    representing the current time in UTC, encoded in network order, as
    metadata for the generated key.

    A tls-crypt-v2 client key is wrapped using a server key. To generate a
    client key, the user must therefore supply the server key using the
    ``--tls-crypt-v2`` option.

    Servers can use ``--tls-crypt-v2-verify`` to specify a metadata
    verification command.

  * Generate *Authentication Token key*
    Generate a new secret that can be used with **--auth-gen-token-secret**

    Syntax:
    ::

       --genkey auth-token [keyfile]

    *Note:*
       This file should be kept secret to the server as anyone that has
       access to this file will be able to generate auth tokens that the
       OpenVPN server will accept as valid.

.. include:: renegotiation.rst
.. include:: tls-options.rst
.. include:: pkcs11-options.rst
