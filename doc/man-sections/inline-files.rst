INLINE FILE SUPPORT
===================

OpenVPN allows including files in the main configuration for the ``--ca``,
``--cert``, ``--dh``, ``--extra-certs``, ``--key``, ``--pkcs12``,
``--crl-verify``, ``--http-proxy-user-pass``, ``--tls-auth``,
``--auth-gen-token-secret``, ``--peer-fingerprint``, ``--tls-crypt``,
``--tls-crypt-v2``, ``--verify-hash`` and ``--auth-user-pass`` options.

Each inline file started by the line ``<option>`` and ended by the line
``</option>``

Here is an example of an inline file usage

::

    <cert>
    -----BEGIN CERTIFICATE-----
    [...]
    -----END CERTIFICATE-----
    </cert>

When using the inline file feature with ``--pkcs12`` the inline file has
to be base64 encoded. Encoding of a .p12 file into base64 can be done
for example with OpenSSL by running :code:`openssl base64 -in input.p12`
