Version 2.4.0
=============


New features
------------

pull-filter
    New option to explicitly allow or reject options pushed by the server.
    May be used multiple times and is applied in the order specified.

push-remove
    new option to remove options on a per-client basis from the "push" list
    (more fine-grained than "push-reset")

keying-material-exporter
    Keying Material Exporter [RFC-5705] allow additional keying material to be
    derived from existing TLS channel.

redirect-gateway ipv6
    OpenVPN has now feature parity between IPv4 and IPv6 for redirect
    gateway including the handling of overlapping IPv6 routes with
    IPv6 remote VPN server address

Mac OS X Keychain management client
    add contrib/keychain-mcd which allows to use Mac OS X keychain
    certificates with OpenVPN

Peer ID support
    Added new packet format P_DATA_V2, which includes peer-id. If
    server and client  support it, client sends all data packets in
    the new format. When data packet arrives, server identifies peer
    by peer-id. If peer's ip/port has changed, server assumes that
    client has floated, verifies HMAC and updates ip/port in internal structs.

Dualstack client connect
    Instead of only using the first address of each --remote OpenVPN
    will now try all addresses (IPv6 and IPv4) of a --remote entry.

LZ4 Compression
    Additionally to LZO compression OpenVPN now also supports LZ4
    compression.

Windows version
    Windows version is detected, logged and possibly signalled to server
    (IV_PLAT_VER=<nn> if --push-peer-info is set on client)

AEAD (GCM) data channel cipher support
    The data channel now supports AEAD ciphers (currently only GCM).  The AEAD
    packet format has a smaller overhead than the CBC packet format, (e.g. 20
    bytes per packet for AES-128-GCM instead of 36 bytes per packet for
    AES-128-CBC + HMAC-SHA1).


User-visible Changes
--------------------
- For certificate DNs with duplicate fields, e.g. "OU=one,OU=two", both fields
  are now exported to the environment, where each second and later occurrence
  of a field get _$N appended to it's field name, starting at N=1.  For the
  example above, that would result in e.g. X509_0_OU=one, X509_0_OU_1=two.
  Note that this breaks setups that rely on the fact that OpenVPN would
  previously (incorrectly) only export the last occurence of a field.

- proto udp and proto tcp specify to use IPv4 and IPv6. The new
  options proto udp4 and tcp4 specify to use IPv4 only.

- connect-timeout specifies now the timeout until the first TLS packet
  is received (identical to server-poll-timeout) and this timeout now
  includes the removed socks proxy timeout and http proxy timeout.

  In --static mode connect-timeout specifies the timeout for TCP and
  proxy connection establishment

- connect-retry now specifies the maximum number of unsucessfully
  trying all remote/connection entries before exiting.

- sndbuf and recvbuf default now to OS default instead of 64k

- OpenVPN exits with  an error if an option has extra parameters;
  previously they were silently ignored

- The default of tls-cipher is now "DEFAULT:!EXP:!PSK:!SRP:!kRSA"
  instead of "DEFAULT" to always select perfect forward security
  cipher suites

- --tls-auth always requires OpenVPN static key files and will no
  longer work with free form files

- proto udp6/tcp6 in server mode will now try to always listen to
  both IPv4 and IPv6 on platforms that allow it. Use bind ipv6only
  to explicitly listen only on IPv6.

- Removed --enable-password-save from configure. This option is now
  always enabled.

- Stricter default TLS cipher list (override with ``--tls-cipher``), that now
  also disables:

  * Non-ephemeral key exchange using static (EC)DH keys
  * DSS private keys

- mbed TLS builds: changed the tls_digest_N values exported to the script
  environment to be equal to the ones exported by OpenSSL builds, namely
  the certificate fingerprint (was the hash of the 'to be signed' data).

- mbed TLS builds: minimum RSA key size is now 2048 bits.  Shorter keys will
  not be accepted, both local and from the peer.


Maintainer-visible changes
--------------------------
- OpenVPN no longer supports building with crypto support, but without TLS
  support.  As a consequence, OPENSSL_CRYPTO_{CFLAGS,LIBS} and
  OPENSSL_SSL_{CFLAGS,LIBS} have been merged into OPENSSL_{CFLAGS,LIBS}.  This
  is particularly relevant for maintainers who build their own OpenSSL library,
  e.g. when cross-compiling.
