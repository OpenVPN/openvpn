Version 2.4.0
=============


New features
------------
Peer ID support
    Added new packet format P_DATA_V2, which includes peer-id. If
    server and client  support it, client sends all data packets in
    the new format. When data packet arrives, server identifies peer
    by peer-id. If peer's ip/port has changed, server assumes that
    client has floated, verifies HMAC and updates ip/port in internal structs.

Cipher negotiation
    Data channel ciphers are now by default negotiated.  If a client advertises
    support for Negotiable Crypto Parameters (NCP), the server will choose a
    cipher (by default AES-256-GCM) for the data channel, and tell the client
    to use that cipher.  Data channel cipher negotiation can be controlled
    using ``--ncp-ciphers`` and ``--ncp-disable``.

    A more limited version also works in client-to-server and server-to-client
    scenarios where one of the end points uses a v2.4 client or server and the
    other side uses an older version.  In such scenarios the v2.4 side will
    change to the ``--cipher`` set by the remote side, if permitted by by
    ``--ncp-ciphers``.  For example, a v2.4 client with ``--cipher BF-CBC``
    and ``ncp-ciphers AES-256-GCM:AES-256-CBC`` can connect to both a v2.3
    server with ``cipher BF-CBC`` as well as a server with
    ``cipher AES-256-CBC`` in its config.  The other way around, a v2.3 client
    with either ``cipher BF-CBC`` or ``cipher AES-256-CBC`` can connect to a
    v2.4 server with e.g. ``cipher BF-CBC`` and
    ``ncp-ciphers AES-256-GCM:AES-256-CBC`` in its config.  For this to work
    it requires that OpenVPN was built without disabling OCC support.

AEAD (GCM) data channel cipher support
    The data channel now supports AEAD ciphers (currently only GCM).  The AEAD
    packet format has a smaller overhead than the CBC packet format, (e.g. 20
    bytes per packet for AES-128-GCM instead of 36 bytes per packet for
    AES-128-CBC + HMAC-SHA1).

ECDH key exchange
    The TLS control channel now supports for elliptic curve diffie-hellmann
    key exchange (ECDH).

Dualstack client connect
    Instead of only using the first address of each ``--remote`` OpenVPN
    will now try all addresses (IPv6 and IPv4) of a ``--remote`` entry.

Support for providing IPv6 DNS servers
     A new DHCP sub-options ``DNS6`` is added alongside with the already existing
     ``DNS`` sub-option.  This is used to provide DNS resolvers available over
     IPv6.  This will be pushed to clients and `` --up`` scripts and ``--plugin``
     can act upon it through the ``foreign_option_<n>`` environment variables.

     Support for the Windows client picking up this new sub-option is added,
     however IPv6 DNS resolvers needs to be configured via ``netsh`` which requires
     administrator privileges if the new interactive services on Windows is not
     being used.  If the interactive services is used, this service will execute
     ``netsh`` in the background with the proper privileges.

New improved Windows Background service
    The new OpenVPNService is based on openvpnserv2, a complete rewrite of the OpenVPN
    service wrapper. It is intended for launching OpenVPN instances that should be
    up at all times, instead of being manually launched by a user. OpenVPNService is
    able to restart individual OpenVPN processes if they crash, and it also works
    properly on recent Windows versions. OpenVPNServiceLegacy tends to work poorly,
    if at all, on newer Windows versions (8+) and its use is not recommended.

New interactive Windows service
    The installer starts OpenVPNServiceInteractive automatically and configures
    it to start	at system startup.

    The interactive Windows service allows unprivileged users to start
    OpenVPN connections in the global config directory (usually
    C:\\Program Files\\OpenVPN\\config) using OpenVPN GUI without any
    extra configuration.

    Users who belong to the built-in Administrator group or to the
    local "OpenVPN Administrator" group can also store configuration
    files under %USERPROFILE%\\OpenVPN\\config for use with the
    interactive service.

redirect-gateway
    if no flags are given, and the interactive service is used, "def1"
    is implicitly set (because "delete and later reinstall the existing
    default route" does not work well here).  If not using the service,
    the old behaviour is kept.

redirect-gateway ipv6
    OpenVPN has now feature parity between IPv4 and IPv6 for redirect
    gateway including the handling of overlapping IPv6 routes with
    IPv6 remote VPN server address

LZ4 Compression and pushable compression
    Additionally to LZO compression OpenVPN now also supports LZ4 compression.
    Compression options are now pushable from the server.

pull-filter
    New option to explicitly allow or reject options pushed by the server.
    May be used multiple times and is applied in the order specified.

push-remove
    new option to remove options on a per-client basis from the "push" list
    (more fine-grained than ``--push-reset``)

Http proxy password inside config file
    Http proxy passwords can be specified with the inline file option
    ``<http-proxy-user-pass>`` .. ``</http-proxy-user-pass>``

Windows version
    Windows version is detected, logged and possibly signalled to server
    (IV_PLAT_VER=<nn> if ``--push-peer-info`` is set on client)

Authentication tokens
    In situations where it is not suitable to save users passwords on the client
    OpenVPN have since v2.3 had support for --auth-token.  This option is
    pushed from the server to the client with a token value to be used instead
    of the users password.  For this to work, the authentication plug-in would
    need to implement this support as well.  In OpenVPN 2.4 --auth-gen-token
    is introduced, which will allow the OpenVPN server to generate a random
    token and push it to the client without any changes to the authentication
    modules.  When the clients need to re-authenticate the OpenVPN server will
    instead of sending the re-authentication request to the authentication
    module do the authentication internally.  This feature is especially
    useful in configurations which adds One Time Password (OTP) authentication
    schemes, as this allows the tunnel to be renegotiated regularly without
    any need to supply new OTP codes.

keying-material-exporter
    Keying Material Exporter [RFC-5705] allow additional keying material to be
    derived from existing TLS channel.

Mac OS X Keychain management client
    added contrib/keychain-mcd which allows to use Mac OS X keychain
    certificates with OpenVPN

Android platform support
    Support for running on Android using Android's VPNService API has been added.
    See doc/android.txt for 	more details. This support is primarily used in
    the OpenVPN for Android app (https://github.com/schwabe/ics-openvpn)

AIX platform support
    AIX platform support has been added. The support only includes tap
    devices since AIX does not provide tun interface.

Control channel encryption (``--tls-crypt``)
    Use a pre-shared static key (like the ``--tls-auth`` key) to encrypt control
    channel packets.  Provides more privacy, some obfuscation and poor-man's
    post-quantum security.

Asynchronous push reply
    Plug-ins providing support for deferred authentication can benefit from a more
    responsive authentication where the server sends PUSH_REPLY immediately once
    the authentication result is ready instead of waiting for the the client to
    to send PUSH_REQUEST once more.  This requires OpenVPN to be built with
    ``./configure --enable-async-push``.  This is a compile-time only switch.


Deprecated features
-------------------
- ``--key-method 1`` is deprecated in 2.4 and will be removed in 2.5.  Migrate
  away from ``--key-method 1`` as soon as possible.  The recommended approach
  is to remove the ``--key-method`` option from the configuration files, OpenVPN
  will then use ``--key-method 2`` by default.  Note that this requires changing
  the option in both the client and server side configs.

- CRLs are now handled by the crypto library (OpenSSL or mbed TLS), instead of
  inside OpenVPN itself.  The crypto library implementations are more strict
  than the OpenVPN implementation was.  This might reject peer certificates
  that would previously be accepted.  If this occurs, OpenVPN will log the
  crypto library's error description.

- ``--tls-remote`` is removed in 2.4, as indicated in the 2.3 man-pages.  A similar
  functionality is provided via ``--verify-x509-name`` which does the same job in
  a better way.

- ``--compat-names`` and ``--no-name-remapping`` was deprecated in 2.3 and will
  be removed in 2.5.  All scripts and plug-ins depending on the old non-standard
  X.509 subject formatting must be updated to the standardized formatting.  See
  the man page for more information.

- ``--no-iv`` is deprecated in 2.4 and will be remove in 2.5.

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

- ``--sndbuf`` and ``--recvbuf`` default now to OS defaults instead of 64k

- OpenVPN exits with  an error if an option has extra parameters;
  previously they were silently ignored

- The default of ``--tls-cipher`` is now "DEFAULT:!EXP:!PSK:!SRP:!kRSA"
  instead of "DEFAULT" to always select perfect forward security
  cipher suites

- ``--tls-auth`` always requires OpenVPN static key files and will no
  longer work with free form files

- ``--proto udp6/tcp6`` in server mode will now try to always listen to
  both IPv4 and IPv6 on platforms that allow it. Use ``--bind ipv6only``
  to explicitly listen only on IPv6.

- Removed ``--enable-password-save`` from configure. This option is now
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

- ``--connect-timeout`` specifies now the timeout until the first TLS packet
  is received (identical to ``--server-poll-timeout``) and this timeout now
  includes the removed socks proxy timeout and http proxy timeout.

  In ``--static`` mode connect-timeout specifies the timeout for TCP and
  proxy connection establishment

- ``--connect-retry-max`` now specifies the maximum number of unsuccessful
  attempts of each remote/connection entry before exiting.

- ``--http-proxy-timeout`` and the static non-changeable socks timeout (5s)
  have been folded into a "unified" ``--connect-timeout`` which covers all
  steps needed to connect to the server, up to the start of the TLS exchange.
  The default value has been raised to 120s, to handle slow http/socks
  proxies graciously.  The old "fail TCP fast" behaviour can be achieved by
  adding "``--connect-timeout 10``" to the client config.

- ``--http-proxy-retry`` and ``--sock-proxy-retry`` have been removed. Proxy connections
  will now behave like regular connection entries and generate a USR1 on failure.

- ``--connect-retry`` gets an optional second argument that specifies the maximum
  time in seconds to wait between reconnection attempts when an exponential
  backoff is triggered due to repeated retries. Default = 300 seconds.

- Data channel cipher negotiation (see New features section) can override
  ciphers configured in the config file.  Use ``--ncp-disable`` if you do not want
  this behavior.

- All tun devices on all platforms are always considered to be IPv6
  capable. The ``--tun-ipv6`` option is ignored (behaves like it is always
  on).

- On the client side recursively routed packets, which have same destination
  as the VPN server, are dropped. This could be disabled with
  --allow-recursive-routing option.

- on Windows, when the ``--register-dns`` option is set, OpenVPN no longer
  restarts the ``dnscache`` service - this had unwanted side effects, and
  seems to be no longer necessary with currently supported Windows versions.

- OpenVPN now reloads a CRL only if the modication time or file size has
  changed, instead of for each new connection.  This reduces the connection
  setup time, in particular when using large CRLs.

- OpenVPN now ships with more up-to-date systemd unit files which takes advantage
  of the improved service management as well as some hardening steps.  The
  configuration files are picked up from the /etc/openvpn/server/ and
  /etc/openvpn/client/ directories (depending on unit file).  This also avoids
  these new unit files and how they work to collide with older pre-existing
  unit files.

- using ``--no-iv`` (which is generally not a recommended setup) will
  require explicitly disabling NCP with ``--disable-ncp``.  This is
  intentional because NCP will by default use AES-GCM, which requires
  an IV - so we want users of that option to consciously reconsider.


Maintainer-visible changes
--------------------------
- OpenVPN no longer supports building with crypto support, but without TLS
  support.  As a consequence, OPENSSL_CRYPTO_{CFLAGS,LIBS} and
  OPENSSL_SSL_{CFLAGS,LIBS} have been merged into OPENSSL_{CFLAGS,LIBS}.  This
  is particularly relevant for maintainers who build their own OpenSSL library,
  e.g. when cross-compiling.

- Linux distributions using systemd is highly encouraged to ship these new unit
  files instead of older ones, to provide a unified behaviour across systemd
  based Linux distributions.

- With OpenVPN v2.4, the project have moved over to depend on and actively use
  the official C99 standard (-std=c99).  This may on some older compiler/libc
  headers combinations fail.  On most of these situations it is recommended to
  do use -std=gnu99 in CFLAGS.  This is known to be needed when doing
  i386/i686 builds on RHEL5.
