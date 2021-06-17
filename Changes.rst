Overview of changes in 2.5.3
============================
Bugfixes
--------
- CVE-2121-3606
  see https://community.openvpn.net/openvpn/wiki/SecurityAnnouncements

  OpenVPN windows builds could possibly load OpenSSL Config files from
  world writeable locations, thus posing a security risk to OpenVPN.

  As a fix, disable OpenSSL config loading completely on Windows.

- disable connect-retry backoff for p2p (--secret) instances
  (Trac #1010, #1384)

- fix build with mbedtls w/o SSL renegotiation support

- Fix SIGSEGV (NULL deref) receiving push "echo" (Trac #1409)

- MSI installers: properly schedule reboot in the end of installation

- fix small memory leak in free_key_ctx for auth_token


User-visible Changes
--------------------
- update copyright messages in files and --version output

New features
------------
- add --auth-token-user option (for --auth-token deployments without
  --auth-user-pass in client config)

- improve MSVC building for Windows

- official MSI installers will now contain arm64 drivers and binaries
  (x86, amd64, arm64)


Overview of changes in 2.5.2
============================

Bugfixes
--------
- CVE-2020-15078
  see https://community.openvpn.net/openvpn/wiki/SecurityAnnouncements

  This bug allows - under very specific circumstances - to trick a
  server using delayed authentication (plugin or management) into
  returning a PUSH_REPLY before the AUTH_FAILED message, which can
  possibly be used to gather information about a VPN setup.

  In combination with "--auth-gen-token" or an user-specific token auth
  solution it can be possible to get access to a VPN with an
  otherwise-invalid account.

- restore pushed "ping" settings correctly on a SIGUSR1 restart

- avoid generating unecessary mbed debug messages - this is actually
  a workaround for an mbedTLS 2.25 bug when using Curve25519 and Curve448
  ED curves - mbedTLS crashes on preparing debug infos that we do not
  actually need unless running with "--verb 8"

- do not print inlined (<dh>...</dh>) Diffie Hellman parameters to log file

- fix Linux/SITNL default route lookup in case of multiple routing tables
  with more than one default route present (always use "main table" for now)

- Fix CRL file handling in combination with chroot

User-visible Changes
--------------------

- OpenVPN will now refuse to start if CRL file is not present at startup
  time.  At "reload time" absense of the CRL file is still OK (and the
  in memory copy is used) but at startup it is now considered an error.


New features
------------
- printing of the TLS ciphers negotiated has been extended, especially
  displaying TLS 1.3 and EC certificates more correctly.


Overview of changes in 2.5.1
============================

New features
------------
- "echo msg" support, to enable the server to pushed messages that are
  then displayed by the client-side GUI.  See doc/gui-notes.txt and
  doc/management-notes.txt.

  Supported by the Windows GUI shipped in 2.5.1, not yet supported by
  Tunnelblick and the Android GUI.

User-visible Changes
--------------------
- make OPENVPN_PLUGIN_ENABLE_PF plugin failures FATAL - if a plugin offers
  to set the "openvpn packet filter", and returns a failure when requested
  to, OpenVPN 2.5.0 would crash trying to clean up not-yet-initialized
  structure members.  Since PF is going away in 2.6.0, this is just turning
  the crash into a well-defined program abort, and no further effort has
  been spent in rewriting the PF plugin error handling (see trac #1377).

Documentation
-------------
- rework sample-plugins/defer/simple.c - this is an extensive rewrite
  of the plugin to bring code quality to acceptable standards and add
  documentation on the various plugin API aspects.  Since it's just
  example code, filed under "Documentation", not under "Bugfix".

- various man page improvements.

- clarify ``--block-ipv6`` intent and direction

Bugfixes
--------
- fix installation of openvpn.8 manpage on systems without docutils.

- Windows: fix DNS search list setup for domains with "-" chars.

- Fix tls-auth mismatch OCC message when tls-cryptv2 is used.

- Windows: Skip DHCP renew with Wintun adapter (Wintun does not support
  DHCP, so this was just causing an - harmless - error and needless delay).

- Windows: Remove 1 second delay before running netsh - speeds up
  interface init for wintun setups not using the interactive service.

- Windows: Fix too early argv freeing when registering DNS - this would
  cause a client side crash on Windows if ``register-dns`` is used,
  and the interactive service is not used.

- Android: Zero initialise msghdr prior to calling sendmesg.

- Fix line number reporting on config file errors after <inline> segments
  (see Trac #1325).

- Fix port-share option with TLS-Crypt v2.

- tls-crypt-v2: also preload tls-crypt-v2 keys (if --persist-key), otherwise
  dropping privs on the server would fail.

- tls-crypt-v2: fix server memory leak (about 600 bytes per connecting
  client with tls-crypt-v2)

- rework handling of server-pushed ``--auth-token`` in combination with
  ``--auth-nocache`` on reconnection / TLS renegotiation events.  This
  used to "forget" to update new incoming token after a reconnection event
  (leading to failure to reauth some time later) and now works in all
  tested cases.


Overview of changes in 2.5.0
============================

New features
------------
Client-specific tls-crypt keys (``--tls-crypt-v2``)
    ``tls-crypt-v2`` adds the ability to supply each client with a unique
    tls-crypt key.  This allows large organisations and VPN providers to profit
    from the same DoS and TLS stack protection that small deployments can
    already achieve using ``tls-auth`` or ``tls-crypt``.

ChaCha20-Poly1305 cipher support
    Added support for using the ChaCha20-Poly1305 cipher in the OpenVPN data
    channel.

Improved Data channel cipher negotiation
    The option ``ncp-ciphers`` has been renamed to ``data-ciphers``.
    The old name is still accepted. The change in name signals that
    ``data-ciphers`` is the preferred way to configure data channel
    ciphers and the data prefix is chosen to avoid the ambiguity that
    exists with ``--cipher`` for the data cipher and ``tls-cipher``
    for the TLS ciphers.

    OpenVPN clients will now signal all supported ciphers from the
    ``data-ciphers`` option to the server via ``IV_CIPHERS``. OpenVPN
    servers will select the first common cipher from the ``data-ciphers``
    list instead of blindly pushing the first cipher of the list. This
    allows to use a configuration like
    ``data-ciphers ChaCha20-Poly1305:AES-256-GCM`` on the server that
    prefers ChaCha20-Poly1305 but uses it only if the client supports it.

    See the data channel negotiation section in the manual for more details.

Removal of BF-CBC support in default configuration:
    By default OpenVPN 2.5 will only accept AES-256-GCM and AES-128-GCM as
    data ciphers. OpenVPN 2.4 allows AES-256-GCM,AES-128-GCM and BF-CBC when
    no --cipher and --ncp-ciphers options are present. Accepting BF-CBC can be
    enabled by adding

        data-ciphers AES-256-GCM:AES-128-GCM:BF-CBC

    and when you need to support very old peers also

        data-ciphers-fallback BF-CBC

    To offer backwards compatibility with older configs an *explicit*

        cipher BF-CBC

    in the configuration will be automatically translated into adding BF-CBC
    to the data-ciphers option and setting data-ciphers-fallback to BF-CBC
    (as in the example commands above). We strongly recommend to switching
    away from BF-CBC to a more secure cipher.

Asynchronous (deferred) authentication support for auth-pam plugin.
    See src/plugins/auth-pam/README.auth-pam for details.

Deferred client-connect
    The ``--client-connect`` option and the connect plugin API allow
    asynchronous/deferred return of the configuration file in the same way
    as the auth-plugin.

Faster connection setup
    A client will signal in the ``IV_PROTO`` variable that it is in pull
    mode. This allows the server to push the configuration options to
    the client without waiting for a ``PULL_REQUEST`` message. The feature
    is automatically enabled if both client and server support it and
    significantly reduces the connection setup time by avoiding one
    extra packet round-trip and 1s of internal event delays.

Netlink support
    On Linux, if configured without ``--enable-iproute2``, configuring IP
    addresses and adding/removing routes is now done via the netlink(3)
    kernel interface.  This is much faster than calling ``ifconfig`` or
    ``route`` and also enables OpenVPN to run with less privileges.

    If configured with --enable-iproute2, the ``ip`` command is used
    (as in 2.4).  Support for ``ifconfig`` and ``route`` is gone.

Wintun support
    On Windows, OpenVPN can now use ``wintun`` devices.  They are faster
    than the traditional ``tap9`` tun/tap devices, but do not provide
    ``--dev tap`` mode - so the official installers contain both.  To use
    a wintun device, add ``--windows-driver wintun`` to your config
    (and use of the interactive service is required as wintun needs
    SYSTEM privileges to enable access).

IPv6-only operation
    It is now possible to have only IPv6 addresses inside the VPN tunnel,
    and IPv6-only address pools (2.4 always required IPv4 config/pools
    and IPv6 was the "optional extra").

Improved Windows 10 detection
    Correctly log OS on Windows 10 now.

Linux VRF support
    Using the new ``--bind-dev`` option, the OpenVPN outside socket can
    now be put into a Linux VRF.  See the "Virtual Routing and Forwarding"
    documentation in the man page.

TLS 1.3 support
    TLS 1.3 support has been added to OpenVPN.  Currently, this requires
    OpenSSL 1.1.1+.
    The options ``--tls-ciphersuites`` and ``--tls-groups`` have been
    added to fine tune TLS protocol options.  Most of the improvements
    were also backported to OpenVPN 2.4 as part of the maintainance
    releases.

Support setting DHCP search domain
    A new option ``--dhcp-option DOMAIN-SEARCH my.example.com`` has been
    defined, and Windows support for it is implemented (tun/tap only, no
    wintun support yet).  Other platforms need to support this via ``--up``
    script (Linux) or GUI (OSX/Tunnelblick).

per-client changing of ``--data-ciphers`` or ``data-ciphers-fallback``
    from client-connect script/dir (NOTE: this only changes preference of
    ciphers for NCP, but can not override what the client announces as
    "willing to accept")

Handle setting of tun/tap interface MTU on Windows
    If IPv6 is in use, MTU must be >= 1280 (Windows enforces IETF requirements)

Add support for OpenSSL engines to access private key material (like TPM).

HMAC based auth-token support
    The ``--auth-gen-token`` support has been improved and now generates HMAC
    based user token. If the optional ``--auth-gen-token-secret`` option is
    used clients will be able to seamlessly reconnect to a different server
    using the same secret file or to the same server after a server restart.

Improved support for pending authentication
    The protocol has been enhanced to be able to signal that
    the authentication should use a secondary authentication
    via web (like SAML) or a two factor authentication without
    disconnecting the OpenVPN session with AUTH_FAILED. The
    session will instead be stay in a authenticated state and
    wait for the second factor authentication to complete.

    This feature currently requires usage of the managent interface
    on both client and server side. See the `management-notes.txt`
    ``client-pending-auth`` and ``cr-response`` commands for more
    details.

VLAN support
    OpenVPN servers in TAP mode can now use 802.1q tagged VLANs
    on the TAP interface to separate clients into different groups
    that can then be handled differently (different subnets / DHCP,
    firewall zones, ...) further down the network.  See the new
    options ``--vlan-tagging``, ``--vlan-accept``, ``--vlan-pvid``.

    802.1q tagging on the client side TAP interface is not handled
    today (= tags are just forwarded transparently to the server).

Support building of .msi installers for Windows

Allow unicode search string in ``--cryptoapicert`` option (Windows)

Support IPv4 configs with /31 netmasks now
    (By no longer trying to configure ``broadcast x.x.x.x'' in
    ifconfig calls, /31 support "just works")

New option ``--block-ipv6`` to reject all IPv6 packets (ICMPv6)
    this is useful if the VPN service has no IPv6, but the clients
    might have (LAN), to avoid client connections to IPv6-enabled
    servers leaking "around" the IPv4-only VPN.

``--ifconfig-ipv6`` and ``--ifconfig-ipv6-push`` will now accept
    hostnames and do a DNS lookup to get the IPv6 address to use


Deprecated features
-------------------
For an up-to-date list of all deprecated options, see this wiki page:
https://community.openvpn.net/openvpn/wiki/DeprecatedOptions

- ``ncp-disable`` has been deprecated
    With the improved and matured data channel cipher negotiation, the use
    of ``ncp-disable`` should not be necessary anymore.

- ``inetd`` has been deprecated
  This is a very limited and not-well-tested way to run OpenVPN, on TCP
  and TAP mode only, which complicates the code quite a bit for little gain.
  To be removed in OpenVPN 2.6 (unless users protest).

- ``no-iv`` has been removed
  This option was made into a NOOP option with OpenVPN 2.4.  This has now
  been completely removed.

- ``--client-cert-not-required`` has been removed
  This option will now cause server configurations to not start.  Use
  ``--verify-client-cert none`` instead.

- ``--ifconfig-pool-linear`` has been removed
  This option is removed.  Use ``--topology p2p`` or ``--topology subnet``
  instead.

- ``--compress xxx`` is considered risky and is warned against, see below.

- ``--key-method 1`` has been removed


User-visible Changes
--------------------
- If multiple connect handlers are used (client-connect, ccd, connect
  plugin) and one of the handler succeeds but a subsequent fails, the
  client-disconnect-script is now called immediately. Previously it
  was called, when the VPN session was terminated.

- Support for building with OpenSSL 1.0.1 has been removed. The minimum
  supported OpenSSL version is now 1.0.2.

- The GET_CONFIG management state is omitted if the server pushes
  the client configuration almost immediately as result of the
  faster connection setup feature.

- ``--compress`` is nowadays considered risky, because attacks exist
  leveraging compression-inside-crypto to reveal plaintext (VORACLE).  So
  by default, ``--compress xxx`` will now accept incoming compressed
  packets (for compatibility with peers that have not been upgraded yet),
  but will not use compression outgoing packets.  This can be controlled with
  the new option ``--allow-compression yes|no|asym``.

- Stop changing ``--txlen`` aways from OS defaults unless explicitly specified
  in config file.  OS defaults nowadays are actually larger then what we used
  to configure, so our defaults sometimes caused packet drops = bad performance.

- remove ``--writepid`` pid file on exit now

- plugin-auth-pam now logs via OpenVPN logging method, no longer to stderr
  (this means you'll have log messages in syslog or openvpn log file now)

- use ISO 8601 time format for file based logging now (YYYY-MM-DD hh:mm:dd)
  (syslog is not affected, nor is ``--machine-readable-output``)

- ``--clr-verify`` now loads all CRLs if more than one CRL is in the same
  file (OpenSSL backend only, mbedTLS always did that)

- when ``--auth-user-pass file`` has no password, and the management interface
  is active, query management interface (instead of trying console query,
  which does not work on windows)

- skip expired certificates in Windows certificate store (``--cryptoapicert``)

- ``--socks-proxy`` + ``--proto udp*`` will now allways use IPv4, even if
  IPv6 is requested and available.  Our SOCKS code does not handle IPv6+UDP,
  and before that change it would just fail in non-obvious ways.

- TCP listen() backlog queue is now set to 32 - this helps TCP servers that
  receive lots of "invalid" connects by TCP port scanners

- do no longer print OCC warnings ("option mismatch") about ``key-method``,
  ``keydir``, ``tls-auth`` and ``cipher`` - these are either gone now, or
  negotiated, and the warnings do not serve a useful purpose.

- ``dhcp-option DNS`` and ``dhcp-option DNS6`` are now treated identically
  (= both accept an IPv4 or IPv6 address for the nameserver)


Maintainer-visible changes
--------------------------
- the man page is now in maintained in .rst format, so building the openvpn.8
  manpage from a git checkout now requires python-docutils (if this is missing,
  the manpage will not be built - which is not considered an error generally,
  but for package builders or ``make distcheck`` it is).  Release tarballs
  contain the openvpn.8 file, so unless some .rst is changed, doc-utils are
  not needed for building.

- OCC support can no longer be disabled

- AEAD support is now required in the crypto library

- ``--disable-server`` has been removed from configure (so it is no longer
  possible to build a client-/p2p-only OpenVPN binary) - the saving in code
  size no longer outweighs the extra maintenance effort.

- ``--enable-iproute2`` will disable netlink(3) support, so maybe remove
  that from package building configs (see above)

- support building with MSVC 2019

- cmocka based unit tests are now only run if cmocka is installed externally
  (2.4 used to ship a local git submodule which was painful to maintain)

- ``--disable-crypto`` configure option has been removed.  OpenVPN is now always
  built with crypto support, which makes the code much easier to maintain.
  This does not affect ``--cipher none`` to do a tunnel without encryption.

- ``--disable-multi`` configure option has been removed



Overview of changes in 2.4
==========================


New features
------------
Seamless client IP/port floating
    Added new packet format P_DATA_V2, which includes peer-id. If both the
    server and client support it, the client sends all data packets in
    the new format. When a data packet arrives, the server identifies peer
    by peer-id. If peer's ip/port has changed, server assumes that
    client has floated, verifies HMAC and updates ip/port in internal structs.
    This allows the connection to be immediately restored, instead of requiring
    a TLS handshake before the server accepts packets from the new client
    ip/port.

Data channel cipher negotiation
    Data channel ciphers (``--cipher``) are now by default negotiated.  If a
    client advertises support for Negotiable Crypto Parameters (NCP), the
    server will choose a cipher (by default AES-256-GCM) for the data channel,
    and tell the client to use that cipher.  Data channel cipher negotiation
    can be controlled using ``--ncp-ciphers`` and ``--ncp-disable``.

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
    packet format has a smaller crypto overhead than the CBC packet format,
    (e.g. 20 bytes per packet for AES-128-GCM instead of 36 bytes per packet
    for AES-128-CBC + HMAC-SHA1).

ECDH key exchange
    The TLS control channel now supports for elliptic curve diffie-hellmann
    key exchange (ECDH).

Improved Certificate Revocation List (CRL) processing
    CRLs are now handled by the crypto library (OpenSSL or mbed TLS), instead
    of inside OpenVPN itself.  The crypto library implementations are more
    strict than the OpenVPN implementation was.  This might reject peer
    certificates that would previously be accepted.  If this occurs, OpenVPN
    will log the crypto library's error description.

Dualstack round-robin DNS client connect
    Instead of only using the first address of each ``--remote`` OpenVPN
    will now try all addresses (IPv6 and IPv4) of a ``--remote`` entry.

Support for providing IPv6 DNS servers
    A new DHCP sub-option ``DNS6`` is added alongside with the already existing
    ``DNS`` sub-option.  This is used to provide DNS resolvers available over
    IPv6.  This may be pushed to clients where `` --up`` scripts and ``--plugin``
    can act upon it through the ``foreign_option_<n>`` environment variables.

    Support for the Windows client picking up this new sub-option is added,
    however IPv6 DNS resolvers need to be configured via ``netsh`` which requires
    administrator privileges unless the new interactive services on Windows is
    being used.  If the interactive service is used, this service will execute
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

redirect-gateway ipv6
    OpenVPN has now feature parity between IPv4 and IPv6 for redirect
    gateway including the handling of overlapping IPv6 routes with
    IPv6 remote VPN server address.

LZ4 Compression and pushable compression
    Additionally to LZO compression OpenVPN now also supports LZ4 compression.
    Compression options are now pushable from the server.

Filter pulled options client-side: pull-filter
    New option to explicitly allow or reject options pushed by the server.
    May be used multiple times and is applied in the order specified.

Per-client remove push options: push-remove
    New option to remove options on a per-client basis from the "push" list
    (more fine-grained than ``--push-reset``).

Http proxy password inside config file
    Http proxy passwords can be specified with the inline file option
    ``<http-proxy-user-pass>`` .. ``</http-proxy-user-pass>``

Windows version detection
    Windows version is detected, logged and possibly signalled to server
    (IV_PLAT_VER=<nn> if ``--push-peer-info`` is set on client).

Authentication tokens
    In situations where it is not suitable to save user passwords on the client,
    OpenVPN has support for pushing a --auth-token since v2.3.  This option is
    pushed from the server to the client with a token value to be used instead
    of the users password.  For this to work, the authentication plug-in would
    need to implement this support as well.  In OpenVPN 2.4 --auth-gen-token
    is introduced, which will allow the OpenVPN server to generate a random
    token and push it to the client without any changes to the authentication
    modules.  When the clients need to re-authenticate the OpenVPN server will
    do the authentication internally, instead of sending the re-authentication
    request to the authentication module .  This feature is especially
    useful in configurations which use One Time Password (OTP) authentication
    schemes, as this allows the tunnel keys to be renegotiated regularly without
    any need to supply new OTP codes.

keying-material-exporter
    Keying Material Exporter [RFC-5705] allow additional keying material to be
    derived from existing TLS channel.

Android platform support
    Support for running on Android using Android's VPNService API has been added.
    See doc/android.txt for more details. This support is primarily used in
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
    the authentication result is ready, instead of waiting for the the client to
    to send PUSH_REQUEST once more.  This requires OpenVPN to be built with
    ``./configure --enable-async-push``.  This is a compile-time only switch.


Deprecated features
-------------------
For an up-to-date list of all deprecated options, see this wiki page:
https://community.openvpn.net/openvpn/wiki/DeprecatedOptions

- ``--key-method 1`` is deprecated in OpenVPN 2.4 and will be removed in v2.5.
  Migrate away from ``--key-method 1`` as soon as possible.  The recommended
  approach is to remove the ``--key-method`` option from the configuration
  files, OpenVPN will then use ``--key-method 2`` by default.  Note that this
  requires changing the option in both the client and server side configs.

- ``--tls-remote`` is removed in OpenVPN 2.4, as indicated in the v2.3
  man-pages.  Similar functionality is provided via ``--verify-x509-name``,
  which does the same job in a better way.

- ``--compat-names`` and ``--no-name-remapping`` were deprecated in OpenVPN 2.3
  and will be removed in v2.5.  All scripts and plug-ins depending on the old
  non-standard X.509 subject formatting must be updated to the standardized
  formatting.  See the man page for more information.

- ``--no-iv`` is deprecated in OpenVPN 2.4 and will be removed in v2.5.

- ``--keysize`` is deprecated in OpenVPN 2.4 and will be removed in v2.6
  together with the support of ciphers with cipher block size less than
  128-bits.

- ``--comp-lzo`` is deprecated in OpenVPN 2.4.  Use ``--compress`` instead.

- ``--ifconfig-pool-linear`` has been deprecated since OpenVPN 2.1 and will be
  removed in v2.5.  Use ``--topology p2p`` instead.

- ``--client-cert-not-required`` is deprecated in OpenVPN 2.4 and will be removed
  in v2.5.  Use ``--verify-client-cert none`` for a functional equivalent.

- ``--ns-cert-type`` is deprecated in OpenVPN 2.3.18 and v2.4.  It will be removed
  in v2.5.  Use the far better ``--remote-cert-tls`` option which replaces this
  feature.


User-visible Changes
--------------------
- When using ciphers with cipher blocks less than 128-bits,
  OpenVPN will complain loudly if the configuration uses ciphers considered
  weak, such as the SWEET32 attack vector.  In such scenarios, OpenVPN will by
  default renegotiate for each 64MB of transported data (``--reneg-bytes``).
  This renegotiation can be disabled, but is HIGHLY DISCOURAGED.

- For certificate DNs with duplicate fields, e.g. "OU=one,OU=two", both fields
  are now exported to the environment, where each second and later occurrence
  of a field get _$N appended to it's field name, starting at N=1.  For the
  example above, that would result in e.g. X509_0_OU=one, X509_0_OU_1=two.
  Note that this breaks setups that rely on the fact that OpenVPN would
  previously (incorrectly) only export the last occurrence of a field.

- ``proto udp`` and ``proto tcp`` now use both IPv4 and IPv6. The new
  options ``proto udp4`` and ``proto tcp4`` use IPv4 only.

- ``--sndbuf`` and ``--recvbuf`` default now to OS defaults instead of 64k

- OpenVPN exits with an error if an option has extra parameters;
  previously they were silently ignored

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

- ``--connect-timeout`` now specifies the timeout until the first TLS packet
  is received (identical to ``--server-poll-timeout``) and this timeout now
  includes the removed socks proxy timeout and http proxy timeout.

  In ``--static`` mode ``connect-timeout`` specifies the timeout for TCP and
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

- On the client side recursively routed packets, which have the same destination
  as the VPN server, are dropped. This can be disabled with
  --allow-recursive-routing option.

- On Windows, when the ``--register-dns`` option is set, OpenVPN no longer
  restarts the ``dnscache`` service - this had unwanted side effects, and
  seems to be no longer necessary with currently supported Windows versions.

- If no flags are given, and the interactive Windows service is used, "def1"
  is implicitly set (because "delete and later reinstall the existing
  default route" does not work well here).  If not using the service,
  the old behaviour is kept.

- OpenVPN now reloads a CRL only if the modication time or file size has
  changed, instead of for each new connection.  This reduces the connection
  setup time, in particular when using large CRLs.

- OpenVPN now ships with more up-to-date systemd unit files which take advantage
  of the improved service management as well as some hardening steps.  The
  configuration files are picked up from the /etc/openvpn/server/ and
  /etc/openvpn/client/ directories (depending on unit file).  This also avoids
  these new unit files and how they work to collide with older pre-existing
  unit files.

- Using ``--no-iv`` (which is generally not a recommended setup) will
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

- With OpenVPN 2.4, the project has moved over to depend on and actively use
  the official C99 standard (-std=c99).  This may fail on some older compiler/libc
  header combinations.  In most of these situations it is recommended to
  use -std=gnu99 in CFLAGS.  This is known to be needed when doing
  i386/i686 builds on RHEL5.


Version 2.4.5
=============

New features
------------
- The new option ``--tls-cert-profile`` can be used to restrict the set of
  allowed crypto algorithms in TLS certificates in mbed TLS builds.  The
  default profile is 'legacy' for now, which allows SHA1+, RSA-1024+ and any
  elliptic curve certificates.  The default will be changed to the 'preferred'
  profile in the future, which requires SHA2+, RSA-2048+ and any curve.


Version 2.4.3
=============

New features
------------
- Support building with OpenSSL 1.1 now (in addition to older versions)

- On Win10, set low interface metric for TAP adapter when block-outside-dns
  is in use, to make Windows prefer the TAP adapter for DNS queries
  (avoiding large delays)


Security
--------
- CVE-2017-7522: Fix ``--x509-track`` post-authentication remote DoS
  A client could crash a v2.4+ mbedtls server, if that server uses the
  ``--x509-track`` option and the client has a correct, signed and unrevoked
  certificate that contains an embedded NUL in the certificate subject.
  Discovered and reported to the OpenVPN security team by Guido Vranken.

- CVE-2017-7521: Fix post-authentication remote-triggerable memory leaks
  A client could cause a server to leak a few bytes each time it connects to the
  server.  That can eventually cause the server to run out of memory, and thereby
  causing the server process to terminate. Discovered and reported to the
  OpenVPN security team by Guido Vranken.  (OpenSSL builds only.)

- CVE-2017-7521: Fix a potential post-authentication remote code execution
  attack on servers that use the ``--x509-username-field`` option with an X.509
  extension field (option argument prefixed with ``ext:``).  A client that can
  cause a server to run out-of-memory (see above) might be able to cause the
  server to double free, which in turn might lead to remote code execution.
  Discovered and reported to the OpenVPN security team by Guido Vranken.
  (OpenSSL builds only.)

- CVE-2017-7520: Pre-authentication remote crash/information disclosure for
  clients. If clients use a HTTP proxy with NTLM authentication (i.e.
  ``--http-proxy <server> <port> [<authfile>|'auto'|'auto-nct'] ntlm2``),
  a man-in-the-middle attacker between the client and the proxy can cause
  the client to crash or disclose at most 96 bytes of stack memory. The
  disclosed stack memory is likely to contain the proxy password. If the
  proxy password is not reused, this is unlikely to compromise the security
  of the OpenVPN tunnel itself.  Clients who do not use the ``--http-proxy``
  option with ntlm2 authentication are not affected.

- CVE-2017-7508: Fix remotely-triggerable ASSERT() on malformed IPv6 packet.
  This can be used to remotely shutdown an openvpn server or client, if
  IPv6 and ``--mssfix`` are enabled and the IPv6 networks used inside the VPN
  are known.

- Fix null-pointer dereference when talking to a malicious http proxy
  that returns a malformed ``Proxy-Authenticate:`` headers for digest auth.

- Fix overflow check for long ``--tls-cipher`` option

- Windows: Pass correct buffer size to ``GetModuleFileNameW()``
  (OSTIF/Quarkslabs audit, finding 5.6)


User-visible Changes
--------------------
- ``--verify-hash`` can now take an optional flag which changes the hashing
  algorithm. It can be either SHA1 or SHA256.  The default if not provided is
  SHA1 to preserve backwards compatibility with existing configurations.

- Restrict the supported ``--x509-username-field`` extension fields to subjectAltName
  and issuerAltName.  Other extensions probably didn't work anyway, and would
  cause OpenVPN to crash when a client connects.


Bugfixes
--------
- Fix fingerprint calculation in mbed TLS builds.  This means that mbed TLS users
  of OpenVPN 2.4.0, v2.4.1 and v2.4.2 that rely on the values of the
  ``tls_digest_*`` env vars, or that use ``--verify-hash`` will have to change
  the fingerprint values they check against.  The security impact of the
  incorrect calculation is very minimal; the last few bytes (max 4, typically
  4) are not verified by the fingerprint.  We expect no real-world impact,
  because users that used this feature before will notice that it has suddenly
  stopped working, and users that didn't will notice that connection setup
  fails if they specify correct fingerprints.

- Fix edge case with NCP when the server sends an empty PUSH_REPLY message
  back, and the client would not initialize it's data channel crypto layer
  properly (trac #903)

- Fix SIGSEGV on unaligned buffer access on OpenBSD/Sparc64

- Fix TCP_NODELAY on OpenBSD

- Remove erroneous limitation on max number of args for ``--plugin``

- Fix NCP behaviour on TLS reconnect (Server would not send a proper
  "cipher ..." message back to the client, leading to client and server
  using different ciphers) (trac #887)


Version 2.4.2
=============

Bugfixes
--------
- Fix memory leak introduced in OpenVPN 2.4.1: if ``--remote-cert-tls`` is
  used, we leaked some memory on each TLS (re)negotiation.


Security
--------
- Fix a pre-authentication denial-of-service attack on both clients and
  servers.  By sending a too-large control packet, OpenVPN 2.4.0 or v2.4.1 can
  be forced to hit an ASSERT() and stop the process.  If ``--tls-auth`` or
  ``--tls-crypt`` is used, only attackers that have the ``--tls-auth`` or
  ``--tls-crypt`` key can mount an attack.
  (OSTIF/Quarkslab audit finding 5.1, CVE-2017-7478)

- Fix an authenticated remote DoS vulnerability that could be triggered by
  causing a packet id roll over.  An attack is rather inefficient; a peer
  would need to get us to send at least about 196 GB of data.
  (OSTIF/Quarkslab audit finding 5.2, CVE-2017-7479)


Version 2.4.1
=============
- ``--remote-cert-ku`` now only requires the certificate to have at least the
  bits set of one of the values in the supplied list, instead of requiring an
  exact match to one of the values in the list.
- ``--remote-cert-tls`` now only requires that a keyUsage is present in the
  certificate, and leaves the verification of the value up to the crypto
  library, which has more information (i.e. the key exchange method in use)
  to verify that the keyUsage is correct.
- ``--ns-cert-type`` is deprecated.  Use ``--remote-cert-tls`` instead.
  The nsCertType x509 extension is very old, and barely used.
  ``--remote-cert-tls`` uses the far more common keyUsage and extendedKeyUsage
  extension instead.  Make sure your certificates carry these to be able to
  use ``--remote-cert-tls``.

