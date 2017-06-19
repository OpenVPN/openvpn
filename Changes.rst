Overview of changes in 2.3
==========================

New features
------------

Windows DNS leak fix
    This feature allows blocking all out-of-tunnel communication on TCP/UDP port
    53 (except for OpenVPN itself), preventing DNS Leaks on Windows 8.1 and 10.

Client-only support for Peer ID
    Added new packet format P_DATA_V2, which includes peer-id. If
    server and client  support it, client sends all data packets in
    the new format. When data packet arrives, server identifies peer
    by peer-id. If peer's ip/port has changed, server assumes that
    client has floated, verifies HMAC and updates ip/port in internal structs.
    OpenvPN 2.3.x has client-side functionality only, server needs 2.4.

TLS version negotiation
    Updated the TLS negotiation logic to adaptively try to connect using
    the highest TLS version supported by both client and server. The behavior
    of this feature can be adjusted as necessary.

Push peer info
    Always push basic set of peer info values to server. This allows the
    server to make informed choices based on the capabilities of the client.
    The capabilities include things like supported compression algorithms,
    SSL library version and GUI version. The amount of data transmitted in peer
    information can be adjusted.

PolarSSL support
    Allow use of PolarSSL in OpenVPN as the crypto library, the SSL library and
    for providing PKCS#11 support (up to 2.3.9 supporting PolarSSL 1.2, starting
    with 2.3.10, PolarSSL 1.3).

Plug-in API v3
    This is a new, more flexible plug-in API.

IPv6 payload and transport support
    Allow tunneling IPv6 traffic inside an IPv6 tunnel, as well as using IPv6
    as the transport for OpenVPN traffic.

Client-side one-to-one NAT support
    This feature allows using SNAT or DNAT internally in OpenVPN to work around
    IP numbering conflicts with pushed routes.

Support for a challenge/response protocol
    Allows an OpenVPN server to generate challenge questions for the user. This
    can be used to implement multi-factor authentication. Both dynamic and
    static challenges are supported.

Improved UTF-8 support
    OpenVPN can now manage UTF-8 characters, for example in usernames,
    passwords, X.509 DNs and Windows paths.


Behavioral changes
------------------

- OpenVPN will complain loudly about ciphers with block sizes less than 128-bits

- OpenVPN will by default re-negotiate the tunnel after 64MB when used with
  ciphers using cipher blocks sizes less than 128-bits

- Remove --enable-password-save option to configure, this is now always enabled

- Disallow usage of ``--server-poll-timeout`` in ``--secret`` key mode

- The second parameter of ``--ifconfig`` is no longer a "remote address" but a
  "netmask" when using ``--dev tun`` and -``-topology subnet``

- Automatic TLS version negotiation may cause issues in certain cases.

- Don't exit daemon if opening or parsing the CRL fails

- Do not upcase x509-username-field for mixed-case arguments

- Allow use of connection block variables after connection blocks: this may
  cause issues in some cases

- Always load intermediate certificates from a PKCS#12 file, instead of ignoring
  them

- Remove the ``--disable-eurephia`` configure option

- Remove the support for using ``system()`` when executing external programs or
  scripts

- Inline files are now always enabled

- Remove the ``--auto-proxy`` option (now handled via management interface)

- Directory layout restructuring

- A Windows buildsystem is no longer bundled with OpenVPN

- Easy-rsa is no longer bundled with OpenVPN

- Tap-windows driver sources are no longer bundled with OpenVPN

- Made some options connection-entry specific

- Make ``--win-sys env`` default

- Do not randomize resolving of IP addresses in getaddr()


Version 2.3.17
==============

Security fixes
--------------
- CVE-2017-7521: Fix post-authentication remote-triggerable memory leaks
  A client could cause a server to leak a few bytes each time it connects to the
  server.  That can eventuall cause the server to run out of memory, and thereby
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

- CVE-2017-7508: Fix remotely-triggerable ``ASSERT()`` on malformed IPv6 packet.
  This can be used to remotely shutdown an openvpn server or client, if
  IPv6 and ``--mssfix`` are enabled and the IPv6 networks used inside the VPN
  are known.

- Fix potential 1-byte overread in TCP option parsing.
- fix null-pointer dereference when talking to a malicious http proxy
  that returns a malformed ``Proxy-Authenticate:`` headers for digest auth.
- fix overflow check for long ``--tls-cipher`` option


Bug fixes
---------
- Fix SIGSEGV crash on unaligned access on OpenBSD/sparc64

- Fix TCP_NODELAY on OpenBSD


Behavioural Changes
-------------------
- Ignore auth-nocache for auth-user-pass if auth-token is pushed


Version 2.3.16
==============

Security fixes
--------------
- Re-roll release because two different tarballs for 2.3.15 were created,
  one of them missing a relevant security fix.  2.3.16 has everything.

- Windows: Check for errors in the return value of ``GetModuleFileNameW()``


Bug fixes
---------
- Fix ``--redirect-gateway`` behaviour when an IPv4 default route does not exist


Version 2.3.15
==============

Security fixes
--------------
- Fix a pre-authentication denial-of-service attack on both clients and servers.
  By sending a too-large control packet, OpenVPN 2.3.12 and newer can be forced
  to hit an ASSERT() and stop the process.  If ``--tls-auth`` is used, only
  attackers that have the ``--tls-auth`` key can mount an attack.
  (OSTIF/Quarkslab audit finding 5.1, CVE-2017-7478)

- Fix an authenticated remote DoS vulnerability that could be triggered by
  causing a packet id roll over.  An attack is rather inefficient; a peer
  would need to get us to send at least about 196 GB of data.
  (OSTIF/Quarkslab audit finding 5.2, CVE-2017-7479)


Version 2.3.14
==============

Behavioral changes
------------------

- On the client side recursively routed packets, which have same destination
  as the VPN server, are dropped. This could be disabled with
  ``--allow-recursive-routing`` option.


Version 2.3.13
==============

- Enforcing a new default value for ``--reneg-bytes`` for known weaker ciphers

  Ciphers with cipher blocks less than 128 bits will now do a renegotiation
  of the tunnel by default for every 64MB of data.  This behaviour can be
  overridden by explicitly setting ``--reneg-bytes 0`` in the configuration file,
  however this is HIGHLY discouraged.

  This is to reduce the risk for SWEET32 attacks.  The general recommendation
  is to change the cipher to a stronger cipher.  For more information see:
  https://community.openvpn.net/openvpn/wiki/SWEET32

  OpenVPN will also complain a little bit more in the logs
  when such weaker ciphers is detected.



Version 2.3.12
==============

Security changes
----------------

- Deprecation of ciphers using less than 128-bits cipher blocks

  It is highly recommended to avoid using ciphers listed in the new
  deprecated section of ``--show-ciphers``.  These ciphers are no longer
  considered safe to use.  If you cannot migrate away from these
  ciphers currently, it is strongly recommended to start using
  ``--reneg-bytes`` with a value less than 64MB.


Version 2.3.11
==============

Behavioral changes
------------------

- Stricter default TLS cipher list: disable various old/weak ciphers.

  This can lead to 'no shared cipher' errors if one of the peers only accepts
  the older/weaker ciphers.  Check your ``--tls-cipher`` settings if this is
  the case.  Disabled ciphers:

  * Export ciphers (these are broken on purpose...)
  * Ciphers in the LOW and MEDIUM security cipher list of OpenSSL.
    The LOW group contains ciphers that are considered insecure (such as DES),
    and will be completely removed from OpenSSL in 1.1.0, the MEDIUM group
    contains less-secure ciphers like RC4 and SEED.
  * Ciphers that were not supported by OpenVPN anyway (cleans up the list)


Version 2.3.10
==============

New features
------------

- Windows version is detected, logged and possibly signalled to server

Behavioral changes
------------------

- PolarSSL support changed from PolarSSL v1.2 to PolarSSL v1.3,
  as v1.2 is end-of-support 2015-12-31.

- fall back to using interface names for netsh.exe calls on
  Windows XP (while keeping interface indexes on Windows 7)


Version 2.3.9
=============

New features
------------

- Windows DNS leak fix (--block-outside-dns, windows only)

- Client-side support for server restart notification

- IPv6 address information is now available as environment variables

- ``--auth-user-pass`` can now work with files that only have a username,
  and will then only prompt for password

Behavioral changes
------------------

- ``--sndbuf`` and ``--recvbuf`` default now to OS default instead of 64k

- Removed ``--enable-password-save`` from configure. This option is now
  always enabled.

- Use interface index when calling netsh.exe to configure IPv6
  addresses or routes on windows (instead of interface name)

- Properly reject client connect if ``--disabled`` option is used
  (in ccd/ or client-connect script/plugin)

- Handle Ctrl-C and Ctrl-BREAK events in Windows

- Do no longer exit if tap6 adapter returns error on Windows
  suspend/resume

- Increase control channel packet size for faster handshakes
  between TLS server and client


Bug fixes
---------

- Repair combination of ``--auth-user-pass``, ``--daemon`` and systemd
  (errors out in 2.3.8 instead of querying systemd)

- Lots of bug fixes and documentation improvements


Version 2.3.8
=============

Bug fixes
---------

- Fix various fallouts of the 2.3.7 change where we daemon()ize
  now first and initialize crypto later

- Lots of bug fixes and documentation improvements


Behavioral changes
------------------

- Print error message if trying to ask for username/password or 
  passphrase and no tty is available (--daemon)

- Delete ipv6 address on close of Linux tun interface
  (relevant for persistant tun interfaces)


Version 2.3.7
=============

Bug fixes
---------

- Lots of bug fixes and documentation improvements


New features
------------

- include ifconfig\_ environment variables in --up-restart env set

- Re-read auth-user-pass file on (re)connect if required


Behavioral changes
------------------

- Disallow usage of --server-poll-timeout in --secret key mode

- Re-enable TLS version negotiation by default

- daemon()ize before initializing crypto (= un-break cryptodev
  on FreeBSD that does not allow fork() after openssl init)

- On FreeBSD and topology subnet, construct a proper address
  for the remote side of the tun if (not our own)

- Fix interaction of ``--peer-id``, ``--link-mtu``, OCC and old/new
  OpenVPN combinations

- Always disable SSL compression


Version 2.3.6
=============

Bug fixes
---------

- A few bug fixes and documentation improvement

New features
------------

- Add client-only support for peer-id
- Add ``--tls-version-max``


Version 2.3.5
=============

Bug fixes
---------

- Fix server routes not working in topology subnet with ``--server`` [v3]
- Fix regression with password protected private keys (polarssl)
- Fix ``code=995`` bug with windows NDIS6 tap driver
- Lots of other bug fixes


Version 2.3.4
=============

Bug fixes
---------

- When ``--tls-version-min`` is unspecified, revert to original versioning approach
- IPv6 address/route delete fix for Win8
- Fix SOCKSv5 method selection
- Lots of other bug fixes and documentation improvements


Version 2.3.3
=============

Bug fixes
---------

- Fix slow memory drain on each client renegotiation
- Fix spurious ignoring of pushed config options (trac#349)
- Lots of bug fixes and documentation improvements


New features
------------

- Add reporting of UI version to basic push-peer-info set
- Add support to ignore specific options
- Add support of utun devices under Mac OS X
- Support non-ASCII TAP adapter names on Windows
- Support non-ASCII characters in Windows tmp path
- Added ``setenv opt`` directive prefix
- ``--management-external-key`` for PolarSSL
- Add support for ``--client-cert-not-required`` for PolarSSL


Behavioral changes
------------------

- TLS version negotiation
- Require polarssl >= 1.2.10 for polarssl-builds, which fixes CVE-2013-5915


Version 2.3.2
=============

Bug fixes
---------

- Fix ``--proto tcp6`` for server & non-P2MP modes
- Fix NULL-pointer crash in ``route_list_add_vpn_gateway()``
- Fix problem with UDP tunneling due to mishandled pktinfo structures
- Fix segfault when enabling pf plug-ins
- Lots of other bug fixes


New features
------------

- Always push basic set of peer info values to server
- make 'explicit-exit-notify' pullable again


Version 2.3.1
=============

Bug fixes
---------

- Repair "tcp server queue overflow" brokenness, more ``<stdbool.h>`` fallout
- Fix directly connected routes for "topology subnet" on Solaris
- Use constant time memcmp when comparing HMACs in openvpn_decrypt
- Lots of other bug fixes and documentation improvements


New features
------------

- reintroduce ``--no-name-remapping`` option
- make ``--tls-remote`` compatible with pre 2.3 configs
- add new option for X.509 name verification
- PolarSSL-1.2 support
- Enable TCP_NODELAY configuration on FreeBSD
- Permit pool size of /64.../112 for ifconfig-ipv6-pool


Behavioral changes
------------------

- Switch to IANA names for TLS ciphers


Version 2.3.0
=============

Bug fixes
---------

- Fix parameter type for IP_TOS setsockopt on non-Linux systems
- Fix client crash on double PUSH_REPLY

Version 2.3_rc2
===============

Bug fixes
---------

- Fix ``--show-pkcs11-ids`` (Bug #239)
- Lots of other bug fixes and documentation improvements


New features
------------

- Implement ``--mssfix`` handling for IPv6 packets


Version 2.3_rc1
===============

Bug fixes
---------

- Fixed a bug where PolarSSL gave an error when using an inline file tag
- Fix v3 plugins to support returning values back to OpenVPN
- Lots of other bug fixes and documentation improvements


New features
------------

- Support UTF-8 ``--client-config-dir``


Behavioral changes
------------------

- Remove the support for using system() when executing external programs or
  scripts


Version 2.3_beta1
=================

Bug fixes
---------

- Fixes error: ``--key`` fails with EXTERNAL_PRIVATE_KEY: No such file or directory
  if ``--management-external-key`` is used
- fix regression with ``--http-proxy[\-\*]`` options
- Lots of other bug fixes and documentation improvements


New features
------------

- Add ``--compat-names`` option
- add API for plug-ins to write to openvpn log


Behavioral changes
------------------

- Keep pre-existing tun/tap devices around on \*BSD


Version 2.3_alpha3
==================

Bug fixes
---------

- Repair "tap server" mode brokenness caused by <stdbool.h> fallout
- make non-blocking connect work on Windows
- A few other bug fixes


New features
------------

- add option ``--management-query-proxy``


Version 2.3_alpha2
==================

Bug fixes
---------

- Lots of other bug fixes and documentation improvements


New features
------------

- Add missing pieces to IPv6 route gateway handling


Behavioral changes
------------------

- Removed support for PolarSSL < 1.1
- Complete overhaul of the project structure and the buildsystem
- remove the --auto-proxy option from openvpn


Version 2.3-alpha1
==================

Bug fixes
---------

- Many \*BSD and Windows bug fixes
- Many Windows installer fixes
- Properly handle certificate serial numbers > 32 bits
- Fixed bug in port-share that could cause port share process to crash
- Fixed issue where a client might receive multiple push replies
- Lots of other bug fixes and documentation improvements


New features
------------

- PolarSSL support
- Add plug-in API v3
- IPv6 payload and transport support
- New feauture: Add ``--stale-routes-check``
- Add support to forward console query to systemd
- Windows UTF-8 input/output
- Added ``--management-external-key`` option
- Added ``--x509-track`` option
- Added ``--client-nat`` option for stateless, one-to-one NAT on the client side
- Extended ``client-kill`` management interface command
- Client will now try to reconnect if no push reply received within
  handshake-window seconds
- Added ``--management-external-key`` option
- Added ``--auth-token`` client directive
- Added ``dir`` flag to ``crl-verify``
- Added support for static challenge/response protocol
- Changed CC_PRINT character class to allow UTF-8 chars
- Extend output of "status" management interface command to include usernames
- Added "memstats" option to maintain real-time operating stats
- Added support for "on-link" routes on Linux client
- Add extv3 X509 field support to ``--x509-username-field``


Behavioral changes
------------------

- Remove support for Linux 2.2
- Make ``--win-sys env`` default
- Remove ``--enable-osxipconfig`` configure option
