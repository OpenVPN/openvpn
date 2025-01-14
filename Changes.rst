Overview of changes in 2.6.13
=============================
New features
------------
- on non-windows clients (MacOS, Linux, Unix) send "release" string from
  uname() call as IV_PLAT_VER= to server - while highly OS specific this
  is still helpful to keep track of OS versions used on the client side
  (GH #637)

- Windows: protect cached username, password and token in client memory
  (using the CryptProtectMemory() windows API

- Windows: use new API to get dco-win driver version from driver
  (newly introduced non-exclusive control device)  (GH: ovpn-dco-win #76)

- Linux: pass --timeout=0 argument to systemd-ask-password, to avoid
  default timeout of 90 seconds ("console prompting also has no timeout")
  (GH #649)


Bug fixes
---------
- fix potentially unaligned access in drop_if_recursive_routing on
  Linux (ASAN)

- correct documentation for port-share journal

- fix logging of IPv6 addresses in port-share journal

- fix various typos in messages, documentation, comments and examples
  (GH #442, GH #644)

- FreeBSD DCO: fix memory leaks in nvlist handling (GH #636)

- route handling: correctly handle case of "route installation fails"
  in the face of an already-existing route - previously, OpenVPN would
  remove the "other" route on exit, incorrectly changing system state.

- fix generation of warning messages for overlapping --local/--remote
  and --ifconfig addresses

- purge proxy authentication credentials from memory after use
  (if --auth-nocache is in use)

- fix missing space in various (long and wrapped) msg() calls


Code maintenance
----------------
- improve documentation/examples for <peer-fingerprint> feature

- simplify Github Action macOS build setup

- update Github Action macOS runners (remove macOS 12, add macOS 15)

- fix a number of uninitialized "struct user_pass" local variables
  (no impact beyond "compiler warning", but future-proofing the code)


Security fixes
--------------
- improve server-side handling of clients sending usernames or passwords
  longer than USER_PASS_LEN - this would not result in a crash, buffer
  overflow or other security issues, but the server would then misparse
  incoming IV_* variables and produce misleading error messages.


Overview of changes in 2.6.12
=============================
Bug fixes
---------
- the fix for CVE-2024-5594 (refuse control channel messages with
  nonprintable characters) was too strict, breaking user configurations
  with AUTH_FAIL messages having trailing CR/NL characters.  This often
  happens if the AUTH_FAIL reason is set by a script.  Strip those before
  testing the command buffer (Github: #568).  Also, add unit test.

- Http-proxy: fix bug preventing proxy credentials caching (Trac: #1187)

Code maintenance
----------------
- try to detect LZO installation with pkg-config (= on many systems
  manually setting LZO_CFLAGS/LZO_LIBS should no longer be necessary)

Overview of changes in 2.6.11
=============================
Security fixes
--------------
- CVE-2024-4877: Windows: harden interactive service pipe.
  Security scope: a malicious process with "some" elevated privileges
  (SeImpersonatePrivilege) could open the pipe a second time, tricking
  openvn GUI into providing user credentials (tokens), getting full
  access to the account openvpn-gui.exe runs as.
  (Zeze with TeamT5)

- CVE-2024-5594: control channel: refuse control channel messages with
  nonprintable characters in them.  Security scope: a malicious openvpn
  peer can send garbage to openvpn log, or cause high CPU load.
  (Reynir Björnsson)

- CVE-2024-28882: only call schedule_exit() once (on a given peer).
  Security scope: an authenticated client can make the server "keep the
  session" even when the server has been told to disconnect this client
  (Reynir Björnsson)

New features
------------
- Windows Crypto-API: Implement Windows CA template match for searching
  certificates in windows crypto store.

- support pre-created DCO interface on FreeBSD (OpenVPN would fail to
  set ifmode p2p/subnet otherwise)

Bugfixes
--------
- fix connect timeout when using SOCKS proxies (trac #328, github #267)

- work around LibreSSL crashing on OpenBSD 7.5 when enumerating ciphers
  (LibreSSL bug, already fixed upstream, but not backported to OpenBSD 7.5,
  see also https://github.com/libressl/openbsd/issues/150)

- Add bracket in fingerprint message and do not warn about missing
  verification (github #516)

Documentation
-------------
- remove "experimental" denotation for --fast-io

- correctly document ifconfig_* variables passed to scripts (script-options.rst)

- documentation: make section levels consistent

- samples: Update sample configurations
   remove compression & old cipher settings, add more informative comments

Code maintenance
----------------
- remove usage of <lzoutils.h> header & macro, discouraged by upstream

- only run coverity scans in OpenVPN/OpenVPN repository (= do not spam
  owners of cloned repos with "cannot run this" messages)

- replace macOS 11 github runners with macOS 14

- remove some unused code in misc.c (leftover from commit 3a4fb1)

- phase2_tcp_server: fix Coverity issue 'Dereference after null check'
  - the code itself was correct, just doing needless checks

- Use snprintf instead of sprintf for get_ssl_library_version
  - the code itself was correct, but macOS clang dislikes sprintf()


Overview of changes in 2.6.10
=============================
Security fixes
--------------
- CVE-2024-27459: Windows: fix a possible stack overflow in the
  interactive service component which might lead to a local privilege
  escalation.
  Reported-by: Vladimir Tokarev <vtokarev@microsoft.com>

- CVE-2024-24974: Windows: disallow access to the interactive service
  pipe from remote computers.
  Reported-by: Vladimir Tokarev <vtokarev@microsoft.com>

- CVE-2024-27903: Windows: disallow loading of plugins from untrusted
  installation paths, which could be used to attack openvpn.exe via
  a malicious plugin.  Plugins can now only be loaded from the OpenVPN
  install directory, the Windows system directory, and possibly from
  a directory specified by HKLM\SOFTWARE\OpenVPN\plugin_dir.
  Reported-by: Vladimir Tokarev <vtokarev@microsoft.com>

Bug fixes
---------
- Windows: if the win-dco driver is used (default) and the GUI requests
  use of a proxy server, the connection would fail.  Disable DCO in
  this case.  (Github: #522)

- Compression: minor bugfix in checking option consistency vs. compiled-in
  algorithm support

- systemd unit files: remove obsolete syslog.target

User visible changes
--------------------
- Update copyright notices to 2024

New features
------------
- t_client.sh can now run pre-tests and skip a test block if needed
  (e.g. skip NTLM proxy tests if SSL library does not support MD4)

Documentation
-------------
- remove license warnings about mbedTLS linking (README.mbedtls)

- update documentation references in systemd unit files

- sample config files: remove obsolete tls-*.conf files

- document that auth-user-pass may be inlined


Overview of changes in 2.6.9
============================

Security fixes
--------------
- Windows Installer: fix CVE 2023-7235 where installing to a non-default
  directory could lead to a local privilege escalation.
  Reported by Will Dormann <will.dormann@analygence.com>.

New features
------------
- add support for building with mbedTLS 3.x.x

- new option "--force-tls-key-material-export" to only accept clients
  that can do TLS keying material export to generate session keys
  (mostly an internal option to better deal with TLS 1.0 PRF failures).

- Windows: bump vcpkg-ports/pkcs11-helper to 1.30

- Log incoming SSL alerts in easier to understand form and move logging
  from "--verb 8" to "--verb 3".

- protocol_dump(): add support for printing "--tls-crypt" packets


User visible changes
--------------------
- license change is now complete, and all code has been re-licensed
  under the new license (still GPLv2, but with new linking exception
  for Apache2 licensed code).  See COPYING for details.

  Code that could not be re-licensed has been removed or rewritten.

- the original code for the "--tls-export-cert" feature has been removed
  (due to the re-licensing effort) and rewritten without looking at the
  original code.  Feature-compatibility has been tested by other developers,
  looking at both old and new code and documentation, so there *should*
  not be a user-visible change here.

- IPv6 route addition/deletion are now logged on the same level (3) as
  for IPv4.  Previously IPv6 was always logged at "--verb 1".

- better handling of TLS 1.0 PRF failures in the underlying SSL library
  (e.g. on some FIPS builds) - this is now reported on startup, and
  clients before 2.6.0 that can not use TLS EKM to generate key material
  are rejected by the server.  Also, error messages are improved to see
  what exactly failed.

- packaged sample-keys renewed (old keys due to expire in October 2024)


Bug fixes / Code cleanup
------------------------
- Windows GUI: always update tray icon on state change (Github: #669)
  (for persistent connection profiles, "connecting" state would not show)

- FreeBSD: for servers with multiple clients, reporting of peer traffic
  statistics would fail due to insufficient buffer space (Github: #487)

- make interaction between "--http-proxy-user-pass" and "--http-proxy"
  more consistent

- doc: improve documentation on "--http-proxy-user-pass"

- doc: improve documentation for IV_ variables and IV_PROTO bits

- doc: improve documentation on CMake requirements

- fix various coverity-reported complains (signed/unsigned comparison etc),
  none of them actual bugs

- NTLMv2: increase phase 2 buffers so things actually work

- NTLM: add extra buffer size verification checks

- doc: improve documentation on "--tls-crypt-v2-verify"

- autoconf on Linux: improve error reporting for missing libraries - in
  case the problem came due to missing "pkg-config" the previous error
  was misleading.  Now clearly report that Linux builds require "pkg-config"
  and abort if not found.

- MacOS X: fix "undefined behaviour" found by UBSAN in get_default_gateway()
  (IV_HWADDR), using getifaddrs(3) instead of old and convoluted
  SIOCGIFCONF API.

- OpenSolaris: correctly implement get_default_gateway() (IV_HWADDR), using
  SIOCGIFHWADDR instead of SIOCGIFCONF API.

- OpenBSD: work around route socket issue in get_default_gateway()
  ("--show-gateway") where RA_IFP must not be set on the query message,
  otherwise kernel will return EINVAL.

- doc: improve documentation of --x509-track

- bugfix: in UDP mode when exceeding "--max-clients", OpenVPN would
  incorrectly close the connection to "peer-id 0".  Fix by correctly
  initializing peer_id with MAX_PEER_ID.

- Windows: do not attempt to delete DNS or WINS servers if they are not set

- configure: get rid of AC_TYPE_SIGNAL macro (unused)

- Linux DCO: add missing check for nl_socket_alloc() failure

- bugfix: check_session_buf_not_used() was not working as planned

- remove dead test code for TEST_GET_DEFAULT_GATEWAY (use "--show-gateway")

- doc: better document "--tls-exit" option

- Github Actions: clean up LibreSSL builds



Overview of changes in 2.6.8
============================

Bug fixes / Code cleanup
------------------------
- SIGSEGV crash: Do not check key_state buffers that are in S_UNDEF state
  (Github #449) - the new sanity check function introduced in 2.6.7
  sometimes tried to use a NULL pointer after an unsuccessful TLS handshake

- Windows: --dns option did not work when tap-windows6 driver was used,
  because internal flag for "apply DNS option to DHCP server" wasn't set
  (Github #447)

- Windows: fix status/log file permissions, caused by regression after
  changing to CMake build system (Github: #454, Trac: #1430)

- Windows: fix --chdir failures, also caused by error in CMake build system
  (Github #448)

- doc: fix typos in documentation

User visible changes
--------------------
- Windows: print warning if pushed options require DHCP (e.g. DOMAIN-SEARCH)
  and driver in use does not use DHCP (wintun, dco).


Overview of changes in 2.6.7
============================

Bug fixes / Code cleanup
------------------------
- CVE-2023-46850 OpenVPN versions between 2.6.0 and 2.6.6 incorrectly use
  a send buffer after it has been free()d in some circumstances, causing
  some free()d memory to be sent to the peer.  All configurations using TLS
  (e.g. not using --secret) are affected by this issue.
  (found while tracking down CVE-2023-46849 / Github #400, #417)

- CVE-2023-46849 OpenVPN versions between 2.6.0 and 2.6.6 incorrectly
  restore "--fragment" configuration in some circumstances, leading to
  a division by zero when "--fragment" is used.  On platforms where
  division by zero is fatal, this will cause an OpenVPN crash.

  Reported by Niccolo Belli <niccolo.belli@linuxsystems.it> and WIPocket
  (Github #400, #417).

- cleanup bits and pieces of documentation

- cleanup code to remove strlen() related warnings in buf_catrunc()

- DCO on Linux: fix NULL-pointer crash if "--multihome" is used together
  with "--proto tcp"

- work around build fails caused by LibreSSL not longer having engine support


User visible changes
--------------------
- DCO: warn if DATA_V1 packets are sent by the other side - this a hard
  incompatibility between a 2.6.x client connecting to a 2.4.0-2.4.4 server,
  and the only fix is to use "--disable-dco".

- Remove OpenSSL Engine method for loading a key.  This had to be removed
  because the original author did not agree to relicensing the code with
  the new linking exception added.  This was a somewhat obsolete feature
  anyway as it only worked with OpenSSL 1.x, which is end-of-support.

- add warning if p2p NCP client connects to a p2mp server - this is a
  combination that used to work without cipher negotiation (pre 2.6 on
  both ends), but would fail in non-obvious ways with 2.6 to 2.6.

- add warning to "--show-groups" that not all supported groups are listed
  (this is due the internal enumeration in OpenSSL being a bit weird,
  omitting X448 and X25519 curves).

- "--dns": remove support for "exclude-domains" argument
  (this was a new 2.6 option, with no backend support implemented yet
  on any platform, and it turns out that no platform supported it at all -
  so remove option again)

- warn user if INFO control message too long, do not forward to management
  client (safeguard against protocol-violating server implementations)


New features
------------
- DCO-WIN: get and log driver version (for easier debugging).

- print "peer temporary key details" in TLS handshake

- log OpenSSL errors on failure to set certificate, for example if the
  algorithms used are in acceptable to OpenSSL (misleading message would
  be printed in cryptoapi / pkcs#11 scenarios)

- add CMake build system for MinGW and MSVC builds

- remove old MSVC build system

- improve cmocka unit test building for Windows


Overview of changes in 2.6.6
============================

User visible changes
--------------------
- OCC exit messages are now logged more visibly
  (Github #391)

- OpenSSL error messages are now logged with more details (for example,
  when loading a provider fails, which .so was tried, and why did it fail)
  (Github #361)

- print a more user-friendly message when tls-crypt-v2 client auth fails

- packaging now includes all documentation in the tarball


New features
------------
- set WINS server via interactive service - this adds support for
  "dhcp-option WINS 192.0.2.1" for DCO + wintun interfaces where no
  DHCP server is used (Github #373).

Bug fixes / Code cleanup
------------------------
- route.c was sometimes ignoring return values of add_route3()
  (found by coverity)

- ntlm: clarify use of buffer in case of truncated NTLM challenge,
  no actual code change (reported by Trial of Bits, TOB-OVPN-14)

- pkcs11_openssl.c: disable unused code (found by coverity)

- options.c: do not hide variable from parent scope (found by coverity)

- configure: fix typo in LIBCAPNG_CFALGS (Github #371)

- ignore IPv6 route deletion request on Android, reduce IPv4 route-related
  message verbosity on Android

- manage.c: document missing KID parameter of "client-pending-auth"
  (new addition in da083c3b (2.6.2)) in manage interface help text

- vpn-network-options.rst: fix typo of "dhcp-option" (Github #313)

- tun.c/windows: quote WMIC call to set DHCP/DNS domain with hyphen
  (Github #363)

- fix CR_RESPONSE management message using wrong key_id

- work around false positive compiler warnings with MinGW 12

- work around false positive compiler warnings with GCC 12.2.0

- fix more compiler warnings on FreeBSD

- test_tls_crypt: improve cmocka testing portability

- dco-linux: fix counter print format (signed/unsigned)

- packaging: include everything that is needed for a MSVC build in tarballs
  (Github #344)


Overview of changes in 2.6.5
============================

User visible changes
--------------------
- tapctl (windows): generate driver-specific names (if using tapctl to
  create additional tap/wintun/dco devices, and not using --name)
  (Github #337)

- interactive service (windows): do not force target desktop for
  openvpn.exe - this has no impact for normal use, but enables running
  of OpenVPN in a scripted way when no user is logged on (for example,
  via task scheduler) (Github OpenVPN/openvpn-gui#626)

Bug fixes
---------
- fix use-after-free with EVP_CIPHER_free

- fix building with MSVC from release tarball (missing version.m4.in)

- dco-win: repair use of --dev-node to select specific DCO drivers
  (Github #336)

- fix missing malloc() return check in dco_freebsd.c

- windows: correctly handle unicode names for "exit event"

- fix memleak in client-connect example plugin

- fix fortify build problem in keying-material-exporter-demo plugin

- fix memleak in dco_linux.c/dco_get_peer_stats_multi() - this will
  leak a small amount of memory every 15s on DCO enabled servers,
  leading to noticeable memory waste for long-running processes.

- dco_linux.c: properly close dco version file (fd leak)


Overview of changes in 2.6.4
============================

User visible changes
--------------------
- License amendment: all NEW commits fall under a modified license that
  explicitly permits linking with Apache2 libraries (mbedTLS, OpenSSL) -
  see COPYING for details.  Existing code will fall under the new license
  as soon as all contributors have agreed to the change - work ongoing.

New features
------------
- DCO: support kernel-triggered key rotation (avoid IV reuse after 2^32
  packets).  This is the userland side, accepting a message from kernel,
  and initiating a TLS renegotiation.  As of release, only implemented in
  FreeBSD kernel.

Bug fixes
---------
- fix pkcs#11 usage with OpenSSL 3.x and PSS signing (Github #323)

- fix compile error on TARGET_ANDROID

- fix typo in help text

- manpage updates (--topology)

- encoding of non-ASCII windows error messages in log + management fixed
  (use UTF8 "as for everything else", not ANSI codepages)  (Github #319)


Overview of changes in 2.6.3
============================

New features
------------
- Windows: support setting DNS domain in configurations without DHCP
  (typically wintun or windco drivers), see GH OpenVPN/openvpn#306.

Bug fixes
---------
- fix possible crash with Linux client on reconnect on TLS errors
  (needs either "--status file" or active management interface to trigger)

- fix incorrect formatting in .rst documents

- Windows .msi installer: ensure interactive service stays enabled after
  silent reinstall, see GH OpenVPN/openvpn-build#348, #349 and #351

- Windows installer: repair querying install path info for easyrsa-start.bat
  on some Windows language versions, see GH OpenVPN/openvpn-build#352.

- Windows DCO driver: use correct crypto library so it loads on x86,
  see GH OpenVPN/ovpn-dco-win#43



Overview of changes in 2.6.2
============================

New features
------------
- implement byte counter statistics for DCO Linux (p2mp server and client)

- implement byte counter statistics for DCO Windows (client only)

- '--dns server <n> address ...' now permits up to 8 v4 or v6 addresses

- fix a few cases of possibly undefined behaviour detected by ASAN

- add more unit tests for Windows cryptoapi interface


Bug fixes
---------
- sending of AUTH_PENDING and INFO_PRE messages fixed (OpenVPN/openvpn#256)

- Windows: do not treat "setting IPv6 interface metric failed" as fatal
  error on "block-dns" install - this can happen if IPv6 is disabled on
  the interface and is not harmful in itself (GH #294)

- fix '--inactive' if DCO is in use
  NOTE: on FreeBSD, this is not working yet (missing per-peer stats)

- DCO-Linux: do not print errno on netlink errors (errno is not set by NL)

- SOCKS client: improve error reporting on server disconnects

- DCO-Linux: fix lockups due to netlink buffer overflows on high
  client connect/disconnect activity.  See "User visible changes" for
  more details of this.

- fix some uses of the OpenSSL3 API for non-default providers
  (enable use of quantum-crypto OpenSSL provider)

- fix memory leak of approx. 1600 bytes per incoming initial TLS packet

- fix bug when using ECDSA signatures with OpenSSL 3.0.x and pkcs11-helper
  (data format conversion was not done properly)

- fix 'make distcheck' - unexpected side effect of 'subdir-objects'

- fix ASSERT() with dynamic tls-crypt and --tls-crypt-v2 (GH #272)


User visible changes
--------------------
- print (kernel) DCO version on startup - helpful for getting a more
  complete picture of the environment in use.

- New control packets flow for data channel offloading on Linux.
  2.6.2+ changes the way OpenVPN control packets are handled on
  Linux when DCO is active, fixing the lockups observed with 2.6.0/2.6.1
  under high client connect/disconnect activity.
  This is an *INCOMPATIBLE* change and therefore an ovpn-dco kernel
  module older than v0.2.20230323 (commit ID 726fdfe0fa21) will not
  work anymore and must be upgraded.  The kernel module was renamed to
  "ovpn-dco-v2.ko" in order to highlight this change and ensure that
  users and userspace software could easily understand which version
  is loaded.  Attempting to use the old ovpn-dco with 2.6.2+ will
  lead to disabling DCO at runtime.

- The ``client-pending-auth`` management command now requires also the
  key id. The management version has been changed to 5 to indicate this change.

- A client will now refuse a connection if pushed compression settings
  will contradict the setting of ``allow-compression`` as this almost
  always results in a non-working connection.


Overview of changes in 2.6.1
============================

New features
------------
- Dynamic TLS Crypt
  When both peers are OpenVPN 2.6.1+, OpenVPN will dynamically create
  a tls-crypt key that is used for renegotiation. This ensure that only the
  previously authenticated peer can do trigger renegotiation and complete
  renegotiations.

- CryptoAPI (Windows): support issuer name as a selector.
  Certificate selection string can now specify a partial
  issuer name string as "--cryptoapicert ISSUER:<string>" where
  <string> is matched as a substring of the issuer (CA) name in
  the certificate.


User visible changes
--------------------
- on crypto initialization, move old "quite verbose" messages to --verb 4
  and only print a more compact summary about crypto and timing parameters
  by default

- configure now enables DCO build by default on FreeBSD and Linux, which
  brings in a default dependency for libnl-genl (for Linux distributions
  that are too old to have this library, use "configure --disable-dco")

- make "configure --help" output more consistent

- CryptoAPI (Windows): remove support code for OpenSSL before 3.0.1
  (this will not affect official OpenVPN for Windows installers, as they
  will always be built with OpenSSL 3.0.x)

- CryptoAPI (Windows): log the selected certificate's name

- "configure" now uses "subdir-objects", for automake >= 1.16
  (less warnings for recent-enough automake versions, will change
  the way .o files are created)


Bugfixes / minor improvements
-----------------------------
- fixed old IPv6 ifconfig race condition for FreeBSD 12.4 (trac #1226)

- fix compile-time breakage related to DCO defines on FreeBSD 14

- enforce minimum packet size for "--fragment" (avoid division by zero)

- some alignment fixes to avoid unaligned memory accesses, which will
  bring problems on some architectures (Sparc64, some ARM versions) -
  found by USAN clang checker

- windows source code fixes to reduce number of compile time warnings
  (eventual goal is to be able to compile with -Werror on MinGW), mostly
  related to signed/unsigned char * conversions, printf() format specifiers
  and unused variables.

- avoid endless loop on logging with --management + --verb 6+

- build (but not run) unit tests on MinGW cross compiles, and run them
  when building with GitHub Actions.

- add unit test for parts of cryptoapi.c

- add debug logging to help with diagnosing windows driver selection

- disable DCO if proxy config is set via management interface

- do not crash on Android if run without --management

- improve documentation about cipher negotiation and OpenVPN3

- for x86 windows builds, use proper calling conventions for dco-win
  (__stdcall)

- differentiate "dhcp-option ..." options into "needs an interface with
  true DHCP service" (tap-windows) and "can also be installed by IPAPI
  or service, and can be used on non-DHCP interfaces" (wintun, dco-win)

- windows interactive service: fix possible double-free if "--block-dns"
  installation fails due to "security products" interfering
  (Github OpenVPN/openvpn#232)

- "make dist": package ovpn_dco_freebsd.h to permit building from tarballs
  on FreeBSD 14


Overview of changes in 2.6.0, relative to 2.6_rc2
=================================================

(See below for changes in 2.6 relative to 2.5)

New features
------------
- no new features relative to 2.6_rc2

User-Visible Changes
--------------------
- no user-visible changes relative to 2.6_rc2

Bugfixes / minor improvements
-----------------------------
- repair handling of "route already exists" errors for Linux/sitnl builds,
  which would lead to erroneous attempts to remove routes later on, possibly
  removing "non openvpn installed" routes.

- repair error handling for Linux/iproute2 builds - this was ignoring
  all errors on route installation, causing issues on route removal.

- improve logging (errors and debug messages) for route handling on Windows

- print warning if pkcs11-id or pkcs11-id-management options are used but
  no pkcs11-providers has been selected

- openvpnmsica: improve handling of win-dco driver (use MSM now)

- for Linux/DCO builds, increase libnl buffer size to reduce propability
  of ENOBUFS occurance if kernel-to-userland netlink queue overruns
  (bandaid fix)

- re-enable use of suid binaries in scripts run by OpenVPN - new
  capability-handling code was too strict and cleared all capabilities,
  breaking users' use of "sudo" (etc) in scripts (Github OpenVPN/openvpn#220).


Overview of changes in 2.6_rc2
==============================
New features
------------
- ``remote-entry-get`` management command will now show enabled/disabled
  status for each connection entry

- report ``CONNECTED,ROUTE_ERROR`` to management GUI if connection to
  server succeeds but not all routes can be installed (Windows and
  Linux/Netlink only, so far)

- add rate limiter for incoming "initial handshake packets", enabled by
  default with a limit of 100 packets per 10 seconds.  New option
  ``--connect-freq-initial`` to configure values.  This change makes
  OpenVPN servers uninteresting as an UDP reflection DDoS engine.

User-Visible Changes
--------------------
- OCC (options compatibility check) log messages are considered obsolete
  and are only shown on loglevel 7 or higher now

- copyright line has been updated in all files to "xxx-2023"

- include peer-id=nn in multi prefix for DCO servers if loglevel is 7+
  (helps with DCO debugging)

Bugfixes / minor improvements
-----------------------------
- improve documentation on no-longer-supported options

- reduce amount of log messages about "dco_update_keys: peer_id=-1"

- undo FreeBSD "ipv6 ifconfig" workaround for FreeBSD 12.4 and up (Trac 1226)

- fix signal handling issues where a SIGUSR1 "restart" signal could overwrite
  a SIGTERM/SIGINT "please end!" signal already queued, making OpenVPN hard
  to stop (Trac 311, Trac 639, GH issue #205)

- fix signal handling issues on windows, where OpenVPN could not be
  interrupted by ctrl-c when sleep()ing between connection attempts

- use IPAPI for IPv6 route installation on Windows, if OpenVPN runs without
  service pipe ("run as admin from cmd.exe")

- fix spurious DCO log messages about "peer-id unknown to OpenVPN: -1"

- on Windows, repair wintun buffer cleanup on program end


Overview of changes in 2.6_rc1
==============================

New features
------------
Support unlimited number of connection entries and remote entries

New management commands to enumerate and list remote entries
    Use ``remote-entry-count`` and ``remote-entry-get``
    commands from the management interface to get the number of
    remote entries and the entries themselves.


Bugfixes / minor improvements
-----------------------------
Improve DCO-related logging in many places.

DCO/Linux robustness fixes.

DCO/Linux TCP crashbug (recvfrom(-1) endless loop) worked around - root
    cause has not been found, but the condition is detected and the
    offending client is removed, instead of crashing the server.

Rename internal TLS state TM_UNTRUSTED to TM_INITIAL, always start new
    peer handshake (new connect or renegotiation) in TM_INITIAL state.

Upgrade Windows build environment to MSVC 2022

Make management password check constant time

Repair keepalive and mss setting in DCO peer-to-peer mode.

Persist DCO client data channel traffic stats on restart (Windows only).

Do not include auth-token in pulled option digest.

Reduce default restart pause (--connect-retry) to 1 second.

Deprecate NTLMv1 proxy auth method.

Fix possible buffer-overrun in command line and ccd/ argument parsing.

Fix memleak if creating deferred auth control files fails


Overview of changes in 2.6_beta2
================================

New features
------------
Transport statistics (bytes in/out) for DCO environments
    With DCO, OpenVPN userland will not see data packets and can not
    count them, thus, no statistics.  This feature implements server-side
    statistics for FreeBSD+DCO and client-side statistics for Windows+DCO,
    Linux and FreeBSD client will follow.

pkcs11-helper updates
    improve shared library loading on Windows, so "copy .dll to application
    directory" recipes should no longer be necessary for pkcs#11 providers

Bugfixes / minor improvements
-----------------------------
- add proper documentation for tls-crypt-v2 metadata limits, and better
  error messages when these are exceeded

- trigger SIGUSR1 if dco_update_keys() fails - this is, when OpenVPN
  userland and kernel side key handling gets out of sync, restart instance
  to recover.

- improve logging for DCO key update handling

- ignore incoming client connects while server is being shutdown
  (Github: OpenVPN/openvpn#189)

- disable DCO for p2p modes with no crypto or --secret pre-shared key
  (= everything that is not TLS)

- fix endianness issues for TLS cookie handling and unit test



Overview of changes in 2.6
==========================

Project changes
---------------

We want to deprecate our old Trac bug tracking system.
Please report any issues with this release in GitHub
instead: https://github.com/OpenVPN/openvpn/issues

New features
------------
Keying Material Exporters (RFC 5705) based key generation
    As part of the cipher negotiation OpenVPN will automatically prefer
    the RFC5705 based key material generation to the current custom
    OpenVPN PRF. This feature requires OpenSSL or mbed TLS 2.18+.

Compatibility with OpenSSL in FIPS mode
    OpenVPN will now work with OpenSSL in FIPS mode. Note, no effort
    has been made to check or implement all the
    requirements/recommendation of FIPS 140-2. This just allows OpenVPN
    to be run on a system that be configured OpenSSL in FIPS mode.

``mlock`` will now check if enough memlock-able memory has been reserved,
    and if less than 100MB RAM are available, use setrlimit() to upgrade
    the limit.  See Trac #1390.  Not available on OpenSolaris.

Certificate pinning/verify peer fingerprint
    The ``--peer-fingerprint`` option has been introduced to give users an
    easy to use alternative to the ``tls-verify`` for matching the
    fingerprint of the peer. The option takes use a number of allowed
    SHA256 certificate fingerprints.

    See the man page section "Small OpenVPN setup with peer-fingerprint"
    for a tutorial on how to use this feature. This is also available online
    under https://github.com/openvpn/openvpn/blob/master/doc/man-sections/example-fingerprint.rst

TLS mode with self-signed certificates
    When ``--peer-fingerprint`` is used, the ``--ca`` and ``--capath`` option
    become optional. This allows for small OpenVPN setups without setting up
    a PKI with Easy-RSA or similar software.

Deferred auth support for scripts
    The ``--auth-user-pass-verify`` script supports now deferred authentication.

Pending auth support for plugins and scripts
    Both auth plugin and script can now signal pending authentication to
    the client when using deferred authentication. The new ``client-crresponse``
    script option and ``OPENVPN_PLUGIN_CLIENT_CRRESPONSE`` plugin function can
    be used to parse a client response to a ``CR_TEXT`` two factor challenge.

    See ``sample/sample-scripts/totpauth.py`` for an example.

Compatibility mode (``--compat-mode``)
    The modernisation of defaults can impact the compatibility of OpenVPN 2.6.0
    with older peers. The options ``--compat-mode`` allows UIs to provide users
    with an easy way to still connect to older servers.

OpenSSL 3.0 support
    OpenSSL 3.0 has been added. Most of OpenSSL 3.0 changes are not user visible but
    improve general compatibility with OpenSSL 3.0. ``--tls-cert-profile insecure``
    has been added to allow selecting the lowest OpenSSL security level (not
    recommended, use only if you must). OpenSSL 3.0 no longer supports the Blowfish
    (and other deprecated) algorithm by default and the new option ``--providers``
    allows loading the legacy provider to renable these algorithms.

Optional ciphers in ``--data-ciphers``
    Ciphers in ``--data-ciphers`` can now be prefixed with a ``?`` to mark
    those as optional and only use them if the SSL library supports them.


Improved ``--mssfix`` and ``--fragment`` calculation
    The ``--mssfix`` and ``--fragment`` options now allow an optional :code:`mtu`
    parameter to specify that different overhead for IPv4/IPv6 should taken into
    account and the resulting size is specified as the total size of the VPN packets
    including IP and UDP headers.

Cookie based handshake for UDP server
    Instead of allocating a connection for each client on the initial packet
    OpenVPN server will now use an HMAC based cookie as its session id. This
    way the server can verify it on completing the handshake without keeping
    state. This eliminates the amplification and resource exhaustion attacks.
    For tls-crypt-v2 clients, this requires OpenVPN 2.6 clients or later
    because the client needs to resend its client key on completing the hand
    shake. The tls-crypt-v2 option allows controlling if older clients are
    accepted.

    By default the rate of initial packet responses is limited to 100 per 10s
    interval to avoid OpenVPN servers being abused in reflection attacks
    (see ``--connect-freq-initial``).

Data channel offloading with ovpn-dco
    2.6.0+ implements support for data-channel offloading where the data packets
    are directly processed and forwarded in kernel space thanks to the ovpn-dco
    kernel module. The userspace openvpn program acts purely as a control plane
    application. Note that DCO will use DATA_V2 packets in P2P mode, therefore,
    this implies that peers must be running 2.6.0+ in order to have P2P-NCP
    which brings DATA_V2 packet support.

Session timeout
    It is now possible to terminate a session (or all) after a specified amount
    of seconds has passed session commencement. This behaviour can be configured
    using ``--session-timeout``. This option can be configured on the server, on
    the client or can also be pushed.

Inline auth username and password
    Username and password can now be specified inline in the configuration file
    within the <auth-user-pass></auth-user-pass> tags. If the password is
    missing OpenVPN will prompt for input via stdin. This applies to inline'd
    http-proxy-user-pass too.

Tun MTU can be pushed
    The  client can now also dynamically configure its MTU and the server
    will try to push the client MTU when the client supports it. The
    directive ``--tun-mtu-max`` has been introduced to increase the maximum
    pushable MTU size (defaults to 1600).

Improved control channel packet size control (``max-packet-size``)
    The size of control channel is no longer tied to
    ``--link-mtu``/``--tun-mtu`` and can be set using ``--max-packet-size``.
    Sending large control channel frames is also optimised by allowing 6
    outstanding packets instead of just 4. ``max-packet-size`` will also set
    ``mssfix`` to try to limit data-channel packets as well.

Deprecated features
-------------------
``inetd`` has been removed
    This was a very limited and not-well-tested way to run OpenVPN, on TCP
    and TAP mode only.

``verify-hash`` has been deprecated
    This option has very limited usefulness and should be replaced by either
    a better ``--ca`` configuration or with a ``--tls-verify`` script.

``secret`` has been deprecated
    static key mode (non-TLS) is no longer considered "good and secure enough"
    for today's requirements.  Use TLS mode instead.  If deploying a PKI CA
    is considered "too complicated", using ``--peer-fingerprint`` makes
    TLS mode about as easy as using ``--secret``.

``ncp-disable`` has been removed
    This option mainly served a role as debug option when NCP was first
    introduced. It should now no longer be necessary.

TLS 1.0 and 1.1 are deprecated
    ``tls-version-min`` is set to 1.2 by default.  OpenVPN 2.6.0 defaults
    to a minimum TLS version of 1.2 as TLS 1.0 and 1.1 should be generally
    avoided. Note that OpenVPN versions older than 2.3.7 use TLS 1.0 only.

``--cipher`` argument is no longer appended to ``--data-ciphers``
    by default. Data cipher negotiation has been introduced in 2.4.0
    and been significantly improved in 2.5.0. The implicit fallback
    to the cipher specified in ``--cipher`` has been removed.
    Effectively, ``--cipher`` is a no-op in TLS mode now, and will
    only have an effect in pre-shared-key mode (``--secret``).
    From now on ``--cipher`` should not be used in new configurations
    for TLS mode.
    Should backwards compatibility with older OpenVPN peers be
    required, please see the ``--compat-mode`` instead.

``--prng`` has beeen removed
    OpenVPN used to implement its own PRNG based on a hash. However implementing
    a PRNG is better left to a crypto library. So we use the PRNG
    mbed TLS or OpenSSL now.

``--keysize`` has been removed
    The ``--keysize`` option was only useful to change the key length when using the
    BF, CAST6 or RC2 ciphers. For all other ciphers the key size is fixed with the
    chosen cipher. As OpenVPN v2.6 no longer supports any of these variable length
    ciphers, this option was removed as well to avoid confusion.

Compression no longer enabled by default
    Unless an explicit compression option is specified in the configuration,
    ``--allow-compression`` defaults to ``no`` in OpeNVPN 2.6.0.
    By default, OpenVPN 2.5 still allowed a server to enable compression by
    pushing compression related options.

PF (Packet Filtering) support has been removed
   The built-in PF functionality has been removed from the code base. This
   feature wasn't really easy to use and was long unmaintained.
   This implies that also ``--management-client-pf`` and any other compile
   time or run time related option do not exist any longer.

Option conflict checking is being deprecated and phased out
    The static option checking (OCC) is no longer useful in typical setups
    that negotiate most connection parameters. The ``--opt-verify`` and
    ``--occ-disable`` options are deprecated, and the configure option
    ``--enable-strict-options`` has been removed. Logging of mismatched
    options has been moved to debug logging (verb 7).

User-visible Changes
--------------------
- CHACHA20-POLY1305 is included in the default of ``--data-ciphers`` when available.
- Option ``--prng`` is ignored as we rely on the SSL library random number generator.
- Option ``--nobind`` is default when ``--client`` or ``--pull`` is used in the configuration
- :code:`link_mtu` parameter is removed from environment or replaced with 0 when scripts are
  called with parameters. This parameter is unreliable and no longer internally calculated.

- control channel packet maximum size is no longer influenced by
  ``--link-mtu``/``--tun-mtu`` and must be set by ``--max-packet-size`` now.
  The default is 1250 for the control channel size.

- In point-to-point OpenVPN setups (no ``--server``), using
  ``--explict-exit-notiy`` on one end would terminate the other side at
  session end.  This is considered a no longer useful default and has
  been changed to "restart on reception of explicit-exit-notify message".
  If the old behaviour is still desired, ``--remap-usr1 SIGTERM`` can be used.

- FreeBSD tun interfaces with ``--topology subnet`` are now put into real
  subnet mode (IFF_BROADCAST instead of IFF_POINTOPOINT) - this might upset
  software that enumerates interfaces, looking for "broadcast capable?" and
  expecting certain results.  Normal uses should not see any difference.

- The default configurations will no longer allow connections to OpenVPN 2.3.x
  peer or earlier, use the new ``--compat-mode`` option if you need
  compatibility with older versions. See the manual page on the
  ``--compat-mode`` for details.

Common errors with OpenSSL 3.0 and OpenVPN 2.6
----------------------------------------------
Both OpenVPN 2.6 and OpenSSL 3.0 tighten the security considerable, so some
configuration will no longer work. This section will cover the most common
causes and error message we have seen and explain their reason and temporary
workarounds. You should fix the underlying problems as soon as possible since
these workaround are not secure and will eventually stop working in a future
update.

- weak SHA1 or MD5 signature on certificates

  This will happen on either loading of certificates or on connection
  to a server::

      OpenSSL: error:0A00018E:SSL routines::ca md too weak
      Cannot load certificate file cert.crt
      Exiting due to fatal error

  OpenSSL 3.0 no longer allows weak signatures on certificates. You can
  downgrade your security to allow them by using ``--tls-cert-profile insecure``
  but should replace/regenerate these certificates as soon as possible.


- 1024 bit RSA certificates, 1024 bit DH parameters, other weak keys

  This happens if you use private keys or other cryptographic material that
  does not meet today's cryptographic standards anymore. Messages are similar
  to::

      OpenSSL: error:0A00018F:SSL routines::ee key too small
      OpenSSL: error:1408518A:SSL routines:ssl3_ctx_ctrl:dh key too small

  DH parameters (``--dh``) can be regenerated with ``openssl dhparam 2048``.
  For other cryptographic keys, these keys and certificates need to be
  regenerated. TLS Security level can be temporarily lowered with
  ``--tls-cert-profile legacy`` or even ``--tls-cert-profile insecure``.

- Connecting to a OpenVPN 2.3.x server or allowing OpenVPN 2.3.x or earlier
  clients

  This will normally result in messages like::

     OPTIONS ERROR: failed to negotiate cipher with server.  Add the server's cipher ('AES-128-CBC') to --data-ciphers (currently 'AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305') if you want to connect to this server.

     or

     client/127.0.0.1:49954 SENT CONTROL [client]: 'AUTH_FAILED,Data channel cipher negotiation failed (no shared cipher)' (status=1)

  You can manually add the missing cipher to the ``--data-ciphers``. The
  standard ciphers should be included as well, e.g.
  ``--data-ciphers AES-256-GCM:AES-128-GCM:?Chacha20-Poly1305:?AES-128-CBC``.
  You can also use the ``--compat-mode`` option. Note that these message may
  also indicate other cipher configuration problems. See the data channel
  cipher negotiation manual section for more details. (Available online under
  https://github.com/OpenVPN/openvpn/blob/master/doc/man-sections/cipher-negotiation.rst)

- Use of a legacy or deprecated cipher (e.g. 64bit block ciphers)

  OpenSSL 3.0 no longer supports a number of insecure and outdated ciphers in
  its default configuration. Some of these ciphers are known to be vulnerable (SWEET32 attack).

  This will typically manifest itself in messages like::

      OpenSSL: error:0308010C:digital envelope routines::unsupported
      Cipher algorithm 'BF-CBC' not found
      Unsupported cipher in --data-ciphers: BF-CBC

  If your OpenSSL distribution comes with the legacy provider (see
  also ``man OSSL_PROVIDER-legacy``), you can load it with
  ``--providers legacy default``.  This will re-enable the old algorithms.

- OpenVPN version not supporting TLS 1.2 or later

  The default in OpenVPN 2.6 and also in many distributions is now TLS 1.2 or
  later. Connecting to a peer that does not support this will results in
  messages like::

    TLS error: Unsupported protocol. This typically indicates that client and
    server have no common TLS version enabled. This can be caused by mismatched
    tls-version-min and tls-version-max options on client and server. If your
    OpenVPN client is between v2.3.6 and v2.3.2 try adding tls-version-min 1.0
    to the client configuration to use TLS 1.0+ instead of TLS 1.0 only
    OpenSSL: error:0A000102:SSL routines::unsupported protocol

  This can be an OpenVPN 2.3.6 or earlier version. ``compat-version 2.3.0`` will
  enable TLS 1.0 support if supported by the OpenSSL distribution. Note that
  on some Linux distributions enabling TLS 1.1 or 1.0 is not possible.



Overview of changes in 2.5
==========================

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
    the authentication result is ready, instead of waiting for the client to
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

